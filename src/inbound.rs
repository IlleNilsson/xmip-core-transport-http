//! What an HTTP Receive Location keeps between its receives: its listener,
//! bound on the first, and the connections its callers keep open, each
//! request answered in the version it speaks — once its receive cycle has
//! ended.
//!
//! Every sender keeps its connection between requests (`endpoint`), and
//! until 2026-09-27 a Receive Location bound a new listener for every
//! request and answered each with `Connection: close` — or, in HTTP/2, a
//! `GOAWAY` — so every request was a new connection, and one that came
//! between two receives was refused. The waiting and keeping are the
//! capability's (`transport::serving`); what a turn on an HTTP connection
//! is lives here: the version told from the first octets, a request read
//! whole, and the connection kept unless the caller said it is done.
//!
//! **The caller waits for the verdict.** A request that carries a Stream
//! is not answered as it is read: its [`Reply`] goes to the runtime inside
//! the arrival's acknowledgement, and the answer — `202`, an MDN, a
//! receipt — is written once the receive cycle has ended (runtime-model
//! section 5), on the connection its [`Answer`] holds. Until then the
//! connection is [`Busy`] (`serving::Open::busy`) and takes no next
//! request; a reply let go unanswered shuts it. A request that carries
//! none — a handshake, a malformed message — is answered at once
//! ([`Heard::Answered`]). Every technology riding on HTTP that listens —
//! AS2, AS4, SNS's subscription, Event Grid's webhook, MSMQ, Peppol —
//! receives through this.

use std::io::BufReader;
use std::mem;
use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use net::http::{Request, Response, read_request, write_response};
use net::http2::{Replayed, Server, sniff};
use transport::answer::{Answer, Busy};
use transport::error::{Result, classify};
use transport::serving::{Open, Serving, Turn};
use transport::{Acknowledgement, Verdict};

/// A Receive Location's listener and the connections kept open on it.
#[derive(Clone, Debug, Default)]
pub struct Inbound {
    serving: Serving<Caller>,
}

/// What a technology made of one request.
pub enum Heard<T> {
    /// Not a Stream — a handshake, a refusal of what is not the protocol's
    /// message: answered now with the response.
    Answered(T, Response),
    /// A Stream: the caller waits for the answer its [`Reply`] gives after
    /// the receive cycle.
    Waiting(T),
}

impl<T> Heard<T> {
    /// The same answer or wait, carrying `f` of what was heard: what a
    /// technology riding on HTTP adds to it — who sent the request.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Heard<U> {
        match self {
            Self::Answered(heard, answer) => Heard::Answered(f(heard), answer),
            Self::Waiting(heard) => Heard::Waiting(f(heard)),
        }
    }
}

impl Inbound {
    /// Nothing bound, nothing open.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            serving: Serving::new(),
        }
    }

    /// The next request from whichever caller sends first within `timeout`
    /// (`None` waits as long as it takes), what `hear` made of it, and the
    /// [`Reply`] its caller waits on where `hear` said
    /// [`Heard::Waiting`]. The listener is bound by `bind` on the first
    /// call and kept. `hear` is handed the caller's address, which an
    /// origin names.
    ///
    /// # Errors
    /// Where the listener could not be bound, nothing arrived within
    /// `timeout`, or a caller's connection broke or carried a malformed
    /// request — that connection is let go.
    pub fn next<T>(
        &self,
        bind: impl FnOnce() -> Result<(TcpListener, String)>,
        timeout: Option<Duration>,
        mut hear: impl FnMut(Request, SocketAddr) -> Heard<T>,
    ) -> Result<(T, Option<Reply>)> {
        self.serving
            .next(bind, timeout, Caller::new, |caller| caller.turn(&mut hear))
    }

    /// Where the listener is bound: `None` before the first receive.
    #[must_use]
    pub fn address(&self) -> Option<&str> {
        self.serving.address()
    }

    /// Bind the listener by `bind` now, where no receive has, and say
    /// where it is.
    ///
    /// # Errors
    /// As `bind`.
    pub fn bound(&self, bind: impl FnOnce() -> Result<(TcpListener, String)>) -> Result<&str> {
        self.serving.bound(bind)
    }

    /// How many callers' connections are kept open now.
    #[must_use]
    pub fn open(&self) -> usize {
        self.serving.open()
    }
}

/// The answer one caller waits for: given once, after the receive cycle.
/// Dropped unanswered, it lets the caller go — the connection is shut
/// ([`Answer`]) — so a caller is never left holding a request nobody will
/// answer.
pub struct Reply {
    line: Arc<Mutex<Line>>,
    /// The connection held for the answer, busy until it is given.
    answer: Answer,
    /// The HTTP/2 stream the request came on; `None` is HTTP/1.1.
    stream: Option<u32>,
    /// Whether the caller said this request is its last.
    last: bool,
}

impl Reply {
    /// Answer the caller with `response`.
    ///
    /// # Errors
    /// Where the connection broke before the answer was written.
    pub fn answer(self, response: &Response) -> Result<()> {
        let Self {
            line,
            answer,
            stream,
            last,
        } = self;
        answer.with(|probe| written(&line, probe, stream, last, response))
    }

    /// The acknowledgement an arrival carries: the caller is answered with
    /// what `answer` makes of the verdict.
    #[must_use]
    pub fn acknowledgement(
        self,
        answer: impl FnOnce(Verdict) -> Response + Send + 'static,
    ) -> Acknowledgement {
        Acknowledgement::deferred(move |verdict| self.answer(&answer(verdict)))
    }
}

/// `response` written on `line` in the version it speaks — on the HTTP/2
/// `stream`, or HTTP/1.1 where there is none — and the connection shut by
/// `probe` where the caller said this request is its `last` or the
/// response closes it.
fn written(
    line: &Mutex<Line>,
    probe: &TcpStream,
    stream: Option<u32>,
    last: bool,
    response: &Response,
) -> Result<()> {
    let mut line = line.lock().unwrap_or_else(PoisonError::into_inner);
    match (&mut line.speaking, stream) {
        (Speaking::One(reader), None) => {
            let mut response = response.clone();
            if !last && response.header_value("connection").is_none() {
                response = response.header("Connection", "keep-alive");
            }
            write_response(reader.get_mut(), &response)?;
            if last || closes(response.header_value("connection")) {
                line.speaking = Speaking::Spent;
                drop(probe.shutdown(Shutdown::Both));
            }
            Ok(())
        }
        (Speaking::Two(server), Some(stream)) => Ok(server.respond(stream, response)?),
        _ => Ok(()),
    }
}

impl std::fmt::Debug for Reply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reply")
            .field("stream", &self.stream)
            .field("last", &self.last)
            .finish_non_exhaustive()
    }
}

/// One caller's connection, and the version it speaks once its first
/// octets say. Shared with the [`Reply`] its request waits on.
struct Caller {
    /// The same socket, for its readiness: the connection itself is read
    /// through what speaks it.
    probe: TcpStream,
    peer: SocketAddr,
    line: Arc<Mutex<Line>>,
    /// A request taken and not yet answered.
    busy: Busy,
}

struct Line {
    speaking: Speaking,
    /// Whether an HTTP/2 read finished a request that is not yet taken.
    more: bool,
}

enum Speaking {
    Unheard(TcpStream),
    One(BufReader<Replayed<TcpStream>>),
    Two(Box<Server<Replayed<TcpStream>>>),
    Spent,
}

impl Open for Caller {
    fn socket(&self) -> &TcpStream {
        &self.probe
    }

    fn waiting(&self) -> bool {
        let line = self.line.lock().unwrap_or_else(PoisonError::into_inner);
        match &line.speaking {
            Speaking::One(reader) => !reader.buffer().is_empty(),
            Speaking::Two(_) => line.more,
            Speaking::Unheard(_) | Speaking::Spent => false,
        }
    }

    fn busy(&self) -> bool {
        self.busy.is_busy()
    }
}

impl Caller {
    fn new(stream: TcpStream, peer: SocketAddr) -> Result<Self> {
        let probe = stream
            .try_clone()
            .map_err(|e| classify("keeping the connection", &e))?;
        Ok(Self {
            probe,
            peer,
            line: Arc::new(Mutex::new(Line {
                speaking: Speaking::Unheard(stream),
                more: false,
            })),
            busy: Busy::new(),
        })
    }

    /// One turn: the version told where it is not yet, then one request
    /// taken — answered now, or left waiting on its [`Reply`].
    fn turn<T>(
        &mut self,
        hear: &mut impl FnMut(Request, SocketAddr) -> Heard<T>,
    ) -> Result<Turn<(T, Option<Reply>)>> {
        let mut line = self.line.lock().unwrap_or_else(PoisonError::into_inner);
        if matches!(line.speaking, Speaking::Unheard(_))
            && let Speaking::Unheard(stream) = mem::replace(&mut line.speaking, Speaking::Spent)
        {
            // A caller that connected and closed without a word — a poke,
            // a pool that opened ahead — has hung up, not failed.
            let mut first = [0u8; 1];
            let peeked = stream
                .peek(&mut first)
                .map_err(|e| classify("reading the first octets", &e))?;
            if peeked == 0 {
                return Ok(Turn::Closed);
            }
            line.speaking = heard(stream)?;
        }
        let Line { speaking, more } = &mut *line;
        let (request, stream) = match speaking {
            Speaking::One(reader) => match read_request(reader)? {
                Some(request) => (request, None),
                None => return Ok(Turn::Closed),
            },
            Speaking::Two(server) => {
                if !*more && !server.read_frame()? {
                    return Ok(Turn::Closed);
                }
                let Some((stream, request)) = server.finished()? else {
                    *more = false;
                    return Ok(Turn::Nothing);
                };
                *more = true;
                (request, Some(stream))
            }
            Speaking::Unheard(_) | Speaking::Spent => return Ok(Turn::Closed),
        };
        let last = stream.is_none() && closes(request.header_value("connection"));
        let taken = match hear(request, self.peer) {
            Heard::Answered(taken, response) => {
                let reply = self.reply(stream, last)?;
                drop(line);
                reply.answer(&response)?;
                (taken, None)
            }
            Heard::Waiting(taken) => (taken, Some(self.reply(stream, last)?)),
        };
        Ok(if last {
            Turn::Last(taken)
        } else {
            Turn::Taken(taken)
        })
    }

    /// The reply a request waits on: the connection busy until it is
    /// given.
    fn reply(&self, stream: Option<u32>, last: bool) -> Result<Reply> {
        Ok(Reply {
            line: Arc::clone(&self.line),
            answer: Answer::held(&self.probe)?.busy(&self.busy),
            stream,
            last,
        })
    }
}

/// Whether a `Connection` header says the connection ends.
fn closes(said: Option<&str>) -> bool {
    said.is_some_and(|said| said.eq_ignore_ascii_case("close"))
}

/// The version a connection speaks, told from its first octets, which are
/// read again.
fn heard(mut stream: TcpStream) -> Result<Speaking> {
    let (h2, first) = sniff(&mut stream)?;
    let connection = Replayed::new(first, stream);
    Ok(if h2 {
        Speaking::Two(Box::new(Server::handshake(connection)?))
    } else {
        Speaking::One(BufReader::new(connection))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::{self, Connections, Offer};
    use net::Endpoint;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use transport::socket;

    const WAIT: Option<Duration> = Some(Duration::from_secs(5));

    /// The body and the caller, waiting for the verdict.
    fn waiting(request: Request, peer: SocketAddr) -> Heard<(Vec<u8>, SocketAddr)> {
        Heard::Waiting((request.body, peer))
    }

    /// The next request, answered `202`.
    fn accepted(inbound: &Inbound) -> Result<(Vec<u8>, SocketAddr)> {
        let unbound = || -> Result<(TcpListener, String)> { panic!("bound twice") };
        let (taken, reply) = inbound.next(unbound, WAIT, waiting)?;
        reply.expect("waiting").answer(&Response::new(202))?;
        Ok(taken)
    }

    fn bound(inbound: &Inbound, binds: &AtomicUsize) -> String {
        let bind = || {
            binds.fetch_add(1, Ordering::SeqCst);
            socket::bind_tcp("127.0.0.1:0")
        };
        drop(inbound.next(bind, Some(Duration::from_millis(1)), waiting));
        inbound.address().expect("bound").to_string()
    }

    fn post(at: &Endpoint, body: &[u8]) -> Request {
        Request::new("POST", at.path())
            .header("Host", &at.authority())
            .body(body)
    }

    fn requests_on_kept_connections(offer: Offer) {
        const ROUNDS: usize = 20;
        let inbound = Inbound::new();
        let binds = AtomicUsize::new(0);
        let address = bound(&inbound, &binds);
        let at = Endpoint::parse(&format!("http://{address}/orders")).expect("parsed");
        let sender = std::thread::spawn(move || {
            let connections = Connections::new();
            for round in 0..ROUNDS {
                let request = post(&at, format!("order {round}").as_bytes());
                let answer = connections
                    .exchange(&at, WAIT, offer, &request)
                    .expect("answered");
                assert_eq!(answer.status, 202);
            }
        });
        let mut peers = Vec::new();
        for round in 0..ROUNDS {
            let (body, peer) = accepted(&inbound).expect("arrived");
            assert_eq!(body, format!("order {round}").as_bytes());
            peers.push(peer);
        }
        sender.join().expect("sender");
        assert_eq!(binds.load(Ordering::SeqCst), 1, "one listener");
        peers.dedup();
        assert_eq!(
            peers.len(),
            1,
            "one connection carried every request: {peers:?}"
        );
        assert_eq!(inbound.open(), 1);
    }

    #[test]
    fn a_kept_http_1_connection_carries_every_request() {
        requests_on_kept_connections(Offer::agreed(false));
    }

    #[test]
    fn a_kept_http_2_connection_carries_every_request() {
        requests_on_kept_connections(Offer::PriorKnowledge);
    }

    #[test]
    fn the_caller_waits_for_the_verdict_and_hears_it() {
        for offer in [Offer::agreed(false), Offer::PriorKnowledge] {
            let inbound = Inbound::new();
            let binds = AtomicUsize::new(0);
            let address = bound(&inbound, &binds);
            let at = Endpoint::parse(&format!("http://{address}/orders")).expect("parsed");
            let caller = std::thread::spawn(move || {
                let connections = Connections::new();
                let first = connections
                    .exchange(&at, WAIT, offer, &post(&at, b"one"))
                    .expect("answered");
                let second = connections
                    .exchange(&at, WAIT, offer, &post(&at, b"two"))
                    .expect("answered");
                (first.status, second.status)
            });
            let unbound = || -> Result<(TcpListener, String)> { panic!("bound twice") };
            let (one, reply) = inbound.next(unbound, WAIT, waiting).expect("one");
            assert_eq!(one.0, b"one");
            assert!(!caller.is_finished(), "nothing answered before the verdict");
            reply
                .expect("waiting")
                .answer(&Response::new(503))
                .expect("refused");
            assert_eq!(accepted(&inbound).expect("two").0, b"two");
            assert_eq!(caller.join().expect("caller"), (503, 202));
        }
    }

    #[test]
    fn a_request_heard_as_no_stream_is_answered_at_once() {
        let inbound = Inbound::new();
        let binds = AtomicUsize::new(0);
        let address = bound(&inbound, &binds);
        let at = Endpoint::parse(&format!("http://{address}/hello")).expect("parsed");
        let caller = std::thread::spawn(move || {
            Connections::new()
                .exchange(&at, WAIT, Offer::Http11, &post(&at, b"hello"))
                .expect("answered")
                .status
        });
        let unbound = || -> Result<(TcpListener, String)> { panic!("bound twice") };
        let (said, reply) = inbound
            .next(unbound, WAIT, |request, _| {
                Heard::Answered(request.body, Response::new(200))
            })
            .expect("heard");
        assert_eq!((said.as_slice(), reply.is_none()), (&b"hello"[..], true));
        assert_eq!(caller.join().expect("caller"), 200);
    }

    #[test]
    fn a_reply_dropped_unanswered_lets_the_caller_go() {
        let inbound = Inbound::new();
        let binds = AtomicUsize::new(0);
        let address = bound(&inbound, &binds);
        let at = Endpoint::parse(&format!("http://{address}/orders")).expect("parsed");
        let stream = endpoint::connect(&at, WAIT).expect("connect");
        let request = post(&at, b"dropped");
        let caller = std::thread::spawn(move || net::http::exchange(stream, &request));
        let unbound = || -> Result<(TcpListener, String)> { panic!("bound twice") };
        let (_, reply) = inbound.next(unbound, WAIT, waiting).expect("taken");
        drop(reply);
        assert!(caller.join().expect("caller").is_err(), "let go unanswered");
    }

    #[test]
    fn pipelined_requests_are_each_taken_from_the_buffer() {
        let inbound = Inbound::new();
        let binds = AtomicUsize::new(0);
        let address = bound(&inbound, &binds);
        let at = Endpoint::parse(&format!("http://{address}/once")).expect("parsed");
        let mut stream = endpoint::connect(&at, WAIT).expect("connect");
        let request = post(&at, b"one");
        // Both requests written before either is read: the second waits in
        // this side's buffer, where no readiness can see it.
        let caller = std::thread::spawn(move || {
            let mut pipelined = Vec::new();
            net::http::write_request(&mut pipelined, &request).expect("written");
            let pipelined = String::from_utf8(pipelined).expect("text");
            let kept = pipelined.replace("Connection: close\r\n", "");
            std::io::Write::write_all(&mut stream, format!("{kept}{kept}").as_bytes())
                .expect("both");
            let mut reader = std::io::BufReader::new(stream);
            let first = net::http::read_response(&mut reader).expect("first");
            let second = net::http::read_response(&mut reader).expect("second");
            (first.status, second.status)
        });
        let one = accepted(&inbound);
        let two = accepted(&inbound);
        assert_eq!(caller.join().expect("caller"), (202, 202));
        assert_eq!(one.expect("one").0, b"one");
        assert_eq!(two.expect("two").0, b"one");
    }

    #[test]
    fn a_caller_that_closes_is_answered_and_let_go() {
        let inbound = Inbound::new();
        let binds = AtomicUsize::new(0);
        let address = bound(&inbound, &binds);
        let at = Endpoint::parse(&format!("http://{address}/once")).expect("parsed");
        // Connected before the receive: queued, not refused.
        let stream = endpoint::connect(&at, WAIT).expect("connect");
        let request = post(&at, b"once");
        let caller =
            std::thread::spawn(move || net::http::exchange(stream, &request).expect("answered"));
        let (body, _) = accepted(&inbound).expect("arrived");
        let answer = caller.join().expect("caller");
        assert_eq!((answer.status, body.as_slice()), (202, &b"once"[..]));
        assert_eq!(answer.header_value("connection"), Some("close"));
        assert_eq!(inbound.open(), 0, "the caller said close");
        drop(endpoint::connect(&at, WAIT).expect("a poke"));
        let error = inbound
            .next(
                || panic!("bound twice"),
                Some(Duration::from_millis(200)),
                waiting,
            )
            .expect_err("nothing but a poke");
        assert!(
            error.retryable,
            "a poke hangs up, and nothing arrived: {error}"
        );
    }
}
