//! What an HTTP Receive Location keeps between its receives: its listener,
//! bound as its transport is opened (`Configured::listening`; the owner,
//! 2026-11-16, *Bind at open*), and the connections its callers keep open,
//! each request answered in the version it speaks — once its receive cycle
//! has ended.
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
use std::sync::{Arc, Mutex};
use std::time::Duration;
use xcore::Clock;
use xcore::lock::Locked;

use net::http::{Request, Response, read_request, write_response};
use net::http2::{Replayed, Server, sniff};
use transport::answer::{Answer, Busy};
use transport::deadline::Within;
use transport::error::{Result, TransportError, classify};
use transport::serving::{Open, Serving, Turn};
use transport::{Acknowledgement, Turned, Verdict};

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
    /// Not the technology's message, refused at the door for why: answered
    /// now with the response as the connection's last, and the caller
    /// turned away ([`Inbound::turned_away`]) while the receive goes on for
    /// the others. A caller's refusal is never the receive's failure.
    Refused(TransportError, Response),
}

impl<T> Heard<T> {
    /// The same answer, wait or refusal, carrying `f` of what was heard:
    /// what a technology riding on HTTP adds to it — who sent the request.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Heard<U> {
        match self {
            Self::Answered(heard, answer) => Heard::Answered(f(heard), answer),
            Self::Waiting(heard) => Heard::Waiting(f(heard)),
            Self::Refused(why, answer) => Heard::Refused(why, answer),
        }
    }
}

impl Inbound {
    /// Nothing bound, nothing open.
    #[must_use]
    pub fn new() -> Self {
        Self {
            serving: Serving::new(),
        }
    }

    /// Each caller's turn taking at most `turn`, every read of it waiting
    /// only what is left (`transport::serving::Serving::turning_within`):
    /// a request head sent in part and never ended is cut at its turn.
    #[must_use]
    pub fn turning_within(self, turn: Duration) -> Self {
        Self {
            serving: self.serving.turning_within(turn),
        }
    }

    /// Each caller's turn counted on `clock`, the node's, and an HTTP/2
    /// caller's frames in a span on it too
    /// (`transport::serving::Serving::timed_by`).
    #[must_use]
    pub fn timed_by(self, clock: &Arc<dyn Clock>) -> Self {
        Self {
            serving: self.serving.timed_by(clock),
        }
    }

    /// The most one caller's turn takes.
    #[must_use]
    pub const fn turn(&self) -> Duration {
        self.serving.turn()
    }

    /// The next request from whichever caller sends first within `timeout`
    /// (`None` waits as long as it takes), what `hear` made of it, and the
    /// [`Reply`] its caller waits on where `hear` said
    /// [`Heard::Waiting`], on the listener [`Inbound::bound`] bound as the
    /// transport was opened. `hear` is handed the caller's address, which
    /// an origin names.
    ///
    /// A caller whose connection broke or carried a malformed request is
    /// let go and turned away ([`Inbound::turned_away`]), and the wait goes
    /// on for the others.
    ///
    /// # Errors
    /// Where nothing is bound, the listener could not be waited on or
    /// accepted from, or nothing arrived within `timeout`.
    pub fn next<T>(
        &self,
        timeout: Option<Duration>,
        mut hear: impl FnMut(Request, SocketAddr) -> Heard<T>,
    ) -> Result<(T, Option<Reply>)> {
        self.serving
            .next(timeout, Caller::new, |caller| caller.turn(&mut hear))
    }

    /// Where the listener is bound: `None` until it is.
    #[must_use]
    pub fn address(&self) -> Option<&str> {
        self.serving.address()
    }

    /// Bind the listener by `bind` now, where it is not yet, and say where
    /// it is: what each technology receiving through this calls in its
    /// `Configured::listening`.
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

    /// The callers turned away at their own connection since this was last
    /// asked, taken: what every technology receiving through this hands
    /// the runtime as its `Transport::turned_away`.
    #[must_use]
    pub fn turned_away(&self) -> Turned {
        self.serving.turned_away()
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
    let mut line = line.locked();
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

/// The version a connection speaks, its reads within each turn.
enum Speaking {
    Unheard(Within),
    One(BufReader<Replayed<Within>>),
    Two(Box<Server<Replayed<Within>>>),
    Spent,
}

impl Open for Caller {
    fn socket(&self) -> &TcpStream {
        &self.probe
    }

    fn waiting(&self) -> bool {
        let line = self.line.locked();
        match &line.speaking {
            Speaking::One(reader) => !reader.buffer().is_empty(),
            Speaking::Two(_) => line.more,
            Speaking::Unheard(_) | Speaking::Spent => false,
        }
    }

    fn busy(&self) -> Option<&Busy> {
        Some(&self.busy)
    }
}

impl Caller {
    fn new(stream: Within, peer: SocketAddr) -> Result<Self> {
        let probe = stream
            .socket()
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
        let mut line = self.line.locked();
        if matches!(line.speaking, Speaking::Unheard(_))
            && let Speaking::Unheard(mut stream) = mem::replace(&mut line.speaking, Speaking::Spent)
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
            Heard::Refused(why, response) => {
                let reply = self.reply(stream, true)?;
                drop(line);
                // Answered or not, the caller is let go for why.
                drop(reply.answer(&response));
                return Err(why);
            }
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
/// read again; HTTP/2's spans counted on the Clock its turns are.
fn heard(mut stream: Within) -> Result<Speaking> {
    let (h2, first) = sniff(&mut stream)?;
    let now = Box::new(xcore::clock::reading(stream.clock()));
    let connection = Replayed::new(first, stream);
    Ok(if h2 {
        Speaking::Two(Box::new(Server::handshake(connection, now)?))
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
        let (taken, reply) = inbound.next(WAIT, waiting)?;
        reply.expect("waiting").answer(&Response::new(202))?;
        Ok(taken)
    }

    fn bound(inbound: &Inbound, binds: &AtomicUsize) -> String {
        let bind = || {
            binds.fetch_add(1, Ordering::SeqCst);
            socket::bind_tcp("127.0.0.1:0")
        };
        inbound.bound(bind).expect("bound").to_string()
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
            let (one, reply) = inbound.next(WAIT, waiting).expect("one");
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
        let (said, reply) = inbound
            .next(WAIT, |request, _| {
                Heard::Answered(request.body, Response::new(200))
            })
            .expect("heard");
        assert_eq!((said.as_slice(), reply.is_none()), (&b"hello"[..], true));
        assert_eq!(caller.join().expect("caller"), 200);
    }

    #[test]
    fn a_caller_past_a_bound_is_turned_away_and_the_next_caller_served() {
        let inbound = Inbound::new();
        let binds = AtomicUsize::new(0);
        let address = bound(&inbound, &binds);
        let at = Endpoint::parse(&format!("http://{address}/orders")).expect("parsed");
        let mut breaching = std::net::TcpStream::connect(&address).expect("connect");
        breaching.set_read_timeout(WAIT).expect("a bounded wait");
        let from = breaching.local_addr().expect("its address");
        // A head past the longest line read, never ended: no request. The
        // next caller calls once it is let go, so it is taken first.
        let callers = std::thread::spawn(move || {
            let head = vec![b'a'; net::read::MAX_LINE + 1];
            drop(std::io::Write::write_all(&mut breaching, &head));
            drop(std::io::Read::read_to_end(&mut breaching, &mut Vec::new()));
            Connections::new()
                .exchange(&at, WAIT, Offer::Http11, &post(&at, b"after"))
                .expect("answered")
                .status
        });
        assert_eq!(accepted(&inbound).expect("the next caller").0, b"after");
        assert_eq!(callers.join().expect("callers"), 202);
        let turned = inbound.turned_away();
        assert_eq!(turned.callers.len(), 1, "{turned:?}");
        assert_eq!(turned.callers[0].peer, from);
        assert!(inbound.turned_away().is_empty(), "taken once");
    }

    #[test]
    fn a_head_sent_in_part_is_cut_at_its_turn_and_the_next_caller_served() {
        // Half a head, never ended. Until 2026-11-14 it held the turn as
        // long as a read waits — five seconds here, for good where a
        // Location waits as long as it takes — and every caller behind it.
        let turn = Duration::from_millis(200);
        let inbound = Inbound::new().turning_within(turn);
        assert_eq!(inbound.clone().turn(), turn);
        let binds = AtomicUsize::new(0);
        let address = bound(&inbound, &binds);
        let at = Endpoint::parse(&format!("http://{address}/orders")).expect("parsed");
        let mut stopped = std::net::TcpStream::connect(&address).expect("connect");
        let from = stopped.local_addr().expect("its address");
        let half = b"POST /orders HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-";
        std::io::Write::write_all(&mut stopped, half).expect("half a head");
        let caller = std::thread::spawn(move || {
            Connections::new()
                .exchange(&at, WAIT, Offer::Http11, &post(&at, b"after"))
                .expect("answered")
                .status
        });
        let began = std::time::Instant::now();
        assert_eq!(accepted(&inbound).expect("the next caller").0, b"after");
        let took = began.elapsed();
        assert!(took < Duration::from_secs(3), "served after {took:?}");
        assert_eq!(caller.join().expect("caller"), 202);
        let turned = inbound.turned_away();
        assert_eq!(turned.callers.len(), 1, "{turned:?}");
        assert_eq!(turned.callers[0].peer, from);
        assert!(turned.callers[0].why.message.contains("turn"), "{turned:?}");
        drop(stopped);
    }

    #[test]
    fn a_request_refused_at_the_door_is_answered_and_the_next_caller_served() {
        let inbound = Inbound::new();
        let binds = AtomicUsize::new(0);
        let address = bound(&inbound, &binds);
        let at = Endpoint::parse(&format!("http://{address}/orders")).expect("parsed");
        let callers = std::thread::spawn(move || {
            let refused = Connections::new()
                .exchange(&at, WAIT, Offer::Http11, &post(&at, b"not ours"))
                .expect("answered");
            let next = Connections::new()
                .exchange(&at, WAIT, Offer::Http11, &post(&at, b"ours"))
                .expect("answered");
            (refused.status, refused.body, next.status)
        });
        let hear = |request: Request, peer| {
            if request.body == b"not ours" {
                let why = TransportError::permanent("not this technology's message");
                return Heard::Refused(why, Response::new(400).body(b"not ours"));
            }
            waiting(request, peer)
        };
        let (taken, reply) = inbound.next(WAIT, hear).expect("the next caller");
        assert_eq!(taken.0, b"ours");
        reply
            .expect("waiting")
            .answer(&Response::new(202))
            .expect("answered");
        assert_eq!(
            callers.join().expect("callers"),
            (400, b"not ours".to_vec(), 202)
        );
        let turned = inbound.turned_away();
        assert_eq!(turned.callers.len(), 1, "{turned:?}");
        assert_eq!(
            turned.callers[0].why.message,
            "not this technology's message"
        );
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
        let (_, reply) = inbound.next(WAIT, waiting).expect("taken");
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
            .next(Some(Duration::from_millis(200)), waiting)
            .expect_err("nothing but a poke");
        assert!(
            error.retryable,
            "a poke hangs up, and nothing arrived: {error}"
        );
    }
}
