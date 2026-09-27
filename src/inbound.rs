//! What an HTTP Receive Location keeps between its receives: its listener,
//! bound on the first, and the connections its callers keep open, each
//! answered request after request in the version it speaks.
//!
//! Every sender keeps its connection between requests (`endpoint`), and
//! until 2026-09-27 a Receive Location bound a new listener for every
//! request and answered each with `Connection: close` — or, in HTTP/2, a
//! `GOAWAY` — so every request was a new connection, and one that came
//! between two receives was refused. The waiting and keeping are the
//! capability's (`transport::serving`); what a turn on an HTTP connection
//! is lives here: the version told from the first octets, a request read
//! whole and answered, and the connection kept unless the caller said it
//! is done. Every technology riding on HTTP that listens — AS2, AS4, SNS's
//! subscription, Event Grid's webhook, MSMQ, Peppol — receives through
//! this, with what it answers handed in.

use std::io::BufReader;
use std::mem;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::time::Duration;

use net::http::{Request, Response, read_request, write_response};
use net::http2::{Replayed, Server, sniff};
use transport::error::{Result, classify};
use transport::serving::{Open, Serving, Turn};

/// A Receive Location's listener and the connections kept open on it.
#[derive(Clone, Debug, Default)]
pub struct Inbound {
    serving: Serving<Caller>,
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
    /// (`None` waits as long as it takes), answered as `answer` says, and
    /// what `answer` made of it. The listener is bound by `bind` on the
    /// first call and kept. `answer` is handed the caller's address, which
    /// an origin names.
    ///
    /// # Errors
    /// Where the listener could not be bound, nothing arrived within
    /// `timeout`, or a caller's connection broke or carried a malformed
    /// request — that connection is let go.
    pub fn next<T>(
        &self,
        bind: impl FnOnce() -> Result<(TcpListener, String)>,
        timeout: Option<Duration>,
        mut answer: impl FnMut(&Request, SocketAddr) -> (T, Response),
    ) -> Result<T> {
        self.serving.next(bind, timeout, Caller::new, |caller| {
            caller.turn(&mut answer)
        })
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

/// One caller's connection, and the version it speaks once its first
/// octets say.
struct Caller {
    /// The same socket, for its readiness: the connection itself is read
    /// through what speaks it.
    probe: TcpStream,
    peer: SocketAddr,
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
        match &self.speaking {
            Speaking::One(reader) => !reader.buffer().is_empty(),
            Speaking::Two(_) => self.more,
            Speaking::Unheard(_) | Speaking::Spent => false,
        }
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
            speaking: Speaking::Unheard(stream),
            more: false,
        })
    }

    /// One turn: the version told where it is not yet, then one request
    /// taken and answered where one is there.
    fn turn<T>(
        &mut self,
        answer: &mut impl FnMut(&Request, SocketAddr) -> (T, Response),
    ) -> Result<Turn<T>> {
        if matches!(self.speaking, Speaking::Unheard(_))
            && let Speaking::Unheard(stream) = mem::replace(&mut self.speaking, Speaking::Spent)
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
            self.speaking = heard(stream)?;
        }
        let peer = self.peer;
        match &mut self.speaking {
            Speaking::One(reader) => one(reader, |request| answer(request, peer)),
            Speaking::Two(server) => two(server, &mut self.more, |request| answer(request, peer)),
            Speaking::Unheard(_) | Speaking::Spent => Ok(Turn::Closed),
        }
    }
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

/// One HTTP/1.1 request, answered, and the connection kept unless either
/// side says `Connection: close`.
fn one<T>(
    reader: &mut BufReader<Replayed<TcpStream>>,
    answer: impl FnOnce(&Request) -> (T, Response),
) -> Result<Turn<T>> {
    let Some(request) = read_request(reader)? else {
        return Ok(Turn::Closed);
    };
    let (taken, mut response) = answer(&request);
    let closes = |said: Option<&str>| said.is_some_and(|said| said.eq_ignore_ascii_case("close"));
    let last = closes(request.header_value("connection"));
    if !last && response.header_value("connection").is_none() {
        response = response.header("Connection", "keep-alive");
    }
    let last = last || closes(response.header_value("connection"));
    write_response(reader.get_mut(), &response)?;
    Ok(if last {
        Turn::Last(taken)
    } else {
        Turn::Taken(taken)
    })
}

/// One HTTP/2 request finished and answered, reading a frame first unless
/// the last read finished more than one.
fn two<T>(
    server: &mut Server<Replayed<TcpStream>>,
    more: &mut bool,
    answer: impl FnOnce(&Request) -> (T, Response),
) -> Result<Turn<T>> {
    if !*more && !server.read_frame()? {
        return Ok(Turn::Closed);
    }
    let Some((stream, request)) = server.finished()? else {
        *more = false;
        return Ok(Turn::Nothing);
    };
    *more = true;
    let (taken, response) = answer(&request);
    server.respond(stream, &response)?;
    Ok(Turn::Taken(taken))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint::{self, Connections, Offer};
    use crate::server::arrival;
    use net::Endpoint;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use transport::socket;

    const WAIT: Option<Duration> = Some(Duration::from_secs(5));

    fn bound(inbound: &Inbound, binds: &AtomicUsize) -> String {
        let bind = || {
            binds.fetch_add(1, Ordering::SeqCst);
            socket::bind_tcp("127.0.0.1:0")
        };
        drop(inbound.next(bind, Some(Duration::from_millis(1)), arrival));
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
            let unbound = || -> Result<(TcpListener, String)> { panic!("bound twice") };
            let arrived = inbound.next(unbound, WAIT, arrival).expect("arrived");
            assert_eq!(arrived.bytes, format!("order {round}").as_bytes());
            peers.push(arrived.origin_uri);
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
        let one = inbound.next(|| panic!("bound twice"), WAIT, arrival);
        let two = inbound.next(|| panic!("bound twice"), WAIT, arrival);
        assert_eq!(caller.join().expect("caller"), (202, 202));
        assert_eq!(one.expect("one").bytes, b"one");
        assert_eq!(two.expect("two").bytes, b"one");
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
        let arrived = inbound
            .next(|| panic!("bound twice"), WAIT, arrival)
            .expect("arrived");
        let answer = caller.join().expect("caller");
        assert_eq!(
            (answer.status, arrived.bytes.as_slice()),
            (202, &b"once"[..])
        );
        assert_eq!(answer.header_value("connection"), Some("close"));
        assert_eq!(inbound.open(), 0, "the caller said close");
        drop(endpoint::connect(&at, WAIT).expect("a poke"));
        let error = inbound
            .next(
                || panic!("bound twice"),
                Some(Duration::from_millis(200)),
                arrival,
            )
            .expect_err("nothing but a poke");
        assert!(
            error.retryable,
            "a poke hangs up, and nothing arrived: {error}"
        );
    }
}
