//! A connection to the endpoint a Location is configured with, the version
//! of HTTP it speaks, and the connections a transport keeps between
//! requests.
//!
//! The endpoint is read by `net::Endpoint` — `http://host:port` or
//! `https://host:port` — and the connection it opens is what `net::http`
//! or `net::http2` exchanges a request over. TLS is `xmip-core-library-tls`
//! behind this crate's `tls` feature — one TLS stack in the estate
//! (ADR-0033) — and without the feature an `https://` endpoint is refused
//! with a message saying so rather than sent in the clear.
//!
//! **The version is the connection's.** Over TLS it is agreed by ALPN
//! where the caller offers ([`Offer`]): `h2` and `http/1.1`, and the server
//! selects. Over cleartext HTTP/2 is spoken only by prior knowledge, where
//! the Location says so (`h2c`); RFC 9113 removed HTTP/1.1's `Upgrade` to
//! it, and there is none here.
//!
//! **Connected once, not per request.** [`Connections`] keeps what it
//! opened, per endpoint, and every request after the first goes on the
//! connection already open: HTTP/1.1 kept alive, one HTTP/2 connection
//! carrying stream after stream. A transport holds one, and so does every
//! client it makes. Until 2026-09-27 every request of every technology
//! riding on HTTP connected, handshook TLS and said `Connection: close`,
//! and every HTTP/2 request opened a connection of its own, preface and
//! settings included.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use net::Endpoint;
use net::http::{Request, Response, Version};
use net::http2::Client;
use transport::error::Result;
use transport::pool::{alive, quiet};
use transport::socket;
use transport::{Pool, Pooled};

/// Anything a request can travel over: a plain socket, or one wrapped in
/// TLS. Sendable, so a connection kept open between requests can be held
/// by whichever thread sends next.
pub trait Connection: Read + Write + Send {}

impl<S: Read + Write + Send> Connection for S {}

/// Which versions of HTTP a connection is opened to speak.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Offer {
    /// HTTP/1.1 alone: nothing offered by ALPN. What a technology whose
    /// service speaks HTTP/1.1 under its signature opens.
    Http11,
    /// HTTP/2 where TLS agrees it by ALPN, HTTP/1.1 otherwise and in the
    /// clear.
    Agreed,
    /// As [`Offer::Agreed`], and HTTP/2 in the clear too, by prior
    /// knowledge (`h2c`).
    PriorKnowledge,
}

impl Offer {
    /// [`Offer::PriorKnowledge`] where `h2c` says the service speaks HTTP/2
    /// in the clear, [`Offer::Agreed`] otherwise.
    #[must_use]
    pub const fn agreed(h2c: bool) -> Self {
        if h2c {
            Self::PriorKnowledge
        } else {
            Self::Agreed
        }
    }
}

/// Open a connection to `endpoint` within `timeout`, with `timeout` on its
/// reads, and guard it where the endpoint is `https://`: HTTP/1.1, which
/// nothing is offered beside. For a session that holds its one connection
/// itself — `WebDAV`'s, a simulated service pushing to a subscriber.
///
/// # Errors
/// Where the endpoint could not be reached, or asks for TLS this build does
/// not carry.
pub fn connect(endpoint: &Endpoint, timeout: Option<Duration>) -> Result<Box<dyn Connection>> {
    Ok(open(endpoint, timeout, Offer::Http11)?.connection)
}

/// A connection just opened: what a request travels over, the version it
/// speaks, and the socket beneath it, whose far end a kept connection is
/// asked after.
pub struct Opened {
    /// The plain socket, or the socket in TLS.
    pub connection: Box<dyn Connection>,
    /// What the connection speaks.
    pub version: Version,
    /// The socket beneath, TLS or not.
    pub socket: TcpStream,
}

/// Open a connection to `endpoint` as [`connect`] does, and the version it
/// speaks: over TLS what ALPN agreed of what `offer` offered; in the clear
/// HTTP/2 where `offer` knows it beforehand, and HTTP/1.1 otherwise.
///
/// # Errors
/// As [`connect`], and where the handshake failed.
pub fn open(endpoint: &Endpoint, timeout: Option<Duration>, offer: Offer) -> Result<Opened> {
    let tcp = socket::connect_tcp(&endpoint.address(), timeout)?;
    let socket = tcp
        .try_clone()
        .map_err(|e| transport::error::classify("keeping the socket", &e))?;
    let (connection, version) = if endpoint.secure() {
        secure(endpoint.host(), tcp, offer != Offer::Http11)?
    } else if offer == Offer::PriorKnowledge {
        (Box::new(tcp) as Box<dyn Connection>, Version::Http2)
    } else {
        (Box::new(tcp) as Box<dyn Connection>, Version::Http11)
    };
    Ok(Opened {
        connection,
        version,
        socket,
    })
}

/// A connection kept open between requests, in the version it speaks, and
/// the socket beneath it.
struct Kept {
    speaking: Speaking,
    socket: TcpStream,
}

/// What a kept connection speaks.
enum Speaking {
    /// HTTP/1.1, and whether its last answer left it open for the next.
    Http11 {
        connection: Box<dyn Connection>,
        open: bool,
    },
    Http2(Box<Client<Box<dyn Connection>>>),
}

impl Pooled for Kept {
    /// Not where the last answer said `Connection: close` or ended with the
    /// connection, nor where the server said `GOAWAY`, nor where the server
    /// has closed the socket meanwhile. An HTTP/1.1 server speaks only when
    /// asked, so anything it sent to an idle connection lets it go too.
    fn usable(&mut self) -> bool {
        match &self.speaking {
            Speaking::Http11 { open, .. } => *open && quiet(&self.socket),
            Speaking::Http2(client) => !client.going_away() && alive(&self.socket),
        }
    }
}

/// Where kept connections are found: the endpoint's scheme and address,
/// and what was offered when they were opened.
type Key = (bool, String, Offer);

/// The connections a transport keeps to the endpoints it sends to: the
/// capability's [`Pool`] of HTTP connections, opened on the first request
/// to an endpoint and kept for the next, by the transport and every clone
/// of it and every client it hands them to. One the far end closed
/// meanwhile — an idle timeout, a `GOAWAY`, a restart — fails on reuse,
/// and the request goes again on a new connection, as the pool does for
/// every session.
#[derive(Clone, Default)]
pub struct Connections {
    pool: Pool<Kept, Key>,
}

impl Connections {
    /// None kept yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Send `request` to `endpoint` on a connection kept to it, or on a new
    /// one opened within `timeout` offering `offer`, and read its answer.
    ///
    /// # Errors
    /// Where the endpoint could not be reached, the handshake failed, or the
    /// exchange on a new connection failed.
    pub fn exchange(
        &self,
        endpoint: &Endpoint,
        timeout: Option<Duration>,
        offer: Offer,
        request: &Request,
    ) -> Result<Response> {
        let key = (endpoint.secure(), endpoint.address(), offer);
        self.pool.exchange(
            &key,
            || kept(endpoint, timeout, offer),
            |kept| exchange_on(kept, request),
        )
    }

    /// How many connections these have opened: one per endpoint while the
    /// far end keeps them, however many requests.
    #[must_use]
    pub fn opened(&self) -> usize {
        self.pool.opened()
    }
}

/// A new connection to `endpoint`, handshaken where it speaks HTTP/2.
fn kept(endpoint: &Endpoint, timeout: Option<Duration>, offer: Offer) -> Result<Kept> {
    let Opened {
        connection,
        version,
        socket,
    } = open(endpoint, timeout, offer)?;
    let speaking = match version {
        Version::Http11 => Speaking::Http11 {
            connection,
            open: true,
        },
        Version::Http2 => {
            let scheme = if endpoint.secure() { "https" } else { "http" };
            Speaking::Http2(Box::new(Client::handshake(connection, scheme)?))
        }
    };
    Ok(Kept { speaking, socket })
}

/// `request` on `kept`, and its answer.
fn exchange_on(kept: &mut Kept, request: &Request) -> Result<Response> {
    Ok(match &mut kept.speaking {
        Speaking::Http11 { connection, open } => {
            let (answer, reusable) = net::http::exchange_kept(connection, request)?;
            *open = reusable;
            answer
        }
        Speaking::Http2(client) => client.send(request)?,
    })
}

#[cfg(feature = "tls")]
fn secure(host: &str, tcp: TcpStream, offer: bool) -> Result<(Box<dyn Connection>, Version)> {
    if !offer {
        return Ok((Box::new(tls::client(host, tcp)?), Version::Http11));
    }
    let offered = [Version::Http2.alpn(), Version::Http11.alpn()];
    let mut guarded = tls::client_offering(host, tcp, &offered)?;
    let agreed = tls::alpn::agreed(&mut guarded)?;
    Ok((Box::new(guarded), Version::agreed(agreed.as_deref())))
}

#[cfg(not(feature = "tls"))]
fn secure(_host: &str, tcp: TcpStream, _offer: bool) -> Result<(Box<dyn Connection>, Version)> {
    drop(tcp);
    Err(transport::error::protocol_error(
        "https was asked for and this build has no tls feature compiled in",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::BufReader;
    use std::net::TcpListener;

    #[test]
    fn an_https_endpoint_without_tls_says_so() {
        let (listener, address) = socket::bind_tcp("127.0.0.1:0").expect("bind");
        let endpoint = Endpoint::parse(&format!("https://{address}")).expect("parsed");
        let failure = connect(&endpoint, None).err();
        drop(listener);
        #[cfg(not(feature = "tls"))]
        assert!(failure.expect("no tls").message.contains("tls"));
        #[cfg(feature = "tls")]
        assert!(failure.is_none());
    }

    #[test]
    fn a_cleartext_connection_speaks_http_2_only_by_prior_knowledge() {
        let (_listener, address) = socket::bind_tcp("127.0.0.1:0").expect("bind");
        let endpoint = Endpoint::parse(&format!("http://{address}")).expect("parsed");
        let timeout = Some(Duration::from_secs(2));
        for (offer, version) in [
            (Offer::Http11, Version::Http11),
            (Offer::Agreed, Version::Http11),
            (Offer::PriorKnowledge, Version::Http2),
        ] {
            assert_eq!(
                open(&endpoint, timeout, offer).expect("open").version,
                version
            );
        }
    }

    /// A far end that keeps every connection it accepts and answers every
    /// request on it, HTTP/1.1 or HTTP/2 as the connection opens: how many
    /// connections it accepted, and how many requests it answered.
    fn keeping(listener: &TcpListener, connections: usize) -> (usize, usize) {
        let mut answered = 0;
        for _ in 0..connections {
            let (stream, _) = socket::accept_tcp(listener, None).expect("accept");
            let (h2, first) = net::http2::sniff(&mut &stream).expect("sniffed");
            let replayed = net::http2::Replayed::new(first, &stream);
            if h2 {
                // Served until the near end lets the connection go.
                let _ = net::http2::serve(replayed, |_| {
                    answered += 1;
                    Response::new(204)
                });
                continue;
            }
            let mut reader = BufReader::new(replayed);
            while let Ok(Some(_)) = net::http::read_request(&mut reader) {
                let kept = Response::new(200).header("Connection", "keep-alive");
                net::http::write_response(reader.get_mut(), &kept).expect("answered");
                answered += 1;
            }
        }
        (connections, answered)
    }

    #[test]
    fn a_hundred_requests_to_one_endpoint_open_one_connection() {
        const REQUESTS: usize = 100;
        for offer in [Offer::Http11, Offer::PriorKnowledge] {
            let (listener, address) = socket::bind_tcp("127.0.0.1:0").expect("bind");
            let far_end = std::thread::spawn(move || keeping(&listener, 1));
            let endpoint = Endpoint::parse(&format!("http://{address}/orders")).expect("url");
            let connections = Connections::new();
            let shared = connections.clone();
            let began = std::time::Instant::now();
            for n in 0..REQUESTS {
                let request = Request::new("POST", "/orders")
                    .header("Host", &address)
                    .body(n.to_string().as_bytes());
                let by = if n % 2 == 0 { &connections } else { &shared };
                let timeout = Some(Duration::from_secs(5));
                let answer = by
                    .exchange(&endpoint, timeout, offer, &request)
                    .expect("answer");
                assert!((200..300).contains(&answer.status), "{offer:?}");
            }
            // Generous for a debug build under load; a request that waited
            // on a delayed acknowledgement took forty milliseconds on Linux.
            let took = began.elapsed();
            assert!(took < Duration::from_millis(5 * 100), "{offer:?}: {took:?}");
            assert_eq!(connections.opened(), 1, "{offer:?}");
            drop((connections, shared));
            assert_eq!(far_end.join().expect("far end"), (1, REQUESTS), "{offer:?}");
        }
    }

    #[test]
    fn connections_to_far_ends_that_hung_up_are_closed_not_kept() {
        // The Playground, 2026-09-29: a WebDAV far end at a new port every
        // round answered its PUT and hung up, and the kept connection to it
        // was never asked for again — a socket in CLOSE_WAIT a round. A kept
        // connection is closed when this side's socket is: the far end then
        // reads the end of the stream.
        const ROUNDS: usize = 30;
        let connections = Connections::new();
        let mut far_ends = Vec::new();
        for round in 0..ROUNDS {
            let (listener, address) = socket::bind_tcp("127.0.0.1:0").expect("bind");
            let far_end = std::thread::spawn(move || {
                let (stream, _) = listener.accept().expect("accept");
                let mut reader = BufReader::new(&stream);
                net::http::read_request(&mut reader)
                    .expect("read")
                    .expect("one");
                let kept = Response::new(201).header("Connection", "keep-alive");
                net::http::write_response(&mut &stream, &kept).expect("answered");
                stream.shutdown(std::net::Shutdown::Write).expect("hung up");
                stream
            });
            let endpoint = Endpoint::parse(&format!("http://{address}/dav")).expect("url");
            let request = Request::new("PUT", "/dav")
                .header("Host", &address)
                .body(b"x");
            let timeout = Some(Duration::from_secs(5));
            let answer = connections
                .exchange(&endpoint, timeout, Offer::Http11, &request)
                .expect("answered");
            assert_eq!(answer.status, 201, "round {round}");
            far_ends.push(far_end.join().expect("far end"));
        }
        // The last round or two may not have seen their hang-up yet.
        for (round, mut stream) in far_ends.into_iter().take(ROUNDS - 2).enumerate() {
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .expect("timeout");
            let read = stream.read(&mut [0u8; 1]);
            assert!(
                matches!(read, Ok(0)),
                "round {round}: still kept ({read:?})"
            );
        }
    }

    #[test]
    fn a_connection_the_far_end_closed_is_replaced_and_the_request_sent_again() {
        let (listener, address) = socket::bind_tcp("127.0.0.1:0").expect("bind");
        // Says it keeps each connection, then closes it after one answer.
        let far_end = std::thread::spawn(move || {
            for _ in 0..2 {
                let (stream, _) = listener.accept().expect("accept");
                let mut reader = BufReader::new(&stream);
                let request = net::http::read_request(&mut reader)
                    .expect("read")
                    .expect("one");
                let kept = Response::new(202).header("Connection", "keep-alive");
                net::http::write_response(&mut &stream, &kept.body(&request.body)).expect("w");
            }
        });
        let endpoint = Endpoint::parse(&format!("http://{address}/hook")).expect("url");
        let connections = Connections::new();
        for body in [&b"one"[..], b"two"] {
            let request = Request::new("POST", "/hook")
                .header("Host", &address)
                .body(body);
            let timeout = Some(Duration::from_secs(5));
            let answer = connections
                .exchange(&endpoint, timeout, Offer::Http11, &request)
                .expect("answered");
            assert_eq!(answer.body, body);
        }
        assert_eq!(connections.opened(), 2);
        far_end.join().expect("far end");
    }
}
