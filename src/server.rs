//! Taking one request off a connection and answering it, in the version
//! of HTTP the connection opens with.
//!
//! A connection that opens with HTTP/2's preface — a client speaking it
//! by prior knowledge — is served by `net::http2`; any other by
//! `net::http`, the one HTTP/1.1 codec. Nothing is lost telling them
//! apart: the octets read to tell are read again. What is the transport's
//! is the connection accepted within its timeout, what a Receive Location
//! answers, and the Stream that arrived.

use std::io::{BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::time::Duration;

use net::http::{Request, Response, read_request, write_response};
use net::http2::{Replayed, Server, sniff};
use net::{Endpoint, Schemes, Target};
use transport::error::{Result, protocol_error};
use transport::socket;
use transport::{
    Acknowledgement, ArrivalIdentity, Arrived, Headers, Refusal, Taken, TransportError, Verdict,
};

use context::property::{HTTP_METHOD, HTTP_QUERY_PREFIX, HTTP_URI};
use xcore::{Clock, SystemClock};

/// What Xmip answers a caller whose Stream the receive cycle accepted.
///
/// `202 Accepted`, deliberately. Xmip has taken the Stream into custody and has
/// promised nothing else — which is exactly the state a Stream is in once the
/// receive cycle has written it to the Ledger and before the Journey exists.
/// `200 OK` would claim the work is done.
pub const ACCEPTED: u16 = 202;

/// What Xmip answers a caller whose receive cycle Xmip could not complete:
/// `503 Service Unavailable` (RFC 9110 section 15.6.4), a transient
/// condition, so the caller keeps the Stream and sends it again — nothing
/// was taken into custody.
pub const FAILED: u16 = 503;

/// What Xmip answers a caller whose Stream the receive cycle refused, by
/// why: a client error the caller does not repeat unchanged (RFC 9110
/// section 15.5). `401 Unauthorized` where the caller could not be
/// identified (section 15.5.2), `403 Forbidden` where it is known and not
/// permitted (section 15.5.4), `422 Unprocessable Content` where the
/// content was refused — its routing property unreadable, or it failed
/// Validation (section 15.5.21).
#[must_use]
pub const fn refused(why: Refusal) -> u16 {
    match why {
        Refusal::Unidentified => 401,
        Refusal::Forbidden => 403,
        Refusal::Unacceptable => 422,
    }
}

/// The status a verdict is: [`ACCEPTED`], [`refused`] by why, or
/// [`FAILED`].
#[must_use]
pub const fn status(verdict: Verdict) -> u16 {
    match verdict {
        Verdict::Accepted => ACCEPTED,
        Verdict::Refused(why) => refused(why),
        Verdict::Failed => FAILED,
    }
}

/// The answer a verdict is, with no body: its [`status`].
#[must_use]
pub fn verdict(verdict: Verdict) -> Response {
    Response::new(status(verdict))
}

/// Where a request came from: `http://<peer><target>`.
#[must_use]
pub fn origin(request: &Request, peer: SocketAddr) -> String {
    format!("http://{peer}{}", request.target())
}

/// One request as it arrived from `peer`, its far end told by
/// `acknowledgement`: the body whole, the request's headers as HTTP's
/// ([`Headers`]), and what the request says of its sender for the identity
/// gates — the peer, the method, the target and each query parameter, under
/// `context::property`'s names (ADR-0019 clause 5, amendment 2026-09-24).
/// Every technology that takes a Stream as an HTTP request builds its
/// arrival here, or through [`Sender`] where its body is not the request's.
#[must_use]
pub fn arrived(request: Request, peer: SocketAddr, acknowledgement: Acknowledgement) -> Arrived {
    let origin = origin(&request, peer);
    let sender = Sender::of(&request, peer);
    sender.on(Arrived::whole(origin, request.body, acknowledgement))
}

/// What one request from `peer` says of its sender: its headers, HTTP's,
/// and its peer, method, target and query under `context::property`'s
/// names. Read off the request once, and put on the arrival a technology
/// riding on HTTP builds from it — AS2 and AS4, whose Stream is the entity
/// the request carries, not its body.
#[derive(Clone, Debug)]
pub struct Sender {
    headers: Headers,
    observed: Vec<(String, String)>,
}

/// What every arrival from an HTTP request carries of its sender before any
/// header does: its peer and its request line ([`Sender`]).
pub const REQUEST: ArrivalIdentity =
    ArrivalIdentity::Named(&[context::property::PEER_ADDRESS, HTTP_METHOD, HTTP_URI]);

impl Sender {
    /// What `request`, from `peer`, says of who sent it.
    #[must_use]
    pub fn of(request: &Request, peer: SocketAddr) -> Self {
        let (address, at) = transport::arrival_identity::peer(peer);
        let mut observed = vec![
            (address, at),
            (HTTP_METHOD.to_string(), request.method.clone()),
            (HTTP_URI.to_string(), request.target()),
        ];
        observed.extend(
            request
                .query
                .iter()
                .map(|(name, value)| (format!("{HTTP_QUERY_PREFIX}{name}"), value.clone())),
        );
        Self {
            headers: Headers::of("http").text(request.headers.iter().cloned()),
            observed,
        }
    }

    /// What a far end took whole, carrying what the request said of its
    /// sender: what a loopback round holds it to.
    #[must_use]
    pub fn taken(self, mut taken: Taken) -> Taken {
        taken.observed.extend(self.observed);
        taken
    }

    /// `arrived`, carrying what the request said of its sender.
    #[must_use]
    pub fn on(self, arrived: Arrived) -> Arrived {
        arrived
            .with_headers(self.headers)
            .observing_all(self.observed)
    }
}

/// What a listener entered with a secure scheme is refused with: no
/// Receive Location riding on HTTP terminates TLS yet (open problem 61).
pub const NOT_TERMINATED: &str = "asks for TLS, which a Receive Location riding on HTTP does \
                                  not terminate yet, and is refused rather than served \
                                  without it";

/// Bind a Receive Location's listener at the address it was `entered`
/// with, read under the `schemes` its technology declares
/// (`net::Endpoint::parse_under`): in the clear where the scheme is a
/// plain one, and refused where it asks for TLS. A bare `host:port` a
/// program gives names no scheme and is bound as it is. The one rule every
/// technology riding on HTTP listens through, so none decides for itself
/// whether its address asked for TLS.
///
/// # Errors
/// Where the scheme asks for TLS — permanent, naming the plain address to
/// enter instead — the address is none of `schemes`, or the bind fails.
pub fn listen(entered: &str, schemes: &Schemes) -> Result<(TcpListener, String)> {
    let Ok(named) = Target::parse(entered) else {
        return socket::bind_tcp(entered);
    };
    let endpoint = Endpoint::parse_under(entered, schemes)?;
    if endpoint.secure() {
        // Scheme, authority and path: never the user information.
        let at = format!("{}{}", endpoint.address(), endpoint.path());
        let asked = named.scheme().to_ascii_lowercase();
        let plain = schemes.plain_twin(&asked).unwrap_or("http");
        return Err(TransportError::permanent(format!(
            "{asked}://{at} {NOT_TERMINATED}: enter it as {plain}://{at} to listen in the clear"
        )));
    }
    socket::bind_tcp(&endpoint.address())
}

/// Accept one request within `timeout`, with `timeout` on its reads, and
/// answer it `202` as it is taken: what the Loopback far end does.
///
/// # Errors
///
/// Where nothing connected within `timeout`, the connection failed, the
/// request was malformed, or the body was larger than `net::MAX_BODY`.
pub fn accept_one(listener: &TcpListener, timeout: Option<Duration>) -> Result<Taken> {
    serve_one_from(listener, timeout, |request, peer| {
        let at_once = Acknowledgement::at_most_once("answered 202 as it is taken");
        (
            arrived(request.clone(), peer, at_once).taken(),
            Response::new(ACCEPTED),
        )
    })?
}

/// Accept one connection on `listener`, with `timeout` on its reads, read
/// the one request it carries, answer it as `answer` says, and report what
/// `answer` made of it.
///
/// The far end every REST technology runs on loopback — s3, azure-blob,
/// google-pub-sub and seven more — accepted, split, read, answered and
/// wrote these same lines each until 2026-09-14. What a session does with a
/// request stays in the technology; taking one off a connection is HTTP's
/// (ADR-0044).
///
/// # Errors
/// Where the connection could not be accepted, broke, or sent nothing.
pub fn serve_one<T>(
    listener: &TcpListener,
    timeout: Option<Duration>,
    answer: impl FnOnce(&Request) -> (T, Response),
) -> Result<T> {
    serve_one_from(listener, timeout, |request, _| answer(request))
}

/// [`serve_one`], with the peer it serves handed to `answer`: an origin
/// that names who posted — AS2, AS4 — reads it here rather than accepting
/// the connection itself, which both did until 2026-09-27 because this
/// kept the peer to itself.
///
/// # Errors
/// As [`serve_one`].
pub fn serve_one_from<T>(
    listener: &TcpListener,
    timeout: Option<Duration>,
    answer: impl FnOnce(&Request, SocketAddr) -> (T, Response),
) -> Result<T> {
    // The wait for the connection is bounded as well as the reads. This did
    // a bare accept until 2026-09-21, so a far end whose near end never
    // connected waited for good, and a hang has no verdict.
    let (stream, peer) = socket::accept_tcp(listener, timeout)?;
    answer_on(stream, |request| answer(request, peer))
}

/// Read the one request a connection already accepted carries, in the
/// version it opens with, answer it as `answer` says, and report what
/// `answer` made of it.
///
/// For a server whose wait for a connection and whose reads are bounded
/// apart: a scrape endpoint waits for its scraper as long as it runs, and
/// bounds each read (`xmip-core-observe-prometheus`). The connection's own
/// timeouts are the caller's.
///
/// # Errors
/// Where the connection broke, sent nothing, or sent a malformed request.
pub fn answer_on<S: Read + Write, T>(
    mut stream: S,
    answer: impl FnOnce(&Request) -> (T, Response),
) -> Result<T> {
    let (h2, first) = sniff(&mut stream)?;
    let mut connection = Replayed::new(first, stream);
    if h2 {
        // One request, on a connection whose callers hold no Clock: its
        // frames in a span counted on the operating system's.
        let mut server = Server::handshake(connection, Box::new(|| SystemClock.monotonic_nanos()))?;
        let (id, request) = server
            .next_request()?
            .ok_or_else(|| protocol_error("an HTTP/2 connection that sent no request"))?;
        // One request is all this connection carries, and the client is
        // told before its answer: a client that keeps connections reads the
        // GOAWAY on its way to the answer and lets this one go, rather than
        // holding it open while the close below waits for it to.
        server.go_away()?;
        let (report, response) = answer(&request);
        server.respond(id, &response)?;
        server.close();
        return Ok(report);
    }
    let request = read_request(&mut BufReader::new(&mut connection))?
        .ok_or_else(|| protocol_error("a connection that sent no request"))?;
    let (report, response) = answer(&request);
    write_response(&mut connection, &response)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint;
    use net::Endpoint;

    #[test]
    fn a_secure_scheme_is_refused_naming_its_plain_twin_and_a_plain_one_listens() {
        const AS4: Schemes = Schemes {
            plain: &["http", "as4"],
            secure: &["https", "as4s"],
        };
        let refused = listen("AS4S://user@127.0.0.1:8443/msh", &AS4).expect_err("TLS");
        assert!(!refused.retryable, "{refused}");
        assert_eq!(
            refused.message,
            format!(
                "as4s://127.0.0.1:8443/msh {NOT_TERMINATED}: enter it as \
                 as4://127.0.0.1:8443/msh to listen in the clear"
            )
        );
        let https = listen("https://127.0.0.1:0", &AS4).expect_err("TLS");
        assert!(
            https.message.contains("enter it as http://127.0.0.1:0/"),
            "{https}"
        );
        let (_, plain) = listen("as4://127.0.0.1:0/msh", &AS4).expect("in the clear");
        assert!(plain.starts_with("127.0.0.1:"), "{plain}");
        let (_, bare) = listen("127.0.0.1:0", &AS4).expect("a bare address");
        assert!(bare.starts_with("127.0.0.1:"), "{bare}");
        assert!(
            listen("as2s://127.0.0.1:0", &AS4).is_err(),
            "not this technology's"
        );
    }

    #[test]
    fn one_request_is_served_with_what_the_session_answers() {
        let (listener, address) = socket::bind_tcp("127.0.0.1:0").expect("bind");
        let timeout = Some(Duration::from_secs(2));
        let far_end = std::thread::spawn(move || {
            let served = serve_one(&listener, timeout, |request| {
                (
                    request.method.clone(),
                    Response::new(201).body(&request.body),
                )
            });
            let closed = serve_one(&listener, timeout, |_| ((), Response::new(200)));
            (served, closed)
        });
        let at = Endpoint::parse(&format!("http://{address}")).expect("parsed");
        let stream = endpoint::connect(&at, timeout).expect("connect");
        let request = Request::new("PUT", "/orders").body(b"UNA");
        let answer = net::http::exchange(stream, &request).expect("answered");
        assert_eq!((answer.status, answer.body), (201, b"UNA".to_vec()));
        drop(endpoint::connect(&at, timeout).expect("connect"));
        let (served, closed) = far_end.join().expect("thread");
        assert_eq!(served.expect("served"), "PUT");
        assert!(closed.is_err(), "a connection that sent nothing");
    }

    #[test]
    fn a_connection_that_opens_with_the_preface_is_served_in_http_2() {
        let (listener, address) = socket::bind_tcp("127.0.0.1:0").expect("bind");
        let timeout = Some(Duration::from_secs(5));
        let far_end = std::thread::spawn(move || {
            serve_one(&listener, timeout, |request| {
                let answer = Response::new(200)
                    .body(&request.body)
                    .trailer("grpc-status", "0");
                (request.header_value("host").map(str::to_string), answer)
            })
        });
        let at = Endpoint::parse(&format!("http://{address}/orders")).expect("parsed");
        let request = Request::new("POST", at.path())
            .header("Host", &at.authority())
            .body(b"UNB");
        let answer = endpoint::Connections::new()
            .exchange(&at, timeout, endpoint::Offer::PriorKnowledge, &request)
            .expect("answered");
        assert_eq!((answer.status, answer.body.as_slice()), (200, &b"UNB"[..]));
        assert_eq!(answer.trailer_value("grpc-status"), Some("0"));
        let host = far_end.join().expect("thread").expect("served");
        assert_eq!(host.as_deref(), Some(address.as_str()));
    }
}
