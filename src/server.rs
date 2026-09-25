//! Taking one request off a connection and answering it.
//!
//! The request is read and the answer written by `net::http`, the one
//! HTTP/1.1 codec; what is the transport's is the connection accepted
//! within its timeout, what a Receive Location answers, and the Stream
//! that arrived.

use std::net::{SocketAddr, TcpListener};
use std::time::Duration;

use net::http::{Request, Response, read_request, write_response};
use transport::Arrived;
use transport::error::{Result, protocol_error};
use transport::socket;

/// What Xmip answers a caller.
///
/// `202 Accepted`, deliberately. Xmip has taken the Stream into custody and has
/// promised nothing else — which is exactly the state a Stream is in once the
/// arrival gate has passed and before the Journey exists. `200 OK` would claim
/// the work is done.
const ACCEPTED: u16 = 202;

/// Accept one request within `timeout`, with `timeout` on its reads, and
/// answer it. `None` waits forever, which is what a listening Receive
/// Location does.
///
/// # Errors
///
/// Where nothing connected within `timeout`, the connection failed, the
/// request was malformed, or the body was larger than `net::http::MAX_BODY`.
pub fn accept_one(listener: &TcpListener, timeout: Option<Duration>) -> Result<Arrived> {
    let ((target, bytes), peer) = take_one(listener, timeout, |request| {
        (
            (request.target(), request.body.clone()),
            Response::new(ACCEPTED),
        )
    })?;

    Ok(Arrived::new(format!("http://{peer}{target}"), bytes))
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
    take_one(listener, timeout, answer).map(|(report, _)| report)
}

/// [`serve_one`], and the peer it served.
fn take_one<T>(
    listener: &TcpListener,
    timeout: Option<Duration>,
    answer: impl FnOnce(&Request) -> (T, Response),
) -> Result<(T, SocketAddr)> {
    // The wait for the connection is bounded as well as the reads. This did
    // a bare accept until 2026-09-21, so a far end whose near end never
    // connected waited for good, and a hang has no verdict.
    let (stream, peer) = socket::accept_tcp(listener, timeout)?;
    let (mut reader, mut writer) = socket::split(stream)?;
    let request = read_request(&mut reader)?
        .ok_or_else(|| protocol_error("a connection that sent no request"))?;
    let (report, response) = answer(&request);
    write_response(&mut writer, &response)?;
    Ok((report, peer))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint;
    use net::Endpoint;

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
}
