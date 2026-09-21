//! Taking one request off a connection and answering it.

use std::io::{BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use transport::Arrived;
use transport::error::{Result, classify, protocol_error};
use transport::socket;
use transport::wire::read_head;

use crate::message::{self, Request, Response, body_length, read_body};

/// What Xmip answers a caller.
///
/// `202 Accepted`, deliberately. Xmip has taken the Stream into custody and has
/// promised nothing else — which is exactly the state a Stream is in once the
/// arrival gate has passed and before the Journey exists. `200 OK` would claim
/// the work is done.
const ACCEPTED: &[u8] = b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// Accept one request within `timeout`, with `timeout` on its reads, and
/// answer it. `None` waits forever, which is what a listening Receive
/// Location does.
///
/// # Errors
///
/// Where nothing connected within `timeout`, the connection failed, the
/// request was malformed, or the body was larger than
/// [`transport::wire::MAX_BODY`].
pub fn accept_one(listener: &TcpListener, timeout: Option<Duration>) -> Result<Arrived> {
    // The wait for the connection is bounded as well as the reads. This did
    // a bare accept until 2026-09-21, so a far end whose near end never
    // connected waited for good, and a hang has no verdict.
    let (mut stream, peer) = socket::accept_tcp(listener, timeout)?;

    let mut reader = BufReader::new(
        stream
            .try_clone()
            .map_err(|e| classify("cloning the connection", &e))?,
    );

    let head = read_head(&mut reader)?;
    let path = request_path(&head)?;
    let bytes = read_body(&mut reader, body_length(&head)?)?;

    answer(&mut stream)?;

    Ok(Arrived::new(format!("http://{peer}{path}"), bytes))
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
    let (stream, _) = socket::accept_tcp(listener, timeout)?;
    let (mut reader, mut writer) = socket::split(stream)?;
    let request = message::read_request(&mut reader)?
        .ok_or_else(|| protocol_error("a connection that sent no request"))?;
    let (report, response) = answer(&request);
    message::write_response(&mut writer, &response)?;
    Ok(report)
}

/// The path out of the request line: `POST /orders HTTP/1.1`.
fn request_path(head: &[String]) -> Result<String> {
    let request_line = head
        .first()
        .ok_or_else(|| protocol_error("a connection that sent no request"))?;

    Ok(request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .to_string())
}

fn answer(stream: &mut TcpStream) -> Result<()> {
    stream
        .write_all(ACCEPTED)
        .map_err(|e| classify("answering the request", &e))?;

    stream
        .flush()
        .map_err(|e| classify("flushing the answer", &e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoint;

    fn head(lines: &[&str]) -> Vec<String> {
        lines.iter().map(|line| (*line).to_string()).collect()
    }

    #[test]
    fn the_path_comes_from_the_request_line() {
        assert_eq!(
            request_path(&head(&["POST /orders HTTP/1.1"])).expect("parsed"),
            "/orders"
        );
    }

    #[test]
    fn a_request_line_without_a_path_defaults_to_root() {
        assert_eq!(request_path(&head(&["POST"])).expect("parsed"), "/");
    }

    #[test]
    fn a_connection_that_sent_nothing_is_a_protocol_error() {
        assert!(request_path(&[]).is_err());
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
        let stream = endpoint::connect(&format!("http://{address}"), timeout).expect("connect");
        let request = Request::new("PUT", "/orders").body(b"UNA");
        let answer = message::exchange(stream, &request).expect("answered");
        assert_eq!((answer.status, answer.body), (201, b"UNA".to_vec()));
        drop(endpoint::connect(&format!("http://{address}"), timeout).expect("connect"));
        let (served, closed) = far_end.join().expect("thread");
        assert_eq!(served.expect("served"), "PUT");
        assert!(closed.is_err(), "a connection that sent nothing");
    }
}
