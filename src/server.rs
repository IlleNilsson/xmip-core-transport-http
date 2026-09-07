//! Taking one request off a connection and answering it.

use std::io::{BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};

use transport::Arrived;
use transport::error::{Result, classify, protocol_error};
use transport::wire::{MAX_BODY, header, read_head};

/// What Xmip answers a caller.
///
/// `202 Accepted`, deliberately. Xmip has taken the Stream into custody and has
/// promised nothing else — which is exactly the state a Stream is in once the
/// arrival gate has passed and before the Journey exists. `200 OK` would claim
/// the work is done.
const ACCEPTED: &[u8] = b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";

/// Accept one request and answer it.
///
/// # Errors
///
/// Where the connection failed, the request was malformed, or the body was
/// larger than [`MAX_BODY`].
pub fn accept_one(listener: &TcpListener) -> Result<Arrived> {
    let (mut stream, peer) = listener
        .accept()
        .map_err(|e| classify("accepting a connection", &e))?;

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

/// How many bytes of body to expect.
///
/// No `Content-Length` means no body. That is not the same as a chunked
/// request, which this does not implement and would be a different reader.
fn body_length(head: &[String]) -> Result<usize> {
    let Some(value) = header(head, "content-length") else {
        return Ok(0);
    };

    let length: usize = value
        .parse()
        .map_err(|_| protocol_error(format!("a content-length that is not a number: {value}")))?;

    if length > MAX_BODY {
        return Err(protocol_error(format!(
            "a body of {length} bytes, over the {MAX_BODY} byte limit"
        )));
    }

    Ok(length)
}

fn read_body(reader: &mut impl Read, length: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0u8; length];

    reader
        .read_exact(&mut bytes)
        .map_err(|e| classify("reading the request body", &e))?;

    Ok(bytes)
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
    fn no_content_length_means_no_body() {
        assert_eq!(body_length(&head(&["POST / HTTP/1.1"])).expect("read"), 0);
    }

    #[test]
    fn a_content_length_that_is_not_a_number_is_refused() {
        let lines = head(&["POST / HTTP/1.1", "Content-Length: eight"]);

        assert!(body_length(&lines).is_err());
    }

    #[test]
    fn a_body_over_the_limit_is_refused_before_it_is_read() {
        // The point of checking the header rather than the read: a peer
        // claiming four gigabytes must not get four gigabytes allocated.
        let lines = head(&[
            "POST / HTTP/1.1",
            &format!("Content-Length: {}", MAX_BODY + 1),
        ]);

        assert!(body_length(&lines).is_err());
    }
}
