//! Writing a request and reading the answer.

use std::io::{BufRead, BufReader, Read, Write};

use transport::error::{Result, TransportError, classify, protocol_error};

use super::message::retryable;
use super::target::HttpTarget;

/// Write a request and read back the status, over anything that reads and
/// writes.
///
/// Generic over the stream so plaintext and TLS take the same path. A protocol
/// implemented twice is a protocol that behaves two ways.
///
/// # Errors
///
/// Where the connection failed, the status line was unreadable, or the server
/// answered outside the 2xx range.
pub fn exchange<S: Read + Write>(
    mut stream: S,
    target: &HttpTarget<'_>,
    bytes: &[u8],
) -> Result<()> {
    write_request(&mut stream, target, bytes)?;

    let code = read_status(&mut BufReader::new(stream))?;

    judge(code)
}

fn write_request<S: Write>(stream: &mut S, target: &HttpTarget<'_>, bytes: &[u8]) -> Result<()> {
    let head = format!(
        "POST {} HTTP/1.1\r\n\
         Host: {}\r\n\
         Content-Type: application/octet-stream\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n",
        target.path,
        target.authority,
        bytes.len()
    );

    stream
        .write_all(head.as_bytes())
        .map_err(|e| classify("writing the request head", &e))?;

    stream
        .write_all(bytes)
        .map_err(|e| classify("writing the request body", &e))?;

    stream
        .flush()
        .map_err(|e| classify("flushing the request", &e))
}

fn read_status(reader: &mut impl BufRead) -> Result<u16> {
    let mut status = String::new();

    reader
        .read_line(&mut status)
        .map_err(|e| classify("reading the status line", &e))?;

    status
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| protocol_error(format!("a status line Xmip cannot read: {}", status.trim())))
}

/// Whether the answer was a success, and whether a failure is worth repeating
/// — the status rule [`retryable`] states, which every technology riding on
/// HTTP judges by.
fn judge(code: u16) -> Result<()> {
    if (200..300).contains(&code) {
        return Ok(());
    }

    Err(TransportError {
        message: format!("the server answered {code}"),
        retryable: retryable(code),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_success_is_any_two_hundred() {
        assert!(judge(200).is_ok());
        assert!(judge(201).is_ok());
        assert!(judge(202).is_ok());
        assert!(judge(299).is_ok());
    }

    #[test]
    fn a_server_failure_is_worth_repeating_and_a_client_one_is_not() {
        assert!(judge(503).expect_err("server").retryable);
        assert!(!judge(404).expect_err("client").retryable);
    }

    #[test]
    fn the_two_client_codes_that_mean_try_again_are_retryable() {
        // 408 Request Timeout and 429 Too Many Requests both say, in the 4xx
        // range, exactly what 5xx says: come back.
        assert!(judge(408).expect_err("timeout").retryable);
        assert!(judge(429).expect_err("rate limited").retryable);
    }

    #[test]
    fn a_status_line_xmip_cannot_read_is_a_protocol_error() {
        let failure = read_status(&mut &b"not a status line\r\n"[..]).expect_err("unreadable");

        assert!(!failure.retryable);
    }

    #[test]
    fn the_request_carries_the_host_and_the_length() {
        let target = HttpTarget::parse("http://example.com:8080/orders").expect("parsed");
        let mut written = Vec::new();

        write_request(&mut written, &target, b"<order/>").expect("written");

        let text = String::from_utf8(written).expect("utf-8");

        assert!(text.starts_with("POST /orders HTTP/1.1\r\n"));
        assert!(text.contains("Host: example.com:8080\r\n"));
        assert!(text.contains("Content-Length: 8\r\n"));
        assert!(text.ends_with("<order/>"));
    }
}
