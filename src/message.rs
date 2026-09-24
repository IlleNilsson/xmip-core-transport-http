//! Plain HTTP/1.1 on the wire: a request and its answer, `Content-Length`
//! framed, and `Connection: close` unless the message names its own
//! `Connection` — `WebDAV` keeps its connection for the next method, and
//! says `keep-alive` on both sides.
//!
//! What every REST API over HTTP is underneath its signature — S3, Azure
//! Blob, Cloud Storage — and what their far ends read, and the one HTTP
//! codec the technologies riding on HTTP write and read with: `WebDAV`
//! carried its own until 2026-09-24. Xmip's side writes a request and reads
//! the answer; a technology's session reads a request and writes an answer.
//! Both halves are here so the two cannot drift: a header written one way
//! is read the same way.
//!
//! Chunked transfer encoding is not read, and an answer that uses it is
//! refused rather than misread. An answer carrying no `Content-Length`
//! ends where the connection closes; a 204 or a 304 has no body at all.

use std::io::{BufRead, BufReader, Read, Write};

use transport::error::{Result, TransportError, classify, protocol_error};
use transport::wire::{MAX_BODY, header, read_head};

use net::percent::{decode, encode};

/// One request, as Xmip's side builds it and the far end reads it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    /// The path as it travels: percent-encoded, opening with `/`.
    pub path: String,
    /// The query as names and values, before encoding.
    pub query: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    #[must_use]
    pub fn new(method: &str, path: impl Into<String>) -> Self {
        Self {
            method: method.to_string(),
            path: path.into(),
            ..Self::default()
        }
    }

    #[must_use]
    pub fn query(mut self, name: &str, value: &str) -> Self {
        self.query.push((name.to_string(), value.to_string()));
        self
    }

    #[must_use]
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    #[must_use]
    pub fn body(mut self, bytes: &[u8]) -> Self {
        self.body = bytes.to_vec();
        self
    }

    /// One header's value, however it was capitalised.
    #[must_use]
    pub fn header_value(&self, name: &str) -> Option<&str> {
        find(&self.headers, name)
    }

    /// One query parameter's value.
    #[must_use]
    pub fn query_value(&self, name: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(candidate, _)| candidate == name)
            .map(|(_, value)| value.as_str())
    }

    /// The request target as the request line carries it: the path, and the
    /// query encoded and joined.
    #[must_use]
    pub fn target(&self) -> String {
        if self.query.is_empty() {
            return self.path.clone();
        }
        let query: Vec<String> = self
            .query
            .iter()
            .map(|(name, value)| format!("{}={}", encode(name, false), encode(value, false)))
            .collect();
        format!("{}?{}", self.path, query.join("&"))
    }
}

/// One answer.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    #[must_use]
    pub fn new(status: u16) -> Self {
        Self {
            status,
            ..Self::default()
        }
    }

    #[must_use]
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    #[must_use]
    pub fn body(mut self, bytes: &[u8]) -> Self {
        self.body = bytes.to_vec();
        self
    }

    /// One header's value, however it was capitalised.
    #[must_use]
    pub fn header_value(&self, name: &str) -> Option<&str> {
        find(&self.headers, name)
    }

    /// The body as text, lossily.
    #[must_use]
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// Whether `status` says come back.
///
/// 5xx is the server's problem and may well pass on a second attempt. 4xx
/// is ours and will not — with two documented exceptions, 408 Request
/// Timeout and 429 Too Many Requests, which say in that range exactly what
/// 5xx says.
#[must_use]
pub const fn retryable(status: u16) -> bool {
    status >= 500 || status == 408 || status == 429
}

/// A 2xx answer as it is; anything else as a failure naming `service`, the
/// status and the code `code` reads from the body, retryable where the
/// status says come back or `retryable_code` says the code does.
///
/// Eight technologies each wrote the status rule beside their own body
/// reader until 2026-09-14. The rule is HTTP's and lives here; the reader
/// and the one extra code — `SlowDown`, `ServerBusy`, `Throttling` — stay
/// the technology's, which is the dialect ADR-0044 leaves in place.
///
/// # Errors
/// Where the status is not 2xx.
pub fn judge(
    service: &str,
    response: Response,
    code: impl FnOnce(&Response) -> String,
    retryable_code: impl FnOnce(&str) -> bool,
) -> Result<Response> {
    if (200..300).contains(&response.status) {
        return Ok(response);
    }
    let code = code(&response);
    let retryable = retryable(response.status) || retryable_code(&code);
    Err(TransportError {
        message: format!("{service} answered {} {code}", response.status),
        retryable,
    })
}

/// Write `request` and read the answer, on a connection that closes after.
///
/// # Errors
/// Where the connection broke, or the answer is not HTTP Xmip can read.
pub fn exchange<S: Read + Write>(mut stream: S, request: &Request) -> Result<Response> {
    write_request(&mut stream, request)?;
    read_response(&mut BufReader::new(stream))
}

/// Write `request`, written and flushed: its request line, its headers,
/// the length its body has, and `Connection: close` unless it names its
/// own `Connection`.
///
/// # Errors
/// Where the connection broke.
pub fn write_request(writer: &mut impl Write, request: &Request) -> Result<()> {
    let first = format!("{} {} HTTP/1.1", request.method, request.target());
    write_message(
        writer,
        &first,
        &request.headers,
        &request.body,
        "the request",
    )
}

/// Read one answer.
///
/// # Errors
/// A status line Xmip cannot read, a chunked body, a body over
/// [`MAX_BODY`], or a connection that closed before answering.
pub fn read_response(reader: &mut impl BufRead) -> Result<Response> {
    let head = read_head(reader)?;
    let status = head
        .first()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| protocol_error("an answer with no status line"))?;
    let chunked = header(&head, "transfer-encoding").is_some_and(|codings| {
        codings
            .split(',')
            .any(|coding| coding.trim().eq_ignore_ascii_case("chunked"))
    });
    if chunked {
        return Err(protocol_error(
            "a chunked answer, which this transport does not read",
        ));
    }
    let body = if status == 204 || status == 304 {
        Vec::new()
    } else if header(&head, "content-length").is_some() {
        read_body(reader, body_length(&head)?)?
    } else {
        let mut body = Vec::new();
        reader
            .read_to_end(&mut body)
            .map_err(|e| classify("reading the answer body", &e))?;
        body
    };
    Ok(Response {
        status,
        headers: headers_of(&head),
        body,
    })
}

/// The far end's side: one request off a connection, or `None` where the
/// peer closed without sending one.
///
/// # Errors
/// Where the connection broke, the request line is unreadable, or the body
/// is over what Xmip will read.
pub fn read_request(reader: &mut impl BufRead) -> Result<Option<Request>> {
    let head = read_head(reader)?;
    let Some(line) = head.first() else {
        return Ok(None);
    };
    let mut words = line.split_whitespace();
    let (Some(method), Some(target)) = (words.next(), words.next()) else {
        return Err(protocol_error(format!(
            "a request line Xmip cannot read: {line}"
        )));
    };
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let query = query
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            (decode(name), decode(value))
        })
        .collect();
    let body = read_body(reader, body_length(&head)?)?;
    Ok(Some(Request {
        method: method.to_string(),
        path: path.to_string(),
        query,
        headers: headers_of(&head),
        body,
    }))
}

/// The far end's answer, written and flushed, `Connection: close` unless
/// it names its own `Connection`.
///
/// # Errors
/// Where the connection broke.
pub fn write_response(writer: &mut impl Write, response: &Response) -> Result<()> {
    let first = format!("HTTP/1.1 {} {}", response.status, reason(response.status));
    write_message(
        writer,
        &first,
        &response.headers,
        &response.body,
        "the answer",
    )
}

/// One message: its first line, its headers, the length, the connection
/// closing unless a header says otherwise, the blank line and the body.
fn write_message(
    writer: &mut impl Write,
    first: &str,
    headers: &[(String, String)],
    body: &[u8],
    what: &str,
) -> Result<()> {
    let lines: Vec<String> = headers
        .iter()
        .map(|(name, value)| format!("{name}: {value}\r\n"))
        .collect();
    let lines = lines.concat();
    let close = if find(headers, "connection").is_none() {
        "Connection: close\r\n"
    } else {
        ""
    };
    let head = format!(
        "{first}\r\n{lines}Content-Length: {}\r\n{close}\r\n",
        body.len()
    );
    writer
        .write_all(head.as_bytes())
        .map_err(|e| classify(&format!("writing {what} head"), &e))?;
    writer
        .write_all(body)
        .map_err(|e| classify(&format!("writing {what} body"), &e))?;
    writer
        .flush()
        .map_err(|e| classify(&format!("flushing {what}"), &e))
}

fn headers_of(head: &[String]) -> Vec<(String, String)> {
    head.iter()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .map(|(name, value)| (name.trim().to_string(), value.trim().to_string()))
        .collect()
}

fn find<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

/// How many bytes of body to expect, checked against [`MAX_BODY`] before
/// anything is allocated.
///
/// No `Content-Length` means no body. That is not the same as a chunked
/// request, which this does not implement and would be a different reader.
pub(crate) fn body_length(head: &[String]) -> Result<usize> {
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

pub(crate) fn read_body(reader: &mut impl Read, length: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0u8; length];
    reader
        .read_exact(&mut bytes)
        .map_err(|e| classify("reading the body", &e))?;
    Ok(bytes)
}

/// The phrase a status is written with; one the table does not know is
/// written `Status`, which a reader ignores.
#[must_use]
pub const fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        207 => "Multi-Status",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        409 => "Conflict",
        423 => "Locked",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        _ => "Status",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A stream that records what is written and serves a canned answer.
    struct Both(Vec<u8>, std::io::Cursor<Vec<u8>>);

    impl Read for Both {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.1.read(buf)
        }
    }

    impl Write for Both {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_request_round_trips_through_its_own_reader() {
        let request = Request::new("PUT", "/bucket/in/1%20a.edi")
            .query("prefix", "in/")
            .header("Host", "s3.local")
            .body(b"UNA");
        let answer = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok".to_vec();
        let mut both = Both(Vec::new(), std::io::Cursor::new(answer));
        let response = exchange(&mut both, &request).expect("exchanged");
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"ok");
        let written = both.0;
        assert!(written.starts_with(b"PUT /bucket/in/1%20a.edi?prefix=in%2F HTTP/1.1\r\n"));
        let read = read_request(&mut &written[..]).expect("read").expect("one");
        assert_eq!(read.method, "PUT");
        assert_eq!(read.path, "/bucket/in/1%20a.edi");
        assert_eq!(read.query_value("prefix"), Some("in/"));
        assert_eq!(read.query_value("absent"), None);
        assert_eq!(read.header_value("host"), Some("s3.local"));
        assert_eq!(read.body, b"UNA");
        assert!(read_request(&mut &b""[..]).expect("closed").is_none());
        assert!(read_request(&mut &b"GET\r\n\r\n"[..]).is_err());
    }

    #[test]
    fn a_connection_kept_carries_the_next_message_and_no_body_is_read_past_a_204() {
        let kept = Request::new("PROPFIND", "/orders")
            .header("Host", "dav.example")
            .header("Connection", "keep-alive");
        let mut written = Vec::new();
        write_request(&mut written, &kept).expect("written");
        write_request(&mut written, &Request::new("GET", "/orders/1")).expect("written");
        let text = String::from_utf8_lossy(&written).into_owned();
        assert_eq!(text.matches("Connection:").count(), 2, "{text}");
        assert!(text.contains("Connection: keep-alive\r\n"), "{text}");
        let mut reader = &written[..];
        let first = read_request(&mut reader).expect("read").expect("one");
        assert_eq!(first.method, "PROPFIND");
        let second = read_request(&mut reader).expect("read").expect("two");
        assert_eq!(second.path, "/orders/1");
        let mut answers = Vec::new();
        let open = Response::new(204).header("Connection", "keep-alive");
        write_response(&mut answers, &open).expect("written");
        write_response(&mut answers, &Response::new(207).body(b"<a/>")).expect("written");
        assert!(answers.starts_with(b"HTTP/1.1 204 No Content\r\n"));
        let mut reader = &answers[..];
        assert!(read_response(&mut reader).expect("204").body.is_empty());
        let multi = read_response(&mut reader).expect("207");
        assert_eq!((multi.status, multi.body.as_slice()), (207, &b"<a/>"[..]));
        let gzip = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n";
        assert!(read_response(&mut &gzip[..]).is_err(), "chunked last");
        assert!(read_response(&mut &b""[..]).is_err(), "closed early");
    }

    #[test]
    fn an_answer_is_written_as_it_is_read_back() {
        let mut written = Vec::new();
        write_response(&mut written, &Response::new(404).body(b"<Error/>")).expect("written");
        let response = read_response(&mut &written[..]).expect("read");
        assert_eq!(response.status, 404);
        assert_eq!(response.body, b"<Error/>");
        assert!(read_response(&mut &b"nonsense\r\n\r\n"[..]).is_err());
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n";
        assert!(read_response(&mut &chunked[..]).is_err());
        let unframed = b"HTTP/1.1 200 OK\r\n\r\nto the end";
        assert_eq!(
            read_response(&mut &unframed[..]).expect("read").body,
            b"to the end"
        );
        let over = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY + 1
        );
        assert!(read_response(&mut over.as_bytes()).is_err());
    }

    fn head(lines: &[&str]) -> Vec<String> {
        lines.iter().map(|line| (*line).to_string()).collect()
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

    #[test]
    fn a_success_is_any_two_hundred_and_the_two_client_codes_that_mean_try_again_retry() {
        assert!(!retryable(200) && !retryable(299) && !retryable(404));
        assert!(retryable(503) && retryable(408) && retryable(429));
        let code = |answer: &Response| answer.text();
        assert_eq!(
            judge("S3", Response::new(204), code, |_| false)
                .expect("ok")
                .status,
            204
        );
        let refused = judge("S3", Response::new(403).body(b"Denied"), code, |_| false)
            .expect_err("forbidden");
        assert_eq!(refused.message, "S3 answered 403 Denied");
        assert!(!refused.retryable);
        assert!(
            judge("S3", Response::new(503), code, |_| false)
                .expect_err("server")
                .retryable
        );
        let slow = judge("S3", Response::new(400).body(b"SlowDown"), code, |c| {
            c == "SlowDown"
        })
        .expect_err("slow down");
        assert!(slow.retryable, "the technology's own code is honored");
    }
}
