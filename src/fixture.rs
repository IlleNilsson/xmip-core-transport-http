//! The far end this crate's tests and its timing program both stand up,
//! written once (`test-support`; `doc/governance/rust-style.md` section
//! 5c): never a production build.

use std::io::BufReader;
use std::net::TcpListener;

use net::http::Response;
use transport::socket;

/// A far end that keeps every connection it accepts and answers every
/// request on it, HTTP/1.1 or HTTP/2 as the connection opens: how many
/// connections it accepted, and how many requests it answered.
///
/// # Panics
///
/// When a connection is not accepted, its first bytes cannot be read, or
/// an HTTP/1.1 answer cannot be written: a test's far end, failing it.
#[must_use]
pub fn keeping(listener: &TcpListener, connections: usize) -> (usize, usize) {
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
