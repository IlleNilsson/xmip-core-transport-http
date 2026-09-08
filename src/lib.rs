#![forbid(unsafe_code)]

//! Streams that arrive as HTTP request bodies. One request is one Stream.
//!
//! The pushed case **with a reply channel**, which is the distinction that
//! matters to custody: the caller is still holding the connection open, so a
//! Contract failure can be answered rather than only audited. UDP cannot do
//! that, and the two behave differently at the gate for that reason alone.
//!
//! ```text
//! target.rs   where a send is going
//! client.rs   writing the request, reading the answer
//! server.rs   taking one request off a connection
//! tls.rs      https, behind the `tls` feature
//! ```

pub mod client;
pub mod server;
pub mod target;

#[cfg(feature = "tls")]
pub mod tls;

use std::net::{TcpListener, TcpStream};

use transport::Arrived;
use transport::Directions;
use transport::Transport;
use transport::error::{Result, classify};
use transport::socket;

use target::HttpTarget;

pub struct HttpTransport {
    bind: String,
}

impl HttpTransport {
    #[must_use]
    pub fn new(bind: impl Into<String>) -> Self {
        Self { bind: bind.into() }
    }

    /// Bind and report the address actually assigned.
    ///
    /// Binding to port 0 lets the operating system choose, which is what a test
    /// wants and what an operator never does.
    ///
    /// # Errors
    ///
    /// Where the address is taken, malformed, or not permitted.
    pub fn bind(&self) -> Result<(TcpListener, String)> {
        socket::bind_tcp(&self.bind)
    }

    /// Take one request from an already-bound listener and answer it.
    ///
    /// # Errors
    ///
    /// As [`server::accept_one`].
    pub fn accept_one(&self, listener: &TcpListener) -> Result<Arrived> {
        server::accept_one(listener)
    }

    /// Send over TLS, or say why not.
    #[cfg(feature = "tls")]
    fn send_secure(target: &HttpTarget<'_>, tcp: TcpStream, bytes: &[u8]) -> Result<()> {
        let host = transport::wire::host_of(target.authority);
        let guarded = tls::client(host, tcp)?;

        client::exchange(guarded, target, bytes)
    }

    #[cfg(not(feature = "tls"))]
    #[allow(clippy::needless_pass_by_value)]
    fn send_secure(_target: &HttpTarget<'_>, tcp: TcpStream, _bytes: &[u8]) -> Result<()> {
        drop(tcp);

        Err(transport::error::protocol_error(
            "https was asked for and this build has no tls feature compiled in",
        ))
    }
}

impl Transport for HttpTransport {
    fn name(&self) -> &'static str {
        "http"
    }

    fn directions(&self) -> Directions {
        Directions::BOTH
    }

    fn receive(&self) -> Result<Vec<Arrived>> {
        let (listener, _) = self.bind()?;

        Ok(vec![self.accept_one(&listener)?])
    }

    fn send(&self, target: &str, bytes: &[u8]) -> Result<()> {
        let target = HttpTarget::parse(target)?;

        let tcp = TcpStream::connect(target.address())
            .map_err(|e| classify("connecting to the server", &e))?;

        if target.secure {
            return Self::send_secure(&target, tcp, bytes);
        }

        client::exchange(tcp, &target, bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_round_trip_carries_the_body_and_the_path() {
        let receiver = HttpTransport::new("127.0.0.1:0");
        let (listener, address) = receiver.bind().expect("binding");

        let sender = std::thread::spawn(move || {
            HttpTransport::new("127.0.0.1:0")
                .send(&format!("http://{address}/orders"), b"<order/>")
                .expect("sending");
        });

        let arrived = receiver.accept_one(&listener).expect("accepting");
        sender.join().expect("the sending thread panicked");

        assert_eq!(arrived.bytes, b"<order/>");
        assert!(arrived.origin_uri.starts_with("http://127.0.0.1:"));
        assert!(arrived.origin_uri.ends_with("/orders"));
    }

    #[test]
    fn an_http_target_without_a_scheme_is_rejected() {
        let failure = HttpTransport::new("127.0.0.1:0")
            .send("example.com/orders", b"")
            .expect_err("no scheme");

        assert!(!failure.retryable);
    }

    #[cfg(not(feature = "tls"))]
    #[test]
    fn https_without_the_tls_feature_says_so_rather_than_sending_in_the_clear() {
        // The failure that matters. Silently downgrading to http would put a
        // partner's data on the wire unencrypted because a build flag was
        // missing.
        let receiver = HttpTransport::new("127.0.0.1:0");
        let (_listener, address) = receiver.bind().expect("binding");

        let failure = HttpTransport::new("127.0.0.1:0")
            .send(&format!("https://{address}/orders"), b"secret")
            .expect_err("no tls in this build");

        assert!(failure.message.contains("tls"));
        assert!(!failure.retryable);
    }
}
