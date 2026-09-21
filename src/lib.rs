#![forbid(unsafe_code)]

//! Streams that arrive as HTTP request bodies. One request is one Stream.
//!
//! The pushed case **with a reply channel**, which is the distinction that
//! matters to custody: the caller is still holding the connection open, so a
//! Contract failure can be answered rather than only audited. UDP cannot do
//! that, and the two behave differently at the gate for that reason alone.
//!
//! ```text
//! target.rs     where a send is going
//! client.rs     writing the request, reading the answer
//! server.rs     taking one request off a connection, and serving one to
//!               a technology's session
//! tls.rs        https, behind the `tls` feature
//! message.rs    one request and its answer, both directions, and the
//!               judgement of an answer, for the technologies that ride
//!               on HTTP
//! endpoint.rs   an `http://` or `https://` endpoint and a connection to it
//! percent.rs    percent-encoding, RFC 3986's unreserved set
//! date.rs       the moment a header carries: RFC 1123, and x-amz-date
//! signature.rs  a signature as text: hex, and the constant-time compare
//! sigv4.rs      AWS Signature Version 4, for s3, aws-sqs, aws-sns, aws-kinesis
//! query.rs      the AWS Query API, for aws-sqs and aws-sns
//! sas.rs        Azure's Shared Access Signature, for azure-service-bus and
//!               azure-event-hubs
//! namespace.rs  what a servicebus.windows.net namespace answers when it
//!               refuses, for the same two
//! ```
//!
//! `message`, `endpoint` and `percent` moved here from the object-store
//! transports on 2026-09-09, where each had carried an identical copy; the
//! signers, the Query API, the header dates and the judgement followed on
//! 2026-09-14, when aws-sqs was found importing s3, aws-sns and aws-kinesis
//! importing aws-sqs, and azure-event-hubs importing azure-service-bus. A
//! technology that rides on HTTP shares HTTP's helpers through the http
//! technology, never by copying a sibling's file and never by importing a
//! sibling (ADR-0044).

pub mod client;
pub mod date;
pub mod endpoint;
pub mod message;
pub mod namespace;
pub mod percent;
pub mod query;
pub mod sas;
pub mod server;
pub mod signature;
pub mod sigv4;
pub mod target;

#[cfg(feature = "tls")]
pub mod tls;

use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use transport::Arrived;
use transport::Directions;
use transport::Transport;
use transport::error::Result;
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};
use transport::socket;

use target::HttpTarget;

#[derive(Clone)]
pub struct HttpTransport {
    bind: String,
    timeout: Option<Duration>,
}

impl HttpTransport {
    #[must_use]
    pub fn new(bind: impl Into<String>) -> Self {
        Self {
            bind: bind.into(),
            timeout: None,
        }
    }

    /// Give up on a connection that does not arrive, or stops sending, as
    /// `TcpTransport` does.
    #[must_use]
    pub const fn timing_out_after(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
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
        server::accept_one(listener, self.timeout)
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

        // The connect is bounded as well as the reads. This was a bare
        // connect until 2026-09-21, which waits on the operating system's
        // schedule, and longer still on a machine out of ephemeral ports.
        let tcp = socket::connect_tcp(&target.address(), self.timeout)?;

        if target.secure {
            return Self::send_secure(&target, tcp, bytes);
        }

        client::exchange(tcp, &target, bytes)
    }
}

impl HttpTransport {
    /// Both ends on this machine: an ephemeral local port, the loopback
    /// timeout on the accept, the connect and the reads.
    #[must_use]
    pub fn loopback() -> Self {
        Self::new("127.0.0.1:0").timing_out_after(LOOPBACK_TIMEOUT)
    }
}

/// A bound listener waiting for its one request.
struct Listening {
    transport: HttpTransport,
    listener: TcpListener,
    address: String,
}

impl FarEnd for Listening {
    fn address(&self) -> &str {
        &self.address
    }

    fn take_one(self: Box<Self>) -> Result<Arrived> {
        self.transport.accept_one(&self.listener)
    }
}

impl Loopback for HttpTransport {
    fn far_end(&self) -> Result<Box<dyn FarEnd>> {
        let (listener, address) = self.bind()?;
        Ok(Box::new(Listening {
            transport: self.clone(),
            listener,
            address,
        }))
    }

    fn send_to(&self, address: &str, payload: &[u8]) -> Result<()> {
        Self::loopback().send(&format!("http://{address}/round-trip"), payload)
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
