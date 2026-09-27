#![forbid(unsafe_code)]

//! Streams that arrive as HTTP request bodies. One request is one Stream.
//!
//! The pushed case **with a reply channel**, which is the distinction that
//! matters to custody: the caller is still holding the connection open, so a
//! Contract failure can be answered rather than only audited. UDP cannot do
//! that, and the two behave differently at the gate for that reason alone.
//!
//! ```text
//! endpoint.rs   a connection to an `http://` or `https://` endpoint, TLS
//!               behind the `tls` feature, and the version it speaks
//! server.rs     taking one request off a connection, HTTP/2 or HTTP/1.1,
//!               and serving one to a technology's session
//! status.rs     the judgement of an answer's status, for the
//!               technologies that ride on HTTP
//! date.rs       the moment a header carries: RFC 1123
//! event_wire.rs
//!               the event capability's webhook: a `WireEvent` posted as
//!               the HTTP binding says, and read back off a request
//! ```
//!
//! **HTTP/2 or HTTP/1.1, per connection.** A Send Location offers `h2`
//! and `http/1.1` by ALPN over TLS and speaks what the server selects; in
//! the clear it speaks HTTP/2 only where it is configured to
//! ([`HttpTransport::speaking_h2c`], prior knowledge — RFC 9113 removed
//! the `Upgrade`), and HTTP/1.1 otherwise. A Receive Location, and the
//! Loopback far end, serve either: a connection that opens with HTTP/2's
//! preface is answered in HTTP/2. The technologies riding on HTTP connect
//! with [`endpoint::connect`], which offers nothing, and speak HTTP/1.1
//! through `net::http` unchanged.
//!
//! The request and its answer, both halves, and the exchange of one for
//! the other are `net::http`'s and `net::http2`'s, and the URL a Location
//! names is read by `net::Endpoint`, in `xmip-core-library-net`: one codec
//! per version for the transport, the technologies riding on it and the
//! capabilities that ask a service beside them. This crate carried a
//! second HTTP/1.1 codec, which refused
//! a chunked answer, a third writer to send a Stream, and its own URL
//! reader, `HttpTarget`, until 2026-09-25.
//!
//! `message` and `endpoint` moved here from the object-store transports on
//! 2026-09-09, where each had carried an identical copy; the header dates
//! and the judgement followed on 2026-09-14. A technology that rides on
//! HTTP shares HTTP's helpers through the http technology, never by copying
//! a sibling's file and never by importing a sibling (ADR-0044).
//! Percent-encoding came with them and left on 2026-09-24 for
//! `xmip-core-library-net`, beside the authority, where the identifier and
//! the form shape that also write it reach it; a technology riding on HTTP
//! calls `net::percent` directly.
//!
//! What one vendor speaks over HTTP is that vendor's, not HTTP's: Signature
//! Version 4 and the AWS Query API, and Azure's Shared Access Signature and
//! the answers of a Service Bus namespace, came here on 2026-09-14 and left
//! on the owner's ruling of 2026-09-22 for `xmip-core-transport-aws` and
//! `xmip-core-transport-azure`, which ride on this crate.

pub mod date;
pub mod endpoint;
pub mod event_wire;
pub mod server;
pub mod status;

use std::net::TcpListener;
use std::time::Duration;

use transport::Arrived;
use transport::Configured;
use transport::Directions;
use transport::Transport;
use transport::error::Result;
use transport::listening::Listening;
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};
use transport::socket;

use net::Endpoint;
use net::http::Request;
use xcore::settings::{Applies, Kind, Presence, Read, Setting, Settings};

#[derive(Clone)]
pub struct HttpTransport {
    bind: String,
    timeout: Option<Duration>,
    h2c: bool,
}

impl HttpTransport {
    #[must_use]
    pub fn new(bind: impl Into<String>) -> Self {
        Self {
            bind: bind.into(),
            timeout: None,
            h2c: false,
        }
    }

    /// Speak HTTP/2 to an `http://` endpoint by prior knowledge (`h2c`),
    /// where the service is known to; over TLS the version is agreed by
    /// ALPN whatever this says.
    #[must_use]
    pub const fn speaking_h2c(mut self) -> Self {
        self.h2c = true;
        self
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
        let endpoint = Endpoint::parse(target)?;
        let request = Request::new("POST", endpoint.path())
            .header("Host", &endpoint.authority())
            .header("Content-Type", "application/octet-stream")
            .body(bytes);

        // The connect is bounded as well as the reads. This was a bare
        // connect until 2026-09-21, which waits on the operating system's
        // schedule, and longer still on a machine out of ephemeral ports.
        let answer = endpoint::exchange(&endpoint, self.timeout, self.h2c, &request)?;

        status::judge(
            "the server",
            answer,
            |answer| answer.reason.clone(),
            |_| false,
        )
        .map(|_| ())
    }
}

impl Configured for HttpTransport {
    /// The address is where a Receive Location listens; a Send Location
    /// posts to the URL its target names.
    const SETTINGS: &'static Settings = &Settings {
        technology: env!("CARGO_PKG_NAME"),
        settings: &[
            Setting {
                name: "h2c",
                kind: Kind::Boolean,
                presence: Presence::Optional,
                meaning: "Whether HTTP/2 is spoken to an http:// endpoint by prior knowledge; \
                          HTTP/1.1 in the clear when left out.",
                applies: Applies::Send,
            },
            Setting {
                name: "timeout",
                kind: Kind::Duration,
                presence: Presence::Optional,
                meaning: "How long a connection is waited for, accepted or opened, and how \
                          long one that stops sending is waited on; unbounded when left out.",
                applies: Applies::Both,
            },
        ],
    };

    fn configured(address: &str, settings: &Read) -> Result<Self> {
        let mut transport = Self::new(address);
        if settings.optional_boolean("h2c") == Some(true) {
            transport = transport.speaking_h2c();
        }
        if let Some(timeout) = settings.optional_duration("timeout") {
            transport = transport.timing_out_after(timeout);
        }
        Ok(transport)
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

impl Loopback for HttpTransport {
    /// A bound listener waiting for its one request.
    fn far_end(&self) -> Result<Box<dyn FarEnd>> {
        let transport = self.clone();
        Ok(Box::new(Listening::new(
            move |listener: &TcpListener| transport.accept_one(listener),
            self.bind()?,
        )))
    }

    fn send_to(&self, address: &str, payload: &[u8]) -> Result<()> {
        Self::loopback().send(&format!("http://{address}/round-trip"), payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_declares_its_settings_and_reads_through_them() {
        use xcore::settings::Given;
        assert_eq!(HttpTransport::SETTINGS.problems(), Vec::<String>::new());
        let given = [
            ("h2c".to_string(), Given::Boolean(true)),
            ("timeout".to_string(), Given::Text("3s".to_string())),
        ];
        let built = HttpTransport::open("0.0.0.0:8080", Applies::Send, &given).expect("built");
        assert!(built.h2c);
        assert_eq!(built.timeout, Some(Duration::from_secs(3)));
        let Err(refused) = HttpTransport::open("0.0.0.0:8080", Applies::Receive, &given) else {
            panic!("a Receive Location speaks no h2c of its own");
        };
        assert!(refused.message.contains("\"h2c\""), "{}", refused.message);
    }

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
    fn the_loopback_far_end_serves_http_2_and_http_1_1_alike() {
        for sender in [
            HttpTransport::loopback(),
            HttpTransport::loopback().speaking_h2c(),
        ] {
            let far = HttpTransport::loopback().far_end().expect("far end");
            let address = far.address().to_string();
            let taking = std::thread::spawn(move || far.take_one());
            sender
                .send(&format!("http://{address}/round-trip"), b"UNA:+.? '")
                .expect("sent");
            let arrived = taking.join().expect("thread").expect("arrived");
            assert_eq!(arrived.bytes, b"UNA:+.? '");
            assert!(arrived.origin_uri.ends_with("/round-trip"));
        }
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
