//! A connection to the endpoint a Location is configured with, and the
//! version of HTTP it speaks.
//!
//! The endpoint is read by `net::Endpoint` — `http://host:port` or
//! `https://host:port` — and the connection it opens is what `net::http`
//! or `net::http2` exchanges a request over. TLS is `xmip-core-library-tls`
//! behind this crate's `tls` feature — one TLS stack in the estate
//! (ADR-0033) — and without the feature an `https://` endpoint is refused
//! with a message saying so rather than sent in the clear.
//!
//! **The version is the connection's.** Over TLS it is agreed by ALPN:
//! [`open`] offers `h2` and `http/1.1`, and the server selects. Over
//! cleartext HTTP/2 is spoken only by prior knowledge, where the Location
//! says so (`h2c`); RFC 9113 removed HTTP/1.1's `Upgrade` to it, and there
//! is none here. [`connect`] offers nothing and speaks HTTP/1.1, which is
//! what the technologies riding on HTTP write with `net::http`.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use net::Endpoint;
use net::http::{Request, Response, Version};
use transport::error::Result;
use transport::socket;

/// Anything a request can travel over: a plain socket, or one wrapped in
/// TLS.
pub trait Connection: Read + Write {}

impl<S: Read + Write> Connection for S {}

/// Open a connection to `endpoint` within `timeout`, with `timeout` on its
/// reads, and guard it where the endpoint is `https://`: HTTP/1.1, which
/// nothing is offered beside.
///
/// # Errors
/// Where the endpoint could not be reached, or asks for TLS this build does
/// not carry.
pub fn connect(endpoint: &Endpoint, timeout: Option<Duration>) -> Result<Box<dyn Connection>> {
    let tcp = socket::connect_tcp(&endpoint.address(), timeout)?;
    if endpoint.secure() {
        return Ok(secure(endpoint.host(), tcp, false)?.0);
    }
    Ok(Box::new(tcp))
}

/// Open a connection to `endpoint` as [`connect`] does, and the version it
/// speaks: over TLS what ALPN agreed, offering HTTP/2 first; in the clear
/// HTTP/2 where `h2c` says the service speaks it by prior knowledge, and
/// HTTP/1.1 otherwise.
///
/// # Errors
/// As [`connect`], and where the handshake failed.
pub fn open(
    endpoint: &Endpoint,
    timeout: Option<Duration>,
    h2c: bool,
) -> Result<(Box<dyn Connection>, Version)> {
    let tcp = socket::connect_tcp(&endpoint.address(), timeout)?;
    if endpoint.secure() {
        return secure(endpoint.host(), tcp, true);
    }
    let version = if h2c { Version::Http2 } else { Version::Http11 };
    Ok((Box::new(tcp), version))
}

/// Send `request` to `endpoint` on a connection of its own, in the version
/// [`open`] finds the connection speaks, and read its answer.
///
/// # Errors
/// As [`open`], and where the exchange failed.
pub fn exchange(
    endpoint: &Endpoint,
    timeout: Option<Duration>,
    h2c: bool,
    request: &Request,
) -> Result<Response> {
    let (connection, version) = open(endpoint, timeout, h2c)?;
    let scheme = if endpoint.secure() { "https" } else { "http" };
    Ok(match version {
        Version::Http11 => net::http::exchange(connection, request)?,
        Version::Http2 => net::http2::exchange(connection, scheme, request)?,
    })
}

#[cfg(feature = "tls")]
fn secure(host: &str, tcp: TcpStream, offer: bool) -> Result<(Box<dyn Connection>, Version)> {
    if !offer {
        return Ok((Box::new(tls::client(host, tcp)?), Version::Http11));
    }
    let offered = [Version::Http2.alpn(), Version::Http11.alpn()];
    let mut guarded = tls::client_offering(host, tcp, &offered)?;
    let agreed = tls::alpn::agreed(&mut guarded)?;
    Ok((Box::new(guarded), Version::agreed(agreed.as_deref())))
}

#[cfg(not(feature = "tls"))]
fn secure(_host: &str, tcp: TcpStream, _offer: bool) -> Result<(Box<dyn Connection>, Version)> {
    drop(tcp);
    Err(transport::error::protocol_error(
        "https was asked for and this build has no tls feature compiled in",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_https_endpoint_without_tls_says_so() {
        let (listener, address) = socket::bind_tcp("127.0.0.1:0").expect("bind");
        let endpoint = Endpoint::parse(&format!("https://{address}")).expect("parsed");
        let failure = connect(&endpoint, None).err();
        drop(listener);
        #[cfg(not(feature = "tls"))]
        assert!(failure.expect("no tls").message.contains("tls"));
        #[cfg(feature = "tls")]
        assert!(failure.is_none());
    }

    #[test]
    fn a_cleartext_connection_speaks_http_2_only_by_prior_knowledge() {
        let (_listener, address) = socket::bind_tcp("127.0.0.1:0").expect("bind");
        let endpoint = Endpoint::parse(&format!("http://{address}")).expect("parsed");
        let timeout = Some(Duration::from_secs(2));
        assert_eq!(
            open(&endpoint, timeout, false).expect("open").1,
            Version::Http11
        );
        assert_eq!(
            open(&endpoint, timeout, true).expect("open").1,
            Version::Http2
        );
    }
}
