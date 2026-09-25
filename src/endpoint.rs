//! A connection to the endpoint a Location is configured with.
//!
//! The endpoint is read by `net::Endpoint` — `http://host:port` or
//! `https://host:port` — and the connection it opens is what `net::http`
//! exchanges a request over. TLS is `xmip-core-library-tls` behind this
//! crate's `tls` feature — one TLS stack in the estate (ADR-0033) — and
//! without the feature an `https://` endpoint is refused with a message
//! saying so rather than sent in the clear.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use net::Endpoint;
use transport::error::Result;
use transport::socket;

/// Anything a request can travel over: a plain socket, or one wrapped in
/// TLS.
pub trait Connection: Read + Write {}

impl<S: Read + Write> Connection for S {}

/// Open a connection to `endpoint` within `timeout`, with `timeout` on its
/// reads, and guard it where the endpoint is `https://`.
///
/// # Errors
/// Where the endpoint could not be reached, or asks for TLS this build does
/// not carry.
pub fn connect(endpoint: &Endpoint, timeout: Option<Duration>) -> Result<Box<dyn Connection>> {
    let tcp = socket::connect_tcp(&endpoint.address(), timeout)?;
    if endpoint.secure() {
        return secure(endpoint.host(), tcp);
    }
    Ok(Box::new(tcp))
}

#[cfg(feature = "tls")]
fn secure(host: &str, tcp: TcpStream) -> Result<Box<dyn Connection>> {
    Ok(Box::new(tls::client(host, tcp)?))
}

#[cfg(not(feature = "tls"))]
fn secure(_host: &str, tcp: TcpStream) -> Result<Box<dyn Connection>> {
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
}
