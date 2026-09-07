//! Wrapping a connection in TLS, verified against the operating system store.
//!
//! Behind the `tls` feature, which is off by default. Everything here is
//! compiled out otherwise, and `HttpTransport::send` refuses `https://` with a
//! message saying so rather than silently sending in the clear.

use std::net::TcpStream;
use std::sync::Arc;

use transport::error::{Result, protocol_error};

/// A client-side TLS connection ready to read and write.
pub type Guarded = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;

/// A server-side TLS connection ready to read and write — a Receive Location's
/// encrypted channel. ADR-0033.
pub type GuardedServer = rustls::StreamOwned<rustls::ServerConnection, TcpStream>;

/// A server TLS configuration from a certificate chain and its private key, both
/// PEM. This is the Receive side of certificates: the node presents this
/// certificate to callers. Client-certificate verification (mutual-TLS) is the
/// next step and layers a verifier onto this.
///
/// # Errors
///
/// Where the certificate or key cannot be read, or the pair is not usable.
pub fn server_config(certificate_pem: &[u8], key_pem: &[u8]) -> Result<rustls::ServerConfig> {
    let certificates = rustls_pemfile::certs(&mut &certificate_pem[..])
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| protocol_error(format!("reading the certificate: {e}")))?;

    if certificates.is_empty() {
        return Err(protocol_error("the certificate PEM held no certificate"));
    }

    let key = rustls_pemfile::private_key(&mut &key_pem[..])
        .map_err(|e| protocol_error(format!("reading the private key: {e}")))?
        .ok_or_else(|| protocol_error("the key PEM held no private key"))?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());

    rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| protocol_error(format!("selecting tls versions: {e}")))?
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .map_err(|e| protocol_error(format!("loading the certificate and key: {e}")))
}

/// Accept a TLS connection on an already-accepted TCP stream, using a server
/// configuration from [`server_config`].
///
/// # Errors
///
/// Where the handshake could not be started.
pub fn server(tcp: TcpStream, config: Arc<rustls::ServerConfig>) -> Result<GuardedServer> {
    let connection = rustls::ServerConnection::new(config)
        .map_err(|e| protocol_error(format!("starting the server tls session: {e}")))?;

    Ok(rustls::StreamOwned::new(connection, tcp))
}

/// Wrap a connection in TLS for one host.
///
/// # Errors
///
/// Where the trust store is empty or unreadable, the host is not a name TLS can
/// use, or the handshake could not be started.
pub fn client(host: &str, tcp: TcpStream) -> Result<Guarded> {
    let config = Arc::new(configure()?);

    let name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| protocol_error(format!("a server name tls cannot use: {host}")))?;

    let connection = rustls::ClientConnection::new(config, name)
        .map_err(|e| protocol_error(format!("starting the tls session: {e}")))?;

    Ok(rustls::StreamOwned::new(connection, tcp))
}

fn configure() -> Result<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let versions = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| protocol_error(format!("selecting tls versions: {e}")))?;

    Ok(versions
        .with_root_certificates(native_roots()?)
        .with_no_client_auth())
}

/// The operating system trust store.
///
/// The native store rather than a bundled root list, because the organisations
/// Xmip is aimed at run internal certificate authorities and expect their own
/// certificates to work without waiting for Xmip to ship a new root bundle.
fn native_roots() -> Result<rustls::RootCertStore> {
    let mut roots = rustls::RootCertStore::empty();

    for certificate in rustls_native_certs::load_native_certs().certs {
        // One unparsable certificate is not a reason to refuse every other
        // certificate in the store.
        let _ = roots.add(certificate);
    }

    if roots.is_empty() {
        return Err(protocol_error(
            "the operating system trust store held no usable certificates",
        ));
    }

    Ok(roots)
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};

    use super::*;

    fn self_signed() -> rcgen::CertifiedKey {
        rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("generating a cert")
    }

    #[test]
    fn a_server_config_builds_from_a_certificate_and_key() {
        let signed = self_signed();
        let config = server_config(
            signed.cert.pem().as_bytes(),
            signed.key_pair.serialize_pem().as_bytes(),
        );
        assert!(config.is_ok(), "the server config should build");
    }

    #[test]
    fn a_missing_certificate_is_refused() {
        let signed = self_signed();
        let config = server_config(b"not a cert", signed.key_pair.serialize_pem().as_bytes());
        assert!(config.is_err());
    }

    #[test]
    fn a_client_and_server_complete_a_tls_handshake_over_loopback() {
        let signed = self_signed();
        let server_cfg = Arc::new(
            server_config(
                signed.cert.pem().as_bytes(),
                signed.key_pair.serialize_pem().as_bytes(),
            )
            .expect("server config"),
        );

        let listener = TcpListener::bind("127.0.0.1:0").expect("binding");
        let address = listener.local_addr().expect("address").to_string();
        let trusted = signed.cert.der().clone();

        let caller = std::thread::spawn(move || {
            let mut roots = rustls::RootCertStore::empty();
            roots.add(trusted).expect("trusting the test cert");
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let config = Arc::new(
                rustls::ClientConfig::builder_with_provider(provider)
                    .with_safe_default_protocol_versions()
                    .expect("versions")
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            );
            let name = rustls::pki_types::ServerName::try_from("localhost").expect("name");
            let tcp = TcpStream::connect(&address).expect("connect");
            let connection = rustls::ClientConnection::new(config, name).expect("client session");
            let mut stream = rustls::StreamOwned::new(connection, tcp);
            stream.write_all(b"ping").expect("write");
            stream.flush().expect("flush");
            let mut back = [0u8; 4];
            stream.read_exact(&mut back).expect("read");
            back
        });

        let (tcp, _) = listener.accept().expect("accept");
        let mut guarded = server(tcp, server_cfg).expect("server session");
        let mut received = [0u8; 4];
        guarded.read_exact(&mut received).expect("read ping");
        assert_eq!(&received, b"ping");
        guarded.write_all(b"pong").expect("write pong");
        guarded.flush().expect("flush");

        assert_eq!(&caller.join().expect("client thread"), b"pong");
    }
}
