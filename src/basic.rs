//! HTTP Basic authentication (RFC 7617): what a Send Location presents
//! where it names a password secret (ADR-0019, amendment 2026-10-29).

use net::Target;
use transport::Secured;
use transport::error::Result;

/// The `Authorization` a send to `target` carries: Basic for the user the
/// address names — `https://orders@host/in` — and the password `secret`
/// holds, read now; none where the Location names no secret.
///
/// # Errors
///
/// The secret is not set, cannot be read, or is no password.
pub fn basic(secret: Option<&Secured>, target: &str) -> Result<Option<String>> {
    let Some(secret) = secret else {
        return Ok(None);
    };
    let password = secret.as_kind(xcore::SecretKind::Password, "http")?;
    let user = Target::under(crate::SCHEMES, target)
        .and_then(|named| named.user())
        .unwrap_or_default();
    let pair = format!("{user}:{password}");
    Ok(Some(format!(
        "Basic {}",
        codec::base64::encode(pair.as_bytes())
    )))
}
