//! Where a send is going, read out of the target string.

use transport::error::{Result, protocol_error};
use transport::wire::with_default_port;

/// A parsed `http://` or `https://` target.
///
/// Its own type because reading it is a real step with three ways to be wrong,
/// and because doing it inline is how `send` grew to forty lines.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpTarget<'a> {
    pub secure: bool,
    pub authority: &'a str,
    pub path: &'a str,
}

impl<'a> HttpTarget<'a> {
    /// # Errors
    ///
    /// Where the target carries no scheme, or a scheme that is not HTTP, or no
    /// host. All three are configuration mistakes and none is retryable.
    pub fn parse(target: &'a str) -> Result<Self> {
        let (secure, rest) = Self::scheme(target)?;
        let (authority, path) = Self::split_path(rest);

        if authority.is_empty() {
            return Err(protocol_error(format!(
                "an http target with no host — got {target}"
            )));
        }

        Ok(Self {
            secure,
            authority,
            path,
        })
    }

    fn scheme(target: &'a str) -> Result<(bool, &'a str)> {
        if let Some(rest) = target.strip_prefix("https://") {
            return Ok((true, rest));
        }

        if let Some(rest) = target.strip_prefix("http://") {
            return Ok((false, rest));
        }

        Err(protocol_error(format!(
            "an http target must begin with http:// or https:// — got {target}"
        )))
    }

    fn split_path(rest: &'a str) -> (&'a str, &'a str) {
        match rest.find('/') {
            Some(cut) => (&rest[..cut], &rest[cut..]),
            None => (rest, "/"),
        }
    }

    /// The address to connect to, with the scheme's default port where the
    /// target did not carry one.
    #[must_use]
    pub fn address(&self) -> String {
        with_default_port(self.authority, if self.secure { 443 } else { 80 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_path_is_taken_from_the_target_or_defaulted() {
        assert_eq!(
            HttpTarget::parse("http://example.com/orders")
                .expect("parsed")
                .path,
            "/orders"
        );
        assert_eq!(
            HttpTarget::parse("http://example.com")
                .expect("parsed")
                .path,
            "/"
        );
    }

    #[test]
    fn the_scheme_decides_the_default_port() {
        assert_eq!(
            HttpTarget::parse("http://example.com/x")
                .expect("parsed")
                .address(),
            "example.com:80"
        );
        assert_eq!(
            HttpTarget::parse("https://example.com/x")
                .expect("parsed")
                .address(),
            "example.com:443"
        );
    }

    #[test]
    fn a_port_in_the_target_is_left_alone() {
        assert_eq!(
            HttpTarget::parse("http://example.com:8080/x")
                .expect("parsed")
                .address(),
            "example.com:8080"
        );
    }

    #[test]
    fn a_target_without_a_scheme_is_rejected() {
        let failure = HttpTarget::parse("example.com/orders").expect_err("no scheme");

        assert!(!failure.retryable, "a bad target will be bad next time too");
    }

    #[test]
    fn a_target_without_a_host_is_rejected() {
        assert!(HttpTarget::parse("http:///orders").is_err());
    }
}
