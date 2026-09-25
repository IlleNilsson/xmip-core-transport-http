//! The judgement of an answer's status: a success as it is, a failure
//! retryable where the status says come back.
//!
//! The message itself — writing a request, reading its answer — is
//! `net::http`'s; what the transport makes of a status is the transport's,
//! because retryability is a property of the transport's failure.

use net::http::Response;
use transport::error::{Result, TransportError};

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

#[cfg(test)]
mod tests {
    use super::*;

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
