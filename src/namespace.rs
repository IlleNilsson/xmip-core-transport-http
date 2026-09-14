//! What a `servicebus.windows.net` namespace answers when it refuses, and
//! the judgement of what it answers.
//!
//! An error is an XML `Error` with a `Code` that repeats the status and a
//! `Detail` that says what went wrong, its leading subcode the part worth
//! reading — `40103` is a bad signature, `50002` a namespace that is busy.
//! Service Bus and Event Hubs answer the same shapes at the same
//! namespaces; azure-service-bus carried this for azure-event-hubs to take
//! until 2026-09-14, and what two technologies both read over HTTP is
//! shared through the http technology (ADR-0044).

use transport::error::Result;
use transport::xml::{escape, first};

use crate::message::{self, Response};

/// The far end's answer that is not a result: an `Error` with `status` for
/// its code and `detail` for what went wrong, `40103: Invalid authorization
/// token signature` style.
#[must_use]
pub fn error(status: u16, detail: &str) -> Response {
    let body = format!(
        "<Error><Code>{status}</Code><Detail>{}</Detail></Error>",
        escape(detail)
    );
    Response::new(status)
        .header("Content-Type", "application/xml; charset=utf-8")
        .body(body.as_bytes())
}

/// The subcode an error's detail opens with — `40103` — or the whole detail
/// where it opens with none.
#[must_use]
pub fn subcode(detail: &str) -> String {
    detail
        .split_once(':')
        .map_or(detail, |(code, _)| code)
        .trim()
        .to_string()
}

/// A 2xx answer as it is; anything else as a failure naming the status and
/// the detail the namespace put in the body, retryable where it says come
/// back — a server fault, a timeout, a throttle, a namespace that is busy.
///
/// # Errors
/// Where the status is not 2xx.
pub fn judge(service: &str, response: Response) -> Result<Response> {
    message::judge(
        service,
        response,
        |answer| first(&answer.text(), "Detail").unwrap_or_default(),
        |detail| detail.starts_with("50002"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_server_failure_is_worth_repeating_and_a_client_one_is_not() {
        assert!(
            judge("Service Bus", Response::new(503))
                .expect_err("s")
                .retryable
        );
        assert!(
            judge("Service Bus", Response::new(429))
                .expect_err("t")
                .retryable
        );
        let busy = error(500, "50002: The server is busy <now>");
        assert_eq!(
            busy.header_value("content-type"),
            Some("application/xml; charset=utf-8")
        );
        assert!(busy.text().contains("busy &lt;now&gt;"));
        assert!(judge("Service Bus", busy).expect_err("busy").retryable);
        let denied = judge(
            "Event Hubs",
            error(401, "40103: Invalid authorization token signature"),
        )
        .expect_err("denied");
        assert!(!denied.retryable);
        assert_eq!(
            denied.message,
            "Event Hubs answered 401 40103: Invalid authorization token signature"
        );
        assert_eq!(subcode("40103: Invalid"), "40103");
        assert_eq!(subcode("no such entity"), "no such entity");
        assert_eq!(judge("x", Response::new(204)).expect("ok").status, 204);
    }
}
