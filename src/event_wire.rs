//! Wire events over HTTP, as the standard they follow (`CloudEvents` 1.0)
//! binds them: the webhook the event capability forwards a
//! subscription to (ADR-0065 clause 3), and the read side a receiving
//! Xmip turns a request back into an event with.
//!
//! What goes on the request is decided once, in `xmip-core-event`'s
//! binding: this file only puts a [`Carried`] where the HTTP protocol
//! binding 1.0.2 puts it — a `POST` whose body is the body, whose
//! `Content-Type` is the content type, and whose `ce-` headers are the
//! attributes, already escaped — and takes it back off a request the same
//! way. The request goes out through this transport's own exchange,
//! HTTP/2 or HTTP/1.1 as the connection agrees, TLS through the estate's
//! own where the webhook is `https://` (the `tls` feature).
//!
//! The answer is judged as every answer HTTP gets is ([`status::judge`]):
//! 2xx acknowledged; 5xx, 408 and 429 retryable; any other 4xx permanent,
//! because the webhook will say it again. A connection that fails is
//! retryable as the socket says. The resilience guards decide each
//! attempt: at least once.
//!
//! **The identity presented** is configured per Party, as ADR-0019 clause
//! 3 has a Send side present the identity configured for the Party it
//! reaches, and applied with HTTP's own mechanism: a bearer token in
//! `Authorization`. A client certificate is the other way HTTP presents
//! one, and waits on the estate's TLS offering a client identity.
//!
//! **Connected once, not per event.** The wire keeps its connections in
//! the transport's [`Connections`]: over HTTP/1.1 the connection to a
//! webhook stays open between events, and over HTTP/2 one connection
//! carries event after event, so an event costs one exchange and not a
//! connect — which on loopback is half of it. A webhook that answers
//! `Connection: close` is connected to afresh next time; one that closed a
//! kept connection meanwhile is connected to afresh at once, the event
//! sent again: at least once.

use std::collections::BTreeMap;
use std::time::Duration;

use event::binding::Carried;
use event::forward::Wire;
use net::Endpoint;
use net::http::Request;
use resilience::Failure;
use transport::error::Result;
use xcore::PartyId;

use crate::endpoint::{Connections, Offer};
use crate::status;

/// Where one Party's events are posted, and what is presented there.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Webhook {
    endpoint: Endpoint,
    authorization: Option<String>,
    h2c: bool,
}

impl Webhook {
    /// The webhook at `url`: `https://` or `http://`, a path, a query.
    ///
    /// # Errors
    /// Where `url` is not an HTTP URL.
    pub fn new(url: &str) -> Result<Self> {
        Ok(Self {
            endpoint: Endpoint::parse(url)?,
            authorization: None,
            h2c: false,
        })
    }

    /// Present `token` as `Authorization: Bearer`.
    #[must_use]
    pub fn presenting_bearer(mut self, token: &str) -> Self {
        self.authorization = Some(format!("Bearer {token}"));
        self
    }

    /// Speak HTTP/2 to an `http://` webhook by prior knowledge.
    #[must_use]
    pub const fn speaking_h2c(mut self) -> Self {
        self.h2c = true;
        self
    }

    /// The request that carries `carried` here.
    fn request(&self, carried: &Carried) -> Request {
        let mut request =
            Request::new("POST", self.endpoint.path()).header("Host", &self.endpoint.authority());
        if let Some(media) = &carried.content_type {
            request = request.header("Content-Type", media);
        }
        for (name, value) in &carried.headers {
            request = request.header(name, value);
        }
        if let Some(authorization) = &self.authorization {
            request = request.header("Authorization", authorization);
        }
        request.body(&carried.body)
    }
}

/// The HTTP wire: each Party's webhook, and the connections kept open to
/// them.
pub struct EventWire {
    webhooks: BTreeMap<PartyId, Webhook>,
    timeout: Option<Duration>,
    connections: Connections,
}

impl EventWire {
    /// A wire configured for no Party yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            webhooks: BTreeMap::new(),
            timeout: None,
            connections: Connections::new(),
        }
    }

    /// Post `party`'s events to `webhook`.
    #[must_use]
    pub fn to(mut self, party: PartyId, webhook: Webhook) -> Self {
        self.webhooks.insert(party, webhook);
        self
    }

    /// Give up on a webhook that does not connect or answer within
    /// `timeout`.
    #[must_use]
    pub const fn timing_out_after(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
}

impl Default for EventWire {
    fn default() -> Self {
        Self::new()
    }
}

impl Wire for EventWire {
    /// One `POST` to the Party's webhook, a 2xx its acknowledgement.
    fn carry(&self, party: PartyId, carried: &Carried) -> std::result::Result<(), Failure> {
        let webhook = self.webhooks.get(&party).ok_or_else(|| {
            Failure::permanent(format!("no webhook is configured for Party {party}"))
        })?;
        let answer = self.connections.exchange(
            &webhook.endpoint,
            self.timeout,
            Offer::agreed(webhook.h2c),
            &webhook.request(carried),
        )?;
        status::judge(
            "the webhook",
            answer,
            |answer| answer.reason.clone(),
            |_| false,
        )?;
        Ok(())
    }
}

/// What `request` carries, for the binding to read a `WireEvent` from:
/// its `Content-Type` as the content type, every other header as it came,
/// its body.
#[must_use]
pub fn carried(request: &Request) -> Carried {
    Carried {
        content_type: request.header_value("content-type").map(str::to_string),
        headers: request
            .headers
            .iter()
            .filter(|(name, _)| !name.eq_ignore_ascii_case("content-type"))
            .cloned()
            .collect(),
        body: request.body.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use net::http::Response;

    #[test]
    fn a_carried_event_is_its_request_and_its_request_the_carried_event() {
        let carried = Carried {
            content_type: Some("application/json".to_string()),
            headers: vec![("ce-id".to_string(), "a%20b".to_string())],
            body: b"{}".to_vec(),
        };
        let webhook = Webhook::new("http://127.0.0.1:1/hooks/events?code=1")
            .expect("a URL")
            .presenting_bearer("t0ken");
        let request = webhook.request(&carried);
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/hooks/events?code=1");
        assert_eq!(request.header_value("authorization"), Some("Bearer t0ken"));
        let back = super::carried(&request);
        assert_eq!(back.content_type, carried.content_type);
        assert_eq!(back.body, carried.body);
        assert!(
            back.headers
                .contains(&("ce-id".to_string(), "a%20b".to_string()))
        );
    }

    #[test]
    fn a_kept_connection_the_webhook_closed_is_replaced_and_the_event_sent_again() {
        let (listener, address) = transport::socket::bind_tcp("127.0.0.1:0").expect("bind");
        let timeout = Some(Duration::from_secs(2));
        // Says it keeps the connection, then closes it after each answer.
        let far_end = std::thread::spawn(move || {
            (0..2)
                .map(|_| {
                    crate::server::serve_one(&listener, timeout, |request| {
                        let kept = Response::new(202).header("Connection", "keep-alive");
                        (request.body.clone(), kept)
                    })
                })
                .collect::<Vec<_>>()
        });
        let webhook = Webhook::new(&format!("http://{address}/hook")).expect("a URL");
        let wire = EventWire::new()
            .to(PartyId::new(1), webhook)
            .timing_out_after(Duration::from_secs(2));
        for body in [b"one", b"two"] {
            let carried = Carried {
                body: body.to_vec(),
                ..Carried::default()
            };
            wire.carry(PartyId::new(1), &carried).expect("carried");
        }
        let served = far_end.join().expect("served");
        let bodies: Vec<Vec<u8>> = served.into_iter().map(|body| body.expect("one")).collect();
        assert_eq!(bodies, [b"one".to_vec(), b"two".to_vec()]);
    }

    #[test]
    fn a_party_with_no_webhook_is_refused_for_good_and_an_unreachable_one_is_retried() {
        let webhook = Webhook::new("http://127.0.0.1:1/hook").expect("a URL");
        let wire = EventWire::new()
            .to(PartyId::new(1), webhook)
            .timing_out_after(Duration::from_secs(1));
        let refused = wire
            .carry(PartyId::new(2), &Carried::default())
            .expect_err("no webhook");
        assert!(!refused.is_retryable());
        assert!(refused.reason.contains("no webhook"), "{refused}");
        let unreachable = wire
            .carry(PartyId::new(1), &Carried::default())
            .expect_err("nothing listens");
        assert!(unreachable.is_retryable(), "{unreachable}");
        assert!(Webhook::new("hook.example/x").is_err(), "not HTTP");
    }
}
