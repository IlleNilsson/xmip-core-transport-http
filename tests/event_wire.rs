//! The event capability over HTTP (ADR-0065 clause 3): a subscription
//! forwarded through this transport's webhook wire to its own far end,
//! read back as the Event that was published — in both modes of the
//! binding, over HTTP/1.1 and HTTP/2, presenting the Party's bearer token,
//! at least once through a webhook that answers 503; and the HTTP
//! binding's own examples, its headers in any case and its
//! percent-encoding. How near real time it is (the owner, 2026-09-26) is
//! held in the module's timing program, `tests/measured`.

use std::fs;
use std::time::Duration;

use event::Event;
use event::binding::{Carried, Mode, Rules};
use event::wire::{Data, WireEvent};
use resilience::Guard;
use retry::Retry;
use xcluster::delivery::forward::Forwarder;
use xmip_core_transport_http::event_wire::HttpEventRules;

#[path = "event_wire/fixture.rs"]
mod fixture;

use fixture::{TIMEOUT, allowing, audit_at, far_end, published, read_back, subscribed, wire};

/// HTTP binding section 3.1.4, the binary-mode example.
#[test]
fn the_http_binary_example_reads_with_headers_in_any_case() {
    let carried = Carried {
        content_type: Some("application/json; charset=utf-8".to_string()),
        headers: [
            ("ce-specversion", "1.0"),
            ("ce-type", "com.example.someevent"),
            ("CE-Time", "2018-04-05T03:56:24Z"),
            ("ce-id", "1234-1234-1234"),
            ("ce-source", "/mycontext/subcontext"),
            ("Host", "webhook.example.com"),
        ]
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .to_vec(),
        body: br#"{"appinfoA":"abc"}"#.to_vec(),
    };

    let event = HttpEventRules.read(&carried).expect("a WireEvent");

    assert_eq!(event.source, "/mycontext/subcontext");
    assert_eq!(event.time.as_deref(), Some("2018-04-05T03:56:24Z"));
    assert_eq!(
        event.data_content_type.as_deref(),
        Some("application/json; charset=utf-8")
    );
    assert_eq!(
        event.data,
        Some(Data::Binary(br#"{"appinfoA":"abc"}"#.to_vec())),
        "the body stays bytes"
    );
    let data = event.json_data().expect("declared JSON").expect("data");
    assert_eq!(data["appinfoA"], "abc");
    assert!(!event.extensions.contains_key("host"), "not a ce- header");
    let kafkas = Carried {
        headers: carried
            .headers
            .iter()
            .map(|(name, value)| (name.replacen('-', "_", 1), value.clone()))
            .collect(),
        ..carried
    };
    assert!(HttpEventRules.read(&kafkas).is_err(), "ce_ is not HTTP's");
}

/// HTTP binding section 3.1.3.2: `Euro € 😀` as a header, and a `%` that
/// two hex digits do not follow refused.
#[test]
fn an_http_header_is_percent_encoded_as_the_binding_says() {
    let mut event = WireEvent::new("1", "/s", "t");
    event.subject = Some("Euro € 😀".to_string());

    let mut carried = HttpEventRules.write(&event, Mode::Binary).expect("written");
    let subject = carried
        .headers
        .iter()
        .find(|(name, _)| name == "ce-subject")
        .map(|(_, value)| value.as_str());

    assert_eq!(subject, Some("Euro%20%E2%82%AC%20%F0%9F%98%80"));
    assert_eq!(HttpEventRules.read(&carried).expect("read"), event);
    for (name, value) in &mut carried.headers {
        if name == "ce-subject" {
            *value = "100%".to_string();
        }
    }
    assert!(HttpEventRules.read(&carried).is_err(), "a broken escape");
}

#[test]
fn a_published_event_arrives_as_the_same_event_in_either_mode_and_version() {
    let (_folder, at) = audit_at("modes");
    for (mode, h2c) in [
        (Mode::Structured, false),
        (Mode::Binary, false),
        (Mode::Structured, true),
        (Mode::Binary, true),
    ] {
        let hub = allowing();
        let (address, told) = far_end(0);
        let mut forwarder = Forwarder::new(subscribed(&hub, &at), mode, wire(&address, h2c));
        let event = published();
        let _ = hub.publish(event.clone());

        let once = Retry::new(1, Duration::ZERO);
        let pumped = forwarder.pump(TIMEOUT, &[&once as &dyn Guard]);

        assert_eq!((pumped.carried, pumped.pending), (1, 0), "{mode:?} {h2c}");
        let (_, bearer, carried) = told.recv_timeout(TIMEOUT).expect("posted");
        assert_eq!(bearer.as_deref(), Some("Bearer presented-for-party-23"));
        let attributes = carried
            .headers
            .iter()
            .filter(|(name, _)| name.to_ascii_lowercase().starts_with("ce-"))
            .count();
        match mode {
            Mode::Structured => assert_eq!(attributes, 0),
            Mode::Binary => assert!(attributes > 4, "{:?}", carried.headers),
        }
        assert_eq!(read_back(&carried), event, "{mode:?} {h2c}");
    }
    let _ = fs::remove_dir_all(&at);
}

#[test]
fn a_webhook_that_answers_503_is_retried_and_the_events_arrive_in_order() {
    let (_folder, at) = audit_at("again");
    let hub = allowing();
    let (address, told) = far_end(2);
    let subscription = subscribed(&hub, &at);
    let mut forwarder = Forwarder::new(subscription, Mode::Binary, wire(&address, false));
    let first = published();
    let second = published();
    let _ = hub.publish(first.clone());
    let _ = hub.publish(second.clone());

    let thrice = Retry::new(3, Duration::ZERO);
    let pumped = forwarder.pump(TIMEOUT, &[&thrice as &dyn Guard]);

    assert_eq!((pumped.carried, pumped.pending), (2, 0), "{pumped:?}");
    let arrived: Vec<Event> = (0..2)
        .map(|_| read_back(&told.recv_timeout(TIMEOUT).expect("posted").2))
        .collect();
    assert_eq!(arrived, [first, second], "once each, in order");
    let _ = fs::remove_dir_all(&at);
}
