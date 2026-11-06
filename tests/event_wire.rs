//! The event capability over HTTP (ADR-0065 clause 3): a subscription
//! forwarded through this transport's webhook wire to its own far end,
//! read back as the Event that was published — in both modes of the
//! binding, over HTTP/1.1 and HTTP/2, presenting the Party's bearer token,
//! at least once through a webhook that answers 503. How near real time it
//! is (the owner, 2026-09-26) is held in the module's timing program,
//! `tests/measured`.

use std::fs;
use std::time::Duration;

use event::Event;
use event::binding::{Binding, Mode};
use event::forward::Forwarder;
use resilience::Guard;
use retry::Retry;

#[path = "event_wire/fixture.rs"]
mod fixture;

use fixture::{TIMEOUT, allowing, audit_at, far_end, published, read_back, subscribed, wire};

#[test]
fn a_published_event_arrives_as_the_same_event_in_either_mode_and_version() {
    let at = audit_at("modes");
    for (mode, h2c) in [
        (Mode::Structured, false),
        (Mode::Binary, false),
        (Mode::Structured, true),
        (Mode::Binary, true),
    ] {
        let hub = allowing();
        let (address, told) = far_end(0);
        let mut forwarder = Forwarder::new(
            subscribed(&hub, &at),
            Binding::Http,
            mode,
            wire(&address, h2c),
        );
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
    let at = audit_at("again");
    let hub = allowing();
    let (address, told) = far_end(2);
    let subscription = subscribed(&hub, &at);
    let mut forwarder = Forwarder::new(
        subscription,
        Binding::Http,
        Mode::Binary,
        wire(&address, false),
    );
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
