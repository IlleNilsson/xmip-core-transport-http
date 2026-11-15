//! The module's timing program (`doc/governance/rust-style.md` section
//! 5c): this transport held to how long Xmip takes — the millisecond rule
//! (`CONTRIBUTING.md`, *Rust is here for one reason*). A plain `cargo test`
//! leaves it out; the landing runs it after every other test of the module,
//! alone, one test at a time
//! (`cargo test --test measured --all-features -- --test-threads=1`), so
//! what is measured is Xmip's work and not its neighbors':
//!
//! - a hundred requests on one kept connection, HTTP/1.1 and HTTP/2, take
//!   five milliseconds each at most, the fastest of five
//!   (`xcore::latency::spread`);
//! - a request received, accepted after its verdict and answered takes
//!   under a millisecond beyond its wakes;
//! - an Event forwarded to a webhook reaches it within a millisecond apart
//!   from load, and this process's processor time across it is under a
//!   millisecond beyond a plain wake's (the shared webhook is
//!   `tests/event_wire/fixture.rs`).
//!
//! The last two round by round beside a plain wake, the fastest of five
//! (`xcore::latency::Rounds`).

use std::fs;
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use event::binding::Mode;
use net::Endpoint;
use net::http::Request;
use resilience::Guard;
use retry::Retry;
use transport::Transport;
use transport::socket;
use xcluster::delivery::forward::Forwarder;
use xcore::latency::{Rounds, spin, spread};
use xcore::processor_time::ProcessorTime;
use xmip_core_transport_http::HttpTransport;
use xmip_core_transport_http::endpoint::{Connections, Offer};
use xmip_core_transport_http::fixture::keeping;

#[allow(dead_code)]
#[path = "../event_wire/fixture.rs"]
mod fixture;

use fixture::{allowing, audit_at, far_end, published, subscribed, wire};

#[test]
fn a_hundred_requests_on_one_connection_take_five_milliseconds_each_at_most() {
    const REQUESTS: usize = 100;
    for offer in [Offer::Http11, Offer::PriorKnowledge] {
        let (listener, address) = socket::bind_tcp("127.0.0.1:0").expect("bind");
        let far_end = thread::spawn(move || keeping(&listener, 1));
        let endpoint = Endpoint::parse(&format!("http://{address}/orders")).expect("url");
        let connections = Connections::new();
        let shared = connections.clone();
        let mut took = Vec::with_capacity(REQUESTS);
        for n in 0..REQUESTS {
            let request = Request::new("POST", "/orders")
                .header("Host", &address)
                .body(n.to_string().as_bytes());
            let by = if n % 2 == 0 { &connections } else { &shared };
            let timeout = Some(Duration::from_secs(5));
            let began = Instant::now();
            let answer = by
                .exchange(&endpoint, timeout, offer, &request)
                .expect("answer");
            took.push(began.elapsed());
            assert!((200..300).contains(&answer.status), "{offer:?}");
        }
        // Five milliseconds a request, the fastest of five: a request that
        // waited on a delayed acknowledgement took forty milliseconds on
        // Linux, and waits so in every round. The budget is five
        // milliseconds, not the millisecond `Rounds` holds a wake to, so no
        // plain wake is measured beside it. Until 2026-11-15 the hundred
        // were timed once together.
        let took = spread(&format!("a request, {offer:?}"), took);
        assert!(
            took.fastest_of_five < Duration::from_millis(5),
            "{offer:?}: {took:?}"
        );
        drop((connections, shared));
        assert_eq!(far_end.join().expect("far end"), (1, REQUESTS), "{offer:?}");
    }
}

#[test]
fn a_request_answered_after_its_verdict_takes_under_a_millisecond() {
    // The owner's rule, held: around a payload, Xmip's own work is
    // under a millisecond — the caller waiting for the verdict, the
    // reply kept beside its connection and written after, included.
    const ROUNDS: u32 = 500;
    let receiver = HttpTransport::loopback();
    let address = receiver.listening().expect("bound");
    let target = format!("http://{address}/orders");
    let sender = thread::spawn(move || {
        let sender = HttpTransport::loopback();
        for _ in 0..ROUNDS {
            sender.send(&target, b"x").expect("sent");
        }
    });
    // Each round beside a plain wake; until 2026-11-15 the five hundred
    // were held together, an average.
    let mut rounds = Rounds::crossing(RECEIVE_WAKES);
    for _ in 0..ROUNDS {
        rounds.round(|| {
            let arrived = receiver.receive().expect("received").remove(0);
            arrived.taken().expect("accepted");
        });
    }
    sender.join().expect("sender");
    rounds.hold("an HTTP request received, accepted and answered");
}

/// What a request received and answered wakes where a plain wake wakes
/// one: the sender at the answer, and this end at its next request
/// (`xcore::latency::Rounds`).
const RECEIVE_WAKES: u32 = 2;

/// How many Events the latency test forwards.
const ROUNDS: usize = 300;

/// What an Event's way to the webhook wakes where a plain wake wakes one:
/// the forwarder at the publish, and the webhook at its request.
const EVENT_WAKES: u32 = 2;

#[test]
fn an_event_reaches_the_webhook_within_a_millisecond_apart_from_load() {
    let at = audit_at("latency");
    let hub = Arc::new(allowing());
    let (address, told) = far_end(0);
    let mut forwarder = Forwarder::new(subscribed(&hub, &at), Mode::Binary, wire(&address, false));
    let forwarding = thread::spawn(move || {
        let once = Retry::new(1, Duration::ZERO);
        let mut carried = 0;
        while carried < ROUNDS {
            carried += forwarder
                .pump(Duration::from_secs(5), &[&once as &dyn Guard])
                .carried;
        }
    });
    // From the publish to the webhook's arrival, and this process's
    // processor time across it — the publisher, the forwarder and the
    // webhook — round by round beside a plain wake. Until 2026-11-15 the
    // processor time was an Event's share of the whole run, held flat.
    let mut rounds = Rounds::crossing(EVENT_WAKES);
    for _ in 0..ROUNDS {
        spin(Duration::from_micros(500));
        let event = published();
        let from = ProcessorTime::process();
        let sent = Instant::now();
        let _ = hub.publish(event);
        let (arrived, _, _) = told.recv_timeout(Duration::from_secs(5)).expect("posted");
        rounds.took.push(arrived - sent);
        rounds.worked.push(from.elapsed());
        rounds.beside();
    }
    forwarding.join().expect("forwarded");
    rounds.hold("publish to the HTTP webhook");
    let _ = fs::remove_dir_all(&at);
}
