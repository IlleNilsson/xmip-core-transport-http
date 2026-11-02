//! The module's timing program (`doc/governance/rust-style.md` section
//! 5c): this transport held to how long Xmip takes — the millisecond rule
//! (`CONTRIBUTING.md`, *Rust is here for one reason*). A plain `cargo test`
//! leaves it out; the landing runs it after every other test of the module,
//! alone, one test at a time
//! (`cargo test --test measured --all-features -- --test-threads=1`), so
//! what is measured is Xmip's work and not its neighbors':
//!
//! - a hundred requests on one kept connection, HTTP/1.1 and HTTP/2, take
//!   five milliseconds each at most;
//! - a request received, accepted after its verdict and answered takes
//!   under a millisecond;
//! - an Event forwarded to a webhook reaches it within a millisecond apart
//!   from load, and Xmip's own processor time an Event is under a
//!   millisecond (the shared webhook is `tests/event_wire/fixture.rs`).

use std::fs;
use std::io::BufReader;
use std::net::TcpListener;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use event::binding::{Binding, Mode};
use event::forward::Forwarder;
use net::Endpoint;
use net::http::{Request, Response};
use resilience::Guard;
use retry::Retry;
use transport::Transport;
use transport::latency::TcpControl;
use transport::socket;
use xcore::latency::{spin, spread};
use xcore::processor_time::ProcessorTime;
use xmip_core_transport_http::HttpTransport;
use xmip_core_transport_http::endpoint::{Connections, Offer};

#[allow(dead_code)]
#[path = "../event_wire/fixture.rs"]
mod fixture;

use fixture::{allowing, audit_at, far_end, published, subscribed, wire};

/// A far end that keeps every connection it accepts and answers every
/// request on it, HTTP/1.1 or HTTP/2 as the connection opens: how many
/// connections it accepted, and how many requests it answered.
fn keeping(listener: &TcpListener, connections: usize) -> (usize, usize) {
    let mut answered = 0;
    for _ in 0..connections {
        let (stream, _) = socket::accept_tcp(listener, None).expect("accept");
        let (h2, first) = net::http2::sniff(&mut &stream).expect("sniffed");
        let replayed = net::http2::Replayed::new(first, &stream);
        if h2 {
            // Served until the near end lets the connection go.
            let _ = net::http2::serve(replayed, |_| {
                answered += 1;
                Response::new(204)
            });
            continue;
        }
        let mut reader = BufReader::new(replayed);
        while let Ok(Some(_)) = net::http::read_request(&mut reader) {
            let kept = Response::new(200).header("Connection", "keep-alive");
            net::http::write_response(reader.get_mut(), &kept).expect("answered");
            answered += 1;
        }
    }
    (connections, answered)
}

#[test]
fn a_hundred_requests_on_one_connection_take_five_milliseconds_each_at_most() {
    const REQUESTS: usize = 100;
    for offer in [Offer::Http11, Offer::PriorKnowledge] {
        let (listener, address) = socket::bind_tcp("127.0.0.1:0").expect("bind");
        let far_end = thread::spawn(move || keeping(&listener, 1));
        let endpoint = Endpoint::parse(&format!("http://{address}/orders")).expect("url");
        let connections = Connections::new();
        let shared = connections.clone();
        let began = Instant::now();
        for n in 0..REQUESTS {
            let request = Request::new("POST", "/orders")
                .header("Host", &address)
                .body(n.to_string().as_bytes());
            let by = if n % 2 == 0 { &connections } else { &shared };
            let timeout = Some(Duration::from_secs(5));
            let answer = by
                .exchange(&endpoint, timeout, offer, &request)
                .expect("answer");
            assert!((200..300).contains(&answer.status), "{offer:?}");
        }
        // Generous for a debug build under load; a request that waited
        // on a delayed acknowledgement took forty milliseconds on Linux.
        let took = began.elapsed();
        assert!(took < Duration::from_millis(5 * 100), "{offer:?}: {took:?}");
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
    let began = Instant::now();
    for _ in 0..ROUNDS {
        let arrived = receiver.receive().expect("received").remove(0);
        arrived.taken().expect("accepted");
    }
    let each = began.elapsed() / ROUNDS;
    sender.join().expect("sender");
    println!("an HTTP request received, accepted and answered: {each:?} each");
    assert!(each < Duration::from_millis(1), "{each:?} each");
}

/// How many Events the latency test forwards.
const ROUNDS: usize = 300;

/// The bound: about a millisecond, apart from load.
const BOUND: Duration = Duration::from_millis(1);

#[test]
fn an_event_reaches_the_webhook_within_a_millisecond_apart_from_load() {
    let at = audit_at("latency");
    let hub = Arc::new(allowing());
    let (address, told) = far_end(0);
    let mut forwarder = Forwarder::new(
        subscribed(&hub, &at),
        Binding::Http,
        Mode::Binary,
        wire(&address, false),
    );
    // The forwarding thread's processor time over every Event: its waits
    // are not counted, only its work.
    let forwarding = thread::spawn(move || {
        let spent = ProcessorTime::thread();
        let once = Retry::new(1, Duration::ZERO);
        let mut carried = 0;
        while carried < ROUNDS {
            carried += forwarder
                .pump(Duration::from_secs(5), &[&once as &dyn Guard])
                .carried;
        }
        spent.elapsed()
    });
    let sent = Arc::new(Mutex::new(Vec::with_capacity(ROUNDS)));
    let receiving = {
        let sent = Arc::clone(&sent);
        thread::spawn(move || {
            (0..ROUNDS)
                .map(|index| {
                    let (arrived, _, _) =
                        told.recv_timeout(Duration::from_secs(5)).expect("posted");
                    arrived - sent.lock().expect("sent")[index]
                })
                .collect::<Vec<Duration>>()
        })
    };
    let mut control = TcpControl::start();
    let mut publishing = Duration::ZERO;

    for _ in 0..ROUNDS {
        spin(Duration::from_micros(500));
        let event = published();
        sent.lock().expect("sent").push(Instant::now());
        let from = ProcessorTime::thread();
        hub.publish(event);
        publishing += from.elapsed();
        spin(Duration::from_micros(500));
        control.poke();
    }

    let taken = spread(
        "publish to the HTTP webhook",
        receiving.join().expect("received"),
    );
    let forwarding_time = forwarding.join().expect("forwarded");
    let machine = control.load();
    // The wake is a wake: the fastest of each five against the machine's.
    assert!(
        taken.fastest_of_five < BOUND + machine.fastest_of_five,
        "the fastest of five {:?}, the machine's own {:?}",
        taken.fastest_of_five,
        machine.fastest_of_five
    );
    // Xmip's own work: the publisher's and the forwarder's processor time,
    // an Event's share.
    let own = (publishing + forwarding_time) / u32::try_from(ROUNDS).expect("a count");
    println!("Xmip's own processor time: {own:?} an Event");
    assert!(own < BOUND, "Xmip's own processor time, {own:?} an Event");
    let _ = fs::remove_dir_all(&at);
}
