//! The event capability over HTTP (ADR-0065 clause 3): a subscription
//! forwarded through this transport's webhook wire to its own far end,
//! read back as the Event that was published — in both modes of the
//! binding, over HTTP/1.1 and HTTP/2, presenting the Party's bearer token,
//! at least once through a webhook that answers 503, and near, very near
//! real time (the owner, 2026-09-26).

use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use audit::program_audit::ProgramAudit;
use authorize_party::PartyPolicy;
use event::Event;
use event::binding::{Binding, Carried, Mode};
use event::filter::Filter;
use event::forward::Forwarder;
use event::hub::{EventSubscription, Hub};
use event::outcome::Outcome;
use event::subscriber::Subscriber;
use net::http::Response;
use node::Stage;
use resilience::Guard;
use retry::Retry;
use transport::latency::{TcpControl, spin, spread};
use xcore::{JourneyId, PartyId};
use xmip_core_transport_http::event_wire::{EventWire, Webhook, carried};
use xmip_core_transport_http::server;

/// The subscriber, a remote Party.
const PARTY: PartyId = PartyId::new(23);

/// A hub whose policy allows the Party these tests subscribe as: being in
/// this process admits nobody (ADR-0065, amendment 2026-09-26).
fn allowing() -> Hub {
    Hub::new(vec![Arc::new(PartyPolicy::new().allow(PARTY))])
}

/// The token configured to be presented for the Party.
const TOKEN: &str = "presented-for-party-23";

/// How many Events the latency test forwards.
const ROUNDS: usize = 300;

/// The bound: about a millisecond, apart from load.
const BOUND: Duration = Duration::from_millis(1);

/// The tail's bound, apart from load: a connection, one exchange on
/// loopback TCP and the thread wakes between them.
const TAIL: Duration = Duration::from_millis(5);

const TIMEOUT: Duration = Duration::from_secs(2);

/// A temporary audit directory of its own, never empty and never the
/// estate's.
fn audit_at(name: &str) -> PathBuf {
    let at = std::env::temp_dir().join(format!("xmip-http-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&at);
    at
}

fn subscribed(hub: &Hub, at: &Path) -> EventSubscription {
    let audit = ProgramAudit::new("xmip-core-transport-http tests", Some(at));
    hub.subscribe(
        Subscriber::in_process(PARTY, audit),
        Filter::everything(),
        0,
    )
    .expect("allowed")
}

fn published() -> Event {
    Event::completed(
        Stage::Send,
        Outcome::Failure,
        format!(
            "{}/send/billing",
            configure::fixture::test_cluster().node_scope(0)
        ),
    )
    .in_journey(JourneyId::new(7))
    .on_artifact("billing \"east\" 100%")
    .about(PARTY)
    .saying("status", "503 Service Unavailable")
}

/// What the far end took: when, the bearer it was shown, and the event.
type Taken = (Instant, Option<String>, Carried);

/// The far end: a webhook keeping each connection open as an ordinary
/// server does, the first `refusing` requests answered 503, each other one
/// answered 202 and handed over.
fn far_end(refusing: u32) -> (String, Receiver<Taken>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("a port");
    let address = listener.local_addr().expect("address").to_string();
    let (tell, told) = mpsc::channel();
    thread::spawn(move || {
        let mut refusing = refusing;
        let within = Some(Duration::from_secs(10));
        while let Ok((mut stream, _)) = transport::socket::accept_tcp(&listener, within) {
            loop {
                let served = server::answer_on(&mut stream, |request| {
                    let kept = Response::new(503).header("Connection", "keep-alive");
                    if refusing > 0 {
                        refusing -= 1;
                        return (None, kept);
                    }
                    let bearer = request.header_value("authorization").map(str::to_string);
                    let taken = (Instant::now(), bearer, carried(request));
                    let kept = Response::new(202).header("Connection", "keep-alive");
                    (Some(taken), kept)
                });
                match served {
                    Ok(Some(taken)) => {
                        if tell.send(taken).is_err() {
                            return;
                        }
                    }
                    Ok(None) => {}
                    Err(_) => break,
                }
            }
        }
    });
    (address, told)
}

fn wire(address: &str, h2c: bool) -> EventWire {
    let webhook = Webhook::new(&format!("http://{address}/hooks/xmip?source=node-n"))
        .expect("a URL")
        .presenting_bearer(TOKEN);
    let webhook = if h2c { webhook.speaking_h2c() } else { webhook };
    EventWire::new()
        .to(PARTY, webhook)
        .timing_out_after(TIMEOUT)
}

fn read_back(carried: &Carried) -> Event {
    let wire_event = Binding::Http.read(carried).expect("a WireEvent");
    wire_event.event().expect("an Xmip Event")
}

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
        hub.publish(event.clone());

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
    hub.publish(first.clone());
    hub.publish(second.clone());

    let thrice = Retry::new(3, Duration::ZERO);
    let pumped = forwarder.pump(TIMEOUT, &[&thrice as &dyn Guard]);

    assert_eq!((pumped.carried, pumped.pending), (2, 0), "{pumped:?}");
    let arrived: Vec<Event> = (0..2)
        .map(|_| read_back(&told.recv_timeout(TIMEOUT).expect("posted").2))
        .collect();
    assert_eq!(arrived, [first, second], "once each, in order");
    let _ = fs::remove_dir_all(&at);
}

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
    let forwarding = thread::spawn(move || {
        let once = Retry::new(1, Duration::ZERO);
        let mut carried = 0;
        while carried < ROUNDS {
            carried += forwarder
                .pump(Duration::from_secs(5), &[&once as &dyn Guard])
                .carried;
        }
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

    for _ in 0..ROUNDS {
        spin(Duration::from_micros(500));
        let event = published();
        sent.lock().expect("sent").push(Instant::now());
        hub.publish(event);
        spin(Duration::from_micros(500));
        control.poke();
    }

    let taken = spread(
        "publish to the HTTP webhook",
        receiving.join().expect("received"),
    );
    forwarding.join().expect("forwarded");
    let machine = control.load();
    assert!(
        taken.median < BOUND + machine.median,
        "median {:?}, the machine's own {:?}",
        taken.median,
        machine.median
    );
    assert!(
        taken.p99 < TAIL + machine.p99,
        "p99 {:?}, the machine's own {:?}",
        taken.p99,
        machine.p99
    );
    let _ = fs::remove_dir_all(&at);
}
