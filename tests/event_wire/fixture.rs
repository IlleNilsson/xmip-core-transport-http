//! What the event-wire tests and the timing program share: the Party's
//! hub and token, its subscription and Event, the webhook that admits it
//! and the wire that reaches it.

use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use audit::program_audit::ProgramAudit;
use authorize_party::PartyPolicy;
use event::Event;
use event::binding::{Binding, Carried};
use event::filter::Filter;
use event::hub::{EventSubscription, Hub};
use event::outcome::Outcome;
use event::subscriber::Subscriber;
use net::http::Response;
use node::Stage;
use xcore::{JourneyId, PartyId};
use xmip_core_transport_http::event_wire::{EventWire, Webhook, carried};
use xmip_core_transport_http::server;

/// The subscriber, a remote Party.
pub const PARTY: PartyId = PartyId::new(23);

/// A hub whose policy allows the Party these tests subscribe as: being in
/// this process admits nobody (ADR-0065, amendment 2026-09-26).
pub fn allowing() -> Hub {
    Hub::new(vec![Arc::new(PartyPolicy::new().allow(PARTY))])
}

/// The token configured to be presented for the Party.
pub const TOKEN: &str = "presented-for-party-23";

pub const TIMEOUT: Duration = Duration::from_secs(2);

/// A temporary audit directory of its own, never empty and never the
/// estate's.
pub fn audit_at(name: &str) -> PathBuf {
    let at = std::env::temp_dir().join(format!("xmip-http-{name}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&at);
    at
}

pub fn subscribed(hub: &Hub, at: &Path) -> EventSubscription {
    let audit = ProgramAudit::new("xmip-core-transport-http tests", Some(at));
    hub.subscribe(
        Subscriber::in_process(PARTY, audit),
        Filter::everything(),
        0,
    )
    .expect("allowed")
}

pub fn published() -> Event {
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
pub type Taken = (Instant, Option<String>, Carried);

/// The far end: a webhook keeping each connection open as an ordinary
/// server does, the first `refusing` requests answered 503, each other one
/// answered 202 and handed over.
pub fn far_end(refusing: u32) -> (String, Receiver<Taken>) {
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

pub fn wire(address: &str, h2c: bool) -> EventWire {
    let webhook = Webhook::new(&format!("http://{address}/hooks/xmip?source=node-n"))
        .expect("a URL")
        .presenting_bearer(TOKEN);
    let webhook = if h2c { webhook.speaking_h2c() } else { webhook };
    EventWire::new()
        .to(PARTY, webhook)
        .timing_out_after(TIMEOUT)
}

pub fn read_back(carried: &Carried) -> Event {
    let wire_event = Binding::Http.read(carried).expect("a WireEvent");
    wire_event.event().expect("an Xmip Event")
}
