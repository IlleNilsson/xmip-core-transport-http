//! A keyed send carries its deduplication key in the `Idempotency-Key`
//! header (draft-ietf-httpapi-idempotency-key-header), the same on every
//! attempt of one Journey; an unkeyed send carries none.

use std::net::TcpListener;
use std::thread;

use net::http::Response;
use transport::Transport;
use transport::loopback::LOOPBACK_TIMEOUT;
use xmip_core_transport_http::{HttpTransport, server};

/// A Journey's identifier, as the runtime hands it.
const KEY: &str = "0b6f5a52-7c1e-4d0a-9a4e-3f1d2c8b9e70";

/// The far end: `requests` requests served on `listener`, each reporting
/// its `Idempotency-Key` header, if any.
fn hearing(listener: TcpListener, requests: usize) -> thread::JoinHandle<Vec<Option<String>>> {
    thread::spawn(move || {
        (0..requests)
            .map(|_| {
                server::serve_one(&listener, Some(LOOPBACK_TIMEOUT), |request| {
                    let key = request.header_value("idempotency-key").map(str::to_string);
                    (key, Response::new(server::ACCEPTED))
                })
                .expect("served")
            })
            .collect()
    })
}

#[test]
fn a_keyed_send_carries_the_journey_id_as_its_idempotency_key_on_every_attempt() {
    let far = HttpTransport::loopback();
    let (listener, address) = far.bind().expect("bound");
    let heard = hearing(listener, 3);
    let target = format!("http://{address}/orders");
    let sender = HttpTransport::loopback();
    sender.send_keyed(&target, b"order", KEY).expect("sent");
    sender
        .send_keyed(&target, b"order", KEY)
        .expect("sent again");
    sender.send(&target, b"order").expect("sent unkeyed");
    let quoted = format!("\"{KEY}\"");
    assert_eq!(
        heard.join().expect("far end"),
        [Some(quoted.clone()), Some(quoted), None]
    );
}

#[test]
fn a_key_is_written_as_a_structured_field_string() {
    assert_eq!(
        xmip_core_transport_http::idempotency_key("a\"b\\c"),
        "\"a\\\"b\\\\c\""
    );
}
