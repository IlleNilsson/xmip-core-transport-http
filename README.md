# xmip-core-transport-http

HTTP transport: one request body is one Stream, with a reply channel; HTTP/2 or HTTP/1.1 per connection; HTTPS behind the tls feature. A technology of
[xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport), which
owns the direction-neutral `Transport` trait this crate implements (ADR-0010).

Lifted out of the capability crate on 2026-09-07, where it had lived as
`src/http` since 2026-08-27 waiting for this repository. The capability keeps
the trait, the error vocabulary and the shared wire helpers; nothing in it names
a protocol. The head a line-oriented protocol reads — lines, then a blank
line — left it on 2026-09-25 for `net::head` in
[xmip-core-library-net](https://github.com/IlleNilsson/xmip-core-library-net).

This crate holds what is the HTTP transport's own: the connection to an
endpoint, HTTPS through
[xmip-core-library-tls](https://github.com/IlleNilsson/xmip-core-library-tls),
a request taken off a connection and answered, RFC 1123's date and the
judgement of a status, which the technologies riding on HTTP share
(ADR-0044). The request and its answer — both halves, read by length,
chunks or the end — and the URL a Location names are `net::http` and
`net::Endpoint` in
[xmip-core-library-net](https://github.com/IlleNilsson/xmip-core-library-net)
since 2026-09-25: one HTTP/1.1 codec, which the technologies riding on HTTP
call directly. This crate carried a second one, a third writer to send a
Stream and its own URL reader until then. Percent-encoding and the
authority are URI's, not HTTP's, and are read and written in
[xmip-core-library-net](https://github.com/IlleNilsson/xmip-core-library-net)
since 2026-09-24, where the identifiers and the form shape reach them too. What a vendor speaks
over it is the vendor's: Signature Version 4, the AWS Query API and
`x-amz-date` are in
[xmip-core-transport-aws](https://github.com/IlleNilsson/xmip-core-transport-aws),
and Azure's Shared Access Signature and a Service Bus namespace's answers in
[xmip-core-transport-azure](https://github.com/IlleNilsson/xmip-core-transport-azure).
They lived here from 2026-09-14 until the owner's ruling of 2026-09-22 moved
them, on 2026-09-24.

## HTTP/2 or HTTP/1.1, per connection

Since 2026-09-25 the version is the connection's. `endpoint::open` offers
`h2` and `http/1.1` by ALPN over TLS and reports what the server selected;
in the clear it speaks HTTP/2 only where the Location says so —
`HttpTransport::speaking_h2c`, prior knowledge, since RFC 9113 removed
HTTP/1.1's `Upgrade` — and HTTP/1.1 otherwise. `endpoint::exchange` sends
a request in whichever it is, through `net::http` or `net::http2`. A
request served (`server::serve_one`, a Receive Location, the Loopback far
end) is answered in HTTP/2 where the connection opens with its preface, and
in HTTP/1.1 otherwise; the octets read to tell are read again.
`server::answer_on` does the same on a connection already accepted, for a
server that bounds its wait for a connection and its reads apart — the
observe capability's Prometheus scrape endpoint, and its OTLP exporter
sends with `endpoint::exchange`. The
technologies riding on HTTP connect with `endpoint::connect`, which offers
nothing, and keep speaking HTTP/1.1 unchanged. HTTP/3 is open problem 30.

## The event capability's webhook

Since 2026-09-26 this transport carries the event capability's wire events
(ADR-0065 clause 3). `event_wire::EventWire` implements
[xmip-core-event](https://github.com/IlleNilsson/xmip-core-event)'s `Wire`:
it `POST`s what the event crate's HTTP binding wrote — structured or binary
mode, the `ce-` headers already escaped there, once — to the webhook
configured for the subscriber's Party, through `endpoint::open` and
`net::http`, TLS through the estate's own for `https://`. A 2xx is the
acknowledgement; 5xx, 408, 429 and a failed connection are retryable, any
other 4xx permanent (`status::judge`), and the resilience guards decide each
attempt: at least once. The identity presented is the bearer token
configured for the Party (ADR-0019 clause 3); a client certificate waits on
the estate's TLS offering a client identity. Over HTTP/1.1 the connection to
a webhook is kept open between events, so an event costs one exchange rather
than a connect. `event_wire::carried` is the read side: a request a
receiving Xmip took, as the binding reads a `WireEvent` from.

Near, very near real time: `tests/event_wire.rs` measures publish to the
webhook's receipt over 300 Events and holds the median to a millisecond and
the 99th percentile to five, each beside a plain loopback TCP wake measured
under the same load.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
