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
a request taken off a connection and answered, and the judgement of a
status, which the technologies riding on HTTP share
(ADR-0044). The request and its answer — both halves, read by length,
chunks or the end — the RFC 1123 date a header carries, and the URL a
Location names are `net::http` and
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
what its `Offer` says — `Http11`, nothing; `Agreed`, `h2` and `http/1.1`
by ALPN over TLS; `PriorKnowledge`, HTTP/2 in the clear too — and reports
what the server selected; in the clear it speaks HTTP/2 only where the
Location says so — `HttpTransport::speaking_h2c`, prior knowledge, since
RFC 9113 removed HTTP/1.1's `Upgrade` — and HTTP/1.1 otherwise. A request
served (`server::serve_one`, a Receive Location, the Loopback far end) is
answered in HTTP/2 where the connection opens with its preface, and in
HTTP/1.1 otherwise; the octets read to tell are read again. A connection
served for one request — a far end, `server::serve_one` — says so before
its answer — `Connection: close`, or a `GOAWAY` ahead of the HTTP/2
answer — so a client that keeps connections lets it go.
`server::serve_one_from` hands the answer the peer it serves, which AS2's
and AS4's origins name. `server::answer_on` does the same on a connection
already accepted, for a server that bounds its wait for a connection and
its reads apart — the observe capability's Prometheus scrape endpoint.
HTTP/3 is open problem 30.

A Receive Location keeps what it serves on (`inbound::Inbound`, since
2026-09-27): its listener, bound on the first receive, and the
connections its callers keep, on the capability's `serving::Serving`.
Each receive takes the next request from whichever caller sends first —
HTTP/1.1 answered `Connection: keep-alive` unless the request said
`close`, HTTP/2 stream after stream on one connection, a pipelined
request taken from the buffer it was read into. Until then every receive
bound a listener of its own and answered one request with `Connection:
close`, so a sender's kept connection was used once and a request that
came between two receives was refused. AS2, AS4, Peppol, MSMQ, SNS's
subscription and Event Grid's webhook receive through it, each handing in
what it answers.

## The caller waits for the verdict

A request carrying a Stream is answered only after the runtime's whole
receive cycle (runtime-model section 5): `inbound::Inbound::next` hands back
what the technology heard and an `inbound::Reply`, which goes into the
arrival's acknowledgement (`Reply::acknowledgement`). The cycle ends in one
of three verdicts, and `HttpTransport` answers each by its status
(`server::status`, `server::verdict`), RFC 9110 section 15:

| Verdict | Status | The caller |
| --- | --- | --- |
| Accepted | `202 Accepted` | is done: the Stream is in Xmip's custody |
| Refused, Unidentified | `401 Unauthorized` | does not send it again unchanged |
| Refused, Forbidden | `403 Forbidden` | does not send it again unchanged |
| Refused, Unacceptable | `422 Unprocessable Content` | does not send it again unchanged |
| Failed | `503 Service Unavailable` | keeps the Stream and sends it again |

`202`, not `200`: Xmip has taken the Stream into custody and promised
nothing else. A technology riding on HTTP answers its own — an MDN, a
receipt — and takes these statuses where its protocol answers in HTTP's. The reply holds the connection for its answer
(`transport::answer::Answer`). Until the answer is written the connection is
busy (`transport::answer::Busy`, `serving::Open::busy`): it takes no next
request. A reply dropped unanswered shuts the connection, so a caller is
never left waiting. A
request that carries no Stream — a handshake, a refusal of what is not the
protocol's message — is answered at once (`inbound::Heard::Answered`). The
request body is read whole by `net::http`, within `net::MAX_BODY`, and
handed to the runtime as a reader over it.

## Connected once, not per request

`endpoint::Connections` keeps the connections a sender opened, per
endpoint — the transport capability's one session pool (`transport::Pool`),
holding HTTP connections — and every request after the first goes on the connection already
open: HTTP/1.1 kept alive — the request says no `Connection: close` — and
one HTTP/2 connection carrying stream after stream. `HttpTransport`, the
event wire, the observe capability's OTLP exporter and every technology
riding on HTTP hold one; a technology's transport hands its own to every
client it makes (`Client::sharing`), and the technologies offer `Http11`,
speaking HTTP/1.1 under their signatures unchanged. A connection is taken
for one request and put back after, so requests on several threads each
have one. One the far end closed meanwhile fails on reuse, and the request
goes again on a new connection: at least once. A kept connection holds
the socket beneath it, TLS or not, and is let go once the server has
closed it or, over HTTP/1.1, sent anything to it while it was idle
(`transport::pool::quiet`); the pool closes those before it opens another,
so a server gone for good holds no socket here. Until 2026-09-29 a
connection to a WebDAV far end at a new port every round was kept in
`CLOSE_WAIT` for good. `Connections::opened` says
how many were opened, and a test holds a hundred requests to one endpoint
to one connection, in either version. Until 2026-09-27 every request
connected, handshook TLS and said `Connection: close`, and every HTTP/2
request opened a connection of its own. `endpoint::connect` remains for a
session that holds its one connection itself: `WebDAV`'s, and a simulated
service pushing to its subscriber.

## The event capability's webhook

Since 2026-09-26 this transport carries the event capability's wire events
(ADR-0065 clause 3). `event_wire::EventWire` implements
[xmip-core-event](https://github.com/IlleNilsson/xmip-core-event)'s `Wire`:
it `POST`s what the event crate's HTTP binding wrote — structured or binary
mode, the `ce-` headers already escaped there, once — to the webhook
configured for the subscriber's Party, through `endpoint::Connections`,
TLS through the estate's own for `https://`. A 2xx is the
acknowledgement; 5xx, 408, 429 and a failed connection are retryable, any
other 4xx permanent (`status::judge`), and the resilience guards decide each
attempt: at least once. The identity presented is the bearer token
configured for the Party (ADR-0019 clause 3); a client certificate waits on
the estate's TLS offering a client identity. The connection to a webhook is
kept open between events, in either version, so an event costs one exchange
rather than a connect. `event_wire::carried` is the read side: a request a
receiving Xmip took, as the binding reads a `WireEvent` from.

Near, very near real time: `tests/event_wire.rs` measures publish to the
webhook's receipt over 300 Events and holds the median to a millisecond and
the 99th percentile to five, each beside a plain loopback TCP wake measured
under the same load.

## The deduplication key

A keyed send (`Transport::send_keyed`, built 2026-10-04) carries the Journey's identifier in the `Idempotency-Key` header of draft-ietf-httpapi-idempotency-key-header, written as the Structured Field string it defines: `Idempotency-Key: "<key>"` (`IDEMPOTENCY_KEY`, `idempotency_key`). Every attempt of one Journey carries the same key, so a server that honors the header answers a repeated POST with the first one's outcome rather than act on it twice; a server that does not ignores it. An unkeyed `send` carries no such header.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
