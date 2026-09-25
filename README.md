# xmip-core-transport-http

HTTP transport: one request body is one Stream, with a reply channel; HTTPS behind the tls feature. A technology of
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

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
