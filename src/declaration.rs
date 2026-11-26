//! What a Location of this technology is configured with: its declaration,
//! which `Configured` reads, built with the crate's `declaration` feature
//! alone and the code behind the default (ADR-0064, amendments 2026-10-22
//! and 2026-11-26), for the library the surfaces load to carry (open
//! problem 48).

use xcore::settings::{Applies, Kind, Presence, Setting, Settings};

/// Every setting a Location takes beyond its address: where a Receive
/// Location listens; a Send Location posts to the URL its target names.
pub const SETTINGS: &Settings = &Settings {
    technology: env!("CARGO_PKG_NAME"),
    settings: &[
        Setting {
            name: "h2c",
            kind: Kind::Boolean,
            presence: Presence::Optional,
            meaning: "Whether HTTP/2 is spoken to an http:// endpoint by prior knowledge; \
                      HTTP/1.1 in the clear when left out.",
            applies: Applies::Send,
        },
        transport::configured::timeout(
            Applies::Both,
            None,
            "How long a connection is waited for, accepted or opened, and how \
             long one that stops sending is waited on; unbounded when left out.",
        ),
    ],
};

/// The schemes an HTTP Location's address is entered with.
pub const SCHEMES: &[&str] = &["http", "https"];
