//! This technology's declaration: the transport guide's "The declaration",
//! `module/core/capability/transport/doc/adding-a-transport.md`.

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
