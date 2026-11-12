//! Platform-independent core of Proxidize: configuration, rules, packet codec, DNS, proxy clients and the relay.
//! Everything here builds and is tested on any OS; the Windows-only parts live in `proxidize-win`.

pub mod clock;
pub mod config;
pub mod dns;
pub mod fakeip;
pub mod fragments;
pub mod health;
pub mod log;
pub mod matching;
pub mod net;
pub mod packet;
pub mod proxy;
pub mod proxycap;
pub mod relay;
pub mod resolve;
pub mod rules;
