//! The Windows engine of Proxidize: packet diversion (WinDivert), TCP/UDP redirection, DNS interception, process
//! lookup, the WFP kill switch and the Windows integration (DPAPI, Start with Windows, firewall).
//!
//! The redirection logic is written against small traits ([`divert::Divert`], [`process::SystemInfo`],
//! [`killswitch::Filters`], [`engine::Platform`]) so it builds and is tested on any OS; the Windows
//! implementations of those traits are compiled on Windows only.

pub mod context;
pub mod divert;
pub mod dnsdivert;
pub mod engine;
pub mod killswitch;
pub mod process;
pub mod tcp;
pub mod udp;

#[cfg(windows)]
pub mod platform;
#[cfg(windows)]
pub mod wfp;
#[cfg(windows)]
pub mod win;
#[cfg(windows)]
pub mod windivert;

#[cfg(test)]
mod tests;
