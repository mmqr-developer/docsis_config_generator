//! DOCSIS configuration file encoding and decoding.
//!
//! A Rust port of the `docsis` utility originally written by Cornel Ciocirlan
//! and later maintained by Evvolve Media and Adrian Simionov.  The library
//! reads a human-readable configuration file and produces the binary form a
//! cable modem or PacketCable MTA is provisioned with, and reverses it.
//!
//! DOCSIS is a registered trademark of CableLabs, http://www.cablelabs.com

/// The name this program is installed and invoked as.
///
/// It prefixes every diagnostic and appears in the usage text, so it has to
/// match the `[[bin]]` name in `Cargo.toml`. Kept in one place rather than
/// spelled out at each of the dozen call sites, which is how a renamed tool
/// ends up still introducing itself by its old name.
pub const PROG: &str = "gen_docsis";

pub mod asn1;
pub mod decode;
pub mod encode;
pub mod ethermac;
pub mod lexer;
pub mod mib;
pub mod parser;
pub mod snmp;
pub mod symbol;
pub mod symtable;
pub mod value;
pub mod version;
