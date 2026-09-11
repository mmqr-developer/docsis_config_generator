//! Turning configuration-setting values into TLV value bytes.
//!
//! One function per `Enc` variant of the symbol table, mirroring the original
//! `docsis_encode.c`.  Every encoder reports the offending line and aborts on
//! bad input, which is what the C program did and what config authors expect.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::process::exit;

use crate::ethermac::ether_aton;
use crate::mib::Mib;
use crate::snmp;
use crate::symbol::{Enc, Symbol};
use crate::value::Value;
use crate::PROG;

pub struct Ctx<'a> {
    pub mib: &'a Mib,
    pub line: u32,
}

/// Encode one value according to the symbol's declared encoding.
pub fn encode(ctx: &Ctx, sym: &Symbol, value: &Value) -> Vec<u8> {
    match sym.enc {
        Enc::Uint => encode_uint(ctx, sym, value),
        Enc::Uint24 => encode_uint24(value),
        Enc::Ushort => encode_ushort(ctx, sym, value),
        Enc::Uchar => encode_uchar(ctx, sym, value),
        Enc::Ip => encode_ip(ctx, value),
        Enc::IpList => encode_ip_list(ctx, value),
        Enc::Ip6 => encode_ip6(ctx, value),
        Enc::Ip6List => encode_ip6_list(ctx, value),
        Enc::Ip6PrefixList => encode_ip6_prefix_list(ctx, value),
        Enc::IpIp6 => encode_ip_ip6(ctx, value),
        Enc::CharIpIp6 => encode_char_ip_ip6(ctx, value),
        Enc::IpIp6Port => encode_ip_ip6_port(ctx, value),
        Enc::Lenzero => Vec::new(),
        Enc::Ether => encode_ether(ctx, value),
        Enc::DualQtag => encode_dual_qtag(value),
        Enc::CharList => encode_char_list(value),
        Enc::Ethermask => encode_ethermask(ctx, value),
        Enc::String => encode_string(sym, value),
        Enc::Strzero => encode_strzero(sym, value),
        Enc::Hexstr => encode_hexstr(sym, value),
        Enc::Oid => encode_oid(ctx, value),
        Enc::UshortList => encode_ushort_list(ctx, sym, value),
        Enc::Nothing => Vec::new(),
    }
}

fn range_check(ctx: &Ctx, sym: &Symbol, v: u32) {
    if sym.low == 0 && sym.high == 0 {
        return;
    }
    if v < sym.low || v > sym.high {
        eprintln!(
            "{PROG}: at line {}, {} value {} out of range {}-{}",
            ctx.line, sym.ident, v, sym.low, sym.high
        );
        exit(241); // the C program's exit(-15)
    }
}

fn encode_uint(ctx: &Ctx, sym: &Symbol, value: &Value) -> Vec<u8> {
    let v = value.as_num() as u32;
    range_check(ctx, sym, v);
    v.to_be_bytes().to_vec()
}

fn encode_uint24(value: &Value) -> Vec<u8> {
    let v = value.as_num() as u32;
    vec![(v >> 16) as u8, (v >> 8) as u8, v as u8]
}

fn encode_ushort(ctx: &Ctx, sym: &Symbol, value: &Value) -> Vec<u8> {
    let v = value.as_num() as u32;
    range_check(ctx, sym, v);
    (v as u16).to_be_bytes().to_vec()
}

fn encode_uchar(ctx: &Ctx, sym: &Symbol, value: &Value) -> Vec<u8> {
    let v = value.as_num() as u32;
    range_check(ctx, sym, v);
    vec![v as u8]
}

/// Parse a dotted quad the way `inet_aton` does for the four-part form.
fn parse_ipv4(text: &str) -> Option<Ipv4Addr> {
    let parts: Vec<&str> = text.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut out = [0u8; 4];
    for (i, p) in parts.iter().enumerate() {
        let v: u32 = p.parse().ok()?;
        if v > 255 {
            return None;
        }
        out[i] = v as u8;
    }
    Some(Ipv4Addr::from(out))
}

fn bad_ip(ctx: &Ctx, text: &str) -> ! {
    eprintln!("Invalid IP address {} at line {}", text, ctx.line);
    exit(255);
}

fn encode_ip(ctx: &Ctx, value: &Value) -> Vec<u8> {
    let text = value.as_text();
    match parse_ipv4(text) {
        Some(a) => a.octets().to_vec(),
        None => bad_ip(ctx, text),
    }
}

fn encode_ip_list(ctx: &Ctx, value: &Value) -> Vec<u8> {
    let text = value.as_text();
    let mut out = Vec::new();
    for part in text.split(',').filter(|p| !p.is_empty()) {
        match parse_ipv4(part) {
            Some(a) => out.extend_from_slice(&a.octets()),
            None => bad_ip(ctx, text),
        }
    }
    out
}

fn encode_ip6(ctx: &Ctx, value: &Value) -> Vec<u8> {
    let text = value.as_text();
    match text.parse::<Ipv6Addr>() {
        Ok(a) => a.octets().to_vec(),
        Err(_) => bad_ip(ctx, text),
    }
}

fn encode_ip6_list(ctx: &Ctx, value: &Value) -> Vec<u8> {
    let text = value.as_text();
    let mut out = Vec::new();
    for part in text.split(',').filter(|p| !p.is_empty()) {
        match part.parse::<Ipv6Addr>() {
            Ok(a) => out.extend_from_slice(&a.octets()),
            Err(_) => bad_ip(ctx, text),
        }
    }
    out
}

/// Each entry is a 16-octet address followed by a one-octet prefix length.
fn encode_ip6_prefix_list(_ctx: &Ctx, value: &Value) -> Vec<u8> {
    let text = value.as_text();
    let mut out = Vec::new();
    for entry in text.split(',').filter(|p| !p.is_empty()) {
        let mut addr = [0u8; 16];
        let mut prefix = 0u8;
        for field in entry.split('/') {
            match field.parse::<Ipv6Addr>() {
                Ok(a) => addr = a.octets(),
                Err(_) => prefix = field.parse::<u8>().unwrap_or(0),
            }
        }
        out.extend_from_slice(&addr);
        out.push(prefix);
    }
    out
}

fn encode_ip_ip6(ctx: &Ctx, value: &Value) -> Vec<u8> {
    let text = value.as_text();
    if let Ok(a) = text.parse::<Ipv6Addr>() {
        return a.octets().to_vec();
    }
    match parse_ipv4(text) {
        Some(a) => a.octets().to_vec(),
        None => bad_ip(ctx, text),
    }
}

/// An address family selector byte followed by the address.
fn encode_char_ip_ip6(ctx: &Ctx, value: &Value) -> Vec<u8> {
    let text = value.as_text();
    if let Ok(a) = text.parse::<Ipv6Addr>() {
        let mut out = vec![2u8];
        out.extend_from_slice(&a.octets());
        return out;
    }
    match parse_ipv4(text) {
        Some(a) => {
            let mut out = vec![1u8];
            out.extend_from_slice(&a.octets());
            out
        }
        None => bad_ip(ctx, text),
    }
}

fn encode_ip_ip6_port(ctx: &Ctx, value: &Value) -> Vec<u8> {
    let text = value.as_text();
    let mut parts = text.split('/');
    let addr = parts.next().unwrap_or("");
    let port: u16 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(0);

    let mut out = if let Ok(a) = addr.parse::<Ipv6Addr>() {
        a.octets().to_vec()
    } else {
        match parse_ipv4(addr) {
            Some(a) => a.octets().to_vec(),
            None => {
                eprintln!(
                    "Invalid IP address / port combination {} at line {}",
                    text, ctx.line
                );
                exit(255);
            }
        }
    };
    out.extend_from_slice(&port.to_be_bytes());
    out
}

fn encode_ether(ctx: &Ctx, value: &Value) -> Vec<u8> {
    let text = value.as_text();
    match ether_aton(text) {
        Some(m) => m.to_vec(),
        None => {
            eprintln!("Invalid MAC address {} at line {}", text, ctx.line);
            exit(255);
        }
    }
}

/// `outer,inner` packed as two big-endian 16-bit tags.
fn encode_dual_qtag(value: &Value) -> Vec<u8> {
    let text = value.as_text();
    let mut parts = text.split(',');
    let a: u16 = parts
        .next()
        .and_then(|p| p.trim().parse().ok())
        .unwrap_or(0);
    let b: u16 = parts
        .next()
        .and_then(|p| p.trim().parse().ok())
        .unwrap_or(0);
    let mut out = a.to_be_bytes().to_vec();
    out.extend_from_slice(&b.to_be_bytes());
    out
}

fn encode_char_list(value: &Value) -> Vec<u8> {
    value
        .as_text()
        .split(',')
        .filter(|p| !p.is_empty())
        .map(|p| p.trim().parse::<i64>().unwrap_or(0) as u8)
        .collect()
}

fn encode_ethermask(ctx: &Ctx, value: &Value) -> Vec<u8> {
    let text = value.as_text();
    let Some((mac, mask)) = text.split_once('/') else {
        eprintln!(
            "encode_ethermask: at line {}, format should be <mac_address>/<mac_mask>",
            ctx.line
        );
        exit(255);
    };
    let mut out = Vec::with_capacity(12);
    for part in [mac, mask] {
        match ether_aton(part) {
            Some(m) => out.extend_from_slice(&m),
            None => {
                eprintln!("Invalid MAC address {} at line {}", part, ctx.line);
                exit(255);
            }
        }
    }
    out
}

fn check_string_len(sym: &Symbol, len: usize, what: &str) {
    if sym.low == 0 && sym.high == 0 {
        return;
    }
    if (len as u32) < sym.low {
        eprintln!("encode_{}: too short, must be min {} chars", what, sym.low);
        exit(255);
    }
    if sym.high < len as u32 {
        eprintln!(
            "encode_{}: too long ({} chars), must be max {} chars",
            what, len, sym.high
        );
        exit(255);
    }
}

fn encode_string(sym: &Symbol, value: &Value) -> Vec<u8> {
    let bytes = value.as_bytes().to_vec();
    check_string_len(sym, bytes.len(), "string");
    bytes
}

/// Strings that carry their terminating NUL, e.g. Service Flow Class Name.
fn encode_strzero(sym: &Symbol, value: &Value) -> Vec<u8> {
    let mut bytes = value.as_bytes().to_vec();
    check_string_len(sym, bytes.len(), "string");
    bytes.push(0);
    bytes
}

/// Convert a `0x...` literal to bytes. The digit count must be even and the
/// prefix is required, matching the original encoder.
pub fn parse_hexstr(text: &[u8]) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 {
        return None;
    }
    let body = text
        .strip_prefix(b"0x")
        .or_else(|| text.strip_prefix(b"0X"))?;
    let mut out = Vec::with_capacity(body.len() / 2);
    for pair in body.chunks(2) {
        let s = std::str::from_utf8(pair).ok()?;
        out.push(u8::from_str_radix(s, 16).ok()?);
    }
    Some(out)
}

fn encode_hexstr(sym: &Symbol, value: &Value) -> Vec<u8> {
    let raw = value.as_bytes();
    let Some(bytes) = parse_hexstr(raw) else {
        eprintln!(
            "encode_hexstr: invalid hex string {}",
            String::from_utf8_lossy(raw)
        );
        exit(255);
    };
    if sym.low != 0 || sym.high != 0 {
        if (bytes.len() as u32) < sym.low {
            eprintln!(
                "encode_hexstr: Hex value too short, must be min {} octets",
                sym.low
            );
            exit(255);
        }
        if sym.high < bytes.len() as u32 {
            eprintln!(
                "encode_hexstr: Hex value too long, must be max {} octets",
                sym.high
            );
            exit(255);
        }
    }
    bytes
}

fn encode_oid(ctx: &Ctx, value: &Value) -> Vec<u8> {
    snmp::encode_snmp_oid(ctx.mib, value.as_text(), ctx.line).unwrap_or_default()
}

fn encode_ushort_list(ctx: &Ctx, sym: &Symbol, value: &Value) -> Vec<u8> {
    let text = value.as_text();
    let mut out = Vec::new();
    let mut count = 0u32;
    for part in text.split([',', ' ']).filter(|p| !p.is_empty()) {
        let Ok(v) = part.parse::<u64>() else {
            eprintln!("Parse error at line {}: expecting digits", ctx.line);
            exit(245);
        };
        if v > 65535 {
            eprintln!(
                "Parse error at line {}: value cannot exceed 65535",
                ctx.line
            );
            exit(245);
        }
        out.extend_from_slice(&(v as u16).to_be_bytes());
        count += 1;
    }
    if sym.low != 0 || sym.high != 0 {
        if count < sym.low {
            eprintln!("Line {}: Not enough numbers, minimum {}", ctx.line, sym.low);
            exit(255);
        }
        if sym.high < count {
            eprintln!("Line {}: too many numbers, max {}", ctx.line, sym.high);
            exit(255);
        }
    }
    out
}
