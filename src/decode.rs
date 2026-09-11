//! Rendering a binary DOCSIS configuration file back into text.
//!
//! The output format is the one the encoder accepts, so a decoded file can be
//! re-encoded to the same bytes.  Indentation and comment placement follow the
//! original `docsis_decode.c` exactly.

use std::io::Write as _;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::ethermac::ether_ntoa;
use crate::mib::Mib;
use crate::snmp;
use crate::symbol::{self, Dec, Symbol};

const DIALPLAN_OUTPUT: &str = "dialplan_output.txt";

/// A varbind holding the PacketCable NA or EU configuration hash.
const NA_HASH_PREFIX: &[u8] = &[0x30, 0x26, 0x06, 0x0e];
const EU_HASH_PREFIX: &[u8] = &[0x30, 0x24, 0x06, 0x0c];
/// The OID of the PacketCable 2.0 dial plan object, as it appears in a varbind.
const DIALPLAN_OID: &[u8] = &[
    0x06, 0x12, 0x2b, 0x06, 0x01, 0x04, 0x01, 0xa3, 0x0b, 0x02, 0x02, 0x08, 0x02, 0x01, 0x01, 0x03,
    0x01, 0x01, 0x02,
];

pub struct Decoder<'a> {
    pub mib: &'a Mib,
    /// Suppress the PacketCable hash by rendering it as a comment.
    pub nohash: bool,
    out: Vec<u8>,
    tabs: usize,
    /// Set once a VendorIdentifier shows a non-generic vendor, after which
    /// sibling settings inside that block are no longer interpreted.
    vspecific: bool,
    /// Print object identifiers as numbers instead of names.
    numeric_oids: bool,
}

impl<'a> Decoder<'a> {
    pub fn new(mib: &'a Mib, nohash: bool) -> Decoder<'a> {
        Decoder {
            mib,
            nohash,
            out: Vec::new(),
            tabs: 0,
            vspecific: false,
            numeric_oids: false,
        }
    }

    /// Render object identifiers numerically, as the `-o` flag asks for.
    pub fn set_numeric_oids(&mut self, on: bool) {
        self.numeric_oids = on;
    }

    /// The decoded text. Bytes rather than a `String` because TLV string
    /// values are printed verbatim and need not be valid UTF-8.
    pub fn into_output(self) -> Vec<u8> {
        self.out
    }

    fn indent(&mut self) {
        for _ in 0..self.tabs {
            self.out.push(b'\t');
        }
    }

    /// Decode a whole configuration file.
    ///
    /// Unlike a nested aggregate this has no enclosing type or length, and it
    /// must cope with the MTA form where TLV 64 carries a 16-bit length.
    pub fn decode_main_aggregate(&mut self, buf: &[u8]) {
        self.tabs = 0;
        self.out.extend_from_slice(b"Main \n{\n");
        self.tabs += 1;

        let mut pos = 0usize;
        let mut is_mta = false;

        // The loop reads a length byte that may sit one past the end of a
        // padded file; a missing byte counts as zero.
        while pos < buf.len() {
            self.indent();

            let code = buf[pos];
            let mut sym = symbol::find_by_code_and_pid(code, 0);
            let mut llen = 1usize;
            let mut vlen = byte_at(buf, pos + 1) as usize;

            if code == 254 {
                is_mta = true;
            }
            if is_mta && code == 64 {
                // TLV 64 is the long form of TLV 11 (SnmpMibObject).
                sym = symbol::find_by_code_and_pid(11, 0);
                llen = 2;
                vlen = u16::from_be_bytes([byte_at(buf, pos + 1), byte_at(buf, pos + 2)]) as usize;
            }

            let vstart = (pos + 1 + llen).min(buf.len());
            let vend = (vstart + vlen).min(buf.len());
            match sym {
                Some(s) => self.dispatch(s, &buf[vstart..vend]),
                None => self.decode_unknown(&buf[pos..], vlen),
            }
            pos = vstart + vlen;
        }

        self.tabs -= 1;
        self.out.extend_from_slice(b"}\n");
    }

    fn dispatch(&mut self, sym: &Symbol, value: &[u8]) {
        match sym.dec {
            Dec::Aggregate => self.decode_aggregate(sym, value),
            Dec::Special => {
                let _ = writeln!(self.out, "{}", sym.ident);
            }
            Dec::Uint => self.decode_uint(sym, value),
            Dec::Uint24 => self.decode_uint24(sym, value),
            Dec::Ushort => self.decode_ushort(sym, value),
            Dec::Uchar => self.decode_uchar(sym, value),
            Dec::Ip => self.decode_ip(sym, value),
            Dec::IpList => self.decode_ip_list(sym, value),
            Dec::Ip6 => self.decode_ip6(sym, value),
            Dec::Ip6List => self.decode_ip6_list(sym, value),
            Dec::Ip6PrefixList => self.decode_ip6_prefix_list(sym, value),
            Dec::IpIp6 => self.decode_ip_ip6(sym, value),
            Dec::CharIpIp6 => self.decode_char_ip_ip6(sym, value),
            Dec::IpIp6Port => self.decode_ip_ip6_port(sym, value),
            Dec::Lenzero => {
                let _ = writeln!(self.out, "{} 0x00;", sym.ident);
            }
            Dec::Ether => self.decode_ether(sym, value),
            Dec::DualQtag => self.decode_dual_qtag(sym, value),
            Dec::CharList => self.decode_char_list(sym, value),
            Dec::Ethermask => self.decode_ethermask(sym, value),
            Dec::Md5 => self.decode_md5(sym, value),
            Dec::Oid => self.decode_oid(sym, value),
            Dec::SnmpObject => self.decode_snmp_object(sym, value),
            Dec::SnmpWd => self.decode_snmp_wd(sym, value),
            Dec::String => self.decode_string(sym, value),
            Dec::Strzero => self.decode_strzero(sym, value),
            Dec::Hexstr => self.decode_hexstr(sym, value),
            Dec::UshortList => self.decode_ushort_list(sym, value),
        }
    }

    fn decode_aggregate(&mut self, sym: &Symbol, buf: &[u8]) {
        let _ = writeln!(self.out, "{}", sym.ident);
        self.indent();
        self.out.extend_from_slice(b"{\n");
        self.tabs += 1;

        let mut pos = 0usize;
        while pos < buf.len() {
            self.indent();
            let vlen = byte_at(buf, pos + 1) as usize;
            let child = if self.vspecific {
                None
            } else {
                symbol::find_by_code_and_pid(buf[pos], sym.id)
            };
            let vstart = (pos + 2).min(buf.len());
            let vend = (vstart + vlen).min(buf.len());
            match child {
                Some(c) => self.dispatch(c, &buf[vstart..vend]),
                None => self.decode_unknown(&buf[pos..], vlen),
            }
            pos = vstart + vlen;
        }

        self.tabs -= 1;
        self.indent();
        self.vspecific = false;
        self.out.extend_from_slice(b"}\n");
    }

    /// Render a TLV with no symbol-table entry as a `GenericTLV` statement.
    fn decode_unknown(&mut self, tlv: &[u8], length: usize) {
        let mut len = length;
        if len > 256 {
            eprint!("/* ** next TLV is truncated** */");
            len = 256;
        }
        let code = tlv.first().copied().unwrap_or(0);
        let body = if tlv.len() > 2 {
            &tlv[2..(2 + len).min(tlv.len())]
        } else {
            &[][..]
        };

        if snmp::is_printable(body) && len > 1 {
            let _ = write!(
                self.out,
                "GenericTLV TlvCode {} TlvString \"{}\"; /* tlv length = {} */",
                code,
                String::from_utf8_lossy(body),
                len
            );
        } else if len > 1 && body.last() == Some(&0) && snmp::is_printable(&body[..body.len() - 1])
        {
            let _ = write!(
                self.out,
                "GenericTLV TlvCode {} TlvStringZero \"{}\"; /* tlv length = {} */",
                code,
                String::from_utf8_lossy(&body[..body.len() - 1]),
                len
            );
        } else {
            let _ = write!(
                self.out,
                "GenericTLV TlvCode {} TlvLength {} TlvValue {};",
                code,
                len,
                snmp::hexadecimal(body)
            );
        }
        self.out.push(b'\n');
    }

    fn decode_uint(&mut self, sym: &Symbol, v: &[u8]) {
        if v.len() != 4 {
            eprintln!("u_int length mismatch");
            std::process::exit(211);
        }
        let n = u32::from_be_bytes([v[0], v[1], v[2], v[3]]);
        let _ = writeln!(self.out, "{} {};", sym.ident, n);
    }

    fn decode_uint24(&mut self, sym: &Symbol, v: &[u8]) {
        let n = (v[0] as u32) << 16 | (v[1] as u32) << 8 | v[2] as u32;
        let _ = writeln!(self.out, "{} {};", sym.ident, n);
    }

    fn decode_ushort(&mut self, sym: &Symbol, v: &[u8]) {
        if v.len() != 2 {
            eprintln!("u_short length mismatch");
            std::process::exit(211);
        }
        let _ = writeln!(
            self.out,
            "{} {};",
            sym.ident,
            u16::from_be_bytes([v[0], v[1]])
        );
    }

    fn decode_uchar(&mut self, sym: &Symbol, v: &[u8]) {
        let _ = writeln!(
            self.out,
            "{} {};",
            sym.ident,
            v.first().copied().unwrap_or(0)
        );
    }

    fn decode_ip(&mut self, sym: &Symbol, v: &[u8]) {
        if v.len() != 4 {
            eprintln!("ip address length mismatch");
            std::process::exit(211);
        }
        let _ = writeln!(self.out, "{} {};", sym.ident, ipv4(v));
    }

    fn decode_ip_list(&mut self, sym: &Symbol, v: &[u8]) {
        let items: Vec<String> = v.chunks_exact(4).map(ipv4).collect();
        let _ = writeln!(self.out, "{} {};", sym.ident, items.join(","));
    }

    fn decode_ip6(&mut self, sym: &Symbol, v: &[u8]) {
        if v.len() != 16 {
            eprintln!("ip address length mismatch");
            std::process::exit(211);
        }
        let _ = writeln!(self.out, "{} {};", sym.ident, ipv6(v));
    }

    fn decode_ip6_list(&mut self, sym: &Symbol, v: &[u8]) {
        let items: Vec<String> = v.chunks_exact(16).map(ipv6).collect();
        let _ = writeln!(self.out, "{} {};", sym.ident, items.join(","));
    }

    fn decode_ip6_prefix_list(&mut self, sym: &Symbol, v: &[u8]) {
        let items: Vec<String> = v
            .chunks_exact(17)
            .map(|c| format!("{}/{}", ipv6(&c[..16]), c[16]))
            .collect();
        let _ = writeln!(self.out, "{} {};", sym.ident, items.join(","));
    }

    fn decode_ip_ip6(&mut self, sym: &Symbol, v: &[u8]) {
        match v.len() {
            4 => {
                let _ = writeln!(self.out, "{} {};", sym.ident, ipv4(v));
            }
            16 => {
                let _ = writeln!(self.out, "{} {};", sym.ident, ipv6(v));
            }
            _ => {}
        }
    }

    fn decode_char_ip_ip6(&mut self, sym: &Symbol, v: &[u8]) {
        match v.len() {
            5 => {
                let _ = writeln!(self.out, "{} {};", sym.ident, ipv4(&v[1..5]));
            }
            17 => {
                let _ = writeln!(self.out, "{} {};", sym.ident, ipv6(&v[1..17]));
            }
            _ => {}
        }
    }

    fn decode_ip_ip6_port(&mut self, sym: &Symbol, v: &[u8]) {
        match v.len() {
            6 => {
                let port = u16::from_be_bytes([v[4], v[5]]);
                let _ = writeln!(self.out, "{} {}/{};", sym.ident, ipv4(&v[..4]), port);
            }
            18 => {
                let port = u16::from_be_bytes([v[16], v[17]]);
                let _ = writeln!(self.out, "{} {}/{};", sym.ident, ipv6(&v[..16]), port);
            }
            _ => {}
        }
    }

    fn decode_ether(&mut self, sym: &Symbol, v: &[u8]) {
        if v.len() != 6 {
            eprintln!("ethermac length mismatch");
            std::process::exit(211);
        }
        let _ = writeln!(self.out, "{} {};", sym.ident, ether_ntoa(v));
    }

    fn decode_dual_qtag(&mut self, sym: &Symbol, v: &[u8]) {
        if v.len() != 4 {
            eprintln!("dual qtag length mismatch");
            std::process::exit(211);
        }
        let _ = writeln!(
            self.out,
            "{} {},{};",
            sym.ident,
            u16::from_be_bytes([v[0], v[1]]),
            u16::from_be_bytes([v[2], v[3]])
        );
    }

    fn decode_char_list(&mut self, sym: &Symbol, v: &[u8]) {
        let items: Vec<String> = v.iter().map(|b| b.to_string()).collect();
        let _ = writeln!(self.out, "{} {};", sym.ident, items.join(","));
    }

    fn decode_ethermask(&mut self, sym: &Symbol, v: &[u8]) {
        if v.len() != 12 {
            eprintln!("ethermac_and_mask length mismatch");
            std::process::exit(211);
        }
        let _ = writeln!(
            self.out,
            "{} {}/{};",
            sym.ident,
            ether_ntoa(&v[..6]),
            ether_ntoa(&v[6..12])
        );
    }

    fn decode_md5(&mut self, sym: &Symbol, v: &[u8]) {
        if v.len() != 16 {
            eprintln!("md5digest length mismatch");
            std::process::exit(211);
        }
        let hex: String = v.iter().map(|b| format!("{:02x}", b)).collect();
        let _ = writeln!(self.out, "/* {} {}; */", sym.ident, hex);
    }

    fn decode_string(&mut self, sym: &Symbol, v: &[u8]) {
        self.write_quoted(sym, v);
    }

    fn decode_strzero(&mut self, sym: &Symbol, v: &[u8]) {
        self.write_quoted(sym, v);
    }

    /// Emit `Name "value";` with the value bytes verbatim, stopping at the
    /// first NUL just as printing a C string would.
    fn write_quoted(&mut self, sym: &Symbol, v: &[u8]) {
        let end = v.iter().position(|&b| b == 0).unwrap_or(v.len());
        let _ = write!(self.out, "{} \"", sym.ident);
        self.out.extend_from_slice(&v[..end]);
        let _ = writeln!(self.out, "\";");
    }

    fn decode_hexstr(&mut self, sym: &Symbol, v: &[u8]) {
        let _ = writeln!(self.out, "{} {};", sym.ident, snmp::hexadecimal(v));
        // A vendor-specific block stops being interpretable past its identifier.
        if sym.ident.starts_with("VendorIdentifier")
            && v.len() >= 3
            && !(v[0] == 0xFF && v[1] == 0xFF && v[2] == 0xFF)
        {
            self.vspecific = true;
        }
    }

    fn decode_ushort_list(&mut self, sym: &Symbol, v: &[u8]) {
        let _ = write!(self.out, "{} ", sym.ident);
        let len = v.len() as u32;
        if len < 2 * sym.low || len > 2 * sym.high {
            self.out
                .extend_from_slice(b"/* -- warning: illegal length of buffer --*/");
        }
        let items: Vec<String> = v
            .chunks_exact(2)
            .map(|c| u16::from_be_bytes([c[0], c[1]]).to_string())
            .collect();
        let _ = writeln!(self.out, "{};", items.join(","));
    }

    fn decode_oid(&mut self, sym: &Symbol, v: &[u8]) {
        let _ = writeln!(
            self.out,
            "{} {};",
            sym.ident,
            snmp::decode_snmp_oid(self.mib, v)
        );
    }

    fn decode_snmp_wd(&mut self, sym: &Symbol, v: &[u8]) {
        if v.is_empty() {
            return;
        }
        let oid = snmp::decode_snmp_oid(self.mib, &v[..v.len() - 1]);
        let _ = writeln!(self.out, "{} {} {};", sym.ident, oid, v[v.len() - 1]);
    }

    fn decode_snmp_object(&mut self, sym: &Symbol, v: &[u8]) {
        if self.nohash && (v.starts_with(NA_HASH_PREFIX) || v.starts_with(EU_HASH_PREFIX)) {
            let _ = writeln!(
                self.out,
                "/* {} {} */",
                sym.ident,
                snmp::decode_vbind(self.mib, v, self.numeric_oids)
            );
            return;
        }

        // A PC2.0 dial plan is too large to show inline, so it is written out
        // to a file and referenced by name.
        let short_form = v.len() >= 24 && v[2..21] == *DIALPLAN_OID;
        let long_form = v.len() >= 26 && v[4..23] == *DIALPLAN_OID;
        if short_form || long_form {
            let body = if short_form {
                &v[24..]
            } else if v.len() >= 26 && v[24..26] == [0x04, 0x82] {
                &v[28.min(v.len())..]
            } else {
                &v[26.min(v.len())..]
            };
            if let Err(e) = std::fs::write(DIALPLAN_OUTPUT, body) {
                eprintln!("Cannot write {}: {}", DIALPLAN_OUTPUT, e);
            }
            let _ = writeln!(
                self.out,
                "DigitMap \"{}\"; /* file created. */",
                DIALPLAN_OUTPUT
            );
            return;
        }

        let _ = writeln!(
            self.out,
            "{} {}",
            sym.ident,
            snmp::decode_vbind(self.mib, v, self.numeric_oids)
        );
    }
}

/// Read a byte, treating anything past the end as zero, which is what the
/// original did when a padded file left the final length byte off the end.
fn byte_at(buf: &[u8], i: usize) -> u8 {
    buf.get(i).copied().unwrap_or(0)
}

fn ipv4(v: &[u8]) -> String {
    Ipv4Addr::new(v[0], v[1], v[2], v[3]).to_string()
}

fn ipv6(v: &[u8]) -> String {
    let mut octets = [0u8; 16];
    octets.copy_from_slice(&v[..16]);
    Ipv6Addr::from(octets).to_string()
}
