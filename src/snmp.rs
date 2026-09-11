//! SNMP variable-binding encoding and decoding for TLV 11 (SnmpMibObject),
//! TLV 34.1 (SnmpWriteControl) and the SNMPv3 access-view subtree settings.

use crate::asn1;
use crate::mib::{Mib, OidFormat};

/// The value types a `SnmpMibObject` line can carry, keyed by the same
/// single-character codes the original grammar used.
#[derive(Clone, Debug)]
pub enum VarValue {
    Int(i32),
    Gauge(u32),
    Counter(u32),
    TimeTicks(u32),
    Str(Vec<u8>),
    Ip([u8; 4]),
    Oid(String),
}

/// Build the value TLV plus the varbind SEQUENCE for one MIB object setting.
///
/// Returns `None` if the OID cannot be resolved, matching the original's
/// behaviour of reporting the problem and emitting a zero-length TLV.
pub fn encode_vbind(mib: &Mib, oid_string: &str, value: &VarValue, line: u32) -> Option<Vec<u8>> {
    let oid = match mib.resolve_oid(oid_string) {
        Some(o) => o,
        None => {
            eprintln!(
                "/* Error: Can't find oid {} at line {} */",
                oid_string, line
            );
            return None;
        }
    };

    let mut val = Vec::new();
    let mut short_header = true;

    match value {
        VarValue::Int(v) => asn1::build_int(&mut val, asn1::ASN_INTEGER, *v as i64),
        // The original assigns a signed int to an unsigned long, so a negative
        // literal sign-extends before encoding.
        VarValue::Gauge(v) => {
            asn1::build_unsigned_int(&mut val, asn1::ASN_GAUGE, *v as i32 as i64 as u64)
        }
        VarValue::Counter(v) => {
            asn1::build_unsigned_int(&mut val, asn1::ASN_COUNTER, *v as i32 as i64 as u64)
        }
        VarValue::TimeTicks(v) => {
            asn1::build_unsigned_int(&mut val, asn1::ASN_TIMETICKS, *v as i32 as i64 as u64)
        }
        VarValue::Ip(addr) => asn1::build_string(&mut val, asn1::ASN_IPADDRESS, addr),
        VarValue::Oid(text) => {
            let value_oid = mib.read_objid(text).or_else(|| mib.get_node(text))?;
            if !asn1::build_objid(&mut val, asn1::ASN_OBJECT_ID, &value_oid) {
                eprintln!("Can't find oid {} at line {}", text, line);
                return None;
            }
        }
        VarValue::Str(bytes) => {
            // Range-check the string against the MIB object's SIZE clause.
            if let Some(node) = mib.get_tree(&oid) {
                let ranges = &mib.node(node).syntax.ranges;
                if !ranges.is_empty()
                    && !ranges
                        .iter()
                        .any(|(lo, hi)| (*lo..=*hi).contains(&(bytes.len() as i64)))
                {
                    eprintln!("Value too long at line {}", line);
                    return None;
                }
            }
            // Long bindings need the four-octet SEQUENCE header.
            short_header = bytes.len() + oid.len() + 8 < 0x7f;
            asn1::build_string(&mut val, asn1::ASN_OCTET_STR, bytes);
        }
    }

    Some(asn1::build_var_op(&oid, &val, short_header))
}

/// Encode a bare object identifier value, as TLV 34.1 and TLV 54.2 use.
pub fn encode_snmp_oid(mib: &Mib, oid_string: &str, line: u32) -> Option<Vec<u8>> {
    let oid = match mib.resolve_oid_numeric_first(oid_string) {
        Some(o) => o,
        None => {
            eprintln!("Can't find oid {} at line {}", oid_string, line);
            return None;
        }
    };
    let mut out = Vec::new();
    if !asn1::build_objid(&mut out, asn1::ASN_OBJECT_ID, &oid) {
        return None;
    }
    Some(out)
}

/// Render an encoded object identifier in numeric form.
pub fn decode_snmp_oid(mib: &Mib, data: &[u8]) -> String {
    match asn1::parse_objid(data) {
        Some(oid) => mib.sprint_objid(&oid, OidFormat::Numeric),
        None => {
            eprint!("OID.parse.error");
            String::new()
        }
    }
}

/// Render a variable binding as `<oid> <Type> <value>;`, with the enumeration
/// label appended as a comment when the MIB names the integer value.
pub fn decode_vbind(mib: &Mib, data: &[u8], numeric_oids: bool) -> String {
    let Some(vb) = asn1::parse_var_op(data) else {
        return String::new();
    };

    let format = if numeric_oids {
        OidFormat::Numeric
    } else {
        OidFormat::Suffix
    };
    let mut oid_text = mib.sprint_objid(&vb.name, format);

    // The original re-parses the printed name to locate the MIB node; if that
    // fails it falls back to printing the fully qualified form.
    let resolved = mib.resolve_oid(&oid_text);
    if resolved.is_none() {
        eprintln!(
            "/* Hmm ... can't find oid {} ... perhaps the MIBs are not installed ? */",
            oid_text
        );
        oid_text = mib.sprint_objid(&vb.name, OidFormat::Full);
    }

    let node = resolved.as_deref().and_then(|o| mib.get_tree(o));
    let hint = node.and_then(|n| mib.node(n).syntax.hint.clone());

    let mut label = type_label(vb.val_type);
    let value_text = match vb.val_type {
        asn1::ASN_INTEGER => {
            let v = asn1::parse_int(vb.val);
            match &hint {
                Some(h) => hinted_integer(v, 'd', h),
                None => v.to_string(),
            }
        }
        asn1::ASN_COUNTER | asn1::ASN_GAUGE | asn1::ASN_UINTEGER => {
            let v = asn1::parse_unsigned(vb.val) as u32;
            match &hint {
                Some(h) => hinted_integer(v as i64, 'u', h),
                None => v.to_string(),
            }
        }
        // NUMERIC_TIMETICKS is enabled, so ticks print as a plain number.
        asn1::ASN_TIMETICKS => (asn1::parse_unsigned(vb.val) as u32).to_string(),
        asn1::ASN_COUNTER64 => asn1::parse_unsigned(vb.val).to_string(),
        asn1::ASN_OCTET_STR | asn1::ASN_OPAQUE | asn1::ASN_NSAP => {
            if is_printable(vb.val) {
                format!("\"{}\"", String::from_utf8_lossy(vb.val))
            } else {
                label = "HexString";
                hexadecimal(vb.val)
            }
        }
        asn1::ASN_IPADDRESS => {
            if vb.val.len() >= 4 {
                format!("{}.{}.{}.{}", vb.val[0], vb.val[1], vb.val[2], vb.val[3])
            } else {
                String::new()
            }
        }
        asn1::ASN_OBJECT_ID => match asn1::parse_objid_body(vb.val) {
            Some(o) => mib.sprint_objid(&o, OidFormat::Numeric),
            None => String::new(),
        },
        asn1::ASN_BIT_STR => hexadecimal(vb.val),
        asn1::ASN_NULL
        | asn1::SNMP_NOSUCHOBJECT
        | asn1::SNMP_NOSUCHINSTANCE
        | asn1::SNMP_ENDOFMIBVIEW => String::new(),
        other => {
            eprintln!("Error: bad type returned ({:x})", other);
            String::new()
        }
    };

    // Only integer values can match an enumeration in the MIB.
    let enum_label = if matches!(vb.val_type, asn1::ASN_INTEGER) {
        let v = asn1::parse_int(vb.val);
        node.and_then(|n| {
            mib.node(n)
                .syntax
                .enums
                .iter()
                .find(|(_, ev)| *ev == v)
                .map(|(l, _)| l.clone())
        })
    } else {
        None
    };

    match enum_label {
        Some(e) => format!("{} {} {}; /* {} */", oid_text, label, value_text, e),
        None => format!("{} {} {};", oid_text, label, value_text),
    }
}

fn type_label(t: u8) -> &'static str {
    match t {
        asn1::ASN_INTEGER => "Integer",
        asn1::ASN_COUNTER => "Counter32",
        asn1::ASN_GAUGE => "Gauge32",
        asn1::ASN_TIMETICKS => "TimeTicks",
        asn1::ASN_UINTEGER => "Unsigned32",
        asn1::ASN_COUNTER64 => "Counter64",
        asn1::ASN_OCTET_STR => "String",
        asn1::ASN_IPADDRESS => "IPAddress",
        asn1::ASN_OPAQUE => "Opaque",
        asn1::ASN_NSAP => "NSAP",
        asn1::ASN_OBJECT_ID => "ObjectID",
        asn1::ASN_BIT_STR => "BitString",
        asn1::ASN_BOOLEAN => "Boolean",
        _ => "",
    }
}

pub fn is_printable(s: &[u8]) -> bool {
    s.iter().all(|&b| (0x20..=0x7e).contains(&b))
}

pub fn hexadecimal(s: &[u8]) -> String {
    let mut out = String::with_capacity(2 + s.len() * 2);
    out.push_str("0x");
    for b in s {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

/// Apply a DISPLAY-HINT to an integer, following net-snmp's implementation.
fn hinted_integer(val: i64, decimal_type: char, hint: &str) -> String {
    let bytes = hint.as_bytes();
    if bytes.is_empty() {
        return val.to_string();
    }

    let mut shift = 0usize;
    let mut negative = false;
    let mut text = match bytes[0] {
        b'd' => {
            if bytes.len() > 1 && bytes[1] == b'-' {
                shift = hint[2..].parse::<usize>().unwrap_or(0);
            }
            let mut v = val;
            if v < 0 {
                negative = true;
                v = -v;
            }
            match decimal_type {
                'u' => (v as u64).to_string(),
                'x' => format!("{:x}", v),
                'o' => format!("{:o}", v),
                _ => v.to_string(),
            }
        }
        b'x' => format!("{:x}", val),
        b'o' => format!("{:o}", val),
        b'b' => {
            let mut s = String::with_capacity(32);
            for i in (0..32).rev() {
                s.push(if val & (1 << i) != 0 { '1' } else { '0' });
            }
            s
        }
        _ => return val.to_string(),
    };

    if shift != 0 {
        let len = text.len();
        if shift <= len {
            text.insert(len - shift, '.');
        } else {
            let mut s = String::from(".");
            for _ in 0..(shift - len) {
                s.push('0');
            }
            s.push_str(&text);
            text = s;
        }
    }
    if negative {
        text.insert(0, '-');
    }
    text
}
