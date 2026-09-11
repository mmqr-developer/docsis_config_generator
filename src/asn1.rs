//! Minimal ASN.1 BER encoding and decoding for SNMP variable bindings.
//!
//! This replaces the net-snmp `asn_build_*`/`asn_parse_*` calls the original C
//! program used, including the DOCSIS-specific quirk of forcing a short-form
//! length on the varbind SEQUENCE so that a binding fits in a single TLV.

pub const ASN_BOOLEAN: u8 = 0x01;
pub const ASN_INTEGER: u8 = 0x02;
pub const ASN_BIT_STR: u8 = 0x03;
pub const ASN_OCTET_STR: u8 = 0x04;
pub const ASN_NULL: u8 = 0x05;
pub const ASN_OBJECT_ID: u8 = 0x06;
pub const ASN_SEQUENCE: u8 = 0x30;

pub const ASN_IPADDRESS: u8 = 0x40;
pub const ASN_COUNTER: u8 = 0x41;
pub const ASN_GAUGE: u8 = 0x42;
pub const ASN_TIMETICKS: u8 = 0x43;
pub const ASN_OPAQUE: u8 = 0x44;
pub const ASN_NSAP: u8 = 0x45;
pub const ASN_COUNTER64: u8 = 0x46;
pub const ASN_UINTEGER: u8 = 0x47;

pub const SNMP_NOSUCHOBJECT: u8 = 0x80;
pub const SNMP_NOSUCHINSTANCE: u8 = 0x81;
pub const SNMP_ENDOFMIBVIEW: u8 = 0x82;

/// Append a BER length in the shortest form net-snmp would use.
pub fn build_length(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xFF {
        out.push(0x81);
        out.push(len as u8);
    } else {
        out.push(0x82);
        out.push((len >> 8) as u8);
        out.push(len as u8);
    }
}

pub fn build_header(out: &mut Vec<u8>, tag: u8, len: usize) {
    out.push(tag);
    build_length(out, len);
}

/// Encode a signed integer with the minimum number of content octets.
pub fn build_int(out: &mut Vec<u8>, tag: u8, value: i64) {
    let mut bytes = value.to_be_bytes().to_vec();
    // Drop leading octets that only replicate the sign bit.
    while bytes.len() > 1 {
        let lead = bytes[0];
        let next_high = bytes[1] & 0x80;
        if (lead == 0x00 && next_high == 0) || (lead == 0xFF && next_high != 0) {
            bytes.remove(0);
        } else {
            break;
        }
    }
    build_header(out, tag, bytes.len());
    out.extend_from_slice(&bytes);
}

/// Encode an unsigned integer, prefixing a zero octet when the high bit is set.
pub fn build_unsigned_int(out: &mut Vec<u8>, tag: u8, value: u64) {
    let mut bytes = value.to_be_bytes().to_vec();
    while bytes.len() > 1 && bytes[0] == 0 {
        bytes.remove(0);
    }
    if bytes[0] & 0x80 != 0 {
        bytes.insert(0, 0);
    }
    build_header(out, tag, bytes.len());
    out.extend_from_slice(&bytes);
}

pub fn build_string(out: &mut Vec<u8>, tag: u8, value: &[u8]) {
    build_header(out, tag, value.len());
    out.extend_from_slice(value);
}

/// Encode an object identifier, packing the first two arcs as net-snmp does.
pub fn build_objid(out: &mut Vec<u8>, tag: u8, oid: &[u32]) -> bool {
    if !oid.is_empty() && oid[0] > 2 {
        return false;
    }

    let mut subids: Vec<u32> = Vec::with_capacity(oid.len());
    match oid.len() {
        0 => subids.push(0),
        1 => subids.push(oid[0] * 40),
        _ => {
            subids.push(oid[0] * 40 + oid[1]);
            subids.extend_from_slice(&oid[2..]);
        }
    }

    let mut body = Vec::with_capacity(subids.len() * 2);
    for &v in &subids {
        encode_subid(&mut body, v);
    }
    build_header(out, tag, body.len());
    out.extend_from_slice(&body);
    true
}

fn encode_subid(out: &mut Vec<u8>, mut v: u32) {
    let mut stack = [0u8; 5];
    let mut n = 0;
    loop {
        stack[n] = (v & 0x7F) as u8;
        n += 1;
        v >>= 7;
        if v == 0 {
            break;
        }
    }
    for i in (0..n).rev() {
        let last = i == 0;
        out.push(if last { stack[i] } else { stack[i] | 0x80 });
    }
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

pub struct Tlv<'a> {
    pub tag: u8,
    pub value: &'a [u8],
    /// Length of tag plus length octets.
    pub header_len: usize,
}

/// Read one BER tag/length pair and the value it delimits.
pub fn parse_tlv(data: &[u8]) -> Option<Tlv<'_>> {
    if data.len() < 2 {
        return None;
    }
    let tag = data[0];
    let first = data[1];
    let (len, header_len) = if first & 0x80 == 0 {
        (first as usize, 2)
    } else {
        let count = (first & 0x7F) as usize;
        if count == 0 || count > 4 || data.len() < 2 + count {
            return None;
        }
        let mut len = 0usize;
        for i in 0..count {
            len = (len << 8) | data[2 + i] as usize;
        }
        (len, 2 + count)
    };
    if data.len() < header_len + len {
        return None;
    }
    Some(Tlv {
        tag,
        value: &data[header_len..header_len + len],
        header_len,
    })
}

pub fn parse_int(value: &[u8]) -> i64 {
    if value.is_empty() {
        return 0;
    }
    let mut out: i64 = if value[0] & 0x80 != 0 { -1 } else { 0 };
    for &b in value {
        out = (out << 8) | b as i64;
    }
    out
}

pub fn parse_unsigned(value: &[u8]) -> u64 {
    let mut out: u64 = 0;
    for &b in value {
        out = (out << 8) | b as u64;
    }
    out
}

/// Decode the contents of an OBJECT IDENTIFIER, unpacking the first two arcs.
pub fn parse_objid_body(value: &[u8]) -> Option<Vec<u32>> {
    let mut out = Vec::new();
    let mut i = 0;
    let mut first = true;
    while i < value.len() {
        let mut v: u32 = 0;
        loop {
            if i >= value.len() {
                return None;
            }
            let b = value[i];
            i += 1;
            v = v.checked_mul(128)?.checked_add((b & 0x7F) as u32)?;
            if b & 0x80 == 0 {
                break;
            }
        }
        if first {
            first = false;
            // net-snmp splits values below 40 as 0.x, else 1.x or 2.x.
            if v < 40 {
                out.push(0);
                out.push(v);
            } else if v < 80 {
                out.push(1);
                out.push(v - 40);
            } else {
                out.push(2);
                out.push(v - 80);
            }
        } else {
            out.push(v);
        }
    }
    Some(out)
}

/// Parse a complete OBJECT IDENTIFIER TLV.
pub fn parse_objid(data: &[u8]) -> Option<Vec<u32>> {
    let tlv = parse_tlv(data)?;
    if tlv.tag != ASN_OBJECT_ID {
        return None;
    }
    parse_objid_body(tlv.value)
}

/// One decoded SNMP variable binding.
pub struct VarBind<'a> {
    pub name: Vec<u32>,
    pub val_type: u8,
    pub val: &'a [u8],
}

/// Parse `SEQUENCE { OBJECT IDENTIFIER, value }`, the shape of TLV 11's payload.
pub fn parse_var_op(data: &[u8]) -> Option<VarBind<'_>> {
    let seq = parse_tlv(data)?;
    if seq.tag != ASN_SEQUENCE {
        return None;
    }
    let body = seq.value;
    let name_tlv = parse_tlv(body)?;
    if name_tlv.tag != ASN_OBJECT_ID {
        return None;
    }
    let name = parse_objid_body(name_tlv.value)?;
    let rest = &body[name_tlv.header_len + name_tlv.value.len()..];
    let val_tlv = parse_tlv(rest)?;
    Some(VarBind {
        name,
        val_type: val_tlv.tag,
        val: val_tlv.value,
    })
}

/// Build a variable binding TLV from an OID and an already-encoded value TLV.
///
/// `short_header` selects the DOCSIS-specific two-octet SEQUENCE header the
/// original program emits for bindings that fit; otherwise the four-octet
/// long form net-snmp always writes is used.
pub fn build_var_op(oid: &[u32], val_tlv: &[u8], short_header: bool) -> Vec<u8> {
    let mut inner = Vec::new();
    build_objid(&mut inner, ASN_OBJECT_ID, oid);
    inner.extend_from_slice(val_tlv);

    let mut out = Vec::with_capacity(inner.len() + 4);
    if short_header {
        out.push(ASN_SEQUENCE);
        out.push((inner.len() & 0xFF) as u8);
    } else {
        out.push(ASN_SEQUENCE);
        out.push(0x82);
        out.push((inner.len() >> 8) as u8);
        out.push((inner.len() & 0xFF) as u8);
    }
    out.extend_from_slice(&inner);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_use_the_shortest_encoding() {
        let mut out = Vec::new();
        build_int(&mut out, ASN_INTEGER, 1);
        assert_eq!(out, vec![0x02, 0x01, 0x01]);

        out.clear();
        build_int(&mut out, ASN_INTEGER, 0);
        assert_eq!(out, vec![0x02, 0x01, 0x00]);

        out.clear();
        build_int(&mut out, ASN_INTEGER, -1);
        assert_eq!(out, vec![0x02, 0x01, 0xFF]);

        out.clear();
        build_int(&mut out, ASN_INTEGER, 128);
        assert_eq!(out, vec![0x02, 0x02, 0x00, 0x80]);

        out.clear();
        build_int(&mut out, ASN_INTEGER, 65535);
        assert_eq!(out, vec![0x02, 0x03, 0x00, 0xFF, 0xFF]);
    }

    #[test]
    fn unsigned_values_keep_a_leading_zero_when_signed_would_flip() {
        let mut out = Vec::new();
        build_unsigned_int(&mut out, ASN_GAUGE, 5060);
        assert_eq!(out, vec![0x42, 0x02, 0x13, 0xC4]);

        out.clear();
        build_unsigned_int(&mut out, ASN_GAUGE, 0x8000_0000);
        assert_eq!(out, vec![0x42, 0x05, 0x00, 0x80, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn lengths_switch_to_the_long_form_past_127() {
        let mut out = Vec::new();
        build_length(&mut out, 0x7f);
        assert_eq!(out, vec![0x7f]);

        out.clear();
        build_length(&mut out, 0x80);
        assert_eq!(out, vec![0x81, 0x80]);

        out.clear();
        build_length(&mut out, 0x1234);
        assert_eq!(out, vec![0x82, 0x12, 0x34]);
    }

    #[test]
    fn object_identifiers_pack_the_first_two_arcs() {
        let mut out = Vec::new();
        // sysContact.0
        assert!(build_objid(
            &mut out,
            ASN_OBJECT_ID,
            &[1, 3, 6, 1, 2, 1, 1, 4, 0]
        ));
        assert_eq!(out, vec![0x06, 0x08, 0x2b, 6, 1, 2, 1, 1, 4, 0]);
        assert_eq!(parse_objid(&out).unwrap(), vec![1, 3, 6, 1, 2, 1, 1, 4, 0]);
    }

    #[test]
    fn large_subidentifiers_use_continuation_octets() {
        let mut out = Vec::new();
        assert!(build_objid(
            &mut out,
            ASN_OBJECT_ID,
            &[1, 3, 6, 1, 4, 1, 4491]
        ));
        assert_eq!(out, vec![0x06, 0x07, 0x2b, 6, 1, 4, 1, 0xa3, 0x0b]);
        assert_eq!(parse_objid(&out).unwrap(), vec![1, 3, 6, 1, 4, 1, 4491]);
    }

    #[test]
    fn a_varbind_round_trips() {
        let mut val = Vec::new();
        build_int(&mut val, ASN_INTEGER, 3);
        let vb = build_var_op(&[1, 3, 6, 1, 2, 1, 69, 1, 1, 1, 0], &val, true);
        assert_eq!(vb[0], ASN_SEQUENCE);
        assert_eq!(vb[1] as usize, vb.len() - 2);

        let parsed = parse_var_op(&vb).unwrap();
        assert_eq!(parsed.name, vec![1, 3, 6, 1, 2, 1, 69, 1, 1, 1, 0]);
        assert_eq!(parsed.val_type, ASN_INTEGER);
        assert_eq!(parse_int(parsed.val), 3);
    }

    #[test]
    fn the_long_sequence_header_is_four_octets() {
        let mut val = Vec::new();
        build_string(&mut val, ASN_OCTET_STR, &[b'x'; 300]);
        let vb = build_var_op(&[1, 3, 6, 1], &val, false);
        assert_eq!(&vb[..2], &[ASN_SEQUENCE, 0x82]);
        assert_eq!(u16::from_be_bytes([vb[2], vb[3]]) as usize, vb.len() - 4);
    }
}
