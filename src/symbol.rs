//! The DOCSIS configuration-setting symbol table.
//!
//! Each `Symbol` ties a human-readable configuration keyword (as written in a
//! text config file) to the TLV code it encodes to, the encoder/decoder pair
//! used for its value, and the legal range of that value.  `parent_id` chains
//! entries into a tree: a sub-TLV names the `id` of the aggregate it lives in,
//! and top-level settings use 0.
//!
//! DOCSIS is a registered trademark of CableLabs, http://www.cablelabs.com

use crate::symtable::SYMTABLE;

/// How the value of a configuration setting is turned into TLV value bytes.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Enc {
    CharIpIp6,
    CharList,
    DualQtag,
    Ether,
    Ethermask,
    Hexstr,
    Ip,
    Ip6,
    Ip6List,
    Ip6PrefixList,
    IpIp6,
    IpIp6Port,
    IpList,
    Lenzero,
    Nothing,
    Oid,
    String,
    Strzero,
    Uchar,
    Uint,
    Uint24,
    Ushort,
    UshortList,
}

/// How TLV value bytes are rendered back into config-file text.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Dec {
    Aggregate,
    CharIpIp6,
    CharList,
    DualQtag,
    Ether,
    Ethermask,
    Hexstr,
    Ip,
    Ip6,
    Ip6List,
    Ip6PrefixList,
    IpIp6,
    IpIp6Port,
    IpList,
    Lenzero,
    Md5,
    Oid,
    SnmpObject,
    SnmpWd,
    Special,
    String,
    Strzero,
    Uchar,
    Uint,
    Uint24,
    Ushort,
    UshortList,
}

#[derive(Clone, Copy, Debug)]
pub struct Symbol {
    pub id: u32,
    pub ident: &'static str,
    pub code: u8,
    pub parent_id: u32,
    pub enc: Enc,
    pub dec: Dec,
    pub low: u32,
    pub high: u32,
}

/// Look up a setting by the keyword used in a text config file.
///
/// The first match in table order wins, matching the original C behaviour for
/// the handful of identifiers that repeat under different parents.
pub fn find_by_name(name: &str) -> Option<&'static Symbol> {
    SYMTABLE.iter().find(|s| s.ident == name)
}

/// Look up a setting by its TLV code within a given parent aggregate.
pub fn find_by_code_and_pid(code: u8, pid: u32) -> Option<&'static Symbol> {
    SYMTABLE
        .iter()
        .find(|s| s.code == code && s.parent_id == pid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};

    /// Walk from a symbol up to a top-level setting, returning its TLV path.
    fn tlv_path(sym: &Symbol) -> Option<Vec<u8>> {
        let by_id: HashMap<u32, &Symbol> = SYMTABLE.iter().map(|s| (s.id, s)).collect();
        let mut path = vec![sym.code];
        let mut cur = sym;
        for _ in 0..16 {
            if cur.parent_id == 0 {
                path.reverse();
                return Some(path);
            }
            cur = by_id.get(&cur.parent_id)?;
            path.push(cur.code);
        }
        None
    }

    #[test]
    fn every_symbol_reaches_a_top_level_setting() {
        for sym in SYMTABLE {
            assert!(
                tlv_path(sym).is_some(),
                "{} (id {}) has no path to a top-level TLV",
                sym.ident,
                sym.id
            );
        }
    }

    #[test]
    fn no_symbol_is_its_own_parent() {
        for sym in SYMTABLE {
            // Top-level settings use parent 0, which is also the id of the pad
            // marker; only a non-zero self-reference is a defect.
            if sym.parent_id == 0 {
                continue;
            }
            assert_ne!(
                sym.id, sym.parent_id,
                "{} (id {}) names itself as its parent",
                sym.ident, sym.id
            );
        }
    }

    /// A keyword is looked up by name alone, so the same keyword appearing
    /// under several parents must always encode to the same TLV code with the
    /// same encoder; otherwise only the first row would ever be reachable.
    #[test]
    fn a_keyword_always_means_the_same_tlv() {
        let mut seen: HashMap<&str, (u8, Enc)> = HashMap::new();
        for sym in SYMTABLE {
            match seen.get(sym.ident) {
                Some((code, enc)) => assert!(
                    *code == sym.code && *enc == sym.enc,
                    "{} means TLV {} as {:?} in one place and TLV {} as {:?} in another",
                    sym.ident,
                    code,
                    enc,
                    sym.code,
                    sym.enc
                ),
                None => {
                    seen.insert(sym.ident, (sym.code, sym.enc));
                }
            }
        }
    }

    /// Several keywords are deliberate aliases for one TLV - `DigitMap` and
    /// `SnmpMibObject` both write TLV 11, and `ManufacturerCVC` names a file
    /// whose contents `MfgCVCData` gives inline. Decoding picks the first row
    /// for a given code, so aliases must agree on how the value is rendered.
    #[test]
    fn aliases_for_one_tlv_decode_the_same_way() {
        let mut seen: HashSet<(u32, u8)> = HashSet::new();
        for sym in SYMTABLE {
            if !seen.insert((sym.parent_id, sym.code)) {
                let first = find_by_code_and_pid(sym.code, sym.parent_id).unwrap();
                assert_eq!(
                    first.dec, sym.dec,
                    "TLV code {} under parent {} decodes as {:?} via {} but {:?} via {}",
                    sym.code, sym.parent_id, first.dec, first.ident, sym.dec, sym.ident
                );
            }
        }
    }

    #[test]
    fn settings_added_from_the_current_specifications_are_reachable() {
        // Each of these was absent or unreachable in the C symbol table this
        // port was converted from; see docs/spec-coverage.md.
        for (ident, path) in [
            ("SingleDsChannelType", vec![41, 1, 3]),
            ("DsFreqRangeChannelType", vec![41, 2, 5]),
            ("DownstreamEHQoSASF", vec![94]),
        ] {
            let sym = find_by_name(ident).unwrap_or_else(|| panic!("{ident} is missing"));
            assert_eq!(
                tlv_path(sym).unwrap(),
                path,
                "{ident} sits at the wrong TLV path"
            );
        }

        // An L2VPN Encoding appears under seven different parents, so each new
        // subtype needs a row under all of them.
        for (ident, code) in [
            ("VPNSGAttribute", 22u8),
            ("L2VPNNetworkTimingProfileReference", 25),
            ("L2VPNMultipointForwardingMode", 27),
        ] {
            let parents: Vec<u32> = SYMTABLE
                .iter()
                .filter(|s| s.ident == "L2VPNEncoding")
                .map(|s| s.id)
                .collect();
            assert_eq!(parents.len(), 7);
            for parent in parents {
                let sym = find_by_code_and_pid(code, parent)
                    .unwrap_or_else(|| panic!("{ident} is missing under parent {parent}"));
                assert_eq!(sym.ident, ident);
            }
        }

        // These four were present but pointed at the wrong parent, so they
        // encoded correctly yet decoded as unknown TLVs.
        let by_id: HashMap<u32, &Symbol> = SYMTABLE.iter().map(|s| (s.id, s)).collect();
        let dls = SYMTABLE
            .iter()
            .find(|s| s.ident == "EnergyManagementDLSMode")
            .expect("TLV 74.4 is missing");
        let upstream = SYMTABLE
            .iter()
            .find(|s| s.ident == "UpstreamActivityDetectionParameters" && s.parent_id == dls.id)
            .expect("TLV 74.4.2 is missing");
        for code in 1..=4u8 {
            let child = find_by_code_and_pid(code, upstream.id)
                .unwrap_or_else(|| panic!("TLV 74.4.2.{code} is unreachable"));
            assert_eq!(
                by_id[&child.parent_id].ident,
                "UpstreamActivityDetectionParameters"
            );
        }
    }
}
