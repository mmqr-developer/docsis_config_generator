//! Conversion between numeric OIDs and their symbolic text form.
//!
//! Both directions reproduce net-snmp's behaviour, including how table indexes
//! are broken out into quoted strings, enum labels and dotted quads, because
//! DOCSIS config files are round-tripped through this representation.

use super::{BaseType, Index, Mib, NodeId};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum OidFormat {
    /// `.1.3.6.1.2.1.1.4.0`
    Numeric,
    /// `.iso.org.dod.internet.mgmt.mib-2.system.sysContact.0`
    Full,
    /// `sysContact.0` - the last named node plus its instance.
    Suffix,
}

impl Mib {
    /// Render a numeric OID in the requested format.
    pub fn sprint_objid(&self, oid: &[u32], format: OidFormat) -> String {
        let numeric = format == OidFormat::Numeric;
        let mut buf = String::from(".");
        let mut end_of_known = None;

        let roots = self.roots.clone();
        self.get_symbol(oid, &roots, &mut buf, None, &mut end_of_known, numeric);

        match format {
            OidFormat::Numeric | OidFormat::Full => buf,
            OidFormat::Suffix => {
                let bytes = buf.as_bytes();
                // Start just before the '.' that precedes the unresolved tail;
                // with nothing unresolved, start at the last letter.
                let mut cp: isize = match end_of_known {
                    Some(off) => off as isize - 2,
                    None => {
                        let mut k = bytes.len() as isize;
                        while k >= 0 {
                            if k < bytes.len() as isize && bytes[k as usize].is_ascii_alphabetic() {
                                break;
                            }
                            k -= 1;
                        }
                        k
                    }
                };
                while cp >= 0 {
                    if bytes[cp as usize] == b'.' {
                        break;
                    }
                    cp -= 1;
                }
                buf[(cp + 1) as usize..].to_string()
            }
        }
    }

    /// The recursive tree walk behind `sprint_objid`.
    ///
    /// Returns the deepest node matched, or `None` once the OID leaves the
    /// tree, in which case `end_of_known` records where the names stopped.
    fn get_symbol(
        &self,
        objid: &[u32],
        subtree: &[NodeId],
        buf: &mut String,
        in_dices: Option<Vec<Index>>,
        end_of_known: &mut Option<usize>,
        numeric: bool,
    ) -> Option<NodeId> {
        let mut in_dices = in_dices;

        if !objid.is_empty() {
            for &id in subtree {
                let node = &self.nodes[id];
                if node.subid != objid[0] {
                    continue;
                }

                if let Some(idx) = self.indexes_of(id) {
                    in_dices = Some(idx.to_vec());
                }

                if node.anonymous || numeric {
                    buf.push_str(&node.subid.to_string());
                } else {
                    buf.push_str(&node.label);
                }

                if objid.len() > 1 {
                    buf.push('.');
                    let children = node.children.clone();
                    let deeper = self.get_symbol(
                        &objid[1..],
                        &children,
                        buf,
                        in_dices,
                        end_of_known,
                        numeric,
                    );
                    if deeper.is_some() {
                        return deeper;
                    }
                }
                return Some(id);
            }
        }

        *end_of_known = Some(buf.len());

        let mut rest = objid;

        // A row entry's own sub-identifier is not part of any index.
        if !subtree.is_empty() && in_dices.is_some() && !rest.is_empty() {
            buf.push_str(&format!("{}.", rest[0]));
            rest = &rest[1..];
        }

        if !numeric {
            if let Some(indices) = in_dices {
                rest = self.format_indexes(&indices, rest, buf);
            }
        }

        // Anything left over prints as bare numbers.
        if !buf.ends_with('.') {
            buf.push('.');
        }
        for sub in rest {
            buf.push_str(&format!("{}.", sub));
        }
        buf.pop();

        None
    }

    /// Render as many index values as the remaining sub-identifiers allow,
    /// returning what is left unconsumed.
    fn format_indexes<'a>(
        &self,
        indices: &[Index],
        mut objid: &'a [u32],
        buf: &mut String,
    ) -> &'a [u32] {
        for index in indices {
            if objid.is_empty() {
                break;
            }
            let Some(tp) = self.find_by_label(&index.label) else {
                break;
            };
            let syntax = &self.nodes[tp].syntax;

            match syntax.base {
                BaseType::OctetStr => {
                    let fixed = match syntax.ranges.as_slice() {
                        [(lo, hi)] if lo == hi => Some(*lo as usize),
                        _ => None,
                    };
                    if index.implied {
                        let n = objid.len();
                        dump_oid_to_string(&objid[..n], buf, '\'');
                        objid = &objid[n..];
                    } else if let Some(n) = fixed {
                        if n > objid.len() {
                            break;
                        }
                        dump_oid_to_string(&objid[..n], buf, '\'');
                        objid = &objid[n..];
                    } else {
                        let n = objid[0] as usize + 1;
                        if n > objid.len() {
                            break;
                        }
                        if n == 1 {
                            buf.push_str("\"\"");
                        } else {
                            dump_oid_to_string(&objid[1..n], buf, '"');
                        }
                        objid = &objid[n..];
                    }
                }
                b if b.is_integerish() => {
                    let v = objid[0] as i64;
                    match syntax.enums.iter().find(|(_, ev)| *ev == v) {
                        Some((label, _)) => buf.push_str(label),
                        None => buf.push_str(&v.to_string()),
                    }
                    objid = &objid[1..];
                }
                BaseType::TimeTicks => {
                    buf.push_str(&objid[0].to_string());
                    objid = &objid[1..];
                }
                BaseType::ObjId => {
                    let n = if index.implied {
                        objid.len()
                    } else {
                        objid[0] as usize + 1
                    };
                    if n > objid.len() {
                        break;
                    }
                    let roots = self.roots.clone();
                    let mut ignored = None;
                    self.get_symbol(&objid[..n], &roots, buf, None, &mut ignored, false);
                    objid = &objid[n..];
                }
                BaseType::IpAddr => {
                    if objid.len() < 4 {
                        break;
                    }
                    buf.push_str(&format!(
                        "{}.{}.{}.{}",
                        objid[0], objid[1], objid[2], objid[3]
                    ));
                    objid = &objid[4..];
                }
                BaseType::NetAddr => {
                    let ntype = objid[0];
                    buf.push_str(&format!("{}.", ntype));
                    objid = &objid[1..];
                    if ntype == 1 && objid.len() >= 4 {
                        buf.push_str(&format!(
                            "{}.{}.{}.{}",
                            objid[0], objid[1], objid[2], objid[3]
                        ));
                        objid = &objid[4..];
                    } else {
                        break;
                    }
                }
                _ => break,
            }

            buf.push('.');
        }

        objid
    }
}

/// Print sub-identifiers as a quoted character string, substituting '.' for
/// anything unprintable, exactly as net-snmp does.
fn dump_oid_to_string(objid: &[u32], buf: &mut String, quote: char) {
    if objid.is_empty() {
        return;
    }
    buf.push(quote);
    for &sub in objid {
        let c = if sub > 254 || !(0x20..0x7f).contains(&sub) {
            '.'
        } else {
            sub as u8 as char
        };
        buf.push(c);
    }
    buf.push(quote);
}
