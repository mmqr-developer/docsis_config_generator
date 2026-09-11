//! Parsing symbolic OIDs, including table index suffixes, back to numbers.
//!
//! Mirrors net-snmp's `get_node`/`read_objid` pair so that a config file
//! produced by decoding re-encodes to the same bytes.

use super::{BaseType, Index, Mib, NodeId};

/// Where the walk currently sits: above the roots, or at a named node.
#[derive(Clone, Copy)]
enum Cur {
    Top,
    Node(NodeId),
}

impl Mib {
    /// Resolve an OID written as a name, a numeric path, or a name followed by
    /// index values.  Tries name-first resolution before a rooted numeric path,
    /// which is the order the encoder uses.
    pub fn resolve_oid(&self, input: &str) -> Option<Vec<u32>> {
        self.get_node(input).or_else(|| self.read_objid(input))
    }

    /// Resolve a numeric path first, falling back to a name. Used where an OID
    /// is expected to be fully qualified.
    pub fn resolve_oid_numeric_first(&self, input: &str) -> Option<Vec<u32>> {
        self.read_objid(input).or_else(|| self.get_node(input))
    }

    /// Look up `name[.rest]`, where `name` is an object name anywhere in the tree.
    pub fn get_node(&self, input: &str) -> Option<Vec<u32>> {
        // Accept "MODULE::object" and "MODULE:object" qualification.
        let input = match input.rfind(':') {
            Some(pos) => &input[pos + 1..],
            None => input,
        };
        let input = input.strip_prefix('.').unwrap_or(input);

        let (first, rest) = split_component(input);
        let tp = self.find_by_label(first)?;
        let mut oid = self.oid_of(tp);
        if rest.is_some() && !self.add_strings_to_oid(Cur::Node(tp), rest, &mut oid) {
            return None;
        }
        Some(oid)
    }

    /// Look up a path starting from the OID roots, e.g. `.1.3.6.1.2.1.1.4.0`.
    pub fn read_objid(&self, input: &str) -> Option<Vec<u32>> {
        if input.contains(':') {
            return self.get_node(input);
        }
        let input = input.strip_prefix('.').unwrap_or(input);
        let mut oid = Vec::new();
        if self.add_strings_to_oid(Cur::Top, Some(input), &mut oid) {
            Some(oid)
        } else {
            None
        }
    }

    fn children_of(&self, cur: Cur) -> &[NodeId] {
        match cur {
            Cur::Top => &self.roots,
            Cur::Node(id) => &self.nodes[id].children,
        }
    }

    fn add_strings_to_oid(&self, start: Cur, mut cp: Option<&str>, oid: &mut Vec<u32>) -> bool {
        let mut tp = Some(start);

        // Descend the tree for as long as components name known children.
        while let (Some(text), Some(cur)) = (cp, tp) {
            if self.children_of(cur).is_empty() {
                break;
            }
            let (comp, rest) = split_component(text);
            let children = self.children_of(cur);

            let (subid, found) = if comp.starts_with(|c: char| c.is_ascii_digit()) {
                let Some(v) = parse_subid(comp) else {
                    return false;
                };
                (
                    v,
                    children.iter().copied().find(|&c| self.nodes[c].subid == v),
                )
            } else {
                let Some(id) = children
                    .iter()
                    .copied()
                    .find(|&c| self.nodes[c].label == comp)
                else {
                    return false;
                };
                (self.nodes[id].subid, Some(id))
            };

            oid.push(subid);
            cp = rest;
            match found {
                Some(id) => tp = Some(Cur::Node(id)),
                None => break,
            }
        }

        // Landing on a leaf means what follows are table index values.
        let mut in_dices: Vec<Index> = Vec::new();
        if let Some(Cur::Node(id)) = tp {
            if self.nodes[id].children.is_empty() {
                if let Some(parent) = self.nodes[id].parent {
                    if let Some(idx) = self.indexes_of(parent) {
                        in_dices = idx.to_vec();
                    }
                }
            }
        }

        let mut index_iter = in_dices.into_iter().peekable();
        while cp.is_some() && index_iter.peek().is_some() {
            let index = index_iter.next().unwrap();
            let Some(tp) = self.find_by_label(&index.label) else {
                break;
            };
            let syntax = self.nodes[tp].syntax.clone();
            let text = cp.unwrap();

            match syntax.base {
                b if b.is_integerish() || b == BaseType::TimeTicks => {
                    let (comp, rest) = split_component(text);
                    let subid = if comp.starts_with(|c: char| c.is_ascii_digit()) {
                        match parse_subid(comp) {
                            Some(v) => v,
                            None => return false,
                        }
                    } else {
                        match syntax.enums.iter().find(|(l, _)| l == comp) {
                            Some((_, v)) => *v as u32,
                            None => return false,
                        }
                    };
                    if !syntax.ranges.is_empty()
                        && !syntax
                            .ranges
                            .iter()
                            .any(|(lo, hi)| (*lo..=*hi).contains(&(subid as i64)))
                    {
                        return false;
                    }
                    oid.push(subid);
                    cp = rest;
                }
                BaseType::IpAddr => {
                    let mut text = Some(text);
                    for _ in 0..4 {
                        let Some(t) = text else { break };
                        let (comp, rest) = split_component(t);
                        let Some(v) = parse_subid(comp) else {
                            return false;
                        };
                        if v > 255 {
                            return false;
                        }
                        oid.push(v);
                        text = rest;
                    }
                    cp = text;
                }
                BaseType::OctetStr => {
                    let fixed = match syntax.ranges.as_slice() {
                        [(lo, hi)] if lo == hi => Some(*lo as usize),
                        _ => None,
                    };
                    let first = text.as_bytes().first().copied();
                    if first == Some(b'"') || first == Some(b'\'') {
                        let quote = first.unwrap() as char;
                        if fixed.is_none() && !index.implied {
                            if quote == '\'' {
                                return false; // '-quotes are for fixed-length strings
                            }
                        } else if quote == '"' {
                            return false; // "-quotes are for variable-length strings
                        }
                        let body_start = 1;
                        let Some(close) = find_unescaped(&text[body_start..], quote) else {
                            return false;
                        };
                        let body = unescape(&text[body_start..body_start + close]);
                        let len_index = if fixed.is_none() && !index.implied {
                            oid.push(0);
                            Some(oid.len() - 1)
                        } else {
                            None
                        };
                        for b in body.as_bytes() {
                            oid.push(*b as u32);
                        }
                        let pos = body.len();
                        if let Some(n) = fixed {
                            if pos != n {
                                return false;
                            }
                        } else {
                            if !syntax.ranges.is_empty()
                                && !syntax
                                    .ranges
                                    .iter()
                                    .any(|(lo, hi)| (*lo..=*hi).contains(&(pos as i64)))
                            {
                                return false;
                            }
                            if let Some(li) = len_index {
                                oid[li] = pos as u32;
                            }
                        }
                        let after = body_start + close + 1;
                        cp = match text.as_bytes().get(after) {
                            None => None,
                            Some(b'.') => Some(&text[after + 1..]),
                            Some(_) => return false,
                        };
                    } else {
                        let mut text = Some(text);
                        let mut len = fixed.map(|n| n as i64).unwrap_or(-1);
                        if len == -1 && !index.implied {
                            let Some(t) = text else { return false };
                            let (comp, rest) = split_component(t);
                            let Some(v) = parse_subid(comp) else {
                                return false;
                            };
                            oid.push(v);
                            len = v as i64;
                            text = rest;
                        }
                        while len > 0 {
                            let Some(t) = text else { break };
                            let (comp, rest) = split_component(t);
                            let Some(v) = parse_subid(comp) else {
                                return false;
                            };
                            if v > 255 {
                                return false;
                            }
                            oid.push(v);
                            len -= 1;
                            text = rest;
                        }
                        cp = text;
                    }
                }
                // Object identifier and unknown index types stop the breakdown.
                _ => break,
            }
        }

        // Whatever remains is a bare numeric or quoted-string tail.
        while let Some(text) = cp {
            if text.is_empty() {
                return false;
            }
            let first = text.as_bytes()[0];
            if first.is_ascii_digit() {
                let (comp, rest) = split_component(text);
                let Some(v) = parse_subid(comp) else {
                    return false;
                };
                oid.push(v);
                cp = rest;
            } else if first == b'"' || first == b'\'' {
                let quote = first as char;
                let Some(close) = text[1..].find(quote) else {
                    return false;
                };
                let body = &text[1..1 + close];
                if quote == '"' {
                    oid.push(body.len() as u32);
                }
                for b in body.as_bytes() {
                    oid.push(*b as u32);
                }
                let after = 1 + close + 1;
                cp = match text.as_bytes().get(after) {
                    None => None,
                    Some(b'.') => Some(&text[after + 1..]),
                    Some(_) => return false,
                };
            } else {
                return false;
            }
        }

        true
    }
}

/// Split off the text up to the next '.', returning the rest (if any).
fn split_component(s: &str) -> (&str, Option<&str>) {
    match s.find('.') {
        Some(pos) => (&s[..pos], Some(&s[pos + 1..])),
        None => (s, None),
    }
}

fn parse_subid(s: &str) -> Option<u32> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u32::from_str_radix(hex, 16).ok();
    }
    s.parse::<u32>().ok()
}

/// Find the closing quote, honouring backslash escapes.
fn find_unescaped(s: &str, quote: char) -> Option<usize> {
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' {
            i += 2;
            continue;
        }
        if bytes[i] == quote as u8 {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(n) = chars.next() {
                out.push(n);
            }
        } else {
            out.push(c);
        }
    }
    out
}
