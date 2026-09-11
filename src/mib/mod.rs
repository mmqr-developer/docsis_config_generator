//! A self-contained SMIv1/SMIv2 MIB reader.
//!
//! It replaces the parts of net-snmp the original C program relied on: turning
//! MIB modules on disk into an OID tree, resolving object names (with table
//! index suffixes) to numeric OIDs, and rendering numeric OIDs back to the
//! symbolic form used in DOCSIS text config files.

pub mod lexer;
mod oidstr;
mod parse;
mod render;
mod resolve;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

pub use render::OidFormat;

/// The base ASN.1 type an object resolves to once textual conventions and
/// type aliases have been followed.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum BaseType {
    #[default]
    Other,
    ObjId,
    OctetStr,
    Integer,
    NetAddr,
    IpAddr,
    Counter,
    Gauge,
    TimeTicks,
    Opaque,
    Null,
    Counter64,
    BitString,
    Uinteger,
    Unsigned32,
    Integer32,
}

impl BaseType {
    /// Whether an index of this type occupies one sub-identifier holding a
    /// plain number, which several code paths treat alike.
    pub fn is_integerish(self) -> bool {
        matches!(
            self,
            BaseType::Integer
                | BaseType::Integer32
                | BaseType::Uinteger
                | BaseType::Unsigned32
                | BaseType::Gauge
        )
    }
}

#[derive(Clone, Debug, Default)]
pub struct Syntax {
    pub base: BaseType,
    /// Named values from `INTEGER { up(1), down(2) }` or a `BITS` clause.
    pub enums: Vec<(String, i64)>,
    /// Value ranges, or SIZE ranges when `base` is `OctetStr`.
    pub ranges: Vec<(i64, i64)>,
    /// The textual convention's DISPLAY-HINT, if it had one.
    pub hint: Option<String>,
}

#[derive(Clone, Debug)]
pub struct Index {
    pub label: String,
    pub implied: bool,
}

pub type NodeId = usize;

#[derive(Clone, Debug)]
pub struct Node {
    pub label: String,
    pub subid: u32,
    pub parent: Option<NodeId>,
    pub children: Vec<NodeId>,
    pub syntax: Syntax,
    /// INDEX clause of a table row entry.
    pub indexes: Vec<Index>,
    /// AUGMENTS clause: this row's indexes come from another table's entry.
    pub augments: Option<String>,
    /// True for the placeholder nodes we invent for unnamed OID arcs.
    pub anonymous: bool,
}

pub struct Mib {
    nodes: Vec<Node>,
    roots: Vec<NodeId>,
    by_label: HashMap<String, NodeId>,
}

impl Default for Mib {
    fn default() -> Self {
        Self::new()
    }
}

impl Mib {
    pub fn new() -> Mib {
        Mib {
            nodes: Vec::new(),
            roots: Vec::new(),
            by_label: HashMap::new(),
        }
    }

    pub fn node(&self, id: NodeId) -> &Node {
        &self.nodes[id]
    }

    /// Load every MIB module found in `dirs`, in the order given.
    ///
    /// Files that fail to parse are skipped silently, matching net-snmp's
    /// tolerance of the malformed MIBs that ship with real hardware.
    pub fn load_dirs<P: AsRef<Path>>(dirs: &[P]) -> Mib {
        let mut files: Vec<PathBuf> = Vec::new();
        for dir in dirs {
            let Ok(entries) = std::fs::read_dir(dir.as_ref()) else {
                continue;
            };
            let mut here: Vec<PathBuf> = entries
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.is_file() && !is_ignored_file(p))
                .collect();
            here.sort();
            files.extend(here);
        }

        let mut mib = Mib::new();
        mib.seed_roots();

        let mut defs = Vec::new();
        let mut types: HashMap<String, parse::TypeDef> = HashMap::new();
        for path in &files {
            let Ok(src) = std::fs::read(path) else {
                continue;
            };
            let toks = lexer::tokenize(&src);
            parse::parse_module(&toks, &mut defs, &mut types);
        }

        mib.install(defs, &types);
        mib
    }

    /// Register the three ASN.1 roots plus the arcs every MIB assumes exist.
    fn seed_roots(&mut self) {
        for (label, subid) in [("ccitt", 0u32), ("iso", 1), ("joint-iso-ccitt", 2)] {
            let id = self.push_node(label.to_string(), subid, None);
            self.roots.push(id);
        }
    }

    fn push_node(&mut self, label: String, subid: u32, parent: Option<NodeId>) -> NodeId {
        let anonymous = label.is_empty();
        let id = self.nodes.len();
        self.nodes.push(Node {
            label: label.clone(),
            subid,
            parent,
            children: Vec::new(),
            syntax: Syntax::default(),
            indexes: Vec::new(),
            augments: None,
            anonymous,
        });
        if let Some(p) = parent {
            self.nodes[p].children.push(id);
        }
        if !anonymous {
            // First definition of a label wins, so that a core MIB is not
            // shadowed by a vendor module loaded later.
            self.by_label.entry(label).or_insert(id);
        }
        id
    }

    fn find_child(&self, parent: Option<NodeId>, subid: u32) -> Option<NodeId> {
        let list = match parent {
            Some(p) => &self.nodes[p].children,
            None => &self.roots,
        };
        list.iter().copied().find(|&c| self.nodes[c].subid == subid)
    }

    fn find_child_by_label(&self, parent: Option<NodeId>, label: &str) -> Option<NodeId> {
        let list = match parent {
            Some(p) => &self.nodes[p].children,
            None => &self.roots,
        };
        list.iter().copied().find(|&c| self.nodes[c].label == label)
    }

    /// Find or create the node at `parent.subid`, naming it if it was anonymous.
    fn ensure_child(&mut self, parent: Option<NodeId>, subid: u32, label: &str) -> NodeId {
        if let Some(id) = self.find_child(parent, subid) {
            if !label.is_empty() && self.nodes[id].anonymous {
                self.nodes[id].label = label.to_string();
                self.nodes[id].anonymous = false;
                self.by_label.entry(label.to_string()).or_insert(id);
            } else if !label.is_empty() {
                self.by_label.entry(label.to_string()).or_insert(id);
            }
            return id;
        }
        let id = self.push_node(label.to_string(), subid, parent);
        if parent.is_none() {
            self.roots.push(id);
        }
        id
    }

    /// Look up a node by its bare object name.
    pub fn find_by_label(&self, label: &str) -> Option<NodeId> {
        self.by_label.get(label).copied()
    }

    /// The numeric OID of a node.
    pub fn oid_of(&self, id: NodeId) -> Vec<u32> {
        let mut out = Vec::new();
        let mut cur = Some(id);
        while let Some(c) = cur {
            out.push(self.nodes[c].subid);
            cur = self.nodes[c].parent;
        }
        out.reverse();
        out
    }

    /// Walk as far down the tree as `oid` goes, returning the deepest node
    /// reached.  Equivalent to net-snmp's `get_tree`.
    pub fn get_tree(&self, oid: &[u32]) -> Option<NodeId> {
        let mut parent: Option<NodeId> = None;
        let mut last = None;
        for &sub in oid {
            match self.find_child(parent, sub) {
                Some(id) => {
                    last = Some(id);
                    parent = Some(id);
                }
                None => break,
            }
        }
        last
    }

    /// The INDEX list that applies to a row entry, following AUGMENTS.
    fn indexes_of(&self, id: NodeId) -> Option<&[Index]> {
        let n = &self.nodes[id];
        if !n.indexes.is_empty() {
            return Some(&n.indexes);
        }
        if let Some(aug) = &n.augments {
            let other = self.find_by_label(aug)?;
            if !self.nodes[other].indexes.is_empty() {
                return Some(&self.nodes[other].indexes);
            }
        }
        None
    }
}

/// Skip build scaffolding that happens to sit next to the MIB files.
fn is_ignored_file(p: &Path) -> bool {
    let Some(name) = p.file_name().and_then(|s| s.to_str()) else {
        return true;
    };
    name.starts_with('.')
        || name.starts_with("Makefile")
        || name.ends_with(".am")
        || name.ends_with(".in")
        || name.ends_with(".o")
        || name.ends_with(".gz")
        || name.ends_with(".bz2")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mib::parse::TypeDef;
    use std::collections::HashMap;

    /// Build a MIB from module text, as if the modules had been read from disk.
    fn load(sources: &[&str]) -> Mib {
        let mut mib = Mib::new();
        mib.seed_roots();
        let mut defs = Vec::new();
        let mut types: HashMap<String, TypeDef> = HashMap::new();
        for src in sources {
            let toks = lexer::tokenize(src.as_bytes());
            parse::parse_module(&toks, &mut defs, &mut types);
        }
        mib.install(defs, &types);
        mib
    }

    const SMI: &str = r#"
        SNMPv2-SMI DEFINITIONS ::= BEGIN
        org OBJECT IDENTIFIER ::= { iso 3 }
        dod OBJECT IDENTIFIER ::= { org 6 }
        internet OBJECT IDENTIFIER ::= { dod 1 }
        mgmt OBJECT IDENTIFIER ::= { internet 2 }
        mib-2 OBJECT IDENTIFIER ::= { mgmt 1 }
        private OBJECT IDENTIFIER ::= { internet 4 }
        enterprises OBJECT IDENTIFIER ::= { private 1 }
        END
    "#;

    const TC: &str = r#"
        SNMPv2-TC DEFINITIONS ::= BEGIN
        DisplayString ::= TEXTUAL-CONVENTION
            DISPLAY-HINT "255a"
            STATUS current
            DESCRIPTION "text"
            SYNTAX OCTET STRING (SIZE (0..255))
        RowStatus ::= TEXTUAL-CONVENTION
            STATUS current
            DESCRIPTION "text"
            SYNTAX INTEGER { active(1), notInService(2), createAndGo(4), destroy(6) }
        END
    "#;

    const TABLE: &str = r#"
        EXAMPLE-MIB DEFINITIONS ::= BEGIN
        IMPORTS DisplayString, RowStatus FROM SNMPv2-TC;
        exMib OBJECT IDENTIFIER ::= { mib-2 9999 }

        exName OBJECT-TYPE
            SYNTAX DisplayString
            MAX-ACCESS read-only
            STATUS current
            DESCRIPTION "-- not a comment --"
            ::= { exMib 1 }

        exTable OBJECT-TYPE
            SYNTAX SEQUENCE OF ExEntry
            MAX-ACCESS not-accessible
            STATUS current
            DESCRIPTION "t"
            ::= { exMib 2 }

        exEntry OBJECT-TYPE
            SYNTAX ExEntry
            MAX-ACCESS not-accessible
            STATUS current
            DESCRIPTION "e"
            INDEX { exIndex, IMPLIED exLabel }
            ::= { exTable 1 }

        ExEntry ::= SEQUENCE { exIndex INTEGER, exLabel DisplayString, exStatus RowStatus }

        exIndex OBJECT-TYPE
            SYNTAX INTEGER (1..64)
            MAX-ACCESS not-accessible
            STATUS current
            DESCRIPTION "i"
            ::= { exEntry 1 }

        exLabel OBJECT-TYPE
            SYNTAX DisplayString (SIZE (1..32))
            MAX-ACCESS not-accessible
            STATUS current
            DESCRIPTION "l"
            ::= { exEntry 2 }

        exStatus OBJECT-TYPE
            SYNTAX RowStatus
            MAX-ACCESS read-create
            STATUS current
            DESCRIPTION "s"
            ::= { exEntry 3 }
        END
    "#;

    #[test]
    fn resolves_names_to_numeric_oids() {
        let mib = load(&[SMI, TC, TABLE]);
        assert_eq!(
            mib.get_node("exName.0").unwrap(),
            vec![1, 3, 6, 1, 2, 1, 9999, 1, 0]
        );
        assert_eq!(
            mib.read_objid(".1.3.6.1.2.1.9999.1.0").unwrap(),
            vec![1, 3, 6, 1, 2, 1, 9999, 1, 0]
        );
    }

    #[test]
    fn a_textual_convention_carries_its_hint_and_enums() {
        let mib = load(&[SMI, TC, TABLE]);
        let name = mib.find_by_label("exName").unwrap();
        assert_eq!(mib.node(name).syntax.base, BaseType::OctetStr);
        assert_eq!(mib.node(name).syntax.hint.as_deref(), Some("255a"));

        let status = mib.find_by_label("exStatus").unwrap();
        assert_eq!(mib.node(status).syntax.base, BaseType::Integer);
        assert!(mib
            .node(status)
            .syntax
            .enums
            .iter()
            .any(|(l, v)| l == "createAndGo" && *v == 4));
    }

    #[test]
    fn an_outer_constraint_narrows_the_conventions_range() {
        let mib = load(&[SMI, TC, TABLE]);
        let label = mib.find_by_label("exLabel").unwrap();
        assert_eq!(mib.node(label).syntax.ranges, vec![(1, 32)]);
    }

    #[test]
    fn table_indexes_round_trip_through_text() {
        let mib = load(&[SMI, TC, TABLE]);
        // exIndex is a plain integer; exLabel is an IMPLIED string.
        let oid = mib.get_node("exStatus.7.'abc'").unwrap();
        let mut want = vec![1, 3, 6, 1, 2, 1, 9999, 2, 1, 3, 7];
        want.extend(b"abc".iter().map(|b| *b as u32));
        assert_eq!(oid, want);
        assert_eq!(
            mib.sprint_objid(&oid, OidFormat::Suffix),
            "exStatus.7.'abc'"
        );
    }

    #[test]
    fn an_unresolved_tail_prints_as_numbers() {
        let mib = load(&[SMI, TC, TABLE]);
        let oid = vec![1, 3, 6, 1, 4, 1, 4115, 11, 1, 2, 1];
        assert_eq!(
            mib.sprint_objid(&oid, OidFormat::Suffix),
            "enterprises.4115.11.1.2.1"
        );
        assert_eq!(
            mib.sprint_objid(&oid, OidFormat::Numeric),
            ".1.3.6.1.4.1.4115.11.1.2.1"
        );
    }

    #[test]
    fn the_first_module_to_define_a_node_wins() {
        let other = r#"
            OTHER-MIB DEFINITIONS ::= BEGIN
            exName OBJECT-TYPE
                SYNTAX INTEGER (0..7)
                MAX-ACCESS read-only
                STATUS current
                DESCRIPTION "conflicting definition at the same OID"
                ::= { exMib 1 }
            END
        "#;
        let mib = load(&[SMI, TC, TABLE, other]);
        let name = mib.find_by_label("exName").unwrap();
        assert_eq!(mib.node(name).syntax.base, BaseType::OctetStr);
    }

    #[test]
    fn comment_syntax_does_not_swallow_definitions() {
        let mib = load(&[SMI, TC, TABLE]);
        // The description above exName contains "--" inside a string literal.
        assert!(mib.find_by_label("exTable").is_some());
        assert!(mib.find_by_label("exStatus").is_some());
    }
}
