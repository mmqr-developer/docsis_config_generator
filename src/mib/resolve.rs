//! Places parsed definitions into the OID tree and resolves their syntax.
//!
//! Modules reference parents defined in other modules, so placement runs in
//! repeated passes until a pass makes no further progress.

use std::collections::HashMap;

use super::parse::{Def, OidElem, SyntaxRef, TypeDef};
use super::{BaseType, Mib, NodeId, Syntax};

impl Mib {
    pub(super) fn install(&mut self, defs: Vec<Def>, types: &HashMap<String, TypeDef>) {
        let mut pending = defs;

        loop {
            let before = pending.len();
            let mut deferred = Vec::with_capacity(before);

            for def in pending {
                match self.place(&def) {
                    Some(id) => self.attach(id, &def, types),
                    None => deferred.push(def),
                }
            }

            pending = deferred;
            if pending.len() == before || pending.is_empty() {
                break;
            }
        }
    }

    /// Resolve a definition's OID value to a node, creating arcs as needed.
    fn place(&mut self, def: &Def) -> Option<NodeId> {
        if def.elems.is_empty() {
            return None;
        }

        let mut cur: Option<NodeId> = None;
        let last = def.elems.len() - 1;

        for (idx, elem) in def.elems.iter().enumerate() {
            // Only the final arc carries the definition's own name.
            let label = if idx == last { def.name.as_str() } else { "" };

            cur = Some(match elem {
                OidElem::Num(v) => self.ensure_child(cur, *v, label),
                OidElem::NamedNum(name, v) => {
                    let id = self.ensure_child(cur, *v, name);
                    if idx == last && !def.name.is_empty() {
                        self.ensure_child(cur, *v, &def.name);
                    }
                    id
                }
                OidElem::Name(name) => {
                    if idx == 0 {
                        self.find_by_label(name)?
                    } else {
                        // A bare name deeper in the value must already exist as
                        // a child; otherwise its number is unknowable.
                        self.find_child_by_label(cur, name)?
                    }
                }
            });
        }

        cur
    }

    /// Attach a definition's syntax and indexes to a node.
    ///
    /// Two modules can define the same OID differently - the bundled
    /// PacketCable MIBs do exactly that.  net-snmp keeps both as peers but
    /// resolves lookups to the one loaded first, so the first definition to
    /// reach a node here is the one that sticks.
    fn attach(&mut self, id: NodeId, def: &Def, types: &HashMap<String, TypeDef>) {
        if let Some(sr) = &def.syntax {
            let syntax = resolve_syntax(sr, types, 0);
            let existing = &self.nodes[id].syntax;
            let unset = existing.base == BaseType::Other
                && existing.enums.is_empty()
                && existing.ranges.is_empty()
                && existing.hint.is_none();
            if unset && (syntax.base != BaseType::Other || !syntax.enums.is_empty()) {
                self.nodes[id].syntax = syntax;
            }
        }
        if !def.indexes.is_empty() && self.nodes[id].indexes.is_empty() {
            self.nodes[id].indexes = def.indexes.clone();
        }
        if def.augments.is_some() && self.nodes[id].augments.is_none() {
            self.nodes[id].augments = def.augments.clone();
        }
    }
}

/// Follow named types through textual conventions to a base type, keeping the
/// most specific constraint and enumeration seen along the way.
fn resolve_syntax(sr: &SyntaxRef, types: &HashMap<String, TypeDef>, depth: u32) -> Syntax {
    let mut out = Syntax {
        base: sr.base.unwrap_or_default(),
        enums: sr.enums.clone(),
        ranges: sr.ranges.clone(),
        hint: sr.hint.clone(),
    };

    if let Some(name) = &sr.named {
        if depth < 16 {
            if let Some(td) = types.get(name) {
                let inner = resolve_syntax(&td.syntax, types, depth + 1);
                out.base = inner.base;
                if out.enums.is_empty() {
                    out.enums = inner.enums;
                }
                // An outer constraint narrows the convention's own range.
                if out.ranges.is_empty() {
                    out.ranges = inner.ranges;
                }
                if out.hint.is_none() {
                    out.hint = inner.hint;
                }
            }
        }
    }

    out
}
