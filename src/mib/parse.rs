//! Turns a tokenized MIB module into unresolved OID definitions and type
//! definitions.  Nothing here touches the OID tree; placement happens later,
//! once every module has been read, because modules routinely forward-reference
//! parents defined in a file that has not been loaded yet.

use super::lexer::Tok;
use super::{BaseType, Index};

/// One element of an OID value such as `{ iso org(3) dod(6) 1 }`.
#[derive(Clone, Debug)]
pub enum OidElem {
    Num(u32),
    Name(String),
    NamedNum(String, u32),
}

/// A syntax clause before textual conventions have been resolved.
#[derive(Clone, Debug, Default)]
pub struct SyntaxRef {
    /// A type name still to be looked up, e.g. `SnmpAdminString`.
    pub named: Option<String>,
    pub base: Option<BaseType>,
    pub enums: Vec<(String, i64)>,
    pub ranges: Vec<(i64, i64)>,
    pub hint: Option<String>,
}

#[derive(Clone, Debug)]
pub struct TypeDef {
    pub syntax: SyntaxRef,
}

#[derive(Clone, Debug)]
pub struct Def {
    pub name: String,
    pub elems: Vec<OidElem>,
    pub syntax: Option<SyntaxRef>,
    pub indexes: Vec<Index>,
    pub augments: Option<String>,
}

/// Macro names whose invocations end in `::= { oid }` and therefore name a node.
const OID_MACROS: &[&str] = &[
    "OBJECT-TYPE",
    "MODULE-IDENTITY",
    "OBJECT-IDENTITY",
    "NOTIFICATION-TYPE",
    "OBJECT-GROUP",
    "NOTIFICATION-GROUP",
    "MODULE-COMPLIANCE",
    "AGENT-CAPABILITIES",
];

fn is_word(t: Option<&Tok>, w: &str) -> bool {
    matches!(t, Some(Tok::Word(x)) if x == w)
}

pub fn parse_module(
    toks: &[Tok],
    defs: &mut Vec<Def>,
    types: &mut std::collections::HashMap<String, TypeDef>,
) {
    let n = toks.len();
    let mut i = 0usize;

    while i < n {
        // IMPORTS/EXPORTS lists look like definitions; skip them wholesale.
        if is_word(toks.get(i), "IMPORTS") || is_word(toks.get(i), "EXPORTS") {
            while i < n && toks[i] != Tok::Semi {
                i += 1;
            }
            i += 1;
            continue;
        }

        // "<Module> DEFINITIONS ::= BEGIN"
        if is_word(toks.get(i + 1), "DEFINITIONS") {
            while i < n && !is_word(toks.get(i), "BEGIN") {
                i += 1;
            }
            i += 1;
            continue;
        }

        let Some(Tok::Word(name)) = toks.get(i) else {
            i += 1;
            continue;
        };

        // "<name> OBJECT IDENTIFIER ::= { ... }"
        if is_word(toks.get(i + 1), "OBJECT")
            && is_word(toks.get(i + 2), "IDENTIFIER")
            && toks.get(i + 3) == Some(&Tok::Assign)
        {
            if let Some((elems, next)) = parse_oid_value(toks, i + 4) {
                defs.push(Def {
                    name: name.clone(),
                    elems,
                    syntax: None,
                    indexes: Vec::new(),
                    augments: None,
                });
                i = next;
                continue;
            }
            i += 4;
            continue;
        }

        // "<name> <MACRO> ... ::= { ... }"
        if let Some(Tok::Word(m)) = toks.get(i + 1) {
            if OID_MACROS.contains(&m.as_str()) {
                let is_object_type = m == "OBJECT-TYPE";
                let (body, assign_at) = scan_to_assign(toks, i + 2);
                let mut def = Def {
                    name: name.clone(),
                    elems: Vec::new(),
                    syntax: None,
                    indexes: Vec::new(),
                    augments: None,
                };
                if is_object_type {
                    collect_object_clauses(toks, body, assign_at, &mut def);
                }
                match parse_oid_value(toks, assign_at + 1) {
                    Some((elems, next)) => {
                        def.elems = elems;
                        defs.push(def);
                        i = next;
                    }
                    // SMIv1 TRAP-TYPE and friends end in "::= <number>".
                    None => i = assign_at + 1,
                }
                continue;
            }
        }

        // "<Name> ::= <type>" - a textual convention or plain type alias.
        if toks.get(i + 1) == Some(&Tok::Assign) {
            if is_word(toks.get(i + 2), "BEGIN") {
                i += 3;
                continue;
            }
            if is_word(toks.get(i + 2), "TEXTUAL-CONVENTION") {
                let (syntax, next) = parse_textual_convention(toks, i + 3);
                types.insert(name.clone(), TypeDef { syntax });
                i = next;
                continue;
            }
            let (syntax, next) = parse_type(toks, i + 2);
            if syntax.base.is_some() || syntax.named.is_some() {
                types.insert(name.clone(), TypeDef { syntax });
            }
            i = next;
            continue;
        }

        i += 1;
    }
}

/// Find the `::=` that terminates a macro invocation, returning the body span.
fn scan_to_assign(toks: &[Tok], start: usize) -> (usize, usize) {
    let mut i = start;
    while i < toks.len() && toks[i] != Tok::Assign {
        i += 1;
    }
    (start, i.min(toks.len().saturating_sub(1)))
}

/// Pull SYNTAX, INDEX and AUGMENTS out of an OBJECT-TYPE body.
fn collect_object_clauses(toks: &[Tok], start: usize, end: usize, def: &mut Def) {
    let mut i = start;
    while i < end {
        match &toks[i] {
            Tok::Word(w) if w == "SYNTAX" && def.syntax.is_none() => {
                let (syntax, next) = parse_type(toks, i + 1);
                def.syntax = Some(syntax);
                i = next;
            }
            Tok::Word(w) if w == "INDEX" => {
                i += 1;
                if toks.get(i) == Some(&Tok::LBrace) {
                    i += 1;
                    let mut implied = false;
                    while i < end && toks[i] != Tok::RBrace {
                        match &toks[i] {
                            Tok::Word(w) if w == "IMPLIED" => implied = true,
                            Tok::Word(w) => {
                                def.indexes.push(Index {
                                    label: w.clone(),
                                    implied,
                                });
                                implied = false;
                            }
                            _ => {}
                        }
                        i += 1;
                    }
                    i += 1;
                }
            }
            Tok::Word(w) if w == "AUGMENTS" => {
                i += 1;
                if toks.get(i) == Some(&Tok::LBrace) {
                    i += 1;
                    if let Some(Tok::Word(w)) = toks.get(i) {
                        def.augments = Some(w.clone());
                    }
                    while i < end && toks[i] != Tok::RBrace {
                        i += 1;
                    }
                    i += 1;
                }
            }
            _ => i += 1,
        }
    }
}

fn parse_textual_convention(toks: &[Tok], start: usize) -> (SyntaxRef, usize) {
    let mut hint = None;
    let mut i = start;
    // Walk the TC's clauses until SYNTAX, which is always last.
    while i < toks.len() {
        match &toks[i] {
            Tok::Word(w) if w == "DISPLAY-HINT" => {
                if let Some(Tok::Str(s)) = toks.get(i + 1) {
                    hint = Some(s.clone());
                }
                i += 2;
            }
            Tok::Word(w) if w == "SYNTAX" => {
                let (mut syntax, next) = parse_type(toks, i + 1);
                if syntax.hint.is_none() {
                    syntax.hint = hint;
                }
                return (syntax, next);
            }
            _ => i += 1,
        }
        // A malformed TC should not swallow the rest of the file.
        if i > start + 400 {
            break;
        }
    }
    (
        SyntaxRef {
            hint,
            ..Default::default()
        },
        i,
    )
}

/// Parse a type reference, returning the syntax and the index just past it.
pub fn parse_type(toks: &[Tok], start: usize) -> (SyntaxRef, usize) {
    let mut out = SyntaxRef::default();
    let mut i = start;

    match toks.get(i) {
        Some(Tok::Word(w)) if w == "INTEGER" => {
            out.base = Some(BaseType::Integer);
            i += 1;
        }
        Some(Tok::Word(w)) if w == "OCTET" && is_word(toks.get(i + 1), "STRING") => {
            out.base = Some(BaseType::OctetStr);
            i += 2;
        }
        Some(Tok::Word(w)) if w == "OBJECT" && is_word(toks.get(i + 1), "IDENTIFIER") => {
            out.base = Some(BaseType::ObjId);
            i += 2;
        }
        Some(Tok::Word(w)) if w == "BITS" => {
            out.base = Some(BaseType::BitString);
            i += 1;
        }
        Some(Tok::Word(w)) if w == "NULL" => {
            out.base = Some(BaseType::Null);
            i += 1;
        }
        Some(Tok::Word(w)) if w == "SEQUENCE" => {
            i += 1;
            if is_word(toks.get(i), "OF") {
                i += 2;
            } else if toks.get(i) == Some(&Tok::LBrace) {
                i = skip_braces(toks, i);
            }
            return (out, i);
        }
        Some(Tok::Word(w)) => {
            if let Some(b) = builtin_type(w) {
                out.base = Some(b);
            } else {
                out.named = Some(w.clone());
            }
            i += 1;
        }
        _ => return (out, i + 1),
    }

    // An optional enumeration or constraint follows the base type.
    if toks.get(i) == Some(&Tok::LBrace) {
        let (enums, next) = parse_enums(toks, i);
        out.enums = enums;
        i = next;
    } else if toks.get(i) == Some(&Tok::LParen) {
        let (ranges, next) = parse_constraint(toks, i);
        out.ranges = ranges;
        i = next;
    }

    (out, i)
}

fn builtin_type(w: &str) -> Option<BaseType> {
    Some(match w {
        "Integer32" => BaseType::Integer32,
        "Unsigned32" => BaseType::Unsigned32,
        "Gauge" | "Gauge32" => BaseType::Gauge,
        "Counter" | "Counter32" => BaseType::Counter,
        "Counter64" => BaseType::Counter64,
        "TimeTicks" => BaseType::TimeTicks,
        "IpAddress" => BaseType::IpAddr,
        "NetworkAddress" => BaseType::NetAddr,
        "Opaque" => BaseType::Opaque,
        "UInteger32" => BaseType::Uinteger,
        _ => return None,
    })
}

fn parse_enums(toks: &[Tok], start: usize) -> (Vec<(String, i64)>, usize) {
    let mut out = Vec::new();
    let mut i = start + 1;
    while i < toks.len() && toks[i] != Tok::RBrace {
        if let (Some(Tok::Word(label)), Some(Tok::LParen), Some(Tok::Num(v))) =
            (toks.get(i), toks.get(i + 1), toks.get(i + 2))
        {
            out.push((label.clone(), *v));
            i += 4; // label ( value )
            continue;
        }
        i += 1;
    }
    (out, i + 1)
}

/// Parse `(0..255)`, `(SIZE (1..32))`, `(SIZE(0|4|16))` and unions thereof.
fn parse_constraint(toks: &[Tok], start: usize) -> (Vec<(i64, i64)>, usize) {
    let end = skip_parens(toks, start);
    let mut out = Vec::new();
    let mut i = start + 1;

    if is_word(toks.get(i), "SIZE") {
        i += 1;
        if toks.get(i) == Some(&Tok::LParen) {
            i += 1;
        }
    }

    while i < end {
        match (toks.get(i), toks.get(i + 1)) {
            (Some(Tok::Num(a)), Some(Tok::DotDot)) => {
                if let Some(Tok::Num(b)) = toks.get(i + 2) {
                    out.push((*a, *b));
                }
                i += 3;
            }
            (Some(Tok::Num(a)), _) => {
                out.push((*a, *a));
                i += 1;
            }
            // A named upper bound or anything else we cannot evaluate.
            _ => i += 1,
        }
    }

    (out, end)
}

fn skip_braces(toks: &[Tok], start: usize) -> usize {
    let mut depth = 0usize;
    let mut i = start;
    while i < toks.len() {
        match toks[i] {
            Tok::LBrace => depth += 1,
            Tok::RBrace => {
                depth -= 1;
                if depth == 0 {
                    return i + 1;
                }
            }
            _ => {}
        }
        i += 1;
    }
    i
}

fn skip_parens(toks: &[Tok], start: usize) -> usize {
    let mut depth = 0usize;
    let mut i = start;
    while i < toks.len() {
        match toks[i] {
            Tok::LParen => depth += 1,
            Tok::RParen => {
                depth -= 1;
                if depth == 0 {
                    return i;
                }
            }
            _ => {}
        }
        i += 1;
    }
    i
}

/// Parse `{ parent name(3) 6 1 }` into its elements.
fn parse_oid_value(toks: &[Tok], start: usize) -> Option<(Vec<OidElem>, usize)> {
    if toks.get(start) != Some(&Tok::LBrace) {
        return None;
    }
    let mut out = Vec::new();
    let mut i = start + 1;
    while i < toks.len() && toks[i] != Tok::RBrace {
        match (&toks[i], toks.get(i + 1), toks.get(i + 2)) {
            (Tok::Word(w), Some(Tok::LParen), Some(Tok::Num(v))) => {
                out.push(OidElem::NamedNum(w.clone(), *v as u32));
                i += 4;
            }
            (Tok::Word(w), _, _) => {
                out.push(OidElem::Name(w.clone()));
                i += 1;
            }
            (Tok::Num(v), _, _) => {
                out.push(OidElem::Num(*v as u32));
                i += 1;
            }
            _ => i += 1,
        }
    }
    Some((out, i + 1))
}
