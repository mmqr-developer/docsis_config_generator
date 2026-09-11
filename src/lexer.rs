//! Scanner for DOCSIS text configuration files.
//!
//! The original used flex, which picks the longest match and breaks ties by
//! rule order.  This scanner does the same: at each position every pattern is
//! tried, the longest wins, and equal-length matches fall to the pattern
//! declared first.  That ordering is load-bearing - `1.3.6.1` is an IP address
//! but `.1.3.6.1` is an OID, and `docsDevCpeIpMax.0` is an OID rather than an
//! identifier followed by a number.

use crate::symbol::{self, Symbol};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AsnType {
    Int,
    Uint,
    Short,
    Char,
    Gauge,
    Counter,
    TimeTicks,
    Ip,
    ObjId,
    Str,
    HexStr,
    DecStr,
    BitStr,
    BigInt,
    UBigInt,
    Float,
    Double,
}

#[derive(Clone, Debug)]
pub enum Tok {
    Identifier(&'static Symbol),
    IdentSnmpW(&'static Symbol),
    IdentSnmpSet(&'static Symbol),
    IdentGeneric(&'static Symbol),
    IdentCvc(&'static Symbol),
    DigitMap(&'static Symbol),
    Main,
    Integer(i64),
    /// A `"..."` literal with escapes already applied, kept as bytes.
    Str(Vec<u8>),
    HexString(String),
    SubmgtFilters(String),
    Ip(String),
    IpList(String),
    Ip6(String),
    Ip6List(String),
    Ip6PrefixList(String),
    IpIp6Port(String),
    Mac(String),
    Ethermask(String),
    LabelOid(String),
    TimeTicks(String),
    AsnType(AsnType),
    TlvCode,
    TlvLength,
    TlvValue,
    TlvString,
    TlvStringZero,
    TlvType,
    LBrace,
    RBrace,
    Semi,
}

pub struct Token {
    pub tok: Tok,
    pub line: u32,
}

pub struct Lexer<'a> {
    src: &'a [u8],
    pos: usize,
    line: u32,
}

/// The token kinds a value pattern can produce, in flex rule order so that
/// equal-length matches resolve the same way.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Pat {
    SubmgtFilters,
    Ip,
    IpList,
    HexString,
    Ethermask,
    IpIp6Port,
    Mac,
    LabelOid,
    LabelOidQuoted,
    LabelOidText,
    TimeTicks,
    Word,
    Integer,
    Ip6,
    Ip6Port,
    Ip6PrefixList,
    Ip6List,
}

const PATTERNS: &[Pat] = &[
    Pat::SubmgtFilters,
    Pat::Ip,
    Pat::IpList,
    Pat::HexString,
    Pat::Ethermask,
    Pat::IpIp6Port,
    Pat::Mac,
    Pat::LabelOid,
    Pat::LabelOidQuoted,
    Pat::LabelOidText,
    Pat::TimeTicks,
    Pat::Word,
    Pat::Integer,
    Pat::Ip6,
    Pat::Ip6Port,
    Pat::Ip6PrefixList,
    Pat::Ip6List,
];

impl<'a> Lexer<'a> {
    pub fn new(src: &'a [u8]) -> Lexer<'a> {
        Lexer {
            src,
            pos: 0,
            line: 1,
        }
    }

    /// Read the whole input, reporting the line of the first problem found.
    pub fn tokenize(mut self) -> Result<Vec<Token>, String> {
        let mut out = Vec::new();
        loop {
            match self.next_token()? {
                Some(t) => out.push(t),
                None => return Ok(out),
            }
        }
    }

    fn next_token(&mut self) -> Result<Option<Token>, String> {
        loop {
            if self.pos >= self.src.len() {
                return Ok(None);
            }
            let c = self.src[self.pos];

            if c == b' ' || c == b'\t' || c == b'\r' {
                self.pos += 1;
                continue;
            }
            if c == b'\n' {
                self.pos += 1;
                self.line += 1;
                continue;
            }
            // A comment opens with '/' followed by one or more '*'.
            if c == b'/' && self.src.get(self.pos + 1) == Some(&b'*') {
                self.skip_comment();
                continue;
            }
            if c == b'"' {
                let line = self.line;
                let s = self.scan_string()?;
                return Ok(Some(Token {
                    tok: Tok::Str(s),
                    line,
                }));
            }
            match c {
                b'{' => {
                    self.pos += 1;
                    return Ok(Some(Token {
                        tok: Tok::LBrace,
                        line: self.line,
                    }));
                }
                b'}' => {
                    self.pos += 1;
                    return Ok(Some(Token {
                        tok: Tok::RBrace,
                        line: self.line,
                    }));
                }
                b';' => {
                    self.pos += 1;
                    return Ok(Some(Token {
                        tok: Tok::Semi,
                        line: self.line,
                    }));
                }
                _ => {}
            }

            let (pat, len) = self.longest_match();
            if len == 0 {
                return Err(format!(
                    "Unrecognized char \"{}\" at line {}",
                    c as char, self.line
                ));
            }
            let text = String::from_utf8_lossy(&self.src[self.pos..self.pos + len]).into_owned();
            let line = self.line;
            self.pos += len;
            return Ok(Some(Token {
                tok: self.classify(pat, text, line)?,
                line,
            }));
        }
    }

    fn longest_match(&self) -> (Pat, usize) {
        let mut best = (Pat::Word, 0usize);
        for &p in PATTERNS {
            let len = match_pattern(p, self.src, self.pos);
            if len > best.1 {
                best = (p, len);
            }
        }
        best
    }

    fn classify(&self, pat: Pat, text: String, line: u32) -> Result<Tok, String> {
        Ok(match pat {
            Pat::SubmgtFilters => Tok::SubmgtFilters(text),
            Pat::Ip => Tok::Ip(text),
            Pat::IpList => Tok::IpList(text),
            Pat::HexString => Tok::HexString(text),
            Pat::Ethermask => Tok::Ethermask(text),
            Pat::IpIp6Port | Pat::Ip6Port => Tok::IpIp6Port(text),
            Pat::Mac => Tok::Mac(text),
            Pat::LabelOid | Pat::LabelOidQuoted | Pat::LabelOidText => Tok::LabelOid(text),
            Pat::TimeTicks => Tok::TimeTicks(text),
            Pat::Ip6 => Tok::Ip6(text),
            Pat::Ip6PrefixList => Tok::Ip6PrefixList(text),
            Pat::Ip6List => Tok::Ip6List(text),
            Pat::Integer => Tok::Integer(text.parse::<i64>().unwrap_or(0)),
            Pat::Word => return keyword_or_identifier(&text, line),
        })
    }

    fn skip_comment(&mut self) {
        self.pos += 1;
        while self.pos < self.src.len() && self.src[self.pos] == b'*' {
            self.pos += 1;
        }
        while self.pos < self.src.len() {
            if self.src[self.pos] == b'\n' {
                self.line += 1;
                self.pos += 1;
                continue;
            }
            if self.src[self.pos] == b'*' {
                let mut j = self.pos;
                while j < self.src.len() && self.src[j] == b'*' {
                    j += 1;
                }
                if self.src.get(j) == Some(&b'/') {
                    self.pos = j + 1;
                    return;
                }
                self.pos = j;
                continue;
            }
            self.pos += 1;
        }
    }

    /// Read a quoted string. `\"` yields a quote; any other backslash becomes
    /// a space, which is what the original scanner did.
    fn scan_string(&mut self) -> Result<Vec<u8>, String> {
        self.pos += 1; // opening quote
        let mut out: Vec<u8> = Vec::new();
        while self.pos < self.src.len() {
            let c = self.src[self.pos];
            match c {
                b'"' => {
                    self.pos += 1;
                    return Ok(out);
                }
                b'\n' => {
                    return Err(format!(
                        "line {}: \\n not allowed in string, unmatched \" ?",
                        self.line
                    ))
                }
                b'\t' => {
                    return Err(format!(
                        "line {}: \\t not allowed in string, unmatched \" ?",
                        self.line
                    ))
                }
                b'\\' => {
                    if self.src.get(self.pos + 1) == Some(&b'"') {
                        out.push(b'"');
                        self.pos += 2;
                    } else {
                        out.push(b' ');
                        self.pos += 1;
                    }
                }
                _ => {
                    out.push(c);
                    self.pos += 1;
                }
            }
            if out.len() > 2048 {
                return Err(format!(
                    "line {}: string too long (max 2048 characters)",
                    self.line
                ));
            }
        }
        Err(format!("line {}: unterminated string", self.line))
    }
}

fn keyword_or_identifier(text: &str, line: u32) -> Result<Tok, String> {
    if text.eq_ignore_ascii_case("main") {
        return Ok(Tok::Main);
    }
    let asn = match text {
        "Integer" => Some(AsnType::Int),
        "Unsigned32" => Some(AsnType::Uint),
        "Short" => Some(AsnType::Short),
        "Char" => Some(AsnType::Char),
        "Gauge" | "Gauge32" => Some(AsnType::Gauge),
        "Counter32" => Some(AsnType::Counter),
        "TimeTicks" => Some(AsnType::TimeTicks),
        "IPAddress" => Some(AsnType::Ip),
        "ObjectID" => Some(AsnType::ObjId),
        "String" => Some(AsnType::Str),
        "HexString" => Some(AsnType::HexStr),
        "DecimalString" => Some(AsnType::DecStr),
        "BitString" => Some(AsnType::BitStr),
        "BigInt" => Some(AsnType::BigInt),
        "UnsignedBigInt" => Some(AsnType::UBigInt),
        "Float" => Some(AsnType::Float),
        "Double" => Some(AsnType::Double),
        _ => None,
    };
    if let Some(a) = asn {
        return Ok(Tok::AsnType(a));
    }
    match text {
        "TlvCode" => return Ok(Tok::TlvCode),
        "TlvLength" => return Ok(Tok::TlvLength),
        "TlvValue" => return Ok(Tok::TlvValue),
        "TlvString" => return Ok(Tok::TlvString),
        "TlvStringZero" => return Ok(Tok::TlvStringZero),
        "TlvType" => return Ok(Tok::TlvType),
        _ => {}
    }

    let sym = symbol::find_by_name(text)
        .ok_or_else(|| format!("Unrecognized symbol {} at line {}", text, line))?;

    Ok(match text {
        "SnmpWriteControl" => Tok::IdentSnmpW(sym),
        "SnmpMibObject" => Tok::IdentSnmpSet(sym),
        "DigitMap" => Tok::DigitMap(sym),
        "ManufacturerCVC" | "CoSignerCVC" | "ManufacturerCVCChainFile" | "CoSignerCVCChainFile" => {
            Tok::IdentCvc(sym)
        }
        "GenericTLV" => Tok::IdentGeneric(sym),
        _ => Tok::Identifier(sym),
    })
}

// ---------------------------------------------------------------------------
// Pattern matchers. Each returns the length of the match at `pos`, or 0.
// ---------------------------------------------------------------------------

fn is_alnum(c: u8) -> bool {
    c.is_ascii_alphanumeric()
}

fn is_label_char(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_' || c == b'-'
}

fn is_hex(c: u8) -> bool {
    c.is_ascii_hexdigit()
}

fn digits(s: &[u8], pos: usize) -> usize {
    let mut i = pos;
    while i < s.len() && s[i].is_ascii_digit() {
        i += 1;
    }
    i - pos
}

fn match_pattern(p: Pat, s: &[u8], pos: usize) -> usize {
    match p {
        Pat::SubmgtFilters => m_submgt_filters(s, pos),
        Pat::Ip => m_ipv4(s, pos),
        Pat::IpList => m_list(s, pos, m_ipv4, 16),
        Pat::HexString => m_hexstring(s, pos),
        Pat::Ethermask => m_ethermask(s, pos),
        Pat::IpIp6Port => m_with_suffix_num(s, pos, m_ipv4),
        Pat::Mac => m_mac(s, pos),
        Pat::LabelOid => m_label_oid(s, pos),
        Pat::LabelOidQuoted => m_label_oid_quoted(s, pos),
        Pat::LabelOidText => m_label_oid_text(s, pos),
        Pat::TimeTicks => m_timeticks(s, pos),
        Pat::Word => m_word(s, pos),
        Pat::Integer => m_integer(s, pos),
        Pat::Ip6 => m_ipv6(s, pos),
        Pat::Ip6Port => m_with_suffix_num(s, pos, m_ipv6),
        Pat::Ip6PrefixList => m_list(s, pos, |s, p| m_with_suffix_num(s, p, m_ipv6), 15),
        Pat::Ip6List => m_list(s, pos, m_ipv6, 16),
    }
}

/// `([0-9]+,){1,127}[0-9]+`
fn m_submgt_filters(s: &[u8], pos: usize) -> usize {
    let mut i = pos;
    let mut groups = 0;
    loop {
        let d = digits(s, i);
        if d == 0 {
            return 0;
        }
        if s.get(i + d) == Some(&b',') && groups < 127 {
            i += d + 1;
            groups += 1;
            continue;
        }
        if groups == 0 {
            return 0;
        }
        return i + d - pos;
    }
}

/// `([0-9]+\.){3}[0-9]+`
fn m_ipv4(s: &[u8], pos: usize) -> usize {
    let mut i = pos;
    for _ in 0..3 {
        let d = digits(s, i);
        if d == 0 || s.get(i + d) != Some(&b'.') {
            return 0;
        }
        i += d + 1;
    }
    let d = digits(s, i);
    if d == 0 {
        return 0;
    }
    i + d - pos
}

/// A comma-separated list of at most `max` items.
fn m_list(s: &[u8], pos: usize, item: fn(&[u8], usize) -> usize, max: usize) -> usize {
    let mut i = pos;
    let mut count = 0;
    let mut end = 0;
    loop {
        let len = item(s, i);
        if len == 0 {
            break;
        }
        i += len;
        count += 1;
        if count >= 2 {
            end = i;
        }
        if count >= max || s.get(i) != Some(&b',') {
            break;
        }
        i += 1;
    }
    if count < 2 {
        0
    } else {
        end - pos
    }
}

/// An item followed by `/` and a decimal number.
fn m_with_suffix_num(s: &[u8], pos: usize, item: fn(&[u8], usize) -> usize) -> usize {
    let len = item(s, pos);
    if len == 0 || s.get(pos + len) != Some(&b'/') {
        return 0;
    }
    let d = digits(s, pos + len + 1);
    if d == 0 {
        return 0;
    }
    len + 1 + d
}

/// `0[Xx][0-9A-Fa-f]+`
fn m_hexstring(s: &[u8], pos: usize) -> usize {
    if s.get(pos) != Some(&b'0') || !matches!(s.get(pos + 1), Some(b'x') | Some(b'X')) {
        return 0;
    }
    let mut i = pos + 2;
    while i < s.len() && is_hex(s[i]) {
        i += 1;
    }
    if i == pos + 2 {
        0
    } else {
        i - pos
    }
}

/// `([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}`
fn m_mac(s: &[u8], pos: usize) -> usize {
    let mut i = pos;
    for _ in 0..5 {
        if i + 2 >= s.len() || !is_hex(s[i]) || !is_hex(s[i + 1]) || s[i + 2] != b':' {
            return 0;
        }
        i += 3;
    }
    if i + 1 >= s.len() || !is_hex(s[i]) || !is_hex(s[i + 1]) {
        return 0;
    }
    i + 2 - pos
}

fn m_ethermask(s: &[u8], pos: usize) -> usize {
    let a = m_mac(s, pos);
    if a == 0 || s.get(pos + a) != Some(&b'/') {
        return 0;
    }
    let b = m_mac(s, pos + a + 1);
    if b == 0 {
        return 0;
    }
    a + 1 + b
}

/// `([0-9]+:){3}[0-9]+\.[0-9]+`
fn m_timeticks(s: &[u8], pos: usize) -> usize {
    let mut i = pos;
    for _ in 0..3 {
        let d = digits(s, i);
        if d == 0 || s.get(i + d) != Some(&b':') {
            return 0;
        }
        i += d + 1;
    }
    let d = digits(s, i);
    if d == 0 || s.get(i + d) != Some(&b'.') {
        return 0;
    }
    i += d + 1;
    let d = digits(s, i);
    if d == 0 {
        return 0;
    }
    i + d - pos
}

fn m_word(s: &[u8], pos: usize) -> usize {
    if pos >= s.len() || !s[pos].is_ascii_alphabetic() {
        return 0;
    }
    let mut i = pos;
    while i < s.len() && s[i].is_ascii_alphabetic() {
        i += 1;
    }
    while i < s.len() && is_alnum(s[i]) {
        i += 1;
    }
    i - pos
}

fn m_integer(s: &[u8], pos: usize) -> usize {
    let start = if s.get(pos) == Some(&b'-') {
        pos + 1
    } else {
        pos
    };
    let d = digits(s, start);
    if d == 0 {
        0
    } else {
        start + d - pos
    }
}

/// Consume the leading dots and `label.` groups shared by the OID patterns,
/// returning the position after each group boundary.
fn oid_prefix_positions(s: &[u8], pos: usize) -> Vec<usize> {
    let mut i = pos;
    while s.get(i) == Some(&b'.') {
        i += 1;
    }
    let mut out = Vec::new();
    loop {
        let start = i;
        let mut j = i;
        while j < s.len() && is_label_char(s[j]) {
            j += 1;
        }
        if j == start || s.get(j) != Some(&b'.') {
            break;
        }
        i = j + 1;
        out.push(i);
    }
    out
}

/// `(\.)*([A-Za-z0-9_-]+\.)+[A-Za-z0-9]+`
fn m_label_oid(s: &[u8], pos: usize) -> usize {
    let mut best = 0;
    for &start in &oid_prefix_positions(s, pos) {
        let mut j = start;
        while j < s.len() && is_alnum(s[j]) {
            j += 1;
        }
        if j > start {
            best = j - pos;
        }
    }
    best
}

/// `(\.)*([A-Za-z0-9_-]+\.)+'[\[A-Za-z0-9@,:_.\-\]]+'`
fn m_label_oid_quoted(s: &[u8], pos: usize) -> usize {
    let mut best = 0;
    for &start in &oid_prefix_positions(s, pos) {
        if s.get(start) != Some(&b'\'') {
            continue;
        }
        let mut j = start + 1;
        while j < s.len()
            && (is_alnum(s[j])
                || matches!(s[j], b'[' | b']' | b'@' | b',' | b':' | b'_' | b'.' | b'-'))
        {
            j += 1;
        }
        if j > start + 1 && s.get(j) == Some(&b'\'') {
            best = j + 1 - pos;
        }
    }
    best
}

/// `(\.)*([A-Za-z0-9_-]+\.)+((")*[A-Za-z0-9,:_.\-]+(")*)+`
fn m_label_oid_text(s: &[u8], pos: usize) -> usize {
    let mut best = 0;
    for &start in &oid_prefix_positions(s, pos) {
        let mut j = start;
        let mut saw_body = false;
        while j < s.len() {
            let c = s[j];
            if c == b'"' {
                j += 1;
            } else if is_alnum(c) || matches!(c, b',' | b':' | b'_' | b'.' | b'-') {
                saw_body = true;
                j += 1;
            } else {
                break;
            }
        }
        // The run must contain at least one non-quote character.
        if saw_body {
            best = j - pos;
        }
    }
    best
}

/// The IPv6 forms the original scanner accepted, recognised by parsing.
fn m_ipv6(s: &[u8], pos: usize) -> usize {
    let mut end = pos;
    while end < s.len() && (is_hex(s[end]) || s[end] == b':') {
        end += 1;
    }
    while end > pos {
        let text = &s[pos..end];
        if text.contains(&b':') {
            if let Ok(t) = std::str::from_utf8(text) {
                if t.parse::<std::net::Ipv6Addr>().is_ok() {
                    return end - pos;
                }
            }
        }
        end -= 1;
    }
    0
}
