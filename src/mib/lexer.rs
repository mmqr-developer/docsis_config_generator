//! Tokenizer for ASN.1/SMI MIB modules.
//!
//! This is deliberately loose: it recognises just enough of ASN.1 to walk the
//! macro invocations that define OIDs, and skips everything else.  Vendors ship
//! MIBs with all sorts of syntax errors, so the rule is to never fail a whole
//! file over a construct we do not understand.

#[derive(Clone, Debug, PartialEq)]
pub enum Tok {
    /// A bare word: type name, object name, macro name, keyword.
    Word(String),
    /// A decimal number.
    Num(i64),
    /// The contents of a `"..."` literal, with the quotes stripped.
    Str(String),
    /// A `'...'B` or `'...'H` literal, already converted to its numeric value.
    Bits(i64),
    Assign,
    LBrace,
    RBrace,
    LParen,
    RParen,
    LBracket,
    RBracket,
    Comma,
    Semi,
    Pipe,
    DotDot,
    Dot,
    /// Anything we do not model; carried through so callers can skip it.
    Other(char),
}

pub fn tokenize(src: &[u8]) -> Vec<Tok> {
    let mut out = Vec::with_capacity(src.len() / 6);
    let mut i = 0usize;
    let n = src.len();

    while i < n {
        let c = src[i];

        if c.is_ascii_whitespace() {
            i += 1;
            continue;
        }

        // An SMI comment runs from "--" to either the next "--" or end of line.
        if c == b'-' && i + 1 < n && src[i + 1] == b'-' {
            i += 2;
            while i < n {
                if src[i] == b'\n' {
                    i += 1;
                    break;
                }
                if src[i] == b'-' && i + 1 < n && src[i + 1] == b'-' {
                    i += 2;
                    break;
                }
                i += 1;
            }
            continue;
        }

        if c == b'"' {
            i += 1;
            let start = i;
            while i < n && src[i] != b'"' {
                i += 1;
            }
            let s = String::from_utf8_lossy(&src[start..i.min(n)]).into_owned();
            if i < n {
                i += 1;
            }
            out.push(Tok::Str(s));
            continue;
        }

        // '1010'B and 'FF'H binary/hex literals.
        if c == b'\'' {
            i += 1;
            let start = i;
            while i < n && src[i] != b'\'' {
                i += 1;
            }
            let body = String::from_utf8_lossy(&src[start..i.min(n)]).into_owned();
            if i < n {
                i += 1;
            }
            let radix = match src.get(i) {
                Some(b'H') | Some(b'h') => {
                    i += 1;
                    16
                }
                Some(b'B') | Some(b'b') => {
                    i += 1;
                    2
                }
                _ => 16,
            };
            let cleaned: String = body.chars().filter(|c| !c.is_whitespace()).collect();
            let v = i64::from_str_radix(&cleaned, radix).unwrap_or(0);
            out.push(Tok::Bits(v));
            continue;
        }

        if c.is_ascii_digit() || (c == b'-' && src.get(i + 1).is_some_and(u8::is_ascii_digit)) {
            let start = i;
            if c == b'-' {
                i += 1;
            }
            while i < n && src[i].is_ascii_digit() {
                i += 1;
            }
            let text = std::str::from_utf8(&src[start..i]).unwrap_or("0");
            // Saturate rather than reject: oversized DEFVALs are never OID subids.
            let v = text.parse::<i64>().unwrap_or(i64::MAX);
            out.push(Tok::Num(v));
            continue;
        }

        if c.is_ascii_alphabetic() || c == b'_' {
            let start = i;
            while i < n && (src[i].is_ascii_alphanumeric() || src[i] == b'-' || src[i] == b'_') {
                // A trailing '-' belongs to the next token unless a word char follows.
                if src[i] == b'-' && !src.get(i + 1).is_some_and(|c| c.is_ascii_alphanumeric()) {
                    break;
                }
                i += 1;
            }
            out.push(Tok::Word(
                String::from_utf8_lossy(&src[start..i]).into_owned(),
            ));
            continue;
        }

        match c {
            b':' if src[i..].starts_with(b"::=") => {
                out.push(Tok::Assign);
                i += 3;
            }
            b'{' => {
                out.push(Tok::LBrace);
                i += 1;
            }
            b'}' => {
                out.push(Tok::RBrace);
                i += 1;
            }
            b'(' => {
                out.push(Tok::LParen);
                i += 1;
            }
            b')' => {
                out.push(Tok::RParen);
                i += 1;
            }
            b'[' => {
                out.push(Tok::LBracket);
                i += 1;
            }
            b']' => {
                out.push(Tok::RBracket);
                i += 1;
            }
            b',' => {
                out.push(Tok::Comma);
                i += 1;
            }
            b';' => {
                out.push(Tok::Semi);
                i += 1;
            }
            b'|' => {
                out.push(Tok::Pipe);
                i += 1;
            }
            b'.' if src[i..].starts_with(b"..") => {
                out.push(Tok::DotDot);
                i += 2;
            }
            b'.' => {
                out.push(Tok::Dot);
                i += 1;
            }
            _ => {
                out.push(Tok::Other(c as char));
                i += 1;
            }
        }
    }

    out
}
