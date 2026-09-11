//! Recursive-descent parser for DOCSIS text configuration files.
//!
//! It follows the same grammar the original bison file described, and like
//! that version it encodes values as it reduces, so range errors are reported
//! against the line they appear on.

use std::process::exit;

use crate::encode::{self, Ctx};
use crate::lexer::{AsnType, Tok, Token};
use crate::mib::Mib;
use crate::snmp::{self, VarValue};
use crate::symbol::Symbol;
use crate::value::Value;

/// A configuration setting in its binary form. A node either carries a value
/// or a list of sub-settings, never both.
#[derive(Clone, Debug)]
pub struct Tlv {
    pub code: u8,
    pub value: Vec<u8>,
    pub children: Option<Vec<Tlv>>,
}

impl Tlv {
    fn leaf(code: u8, value: Vec<u8>) -> Tlv {
        Tlv {
            code,
            value,
            children: None,
        }
    }
}

pub struct Parser<'a> {
    toks: Vec<Token>,
    pos: usize,
    mib: &'a Mib,
}

const MAX_DIALPLAN_SIZE: u64 = 8192; // from CL-PKTC-EUE-RST-MIB
const DIALPLAN_OID: &str = "1.3.6.1.4.1.4491.2.2.8.2.1.1.3.1.1.2.1";

impl<'a> Parser<'a> {
    pub fn new(toks: Vec<Token>, mib: &'a Mib) -> Parser<'a> {
        Parser { toks, pos: 0, mib }
    }

    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos).map(|t| &t.tok)
    }

    fn peek_at(&self, n: usize) -> Option<&Tok> {
        self.toks.get(self.pos + n).map(|t| &t.tok)
    }

    fn line(&self) -> u32 {
        self.toks
            .get(self.pos)
            .or_else(|| self.toks.last())
            .map(|t| t.line)
            .unwrap_or(0)
    }

    fn ctx(&self) -> Ctx<'a> {
        Ctx {
            mib: self.mib,
            line: self.line(),
        }
    }

    fn bump(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).map(|t| t.tok.clone());
        self.pos += 1;
        t
    }

    fn error(&self, what: &str) -> ! {
        eprintln!("{}: parse error near line {}", what, self.line());
        exit(255);
    }

    fn expect_semi(&mut self) {
        match self.bump() {
            Some(Tok::Semi) => {}
            _ => self.error("expected ';'"),
        }
    }

    fn expect_lbrace(&mut self) {
        match self.bump() {
            Some(Tok::LBrace) => {}
            _ => self.error("expected '{'"),
        }
    }

    fn expect_rbrace(&mut self) {
        match self.bump() {
            Some(Tok::RBrace) => {}
            _ => self.error("expected '}'"),
        }
    }

    fn expect_integer(&mut self) -> i64 {
        match self.bump() {
            Some(Tok::Integer(v)) => v,
            _ => self.error("expected an integer"),
        }
    }

    fn expect_string(&mut self) -> Vec<u8> {
        match self.bump() {
            Some(Tok::Str(s)) => s,
            _ => self.error("expected a quoted string"),
        }
    }

    /// A quoted string used as a file name.
    fn expect_path(&mut self) -> String {
        String::from_utf8_lossy(&self.expect_string()).into_owned()
    }

    fn expect_label_oid(&mut self) -> String {
        match self.bump() {
            Some(Tok::LabelOid(s)) => s,
            // A bare dotted quad also reads as an OID, e.g. "83.1.2.1.2.1".
            Some(Tok::Ip(s)) => s,
            _ => self.error("expected an object identifier"),
        }
    }

    /// `Main { ... }`
    pub fn parse(&mut self) -> Vec<Tlv> {
        match self.bump() {
            Some(Tok::Main) => {}
            _ => self.error("expected 'Main'"),
        }
        self.expect_lbrace();
        let list = self.assignment_list();
        self.expect_rbrace();
        list
    }

    fn assignment_list(&mut self) -> Vec<Tlv> {
        let mut out = Vec::new();
        while !matches!(self.peek(), Some(Tok::RBrace) | None) {
            out.extend(self.statement());
        }
        out
    }

    fn statement(&mut self) -> Vec<Tlv> {
        match self.peek().cloned() {
            Some(Tok::Identifier(sym)) => {
                if matches!(self.peek_at(1), Some(Tok::LBrace)) {
                    self.pos += 1;
                    self.expect_lbrace();
                    let children = self.assignment_list();
                    self.expect_rbrace();
                    vec![Tlv {
                        code: sym.code,
                        value: Vec::new(),
                        children: Some(children),
                    }]
                } else {
                    self.pos += 1;
                    let value = self.take_value();
                    let ctx = self.ctx();
                    self.expect_semi();
                    vec![Tlv::leaf(sym.code, encode::encode(&ctx, sym, &value))]
                }
            }
            Some(Tok::IdentGeneric(sym)) => self.generic_statement(sym),
            Some(Tok::IdentCvc(sym)) => {
                self.pos += 1;
                let path = self.expect_path();
                let line = self.line();
                self.expect_semi();
                self.external_file_tlvs(sym, &path, line)
            }
            Some(Tok::IdentSnmpW(sym)) => {
                self.pos += 1;
                let oid = self.expect_label_oid();
                let control = self.expect_integer();
                let line = self.line();
                self.expect_semi();
                let mut value = match snmp::encode_snmp_oid(self.mib, &oid, line) {
                    Some(v) => v,
                    None => {
                        eprintln!(
                            "got len 0 value while scanning for {} at line {}",
                            sym.ident, line
                        );
                        exit(255);
                    }
                };
                value.push(control as u8);
                vec![Tlv::leaf(sym.code, value)]
            }
            Some(Tok::IdentSnmpSet(sym)) => {
                self.pos += 1;
                let oid = self.expect_label_oid();
                let var = self.take_var_value();
                let line = self.line();
                self.expect_semi();
                self.snmpset_tlv(sym, &oid, var, line)
            }
            Some(Tok::DigitMap(sym)) => {
                self.pos += 1;
                let path = self.expect_path();
                let line = self.line();
                self.expect_semi();
                let body = self.read_dialplan(&path, line);
                self.snmpset_tlv(sym, DIALPLAN_OID, VarValue::Str(body), line)
            }
            Some(_) => self.error("unexpected token"),
            None => self.error("unexpected end of file"),
        }
    }

    fn snmpset_tlv(&mut self, sym: &Symbol, oid: &str, var: VarValue, line: u32) -> Vec<Tlv> {
        match snmp::encode_vbind(self.mib, oid, &var, line) {
            Some(v) => vec![Tlv::leaf(sym.code, v)],
            None => {
                eprintln!(
                    "got len 0 value while scanning for {} at line {}",
                    sym.ident, line
                );
                exit(255);
            }
        }
    }

    /// `GenericTLV TlvCode <n> ...` in each of its five shapes.
    fn generic_statement(&mut self, sym: &'static Symbol) -> Vec<Tlv> {
        self.pos += 1;
        match self.bump() {
            Some(Tok::TlvCode) => {}
            _ => self.error("expected TlvCode"),
        }
        let code = self.expect_integer() as u8;

        match self.peek().cloned() {
            Some(Tok::LBrace) => {
                self.expect_lbrace();
                let children = self.assignment_list();
                self.expect_rbrace();
                vec![Tlv {
                    code,
                    value: Vec::new(),
                    children: Some(children),
                }]
            }
            Some(Tok::TlvString) => {
                self.pos += 1;
                let s = self.expect_string();
                self.expect_semi();
                vec![Tlv::leaf(code, s)]
            }
            Some(Tok::TlvStringZero) => {
                self.pos += 1;
                let s = self.expect_string();
                self.expect_semi();
                let mut bytes = s;
                if bytes.len() <= 254 {
                    bytes.push(0);
                }
                vec![Tlv::leaf(code, bytes)]
            }
            Some(Tok::TlvLength) => {
                self.pos += 1;
                let declared = self.expect_integer();
                match self.bump() {
                    Some(Tok::TlvValue) => {}
                    _ => self.error("expected TlvValue"),
                }
                let hex = match self.bump() {
                    Some(Tok::HexString(s)) => s,
                    _ => self.error("expected a hex string"),
                };
                let line = self.line();
                self.expect_semi();
                let Some(bytes) = encode::parse_hexstr(hex.as_bytes()) else {
                    eprintln!("encode_hexstr: invalid hex string {}", hex);
                    exit(255);
                };
                if bytes.len() as i64 != declared {
                    eprintln!(
                        "Length mismatch while encoding GenericTLV: given length {}, value length {} at line {}",
                        declared,
                        bytes.len(),
                        line
                    );
                    exit(255);
                }
                vec![Tlv::leaf(code, bytes)]
            }
            Some(Tok::TlvType) => {
                self.pos += 1;
                let asn = match self.bump() {
                    Some(Tok::AsnType(a)) => a,
                    _ => self.error("expected a type name"),
                };
                match self.bump() {
                    Some(Tok::TlvValue) => {}
                    _ => self.error("expected TlvValue"),
                }
                let value = self.take_value();
                let ctx = self.ctx();
                self.expect_semi();
                let bytes = match asn {
                    AsnType::Int => (value.as_num() as u32).to_be_bytes().to_vec(),
                    AsnType::Short => (value.as_num() as u16).to_be_bytes().to_vec(),
                    AsnType::Char => vec![value.as_num() as u8],
                    AsnType::Ip => encode::encode(&ctx, ip_symbol(), &value),
                    _ => self.error("unsupported TlvType"),
                };
                vec![Tlv::leaf(code, bytes)]
            }
            _ => {
                let _ = sym;
                self.error("unexpected token after TlvCode")
            }
        }
    }

    /// Read a certificate chain file, splitting it into TLV-sized pieces.
    fn external_file_tlvs(&self, sym: &Symbol, path: &str, line: u32) -> Vec<Tlv> {
        let data = match std::fs::read(path) {
            Ok(d) => d,
            Err(_) => {
                eprintln!("Error: can't open external file {} at line {}", path, line);
                exit(251);
            }
        };
        if data.is_empty() {
            eprintln!("Error reading data from {}", path);
            exit(251);
        }
        data.chunks(254)
            .map(|c| Tlv::leaf(sym.code, c.to_vec()))
            .collect()
    }

    fn read_dialplan(&self, path: &str, line: u32) -> Vec<u8> {
        let meta = std::fs::metadata(path);
        if let Ok(m) = &meta {
            if m.len() > MAX_DIALPLAN_SIZE {
                eprintln!(
                    "Dialplan file {} too big at line {}. Must <= {}",
                    path, line, MAX_DIALPLAN_SIZE
                );
                exit(251);
            }
        }
        match std::fs::read(path) {
            Ok(d) => {
                // The value is handled as a C string, so it stops at a NUL.
                let end = d.iter().position(|&b| b == 0).unwrap_or(d.len());
                d[..end].to_vec()
            }
            Err(_) => {
                eprintln!("Error: can't open file {} at line {}", path, line);
                exit(251);
            }
        }
    }

    /// Consume a value token for a plain setting.
    fn take_value(&mut self) -> Value {
        match self.bump() {
            Some(Tok::Integer(v)) => Value::Num(v),
            Some(Tok::Str(s)) => Value::Bytes(s),
            Some(Tok::HexString(s))
            | Some(Tok::SubmgtFilters(s))
            | Some(Tok::Ip(s))
            | Some(Tok::IpList(s))
            | Some(Tok::Ip6(s))
            | Some(Tok::Ip6List(s))
            | Some(Tok::Ip6PrefixList(s))
            | Some(Tok::IpIp6Port(s))
            | Some(Tok::Mac(s))
            | Some(Tok::Ethermask(s))
            | Some(Tok::LabelOid(s))
            | Some(Tok::TimeTicks(s)) => Value::Text(s),
            _ => {
                self.pos -= 1;
                self.error("expected a value")
            }
        }
    }

    /// Consume the `<type> <value>` pair of a `SnmpMibObject` statement.
    fn take_var_value(&mut self) -> VarValue {
        let asn = match self.bump() {
            Some(Tok::AsnType(a)) => a,
            _ => self.error("expected a type name for SnmpMibObject"),
        };
        match asn {
            AsnType::Int => VarValue::Int(self.expect_integer() as i32),
            AsnType::Gauge => VarValue::Gauge(self.expect_integer() as u32),
            AsnType::Uint => VarValue::Gauge(self.expect_integer() as u32),
            AsnType::Counter => VarValue::Counter(self.expect_integer() as u32),
            AsnType::TimeTicks => VarValue::TimeTicks(self.expect_integer() as u32),
            AsnType::Ip => {
                let text = match self.bump() {
                    Some(Tok::Ip(s)) => s,
                    _ => self.error("expected an IP address"),
                };
                let mut out = [0u8; 4];
                for (i, part) in text.split('.').enumerate().take(4) {
                    out[i] = part.parse::<u32>().unwrap_or(0) as u8;
                }
                VarValue::Ip(out)
            }
            AsnType::Str => VarValue::Str(self.expect_string()),
            AsnType::HexStr => {
                let hex = match self.bump() {
                    Some(Tok::HexString(s)) => s,
                    _ => self.error("expected a hex string"),
                };
                match hexadecimal_to_binary(&hex) {
                    Some(b) => VarValue::Str(b),
                    None => {
                        eprintln!("Invalid hexadecimal string at line {}", self.line());
                        exit(255);
                    }
                }
            }
            AsnType::ObjId => VarValue::Oid(self.expect_label_oid()),
            _ => self.error("unsupported SnmpMibObject type"),
        }
    }
}

/// The symbol used for range-free IP encoding inside `GenericTLV TlvType`.
fn ip_symbol() -> &'static Symbol {
    crate::symbol::find_by_name("GenericTLV").expect("GenericTLV must exist in the symbol table")
}

/// Lenient hex conversion, matching net-snmp's `hexadecimal_to_binary`:
/// an optional `0x` prefix and embedded whitespace are allowed.
fn hexadecimal_to_binary(text: &str) -> Option<Vec<u8>> {
    let body = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text);
    let digits: Vec<u8> = body.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if digits.len() % 2 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(digits.len() / 2);
    for pair in digits.chunks(2) {
        let s = std::str::from_utf8(pair).ok()?;
        out.push(u8::from_str_radix(s, 16).ok()?);
    }
    Some(out)
}
