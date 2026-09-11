//! The raw value carried by a configuration setting between the parser and
//! the encoders.

#[derive(Clone, Debug)]
pub enum Value {
    /// A decimal literal. Held signed because the grammar accepts `-1`.
    Num(i64),
    /// A value the lexer captured as text: addresses, hex strings, OIDs.
    Text(String),
    /// A quoted string literal, kept as bytes so that non-ASCII content
    /// survives the round trip.
    Bytes(Vec<u8>),
}

impl Value {
    pub fn as_num(&self) -> i64 {
        match self {
            Value::Num(v) => *v,
            _ => 0,
        }
    }

    pub fn as_text(&self) -> &str {
        match self {
            Value::Text(s) => s,
            _ => "",
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Value::Text(s) => s.as_bytes(),
            Value::Bytes(b) => b,
            Value::Num(_) => &[],
        }
    }
}
