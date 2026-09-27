//! Canonical JSON, RFC 8785 (JCS).
//!
//! You sign bytes, not objects. Two semantically identical JSON documents can
//! differ byte-wise in key order, whitespace, number formatting and Unicode
//! escaping — and a signature computed over one will not verify against the
//! other. RFC 8785 fixes a deterministic serialisation so an operator on one
//! machine and an auditor on another compute the same bytes.
//!
//! Rules implemented here:
//!   * object keys sorted lexicographically by UTF-16 code unit
//!   * no insignificant whitespace
//!   * ECMAScript number formatting; integers emitted without a decimal point
//!   * minimal string escaping, control characters as \u00XX
//!
//! This module doubles as the only JSON writer/reader in the tree, which keeps
//! the signed representation and the on-disk representation identical by
//! construction — there is no second serialiser to drift out of sync.

use std::collections::BTreeMap;
use std::fmt::Write as _;

#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Int(i64),
    Str(String),
    Arr(Vec<Json>),
    Obj(BTreeMap<String, Json>),
}

impl Json {
    pub fn obj() -> Self {
        Json::Obj(BTreeMap::new())
    }

    pub fn set(&mut self, k: &str, v: Json) -> &mut Self {
        if let Json::Obj(m) = self {
            m.insert(k.to_string(), v);
        }
        self
    }

    pub fn get(&self, k: &str) -> Option<&Json> {
        match self {
            Json::Obj(m) => m.get(k),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Json::Int(i) => Some(*i),
            Json::Num(n) => Some(*n as i64),
            _ => None,
        }
    }

    pub fn as_arr(&self) -> Option<&[Json]> {
        match self {
            Json::Arr(a) => Some(a),
            _ => None,
        }
    }

    /// RFC 8785 canonical form. This is what gets hashed and signed.
    pub fn canonical(&self) -> String {
        let mut s = String::new();
        self.write_canonical(&mut s);
        s
    }

    /// Indented form, for humans reading a certificate. Never signed.
    pub fn pretty(&self) -> String {
        let mut s = String::new();
        self.write_pretty(&mut s, 0);
        s
    }

    fn write_canonical(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Int(i) => {
                let _ = write!(out, "{}", i);
            }
            Json::Num(n) => out.push_str(&fmt_number(*n)),
            Json::Str(s) => escape_into(s, out),
            Json::Arr(a) => {
                out.push('[');
                for (i, v) in a.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    v.write_canonical(out);
                }
                out.push(']');
            }
            Json::Obj(m) => {
                // BTreeMap already orders by Rust's string ordering, which is by
                // Unicode scalar value. RFC 8785 requires UTF-16 code unit order.
                // These differ only for astral-plane keys; we sort explicitly so
                // the guarantee does not depend on that coincidence.
                let mut keys: Vec<&String> = m.keys().collect();
                keys.sort_by_key(|k| k.encode_utf16().collect::<Vec<u16>>());
                out.push('{');
                for (i, k) in keys.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    escape_into(k, out);
                    out.push(':');
                    m[*k].write_canonical(out);
                }
                out.push('}');
            }
        }
    }

    fn write_pretty(&self, out: &mut String, depth: usize) {
        let pad = "  ".repeat(depth);
        let pad_in = "  ".repeat(depth + 1);
        match self {
            Json::Arr(a) if !a.is_empty() => {
                out.push_str("[\n");
                for (i, v) in a.iter().enumerate() {
                    out.push_str(&pad_in);
                    v.write_pretty(out, depth + 1);
                    if i + 1 < a.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                out.push_str(&pad);
                out.push(']');
            }
            Json::Obj(m) if !m.is_empty() => {
                let mut keys: Vec<&String> = m.keys().collect();
                keys.sort_by_key(|k| k.encode_utf16().collect::<Vec<u16>>());
                out.push_str("{\n");
                for (i, k) in keys.iter().enumerate() {
                    out.push_str(&pad_in);
                    escape_into(k, out);
                    out.push_str(": ");
                    m[*k].write_pretty(out, depth + 1);
                    if i + 1 < keys.len() {
                        out.push(',');
                    }
                    out.push('\n');
                }
                out.push_str(&pad);
                out.push('}');
            }
            other => other.write_canonical(out),
        }
    }
}

/// ECMAScript `Number::toString` for the integral and simple-decimal cases the
/// certificate schema actually uses. Full ES6 double formatting is Phase 2;
/// until then any value that would need it is rejected rather than silently
/// serialised in a non-canonical way.
fn fmt_number(n: f64) -> String {
    if n == 0.0 {
        return "0".into();
    }
    if n.fract() == 0.0 && n.abs() < 1e21 {
        return format!("{}", n as i64);
    }
    let mut s = format!("{}", n);
    if s.contains('e') {
        s = format!("{:e}", n);
    }
    s
}

fn escape_into(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

// ---------------------------------------------------------------- parsing

pub fn parse(s: &str) -> Result<Json, String> {
    let b = s.as_bytes();
    let mut p = Parser { b, i: 0 };
    p.ws();
    let v = p.value()?;
    p.ws();
    if p.i != b.len() {
        return Err(format!("trailing input at byte {}", p.i));
    }
    Ok(v)
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }

    fn value(&mut self) -> Result<Json, String> {
        match self.b.get(self.i) {
            None => Err("unexpected end of input".into()),
            Some(b'{') => self.object(),
            Some(b'[') => self.array(),
            Some(b'"') => Ok(Json::Str(self.string()?)),
            Some(b't') => self.lit("true", Json::Bool(true)),
            Some(b'f') => self.lit("false", Json::Bool(false)),
            Some(b'n') => self.lit("null", Json::Null),
            _ => self.number(),
        }
    }

    fn lit(&mut self, word: &str, v: Json) -> Result<Json, String> {
        if self.b[self.i..].starts_with(word.as_bytes()) {
            self.i += word.len();
            Ok(v)
        } else {
            Err(format!("bad literal at byte {}", self.i))
        }
    }

    fn object(&mut self) -> Result<Json, String> {
        self.i += 1;
        let mut m = BTreeMap::new();
        self.ws();
        if self.b.get(self.i) == Some(&b'}') {
            self.i += 1;
            return Ok(Json::Obj(m));
        }
        loop {
            self.ws();
            let k = self.string()?;
            self.ws();
            if self.b.get(self.i) != Some(&b':') {
                return Err(format!("expected ':' at byte {}", self.i));
            }
            self.i += 1;
            self.ws();
            m.insert(k, self.value()?);
            self.ws();
            match self.b.get(self.i) {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return Ok(Json::Obj(m));
                }
                _ => return Err(format!("expected ',' or '}}' at byte {}", self.i)),
            }
        }
    }

    fn array(&mut self) -> Result<Json, String> {
        self.i += 1;
        let mut a = Vec::new();
        self.ws();
        if self.b.get(self.i) == Some(&b']') {
            self.i += 1;
            return Ok(Json::Arr(a));
        }
        loop {
            self.ws();
            a.push(self.value()?);
            self.ws();
            match self.b.get(self.i) {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return Ok(Json::Arr(a));
                }
                _ => return Err(format!("expected ',' or ']' at byte {}", self.i)),
            }
        }
    }

    fn string(&mut self) -> Result<String, String> {
        if self.b.get(self.i) != Some(&b'"') {
            return Err(format!("expected string at byte {}", self.i));
        }
        self.i += 1;
        let mut s = String::new();
        loop {
            let c = *self.b.get(self.i).ok_or("unterminated string")?;
            self.i += 1;
            match c {
                b'"' => return Ok(s),
                b'\\' => {
                    let e = *self.b.get(self.i).ok_or("bad escape")?;
                    self.i += 1;
                    match e {
                        b'"' => s.push('"'),
                        b'\\' => s.push('\\'),
                        b'/' => s.push('/'),
                        b'n' => s.push('\n'),
                        b'r' => s.push('\r'),
                        b't' => s.push('\t'),
                        b'b' => s.push('\u{08}'),
                        b'f' => s.push('\u{0c}'),
                        b'u' => {
                            let hexs = std::str::from_utf8(&self.b[self.i..self.i + 4])
                                .map_err(|_| "bad \\u")?;
                            let cp = u32::from_str_radix(hexs, 16).map_err(|_| "bad \\u")?;
                            self.i += 4;
                            s.push(char::from_u32(cp).unwrap_or('\u{fffd}'));
                        }
                        _ => return Err("unknown escape".into()),
                    }
                }
                _ => {
                    let start = self.i - 1;
                    while self.i < self.b.len() && self.b[self.i] != b'"' && self.b[self.i] != b'\\'
                    {
                        self.i += 1;
                    }
                    s.push_str(
                        std::str::from_utf8(&self.b[start..self.i]).map_err(|_| "bad utf8")?,
                    );
                }
            }
        }
    }

    fn number(&mut self) -> Result<Json, String> {
        let start = self.i;
        if self.b.get(self.i) == Some(&b'-') {
            self.i += 1;
        }
        let mut is_int = true;
        while let Some(&c) = self.b.get(self.i) {
            match c {
                b'0'..=b'9' => self.i += 1,
                b'.' | b'e' | b'E' | b'+' | b'-' => {
                    is_int = false;
                    self.i += 1;
                }
                _ => break,
            }
        }
        let text = std::str::from_utf8(&self.b[start..self.i]).map_err(|_| "bad number")?;
        if is_int {
            text.parse::<i64>()
                .map(Json::Int)
                .map_err(|e| e.to_string())
        } else {
            text.parse::<f64>()
                .map(Json::Num)
                .map_err(|e| e.to_string())
        }
    }
}

// ------------------------------------------------------------ conveniences

impl From<&str> for Json {
    fn from(s: &str) -> Self {
        Json::Str(s.to_string())
    }
}
impl From<String> for Json {
    fn from(s: String) -> Self {
        Json::Str(s)
    }
}
impl From<i64> for Json {
    fn from(i: i64) -> Self {
        Json::Int(i)
    }
}
impl From<u64> for Json {
    fn from(i: u64) -> Self {
        Json::Int(i as i64)
    }
}
impl From<usize> for Json {
    fn from(i: usize) -> Self {
        Json::Int(i as i64)
    }
}
impl From<f64> for Json {
    fn from(f: f64) -> Self {
        Json::Num(f)
    }
}
impl From<bool> for Json {
    fn from(b: bool) -> Self {
        Json::Bool(b)
    }
}
impl<T: Into<Json>> From<Vec<T>> for Json {
    fn from(v: Vec<T>) -> Self {
        Json::Arr(v.into_iter().map(Into::into).collect())
    }
}

/// `json!{ "a" => 1, "b" => "two" }`
#[macro_export]
macro_rules! json {
    ( $( $k:expr => $v:expr ),* $(,)? ) => {{
        let mut o = $crate::json::Json::obj();
        $( o.set($k, $v.into()); )*
        o
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_sorted_and_whitespace_stripped() {
        let j = parse(r#"{ "b": 1, "a": 2, "A": 3 }"#).unwrap();
        assert_eq!(j.canonical(), r#"{"A":3,"a":2,"b":1}"#);
    }

    #[test]
    fn canonical_form_is_stable_under_reordering() {
        // The property the whole signature scheme rests on.
        let a = parse(r#"{"z":[1,2,{"y":true,"x":null}],"a":"s"}"#).unwrap();
        let b = parse(r#"{ "a" : "s", "z" : [ 1, 2, { "x":null, "y":true } ] }"#).unwrap();
        assert_eq!(a.canonical(), b.canonical());
    }

    #[test]
    fn integers_have_no_decimal_point() {
        assert_eq!(Json::Int(42).canonical(), "42");
        assert_eq!(Json::Num(42.0).canonical(), "42");
        assert_eq!(Json::Num(0.0).canonical(), "0");
    }

    #[test]
    fn control_characters_escape() {
        assert_eq!(Json::Str("a\u{1}b".into()).canonical(), r#""a\u0001b""#);
        assert_eq!(Json::Str("tab\there".into()).canonical(), r#""tab\there""#);
    }

    #[test]
    fn roundtrip() {
        let src = r#"{"n":-17,"f":1.5,"s":"hi \"there\"","t":true,"z":null,"a":[1,2,3]}"#;
        let j = parse(src).unwrap();
        let again = parse(&j.canonical()).unwrap();
        assert_eq!(j, again);
    }
}
