//! Differential fuzzing of the v05 canonical-JSON acceptance (`canonical_body`) and the strict
//! parser (`strict_parse`) against an independent model written here from the §2.1/§2.3 text:
//! an RFC 8259 parser (no serde) and a canonical writer (Ryū rules re-implemented over Rust's
//! shortest float formatting).
//! Ported from the independent attack review of colophon#4 (04c0eef), adapted to the
//! sealed revision-6 API.
#![allow(
    clippy::unwrap_used,
    clippy::explicit_auto_deref,
    clippy::unnecessary_cast,
    clippy::too_many_arguments,
    clippy::type_complexity
)]
#[path = "v05_attack_support/mod.rs"]
mod support;
use colophon_core::v05::encoding::{canonical_body, strict_parse};
use std::fmt::Write as _;
use support::Rng;

// ----------------------------------------------------------------------------------------
// Model value and strict parser.
#[derive(Clone, Debug, PartialEq)]
enum J {
    Null,
    Bool(bool),
    Int(i128),
    Float(f64),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(String, J)>),
}

struct P<'a> {
    b: &'a [u8],
    i: usize,
    depth: usize,
    max_depth: usize,
}
type R<T> = Result<T, &'static str>;
impl<'a> P<'a> {
    fn ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }
    fn lit(&mut self, s: &[u8]) -> R<()> {
        if self.b[self.i..].starts_with(s) {
            self.i += s.len();
            Ok(())
        } else {
            Err("literal")
        }
    }
    fn value(&mut self) -> R<J> {
        self.ws();
        match self.peek().ok_or("eof")? {
            b'n' => self.lit(b"null").map(|_| J::Null),
            b't' => self.lit(b"true").map(|_| J::Bool(true)),
            b'f' => self.lit(b"false").map(|_| J::Bool(false)),
            b'"' => self.string().map(J::Str),
            b'[' => {
                self.depth += 1;
                if self.depth > self.max_depth {
                    return Err("depth");
                }
                self.i += 1;
                let mut v = Vec::new();
                self.ws();
                if self.peek() == Some(b']') {
                    self.i += 1;
                } else {
                    loop {
                        v.push(self.value()?);
                        self.ws();
                        match self.peek() {
                            Some(b',') => self.i += 1,
                            Some(b']') => {
                                self.i += 1;
                                break;
                            }
                            _ => return Err("array"),
                        }
                    }
                }
                self.depth -= 1;
                Ok(J::Arr(v))
            }
            b'{' => {
                self.depth += 1;
                if self.depth > self.max_depth {
                    return Err("depth");
                }
                self.i += 1;
                let mut v: Vec<(String, J)> = Vec::new();
                self.ws();
                if self.peek() == Some(b'}') {
                    self.i += 1;
                } else {
                    loop {
                        self.ws();
                        if self.peek() != Some(b'"') {
                            return Err("key");
                        }
                        let k = self.string()?;
                        self.ws();
                        if self.peek() != Some(b':') {
                            return Err("colon");
                        }
                        self.i += 1;
                        let val = self.value()?;
                        if v.iter().any(|(x, _)| x == &k) {
                            return Err("duplicate");
                        }
                        v.push((k, val));
                        self.ws();
                        match self.peek() {
                            Some(b',') => self.i += 1,
                            Some(b'}') => {
                                self.i += 1;
                                break;
                            }
                            _ => return Err("object"),
                        }
                    }
                }
                self.depth -= 1;
                Ok(J::Obj(v))
            }
            b'-' | b'0'..=b'9' => self.number(),
            _ => Err("token"),
        }
    }
    fn hex4(&mut self) -> R<u32> {
        let s = self.b.get(self.i..self.i + 4).ok_or("hex")?;
        let mut v = 0u32;
        for &c in s {
            v = v * 16
                + match c {
                    b'0'..=b'9' => c - b'0',
                    b'a'..=b'f' => c - b'a' + 10,
                    b'A'..=b'F' => c - b'A' + 10,
                    _ => return Err("hex"),
                } as u32;
        }
        self.i += 4;
        Ok(v)
    }
    fn string(&mut self) -> R<String> {
        self.i += 1; // opening quote
        let mut out: Vec<u8> = Vec::new();
        loop {
            let c = self.peek().ok_or("unterminated")?;
            self.i += 1;
            match c {
                b'"' => break,
                b'\\' => {
                    let e = self.peek().ok_or("escape")?;
                    self.i += 1;
                    match e {
                        b'"' => out.push(b'"'),
                        b'\\' => out.push(b'\\'),
                        b'/' => out.push(b'/'),
                        b'b' => out.push(8),
                        b'f' => out.push(12),
                        b'n' => out.push(b'\n'),
                        b'r' => out.push(b'\r'),
                        b't' => out.push(b'\t'),
                        b'u' => {
                            let u = self.hex4()?;
                            let cp = if (0xD800..0xDC00).contains(&u) {
                                if !self.b[self.i..].starts_with(b"\\u") {
                                    return Err("lone high surrogate");
                                }
                                self.i += 2;
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err("bad low surrogate");
                                }
                                0x10000 + ((u - 0xD800) << 10) + (lo - 0xDC00)
                            } else if (0xDC00..0xE000).contains(&u) {
                                return Err("lone low surrogate");
                            } else {
                                u
                            };
                            let ch = char::from_u32(cp).ok_or("cp")?;
                            let mut buf = [0u8; 4];
                            out.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        _ => return Err("escape"),
                    }
                }
                0..=0x1f => return Err("control"),
                _ => out.push(c),
            }
        }
        String::from_utf8(out).map_err(|_| "utf8")
    }
    fn number(&mut self) -> R<J> {
        let start = self.i;
        let mut is_int = true;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        match self.peek() {
            Some(b'0') => self.i += 1,
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.i += 1;
                }
            }
            _ => return Err("number"),
        }
        if self.peek() == Some(b'.') {
            is_int = false;
            self.i += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err("fraction");
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.i += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            is_int = false;
            self.i += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.i += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err("exponent");
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.i += 1;
            }
        }
        let tok = std::str::from_utf8(&self.b[start..self.i]).unwrap();
        if is_int {
            // Integer tokens within the signed or unsigned 64-bit range (§2.1).
            if let Ok(v) = tok.parse::<i128>() {
                if v >= i64::MIN as i128 && v <= u64::MAX as i128 && tok != "-0" {
                    return Ok(J::Int(v));
                }
            }
        }
        let f: f64 = tok.parse().map_err(|_| "float")?;
        if !f.is_finite() {
            return Err("non-finite");
        }
        Ok(J::Float(f))
    }
}
fn model_parse(b: &[u8], max_depth: usize) -> R<J> {
    let mut p = P {
        b,
        i: 0,
        depth: 0,
        max_depth,
    };
    let v = p.value()?;
    p.ws();
    if p.i != b.len() {
        return Err("trailing");
    }
    Ok(v)
}

// ----------------------------------------------------------------------------------------
// Model canonical writer.
fn enc_str(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}
/// Shortest round-trip digits, nearest to the exact value, ties to even (as Ryū and
/// ECMAScript). Rust's own shortest formatter breaks exact ties upward, so ties are fixed here
/// from the exact decimal expansion.
fn shortest_ties_even(f: f64) -> (String, i64) {
    let e = format!("{:e}", f);
    let (m, x) = e.split_once('e').unwrap();
    let digits: String = m.chars().filter(|c| *c != '.').collect();
    let exp: i64 = x.parse().unwrap();
    let exact = format!("{:.1100e}", f);
    let (em, ex) = exact.split_once('e').unwrap();
    let ed: String = em.chars().filter(|c| *c != '.').collect();
    let eexp: i64 = ex.parse().unwrap();
    let n = digits.len();
    if eexp == exp
        && ed.len() > n
        && ed.as_bytes()[n] == b'5'
        && ed[n + 1..].bytes().all(|c| c == b'0')
    {
        let t = ed[..n].to_string();
        // t + 1 in decimal
        let mut up: Vec<u8> = t.clone().into_bytes();
        let mut i = up.len();
        let mut carry = true;
        while carry && i > 0 {
            i -= 1;
            if up[i] == b'9' {
                up[i] = b'0';
            } else {
                up[i] += 1;
                carry = false;
            }
        }
        if !carry {
            let up = String::from_utf8(up).unwrap();
            let rt = |d: &str| -> bool {
                let s = format!("{}.{}e{}", &d[..1], &d[1..], exp);
                s.parse::<f64>().map(|g| g == f).unwrap_or(false)
            };
            if rt(&t) && rt(&up) {
                let even = |d: &str| (d.as_bytes()[d.len() - 1] - b'0') % 2 == 0;
                let pick = if even(&t) { t } else { up };
                return (pick.trim_end_matches('0').to_string().max_len1(), exp);
            }
        }
    }
    (digits, exp)
}
trait MaxLen1 {
    fn max_len1(self) -> String;
}
impl MaxLen1 for String {
    fn max_len1(self) -> String {
        if self.is_empty() {
            "0".into()
        } else {
            self
        }
    }
}
/// Ryū's `format64` layout over the shortest round-trip digits.
fn enc_float(f: f64, out: &mut String) {
    if f == 0.0 {
        out.push_str(if f.is_sign_negative() { "-0.0" } else { "0.0" });
        return;
    }
    if f < 0.0 {
        out.push('-');
    }
    let (digits, exp) = shortest_ties_even(f.abs());
    let len = digits.len() as i64;
    let kk = exp + 1;
    let k = kk - len;
    if 0 <= k && kk <= 16 {
        out.push_str(&digits);
        for _ in len..kk {
            out.push('0');
        }
        out.push_str(".0");
    } else if 0 < kk && kk <= 16 {
        out.push_str(&digits[..kk as usize]);
        out.push('.');
        out.push_str(&digits[kk as usize..]);
    } else if -5 < kk && kk <= 0 {
        out.push_str("0.");
        for _ in 0..(-kk) {
            out.push('0');
        }
        out.push_str(&digits);
    } else if len == 1 {
        out.push_str(&digits);
        let _ = write!(out, "e{}", kk - 1);
    } else {
        out.push_str(&digits[..1]);
        out.push('.');
        out.push_str(&digits[1..]);
        let _ = write!(out, "e{}", kk - 1);
    }
}
fn enc(v: &J, out: &mut String) {
    match v {
        J::Null => out.push_str("null"),
        J::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        J::Int(i) => {
            let _ = write!(out, "{i}");
        }
        J::Float(f) => enc_float(*f, out),
        J::Str(s) => enc_str(s, out),
        J::Arr(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                enc(x, out);
            }
            out.push(']');
        }
        J::Obj(o) => {
            let mut o: Vec<&(String, J)> = o.iter().collect();
            o.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            out.push('{');
            for (i, (k, x)) in o.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                enc_str(k, out);
                out.push(':');
                enc(x, out);
            }
            out.push('}');
        }
    }
}
fn model_canonical_accepts(b: &[u8], max_depth: usize) -> bool {
    match model_parse(b, max_depth) {
        Ok(v @ J::Obj(_)) => {
            let mut s = String::new();
            enc(&v, &mut s);
            s.as_bytes() == b
        }
        _ => false,
    }
}

// ----------------------------------------------------------------------------------------
// Generator and mutating writer.
const KEYS: &[&str] = &[
    "a", "b", "aa", "ab", "A", "Z", "_", "é", "e\u{301}", "\u{2028}", "/", "\"", "\\", "\u{1}",
    "\u{1f}", "\u{7f}", "𝄞", "", "\u{feff}", "z\u{0}", "\t", "ü", "ü",
];
fn gen_str(r: &mut Rng) -> String {
    let n = r.below(6);
    (0..n).map(|_| *r.pick(KEYS)).collect()
}
fn gen_float(r: &mut Rng) -> f64 {
    const SPECIAL: &[f64] = &[
        0.0,
        -0.0,
        1.0,
        -1.0,
        0.1,
        0.5,
        1e21,
        1e22,
        1e-7,
        1e-6,
        1e-5,
        1e15,
        1e16,
        1e17,
        5e-324,
        f64::MAX,
        f64::MIN_POSITIVE,
        123456789012345680.0,
        9007199254740993.0,
        1.7976931348623157e308,
        2.2250738585072014e-308,
        0.30000000000000004,
        1234.5678e30,
    ];
    if r.chance(1, 3) {
        return *r.pick(SPECIAL);
    }
    loop {
        let f = f64::from_bits(r.next());
        if f.is_finite() {
            return f;
        }
    }
}
fn gen(r: &mut Rng, depth: u32) -> J {
    match r.below(if depth == 0 { 6 } else { 9 }) {
        0 => J::Null,
        1 => J::Bool(r.chance(1, 2)),
        2 => J::Int(match r.below(6) {
            0 => r.below(100) as i128,
            1 => -(r.below(1 << 60) as i128),
            2 => r.next() as i128,
            3 => i64::MIN as i128,
            4 => u64::MAX as i128,
            _ => (1i128 << 53) + r.below(3) as i128 - 1,
        }),
        3 => J::Float(gen_float(r)),
        4 | 5 => J::Str(gen_str(r)),
        6 => J::Arr((0..r.below(4)).map(|_| gen(r, depth - 1)).collect()),
        _ => {
            let mut o: Vec<(String, J)> = Vec::new();
            for _ in 0..r.below(5) {
                let k = gen_str(r);
                if !o.iter().any(|(x, _)| x == &k) {
                    o.push((k, gen(r, depth - 1)));
                }
            }
            J::Obj(o)
        }
    }
}
fn gen_root(r: &mut Rng) -> J {
    let mut o: Vec<(String, J)> = Vec::new();
    for _ in 0..r.below(6) {
        let k = gen_str(r);
        if !o.iter().any(|(x, _)| x == &k) {
            o.push((k, gen(r, 3)));
        }
    }
    J::Obj(o)
}

struct M<'r> {
    r: &'r mut Rng,
    p: u64, // mutation probability per opportunity, out of 1000
}
impl M<'_> {
    fn hit(&mut self) -> bool {
        self.r.below(1000) < self.p
    }
    fn ws(&mut self, out: &mut String) {
        if self.hit() {
            out.push_str(*self.r.pick(&[
                " ", "\n", "\t", "\r", "  ", "\u{a0}", "\u{feff}", "\u{2028}",
            ]));
        }
    }
    fn s(&mut self, s: &str, out: &mut String) {
        if !self.hit() {
            enc_str(s, out);
            return;
        }
        out.push('"');
        for ch in s.chars() {
            let c = ch as u32;
            match self.r.below(9) {
                0 => {
                    let _ = write!(out, "\\u{:04x}", c.min(0xffff));
                    if c > 0xffff {
                        out.push(ch);
                    }
                }
                1 => {
                    if c > 0xffff {
                        let v = c - 0x10000;
                        let (h, l) = (0xD800 + (v >> 10), 0xDC00 + (v & 0x3ff));
                        let _ = write!(out, "\\u{h:04X}\\u{l:04x}");
                    } else {
                        let _ = write!(out, "\\u{:04X}", c);
                    }
                }
                2 if ch == '/' => out.push_str("\\/"),
                3 if (c as u32) < 0x20 => out.push(ch), // raw control
                4 => out.push_str(*self.r.pick(&[
                    "\\ud800",
                    "\\udc00",
                    "\\uD83D",
                    "\\ud834\\u0041",
                    "\\x41",
                    "\\'",
                    "\\U0041",
                ])),
                _ => {
                    let mut t = String::new();
                    enc_str(&ch.to_string(), &mut t);
                    out.push_str(&t[1..t.len() - 1]);
                }
            }
        }
        out.push('"');
    }
    fn num_variant(&mut self, canon: &str) -> String {
        let r = &mut *self.r;
        match r.below(14) {
            0 => canon.replace('e', "E"),
            1 => canon.replace("e", "e+"),
            2 => canon.replace("e-", "e-0").replace("e1", "e01"),
            3 => format!("{canon}0"),
            4 => format!("0{canon}"),
            5 => format!("-{canon}"),
            6 => canon.trim_end_matches(".0").to_string(),
            7 => {
                if let Some(x) = canon.strip_suffix(".0") {
                    format!("{x}e0")
                } else {
                    format!("{canon}e0")
                }
            }
            8 => format!("{canon}0000000000001"),
            9 => "-0".into(),
            10 => r
                .pick(&[
                    "1E21",
                    "1e+21",
                    "1.0e21",
                    "100000000000000000000000",
                    "18446744073709551616",
                    "-9223372036854775809",
                    "1e400",
                    "-1e400",
                    "1e-400",
                    ".5",
                    "5.",
                    "+1",
                    "0x10",
                    "Infinity",
                    "NaN",
                    "-",
                    "1.5e",
                    "00",
                    "-01",
                    "1.50",
                    "9007199254740993",
                    "123456789012345678901234567890",
                    "0.000001",
                    "1e-7",
                    "1e-07",
                    "10000000000000000.0",
                    "1e16",
                    "1000000000000000.0",
                ])
                .to_string(),
            _ => {
                let mut s = String::new();
                if r.chance(1, 3) {
                    s.push('-');
                }
                let n = 1 + r.below(25);
                for i in 0..n {
                    s.push(char::from(
                        b'0' + if i == 0 && r.chance(3, 4) {
                            1 + r.below(9) as u8
                        } else {
                            r.below(10) as u8
                        },
                    ));
                }
                if r.chance(1, 2) {
                    s.push('.');
                    for _ in 0..1 + r.below(20) {
                        s.push(char::from(b'0' + r.below(10) as u8));
                    }
                }
                if r.chance(1, 2) {
                    s.push(*r.pick(&['e', 'E']));
                    if r.chance(1, 2) {
                        s.push(*r.pick(&['+', '-']));
                    }
                    for _ in 0..1 + r.below(3) {
                        s.push(char::from(b'0' + r.below(10) as u8));
                    }
                }
                s
            }
        }
    }
    fn w(&mut self, v: &J, out: &mut String) {
        self.ws(out);
        match v {
            J::Null | J::Bool(_) => {
                if self.hit() {
                    out.push_str(*self.r.pick(&["Null", "nul", "True", "fals", "null ", "0"]));
                } else {
                    enc(v, out)
                }
            }
            J::Int(_) | J::Float(_) => {
                let mut c = String::new();
                enc(v, &mut c);
                if self.hit() {
                    let x = self.num_variant(&c);
                    out.push_str(&x);
                } else {
                    out.push_str(&c);
                }
            }
            J::Str(s) => self.s(s, out),
            J::Arr(a) => {
                out.push('[');
                for (i, x) in a.iter().enumerate() {
                    if i > 0 {
                        self.ws(out);
                        out.push(',');
                    }
                    self.w(x, out);
                    self.ws(out);
                }
                if self.hit() && !a.is_empty() {
                    out.push(',');
                }
                out.push(']');
            }
            J::Obj(o) => {
                let mut o: Vec<(String, J)> = o.clone();
                o.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
                if self.hit() && o.len() > 1 {
                    let i = self.r.below(o.len() as u64) as usize;
                    let j = self.r.below(o.len() as u64) as usize;
                    o.swap(i, j);
                }
                if self.hit() && !o.is_empty() {
                    let i = self.r.below(o.len() as u64) as usize;
                    let dup = o[i].clone();
                    let at = self.r.below(o.len() as u64 + 1) as usize;
                    o.insert(at, dup);
                }
                out.push('{');
                for (i, (k, x)) in o.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    self.ws(out);
                    self.s(k, out);
                    self.ws(out);
                    out.push(':');
                    self.w(x, out);
                    self.ws(out);
                }
                out.push('}');
            }
        }
    }
}
fn byte_mutate(r: &mut Rng, b: &mut Vec<u8>) {
    match r.below(8) {
        0 if !b.is_empty() => {
            let i = r.below(b.len() as u64) as usize;
            b[i] ^= 1 << r.below(8);
        }
        1 => {
            let i = r.below(b.len() as u64 + 1) as usize;
            b.insert(
                i,
                *r.pick(&[
                    0x80u8, 0xff, 0xc0, 0xed, 0xf4, 0x00, b' ', b'"', b'\\', b',', b'}',
                ]),
            );
        }
        2 if !b.is_empty() => {
            let i = r.below(b.len() as u64) as usize;
            b.remove(i);
        }
        3 => b.splice(0..0, [0xEFu8, 0xBB, 0xBF]).for_each(drop),
        4 => b.extend_from_slice(*r.pick(&[&b" "[..], b"\n", b"\0", b"{}", b"x", b"\xef\xbb\xbf"])),
        5 if b.len() > 2 => {
            let n = r.below(b.len() as u64) as usize;
            b.truncate(n);
        }
        6 => {
            // invalid UTF-8 inside a string (after a quote)
            if let Some(i) = b.iter().position(|c| *c == b'"') {
                b.insert(i + 1, *r.pick(&[0xc3u8, 0xe2, 0xed, 0xf0, 0xf8, 0x80]));
                if r.chance(1, 2) {
                    b.insert(i + 2, *r.pick(&[0xa0u8, 0x80, 0xbf, 0x28]));
                }
            }
        }
        _ => {}
    }
}

fn engine_canonical(b: &[u8]) -> bool {
    canonical_body(b, usize::MAX).is_ok()
}

#[test]
fn differential_canonical_and_strict() {
    let n: u64 = std::env::var("JSON_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(250_000);
    let mut r = Rng(0xC0105);
    let (mut total, mut acc_both, mut rej_both) = (0u64, 0u64, 0u64);
    let mut dis_canon: Vec<String> = Vec::new();
    let mut dis_strict: Vec<String> = Vec::new();
    let mut strict_cases = 0u64;
    for case in 0..n {
        let v = gen_root(&mut r);
        let mut out = String::new();
        let p = match case % 4 {
            0 => 0,
            1 => 30,
            2 => 120,
            _ => 400,
        };
        M { r: &mut r, p }.w(&v, &mut out);
        let mut bytes = out.into_bytes();
        let byte_mutated = case % 5 == 4;
        if byte_mutated {
            byte_mutate(&mut r, &mut bytes);
        }
        total += 1;
        let model = model_canonical_accepts(&bytes, 127);
        let engine = engine_canonical(&bytes);
        if case % 4 == 0 && !byte_mutated && !(engine && model) {
            // Unmutated canonical bytes must be accepted by both.
            dis_canon.push(format!(
                "UNMUTATED engine={engine} model={model}: {}",
                String::from_utf8_lossy(&bytes)
            ));
        }
        match (model, engine) {
            (true, true) => acc_both += 1,
            (false, false) => rej_both += 1,
            _ => {
                if dis_canon.len() < 50 {
                    dis_canon.push(format!(
                        "engine={engine} model={model}: {:?}",
                        String::from_utf8_lossy(&bytes)
                    ));
                }
            }
        }
        // Strict generic parse agreement (any JSON, canonical or not).
        strict_cases += 1;
        let ms = model_parse(&bytes, 127).is_ok();
        let es = strict_parse(&bytes).is_ok();
        if ms != es && dis_strict.len() < 50 {
            dis_strict.push(format!(
                "strict engine={es} model={ms}: {:?}",
                String::from_utf8_lossy(&bytes)
            ));
        }
    }
    println!("canonical differential: {total} inputs, both accept {acc_both}, both refuse {rej_both}, disagreements {}", dis_canon.len());
    println!(
        "strict differential: {strict_cases} inputs, disagreements {}",
        dis_strict.len()
    );
    for d in dis_canon.iter().chain(dis_strict.iter()).take(60) {
        println!("  {d}");
    }
    assert!(dis_canon.is_empty() && dis_strict.is_empty());
}

/// Every number spelling, directly: token in an object, engine vs model.
#[test]
fn number_forms_exhaustive() {
    let mut r = Rng(77);
    let mut dis = Vec::new();
    let mut count = 0;
    let mut forms: Vec<String> = Vec::new();
    for _ in 0..60_000 {
        let f = gen_float(&mut r);
        let mut c = String::new();
        enc_float(f, &mut c);
        forms.push(c.clone());
        forms.push(format!("{}", f)); // Rust Display: no exponent
        forms.push(format!("{:e}", f));
        forms.push(format!("{:.17e}", f));
        let mut m = M { r: &mut r, p: 1000 };
        forms.push(m.num_variant(&c));
    }
    for i in [
        0i128,
        1,
        -1,
        9007199254740991,
        9007199254740992,
        i64::MIN as i128,
        i64::MAX as i128,
        u64::MAX as i128,
        u64::MAX as i128 + 1,
        i64::MIN as i128 - 1,
    ] {
        forms.push(i.to_string());
        forms.push(format!("{i}.0"));
    }
    for t in forms {
        count += 1;
        let b = format!("{{\"n\":{t}}}");
        let (m, e) = (
            model_canonical_accepts(b.as_bytes(), 127),
            engine_canonical(b.as_bytes()),
        );
        if m != e {
            dis.push(format!("{t}: engine={e} model={m}"));
        }
    }
    println!("number forms: {count}, disagreements {}", dis.len());
    for d in dis.iter().take(40) {
        println!("  {d}");
    }
    assert!(dis.is_empty());
}

/// Every single BMP code point and escape form inside a string.
#[test]
fn string_escapes_exhaustive() {
    let mut dis = Vec::new();
    let mut count = 0;
    for cp in 0u32..0x11000 {
        let mut forms: Vec<String> = Vec::new();
        if let Some(ch) = char::from_u32(cp) {
            forms.push(ch.to_string());
            let mut t = String::new();
            enc_str(&ch.to_string(), &mut t);
            forms.push(t[1..t.len() - 1].to_string());
        }
        if cp <= 0xffff {
            forms.push(format!("\\u{cp:04x}"));
            forms.push(format!("\\u{cp:04X}"));
        }
        for f in forms {
            count += 1;
            let b = format!("{{\"s\":\"{f}\"}}");
            let (m, e) = (
                model_canonical_accepts(b.as_bytes(), 127),
                engine_canonical(b.as_bytes()),
            );
            let (ms, es) = (
                model_parse(b.as_bytes(), 127).is_ok(),
                strict_parse(b.as_bytes()).is_ok(),
            );
            if m != e || ms != es {
                dis.push(format!("U+{cp:04X} {f:?}: canonical engine={e} model={m}; strict engine={es} model={ms}"));
            }
        }
    }
    // Raw invalid UTF-8 sequences.
    for seq in [
        &b"\xc0\x80"[..],
        b"\xed\xa0\x80",
        b"\xf4\x90\x80\x80",
        b"\xf8\x88\x80\x80\x80",
        b"\xe2\x82",
        b"\x80",
        b"\xc3",
    ] {
        count += 1;
        let mut b = b"{\"s\":\"".to_vec();
        b.extend_from_slice(seq);
        b.extend_from_slice(b"\"}");
        if engine_canonical(&b) || strict_parse(&b).is_ok() {
            dis.push(format!("invalid UTF-8 accepted: {seq:?}"));
        }
    }
    println!("string forms: {count}, disagreements {}", dis.len());
    for d in dis.iter().take(40) {
        println!("  {d}");
    }
    assert!(dis.is_empty());
}

/// Duplicate names at every depth, including escaped spellings of the same name.
#[test]
fn duplicates_everywhere() {
    let cases = [
        r#"{"a":1,"a":1}"#,
        r#"{"a":1,"a":1}"#,
        r#"{"é":1,"é":1}"#,
        r#"{"é":1,"é":1}"#,
        r#"{"𝄞":1,"𝄞":1}"#,
        r#"{"x":{"b":1,"b":2}}"#,
        r#"{"x":[{"b":1,"b":2}]}"#,
        r#"{"x":[[[[{"c":1,"c":1}]]]]}"#,
        r#"{"\/":1,"/":1}"#,
        r#"{"a\n":1,"a\u000a":1}"#,
    ];
    for c in cases {
        assert!(strict_parse(c.as_bytes()).is_err(), "{c}");
        assert!(canonical_body(c.as_bytes(), usize::MAX).is_err(), "{c}");
    }
    // NFC vs NFD are different names (not duplicates).
    assert!(strict_parse("{\"é\":1,\"e\u{301}\":1}".as_bytes()).is_ok());
}

/// Nesting: find the parser's limit; confirm deep inputs never exhaust the stack (run in a
/// thread with a small 256 KiB stack to make exhaustion visible).
#[test]
fn nesting_limit_and_no_stack_exhaustion() {
    let h = std::thread::Builder::new()
        .stack_size(256 * 1024)
        .spawn(|| {
            let mut limit = 0;
            for d in 1..300usize {
                let b = format!("{{\"a\":{}{}}}", "[".repeat(d - 1), "]".repeat(d - 1));
                if strict_parse(b.as_bytes()).is_ok() {
                    limit = d;
                }
            }
            for d in [1_000usize, 100_000, 5_000_000] {
                let b = format!("{{\"a\":{}{}}}", "[".repeat(d), "]".repeat(d));
                assert!(strict_parse(b.as_bytes()).is_err());
                assert!(canonical_body(b.as_bytes(), usize::MAX).is_err());
                let o = format!("{}1{}", "{\"a\":".repeat(d), "}".repeat(d));
                assert!(strict_parse(o.as_bytes()).is_err());
                // Unclosed deep input.
                let u = "[".repeat(d);
                assert!(strict_parse(u.as_bytes()).is_err());
            }
            limit
        })
        .unwrap();
    let limit = h.join().expect("stack exhaustion or panic in deep nesting");
    println!("maximum accepted nesting depth (containers): {limit}");
    // The model must agree at the boundary.
    for d in [limit - 1, limit, limit + 1] {
        let b = format!("{{\"a\":{}{}}}", "[".repeat(d - 1), "]".repeat(d - 1));
        assert_eq!(
            model_canonical_accepts(b.as_bytes(), 127),
            engine_canonical(b.as_bytes()),
            "depth {d}"
        );
    }
}

/// Size bounds and timing for the largest allowed bodies; no quadratic behaviour.
#[test]
fn bounds_and_timing() {
    use colophon_core::v05::encoding::bounds;
    use std::time::Instant;
    for (name, bound) in [
        ("authority", bounds::AUTHORITY_BODY),
        ("call", bounds::CALL_BODY),
        ("header", bounds::OPERATION_HEADER_BODY),
    ] {
        // Exactly at the bound: one long string; one long array of small ints; deep-ish objects.
        let pad = bound - r#"{"s":""}"#.len();
        let s = format!("{{\"s\":\"{}\"}}", "a".repeat(pad));
        assert_eq!(s.len(), bound);
        let t = Instant::now();
        assert!(canonical_body(s.as_bytes(), bound).is_ok());
        let ts = t.elapsed();
        let over = format!("{{\"s\":\"{}\"}}", "a".repeat(pad + 1));
        assert!(canonical_body(over.as_bytes(), bound).is_err());
        let n = (bound - 8) / 2;
        let mut arr = String::with_capacity(bound);
        arr.push_str("{\"a\":[");
        for i in 0..n {
            if i > 0 {
                arr.push(',');
            }
            arr.push('0');
        }
        arr.push_str("]}");
        let t = Instant::now();
        let ok = canonical_body(arr.as_bytes(), bound).is_ok();
        let ta = t.elapsed();
        // Many members (sorting cost).
        let mut obj = String::from("{");
        let mut i = 0u64;
        while obj.len() + 20 < bound {
            if i > 0 {
                obj.push(',');
            }
            let _ = write!(obj, "\"k{:015}\":0", i);
            i += 1;
        }
        obj.push('}');
        let t = Instant::now();
        let ok2 = canonical_body(obj.as_bytes(), bound).is_ok();
        let to = t.elapsed();
        // Escape-heavy string (each char 6 bytes).
        let esc = format!("{{\"s\":\"{}\"}}", "\\u0001".repeat((bound - 10) / 6));
        let t = Instant::now();
        let ok3 = canonical_body(esc.as_bytes(), bound).is_ok();
        let te = t.elapsed();
        println!(
            "{name} bound {bound}: string {ts:?}; array of {n} ints {ta:?} ({ok}); {i} members {to:?} ({ok2}); escapes {te:?} ({ok3})"
        );
    }
}
