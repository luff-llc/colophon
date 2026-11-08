//! Minimal definite-length COSE_Key reader for ES256 registration (§2.5).
use super::{malformed, point, require};
use crate::Result;

/// Parse exactly the five minimally encoded COSE_Key entries and return a valid
/// uncompressed P-256 point. Map ordering is unrestricted; trailing bytes are forbidden.
pub fn parse(bytes: &[u8]) -> Result<[u8; 65]> {
    let mut reader = Reader { bytes, offset: 0 };
    require(
        reader.byte()? == 0xa5,
        "COSE map must have exactly five entries",
    )?;
    let mut seen = [false; 5];
    let mut public = [0; 65];
    public[0] = 4;
    for _ in 0..5 {
        let key = reader.byte()?;
        let index = match key {
            0x01 => 0,
            0x03 => 1,
            0x20 => 2,
            0x21 => 3,
            0x22 => 4,
            _ => return Err(malformed("unknown or non-minimal COSE key")),
        };
        require(!seen[index], "duplicate COSE key")?;
        seen[index] = true;
        match index {
            0 => require(reader.byte()? == 0x02, "COSE kty must be 2")?,
            1 => require(reader.byte()? == 0x26, "COSE alg must be -7")?,
            2 => require(reader.byte()? == 0x01, "COSE crv must be 1")?,
            _ => {
                require(
                    reader.byte()? == 0x58 && reader.byte()? == 0x20,
                    "COSE coordinate must be minimal 32-byte string",
                )?;
                let start = if index == 3 { 1 } else { 33 };
                public[start..start + 32].copy_from_slice(reader.take(32)?);
            }
        }
    }
    require(reader.offset == bytes.len(), "trailing COSE bytes")?;
    point(&public)?;
    Ok(public)
}
struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    fn byte(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| malformed("CBOR length"))?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| malformed("truncated COSE key"))?;
        self.offset = end;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    fn entries() -> Vec<Vec<u8>> {
        let key = p256::ecdsa::SigningKey::from_slice(&[1; 32]).unwrap();
        let point = key.verifying_key().to_encoded_point(false);
        vec![
            vec![1, 2],
            vec![3, 0x26],
            vec![0x20, 1],
            [vec![0x21, 0x58, 0x20], point.as_bytes()[1..33].to_vec()].concat(),
            [vec![0x22, 0x58, 0x20], point.as_bytes()[33..].to_vec()].concat(),
        ]
    }
    fn encode(entries: &[Vec<u8>]) -> Vec<u8> {
        [vec![0xa5], entries.concat()].concat()
    }
    #[test]
    fn valid_and_order_independent() {
        let mut e = entries();
        let point = parse(&encode(&e)).unwrap();
        e.reverse();
        assert_eq!(parse(&encode(&e)).unwrap(), point);
    }
    #[test]
    fn extra_duplicate_trailing_truncation_and_invalid_point() {
        let original = encode(&entries());
        for n in 0..original.len() {
            assert!(parse(&original[..n]).is_err());
        }
        let mut b = original.clone();
        b.push(0);
        assert!(parse(&b).is_err());
        let mut b = original.clone();
        b[0] = 0xa6;
        b.extend([4, 0]);
        assert!(parse(&b).is_err());
        let mut e = entries();
        e[1] = e[0].clone();
        assert!(parse(&encode(&e)).is_err());
        let mut e = entries();
        e[3][3..].fill(0);
        e[4][3..].fill(0);
        assert!(parse(&encode(&e)).is_err());
        for head in [0xa4, 0xbf, 0xb8, 0x85] {
            let mut b = original.clone();
            b[0] = head;
            assert!(parse(&b).is_err());
        }
    }
    #[test]
    fn minimal_encodings_and_exact_types() {
        for (i, replacement) in [
            (0, vec![0x18, 1, 2]),
            (0, vec![1, 0x18, 2]),
            (1, vec![3, 0x38, 6]),
            (2, vec![0x38, 0, 1]),
            (2, vec![0x20, 0x18, 1]),
            (0, vec![1, 3]),
            (1, vec![3, 7]),
            (2, vec![0x20, 2]),
            (0, vec![4, 2]),
        ] {
            let mut e = entries();
            e[i] = replacement;
            assert!(parse(&encode(&e)).is_err());
        }
        for prefix in [
            vec![0x59, 0, 32],
            vec![0x5f],
            vec![0x78, 32],
            vec![0x58, 31],
            vec![0x58, 33],
        ] {
            let mut e = entries();
            e[3] = [vec![0x21], prefix, e[3][3..].to_vec()].concat();
            assert!(parse(&encode(&e)).is_err());
        }
    }
}
