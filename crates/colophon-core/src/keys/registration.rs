//! Registration extraction. Attestation statements are ignored, never verified (§2.5).
use super::{cose, malformed, require, KeyDescriptor};
use crate::Result;
use sha2::{Digest, Sha256};

/// Extract an ES256 WebAuthn descriptor from an attestation object for `rp`.
/// Requires attested credential data and checks its RP hash; attestation conveys no trust.
pub fn parse(attestation_object: &[u8], rp: &str) -> Result<KeyDescriptor> {
    let mut reader = Reader::new(attestation_object);
    require(
        reader.head()? == (5, 3),
        "attestation map requires three entries",
    )?;
    let mut seen = [false; 3];
    let mut auth_data = None;
    for _ in 0..3 {
        let index = match reader.string(3)? {
            b"fmt" => 0,
            b"attStmt" => 1,
            b"authData" => 2,
            _ => return Err(malformed("unknown attestation field")),
        };
        require(!seen[index], "duplicate attestation field")?;
        seen[index] = true;
        match index {
            0 => {
                reader.string(3)?;
            }
            1 => {
                let start = reader.offset;
                require(reader.head()?.0 == 5, "attStmt must be a map")?;
                reader.offset = start;
                reader.skip()?;
            }
            _ => auth_data = Some(reader.string(2)?),
        }
    }
    require(
        reader.offset == attestation_object.len(),
        "trailing attestation bytes",
    )?;
    let mut data = Reader::new(auth_data.ok_or_else(|| malformed("missing authData"))?);
    require(
        data.take(32)? == Sha256::digest(rp.as_bytes()).as_slice(),
        "registration RP hash",
    )?;
    let flags = data.take(1)?[0];
    require(flags & 0x40 != 0, "registration requires AT")?;
    data.take(4 + 16)?; // counter and AAGUID
    let length = data.take(2)?;
    let length = usize::from(u16::from_be_bytes([length[0], length[1]]));
    let credential = data.take(length)?.to_vec();
    let start = data.offset;
    data.skip()?;
    let signing = cose::parse(&data.bytes[start..data.offset])?.to_vec();
    if flags & 0x80 != 0 {
        let start = data.offset;
        require(data.head()?.0 == 5, "extensions must be a map")?;
        data.offset = start;
        data.skip()?;
    }
    require(
        data.offset == data.bytes.len(),
        "trailing authenticator data",
    )?;
    let key = KeyDescriptor::WebAuthn {
        signing,
        rp: rp.into(),
        credential,
        origins: None,
    };
    key.validate()?;
    Ok(key)
}

struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| malformed("CBOR length"))?;
        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or_else(|| malformed("truncated CBOR"))?;
        self.offset = end;
        Ok(bytes)
    }
    fn head(&mut self) -> Result<(u8, u64)> {
        let byte = self.take(1)?[0];
        let additional = byte & 31;
        let value = match additional {
            0..=23 => u64::from(additional),
            24..=27 => {
                let count = 1usize << (additional - 24);
                let mut value = 0u64;
                for b in self.take(count)? {
                    value = (value << 8) | u64::from(*b);
                }
                let min = match additional {
                    24 => 24,
                    25 => 256,
                    26 => 65536,
                    _ => 4294967296,
                };
                require(value >= min, "non-minimal CBOR")?;
                value
            }
            _ => return Err(malformed("indefinite or reserved CBOR")),
        };
        Ok((byte >> 5, value))
    }
    fn string(&mut self, kind: u8) -> Result<&'a [u8]> {
        let (major, len) = self.head()?;
        require(major == kind, "CBOR string type")?;
        let value = self.take(usize::try_from(len).map_err(|_| malformed("CBOR length"))?)?;
        if kind == 3 {
            std::str::from_utf8(value).map_err(|_| malformed("CBOR UTF-8"))?;
        }
        Ok(value)
    }
    fn skip(&mut self) -> Result<()> {
        let mut remaining = 1u64;
        while remaining > 0 {
            remaining -= 1;
            let start = self.offset;
            let byte = self.take(1)?[0];
            if byte >> 5 == 7 {
                match byte & 31 {
                    0..=23 => (),
                    24 => require(self.take(1)?[0] >= 32, "non-minimal CBOR simple value")?,
                    25 => {
                        self.take(2)?;
                    }
                    26 => {
                        self.take(4)?;
                    }
                    27 => {
                        self.take(8)?;
                    }
                    _ => return Err(malformed("reserved CBOR simple value")),
                }
                continue;
            }
            self.offset = start;
            let (major, len) = self.head()?;
            let children = match major {
                0 | 1 => 0,
                2 | 3 => {
                    let bytes =
                        self.take(usize::try_from(len).map_err(|_| malformed("CBOR length"))?)?;
                    if major == 3 {
                        std::str::from_utf8(bytes).map_err(|_| malformed("CBOR UTF-8"))?;
                    }
                    0
                }
                4 => len,
                5 => len.checked_mul(2).ok_or_else(|| malformed("CBOR length"))?,
                6 => 1,
                _ => return Err(malformed("CBOR type")),
            };
            remaining = remaining
                .checked_add(children)
                .ok_or_else(|| malformed("CBOR length"))?;
            require(
                remaining <= (self.bytes.len() - self.offset) as u64,
                "CBOR length",
            )?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use crate::keys::testing::SyntheticAuthenticator;
    fn registration() -> Vec<u8> {
        let key = SyntheticAuthenticator::new()
            .unwrap()
            .descriptor("id.luff.works", None)
            .unwrap();
        let p = key.signing();
        let cose = [
            vec![0xa5, 1, 2, 3, 0x26, 0x20, 1, 0x21, 0x58, 32],
            p[1..33].to_vec(),
            vec![0x22, 0x58, 32],
            p[33..].to_vec(),
        ]
        .concat();
        let data = [
            Sha256::digest(b"id.luff.works").to_vec(),
            vec![0x41],
            vec![0; 20],
            vec![0, 1, 1],
            cose,
        ]
        .concat();
        [
            vec![0xa3, 0x68],
            b"authData".to_vec(),
            vec![0x58, data.len() as u8],
            data,
            vec![0x63],
            b"fmt".to_vec(),
            vec![0x64],
            b"none".to_vec(),
            vec![0x67],
            b"attStmt".to_vec(),
            vec![0xa0],
        ]
        .concat()
    }
    #[test]
    fn synthetic_registration_and_refusals() {
        let bytes = registration();
        let key = parse(&bytes, "id.luff.works").unwrap();
        assert_eq!(
            key,
            SyntheticAuthenticator::new()
                .unwrap()
                .descriptor("id.luff.works", None)
                .unwrap()
        );
        assert!(parse(&bytes, "other.example").is_err());
        for end in 0..bytes.len() {
            assert!(parse(&bytes[..end], "id.luff.works").is_err());
        }
        let mut bad = bytes.clone();
        bad.push(0);
        assert!(parse(&bad, "id.luff.works").is_err());
        let mut bad = bytes.clone();
        bad[44] &= !0x40;
        assert!(parse(&bad, "id.luff.works").is_err());
        let mut bad = bytes;
        bad[0] = 0xa4;
        assert!(parse(&bad, "id.luff.works").is_err());
    }
    #[test]
    fn every_standard_field_order_and_ignored_attestation() {
        let bytes = registration();
        let end = 12 + usize::from(bytes[11]);
        let entries = [&bytes[1..end], &bytes[end..end + 9], &bytes[end + 9..]];
        let expected = parse(&bytes, "id.luff.works").unwrap();
        for order in [
            [0, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ] {
            let mut encoded = vec![0xa3];
            for i in order {
                encoded.extend_from_slice(entries[i]);
            }
            assert_eq!(parse(&encoded, "id.luff.works").unwrap(), expected);
        }
        let mut encoded = vec![0xa3];
        encoded.extend_from_slice(entries[0]);
        encoded.extend_from_slice(entries[1]);
        encoded.extend_from_slice(&[
            0x67, b'a', b't', b't', b'S', b't', b'm', b't', 0xa1, 0x63, b'f', b'o', b'o', 0xf5,
        ]);
        assert_eq!(parse(&encoded, "id.luff.works").unwrap(), expected);
        let duplicate = [
            vec![0xa3],
            entries[0].to_vec(),
            entries[0].to_vec(),
            entries[2].to_vec(),
        ]
        .concat();
        assert!(parse(&duplicate, "id.luff.works").is_err());
    }
    #[test]
    fn minimal_cbor_and_authenticator_data_boundaries() {
        let bytes = registration();
        let end = 12 + usize::from(bytes[11]);
        let mut bad = [vec![0xb8, 3], bytes[1..].to_vec()].concat();
        assert!(parse(&bad, "id.luff.works").is_err());
        bad = [bytes[..1].to_vec(), vec![0x78, 8], bytes[2..].to_vec()].concat();
        assert!(parse(&bad, "id.luff.works").is_err());
        bad = bytes.clone();
        bad[68] = 0xa6;
        assert!(parse(&bad, "id.luff.works").is_err());
        bad = bytes.clone();
        bad.insert(end, 0);
        bad[11] += 1;
        assert!(parse(&bad, "id.luff.works").is_err());
        let mut extensions = bytes.clone();
        extensions[44] |= 0x80;
        assert!(parse(&extensions, "id.luff.works").is_err());
        extensions.insert(end, 0xa0);
        extensions[11] += 1;
        assert_eq!(
            parse(&extensions, "id.luff.works").unwrap(),
            parse(&bytes, "id.luff.works").unwrap()
        );
    }
}
