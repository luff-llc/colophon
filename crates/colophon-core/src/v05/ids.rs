//! Account IDs, key IDs and the 0.4 legacy library ID relation (§3.1, §5.1).
use super::encoding::{digest, is_lower_hex};
use super::{malformed, Result};
use sha2::{Digest, Sha256};

/// The text-form prefix of an account ID.
pub const ACCOUNT_PREFIX: &str = "colophon:";

/// An account ID: all 64 lowercase hex characters of SHA-256 of the first authority body.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AccountId(String);
impl AccountId {
    /// The ID of the account whose first authority body is `genesis_body` (exact bytes).
    pub fn of_genesis(genesis_body: &[u8]) -> Self {
        Self(digest(genesis_body))
    }
    /// Parse a 64-hex ID. A 32-hex legacy library ID, or anything else, is `malformed`
    /// wherever a 0.5 format names an account (§5.1).
    pub fn parse(s: &str) -> Result<Self> {
        if is_lower_hex(s, 32) {
            return Err(malformed(
                "legacy 32-hex library ID where a 0.5 account ID is required",
            ));
        }
        if !is_lower_hex(s, 64) {
            return Err(malformed("account ID is not 64 lowercase hex"));
        }
        Ok(Self(s.into()))
    }
    /// Parse the text form `colophon:<64 hex>`.
    pub fn parse_text(s: &str) -> Result<Self> {
        Self::parse(
            s.strip_prefix(ACCOUNT_PREFIX)
                .ok_or_else(|| malformed("missing colophon: prefix"))?,
        )
    }
    /// The 64 hex characters.
    pub fn as_str(&self) -> &str {
        &self.0
    }
    /// The text form.
    pub fn text(&self) -> String {
        format!("{ACCOUNT_PREFIX}{}", self.0)
    }
    /// The legacy 0.4 library ID of an account upgraded in place: its first 32 characters.
    /// For a native 0.5 account this prefix has no meaning outside `/3` epoch labels (§11.1).
    pub fn legacy_library_id(&self) -> &str {
        &self.0[..32]
    }
    /// True when `legacy` (32 hex) is this account's legacy library ID. This is the only way a
    /// legacy ID is resolved: by obtaining the history and checking the prefix (§5.1).
    pub fn has_legacy_id(&self, legacy: &str) -> bool {
        is_lower_hex(legacy, 32) && self.legacy_library_id() == legacy
    }
}
impl std::fmt::Display for AccountId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The key ID of a signing point: the first 32 lowercase hex characters of SHA-256 (§3.1).
/// Controller, member and home IDs are key IDs.
pub fn key_id(signing: &[u8]) -> String {
    let full = Sha256::digest(signing);
    super::encoding::hex(&full[..16])
}

/// True for a syntactically valid key ID (32 lowercase hex).
pub fn is_key_id(s: &str) -> bool {
    is_lower_hex(s, 32)
}

/// An account reference (§5.2): `{"account", "hints"?}`. Hints are 1–8 `https://` URLs of at
/// most 512 bytes, never signed and never trusted; what they return is checked or dropped.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reference {
    /// The account.
    pub account: AccountId,
    /// Untrusted location hints.
    pub hints: Option<Vec<String>>,
}
impl Reference {
    /// Parse a reference value. Unknown fields go to `unknown`.
    pub fn parse(value: serde_json::Value, unknown: &mut super::Unknown) -> Result<Self> {
        let mut o = super::encoding::Obj::new(value, "reference")?;
        let account = AccountId::parse(&o.string("account")?)?;
        let hints = match o.opt_nonempty_array("hints")? {
            None => None,
            Some(items) => {
                super::require(items.len() <= 8, "at most 8 hints")?;
                let list = items
                    .into_iter()
                    .map(|v| match v {
                        serde_json::Value::String(h)
                            if h.starts_with("https://") && h.len() > 8 && h.len() <= 512 =>
                        {
                            Ok(h)
                        }
                        _ => Err(malformed("hints are https:// URLs of at most 512 bytes")),
                    })
                    .collect::<Result<Vec<_>>>()?;
                Some(list)
            }
        };
        o.finish(unknown);
        Ok(Self { account, hints })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn account_ids_and_legacy_prefix() {
        let a = AccountId::of_genesis(b"{}");
        assert_eq!(a.as_str().len(), 64);
        assert_eq!(AccountId::parse(a.as_str()).unwrap(), a);
        assert_eq!(AccountId::parse_text(&a.text()).unwrap(), a);
        assert!(a.has_legacy_id(&a.as_str()[..32]));
        assert!(AccountId::parse(&a.as_str()[..32]).is_err());
        assert!(AccountId::parse(&a.as_str().to_uppercase()).is_err());
        assert!(AccountId::parse_text(a.as_str()).is_err());
        assert_eq!(key_id(b"x"), digest(b"x")[..32]);
    }
}
