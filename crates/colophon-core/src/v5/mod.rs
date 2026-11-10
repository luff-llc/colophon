//! Colophon 0.5 speaks-for primitives. This is deliberately independent of 0.4 replay.
//! The host supplies authenticated history, its clock, nonce observations and private-key work.

pub mod speaks;
pub mod terms;

/// The normative, stable Colophon 0.5 check outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// The action is permitted; `unguarded` means session revocation was not checked.
    Ok { unguarded: bool },
    /// Invalid syntax, structure, bounds or canonical encoding.
    Malformed,
    /// The signature/possession check failed.
    BadSignature,
    /// Authenticated data uses an unknown format or term.
    NewerFormat,
    /// Validly formed action refused for one of the specified reasons.
    Refused(Refusal),
}

/// Refusals defined by draft §5.3 (no new status codes are introduced here).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Requested authority head is not available.
    Stale,
    /// Member is absent or revoked.
    Revoked,
    /// Grant, link or request expired or is not yet valid.
    Expired,
    /// Delegation broadened its parent or exceeded link depth.
    NotNarrower,
    /// The member session number changed.
    Ended,
    /// A purpose, condition, audience or request binding is not allowed.
    OutOfScope,
}
impl Verdict {
    /// Exact protocol result code; the unguarded bit is returned separately.
    pub const fn code(self) -> &'static str {
        match self {
            Self::Ok { .. } => "ok",
            Self::Malformed => "malformed",
            Self::BadSignature => "badSignature",
            Self::NewerFormat => "newerFormat",
            Self::Refused(Refusal::Stale) => "refused:stale",
            Self::Refused(Refusal::Revoked) => "refused:revoked",
            Self::Refused(Refusal::Expired) => "refused:expired",
            Self::Refused(Refusal::NotNarrower) => "refused:notNarrower",
            Self::Refused(Refusal::Ended) => "refused:ended",
            Self::Refused(Refusal::OutOfScope) => "refused:outOfScope",
        }
    }
}

/// Parse the 0.3/0.4 UTC date forms to milliseconds since the Unix epoch.
/// No external clock or date dependency is used.
pub(crate) fn timestamp(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    let compact = b.len() == 20;
    if !compact && b.len() != 24 {
        return None;
    }
    for (i, expected) in [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')] {
        if b[i] != expected {
            return None;
        }
    }
    if (compact && b[19] != b'Z')
        || (!compact && (b[19] != b'.' || b[23] != b'Z'))
    {
        return None;
    }
    let number = |start: usize, end: usize| -> Option<i64> {
        let slice = b.get(start..end)?;
        if !slice.iter().all(u8::is_ascii_digit) {
            return None;
        }
        std::str::from_utf8(slice).ok()?.parse().ok()
    };
    let y = number(0, 4)?;
    let m = number(5, 7)?;
    let d = number(8, 10)?;
    let hh = number(11, 13)?;
    let mm = number(14, 16)?;
    let ss = number(17, 19)?;
    let millis = if compact { 0 } else { number(20, 23)? };
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let mdays = match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    if !(1..=9999).contains(&y) || d < 1 || d > mdays || hh > 23 || mm > 59 || ss > 59 {
        return None;
    }
    // Howard Hinnant's civil-date conversion; all arithmetic fits i64 for 1..9999.
    let yy = if m <= 2 { y - 1 } else { y };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let mp = m + if m > 2 { -3 } else { 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some((days * 86400 + hh * 3600 + mm * 60 + ss) * 1000 + millis)
}

#[cfg(test)]
mod tests {
    use super::timestamp;
    #[test]
    fn utc_calendar_and_millisecond_forms() {
        assert_eq!(timestamp("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(timestamp("1970-01-01T00:00:00.001Z"), Some(1));
        assert_eq!(timestamp("2024-02-29T23:59:59Z"), timestamp("2024-02-29T23:59:59.000Z"));
        assert_eq!(timestamp("2023-02-29T00:00:00Z"), None);
        assert_eq!(timestamp("2026-11-10T23:59:60Z"), None);
    }
}
