//! Upload destination facts reported beside an `exfil.outbound_upload` action
//! finding, for embedding hosts that keep their own destination trust lists.
//!
//! Facts describe what the command text names. They never change rule
//! matching, scores or semantic identities, and Telltale applies no trust list.
//! Entries are built from parsed URL parts in a closed alphabet, never from
//! sanitizer output, and each is a fixed point of the evidence sanitizer, which
//! [`DestinationFacts::is_valid`] lets a strict consumer check.

use serde::{Deserialize, Serialize};

use crate::event::redact_sensitive_text;

/// The most destinations one finding lists.
pub const MAX_DESTINATIONS: usize = 16;
/// The longest destination entry, in bytes.
pub const MAX_DESTINATION_LEN: usize = 256;

/// Where an `exfil.outbound_upload` action sends, as far as its command text
/// says. Both flags fail closed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DestinationFacts {
    /// Non-loopback destinations: lowercased, sorted, distinct, at most
    /// [`MAX_DESTINATIONS`]. A DNS-scheme URL (http, https, ws, wss, ftp, ftps,
    /// sftp, scp, tftp) is `host`, `host/seg` or `host/seg/seg`; any other
    /// scheme keeps `scheme://authority[/seg[/seg]]`. Never a port, userinfo,
    /// query or fragment; path segments stop before one that is not a plain
    /// name.
    pub destinations: Vec<String>,
    /// Every URL in the command field was read, every upload stage named a
    /// destination URL, and nothing could send the upload elsewhere: no
    /// variable, schemeless destination, proxy, resolve, connect-to, config or
    /// socket override, host header, cloud-client profile, unknown option,
    /// command or process substitution, quoting another shell reads
    /// differently, or network redirection.
    pub complete: bool,
    /// The whole field is one simple curl, wget or PowerShell web cmdlet
    /// upload, by bare program names, that follows no redirect and whose
    /// every destination is loopback (`localhost`, 127.0.0.0/8, `[::1]`,
    /// `0.0.0.0`). Implies `complete` and no `destinations`.
    pub local_only: bool,
}

impl DestinationFacts {
    /// Whether the facts keep their invariants: bounded, sorted, distinct
    /// entries in the closed alphabet that the evidence sanitizer leaves
    /// unchanged, and `local_only` only with `complete` and no entries.
    pub fn is_valid(&self) -> bool {
        self.destinations.len() <= MAX_DESTINATIONS
            && (!self.local_only || self.complete && self.destinations.is_empty())
            && self.destinations.windows(2).all(|pair| pair[0] < pair[1])
            && self.destinations.iter().all(|entry| {
                entry.len() <= MAX_DESTINATION_LEN
                    && well_formed(entry)
                    && redact_sensitive_text(entry) == *entry
            })
    }
}

/// An entry's shape: an optional `scheme://`, a host (a bracketed IPv6
/// address may hold colons, nothing else may), then plain path segments.
fn well_formed(entry: &str) -> bool {
    let name = |text: &str| {
        !text.is_empty()
            && !text.contains("..")
            && text.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'~' | b'-')
            })
    };
    let rest = match entry.split_once("://") {
        Some((scheme, rest))
            if scheme.starts_with(|c: char| c.is_ascii_lowercase()) && name(scheme) =>
        {
            rest
        }
        Some(_) => return false,
        None => entry,
    };
    let mut parts = rest.split('/');
    let host = parts.next().unwrap_or_default();
    let host_ok = match host
        .strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
    {
        Some(address) => address.parse::<std::net::Ipv6Addr>().is_ok(),
        None => name(host),
    };
    host_ok && parts.all(name)
}

#[cfg(test)]
mod tests {
    use super::DestinationFacts;

    fn facts(destinations: &[&str], complete: bool, local_only: bool) -> DestinationFacts {
        DestinationFacts {
            destinations: destinations
                .iter()
                .map(|entry| (*entry).to_owned())
                .collect(),
            complete,
            local_only,
        }
    }

    #[test]
    fn validation_keeps_order_alphabet_fixed_point_and_flag_invariants() {
        assert!(
            facts(
                &[
                    "artifacts.example.invalid/org/repo",
                    "s3://synthetic-bucket/prefix"
                ],
                true,
                false
            )
            .is_valid()
        );
        assert!(facts(&["[2001:db8::1]/x"], false, false).is_valid());
        assert!(facts(&[], true, true).is_valid());
        // `local_only` needs `complete` and no entries.
        assert!(!facts(&["example.invalid"], true, true).is_valid());
        assert!(!facts(&[], false, true).is_valid());
        // Sorted and distinct.
        assert!(!facts(&["b.invalid", "a.invalid"], true, false).is_valid());
        assert!(!facts(&["a.invalid", "a.invalid"], true, false).is_valid());
        // Bounded.
        let many: Vec<String> = (0..17).map(|n| format!("h{n:02}.invalid")).collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        assert!(!facts(&many, false, false).is_valid());
        for bad in [
            "",
            "Example.Invalid",
            "user@example.invalid",
            "example.invalid?a=1",
            "example.invalid#frag",
            "example.invalid/a/../b",
            "example.invalid/%2e",
            "example.invalid:8443",
            // In the alphabet, but the sanitizer would rewrite it.
            "example.invalid/v1/0123456789abcdef0123456789abcdef01234567",
            "example.invalid/akiaiosfodnn7example",
        ] {
            assert!(!facts(&[bad], false, false).is_valid(), "{bad}");
        }
    }
}
