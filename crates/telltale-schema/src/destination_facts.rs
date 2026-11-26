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
/// Path segments an entry keeps after its host or authority.
pub const MAX_DESTINATION_SEGMENTS: usize = 2;
/// Schemes whose authority is a DNS host: an entry drops them and starts at
/// the host. Any other scheme stays in its entry.
pub const DNS_SCHEMES: [&str; 9] = [
    "http", "https", "ws", "wss", "ftp", "ftps", "sftp", "scp", "tftp",
];

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
    /// destination URL, and nothing could send the upload to another first
    /// hop (what a listed host does with it, a redirect included, is that
    /// host's): no
    /// variable, schemeless destination, proxy, resolve, connect-to, config or
    /// socket override, host header, cloud-client profile, unknown option,
    /// command or process substitution, quoting another shell reads
    /// differently, or network redirection.
    pub complete: bool,
    /// The whole field is one simple curl, wget or PowerShell web cmdlet
    /// upload, by bare program names, that follows no redirect and whose
    /// every destination is loopback (`localhost` by name, 127.0.0.0/8,
    /// `[::1]`, `0.0.0.0`). Implies `complete` and no `destinations`; without
    /// it, no `destinations` does not mean the upload stayed local.
    pub local_only: bool,
}

impl DestinationFacts {
    /// Whether the facts keep their invariants: bounded, sorted, distinct
    /// entries of the documented structure (no DNS scheme, a host or
    /// bracketed lowercase IPv6 address, at most
    /// [`MAX_DESTINATION_SEGMENTS`] segments, all in the closed alphabet)
    /// that the evidence sanitizer leaves unchanged, and `local_only` only
    /// with `complete` and no entries. Which segments count as plain names is
    /// the producer's reading and is not checked again here.
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

/// An entry's shape: `scheme://` unless the scheme is one of [`DNS_SCHEMES`],
/// a host (a bracketed lowercase IPv6 address may hold colons, nothing else
/// may), then at most [`MAX_DESTINATION_SEGMENTS`] path segments.
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
            if scheme.starts_with(|c: char| c.is_ascii_lowercase())
                && name(scheme)
                && !DNS_SCHEMES.contains(&scheme) =>
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
        Some(address) => {
            address
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f' | b':' | b'.'))
                && address.parse::<std::net::Ipv6Addr>().is_ok()
        }
        None => name(host),
    };
    let mut segments = 0;
    host_ok
        && parts.all(|segment| {
            segments += 1;
            segments <= MAX_DESTINATION_SEGMENTS && name(segment)
        })
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
            // Not the entry shape: an uppercase address, a DNS scheme kept, a
            // third path segment.
            "[2001:DB8::1]",
            "https://example.invalid",
            "example.invalid/a/b/c",
            "s3://synthetic-bucket/a/b/c",
            // In the alphabet, but the sanitizer would rewrite it.
            "example.invalid/v1/0123456789abcdef0123456789abcdef01234567",
            "example.invalid/akiaiosfodnn7example",
        ] {
            assert!(!facts(&[bad], false, false).is_valid(), "{bad}");
        }
    }
}
