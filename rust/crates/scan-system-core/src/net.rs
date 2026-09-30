//! Ported from `scanner_windows.is_public_ipv4`/`format_rate`/`build_threat_feed_ip_set`.

use std::{collections::HashSet, net::IpAddr};

use serde::Deserialize;

/// `true` only for a real, publicly-routable IPv4 address — not private/loopback/
/// multicast/link-local, and not IPv6 at all (the Python original is IPv4-only by
/// design: `isinstance(ip_obj, ipaddress.IPv4Address)`).
#[must_use]
pub fn is_public_ipv4(value: &str) -> bool {
    match value.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            !(v4.is_unspecified()
                || v4.is_private()
                || v4.is_loopback()
                || v4.is_multicast()
                || v4.is_link_local())
        }
        _ => false,
    }
}

/// Formats a byte rate as a human bit rate (bps/Kbps/Mbps/Gbps), one decimal past the
/// first unit. Negative input clamps to `0 bps` rather than producing a negative rate.
#[must_use]
pub fn format_rate(bytes_per_sec: f64) -> String {
    let bits = (bytes_per_sec * 8.0).max(0.0);
    if bits >= 1_000_000_000.0 {
        format!("{:.1} Gbps", bits / 1_000_000_000.0)
    } else if bits >= 1_000_000.0 {
        format!("{:.1} Mbps", bits / 1_000_000.0)
    } else if bits >= 1_000.0 {
        format!("{:.1} Kbps", bits / 1_000.0)
    } else {
        format!("{bits:.0} bps")
    }
}

/// One threat feed's parsed entries, as cached by `refresh_threat_feeds_cache`
/// (`scan-system-platform`, phase 2 — the network fetch itself isn't pure). `ips` and
/// `sample` are `Option`, not defaulted to empty, so [`build_threat_feed_ip_set`] can
/// tell "key absent, fall back to sample" from "key present but empty" — the same
/// distinction `dict.get("ips", ...)` makes in the Python original.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct ThreatFeed {
    #[serde(default)]
    pub ips: Option<Vec<String>>,
    #[serde(default)]
    pub sample: Option<Vec<String>>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct ThreatFeedsRefresh {
    #[serde(default)]
    pub feeds: Vec<ThreatFeed>,
}

/// Flattens every feed's IPs into one deduplicated set, preferring the full `ips` list
/// over the truncated `sample` when both are present (mirrors `feed.get("ips",
/// feed.get("sample", []))`). Blank entries (empty after trimming) are dropped.
#[must_use]
pub fn build_threat_feed_ip_set(refresh: &ThreatFeedsRefresh) -> HashSet<String> {
    let mut ips = HashSet::new();
    for feed in &refresh.feeds {
        let entries = feed.ips.as_ref().or(feed.sample.as_ref());
        let Some(entries) = entries else { continue };
        for entry in entries {
            let trimmed = entry.trim();
            if !trimmed.is_empty() {
                ips.insert(trimmed.to_string());
            }
        }
    }
    ips
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed(ips: Option<&[&str]>, sample: Option<&[&str]>) -> ThreatFeed {
        ThreatFeed {
            ips: ips.map(|s| s.iter().map(|x| (*x).to_string()).collect()),
            sample: sample.map(|s| s.iter().map(|x| (*x).to_string()).collect()),
        }
    }

    #[test]
    fn is_public_ipv4_true_for_real_public_address() {
        assert!(is_public_ipv4("8.8.8.8"));
    }

    #[test]
    fn is_public_ipv4_false_for_private_loopback_multicast_linklocal() {
        assert!(!is_public_ipv4("192.168.1.1"));
        assert!(!is_public_ipv4("10.0.0.5"));
        assert!(!is_public_ipv4("127.0.0.1"));
        assert!(!is_public_ipv4("224.0.0.1"));
        assert!(!is_public_ipv4("169.254.1.1"));
        assert!(!is_public_ipv4("0.0.0.0"));
    }

    #[test]
    fn is_public_ipv4_false_for_ipv6_and_garbage() {
        assert!(!is_public_ipv4("2001:4860:4860::8888"));
        assert!(!is_public_ipv4("not-an-ip"));
        assert!(!is_public_ipv4(""));
    }

    #[test]
    fn format_rate_units() {
        assert_eq!(format_rate(0.0), "0 bps");
        assert_eq!(format_rate(100.0), "800 bps");
        assert_eq!(format_rate(125.0), "1.0 Kbps");
        assert_eq!(format_rate(125_000.0), "1.0 Mbps");
        assert_eq!(format_rate(125_000_000.0), "1.0 Gbps");
    }

    #[test]
    fn format_rate_clamps_negative_to_zero() {
        assert_eq!(format_rate(-500.0), "0 bps");
    }

    #[test]
    fn build_threat_feed_ip_set_prefers_ips_over_sample() {
        let refresh = ThreatFeedsRefresh {
            feeds: vec![feed(Some(&["1.1.1.1"]), Some(&["9.9.9.9"]))],
        };
        assert_eq!(
            build_threat_feed_ip_set(&refresh),
            HashSet::from(["1.1.1.1".to_string()])
        );
    }

    #[test]
    fn build_threat_feed_ip_set_falls_back_to_sample() {
        let refresh = ThreatFeedsRefresh {
            feeds: vec![feed(None, Some(&["9.9.9.9", " 8.8.8.8 "]))],
        };
        assert_eq!(
            build_threat_feed_ip_set(&refresh),
            HashSet::from(["9.9.9.9".to_string(), "8.8.8.8".to_string()])
        );
    }

    #[test]
    fn build_threat_feed_ip_set_merges_multiple_feeds_and_dedupes() {
        let refresh = ThreatFeedsRefresh {
            feeds: vec![
                feed(Some(&["1.1.1.1", "2.2.2.2"]), None),
                feed(Some(&["2.2.2.2", "3.3.3.3"]), None),
            ],
        };
        assert_eq!(
            build_threat_feed_ip_set(&refresh),
            HashSet::from([
                "1.1.1.1".to_string(),
                "2.2.2.2".to_string(),
                "3.3.3.3".to_string()
            ])
        );
    }

    #[test]
    fn build_threat_feed_ip_set_ignores_blank_entries() {
        let refresh = ThreatFeedsRefresh {
            feeds: vec![feed(Some(&["", "   ", "1.1.1.1"]), None)],
        };
        assert_eq!(
            build_threat_feed_ip_set(&refresh),
            HashSet::from(["1.1.1.1".to_string()])
        );
    }

    #[test]
    fn build_threat_feed_ip_set_empty_input() {
        assert_eq!(
            build_threat_feed_ip_set(&ThreatFeedsRefresh::default()),
            HashSet::new()
        );
    }
}
