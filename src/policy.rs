//! Domain matching and per-level allow/deny evaluation.
//!
//! A [`DomainSet`] holds a set of domain patterns and answers "does this host
//! match?" in O(number of labels) hash lookups — no regex, no allocation on the
//! hot path. Patterns supported:
//!
//! * `*`               — matches every host (wildcard-all)
//! * `example.com`     — matches `example.com` and any subdomain `*.example.com`
//! * `.example.com`    — same as above (leading dot is stripped)
//! * `*.example.com`   — matches strict subdomains only (not the apex)

use std::collections::HashSet;

use serde::Deserialize;

/// Raw allow/deny lists as read from the config file.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct RawRules {
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
}

/// Final allow/deny outcome for a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}

/// A compiled set of domain patterns optimized for fast membership tests.
#[derive(Debug, Default)]
pub struct DomainSet {
    /// `*` was present — everything matches.
    all: bool,
    /// Patterns that match the apex and all subdomains.
    domains: HashSet<String>,
    /// Patterns (from `*.d`) that match strict subdomains only.
    subdomains: HashSet<String>,
}

impl DomainSet {
    /// Compile a list of raw patterns into a `DomainSet`.
    pub fn build(list: &[String]) -> Self {
        let mut set = DomainSet::default();
        for raw in list {
            let e = raw.trim().trim_end_matches('.').to_ascii_lowercase();
            if e.is_empty() {
                continue;
            }
            if e == "*" {
                set.all = true;
            } else if let Some(rest) = e.strip_prefix("*.") {
                if !rest.is_empty() {
                    set.subdomains.insert(rest.to_string());
                }
            } else if let Some(rest) = e.strip_prefix('.') {
                if !rest.is_empty() {
                    set.domains.insert(rest.to_string());
                }
            } else {
                set.domains.insert(e);
            }
        }
        set
    }

    /// Returns true if `host` matches any pattern in this set.
    ///
    /// `host` is expected to be lowercase and without a trailing dot or port;
    /// see [`normalize_host`].
    pub fn matches(&self, host: &str) -> bool {
        if self.all {
            return true;
        }
        if host.is_empty() {
            return false;
        }
        // Full host matches "self + subdomains" patterns.
        if self.domains.contains(host) {
            return true;
        }
        // Walk each suffix that begins right after a '.'.
        for (i, c) in host.char_indices() {
            if c == '.' {
                let suffix = &host[i + 1..];
                if self.domains.contains(suffix) || self.subdomains.contains(suffix) {
                    return true;
                }
            }
        }
        false
    }
}

/// A single level's allow/deny rules (global, a department, or an individual).
#[derive(Debug)]
pub struct Rules {
    pub allow: DomainSet,
    pub deny: DomainSet,
}

impl Rules {
    pub fn from_raw(raw: &RawRules) -> Self {
        Rules {
            allow: DomainSet::build(&raw.allow),
            deny: DomainSet::build(&raw.deny),
        }
    }

    /// Evaluate this level in isolation.
    ///
    /// Deny is checked before allow (fail-safe). Returns `None` when this level
    /// expresses no opinion, so the caller can fall through to the next level.
    pub fn decide(&self, host: &str) -> Option<Decision> {
        if self.deny.matches(host) {
            Some(Decision::Deny)
        } else if self.allow.matches(host) {
            Some(Decision::Allow)
        } else {
            None
        }
    }
}

/// Normalize a request host: strip an optional port, trailing dot, and lowercase.
///
/// Handles bracketed IPv6 literals like `[::1]:443`.
pub fn normalize_host(raw: &str) -> String {
    let host = raw.trim();
    let host = if let Some(rest) = host.strip_prefix('[') {
        // IPv6 literal: take up to the closing bracket.
        match rest.split_once(']') {
            Some((inner, _)) => inner,
            None => rest,
        }
    } else {
        // Strip ":port" if present (IPv4 / hostname).
        match host.rsplit_once(':') {
            Some((h, _)) => h,
            None => host,
        }
    };
    host.trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_and_subdomain() {
        let s = DomainSet::build(&["example.com".into()]);
        assert!(s.matches("example.com"));
        assert!(s.matches("www.example.com"));
        assert!(s.matches("a.b.example.com"));
        assert!(!s.matches("notexample.com"));
        assert!(!s.matches("example.com.evil.com"));
    }

    #[test]
    fn strict_subdomain() {
        let s = DomainSet::build(&["*.example.com".into()]);
        assert!(!s.matches("example.com"));
        assert!(s.matches("www.example.com"));
    }

    #[test]
    fn wildcard_all() {
        let s = DomainSet::build(&["*".into()]);
        assert!(s.matches("anything.test"));
    }

    #[test]
    fn deny_before_allow() {
        let r = Rules::from_raw(&RawRules {
            allow: vec!["*".into()],
            deny: vec!["bad.com".into()],
        });
        assert_eq!(r.decide("bad.com"), Some(Decision::Deny));
        assert_eq!(r.decide("good.com"), Some(Decision::Allow));
    }

    #[test]
    fn normalize() {
        assert_eq!(normalize_host("Example.COM:443"), "example.com");
        assert_eq!(normalize_host("[::1]:8080"), "::1");
        assert_eq!(normalize_host("host."), "host");
    }
}
