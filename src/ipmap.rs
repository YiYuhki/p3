//! Maps a client IP address to a department via CIDR longest-prefix match.
//!
//! For a corporate proxy the number of CIDR blocks is modest (dozens to a few
//! hundred), so a linear scan tracking the most-specific (longest-prefix) match
//! is both simple and fast. Entries are pre-sorted by prefix length descending
//! so the first containing match is already the most specific and the scan can
//! stop early.

use ipnet::IpNet;
use std::net::IpAddr;

#[derive(Debug)]
struct Entry {
    net: IpNet,
    dept: usize,
}

/// Resolves an IP address to a department index.
#[derive(Debug, Default)]
pub struct IpMap {
    entries: Vec<Entry>,
}

impl IpMap {
    pub fn new() -> Self {
        IpMap {
            entries: Vec::new(),
        }
    }

    /// Associate a CIDR block with a department index.
    pub fn insert(&mut self, net: IpNet, dept: usize) {
        self.entries.push(Entry { net, dept });
    }

    /// Call once after all inserts: sort by prefix length descending so the
    /// first match found during lookup is the most specific one.
    pub fn finalize(&mut self) {
        self.entries
            .sort_by(|a, b| b.net.prefix_len().cmp(&a.net.prefix_len()));
    }

    /// Return the department index for `ip`, if any CIDR contains it.
    pub fn department(&self, ip: IpAddr) -> Option<usize> {
        for e in &self.entries {
            if e.net.contains(&ip) {
                return Some(e.dept);
            }
        }
        None
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn longest_prefix_wins() {
        let mut m = IpMap::new();
        m.insert("10.0.0.0/8".parse().unwrap(), 0); // broad
        m.insert("10.1.2.0/24".parse().unwrap(), 1); // specific
        m.finalize();

        assert_eq!(m.department("10.1.2.5".parse().unwrap()), Some(1));
        assert_eq!(m.department("10.9.9.9".parse().unwrap()), Some(0));
        assert_eq!(m.department("192.168.0.1".parse().unwrap()), None);
    }
}
