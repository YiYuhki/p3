//! Minimal TLS ClientHello SNI extractor.
//!
//! Used by the transparent proxy to learn the target host for HTTPS flows
//! without decrypting anything. We parse only enough of the first TLS record to
//! reach the `server_name` extension.

/// Outcome of attempting to read SNI from a buffer.
pub enum SniResult {
    /// SNI hostname found.
    Found(String),
    /// Valid so far, but we need more bytes to finish parsing.
    NeedMore,
    /// Not a TLS ClientHello, or no SNI present.
    None,
}

/// Try to extract the SNI host name from the start of a TLS stream.
pub fn parse_sni(buf: &[u8]) -> SniResult {
    // TLS record header: type(1) version(2) length(2)
    if buf.len() < 5 {
        return SniResult::NeedMore;
    }
    if buf[0] != 0x16 {
        // Not a handshake record.
        return SniResult::None;
    }
    let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    let record_end = 5 + record_len;
    if buf.len() < record_end {
        return SniResult::NeedMore;
    }
    let hs = &buf[5..record_end];

    // Handshake header: type(1) length(3)
    if hs.len() < 4 {
        return SniResult::NeedMore;
    }
    if hs[0] != 0x01 {
        // Not a ClientHello.
        return SniResult::None;
    }
    let mut p = 4usize;

    // client_version(2) + random(32)
    p = match advance(hs, p, 2 + 32) {
        Some(v) => v,
        None => return SniResult::None,
    };

    // session_id: len(1) + data
    let sid_len = match read_u8(hs, p) {
        Some(v) => v as usize,
        None => return SniResult::None,
    };
    p += 1;
    p = match advance(hs, p, sid_len) {
        Some(v) => v,
        None => return SniResult::None,
    };

    // cipher_suites: len(2) + data
    let cs_len = match read_u16(hs, p) {
        Some(v) => v as usize,
        None => return SniResult::None,
    };
    p += 2;
    p = match advance(hs, p, cs_len) {
        Some(v) => v,
        None => return SniResult::None,
    };

    // compression_methods: len(1) + data
    let cm_len = match read_u8(hs, p) {
        Some(v) => v as usize,
        None => return SniResult::None,
    };
    p += 1;
    p = match advance(hs, p, cm_len) {
        Some(v) => v,
        None => return SniResult::None,
    };

    // extensions: len(2) + data
    let ext_total = match read_u16(hs, p) {
        Some(v) => v as usize,
        None => return SniResult::None,
    };
    p += 2;
    let ext_end = p + ext_total;
    if ext_end > hs.len() {
        return SniResult::None;
    }

    while p + 4 <= ext_end {
        let ext_type = read_u16(hs, p).unwrap();
        let ext_len = read_u16(hs, p + 2).unwrap() as usize;
        p += 4;
        if p + ext_len > ext_end {
            return SniResult::None;
        }
        if ext_type == 0x0000 {
            // server_name extension.
            return parse_sni_extension(&hs[p..p + ext_len]);
        }
        p += ext_len;
    }

    SniResult::None
}

fn parse_sni_extension(data: &[u8]) -> SniResult {
    // ServerNameList: len(2) then entries of type(1) + len(2) + name.
    if data.len() < 2 {
        return SniResult::None;
    }
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;
    let mut p = 2usize;
    let end = std::cmp::min(2 + list_len, data.len());
    while p + 3 <= end {
        let name_type = data[p];
        let name_len = u16::from_be_bytes([data[p + 1], data[p + 2]]) as usize;
        p += 3;
        if p + name_len > end {
            return SniResult::None;
        }
        if name_type == 0 {
            // host_name
            return match std::str::from_utf8(&data[p..p + name_len]) {
                Ok(s) => SniResult::Found(s.to_ascii_lowercase()),
                Err(_) => SniResult::None,
            };
        }
        p += name_len;
    }
    SniResult::None
}

fn read_u8(buf: &[u8], pos: usize) -> Option<u8> {
    buf.get(pos).copied()
}

fn read_u16(buf: &[u8], pos: usize) -> Option<u16> {
    if pos + 2 <= buf.len() {
        Some(u16::from_be_bytes([buf[pos], buf[pos + 1]]))
    } else {
        None
    }
}

fn advance(buf: &[u8], pos: usize, by: usize) -> Option<usize> {
    let next = pos + by;
    if next <= buf.len() {
        Some(next)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn not_tls() {
        assert!(matches!(parse_sni(b"GET / HTTP/1.1\r\n"), SniResult::None));
    }

    #[test]
    fn needs_more() {
        assert!(matches!(parse_sni(&[0x16, 0x03]), SniResult::NeedMore));
    }
}
