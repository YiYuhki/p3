//! Minimal, streaming HTTP/1.x helpers shared by the forward and MITM proxies.
//!
//! We deliberately avoid a full HTTP library: a proxy only needs to find the
//! target host, know where a message's head ends, and relay the body according
//! to its framing (Content-Length / chunked / close). Everything streams in
//! fixed-size chunks so memory stays flat regardless of payload size.

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_HEAD: usize = 64 * 1024;
const COPY_BUF: usize = 32 * 1024;

/// A buffered connection: owns a stream plus any bytes read past the last head.
pub struct Conn<S> {
    pub stream: S,
    pub buf: BytesMut,
}

impl<S> Conn<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(stream: S) -> Self {
        Conn {
            stream,
            buf: BytesMut::with_capacity(8 * 1024),
        }
    }

    /// Read one message head (request or status line + headers), consuming it
    /// from the buffer. Returns `None` on a clean EOF at a message boundary.
    pub async fn read_head(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        loop {
            if let Some(pos) = find_crlf_crlf(&self.buf) {
                let end = pos + 4;
                let head = self.buf.split_to(end);
                return Ok(Some(head.to_vec()));
            }
            if self.buf.len() > MAX_HEAD {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "HTTP head too large",
                ));
            }
            let n = self.stream.read_buf(&mut self.buf).await?;
            if n == 0 {
                if self.buf.is_empty() {
                    return Ok(None);
                }
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed mid-head",
                ));
            }
        }
    }
}

/// Locate the `\r\n\r\n` separating head from body.
fn find_crlf_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

/// A parsed HTTP message head (we keep the raw lines for faithful relaying).
pub struct Head {
    /// Request line or status line.
    pub first_line: String,
    /// (name, value) pairs, names as sent (used for relaying), plus a lowercased
    /// copy of the name for matching.
    pub headers: Vec<(String, String)>,
}

impl Head {
    pub fn parse(bytes: &[u8]) -> Option<Head> {
        let text = std::str::from_utf8(bytes).ok()?;
        let mut lines = text.split("\r\n");
        let first_line = lines.next()?.to_string();
        if first_line.is_empty() {
            return None;
        }
        let mut headers = Vec::new();
        for line in lines {
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':') {
                headers.push((name.trim().to_string(), value.trim().to_string()));
            }
        }
        Some(Head {
            first_line,
            headers,
        })
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Request method (first token of the request line). Empty for responses.
    pub fn method(&self) -> &str {
        self.first_line.split(' ').next().unwrap_or("")
    }

    /// Request target (second token of the request line).
    pub fn target(&self) -> &str {
        self.first_line.split(' ').nth(1).unwrap_or("")
    }

    /// Response status code (second token of the status line).
    pub fn status_code(&self) -> Option<u16> {
        self.first_line.split(' ').nth(1)?.parse().ok()
    }

    pub fn connection_close(&self) -> bool {
        self.header("connection")
            .map(|v| v.eq_ignore_ascii_case("close") || v.to_ascii_lowercase().contains("close"))
            .unwrap_or(false)
    }

    /// Determine how the body is framed.
    pub fn body_framing(&self) -> Framing {
        if let Some(te) = self.header("transfer-encoding") {
            if te.to_ascii_lowercase().contains("chunked") {
                return Framing::Chunked;
            }
        }
        if let Some(cl) = self.header("content-length") {
            if let Ok(n) = cl.trim().parse::<u64>() {
                return Framing::Length(n);
            }
        }
        Framing::None
    }

    /// Serialize the head back to bytes, optionally replacing the first line.
    /// Hop-by-hop proxy headers are dropped.
    pub fn serialize(&self, first_line_override: Option<&str>) -> Vec<u8> {
        let mut out = String::with_capacity(256);
        out.push_str(first_line_override.unwrap_or(&self.first_line));
        out.push_str("\r\n");
        for (name, value) in &self.headers {
            let lname = name.to_ascii_lowercase();
            // Drop proxy-specific hop-by-hop headers; keep everything else.
            if lname == "proxy-connection" {
                continue;
            }
            out.push_str(name);
            out.push_str(": ");
            out.push_str(value);
            out.push_str("\r\n");
        }
        out.push_str("\r\n");
        out.into_bytes()
    }
}

/// How a message body is delimited.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    /// No body (or zero-length).
    None,
    /// Exactly N bytes.
    Length(u64),
    /// Chunked transfer-encoding.
    Chunked,
    /// Body runs until the connection closes.
    UntilClose,
}

/// Stream a request/response body from `src` to `dst` according to `framing`.
/// Bytes already buffered in `src` are flushed first.
pub async fn relay_body<R, W>(
    src: &mut Conn<R>,
    dst: &mut W,
    framing: Framing,
) -> std::io::Result<()>
where
    R: AsyncRead + AsyncWrite + Unpin,
    W: AsyncWrite + Unpin,
{
    match framing {
        Framing::None => Ok(()),
        Framing::Length(n) => relay_length(src, dst, n).await,
        Framing::Chunked => relay_chunked(src, dst).await,
        Framing::UntilClose => relay_until_close(src, dst).await,
    }
}

async fn relay_length<R, W>(src: &mut Conn<R>, dst: &mut W, mut remaining: u64) -> std::io::Result<()>
where
    R: AsyncRead + AsyncWrite + Unpin,
    W: AsyncWrite + Unpin,
{
    // Flush buffered bytes first.
    if !src.buf.is_empty() {
        let take = std::cmp::min(src.buf.len() as u64, remaining) as usize;
        let chunk = src.buf.split_to(take);
        dst.write_all(&chunk).await?;
        remaining -= take as u64;
    }
    let mut buf = vec![0u8; COPY_BUF];
    while remaining > 0 {
        let want = std::cmp::min(remaining, buf.len() as u64) as usize;
        let n = src.stream.read(&mut buf[..want]).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "eof before Content-Length satisfied",
            ));
        }
        dst.write_all(&buf[..n]).await?;
        remaining -= n as u64;
    }
    dst.flush().await
}

async fn relay_until_close<R, W>(src: &mut Conn<R>, dst: &mut W) -> std::io::Result<()>
where
    R: AsyncRead + AsyncWrite + Unpin,
    W: AsyncWrite + Unpin,
{
    if !src.buf.is_empty() {
        let chunk = src.buf.split();
        dst.write_all(&chunk).await?;
    }
    let mut buf = vec![0u8; COPY_BUF];
    loop {
        let n = src.stream.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        dst.write_all(&buf[..n]).await?;
    }
    dst.flush().await
}

/// Relay a chunked body. We parse just enough to find the terminating 0-chunk,
/// forwarding bytes verbatim (including chunk framing and trailers).
async fn relay_chunked<R, W>(src: &mut Conn<R>, dst: &mut W) -> std::io::Result<()>
where
    R: AsyncRead + AsyncWrite + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        // Read a chunk-size line.
        let line = read_line(src).await?;
        dst.write_all(&line).await?;
        let size_str = std::str::from_utf8(&line)
            .map_err(|_| invalid("non-utf8 chunk size"))?
            .trim();
        // Chunk size may carry extensions after ';'.
        let size_hex = size_str.split(';').next().unwrap_or("").trim();
        let size = u64::from_str_radix(size_hex, 16).map_err(|_| invalid("bad chunk size"))?;

        if size == 0 {
            // Relay trailers until the final blank line.
            loop {
                let trailer = read_line(src).await?;
                dst.write_all(&trailer).await?;
                if trailer == b"\r\n" || trailer == b"\n" {
                    break;
                }
            }
            break;
        }

        // Relay `size` bytes plus the trailing CRLF.
        relay_exact(src, dst, size + 2).await?;
    }
    dst.flush().await
}

/// Read a single line (through the next `\n`) from the buffered connection.
async fn read_line<R>(src: &mut Conn<R>) -> std::io::Result<Vec<u8>>
where
    R: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        if let Some(pos) = src.buf.iter().position(|&b| b == b'\n') {
            let line = src.buf.split_to(pos + 1);
            return Ok(line.to_vec());
        }
        if src.buf.len() > MAX_HEAD {
            return Err(invalid("chunk line too long"));
        }
        let n = src.stream.read_buf(&mut src.buf).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "eof in chunked body",
            ));
        }
    }
}

/// Relay exactly `count` bytes, pulling from the buffer first.
async fn relay_exact<R, W>(src: &mut Conn<R>, dst: &mut W, mut count: u64) -> std::io::Result<()>
where
    R: AsyncRead + AsyncWrite + Unpin,
    W: AsyncWrite + Unpin,
{
    if !src.buf.is_empty() {
        let take = std::cmp::min(src.buf.len() as u64, count) as usize;
        let chunk = src.buf.split_to(take);
        dst.write_all(&chunk).await?;
        count -= take as u64;
    }
    let mut buf = vec![0u8; COPY_BUF];
    while count > 0 {
        let want = std::cmp::min(count, buf.len() as u64) as usize;
        let n = src.stream.read(&mut buf[..want]).await?;
        if n == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "eof mid-chunk",
            ));
        }
        dst.write_all(&buf[..n]).await?;
        count -= n as u64;
    }
    Ok(())
}

fn invalid(msg: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg)
}

/// Compute the response body framing, accounting for status codes and the
/// request method that have no body regardless of headers.
pub fn response_framing(resp: &Head, request_method: &str) -> Framing {
    let status = resp.status_code().unwrap_or(0);
    let no_body = request_method.eq_ignore_ascii_case("HEAD")
        || status == 204
        || status == 304
        || (100..200).contains(&status);
    if no_body {
        return Framing::None;
    }
    match resp.body_framing() {
        Framing::None => {
            // No explicit length and a body is permitted: read until close.
            Framing::UntilClose
        }
        other => other,
    }
}
