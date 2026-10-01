//! Proxy engines and the helpers they share.

pub mod forward;
pub mod mitm;
pub mod transparent;

use std::pin::Pin;
use std::task::{Context as TaskContext, Poll};

use bytes::BytesMut;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// 200 response that completes a CONNECT tunnel.
pub const CONN_ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";

/// Build a 403 response for a denied request.
pub fn forbidden_response(host: &str) -> Vec<u8> {
    let body = format!(
        "<html><head><title>403 Forbidden</title></head><body>\
         <h1>403 Forbidden</h1><p>Access to <b>{host}</b> is blocked by policy.</p>\
         </body></html>"
    );
    format!(
        "HTTP/1.1 403 Forbidden\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: keep-alive\r\n\
         \r\n{}",
        body.len(),
        body
    )
    .into_bytes()
}

/// 502 for upstream connection failures.
pub fn bad_gateway() -> Vec<u8> {
    let body = "<html><body><h1>502 Bad Gateway</h1></body></html>";
    format!(
        "HTTP/1.1 502 Bad Gateway\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n{}",
        body.len(),
        body
    )
    .into_bytes()
}

/// A stream that first replays a buffered prefix, then delegates to the inner
/// stream. Used to feed already-read bytes (e.g. a partial TLS ClientHello) into
/// a TLS acceptor transparently.
pub struct PrefixedStream<S> {
    prefix: BytesMut,
    inner: S,
}

impl<S> PrefixedStream<S> {
    pub fn new(prefix: BytesMut, inner: S) -> Self {
        PrefixedStream { prefix, inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if !self.prefix.is_empty() {
            let n = std::cmp::min(self.prefix.len(), buf.remaining());
            let chunk = self.prefix.split_to(n);
            buf.put_slice(&chunk);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Split a `host:port` authority, falling back to `default_port`.
pub fn split_host_port(authority: &str, default_port: u16) -> (String, u16) {
    let authority = authority.trim();
    if let Some(rest) = authority.strip_prefix('[') {
        // IPv6 literal: [addr]:port
        if let Some((inner, after)) = rest.split_once(']') {
            let port = after
                .strip_prefix(':')
                .and_then(|p| p.parse().ok())
                .unwrap_or(default_port);
            return (inner.to_string(), port);
        }
    }
    match authority.rsplit_once(':') {
        Some((h, p)) => {
            let port = p.parse().unwrap_or(default_port);
            (h.to_string(), port)
        }
        None => (authority.to_string(), default_port),
    }
}

/// Given an absolute-form request target (`http://host[:port]/path`), return the
/// authority and the origin-form path.
pub fn parse_absolute_uri(target: &str) -> Option<(String, String)> {
    let rest = target
        .strip_prefix("http://")
        .or_else(|| target.strip_prefix("https://"))?;
    match rest.find('/') {
        Some(idx) => Some((rest[..idx].to_string(), rest[idx..].to_string())),
        None => Some((rest.to_string(), "/".to_string())),
    }
}
