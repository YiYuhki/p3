//! Transparent interception proxy.
//!
//! Traffic is redirected here by the firewall (e.g. iptables REDIRECT). The
//! client is unaware of the proxy, so we recover the intended destination from
//! `SO_ORIGINAL_DST` and the host name from the TLS SNI (port 443) or the HTTP
//! `Host` header (port 80). No decryption occurs — allowed flows are tunneled.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use anyhow::{anyhow, Result};
use bytes::BytesMut;
use tokio::io::{copy_bidirectional, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

use crate::http1::Head;
use crate::policy::Decision;
use crate::proxy::forbidden_response;
use crate::resolver::Engine;
use crate::tls::sni::{parse_sni, SniResult};

const PEEK_LIMIT: usize = 16 * 1024;

pub async fn run(listener: TcpListener, engine: Arc<Engine>) -> Result<()> {
    info!("transparent proxy listening on {}", listener.local_addr()?);
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!("accept error: {e}");
                continue;
            }
        };
        let engine = engine.clone();
        tokio::spawn(async move {
            let _ = stream.set_nodelay(true);
            if let Err(e) = handle(stream, peer.ip(), engine).await {
                debug!("transparent connection from {peer} ended: {e}");
            }
        });
    }
}

async fn handle(mut client: TcpStream, client_ip: IpAddr, engine: Arc<Engine>) -> Result<()> {
    let orig = original_dst(&client)?;

    // Peek the opening bytes to learn the host name (without consuming them).
    let mut buf = BytesMut::with_capacity(4096);
    let host = detect_host(&mut client, &mut buf).await?;

    let host_for_policy = host.as_deref().unwrap_or("");
    let verdict = engine.evaluate(client_ip, host_for_policy);
    let host_disp = host.as_deref().unwrap_or("<unknown>");
    match verdict.decision {
        Decision::Allow => debug!(
            "ALLOW {client_ip} -> {orig} host={host_disp} (level={})",
            verdict.level
        ),
        Decision::Deny => info!(
            "DENY  {client_ip} -> {orig} host={host_disp} (level={})",
            verdict.level
        ),
    }

    if verdict.decision == Decision::Deny {
        // For plain HTTP we can return a readable error; for TLS we just close.
        if orig.port() == 80 || buf.first() != Some(&0x16) {
            let _ = client.write_all(&forbidden_response(host_disp)).await;
        }
        return Ok(());
    }

    // Connect to the real destination and replay the peeked bytes.
    let mut upstream = TcpStream::connect(orig).await?;
    let _ = upstream.set_nodelay(true);
    if !buf.is_empty() {
        upstream.write_all(&buf).await?;
    }
    copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

/// Read bytes into `buf` (without consuming them from the logical stream) until
/// the host can be determined. Returns `None` if it cannot be found.
async fn detect_host(client: &mut TcpStream, buf: &mut BytesMut) -> Result<Option<String>> {
    loop {
        if !buf.is_empty() {
            if buf[0] == 0x16 {
                // Looks like TLS: try SNI.
                match parse_sni(buf) {
                    SniResult::Found(h) => return Ok(Some(h)),
                    SniResult::None => return Ok(None),
                    SniResult::NeedMore => {}
                }
            } else {
                // Assume HTTP: look for the end of the header block.
                if let Some(pos) = find_crlf_crlf(buf) {
                    let head = Head::parse(&buf[..pos + 4]);
                    let host = head.and_then(|h| h.header("host").map(|s| s.to_string()));
                    return Ok(host);
                }
            }
        }

        if buf.len() >= PEEK_LIMIT {
            return Ok(None);
        }
        let n = client.read_buf(buf).await?;
        if n == 0 {
            // Connection closed before we could learn the host.
            if buf.is_empty() {
                return Err(anyhow!("client closed before sending data"));
            }
            return Ok(None);
        }
    }
}

fn find_crlf_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

#[cfg(target_os = "linux")]
fn original_dst(sock: &TcpStream) -> Result<SocketAddr> {
    use std::os::fd::AsRawFd;

    const SO_ORIGINAL_DST: libc::c_int = 80;

    let fd = sock.as_raw_fd();
    let is_v6 = sock.local_addr().map(|a| a.is_ipv6()).unwrap_or(false);

    unsafe {
        let mut addr: libc::sockaddr_storage = std::mem::zeroed();
        let mut len = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
        let (level, optname) = if is_v6 {
            (libc::SOL_IPV6, SO_ORIGINAL_DST)
        } else {
            (libc::SOL_IP, SO_ORIGINAL_DST)
        };
        let ret = libc::getsockopt(
            fd,
            level,
            optname,
            &mut addr as *mut _ as *mut libc::c_void,
            &mut len,
        );
        if ret != 0 {
            return Err(anyhow!(
                "SO_ORIGINAL_DST failed (is traffic redirected via iptables?): {}",
                std::io::Error::last_os_error()
            ));
        }
        sockaddr_to_socketaddr(&addr)
    }
}

#[cfg(target_os = "linux")]
fn sockaddr_to_socketaddr(storage: &libc::sockaddr_storage) -> Result<SocketAddr> {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};

    match storage.ss_family as libc::c_int {
        libc::AF_INET => unsafe {
            let addr = &*(storage as *const _ as *const libc::sockaddr_in);
            let ip = Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr));
            let port = u16::from_be(addr.sin_port);
            Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)))
        },
        libc::AF_INET6 => unsafe {
            let addr = &*(storage as *const _ as *const libc::sockaddr_in6);
            let ip = Ipv6Addr::from(addr.sin6_addr.s6_addr);
            let port = u16::from_be(addr.sin6_port);
            Ok(SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0)))
        },
        other => Err(anyhow!("unexpected address family {other}")),
    }
}

#[cfg(not(target_os = "linux"))]
fn original_dst(_sock: &TcpStream) -> Result<SocketAddr> {
    Err(anyhow!("transparent mode is only supported on Linux"))
}
