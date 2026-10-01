//! Explicit forward proxy: clients are configured to send requests here.
//!
//! * Plain HTTP arrives in absolute form (`GET http://host/path`); we filter by
//!   host, rewrite to origin form, and relay.
//! * HTTPS arrives as `CONNECT host:port`; we filter by the target host and, if
//!   allowed, open a raw TCP tunnel (no decryption).

use std::net::IpAddr;
use std::sync::Arc;

use anyhow::Result;
use tokio::io::{copy_bidirectional, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

use crate::http1::{relay_body, response_framing, Conn, Head};
use crate::policy::Decision;
use crate::proxy::{
    bad_gateway, forbidden_response, parse_absolute_uri, split_host_port, CONN_ESTABLISHED,
};
use crate::resolver::Engine;

pub async fn run(listener: TcpListener, engine: Arc<Engine>) -> Result<()> {
    info!("forward proxy listening on {}", listener.local_addr()?);
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
            if let Err(e) = handle_conn(stream, peer.ip(), engine).await {
                debug!("connection from {peer} ended: {e}");
            }
        });
    }
}

async fn handle_conn(stream: TcpStream, client_ip: IpAddr, engine: Arc<Engine>) -> Result<()> {
    let mut cconn = Conn::new(stream);
    loop {
        let head_bytes = match cconn.read_head().await? {
            Some(h) => h,
            None => return Ok(()), // clean EOF
        };
        let head = match Head::parse(&head_bytes) {
            Some(h) => h,
            None => return Ok(()),
        };

        if head.method().eq_ignore_ascii_case("CONNECT") {
            // Tunnel consumes the connection.
            return handle_connect(cconn, head, client_ip, &engine).await;
        }

        let keep_alive = handle_plain(&mut cconn, head, client_ip, &engine).await?;
        if !keep_alive {
            return Ok(());
        }
    }
}

/// Handle one plain-HTTP request. Returns whether the connection may be reused.
pub(crate) async fn handle_plain<S>(
    cconn: &mut Conn<S>,
    head: Head,
    client_ip: IpAddr,
    engine: &Engine,
) -> Result<bool>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let method = head.method().to_string();
    let target = head.target().to_string();

    // Determine authority + origin-form path.
    let (authority, path) = match parse_absolute_uri(&target) {
        Some((a, p)) => (a, p),
        None => {
            // Origin-form target (e.g. a transparent/MITM request): use Host header.
            match head.header("host") {
                Some(h) => (h.to_string(), target.clone()),
                None => {
                    let _ = cconn.stream.write_all(&forbidden_response("unknown")).await;
                    return Ok(false);
                }
            }
        }
    };
    let (host, port) = split_host_port(&authority, 80);

    let verdict = engine.evaluate(client_ip, &host);
    log_decision(client_ip, &host, &method, &verdict);

    if verdict.decision == Decision::Deny {
        cconn
            .stream
            .write_all(&forbidden_response(&host))
            .await?;
        // Drain the request body so the connection stays in sync.
        let framing = head.body_framing();
        relay_body(cconn, &mut tokio::io::sink(), framing).await?;
        return Ok(!head.connection_close());
    }

    // Connect upstream.
    let upstream = match TcpStream::connect((host.as_str(), port)).await {
        Ok(s) => s,
        Err(e) => {
            warn!("upstream connect to {host}:{port} failed: {e}");
            cconn.stream.write_all(&bad_gateway()).await?;
            return Ok(false);
        }
    };
    let _ = upstream.set_nodelay(true);
    let mut uconn = Conn::new(upstream);

    // Rewrite request line to origin form and relay the request.
    let new_line = format!(
        "{} {} {}",
        method,
        path,
        head.first_line.rsplit(' ').next().unwrap_or("HTTP/1.1")
    );
    let out_head = head.serialize(Some(&new_line));
    uconn.stream.write_all(&out_head).await?;
    relay_body(cconn, &mut uconn.stream, head.body_framing()).await?;

    // Relay the response back.
    let resp_bytes = match uconn.read_head().await? {
        Some(h) => h,
        None => {
            cconn.stream.write_all(&bad_gateway()).await?;
            return Ok(false);
        }
    };
    let resp = match Head::parse(&resp_bytes) {
        Some(h) => h,
        None => return Ok(false),
    };
    cconn.stream.write_all(&resp_bytes).await?;
    let rframing = response_framing(&resp, &method);
    relay_body(&mut uconn, &mut cconn.stream, rframing).await?;

    let keep = !head.connection_close()
        && !resp.connection_close()
        && rframing != crate::http1::Framing::UntilClose;
    Ok(keep)
}

/// Handle a CONNECT request by tunneling raw bytes after a policy check.
pub(crate) async fn handle_connect<S>(
    mut cconn: Conn<S>,
    head: Head,
    client_ip: IpAddr,
    engine: &Engine,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let (host, port) = split_host_port(head.target(), 443);
    let verdict = engine.evaluate(client_ip, &host);
    log_decision(client_ip, &host, "CONNECT", &verdict);

    if verdict.decision == Decision::Deny {
        cconn.stream.write_all(&forbidden_response(&host)).await?;
        return Ok(());
    }

    let mut upstream = match TcpStream::connect((host.as_str(), port)).await {
        Ok(s) => s,
        Err(e) => {
            warn!("CONNECT upstream {host}:{port} failed: {e}");
            cconn.stream.write_all(&bad_gateway()).await?;
            return Ok(());
        }
    };
    let _ = upstream.set_nodelay(true);

    cconn.stream.write_all(CONN_ESTABLISHED).await?;
    // Flush any bytes the client already sent after CONNECT.
    if !cconn.buf.is_empty() {
        upstream.write_all(&cconn.buf).await?;
        cconn.buf.clear();
    }

    copy_bidirectional(&mut cconn.stream, &mut upstream).await?;
    Ok(())
}

fn log_decision(client_ip: IpAddr, host: &str, method: &str, verdict: &crate::resolver::Verdict) {
    let dept = verdict.department.as_deref().unwrap_or("-");
    match verdict.decision {
        Decision::Allow => debug!(
            "ALLOW {client_ip} {method} {host} (level={} dept={dept})",
            verdict.level
        ),
        Decision::Deny => info!(
            "DENY  {client_ip} {method} {host} (level={} dept={dept})",
            verdict.level
        ),
    }
}
