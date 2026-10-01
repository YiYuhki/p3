//! Man-in-the-middle proxy.
//!
//! Operates like a forward proxy for the handshake: the client issues
//! `CONNECT host:port`, we answer `200`, then — instead of blind-tunneling — we
//! terminate TLS using a certificate minted by our local CA, open our own TLS
//! connection to the real upstream, and relay decrypted HTTP in between. This
//! lets policy see full request URLs. Plain-HTTP requests are handled exactly as
//! in forward mode.

use std::net::IpAddr;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tracing::{debug, info, warn};

use crate::http1::{relay_body, response_framing, Conn, Head};
use crate::policy::{normalize_host, Decision};
use crate::proxy::forward::handle_plain;
use crate::proxy::{bad_gateway, forbidden_response, split_host_port, PrefixedStream, CONN_ESTABLISHED};
use crate::resolver::Engine;
use crate::tls::ca::CertAuthority;

pub async fn run(
    listener: TcpListener,
    engine: Arc<Engine>,
    ca: Arc<CertAuthority>,
    client_config: Arc<ClientConfig>,
) -> Result<()> {
    info!("MITM proxy listening on {}", listener.local_addr()?);
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!("accept error: {e}");
                continue;
            }
        };
        let engine = engine.clone();
        let ca = ca.clone();
        let client_config = client_config.clone();
        tokio::spawn(async move {
            let _ = stream.set_nodelay(true);
            if let Err(e) = handle_conn(stream, peer.ip(), engine, ca, client_config).await {
                debug!("MITM connection from {peer} ended: {e}");
            }
        });
    }
}

async fn handle_conn(
    stream: TcpStream,
    client_ip: IpAddr,
    engine: Arc<Engine>,
    ca: Arc<CertAuthority>,
    client_config: Arc<ClientConfig>,
) -> Result<()> {
    let mut cconn = Conn::new(stream);
    loop {
        let head_bytes = match cconn.read_head().await? {
            Some(h) => h,
            None => return Ok(()),
        };
        let head = match Head::parse(&head_bytes) {
            Some(h) => h,
            None => return Ok(()),
        };

        if head.method().eq_ignore_ascii_case("CONNECT") {
            // MITM the TLS session; this consumes the connection.
            return mitm_connect(cconn, head, client_ip, &engine, &ca, &client_config).await;
        }

        // Plain HTTP: identical handling to forward mode.
        let keep_alive = handle_plain(&mut cconn, head, client_ip, &engine).await?;
        if !keep_alive {
            return Ok(());
        }
    }
}

async fn mitm_connect(
    mut cconn: Conn<TcpStream>,
    head: Head,
    client_ip: IpAddr,
    engine: &Engine,
    ca: &CertAuthority,
    client_config: &Arc<ClientConfig>,
) -> Result<()> {
    let (host, port) = split_host_port(head.target(), 443);

    // First-pass policy check on the CONNECT host.
    let verdict = engine.evaluate(client_ip, &host);
    if verdict.decision == Decision::Deny {
        info!("DENY  {client_ip} CONNECT {host} (level={})", verdict.level);
        cconn.stream.write_all(&forbidden_response(&host)).await?;
        return Ok(());
    }

    // Mint / fetch a leaf certificate for this host.
    let server_config = match ca.server_config(&host) {
        Ok(c) => c,
        Err(e) => {
            warn!("cert generation for {host} failed: {e}");
            cconn.stream.write_all(&bad_gateway()).await?;
            return Ok(());
        }
    };

    cconn.stream.write_all(CONN_ESTABLISHED).await?;

    // Hand the raw socket (plus any buffered bytes) to the TLS acceptor.
    let Conn { stream, buf } = cconn;
    let client_side = PrefixedStream::new(buf, stream);
    let acceptor = TlsAcceptor::from(server_config);
    let client_tls = match acceptor.accept(client_side).await {
        Ok(t) => t,
        Err(e) => {
            debug!("client TLS handshake with {host} failed: {e}");
            return Ok(());
        }
    };

    // Open the real upstream TLS connection.
    let upstream_tcp = match TcpStream::connect((host.as_str(), port)).await {
        Ok(s) => s,
        Err(e) => {
            warn!("MITM upstream connect {host}:{port} failed: {e}");
            return Ok(());
        }
    };
    let _ = upstream_tcp.set_nodelay(true);
    let connector = TlsConnector::from(client_config.clone());
    let server_name = ServerName::try_from(host.clone())
        .map_err(|_| anyhow!("invalid upstream server name {host}"))?;
    let upstream_tls = match connector.connect(server_name, upstream_tcp).await {
        Ok(t) => t,
        Err(e) => {
            warn!("MITM upstream TLS handshake {host} failed: {e}");
            return Ok(());
        }
    };

    relay_decrypted(client_tls, upstream_tls, client_ip, &host, engine).await
}

/// Relay decrypted HTTP requests/responses between the client and upstream TLS
/// sessions, applying per-request policy (now with full visibility of the path).
async fn relay_decrypted<C, U>(
    client_tls: C,
    upstream_tls: U,
    client_ip: IpAddr,
    connect_host: &str,
    engine: &Engine,
) -> Result<()>
where
    C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut cc = Conn::new(client_tls);
    let mut uc = Conn::new(upstream_tls);

    loop {
        let req_bytes = match cc.read_head().await? {
            Some(h) => h,
            None => return Ok(()),
        };
        let req = match Head::parse(&req_bytes) {
            Some(h) => h,
            None => return Ok(()),
        };
        let method = req.method().to_string();

        // Re-evaluate using the real request Host (defends against domain fronting).
        let req_host = req
            .header("host")
            .map(normalize_host)
            .unwrap_or_else(|| connect_host.to_string());
        let verdict = engine.evaluate(client_ip, &req_host);
        let url = format!("https://{}{}", req_host, req.target());
        match verdict.decision {
            Decision::Allow => debug!("ALLOW {client_ip} {method} {url} (level={})", verdict.level),
            Decision::Deny => info!("DENY  {client_ip} {method} {url} (level={})", verdict.level),
        }

        if verdict.decision == Decision::Deny {
            cc.stream.write_all(&forbidden_response(&req_host)).await?;
            relay_body(&mut cc, &mut tokio::io::sink(), req.body_framing()).await?;
            if req.connection_close() {
                return Ok(());
            }
            continue;
        }

        // Forward the (origin-form) request upstream.
        let out_head = req.serialize(None);
        uc.stream.write_all(&out_head).await?;
        relay_body(&mut cc, &mut uc.stream, req.body_framing()).await?;

        // Relay the response back to the client.
        let resp_bytes = match uc.read_head().await? {
            Some(h) => h,
            None => {
                cc.stream.write_all(&bad_gateway()).await?;
                return Ok(());
            }
        };
        let resp = match Head::parse(&resp_bytes) {
            Some(h) => h,
            None => return Ok(()),
        };
        cc.stream.write_all(&resp_bytes).await?;
        let rframing = response_framing(&resp, &method);
        relay_body(&mut uc, &mut cc.stream, rframing).await?;

        if req.connection_close()
            || resp.connection_close()
            || rframing == crate::http1::Framing::UntilClose
        {
            return Ok(());
        }
    }
}
