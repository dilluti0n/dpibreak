// SPDX-License-Identifier: GPL-3.0-or-later

//! HTTPS reachability probe with a Rust TLS client (no curl needed).
//!
//! The ClientHello leaves through the same netfilter OUTPUT hook as a
//! browser's, so a completed handshake means the bypass works for that
//! host. How the attempt fails tells apart the usual kinds of block.

use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::{Arc, OnceLock, mpsc};
use std::time::{Duration, Instant};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore};

use crate::probe::Outcome;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

fn tls_config() -> Arc<ClientConfig> {
    static CONFIG: OnceLock<Arc<ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let roots = RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            let mut cfg = ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .expect("default TLS versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
            cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
            Arc::new(cfg)
        })
        .clone()
}

struct Target {
    tls: bool,
    host: String,
    port: u16,
    path: String,
}

fn parse_url(url: &str) -> Option<Target> {
    let url = url.trim();
    let (tls, rest) = if let Some(r) = url.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = url.strip_prefix("http://") {
        (false, r)
    } else {
        (true, url)
    };
    let (authority, path) = match rest.find(['/', '?', '#']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let authority = authority.rsplit('@').next()?;
    let default_port = if tls { 443 } else { 80 };
    let (host, port) = if let Some(v6) = authority.strip_prefix('[') {
        let (h, after) = v6.split_once(']')?;
        let port = match after.strip_prefix(':') {
            Some(p) => p.parse().ok()?,
            None => default_port,
        };
        (h.to_string(), port)
    } else {
        match authority.rsplit_once(':') {
            Some((h, p)) => (h.to_string(), p.parse().ok()?),
            None => (authority.to_string(), default_port),
        }
    };
    if host.is_empty() {
        return None;
    }
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    Some(Target {
        tls,
        host,
        port,
        path,
    })
}

/// Stage of the attempt an I/O error happened in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    Connect,
    Handshake,
}

/// Map an error to an outcome. TLS errors from rustls arrive wrapped in
/// an `io::Error` (kind `InvalidData`).
pub fn classify(stage: Stage, e: &io::Error) -> Outcome {
    use io::ErrorKind as K;

    if let Some(tls) = e.get_ref().and_then(|i| i.downcast_ref::<rustls::Error>()) {
        return match tls {
            // Wrong name, unknown issuer, expired...: the answer did not
            // come from the real site, typically a DNS block page.
            rustls::Error::InvalidCertificate(_) => Outcome::BadCert,
            _ => Outcome::TlsFailed,
        };
    }
    match (stage, e.kind()) {
        (_, K::TimedOut | K::WouldBlock) => Outcome::Timeout,
        (
            Stage::Connect,
            K::ConnectionRefused
            | K::HostUnreachable
            | K::NetworkUnreachable
            | K::AddrNotAvailable
            | K::ConnectionReset,
        ) => Outcome::Connect,
        (Stage::Handshake, K::ConnectionReset) => Outcome::Reset,
        (Stage::Handshake, K::UnexpectedEof | K::ConnectionAborted | K::BrokenPipe) => {
            Outcome::TlsFailed
        }
        (Stage::Handshake, K::InvalidData) => Outcome::TlsFailed,
        _ => Outcome::Other(e.raw_os_error().unwrap_or(-2)),
    }
}

/// getaddrinfo cannot be given a timeout; run it on a thread.
fn resolve(host: &str, port: u16, within: Duration) -> Option<Vec<SocketAddr>> {
    let (tx, rx) = mpsc::channel();
    let host = host.to_string();
    std::thread::spawn(move || {
        _ = tx.send((host.as_str(), port).to_socket_addrs().map(Vec::from_iter));
    });
    match rx.recv_timeout(within) {
        Ok(Ok(addrs)) if !addrs.is_empty() => Some(addrs),
        _ => None,
    }
}

fn connect(addrs: &[SocketAddr], deadline: Instant) -> Result<TcpStream, io::Error> {
    let mut last = io::Error::new(io::ErrorKind::TimedOut, "no time left");
    for addr in addrs {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            break;
        }
        match TcpStream::connect_timeout(addr, left.min(CONNECT_TIMEOUT)) {
            Ok(s) => return Ok(s),
            Err(e) => last = e,
        }
    }
    Err(last)
}

fn set_timeouts(sock: &TcpStream, deadline: Instant) -> io::Result<()> {
    let left = deadline
        .saturating_duration_since(Instant::now())
        .max(Duration::from_millis(10));
    sock.set_read_timeout(Some(left))?;
    sock.set_write_timeout(Some(left))
}

/// Read the HTTP status code from the first bytes of a response.
fn read_status(stream: &mut impl Read) -> u16 {
    let mut buf = [0u8; 64];
    let mut got = 0;
    while got < buf.len() {
        match stream.read(&mut buf[got..]) {
            Ok(0) | Err(_) => break,
            Ok(n) => got += n,
        }
        if buf[..got].contains(&b'\n') {
            break;
        }
    }
    let text = String::from_utf8_lossy(&buf[..got]);
    text.split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0)
}

fn request_text(t: &Target) -> String {
    format!(
        "HEAD {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: DPIBreak-Panel\r\nAccept: */*\r\n\
         Connection: close\r\n\r\n",
        t.path, t.host
    )
}

pub fn probe(url: &str, max_secs: u32) -> Outcome {
    let start = Instant::now();
    let deadline = start + Duration::from_secs(u64::from(max_secs.max(1)));
    let Some(t) = parse_url(url) else {
        return Outcome::Other(-1);
    };

    let Some(addrs) = resolve(&t.host, t.port, deadline.saturating_duration_since(start)) else {
        return Outcome::Dns;
    };
    let mut sock = match connect(&addrs, deadline) {
        Ok(s) => s,
        Err(e) => return classify(Stage::Connect, &e),
    };
    if let Err(e) = set_timeouts(&sock, deadline) {
        return classify(Stage::Connect, &e);
    }

    if !t.tls {
        let secs = start.elapsed().as_secs_f32();
        if sock.write_all(request_text(&t).as_bytes()).is_err() {
            return Outcome::Ok { http: 0, secs };
        }
        return Outcome::Ok {
            http: read_status(&mut sock),
            secs,
        };
    }

    let Ok(name) = ServerName::try_from(t.host.clone()) else {
        return Outcome::Other(-1);
    };
    let mut conn = match ClientConnection::new(tls_config(), name) {
        Ok(c) => c,
        Err(_) => return Outcome::Other(-1),
    };
    while conn.is_handshaking() {
        if let Err(e) = conn.complete_io(&mut sock) {
            return classify(Stage::Handshake, &e);
        }
    }
    // Like curl's time_appconnect: name lookup, connect and handshake.
    let secs = start.elapsed().as_secs_f32();

    // Any HTTP answer counts; the status is informational.
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);
    let http = if tls.write_all(request_text(&t).as_bytes()).is_ok() {
        read_status(&mut tls)
    } else {
        0
    };
    Outcome::Ok { http, secs }
}

#[cfg(test)]
mod tests {
    use super::*;
    use io::ErrorKind as K;
    use std::net::TcpListener;

    fn io_err(kind: K) -> io::Error {
        io::Error::new(kind, "test")
    }

    fn tls_err(e: rustls::Error) -> io::Error {
        io::Error::new(K::InvalidData, e)
    }

    #[test]
    fn mapping() {
        use rustls::{AlertDescription, CertificateError};
        let c = |s, e: &io::Error| classify(s, e).short();
        assert_eq!(
            c(Stage::Connect, &io_err(K::ConnectionRefused)),
            "no connect"
        );
        assert_eq!(c(Stage::Connect, &io_err(K::HostUnreachable)), "no connect");
        assert_eq!(
            c(Stage::Connect, &io_err(K::NetworkUnreachable)),
            "no connect"
        );
        assert_eq!(c(Stage::Connect, &io_err(K::TimedOut)), "timeout");
        assert_eq!(c(Stage::Handshake, &io_err(K::TimedOut)), "timeout");
        assert_eq!(c(Stage::Handshake, &io_err(K::WouldBlock)), "timeout");
        assert_eq!(c(Stage::Handshake, &io_err(K::ConnectionReset)), "reset");
        assert_eq!(c(Stage::Handshake, &io_err(K::UnexpectedEof)), "TLS fail");
        assert_eq!(
            c(
                Stage::Handshake,
                &tls_err(rustls::Error::InvalidCertificate(
                    CertificateError::NotValidForName
                ))
            ),
            "bad cert"
        );
        assert_eq!(
            c(
                Stage::Handshake,
                &tls_err(rustls::Error::InvalidCertificate(
                    CertificateError::UnknownIssuer
                ))
            ),
            "bad cert"
        );
        assert_eq!(
            c(
                Stage::Handshake,
                &tls_err(rustls::Error::AlertReceived(
                    AlertDescription::HandshakeFailure
                ))
            ),
            "TLS fail"
        );
    }

    #[test]
    fn urls() {
        let t = parse_url("https://www.google.com").unwrap();
        assert!(t.tls);
        assert_eq!(
            (t.host.as_str(), t.port, t.path.as_str()),
            ("www.google.com", 443, "/")
        );
        let t = parse_url("http://example.org:8080/a?b").unwrap();
        assert!(!t.tls);
        assert_eq!(
            (t.host.as_str(), t.port, t.path.as_str()),
            ("example.org", 8080, "/a?b")
        );
        let t = parse_url("https://[::1]:8443/").unwrap();
        assert_eq!((t.host.as_str(), t.port), ("::1", 8443));
        assert!(parse_url("https://").is_none());
    }

    #[test]
    fn status_line() {
        assert_eq!(read_status(&mut &b"HTTP/1.1 301 Moved\r\n"[..]), 301);
        assert_eq!(read_status(&mut &b"garbage"[..]), 0);
    }

    // Local servers that misbehave like a DPI box would.

    fn local(handler: impl FnOnce(TcpStream) + Send + 'static) -> String {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = l.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((s, _)) = l.accept() {
                handler(s);
            }
        });
        format!("https://localhost:{port}/")
    }

    fn read_some(s: &mut TcpStream) {
        let mut b = [0u8; 512];
        _ = s.read(&mut b);
    }

    #[test]
    fn closed_port_is_connect() {
        let port = {
            let l = TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let o = probe(&format!("https://127.0.0.1:{port}/"), 3);
        assert!(matches!(o, Outcome::Connect), "{o:?}");
    }

    #[test]
    fn eof_after_hello_is_tls_cut() {
        let url = local(|mut s| read_some(&mut s));
        let o = probe(&url, 3);
        assert!(matches!(o, Outcome::TlsFailed), "{o:?}");
    }

    #[test]
    fn rst_after_hello_is_reset() {
        let url = local(|mut s| {
            read_some(&mut s);
            // SO_LINGER 0: close sends RST.
            let fd = std::os::fd::AsRawFd::as_raw_fd(&s);
            let l = libc::linger {
                l_onoff: 1,
                l_linger: 0,
            };
            // SAFETY: valid socket and correctly sized option.
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_LINGER,
                    (&raw const l).cast(),
                    size_of::<libc::linger>() as libc::socklen_t,
                );
            }
        });
        let o = probe(&url, 3);
        assert!(matches!(o, Outcome::Reset), "{o:?}");
    }

    #[test]
    fn silence_is_timeout() {
        let url = local(|mut s| {
            read_some(&mut s);
            std::thread::sleep(Duration::from_secs(4));
        });
        let o = probe(&url, 1);
        assert!(matches!(o, Outcome::Timeout), "{o:?}");
    }

    #[test]
    fn garbage_reply_is_tls_fail() {
        let url = local(|mut s| {
            read_some(&mut s);
            _ = s.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n");
            std::thread::sleep(Duration::from_millis(300));
        });
        let o = probe(&url, 3);
        assert!(matches!(o, Outcome::TlsFailed), "{o:?}");
    }

    /// Needs the internet: `cargo test -p dpibreak-gui -- --ignored`.
    #[test]
    #[ignore]
    fn live() {
        let ok = probe("https://www.google.com", 8);
        assert!(ok.works(), "{ok:?}");
        let o = probe("https://wrong.host.badssl.com/", 8);
        assert!(matches!(o, Outcome::BadCert), "{o:?}");
        let o = probe("https://expired.badssl.com/", 8);
        assert!(matches!(o, Outcome::BadCert), "{o:?}");
        let o = probe("https://nonexistent.invalid/", 8);
        assert!(matches!(o, Outcome::Dns), "{o:?}");
    }
}
