/// PhantomScan Rust TLS Inspector
///
/// Reads a JSON request from stdin, connects to the target over TLS using rustls,
/// performs real certificate inspection with x509-parser, grades the connection,
/// and emits a JSON response to stdout conforming to the phantomscan.engine.v1 schema.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use serde::{Deserialize, Serialize};
use x509_parser::prelude::*;

// ── Schema types ──────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct Request {
    target: String,
    #[serde(default = "default_timeout")]
    timeout_seconds: u64,
}

fn default_timeout() -> u64 { 10 }

#[derive(Serialize)]
struct Observation {
    name: String,
    value: serde_json::Value,
    source: String,
}

#[derive(Serialize)]
struct Finding {
    id: String,
    title: String,
    severity: String,
    confidence: String,
    category: String,
    target: String,
    evidence: String,
    recommendation: String,
    references: Vec<String>,
}

#[derive(Serialize, Default)]
struct TlsDetails {
    host: String,
    port: u16,
    protocol: String,
    cipher: String,
    grade: String,
    cert_subject: String,
    cert_issuer: String,
    cert_sans: Vec<String>,
    cert_not_before: String,
    cert_not_after: String,
    days_remaining: i64,
    is_expired: bool,
    is_self_signed: bool,
    is_wildcard: bool,
}

#[derive(Serialize)]
struct Response {
    schema: String,
    engine: String,
    status: String,
    target: String,
    started_at: String,
    finished_at: String,
    findings: Vec<Finding>,
    observations: Vec<Observation>,
    warnings: Vec<String>,
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() {
    // Rustls 0.23 requires a process-level CryptoProvider to be installed
    let _ = rustls::crypto::ring::default_provider().install_default();

    let started = timestamp();

    let mut input = String::new();
    if let Err(e) = io::stdin().read_to_string(&mut input) {
        eprintln!("Failed to read stdin: {e}");
        std::process::exit(1);
    }

    let request: Request = match serde_json::from_str(&input) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Failed to parse request JSON: {e}");
            std::process::exit(1);
        }
    };

    let (details, mut findings, warnings) =
        inspect_tls(&request.target, 443, request.timeout_seconds);

    let tls_port_reachable = !details.protocol.is_empty();

    // Derive SSL grade observation value
    let grade = details.grade.clone();

    // ── Expiry findings ───────────────────────────────────────────────────────
    if details.is_expired {
        findings.push(Finding {
            id: "TLS-CERT-EXPIRED".to_string(),
            title: "TLS certificate is expired".to_string(),
            severity: "critical".to_string(),
            confidence: "high".to_string(),
            category: "ssl".to_string(),
            target: request.target.clone(),
            evidence: format!(
                "Certificate expired {} days ago. Not-After: {}",
                details.days_remaining.abs(),
                details.cert_not_after
            ),
            recommendation: "Renew and deploy a valid TLS certificate immediately.".to_string(),
            references: vec!["https://letsencrypt.org/".to_string()],
        });
    } else if details.days_remaining > 0 && details.days_remaining < 30 {
        findings.push(Finding {
            id: "TLS-CERT-EXPIRING-SOON".to_string(),
            title: "TLS certificate expires within 30 days".to_string(),
            severity: "high".to_string(),
            confidence: "high".to_string(),
            category: "ssl".to_string(),
            target: request.target.clone(),
            evidence: format!(
                "Certificate expires in {} days. Not-After: {}",
                details.days_remaining, details.cert_not_after
            ),
            recommendation: "Renew the TLS certificate before it expires.".to_string(),
            references: vec![],
        });
    }

    // ── Self-signed finding ───────────────────────────────────────────────────
    if details.is_self_signed {
        findings.push(Finding {
            id: "TLS-CERT-SELF-SIGNED".to_string(),
            title: "TLS certificate is self-signed".to_string(),
            severity: "high".to_string(),
            confidence: "high".to_string(),
            category: "ssl".to_string(),
            target: request.target.clone(),
            evidence: format!(
                "Certificate issuer matches subject: {}",
                details.cert_subject
            ),
            recommendation: "Replace the self-signed certificate with one issued by a trusted CA.".to_string(),
            references: vec![],
        });
    }

    let observations = vec![
        Observation {
            name: "tls_port_reachable".to_string(),
            value: serde_json::Value::Bool(tls_port_reachable),
            source: "rust-tls".to_string(),
        },
        Observation {
            name: "ssl_grade".to_string(),
            value: serde_json::Value::String(grade),
            source: "rust-tls".to_string(),
        },
        Observation {
            name: "tls_inspection".to_string(),
            value: serde_json::to_value(&details).unwrap_or(serde_json::Value::Null),
            source: "rust-tls".to_string(),
        },
    ];

    let status = if tls_port_reachable { "ok" } else { "partial" };

    let response = Response {
        schema: "phantomscan.engine.v1".to_string(),
        engine: "rust-tls".to_string(),
        status: status.to_string(),
        target: request.target.clone(),
        started_at: started,
        finished_at: timestamp(),
        findings,
        observations,
        warnings,
    };

    match serde_json::to_string(&response) {
        Ok(json) => {
            println!("{json}");
        }
        Err(e) => {
            eprintln!("Failed to serialise response: {e}");
            std::process::exit(1);
        }
    }
}

// ── TLS inspection ────────────────────────────────────────────────────────────

fn inspect_tls(
    host: &str,
    port: u16,
    timeout_secs: u64,
) -> (TlsDetails, Vec<Finding>, Vec<String>) {
    let mut details = TlsDetails {
        host: host.to_string(),
        port,
        ..Default::default()
    };
    let findings: Vec<Finding> = vec![];
    let mut warnings: Vec<String> = vec![];

    // Build rustls client config with system/public root certificates
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let server_name = match ServerName::try_from(host.to_string()) {
        Ok(n) => n,
        Err(e) => {
            warnings.push(format!("Invalid server name '{host}': {e}"));
            return (details, findings, warnings);
        }
    };

    // TCP connect with timeout
    let timeout = Duration::from_secs(timeout_secs);
    let addr = format!("{host}:{port}");
    let tcp = match connect_with_timeout(&addr, timeout) {
        Ok(s) => s,
        Err(e) => {
            warnings.push(format!("TCP connect to {addr} failed: {e}"));
            return (details, findings, warnings);
        }
    };

    if let Err(e) = tcp.set_read_timeout(Some(timeout)) {
        warnings.push(format!("set_read_timeout failed: {e}"));
    }
    if let Err(e) = tcp.set_write_timeout(Some(timeout)) {
        warnings.push(format!("set_write_timeout failed: {e}"));
    }

    let mut conn = match ClientConnection::new(Arc::new(config), server_name) {
        Ok(c) => c,
        Err(e) => {
            warnings.push(format!("rustls ClientConnection::new failed: {e}"));
            return (details, findings, warnings);
        }
    };

    let mut tcp_clone = tcp;
    let mut stream = rustls::Stream::new(&mut conn, &mut tcp_clone);

    // Trigger the TLS handshake by sending a minimal HTTP request
    if let Err(e) = stream.write_all(b"HEAD / HTTP/1.0\r\nHost: phantom\r\n\r\n") {
        // Handshake may still complete even if write fails
        warnings.push(format!("TLS write probe failed (handshake may still be complete): {e}"));
    }
    // Read enough to flush the response (ignore errors — we care about the handshake)
    let mut buf = [0u8; 4096];
    let _ = stream.read(&mut buf);

    // ── Protocol version ──────────────────────────────────────────────────────
    let proto = match conn.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_3) => "TLSv1.3",
        Some(rustls::ProtocolVersion::TLSv1_2) => "TLSv1.2",
        _ => "Unknown",
    };
    details.protocol = proto.to_string();

    // ── Cipher suite ──────────────────────────────────────────────────────────
    if let Some(suite) = conn.negotiated_cipher_suite() {
        details.cipher = format!("{:?}", suite.suite());
    }

    // ── Certificate inspection ────────────────────────────────────────────────
    if let Some(certs) = conn.peer_certificates() {
        if let Some(leaf) = certs.first() {
            match X509Certificate::from_der(leaf.as_ref()) {
                Ok((_, x509)) => {
                    details.cert_subject = x509.subject().to_string();
                    details.cert_issuer  = x509.issuer().to_string();

                    // Validity window
                    let not_before = x509.validity().not_before.timestamp();
                    let not_after  = x509.validity().not_after.timestamp();
                    details.cert_not_before = format_ts(not_before);
                    details.cert_not_after  = format_ts(not_after);

                    let now = now_unix();
                    details.days_remaining = (not_after - now) / 86_400;
                    details.is_expired     = now > not_after;
                    details.is_self_signed = details.cert_subject == details.cert_issuer;
                    details.is_wildcard    = details.cert_subject.contains("*.");

                    // Subject Alternative Names
                    if let Ok(Some(san_ext)) = x509.subject_alternative_name() {
                        for gn in san_ext.value.general_names.iter() {
                            let s = match gn {
                                GeneralName::DNSName(n)  => n.to_string(),
                                GeneralName::IPAddress(b) => {
                                    b.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(".")
                                }
                                _ => continue,
                            };
                            details.cert_sans.push(s.clone());
                            if s.starts_with("*.") {
                                details.is_wildcard = true;
                            }
                        }
                    }
                }
                Err(e) => {
                    warnings.push(format!("x509-parser failed to parse leaf cert: {e}"));
                }
            }
        }
    } else {
        warnings.push("No peer certificates received from server.".to_string());
    }

    // ── Grade calculation ─────────────────────────────────────────────────────
    details.grade = calculate_grade(proto, details.is_expired, details.is_self_signed);

    (details, findings, warnings)
}

fn calculate_grade(proto: &str, expired: bool, self_signed: bool) -> String {
    if expired || self_signed {
        return "F".to_string();
    }
    match proto {
        "TLSv1.3" => "A+".to_string(),
        "TLSv1.2" => "B".to_string(),
        "TLSv1.1" => "C".to_string(),
        "TLSv1.0" => "D".to_string(),
        _ => "F".to_string(),
    }
}

// ── TCP helper ────────────────────────────────────────────────────────────────

fn connect_with_timeout(addr: &str, timeout: Duration) -> io::Result<TcpStream> {
    use std::net::ToSocketAddrs;
    let socket_addr = addr
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no addresses resolved"))?;
    TcpStream::connect_timeout(&socket_addr, timeout)
}

// ── Time utilities ────────────────────────────────────────────────────────────

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn timestamp() -> String {
    now_unix().to_string()
}

fn format_ts(unix: i64) -> String {
    // Simple ISO-8601-ish output without pulling in chrono
    // Unix epoch → approximate date string for evidence display
    if unix <= 0 {
        return "1970-01-01".to_string();
    }
    let secs = unix as u64;
    let days_since_epoch = secs / 86_400;
    // Approximate year (not perfect but good enough for display)
    let year = 1970 + days_since_epoch / 365;
    format!("~{year} (unix: {unix})")
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grade_expired_is_f() {
        assert_eq!(calculate_grade("TLSv1.3", true, false), "F");
    }

    #[test]
    fn grade_self_signed_is_f() {
        assert_eq!(calculate_grade("TLSv1.3", false, true), "F");
    }

    #[test]
    fn grade_tls13_clean_is_aplus() {
        assert_eq!(calculate_grade("TLSv1.3", false, false), "A+");
    }

    #[test]
    fn grade_tls12_clean_is_b() {
        assert_eq!(calculate_grade("TLSv1.2", false, false), "B");
    }

    #[test]
    fn deserialises_request() {
        let json = r#"{"target":"example.com","timeout_seconds":5}"#;
        let req: Request = serde_json::from_str(json).unwrap();
        assert_eq!(req.target, "example.com");
        assert_eq!(req.timeout_seconds, 5);
    }

    #[test]
    fn now_unix_is_positive() {
        assert!(now_unix() > 0);
    }
}
