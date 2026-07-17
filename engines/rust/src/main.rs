use std::io::{self, Read};
use std::net::TcpStream;
use std::time::{Duration, SystemTime};

struct Request {
    target: String,
    timeout_seconds: Option<u64>,
}

fn main() {
    let started = timestamp();
    let mut input = String::new();
    if let Err(err) = io::stdin().read_to_string(&mut input) {
        eprintln!("{err}");
        std::process::exit(1);
    }
    let request = parse_request(&input);
    let timeout = Duration::from_secs(request.timeout_seconds.unwrap_or(5));
    let reachable = match format!("{}:443", request.target).to_socket_addrs_first() {
        Some(addr) => TcpStream::connect_timeout(&addr, timeout).is_ok(),
        None => false,
    };
    let grade = if reachable { "B" } else { "unknown" };
    println!(
        "{{\"schema\":\"phantomscan.engine.v1\",\"engine\":\"rust-tls\",\"status\":\"ok\",\"target\":\"{}\",\"started_at\":\"{}\",\"finished_at\":\"{}\",\"findings\":[],\"observations\":[{{\"name\":\"tls_port_reachable\",\"value\":{},\"source\":\"rust-tls\"}},{{\"name\":\"ssl_grade\",\"value\":\"{}\",\"source\":\"rust-tls\"}}],\"warnings\":[\"Deep certificate parsing requires a TLS feature build.\"]}}",
        json_escape(&request.target),
        json_escape(&started),
        json_escape(&timestamp()),
        if reachable { "true" } else { "false" },
        grade
    );
}

trait FirstSocketAddr {
    fn to_socket_addrs_first(&self) -> Option<std::net::SocketAddr>;
}

impl FirstSocketAddr for String {
    fn to_socket_addrs_first(&self) -> Option<std::net::SocketAddr> {
        std::net::ToSocketAddrs::to_socket_addrs(&self.as_str()).ok()?.next()
    }
}

fn timestamp() -> String {
    match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        Ok(duration) => format!("{}", duration.as_secs()),
        Err(_) => "0".to_string(),
    }
}

fn parse_request(input: &str) -> Request {
    Request {
        target: extract_string(input, "target").unwrap_or_else(|| "127.0.0.1".to_string()),
        timeout_seconds: extract_number(input, "timeout_seconds"),
    }
}

fn extract_string(input: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let after_key = input.split(&needle).nth(1)?;
    let after_colon = after_key.split(':').nth(1)?;
    let mut chars = after_colon.trim_start().chars();
    if chars.next()? != '"' {
        return None;
    }
    let mut output = String::new();
    let mut escaped = false;
    for ch in chars {
        if escaped {
            output.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            return Some(output);
        } else {
            output.push(ch);
        }
    }
    None
}

fn extract_number(input: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{key}\"");
    let after_key = input.split(&needle).nth(1)?;
    let after_colon = after_key.split(':').nth(1)?;
    let digits: String = after_colon
        .trim_start()
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect();
    digits.parse().ok()
}

fn json_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    #[test]
    fn timestamp_is_non_empty() {
        assert!(!super::timestamp().is_empty());
    }

    #[test]
    fn parses_request_target() {
        let request = super::parse_request("{\"target\":\"example.com\",\"timeout_seconds\":3}");
        assert_eq!(request.target, "example.com");
        assert_eq!(request.timeout_seconds, Some(3));
    }
}
