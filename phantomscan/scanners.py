"""Real network scanners used when optional engines are unavailable."""

from __future__ import annotations

import asyncio
import logging
import socket
import ssl
import time
from typing import Any

from .models import Finding, Observation
from .scope import Target


TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5900, 8080, 8443, 8888, 27017, 6379, 5432, 9200,
    5601, 2375, 2376, 4443, 8008, 8181, 9090, 9443, 4848, 7001, 7002,
    8161, 61616, 11211, 28017, 50000, 1521, 1433, 5000, 5001, 8069,
    8000, 9000, 9001, 8983, 4444, 587, 465, 389, 636, 2049, 5985, 5986,
    15672, 5672, 1883, 8883, 3000, 3001, 5000, 5601, 7000, 8081, 8082,
    8088, 8090, 8091, 9002, 9201, 9300, 10000, 27018, 27019, 50070,
    50075, 9200, 9300, 11211, 123, 161, 162, 179, 2222, 2323, 2483,
    2484, 3268, 3269, 5353, 5984, 7474, 7687, 9000, 9999, 49152,
]

RISKY_PORTS = {
    23: ("critical", "Telnet is reachable."),
    139: ("high", "NetBIOS is reachable."),
    445: ("high", "SMB is reachable."),
    1433: ("high", "Microsoft SQL Server is reachable."),
    2375: ("critical", "Unauthenticated Docker API port is reachable."),
    2376: ("high", "Docker API TLS port is reachable."),
    3306: ("medium", "MySQL is reachable."),
    5432: ("medium", "PostgreSQL is reachable."),
    5601: ("medium", "Kibana is reachable."),
    6379: ("high", "Redis is reachable."),
    9200: ("high", "Elasticsearch is reachable."),
    11211: ("high", "Memcached is reachable."),
    27017: ("high", "MongoDB is reachable."),
}


async def scan_ports(target: Target, ports_spec: str, logger: logging.Logger) -> tuple[list[Observation], list[dict[str, Any]]]:
    """Run a real TCP connect scan with banner grabbing."""
    if target.target_type == "cidr":
        return [Observation("port_scan_skipped", "CIDR host enumeration is not enabled in this build.", "python-portscan")], []
    ports = _parse_ports(ports_spec)
    if target.port and target.port not in ports:
        ports = [target.port] + ports
    logger.info("Scanning %s TCP ports on %s", len(ports), target.host)
    started = time.perf_counter()
    semaphore = asyncio.Semaphore(100)

    async def one(port: int) -> dict[str, Any] | None:
        async with semaphore:
            return await asyncio.to_thread(_scan_one_port, target.host, port, 1.5)

    results = [item for item in await asyncio.gather(*(one(port) for port in ports)) if item]
    elapsed_ms = int((time.perf_counter() - started) * 1000)
    findings: list[Finding] = []
    for result in results:
        port = int(result["port"])
        if port in RISKY_PORTS:
            severity, note = RISKY_PORTS[port]
            findings.append(
                Finding(
                    id=f"OPEN-RISKY-PORT-{port}",
                    title="Risk-sensitive service is reachable",
                    severity=severity,  # type: ignore[arg-type]
                    confidence="high",
                    category="network",
                    target=target.host,
                    evidence=f"TCP {port} open. Service={result['service']}. Banner={result.get('banner') or 'none'}",
                    recommendation=f"{note} Restrict exposure to trusted networks and verify patch/authentication state.",
                )
            )
    logger.info("Port scan complete: %s open ports in %sms", len(results), elapsed_ms)
    return [
        Observation("open_tcp_ports", [item["port"] for item in results], "python-portscan"),
        Observation("port_scan_results", results, "python-portscan"),
        Observation("port_scan_duration_ms", elapsed_ms, "python-portscan"),
    ], [item.to_dict() for item in findings]


async def inspect_tls(target: Target, logger: logging.Logger) -> tuple[list[Observation], list[dict[str, Any]]]:
    """Perform a real TLS handshake and certificate inspection."""
    if target.target_type == "cidr":
        return [Observation("tls_skipped", "CIDR target", "python-tls")], []
    if target.scheme == "http" and target.is_local:
        return [Observation("tls_skipped", "Plaintext HTTP local target", "python-tls")], []
    tls_port = target.port if (target.port and target.scheme == "https") else 443
    logger.info("Inspecting TLS on %s:%s", target.host, tls_port)
    started = time.perf_counter()
    try:
        result = await asyncio.to_thread(_inspect_tls_blocking, target.host, tls_port, 10.0)
    except (OSError, ssl.SSLError, TimeoutError) as exc:
        logger.warning("TLS inspection failed for %s: %s", target.host, exc)
        logger.debug("TLS inspection failure details: %r", exc)
        return [Observation("tls_error", str(exc), "python-tls")], [
            Finding(
                id="TLS-INSPECTION-FAILED",
                title="TLS service could not be verified",
                severity="info",
                confidence="high",
                category="ssl",
                target=target.host,
                evidence=f"TLS handshake to {target.host}:443 failed: {exc}",
                recommendation="Confirm whether HTTPS is expected and reachable from the assessment network.",
            ).to_dict()
        ]
    elapsed_ms = int((time.perf_counter() - started) * 1000)
    result["duration_ms"] = elapsed_ms
    findings: list[dict[str, Any]] = []
    if result.get("expired"):
        findings.append(
            Finding(
                id="TLS-CERT-EXPIRED",
                title="TLS certificate is expired",
                severity="high",
                confidence="high",
                category="ssl",
                target=target.host,
                evidence=f"Certificate notAfter={result.get('not_after')}",
                recommendation="Renew and deploy a valid TLS certificate.",
            ).to_dict()
        )
    logger.info("TLS inspection complete: grade %s in %sms", result.get("grade"), elapsed_ms)
    return [Observation("tls_inspection", result, "python-tls"), Observation("ssl_grade", result.get("grade"), "python-tls")], findings


def _scan_one_port(host: str, port: int, timeout: float) -> dict[str, Any] | None:
    try:
        with socket.create_connection((host, port), timeout=timeout) as conn:
            conn.settimeout(5.0)
            banner = _grab_banner(conn, port)
            return {
                "port": port,
                "state": "open",
                "service": _identify_service(port, banner),
                "banner": banner[:200],
            }
    except (OSError, TimeoutError):
        return None


def _grab_banner(conn: socket.socket, port: int) -> str:
    probes = {
        80: b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
        8080: b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
        25: b"",
        21: b"",
        22: b"",
    }
    probe = probes.get(port)
    try:
        if probe:
            conn.sendall(probe)
        data = conn.recv(1024)
        return data.decode("utf-8", errors="replace").strip()
    except OSError:
        return ""


def _identify_service(port: int, banner: str) -> str:
    names = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        80: "http", 443: "https", 445: "smb", 3306: "mysql",
        3389: "rdp", 5432: "postgresql", 6379: "redis", 8080: "http-alt",
        8443: "https-alt", 9200: "elasticsearch", 27017: "mongodb",
    }
    lowered = banner.lower()
    if "ssh" in lowered:
        return "ssh"
    if "http" in lowered:
        return "http"
    return names.get(port, "unknown")


def _parse_ports(spec: str) -> list[int]:
    if spec == "top1000":
        return sorted(set(TOP_PORTS))
    if spec == "top100":
        return sorted(set(TOP_PORTS[:100]))
    ports: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            start_s, end_s = part.split("-", 1)
            start = max(1, int(start_s))
            end = min(65535, int(end_s))
            ports.update(range(start, end + 1))
        else:
            ports.add(int(part))
    return sorted(port for port in ports if 1 <= port <= 65535)


def _inspect_tls_blocking(host: str, port: int, timeout: float) -> dict[str, Any]:
    context = ssl.create_default_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert()
            cipher = tls.cipher()
            protocol = tls.version()
    not_after = cert.get("notAfter", "")
    expired = False
    if not_after:
        parsed = ssl.cert_time_to_seconds(not_after)
        expired = parsed < time.time()
    grade = _tls_grade(protocol, cipher[0] if cipher else "", expired)
    return {
        "host": host,
        "port": port,
        "protocol": protocol,
        "cipher": cipher[0] if cipher else "",
        "cipher_bits": cipher[2] if cipher else None,
        "subject": cert.get("subject", []),
        "issuer": cert.get("issuer", []),
        "not_before": cert.get("notBefore", ""),
        "not_after": not_after,
        "san": cert.get("subjectAltName", []),
        "expired": expired,
        "grade": grade,
    }


def _tls_grade(protocol: str | None, cipher: str, expired: bool) -> str:
    if expired:
        return "F"
    proto = protocol or ""
    lowered = cipher.lower()
    if "ssl" in proto or "rc4" in lowered or "des" in lowered:
        return "F"
    if proto in {"TLSv1", "TLSv1.1"}:
        return "C"
    if proto == "TLSv1.3":
        return "A"
    if proto == "TLSv1.2":
        return "B"
    return "D"
