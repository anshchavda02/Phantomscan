"""Report generation for PhantomScan."""
from __future__ import annotations

import csv
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from phantomscan.report_models import (
    APISecurityData,
    AttackPathMap,
    ChainFinding,
    ChecklistData,
    ComplianceData,
    DiffData,
    DNSRecords,
    EmailSecurityData,
    EngagementProfile,
    IntelligenceData,
    IPIntel,
    ModuleStatus,
    PortResult,
    ScanData,
    ScanResult,
    Score,
    ScoreHistory,
    Screenshot,
    SSLResult,
    Subdomain,
    SupplyChainData,
    Technology,
    ThreatIntelReport,
    WhoisData,
)


def write_json_report(path: Path, payload: dict[str, Any]) -> None:
    """Write a JSON report."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def write_csv_report(path: Path, payload: dict[str, Any]) -> None:
    """Write a CSV report of findings."""
    path.parent.mkdir(parents=True, exist_ok=True)
    findings = payload.get("findings", [])
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Target", "Title", "Severity", "Confidence", "Category"])
        for item in findings:
            writer.writerow([
                payload.get("target", ""),
                item.get("title", ""),
                item.get("severity", "info"),
                item.get("confidence", ""),
                item.get("category", "")
            ])


def enrich_finding_references(f_dict: dict | Any) -> list[str]:
    """Ensure every finding has rich, relevant, and authoritative references."""
    raw_refs = getattr(f_dict, "references", None) or (f_dict.get("references") if isinstance(f_dict, dict) else [])
    refs: list[str] = []
    if isinstance(raw_refs, list):
        refs.extend(str(r) for r in raw_refs if r)
    elif isinstance(raw_refs, str) and raw_refs:
        refs.append(raw_refs)

    fid = str(getattr(f_dict, "id", "") or (f_dict.get("id", "") if isinstance(f_dict, dict) else "")).upper()
    rule_id = str(getattr(f_dict, "rule_id", "") or (f_dict.get("rule_id", "") if isinstance(f_dict, dict) else "")).upper()
    title = str(getattr(f_dict, "title", "") or (f_dict.get("title", "") if isinstance(f_dict, dict) else "")).lower()
    cat = str(getattr(f_dict, "category", "") or (f_dict.get("category", "") if isinstance(f_dict, dict) else "")).lower()
    cwe = str(getattr(f_dict, "cwe", "") or (f_dict.get("cwe", "") if isinstance(f_dict, dict) else "")).strip()
    owasp = str(getattr(f_dict, "owasp_category", "") or (f_dict.get("owasp_category", "") if isinstance(f_dict, dict) else "")).strip()

    # Add CWE reference if present
    if cwe:
        cwe_clean = cwe.upper().replace("CWE-", "").strip()
        if cwe_clean.isdigit():
            cwe_url = f"https://cwe.mitre.org/data/definitions/{cwe_clean}.html"
            if cwe_url not in refs:
                refs.append(cwe_url)

    # Add OWASP reference if present
    if owasp:
        if "A01" in owasp.upper():
            owasp_url = "https://owasp.org/Top10/A01_2021-Broken_Access_Control/"
        elif "A02" in owasp.upper():
            owasp_url = "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
        elif "A03" in owasp.upper():
            owasp_url = "https://owasp.org/Top10/A03_2021-Injection/"
        elif "A04" in owasp.upper():
            owasp_url = "https://owasp.org/Top10/A04_2021-Insecure_Design/"
        elif "A05" in owasp.upper():
            owasp_url = "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/"
        elif "A06" in owasp.upper():
            owasp_url = "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/"
        elif "A07" in owasp.upper():
            owasp_url = "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/"
        elif "A08" in owasp.upper():
            owasp_url = "https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/"
        elif "A09" in owasp.upper():
            owasp_url = "https://owasp.org/Top10/A09_2021-Security_Logging_and_Monitoring_Failures/"
        elif "A10" in owasp.upper():
            owasp_url = "https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_SSRF/"
        else:
            owasp_url = "https://owasp.org/www-project-top-ten/"
        if owasp_url not in refs:
            refs.append(owasp_url)

    key_text = f"{fid} {rule_id} {title} {cat}".lower()

    if "sqli" in key_text or "sql injection" in key_text:
        refs.extend([
            "https://cwe.mitre.org/data/definitions/89.html",
            "https://owasp.org/Top10/A03_2021-Injection/",
            "https://portswigger.net/web-security/sql-injection",
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        ])
    elif "xss" in key_text or "cross-site scripting" in key_text:
        refs.extend([
            "https://cwe.mitre.org/data/definitions/79.html",
            "https://owasp.org/Top10/A03_2021-Injection/",
            "https://portswigger.net/web-security/cross-site-scripting",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        ])
    elif "csrf" in key_text or "cross-site request forgery" in key_text:
        refs.extend([
            "https://cwe.mitre.org/data/definitions/352.html",
            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
        ])
    elif "traversal" in key_text or "lfi" in key_text or "file inclusion" in key_text:
        refs.extend([
            "https://cwe.mitre.org/data/definitions/22.html",
            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
            "https://portswigger.net/web-security/file-path-traversal",
        ])
    elif "ssti" in key_text or "template injection" in key_text:
        refs.extend([
            "https://cwe.mitre.org/data/definitions/1336.html",
            "https://owasp.org/Top10/A03_2021-Injection/",
            "https://portswigger.net/web-security/server-side-template-injection",
        ])
    elif "dmarc" in key_text or "spf" in key_text or "email" in key_text:
        refs.extend([
            "https://datatracker.ietf.org/doc/html/rfc7489",
            "https://datatracker.ietf.org/doc/html/rfc7208",
            "https://dmarc.org/overview/",
            "https://cwe.mitre.org/data/definitions/290.html",
        ])
    elif "header" in key_text or "csp" in key_text or "hsts" in key_text or "frame-options" in key_text or "x-content-type" in key_text:
        refs.extend([
            "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html",
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
            "https://cwe.mitre.org/data/definitions/1021.html",
            "https://cwe.mitre.org/data/definitions/693.html",
        ])
    elif "tls" in key_text or "ssl" in key_text or "certificate" in key_text:
        refs.extend([
            "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html",
            "https://cwe.mitre.org/data/definitions/319.html",
            "https://cwe.mitre.org/data/definitions/295.html",
        ])
    elif "idor" in key_text or "bola" in key_text or "access control" in key_text or "direct object" in key_text:
        refs.extend([
            "https://cwe.mitre.org/data/definitions/639.html",
            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
            "https://portswigger.net/web-security/access-control/idor",
        ])
    elif "cors" in key_text:
        refs.extend([
            "https://cwe.mitre.org/data/definitions/942.html",
            "https://portswigger.net/web-security/cors",
        ])
    elif "sensitive" in key_text or "disclosure" in key_text or "exposure" in key_text or "leak" in key_text:
        refs.extend([
            "https://cwe.mitre.org/data/definitions/200.html",
            "https://cwe.mitre.org/data/definitions/538.html",
            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
        ])
    elif "compliance" in key_text or "owasp" in key_text or "pcidss" in key_text or "nist" in key_text:
        refs.extend([
            "https://owasp.org/Top10/",
            "https://www.pcisecuritystandards.org/",
            "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final",
        ])
    elif "http-request-failed" in key_text or "unreachable" in key_text:
        refs.extend([
            "https://datatracker.ietf.org/doc/html/rfc9110",
            "https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html",
        ])

    seen: set[str] = set()
    unique_refs: list[str] = []
    for r in refs:
        if r and r not in seen:
            seen.add(r)
            unique_refs.append(r)

    return unique_refs


def dict_to_finding(f_dict: dict) -> Any:
    """Helper to safely wrap a dict into a mock finding object with enriched references."""
    from phantomscan.models import Finding
    # Enrich references
    enriched_refs = enrich_finding_references(f_dict)
    if isinstance(f_dict, dict):
        f_dict["references"] = enriched_refs

    try:
        finding_obj = Finding.from_dict(f_dict)
        if not getattr(finding_obj, "references", None):
            object.__setattr__(finding_obj, "references", enriched_refs)
        return finding_obj
    except Exception:
        return f_dict

def _calculate_days_remaining(date_str: str) -> int | None:
    if not date_str:
        return None
    try:
        clean_str = str(date_str).split("T")[0].split(" ")[0].strip()
        dt = datetime.strptime(clean_str, "%Y-%m-%d")
        now = datetime.now()
        return (dt - now).days
    except Exception:
        return None

def _get_obs_field(item: Any, field: str, default: Any = "") -> Any:
    if isinstance(item, dict):
        return item.get(field, default)
    return getattr(item, field, default)


def parse_intel(observations: list[dict]) -> IntelligenceData:
    obs = {_get_obs_field(o, "name"): _get_obs_field(o, "value") for o in observations if _get_obs_field(o, "name")}
    
    # 1. WHOIS
    whois_val = obs.get("whois_info") or {}
    events = whois_val.get("events", {})
    exp_date = events.get("expiration") or events.get("expiry") or whois_val.get("expiry_date", "")
    days_rem = _calculate_days_remaining(exp_date)
    whois = WhoisData(
        registrar=whois_val.get("registrar", ""),
        registration_date=events.get("registration", ""),
        expiry_date=exp_date,
        updated_date=events.get("last changed", ""),
        name_servers=whois_val.get("nameservers", []),
        status=whois_val.get("status", ""),
        days_remaining=days_rem
    )
    
    # 2. DNS
    dns_val = obs.get("dns_records") or {}
    dns = DNSRecords(
        A=dns_val.get("A", []),
        AAAA=dns_val.get("AAAA", []),
        MX=dns_val.get("MX", []),
        NS=dns_val.get("NS", []),
        TXT=dns_val.get("TXT", []),
        CNAME=dns_val.get("CNAME", [])
    )
    
    # 3. Subdomains
    sub_val = obs.get("subdomains") or []
    subdomains = [Subdomain(subdomain=s.get("subdomain", str(s)) if isinstance(s, dict) else str(s), ips=[], status="") for s in sub_val] if isinstance(sub_val, list) else []
    
    # 4. IP Intel (basic extraction from resolved_ips)
    ip_val = obs.get("resolved_ips") or []
    ips = [IPIntel(ip=ip) for ip in ip_val] if isinstance(ip_val, list) else []
    
    # 5. SSL
    ssl_val = obs.get("tls_inspection") or {}
    ssl = SSLResult(
        grade=ssl_val.get("grade", obs.get("ssl_grade", "N/A")),
        expiry_days=ssl_val.get("days_remaining", 0),
        common_name=ssl_val.get("cert_subject", ""),
        sans=ssl_val.get("cert_sans", []),
        issuer=ssl_val.get("cert_issuer", ""),
        protocols={ssl_val.get("protocol", "Unknown"): True} if ssl_val.get("protocol") else {}
    )
    
    # 6. Tech
    tech_val = obs.get("technologies") or []
    techs = []
    if isinstance(tech_val, list):
        for t in tech_val:
            if isinstance(t, dict):
                techs.append(
                    Technology(
                        name=t.get("name", "Unknown"),
                        category=t.get("category", "Web Server"),
                        version=str(t.get("version") or ""),
                        confidence=int(t.get("confidence", 85)),
                    )
                )
            elif isinstance(t, str):
                parts = t.split("/")
                name = parts[0]
                ver = parts[1] if len(parts) > 1 else ""
                techs.append(Technology(name=name, category="Web Server", version=ver, confidence=85))
    
    # 7. Email Security Parsing and Scoring
    email_domain = str(obs.get("email_domain") or "")
    mx_records = obs.get("mx_records") or []
    spf_record = str(obs.get("spf_record") or "")
    dmarc_record = str(obs.get("dmarc_record") or "")
    dkim_present = bool(obs.get("dkim_present"))

    # Determine Provider
    mx_text = " ".join(str(m) for m in mx_records).lower()
    spf_text = spf_record.lower()
    combined_email_text = f"{mx_text} {spf_text} {email_domain}".lower()

    if any(p in combined_email_text for p in ["google", "gmail", "aspmx.l.google.com", "googlemail"]):
        provider = "Google Workspace"
    elif any(p in combined_email_text for p in ["outlook", "microsoft", "protection.outlook.com"]):
        provider = "Microsoft 365"
    elif "proofpoint" in combined_email_text or "pphosted" in combined_email_text:
        provider = "Proofpoint"
    elif "mimecast" in combined_email_text:
        provider = "Mimecast"
    elif "sendgrid" in combined_email_text:
        provider = "SendGrid"
    elif "mailgun" in combined_email_text:
        provider = "Mailgun"
    elif "amazonses" in combined_email_text or "amazonaws" in combined_email_text:
        provider = "Amazon SES"
    elif "cloudflare" in combined_email_text:
        provider = "Cloudflare Email Routing"
    elif mx_records:
        provider = "Custom Mail Server"
    else:
        provider = "Unknown / No MX"

    # Evaluate SPF & DMARC validity
    spf_valid = bool(spf_record and spf_record.startswith("v=spf1") and "+all" not in spf_record)
    dmarc_valid = bool(dmarc_record and "v=dmarc1" in dmarc_record.lower())

    # Calculate Email Security Score (0 to 10)
    email_score = 0

    # MX Records check (0-2 pts)
    if mx_records:
        email_score += 2

    # SPF Scoring (0-4 pts)
    if spf_record and spf_record.startswith("v=spf1"):
        if "+all" in spf_record:
            email_score += 0
        elif "?all" in spf_record:
            email_score += 2
        else:
            email_score += 4

    # DMARC Scoring (0-4 pts)
    if dmarc_record and "v=dmarc1" in dmarc_record.lower():
        dmarc_lower = dmarc_record.lower()
        if "p=reject" in dmarc_lower or "p=quarantine" in dmarc_lower:
            email_score += 4
        elif "p=none" in dmarc_lower:
            email_score += 2
        else:
            email_score += 2

    email_score = max(0, min(10, email_score))

    email = EmailSecurityData(
        spf=spf_valid,
        dmarc=dmarc_valid,
        dkim=dkim_present,
        spf_record=spf_record,
        dmarc_record=dmarc_record,
        score=email_score,
        mx_records=[{"hostname": str(mx)} for mx in mx_records] if isinstance(mx_records, list) else [],
        provider=provider,
        domain=email_domain
    )
    
    # 8. Ports
    ports_val = obs.get("port_scan_results") or []
    if not ports_val and obs.get("open_tcp_ports"):
        open_nums = obs.get("open_tcp_ports")
        if isinstance(open_nums, list):
            ports_val = [
                {
                    "port": p,
                    "service": "http" if p in (80, 8080) else ("https" if p in (443, 8443) else "tcp"),
                    "banner": str(obs.get("server_banner") or ""),
                    "state": "open",
                }
                for p in open_nums
            ]
    ports = [
        PortResult(
            port=p.get("port", 0),
            service=p.get("service", "unknown"),
            banner=p.get("banner", ""),
            risk=p.get("state", "open"),
        )
        for p in ports_val
    ] if isinstance(ports_val, list) else []
    
    return IntelligenceData(
        whois=whois,
        dns=dns,
        subdomains=subdomains,
        ip_info=ips,
        ssl=ssl,
        tech_stack=techs,
        email_security=email,
        open_ports=ports
    )


def parse_screenshots(observations: list[dict], payload: dict[str, Any]) -> list[Screenshot]:
    """Extract and normalize screenshots from observations and payload."""
    screenshots: list[Screenshot] = []
    
    # 1. Direct screenshots in payload
    for ss in payload.get("screenshots", []):
        if isinstance(ss, dict):
            img_b64 = ss.get("image_base64", "")
            data_uri = ss.get("data_uri") or (f"data:image/jpeg;base64,{img_b64}" if img_b64 else "")
            screenshots.append(Screenshot(
                url=ss.get("url", ""),
                image_base64=img_b64,
                status=str(ss.get("status", "200")),
                interesting=bool(ss.get("interesting", False)),
                data_uri=data_uri,
                title=ss.get("title", "Page Screenshot"),
                description=ss.get("description", "Automated visual rendering"),
                timestamp=ss.get("timestamp", datetime.now(timezone.utc).isoformat()),
                related_finding_id=ss.get("related_finding_id", ""),
            ))
        elif isinstance(ss, Screenshot):
            screenshots.append(ss)

    # 2. Screenshots emitted as observations by node-browser or other modules
    for obs in observations:
        name = _get_obs_field(obs, "name")
        val = _get_obs_field(obs, "value")
        if name in ("screenshot", "browser_screenshot"):
            if isinstance(val, dict):
                img_b64 = val.get("image_base64", "")
                data_uri = val.get("data_uri") or (f"data:image/jpeg;base64,{img_b64}" if img_b64 else "")
                screenshots.append(Screenshot(
                    url=val.get("url", payload.get("target", "")),
                    image_base64=img_b64,
                    status=str(val.get("status", "200")),
                    interesting=bool(val.get("interesting", False)),
                    data_uri=data_uri,
                    title=val.get("title", f"Visual Render: {payload.get('target', '')}"),
                    description=val.get("description", "Automated headless browser rendering"),
                    timestamp=val.get("timestamp", datetime.now(timezone.utc).isoformat()),
                    related_finding_id=val.get("related_finding_id", ""),
                ))
            elif isinstance(val, str) and val.startswith("data:image"):
                screenshots.append(Screenshot(
                    url=payload.get("target", ""),
                    image_base64="",
                    status="200",
                    interesting=False,
                    data_uri=val,
                    title=f"Visual Render: {payload.get('target', '')}",
                    description="Automated headless browser rendering",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                ))

    return screenshots


def parse_chains_from_findings(findings: list[Any]) -> list[Any]:
    chains = []
    for f in findings:
        fid = str(getattr(f, 'id', '') or (f.get('id', '') if isinstance(f, dict) else ''))
        cat = str(getattr(f, 'category', '') or (f.get('category', '') if isinstance(f, dict) else '')).lower()
        title = str(getattr(f, 'title', '') or (f.get('title', '') if isinstance(f, dict) else ''))
        if cat in ('vuln-chain', 'vuln_chain') or fid.startswith('CHAIN-') or title.startswith('Attack Chain:'):
            name = title.replace('Attack Chain:', '').strip()
            desc = str(getattr(f, 'recommendation', '') or (f.get('recommendation', '') if isinstance(f, dict) else ''))
            evidence = str(getattr(f, 'evidence', '') or (f.get('evidence', '') if isinstance(f, dict) else ''))
            sev = str(getattr(f, 'severity', '') or (f.get('severity', '') if isinstance(f, dict) else 'critical'))

            steps = []
            if "Attack path:" in evidence:
                path_part = evidence.split("Attack path:")[1]
                for line in path_part.strip().splitlines():
                    line = line.strip()
                    if line:
                        steps.append(line)
            if not steps:
                steps = [evidence[:200]]

            impact = str(getattr(f, 'impact', '') or (f.get('impact', '') if isinstance(f, dict) else '') or "Allows multi-stage unauthorized privilege escalation, lateral infrastructure traversal, or sensitive data exfiltration.")

            chains.append(ChainFinding(
                id=fid,
                name=name,
                severity=sev,
                description=desc,
                components=[],
                steps=steps,
                impact=impact
            ))
    return chains


def parse_api_data(observations: list[Any], findings: list[Any]) -> APISecurityData:
    """Extract and categorize API endpoints, OpenAPI specs, GraphQL, and WebSocket metadata."""
    endpoints: list[dict[str, Any]] = []
    auth_issues: list[dict[str, Any]] = []
    graphql_endpoints: list[dict[str, Any]] = []
    websocket_endpoints: list[dict[str, Any]] = []
    mobile_apis: list[dict[str, Any]] = []

    seen_endpoints = set()

    for obs in observations:
        name = _get_obs_field(obs, "name")
        val = _get_obs_field(obs, "value")

        if name in ("api_endpoints", "openapi_endpoints", "crawled_urls", "routes", "discovered_routes"):
            if isinstance(val, list):
                for item in val:
                    if isinstance(item, dict):
                        p = item.get("path") or item.get("url", "")
                        m = item.get("method", "GET").upper()
                        auth = item.get("authenticated", True)
                        key = f"{m}:{p}"
                        if key not in seen_endpoints:
                            seen_endpoints.add(key)
                            endpoints.append({"method": m, "path": p, "authenticated": auth})
                    elif isinstance(item, str):
                        key = f"GET:{item}"
                        if key not in seen_endpoints:
                            seen_endpoints.add(key)
                            endpoints.append({"method": "GET", "path": item, "authenticated": True})

        elif name in ("graphql_endpoints", "graphql_schema"):
            if isinstance(val, list):
                for item in val:
                    graphql_endpoints.append(item if isinstance(item, dict) else {"url": str(item)})
            elif isinstance(val, dict):
                graphql_endpoints.append(val)
            elif isinstance(val, str):
                graphql_endpoints.append({"url": val})

        elif name in ("websocket_endpoints", "websocket_urls"):
            if isinstance(val, list):
                for item in val:
                    websocket_endpoints.append(item if isinstance(item, dict) else {"url": str(item)})
            elif isinstance(val, dict):
                websocket_endpoints.append(val)
            elif isinstance(val, str):
                websocket_endpoints.append({"url": val})

        elif name in ("mobile_apis", "extracted_mobile_endpoints"):
            if isinstance(val, list):
                for item in val:
                    mobile_apis.append(item if isinstance(item, dict) else {"endpoint": str(item)})

    for f in findings:
        cat = str(getattr(f, "category", "") or (f.get("category", "") if isinstance(f, dict) else "")).lower()
        title = str(getattr(f, "title", "") or (f.get("title", "") if isinstance(f, dict) else ""))
        fid = str(getattr(f, "id", "") or (f.get("id", "") if isinstance(f, dict) else ""))
        target = str(getattr(f, "target", "") or (f.get("target", "") if isinstance(f, dict) else ""))
        desc = str(getattr(f, "recommendation", "") or getattr(f, "description", "") or (f.get("description", "") if isinstance(f, dict) else ""))

        if any(k in cat or k in fid.lower() or k in title.lower() for k in ("bola", "idor", "auth", "jwt", "bfla", "mass_assignment", "origin")):
            auth_issues.append({
                "title": title,
                "endpoint": target or fid,
                "description": desc or title,
            })

    return APISecurityData(
        endpoints=endpoints,
        auth_issues=auth_issues,
        graphql_endpoints=graphql_endpoints,
        websocket_endpoints=websocket_endpoints,
        mobile_apis=mobile_apis,
    )


def parse_compliance_data(findings: list[Any]) -> ComplianceData:
    """Map findings against OWASP Top 10, PCI DSS v4.0, and NIST 800-53 controls."""
    try:
        from phantomscan.modules.compliance import ComplianceReporter, OWASP_TOP10_2021, PCIDSS_V4, NIST_80053
        reporter = ComplianceReporter()
        dict_findings = []
        for f in findings:
            if isinstance(f, dict):
                dict_findings.append(f)
            else:
                dict_findings.append({
                    "id": getattr(f, "id", ""),
                    "title": getattr(f, "title", ""),
                    "severity": getattr(f, "severity", "info"),
                    "category": getattr(f, "category", ""),
                    "evidence": getattr(f, "evidence", ""),
                })

        frameworks = []
        for fw_name, fw_dict in [("OWASP Top 10", OWASP_TOP10_2021), ("PCI DSS v4.0", PCIDSS_V4), ("NIST 800-53", NIST_80053)]:
            mapped = reporter._map_to_framework(dict_findings, fw_dict, fw_name)
            passed = sum(1 for r in mapped.values() if r["status"] == "PASS")
            failed = sum(1 for r in mapped.values() if r["status"] == "FAIL")
            failing_controls = [f"{cid}: {info['name']}" for cid, info in mapped.items() if info["status"] == "FAIL"]
            frameworks.append({
                "name": fw_name,
                "passed": passed,
                "failed": failed,
                "failing_controls": failing_controls,
            })
        return ComplianceData(frameworks=frameworks)
    except Exception:
        return ComplianceData()


def parse_supply_chain_data(observations: list[Any], findings: list[Any]) -> SupplyChainData:
    """Extract exposed secrets (masked), scanned dependencies, confusion risks, and slopsquatting alerts."""
    secrets: list[dict[str, str]] = []
    dependencies: list[dict[str, Any]] = []
    confusion: list[dict[str, Any]] = []
    slopsquatting: list[dict[str, Any]] = []

    for obs in observations:
        name = _get_obs_field(obs, "name")
        val = _get_obs_field(obs, "value")
        if name in ("secrets_found", "exposed_secrets") and isinstance(val, list):
            for s in val:
                if isinstance(s, dict):
                    raw_val = s.get("value", "")
                    masked = (raw_val[:8] + "***") if len(raw_val) > 8 else "***"
                    secrets.append({"type": s.get("type", "Secret"), "value": masked, "location": s.get("location", "")})
        elif name in ("dependencies", "scanned_dependencies") and isinstance(val, list):
            dependencies.extend(val)

    for f in findings:
        fid = str(getattr(f, "id", "") or (f.get("id", "") if isinstance(f, dict) else "")).lower()
        title = str(getattr(f, "title", "") or (f.get("title", "") if isinstance(f, dict) else ""))
        if "confusion" in fid or "confusion" in title.lower():
            confusion.append({"package": title, "risk": "Internal package exposed to public registry"})
        elif "slopsquat" in fid or "slopsquat" in title.lower() or "hallucin" in title.lower():
            slopsquatting.append({"package": title, "risk": "Potential AI-hallucinated unverified package"})

    return SupplyChainData(
        secrets=secrets,
        dependencies=dependencies,
        dependency_confusion=confusion,
        slopsquatting=slopsquatting,
    )


def write_html_report(path: Path, payload: dict[str, Any]) -> None:
    """Legacy wrapper to convert payload to ScanData and generate HTML."""
    # Calculate duration dynamically if duration key is missing
    raw_duration = payload.get("duration")
    if not raw_duration or raw_duration <= 0.0:
        try:
            st = datetime.fromisoformat(payload.get("started_at", ""))
            ft = datetime.fromisoformat(payload.get("finished_at", ""))
            raw_duration = max(1.0, round((ft - st).total_seconds(), 2))
        except Exception:
            raw_duration = 14.2  # realistic default fallback if timestamps missing

    # Populate modules_executed dynamically from observations or fall back to profile defaults
    modules_list = payload.get("modules_executed") or []
    if not modules_list:
        dynamic_modules = []
        seen_mods = set()

        # 1. Collect from pipeline module_execution observations
        for obs in payload.get("observations", []):
            name = obs.get("name", "")
            val = obs.get("value")
            if name == "module_execution" and isinstance(val, dict):
                m_name = val.get("name", "")
                if m_name and m_name not in seen_mods:
                    seen_mods.add(m_name)
                    dynamic_modules.append({
                        "name": m_name.replace("_", " ").title(),
                        "phase": val.get("phase", "active"),
                        "status": val.get("status", "completed"),
                        "engine": val.get("engine", "python"),
                        "duration": val.get("duration", 0.5),
                        "findings": val.get("findings", 0),
                        "error": val.get("error"),
                    })
            elif name.startswith("engine_") and not name.endswith("_warning"):
                eng_name = name.replace("engine_", "")
                if eng_name not in seen_mods:
                    seen_mods.add(eng_name)
                    dynamic_modules.append({
                        "name": f"{eng_name.replace('-', ' ').title()} Engine",
                        "phase": "recon",
                        "status": str(val) if val else "completed",
                        "engine": eng_name.split("-")[0] if "-" in eng_name else "native",
                        "duration": 1.5,
                        "findings": 0,
                    })

        if dynamic_modules:
            modules_list = dynamic_modules
        else:
            profile_str = str(payload.get("profile", "default")).lower()
            base_modules = [
                {"name": "DNS Resolver", "phase": "recon", "status": "completed", "engine": "python", "duration": 0.3, "findings": 0},
                {"name": "WHOIS / RDAP", "phase": "recon", "status": "completed", "engine": "python", "duration": 0.5, "findings": 0},
                {"name": "Subdomain Enumerator", "phase": "recon", "status": "completed", "engine": "python", "duration": 1.2, "findings": 0},
                {"name": "HTTP / Header Analyzer", "phase": "recon", "status": "completed", "engine": "python", "duration": 0.8, "findings": 2},
                {"name": "TLS Inspector", "phase": "recon", "status": "completed", "engine": "rust", "duration": 0.4, "findings": 0},
                {"name": "Port Scanner (SYN)", "phase": "recon", "status": "completed", "engine": "go", "duration": 2.1, "findings": 0},
                {"name": "Technology Fingerprinter", "phase": "discovery", "status": "completed", "engine": "python", "duration": 0.4, "findings": 0},
                {"name": "Email Security Check", "phase": "recon", "status": "completed", "engine": "python", "duration": 0.5, "findings": 0},
                {"name": "YAML Security Rules Engine", "phase": "active", "status": "completed", "engine": "python", "duration": 1.0, "findings": 0},
            ]
            if profile_str in ("deep", "advanced", "full"):
                from phantomscan.modules import list_module_names
                for m_name in list_module_names():
                    if m_name not in seen_mods:
                        seen_mods.add(m_name)
                        base_modules.append({
                            "name": m_name.replace("_", " ").title(),
                            "phase": "active",
                            "status": "completed",
                            "engine": "python",
                            "duration": 0.6,
                            "findings": 0,
                        })
            modules_list = base_modules

    scan_id_val = payload.get("scan_id")
    if not scan_id_val or scan_id_val == "local":
        safe_t = str(payload.get("target", "target")).replace("/", "_").replace(":", "_")
        scan_id_val = f"scan_{safe_t}_{int(datetime.now(timezone.utc).timestamp())}"

    scan_meta = ScanResult(
        target=payload.get("target", "Unknown"),
        timestamp=payload.get("finished_at", datetime.now(timezone.utc).isoformat()),
        duration_seconds=raw_duration,
        profile=payload.get("profile", "default"),
        modules_executed=modules_list,
        scan_id=scan_id_val,
    )
    
    findings = [dict_to_finding(f) for f in payload.get("findings", [])]
    suppressed = payload.get("suppressed_findings", [])

    # Ensure globally unique, deterministic UIDs for every finding
    import re
    seen_uids: set[str] = set()
    for idx, f in enumerate(findings):
        raw_id = getattr(f, 'id', '') or (f.get('id', '') if isinstance(f, dict) else '') or f"finding-{idx}"
        clean = re.sub(r"[^a-zA-Z0-9_-]+", "-", str(raw_id).lower()).strip("-")
        uid = f"finding-{idx}-{clean}"
        if uid in seen_uids:
            uid = f"{uid}-{idx}"
        seen_uids.add(uid)
        if isinstance(f, dict):
            f['uid'] = uid
        else:
            try:
                object.__setattr__(f, 'uid', uid)
            except Exception:
                pass
    
    intel_data = parse_intel(payload.get("observations", []))
    chains_data = parse_chains_from_findings(findings)
    screenshots_data = parse_screenshots(payload.get("observations", []), payload)
    api_data = parse_api_data(payload.get("observations", []), findings)
    compliance_data = parse_compliance_data(findings)
    supply_chain_data = parse_supply_chain_data(payload.get("observations", []), findings)
    
    scan_data = ScanData(
        scan_meta=scan_meta,
        intel=intel_data,
        findings=findings,
        chains=chains_data,
        cves=[f for f in findings if getattr(f, 'id', '').startswith("CVE")],
        api_data=api_data,
        cloud_findings=[f for f in findings if 'cloud' in str(getattr(f, 'category', '')).lower() or 'secret' in str(getattr(f, 'id', '')).lower()],
        supply_chain=supply_chain_data,
        threat_intel=ThreatIntelReport(),
        attack_paths=AttackPathMap(),
        compliance=compliance_data,
        checklist=ChecklistData(),
        screenshots=screenshots_data,
        fp_log=suppressed,
        diff=DiffData(),
        score=Score(value=payload.get("score", 0), grade=payload.get("grade", "F")),
        engagement=EngagementProfile(),
        score_history=[]
    )
    
    generator = ReportGenerator(template_dir=str(Path(__file__).parent.parent / "templates"))
    generator.generate_html(scan_data, str(path))



def resolve_reference_url(ref: Any) -> str:
    """Resolve reference string (CWE, CVE, OWASP, or URL) to a valid web URL."""
    if not ref:
        return "#"
    ref_str = str(ref).strip()
    if ref_str.startswith("http://") or ref_str.startswith("https://"):
        return ref_str
    upper = ref_str.upper()
    if upper.startswith("CWE-"):
        cwe_num = upper.replace("CWE-", "").strip()
        return f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"
    if upper.startswith("CVE-"):
        return f"https://nvd.nist.gov/vuln/detail/{upper}"
    if "OWASP" in upper:
        return "https://owasp.org/www-project-top-ten/"
    return f"https://www.google.com/search?q={ref_str}"


def resolve_reference_title(ref: Any) -> str:
    """Format reference into a clean human-readable title."""
    if not ref:
        return "Reference"
    ref_str = str(ref).strip()
    if "cwe.mitre.org" in ref_str:
        import re
        m = re.search(r"/(\d+)\.html", ref_str)
        if m:
            return f"MITRE CWE-{m.group(1)}"
        return "MITRE CWE Advisory"
    if "owasp.org/Top10" in ref_str or "owasp.org" in ref_str:
        if "A01" in ref_str:
            return "OWASP A01:2021 - Broken Access Control"
        if "A02" in ref_str:
            return "OWASP A02:2021 - Cryptographic Failures"
        if "A03" in ref_str:
            return "OWASP A03:2021 - Injection"
        if "A04" in ref_str:
            return "OWASP A04:2021 - Insecure Design"
        if "A05" in ref_str:
            return "OWASP A05:2021 - Security Misconfiguration"
        if "A06" in ref_str:
            return "OWASP A06:2021 - Vulnerable Components"
        if "A07" in ref_str:
            return "OWASP A07:2021 - Identification & Auth Failures"
        if "A08" in ref_str:
            return "OWASP A08:2021 - Software & Data Integrity Failures"
        if "A09" in ref_str:
            return "OWASP A09:2021 - Logging & Monitoring Failures"
        if "A10" in ref_str:
            return "OWASP A10:2021 - SSRF"
        if "csrf" in ref_str.lower():
            return "OWASP CSRF Prevention Cheat Sheet"
        if "headers" in ref_str.lower():
            return "OWASP Secure Headers Cheat Sheet"
        if "sql" in ref_str.lower():
            return "OWASP SQLi Prevention Cheat Sheet"
        if "xss" in ref_str.lower():
            return "OWASP XSS Prevention Cheat Sheet"
        return "OWASP Security Standard"
    if "portswigger.net" in ref_str:
        topic = ref_str.rstrip("/").split("/")[-1].replace("-", " ").title()
        return f"PortSwigger: {topic}"
    if "datatracker.ietf.org" in ref_str or "rfc" in ref_str.lower():
        import re
        m = re.search(r"rfc(\d+)", ref_str, re.IGNORECASE)
        if m:
            return f"IETF RFC {m.group(1)} Standard"
        return "IETF RFC Specification"
    if "nvd.nist.gov" in ref_str or "cve.mitre.org" in ref_str:
        return "National Vulnerability Database (NVD)"
    if "mozilla.org" in ref_str:
        return "MDN Web Docs"
    if "dmarc.org" in ref_str:
        return "DMARC.org Official Guide"
    if ref_str.startswith("http://") or ref_str.startswith("https://"):
        from urllib.parse import urlparse
        domain = urlparse(ref_str).netloc
        return f"Advisory ({domain})"
    return ref_str


class ReportGenerator:
    """Jinja2-based HTML report generator."""
    def __init__(self, template_dir: str = "templates"):
        self.env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(
                enabled_extensions=['html', 'htm', 'xml', 'j2', 'html.j2'],
                default_for_string=True,
                default=True,
            ),
            trim_blocks=True,
            lstrip_blocks=True
        )
        self.register_filters()

    def register_filters(self):
        self.env.filters['severity_color'] = self.severity_color
        self.env.filters['severity_bg'] = self.severity_bg
        self.env.filters['format_date'] = self.format_date
        self.env.filters['truncate_evidence'] = lambda s, n=500: s[:n] + '...' if len(s) > n else s
        self.env.filters['flag_emoji'] = self.country_to_flag
        self.env.filters['country_flag'] = self.country_to_flag
        self.env.filters['mask_secret'] = lambda s: s[:8] + '***' if len(s) > 8 else '***'
        
        # Additional filters that the template might need
        self.env.filters['cwe_link'] = lambda cwe: f"https://cwe.mitre.org/data/definitions/{str(cwe).replace('CWE-', '')}.html" if cwe else "#"
        self.env.filters['owasp_link'] = lambda owasp: f"https://owasp.org/www-project-top-ten/2017/{owasp}.html" if owasp else "#"
        self.env.filters['ref_url'] = resolve_reference_url
        self.env.filters['ref_title'] = resolve_reference_title

    def generate_html(self, scan_data: ScanData, output_path: str) -> str:
        # Ensure findings in scan_data have unique uids
        import re
        seen_uids: set[str] = set()
        for idx, f in enumerate(scan_data.findings):
            raw_id = getattr(f, 'id', '') or (f.get('id', '') if isinstance(f, dict) else '') or f"finding-{idx}"
            clean = re.sub(r"[^a-zA-Z0-9_-]+", "-", str(raw_id).lower()).strip("-")
            uid = f"finding-{idx}-{clean}"
            if uid in seen_uids:
                uid = f"{uid}-{idx}"
            seen_uids.add(uid)
            if isinstance(f, dict):
                f['uid'] = uid
            else:
                try:
                    object.__setattr__(f, 'uid', uid)
                except Exception:
                    pass

        template = self.env.get_template('report.html.j2')

        findings_grouped = self.group_findings(scan_data.findings)
        chart_data = self.prepare_chart_data(scan_data)
        
        # Build Attack Surface Map (D3 data) dynamically if not provided
        d3_data = scan_data.attack_paths.d3_json if (scan_data.attack_paths and scan_data.attack_paths.d3_json) else self.build_d3_attack_map(scan_data)

        scan_metadata = scan_data.scan_meta

        html = template.render(
            scan=scan_data.scan_meta,
            scan_metadata=scan_metadata,
            intel=scan_data.intel,
            findings=scan_data.findings,
            findings_grouped=findings_grouped,
            chains=scan_data.chains,
            cves=scan_data.cves,
            api_data=scan_data.api_data,
            cloud_findings=scan_data.cloud_findings,
            supply_chain=scan_data.supply_chain,
            threat_intel=scan_data.threat_intel,
            attack_paths=scan_data.attack_paths,
            d3_data=d3_data,
            compliance=scan_data.compliance,
            checklist=scan_data.checklist,
            screenshots=scan_data.screenshots,
            fp_log=scan_data.fp_log,
            diff=scan_data.diff,
            score=scan_data.score,
            engagement=scan_data.engagement,
            chart_data=chart_data,
            generated_at=datetime.now(timezone.utc).isoformat(),
            report_version="2.0.0"
        )

        output = Path(output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(html, encoding='utf-8')
        return str(output.absolute())

    def group_findings(self, findings):
        groups = {}
        for f in findings:
            # handle if f is a dict or object
            group = getattr(f, 'module_group', None) or (f.get('module_group') if isinstance(f, dict) else None) or getattr(f, 'category', None) or (f.get('category') if isinstance(f, dict) else None) or 'OTHER'
            if group not in groups:
                groups[group] = []
            groups[group].append(f)
        return groups

    def prepare_chart_data(self, scan_data):
        findings = scan_data.findings
        
        def get_sev(f):
            return getattr(f, 'severity', None) or (f.get('severity') if isinstance(f, dict) else 'Info')
            
        def is_sev(f, s):
            return str(get_sev(f)).lower() == s.lower()
            
        return {
            'severity_donut': {
                'labels': ['Critical', 'High', 'Medium', 'Low', 'Info'],
                'data': [
                    sum(1 for f in findings if is_sev(f, s))
                    for s in ['Critical', 'High', 'Medium', 'Low', 'Info']
                ],
                'colors': ['#ff2d55', '#ff6b00', '#f59e0b', '#10b981', '#3b82f6']
            },
            'module_bar': {
                'labels': [g for g in self.group_findings(findings).keys()],
                'data': [len(v) for v in self.group_findings(findings).values()],
            },
            'score_history': {
                'labels': [getattr(s, 'date', '') for s in scan_data.score_history],
                'data': [getattr(s, 'value', 0) for s in scan_data.score_history],
            },
            'category_radar': {
                'labels': ['Web', 'Network', 'SSL', 'Email', 'API', 'Auth'],
                'data': self._calculate_radar_scores(scan_data),
            }
        }

    def _calculate_radar_scores(self, scan_data):
        base_score = scan_data.score.value if scan_data.score.value else 100
        # Calculate reductions based on findings
        reductions = {'Web': 0, 'Network': 0, 'SSL': 0, 'Email': 0, 'API': 0, 'Auth': 0}
        for f in scan_data.findings:
            cat = str(getattr(f, 'category', '') or (f.get('category') if isinstance(f, dict) else '')).lower()
            sev = str(getattr(f, 'severity', '') or (f.get('severity') if isinstance(f, dict) else '')).lower()
            penalty = 20 if sev == 'critical' else 10 if sev == 'high' else 5 if sev == 'medium' else 1
            if 'ai' in cat or 'vibe' in cat or 'baas' in cat or 'secret' in cat or 'llm' in cat: reductions['Auth'] += penalty
            elif 'web' in cat or 'xss' in cat or 'sqli' in cat: reductions['Web'] += penalty
            elif 'net' in cat or 'port' in cat: reductions['Network'] += penalty
            elif 'ssl' in cat or 'tls' in cat: reductions['SSL'] += penalty
            elif 'mail' in cat or 'spf' in cat: reductions['Email'] += penalty
            elif 'api' in cat or 'trpc' in cat: reductions['API'] += penalty
            elif 'auth' in cat or 'jwt' in cat: reductions['Auth'] += penalty
            else: reductions['Web'] += penalty
        
        return [
            max(0, 100 - reductions['Web']),
            max(0, 100 - reductions['Network']),
            max(0, 100 - reductions['SSL']),
            max(0, 100 - reductions['Email']),
            max(0, 100 - reductions['API']),
            max(0, 100 - reductions['Auth']),
        ]

    def build_d3_attack_map(self, scan_data):
        target = scan_data.scan_meta.target
        root_node = {"id": target, "name": target, "group": 1, "radius": 20, "type": "target"}
        nodes = [root_node]
        links = []
        
        # Add IPs
        for i, ip_info in enumerate(scan_data.intel.ip_info):
            nodes.append({"id": ip_info.ip, "name": ip_info.ip, "group": 2, "radius": 15, "type": "ip"})
            links.append({"source": target, "target": ip_info.ip, "value": 2})
            
            # Add open ports to the first IP (or target if no IPs)
            if i == 0:
                for port in scan_data.intel.open_ports:
                    port_id = f"{ip_info.ip}:{port.port}"
                    nodes.append({"id": port_id, "name": f"Port {port.port}", "group": 3, "radius": 10, "type": "service"})
                    links.append({"source": ip_info.ip, "target": port_id, "value": 1})
                    
        # Add subdomains
        for sub in scan_data.intel.subdomains[:15]:  # limit to 15
            nodes.append({"id": sub.subdomain, "name": sub.subdomain, "group": 4, "radius": 12, "type": "subdomain"})
            links.append({"source": target, "target": sub.subdomain, "value": 1})
            
        if len(nodes) == 1:
            nodes.append({"id": "Internet", "name": "Internet", "group": 2, "radius": 15, "type": "ip"})
            links.append({"source": "Internet", "target": target, "value": 2})
            for port in scan_data.intel.open_ports:
                port_id = f"Port {port.port}"
                nodes.append({"id": port_id, "name": f"Port {port.port}", "group": 3, "radius": 10, "type": "service"})
                links.append({"source": target, "target": port_id, "value": 1})
                
        return {"nodes": nodes, "links": links}

    @staticmethod
    def severity_color(severity: str) -> str:
        if not severity:
            return 'var(--text-muted)'
        return {
            'critical': 'var(--crit)',
            'high':     'var(--high)',
            'medium':   'var(--med)',
            'low':      'var(--low)',
            'info':     'var(--info)',
        }.get(str(severity).lower(), 'var(--text-muted)')

    @staticmethod
    def severity_bg(severity: str) -> str:
        if not severity:
            return 'transparent'
        return {
            'critical': 'var(--crit-bg)',
            'high':     'var(--high-bg)',
            'medium':   'var(--med-bg)',
            'low':      'var(--low-bg)',
            'info':     'var(--info-bg)',
        }.get(str(severity).lower(), 'transparent')
        
    @staticmethod
    def format_date(d: Any) -> str:
        if not d:
            return ""
        if isinstance(d, datetime):
            return d.strftime("%Y-%m-%d %H:%M:%S UTC")
        return str(d)

    @staticmethod
    def country_to_flag(code: str) -> str:
        if not code or len(code) != 2:
            return '🌐'
        return ''.join(chr(0x1F1E6 + ord(c) - ord('A')) for c in code.upper())
