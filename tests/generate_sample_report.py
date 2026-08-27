import sys
from pathlib import Path
from datetime import datetime

from phantomscan.models import Finding
from phantomscan.report_models import (
    ScanData, ScanResult, IntelligenceData, WhoisData, DNSRecords, Subdomain,
    IPIntel, SSLResult, Technology, EmailSecurityData, PortResult, Score,
    DiffData, ChecklistData, ComplianceData, AttackPathMap,
    ThreatIntelReport, SupplyChainData, APISecurityData,
    EngagementProfile, ChainFinding
)
from phantomscan.reporting import ReportGenerator

def generate_sample_report():
    scan_meta = ScanResult(
        target="api.internal.acme-corp.com",
        timestamp=datetime.utcnow().isoformat(),
        duration_seconds=18.4,
        profile="deep",
        modules_executed=[
            {"name": "DNS Resolver", "status": "completed", "engine": "python", "duration": 0.3, "findings": 0, "timestamp": "10:14:02"},
            {"name": "WHOIS / RDAP", "status": "completed", "engine": "python", "duration": 0.4, "findings": 0, "timestamp": "10:14:02"},
            {"name": "Subdomain Enumerator", "status": "completed", "engine": "python", "duration": 1.2, "findings": 0, "timestamp": "10:14:03"},
            {"name": "TLS Inspector", "status": "completed", "engine": "rust", "duration": 0.2, "findings": 1, "timestamp": "10:14:04"},
            {"name": "Port Scanner (SYN)", "status": "completed", "engine": "go", "duration": 1.8, "findings": 2, "timestamp": "10:14:06"},
            {"name": "Technology Fingerprinter", "status": "completed", "engine": "python", "duration": 0.5, "findings": 0, "timestamp": "10:14:07"},
            {"name": "Email Security Check", "status": "completed", "engine": "python", "duration": 0.3, "findings": 0, "timestamp": "10:14:07"},
            {"name": "API Security Analyzer", "status": "completed", "engine": "python", "duration": 2.1, "findings": 3, "timestamp": "10:14:09"},
            {"name": "Secret Pattern Engine", "status": "completed", "engine": "python", "duration": 1.4, "findings": 2, "timestamp": "10:14:11"},
            {"name": "JWT / OAuth Tester", "status": "completed", "engine": "python", "duration": 1.1, "findings": 1, "timestamp": "10:14:12"},
            {"name": "SSRF & Cloud Metadata Prober", "status": "completed", "engine": "python", "duration": 1.9, "findings": 1, "timestamp": "10:14:14"},
            {"name": "Vulnerability Chain Engine", "status": "completed", "engine": "python", "duration": 0.8, "findings": 1, "timestamp": "10:14:15"},
            {"name": "Privacy & PII Scanner", "status": "completed", "engine": "python", "duration": 0.9, "findings": 1, "timestamp": "10:14:16"},
            {"name": "Attack Path Engine", "status": "completed", "engine": "python", "duration": 0.6, "findings": 0, "timestamp": "10:14:17"},
        ],
        scan_id="scn_9f82a17bc04e"
    )

    intel = IntelligenceData(
        whois=WhoisData(
            registrar="MarkMonitor Inc.",
            registration_date="2018-04-12",
            expiry_date="2027-04-12",
            updated_date="2025-03-01",
            name_servers=["ns1.acme-corp.com", "ns2.acme-corp.com"],
            status=["clientTransferProhibited"],
            days_remaining=410,
            registrant_org="ACME Security Holdings LLC",
            country="US"
        ),
        dns=DNSRecords(
            A=["198.51.100.42", "198.51.100.43"],
            AAAA=["2001:db8:85a3::8a2e:370:7334"],
            MX=["mail.acme-corp.com", "alt-mail.acme-corp.com"],
            NS=["ns1.acme-corp.com", "ns2.acme-corp.com"],
            TXT=["v=spf1 include:_spf.google.com ~all", "docusign=e2938472"],
            CNAME=["lb-ext.aws.acme-corp.com"]
        ),
        subdomains=[
            Subdomain(subdomain="auth.internal.acme-corp.com", ips=["198.51.100.44"], status="200"),
            Subdomain(subdomain="graphql.internal.acme-corp.com", ips=["198.51.100.45"], status="200"),
            Subdomain(subdomain="billing.internal.acme-corp.com", ips=["198.51.100.46"], status="200"),
            Subdomain(subdomain="staging.internal.acme-corp.com", ips=["198.51.100.47"], status="200"),
        ],
        ip_info=[
            IPIntel(ip="198.51.100.42", asn="AS16509", hosting="AWS us-east-1", country="US", city="Ashburn"),
            IPIntel(ip="198.51.100.43", asn="AS16509", hosting="AWS us-east-1", country="US", city="Ashburn"),
        ],
        ssl=SSLResult(
            grade="A+",
            expiry_days=245,
            common_name="*.internal.acme-corp.com",
            sans=["internal.acme-corp.com", "api.internal.acme-corp.com", "auth.internal.acme-corp.com"],
            issuer="DigiCert Global Root G2",
            protocols={"TLSv1.3": True, "TLSv1.2": True}
        ),
        tech_stack=[
            Technology(name="FastAPI", category="Web Framework", version="0.110.0"),
            Technology(name="Uvicorn", category="ASGI Server", version="0.28.0"),
            Technology(name="PostgreSQL", category="Database", version="16.2"),
            Technology(name="Redis", category="Cache", version="7.2.4"),
            Technology(name="AWS ALB", category="Load Balancer", version=""),
        ],
        email_security=EmailSecurityData(
            domain="acme-corp.com",
            spf=True,
            dkim=True,
            dmarc=True,
            score=9,
            mx_records=[{"host": "mail.acme-corp.com", "priority": "10"}, {"host": "alt-mail.acme-corp.com", "priority": "20"}]
        ),
        open_ports=[
            PortResult(port=80, service="http"),
            PortResult(port=443, service="https"),
            PortResult(port=8443, service="https-alt"),
            PortResult(port=6379, service="redis"),
        ]
    )

    findings = [
        Finding(
            id="FIND-001",
            title="Unauthenticated Redis Instance Exposed to Public Subnet",
            severity="critical",
            confidence="high",
            category="network",
            recommendation="Restrict port 6379 to VPC-internal access only via Security Group rules and enable requirepass authentication.",
            evidence="PORT 6379/TCP OPEN\nRESP PING -> +PONG\nINFO server -> redis_version:7.2.4\nKEYS * -> 14 keys found in db0",
            references=["https://redis.io/docs/management/security/", "https://nvd.nist.gov/vuln/detail/CVE-2022-0543"],
            cwe="CWE-306"
        ),
        Finding(
            id="FIND-002",
            title="Broken Object Level Authorization (BOLA) in User Profile Export",
            severity="high",
            confidence="high",
            category="api",
            recommendation="Implement object-level ownership checks verifying that the authenticated user ID matches the requested resource ID before returning profile records.",
            evidence="GET /v2/users/8942/export HTTP/1.1\nHost: api.internal.acme-corp.com\nAuthorization: Bearer <user_102_token>\n\nHTTP/1.1 200 OK\n{\"id\": 8942, \"email\": \"cfo@acme-corp.com\", \"ssn\": \"***-**-4912\", \"salary\": 245000}",
            references=["https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"],
            cwe="CWE-639"
        ),
        Finding(
            id="FIND-003",
            title="Hardcoded AWS Production IAM Access Key in Static Bundle",
            severity="high",
            confidence="high",
            category="auth",
            recommendation="Revoke the exposed access key AKIAIOSFODNN7EXAMPLE immediately in AWS IAM, audit CloudTrail logs, and migrate to IAM Roles for EC2/EKS.",
            evidence="Pattern Match: AKIA[0-9A-Z]{16}\nFile: /static/chunks/app.bundle.js:412\nMatches: AKIAIOSFODNN7EXAMPLE (verified active via sts:GetCallerIdentity)",
            references=["https://docs.aws.amazon.com/general/latest/gr/aws-access-keys-best-practices.html"],
            cwe="CWE-798"
        ),
        Finding(
            id="FIND-004",
            title="Server-Side Request Forgery (SSRF) via Webhook Verification",
            severity="medium",
            confidence="high",
            category="web",
            recommendation="Enforce strict allowlists of authorized target domains, disable following HTTP redirects, and block local/private IP ranges (127.0.0.0/8, 169.254.169.254, 10.0.0.0/8).",
            evidence="POST /api/webhooks/test\n{\"url\": \"http://169.254.169.254/latest/meta-data/\"}\n\nHTTP/1.1 200 OK\nami-id\nhostname\niam/\ninstance-id",
            references=["https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/"],
            cwe="CWE-918"
        ),
        Finding(
            id="FIND-005",
            title="Missing Strict-Transport-Security (HSTS) Header on Port 8443",
            severity="low",
            confidence="high",
            category="ssl",
            recommendation="Add Strict-Transport-Security: max-age=31536000; includeSubDomains; preload header to all TLS-enabled responses.",
            evidence="HTTP/1.1 200 OK\nHost: api.internal.acme-corp.com:8443\nMissing: Strict-Transport-Security",
            references=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"],
            cwe="CWE-523"
        )
    ]

    chains = [
        ChainFinding(
            id="CHAIN-001",
            name="Public Redis RCE to Cloud Metadata SSRF Compromise",
            severity="critical",
            description="An unauthenticated attacker connects to the exposed Redis port, injects a rogue webhook configuration payload, and pivots through the SSRF endpoint to query the AWS IMDSv1 instance metadata service to steal node credentials.",
            components=[],
            steps=[
                "Attacker connects to Redis instance exposed on port 6379 without authentication",
                "Attacker extracts internal API tokens and webhook configurations from db0 cache keys",
                "Attacker invokes the /api/webhooks/test endpoint passing AWS Instance Metadata Service IP (169.254.169.254)",
                "Attacker exfiltrates IAM Role temporary session credentials from IMDSv1"
            ],
            impact="Full node takeover and unauthorized lateral movement into the ACME AWS Production environment allowing access to all customer databases."
        )
    ]

    cves = []

    api_data = APISecurityData(
        endpoints=[
            {"method": "GET", "path": "/v2/users/{id}/export", "authenticated": True},
            {"method": "POST", "path": "/api/webhooks/test", "authenticated": False},
            {"method": "GET", "path": "/api/health", "authenticated": False},
            {"method": "POST", "path": "/v1/auth/login", "authenticated": False},
            {"method": "DELETE", "path": "/v2/users/{id}", "authenticated": True},
        ]
    )

    attack_paths = AttackPathMap()

    compliance = ComplianceData(
        frameworks=[
            {"name": "SOC 2 Type II", "passed": 18, "failed": 2, "failing_controls": ["CC6.1 - Access Control", "CC6.6 - Boundary Protection"]},
            {"name": "ISO 27001:2022", "passed": 24, "failed": 1, "failing_controls": ["A.8.20 - Network Security"]},
            {"name": "PCI DSS v4.0", "passed": 32, "failed": 3, "failing_controls": ["Req 1.3 - Inbound Traffic", "Req 8.3 - Strong Authentication", "Req 10.2 - Audit Logging"]},
        ]
    )

    checklist = ChecklistData(
        categories=[
            {
                "name": "Access Control",
                "items": [
                    {"task": "Verify Redis authentication requirepass directive in redis.conf", "context": "Port 6379 exposure", "module": "port_scanner"},
                    {"task": "Confirm IAM key AKIAIOSFODNN7EXAMPLE revocation in AWS Console", "context": "Hardcoded AWS Credential", "module": "secret_engine"}
                ]
            }
        ]
    )

    fp_log = [
        {
            "id": "FP-001",
            "title": "Suspected SQL Injection in /api/health",
            "severity": "high",
            "target": "https://api.internal.acme-corp.com/api/health?probe='OR'1'='1",
            "gate_rejection_reason": "Single timing anomaly did not replicate across 5 consecutive deterministic probes (jitter variance < 12ms)",
            "verification_method": "Statistical Timing Validation",
            "category": "web",
            "evidence": "Probe 1: 104ms, Probe 2: 22ms, Probe 3: 21ms, Probe 4: 20ms, Probe 5: 21ms"
        },
        {
            "id": "FP-002",
            "title": "Suspected Sensitive Path Exposure /admin",
            "severity": "medium",
            "target": "https://api.internal.acme-corp.com/admin",
            "suppression_reason": "Soft 404 SPA fallback page matched static index.html hash",
            "verification_method": "Differential Baseline Matcher",
            "category": "web",
            "evidence": "Status 200 returned but DOM body hash matches baseline 404 router redirect"
        }
    ]

    scan_data = ScanData(
        scan_meta=scan_meta,
        intel=intel,
        findings=findings,
        chains=chains,
        cves=cves,
        api_data=api_data,
        cloud_findings=[],
        supply_chain=SupplyChainData(),
        threat_intel=ThreatIntelReport(),
        attack_paths=attack_paths,
        compliance=compliance,
        checklist=checklist,
        screenshots=[],
        fp_log=fp_log,
        diff=DiffData(
            new_findings=2,
            resolved_findings=0
        ),
        score=Score(value=42, grade="D", delta=-5),
        engagement=EngagementProfile(client="Acme Financial Corp", assessor="PhantomScan Autonomous Engine", engagement_type="Authorized External Penetration Test", reference="ENG-2026-0842"),
        score_history=[]
    )

    gen = ReportGenerator(template_dir="templates")
    out_path = "tests/fixtures/sample_rendered_report.html"
    res = gen.generate_html(scan_data, out_path)
    print(f"Report successfully generated at: {res}")

if __name__ == "__main__":
    generate_sample_report()
