"""Data models for the HTML report system."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
from phantomscan.models import Confidence, Finding, Severity

@dataclass
class ModuleStatus:
    name: str
    status: str
    duration: float
    findings: int
    engine: str

@dataclass
class ScanResult:
    target: str
    timestamp: str
    duration_seconds: float
    profile: str
    modules_executed: List[ModuleStatus]
    scan_id: str

@dataclass
class WhoisData:
    registrar: str = ""
    registration_date: str = ""
    expiry_date: str = ""
    updated_date: str = ""
    registrant_org: str = ""
    country: str = ""
    name_servers: List[str] = field(default_factory=list)
    status: List[str] = field(default_factory=list)
    dnssec: bool = False
    days_remaining: int = 0

@dataclass
class DNSRecords:
    A: List[str] = field(default_factory=list)
    AAAA: List[str] = field(default_factory=list)
    MX: List[str] = field(default_factory=list)
    NS: List[str] = field(default_factory=list)
    TXT: List[str] = field(default_factory=list)
    CNAME: List[str] = field(default_factory=list)
    SOA: List[str] = field(default_factory=list)
    CAA: List[str] = field(default_factory=list)

@dataclass
class Subdomain:
    subdomain: str
    ips: List[str]
    status: str
    title: str = ""
    source: str = ""
    interesting: bool = False
    different_ip: bool = False

@dataclass
class IPIntel:
    ip: str
    country: str = ""
    city: str = ""
    hosting: str = ""
    asn: str = ""
    isp: str = ""
    datacenter: bool = False
    proxy_vpn: bool = False
    hostname: str = ""

@dataclass
class SSLResult:
    grade: str = ""
    expiry_days: int = 0
    common_name: str = ""
    sans: List[str] = field(default_factory=list)
    issuer: str = ""
    chain_depth: int = 0
    protocols: Dict[str, bool] = field(default_factory=dict)
    hsts: Dict[str, Any] = field(default_factory=dict)
    ct: bool = False
    ocsp: bool = False
    http2: bool = False
    http3: bool = False

@dataclass
class Technology:
    name: str
    category: str
    version: str = ""
    confidence: int = 0
    cves: int = 0

@dataclass
class EmailSecurityData:
    spf: Any = False
    dmarc: Any = False
    dkim: Any = False
    spf_record: str = ""
    dmarc_record: str = ""
    score: int = 0
    mx_records: List[Dict[str, str]] = field(default_factory=list)
    provider: str = ""
    domain: str = ""

@dataclass
class PortResult:
    port: int
    service: str
    version: str = ""
    banner: str = ""
    risk: str = "safe"
    explanation: str = ""
    recommendation: str = ""

@dataclass
class IntelligenceData:
    whois: WhoisData = field(default_factory=WhoisData)
    dns: DNSRecords = field(default_factory=DNSRecords)
    subdomains: List[Subdomain] = field(default_factory=list)
    ip_info: List[IPIntel] = field(default_factory=list)
    ssl: SSLResult = field(default_factory=SSLResult)
    tech_stack: List[Technology] = field(default_factory=list)
    email_security: EmailSecurityData = field(default_factory=EmailSecurityData)
    open_ports: List[PortResult] = field(default_factory=list)

@dataclass
class ChainFinding:
    id: str
    name: str
    severity: str
    description: str
    components: List[Finding]
    steps: List[Any]
    impact: str = ""

@dataclass(frozen=True)
class CVEFinding(Finding):
    cvss: float = 0.0
    affected_versions: List[str] = field(default_factory=list)
    verification_status: str = "NEEDS VERIFICATION"
    patch_version: str = ""

@dataclass
class APISecurityData:
    endpoints: List[Dict[str, Any]] = field(default_factory=list)
    auth_issues: List[Dict[str, Any]] = field(default_factory=list)
    graphql_endpoints: List[Dict[str, Any]] = field(default_factory=list)
    websocket_endpoints: List[Dict[str, Any]] = field(default_factory=list)
    mobile_apis: List[Dict[str, Any]] = field(default_factory=list)

@dataclass
class SupplyChainData:
    secrets: List[Dict[str, str]] = field(default_factory=list)
    external_scripts: List[Dict[str, Any]] = field(default_factory=list)
    dependencies: List[Dict[str, Any]] = field(default_factory=list)
    dependency_confusion: List[Dict[str, Any]] = field(default_factory=list)
    slopsquatting: List[Dict[str, Any]] = field(default_factory=list)

@dataclass
class ThreatIntelReport:
    reputation: List[Dict[str, Any]] = field(default_factory=list)
    breaches: List[Dict[str, Any]] = field(default_factory=list)

@dataclass
class AttackPathMap:
    d3_json: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ComplianceData:
    frameworks: List[Dict[str, Any]] = field(default_factory=list)

@dataclass
class ChecklistData:
    categories: List[Dict[str, Any]] = field(default_factory=list)

@dataclass
class Screenshot:
    url: str = ""
    image_base64: str = ""
    status: str = "200"
    interesting: bool = False
    data_uri: str = ""
    title: str = "Page Screenshot"
    description: str = "Automated visual rendering"
    timestamp: str = ""
    related_finding_id: str = ""

@dataclass
class SuppressedFinding:
    title: str
    reason: str
    rule: str

@dataclass
class DiffData:
    new_findings: int = 0
    resolved_findings: int = 0
    changed_findings: int = 0
    same_findings: int = 0
    score_delta: int = 0
    new_list: List[Finding] = field(default_factory=list)
    resolved_list: List[Finding] = field(default_factory=list)

@dataclass
class Score:
    value: int = 0
    grade: str = "F"
    delta: int = 0
    categories: List[int] = field(default_factory=lambda: [0, 0, 0, 0, 0, 0])

@dataclass
class ScoreHistory:
    date: str
    value: int

@dataclass
class EngagementProfile:
    client: str = ""
    assessor: str = ""
    engagement_type: str = ""
    reference: str = ""
    date: str = ""

@dataclass
class ScanData:
    scan_meta: ScanResult
    intel: IntelligenceData
    findings: List[Finding]
    chains: List[ChainFinding]
    cves: List[CVEFinding]
    api_data: APISecurityData
    cloud_findings: List[Finding]
    supply_chain: SupplyChainData
    threat_intel: ThreatIntelReport
    attack_paths: AttackPathMap
    compliance: ComplianceData
    checklist: ChecklistData
    screenshots: List[Screenshot]
    fp_log: List[SuppressedFinding]
    diff: DiffData
    score: Score
    engagement: EngagementProfile
    score_history: List[ScoreHistory]
