"""Report generation for PhantomScan."""
from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from phantomscan.report_models import ScanData


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


def dict_to_finding(f_dict: dict) -> Any:
    """Helper to safely wrap a dict into a mock finding object."""
    from phantomscan.models import Finding
    try:
        return Finding.from_dict(f_dict)
    except:
        return f_dict

def write_html_report(path: Path, payload: dict[str, Any]) -> None:
    """Legacy wrapper to convert payload to ScanData and generate HTML."""
    from phantomscan.report_models import (
        ScanData, ScanResult, IntelligenceData, Score, 
        ScoreHistory, DiffData, ChecklistData, ComplianceData,
        AttackPathMap, ThreatIntelReport, SupplyChainData,
        APISecurityData, EngagementProfile
    )
    
    # Map payload to the new dataclasses for Jinja2
    scan_meta = ScanResult(
        target=payload.get("target", "Unknown"),
        timestamp=payload.get("finished_at", datetime.utcnow().isoformat()),
        duration_seconds=payload.get("duration", 0.0),
        profile=payload.get("profile", "default"),
        modules_executed=[],
        scan_id=payload.get("scan_id", "local")
    )
    
    findings = [dict_to_finding(f) for f in payload.get("findings", [])]
    suppressed = payload.get("suppressed_findings", [])
    
    scan_data = ScanData(
        scan_meta=scan_meta,
        intel=IntelligenceData(),
        findings=findings,
        chains=[],
        cves=[f for f in findings if getattr(f, 'id', '').startswith("CVE")],
        api_data=APISecurityData(),
        cloud_findings=[],
        supply_chain=SupplyChainData(),
        threat_intel=ThreatIntelReport(),
        attack_paths=AttackPathMap(),
        compliance=ComplianceData(),
        checklist=ChecklistData(),
        screenshots=[],
        fp_log=suppressed,
        diff=DiffData(),
        score=Score(value=payload.get("score", 0), grade=payload.get("grade", "F")),
        engagement=EngagementProfile(),
        score_history=[]
    )
    
    generator = ReportGenerator(template_dir=str(Path(__file__).parent.parent / "templates"))
    generator.generate_html(scan_data, str(path))


class ReportGenerator:
    """Jinja2-based HTML report generator."""
    def __init__(self, template_dir: str = "templates"):
        self.env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(['html']),
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
        self.env.filters['mask_secret'] = lambda s: s[:8] + '***' if len(s) > 8 else '***'
        
        # Additional filters that the template might need
        self.env.filters['cwe_link'] = lambda cwe: f"https://cwe.mitre.org/data/definitions/{cwe.replace('CWE-', '')}.html" if cwe else "#"
        self.env.filters['owasp_link'] = lambda owasp: f"https://owasp.org/www-project-top-ten/2017/{owasp}.html" if owasp else "#"

    def generate_html(self, scan_data: ScanData, output_path: str) -> str:
        template = self.env.get_template('report.html.j2')

        findings_grouped = self.group_findings(scan_data.findings)
        chart_data = self.prepare_chart_data(scan_data)
        d3_data = scan_data.attack_paths.d3_json if scan_data.attack_paths else {}

        html = template.render(
            scan=scan_data.scan_meta,
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
            d3_data=json.dumps(d3_data),
            compliance=scan_data.compliance,
            checklist=scan_data.checklist,
            screenshots=scan_data.screenshots,
            fp_log=scan_data.fp_log,
            diff=scan_data.diff,
            score=scan_data.score,
            engagement=scan_data.engagement,
            chart_data=json.dumps(chart_data),
            generated_at=datetime.utcnow().isoformat(),
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
                'data': getattr(scan_data.score, 'categories', [0]*6) if hasattr(scan_data.score, 'categories') else [0]*6,
            }
        }

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
