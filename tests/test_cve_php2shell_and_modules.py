"""Test suite for updated CVE intelligence, PHP2Shell detection, and enhanced security modules."""

import pytest
from pathlib import Path
from unittest.mock import AsyncMock

from modules.cve_engine import CVEEngine, TechnologyVersion, build_cpe, version_in_range
from phantomscan.modules.cve_engine import CVEEngineScanner, normalize_tech
from phantomscan.modules.supply_chain import SupplyChainAnalyzer
from modules.sensitive_path_scanner import SensitivePathScanner
from modules.template_loader import TemplateLoader
from phantomscan.recon import detect_technologies


# ── 1. PHP2Shell & Curated CVE Engine Tests ───────────────────────────────────

def test_php2shell_detected_on_vulnerable_versions():
    """Verify PHP2Shell (CVE-2026-109618 and CVE-2026-109619) flags unpatched PHP versions."""
    engine = CVEEngine()

    # PHP 8.3.10 is vulnerable to PHP2Shell (< 8.3.36) and PHP-CGI (< 8.3.8 is false, so no CGI, but has PHP2Shell)
    tech = TechnologyVersion(vendor="php", product="php", version="8.3.10", evidence_methods=2)
    findings = engine._match_curated_cves(tech, "example.com")
    cve_ids = {f.id for f in findings}

    assert "CVE-2026-109618" in cve_ids
    assert "CVE-2026-109619" in cve_ids

    # Check finding details for PHP2Shell
    php2shell_oom = next(f for f in findings if f.id == "CVE-2026-109618")
    assert php2shell_oom.severity == "critical"
    assert php2shell_oom.confidence == "high"
    assert php2shell_oom.category == "cve"
    assert php2shell_oom.cvss_score == 9.8
    assert "8.5.12" in php2shell_oom.recommendation


def test_php2shell_suppressed_on_patched_versions():
    """Verify PHP2Shell is not reported on patched PHP releases (8.5.12, 8.4.27, 8.3.36, 8.2.35)."""
    engine = CVEEngine()

    for patched_ver in ["8.2.35", "8.3.36", "8.4.27", "8.5.12", "8.5.13"]:
        tech = TechnologyVersion(vendor="php", product="php", version=patched_ver, evidence_methods=2)
        findings = engine._match_curated_cves(tech, "example.com")
        cve_ids = {f.id for f in findings}
        assert "CVE-2026-109618" not in cve_ids, f"Should not flag patched version {patched_ver}"
        assert "CVE-2026-109619" not in cve_ids, f"Should not flag patched version {patched_ver}"


def test_php2shell_legacy_eol_versions():
    """Verify PHP 8.1, 8.0, 7.4 are flagged for PHP2Shell and other legacy flaws."""
    engine = CVEEngine()

    for eol_ver in ["8.1.2", "8.0.28", "7.4.33"]:
        tech = TechnologyVersion(vendor="php", product="php", version=eol_ver, evidence_methods=2)
        findings = engine._match_curated_cves(tech, "example.com")
        cve_ids = {f.id for f in findings}
        assert "CVE-2026-109618" in cve_ids
        assert "CVE-2026-109619" in cve_ids


def test_php_cgi_argument_injection_cve():
    """Verify CVE-2024-4577 is reported on PHP < 8.3.8."""
    engine = CVEEngine()
    tech = TechnologyVersion(vendor="php", product="php", version="8.3.4", evidence_methods=2)
    findings = engine._match_curated_cves(tech, "example.com")
    cve_ids = {f.id for f in findings}
    assert "CVE-2024-4577" in cve_ids


def test_apache_path_traversal_cve():
    """Verify CVE-2021-41773 is reported strictly on Apache 2.4.49."""
    engine = CVEEngine()
    tech_vuln = TechnologyVersion(vendor="apache", product="http_server", version="2.4.49", evidence_methods=2)
    findings_vuln = engine._match_curated_cves(tech_vuln, "example.com")
    assert any(f.id == "CVE-2021-41773" for f in findings_vuln)

    tech_safe = TechnologyVersion(vendor="apache", product="http_server", version="2.4.52", evidence_methods=2)
    findings_safe = engine._match_curated_cves(tech_safe, "example.com")
    assert not any(f.id == "CVE-2021-41773" for f in findings_safe)


def test_spring4shell_and_confluence_cves():
    """Verify Spring4Shell and Confluence OGNL CVE matching."""
    engine = CVEEngine()

    spring_tech = TechnologyVersion(vendor="spring", product="spring_framework", version="5.3.15", evidence_methods=2)
    spring_findings = engine._match_curated_cves(spring_tech, "example.com")
    assert any(f.id == "CVE-2022-22965" for f in spring_findings)

    confluence_tech = TechnologyVersion(vendor="atlassian", product="confluence_server", version="7.16.2", evidence_methods=2)
    confluence_findings = engine._match_curated_cves(confluence_tech, "example.com")
    assert any(f.id == "CVE-2022-26134" for f in confluence_findings)


@pytest.mark.asyncio
async def test_lookup_cves_offline_fallback():
    """Verify lookup_cves returns curated intelligence even if online NVD is not available."""
    engine = CVEEngine()
    engine._circuit_open = True  # simulate offline or circuit breaker tripped

    tech = TechnologyVersion(vendor="php", product="php", version="8.3.10", evidence_methods=2)
    findings = await engine.lookup_cves(tech, http_client=None, target_host="testserver.local")

    assert len(findings) >= 2
    assert any(f.id == "CVE-2026-109618" for f in findings)


# ── 2. Technology Normalization & Scanner DAG Adapter ─────────────────────────

def test_normalize_tech_helper():
    assert normalize_tech("PHP", "PHP") == ("php", "php")
    assert normalize_tech("Apache HTTP Server", "Apache") == ("apache", "http_server")
    assert normalize_tech("nginx", "nginx") == ("nginx", "nginx")
    assert normalize_tech("OpenSSL", "OpenSSL") == ("openssl", "openssl")
    assert normalize_tech("Spring Framework", "Spring") == ("spring", "spring_framework")


@pytest.mark.asyncio
async def test_cve_engine_scanner_dag_adapter():
    scanner = CVEEngineScanner(http=None)
    observations = [
        {
            "name": "technologies",
            "source": "tech",
            "value": [
                {"name": "PHP", "version": "8.3.12", "evidence_methods": 2},
            ],
        }
    ]
    findings = await scanner.run("https://app.example.com", observations)
    assert len(findings) >= 2
    f_ids = [f["id"] for f in findings]
    assert "CVE-2026-109618" in f_ids
    assert "CVE-2026-109619" in f_ids


# ── 3. Recon Compound Banner & Version Extraction ─────────────────────────────

def test_detect_technologies_compound_banner():
    obs = [
        {
            "name": "headers",
            "value": {
                "server": "Apache/2.4.49 (Ubuntu) PHP/8.1.2 OpenSSL/1.1.1f",
                "x-powered-by": "PHP/8.1.2",
            },
        }
    ]
    result = detect_technologies(obs)
    tech_list = result[0].value
    tech_names = {t["name"]: t.get("version", "") for t in tech_list}

    assert "Apache" in tech_names
    assert tech_names["Apache"] == "2.4.49"
    assert "PHP" in tech_names
    assert tech_names["PHP"] == "8.1.2"
    assert "OpenSSL" in tech_names
    assert tech_names["OpenSSL"] == "1.1.1f"


# ── 4. YAML CVE Rules Loading ─────────────────────────────────────────────────

def test_new_cve_templates_load_cleanly():
    rules_dir = Path(__file__).parent.parent / "rules" / "cve"
    loader = TemplateLoader()
    templates = loader.load_directory(rules_dir)

    template_ids = {t.id for t in templates}
    assert "php2shell-rce" in template_ids
    assert "php-cgi-arg-injection-rce" in template_ids
    assert "spring-core-rce" in template_ids
    assert "apache-path-traversal-rce" in template_ids
    assert "nginx-alias-traversal" in template_ids
    assert "confluence-ognl-injection" in template_ids
    assert "drupalgeddon2-rce" in template_ids
    assert "openssl-punycode-overflow" in template_ids


# ── 5. Sensitive Path Scanner PHP & Config Endpoints ──────────────────────────

def test_sensitive_path_scanner_php_paths():
    scanner = SensitivePathScanner(http_client=None)
    paths = [p["path"] for p in scanner.SENSITIVE_PATHS]

    assert "/phpinfo.php" in paths
    assert "/info.php" in paths
    assert "/php_info.php" in paths
    assert "/admin/phpinfo.php" in paths
    assert "/pma/" in paths
    assert "/.env.backup" in paths
    assert "/docker-compose.yml" in paths
    assert "/storage/logs/laravel.log" in paths


# ── 6. Supply Chain Analyzer: Vulnerable Libraries & Secrets ──────────────────

def test_supply_chain_vulnerable_libraries():
    analyzer = SupplyChainAnalyzer(http=None)

    html_content = """
    <html>
      <script src="/js/jquery-3.4.1.min.js"></script>
      <script src="/js/lodash-4.17.15.min.js"></script>
    </html>
    """
    findings = analyzer._detect_outdated_libraries(html_content)
    f_ids = {f["id"] for f in findings}

    assert "SC-VULN-CVE-2020-11022" in f_ids  # jQuery 3.4.1 < 3.5.0
    assert "SC-VULN-CVE-2020-8203" in f_ids   # Lodash 4.17.15 < 4.17.19


def test_supply_chain_modern_secret_detection():
    analyzer = SupplyChainAnalyzer(http=None)

    js_code = """
    const claudeKey = "sk-ant-api03-abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234";
    const supabaseSecret = "sb_secret_abcdef123456789012345678";
    """
    findings = analyzer._scan_for_secrets(js_code, "https://example.com")
    f_titles = [f["title"] for f in findings]

    assert any("Anthropic" in t for t in f_titles)
    assert any("Supabase" in t for t in f_titles)
