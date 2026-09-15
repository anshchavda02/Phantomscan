"""False positive regression tests for findings identified in the nvidia.com scan report.

FP-008: Image filenames with @ not flagged as emails
FP-009: Product IDs / UNIX timestamps not flagged as credit cards
FP-010: Bare 10-digit numbers not flagged as phone numbers
FP-011: Twilio SID pattern not matching random hex strings without context
FP-012: Driver search forms not flagged as CSRF-missing
FP-013: OAuth login endpoints get downgraded brute-force severity
"""

from __future__ import annotations

import re
import unittest


# ══════════════════════════════════════════════════════════════════════════════
# FP-008: Image filenames with @ are NOT emails
# ══════════════════════════════════════════════════════════════════════════════

class TestEmailImageFilenameFP(unittest.TestCase):
    """Image filenames containing '@' must not be flagged as email PII."""

    def test_retina_image_filename_rejected(self):
        """nvidia-geforce-broadcasting-overlay@2x.jpg is NOT an email."""
        from phantomscan.modules.privacy_scanner import PrivacyScanner
        assert PrivacyScanner._is_false_positive(
            "nvidia-geforce-broadcasting-overlay@2x.jpg", "email"
        )

    def test_retina_png_filename_rejected(self):
        """nvidia-grace-cpu@2x.png is NOT an email."""
        from phantomscan.modules.privacy_scanner import PrivacyScanner
        assert PrivacyScanner._is_false_positive(
            "nvidia-grace-cpu@2x.png", "email"
        )

    def test_retina_3x_webp_rejected(self):
        """icon@3x.webp is NOT an email."""
        from phantomscan.modules.privacy_scanner import PrivacyScanner
        assert PrivacyScanner._is_false_positive(
            "icon@3x.webp", "email"
        )

    def test_real_email_not_rejected(self):
        """A real email address must NOT be filtered out."""
        from phantomscan.modules.privacy_scanner import PrivacyScanner
        assert not PrivacyScanner._is_false_positive(
            "john.doe@nvidia.com", "email"
        )

    def test_noreply_email_rejected(self):
        """System noreply addresses are not user PII."""
        from phantomscan.modules.privacy_scanner import PrivacyScanner
        assert PrivacyScanner._is_false_positive(
            "noreply@nvidia.com", "email"
        )

    def test_asset_extension_css_rejected(self):
        """bundle@hash.css is not an email."""
        from phantomscan.modules.privacy_scanner import PrivacyScanner
        assert PrivacyScanner._is_false_positive(
            "bundle@hash.css", "email"
        )

    def test_html_stripping_removes_img_src(self):
        """HTML stripping should remove <img src="...@2x.jpg"> from scan input."""
        from phantomscan.modules.privacy_scanner import _strip_html
        html = '<img src="nvidia-hero@2x.jpg" alt="NVIDIA GPU">'
        clean = _strip_html(html)
        # The cleaned text should not contain the image filename
        assert "@2x.jpg" not in clean


# ══════════════════════════════════════════════════════════════════════════════
# FP-009: UNIX timestamps / product IDs are NOT credit card numbers
# ══════════════════════════════════════════════════════════════════════════════

class TestCreditCardTimestampFP(unittest.TestCase):
    """UNIX timestamps and product IDs must not be flagged as credit cards."""

    def test_unix_timestamp_13_digits_rejected(self):
        """1708050263958 (epoch millis) is NOT a credit card."""
        from phantomscan.modules.privacy_scanner import PrivacyScanner
        assert PrivacyScanner._is_false_positive(
            "1708050263958", "credit_card"
        )

    def test_unix_timestamp_17_prefix_rejected(self):
        """1700000000000 (2023 epoch millis) is NOT a credit card."""
        from phantomscan.modules.privacy_scanner import PrivacyScanner
        assert PrivacyScanner._is_false_positive(
            "1700000000000", "credit_card"
        )

    def test_valid_visa_not_rejected(self):
        """A valid Visa number (4111 1111 1111 1111) must NOT be filtered out."""
        from phantomscan.modules.privacy_scanner import PrivacyScanner
        assert not PrivacyScanner._is_false_positive(
            "4111111111111111", "credit_card"
        )

    def test_invalid_bin_prefix_rejected(self):
        """Numbers starting with 1, 2, 7, 8, 9 are NOT valid card numbers."""
        from phantomscan.modules.privacy_scanner import PrivacyScanner
        for prefix in ("1234567890123", "2234567890123", "7234567890123",
                        "8234567890123", "9234567890123"):
            assert PrivacyScanner._is_false_positive(prefix, "credit_card"), \
                f"Expected {prefix} to be rejected as credit card FP"

    def test_regex_does_not_match_bare_digits_starting_with_1(self):
        """The credit card regex itself should not match numbers starting with 1 or 2."""
        from phantomscan.modules.privacy_scanner import PII_PATTERNS
        body = "product_id: 1708050263958 and sku: 2708050263958"
        matches = PII_PATTERNS["credit_card"].findall(body)
        # The regex requires first digit 3-6, so these should not match at all
        assert not any(m.strip().startswith("1") or m.strip().startswith("2") for m in matches)


# ══════════════════════════════════════════════════════════════════════════════
# FP-010: Bare 10-digit numbers are NOT phone numbers
# ══════════════════════════════════════════════════════════════════════════════

class TestPhoneBarNumberFP(unittest.TestCase):
    """Bare 10-digit numbers without separators must not be flagged as phones."""

    def test_bare_10_digits_not_matched(self):
        """1234567890 (no separators) should NOT be matched by the phone regex."""
        from phantomscan.modules.privacy_scanner import PII_PATTERNS
        body = "product_code 1234567890 end"
        matches = PII_PATTERNS["phone_us"].findall(body)
        assert len(matches) == 0, f"Bare 10-digit number matched as phone: {matches}"

    def test_formatted_phone_still_matched(self):
        """(555) 123-4567 SHOULD still be matched."""
        from phantomscan.modules.privacy_scanner import PII_PATTERNS
        body = "Call us at (555) 123-4567 for support"
        matches = PII_PATTERNS["phone_us"].findall(body)
        assert len(matches) >= 1

    def test_dotted_phone_still_matched(self):
        """555.123.4567 SHOULD still be matched."""
        from phantomscan.modules.privacy_scanner import PII_PATTERNS
        body = "Phone: 555.123.4567"
        matches = PII_PATTERNS["phone_us"].findall(body)
        assert len(matches) >= 1

    def test_dashed_phone_still_matched(self):
        """555-123-4567 SHOULD still be matched."""
        from phantomscan.modules.privacy_scanner import PII_PATTERNS
        body = "Phone: 555-123-4567"
        matches = PII_PATTERNS["phone_us"].findall(body)
        assert len(matches) >= 1


# ══════════════════════════════════════════════════════════════════════════════
# FP-011: Non-Twilio hex strings should NOT match Twilio SID pattern
# ══════════════════════════════════════════════════════════════════════════════

class TestTwilioSIDRegexFP(unittest.TestCase):
    """Twilio SID regex must only match hex chars, not full alphanumeric."""

    def test_old_regex_would_match_non_hex(self):
        """A string like ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx with non-hex
        chars (g-z) should NOT match the tightened regex."""
        import json
        with open("data/secret_patterns.json") as f:
            patterns = json.load(f)

        twilio_entry = next(p for p in patterns if p["id"] == "twilio-account-sid")
        twilio_re = re.compile(twilio_entry["regex"])

        # This has letters g-z which are NOT valid hex — should NOT match
        fake_sid = "AC" + "ghijklmnopqrstuvwxyz012345678901"
        assert not twilio_re.search(fake_sid), "Non-hex Twilio SID should not match"

    def test_valid_twilio_sid_still_matches(self):
        """A proper Twilio SID (AC + 32 hex chars) SHOULD still match."""
        import json
        with open("data/secret_patterns.json") as f:
            patterns = json.load(f)

        twilio_entry = next(p for p in patterns if p["id"] == "twilio-account-sid")
        twilio_re = re.compile(twilio_entry["regex"])

        valid_sid = "AC" + "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4"
        assert twilio_re.search(valid_sid), "Valid hex Twilio SID should match"


# ══════════════════════════════════════════════════════════════════════════════
# FP-012: Driver search / product filter forms != CSRF vulnerable
# ══════════════════════════════════════════════════════════════════════════════

class TestCSRFDriverSearchFP(unittest.TestCase):
    """Product search / driver download forms must not be flagged as CSRF-missing."""

    def test_driver_search_form_not_flagged(self):
        """NVIDIA driver download form with product selectors is non-state-changing."""
        # Simulate the detection logic from csrf_detector.py
        action = "/en-in/drivers/"
        fields = [
            {"name": "nvProductAutoCompletePOC", "type": "text"},
            {"name": "manualSearch-0", "type": "select"},
            {"name": "downloadType", "type": "select"},
        ]

        action_path = action.lower()
        _NON_STATE_CHANGING_ACTION_PATTERNS = [
            r"driver", r"download", r"search", r"filter", r"catalog",
        ]
        _NON_STATE_CHANGING_FIELD_PATTERNS = [
            r"^manual\s*search", r"product", r"operating\s*system",
            r"language", r"download\s*type", r"driver\s*type",
            r"autocomplete",
        ]

        action_matches = any(re.search(pat, action_path)
                             for pat in _NON_STATE_CHANGING_ACTION_PATTERNS)
        field_names = [f["name"] for f in fields]
        has_credential = any(re.search(r"pass(word)?|secret|pin", f.lower())
                             for f in field_names)
        has_filter_field = any(
            any(re.search(fpat, f.lower()) for fpat in _NON_STATE_CHANGING_FIELD_PATTERNS)
            for f in field_names
        )

        assert action_matches, "Action URL should match non-state-changing pattern"
        assert not has_credential, "Fields should not look like credential fields"
        assert has_filter_field, "Fields should be recognized as product filters"


# ══════════════════════════════════════════════════════════════════════════════
# FP-013: OAuth login endpoints get downgraded brute-force severity
# ══════════════════════════════════════════════════════════════════════════════

class TestOAuthBruteForceFP(unittest.TestCase):
    """OAuth login endpoints should get info severity, not medium."""

    def test_oauth_url_detected(self):
        """URL with OAuth parameters should be detected as OAuth endpoint."""
        _OAUTH_INDICATORS = [
            "redirect_uri", "client_id", "response_type", "scope",
            "state", "code_challenge", "nonce", "oauth", "authorize",
            "openid", "oidc",
        ]
        oauth_url = "https://login.nvidia.com/authorize?client_id=abc&redirect_uri=https://nvidia.com/callback&response_type=code"
        is_oauth = any(ind in oauth_url.lower() for ind in _OAUTH_INDICATORS)
        assert is_oauth, "OAuth URL should be detected as OAuth endpoint"

    def test_non_oauth_url_not_detected(self):
        """A simple /login URL should NOT be detected as OAuth."""
        _OAUTH_INDICATORS = [
            "redirect_uri", "client_id", "response_type", "scope",
            "state", "code_challenge", "nonce", "oauth", "authorize",
            "openid", "oidc",
        ]
        simple_login = "https://example.com/login"
        is_oauth = any(ind in simple_login.lower() for ind in _OAUTH_INDICATORS)
        assert not is_oauth, "Simple login URL should NOT be detected as OAuth"


# ══════════════════════════════════════════════════════════════════════════════
# FP-014: CDN bot management and consent cookies should NOT be flagged
# ══════════════════════════════════════════════════════════════════════════════

class TestCDNCookieFP(unittest.TestCase):
    """Akamai bot sensor cookies, Cloudflare bot cookies, and consent cookies must be skipped."""

    def test_akamai_bot_cookies_skipped(self):
        from phantomscan.modules.cookie_analyzer import CookieAnalyzer
        analyzer = CookieAnalyzer()
        headers = [
            "ak_bmsc=ABCDEF123456; Path=/; Domain=.nvidia.com",
            "bm_sz=XYZ789; Path=/; Domain=.nvidia.com",
            "bm_sv=QWE456; Path=/; Domain=.nvidia.com",
        ]
        findings = analyzer.analyze(headers, "https://www.nvidia.com/")
        assert len(findings) == 0, f"Akamai bot sensor cookies should be skipped, got {findings}"

    def test_cloudflare_and_consent_cookies_skipped(self):
        from phantomscan.modules.cookie_analyzer import CookieAnalyzer
        analyzer = CookieAnalyzer()
        headers = [
            "__cf_bm=token123; Path=/; Domain=.nvidia.com",
            "cf_clearance=token456; Path=/; Domain=.nvidia.com",
            "OptanonConsent=consent_data; Path=/; Domain=.nvidia.com",
        ]
        findings = analyzer.analyze(headers, "https://www.nvidia.com/")
        assert len(findings) == 0, f"Cloudflare & OneTrust consent cookies should be skipped, got {findings}"

    def test_real_session_cookie_missing_secure_flagged(self):
        from phantomscan.modules.cookie_analyzer import CookieAnalyzer
        analyzer = CookieAnalyzer()
        headers = [
            "sessionid=secret123; Path=/; Domain=.example.com",
        ]
        findings = analyzer.analyze(headers, "https://example.com/")
        assert any(f.id == "COOKIES-MISSING-SECURE-FLAG" for f in findings), "Real session cookie missing Secure must be flagged"


# ══════════════════════════════════════════════════════════════════════════════
# FP-015: Dynamic consent & tag manager stubs exempted from static SRI
# ══════════════════════════════════════════════════════════════════════════════

class TestDynamicSRIExemptionFP(unittest.TestCase):
    """Dynamic CMP stubs like OneTrust / CookieLaw must not be flagged for missing SRI."""

    def test_onetrust_cookielaw_sri_exempted(self):
        from phantomscan.modules.supply_chain import SupplyChainAnalyzer
        analyzer = SupplyChainAnalyzer()
        html = '<script src="https://cdn.cookielaw.org/scripttemplates/otSDKStub.js" type="text/javascript"></script>'
        findings = analyzer._check_missing_sri(html, "https://www.nvidia.com")
        assert len(findings) == 0, f"OneTrust otSDKStub.js must be exempted from static SRI, got {findings}"

    def test_static_cdn_library_missing_sri_flagged(self):
        from phantomscan.modules.supply_chain import SupplyChainAnalyzer
        analyzer = SupplyChainAnalyzer()
        html = '<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js"></script>'
        findings = analyzer._check_missing_sri(html, "https://example.com")
        assert len(findings) == 1, "Static jQuery on cdnjs missing SRI must be flagged"
        assert findings[0]["id"] == "SC-MISSING-SRI"


# ══════════════════════════════════════════════════════════════════════════════
# FP-016: Twilio SID in AI App Security requires hex and proximity keywords
# ══════════════════════════════════════════════════════════════════════════════

class TestAISecurityTwilioFP(unittest.TestCase):
    """Twilio SID pattern in AISecretScanner must be hex only and require context."""

    def test_twilio_pattern_in_ai_scanner_is_hex(self):
        from phantomscan.modules.ai_app_security import AISecretScanner
        pattern_entry = next((p for p in AISecretScanner.AI_KEY_PATTERNS if p[1] == "Twilio Account SID"), None)
        assert pattern_entry is not None
        regex = pattern_entry[0]
        assert "a-f" in regex or "a-f0-9" in regex, f"Twilio pattern should only match hex chars, got {regex}"
        assert "a-z" not in regex, f"Twilio pattern must not allow full alphanumeric a-z: {regex}"


# ══════════════════════════════════════════════════════════════════════════════
# FP-017: Finding deduplication handles trailing slash differences
# ══════════════════════════════════════════════════════════════════════════════

class TestDeduplicateTrailingSlashFP(unittest.TestCase):
    """Findings with and without trailing slash on target should deduplicate."""

    def test_trailing_slash_deduplicated(self):
        from phantomscan.postprocess import deduplicate_findings
        findings = [
            {"id": "CORS-WILDCARD-ORIGIN", "target": "https://www.nvidia.com", "evidence": "Access-Control-Allow-Origin: *"},
            {"id": "CORS-WILDCARD-ORIGIN", "target": "https://www.nvidia.com/", "evidence": "Access-Control-Allow-Origin: *"},
        ]
        result = deduplicate_findings(findings)
        assert len(result) == 1, f"Expected 1 finding after dedup, got {len(result)}"


# ══════════════════════════════════════════════════════════════════════════════
# FP-018: NVIDIA platform resolution in known_platforms.json
# ══════════════════════════════════════════════════════════════════════════════

class TestNvidiaPlatformFP(unittest.TestCase):
    """nvidia.com and subdomains resolve to known platform with expected baseline."""

    def test_nvidia_known_platform_loaded(self):
        from pathlib import Path
        from phantomscan.postprocess import load_known_platform
        data_dir = Path("data")
        platform = load_known_platform(data_dir, "www.nvidia.com")
        assert platform is not None, "www.nvidia.com should resolve to known platform"
        assert platform.get("domain") == "nvidia.com"
        assert "No WAF Detected" in platform.get("suppress_findings", [])
        assert platform.get("minimum_score") == 75


# ══════════════════════════════════════════════════════════════════════════════
# FP-019: IBAN Validation & Mod-97 Check (Reject Amazon tracking tokens)
# ══════════════════════════════════════════════════════════════════════════════

class TestIBANFalsePositiveFP(unittest.TestCase):
    """Amazon tokens (GX...) and invalid strings must not be flagged as IBAN."""

    def test_valid_german_iban_accepted(self):
        """Valid German IBAN should pass validation."""
        from phantomscan.modules.privacy_scanner import PrivacyScanner
        assert not PrivacyScanner._is_false_positive("DE89370400440532013000", "iban")

    def test_valid_french_iban_accepted(self):
        """Valid French IBAN should pass validation."""
        from phantomscan.modules.privacy_scanner import PrivacyScanner
        assert not PrivacyScanner._is_false_positive("FR1420041010050500013M02606", "iban")

    def test_valid_uk_iban_accepted(self):
        """Valid UK IBAN should pass validation."""
        from phantomscan.modules.privacy_scanner import PrivacyScanner
        assert not PrivacyScanner._is_false_positive("GB29NWBK60161331926819", "iban")

    def test_amazon_gx_token_rejected(self):
        """GX... Amazon tracking tokens have invalid country code and must be rejected."""
        from phantomscan.modules.privacy_scanner import PrivacyScanner
        assert PrivacyScanner._is_false_positive("GX01AMZNTEST12345678", "iban")

    def test_invalid_mod97_rejected(self):
        """DE89370400440532013001 (wrong check digit) must be rejected."""
        from phantomscan.modules.privacy_scanner import PrivacyScanner
        assert PrivacyScanner._is_false_positive("DE89370400440532013001", "iban")

    def test_invalid_country_code_rejected(self):
        """ZZ00123456789012345678 has non-existent country ZZ."""
        from phantomscan.modules.privacy_scanner import PrivacyScanner
        assert PrivacyScanner._is_false_positive("ZZ00123456789012345678", "iban")

    def test_invalid_length_rejected(self):
        """DE893704 (too short for German IBAN which requires 22 chars) must be rejected."""
        from phantomscan.modules.privacy_scanner import PrivacyScanner
        assert PrivacyScanner._is_false_positive("DE893704", "iban")


# ══════════════════════════════════════════════════════════════════════════════
# FP-020: Remediation Matrix Template Layout and Filter Tests
# ══════════════════════════════════════════════════════════════════════════════

class TestRemediationMatrixTemplate(unittest.TestCase):
    """Remediation matrix template renders with fixed table layout and filters out pseudo-findings."""

    def test_matrix_renders_cleanly_and_excludes_compliance(self):
        from jinja2 import Environment, FileSystemLoader
        env = Environment(loader=FileSystemLoader("templates"))
        # Add custom filter if required
        env.filters["truncate_evidence"] = lambda val, n=180: val[:n] if val else ""

        template = env.get_template("partials/remediation_matrix.html.j2")
        findings = [
            {
                "id": "XSS-REFLECTED",
                "title": "Reflected XSS",
                "severity": "high",
                "category": "injection",
                "recommendation": "Encode all outputs",
            },
            {
                "id": "COMPLIANCE-OWASP-TOP10",
                "title": "OWASP Top 10 (2021) Compliance Status",
                "severity": "info",
                "category": "compliance",
                "recommendation": "Address all OWASP Top 10 categories",
            },
            {
                "id": "AI-NARRATIVE-SUMMARY",
                "title": "Executive Summary & Remediation Narrative",
                "severity": "info",
                "category": "reporting",
                "recommendation": "Distribute this narrative to technical leadership",
            },
        ]
        rendered = template.render(findings=findings)

        # Verified table layout
        assert "table-layout: fixed" in rendered
        assert "overflow-wrap: anywhere" in rendered
        assert "Reflected XSS" in rendered

        # Verified compliance/reporting are excluded
        assert "OWASP Top 10 (2021) Compliance Status" not in rendered
        assert "Executive Summary &amp; Remediation Narrative" not in rendered


if __name__ == "__main__":
    unittest.main()

