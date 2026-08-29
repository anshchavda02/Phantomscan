"""Module 13 — Cloud Metadata Exposure Detector.

Probes for direct access to cloud metadata endpoints (AWS IMDSv1, GCP, Azure,
DigitalOcean), detects cloud provider fingerprints, and checks for S3 bucket
misconfigurations.
"""

from __future__ import annotations

import logging
import re
from typing import Any

from phantomscan.http_client import RobustHTTPClient

logger = logging.getLogger(__name__)

_CLOUD_HEADERS = {
    "AWS": ["x-amz-request-id", "x-amz-id-2", "x-amzn-requestid"],
    "GCP": ["x-cloud-trace-context", "x-goog-generation"],
    "Azure": ["x-ms-request-id", "x-ms-version", "x-azure-ref"],
    "CloudFlare": ["cf-ray", "cf-cache-status"],
}

_S3_PATTERNS = [
    re.compile(r"([a-z0-9.-]+)\.s3[.-][\w-]*\.amazonaws\.com", re.I),
    re.compile(r"s3[.-][\w-]*\.amazonaws\.com/([a-z0-9.-]+)", re.I),
    re.compile(r"([a-z0-9.-]+)\.storage\.googleapis\.com", re.I),
    re.compile(r"storage\.googleapis\.com/([a-z0-9.-]+)", re.I),
]


class CloudMetadataDetector:
    """Detect cloud metadata exposure and misconfigured storage buckets."""

    def __init__(self, http: RobustHTTPClient) -> None:
        self.http = http

    async def run(
        self,
        base_url: str,
        observations: list[dict[str, Any]],
        **kwargs: Any,
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        target = base_url.rstrip("/")

        # Test 1: Cloud provider fingerprinting from headers
        provider = self._detect_cloud_provider(observations)
        if provider:
            findings.append({
                "id": "CLOUD-PROVIDER-DETECTED",
                "title": f"Cloud Provider Detected: {provider}",
                "severity": "info",
                "confidence": "high",
                "category": "cloud",
                "target": target,
                "evidence": f"Cloud-specific headers indicate {provider} hosting.",
                "recommendation": (
                    "Ensure cloud-specific security best practices are followed. "
                    "Review IAM policies, network ACLs, and metadata service "
                    "configuration."
                ),
            })

        # Test 2: Check for exposed S3/GCS buckets from page content
        bucket_findings = await self._check_bucket_exposure(target, observations)
        findings.extend(bucket_findings)

        # Test 3: Direct metadata endpoint probe (only useful if the scanner
        # is running on the same network as the target)
        meta_findings = await self._probe_metadata_direct()
        findings.extend(meta_findings)

        return findings

    def _detect_cloud_provider(
        self, observations: list[dict[str, Any]]
    ) -> str | None:
        headers_text = ""
        for obs in observations:
            if obs.get("name") == "headers":
                val = obs.get("value", {})
                if isinstance(val, dict):
                    headers_text = " ".join(f"{k}: {v}" for k, v in val.items())
                else:
                    headers_text = str(val)
                break

        lower = headers_text.lower()
        for provider, header_names in _CLOUD_HEADERS.items():
            if any(h in lower for h in header_names):
                return provider
        return None

    async def _check_bucket_exposure(
        self, target: str, observations: list[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        # Gather all text content from observations
        all_text = ""
        for obs in observations:
            all_text += " " + str(obs.get("value", ""))

        # Also fetch main page
        try:
            response = await self.http.get(target + "/", retries=1)
            all_text += " " + response.text()
        except Exception:
            pass

        buckets: set[str] = set()
        for pattern in _S3_PATTERNS:
            for match in pattern.finditer(all_text):
                buckets.add(match.group(1))

        for bucket in list(buckets)[:5]:
            # Test S3 bucket for public access
            for bucket_url in [
                f"https://{bucket}.s3.amazonaws.com/",
                f"https://storage.googleapis.com/{bucket}/",
            ]:
                try:
                    resp = await self.http.get(bucket_url, retries=1)
                    body = resp.text()
                    if resp.status == 200 and (
                        "<ListBucketResult" in body
                        or "<ListAllMyBucketsResult" in body
                        or "Contents" in body
                    ):
                        findings.append({
                            "id": "CLOUD-BUCKET-PUBLIC",
                            "title": f"Cloud Storage Bucket Publicly Listable: {bucket}",
                            "severity": "high",
                            "confidence": "high",
                            "category": "cloud",
                            "target": bucket_url,
                            "evidence": (
                                f"Bucket {bucket} returns directory listing.\n"
                                f"Response preview: {body[:300]}"
                            ),
                            "recommendation": (
                                "Restrict bucket access using IAM policies and "
                                "bucket policies. Disable public listing. "
                                "Enable server-side encryption."
                            ),
                        })
                except Exception:
                    continue
        return findings

    async def _probe_metadata_direct(self) -> list[dict[str, Any]]:
        """Probe metadata endpoints directly (useful if scanner is in the cloud)."""
        import aiohttp as _aiohttp
        import asyncio

        findings: list[dict[str, Any]] = []
        probes = [
            ("AWS IMDSv1", "http://169.254.169.254/latest/meta-data/",
             {}, ["ami-id", "instance-id", "hostname"]),
            ("GCP", "http://metadata.google.internal/computeMetadata/v1/",
             {"Metadata-Flavor": "Google"}, ["project-id"]),
            ("Azure", "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
             {"Metadata": "true"}, ["compute", "vmId"]),
        ]

        async def probe_one(provider: str, url: str, headers: dict[str, str], signals: list[str]) -> dict[str, Any] | None:
            try:
                response = await self.http.get(
                    url, headers=headers, retries=1,
                    timeout=_aiohttp.ClientTimeout(total=1.5, connect=1.0),
                )
                body = response.text()
                if response.status == 200 and any(s in body for s in signals):
                    return {
                        "id": f"CLOUD-METADATA-DIRECT-{provider.split()[0].upper()}",
                        "title": f"Cloud Metadata Service Accessible ({provider})",
                        "severity": "critical",
                        "confidence": "high",
                        "category": "cloud",
                        "target": url,
                        "evidence": (
                            f"Direct access to {provider} metadata service.\n"
                            f"Response: {body[:500]}"
                        ),
                        "recommendation": (
                            f"For AWS: enforce IMDSv2 (require token). "
                            f"For all: restrict metadata access via network "
                            f"policies and firewall rules."
                        ),
                    }
            except Exception:
                pass
            return None

        results = await asyncio.gather(*(probe_one(*p) for p in probes), return_exceptions=True)
        for r in results:
            if isinstance(r, dict) and r:
                findings.append(r)
        return findings
