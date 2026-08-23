"""YAML Template Loader and Schema Validator for PhantomScan."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional
import yaml

logger = logging.getLogger(__name__)

VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}


@dataclass
class TemplateInfo:
    name: str
    author: str = "phantomscan"
    severity: str = "medium"
    description: str = ""
    tags: list[str] = field(default_factory=list)
    reference: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class RequestDefinition:
    method: str = "GET"
    path: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    redirects: bool = True
    matchers_condition: str = "and"
    matchers: list[dict[str, Any]] = field(default_factory=list)
    extractors: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class Template:
    id: str
    info: TemplateInfo
    requests: list[RequestDefinition]
    flow: Optional[str] = None
    raw: dict[str, Any] = field(default_factory=dict)
    file_path: Optional[Path] = None


class TemplateLoader:
    """Loads, validates, and indexes YAML templates from disk."""

    def __init__(self, templates_dir: Optional[Path | str] = None) -> None:
        self.templates_dir = Path(templates_dir) if templates_dir else None
        self._cache: dict[str, Template] = {}
        self._by_tag: dict[str, list[Template]] = {}
        self._by_severity: dict[str, list[Template]] = {}

    def parse_template_dict(self, data: dict[str, Any], file_path: Optional[Path] = None) -> Template:
        """Validate and parse a raw dictionary into a Template object."""
        if not isinstance(data, dict):
            raise ValueError("Template content must be a YAML dictionary")

        template_id = str(data.get("id", "")).strip()
        if not template_id:
            raise ValueError("Template missing required 'id' field")

        info_raw = data.get("info", {})
        if not isinstance(info_raw, dict):
            raise ValueError("Template missing required 'info' dictionary")

        name = str(info_raw.get("name", "")).strip()
        if not name:
            name = template_id

        severity = str(info_raw.get("severity", "medium")).strip().lower()
        if severity not in VALID_SEVERITIES:
            severity = "medium"

        tags_raw = info_raw.get("tags", "")
        if isinstance(tags_raw, str):
            tags = [t.strip().lower() for t in tags_raw.split(",") if t.strip()]
        elif isinstance(tags_raw, list):
            tags = [str(t).strip().lower() for t in tags_raw if str(t).strip()]
        else:
            tags = []

        refs = info_raw.get("reference", [])
        if isinstance(refs, str):
            refs = [refs]
        elif not isinstance(refs, list):
            refs = []

        metadata = info_raw.get("metadata", {})
        if not isinstance(metadata, dict):
            metadata = {}

        info = TemplateInfo(
            name=name,
            author=str(info_raw.get("author", "phantomscan")),
            severity=severity,
            description=str(info_raw.get("description", "")),
            tags=tags,
            reference=refs,
            metadata=metadata,
        )

        # Support both 'requests' and 'http' keys (Nuclei format compatibility)
        reqs_raw = data.get("requests") or data.get("http") or []
        if not isinstance(reqs_raw, list) or len(reqs_raw) == 0:
            raise ValueError("Template must contain at least one request definition in 'requests' or 'http'")

        requests: list[RequestDefinition] = []
        for r in reqs_raw:
            if not isinstance(r, dict):
                continue
            method = str(r.get("method", "GET")).upper()
            paths = r.get("path", [])
            if isinstance(paths, str):
                paths = [paths]
            elif not isinstance(paths, list):
                paths = []

            matchers = r.get("matchers", [])
            if not isinstance(matchers, list):
                matchers = []

            extractors = r.get("extractors", [])
            if not isinstance(extractors, list):
                extractors = []

            matchers_cond = str(r.get("matchers-condition", "and")).lower()
            if matchers_cond not in ("and", "or"):
                matchers_cond = "and"

            # Validate that matchers exist for the request if no explicit flow override
            if not matchers and not data.get("flow"):
                raise ValueError(f"Request in template '{template_id}' is missing matchers")

            requests.append(
                RequestDefinition(
                    method=method,
                    path=paths,
                    headers=r.get("headers", {}) if isinstance(r.get("headers"), dict) else {},
                    body=str(r.get("body", "")),
                    redirects=bool(r.get("redirects", True)),
                    matchers_condition=matchers_cond,
                    matchers=matchers,
                    extractors=extractors,
                )
            )

        if not requests:
            raise ValueError(f"Template '{template_id}' has no valid requests")

        flow = data.get("flow")

        template = Template(
            id=template_id,
            info=info,
            requests=requests,
            flow=str(flow) if flow else None,
            raw=data,
            file_path=file_path,
        )
        return template

    def load_template(self, path: Path | str) -> Template:
        """Load and validate a single YAML template file."""
        file_path = Path(path)
        if not file_path.exists():
            raise FileNotFoundError(f"Template file not found: {file_path}")

        with open(file_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        template = self.parse_template_dict(data, file_path=file_path)
        self._index_template(template)
        return template

    def load_directory(self, path: Optional[Path | str] = None) -> list[Template]:
        """Recursively discover and parse all *.yaml files in a directory."""
        dir_path = Path(path) if path else self.templates_dir
        if not dir_path or not dir_path.exists():
            logger.warning("Templates directory does not exist: %s", dir_path)
            return []

        templates: list[Template] = []
        for yaml_file in dir_path.rglob("*.yaml"):
            try:
                tmpl = self.load_template(yaml_file)
                templates.append(tmpl)
            except Exception as e:
                logger.warning("Failed to load template %s: %s", yaml_file, e)

        for yml_file in dir_path.rglob("*.yml"):
            try:
                tmpl = self.load_template(yml_file)
                templates.append(tmpl)
            except Exception as e:
                logger.warning("Failed to load template %s: %s", yml_file, e)

        return templates

    def _index_template(self, template: Template) -> None:
        """Index template by ID, tags, and severity in internal cache."""
        self._cache[template.id] = template

        for tag in template.info.tags:
            if tag not in self._by_tag:
                self._by_tag[tag] = []
            if template not in self._by_tag[tag]:
                self._by_tag[tag].append(template)

        sev = template.info.severity
        if sev not in self._by_severity:
            self._by_severity[sev] = []
        if template not in self._by_severity[sev]:
            self._by_severity[sev].append(template)

    def load_by_tags(self, tags: list[str]) -> list[Template]:
        """Return all indexed templates matching any of the given tags."""
        matched: set[str] = set()
        results: list[Template] = []
        for tag in tags:
            tag_clean = tag.strip().lower()
            for tmpl in self._by_tag.get(tag_clean, []):
                if tmpl.id not in matched:
                    matched.add(tmpl.id)
                    results.append(tmpl)
        return results

    def load_by_severity(self, severities: list[str]) -> list[Template]:
        """Return all indexed templates matching any of the given severities."""
        matched: set[str] = set()
        results: list[Template] = []
        for sev in severities:
            sev_clean = sev.strip().lower()
            for tmpl in self._by_severity.get(sev_clean, []):
                if tmpl.id not in matched:
                    matched.add(tmpl.id)
                    results.append(tmpl)
        return results

    def get_template_by_id(self, template_id: str) -> Optional[Template]:
        """Retrieve a template by its unique ID."""
        return self._cache.get(template_id)
