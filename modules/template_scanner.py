"""High-performance Concurrent Template Scanner for PhantomScan."""
from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any, Optional

from modules.catch_all_detector import CatchAllDetector, CatchAllResult
from modules.template_executor import TemplateExecutor
from modules.template_loader import TemplateLoader, Template
from phantomscan.models import Finding

logger = logging.getLogger(__name__)


class TemplateScanner:
    """Discovers, filters, and executes YAML security templates concurrently."""

    def __init__(self, http_client: Any) -> None:
        self.http = http_client
        self.executor = TemplateExecutor(http_client=self.http)
        self.loader = TemplateLoader()

    async def scan(
        self,
        target: str,
        template_dir: Path | str,
        tags: Optional[list[str]] = None,
        severity: Optional[list[str]] = None,
        max_concurrent: int = 10,
        catch_all: Optional[CatchAllResult] = None,
    ) -> list[Finding]:
        """Scan target with all applicable YAML templates."""
        dir_path = Path(template_dir)
        if not dir_path.exists():
            logger.warning("Templates directory not found: %s", dir_path)
            return []

        # 1. Detect catch-all server if not already provided
        if catch_all is None:
            try:
                detector = CatchAllDetector(http_client=self.http)
                catch_all = await detector.detect(target)
            except Exception as e:
                logger.debug("Catch-all detection failed: %s", e)
                catch_all = CatchAllResult(has_catch_all=False)

        # 2. Load templates
        all_templates = self.loader.load_directory(dir_path)

        # Filter by tags if specified
        if tags:
            tag_set = {t.strip().lower() for t in tags}
            templates = [
                t for t in all_templates
                if any(t_tag in tag_set for t_tag in t.info.tags)
            ]
        else:
            templates = all_templates

        # Filter by severity if specified
        if severity:
            sev_set = {s.strip().lower() for s in severity}
            templates = [t for t in templates if t.info.severity in sev_set]

        if not templates:
            logger.debug("No templates matched filters (tags=%s, severity=%s)", tags, severity)
            return []

        # 3. Concurrent Execution with Semaphore
        semaphore = asyncio.Semaphore(max_concurrent)

        async def _run_template(tmpl: Template) -> Optional[Finding]:
            async with semaphore:
                try:
                    return await self.executor.execute(tmpl, target, catch_all=catch_all)
                except Exception as e:
                    logger.debug("Template %s error on %s: %s", tmpl.id, target, e)
                    return None

        tasks = [_run_template(tmpl) for tmpl in templates]
        results = await asyncio.gather(*tasks)

        # 4. Deduplicate findings
        findings: list[Finding] = []
        seen_keys: set[str] = set()

        for res in results:
            if res is not None:
                dedup_key = f"{res.id}:{res.title}:{res.target}"
                if dedup_key not in seen_keys:
                    seen_keys.add(dedup_key)
                    findings.append(res)

        logger.info(
            "Template scan completed for %s: executed %d templates, found %d findings",
            target,
            len(templates),
            len(findings),
        )
        return findings
