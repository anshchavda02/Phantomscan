"""
YAML Vulnerability Rule Engine for PhantomScan.

This module parses Nuclei/Xray style YAML templates and executes them against targets.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any
import yaml
import aiohttp

from phantomscan.models import Observation


class RuleEngine:
    def __init__(self, rules_dir: str = "rules"):
        self.rules_dir = Path(rules_dir)
        self.rules = self._load_rules()

    def _load_rules(self) -> list[dict[str, Any]]:
        """Load all YAML rules from the rules directory."""
        rules = []
        if not self.rules_dir.exists():
            return rules
            
        for path in self.rules_dir.rglob("*.yaml"):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    rule = yaml.safe_load(f)
                    if rule and "id" in rule and "requests" in rule:
                        rules.append(rule)
            except Exception as e:
                print(f"Failed to load rule {path}: {e}")
        return rules

    async def _execute_rule(self, session: aiohttp.ClientSession, target: str, rule: dict[str, Any], observations: list[Observation]) -> None:
        """Execute a single rule against a target."""
        base_url = f"http://{target}" if not target.startswith("http") else target
        
        for req in rule.get("requests", []):
            method = req.get("method", "GET").upper()
            paths = req.get("path", [])
            
            for path_template in paths:
                url = path_template.replace("{{BaseURL}}", base_url)
                try:
                    async with session.request(method, url, timeout=aiohttp.ClientTimeout(total=5)) as response:
                        text = await response.text()
                        status = response.status
                        
                        if self._match_response(req, status, text):
                            info = rule.get("info", {})
                            observations.append(
                                Observation(
                                    name="yaml_rule_match",
                                    value={
                                        "id": rule.get("id"),
                                        "name": info.get("name"),
                                        "severity": info.get("severity"),
                                        "matched_url": url
                                    },
                                    source="yaml_engine"
                                )
                            )
                            return # Stop processing paths for this request if one matches
                except Exception:
                    pass

    def _match_response(self, request_def: dict[str, Any], status: int, body: str) -> bool:
        """Check if a response matches the rule criteria."""
        matchers = request_def.get("matchers", [])
        if not matchers:
            return False
            
        condition = request_def.get("matchers-condition", "or").lower()
        results = []
        
        for matcher in matchers:
            m_type = matcher.get("type")
            if m_type == "status":
                expected_statuses = matcher.get("status", [])
                results.append(status in expected_statuses)
            elif m_type == "word":
                words = matcher.get("words", [])
                w_condition = matcher.get("condition", "or").lower()
                word_matches = [w in body for w in words]
                
                if w_condition == "and":
                    results.append(all(word_matches) if word_matches else False)
                else:
                    results.append(any(word_matches) if word_matches else False)
            else:
                results.append(False) # Unknown matcher
                
        if condition == "and":
            return all(results) if results else False
        return any(results) if results else False


async def run_yaml_rules(target: str, observations: list[Observation]) -> None:
    """Entry point to execute all loaded rules against a target."""
    engine = RuleEngine()
    if not engine.rules:
        return
        
    resolver = aiohttp.ThreadedResolver()
    connector = aiohttp.TCPConnector(ssl=False, resolver=resolver)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [engine._execute_rule(session, target, rule, observations) for rule in engine.rules]
        await asyncio.gather(*tasks)
