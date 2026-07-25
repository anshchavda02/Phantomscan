"""Advanced security testing modules for PhantomScan.

Each module is a standalone async class that accepts a RobustHTTPClient and
returns a list of Finding dicts.  The :func:`get_all_modules` factory returns
name→class pairs for the orchestrator.
"""

from __future__ import annotations

from typing import Any, Type

# Lazy imports to avoid circular dependencies — each module is imported only
# when the orchestrator actually instantiates it.

MODULE_REGISTRY: dict[str, str] = {
    "business_logic":       ".business_logic.BusinessLogicAnalyzer",
    "idor":                 ".idor_detector.IDORDetector",
    "vuln_chain":           ".vuln_chain.VulnChainEngine",
    "jwt_oauth":            ".jwt_oauth.JWTOAuthTester",
    "oob_detector":         ".oob_detector.OOBDetector",
    "race_condition":       ".race_condition.RaceConditionDetector",
    "http_smuggling":       ".http_smuggling.HTTPSmugglingDetector",
    "ssrf":                 ".ssrf_detector.SSRFDetector",
    "prototype_pollution":  ".prototype_pollution.PrototypePollutionDetector",
    "graphql":              ".graphql_tester.GraphQLTester",
    "websocket":            ".websocket_tester.WebSocketTester",
    "supply_chain":         ".supply_chain.SupplyChainAnalyzer",
    "cloud_metadata":       ".cloud_metadata.CloudMetadataDetector",
    "second_order":         ".second_order.SecondOrderDetector",
    "auth_session":         ".auth_session.AuthSessionManager",
    "compliance":           ".compliance.ComplianceReporter",
    "continuous_monitor":   ".continuous_monitor.ContinuousMonitor",
    "ai_narrative":         ".ai_narrative.AINarrativeReporter",
    "stateful_scanner":     ".stateful_scanner.StatefulScanner",
    "attack_path":          ".attack_path.AttackPathBuilder",
}


def get_module_class(name: str) -> Type[Any]:
    """Import and return the class for the given module *name*."""
    import importlib

    dotted = MODULE_REGISTRY[name]
    module_path, class_name = dotted.rsplit(".", 1)
    mod = importlib.import_module(module_path, package=__name__)
    return getattr(mod, class_name)


def get_all_modules() -> dict[str, Type[Any]]:
    """Return a mapping of ``name → class`` for every registered module."""
    return {name: get_module_class(name) for name in MODULE_REGISTRY}


def list_module_names() -> list[str]:
    """Return the names of all available modules."""
    return list(MODULE_REGISTRY)
