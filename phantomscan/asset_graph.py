"""Shared Attack-Surface & Asset Graph Model for PhantomScan.

Provides a unified in-memory graph representation of target entities:
- HostNode (domains, IPs, local network flags)
- ServiceNode (open ports, protocols, banners, TLS state)
- EndpointNode (URLs, HTTP methods, paths, status codes)
- ParameterNode (query, form, JSON, header inputs)
- TechnologyNode (fingerprinted frameworks, versions, confidence)
- AuthContextNode (session tokens, cookies, role identities)

Eliminates redundant network discovery across modules and enables
intelligent, technology-aware scan scheduling.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import logging
import re
from typing import Any, Optional
from urllib.parse import parse_qs, urljoin, urlparse, urlunparse

from phantomscan.models import Observation

logger = logging.getLogger(__name__)


# ── Graph Entity Nodes ────────────────────────────────────────────────────────


@dataclass
class HostNode:
    """A network host or domain asset."""
    hostname: str
    ip_addresses: list[str] = field(default_factory=list)
    is_local: bool = False
    root_domain: str = ""
    os_fingerprint: str = ""
    tags: list[str] = field(default_factory=list)


@dataclass
class ServiceNode:
    """A network service listening on an open port."""
    host: str
    port: int
    protocol: str = "tcp"
    service_name: str = ""
    banner: str = ""
    tls_enabled: bool = False
    risk_level: str = ""
    risk_note: str = ""

    @property
    def key(self) -> str:
        return f"{self.host.lower()}:{self.port}/{self.protocol.lower()}"


@dataclass
class EndpointNode:
    """An HTTP web or API endpoint."""
    url: str
    method: str = "GET"
    path: str = "/"
    status_code: int = 0
    content_type: str = ""
    auth_required: bool = False
    response_size: int = 0
    title: str = ""
    tags: list[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.method.upper()}:{self.url.strip()}"


@dataclass
class ParameterNode:
    """A discrete parameter or injectable input field."""
    url: str
    method: str = "GET"
    param_name: str = ""
    param_type: str = "query"  # "query", "form", "json", "header", "path"
    original_value: str = ""
    hidden_fields: dict[str, str] = field(default_factory=dict)
    all_params: dict[str, str] = field(default_factory=dict)

    @property
    def key(self) -> str:
        parsed = urlparse(self.url)
        path = parsed.path.rstrip("/") or "/"
        return f"{self.method.upper()}:{parsed.netloc.lower()}{path}:{self.param_name.strip()}"


@dataclass
class TechnologyNode:
    """A detected software technology, framework, or library."""
    name: str
    version: str = ""
    category: str = ""
    confidence: str = "medium"
    evidence: str = ""
    cpe: str = ""

    @property
    def key(self) -> str:
        return self.name.strip().lower()


@dataclass
class AuthContextNode:
    """An authenticated identity, session, or role context."""
    context_id: str
    role: str = "user"
    auth_type: str = "bearer"  # "bearer", "cookie", "basic", "api_key"
    token_or_cookie: str = ""
    headers: dict[str, str] = field(default_factory=dict)


# ── Asset Graph Container ─────────────────────────────────────────────────────


class AssetGraph:
    """Centralized, unified in-memory attack surface and asset graph."""

    def __init__(self) -> None:
        self.hosts: dict[str, HostNode] = {}
        self.services: dict[str, ServiceNode] = {}
        self.endpoints: dict[str, EndpointNode] = {}
        self.parameters: dict[str, ParameterNode] = {}
        self.technologies: dict[str, TechnologyNode] = {}
        self.auth_contexts: dict[str, AuthContextNode] = {}
        self.edges: list[dict[str, str]] = []

    def add_host(
        self,
        hostname: str,
        ip_addresses: list[str] | None = None,
        is_local: bool = False,
        root_domain: str = "",
        os_fingerprint: str = "",
        tags: list[str] | None = None,
    ) -> HostNode:
        """Register or update a host node."""
        clean_host = hostname.strip().lower()
        if clean_host not in self.hosts:
            self.hosts[clean_host] = HostNode(
                hostname=clean_host,
                ip_addresses=list(ip_addresses or []),
                is_local=is_local,
                root_domain=root_domain or clean_host,
                os_fingerprint=os_fingerprint,
                tags=list(tags or []),
            )
        else:
            existing = self.hosts[clean_host]
            if ip_addresses:
                for ip in ip_addresses:
                    if ip not in existing.ip_addresses:
                        existing.ip_addresses.append(ip)
            if tags:
                for t in tags:
                    if t not in existing.tags:
                        existing.tags.append(t)
        return self.hosts[clean_host]

    def add_service(
        self,
        host: str,
        port: int,
        protocol: str = "tcp",
        service_name: str = "",
        banner: str = "",
        tls_enabled: bool = False,
        risk_level: str = "",
        risk_note: str = "",
    ) -> ServiceNode:
        """Register or update an open network service node."""
        clean_host = host.strip().lower()
        self.add_host(clean_host)
        node = ServiceNode(
            host=clean_host,
            port=port,
            protocol=protocol.lower(),
            service_name=service_name,
            banner=banner,
            tls_enabled=tls_enabled or (port in (443, 8443)),
            risk_level=risk_level,
            risk_note=risk_note,
        )
        self.services[node.key] = node
        self.edges.append({"source": clean_host, "target": node.key, "type": "RUNS"})
        return node

    def add_endpoint(
        self,
        url: str,
        method: str = "GET",
        status_code: int = 0,
        content_type: str = "",
        auth_required: bool = False,
        response_size: int = 0,
        title: str = "",
        tags: list[str] | None = None,
    ) -> EndpointNode:
        """Register or update an HTTP endpoint node."""
        clean_url = url.strip()
        parsed = urlparse(clean_url)
        host = parsed.hostname or "localhost"
        self.add_host(host)

        node = EndpointNode(
            url=clean_url,
            method=method.upper().strip(),
            path=parsed.path or "/",
            status_code=status_code,
            content_type=content_type,
            auth_required=auth_required,
            response_size=response_size,
            title=title,
            tags=list(tags or []),
        )
        self.endpoints[node.key] = node
        self.edges.append({"source": host, "target": node.key, "type": "EXPOSES"})
        return node

    def add_parameter(
        self,
        url: str,
        method: str = "GET",
        param_name: str = "",
        param_type: str = "query",
        original_value: str = "",
        hidden_fields: dict[str, str] | None = None,
        all_params: dict[str, str] | None = None,
    ) -> ParameterNode | None:
        """Register or update an injection parameter node."""
        clean_pname = param_name.strip()
        if clean_pname.startswith("amp;"):
            clean_pname = clean_pname.removeprefix("amp;")
        if not clean_pname or clean_pname.lower() in {
            "__viewstate",
            "__viewstategenerator",
            "__eventvalidation",
            "__eventtarget",
            "__eventargument",
        }:
            return None

        # Ensure parent endpoint exists
        endpoint = self.add_endpoint(url=url, method=method)

        node = ParameterNode(
            url=url.strip(),
            method=method.upper().strip(),
            param_name=clean_pname,
            param_type=param_type,
            original_value=original_value or "test",
            hidden_fields=dict(hidden_fields or {}),
            all_params=dict(all_params or {clean_pname: original_value or "test"}),
        )
        self.parameters[node.key] = node
        self.edges.append({"source": endpoint.key, "target": node.key, "type": "ACCEPTS"})
        return node

    def add_technology(
        self,
        name: str,
        version: str = "",
        category: str = "",
        confidence: str = "medium",
        evidence: str = "",
        cpe: str = "",
    ) -> TechnologyNode:
        """Register or update a detected technology node."""
        clean_name = name.strip()
        key = clean_name.lower()
        if key not in self.technologies:
            node = TechnologyNode(
                name=clean_name,
                version=version,
                category=category,
                confidence=confidence,
                evidence=evidence,
                cpe=cpe,
            )
            self.technologies[key] = node
        else:
            node = self.technologies[key]
            if version and not node.version:
                node.version = version
            if evidence and not node.evidence:
                node.evidence = evidence
        return node

    def add_auth_context(
        self,
        context_id: str,
        role: str = "user",
        auth_type: str = "bearer",
        token_or_cookie: str = "",
        headers: dict[str, str] | None = None,
    ) -> AuthContextNode:
        """Register an authenticated identity / authorization context."""
        node = AuthContextNode(
            context_id=context_id,
            role=role,
            auth_type=auth_type,
            token_or_cookie=token_or_cookie,
            headers=dict(headers or {}),
        )
        self.auth_contexts[context_id] = node
        return node

    def has_technology(self, tech_name: str) -> bool:
        """Query if a given technology keyword exists in the graph."""
        clean = tech_name.strip().lower()
        return any(clean in key or clean in t.category.lower() for key, t in self.technologies.items())

    def get_technologies(self) -> list[TechnologyNode]:
        """Return all detected technologies."""
        return list(self.technologies.values())

    def get_injection_targets(self, max_targets: int = 100) -> list[Any]:
        """Export all parameters as InjectionTarget objects."""
        from phantomscan.injection_target import InjectionTarget

        targets: list[InjectionTarget] = []
        for param in self.parameters.values():
            if len(targets) >= max_targets:
                break
            targets.append(
                InjectionTarget(
                    url=param.url,
                    method=param.method,
                    param_name=param.param_name,
                    original_value=param.original_value,
                    all_params=dict(param.all_params),
                    hidden_fields=dict(param.hidden_fields),
                    target_type=param.param_type,
                )
            )
        return targets

    @classmethod
    def from_observations(cls, observations: list[dict[str, Any]], base_url: str = "") -> AssetGraph:
        """Construct a complete AssetGraph from raw scan observations."""
        graph = cls()
        clean_base = base_url.rstrip("/")

        if clean_base:
            parsed_base = urlparse(clean_base)
            host = parsed_base.hostname or "localhost"
            graph.add_host(host)
            graph.add_endpoint(clean_base, method="GET")

            # Direct base URL query params
            if "?" in clean_base:
                clean_url = urlunparse(parsed_base._replace(query=""))
                qs = parse_qs(parsed_base.query, keep_blank_values=True)
                all_p = {k: v[0] if v else "" for k, v in qs.items()}
                for pname, pval in all_p.items():
                    graph.add_parameter(
                        url=clean_url,
                        method="GET",
                        param_name=pname,
                        param_type="query",
                        original_value=pval or "test",
                        all_params=dict(all_p),
                    )

        for obs in observations:
            name = str(obs.get("name", ""))
            val = obs.get("value", "")

            # 1. DNS / WHOIS / Host intel
            if name == "dns_records" and isinstance(val, dict):
                for ip in val.get("A", []) + val.get("AAAA", []):
                    if clean_base:
                        host = urlparse(clean_base).hostname or clean_base
                        graph.add_host(host, ip_addresses=[str(ip)])

            # 2. Port scans & open services
            if name == "port_results" and isinstance(val, list):
                for p_res in val:
                    if isinstance(p_res, dict):
                        port_num = p_res.get("port")
                        if isinstance(port_num, int):
                            host = p_res.get("host") or (urlparse(clean_base).hostname if clean_base else "localhost")
                            graph.add_service(
                                host=host,
                                port=port_num,
                                protocol=p_res.get("protocol", "tcp"),
                                service_name=p_res.get("service", ""),
                                banner=p_res.get("banner", ""),
                                risk_level=p_res.get("risk_level", ""),
                                risk_note=p_res.get("risk_note", ""),
                            )

            # 3. Technologies
            if name in ("technologies", "tech_detected") and isinstance(val, (list, dict)):
                items = val if isinstance(val, list) else [val]
                for item in items:
                    if isinstance(item, dict):
                        graph.add_technology(
                            name=item.get("name", item.get("technology", "")),
                            version=item.get("version", ""),
                            category=item.get("category", ""),
                            confidence=item.get("confidence", "medium"),
                            evidence=item.get("evidence", ""),
                        )
                    elif isinstance(item, str):
                        graph.add_technology(name=item)

            # 4. URLs / Parameterized URLs
            if name in ("parameterized_urls", "discovered_urls", "http_url") and isinstance(val, (str, list)):
                url_list = [val] if isinstance(val, str) else val
                for u in url_list:
                    if isinstance(u, str) and u.startswith("http"):
                        parsed = urlparse(u)
                        clean_url = urlunparse(parsed._replace(query=""))
                        graph.add_endpoint(clean_url, method="GET")
                        if "?" in u:
                            qs = parse_qs(parsed.query, keep_blank_values=True)
                            all_p = {k: v[0] if v else "" for k, v in qs.items()}
                            for pname, pval in all_p.items():
                                graph.add_parameter(
                                    url=clean_url,
                                    method="GET",
                                    param_name=pname,
                                    param_type="query",
                                    original_value=pval or "test",
                                    all_params=dict(all_p),
                                )

            # 5. Discovered Forms
            if name == "discovered_forms" and isinstance(val, list):
                for form in val:
                    if not isinstance(form, dict):
                        continue
                    action = form.get("action", clean_base or "/")
                    if not action.startswith("http") and clean_base:
                        action = urljoin(clean_base + "/", action)
                    method = form.get("method", "POST").upper()
                    fields = form.get("fields", [])

                    all_inputs: dict[str, str] = {}
                    hidden_fields: dict[str, str] = {}
                    fuzzable_fields: list[tuple[str, str]] = []

                    injectable_types = {
                        "text", "search", "email", "password",
                        "number", "tel", "url", "textarea", "",
                    }

                    for fld in fields:
                        if isinstance(fld, dict):
                            fname = fld.get("name", "").strip()
                            ftype = fld.get("type", "text").lower()
                            fval = str(fld.get("value", ""))
                            if not fname:
                                continue

                            if ftype == "hidden":
                                hidden_fields[fname] = fval
                            elif ftype in injectable_types:
                                all_inputs[fname] = fval or "test"
                                fuzzable_fields.append((fname, fval))
                            else:
                                all_inputs[fname] = fval

                    for fname, fval in fuzzable_fields:
                        graph.add_parameter(
                            url=action,
                            method=method,
                            param_name=fname,
                            param_type="form",
                            original_value=fval or "test",
                            hidden_fields=dict(hidden_fields),
                            all_params=dict(all_inputs),
                        )

            # 6. Discovered API Routes
            if "discovered_api_routes" in name and isinstance(val, list):
                for route in val:
                    if isinstance(route, str) and not route.startswith("#"):
                        full_url = urljoin((clean_base or "http://localhost") + "/", route.lstrip("/"))
                        graph.add_endpoint(full_url, method="GET", tags=["api"])
                        for p in ("q", "search", "id", "query", "name"):
                            graph.add_parameter(
                                url=full_url,
                                method="GET",
                                param_name=p,
                                param_type="query",
                                original_value="test",
                                all_params={p: "test"},
                            )

        return graph

    def to_observations(self) -> list[dict[str, Any]]:
        """Serialize key graph statistics and discoveries into standard Observations."""
        obs: list[dict[str, Any]] = []

        if self.technologies:
            obs.append(
                Observation(
                    name="asset_graph_technologies",
                    value=[asdict(t) for t in self.technologies.values()],
                    source="asset_graph",
                ).to_dict()
            )

        if self.endpoints:
            obs.append(
                Observation(
                    name="asset_graph_endpoints_count",
                    value=len(self.endpoints),
                    source="asset_graph",
                ).to_dict()
            )

        if self.parameters:
            obs.append(
                Observation(
                    name="asset_graph_parameters_count",
                    value=len(self.parameters),
                    source="asset_graph",
                ).to_dict()
            )

        return obs

    def to_dict(self) -> dict[str, Any]:
        """Serialize complete graph representation to dictionary."""
        return {
            "hosts": {k: asdict(v) for k, v in self.hosts.items()},
            "services": {k: asdict(v) for k, v in self.services.items()},
            "endpoints": {k: asdict(v) for k, v in self.endpoints.items()},
            "parameters": {k: asdict(v) for k, v in self.parameters.items()},
            "technologies": {k: asdict(v) for k, v in self.technologies.items()},
            "auth_contexts": {k: asdict(v) for k, v in self.auth_contexts.items()},
            "edges": list(self.edges),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AssetGraph:
        """Instantiate graph from serialized dictionary."""
        graph = cls()
        for k, v in data.get("hosts", {}).items():
            graph.hosts[k] = HostNode(**v)
        for k, v in data.get("services", {}).items():
            graph.services[k] = ServiceNode(**v)
        for k, v in data.get("endpoints", {}).items():
            graph.endpoints[k] = EndpointNode(**v)
        for k, v in data.get("parameters", {}).items():
            graph.parameters[k] = ParameterNode(**v)
        for k, v in data.get("technologies", {}).items():
            graph.technologies[k] = TechnologyNode(**v)
        for k, v in data.get("auth_contexts", {}).items():
            graph.auth_contexts[k] = AuthContextNode(**v)
        graph.edges = list(data.get("edges", []))
        return graph
