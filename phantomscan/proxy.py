"""
Passive Proxy Mode for PhantomScan.

This module uses mitmdump (the CLI component of mitmproxy) via a Python addon 
to intercept HTTP/HTTPS traffic from a browser or API client, and silently passes 
new endpoints and parameters directly into the YAML Rule Engine for vulnerability testing.
"""
import asyncio
import sys
from typing import Optional
from mitmproxy import http
from mitmproxy.tools.dump import DumpMaster
from mitmproxy.options import Options

from phantomscan.models import Observation
from phantomscan.rules_engine import run_yaml_rules

class PhantomProxyAddon:
    def __init__(self, target_scope: str):
        self.target_scope = target_scope
        self.seen_endpoints = set()
        self.observations: list[Observation] = []

    async def request(self, flow: http.HTTPFlow):
        """Intercept outbound requests before they hit the server."""
        url = flow.request.pretty_url
        if not url.startswith(f"http://{self.target_scope}") and not url.startswith(f"https://{self.target_scope}"):
            return # Ignore out-of-scope traffic
            
        # Strip query parameters and fragments for deduplication
        base_endpoint = url.split("?")[0].split("#")[0]
        
        if base_endpoint not in self.seen_endpoints:
            self.seen_endpoints.add(base_endpoint)
            # When we see a brand new endpoint in-scope, we throw it to our YAML vulnerability engine!
            # We don't block the proxy request, we run this analysis concurrently
            asyncio.create_task(run_yaml_rules(base_endpoint, self.observations))


def start_proxy(host: str, port: int, target_scope: str) -> None:
    """Start the mitmproxy passive interception listener."""
    print(f"[*] Starting Passive Proxy Mode on {host}:{port}")
    print(f"[*] Scope Locked to: {target_scope}")
    print(f"[*] Intercepted traffic will automatically trigger YAML vulnerability rules.")
    
    opts = Options(listen_host=host, listen_port=port)
    async def run_proxy():
        m = DumpMaster(opts, with_termlog=True, with_dumper=False)
        m.addons.add(PhantomProxyAddon(target_scope))
        try:
            await m.run()
        except KeyboardInterrupt:
            print("\n[+] Proxy shutting down...")
            
    if sys.platform == "win32":
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    asyncio.run(run_proxy())
