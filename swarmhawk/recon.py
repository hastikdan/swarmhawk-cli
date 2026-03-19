"""
swarmhawk.recon
===============
RECON Agent — attack surface enumeration.

Real tools used (if installed):
  - subfinder: passive subdomain enumeration
  - httpx: probe live HTTP/S endpoints
  - shodan API: exposed services on discovered IPs

Mock mode: generates realistic synthetic data when tools aren't installed.
This lets you demo and develop without the full toolchain.
"""

import json
import subprocess
import shutil
import socket
import logging
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import requests

logger = logging.getLogger("swarmhawk.recon")


@dataclass
class Asset:
    """A discovered asset in the attack surface."""
    url: str
    domain: str
    ip: Optional[str] = None
    port: int = 443
    scheme: str = "https"
    status_code: Optional[int] = None
    title: Optional[str] = None
    server: Optional[str] = None
    tech_stack: list = field(default_factory=list)
    open_ports: list = field(default_factory=list)
    discovered_by: str = "recon-agent"

    def to_dict(self) -> dict:
        return {
            "url": self.url, "domain": self.domain, "ip": self.ip,
            "port": self.port, "scheme": self.scheme,
            "status_code": self.status_code, "title": self.title,
            "server": self.server, "tech_stack": self.tech_stack,
            "open_ports": self.open_ports,
        }


class ReconAgent:
    """
    Passive + active reconnaissance agent.

    Usage:
        agent = ReconAgent(scope, audit)
        assets = agent.run("acme-corp.com")
    """

    # Subdomains to try when subfinder isn't available
    COMMON_SUBDOMAINS = [
        "www", "api", "admin", "mail", "vpn", "dev", "staging",
        "portal", "auth", "app", "cdn", "static", "assets",
        "jenkins", "gitlab", "grafana", "prometheus", "jira",
        "confluence", "help", "support", "docs", "beta",
    ]

    # Mock data for demo/test mode
    MOCK_ASSETS = [
        {"sub": "",         "status": 200, "server": "nginx/1.24.0",     "title": "ACME Corp"},
        {"sub": "api",      "status": 200, "server": "Apache/2.4.49",    "title": "API Gateway"},
        {"sub": "admin",    "status": 200, "server": "Apache/2.4.49",    "title": "Admin Panel"},
        {"sub": "vpn",      "status": 200, "server": "OpenVPN/2.5.1",    "title": "VPN Portal"},
        {"sub": "mail",     "status": 200, "server": "Microsoft-IIS/10", "title": "Outlook Web"},
        {"sub": "dev",      "status": 200, "server": "nginx/1.18.0",     "title": "Dev Environment"},
        {"sub": "jenkins",  "status": 200, "server": "Jetty/9.4.43",     "title": "Jenkins CI"},
        {"sub": "grafana",  "status": 200, "server": "nginx/1.20.1",     "title": "Grafana"},
    ]

    def __init__(self, scope, audit, mock_mode: bool = False):
        self.scope = scope
        self.audit = audit
        self.mock_mode = mock_mode or not self._tools_available()
        if self.mock_mode:
            logger.info(
                "RECON: subfinder/httpx not found — running in MOCK MODE. "
                "Install ProjectDiscovery tools for real enumeration."
            )

    def _tools_available(self) -> bool:
        return (
            shutil.which("subfinder") is not None
            and shutil.which("httpx") is not None
        )

    # ── Main entry point ──────────────────────────────────────────────────────

    def run(self, target: str) -> list[Asset]:
        """
        Full recon pipeline: subdomain enum → live probe → asset enrichment.
        Returns list of live, in-scope Asset objects.
        """
        self.scope.assert_in_scope(target)
        self.scope.assert_window_active()

        logger.info(f"RECON: Starting enumeration for {target}")
        self.audit.append("RECON", "start", target, "initiated")

        # Step 1: Subdomain enumeration
        subdomains = self._enumerate_subdomains(target)
        logger.info(f"RECON: {len(subdomains)} subdomains discovered")
        self.audit.append(
            "RECON", "subdomain_enum", target, "complete",
            {"count": len(subdomains)}
        )

        # Step 2: Filter to in-scope only
        subdomains = [s for s in subdomains if self.scope.is_in_scope(s)]

        # Step 3: Probe live endpoints
        assets = self._probe_live(subdomains)
        logger.info(f"RECON: {len(assets)} live assets confirmed")
        self.audit.append(
            "RECON", "httpx_probe", target, "complete",
            {"live_count": len(assets)}
        )

        # Step 4: Enrich with IP / port data
        assets = self._enrich(assets)

        logger.info(f"RECON: Complete — {len(assets)} assets in attack surface")
        return assets

    # ── Subdomain enumeration ─────────────────────────────────────────────────

    def _enumerate_subdomains(self, target: str) -> list[str]:
        if self.mock_mode:
            return self._mock_subdomains(target)
        return self._subfinder(target)

    def _subfinder(self, target: str) -> list[str]:
        """Run subfinder binary."""
        try:
            result = subprocess.run(
                ["subfinder", "-d", target, "-silent", "-all"],
                capture_output=True, text=True, timeout=120
            )
            subs = [
                line.strip() for line in result.stdout.splitlines()
                if line.strip() and "." in line
            ]
            return subs or [target]
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.warning(f"RECON: subfinder failed ({e}), falling back to common list")
            return self._common_subdomain_check(target)

    def _common_subdomain_check(self, target: str) -> list[str]:
        """DNS brute-force with common subdomain list."""
        found = [target]
        for sub in self.COMMON_SUBDOMAINS:
            fqdn = f"{sub}.{target}"
            try:
                socket.getaddrinfo(fqdn, None, timeout=2)
                found.append(fqdn)
            except (socket.gaierror, OSError):
                pass
        return found

    def _mock_subdomains(self, target: str) -> list[str]:
        return [
            target if m["sub"] == "" else f"{m['sub']}.{target}"
            for m in self.MOCK_ASSETS
        ]

    # ── Live probing ──────────────────────────────────────────────────────────

    def _probe_live(self, subdomains: list[str]) -> list[Asset]:
        if self.mock_mode:
            return self._mock_assets(subdomains)
        return self._httpx_probe(subdomains)

    def _httpx_probe(self, subdomains: list[str]) -> list[Asset]:
        """Run httpx binary to confirm live endpoints."""
        if not subdomains:
            return []
        try:
            input_data = "\n".join(subdomains)
            result = subprocess.run(
                ["httpx", "-silent", "-json", "-title", "-server",
                 "-status-code", "-follow-redirects"],
                input=input_data, capture_output=True, text=True, timeout=180
            )
            assets = []
            for line in result.stdout.splitlines():
                if not line.strip():
                    continue
                try:
                    data = json.loads(line)
                    parsed = urlparse(data.get("url", ""))
                    assets.append(Asset(
                        url=data.get("url", ""),
                        domain=parsed.netloc or parsed.path,
                        scheme=parsed.scheme,
                        port=parsed.port or (443 if parsed.scheme == "https" else 80),
                        status_code=data.get("status-code"),
                        title=data.get("title"),
                        server=data.get("webserver"),
                    ))
                except (json.JSONDecodeError, KeyError):
                    pass
            return assets
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            logger.warning(f"RECON: httpx failed ({e}), using requests fallback")
            return self._requests_probe(subdomains)

    def _requests_probe(self, subdomains: list[str]) -> list[Asset]:
        """Fallback: probe with requests library."""
        assets = []
        for sub in subdomains[:20]:   # Cap at 20 for fallback mode
            for scheme in ("https", "http"):
                url = f"{scheme}://{sub}"
                try:
                    r = requests.get(
                        url, timeout=5,
                        allow_redirects=True,
                        verify=False,
                        headers={"User-Agent": "SwarmHawk-Security-Scanner/1.0"},
                    )
                    assets.append(Asset(
                        url=url, domain=sub,
                        scheme=scheme,
                        port=443 if scheme == "https" else 80,
                        status_code=r.status_code,
                        server=r.headers.get("Server"),
                        title=self._extract_title(r.text),
                    ))
                    break
                except Exception:
                    pass
        return assets

    def _mock_assets(self, subdomains: list[str]) -> list[Asset]:
        assets = []
        for i, sub in enumerate(subdomains):
            m = self.MOCK_ASSETS[i % len(self.MOCK_ASSETS)]
            assets.append(Asset(
                url=f"https://{sub}",
                domain=sub,
                scheme="https",
                port=443,
                status_code=m["status"],
                server=m["server"],
                title=m["title"],
                ip=f"54.23.{i+1}.{10+i}",
            ))
        return assets

    # ── Enrichment ────────────────────────────────────────────────────────────

    def _enrich(self, assets: list[Asset]) -> list[Asset]:
        """Resolve IPs and detect tech stack from server headers."""
        for asset in assets:
            # IP resolution
            if not asset.ip:
                try:
                    asset.ip = socket.gethostbyname(asset.domain)
                except (socket.gaierror, OSError):
                    asset.ip = "0.0.0.0"

            # Tech stack detection from server header
            if asset.server:
                asset.tech_stack = self._detect_tech(asset.server)

        return assets

    @staticmethod
    def _detect_tech(server_header: str) -> list[str]:
        """Identify technologies from HTTP server header."""
        techs = []
        header_lower = server_header.lower()
        mapping = {
            "nginx": "Nginx", "apache": "Apache", "iis": "IIS",
            "jetty": "Jetty", "tomcat": "Tomcat", "php": "PHP",
            "python": "Python", "node": "Node.js", "express": "Express",
            "wordpress": "WordPress", "drupal": "Drupal",
        }
        for key, name in mapping.items():
            if key in header_lower:
                techs.append(name)
                # Try to extract version
                import re
                version_match = re.search(
                    rf"{key}[/ ]([\d.]+)", header_lower, re.IGNORECASE
                )
                if version_match:
                    techs[-1] = f"{name}/{version_match.group(1)}"
        return techs

    @staticmethod
    def _extract_title(html: str) -> Optional[str]:
        import re
        m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
        return m.group(1).strip()[:120] if m else None
