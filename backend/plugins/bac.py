"""Broken Access Control (BAC) detection plugin."""

from typing import List, Optional
import httpx

from plugins.base import BasePlugin
from core.models import Finding, CrawledEndpoint, SeverityLevel, AttackType, AttackPrimitive


ADMIN_PATHS = [
    "/admin", "/admin/", "/administrator", "/administration",
    "/dashboard", "/manage", "/management",
    "/api/admin", "/api/admin/users", "/api/admin/config",
    "/api/users", "/api/settings",
    "/settings", "/settings/users",
    "/console", "/debug", "/devtools",
    "/_debug", "/_admin",
    "/wp-admin", "/wp-login.php",
    "/phpmyadmin", "/adminer",
    "/api/v1/admin", "/api/v2/admin",
    "/graphql",  # Often unrestricted
    "/swagger", "/swagger-ui", "/api-docs", "/openapi.json",
    "/actuator", "/actuator/health", "/actuator/env",
    "/metrics", "/prometheus",
]

SENSITIVE_PATHS = [
    "/.env", "/.git", "/.git/HEAD", "/.git/config",
    "/.gitignore", "/.svn",
    "/robots.txt", "/sitemap.xml",
    "/.htaccess", "/.htpasswd",
    "/web.config", "/crossdomain.xml",
    "/backup", "/backup.sql", "/dump.sql",
    "/config.json", "/config.yaml", "/config.yml",
    "/package.json", "/composer.json",
    "/Dockerfile", "/docker-compose.yml",
    "/.dockerenv",
    "/server-status", "/server-info",
    "/ftp", "/uploads", "/temp",
    "/test", "/testing",
    "/trace", "/elmah.axd",
]


class BACPlugin(BasePlugin):
    name = "bac"
    description = "Broken Access Control detection"

    async def detect(
        self,
        endpoint: CrawledEndpoint,
        session: httpx.AsyncClient,
        context: Optional[dict] = None,
    ) -> List[Finding]:
        findings = []

        # ── 1. Probe admin/restricted paths ──
        from urllib.parse import urljoin
        base_url = endpoint.url.split("?")[0].rstrip("/")
        # Use only the origin
        from urllib.parse import urlparse
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # Only run path probing from the root endpoint to avoid duplicates
        if parsed.path in ("", "/", "/index.html"):
            for path in ADMIN_PATHS:
                test_url = origin + path
                finding = await self._probe_path(session, test_url, "admin")
                if finding:
                    findings.append(finding)

            for path in SENSITIVE_PATHS:
                test_url = origin + path
                finding = await self._probe_path(session, test_url, "sensitive")
                if finding:
                    findings.append(finding)

        # ── 2. Check if authenticated endpoints are accessible without auth ──
        if endpoint.requires_auth:
            unauth_finding = await self._test_unauth_access(session, endpoint)
            if unauth_finding:
                findings.append(unauth_finding)

        return findings

    async def _probe_path(
        self,
        session: httpx.AsyncClient,
        url: str,
        path_type: str,
    ) -> Optional[Finding]:
        """Probe for accessible admin/sensitive paths."""
        response = await self._send_request(session, url, timeout=5.0)

        if response is None:
            return None

        # 200 with substantive body = exposed
        if response.status_code == 200 and len(response.text) > 200:
            # Filter out generic error pages or redirects to login
            body_lower = response.text.lower()
            if any(kw in body_lower for kw in ["login", "sign in", "404", "not found", "access denied"]):
                return None

            severity = SeverityLevel.HIGH if path_type == "admin" else SeverityLevel.MEDIUM
            cvss = 8.2 if path_type == "admin" else 5.3

            return Finding(
                vuln_type=AttackType.BAC,
                severity=severity,
                url=url,
                method="GET",
                evidence=f"Path accessible (HTTP {response.status_code}, {len(response.text)} bytes)",
                description=f"{'Admin/restricted' if path_type == 'admin' else 'Sensitive'} path '{url}' is accessible without authentication.",
                cvss_score=cvss,
                owasp_category="A01:2021 - Broken Access Control",
                primitive=AttackPrimitive.AUTH_BYPASS if path_type == "admin" else AttackPrimitive.INFO_DISCLOSURE,
            )

        # 403 with info leakage in body
        if response.status_code == 403 and len(response.text) > 500:
            if any(kw in response.text.lower() for kw in ["version", "server", "powered by", "stack trace"]):
                return Finding(
                    vuln_type=AttackType.MISCONFIG,
                    severity=SeverityLevel.LOW,
                    url=url,
                    method="GET",
                    evidence=f"403 response leaks information ({len(response.text)} bytes)",
                    description=f"Restricted path returns verbose error with server information.",
                    cvss_score=3.7,
                    owasp_category="A05:2021 - Security Misconfiguration",
                    primitive=AttackPrimitive.INFO_DISCLOSURE,
                )

        return None

    async def _test_unauth_access(
        self,
        session: httpx.AsyncClient,
        endpoint: CrawledEndpoint,
    ) -> Optional[Finding]:
        """Test if an authenticated endpoint is accessible without auth."""
        # Create a clean session without auth cookies
        async with httpx.AsyncClient(verify=False) as clean_session:
            response = await self._send_request(
                clean_session, endpoint.url,
                method=endpoint.method,
                params=endpoint.params if endpoint.method == "GET" else None,
                data=endpoint.form_data if endpoint.method == "POST" else None,
            )

            if response and response.status_code == 200 and len(response.text) > 200:
                body_lower = response.text.lower()
                if not any(kw in body_lower for kw in ["login", "sign in", "unauthorized"]):
                    return Finding(
                        vuln_type=AttackType.BAC,
                        severity=SeverityLevel.HIGH,
                        url=endpoint.url,
                        method=endpoint.method,
                        evidence=f"Authenticated endpoint accessible without auth (HTTP 200, {len(response.text)} bytes)",
                        description=f"Endpoint '{endpoint.url}' intended for authenticated users is accessible without session/cookie.",
                        cvss_score=8.2,
                        owasp_category="A01:2021 - Broken Access Control",
                        primitive=AttackPrimitive.AUTH_BYPASS,
                    )

        return None
