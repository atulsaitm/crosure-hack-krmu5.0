"""Security Misconfiguration detection plugin."""

from typing import List, Optional
import httpx

from plugins.base import BasePlugin
from core.models import Finding, CrawledEndpoint, SeverityLevel, AttackType, AttackPrimitive


REQUIRED_HEADERS = {
    "content-security-policy": {
        "severity": SeverityLevel.MEDIUM,
        "desc": "Content Security Policy (CSP) not set. Allows inline scripts and reduces XSS protection.",
        "cvss": 5.0,
    },
    "strict-transport-security": {
        "severity": SeverityLevel.MEDIUM,
        "desc": "HTTP Strict Transport Security (HSTS) not set. Browser may connect over insecure HTTP.",
        "cvss": 4.8,
    },
    "x-frame-options": {
        "severity": SeverityLevel.MEDIUM,
        "desc": "X-Frame-Options not set. Page can be embedded in iframes (clickjacking risk).",
        "cvss": 4.3,
    },
    "x-content-type-options": {
        "severity": SeverityLevel.LOW,
        "desc": "X-Content-Type-Options not set. Browser may MIME-sniff responses.",
        "cvss": 3.1,
    },
    "x-xss-protection": {
        "severity": SeverityLevel.LOW,
        "desc": "X-XSS-Protection header not set. Legacy browsers lack XSS filter.",
        "cvss": 2.0,
    },
    "referrer-policy": {
        "severity": SeverityLevel.LOW,
        "desc": "Referrer-Policy not set. Sensitive URLs may leak in Referer header.",
        "cvss": 3.1,
    },
    "permissions-policy": {
        "severity": SeverityLevel.LOW,
        "desc": "Permissions-Policy not set. Browser features (camera, geolocation) not restricted.",
        "cvss": 2.0,
    },
}


class MisconfigPlugin(BasePlugin):
    name = "misconfig"
    description = "Security misconfiguration and missing headers detection"

    async def detect(
        self,
        endpoint: CrawledEndpoint,
        session: httpx.AsyncClient,
        context: Optional[dict] = None,
    ) -> List[Finding]:
        findings = []

        response = await self._send_request(
            session, endpoint.url, method=endpoint.method,
            params=endpoint.params if endpoint.method == "GET" else None,
            data=endpoint.form_data if endpoint.method == "POST" else None,
        )

        if response is None:
            return findings

        headers = {k.lower(): v for k, v in response.headers.items()}

        # ── 1. Missing Security Headers ──
        from urllib.parse import urlparse
        parsed = urlparse(endpoint.url)

        # Only check headers on root/main pages to avoid duplicates
        if parsed.path in ("", "/", "/index.html") or not any(
            f.vuln_type == AttackType.MISCONFIG for f in findings
        ):
            for header_name, info in REQUIRED_HEADERS.items():
                if header_name not in headers:
                    findings.append(Finding(
                        vuln_type=AttackType.MISCONFIG,
                        severity=info["severity"],
                        url=endpoint.url,
                        method="GET",
                        parameter=header_name,
                        evidence=f"Missing header: {header_name}",
                        description=info["desc"],
                        cvss_score=info["cvss"],
                        owasp_category="A05:2021 - Security Misconfiguration",
                        primitive=AttackPrimitive.INFO_DISCLOSURE,
                    ))

        # ── 2. Server Version Disclosure ──
        server = headers.get("server", "")
        powered_by = headers.get("x-powered-by", "")

        if server and any(c.isdigit() for c in server):
            findings.append(Finding(
                vuln_type=AttackType.MISCONFIG,
                severity=SeverityLevel.LOW,
                url=endpoint.url,
                method="GET",
                parameter="Server",
                evidence=f"Server: {server}",
                description=f"Server version disclosed: '{server}'. Helps attackers identify specific vulnerabilities.",
                cvss_score=2.6,
                owasp_category="A05:2021 - Security Misconfiguration",
                primitive=AttackPrimitive.INFO_DISCLOSURE,
            ))

        if powered_by:
            findings.append(Finding(
                vuln_type=AttackType.MISCONFIG,
                severity=SeverityLevel.LOW,
                url=endpoint.url,
                method="GET",
                parameter="X-Powered-By",
                evidence=f"X-Powered-By: {powered_by}",
                description=f"Technology stack disclosed: '{powered_by}'. Remove this header.",
                cvss_score=2.6,
                owasp_category="A05:2021 - Security Misconfiguration",
                primitive=AttackPrimitive.INFO_DISCLOSURE,
            ))

        # ── 3. Directory Listing Detection ──
        if response.status_code == 200:
            body = response.text.lower()
            if "index of /" in body or "directory listing" in body or "<title>index of" in body:
                findings.append(Finding(
                    vuln_type=AttackType.MISCONFIG,
                    severity=SeverityLevel.MEDIUM,
                    url=endpoint.url,
                    method="GET",
                    evidence="Directory listing enabled",
                    description="Web server directory listing is enabled. Internal file structure is exposed.",
                    cvss_score=5.3,
                    owasp_category="A05:2021 - Security Misconfiguration",
                    primitive=AttackPrimitive.INFO_DISCLOSURE,
                ))

        # ── 4. Verbose Error Pages ──
        if response.status_code >= 400:
            body = response.text.lower()
            error_indicators = [
                "stack trace", "traceback", "exception", "at line",
                "debug mode", "django debug", "flask debugger",
                "laravel", "symfony", "rails error",
            ]
            for indicator in error_indicators:
                if indicator in body:
                    findings.append(Finding(
                        vuln_type=AttackType.MISCONFIG,
                        severity=SeverityLevel.MEDIUM,
                        url=endpoint.url,
                        method="GET",
                        evidence=f"Verbose error page contains: '{indicator}'",
                        description="Application exposes detailed error/debug information. Stack traces reveal internal paths and code.",
                        cvss_score=5.3,
                        owasp_category="A05:2021 - Security Misconfiguration",
                        primitive=AttackPrimitive.INFO_DISCLOSURE,
                    ))
                    break

        return findings
