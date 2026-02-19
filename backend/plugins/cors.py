"""CORS Misconfiguration detection plugin."""

from typing import List, Optional
import httpx

from plugins.base import BasePlugin
from core.models import Finding, CrawledEndpoint, SeverityLevel, AttackType, AttackPrimitive


TEST_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null",
    "https://evil.target.com",  # subdomain confusion
]


class CORSPlugin(BasePlugin):
    name = "cors"
    description = "CORS misconfiguration detection"

    async def detect(
        self,
        endpoint: CrawledEndpoint,
        session: httpx.AsyncClient,
        context: Optional[dict] = None,
    ) -> List[Finding]:
        findings = []

        for origin in TEST_ORIGINS:
            finding = await self._test_origin(session, endpoint, origin)
            if finding:
                findings.append(finding)
                break  # One CORS finding per endpoint

        return findings

    async def _test_origin(
        self,
        session: httpx.AsyncClient,
        endpoint: CrawledEndpoint,
        test_origin: str,
    ) -> Optional[Finding]:
        """Test if server reflects arbitrary Origin in CORS headers."""
        headers = {"Origin": test_origin}
        response = await self._send_request(
            session, endpoint.url, headers=headers
        )

        if response is None:
            return None

        acao = response.headers.get("access-control-allow-origin", "")
        acac = response.headers.get("access-control-allow-credentials", "").lower()

        if not acao:
            return None

        # Wildcard with credentials = critical
        if acao == "*" and acac == "true":
            return Finding(
                vuln_type=AttackType.CORS,
                severity=SeverityLevel.CRITICAL,
                url=endpoint.url,
                method="GET",
                payload=f"Origin: {test_origin}",
                evidence=f"ACAO: * with ACAC: true",
                description="CORS allows any origin with credentials. Browsers block this, but it indicates severe misconfiguration.",
                cvss_score=8.6,
                owasp_category="A05:2021 - Security Misconfiguration",
                primitive=AttackPrimitive.DATA_ACCESS,
            )

        # Reflected origin with credentials = critical
        if acao == test_origin and acac == "true":
            return Finding(
                vuln_type=AttackType.CORS,
                severity=SeverityLevel.CRITICAL,
                url=endpoint.url,
                method="GET",
                payload=f"Origin: {test_origin}",
                evidence=f"ACAO reflects '{test_origin}' with ACAC: true",
                description=f"CORS reflects arbitrary origin '{test_origin}' with credentials. Cross-origin data theft possible.",
                cvss_score=8.6,
                owasp_category="A05:2021 - Security Misconfiguration",
                primitive=AttackPrimitive.DATA_ACCESS,
            )

        # Reflected origin without credentials = medium
        if acao == test_origin:
            return Finding(
                vuln_type=AttackType.CORS,
                severity=SeverityLevel.MEDIUM,
                url=endpoint.url,
                method="GET",
                payload=f"Origin: {test_origin}",
                evidence=f"ACAO reflects '{test_origin}'",
                description=f"CORS reflects arbitrary origin '{test_origin}'. Cross-origin requests allowed.",
                cvss_score=5.3,
                owasp_category="A05:2021 - Security Misconfiguration",
                primitive=AttackPrimitive.INFO_DISCLOSURE,
            )

        # Null origin accepted with credentials
        if acao == "null" and test_origin == "null" and acac == "true":
            return Finding(
                vuln_type=AttackType.CORS,
                severity=SeverityLevel.HIGH,
                url=endpoint.url,
                method="GET",
                payload="Origin: null",
                evidence="ACAO: null with ACAC: true",
                description="CORS accepts 'null' origin with credentials. Exploitable via sandboxed iframes.",
                cvss_score=7.5,
                owasp_category="A05:2021 - Security Misconfiguration",
                primitive=AttackPrimitive.DATA_ACCESS,
            )

        return None
