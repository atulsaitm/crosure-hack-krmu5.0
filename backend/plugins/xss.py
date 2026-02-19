"""Cross-Site Scripting (XSS) detection plugin."""

import re
import uuid
from typing import List, Optional
import httpx

from plugins.base import BasePlugin
from core.models import Finding, CrawledEndpoint, SeverityLevel, AttackType, AttackPrimitive


# XSS test payloads with unique markers
def _generate_payloads(marker: str) -> List[str]:
    return [
        f'<script>alert("{marker}")</script>',
        f'"><script>alert("{marker}")</script>',
        f"'><script>alert('{marker}')</script>",
        f'<img src=x onerror=alert("{marker}")>',
        f'"><img src=x onerror=alert("{marker}")>',
        f'<svg/onload=alert("{marker}")>',
        f'"><svg/onload=alert("{marker}")>',
        f"javascript:alert('{marker}')",
        f'<body onload=alert("{marker}")>',
        f'<details open ontoggle=alert("{marker}")>',
        f'{{{{constructor.constructor("return alert(\'{marker}\')")()}}}}',
    ]

# Patterns to check for reflection
REFLECTION_PATTERNS = [
    r'<script>alert\("{}"\)</script>',
    r'<img[^>]*onerror=alert\("{}"\)>',
    r'<svg[^>]*onload=alert\("{}"\)>',
    r'<body[^>]*onload=alert\("{}"\)>',
    r'<details[^>]*ontoggle=alert\("{}"\)>',
]


class XSSPlugin(BasePlugin):
    name = "xss"
    description = "Reflected Cross-Site Scripting detection"

    async def detect(
        self,
        endpoint: CrawledEndpoint,
        session: httpx.AsyncClient,
        context: Optional[dict] = None,
    ) -> List[Finding]:
        findings = []

        params_to_test = {}
        if endpoint.params:
            params_to_test.update(endpoint.params)
        if endpoint.form_data:
            params_to_test.update(endpoint.form_data)

        if not params_to_test:
            return findings

        for param_name, original_value in params_to_test.items():
            finding = await self._test_reflected_xss(
                session, endpoint, param_name, original_value
            )
            if finding:
                findings.append(finding)

        return findings

    async def _test_reflected_xss(
        self,
        session: httpx.AsyncClient,
        endpoint: CrawledEndpoint,
        param_name: str,
        original_value: str,
    ) -> Optional[Finding]:
        """Test for reflected XSS."""
        marker = f"crosure{uuid.uuid4().hex[:8]}"
        payloads = _generate_payloads(marker)

        for payload in payloads:
            test_value = payload

            if endpoint.method == "POST" and endpoint.form_data:
                data = dict(endpoint.form_data)
                data[param_name] = test_value
                response = await self._send_request(
                    session, endpoint.url, method="POST", data=data
                )
            else:
                params = dict(endpoint.params) if endpoint.params else {}
                params[param_name] = test_value
                response = await self._send_request(
                    session, endpoint.url, params=params
                )

            if response is None:
                continue

            body = response.text

            # Check if payload is reflected unescaped
            if marker in body:
                # Check for actual dangerous reflection (not just the marker text)
                for pattern in REFLECTION_PATTERNS:
                    if re.search(pattern.format(re.escape(marker)), body, re.IGNORECASE):
                        return Finding(
                            vuln_type=AttackType.XSS,
                            severity=SeverityLevel.MEDIUM,
                            url=endpoint.url,
                            method=endpoint.method,
                            parameter=param_name,
                            payload=payload,
                            evidence=f"XSS payload reflected unescaped in response",
                            description=f"Reflected XSS in parameter '{param_name}'. Payload is rendered without sanitization.",
                            cvss_score=6.1,
                            owasp_category="A03:2021 - Injection",
                            primitive=AttackPrimitive.SESSION_HIJACK,
                        )

                # Even partial reflection (marker present but not full payload) is suspicious
                if payload.replace('"', '').replace("'", '') in body:
                    return Finding(
                        vuln_type=AttackType.XSS,
                        severity=SeverityLevel.MEDIUM,
                        url=endpoint.url,
                        method=endpoint.method,
                        parameter=param_name,
                        payload=payload,
                        evidence=f"XSS marker '{marker}' reflected in response body",
                        description=f"Potential reflected XSS in parameter '{param_name}'. Input is partially reflected.",
                        cvss_score=5.4,
                        owasp_category="A03:2021 - Injection",
                        primitive=AttackPrimitive.SESSION_HIJACK,
                    )

        return None
