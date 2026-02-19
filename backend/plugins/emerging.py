"""Emerging Web Threats detection plugin.
Covers: Prototype Pollution, GraphQL Injection, HTTP Request Smuggling,
WebSocket Security, API Mass Assignment."""

import re
import json
from typing import List, Optional
import httpx

from plugins.base import BasePlugin
from core.models import Finding, CrawledEndpoint, SeverityLevel, AttackType, AttackPrimitive


class EmergingThreatsPlugin(BasePlugin):
    name = "emerging"
    description = "Emerging web threats: prototype pollution, GraphQL, smuggling, WebSocket, mass assignment"

    async def detect(
        self,
        endpoint: CrawledEndpoint,
        session: httpx.AsyncClient,
        context: Optional[dict] = None,
    ) -> List[Finding]:
        findings = []

        # ── 1. Prototype Pollution ──
        pp_findings = await self._test_prototype_pollution(session, endpoint)
        findings.extend(pp_findings)

        # ── 2. GraphQL Introspection ──
        gql_findings = await self._test_graphql(session, endpoint)
        findings.extend(gql_findings)

        # ── 3. HTTP Request Smuggling ──
        smuggle_findings = await self._test_request_smuggling(session, endpoint)
        findings.extend(smuggle_findings)

        # ── 4. WebSocket Security ──
        if endpoint.method == "WS" or "ws://" in endpoint.url or "wss://" in endpoint.url:
            ws_findings = await self._test_websocket(endpoint)
            findings.extend(ws_findings)

        # ── 5. API Mass Assignment ──
        if endpoint.method in ("POST", "PUT", "PATCH"):
            mass_findings = await self._test_mass_assignment(session, endpoint)
            findings.extend(mass_findings)

        return findings

    async def _test_prototype_pollution(
        self, session: httpx.AsyncClient, endpoint: CrawledEndpoint
    ) -> List[Finding]:
        """Test for prototype pollution via query params and JSON body."""
        findings = []

        # Via query params
        pp_params = {
            "__proto__[polluted]": "crosure_pp_test",
            "constructor[prototype][polluted]": "crosure_pp_test",
            "__proto__.polluted": "crosure_pp_test",
        }

        for payload_key, payload_value in pp_params.items():
            params = dict(endpoint.params) if endpoint.params else {}
            params[payload_key] = payload_value

            response = await self._send_request(session, endpoint.url, params=params)
            if response and "crosure_pp_test" in response.text:
                findings.append(Finding(
                    vuln_type=AttackType.PROTOTYPE_POLLUTION,
                    severity=SeverityLevel.HIGH,
                    url=endpoint.url,
                    method="GET",
                    parameter=payload_key,
                    payload=f"{payload_key}={payload_value}",
                    evidence="Prototype pollution payload reflected in response",
                    description=f"Prototype Pollution via query parameter. Injected '{payload_key}' is reflected, indicating object prototype manipulation.",
                    cvss_score=7.5,
                    owasp_category="A03:2021 - Injection",
                    primitive=AttackPrimitive.CODE_EXEC,
                ))
                break

        # Via JSON body
        if endpoint.method in ("POST", "PUT", "PATCH"):
            payloads = [
                {"__proto__": {"polluted": "crosure_pp_test"}},
                {"constructor": {"prototype": {"polluted": "crosure_pp_test"}}},
            ]
            for payload in payloads:
                try:
                    response = await session.post(
                        endpoint.url,
                        json=payload,
                        timeout=10.0,
                    )
                    if response and "crosure_pp_test" in response.text:
                        findings.append(Finding(
                            vuln_type=AttackType.PROTOTYPE_POLLUTION,
                            severity=SeverityLevel.HIGH,
                            url=endpoint.url,
                            method="POST",
                            payload=json.dumps(payload),
                            evidence="Prototype pollution via JSON body reflected",
                            description="Prototype Pollution via JSON request body. Server-side object prototype can be manipulated.",
                            cvss_score=7.5,
                            owasp_category="A03:2021 - Injection",
                            primitive=AttackPrimitive.CODE_EXEC,
                        ))
                        break
                except Exception:
                    continue

        return findings

    async def _test_graphql(
        self, session: httpx.AsyncClient, endpoint: CrawledEndpoint
    ) -> List[Finding]:
        """Test for GraphQL introspection and injection."""
        findings = []

        from urllib.parse import urlparse
        parsed = urlparse(endpoint.url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        # Only test /graphql-like paths
        gql_paths = ["/graphql", "/api/graphql", "/v1/graphql", "/gql"]
        if not any(parsed.path.rstrip("/").endswith(p.rstrip("/")) for p in gql_paths):
            # Also try common graphql endpoints from root
            if parsed.path not in ("", "/"):
                return findings

        for gql_path in gql_paths:
            gql_url = origin + gql_path

            # Test introspection
            introspection_query = {
                "query": "{__schema{types{name,fields{name,type{name}}}}}"
            }

            try:
                response = await session.post(
                    gql_url,
                    json=introspection_query,
                    headers={"Content-Type": "application/json"},
                    timeout=10.0,
                )

                if response.status_code == 200 and "__schema" in response.text:
                    findings.append(Finding(
                        vuln_type=AttackType.GRAPHQL,
                        severity=SeverityLevel.MEDIUM,
                        url=gql_url,
                        method="POST",
                        payload=json.dumps(introspection_query),
                        evidence=f"GraphQL introspection enabled. Schema exposed ({len(response.text)} bytes).",
                        description="GraphQL introspection is enabled. Full API schema is publicly accessible, revealing all types, queries, and mutations.",
                        cvss_score=5.3,
                        owasp_category="A05:2021 - Security Misconfiguration",
                        primitive=AttackPrimitive.INFO_DISCLOSURE,
                    ))
                    break
            except Exception:
                continue

        return findings

    async def _test_request_smuggling(
        self, session: httpx.AsyncClient, endpoint: CrawledEndpoint
    ) -> List[Finding]:
        """Detect potential HTTP request smuggling."""
        findings = []

        # Test CL.TE ambiguity
        try:
            headers = {
                "Content-Length": "6",
                "Transfer-Encoding": "chunked",
            }
            response = await self._send_request(
                session, endpoint.url, method="POST",
                headers=headers,
                data="0\r\n\r\nX",
                timeout=10.0,
            )

            if response and response.status_code not in (400, 501):
                findings.append(Finding(
                    vuln_type=AttackType.OTHER,
                    severity=SeverityLevel.MEDIUM,
                    url=endpoint.url,
                    method="POST",
                    payload="CL+TE ambiguous headers",
                    evidence=f"Server accepted CL+TE headers (status: {response.status_code})",
                    description="Server accepts both Content-Length and Transfer-Encoding headers. Potential HTTP Request Smuggling vector.",
                    cvss_score=7.5,
                    owasp_category="A05:2021 - Security Misconfiguration",
                    primitive=AttackPrimitive.AUTH_BYPASS,
                ))
        except Exception:
            pass

        return findings

    async def _test_websocket(self, endpoint: CrawledEndpoint) -> List[Finding]:
        """Test WebSocket security."""
        findings = []

        ws_url = endpoint.url
        if ws_url.startswith("http"):
            ws_url = ws_url.replace("https://", "wss://").replace("http://", "ws://")

        # Test connection without auth and with evil origin
        try:
            import websockets

            async with websockets.connect(
                ws_url,
                additional_headers={"Origin": "https://evil.com"},
                open_timeout=5,
            ) as ws:
                findings.append(Finding(
                    vuln_type=AttackType.WEBSOCKET,
                    severity=SeverityLevel.HIGH,
                    url=ws_url,
                    method="WS",
                    payload="Origin: https://evil.com",
                    evidence="WebSocket accepts connections from arbitrary origins without auth",
                    description="Cross-Site WebSocket Hijacking (CSWSH): WebSocket endpoint accepts connections from any origin without authentication.",
                    cvss_score=7.5,
                    owasp_category="A01:2021 - Broken Access Control",
                    primitive=AttackPrimitive.DATA_ACCESS,
                ))
        except Exception:
            pass

        return findings

    async def _test_mass_assignment(
        self, session: httpx.AsyncClient, endpoint: CrawledEndpoint
    ) -> List[Finding]:
        """Test for API mass assignment."""
        findings = []

        # Extra fields to inject
        extra_fields = {
            "role": "admin",
            "is_admin": True,
            "admin": True,
            "privilege": "admin",
            "user_type": "admin",
            "price": 0,
            "discount": 100,
            "verified": True,
        }

        if endpoint.form_data:
            data = dict(endpoint.form_data)
            data.update(extra_fields)

            response = await self._send_request(
                session, endpoint.url, method="POST", data=data
            )

            if response and response.status_code in (200, 201):
                body = response.text.lower()
                for field, value in extra_fields.items():
                    str_value = str(value).lower()
                    if f'"{field}"' in body and str_value in body:
                        findings.append(Finding(
                            vuln_type=AttackType.MASS_ASSIGNMENT,
                            severity=SeverityLevel.HIGH,
                            url=endpoint.url,
                            method="POST",
                            parameter=field,
                            payload=f"{field}={value}",
                            evidence=f"Injected field '{field}={value}' reflected in response",
                            description=f"API Mass Assignment: injected '{field}' field was accepted and reflected. Privilege escalation possible.",
                            cvss_score=8.1,
                            owasp_category="A04:2021 - Insecure Design",
                            primitive=AttackPrimitive.PRIVILEGE_ESCALATION,
                        ))
                        break

        return findings
