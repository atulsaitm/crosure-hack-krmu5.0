"""Remote Code Execution (RCE) detection plugin.
Covers: OS command injection (time-based), SSTI-to-RCE escalation, deserialization signatures."""

import time
import re
from typing import List, Optional
import httpx

from plugins.base import BasePlugin
from core.models import Finding, CrawledEndpoint, SeverityLevel, AttackType, AttackPrimitive


# Time-based OS command injection payloads
CMD_INJECTION_PAYLOADS = [
    ("; sleep 5 ;", 5),
    ("| sleep 5", 5),
    ("`sleep 5`", 5),
    ("$(sleep 5)", 5),
    ("%0asleep 5", 5),
    ("& sleep 5 &", 5),
    ("|| sleep 5", 5),
    # Windows
    ("& timeout /t 5 &", 5),
    ("| ping -n 5 127.0.0.1", 5),
]

# Deserialization signatures (passive detection)
DESER_SIGNATURES = [
    {"pattern": r"rO0AB", "tech": "Java", "desc": "Java serialized object (Base64)"},
    {"pattern": r"aced0005", "tech": "Java", "desc": "Java serialized object (hex)"},
    {"pattern": r'O:\d+:"', "tech": "PHP", "desc": "PHP serialized object"},
    {"pattern": r"AAEAAAD", "tech": ".NET", "desc": ".NET BinaryFormatter object"},
    {"pattern": r"gASV|gANj", "tech": "Python", "desc": "Python pickle object (Base64)"},
]


class RCEPlugin(BasePlugin):
    name = "rce"
    description = "Remote Code Execution via command injection, SSTI escalation, and deserialization"

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

        # ── 1. OS Command Injection (time-based) ──
        for param_name, original_value in params_to_test.items():
            finding = await self._test_command_injection(
                session, endpoint, param_name, original_value
            )
            if finding:
                findings.append(finding)

        # ── 2. Deserialization detection (passive) ──
        deser_finding = await self._check_deserialization(session, endpoint)
        if deser_finding:
            findings.append(deser_finding)

        return findings

    async def _test_command_injection(
        self,
        session: httpx.AsyncClient,
        endpoint: CrawledEndpoint,
        param_name: str,
        original_value: str,
    ) -> Optional[Finding]:
        """Time-based OS command injection detection."""
        # Get baseline
        start = time.time()
        if endpoint.method == "POST" and endpoint.form_data:
            await self._send_request(session, endpoint.url, method="POST", data=endpoint.form_data)
        else:
            await self._send_request(session, endpoint.url, params=endpoint.params)
        baseline = time.time() - start

        for payload, sleep_time in CMD_INJECTION_PAYLOADS[:5]:
            test_value = str(original_value) + payload

            start = time.time()
            if endpoint.method == "POST" and endpoint.form_data:
                data = dict(endpoint.form_data)
                data[param_name] = test_value
                response = await self._send_request(
                    session, endpoint.url, method="POST", data=data, timeout=sleep_time + 5
                )
            else:
                params = dict(endpoint.params) if endpoint.params else {}
                params[param_name] = test_value
                response = await self._send_request(
                    session, endpoint.url, params=params, timeout=sleep_time + 5
                )
            elapsed = time.time() - start

            if response and elapsed >= (sleep_time - 1) and elapsed > baseline * 3:
                return Finding(
                    vuln_type=AttackType.COMMAND_INJECTION,
                    severity=SeverityLevel.CRITICAL,
                    url=endpoint.url,
                    method=endpoint.method,
                    parameter=param_name,
                    payload=payload,
                    evidence=f"Command injection: response delayed {elapsed:.1f}s (baseline: {baseline:.1f}s)",
                    description=f"OS Command Injection in '{param_name}'. Server executed sleep command.",
                    cvss_score=9.8,
                    owasp_category="A03:2021 - Injection",
                    primitive=AttackPrimitive.CODE_EXEC,
                )

        return None

    async def _check_deserialization(
        self,
        session: httpx.AsyncClient,
        endpoint: CrawledEndpoint,
    ) -> Optional[Finding]:
        """Passive deserialization signature detection."""
        response = await self._send_request(
            session, endpoint.url, method=endpoint.method,
            params=endpoint.params if endpoint.method == "GET" else None,
            data=endpoint.form_data if endpoint.method == "POST" else None,
        )

        if response is None:
            return None

        # Check response body
        body = response.text
        # Check cookies
        cookies_str = str(response.headers.get("set-cookie", ""))
        check_text = body + " " + cookies_str

        for sig in DESER_SIGNATURES:
            if re.search(sig["pattern"], check_text):
                return Finding(
                    vuln_type=AttackType.DESERIALIZATION,
                    severity=SeverityLevel.HIGH,
                    url=endpoint.url,
                    method=endpoint.method,
                    payload=None,
                    evidence=f"Deserialization signature detected: {sig['desc']} ({sig['tech']})",
                    description=f"Insecure deserialization indicator ({sig['tech']}). Serialized objects found in response/cookies.",
                    cvss_score=8.1,
                    owasp_category="A08:2021 - Software and Data Integrity Failures",
                    primitive=AttackPrimitive.CODE_EXEC,
                )

        return None
