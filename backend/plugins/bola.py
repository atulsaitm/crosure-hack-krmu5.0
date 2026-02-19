"""Broken Object Level Authorization (BOLA/IDOR) detection plugin."""

import re
import hashlib
from typing import List, Optional
import httpx

from plugins.base import BasePlugin
from core.models import Finding, CrawledEndpoint, SeverityLevel, AttackType, AttackPrimitive


class BOLAPlugin(BasePlugin):
    name = "bola"
    description = "Broken Object Level Authorization (IDOR) detection"

    async def detect(
        self,
        endpoint: CrawledEndpoint,
        session: httpx.AsyncClient,
        context: Optional[dict] = None,
    ) -> List[Finding]:
        findings = []

        # ── 1. Check URL path for ID segments ──
        path_ids = re.findall(r'/(\d+)(?:/|$|\?)', endpoint.url)
        uuid_ids = re.findall(r'/([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})', endpoint.url, re.I)

        for original_id in path_ids:
            finding = await self._test_path_idor(session, endpoint, original_id, is_numeric=True)
            if finding:
                findings.append(finding)

        for original_id in uuid_ids:
            finding = await self._test_path_idor(session, endpoint, original_id, is_numeric=False)
            if finding:
                findings.append(finding)

        # ── 2. Check query params for IDs ──
        id_params = {}
        if endpoint.params:
            for key, value in endpoint.params.items():
                if re.match(r'^\d+$', str(value)):
                    id_params[key] = value
                elif any(k in key.lower() for k in ["id", "user", "account", "order", "item", "profile"]):
                    id_params[key] = value

        for param_name, original_value in id_params.items():
            finding = await self._test_param_idor(session, endpoint, param_name, original_value)
            if finding:
                findings.append(finding)

        return findings

    async def _test_path_idor(
        self,
        session: httpx.AsyncClient,
        endpoint: CrawledEndpoint,
        original_id: str,
        is_numeric: bool,
    ) -> Optional[Finding]:
        """Test IDOR in URL path segments."""
        # Get original response
        orig_response = await self._send_request(session, endpoint.url)
        if orig_response is None or orig_response.status_code != 200:
            return None

        orig_hash = hashlib.md5(orig_response.text.encode()).hexdigest()
        orig_len = len(orig_response.text)

        # Generate test IDs
        if is_numeric:
            test_ids = [str(int(original_id) + 1), str(int(original_id) - 1), "1", "2", "999999"]
        else:
            test_ids = ["00000000-0000-0000-0000-000000000001"]

        for test_id in test_ids:
            test_url = endpoint.url.replace(original_id, test_id, 1)
            test_response = await self._send_request(session, test_url)

            if test_response is None:
                continue

            if test_response.status_code == 200:
                test_hash = hashlib.md5(test_response.text.encode()).hexdigest()
                test_len = len(test_response.text)

                # Different content = accessing another user's data = BOLA
                if test_hash != orig_hash and test_len > 50 and abs(test_len - orig_len) < orig_len * 3:
                    return Finding(
                        vuln_type=AttackType.BOLA,
                        severity=SeverityLevel.HIGH,
                        url=endpoint.url,
                        method="GET",
                        parameter=f"path_id:{original_id}",
                        payload=f"Changed ID from {original_id} to {test_id}",
                        evidence=f"Different response for ID {test_id} (len: {test_len}) vs original ID {original_id} (len: {orig_len})",
                        description=f"BOLA/IDOR: Accessing resource ID {test_id} returns different user data without authorization check.",
                        cvss_score=7.5,
                        owasp_category="A01:2021 - Broken Access Control",
                        primitive=AttackPrimitive.DATA_ACCESS,
                    )

        return None

    async def _test_param_idor(
        self,
        session: httpx.AsyncClient,
        endpoint: CrawledEndpoint,
        param_name: str,
        original_value: str,
    ) -> Optional[Finding]:
        """Test IDOR in query parameters."""
        params = dict(endpoint.params) if endpoint.params else {}
        orig_response = await self._send_request(session, endpoint.url, params=params)

        if orig_response is None or orig_response.status_code != 200:
            return None

        orig_hash = hashlib.md5(orig_response.text.encode()).hexdigest()

        # Try swapped values
        if original_value.isdigit():
            test_values = [str(int(original_value) + 1), str(int(original_value) - 1), "1"]
        else:
            test_values = ["1", "admin", "test"]

        for test_val in test_values:
            test_params = dict(params)
            test_params[param_name] = test_val
            test_response = await self._send_request(session, endpoint.url, params=test_params)

            if test_response and test_response.status_code == 200:
                test_hash = hashlib.md5(test_response.text.encode()).hexdigest()
                if test_hash != orig_hash and len(test_response.text) > 50:
                    return Finding(
                        vuln_type=AttackType.BOLA,
                        severity=SeverityLevel.HIGH,
                        url=endpoint.url,
                        method=endpoint.method,
                        parameter=param_name,
                        payload=f"Changed {param_name} from {original_value} to {test_val}",
                        evidence=f"Different response for {param_name}={test_val} vs {param_name}={original_value}",
                        description=f"BOLA/IDOR in parameter '{param_name}': swapping ID returns different user's data.",
                        cvss_score=7.5,
                        owasp_category="A01:2021 - Broken Access Control",
                        primitive=AttackPrimitive.DATA_ACCESS,
                    )

        return None
