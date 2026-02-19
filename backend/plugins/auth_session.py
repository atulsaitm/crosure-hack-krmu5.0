"""Authentication & Session Management flaw detection plugin."""

import re
import base64
import json
from typing import List, Optional
import httpx

from plugins.base import BasePlugin
from core.models import Finding, CrawledEndpoint, SeverityLevel, AttackType, AttackPrimitive


# Common weak credentials
DEFAULT_CREDS = [
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "admin123"),
    ("admin", "123456"),
    ("root", "root"),
    ("test", "test"),
    ("user", "user"),
    ("admin", ""),
    ("guest", "guest"),
]

# Weak JWT secrets to try
WEAK_JWT_SECRETS = [
    "secret", "password", "123456", "admin", "key",
    "jwt_secret", "supersecret", "changeme", "test",
    "default", "mysecret", "s3cr3t", "qwerty",
    "letmein", "welcome", "abc123", "token_secret",
]


class AuthSessionPlugin(BasePlugin):
    name = "auth_session"
    description = "Authentication and session management flaw detection"

    async def detect(
        self,
        endpoint: CrawledEndpoint,
        session: httpx.AsyncClient,
        context: Optional[dict] = None,
    ) -> List[Finding]:
        findings = []

        # ── 1. Cookie Security Flags ──
        response = await self._send_request(
            session, endpoint.url, method=endpoint.method,
            params=endpoint.params if endpoint.method == "GET" else None,
            data=endpoint.form_data if endpoint.method == "POST" else None,
        )

        if response:
            cookie_findings = self._check_cookie_flags(response, endpoint.url)
            findings.extend(cookie_findings)

            # ── 2. JWT Vulnerabilities ──
            jwt_findings = await self._check_jwt(response, session, endpoint)
            findings.extend(jwt_findings)

        # ── 3. Default Credentials (only on login-like endpoints) ──
        if self._is_login_endpoint(endpoint):
            cred_findings = await self._check_default_creds(session, endpoint)
            findings.extend(cred_findings)

        return findings

    def _check_cookie_flags(self, response: httpx.Response, url: str) -> List[Finding]:
        """Check Set-Cookie headers for missing security flags."""
        findings = []
        set_cookies = response.headers.get_list("set-cookie") if hasattr(response.headers, 'get_list') else []

        if not set_cookies:
            # Fallback for headers without get_list
            raw = response.headers.get("set-cookie", "")
            if raw:
                set_cookies = [raw]

        for cookie in set_cookies:
            cookie_lower = cookie.lower()
            cookie_name = cookie.split("=")[0].strip() if "=" in cookie else "unknown"

            if "httponly" not in cookie_lower:
                findings.append(Finding(
                    vuln_type=AttackType.SESSION,
                    severity=SeverityLevel.MEDIUM,
                    url=url,
                    method="GET",
                    parameter=f"cookie:{cookie_name}",
                    evidence=f"Set-Cookie: {cookie[:100]}...",
                    description=f"Cookie '{cookie_name}' missing HttpOnly flag. Accessible via JavaScript (XSS risk).",
                    cvss_score=4.3,
                    owasp_category="A07:2021 - Identification and Authentication Failures",
                    primitive=AttackPrimitive.SESSION_HIJACK,
                ))

            if "secure" not in cookie_lower and url.startswith("https"):
                findings.append(Finding(
                    vuln_type=AttackType.SESSION,
                    severity=SeverityLevel.MEDIUM,
                    url=url,
                    method="GET",
                    parameter=f"cookie:{cookie_name}",
                    evidence=f"Set-Cookie: {cookie[:100]}...",
                    description=f"Cookie '{cookie_name}' missing Secure flag. Sent over unencrypted HTTP.",
                    cvss_score=4.3,
                    owasp_category="A07:2021 - Identification and Authentication Failures",
                    primitive=AttackPrimitive.SESSION_HIJACK,
                ))

            if "samesite" not in cookie_lower:
                findings.append(Finding(
                    vuln_type=AttackType.SESSION,
                    severity=SeverityLevel.LOW,
                    url=url,
                    method="GET",
                    parameter=f"cookie:{cookie_name}",
                    evidence=f"Set-Cookie: {cookie[:100]}...",
                    description=f"Cookie '{cookie_name}' missing SameSite attribute. Vulnerable to CSRF.",
                    cvss_score=3.1,
                    owasp_category="A07:2021 - Identification and Authentication Failures",
                    primitive=AttackPrimitive.SESSION_HIJACK,
                ))

        return findings

    async def _check_jwt(
        self, response: httpx.Response, session: httpx.AsyncClient, endpoint: CrawledEndpoint
    ) -> List[Finding]:
        """Check for JWT vulnerabilities."""
        findings = []

        # Find JWTs in cookies and response body
        jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'
        cookies_str = str(response.headers.get("set-cookie", ""))
        jwt_tokens = re.findall(jwt_pattern, cookies_str + " " + response.text[:10000])

        for token in jwt_tokens[:3]:  # Test up to 3 tokens
            parts = token.split(".")
            if len(parts) < 2:
                continue

            try:
                # Decode header
                header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
                header = json.loads(base64.urlsafe_b64decode(header_b64))

                # Decode payload
                payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
                payload = json.loads(base64.urlsafe_b64decode(payload_b64))

                # ── Check "none" algorithm ──
                none_finding = await self._test_jwt_none(session, endpoint, header, payload, token)
                if none_finding:
                    findings.append(none_finding)

                # ── Check expired token acceptance ──
                if "exp" in payload:
                    import time as time_mod
                    if payload["exp"] < time_mod.time():
                        findings.append(Finding(
                            vuln_type=AttackType.JWT,
                            severity=SeverityLevel.MEDIUM,
                            url=endpoint.url,
                            method="GET",
                            evidence=f"JWT expired at {payload['exp']} but still accepted",
                            description="Expired JWT token is still accepted by the server.",
                            cvss_score=5.3,
                            owasp_category="A07:2021 - Identification and Authentication Failures",
                            primitive=AttackPrimitive.AUTH_BYPASS,
                        ))

                # ── Check weak secret ──
                weak_finding = self._test_weak_jwt_secret(token, header, payload, endpoint.url)
                if weak_finding:
                    findings.append(weak_finding)

            except Exception:
                continue

        return findings

    async def _test_jwt_none(
        self, session, endpoint, header, payload, original_token
    ) -> Optional[Finding]:
        """Test JWT none algorithm bypass."""
        try:
            # Create token with alg:none
            header["alg"] = "none"
            new_header = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
            new_payload = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
            forged_token = f"{new_header}.{new_payload}."

            # Try request with forged token
            headers = {"Authorization": f"Bearer {forged_token}"}
            response = await self._send_request(session, endpoint.url, headers=headers)

            if response and response.status_code == 200 and len(response.text) > 100:
                return Finding(
                    vuln_type=AttackType.JWT,
                    severity=SeverityLevel.CRITICAL,
                    url=endpoint.url,
                    method="GET",
                    payload=f"alg:none token: {forged_token[:50]}...",
                    evidence="Server accepts JWT with algorithm 'none'",
                    description="JWT none algorithm bypass: server accepts unsigned tokens. Full authentication bypass possible.",
                    cvss_score=9.8,
                    owasp_category="A07:2021 - Identification and Authentication Failures",
                    primitive=AttackPrimitive.AUTH_BYPASS,
                )
        except Exception:
            pass
        return None

    def _test_weak_jwt_secret(self, token, header, payload, url) -> Optional[Finding]:
        """Test if JWT uses a weak signing secret."""
        try:
            import jwt as pyjwt
            for secret in WEAK_JWT_SECRETS:
                try:
                    pyjwt.decode(token, secret, algorithms=[header.get("alg", "HS256")])
                    return Finding(
                        vuln_type=AttackType.JWT,
                        severity=SeverityLevel.CRITICAL,
                        url=url,
                        method="GET",
                        payload=f"Weak secret: '{secret}'",
                        evidence=f"JWT signed with weak secret '{secret}'. Token can be forged.",
                        description="JWT uses a weak/guessable signing secret. An attacker can forge any token.",
                        cvss_score=9.1,
                        owasp_category="A07:2021 - Identification and Authentication Failures",
                        primitive=AttackPrimitive.AUTH_BYPASS,
                    )
                except Exception:
                    continue
        except ImportError:
            pass
        return None

    def _is_login_endpoint(self, endpoint: CrawledEndpoint) -> bool:
        """Check if this looks like a login endpoint."""
        url_lower = endpoint.url.lower()
        return any(kw in url_lower for kw in ["login", "signin", "sign-in", "auth", "authenticate"])

    async def _check_default_creds(
        self, session: httpx.AsyncClient, endpoint: CrawledEndpoint
    ) -> List[Finding]:
        """Check for default/weak credentials on login endpoints."""
        findings = []

        for username, password in DEFAULT_CREDS[:5]:
            data = {}
            if endpoint.form_data:
                data = dict(endpoint.form_data)
                # Guess field names
                for key in data:
                    if any(k in key.lower() for k in ["user", "email", "login", "name"]):
                        data[key] = username
                    elif any(k in key.lower() for k in ["pass", "pwd", "secret"]):
                        data[key] = password
            else:
                data = {"username": username, "password": password}

            response = await self._send_request(
                session, endpoint.url, method="POST", data=data
            )

            if response and response.status_code in (200, 302):
                body_lower = response.text.lower()
                # Check for successful login indicators
                if any(kw in body_lower for kw in ["welcome", "dashboard", "logout", "profile"]):
                    findings.append(Finding(
                        vuln_type=AttackType.AUTH_BYPASS,
                        severity=SeverityLevel.CRITICAL,
                        url=endpoint.url,
                        method="POST",
                        payload=f"Credentials: {username}:{password}",
                        evidence=f"Login successful with {username}:{password}",
                        description=f"Default credentials accepted: {username}:{password}",
                        cvss_score=9.8,
                        owasp_category="A07:2021 - Identification and Authentication Failures",
                        primitive=AttackPrimitive.AUTH_BYPASS,
                    ))
                    break

        return findings
