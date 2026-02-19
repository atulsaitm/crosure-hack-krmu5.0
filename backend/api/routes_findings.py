"""Findings & Remediation API routes."""

from fastapi import APIRouter, HTTPException
from typing import List

from core.models import (
    Finding, RemediationRequest, RemediationResponse,
    TriageResponse,
)
from llm.ollama_client import get_remediation, triage_finding

router = APIRouter(prefix="/api/findings", tags=["findings"])


@router.post("/remediate", response_model=RemediationResponse)
async def get_finding_remediation(request: RemediationRequest):
    """Get AI-powered remediation for a finding."""
    f = request.finding
    try:
        remediation = await get_remediation(
            vuln_type=f.get("vuln_type", f.get("type", "unknown")),
            url=f.get("url", "N/A"),
            parameter=f.get("parameter", ""),
            evidence=f.get("evidence", ""),
            severity=f.get("severity", "medium"),
            chain_context=f.get("chain_context", ""),
        )
        return RemediationResponse(remediation=remediation)
    except Exception as e:
        # Fallback: provide a basic remediation when Ollama is unavailable
        vuln = f.get("vuln_type", f.get("type", "unknown"))
        fallback = _fallback_remediation(vuln)
        return RemediationResponse(remediation=fallback)


@router.post("/triage", response_model=TriageResponse)
async def triage_vuln_finding(request: RemediationRequest):
    """AI triage a finding for severity validation."""
    f = request.finding
    try:
        result = await triage_finding(
            vuln_type=f.get("vuln_type", f.get("type", "unknown")),
            url=f.get("url", "N/A"),
            payload=f.get("payload", f.get("parameter", "")),
            evidence=f.get("evidence", ""),
        )
        return TriageResponse(**result)
    except Exception as e:
        return TriageResponse(verdict="needs_review", confidence=0.5, reasoning=f"Auto-triage unavailable: {e}")


@router.post("/batch-remediate", response_model=List[RemediationResponse])
async def batch_remediate(findings: List[dict]):
    """Get remediation for multiple findings."""
    results = []
    for finding in findings[:20]:  # Limit to 20
        try:
            remediation = await get_remediation(finding)
            results.append(RemediationResponse(remediation=remediation))
        except Exception:
            results.append(RemediationResponse(
                remediation=f"Apply security best practices for {finding.get('vuln_type', 'this vulnerability')}."
            ))
    return results


def _fallback_remediation(vuln_type: str) -> str:
    """Provide basic remediation when LLM is unavailable."""
    guides = {
        "xss": "## Remediation: Cross-Site Scripting (XSS)\n\n"
            "1. **Encode all output** — Use context-aware encoding (HTML entity, JS, URL) before rendering user input.\n"
            "2. **Use Content-Security-Policy** — Set `Content-Security-Policy: default-src 'self'` header.\n"
            "3. **Sanitize input** — Use an allowlist approach; strip `<script>`, event handlers, and `javascript:` URIs.\n"
            "4. **Use framework auto-escaping** — React JSX, Django templates, and Jinja2 auto-escape by default.\n",
        "sqli": "## Remediation: SQL Injection\n\n"
            "1. **Use parameterized queries** — Never concatenate user input into SQL strings.\n"
            "2. **Use an ORM** — SQLAlchemy, Prisma, or Sequelize handle escaping automatically.\n"
            "3. **Apply least-privilege DB accounts** — App DB user should not have DDL or admin rights.\n"
            "4. **Enable WAF rules** — Block common SQLi patterns at the edge.\n",
        "csrf": "## Remediation: Cross-Site Request Forgery\n\n"
            "1. **Use anti-CSRF tokens** — Include a unique token per session in every state-changing form.\n"
            "2. **Set SameSite cookies** — Use `SameSite=Strict` or `SameSite=Lax` on session cookies.\n"
            "3. **Verify Origin/Referer headers** — Reject requests from unexpected origins.\n",
        "ssrf": "## Remediation: Server-Side Request Forgery\n\n"
            "1. **Allowlist URLs** — Only permit requests to known, trusted hosts.\n"
            "2. **Block internal ranges** — Deny 127.0.0.0/8, 10.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, 192.168.0.0/16.\n"
            "3. **Disable redirects** — Or validate each redirect destination against the allowlist.\n",
        "idor": "## Remediation: Insecure Direct Object Reference\n\n"
            "1. **Enforce authorization checks** — Verify the authenticated user owns/has access to the requested resource.\n"
            "2. **Use indirect references** — Map user-facing IDs to internal IDs server-side.\n"
            "3. **Log access attempts** — Detect and alert on enumeration patterns.\n",
        "open_redirect": "## Remediation: Open Redirect\n\n"
            "1. **Allowlist redirect targets** — Only redirect to known, trusted URLs.\n"
            "2. **Validate URL scheme** — Block `javascript:`, `data:`, and other dangerous schemes.\n"
            "3. **Use relative paths** — Avoid accepting full URLs as redirect parameters.\n",
        "header_injection": "## Remediation: Header Injection\n\n"
            "1. **Sanitize header values** — Strip CR/LF characters from user-controlled header values.\n"
            "2. **Use framework APIs** — Use `response.headers[key] = value` instead of raw header writes.\n",
        "cors": "## Remediation: CORS Misconfiguration\n\n"
            "1. **Restrict allowed origins** — Never use `Access-Control-Allow-Origin: *` with credentials.\n"
            "2. **Validate Origin header** — Check against an explicit allowlist of trusted domains.\n"
            "3. **Limit exposed headers** — Only expose headers the frontend actually needs.\n",
    }
    # Try exact match, then prefix match
    vt = vuln_type.lower().replace("-", "_").replace(" ", "_")
    if vt in guides:
        return guides[vt]
    for key, val in guides.items():
        if key in vt or vt in key:
            return val
    return (
        f"## Remediation: {vuln_type}\n\n"
        "1. **Validate and sanitize all user input** at every trust boundary.\n"
        "2. **Apply the principle of least privilege** to all systems and accounts.\n"
        "3. **Keep dependencies updated** and monitor for known CVEs.\n"
        "4. **Enable security headers** — HSTS, CSP, X-Content-Type-Options, X-Frame-Options.\n"
        "5. **Review OWASP guidance** for this vulnerability class.\n"
    )
