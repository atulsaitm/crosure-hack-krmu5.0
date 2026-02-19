"""Ollama LLM client for remediation, triage, and exploit parsing."""

import httpx
import json
from typing import Optional
from config import settings


async def query_ollama(
    prompt: str,
    system: str = "",
    model: Optional[str] = None,
    temperature: float = 0.3,
    max_tokens: int = 1024,
) -> str:
    """Query the Ollama API."""
    model = model or settings.OLLAMA_MODEL

    async with httpx.AsyncClient(timeout=120.0) as client:
        response = await client.post(
            f"{settings.OLLAMA_URL}/api/generate",
            json={
                "model": model,
                "prompt": prompt,
                "system": system,
                "stream": False,
                "options": {
                    "temperature": temperature,
                    "num_predict": max_tokens,
                },
            },
        )
        response.raise_for_status()
        return response.json().get("response", "")


REMEDIATION_SYSTEM = """You are a senior application security engineer. Given a vulnerability finding,
provide a concise, actionable remediation. Output in this exact format:

## Risk Explanation
(2-3 sentences explaining the risk)

## Code Fix
```
// BEFORE (vulnerable)
<vulnerable code pattern>

// AFTER (fixed)
<fixed code pattern>
```

## Configuration Changes
(Specific config changes needed, or "None required")

## Chain Impact
(If this vulnerability is part of an attack chain, explain how fixing it breaks the chain)

Be specific to the technology detected. Do NOT give generic advice."""


TRIAGE_SYSTEM = """You are a vulnerability triage analyst. Given a potential vulnerability finding
with evidence (HTTP request/response), determine if this is a TRUE POSITIVE or FALSE POSITIVE.

Output ONLY valid JSON:
{"verdict": "true_positive" or "false_positive" or "needs_review", "confidence": 0.0 to 1.0, "reasoning": "brief explanation"}"""


async def get_remediation(
    vuln_type: str,
    url: str,
    parameter: str,
    evidence: str,
    severity: str,
    chain_context: str = "",
) -> str:
    """Generate remediation advice for a vulnerability finding."""
    prompt = f"""Vulnerability: {vuln_type}
URL: {url}
Parameter: {parameter or 'N/A'}
Evidence: {evidence or 'N/A'}
Severity: {severity}
Attack Chain Context: {chain_context or 'Not part of a known chain'}

Provide specific remediation steps."""

    return await query_ollama(prompt, system=REMEDIATION_SYSTEM)


async def triage_finding(
    vuln_type: str,
    url: str,
    payload: str,
    evidence: str,
) -> dict:
    """Analyze whether a finding is a true or false positive."""
    prompt = f"""Scan found potential {vuln_type} at {url}
Payload sent: {payload or 'N/A'}
Response evidence: {(evidence or '')[:2000]}

Is this a true positive?"""

    try:
        result = await query_ollama(prompt, system=TRIAGE_SYSTEM)
        # Try to parse JSON from response
        import re
        json_match = re.search(r'\{.*\}', result, re.DOTALL)
        if json_match:
            return json.loads(json_match.group())
    except Exception:
        pass

    return {"verdict": "needs_review", "confidence": 0.5, "reasoning": "Could not analyze automatically"}
