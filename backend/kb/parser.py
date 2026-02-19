"""LLM-powered exploit file parser via Ollama."""

import json
import re
from typing import Dict, Any, Optional
from llm.ollama_client import query_ollama


MARKDOWN_PARSE_SYSTEM = """You are a cybersecurity exploit analyst. Parse the following exploit writeup
into structured JSON. Extract ONLY what is explicitly stated. Do NOT invent information.

Output ONLY valid JSON (no markdown, no explanation):
{
  "title": "string",
  "cve_id": "CVE-XXXX-XXXXX or null",
  "attack_type": "one of: SQLi, XSS, SSTI, CSTI, RCE, SSRF, IDOR, BAC, BOLA, Auth_Bypass, Command_Injection, Misconfig, Other",
  "severity": "critical|high|medium|low",
  "affected_software": ["software names"],
  "affected_versions": ["version ranges"],
  "prerequisites": ["list of conditions needed for exploitation"],
  "steps": [
    {"order": 1, "action": "description of step", "payload": "payload if any", "expected_result": "what happens"}
  ],
  "impact": "what the attacker ultimately achieves",
  "tags": ["relevant keywords for searchability"]
}"""


CODE_PARSE_SYSTEM = """You are a cybersecurity code analyst. Analyze this exploit PoC code
and extract structured information. Output ONLY valid JSON (no markdown):
{
  "title": "string",
  "cve_id": "CVE-XXXX-XXXXX or null",
  "attack_type": "one of: SQLi, XSS, SSTI, CSTI, RCE, SSRF, IDOR, BAC, BOLA, Auth_Bypass, Command_Injection, Misconfig, Other",
  "severity": "critical|high|medium|low",
  "affected_software": ["software names"],
  "target_pattern": "URL pattern or service targeted",
  "payload": "the core malicious payload/input",
  "technique": "how the exploit works",
  "impact": "what the attacker achieves",
  "tags": ["relevant keywords"]
}"""


CHAIN_PARSE_SYSTEM = """You are a cybersecurity attack chain analyst. Extract an ordered attack chain
from this document. Output ONLY valid JSON (no markdown):
{
  "title": "chain title",
  "description": "overall chain description",
  "chain_type": "one of: privilege_escalation, data_exfil, full_takeover, lateral_movement, denial_of_service",
  "overall_impact": "end result of the chain",
  "steps": [
    {
      "step_order": 1,
      "step_type": "one of: recon, exploit, post_exploit, pivot, exfil",
      "description": "what this step does",
      "prerequisites": ["what's needed for this step"],
      "output_data": {"key": "what this step produces for the next step"}
    }
  ]
}"""


def detect_file_type(filename: str, content: str) -> str:
    """Detect exploit file format."""
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    if ext in ("md", "markdown"):
        return "markdown"
    elif ext in ("py", "python"):
        return "python"
    elif ext in ("yaml", "yml"):
        return "yaml"
    elif ext == "json":
        return "json"
    elif ext in ("rb", "ruby"):
        return "ruby"
    elif ext in ("js", "ts"):
        return "javascript"
    elif ext in ("sh", "bash"):
        return "shell"
    elif ext == "txt":
        # Check content for clues
        if "```" in content or "##" in content:
            return "markdown"
        return "text"
    else:
        return "text"


def preprocess_content(content: str) -> Dict[str, Any]:
    """Extract structured hints via regex before LLM processing."""
    hints = {}

    # CVE IDs
    cves = re.findall(r'CVE-\d{4}-\d{4,7}', content, re.IGNORECASE)
    if cves:
        hints["cve_ids"] = list(set(cves))

    # URLs
    urls = re.findall(r'https?://[^\s\'"<>]+', content)
    if urls:
        hints["urls"] = urls[:10]

    # Code blocks
    code_blocks = re.findall(r'```[\w]*\n(.*?)```', content, re.DOTALL)
    if code_blocks:
        hints["has_code_blocks"] = True
        hints["code_block_count"] = len(code_blocks)

    # Common vulnerability keywords
    vuln_keywords = {
        "sql injection": "SQLi", "sqli": "SQLi",
        "cross-site scripting": "XSS", "xss": "XSS",
        "server-side template injection": "SSTI", "ssti": "SSTI",
        "client-side template injection": "CSTI", "csti": "CSTI",
        "remote code execution": "RCE", "rce": "RCE",
        "ssrf": "SSRF", "server-side request forgery": "SSRF",
        "idor": "IDOR", "insecure direct object": "IDOR",
        "broken access control": "BAC",
        "command injection": "Command_Injection",
        "deserialization": "Deserialization",
        "prototype pollution": "Prototype_Pollution",
    }
    content_lower = content.lower()
    for keyword, attack_type in vuln_keywords.items():
        if keyword in content_lower:
            hints["likely_attack_type"] = attack_type
            break

    return hints


async def parse_exploit_file(filename: str, content: str) -> Optional[Dict[str, Any]]:
    """Parse an exploit file into structured data using LLM."""
    file_type = detect_file_type(filename, content)
    hints = preprocess_content(content)

    # Truncate content for model context window
    max_chars = 6000
    truncated = content[:max_chars]
    if len(content) > max_chars:
        truncated += "\n\n[... content truncated ...]"

    # Choose system prompt
    if file_type in ("markdown", "text"):
        system = MARKDOWN_PARSE_SYSTEM
    elif file_type in ("python", "ruby", "javascript", "shell"):
        system = CODE_PARSE_SYSTEM
    else:
        system = MARKDOWN_PARSE_SYSTEM

    prompt = f"FILE: {filename}\nTYPE: {file_type}\n\nCONTENT:\n{truncated}"

    if hints:
        prompt += f"\n\nPRE-EXTRACTED HINTS: {json.dumps(hints)}"

    try:
        response = await query_ollama(prompt, system=system)
        # Extract JSON from response
        parsed = extract_json(response)
        if parsed:
            # Merge pre-extracted hints
            if "cve_ids" in hints and not parsed.get("cve_id"):
                parsed["cve_id"] = hints["cve_ids"][0]
            return parsed
    except Exception as e:
        print(f"LLM parsing failed for {filename}: {e}, using regex fallback")

    # Fallback: build structured data from regex hints
    return _fallback_parse(filename, content, hints)


async def parse_chain_document(content: str) -> Optional[Dict[str, Any]]:
    """Parse a document describing an attack chain."""
    truncated = content[:6000]
    try:
        response = await query_ollama(truncated, system=CHAIN_PARSE_SYSTEM)
        return extract_json(response)
    except Exception as e:
        print(f"Error parsing chain: {e}")
        return None


def _fallback_parse(filename: str, content: str, hints: Dict[str, Any]) -> Dict[str, Any]:
    """Regex-based fallback parser when LLM is unavailable."""
    # Extract title from first heading or filename
    title_match = re.search(r'^#\s+(.+)$', content, re.MULTILINE)
    title = title_match.group(1).strip() if title_match else filename.rsplit(".", 1)[0].replace("-", " ").replace("_", " ").title()

    # Extract first paragraph as description
    paragraphs = re.split(r'\n\n+', content.strip())
    description = ""
    for p in paragraphs:
        cleaned = p.strip()
        if cleaned and not cleaned.startswith("#") and len(cleaned) > 20:
            description = cleaned[:500]
            break

    # Determine attack type from hints or content
    attack_type = hints.get("likely_attack_type", "Other")

    # Determine severity heuristically
    content_lower = content.lower()
    severity = "medium"
    if any(w in content_lower for w in ["critical", "rce", "remote code execution", "full compromise", "unauthenticated"]):
        severity = "critical"
    elif any(w in content_lower for w in ["high", "privilege escalation", "admin", "bypass authentication"]):
        severity = "high"
    elif any(w in content_lower for w in ["low", "information disclosure", "verbose error"]):
        severity = "low"

    # Extract steps from numbered lists
    steps = []
    step_matches = re.findall(r'^\s*(\d+)[.\)]\s+(.+)$', content, re.MULTILINE)
    for order, action in step_matches[:10]:
        steps.append({"order": int(order), "action": action.strip(), "payload": "", "expected_result": ""})

    # Extract code blocks as potential payloads
    code_blocks = re.findall(r'```[\w]*\n(.*?)```', content, re.DOTALL)
    if code_blocks and steps:
        for i, block in enumerate(code_blocks[:len(steps)]):
            steps[i]["payload"] = block.strip()[:200]

    # Build tags
    tags = []
    if hints.get("cve_ids"):
        tags.extend(hints["cve_ids"])
    tags.append(attack_type.lower())

    return {
        "title": title,
        "cve_id": hints.get("cve_ids", [None])[0] if hints.get("cve_ids") else None,
        "attack_type": attack_type,
        "severity": severity,
        "description": description or f"Exploit from {filename}",
        "prerequisites": [],
        "steps": steps,
        "impact": "",
        "remediation": "",
        "tags": tags,
    }


def extract_json(text: str) -> Optional[Dict[str, Any]]:
    """Extract JSON from LLM response, handling markdown wrapping."""
    # Try direct parse
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Try extracting from markdown code blocks
    json_match = re.search(r'```(?:json)?\s*\n?(.*?)```', text, re.DOTALL)
    if json_match:
        try:
            return json.loads(json_match.group(1).strip())
        except json.JSONDecodeError:
            pass

    # Try finding JSON object in text
    brace_match = re.search(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', text, re.DOTALL)
    if brace_match:
        try:
            return json.loads(brace_match.group())
        except json.JSONDecodeError:
            pass

    return None
