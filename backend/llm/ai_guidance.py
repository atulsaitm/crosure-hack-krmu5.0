"""AI Guidance Engine — Tech-stack-adaptive scanning, KB-informed prioritization, and real-time triage.

This is the core AI brain of Crosure. It makes three key decisions:
1. BEFORE scan: Which plugins to prioritize based on detected tech stack + KB CVE data
2. DURING scan: Real-time confidence scoring via LLM triage (batched)
3. AFTER scan: Context-aware remediation (existing, enhanced with tech context)
"""

import asyncio
import json
import logging
import re
from typing import List, Dict, Any, Optional, Tuple

import httpx
from config import settings
from core.models import Finding, SeverityLevel, AttackType

logger = logging.getLogger("crosure.ai_guidance")


# ── Tech Stack → Plugin Priority Mapping ──────────────────────────────────────
# Maps detected technologies to plugins that should be prioritized (run first,
# findings weighted higher). This is deterministic and doesn't need the LLM.

TECH_PLUGIN_MAP: Dict[str, List[Tuple[str, float]]] = {
    # Server-side template engines → SSTI is critical
    "jinja2":       [("ssti", 2.0), ("rce", 1.5)],
    "mako":         [("ssti", 2.0), ("rce", 1.5)],
    "twig":         [("ssti", 2.0), ("rce", 1.5)],
    "freemarker":   [("ssti", 2.0), ("rce", 1.5)],
    "thymeleaf":    [("ssti", 1.8), ("rce", 1.3)],
    "velocity":     [("ssti", 2.0), ("rce", 1.5)],

    # Client-side frameworks → CSTI / XSS
    "angular":      [("csti", 2.0), ("xss", 1.5)],
    "angularjs":    [("csti", 2.5), ("xss", 1.8)],  # AngularJS sandbox bypass
    "react":        [("xss", 1.3), ("csti", 1.2)],
    "vue":          [("csti", 1.8), ("xss", 1.5)],
    "nextjs":       [("xss", 1.3), ("misconfig", 1.3), ("auth_session", 1.2)],
    "nuxt":         [("xss", 1.3), ("misconfig", 1.3)],

    # PHP → SQLi, RCE, file inclusion
    "php":          [("sqli", 1.8), ("rce", 1.5), ("xss", 1.3)],

    # Java / Spring
    "spring":       [("ssti", 1.5), ("rce", 1.3), ("bola", 1.3)],
    "tomcat":       [("misconfig", 1.5), ("rce", 1.3)],
    "apache":       [("misconfig", 1.3)],

    # Node.js / Express → prototype pollution, SSRF
    "express":      [("emerging", 1.8), ("xss", 1.3), ("sqli", 1.2)],
    "node.js":      [("emerging", 1.8), ("rce", 1.3)],
    "nodejs":       [("emerging", 1.8), ("rce", 1.3)],
    "koa":          [("emerging", 1.5), ("xss", 1.3)],

    # Python frameworks
    "flask":        [("ssti", 2.0), ("sqli", 1.3)],
    "django":       [("sqli", 1.3), ("misconfig", 1.3), ("auth_session", 1.3)],
    "fastapi":      [("bola", 1.5), ("auth_session", 1.3)],
    "werkzeug":     [("ssti", 1.8), ("misconfig", 1.5)],

    # .NET
    "asp.net":      [("sqli", 1.3), ("xss", 1.3), ("misconfig", 1.3)],
    "iis":          [("misconfig", 1.5)],

    # Database backends (from error pages, headers)
    "mysql":        [("sqli", 2.0)],
    "postgresql":   [("sqli", 2.0)],
    "mongodb":      [("sqli", 1.5), ("bola", 1.5)],  # NoSQL injection
    "sqlite":       [("sqli", 2.0)],

    # API patterns
    "graphql":      [("emerging", 2.0), ("bola", 1.5)],
    "swagger":      [("bola", 1.5), ("misconfig", 1.5)],
    "openapi":      [("bola", 1.5), ("misconfig", 1.5)],

    # CMS
    "wordpress":    [("sqli", 1.5), ("xss", 1.5), ("auth_session", 1.5), ("misconfig", 1.3)],
    "drupal":       [("sqli", 1.5), ("rce", 1.5)],

    # Cloud / Infra
    "nginx":        [("misconfig", 1.5), ("cors", 1.3)],
    "cloudflare":   [("cors", 1.2)],
}


def compute_plugin_priorities(
    tech_stack: List[str],
    framework: Optional[str] = None,
) -> Dict[str, float]:
    """
    Given discovered tech stack, compute a priority multiplier for each plugin.
    Higher multiplier → run earlier, weight findings higher.
    Returns: {"sqli": 2.0, "xss": 1.5, ...}
    """
    priorities: Dict[str, float] = {}

    # Normalize tech identifiers
    all_tech = [t.lower().strip() for t in tech_stack]
    if framework:
        all_tech.append(framework.lower().strip())

    for tech in all_tech:
        for key, plugin_weights in TECH_PLUGIN_MAP.items():
            if key in tech:
                for plugin_name, weight in plugin_weights:
                    # Take the highest weight if multiple techs match the same plugin
                    if plugin_name not in priorities or weight > priorities[plugin_name]:
                        priorities[plugin_name] = weight

    logger.info(f"AI Guidance: Tech stack {all_tech} → plugin priorities: {priorities}")
    return priorities


def sort_plugins_by_priority(plugins: list, priorities: Dict[str, float]) -> list:
    """Sort plugins so highest-priority ones run first."""
    return sorted(plugins, key=lambda p: priorities.get(p.name, 1.0), reverse=True)


# ── KB-Informed CVE Hints ─────────────────────────────────────────────────────

def query_kb_for_tech(tech_stack: List[str]) -> List[Dict[str, Any]]:
    """
    Query both ChromaDB (semantic) and PostgreSQL (structured) for known 
    CVEs/exploits matching detected tech. Returns sorted by relevance.
    """
    from kb.embeddings import search_exploits

    all_hints: List[Dict[str, Any]] = []

    if not tech_stack:
        return all_hints

    # 1. Semantic search in ChromaDB
    query = f"vulnerabilities exploits CVE for {' '.join(tech_stack[:5])}"
    try:
        results = search_exploits(query, n_results=15)
        for r in results:
            if r.get("distance", 1.0) < 0.8:
                all_hints.append({
                    "id": r["id"],
                    "source": "chromadb",
                    "text": r.get("document", "")[:500],
                    "attack_type": r.get("metadata", {}).get("attack_type", ""),
                    "severity": r.get("metadata", {}).get("severity", ""),
                    "relevance": 1.0 - r.get("distance", 1.0),
                })
    except Exception as e:
        logger.warning(f"AI Guidance: ChromaDB query failed (non-fatal): {e}")

    # 2. Structured query from PostgreSQL — search exploits by attack_type matching tech priorities
    try:
        import asyncio
        from kb.database import get_session, Exploit
        from sqlalchemy import select, or_

        async def _query_db():
            db_hints = []
            async with get_session() as session:
                # Build filters: match exploit descriptions/titles against tech stack
                tech_filters = []
                for tech in tech_stack[:5]:
                    clean = tech.split("/")[0].lower().strip()
                    if len(clean) >= 2:
                        tech_filters.append(Exploit.title.ilike(f"%{clean}%"))
                        tech_filters.append(Exploit.description.ilike(f"%{clean}%"))

                if tech_filters:
                    stmt = (
                        select(Exploit)
                        .where(or_(*tech_filters))
                        .order_by(
                            # Sort: critical > high > medium > low
                            Exploit.severity.desc(),
                            Exploit.created_at.desc(),
                        )
                        .limit(20)
                    )
                    result = await session.execute(stmt)
                    exploits = result.scalars().all()

                    for e in exploits:
                        db_hints.append({
                            "id": f"db_exploit_{e.id}",
                            "source": "postgresql",
                            "text": f"{e.title}: {(e.description or '')[:300]}",
                            "attack_type": e.attack_type or "",
                            "severity": e.severity or "medium",
                            "cve_id": e.cve_id,
                            "relevance": _severity_to_relevance(e.severity),
                        })
            return db_hints

        # Run async DB query from sync context
        try:
            loop = asyncio.get_running_loop()
            # Already in async context — can't nest, skip DB query
            logger.debug("AI Guidance: Skipping DB query (already in async context, will use ChromaDB results)")
        except RuntimeError:
            db_results = asyncio.run(_query_db())
            all_hints.extend(db_results)

    except Exception as e:
        logger.warning(f"AI Guidance: DB query failed (non-fatal): {e}")

    # 3. Sort all hints by relevance (highest first)
    all_hints.sort(key=lambda h: h.get("relevance", 0), reverse=True)

    # Deduplicate by attack_type (keep top per type)
    seen_types = set()
    unique_hints = []
    for h in all_hints:
        at = h.get("attack_type", "").lower()
        key = f"{at}_{h.get('text', '')[:50]}"
        if key not in seen_types:
            seen_types.add(key)
            unique_hints.append(h)
    all_hints = unique_hints[:20]

    logger.info(f"AI Guidance: KB returned {len(all_hints)} relevant CVE hints for {tech_stack}")
    return all_hints


def _severity_to_relevance(severity: str) -> float:
    """Convert severity string to a relevance score for sorting."""
    return {"critical": 1.0, "high": 0.8, "medium": 0.6, "low": 0.3}.get(
        (severity or "medium").lower(), 0.5
    )


def boost_findings_from_kb(
    findings: List[Finding],
    kb_hints: List[Dict[str, Any]],
    plugin_priorities: Dict[str, float],
) -> List[Finding]:
    """
    Boost finding CVSS scores based on KB relevance and tech-stack priority.
    This makes findings that align with known CVEs rank higher.
    """
    # Map attack types from KB hints
    kb_attack_types = set()
    for hint in kb_hints:
        at = hint.get("attack_type", "")
        if at:
            kb_attack_types.add(at.lower())

    for finding in findings:
        boost = 1.0

        # Boost from plugin priorities (tech-stack match)
        plugin_name = _attack_type_to_plugin(finding.vuln_type)
        if plugin_name in plugin_priorities:
            boost *= plugin_priorities[plugin_name]

        # Boost if KB has matching CVEs for this attack type
        if finding.vuln_type.value.lower() in kb_attack_types:
            boost *= 1.2  # KB-informed boost

        # Apply boost to CVSS (cap at 10.0)
        if boost > 1.0:
            original = finding.cvss_score
            finding.cvss_score = min(10.0, finding.cvss_score * boost)
            if finding.cvss_score != original:
                finding.description = (
                    f"[AI-Boosted: {boost:.1f}x — tech-stack & KB match] "
                    + finding.description
                )

    return findings


def _attack_type_to_plugin(attack_type: AttackType) -> str:
    """Map AttackType enum to plugin name."""
    mapping = {
        AttackType.SQLI: "sqli",
        AttackType.XSS: "xss",
        AttackType.SSTI: "ssti",
        AttackType.CSTI: "csti",
        AttackType.RCE: "rce",
        AttackType.BOLA: "bola",
        AttackType.BAC: "bac",
        AttackType.AUTH_BYPASS: "auth_session",
        AttackType.SESSION: "auth_session",
        AttackType.MISCONFIG: "misconfig",
        AttackType.CORS: "cors",
        AttackType.OAST: "oast",
        AttackType.PROTOTYPE_POLLUTION: "emerging",
        AttackType.GRAPHQL: "emerging",
        AttackType.WEBSOCKET: "emerging",
    }
    return mapping.get(attack_type, "")


# ── AI Triage (LLM-based confidence scoring) ─────────────────────────────────

BATCH_TRIAGE_SYSTEM = """You are a vulnerability triage analyst reviewing scanner findings.
For EACH finding, assess whether it is a true positive or false positive based on the evidence.

Output ONLY a valid JSON array with one object per finding:
[
  {"index": 0, "verdict": "true_positive", "confidence": 0.95, "reasoning": "SQL error in response confirms injection"},
  {"index": 1, "verdict": "false_positive", "confidence": 0.8, "reasoning": "Reflected string is HTML-encoded, no XSS"}
]

Verdicts: "true_positive", "false_positive", "needs_review"
Confidence: 0.0 to 1.0"""


async def ai_triage_batch(
    findings: List[Finding],
    batch_size: int = 8,
) -> List[Dict[str, Any]]:
    """
    Run LLM triage on a batch of findings. Returns triage results with
    confidence scores. Uses batching to minimize LLM calls.
    """
    from llm.ollama_client import query_ollama

    all_results = []

    for batch_start in range(0, len(findings), batch_size):
        batch = findings[batch_start:batch_start + batch_size]

        # Build batch prompt
        findings_text = []
        for i, f in enumerate(batch):
            findings_text.append(
                f"[{i}] {f.vuln_type.value} | {f.severity.value} | {f.url} | "
                f"Param: {f.parameter or 'N/A'} | Payload: {(f.payload or 'N/A')[:200]} | "
                f"Evidence: {(f.evidence or 'N/A')[:300]}"
            )

        prompt = (
            f"Triage these {len(batch)} vulnerability findings:\n\n"
            + "\n".join(findings_text)
        )

        try:
            raw = await asyncio.wait_for(
                query_ollama(prompt, system=BATCH_TRIAGE_SYSTEM, temperature=0.1, max_tokens=1500),
                timeout=60.0,
            )

            # Parse JSON array from response
            json_match = re.search(r'\[.*\]', raw, re.DOTALL)
            if json_match:
                triage_results = json.loads(json_match.group())
                for tr in triage_results:
                    idx = tr.get("index", 0)
                    actual_idx = batch_start + idx
                    if actual_idx < len(findings):
                        all_results.append({
                            "finding_id": findings[actual_idx].id,
                            "verdict": tr.get("verdict", "needs_review"),
                            "confidence": float(tr.get("confidence", 0.5)),
                            "reasoning": tr.get("reasoning", ""),
                        })
            else:
                # Fallback — mark batch as needs_review
                for i, f in enumerate(batch):
                    all_results.append({
                        "finding_id": f.id,
                        "verdict": "needs_review",
                        "confidence": 0.5,
                        "reasoning": "LLM response parsing failed",
                    })

        except asyncio.TimeoutError:
            logger.warning(f"AI triage batch timed out (batch {batch_start}-{batch_start + len(batch)})")
            for f in batch:
                all_results.append({
                    "finding_id": f.id,
                    "verdict": "needs_review",
                    "confidence": 0.5,
                    "reasoning": "Triage timed out",
                })
        except Exception as e:
            logger.warning(f"AI triage batch failed: {e}")
            for f in batch:
                all_results.append({
                    "finding_id": f.id,
                    "verdict": "needs_review",
                    "confidence": 0.5,
                    "reasoning": f"Triage error: {str(e)[:100]}",
                })

    logger.info(
        f"AI Triage complete: {len(all_results)} findings triaged — "
        f"{sum(1 for r in all_results if r['verdict'] == 'true_positive')} true positives, "
        f"{sum(1 for r in all_results if r['verdict'] == 'false_positive')} false positives"
    )
    return all_results


def apply_triage_to_findings(
    findings: List[Finding],
    triage_results: List[Dict[str, Any]],
) -> List[Finding]:
    """Apply triage verdicts back to findings — sets confidence and reasoning."""
    triage_map = {tr["finding_id"]: tr for tr in triage_results}

    for finding in findings:
        tr = triage_map.get(finding.id)
        if tr:
            finding.ai_confidence = tr["confidence"]
            finding.ai_verdict = tr["verdict"]
            finding.ai_reasoning = tr["reasoning"]

            # Downweight false positives in CVSS
            if tr["verdict"] == "false_positive" and tr["confidence"] >= 0.7:
                finding.cvss_score = max(1.0, finding.cvss_score * 0.5)
                finding.description = f"[AI: Likely False Positive — {tr['reasoning']}] " + finding.description
            elif tr["verdict"] == "true_positive" and tr["confidence"] >= 0.8:
                finding.description = f"[AI: Confirmed — {tr['reasoning']}] " + finding.description

    return findings


# ── Consolidated AI Guidance Summary ──────────────────────────────────────────

def generate_guidance_summary(
    tech_stack: List[str],
    plugin_priorities: Dict[str, float],
    kb_hints: List[Dict[str, Any]],
) -> str:
    """Generate a human-readable AI guidance summary for the scan."""
    lines = ["AI Guidance Report:"]
    lines.append(f"  Detected tech: {', '.join(tech_stack) if tech_stack else 'Unknown'}")

    if plugin_priorities:
        top = sorted(plugin_priorities.items(), key=lambda x: x[1], reverse=True)[:5]
        lines.append(f"  Priority plugins: {', '.join(f'{p}({w:.1f}x)' for p, w in top)}")

    if kb_hints:
        lines.append(f"  KB matches: {len(kb_hints)} relevant CVEs/exploits found")
        for hint in kb_hints[:3]:
            lines.append(f"    • {hint.get('attack_type', '?')}: {hint.get('text', '')[:80]}...")

    return "\n".join(lines)


# ── Chain-Based Fallback Triage ───────────────────────────────────────────────
# When LLM is unavailable, use attack chain position to assign confidence.
# Findings that appear in chains are more likely true positives because they
# connect to other findings in a logical attack sequence.

# Severity-based base confidence (heuristic)
SEVERITY_CONFIDENCE = {
    "critical": 0.90,
    "high": 0.80,
    "medium": 0.60,
    "low": 0.40,
    "info": 0.20,
}

# Evidence quality indicators that increase confidence
STRONG_EVIDENCE_PATTERNS = [
    r"SQL\s*error|syntax\s*error|ORA-\d+|mysql|pg_query|sqlite",  # SQL errors
    r"<script>|onerror=|onload=|alert\(",                          # XSS reflection
    r"\{\{.*\}\}.*rendered|49|7\*7",                               # SSTI evaluation
    r"root:|/etc/passwd|uid=\d+",                                  # RCE/LFI output
    r"(access|auth).*bypass|admin.*panel|unauthorized.*access",    # Auth bypass
    r"CORS.*allow|Access-Control-Allow-Origin:\s*\*",              # CORS misconfig
]


def chain_based_fallback_triage(
    findings: List[Finding],
    chains: List[Any],
) -> List[Finding]:
    """
    Fallback triage when LLM is unavailable.
    Uses attack chain membership + evidence pattern matching to assign confidence.
    
    Logic:
    - Finding in a chain → higher confidence (chains validate each other)
    - Finding with strong evidence patterns → higher confidence
    - Chain entry points get slightly lower confidence than chain endpoints
    - Isolated findings with weak evidence → lower confidence
    """
    import re as regex_module

    # Build set of finding IDs that appear in chains
    chained_finding_ids = set()
    chain_position = {}  # finding_id → (chain_count, max_step)

    for chain in chains:
        chain_nodes = chain.nodes if hasattr(chain, 'nodes') else []
        for node in chain_nodes:
            fid = node.finding_id if hasattr(node, 'finding_id') else node.get('finding_id', '')
            step = node.step if hasattr(node, 'step') else node.get('step', 1)
            chained_finding_ids.add(fid)
            if fid not in chain_position:
                chain_position[fid] = {"count": 0, "max_step": 0}
            chain_position[fid]["count"] += 1
            chain_position[fid]["max_step"] = max(chain_position[fid]["max_step"], step)

    triaged = 0
    for finding in findings:
        # Start with severity-based baseline
        base_conf = SEVERITY_CONFIDENCE.get(finding.severity.value, 0.5)

        # Evidence quality boost
        evidence_boost = 0.0
        evidence_text = (finding.evidence or "") + (finding.payload or "")
        for pattern in STRONG_EVIDENCE_PATTERNS:
            if regex_module.search(pattern, evidence_text, regex_module.IGNORECASE):
                evidence_boost = 0.15
                break

        # Chain membership boost
        chain_boost = 0.0
        chain_reason = ""
        if finding.id in chained_finding_ids:
            pos = chain_position[finding.id]
            # In more chains → more likely real
            chain_boost = min(0.15, pos["count"] * 0.05)
            # Later steps in chain (exploitation) → higher confidence
            if pos["max_step"] >= 3:
                chain_boost += 0.05
                chain_reason = f"chain endpoint (step {pos['max_step']}, {pos['count']} chains)"
            else:
                chain_reason = f"chain member ({pos['count']} chains)"
        else:
            chain_reason = "isolated finding"

        # Compute final confidence
        confidence = min(1.0, base_conf + evidence_boost + chain_boost)

        # Determine verdict
        if confidence >= 0.75:
            verdict = "true_positive"
        elif confidence <= 0.35:
            verdict = "false_positive"
        else:
            verdict = "needs_review"

        # Apply to finding
        finding.ai_confidence = round(confidence, 2)
        finding.ai_verdict = verdict
        finding.ai_reasoning = f"Chain fallback: {chain_reason}, evidence={'strong' if evidence_boost > 0 else 'weak'}"

        if verdict == "true_positive" and confidence >= 0.85:
            finding.description = f"[Chain-Confirmed: {chain_reason}] " + finding.description
        elif verdict == "false_positive":
            finding.cvss_score = max(1.0, finding.cvss_score * 0.5)
            finding.description = f"[Chain-Deprioritized: {chain_reason}] " + finding.description

        triaged += 1

    tp = sum(1 for f in findings if f.ai_verdict == "true_positive")
    fp = sum(1 for f in findings if f.ai_verdict == "false_positive")
    nr = sum(1 for f in findings if f.ai_verdict == "needs_review")
    logger.info(
        f"Chain Fallback Triage: {triaged} findings — "
        f"{tp} true_positive, {fp} false_positive, {nr} needs_review"
    )

    return findings


async def check_ollama_available() -> bool:
    """Quick check if Ollama is reachable and has a model."""
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"{settings.OLLAMA_URL}/api/tags")
            data = resp.json()
            return len(data.get("models", [])) > 0
    except Exception:
        return False
