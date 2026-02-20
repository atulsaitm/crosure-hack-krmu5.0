"""Core scan orchestrator. Coordinates crawl → detect → chain → store."""

import asyncio
import uuid
import time
from typing import List, Optional, Callable, Awaitable
import httpx

from config import settings
from core.models import (
    ScanRequest, ScanResponse, Finding, AttackChain,
    CrawledEndpoint, ScanPhase, WSEvent, SeverityLevel,
)
from crawler.playwright_crawler import PlaywrightCrawler
from chains.graph_engine import ChainEngine
from kb.embeddings import search_chains_for_findings
from llm.ollama_client import get_remediation, triage_finding
from llm.ai_guidance import (
    compute_plugin_priorities,
    sort_plugins_by_priority,
    query_kb_for_tech,
    boost_findings_from_kb,
    ai_triage_batch,
    apply_triage_to_findings,
    generate_guidance_summary,
    chain_based_fallback_triage,
    check_ollama_available,
)

# Import all plugins
from plugins.sqli import SQLiPlugin
from plugins.xss import XSSPlugin
from plugins.ssti import SSTIPlugin
from plugins.csti import CSTIPlugin
from plugins.rce import RCEPlugin
from plugins.bola import BOLAPlugin
from plugins.bac import BACPlugin
from plugins.auth_session import AuthSessionPlugin
from plugins.misconfig import MisconfigPlugin
from plugins.cors import CORSPlugin
from plugins.oast import OASTPlugin
from plugins.emerging import EmergingThreatsPlugin


ALL_PLUGINS = [
    SQLiPlugin(),
    XSSPlugin(),
    SSTIPlugin(),
    CSTIPlugin(),
    RCEPlugin(),
    BOLAPlugin(),
    BACPlugin(),
    AuthSessionPlugin(),
    MisconfigPlugin(),
    CORSPlugin(),
    OASTPlugin(),
    EmergingThreatsPlugin(),
]


class ScanOrchestrator:
    """Orchestrates the full scan pipeline."""

    def __init__(self, ws_callback: Optional[Callable[[WSEvent], Awaitable[None]]] = None):
        self.ws_callback = ws_callback
        self.scan_id = str(uuid.uuid4())

    async def _emit(self, phase: ScanPhase, message: str, progress: float = 0):
        """Send WebSocket event."""
        if self.ws_callback:
            event = WSEvent(
                scan_id=self.scan_id,
                phase=phase,
                message=message,
                progress=progress,
            )
            try:
                await self.ws_callback(event)
            except Exception:
                pass

    async def run_scan(self, request: ScanRequest) -> ScanResponse:
        """Execute full scan pipeline."""
        start_time = time.time()
        all_findings: List[Finding] = []
        all_chains: List[AttackChain] = []
        errors: List[str] = []

        try:
            # ── Phase 1: Crawl ──
            await self._emit(ScanPhase.CRAWLING, f"Starting crawl of {request.target_url}", 0.05)

            crawler = PlaywrightCrawler(
                target_url=request.target_url,
                max_pages=request.max_pages or settings.MAX_CRAWL_PAGES,
                auth_cookie=request.auth_cookie,
            )

            endpoints, nav_graph = await crawler.crawl()
            tech_stack = crawler.discovered_tech or []
            framework = crawler.detected_framework

            # ── AI Guidance: Compute plugin priorities from tech stack ──
            plugin_priorities = compute_plugin_priorities(tech_stack, framework)
            kb_hints = query_kb_for_tech(tech_stack)
            guidance_summary = generate_guidance_summary(tech_stack, plugin_priorities, kb_hints)
            import logging
            logging.info(guidance_summary)

            await self._emit(
                ScanPhase.CRAWLING,
                f"Crawled {len(endpoints)} endpoints. Tech: {', '.join(tech_stack[:5])}. "
                f"AI prioritized {len(plugin_priorities)} plugins, found {len(kb_hints)} KB matches.",
                0.20,
            )

            if not endpoints:
                await self._emit(ScanPhase.COMPLETE, "No endpoints found to scan.", 1.0)
                return ScanResponse(
                    scan_id=self.scan_id,
                    target_url=request.target_url,
                    findings=[],
                    chains=[],
                    endpoints_crawled=0,
                    scan_duration=time.time() - start_time,
                    errors=["No endpoints found during crawl"],
                )

            # ── Phase 2: AI-Guided Detection ──
            await self._emit(ScanPhase.SCANNING, "Running AI-prioritized vulnerability detection...", 0.25)

            # Select and sort plugins by AI-computed priority
            active_plugins = self._select_plugins(request.scan_scope)
            active_plugins = sort_plugins_by_priority(active_plugins, plugin_priorities)

            # Build cookies for httpx session
            cookies = None
            if request.auth_cookie:
                cookies = {}
                for part in request.auth_cookie.split(";"):
                    if "=" in part:
                        k, v = part.strip().split("=", 1)
                        cookies[k.strip()] = v.strip()

            async with httpx.AsyncClient(
                verify=False,
                timeout=15.0,
                follow_redirects=True,
                headers={"User-Agent": "Crosure/1.0 Vulnerability Scanner"},
                cookies=cookies,
            ) as http_session:

                # Run plugins against each endpoint
                total_work = len(endpoints) * len(active_plugins)
                completed = 0

                for ep_idx, endpoint in enumerate(endpoints):

                    # Run all plugins concurrently per endpoint
                    plugin_tasks = []
                    for plugin in active_plugins:
                        plugin_tasks.append(
                            self._run_plugin_safe(plugin, endpoint, http_session, request)
                        )

                    results = await asyncio.gather(*plugin_tasks)

                    for plugin_findings in results:
                        all_findings.extend(plugin_findings)

                    completed += len(active_plugins)
                    progress = 0.25 + (completed / total_work) * 0.45

                    if (ep_idx + 1) % 5 == 0 or ep_idx == len(endpoints) - 1:
                        # Show deduplicated count so it matches the final number
                        unique_count = len(self._deduplicate_findings(all_findings))
                        await self._emit(
                            ScanPhase.SCANNING,
                            f"Scanned {ep_idx + 1}/{len(endpoints)} endpoints. Found {unique_count} vulnerabilities.",
                            progress,
                        )

            # ── Phase 3: Deduplicate & AI-Boost ──
            all_findings = self._deduplicate_findings(all_findings)
            all_findings = boost_findings_from_kb(all_findings, kb_hints, plugin_priorities)
            await self._emit(
                ScanPhase.SCANNING,
                f"Detection complete: {len(all_findings)} unique vulnerabilities (AI-boosted from KB).",
                0.72,
            )

            # ── Phase 4: Chain Discovery ──
            await self._emit(ScanPhase.CHAINING, "Discovering attack chains...", 0.75)

            if len(all_findings) >= 2:
                # Query KB for known chain patterns (pass string, not list)
                kb_chains = []
                try:
                    findings_desc = "; ".join(f"{f.vuln_type.value} at {f.url}" for f in all_findings[:10])
                    kb_results = search_chains_for_findings(findings_desc)
                    kb_chains = kb_results
                except Exception as e:
                    import logging
                    logging.warning(f"KB chain search failed (non-fatal): {e}")

                # Cap findings for chain engine — sort by severity first
                sev_order = {SeverityLevel.CRITICAL: 0, SeverityLevel.HIGH: 1, SeverityLevel.MEDIUM: 2, SeverityLevel.LOW: 3, SeverityLevel.INFO: 4}
                sorted_findings = sorted(all_findings, key=lambda f: (sev_order.get(f.severity, 5), -(f.cvss_score or 0)))
                chain_findings = sorted_findings[:100]
                try:
                    engine = ChainEngine()
                    all_chains = await asyncio.wait_for(
                        asyncio.to_thread(
                            engine.build_chains,
                            chain_findings,
                            kb_chains=kb_chains,
                            max_chain_length=4,
                            min_chain_length=2,
                        ),
                        timeout=60.0,  # 60 second timeout for chaining
                    )
                except asyncio.TimeoutError:
                    import logging
                    logging.warning(f"Chain discovery timed out with {len(chain_findings)} findings, using partial results")
                    all_chains = []
                except Exception as e:
                    import logging
                    logging.error(f"Chain discovery failed: {e}", exc_info=True)
                    all_chains = []

                await self._emit(
                    ScanPhase.CHAINING,
                    f"Discovered {len(all_chains)} attack chains.",
                    0.85,
                )

            # ── Phase 5: AI Triage & Remediation ──
            await self._emit(ScanPhase.AI_ANALYSIS, "Checking AI engine availability...", 0.87)

            import logging as _log

            # Check if Ollama is available with a model
            ollama_ready = await check_ollama_available()
            ai_mode = "llm" if ollama_ready else "chain_fallback"
            _log.info(f"[AI] Ollama ready: {ollama_ready} → triage mode: {ai_mode}")

            high_findings = [f for f in all_findings if f.severity in (SeverityLevel.HIGH, SeverityLevel.CRITICAL)]
            triage_targets = high_findings[:24]

            if ai_mode == "llm" and triage_targets:
                # ── PRIMARY: LLM-based triage ──
                await self._emit(ScanPhase.AI_ANALYSIS, "Running LLM-based AI confidence triage...", 0.88)
                try:
                    triage_results = await asyncio.wait_for(
                        ai_triage_batch(triage_targets, batch_size=8),
                        timeout=90.0,
                    )
                    all_findings = apply_triage_to_findings(all_findings, triage_results)
                    tp = sum(1 for r in triage_results if r["verdict"] == "true_positive")
                    fp = sum(1 for r in triage_results if r["verdict"] == "false_positive")
                    await self._emit(
                        ScanPhase.AI_ANALYSIS,
                        f"LLM triage: {tp} confirmed, {fp} false positives from {len(triage_targets)} findings.",
                        0.91,
                    )
                    _log.info(f"[AI] LLM triage success: {tp} TP, {fp} FP out of {len(triage_targets)}")
                except (asyncio.TimeoutError, Exception) as e:
                    _log.warning(f"[AI] LLM triage failed ({e}), falling back to chain-based triage")
                    await self._emit(
                        ScanPhase.AI_ANALYSIS,
                        "LLM triage failed — switching to chain-based fallback...",
                        0.89,
                    )
                    # Fallback to chain-based
                    all_findings = chain_based_fallback_triage(all_findings, all_chains)
                    tp = sum(1 for f in all_findings if f.ai_verdict == "true_positive")
                    fp = sum(1 for f in all_findings if f.ai_verdict == "false_positive")
                    await self._emit(
                        ScanPhase.AI_ANALYSIS,
                        f"Chain fallback triage: {tp} confirmed, {fp} deprioritized from {len(all_findings)} findings.",
                        0.91,
                    )
            else:
                # ── FALLBACK: Chain-based triage ──
                if not ollama_ready:
                    await self._emit(
                        ScanPhase.AI_ANALYSIS,
                        "Ollama unavailable — using chain-based attack analysis for triage...",
                        0.88,
                    )
                    _log.info("[AI] Using chain-based fallback triage (no LLM available)")
                all_findings = chain_based_fallback_triage(all_findings, all_chains)
                tp = sum(1 for f in all_findings if f.ai_verdict == "true_positive")
                fp = sum(1 for f in all_findings if f.ai_verdict == "false_positive")
                await self._emit(
                    ScanPhase.AI_ANALYSIS,
                    f"Chain-based triage: {tp} confirmed, {fp} deprioritized from {len(all_findings)} findings.",
                    0.91,
                )

            # AI Remediation — builtin for ALL findings (instant), LLM enrichment for top 10
            # First: set builtin remediation on every finding so clicks are instant
            for finding in all_findings:
                finding.remediation = self._builtin_remediation(finding)

            # Then: overwrite top findings with richer LLM remediation if Ollama is available
            if ollama_ready:
                await self._emit(ScanPhase.AI_ANALYSIS, "Generating AI remediation guidance for top findings...", 0.92)
                for finding in high_findings[:10]:
                    try:
                        remediation = await get_remediation(
                            vuln_type=finding.vuln_type.value,
                            url=finding.url,
                            parameter=finding.parameter or "",
                            evidence=finding.evidence or "",
                            severity=finding.severity.value,
                        )
                        finding.remediation = remediation
                    except Exception:
                        pass  # Keep builtin remediation already set

            await self._emit(ScanPhase.AI_ANALYSIS, f"AI analysis complete (mode: {ai_mode}).", 0.95)

            # ── Phase 6: Store Results ──
            await self._emit(ScanPhase.COMPLETE, "Scan complete!", 1.0)

            duration = time.time() - start_time

            return ScanResponse(
                scan_id=self.scan_id,
                target_url=request.target_url,
                findings=all_findings,
                chains=all_chains,
                endpoints_crawled=len(endpoints),
                scan_duration=duration,
                tech_stack=tech_stack,
                errors=errors if errors else None,
            )

        except Exception as e:
            import logging
            logging.error(f"Scan pipeline crashed: {e}", exc_info=True)
            await self._emit(ScanPhase.COMPLETE, f"Scan failed: {str(e)}", 1.0)
            return ScanResponse(
                scan_id=self.scan_id,
                target_url=request.target_url,
                findings=all_findings,
                chains=all_chains,
                endpoints_crawled=0,
                scan_duration=time.time() - start_time,
                errors=[str(e)],
            )

    async def _run_plugin_safe(self, plugin, endpoint, session, request) -> List[Finding]:
        """Run a plugin with error handling."""
        try:
            context = {
                "auth_cookie": request.auth_cookie,
                "scan_scope": request.scan_scope,
            }
            return await asyncio.wait_for(
                plugin.detect(endpoint, session, context),
                timeout=30.0,
            )
        except asyncio.TimeoutError:
            import logging
            logging.error(f"Plugin {plugin.name} timed out on {endpoint.url}")
            return []
        except Exception as e:
            import logging
            logging.error(f"Plugin {plugin.name} failed on {endpoint.url}: {e}", exc_info=True)
            return []

    def _select_plugins(self, scope: Optional[List[str]] = None):
        """Select plugins based on scope. None = all."""
        if not scope:
            return ALL_PLUGINS
        return [p for p in ALL_PLUGINS if p.name in scope]

    def _deduplicate_findings(self, findings: List[Finding]) -> List[Finding]:
        """Remove duplicate findings by (url, vuln_type, parameter)."""
        seen = set()
        unique = []
        for f in findings:
            key = (f.url, f.vuln_type.value, f.parameter or "", f.method)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique

    def _builtin_remediation(self, finding: Finding) -> str:
        """Built-in remediation when LLM is unavailable."""
        remediation_map = {
            "SQLi": "**SQL Injection**: Use parameterized queries / prepared statements. Never concatenate user input into SQL. Apply ORM-level query builders. Deploy WAF rules for SQL injection patterns.",
            "XSS": "**Cross-Site Scripting**: Encode all output (HTML entity encoding). Use Content-Security-Policy headers. Sanitize input with allowlists. Use framework auto-escaping (React JSX, Jinja2 |e).",
            "SSTI": "**Server-Side Template Injection**: Never pass user input directly to template engines. Use sandboxed template rendering. Upgrade to latest template engine version. Restrict template builtins.",
            "CSTI": "**Client-Side Template Injection**: Avoid interpolating user input in Angular/Vue templates. Use textContent instead of innerHTML. Enable strict CSP. Sanitize with DOMPurify.",
            "RCE": "**Remote Code Execution**: Never pass user input to system commands. Use language-level APIs instead of shell exec. Apply strict input validation. Run with minimal OS privileges.",
            "BOLA": "**Broken Object Level Authorization**: Implement object-level access control checks. Verify resource ownership on every API call. Use indirect object references (UUIDs). Log access attempts.",
            "BAC": "**Broken Access Control**: Enforce role-based access at both API and data layer. Deny by default. Validate permissions server-side. Implement proper session management.",
            "Auth_Bypass": "**Authentication Bypass**: Enforce auth on all protected endpoints. Use proven auth frameworks. Implement MFA. Validate session tokens server-side.",
            "Misconfig": "**Security Misconfiguration**: Remove default credentials and debug endpoints. Set secure HTTP headers (HSTS, X-Frame-Options, CSP). Disable directory listing. Review server configuration.",
            "CORS": "**CORS Misconfiguration**: Restrict Access-Control-Allow-Origin to specific trusted domains. Never use wildcard (*) with credentials. Validate Origin header server-side.",
            "OAST": "**Out-of-Band Interaction**: Review and restrict external network calls. Implement SSRF protections. Use allowlists for outbound requests. Monitor DNS and HTTP callbacks.",
        }
        vuln_key = finding.vuln_type.value
        return remediation_map.get(vuln_key, f"Fix {vuln_key}: Apply input validation, output encoding, and least privilege principles.")
