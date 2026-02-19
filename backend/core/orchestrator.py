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

            await self._emit(
                ScanPhase.CRAWLING,
                f"Crawled {len(endpoints)} endpoints. Tech: {', '.join(tech_stack[:5])}",
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

            # ── Phase 2: Detection ──
            await self._emit(ScanPhase.SCANNING, "Running vulnerability detection plugins...", 0.25)

            # Select plugins based on request scope
            active_plugins = self._select_plugins(request.scan_scope)

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
                        await self._emit(
                            ScanPhase.SCANNING,
                            f"Scanned {ep_idx + 1}/{len(endpoints)} endpoints. Found {len(all_findings)} vulnerabilities.",
                            progress,
                        )

            # ── Phase 3: Deduplicate ──
            all_findings = self._deduplicate_findings(all_findings)
            await self._emit(
                ScanPhase.SCANNING,
                f"Detection complete: {len(all_findings)} unique vulnerabilities found.",
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

                # Cap findings for chain engine to prevent O(n^2) explosion
                chain_findings = all_findings[:80]
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
            await self._emit(ScanPhase.AI_ANALYSIS, "Running AI triage and remediation...", 0.87)

            # Triage top findings
            high_findings = [f for f in all_findings if f.severity in (SeverityLevel.HIGH, SeverityLevel.CRITICAL)]
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
                    finding.remediation = f"Fix {finding.vuln_type.value}: Apply input validation, output encoding, and least privilege."

            await self._emit(ScanPhase.AI_ANALYSIS, "AI analysis complete.", 0.95)

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
