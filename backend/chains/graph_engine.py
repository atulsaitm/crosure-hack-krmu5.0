"""Attack Chain Graph Engine v2.
Discovers multi-step attack chains with additive scoring,
critical-path prioritisation, and frozenset-based dedup."""

import uuid
from typing import List, Dict, Optional
from collections import defaultdict
from urllib.parse import urlparse
import networkx as nx

from core.models import (
    Finding, AttackChain, VulnNode, EnablesEdge,
    SeverityLevel, ChainType, AttackPrimitive,
)
from chains.primitives import (
    ATTACK_TYPE_TO_PRIMITIVE,
    get_allowed_transitions,
    get_transition_boost,
)

# High-impact terminal primitives — chains ending here score higher
_CRITICAL_TERMINALS = {AttackPrimitive.CODE_EXEC, AttackPrimitive.PRIVILEGE_ESCALATION}

# Realistic entry-point primitives (removed DATA_ACCESS — it's a goal, not a start)
_ENTRY_PRIMITIVES = {
    AttackPrimitive.INFO_DISCLOSURE,
    AttackPrimitive.SESSION_HIJACK,
    AttackPrimitive.AUTH_BYPASS,
}


class ChainEngine:
    """Build attack-chain graphs from scan findings."""

    def __init__(self):
        self.graph = nx.DiGraph()
        self.findings: Dict[str, Finding] = {}
        self.transitions = get_allowed_transitions()

    # ── Public API ──────────────────────────────────────────────────────────

    def build_chains(
        self,
        findings: List[Finding],
        kb_chains: Optional[List[dict]] = None,
        max_chain_length: int = 5,
        min_chain_length: int = 2,
    ) -> List[AttackChain]:
        if len(findings) < 2:
            return []

        # Step 1 — index & assign primitives
        for finding in findings:
            fid = finding.id or str(uuid.uuid4())
            finding.id = fid
            if not finding.primitive:
                finding.primitive = ATTACK_TYPE_TO_PRIMITIVE.get(
                    finding.vuln_type, AttackPrimitive.INFO_DISCLOSURE
                )
            self.findings[fid] = finding
            self.graph.add_node(fid, finding=finding)

        # Step 2 — build edges via transition rules
        finding_list = list(self.findings.values())
        by_primitive: Dict[AttackPrimitive, List[Finding]] = defaultdict(list)
        for f in finding_list:
            by_primitive[f.primitive].append(f)

        for f1 in finding_list:
            for target_prim in self.transitions.get(f1.primitive, []):
                for f2 in by_primitive.get(target_prim, []):
                    if f1.id == f2.id:
                        continue
                    if not self._are_related(f1, f2):
                        continue
                    boost = get_transition_boost(f1.primitive, f2.primitive)
                    condition = self._get_chain_condition(f1, f2)
                    self.graph.add_edge(f1.id, f2.id, boost=boost, condition=condition)

        # Step 3 — find chains via DFS
        nodes = list(self.graph.nodes)
        sources = [n for n in nodes if self.findings[n].primitive in _ENTRY_PRIMITIVES]
        if not sources:
            sources = [n for n in nodes if self.graph.out_degree(n) > 0]
        sources = sources[:40]
        targets_set = {n for n in nodes if self.graph.in_degree(n) > 0}

        raw_chains: List[List[str]] = []
        MAX_RAW = 300
        for source in sources:
            if len(raw_chains) >= MAX_RAW:
                break
            for target in targets_set:
                if source == target or len(raw_chains) >= MAX_RAW:
                    continue
                try:
                    for path in nx.all_simple_paths(self.graph, source, target, cutoff=max_chain_length):
                        if len(path) >= min_chain_length:
                            raw_chains.append(path)
                            if len(raw_chains) >= MAX_RAW:
                                break
                except nx.NetworkXError:
                    continue

        # Step 4 — deduplicate (frozenset-based)
        raw_chains.sort(key=len, reverse=True)
        unique_chains = self._deduplicate_chains(raw_chains)

        # Step 5 — score, build AttackChain objects
        attack_chains = []
        for chain_path in unique_chains[:25]:
            chain = self._build_attack_chain(chain_path, kb_chains)
            attack_chains.append(chain)

        # Prioritise critical-terminal chains, then by score
        attack_chains.sort(
            key=lambda c: (
                1 if c.chain_type in (ChainType.FULL_COMPROMISE, ChainType.PRIVILEGE_ESCALATION) else 0,
                c.total_score,
            ),
            reverse=True,
        )

        # Assign chain IDs to findings
        for chain in attack_chains:
            for node in chain.nodes:
                f = self.findings.get(node.finding_id)
                if f and f.chain_ids is not None:
                    f.chain_ids.append(chain.id)

        return attack_chains

    # ── Private helpers ─────────────────────────────────────────────────────

    def _are_related(self, f1: Finding, f2: Finding) -> bool:
        """Two findings are related if they share domain + path prefix,
        or either is high/critical, or the target is a critical terminal."""
        u1, u2 = urlparse(f1.url), urlparse(f2.url)
        if u1.netloc != u2.netloc:
            return False

        p1 = u1.path.strip("/").split("/")[:2]
        p2 = u2.path.strip("/").split("/")[:2]
        if p1 and p2 and p1[0] == p2[0]:
            return True

        # Allow cross-path chaining for high-severity or critical-terminal
        if f1.severity in (SeverityLevel.HIGH, SeverityLevel.CRITICAL) or \
           f2.severity in (SeverityLevel.HIGH, SeverityLevel.CRITICAL):
            return True
        if f2.primitive in _CRITICAL_TERMINALS:
            return True

        return False

    @staticmethod
    def _get_chain_condition(f1: Finding, f2: Finding) -> str:
        p1 = f1.primitive.value if f1.primitive else "unknown"
        p2 = f2.primitive.value if f2.primitive else "unknown"
        return f"{f1.vuln_type.value} ({p1}) enables {f2.vuln_type.value} ({p2})"

    @staticmethod
    def _deduplicate_chains(chains: List[List[str]]) -> List[List[str]]:
        """Deduplicate using frozenset — two chains with the same node-set
        keep only the longer one."""
        seen: set = set()
        unique = []
        for chain in chains:
            key = frozenset(chain)
            if key in seen:
                continue
            seen.add(key)
            unique.append(chain)
        return unique

    def _build_attack_chain(
        self, path: List[str], kb_chains: Optional[List[dict]] = None
    ) -> AttackChain:
        chain_id = str(uuid.uuid4())
        nodes = []
        edges = []

        # ── Additive scoring ──
        cvss_sum = 0.0
        boost_sum = 0.0

        for idx, fid in enumerate(path):
            finding = self.findings[fid]
            base_score = finding.cvss_score or 5.0
            cvss_sum += base_score

            nodes.append(VulnNode(
                finding_id=fid,
                step=idx + 1,
                vuln_type=finding.vuln_type,
                primitive=finding.primitive,
                cvss=base_score,
                url=finding.url,
            ))

            if idx > 0:
                prev_fid = path[idx - 1]
                edge_data = self.graph.edges.get((prev_fid, fid), {})
                boost = edge_data.get("boost", 1.0)
                condition = edge_data.get("condition", "enables")
                boost_sum += boost

                edges.append(EnablesEdge(
                    from_id=prev_fid,
                    to_id=fid,
                    condition=condition,
                    boost=boost,
                ))

        # Normalise: (avg CVSS) * (1 + avg boost/2), clamped to 10
        n = len(path)
        avg_cvss = cvss_sum / n
        avg_boost = boost_sum / max(len(edges), 1)
        total_score = min(avg_cvss * (1 + avg_boost / 2), 10.0)

        # KB boost
        kb_boost = 1.0
        if kb_chains:
            kb_boost = self._compute_kb_boost(path, kb_chains)
            total_score = min(total_score * kb_boost, 10.0)

        # Critical-terminal bonus (+1 if chain ends at CODE_EXEC/PRIV_ESC)
        final_finding = self.findings[path[-1]]
        if final_finding.primitive in _CRITICAL_TERMINALS:
            total_score = min(total_score + 1.0, 10.0)

        chain_type = self._classify_chain(final_finding)
        description = self._generate_description(nodes, edges, chain_type)

        return AttackChain(
            id=chain_id,
            nodes=nodes,
            edges=edges,
            total_score=round(total_score, 2),
            chain_type=chain_type,
            description=description,
            kb_matched=kb_boost > 1.0,
        )

    @staticmethod
    def _classify_chain(final: Finding) -> ChainType:
        if final.primitive == AttackPrimitive.CODE_EXEC:
            return ChainType.FULL_COMPROMISE
        elif final.primitive == AttackPrimitive.PRIVILEGE_ESCALATION:
            return ChainType.PRIVILEGE_ESCALATION
        elif final.primitive == AttackPrimitive.DATA_ACCESS:
            return ChainType.DATA_BREACH
        elif final.primitive == AttackPrimitive.AUTH_BYPASS:
            return ChainType.AUTH_BYPASS
        return ChainType.DATA_BREACH

    def _compute_kb_boost(self, path: List[str], kb_chains: List[dict]) -> float:
        chain_types = [self.findings[fid].vuln_type.value for fid in path]
        for kb_chain in kb_chains:
            kb_steps = kb_chain.get("steps", [])
            kb_types = [s.get("vuln_type", "") for s in kb_steps]
            if self._is_subsequence(chain_types, kb_types):
                return 1.3
        return 1.0

    @staticmethod
    def _is_subsequence(seq: list, target: list) -> bool:
        it = iter(target)
        return all(item in it for item in seq)

    @staticmethod
    def _generate_description(nodes: List[VulnNode], edges: List[EnablesEdge], chain_type: ChainType) -> str:
        impact_labels = {
            ChainType.FULL_COMPROMISE: "Full System Compromise",
            ChainType.PRIVILEGE_ESCALATION: "Privilege Escalation",
            ChainType.DATA_BREACH: "Data Breach",
            ChainType.AUTH_BYPASS: "Authentication Bypass",
        }
        parts = [f"Impact: {impact_labels.get(chain_type, 'Unknown')}", ""]
        for i, node in enumerate(nodes):
            parts.append(f"Step {node.step}: {node.vuln_type.value} at {node.url}")
            if i < len(edges):
                parts.append(f"  ↓ {edges[i].condition} (boost: {edges[i].boost}x)")
        return "\n".join(parts)
