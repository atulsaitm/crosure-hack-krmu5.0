"""Attack Chain Graph Engine.
Discovers multi-step attack chains by linking vulnerability findings
through their attack primitives using transition rules + KB matching."""

import uuid
from typing import List, Dict, Optional, Tuple
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


class ChainEngine:
    """Build attack chain graphs from findings."""

    def __init__(self):
        self.graph = nx.DiGraph()
        self.findings: Dict[str, Finding] = {}
        self.transitions = get_allowed_transitions()

    def build_chains(
        self,
        findings: List[Finding],
        kb_chains: Optional[List[dict]] = None,
        max_chain_length: int = 5,
        min_chain_length: int = 2,
    ) -> List[AttackChain]:
        """
        Build attack chains from findings.

        1. Assign primitives to each finding
        2. Build a directed graph based on transition rules
        3. Search for all simple paths (chains)
        4. Score and rank chains
        5. Optionally boost chains that match KB patterns
        """
        if len(findings) < 2:
            return []

        # ── Step 1: Index findings and assign primitives ──
        for finding in findings:
            fid = finding.id or str(uuid.uuid4())
            finding.id = fid

            # Assign primitive if not set
            if not finding.primitive:
                finding.primitive = ATTACK_TYPE_TO_PRIMITIVE.get(
                    finding.vuln_type, AttackPrimitive.INFO_DISCLOSURE
                )

            self.findings[fid] = finding
            self.graph.add_node(fid, finding=finding)

        # ── Step 2: Build edges based on transition rules ──
        finding_list = list(self.findings.values())

        # Group by primitive to avoid O(n^2) on full list
        from collections import defaultdict
        by_primitive = defaultdict(list)
        for f in finding_list:
            by_primitive[f.primitive].append(f)

        for f1 in finding_list:
            allowed_targets = self.transitions.get(f1.primitive, [])
            for target_prim in allowed_targets:
                for f2 in by_primitive.get(target_prim, []):
                    if f1.id == f2.id:
                        continue
                    # Only chain findings on related endpoints
                    if not self._are_related(f1, f2):
                        continue
                    boost = get_transition_boost(f1.primitive, f2.primitive)
                    condition = self._get_chain_condition(f1, f2)
                    self.graph.add_edge(
                        f1.id, f2.id,
                        boost=boost,
                        condition=condition,
                    )

        # ── Step 3: Find attack chains via DFS from high-value sources ──
        raw_chains: List[List[str]] = []
        nodes = list(self.graph.nodes)

        # Only start chains from entry-point primitives (info leak, session hijack, etc)
        entry_primitives = {AttackPrimitive.INFO_DISCLOSURE, AttackPrimitive.SESSION_HIJACK, AttackPrimitive.AUTH_BYPASS, AttackPrimitive.DATA_ACCESS}
        sources = [n for n in nodes if self.findings[n].primitive in entry_primitives]
        # Fallback: if no entry nodes, use nodes with outgoing edges
        if not sources:
            sources = [n for n in nodes if self.graph.out_degree(n) > 0]

        # Limit sources and targets to keep it fast
        sources = sources[:30]
        targets_set = set(n for n in nodes if self.graph.in_degree(n) > 0)
        MAX_CHAINS = 200

        for source in sources:
            if len(raw_chains) >= MAX_CHAINS:
                break
            for target in targets_set:
                if source == target:
                    continue
                if len(raw_chains) >= MAX_CHAINS:
                    break
                try:
                    paths = list(nx.all_simple_paths(
                        self.graph, source, target,
                        cutoff=max_chain_length,
                    ))
                    for path in paths:
                        if len(path) >= min_chain_length:
                            raw_chains.append(path)
                            if len(raw_chains) >= MAX_CHAINS:
                                break
                except nx.NetworkXError:
                    continue

        # ── Step 4: Deduplicate by sub-path containment ──
        raw_chains.sort(key=len, reverse=True)
        unique_chains = self._deduplicate_chains(raw_chains)

        # ── Step 5: Score and convert to AttackChain model ──
        attack_chains = []
        for chain_path in unique_chains[:20]:  # Limit to top 20
            chain = self._build_attack_chain(chain_path, kb_chains)
            attack_chains.append(chain)

        # Sort by score descending
        attack_chains.sort(key=lambda c: c.total_score, reverse=True)

        # Assign chain IDs to findings
        for chain in attack_chains:
            for node in chain.nodes:
                finding = self.findings.get(node.finding_id)
                if finding and finding.chain_ids is not None:
                    finding.chain_ids.append(chain.id)

        return attack_chains

    def _can_chain(self, f1: Finding, f2: Finding) -> bool:
        """Check if f1's primitive can transition to f2's primitive."""
        p1 = f1.primitive
        p2 = f2.primitive

        if p1 == p2:
            return False

        allowed = self.transitions.get(p1, [])
        if p2 not in allowed:
            return False

        # Extra proximity check: same or related endpoints
        if self._are_related(f1, f2):
            return True

        # Allow even unrelated domain if transition makes sense
        return True

    def _are_related(self, f1: Finding, f2: Finding) -> bool:
        """Check if two findings are on related endpoints."""
        from urllib.parse import urlparse
        u1, u2 = urlparse(f1.url), urlparse(f2.url)

        # Must be same domain
        if u1.netloc != u2.netloc:
            return False

        # Same path prefix (first 2 segments) counts as related
        p1_parts = u1.path.strip("/").split("/")[:2]
        p2_parts = u2.path.strip("/").split("/")[:2]

        if p1_parts and p2_parts and p1_parts[0] == p2_parts[0]:
            return True

        # Different path prefixes — only chain high-severity findings
        if f1.severity in (SeverityLevel.HIGH, SeverityLevel.CRITICAL) or \
           f2.severity in (SeverityLevel.HIGH, SeverityLevel.CRITICAL):
            return True

        return False

    def _get_chain_condition(self, f1: Finding, f2: Finding) -> str:
        """Generate human-readable chain condition."""
        p1_name = f1.primitive.value if f1.primitive else "unknown"
        p2_name = f2.primitive.value if f2.primitive else "unknown"
        return f"{f1.vuln_type.value} ({p1_name}) enables {f2.vuln_type.value} ({p2_name})"

    def _deduplicate_chains(self, chains: List[List[str]]) -> List[List[str]]:
        """Remove chains that are sub-paths of longer chains."""
        unique = []
        seen_sets = set()

        for chain in chains:
            chain_key = tuple(chain)
            if chain_key in seen_sets:
                continue

            # Check if this chain is a sub-path of an existing chain
            is_subpath = False
            for existing in unique:
                if len(chain) < len(existing):
                    existing_str = "→".join(existing)
                    chain_str = "→".join(chain)
                    if chain_str in existing_str:
                        is_subpath = True
                        break

            if not is_subpath:
                unique.append(chain)
                seen_sets.add(chain_key)

        return unique

    def _build_attack_chain(
        self, path: List[str], kb_chains: Optional[List[dict]] = None
    ) -> AttackChain:
        """Convert a path of finding IDs into an AttackChain model."""
        chain_id = str(uuid.uuid4())
        nodes = []
        edges = []
        total_score = 1.0

        for idx, fid in enumerate(path):
            finding = self.findings[fid]

            # Base score from CVSS
            base_score = finding.cvss_score or 5.0

            node = VulnNode(
                finding_id=fid,
                step=idx + 1,
                vuln_type=finding.vuln_type,
                primitive=finding.primitive,
                cvss=base_score,
                url=finding.url,
            )
            nodes.append(node)

            # Multiply scores along chain
            total_score *= (base_score / 10.0) if idx > 0 else 1.0

            # Add edge
            if idx > 0:
                prev_fid = path[idx - 1]
                edge_data = self.graph.edges.get((prev_fid, fid), {})
                boost = edge_data.get("boost", 1.0)
                condition = edge_data.get("condition", "enables")

                total_score *= boost

                edge = EnablesEdge(
                    from_id=prev_fid,
                    to_id=fid,
                    condition=condition,
                    boost=boost,
                )
                edges.append(edge)

        # Normalize score
        total_score = min(total_score * 10, 10.0)

        # Determine chain type based on final primitive
        final_finding = self.findings[path[-1]]
        chain_type = self._classify_chain(nodes, final_finding)

        # KB boost
        kb_boost = 1.0
        if kb_chains:
            kb_boost = self._compute_kb_boost(path, kb_chains)
            total_score = min(total_score * kb_boost, 10.0)

        # Generate description
        description = self._generate_description(nodes, edges)

        return AttackChain(
            id=chain_id,
            nodes=nodes,
            edges=edges,
            total_score=round(total_score, 2),
            chain_type=chain_type,
            description=description,
            kb_matched=kb_boost > 1.0,
        )

    def _classify_chain(self, nodes: List[VulnNode], final: Finding) -> ChainType:
        """Classify chain by its final impact."""
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
        """Check if chain pattern matches any known KB chains."""
        # Extract vuln types from path
        chain_types = []
        for fid in path:
            f = self.findings[fid]
            chain_types.append(f.vuln_type.value)

        for kb_chain in kb_chains:
            kb_steps = kb_chain.get("steps", [])
            kb_types = [s.get("vuln_type", "") for s in kb_steps]

            # Check for subsequence match
            if self._is_subsequence(chain_types, kb_types):
                return 1.3  # KB match boost

        return 1.0

    @staticmethod
    def _is_subsequence(seq: list, target: list) -> bool:
        """Check if seq is a subsequence of target."""
        it = iter(target)
        return all(item in it for item in seq)

    def _generate_description(self, nodes: List[VulnNode], edges: List[EnablesEdge]) -> str:
        """Generate human-readable chain description."""
        parts = []
        for i, node in enumerate(nodes):
            step = f"Step {node.step}: {node.vuln_type.value} at {node.url}"
            parts.append(step)
            if i < len(edges):
                parts.append(f"  ↓ {edges[i].condition} (boost: {edges[i].boost}x)")

        return "\n".join(parts)
