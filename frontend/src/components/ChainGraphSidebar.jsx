import { useEffect, useRef, useMemo, useState } from 'react';
import { useStore } from '../store';
import { GitBranch, X, Zap, ChevronLeft, ChevronRight, Maximize2 } from 'lucide-react';

const severityColors = {
  critical: { bg: '#3d1515', border: 'rgba(239,68,68,0.4)', label: 'text-red-400' },
  high: { bg: '#3d2515', border: 'rgba(249,115,22,0.4)', label: 'text-orange-400' },
  medium: { bg: '#3d3515', border: 'rgba(234,179,8,0.3)', label: 'text-yellow-400' },
  low: { bg: '#15253d', border: 'rgba(59,130,246,0.3)', label: 'text-blue-400' },
  info: { bg: '#1a1a1e', border: 'rgba(255,255,255,0.08)', label: 'text-white/40' },
};

export default function ChainGraphSidebar() {
  const chains = useStore((s) => s.chains);
  const findings = useStore((s) => s.findings);
  const graphSidebarOpen = useStore((s) => s.graphSidebarOpen);
  const setGraphSidebarOpen = useStore((s) => s.setGraphSidebarOpen);
  const [selectedChainIdx, setSelectedChainIdx] = useState(0);
  const [expanded, setExpanded] = useState(false);
  const containerRef = useRef(null);
  const cyRef = useRef(null);

  // Build graph data for selected chain
  const graphData = useMemo(() => {
    if (!chains.length || !findings.length) return null;

    const chain = chains[selectedChainIdx] || chains[0];
    if (!chain) return null;

    const nodes = [];
    const edges = [];
    const addedNodes = new Set();

    const findingMap = {};
    findings.forEach((f) => { findingMap[f.id] = f; });

    chain.nodes?.forEach((node) => {
      if (!addedNodes.has(node.finding_id)) {
        addedNodes.add(node.finding_id);
        const finding = findingMap[node.finding_id] || {};
        nodes.push({
          data: {
            id: node.finding_id,
            label: `${node.vuln_type}\n${node.cvss?.toFixed(1) || '?'}`,
            vuln_type: node.vuln_type,
            severity: finding.severity || 'info',
            cvss: node.cvss || 0,
            url: node.url || finding.url || '',
            step: node.step,
            primitive: node.primitive || '',
          },
        });
      }
    });

    chain.edges?.forEach((edge, edgeIdx) => {
      edges.push({
        data: {
          id: `e-${selectedChainIdx}-${edgeIdx}`,
          source: edge.from_id,
          target: edge.to_id,
          label: edge.condition || 'enables',
          boost: edge.boost || 1.0,
        },
      });
    });

    return { nodes, edges, chain };
  }, [chains, findings, selectedChainIdx]);

  // Init Cytoscape
  useEffect(() => {
    if (!graphData || !containerRef.current || !graphSidebarOpen) return;

    let cy;
    const initCytoscape = async () => {
      const cytoscape = (await import('cytoscape')).default;
      const dagre = (await import('cytoscape-dagre')).default;
      cytoscape.use(dagre);

      if (cyRef.current) {
        cyRef.current.destroy();
      }

      cy = cytoscape({
        container: containerRef.current,
        elements: [...graphData.nodes, ...graphData.edges],
        layout: {
          name: 'dagre',
          rankDir: expanded ? 'LR' : 'TB',
          nodeSep: expanded ? 60 : 40,
          rankSep: expanded ? 100 : 60,
          padding: 20,
        },
        style: [
          {
            selector: 'node',
            style: {
              label: 'data(label)',
              'text-wrap': 'wrap',
              'text-valign': 'center',
              'text-halign': 'center',
              'font-size': expanded ? '10px' : '9px',
              'font-family': 'JetBrains Mono, monospace',
              color: '#e2e8f0',
              'text-outline-color': '#08080a',
              'text-outline-width': 2,
              width: expanded ? 80 : 60,
              height: expanded ? 80 : 60,
              shape: 'roundrectangle',
              'background-color': (ele) => {
                const sev = ele.data('severity');
                return severityColors[sev]?.bg || '#1a1a1e';
              },
              'border-width': 1.5,
              'border-color': (ele) => {
                const sev = ele.data('severity');
                return severityColors[sev]?.border || 'rgba(255,255,255,0.08)';
              },
              'background-opacity': 0.95,
            },
          },
          {
            selector: 'edge',
            style: {
              width: (ele) => Math.max(1, (ele.data('boost') - 0.8) * 5),
              'line-color': 'rgba(212, 165, 116, 0.35)',
              'target-arrow-color': 'rgba(212, 165, 116, 0.6)',
              'target-arrow-shape': 'triangle',
              'curve-style': 'bezier',
              label: expanded ? 'data(label)' : '',
              'font-size': '8px',
              'font-family': 'Inter, sans-serif',
              color: 'rgba(212, 165, 116, 0.6)',
              'text-rotation': 'autorotate',
              'text-margin-y': -8,
              'text-outline-color': '#08080a',
              'text-outline-width': 2,
              opacity: 0.8,
            },
          },
          {
            selector: 'node:selected',
            style: {
              'border-width': 2,
              'border-color': '#d4a574',
              'overlay-padding': 4,
              'overlay-color': '#d4a574',
              'overlay-opacity': 0.12,
            },
          },
        ],
        minZoom: 0.3,
        maxZoom: 3,
        wheelSensitivity: 0.3,
      });

      cyRef.current = cy;

      // Fit after layout finishes
      cy.on('layoutstop', () => {
        cy.fit(undefined, 20);
      });
    };

    // Small delay to let the panel animate open
    const timer = setTimeout(initCytoscape, 100);

    return () => {
      clearTimeout(timer);
      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      }
    };
  }, [graphData, graphSidebarOpen, expanded]);

  if (!graphSidebarOpen || !chains.length) return null;

  const chain = graphData?.chain;

  return (
    <>
      {/* Backdrop */}
      {expanded && (
        <div
          className="fixed inset-0 bg-black/50 z-40 backdrop-blur-sm"
          onClick={() => setExpanded(false)}
        />
      )}

      {/* Sidebar Panel */}
      <div
        className={`fixed top-0 right-0 h-full z-50 flex flex-col
          bg-[#0c0c0f]/95 backdrop-blur-md border-l border-white/[0.06]
          shadow-[-4px_0_24px_rgba(0,0,0,0.5)]
          transition-all duration-300 ease-out
          ${expanded ? 'w-[70vw]' : 'w-[420px]'}`}
      >
        {/* Header */}
        <div className="flex items-center justify-between p-4 border-b border-white/[0.04]">
          <div className="flex items-center gap-2.5">
            <div className="w-7 h-7 rounded-lg bg-accent-rose/10 border border-accent-rose/20 flex items-center justify-center">
              <GitBranch className="w-3.5 h-3.5 text-accent-rose/70" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-white/80">Attack Chains</h3>
              <p className="text-[10px] text-white/25">{chains.length} chain{chains.length !== 1 ? 's' : ''} discovered</p>
            </div>
          </div>
          <div className="flex items-center gap-1.5">
            <button
              onClick={() => setExpanded(!expanded)}
              className="key-btn p-1.5 text-white/30 hover:text-white/60"
              title={expanded ? 'Collapse' : 'Expand'}
            >
              <Maximize2 className="w-3.5 h-3.5" />
            </button>
            <button
              onClick={() => { setGraphSidebarOpen(false); setExpanded(false); }}
              className="key-btn p-1.5 text-white/30 hover:text-white/60"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Chain Selector Tabs */}
        <div className="flex items-center gap-1 px-4 py-2.5 border-b border-white/[0.04] overflow-x-auto scrollbar-hide">
          {chains.map((c, idx) => (
            <button
              key={c.id || idx}
              onClick={() => setSelectedChainIdx(idx)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[11px] font-medium whitespace-nowrap transition-all ${
                idx === selectedChainIdx
                  ? 'bg-accent-warm/10 border border-accent-warm/20 text-accent-warm'
                  : 'text-white/30 hover:text-white/50 hover:bg-white/[0.03]'
              }`}
            >
              <Zap className="w-3 h-3" />
              Chain {idx + 1}
              <span className="mono text-[10px] opacity-60">{c.total_score?.toFixed(1)}</span>
            </button>
          ))}
        </div>

        {/* Chain Info */}
        {chain && (
          <div className="px-4 py-2.5 border-b border-white/[0.04] flex items-center gap-3">
            <span className="metal-badge px-2 py-0.5 text-[10px] text-white/40">
              {chain.chain_type?.replace(/_/g, ' ') || 'Attack Path'}
            </span>
            <span className="text-[10px] text-white/25">
              {chain.nodes?.length || 0} steps
            </span>
            <span className="mono text-[10px] text-accent-warm/60 font-bold">
              Score: {chain.total_score?.toFixed(1)}
            </span>
            {chain.kb_matched && (
              <span className="text-[10px] text-accent-amber/60 metal-badge px-2 py-0.5">KB Match</span>
            )}
          </div>
        )}

        {/* Graph Container */}
        <div className="flex-1 bg-[#08080a] relative min-h-0">
          <div ref={containerRef} className="absolute inset-0" />
        </div>

        {/* Chain Steps Legend */}
        {chain && (
          <div className="border-t border-white/[0.04] p-3 max-h-36 overflow-y-auto">
            <p className="text-[10px] text-white/20 uppercase tracking-wider mb-2">Attack Path Steps</p>
            <div className="space-y-1">
              {chain.nodes?.map((node, i) => {
                const sevColor = severityColors[node.severity || 'info'];
                return (
                  <div key={i} className="flex items-center gap-2 text-[11px]">
                    <span className="w-4 h-4 rounded bg-white/[0.04] flex items-center justify-center text-[9px] text-white/30 font-mono">{i + 1}</span>
                    <span className={`font-medium ${sevColor?.label || 'text-white/40'}`}>{node.vuln_type}</span>
                    <span className="text-white/15 truncate flex-1">{node.url?.split('/').slice(-2).join('/') || ''}</span>
                    <span className="mono text-[10px] text-white/20">{node.cvss?.toFixed(1) || '—'}</span>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>
    </>
  );
}
