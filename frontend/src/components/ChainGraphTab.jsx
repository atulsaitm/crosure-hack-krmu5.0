import { useEffect, useRef, useMemo } from 'react';
import { useStore } from '../store';
import { GitBranch, AlertTriangle, Layers, Zap } from 'lucide-react';

export default function ChainGraphTab() {
  const chains = useStore((s) => s.chains);
  const findings = useStore((s) => s.findings);
  const containerRef = useRef(null);
  const cyRef = useRef(null);

  const graphData = useMemo(() => {
    if (!chains.length || !findings.length) return null;

    const nodes = [];
    const edges = [];
    const addedNodes = new Set();

    const findingMap = {};
    findings.forEach((f) => {
      findingMap[f.id] = f;
    });

    chains.forEach((chain, chainIdx) => {
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
            id: `e-${chainIdx}-${edgeIdx}`,
            source: edge.from_id,
            target: edge.to_id,
            label: edge.condition || 'enables',
            boost: edge.boost || 1.0,
          },
        });
      });
    });

    return { nodes, edges };
  }, [chains, findings]);

  useEffect(() => {
    if (!graphData || !containerRef.current) return;

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
          rankDir: 'LR',
          nodeSep: 60,
          rankSep: 100,
          padding: 30,
        },
        style: [
          {
            selector: 'node',
            style: {
              label: 'data(label)',
              'text-wrap': 'wrap',
              'text-valign': 'center',
              'text-halign': 'center',
              'font-size': '10px',
              'font-family': 'JetBrains Mono, monospace',
              color: '#e2e8f0',
              'text-outline-color': '#0a0a0c',
              'text-outline-width': 2,
              width: 75,
              height: 75,
              shape: 'roundrectangle',
              'background-color': (ele) => {
                const sev = ele.data('severity');
                return sev === 'critical' ? '#3d1515' :
                       sev === 'high' ? '#3d2515' :
                       sev === 'medium' ? '#3d3515' :
                       sev === 'low' ? '#15253d' : '#1a1a1e';
              },
              'border-width': 1,
              'border-color': (ele) => {
                const sev = ele.data('severity');
                return sev === 'critical' ? 'rgba(239,68,68,0.4)' :
                       sev === 'high' ? 'rgba(249,115,22,0.4)' :
                       sev === 'medium' ? 'rgba(234,179,8,0.3)' :
                       sev === 'low' ? 'rgba(59,130,246,0.3)' : 'rgba(255,255,255,0.08)';
              },
              'background-opacity': 0.95,
            },
          },
          {
            selector: 'edge',
            style: {
              width: (ele) => Math.max(1, (ele.data('boost') - 0.8) * 5),
              'line-color': 'rgba(212, 165, 116, 0.3)',
              'target-arrow-color': 'rgba(212, 165, 116, 0.5)',
              'target-arrow-shape': 'triangle',
              'curve-style': 'bezier',
              label: 'data(label)',
              'font-size': '8px',
              'font-family': 'Inter, sans-serif',
              color: 'rgba(212, 165, 116, 0.6)',
              'text-rotation': 'autorotate',
              'text-margin-y': -10,
              'text-outline-color': '#0a0a0c',
              'text-outline-width': 2,
              opacity: 0.7,
            },
          },
          {
            selector: 'node:selected',
            style: {
              'border-width': 2,
              'border-color': '#d4a574',
              'overlay-padding': 6,
              'overlay-color': '#d4a574',
              'overlay-opacity': 0.1,
            },
          },
        ],
        minZoom: 0.3,
        maxZoom: 3,
        wheelSensitivity: 0.3,
      });

      cyRef.current = cy;
    };

    initCytoscape();

    return () => {
      if (cyRef.current) {
        cyRef.current.destroy();
        cyRef.current = null;
      }
    };
  }, [graphData]);

  return (
    <div className="h-full flex flex-col dot-pattern">
      {/* Toolbar */}
      <div className="glass border-b border-white/[0.04] p-5 flex items-center justify-between">
        <h2 className="text-base font-semibold text-white/80 flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-xl bg-accent-rose/10 border border-accent-rose/20 flex items-center justify-center">
            <GitBranch className="w-4 h-4 text-accent-rose/70" />
          </div>
          Attack Chain Graph
        </h2>
        <div className="flex items-center gap-3">
          <span className="metal-badge px-2.5 py-1 text-[11px] text-white/30">
            {chains.length} chain{chains.length !== 1 ? 's' : ''}
          </span>
          {chains.length > 0 && (
            <span className="metal-badge px-2.5 py-1 text-[11px] text-accent-warm/50">
              Top: {Math.max(...chains.map(c => c.total_score || 0)).toFixed(1)}
            </span>
          )}
        </div>
      </div>

      {/* Chain List Sidebar + Graph */}
      <div className="flex-1 flex overflow-hidden">
        {/* Chain list */}
        {chains.length > 0 && (
          <div className="w-64 border-r border-white/[0.04] overflow-auto p-3 space-y-2 glass-sm">
            {chains.map((chain, idx) => (
              <div
                key={chain.id || idx}
                className="glass-card p-3 cursor-pointer"
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-[11px] font-semibold text-accent-warm/70 flex items-center gap-1.5">
                    <Zap className="w-3 h-3" />
                    Chain #{idx + 1}
                  </span>
                  <span className="text-[11px] mono text-white/70 font-bold">
                    {chain.total_score?.toFixed(1) || '?'}
                  </span>
                </div>
                <p className="text-[11px] text-white/30">
                  {chain.chain_type?.replace(/_/g, ' ')}
                </p>
                <p className="text-[10px] text-white/20 mt-1">
                  {chain.nodes?.length || 0} steps
                  {chain.kb_matched && (
                    <span className="ml-1 text-accent-amber/60">(KB match)</span>
                  )}
                </p>
              </div>
            ))}
          </div>
        )}

        {/* Cytoscape container */}
        <div className="flex-1 bg-[#08080a] relative">
          {graphData ? (
            <div ref={containerRef} className="cytoscape-container" />
          ) : (
            <div className="flex flex-col items-center justify-center h-full">
              <div className="w-16 h-16 rounded-2xl glass-card flex items-center justify-center mb-4 animate-float">
                <Layers className="w-8 h-8 text-white/10" />
              </div>
              <p className="text-white/25 text-sm">No attack chains discovered yet</p>
              <p className="text-white/15 text-xs mt-1">Run a scan to discover multi-step attack paths</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
