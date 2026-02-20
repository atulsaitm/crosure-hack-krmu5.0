import { useStore } from '../store';
import { AlertTriangle, ChevronRight, ShieldAlert } from 'lucide-react';

const severityConfig = {
  critical: { bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500/20', dot: 'bg-red-500', glow: 'severity-critical' },
  high: { bg: 'bg-orange-500/10', text: 'text-orange-400', border: 'border-orange-500/20', dot: 'bg-orange-500', glow: 'severity-high' },
  medium: { bg: 'bg-yellow-500/10', text: 'text-yellow-400', border: 'border-yellow-500/20', dot: 'bg-yellow-500', glow: 'severity-medium' },
  low: { bg: 'bg-blue-500/10', text: 'text-blue-400', border: 'border-blue-500/20', dot: 'bg-blue-500', glow: 'severity-low' },
  info: { bg: 'bg-white/5', text: 'text-white/40', border: 'border-white/10', dot: 'bg-white/30', glow: '' },
};

export default function FindingsTable() {
  const findings = useStore((s) => s.findings);
  const selectedFinding = useStore((s) => s.selectedFinding);
  const setSelectedFinding = useStore((s) => s.setSelectedFinding);

  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const sorted = [...findings].sort(
    (a, b) => (severityOrder[a.severity] ?? 5) - (severityOrder[b.severity] ?? 5)
  );

  const counts = findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {});

  return (
    <div>
      {/* Summary Bar */}
      <div className="flex items-center gap-4 mb-5">
        <h2 className="text-base font-semibold text-white/90 flex items-center gap-2">
          <ShieldAlert className="w-5 h-5 text-accent-warm/70" />
          Findings
          <span className="text-white/30 font-normal">({findings.length})</span>
        </h2>
        <div className="flex gap-2">
          {['critical', 'high', 'medium', 'low', 'info'].map((sev) => {
            const cfg = severityConfig[sev];
            return counts[sev] ? (
              <span
                key={sev}
                className={`metal-badge px-2.5 py-1 text-[11px] font-medium ${cfg.text} ${cfg.bg} ${cfg.border}`}
              >
                {counts[sev]} {sev}
              </span>
            ) : null;
          })}
        </div>
      </div>

      {/* Table */}
      <div className="glass-card overflow-hidden">
        <table className="w-full text-sm">
          <thead className="sticky top-0 z-10 bg-[#0d0f12]/95 backdrop-blur-sm">
            <tr className="border-b border-white/[0.04]">
              <th className="text-left py-3 px-4 text-[11px] text-white/25 uppercase tracking-wider font-medium">Severity</th>
              <th className="text-left py-3 px-4 text-[11px] text-white/25 uppercase tracking-wider font-medium">Type</th>
              <th className="text-left py-3 px-4 text-[11px] text-white/25 uppercase tracking-wider font-medium">URL</th>
              <th className="text-left py-3 px-4 text-[11px] text-white/25 uppercase tracking-wider font-medium">Parameter</th>
              <th className="text-left py-3 px-4 text-[11px] text-white/25 uppercase tracking-wider font-medium">CVSS</th>
              <th className="text-left py-3 px-4 text-[11px] text-white/25 uppercase tracking-wider font-medium">AI Conf.</th>
              <th className="text-left py-3 px-4 text-[11px] text-white/25 uppercase tracking-wider font-medium">Chains</th>
              <th className="py-3 px-4 w-8"></th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((f, idx) => {
              const cfg = severityConfig[f.severity] || severityConfig.info;
              return (
                <tr
                  key={f.id || idx}
                  onClick={() => setSelectedFinding(f)}
                  className={`border-b border-white/[0.03] cursor-pointer transition-all duration-200
                    ${selectedFinding?.id === f.id
                      ? 'bg-accent-warm/[0.04] border-l-2 border-l-accent-warm/30'
                      : 'hover:bg-white/[0.02] border-l-2 border-l-transparent'}
                  `}
                >
                  <td className="py-3 px-4">
                    <div className="flex items-center gap-2">
                      <div className={`w-1.5 h-1.5 rounded-full ${cfg.dot}`} />
                      <span className={`text-[11px] font-medium uppercase tracking-wide ${cfg.text}`}>
                        {f.severity}
                      </span>
                    </div>
                  </td>
                  <td className="py-3 px-4">
                    <span className="mono text-[11px] text-white/70 metal-badge px-2 py-0.5">
                      {f.vuln_type}
                    </span>
                  </td>
                  <td className="py-3 px-4 text-white/40 max-w-xs truncate mono text-[11px]">
                    {f.url}
                  </td>
                  <td className="py-3 px-4 text-white/30 mono text-[11px]">
                    {f.parameter || '—'}
                  </td>
                  <td className="py-3 px-4">
                    <span className={`mono text-[11px] font-bold ${
                      f.cvss_score >= 9 ? 'text-red-400' :
                      f.cvss_score >= 7 ? 'text-orange-400' :
                      f.cvss_score >= 4 ? 'text-yellow-400' : 'text-white/30'
                    }`}>
                      {f.cvss_score?.toFixed(1) || '—'}
                    </span>
                  </td>
                  <td className="py-3 px-4">
                    {f.ai_confidence != null ? (
                      <div className="flex items-center gap-1.5">
                        <div className="w-12 h-1.5 bg-white/[0.06] rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full ${
                              f.ai_verdict === 'true_positive' ? 'bg-green-500/70' :
                              f.ai_verdict === 'false_positive' ? 'bg-red-400/70' :
                              'bg-yellow-500/70'
                            }`}
                            style={{ width: `${(f.ai_confidence * 100).toFixed(0)}%` }}
                          />
                        </div>
                        <span className={`mono text-[10px] ${
                          f.ai_verdict === 'true_positive' ? 'text-green-400/80' :
                          f.ai_verdict === 'false_positive' ? 'text-red-400/80' :
                          'text-yellow-400/80'
                        }`}>
                          {(f.ai_confidence * 100).toFixed(0)}%
                        </span>
                      </div>
                    ) : <span className="text-white/15 text-[11px]">—</span>}
                  </td>
                  <td className="py-3 px-4 text-[11px]">
                    {f.chain_ids?.length ? (
                      <span className="text-accent-rose/70">{f.chain_ids.length} chain{f.chain_ids.length > 1 ? 's' : ''}</span>
                    ) : <span className="text-white/15">—</span>}
                  </td>
                  <td className="py-3 px-4">
                    <ChevronRight className="w-3.5 h-3.5 text-white/10" />
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
