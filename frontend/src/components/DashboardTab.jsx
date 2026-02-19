import { useStore } from '../store';
import {
  BarChart3, Shield, AlertTriangle, Clock, Globe,
  Cpu, GitBranch, Zap, Activity, Target,
} from 'lucide-react';

export default function DashboardTab() {
  const findings = useStore((s) => s.findings);
  const chains = useStore((s) => s.chains);
  const techStack = useStore((s) => s.techStack);
  const endpointsCrawled = useStore((s) => s.endpointsCrawled);
  const scanDuration = useStore((s) => s.scanDuration);
  const scanStatus = useStore((s) => s.scanStatus);
  const targetUrl = useStore((s) => s.targetUrl);
  const kbStats = useStore((s) => s.kbStats);

  const severityCounts = findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {});

  const typeCounts = findings.reduce((acc, f) => {
    acc[f.vuln_type] = (acc[f.vuln_type] || 0) + 1;
    return acc;
  }, {});

  const topTypes = Object.entries(typeCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8);

  const maxCvss = findings.length
    ? Math.max(...findings.map((f) => f.cvss_score || 0))
    : 0;

  const avgCvss = findings.length
    ? (findings.reduce((s, f) => s + (f.cvss_score || 0), 0) / findings.length).toFixed(1)
    : 0;

  return (
    <div className="p-6 overflow-auto dot-pattern">
      <h2 className="text-base font-semibold text-white/80 flex items-center gap-2.5 mb-6">
        <div className="w-8 h-8 rounded-xl bg-accent-warm/10 border border-accent-warm/20 flex items-center justify-center">
          <BarChart3 className="w-4 h-4 text-accent-warm" />
        </div>
        Scan Dashboard
      </h2>

      {(scanStatus === 'idle' && findings.length === 0) ? (
        <div className="flex flex-col items-center justify-center py-20">
          <div className="w-20 h-20 rounded-3xl glass-card flex items-center justify-center mb-5 animate-float">
            <Shield className="w-10 h-10 text-white/8" />
          </div>
          <p className="text-white/25 text-sm">No scan results yet</p>
          <p className="text-white/15 text-xs mt-1">Start a scan to see the dashboard</p>
        </div>
      ) : (
        <>
          {/* Stat Cards */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            <StatCard
              icon={<AlertTriangle className="w-4 h-4 text-red-400/70" />}
              iconBg="bg-red-500/10 border-red-500/15"
              label="Total Findings"
              value={findings.length}
              sub={`${severityCounts.critical || 0} critical, ${severityCounts.high || 0} high`}
            />
            <StatCard
              icon={<GitBranch className="w-4 h-4 text-accent-rose/70" />}
              iconBg="bg-accent-rose/10 border-accent-rose/15"
              label="Attack Chains"
              value={chains.length}
              sub={chains.length > 0 ? `Top: ${Math.max(...chains.map(c => c.total_score || 0)).toFixed(1)}` : 'None found'}
            />
            <StatCard
              icon={<Target className="w-4 h-4 text-accent-ice/70" />}
              iconBg="bg-accent-ice/10 border-accent-ice/15"
              label="Endpoints"
              value={endpointsCrawled}
              sub={targetUrl ? (() => { try { return new URL(targetUrl).hostname; } catch { return '—'; } })() : '—'}
            />
            <StatCard
              icon={<Clock className="w-4 h-4 text-accent-amber/70" />}
              iconBg="bg-accent-amber/10 border-accent-amber/15"
              label="Duration"
              value={`${scanDuration.toFixed(0)}s`}
              sub={`Avg: ${avgCvss} | Max: ${maxCvss.toFixed(1)}`}
            />
          </div>

          {/* Severity Breakdown + Vuln Types */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
            <div className="glass-card p-5">
              <h3 className="text-[13px] font-semibold text-white/70 mb-4 flex items-center gap-2">
                <Activity className="w-3.5 h-3.5 text-accent-warm/50" />
                Severity Distribution
              </h3>
              <div className="space-y-3.5">
                {['critical', 'high', 'medium', 'low', 'info'].map((sev) => {
                  const count = severityCounts[sev] || 0;
                  const pct = findings.length ? (count / findings.length) * 100 : 0;
                  const gradients = {
                    critical: 'from-red-500/60 to-red-500/20',
                    high: 'from-orange-500/60 to-orange-500/20',
                    medium: 'from-yellow-500/50 to-yellow-500/15',
                    low: 'from-blue-500/50 to-blue-500/15',
                    info: 'from-white/20 to-white/5',
                  };
                  const textColors = {
                    critical: 'text-red-400/70',
                    high: 'text-orange-400/70',
                    medium: 'text-yellow-400/70',
                    low: 'text-blue-400/70',
                    info: 'text-white/30',
                  };
                  return (
                    <div key={sev}>
                      <div className="flex justify-between text-[11px] mb-1.5">
                        <span className={`capitalize font-medium ${textColors[sev]}`}>{sev}</span>
                        <span className="text-white/25 mono">{count}</span>
                      </div>
                      <div className="h-1.5 bg-white/[0.03] rounded-full overflow-hidden">
                        <div
                          className={`h-full bg-gradient-to-r ${gradients[sev]} rounded-full transition-all duration-700`}
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>

            <div className="glass-card p-5">
              <h3 className="text-[13px] font-semibold text-white/70 mb-4 flex items-center gap-2">
                <Zap className="w-3.5 h-3.5 text-accent-warm/50" />
                Vulnerability Types
              </h3>
              <div className="space-y-2.5">
                {topTypes.map(([type, count]) => (
                  <div key={type} className="flex items-center justify-between">
                    <span className="metal-badge text-[11px] mono text-accent-warm/60 px-2 py-0.5">
                      {type}
                    </span>
                    <div className="flex items-center gap-2">
                      <div className="w-12 h-1 bg-white/[0.03] rounded-full overflow-hidden">
                        <div
                          className="h-full bg-gradient-to-r from-accent-warm/40 to-accent-warm/10 rounded-full"
                          style={{ width: `${(count / findings.length) * 100}%` }}
                        />
                      </div>
                      <span className="text-[11px] text-white/25 mono w-4 text-right">{count}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Tech Stack + KB Stats */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div className="glass-card p-5">
              <h3 className="text-[13px] font-semibold text-white/70 mb-3 flex items-center gap-2">
                <Cpu className="w-3.5 h-3.5 text-accent-sage/50" />
                Detected Technology
              </h3>
              {techStack?.length > 0 ? (
                <div className="flex flex-wrap gap-2">
                  {techStack.map((tech) => (
                    <span key={tech} className="metal-badge text-[11px] text-accent-sage/60 px-2.5 py-1 bg-accent-sage/5 border-accent-sage/15">
                      {tech}
                    </span>
                  ))}
                </div>
              ) : (
                <p className="text-[11px] text-white/20">No tech detected</p>
              )}
            </div>

            <div className="glass-card p-5">
              <h3 className="text-[13px] font-semibold text-white/70 mb-3 flex items-center gap-2">
                <Zap className="w-3.5 h-3.5 text-accent-amber/50" />
                Knowledge Base
              </h3>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <p className="text-2xl font-bold text-white/80 mono">{kbStats.total_exploits}</p>
                  <p className="text-[11px] text-white/20 mt-0.5">Exploits</p>
                </div>
                <div>
                  <p className="text-2xl font-bold text-white/80 mono">{kbStats.total_chains}</p>
                  <p className="text-[11px] text-white/20 mt-0.5">Known Chains</p>
                </div>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

function StatCard({ icon, iconBg, label, value, sub }) {
  return (
    <div className="glass-card p-4">
      <div className="flex items-center gap-2 mb-3">
        <div className={`w-7 h-7 rounded-lg border flex items-center justify-center ${iconBg}`}>
          {icon}
        </div>
        <span className="text-[11px] text-white/30 font-medium">{label}</span>
      </div>
      <p className="text-2xl font-bold text-white/85 mono">{value}</p>
      <p className="text-[11px] text-white/20 mt-1">{sub}</p>
    </div>
  );
}
