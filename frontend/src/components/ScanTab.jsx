import { useState } from 'react';
import { useStore } from '../store';
import { getRemediation } from '../api';
import ScanControl from './ScanControl';
import FindingsTable from './FindingsTable';
import RemediationPanel from './RemediationPanel';
import ScanProgress from './ScanProgress';
import { Shield, Crosshair, AlertTriangle, CheckCircle2 } from 'lucide-react';

export default function ScanTab() {
  const scanStatus = useStore((s) => s.scanStatus);
  const findings = useStore((s) => s.findings);
  const selectedFinding = useStore((s) => s.selectedFinding);
  const scanMessage = useStore((s) => s.scanMessage);
  const scanError = useStore((s) => s.scanError);
  const endpointsCrawled = useStore((s) => s.endpointsCrawled);

  return (
    <div className="flex flex-col h-full dot-pattern">
      {/* Scan Controls */}
      <ScanControl />

      {/* Progress bar */}
      {scanStatus === 'running' && <ScanProgress />}

      {/* Error / Success Banner */}
      {scanStatus === 'error' && (
        <div className="mx-5 mt-3 px-4 py-2.5 rounded-lg bg-red-500/10 border border-red-500/20 flex items-center gap-3">
          <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0" />
          <div className="flex-1 min-w-0">
            <span className="text-red-400/90 text-xs font-medium">Scan encountered an error</span>
            <p className="text-white/30 text-[11px] truncate">{scanError || 'Connection timed out. Partial results shown below.'}</p>
          </div>
          {findings.length > 0 && (
            <span className="text-white/40 text-[11px] flex-shrink-0">{findings.length} findings recovered</span>
          )}
        </div>
      )}

      {scanStatus === 'complete' && findings.length > 0 && (
        <div className="mx-5 mt-3 px-4 py-2.5 rounded-lg bg-accent-sage/10 border border-accent-sage/20 flex items-center gap-3">
          <CheckCircle2 className="w-4 h-4 text-accent-sage flex-shrink-0" />
          <span className="text-accent-sage/90 text-xs font-medium">
            Scan complete — {findings.length} vulnerabilities found across {endpointsCrawled} endpoints
          </span>
        </div>
      )}

      {/* Main content area */}
      <div className="flex-1 flex overflow-hidden">
        {/* Findings Table */}
        <div className={`${selectedFinding ? 'w-2/3' : 'w-full'} overflow-auto p-5`}>
          {findings.length > 0 ? (
            <FindingsTable />
          ) : (scanStatus === 'complete' || scanStatus === 'error') ? (
            <div className="flex flex-col items-center justify-center h-64">
              <div className="w-14 h-14 rounded-2xl glass-card flex items-center justify-center mb-4">
                <Shield className="w-7 h-7 text-accent-sage/60" />
              </div>
              <p className="text-white/40 text-sm">
                {scanStatus === 'error' ? 'No vulnerabilities recovered' : 'No vulnerabilities found'}
              </p>
              <p className="text-white/20 text-xs mt-1">
                {scanStatus === 'error' ? 'The scan failed before findings could be collected' : 'Target may be secure or scan scope too limited'}
              </p>
            </div>
          ) : scanStatus === 'idle' ? (
            <div className="flex flex-col items-center justify-center h-64">
              <div className="w-16 h-16 rounded-2xl glass-card flex items-center justify-center mb-4 animate-float">
                <Crosshair className="w-8 h-8 text-accent-warm/40" />
              </div>
              <p className="text-white/30 text-sm">Enter a target URL and start scanning</p>
              <p className="text-white/15 text-xs mt-1">Supports HTTP/HTTPS web applications</p>
            </div>
          ) : null}
        </div>

        {/* Remediation Panel */}
        {selectedFinding && (
          <div className="w-1/3 border-l border-white/[0.04] overflow-auto">
            <RemediationPanel />
          </div>
        )}
      </div>
    </div>
  );
}
