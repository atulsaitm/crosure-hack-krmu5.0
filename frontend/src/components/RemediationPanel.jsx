import { useEffect } from 'react';
import { useStore } from '../store';
import { getRemediation } from '../api';
import { X, Sparkles, Loader2, ExternalLink, ShieldAlert, Tag, Globe, Code, FileWarning } from 'lucide-react';
import ReactMarkdown from 'react-markdown';

export default function RemediationPanel() {
  const finding = useStore((s) => s.selectedFinding);
  const setSelectedFinding = useStore((s) => s.setSelectedFinding);
  const remediationText = useStore((s) => s.remediationText);
  const remediationLoading = useStore((s) => s.remediationLoading);
  const setRemediation = useStore((s) => s.setRemediation);
  const setRemediationLoading = useStore((s) => s.setRemediationLoading);

  useEffect(() => {
    if (!finding) return;

    if (finding.remediation) {
      setRemediation(finding.remediation);
      return;
    }

    setRemediationLoading(true);
    getRemediation(finding)
      .then(({ data }) => setRemediation(data.remediation))
      .catch(() => setRemediation('Unable to generate remediation. Please check Ollama status.'));
  }, [finding?.id]);

  if (!finding) return null;

  return (
    <div className="p-5 flex flex-col glass">
      {/* Header */}
      <div className="flex items-center justify-between mb-5">
        <h3 className="text-sm font-semibold text-white/80 flex items-center gap-2">
          <div className="w-6 h-6 rounded-lg bg-accent-warm/10 flex items-center justify-center">
            <ShieldAlert className="w-3.5 h-3.5 text-accent-warm" />
          </div>
          Finding Detail
        </h3>
        <button
          onClick={() => setSelectedFinding(null)}
          className="key-btn p-1.5 text-white/30 hover:text-white/60"
        >
          <X className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* Finding Info */}
      <div className="space-y-3 mb-5">
        <InfoRow icon={<Tag className="w-3 h-3" />} label="Vulnerability" value={finding.vuln_type} highlight />
        <InfoRow icon={<Globe className="w-3 h-3" />} label="URL" value={finding.url} mono breakAll />
        {finding.parameter && (
          <InfoRow icon={<Code className="w-3 h-3" />} label="Parameter" value={finding.parameter} mono />
        )}
        {finding.payload && (
          <div>
            <label className="text-[10px] text-white/25 block mb-1 uppercase tracking-wider">Payload</label>
            <pre className="text-[11px] text-accent-warm/80 mono bg-black/30 p-2.5 rounded-lg border border-white/[0.04] overflow-x-auto">
              {finding.payload}
            </pre>
          </div>
        )}
        {finding.evidence && (
          <div>
            <label className="text-[10px] text-white/25 block mb-1 uppercase tracking-wider">Evidence</label>
            <p className="text-[11px] text-white/50 bg-black/20 p-2.5 rounded-lg border border-white/[0.04]">{finding.evidence}</p>
          </div>
        )}
        <div>
          <label className="text-[10px] text-white/25 block mb-1 uppercase tracking-wider">Description</label>
          <p className="text-[11px] text-white/50 leading-relaxed">{finding.description}</p>
        </div>
        {finding.owasp_category && (
          <div>
            <label className="text-[10px] text-white/25 block mb-1 uppercase tracking-wider">OWASP</label>
            <span className="metal-badge text-[11px] text-accent-rose/70 px-2 py-0.5 inline-block">{finding.owasp_category}</span>
          </div>
        )}
      </div>

      {/* Warm divider */}
      <div className="warm-divider mb-4" />

      {/* AI Remediation */}
      <div className="glass-card p-4">
        <h4 className="text-[13px] font-medium text-white/70 flex items-center gap-2 mb-3">
          <Sparkles className="w-4 h-4 text-accent-warm/60" />
          AI Remediation
        </h4>

        {remediationLoading ? (
          <div className="flex items-center gap-2.5 text-white/30 text-sm">
            <Loader2 className="w-4 h-4 animate-spin text-accent-warm/50" />
            Generating remediation...
          </div>
        ) : remediationText ? (
          <div className="prose prose-invert prose-sm max-w-none
            prose-headings:text-white/80 prose-headings:text-[13px] prose-headings:font-semibold prose-headings:mt-3 prose-headings:mb-1.5
            prose-p:text-white/50 prose-p:text-[12px] prose-p:leading-relaxed prose-p:my-1
            prose-li:text-white/50 prose-li:text-[12px] prose-li:my-0.5
            prose-strong:text-accent-warm/80
            prose-code:text-accent-warm/70 prose-code:bg-black/30 prose-code:px-1 prose-code:py-0.5 prose-code:rounded prose-code:text-[11px]
            prose-pre:bg-black/40 prose-pre:border prose-pre:border-white/[0.06] prose-pre:rounded-lg prose-pre:text-[11px] prose-pre:p-3
            prose-a:text-accent-warm/70 prose-a:no-underline hover:prose-a:text-accent-warm">
            <ReactMarkdown>{remediationText}</ReactMarkdown>
          </div>
        ) : (
          <p className="text-[12px] text-white/30">Click a finding to get AI-powered remediation.</p>
        )}
      </div>
    </div>
  );
}

function InfoRow({ icon, label, value, mono, highlight, breakAll }) {
  return (
    <div>
      <label className="text-[10px] text-white/25 block mb-0.5 uppercase tracking-wider flex items-center gap-1">
        <span className="text-white/15">{icon}</span>
        {label}
      </label>
      <p className={`text-[12px] ${highlight ? 'text-white/80 font-medium' : 'text-white/50'} ${mono ? 'mono' : ''} ${breakAll ? 'break-all' : ''}`}>
        {value}
      </p>
    </div>
  );
}
