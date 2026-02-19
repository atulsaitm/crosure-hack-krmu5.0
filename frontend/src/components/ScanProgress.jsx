import { useStore } from '../store';
import { Activity } from 'lucide-react';

export default function ScanProgress() {
  const progress = useStore((s) => s.scanProgress);
  const phase = useStore((s) => s.scanPhase);
  const message = useStore((s) => s.scanMessage);

  return (
    <div className="glass-sm border-b border-white/[0.04] px-5 py-3">
      <div className="flex items-center justify-between mb-2">
        <span className="text-[11px] font-medium text-accent-warm uppercase tracking-wider flex items-center gap-2">
          <Activity className="w-3 h-3 animate-pulse" />
          {phase || 'Initializing...'}
        </span>
        <span className="text-[11px] text-white/30 mono">
          {Math.round(progress * 100)}%
        </span>
      </div>

      {/* Progress bar */}
      <div className="w-full h-1 bg-white/[0.04] rounded-full overflow-hidden">
        <div
          className="h-full scan-progress-bar rounded-full transition-all duration-700 ease-out"
          style={{ width: `${Math.max(progress * 100, 2)}%` }}
        />
      </div>

      {message && (
        <p className="text-[11px] text-white/20 mt-1.5 truncate">{message}</p>
      )}
    </div>
  );
}
