import { useStore } from '../store';
import { Shield, Search, GitBranch, Database, BarChart3 } from 'lucide-react';

const tabs = [
  { id: 'scan', label: 'Scan', icon: Search },
  { id: 'graph', label: 'Attack Graph', icon: GitBranch },
  { id: 'kb', label: 'Knowledge Base', icon: Database },
  { id: 'dashboard', label: 'Dashboard', icon: BarChart3 },
];

export default function Header() {
  const activeTab = useStore((s) => s.activeTab);
  const setActiveTab = useStore((s) => s.setActiveTab);
  const scanStatus = useStore((s) => s.scanStatus);

  return (
    <header className="glass border-b border-white/[0.04] px-6 py-3 relative z-10">
      <div className="flex items-center justify-between">
        {/* Logo */}
        <div className="flex items-center gap-3">
          <div className="relative">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-accent-warm/20 to-accent-warm/5 border border-accent-warm/20 flex items-center justify-center shadow-glow-warm">
              <Shield className="w-5 h-5 text-accent-warm" />
            </div>
          </div>
          <div>
            <h1 className="text-lg font-bold tracking-[0.15em] text-white/90">
              CROSURE
            </h1>
            <p className="text-[10px] text-white/25 -mt-0.5 tracking-wider uppercase">Attack-Chain Scanner</p>
          </div>
        </div>

        {/* Keyboard-style Tabs */}
        <nav className="flex items-center gap-1.5">
          {tabs.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              onClick={() => setActiveTab(id)}
              className={`key-btn flex items-center gap-2 px-4 py-2 text-sm font-medium ${
                activeTab === id ? 'key-active' : 'text-white/40 hover:text-white/70'
              }`}
            >
              <Icon className="w-4 h-4" />
              {label}
            </button>
          ))}
        </nav>

        {/* Status indicator */}
        <div className="flex items-center gap-2.5">
          <div className="flex items-center gap-2 metal-badge px-3 py-1.5">
            <div className={`w-1.5 h-1.5 rounded-full ${
              scanStatus === 'running' ? 'bg-accent-amber animate-pulse shadow-[0_0_6px_rgba(245,158,11,0.5)]' :
              scanStatus === 'complete' ? 'bg-accent-sage shadow-[0_0_6px_rgba(156,175,136,0.4)]' :
              scanStatus === 'error' ? 'bg-threat-critical shadow-[0_0_6px_rgba(239,68,68,0.4)]' :
              'bg-white/20'
            }`} />
            <span className="text-[11px] text-white/40 capitalize tracking-wide">{scanStatus}</span>
          </div>
        </div>
      </div>
    </header>
  );
}
