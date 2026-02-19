import { useState, useEffect } from 'react';
import { useStore } from '../store';
import {
  listExploits, searchExploits, uploadExploitFile,
  listChains as apiListChains, getKBStats,
} from '../api';
import {
  Database, Search, Upload, FileText, Link2,
  Loader2, CheckCircle2, AlertCircle, BookOpen,
  Shield, Zap, Hash, Tag,
} from 'lucide-react';

export default function KnowledgeBaseTab() {
  const exploits = useStore((s) => s.exploits);
  const setExploits = useStore((s) => s.setExploits);
  const kbChains = useStore((s) => s.kbChains);
  const setKBChains = useStore((s) => s.setKBChains);
  const kbStats = useStore((s) => s.kbStats);
  const setKBStats = useStore((s) => s.setKBStats);

  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [uploadResult, setUploadResult] = useState(null);
  const [activeSection, setActiveSection] = useState('exploits');

  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      const [exploitsRes, chainsRes, statsRes] = await Promise.all([
        listExploits().catch(() => ({ data: [] })),
        apiListChains().catch(() => ({ data: [] })),
        getKBStats().catch(() => ({ data: { total_exploits: 0, total_chains: 0 } })),
      ]);
      setExploits(exploitsRes.data);
      setKBChains(chainsRes.data);
      setKBStats(statsRes.data);
    } catch (e) {
      console.error('Failed to load KB data', e);
    }
  };

  const handleSearch = async () => {
    if (!searchQuery.trim()) return;
    setActiveSection('search results');
    try {
      const { data } = await searchExploits(searchQuery);
      setSearchResults(data);
    } catch {
      setSearchResults([]);
    }
  };

  const handleUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    setUploading(true);
    setUploadResult(null);

    try {
      const { data } = await uploadExploitFile(file);
      setUploadResult({ success: true, data });
      loadData();
    } catch (err) {
      setUploadResult({
        success: false,
        error: err.response?.data?.detail || 'Upload failed',
      });
    } finally {
      setUploading(false);
    }
  };

  const sectionTabs = [
    { id: 'exploits', label: 'Exploits', icon: FileText },
    { id: 'chains', label: 'Chains', icon: Link2 },
    { id: 'search results', label: 'Search Results', icon: Search },
  ];

  return (
    <div className="h-full flex flex-col dot-pattern">
      {/* Header */}
      <div className="glass border-b border-white/[0.04] p-5">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-base font-semibold text-white/80 flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-xl bg-accent-sage/10 border border-accent-sage/20 flex items-center justify-center">
              <Database className="w-4 h-4 text-accent-sage" />
            </div>
            Community Exploit Knowledge Base
          </h2>
          <div className="flex items-center gap-3">
            <span className="metal-badge px-2.5 py-1 text-[11px] text-white/30">
              {kbStats.total_exploits} exploits
            </span>
            <span className="metal-badge px-2.5 py-1 text-[11px] text-white/30">
              {kbStats.total_chains} chains
            </span>
          </div>
        </div>

        {/* Search + Upload */}
        <div className="flex items-center gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-white/20" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
              placeholder="Semantic search: 'JWT bypass', 'SQLi RCE chain', 'CVE-2024-...'"
              className="w-full metal-input pl-10 pr-4 py-2.5 text-white/90 placeholder-white/20 text-sm"
            />
          </div>
          <button
            onClick={handleSearch}
            className="key-btn px-5 py-2.5 text-accent-sage text-sm font-medium"
          >
            Search
          </button>

          <label className={`key-btn flex items-center gap-2 px-4 py-2.5 text-sm font-medium cursor-pointer
            ${uploading ? 'text-white/30' : 'text-accent-rose/70 hover:text-accent-rose'}`}>
            {uploading ? <Loader2 className="w-4 h-4 animate-spin" /> : <Upload className="w-4 h-4" />}
            {uploading ? 'Parsing...' : 'Upload'}
            <input type="file" className="hidden" onChange={handleUpload} disabled={uploading} />
          </label>
        </div>

        {/* Upload result */}
        {uploadResult && (
          <div className={`mt-3 glass-sm p-3 rounded-xl text-[12px] flex items-center gap-2 ${
            uploadResult.success
              ? 'border border-accent-sage/20 text-accent-sage'
              : 'border border-red-500/20 text-red-400'
          }`}>
            {uploadResult.success ? <CheckCircle2 className="w-4 h-4" /> : <AlertCircle className="w-4 h-4" />}
            {uploadResult.success
              ? `Uploaded: ${uploadResult.data?.title || 'Exploit'} — parsed successfully`
              : uploadResult.error}
          </div>
        )}
      </div>

      {/* Section tabs */}
      <div className="border-b border-white/[0.04] flex px-2">
        {sectionTabs.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setActiveSection(id)}
            className={`flex items-center gap-2 px-5 py-2.5 text-sm font-medium transition-all border-b-2 ${
              activeSection === id
                ? 'text-accent-warm border-accent-warm/50'
                : 'text-white/25 border-transparent hover:text-white/40'
            }`}
          >
            <Icon className="w-3.5 h-3.5" />
            {label}
          </button>
        ))}
      </div>

      {/* Content */}
      <div className="flex-1 overflow-auto p-5">
        {activeSection === 'exploits' && <ExploitList exploits={exploits} />}
        {activeSection === 'chains' && <ChainList chains={kbChains} />}
        {activeSection === 'search results' && <SearchResults results={searchResults} />}
      </div>
    </div>
  );
}

function ExploitList({ exploits }) {
  if (!exploits?.length) {
    return (
      <div className="flex flex-col items-center justify-center py-16">
        <div className="w-14 h-14 rounded-2xl glass-card flex items-center justify-center mb-4">
          <FileText className="w-7 h-7 text-white/15" />
        </div>
        <p className="text-white/25 text-sm">No exploits in the knowledge base yet</p>
        <p className="text-white/15 text-xs mt-1">Upload exploit files to get started</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {exploits.map((e, idx) => (
        <div key={e.id || idx} className="glass-card p-4">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-[13px] font-semibold text-white/80">{e.title}</h3>
            <div className="flex items-center gap-2">
              {e.cve_id && (
                <span className="metal-badge text-[11px] mono text-accent-ice px-2 py-0.5">
                  {e.cve_id}
                </span>
              )}
              <SeverityBadge severity={e.severity} />
            </div>
          </div>
          <p className="text-[12px] text-white/35 leading-relaxed">{e.description}</p>
          {e.tags?.length > 0 && (
            <div className="flex gap-1.5 mt-2.5">
              {e.tags.map((t) => (
                <span key={t} className="metal-badge text-[10px] text-white/25 px-2 py-0.5">
                  {t}
                </span>
              ))}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function ChainList({ chains }) {
  if (!chains?.length) {
    return (
      <div className="flex flex-col items-center justify-center py-16">
        <div className="w-14 h-14 rounded-2xl glass-card flex items-center justify-center mb-4">
          <Link2 className="w-7 h-7 text-white/15" />
        </div>
        <p className="text-white/25 text-sm">No attack chains in the knowledge base</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {chains.map((c, idx) => (
        <div key={c.id || idx} className="glass-card p-4">
          <div className="flex items-center gap-2 mb-1">
            <Zap className="w-3.5 h-3.5 text-accent-warm/50" />
            <h3 className="text-[13px] font-semibold text-white/80">{c.name}</h3>
          </div>
          <p className="text-[12px] text-white/35 mt-1">{c.description}</p>
          <span className="metal-badge text-[10px] text-accent-rose/60 px-2 py-0.5 mt-2 inline-block">{c.chain_type}</span>
        </div>
      ))}
    </div>
  );
}

function SearchResults({ results }) {
  if (results === null) {
    return (
      <div className="flex flex-col items-center justify-center py-16">
        <div className="w-14 h-14 rounded-2xl glass-card flex items-center justify-center mb-4 animate-float">
          <Search className="w-7 h-7 text-white/15" />
        </div>
        <p className="text-white/25 text-sm">Enter a query to semantically search the knowledge base</p>
        <p className="text-white/15 text-xs mt-1">Powered by vector embeddings for intelligent matching</p>
      </div>
    );
  }

  if (!results?.length) {
    return (
      <div className="flex flex-col items-center justify-center py-16">
        <p className="text-white/25 text-sm">No results found</p>
        <p className="text-white/15 text-xs mt-1">Try different keywords or broader terms</p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {results.map((r, idx) => {
        // Parse the result - handle both structured and raw formats
        const id = r.id || r.exploit_id || `result-${idx}`;
        const document = r.document || r.text || r.description || '';
        const metadata = r.metadata || {};
        const distance = r.distance ?? r.score ?? null;
        const title = metadata.title || r.title || id;
        const severity = metadata.severity || r.severity || 'info';
        const attackType = metadata.attack_type || r.attack_type || '';
        const cveId = metadata.cve_id || r.cve_id || '';

        // Calculate relevance percentage from distance (lower distance = higher relevance)
        const relevance = distance !== null ? Math.max(0, Math.round((1 - distance) * 100)) : null;

        return (
          <div key={idx} className="glass-card p-4">
            <div className="flex items-start justify-between mb-2">
              <div className="flex items-center gap-2">
                <div className="w-7 h-7 rounded-lg bg-accent-ice/10 border border-accent-ice/15 flex items-center justify-center">
                  <BookOpen className="w-3.5 h-3.5 text-accent-ice/70" />
                </div>
                <div>
                  <h3 className="text-[13px] font-semibold text-white/80">{title}</h3>
                  <div className="flex items-center gap-2 mt-0.5">
                    {cveId && (
                      <span className="metal-badge text-[10px] mono text-accent-ice px-1.5 py-0.5">{cveId}</span>
                    )}
                    {attackType && (
                      <span className="metal-badge text-[10px] text-accent-warm/60 px-1.5 py-0.5">{attackType}</span>
                    )}
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-2">
                {relevance !== null && (
                  <div className="flex items-center gap-1.5">
                    <div className="w-16 h-1 bg-white/[0.04] rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full bg-gradient-to-r from-accent-warm/50 to-accent-warm/30"
                        style={{ width: `${relevance}%` }}
                      />
                    </div>
                    <span className="text-[10px] mono text-accent-warm/60">{relevance}%</span>
                  </div>
                )}
                <SeverityBadge severity={severity} />
              </div>
            </div>
            <p className="text-[12px] text-white/40 leading-relaxed mt-2 line-clamp-3">
              {document}
            </p>
          </div>
        );
      })}
    </div>
  );
}

function SeverityBadge({ severity }) {
  const config = {
    critical: 'text-red-400 bg-red-500/10 border-red-500/20',
    high: 'text-orange-400 bg-orange-500/10 border-orange-500/20',
    medium: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
    low: 'text-blue-400 bg-blue-500/10 border-blue-500/20',
    info: 'text-white/30 bg-white/5 border-white/10',
  };
  return (
    <span className={`metal-badge text-[10px] font-medium uppercase px-2 py-0.5 ${config[severity] || config.info}`}>
      {severity || 'info'}
    </span>
  );
}
