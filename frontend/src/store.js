import { create } from 'zustand';

export const useStore = create((set, get) => ({
  // ── Active tab ──
  activeTab: 'scan',
  setActiveTab: (tab) => set({ activeTab: tab }),

  // ── Scan state ──
  scanId: null,
  scanStatus: 'idle', // idle | running | complete | error
  scanProgress: 0,
  scanPhase: '',
  scanMessage: '',
  scanError: '',
  targetUrl: '',
  setTargetUrl: (url) => set({ targetUrl: url }),

  // ── Results ──
  findings: [],
  chains: [],
  techStack: [],
  endpointsCrawled: 0,
  scanDuration: 0,

  // ── Selected finding for remediation panel ──
  selectedFinding: null,
  setSelectedFinding: (f) => set({ selectedFinding: f }),
  remediationText: '',
  remediationLoading: false,

  // ── Graph sidebar ──
  graphSidebarOpen: false,
  setGraphSidebarOpen: (v) => set({ graphSidebarOpen: v }),
  toggleGraphSidebar: () => set((s) => ({ graphSidebarOpen: !s.graphSidebarOpen })),

  // ── KB ──
  exploits: [],
  kbChains: [],
  kbStats: { total_exploits: 0, total_chains: 0 },

  // ── Actions ──
  startScan: (scanId) => {
    console.log('[Store] startScan:', scanId);
    set({
      scanId: scanId || null,
      scanStatus: 'running',
      scanProgress: 0,
      scanPhase: 'Starting...',
      scanMessage: '',
      scanError: '',
      findings: [],
      chains: [],
      selectedFinding: null,
      remediationText: '',
    });
  },

  completeScan: (result) => {
    console.log('[Store] completeScan:', result?.findings?.length, 'findings,', result?.chains?.length, 'chains');
    set({
      scanStatus: 'complete',
      scanProgress: 1.0,
      scanPhase: 'Complete',
      scanId: result.scan_id,
      findings: result.findings || [],
      chains: result.chains || [],
      techStack: result.tech_stack || [],
      endpointsCrawled: result.endpoints_crawled || 0,
      scanDuration: result.scan_duration || 0,
      scanError: (result.errors && result.errors.length > 0) ? result.errors.join('; ') : '',
    });
  },

  failScan: (error, partialResult) => {
    console.error('[Store] failScan:', error, partialResult ? `(${partialResult.findings?.length || 0} partial findings)` : '(no partial)');
    const update = {
      scanStatus: 'error',
      scanError: error,
    };
    // Preserve partial results if available
    if (partialResult) {
      update.findings = partialResult.findings || [];
      update.chains = partialResult.chains || [];
      update.techStack = partialResult.tech_stack || [];
      update.endpointsCrawled = partialResult.endpoints_crawled || 0;
      update.scanDuration = partialResult.scan_duration || 0;
    }
    set(update);
  },

  updateProgress: (event) => {
    const state = get();
    // Don't update progress if scan already completed or errored (stale WS events)
    if (state.scanStatus !== 'running') {
      console.log('[Store] Ignoring progress event (status:', state.scanStatus, ')');
      return;
    }
    console.log('[Store] Progress:', event.phase, Math.round((event.progress || 0) * 100) + '%', event.message || '');
    set({
      scanProgress: event.progress || 0,
      scanPhase: event.phase || '',
      scanMessage: event.message || '',
    });
  },

  setRemediation: (text) => set({ remediationText: text, remediationLoading: false }),
  setRemediationLoading: (v) => set({ remediationLoading: v }),

  setExploits: (exploits) => set({ exploits }),
  setKBChains: (chains) => set({ kbChains: chains }),
  setKBStats: (stats) => set({ kbStats: stats }),
}));
