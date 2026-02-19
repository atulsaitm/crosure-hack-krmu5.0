import axios from 'axios';

const API_BASE = import.meta.env.VITE_API_URL || '';

const api = axios.create({
  baseURL: API_BASE,
  timeout: 300000, // 5 min for scans
});

// ── Scan ──
export const startScan = (data) => api.post('/api/scan/', data);
export const startScanAsync = (data) => api.post('/api/scan/async', data);
export const getScanStatus = (scanId) => api.get(`/api/scan/${scanId}/status`);
export const getScanResult = (scanId) => api.get(`/api/scan/${scanId}/result`);

// ── Findings ──
export const getRemediation = (finding) => api.post('/api/findings/remediate', { finding });
export const triageFinding = (finding) => api.post('/api/findings/triage', { finding });

// ── Knowledge Base ──
export const listExploits = (limit = 50) => api.get(`/api/kb/exploits?limit=${limit}`);
export const searchExploits = (query, attackType, severity) => {
  const params = new URLSearchParams({ query });
  if (attackType) params.append('attack_type', attackType);
  if (severity) params.append('severity', severity);
  return api.get(`/api/kb/exploits/search?${params}`);
};
export const createExploit = (data) => api.post('/api/kb/exploits', data);
export const uploadExploitFile = (file, title) => {
  const formData = new FormData();
  formData.append('file', file);
  if (title) formData.append('title', title);
  return api.post('/api/kb/upload', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  });
};
export const listChains = () => api.get('/api/kb/chains');
export const createChain = (data) => api.post('/api/kb/chains', data);
export const getKBStats = () => api.get('/api/kb/stats');

// ── Health ──
export const healthCheck = () => api.get('/health');

// ── WebSocket ──
export const connectWebSocket = (onEvent) => {
  const wsUrl = `${window.location.protocol === 'https:' ? 'wss:' : 'ws:'}//${window.location.host}/ws`;
  console.log('[Crosure WS] Connecting to:', wsUrl);
  const ws = new WebSocket(wsUrl);

  ws.onopen = () => {
    console.log('[Crosure WS] Connected');
  };

  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      onEvent(data);
    } catch (e) {
      console.error('[Crosure WS] Parse error', e);
    }
  };

  ws.onclose = (ev) => {
    console.warn('[Crosure WS] Disconnected, code:', ev.code, 'reason:', ev.reason, '— reconnecting in 3s');
    setTimeout(() => connectWebSocket(onEvent), 3000);
  };

  ws.onerror = (err) => {
    console.error('[Crosure WS] Error', err);
  };

  return ws;
};

export default api;
