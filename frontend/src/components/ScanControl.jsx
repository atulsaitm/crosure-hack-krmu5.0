import { useState } from 'react';
import { useStore } from '../store';
import { startScanAsync, getScanResult } from '../api';
import { Play, Loader2, Globe, Cookie, ChevronDown } from 'lucide-react';

export default function ScanControl() {
  const targetUrl = useStore((s) => s.targetUrl);
  const setTargetUrl = useStore((s) => s.setTargetUrl);
  const scanStatus = useStore((s) => s.scanStatus);
  const storeScan = useStore((s) => s.startScan);
  const completeScan = useStore((s) => s.completeScan);
  const failScan = useStore((s) => s.failScan);

  const [authCookie, setAuthCookie] = useState('');
  const [showAdvanced, setShowAdvanced] = useState(false);

  const handleScan = async () => {
    if (!targetUrl.trim() || scanStatus === 'running') return;

    console.log('[Crosure] Starting scan for:', targetUrl.trim());

    try {
      // Start async scan — returns immediately with scan_id
      const { data } = await startScanAsync({
        target_url: targetUrl.trim(),
        auth_cookie: authCookie || null,
      });

      const scanId = data.scan_id;
      console.log('[Crosure] Scan started, id:', scanId);
      storeScan(scanId);

      // Poll for completion every 4 seconds
      let pollCount = 0;
      const pollInterval = setInterval(async () => {
        pollCount++;
        try {
          const result = await getScanResult(scanId);
          const status = result.status;
          console.log(`[Crosure] Poll #${pollCount} → HTTP ${status}`);

          // 202 means still running — keep polling
          if (status === 202) {
            console.log('[Crosure] Scan still in progress...');
            return;
          }

          // 200 means done (complete or errored)
          clearInterval(pollInterval);
          const respData = result.data;
          console.log('[Crosure] Scan finished:', {
            findings: respData.findings?.length || 0,
            chains: respData.chains?.length || 0,
            errors: respData.errors,
          });

          if (respData.errors && respData.errors.length > 0 && (!respData.findings || respData.findings.length === 0)) {
            failScan(respData.errors.join('; '), respData);
          } else {
            completeScan(respData);
          }
        } catch (err) {
          console.warn(`[Crosure] Poll #${pollCount} error:`, err.message, 'status:', err.response?.status);
          if (err.response?.status === 404) {
            clearInterval(pollInterval);
            failScan('Scan not found on server');
            return;
          }
          // Other error — keep polling (transient network issue)
        }
      }, 4000);

      // Safety timeout: stop polling after 20 minutes
      setTimeout(() => {
        clearInterval(pollInterval);
        const state = useStore.getState();
        if (state.scanStatus === 'running') {
          console.error('[Crosure] Scan timed out after 20 minutes');
          failScan('Scan timed out after 20 minutes');
        }
      }, 20 * 60 * 1000);

    } catch (err) {
      console.error('[Crosure] Failed to start scan:', err);
      failScan(err.response?.data?.detail || err.message || 'Failed to start scan');
    }
  };

  return (
    <div className="glass border-b border-white/[0.04] p-5">
      <div className="flex items-end gap-3 max-w-5xl">
        {/* URL Input */}
        <div className="flex-1">
          <label className="text-[11px] text-white/30 mb-1.5 block uppercase tracking-wider font-medium">Target URL</label>
          <div className="relative">
            <Globe className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-white/20" />
            <input
              type="url"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="https://target-app.com"
              disabled={scanStatus === 'running'}
              onKeyDown={(e) => e.key === 'Enter' && handleScan()}
              className="w-full metal-input pl-10 pr-4 py-2.5
                         text-white/90 placeholder-white/20 disabled:opacity-40 mono text-sm"
            />
          </div>
        </div>

        {/* Auth Cookie (toggle) */}
        <button
          onClick={() => setShowAdvanced(!showAdvanced)}
          className="key-btn px-3 py-2.5 text-white/30 hover:text-white/60 transition-colors"
          title="Authentication cookie"
        >
          <Cookie className="w-5 h-5" />
        </button>

        {/* Scan Button */}
        <button
          onClick={handleScan}
          disabled={scanStatus === 'running' || !targetUrl.trim()}
          className="btn-primary flex items-center gap-2 px-7 py-2.5 text-sm"
        >
          {scanStatus === 'running' ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : (
            <Play className="w-4 h-4" />
          )}
          {scanStatus === 'running' ? 'Scanning...' : 'Start Scan'}
        </button>
      </div>

      {/* Advanced options */}
      {showAdvanced && (
        <div className="mt-3 max-w-5xl">
          <label className="text-[11px] text-white/30 mb-1.5 block uppercase tracking-wider font-medium">Auth Cookie (optional)</label>
          <input
            type="text"
            value={authCookie}
            onChange={(e) => setAuthCookie(e.target.value)}
            placeholder="session=abc123; token=xyz"
            className="w-full metal-input px-4 py-2 text-white/90 placeholder-white/20 mono text-sm"
          />
        </div>
      )}
    </div>
  );
}
