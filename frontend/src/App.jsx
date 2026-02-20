import { useEffect } from 'react';
import { useStore } from './store';
import { connectWebSocket } from './api';
import Header from './components/Header';
import ScanTab from './components/ScanTab';
import ChainGraphTab from './components/ChainGraphTab';
import KnowledgeBaseTab from './components/KnowledgeBaseTab';
import DashboardTab from './components/DashboardTab';

export default function App() {
  const activeTab = useStore((s) => s.activeTab);
  const updateProgress = useStore((s) => s.updateProgress);

  useEffect(() => {
    console.log('[Crosure] Connecting WebSocket...');
    const ws = connectWebSocket((event) => {
      console.log('[Crosure] WS event:', event.phase, event.message);
      updateProgress(event);
    });
    return () => ws?.close();
  }, []);

  return (
    <div className="h-screen bg-[#0a0a0c] flex flex-col overflow-hidden">
      <Header />
      <main className="flex-1 overflow-hidden relative">
        {activeTab === 'scan' && <ScanTab />}
        {activeTab === 'graph' && <ChainGraphTab />}
        {activeTab === 'kb' && <KnowledgeBaseTab />}
        {activeTab === 'dashboard' && <DashboardTab />}
      </main>
    </div>
  );
}
