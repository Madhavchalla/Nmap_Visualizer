import { useState } from 'react';
import type { NormalizedScan } from './types/nmap';
import { getSampleScans } from './utils/sampleData';
import { exportToCsv, exportToJson } from './utils/exportUtils';
import type { DashboardView } from './components/header/TopHeader';
import { TopHeader } from './components/header/TopHeader';
import { SummaryCards } from './components/overview/SummaryCards';
import { PortBarChart } from './components/overview/PortBarChart';
import { OsDistributionChart } from './components/overview/OsDistributionChart';
import { HostTable } from './components/hosts/HostTable';
import { TopologyGraph } from './components/topology/TopologyGraph';
import { RiskFlagPanel } from './components/risks/RiskFlagPanel';
import { ScanDiffView } from './components/diff/ScanDiffView';
import { RawTerminalView } from './components/raw/RawTerminalView';
import { ReportView } from './components/export/ReportView';
import { FileUploader } from './components/upload/FileUploader';
import { Modal } from './components/common/Modal';

export function App() {
  const [scans, setScans] = useState<NormalizedScan[]>([]);
  const [activeScanId, setActiveScanId] = useState<string | null>(null);
  const [activeView, setActiveView] = useState<DashboardView>('overview');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedPortFilter, setSelectedPortFilter] = useState<number | null>(null);
  const [isUploadModalOpen, setIsUploadModalOpen] = useState(false);

  const activeScan = scans.find((s) => s.id === activeScanId) || scans[0];

  const handleScanLoaded = (newScans: NormalizedScan[]) => {
    setScans((prev) => [...newScans, ...prev]);
    if (newScans.length > 0) {
      setActiveScanId(newScans[0].id);
    }
    setIsUploadModalOpen(false);
  };

  const handleLoadSamples = (sampleIndex?: number) => {
    const samples = getSampleScans();
    if (sampleIndex !== undefined && samples[sampleIndex]) {
      setScans([samples[sampleIndex]]);
      setActiveScanId(samples[sampleIndex].id);
    } else {
      setScans(samples);
      if (samples.length > 0) {
        setActiveScanId(samples[0].id);
      }
    }
    setIsUploadModalOpen(false);
  };

  const handleClearScans = () => {
    setScans([]);
    setActiveScanId(null);
    setActiveView('overview');
    setSearchQuery('');
    setSelectedPortFilter(null);
  };

  const handleSelectPortFromChart = (port: number) => {
    setSelectedPortFilter(port);
    setActiveView('hosts');
  };

  return (
    <div className="min-h-screen bg-[#0a0c10] text-[#cbd5e1] font-sans flex flex-col selection:bg-cyan-500/20 selection:text-cyan-200">
      {/* Top Header */}
      <TopHeader
        scans={scans}
        activeScanId={activeScanId}
        onSelectScan={setActiveScanId}
        activeView={activeView}
        onSelectView={setActiveView}
        searchQuery={searchQuery}
        onSearchChange={setSearchQuery}
        onOpenUpload={() => setIsUploadModalOpen(true)}
        onClearScans={handleClearScans}
        onExportJson={() => activeScan && exportToJson(activeScan)}
        onExportCsv={() => activeScan && exportToCsv(activeScan)}
        onExportPdf={() => setActiveView('report')}
      />

      {/* Main Content */}
      <main className="flex-1 max-w-[1600px] w-full mx-auto px-4 sm:px-6 py-6 transition-all duration-200">
        {!activeScan ? (
          <div className="py-6">
            <FileUploader
              onScanLoaded={handleScanLoaded}
              onLoadSamples={handleLoadSamples}
            />
          </div>
        ) : (
          <div className="space-y-6 animate-in fade-in duration-200">
            {/* VIEW 1: OVERVIEW */}
            {activeView === 'overview' && (
              <div className="space-y-6">
                <SummaryCards scan={activeScan} />
                <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
                  <div className="lg:col-span-2">
                    <PortBarChart scan={activeScan} onSelectPort={handleSelectPortFromChart} />
                  </div>
                  <div>
                    <OsDistributionChart scan={activeScan} />
                  </div>
                </div>
              </div>
            )}

            {/* VIEW 2: HOSTS & PORTS TABLE */}
            {activeView === 'hosts' && (
              <HostTable
                scan={activeScan}
                searchQuery={searchQuery}
                selectedPortFilter={selectedPortFilter}
              />
            )}

            {/* VIEW 3: NETWORK TOPOLOGY D3 GRAPH */}
            {activeView === 'topology' && <TopologyGraph scan={activeScan} />}

            {/* VIEW 4: RISKS & HEURISTIC FINDINGS */}
            {activeView === 'vulnerabilities' && <RiskFlagPanel scan={activeScan} />}

            {/* VIEW 5: DIFF & COMPARE */}
            {activeView === 'diff' && <ScanDiffView scans={scans} />}

            {/* VIEW 6: RAW TERMINAL OUTPUT */}
            {activeView === 'raw' && <RawTerminalView scan={activeScan} />}

            {/* VIEW 7: REPORT & PDF VIEW */}
            {activeView === 'report' && <ReportView scan={activeScan} />}
          </div>
        )}
      </main>

      {/* Import / Upload File Modal */}
      <Modal
        isOpen={isUploadModalOpen}
        onClose={() => setIsUploadModalOpen(false)}
        title="Import Additional Nmap Scan Output"
        width="xl"
      >
        <FileUploader
          onScanLoaded={handleScanLoaded}
          onLoadSamples={handleLoadSamples}
        />
      </Modal>

      {/* Refined Dark Ops Footer */}
      <footer className="border-t border-[#171b26] py-3.5 px-6 text-center text-xs text-slate-500 bg-[#0c0e14] flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <span className="w-2 h-2 rounded-full bg-emerald-500 inline-block animate-pulse"></span>
          <span className="font-sans text-slate-400">Local Browser Ingestion Active</span>
        </div>
        <div className="text-[11px] text-slate-500 font-sans">
          No scan data leaves your machine — 100% Client-Side Evaluation
        </div>
        <div className="text-[11px] font-mono text-slate-500">
          Nmap Visualizer v2.0
        </div>
      </footer>
    </div>
  );
}

export default App;
