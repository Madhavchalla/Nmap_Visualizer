import { useState, useMemo } from 'react';
import type { NormalizedScan } from './types/nmap';
import { getSampleScans } from './utils/sampleData';
import { exportToCsv, exportToJson } from './utils/exportUtils';
import type { DashboardView, PageWorkspace } from './components/header/TopHeader';
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
  const [activePage, setActivePage] = useState<PageWorkspace>('custom');
  const [customScans, setCustomScans] = useState<NormalizedScan[]>([]);
  const [activeCustomScanId, setActiveCustomScanId] = useState<string | null>(null);

  const [activeView, setActiveView] = useState<DashboardView>('overview');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedPortFilter, setSelectedPortFilter] = useState<number | null>(null);
  const [isUploadModalOpen, setIsUploadModalOpen] = useState(false);

  // Lazy-load sample datasets on demand
  const sampleScans = useMemo(() => getSampleScans(), []);

  // Determine active scan based on currently selected page
  const activeScan: NormalizedScan | null = useMemo(() => {
    if (activePage === 'enterprise-xml') {
      return sampleScans[0] || null;
    }
    if (activePage === 'cloud-normal') {
      return sampleScans[1] || null;
    }
    if (activePage === 'diff-compare') {
      return sampleScans[0] || null; // Base scan for diff view
    }
    // 'custom' page:
    if (customScans.length > 0) {
      return customScans.find((s) => s.id === activeCustomScanId) || customScans[0];
    }
    return null;
  }, [activePage, sampleScans, customScans, activeCustomScanId]);

  const handleCustomScanLoaded = (newScans: NormalizedScan[]) => {
    setCustomScans((prev) => [...newScans, ...prev]);
    if (newScans.length > 0) {
      setActiveCustomScanId(newScans[0].id);
    }
    setActivePage('custom');
    setActiveView('overview');
    setIsUploadModalOpen(false);
  };

  const handleSelectPortFromChart = (port: number) => {
    setSelectedPortFilter(port);
    setActiveView('hosts');
  };

  return (
    <div className="min-h-screen bg-[#0a0c10] text-[#cbd5e1] font-sans flex flex-col selection:bg-cyan-500/20 selection:text-cyan-200">
      {/* Top Header with 4 Dedicated Page Tabs */}
      <TopHeader
        activePage={activePage}
        onSelectPage={(page) => {
          setActivePage(page);
          setActiveView('overview');
          setSelectedPortFilter(null);
          setSearchQuery('');
        }}
        activeScan={activeScan}
        activeView={activeView}
        onSelectView={setActiveView}
        searchQuery={searchQuery}
        onSearchChange={setSearchQuery}
        onOpenUpload={() => setIsUploadModalOpen(true)}
        onExportJson={() => activeScan && exportToJson(activeScan)}
        onExportCsv={() => activeScan && exportToCsv(activeScan)}
        onExportPdf={() => setActiveView('report')}
        hasCustomScan={customScans.length > 0}
      />

      {/* Main Page Workspace */}
      <main className="flex-1 max-w-[1600px] w-full mx-auto px-4 sm:px-6 py-6 transition-all duration-200">
        {/* PAGE 1: CUSTOM SCAN UPLOAD / WORKSPACE */}
        {activePage === 'custom' && (
          <div>
            {!activeScan ? (
              <div className="py-6 animate-in fade-in duration-200">
                <FileUploader
                  onScanLoaded={handleCustomScanLoaded}
                  onLoadSamples={(idx) => {
                    if (idx === 1) setActivePage('cloud-normal');
                    else setActivePage('enterprise-xml');
                  }}
                />
              </div>
            ) : (
              <div className="space-y-6 animate-in fade-in duration-200">
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
                {activeView === 'hosts' && (
                  <HostTable scan={activeScan} searchQuery={searchQuery} selectedPortFilter={selectedPortFilter} />
                )}
                {activeView === 'topology' && <TopologyGraph scan={activeScan} />}
                {activeView === 'vulnerabilities' && <RiskFlagPanel scan={activeScan} />}
                {activeView === 'raw' && <RawTerminalView scan={activeScan} />}
                {activeView === 'report' && <ReportView scan={activeScan} />}
              </div>
            )}
          </div>
        )}

        {/* PAGE 2: ENTERPRISE CORPORATE AUDIT (XML -oX) */}
        {activePage === 'enterprise-xml' && activeScan && (
          <div className="space-y-6 animate-in fade-in duration-200">
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
            {activeView === 'hosts' && (
              <HostTable scan={activeScan} searchQuery={searchQuery} selectedPortFilter={selectedPortFilter} />
            )}
            {activeView === 'topology' && <TopologyGraph scan={activeScan} />}
            {activeView === 'vulnerabilities' && <RiskFlagPanel scan={activeScan} />}
            {activeView === 'raw' && <RawTerminalView scan={activeScan} />}
            {activeView === 'report' && <ReportView scan={activeScan} />}
          </div>
        )}

        {/* PAGE 3: CLOUD PERIMETER RECON (NORMAL -oN) */}
        {activePage === 'cloud-normal' && activeScan && (
          <div className="space-y-6 animate-in fade-in duration-200">
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
            {activeView === 'hosts' && (
              <HostTable scan={activeScan} searchQuery={searchQuery} selectedPortFilter={selectedPortFilter} />
            )}
            {activeView === 'topology' && <TopologyGraph scan={activeScan} />}
            {activeView === 'vulnerabilities' && <RiskFlagPanel scan={activeScan} />}
            {activeView === 'raw' && <RawTerminalView scan={activeScan} />}
            {activeView === 'report' && <ReportView scan={activeScan} />}
          </div>
        )}

        {/* PAGE 4: MULTI-SCAN DELTA & DIFF COMPARISON */}
        {activePage === 'diff-compare' && (
          <div className="animate-in fade-in duration-200">
            <ScanDiffView scans={sampleScans} />
          </div>
        )}
      </main>

      {/* Upload File Modal */}
      <Modal
        isOpen={isUploadModalOpen}
        onClose={() => setIsUploadModalOpen(false)}
        title="Upload Nmap Scan File"
        width="xl"
      >
        <FileUploader
          onScanLoaded={handleCustomScanLoaded}
          onLoadSamples={(idx) => {
            if (idx === 1) setActivePage('cloud-normal');
            else setActivePage('enterprise-xml');
            setIsUploadModalOpen(false);
          }}
        />
      </Modal>

      {/* Refined Footer */}
      <footer className="border-t border-[#171b26] py-3.5 px-6 text-center text-xs text-slate-500 bg-[#0c0e14] flex items-center justify-between">
        <div className="flex items-center space-x-2">
          <span className="w-2 h-2 rounded-full bg-emerald-500 inline-block"></span>
          <span className="font-sans text-slate-400">100% Client-Side Ingestion — Zero Network Calls</span>
        </div>
        <div className="text-[11px] font-mono text-slate-500">
          Nmap Scan Visualizer v2.0
        </div>
      </footer>
    </div>
  );
}

export default App;
