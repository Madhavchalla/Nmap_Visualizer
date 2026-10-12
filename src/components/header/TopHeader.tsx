import React from 'react';
import { 
  ShieldAlert, 
  BarChart3, 
  Server, 
  GitFork, 
  AlertTriangle, 
  FileText, 
  Download, 
  PlusCircle, 
  Search, 
  Printer,
  ChevronDown,
  XCircle
} from 'lucide-react';
import type { NormalizedScan } from '../../types/nmap';
import { Badge } from '../common/Badge';

export type DashboardView = 'overview' | 'hosts' | 'topology' | 'vulnerabilities' | 'diff' | 'raw' | 'report';

interface TopHeaderProps {
  scans: NormalizedScan[];
  activeScanId: string | null;
  onSelectScan: (scanId: string) => void;
  activeView: DashboardView;
  onSelectView: (view: DashboardView) => void;
  searchQuery: string;
  onSearchChange: (q: string) => void;
  onOpenUpload: () => void;
  onClearScans: () => void;
  onExportJson: () => void;
  onExportCsv: () => void;
  onExportPdf: () => void;
}

export const TopHeader: React.FC<TopHeaderProps> = ({
  scans,
  activeScanId,
  onSelectScan,
  activeView,
  onSelectView,
  searchQuery,
  onSearchChange,
  onOpenUpload,
  onClearScans,
  onExportJson,
  onExportCsv,
  onExportPdf
}) => {
  const activeScan = scans.find(s => s.id === activeScanId) || scans[0];
  const [showExportMenu, setShowExportMenu] = React.useState(false);

  const navItems: Array<{ id: DashboardView; label: string; icon: React.ReactNode; count?: number }> = [
    { id: 'overview', label: 'Overview', icon: <BarChart3 className="w-3.5 h-3.5" /> },
    { id: 'hosts', label: 'Hosts & Ports', icon: <Server className="w-3.5 h-3.5" />, count: activeScan?.hosts.length },
    { id: 'topology', label: 'Topology Graph', icon: <GitFork className="w-3.5 h-3.5" /> },
    { 
      id: 'vulnerabilities', 
      label: 'Risks & Heuristics', 
      icon: <AlertTriangle className="w-3.5 h-3.5" />, 
      count: activeScan?.hosts.reduce((acc, h) => acc + h.riskFlags.length, 0) 
    },
    { id: 'diff', label: 'Diff & Compare', icon: <GitFork className="w-3.5 h-3.5 rotate-90" /> },
    { id: 'raw', label: 'Raw Output', icon: <FileText className="w-3.5 h-3.5" /> },
    { id: 'report', label: 'Report PDF', icon: <Printer className="w-3.5 h-3.5" /> }
  ];

  return (
    <header className="bg-[#0e1118] border-b border-[#1b202e] sticky top-0 z-40 shadow-xl backdrop-blur-xs">
      {/* Upper Bar */}
      <div className="max-w-[1600px] mx-auto px-4 sm:px-6 py-2.5 flex items-center justify-between gap-4">
        {/* Logo & Brand */}
        <div className="flex items-center space-x-3 shrink-0">
          <div className="w-8 h-8 rounded-lg bg-cyan-950/80 border border-cyan-800/80 flex items-center justify-center text-cyan-400 shadow-inner">
            <ShieldAlert className="w-4.5 h-4.5" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-sans font-bold text-sm text-slate-100 tracking-tight">NMAP VISUALIZER</span>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-cyan-950/90 text-cyan-300 border border-cyan-800/70 font-semibold">
                v2.0
              </span>
            </div>
            <p className="text-[11px] text-slate-400 font-sans">Network Reconnaissance & Audit Dashboard</p>
          </div>
        </div>

        {/* Scan Selector (Only if scans are loaded) */}
        {scans.length > 0 && (
          <div className="flex items-center space-x-2 bg-[#131722] border border-[#202738] rounded-lg px-2.5 py-1 max-w-sm truncate">
            <span className="text-xs text-slate-400 font-sans hidden sm:inline shrink-0">Target:</span>
            <select
              value={activeScanId || ''}
              onChange={(e) => onSelectScan(e.target.value)}
              className="bg-transparent text-slate-200 text-xs font-mono font-medium focus:outline-none cursor-pointer truncate max-w-[220px]"
            >
              {scans.map((s) => (
                <option key={s.id} value={s.id} className="bg-[#131722] text-slate-200 font-mono">
                  {s.meta.filename} ({s.meta.totalHosts} hosts)
                </option>
              ))}
            </select>
            {activeScan && <Badge variant="format">{activeScan.meta.format.toUpperCase()}</Badge>}
          </div>
        )}

        {/* Global Search Bar (Only if scans loaded) */}
        {scans.length > 0 && (
          <div className="relative flex-1 max-w-xs hidden lg:block">
            <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => onSearchChange(e.target.value)}
              placeholder="Search IP, host, port, service..."
              className="w-full bg-[#131722] border border-[#202738] focus:border-cyan-500 rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 font-sans focus:outline-none transition-colors"
            />
          </div>
        )}

        {/* Actions */}
        <div className="flex items-center space-x-2 shrink-0">
          {scans.length > 0 ? (
            <>
              <button
                onClick={onOpenUpload}
                className="px-2.5 py-1.5 bg-[#171c28] hover:bg-[#202636] border border-[#273044] text-slate-200 rounded-lg text-xs font-sans font-medium flex items-center space-x-1.5 transition-colors cursor-pointer"
                title="Upload another Nmap scan file"
              >
                <PlusCircle className="w-3.5 h-3.5 text-cyan-400" />
                <span className="hidden sm:inline">Add Scan</span>
              </button>

              <button
                onClick={onClearScans}
                className="px-2.5 py-1.5 bg-[#171c28] hover:bg-rose-950/40 border border-[#273044] hover:border-rose-800 text-slate-400 hover:text-rose-300 rounded-lg text-xs font-sans font-medium flex items-center space-x-1 transition-colors cursor-pointer"
                title="Unload current scan files and return to upload screen"
              >
                <XCircle className="w-3.5 h-3.5" />
                <span className="hidden md:inline">Reset</span>
              </button>

              {/* Export Dropdown */}
              <div className="relative">
                <button
                  onClick={() => setShowExportMenu(!showExportMenu)}
                  className="px-3 py-1.5 bg-cyan-950/80 hover:bg-cyan-900/80 border border-cyan-800/80 text-cyan-300 rounded-lg text-xs font-sans font-semibold flex items-center space-x-1.5 transition-colors cursor-pointer"
                >
                  <Download className="w-3.5 h-3.5" />
                  <span>Export</span>
                  <ChevronDown className="w-3 h-3" />
                </button>

                {showExportMenu && (
                  <div
                    className="absolute right-0 mt-1.5 w-44 bg-[#131722] border border-[#22293b] rounded-lg shadow-2xl py-1 z-50 text-xs font-sans"
                    onClick={() => setShowExportMenu(false)}
                  >
                    <button
                      onClick={onExportJson}
                      className="w-full text-left px-3 py-2 text-slate-300 hover:bg-[#1a2130] hover:text-slate-100 flex items-center justify-between"
                    >
                      <span>Export JSON</span>
                      <span className="font-mono text-[10px] text-slate-500">.json</span>
                    </button>
                    <button
                      onClick={onExportCsv}
                      className="w-full text-left px-3 py-2 text-slate-300 hover:bg-[#1a2130] hover:text-slate-100 flex items-center justify-between"
                    >
                      <span>Export CSV</span>
                      <span className="font-mono text-[10px] text-slate-500">.csv</span>
                    </button>
                    <button
                      onClick={onExportPdf}
                      className="w-full text-left px-3 py-2 text-slate-300 hover:bg-[#1a2130] hover:text-slate-100 flex items-center justify-between border-t border-[#1e2536]"
                    >
                      <span>PDF Audit Report</span>
                      <span className="font-mono text-[10px] text-cyan-400 font-semibold">.pdf</span>
                    </button>
                  </div>
                )}
              </div>
            </>
          ) : (
            <button
              onClick={onOpenUpload}
              className="px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 text-slate-950 font-sans font-semibold text-xs rounded-lg flex items-center space-x-1.5 transition-colors cursor-pointer shadow-md"
            >
              <PlusCircle className="w-3.5 h-3.5" />
              <span>Import Scan File</span>
            </button>
          )}
        </div>
      </div>

      {/* Navigation Tabs Bar (Only when scans loaded) */}
      {scans.length > 0 && (
        <div className="bg-[#0a0c12] border-t border-[#181d2a] px-4 sm:px-6 overflow-x-auto no-scrollbar">
          <div className="max-w-[1600px] mx-auto flex items-center space-x-1">
            {navItems.map((item) => {
              const isActive = activeView === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => onSelectView(item.id)}
                  className={`px-3 py-2 text-xs font-sans flex items-center space-x-2 border-b-2 transition-all cursor-pointer whitespace-nowrap ${
                    isActive
                      ? 'border-cyan-400 text-cyan-300 bg-cyan-950/25 font-semibold'
                      : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-[#131622] font-medium'
                  }`}
                >
                  <span className={isActive ? 'text-cyan-400' : 'text-slate-500'}>{item.icon}</span>
                  <span>{item.label}</span>
                  {item.count !== undefined && (
                    <span
                      className={`ml-1 text-[10px] px-1.5 py-0.2 rounded-full font-mono ${
                        isActive ? 'bg-cyan-900/80 text-cyan-200 font-semibold' : 'bg-[#181e2b] text-slate-400'
                      }`}
                    >
                      {item.count}
                    </span>
                  )}
                </button>
              );
            })}
          </div>
        </div>
      )}
    </header>
  );
};
