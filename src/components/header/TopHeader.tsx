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
  UploadCloud,
  Layers,
  Cloud,
  SplitSquareVertical
} from 'lucide-react';
import type { NormalizedScan } from '../../types/nmap';
import { Badge } from '../common/Badge';

export type DashboardView = 'overview' | 'hosts' | 'topology' | 'vulnerabilities' | 'raw' | 'report';
export type PageWorkspace = 'custom' | 'enterprise-xml' | 'cloud-normal' | 'diff-compare';

interface TopHeaderProps {
  activePage: PageWorkspace;
  onSelectPage: (page: PageWorkspace) => void;
  activeScan: NormalizedScan | null;
  activeView: DashboardView;
  onSelectView: (view: DashboardView) => void;
  searchQuery: string;
  onSearchChange: (q: string) => void;
  onOpenUpload: () => void;
  onExportJson: () => void;
  onExportCsv: () => void;
  onExportPdf: () => void;
  hasCustomScan: boolean;
}

export const TopHeader: React.FC<TopHeaderProps> = ({
  activePage,
  onSelectPage,
  activeScan,
  activeView,
  onSelectView,
  searchQuery,
  onSearchChange,
  onOpenUpload,
  onExportJson,
  onExportCsv,
  onExportPdf,
  hasCustomScan
}) => {
  const [showExportMenu, setShowExportMenu] = React.useState(false);

  const mainPages: Array<{ id: PageWorkspace; label: string; badge?: string; icon: React.ReactNode }> = [
    { 
      id: 'custom', 
      label: hasCustomScan ? 'Custom Scan' : 'Upload Scan', 
      badge: hasCustomScan ? 'ACTIVE' : undefined,
      icon: <UploadCloud className="w-4 h-4" /> 
    },
    { 
      id: 'enterprise-xml', 
      label: 'Enterprise Audit', 
      badge: 'XML (-oX)',
      icon: <Layers className="w-4 h-4" /> 
    },
    { 
      id: 'cloud-normal', 
      label: 'Cloud Perimeter', 
      badge: 'Normal (-oN)',
      icon: <Cloud className="w-4 h-4" /> 
    },
    { 
      id: 'diff-compare', 
      label: 'Multi-Scan Diff', 
      badge: 'Delta',
      icon: <SplitSquareVertical className="w-4 h-4" /> 
    }
  ];

  const subNavItems: Array<{ id: DashboardView; label: string; icon: React.ReactNode; count?: number }> = [
    { id: 'overview', label: 'Overview', icon: <BarChart3 className="w-3.5 h-3.5" /> },
    { id: 'hosts', label: 'Hosts & Ports', icon: <Server className="w-3.5 h-3.5" />, count: activeScan?.hosts.length },
    { id: 'topology', label: 'Topology Graph', icon: <GitFork className="w-3.5 h-3.5" /> },
    { 
      id: 'vulnerabilities', 
      label: 'Risks & Heuristics', 
      icon: <AlertTriangle className="w-3.5 h-3.5" />, 
      count: activeScan?.hosts.reduce((acc, h) => acc + h.riskFlags.length, 0) 
    },
    { id: 'raw', label: 'Raw Output', icon: <FileText className="w-3.5 h-3.5" /> },
    { id: 'report', label: 'Report PDF', icon: <Printer className="w-3.5 h-3.5" /> }
  ];

  return (
    <header className="bg-[#0e1118] border-b border-[#1b202e] sticky top-0 z-40 shadow-xl backdrop-blur-xs">
      {/* Upper Navigation Bar */}
      <div className="max-w-[1600px] mx-auto px-4 sm:px-6 py-2.5 flex flex-wrap items-center justify-between gap-4">
        {/* Brand Logo */}
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

        {/* Dedicated Pages Selector (3 Files / Pages + Custom Upload) */}
        <div className="flex items-center bg-[#131722] border border-[#202738] rounded-xl p-1 gap-1">
          {mainPages.map((pg) => {
            const isCurrent = activePage === pg.id;
            return (
              <button
                key={pg.id}
                onClick={() => onSelectPage(pg.id)}
                className={`px-3 py-1.5 rounded-lg text-xs font-sans font-medium flex items-center space-x-2 transition-all cursor-pointer ${
                  isCurrent
                    ? 'bg-cyan-950 text-cyan-300 border border-cyan-700/80 shadow-xs font-semibold'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-[#1a202e]'
                }`}
              >
                <span className={isCurrent ? 'text-cyan-400' : 'text-slate-500'}>{pg.icon}</span>
                <span>{pg.label}</span>
                {pg.badge && (
                  <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded ${
                    isCurrent ? 'bg-cyan-900/80 text-cyan-200' : 'bg-[#1b212f] text-slate-400'
                  }`}>
                    {pg.badge}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {/* Right Actions: Search + Export / Add */}
        <div className="flex items-center space-x-2 shrink-0">
          {activeScan && activePage !== 'diff-compare' && (
            <div className="relative max-w-xs hidden xl:block">
              <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-slate-400" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => onSearchChange(e.target.value)}
                placeholder="Search IP, host, port..."
                className="w-48 bg-[#131722] border border-[#202738] focus:border-cyan-500 rounded-lg pl-8 pr-2.5 py-1.5 text-xs text-slate-200 placeholder-slate-500 font-sans focus:outline-none transition-colors"
              />
            </div>
          )}

          {activePage === 'custom' && (
            <button
              onClick={onOpenUpload}
              className="px-2.5 py-1.5 bg-[#171c28] hover:bg-[#202636] border border-[#273044] text-slate-200 rounded-lg text-xs font-sans font-medium flex items-center space-x-1.5 transition-colors cursor-pointer"
            >
              <PlusCircle className="w-3.5 h-3.5 text-cyan-400" />
              <span>{hasCustomScan ? 'Replace File' : 'Upload File'}</span>
            </button>
          )}

          {activeScan && (
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
                    className="w-full text-left px-3 py-2 text-slate-300 hover:bg-[#1a2130] hover:text-slate-100 flex items-center justify-between cursor-pointer"
                  >
                    <span>Export JSON</span>
                    <span className="font-mono text-[10px] text-slate-500">.json</span>
                  </button>
                  <button
                    onClick={onExportCsv}
                    className="w-full text-left px-3 py-2 text-slate-300 hover:bg-[#1a2130] hover:text-slate-100 flex items-center justify-between cursor-pointer"
                  >
                    <span>Export CSV</span>
                    <span className="font-mono text-[10px] text-slate-500">.csv</span>
                  </button>
                  <button
                    onClick={onExportPdf}
                    className="w-full text-left px-3 py-2 text-slate-300 hover:bg-[#1a2130] hover:text-slate-100 flex items-center justify-between border-t border-[#1e2536] cursor-pointer"
                  >
                    <span>PDF Audit Report</span>
                    <span className="font-mono text-[10px] text-cyan-400 font-semibold">.pdf</span>
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Sub-view Navigation Bar (for current active page dashboard) */}
      {activeScan && activePage !== 'diff-compare' && (
        <div className="bg-[#0a0c12] border-t border-[#181d2a] px-4 sm:px-6 overflow-x-auto no-scrollbar">
          <div className="max-w-[1600px] mx-auto flex items-center justify-between">
            <div className="flex items-center space-x-1">
              {subNavItems.map((item) => {
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

            {/* Target File Info Chip */}
            <div className="hidden md:flex items-center space-x-2 text-xs font-mono text-slate-400 py-1">
              <span>File:</span>
              <span className="text-slate-200 font-semibold">{activeScan.meta.filename}</span>
              <Badge variant="format">{activeScan.meta.format.toUpperCase()}</Badge>
            </div>
          </div>
        </div>
      )}
    </header>
  );
};
