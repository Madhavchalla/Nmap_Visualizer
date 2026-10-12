import React from 'react';
import { Filter, X } from 'lucide-react';
import type { RiskSeverity } from '../../types/nmap';

interface HostFilterBarProps {
  selectedStatus: 'all' | 'up' | 'down';
  onStatusChange: (status: 'all' | 'up' | 'down') => void;
  selectedRisk: 'all' | RiskSeverity;
  onRiskChange: (risk: 'all' | RiskSeverity) => void;
  selectedPort: number | null;
  onPortChange: (port: number | null) => void;
  totalResults: number;
  onClearAll: () => void;
}

export const HostFilterBar: React.FC<HostFilterBarProps> = ({
  selectedStatus,
  onStatusChange,
  selectedRisk,
  onRiskChange,
  selectedPort,
  onPortChange,
  totalResults,
  onClearAll
}) => {
  const quickPorts = [21, 22, 80, 443, 445, 3306, 3389, 6379, 27017];
  const hasActiveFilters = selectedStatus !== 'all' || selectedRisk !== 'all' || selectedPort !== null;

  return (
    <div className="bg-[#11141d] border border-[#1e2434] rounded-xl p-3.5 space-y-3 font-sans">
      <div className="flex flex-wrap items-center justify-between gap-3">
        {/* Status Filter */}
        <div className="flex items-center space-x-2">
          <span className="text-xs text-slate-400 font-medium flex items-center space-x-1.5">
            <Filter className="w-3.5 h-3.5 text-cyan-400" />
            <span>Host Status:</span>
          </span>
          <div className="inline-flex rounded-lg bg-[#0e1118] p-0.5 border border-[#1e2434]">
            {(['all', 'up', 'down'] as const).map((st) => (
              <button
                key={st}
                onClick={() => onStatusChange(st)}
                className={`px-2.5 py-1 text-xs font-medium rounded-md transition-colors cursor-pointer capitalize ${
                  selectedStatus === st
                    ? 'bg-cyan-950 text-cyan-300 border border-cyan-800/80 font-semibold shadow-xs'
                    : 'text-slate-400 hover:text-slate-200'
                }`}
              >
                {st === 'all' ? 'All Hosts' : st === 'up' ? 'Online' : 'Offline'}
              </button>
            ))}
          </div>
        </div>

        {/* Risk Level Filter */}
        <div className="flex items-center space-x-2">
          <span className="text-xs text-slate-400 font-medium">Risk Filter:</span>
          <select
            value={selectedRisk}
            onChange={(e) => onRiskChange(e.target.value as any)}
            className="bg-[#0e1118] border border-[#1e2434] text-slate-200 text-xs font-sans rounded-lg px-2.5 py-1 focus:outline-none focus:border-cyan-500 cursor-pointer"
          >
            <option value="all">All Severity Levels</option>
            <option value="critical">Critical Severity</option>
            <option value="high">High Severity</option>
            <option value="medium">Medium Severity</option>
            <option value="low">Low Severity</option>
            <option value="info">Informational</option>
          </select>
        </div>

        {/* Total Count */}
        <div className="text-xs text-slate-400 font-sans">
          Showing <span className="text-slate-100 font-semibold">{totalResults}</span> host(s)
        </div>

        {/* Clear Filters */}
        {hasActiveFilters && (
          <button
            onClick={onClearAll}
            className="text-xs text-rose-400 hover:text-rose-300 font-medium flex items-center space-x-1 transition-colors cursor-pointer"
          >
            <X className="w-3.5 h-3.5" />
            <span>Reset Filters</span>
          </button>
        )}
      </div>

      {/* Quick Port Pills */}
      <div className="flex flex-wrap items-center space-x-1.5 pt-2 border-t border-[#181d2a]">
        <span className="text-[11px] text-slate-400 font-medium mr-1">Quick Port Filter:</span>
        {quickPorts.map((pt) => {
          const isSelected = selectedPort === pt;
          return (
            <button
              key={pt}
              onClick={() => onPortChange(isSelected ? null : pt)}
              className={`px-2 py-0.5 text-[11px] font-mono rounded-md transition-colors cursor-pointer ${
                isSelected
                  ? 'bg-cyan-500 text-slate-950 font-bold shadow-xs'
                  : 'bg-[#151924] text-slate-300 hover:bg-[#1e2434] border border-[#232a3c]'
              }`}
            >
              :{pt}
            </button>
          );
        })}
      </div>
    </div>
  );
};
