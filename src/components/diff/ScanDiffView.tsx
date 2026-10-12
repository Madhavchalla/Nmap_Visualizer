import React, { useState } from 'react';
import { GitFork, PlusCircle, MinusCircle, AlertCircle } from 'lucide-react';
import type { NormalizedScan } from '../../types/nmap';
import { compareScans } from '../../utils/diffEngine';
import { Badge } from '../common/Badge';
import { Card } from '../common/Card';

interface ScanDiffViewProps {
  scans: NormalizedScan[];
}

export const ScanDiffView: React.FC<ScanDiffViewProps> = ({ scans }) => {
  const [scanAId, setScanAId] = useState<string>(scans[0]?.id || '');
  const [scanBId, setScanBId] = useState<string>(scans[1]?.id || scans[0]?.id || '');

  if (scans.length < 2) {
    return (
      <Card title="Scan Comparison & Delta Diff Tool" icon={<GitFork className="w-4 h-4 text-cyan-400" />}>
        <div className="p-8 text-center space-y-3 font-mono">
          <AlertCircle className="w-8 h-8 text-amber-400 mx-auto" />
          <h4 className="text-sm font-bold text-slate-200">Requires At Least 2 Scans to Compare</h4>
          <p className="text-xs text-slate-400 max-w-md mx-auto font-sans">
            Import an additional scan file (e.g. a follow-up scan of the same network or target) to analyze newly opened ports, closed ports, host status changes, and version deltas side-by-side.
          </p>
        </div>
      </Card>
    );
  }

  const scanA = scans.find((s) => s.id === scanAId) || scans[0];
  const scanB = scans.find((s) => s.id === scanBId) || scans[1];

  const diff = compareScans(scanA, scanB);

  return (
    <div className="space-y-6">
      {/* Scan Selector Header Bar */}
      <Card title="Select Target Scans to Compare" icon={<GitFork className="w-4 h-4 text-cyan-400" />}>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 font-mono text-xs">
          <div className="bg-[#0f121a] p-3 rounded-lg border border-[#202636] space-y-1.5">
            <span className="text-slate-400 font-bold block">BASE SCAN (Scan A):</span>
            <select
              value={scanAId}
              onChange={(e) => setScanAId(e.target.value)}
              className="w-full bg-[#13161f] border border-[#202636] text-slate-200 text-xs rounded p-2 font-mono cursor-pointer focus:outline-none focus:border-cyan-500"
            >
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.meta.filename} ({s.meta.totalHosts} hosts, {s.meta.startTime.slice(0, 10)})
                </option>
              ))}
            </select>
          </div>

          <div className="bg-[#0f121a] p-3 rounded-lg border border-[#202636] space-y-1.5">
            <span className="text-slate-400 font-bold block">COMPARISON SCAN (Scan B):</span>
            <select
              value={scanBId}
              onChange={(e) => setScanBId(e.target.value)}
              className="w-full bg-[#13161f] border border-[#202636] text-slate-200 text-xs rounded p-2 font-mono cursor-pointer focus:outline-none focus:border-cyan-500"
            >
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  {s.meta.filename} ({s.meta.totalHosts} hosts, {s.meta.startTime.slice(0, 10)})
                </option>
              ))}
            </select>
          </div>
        </div>
      </Card>

      {/* Delta KPI Summary */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 font-mono">
        <Card className="border-l-4 border-l-emerald-500">
          <div className="text-[11px] text-slate-400">NEWLY OPENED PORTS</div>
          <div className="text-xl font-bold text-emerald-400 mt-1">+{diff.newlyOpenedPortsCount}</div>
        </Card>
        <Card className="border-l-4 border-l-rose-500">
          <div className="text-[11px] text-slate-400">CLOSED PORTS</div>
          <div className="text-xl font-bold text-rose-400 mt-1">-{diff.newlyClosedPortsCount}</div>
        </Card>
        <Card className="border-l-4 border-l-cyan-500">
          <div className="text-[11px] text-slate-400">ADDED HOSTS</div>
          <div className="text-xl font-bold text-cyan-400 mt-1">+{diff.addedHostsCount}</div>
        </Card>
        <Card className="border-l-4 border-l-amber-500">
          <div className="text-[11px] text-slate-400">REMOVED HOSTS</div>
          <div className="text-xl font-bold text-amber-400 mt-1">-{diff.removedHostsCount}</div>
        </Card>
      </div>

      {/* Host-by-Host Diff List */}
      <Card title="Host-Level Network Delta Breakdown">
        <div className="space-y-4">
          {diff.hostDiffs.map((hd, i) => (
            <div key={i} className="bg-[#0f121a] border border-[#202636] rounded-lg p-4 font-mono text-xs space-y-3">
              <div className="flex items-center justify-between border-b border-[#1c2230] pb-2">
                <div className="flex items-center space-x-2">
                  <span className="font-bold text-slate-100 text-sm">{hd.ip}</span>
                  {hd.hostname && <span className="text-cyan-400">({hd.hostname})</span>}
                  <Badge
                    variant={
                      hd.type === 'added'
                        ? 'up'
                        : hd.type === 'removed'
                        ? 'closed'
                        : hd.type === 'modified'
                        ? 'filtered'
                        : 'neutral'
                    }
                  >
                    {hd.type.toUpperCase()}
                  </Badge>
                </div>

                <div className="text-slate-400">
                  Risk Delta:{' '}
                  <span className={`font-bold ${hd.riskDelta > 0 ? 'text-rose-400' : 'text-emerald-400'}`}>
                    {hd.riskDelta > 0 ? `+${hd.riskDelta}` : hd.riskDelta}
                  </span>
                </div>
              </div>

              {/* Newly Opened Ports */}
              {hd.openedPorts.length > 0 && (
                <div className="bg-emerald-950/30 border border-emerald-900/50 p-2.5 rounded text-emerald-300">
                  <div className="font-bold text-xs flex items-center space-x-1.5 mb-1">
                    <PlusCircle className="w-3.5 h-3.5 text-emerald-400" />
                    <span>Newly Opened Ports ({hd.openedPorts.length}):</span>
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {hd.openedPorts.map((p, idx) => (
                      <span key={idx} className="bg-emerald-950 px-2 py-0.5 rounded text-[11px] font-bold">
                        :{p.port}/{p.protocol} ({p.service || 'unknown'})
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Closed Ports */}
              {hd.closedPorts.length > 0 && (
                <div className="bg-rose-950/30 border border-rose-900/50 p-2.5 rounded text-rose-300">
                  <div className="font-bold text-xs flex items-center space-x-1.5 mb-1">
                    <MinusCircle className="w-3.5 h-3.5 text-rose-400" />
                    <span>Ports Closed Since Base Scan ({hd.closedPorts.length}):</span>
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {hd.closedPorts.map((p, idx) => (
                      <span key={idx} className="bg-rose-950 px-2 py-0.5 rounded text-[11px] font-bold">
                        :{p.port}/{p.protocol} ({p.service || 'unknown'})
                      </span>
                    ))}
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
};
