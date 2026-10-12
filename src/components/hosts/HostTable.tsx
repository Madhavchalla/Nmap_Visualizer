import React, { useState, useMemo } from 'react';
import { ArrowUpDown, Eye, ChevronLeft, ChevronRight } from 'lucide-react';
import type { HostInfo, NormalizedScan, RiskSeverity } from '../../types/nmap';
import { Badge } from '../common/Badge';
import { Card } from '../common/Card';
import { HostFilterBar } from './HostFilterBar';
import { HostDetailDrawer } from './HostDetailDrawer';

interface HostTableProps {
  scan: NormalizedScan;
  searchQuery: string;
  selectedPortFilter?: number | null;
}

type SortField = 'ip' | 'hostname' | 'portsCount' | 'riskScore';
type SortOrder = 'asc' | 'desc';

export const HostTable: React.FC<HostTableProps> = ({ scan, searchQuery, selectedPortFilter }) => {
  const [selectedStatus, setSelectedStatus] = useState<'all' | 'up' | 'down'>('all');
  const [selectedRisk, setSelectedRisk] = useState<'all' | RiskSeverity>('all');
  const [selectedPort, setSelectedPort] = useState<number | null>(selectedPortFilter || null);
  const [sortField, setSortField] = useState<SortField>('riskScore');
  const [sortOrder, setSortOrder] = useState<SortOrder>('desc');
  const [selectedHost, setSelectedHost] = useState<HostInfo | null>(null);

  // Pagination
  const [currentPage, setCurrentPage] = useState(1);
  const pageSize = 15;

  React.useEffect(() => {
    if (selectedPortFilter !== undefined) {
      setSelectedPort(selectedPortFilter);
    }
  }, [selectedPortFilter]);

  const filteredHosts = useMemo(() => {
    return scan.hosts.filter((h) => {
      // 1. Status Filter
      if (selectedStatus !== 'all' && h.status !== selectedStatus) return false;

      // 2. Risk Level Filter
      if (selectedRisk !== 'all') {
        const hasRisk = h.riskFlags.some((f) => f.severity === selectedRisk);
        if (!hasRisk) return false;
      }

      // 3. Port Filter
      if (selectedPort !== null) {
        const hasPort = h.ports.some((p) => p.port === selectedPort && p.state === 'open');
        if (!hasPort) return false;
      }

      // 4. Search Query
      if (searchQuery.trim().length > 0) {
        const q = searchQuery.toLowerCase().trim();
        const matchesIp = h.ip.toLowerCase().includes(q);
        const matchesHost = h.hostname?.toLowerCase().includes(q) || false;
        const matchesOs = h.os.name?.toLowerCase().includes(q) || false;
        const matchesPort = h.ports.some(
          (p) => p.port.toString().includes(q) || p.service.toLowerCase().includes(q) || (p.product && p.product.toLowerCase().includes(q))
        );
        return matchesIp || matchesHost || matchesOs || matchesPort;
      }

      return true;
    });
  }, [scan.hosts, selectedStatus, selectedRisk, selectedPort, searchQuery]);

  const sortedHosts = useMemo(() => {
    return [...filteredHosts].sort((a, b) => {
      let valA: any = a[sortField as keyof HostInfo];
      let valB: any = b[sortField as keyof HostInfo];

      if (sortField === 'portsCount') {
        valA = a.ports.filter((p) => p.state === 'open').length;
        valB = b.ports.filter((p) => p.state === 'open').length;
      }

      if (valA < valB) return sortOrder === 'asc' ? -1 : 1;
      if (valA > valB) return sortOrder === 'asc' ? 1 : -1;
      return 0;
    });
  }, [filteredHosts, sortField, sortOrder]);

  const totalPages = Math.ceil(sortedHosts.length / pageSize) || 1;
  const paginatedHosts = sortedHosts.slice((currentPage - 1) * pageSize, currentPage * pageSize);

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc');
    } else {
      setSortField(field);
      setSortOrder('desc');
    }
  };

  return (
    <div className="space-y-4">
      {/* Filter Bar */}
      <HostFilterBar
        selectedStatus={selectedStatus}
        onStatusChange={(st) => {
          setSelectedStatus(st);
          setCurrentPage(1);
        }}
        selectedRisk={selectedRisk}
        onRiskChange={(r) => {
          setSelectedRisk(r);
          setCurrentPage(1);
        }}
        selectedPort={selectedPort}
        onPortChange={(pt) => {
          setSelectedPort(pt);
          setCurrentPage(1);
        }}
        totalResults={filteredHosts.length}
        onClearAll={() => {
          setSelectedStatus('all');
          setSelectedRisk('all');
          setSelectedPort(null);
          setCurrentPage(1);
        }}
      />

      {/* Main Host Data Table */}
      <Card bodyClassName="p-0" className="bg-[#11141d] border-[#1e2434]">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border-collapse">
            <thead className="bg-[#0e1118] text-slate-400 border-b border-[#1e2434] font-sans">
              <tr>
                <th className="p-3.5 cursor-pointer hover:text-slate-200" onClick={() => handleSort('ip')}>
                  <div className="flex items-center space-x-1 font-medium">
                    <span>IP ADDRESS / HOSTNAME</span>
                    <ArrowUpDown className="w-3 h-3 text-slate-500" />
                  </div>
                </th>
                <th className="p-3.5 font-medium">STATUS</th>
                <th className="p-3.5 font-medium">OS FINGERPRINT</th>
                <th className="p-3.5 cursor-pointer hover:text-slate-200" onClick={() => handleSort('portsCount')}>
                  <div className="flex items-center space-x-1 font-medium">
                    <span>OPEN PORTS</span>
                    <ArrowUpDown className="w-3 h-3 text-slate-500" />
                  </div>
                </th>
                <th className="p-3.5 font-medium">SERVICES</th>
                <th className="p-3.5 cursor-pointer hover:text-slate-200" onClick={() => handleSort('riskScore')}>
                  <div className="flex items-center space-x-1 font-medium">
                    <span>RISK SCORE</span>
                    <ArrowUpDown className="w-3 h-3 text-slate-500" />
                  </div>
                </th>
                <th className="p-3.5 text-right font-medium">ACTION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#181d2a]">
              {paginatedHosts.length === 0 ? (
                <tr>
                  <td colSpan={7} className="p-8 text-center text-slate-500 font-sans">
                    No hosts match the specified filters or search query.
                  </td>
                </tr>
              ) : (
                paginatedHosts.map((host) => {
                  const openPorts = host.ports.filter((p) => p.state === 'open');
                  const topServices = openPorts.slice(0, 4);

                  return (
                    <tr
                      key={host.id}
                      onClick={() => setSelectedHost(host)}
                      className="hover:bg-[#151924] transition-colors cursor-pointer group"
                    >
                      <td className="p-3.5">
                        <div className="font-mono font-bold text-slate-100 group-hover:text-cyan-300 transition-colors">
                          {host.ip}
                        </div>
                        {host.hostname && (
                          <div className="text-[11px] text-cyan-400 font-mono mt-0.5">{host.hostname}</div>
                        )}
                      </td>
                      <td className="p-3.5">
                        <Badge variant={host.status === 'up' ? 'up' : 'down'}>{host.status}</Badge>
                      </td>
                      <td className="p-3.5 text-slate-300 font-sans">
                        {host.os.name || <span className="text-slate-600">Unidentified</span>}
                      </td>
                      <td className="p-3.5 font-sans font-semibold text-emerald-400">
                        {openPorts.length} Open
                      </td>
                      <td className="p-3.5">
                        <div className="flex flex-wrap gap-1 font-mono">
                          {topServices.map((p, idx) => (
                            <span
                              key={idx}
                              className="px-1.5 py-0.5 rounded bg-[#161a25] border border-[#232a3c] text-[10px] text-slate-300"
                            >
                              :{p.port} ({p.service})
                            </span>
                          ))}
                          {openPorts.length > 4 && (
                            <span className="text-[10px] text-slate-500 self-center font-sans">
                              +{openPorts.length - 4} more
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="p-3.5">
                        <div className="flex items-center space-x-2">
                          <span
                            className={`font-sans font-bold text-xs ${
                              host.riskScore >= 50
                                ? 'text-rose-400'
                                : host.riskScore >= 25
                                ? 'text-amber-400'
                                : 'text-emerald-400'
                            }`}
                          >
                            {host.riskScore}/100
                          </span>
                          {host.riskFlags.length > 0 && (
                            <Badge variant={host.riskFlags[0].severity}>{host.riskFlags.length} Flags</Badge>
                          )}
                        </div>
                      </td>
                      <td className="p-3.5 text-right">
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            setSelectedHost(host);
                          }}
                          className="p-1.5 rounded-lg bg-[#181d2b] text-cyan-400 hover:bg-cyan-950 hover:text-cyan-300 border border-cyan-800/60 transition-colors"
                        >
                          <Eye className="w-4 h-4" />
                        </button>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Controls */}
        {totalPages > 1 && (
          <div className="px-4 py-3 bg-[#0e1118] border-t border-[#1e2434] flex items-center justify-between font-sans text-xs">
            <span className="text-slate-400">
              Page <span className="text-slate-200 font-semibold">{currentPage}</span> of {totalPages}
            </span>
            <div className="flex items-center space-x-2">
              <button
                disabled={currentPage === 1}
                onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                className="p-1.5 rounded-lg bg-[#141824] border border-[#1e2434] disabled:opacity-40 text-slate-300 hover:bg-[#1c2232] cursor-pointer"
              >
                <ChevronLeft className="w-4 h-4" />
              </button>
              <button
                disabled={currentPage === totalPages}
                onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                className="p-1.5 rounded-lg bg-[#141824] border border-[#1e2434] disabled:opacity-40 text-slate-300 hover:bg-[#1c2232] cursor-pointer"
              >
                <ChevronRight className="w-4 h-4" />
              </button>
            </div>
          </div>
        )}
      </Card>

      {/* Host Detail Slide-over Drawer */}
      <HostDetailDrawer
        host={selectedHost}
        isOpen={selectedHost !== null}
        onClose={() => setSelectedHost(null)}
      />
    </div>
  );
};
