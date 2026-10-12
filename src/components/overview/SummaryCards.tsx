import React from 'react';
import { Server, Activity, Unlock, AlertOctagon, ShieldAlert } from 'lucide-react';
import type { NormalizedScan } from '../../types/nmap';
import { Card } from '../common/Card';

interface SummaryCardsProps {
  scan: NormalizedScan;
}

export const SummaryCards: React.FC<SummaryCardsProps> = ({ scan }) => {
  const meta = scan.meta;

  const totalCritical = scan.hosts.reduce(
    (acc, h) => acc + h.riskFlags.filter((f) => f.severity === 'critical' || f.severity === 'high').length,
    0
  );

  const totalFlags = scan.hosts.reduce((acc, h) => acc + h.riskFlags.length, 0);

  const stats = [
    {
      title: 'Scanned Targets',
      value: meta.totalHosts,
      sub: `${meta.hostsUp} live / ${meta.hostsDown} down`,
      icon: <Server className="w-4 h-4 text-cyan-400" />,
      iconBg: 'bg-cyan-950/70 border-cyan-800/60',
      badge: 'TARGETS',
      badgeColor: 'text-cyan-400 bg-cyan-950/60 border-cyan-800/40'
    },
    {
      title: 'Hosts Online',
      value: meta.hostsUp,
      sub: `${((meta.hostsUp / (meta.totalHosts || 1)) * 100).toFixed(0)}% responsive`,
      icon: <Activity className="w-4 h-4 text-emerald-400" />,
      iconBg: 'bg-emerald-950/70 border-emerald-800/60',
      badge: 'ONLINE',
      badgeColor: 'text-emerald-400 bg-emerald-950/60 border-emerald-800/40'
    },
    {
      title: 'Open Ports',
      value: meta.totalOpenPorts,
      sub: `${meta.totalFilteredPorts} filtered, ${meta.totalClosedPorts} closed`,
      icon: <Unlock className="w-4 h-4 text-amber-400" />,
      iconBg: 'bg-amber-950/70 border-amber-800/60',
      badge: 'SURFACE',
      badgeColor: 'text-amber-400 bg-amber-950/60 border-amber-800/40'
    },
    {
      title: 'High & Critical Risks',
      value: totalCritical,
      sub: `${totalFlags} total heuristic flags`,
      icon: <AlertOctagon className="w-4 h-4 text-rose-400" />,
      iconBg: 'bg-rose-950/70 border-rose-800/60',
      badge: totalCritical > 0 ? 'ALERT' : 'CLEAR',
      badgeColor: totalCritical > 0 ? 'text-rose-400 bg-rose-950/60 border-rose-800/40' : 'text-emerald-400 bg-emerald-950/60 border-emerald-800/40'
    },
    {
      title: 'Primary Service',
      value: meta.mostCommonService ? meta.mostCommonService.split(' ')[0] : 'None',
      sub: `Scanner: Nmap ${meta.nmapVersion || '7.x'}`,
      icon: <ShieldAlert className="w-4 h-4 text-blue-400" />,
      iconBg: 'bg-blue-950/70 border-blue-800/60',
      badge: 'PROTOCOL',
      badgeColor: 'text-blue-400 bg-blue-950/60 border-blue-800/40'
    }
  ];

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3.5">
      {stats.map((st, i) => (
        <Card key={i} className="bg-[#11141d] border-[#1e2434] hover:border-[#2a3449] transition-all duration-200">
          <div className="flex items-center justify-between mb-3">
            <span className="text-xs font-sans font-medium text-slate-400">{st.title}</span>
            <div className={`w-7 h-7 rounded-lg border flex items-center justify-center ${st.iconBg}`}>
              {st.icon}
            </div>
          </div>
          <div className="flex items-baseline space-x-2">
            <span className="text-2xl font-bold font-sans text-slate-100 tracking-tight">{st.value}</span>
            <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${st.badgeColor}`}>
              {st.badge}
            </span>
          </div>
          <p className="text-xs font-sans text-slate-400 mt-1.5 truncate">{st.sub}</p>
        </Card>
      ))}
    </div>
  );
};
