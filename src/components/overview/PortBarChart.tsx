import React from 'react';
import { ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, Cell } from 'recharts';
import type { NormalizedScan } from '../../types/nmap';
import { Card } from '../common/Card';
import { BarChart2 } from 'lucide-react';

interface PortBarChartProps {
  scan: NormalizedScan;
  onSelectPort?: (port: number) => void;
}

export const PortBarChart: React.FC<PortBarChartProps> = ({ scan, onSelectPort }) => {
  // Aggregate ports & services
  const portCounts: Record<string, { port: number; service: string; count: number }> = {};

  scan.hosts.forEach((h) => {
    h.ports.forEach((p) => {
      if (p.state === 'open') {
        const key = `${p.port}/${p.protocol}`;
        if (!portCounts[key]) {
          portCounts[key] = { port: p.port, service: p.service || 'unknown', count: 0 };
        }
        portCounts[key].count += 1;
      }
    });
  });

  const data = Object.entries(portCounts)
    .map(([key, val]) => ({
      name: key,
      port: val.port,
      service: val.service,
      count: val.count
    }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 8);

  // Cohesive, desaturated cyan-to-steel color palette
  const colors = [
    '#06b6d4', // cyan-500
    '#0891b2', // cyan-600
    '#0284c7', // sky-600
    '#0369a1', // sky-700
    '#0e7490', // cyan-700
    '#155e75', // cyan-800
    '#1e40af', // blue-800
    '#334155'  // slate-700
  ];

  const CustomTooltip = ({ active, payload }: any) => {
    if (active && payload && payload.length) {
      const d = payload[0].payload;
      return (
        <div className="bg-[#0f121a] border border-[#272d3d] p-3 rounded-lg shadow-xl font-sans text-xs">
          <div className="flex items-center space-x-2">
            <span className="font-mono text-cyan-400 font-bold">{d.name}</span>
            <span className="text-slate-400">({d.service})</span>
          </div>
          <p className="text-slate-200 mt-1 font-sans">
            Open on <span className="text-cyan-300 font-bold">{d.count}</span> scanned host(s)
          </p>
          <p className="text-[10px] text-slate-500 mt-1">Click to filter hosts by this port</p>
        </div>
      );
    }
    return null;
  };

  return (
    <Card
      title="Top Open Ports & Services"
      subtitle="Frequency of open port instances discovered across scanned hosts"
      icon={<BarChart2 className="w-4 h-4 text-cyan-400" />}
      className="bg-[#11141d] border-[#1e2434]"
    >
      {data.length === 0 ? (
        <div className="h-64 flex items-center justify-center text-xs text-slate-500 font-sans">
          No open ports discovered in this scan file.
        </div>
      ) : (
        <div className="h-64 w-full pt-1">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart
              data={data}
              layout="vertical"
              margin={{ top: 5, right: 30, left: 35, bottom: 5 }}
            >
              <XAxis
                type="number"
                stroke="#334155"
                allowDecimals={false}
                tick={{ fill: '#64748b', fontSize: 11, fontFamily: 'JetBrains Mono' }}
              />
              <YAxis
                type="category"
                dataKey="name"
                stroke="#334155"
                tick={{ fill: '#cbd5e1', fontSize: 11, fontFamily: 'JetBrains Mono' }}
                width={80}
              />
              <Tooltip content={<CustomTooltip />} />
              <Bar
                dataKey="count"
                barSize={16}
                radius={[0, 4, 4, 0]}
                className="cursor-pointer"
                onClick={(entry: any) => onSelectPort && onSelectPort(entry.port)}
              >
                {data.map((_, index) => (
                  <Cell
                    key={`cell-${index}`}
                    fill={colors[index % colors.length]}
                    className="hover:opacity-80 transition-opacity"
                  />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      )}
    </Card>
  );
};
