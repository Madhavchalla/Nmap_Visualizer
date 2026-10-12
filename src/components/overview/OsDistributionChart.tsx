import React from 'react';
import { ResponsiveContainer, PieChart, Pie, Cell, Tooltip, Legend } from 'recharts';
import type { NormalizedScan } from '../../types/nmap';
import { Card } from '../common/Card';
import { Cpu } from 'lucide-react';

interface OsDistributionChartProps {
  scan: NormalizedScan;
}

export const OsDistributionChart: React.FC<OsDistributionChartProps> = ({ scan }) => {
  const osCounts: Record<string, number> = {};

  scan.hosts.forEach((h) => {
    let osName = h.os.name || 'Unidentified OS';
    if (osName.includes('Linux')) osName = 'Linux Kernel';
    else if (osName.includes('Windows')) osName = 'Microsoft Windows';
    else if (osName.includes('BSD') || osName.includes('Unix')) osName = 'BSD / Unix';
    else if (osName.includes('Cisco')) osName = 'Cisco IOS';

    osCounts[osName] = (osCounts[osName] || 0) + 1;
  });

  const data = Object.entries(osCounts).map(([name, count]) => ({
    name,
    value: count
  }));

  const COLORS = ['#06b6d4', '#0284c7', '#10b981', '#f59e0b', '#64748b'];

  const CustomTooltip = ({ active, payload }: any) => {
    if (active && payload && payload.length) {
      const d = payload[0];
      return (
        <div className="bg-[#0f121a] border border-[#272d3d] p-2.5 rounded-lg shadow-xl font-sans text-xs">
          <p className="text-cyan-400 font-bold">{d.name}</p>
          <p className="text-slate-300 mt-1">
            <span className="text-slate-100 font-bold">{d.value}</span> Host(s) ({((d.value / (scan.hosts.length || 1)) * 100).toFixed(0)}%)
          </p>
        </div>
      );
    }
    return null;
  };

  return (
    <Card
      title="Operating System Distribution"
      subtitle="Fingerprint classifications detected across hosts"
      icon={<Cpu className="w-4 h-4 text-cyan-400" />}
      className="bg-[#11141d] border-[#1e2434]"
    >
      {data.length === 0 ? (
        <div className="h-64 flex items-center justify-center text-xs text-slate-500 font-sans">
          No OS detection (-O) data present in scan file.
        </div>
      ) : (
        <div className="h-64 w-full relative">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={data}
                cx="50%"
                cy="45%"
                innerRadius={50}
                outerRadius={75}
                paddingAngle={4}
                dataKey="value"
              >
                {data.map((_, index) => (
                  <Cell
                    key={`cell-${index}`}
                    fill={COLORS[index % COLORS.length]}
                    stroke="#11141d"
                    strokeWidth={2}
                    className="hover:opacity-85 transition-opacity"
                  />
                ))}
              </Pie>
              <Tooltip content={<CustomTooltip />} />
              <Legend
                verticalAlign="bottom"
                height={40}
                formatter={(value: string) => <span className="text-slate-300 text-[11px] font-sans">{value}</span>}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>
      )}
    </Card>
  );
};
