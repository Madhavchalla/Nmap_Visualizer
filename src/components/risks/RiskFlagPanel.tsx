import React, { useState } from 'react';
import { AlertTriangle, ShieldAlert, Copy, Check } from 'lucide-react';
import type { NormalizedScan, RiskFlag, RiskSeverity } from '../../types/nmap';
import { Badge, RiskSeverityBadge } from '../common/Badge';
import { Card } from '../common/Card';

interface RiskFlagPanelProps {
  scan: NormalizedScan;
}

export const RiskFlagPanel: React.FC<RiskFlagPanelProps> = ({ scan }) => {
  const [selectedSeverity, setSelectedSeverity] = useState<'all' | RiskSeverity>('all');
  const [selectedCategory] = useState<'all' | string>('all');
  const [searchFilter] = useState('');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Collect all risk flags across all hosts
  const allFindings: Array<{ hostIp: string; hostname: string | null; flag: RiskFlag }> = [];
  scan.hosts.forEach((h) => {
    h.riskFlags.forEach((f) => {
      allFindings.push({
        hostIp: h.ip,
        hostname: h.hostname,
        flag: f
      });
    });
  });

  const severityCounts = {
    critical: allFindings.filter((f) => f.flag.severity === 'critical').length,
    high: allFindings.filter((f) => f.flag.severity === 'high').length,
    medium: allFindings.filter((f) => f.flag.severity === 'medium').length,
    low: allFindings.filter((f) => f.flag.severity === 'low').length,
    info: allFindings.filter((f) => f.flag.severity === 'info').length
  };

  const filteredFindings = allFindings.filter(({ hostIp, hostname, flag }) => {
    if (selectedSeverity !== 'all' && flag.severity !== selectedSeverity) return false;
    if (selectedCategory !== 'all' && flag.category !== selectedCategory) return false;
    if (searchFilter.trim().length > 0) {
      const q = searchFilter.toLowerCase();
      const matchHost = hostIp.includes(q) || (hostname && hostname.toLowerCase().includes(q));
      const matchTitle = flag.title.toLowerCase().includes(q);
      const matchDesc = flag.description.toLowerCase().includes(q);
      return matchHost || matchTitle || matchDesc;
    }
    return true;
  });

  const handleCopyEvidence = (evidence: string, id: string) => {
    navigator.clipboard.writeText(evidence);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div className="space-y-6 font-sans">
      {/* Disclaimer Banner */}
      <div className="bg-amber-950/30 border border-amber-800/60 rounded-xl p-3.5 flex items-center space-x-3 text-amber-200 text-xs">
        <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0" />
        <div className="leading-relaxed">
          <span className="font-bold text-amber-300">HEURISTIC SECURITY INDICATORS: </span>
          Risk flags are rule-based inferences calculated from detected open ports, service banners, and NSE script outputs. These highlight high-probability exposure points, not confirmed exploits.
        </div>
      </div>

      {/* Severity Counter Pills */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        {(['critical', 'high', 'medium', 'low', 'info'] as const).map((sev) => {
          const count = severityCounts[sev];
          const isSelected = selectedSeverity === sev;
          return (
            <button
              key={sev}
              onClick={() => setSelectedSeverity(isSelected ? 'all' : sev)}
              className={`p-3 rounded-xl border flex items-center justify-between cursor-pointer transition-all ${
                isSelected
                  ? 'bg-cyan-950/60 border-cyan-500 shadow-md ring-1 ring-cyan-500/30'
                  : 'bg-[#11141d] border-[#1e2434] hover:border-[#2b354a]'
              }`}
            >
              <div className="flex items-center space-x-2">
                <RiskSeverityBadge severity={sev} />
              </div>
              <span className="text-base font-bold font-sans text-slate-100">{count}</span>
            </button>
          );
        })}
      </div>

      {/* Findings List */}
      <Card
        title={`Automated Security Findings (${filteredFindings.length})`}
        subtitle="Rule-based risk evaluation across all target scan hosts"
        icon={<ShieldAlert className="w-4 h-4 text-cyan-400" />}
        className="bg-[#11141d] border-[#1e2434]"
      >
        <div className="space-y-3.5">
          {filteredFindings.length === 0 ? (
            <div className="p-8 text-center text-xs font-sans text-slate-500">
              No risk findings match the selected filters.
            </div>
          ) : (
            filteredFindings.map(({ hostIp, hostname, flag }, idx) => (
              <div key={idx} className="bg-[#0e1118] border border-[#1e2434] hover:border-[#2a3449] rounded-xl p-4 space-y-3 transition-colors">
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-[#181d2a] pb-2.5">
                  <div className="flex items-center space-x-2.5">
                    <RiskSeverityBadge severity={flag.severity} />
                    <span className="text-sm font-bold text-slate-100 font-sans">{flag.title}</span>
                  </div>
                  <div className="flex items-center space-x-2 text-xs">
                    <span className="text-cyan-400 font-mono font-bold">{hostIp}</span>
                    {hostname && <span className="text-slate-400 font-mono">({hostname})</span>}
                    {flag.port && <Badge variant="neutral">:{flag.port}/{flag.protocol}</Badge>}
                  </div>
                </div>

                <p className="text-xs text-slate-300 font-sans leading-relaxed">{flag.description}</p>

                {flag.remediation && (
                  <div className="bg-[#131722] border border-[#1e2536] p-3 rounded-lg text-xs font-sans text-slate-200">
                    <span className="font-bold text-cyan-400 mr-1.5">REMEDIATION:</span>
                    <span className="text-slate-300">{flag.remediation}</span>
                  </div>
                )}

                {flag.evidence && (
                  <div className="relative bg-[#090b0f] border border-[#161a25] p-3 rounded-lg text-xs">
                    <div className="flex items-center justify-between text-[11px] text-slate-500 mb-1 font-sans">
                      <span>EVIDENCE LOG / NSE SCRIPT SNIPPET</span>
                      <button
                        onClick={() => handleCopyEvidence(flag.evidence!, flag.id)}
                        className="text-slate-400 hover:text-slate-200 flex items-center space-x-1 cursor-pointer font-sans"
                      >
                        {copiedId === flag.id ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                        <span>Copy</span>
                      </button>
                    </div>
                    <pre className="text-xs text-slate-400 whitespace-pre-wrap font-mono overflow-x-auto leading-relaxed">
                      {flag.evidence}
                    </pre>
                  </div>
                )}
              </div>
            ))
          )}
        </div>
      </Card>
    </div>
  );
};
