import React, { useState } from 'react';
import { Server, ChevronDown, ChevronRight, Copy, Check } from 'lucide-react';
import type { HostInfo } from '../../types/nmap';
import { Badge, RiskSeverityBadge } from '../common/Badge';
import { Modal } from '../common/Modal';

interface HostDetailDrawerProps {
  host: HostInfo | null;
  isOpen: boolean;
  onClose: () => void;
}

export const HostDetailDrawer: React.FC<HostDetailDrawerProps> = ({ host, isOpen, onClose }) => {
  const [activeTab, setActiveTab] = useState<'ports' | 'scripts' | 'risks' | 'raw'>('ports');
  const [expandedScript, setExpandedScript] = useState<string | null>(null);
  const [copiedScript, setCopiedScript] = useState<string | null>(null);

  if (!host) return null;

  const openPorts = host.ports.filter((p) => p.state === 'open');

  // Collect all script outputs
  const allScripts: Array<{ port: number; protocol: string; scriptId: string; output: string }> = [];
  host.ports.forEach((p) => {
    p.scriptOutputs?.forEach((so) => {
      allScripts.push({
        port: p.port,
        protocol: p.protocol,
        scriptId: so.id,
        output: so.output
      });
    });
  });

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedScript(id);
    setTimeout(() => setCopiedScript(null), 2000);
  };

  return (
    <Modal
      isOpen={isOpen}
      onClose={onClose}
      drawer={true}
      title={
        <div className="flex items-center space-x-3">
          <Server className="w-5 h-5 text-cyan-400" />
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-mono font-bold text-slate-100">{host.ip}</span>
              {host.hostname && <span className="text-xs font-mono text-cyan-400">({host.hostname})</span>}
              <Badge variant={host.status === 'up' ? 'up' : 'down'}>{host.status.toUpperCase()}</Badge>
            </div>
            <p className="text-[11px] font-mono text-slate-400 mt-0.5">
              Risk Score: <span className="text-rose-400 font-bold">{host.riskScore}/100</span> | MAC: {host.mac || 'N/A'}{' '}
              {host.macVendor ? `(${host.macVendor})` : ''}
            </p>
          </div>
        </div>
      }
    >
      <div className="space-y-6">
        {/* Host Meta Grid */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-[#0f121a] p-3 rounded-lg border border-[#202636] font-mono text-xs">
          <div>
            <span className="text-slate-500 text-[10px] block uppercase">STATUS REASON</span>
            <span className="text-slate-200 font-semibold">{host.statusReason || 'echo-reply / syn-ack'}</span>
          </div>
          <div>
            <span className="text-slate-500 text-[10px] block uppercase">OS GUESS</span>
            <span className="text-slate-200 font-semibold">{host.os.name || 'Unidentified'}</span>
            {host.os.accuracy > 0 && <span className="text-[10px] text-cyan-400 ml-1">({host.os.accuracy}%)</span>}
          </div>
          <div>
            <span className="text-slate-500 text-[10px] block uppercase">OPEN PORTS</span>
            <span className="text-emerald-400 font-bold">{openPorts.length} Open</span>
          </div>
          <div>
            <span className="text-slate-500 text-[10px] block uppercase">RISK FLAGS</span>
            <span className="text-rose-400 font-bold">{host.riskFlags.length} Findings</span>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="flex border-b border-[#202636] space-x-1">
          <button
            onClick={() => setActiveTab('ports')}
            className={`px-4 py-2 text-xs font-mono font-semibold border-b-2 transition-colors cursor-pointer ${
              activeTab === 'ports'
                ? 'border-cyan-500 text-cyan-400 bg-cyan-950/20'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Ports & Services ({host.ports.length})
          </button>
          <button
            onClick={() => setActiveTab('scripts')}
            className={`px-4 py-2 text-xs font-mono font-semibold border-b-2 transition-colors cursor-pointer ${
              activeTab === 'scripts'
                ? 'border-cyan-500 text-cyan-400 bg-cyan-950/20'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            NSE Scripts ({allScripts.length})
          </button>
          <button
            onClick={() => setActiveTab('risks')}
            className={`px-4 py-2 text-xs font-mono font-semibold border-b-2 transition-colors cursor-pointer ${
              activeTab === 'risks'
                ? 'border-cyan-500 text-cyan-400 bg-cyan-950/20'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            Security Risks ({host.riskFlags.length})
          </button>
        </div>

        {/* Tab 1: Ports Table */}
        {activeTab === 'ports' && (
          <div className="overflow-x-auto border border-[#202636] rounded-lg">
            <table className="w-full text-left font-mono text-xs">
              <thead className="bg-[#0f121a] text-slate-400 border-b border-[#202636]">
                <tr>
                  <th className="p-2.5">PORT / PROTO</th>
                  <th className="p-2.5">STATE</th>
                  <th className="p-2.5">SERVICE</th>
                  <th className="p-2.5">PRODUCT & VERSION</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1c2230]">
                {host.ports.map((p, i) => (
                  <tr key={i} className="hover:bg-[#161a26]">
                    <td className="p-2.5 text-slate-200 font-bold">
                      {p.port}/{p.protocol}
                    </td>
                    <td className="p-2.5">
                      <Badge variant={p.state as any}>{p.state}</Badge>
                    </td>
                    <td className="p-2.5 text-cyan-300 font-semibold">{p.service || 'unknown'}</td>
                    <td className="p-2.5 text-slate-300">
                      {p.product} {p.version} {p.extraInfo ? `(${p.extraInfo})` : ''}
                      {!p.product && !p.version && <span className="text-slate-600">-</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Tab 2: NSE Script Accordion */}
        {activeTab === 'scripts' && (
          <div className="space-y-3">
            {allScripts.length === 0 ? (
              <p className="text-xs font-mono text-slate-500 italic p-4 text-center">
                No NSE script execution results found for host {host.ip}.
              </p>
            ) : (
              allScripts.map((s, idx) => {
                const scriptKey = `${s.port}-${s.scriptId}-${idx}`;
                const isExpanded = expandedScript === scriptKey;

                return (
                  <div key={scriptKey} className="border border-[#202636] bg-[#0f121a] rounded-lg overflow-hidden font-mono text-xs">
                    <button
                      onClick={() => setExpandedScript(isExpanded ? null : scriptKey)}
                      className="w-full px-4 py-2.5 flex items-center justify-between hover:bg-[#161a26] text-left cursor-pointer"
                    >
                      <div className="flex items-center space-x-2">
                        {isExpanded ? <ChevronDown className="w-4 h-4 text-cyan-400" /> : <ChevronRight className="w-4 h-4 text-slate-500" />}
                        <span className="text-slate-400 font-semibold">:{s.port}/{s.protocol}</span>
                        <span className="text-cyan-400 font-bold">{s.scriptId}</span>
                      </div>
                      <span className="text-[10px] text-slate-500">Click to expand</span>
                    </button>

                    {isExpanded && (
                      <div className="p-4 bg-[#090b0e] border-t border-[#202636] relative">
                        <button
                          onClick={() => copyToClipboard(s.output, scriptKey)}
                          className="absolute right-3 top-3 p-1.5 rounded bg-[#161a26] text-slate-400 hover:text-slate-200 border border-[#272d3d]"
                        >
                          {copiedScript === scriptKey ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                        </button>
                        <pre className="text-xs text-slate-300 overflow-x-auto whitespace-pre-wrap font-mono select-all">
                          {s.output}
                        </pre>
                      </div>
                    )}
                  </div>
                );
              })
            )}
          </div>
        )}

        {/* Tab 3: Security Risk Flags */}
        {activeTab === 'risks' && (
          <div className="space-y-3">
            {host.riskFlags.length === 0 ? (
              <p className="text-xs font-mono text-emerald-400 p-4 text-center border border-emerald-900/50 bg-emerald-950/20 rounded-lg">
                No automated risk flags triggered for host {host.ip}.
              </p>
            ) : (
              host.riskFlags.map((rf, i) => (
                <div key={i} className="border border-[#202636] bg-[#0f121a] rounded-lg p-4 space-y-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2">
                      <RiskSeverityBadge severity={rf.severity} />
                      <span className="font-mono text-xs font-bold text-slate-100">{rf.title}</span>
                    </div>
                    {rf.port && <span className="font-mono text-xs text-slate-400">Port {rf.port}/{rf.protocol}</span>}
                  </div>
                  <p className="text-xs text-slate-300 font-sans">{rf.description}</p>
                  {rf.remediation && (
                    <div className="bg-[#13161f] p-2.5 rounded border border-[#202636] text-[11px] font-mono text-cyan-300">
                      <span className="font-bold text-cyan-400">Remediation: </span>
                      {rf.remediation}
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        )}
      </div>
    </Modal>
  );
};
