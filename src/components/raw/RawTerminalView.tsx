import React, { useState } from 'react';
import { Terminal, Copy, Check, Search } from 'lucide-react';
import type { NormalizedScan } from '../../types/nmap';
import { Card } from '../common/Card';

interface RawTerminalViewProps {
  scan: NormalizedScan;
}

export const RawTerminalView: React.FC<RawTerminalViewProps> = ({ scan }) => {
  const [filterText, setFilterText] = useState('');
  const [isCopied, setIsCopied] = useState(false);

  const lines = (scan.rawContent || '').split(/\r?\n/);
  const filteredLines = filterText
    ? lines.filter((line) => line.toLowerCase().includes(filterText.toLowerCase()))
    : lines;

  const handleCopy = () => {
    navigator.clipboard.writeText(scan.rawContent || '');
    setIsCopied(true);
    setTimeout(() => setIsCopied(false), 2000);
  };

  return (
    <Card
      title={`Raw Terminal / File Output (${scan.meta.filename})`}
      subtitle={`Original un-parsed Nmap scan output (${lines.length} lines)`}
      icon={<Terminal className="w-4 h-4 text-cyan-400" />}
      headerAction={
        <div className="flex items-center space-x-3">
          <div className="relative">
            <Search className="w-3 h-3 absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
            <input
              type="text"
              value={filterText}
              onChange={(e) => setFilterText(e.target.value)}
              placeholder="Search raw lines..."
              className="bg-[#13161f] border border-[#202636] focus:border-cyan-500 text-xs font-mono rounded pl-7 pr-2 py-1 text-slate-200 focus:outline-none"
            />
          </div>

          <button
            onClick={handleCopy}
            className="px-3 py-1 bg-[#1f2638] hover:bg-cyan-950 text-cyan-300 border border-cyan-800/80 rounded text-xs font-mono flex items-center space-x-1.5 cursor-pointer transition-colors"
          >
            {isCopied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            <span>{isCopied ? 'Copied' : 'Copy All'}</span>
          </button>
        </div>
      }
    >
      <div className="bg-[#080a0e] border border-[#202636] rounded-lg p-4 font-mono text-xs overflow-x-auto max-h-[650px]">
        {filteredLines.map((line, idx) => (
          <div key={idx} className="flex hover:bg-[#111520] py-0.5 px-1 rounded">
            <span className="text-slate-600 select-none w-12 text-right pr-4 shrink-0 font-mono text-[11px]">
              {idx + 1}
            </span>
            <span
              className={`whitespace-pre-wrap font-mono ${
                line.includes('Nmap scan report')
                  ? 'text-cyan-400 font-bold'
                  : line.includes('open')
                  ? 'text-emerald-400'
                  : line.includes('filtered')
                  ? 'text-amber-400'
                  : line.includes('closed')
                  ? 'text-rose-400'
                  : 'text-slate-300'
              }`}
            >
              {line}
            </span>
          </div>
        ))}
      </div>
    </Card>
  );
};
