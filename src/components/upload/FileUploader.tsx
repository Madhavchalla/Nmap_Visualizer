import React, { useState, useRef } from 'react';
import { Upload, AlertTriangle, Play, Shield, Terminal, ArrowRight, CheckCircle2 } from 'lucide-react';
import { detectFormat } from '../../utils/parsers/formatDetector';
import { parseNmapScan } from '../../utils/parsers/nmapParser';
import type { InputFormat, NormalizedScan, ParseResult } from '../../types/nmap';
import { Badge } from '../common/Badge';

interface FileUploaderProps {
  onScanLoaded: (scans: NormalizedScan[]) => void;
  onLoadSamples: (sampleIndex?: number) => void;
  loadedScansCount?: number;
}

interface StagedFile {
  file: File;
  content: string;
  detectedFormat: InputFormat;
  parseResult?: ParseResult;
}

export const FileUploader: React.FC<FileUploaderProps> = ({ onScanLoaded, onLoadSamples }) => {
  const [, setStagedFiles] = useState<StagedFile[]>([]);
  const [isDragging, setIsDragging] = useState(false);
  const [parseErrors, setParseErrors] = useState<string[]>([]);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const processFiles = (files: FileList | File[]) => {
    const fileArray = Array.from(files);
    const errors: string[] = [];
    const newStaged: StagedFile[] = [];

    let processedCount = 0;

    fileArray.forEach((file) => {
      const reader = new FileReader();
      reader.onload = (e) => {
        const text = (e.target?.result as string) || '';
        const detectedFormat = detectFormat(text);
        const result = parseNmapScan(text, file.name);

        if (result.success && result.scan) {
          newStaged.push({
            file,
            content: text,
            detectedFormat,
            parseResult: result
          });
        } else if (result.error) {
          errors.push(result.error);
        }

        processedCount++;
        if (processedCount === fileArray.length) {
          if (newStaged.length > 0) {
            setStagedFiles((prev) => [...prev, ...newStaged]);
            const newScans = newStaged.map((s) => s.parseResult!.scan!);
            onScanLoaded(newScans);
          }
          if (errors.length > 0) {
            setParseErrors((prev) => [...prev, ...errors]);
          }
        }
      };

      reader.onerror = () => {
        errors.push(`Failed to read file '${file.name}'. Permission denied or corrupted file.`);
        processedCount++;
        if (processedCount === fileArray.length && errors.length > 0) {
          setParseErrors((prev) => [...prev, ...errors]);
        }
      };

      reader.readAsText(file);
    });
  };

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      processFiles(e.dataTransfer.files);
    }
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      processFiles(e.target.files);
    }
  };

  return (
    <div className="space-y-8 max-w-4xl mx-auto">
      {/* Intro Header */}
      <div className="text-center space-y-2">
        <div className="inline-flex items-center space-x-2 px-3 py-1 rounded-full bg-cyan-950/60 border border-cyan-800/60 text-cyan-400 text-xs font-mono font-medium">
          <Shield className="w-3.5 h-3.5" />
          <span>ZERO DATA TRANSMISSION — 100% CLIENT-SIDE INGESTION</span>
        </div>
        <h2 className="text-2xl sm:text-3xl font-bold tracking-tight text-slate-100 font-sans">
          Nmap Scan Visualization Dashboard
        </h2>
        <p className="text-sm text-slate-400 max-w-xl mx-auto font-sans leading-relaxed">
          Upload raw scan outputs to instantly generate interactive network topology graphs, 
          port breakdowns, heuristic security flags, and printable PDF audit reports.
        </p>
      </div>

      {/* Upload Zone Card */}
      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        onClick={() => fileInputRef.current?.click()}
        className={`relative border-2 border-dashed rounded-xl p-10 text-center cursor-pointer transition-all duration-200 group ${
          isDragging
            ? 'border-cyan-400 bg-cyan-950/30 scale-[1.01]'
            : 'border-[#222838] bg-[#11141d] hover:border-cyan-500/60 hover:bg-[#141824]'
        }`}
      >
        <input
          type="file"
          ref={fileInputRef}
          onChange={handleFileChange}
          multiple
          accept=".xml,.nmap,.gnmap,.txt"
          className="hidden"
        />

        <div className="flex flex-col items-center justify-center space-y-4">
          <div className="w-16 h-16 rounded-2xl bg-[#161a26] border border-[#262e42] flex items-center justify-center text-cyan-400 group-hover:scale-110 group-hover:border-cyan-500/50 transition-all duration-200 shadow-xl">
            <Upload className="w-8 h-8" />
          </div>

          <div className="space-y-1">
            <h3 className="text-base font-semibold text-slate-100 font-sans">
              Drop Nmap scan output file here, or <span className="text-cyan-400 group-hover:underline">browse files</span>
            </h3>
            <p className="text-xs text-slate-400 font-sans">
              Accepts XML (<span className="font-mono text-slate-300">-oX</span>), Normal text (<span className="font-mono text-slate-300">-oN</span>), Grepable (<span className="font-mono text-slate-300">-oG</span>), or batch files
            </p>
          </div>

          <div className="flex flex-wrap items-center justify-center gap-2 pt-2">
            <span className="px-2.5 py-1 rounded bg-[#181d2a] border border-[#252c3f] text-slate-300 text-xs font-mono flex items-center space-x-1">
              <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400" />
              <span>XML (-oX)</span>
            </span>
            <span className="px-2.5 py-1 rounded bg-[#181d2a] border border-[#252c3f] text-slate-300 text-xs font-mono flex items-center space-x-1">
              <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400" />
              <span>Normal (-oN)</span>
            </span>
            <span className="px-2.5 py-1 rounded bg-[#181d2a] border border-[#252c3f] text-slate-300 text-xs font-mono flex items-center space-x-1">
              <CheckCircle2 className="w-3.5 h-3.5 text-cyan-400" />
              <span>Grepable (-oG)</span>
            </span>
          </div>
        </div>
      </div>

      {/* Parse Errors Notification */}
      {parseErrors.length > 0 && (
        <div className="bg-rose-950/40 border border-rose-800/80 rounded-xl p-4 space-y-2">
          <div className="flex items-center space-x-2 text-rose-300 font-semibold text-sm font-sans">
            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0" />
            <span>Parsing Issues Detected ({parseErrors.length})</span>
          </div>
          <ul className="text-xs text-rose-200 font-mono space-y-1 list-disc list-inside">
            {parseErrors.map((err, i) => (
              <li key={i}>{err}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Sample Scans Option Cards */}
      <div className="bg-[#11141d] border border-[#1e2332] rounded-xl p-6 space-y-4">
        <div className="flex items-center justify-between border-b border-[#1b202d] pb-3">
          <div>
            <h4 className="text-sm font-semibold text-slate-100 font-sans">Or Explore With Pre-Configured Sample Scans</h4>
            <p className="text-xs text-slate-400 font-sans mt-0.5">
              Click any realistic scan scenario below to immediately test the visualization dashboard without uploading.
            </p>
          </div>
          <button
            onClick={() => onLoadSamples()}
            className="px-3 py-1.5 bg-[#181d2b] hover:bg-[#20273a] text-cyan-400 border border-[#2b354d] text-xs font-sans font-medium rounded-lg transition-colors cursor-pointer flex items-center space-x-1"
          >
            <span>Load All Scans (Diff Ready)</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          {/* Sample 1 */}
          <button
            onClick={() => onLoadSamples(0)}
            className="text-left p-3.5 rounded-lg bg-[#0d1017] border border-[#1c2230] hover:border-cyan-500/50 hover:bg-[#121620] transition-all group cursor-pointer"
          >
            <div className="flex items-center justify-between mb-2">
              <Badge variant="format">XML (-oX)</Badge>
              <Play className="w-3.5 h-3.5 text-slate-500 group-hover:text-cyan-400 transition-colors" />
            </div>
            <div className="font-semibold text-xs text-slate-200 group-hover:text-cyan-300 font-sans">
              Enterprise Corporate Audit
            </div>
            <p className="text-[11px] text-slate-400 font-sans mt-1 leading-snug">
              6 hosts: Domain Controller, FTP backdoor hint, exposed Redis & MongoDB.
            </p>
          </button>

          {/* Sample 2 */}
          <button
            onClick={() => onLoadSamples(1)}
            className="text-left p-3.5 rounded-lg bg-[#0d1017] border border-[#1c2230] hover:border-cyan-500/50 hover:bg-[#121620] transition-all group cursor-pointer"
          >
            <div className="flex items-center justify-between mb-2">
              <Badge variant="neutral">Normal (-oN)</Badge>
              <Play className="w-3.5 h-3.5 text-slate-500 group-hover:text-cyan-400 transition-colors" />
            </div>
            <div className="font-semibold text-xs text-slate-200 group-hover:text-cyan-300 font-sans">
              Cloud Perimeter Recon
            </div>
            <p className="text-[11px] text-slate-400 font-sans mt-1 leading-snug">
              4 hosts: Kubernetes ingress, Elasticsearch cluster, Postgres DB.
            </p>
          </button>

          {/* Sample 3 */}
          <button
            onClick={() => onLoadSamples()}
            className="text-left p-3.5 rounded-lg bg-[#0d1017] border border-[#1c2230] hover:border-cyan-500/50 hover:bg-[#121620] transition-all group cursor-pointer"
          >
            <div className="flex items-center justify-between mb-2">
              <Badge variant="open">Diff Comparison</Badge>
              <Play className="w-3.5 h-3.5 text-slate-500 group-hover:text-cyan-400 transition-colors" />
            </div>
            <div className="font-semibold text-xs text-slate-200 group-hover:text-cyan-300 font-sans">
              Multi-Scan Delta Demo
            </div>
            <p className="text-[11px] text-slate-400 font-sans mt-1 leading-snug">
              Baseline vs follow-up scan for testing delta diff and new ports.
            </p>
          </button>
        </div>
      </div>

      {/* Terminal Cheat Sheet */}
      <div className="bg-[#0c0e14] border border-[#191e2b] rounded-xl p-4 font-sans text-xs space-y-2 text-slate-400">
        <div className="flex items-center space-x-2 text-slate-300 font-medium">
          <Terminal className="w-4 h-4 text-cyan-400" />
          <span>Quick Terminal Command Guide</span>
        </div>
        <p className="text-[11px] text-slate-400 leading-relaxed">
          To generate compatible output files with your Nmap CLI, run any of the following commands:
        </p>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-2 pt-1 font-mono text-[11px]">
          <div className="p-2 rounded bg-[#10131c] border border-[#1e2332] text-slate-300">
            <span className="text-cyan-400 select-none">$ </span>nmap -sS -sV -O -oX audit.xml 192.168.1.0/24
          </div>
          <div className="p-2 rounded bg-[#10131c] border border-[#1e2332] text-slate-300">
            <span className="text-cyan-400 select-none">$ </span>nmap -sV -sC -oN audit.nmap 10.0.0.0/24
          </div>
        </div>
      </div>
    </div>
  );
};
