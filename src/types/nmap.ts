export type InputFormat = 'xml' | 'normal' | 'grepable' | 'unknown';

export interface ScriptOutput {
  id: string;
  output: string;
  elements?: Record<string, string>;
}

export interface PortInfo {
  port: number;
  protocol: 'tcp' | 'udp' | 'sctp' | string;
  state: 'open' | 'closed' | 'filtered' | 'open|filtered' | 'unfiltered' | string;
  stateReason?: string;
  service: string;
  product?: string;
  version?: string;
  extraInfo?: string;
  cpe?: string[];
  scriptOutputs?: ScriptOutput[];
}

export interface HostOS {
  name: string | null;
  accuracy: number;
  family?: string;
  vendor?: string;
  generation?: string;
  matches?: Array<{ name: string; accuracy: number; family?: string }>;
}

export interface HostInfo {
  id: string;
  ip: string;
  ipv6?: string;
  mac?: string;
  macVendor?: string;
  hostname: string | null;
  hostnames: string[];
  status: 'up' | 'down';
  statusReason?: string;
  os: HostOS;
  ports: PortInfo[];
  uptimeSeconds?: number;
  lastBoot?: string;
  riskScore: number; // 0-100 heuristic
  riskFlags: RiskFlag[];
  rawText?: string;
}

export type RiskSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type RiskCategory = 
  | 'Unencrypted Protocol'
  | 'Database Exposure'
  | 'Vulnerable Service'
  | 'SMB / NetBIOS Risk'
  | 'Anonymous Access'
  | 'Default Credentials'
  | 'Dangerous Port'
  | 'Information Disclosure';

export interface RiskFlag {
  id: string;
  severity: RiskSeverity;
  title: string;
  description: string;
  category: RiskCategory;
  port?: number;
  protocol?: string;
  service?: string;
  evidence?: string;
  remediation?: string;
  cve?: string[];
}

export interface ScanMeta {
  scanId: string;
  filename: string;
  format: InputFormat;
  startTime: string; // ISO or formatted
  endTime?: string;
  nmapVersion: string;
  args: string;
  scanType?: string;
  totalHosts: number;
  hostsUp: number;
  hostsDown: number;
  totalOpenPorts: number;
  totalFilteredPorts: number;
  totalClosedPorts: number;
  mostCommonService?: string;
}

export interface NormalizedScan {
  id: string;
  meta: ScanMeta;
  hosts: HostInfo[];
  rawContent: string;
  uploadedAt: string;
}

export interface ParseResult {
  success: boolean;
  scan?: NormalizedScan;
  error?: string;
  formatDetected: InputFormat;
  filename: string;
}

// Diff Comparison Types
export interface HostDiff {
  ip: string;
  hostname: string | null;
  type: 'added' | 'removed' | 'modified' | 'unchanged';
  statusChange?: { from: 'up' | 'down'; to: 'up' | 'down' };
  openedPorts: PortInfo[];
  closedPorts: PortInfo[];
  modifiedPorts: Array<{
    port: number;
    protocol: string;
    oldVersion?: string;
    newVersion?: string;
  }>;
  riskDelta: number;
}

export interface ScanDiff {
  scanAId: string;
  scanBId: string;
  scanAName: string;
  scanBName: string;
  addedHostsCount: number;
  removedHostsCount: number;
  newlyOpenedPortsCount: number;
  newlyClosedPortsCount: number;
  hostDiffs: HostDiff[];
}
