import type { HostInfo, HostOS, NormalizedScan, PortInfo, ScanMeta } from '../../types/nmap';
import { analyzeHostRisks } from '../riskEngine';

export function parseGrepableNmap(content: string, filename: string): NormalizedScan {
  const lines = content.split(/\r?\n/);

  let nmapVersion = '7.xx';
  let args = 'nmap scan (-oG)';
  let startTime = new Date().toISOString();

  // Sniff metadata comment headers
  for (const line of lines) {
    if (line.startsWith('# Nmap')) {
      const verMatch = line.match(/Nmap\s+([0-9\.\w]+)/);
      if (verMatch) nmapVersion = verMatch[1];
      const asMatch = line.match(/as:\s+(.*)$/);
      if (asMatch) args = asMatch[1];
      const dateMatch = line.match(/initiated\s+(.*?)\s+as:/);
      if (dateMatch) startTime = dateMatch[1];
    }
  }

  interface GrepHostMap {
    ip: string;
    hostname: string | null;
    status: 'up' | 'down';
    statusReason?: string;
    osName: string | null;
    portsMap: Map<string, PortInfo>;
  }

  const hostMap = new Map<string, GrepHostMap>();

  for (const line of lines) {
    if (!line.startsWith('Host:')) continue;

    // Line format: Host: <IP> (<hostname>)\t<Key>: <Value>\t<Key>: <Value>...
    const hostHeaderMatch = line.match(/^Host:\s+([^\s\(\)]+)\s*(?:\((.*?)\))?\t(.*)$/);
    if (!hostHeaderMatch) continue;

    const ip = hostHeaderMatch[1];
    const hostname = hostHeaderMatch[2] ? (hostHeaderMatch[2].trim() || null) : null;
    const kvPayload = hostHeaderMatch[3];

    let entry = hostMap.get(ip);
    if (!entry) {
      entry = {
        ip,
        hostname,
        status: 'up',
        osName: null,
        portsMap: new Map()
      };
      hostMap.set(ip, entry);
    }

    if (hostname && !entry.hostname) entry.hostname = hostname;

    // Split key-value fields separated by tabs
    const fields = kvPayload.split('\t');
    for (const field of fields) {
      const colonIdx = field.indexOf(':');
      if (colonIdx === -1) continue;

      const key = field.substring(0, colonIdx).trim();
      const val = field.substring(colonIdx + 1).trim();

      if (key === 'Status') {
        entry.status = val.toLowerCase().startsWith('up') ? 'up' : 'down';
      } else if (key === 'OS') {
        entry.osName = val;
      } else if (key === 'Ports') {
        // Ports format: 80/open/tcp//http//Apache httpd 2.4.41/, 443/open/tcp//https///
        const portEntries = val.split(/,\s*/);
        for (const pe of portEntries) {
          const parts = pe.split('/');
          if (parts.length >= 5) {
            const portNum = parseInt(parts[0], 10);
            const state = parts[1].toLowerCase();
            const protocol = parts[2].toLowerCase() || 'tcp';
            const service = parts[4] || 'unknown';
            const versionStr = parts[6] ? parts[6].trim() : undefined;

            if (isNaN(portNum)) continue;

            const keyStr = `${portNum}/${protocol}`;
            entry.portsMap.set(keyStr, {
              port: portNum,
              protocol,
              state,
              service,
              version: versionStr,
              scriptOutputs: []
            });
          }
        }
      }
    }
  }

  let totalOpenPorts = 0;
  let totalFilteredPorts = 0;
  let totalClosedPorts = 0;
  let hostsUpCount = 0;
  let hostsDownCount = 0;
  const serviceCounts: Record<string, number> = {};

  const hosts: HostInfo[] = [];
  let idx = 0;

  hostMap.forEach((entry) => {
    if (entry.status === 'up') hostsUpCount++;
    else hostsDownCount++;

    const portsList: PortInfo[] = Array.from(entry.portsMap.values());
    portsList.forEach((p) => {
      if (p.state === 'open') {
        totalOpenPorts++;
        if (p.service) serviceCounts[p.service] = (serviceCounts[p.service] || 0) + 1;
      } else if (p.state === 'filtered') totalFilteredPorts++;
      else if (p.state === 'closed') totalClosedPorts++;
    });

    const os: HostOS = {
      name: entry.osName,
      accuracy: entry.osName ? 85 : 0
    };

    const { riskFlags, riskScore } = analyzeHostRisks(entry.ip, portsList, os.name);

    hosts.push({
      id: `host-grepable-${entry.ip}-${idx++}`,
      ip: entry.ip,
      hostname: entry.hostname,
      hostnames: entry.hostname ? [entry.hostname] : [],
      status: entry.status,
      os,
      ports: portsList,
      riskScore,
      riskFlags
    });
  });

  let mostCommonService = 'None';
  let maxCount = 0;
  Object.entries(serviceCounts).forEach(([svc, count]) => {
    if (count > maxCount) {
      maxCount = count;
      mostCommonService = `${svc} (${count})`;
    }
  });

  const scanId = `scan-grepable-${Date.now()}`;
  const meta: ScanMeta = {
    scanId,
    filename,
    format: 'grepable',
    startTime,
    nmapVersion,
    args,
    totalHosts: hosts.length,
    hostsUp: hostsUpCount,
    hostsDown: hostsDownCount,
    totalOpenPorts,
    totalFilteredPorts,
    totalClosedPorts,
    mostCommonService
  };

  return {
    id: scanId,
    meta,
    hosts,
    rawContent: content,
    uploadedAt: new Date().toISOString()
  };
}
