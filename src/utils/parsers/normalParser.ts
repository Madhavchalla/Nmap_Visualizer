import type { HostInfo, HostOS, NormalizedScan, PortInfo, ScanMeta } from '../../types/nmap';
import { analyzeHostRisks } from '../riskEngine';

export function parseNormalNmap(content: string, filename: string): NormalizedScan {
  const lines = content.split(/\r?\n/);
  
  let nmapVersion = '7.xx';
  let args = 'nmap scan (-oN)';
  let startTime = new Date().toISOString();

  // Extract header metadata if present
  for (const line of lines.slice(0, 10)) {
    if (line.startsWith('# Nmap')) {
      const verMatch = line.match(/Nmap\s+([0-9\.\w]+)/);
      if (verMatch) nmapVersion = verMatch[1];
      const asMatch = line.match(/as:\s+(.*)$/);
      if (asMatch) args = asMatch[1];
    }
  }

  interface TempHost {
    ip: string;
    hostname: string | null;
    status: 'up' | 'down';
    statusReason?: string;
    mac?: string;
    macVendor?: string;
    osName: string | null;
    osAccuracy: number;
    ports: PortInfo[];
  }

  const rawHosts: TempHost[] = [];
  let currentHost: TempHost | null = null;
  let currentPort: PortInfo | null = null;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();

    // 1. Host report header
    if (line.startsWith('Nmap scan report for')) {
      if (currentHost) {
        if (currentPort) currentHost.ports.push(currentPort);
        rawHosts.push(currentHost);
        currentPort = null;
      }

      // Format: Nmap scan report for hostname (IP) OR Nmap scan report for IP
      const match = line.match(/Nmap scan report for (?:([^\s\(\)]+)\s+\(([\d\.:a-fA-F]+)\)|([\d\.:a-fA-F]+)|([^\s]+))/);
      let hostname: string | null = null;
      let ip = '0.0.0.0';

      if (match) {
        if (match[1] && match[2]) {
          hostname = match[1];
          ip = match[2];
        } else if (match[3]) {
          ip = match[3];
        } else if (match[4]) {
          if (/^[\d\.:a-fA-F]+$/.test(match[4])) {
            ip = match[4];
          } else {
            hostname = match[4];
            ip = match[4];
          }
        }
      }

      currentHost = {
        ip,
        hostname,
        status: 'up', // default assumption until checked
        ports: [],
        osName: null,
        osAccuracy: 0
      };
      continue;
    }

    if (!currentHost) continue;

    // 2. Status line
    if (line.startsWith('Host is up')) {
      currentHost.status = 'up';
      const reasonMatch = line.match(/\((.*?)\)/);
      if (reasonMatch) currentHost.statusReason = reasonMatch[1];
      continue;
    } else if (line.startsWith('Host is down')) {
      currentHost.status = 'down';
      continue;
    }

    // 3. MAC address
    if (line.startsWith('MAC Address:')) {
      const macMatch = line.match(/MAC Address:\s+([0-9A-Fa-f:]+)\s*(?:\((.*?)\))?/);
      if (macMatch) {
        currentHost.mac = macMatch[1];
        currentHost.macVendor = macMatch[2] || undefined;
      }
      continue;
    }

    // 4. Port table header
    if (line.startsWith('PORT') && line.includes('STATE') && line.includes('SERVICE')) {
      continue;
    }

    // 5. Port line parsing (e.g. "80/tcp open http Apache httpd 2.4.41")
    const portMatch = line.match(/^(\d+)\/([a-z]+)\s+([a-z\|]+)\s+([^\s]+)(?:\s+(.*))?$/i);
    if (portMatch) {
      if (currentPort) {
        currentHost.ports.push(currentPort);
      }

      const portNum = parseInt(portMatch[1], 10);
      const protocol = portMatch[2].toLowerCase();
      const state = portMatch[3].toLowerCase();
      const service = portMatch[4];
      const versionStr = portMatch[5] || '';

      // Try splitting product and version
      let product: string | undefined;
      let version: string | undefined;

      if (versionStr) {
        const parts = versionStr.split(/\s+/);
        product = parts[0];
        version = parts.slice(1).join(' ') || undefined;
      }

      currentPort = {
        port: portNum,
        protocol,
        state,
        service,
        product,
        version,
        scriptOutputs: []
      };
      continue;
    }

    // 6. Script output line (e.g. "| http-title: Welcome" or "|_http-server-header: nginx")
    if (currentPort && (line.startsWith('|') || line.startsWith('|_'))) {
      const scriptLine = line.replace(/^[\|\_\s]+/, '');
      const colonIdx = scriptLine.indexOf(':');
      if (colonIdx !== -1) {
        const scriptId = scriptLine.substring(0, colonIdx).trim();
        const scriptOut = scriptLine.substring(colonIdx + 1).trim();

        if (!currentPort.scriptOutputs) currentPort.scriptOutputs = [];
        
        // Find existing script output or push new
        const existing = currentPort.scriptOutputs.find(s => s.id === scriptId);
        if (existing) {
          existing.output += `\n${scriptOut}`;
        } else {
          currentPort.scriptOutputs.push({ id: scriptId, output: scriptOut });
        }
      } else {
        // Line continuation
        if (currentPort.scriptOutputs && currentPort.scriptOutputs.length > 0) {
          currentPort.scriptOutputs[currentPort.scriptOutputs.length - 1].output += `\n${scriptLine}`;
        }
      }
      continue;
    }

    // If line stops starting with | or port pattern, save currentPort
    if (currentPort && !line.startsWith('|') && !line.startsWith('|_')) {
      currentHost.ports.push(currentPort);
      currentPort = null;
    }

    // 7. OS Details line
    if (line.startsWith('OS details:') || line.startsWith('Running:')) {
      const osStr = line.replace(/^(OS details:|Running:)\s*/, '');
      currentHost.osName = osStr;
      currentHost.osAccuracy = 90;
      continue;
    }
  }

  // Save last host
  if (currentHost) {
    if (currentPort) currentHost.ports.push(currentPort);
    rawHosts.push(currentHost);
  }

  let totalOpenPorts = 0;
  let totalFilteredPorts = 0;
  let totalClosedPorts = 0;
  let hostsUpCount = 0;
  let hostsDownCount = 0;
  const serviceCounts: Record<string, number> = {};

  const hosts: HostInfo[] = rawHosts.map((h, index) => {
    if (h.status === 'up') hostsUpCount++;
    else hostsDownCount++;

    h.ports.forEach(p => {
      if (p.state === 'open') {
        totalOpenPorts++;
        if (p.service) serviceCounts[p.service] = (serviceCounts[p.service] || 0) + 1;
      } else if (p.state === 'filtered') totalFilteredPorts++;
      else if (p.state === 'closed') totalClosedPorts++;
    });

    const os: HostOS = {
      name: h.osName,
      accuracy: h.osAccuracy
    };

    const { riskFlags, riskScore } = analyzeHostRisks(h.ip, h.ports, os.name);

    return {
      id: `host-normal-${h.ip}-${index}`,
      ip: h.ip,
      mac: h.mac,
      macVendor: h.macVendor,
      hostname: h.hostname,
      hostnames: h.hostname ? [h.hostname] : [],
      status: h.status,
      statusReason: h.statusReason,
      os,
      ports: h.ports,
      riskScore,
      riskFlags
    };
  });

  let mostCommonService = 'None';
  let maxCount = 0;
  Object.entries(serviceCounts).forEach(([svc, count]) => {
    if (count > maxCount) {
      maxCount = count;
      mostCommonService = `${svc} (${count})`;
    }
  });

  const scanId = `scan-normal-${Date.now()}`;
  const meta: ScanMeta = {
    scanId,
    filename,
    format: 'normal',
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
