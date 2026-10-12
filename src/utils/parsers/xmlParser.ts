import { XMLParser } from 'fast-xml-parser';
import type { HostInfo, HostOS, NormalizedScan, PortInfo, ScanMeta, ScriptOutput } from '../../types/nmap';
import { analyzeHostRisks } from '../riskEngine';

export function parseXmlNmap(xmlContent: string, filename: string): NormalizedScan {
  const parser = new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: '@_',
    isArray: (name) => ['host', 'port', 'address', 'hostname', 'script', 'osmatch', 'cpe'].includes(name)
  });

  const parsed = parser.parse(xmlContent);
  const nmaprun = parsed?.nmaprun;

  if (!nmaprun) {
    throw new Error('Invalid Nmap XML format: Missing <nmaprun> root tag.');
  }

  const startTimestamp = nmaprun['@_start'] ? new Date(parseInt(nmaprun['@_start'], 10) * 1000).toISOString() : new Date().toISOString();
  const args = nmaprun['@_args'] || 'nmap scan';
  const nmapVersion = nmaprun['@_version'] || 'Unknown';

  const rawHostList = nmaprun.host ? (Array.isArray(nmaprun.host) ? nmaprun.host : [nmaprun.host]) : [];

  let totalOpenPorts = 0;
  let totalFilteredPorts = 0;
  let totalClosedPorts = 0;
  let hostsUpCount = 0;
  let hostsDownCount = 0;
  const serviceCounts: Record<string, number> = {};

  const hosts: HostInfo[] = rawHostList.map((h: any, index: number) => {
    // 1. Status
    const statusObj = h.status || {};
    const statusState = (statusObj['@_state'] || 'down').toLowerCase();
    const isUp = statusState === 'up';

    if (isUp) hostsUpCount++;
    else hostsDownCount++;

    // 2. Addresses
    const addresses = h.address ? (Array.isArray(h.address) ? h.address : [h.address]) : [];
    let ip = `127.0.0.${index + 1}`;
    let ipv6: string | undefined;
    let mac: string | undefined;
    let macVendor: string | undefined;

    addresses.forEach((addr: any) => {
      const type = addr['@_addrtype'];
      if (type === 'ipv4') ip = addr['@_addr'];
      else if (type === 'ipv6') ipv6 = addr['@_addr'];
      else if (type === 'mac') {
        mac = addr['@_addr'];
        macVendor = addr['@_vendor'];
      }
    });

    // 3. Hostnames
    const hostnamesObj = h.hostnames?.hostname;
    const hostnameList = hostnamesObj ? (Array.isArray(hostnamesObj) ? hostnamesObj : [hostnamesObj]) : [];
    const hostnames = hostnameList.map((hn: any) => hn['@_name']).filter(Boolean);
    const primaryHostname = hostnames[0] || null;

    // 4. Ports
    const portsObj = h.ports?.port;
    const rawPortList = portsObj ? (Array.isArray(portsObj) ? portsObj : [portsObj]) : [];

    const ports: PortInfo[] = rawPortList.map((p: any) => {
      const portNum = parseInt(p['@_portid'], 10);
      const protocol = p['@_protocol'] || 'tcp';
      const state = p.state?.['@_state'] || 'unknown';
      const stateReason = p.state?.['@_reason'];

      if (state === 'open') totalOpenPorts++;
      else if (state === 'filtered') totalFilteredPorts++;
      else if (state === 'closed') totalClosedPorts++;

      const serviceObj = p.service || {};
      const serviceName = serviceObj['@_name'] || 'unknown';
      if (state === 'open' && serviceName !== 'unknown') {
        serviceCounts[serviceName] = (serviceCounts[serviceName] || 0) + 1;
      }

      const product = serviceObj['@_product'];
      const version = serviceObj['@_version'];
      const extraInfo = serviceObj['@_extrainfo'];

      // CPEs
      const cpeList = serviceObj.cpe ? (Array.isArray(serviceObj.cpe) ? serviceObj.cpe : [serviceObj.cpe]) : [];

      // Scripts
      const scriptsObj = p.script;
      const scriptList = scriptsObj ? (Array.isArray(scriptsObj) ? scriptsObj : [scriptsObj]) : [];
      const scriptOutputs: ScriptOutput[] = scriptList.map((s: any) => ({
        id: s['@_id'] || 'script',
        output: typeof s['@_output'] === 'string' ? s['@_output'] : JSON.stringify(s)
      }));

      return {
        port: portNum,
        protocol,
        state,
        stateReason,
        service: serviceName,
        product,
        version,
        extraInfo,
        cpe: cpeList,
        scriptOutputs
      };
    });

    // 5. OS Guess
    const osObj = h.os;
    const osMatches = osObj?.osmatch ? (Array.isArray(osObj.osmatch) ? osObj.osmatch : [osObj.osmatch]) : [];
    const topMatch = osMatches[0];

    const os: HostOS = {
      name: topMatch ? topMatch['@_name'] : null,
      accuracy: topMatch ? parseInt(topMatch['@_accuracy'] || '0', 10) : 0,
      family: topMatch?.osclass ? (Array.isArray(topMatch.osclass) ? topMatch.osclass[0]?.['@_osfamily'] : topMatch.osclass['@_osfamily']) : undefined,
      matches: osMatches.map((m: any) => ({
        name: m['@_name'],
        accuracy: parseInt(m['@_accuracy'] || '0', 10)
      }))
    };

    // 6. Risk Engine Analysis
    const { riskFlags, riskScore } = analyzeHostRisks(ip, ports, os.name);

    return {
      id: `host-${ip}-${index}`,
      ip,
      ipv6,
      mac,
      macVendor,
      hostname: primaryHostname,
      hostnames,
      status: isUp ? 'up' : 'down',
      statusReason: statusObj['@_reason'],
      os,
      ports,
      riskScore,
      riskFlags
    };
  });

  // Calculate Most Common Service
  let mostCommonService = 'None';
  let maxCount = 0;
  Object.entries(serviceCounts).forEach(([svc, count]) => {
    if (count > maxCount) {
      maxCount = count;
      mostCommonService = `${svc} (${count})`;
    }
  });

  const scanId = `scan-xml-${Date.now()}`;
  const meta: ScanMeta = {
    scanId,
    filename,
    format: 'xml',
    startTime: startTimestamp,
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
    rawContent: xmlContent,
    uploadedAt: new Date().toISOString()
  };
}
