import type { HostDiff, NormalizedScan, PortInfo, ScanDiff } from '../types/nmap';

export function compareScans(scanA: NormalizedScan, scanB: NormalizedScan): ScanDiff {
  const hostsA = new Map(scanA.hosts.map(h => [h.ip, h]));
  const hostsB = new Map(scanB.hosts.map(h => [h.ip, h]));

  const allIps = Array.from(new Set([...hostsA.keys(), ...hostsB.keys()]));
  const hostDiffs: HostDiff[] = [];

  let addedHostsCount = 0;
  let removedHostsCount = 0;
  let newlyOpenedPortsCount = 0;
  let newlyClosedPortsCount = 0;

  allIps.forEach(ip => {
    const hostA = hostsA.get(ip);
    const hostB = hostsB.get(ip);

    if (!hostA && hostB) {
      // Host added in Scan B
      addedHostsCount++;
      const openPorts = hostB.ports.filter(p => p.state === 'open');
      newlyOpenedPortsCount += openPorts.length;

      hostDiffs.push({
        ip,
        hostname: hostB.hostname,
        type: 'added',
        openedPorts: openPorts,
        closedPorts: [],
        modifiedPorts: [],
        riskDelta: hostB.riskScore
      });
    } else if (hostA && !hostB) {
      // Host removed in Scan B
      removedHostsCount++;
      const openPorts = hostA.ports.filter(p => p.state === 'open');
      newlyClosedPortsCount += openPorts.length;

      hostDiffs.push({
        ip,
        hostname: hostA.hostname,
        type: 'removed',
        openedPorts: [],
        closedPorts: openPorts,
        modifiedPorts: [],
        riskDelta: -hostA.riskScore
      });
    } else if (hostA && hostB) {
      // Both scans contain host -> inspect ports & status
      const portsA = new Map(hostA.ports.map(p => [`${p.port}/${p.protocol}`, p]));
      const portsB = new Map(hostB.ports.map(p => [`${p.port}/${p.protocol}`, p]));

      const openedPorts: PortInfo[] = [];
      const closedPorts: PortInfo[] = [];
      const modifiedPorts: Array<{ port: number; protocol: string; oldVersion?: string; newVersion?: string }> = [];

      const allPortKeys = Array.from(new Set([...portsA.keys(), ...portsB.keys()]));

      allPortKeys.forEach(key => {
        const pA = portsA.get(key);
        const pB = portsB.get(key);

        if ((!pA || pA.state !== 'open') && pB && pB.state === 'open') {
          openedPorts.push(pB);
          newlyOpenedPortsCount++;
        } else if (pA && pA.state === 'open' && (!pB || pB.state !== 'open')) {
          closedPorts.push(pA);
          newlyClosedPortsCount++;
        } else if (pA && pB && pA.state === 'open' && pB.state === 'open') {
          const vA = `${pA.product || ''} ${pA.version || ''}`.trim();
          const vB = `${pB.product || ''} ${pB.version || ''}`.trim();
          if (vA !== vB) {
            modifiedPorts.push({
              port: pA.port,
              protocol: pA.protocol,
              oldVersion: vA || 'Unknown',
              newVersion: vB || 'Unknown'
            });
          }
        }
      });

      const hasChanges = openedPorts.length > 0 || closedPorts.length > 0 || modifiedPorts.length > 0 || hostA.status !== hostB.status;

      hostDiffs.push({
        ip,
        hostname: hostB.hostname || hostA.hostname,
        type: hasChanges ? 'modified' : 'unchanged',
        statusChange: hostA.status !== hostB.status ? { from: hostA.status, to: hostB.status } : undefined,
        openedPorts,
        closedPorts,
        modifiedPorts,
        riskDelta: hostB.riskScore - hostA.riskScore
      });
    }
  });

  return {
    scanAId: scanA.id,
    scanBId: scanB.id,
    scanAName: scanA.meta.filename,
    scanBName: scanB.meta.filename,
    addedHostsCount,
    removedHostsCount,
    newlyOpenedPortsCount,
    newlyClosedPortsCount,
    hostDiffs
  };
}
