import React, { useEffect, useRef, useState } from 'react';
import * as d3 from 'd3';
import { GitFork } from 'lucide-react';
import type { HostInfo, NormalizedScan } from '../../types/nmap';
import { Card } from '../common/Card';
import { HostDetailDrawer } from '../hosts/HostDetailDrawer';

interface TopologyGraphProps {
  scan: NormalizedScan;
}

export const TopologyGraph: React.FC<TopologyGraphProps> = ({ scan }) => {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const [sizeMode, setSizeMode] = useState<'ports' | 'risk'>('ports');
  const [selectedHost, setSelectedHost] = useState<HostInfo | null>(null);

  useEffect(() => {
    if (!svgRef.current || !scan.hosts || scan.hosts.length === 0) return;

    const width = svgRef.current.parentElement?.clientWidth || 900;
    const height = 550;

    // Clear previous elements
    d3.select(svgRef.current).selectAll('*').remove();

    const svg = d3
      .select(svgRef.current)
      .attr('width', width)
      .attr('height', height)
      .attr('viewBox', [0, 0, width, height]);

    // Group IP hosts by subnet (e.g. 192.168.1.x)
    const subnetMap = new Map<string, HostInfo[]>();
    scan.hosts.forEach((h) => {
      const parts = h.ip.split('.');
      const subnet = parts.length === 4 ? `${parts[0]}.${parts[1]}.${parts[2]}.0/24` : 'Default Network';
      if (!subnetMap.has(subnet)) subnetMap.set(subnet, []);
      subnetMap.get(subnet)!.push(h);
    });

    // Build Graph Data
    interface NodeData extends d3.SimulationNodeDatum {
      id: string;
      ip: string;
      label: string;
      isSubnet?: boolean;
      hostObj?: HostInfo;
      riskScore?: number;
      openPortsCount?: number;
    }

    interface LinkData extends d3.SimulationLinkDatum<NodeData> {
      source: string | NodeData;
      target: string | NodeData;
    }

    const nodes: NodeData[] = [];
    const links: LinkData[] = [];

    subnetMap.forEach((hosts, subnet) => {
      // Subnet Center Node
      nodes.push({
        id: `subnet-${subnet}`,
        ip: subnet,
        label: subnet,
        isSubnet: true
      });

      hosts.forEach((h) => {
        const openPortsCount = h.ports.filter((p) => p.state === 'open').length;
        nodes.push({
          id: h.id,
          ip: h.ip,
          label: h.hostname ? `${h.ip}\n(${h.hostname})` : h.ip,
          isSubnet: false,
          hostObj: h,
          riskScore: h.riskScore,
          openPortsCount
        });

        links.push({
          source: `subnet-${subnet}`,
          target: h.id
        });
      });
    });

    // Zoom setup
    const g = svg.append('g');

    const zoom = d3
      .zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.2, 4])
      .on('zoom', (event) => {
        g.attr('transform', event.transform);
      });

    svg.call(zoom as any);

    // Simulation Setup
    const simulation = d3
      .forceSimulation<NodeData>(nodes)
      .force(
        'link',
        d3.forceLink<NodeData, LinkData>(links).id((d) => d.id).distance(80)
      )
      .force('charge', d3.forceManyBody().strength(-280))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide().radius(35));

    // Render Links
    const link = g
      .append('g')
      .selectAll('line')
      .data(links)
      .join('line')
      .attr('stroke', '#272d3d')
      .attr('stroke-width', 1.5)
      .attr('stroke-dasharray', (d: any) => (d.target.isSubnet ? '3,3' : 'none'));

    // Render Node Containers
    const node = g
      .append('g')
      .selectAll<SVGGElement, NodeData>('.node')
      .data(nodes)
      .join('g')
      .attr('class', 'node')
      .style('cursor', 'pointer')
      .call(
        d3
          .drag<SVGGElement, NodeData>()
          .on('start', (event, d) => {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
          })
          .on('drag', (event, d) => {
            d.fx = event.x;
            d.fy = event.y;
          })
          .on('end', (event, d) => {
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
          }) as any
      )
      .on('click', (_, d) => {
        if (d.hostObj) setSelectedHost(d.hostObj);
      });

    // Node Circles
    node
      .append('circle')
      .attr('r', (d) => {
        if (d.isSubnet) return 16;
        if (sizeMode === 'risk') return Math.max(12, Math.min(30, (d.riskScore || 0) / 3));
        return Math.max(12, Math.min(28, (d.openPortsCount || 0) * 3 + 10));
      })
      .attr('fill', (d) => {
        if (d.isSubnet) return '#0f172a';
        const score = d.riskScore || 0;
        if (score >= 50) return '#ef4444';
        if (score >= 25) return '#f59e0b';
        return '#06b6d4';
      })
      .attr('stroke', (d) => (d.isSubnet ? '#06b6d4' : '#1e293b'))
      .attr('stroke-width', 2);

    // Node Icons / Text
    node
      .append('text')
      .text((d) => (d.isSubnet ? 'SUBNET' : d.ip))
      .attr('dy', (d) => (d.isSubnet ? 26 : 24))
      .attr('text-anchor', 'middle')
      .attr('fill', '#cbd5e1')
      .attr('font-size', '10px')
      .attr('font-family', 'JetBrains Mono');

    // Tooltip Title on Hover
    node.append('title').text((d) =>
      d.isSubnet
        ? `Subnet Range: ${d.ip}`
        : `Host: ${d.ip}\nHostname: ${d.hostObj?.hostname || 'N/A'}\nOpen Ports: ${d.openPortsCount}\nRisk Score: ${d.riskScore}/100`
    );

    simulation.on('tick', () => {
      link
        .attr('x1', (d: any) => d.source.x)
        .attr('y1', (d: any) => d.source.y)
        .attr('x2', (d: any) => d.target.x)
        .attr('y2', (d: any) => d.target.y);

      node.attr('transform', (d: any) => `translate(${d.x},${d.y})`);
    });
  }, [scan, sizeMode]);

  return (
    <Card
      title="Network Topology & Node Relationship Graph"
      subtitle="Interactive D3 force-directed visualization of subnets and target hosts"
      icon={<GitFork className="w-4 h-4 text-cyan-400" />}
      headerAction={
        <div className="flex items-center space-x-2">
          <span className="text-xs text-slate-400 font-mono">Node Sizing:</span>
          <button
            onClick={() => setSizeMode(sizeMode === 'ports' ? 'risk' : 'ports')}
            className="px-2.5 py-1 rounded bg-[#1f2638] text-cyan-300 border border-cyan-800/80 text-xs font-mono font-semibold cursor-pointer"
          >
            {sizeMode === 'ports' ? 'Open Ports Count' : 'Risk Score Level'}
          </button>
        </div>
      }
    >
      <div className="relative bg-[#090b0e] border border-[#202636] rounded-lg overflow-hidden">
        <svg ref={svgRef} className="w-full h-[550px] bg-[#090b0e]"></svg>

        {/* Legend Overlay */}
        <div className="absolute bottom-3 left-3 bg-[#0f121a]/90 border border-[#202636] p-3 rounded-lg font-mono text-[11px] space-y-1.5 backdrop-blur-xs">
          <div className="text-slate-400 font-bold mb-1">NODE COLOR KEY</div>
          <div className="flex items-center space-x-2">
            <span className="w-3 h-3 rounded-full bg-rose-500 inline-block"></span>
            <span className="text-slate-200">High / Critical Risk (50+)</span>
          </div>
          <div className="flex items-center space-x-2">
            <span className="w-3 h-3 rounded-full bg-amber-500 inline-block"></span>
            <span className="text-slate-200">Medium Risk (25-49)</span>
          </div>
          <div className="flex items-center space-x-2">
            <span className="w-3 h-3 rounded-full bg-cyan-500 inline-block"></span>
            <span className="text-slate-200">Low / Healthy Host</span>
          </div>
        </div>
      </div>

      <HostDetailDrawer
        host={selectedHost}
        isOpen={selectedHost !== null}
        onClose={() => setSelectedHost(null)}
      />
    </Card>
  );
};
