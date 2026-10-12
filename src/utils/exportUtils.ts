import jsPDF from 'jspdf';
import html2canvas from 'html2canvas';
import type { NormalizedScan } from '../types/nmap';

export function exportToJson(scan: NormalizedScan) {
  const jsonStr = JSON.stringify(scan, null, 2);
  const blob = new Blob([jsonStr], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `${scan.meta.filename.replace(/\.[^/.]+$/, '')}_normalized.json`;
  a.click();
  URL.revokeObjectURL(url);
}

export function exportToCsv(scan: NormalizedScan) {
  const headers = ['IP Address', 'Hostname', 'Status', 'OS Guess', 'Open Ports Count', 'Open Ports List', 'Risk Score', 'Risk Flags Count'];
  const rows: string[][] = [headers];

  scan.hosts.forEach(h => {
    const openPorts = h.ports.filter(p => p.state === 'open');
    const openPortList = openPorts.map(p => `${p.port}/${p.protocol} (${p.service || 'unknown'})`).join('; ');

    rows.push([
      `"${h.ip}"`,
      `"${h.hostname || ''}"`,
      `"${h.status}"`,
      `"${h.os.name || 'Unknown'}"`,
      `"${openPorts.length}"`,
      `"${openPortList}"`,
      `"${h.riskScore}"`,
      `"${h.riskFlags.length}"`
    ]);
  });

  const csvContent = rows.map(e => e.join(',')).join('\n');
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `${scan.meta.filename.replace(/\.[^/.]+$/, '')}_hosts.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

export async function exportToPdf(elementId: string, filename: string): Promise<boolean> {
  const element = document.getElementById(elementId);
  if (!element) return false;

  try {
    const canvas = await html2canvas(element, {
      scale: 2,
      backgroundColor: '#0b0d11',
      useCORS: true,
      logging: false
    });

    const imgData = canvas.toDataURL('image/png');
    const pdf = new jsPDF({
      orientation: 'portrait',
      unit: 'mm',
      format: 'a4'
    });

    const imgWidth = 210; // A4 width in mm
    const pageHeight = 297; // A4 height in mm
    const imgHeight = (canvas.height * imgWidth) / canvas.width;
    let heightLeft = imgHeight;
    let position = 0;

    pdf.addImage(imgData, 'PNG', 0, position, imgWidth, imgHeight);
    heightLeft -= pageHeight;

    while (heightLeft >= 0) {
      position = heightLeft - imgHeight;
      pdf.addPage();
      pdf.addImage(imgData, 'PNG', 0, position, imgWidth, imgHeight);
      heightLeft -= pageHeight;
    }

    pdf.save(`${filename.replace(/\.[^/.]+$/, '')}_report.pdf`);
    return true;
  } catch (err) {
    console.error('Failed to export PDF:', err);
    return false;
  }
}
