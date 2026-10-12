import type { InputFormat } from '../../types/nmap';

export function detectFormat(content: string): InputFormat {
  const trimmed = content.trim();

  // XML Sniffing: starts with <?xml or <nmaprun
  if (trimmed.startsWith('<?xml') || trimmed.includes('<nmaprun')) {
    return 'xml';
  }

  // Grepable Sniffing: lines starting with Host: ... Ports: or # Nmap ... scan initiated ... as a grepable file
  if (
    trimmed.includes('# Nmap') && trimmed.includes('Grepable') ||
    /^Host:\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/m.test(trimmed) ||
    /Host:\s+.*Ports:\s+/m.test(trimmed)
  ) {
    return 'grepable';
  }

  // Normal Sniffing: Starting with # Nmap X.XX scan initiated or standard "Nmap scan report for"
  if (
    trimmed.startsWith('# Nmap') ||
    trimmed.includes('Nmap scan report for') ||
    trimmed.includes('PORT     STATE SERVICE') ||
    trimmed.includes('Nmap done at')
  ) {
    return 'normal';
  }

  // Script Kiddie (-oS) check: contains l33t speak patterns like "NmAp sCaN rEpOrT"
  if (trimmed.includes('NmAp sCaN') || trimmed.includes('pOrT')) {
    return 'normal'; // Normalize script kiddie as normal text
  }

  return 'unknown';
}
