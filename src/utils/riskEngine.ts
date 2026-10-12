import type { PortInfo, RiskFlag } from '../types/nmap';

export function analyzeHostRisks(ip: string, ports: PortInfo[], _osName?: string | null): { riskFlags: RiskFlag[]; riskScore: number } {
  const flags: RiskFlag[] = [];

  ports.forEach((p) => {
    if (p.state !== 'open') return;

    const portNum = p.port;
    const service = (p.service || '').toLowerCase();
    const product = (p.product || '').toLowerCase();
    const version = (p.version || '').toLowerCase();
    const combinedVersion = `${product} ${version}`.trim();
    const scriptOutputs = p.scriptOutputs || [];

    // 1. Unencrypted Remote Management & Cleartext Auth
    if (portNum === 23 || service.includes('telnet')) {
      flags.push({
        id: `telnet-${ip}-${portNum}`,
        severity: 'high',
        title: 'Unencrypted Telnet Service Exposed',
        category: 'Unencrypted Protocol',
        port: portNum,
        protocol: p.protocol,
        service: p.service,
        description: 'Telnet transmits login credentials and administrative traffic in plain text across the network.',
        remediation: 'Disable Telnet and replace with SSH (Port 22) enforcing key-based or strong password authentication.',
        evidence: `Port ${portNum}/${p.protocol} state: open (Service: ${p.service || 'telnet'})`
      });
    }

    if (portNum === 21 || service.includes('ftp')) {
      flags.push({
        id: `ftp-${ip}-${portNum}`,
        severity: 'medium',
        title: 'Cleartext FTP Protocol Operational',
        category: 'Unencrypted Protocol',
        port: portNum,
        protocol: p.protocol,
        service: p.service,
        description: 'Standard FTP passes credentials without encryption unless explicit FTPS/TLS is enforced.',
        remediation: 'Migrate to SFTP (over SSH) or mandate FTPS with TLS 1.2+ encryption.',
        evidence: `Port ${portNum}/${p.protocol} service: ${p.service || 'ftp'} ${combinedVersion}`
      });
    }

    if (portNum === 80 && !ports.some(hp => (hp.port === 443 || hp.service.includes('https')) && hp.state === 'open')) {
      flags.push({
        id: `http-no-tls-${ip}-${portNum}`,
        severity: 'low',
        title: 'Plain HTTP Exposed Without HTTPS Endpoint',
        category: 'Unencrypted Protocol',
        port: portNum,
        protocol: p.protocol,
        service: p.service,
        description: 'Web server operating on unencrypted HTTP without a corresponding HTTPS service detected on standard ports.',
        remediation: 'Deploy TLS certificates (e.g. Let\'s Encrypt) and redirect all HTTP traffic to HTTPS.',
        evidence: `Port 80/tcp open. Product: ${combinedVersion || 'HTTP server'}`
      });
    }

    // 2. Database Exposure
    if (portNum === 3306 || service.includes('mysql')) {
      flags.push({
        id: `mysql-${ip}-${portNum}`,
        severity: 'high',
        title: 'MySQL Database Port Externally Reachable',
        category: 'Database Exposure',
        port: portNum,
        protocol: p.protocol,
        service: p.service,
        description: 'Direct exposure of database ports allows brute-force attacks and potential remote exploit vectors.',
        remediation: 'Bind database listener to 127.0.0.1 or internal subnet, or restrict access via firewall rules / VPN.',
        evidence: `Port 3306 open. Banner: ${combinedVersion || 'MySQL'}`
      });
    }

    if (portNum === 5432 || service.includes('postgres')) {
      flags.push({
        id: `postgres-${ip}-${portNum}`,
        severity: 'high',
        title: 'PostgreSQL Database Exposed',
        category: 'Database Exposure',
        port: portNum,
        protocol: p.protocol,
        service: p.service,
        description: 'PostgreSQL relational database service exposed on network interface.',
        remediation: 'Configure pg_hba.conf to restrict client IP ranges and enforce strong password auth / SSL.',
        evidence: `Port 5432 open. Product: ${combinedVersion || 'PostgreSQL'}`
      });
    }

    if (portNum === 27017 || service.includes('mongodb')) {
      flags.push({
        id: `mongodb-${ip}-${portNum}`,
        severity: 'critical',
        title: 'MongoDB NoSQL Instance exposed',
        category: 'Database Exposure',
        port: portNum,
        protocol: p.protocol,
        service: p.service,
        description: 'Unfiltered MongoDB instances frequently lack default authentication, risking instant data leakage.',
        remediation: 'Enable security authorization in mongod.conf (`security.authorization: enabled`) and block port 27017.',
        evidence: `Port 27017 open. Service: ${p.service}`
      });
    }

    if (portNum === 6379 || service.includes('redis')) {
      flags.push({
        id: `redis-${ip}-${portNum}`,
        severity: 'critical',
        title: 'Redis Cache Service Exposed',
        category: 'Database Exposure',
        port: portNum,
        protocol: p.protocol,
        service: p.service,
        description: 'Redis servers by default have no password. Exposed Redis instances can allow Remote Code Execution via SSH authorized_keys file write.',
        remediation: 'Set `requirepass` in redis.conf, enable protected-mode, and bind to localhost.',
        evidence: `Port 6379 open. Product: ${combinedVersion || 'Redis'}`
      });
    }

    if (portNum === 9200 || service.includes('elasticsearch')) {
      flags.push({
        id: `elastic-${ip}-${portNum}`,
        severity: 'high',
        title: 'Elasticsearch REST API exposed',
        category: 'Database Exposure',
        port: portNum,
        protocol: p.protocol,
        service: p.service,
        description: 'Unauthenticated Elasticsearch HTTP API allows arbitrary data indexing, reading, and cluster wiping.',
        remediation: 'Enable X-Pack security authorization and HTTPS TLS on Elasticsearch nodes.',
        evidence: `Port 9200 open. Service: ${p.service}`
      });
    }

    // 3. SMB / NetBIOS Risks
    if (portNum === 445 || portNum === 139 || service.includes('microsoft-ds') || service.includes('netbios')) {
      flags.push({
        id: `smb-${ip}-${portNum}`,
        severity: 'high',
        title: 'SMB / NetBIOS File Sharing Exposed',
        category: 'SMB / NetBIOS Risk',
        port: portNum,
        protocol: p.protocol,
        service: p.service,
        description: 'SMB services are primary targets for ransomware propagation (e.g. WannaCry, EternalBlue CVE-2017-0144) and credential hash dumping.',
        remediation: 'Disable SMBv1. Restrict SMB access (port 445) strictly to internal Domain subnets.',
        evidence: `Port ${portNum} open (${p.service}). Version: ${combinedVersion || 'SMB/CIFS'}`
      });
    }

    // 4. Remote Desktop / Admin Access
    if (portNum === 3389 || service.includes('ms-wbt-server') || service.includes('rdp')) {
      flags.push({
        id: `rdp-${ip}-${portNum}`,
        severity: 'medium',
        title: 'RDP (Remote Desktop Protocol) Exposed',
        category: 'Dangerous Port',
        port: portNum,
        protocol: p.protocol,
        service: p.service,
        description: 'Exposed Windows RDP ports are heavily targeted for password guessing and BlueKeep (CVE-2019-0708) exploitation.',
        remediation: 'Enforce Network Level Authentication (NLA), place RDP behind a VPN, or use a Remote Desktop Gateway.',
        evidence: `Port 3389/tcp open. Service: ${p.service}`
      });
    }

    if (portNum === 5900 || service.includes('vnc')) {
      flags.push({
        id: `vnc-${ip}-${portNum}`,
        severity: 'high',
        title: 'VNC Remote Graphical Desktop Exposed',
        category: 'Dangerous Port',
        port: portNum,
        protocol: p.protocol,
        service: p.service,
        description: 'VNC protocol often suffers from weak authentication or cleartext stream transmission.',
        remediation: 'Tunnel VNC traffic inside SSH or VPN and set complex authentication passwords.',
        evidence: `Port 5900 open (${combinedVersion || 'VNC'})`
      });
    }

    // 5. Outdated / Vulnerable Software Versions
    if (combinedVersion.toLowerCase().includes('vsftpd 2.3.4')) {
      flags.push({
        id: `vsftpd-backdoor-${ip}-${portNum}`,
        severity: 'critical',
        title: 'CRITICAL: vsftpd 2.3.4 Backdoor Signature Detected',
        category: 'Vulnerable Service',
        port: portNum,
        protocol: p.protocol,
        service: p.service,
        description: 'vsftpd version 2.3.4 contains a famous malicious backdoor triggering a root shell on port 6200 when a username ending with `:)` is supplied.',
        remediation: 'Immediately remove or update vsftpd to a patched stable release.',
        cve: ['CVE-2011-2523'],
        evidence: `Banner matched: ${combinedVersion}`
      });
    }

    if (combinedVersion.toLowerCase().includes('openssh') && (combinedVersion.includes('4.') || combinedVersion.includes('5.') || combinedVersion.includes('6.'))) {
      flags.push({
        id: `old-openssh-${ip}-${portNum}`,
        severity: 'medium',
        title: 'Legacy OpenSSH Version Detected',
        category: 'Vulnerable Service',
        port: portNum,
        protocol: p.protocol,
        service: p.service,
        description: 'OpenSSH version prior to 7.4 contains deprecated ciphers, user enumeration vulnerabilities, and potential memory disclosure risks.',
        remediation: 'Upgrade OpenSSH package to latest repository version and disable weak ciphers in sshd_config.',
        evidence: `Version string: ${combinedVersion}`
      });
    }

    if (combinedVersion.toLowerCase().includes('apache/2.2') || combinedVersion.toLowerCase().includes('apache/2.0')) {
      flags.push({
        id: `old-apache-${ip}-${portNum}`,
        severity: 'high',
        title: 'End-of-Life Apache HTTP Server Version',
        category: 'Vulnerable Service',
        port: portNum,
        protocol: p.protocol,
        service: p.service,
        description: 'Apache 2.2.x reached End of Life in 2017 and suffers from multiple unpatched vulnerabilities.',
        remediation: 'Upgrade web server to Apache 2.4.x or modern Nginx.',
        evidence: `Server banner: ${combinedVersion}`
      });
    }

    // 6. NSE Script Outputs Evaluation
    scriptOutputs.forEach((so) => {
      const id = so.id.toLowerCase();
      const out = so.output.toLowerCase();

      if (id.includes('ftp-anon') || out.includes('anonymous FTP login allowed')) {
        flags.push({
          id: `ftp-anon-${ip}-${portNum}`,
          severity: 'high',
          title: 'Anonymous FTP Access Enabled',
          category: 'Anonymous Access',
          port: portNum,
          protocol: p.protocol,
          service: p.service,
          description: 'The FTP server permits unauthenticated users to log in using the `anonymous` user handle.',
          remediation: 'Disable anonymous logins in FTP daemon configuration file (`anonymous_enable=NO`).',
          evidence: `NSE script output (${so.id}):\n${so.output}`
        });
      }

      if (id.includes('http-title') && (out.includes('index of /') || out.includes('directory listing'))) {
        flags.push({
          id: `http-dir-list-${ip}-${portNum}`,
          severity: 'low',
          title: 'Web Directory Indexing / Listing Enabled',
          category: 'Information Disclosure',
          port: portNum,
          protocol: p.protocol,
          service: p.service,
          description: 'Web server returns directory file listings when index file is absent, revealing sensitive scripts or backups.',
          remediation: 'Disable directory browsing (`Options -Indexes` in Apache, `autoindex off` in Nginx).',
          evidence: `NSE script output (${so.id}): ${so.output.trim()}`
        });
      }

      if (id.includes('ssl-enum-ciphers') && (out.includes('sslv3') || out.includes('tlsv1.0') || out.includes('cbc') || out.includes('sweet32') || out.includes('rc4'))) {
        flags.push({
          id: `ssl-weak-ciphers-${ip}-${portNum}`,
          severity: 'medium',
          title: 'Depreciated SSL/TLS Ciphers or Protocols Supported',
          category: 'Vulnerable Service',
          port: portNum,
          protocol: p.protocol,
          service: p.service,
          description: 'Server accepts legacy SSLv3/TLS 1.0 protocols or weak ciphers susceptible to POODLE, BEAST, or SWEET32 attacks.',
          remediation: 'Configure web server to support only TLS 1.2 and TLS 1.3 with modern AEAD cipher suites.',
          evidence: `NSE script output snippet:\n${so.output.slice(0, 200)}...`
        });
      }

      if (id.includes('vuln') || id.includes('exploit') || out.includes('vulnerable: yes') || out.includes('state: vulnerable')) {
        flags.push({
          id: `nse-vuln-${id}-${ip}-${portNum}`,
          severity: 'critical',
          title: `NSE Vulnerability Script Warning: ${so.id}`,
          category: 'Vulnerable Service',
          port: portNum,
          protocol: p.protocol,
          service: p.service,
          description: `Nmap script '${so.id}' flagged a potential vulnerability finding on this host.`,
          remediation: 'Inspect full script output, verify patch status, and apply vendor security updates immediately.',
          evidence: `NSE Script (${so.id}):\n${so.output}`
        });
      }

      if (id.includes('smb-os-discovery') && out.includes('smbv1: enabled')) {
        flags.push({
          id: `smbv1-enabled-${ip}-${portNum}`,
          severity: 'high',
          title: 'SMBv1 Protocol Enabled on Host',
          category: 'SMB / NetBIOS Risk',
          port: portNum,
          protocol: p.protocol,
          service: p.service,
          description: 'Legacy SMBv1 protocol is enabled. SMBv1 lacks modern security controls and is vulnerable to remote exploit code.',
          remediation: 'Disable SMBv1 via PowerShell: `Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol`.',
          evidence: `NSE Script (${so.id}): ${so.output}`
        });
      }
    });
  });

  // Calculate Risk Score (0 - 100)
  let score = 0;
  flags.forEach(f => {
    switch (f.severity) {
      case 'critical': score += 40; break;
      case 'high': score += 25; break;
      case 'medium': score += 12; break;
      case 'low': score += 5; break;
      case 'info': score += 1; break;
    }
  });

  return {
    riskFlags: flags,
    riskScore: Math.min(100, score)
  };
}
