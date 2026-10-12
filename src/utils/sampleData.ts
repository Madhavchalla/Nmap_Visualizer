import { parseNmapScan } from './parsers/nmapParser';
import type { NormalizedScan } from '../types/nmap';

const SAMPLE_ENTERPRISE_XML = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun SYSTEM "https://nmap.org/data/nmap.dtd">
<nmaprun scanner="nmap" args="nmap -sS -sV -O -sC -T4 -oX corp_audit.xml 10.0.4.0/24" start="1774880000" version="7.94">
<host starttime="1774880000" endtime="1774880010">
  <status state="up" reason="echo-reply"/>
  <address addr="10.0.4.1" addrtype="ipv4"/>
  <address addr="00:50:56:A1:B2:C3" addrtype="mac" vendor="VMware"/>
  <hostnames><hostname name="fw-gateway.corp.local" type="user"/></hostnames>
  <ports>
    <port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="8.9p1 Ubuntu 3ubuntu0.1"/><script id="ssh-hostkey" output="256 ed25519:e4:65:6d:84 (ED25519)"/></port>
    <port protocol="tcp" portid="53"><state state="open" reason="syn-ack"/><service name="domain" product="dnsmasq" version="2.85"/></port>
    <port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http" product="nginx" version="1.18.0"/><script id="http-title" output="Gateway Firewall Portal"/></port>
    <port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/><service name="https" product="nginx" version="1.18.0"/><script id="ssl-cert" output="Subject: commonName=fw-gateway.corp.local"/></port>
  </ports>
  <os><osmatch name="Linux 5.4 - 5.15" accuracy="98"/></os>
</host>

<host starttime="1774880000" endtime="1774880012">
  <status state="up" reason="syn-ack"/>
  <address addr="10.0.4.10" addrtype="ipv4"/>
  <address addr="00:50:56:A1:B2:C4" addrtype="mac" vendor="VMware"/>
  <hostnames><hostname name="dc01.corp.local" type="user"/></hostnames>
  <ports>
    <port protocol="tcp" portid="53"><state state="open" reason="syn-ack"/><service name="domain" product="Microsoft DNS" version="6.1.7601"/></port>
    <port protocol="tcp" portid="88"><state state="open" reason="syn-ack"/><service name="kerberos-sec" product="Microsoft Windows Kerberos"/></port>
    <port protocol="tcp" portid="135"><state state="open" reason="syn-ack"/><service name="msrpc" product="Microsoft Windows RPC"/></port>
    <port protocol="tcp" portid="139"><state state="open" reason="syn-ack"/><service name="netbios-ssn" product="Microsoft Windows netbios-ssn"/></port>
    <port protocol="tcp" portid="389"><state state="open" reason="syn-ack"/><service name="ldap" product="Microsoft Windows Active Directory LDAP"/></port>
    <port protocol="tcp" portid="445"><state state="open" reason="syn-ack"/><service name="microsoft-ds" product="Windows Server 2016 Datacenter"/><script id="smb-os-discovery" output="OS: Windows Server 2016 Datacenter&#10;SMBv1: enabled"/></port>
    <port protocol="tcp" portid="3389"><state state="open" reason="syn-ack"/><service name="ms-wbt-server" product="Microsoft Terminal Services"/></port>
  </ports>
  <os><osmatch name="Microsoft Windows Server 2016" accuracy="96"/></os>
</host>

<host starttime="1774880000" endtime="1774880015">
  <status state="up" reason="syn-ack"/>
  <address addr="10.0.4.25" addrtype="ipv4"/>
  <address addr="00:50:56:A1:B2:C5" addrtype="mac" vendor="VMware"/>
  <hostnames><hostname name="ftp-store.corp.local" type="user"/></hostnames>
  <ports>
    <port protocol="tcp" portid="21"><state state="open" reason="syn-ack"/><service name="ftp" product="vsftpd" version="2.3.4"/><script id="ftp-anon" output="Anonymous FTP login allowed (FTP code 230)&#10;-rw-r--r-- 1 root root 4096 Sep 10 backup_db.sql"/></port>
    <port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/><service name="ssh" product="OpenSSH" version="6.7p1 Debian"/></port>
  </ports>
  <os><osmatch name="Linux 3.2 - 4.9" accuracy="92"/></os>
</host>

<host starttime="1774880000" endtime="1774880018">
  <status state="up" reason="syn-ack"/>
  <address addr="10.0.4.30" addrtype="ipv4"/>
  <address addr="00:50:56:A1:B2:C6" addrtype="mac" vendor="VMware"/>
  <hostnames><hostname name="app-cache.corp.local" type="user"/></hostnames>
  <ports>
    <port protocol="tcp" portid="6379"><state state="open" reason="syn-ack"/><service name="redis" product="Redis key-value store" version="5.0.7"/></port>
    <port protocol="tcp" portid="27017"><state state="open" reason="syn-ack"/><service name="mongodb" product="MongoDB" version="4.2.8"/></port>
  </ports>
  <os><osmatch name="Ubuntu Linux 20.04" accuracy="95"/></os>
</host>

<host starttime="1774880000" endtime="1774880020">
  <status state="up" reason="syn-ack"/>
  <address addr="10.0.4.45" addrtype="ipv4"/>
  <address addr="00:50:56:A1:B2:C7" addrtype="mac" vendor="VMware"/>
  <hostnames><hostname name="legacy-term.corp.local" type="user"/></hostnames>
  <ports>
    <port protocol="tcp" portid="23"><state state="open" reason="syn-ack"/><service name="telnet" product="BSD telnetd"/></port>
    <port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/><service name="http" product="Apache httpd" version="2.2.15"/><script id="http-title" output="Index of /secret_backups"/></port>
  </ports>
  <os><osmatch name="CentOS 6.5" accuracy="90"/></os>
</host>

<host starttime="1774880000" endtime="1774880022">
  <status state="down" reason="no-response"/>
  <address addr="10.0.4.99" addrtype="ipv4"/>
</host>
</nmaprun>`;

const SAMPLE_CLOUD_NORMAL = `# Nmap 7.94 scan initiated Sun Sep 27 15:30:00 2026 as: nmap -sS -sV -O -oN cloud_recon.nmap 192.168.10.0/24
Nmap scan report for k8s-ingress.cloud.net (192.168.10.10)
Host is up (0.0021s latency).
PORT     STATE SERVICE  VERSION
80/tcp   open  http     nginx/1.23.1
| http-title: Cloud Application Ingress
|_http-server-header: nginx/1.23.1
443/tcp  open  ssl/http nginx/1.23.1
| ssl-enum-ciphers:
|   TLSv1.0: weak ciphers detected
|_  TLSv1.2: ECDHE-RSA-AES128-GCM-SHA256
6443/tcp open  ssl/http Kubernetes API Server

Nmap scan report for elastic-cluster.cloud.net (192.168.10.25)
Host is up (0.0045s latency).
PORT     STATE SERVICE       VERSION
9200/tcp open  elasticsearch Elasticsearch 7.10.0 (rest API)
9300/tcp open  elasticsearch Elasticsearch 7.10.0 (cluster transport)
22/tcp   open  ssh           OpenSSH 8.2p1

Nmap scan report for db-primary.cloud.net (192.168.10.50)
Host is up (0.0018s latency).
PORT     STATE SERVICE  VERSION
5432/tcp open  postgresql PostgreSQL DB 13.4
22/tcp   open  ssh        OpenSSH 8.2p1

Nmap scan report for 192.168.10.99
Host is down.
# Nmap done at Sun Sep 27 15:32:00 2026 -- 4 IP addresses (3 hosts up) scanned in 120.00 seconds`;

const SAMPLE_BASELINE_XML = `<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sS -sV -O -oX corp_baseline.xml 10.0.4.0/24" start="1774275200" version="7.94">
<host starttime="1774275200">
  <status state="up" reason="echo-reply"/>
  <address addr="10.0.4.1" addrtype="ipv4"/>
  <hostnames><hostname name="fw-gateway.corp.local"/></hostnames>
  <ports>
    <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="8.9p1"/></port>
    <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.18.0"/></port>
    <port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx" version="1.18.0"/></port>
  </ports>
</host>

<host starttime="1774275200">
  <status state="up" reason="syn-ack"/>
  <address addr="10.0.4.10" addrtype="ipv4"/>
  <hostnames><hostname name="dc01.corp.local"/></hostnames>
  <ports>
    <port protocol="tcp" portid="53"><state state="open"/><service name="domain"/></port>
    <port protocol="tcp" portid="135"><state state="open"/><service name="msrpc"/></port>
    <port protocol="tcp" portid="445"><state state="open"/><service name="microsoft-ds"/></port>
  </ports>
</host>

<host starttime="1774275200">
  <status state="up" reason="syn-ack"/>
  <address addr="10.0.4.25" addrtype="ipv4"/>
  <hostnames><hostname name="ftp-store.corp.local"/></hostnames>
  <ports>
    <port protocol="tcp" portid="21"><state state="open"/><service name="ftp" product="vsftpd" version="2.3.4"/></port>
  </ports>
</host>
</nmaprun>`;

export function getSampleScans(): NormalizedScan[] {
  const corpRes = parseNmapScan(SAMPLE_ENTERPRISE_XML, 'corp_audit.xml');
  const cloudRes = parseNmapScan(SAMPLE_CLOUD_NORMAL, 'cloud_recon.nmap');
  const baselineRes = parseNmapScan(SAMPLE_BASELINE_XML, 'corp_baseline_7days_ago.xml');

  const scans: NormalizedScan[] = [];
  if (corpRes.success && corpRes.scan) scans.push(corpRes.scan);
  if (cloudRes.success && cloudRes.scan) scans.push(cloudRes.scan);
  if (baselineRes.success && baselineRes.scan) scans.push(baselineRes.scan);

  return scans;
}
