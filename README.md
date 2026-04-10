# Security MCP Tools

A collection of Model Context Protocol (MCP) servers for security tools. Each server exposes a security tool's capabilities as structured MCP tools, allowing AI assistants to perform penetration testing, OSINT reconnaissance, network analysis, Active Directory attacks, web fuzzing, and more through a standardized interface.

MCP is an open protocol that enables AI models to interact with external tools and data sources through a unified API. These servers bridge the gap between AI assistants and established security tooling, enabling automated security workflows without sacrificing the depth and flexibility of purpose-built tools.

All servers connect to tools running on a remote Kali Linux host via SSH. Each tool directory is a self-contained Node.js/TypeScript MCP server.

## Tools

### OSINT and Reconnaissance

| Tool | Directory | Description |
|------|-----------|-------------|
| Shodan | `tools/shodan` | IoT and internet-connected device search engine |
| Censys | `tools/censys` | Internet-wide scan data search |
| Maltego | `tools/maltego` | OSINT visualization and transform automation |
| theHarvester | `tools/theharvester` | Email and subdomain harvesting |
| Amass | `tools/amass` | OWASP subdomain enumeration and attack surface mapping |
| Subfinder | `tools/subfinder` | Passive subdomain discovery |
| SpiderFoot | `tools/spiderfoot` | OSINT automation platform |
| Recon-ng | `tools/recon-ng` | Web reconnaissance framework |

### Network Scanning and Analysis

| Tool | Directory | Description |
|------|-----------|-------------|
| Nmap | `tools/nmap` | Network scanner and security auditing |
| Masscan | `tools/masscan` | High-speed port scanner |
| Wireshark | `tools/wireshark` | Network protocol analyzer (tshark interface) |
| Aircrack-ng | `tools/aircrack-ng` | WiFi security auditing suite |

### Web Application Security

| Tool | Directory | Description |
|------|-----------|-------------|
| Burp Suite | `tools/burpsuite` | Web application security testing platform |
| SQLMap | `tools/sqlmap` | Automated SQL injection detection and exploitation |
| Nikto | `tools/nikto` | Web server vulnerability scanner |
| WPScan | `tools/wpscan` | WordPress security scanner |
| httpx | `tools/httpx` | HTTP toolkit for web reconnaissance |
| BeEF | `tools/beef-xss` | Browser Exploitation Framework |

### Directory and Content Discovery

| Tool | Directory | Description |
|------|-----------|-------------|
| Gobuster | `tools/gobuster` | Directory and DNS brute-forcing |
| ffuf | `tools/ffuf` | Fast web fuzzer |
| wfuzz | `tools/wfuzz` | Web application fuzzer |
| Feroxbuster | `tools/feroxbuster` | Recursive content discovery |
| dirb | `tools/dirb` | Web content scanner |

### Active Directory Attacks

| Tool | Directory | Description |
|------|-----------|-------------|
| BloodHound | `tools/bloodhound` | AD attack path mapping and visualization |
| Impacket | `tools/impacket` | Network protocol toolkit for AD and Windows security |
| CrackMapExec | `tools/crackmapexec` | Network pentesting and AD enumeration |
| NetExec | `tools/netexec` | Network execution tool (CrackMapExec successor) |
| Certipy | `tools/certipy` | AD Certificate Services attack tool |
| Rubeus | `tools/rubeus` | Kerberos abuse toolkit |
| ldapdomaindump | `tools/ldapdomaindump` | Active Directory LDAP enumeration |
| enum4linux | `tools/enum4linux` | SMB/Samba enumeration for Windows systems |
| Evil-WinRM | `tools/evil-winrm` | WinRM shell for Windows penetration testing |
| Mimikatz | `tools/mimikatz` | Credential extraction and security assessment |
| smbmap | `tools/smbmap` | SMB share enumeration and access |

### Password Attacks

| Tool | Directory | Description |
|------|-----------|-------------|
| John the Ripper | `tools/john-the-ripper` | Password cracking and security auditing |
| Hashcat | `tools/hashcat` | GPU-accelerated password recovery |
| Hydra | `tools/hydra` | Network service password brute-forcing |

### C2 Frameworks and Post-Exploitation

| Tool | Directory | Description |
|------|-----------|-------------|
| Sliver C2 | `tools/sliver-c2` | Adversary emulation and C2 framework |
| PowerShell Empire | `tools/powershell-empire` | Post-exploitation framework |
| Veil | `tools/veil-evasion` | Payload generation and AV evasion |
| Social Engineer Toolkit | `tools/social-engineer-toolkit` | Social engineering attack platform |

### Tunneling and Pivoting

| Tool | Directory | Description |
|------|-----------|-------------|
| Chisel | `tools/chisel` | TCP/UDP tunneling over HTTP/WebSocket |
| Ligolo-ng | `tools/ligolo-ng` | Advanced tunneling and pivoting |
| Proxychains | `tools/proxychains` | Route commands through proxy chains |

### Utilities

| Tool | Directory | Description |
|------|-----------|-------------|
| SecLists | `tools/seclists` | Security testing wordlists and payloads |
| Nuclei | `tools/nuclei` | Template-based vulnerability scanner |

## Setup

Each tool is a standalone Node.js project. To build any tool:

```bash
cd tools/<toolname>
npm install
npm run build
```

Most servers expect SSH access to a Kali Linux host where the underlying security tools are installed. See each tool's README for specific configuration requirements.

## License

See individual tool directories for license information.
