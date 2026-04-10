# Certipy MCP Server

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![MCP](https://img.shields.io/badge/MCP-1.0-blue.svg)](https://modelcontextprotocol.io)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.3-blue.svg)](https://www.typescriptlang.org/)

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server that provides AI assistants with tools to interact with [Certipy](https://github.com/ly4k/Certipy) - the premier Active Directory Certificate Services (AD CS) enumeration and abuse tool.

## Overview

This MCP server enables AI assistants to perform AD CS security assessments by executing Certipy commands on a remote Kali Linux machine via SSH. It supports the full range of AD CS attack vectors documented in the [Certified Pre-Owned](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf) research.

### Key Capabilities

- **Enumeration** - Discover Certificate Authorities, templates, and ESC1-ESC16 vulnerabilities
- **Certificate Requests** - Request certificates using vulnerable templates
- **Authentication** - Perform PKINIT authentication to obtain TGTs and NTLM hashes
- **Golden Certificates** - Forge certificates using compromised CA private keys
- **Shadow Credentials** - Account takeover via Key Credential Links
- **NTLM Relay** - Relay attacks against AD CS HTTP/RPC endpoints
- **Template/CA Management** - Modify templates and manage CA configurations

## Installation

### Prerequisites

1. **Kali Linux machine** with Certipy installed:
   ```bash
   sudo apt install certipy-ad
   # or
   pip install certipy-ad
   ```

2. **SSH access** configured to the Kali machine (passwordless recommended):
   ```bash
   # Example ~/.ssh/config entry
   Host kali
       HostName 192.168.1.100
       User root
       IdentityFile ~/.ssh/id_rsa
   ```

3. **Node.js** 18+ on the machine running the MCP server

### Setup

```bash
# Clone the repository
git clone https://github.com/schwarztim/sec-certipy-mcp.git
cd sec-certipy-mcp

# Install dependencies
npm install

# Build
npm run build
```

### Claude Desktop Configuration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "certipy": {
      "command": "node",
      "args": ["/path/to/sec-certipy-mcp/dist/index.js"],
      "env": {
        "CERTIPY_KALI_HOST": "kali",
        "CERTIPY_SSH_OPTIONS": "-o StrictHostKeyChecking=no -o ConnectTimeout=10"
      }
    }
  }
}
```

## Configuration

| Environment Variable | Default | Description |
|---------------------|---------|-------------|
| `CERTIPY_KALI_HOST` | `kali` | SSH host alias or IP for Kali machine |
| `CERTIPY_SSH_OPTIONS` | `-o StrictHostKeyChecking=no -o ConnectTimeout=10` | SSH connection options |

## Available Tools

### certipy_find

Enumerate AD CS configuration and identify vulnerabilities (ESC1-ESC16). This is typically the first step in any AD CS assessment.

```json
{
  "username": "user",
  "password": "password",
  "domain": "corp.local",
  "dc_ip": "192.168.1.1",
  "vulnerable": true
}
```

### certipy_req

Request certificates from AD CS. Supports multiple enrollment protocols (RPC, DCOM, HTTP).

```json
{
  "username": "user",
  "password": "password",
  "domain": "corp.local",
  "dc_ip": "192.168.1.1",
  "ca": "corp-DC-CA",
  "template": "VulnerableTemplate",
  "upn": "administrator@corp.local"
}
```

### certipy_auth

Authenticate using a certificate (PKINIT) to obtain Kerberos TGT and NTLM hash.

```json
{
  "pfx": "/path/to/administrator.pfx",
  "dc_ip": "192.168.1.1"
}
```

### certipy_forge

Forge certificates using a compromised CA private key (Golden Certificate attack).

```json
{
  "ca_pfx": "/path/to/ca.pfx",
  "upn": "administrator@corp.local",
  "subject": "CN=Administrator,CN=Users,DC=corp,DC=local"
}
```

### certipy_shadow

Abuse Shadow Credentials (Key Credential Link) for account takeover.

```json
{
  "username": "attacker",
  "password": "password",
  "domain": "corp.local",
  "dc_ip": "192.168.1.1",
  "account": "target_user",
  "action": "auto"
}
```

### certipy_relay

NTLM relay attack targeting AD CS HTTP/RPC endpoints (ESC8/ESC11).

```json
{
  "target": "http://ca.corp.local/certsrv/certfnsh.asp",
  "ca": "corp-DC-CA",
  "template": "DomainController"
}
```

### certipy_template

View and modify certificate template configurations (ESC4).

```json
{
  "username": "user",
  "password": "password",
  "domain": "corp.local",
  "dc_ip": "192.168.1.1",
  "template": "VulnerableTemplate",
  "save_config": "template_backup.json"
}
```

### certipy_ca

Manage Certificate Authority - list/enable/disable templates, issue/deny requests (ESC7).

```json
{
  "username": "user",
  "password": "password",
  "domain": "corp.local",
  "dc_ip": "192.168.1.1",
  "ca": "corp-DC-CA",
  "list_templates": true
}
```

### certipy_cert

Manage local certificates - import, export, convert between formats.

```json
{
  "pfx": "certificate.pfx",
  "export": true,
  "out": "certificate"
}
```

### certipy_account

Manage AD user and computer accounts for attack setup.

```json
{
  "username": "user",
  "password": "password",
  "domain": "corp.local",
  "dc_ip": "192.168.1.1",
  "user": "newcomputer$",
  "create": true
}
```

### certipy_help

Get help for Certipy commands.

```json
{
  "command": "find"
}
```

## AD CS Attack Vectors Reference

| ESC | Vulnerability | Certipy Tool | Description |
|-----|--------------|--------------|-------------|
| ESC1 | Misconfigured certificate templates | `certipy_req` with `-upn` | Templates allowing requesters to specify SAN |
| ESC2 | Any Purpose or SubCA templates | `certipy_req` | Overly permissive EKU configurations |
| ESC3 | Enrollment agent templates | `certipy_req` with `-on-behalf-of` | Request certs on behalf of other users |
| ESC4 | Vulnerable template ACLs | `certipy_template` | Write access to template objects |
| ESC5 | Vulnerable PKI AD object ACLs | `certipy_ca` | Write access to CA configuration |
| ESC6 | EDITF_ATTRIBUTESUBJECTALTNAME2 | `certipy_req` | CA allows SAN specification |
| ESC7 | Vulnerable CA ACLs | `certipy_ca` | ManageCA or ManageCertificates rights |
| ESC8 | HTTP enrollment (NTLM relay) | `certipy_relay` | Web enrollment vulnerable to relay |
| ESC9-16 | Various misconfigurations | `certipy_find` | Additional template/CA issues |

## Security Notice

This tool is intended for authorized security testing and research purposes only. Unauthorized access to computer systems is illegal. Always ensure you have proper authorization before conducting security assessments.

## References

- [Certipy GitHub Repository](https://github.com/ly4k/Certipy)
- [Certipy Wiki](https://github.com/ly4k/Certipy/wiki)
- [Certified Pre-Owned Whitepaper](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [Model Context Protocol](https://modelcontextprotocol.io)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
