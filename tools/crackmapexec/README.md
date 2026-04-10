# CrackMapExec MCP Server

A Model Context Protocol (MCP) server that provides AI assistants with access to CrackMapExec/NetExec network penetration testing capabilities via SSH to a Kali Linux host.

## Overview

This MCP server enables AI-powered network security assessments by exposing CrackMapExec (CME) / NetExec (NXC) functionality through the standardized MCP interface. It supports multiple protocols and comprehensive enumeration, credential dumping, and command execution capabilities.

## Features

### Supported Protocols

| Protocol | Description |
|----------|-------------|
| **SMB** | Windows file sharing - shares, users, groups, SAM/LSA/NTDS dumping |
| **WinRM** | Windows Remote Management - remote command execution |
| **SSH** | Secure Shell - Linux/Unix command execution |
| **MSSQL** | Microsoft SQL Server - query execution, xp_cmdshell |
| **LDAP** | Active Directory enumeration - users, computers, delegation |
| **RDP** | Remote Desktop Protocol - access validation |
| **WMI** | Windows Management Instrumentation - remote execution |

### Capabilities

- **Enumeration**: Shares, users, groups, sessions, computers, domain controllers
- **Credential Dumping**: SAM, LSA secrets, NTDS.dit, gMSA passwords
- **Command Execution**: cmd, PowerShell, via multiple methods (wmiexec, smbexec, atexec)
- **Password Spraying**: Multi-threaded credential testing with jitter support
- **Module System**: Extensible via NetExec modules
- **Credential Database**: Store and search discovered credentials

## Installation

### Prerequisites

- Node.js 18+
- SSH access to a Kali Linux host with NetExec/CrackMapExec installed
- SSH key-based authentication configured (recommended)

### Setup

```bash
# Clone the repository
git clone https://github.com/schwarztim/sec-crackmapexec-mcp.git
cd sec-crackmapexec-mcp

# Install dependencies
npm install

# Build
npm run build
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `KALI_HOST` | Hostname or IP of the Kali Linux host | `kali` |
| `SSH_USER` | SSH username | (none) |
| `SSH_KEY` | Path to SSH private key | (none) |
| `NXC_BINARY` | Binary name (`nxc` or `crackmapexec`) | `nxc` |

### Claude Desktop Configuration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "crackmapexec": {
      "command": "node",
      "args": ["/path/to/sec-crackmapexec-mcp/dist/index.js"],
      "env": {
        "KALI_HOST": "your-kali-host",
        "SSH_USER": "kali",
        "SSH_KEY": "/path/to/ssh/key"
      }
    }
  }
}
```

## Available Tools

### `cme_smb`

Execute SMB protocol operations including share enumeration, user enumeration, credential dumping, and command execution.

```typescript
// Example: Enumerate shares
{ targets: "192.168.1.0/24", username: "admin", password: "pass123", shares: true }

// Example: Dump SAM hashes
{ targets: "192.168.1.100", username: "admin", password: "pass123", sam: true }
```

### `cme_winrm`

Execute commands via Windows Remote Management (ports 5985/5986).

```typescript
{ targets: "192.168.1.100", username: "admin", password: "pass123", execPowershell: "Get-Process" }
```

### `cme_ssh`

Test SSH credentials and execute commands on Linux/Unix hosts.

```typescript
{ targets: "192.168.1.0/24", username: "root", password: "toor", execCmd: "id" }
```

### `cme_mssql`

Query MSSQL databases and execute OS commands via xp_cmdshell.

```typescript
{ targets: "192.168.1.50", username: "sa", password: "password", query: "SELECT @@version" }
```

### `cme_ldap`

Enumerate Active Directory via LDAP queries.

```typescript
{ targets: "dc01.domain.local", username: "user", password: "pass", domain: "domain.local", usersEnabled: true }
```

### `cme_rdp`

Validate RDP access to targets.

```typescript
{ targets: "192.168.1.0/24", username: "admin", password: "pass123" }
```

### `cme_wmi`

Execute commands via WMI.

```typescript
{ targets: "192.168.1.100", username: "admin", password: "pass123", execCmd: "whoami" }
```

### `cme_modules`

List available modules for a protocol or get module options.

```typescript
// List SMB modules
{ protocol: "smb" }

// Get options for specific module
{ protocol: "smb", moduleName: "mimikatz" }
```

### `cme_spray`

Perform password spraying attacks with jitter support.

```typescript
{
  protocol: "smb",
  targets: "192.168.1.0/24",
  usernames: "users.txt",
  passwords: "Summer2024!",
  domain: "corp.local",
  jitter: "1-3"
}
```

### `cme_creds`

Manage the NetExec credential database.

```typescript
// List all credentials
{ action: "list" }

// Search credentials
{ action: "search", searchTerm: "admin" }

// Export credentials
{ action: "export", exportPath: "creds.csv" }
```

### `cme_raw`

Execute raw NetExec commands for advanced operations.

```typescript
{ command: "smb 192.168.1.100 -u admin -p pass123 --shares" }
```

## Security Considerations

This tool is intended for **authorized security testing only**. Ensure you have:

1. Written authorization to test target systems
2. Proper scope definition for the engagement
3. Understanding of applicable laws and regulations

**Never use this tool against systems without explicit permission.**

## Architecture

```
┌─────────────────┐      SSH      ┌─────────────────┐
│  Claude/AI      │ ────────────► │  Kali Linux     │
│  Assistant      │               │  + NetExec      │
├─────────────────┤               └─────────────────┘
│  MCP Server     │                      │
│  (Node.js)      │                      ▼
└─────────────────┘               ┌─────────────────┐
                                  │  Target Network │
                                  └─────────────────┘
```

## Development

```bash
# Run in development mode
npm run dev

# Build for production
npm run build

# Start production server
npm start
```

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Related Projects

- [NetExec](https://github.com/Pennyw0rth/NetExec) - The network execution tool
- [Model Context Protocol](https://modelcontextprotocol.io/) - The MCP specification
- [MCP SDK](https://github.com/modelcontextprotocol/sdk) - Official MCP SDK

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Disclaimer

This software is provided for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this tool. Always obtain proper authorization before conducting security assessments.
