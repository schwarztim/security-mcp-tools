# enum4linux MCP Server

[![MCP](https://img.shields.io/badge/MCP-Model%20Context%20Protocol-blue)](https://modelcontextprotocol.io/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.3-blue)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Kali Linux](https://img.shields.io/badge/Kali-Linux-557C94)](https://www.kali.org/)

A Model Context Protocol (MCP) server that wraps [enum4linux](https://github.com/CiscoCXSecurity/enum4linux), a powerful Windows/Samba enumeration utility. The server executes enumeration commands via SSH on a Kali Linux host and returns structured JSON results.

## Features

- **12 specialized enumeration tools** covering all enum4linux capabilities
- **Structured JSON output** with parsed users, groups, shares, and policies
- **SSH-based execution** on remote Kali Linux for isolated security testing
- **Configurable timeouts** and buffer sizes for large enumerations
- **Support for authenticated and anonymous enumeration**

## Tools Available

| Tool | Description | enum4linux Flag |
|------|-------------|-----------------|
| `enum4linux_all` | Comprehensive enumeration (users, groups, shares, policies, OS, NetBIOS, RID cycling, printers) | `-a` |
| `enum4linux_users` | Enumerate users via RPC | `-U` |
| `enum4linux_groups` | Enumerate groups and members via RPC | `-G` |
| `enum4linux_shares` | Enumerate SMB shares | `-S` |
| `enum4linux_policies` | Get password policies and lockout settings | `-P` |
| `enum4linux_os` | Get OS information | `-o` |
| `enum4linux_rid` | Enumerate users via RID cycling | `-r` / `-R` |
| `enum4linux_printers` | Enumerate printers | `-i` |
| `enum4linux_netbios` | NetBIOS name lookup (nbtstat equivalent) | `-n` |
| `enum4linux_ldap` | Get domain info via LDAP (DC only) | `-l` |
| `enum4linux_machines` | Enumerate machines in domain | `-M` |
| `enum4linux_aggressive` | Aggressive mode with write checks | `-A` |
| `enum4linux_raw` | Execute with custom flags | Custom |

## Prerequisites

1. **Kali Linux host** with SSH access configured
2. **enum4linux** installed on Kali: `apt install enum4linux`
3. **Samba tools** installed (rpcclient, smbclient, nmblookup, net)
4. **Node.js** 18+ on the host running the MCP server

## Installation

```bash
git clone https://github.com/schwarztim/sec-enum4linux-mcp.git
cd sec-enum4linux-mcp
npm install
npm run build
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `KALI_HOST` | `kali` | SSH hostname for Kali Linux |

### SSH Setup

Ensure passwordless SSH access to your Kali host:

```bash
# Generate SSH key if needed
ssh-keygen -t ed25519

# Copy to Kali host
ssh-copy-id kali

# Test connection
ssh kali "enum4linux -h"
```

### Claude Desktop Configuration

Add to `~/.config/claude/claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "enum4linux": {
      "command": "node",
      "args": ["/path/to/sec-enum4linux-mcp/dist/index.js"],
      "env": {
        "KALI_HOST": "kali"
      }
    }
  }
}
```

## Usage Examples

### Full Enumeration

Perform comprehensive SMB enumeration on a target:

```json
{
  "tool": "enum4linux_all",
  "arguments": {
    "target": "192.168.1.100"
  }
}
```

### Authenticated User Enumeration

Enumerate users with credentials:

```json
{
  "tool": "enum4linux_users",
  "arguments": {
    "target": "192.168.1.100",
    "username": "administrator",
    "password": "Password123",
    "detailed": true
  }
}
```

### Share Enumeration with Brute Force

Enumerate shares with a wordlist:

```json
{
  "tool": "enum4linux_shares",
  "arguments": {
    "target": "192.168.1.100",
    "bruteforce": "/usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt"
  }
}
```

### RID Cycling for User Discovery

Discover users via RID cycling (useful when normal enumeration fails):

```json
{
  "tool": "enum4linux_rid",
  "arguments": {
    "target": "192.168.1.100",
    "ridRanges": "500-550,1000-2000,3000-3050",
    "keepSearching": 20
  }
}
```

### Custom Flags

Execute with specific flags:

```json
{
  "tool": "enum4linux_raw",
  "arguments": {
    "target": "192.168.1.100",
    "flags": "-U -G -S -P -o -n -i"
  }
}
```

## Output Format

Results are returned as structured JSON:

```json
{
  "tool": "enum4linux_users",
  "target": "192.168.1.100",
  "success": true,
  "command_executed": "enum4linux -U 192.168.1.100",
  "users": ["Administrator", "Guest", "krbtgt", "user1"],
  "groups": ["Domain Admins", "Domain Users"],
  "shares": ["ADMIN$", "C$", "IPC$", "NETLOGON", "SYSVOL"],
  "domain": "CONTOSO",
  "os": "Windows Server 2019",
  "password_policy": {
    "min_length": 8,
    "max_age": "42 days",
    "lockout_threshold": 5
  },
  "sections": {
    "users": "...",
    "share_enumeration": "..."
  },
  "raw_output": "..."
}
```

## Security Considerations

- **Authorized testing only**: Only use against systems you have permission to test
- **Network isolation**: Run from a dedicated security testing network
- **Credential handling**: Avoid hardcoding credentials; use environment variables
- **Logging**: Be aware that enum4linux activity may be logged on target systems

## Development

```bash
# Install dependencies
npm install

# Build TypeScript
npm run build

# Watch mode for development
npm run dev

# Run the server
npm start
```

## References

- [enum4linux - Portcullis Labs / Cisco CX Security](https://github.com/CiscoCXSecurity/enum4linux)
- [enum4linux-ng (Python rewrite)](https://github.com/cddmp/enum4linux-ng)
- [Kali Linux Tools - enum4linux](https://www.kali.org/tools/enum4linux/)
- [Model Context Protocol](https://modelcontextprotocol.io/)

## License

MIT License - see [LICENSE](LICENSE) for details.

## Disclaimer

This tool is intended for authorized security testing and educational purposes only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before testing.
