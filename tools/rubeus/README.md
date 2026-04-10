# Rubeus MCP Server

A Model Context Protocol (MCP) server for Kerberos abuse operations using Rubeus on Windows or Impacket on Linux/macOS.

## Overview

This MCP server provides comprehensive tools for Kerberos-based security testing, wrapping the functionality of [Rubeus](https://github.com/GhostPack/Rubeus) (Windows) and [Impacket](https://github.com/fortra/impacket) (cross-platform) into a unified interface accessible through the Model Context Protocol.

> **Security Warning**: This tool is intended for authorized security testing only. Unauthorized use against systems you do not own or have permission to test is illegal and unethical.

## Features

### Ticket Operations
- **asktgt** - Request Ticket Granting Tickets (TGT) using passwords, hashes, or certificates
- **asktgs** - Request Service Tickets (TGS) for specific SPNs
- **renew** - Renew existing TGTs to extend validity
- **ptt** - Pass-the-ticket to apply tickets to current session
- **purge** - Remove tickets from logon sessions
- **describe** - Parse and analyze ticket contents

### Roasting Attacks
- **kerberoast** - Extract service account password hashes via TGS requests
- **asreproast** - Attack accounts without Kerberos pre-authentication

### Ticket Extraction
- **dump** - Extract all tickets from memory
- **triage** - Quick summary of available tickets
- **klist** - Detailed ticket listing
- **harvest** - Continuously monitor and harvest new TGTs
- **monitor** - Watch for new TGT events
- **tgtdeleg** - Extract TGT without elevation using delegation trick

### Delegation Abuse
- **s4u** - Perform S4U2Self/S4U2Proxy constrained delegation attacks
- Bronze Bit exploitation (CVE-2020-17049)

### Ticket Forgery
- **golden** - Forge Golden Tickets with krbtgt hash
- **silver** - Forge Silver Tickets with service account hash
- **diamond** - Forge Diamond Tickets (modified legitimate TGT)

### Utilities
- **hash** - Calculate Kerberos password hashes (RC4, AES128, AES256, DES)
- **changepw** - Change user passwords using TGT
- **createnetonly** - Create processes with different network credentials
- **tgssub** - Substitute service names in tickets

## Installation

### Prerequisites

**Windows (Native Rubeus)**:
- Download [Rubeus.exe](https://github.com/GhostPack/Rubeus) from GhostPack
- .NET Framework 4.0+

**Linux/macOS (Impacket)**:
```bash
pip install impacket
```

### Setup

```bash
# Clone the repository
git clone https://github.com/schwarztim/sec-rubeus-mcp.git
cd sec-rubeus-mcp

# Install dependencies
npm install

# Build
npm run build
```

## Configuration

Configure via environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `RUBEUS_PATH` | Path to Rubeus.exe (Windows) | `Rubeus.exe` |
| `IMPACKET_PATH` | Path to impacket scripts | System PATH |
| `RUBEUS_OUTPUT_DIR` | Directory for output files | `$TMPDIR/rubeus-mcp` |
| `RUBEUS_DOMAIN` | Default AD domain | None |
| `RUBEUS_DC` | Default domain controller | None |
| `RUBEUS_TIMEOUT` | Command timeout (ms) | `300000` |
| `RUBEUS_USE_IMPACKET` | Force impacket mode | Auto-detected |

## Usage with Claude Desktop

Add to your Claude Desktop configuration (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "rubeus": {
      "command": "node",
      "args": ["/path/to/sec-rubeus-mcp/dist/index.js"],
      "env": {
        "RUBEUS_DOMAIN": "corp.example.com",
        "RUBEUS_DC": "dc01.corp.example.com"
      }
    }
  }
}
```

## Usage with Claude Code

Add to your MCP configuration:

```json
{
  "rubeus": {
    "command": "node",
    "args": ["/path/to/sec-rubeus-mcp/dist/index.js"],
    "env": {
      "RUBEUS_DOMAIN": "corp.example.com"
    }
  }
}
```

## Examples

### Check Environment
```
Use rubeus_check_environment to verify your setup
```

### Request a TGT
```
Use rubeus_asktgt with:
- user: "admin"
- domain: "corp.example.com"
- password: "Password123"
```

### Kerberoasting
```
Use rubeus_kerberoast with:
- domain: "corp.example.com"
- outfile: "hashes.txt"
```

### AS-REP Roasting
```
Use rubeus_asreproast with:
- domain: "corp.example.com"
- format: "hashcat"
```

### S4U Delegation Attack
```
Use rubeus_s4u with:
- user: "svc_account"
- rc4: "<ntlm_hash>"
- impersonateuser: "Administrator"
- msdsspn: "cifs/fileserver.corp.example.com"
```

## Cross-Platform Support

| Feature | Windows (Rubeus) | Linux/macOS (Impacket) |
|---------|-----------------|------------------------|
| asktgt | Full | Full |
| asktgs | Full | Full |
| kerberoast | Full | Full |
| asreproast | Full | Full |
| s4u | Full | Full |
| dump | Full | Via secretsdump |
| Golden/Silver tickets | Full | Limited |
| Ticket manipulation | Full | Limited |

## Development

```bash
# Watch mode for development
npm run dev

# Build
npm run build

# Run tests
npm test
```

## Security Considerations

- All tools require appropriate authorization before use
- Output files may contain sensitive data (tickets, hashes)
- Credentials are not logged, but ticket data may be captured
- Use in isolated test environments when possible
- Follow responsible disclosure practices

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Acknowledgments

- [GhostPack/Rubeus](https://github.com/GhostPack/Rubeus) - The original Rubeus toolkit by harmj0y
- [Impacket](https://github.com/fortra/impacket) - Python classes for network protocols by Fortra
- [Model Context Protocol](https://modelcontextprotocol.io/) - The MCP specification by Anthropic

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. The authors are not responsible for misuse or damage caused by this tool. Always obtain proper authorization before testing systems you do not own.
