# Masscan MCP Server

[![MCP](https://img.shields.io/badge/MCP-Model%20Context%20Protocol-blue)](https://modelcontextprotocol.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/Node.js-18%2B-green)](https://nodejs.org)

A Model Context Protocol (MCP) server for [masscan](https://github.com/robertdavidgraham/masscan) - the world's fastest port scanner capable of scanning the entire Internet in under 6 minutes.

## Overview

This MCP server provides a standardized interface for AI assistants to perform network port scanning using masscan. It executes commands on a remote Kali Linux host via SSH, making it ideal for security assessments, network discovery, and penetration testing workflows.

## Features

| Tool | Description |
|------|-------------|
| `masscan_scan` | Full-featured port scanning with comprehensive options |
| `masscan_quick_scan` | Preset-based quick scans for common scenarios |
| `masscan_resume` | Resume interrupted scans from paused.conf |
| `masscan_echo_config` | Generate reusable configuration files |
| `masscan_version` | Verify masscan installation |
| `masscan_help` | Display help by topic |

## Installation

```bash
# Clone the repository
git clone https://github.com/schwarztim/sec-masscan-mcp.git
cd sec-masscan-mcp

# Install dependencies
npm install

# Build
npm run build
```

## Configuration

### MCP Client Configuration

Add to your Claude Desktop config (`~/.claude/user-mcps.json` or equivalent):

```json
{
  "mcpServers": {
    "masscan": {
      "command": "node",
      "args": ["/path/to/sec-masscan-mcp/dist/index.js"],
      "env": {
        "KALI_HOST": "kali"
      }
    }
  }
}
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `KALI_HOST` | SSH hostname/alias for Kali Linux | `kali` |

### SSH Setup

Ensure passwordless SSH access to your Kali host:

```bash
# Generate SSH key if needed
ssh-keygen -t ed25519

# Copy to Kali host
ssh-copy-id kali

# Verify connection
ssh kali "masscan --version"
```

## Usage Examples

### Basic Port Scan

```json
{
  "tool": "masscan_scan",
  "arguments": {
    "targets": "192.168.1.0/24",
    "ports": "80,443,8080"
  }
}
```

### High-Speed Scan with Banner Grabbing

```json
{
  "tool": "masscan_scan",
  "arguments": {
    "targets": "10.0.0.0/8",
    "ports": "22,80,443",
    "rate": 10000,
    "banners": true
  }
}
```

### Quick Web Services Scan

```json
{
  "tool": "masscan_quick_scan",
  "arguments": {
    "targets": "192.168.1.0/24",
    "preset": "web",
    "banners": true
  }
}
```

### Full Port Scan

```json
{
  "tool": "masscan_quick_scan",
  "arguments": {
    "targets": "192.168.1.1",
    "preset": "full",
    "rate": 10000
  }
}
```

### Distributed Scanning (Sharding)

```json
{
  "tool": "masscan_scan",
  "arguments": {
    "targets": "10.0.0.0/8",
    "ports": "80,443",
    "shard": "1/3"
  }
}
```

### Resume Interrupted Scan

```json
{
  "tool": "masscan_resume",
  "arguments": {
    "configFile": "/tmp/paused.conf"
  }
}
```

## Port Presets

| Preset | Ports | Use Case |
|--------|-------|----------|
| `web` | 80, 443, 8080, 8443, 8000, 8888, 3000, 5000 | Web servers |
| `common` | 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080 | Common services |
| `full` | 0-65535 | Complete port scan |
| `ssh` | 22, 2222, 22222 | SSH services |
| `database` | 3306, 5432, 1433, 1521, 27017, 6379, 5984, 9200, 9300, 11211, 28015 | Database servers |

## Output Formats

| Format | Description |
|--------|-------------|
| `json` | JSON output (default) - parsed automatically |
| `list` | Simple host:port list |
| `xml` | XML format for tool integration |
| `grepable` | Nmap-style grepable output |
| `binary` | Binary format for large-scale scans |

## Advanced Options

The `masscan_scan` tool supports all major masscan options:

- **Rate Control**: `rate` - packets per second (up to 25M)
- **Banner Grabbing**: `banners` - perform full TCP handshake
- **Exclusions**: `excludeTargets`, `excludeFile`
- **Network Tuning**: `adapter`, `adapterIp`, `adapterMac`, `routerMac`
- **Timing**: `wait`, `retries`, `connectionTimeout`
- **Protocol**: `ttl`, `sourcePort`
- **Distributed**: `seed`, `shard`
- **Output**: `outputFormat`, `outputFile`, `openOnly`

## Requirements

- **Node.js** 18 or higher
- **SSH access** to a Kali Linux host with masscan installed
- **Root/sudo** access on Kali for high-speed scanning

## Security Considerations

- Only scan networks you have authorization to test
- High scan rates can trigger IDS/IPS alerts
- Banner grabbing establishes full TCP connections
- Consider using exclusion lists for sensitive hosts

## References

- [Masscan GitHub Repository](https://github.com/robertdavidgraham/masscan)
- [Masscan Man Page](https://github.com/robertdavidgraham/masscan/blob/master/doc/masscan.8.markdown)
- [Kali Linux Tools - Masscan](https://www.kali.org/tools/masscan/)
- [Model Context Protocol](https://modelcontextprotocol.io)

## License

MIT License - see [LICENSE](LICENSE) for details.
