# nmap-mcp

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0-blue.svg)](https://www.typescriptlang.org/)
[![MCP](https://img.shields.io/badge/MCP-1.0-green.svg)](https://modelcontextprotocol.io/)
[![Node.js](https://img.shields.io/badge/Node.js-18+-339933.svg)](https://nodejs.org/)

A Model Context Protocol (MCP) server that provides comprehensive network scanning capabilities using [nmap](https://nmap.org/). Designed for security professionals and penetration testers, this server can execute scans either locally or via SSH on a remote Kali Linux box for security isolation.

## Features

- **Multiple Scan Types**: Port scanning, service detection, OS fingerprinting, vulnerability assessment
- **NSE Script Support**: Run 600+ Nmap Scripting Engine scripts
- **Flexible Execution**: Run locally or via SSH to a remote scanning host
- **Structured Output**: Parsed XML results formatted as readable Markdown
- **Security-First**: Input validation to prevent command injection
- **Stealth Options**: Decoys, fragmentation, timing controls for evasive scanning

## Installation

```bash
# Clone the repository
git clone https://github.com/schwarztim/sec-nmap-mcp.git
cd sec-nmap-mcp

# Install dependencies
npm install

# Build
npm run build
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `NMAP_SSH_HOST` | SSH host for remote execution | `kali` |
| `NMAP_SSH_USER` | SSH username (optional) | Uses SSH config default |
| `NMAP_SSH_KEY` | Path to SSH private key (optional) | Uses SSH config default |
| `NMAP_LOCAL` | Set to `"true"` to run nmap locally | `false` |

### Claude Desktop Configuration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "nmap": {
      "command": "node",
      "args": ["/path/to/sec-nmap-mcp/dist/index.js"],
      "env": {
        "NMAP_SSH_HOST": "kali",
        "NMAP_LOCAL": "false"
      }
    }
  }
}
```

For local execution:

```json
{
  "mcpServers": {
    "nmap": {
      "command": "node",
      "args": ["/path/to/sec-nmap-mcp/dist/index.js"],
      "env": {
        "NMAP_LOCAL": "true"
      }
    }
  }
}
```

## Available Tools

### Basic Scanning

| Tool | Description |
|------|-------------|
| `nmap_scan` | Basic port scan with customizable options |
| `nmap_quick_scan` | Fast scan of common ports (-F) |
| `nmap_ping_sweep` | Host discovery without port scanning (-sn) |

### Advanced Scanning

| Tool | Description |
|------|-------------|
| `nmap_service_scan` | Service version detection (-sV) |
| `nmap_os_detect` | OS fingerprinting (-O) |
| `nmap_comprehensive_scan` | Full scan: SYN + version + OS + scripts |
| `nmap_stealth_scan` | Evasive scan with decoys and fragmentation |

### Security Assessment

| Tool | Description |
|------|-------------|
| `nmap_script_scan` | Run specific NSE scripts |
| `nmap_vuln_scan` | Vulnerability assessment scripts |

### Utility

| Tool | Description |
|------|-------------|
| `nmap_status` | Check nmap availability and configuration |
| `nmap_parse_output` | Parse existing nmap XML output |

## Usage Examples

### Basic Port Scan

```
Scan target 192.168.1.1 for open ports
```

### Service Version Detection

```
Run a service scan on 10.0.0.0/24 ports 22,80,443
```

### Vulnerability Assessment

```
Run a vulnerability scan on target.example.com
```

### Stealth Scan with Decoys

```
Perform a stealth scan on 192.168.1.100 using random decoys
```

### Ping Sweep for Host Discovery

```
Find all live hosts on 192.168.1.0/24
```

### NSE Script Scan

```
Run the http-title and ssl-cert scripts on example.com port 443
```

## Security Considerations

### Remote Execution (Recommended)

Running nmap via SSH to a dedicated Kali Linux box provides:

- **Isolation**: Scans originate from a controlled environment
- **Privilege Management**: Root access for advanced scans without local elevation
- **Audit Trail**: Centralized logging on the scanning host
- **Network Segmentation**: Scan traffic separated from workstation

### Input Validation

The server validates all inputs to prevent command injection:

- Targets are validated against allowed character patterns
- Dangerous shell characters are blocked
- Port specifications are strictly validated

### Responsible Use

This tool is intended for:

- Security assessments with proper authorization
- Network inventory and management
- Educational purposes

**Always ensure you have proper authorization before scanning any network or system.**

## Development

```bash
# Watch mode for development
npm run dev

# Build for production
npm run build

# Run the server
npm start
```

## Requirements

- Node.js 18+
- nmap installed (locally or on SSH target)
- SSH access to remote host (if using remote execution)

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgments

- [Nmap](https://nmap.org/) - The Network Mapper
- [Model Context Protocol](https://modelcontextprotocol.io/) - AI tool integration standard
