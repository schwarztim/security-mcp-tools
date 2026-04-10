# SpiderFoot MCP Server

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js Version](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen)](https://nodejs.org/)
[![MCP](https://img.shields.io/badge/MCP-Model%20Context%20Protocol-blue)](https://modelcontextprotocol.io/)
[![SpiderFoot](https://img.shields.io/badge/SpiderFoot-OSINT-red)](https://www.spiderfoot.net/)

A Model Context Protocol (MCP) server for [SpiderFoot](https://www.spiderfoot.net/), the open-source OSINT automation tool. This server enables AI assistants to perform reconnaissance, gather intelligence, and analyze targets through SpiderFoot's comprehensive scanning capabilities.

## Features

- **Full OSINT Automation** - Start, stop, and manage reconnaissance scans
- **200+ Data Modules** - Access SpiderFoot's extensive module library for gathering intelligence
- **Multi-Target Support** - Scan domains, IPs, emails, phone numbers, usernames, and more
- **Correlation Engine** - Leverage SpiderFoot's built-in correlation rules for threat analysis
- **Export & Visualization** - Export data in JSON/GEXF formats for further analysis
- **Search & Filter** - Query across scans with regex support

## Prerequisites

- [SpiderFoot](https://github.com/smicallef/spiderfoot) running with web UI enabled
- Node.js 18.0.0 or higher
- npm or yarn

## Installation

```bash
# Clone the repository
git clone https://github.com/schwarztim/sec-spiderfoot-mcp.git
cd sec-spiderfoot-mcp

# Install dependencies
npm install

# Build the project
npm run build
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SPIDERFOOT_URL` | SpiderFoot web UI URL | `http://127.0.0.1:5001` |
| `SPIDERFOOT_USERNAME` | Authentication username (optional) | - |
| `SPIDERFOOT_PASSWORD` | Authentication password (optional) | - |

### Claude Desktop Configuration

Add to your Claude Desktop config (`~/.config/claude/claude_desktop_config.json` on Linux or `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "spiderfoot": {
      "command": "node",
      "args": ["/path/to/sec-spiderfoot-mcp/dist/index.js"],
      "env": {
        "SPIDERFOOT_URL": "http://127.0.0.1:5001"
      }
    }
  }
}
```

## SpiderFoot Setup

### Option 1: Python (Recommended for Kali Linux)

```bash
# Clone SpiderFoot
git clone https://github.com/smicallef/spiderfoot.git
cd spiderfoot

# Install dependencies
pip3 install -r requirements.txt

# Start with web UI
python3 sf.py -l 127.0.0.1:5001
```

### Option 2: Docker

```bash
docker run -p 5001:5001 spiderfoot/spiderfoot
```

### Option 3: Kali Linux Package

```bash
sudo apt update && sudo apt install spiderfoot
spiderfoot -l 127.0.0.1:5001
```

## Available Tools

### Scan Management

| Tool | Description |
|------|-------------|
| `spiderfoot_ping` | Test connectivity to SpiderFoot server |
| `spiderfoot_scans` | List all scans with status and risk metrics |
| `spiderfoot_scan_status` | Get detailed status of a specific scan |
| `spiderfoot_start_scan` | Start a new OSINT reconnaissance scan |
| `spiderfoot_stop_scan` | Stop a running scan |
| `spiderfoot_delete_scan` | Delete a scan and its data |

### Results & Analysis

| Tool | Description |
|------|-------------|
| `spiderfoot_results` | Get scan findings (filter by type, exclude false positives) |
| `spiderfoot_summary` | Get summary grouped by type/module/entity |
| `spiderfoot_correlations` | Get correlation findings and patterns |
| `spiderfoot_search` | Search across scans (supports regex) |

### Configuration & Metadata

| Tool | Description |
|------|-------------|
| `spiderfoot_modules` | List all available scanning modules |
| `spiderfoot_event_types` | List all data types SpiderFoot can collect |
| `spiderfoot_correlation_rules` | List correlation rules and risk ratings |
| `spiderfoot_config` | Get global SpiderFoot configuration |
| `spiderfoot_scan_config` | Get configuration used for a specific scan |

### Export & Visualization

| Tool | Description |
|------|-------------|
| `spiderfoot_export` | Export scan data in JSON format |
| `spiderfoot_graph` | Get graph data (JSON or GEXF for Gephi) |
| `spiderfoot_discovery_path` | Trace how data elements were discovered |
| `spiderfoot_history` | Get scan timeline/history |

### Diagnostics

| Tool | Description |
|------|-------------|
| `spiderfoot_scan_log` | Get execution log for a scan |
| `spiderfoot_scan_errors` | Get errors encountered during scan |

## Usage Examples

### Start a Reconnaissance Scan

```
Start a footprint scan against example.com:
- Name: "Example Corp Recon"
- Target: "example.com"
- Use Case: "footprint" (attack surface mapping)
```

### Scan Use Cases

| Use Case | Description |
|----------|-------------|
| `all` | Run all modules (comprehensive but slow) |
| `passive` | No active probing - OSINT only |
| `investigate` | Threat investigation focused |
| `footprint` | Attack surface mapping |

### Search with Regex

```
Search for all admin emails across scans:
- value: "/admin.*@.*\.com/"
```

### Get Specific Results

```
Get all email addresses found in scan:
- scan_id: "abc123"
- event_type: "EMAILADDR"
- unique: true
```

## Supported Target Types

SpiderFoot can scan various target types:

- **Domain Names** - `example.com`
- **IP Addresses** - `192.168.1.1`, `192.168.1.0/24`
- **Email Addresses** - `user@example.com`
- **Phone Numbers** - `+1-555-123-4567`
- **Usernames** - `johndoe`
- **Bitcoin Addresses** - `1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa`
- **And more...**

## Security Considerations

- SpiderFoot performs active reconnaissance which may be detected
- Always ensure you have authorization before scanning targets
- Use the `passive` use case for non-intrusive OSINT gathering
- Consider network isolation for sensitive scanning operations

## Development

```bash
# Watch mode for development
npm run dev

# Build for production
npm run build

# Start the server
npm start
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Related Projects

- [SpiderFoot](https://github.com/smicallef/spiderfoot) - The OSINT automation tool
- [Model Context Protocol](https://modelcontextprotocol.io/) - The MCP specification
- [MCP SDK](https://github.com/modelcontextprotocol/typescript-sdk) - TypeScript SDK for MCP

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request
