# theHarvester MCP Server

[![MCP](https://img.shields.io/badge/MCP-Model%20Context%20Protocol-blue)](https://modelcontextprotocol.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.3-blue)](https://www.typescriptlang.org/)

An MCP (Model Context Protocol) server that provides AI assistants with access to [theHarvester](https://github.com/laramies/theHarvester) - a powerful OSINT reconnaissance tool for email and subdomain harvesting during penetration testing.

## Overview

theHarvester is one of the most widely used OSINT tools for gathering intelligence during the reconnaissance phase of penetration testing. This MCP server wraps theHarvester's capabilities, allowing AI assistants like Claude to perform domain reconnaissance tasks through a structured interface.

The server executes theHarvester commands via SSH on a Kali Linux host, making it ideal for security professionals who maintain a dedicated Kali environment.

## Features

- **Email Harvesting** - Discover email addresses associated with target domains
- **Subdomain Discovery** - Find subdomains using 40+ public and premium data sources
- **DNS Brute Force** - Enumerate subdomains using wordlist-based brute forcing
- **Shodan Integration** - Query discovered hosts for open ports, services, and banners
- **Takeover Detection** - Check for subdomain takeover vulnerabilities
- **Virtual Host Discovery** - Identify virtual hosts on discovered IP addresses

## Installation

### Prerequisites

1. **Kali Linux Host** - A Kali Linux system accessible via SSH
2. **SSH Configuration** - SSH access configured in `~/.ssh/config`
3. **theHarvester** - Installed on the Kali host:
   ```bash
   sudo apt install theharvester
   ```
4. **Node.js** - Version 18 or higher

### Setup

```bash
# Clone the repository
git clone https://github.com/schwarztim/sec-theharvester-mcp.git
cd sec-theharvester-mcp

# Install dependencies
npm install

# Build the project
npm run build
```

### MCP Configuration

Add to your Claude Desktop or MCP client configuration:

```json
{
  "mcpServers": {
    "theharvester": {
      "command": "node",
      "args": ["/path/to/sec-theharvester-mcp/dist/index.js"],
      "env": {
        "KALI_HOST": "kali"
      }
    }
  }
}
```

## Tools

| Tool | Description |
|------|-------------|
| `theharvester_search` | Full OSINT search with configurable sources and options |
| `theharvester_sources` | List available data sources and API requirements |
| `theharvester_emails` | Quick search focused on email harvesting |
| `theharvester_hosts` | Quick search for subdomain/host discovery |
| `theharvester_dns_brute` | DNS brute force enumeration |
| `theharvester_shodan` | Search with Shodan integration for detailed host info |
| `theharvester_full_recon` | Comprehensive reconnaissance using all features |
| `theharvester_check_status` | Verify theHarvester availability on Kali host |

## Data Sources

### No API Key Required
- anubis, baidu, bing, crtsh, dnsdumpster, duckduckgo
- hackertarget, otx, rapiddns, sitedossier, subdomaincenter
- threatminer, urlscan, yahoo

### API Key Required
- bevigil, binaryedge, brave, bufferoverun, censys
- criminalip, fullhunt, github-code, hunter, hunterhow
- intelx, leakix, netlas, onyphe, pentesttools
- projectdiscovery, rocketreach, securityscorecard
- securitytrails, shodan, tomba, virustotal, zoomeye

Configure API keys in theHarvester's configuration file on your Kali host.

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `KALI_HOST` | `kali` | SSH hostname for Kali Linux system |

### SSH Setup

Ensure your SSH config (`~/.ssh/config`) includes an entry for your Kali host:

```
Host kali
    HostName 192.168.1.100
    User root
    IdentityFile ~/.ssh/kali_key
```

## Usage Examples

### Basic Domain Search
```json
{
  "tool": "theharvester_search",
  "arguments": {
    "domain": "example.com",
    "sources": ["bing", "crtsh", "dnsdumpster"],
    "limit": 500
  }
}
```

### Email Harvesting
```json
{
  "tool": "theharvester_emails",
  "arguments": {
    "domain": "example.com",
    "sources": ["hunter", "tomba", "bing"]
  }
}
```

### Subdomain Discovery with DNS Resolution
```json
{
  "tool": "theharvester_hosts",
  "arguments": {
    "domain": "example.com",
    "dns_resolve": true,
    "dns_brute": true
  }
}
```

### Full Reconnaissance
```json
{
  "tool": "theharvester_full_recon",
  "arguments": {
    "domain": "example.com"
  }
}
```

## Output Format

All tools return structured JSON with:
- Parsed results (emails, hosts, IPs, URLs, ASNs)
- Statistics and metadata
- Raw output for detailed analysis

Example response:
```json
{
  "domain": "example.com",
  "sources": ["bing", "crtsh"],
  "emails": ["admin@example.com", "support@example.com"],
  "hosts": ["www.example.com", "mail.example.com"],
  "ips": ["93.184.216.34"],
  "urls": [],
  "asns": [],
  "interesting_urls": [],
  "raw_output": "..."
}
```

## Security Considerations

- This tool is intended for **authorized security testing only**
- Always obtain proper authorization before scanning any domain
- Be mindful of rate limits on data source APIs
- Some sources may log your queries

## Development

```bash
# Watch mode for development
npm run dev

# Build for production
npm run build

# Run the server
npm start
```

## Related Projects

- [theHarvester](https://github.com/laramies/theHarvester) - The underlying OSINT tool
- [Model Context Protocol](https://modelcontextprotocol.io) - MCP specification

## License

MIT License - see [LICENSE](LICENSE) for details.

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before scanning any systems or domains. The authors are not responsible for any misuse of this software.
