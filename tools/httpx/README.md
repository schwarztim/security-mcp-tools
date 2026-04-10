# httpx MCP Server

A Model Context Protocol (MCP) server that provides AI assistants with access to [ProjectDiscovery's httpx](https://github.com/projectdiscovery/httpx) - a fast and multi-purpose HTTP toolkit for web reconnaissance.

## Overview

This MCP server enables AI assistants to perform HTTP probing and web server reconnaissance through a secure SSH connection to a remote Kali Linux system. It wraps httpx's powerful capabilities into structured, easy-to-use tools for discovering live web servers, detecting technologies, and gathering HTTP response data.

## Features

- **HTTP Probing** - Discover live web servers from lists of hosts or URLs
- **Technology Detection** - Identify CMS, frameworks, and web technologies using Wappalyzer fingerprints
- **Status Code Filtering** - Filter responses by HTTP status codes
- **Title Extraction** - Extract page titles for quick categorization
- **Screenshot Capture** - Take visual screenshots of web pages
- **CDN Detection** - Identify CDN providers and WAF protection
- **TLS Fingerprinting** - JARM fingerprints for identifying TLS configurations
- **Favicon Hashing** - Calculate favicon mmh3 hashes for application identification
- **Path Probing** - Check specific endpoints across multiple hosts

## Tools

| Tool | Description |
|------|-------------|
| `httpx_probe` | Probe HTTP/HTTPS servers for availability and basic info |
| `httpx_tech_detect` | Detect web technologies using Wappalyzer fingerprints |
| `httpx_status_filter` | Filter responses by HTTP status codes |
| `httpx_title` | Extract page titles from web servers |
| `httpx_screenshot` | Capture screenshots of web pages |
| `httpx_cdn_detect` | Detect CDN/WAF protection |
| `httpx_fingerprint` | Advanced fingerprinting (JARM, favicon hash) |
| `httpx_full_scan` | Comprehensive scan with all major probes |
| `httpx_path_probe` | Probe specific paths across multiple hosts |
| `httpx_custom` | Run httpx with custom flags |

## Prerequisites

- Node.js 18+
- SSH access to a system with httpx installed
- [ProjectDiscovery httpx](https://github.com/projectdiscovery/httpx) binary on the remote system

## Installation

```bash
# Clone the repository
git clone https://github.com/schwarztim/sec-httpx-mcp.git
cd sec-httpx-mcp

# Install dependencies
npm install

# Build
npm run build
```

## Configuration

The server uses environment variables for configuration:

| Variable | Description | Default |
|----------|-------------|---------|
| `HTTPX_SSH_HOST` | SSH host alias or address | `kali` |
| `HTTPX_TIMEOUT` | Command timeout in milliseconds | `300000` (5 min) |
| `HTTPX_BINARY` | Path to httpx binary on remote | `~/bin/httpx-pd` |

### SSH Setup

Ensure you have SSH key-based authentication configured for the remote host:

```bash
# Add to ~/.ssh/config
Host kali
    HostName your-kali-host
    User your-username
    IdentityFile ~/.ssh/your-key
```

## Usage with Claude Desktop

Add to your Claude Desktop configuration (`~/.claude/user-mcps.json` or Claude Desktop config):

```json
{
  "mcpServers": {
    "httpx": {
      "command": "node",
      "args": ["/path/to/sec-httpx-mcp/dist/index.js"],
      "env": {
        "HTTPX_SSH_HOST": "kali",
        "HTTPX_BINARY": "~/bin/httpx-pd"
      }
    }
  }
}
```

## Example Usage

### Probe HTTP Servers

```
Probe these hosts for live web servers:
- example.com
- test.example.org
- 192.168.1.100
```

### Technology Detection

```
Detect technologies on https://example.com
```

### Find Admin Panels

```
Check these hosts for /admin, /login, and /dashboard endpoints:
- https://app1.example.com
- https://app2.example.com
```

### CDN Detection

```
Check if example.com is behind a CDN
```

## Security Considerations

- This tool executes commands on a remote system via SSH
- Only use on systems and targets you have authorization to test
- The remote system should be properly secured
- Consider network isolation for the scanning host

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- [ProjectDiscovery](https://projectdiscovery.io/) for creating httpx
- [Model Context Protocol](https://modelcontextprotocol.io/) specification
