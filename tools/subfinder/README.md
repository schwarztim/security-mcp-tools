# sec-subfinder-mcp

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![MCP](https://img.shields.io/badge/MCP-Model%20Context%20Protocol-blue)](https://modelcontextprotocol.io/)
[![Subfinder](https://img.shields.io/badge/Tool-Subfinder-orange)](https://github.com/projectdiscovery/subfinder)

An MCP (Model Context Protocol) server for [ProjectDiscovery Subfinder](https://github.com/projectdiscovery/subfinder) - a fast passive subdomain enumeration tool used in penetration testing and bug bounty hunting.

## Features

- **Passive Subdomain Discovery** - Enumerate subdomains using 50+ passive sources without active probing
- **Recursive Enumeration** - Find subdomains of subdomains for deeper discovery
- **Bulk Operations** - Process multiple domains in a single operation
- **Source Control** - Select specific sources or exclude unreliable ones
- **Pattern Filtering** - Match or exclude subdomains based on patterns
- **Remote Execution** - Executes on a remote Kali Linux system via SSH

## Prerequisites

- Node.js 18+
- SSH access to a Linux system (e.g., Kali) with [subfinder](https://github.com/projectdiscovery/subfinder) installed
- SSH key authentication configured (passwordless)

### Installing Subfinder on Remote System

```bash
# Using Go
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Or using package manager on Kali
sudo apt install subfinder
```

## Installation

```bash
git clone https://github.com/schwarztim/sec-subfinder-mcp.git
cd sec-subfinder-mcp
npm install
npm run build
```

## Configuration

### Claude Desktop / Claude Code

Add to your MCP configuration:

```json
{
  "mcpServers": {
    "subfinder": {
      "command": "node",
      "args": ["/path/to/sec-subfinder-mcp/dist/index.js"],
      "env": {
        "KALI_HOST": "your-kali-hostname",
        "SSH_PORT": "22"
      }
    }
  }
}
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `KALI_HOST` | `kali` | SSH hostname for the remote system |
| `SSH_PORT` | `22222` | SSH port |
| `SUBFINDER_PATH` | `~/bin/subfinder` | Path to subfinder binary on remote system |

## Available Tools

### subfinder_enum

Main subdomain enumeration tool. Discovers subdomains using passive sources.

```
Input:
- domain (required): Target domain (e.g., "example.com")
- sources: Array of specific sources to use
- excludeSources: Array of sources to exclude
- recursive: Enable recursive enumeration
- all: Use all available sources
- json: Output in JSON format
- collectSources: Include source information in output
- match: Patterns to include
- filter: Patterns to exclude
- rateLimit: Max requests per second
- timeout: Timeout per source (seconds)
```

### subfinder_sources

List all available passive sources for subdomain enumeration.

### subfinder_recursive

Perform recursive subdomain enumeration (finds sub.sub.example.com).

```
Input:
- domain (required): Target domain
- maxDepth: Maximum recursion depth (default: 2)
- sources: Specific sources to use
- rateLimit: Rate limit for requests
```

### subfinder_bulk

Enumerate subdomains for multiple domains simultaneously.

```
Input:
- domains (required): Array of domains
- sources: Specific sources to use
- all: Use all available sources
- json: Output in JSON format
- rateLimit: Rate limit for requests
```

### subfinder_filter

Run enumeration with pattern matching/filtering.

```
Input:
- domain (required): Target domain
- match: Patterns to include (e.g., ["api", "dev"])
- filter: Patterns to exclude (e.g., ["staging"])
- all: Use all sources
```

### subfinder_config

Check subfinder configuration and API key status.

### subfinder_version

Get subfinder version and verify installation.

## Usage Examples

### Basic Enumeration

> Enumerate subdomains for example.com

### Comprehensive Scan

> Find all subdomains for example.com using all available sources

### Targeted Discovery

> Find api and dev subdomains for example.com, excluding staging environments

### Multiple Domains

> Enumerate subdomains for example.com, test.com, and demo.org

## Passive Sources

Subfinder supports 50+ passive sources including:

**Free (No API Key):**
- crtsh, hackertarget, alienvault, anubis, columbus, commoncrawl, dnsdumpster, rapiddns, sitedossier, waybackarchive

**API Key Required:**
- censys, securitytrails, shodan, virustotal, github, chaos, binaryedge, fofa, intelx, netlas, zoomeye, and more

Configure API keys in `~/.config/subfinder/provider-config.yaml` on the remote system:

```yaml
securitytrails:
  - YOUR_API_KEY
shodan:
  - YOUR_API_KEY
virustotal:
  - YOUR_API_KEY
```

## Security Considerations

- This tool performs **passive reconnaissance only** - no active probing of target systems
- Ensure you have authorization before scanning any domain
- Use responsibly and in accordance with applicable laws and regulations
- API keys should be stored securely on the remote system

## Architecture

```
Claude/AI Assistant
       |
       v
  [MCP Server] (Node.js)
       |
       v (SSH)
  [Kali Linux]
       |
       v
  [Subfinder CLI]
       |
       v
  [Passive Sources]
```

## Development

```bash
# Watch mode for development
npm run dev

# Build
npm run build

# Run
npm start
```

## Related Projects

- [Subfinder](https://github.com/projectdiscovery/subfinder) - The underlying subdomain enumeration tool
- [Model Context Protocol](https://modelcontextprotocol.io/) - The protocol specification
- [ProjectDiscovery](https://github.com/projectdiscovery) - Security tools suite

## License

MIT License - see [LICENSE](LICENSE) for details.

## Disclaimer

This tool is intended for authorized security testing and research purposes only. Users are responsible for ensuring they have proper authorization before scanning any systems or domains. The authors are not responsible for any misuse or damage caused by this tool.
