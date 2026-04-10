# Shodan MCP Server

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server that provides comprehensive access to the [Shodan](https://www.shodan.io/) IoT search engine API. This enables AI assistants to perform network reconnaissance, vulnerability research, and security analysis using Shodan's powerful search capabilities.

## Features

- **Device Search**: Search the Shodan database for internet-connected devices using powerful query syntax
- **Host Intelligence**: Get detailed information about specific IP addresses including open ports, services, and vulnerabilities
- **Exploit Database**: Search Shodan's exploit database covering CVE, Exploit-DB, and Metasploit
- **Network Scanning**: Request on-demand scans of IP addresses and network ranges
- **Network Monitoring**: Create alerts to monitor IP ranges for changes
- **DNS Operations**: Perform forward and reverse DNS lookups, enumerate subdomains
- **Honeypot Detection**: Identify potential honeypots using Shodan's honeyscore algorithm

## Prerequisites

- Node.js 18 or higher
- A Shodan API key (get one at [account.shodan.io](https://account.shodan.io/))

## Installation

```bash
# Clone the repository
git clone https://github.com/schwarztim/sec-shodan-mcp.git
cd sec-shodan-mcp

# Install dependencies
npm install

# Build the project
npm run build
```

## Configuration

### Claude Desktop

Add to your Claude Desktop configuration file:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%\Claude\claude_desktop_config.json`
**Linux**: `~/.config/claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "shodan": {
      "command": "node",
      "args": ["/path/to/sec-shodan-mcp/dist/index.js"],
      "env": {
        "SHODAN_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

### Claude Code

Add to `~/.claude/user-mcps.json`:

```json
{
  "mcpServers": {
    "shodan": {
      "command": "node",
      "args": ["/path/to/sec-shodan-mcp/dist/index.js"],
      "env": {
        "SHODAN_API_KEY": "your-api-key-here"
      }
    }
  }
}
```

## Available Tools

### Search & Discovery

| Tool | Description |
|------|-------------|
| `shodan_search` | Search Shodan for devices matching a query with filters like `port:`, `country:`, `org:`, `product:`, `vuln:` |
| `shodan_host` | Get all information about a specific IP including ports, services, banners, vulnerabilities, and SSL certificates |
| `shodan_count` | Count search results without consuming query credits |

### Exploits Database

| Tool | Description |
|------|-------------|
| `shodan_exploits_search` | Search for exploits by CVE, author, platform, type, or port |
| `shodan_exploits_count` | Count matching exploits without returning individual results |

### Network Scanning

| Tool | Description |
|------|-------------|
| `shodan_scan` | Request on-demand scan of IP addresses or CIDR ranges |
| `shodan_scan_status` | Check the status of a previously submitted scan |
| `shodan_list_scans` | List all active on-demand scans |

### Network Alerts

| Tool | Description |
|------|-------------|
| `shodan_alert_create` | Create monitoring alerts for IP ranges |
| `shodan_alert_list` | List all active network alerts |
| `shodan_alert_get` | Get details for a specific alert |
| `shodan_alert_delete` | Delete a network alert |
| `shodan_alert_triggers` | List available alert trigger types |

### DNS Operations

| Tool | Description |
|------|-------------|
| `shodan_dns_resolve` | Resolve hostnames to IP addresses (forward DNS) |
| `shodan_dns_reverse` | Look up hostnames for IP addresses (reverse DNS) |
| `shodan_dns_domain` | Get DNS information for a domain including subdomains |

### Security Analysis

| Tool | Description |
|------|-------------|
| `shodan_honeyscore` | Calculate probability that an IP is a honeypot (0.0 to 1.0) |

### Utility

| Tool | Description |
|------|-------------|
| `shodan_ports` | List all ports that Shodan crawls |
| `shodan_protocols` | List protocols available for on-demand scanning |
| `shodan_filters` | List all search filters available in Shodan |
| `shodan_facets` | List facets available for search result breakdowns |
| `shodan_api_info` | Get API plan info including query and scan credits |
| `shodan_account_profile` | Get account information for the API key |
| `shodan_myip` | Get your current public IP address |

### Query Library

| Tool | Description |
|------|-------------|
| `shodan_saved_queries` | Browse the directory of saved search queries |
| `shodan_search_queries` | Search the saved query directory |

## Usage Examples

### Search for Devices

```
# Find Apache servers in the United States
shodan_search: query="apache country:US"

# Find open SSH servers
shodan_search: query="port:22 product:openssh"

# Find devices vulnerable to Log4Shell
shodan_search: query="vuln:CVE-2021-44228"

# Find webcams with screenshots
shodan_search: query="webcam has_screenshot:true"

# Find industrial control systems
shodan_search: query="tag:ics"

# Find devices by organization
shodan_search: query="org:\"Google LLC\""
```

### Get Host Information

```
# Get details about a specific IP
shodan_host: ip="8.8.8.8"

# Include historical data
shodan_host: ip="8.8.8.8" history=true
```

### Search Exploits

```
# Search for Log4j exploits
shodan_exploits_search: query="log4j"

# Find exploits by CVE
shodan_exploits_search: query="cve:CVE-2021-44228"

# Find Metasploit modules
shodan_exploits_search: query="source:metasploit"
```

### DNS Operations

```
# Resolve hostnames
shodan_dns_resolve: hostnames="google.com,github.com"

# Reverse DNS lookup
shodan_dns_reverse: ips="8.8.8.8,1.1.1.1"

# Get domain information
shodan_dns_domain: domain="example.com"
```

## API Credits

Different Shodan API plans have different credit limits:

- **Free accounts**: Limited search queries per month
- **Search with pagination**: Consumes query credits
- **`shodan_count`**: Does NOT consume credits (use for scoping)
- **On-demand scanning**: Consumes scan credits (1 credit per IP)
- **Some filters** (like `vuln:`) require paid plans

Check your current credits with `shodan_api_info`.

## Development

```bash
# Run in development mode
npm run dev

# Build for production
npm run build

# Start the server
npm start
```

## Security Notice

This tool is intended for legitimate security research, penetration testing (with authorization), and network defense purposes. Always ensure you have proper authorization before scanning or probing systems you do not own.

## Resources

- [Shodan API Documentation](https://developer.shodan.io/api)
- [Shodan Exploits API](https://developer.shodan.io/api/exploits/rest)
- [Search Filter Reference](https://www.shodan.io/search/filters)
- [Model Context Protocol](https://modelcontextprotocol.io/)

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
