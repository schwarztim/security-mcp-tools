# WPScan MCP Server

A Model Context Protocol (MCP) server that provides AI assistants with access to [WPScan](https://wpscan.com/) - the WordPress security scanner. This server executes WPScan commands on a remote Kali Linux host via SSH, making it ideal for security testing workflows.

## Features

- **Full WordPress Security Scanning** - Comprehensive vulnerability assessment
- **Component Enumeration** - Discover plugins, themes, and users
- **Vulnerability Detection** - Check for known CVEs in WordPress core, plugins, and themes
- **Password Auditing** - Brute-force testing capabilities (authorized use only)
- **Flexible Configuration** - Support for proxies, custom user agents, and stealth mode
- **JSON Output** - Structured data for easy AI processing

## Tools

| Tool | Description |
|------|-------------|
| `wpscan_scan` | Perform a full WordPress security scan |
| `wpscan_enumerate` | Enumerate specific components (users, plugins, themes) |
| `wpscan_vulns` | Check for known vulnerabilities |
| `wpscan_plugins` | Enumerate WordPress plugins |
| `wpscan_themes` | Enumerate WordPress themes |
| `wpscan_users` | Enumerate WordPress users |
| `wpscan_bruteforce` | Password brute-force testing (authorized use only) |
| `wpscan_update` | Update the WPScan vulnerability database |
| `wpscan_info` | Get WPScan version and configuration |
| `wpscan_custom` | Execute custom WPScan commands |

## Prerequisites

- Node.js 18+
- SSH access to a Kali Linux host with WPScan installed
- (Optional) WPScan API token for vulnerability data

## Installation

```bash
git clone https://github.com/schwarztim/sec-wpscan-mcp.git
cd sec-wpscan-mcp
npm install
npm run build
```

## Configuration

Set the following environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `KALI_HOST` | SSH hostname for Kali Linux | `kali` |
| `WPSCAN_API_TOKEN` | WPScan API token for vulnerability data | (none) |
| `SSH_TIMEOUT` | SSH command timeout in milliseconds | `300000` |

### SSH Setup

Ensure passwordless SSH access to your Kali host:

```bash
# Generate SSH key if needed
ssh-keygen -t ed25519

# Copy key to Kali host
ssh-copy-id kali

# Test connection
ssh kali "wpscan --version"
```

### Claude Desktop Configuration

Add to your Claude Desktop config (`~/.config/claude/claude_desktop_config.json` on Linux or `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "wpscan": {
      "command": "node",
      "args": ["/path/to/sec-wpscan-mcp/dist/index.js"],
      "env": {
        "KALI_HOST": "kali",
        "WPSCAN_API_TOKEN": "your-api-token"
      }
    }
  }
}
```

## Usage Examples

### Full Security Scan

```
Scan https://example.com for WordPress vulnerabilities
```

The AI will use `wpscan_scan` with appropriate parameters to perform a comprehensive security assessment.

### Enumerate Plugins

```
Find all plugins installed on https://example.com
```

Uses `wpscan_plugins` to discover installed WordPress plugins and their versions.

### Check for Vulnerabilities

```
Check https://example.com for known CVEs
```

Uses `wpscan_vulns` to identify vulnerabilities in WordPress core, plugins, and themes.

### Stealth Mode

```
Perform a stealthy scan of https://example.com to avoid detection
```

Uses `wpscan_scan` with stealth options (passive detection, random user agent).

## Security Considerations

- **Authorization Required** - Only scan systems you have explicit permission to test
- **API Token Security** - Keep your WPScan API token secure; do not commit to version control
- **Brute-Force Caution** - Password testing features should only be used in authorized penetration tests
- **Network Isolation** - Consider running Kali in an isolated network for security testing

## Getting a WPScan API Token

1. Register at [https://wpscan.com/](https://wpscan.com/)
2. Navigate to your profile to obtain an API token
3. The free tier includes 25 API requests per day

## License

MIT License - see [LICENSE](LICENSE) for details.

## Related Projects

- [WPScan](https://github.com/wpscanteam/wpscan) - The WordPress security scanner
- [Model Context Protocol](https://modelcontextprotocol.io/) - The protocol specification
- [MCP SDK](https://github.com/modelcontextprotocol/typescript-sdk) - TypeScript SDK for MCP

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
