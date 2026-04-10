# Nikto MCP Server

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![MCP](https://img.shields.io/badge/MCP-Compatible-blue)](https://modelcontextprotocol.io/)
[![Node.js](https://img.shields.io/badge/Node.js-20%2B-green)](https://nodejs.org/)

An MCP (Model Context Protocol) server that enables AI agents to interact with the [Nikto web server scanner](https://github.com/sullo/nikto) via SSH to a Kali Linux host.

## Features

- **Web Server Vulnerability Scanning**: Scan targets for 6700+ potentially dangerous files/programs
- **Configurable Test Categories**: Tuning options for specific vulnerability types
- **IDS Evasion**: Multiple techniques to bypass intrusion detection systems
- **Plugin System**: Modular plugin architecture for extensible scanning
- **Multiple Output Formats**: JSON, CSV, HTML, XML, and text output
- **SSH Execution**: Runs Nikto on a remote Kali Linux host for isolation
- **Security**: Input validation to prevent command injection

## Prerequisites

- Node.js 20.0.0 or higher
- SSH access to a Kali Linux host with Nikto installed
- SSH key-based authentication configured (BatchMode)

## Installation

```bash
# Clone the repository
git clone https://github.com/schwarztim/sec-nikto-mcp.git
cd sec-nikto-mcp

# Install dependencies
npm install

# Build
npm run build
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `KALI_HOST` | `kali` | SSH hostname for Kali Linux |
| `SSH_USER` | (empty) | SSH username (optional if using SSH config) |
| `NIKTO_TIMEOUT` | `300000` | Default scan timeout in milliseconds (5 min) |

### Claude Desktop Configuration

Add to your Claude Desktop config:

```json
{
  "mcpServers": {
    "nikto": {
      "command": "node",
      "args": ["/path/to/sec-nikto-mcp/dist/index.js"],
      "env": {
        "KALI_HOST": "your-kali-host",
        "SSH_USER": "kali",
        "NIKTO_TIMEOUT": "600000"
      }
    }
  }
}
```

## Tools

### nikto_scan

Start a web server vulnerability scan.

**Parameters:**

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `target` | string | Yes | URL, IP address, or hostname |
| `port` | string | No | TCP port(s) - single, range (80-90), or comma-separated |
| `ssl` | boolean | No | Force SSL/HTTPS testing |
| `nossl` | boolean | No | Disable SSL testing |
| `tuning` | string | No | Test categories (0-9, a-c, x for exclude) |
| `plugins` | string | No | Comma-separated plugin list |
| `evasion` | string | No | IDS evasion techniques (1-8) |
| `timeout` | number | No | Per-request timeout in seconds |
| `pause` | number | No | Delay between tests (rate limiting) |
| `vhost` | string | No | Virtual host header |
| `id` | string | No | HTTP Basic auth (id:password) |
| `root` | string | No | Prepend path to all requests |
| `cgidirs` | string | No | CGI directories to scan |
| `useproxy` | boolean | No | Use configured proxy |
| `nolookup` | boolean | No | Disable DNS lookups |
| `no404` | boolean | No | Disable 404 checking |
| `findonly` | boolean | No | Port discovery only |
| `mutate` | string | No | Mutation techniques (1-6) |
| `format` | string | No | Output format (csv, htm, txt, xml, json) |
| `scan_timeout` | number | No | Overall scan timeout in seconds |

### nikto_plugins

List all available Nikto plugins.

### nikto_tuning

Get detailed reference for tuning options (test categories).

### nikto_evasion

Get detailed reference for IDS evasion techniques.

### nikto_update

Update Nikto plugins and databases from cirt.net.

### nikto_version

Get Nikto version and database information.

### nikto_check_db

Check scan databases for syntax errors.

## Usage Examples

### Basic Scan

```
Scan https://example.com with Nikto
```

### SSL Scan with Tuning

```
Run a Nikto scan on example.com port 443 with SSL, focusing on misconfiguration and information disclosure tests
```

### Stealth Scan with IDS Evasion

```
Scan target.com using IDS evasion techniques 1, 2, and 4 with a 2-second pause between requests
```

### Comprehensive Audit

```
Perform a full Nikto scan on example.com ports 80 and 443 with SSL, output in JSON format
```

## Tuning Reference

| Code | Category |
|------|----------|
| 0 | File Upload |
| 1 | Interesting File / Seen in logs |
| 2 | Misconfiguration / Default File |
| 3 | Information Disclosure |
| 4 | Injection (XSS/Script/HTML) |
| 5 | Remote File Retrieval - Inside Web Root |
| 6 | Denial of Service |
| 7 | Remote File Retrieval - Server Wide |
| 8 | Command Execution / Remote Shell |
| 9 | SQL Injection |
| a | Authentication Bypass |
| b | Software Identification |
| c | Remote Source Inclusion |
| x | Reverse (exclude specified) |

## Evasion Techniques

| Code | Technique |
|------|-----------|
| 1 | Random URI encoding (non-UTF8) |
| 2 | Directory self-reference (/./) |
| 3 | Premature URL ending |
| 4 | Prepend long random string |
| 5 | Fake parameter |
| 6 | TAB as request spacer |
| 7 | Change the case of the URL |
| 8 | Use Windows directory separator (\\) |

## Security Considerations

- This tool is intended for **authorized security testing only**
- Always obtain proper authorization before scanning any systems
- Input validation prevents command injection attacks
- SSH keys should be properly secured with restricted permissions
- Consider network isolation for scanning infrastructure
- The server uses `BatchMode=yes` for non-interactive SSH execution

## Related Projects

- [Nikto](https://github.com/sullo/nikto) - The Nikto web server scanner
- [Model Context Protocol](https://modelcontextprotocol.io/) - MCP specification
- [MCP SDK](https://github.com/modelcontextprotocol/sdk) - Official MCP SDK
- [Kali Linux](https://www.kali.org/) - Penetration testing distribution

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before scanning any systems. The authors are not responsible for any misuse or damage caused by this tool.
