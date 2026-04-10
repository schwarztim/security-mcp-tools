# DIRB MCP Server

A Model Context Protocol (MCP) server that provides tools for running [DIRB](https://dirb.sourceforge.net/) web content scans via SSH to a Kali Linux machine.

DIRB is a dictionary-based web content scanner that discovers hidden directories and files by launching dictionary attacks against web servers and analyzing responses.

## Features

- **Directory Scanning**: Discover hidden directories and files on web servers
- **Multiple Wordlists**: Supports 20+ built-in wordlists including vulnerability-specific ones
- **Authentication Support**: HTTP Basic Auth and proxy authentication
- **Proxy Integration**: Route scans through Burp Suite, OWASP ZAP, or other proxies
- **Technology-Specific Scans**: Targeted wordlists for Apache, IIS, Tomcat, SharePoint, and more
- **Full DIRB Options**: Access to all DIRB command-line features

## Prerequisites

- **Kali Linux** machine with DIRB installed (accessible via SSH)
- **SSH key-based authentication** configured to the Kali machine
- **Node.js** 18+ on the machine running the MCP server

## Installation

```bash
git clone https://github.com/schwarztim/sec-dirb-mcp.git
cd sec-dirb-mcp
npm install
npm run build
```

## Configuration

Set environment variables to configure SSH connection:

| Variable | Description | Default |
|----------|-------------|---------|
| `KALI_SSH_HOST` | Kali Linux hostname or IP | `kali` |
| `KALI_SSH_USER` | SSH username | (uses SSH config) |
| `KALI_SSH_PORT` | SSH port | `22` |
| `DIRB_WORDLIST_PATH` | Default wordlist path | `/usr/share/dirb/wordlists/common.txt` |

### SSH Configuration

For seamless connectivity, configure your `~/.ssh/config`:

```
Host kali
    HostName 192.168.1.100
    User kali
    IdentityFile ~/.ssh/id_rsa
```

## MCP Client Configuration

### Claude Desktop

Add to your Claude Desktop configuration (`~/.config/claude/claude_desktop_config.json` on Linux or `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "dirb": {
      "command": "node",
      "args": ["/path/to/sec-dirb-mcp/dist/index.js"],
      "env": {
        "KALI_SSH_HOST": "kali",
        "KALI_SSH_USER": "kali"
      }
    }
  }
}
```

### Claude Code CLI

Add to your user MCP configuration (`~/.claude/user-mcps.json`):

```json
{
  "mcpServers": {
    "dirb": {
      "command": "node",
      "args": ["/path/to/sec-dirb-mcp/dist/index.js"],
      "env": {
        "KALI_SSH_HOST": "kali"
      }
    }
  }
}
```

## Available Tools

### `dirb_scan`

Standard directory scan against a target URL.

```
Parameters:
- url (required): Target URL (e.g., http://example.com)
- wordlist: Wordlist name or path (default: common)
- extensions: File extensions to append (e.g., ".php,.html,.bak")
- recursive: Enable recursive scanning (default: true)
- delay: Delay in ms between requests
- caseInsensitive: Case-insensitive search
- ignoreCode: HTTP status code to ignore
- timeout: Scan timeout in seconds (default: 300)
```

### `dirb_scan_auth`

Scan with HTTP Basic Authentication.

```
Parameters:
- url (required): Target URL
- username (required): HTTP Basic Auth username
- password (required): HTTP Basic Auth password
- wordlist, extensions, timeout: Same as dirb_scan
```

### `dirb_scan_proxy`

Scan through a proxy (e.g., Burp Suite).

```
Parameters:
- url (required): Target URL
- proxy (required): Proxy address (e.g., "127.0.0.1:8080")
- proxyAuth: Proxy authentication (username:password)
- wordlist, extensions, timeout: Same as dirb_scan
```

### `dirb_vuln_scan`

Vulnerability-focused scan using technology-specific wordlists.

```
Parameters:
- url (required): Target URL
- technology (required): Target technology
  Options: apache, iis, tomcat, weblogic, frontpage, netware, cgis, sap, sharepoint
- extensions, delay, timeout: Same as dirb_scan
```

### `dirb_scan_custom`

Advanced scan with full control over all DIRB options.

```
Parameters:
- All parameters from other tools, plus:
- cookie: Cookie string for requests
- userAgent: Custom User-Agent
- showLocation: Show Location header
- noEndingSlash: Don't force ending slash
- silentMode: Don't show tested words
- showNotFound: Show NOT_FOUND pages
- noWarnings: Don't stop on warnings
- customHeader: Custom HTTP header
- clientCert: Client certificate path
- fineTuning404: Fine tuning of 404 detection
```

### `dirb_list_wordlists`

List all available preset wordlists.

### `dirb_check_status`

Check SSH connectivity and DIRB installation status.

## Wordlists

### General
- `common` - Standard common directory names
- `big` - Large comprehensive wordlist
- `small` - Quick scan with common names

### Vulnerability-Specific
- `vulns_apache` - Apache vulnerabilities
- `vulns_iis` - IIS vulnerabilities
- `vulns_tomcat` - Tomcat paths
- `vulns_weblogic` - WebLogic paths
- `vulns_frontpage` - FrontPage paths
- `vulns_sharepoint` - SharePoint paths
- `vulns_cgis` - Common CGI vulnerabilities
- `vulns_sap` - SAP paths
- `vulns_netware` - NetWare paths

### Language-Specific
- `catala`, `euskera`, `spanish`

## Usage Examples

### Basic Scan
```
"Scan http://target.local for directories"
```

### Scan with Extensions
```
"Scan http://target.local looking for .php, .html, and .bak files"
```

### Vulnerability Scan
```
"Run an Apache vulnerability scan against http://target.local"
```

### Authenticated Scan
```
"Scan http://target.local with username admin and password secret123"
```

### Proxy Scan
```
"Scan http://target.local through Burp proxy at 127.0.0.1:8080"
```

## Security Considerations

- **Authorization**: Only scan systems you have explicit permission to test
- **Rate Limiting**: Use the `delay` parameter to avoid overwhelming targets
- **Proxy Usage**: Route through a proxy for traffic inspection and evidence collection
- **Credentials**: Avoid hardcoding credentials; use environment variables

## Troubleshooting

### SSH Connection Issues

1. Test SSH manually:
   ```bash
   ssh kali "echo hello"
   ```

2. Verify SSH key is added:
   ```bash
   ssh-add -l
   ```

3. Check SSH config permissions:
   ```bash
   chmod 600 ~/.ssh/config
   chmod 700 ~/.ssh
   ```

### DIRB Not Found

Install DIRB on Kali Linux:
```bash
sudo apt update && sudo apt install dirb
```

### Timeout Issues

Increase the timeout parameter for large wordlists or slow networks:
```
timeout: 600  # 10 minutes
```

## License

MIT License - see [LICENSE](LICENSE) file.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Disclaimer

This tool is intended for authorized security testing only. Unauthorized access to computer systems is illegal. Always obtain proper authorization before scanning any systems.
