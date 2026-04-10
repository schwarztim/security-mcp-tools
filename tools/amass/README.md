# sec-amass-mcp

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![MCP](https://img.shields.io/badge/MCP-1.0-blue.svg)](https://modelcontextprotocol.io)
[![OWASP Amass](https://img.shields.io/badge/OWASP-Amass-green.svg)](https://owasp.org/www-project-amass/)

A Model Context Protocol (MCP) server for **OWASP Amass** - the premier open-source tool for subdomain enumeration and attack surface mapping. This server enables AI assistants to perform comprehensive reconnaissance and asset discovery via natural language.

## Overview

This MCP server provides a bridge between AI assistants and OWASP Amass, executing commands via SSH on a remote Kali Linux system. It exposes all major Amass capabilities including subdomain enumeration, intelligence gathering, change tracking, and visualization generation.

### Key Features

- **Subdomain Enumeration** - Passive (OSINT), active (DNS), and brute-force discovery
- **Intelligence Gathering** - Reverse WHOIS, ASN lookup, CIDR investigation
- **Attack Surface Tracking** - Monitor infrastructure changes over time
- **Graph Database** - Query and manage discovered assets
- **Visualization Export** - D3.js, Vis.js, Maltego, GEXF formats
- **Configurable Data Sources** - Support for 50+ OSINT APIs

## Prerequisites

### 1. Kali Linux with Amass

Amass must be installed on a Kali Linux system:

```bash
# Option 1: Package manager
sudo apt update && sudo apt install amass

# Option 2: Go install (latest version)
go install -v github.com/owasp-amass/amass/v4/...@master
```

### 2. SSH Access Configuration

Key-based SSH authentication to your Kali system is required. Configure a host alias in `~/.ssh/config`:

```
Host kali
    HostName 192.168.1.100
    Port 22
    User your-username
    IdentityFile ~/.ssh/id_ed25519
```

Test connectivity:

```bash
ssh kali amass -version
```

### 3. Optional: Sudoers Configuration

If Amass requires elevated privileges on your Kali system:

```bash
echo "your-username ALL=(ALL) NOPASSWD: /usr/bin/amass" | sudo tee /etc/sudoers.d/amass
```

## Installation

```bash
git clone https://github.com/schwarztim/sec-amass-mcp.git
cd sec-amass-mcp
npm install
npm run build
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `AMASS_SSH_HOST` | `kali` | SSH host alias for Kali system |
| `AMASS_TIMEOUT` | `600000` | Command timeout in milliseconds (10 min default) |

### Claude Desktop Configuration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "amass": {
      "command": "node",
      "args": ["/path/to/sec-amass-mcp/dist/index.js"],
      "env": {
        "AMASS_SSH_HOST": "kali",
        "AMASS_TIMEOUT": "600000"
      }
    }
  }
}
```

### Amass Configuration (Optional)

For enhanced results, configure API keys in `~/.config/amass/config.yaml` on your Kali system:

```yaml
scope:
  domains:
    - example.com

options:
  resolvers:
    - 8.8.8.8
    - 1.1.1.1

data_sources:
  - name: SecurityTrails
    credentials:
      apikey: your-api-key
  - name: Shodan
    credentials:
      apikey: your-api-key
```

## Available Tools

### `amass_enum`

Perform DNS enumeration and subdomain discovery.

**Parameters:**
- `domain` (required) - Target domain to enumerate
- `passive` - OSINT-only mode (no DNS queries, stealthier)
- `active` - Enable DNS resolution validation
- `brute` - Enable brute-force subdomain discovery
- `wordlist` - Custom wordlist path for brute-force
- `recursive` - Recursively brute-force discovered subdomains
- `json` - Output results in JSON format
- `src` - Show data source for each result
- `ip` - Include IP addresses in output
- `asn` - Filter by ASN numbers
- `cidr` - Filter by CIDR ranges
- `timeout` - Custom timeout in milliseconds

### `amass_intel`

Gather intelligence about an organization's attack surface.

**Parameters:**
- `domain` - Target domain for investigation
- `org` - Organization name for reverse WHOIS lookup
- `asn` - ASN numbers to investigate
- `ip` - IP address to investigate
- `cidr` - CIDR ranges to investigate
- `whois` - Enable reverse WHOIS lookups
- `active` - Enable active intelligence gathering

### `amass_track`

Track attack surface changes over time.

**Parameters:**
- `domain` (required) - Target domain to track
- `last` - Compare against last N enumerations
- `since` - Compare since date (format: 2006-01-02)
- `history` - Show full enumeration history

### `amass_db`

Query and manage the Amass graph database.

**Parameters:**
- `domain` - Filter by domain
- `names` - Show discovered subdomain names
- `ip` - Show discovered IP addresses
- `asn` - Show ASN information
- `cidr` - Show CIDR ranges
- `summary` - Show summary statistics
- `list` - List available enumerations

### `amass_viz`

Generate visualizations from enumeration data.

**Parameters:**
- `domain` - Filter by domain
- `d3` - Output path for D3.js HTML visualization
- `visjs` - Output path for Vis.js HTML visualization
- `maltego` - Output path for Maltego CSV
- `gexf` - Output path for GEXF graph format

### `amass_brute`

Dedicated brute-force subdomain discovery.

**Parameters:**
- `domain` (required) - Target domain
- `wordlist` (required) - Path to wordlist file
- `recursive` - Recursively brute-force discoveries
- `min_for_recursive` - Minimum subdomains before recursion

### `amass_config`

Check Amass configuration and available data sources.

**Parameters:**
- `check` - Validate configuration file
- `list_sources` - List all available data sources

### `amass_version`

Get the installed Amass version.

## Usage Examples

### Passive Enumeration (Stealthy)

```json
{
  "tool": "amass_enum",
  "arguments": {
    "domain": "example.com",
    "passive": true,
    "src": true
  }
}
```

### Active Enumeration with IP Resolution

```json
{
  "tool": "amass_enum",
  "arguments": {
    "domain": "example.com",
    "active": true,
    "ip": true,
    "json": true
  }
}
```

### Comprehensive Brute-Force

```json
{
  "tool": "amass_enum",
  "arguments": {
    "domain": "example.com",
    "brute": true,
    "recursive": true,
    "wordlist": "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
  }
}
```

### Organization Intelligence

```json
{
  "tool": "amass_intel",
  "arguments": {
    "org": "Example Corporation",
    "whois": true
  }
}
```

### Track Infrastructure Changes

```json
{
  "tool": "amass_track",
  "arguments": {
    "domain": "example.com",
    "last": 5
  }
}
```

### Generate D3 Visualization

```json
{
  "tool": "amass_viz",
  "arguments": {
    "domain": "example.com",
    "d3": "/tmp/example-graph.html"
  }
}
```

## Security Considerations

- This tool is designed for **authorized security testing only**
- Always obtain proper authorization before scanning any domain
- Passive mode (`-passive`) minimizes detection risk
- Active and brute-force modes generate significant DNS traffic
- Configure rate limiting via Amass config to avoid detection

## Troubleshooting

### SSH Connection Issues

```bash
# Test SSH connectivity
ssh kali echo "Connection successful"

# Test Amass availability
ssh kali amass -version
```

### Timeout Errors

For large scopes, increase the timeout:

```json
{
  "arguments": {
    "domain": "example.com",
    "timeout": 1800000
  }
}
```

### No Results

- Check if DNS resolvers are accessible from Kali
- Verify API keys are configured correctly
- Try passive mode first to test OSINT sources

## References

- [OWASP Amass Project](https://owasp.org/www-project-amass/)
- [Amass Documentation](https://github.com/owasp-amass/amass/blob/master/doc/user_guide.md)
- [Amass Data Sources](https://github.com/owasp-amass/amass/blob/master/doc/datasources.md)
- [Model Context Protocol](https://modelcontextprotocol.io)

## License

MIT License - see [LICENSE](LICENSE) for details.

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before scanning any systems or networks. Unauthorized scanning may violate laws and regulations.
