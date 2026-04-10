# Nuclei MCP Server

An MCP (Model Context Protocol) server that provides AI assistants with access to [Nuclei](https://github.com/projectdiscovery/nuclei), the fast and customizable vulnerability scanner by ProjectDiscovery.

## Overview

This MCP server enables AI assistants to perform vulnerability scanning through Nuclei via SSH connection to a Kali Linux host. It provides a comprehensive set of tools for security assessments, including template management, workflow execution, and specialized scans for Known Exploited Vulnerabilities (KEV).

## Features

- **Vulnerability Scanning**: Run Nuclei scans against single or multiple targets
- **Template Management**: List, search, and filter templates by tags, severity, author, and type
- **Workflow Execution**: Run predefined workflows for comprehensive technology-specific scanning
- **KEV Scanning**: Dedicated tool for scanning CISA Known Exploited Vulnerabilities
- **Configuration Presets**: Built-in recommendations for stealth, fast, comprehensive, API, and web scanning
- **Rate Limiting**: Configurable rate limits to control scan intensity

## Requirements

- Node.js 18+
- SSH access to a Kali Linux host with Nuclei installed
- SSH key-based authentication configured

## Installation

```bash
# Clone the repository
git clone https://github.com/schwarztim/sec-nuclei-mcp.git
cd sec-nuclei-mcp

# Install dependencies
npm install

# Build
npm run build
```

## Configuration

Set the following environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `KALI_HOST` | SSH hostname for Kali Linux | `kali` |
| `SSH_TIMEOUT` | Command timeout in seconds | `300` |
| `DEFAULT_RATE_LIMIT` | Default requests per second | `150` |

### SSH Setup

Ensure SSH key-based authentication is configured to your Kali host:

```bash
# Add your Kali host to ~/.ssh/config
Host kali
    HostName your-kali-ip-or-hostname
    User root
    IdentityFile ~/.ssh/id_rsa
```

## MCP Configuration

Add to your Claude Desktop or MCP client configuration:

```json
{
  "mcpServers": {
    "nuclei": {
      "command": "node",
      "args": ["/path/to/sec-nuclei-mcp/dist/index.js"],
      "env": {
        "KALI_HOST": "kali"
      }
    }
  }
}
```

## Available Tools

### `nuclei_scan`

Run vulnerability scans against targets with extensive filtering options.

```javascript
// Basic scan
nuclei_scan({ target: "https://example.com" })

// High severity only
nuclei_scan({
  target: "https://example.com",
  severity: ["high", "critical"]
})

// Specific vulnerability types
nuclei_scan({
  target: "https://example.com",
  tags: ["cve", "rce", "sqli"]
})

// Multiple targets
nuclei_scan({
  targets: ["https://a.com", "https://b.com"]
})
```

### `nuclei_templates`

List and search available templates.

```javascript
// List critical severity templates
nuclei_templates({ severity: ["critical"] })

// Search by tags
nuclei_templates({ tags: ["wordpress", "cve"] })

// Filter by author
nuclei_templates({ author: "pdteam" })
```

### `nuclei_kev_scan`

Scan for Known Exploited Vulnerabilities (CISA KEV catalog).

```javascript
nuclei_kev_scan({ target: "https://example.com" })
```

### `nuclei_workflows`

List available scanning workflows.

```javascript
// List all workflows
nuclei_workflows({})

// Search for specific workflows
nuclei_workflows({ search: "wordpress" })
```

### `nuclei_run_workflow`

Execute a workflow against a target.

```javascript
nuclei_run_workflow({
  target: "https://example.com",
  workflow: "wordpress-workflow"
})
```

### `nuclei_config`

Get configuration recommendations for different scanning scenarios.

```javascript
// Available scenarios: stealth, fast, comprehensive, api, web
nuclei_config({ scenario: "stealth" })
```

### `nuclei_update_templates`

Update templates to the latest version.

```javascript
nuclei_update_templates({})
```

### `nuclei_version`

Get Nuclei version and configuration information.

### `nuclei_tags`

List popular template tags with descriptions.

### `nuclei_severity_stats`

Get template counts by severity level.

## Scan Options

| Option | Type | Description |
|--------|------|-------------|
| `target` | string | Single target URL |
| `targets` | string[] | Multiple target URLs |
| `templates` | string[] | Specific template paths/IDs |
| `tags` | string[] | Filter by tags (cve, rce, xss, etc.) |
| `excludeTags` | string[] | Exclude templates with tags |
| `severity` | string[] | Filter by severity (info, low, medium, high, critical) |
| `author` | string | Filter by template author |
| `rateLimit` | number | Max requests per second |
| `concurrency` | number | Concurrent template executions |
| `timeout` | number | Request timeout in seconds |
| `proxy` | string | HTTP/SOCKS proxy URL |
| `headless` | boolean | Enable headless browser |
| `customHeaders` | object | Custom HTTP headers |
| `followRedirects` | boolean | Follow HTTP redirects |
| `maxRedirects` | number | Maximum redirects to follow |
| `debug` | boolean | Enable debug output |

## Popular Tags Reference

| Tag | Description |
|-----|-------------|
| `cve` | CVE vulnerabilities |
| `kev` | Known Exploited Vulnerabilities |
| `rce` | Remote Code Execution |
| `xss` | Cross-Site Scripting |
| `sqli` | SQL Injection |
| `lfi` | Local File Inclusion |
| `ssrf` | Server-Side Request Forgery |
| `default-login` | Default credentials |
| `exposure` | Information exposure |
| `misconfig` | Misconfigurations |
| `panel` | Admin panels |
| `tech` | Technology detection |

## Security Considerations

- This tool is intended for authorized security testing only
- Always obtain proper authorization before scanning targets
- Use rate limiting to avoid overwhelming target systems
- Consider using stealth mode for sensitive assessments

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- [ProjectDiscovery](https://projectdiscovery.io/) for creating Nuclei
- [Anthropic](https://anthropic.com/) for the Model Context Protocol
