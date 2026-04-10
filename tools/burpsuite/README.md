# Burp Suite MCP Server

[![npm version](https://img.shields.io/npm/v/burpsuite-mcp.svg)](https://www.npmjs.com/package/burpsuite-mcp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![MCP](https://img.shields.io/badge/MCP-Compatible-blue.svg)](https://modelcontextprotocol.io)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.3-blue.svg)](https://www.typescriptlang.org/)

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server for integrating with Burp Suite Professional's REST API. This server enables AI assistants to perform web application security testing through Burp Suite.

## Features

- **Active Scanning** - Start, pause, resume, and monitor vulnerability scans
- **Issue Detection** - List and analyze discovered security vulnerabilities
- **Sitemap Exploration** - View discovered URLs and application structure
- **Proxy History** - Access all intercepted HTTP requests/responses
- **Spider/Crawler** - Automated content discovery
- **Repeater/Intruder** - Send requests to Burp's manual testing tools
- **Scope Management** - Control target scope programmatically
- **State Management** - Export/reset project state

## Prerequisites

- **Burp Suite Professional** with REST API enabled
- **Node.js** 18 or higher

### Enabling Burp Suite REST API

1. Open Burp Suite Professional
2. Go to **Settings** > **Suite** > **REST API**
3. Check **"Service running"**
4. Configure the port (default: `1337`)
5. Optionally create an API key for authentication

## Installation

### From Source

```bash
git clone https://github.com/schwarztim/sec-burpsuite-mcp.git
cd sec-burpsuite-mcp
npm install
npm run build
```

### NPM (coming soon)

```bash
npm install -g burpsuite-mcp
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `BURP_URL` | Burp Suite REST API URL | `http://127.0.0.1:1337` |
| `BURP_API_KEY` | API key (if configured in Burp) | - |
| `BURP_TIMEOUT` | Request timeout in milliseconds | `30000` |

### Claude Desktop Configuration

Add to your `~/.claude/user-mcps.json`:

```json
{
  "mcpServers": {
    "burpsuite": {
      "command": "node",
      "args": ["/path/to/sec-burpsuite-mcp/dist/index.js"],
      "env": {
        "BURP_URL": "http://127.0.0.1:1337",
        "BURP_API_KEY": "your-api-key-if-configured"
      }
    }
  }
}
```

## Available Tools

### Health and Status

| Tool | Description |
|------|-------------|
| `burp_health_check` | Check if Burp REST API is accessible |
| `burp_get_version` | Get Burp Suite version information |

### Scanning

| Tool | Description |
|------|-------------|
| `burp_scan_start` | Start an active vulnerability scan |
| `burp_scan_status` | Get scan progress and status |
| `burp_scan_pause` | Pause the current scan |
| `burp_scan_resume` | Resume a paused scan |

### Vulnerability Detection

| Tool | Description |
|------|-------------|
| `burp_issues_list` | List all discovered vulnerabilities |
| `burp_issue_definitions` | Get Burp's issue type knowledge base |

### Target and Scope

| Tool | Description |
|------|-------------|
| `burp_sitemap_get` | Get sitemap of discovered content |
| `burp_scope_add` | Add URL to target scope |
| `burp_scope_remove` | Remove URL from target scope |
| `burp_scope_check` | Check if URL is in scope |

### Proxy History

| Tool | Description |
|------|-------------|
| `burp_proxy_history` | Get all proxy history items |
| `burp_proxy_history_item` | Get specific history item details |

### Spider/Crawler

| Tool | Description |
|------|-------------|
| `burp_spider_start` | Start content discovery crawler |
| `burp_spider_status` | Get crawler status |

### Manual Testing Tools

| Tool | Description |
|------|-------------|
| `burp_send_to_repeater` | Send request to Repeater tool |
| `burp_send_to_intruder` | Send request to Intruder tool |
| `burp_send_http_request` | Send HTTP request through Burp |

### State Management

| Tool | Description |
|------|-------------|
| `burp_export_state` | Export project state to file |
| `burp_reset_state` | Clear all Burp state |
| `burp_shutdown` | Shutdown Burp Suite |

## Usage Examples

### Basic Security Scan

```
User: Scan https://testapp.example.com for vulnerabilities

AI Assistant will:
1. Call burp_scan_start with url: "https://testapp.example.com"
2. Monitor progress with burp_scan_status
3. Retrieve findings with burp_issues_list
```

### Explore Application Structure

```
User: Show me what endpoints have been discovered on example.com

AI Assistant will:
1. Call burp_sitemap_get with urlPrefix: "https://example.com"
2. Present the discovered URLs and resources
```

### Review Proxy Traffic

```
User: Show me the recent HTTP requests through Burp

AI Assistant will:
1. Call burp_proxy_history with limit: 20
2. Display request/response summaries
```

## API Compatibility

This MCP server supports multiple Burp Suite API implementations:

- **Burp Suite Professional** built-in REST API (default port 1337)
- **VMware burp-rest-api** extension (default port 8090)

The client automatically adapts to the available API format.

## Security Considerations

- **Authorization Required**: Only use against applications you have permission to test
- **API Key**: Configure an API key in Burp Suite for additional security
- **Network Isolation**: Consider running Burp Suite in an isolated environment
- **Sensitive Data**: Proxy history may contain credentials and sensitive information

## Troubleshooting

### Cannot connect to Burp Suite

1. Verify Burp Suite Professional is running
2. Check REST API is enabled in Settings > Suite > REST API
3. Confirm the port matches your `BURP_URL` configuration
4. Check firewall rules if connecting remotely

### API Key Authentication Failing

1. Generate a new API key in Burp Suite REST API settings
2. Update `BURP_API_KEY` environment variable
3. Restart the MCP server

### Scan Not Starting

1. Verify the target URL is accessible
2. Check if URL is in target scope (use `burp_scope_add` first)
3. Ensure no other scan is currently running

## Related Resources

- [Burp Suite REST API Documentation](https://portswigger.net/burp/documentation/desktop/settings/suite/rest-api)
- [Official Burp MCP Server (Java Extension)](https://github.com/PortSwigger/mcp-server)
- [VMware burp-rest-api Extension](https://github.com/vmware/burp-rest-api)
- [Model Context Protocol](https://modelcontextprotocol.io)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Disclaimer

This tool is intended for authorized security testing only. Always obtain proper authorization before testing any systems. The authors are not responsible for misuse of this software.
