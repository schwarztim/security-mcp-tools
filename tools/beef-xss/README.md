# BeEF XSS MCP Server

A Model Context Protocol (MCP) server that provides programmatic access to [BeEF (Browser Exploitation Framework)](https://beefproject.com/) REST API. This server enables AI assistants and other MCP clients to interact with BeEF for authorized security testing and penetration testing workflows.

## Overview

BeEF is a penetration testing tool that focuses on web browser exploitation. This MCP server exposes BeEF's capabilities through a standardized interface, allowing security professionals to:

- Manage hooked browsers and sessions
- Execute command modules against targets
- Configure DNS rules for phishing simulations
- Set up autorun rules for automated testing
- Monitor network discovery results

## Prerequisites

- [Node.js](https://nodejs.org/) v18 or higher
- [BeEF](https://github.com/beefproject/beef) installed and running
- Access to BeEF REST API (typically on port 3000)

## Installation

```bash
# Clone the repository
git clone https://github.com/schwarztim/sec-beef-xss-mcp.git
cd sec-beef-xss-mcp

# Install dependencies
npm install

# Build the project
npm run build
```

## Configuration

The server requires the following environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `BEEF_URL` | BeEF server URL | `http://127.0.0.1:3000` |
| `BEEF_USERNAME` | BeEF admin username | `beef` |
| `BEEF_PASSWORD` | BeEF admin password | `beef` |

### Claude Desktop Configuration

Add to your Claude Desktop config (`~/.config/claude/claude_desktop_config.json` on Linux or `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "beef-xss": {
      "command": "node",
      "args": ["/path/to/sec-beef-xss-mcp/dist/index.js"],
      "env": {
        "BEEF_URL": "http://127.0.0.1:3000",
        "BEEF_USERNAME": "beef",
        "BEEF_PASSWORD": "your-password"
      }
    }
  }
}
```

## Available Tools

### Connection & Status

| Tool | Description |
|------|-------------|
| `beef_status` | Check BeEF server connection and authentication status |

### Hook Management

| Tool | Description |
|------|-------------|
| `beef_hooks` | List all hooked browsers (online/offline/all) |
| `beef_hook_info` | Get detailed info about a specific hooked browser |
| `beef_logs` | Retrieve logs (global or per-session) |

### Module Execution

| Tool | Description |
|------|-------------|
| `beef_modules` | List available command modules (optionally filter by category) |
| `beef_module_info` | Get detailed module information and parameters |
| `beef_execute` | Execute a module against a hooked browser |
| `beef_command_result` | Get results of a previously executed command |
| `beef_execute_multi_browser` | Execute module against multiple browsers |
| `beef_execute_multi_module` | Execute multiple modules against one browser |

### DNS Management

| Tool | Description |
|------|-------------|
| `beef_dns_rules` | List all DNS rules |
| `beef_dns_rule_info` | Get details of a specific DNS rule |
| `beef_dns_add_rule` | Add a new DNS rule (A, AAAA, CNAME, MX, NS, SOA, TXT) |
| `beef_dns_delete_rule` | Delete a DNS rule |

### Automation

| Tool | Description |
|------|-------------|
| `beef_autorun_rules` | List autorun rules |
| `beef_autorun_add` | Add autorun rule for automatic module execution |
| `beef_network_hosts` | Get discovered network hosts |

## Usage Examples

### Check Server Status

```
Use beef_status to verify connection to BeEF server
```

### List Online Hooked Browsers

```
Use beef_hooks with status="online" to see active sessions
```

### Execute a Module

```
1. Use beef_modules to find the module ID
2. Use beef_module_info to see required parameters
3. Use beef_execute with session ID, module ID, and options
4. Use beef_command_result to retrieve the output
```

## Security Notice

**This tool is intended for authorized security testing only.**

- Only use against systems you own or have explicit written permission to test
- BeEF and this MCP server are penetration testing tools
- Unauthorized use may violate computer crime laws
- Always follow responsible disclosure practices

## Development

```bash
# Run in development mode
npm run dev

# Build for production
npm run build

# Start the server
npm start
```

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Related Projects

- [BeEF Project](https://beefproject.com/) - Browser Exploitation Framework
- [Model Context Protocol](https://modelcontextprotocol.io/) - MCP Specification
- [MCP SDK](https://github.com/modelcontextprotocol/sdk) - Official MCP SDK

## Contributing

Contributions are welcome! Please ensure all changes maintain compatibility with the BeEF REST API and follow the MCP specification.

1. Fork the repository
2. Create a feature branch
3. Submit a pull request

## Disclaimer

This software is provided for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this tool. Always obtain proper authorization before conducting security assessments.
