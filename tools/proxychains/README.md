# Proxychains MCP Server

[![MCP](https://img.shields.io/badge/MCP-Model%20Context%20Protocol-blue)](https://modelcontextprotocol.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0-blue)](https://www.typescriptlang.org/)

MCP server for [proxychains-ng](https://github.com/rofl0r/proxychains-ng) (proxychains4) - route commands through proxy chains via SSH to a remote Linux host (e.g., Kali Linux).

## Overview

This MCP server provides tools to manage and use proxychains configurations dynamically. It executes commands through SSH on a remote host where proxychains4 is installed, allowing AI assistants to route network traffic through proxy chains for privacy, security testing, or accessing geo-restricted resources.

## Features

| Tool | Description |
|------|-------------|
| `proxychains_run` | Execute commands through the configured proxy chain |
| `proxychains_config` | Get, set, or reset the full configuration |
| `proxychains_add` | Add a proxy to the chain (SOCKS4, SOCKS5, HTTP, RAW) |
| `proxychains_remove` | Remove a proxy by index or host:port |
| `proxychains_mode` | Set chain mode (strict, dynamic, random, round_robin) |
| `proxychains_dns` | Configure DNS handling mode |
| `proxychains_test` | Test proxy chain connectivity and latency |
| `proxychains_list` | List all configured proxies |
| `proxychains_import` | Import proxies from file or URL |
| `proxychains_export` | Export configuration in various formats |

## Installation

### Prerequisites

- Node.js 18+
- SSH access to a Linux host with proxychains4 installed
- The SSH host should be configured in `~/.ssh/config` or accessible by hostname

### Setup

```bash
# Clone the repository
git clone https://github.com/schwarztim/sec-proxychains-mcp.git
cd sec-proxychains-mcp

# Install dependencies
npm install

# Build
npm run build
```

### MCP Configuration

Add to your Claude Desktop or MCP client configuration:

```json
{
  "mcpServers": {
    "proxychains": {
      "command": "node",
      "args": ["/path/to/sec-proxychains-mcp/dist/index.js"],
      "env": {
        "PROXYCHAINS_KALI_HOST": "kali",
        "PROXYCHAINS_SSH_TIMEOUT": "30000"
      }
    }
  }
}
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PROXYCHAINS_KALI_HOST` | `kali` | SSH hostname for the remote host |
| `PROXYCHAINS_SSH_TIMEOUT` | `30000` | SSH command timeout in milliseconds |
| `PROXYCHAINS_CONFIG_DIR` | `~/.proxychains-mcp` | Local config storage directory |

### Chain Modes

| Mode | Description |
|------|-------------|
| `strict_chain` | All proxies must work, used in order specified |
| `dynamic_chain` | Skip dead proxies, at least one must work |
| `random_chain` | Random proxy selection for each connection |
| `round_robin_chain` | Rotate through proxies sequentially |

### Proxy Types

| Type | Description |
|------|-------------|
| `socks5` | SOCKS5 proxy (recommended) |
| `socks4` | SOCKS4 proxy |
| `http` | HTTP CONNECT proxy |
| `raw` | Raw TCP forwarding |

### DNS Modes

| Mode | Description |
|------|-------------|
| `proxy_dns` | Route DNS through proxy (recommended, prevents leaks) |
| `proxy_dns_old` | Legacy mode using proxyresolv |
| `proxy_dns_daemon` | Daemon-based DNS resolution |
| `none` | No DNS proxying (may leak DNS queries) |

## Usage Examples

### Basic Setup

```javascript
// Add a SOCKS5 proxy (e.g., Tor)
proxychains_add({ type: "socks5", host: "127.0.0.1", port: 9050 })

// Add an authenticated HTTP proxy
proxychains_add({
  type: "http",
  host: "proxy.example.com",
  port: 8080,
  user: "admin",
  pass: "secret"
})

// Set dynamic chain mode (skip dead proxies)
proxychains_mode({ mode: "dynamic_chain" })
```

### Testing the Chain

```javascript
// Test connectivity
proxychains_test({ verbose: true })

// Test against specific target
proxychains_test({ target: "https://api.ipify.org" })
```

### Running Commands

```javascript
// Check your proxied IP
proxychains_run({ command: "curl https://httpbin.org/ip" })

// Run nmap through proxies
proxychains_run({ command: "nmap -sT -Pn target.com" })

// Custom timeout for long operations
proxychains_run({ command: "wget https://example.com/large-file", timeout: 120000 })
```

### Importing Proxies

```javascript
// Import from URL
proxychains_import({
  source: "https://raw.githubusercontent.com/example/proxies/main/list.txt",
  defaultType: "socks5"
})

// Import from file on remote host
proxychains_import({ source: "/tmp/proxies.txt" })
```

### Exporting Configuration

```javascript
// Export as proxychains.conf format
proxychains_export({ format: "proxychains" })

// Export as JSON
proxychains_export({ format: "json" })

// Export as simple ip:port list
proxychains_export({ format: "ip:port" })
```

## Remote Host Setup

The remote host (e.g., Kali Linux) needs proxychains4 installed:

```bash
# Debian/Ubuntu/Kali
sudo apt update
sudo apt install proxychains4 curl

# Verify installation
proxychains4 --version
```

Ensure SSH access works without password prompts:

```bash
# Test SSH connection
ssh kali "echo 'Connection successful'"
```

## Security Considerations

- **SSH Keys**: Use SSH key authentication instead of passwords
- **DNS Leaks**: Use `proxy_dns` mode to prevent DNS leakage
- **Proxy Trust**: Only use trusted proxies; traffic is visible to proxy operators
- **Authentication**: Proxy credentials are stored locally in `~/.proxychains-mcp/config.json`

## Architecture

```
┌─────────────────┐     SSH      ┌─────────────────┐     Proxies     ┌─────────────┐
│   MCP Client    │─────────────▶│   Remote Host   │────────────────▶│   Target    │
│  (Claude, etc)  │              │   (Kali Linux)  │                 │             │
└─────────────────┘              │   proxychains4  │                 └─────────────┘
                                 └─────────────────┘
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [proxychains-ng](https://github.com/rofl0r/proxychains-ng) - The proxychains implementation
- [Model Context Protocol](https://modelcontextprotocol.io) - The MCP specification
