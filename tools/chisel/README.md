# sec-chisel-mcp

[![MCP](https://img.shields.io/badge/MCP-Model%20Context%20Protocol-blue)](https://modelcontextprotocol.io)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.3-blue?logo=typescript)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/Node.js-18+-green?logo=node.js)](https://nodejs.org/)

An MCP (Model Context Protocol) server for managing [Chisel](https://github.com/jpillora/chisel) TCP/UDP tunnels. Enables AI assistants to create and manage secure tunneling connections through a remote host.

## Features

- **Server Management** - Start chisel servers with SOCKS5 and reverse tunnel support
- **Client Connections** - Connect to chisel servers and establish tunnels
- **Reverse Tunneling** - Create reverse port forwards for accessing internal services
- **SOCKS5 Proxy** - Set up SOCKS5 proxies for traffic routing
- **Port Forwarding** - Create local-to-remote port forwards
- **Process Management** - Track, monitor, and stop active tunnels

## Installation

```bash
# Clone the repository
git clone https://github.com/schwarztim/sec-chisel-mcp.git
cd sec-chisel-mcp

# Install dependencies
npm install

# Build
npm run build
```

## Configuration

### Claude Desktop

Add to your Claude Desktop configuration (`~/.claude.json` or similar):

```json
{
  "mcpServers": {
    "chisel": {
      "command": "node",
      "args": ["/path/to/sec-chisel-mcp/dist/index.js"],
      "env": {
        "CHISEL_KALI_HOST": "kali",
        "CHISEL_DEFAULT_PORT": "8080"
      }
    }
  }
}
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `CHISEL_KALI_HOST` | `kali` | SSH hostname for the remote machine |
| `CHISEL_DEFAULT_PORT` | `8080` | Default chisel server port |

## Prerequisites

1. **Chisel installed on the remote host**
   ```bash
   # Install via script
   curl https://i.jpillora.com/chisel! | bash

   # Or via package manager (Kali/Debian)
   sudo apt install chisel
   ```

2. **SSH access configured**
   - Key-based authentication recommended
   - Host configured in `~/.ssh/config`

## Tools

| Tool | Description |
|------|-------------|
| `chisel_server` | Start a chisel server with SOCKS5 and reverse tunnel support |
| `chisel_client` | Connect to a chisel server and create tunnels |
| `chisel_reverse` | Start a server configured for reverse tunneling |
| `chisel_socks` | Start a SOCKS5 proxy server |
| `chisel_forward` | Create a local port forward tunnel |
| `chisel_status` | Check status of active tunnels |
| `chisel_stop` | Stop one or all tunnels |
| `chisel_list_processes` | List all chisel processes on the remote host |
| `chisel_version` | Check chisel installation and version |

## Usage Examples

### Start a Chisel Server

```json
{
  "tool": "chisel_server",
  "arguments": {
    "port": "8080",
    "reverse": true,
    "socks5": true,
    "auth": "user:password"
  }
}
```

### Create a Reverse Tunnel

Expose an internal service externally:

```json
{
  "tool": "chisel_client",
  "arguments": {
    "server": "http://server:8080",
    "remotes": ["R:2222:localhost:22"]
  }
}
```

### Set Up SOCKS5 Proxy

```json
{
  "tool": "chisel_socks",
  "arguments": {
    "port": "8080"
  }
}
```

Connect a client:
```bash
chisel client <server>:8080 socks
```

Use with proxychains:
```bash
# Add to /etc/proxychains.conf
socks5 127.0.0.1 1080
```

### Local Port Forward

Forward local traffic to a remote destination:

```json
{
  "tool": "chisel_forward",
  "arguments": {
    "server": "http://pivot:8080",
    "localPort": "3389",
    "remoteHost": "10.10.10.100",
    "remotePort": "3389"
  }
}
```

### Check Tunnel Status

```json
{
  "tool": "chisel_status",
  "arguments": {}
}
```

### Stop All Tunnels

```json
{
  "tool": "chisel_stop",
  "arguments": {
    "force": false
  }
}
```

## Chisel Remote Syntax

Chisel uses the following format for remote specifications:

```
<local-host>:<local-port>:<remote-host>:<remote-port>/<protocol>
```

Examples:
- `3000` - Forward local 3000 to server's 3000
- `3000:google.com:80` - Tunnel to external host
- `R:2222:localhost:22` - Reverse port forward
- `socks` - SOCKS5 proxy connection
- `R:socks` - Reverse SOCKS proxy

## Security Considerations

- **Authentication**: Use `--auth user:password` for production deployments
- **Fingerprint Verification**: Use `--fingerprint` on clients to verify server identity
- **TLS Encryption**: Consider using `--tls-key` and `--tls-cert` for encrypted transport
- **Traffic Profile**: Chisel traffic appears as HTTP/WebSocket traffic, useful for firewall evasion

## Development

```bash
# Run in development mode
npm run dev

# Build for production
npm run build

# Start the server
npm start
```

## References

- [Chisel GitHub Repository](https://github.com/jpillora/chisel)
- [Model Context Protocol](https://modelcontextprotocol.io)
- [HackTricks Tunneling Guide](https://book.hacktricks.xyz/generic-methodologies-and-resources/tunneling-and-port-forwarding)

## License

MIT License - see [LICENSE](LICENSE) for details.
