# Ligolo-ng MCP Server

A Model Context Protocol (MCP) server for managing [Ligolo-ng](https://github.com/nicocha30/ligolo-ng) - a lightweight and fast tunneling tool for establishing reverse TCP/TLS tunnels during penetration testing and red team engagements.

## Overview

This MCP server enables AI assistants to control Ligolo-ng operations on a remote Kali Linux machine via SSH. It provides tools for managing the proxy server, agents, tunnels, routes, and listeners - all the core functionality needed for network pivoting during security assessments.

## Features

- **Proxy Management**: Start, stop, and monitor the Ligolo-ng proxy server
- **Agent Control**: List connected agents and manage sessions
- **Network Interface**: Create and manage TUN interfaces for tunneling
- **Tunnel Operations**: Start/stop tunnels through agent sessions
- **Route Management**: Add and remove routes to target networks
- **Listener Configuration**: Set up port forwarding through agents
- **Agent Command Generation**: Generate agent connection commands for targets

## Prerequisites

- Node.js 18+
- SSH access to a Kali Linux machine with Ligolo-ng installed
- SSH key-based authentication configured (passwordless SSH)

## Installation

```bash
# Clone the repository
git clone https://github.com/schwarztim/sec-ligolo-ng-mcp.git
cd sec-ligolo-ng-mcp

# Install dependencies
npm install

# Build the project
npm run build
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `KALI_HOST` | `kali` | SSH hostname or alias for your Kali machine |
| `LIGOLO_PROXY_PORT` | `11601` | Port for agent connections |
| `LIGOLO_API_PORT` | `8080` | Port for the Ligolo-ng web API |
| `LIGOLO_INTERFACE` | `ligolo` | Default TUN interface name |

### SSH Configuration

Ensure your SSH config (`~/.ssh/config`) has an entry for your Kali machine:

```
Host kali
    HostName 192.168.1.100
    User root
    IdentityFile ~/.ssh/id_rsa
```

### Claude Desktop Integration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ligolo-ng": {
      "command": "node",
      "args": ["/path/to/sec-ligolo-ng-mcp/dist/index.js"],
      "env": {
        "KALI_HOST": "kali",
        "LIGOLO_PROXY_PORT": "11601"
      }
    }
  }
}
```

## Available Tools

### Proxy Management

| Tool | Description |
|------|-------------|
| `ligolo_proxy_start` | Start the Ligolo-ng proxy server with optional self-signed certs and API |
| `ligolo_proxy_stop` | Stop the running proxy server |
| `ligolo_proxy_status` | Check proxy status and view recent logs |

### Session Management

| Tool | Description |
|------|-------------|
| `ligolo_agents_list` | List all connected agents |
| `ligolo_session_select` | Select an agent session to work with |
| `ligolo_agent_info` | Get network information from the selected agent |

### Network Configuration

| Tool | Description |
|------|-------------|
| `ligolo_interface_create` | Create a TUN interface for tunneling |
| `ligolo_interface_list` | List all TUN interfaces |
| `ligolo_tunnel_start` | Start a tunnel through the selected session |
| `ligolo_tunnel_stop` | Stop the active tunnel |

### Routing

| Tool | Description |
|------|-------------|
| `ligolo_route_add` | Add a route to access target networks |
| `ligolo_route_delete` | Remove a route |
| `ligolo_route_list` | List all Ligolo routes |

### Port Forwarding

| Tool | Description |
|------|-------------|
| `ligolo_listener_add` | Add a listener for reverse connections |
| `ligolo_listener_list` | List active listeners |
| `ligolo_listener_delete` | Remove a listener |

### Utilities

| Tool | Description |
|------|-------------|
| `ligolo_agent_command` | Generate agent command for target deployment |
| `ligolo_certificate_fingerprint` | Get certificate fingerprint for secure connections |
| `ligolo_send_command` | Send raw commands to the proxy console |

## Usage Example

### Basic Pivoting Workflow

1. **Start the proxy on Kali**:
   ```
   Use ligolo_proxy_start with selfcert enabled
   ```

2. **Generate agent command**:
   ```
   Use ligolo_agent_command with your Kali IP
   ```

3. **Create TUN interface**:
   ```
   Use ligolo_interface_create
   ```

4. **After agent connects, add routes**:
   ```
   Use ligolo_route_add with network 10.10.10.0/24
   ```

5. **Start the tunnel**:
   ```
   Use ligolo_tunnel_start
   ```

Now you can access the 10.10.10.0/24 network through your Kali machine.

### Setting Up Reverse Shell Callback

Use listeners to receive reverse shells through the pivot:

```
Use ligolo_listener_add with:
  localAddress: 0.0.0.0:4444
  remoteAddress: 127.0.0.1:4444
```

This forwards connections from port 4444 on the agent back to your Kali's port 4444.

## Security Considerations

- This tool is designed for authorized security testing only
- Always use certificate verification in production environments
- The proxy runs with elevated privileges to manage network interfaces
- SSH keys should be properly secured and not shared

## Development

```bash
# Watch mode for development
npm run dev

# Build
npm run build

# Start the server
npm start
```

## License

MIT License - See [LICENSE](LICENSE) for details.

## Acknowledgments

- [Ligolo-ng](https://github.com/nicocha30/ligolo-ng) by Nicolas Chatelain
- [Model Context Protocol](https://modelcontextprotocol.io) by Anthropic

## Disclaimer

This tool is intended for authorized security testing and educational purposes only. Users are responsible for ensuring they have proper authorization before using this tool against any systems. The authors are not responsible for any misuse or damage caused by this tool.
