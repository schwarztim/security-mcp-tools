# Aircrack-ng MCP Server

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![MCP](https://img.shields.io/badge/MCP-Compatible-blue.svg)](https://modelcontextprotocol.io)
[![Kali Linux](https://img.shields.io/badge/Kali-Linux-557C94.svg)](https://www.kali.org/)

A Model Context Protocol (MCP) server that provides WiFi security auditing capabilities using the [aircrack-ng](https://www.aircrack-ng.org/) suite. Commands are executed on a remote Kali Linux system via SSH, enabling AI assistants to perform authorized wireless security assessments.

## Features

- **Monitor Mode Management** - Enable/disable monitor mode on wireless interfaces
- **Network Discovery** - Scan and enumerate wireless networks with detailed information
- **Packet Capture** - Capture packets from targeted access points (background operation)
- **Handshake Capture** - Deauthentication attacks to capture WPA/WPA2 handshakes
- **Password Cracking** - Attempt to crack captured handshakes using wordlists
- **Remote Execution** - All operations run on a remote Kali system via SSH

## Prerequisites

- **Kali Linux System** - With aircrack-ng suite installed
- **SSH Access** - Passwordless SSH recommended (key-based authentication)
- **Wireless Adapter** - Compatible adapter that supports monitor mode and packet injection
- **Node.js** - Version 18 or higher

## Installation

```bash
# Clone the repository
git clone https://github.com/schwarztim/sec-aircrack-ng-mcp.git
cd sec-aircrack-ng-mcp

# Install dependencies
npm install

# Build the TypeScript code
npm run build
```

## Configuration

Configure the server using environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `KALI_HOST` | Hostname or IP address of Kali system | `kali` |
| `SSH_USER` | SSH username | `kali` |
| `SSH_KEY` | Path to SSH private key file | (none - uses default) |
| `CAPTURE_DIR` | Directory for capture files on Kali | `/tmp/aircrack-captures` |

### Claude Desktop Configuration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "aircrack-ng": {
      "command": "node",
      "args": ["/path/to/sec-aircrack-ng-mcp/dist/index.js"],
      "env": {
        "KALI_HOST": "192.168.1.100",
        "SSH_USER": "kali",
        "SSH_KEY": "/path/to/ssh/key"
      }
    }
  }
}
```

## Available Tools

### Connection & Setup

| Tool | Description |
|------|-------------|
| `test_connection` | Test SSH connection and verify aircrack-ng installation |
| `airmon_check` | List wireless interfaces and their status |
| `airmon_check_kill` | Kill processes that interfere with monitor mode |
| `airmon_start` | Enable monitor mode on a wireless interface |
| `airmon_stop` | Disable monitor mode and restore managed mode |

### Scanning & Capture

| Tool | Description |
|------|-------------|
| `airodump_scan` | Scan for wireless networks (returns BSSID, channel, encryption, ESSID) |
| `airodump_capture` | Start packet capture on a specific target (runs in background) |
| `airodump_stop` | Stop a running packet capture |
| `airodump_status` | Check status of a running capture |

### Attacks

| Tool | Description |
|------|-------------|
| `aireplay_deauth` | Send deauthentication frames (helps capture WPA handshakes) |
| `aireplay_fakeauth` | Perform fake authentication with AP (for WEP attacks) |

### Cracking

| Tool | Description |
|------|-------------|
| `aircrack_crack` | Attempt to crack WPA/WPA2 handshake using a wordlist |
| `aircrack_check_handshake` | Verify if a valid handshake has been captured |

### Utilities

| Tool | Description |
|------|-------------|
| `list_captures` | List all capture files in the captures directory |
| `cleanup_captures` | Delete capture files |
| `get_interface_info` | Get detailed information about a wireless interface |

## Typical Workflow

A typical WPA/WPA2 security assessment workflow:

```
1. test_connection              # Verify SSH connectivity and aircrack-ng
2. airmon_check                 # List available wireless interfaces
3. airmon_check_kill            # Kill interfering processes
4. airmon_start(wlan0)          # Enable monitor mode -> wlan0mon
5. airodump_scan(wlan0mon, 30)  # Scan for networks (30 seconds)
6. airodump_capture(...)        # Start capturing target network
7. aireplay_deauth(...)         # Deauth to force handshake
8. aircrack_check_handshake(...) # Verify handshake captured
9. aircrack_crack(...)          # Attempt to crack password
10. airodump_stop(...)          # Stop the capture
11. airmon_stop(wlan0mon)       # Restore managed mode
```

## Security Considerations

- **Authorization Required** - Only use on networks you own or have explicit written permission to test
- **SSH Security** - Use key-based authentication and restrict SSH access
- **Capture Files** - Captured data may contain sensitive information; handle appropriately
- **Legal Compliance** - Ensure compliance with local laws and regulations

## Legal Notice

**WARNING:** Unauthorized access to computer networks is illegal in most jurisdictions.

This tool is intended **exclusively** for:
- Authorized penetration testing
- Security research on networks you own
- Educational purposes in controlled environments

The authors assume no liability for misuse of this software. Users are solely responsible for ensuring they have proper authorization before conducting any security testing.

## Development

```bash
# Watch mode for development
npm run dev

# Build for production
npm run build

# Run the server
npm start
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgments

- [Aircrack-ng Team](https://www.aircrack-ng.org/) - For the excellent wireless security suite
- [Model Context Protocol](https://modelcontextprotocol.io) - For the MCP specification
- [Anthropic](https://www.anthropic.com/) - For Claude and the MCP ecosystem
