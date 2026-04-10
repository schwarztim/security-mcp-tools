# SMBMap MCP Server

[![MCP](https://img.shields.io/badge/MCP-Model%20Context%20Protocol-blue)](https://modelcontextprotocol.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/Node.js-18%2B-green)](https://nodejs.org/)
[![Kali Linux](https://img.shields.io/badge/Kali%20Linux-Required-557C94)](https://www.kali.org/)

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server that provides AI assistants with SMB share enumeration and interaction capabilities via [SMBMap](https://github.com/ShawnDEvans/smbmap).

## Overview

This MCP server enables AI assistants like Claude to perform SMB-based security assessments and penetration testing tasks. It executes commands on a remote Kali Linux machine via SSH, providing a secure and isolated execution environment.

```
[AI Assistant] <-> [MCP Server] <-> [SSH] <-> [Kali Linux] <-> [SMBMap] <-> [Target]
```

## Features

| Tool | Description |
|------|-------------|
| `smbmap_enum` | Enumerate SMB shares on a target host |
| `smbmap_permissions` | Check share permissions (READ, WRITE, NO ACCESS) |
| `smbmap_list` | List files and directories in shares (supports recursion) |
| `smbmap_download` | Download files from SMB shares |
| `smbmap_upload` | Upload files to SMB shares |
| `smbmap_exec` | Execute commands via SMB (requires admin) |
| `smbmap_search` | Search for files by name pattern (regex supported) |
| `smbmap_content_search` | Search file contents (requires admin + PowerShell) |
| `smbmap_drives` | List all drives on target system |
| `smbmap_delete` | Delete files from SMB shares |
| `smbmap_host_file` | Scan multiple hosts from a file |

## Prerequisites

- **Node.js 18+**
- **SSH access** to a Kali Linux machine (passwordless SSH recommended)
- **SMBMap** installed on Kali (`apt install smbmap`)

## Installation

```bash
# Clone the repository
git clone https://github.com/schwarztim/sec-smbmap-mcp.git
cd sec-smbmap-mcp

# Install dependencies
npm install

# Build the project
npm run build
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `KALI_HOST` | `kali` | SSH hostname or IP of Kali Linux machine |
| `SSH_OPTIONS` | `-o StrictHostKeyChecking=no -o ConnectTimeout=10` | SSH connection options |

### Claude Desktop Configuration

Add to your Claude Desktop configuration file (`~/.config/claude/claude_desktop_config.json` on Linux or `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "smbmap": {
      "command": "node",
      "args": ["/path/to/sec-smbmap-mcp/dist/index.js"],
      "env": {
        "KALI_HOST": "your-kali-host"
      }
    }
  }
}
```

### SSH Setup

Ensure passwordless SSH access to your Kali machine:

```bash
# Generate SSH key if needed
ssh-keygen -t ed25519

# Copy key to Kali machine
ssh-copy-id kali

# Test connection
ssh kali "smbmap --help"
```

## Usage Examples

### Basic Share Enumeration (Null Session)

```json
{
  "tool": "smbmap_enum",
  "arguments": {
    "host": "192.168.1.100"
  }
}
```

### Authenticated Enumeration

```json
{
  "tool": "smbmap_enum",
  "arguments": {
    "host": "192.168.1.100",
    "username": "admin",
    "password": "password123",
    "domain": "CORP"
  }
}
```

### Pass-the-Hash Authentication

```json
{
  "tool": "smbmap_enum",
  "arguments": {
    "host": "192.168.1.100",
    "username": "admin",
    "password": "aad3b435b51404eeaad3b435b51404ee:da76f2c4c96028b7a6111aef4a50a94d"
  }
}
```

### Recursive Directory Listing

```json
{
  "tool": "smbmap_list",
  "arguments": {
    "host": "192.168.1.100",
    "username": "admin",
    "password": "password123",
    "path": "C$\\Users",
    "recursive": true,
    "depth": 2
  }
}
```

### Search for Sensitive Files

```json
{
  "tool": "smbmap_search",
  "arguments": {
    "host": "192.168.1.100",
    "username": "admin",
    "password": "password123",
    "pattern": ".*password.*",
    "search_path": "C$\\Users"
  }
}
```

### Execute Remote Command

```json
{
  "tool": "smbmap_exec",
  "arguments": {
    "host": "192.168.1.100",
    "username": "admin",
    "password": "password123",
    "command": "ipconfig /all"
  }
}
```

### Download File

```json
{
  "tool": "smbmap_download",
  "arguments": {
    "host": "192.168.1.100",
    "username": "admin",
    "password": "password123",
    "remote_path": "C$\\Users\\admin\\Desktop\\passwords.txt"
  }
}
```

### Multi-Host Scanning

```json
{
  "tool": "smbmap_host_file",
  "arguments": {
    "host_file": "/tmp/targets.txt",
    "username": "admin",
    "password": "password123",
    "domain": "CORP"
  }
}
```

## Security Notice

**This tool is intended for authorized penetration testing and security assessments only.**

- Always obtain proper written authorization before scanning any systems
- Follow responsible disclosure practices
- Comply with all applicable laws and regulations
- Never use this tool against systems you do not own or have explicit permission to test

Unauthorized access to computer systems is illegal and unethical.

## Development

```bash
# Watch mode for development
npm run dev

# Build for production
npm run build

# Start the server
npm start
```

## References

- [SMBMap](https://github.com/ShawnDEvans/smbmap) - The underlying enumeration tool
- [Model Context Protocol](https://modelcontextprotocol.io/) - MCP specification
- [Kali Linux Tools - smbmap](https://www.kali.org/tools/smbmap/) - Kali documentation
- [MCP TypeScript SDK](https://github.com/modelcontextprotocol/typescript-sdk) - SDK used for this server

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request
