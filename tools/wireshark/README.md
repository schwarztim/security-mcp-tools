# Wireshark MCP Server

A Model Context Protocol (MCP) server that provides network packet analysis capabilities via [Wireshark](https://www.wireshark.org/)/[tshark](https://www.wireshark.org/docs/man-pages/tshark.html) on a remote machine (e.g., Kali Linux).

This server enables AI assistants to perform sophisticated network traffic analysis, packet capture, protocol inspection, and security-focused operations through a standardized MCP interface.

## Features

- **Live Packet Capture** - Capture network traffic on remote interfaces with BPF filters
- **PCAP Analysis** - Read and analyze existing pcap files
- **Protocol Statistics** - Generate protocol hierarchy, conversations, endpoints, and I/O statistics
- **Stream Reconstruction** - Follow TCP, UDP, HTTP, and TLS streams
- **File Extraction** - Extract files from HTTP, SMB, DICOM, IMF, and TFTP traffic
- **Deep Packet Inspection** - Decode packets with full protocol details
- **Credential Extraction** - Search for credentials in HTTP Basic Auth, FTP, Telnet, and form submissions
- **HTTP Object Export** - List and export HTTP objects from captures

## Prerequisites

- Node.js 18+
- SSH access to a remote machine with tshark installed (e.g., Kali Linux)
- SSH key-based authentication configured (password-less)
- `sudo` access on the remote machine for packet capture

## Installation

```bash
git clone https://github.com/schwarztim/sec-wireshark-mcp.git
cd sec-wireshark-mcp
npm install
npm run build
```

## Configuration

Set the following environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `WIRESHARK_SSH_HOST` | SSH hostname or IP of the remote machine | `kali` |
| `WIRESHARK_SSH_USER` | SSH username (optional if using SSH config) | (empty) |
| `WIRESHARK_PCAP_DIR` | Directory on remote host for pcap files | `/tmp/mcp-pcaps` |

### Example Configuration

```bash
export WIRESHARK_SSH_HOST="192.168.1.100"
export WIRESHARK_SSH_USER="kali"
```

Or use an SSH config entry:

```
# ~/.ssh/config
Host kali
    HostName 192.168.1.100
    User kali
    IdentityFile ~/.ssh/id_rsa
```

## Usage with Claude Desktop

Add to your Claude Desktop configuration (`~/.claude/user-mcps.json` or Claude Desktop settings):

```json
{
  "mcpServers": {
    "wireshark": {
      "command": "node",
      "args": ["/path/to/sec-wireshark-mcp/dist/index.js"],
      "env": {
        "WIRESHARK_SSH_HOST": "kali",
        "WIRESHARK_SSH_USER": "kali"
      }
    }
  }
}
```

## Available Tools

### `tshark_list_interfaces`
List available network interfaces on the remote machine for packet capture.

### `tshark_capture`
Start packet capture on a specified interface.

**Parameters:**
- `interface` (required): Network interface (e.g., `eth0`, `wlan0`)
- `count`: Number of packets to capture (default: 10, max: 1000)
- `filter`: BPF capture filter (e.g., `port 80`, `host 192.168.1.1`)
- `timeout`: Capture timeout in seconds (default: 10, max: 60)
- `outputFile`: Save capture to pcap file on remote host

### `tshark_read_pcap`
Read and analyze a pcap file.

**Parameters:**
- `file` (required): Path to the pcap file on remote host
- `filter`: Wireshark display filter
- `count`: Maximum packets to return (default: 100, max: 1000)
- `fields`: Specific fields to extract (e.g., `['ip.src', 'ip.dst', 'tcp.port']`)

### `tshark_filter`
Apply a display filter to a pcap file.

**Parameters:**
- `file` (required): Path to the pcap file
- `filter` (required): Display filter (e.g., `http.request`, `dns`, `tcp.flags.syn == 1`)
- `outputFormat`: `json`, `text`, or `fields` (default: `json`)
- `fields`: Fields to extract when using `fields` format

### `tshark_stats`
Generate protocol statistics from a pcap file.

**Parameters:**
- `file` (required): Path to the pcap file
- `type` (required): `hierarchy`, `conversations`, `endpoints`, `io`, `http`, or `dns`
- `protocol`: Protocol for conversations/endpoints (e.g., `tcp`, `udp`, `ip`)

### `tshark_follow_stream`
Reconstruct a TCP, UDP, HTTP, or TLS stream.

**Parameters:**
- `file` (required): Path to the pcap file
- `protocol` (required): `tcp`, `udp`, `http`, or `tls`
- `streamIndex`: Stream index number (default: 0)
- `format`: `ascii`, `hex`, or `raw` (default: `ascii`)

### `tshark_extract_files`
Extract files from protocol traffic.

**Parameters:**
- `file` (required): Path to the pcap file
- `protocol`: `http`, `dicom`, `imf`, `smb`, or `tftp` (default: `http`)
- `outputDir`: Directory for extracted files (default: `/tmp/mcp-extracted`)

### `tshark_decode`
Deep packet inspection with full protocol details.

**Parameters:**
- `file` (required): Path to the pcap file
- `packetNumber`: Specific packet number to decode
- `filter`: Display filter to select packets
- `protocols`: Specific protocols to show (e.g., `['http', 'tcp', 'ip']`)
- `verbose`: Show all protocol details (default: false)

### `tshark_extract_credentials`
Search for potential credentials in network traffic.

**Parameters:**
- `file` (required): Path to the pcap file

Searches for HTTP Basic Auth, FTP credentials, HTTP POST form data, and Telnet data.

### `tshark_export_objects`
List and export HTTP objects from a capture.

**Parameters:**
- `file` (required): Path to the pcap file
- `listOnly`: Only list objects without extracting (default: true)
- `outputDir`: Directory for extracted objects

## Security Considerations

- This server executes commands on a remote machine via SSH
- Input sanitization is implemented to prevent command injection
- Use SSH key authentication with appropriate permissions
- Consider network segmentation for the capture machine
- The remote machine requires `sudo` access for live capture
- Credential extraction features should be used only for authorized security testing

## Development

```bash
# Run in development mode
npm run dev

# Build for production
npm run build

# Start production server
npm start
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Related Projects

- [Model Context Protocol](https://modelcontextprotocol.io/) - The protocol specification
- [Wireshark](https://www.wireshark.org/) - Network protocol analyzer
- [tshark](https://www.wireshark.org/docs/man-pages/tshark.html) - Terminal-based Wireshark
