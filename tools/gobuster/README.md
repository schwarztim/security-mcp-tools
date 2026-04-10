# gobuster-mcp

A Model Context Protocol (MCP) server for [Gobuster](https://github.com/OJ/gobuster) - a powerful directory/file, DNS, virtual host, S3 bucket, and TFTP enumeration tool written in Go.

This MCP server enables AI assistants to perform security reconnaissance and enumeration tasks by executing Gobuster commands on a remote Kali Linux host via SSH.

## Features

- **Directory/File Enumeration** (`gobuster_dir`) - Discover hidden directories and files on web servers
- **DNS Subdomain Enumeration** (`gobuster_dns`) - Find subdomains for target domains
- **Virtual Host Discovery** (`gobuster_vhost`) - Enumerate virtual hosts by brute-forcing Host headers
- **Fuzzing** (`gobuster_fuzz`) - Replace FUZZ keyword in URLs, headers, or POST data
- **S3 Bucket Enumeration** (`gobuster_s3`) - Discover open Amazon S3 buckets
- **TFTP Enumeration** (`gobuster_tftp`) - Find files on TFTP servers
- **Async Scan Support** - Run long scans in background with status tracking
- **Wordlist Discovery** - List available wordlists on the Kali host

## Prerequisites

- Node.js 18+
- SSH access to a Kali Linux host with Gobuster installed
- SSH key-based authentication configured (no password prompts)

## Installation

```bash
# Clone the repository
git clone https://github.com/schwarztim/sec-gobuster-mcp.git
cd sec-gobuster-mcp

# Install dependencies
npm install

# Build
npm run build
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `KALI_HOST` | `kali` | SSH hostname or alias for the Kali Linux host |

### SSH Setup

Ensure your SSH config (~/.ssh/config) has an entry for your Kali host:

```
Host kali
    HostName 192.168.1.100
    User root
    IdentityFile ~/.ssh/id_rsa
```

### Claude Desktop Configuration

Add to your Claude Desktop config (`~/.config/claude/claude_desktop_config.json` on Linux or `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "gobuster": {
      "command": "node",
      "args": ["/path/to/sec-gobuster-mcp/dist/index.js"],
      "env": {
        "KALI_HOST": "kali"
      }
    }
  }
}
```

## Available Tools

### gobuster_dir

Directory/file enumeration mode - discovers hidden directories and files on web servers.

```json
{
  "url": "https://example.com",
  "extensions": "php,html,txt",
  "threads": 20,
  "status_codes": "200,204,301,302",
  "exclude_status": "404,403"
}
```

### gobuster_dns

DNS subdomain enumeration - discovers subdomains for a target domain.

```json
{
  "domain": "example.com",
  "resolver": "8.8.8.8",
  "show_ips": true,
  "show_cname": true
}
```

### gobuster_vhost

Virtual host enumeration - discovers virtual hosts by brute-forcing Host header values.

```json
{
  "url": "https://example.com",
  "domain": "example.com",
  "exclude_length": "1234"
}
```

### gobuster_fuzz

Fuzzing mode - replaces FUZZ keyword in URLs, headers, or POST data.

```json
{
  "url": "https://example.com/api?param=FUZZ",
  "method": "GET",
  "exclude_status": "404,500"
}
```

### gobuster_s3

Amazon S3 bucket enumeration.

```json
{
  "wordlist": "/usr/share/wordlists/bucket-names.txt",
  "max_files": 10
}
```

### gobuster_tftp

TFTP file enumeration.

```json
{
  "server": "192.168.1.50",
  "timeout": 5
}
```

### Async Operations

All scan tools support an `async` parameter to run scans in the background:

```json
{
  "url": "https://example.com",
  "async": true
}
```

Use these tools to manage async scans:
- `gobuster_status` - Check scan status and retrieve output
- `gobuster_stop` - Stop a running scan
- `gobuster_list_scans` - List all active and recent scans

### gobuster_wordlists

List available wordlists on the Kali host.

```json
{
  "category": "dirb"
}
```

Categories: `all`, `dirb`, `dirbuster`, `wfuzz`, `seclists`, `subdomains`

## Common Options

Most scan tools support these common options:

| Option | Description |
|--------|-------------|
| `wordlist` | Path to wordlist file on Kali |
| `threads` | Number of concurrent threads (default: 10) |
| `timeout` | Request timeout in seconds |
| `quiet` | Suppress banner output |
| `cookies` | Cookies to include in requests |
| `headers` | Custom headers array |
| `user_agent` | Custom User-Agent string |
| `no_tls_validation` | Skip TLS certificate verification |
| `follow_redirect` | Follow HTTP redirects |

## Security Considerations

This tool is intended for authorized security testing only. Always ensure you have proper authorization before scanning any systems.

- Use only against systems you own or have explicit permission to test
- Be aware of rate limiting and server load
- Consider legal implications in your jurisdiction
- Use responsibly and ethically

## Development

```bash
# Watch mode for development
npm run dev

# Build
npm run build

# Run
npm start
```

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Related Projects

- [Gobuster](https://github.com/OJ/gobuster) - The underlying enumeration tool
- [Model Context Protocol](https://modelcontextprotocol.io/) - The protocol specification
- [MCP SDK](https://github.com/modelcontextprotocol/typescript-sdk) - TypeScript SDK for MCP
