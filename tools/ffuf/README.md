# sec-ffuf-mcp

An MCP (Model Context Protocol) server for [ffuf](https://github.com/ffuf/ffuf) - Fast web fuzzer written in Go.

This server enables AI assistants to perform web content discovery, directory brute-forcing, subdomain enumeration, virtual host discovery, and parameter fuzzing through a secure SSH connection to a Kali Linux host.

## Features

- **Web Content Discovery** - Fuzz directories, files, and endpoints
- **Subdomain Enumeration** - Discover subdomains via Host header injection
- **Virtual Host Discovery** - Find hidden vhosts on target IPs
- **Parameter Fuzzing** - Discover hidden GET/POST parameters
- **Recursive Scanning** - Deep directory traversal with configurable depth
- **Response Filtering** - Match or filter by status codes, size, words, lines, or regex
- **Rate Limiting** - Thread control and request delays for responsible testing
- **Multiple Wordlists** - Pre-configured access to common wordlists (dirb, DirBuster, SecLists)

## Prerequisites

- Node.js 18+
- SSH access to a Kali Linux host with ffuf installed
- SSH key authentication configured (recommended)

## Installation

```bash
git clone https://github.com/schwarztim/sec-ffuf-mcp.git
cd sec-ffuf-mcp
npm install
npm run build
```

## Configuration

Set the Kali Linux host via environment variable:

```bash
export KALI_HOST="kali"  # default: "kali"
```

Ensure SSH key authentication is configured for passwordless access to your Kali host.

## MCP Configuration

Add to your Claude Desktop or MCP client configuration:

```json
{
  "mcpServers": {
    "ffuf": {
      "command": "node",
      "args": ["/path/to/sec-ffuf-mcp/dist/index.js"],
      "env": {
        "KALI_HOST": "your-kali-hostname"
      }
    }
  }
}
```

## Available Tools

### `ffuf_fuzz`
Run ffuf web fuzzing against a target URL.

```json
{
  "url": "https://target.com/FUZZ",
  "wordlist": "common",
  "threads": 40,
  "extensions": ".php,.html,.txt"
}
```

### `ffuf_matchers`
Run ffuf with specific response matchers.

```json
{
  "url": "https://target.com/FUZZ",
  "matchCodes": "200,301,302",
  "matchSize": "1234"
}
```

### `ffuf_filters`
Run ffuf with response filters to exclude unwanted results.

```json
{
  "url": "https://target.com/FUZZ",
  "filterCodes": "404,403",
  "filterSize": "0"
}
```

### `ffuf_recursion`
Recursive directory scanning.

```json
{
  "url": "https://target.com/FUZZ",
  "depth": 3,
  "strategy": "greedy"
}
```

### `ffuf_subdomain`
Subdomain enumeration via Host header injection.

```json
{
  "domain": "example.com",
  "wordlist": "subdomains",
  "filterSize": "1234"
}
```

### `ffuf_vhost`
Virtual host discovery.

```json
{
  "ip": "192.168.1.100",
  "domain": "example.com",
  "wordlist": "subdomains"
}
```

### `ffuf_parameter`
Hidden parameter discovery.

```json
{
  "url": "https://target.com/api/endpoint",
  "method": "POST",
  "wordlist": "parameters"
}
```

### `ffuf_wordlists`
List all available predefined wordlists.

### `ffuf_status`
Check ffuf availability and version on Kali host.

## Available Wordlists

| Name | Description | Path |
|------|-------------|------|
| `common` | Common directory/file names (4614 entries) | `/usr/share/wordlists/dirb/common.txt` |
| `big` | Larger common list (20469 entries) | `/usr/share/wordlists/dirb/big.txt` |
| `small` | Quick scan list (959 entries) | `/usr/share/wordlists/dirb/small.txt` |
| `dirbuster_small` | DirBuster small list (~87k entries) | `/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt` |
| `dirbuster_medium` | DirBuster medium list (~220k entries) | `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt` |
| `dirbuster_big` | DirBuster big list (~1.27M entries) | `/usr/share/wordlists/dirbuster/directory-list-2.3-big.txt` |
| `seclists_common` | SecLists common web content | `/usr/share/seclists/Discovery/Web-Content/common.txt` |
| `seclists_directories` | SecLists directory list medium | `/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt` |
| `subdomains` | Top 5000 subdomains | `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt` |
| `parameters` | Burp parameter names | `/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt` |
| `api_endpoints` | Common API endpoints | `/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt` |

## Usage Examples

### Basic Directory Fuzzing
```
Use ffuf_fuzz with url "https://target.com/FUZZ" and wordlist "common"
```

### Finding PHP Files
```
Use ffuf_fuzz with url "https://target.com/FUZZ" and extensions ".php,.php5,.phtml"
```

### Recursive Scan with Depth Limit
```
Use ffuf_recursion with url "https://target.com/FUZZ", depth 2, and maxtime 300
```

### Subdomain Enumeration
```
Use ffuf_subdomain with domain "example.com" and filterSize "1234" to exclude default response
```

### POST Parameter Discovery
```
Use ffuf_parameter with url "https://target.com/login" and method "POST"
```

## Security Notice

This tool is intended for authorized security testing only. Always ensure you have explicit permission before testing any systems. Unauthorized access to computer systems is illegal.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- [ffuf](https://github.com/ffuf/ffuf) by joohoi - The fast web fuzzer this MCP wraps
- [Model Context Protocol](https://modelcontextprotocol.io/) by Anthropic
