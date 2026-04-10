# Feroxbuster MCP Server

A Model Context Protocol (MCP) server for [feroxbuster](https://github.com/epi052/feroxbuster) - a fast, simple, recursive content discovery tool written in Rust.

## Overview

This MCP server enables AI assistants to control feroxbuster scans on a remote Kali Linux system via SSH. It provides a complete interface for web content discovery with support for:

- Directory and file brute-forcing with customizable wordlists
- Recursive scanning with configurable depth
- Flexible filtering (status codes, response size, word count, line count)
- Rate limiting, auto-tuning, and auto-bail features
- Background scans with real-time progress monitoring
- Resume capability from state files
- Multiple output formats (text, JSON, URLs)

## Prerequisites

- **Node.js 18+**
- **SSH access** to a Kali Linux system (or any system with feroxbuster installed)
- **SSH key authentication** configured for passwordless access (recommended)
- **feroxbuster** installed on the remote system

## Installation

```bash
git clone https://github.com/schwarztim/sec-feroxbuster-mcp.git
cd sec-feroxbuster-mcp
npm install
npm run build
```

## Configuration

### Claude Desktop / Claude Code

Add the server to your MCP configuration:

**Claude Desktop** (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "feroxbuster": {
      "command": "node",
      "args": ["/path/to/sec-feroxbuster-mcp/dist/index.js"],
      "env": {
        "KALI_HOST": "kali"
      }
    }
  }
}
```

**Claude Code** (`~/.claude/user-mcps.json`):

```json
{
  "feroxbuster": {
    "command": "node",
    "args": ["/path/to/sec-feroxbuster-mcp/dist/index.js"],
    "env": {
      "KALI_HOST": "kali"
    }
  }
}
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `KALI_HOST` | SSH hostname for the remote system with feroxbuster | `kali` |

### SSH Setup

Ensure SSH key authentication is configured:

```bash
# Generate key if needed
ssh-keygen -t ed25519 -C "feroxbuster-mcp"

# Copy to remote host
ssh-copy-id kali

# Test connection
ssh kali "feroxbuster --version"
```

## Available Tools

### feroxbuster_scan

Start a directory/file discovery scan against a target URL.

**Parameters:**

| Parameter | Type | Description |
|-----------|------|-------------|
| `url` | string | **(required)** Target URL to scan |
| `wordlist` | string | Path to wordlist on remote system |
| `extensions` | string[] | File extensions to check (e.g., `["php", "html", "js"]`) |
| `recursion_depth` | number | Maximum recursion depth (0 = infinite, default: 4) |
| `threads` | number | Concurrent threads (default: 50) |
| `timeout` | number | Request timeout in seconds (default: 7) |
| `rate_limit` | number | Max requests per second per directory |
| `filter_status` | number[] | Status codes to exclude from results |
| `status_codes` | number[] | Status codes to include |
| `filter_size` | number[] | Response sizes to exclude |
| `filter_words` | number[] | Word counts to exclude |
| `filter_lines` | number[] | Line counts to exclude |
| `headers` | object | Custom headers (e.g., `{"Authorization": "Bearer token"}`) |
| `proxy` | string | Proxy URL (HTTP or SOCKS5) |
| `insecure` | boolean | Disable TLS certificate validation |
| `no_recursion` | boolean | Disable recursive scanning |
| `force_recursion` | boolean | Force recursion on all discovered paths |
| `auto_tune` | boolean | Automatically reduce rate on errors |
| `auto_bail` | boolean | Automatically stop on excessive errors |
| `silent` | boolean | Only output URLs (for piping) |
| `json` | boolean | Output results as JSON |
| `background` | boolean | Run scan in background |
| `dont_scan` | string[] | URLs to exclude from recursion |
| `time_limit` | string | Maximum scan time (e.g., `"10m"`, `"1h"`) |
| `scan_limit` | number | Maximum concurrent directory scans |
| `user_agent` | string | Custom User-Agent string |
| `cookies` | string | Cookie string to include |
| `data` | string | POST request body |
| `methods` | string[] | HTTP methods to use (default: GET) |
| `query` | string | Query parameters to append |

### feroxbuster_config

Configure default settings for subsequent scans. Accepts same filtering and connection parameters as `feroxbuster_scan`.

### feroxbuster_status

Check the status of a running or completed scan.

| Parameter | Type | Description |
|-----------|------|-------------|
| `tail_lines` | number | Number of output lines to show (default: 50) |

### feroxbuster_stop

Stop a running scan gracefully. Preserves state file for potential resume.

### feroxbuster_resume

Resume a previously interrupted scan from its state file.

| Parameter | Type | Description |
|-----------|------|-------------|
| `state_file` | string | Path to state file (optional, uses last scan) |
| `background` | boolean | Run resumed scan in background |

### feroxbuster_wordlists

List available wordlists on the remote system.

| Parameter | Type | Description |
|-----------|------|-------------|
| `search` | string | Filter wordlists by search term |
| `category` | string | Category: `"common"`, `"directory"`, `"web"`, `"api"`, `"all"` |

### feroxbuster_results

Retrieve and format results from the last completed scan.

| Parameter | Type | Description |
|-----------|------|-------------|
| `format` | string | Output format: `"text"`, `"json"`, `"urls"` |
| `filter_status` | number[] | Filter results by status codes |

### feroxbuster_version

Get feroxbuster version information from the remote system.

## Usage Examples

### Basic Scan

```
Scan http://target.com for directories and files
```

### Scan with Extensions and Filtering

```
Scan http://target.com looking for php, html, and txt files.
Exclude 404 and 500 responses. Limit recursion to 3 levels.
```

### Background Scan with Rate Limiting

```
Start a background scan of http://target.com with rate limiting
at 100 requests/second and auto-tune enabled.
```

### Check Scan Progress

```
What's the status of my feroxbuster scan?
```

### Resume an Interrupted Scan

```
Resume the last feroxbuster scan in the background
```

### List Available Wordlists

```
Show me API-related wordlists on the Kali system
```

## State Management

Scan state is persisted in `~/.feroxbuster-mcp/state.json`:

- Active scan information (PID, URL, output file, state file)
- Last scan results for retrieval
- Default configuration settings

This enables scan resumption and result retrieval across sessions.

## Security Considerations

- This tool is designed for authorized security testing only
- Always obtain proper authorization before scanning any systems
- Use rate limiting to avoid overwhelming target servers
- Consider using the `auto_bail` option to stop on errors
- Proxy support enables routing through Burp Suite or other tools

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- [feroxbuster](https://github.com/epi052/feroxbuster) by epi052
- [Model Context Protocol](https://modelcontextprotocol.io) by Anthropic
