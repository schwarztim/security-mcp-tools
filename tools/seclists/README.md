# SecLists MCP Server

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![MCP](https://img.shields.io/badge/MCP-Compatible-blue)](https://modelcontextprotocol.io)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-blue)](https://www.typescriptlang.org/)
[![Node.js](https://img.shields.io/badge/Node.js-18%2B-green)](https://nodejs.org/)

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server for working with [SecLists](https://github.com/danielmiessler/SecLists) - the security tester's companion collection of multiple types of lists used during security assessments.

## Overview

This MCP server provides AI assistants with structured access to SecLists wordlists for security testing, penetration testing, and red team operations. It enables searching, browsing, previewing, and combining wordlists without loading massive files into memory.

### Key Features

- **Smart Discovery** - Auto-detects SecLists installation in common paths
- **Category Browsing** - Navigate wordlists by category (Discovery, Fuzzing, Passwords, etc.)
- **Intelligent Search** - Find wordlists by name or keywords
- **Preview Mode** - View wordlist contents without loading entire files
- **Entry Counting** - Get line counts for any wordlist
- **Wordlist Combining** - Merge multiple wordlists with deduplication
- **Auto-Installation** - Clone SecLists from GitHub if not present

## Installation

### Prerequisites

- Node.js 18+
- npm or yarn
- Git (for SecLists installation)

### Install the MCP Server

```bash
git clone https://github.com/schwarztim/sec-seclists-mcp.git
cd sec-seclists-mcp
npm install
npm run build
```

### Install SecLists

The MCP server automatically searches for SecLists in common locations:

- `/usr/share/seclists` (Kali Linux default)
- `/usr/share/wordlists/seclists`
- `~/SecLists`
- `/opt/seclists`

**Option 1: Use the MCP tool**
```
seclists_install
```

**Option 2: Manual installation**
```bash
git clone --depth 1 https://github.com/danielmiessler/SecLists.git ~/SecLists
```

**Option 3: Package manager (Kali/Debian)**
```bash
sudo apt install seclists
```

### Configure with Claude Desktop

Add to your Claude Desktop configuration (`~/.claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "seclists": {
      "command": "node",
      "args": ["/path/to/sec-seclists-mcp/dist/index.js"],
      "env": {
        "SECLISTS_PATH": "/usr/share/seclists"
      }
    }
  }
}
```

## Available Tools

### `seclists_status`

Check SecLists installation status and statistics.

```
seclists_status
```

**Returns:** Installation path, wordlist count, total size, and category count.

---

### `seclists_install`

Install SecLists or configure a custom path.

```
seclists_install path="/custom/path"
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `path` | string | Custom installation path (default: `~/SecLists`) |

---

### `seclists_categories`

List all SecLists categories with descriptions.

```
seclists_categories
```

**Returns:** All categories with descriptions, existence status, and wordlist counts.

---

### `seclists_list`

List available wordlists, optionally filtered by category or pattern.

```
seclists_list category="Discovery/Web-Content" pattern="raft-*"
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `category` | string | Category to list (e.g., `Discovery/Web-Content`) |
| `pattern` | string | Glob pattern to filter (e.g., `*.txt`, `raft-*`) |

---

### `seclists_search`

Search for wordlists by name or content keywords.

```
seclists_search query="sqli" category="Fuzzing"
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `query` | string | Yes | Search query |
| `category` | string | No | Limit search to specific category |

---

### `seclists_get`

Get the full path to a specific wordlist.

```
seclists_get name="rockyou.txt"
seclists_get name="Discovery/Web-Content/common.txt"
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | Yes | Wordlist name or relative path |

**Returns:** Full path, relative path, file size, and entry count.

---

### `seclists_preview`

Preview wordlist contents without loading entire files.

```
seclists_preview name="Discovery/Web-Content/common.txt" lines=50 offset=100
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `name` | string | - | Wordlist name or path (required) |
| `lines` | number | 20 | Number of lines to preview (max: 100) |
| `offset` | number | 0 | Line offset to start from |

---

### `seclists_count`

Count entries in a wordlist.

```
seclists_count name="Passwords/Leaked-Databases/rockyou.txt"
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `name` | string | Yes | Wordlist name or path |

---

### `seclists_combine`

Combine multiple wordlists into one with optional deduplication.

```
seclists_combine wordlists=["list1.txt", "list2.txt"] dedupe=true output="/tmp/combined.txt"
```

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `wordlists` | string[] | - | Array of wordlist paths (required) |
| `dedupe` | boolean | true | Remove duplicate entries |
| `output` | string | - | Output file path (returns content if not specified) |

---

### `seclists_popular`

List popular/recommended wordlists with descriptions.

```
seclists_popular category="Discovery"
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `category` | string | Filter by category prefix |

## SecLists Categories

| Category | Description |
|----------|-------------|
| `Discovery/DNS` | DNS enumeration wordlists (subdomains, zone transfers) |
| `Discovery/Web-Content` | Common directories, files, and backup artifacts |
| `Discovery/Infrastructure` | Network and infrastructure discovery |
| `Fuzzing/SQLi` | SQL injection payloads (generic and DB-specific) |
| `Fuzzing/XSS` | Cross-site scripting vectors and polyglots |
| `Fuzzing/LFI` | Local file inclusion payloads |
| `Passwords/Common-Credentials` | Commonly used username/password combinations |
| `Passwords/Leaked-Databases` | Passwords from known data breaches |
| `Passwords/Default-Credentials` | Default credentials for various systems |
| `Usernames` | Username wordlists for enumeration |
| `Payloads` | Attack payloads and shells |
| `Pattern-Matching` | Patterns for sensitive data detection |

## Popular Wordlists

### Web Content Discovery

| Wordlist | Entries | Description |
|----------|---------|-------------|
| `Discovery/Web-Content/raft-large-directories.txt` | ~62k | Comprehensive directory names |
| `Discovery/Web-Content/raft-large-files.txt` | ~37k | Comprehensive filenames |
| `Discovery/Web-Content/common.txt` | ~4.6k | Common web paths |
| `Discovery/Web-Content/directory-list-2.3-medium.txt` | ~220k | DirBuster medium list |

### DNS Discovery

| Wordlist | Entries | Description |
|----------|---------|-------------|
| `Discovery/DNS/subdomains-top1million-5000.txt` | 5k | Top 5000 subdomains |
| `Discovery/DNS/subdomains-top1million-20000.txt` | 20k | Top 20000 subdomains |
| `Discovery/DNS/subdomains-top1million-110000.txt` | 110k | Top 110000 subdomains |

### Passwords

| Wordlist | Entries | Description |
|----------|---------|-------------|
| `Passwords/Common-Credentials/10-million-password-list-top-1000.txt` | 1k | Top 1000 passwords |
| `Passwords/Common-Credentials/10-million-password-list-top-10000.txt` | 10k | Top 10000 passwords |
| `Passwords/Leaked-Databases/rockyou.txt` | ~14M | RockYou breach passwords |

### Fuzzing

| Wordlist | Description |
|----------|-------------|
| `Fuzzing/SQLi/Generic-SQLi.txt` | Generic SQL injection payloads |
| `Fuzzing/XSS/XSS-Bypass-Strings-BruteLogic.txt` | XSS filter bypass strings |
| `Fuzzing/LFI/LFI-Jhaddix.txt` | LFI payloads from Jhaddix |

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SECLISTS_PATH` | Custom path to SecLists installation | Auto-detected |

## Example Workflows

### Web Application Testing

```
# Find relevant wordlists for web fuzzing
seclists_search query="web" category="Discovery"

# Preview a directory wordlist
seclists_preview name="Discovery/Web-Content/raft-large-directories.txt" lines=20

# Get the full path for use with other tools
seclists_get name="Discovery/Web-Content/common.txt"
```

### Password Auditing

```
# List popular password wordlists
seclists_popular category="Passwords"

# Count entries in rockyou
seclists_count name="rockyou.txt"

# Combine multiple password lists
seclists_combine wordlists=["Passwords/Common-Credentials/10-million-password-list-top-1000.txt", "Passwords/Common-Credentials/best1050.txt"] dedupe=true
```

### SQL Injection Testing

```
# Search for SQLi payloads
seclists_search query="sqli"

# Preview injection strings
seclists_preview name="Fuzzing/SQLi/Generic-SQLi.txt" lines=50
```

## Development

```bash
# Install dependencies
npm install

# Build TypeScript
npm run build

# Run in development mode
npm run dev

# Run the server
npm start
```

## Security Considerations

This tool provides access to security testing wordlists. Use responsibly:

- Only use against systems you own or have explicit authorization to test
- Follow responsible disclosure practices
- Comply with all applicable laws and regulations
- Some wordlists contain sensitive content (leaked passwords, exploit payloads)

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Credits

- [SecLists](https://github.com/danielmiessler/SecLists) by Daniel Miessler
- [Model Context Protocol](https://modelcontextprotocol.io) by Anthropic

## Related Projects

- [SecLists](https://github.com/danielmiessler/SecLists) - The wordlist collection
- [MCP SDK](https://github.com/modelcontextprotocol/sdk) - Model Context Protocol SDK
- [ffuf](https://github.com/ffuf/ffuf) - Fast web fuzzer
- [gobuster](https://github.com/OJ/gobuster) - Directory/DNS busting tool
