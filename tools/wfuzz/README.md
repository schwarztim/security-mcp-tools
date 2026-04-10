# wfuzz-mcp

An MCP (Model Context Protocol) server that provides AI assistants with powerful web application fuzzing capabilities through [wfuzz](https://github.com/xmendez/wfuzz).

## Overview

This MCP server enables AI assistants to perform web application security testing using wfuzz, a flexible web fuzzer. It executes commands on a remote Kali Linux system via SSH, making it ideal for security testing environments.

## Features

- **Directory/File Discovery** - Brute-force hidden directories and files
- **Parameter Fuzzing** - Test for SQL injection, XSS, and other vulnerabilities
- **Authentication Testing** - Support for Basic, NTLM, and Digest authentication
- **Multiple Payload Types** - Wordlists, ranges, lists, permutations, and more
- **Advanced Filtering** - Hide/show results by status code, lines, words, or characters
- **Encoder Support** - MD5, SHA1, Base64, URL encoding, and chained encoders
- **Proxy Integration** - Route traffic through Burp Suite or other proxies
- **Recipe Management** - Save and reuse fuzzing configurations

## Prerequisites

- Node.js 18+
- SSH access to a Kali Linux system with wfuzz installed
- An MCP-compatible AI assistant (e.g., Claude)

## Installation

```bash
git clone https://github.com/schwarztim/sec-wfuzz-mcp.git
cd sec-wfuzz-mcp
npm install
npm run build
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `WFUZZ_KALI_HOST` | `kali` | SSH hostname for the Kali system |

### SSH Setup

Ensure passwordless SSH access to your Kali system:

```bash
ssh-copy-id kali
```

### Claude Desktop Configuration

Add to your Claude Desktop config (`~/.claude.json` or equivalent):

```json
{
  "mcpServers": {
    "wfuzz": {
      "command": "node",
      "args": ["/path/to/sec-wfuzz-mcp/dist/index.js"],
      "env": {
        "WFUZZ_KALI_HOST": "kali"
      }
    }
  }
}
```

## Available Tools

### wfuzz_fuzz

Execute fuzzing against a target URL.

```typescript
{
  url: string;           // Target URL with FUZZ keyword(s)
  wordlist?: string;     // Path to wordlist
  payloads?: PayloadConfig[];  // Advanced payload configurations
  method?: string;       // HTTP method (GET, POST, etc.)
  data?: string;         // POST data
  headers?: Record<string, string>;
  cookies?: string[];
  hideCode?: number[];   // Hide these status codes
  showCode?: number[];   // Show only these status codes
  hideLines?: number;
  hideWords?: number;
  hideChars?: number;
  filter?: string;       // Advanced filter expression
  threads?: number;
  delay?: number;
  proxy?: string;
  auth?: { type: "basic" | "ntlm" | "digest"; credentials: string };
  followRedirects?: boolean;
  recursion?: number;
  scripts?: string[];
  ignoreErrors?: boolean;
  verbose?: boolean;
  maxResults?: number;
}
```

### wfuzz_payloads

List available payload types (file, range, list, stdin, etc.).

### wfuzz_encoders

List available encoders (md5, sha1, base64, urlencode, etc.).

### wfuzz_iterators

List iterator types for combining payloads (zip, chain, product).

### wfuzz_scripts

List available wfuzz scripts for analyzing responses.

### wfuzz_filters

Get documentation on the filter language for advanced result filtering.

### wfuzz_recipe

Save, load, or list wfuzz recipes (reusable configurations).

### wfuzz_wordlists

List common wordlists available on Kali by category.

### wfuzz_help

Get wfuzz help and version information.

## Usage Examples

### Directory Discovery

```
Use wfuzz to discover hidden directories on http://target.com using the common wordlist
```

### Parameter Fuzzing

```
Fuzz the id parameter on http://target.com/page?id=FUZZ with numbers 1-1000
```

### Authentication Brute Force

```
Fuzz login at http://target.com/login with POST data username=admin&password=FUZZ using rockyou.txt, hiding 401 responses
```

### Subdomain Discovery

```
Enumerate subdomains for target.com using FUZZ.target.com pattern
```

## Security Considerations

This tool is intended for authorized security testing only. Always:

- Obtain written permission before testing any system
- Use only on systems you own or have explicit authorization to test
- Comply with all applicable laws and regulations
- Be aware of rate limiting and potential service disruption

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Related Projects

- [wfuzz](https://github.com/xmendez/wfuzz) - The underlying fuzzer
- [MCP Protocol](https://modelcontextprotocol.io/) - Model Context Protocol specification
