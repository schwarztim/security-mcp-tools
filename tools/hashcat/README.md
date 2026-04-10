# Hashcat MCP Server

[![MCP](https://img.shields.io/badge/MCP-Model%20Context%20Protocol-blue)](https://modelcontextprotocol.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/Node.js-18%2B-green)](https://nodejs.org)

A Model Context Protocol (MCP) server that provides AI assistants with GPU-accelerated password recovery capabilities via [hashcat](https://hashcat.net/hashcat/). Designed for security professionals, penetration testers, and red team operators conducting authorized security assessments.

## Overview

This MCP server enables AI assistants to orchestrate hashcat operations on a remote Kali Linux system via SSH, providing:

- Full control over hashcat cracking sessions
- Support for all attack modes (dictionary, brute-force, hybrid, combinator)
- Session management with pause/resume capabilities
- Hash identification and mode lookup
- Benchmark and performance testing

## Features

### 12 Comprehensive Tools

| Tool | Description |
|------|-------------|
| `hashcat_crack` | Start password cracking with configurable attack modes |
| `hashcat_status` | Monitor running session progress |
| `hashcat_show` | Display cracked passwords from potfile |
| `hashcat_benchmark` | Test GPU cracking performance |
| `hashcat_modes` | List and search 600+ supported hash types |
| `hashcat_attack_modes` | Explain available attack methodologies |
| `hashcat_rules` | Browse and inspect rule files |
| `hashcat_restore` | Resume interrupted sessions |
| `hashcat_stop` | Gracefully stop with checkpoint save |
| `hashcat_wordlists` | Discover available wordlists |
| `hashcat_identify` | Identify unknown hash types |
| `hashcat_sessions` | List all saved sessions |

### Supported Attack Modes

| Mode | Name | Description |
|------|------|-------------|
| 0 | Dictionary | Straight wordlist attack |
| 1 | Combinator | Combine two wordlists |
| 3 | Brute-force | Mask-based character generation |
| 6 | Hybrid W+M | Wordlist + mask suffix |
| 7 | Hybrid M+W | Mask prefix + wordlist |
| 9 | Association | Context-aware targeted cracking |

### Common Hash Types

| Name | Mode | Description |
|------|------|-------------|
| `md5` | 0 | MD5 |
| `sha1` | 100 | SHA1 |
| `sha256` | 1400 | SHA2-256 |
| `sha512` | 1700 | SHA2-512 |
| `ntlm` | 1000 | Windows NTLM |
| `netntlmv2` | 5600 | NetNTLMv2 |
| `wpa` | 22000 | WPA-PBKDF2-PMKID+EAPOL |
| `bcrypt` | 3200 | bcrypt |
| `sha512crypt` | 1800 | SHA512 Unix crypt |

## Installation

### Prerequisites

- Node.js 18 or higher
- SSH access to a Kali Linux system (or any system with hashcat)
- hashcat installed on the remote system
- GPU with OpenCL/CUDA support (recommended for performance)

### Setup

```bash
# Clone the repository
git clone https://github.com/schwarztim/sec-hashcat-mcp.git
cd sec-hashcat-mcp

# Install dependencies
npm install

# Build
npm run build
```

### Configuration

Configure via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `HASHCAT_SSH_HOST` | `kali` | SSH hostname for the hashcat system |
| `HASHCAT_SSH_USER` | (current user) | SSH username |
| `HASHCAT_SSH_OPTIONS` | `-o StrictHostKeyChecking=no -o ConnectTimeout=10` | SSH connection options |
| `HASHCAT_PATH` | `hashcat` | Path to hashcat binary on remote |
| `HASHCAT_WORDLIST` | `/usr/share/wordlists/rockyou.txt` | Default wordlist path |
| `HASHCAT_RULES` | `/usr/share/hashcat/rules/best64.rule` | Default rules file path |

### Claude Desktop Integration

Add to your Claude Desktop configuration (`~/.claude.json` or equivalent):

```json
{
  "mcpServers": {
    "hashcat": {
      "command": "node",
      "args": ["/path/to/sec-hashcat-mcp/dist/index.js"],
      "env": {
        "HASHCAT_SSH_HOST": "kali",
        "HASHCAT_SSH_USER": "root"
      }
    }
  }
}
```

## Usage Examples

### Dictionary Attack on MD5

```json
{
  "tool": "hashcat_crack",
  "arguments": {
    "hash": "5d41402abc4b2a76b9719d911017c592",
    "hash_mode": "md5",
    "attack_mode": "dictionary",
    "wordlist": "/usr/share/wordlists/rockyou.txt"
  }
}
```

### Brute-Force with Mask

Crack a 6-character lowercase password:

```json
{
  "tool": "hashcat_crack",
  "arguments": {
    "hash": "5d41402abc4b2a76b9719d911017c592",
    "hash_mode": 0,
    "attack_mode": "bruteforce",
    "mask": "?l?l?l?l?l?l"
  }
}
```

### NTLM with Rules

```json
{
  "tool": "hashcat_crack",
  "arguments": {
    "hash": "32ed87bdb5fdc5e9cba88547376818d4",
    "hash_mode": "ntlm",
    "attack_mode": "dictionary",
    "rules": "/usr/share/hashcat/rules/best64.rule",
    "session": "ntlm_audit"
  }
}
```

### Background Long-Running Crack

```json
{
  "tool": "hashcat_crack",
  "arguments": {
    "hash": "/tmp/hashes.txt",
    "hash_mode": 1000,
    "attack_mode": "dictionary",
    "session": "overnight_crack",
    "background": true,
    "workload": 3
  }
}
```

Then check progress:

```json
{
  "tool": "hashcat_status",
  "arguments": {
    "session": "overnight_crack"
  }
}
```

### Incremental Mask Attack

Try passwords from 1-8 characters:

```json
{
  "tool": "hashcat_crack",
  "arguments": {
    "hash": "5d41402abc4b2a76b9719d911017c592",
    "hash_mode": "md5",
    "attack_mode": "bruteforce",
    "mask": "?a?a?a?a?a?a?a?a",
    "increment": true,
    "increment_min": 1,
    "increment_max": 8
  }
}
```

## Mask Charsets

| Charset | Characters |
|---------|------------|
| `?l` | `a-z` (lowercase) |
| `?u` | `A-Z` (uppercase) |
| `?d` | `0-9` (digits) |
| `?h` | `0-9a-f` (hex lowercase) |
| `?H` | `0-9A-F` (hex uppercase) |
| `?s` | Special characters |
| `?a` | All printable ASCII |
| `?b` | `0x00-0xff` (full byte range) |

## Security Considerations

This tool is intended for **authorized security testing only**. Users must:

- Have explicit written authorization to test target systems
- Comply with all applicable laws and regulations
- Use responsibly within the scope of authorized engagements
- Protect recovered credentials appropriately

**Misuse of password cracking tools may violate computer crime laws.**

## Development

```bash
# Watch mode for development
npm run dev

# Run tests
npm test
```

## Architecture

```
hashcat-mcp/
├── src/
│   └── index.ts      # Main MCP server implementation
├── dist/             # Compiled JavaScript
├── package.json
└── tsconfig.json
```

The server communicates via stdio transport and executes hashcat commands through SSH to the configured remote system.

## Contributing

Contributions are welcome! Please ensure any changes:

1. Maintain TypeScript type safety
2. Follow existing code style
3. Include appropriate error handling
4. Update documentation as needed

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- [hashcat](https://hashcat.net/hashcat/) - The world's fastest password cracker
- [Model Context Protocol](https://modelcontextprotocol.io) - AI tool integration standard
- [Kali Linux](https://www.kali.org/) - Security-focused Linux distribution

## Related Projects

- [hashcat](https://github.com/hashcat/hashcat) - GPU password cracker
- [MCP SDK](https://github.com/modelcontextprotocol/sdk) - Official MCP SDK
