# John the Ripper MCP Server

A Model Context Protocol (MCP) server that provides AI assistants with access to [John the Ripper](https://www.openwall.com/john/), the legendary password security auditing and recovery tool. This server executes commands on a remote Kali Linux system via SSH, enabling secure password analysis workflows.

## Features

- **Password Cracking** - Multiple attack modes: wordlist, incremental, single crack, and rules-based
- **Hash Management** - Show cracked passwords, manage pot files, identify hash types
- **Session Control** - Create, monitor, restore, and terminate cracking sessions
- **Hash Extraction** - Extract hashes from encrypted files (ZIP, PDF, SSH keys, Office docs, etc.)
- **Benchmarking** - Test cracking performance for different hash formats
- **Rules Engine** - List and test password mangling rules

## Installation

```bash
# Clone the repository
git clone https://github.com/schwarztim/sec-john-the-ripper-mcp.git
cd sec-john-the-ripper-mcp

# Install dependencies
npm install

# Build
npm run build
```

## Configuration

The server connects to a remote Kali Linux system via SSH. Configure via environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `JOHN_SSH_HOST` | SSH hostname or IP of Kali system | `kali` |
| `JOHN_SSH_USER` | SSH username (optional) | (none) |
| `JOHN_PATH` | Path to john binary on remote system | `john` |
| `JOHN_WORK_DIR` | Remote working directory for temp files | `/tmp/john-mcp` |

### Prerequisites

1. **SSH Access** - Passwordless SSH key authentication to your Kali system
2. **John the Ripper** - Installed on the remote Kali system (`apt install john`)
3. **Node.js** - Version 18+ recommended

### Claude Desktop Configuration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "john-the-ripper": {
      "command": "node",
      "args": ["/path/to/sec-john-the-ripper-mcp/dist/index.js"],
      "env": {
        "JOHN_SSH_HOST": "your-kali-host",
        "JOHN_SSH_USER": "kali"
      }
    }
  }
}
```

## Available Tools

### Cracking Operations

| Tool | Description |
|------|-------------|
| `john_crack` | Start password cracking with configurable modes and options |
| `john_show` | Display cracked passwords from hash files |
| `john_status` | Check the status of running sessions |
| `john_restore` | Resume an interrupted cracking session |
| `john_sessions` | List all active and saved sessions |
| `john_kill` | Terminate running John processes |

### Hash Analysis

| Tool | Description |
|------|-------------|
| `john_identify` | Identify hash type(s) for given values |
| `john_formats` | List supported hash formats with optional filtering |
| `john_hash_extract` | Extract hashes from encrypted files using *2john utilities |

### Configuration & Testing

| Tool | Description |
|------|-------------|
| `john_rules` | List available rules or test rules against sample words |
| `john_benchmark` | Run performance benchmarks for hash formats |
| `john_pot` | Manage the john.pot file (show, clear, export, search) |

## Usage Examples

### Crack MD5 Hashes with Wordlist

```
Use john_crack with:
- hash_content: "5f4dcc3b5aa765d61d8327deb882cf99"
- format: "raw-md5"
- wordlist: "/usr/share/wordlists/rockyou.txt"
```

### Identify Unknown Hash

```
Use john_identify with:
- hash: "$2a$10$N9qo8uLOickgx2ZMRZoMy..."
```

### Extract Hash from ZIP File

```
Use john_hash_extract with:
- type: "zip"
- file_path: "/path/to/encrypted.zip"
```

### Check Cracking Progress

```
Use john_status with:
- session: "my-crack-session"
```

## Supported Hash Extraction Types

- `zip` - ZIP archives
- `rar` - RAR archives
- `pdf` - PDF documents
- `ssh` - SSH private keys
- `gpg` - GPG/PGP keys
- `office` - Microsoft Office documents
- `keepass` - KeePass databases
- `7z` - 7-Zip archives
- `bitlocker` - BitLocker volumes
- `luks` - LUKS encrypted volumes
- `truecrypt` / `veracrypt` - TrueCrypt/VeraCrypt volumes
- `ethereum` / `bitcoin` - Cryptocurrency wallets

## Security Considerations

This tool is intended for **authorized security testing only**. Ensure you have proper authorization before:

- Testing password strength on systems you own or administer
- Conducting penetration tests with written permission
- Recovering passwords for files you have legitimate access to

**Unauthorized password cracking is illegal.** Always follow your organization's security policies and applicable laws.

## License

MIT License - See [LICENSE](LICENSE) for details.

## Contributing

Contributions welcome! Please open an issue or submit a pull request.

## Credits

- [John the Ripper](https://www.openwall.com/john/) by Openwall
- Built with the [Model Context Protocol SDK](https://github.com/modelcontextprotocol/sdk)
