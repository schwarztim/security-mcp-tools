# Mimikatz MCP Server

A Model Context Protocol (MCP) server that provides programmatic access to [Mimikatz](https://github.com/gentilkiwi/mimikatz), the powerful credential extraction and security assessment tool for Windows systems.

> **WARNING**: This tool is intended for **authorized security testing only**. Unauthorized use of Mimikatz may be illegal and unethical. Always ensure you have proper authorization before using this tool.

## Features

- **Credential Extraction**: Extract plaintext passwords, NTLM hashes, Kerberos tickets from memory
- **SAM/LSA Dumping**: Dump local SAM database and LSA secrets
- **DCSync Attacks**: Replicate Active Directory credentials
- **Kerberos Attacks**: Create Golden/Silver tickets, Pass-the-Ticket
- **DPAPI Decryption**: Decrypt Windows Data Protection API master keys
- **Certificate Export**: Export certificates with private keys
- **Token Manipulation**: Elevate privileges and impersonate users

## Installation

### Prerequisites

- Node.js 18+
- Mimikatz binary (see [Setup](#mimikatz-setup))
- Windows (native) or Linux with Wine (for Kali Linux)

### Quick Start

```bash
# Clone the repository
git clone https://github.com/schwarztim/sec-mimikatz-mcp.git
cd sec-mimikatz-mcp

# Install dependencies
npm install

# Build
npm run build
```

### Mimikatz Setup

#### Windows

Download Mimikatz from the [official repository](https://github.com/gentilkiwi/mimikatz/releases) and place it in one of these locations:

- `C:\tools\mimikatz\x64\mimikatz.exe`
- `C:\mimikatz\x64\mimikatz.exe`
- `%USERPROFILE%\mimikatz\x64\mimikatz.exe`

Or set the `MIMIKATZ_PATH` environment variable.

#### Kali Linux

Mimikatz is typically pre-installed:

```bash
# Check if mimikatz is available
locate mimikatz.exe

# Common paths on Kali:
# /usr/share/windows-resources/mimikatz/x64/mimikatz.exe
# /usr/share/mimikatz/x64/mimikatz.exe
```

## Usage

### Claude Desktop Configuration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "mimikatz": {
      "command": "node",
      "args": ["/path/to/sec-mimikatz-mcp/dist/index.js"],
      "env": {
        "MIMIKATZ_PATH": "/path/to/mimikatz.exe"
      }
    }
  }
}
```

### MCP Configuration (user-mcps.json)

```json
{
  "mimikatz": {
    "command": "node",
    "args": ["/path/to/sec-mimikatz-mcp/dist/index.js"],
    "env": {
      "MIMIKATZ_PATH": "/usr/share/windows-resources/mimikatz/x64/mimikatz.exe"
    }
  }
}
```

## Available Tools

### Status and Information

| Tool | Description |
|------|-------------|
| `mimikatz_status` | Check Mimikatz installation status and system compatibility |

### Credential Extraction (sekurlsa)

| Tool | Description |
|------|-------------|
| `mimikatz_sekurlsa_logonpasswords` | Extract plaintext passwords, hashes, PIN codes, and Kerberos tickets |
| `mimikatz_sekurlsa_wdigest` | Extract WDigest credentials from LSASS |
| `mimikatz_sekurlsa_kerberos` | List Kerberos credentials and tickets |
| `mimikatz_sekurlsa_msv` | Extract NTLM hashes (MSV1_0 credentials) |

### LSA/SAM Dumping

| Tool | Description |
|------|-------------|
| `mimikatz_lsadump_sam` | Dump SAM database hashes (local accounts) |
| `mimikatz_lsadump_secrets` | Dump LSA secrets (service account credentials) |
| `mimikatz_lsadump_dcsync` | DCSync attack to replicate AD credentials |

### Kerberos Attacks

| Tool | Description |
|------|-------------|
| `mimikatz_kerberos_golden` | Create Golden Ticket for persistent domain access |
| `mimikatz_kerberos_silver` | Create Silver Ticket for service-specific access |
| `mimikatz_kerberos_ptt` | Pass-the-Ticket: Import a Kerberos ticket |
| `mimikatz_kerberos_list` | List Kerberos tickets in current session |
| `mimikatz_kerberos_purge` | Purge all Kerberos tickets |

### Additional Tools

| Tool | Description |
|------|-------------|
| `mimikatz_vault_cred` | Dump Windows Vault credentials (saved passwords) |
| `mimikatz_dpapi_masterkey` | Decrypt DPAPI master keys |
| `mimikatz_crypto_certificates` | Export certificates with private keys |
| `mimikatz_token_elevate` | Elevate to SYSTEM or impersonate users |
| `mimikatz_privilege_debug` | Enable SeDebugPrivilege |
| `mimikatz_process_list` | List running processes with security context |
| `mimikatz_misc_cmd` | Spawn command prompt with elevated context |
| `mimikatz_custom` | Execute custom Mimikatz commands |

## Examples

### Check Installation Status

```
Tool: mimikatz_status
```

### Extract Logon Passwords

```
Tool: mimikatz_sekurlsa_logonpasswords
```

### DCSync Attack

```
Tool: mimikatz_lsadump_dcsync
Arguments:
  domain: "corp.example.com"
  user: "Administrator"
```

### Create Golden Ticket

```
Tool: mimikatz_kerberos_golden
Arguments:
  domain: "corp.example.com"
  sid: "S-1-5-21-..."
  krbtgt_hash: "aad3b435b51404eeaad3b435b51404ee"
  user: "FakeAdmin"
```

### Custom Commands

```
Tool: mimikatz_custom
Arguments:
  commands: ["privilege::debug", "sekurlsa::logonpasswords", "exit"]
```

## Security Considerations

1. **Authorization**: Only use on systems you own or have explicit permission to test
2. **Privilege Requirements**: Most tools require administrative/SYSTEM privileges
3. **Detection**: Mimikatz is detected by most antivirus/EDR solutions
4. **Audit Logs**: Actions may be logged by Windows Event Log and SIEM systems
5. **Legal Compliance**: Ensure compliance with all applicable laws and regulations

## Environment Variables

| Variable | Description |
|----------|-------------|
| `MIMIKATZ_PATH` | Full path to mimikatz.exe binary |

## Troubleshooting

### Mimikatz Not Found

Set the `MIMIKATZ_PATH` environment variable to the full path of your mimikatz.exe binary.

### Permission Denied

Run with elevated privileges (Administrator on Windows, root on Linux).

### Wine Issues on Linux

Ensure Wine is properly installed and configured:

```bash
sudo apt install wine64
wine --version
```

## Development

```bash
# Install dependencies
npm install

# Development mode (with hot reload)
npm run dev

# Build
npm run build

# Run
npm start
```

## License

MIT License - see [LICENSE](LICENSE)

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this tool. Always obtain proper authorization before conducting security assessments.

## References

- [Mimikatz GitHub](https://github.com/gentilkiwi/mimikatz)
- [Mimikatz Wiki](https://github.com/gentilkiwi/mimikatz/wiki)
- [Model Context Protocol](https://modelcontextprotocol.io/)
