# ldapdomaindump MCP Server

A Model Context Protocol (MCP) server that provides AI assistants with access to [ldapdomaindump](https://github.com/dirkjanm/ldapdomaindump), a powerful Active Directory LDAP enumeration tool commonly used in penetration testing and security assessments.

## Overview

This MCP server enables AI assistants to perform Active Directory reconnaissance by enumerating:

- **Domain Users** - Account names, descriptions, last logon times, password expiry, account status
- **Domain Groups** - Group memberships, descriptions, nested groups
- **Domain Computers** - Computer accounts, operating systems, DNS hostnames
- **Domain Trusts** - Trust relationships, directions, and types
- **Password Policies** - Lockout thresholds, password requirements, fine-grained policies

## Architecture

The server executes commands on a remote Kali Linux host via SSH, making it ideal for setups where the AI assistant runs on a different machine than the pentesting environment.

```
┌─────────────┐      SSH      ┌─────────────┐      LDAP      ┌─────────────┐
│  MCP Host   │ ────────────> │    Kali     │ ─────────────> │   Domain    │
│  (Claude)   │               │   Linux     │                │ Controller  │
└─────────────┘               └─────────────┘                └─────────────┘
```

## Prerequisites

1. **Kali Linux host** with SSH access configured
2. **ldapdomaindump** installed on Kali:
   ```bash
   pip install ldapdomaindump
   ```
3. **SSH key-based authentication** to the Kali host
4. **Node.js 18+** on the MCP host

## Installation

```bash
git clone https://github.com/schwarztim/sec-ldapdomaindump-mcp.git
cd sec-ldapdomaindump-mcp
npm install
npm run build
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `KALI_HOST` | SSH hostname or alias for Kali | `kali` |
| `LDAP_OUTPUT_DIR` | Directory on Kali for output files | `/tmp/ldapdomaindump` |

### SSH Setup

Ensure you have SSH key-based access to your Kali host:

```bash
# Add to ~/.ssh/config
Host kali
    HostName 192.168.1.100
    User root
    IdentityFile ~/.ssh/kali_key
```

### Claude Desktop Configuration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "ldapdomaindump": {
      "command": "node",
      "args": ["/path/to/sec-ldapdomaindump-mcp/dist/index.js"],
      "env": {
        "KALI_HOST": "kali",
        "LDAP_OUTPUT_DIR": "/tmp/ldapdomaindump"
      }
    }
  }
}
```

## Available Tools

### `ldapdomaindump_dump`
Perform a full LDAP domain dump - enumerates all objects and outputs HTML, JSON, and greppable files.

### `ldapdomaindump_users`
Enumerate domain users with attributes like SAM account name, display name, last logon, and account status.

### `ldapdomaindump_groups`
Enumerate domain groups and their memberships.

### `ldapdomaindump_computers`
Enumerate domain computers with OS information and DNS hostnames.

### `ldapdomaindump_trusts`
Enumerate domain trust relationships.

### `ldapdomaindump_policies`
Get domain password policies including lockout thresholds and complexity requirements.

### `ldapdomaindump_read_output`
Read previously generated output files from the Kali host.

### `ldapdomaindump_ldd2pretty`
Convert JSON output to enum4linux-like readable format using ldd2pretty.

### `ldapdomaindump_check`
Verify ldapdomaindump installation and SSH connectivity.

## Usage Examples

### Full Domain Dump
```
Use ldapdomaindump_dump with:
- hostname: 10.10.10.1
- username: CORP\jsmith
- password: Password123
```

### Enumerate Users Only
```
Use ldapdomaindump_users with:
- hostname: dc01.corp.local
- username: CORP\enumuser
- password: EnumPass!
- useSsl: true
```

### Pass-the-Hash Authentication
```
Use ldapdomaindump_dump with:
- hostname: 10.10.10.1
- username: CORP\administrator
- password: aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
- authType: NTLM
```

## Output Files

ldapdomaindump generates several output files:

| File | Description |
|------|-------------|
| `domain_users.json` | All user accounts |
| `domain_groups.json` | All groups and memberships |
| `domain_computers.json` | All computer accounts |
| `domain_trusts.json` | Domain trust relationships |
| `domain_policy.json` | Password and lockout policies |
| `domain_users_by_group.json` | Users organized by group (with `--grouped-json`) |
| `domain_computers_by_os.json` | Computers organized by OS (with `--grouped-json`) |

## Security Considerations

- This tool is intended for **authorized security assessments only**
- Credentials are passed via command-line arguments - ensure your Kali host is secure
- Output files may contain sensitive information - clean up after assessments
- Large domains may cause high load on domain controllers when using DNS resolution

## Troubleshooting

### SSH Connection Failed
```bash
# Test SSH connectivity
ssh kali "echo 'Connected'"

# Verify ldapdomaindump is installed
ssh kali "which ldapdomaindump"
```

### Authentication Errors
- Verify username format: `DOMAIN\username` or `username@domain.local`
- Check password/hash format for NTLM authentication
- Try SIMPLE auth type if NTLM fails

### No Output Files
- Check if the output directory exists and is writable
- Verify LDAP connectivity from Kali to the domain controller
- Review stderr for authentication or network errors

## Related Tools

- [ldapdomaindump](https://github.com/dirkjanm/ldapdomaindump) - The underlying Python tool
- [BloodHound](https://github.com/BloodHoundAD/BloodHound) - AD attack path analysis
- [ldd2bloodhound](https://github.com/dirkjanm/ldapdomaindump) - Convert output to BloodHound format

## License

MIT License - See [LICENSE](LICENSE) for details.

## Disclaimer

This tool is provided for educational and authorized security testing purposes only. Users are responsible for ensuring they have proper authorization before using this tool against any systems. Unauthorized access to computer systems is illegal.
