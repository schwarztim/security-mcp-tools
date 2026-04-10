# Hydra MCP Server

A Model Context Protocol (MCP) server that provides AI assistants with controlled access to [THC-Hydra](https://github.com/vanhauser-thc/thc-hydra), the fast and flexible network login cracker. Designed for authorized penetration testing and security assessments.

## Overview

This MCP server enables AI assistants to orchestrate password security testing through THC-Hydra on a remote Kali Linux system via SSH. It provides structured tools for brute-force attacks, HTTP form testing, and session management.

**Important:** This tool is intended exclusively for authorized security testing. Unauthorized access attempts are illegal and unethical.

## Features

- **Multi-Protocol Support** - 60+ protocols including SSH, FTP, RDP, HTTP forms, databases, and more
- **HTTP Form Attacks** - Specialized support for web application login testing
- **Remote Execution** - Runs Hydra commands on Kali Linux via SSH
- **Session Management** - Save, restore, and monitor attack sessions
- **Wordlist Integration** - Access to common Kali Linux wordlists
- **Command Generation** - Preview commands before execution

## Prerequisites

- Node.js 18+
- SSH access to a Kali Linux system with THC-Hydra installed
- SSH key-based authentication configured (recommended)

## Installation

```bash
# Clone the repository
git clone https://github.com/schwarztim/sec-hydra-mcp.git
cd sec-hydra-mcp

# Install dependencies
npm install

# Build
npm run build
```

## Configuration

Set environment variables for your Kali Linux connection:

```bash
export KALI_HOST="kali"      # Hostname or IP of your Kali system
export KALI_USER="kali"      # SSH username
```

Ensure SSH key authentication is configured:

```bash
ssh-copy-id kali@your-kali-host
```

### MCP Client Configuration

Add to your Claude Desktop or MCP client configuration:

```json
{
  "mcpServers": {
    "hydra": {
      "command": "node",
      "args": ["/path/to/sec-hydra-mcp/dist/index.js"],
      "env": {
        "KALI_HOST": "your-kali-host",
        "KALI_USER": "kali"
      }
    }
  }
}
```

## Available Tools

### hydra_attack

Execute a brute-force attack against a target service.

```typescript
{
  target: "192.168.1.100",
  protocol: "ssh",
  username: "admin",
  password_file: "/usr/share/wordlists/rockyou.txt",
  tasks: 4,
  exit_on_first: true
}
```

### hydra_http_form

Specialized tool for attacking HTTP/HTTPS form-based authentication.

```typescript
{
  target: "example.com",
  path: "/login.php",
  form_data: "username=^USER^&password=^PASS^",
  failure_string: "Invalid credentials",
  username_file: "/usr/share/wordlists/top-usernames-shortlist.txt",
  password_file: "/usr/share/wordlists/fasttrack.txt",
  ssl: true
}
```

### hydra_protocols

List all 60+ supported protocols with descriptions.

### hydra_wordlists

List common wordlists available on Kali Linux, optionally verifying their existence.

### hydra_status

Check if Hydra is currently running and view process information.

### hydra_stop

Stop running Hydra processes (supports graceful and forced termination).

### hydra_restore

Resume a previous attack session from a restore file.

### hydra_version

Display Hydra version and build information.

### hydra_module_help

Get detailed help for a specific protocol module.

### hydra_generate_command

Generate a Hydra command without executing it for review.

## Supported Protocols

<details>
<summary>Click to expand full protocol list</summary>

| Category | Protocols |
|----------|-----------|
| Remote Access | ssh, rdp, vnc, telnet, rlogin, rsh, rexec |
| File Transfer | ftp, ftps, svn, afp, ncp |
| Web | http-form-get, http-form-post, http-get, http-post, https-form-get, https-form-post, http-proxy |
| Mail | smtp, smtps, pop3, pop3s, imap, imaps, nntp |
| Databases | mysql, postgres, mssql, oracle, oracle-listener, oracle-sid, mongodb, redis, memcached, firebird |
| Directory | ldap2, ldap3, ldap3-crammd5, ldap3-digestmd5 |
| Network | snmp, socks5, sip, cisco, cisco-enable, s7-300, pcnfs, rpcap |
| Other | smb, icq, irc, xmpp, teamspeak, vmauthd, cvs, radmin2, asterisk, pcanywhere, rtsp, sap-r3, sshkey |

</details>

## Common Wordlists

| Name | Path |
|------|------|
| RockYou | `/usr/share/wordlists/rockyou.txt` |
| Unix Users | `/usr/share/wordlists/metasploit/unix_users.txt` |
| Unix Passwords | `/usr/share/wordlists/metasploit/unix_passwords.txt` |
| FastTrack | `/usr/share/wordlists/fasttrack.txt` |
| Top Usernames | `/usr/share/seclists/Usernames/top-usernames-shortlist.txt` |
| Default Credentials | `/usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt` |

## Security Considerations

1. **Authorization** - Only use against systems you own or have explicit written permission to test
2. **Network Isolation** - Run tests in isolated lab environments when possible
3. **Logging** - All commands are logged; maintain audit trails
4. **Rate Limiting** - Use appropriate thread counts to avoid DoS conditions
5. **Legal Compliance** - Ensure compliance with local laws and regulations

## Example Usage

### Testing SSH with a Single Credential

```typescript
await hydra_attack({
  target: "192.168.1.100",
  protocol: "ssh",
  username: "root",
  password: "toor",
  tasks: 4
});
```

### Dictionary Attack on FTP

```typescript
await hydra_attack({
  target: "ftp.example.com",
  protocol: "ftp",
  username_file: "/usr/share/wordlists/metasploit/unix_users.txt",
  password_file: "/usr/share/wordlists/fasttrack.txt",
  tasks: 16,
  exit_on_first: true
});
```

### Web Form Authentication Test

```typescript
await hydra_http_form({
  target: "webapp.local",
  path: "/login",
  form_data: "user=^USER^&pass=^PASS^&submit=Login",
  failure_string: "Invalid username or password",
  username: "admin",
  password_file: "/usr/share/wordlists/rockyou.txt",
  ssl: true
});
```

## Development

```bash
# Run in development mode with auto-rebuild
npm run dev

# Build for production
npm run build

# Start the server
npm start
```

## License

MIT License - See [LICENSE](LICENSE) for details.

## Disclaimer

This tool is provided for authorized security testing and educational purposes only. The authors are not responsible for misuse or damage caused by this software. Always obtain proper authorization before testing any systems.

## Related Projects

- [THC-Hydra](https://github.com/vanhauser-thc/thc-hydra) - The underlying brute-force tool
- [Model Context Protocol](https://modelcontextprotocol.io/) - The MCP specification
- [SecLists](https://github.com/danielmiessler/SecLists) - Collection of security testing wordlists
