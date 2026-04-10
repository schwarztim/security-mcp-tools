# PowerShell Empire MCP Server

A Model Context Protocol (MCP) server for interacting with [PowerShell Empire](https://github.com/BC-SECURITY/Empire), the post-exploitation framework maintained by BC-Security.

> **Note**: This tool is intended for authorized security testing, red team operations, and educational purposes only. Ensure you have proper authorization before using this tool against any systems.

## Features

This MCP server provides comprehensive access to Empire's REST API (v5+), enabling AI assistants to:

- **Listener Management**: Create, list, enable/disable, and delete listeners
- **Stager Generation**: Generate payloads using various templates (PowerShell, Python, C#, etc.)
- **Agent Control**: List agents, execute commands, upload/download files
- **Module Execution**: Search and run post-exploitation modules
- **Credential Management**: View and store harvested credentials
- **Plugin System**: Execute Empire plugins
- **C2 Profiles**: Access malleable C2 profiles for HTTP/S listeners

## Installation

```bash
# Clone the repository
git clone https://github.com/schwarztim/sec-powershell-empire-mcp.git
cd sec-powershell-empire-mcp

# Install dependencies
npm install

# Build
npm run build
```

## Configuration

Set the following environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `EMPIRE_URL` | Empire REST API URL | `http://localhost:1337` |
| `EMPIRE_USERNAME` | Empire username | `empireadmin` |
| `EMPIRE_PASSWORD` | Empire password | `password123` |

### Claude Desktop Configuration

Add to your Claude Desktop configuration (`~/.claude/user-mcps.json` or Claude Desktop settings):

```json
{
  "mcpServers": {
    "powershell-empire": {
      "command": "node",
      "args": ["/path/to/sec-powershell-empire-mcp/dist/index.js"],
      "env": {
        "EMPIRE_URL": "https://your-empire-server:1337",
        "EMPIRE_USERNAME": "your-username",
        "EMPIRE_PASSWORD": "your-password"
      }
    }
  }
}
```

## Available Tools

### empire_listeners
Manage Empire listeners - list, create, enable, disable, or delete listeners.

```
Actions: list, get, templates, create, delete, enable, disable
```

### empire_stagers
Generate and manage stagers/payloads for Empire agents.

```
Actions: list, templates, create, get, delete
```

### empire_agents
List and manage active Empire agents.

```
Actions: list, get, kill, rename, checkins, files, tasks
```

### empire_modules
Search and view Empire post-exploitation modules.

```
Actions: list, search, get, execute
```

### empire_shell
Execute shell commands on an Empire agent.

### empire_upload
Upload a file to an Empire agent.

### empire_download
Download a file from an Empire agent.

### empire_credentials
Manage harvested credentials in Empire.

```
Actions: list, create
```

### empire_hosts
List hosts that agents are running on.

### empire_downloads
List files downloaded from agents.

```
Actions: list, get
```

### empire_plugins
Manage Empire plugins.

```
Actions: list, execute
```

### empire_bypasses
List available AMSI/AV bypasses.

### empire_profiles
List malleable C2 profiles for HTTP listeners.

### empire_task_result
Get the result of a specific task.

## Usage Examples

### List Active Agents
```
Use empire_agents with action "list" to see all active agents.
```

### Execute a Shell Command
```
Use empire_shell with agent_id "ABC123" and command "whoami" to run a command on an agent.
```

### Generate a PowerShell Stager
```
Use empire_stagers with action "create", template "multi_launcher", name "test_stager",
and options including the Listener name.
```

### Search for Modules
```
Use empire_modules with action "search" and search term "mimikatz" to find credential dumping modules.
```

## Requirements

- Node.js 18+
- PowerShell Empire v5+ (BC-Security fork)
- Empire REST API enabled

## Security Considerations

- Store credentials securely; avoid hardcoding in configurations
- Use HTTPS for Empire API connections in production
- Limit API access to authorized networks only
- Follow your organization's security policies for red team tools

## License

MIT License - see [LICENSE](LICENSE) file.

## Disclaimer

This software is provided for authorized security testing and educational purposes only. Users are responsible for ensuring compliance with applicable laws and regulations. The authors assume no liability for misuse of this software.

## References

- [PowerShell Empire](https://github.com/BC-SECURITY/Empire)
- [Empire REST API Documentation](https://bc-security.gitbook.io/empire-wiki/restful-api)
- [Model Context Protocol](https://modelcontextprotocol.io/)
