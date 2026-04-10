# Recon-ng MCP Server

[![MCP](https://img.shields.io/badge/MCP-Compatible-blue)](https://modelcontextprotocol.io)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.3-blue)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Recon-ng](https://img.shields.io/badge/recon--ng-OSINT-green)](https://github.com/lanmaster53/recon-ng)

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io) server that provides AI assistants with access to [recon-ng](https://github.com/lanmaster53/recon-ng), the powerful open-source reconnaissance framework. Execute OSINT operations, manage workspaces, run modules, and query reconnaissance data through natural language interactions.

## Features

- **Workspace Management** - Create, load, list, and remove workspaces for organizing reconnaissance projects
- **Module Operations** - Search, install, and execute recon-ng modules from the marketplace
- **Database Queries** - Query the SQLite database, view schemas, and run custom SQL
- **Target Management** - Add and remove domains, hosts, contacts, credentials, and other target types
- **Reporting** - Generate reports in HTML, CSV, JSON, XLSX, and XML formats
- **API Key Management** - Configure API keys for external services (Shodan, VirusTotal, etc.)
- **Snapshots** - Save and restore database states for workflow checkpoints
- **Remote Execution** - Connects via SSH to a Kali Linux system running recon-ng

## Prerequisites

- Node.js 18+
- A remote system (e.g., Kali Linux) with recon-ng installed
- SSH access to the remote system (key-based or password authentication)

## Installation

```bash
git clone https://github.com/schwarztim/sec-recon-ng-mcp.git
cd sec-recon-ng-mcp
npm install
npm run build
```

## Configuration

Configure the MCP server using environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `RECONNG_SSH_HOST` | SSH hostname or IP of the recon-ng system | `kali` |
| `RECONNG_SSH_PORT` | SSH port | `22` |
| `RECONNG_SSH_USER` | SSH username | `kali` |
| `RECONNG_SSH_KEY_PATH` | Path to SSH private key | `~/.ssh/id_rsa` |
| `RECONNG_SSH_PASSWORD` | SSH password (alternative to key auth) | - |
| `RECONNG_PATH` | Path to recon-ng binary on remote system | `recon-ng` |
| `RECONNG_TIMEOUT` | Command timeout in milliseconds | `60000` |

### Claude Desktop Configuration

Add to your Claude Desktop configuration (`~/.config/claude/claude_desktop_config.json` on Linux or `~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "recon-ng": {
      "command": "node",
      "args": ["/path/to/sec-recon-ng-mcp/dist/index.js"],
      "env": {
        "RECONNG_SSH_HOST": "your-kali-host",
        "RECONNG_SSH_USER": "kali",
        "RECONNG_SSH_KEY_PATH": "/path/to/.ssh/id_rsa"
      }
    }
  }
}
```

## Available Tools

### `reconng_workspaces`
Manage workspaces for organizing reconnaissance projects.

**Actions:** `list`, `create`, `load`, `remove`

### `reconng_modules`
Search, inspect, and install modules from the recon-ng marketplace.

**Actions:** `list`, `search`, `info`, `install`

### `reconng_run`
Execute reconnaissance modules with configurable options and sources.

### `reconng_db`
Query the recon-ng database.

**Actions:** `schema`, `query`, `show`

**Tables:** domains, hosts, contacts, credentials, leaks, netblocks, ports, profiles, pushpins, repositories, vulnerabilities, companies, locations

### `reconng_add`
Add targets to the database (domains, hosts, companies, contacts, etc.).

### `reconng_delete`
Remove records from the database.

### `reconng_report`
Generate reports from collected data.

**Formats:** HTML, CSV, JSON, XLSX, XML, list, pushpin

### `reconng_keys`
Manage API keys for external services.

**Actions:** `list`, `add`, `remove`

### `reconng_snapshots`
Save and restore database states.

**Actions:** `list`, `take`, `load`, `remove`

### `reconng_raw`
Execute raw recon-ng commands for advanced operations.

### `reconng_status`
Check recon-ng installation status and system information.

## Usage Examples

### Create a workspace and add targets

```
Create a workspace called "acme-corp" and add the domain acme.com
```

### Run reconnaissance modules

```
Search for available DNS modules in recon-ng
```

```
Run the hackertarget module against acme.com in the acme-corp workspace
```

### Query results

```
Show all discovered hosts in the acme-corp workspace
```

```
Generate an HTML report of all findings in the acme-corp workspace
```

### Manage API keys

```
Add my Shodan API key to recon-ng
```

## Security Considerations

- This server executes commands on a remote system via SSH
- Ensure SSH keys are properly secured with appropriate permissions
- Use dedicated reconnaissance systems isolated from production networks
- Follow responsible disclosure practices for any vulnerabilities discovered
- Comply with all applicable laws and regulations regarding security testing

## Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│  AI Assistant   │────▶│  MCP Server     │────▶│  Kali Linux     │
│  (Claude, etc.) │     │  (Node.js)      │ SSH │  (recon-ng)     │
└─────────────────┘     └─────────────────┘     └─────────────────┘
```

## Development

```bash
# Install dependencies
npm install

# Build TypeScript
npm run build

# Run in development mode
npm run dev
```

## Related Projects

- [recon-ng](https://github.com/lanmaster53/recon-ng) - The recon-ng framework
- [Model Context Protocol](https://modelcontextprotocol.io) - MCP specification
- [@modelcontextprotocol/sdk](https://www.npmjs.com/package/@modelcontextprotocol/sdk) - MCP TypeScript SDK

## License

MIT License - see [LICENSE](LICENSE) for details.

## Disclaimer

This tool is provided for authorized security testing and research purposes only. Users are responsible for ensuring they have proper authorization before conducting any reconnaissance activities. The authors are not responsible for any misuse of this software.
