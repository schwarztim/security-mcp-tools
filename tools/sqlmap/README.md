# sqlmap MCP Server

A Model Context Protocol (MCP) server that provides programmatic access to [sqlmap](https://sqlmap.org/), the powerful automatic SQL injection and database takeover tool.

## Overview

This MCP server wraps sqlmap's REST API, enabling AI assistants and automation tools to perform SQL injection testing through a standardized interface. It provides both low-level control over sqlmap tasks and convenient high-level tools for common operations.

**Important:** This tool is intended for authorized security testing only. Always obtain proper authorization before testing any systems.

## Features

- **Task Management** - Create, configure, and delete sqlmap scanning tasks
- **Scan Control** - Start, stop, and monitor SQL injection scans
- **Database Enumeration** - Discover databases, tables, columns, and dump data
- **OS Interaction** - Execute operating system commands via SQL injection (when conditions allow)
- **Convenience Tools** - High-level tools that handle the full scan workflow automatically
- **Flexible Configuration** - Support for all sqlmap options including level, risk, techniques, and more

## Prerequisites

- Node.js 18+
- sqlmap with REST API server running (`sqlmapapi.py -s`)

### Starting the sqlmap API Server

```bash
# From your sqlmap installation directory
python sqlmapapi.py -s

# Or with custom host/port
python sqlmapapi.py -s -H 0.0.0.0 -p 8775

# With basic authentication
python sqlmapapi.py -s --username admin --password secret
```

## Installation

```bash
# Clone the repository
git clone https://github.com/schwarztim/sec-sqlmap-mcp.git
cd sec-sqlmap-mcp

# Install dependencies
npm install

# Build
npm run build
```

## Configuration

Configure via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `SQLMAP_API_HOST` | `127.0.0.1` | sqlmap API server host |
| `SQLMAP_API_PORT` | `8775` | sqlmap API server port |
| `SQLMAP_API_USERNAME` | (none) | Basic auth username (optional) |
| `SQLMAP_API_PASSWORD` | (none) | Basic auth password (optional) |

## Usage with Claude Desktop

Add to your Claude Desktop configuration (`~/.claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "sqlmap": {
      "command": "node",
      "args": ["/path/to/sec-sqlmap-mcp/dist/index.js"],
      "env": {
        "SQLMAP_API_HOST": "127.0.0.1",
        "SQLMAP_API_PORT": "8775"
      }
    }
  }
}
```

## Available Tools

### Core Task Management

| Tool | Description |
|------|-------------|
| `sqlmap_new_task` | Create a new scanning task |
| `sqlmap_delete_task` | Delete an existing task |
| `sqlmap_set_options` | Configure task options |
| `sqlmap_get_options` | Retrieve current options |
| `sqlmap_list_options` | List all available options |

### Scan Control

| Tool | Description |
|------|-------------|
| `sqlmap_start_scan` | Start a configured scan |
| `sqlmap_scan_status` | Check scan status |
| `sqlmap_scan_data` | Get scan results |
| `sqlmap_scan_log` | Get scan log messages |
| `sqlmap_stop_scan` | Stop a scan gracefully |
| `sqlmap_kill_scan` | Force terminate a scan |

### Convenience Tools (Recommended)

These tools handle the complete workflow automatically:

| Tool | Description |
|------|-------------|
| `sqlmap_enumerate_dbs` | Discover all databases |
| `sqlmap_enumerate_tables` | List tables in a database |
| `sqlmap_enumerate_columns` | List columns in a table |
| `sqlmap_dump_table` | Extract data from a table |
| `sqlmap_os_shell` | Attempt to get OS shell access |
| `sqlmap_os_cmd` | Execute an OS command |

### Utility

| Tool | Description |
|------|-------------|
| `sqlmap_check_connection` | Verify API server connectivity |
| `sqlmap_version` | Get sqlmap version info |

## Example Usage

### Enumerate Databases

```javascript
// Using the convenience tool
sqlmap_enumerate_dbs({
  url: "http://target.com/page?id=1",
  level: 3,
  risk: 2
})
```

### Manual Workflow

```javascript
// 1. Create task
const { taskid } = await sqlmap_new_task()

// 2. Configure options
await sqlmap_set_options({
  taskId: taskid,
  options: {
    url: "http://target.com/page?id=1",
    level: 3,
    risk: 2,
    dbs: true,
    batch: true
  }
})

// 3. Start scan
await sqlmap_start_scan({ taskId: taskid })

// 4. Monitor status
const status = await sqlmap_scan_status({ taskId: taskid })

// 5. Get results when complete
const results = await sqlmap_scan_data({ taskId: taskid })

// 6. Cleanup
await sqlmap_delete_task({ taskId: taskid })
```

### Dump Specific Data

```javascript
// Dump usernames and passwords from users table
sqlmap_dump_table({
  url: "http://target.com/page?id=1",
  database: "webapp",
  table: "users",
  columns: "username,password",
  level: 2,
  risk: 1
})
```

## Common Options

| Option | Description |
|--------|-------------|
| `url` | Target URL with injectable parameter |
| `data` | POST data (e.g., `username=admin&password=test`) |
| `cookie` | HTTP Cookie header value |
| `level` | Level of tests (1-5, higher = more thorough) |
| `risk` | Risk of tests (1-3, higher = more aggressive) |
| `technique` | Injection techniques: B(oolean), E(rror), U(nion), S(tacked), T(ime), Q(inline) |
| `dbms` | Force specific DBMS (MySQL, PostgreSQL, MSSQL, Oracle, etc.) |
| `threads` | Number of concurrent threads |

## Security Considerations

- **Authorization Required** - Only test systems you have explicit permission to test
- **Network Isolation** - Run in isolated environments when possible
- **Audit Logging** - All scan activities are logged
- **Credential Protection** - Use environment variables for sensitive configuration

## License

MIT License - see [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please feel free to submit issues and pull requests.

## Related Projects

- [sqlmap](https://sqlmap.org/) - The underlying SQL injection tool
- [Model Context Protocol](https://modelcontextprotocol.io/) - The MCP specification
