# BloodHound MCP Server

A Model Context Protocol (MCP) server for [BloodHound Community Edition](https://github.com/SpecterOps/BloodHound) - the industry-standard tool for Active Directory attack path mapping and analysis.

## Overview

This MCP server enables AI assistants to interact with BloodHound CE, providing comprehensive access to Active Directory reconnaissance data, attack path analysis, and security posture assessment capabilities.

## Features

### Domain Operations
- List and inspect Active Directory domains
- View domain controllers and trust relationships
- Analyze Group Policy Objects (GPOs) and Organizational Units (OUs)

### Identity Analysis
- **Users**: List users, view admin rights, group memberships, and active sessions
- **Computers**: Enumerate computers, administrators, and sessions
- **Groups**: Inspect group membership and administrative privileges

### Attack Path Analysis
- Find shortest attack paths between any two nodes
- Execute custom Cypher queries against the graph database
- List and analyze pre-computed attack paths
- Start attack path analysis jobs

### High-Value Target Detection
- **Kerberoastable Users**: Find users with SPNs vulnerable to offline password cracking
- **AS-REP Roastable Users**: Identify users with Kerberos pre-authentication disabled
- **Unconstrained Delegation**: Locate computers that can impersonate any user
- **DCSync Rights**: Find principals capable of dumping domain credentials

### Data Quality
- Collection statistics and data quality metrics
- API version information

## Installation

```bash
# Clone the repository
git clone https://github.com/schwarztim/sec-bloodhound-mcp.git
cd sec-bloodhound-mcp

# Install dependencies
npm install

# Build the project
npm run build
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `BLOODHOUND_URL` | BloodHound CE API URL | `http://localhost:8080` |
| `BLOODHOUND_TOKEN_ID` | API token ID (required) | - |
| `BLOODHOUND_TOKEN_KEY` | API token key (required) | - |

### Creating API Tokens

1. Log into your BloodHound CE instance
2. Navigate to **Settings** > **API Tokens**
3. Create a new token and note the Token ID and Token Key
4. Set the environment variables before starting the MCP server

### Claude Desktop Configuration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "bloodhound": {
      "command": "node",
      "args": ["/path/to/sec-bloodhound-mcp/dist/index.js"],
      "env": {
        "BLOODHOUND_URL": "http://localhost:8080",
        "BLOODHOUND_TOKEN_ID": "your-token-id",
        "BLOODHOUND_TOKEN_KEY": "your-token-key"
      }
    }
  }
}
```

## Available Tools

### Domain Operations
| Tool | Description |
|------|-------------|
| `bloodhound_domains` | List all available AD domains |
| `bloodhound_domain_info` | Get detailed domain information |
| `bloodhound_domain_controllers` | List domain controllers |
| `bloodhound_trusts` | Get trust relationships |
| `bloodhound_gpos` | List Group Policy Objects |
| `bloodhound_ous` | List Organizational Units |

### User Operations
| Tool | Description |
|------|-------------|
| `bloodhound_users` | List domain users (paginated) |
| `bloodhound_user_info` | Get user details |
| `bloodhound_user_admin_rights` | Systems where user has admin |
| `bloodhound_user_memberships` | User's group memberships |
| `bloodhound_user_sessions` | User's active sessions |

### Computer Operations
| Tool | Description |
|------|-------------|
| `bloodhound_computers` | List domain computers (paginated) |
| `bloodhound_computer_info` | Get computer details |
| `bloodhound_computer_admins` | Computer's administrators |
| `bloodhound_computer_sessions` | Active sessions on computer |

### Group Operations
| Tool | Description |
|------|-------------|
| `bloodhound_groups` | List domain groups (paginated) |
| `bloodhound_group_info` | Get group details |
| `bloodhound_group_members` | Group membership |
| `bloodhound_group_admin_rights` | Admin rights held by group |

### Search & Graph
| Tool | Description |
|------|-------------|
| `bloodhound_search` | Search objects by name/ID |
| `bloodhound_path` | Find shortest attack path |
| `bloodhound_cypher` | Execute custom Cypher queries |

### Attack Paths
| Tool | Description |
|------|-------------|
| `bloodhound_attack_paths` | List attack path types |
| `bloodhound_domain_attack_paths` | Domain-specific attack paths |
| `bloodhound_findings` | Attack path findings |
| `bloodhound_analyze` | Start analysis job |
| `bloodhound_dcsyncers` | Principals with DCSync rights |

### Vulnerability Detection
| Tool | Description |
|------|-------------|
| `bloodhound_kerberoastable` | Find Kerberoastable users |
| `bloodhound_asreproastable` | Find AS-REP Roastable users |
| `bloodhound_unconstrained_delegation` | Find unconstrained delegation |

### System
| Tool | Description |
|------|-------------|
| `bloodhound_data_quality` | Collection quality stats |
| `bloodhound_version` | API version info |

## Example Usage

### Find Attack Path to Domain Admins

```
Use bloodhound_path with:
- start_node: "JSMITH@CONTOSO.LOCAL"
- end_node: "DOMAIN ADMINS@CONTOSO.LOCAL"
```

### Find All Kerberoastable Users

```
Use bloodhound_kerberoastable with:
- domain_id: "S-1-5-21-..."
```

### Custom Cypher Query

```
Use bloodhound_cypher with:
- query: "MATCH (u:User)-[r:MemberOf*1..]->(g:Group) WHERE g.name = 'DOMAIN ADMINS@CONTOSO.LOCAL' RETURN u.name"
```

## Authentication

This MCP server implements BloodHound CE's HMAC-SHA256 signed request authentication:

1. **Operation Key**: `HMAC(tokenKey, method + uri)` - Prevents method/URI modification
2. **Date Key**: `HMAC(operationKey, datetime)` - Prevents replay attacks
3. **Signature**: `HMAC(dateKey, body)` - Prevents payload tampering

All requests include the `Authorization`, `RequestDate`, and `Signature` headers.

## Security Considerations

- **API tokens should be treated as secrets** - Never commit them to version control
- **Use environment variables** for credential management
- **Network security** - BloodHound typically runs on internal networks; ensure appropriate access controls
- **Audit logging** - BloodHound logs all API access; monitor for unauthorized usage

## Requirements

- Node.js 18+
- BloodHound Community Edition 5.x+
- Valid API token with appropriate permissions

## License

MIT License - See [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request.

## Related Projects

- [BloodHound CE](https://github.com/SpecterOps/BloodHound) - The BloodHound application
- [SharpHound](https://github.com/BloodHoundAD/SharpHound) - BloodHound data collector
- [Model Context Protocol](https://modelcontextprotocol.io/) - MCP specification

## Disclaimer

This tool is intended for authorized security testing and research only. Always obtain proper authorization before conducting security assessments. The authors are not responsible for misuse of this software.
