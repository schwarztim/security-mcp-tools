# Maltego MCP Server

A [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) server that provides programmatic access to [Maltego](https://www.maltego.com/) transforms, entity management, graph operations, and machine automation for OSINT visualization and investigation workflows.

## Features

- **Transform Management** - List, execute, and configure Maltego transforms
- **Entity Operations** - Create, validate, and search entities with type-safe handling
- **Graph Export/Import** - Export investigation graphs to GraphML, CSV, JSON, or MTGX formats
- **Machine Automation** - Run predefined transform sequences (machines) for automated reconnaissance
- **TDS Integration** - Connect to Transform Distribution Server for remote/custom transforms
- **Built-in Transforms** - 15+ standard transforms work offline without TDS

## Installation

### Prerequisites

- Node.js 18+
- npm or yarn

### Quick Start

```bash
# Clone the repository
git clone https://github.com/schwarztim/sec-maltego-mcp.git
cd sec-maltego-mcp

# Install dependencies
npm install

# Build
npm run build

# Run
npm start
```

### Claude Desktop Configuration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "maltego": {
      "command": "node",
      "args": ["/path/to/sec-maltego-mcp/dist/index.js"],
      "env": {
        "MALTEGO_TDS_URL": "http://localhost:8081",
        "MALTEGO_TRANSFORM_SERVER_URL": "http://localhost:8080"
      }
    }
  }
}
```

## Configuration

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| `MALTEGO_TDS_URL` | Transform Distribution Server URL | `http://localhost:8081` |
| `MALTEGO_TRANSFORM_SERVER_URL` | Transform Server URL | `http://localhost:8080` |
| `MALTEGO_API_KEY` | API key for authenticated transforms | (none) |
| `MALTEGO_GRAPH_EXPORT_PATH` | Directory for graph exports | `/tmp/maltego-exports` |

## Available Tools

### Transform Operations

| Tool | Description |
|------|-------------|
| `maltego_list_transforms` | List available transforms with optional category/entity type filtering |
| `maltego_run_transform` | Execute a transform on an entity |
| `maltego_get_transform_settings` | Get configuration options for a specific transform |

### Entity Operations

| Tool | Description |
|------|-------------|
| `maltego_list_entities` | List available entity types |
| `maltego_create_entity` | Create a new entity with type, value, and properties |
| `maltego_validate_entity` | Validate entity value against type constraints |
| `maltego_search_entities` | Search entities in the current session |

### Graph Operations

| Tool | Description |
|------|-------------|
| `maltego_export_graph` | Export entities and links to GraphML, CSV, JSON, or MTGX |
| `maltego_import_data` | Import data and convert to Maltego entities |

### Machine Operations

| Tool | Description |
|------|-------------|
| `maltego_run_machine` | Run automated transform sequences |

### Status

| Tool | Description |
|------|-------------|
| `maltego_tds_status` | Check TDS connectivity and available transforms |

## Built-in Transforms

These transforms work without a TDS connection:

| Transform | Input | Output | Description |
|-----------|-------|--------|-------------|
| `DNSToIP` | DNSName | IPv4/IPv6Address | DNS resolution |
| `IPToDNS` | IPv4Address | DNSName | Reverse DNS lookup |
| `DomainToMXRecords` | Domain | MXRecord | Mail exchange lookup |
| `DomainToNSRecords` | Domain | NSRecord | Name server lookup |
| `DomainToWebsite` | Domain | Website | Find websites on domain |
| `EmailToAlias` | EmailAddress | Alias | Extract username |
| `EmailToDomain` | EmailAddress | Domain | Extract domain |
| `PersonToEmail` | Person | EmailAddress | Find email addresses |
| `PersonToPhoneNumber` | Person | PhoneNumber | Find phone numbers |
| `CompanyToDomain` | Company | Domain | Company domains |
| `DomainToCompany` | Domain | Company | Identify company from WHOIS |
| `IPToNetblock` | IPv4Address | Netblock | Find containing netblock |
| `IPToAS` | IPv4Address | AS | Find autonomous system |
| `URLToWebsite` | URL | Website | Extract website from URL |
| `WebsiteToDomain` | Website | Domain | Extract domain from website |

## Built-in Machines

Automated transform sequences for common investigation scenarios:

| Machine | Description |
|---------|-------------|
| `CompanyFootprint` | Full company reconnaissance - domains, IPs, emails, infrastructure |
| `PersonalFootprint` | Person's online presence - emails, aliases, social accounts |
| `DomainRecon` | Domain enumeration - DNS, websites, IPs, infrastructure |
| `InfrastructureRecon` | Network infrastructure mapping from IP |
| `EmailRecon` | Email analysis - alias, domain, mail servers |

## Usage Examples

### List DNS Transforms

```json
{
  "name": "maltego_list_transforms",
  "arguments": {
    "category": "DNS"
  }
}
```

### Run Transform

```json
{
  "name": "maltego_run_transform",
  "arguments": {
    "transformName": "EmailToDomain",
    "entityType": "maltego.EmailAddress",
    "entityValue": "user@example.com"
  }
}
```

### Run Domain Reconnaissance Machine

```json
{
  "name": "maltego_run_machine",
  "arguments": {
    "machineName": "DomainRecon",
    "entityType": "maltego.Domain",
    "entityValue": "example.com",
    "depth": 2
  }
}
```

### Export Investigation Graph

```json
{
  "name": "maltego_export_graph",
  "arguments": {
    "entities": [
      {"type": "maltego.Domain", "value": "example.com"},
      {"type": "maltego.IPv4Address", "value": "93.184.216.34"}
    ],
    "links": [
      {"source": "example.com", "target": "93.184.216.34", "label": "resolves_to"}
    ],
    "format": "graphml",
    "filename": "investigation"
  }
}
```

### Validate Entity

```json
{
  "name": "maltego_validate_entity",
  "arguments": {
    "entityType": "maltego.EmailAddress",
    "value": "user@example.com"
  }
}
```

## Entity Types

### Infrastructure
`maltego.Domain`, `maltego.DNSName`, `maltego.IPv4Address`, `maltego.IPv6Address`, `maltego.Website`, `maltego.URL`, `maltego.Netblock`, `maltego.AS`, `maltego.Port`, `maltego.Service`, `maltego.MXRecord`, `maltego.NSRecord`

### Personal
`maltego.Person`, `maltego.EmailAddress`, `maltego.PhoneNumber`, `maltego.Alias`, `maltego.Image`, `maltego.Document`, `maltego.Location`

### Organization
`maltego.Company`, `maltego.Organization`

### Files
`maltego.Hash`, `maltego.File`

### Social
`maltego.FacebookObject`, `maltego.TwitterAffiliation`, `maltego.Affiliation`

## TDS Setup (Optional)

For remote/custom transforms, set up a Maltego Transform Distribution Server:

1. Deploy Maltego TDS (Docker recommended)
2. Configure `MALTEGO_TDS_URL` environment variable
3. Register your custom transforms in the TDS
4. Configure API keys if required for specific transforms

## Development

```bash
# Watch mode for development
npm run dev

# Build
npm run build

# Run tests
npm test
```

## Security Considerations

- This tool is designed for legitimate security research and OSINT investigations
- Always obtain proper authorization before investigating targets
- Respect rate limits and terms of service for data sources
- Handle sensitive data according to applicable regulations
- API keys and credentials should be stored securely

## License

MIT License - see [LICENSE](LICENSE) for details.

## Related Projects

- [Model Context Protocol](https://modelcontextprotocol.io/) - The MCP specification
- [Maltego](https://www.maltego.com/) - The Maltego OSINT platform
- [Claude](https://claude.ai/) - Anthropic's AI assistant

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
