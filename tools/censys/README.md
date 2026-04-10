# Censys MCP Server

[![MCP](https://img.shields.io/badge/MCP-Compatible-blue)](https://modelcontextprotocol.io)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.3-blue)](https://www.typescriptlang.org/)

A Model Context Protocol (MCP) server for the [Censys Search API v2](https://search.censys.io/api), enabling AI assistants to search internet-wide scan data, SSL/TLS certificates, and host information.

## Overview

Censys is a search engine that allows security researchers to discover, monitor, and analyze devices and services exposed on the Internet. This MCP server provides comprehensive access to Censys Search API capabilities including:

- **Host Discovery** - Search billions of IP addresses and their services
- **Certificate Intelligence** - Find and analyze SSL/TLS certificates
- **Historical Analysis** - Track changes to hosts over time
- **Aggregate Statistics** - Generate reports and statistics

## Features

### Host Search Tools

| Tool | Description |
|------|-------------|
| `censys_search_hosts` | Search for hosts using Censys Search Language |
| `censys_view_host` | Get detailed information about a specific IP address |
| `censys_host_diff` | Compare host data between two timestamps |
| `censys_host_events` | Get timeline of changes/events for a host |
| `censys_host_names` | Get DNS names associated with an IP |
| `censys_aggregate_hosts` | Generate aggregate statistics for hosts |

### Certificate Tools

| Tool | Description |
|------|-------------|
| `censys_search_certs` | Search SSL/TLS certificates |
| `censys_view_cert` | Get certificate details by SHA-256 fingerprint |
| `censys_cert_hosts` | Get hosts presenting a specific certificate |
| `censys_aggregate_certs` | Generate certificate statistics |

### Organization Tools

| Tool | Description |
|------|-------------|
| `censys_list_tags` | List available tags in your account |
| `censys_create_tag` | Create a new tag for organizing assets |
| `censys_tag_host` | Add or remove tags from hosts |
| `censys_host_comments` | Get or add comments on hosts |
| `censys_metadata` | Get index metadata and data freshness info |

## Installation

```bash
git clone https://github.com/schwarztim/sec-censys-mcp.git
cd sec-censys-mcp
npm install
npm run build
```

## Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `CENSYS_API_ID` | Yes | Your Censys API ID |
| `CENSYS_API_SECRET` | Yes | Your Censys API Secret |

Get your API credentials from: https://search.censys.io/account/api

### Claude Desktop Configuration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "censys": {
      "command": "node",
      "args": ["/path/to/sec-censys-mcp/dist/index.js"],
      "env": {
        "CENSYS_API_ID": "your-api-id",
        "CENSYS_API_SECRET": "your-api-secret"
      }
    }
  }
}
```

## Usage Examples

### Search for hosts with open SSH port in the US

```json
{
  "tool": "censys_search_hosts",
  "arguments": {
    "query": "services.port: 22 AND location.country: US",
    "per_page": 10
  }
}
```

### Get detailed information about an IP

```json
{
  "tool": "censys_view_host",
  "arguments": {
    "ip": "8.8.8.8"
  }
}
```

### Search for wildcard certificates

```json
{
  "tool": "censys_search_certs",
  "arguments": {
    "query": "names: *.google.com"
  }
}
```

### Find top countries running HTTP servers

```json
{
  "tool": "censys_aggregate_hosts",
  "arguments": {
    "query": "services.service_name: HTTP",
    "field": "location.country",
    "num_buckets": 10
  }
}
```

### Track changes to a host over time

```json
{
  "tool": "censys_host_events",
  "arguments": {
    "ip": "1.2.3.4",
    "start_time": "2024-01-01T00:00:00Z",
    "end_time": "2024-12-31T23:59:59Z"
  }
}
```

## Censys Search Language

Censys uses a powerful query language for searching. Common patterns:

### Host Queries

| Query | Description |
|-------|-------------|
| `services.port: 443` | Hosts with port 443 open |
| `services.service_name: HTTP` | Hosts running HTTP services |
| `services.software.product: nginx` | Hosts running nginx |
| `location.country: US` | Hosts located in the United States |
| `location.city: "New York"` | Hosts in New York City |
| `autonomous_system.name: Amazon` | Hosts in Amazon's AS |
| `autonomous_system.asn: 15169` | Hosts in AS 15169 (Google) |
| `services.tls.certificates.leaf_data.issuer.common_name: "Let's Encrypt"` | Hosts with Let's Encrypt certs |

### Certificate Queries

| Query | Description |
|-------|-------------|
| `names: example.com` | Certificates for exact domain |
| `names: *.example.com` | Wildcard certificates |
| `parsed.issuer.common_name: "DigiCert"` | Certificates issued by DigiCert |
| `parsed.validity_period.not_after: [NOW TO *]` | Currently valid certificates |

### Combining Queries

```
services.port: 443 AND location.country: US AND NOT autonomous_system.name: Amazon
```

## API Rate Limits

Rate limits depend on your Censys account tier:

| Tier | Queries/Month | Results/Query |
|------|---------------|---------------|
| Free | 250 | 100 |
| Solo | 1,000 | 1,000 |
| Team | 5,000 | 10,000 |
| Enterprise | Custom | Custom |

Check your usage at: https://search.censys.io/account

## Security Considerations

- Store API credentials securely using environment variables
- Never commit credentials to version control
- Use appropriate rate limiting to avoid API abuse
- Follow responsible disclosure practices when discovering vulnerabilities

## Development

```bash
# Install dependencies
npm install

# Build TypeScript
npm run build

# Run in development mode
npm run dev
```

## License

MIT License - see [LICENSE](LICENSE) for details.

## Links

- [Censys Search](https://search.censys.io/)
- [Censys API Documentation](https://search.censys.io/api)
- [Model Context Protocol](https://modelcontextprotocol.io)
- [MCP TypeScript SDK](https://github.com/modelcontextprotocol/typescript-sdk)
