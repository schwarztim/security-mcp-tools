# sec-shodan-mcp v2 — Full Rewrite Design Spec

## Overview

Full rewrite of sec-shodan-mcp from a thesun-generated 731-line monolith into a modular, validated, response-aware MCP server. Adds CVEDB tools, zod validation, smart response truncation, tool annotations, and status-aware error handling.

## Architecture

### Framework: FastMCP

Switch from raw `@modelcontextprotocol/sdk` to `fastmcp`. Benefits:

- Zod schemas as tool input definitions (runtime validation built in)
- `UserError` for clean error surfacing to agents
- Tool annotations (`readOnlyHint`, `destructiveHint`, `openWorldHint`)
- Automatic schema generation from zod

### File Structure

```
src/
  index.ts              # Server bootstrap, tool registration
  client.ts             # Axios instances, request helpers (shodan, exploits, cvedb)
  response.ts           # formatResponse(), truncation, summary generation
  errors.ts             # ShodanApiError, status code handling
  tools/
    search.ts           # shodan_search, shodan_host, shodan_count
    dns.ts              # shodan_dns_resolve, shodan_dns_reverse, shodan_dns_domain
    scanning.ts         # shodan_scan, shodan_scan_status, shodan_list_scans
    alerts.ts           # shodan_alert_create/list/get/delete/triggers
    exploits.ts         # shodan_exploits_search, shodan_exploits_count
    cvedb.ts            # shodan_cve_lookup, shodan_cve_search, shodan_cpe_lookup,
                        #   shodan_cves_newest, shodan_cves_kev, shodan_cves_by_epss
    utility.ts          # shodan_ports, shodan_protocols, shodan_filters, shodan_facets,
                        #   shodan_api_info, shodan_account_profile, shodan_myip,
                        #   shodan_honeyscore, shodan_saved_queries, shodan_search_queries
```

Each tool file exports an array of FastMCP tool definitions. `index.ts` imports and registers all.

## Response Handling

### The Problem

Claude CLI truncates MCP responses exceeding `MAX_MCP_OUTPUT_TOKENS * 4` characters. Shodan search results, host history, and exploit listings routinely exceed this. Raw `JSON.stringify` dumps are unparseable when truncated.

### Solution: `formatResponse()`

Every tool handler passes its API response through `formatResponse(data, options)` before returning.

```typescript
interface FormatOptions {
  maxResults?: number; // cap array items (default varies by tool)
  summaryFields?: string[]; // fields to extract per item for compact view
  detailed?: boolean; // return full objects (false = summarized)
  label?: string; // e.g. "hosts", "exploits", "CVEs"
}
```

Behavior:

1. If response is an array or contains a results array: count total, slice to `maxResults`
2. Prepend summary header: `"Showing {n} of {total} {label}."`
3. If `!detailed`: extract only `summaryFields` from each item
4. If response has `facets`: always include facets (small, high-value)
5. Final output is formatted text, not raw JSON

### Per-Tool Defaults

| Tool                     | maxResults    | summaryFields                                    | detailed |
| ------------------------ | ------------- | ------------------------------------------------ | -------- |
| `shodan_search`          | 10            | ip_str, port, org, product, os, hostnames, vulns | false    |
| `shodan_host`            | 15 (services) | port, transport, product, version, vulns         | false    |
| `shodan_exploits_search` | 10            | description, source, cve, platform, type         | false    |
| `shodan_cve_search`      | 10            | cve_id, summary, cvss, epss, published           | false    |
| `shodan_dns_domain`      | 20 (records)  | subdomain, type, value                           | true     |
| Utility lists            | 50            | (full items, they're small)                      | true     |

All tools accept an optional `maxResults` parameter to override defaults. Setting `detailed: true` returns full objects (use with low `maxResults` to avoid overflow).

### Summary Format Example

```
Showing 10 of 847 hosts matching "apache country:US"

Facets:
  country: US (847)
  port: 80 (612), 443 (498), 8080 (89)

Results:
  1. 203.0.113.1 — Apache/2.4.41 (Ubuntu) — ports: 80, 443 — org: Example Corp
     vulns: CVE-2021-44228, CVE-2023-25690
  2. 198.51.100.5 — Apache/2.4.52 — ports: 80, 8080 — org: Hosting Inc
     ...
```

## New Tools: CVEDB (cvedb.shodan.io)

6 new tools covering the Shodan CVE database API:

### shodan_cve_lookup

- Endpoint: `GET /cve/{cve_id}`
- Params: `cve_id` (string, required) — e.g. "CVE-2021-44228"
- Returns: CVE details including CVSS, EPSS, references, affected products

### shodan_cve_search

- Endpoint: `GET /cves`
- Params: `cpe23` (string), `product` (string), `is_kev` (boolean), `sort_by_epss` (boolean), `start_date` (string), `end_date` (string), `skip` (number), `limit` (number)
- Mutual exclusion: `cpe23` and `product` cannot both be specified
- Returns: List of CVEs matching criteria

### shodan_cpe_lookup

- Endpoint: `GET /cpes`
- Params: `product` (string, required), `count` (boolean), `skip` (number), `limit` (number)
- Returns: CPE 2.3 identifiers matching product name

### shodan_cves_newest

- Endpoint: `GET /cves/latest`
- Params: `limit` (number, default 10)
- Returns: Most recently published CVEs

### shodan_cves_kev

- Endpoint: `GET /cves/kev`
- Params: `skip` (number), `limit` (number)
- Returns: CISA Known Exploited Vulnerabilities catalog entries

### shodan_cves_by_epss

- Endpoint: `GET /cves/epss`
- Params: `min_epss` (number, 0-1), `order` (string, "asc"/"desc"), `skip` (number), `limit` (number)
- Returns: CVEs ranked by EPSS (Exploit Prediction Scoring System) score

## API Client (`client.ts`)

Three axios instances:

```typescript
const shodanApi = axios.create({
  baseURL: "https://api.shodan.io",
  timeout: 30000,
});
const exploitsApi = axios.create({
  baseURL: "https://exploits.shodan.io/api",
  timeout: 30000,
});
const cvedbApi = axios.create({
  baseURL: "https://cvedb.shodan.io/api",
  timeout: 30000,
});
```

Shared request helpers:

- `shodanRequest(endpoint, params, method)` — appends API key, handles errors
- `exploitsRequest(endpoint, params)` — appends API key, GET only
- `cvedbRequest(endpoint, params)` — NO API key needed (cvedb is public), GET only

## Error Handling (`errors.ts`)

```typescript
class ShodanApiError extends Error {
  constructor(
    message: string,
    public statusCode?: number,
    public endpoint?: string,
  ) {
    super(message);
  }
}
```

Status-aware error messages:

- **401**: "Invalid API key. Verify SHODAN_API_KEY."
- **402**: "Insufficient credits. This query requires a paid Shodan plan."
- **429**: "Rate limit exceeded. Wait before retrying."
- **404**: "Resource not found." (for host lookups, scan IDs, alert IDs)
- **Other**: Pass through Shodan's error message from response body

Errors surfaced via FastMCP's `UserError` so agents see clean messages.

## Tool Annotations

Every tool gets MCP-spec annotations:

| Tool Category                                      | readOnlyHint | destructiveHint | openWorldHint |
| -------------------------------------------------- | ------------ | --------------- | ------------- |
| Search, Host, Count, DNS, Exploits, CVEDB, Utility | true         | false           | true          |
| Scanning (scan, scan_status, list_scans)           | false        | false           | true          |
| Alert Create                                       | false        | false           | false         |
| Alert Delete                                       | false        | true            | false         |
| Alert List/Get/Triggers                            | true         | false           | false         |

## Zod Validation

All tool inputs validated with zod schemas. Examples:

```typescript
// shodan_search
z.object({
  query: z.string().describe("Shodan search query"),
  page: z
    .number()
    .int()
    .positive()
    .optional()
    .describe("Page number (default: 1)"),
  facets: z.string().optional().describe("Comma-separated facets"),
  minify: z.boolean().optional().describe("Return minimal host info"),
  maxResults: z
    .number()
    .int()
    .min(1)
    .max(100)
    .optional()
    .describe("Max results to return (default: 10)"),
  detailed: z
    .boolean()
    .optional()
    .describe("Return full host objects instead of summaries"),
});

// shodan_cve_search — mutual exclusion
z.object({
  cpe23: z.string().optional(),
  product: z.string().optional(),
  is_kev: z.boolean().optional(),
  sort_by_epss: z.boolean().optional(),
  start_date: z.string().optional(),
  end_date: z.string().optional(),
  skip: z.number().int().min(0).optional(),
  limit: z.number().int().min(1).max(100).optional(),
}).refine((d) => !(d.cpe23 && d.product), {
  message: "Cannot specify both cpe23 and product",
});
```

## Dependencies

```json
{
  "dependencies": {
    "fastmcp": "^3.33.0",
    "axios": "^1.6.0",
    "zod": "^3.22.0"
  },
  "devDependencies": {
    "@types/node": "^20.10.0",
    "typescript": "^5.3.0"
  }
}
```

## Migration Notes

- Package name stays `shodan-mcp`
- All 26 existing tool names preserved (no breaking changes for existing users)
- 6 new CVEDB tools added with `shodan_cve_` / `shodan_cpe_` / `shodan_cves_` prefixes
- `maxResults` and `detailed` params added to search/list tools (optional, backward compatible)
- Version bumped to `2.0.0`

## Success Criteria

1. All 32 tools register and respond to `ListTools`
2. Zod rejects invalid inputs with descriptive errors (not raw crashes)
3. `shodan_search` with a broad query returns a formatted summary, not 500KB of JSON
4. `shodan_host` with `history=true` returns truncated service list with count
5. CVEDB tools return results from `cvedb.shodan.io`
6. 401/402/429 errors produce clean, actionable messages
7. `npm run build` succeeds with zero TypeScript errors
8. Existing tool names unchanged — drop-in replacement for v1
