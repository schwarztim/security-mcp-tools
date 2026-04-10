#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { exec } from "child_process";
import { promisify } from "util";

const execAsync = promisify(exec);

// Configuration
const SSH_HOST = process.env.AMASS_SSH_HOST || "kali";
const DEFAULT_TIMEOUT = parseInt(process.env.AMASS_TIMEOUT || "600000"); // 10 minutes default

interface AmassEnumParams {
  domain: string;
  domains_file?: string;
  passive?: boolean;
  active?: boolean;
  brute?: boolean;
  wordlist?: string;
  recursive?: boolean;
  min_for_recursive?: number;
  config?: string;
  output_dir?: string;
  json?: boolean;
  timeout?: number;
  src?: boolean;
  ip?: boolean;
  ipv4?: boolean;
  ipv6?: boolean;
  asn?: number[];
  cidr?: string[];
  max_dns_queries?: number;
}

interface AmassIntelParams {
  domain?: string;
  org?: string;
  asn?: number[];
  ip?: string;
  cidr?: string[];
  whois?: boolean;
  active?: boolean;
  config?: string;
  output_dir?: string;
  timeout?: number;
}

interface AmassTrackParams {
  domain: string;
  config?: string;
  output_dir?: string;
  last?: number;
  since?: string;
  history?: boolean;
  timeout?: number;
}

interface AmassDbParams {
  domain?: string;
  config?: string;
  output_dir?: string;
  names?: boolean;
  ip?: boolean;
  asn?: boolean;
  cidr?: boolean;
  summary?: boolean;
  show?: boolean;
  list?: boolean;
  import_file?: string;
  timeout?: number;
}

interface AmassVizParams {
  domain?: string;
  config?: string;
  output_dir?: string;
  d3?: string;
  visjs?: string;
  graphistry?: boolean;
  maltego?: string;
  gexf?: string;
  timeout?: number;
}

interface AmassConfigParams {
  check?: boolean;
  list_sources?: boolean;
  timeout?: number;
}

interface AmassBruteParams {
  domain: string;
  wordlist: string;
  recursive?: boolean;
  min_for_recursive?: number;
  config?: string;
  output_dir?: string;
  timeout?: number;
}

// Execute command via SSH to Kali
async function executeOnKali(command: string, timeout: number = DEFAULT_TIMEOUT): Promise<string> {
  const sshCommand = `ssh ${SSH_HOST} "${command.replace(/"/g, '\\"')}"`;

  try {
    const { stdout, stderr } = await execAsync(sshCommand, {
      timeout,
      maxBuffer: 50 * 1024 * 1024, // 50MB buffer for large outputs
    });

    if (stderr && !stdout) {
      return stderr;
    }
    return stdout || stderr || "Command completed successfully (no output)";
  } catch (error: any) {
    if (error.killed) {
      throw new Error(`Command timed out after ${timeout}ms`);
    }
    // Return stderr if available, otherwise the error message
    if (error.stderr) {
      return `Error: ${error.stderr}`;
    }
    throw error;
  }
}

// Build amass enum command
function buildEnumCommand(params: AmassEnumParams): string {
  const args: string[] = ["amass", "enum"];

  // Required domain
  if (params.domain) {
    args.push("-d", params.domain);
  }
  if (params.domains_file) {
    args.push("-df", params.domains_file);
  }

  // Mode flags
  if (params.passive) args.push("-passive");
  if (params.active) args.push("-active");
  if (params.brute) args.push("-brute");
  if (params.recursive) args.push("-recursive");

  // Additional options
  if (params.wordlist) args.push("-w", params.wordlist);
  if (params.min_for_recursive) args.push("-min-for-recursive", params.min_for_recursive.toString());
  if (params.config) args.push("-config", params.config);
  if (params.output_dir) args.push("-dir", params.output_dir);
  if (params.json) args.push("-json", "-");
  if (params.src) args.push("-src");
  if (params.ip) args.push("-ip");
  if (params.ipv4) args.push("-ipv4");
  if (params.ipv6) args.push("-ipv6");
  if (params.max_dns_queries) args.push("-max-dns-queries", params.max_dns_queries.toString());

  // ASN and CIDR filters
  if (params.asn && params.asn.length > 0) {
    args.push("-asn", params.asn.join(","));
  }
  if (params.cidr && params.cidr.length > 0) {
    args.push("-cidr", params.cidr.join(","));
  }

  return args.join(" ");
}

// Build amass intel command
function buildIntelCommand(params: AmassIntelParams): string {
  const args: string[] = ["amass", "intel"];

  if (params.domain) args.push("-d", params.domain);
  if (params.org) args.push("-org", `'${params.org}'`);
  if (params.ip) args.push("-ip", params.ip);
  if (params.whois) args.push("-whois");
  if (params.active) args.push("-active");
  if (params.config) args.push("-config", params.config);
  if (params.output_dir) args.push("-dir", params.output_dir);

  if (params.asn && params.asn.length > 0) {
    args.push("-asn", params.asn.join(","));
  }
  if (params.cidr && params.cidr.length > 0) {
    args.push("-cidr", params.cidr.join(","));
  }

  return args.join(" ");
}

// Build amass track command
function buildTrackCommand(params: AmassTrackParams): string {
  const args: string[] = ["amass", "track"];

  args.push("-d", params.domain);

  if (params.config) args.push("-config", params.config);
  if (params.output_dir) args.push("-dir", params.output_dir);
  if (params.last) args.push("-last", params.last.toString());
  if (params.since) args.push("-since", params.since);
  if (params.history) args.push("-history");

  return args.join(" ");
}

// Build amass db command
function buildDbCommand(params: AmassDbParams): string {
  const args: string[] = ["amass", "db"];

  if (params.domain) args.push("-d", params.domain);
  if (params.config) args.push("-config", params.config);
  if (params.output_dir) args.push("-dir", params.output_dir);
  if (params.names) args.push("-names");
  if (params.ip) args.push("-ip");
  if (params.asn) args.push("-asn");
  if (params.cidr) args.push("-cidr");
  if (params.summary) args.push("-summary");
  if (params.show) args.push("-show");
  if (params.list) args.push("-list");
  if (params.import_file) args.push("-import", params.import_file);

  return args.join(" ");
}

// Build amass viz command
function buildVizCommand(params: AmassVizParams): string {
  const args: string[] = ["amass", "viz"];

  if (params.domain) args.push("-d", params.domain);
  if (params.config) args.push("-config", params.config);
  if (params.output_dir) args.push("-dir", params.output_dir);
  if (params.d3) args.push("-d3", params.d3);
  if (params.visjs) args.push("-visjs", params.visjs);
  if (params.graphistry) args.push("-graphistry");
  if (params.maltego) args.push("-maltego", params.maltego);
  if (params.gexf) args.push("-gexf", params.gexf);

  return args.join(" ");
}

// Define tools
const tools: Tool[] = [
  {
    name: "amass_enum",
    description: "Perform DNS enumeration and subdomain discovery using OWASP Amass. Supports passive (OSINT only), active (DNS resolution), and brute-force modes. Discovers subdomains, IP addresses, ASNs, and related infrastructure.",
    inputSchema: {
      type: "object",
      properties: {
        domain: {
          type: "string",
          description: "Target domain to enumerate (e.g., example.com)"
        },
        domains_file: {
          type: "string",
          description: "Path to file containing multiple domains to enumerate"
        },
        passive: {
          type: "boolean",
          description: "Use passive mode only (OSINT sources, no DNS queries). Less detectable but fewer results."
        },
        active: {
          type: "boolean",
          description: "Enable active enumeration with DNS resolution validation"
        },
        brute: {
          type: "boolean",
          description: "Enable brute-force subdomain discovery using wordlist"
        },
        wordlist: {
          type: "string",
          description: "Path to wordlist file for brute-force (default: built-in wordlist)"
        },
        recursive: {
          type: "boolean",
          description: "Recursively brute-force discovered subdomains"
        },
        min_for_recursive: {
          type: "number",
          description: "Minimum subdomains required before recursive brute-forcing starts"
        },
        config: {
          type: "string",
          description: "Path to Amass configuration file with API keys"
        },
        output_dir: {
          type: "string",
          description: "Directory for Amass output and graph database"
        },
        json: {
          type: "boolean",
          description: "Output results in JSON format"
        },
        src: {
          type: "boolean",
          description: "Show data source for each discovered subdomain"
        },
        ip: {
          type: "boolean",
          description: "Show IP addresses for discovered subdomains"
        },
        ipv4: {
          type: "boolean",
          description: "Show only IPv4 addresses"
        },
        ipv6: {
          type: "boolean",
          description: "Show only IPv6 addresses"
        },
        asn: {
          type: "array",
          items: { type: "number" },
          description: "Filter results by ASN numbers"
        },
        cidr: {
          type: "array",
          items: { type: "string" },
          description: "Filter results by CIDR ranges"
        },
        max_dns_queries: {
          type: "number",
          description: "Maximum number of concurrent DNS queries"
        },
        timeout: {
          type: "number",
          description: "Command timeout in milliseconds (default: 600000 = 10 minutes)"
        }
      },
      required: ["domain"]
    }
  },
  {
    name: "amass_intel",
    description: "Gather intelligence about an organization's attack surface. Discovers additional root domains, ASNs, and infrastructure using reverse whois, OSINT sources, and passive techniques.",
    inputSchema: {
      type: "object",
      properties: {
        domain: {
          type: "string",
          description: "Target domain for intelligence gathering"
        },
        org: {
          type: "string",
          description: "Organization name for reverse whois lookup"
        },
        asn: {
          type: "array",
          items: { type: "number" },
          description: "ASN numbers to investigate"
        },
        ip: {
          type: "string",
          description: "IP address to investigate"
        },
        cidr: {
          type: "array",
          items: { type: "string" },
          description: "CIDR ranges to investigate"
        },
        whois: {
          type: "boolean",
          description: "Enable reverse whois lookups"
        },
        active: {
          type: "boolean",
          description: "Enable active intelligence gathering"
        },
        config: {
          type: "string",
          description: "Path to Amass configuration file"
        },
        output_dir: {
          type: "string",
          description: "Directory for Amass output"
        },
        timeout: {
          type: "number",
          description: "Command timeout in milliseconds"
        }
      }
    }
  },
  {
    name: "amass_track",
    description: "Track changes in attack surface over time. Compares current enumeration results with historical data to identify new or removed subdomains, IPs, and infrastructure changes.",
    inputSchema: {
      type: "object",
      properties: {
        domain: {
          type: "string",
          description: "Target domain to track changes for"
        },
        config: {
          type: "string",
          description: "Path to Amass configuration file"
        },
        output_dir: {
          type: "string",
          description: "Directory containing historical Amass data"
        },
        last: {
          type: "number",
          description: "Compare against last N enumerations"
        },
        since: {
          type: "string",
          description: "Compare against enumerations since this date (format: 2006-01-02)"
        },
        history: {
          type: "boolean",
          description: "Show full enumeration history"
        },
        timeout: {
          type: "number",
          description: "Command timeout in milliseconds"
        }
      },
      required: ["domain"]
    }
  },
  {
    name: "amass_db",
    description: "Query and manage the Amass graph database. View stored enumeration results, export data, or import external data.",
    inputSchema: {
      type: "object",
      properties: {
        domain: {
          type: "string",
          description: "Filter results by domain"
        },
        config: {
          type: "string",
          description: "Path to Amass configuration file"
        },
        output_dir: {
          type: "string",
          description: "Directory containing Amass graph database"
        },
        names: {
          type: "boolean",
          description: "Show discovered subdomain names"
        },
        ip: {
          type: "boolean",
          description: "Show discovered IP addresses"
        },
        asn: {
          type: "boolean",
          description: "Show discovered ASN information"
        },
        cidr: {
          type: "boolean",
          description: "Show discovered CIDR ranges"
        },
        summary: {
          type: "boolean",
          description: "Show summary statistics"
        },
        show: {
          type: "boolean",
          description: "Show all stored enumeration data"
        },
        list: {
          type: "boolean",
          description: "List available enumerations in database"
        },
        import_file: {
          type: "string",
          description: "Import data from file into database"
        },
        timeout: {
          type: "number",
          description: "Command timeout in milliseconds"
        }
      }
    }
  },
  {
    name: "amass_viz",
    description: "Generate visualizations from Amass enumeration data. Supports D3.js, Vis.js, Maltego, GEXF, and Graphistry formats for analyzing relationships between domains, IPs, and ASNs.",
    inputSchema: {
      type: "object",
      properties: {
        domain: {
          type: "string",
          description: "Filter visualization by domain"
        },
        config: {
          type: "string",
          description: "Path to Amass configuration file"
        },
        output_dir: {
          type: "string",
          description: "Directory containing Amass graph database"
        },
        d3: {
          type: "string",
          description: "Output path for D3.js HTML visualization"
        },
        visjs: {
          type: "string",
          description: "Output path for Vis.js HTML visualization"
        },
        graphistry: {
          type: "boolean",
          description: "Export to Graphistry format"
        },
        maltego: {
          type: "string",
          description: "Output path for Maltego compatible CSV"
        },
        gexf: {
          type: "string",
          description: "Output path for GEXF graph format"
        },
        timeout: {
          type: "number",
          description: "Command timeout in milliseconds"
        }
      }
    }
  },
  {
    name: "amass_config",
    description: "Check Amass configuration and available data sources. Lists configured API keys and their status.",
    inputSchema: {
      type: "object",
      properties: {
        check: {
          type: "boolean",
          description: "Check configuration file for errors"
        },
        list_sources: {
          type: "boolean",
          description: "List all available data sources and their API key status"
        },
        timeout: {
          type: "number",
          description: "Command timeout in milliseconds"
        }
      }
    }
  },
  {
    name: "amass_brute",
    description: "Dedicated brute-force subdomain discovery. Uses wordlist-based enumeration with optional recursive brute-forcing of discovered subdomains.",
    inputSchema: {
      type: "object",
      properties: {
        domain: {
          type: "string",
          description: "Target domain for brute-force enumeration"
        },
        wordlist: {
          type: "string",
          description: "Path to wordlist file (required)"
        },
        recursive: {
          type: "boolean",
          description: "Recursively brute-force discovered subdomains"
        },
        min_for_recursive: {
          type: "number",
          description: "Minimum subdomains required before recursive brute-forcing"
        },
        config: {
          type: "string",
          description: "Path to Amass configuration file"
        },
        output_dir: {
          type: "string",
          description: "Directory for Amass output"
        },
        timeout: {
          type: "number",
          description: "Command timeout in milliseconds"
        }
      },
      required: ["domain", "wordlist"]
    }
  },
  {
    name: "amass_version",
    description: "Get the installed Amass version on the remote Kali system",
    inputSchema: {
      type: "object",
      properties: {}
    }
  }
];

// Create and configure the server
const server = new Server(
  {
    name: "amass-mcp",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Handle list tools request
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return { tools };
});

// Handle tool execution
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    let result: string;

    switch (name) {
      case "amass_enum": {
        const params = args as unknown as AmassEnumParams;
        const command = buildEnumCommand(params);
        result = await executeOnKali(command, params.timeout || DEFAULT_TIMEOUT);
        break;
      }

      case "amass_intel": {
        const params = args as unknown as AmassIntelParams;
        const command = buildIntelCommand(params);
        result = await executeOnKali(command, params.timeout || DEFAULT_TIMEOUT);
        break;
      }

      case "amass_track": {
        const params = args as unknown as AmassTrackParams;
        const command = buildTrackCommand(params);
        result = await executeOnKali(command, params.timeout || DEFAULT_TIMEOUT);
        break;
      }

      case "amass_db": {
        const params = args as unknown as AmassDbParams;
        const command = buildDbCommand(params);
        result = await executeOnKali(command, params.timeout || DEFAULT_TIMEOUT);
        break;
      }

      case "amass_viz": {
        const params = args as unknown as AmassVizParams;
        const command = buildVizCommand(params);
        result = await executeOnKali(command, params.timeout || DEFAULT_TIMEOUT);
        break;
      }

      case "amass_config": {
        const params = args as unknown as AmassConfigParams;
        let command = "amass enum -list";
        if (params.check) {
          command = "amass enum -list 2>&1";
        }
        result = await executeOnKali(command, params.timeout || 60000);
        break;
      }

      case "amass_brute": {
        const params = args as unknown as AmassBruteParams;
        // Build enum command with brute-force enabled
        const enumParams: AmassEnumParams = {
          domain: params.domain,
          brute: true,
          wordlist: params.wordlist,
          recursive: params.recursive,
          min_for_recursive: params.min_for_recursive,
          config: params.config,
          output_dir: params.output_dir,
        };
        const command = buildEnumCommand(enumParams);
        result = await executeOnKali(command, params.timeout || DEFAULT_TIMEOUT);
        break;
      }

      case "amass_version": {
        result = await executeOnKali("amass -version", 30000);
        break;
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }

    return {
      content: [
        {
          type: "text",
          text: result,
        },
      ],
    };
  } catch (error: any) {
    return {
      content: [
        {
          type: "text",
          text: `Error executing ${name}: ${error.message}`,
        },
      ],
      isError: true,
    };
  }
});

// Start the server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Amass MCP server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
