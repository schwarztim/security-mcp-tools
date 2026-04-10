#!/usr/bin/env node
/**
 * theHarvester MCP Server
 *
 * An MCP server that wraps theHarvester OSINT tool for email/subdomain harvesting.
 * Executes commands via SSH on a Kali Linux host.
 */

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
const KALI_HOST = process.env.KALI_HOST || "kali";
const SSH_OPTIONS = "-o StrictHostKeyChecking=no -o ConnectTimeout=30";

// Available data sources for theHarvester
const DATA_SOURCES = [
  "anubis", "baidu", "bevigil", "binaryedge", "bing", "bingapi",
  "brave", "bufferoverun", "censys", "certspotter", "criminalip",
  "crtsh", "dnsdumpster", "duckduckgo", "fullhunt", "github-code",
  "hackertarget", "hunter", "hunterhow", "intelx", "leakix",
  "netlas", "onyphe", "otx", "pentesttools", "projectdiscovery",
  "rapiddns", "rocketreach", "securityscorecard", "securitytrails",
  "shodan", "sitedossier", "subdomaincenter", "subdomainfinderc99",
  "threatminer", "tomba", "urlscan", "virustotal", "yahoo", "zoomeye"
];

interface HarvesterResult {
  domain: string;
  sources: string[];
  emails: string[];
  hosts: string[];
  ips: string[];
  urls: string[];
  asns: string[];
  interesting_urls: string[];
  raw_output: string;
  error?: string;
}

/**
 * Execute a command via SSH on the Kali host
 */
async function executeOnKali(command: string, timeout = 300000): Promise<string> {
  const sshCommand = `ssh ${SSH_OPTIONS} ${KALI_HOST} "${command.replace(/"/g, '\\"')}"`;

  try {
    const { stdout, stderr } = await execAsync(sshCommand, {
      maxBuffer: 50 * 1024 * 1024, // 50MB buffer
      timeout,
    });

    if (stderr && !stdout) {
      return stderr;
    }
    return stdout || stderr;
  } catch (error: any) {
    if (error.stdout) {
      return error.stdout;
    }
    throw new Error(`SSH execution failed: ${error.message}`);
  }
}

/**
 * Parse theHarvester output to extract structured data
 */
function parseHarvesterOutput(output: string): Partial<HarvesterResult> {
  const result: Partial<HarvesterResult> = {
    emails: [],
    hosts: [],
    ips: [],
    urls: [],
    asns: [],
    interesting_urls: [],
  };

  const lines = output.split("\n");
  let currentSection = "";

  for (const line of lines) {
    const trimmedLine = line.trim();

    // Detect section headers
    if (trimmedLine.includes("[*] Emails found:")) {
      currentSection = "emails";
      continue;
    } else if (trimmedLine.includes("[*] Hosts found:") || trimmedLine.includes("[*] Subdomains found:")) {
      currentSection = "hosts";
      continue;
    } else if (trimmedLine.includes("[*] IPs found:")) {
      currentSection = "ips";
      continue;
    } else if (trimmedLine.includes("[*] URLs found:")) {
      currentSection = "urls";
      continue;
    } else if (trimmedLine.includes("[*] ASNs found:")) {
      currentSection = "asns";
      continue;
    } else if (trimmedLine.includes("[*] Interesting URLs found:")) {
      currentSection = "interesting_urls";
      continue;
    } else if (trimmedLine.startsWith("[*]") || trimmedLine.startsWith("[-]")) {
      currentSection = "";
      continue;
    }

    // Skip empty lines and dividers
    if (!trimmedLine || trimmedLine.startsWith("-") || trimmedLine.startsWith("=")) {
      continue;
    }

    // Add to appropriate section
    if (currentSection && trimmedLine) {
      const arr = result[currentSection as keyof typeof result];
      if (Array.isArray(arr) && !arr.includes(trimmedLine)) {
        arr.push(trimmedLine);
      }
    }
  }

  return result;
}

/**
 * Build theHarvester command from options
 */
function buildCommand(options: {
  domain: string;
  sources?: string[];
  limit?: number;
  start?: number;
  dnsResolve?: boolean;
  dnsBrute?: boolean;
  shodan?: boolean;
  takeover?: boolean;
  virtualHost?: boolean;
  filename?: string;
  dnsServer?: string;
  proxies?: boolean;
}): string {
  const parts = ["theHarvester"];

  parts.push(`-d ${options.domain}`);

  if (options.sources && options.sources.length > 0) {
    parts.push(`-b ${options.sources.join(",")}`);
  } else {
    parts.push("-b all");
  }

  if (options.limit) {
    parts.push(`-l ${options.limit}`);
  }

  if (options.start) {
    parts.push(`-S ${options.start}`);
  }

  if (options.dnsResolve) {
    parts.push("-r");
  }

  if (options.dnsBrute) {
    parts.push("-c");
  }

  if (options.shodan) {
    parts.push("-s");
  }

  if (options.takeover) {
    parts.push("-t");
  }

  if (options.virtualHost) {
    parts.push("-v");
  }

  if (options.dnsServer) {
    parts.push(`-e ${options.dnsServer}`);
  }

  if (options.proxies) {
    parts.push("-p");
  }

  if (options.filename) {
    parts.push(`-f ${options.filename}`);
  }

  return parts.join(" ");
}

// Define MCP tools
const tools: Tool[] = [
  {
    name: "theharvester_search",
    description: "Run theHarvester to gather OSINT on a domain. Collects emails, subdomains, hosts, IPs, and URLs from various public sources.",
    inputSchema: {
      type: "object",
      properties: {
        domain: {
          type: "string",
          description: "Target domain to search (e.g., 'example.com')",
        },
        sources: {
          type: "array",
          items: { type: "string" },
          description: `Data sources to use. Available: ${DATA_SOURCES.join(", ")}. Leave empty for 'all'.`,
        },
        limit: {
          type: "number",
          description: "Maximum number of results to return (default: 500)",
        },
        dns_resolve: {
          type: "boolean",
          description: "Perform DNS resolution on discovered subdomains",
        },
        dns_brute: {
          type: "boolean",
          description: "Perform DNS brute force enumeration",
        },
        shodan: {
          type: "boolean",
          description: "Query Shodan for discovered hosts",
        },
        takeover: {
          type: "boolean",
          description: "Check for subdomain takeover vulnerabilities",
        },
      },
      required: ["domain"],
    },
  },
  {
    name: "theharvester_sources",
    description: "List all available data sources for theHarvester, with information about API key requirements.",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "theharvester_emails",
    description: "Quick search focused on harvesting email addresses from a domain.",
    inputSchema: {
      type: "object",
      properties: {
        domain: {
          type: "string",
          description: "Target domain to search for emails",
        },
        sources: {
          type: "array",
          items: { type: "string" },
          description: "Specific sources to use (default: hunter, tomba, rocketreach, bing, yahoo, duckduckgo)",
        },
        limit: {
          type: "number",
          description: "Maximum results per source (default: 200)",
        },
      },
      required: ["domain"],
    },
  },
  {
    name: "theharvester_hosts",
    description: "Quick search focused on discovering subdomains and hosts for a domain.",
    inputSchema: {
      type: "object",
      properties: {
        domain: {
          type: "string",
          description: "Target domain to search for subdomains",
        },
        sources: {
          type: "array",
          items: { type: "string" },
          description: "Specific sources to use (default: crtsh, dnsdumpster, hackertarget, rapiddns, threatminer)",
        },
        dns_resolve: {
          type: "boolean",
          description: "Resolve discovered subdomains to verify they're active (default: true)",
        },
        dns_brute: {
          type: "boolean",
          description: "Also perform DNS brute force enumeration",
        },
      },
      required: ["domain"],
    },
  },
  {
    name: "theharvester_dns_brute",
    description: "Perform DNS brute force enumeration to discover subdomains using a wordlist.",
    inputSchema: {
      type: "object",
      properties: {
        domain: {
          type: "string",
          description: "Target domain for DNS brute force",
        },
        dns_server: {
          type: "string",
          description: "Custom DNS server to use for lookups",
        },
      },
      required: ["domain"],
    },
  },
  {
    name: "theharvester_shodan",
    description: "Run theHarvester with Shodan integration to get detailed host information including open ports and banners.",
    inputSchema: {
      type: "object",
      properties: {
        domain: {
          type: "string",
          description: "Target domain",
        },
        sources: {
          type: "array",
          items: { type: "string" },
          description: "Additional sources to combine with Shodan",
        },
      },
      required: ["domain"],
    },
  },
  {
    name: "theharvester_full_recon",
    description: "Comprehensive reconnaissance using all available sources and features. Takes longer but provides the most complete results.",
    inputSchema: {
      type: "object",
      properties: {
        domain: {
          type: "string",
          description: "Target domain for full reconnaissance",
        },
        output_file: {
          type: "string",
          description: "Base filename to save results (will create .json and .xml files)",
        },
      },
      required: ["domain"],
    },
  },
  {
    name: "theharvester_check_status",
    description: "Check if theHarvester is available and working on the Kali host.",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
];

// Create and configure the MCP server
const server = new Server(
  {
    name: "theharvester-mcp",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Handle tool listing
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return { tools };
});

// Handle tool execution
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case "theharvester_search": {
        const { domain, sources, limit, dns_resolve, dns_brute, shodan, takeover } = args as {
          domain: string;
          sources?: string[];
          limit?: number;
          dns_resolve?: boolean;
          dns_brute?: boolean;
          shodan?: boolean;
          takeover?: boolean;
        };

        const command = buildCommand({
          domain,
          sources,
          limit: limit || 500,
          dnsResolve: dns_resolve,
          dnsBrute: dns_brute,
          shodan,
          takeover,
        });

        const output = await executeOnKali(command);
        const parsed = parseHarvesterOutput(output);

        const result: HarvesterResult = {
          domain,
          sources: sources || ["all"],
          emails: parsed.emails || [],
          hosts: parsed.hosts || [],
          ips: parsed.ips || [],
          urls: parsed.urls || [],
          asns: parsed.asns || [],
          interesting_urls: parsed.interesting_urls || [],
          raw_output: output,
        };

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(result, null, 2),
            },
          ],
        };
      }

      case "theharvester_sources": {
        const sourceInfo = {
          no_api_required: [
            "anubis", "baidu", "bing", "crtsh", "dnsdumpster", "duckduckgo",
            "hackertarget", "otx", "rapiddns", "sitedossier", "subdomaincenter",
            "threatminer", "urlscan", "yahoo"
          ],
          api_required: {
            bevigil: "50 free queries/month, 1k/month for $50",
            binaryedge: "100 free queries/month",
            brave: "Free plan available, Pro for higher limits",
            bufferoverun: "100 free queries/month, 10k/month for $25",
            censys: "Free tier available with registration",
            criminalip: "Requires registration",
            fullhunt: "Requires registration",
            github_code: "GitHub personal access token",
            hunter: "50 free requests/month",
            hunterhow: "Requires registration",
            intelx: "Requires registration",
            leakix: "Requires API key",
            netlas: "Requires registration",
            onyphe: "Requires registration",
            pentesttools: "Requires registration",
            projectdiscovery: "Requires work email for registration",
            rocketreach: "Requires registration",
            securityscorecard: "Requires registration",
            securitytrails: "50 free queries/month",
            shodan: "Free tier with registration",
            tomba: "50 free requests/month",
            virustotal: "Free tier with registration",
            zoomeye: "Requires registration",
          },
          all_sources: DATA_SOURCES,
        };

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(sourceInfo, null, 2),
            },
          ],
        };
      }

      case "theharvester_emails": {
        const { domain, sources, limit } = args as {
          domain: string;
          sources?: string[];
          limit?: number;
        };

        const emailSources = sources || ["hunter", "tomba", "rocketreach", "bing", "yahoo", "duckduckgo"];
        const command = buildCommand({
          domain,
          sources: emailSources,
          limit: limit || 200,
        });

        const output = await executeOnKali(command);
        const parsed = parseHarvesterOutput(output);

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                domain,
                sources_used: emailSources,
                emails_found: parsed.emails?.length || 0,
                emails: parsed.emails || [],
                raw_output: output,
              }, null, 2),
            },
          ],
        };
      }

      case "theharvester_hosts": {
        const { domain, sources, dns_resolve, dns_brute } = args as {
          domain: string;
          sources?: string[];
          dns_resolve?: boolean;
          dns_brute?: boolean;
        };

        const hostSources = sources || ["crtsh", "dnsdumpster", "hackertarget", "rapiddns", "threatminer", "anubis"];
        const command = buildCommand({
          domain,
          sources: hostSources,
          dnsResolve: dns_resolve !== false, // Default to true
          dnsBrute: dns_brute,
        });

        const output = await executeOnKali(command);
        const parsed = parseHarvesterOutput(output);

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                domain,
                sources_used: hostSources,
                hosts_found: parsed.hosts?.length || 0,
                hosts: parsed.hosts || [],
                ips_found: parsed.ips?.length || 0,
                ips: parsed.ips || [],
                raw_output: output,
              }, null, 2),
            },
          ],
        };
      }

      case "theharvester_dns_brute": {
        const { domain, dns_server } = args as {
          domain: string;
          dns_server?: string;
        };

        const command = buildCommand({
          domain,
          sources: ["crtsh"], // Use a minimal source since we're focusing on brute force
          dnsBrute: true,
          dnsServer: dns_server,
        });

        const output = await executeOnKali(command, 600000); // 10 minute timeout for brute force
        const parsed = parseHarvesterOutput(output);

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                domain,
                dns_brute_enabled: true,
                dns_server: dns_server || "default",
                hosts_found: parsed.hosts?.length || 0,
                hosts: parsed.hosts || [],
                raw_output: output,
              }, null, 2),
            },
          ],
        };
      }

      case "theharvester_shodan": {
        const { domain, sources } = args as {
          domain: string;
          sources?: string[];
        };

        const allSources = sources ? [...sources, "shodan"] : ["shodan", "crtsh", "dnsdumpster"];
        const command = buildCommand({
          domain,
          sources: allSources,
          shodan: true,
          dnsResolve: true,
        });

        const output = await executeOnKali(command);
        const parsed = parseHarvesterOutput(output);

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                domain,
                shodan_enabled: true,
                sources_used: allSources,
                hosts: parsed.hosts || [],
                ips: parsed.ips || [],
                asns: parsed.asns || [],
                raw_output: output,
              }, null, 2),
            },
          ],
        };
      }

      case "theharvester_full_recon": {
        const { domain, output_file } = args as {
          domain: string;
          output_file?: string;
        };

        const command = buildCommand({
          domain,
          sources: undefined, // Use all
          limit: 1000,
          dnsResolve: true,
          dnsBrute: true,
          shodan: true,
          takeover: true,
          virtualHost: true,
          filename: output_file,
        });

        const output = await executeOnKali(command, 900000); // 15 minute timeout
        const parsed = parseHarvesterOutput(output);

        const result: HarvesterResult = {
          domain,
          sources: ["all"],
          emails: parsed.emails || [],
          hosts: parsed.hosts || [],
          ips: parsed.ips || [],
          urls: parsed.urls || [],
          asns: parsed.asns || [],
          interesting_urls: parsed.interesting_urls || [],
          raw_output: output,
        };

        const summary = {
          ...result,
          full_recon: true,
          features_enabled: ["all_sources", "dns_resolve", "dns_brute", "shodan", "takeover_check", "virtual_host"],
          output_file: output_file || "none",
          stats: {
            emails_found: result.emails.length,
            hosts_found: result.hosts.length,
            ips_found: result.ips.length,
            urls_found: result.urls.length,
            asns_found: result.asns.length,
          },
        };

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(summary, null, 2),
            },
          ],
        };
      }

      case "theharvester_check_status": {
        try {
          const versionOutput = await executeOnKali("theHarvester --help | head -20", 30000);
          const pythonVersion = await executeOnKali("python3 --version", 10000);

          return {
            content: [
              {
                type: "text",
                text: JSON.stringify({
                  status: "available",
                  kali_host: KALI_HOST,
                  python_version: pythonVersion.trim(),
                  theharvester_help: versionOutput.substring(0, 500),
                }, null, 2),
              },
            ],
          };
        } catch (error: any) {
          return {
            content: [
              {
                type: "text",
                text: JSON.stringify({
                  status: "unavailable",
                  kali_host: KALI_HOST,
                  error: error.message,
                  suggestion: "Ensure SSH access to Kali host is configured and theHarvester is installed.",
                }, null, 2),
              },
            ],
          };
        }
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error: any) {
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            error: error.message,
            tool: name,
            args,
          }, null, 2),
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
  console.error("theHarvester MCP server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
