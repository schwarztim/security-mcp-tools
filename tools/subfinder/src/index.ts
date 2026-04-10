#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { spawn } from "child_process";

// SSH configuration for Kali
const KALI_HOST = process.env.KALI_HOST || "kali";
const SSH_PORT = process.env.SSH_PORT || "22222";
const SUBFINDER_PATH = process.env.SUBFINDER_PATH || "~/bin/subfinder";

/**
 * Execute a command on Kali via SSH
 */
async function executeOnKali(command: string): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  return new Promise((resolve) => {
    const args = [
      "-o", "StrictHostKeyChecking=no",
      "-o", "ConnectTimeout=10",
      "-p", SSH_PORT,
      KALI_HOST,
      command
    ];

    const proc = spawn("ssh", args);
    let stdout = "";
    let stderr = "";

    proc.stdout.on("data", (data) => {
      stdout += data.toString();
    });

    proc.stderr.on("data", (data) => {
      stderr += data.toString();
    });

    proc.on("close", (code) => {
      resolve({
        stdout: stdout.trim(),
        stderr: stderr.trim(),
        exitCode: code ?? 1
      });
    });

    proc.on("error", (err) => {
      resolve({
        stdout: "",
        stderr: `SSH connection error: ${err.message}`,
        exitCode: 1
      });
    });
  });
}

/**
 * Build subfinder command from options
 */
function buildSubfinderCommand(options: SubfinderOptions): string {
  const args: string[] = [SUBFINDER_PATH];

  // Domain(s) - required
  if (options.domain) {
    if (Array.isArray(options.domain)) {
      args.push("-d", options.domain.join(","));
    } else {
      args.push("-d", options.domain);
    }
  }

  // Sources
  if (options.sources && options.sources.length > 0) {
    args.push("-s", options.sources.join(","));
  }

  // Exclude sources
  if (options.excludeSources && options.excludeSources.length > 0) {
    args.push("-es", options.excludeSources.join(","));
  }

  // Use all sources
  if (options.all) {
    args.push("-all");
  }

  // Recursive enumeration
  if (options.recursive) {
    args.push("-recursive");
  }

  // Rate limiting
  if (options.rateLimit) {
    args.push("-rl", options.rateLimit.toString());
  }

  // Threads
  if (options.threads) {
    args.push("-t", options.threads.toString());
  }

  // JSON output
  if (options.json) {
    args.push("-oJ");
  }

  // Include source info in output
  if (options.collectSources) {
    args.push("-cs");
  }

  // Match filter
  if (options.match && options.match.length > 0) {
    args.push("-m", options.match.join(","));
  }

  // Exclude filter
  if (options.filter && options.filter.length > 0) {
    args.push("-f", options.filter.join(","));
  }

  // Silent mode (less verbose)
  if (options.silent) {
    args.push("-silent");
  }

  // Timeout
  if (options.timeout) {
    args.push("-timeout", options.timeout.toString());
  }

  return args.join(" ");
}

interface SubfinderOptions {
  domain?: string | string[];
  sources?: string[];
  excludeSources?: string[];
  all?: boolean;
  recursive?: boolean;
  rateLimit?: number;
  threads?: number;
  json?: boolean;
  collectSources?: boolean;
  match?: string[];
  filter?: string[];
  silent?: boolean;
  timeout?: number;
}

// Tool definitions
const TOOLS: Tool[] = [
  {
    name: "subfinder_enum",
    description: "Enumerate subdomains for one or more domains using passive sources. This is the main subdomain discovery tool.",
    inputSchema: {
      type: "object",
      properties: {
        domain: {
          type: "string",
          description: "Domain or comma-separated list of domains to enumerate (e.g., 'example.com' or 'example.com,test.com')"
        },
        sources: {
          type: "array",
          items: { type: "string" },
          description: "Specific sources to use (e.g., ['crtsh', 'github', 'hackertarget']). Use subfinder_sources to list available sources."
        },
        excludeSources: {
          type: "array",
          items: { type: "string" },
          description: "Sources to exclude from enumeration"
        },
        recursive: {
          type: "boolean",
          description: "Enable recursive subdomain enumeration (find subdomains of subdomains)"
        },
        all: {
          type: "boolean",
          description: "Use all available sources (slower but more comprehensive)"
        },
        json: {
          type: "boolean",
          description: "Output results in JSON format with additional metadata"
        },
        collectSources: {
          type: "boolean",
          description: "Include source information in output (requires json=true)"
        },
        match: {
          type: "array",
          items: { type: "string" },
          description: "Only include subdomains matching these patterns"
        },
        filter: {
          type: "array",
          items: { type: "string" },
          description: "Exclude subdomains matching these patterns"
        },
        rateLimit: {
          type: "number",
          description: "Maximum HTTP requests per second (default: unlimited)"
        },
        timeout: {
          type: "number",
          description: "Timeout in seconds for each source"
        }
      },
      required: ["domain"]
    }
  },
  {
    name: "subfinder_sources",
    description: "List all available passive sources that subfinder can use for subdomain enumeration",
    inputSchema: {
      type: "object",
      properties: {},
      required: []
    }
  },
  {
    name: "subfinder_recursive",
    description: "Perform recursive subdomain enumeration - finds subdomains of subdomains (e.g., sub.sub.example.com)",
    inputSchema: {
      type: "object",
      properties: {
        domain: {
          type: "string",
          description: "Domain to enumerate recursively"
        },
        maxDepth: {
          type: "number",
          description: "Maximum recursion depth (default: 2, max recommended: 3)"
        },
        sources: {
          type: "array",
          items: { type: "string" },
          description: "Specific sources to use"
        },
        rateLimit: {
          type: "number",
          description: "Rate limit for requests per second"
        }
      },
      required: ["domain"]
    }
  },
  {
    name: "subfinder_bulk",
    description: "Enumerate subdomains for multiple domains from a list",
    inputSchema: {
      type: "object",
      properties: {
        domains: {
          type: "array",
          items: { type: "string" },
          description: "List of domains to enumerate"
        },
        sources: {
          type: "array",
          items: { type: "string" },
          description: "Specific sources to use"
        },
        all: {
          type: "boolean",
          description: "Use all available sources"
        },
        json: {
          type: "boolean",
          description: "Output in JSON format"
        },
        rateLimit: {
          type: "number",
          description: "Rate limit for requests per second"
        }
      },
      required: ["domains"]
    }
  },
  {
    name: "subfinder_filter",
    description: "Run subfinder with specific match/filter patterns to find or exclude specific subdomain patterns",
    inputSchema: {
      type: "object",
      properties: {
        domain: {
          type: "string",
          description: "Domain to enumerate"
        },
        match: {
          type: "array",
          items: { type: "string" },
          description: "Patterns to match (include only these)"
        },
        filter: {
          type: "array",
          items: { type: "string" },
          description: "Patterns to filter out (exclude these)"
        },
        all: {
          type: "boolean",
          description: "Use all sources for comprehensive results"
        }
      },
      required: ["domain"]
    }
  },
  {
    name: "subfinder_config",
    description: "Check subfinder configuration and API key status on the Kali system",
    inputSchema: {
      type: "object",
      properties: {},
      required: []
    }
  },
  {
    name: "subfinder_version",
    description: "Get subfinder version and check if it's installed correctly",
    inputSchema: {
      type: "object",
      properties: {},
      required: []
    }
  }
];

// Create the MCP server
const server = new Server(
  {
    name: "subfinder-mcp",
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
  return { tools: TOOLS };
});

// Handle tool execution
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case "subfinder_enum": {
        const options: SubfinderOptions = {
          domain: args?.domain as string,
          sources: args?.sources as string[],
          excludeSources: args?.excludeSources as string[],
          recursive: args?.recursive as boolean,
          all: args?.all as boolean,
          json: args?.json as boolean,
          collectSources: args?.collectSources as boolean,
          match: args?.match as string[],
          filter: args?.filter as string[],
          rateLimit: args?.rateLimit as number,
          timeout: args?.timeout as number,
          silent: true
        };

        const command = buildSubfinderCommand(options);
        const result = await executeOnKali(command);

        if (result.exitCode !== 0 && result.stderr) {
          return {
            content: [{
              type: "text",
              text: `Error running subfinder:\n${result.stderr}\n\nCommand: ${command}`
            }],
            isError: true
          };
        }

        const subdomains = result.stdout.split("\n").filter(line => line.trim());

        return {
          content: [{
            type: "text",
            text: `Found ${subdomains.length} subdomains for ${args?.domain}:\n\n${result.stdout || "No subdomains found"}\n\nCommand: ${command}`
          }]
        };
      }

      case "subfinder_sources": {
        const result = await executeOnKali(`${SUBFINDER_PATH} -ls`);

        return {
          content: [{
            type: "text",
            text: `Available Subfinder Sources:\n\n${result.stdout}\n\nNote: Some sources require API keys configured in ~/.config/subfinder/provider-config.yaml`
          }]
        };
      }

      case "subfinder_recursive": {
        const domain = args?.domain as string;
        const maxDepth = (args?.maxDepth as number) || 2;
        const sources = args?.sources as string[];
        const rateLimit = args?.rateLimit as number;

        // First pass - get initial subdomains
        const options: SubfinderOptions = {
          domain,
          sources,
          recursive: true,
          rateLimit,
          silent: true
        };

        const command = buildSubfinderCommand(options);
        const result = await executeOnKali(command);

        if (result.exitCode !== 0 && result.stderr && !result.stdout) {
          return {
            content: [{
              type: "text",
              text: `Error running recursive enumeration:\n${result.stderr}`
            }],
            isError: true
          };
        }

        const subdomains = result.stdout.split("\n").filter(line => line.trim());

        return {
          content: [{
            type: "text",
            text: `Recursive enumeration for ${domain} (depth: ${maxDepth}):\n\nFound ${subdomains.length} subdomains:\n\n${result.stdout || "No subdomains found"}\n\nCommand: ${command}`
          }]
        };
      }

      case "subfinder_bulk": {
        const domains = args?.domains as string[];

        if (!domains || domains.length === 0) {
          return {
            content: [{
              type: "text",
              text: "Error: No domains provided"
            }],
            isError: true
          };
        }

        const options: SubfinderOptions = {
          domain: domains,
          sources: args?.sources as string[],
          all: args?.all as boolean,
          json: args?.json as boolean,
          rateLimit: args?.rateLimit as number,
          silent: true
        };

        const command = buildSubfinderCommand(options);
        const result = await executeOnKali(command);

        if (result.exitCode !== 0 && result.stderr && !result.stdout) {
          return {
            content: [{
              type: "text",
              text: `Error running bulk enumeration:\n${result.stderr}`
            }],
            isError: true
          };
        }

        const subdomains = result.stdout.split("\n").filter(line => line.trim());

        return {
          content: [{
            type: "text",
            text: `Bulk enumeration for ${domains.length} domains:\n\nFound ${subdomains.length} total subdomains:\n\n${result.stdout || "No subdomains found"}\n\nCommand: ${command}`
          }]
        };
      }

      case "subfinder_filter": {
        const options: SubfinderOptions = {
          domain: args?.domain as string,
          match: args?.match as string[],
          filter: args?.filter as string[],
          all: args?.all as boolean,
          silent: true
        };

        const command = buildSubfinderCommand(options);
        const result = await executeOnKali(command);

        if (result.exitCode !== 0 && result.stderr && !result.stdout) {
          return {
            content: [{
              type: "text",
              text: `Error running filtered enumeration:\n${result.stderr}`
            }],
            isError: true
          };
        }

        const matchStr = options.match ? `Match: ${options.match.join(", ")}` : "";
        const filterStr = options.filter ? `Filter: ${options.filter.join(", ")}` : "";
        const subdomains = result.stdout.split("\n").filter(line => line.trim());

        return {
          content: [{
            type: "text",
            text: `Filtered enumeration for ${args?.domain}:\n${matchStr}\n${filterStr}\n\nFound ${subdomains.length} subdomains:\n\n${result.stdout || "No subdomains found"}\n\nCommand: ${command}`
          }]
        };
      }

      case "subfinder_config": {
        const configCheck = await executeOnKali("cat ~/.config/subfinder/provider-config.yaml 2>/dev/null || echo 'No config file found'");
        const configExists = await executeOnKali("ls -la ~/.config/subfinder/ 2>/dev/null || echo 'Config directory not found'");

        return {
          content: [{
            type: "text",
            text: `Subfinder Configuration Status:\n\n=== Config Directory ===\n${configExists.stdout}\n\n=== Provider Config ===\n${configCheck.stdout}\n\nNote: Configure API keys in ~/.config/subfinder/provider-config.yaml for premium sources like:\n- Censys\n- SecurityTrails\n- Shodan\n- VirusTotal\n- GitHub`
          }]
        };
      }

      case "subfinder_version": {
        const result = await executeOnKali(`${SUBFINDER_PATH} -version 2>&1`);
        const which = await executeOnKali(`which ${SUBFINDER_PATH} 2>/dev/null || echo "${SUBFINDER_PATH}"`);

        return {
          content: [{
            type: "text",
            text: `Subfinder Installation:\n\nPath: ${which.stdout}\n\n${result.stdout || result.stderr}`
          }]
        };
      }

      default:
        return {
          content: [{
            type: "text",
            text: `Unknown tool: ${name}`
          }],
          isError: true
        };
    }
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return {
      content: [{
        type: "text",
        text: `Error executing ${name}: ${errorMessage}`
      }],
      isError: true
    };
  }
});

// Main entry point
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Subfinder MCP server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
