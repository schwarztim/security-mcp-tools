#!/usr/bin/env node
/**
 * FFUF MCP Server
 *
 * A Model Context Protocol server for ffuf (Fuzz Faster U Fool) - fast web fuzzer.
 * Executes ffuf commands via SSH on a Kali Linux host.
 *
 * Features:
 * - Web content discovery (directories, files, subdomains)
 * - Configurable matchers and filters
 * - Recursion support
 * - Multiple output formats
 * - Thread control for rate limiting
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ErrorCode,
  McpError,
} from "@modelcontextprotocol/sdk/types.js";
import { exec } from "child_process";
import { promisify } from "util";

const execAsync = promisify(exec);

// Configuration
const KALI_HOST = process.env.KALI_HOST || "kali";
const SSH_OPTIONS = "-o StrictHostKeyChecking=no -o ConnectTimeout=30";
const DEFAULT_THREADS = 40;
const DEFAULT_TIMEOUT = 300; // 5 minutes

// Common wordlists on Kali
const WORDLISTS = {
  common: "/usr/share/wordlists/dirb/common.txt",
  big: "/usr/share/wordlists/dirb/big.txt",
  small: "/usr/share/wordlists/dirb/small.txt",
  dirbuster_small: "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
  dirbuster_medium: "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
  dirbuster_big: "/usr/share/wordlists/dirbuster/directory-list-2.3-big.txt",
  seclists_common: "/usr/share/seclists/Discovery/Web-Content/common.txt",
  seclists_directories: "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt",
  subdomains: "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
  parameters: "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
  api_endpoints: "/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt",
};

interface FfufOptions {
  url: string;
  wordlist?: string;
  wordlistPath?: string;
  method?: string;
  headers?: Record<string, string>;
  data?: string;
  cookies?: string;
  matchCodes?: string;
  matchSize?: string;
  matchWords?: string;
  matchLines?: string;
  matchRegex?: string;
  filterCodes?: string;
  filterSize?: string;
  filterWords?: string;
  filterLines?: string;
  filterRegex?: string;
  recursion?: boolean;
  recursionDepth?: number;
  recursionStrategy?: "default" | "greedy";
  threads?: number;
  delay?: string;
  rate?: number;
  timeout?: number;
  maxtime?: number;
  followRedirects?: boolean;
  outputFormat?: "json" | "csv" | "html" | "md" | "all";
  verbose?: boolean;
  silent?: boolean;
  colors?: boolean;
  extensions?: string;
  mode?: "clusterbomb" | "pitchfork" | "sniper";
  proxy?: string;
}

/**
 * Execute SSH command on Kali
 */
async function executeSSH(command: string, timeout: number = DEFAULT_TIMEOUT): Promise<{ stdout: string; stderr: string }> {
  const fullCommand = `ssh ${SSH_OPTIONS} ${KALI_HOST} "${command.replace(/"/g, '\\"')}"`;

  try {
    const result = await execAsync(fullCommand, {
      timeout: timeout * 1000,
      maxBuffer: 50 * 1024 * 1024, // 50MB buffer for large outputs
    });
    return result;
  } catch (error: any) {
    if (error.killed) {
      throw new Error(`Command timed out after ${timeout} seconds`);
    }
    // Return stderr/stdout even on non-zero exit
    return {
      stdout: error.stdout || "",
      stderr: error.stderr || error.message,
    };
  }
}

/**
 * Build ffuf command from options
 */
function buildFfufCommand(options: FfufOptions): string {
  const args: string[] = ["ffuf"];

  // URL (required)
  args.push(`-u '${options.url}'`);

  // Wordlist
  if (options.wordlistPath) {
    args.push(`-w '${options.wordlistPath}'`);
  } else if (options.wordlist && WORDLISTS[options.wordlist as keyof typeof WORDLISTS]) {
    args.push(`-w '${WORDLISTS[options.wordlist as keyof typeof WORDLISTS]}'`);
  } else {
    args.push(`-w '${WORDLISTS.common}'`); // Default to common
  }

  // HTTP Method
  if (options.method) {
    args.push(`-X ${options.method}`);
  }

  // Headers
  if (options.headers) {
    for (const [key, value] of Object.entries(options.headers)) {
      args.push(`-H '${key}: ${value}'`);
    }
  }

  // POST Data
  if (options.data) {
    args.push(`-d '${options.data}'`);
  }

  // Cookies
  if (options.cookies) {
    args.push(`-b '${options.cookies}'`);
  }

  // Matchers
  if (options.matchCodes) {
    args.push(`-mc ${options.matchCodes}`);
  }
  if (options.matchSize) {
    args.push(`-ms ${options.matchSize}`);
  }
  if (options.matchWords) {
    args.push(`-mw ${options.matchWords}`);
  }
  if (options.matchLines) {
    args.push(`-ml ${options.matchLines}`);
  }
  if (options.matchRegex) {
    args.push(`-mr '${options.matchRegex}'`);
  }

  // Filters
  if (options.filterCodes) {
    args.push(`-fc ${options.filterCodes}`);
  }
  if (options.filterSize) {
    args.push(`-fs ${options.filterSize}`);
  }
  if (options.filterWords) {
    args.push(`-fw ${options.filterWords}`);
  }
  if (options.filterLines) {
    args.push(`-fl ${options.filterLines}`);
  }
  if (options.filterRegex) {
    args.push(`-fr '${options.filterRegex}'`);
  }

  // Recursion
  if (options.recursion) {
    args.push("-recursion");
    if (options.recursionDepth) {
      args.push(`-recursion-depth ${options.recursionDepth}`);
    }
    if (options.recursionStrategy) {
      args.push(`-recursion-strategy ${options.recursionStrategy}`);
    }
  }

  // Performance
  if (options.threads) {
    args.push(`-t ${options.threads}`);
  }
  if (options.delay) {
    args.push(`-p ${options.delay}`);
  }
  if (options.rate) {
    args.push(`-rate ${options.rate}`);
  }
  if (options.timeout) {
    args.push(`-timeout ${options.timeout}`);
  }
  if (options.maxtime) {
    args.push(`-maxtime ${options.maxtime}`);
  }

  // Behavior
  if (options.followRedirects) {
    args.push("-r");
  }

  // Extensions
  if (options.extensions) {
    args.push(`-e ${options.extensions}`);
  }

  // Mode
  if (options.mode) {
    args.push(`-mode ${options.mode}`);
  }

  // Proxy
  if (options.proxy) {
    args.push(`-x ${options.proxy}`);
  }

  // Output
  if (options.outputFormat) {
    args.push(`-of ${options.outputFormat}`);
  }

  // Display options
  if (options.verbose) {
    args.push("-v");
  }
  if (options.silent) {
    args.push("-s");
  }
  if (options.colors !== false) {
    args.push("-c");
  }

  // Non-interactive mode (required for automation)
  args.push("-noninteractive");

  return args.join(" ");
}

/**
 * Parse ffuf output
 */
function parseFfufOutput(stdout: string, stderr: string): any {
  const lines = stdout.split("\n").filter((l) => l.trim());
  const results: any[] = [];

  // Parse results
  for (const line of lines) {
    // Match lines like: "admin [Status: 200, Size: 1234, Words: 56, Lines: 12]"
    const match = line.match(/^(\S+)\s+\[Status:\s*(\d+),\s*Size:\s*(\d+),\s*Words:\s*(\d+),\s*Lines:\s*(\d+)/);
    if (match) {
      results.push({
        path: match[1],
        status: parseInt(match[2]),
        size: parseInt(match[3]),
        words: parseInt(match[4]),
        lines: parseInt(match[5]),
      });
    }
  }

  // Extract statistics
  const statsMatch = stdout.match(/:: Progress.*?(\d+)\/(\d+)/);
  const timeMatch = stdout.match(/Duration:\s*(\S+)/);

  return {
    results,
    total: results.length,
    statistics: {
      progress: statsMatch ? `${statsMatch[1]}/${statsMatch[2]}` : "unknown",
      duration: timeMatch ? timeMatch[1] : "unknown",
    },
    rawOutput: stdout,
    errors: stderr || null,
  };
}

// Create server
const server = new Server(
  {
    name: "ffuf-mcp",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// List available tools
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "ffuf_fuzz",
        description: "Run ffuf web fuzzing against a target URL. Use FUZZ keyword in URL to mark injection point. Executes on Kali Linux via SSH.",
        inputSchema: {
          type: "object",
          properties: {
            url: {
              type: "string",
              description: "Target URL with FUZZ keyword marking injection point (e.g., 'https://target.com/FUZZ')",
            },
            wordlist: {
              type: "string",
              enum: Object.keys(WORDLISTS),
              description: "Predefined wordlist to use (common, big, dirbuster_medium, seclists_common, subdomains, etc.)",
            },
            wordlistPath: {
              type: "string",
              description: "Custom wordlist path on Kali (overrides wordlist preset)",
            },
            method: {
              type: "string",
              enum: ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"],
              description: "HTTP method (default: GET)",
            },
            headers: {
              type: "object",
              additionalProperties: { type: "string" },
              description: "Custom headers as key-value pairs",
            },
            data: {
              type: "string",
              description: "POST data (use FUZZ for injection point)",
            },
            cookies: {
              type: "string",
              description: "Cookie data (NAME=VALUE; NAME2=VALUE2)",
            },
            extensions: {
              type: "string",
              description: "File extensions to append (comma-separated, e.g., '.php,.html,.txt')",
            },
            threads: {
              type: "number",
              description: "Number of concurrent threads (default: 40)",
            },
            delay: {
              type: "string",
              description: "Delay between requests (e.g., '0.1' or '0.1-2.0' for range)",
            },
            rate: {
              type: "number",
              description: "Rate limit requests per second",
            },
            maxtime: {
              type: "number",
              description: "Maximum runtime in seconds",
            },
            followRedirects: {
              type: "boolean",
              description: "Follow HTTP redirects",
            },
            verbose: {
              type: "boolean",
              description: "Verbose output with full URLs",
            },
            proxy: {
              type: "string",
              description: "HTTP/SOCKS proxy (e.g., 'http://127.0.0.1:8080')",
            },
          },
          required: ["url"],
        },
      },
      {
        name: "ffuf_matchers",
        description: "Run ffuf with specific response matchers (status codes, size, words, lines, regex)",
        inputSchema: {
          type: "object",
          properties: {
            url: {
              type: "string",
              description: "Target URL with FUZZ keyword",
            },
            wordlist: {
              type: "string",
              enum: Object.keys(WORDLISTS),
              description: "Wordlist to use",
            },
            matchCodes: {
              type: "string",
              description: "Match HTTP status codes (e.g., '200,301,302' or 'all')",
            },
            matchSize: {
              type: "string",
              description: "Match response size (bytes)",
            },
            matchWords: {
              type: "string",
              description: "Match word count",
            },
            matchLines: {
              type: "string",
              description: "Match line count",
            },
            matchRegex: {
              type: "string",
              description: "Match response body regex",
            },
          },
          required: ["url"],
        },
      },
      {
        name: "ffuf_filters",
        description: "Run ffuf with response filters to exclude unwanted results",
        inputSchema: {
          type: "object",
          properties: {
            url: {
              type: "string",
              description: "Target URL with FUZZ keyword",
            },
            wordlist: {
              type: "string",
              enum: Object.keys(WORDLISTS),
              description: "Wordlist to use",
            },
            filterCodes: {
              type: "string",
              description: "Filter out HTTP status codes (e.g., '404,403')",
            },
            filterSize: {
              type: "string",
              description: "Filter out response sizes (bytes)",
            },
            filterWords: {
              type: "string",
              description: "Filter out word counts",
            },
            filterLines: {
              type: "string",
              description: "Filter out line counts",
            },
            filterRegex: {
              type: "string",
              description: "Filter out responses matching regex",
            },
          },
          required: ["url"],
        },
      },
      {
        name: "ffuf_recursion",
        description: "Run ffuf with recursive directory scanning",
        inputSchema: {
          type: "object",
          properties: {
            url: {
              type: "string",
              description: "Target URL ending with FUZZ (e.g., 'https://target.com/FUZZ')",
            },
            wordlist: {
              type: "string",
              enum: Object.keys(WORDLISTS),
              description: "Wordlist to use",
            },
            depth: {
              type: "number",
              description: "Maximum recursion depth (default: 2)",
            },
            strategy: {
              type: "string",
              enum: ["default", "greedy"],
              description: "Recursion strategy: default (redirect-based) or greedy (all matches)",
            },
            maxtime: {
              type: "number",
              description: "Maximum runtime per job in seconds",
            },
          },
          required: ["url"],
        },
      },
      {
        name: "ffuf_subdomain",
        description: "Fuzz for subdomains using Host header injection",
        inputSchema: {
          type: "object",
          properties: {
            domain: {
              type: "string",
              description: "Target domain (e.g., 'example.com')",
            },
            url: {
              type: "string",
              description: "Target URL (defaults to https://domain/)",
            },
            wordlist: {
              type: "string",
              enum: Object.keys(WORDLISTS),
              description: "Subdomain wordlist (default: subdomains)",
            },
            filterSize: {
              type: "string",
              description: "Filter out response sizes (to remove default page)",
            },
          },
          required: ["domain"],
        },
      },
      {
        name: "ffuf_vhost",
        description: "Virtual host discovery by fuzzing Host header",
        inputSchema: {
          type: "object",
          properties: {
            ip: {
              type: "string",
              description: "Target IP address or hostname",
            },
            domain: {
              type: "string",
              description: "Base domain for vhost names",
            },
            wordlist: {
              type: "string",
              enum: Object.keys(WORDLISTS),
              description: "Wordlist for vhost names",
            },
            filterSize: {
              type: "string",
              description: "Filter out default response size",
            },
          },
          required: ["ip", "domain"],
        },
      },
      {
        name: "ffuf_parameter",
        description: "Fuzz for hidden parameters in GET or POST requests",
        inputSchema: {
          type: "object",
          properties: {
            url: {
              type: "string",
              description: "Target URL (FUZZ will be added as parameter name)",
            },
            method: {
              type: "string",
              enum: ["GET", "POST"],
              description: "HTTP method (default: GET)",
            },
            paramValue: {
              type: "string",
              description: "Value to use for parameter testing (default: 'test')",
            },
            wordlist: {
              type: "string",
              enum: Object.keys(WORDLISTS),
              description: "Parameter wordlist (default: parameters)",
            },
            filterSize: {
              type: "string",
              description: "Filter out response sizes",
            },
          },
          required: ["url"],
        },
      },
      {
        name: "ffuf_wordlists",
        description: "List available predefined wordlists on Kali",
        inputSchema: {
          type: "object",
          properties: {},
        },
      },
      {
        name: "ffuf_status",
        description: "Check if ffuf is available on Kali and get version",
        inputSchema: {
          type: "object",
          properties: {},
        },
      },
    ],
  };
});

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args = {} } = request.params;

  try {
    switch (name) {
      case "ffuf_fuzz": {
        const options: FfufOptions = {
          url: args.url as string,
          wordlist: args.wordlist as string,
          wordlistPath: args.wordlistPath as string,
          method: args.method as string,
          headers: args.headers as Record<string, string>,
          data: args.data as string,
          cookies: args.cookies as string,
          extensions: args.extensions as string,
          threads: (args.threads as number) || DEFAULT_THREADS,
          delay: args.delay as string,
          rate: args.rate as number,
          maxtime: args.maxtime as number,
          followRedirects: args.followRedirects as boolean,
          verbose: args.verbose as boolean,
          proxy: args.proxy as string,
        };

        const command = buildFfufCommand(options);
        const timeout = options.maxtime || DEFAULT_TIMEOUT;
        const { stdout, stderr } = await executeSSH(command, timeout + 60);
        const result = parseFfufOutput(stdout, stderr);

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                command,
                ...result,
              }, null, 2),
            },
          ],
        };
      }

      case "ffuf_matchers": {
        const options: FfufOptions = {
          url: args.url as string,
          wordlist: args.wordlist as string,
          matchCodes: args.matchCodes as string,
          matchSize: args.matchSize as string,
          matchWords: args.matchWords as string,
          matchLines: args.matchLines as string,
          matchRegex: args.matchRegex as string,
        };

        const command = buildFfufCommand(options);
        const { stdout, stderr } = await executeSSH(command);
        const result = parseFfufOutput(stdout, stderr);

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                command,
                ...result,
              }, null, 2),
            },
          ],
        };
      }

      case "ffuf_filters": {
        const options: FfufOptions = {
          url: args.url as string,
          wordlist: args.wordlist as string,
          filterCodes: args.filterCodes as string,
          filterSize: args.filterSize as string,
          filterWords: args.filterWords as string,
          filterLines: args.filterLines as string,
          filterRegex: args.filterRegex as string,
        };

        const command = buildFfufCommand(options);
        const { stdout, stderr } = await executeSSH(command);
        const result = parseFfufOutput(stdout, stderr);

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                command,
                ...result,
              }, null, 2),
            },
          ],
        };
      }

      case "ffuf_recursion": {
        const options: FfufOptions = {
          url: args.url as string,
          wordlist: args.wordlist as string,
          recursion: true,
          recursionDepth: (args.depth as number) || 2,
          recursionStrategy: args.strategy as "default" | "greedy",
          maxtime: args.maxtime as number,
        };

        const command = buildFfufCommand(options);
        const timeout = options.maxtime ? options.maxtime + 60 : DEFAULT_TIMEOUT * 2;
        const { stdout, stderr } = await executeSSH(command, timeout);
        const result = parseFfufOutput(stdout, stderr);

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                command,
                ...result,
              }, null, 2),
            },
          ],
        };
      }

      case "ffuf_subdomain": {
        const domain = args.domain as string;
        const url = (args.url as string) || `https://${domain}/`;
        const wordlist = (args.wordlist as string) || "subdomains";

        const options: FfufOptions = {
          url,
          wordlist,
          headers: { Host: `FUZZ.${domain}` },
          filterSize: args.filterSize as string,
        };

        const command = buildFfufCommand(options);
        const { stdout, stderr } = await executeSSH(command);
        const result = parseFfufOutput(stdout, stderr);

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                command,
                domain,
                ...result,
              }, null, 2),
            },
          ],
        };
      }

      case "ffuf_vhost": {
        const ip = args.ip as string;
        const domain = args.domain as string;
        const wordlist = (args.wordlist as string) || "subdomains";

        const options: FfufOptions = {
          url: `http://${ip}/`,
          wordlist,
          headers: { Host: `FUZZ.${domain}` },
          filterSize: args.filterSize as string,
        };

        const command = buildFfufCommand(options);
        const { stdout, stderr } = await executeSSH(command);
        const result = parseFfufOutput(stdout, stderr);

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                command,
                ip,
                domain,
                ...result,
              }, null, 2),
            },
          ],
        };
      }

      case "ffuf_parameter": {
        const baseUrl = args.url as string;
        const method = (args.method as string) || "GET";
        const paramValue = (args.paramValue as string) || "test";
        const wordlist = (args.wordlist as string) || "parameters";

        let options: FfufOptions;

        if (method === "GET") {
          const separator = baseUrl.includes("?") ? "&" : "?";
          options = {
            url: `${baseUrl}${separator}FUZZ=${paramValue}`,
            wordlist,
            filterSize: args.filterSize as string,
          };
        } else {
          options = {
            url: baseUrl,
            wordlist,
            method: "POST",
            data: `FUZZ=${paramValue}`,
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            filterSize: args.filterSize as string,
          };
        }

        const command = buildFfufCommand(options);
        const { stdout, stderr } = await executeSSH(command);
        const result = parseFfufOutput(stdout, stderr);

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                command,
                method,
                ...result,
              }, null, 2),
            },
          ],
        };
      }

      case "ffuf_wordlists": {
        const wordlistInfo = Object.entries(WORDLISTS).map(([name, path]) => ({
          name,
          path,
          description: getWordlistDescription(name),
        }));

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                wordlists: wordlistInfo,
                note: "Use 'wordlist' parameter with the name, or 'wordlistPath' for custom paths",
              }, null, 2),
            },
          ],
        };
      }

      case "ffuf_status": {
        const { stdout, stderr } = await executeSSH("ffuf -V && which ffuf", 30);

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                status: stderr ? "error" : "available",
                version: stdout.trim(),
                host: KALI_HOST,
                error: stderr || null,
              }, null, 2),
            },
          ],
        };
      }

      default:
        throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${name}`);
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

function getWordlistDescription(name: string): string {
  const descriptions: Record<string, string> = {
    common: "Common directory/file names (4614 entries)",
    big: "Larger common list (20469 entries)",
    small: "Quick scan list (959 entries)",
    dirbuster_small: "DirBuster small list (~87k entries)",
    dirbuster_medium: "DirBuster medium list (~220k entries)",
    dirbuster_big: "DirBuster big list (~1.27M entries)",
    seclists_common: "SecLists common web content",
    seclists_directories: "SecLists directory list medium",
    subdomains: "Top 5000 subdomains",
    parameters: "Burp parameter names",
    api_endpoints: "Common API endpoints",
  };
  return descriptions[name] || "Custom wordlist";
}

// Start server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("FFUF MCP server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
