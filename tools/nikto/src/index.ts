#!/usr/bin/env node
/**
 * Nikto MCP Server
 *
 * An MCP server that provides tools for running Nikto web server scanner
 * via SSH to a Kali Linux host.
 *
 * Tools:
 * - nikto_scan: Start a web server vulnerability scan
 * - nikto_plugins: List available Nikto plugins
 * - nikto_tuning: Get tuning options reference
 * - nikto_evasion: Get IDS evasion techniques reference
 * - nikto_update: Update Nikto databases
 * - nikto_version: Get Nikto version info
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { spawn } from "child_process";

// Configuration
const KALI_HOST = process.env.KALI_HOST || "kali";
const SSH_USER = process.env.SSH_USER || "";
const SSH_OPTIONS = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10"];
const DEFAULT_TIMEOUT = parseInt(process.env.NIKTO_TIMEOUT || "300000", 10); // 5 minutes default

// Active scans tracking
interface ScanState {
  id: string;
  target: string;
  status: "running" | "completed" | "error" | "cancelled";
  startTime: Date;
  output: string;
  error?: string;
}

const activeScans = new Map<string, ScanState>();

/**
 * Execute command via SSH to Kali
 */
async function sshExec(
  command: string,
  timeout: number = DEFAULT_TIMEOUT
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  return new Promise((resolve, reject) => {
    const sshTarget = SSH_USER ? `${SSH_USER}@${KALI_HOST}` : KALI_HOST;
    const args = [...SSH_OPTIONS, sshTarget, command];

    const proc = spawn("ssh", args, {
      timeout,
      stdio: ["pipe", "pipe", "pipe"],
    });

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
        stdout,
        stderr,
        exitCode: code ?? 1,
      });
    });

    proc.on("error", (err) => {
      reject(new Error(`SSH execution failed: ${err.message}`));
    });

    // Handle timeout
    setTimeout(() => {
      proc.kill("SIGTERM");
      reject(new Error(`Command timed out after ${timeout}ms`));
    }, timeout);
  });
}

/**
 * Generate unique scan ID
 */
function generateScanId(): string {
  return `nikto-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;
}

/**
 * Build nikto command from options
 */
function buildNiktoCommand(options: {
  target: string;
  port?: number | string;
  ssl?: boolean;
  nossl?: boolean;
  tuning?: string;
  plugins?: string;
  evasion?: string;
  timeout?: number;
  pause?: number;
  vhost?: string;
  id?: string;
  root?: string;
  cgidirs?: string;
  useproxy?: boolean;
  nolookup?: boolean;
  no404?: boolean;
  findonly?: boolean;
  mutate?: string;
  format?: string;
  output?: string;
}): string {
  const args: string[] = ["nikto"];

  // Target (required)
  args.push("-h", `"${options.target}"`);

  // Port
  if (options.port) {
    args.push("-p", String(options.port));
  }

  // SSL options
  if (options.ssl) {
    args.push("-ssl");
  }
  if (options.nossl) {
    args.push("-nossl");
  }

  // Tuning (test categories)
  if (options.tuning) {
    args.push("-Tuning", options.tuning);
  }

  // Plugins
  if (options.plugins) {
    args.push("-Plugins", options.plugins);
  }

  // Evasion techniques
  if (options.evasion) {
    args.push("-evasion", options.evasion);
  }

  // Timeout per request
  if (options.timeout) {
    args.push("-timeout", String(options.timeout));
  }

  // Pause between requests
  if (options.pause) {
    args.push("-Pause", String(options.pause));
  }

  // Virtual host
  if (options.vhost) {
    args.push("-vhost", `"${options.vhost}"`);
  }

  // Authentication
  if (options.id) {
    args.push("-id", `"${options.id}"`);
  }

  // Root path
  if (options.root) {
    args.push("-root", `"${options.root}"`);
  }

  // CGI directories
  if (options.cgidirs) {
    args.push("-Cgidirs", options.cgidirs);
  }

  // Proxy
  if (options.useproxy) {
    args.push("-useproxy");
  }

  // No DNS lookup
  if (options.nolookup) {
    args.push("-nolookup");
  }

  // No 404 checking
  if (options.no404) {
    args.push("-no404");
  }

  // Find only (port discovery)
  if (options.findonly) {
    args.push("-findonly");
  }

  // Mutation techniques
  if (options.mutate) {
    args.push("-mutate", options.mutate);
  }

  // Output format
  if (options.format) {
    args.push("-Format", options.format);
  }

  // Output file
  if (options.output) {
    args.push("-o", options.output);
  }

  return args.join(" ");
}

// Define tools
const tools: Tool[] = [
  {
    name: "nikto_scan",
    description: `Start a Nikto web server vulnerability scan via SSH to Kali Linux.

Nikto performs comprehensive tests against web servers for multiple items, including:
- Over 6700 potentially dangerous files/programs
- Server version checks
- Server configuration issues
- Default files and programs
- Insecure CGI scripts`,
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target URL, IP address, or hostname to scan (required)",
        },
        port: {
          type: "string",
          description: "TCP port(s) to scan. Can be single port (80), range (80-90), or comma-separated (80,443,8080). Default: 80",
        },
        ssl: {
          type: "boolean",
          description: "Force SSL/HTTPS testing on specified ports",
        },
        nossl: {
          type: "boolean",
          description: "Disable SSL testing",
        },
        tuning: {
          type: "string",
          description: `Test tuning options (combine multiple):
0 - File Upload
1 - Interesting File / Seen in logs
2 - Misconfiguration / Default File
3 - Information Disclosure
4 - Injection (XSS/Script/HTML)
5 - Remote File Retrieval - Inside Web Root
6 - Denial of Service
7 - Remote File Retrieval - Server Wide
8 - Command Execution / Remote Shell
9 - SQL Injection
a - Authentication Bypass
b - Software Identification
c - Remote Source Inclusion
x - Reverse Tuning (exclude specified)`,
        },
        plugins: {
          type: "string",
          description: "Comma-separated list of plugins to run (use nikto_plugins to list available)",
        },
        evasion: {
          type: "string",
          description: `IDS evasion technique(s) (combine multiple):
1 - Random URI encoding (non-UTF8)
2 - Directory self-reference (/./
3 - Premature URL ending
4 - Prepend long random string
5 - Fake parameter
6 - TAB as request spacer
7 - Change the case of the URL
8 - Use Windows directory separator (\\)`,
        },
        timeout: {
          type: "number",
          description: "Seconds to wait before timing out a request (default: 10)",
        },
        pause: {
          type: "number",
          description: "Seconds to delay between each test (for rate limiting)",
        },
        vhost: {
          type: "string",
          description: "Virtual host header to send to the target",
        },
        id: {
          type: "string",
          description: "HTTP Basic authentication credentials (format: id:password)",
        },
        root: {
          type: "string",
          description: "Prepend this path to all requests (e.g., /app)",
        },
        cgidirs: {
          type: "string",
          description: "CGI directories to scan. Use 'all' or 'none', or specify custom paths",
        },
        useproxy: {
          type: "boolean",
          description: "Use HTTP proxy defined in Nikto configuration",
        },
        nolookup: {
          type: "boolean",
          description: "Disable DNS lookups",
        },
        no404: {
          type: "boolean",
          description: "Disable 404 (file not found) checking",
        },
        findonly: {
          type: "boolean",
          description: "Only discover HTTP(S) ports without performing security scan",
        },
        mutate: {
          type: "string",
          description: `Mutation techniques:
1 - Test all files with all root directories
2 - Guess for password file names
3 - Enumerate user names via Apache (/~user)
4 - Enumerate user names via cgiwrap (/cgi-bin/cgiwrap/~user)
5 - Attempt to brute force sub-domain names
6 - Attempt to guess directory names from supplied dictionary`,
        },
        format: {
          type: "string",
          enum: ["csv", "htm", "txt", "xml", "json"],
          description: "Output format (default: text to stdout)",
        },
        scan_timeout: {
          type: "number",
          description: "Overall scan timeout in seconds (default: 300)",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "nikto_plugins",
    description: "List all available Nikto plugins that can be used with nikto_scan",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "nikto_tuning",
    description: "Get detailed reference for Nikto tuning options (test categories)",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "nikto_evasion",
    description: "Get detailed reference for Nikto IDS evasion techniques",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "nikto_update",
    description: "Update Nikto plugins and databases from cirt.net",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "nikto_version",
    description: "Get Nikto version and database information",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "nikto_check_db",
    description: "Check Nikto scan databases for syntax errors",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
];

// Create server
const server = new Server(
  {
    name: "nikto-mcp",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Handle list tools
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return { tools };
});

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case "nikto_scan": {
        const scanArgs = args as {
          target: string;
          port?: string;
          ssl?: boolean;
          nossl?: boolean;
          tuning?: string;
          plugins?: string;
          evasion?: string;
          timeout?: number;
          pause?: number;
          vhost?: string;
          id?: string;
          root?: string;
          cgidirs?: string;
          useproxy?: boolean;
          nolookup?: boolean;
          no404?: boolean;
          findonly?: boolean;
          mutate?: string;
          format?: string;
          scan_timeout?: number;
        };

        if (!scanArgs.target) {
          return {
            content: [
              {
                type: "text",
                text: "Error: target is required",
              },
            ],
            isError: true,
          };
        }

        // Validate target (basic sanitization)
        const target = scanArgs.target.trim();
        if (target.includes(";") || target.includes("&") || target.includes("|") || target.includes("`")) {
          return {
            content: [
              {
                type: "text",
                text: "Error: Invalid characters in target. Potential command injection detected.",
              },
            ],
            isError: true,
          };
        }

        const scanId = generateScanId();
        const scanTimeout = (scanArgs.scan_timeout || 300) * 1000;

        // Build the command
        const command = buildNiktoCommand({
          ...scanArgs,
          target,
        });

        // Track scan
        const scanState: ScanState = {
          id: scanId,
          target,
          status: "running",
          startTime: new Date(),
          output: "",
        };
        activeScans.set(scanId, scanState);

        try {
          const result = await sshExec(command, scanTimeout);

          scanState.status = result.exitCode === 0 ? "completed" : "error";
          scanState.output = result.stdout;
          if (result.stderr) {
            scanState.error = result.stderr;
          }

          return {
            content: [
              {
                type: "text",
                text: `# Nikto Scan Results

**Scan ID:** ${scanId}
**Target:** ${target}
**Status:** ${scanState.status}
**Duration:** ${Math.round((Date.now() - scanState.startTime.getTime()) / 1000)}s

## Command Executed
\`\`\`
${command}
\`\`\`

## Output
\`\`\`
${result.stdout || "(no output)"}
\`\`\`

${result.stderr ? `## Errors/Warnings\n\`\`\`\n${result.stderr}\n\`\`\`` : ""}

**Exit Code:** ${result.exitCode}`,
              },
            ],
          };
        } catch (error) {
          scanState.status = "error";
          scanState.error = error instanceof Error ? error.message : String(error);

          return {
            content: [
              {
                type: "text",
                text: `# Nikto Scan Failed

**Scan ID:** ${scanId}
**Target:** ${target}
**Error:** ${scanState.error}

## Command Attempted
\`\`\`
${command}
\`\`\`

**Tip:** Ensure SSH connectivity to Kali host (${KALI_HOST}) is working.`,
              },
            ],
            isError: true,
          };
        }
      }

      case "nikto_plugins": {
        try {
          const result = await sshExec("nikto -list-plugins", 30000);

          return {
            content: [
              {
                type: "text",
                text: `# Available Nikto Plugins

${result.stdout || "Unable to retrieve plugin list"}

${result.stderr ? `## Notes\n${result.stderr}` : ""}

**Usage:** Use the \`plugins\` parameter in nikto_scan to specify which plugins to run.
Example: \`plugins: "apacheusers,cgi,headers"\``,
              },
            ],
          };
        } catch (error) {
          return {
            content: [
              {
                type: "text",
                text: `Error listing plugins: ${error instanceof Error ? error.message : String(error)}`,
              },
            ],
            isError: true,
          };
        }
      }

      case "nikto_tuning": {
        return {
          content: [
            {
              type: "text",
              text: `# Nikto Tuning Options

Tuning options control which test categories Nikto runs. You can combine multiple options.

## Test Categories

| Code | Category | Description |
|------|----------|-------------|
| 0 | File Upload | Tests for file upload vulnerabilities |
| 1 | Interesting File | Files seen in logs, may indicate compromise |
| 2 | Misconfiguration | Default files, misconfigurations |
| 3 | Information Disclosure | Information leakage issues |
| 4 | Injection | XSS, Script injection, HTML injection |
| 5 | Remote File Retrieval (Web Root) | Files retrievable within web root |
| 6 | Denial of Service | DoS vulnerabilities |
| 7 | Remote File Retrieval (Server Wide) | Files retrievable anywhere on server |
| 8 | Command Execution | Remote shell, command injection |
| 9 | SQL Injection | SQL injection vulnerabilities |
| a | Authentication Bypass | Auth bypass vulnerabilities |
| b | Software Identification | Version/software identification |
| c | Remote Source Inclusion | Remote file inclusion |

## Special Options

| Code | Function |
|------|----------|
| x | Reverse (exclude) - Use with other codes to EXCLUDE those tests |

## Examples

- \`tuning: "123"\` - Run File Upload, Interesting Files, and Misconfiguration tests
- \`tuning: "x6"\` - Run all tests EXCEPT Denial of Service
- \`tuning: "49"\` - Focus on Injection and SQL Injection only

**Usage:** Use the \`tuning\` parameter in nikto_scan.`,
            },
          ],
        };
      }

      case "nikto_evasion": {
        return {
          content: [
            {
              type: "text",
              text: `# Nikto IDS Evasion Techniques

Evasion techniques help bypass Intrusion Detection Systems (IDS) during scans.

## Available Techniques

| Code | Technique | Description |
|------|-----------|-------------|
| 1 | Random URI encoding | Encode characters with non-UTF8 encoding |
| 2 | Directory self-reference | Add /./ to paths |
| 3 | Premature URL ending | End URL prematurely |
| 4 | Long random string | Prepend long random strings to paths |
| 5 | Fake parameter | Add fake query parameters |
| 6 | TAB spacer | Use TAB instead of space in requests |
| 7 | Case variation | Randomly change URL case |
| 8 | Windows separator | Use backslash (\\) instead of forward slash |

## Examples

- \`evasion: "1"\` - Use random URI encoding
- \`evasion: "124"\` - Combine encoding, self-reference, and long strings
- \`evasion: "12345678"\` - Use all evasion techniques

## Notes

- Evasion techniques can slow down scans
- Some techniques may cause false negatives
- Use responsibly and only on systems you have permission to test

**Usage:** Use the \`evasion\` parameter in nikto_scan.`,
            },
          ],
        };
      }

      case "nikto_update": {
        try {
          const result = await sshExec("nikto -update", 120000);

          return {
            content: [
              {
                type: "text",
                text: `# Nikto Database Update

${result.stdout || "Update completed"}

${result.stderr ? `## Messages\n${result.stderr}` : ""}

**Note:** Updates are downloaded from cirt.net`,
              },
            ],
          };
        } catch (error) {
          return {
            content: [
              {
                type: "text",
                text: `Error updating Nikto: ${error instanceof Error ? error.message : String(error)}`,
              },
            ],
            isError: true,
          };
        }
      }

      case "nikto_version": {
        try {
          const result = await sshExec("nikto -Version", 15000);

          return {
            content: [
              {
                type: "text",
                text: `# Nikto Version Information

${result.stdout || "Unable to retrieve version"}

${result.stderr ? result.stderr : ""}`,
              },
            ],
          };
        } catch (error) {
          return {
            content: [
              {
                type: "text",
                text: `Error getting version: ${error instanceof Error ? error.message : String(error)}`,
              },
            ],
            isError: true,
          };
        }
      }

      case "nikto_check_db": {
        try {
          const result = await sshExec("nikto -dbcheck", 30000);

          return {
            content: [
              {
                type: "text",
                text: `# Nikto Database Check

${result.stdout || "Database check completed"}

${result.stderr ? `## Issues Found\n${result.stderr}` : "## Status\nNo syntax errors detected."}`,
              },
            ],
          };
        } catch (error) {
          return {
            content: [
              {
                type: "text",
                text: `Error checking database: ${error instanceof Error ? error.message : String(error)}`,
              },
            ],
            isError: true,
          };
        }
      }

      default:
        return {
          content: [
            {
              type: "text",
              text: `Unknown tool: ${name}`,
            },
          ],
          isError: true,
        };
    }
  } catch (error) {
    return {
      content: [
        {
          type: "text",
          text: `Error executing ${name}: ${error instanceof Error ? error.message : String(error)}`,
        },
      ],
      isError: true,
    };
  }
});

// Main entry point
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Nikto MCP server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
