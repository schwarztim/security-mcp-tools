#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { exec, spawn } from "child_process";
import { promisify } from "util";

const execAsync = promisify(exec);

// Configuration
const KALI_HOST = process.env.KALI_HOST || "kali";
const SSH_OPTIONS = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10";
const DEFAULT_WORDLIST = "/usr/share/wordlists/dirb/common.txt";
const DEFAULT_DNS_WORDLIST = "/usr/share/wordlists/subdomains-top1million-5000.txt";

// Type definitions for tool arguments
interface DirArgs {
  url: string;
  wordlist?: string;
  extensions?: string;
  threads?: number;
  status_codes?: string;
  exclude_status?: string;
  cookies?: string;
  headers?: string[];
  user_agent?: string;
  timeout?: number;
  follow_redirect?: boolean;
  no_tls_validation?: boolean;
  show_length?: boolean;
  expanded?: boolean;
  quiet?: boolean;
  async?: boolean;
}

interface DnsArgs {
  domain: string;
  wordlist?: string;
  resolver?: string;
  threads?: number;
  show_ips?: boolean;
  show_cname?: boolean;
  timeout?: number;
  wildcard?: boolean;
  quiet?: boolean;
  async?: boolean;
}

interface VhostArgs {
  url: string;
  wordlist?: string;
  domain?: string;
  threads?: number;
  cookies?: string;
  headers?: string[];
  user_agent?: string;
  timeout?: number;
  follow_redirect?: boolean;
  no_tls_validation?: boolean;
  exclude_length?: string;
  quiet?: boolean;
  async?: boolean;
}

interface FuzzArgs {
  url: string;
  wordlist?: string;
  threads?: number;
  post_data?: string;
  headers?: string[];
  cookies?: string;
  method?: string;
  exclude_status?: string;
  exclude_length?: string;
  timeout?: number;
  no_tls_validation?: boolean;
  quiet?: boolean;
  async?: boolean;
}

interface S3Args {
  wordlist: string;
  threads?: number;
  max_files?: number;
  quiet?: boolean;
  async?: boolean;
}

interface TftpArgs {
  server: string;
  wordlist?: string;
  threads?: number;
  timeout?: number;
  quiet?: boolean;
  async?: boolean;
}

interface StatusArgs {
  scan_id: string;
}

interface StopArgs {
  scan_id: string;
}

interface WordlistArgs {
  category?: string;
}

// Active scans tracking
const activeScans: Map<string, {
  process: ReturnType<typeof spawn> | null;
  output: string[];
  status: "running" | "completed" | "error";
  startTime: Date;
  mode: string;
  target: string;
}> = new Map();

// Tool definitions
const tools: Tool[] = [
  {
    name: "gobuster_dir",
    description: "Directory/file enumeration mode - discovers hidden directories and files on web servers using wordlist-based brute forcing. Executes on remote Kali host via SSH.",
    inputSchema: {
      type: "object",
      properties: {
        url: {
          type: "string",
          description: "Target URL (e.g., https://example.com or https://example.com/path)"
        },
        wordlist: {
          type: "string",
          description: `Path to wordlist file on Kali (default: ${DEFAULT_WORDLIST})`
        },
        extensions: {
          type: "string",
          description: "File extensions to search for, comma-separated (e.g., php,html,txt,js)"
        },
        threads: {
          type: "number",
          description: "Number of concurrent threads (default: 10)"
        },
        status_codes: {
          type: "string",
          description: "Positive status codes to match, comma-separated (e.g., 200,204,301,302)"
        },
        exclude_status: {
          type: "string",
          description: "Status codes to exclude, comma-separated (e.g., 404,403)"
        },
        cookies: {
          type: "string",
          description: "Cookies to use for requests (e.g., session=abc123)"
        },
        headers: {
          type: "array",
          items: { type: "string" },
          description: "Custom headers (e.g., ['Authorization: Bearer token', 'X-Custom: value'])"
        },
        user_agent: {
          type: "string",
          description: "Custom User-Agent string"
        },
        timeout: {
          type: "number",
          description: "HTTP timeout in seconds (default: 10)"
        },
        follow_redirect: {
          type: "boolean",
          description: "Follow redirects (default: false)"
        },
        no_tls_validation: {
          type: "boolean",
          description: "Skip TLS certificate verification (default: false)"
        },
        show_length: {
          type: "boolean",
          description: "Show response length (default: true)"
        },
        expanded: {
          type: "boolean",
          description: "Expanded mode, print full URLs (default: false)"
        },
        quiet: {
          type: "boolean",
          description: "Don't print banner and other noise (default: false)"
        },
        async: {
          type: "boolean",
          description: "Run scan asynchronously and return scan ID (default: false)"
        }
      },
      required: ["url"]
    }
  },
  {
    name: "gobuster_dns",
    description: "DNS subdomain enumeration mode - discovers subdomains for a target domain using wordlist-based brute forcing. Executes on remote Kali host via SSH.",
    inputSchema: {
      type: "object",
      properties: {
        domain: {
          type: "string",
          description: "Target domain (e.g., example.com)"
        },
        wordlist: {
          type: "string",
          description: `Path to wordlist file on Kali (default: ${DEFAULT_DNS_WORDLIST})`
        },
        resolver: {
          type: "string",
          description: "Custom DNS resolver (e.g., 8.8.8.8 or 8.8.8.8:53)"
        },
        threads: {
          type: "number",
          description: "Number of concurrent threads (default: 10)"
        },
        show_ips: {
          type: "boolean",
          description: "Show IP addresses for found subdomains (default: true)"
        },
        show_cname: {
          type: "boolean",
          description: "Show CNAME records (default: false)"
        },
        timeout: {
          type: "number",
          description: "DNS timeout in seconds (default: 1)"
        },
        wildcard: {
          type: "boolean",
          description: "Force wildcards check (default: false)"
        },
        quiet: {
          type: "boolean",
          description: "Don't print banner and other noise (default: false)"
        },
        async: {
          type: "boolean",
          description: "Run scan asynchronously and return scan ID (default: false)"
        }
      },
      required: ["domain"]
    }
  },
  {
    name: "gobuster_vhost",
    description: "Virtual host enumeration mode - discovers virtual hosts on a web server by brute forcing Host header values. Executes on remote Kali host via SSH.",
    inputSchema: {
      type: "object",
      properties: {
        url: {
          type: "string",
          description: "Target URL (e.g., https://example.com)"
        },
        wordlist: {
          type: "string",
          description: `Path to wordlist file on Kali (default: ${DEFAULT_WORDLIST})`
        },
        domain: {
          type: "string",
          description: "Domain to append to wordlist entries (--append-domain)"
        },
        threads: {
          type: "number",
          description: "Number of concurrent threads (default: 10)"
        },
        cookies: {
          type: "string",
          description: "Cookies to use for requests"
        },
        headers: {
          type: "array",
          items: { type: "string" },
          description: "Custom headers"
        },
        user_agent: {
          type: "string",
          description: "Custom User-Agent string"
        },
        timeout: {
          type: "number",
          description: "HTTP timeout in seconds (default: 10)"
        },
        follow_redirect: {
          type: "boolean",
          description: "Follow redirects (default: false)"
        },
        no_tls_validation: {
          type: "boolean",
          description: "Skip TLS certificate verification (default: false)"
        },
        exclude_length: {
          type: "string",
          description: "Exclude results with these response lengths, comma-separated"
        },
        quiet: {
          type: "boolean",
          description: "Don't print banner and other noise (default: false)"
        },
        async: {
          type: "boolean",
          description: "Run scan asynchronously and return scan ID (default: false)"
        }
      },
      required: ["url"]
    }
  },
  {
    name: "gobuster_fuzz",
    description: "Fuzzing mode - replaces the FUZZ keyword in URLs, headers, or POST data with wordlist entries. Useful for parameter discovery and testing. Executes on remote Kali host via SSH.",
    inputSchema: {
      type: "object",
      properties: {
        url: {
          type: "string",
          description: "Target URL containing FUZZ keyword (e.g., https://example.com?param=FUZZ)"
        },
        wordlist: {
          type: "string",
          description: `Path to wordlist file on Kali (default: ${DEFAULT_WORDLIST})`
        },
        threads: {
          type: "number",
          description: "Number of concurrent threads (default: 10)"
        },
        post_data: {
          type: "string",
          description: "POST data containing FUZZ keyword (e.g., username=admin&password=FUZZ)"
        },
        headers: {
          type: "array",
          items: { type: "string" },
          description: "Custom headers, can contain FUZZ keyword (e.g., ['X-Custom-Header: FUZZ'])"
        },
        cookies: {
          type: "string",
          description: "Cookies to use for requests"
        },
        method: {
          type: "string",
          description: "HTTP method (default: GET, or POST if post_data provided)"
        },
        exclude_status: {
          type: "string",
          description: "Status codes to exclude, comma-separated"
        },
        exclude_length: {
          type: "string",
          description: "Response lengths to exclude, comma-separated"
        },
        timeout: {
          type: "number",
          description: "HTTP timeout in seconds (default: 10)"
        },
        no_tls_validation: {
          type: "boolean",
          description: "Skip TLS certificate verification (default: false)"
        },
        quiet: {
          type: "boolean",
          description: "Don't print banner and other noise (default: false)"
        },
        async: {
          type: "boolean",
          description: "Run scan asynchronously and return scan ID (default: false)"
        }
      },
      required: ["url"]
    }
  },
  {
    name: "gobuster_s3",
    description: "Amazon S3 bucket enumeration mode - discovers open S3 buckets using wordlist-based brute forcing. Executes on remote Kali host via SSH.",
    inputSchema: {
      type: "object",
      properties: {
        wordlist: {
          type: "string",
          description: "Path to wordlist file containing bucket names on Kali"
        },
        threads: {
          type: "number",
          description: "Number of concurrent threads (default: 10)"
        },
        max_files: {
          type: "number",
          description: "Maximum files to list when bucket is listable (default: 5)"
        },
        quiet: {
          type: "boolean",
          description: "Don't print banner and other noise (default: false)"
        },
        async: {
          type: "boolean",
          description: "Run scan asynchronously and return scan ID (default: false)"
        }
      },
      required: ["wordlist"]
    }
  },
  {
    name: "gobuster_tftp",
    description: "TFTP file enumeration mode - discovers files on TFTP servers. Executes on remote Kali host via SSH.",
    inputSchema: {
      type: "object",
      properties: {
        server: {
          type: "string",
          description: "Target TFTP server IP address"
        },
        wordlist: {
          type: "string",
          description: `Path to wordlist file on Kali (default: ${DEFAULT_WORDLIST})`
        },
        threads: {
          type: "number",
          description: "Number of concurrent threads (default: 10)"
        },
        timeout: {
          type: "number",
          description: "TFTP timeout in seconds (default: 1)"
        },
        quiet: {
          type: "boolean",
          description: "Don't print banner and other noise (default: false)"
        },
        async: {
          type: "boolean",
          description: "Run scan asynchronously and return scan ID (default: false)"
        }
      },
      required: ["server"]
    }
  },
  {
    name: "gobuster_status",
    description: "Check the status of an asynchronous gobuster scan",
    inputSchema: {
      type: "object",
      properties: {
        scan_id: {
          type: "string",
          description: "The scan ID returned from an async scan"
        }
      },
      required: ["scan_id"]
    }
  },
  {
    name: "gobuster_stop",
    description: "Stop a running asynchronous gobuster scan",
    inputSchema: {
      type: "object",
      properties: {
        scan_id: {
          type: "string",
          description: "The scan ID to stop"
        }
      },
      required: ["scan_id"]
    }
  },
  {
    name: "gobuster_list_scans",
    description: "List all active and recent gobuster scans",
    inputSchema: {
      type: "object",
      properties: {}
    }
  },
  {
    name: "gobuster_wordlists",
    description: "List available wordlists on the Kali host",
    inputSchema: {
      type: "object",
      properties: {
        category: {
          type: "string",
          enum: ["all", "dirb", "dirbuster", "wfuzz", "seclists", "subdomains"],
          description: "Category of wordlists to list (default: all)"
        }
      }
    }
  }
];

// Helper function to build command arguments
function buildDirCommand(args: DirArgs): string[] {
  const cmd: string[] = ["gobuster", "dir"];

  cmd.push("-u", args.url);
  cmd.push("-w", args.wordlist || DEFAULT_WORDLIST);

  if (args.extensions) cmd.push("-x", args.extensions);
  if (args.threads) cmd.push("-t", args.threads.toString());
  if (args.status_codes) cmd.push("-s", args.status_codes);
  if (args.exclude_status) cmd.push("-b", args.exclude_status);
  if (args.cookies) cmd.push("-c", args.cookies);
  if (args.headers) {
    for (const h of args.headers) {
      cmd.push("-H", h);
    }
  }
  if (args.user_agent) cmd.push("-a", args.user_agent);
  if (args.timeout) cmd.push("--timeout", `${args.timeout}s`);
  if (args.follow_redirect) cmd.push("-r");
  if (args.no_tls_validation) cmd.push("-k");
  if (args.show_length !== false) cmd.push("-l");
  if (args.expanded) cmd.push("-e");
  if (args.quiet) cmd.push("-q");

  cmd.push("--no-progress");
  cmd.push("--no-color");

  return cmd;
}

function buildDnsCommand(args: DnsArgs): string[] {
  const cmd: string[] = ["gobuster", "dns"];

  cmd.push("-d", args.domain);
  cmd.push("-w", args.wordlist || DEFAULT_DNS_WORDLIST);

  if (args.resolver) cmd.push("-r", args.resolver);
  if (args.threads) cmd.push("-t", args.threads.toString());
  if (args.show_ips !== false) cmd.push("-i");
  if (args.show_cname) cmd.push("-c");
  if (args.timeout) cmd.push("--timeout", `${args.timeout}s`);
  if (args.wildcard) cmd.push("--wildcard");
  if (args.quiet) cmd.push("-q");

  cmd.push("--no-progress");
  cmd.push("--no-color");

  return cmd;
}

function buildVhostCommand(args: VhostArgs): string[] {
  const cmd: string[] = ["gobuster", "vhost"];

  cmd.push("-u", args.url);
  cmd.push("-w", args.wordlist || DEFAULT_WORDLIST);

  if (args.domain) cmd.push("--append-domain", "--domain", args.domain);
  if (args.threads) cmd.push("-t", args.threads.toString());
  if (args.cookies) cmd.push("-c", args.cookies);
  if (args.headers) {
    for (const h of args.headers) {
      cmd.push("-H", h);
    }
  }
  if (args.user_agent) cmd.push("-a", args.user_agent);
  if (args.timeout) cmd.push("--timeout", `${args.timeout}s`);
  if (args.follow_redirect) cmd.push("-r");
  if (args.no_tls_validation) cmd.push("-k");
  if (args.exclude_length) cmd.push("--exclude-length", args.exclude_length);
  if (args.quiet) cmd.push("-q");

  cmd.push("--no-progress");
  cmd.push("--no-color");

  return cmd;
}

function buildFuzzCommand(args: FuzzArgs): string[] {
  const cmd: string[] = ["gobuster", "fuzz"];

  cmd.push("-u", args.url);
  cmd.push("-w", args.wordlist || DEFAULT_WORDLIST);

  if (args.threads) cmd.push("-t", args.threads.toString());
  if (args.post_data) cmd.push("-d", args.post_data);
  if (args.headers) {
    for (const h of args.headers) {
      cmd.push("-H", h);
    }
  }
  if (args.cookies) cmd.push("-c", args.cookies);
  if (args.method) cmd.push("-m", args.method);
  if (args.exclude_status) cmd.push("-b", args.exclude_status);
  if (args.exclude_length) cmd.push("--exclude-length", args.exclude_length);
  if (args.timeout) cmd.push("--timeout", `${args.timeout}s`);
  if (args.no_tls_validation) cmd.push("-k");
  if (args.quiet) cmd.push("-q");

  cmd.push("--no-progress");
  cmd.push("--no-color");

  return cmd;
}

function buildS3Command(args: S3Args): string[] {
  const cmd: string[] = ["gobuster", "s3"];

  cmd.push("-w", args.wordlist);

  if (args.threads) cmd.push("-t", args.threads.toString());
  if (args.max_files) cmd.push("-m", args.max_files.toString());
  if (args.quiet) cmd.push("-q");

  cmd.push("--no-progress");
  cmd.push("--no-color");

  return cmd;
}

function buildTftpCommand(args: TftpArgs): string[] {
  const cmd: string[] = ["gobuster", "tftp"];

  cmd.push("-s", args.server);
  cmd.push("-w", args.wordlist || DEFAULT_WORDLIST);

  if (args.threads) cmd.push("-t", args.threads.toString());
  if (args.timeout) cmd.push("--timeout", `${args.timeout}s`);
  if (args.quiet) cmd.push("-q");

  cmd.push("--no-progress");
  cmd.push("--no-color");

  return cmd;
}

// Execute command synchronously
async function executeSync(cmd: string[]): Promise<string> {
  const escapedCmd = cmd.map(arg => {
    // Escape special characters for SSH
    if (arg.includes(" ") || arg.includes('"') || arg.includes("'") || arg.includes("$")) {
      return `'${arg.replace(/'/g, "'\\''")}'`;
    }
    return arg;
  }).join(" ");

  const sshCommand = `ssh ${SSH_OPTIONS} ${KALI_HOST} "${escapedCmd}"`;

  try {
    const { stdout, stderr } = await execAsync(sshCommand, {
      maxBuffer: 50 * 1024 * 1024,
      timeout: 300000 // 5 minute timeout
    });
    return stdout + (stderr ? `\n[stderr]: ${stderr}` : "");
  } catch (error: unknown) {
    const execError = error as { stdout?: string; stderr?: string; message?: string };
    if (execError.stdout || execError.stderr) {
      return (execError.stdout || "") + (execError.stderr ? `\n[stderr]: ${execError.stderr}` : "");
    }
    throw error;
  }
}

// Execute command asynchronously
function executeAsync(cmd: string[], mode: string, target: string): string {
  const scanId = `gobuster_${mode}_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;

  const escapedCmd = cmd.map(arg => {
    if (arg.includes(" ") || arg.includes('"') || arg.includes("'") || arg.includes("$")) {
      return `'${arg.replace(/'/g, "'\\''")}'`;
    }
    return arg;
  }).join(" ");

  const sshArgs = SSH_OPTIONS.split(" ").concat([KALI_HOST, escapedCmd]);

  const childProcess = spawn("ssh", sshArgs, {
    stdio: ["ignore", "pipe", "pipe"]
  });

  const scanInfo = {
    process: childProcess,
    output: [] as string[],
    status: "running" as const,
    startTime: new Date(),
    mode,
    target
  };

  activeScans.set(scanId, scanInfo);

  childProcess.stdout.on("data", (data: Buffer) => {
    scanInfo.output.push(data.toString());
  });

  childProcess.stderr.on("data", (data: Buffer) => {
    scanInfo.output.push(`[stderr]: ${data.toString()}`);
  });

  childProcess.on("close", (code) => {
    const scan = activeScans.get(scanId);
    if (scan) {
      scan.status = code === 0 ? "completed" : "error";
      scan.process = null;
    }
  });

  childProcess.on("error", (err) => {
    const scan = activeScans.get(scanId);
    if (scan) {
      scan.status = "error";
      scan.output.push(`[error]: ${err.message}`);
      scan.process = null;
    }
  });

  return scanId;
}

// List wordlists on Kali
async function listWordlists(category: string = "all"): Promise<string> {
  const paths: Record<string, string[]> = {
    dirb: ["/usr/share/wordlists/dirb/"],
    dirbuster: ["/usr/share/wordlists/dirbuster/"],
    wfuzz: ["/usr/share/wordlists/wfuzz/"],
    seclists: ["/usr/share/seclists/"],
    subdomains: [
      "/usr/share/wordlists/",
      "/usr/share/seclists/Discovery/DNS/"
    ]
  };

  let searchPaths: string[] = [];
  if (category === "all") {
    searchPaths = Object.values(paths).flat();
  } else if (paths[category]) {
    searchPaths = paths[category];
  } else {
    return `Unknown category: ${category}. Available: ${Object.keys(paths).join(", ")}`;
  }

  const results: string[] = [];
  for (const path of searchPaths) {
    try {
      const output = await executeSync(["find", path, "-name", "*.txt", "-type", "f", "-size", "+0"]);
      if (output.trim()) {
        results.push(`\n=== ${path} ===\n${output}`);
      }
    } catch {
      // Path might not exist, skip
    }
  }

  return results.join("\n") || "No wordlists found in specified paths";
}

// Create server
const server = new Server(
  {
    name: "gobuster-mcp",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Register handlers
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools,
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case "gobuster_dir": {
        const dirArgs = args as unknown as DirArgs;
        const cmd = buildDirCommand(dirArgs);
        if (dirArgs.async) {
          const scanId = executeAsync(cmd, "dir", dirArgs.url);
          return {
            content: [{
              type: "text",
              text: JSON.stringify({
                status: "started",
                scan_id: scanId,
                message: `Directory enumeration scan started against ${dirArgs.url}`,
                check_status: `Use gobuster_status with scan_id: ${scanId}`
              }, null, 2)
            }]
          };
        }
        const result = await executeSync(cmd);
        return {
          content: [{
            type: "text",
            text: `Directory enumeration results for ${dirArgs.url}:\n\n${result}`
          }]
        };
      }

      case "gobuster_dns": {
        const dnsArgs = args as unknown as DnsArgs;
        const cmd = buildDnsCommand(dnsArgs);
        if (dnsArgs.async) {
          const scanId = executeAsync(cmd, "dns", dnsArgs.domain);
          return {
            content: [{
              type: "text",
              text: JSON.stringify({
                status: "started",
                scan_id: scanId,
                message: `DNS subdomain enumeration started for ${dnsArgs.domain}`,
                check_status: `Use gobuster_status with scan_id: ${scanId}`
              }, null, 2)
            }]
          };
        }
        const result = await executeSync(cmd);
        return {
          content: [{
            type: "text",
            text: `DNS subdomain enumeration results for ${dnsArgs.domain}:\n\n${result}`
          }]
        };
      }

      case "gobuster_vhost": {
        const vhostArgs = args as unknown as VhostArgs;
        const cmd = buildVhostCommand(vhostArgs);
        if (vhostArgs.async) {
          const scanId = executeAsync(cmd, "vhost", vhostArgs.url);
          return {
            content: [{
              type: "text",
              text: JSON.stringify({
                status: "started",
                scan_id: scanId,
                message: `Virtual host enumeration started against ${vhostArgs.url}`,
                check_status: `Use gobuster_status with scan_id: ${scanId}`
              }, null, 2)
            }]
          };
        }
        const result = await executeSync(cmd);
        return {
          content: [{
            type: "text",
            text: `Virtual host enumeration results for ${vhostArgs.url}:\n\n${result}`
          }]
        };
      }

      case "gobuster_fuzz": {
        const fuzzArgs = args as unknown as FuzzArgs;
        const cmd = buildFuzzCommand(fuzzArgs);
        if (fuzzArgs.async) {
          const scanId = executeAsync(cmd, "fuzz", fuzzArgs.url);
          return {
            content: [{
              type: "text",
              text: JSON.stringify({
                status: "started",
                scan_id: scanId,
                message: `Fuzzing started against ${fuzzArgs.url}`,
                check_status: `Use gobuster_status with scan_id: ${scanId}`
              }, null, 2)
            }]
          };
        }
        const result = await executeSync(cmd);
        return {
          content: [{
            type: "text",
            text: `Fuzzing results for ${fuzzArgs.url}:\n\n${result}`
          }]
        };
      }

      case "gobuster_s3": {
        const s3Args = args as unknown as S3Args;
        const cmd = buildS3Command(s3Args);
        if (s3Args.async) {
          const scanId = executeAsync(cmd, "s3", "S3 buckets");
          return {
            content: [{
              type: "text",
              text: JSON.stringify({
                status: "started",
                scan_id: scanId,
                message: "S3 bucket enumeration started",
                check_status: `Use gobuster_status with scan_id: ${scanId}`
              }, null, 2)
            }]
          };
        }
        const result = await executeSync(cmd);
        return {
          content: [{
            type: "text",
            text: `S3 bucket enumeration results:\n\n${result}`
          }]
        };
      }

      case "gobuster_tftp": {
        const tftpArgs = args as unknown as TftpArgs;
        const cmd = buildTftpCommand(tftpArgs);
        if (tftpArgs.async) {
          const scanId = executeAsync(cmd, "tftp", tftpArgs.server);
          return {
            content: [{
              type: "text",
              text: JSON.stringify({
                status: "started",
                scan_id: scanId,
                message: `TFTP enumeration started against ${tftpArgs.server}`,
                check_status: `Use gobuster_status with scan_id: ${scanId}`
              }, null, 2)
            }]
          };
        }
        const result = await executeSync(cmd);
        return {
          content: [{
            type: "text",
            text: `TFTP enumeration results for ${tftpArgs.server}:\n\n${result}`
          }]
        };
      }

      case "gobuster_status": {
        const statusArgs = args as unknown as StatusArgs;
        const scanId = statusArgs.scan_id;
        const scan = activeScans.get(scanId);

        if (!scan) {
          return {
            content: [{
              type: "text",
              text: JSON.stringify({
                error: "Scan not found",
                scan_id: scanId
              }, null, 2)
            }]
          };
        }

        const elapsed = Math.floor((Date.now() - scan.startTime.getTime()) / 1000);

        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              scan_id: scanId,
              status: scan.status,
              mode: scan.mode,
              target: scan.target,
              elapsed_seconds: elapsed,
              output_lines: scan.output.length,
              output: scan.output.join("")
            }, null, 2)
          }]
        };
      }

      case "gobuster_stop": {
        const stopArgs = args as unknown as StopArgs;
        const scanId = stopArgs.scan_id;
        const scan = activeScans.get(scanId);

        if (!scan) {
          return {
            content: [{
              type: "text",
              text: JSON.stringify({
                error: "Scan not found",
                scan_id: scanId
              }, null, 2)
            }]
          };
        }

        if (scan.process) {
          scan.process.kill("SIGTERM");
          scan.status = "completed";
          scan.output.push("\n[Scan stopped by user]");
        }

        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              message: "Scan stopped",
              scan_id: scanId,
              final_output: scan.output.join("")
            }, null, 2)
          }]
        };
      }

      case "gobuster_list_scans": {
        const scanList = Array.from(activeScans.entries()).map(([id, scan]) => ({
          scan_id: id,
          status: scan.status,
          mode: scan.mode,
          target: scan.target,
          started: scan.startTime.toISOString(),
          elapsed_seconds: Math.floor((Date.now() - scan.startTime.getTime()) / 1000),
          output_lines: scan.output.length
        }));

        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              total_scans: scanList.length,
              scans: scanList
            }, null, 2)
          }]
        };
      }

      case "gobuster_wordlists": {
        const wordlistArgs = args as unknown as WordlistArgs;
        const result = await listWordlists(wordlistArgs?.category || "all");
        return {
          content: [{
            type: "text",
            text: `Available wordlists on Kali:\n${result}`
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
  } catch (error: unknown) {
    const err = error as { message?: string };
    return {
      content: [{
        type: "text",
        text: `Error executing ${name}: ${err.message || String(error)}`
      }],
      isError: true
    };
  }
});

// Main
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Gobuster MCP server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
