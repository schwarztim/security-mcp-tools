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
import * as fs from "fs";
import * as path from "path";
import * as os from "os";

const execAsync = promisify(exec);

// SSH host for Kali Linux
const KALI_HOST = process.env.KALI_HOST || "kali";

// State file for tracking scans
const STATE_DIR = path.join(os.homedir(), ".feroxbuster-mcp");
const STATE_FILE = path.join(STATE_DIR, "state.json");

// Ensure state directory exists
if (!fs.existsSync(STATE_DIR)) {
  fs.mkdirSync(STATE_DIR, { recursive: true });
}

interface ScanState {
  activeScan?: {
    id: string;
    url: string;
    pid?: number;
    startTime: string;
    outputFile: string;
    stateFile: string;
  };
  lastScanResults?: string;
  config: {
    wordlist?: string;
    extensions?: string[];
    recursionDepth?: number;
    rateLimit?: number;
    threads?: number;
    timeout?: number;
    filterStatus?: number[];
    filterSize?: number[];
    filterWords?: number[];
    filterLines?: number[];
    headers?: Record<string, string>;
    proxy?: string;
  };
}

function loadState(): ScanState {
  try {
    if (fs.existsSync(STATE_FILE)) {
      return JSON.parse(fs.readFileSync(STATE_FILE, "utf-8"));
    }
  } catch (e) {
    // Ignore errors
  }
  return { config: {} };
}

function saveState(state: ScanState): void {
  fs.writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));
}

// Execute command on Kali via SSH
async function sshExec(command: string, timeout: number = 30000): Promise<{ stdout: string; stderr: string }> {
  const sshCommand = `ssh ${KALI_HOST} "${command.replace(/"/g, '\\"')}"`;
  return execAsync(sshCommand, { timeout, maxBuffer: 10 * 1024 * 1024 });
}

// Start a background scan on Kali
async function startBackgroundScan(command: string, outputFile: string): Promise<number | undefined> {
  // Use nohup and background the process, capture PID
  const sshCommand = `ssh ${KALI_HOST} "nohup ${command.replace(/"/g, '\\"')} > ${outputFile} 2>&1 & echo \\$!"`;
  const { stdout } = await execAsync(sshCommand);
  const pid = parseInt(stdout.trim(), 10);
  return isNaN(pid) ? undefined : pid;
}

// Check if process is running on Kali
async function isProcessRunning(pid: number): Promise<boolean> {
  try {
    await sshExec(`kill -0 ${pid} 2>/dev/null && echo "running"`, 5000);
    return true;
  } catch {
    return false;
  }
}

// Read file from Kali
async function readRemoteFile(filepath: string): Promise<string> {
  try {
    const { stdout } = await sshExec(`cat "${filepath}"`, 60000);
    return stdout;
  } catch (e) {
    return "";
  }
}

// Define tools
const tools: Tool[] = [
  {
    name: "feroxbuster_scan",
    description: "Start a feroxbuster directory scan against a target URL. Executes on remote Kali system via SSH.",
    inputSchema: {
      type: "object",
      properties: {
        url: {
          type: "string",
          description: "Target URL to scan (e.g., http://example.com)",
        },
        wordlist: {
          type: "string",
          description: "Path to wordlist on Kali (default: /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt)",
        },
        extensions: {
          type: "array",
          items: { type: "string" },
          description: "File extensions to check (e.g., ['php', 'html', 'js'])",
        },
        recursion_depth: {
          type: "number",
          description: "Maximum recursion depth (0 = infinite, default: 4)",
        },
        threads: {
          type: "number",
          description: "Number of concurrent threads (default: 50)",
        },
        timeout: {
          type: "number",
          description: "Request timeout in seconds (default: 7)",
        },
        rate_limit: {
          type: "number",
          description: "Maximum requests per second per directory",
        },
        filter_status: {
          type: "array",
          items: { type: "number" },
          description: "Status codes to filter OUT (exclude from results)",
        },
        status_codes: {
          type: "array",
          items: { type: "number" },
          description: "Status codes to include (default: 200,204,301,302,307,308,401,403,405,500)",
        },
        filter_size: {
          type: "array",
          items: { type: "number" },
          description: "Response sizes to filter OUT",
        },
        filter_words: {
          type: "array",
          items: { type: "number" },
          description: "Word counts to filter OUT",
        },
        filter_lines: {
          type: "array",
          items: { type: "number" },
          description: "Line counts to filter OUT",
        },
        headers: {
          type: "object",
          description: "Custom headers to include (e.g., {\"Authorization\": \"Bearer token\"})",
        },
        proxy: {
          type: "string",
          description: "Proxy URL (e.g., http://127.0.0.1:8080 or socks5://127.0.0.1:9050)",
        },
        insecure: {
          type: "boolean",
          description: "Disable TLS certificate validation",
        },
        no_recursion: {
          type: "boolean",
          description: "Disable recursive scanning",
        },
        force_recursion: {
          type: "boolean",
          description: "Force recursion on all found paths",
        },
        auto_tune: {
          type: "boolean",
          description: "Automatically lower scan rate on errors",
        },
        auto_bail: {
          type: "boolean",
          description: "Automatically stop on excessive errors",
        },
        silent: {
          type: "boolean",
          description: "Only output URLs (for piping)",
        },
        json: {
          type: "boolean",
          description: "Output results as JSON",
        },
        background: {
          type: "boolean",
          description: "Run scan in background and return immediately",
        },
        dont_scan: {
          type: "array",
          items: { type: "string" },
          description: "URLs to exclude from recursion",
        },
        time_limit: {
          type: "string",
          description: "Maximum scan time (e.g., '10m', '1h', '30s')",
        },
        scan_limit: {
          type: "number",
          description: "Maximum concurrent directory scans",
        },
        user_agent: {
          type: "string",
          description: "Custom User-Agent string",
        },
        cookies: {
          type: "string",
          description: "Cookies to include (e.g., 'session=abc123; token=xyz')",
        },
        data: {
          type: "string",
          description: "Request body data for POST requests",
        },
        methods: {
          type: "array",
          items: { type: "string" },
          description: "HTTP methods to use (default: GET)",
        },
        query: {
          type: "string",
          description: "Query parameters to append (e.g., 'token=abc&debug=true')",
        },
      },
      required: ["url"],
    },
  },
  {
    name: "feroxbuster_config",
    description: "Configure default feroxbuster settings for subsequent scans",
    inputSchema: {
      type: "object",
      properties: {
        wordlist: {
          type: "string",
          description: "Default wordlist path on Kali",
        },
        extensions: {
          type: "array",
          items: { type: "string" },
          description: "Default file extensions",
        },
        recursion_depth: {
          type: "number",
          description: "Default recursion depth",
        },
        rate_limit: {
          type: "number",
          description: "Default rate limit (requests/sec)",
        },
        threads: {
          type: "number",
          description: "Default thread count",
        },
        timeout: {
          type: "number",
          description: "Default request timeout",
        },
        filter_status: {
          type: "array",
          items: { type: "number" },
          description: "Default status codes to filter",
        },
        filter_size: {
          type: "array",
          items: { type: "number" },
          description: "Default sizes to filter",
        },
        filter_words: {
          type: "array",
          items: { type: "number" },
          description: "Default word counts to filter",
        },
        filter_lines: {
          type: "array",
          items: { type: "number" },
          description: "Default line counts to filter",
        },
        headers: {
          type: "object",
          description: "Default headers",
        },
        proxy: {
          type: "string",
          description: "Default proxy URL",
        },
      },
    },
  },
  {
    name: "feroxbuster_status",
    description: "Check the status of a running or completed feroxbuster scan",
    inputSchema: {
      type: "object",
      properties: {
        tail_lines: {
          type: "number",
          description: "Number of lines to show from output (default: 50)",
        },
      },
    },
  },
  {
    name: "feroxbuster_stop",
    description: "Stop a running feroxbuster scan",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "feroxbuster_resume",
    description: "Resume a previously interrupted feroxbuster scan from its state file",
    inputSchema: {
      type: "object",
      properties: {
        state_file: {
          type: "string",
          description: "Path to feroxbuster state file on Kali (optional, uses last scan if not specified)",
        },
        background: {
          type: "boolean",
          description: "Run resumed scan in background",
        },
      },
    },
  },
  {
    name: "feroxbuster_wordlists",
    description: "List available wordlists on the Kali system",
    inputSchema: {
      type: "object",
      properties: {
        search: {
          type: "string",
          description: "Search term to filter wordlists",
        },
        category: {
          type: "string",
          enum: ["common", "directory", "web", "api", "all"],
          description: "Category of wordlists to show",
        },
      },
    },
  },
  {
    name: "feroxbuster_results",
    description: "Get the results from the last completed scan",
    inputSchema: {
      type: "object",
      properties: {
        format: {
          type: "string",
          enum: ["text", "json", "urls"],
          description: "Output format (default: text)",
        },
        filter_status: {
          type: "array",
          items: { type: "number" },
          description: "Filter results by status code",
        },
      },
    },
  },
  {
    name: "feroxbuster_version",
    description: "Get feroxbuster version information from Kali",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
];

// Build feroxbuster command from options
function buildCommand(url: string, options: Record<string, unknown>, state: ScanState): string {
  const config = state.config;
  const parts: string[] = ["feroxbuster"];

  // URL
  parts.push("-u", `'${url}'`);

  // Wordlist
  const wordlist = options.wordlist || config.wordlist || "/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt";
  parts.push("-w", `'${wordlist}'`);

  // Extensions
  const extensions = (options.extensions as string[]) || config.extensions;
  if (extensions && extensions.length > 0) {
    parts.push("-x", extensions.join(","));
  }

  // Recursion depth
  const depth = options.recursion_depth ?? config.recursionDepth;
  if (depth !== undefined) {
    parts.push("-d", String(depth));
  }

  // Threads
  const threads = options.threads ?? config.threads;
  if (threads !== undefined) {
    parts.push("-t", String(threads));
  }

  // Timeout
  const timeout = options.timeout ?? config.timeout;
  if (timeout !== undefined) {
    parts.push("-T", String(timeout));
  }

  // Rate limit
  const rateLimit = options.rate_limit ?? config.rateLimit;
  if (rateLimit !== undefined) {
    parts.push("--rate-limit", String(rateLimit));
  }

  // Filter status codes
  const filterStatus = (options.filter_status as number[]) || config.filterStatus;
  if (filterStatus && filterStatus.length > 0) {
    for (const code of filterStatus) {
      parts.push("-C", String(code));
    }
  }

  // Include status codes
  const statusCodes = options.status_codes as number[];
  if (statusCodes && statusCodes.length > 0) {
    parts.push("-s", statusCodes.join(","));
  }

  // Filter size
  const filterSize = (options.filter_size as number[]) || config.filterSize;
  if (filterSize && filterSize.length > 0) {
    for (const size of filterSize) {
      parts.push("-S", String(size));
    }
  }

  // Filter words
  const filterWords = (options.filter_words as number[]) || config.filterWords;
  if (filterWords && filterWords.length > 0) {
    for (const words of filterWords) {
      parts.push("-W", String(words));
    }
  }

  // Filter lines
  const filterLines = (options.filter_lines as number[]) || config.filterLines;
  if (filterLines && filterLines.length > 0) {
    for (const lines of filterLines) {
      parts.push("-N", String(lines));
    }
  }

  // Headers
  const headers = (options.headers as Record<string, string>) || config.headers;
  if (headers) {
    for (const [key, value] of Object.entries(headers)) {
      parts.push("-H", `'${key}: ${value}'`);
    }
  }

  // Proxy
  const proxy = options.proxy || config.proxy;
  if (proxy) {
    parts.push("--proxy", `'${proxy}'`);
  }

  // Insecure
  if (options.insecure) {
    parts.push("-k");
  }

  // No recursion
  if (options.no_recursion) {
    parts.push("-n");
  }

  // Force recursion
  if (options.force_recursion) {
    parts.push("--force-recursion");
  }

  // Auto tune
  if (options.auto_tune) {
    parts.push("--auto-tune");
  }

  // Auto bail
  if (options.auto_bail) {
    parts.push("--auto-bail");
  }

  // Silent mode
  if (options.silent) {
    parts.push("--silent");
  }

  // JSON output
  if (options.json) {
    parts.push("--json");
  }

  // Dont scan
  const dontScan = options.dont_scan as string[];
  if (dontScan && dontScan.length > 0) {
    for (const url of dontScan) {
      parts.push("--dont-scan", `'${url}'`);
    }
  }

  // Time limit
  if (options.time_limit) {
    parts.push("--time-limit", String(options.time_limit));
  }

  // Scan limit
  if (options.scan_limit) {
    parts.push("-L", String(options.scan_limit));
  }

  // User agent
  if (options.user_agent) {
    parts.push("-a", `'${options.user_agent}'`);
  }

  // Cookies
  if (options.cookies) {
    parts.push("-b", `'${options.cookies}'`);
  }

  // Data (POST body)
  if (options.data) {
    parts.push("--data", `'${options.data}'`);
  }

  // Methods
  const methods = options.methods as string[];
  if (methods && methods.length > 0) {
    for (const method of methods) {
      parts.push("-m", method);
    }
  }

  // Query parameters
  if (options.query) {
    parts.push("-Q", `'${options.query}'`);
  }

  return parts.join(" ");
}

// Handle tool calls
async function handleToolCall(
  name: string,
  args: Record<string, unknown>
): Promise<string> {
  const state = loadState();

  switch (name) {
    case "feroxbuster_scan": {
      const url = args.url as string;
      if (!url) {
        return JSON.stringify({ error: "URL is required" });
      }

      // Check if there's already an active scan
      if (state.activeScan) {
        const running = state.activeScan.pid
          ? await isProcessRunning(state.activeScan.pid)
          : false;
        if (running) {
          return JSON.stringify({
            error: "A scan is already running",
            activeScan: state.activeScan,
            hint: "Use feroxbuster_stop to stop it, or feroxbuster_status to check progress",
          });
        }
      }

      const scanId = `scan_${Date.now()}`;
      const outputFile = `/tmp/feroxbuster_${scanId}.txt`;
      const stateFile = `/tmp/feroxbuster_${scanId}.state`;

      // Build command with state file for resume capability
      let command = buildCommand(url, args, state);
      command += ` --state ${stateFile}`;
      command += ` -o ${outputFile}`;

      // Add quiet mode to reduce noise unless silent is set
      if (!args.silent && !args.json) {
        command += " -q";
      }

      if (args.background) {
        // Run in background
        const pid = await startBackgroundScan(command, outputFile);
        state.activeScan = {
          id: scanId,
          url,
          pid,
          startTime: new Date().toISOString(),
          outputFile,
          stateFile,
        };
        saveState(state);

        return JSON.stringify({
          status: "started",
          scanId,
          pid,
          url,
          message: "Scan started in background. Use feroxbuster_status to check progress.",
        });
      } else {
        // Run synchronously with timeout
        state.activeScan = {
          id: scanId,
          url,
          startTime: new Date().toISOString(),
          outputFile,
          stateFile,
        };
        saveState(state);

        try {
          // Use a longer timeout for scans (5 minutes)
          const { stdout, stderr } = await sshExec(command, 300000);

          // Get results
          const results = await readRemoteFile(outputFile);

          state.lastScanResults = results || stdout;
          delete state.activeScan;
          saveState(state);

          return JSON.stringify({
            status: "completed",
            scanId,
            url,
            results: results || stdout,
            errors: stderr || undefined,
          });
        } catch (error: unknown) {
          const errorMessage = error instanceof Error ? error.message : String(error);

          // Check if it was interrupted or timed out
          if (errorMessage.includes("timeout") || errorMessage.includes("SIGTERM")) {
            return JSON.stringify({
              status: "timeout",
              scanId,
              url,
              message: "Scan timed out. Use feroxbuster_resume to continue from state file.",
              stateFile,
            });
          }

          // Get partial results
          const partialResults = await readRemoteFile(outputFile);
          state.lastScanResults = partialResults;
          delete state.activeScan;
          saveState(state);

          return JSON.stringify({
            status: "error",
            error: errorMessage,
            partialResults: partialResults || undefined,
          });
        }
      }
    }

    case "feroxbuster_config": {
      // Update configuration
      if (args.wordlist) state.config.wordlist = args.wordlist as string;
      if (args.extensions) state.config.extensions = args.extensions as string[];
      if (args.recursion_depth !== undefined) state.config.recursionDepth = args.recursion_depth as number;
      if (args.rate_limit !== undefined) state.config.rateLimit = args.rate_limit as number;
      if (args.threads !== undefined) state.config.threads = args.threads as number;
      if (args.timeout !== undefined) state.config.timeout = args.timeout as number;
      if (args.filter_status) state.config.filterStatus = args.filter_status as number[];
      if (args.filter_size) state.config.filterSize = args.filter_size as number[];
      if (args.filter_words) state.config.filterWords = args.filter_words as number[];
      if (args.filter_lines) state.config.filterLines = args.filter_lines as number[];
      if (args.headers) state.config.headers = args.headers as Record<string, string>;
      if (args.proxy) state.config.proxy = args.proxy as string;

      saveState(state);

      return JSON.stringify({
        status: "configured",
        config: state.config,
      });
    }

    case "feroxbuster_status": {
      if (!state.activeScan) {
        return JSON.stringify({
          status: "no_active_scan",
          message: "No active scan found",
          lastResults: state.lastScanResults ? "Available (use feroxbuster_results)" : "None",
        });
      }

      const running = state.activeScan.pid
        ? await isProcessRunning(state.activeScan.pid)
        : false;

      const tailLines = (args.tail_lines as number) || 50;
      let output = "";
      try {
        const { stdout } = await sshExec(`tail -n ${tailLines} ${state.activeScan.outputFile}`, 10000);
        output = stdout;
      } catch {
        // Ignore errors
      }

      if (!running && state.activeScan.pid) {
        // Scan completed
        const fullOutput = await readRemoteFile(state.activeScan.outputFile);
        state.lastScanResults = fullOutput;
        const completedScan = { ...state.activeScan };
        delete state.activeScan;
        saveState(state);

        return JSON.stringify({
          status: "completed",
          scan: completedScan,
          results: fullOutput,
        });
      }

      return JSON.stringify({
        status: running ? "running" : "unknown",
        scan: state.activeScan,
        recentOutput: output,
      });
    }

    case "feroxbuster_stop": {
      if (!state.activeScan || !state.activeScan.pid) {
        return JSON.stringify({
          status: "no_active_scan",
          message: "No active scan to stop",
        });
      }

      try {
        await sshExec(`kill ${state.activeScan.pid}`, 5000);
      } catch {
        // Process may have already finished
      }

      // Get final results
      const results = await readRemoteFile(state.activeScan.outputFile);
      state.lastScanResults = results;
      const stoppedScan = { ...state.activeScan };
      delete state.activeScan;
      saveState(state);

      return JSON.stringify({
        status: "stopped",
        scan: stoppedScan,
        results,
        message: "Scan stopped. State file preserved for potential resume.",
      });
    }

    case "feroxbuster_resume": {
      const stateFile = (args.state_file as string) || state.activeScan?.stateFile;

      if (!stateFile) {
        return JSON.stringify({
          error: "No state file specified and no previous scan state available",
          hint: "Provide a state_file path or run a scan first",
        });
      }

      // Check if state file exists
      try {
        await sshExec(`test -f ${stateFile}`, 5000);
      } catch {
        return JSON.stringify({
          error: `State file not found: ${stateFile}`,
        });
      }

      const scanId = `resume_${Date.now()}`;
      const outputFile = `/tmp/feroxbuster_${scanId}.txt`;
      const command = `feroxbuster --resume-from ${stateFile} -o ${outputFile} -q`;

      if (args.background) {
        const pid = await startBackgroundScan(command, outputFile);
        state.activeScan = {
          id: scanId,
          url: "resumed",
          pid,
          startTime: new Date().toISOString(),
          outputFile,
          stateFile,
        };
        saveState(state);

        return JSON.stringify({
          status: "resumed",
          scanId,
          pid,
          message: "Scan resumed in background. Use feroxbuster_status to check progress.",
        });
      } else {
        try {
          const { stdout, stderr } = await sshExec(command, 300000);
          const results = await readRemoteFile(outputFile);
          state.lastScanResults = results || stdout;
          saveState(state);

          return JSON.stringify({
            status: "completed",
            scanId,
            results: results || stdout,
            errors: stderr || undefined,
          });
        } catch (error: unknown) {
          const errorMessage = error instanceof Error ? error.message : String(error);
          return JSON.stringify({
            status: "error",
            error: errorMessage,
          });
        }
      }
    }

    case "feroxbuster_wordlists": {
      const search = args.search as string;
      const category = (args.category as string) || "common";

      let searchPath = "/usr/share/wordlists";
      let findCommand = "find";

      switch (category) {
        case "common":
          searchPath = "/usr/share/wordlists/seclists/Discovery/Web-Content";
          break;
        case "directory":
          searchPath = "/usr/share/wordlists/dirb";
          break;
        case "web":
          searchPath = "/usr/share/wordlists/seclists/Discovery";
          break;
        case "api":
          searchPath = "/usr/share/wordlists/seclists/Discovery/Web-Content/api";
          break;
        case "all":
          searchPath = "/usr/share/wordlists";
          break;
      }

      let command = `${findCommand} ${searchPath} -type f -name "*.txt" 2>/dev/null`;
      if (search) {
        command += ` | grep -i "${search}"`;
      }
      command += " | head -50";

      try {
        const { stdout } = await sshExec(command, 30000);
        const wordlists = stdout.split("\n").filter((l) => l.trim());

        return JSON.stringify({
          category,
          searchPath,
          searchTerm: search || null,
          wordlists,
          count: wordlists.length,
        });
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        return JSON.stringify({
          error: `Failed to list wordlists: ${errorMessage}`,
        });
      }
    }

    case "feroxbuster_results": {
      if (!state.lastScanResults) {
        return JSON.stringify({
          error: "No scan results available",
          hint: "Run a scan first with feroxbuster_scan",
        });
      }

      const format = (args.format as string) || "text";
      const filterStatus = args.filter_status as number[];

      let results = state.lastScanResults;

      if (filterStatus && filterStatus.length > 0) {
        const lines = results.split("\n");
        const filtered = lines.filter((line) => {
          for (const code of filterStatus) {
            if (line.includes(` ${code} `)) return true;
          }
          return false;
        });
        results = filtered.join("\n");
      }

      if (format === "urls") {
        // Extract just URLs from results
        const urlRegex = /https?:\/\/[^\s]+/g;
        const urls = results.match(urlRegex) || [];
        return JSON.stringify({
          format: "urls",
          urls: [...new Set(urls)],
          count: urls.length,
        });
      }

      if (format === "json") {
        // Try to parse JSON results or convert text to structured data
        try {
          return JSON.stringify({
            format: "json",
            results: JSON.parse(results),
          });
        } catch {
          // Convert text results to structured format
          const lines = results.split("\n").filter((l) => l.trim());
          const parsed = lines.map((line) => {
            const match = line.match(/(\d+)\s+(\d+)l\s+(\d+)w\s+(\d+)c\s+(https?:\/\/\S+)/);
            if (match) {
              return {
                status: parseInt(match[1]),
                lines: parseInt(match[2]),
                words: parseInt(match[3]),
                chars: parseInt(match[4]),
                url: match[5],
              };
            }
            return { raw: line };
          });

          return JSON.stringify({
            format: "json",
            results: parsed,
          });
        }
      }

      return JSON.stringify({
        format: "text",
        results,
      });
    }

    case "feroxbuster_version": {
      try {
        const { stdout } = await sshExec("feroxbuster --version", 10000);
        return JSON.stringify({
          version: stdout.trim(),
          host: KALI_HOST,
        });
      } catch (error: unknown) {
        const errorMessage = error instanceof Error ? error.message : String(error);
        return JSON.stringify({
          error: `Failed to get version: ${errorMessage}`,
          hint: "Ensure feroxbuster is installed on the Kali host and SSH is configured",
        });
      }
    }

    default:
      return JSON.stringify({ error: `Unknown tool: ${name}` });
  }
}

// Create and run server
async function main() {
  const server = new Server(
    {
      name: "feroxbuster-mcp",
      version: "1.0.0",
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools,
  }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    const result = await handleToolCall(name, args || {});
    return {
      content: [{ type: "text", text: result }],
    };
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);

  console.error("feroxbuster-mcp server running on stdio");
}

main().catch(console.error);
