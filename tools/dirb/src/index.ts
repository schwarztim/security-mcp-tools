#!/usr/bin/env node

/**
 * DIRB MCP Server
 *
 * This MCP server provides tools for interacting with DIRB (Web Content Scanner)
 * via SSH to a Kali Linux machine.
 *
 * DIRB is a dictionary-based web content scanner that looks for existing
 * (and/or hidden) web objects by launching a dictionary-based attack against
 * a web server and analyzing the responses.
 *
 * Environment Variables:
 * - KALI_SSH_HOST: The Kali Linux SSH host (default: kali)
 * - KALI_SSH_USER: SSH username (optional, uses SSH config if not set)
 * - KALI_SSH_PORT: SSH port (default: 22)
 * - DIRB_WORDLIST_PATH: Default wordlist path (default: /usr/share/dirb/wordlists/common.txt)
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { spawn } from "child_process";

// Configuration from environment
const config = {
  sshHost: process.env.KALI_SSH_HOST || "kali",
  sshUser: process.env.KALI_SSH_USER || "",
  sshPort: process.env.KALI_SSH_PORT || "22",
  defaultWordlist: process.env.DIRB_WORDLIST_PATH || "/usr/share/dirb/wordlists/common.txt",
};

// Common wordlists available in Kali Linux
const WORDLISTS = {
  common: "/usr/share/dirb/wordlists/common.txt",
  big: "/usr/share/dirb/wordlists/big.txt",
  small: "/usr/share/dirb/wordlists/small.txt",
  extensions_common: "/usr/share/dirb/wordlists/extensions_common.txt",
  mutations_common: "/usr/share/dirb/wordlists/mutations_common.txt",
  catala: "/usr/share/dirb/wordlists/catala.txt",
  euskera: "/usr/share/dirb/wordlists/euskera.txt",
  spanish: "/usr/share/dirb/wordlists/spanish.txt",
  others_names: "/usr/share/dirb/wordlists/others/names.txt",
  vulns_apache: "/usr/share/dirb/wordlists/vulns/apache.txt",
  vulns_iis: "/usr/share/dirb/wordlists/vulns/iis.txt",
  vulns_cgis: "/usr/share/dirb/wordlists/vulns/cgis.txt",
  vulns_netware: "/usr/share/dirb/wordlists/vulns/netware.txt",
  vulns_weblogic: "/usr/share/dirb/wordlists/vulns/weblogic.txt",
  vulns_tomcat: "/usr/share/dirb/wordlists/vulns/tomcat.txt",
  vulns_frontpage: "/usr/share/dirb/wordlists/vulns/frontpage.txt",
  vulns_sap: "/usr/share/dirb/wordlists/vulns/sap.txt",
  vulns_sharepoint: "/usr/share/dirb/wordlists/vulns/sharepoint.txt",
  stress_test_big: "/usr/share/dirb/wordlists/stress/stress_test_1.txt",
};

// Interface for scan results
interface DirbResult {
  url: string;
  code: number;
  size: number;
  found: boolean;
}

// Interface for scan output
interface ScanOutput {
  target: string;
  wordlist: string;
  startTime: string;
  endTime: string;
  results: DirbResult[];
  rawOutput: string;
  testedWords: number;
  foundDirectories: number;
  command: string;
}

// Execute SSH command to Kali and run dirb
async function executeSSHCommand(
  command: string,
  timeout: number = 300000 // 5 minutes default timeout
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  return new Promise((resolve) => {
    const stdout: string[] = [];
    const stderr: string[] = [];

    // Build SSH command
    const sshArgs: string[] = [];

    if (config.sshPort !== "22") {
      sshArgs.push("-p", config.sshPort);
    }

    // Add connection timeout and batch mode
    sshArgs.push("-o", "ConnectTimeout=10");
    sshArgs.push("-o", "BatchMode=yes");
    sshArgs.push("-o", "StrictHostKeyChecking=accept-new");

    // Build the host string
    const host = config.sshUser ? `${config.sshUser}@${config.sshHost}` : config.sshHost;
    sshArgs.push(host);
    sshArgs.push(command);

    const proc = spawn("ssh", sshArgs, {
      stdio: ["pipe", "pipe", "pipe"],
      shell: false,
    });

    // Set up timeout
    const timeoutId = setTimeout(() => {
      proc.kill("SIGTERM");
      stderr.push(`\nCommand timed out after ${timeout / 1000} seconds`);
    }, timeout);

    proc.stdout.on("data", (data) => {
      stdout.push(data.toString());
    });

    proc.stderr.on("data", (data) => {
      stderr.push(data.toString());
    });

    proc.on("close", (code) => {
      clearTimeout(timeoutId);
      resolve({
        stdout: stdout.join(""),
        stderr: stderr.join(""),
        exitCode: code ?? 0,
      });
    });

    proc.on("error", (err) => {
      clearTimeout(timeoutId);
      resolve({
        stdout: stdout.join(""),
        stderr: `Error executing SSH command: ${err.message}`,
        exitCode: 1,
      });
    });
  });
}

// Parse DIRB output to extract results
function parseDirbOutput(output: string): DirbResult[] {
  const results: DirbResult[] = [];
  const lines = output.split("\n");

  // DIRB output format: + URL (CODE:xxx|SIZE:xxx)
  const resultPattern = /\+\s+(\S+)\s+\(CODE:(\d+)\|SIZE:(\d+)\)/;

  for (const line of lines) {
    const match = line.match(resultPattern);
    if (match) {
      results.push({
        url: match[1],
        code: parseInt(match[2], 10),
        size: parseInt(match[3], 10),
        found: true,
      });
    }
  }

  return results;
}

// Extract scan statistics from output
function extractStats(output: string): { tested: number; found: number } {
  let tested = 0;
  let found = 0;

  // Look for "GENERATED WORDS" line
  const wordsMatch = output.match(/GENERATED WORDS:\s*(\d+)/);
  if (wordsMatch) {
    tested = parseInt(wordsMatch[1], 10);
  }

  // Count found results
  const foundMatches = output.match(/\+\s+\S+\s+\(CODE:/g);
  if (foundMatches) {
    found = foundMatches.length;
  }

  return { tested, found };
}

// Build dirb command with options
function buildDirbCommand(options: {
  url: string;
  wordlist?: string;
  extensions?: string;
  extensionsFile?: string;
  cookie?: string;
  userAgent?: string;
  httpAuth?: string;
  proxy?: string;
  proxyAuth?: string;
  outputFile?: string;
  recursive?: boolean;
  interactiveRecursive?: boolean;
  caseInsensitive?: boolean;
  showLocation?: boolean;
  ignoreCode?: number;
  delay?: number;
  noEndingSlash?: boolean;
  silentMode?: boolean;
  showNotFound?: boolean;
  noWarnings?: boolean;
  customHeader?: string;
  clientCert?: string;
  fineTuning404?: boolean;
}): string {
  const args: string[] = ["dirb", options.url];

  // Add wordlist
  const wordlist = options.wordlist || config.defaultWordlist;
  args.push(wordlist);

  // Extensions
  if (options.extensions) {
    args.push("-X", options.extensions);
  }
  if (options.extensionsFile) {
    args.push("-x", options.extensionsFile);
  }

  // Cookie
  if (options.cookie) {
    args.push("-c", `"${options.cookie}"`);
  }

  // User agent
  if (options.userAgent) {
    args.push("-a", `"${options.userAgent}"`);
  }

  // HTTP authentication
  if (options.httpAuth) {
    args.push("-u", options.httpAuth);
  }

  // Proxy settings
  if (options.proxy) {
    args.push("-p", options.proxy);
  }
  if (options.proxyAuth) {
    args.push("-P", options.proxyAuth);
  }

  // Output file
  if (options.outputFile) {
    args.push("-o", options.outputFile);
  }

  // Recursive options
  if (options.recursive === false) {
    args.push("-r");
  }
  if (options.interactiveRecursive) {
    args.push("-R");
  }

  // Case insensitive
  if (options.caseInsensitive) {
    args.push("-i");
  }

  // Show location header
  if (options.showLocation) {
    args.push("-l");
  }

  // Ignore specific HTTP code
  if (options.ignoreCode) {
    args.push("-N", String(options.ignoreCode));
  }

  // Delay
  if (options.delay) {
    args.push("-z", String(options.delay));
  }

  // No ending slash
  if (options.noEndingSlash) {
    args.push("-t");
  }

  // Silent mode
  if (options.silentMode) {
    args.push("-S");
  }

  // Show not found
  if (options.showNotFound) {
    args.push("-v");
  }

  // No warnings
  if (options.noWarnings) {
    args.push("-w");
  }

  // Custom header
  if (options.customHeader) {
    args.push("-H", `"${options.customHeader}"`);
  }

  // Client certificate
  if (options.clientCert) {
    args.push("-E", options.clientCert);
  }

  // Fine tuning 404
  if (options.fineTuning404) {
    args.push("-f");
  }

  return args.join(" ");
}

// Define MCP tools
const tools: Tool[] = [
  {
    name: "dirb_scan",
    description:
      "Start a DIRB directory scan against a target URL. DIRB performs dictionary-based attacks against web servers to discover hidden directories and files. Runs via SSH on Kali Linux.",
    inputSchema: {
      type: "object",
      properties: {
        url: {
          type: "string",
          description: "Target URL to scan (e.g., http://example.com or https://192.168.1.100)",
        },
        wordlist: {
          type: "string",
          description: "Wordlist to use. Can be a preset name (common, big, small, vulns_apache, vulns_iis, etc.) or a full path. Default: common",
        },
        extensions: {
          type: "string",
          description: "File extensions to append to each word, comma-separated (e.g., '.php,.html,.bak,.txt')",
        },
        recursive: {
          type: "boolean",
          description: "Enable recursive scanning (default: true). Set to false to disable.",
        },
        delay: {
          type: "number",
          description: "Delay in milliseconds between requests to avoid flooding (e.g., 100 for 100ms)",
        },
        caseInsensitive: {
          type: "boolean",
          description: "Use case-insensitive search (default: false)",
        },
        ignoreCode: {
          type: "number",
          description: "Ignore responses with this HTTP status code (e.g., 404)",
        },
        timeout: {
          type: "number",
          description: "Scan timeout in seconds (default: 300)",
        },
      },
      required: ["url"],
    },
  },
  {
    name: "dirb_scan_auth",
    description:
      "Start a DIRB scan with HTTP Basic Authentication. Use this when the target requires authentication.",
    inputSchema: {
      type: "object",
      properties: {
        url: {
          type: "string",
          description: "Target URL to scan",
        },
        username: {
          type: "string",
          description: "HTTP Basic Auth username",
        },
        password: {
          type: "string",
          description: "HTTP Basic Auth password",
        },
        wordlist: {
          type: "string",
          description: "Wordlist preset name or full path (default: common)",
        },
        extensions: {
          type: "string",
          description: "File extensions to append (e.g., '.php,.html')",
        },
        timeout: {
          type: "number",
          description: "Scan timeout in seconds (default: 300)",
        },
      },
      required: ["url", "username", "password"],
    },
  },
  {
    name: "dirb_scan_proxy",
    description:
      "Start a DIRB scan through a proxy (e.g., Burp Suite, OWASP ZAP). Useful for intercepting and analyzing traffic.",
    inputSchema: {
      type: "object",
      properties: {
        url: {
          type: "string",
          description: "Target URL to scan",
        },
        proxy: {
          type: "string",
          description: "Proxy address in format host:port (e.g., '127.0.0.1:8080')",
        },
        proxyAuth: {
          type: "string",
          description: "Proxy authentication in format username:password (optional)",
        },
        wordlist: {
          type: "string",
          description: "Wordlist preset name or full path (default: common)",
        },
        extensions: {
          type: "string",
          description: "File extensions to append (e.g., '.php,.html')",
        },
        timeout: {
          type: "number",
          description: "Scan timeout in seconds (default: 300)",
        },
      },
      required: ["url", "proxy"],
    },
  },
  {
    name: "dirb_scan_custom",
    description:
      "Advanced DIRB scan with full control over all options. Use this for specialized scanning needs.",
    inputSchema: {
      type: "object",
      properties: {
        url: {
          type: "string",
          description: "Target URL to scan",
        },
        wordlist: {
          type: "string",
          description: "Wordlist preset name or full path",
        },
        extensions: {
          type: "string",
          description: "File extensions to append (e.g., '.php,.html,.bak')",
        },
        extensionsFile: {
          type: "string",
          description: "Path to file containing extensions to try",
        },
        cookie: {
          type: "string",
          description: "Cookie string to include in requests",
        },
        userAgent: {
          type: "string",
          description: "Custom User-Agent string",
        },
        httpAuth: {
          type: "string",
          description: "HTTP Basic Auth in format username:password",
        },
        proxy: {
          type: "string",
          description: "Proxy in format host:port",
        },
        proxyAuth: {
          type: "string",
          description: "Proxy auth in format username:password",
        },
        recursive: {
          type: "boolean",
          description: "Enable recursive scanning (default: true)",
        },
        caseInsensitive: {
          type: "boolean",
          description: "Case-insensitive search",
        },
        showLocation: {
          type: "boolean",
          description: "Show Location header when found",
        },
        ignoreCode: {
          type: "number",
          description: "Ignore this HTTP status code",
        },
        delay: {
          type: "number",
          description: "Delay in milliseconds between requests",
        },
        noEndingSlash: {
          type: "boolean",
          description: "Don't force ending '/' on URLs",
        },
        silentMode: {
          type: "boolean",
          description: "Silent mode - don't show tested words",
        },
        showNotFound: {
          type: "boolean",
          description: "Show NOT_FOUND pages",
        },
        noWarnings: {
          type: "boolean",
          description: "Don't stop on warning messages",
        },
        customHeader: {
          type: "string",
          description: "Custom HTTP header (e.g., 'X-Custom: value')",
        },
        clientCert: {
          type: "string",
          description: "Path to client certificate file",
        },
        fineTuning404: {
          type: "boolean",
          description: "Fine tuning of NOT_FOUND (404) detection",
        },
        timeout: {
          type: "number",
          description: "Scan timeout in seconds (default: 300)",
        },
      },
      required: ["url"],
    },
  },
  {
    name: "dirb_list_wordlists",
    description:
      "List all available preset wordlists for DIRB scanning. Shows both general wordlists and vulnerability-specific ones.",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "dirb_check_status",
    description:
      "Check DIRB installation status and SSH connectivity to Kali Linux. Verifies that the MCP server can communicate with the Kali machine.",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "dirb_vuln_scan",
    description:
      "Run a vulnerability-focused DIRB scan using specialized wordlists for specific technologies (Apache, IIS, Tomcat, etc.).",
    inputSchema: {
      type: "object",
      properties: {
        url: {
          type: "string",
          description: "Target URL to scan",
        },
        technology: {
          type: "string",
          enum: ["apache", "iis", "tomcat", "weblogic", "frontpage", "netware", "cgis", "sap", "sharepoint"],
          description: "Target technology to scan for vulnerabilities",
        },
        extensions: {
          type: "string",
          description: "Additional file extensions to try (e.g., '.bak,.old')",
        },
        delay: {
          type: "number",
          description: "Delay in milliseconds between requests",
        },
        timeout: {
          type: "number",
          description: "Scan timeout in seconds (default: 300)",
        },
      },
      required: ["url", "technology"],
    },
  },
];

// Handle tool execution
async function handleToolCall(
  name: string,
  args: Record<string, unknown>
): Promise<string> {
  switch (name) {
    case "dirb_scan": {
      const url = args.url as string;
      let wordlist = args.wordlist as string | undefined;

      // Resolve wordlist preset to path
      if (wordlist && WORDLISTS[wordlist as keyof typeof WORDLISTS]) {
        wordlist = WORDLISTS[wordlist as keyof typeof WORDLISTS];
      }

      const command = buildDirbCommand({
        url,
        wordlist,
        extensions: args.extensions as string | undefined,
        recursive: args.recursive as boolean | undefined,
        delay: args.delay as number | undefined,
        caseInsensitive: args.caseInsensitive as boolean | undefined,
        ignoreCode: args.ignoreCode as number | undefined,
      });

      const timeout = ((args.timeout as number) || 300) * 1000;
      const startTime = new Date().toISOString();

      console.error(`Executing: ssh ${config.sshHost} "${command}"`);

      const result = await executeSSHCommand(command, timeout);
      const endTime = new Date().toISOString();

      if (result.exitCode !== 0 && result.stderr && !result.stdout) {
        return `# DIRB Scan Error

**Target**: ${url}
**Command**: \`${command}\`

**Error**:
\`\`\`
${result.stderr}
\`\`\`

Please verify:
1. SSH connectivity to Kali: \`ssh ${config.sshHost}\`
2. DIRB is installed: \`ssh ${config.sshHost} "which dirb"\`
3. Target URL is reachable from Kali
`;
      }

      const results = parseDirbOutput(result.stdout);
      const stats = extractStats(result.stdout);

      const output: ScanOutput = {
        target: url,
        wordlist: wordlist || config.defaultWordlist,
        startTime,
        endTime,
        results,
        rawOutput: result.stdout,
        testedWords: stats.tested,
        foundDirectories: stats.found,
        command,
      };

      return formatScanOutput(output);
    }

    case "dirb_scan_auth": {
      const url = args.url as string;
      const username = args.username as string;
      const password = args.password as string;
      let wordlist = args.wordlist as string | undefined;

      if (wordlist && WORDLISTS[wordlist as keyof typeof WORDLISTS]) {
        wordlist = WORDLISTS[wordlist as keyof typeof WORDLISTS];
      }

      const command = buildDirbCommand({
        url,
        wordlist,
        extensions: args.extensions as string | undefined,
        httpAuth: `${username}:${password}`,
      });

      const timeout = ((args.timeout as number) || 300) * 1000;
      const startTime = new Date().toISOString();

      const result = await executeSSHCommand(command, timeout);
      const endTime = new Date().toISOString();

      if (result.exitCode !== 0 && result.stderr && !result.stdout) {
        return `# DIRB Authenticated Scan Error

**Target**: ${url}
**Username**: ${username}

**Error**:
\`\`\`
${result.stderr}
\`\`\`
`;
      }

      const results = parseDirbOutput(result.stdout);
      const stats = extractStats(result.stdout);

      return formatScanOutput({
        target: url,
        wordlist: wordlist || config.defaultWordlist,
        startTime,
        endTime,
        results,
        rawOutput: result.stdout,
        testedWords: stats.tested,
        foundDirectories: stats.found,
        command: command.replace(password, "********"),
      });
    }

    case "dirb_scan_proxy": {
      const url = args.url as string;
      const proxy = args.proxy as string;
      let wordlist = args.wordlist as string | undefined;

      if (wordlist && WORDLISTS[wordlist as keyof typeof WORDLISTS]) {
        wordlist = WORDLISTS[wordlist as keyof typeof WORDLISTS];
      }

      const command = buildDirbCommand({
        url,
        wordlist,
        extensions: args.extensions as string | undefined,
        proxy,
        proxyAuth: args.proxyAuth as string | undefined,
      });

      const timeout = ((args.timeout as number) || 300) * 1000;
      const startTime = new Date().toISOString();

      const result = await executeSSHCommand(command, timeout);
      const endTime = new Date().toISOString();

      if (result.exitCode !== 0 && result.stderr && !result.stdout) {
        return `# DIRB Proxy Scan Error

**Target**: ${url}
**Proxy**: ${proxy}

**Error**:
\`\`\`
${result.stderr}
\`\`\`

Verify the proxy is running and accessible from Kali.
`;
      }

      const results = parseDirbOutput(result.stdout);
      const stats = extractStats(result.stdout);

      return formatScanOutput({
        target: url,
        wordlist: wordlist || config.defaultWordlist,
        startTime,
        endTime,
        results,
        rawOutput: result.stdout,
        testedWords: stats.tested,
        foundDirectories: stats.found,
        command,
      });
    }

    case "dirb_scan_custom": {
      const url = args.url as string;
      let wordlist = args.wordlist as string | undefined;

      if (wordlist && WORDLISTS[wordlist as keyof typeof WORDLISTS]) {
        wordlist = WORDLISTS[wordlist as keyof typeof WORDLISTS];
      }

      const command = buildDirbCommand({
        url,
        wordlist,
        extensions: args.extensions as string | undefined,
        extensionsFile: args.extensionsFile as string | undefined,
        cookie: args.cookie as string | undefined,
        userAgent: args.userAgent as string | undefined,
        httpAuth: args.httpAuth as string | undefined,
        proxy: args.proxy as string | undefined,
        proxyAuth: args.proxyAuth as string | undefined,
        recursive: args.recursive as boolean | undefined,
        caseInsensitive: args.caseInsensitive as boolean | undefined,
        showLocation: args.showLocation as boolean | undefined,
        ignoreCode: args.ignoreCode as number | undefined,
        delay: args.delay as number | undefined,
        noEndingSlash: args.noEndingSlash as boolean | undefined,
        silentMode: args.silentMode as boolean | undefined,
        showNotFound: args.showNotFound as boolean | undefined,
        noWarnings: args.noWarnings as boolean | undefined,
        customHeader: args.customHeader as string | undefined,
        clientCert: args.clientCert as string | undefined,
        fineTuning404: args.fineTuning404 as boolean | undefined,
      });

      const timeout = ((args.timeout as number) || 300) * 1000;
      const startTime = new Date().toISOString();

      const result = await executeSSHCommand(command, timeout);
      const endTime = new Date().toISOString();

      if (result.exitCode !== 0 && result.stderr && !result.stdout) {
        return `# DIRB Custom Scan Error

**Command**: \`${command}\`

**Error**:
\`\`\`
${result.stderr}
\`\`\`
`;
      }

      const results = parseDirbOutput(result.stdout);
      const stats = extractStats(result.stdout);

      return formatScanOutput({
        target: url,
        wordlist: wordlist || config.defaultWordlist,
        startTime,
        endTime,
        results,
        rawOutput: result.stdout,
        testedWords: stats.tested,
        foundDirectories: stats.found,
        command,
      });
    }

    case "dirb_list_wordlists": {
      let output = `# DIRB Wordlists

## General Wordlists

| Name | Path | Description |
|------|------|-------------|
| common | ${WORDLISTS.common} | Standard common directory names |
| big | ${WORDLISTS.big} | Large comprehensive wordlist |
| small | ${WORDLISTS.small} | Quick scan with common names |
| extensions_common | ${WORDLISTS.extensions_common} | Common file extensions |
| mutations_common | ${WORDLISTS.mutations_common} | Common mutations/variations |

## Language-Specific

| Name | Path | Description |
|------|------|-------------|
| catala | ${WORDLISTS.catala} | Catalan language terms |
| euskera | ${WORDLISTS.euskera} | Basque language terms |
| spanish | ${WORDLISTS.spanish} | Spanish language terms |
| others_names | ${WORDLISTS.others_names} | Common names |

## Vulnerability Wordlists

| Name | Path | Description |
|------|------|-------------|
| vulns_apache | ${WORDLISTS.vulns_apache} | Apache-specific vulnerabilities |
| vulns_iis | ${WORDLISTS.vulns_iis} | IIS-specific vulnerabilities |
| vulns_tomcat | ${WORDLISTS.vulns_tomcat} | Tomcat-specific paths |
| vulns_weblogic | ${WORDLISTS.vulns_weblogic} | WebLogic-specific paths |
| vulns_frontpage | ${WORDLISTS.vulns_frontpage} | FrontPage-specific paths |
| vulns_netware | ${WORDLISTS.vulns_netware} | NetWare-specific paths |
| vulns_cgis | ${WORDLISTS.vulns_cgis} | Common CGI vulnerabilities |
| vulns_sap | ${WORDLISTS.vulns_sap} | SAP-specific paths |
| vulns_sharepoint | ${WORDLISTS.vulns_sharepoint} | SharePoint-specific paths |

## Stress Testing

| Name | Path | Description |
|------|------|-------------|
| stress_test_big | ${WORDLISTS.stress_test_big} | Large wordlist for stress testing |

## Usage

Use the wordlist name in the \`wordlist\` parameter:
- \`dirb_scan\` with \`wordlist: "big"\`
- \`dirb_vuln_scan\` with \`technology: "apache"\`

Or provide a full path to a custom wordlist.
`;

      return output;
    }

    case "dirb_check_status": {
      // Check SSH connectivity
      const sshCheck = await executeSSHCommand("echo 'SSH OK'", 10000);
      const sshOk = sshCheck.exitCode === 0 && sshCheck.stdout.includes("SSH OK");

      // Check DIRB installation
      const dirbCheck = await executeSSHCommand("which dirb && dirb 2>&1 | head -5", 10000);
      const dirbInstalled = dirbCheck.exitCode === 0 || dirbCheck.stdout.includes("dirb");

      // Get DIRB version if installed
      const versionCheck = await executeSSHCommand("dirb 2>&1 | grep -i 'DIRB v' | head -1", 10000);
      const version = versionCheck.stdout.trim() || "Unknown";

      return `# DIRB MCP Status

## SSH Connection
- **Host**: ${config.sshHost}
- **User**: ${config.sshUser || "(using SSH config)"}
- **Port**: ${config.sshPort}
- **Status**: ${sshOk ? "Connected" : "Failed"}
${!sshOk ? `- **Error**: ${sshCheck.stderr}` : ""}

## DIRB Installation
- **Installed**: ${dirbInstalled ? "Yes" : "No"}
- **Version**: ${version}
- **Default Wordlist**: ${config.defaultWordlist}

## Configuration
- **KALI_SSH_HOST**: ${process.env.KALI_SSH_HOST || "(not set, using 'kali')"}
- **KALI_SSH_USER**: ${process.env.KALI_SSH_USER || "(not set, using SSH config)"}
- **KALI_SSH_PORT**: ${process.env.KALI_SSH_PORT || "(not set, using 22)"}

${!sshOk ? `
## Troubleshooting

1. **Test SSH manually**:
   \`\`\`bash
   ssh ${config.sshUser ? config.sshUser + "@" : ""}${config.sshHost}
   \`\`\`

2. **Check SSH config** (\`~/.ssh/config\`):
   \`\`\`
   Host kali
       HostName <kali-ip-address>
       User <username>
       IdentityFile ~/.ssh/id_rsa
   \`\`\`

3. **Verify Kali is accessible** from this machine
` : ""}

${!dirbInstalled ? `
## Installing DIRB

On Kali Linux, install DIRB with:
\`\`\`bash
sudo apt update && sudo apt install dirb
\`\`\`
` : ""}
`;
    }

    case "dirb_vuln_scan": {
      const url = args.url as string;
      const technology = args.technology as string;

      // Map technology to wordlist
      const techWordlists: Record<string, string> = {
        apache: WORDLISTS.vulns_apache,
        iis: WORDLISTS.vulns_iis,
        tomcat: WORDLISTS.vulns_tomcat,
        weblogic: WORDLISTS.vulns_weblogic,
        frontpage: WORDLISTS.vulns_frontpage,
        netware: WORDLISTS.vulns_netware,
        cgis: WORDLISTS.vulns_cgis,
        sap: WORDLISTS.vulns_sap,
        sharepoint: WORDLISTS.vulns_sharepoint,
      };

      const wordlist = techWordlists[technology];
      if (!wordlist) {
        return `Error: Unknown technology "${technology}". Supported: ${Object.keys(techWordlists).join(", ")}`;
      }

      const command = buildDirbCommand({
        url,
        wordlist,
        extensions: args.extensions as string | undefined,
        delay: args.delay as number | undefined,
      });

      const timeout = ((args.timeout as number) || 300) * 1000;
      const startTime = new Date().toISOString();

      const result = await executeSSHCommand(command, timeout);
      const endTime = new Date().toISOString();

      if (result.exitCode !== 0 && result.stderr && !result.stdout) {
        return `# DIRB Vulnerability Scan Error

**Target**: ${url}
**Technology**: ${technology}
**Wordlist**: ${wordlist}

**Error**:
\`\`\`
${result.stderr}
\`\`\`
`;
      }

      const results = parseDirbOutput(result.stdout);
      const stats = extractStats(result.stdout);

      let output = formatScanOutput({
        target: url,
        wordlist,
        startTime,
        endTime,
        results,
        rawOutput: result.stdout,
        testedWords: stats.tested,
        foundDirectories: stats.found,
        command,
      });

      // Add vulnerability context
      output += `
## Vulnerability Context: ${technology.toUpperCase()}

This scan used the ${technology}-specific wordlist to identify potential vulnerabilities and sensitive paths common to ${technology} deployments.

### What to Check

1. **Configuration files** - May expose sensitive settings
2. **Admin panels** - Unauthorized access potential
3. **Backup files** - May contain credentials
4. **Version info** - Helps identify CVEs

### Next Steps

- Review each found path manually
- Check for default credentials
- Search for known CVEs for this technology
- Consider running additional tools (Nikto, Nuclei)
`;

      return output;
    }

    default:
      return `Unknown tool: ${name}`;
  }
}

// Format scan output for display
function formatScanOutput(output: ScanOutput): string {
  let result = `# DIRB Scan Results

## Summary
- **Target**: ${output.target}
- **Wordlist**: ${output.wordlist}
- **Start Time**: ${output.startTime}
- **End Time**: ${output.endTime}
- **Words Tested**: ${output.testedWords}
- **Directories Found**: ${output.foundDirectories}

## Command
\`\`\`
${output.command}
\`\`\`

`;

  if (output.results.length === 0) {
    result += `## Results

No directories or files were found with the current wordlist.

**Suggestions**:
- Try a larger wordlist (e.g., "big")
- Add file extensions (e.g., -X ".php,.html,.bak")
- Try case-insensitive search (-i)
- Use a technology-specific wordlist
`;
  } else {
    result += `## Found Paths (${output.results.length})

| URL | Status Code | Size |
|-----|-------------|------|
`;

    for (const r of output.results) {
      result += `| ${r.url} | ${r.code} | ${r.size} |\n`;
    }

    result += `
### Status Code Legend
- **200**: OK - Resource exists
- **301/302**: Redirect - May indicate valid path
- **401**: Unauthorized - Requires authentication
- **403**: Forbidden - Access denied but exists
- **500**: Server Error - May indicate vulnerability
`;
  }

  return result;
}

// Main server setup
async function main() {
  const server = new Server(
    {
      name: "dirb-mcp",
      version: "1.0.0",
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  // Log configuration on startup
  console.error("DIRB MCP Server starting...");
  console.error(`SSH Host: ${config.sshHost}`);
  console.error(`SSH User: ${config.sshUser || "(using SSH config)"}`);
  console.error(`SSH Port: ${config.sshPort}`);
  console.error(`Default Wordlist: ${config.defaultWordlist}`);

  // Handle tool listing
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return { tools };
  });

  // Handle tool execution
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    try {
      const result = await handleToolCall(name, (args || {}) as Record<string, unknown>);
      return {
        content: [
          {
            type: "text",
            text: result,
          },
        ],
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      return {
        content: [
          {
            type: "text",
            text: `Error executing tool ${name}: ${errorMessage}`,
          },
        ],
        isError: true,
      };
    }
  });

  // Start the server
  const transport = new StdioServerTransport();
  await server.connect(transport);

  console.error("DIRB MCP Server started successfully");
}

main().catch((error) => {
  console.error("Fatal error starting DIRB MCP Server:", error);
  process.exit(1);
});
