#!/usr/bin/env node
/**
 * httpx MCP Server
 *
 * MCP server for ProjectDiscovery's httpx HTTP toolkit.
 * Executes httpx commands on a remote Kali Linux system via SSH.
 *
 * Features:
 * - HTTP probing and server detection
 * - Technology detection (Wappalyzer-based)
 * - Status code filtering
 * - Page title extraction
 * - Screenshot capture
 * - CDN detection
 * - Pipeline integration with other tools
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
const SSH_HOST = process.env.HTTPX_SSH_HOST || "kali";
const SSH_TIMEOUT = parseInt(process.env.HTTPX_TIMEOUT || "300000"); // 5 minutes default
const HTTPX_BINARY = process.env.HTTPX_BINARY || "~/bin/httpx-pd"; // ProjectDiscovery httpx binary

interface HttpxOptions {
  targets: string[];
  statusCode?: boolean;
  contentLength?: boolean;
  title?: boolean;
  techDetect?: boolean;
  webServer?: boolean;
  ip?: boolean;
  cname?: boolean;
  cdn?: boolean;
  probe?: boolean;
  favicon?: boolean;
  jarm?: boolean;
  responseTime?: boolean;
  location?: boolean;
  method?: boolean;
  matchCodes?: string;
  filterCodes?: string;
  matchString?: string;
  filterString?: string;
  threads?: number;
  rateLimit?: number;
  timeout?: number;
  retries?: number;
  ports?: string;
  path?: string;
  followRedirects?: boolean;
  maxRedirects?: number;
  http2?: boolean;
  tlsProbe?: boolean;
  screenshot?: boolean;
  screenshotDir?: string;
  jsonOutput?: boolean;
  silent?: boolean;
  noColor?: boolean;
  verbose?: boolean;
  headers?: string[];
  customFlags?: string;
}

interface HttpxResult {
  success: boolean;
  output: string;
  error?: string;
  command: string;
  executionTime: number;
  resultCount: number;
}

/**
 * Execute httpx command via SSH on Kali
 */
async function executeHttpx(options: HttpxOptions): Promise<HttpxResult> {
  const startTime = Date.now();

  // Build httpx command
  const args: string[] = [];

  // Input - use stdin for multiple targets
  if (options.targets.length === 1) {
    args.push(`-u "${options.targets[0]}"`);
  }

  // Probe options
  if (options.statusCode) args.push("-sc");
  if (options.contentLength) args.push("-cl");
  if (options.title) args.push("-title");
  if (options.techDetect) args.push("-tech-detect");
  if (options.webServer) args.push("-server");
  if (options.ip) args.push("-ip");
  if (options.cname) args.push("-cname");
  if (options.cdn) args.push("-cdn");
  if (options.probe) args.push("-probe");
  if (options.favicon) args.push("-favicon");
  if (options.jarm) args.push("-jarm");
  if (options.responseTime) args.push("-rt");
  if (options.location) args.push("-location");
  if (options.method) args.push("-method");

  // Matchers and filters
  if (options.matchCodes) args.push(`-mc "${options.matchCodes}"`);
  if (options.filterCodes) args.push(`-fc "${options.filterCodes}"`);
  if (options.matchString) args.push(`-ms "${options.matchString}"`);
  if (options.filterString) args.push(`-fs "${options.filterString}"`);

  // Performance options
  if (options.threads) args.push(`-t ${options.threads}`);
  if (options.rateLimit) args.push(`-rl ${options.rateLimit}`);
  if (options.timeout) args.push(`-timeout ${options.timeout}`);
  if (options.retries) args.push(`-retries ${options.retries}`);

  // Target options
  if (options.ports) args.push(`-p "${options.ports}"`);
  if (options.path) args.push(`-path "${options.path}"`);

  // HTTP options
  if (options.followRedirects) args.push("-fr");
  if (options.maxRedirects) args.push(`-maxr ${options.maxRedirects}`);
  if (options.http2) args.push("-http2");
  if (options.tlsProbe) args.push("-tls-probe");

  // Screenshot
  if (options.screenshot) {
    args.push("-screenshot");
    if (options.screenshotDir) args.push(`-srd "${options.screenshotDir}"`);
  }

  // Output options
  if (options.jsonOutput) args.push("-json");
  if (options.silent) args.push("-silent");
  if (options.noColor) args.push("-nc");
  if (options.verbose) args.push("-v");

  // Custom headers
  if (options.headers && options.headers.length > 0) {
    for (const header of options.headers) {
      args.push(`-H "${header}"`);
    }
  }

  // Custom flags
  if (options.customFlags) args.push(options.customFlags);

  // Build the full command
  let httpxCmd: string;
  if (options.targets.length === 1) {
    httpxCmd = `${HTTPX_BINARY} ${args.join(" ")}`;
  } else {
    // Multiple targets - use echo and pipe
    const targetList = options.targets.map(t => t.replace(/"/g, '\\"')).join("\\n");
    httpxCmd = `echo -e "${targetList}" | ${HTTPX_BINARY} ${args.join(" ")}`;
  }

  // SSH command
  const sshCmd = `ssh ${SSH_HOST} '${httpxCmd.replace(/'/g, "'\"'\"'")}'`;

  try {
    const { stdout, stderr } = await execAsync(sshCmd, {
      timeout: SSH_TIMEOUT,
      maxBuffer: 50 * 1024 * 1024, // 50MB buffer for large outputs
    });

    const output = stdout.trim();
    const lines = output.split("\n").filter(l => l.trim());

    return {
      success: true,
      output,
      command: httpxCmd,
      executionTime: Date.now() - startTime,
      resultCount: lines.length,
    };
  } catch (error: any) {
    return {
      success: false,
      output: error.stdout || "",
      error: error.stderr || error.message,
      command: httpxCmd,
      executionTime: Date.now() - startTime,
      resultCount: 0,
    };
  }
}

// Define MCP tools
const tools: Tool[] = [
  {
    name: "httpx_probe",
    description: `Probe HTTP/HTTPS servers to check availability and gather basic information.

This is the primary reconnaissance tool for discovering live web servers from a list of hosts or URLs.
Returns active URLs with optional status codes, titles, and server info.

Example use cases:
- Discover live web servers from subdomain enumeration output
- Validate if hosts are responding on HTTP/HTTPS
- Get initial recon data before deeper scanning`,
    inputSchema: {
      type: "object",
      properties: {
        targets: {
          type: "array",
          items: { type: "string" },
          description: "List of hosts, URLs, or IP addresses to probe",
        },
        status_code: {
          type: "boolean",
          description: "Display HTTP status codes",
          default: true,
        },
        title: {
          type: "boolean",
          description: "Extract and display page titles",
          default: true,
        },
        content_length: {
          type: "boolean",
          description: "Display response content length",
          default: false,
        },
        web_server: {
          type: "boolean",
          description: "Display web server name from headers",
          default: false,
        },
        follow_redirects: {
          type: "boolean",
          description: "Follow HTTP redirects",
          default: true,
        },
        ports: {
          type: "string",
          description: "Ports to probe (e.g., '80,443,8080' or '80-443')",
        },
        threads: {
          type: "number",
          description: "Number of concurrent threads (default: 50)",
          default: 50,
        },
        timeout: {
          type: "number",
          description: "HTTP timeout in seconds (default: 10)",
          default: 10,
        },
      },
      required: ["targets"],
    },
  },
  {
    name: "httpx_tech_detect",
    description: `Detect web technologies using Wappalyzer fingerprints.

Identifies CMS, frameworks, programming languages, web servers, CDNs, analytics tools, and more.
Essential for understanding the technology stack of target applications.

Example use cases:
- Identify WordPress, Drupal, or other CMS installations
- Detect JavaScript frameworks (React, Vue, Angular)
- Find vulnerable technology versions`,
    inputSchema: {
      type: "object",
      properties: {
        targets: {
          type: "array",
          items: { type: "string" },
          description: "URLs or hosts to scan for technologies",
        },
        status_code: {
          type: "boolean",
          description: "Include status codes in output",
          default: true,
        },
        title: {
          type: "boolean",
          description: "Include page titles",
          default: true,
        },
        follow_redirects: {
          type: "boolean",
          description: "Follow redirects to final destination",
          default: true,
        },
        threads: {
          type: "number",
          description: "Number of threads",
          default: 25,
        },
      },
      required: ["targets"],
    },
  },
  {
    name: "httpx_status_filter",
    description: `Filter HTTP responses by status codes.

Useful for finding specific response types:
- 200: Successfully accessible pages
- 301/302: Redirects
- 401/403: Authentication required or forbidden
- 404: Not found
- 500: Server errors

Example use cases:
- Find all 200 OK responses from a list of URLs
- Identify redirects that might reveal internal paths
- Locate authentication-required endpoints`,
    inputSchema: {
      type: "object",
      properties: {
        targets: {
          type: "array",
          items: { type: "string" },
          description: "URLs or hosts to check",
        },
        match_codes: {
          type: "string",
          description: "Status codes to include (e.g., '200,301,302')",
        },
        filter_codes: {
          type: "string",
          description: "Status codes to exclude (e.g., '404,500')",
        },
        title: {
          type: "boolean",
          description: "Include page titles",
          default: true,
        },
        location: {
          type: "boolean",
          description: "Show redirect location header",
          default: true,
        },
        threads: {
          type: "number",
          description: "Number of threads",
          default: 50,
        },
      },
      required: ["targets"],
    },
  },
  {
    name: "httpx_title",
    description: `Extract page titles from web servers.

Useful for quickly understanding what each server hosts without manual inspection.
Can reveal application names, login pages, admin panels, and more.

Example use cases:
- Identify admin panels or dashboards
- Find login pages across multiple hosts
- Categorize servers by purpose based on titles`,
    inputSchema: {
      type: "object",
      properties: {
        targets: {
          type: "array",
          items: { type: "string" },
          description: "URLs or hosts to extract titles from",
        },
        status_code: {
          type: "boolean",
          description: "Include status codes",
          default: true,
        },
        match_string: {
          type: "string",
          description: "Only show results containing this string in title",
        },
        filter_string: {
          type: "string",
          description: "Exclude results containing this string in title",
        },
        threads: {
          type: "number",
          description: "Number of threads",
          default: 50,
        },
      },
      required: ["targets"],
    },
  },
  {
    name: "httpx_screenshot",
    description: `Capture screenshots of web pages.

Takes visual screenshots of target URLs for documentation and visual analysis.
Useful for quickly reviewing many sites or documenting findings.

Note: Screenshots are saved on the Kali system. Specify a directory to organize them.

Example use cases:
- Visual documentation of discovered web applications
- Quickly review many sites for interesting content
- Evidence collection for reports`,
    inputSchema: {
      type: "object",
      properties: {
        targets: {
          type: "array",
          items: { type: "string" },
          description: "URLs to screenshot",
        },
        output_dir: {
          type: "string",
          description: "Directory on Kali to save screenshots (default: ./screenshots)",
          default: "./screenshots",
        },
        status_code: {
          type: "boolean",
          description: "Include status codes in output",
          default: true,
        },
        title: {
          type: "boolean",
          description: "Include page titles",
          default: true,
        },
        threads: {
          type: "number",
          description: "Number of threads (lower recommended for screenshots)",
          default: 10,
        },
      },
      required: ["targets"],
    },
  },
  {
    name: "httpx_cdn_detect",
    description: `Detect if targets are behind a CDN (Content Delivery Network).

Identifies CDN providers like Cloudflare, Akamai, Fastly, AWS CloudFront, etc.
Important for understanding target infrastructure and potential WAF protection.

Example use cases:
- Identify CDN/WAF protected targets
- Find origin servers that might be directly accessible
- Understand target infrastructure`,
    inputSchema: {
      type: "object",
      properties: {
        targets: {
          type: "array",
          items: { type: "string" },
          description: "URLs or hosts to check for CDN",
        },
        ip: {
          type: "boolean",
          description: "Show IP addresses",
          default: true,
        },
        cname: {
          type: "boolean",
          description: "Show CNAME records",
          default: true,
        },
        status_code: {
          type: "boolean",
          description: "Include status codes",
          default: true,
        },
        threads: {
          type: "number",
          description: "Number of threads",
          default: 25,
        },
      },
      required: ["targets"],
    },
  },
  {
    name: "httpx_fingerprint",
    description: `Advanced fingerprinting including JARM TLS fingerprints and favicon hashes.

JARM fingerprints identify TLS configurations (useful for identifying C2 servers or specific products).
Favicon hashes can identify applications even without other identifying features.

Example use cases:
- Identify specific software by JARM signature
- Find related infrastructure using favicon hashes
- Detect potential malicious servers`,
    inputSchema: {
      type: "object",
      properties: {
        targets: {
          type: "array",
          items: { type: "string" },
          description: "URLs or hosts to fingerprint",
        },
        jarm: {
          type: "boolean",
          description: "Calculate JARM TLS fingerprint",
          default: true,
        },
        favicon: {
          type: "boolean",
          description: "Calculate favicon mmh3 hash",
          default: true,
        },
        status_code: {
          type: "boolean",
          description: "Include status codes",
          default: true,
        },
        title: {
          type: "boolean",
          description: "Include page titles",
          default: true,
        },
        threads: {
          type: "number",
          description: "Number of threads",
          default: 10,
        },
      },
      required: ["targets"],
    },
  },
  {
    name: "httpx_full_scan",
    description: `Comprehensive scan with all major probes enabled.

Runs a full reconnaissance scan including:
- Status codes
- Titles
- Technology detection
- Server info
- IP addresses
- CDN detection
- Response time

Best for thorough initial reconnaissance when you want all available data.`,
    inputSchema: {
      type: "object",
      properties: {
        targets: {
          type: "array",
          items: { type: "string" },
          description: "URLs or hosts for comprehensive scan",
        },
        json_output: {
          type: "boolean",
          description: "Output in JSON format for easier parsing",
          default: false,
        },
        threads: {
          type: "number",
          description: "Number of threads (lower for thorough scan)",
          default: 25,
        },
        timeout: {
          type: "number",
          description: "HTTP timeout in seconds",
          default: 15,
        },
      },
      required: ["targets"],
    },
  },
  {
    name: "httpx_custom",
    description: `Run httpx with custom flags for advanced use cases.

Allows passing arbitrary httpx flags for scenarios not covered by other tools.
Refer to httpx documentation for all available options.

Example custom_flags:
- "-hash sha256" - Calculate SHA256 hash of response body
- "-body-preview 500" - Show first 500 chars of body
- "-vhost" - Probe virtual hosts
- "-http2" - Force HTTP/2 probing`,
    inputSchema: {
      type: "object",
      properties: {
        targets: {
          type: "array",
          items: { type: "string" },
          description: "URLs or hosts to scan",
        },
        custom_flags: {
          type: "string",
          description: "Custom httpx flags to append to command",
        },
        headers: {
          type: "array",
          items: { type: "string" },
          description: "Custom HTTP headers (e.g., 'Authorization: Bearer token')",
        },
        threads: {
          type: "number",
          description: "Number of threads",
          default: 50,
        },
        timeout: {
          type: "number",
          description: "HTTP timeout in seconds",
          default: 10,
        },
      },
      required: ["targets"],
    },
  },
  {
    name: "httpx_path_probe",
    description: `Probe specific paths across multiple hosts.

Useful for checking if specific endpoints exist across many servers.
Can be used to find common files, admin panels, or API endpoints.

Example use cases:
- Check for /robots.txt across all discovered hosts
- Find /admin, /login, or /api endpoints
- Discover common backup files or config files`,
    inputSchema: {
      type: "object",
      properties: {
        targets: {
          type: "array",
          items: { type: "string" },
          description: "Base URLs or hosts",
        },
        paths: {
          type: "array",
          items: { type: "string" },
          description: "Paths to probe on each target (e.g., '/admin', '/api', '/.git/config')",
        },
        match_codes: {
          type: "string",
          description: "Only show these status codes (e.g., '200,301')",
        },
        filter_codes: {
          type: "string",
          description: "Exclude these status codes (e.g., '404')",
          default: "404",
        },
        title: {
          type: "boolean",
          description: "Include page titles",
          default: true,
        },
        threads: {
          type: "number",
          description: "Number of threads",
          default: 25,
        },
      },
      required: ["targets", "paths"],
    },
  },
];

// Create and configure server
const server = new Server(
  {
    name: "httpx-mcp",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Handle tool listing
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools,
}));

// Handle tool execution
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    let result: HttpxResult;

    switch (name) {
      case "httpx_probe": {
        const { targets, status_code, title, content_length, web_server, follow_redirects, ports, threads, timeout } = args as any;
        result = await executeHttpx({
          targets,
          statusCode: status_code ?? true,
          title: title ?? true,
          contentLength: content_length ?? false,
          webServer: web_server ?? false,
          followRedirects: follow_redirects ?? true,
          ports,
          threads: threads ?? 50,
          timeout: timeout ?? 10,
          silent: true,
          noColor: true,
        });
        break;
      }

      case "httpx_tech_detect": {
        const { targets, status_code, title, follow_redirects, threads } = args as any;
        result = await executeHttpx({
          targets,
          techDetect: true,
          statusCode: status_code ?? true,
          title: title ?? true,
          followRedirects: follow_redirects ?? true,
          threads: threads ?? 25,
          silent: true,
          noColor: true,
        });
        break;
      }

      case "httpx_status_filter": {
        const { targets, match_codes, filter_codes, title, location, threads } = args as any;
        result = await executeHttpx({
          targets,
          statusCode: true,
          title: title ?? true,
          location: location ?? true,
          matchCodes: match_codes,
          filterCodes: filter_codes,
          threads: threads ?? 50,
          silent: true,
          noColor: true,
        });
        break;
      }

      case "httpx_title": {
        const { targets, status_code, match_string, filter_string, threads } = args as any;
        result = await executeHttpx({
          targets,
          title: true,
          statusCode: status_code ?? true,
          matchString: match_string,
          filterString: filter_string,
          threads: threads ?? 50,
          silent: true,
          noColor: true,
        });
        break;
      }

      case "httpx_screenshot": {
        const { targets, output_dir, status_code, title, threads } = args as any;
        result = await executeHttpx({
          targets,
          screenshot: true,
          screenshotDir: output_dir ?? "./screenshots",
          statusCode: status_code ?? true,
          title: title ?? true,
          threads: threads ?? 10,
          silent: true,
          noColor: true,
        });
        break;
      }

      case "httpx_cdn_detect": {
        const { targets, ip, cname, status_code, threads } = args as any;
        result = await executeHttpx({
          targets,
          cdn: true,
          ip: ip ?? true,
          cname: cname ?? true,
          statusCode: status_code ?? true,
          threads: threads ?? 25,
          silent: true,
          noColor: true,
        });
        break;
      }

      case "httpx_fingerprint": {
        const { targets, jarm, favicon, status_code, title, threads } = args as any;
        result = await executeHttpx({
          targets,
          jarm: jarm ?? true,
          favicon: favicon ?? true,
          statusCode: status_code ?? true,
          title: title ?? true,
          threads: threads ?? 10,
          silent: true,
          noColor: true,
        });
        break;
      }

      case "httpx_full_scan": {
        const { targets, json_output, threads, timeout } = args as any;
        result = await executeHttpx({
          targets,
          statusCode: true,
          title: true,
          techDetect: true,
          webServer: true,
          ip: true,
          cdn: true,
          responseTime: true,
          method: true,
          jsonOutput: json_output ?? false,
          threads: threads ?? 25,
          timeout: timeout ?? 15,
          silent: true,
          noColor: true,
        });
        break;
      }

      case "httpx_custom": {
        const { targets, custom_flags, headers, threads, timeout } = args as any;
        result = await executeHttpx({
          targets,
          customFlags: custom_flags,
          headers,
          threads: threads ?? 50,
          timeout: timeout ?? 10,
          silent: true,
          noColor: true,
        });
        break;
      }

      case "httpx_path_probe": {
        const { targets, paths, match_codes, filter_codes, title, threads } = args as any;
        // Build targets with paths
        const fullTargets: string[] = [];
        for (const target of targets) {
          for (const path of paths) {
            const base = target.replace(/\/$/, "");
            const p = path.startsWith("/") ? path : `/${path}`;
            fullTargets.push(`${base}${p}`);
          }
        }
        result = await executeHttpx({
          targets: fullTargets,
          statusCode: true,
          title: title ?? true,
          matchCodes: match_codes,
          filterCodes: filter_codes ?? "404",
          threads: threads ?? 25,
          silent: true,
          noColor: true,
        });
        break;
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }

    // Format response
    const responseText = result.success
      ? `## httpx Results

**Command:** \`${result.command}\`
**Execution Time:** ${result.executionTime}ms
**Results Found:** ${result.resultCount}

### Output
\`\`\`
${result.output || "(no output)"}
\`\`\`
`
      : `## httpx Error

**Command:** \`${result.command}\`
**Execution Time:** ${result.executionTime}ms

### Error
\`\`\`
${result.error}
\`\`\`

### Partial Output
\`\`\`
${result.output || "(no output)"}
\`\`\`
`;

    return {
      content: [
        {
          type: "text",
          text: responseText,
        },
      ],
      isError: !result.success,
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

// Start server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("httpx MCP server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
