#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { execSync, spawn } from "child_process";

// Configuration
const KALI_HOST = process.env.KALI_HOST || "kali";
const SSH_TIMEOUT = parseInt(process.env.SSH_TIMEOUT || "300", 10);
const DEFAULT_RATE_LIMIT = parseInt(process.env.DEFAULT_RATE_LIMIT || "150", 10);

// Types
interface ScanOptions {
  target?: string;
  targets?: string[];
  templates?: string[];
  tags?: string[];
  excludeTags?: string[];
  severity?: string[];
  author?: string;
  workflows?: string[];
  outputFormat?: "json" | "jsonl" | "csv" | "markdown";
  rateLimit?: number;
  bulkSize?: number;
  concurrency?: number;
  timeout?: number;
  proxy?: string;
  headless?: boolean;
  interactshServer?: string;
  customHeaders?: Record<string, string>;
  followRedirects?: boolean;
  maxRedirects?: number;
  debug?: boolean;
}

interface TemplateListOptions {
  tags?: string[];
  severity?: string[];
  author?: string;
  type?: string;
  path?: string;
}

// Helper function to execute SSH commands to Kali
async function executeOnKali(command: string, timeout: number = SSH_TIMEOUT): Promise<string> {
  return new Promise((resolve, reject) => {
    const sshCommand = `ssh -o ConnectTimeout=10 -o StrictHostKeyChecking=no ${KALI_HOST} ${JSON.stringify(command)}`;

    let output = "";
    let errorOutput = "";

    const child = spawn("bash", ["-c", sshCommand], {
      timeout: timeout * 1000,
    });

    child.stdout.on("data", (data) => {
      output += data.toString();
    });

    child.stderr.on("data", (data) => {
      errorOutput += data.toString();
    });

    child.on("close", (code) => {
      if (code === 0) {
        resolve(output);
      } else {
        reject(new Error(`SSH command failed (code ${code}): ${errorOutput || output}`));
      }
    });

    child.on("error", (err) => {
      reject(err);
    });
  });
}

// Build nuclei command from options
function buildNucleiCommand(options: ScanOptions): string {
  const args: string[] = ["nuclei"];

  // Target(s)
  if (options.targets && options.targets.length > 0) {
    // Multiple targets - use stdin
    args.push("-l", "-");
  } else if (options.target) {
    args.push("-u", options.target);
  }

  // Templates
  if (options.templates && options.templates.length > 0) {
    options.templates.forEach((t) => args.push("-t", t));
  }

  // Tags
  if (options.tags && options.tags.length > 0) {
    args.push("-tags", options.tags.join(","));
  }

  // Exclude tags
  if (options.excludeTags && options.excludeTags.length > 0) {
    args.push("-etags", options.excludeTags.join(","));
  }

  // Severity
  if (options.severity && options.severity.length > 0) {
    args.push("-severity", options.severity.join(","));
  }

  // Author
  if (options.author) {
    args.push("-author", options.author);
  }

  // Workflows
  if (options.workflows && options.workflows.length > 0) {
    options.workflows.forEach((w) => args.push("-w", w));
  }

  // Output format
  if (options.outputFormat) {
    switch (options.outputFormat) {
      case "json":
        args.push("-json");
        break;
      case "jsonl":
        args.push("-jsonl");
        break;
      case "csv":
        args.push("-csv");
        break;
      case "markdown":
        args.push("-markdown");
        break;
    }
  } else {
    // Default to JSON for easier parsing
    args.push("-json");
  }

  // Rate limiting
  args.push("-rate-limit", String(options.rateLimit || DEFAULT_RATE_LIMIT));

  // Bulk size
  if (options.bulkSize) {
    args.push("-bulk-size", String(options.bulkSize));
  }

  // Concurrency
  if (options.concurrency) {
    args.push("-concurrency", String(options.concurrency));
  }

  // Timeout
  if (options.timeout) {
    args.push("-timeout", String(options.timeout));
  }

  // Proxy
  if (options.proxy) {
    args.push("-proxy", options.proxy);
  }

  // Headless mode
  if (options.headless) {
    args.push("-headless");
  }

  // Interactsh server
  if (options.interactshServer) {
    args.push("-interactsh-server", options.interactshServer);
  }

  // Custom headers
  if (options.customHeaders) {
    Object.entries(options.customHeaders).forEach(([key, value]) => {
      args.push("-H", `${key}: ${value}`);
    });
  }

  // Follow redirects
  if (options.followRedirects !== undefined) {
    if (options.followRedirects) {
      args.push("-follow-redirects");
      if (options.maxRedirects) {
        args.push("-max-redirects", String(options.maxRedirects));
      }
    } else {
      args.push("-no-redirect");
    }
  }

  // Debug mode
  if (options.debug) {
    args.push("-debug");
  }

  // Silent mode for cleaner output (disable banner)
  args.push("-silent");

  // No color for parsing
  args.push("-no-color");

  return args.join(" ");
}

// Define tools
const tools: Tool[] = [
  {
    name: "nuclei_scan",
    description: `Run a Nuclei vulnerability scan against one or more targets via SSH to Kali.

Supports filtering by templates, tags, severity, and more. Returns JSON results.

Examples:
- Basic scan: nuclei_scan(target: "https://example.com")
- High severity only: nuclei_scan(target: "https://example.com", severity: ["high", "critical"])
- Specific tags: nuclei_scan(target: "https://example.com", tags: ["cve", "rce"])
- Multiple targets: nuclei_scan(targets: ["https://a.com", "https://b.com"])`,
    inputSchema: {
      type: "object" as const,
      properties: {
        target: {
          type: "string",
          description: "Single target URL to scan",
        },
        targets: {
          type: "array",
          items: { type: "string" },
          description: "Multiple target URLs to scan",
        },
        templates: {
          type: "array",
          items: { type: "string" },
          description: "Specific template paths or IDs to use",
        },
        tags: {
          type: "array",
          items: { type: "string" },
          description: "Filter templates by tags (e.g., cve, rce, xss, sqli, kev)",
        },
        excludeTags: {
          type: "array",
          items: { type: "string" },
          description: "Exclude templates with these tags",
        },
        severity: {
          type: "array",
          items: { type: "string", enum: ["info", "low", "medium", "high", "critical"] },
          description: "Filter by severity levels",
        },
        author: {
          type: "string",
          description: "Filter templates by author",
        },
        rateLimit: {
          type: "number",
          description: `Maximum requests per second (default: ${DEFAULT_RATE_LIMIT})`,
        },
        concurrency: {
          type: "number",
          description: "Number of concurrent template executions",
        },
        timeout: {
          type: "number",
          description: "Timeout in seconds for each request",
        },
        proxy: {
          type: "string",
          description: "HTTP/SOCKS proxy URL",
        },
        headless: {
          type: "boolean",
          description: "Enable headless browser for complex interactions",
        },
        followRedirects: {
          type: "boolean",
          description: "Follow HTTP redirects",
        },
        maxRedirects: {
          type: "number",
          description: "Maximum redirects to follow",
        },
        customHeaders: {
          type: "object",
          additionalProperties: { type: "string" },
          description: "Custom HTTP headers to include",
        },
        debug: {
          type: "boolean",
          description: "Enable debug output",
        },
      },
      required: [],
    },
  },
  {
    name: "nuclei_templates",
    description: `List and search Nuclei templates available on Kali.

Filter by tags, severity, author, or template type (e.g., http, dns, ssl).`,
    inputSchema: {
      type: "object" as const,
      properties: {
        tags: {
          type: "array",
          items: { type: "string" },
          description: "Filter by tags",
        },
        severity: {
          type: "array",
          items: { type: "string", enum: ["info", "low", "medium", "high", "critical"] },
          description: "Filter by severity",
        },
        author: {
          type: "string",
          description: "Filter by author",
        },
        type: {
          type: "string",
          description: "Filter by protocol type (http, dns, ssl, tcp, etc.)",
        },
        path: {
          type: "string",
          description: "Search within specific template path",
        },
      },
    },
  },
  {
    name: "nuclei_update_templates",
    description: "Update Nuclei templates to the latest version from the community repository.",
    inputSchema: {
      type: "object" as const,
      properties: {},
    },
  },
  {
    name: "nuclei_tags",
    description: "List all available template tags with counts. Useful for discovering filtering options.",
    inputSchema: {
      type: "object" as const,
      properties: {},
    },
  },
  {
    name: "nuclei_severity_stats",
    description: "Get statistics about templates by severity level.",
    inputSchema: {
      type: "object" as const,
      properties: {},
    },
  },
  {
    name: "nuclei_workflows",
    description: `List available Nuclei workflows. Workflows are meta-templates that chain multiple scans.

Examples: wordpress-workflow, jira-workflow, magento-workflow`,
    inputSchema: {
      type: "object" as const,
      properties: {
        search: {
          type: "string",
          description: "Search term to filter workflows",
        },
      },
    },
  },
  {
    name: "nuclei_run_workflow",
    description: `Execute a Nuclei workflow against a target.

Workflows chain multiple templates for comprehensive scanning of specific technologies.`,
    inputSchema: {
      type: "object" as const,
      properties: {
        target: {
          type: "string",
          description: "Target URL to scan",
        },
        workflow: {
          type: "string",
          description: "Workflow name or path to execute",
        },
        rateLimit: {
          type: "number",
          description: `Maximum requests per second (default: ${DEFAULT_RATE_LIMIT})`,
        },
        proxy: {
          type: "string",
          description: "HTTP/SOCKS proxy URL",
        },
      },
      required: ["target", "workflow"],
    },
  },
  {
    name: "nuclei_version",
    description: "Get Nuclei version and configuration information from Kali.",
    inputSchema: {
      type: "object" as const,
      properties: {},
    },
  },
  {
    name: "nuclei_config",
    description: `View or get recommendations for Nuclei configuration.

Provides optimal settings for different scan scenarios.`,
    inputSchema: {
      type: "object" as const,
      properties: {
        scenario: {
          type: "string",
          enum: ["stealth", "fast", "comprehensive", "api", "web"],
          description: "Scanning scenario for recommendations",
        },
      },
    },
  },
  {
    name: "nuclei_kev_scan",
    description: `Scan target for Known Exploited Vulnerabilities (KEV).

Uses templates tagged with 'kev' or 'vkev' to detect actively exploited CVEs.`,
    inputSchema: {
      type: "object" as const,
      properties: {
        target: {
          type: "string",
          description: "Target URL to scan",
        },
        targets: {
          type: "array",
          items: { type: "string" },
          description: "Multiple target URLs",
        },
        rateLimit: {
          type: "number",
          description: `Maximum requests per second (default: ${DEFAULT_RATE_LIMIT})`,
        },
      },
      required: [],
    },
  },
];

// Create server
const server = new Server(
  {
    name: "nuclei-mcp",
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

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case "nuclei_scan": {
        const options = args as ScanOptions;

        if (!options.target && (!options.targets || options.targets.length === 0)) {
          throw new Error("Either 'target' or 'targets' must be provided");
        }

        let command = buildNucleiCommand(options);

        // For multiple targets, pipe them to nuclei
        if (options.targets && options.targets.length > 0) {
          const targetsStr = options.targets.join("\\n");
          command = `echo -e "${targetsStr}" | ${command}`;
        }

        const result = await executeOnKali(command, options.timeout ? options.timeout + 60 : SSH_TIMEOUT);

        // Parse JSON output
        const lines = result.trim().split("\n").filter((l) => l.trim());
        const findings = lines.map((line) => {
          try {
            return JSON.parse(line);
          } catch {
            return { raw: line };
          }
        });

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                success: true,
                findingsCount: findings.length,
                findings,
              }, null, 2),
            },
          ],
        };
      }

      case "nuclei_templates": {
        const options = args as TemplateListOptions;
        let command = "nuclei -tl";

        if (options.tags && options.tags.length > 0) {
          command += ` -tags ${options.tags.join(",")}`;
        }
        if (options.severity && options.severity.length > 0) {
          command += ` -severity ${options.severity.join(",")}`;
        }
        if (options.author) {
          command += ` -author ${options.author}`;
        }
        if (options.type) {
          command += ` -type ${options.type}`;
        }
        if (options.path) {
          command += ` -t ${options.path}`;
        }

        command += " -silent -no-color";

        const result = await executeOnKali(command);
        const templates = result.trim().split("\n").filter((l) => l.trim());

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                success: true,
                count: templates.length,
                templates: templates.slice(0, 100), // Limit output
                truncated: templates.length > 100,
              }, null, 2),
            },
          ],
        };
      }

      case "nuclei_update_templates": {
        const result = await executeOnKali("nuclei -update-templates -silent -no-color", 120);

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                success: true,
                output: result.trim(),
              }, null, 2),
            },
          ],
        };
      }

      case "nuclei_tags": {
        // Get template stats which includes tag information
        const result = await executeOnKali("nuclei -tl -silent -no-color | xargs -I {} grep -h 'tags:' {} 2>/dev/null | sort | uniq -c | sort -rn | head -50", 60);

        // Alternative: use nuclei's built-in stats
        const stats = await executeOnKali("nuclei -stats -silent -no-color 2>&1 || echo 'Stats command not available'", 30);

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                success: true,
                info: "Common nuclei tags include: cve, rce, xss, sqli, lfi, ssrf, kev, vkev, default-login, exposure, misconfig, tech, panel, wordpress, jira, jenkins, etc.",
                popularTags: [
                  "cve - CVE vulnerabilities",
                  "kev - Known Exploited Vulnerabilities (CISA)",
                  "vkev - Verified KEV",
                  "rce - Remote Code Execution",
                  "xss - Cross-Site Scripting",
                  "sqli - SQL Injection",
                  "lfi - Local File Inclusion",
                  "ssrf - Server-Side Request Forgery",
                  "default-login - Default credentials",
                  "exposure - Information exposure",
                  "misconfig - Misconfigurations",
                  "panel - Admin panels",
                  "tech - Technology detection",
                ],
                stats: stats.trim(),
              }, null, 2),
            },
          ],
        };
      }

      case "nuclei_severity_stats": {
        const severities = ["info", "low", "medium", "high", "critical"];
        const stats: Record<string, number> = {};

        for (const sev of severities) {
          const result = await executeOnKali(`nuclei -tl -severity ${sev} -silent -no-color 2>/dev/null | wc -l`, 30);
          stats[sev] = parseInt(result.trim(), 10) || 0;
        }

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                success: true,
                severityStats: stats,
                total: Object.values(stats).reduce((a, b) => a + b, 0),
              }, null, 2),
            },
          ],
        };
      }

      case "nuclei_workflows": {
        const searchArg = args as { search?: string };
        let command = "find ~/nuclei-templates/workflows -name '*.yaml' 2>/dev/null || find /root/nuclei-templates/workflows -name '*.yaml' 2>/dev/null || echo 'Workflows directory not found'";

        if (searchArg.search) {
          command = `find ~/nuclei-templates/workflows -name '*${searchArg.search}*.yaml' 2>/dev/null || find /root/nuclei-templates/workflows -name '*${searchArg.search}*.yaml' 2>/dev/null`;
        }

        const result = await executeOnKali(command, 30);
        const workflows = result.trim().split("\n").filter((l) => l.trim() && !l.includes("not found"));

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                success: true,
                count: workflows.length,
                workflows: workflows.map((w) => ({
                  path: w,
                  name: w.split("/").pop()?.replace(".yaml", ""),
                })),
              }, null, 2),
            },
          ],
        };
      }

      case "nuclei_run_workflow": {
        const { target, workflow, rateLimit, proxy } = args as {
          target: string;
          workflow: string;
          rateLimit?: number;
          proxy?: string;
        };

        let command = `nuclei -u ${target} -w ${workflow} -json -silent -no-color -rate-limit ${rateLimit || DEFAULT_RATE_LIMIT}`;

        if (proxy) {
          command += ` -proxy ${proxy}`;
        }

        const result = await executeOnKali(command, SSH_TIMEOUT);

        const lines = result.trim().split("\n").filter((l) => l.trim());
        const findings = lines.map((line) => {
          try {
            return JSON.parse(line);
          } catch {
            return { raw: line };
          }
        });

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                success: true,
                workflow,
                target,
                findingsCount: findings.length,
                findings,
              }, null, 2),
            },
          ],
        };
      }

      case "nuclei_version": {
        const version = await executeOnKali("nuclei -version 2>&1", 10);
        const config = await executeOnKali("cat ~/.config/nuclei/config.yaml 2>/dev/null || echo 'No config file found'", 10);

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                success: true,
                version: version.trim(),
                configFile: config.trim(),
                kaliHost: KALI_HOST,
              }, null, 2),
            },
          ],
        };
      }

      case "nuclei_config": {
        const { scenario } = args as { scenario?: string };

        const recommendations: Record<string, object> = {
          stealth: {
            description: "Low and slow scanning to avoid detection",
            settings: {
              rateLimit: 10,
              concurrency: 5,
              timeout: 30,
              followRedirects: true,
              maxRedirects: 5,
            },
            command: "nuclei -u TARGET -rate-limit 10 -c 5 -timeout 30",
          },
          fast: {
            description: "Quick scan with high rate limits",
            settings: {
              rateLimit: 500,
              concurrency: 100,
              bulkSize: 50,
              timeout: 10,
            },
            command: "nuclei -u TARGET -rate-limit 500 -c 100 -bulk-size 50 -timeout 10",
          },
          comprehensive: {
            description: "Full scan with all templates",
            settings: {
              rateLimit: 150,
              concurrency: 25,
              timeout: 20,
              headless: true,
              followRedirects: true,
            },
            command: "nuclei -u TARGET -rate-limit 150 -c 25 -timeout 20 -headless -follow-redirects",
          },
          api: {
            description: "API endpoint scanning",
            settings: {
              rateLimit: 100,
              tags: ["api", "graphql", "swagger"],
              timeout: 15,
            },
            command: "nuclei -u TARGET -rate-limit 100 -tags api,graphql,swagger -timeout 15",
          },
          web: {
            description: "Web application scanning",
            settings: {
              rateLimit: 150,
              tags: ["xss", "sqli", "rce", "lfi", "ssrf", "redirect"],
              severity: ["medium", "high", "critical"],
              followRedirects: true,
            },
            command: "nuclei -u TARGET -rate-limit 150 -tags xss,sqli,rce,lfi,ssrf -severity medium,high,critical",
          },
        };

        if (scenario && recommendations[scenario]) {
          return {
            content: [
              {
                type: "text",
                text: JSON.stringify({
                  success: true,
                  scenario,
                  ...recommendations[scenario],
                }, null, 2),
              },
            ],
          };
        }

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                success: true,
                availableScenarios: Object.keys(recommendations),
                recommendations,
              }, null, 2),
            },
          ],
        };
      }

      case "nuclei_kev_scan": {
        const { target, targets, rateLimit } = args as {
          target?: string;
          targets?: string[];
          rateLimit?: number;
        };

        if (!target && (!targets || targets.length === 0)) {
          throw new Error("Either 'target' or 'targets' must be provided");
        }

        let command = `nuclei -tags kev,vkev -json -silent -no-color -rate-limit ${rateLimit || DEFAULT_RATE_LIMIT}`;

        if (targets && targets.length > 0) {
          const targetsStr = targets.join("\\n");
          command = `echo -e "${targetsStr}" | ${command} -l -`;
        } else if (target) {
          command += ` -u ${target}`;
        }

        const result = await executeOnKali(command, SSH_TIMEOUT);

        const lines = result.trim().split("\n").filter((l) => l.trim());
        const findings = lines.map((line) => {
          try {
            return JSON.parse(line);
          } catch {
            return { raw: line };
          }
        });

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                success: true,
                scanType: "Known Exploited Vulnerabilities (KEV)",
                description: "Scanned for vulnerabilities actively exploited in the wild (CISA KEV catalog)",
                findingsCount: findings.length,
                findings,
              }, null, 2),
            },
          ],
        };
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            success: false,
            error: errorMessage,
          }, null, 2),
        },
      ],
      isError: true,
    };
  }
});

// Main
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Nuclei MCP Server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
