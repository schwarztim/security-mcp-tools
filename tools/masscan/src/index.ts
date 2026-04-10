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
const KALI_HOST = process.env.KALI_HOST || "kali";
const SSH_OPTIONS = "-o StrictHostKeyChecking=no -o ConnectTimeout=10";

interface ScanOptions {
  targets: string;
  ports?: string;
  rate?: number;
  banners?: boolean;
  excludeTargets?: string;
  excludeFile?: string;
  outputFormat?: "json" | "list" | "xml" | "grepable" | "binary";
  outputFile?: string;
  adapter?: string;
  adapterIp?: string;
  adapterMac?: string;
  routerMac?: string;
  sourcePort?: number;
  ttl?: number;
  wait?: number;
  retries?: number;
  seed?: number;
  shard?: string;
  ping?: boolean;
  openOnly?: boolean;
  packetTrace?: boolean;
  httpUserAgent?: string;
  connectionTimeout?: number;
}

interface ResumeOptions {
  configFile: string;
}

// Tool definitions
const tools: Tool[] = [
  {
    name: "masscan_scan",
    description: `Start a masscan port scan against specified targets.

Masscan is the world's fastest port scanner - capable of scanning the entire Internet in under 6 minutes at 10 million packets per second.

Examples:
- Basic scan: targets="192.168.1.0/24", ports="80,443"
- Full port scan: targets="10.0.0.1", ports="0-65535", rate=10000
- Banner grabbing: targets="192.168.1.1", ports="22,80,443", banners=true
- IPv6 scan: targets="2001:db8::/32", ports="80"
- Multiple ranges: targets="10.0.0.0/8 192.168.0.0/16", ports="22,80,443,8080"`,
    inputSchema: {
      type: "object",
      properties: {
        targets: {
          type: "string",
          description: "Target IP addresses/ranges (CIDR, ranges like 10.0.0.1-10.0.0.100, or space-separated)",
        },
        ports: {
          type: "string",
          description: "Ports to scan (e.g., '80', '22,80,443', '1-1000', '0-65535', 'U:53' for UDP, 'U:53,T:80' for mixed)",
        },
        rate: {
          type: "number",
          description: "Packets per second (default: 100, max: 25000000). Higher rates require root and proper network config.",
        },
        banners: {
          type: "boolean",
          description: "Enable banner grabbing (performs full TCP handshake, slower but more info)",
        },
        excludeTargets: {
          type: "string",
          description: "Comma-separated IPs/ranges to exclude from scan",
        },
        excludeFile: {
          type: "string",
          description: "Path to file containing excluded IPs (one per line)",
        },
        outputFormat: {
          type: "string",
          enum: ["json", "list", "xml", "grepable", "binary"],
          description: "Output format (default: json)",
        },
        outputFile: {
          type: "string",
          description: "Save results to file on Kali (optional)",
        },
        openOnly: {
          type: "boolean",
          description: "Only report open ports (default: true)",
        },
        ping: {
          type: "boolean",
          description: "Include ICMP ping in scan",
        },
        packetTrace: {
          type: "boolean",
          description: "Print packets to terminal for debugging",
        },
        httpUserAgent: {
          type: "string",
          description: "Custom User-Agent for HTTP banner grabbing",
        },
        connectionTimeout: {
          type: "number",
          description: "TCP connection timeout in seconds for banner grabbing (default: 30)",
        },
        wait: {
          type: "number",
          description: "Seconds to wait after scan completes for late responses (default: 10)",
        },
        retries: {
          type: "number",
          description: "Number of retries per port (default: 0)",
        },
        seed: {
          type: "number",
          description: "Random seed for reproducible scans",
        },
        shard: {
          type: "string",
          description: "Distributed scanning shard (e.g., '1/3' for first of 3 shards)",
        },
        ttl: {
          type: "number",
          description: "IP TTL value for packets",
        },
        sourcePort: {
          type: "number",
          description: "Source port for packets",
        },
        adapter: {
          type: "string",
          description: "Network adapter to use (e.g., eth0)",
        },
        adapterIp: {
          type: "string",
          description: "Source IP address for packets",
        },
        adapterMac: {
          type: "string",
          description: "Source MAC address (format: 00-11-22-33-44-55)",
        },
        routerMac: {
          type: "string",
          description: "Gateway MAC address (format: 00-11-22-33-44-55)",
        },
      },
      required: ["targets"],
    },
  },
  {
    name: "masscan_quick_scan",
    description: `Quick scan with sensible defaults for common scenarios.

Preset modes:
- "web": Scans ports 80,443,8080,8443
- "common": Top 100 most common ports
- "full": All 65535 ports (slower)
- "ssh": SSH ports 22,2222
- "database": Database ports 3306,5432,1433,27017,6379,5984`,
    inputSchema: {
      type: "object",
      properties: {
        targets: {
          type: "string",
          description: "Target IP addresses/ranges",
        },
        preset: {
          type: "string",
          enum: ["web", "common", "full", "ssh", "database"],
          description: "Scan preset to use",
        },
        rate: {
          type: "number",
          description: "Packets per second (default: 1000)",
        },
        banners: {
          type: "boolean",
          description: "Enable banner grabbing",
        },
      },
      required: ["targets", "preset"],
    },
  },
  {
    name: "masscan_resume",
    description: `Resume a previously interrupted scan from a paused.conf file.

When masscan is interrupted with Ctrl+C, it saves state to paused.conf. This tool resumes from that state.`,
    inputSchema: {
      type: "object",
      properties: {
        configFile: {
          type: "string",
          description: "Path to the paused.conf or other config file to resume from",
        },
      },
      required: ["configFile"],
    },
  },
  {
    name: "masscan_echo_config",
    description: `Generate a masscan configuration file from current parameters.

Useful for saving scan configurations for later use or distributed scanning.`,
    inputSchema: {
      type: "object",
      properties: {
        targets: {
          type: "string",
          description: "Target IP addresses/ranges",
        },
        ports: {
          type: "string",
          description: "Ports to scan",
        },
        rate: {
          type: "number",
          description: "Packets per second",
        },
        banners: {
          type: "boolean",
          description: "Enable banner grabbing",
        },
        excludeTargets: {
          type: "string",
          description: "IPs to exclude",
        },
      },
      required: ["targets"],
    },
  },
  {
    name: "masscan_version",
    description: "Get masscan version and verify it's installed on Kali",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "masscan_help",
    description: "Show masscan help and available options",
    inputSchema: {
      type: "object",
      properties: {
        topic: {
          type: "string",
          enum: ["general", "nmap-compat", "output", "advanced"],
          description: "Help topic to display",
        },
      },
    },
  },
];

// Port presets for quick scan
const PORT_PRESETS: Record<string, string> = {
  web: "80,443,8080,8443,8000,8888,3000,5000",
  common: "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5432,5900,8080",
  full: "0-65535",
  ssh: "22,2222,22222",
  database: "3306,5432,1433,1521,27017,6379,5984,9200,9300,11211,28015",
};

// Build masscan command
function buildMasscanCommand(options: ScanOptions): string {
  const args: string[] = ["sudo", "masscan"];

  // Targets (required)
  args.push(options.targets);

  // Ports
  if (options.ports) {
    args.push(`-p${options.ports}`);
  } else {
    args.push("-p80,443"); // Default ports
  }

  // Rate
  if (options.rate) {
    args.push(`--rate=${options.rate}`);
  }

  // Banner grabbing
  if (options.banners) {
    args.push("--banners");
  }

  // Exclusions
  if (options.excludeTargets) {
    args.push(`--exclude=${options.excludeTargets}`);
  }
  if (options.excludeFile) {
    args.push(`--excludefile=${options.excludeFile}`);
  }

  // Output format
  const format = options.outputFormat || "json";
  switch (format) {
    case "json":
      args.push("-oJ", "-");
      break;
    case "list":
      args.push("-oL", "-");
      break;
    case "xml":
      args.push("-oX", "-");
      break;
    case "grepable":
      args.push("-oG", "-");
      break;
    case "binary":
      if (options.outputFile) {
        args.push(`-oB`, options.outputFile);
      }
      break;
  }

  // Output to file if specified (in addition to stdout for non-binary)
  if (options.outputFile && format !== "binary") {
    args.push(`--output-filename=${options.outputFile}`);
  }

  // Open only
  if (options.openOnly !== false) {
    args.push("--open-only");
  }

  // Ping
  if (options.ping) {
    args.push("--ping");
  }

  // Packet trace
  if (options.packetTrace) {
    args.push("--packet-trace");
  }

  // HTTP User-Agent
  if (options.httpUserAgent) {
    args.push(`--http-user-agent="${options.httpUserAgent}"`);
  }

  // Connection timeout
  if (options.connectionTimeout) {
    args.push(`--connection-timeout=${options.connectionTimeout}`);
  }

  // Wait time
  if (options.wait !== undefined) {
    args.push(`--wait=${options.wait}`);
  }

  // Retries
  if (options.retries !== undefined) {
    args.push(`--retries=${options.retries}`);
  }

  // Seed
  if (options.seed !== undefined) {
    args.push(`--seed=${options.seed}`);
  }

  // Shard
  if (options.shard) {
    args.push(`--shard=${options.shard}`);
  }

  // TTL
  if (options.ttl) {
    args.push(`--ttl=${options.ttl}`);
  }

  // Source port
  if (options.sourcePort) {
    args.push(`--source-port=${options.sourcePort}`);
  }

  // Adapter options
  if (options.adapter) {
    args.push(`--adapter=${options.adapter}`);
  }
  if (options.adapterIp) {
    args.push(`--adapter-ip=${options.adapterIp}`);
  }
  if (options.adapterMac) {
    args.push(`--adapter-mac=${options.adapterMac}`);
  }
  if (options.routerMac) {
    args.push(`--router-mac=${options.routerMac}`);
  }

  return args.join(" ");
}

// Execute command on Kali via SSH
async function executeOnKali(command: string): Promise<{ stdout: string; stderr: string }> {
  const sshCommand = `ssh ${SSH_OPTIONS} ${KALI_HOST} "${command.replace(/"/g, '\\"')}"`;

  try {
    const { stdout, stderr } = await execAsync(sshCommand, {
      maxBuffer: 50 * 1024 * 1024, // 50MB buffer for large scan results
      timeout: 600000, // 10 minute timeout
    });
    return { stdout, stderr };
  } catch (error: any) {
    if (error.stdout || error.stderr) {
      return { stdout: error.stdout || "", stderr: error.stderr || error.message };
    }
    throw error;
  }
}

// Parse masscan JSON output
function parseMasscanOutput(output: string): any[] {
  try {
    // Masscan outputs JSON with trailing comma issues, need to fix
    let cleaned = output.trim();

    // Handle array format
    if (cleaned.startsWith("[")) {
      // Remove trailing commas before ]
      cleaned = cleaned.replace(/,\s*]/g, "]");
      // Remove any trailing comma at the end before closing bracket
      cleaned = cleaned.replace(/,(\s*\])$/g, "$1");
      return JSON.parse(cleaned);
    }

    // Handle line-by-line JSON objects
    const results: any[] = [];
    const lines = cleaned.split("\n");
    for (const line of lines) {
      const trimmed = line.trim().replace(/,$/, "");
      if (trimmed && trimmed !== "[" && trimmed !== "]" && trimmed.startsWith("{")) {
        try {
          results.push(JSON.parse(trimmed));
        } catch {
          // Skip malformed lines
        }
      }
    }
    return results;
  } catch {
    return [];
  }
}

// Create server
const server = new Server(
  {
    name: "masscan-mcp",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// List tools handler
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools,
}));

// Call tool handler
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case "masscan_scan": {
        const options: ScanOptions = {
          targets: args?.targets as string,
          ports: args?.ports as string | undefined,
          rate: args?.rate as number | undefined,
          banners: args?.banners as boolean | undefined,
          excludeTargets: args?.excludeTargets as string | undefined,
          excludeFile: args?.excludeFile as string | undefined,
          outputFormat: args?.outputFormat as ScanOptions["outputFormat"],
          outputFile: args?.outputFile as string | undefined,
          openOnly: args?.openOnly as boolean | undefined,
          ping: args?.ping as boolean | undefined,
          packetTrace: args?.packetTrace as boolean | undefined,
          httpUserAgent: args?.httpUserAgent as string | undefined,
          connectionTimeout: args?.connectionTimeout as number | undefined,
          wait: args?.wait as number | undefined,
          retries: args?.retries as number | undefined,
          seed: args?.seed as number | undefined,
          shard: args?.shard as string | undefined,
          ttl: args?.ttl as number | undefined,
          sourcePort: args?.sourcePort as number | undefined,
          adapter: args?.adapter as string | undefined,
          adapterIp: args?.adapterIp as string | undefined,
          adapterMac: args?.adapterMac as string | undefined,
          routerMac: args?.routerMac as string | undefined,
        };

        const command = buildMasscanCommand(options);
        const { stdout, stderr } = await executeOnKali(command);

        // Parse results if JSON format
        let results: any[] = [];
        let summary = "";

        if (options.outputFormat === "json" || !options.outputFormat) {
          results = parseMasscanOutput(stdout);
          const openPorts = results.filter(r => r.ports).length;
          summary = `Found ${openPorts} open ports across scanned targets`;
        }

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                success: true,
                command: command,
                summary: summary || "Scan completed",
                results: results.length > 0 ? results : stdout,
                stderr: stderr || undefined,
              }, null, 2),
            },
          ],
        };
      }

      case "masscan_quick_scan": {
        const preset = args?.preset as string;
        const ports = PORT_PRESETS[preset] || PORT_PRESETS.common;

        const options: ScanOptions = {
          targets: args?.targets as string,
          ports: ports,
          rate: (args?.rate as number) || 1000,
          banners: args?.banners as boolean | undefined,
          outputFormat: "json",
        };

        const command = buildMasscanCommand(options);
        const { stdout, stderr } = await executeOnKali(command);
        const results = parseMasscanOutput(stdout);

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                success: true,
                preset: preset,
                ports: ports,
                command: command,
                results: results.length > 0 ? results : stdout,
                stderr: stderr || undefined,
              }, null, 2),
            },
          ],
        };
      }

      case "masscan_resume": {
        const configFile = args?.configFile as string;
        const command = `sudo masscan --resume ${configFile} -oJ -`;
        const { stdout, stderr } = await executeOnKali(command);
        const results = parseMasscanOutput(stdout);

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                success: true,
                command: command,
                results: results.length > 0 ? results : stdout,
                stderr: stderr || undefined,
              }, null, 2),
            },
          ],
        };
      }

      case "masscan_echo_config": {
        const options: ScanOptions = {
          targets: args?.targets as string,
          ports: args?.ports as string | undefined,
          rate: args?.rate as number | undefined,
          banners: args?.banners as boolean | undefined,
          excludeTargets: args?.excludeTargets as string | undefined,
        };

        const command = buildMasscanCommand(options);
        const echoCommand = `${command.replace("-oJ -", "")} --echo`;
        const { stdout, stderr } = await executeOnKali(echoCommand);

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                success: true,
                command: echoCommand,
                config: stdout,
                stderr: stderr || undefined,
              }, null, 2),
            },
          ],
        };
      }

      case "masscan_version": {
        const { stdout, stderr } = await executeOnKali("masscan --version");

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                success: true,
                version: stdout.trim(),
                stderr: stderr || undefined,
              }, null, 2),
            },
          ],
        };
      }

      case "masscan_help": {
        const topic = args?.topic as string || "general";
        let command = "masscan --help";

        switch (topic) {
          case "nmap-compat":
            command = "masscan --nmap";
            break;
          case "output":
            command = "masscan --help | grep -A 50 'OUTPUT'";
            break;
          case "advanced":
            command = "masscan --help | grep -A 100 'ADAPTER'";
            break;
        }

        const { stdout, stderr } = await executeOnKali(command);

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({
                success: true,
                topic: topic,
                help: stdout,
                stderr: stderr || undefined,
              }, null, 2),
            },
          ],
        };
      }

      default:
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({ error: `Unknown tool: ${name}` }),
            },
          ],
          isError: true,
        };
    }
  } catch (error: any) {
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            error: error.message,
            details: error.stderr || error.stdout || undefined,
          }),
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
  console.error("Masscan MCP server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
