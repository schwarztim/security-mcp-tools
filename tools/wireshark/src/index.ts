#!/usr/bin/env node
/**
 * Wireshark MCP Server
 *
 * Provides network packet analysis capabilities via tshark on a remote Kali machine.
 * Uses SSH to execute tshark commands for packet capture and analysis.
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
const SSH_HOST = process.env.WIRESHARK_SSH_HOST || "kali";
const SSH_USER = process.env.WIRESHARK_SSH_USER || "";
const REMOTE_PCAP_DIR = process.env.WIRESHARK_PCAP_DIR || "/tmp/mcp-pcaps";
const DEFAULT_TIMEOUT = 30000;

interface CommandResult {
  stdout: string;
  stderr: string;
  exitCode: number;
}

/**
 * Execute a command on the remote Kali machine via SSH
 */
async function executeSSH(
  command: string,
  timeout: number = DEFAULT_TIMEOUT
): Promise<CommandResult> {
  return new Promise((resolve, reject) => {
    const sshTarget = SSH_USER ? `${SSH_USER}@${SSH_HOST}` : SSH_HOST;
    const sshArgs = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10", sshTarget, command];

    const proc = spawn("ssh", sshArgs);
    let stdout = "";
    let stderr = "";

    const timer = setTimeout(() => {
      proc.kill("SIGTERM");
      reject(new Error(`Command timed out after ${timeout}ms`));
    }, timeout);

    proc.stdout.on("data", (data) => {
      stdout += data.toString();
    });

    proc.stderr.on("data", (data) => {
      stderr += data.toString();
    });

    proc.on("close", (code) => {
      clearTimeout(timer);
      resolve({
        stdout: stdout.trim(),
        stderr: stderr.trim(),
        exitCode: code ?? 1,
      });
    });

    proc.on("error", (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

/**
 * Validate and sanitize input to prevent command injection
 */
function sanitizeInput(input: string): string {
  // Remove potentially dangerous characters
  return input.replace(/[;&|`$(){}[\]<>\\'"]/g, "");
}

/**
 * Validate interface name
 */
function validateInterface(iface: string): boolean {
  return /^[a-zA-Z0-9_-]+$/.test(iface);
}

/**
 * Validate filter expression (basic validation)
 */
function validateFilter(filter: string): boolean {
  // Allow common filter characters
  return /^[a-zA-Z0-9_\-.\s=!<>()&|,:"\/\[\]]+$/.test(filter);
}

// Tool definitions
const tools: Tool[] = [
  {
    name: "tshark_list_interfaces",
    description: "List available network interfaces on the remote Kali machine for packet capture",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
  {
    name: "tshark_capture",
    description:
      "Start packet capture on the remote Kali machine. Returns captured packets in JSON format. Requires sudo on the remote host.",
    inputSchema: {
      type: "object" as const,
      properties: {
        interface: {
          type: "string",
          description: "Network interface to capture on (e.g., eth0, wlan0)",
        },
        count: {
          type: "number",
          description: "Number of packets to capture (default: 10, max: 1000)",
        },
        filter: {
          type: "string",
          description: "Capture filter (BPF syntax, e.g., 'port 80', 'host 192.168.1.1')",
        },
        timeout: {
          type: "number",
          description: "Capture timeout in seconds (default: 10, max: 60)",
        },
        outputFile: {
          type: "string",
          description: "Optional: Save capture to pcap file on remote host",
        },
      },
      required: ["interface"],
    },
  },
  {
    name: "tshark_read_pcap",
    description: "Read and analyze a pcap file from the remote Kali machine. Returns packets in JSON format.",
    inputSchema: {
      type: "object" as const,
      properties: {
        file: {
          type: "string",
          description: "Path to the pcap file on the remote host",
        },
        filter: {
          type: "string",
          description: "Display filter to apply (Wireshark syntax, e.g., 'http', 'tcp.port == 443')",
        },
        count: {
          type: "number",
          description: "Maximum number of packets to return (default: 100, max: 1000)",
        },
        fields: {
          type: "array",
          items: { type: "string" },
          description: "Specific fields to extract (e.g., ['ip.src', 'ip.dst', 'tcp.port'])",
        },
      },
      required: ["file"],
    },
  },
  {
    name: "tshark_filter",
    description:
      "Apply a display filter to a pcap file and return matching packets. Useful for extracting specific traffic.",
    inputSchema: {
      type: "object" as const,
      properties: {
        file: {
          type: "string",
          description: "Path to the pcap file on the remote host",
        },
        filter: {
          type: "string",
          description: "Display filter (e.g., 'http.request', 'dns', 'tcp.flags.syn == 1')",
        },
        outputFormat: {
          type: "string",
          enum: ["json", "text", "fields"],
          description: "Output format (default: json)",
        },
        fields: {
          type: "array",
          items: { type: "string" },
          description: "Fields to extract when outputFormat is 'fields'",
        },
      },
      required: ["file", "filter"],
    },
  },
  {
    name: "tshark_stats",
    description:
      "Get protocol statistics from a pcap file. Shows protocol hierarchy, conversations, and endpoints.",
    inputSchema: {
      type: "object" as const,
      properties: {
        file: {
          type: "string",
          description: "Path to the pcap file on the remote host",
        },
        type: {
          type: "string",
          enum: ["hierarchy", "conversations", "endpoints", "io", "http", "dns"],
          description: "Type of statistics to generate",
        },
        protocol: {
          type: "string",
          description: "Protocol for conversations/endpoints (e.g., 'tcp', 'udp', 'ip')",
        },
      },
      required: ["file", "type"],
    },
  },
  {
    name: "tshark_follow_stream",
    description:
      "Follow and reconstruct a TCP, UDP, or HTTP stream from a pcap file. Shows the full conversation.",
    inputSchema: {
      type: "object" as const,
      properties: {
        file: {
          type: "string",
          description: "Path to the pcap file on the remote host",
        },
        protocol: {
          type: "string",
          enum: ["tcp", "udp", "http", "tls"],
          description: "Protocol stream to follow",
        },
        streamIndex: {
          type: "number",
          description: "Stream index number (default: 0 for first stream)",
        },
        format: {
          type: "string",
          enum: ["ascii", "hex", "raw"],
          description: "Output format (default: ascii)",
        },
      },
      required: ["file", "protocol"],
    },
  },
  {
    name: "tshark_extract_files",
    description:
      "Extract files from HTTP, DICOM, IMF, SMB, or TFTP traffic in a pcap file.",
    inputSchema: {
      type: "object" as const,
      properties: {
        file: {
          type: "string",
          description: "Path to the pcap file on the remote host",
        },
        protocol: {
          type: "string",
          enum: ["http", "dicom", "imf", "smb", "tftp"],
          description: "Protocol to extract files from (default: http)",
        },
        outputDir: {
          type: "string",
          description: "Directory to save extracted files (default: /tmp/mcp-extracted)",
        },
      },
      required: ["file"],
    },
  },
  {
    name: "tshark_decode",
    description:
      "Decode specific packets with detailed protocol information. Useful for deep packet inspection.",
    inputSchema: {
      type: "object" as const,
      properties: {
        file: {
          type: "string",
          description: "Path to the pcap file on the remote host",
        },
        packetNumber: {
          type: "number",
          description: "Specific packet number to decode (optional)",
        },
        filter: {
          type: "string",
          description: "Display filter to select packets (optional)",
        },
        protocols: {
          type: "array",
          items: { type: "string" },
          description: "Specific protocols to show details for (e.g., ['http', 'tcp', 'ip'])",
        },
        verbose: {
          type: "boolean",
          description: "Show all protocol details (default: false)",
        },
      },
      required: ["file"],
    },
  },
  {
    name: "tshark_extract_credentials",
    description:
      "Search for potential credentials in network traffic (HTTP Basic Auth, FTP, Telnet, etc.)",
    inputSchema: {
      type: "object" as const,
      properties: {
        file: {
          type: "string",
          description: "Path to the pcap file on the remote host",
        },
      },
      required: ["file"],
    },
  },
  {
    name: "tshark_export_objects",
    description: "List and export HTTP objects (files) from a pcap capture",
    inputSchema: {
      type: "object" as const,
      properties: {
        file: {
          type: "string",
          description: "Path to the pcap file on the remote host",
        },
        listOnly: {
          type: "boolean",
          description: "Only list objects without extracting (default: true)",
        },
        outputDir: {
          type: "string",
          description: "Directory to save extracted objects",
        },
      },
      required: ["file"],
    },
  },
];

// Create the MCP server
const server = new Server(
  {
    name: "wireshark-mcp",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// List tools handler
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return { tools };
});

// Call tool handler
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case "tshark_list_interfaces": {
        const result = await executeSSH("tshark -D 2>/dev/null || sudo tshark -D");
        if (result.exitCode !== 0) {
          throw new Error(`Failed to list interfaces: ${result.stderr}`);
        }
        return {
          content: [
            {
              type: "text",
              text: `Available interfaces:\n${result.stdout}`,
            },
          ],
        };
      }

      case "tshark_capture": {
        const iface = args?.interface as string;
        const count = Math.min((args?.count as number) || 10, 1000);
        const filter = args?.filter as string | undefined;
        const timeout = Math.min((args?.timeout as number) || 10, 60);
        const outputFile = args?.outputFile as string | undefined;

        if (!validateInterface(iface)) {
          throw new Error("Invalid interface name");
        }

        let cmd = `sudo tshark -i ${iface} -c ${count} -a duration:${timeout} -T json`;

        if (filter) {
          if (!validateFilter(filter)) {
            throw new Error("Invalid capture filter");
          }
          cmd += ` -f "${sanitizeInput(filter)}"`;
        }

        if (outputFile) {
          const safePath = sanitizeInput(outputFile);
          cmd += ` -w "${safePath}"`;
        }

        const result = await executeSSH(cmd, (timeout + 5) * 1000);

        return {
          content: [
            {
              type: "text",
              text: result.exitCode === 0
                ? `Captured packets:\n${result.stdout}`
                : `Capture completed with warnings:\n${result.stdout}\n\nStderr: ${result.stderr}`,
            },
          ],
        };
      }

      case "tshark_read_pcap": {
        const file = sanitizeInput(args?.file as string);
        const filter = args?.filter as string | undefined;
        const count = Math.min((args?.count as number) || 100, 1000);
        const fields = args?.fields as string[] | undefined;

        let cmd = `tshark -r "${file}" -c ${count}`;

        if (filter) {
          if (!validateFilter(filter)) {
            throw new Error("Invalid display filter");
          }
          cmd += ` -Y "${sanitizeInput(filter)}"`;
        }

        if (fields && fields.length > 0) {
          cmd += " -T fields";
          for (const field of fields) {
            cmd += ` -e ${sanitizeInput(field)}`;
          }
        } else {
          cmd += " -T json";
        }

        const result = await executeSSH(cmd, 60000);
        if (result.exitCode !== 0) {
          throw new Error(`Failed to read pcap: ${result.stderr}`);
        }

        return {
          content: [
            {
              type: "text",
              text: result.stdout,
            },
          ],
        };
      }

      case "tshark_filter": {
        const file = sanitizeInput(args?.file as string);
        const filter = args?.filter as string;
        const outputFormat = (args?.outputFormat as string) || "json";
        const fields = args?.fields as string[] | undefined;

        if (!validateFilter(filter)) {
          throw new Error("Invalid display filter");
        }

        let cmd = `tshark -r "${file}" -Y "${sanitizeInput(filter)}"`;

        if (outputFormat === "json") {
          cmd += " -T json";
        } else if (outputFormat === "fields" && fields) {
          cmd += " -T fields";
          for (const field of fields) {
            cmd += ` -e ${sanitizeInput(field)}`;
          }
        }

        const result = await executeSSH(cmd, 60000);
        if (result.exitCode !== 0) {
          throw new Error(`Filter failed: ${result.stderr}`);
        }

        return {
          content: [
            {
              type: "text",
              text: result.stdout || "No packets matched the filter",
            },
          ],
        };
      }

      case "tshark_stats": {
        const file = sanitizeInput(args?.file as string);
        const type = args?.type as string;
        const protocol = (args?.protocol as string) || "tcp";

        let cmd = `tshark -r "${file}" -q`;

        switch (type) {
          case "hierarchy":
            cmd += " -z io,phs";
            break;
          case "conversations":
            cmd += ` -z conv,${sanitizeInput(protocol)}`;
            break;
          case "endpoints":
            cmd += ` -z endpoints,${sanitizeInput(protocol)}`;
            break;
          case "io":
            cmd += " -z io,stat,1";
            break;
          case "http":
            cmd += " -z http,stat";
            break;
          case "dns":
            cmd += " -z dns,tree";
            break;
          default:
            throw new Error(`Unknown stats type: ${type}`);
        }

        const result = await executeSSH(cmd, 60000);
        if (result.exitCode !== 0) {
          throw new Error(`Statistics failed: ${result.stderr}`);
        }

        return {
          content: [
            {
              type: "text",
              text: result.stdout,
            },
          ],
        };
      }

      case "tshark_follow_stream": {
        const file = sanitizeInput(args?.file as string);
        const protocol = args?.protocol as string;
        const streamIndex = (args?.streamIndex as number) || 0;
        const format = (args?.format as string) || "ascii";

        const cmd = `tshark -r "${file}" -q -z follow,${protocol},${format},${streamIndex}`;

        const result = await executeSSH(cmd, 60000);
        if (result.exitCode !== 0) {
          throw new Error(`Follow stream failed: ${result.stderr}`);
        }

        return {
          content: [
            {
              type: "text",
              text: result.stdout,
            },
          ],
        };
      }

      case "tshark_extract_files": {
        const file = sanitizeInput(args?.file as string);
        const protocol = (args?.protocol as string) || "http";
        const outputDir = sanitizeInput((args?.outputDir as string) || "/tmp/mcp-extracted");

        // Create output directory
        await executeSSH(`mkdir -p "${outputDir}"`);

        const cmd = `tshark -r "${file}" --export-objects ${protocol},"${outputDir}"`;
        const result = await executeSSH(cmd, 120000);

        // List extracted files
        const listResult = await executeSSH(`ls -la "${outputDir}" 2>/dev/null || echo "No files extracted"`);

        return {
          content: [
            {
              type: "text",
              text: `Extraction complete.\n\nExtracted files:\n${listResult.stdout}`,
            },
          ],
        };
      }

      case "tshark_decode": {
        const file = sanitizeInput(args?.file as string);
        const packetNumber = args?.packetNumber as number | undefined;
        const filter = args?.filter as string | undefined;
        const protocols = args?.protocols as string[] | undefined;
        const verbose = args?.verbose as boolean;

        let cmd = `tshark -r "${file}"`;

        if (packetNumber) {
          cmd += ` -Y "frame.number == ${packetNumber}"`;
        } else if (filter) {
          if (!validateFilter(filter)) {
            throw new Error("Invalid display filter");
          }
          cmd += ` -Y "${sanitizeInput(filter)}"`;
        }

        if (verbose) {
          cmd += " -V";
        } else if (protocols && protocols.length > 0) {
          cmd += ` -O ${protocols.map(sanitizeInput).join(",")}`;
        } else {
          cmd += " -V";
        }

        cmd += " -c 10"; // Limit output

        const result = await executeSSH(cmd, 60000);
        if (result.exitCode !== 0) {
          throw new Error(`Decode failed: ${result.stderr}`);
        }

        return {
          content: [
            {
              type: "text",
              text: result.stdout,
            },
          ],
        };
      }

      case "tshark_extract_credentials": {
        const file = sanitizeInput(args?.file as string);

        // Search for various credential patterns
        const queries = [
          // HTTP Basic Auth
          `tshark -r "${file}" -Y "http.authorization" -T fields -e http.authorization -e ip.src -e ip.dst`,
          // FTP credentials
          `tshark -r "${file}" -Y "ftp.request.command == USER || ftp.request.command == PASS" -T fields -e ftp.request.command -e ftp.request.arg -e ip.src`,
          // HTTP POST with forms
          `tshark -r "${file}" -Y "http.request.method == POST" -T fields -e http.host -e http.request.uri -e urlencoded-form.key -e urlencoded-form.value -e ip.src`,
          // Telnet data
          `tshark -r "${file}" -Y "telnet" -T fields -e telnet.data -e ip.src -e ip.dst`,
        ];

        const results: string[] = [];

        for (const query of queries) {
          const result = await executeSSH(query, 30000);
          if (result.stdout.trim()) {
            results.push(result.stdout.trim());
          }
        }

        return {
          content: [
            {
              type: "text",
              text: results.length > 0
                ? `Potential credentials found:\n\n${results.join("\n\n")}`
                : "No credentials found in the capture",
            },
          ],
        };
      }

      case "tshark_export_objects": {
        const file = sanitizeInput(args?.file as string);
        const listOnly = args?.listOnly !== false;
        const outputDir = sanitizeInput((args?.outputDir as string) || "/tmp/mcp-objects");

        if (listOnly) {
          // Use grep to list HTTP objects
          const cmd = `tshark -r "${file}" -Y "http.response" -T fields -e http.content_type -e http.content_length -e http.response.code -e http.request.uri | head -50`;
          const result = await executeSSH(cmd, 60000);

          return {
            content: [
              {
                type: "text",
                text: `HTTP objects in capture:\n\n${result.stdout || "No HTTP objects found"}`,
              },
            ],
          };
        } else {
          await executeSSH(`mkdir -p "${outputDir}"`);
          const cmd = `tshark -r "${file}" --export-objects http,"${outputDir}"`;
          await executeSSH(cmd, 120000);

          const listResult = await executeSSH(`ls -la "${outputDir}"`);

          return {
            content: [
              {
                type: "text",
                text: `Exported objects to ${outputDir}:\n\n${listResult.stdout}`,
              },
            ],
          };
        }
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
          text: `Error: ${errorMessage}`,
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
  console.error("Wireshark MCP server started");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
