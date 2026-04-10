#!/usr/bin/env node
/**
 * Veil-Evasion MCP Server
 *
 * Provides MCP tools for interacting with the Veil Framework
 * for payload generation and AV evasion testing.
 *
 * Executes commands via SSH on a Kali Linux host.
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
const KALI_HOST = process.env.VEIL_KALI_HOST || "kali";
const VEIL_PATH = process.env.VEIL_PATH || "/usr/share/veil/Veil.py";
const SSH_OPTIONS = "-o StrictHostKeyChecking=no -o ConnectTimeout=10";

// Helper to execute commands on Kali via SSH
async function sshExec(command: string, timeout = 120000): Promise<{ stdout: string; stderr: string }> {
  const sshCommand = `ssh ${SSH_OPTIONS} ${KALI_HOST} "${command.replace(/"/g, '\\"')}"`;
  try {
    const result = await execAsync(sshCommand, {
      timeout,
      maxBuffer: 10 * 1024 * 1024 // 10MB buffer
    });
    return result;
  } catch (error: any) {
    if (error.stdout || error.stderr) {
      return { stdout: error.stdout || "", stderr: error.stderr || error.message };
    }
    throw error;
  }
}

// Define available tools
const tools: Tool[] = [
  {
    name: "veil_list_tools",
    description: "List available Veil tools (Evasion, Ordnance)",
    inputSchema: {
      type: "object",
      properties: {},
      required: []
    }
  },
  {
    name: "veil_list_payloads",
    description: "List all available payloads for a specific Veil tool",
    inputSchema: {
      type: "object",
      properties: {
        tool: {
          type: "string",
          description: "Tool name: 'Evasion' or 'Ordnance'",
          enum: ["Evasion", "Ordnance"]
        }
      },
      required: ["tool"]
    }
  },
  {
    name: "veil_payload_info",
    description: "Get detailed information about a specific payload including required options",
    inputSchema: {
      type: "object",
      properties: {
        tool: {
          type: "string",
          description: "Tool name: 'Evasion' or 'Ordnance'",
          enum: ["Evasion", "Ordnance"]
        },
        payload: {
          type: "string",
          description: "Payload name or number (e.g., 'go/meterpreter/rev_tcp' or '41')"
        }
      },
      required: ["tool", "payload"]
    }
  },
  {
    name: "veil_generate",
    description: "Generate a payload with specified options. Returns the generated file path.",
    inputSchema: {
      type: "object",
      properties: {
        tool: {
          type: "string",
          description: "Tool name: 'Evasion' or 'Ordnance'",
          enum: ["Evasion", "Ordnance"]
        },
        payload: {
          type: "string",
          description: "Payload name or number"
        },
        lhost: {
          type: "string",
          description: "Callback IP address (LHOST)"
        },
        lport: {
          type: "number",
          description: "Callback port (LPORT)",
          default: 4444
        },
        output_name: {
          type: "string",
          description: "Base name for output files (without extension)"
        },
        shellcode_method: {
          type: "string",
          description: "Shellcode generation method",
          enum: ["msfvenom", "ordnance"],
          default: "ordnance"
        },
        msfvenom_payload: {
          type: "string",
          description: "MSFVenom payload to use (e.g., 'windows/meterpreter/reverse_tcp')"
        },
        custom_options: {
          type: "object",
          description: "Additional payload-specific options as key-value pairs",
          additionalProperties: { type: "string" }
        }
      },
      required: ["tool", "payload", "lhost"]
    }
  },
  {
    name: "veil_generate_shellcode",
    description: "Generate shellcode only using Veil-Ordnance",
    inputSchema: {
      type: "object",
      properties: {
        payload: {
          type: "string",
          description: "Ordnance payload (e.g., 'rev_tcp', 'rev_https', 'rev_http')"
        },
        lhost: {
          type: "string",
          description: "Callback IP address"
        },
        lport: {
          type: "number",
          description: "Callback port",
          default: 4444
        },
        encoder: {
          type: "string",
          description: "Encoder to use (optional)"
        },
        iterations: {
          type: "number",
          description: "Number of encoding iterations",
          default: 1
        }
      },
      required: ["payload", "lhost"]
    }
  },
  {
    name: "veil_check_hash",
    description: "Check if a payload hash is detected by VirusTotal (does NOT upload the file)",
    inputSchema: {
      type: "object",
      properties: {
        file_path: {
          type: "string",
          description: "Path to the generated payload file on the Kali system"
        }
      },
      required: ["file_path"]
    }
  },
  {
    name: "veil_clean",
    description: "Clean up generated payloads and artifacts",
    inputSchema: {
      type: "object",
      properties: {
        clean_all: {
          type: "boolean",
          description: "If true, cleans all generated files. If false, prompts for specific cleanup.",
          default: true
        }
      },
      required: []
    }
  },
  {
    name: "veil_list_generated",
    description: "List all previously generated payloads",
    inputSchema: {
      type: "object",
      properties: {},
      required: []
    }
  },
  {
    name: "veil_version",
    description: "Get Veil framework version information",
    inputSchema: {
      type: "object",
      properties: {},
      required: []
    }
  },
  {
    name: "veil_update",
    description: "Update the Veil framework to the latest version",
    inputSchema: {
      type: "object",
      properties: {},
      required: []
    }
  },
  {
    name: "veil_raw_command",
    description: "Execute a raw Veil command for advanced usage",
    inputSchema: {
      type: "object",
      properties: {
        args: {
          type: "string",
          description: "Command line arguments to pass to Veil.py"
        }
      },
      required: ["args"]
    }
  }
];

// Tool implementations
async function handleToolCall(name: string, args: Record<string, unknown>): Promise<string> {
  switch (name) {
    case "veil_list_tools": {
      const { stdout } = await sshExec(`python3 ${VEIL_PATH} --list-tools`);
      return stdout || "Available tools:\n1. Evasion - Generate AV-evading payloads\n2. Ordnance - Generate shellcode";
    }

    case "veil_list_payloads": {
      const tool = args.tool as string;
      const { stdout, stderr } = await sshExec(`python3 ${VEIL_PATH} -t ${tool} --list-payloads`);
      return stdout || stderr || `No payloads found for ${tool}`;
    }

    case "veil_payload_info": {
      const tool = args.tool as string;
      const payload = args.payload as string;
      // Use interactive mode to get info
      const { stdout, stderr } = await sshExec(
        `echo -e "use ${payload}\\ninfo\\nexit" | python3 ${VEIL_PATH} -t ${tool}`,
        60000
      );
      return stdout || stderr || `No info available for payload ${payload}`;
    }

    case "veil_generate": {
      const tool = args.tool as string;
      const payload = args.payload as string;
      const lhost = args.lhost as string;
      const lport = (args.lport as number) || 4444;
      const outputName = (args.output_name as string) || `payload_${Date.now()}`;
      const shellcodeMethod = (args.shellcode_method as string) || "ordnance";
      const msfvenomPayload = args.msfvenom_payload as string;
      const customOptions = args.custom_options as Record<string, string> || {};

      let cmd = `python3 ${VEIL_PATH} -t ${tool} -p ${payload} --ip ${lhost} --port ${lport} -o ${outputName}`;

      if (shellcodeMethod === "msfvenom" && msfvenomPayload) {
        cmd += ` --msfvenom ${msfvenomPayload}`;
      } else if (shellcodeMethod === "ordnance") {
        cmd += ` --ordnance-payload rev_tcp`;
      }

      // Add custom options
      if (Object.keys(customOptions).length > 0) {
        const optStr = Object.entries(customOptions)
          .map(([k, v]) => `${k}=${v}`)
          .join(" ");
        cmd += ` -c ${optStr}`;
      }

      const { stdout, stderr } = await sshExec(cmd, 300000); // 5 min timeout for generation

      // Parse output to find generated file path
      const outputMatch = stdout.match(/Output file written to:\s*(.+)/i) ||
                         stdout.match(/Executable written to:\s*(.+)/i) ||
                         stdout.match(/Payload written to:\s*(.+)/i);

      let result = stdout || stderr;
      if (outputMatch) {
        result += `\n\n[Generated File]: ${outputMatch[1].trim()}`;
      }

      return result;
    }

    case "veil_generate_shellcode": {
      const payload = args.payload as string;
      const lhost = args.lhost as string;
      const lport = (args.lport as number) || 4444;
      const encoder = args.encoder as string;
      const iterations = (args.iterations as number) || 1;

      let cmd = `python3 ${VEIL_PATH} -t Ordnance --ordnance-payload ${payload} --ip ${lhost} --port ${lport}`;

      if (encoder) {
        cmd += ` --encoder ${encoder} --iterations ${iterations}`;
      }

      const { stdout, stderr } = await sshExec(cmd, 120000);
      return stdout || stderr || "Shellcode generation completed";
    }

    case "veil_check_hash": {
      const filePath = args.file_path as string;
      // Calculate hash and check against VT (hash only, no upload)
      const { stdout: hashOutput } = await sshExec(`sha256sum ${filePath}`);
      const hash = hashOutput.split(" ")[0];

      // Use Veil's checkvt if available, otherwise just return the hash
      const { stdout, stderr } = await sshExec(
        `echo -e "checkvt\\n${filePath}\\nexit" | python3 ${VEIL_PATH}`,
        60000
      );

      return `File: ${filePath}\nSHA256: ${hash}\n\n${stdout || stderr || "Use the hash to manually check on VirusTotal"}`;
    }

    case "veil_clean": {
      const cleanAll = args.clean_all !== false;

      if (cleanAll) {
        const { stdout, stderr } = await sshExec(
          `echo "y" | python3 ${VEIL_PATH} --clean`,
          60000
        );
        return stdout || stderr || "Cleanup completed";
      } else {
        return "Use clean_all=true to clean all generated files, or manually remove specific files";
      }
    }

    case "veil_list_generated": {
      // Default Veil output directories
      const dirs = [
        "/var/lib/veil/output/compiled",
        "/var/lib/veil/output/source",
        "/var/lib/veil/output/handlers"
      ];

      let result = "Generated Payloads:\n\n";

      for (const dir of dirs) {
        const { stdout } = await sshExec(`ls -la ${dir} 2>/dev/null || echo "Directory not found: ${dir}"`);
        result += `=== ${dir} ===\n${stdout}\n\n`;
      }

      return result;
    }

    case "veil_version": {
      const { stdout, stderr } = await sshExec(`python3 ${VEIL_PATH} --version`);
      return stdout || stderr || "Version information not available";
    }

    case "veil_update": {
      const { stdout, stderr } = await sshExec(`python3 ${VEIL_PATH} --update`, 300000);
      return stdout || stderr || "Update completed";
    }

    case "veil_raw_command": {
      const cmdArgs = args.args as string;
      const { stdout, stderr } = await sshExec(`python3 ${VEIL_PATH} ${cmdArgs}`, 300000);
      return stdout || stderr || "Command executed";
    }

    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

// Create and run the server
async function main() {
  const server = new Server(
    {
      name: "veil-evasion-mcp",
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
      const result = await handleToolCall(name, args || {});
      return {
        content: [
          {
            type: "text",
            text: result,
          },
        ],
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

  // Start the server
  const transport = new StdioServerTransport();
  await server.connect(transport);

  console.error("Veil-Evasion MCP Server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
