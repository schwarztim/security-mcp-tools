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
const SSH_OPTIONS = process.env.SSH_OPTIONS || "-o StrictHostKeyChecking=no -o ConnectTimeout=10";

// Tool definitions
const tools: Tool[] = [
  {
    name: "smbmap_enum",
    description: "Enumerate SMB shares on a target host. Lists all accessible shares with their permissions (READ, WRITE, NO ACCESS).",
    inputSchema: {
      type: "object",
      properties: {
        host: {
          type: "string",
          description: "Target IP address or hostname"
        },
        username: {
          type: "string",
          description: "Username for authentication (omit for null session)"
        },
        password: {
          type: "string",
          description: "Password or NTLM hash for authentication"
        },
        domain: {
          type: "string",
          description: "Domain name (default: WORKGROUP)"
        },
        port: {
          type: "number",
          description: "SMB port (default: 445)"
        }
      },
      required: ["host"]
    }
  },
  {
    name: "smbmap_permissions",
    description: "Check permissions on SMB shares. Returns detailed access rights for each share.",
    inputSchema: {
      type: "object",
      properties: {
        host: {
          type: "string",
          description: "Target IP address or hostname"
        },
        username: {
          type: "string",
          description: "Username for authentication"
        },
        password: {
          type: "string",
          description: "Password or NTLM hash"
        },
        domain: {
          type: "string",
          description: "Domain name"
        },
        share: {
          type: "string",
          description: "Specific share to check (optional, checks all if not specified)"
        }
      },
      required: ["host"]
    }
  },
  {
    name: "smbmap_list",
    description: "List files and directories in an SMB share. Supports recursive listing.",
    inputSchema: {
      type: "object",
      properties: {
        host: {
          type: "string",
          description: "Target IP address or hostname"
        },
        username: {
          type: "string",
          description: "Username for authentication"
        },
        password: {
          type: "string",
          description: "Password or NTLM hash"
        },
        domain: {
          type: "string",
          description: "Domain name"
        },
        path: {
          type: "string",
          description: "Path to list (e.g., 'C$\\Users' or 'share_name\\folder')"
        },
        recursive: {
          type: "boolean",
          description: "Recursively list directories (default: false)"
        },
        depth: {
          type: "number",
          description: "Maximum recursion depth (default: 5)"
        }
      },
      required: ["host"]
    }
  },
  {
    name: "smbmap_download",
    description: "Download a file from an SMB share to the Kali machine.",
    inputSchema: {
      type: "object",
      properties: {
        host: {
          type: "string",
          description: "Target IP address or hostname"
        },
        username: {
          type: "string",
          description: "Username for authentication"
        },
        password: {
          type: "string",
          description: "Password or NTLM hash"
        },
        domain: {
          type: "string",
          description: "Domain name"
        },
        remote_path: {
          type: "string",
          description: "Remote file path (e.g., 'C$\\temp\\passwords.txt')"
        },
        local_path: {
          type: "string",
          description: "Local destination path on Kali (optional)"
        }
      },
      required: ["host", "remote_path"]
    }
  },
  {
    name: "smbmap_upload",
    description: "Upload a file from Kali to an SMB share on the target.",
    inputSchema: {
      type: "object",
      properties: {
        host: {
          type: "string",
          description: "Target IP address or hostname"
        },
        username: {
          type: "string",
          description: "Username for authentication"
        },
        password: {
          type: "string",
          description: "Password or NTLM hash"
        },
        domain: {
          type: "string",
          description: "Domain name"
        },
        local_path: {
          type: "string",
          description: "Local file path on Kali"
        },
        remote_path: {
          type: "string",
          description: "Remote destination path (e.g., 'C$\\temp\\payload.exe')"
        }
      },
      required: ["host", "local_path", "remote_path"]
    }
  },
  {
    name: "smbmap_exec",
    description: "Execute a command on the target via SMB. Requires administrative privileges.",
    inputSchema: {
      type: "object",
      properties: {
        host: {
          type: "string",
          description: "Target IP address or hostname"
        },
        username: {
          type: "string",
          description: "Username for authentication (admin required)"
        },
        password: {
          type: "string",
          description: "Password or NTLM hash"
        },
        domain: {
          type: "string",
          description: "Domain name"
        },
        command: {
          type: "string",
          description: "Command to execute on target"
        }
      },
      required: ["host", "username", "password", "command"]
    }
  },
  {
    name: "smbmap_search",
    description: "Search for files by name pattern across SMB shares. Supports regex patterns.",
    inputSchema: {
      type: "object",
      properties: {
        host: {
          type: "string",
          description: "Target IP address or hostname"
        },
        username: {
          type: "string",
          description: "Username for authentication"
        },
        password: {
          type: "string",
          description: "Password or NTLM hash"
        },
        domain: {
          type: "string",
          description: "Domain name"
        },
        pattern: {
          type: "string",
          description: "File name pattern (regex supported, e.g., '.*password.*')"
        },
        search_path: {
          type: "string",
          description: "Path to search (e.g., 'C$\\Users')"
        },
        auto_download: {
          type: "boolean",
          description: "Automatically download matching files (default: false)"
        }
      },
      required: ["host", "pattern"]
    }
  },
  {
    name: "smbmap_content_search",
    description: "Search file contents for patterns (requires admin and PowerShell on target).",
    inputSchema: {
      type: "object",
      properties: {
        host: {
          type: "string",
          description: "Target IP address or hostname"
        },
        username: {
          type: "string",
          description: "Username for authentication (admin required)"
        },
        password: {
          type: "string",
          description: "Password or NTLM hash"
        },
        domain: {
          type: "string",
          description: "Domain name"
        },
        pattern: {
          type: "string",
          description: "Content search pattern (e.g., '[Pp]assword')"
        },
        search_path: {
          type: "string",
          description: "Path to search (default: C:\\Users)"
        },
        timeout: {
          type: "number",
          description: "Search timeout in seconds (default: 300)"
        }
      },
      required: ["host", "username", "password", "pattern"]
    }
  },
  {
    name: "smbmap_drives",
    description: "List all drives on the target system.",
    inputSchema: {
      type: "object",
      properties: {
        host: {
          type: "string",
          description: "Target IP address or hostname"
        },
        username: {
          type: "string",
          description: "Username for authentication"
        },
        password: {
          type: "string",
          description: "Password or NTLM hash"
        },
        domain: {
          type: "string",
          description: "Domain name"
        }
      },
      required: ["host"]
    }
  },
  {
    name: "smbmap_delete",
    description: "Delete a file from an SMB share.",
    inputSchema: {
      type: "object",
      properties: {
        host: {
          type: "string",
          description: "Target IP address or hostname"
        },
        username: {
          type: "string",
          description: "Username for authentication"
        },
        password: {
          type: "string",
          description: "Password or NTLM hash"
        },
        domain: {
          type: "string",
          description: "Domain name"
        },
        remote_path: {
          type: "string",
          description: "Remote file path to delete (e.g., 'C$\\temp\\payload.exe')"
        }
      },
      required: ["host", "remote_path"]
    }
  },
  {
    name: "smbmap_host_file",
    description: "Scan multiple hosts from a file for SMB shares.",
    inputSchema: {
      type: "object",
      properties: {
        host_file: {
          type: "string",
          description: "Path to file containing list of hosts (one per line)"
        },
        username: {
          type: "string",
          description: "Username for authentication"
        },
        password: {
          type: "string",
          description: "Password or NTLM hash"
        },
        domain: {
          type: "string",
          description: "Domain name"
        }
      },
      required: ["host_file"]
    }
  }
];

// Helper function to build smbmap command
function buildSmbmapCommand(args: Record<string, unknown>): string {
  const parts: string[] = ["smbmap"];

  if (args.host) {
    parts.push(`-H '${args.host}'`);
  }
  if (args.host_file) {
    parts.push(`--host-file '${args.host_file}'`);
  }
  if (args.username) {
    parts.push(`-u '${args.username}'`);
  }
  if (args.password) {
    parts.push(`-p '${args.password}'`);
  }
  if (args.domain) {
    parts.push(`-d '${args.domain}'`);
  }
  if (args.port) {
    parts.push(`-P ${args.port}`);
  }
  if (args.share) {
    parts.push(`-s '${args.share}'`);
  }

  return parts.join(" ");
}

// Execute command via SSH on Kali
async function executeOnKali(command: string): Promise<{ stdout: string; stderr: string }> {
  const sshCommand = `ssh ${SSH_OPTIONS} ${KALI_HOST} "${command.replace(/"/g, '\\"')}"`;

  try {
    const result = await execAsync(sshCommand, {
      timeout: 300000, // 5 minute timeout
      maxBuffer: 10 * 1024 * 1024 // 10MB buffer
    });
    return result;
  } catch (error: unknown) {
    const execError = error as { stdout?: string; stderr?: string; message?: string };
    // Return output even if command failed (non-zero exit)
    if (execError.stdout || execError.stderr) {
      return {
        stdout: execError.stdout || "",
        stderr: execError.stderr || ""
      };
    }
    throw error;
  }
}

// Tool handlers
async function handleSmbmapEnum(args: Record<string, unknown>): Promise<string> {
  const cmd = buildSmbmapCommand(args);
  const result = await executeOnKali(cmd);
  return formatOutput("Share Enumeration", result);
}

async function handleSmbmapPermissions(args: Record<string, unknown>): Promise<string> {
  const cmd = buildSmbmapCommand(args);
  const result = await executeOnKali(cmd);
  return formatOutput("Permission Check", result);
}

async function handleSmbmapList(args: Record<string, unknown>): Promise<string> {
  let cmd = buildSmbmapCommand(args);

  if (args.recursive) {
    if (args.path) {
      cmd += ` -R '${args.path}'`;
    } else {
      cmd += " -R";
    }
    if (args.depth) {
      cmd += ` --depth ${args.depth}`;
    }
  } else {
    if (args.path) {
      cmd += ` -r '${args.path}'`;
    } else {
      cmd += " -r";
    }
  }

  const result = await executeOnKali(cmd);
  return formatOutput("Directory Listing", result);
}

async function handleSmbmapDownload(args: Record<string, unknown>): Promise<string> {
  let cmd = buildSmbmapCommand(args);
  cmd += ` --download '${args.remote_path}'`;

  const result = await executeOnKali(cmd);
  return formatOutput("File Download", result);
}

async function handleSmbmapUpload(args: Record<string, unknown>): Promise<string> {
  let cmd = buildSmbmapCommand(args);
  cmd += ` --upload '${args.local_path}' '${args.remote_path}'`;

  const result = await executeOnKali(cmd);
  return formatOutput("File Upload", result);
}

async function handleSmbmapExec(args: Record<string, unknown>): Promise<string> {
  let cmd = buildSmbmapCommand(args);
  cmd += ` -x '${args.command}'`;

  const result = await executeOnKali(cmd);
  return formatOutput("Command Execution", result);
}

async function handleSmbmapSearch(args: Record<string, unknown>): Promise<string> {
  let cmd = buildSmbmapCommand(args);

  if (args.auto_download) {
    cmd += ` -A '${args.pattern}'`;
    if (args.search_path) {
      cmd += ` -r '${args.search_path}'`;
    } else {
      cmd += " -r";
    }
  } else {
    // For pattern search without auto-download, we use recursive listing
    if (args.search_path) {
      cmd += ` -R '${args.search_path}'`;
    } else {
      cmd += " -R";
    }
    // Filter will be done on output
  }

  const result = await executeOnKali(cmd);

  // If not auto-download, filter results by pattern
  if (!args.auto_download && args.pattern) {
    const pattern = new RegExp(args.pattern as string, "i");
    const lines = result.stdout.split("\n");
    const filtered = lines.filter(line => pattern.test(line));
    result.stdout = filtered.join("\n");
  }

  return formatOutput("File Search", result);
}

async function handleSmbmapContentSearch(args: Record<string, unknown>): Promise<string> {
  let cmd = buildSmbmapCommand(args);
  cmd += ` -F '${args.pattern}'`;

  if (args.search_path) {
    cmd += ` --search-path '${args.search_path}'`;
  }
  if (args.timeout) {
    cmd += ` --search-timeout ${args.timeout}`;
  }

  const result = await executeOnKali(cmd);
  return formatOutput("Content Search", result);
}

async function handleSmbmapDrives(args: Record<string, unknown>): Promise<string> {
  let cmd = buildSmbmapCommand(args);
  cmd += " -L";

  const result = await executeOnKali(cmd);
  return formatOutput("Drive List", result);
}

async function handleSmbmapDelete(args: Record<string, unknown>): Promise<string> {
  let cmd = buildSmbmapCommand(args);
  cmd += ` --delete '${args.remote_path}' --skip`;

  const result = await executeOnKali(cmd);
  return formatOutput("File Deletion", result);
}

async function handleSmbmapHostFile(args: Record<string, unknown>): Promise<string> {
  const cmd = buildSmbmapCommand(args);
  const result = await executeOnKali(cmd);
  return formatOutput("Multi-Host Scan", result);
}

// Format output helper
function formatOutput(operation: string, result: { stdout: string; stderr: string }): string {
  let output = `=== ${operation} Results ===\n\n`;

  if (result.stdout) {
    output += result.stdout;
  }

  if (result.stderr) {
    output += `\n\n--- Errors/Warnings ---\n${result.stderr}`;
  }

  if (!result.stdout && !result.stderr) {
    output += "No output returned.";
  }

  return output;
}

// Main server setup
const server = new Server(
  {
    name: "smbmap-mcp",
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
    let result: string;

    switch (name) {
      case "smbmap_enum":
        result = await handleSmbmapEnum(args as Record<string, unknown>);
        break;
      case "smbmap_permissions":
        result = await handleSmbmapPermissions(args as Record<string, unknown>);
        break;
      case "smbmap_list":
        result = await handleSmbmapList(args as Record<string, unknown>);
        break;
      case "smbmap_download":
        result = await handleSmbmapDownload(args as Record<string, unknown>);
        break;
      case "smbmap_upload":
        result = await handleSmbmapUpload(args as Record<string, unknown>);
        break;
      case "smbmap_exec":
        result = await handleSmbmapExec(args as Record<string, unknown>);
        break;
      case "smbmap_search":
        result = await handleSmbmapSearch(args as Record<string, unknown>);
        break;
      case "smbmap_content_search":
        result = await handleSmbmapContentSearch(args as Record<string, unknown>);
        break;
      case "smbmap_drives":
        result = await handleSmbmapDrives(args as Record<string, unknown>);
        break;
      case "smbmap_delete":
        result = await handleSmbmapDelete(args as Record<string, unknown>);
        break;
      case "smbmap_host_file":
        result = await handleSmbmapHostFile(args as Record<string, unknown>);
        break;
      default:
        throw new Error(`Unknown tool: ${name}`);
    }

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
          text: `Error executing ${name}: ${errorMessage}`,
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
  console.error("SMBMap MCP server started");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
