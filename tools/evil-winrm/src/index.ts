#!/usr/bin/env node
/**
 * Evil-WinRM MCP Server
 *
 * An MCP server for executing Evil-WinRM commands against Windows targets
 * via SSH to a Kali Linux host.
 *
 * Evil-WinRM is a tool for penetration testing that provides a shell
 * on Windows systems via the WinRM protocol.
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
const KALI_HOST = process.env.KALI_HOST || "kali";
const KALI_USER = process.env.KALI_USER || "kali";
const SSH_KEY = process.env.SSH_KEY || "";
const DEFAULT_PORT = process.env.EVILWINRM_DEFAULT_PORT || "5985";

interface SessionState {
  host?: string;
  user?: string;
  password?: string;
  hash?: string;
  port?: string;
  ssl?: boolean;
  realm?: string;
  scriptsPath?: string;
  execsPath?: string;
}

// Session state for persistent connections
let currentSession: SessionState = {};

/**
 * Execute a command via SSH to Kali
 */
async function executeViaSSH(command: string, timeout: number = 60000): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  return new Promise((resolve) => {
    const sshArgs: string[] = [];

    // Add SSH key if specified
    if (SSH_KEY) {
      sshArgs.push("-i", SSH_KEY);
    }

    // Add common SSH options
    sshArgs.push(
      "-o", "StrictHostKeyChecking=no",
      "-o", "UserKnownHostsFile=/dev/null",
      "-o", "ConnectTimeout=10",
      `${KALI_USER}@${KALI_HOST}`,
      command
    );

    const proc = spawn("ssh", sshArgs);

    let stdout = "";
    let stderr = "";

    proc.stdout.on("data", (data) => {
      stdout += data.toString();
    });

    proc.stderr.on("data", (data) => {
      stderr += data.toString();
    });

    const timer = setTimeout(() => {
      proc.kill();
      resolve({ stdout, stderr: stderr + "\nCommand timed out", exitCode: 124 });
    }, timeout);

    proc.on("close", (code) => {
      clearTimeout(timer);
      resolve({ stdout, stderr, exitCode: code ?? 1 });
    });

    proc.on("error", (error) => {
      clearTimeout(timer);
      resolve({ stdout: "", stderr: error.message, exitCode: 1 });
    });
  });
}

/**
 * Build the evil-winrm command with current session parameters
 */
function buildEvilWinrmCommand(additionalArgs: string = ""): string {
  if (!currentSession.host || !currentSession.user) {
    throw new Error("No active session. Use evilwinrm_connect first.");
  }

  let cmd = `evil-winrm -i ${currentSession.host} -u '${currentSession.user}'`;

  if (currentSession.password) {
    cmd += ` -p '${currentSession.password}'`;
  }

  if (currentSession.hash) {
    cmd += ` -H '${currentSession.hash}'`;
  }

  if (currentSession.port && currentSession.port !== "5985") {
    cmd += ` -P ${currentSession.port}`;
  }

  if (currentSession.ssl) {
    cmd += " -S";
  }

  if (currentSession.realm) {
    cmd += ` -r '${currentSession.realm}'`;
  }

  if (currentSession.scriptsPath) {
    cmd += ` -s '${currentSession.scriptsPath}'`;
  }

  if (currentSession.execsPath) {
    cmd += ` -e '${currentSession.execsPath}'`;
  }

  if (additionalArgs) {
    cmd += ` ${additionalArgs}`;
  }

  return cmd;
}

/**
 * Execute a PowerShell command via evil-winrm
 */
async function executeCommand(command: string, timeout: number = 60000): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  // Build the command to execute a single command and exit
  const evilWinrmCmd = buildEvilWinrmCommand();

  // Use here-string to pass command
  const fullCommand = `echo '${command.replace(/'/g, "'\\''")}' | ${evilWinrmCmd}`;

  return executeViaSSH(fullCommand, timeout);
}

// Define the tools
const tools: Tool[] = [
  {
    name: "evilwinrm_connect",
    description: "Establish connection parameters for Evil-WinRM session. This sets up the target but does not maintain a persistent connection. Supports password, NTLM hash (pass-the-hash), SSL, and Kerberos authentication.",
    inputSchema: {
      type: "object",
      properties: {
        host: {
          type: "string",
          description: "Target IP address or hostname"
        },
        user: {
          type: "string",
          description: "Username for authentication"
        },
        password: {
          type: "string",
          description: "Password (use this OR hash, not both)"
        },
        hash: {
          type: "string",
          description: "NTLM hash for pass-the-hash authentication"
        },
        port: {
          type: "string",
          description: "WinRM port (default: 5985, HTTPS: 5986)"
        },
        ssl: {
          type: "boolean",
          description: "Enable SSL/TLS connection"
        },
        realm: {
          type: "string",
          description: "Kerberos realm/domain for authentication"
        },
        scripts_path: {
          type: "string",
          description: "Path to PowerShell scripts directory on Kali"
        },
        execs_path: {
          type: "string",
          description: "Path to C# executables directory on Kali"
        }
      },
      required: ["host", "user"]
    }
  },
  {
    name: "evilwinrm_exec",
    description: "Execute a PowerShell command on the target via Evil-WinRM. Requires prior evilwinrm_connect call.",
    inputSchema: {
      type: "object",
      properties: {
        command: {
          type: "string",
          description: "PowerShell command to execute"
        },
        timeout: {
          type: "number",
          description: "Command timeout in seconds (default: 60)"
        }
      },
      required: ["command"]
    }
  },
  {
    name: "evilwinrm_upload",
    description: "Upload a file to the target Windows system via Evil-WinRM. Source file must exist on Kali.",
    inputSchema: {
      type: "object",
      properties: {
        local_path: {
          type: "string",
          description: "Path to file on Kali to upload"
        },
        remote_path: {
          type: "string",
          description: "Destination path on target (optional, defaults to current directory)"
        }
      },
      required: ["local_path"]
    }
  },
  {
    name: "evilwinrm_download",
    description: "Download a file from the target Windows system via Evil-WinRM. File is saved to Kali.",
    inputSchema: {
      type: "object",
      properties: {
        remote_path: {
          type: "string",
          description: "Path to file on target to download"
        },
        local_path: {
          type: "string",
          description: "Destination path on Kali (optional)"
        }
      },
      required: ["remote_path"]
    }
  },
  {
    name: "evilwinrm_services",
    description: "List Windows services and show which ones the current user has permissions over. Does not require administrator privileges.",
    inputSchema: {
      type: "object",
      properties: {},
      required: []
    }
  },
  {
    name: "evilwinrm_menu",
    description: "Show available Evil-WinRM menu commands including Invoke-Binary, Dll-Loader, Donut-Loader, and Bypass-4MSI functions.",
    inputSchema: {
      type: "object",
      properties: {},
      required: []
    }
  },
  {
    name: "evilwinrm_dll_loader",
    description: "Load a DLL on the target via Evil-WinRM. Supports SMB, local, or HTTP paths.",
    inputSchema: {
      type: "object",
      properties: {
        method: {
          type: "string",
          enum: ["smb", "local", "http"],
          description: "Loading method: smb, local, or http"
        },
        path: {
          type: "string",
          description: "Path to DLL (SMB: \\\\server\\share\\file.dll, local: C:\\path\\file.dll, http: http://url/file.dll)"
        }
      },
      required: ["method", "path"]
    }
  },
  {
    name: "evilwinrm_invoke_binary",
    description: "Execute a .NET assembly in memory on the target. The assembly must be in the executables path specified during connect.",
    inputSchema: {
      type: "object",
      properties: {
        binary_name: {
          type: "string",
          description: "Name of the .NET assembly (must be in execs_path)"
        },
        arguments: {
          type: "string",
          description: "Comma-separated arguments for the binary"
        }
      },
      required: ["binary_name"]
    }
  },
  {
    name: "evilwinrm_bypass_amsi",
    description: "Execute Bypass-4MSI to patch AMSI (Antimalware Scan Interface) protections on the target.",
    inputSchema: {
      type: "object",
      properties: {},
      required: []
    }
  },
  {
    name: "evilwinrm_test_connection",
    description: "Test if Kali host is reachable and evil-winrm is installed.",
    inputSchema: {
      type: "object",
      properties: {},
      required: []
    }
  },
  {
    name: "evilwinrm_get_session",
    description: "Get current session parameters (without sensitive data like password/hash).",
    inputSchema: {
      type: "object",
      properties: {},
      required: []
    }
  },
  {
    name: "evilwinrm_clear_session",
    description: "Clear the current session parameters.",
    inputSchema: {
      type: "object",
      properties: {},
      required: []
    }
  }
];

// Create the server
const server = new Server(
  {
    name: "evil-winrm-mcp",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Handle tool listing
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return { tools };
});

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case "evilwinrm_connect": {
        const host = args?.host as string;
        const user = args?.user as string;
        const password = args?.password as string | undefined;
        const hash = args?.hash as string | undefined;
        const port = (args?.port as string) || DEFAULT_PORT;
        const ssl = args?.ssl as boolean | undefined;
        const realm = args?.realm as string | undefined;
        const scriptsPath = args?.scripts_path as string | undefined;
        const execsPath = args?.execs_path as string | undefined;

        if (!password && !hash) {
          return {
            content: [{ type: "text", text: "Error: Either password or hash must be provided" }],
            isError: true,
          };
        }

        currentSession = {
          host,
          user,
          password,
          hash,
          port,
          ssl,
          realm,
          scriptsPath,
          execsPath,
        };

        const authMethod = hash ? "NTLM hash (pass-the-hash)" : "password";
        const sslStatus = ssl ? "enabled" : "disabled";

        return {
          content: [{
            type: "text",
            text: `Session configured:\n- Target: ${host}:${port}\n- User: ${user}\n- Auth: ${authMethod}\n- SSL: ${sslStatus}${realm ? `\n- Kerberos realm: ${realm}` : ""}${scriptsPath ? `\n- Scripts path: ${scriptsPath}` : ""}${execsPath ? `\n- Executables path: ${execsPath}` : ""}\n\nUse evilwinrm_exec to execute commands.`
          }],
        };
      }

      case "evilwinrm_exec": {
        const command = args?.command as string;
        const timeout = ((args?.timeout as number) || 60) * 1000;

        const result = await executeCommand(command, timeout);

        return {
          content: [{
            type: "text",
            text: `Command: ${command}\n\n--- STDOUT ---\n${result.stdout}\n--- STDERR ---\n${result.stderr}\n--- Exit Code: ${result.exitCode} ---`
          }],
          isError: result.exitCode !== 0,
        };
      }

      case "evilwinrm_upload": {
        const localPath = args?.local_path as string;
        const remotePath = args?.remote_path as string | undefined;

        const uploadCmd = remotePath
          ? `upload ${localPath} ${remotePath}`
          : `upload ${localPath}`;

        const result = await executeCommand(uploadCmd);

        return {
          content: [{
            type: "text",
            text: `Upload: ${localPath}${remotePath ? ` -> ${remotePath}` : ""}\n\n${result.stdout}${result.stderr ? `\nErrors: ${result.stderr}` : ""}`
          }],
          isError: result.exitCode !== 0,
        };
      }

      case "evilwinrm_download": {
        const remotePath = args?.remote_path as string;
        const localPath = args?.local_path as string | undefined;

        const downloadCmd = localPath
          ? `download ${remotePath} ${localPath}`
          : `download ${remotePath}`;

        const result = await executeCommand(downloadCmd);

        return {
          content: [{
            type: "text",
            text: `Download: ${remotePath}${localPath ? ` -> ${localPath}` : ""}\n\n${result.stdout}${result.stderr ? `\nErrors: ${result.stderr}` : ""}`
          }],
          isError: result.exitCode !== 0,
        };
      }

      case "evilwinrm_services": {
        const result = await executeCommand("services");

        return {
          content: [{
            type: "text",
            text: `Windows Services:\n\n${result.stdout}${result.stderr ? `\nErrors: ${result.stderr}` : ""}`
          }],
          isError: result.exitCode !== 0,
        };
      }

      case "evilwinrm_menu": {
        const result = await executeCommand("menu");

        return {
          content: [{
            type: "text",
            text: `Evil-WinRM Menu:\n\n${result.stdout}${result.stderr ? `\nErrors: ${result.stderr}` : ""}`
          }],
          isError: result.exitCode !== 0,
        };
      }

      case "evilwinrm_dll_loader": {
        const method = args?.method as string;
        const path = args?.path as string;

        const dllCmd = `Dll-Loader -${method} -path ${path}`;
        const result = await executeCommand(dllCmd);

        return {
          content: [{
            type: "text",
            text: `DLL Loader (${method}): ${path}\n\n${result.stdout}${result.stderr ? `\nErrors: ${result.stderr}` : ""}`
          }],
          isError: result.exitCode !== 0,
        };
      }

      case "evilwinrm_invoke_binary": {
        const binaryName = args?.binary_name as string;
        const arguments_ = args?.arguments as string | undefined;

        const invokeCmd = arguments_
          ? `Invoke-Binary ${binaryName} ${arguments_}`
          : `Invoke-Binary ${binaryName}`;

        const result = await executeCommand(invokeCmd);

        return {
          content: [{
            type: "text",
            text: `Invoke-Binary: ${binaryName}${arguments_ ? ` (args: ${arguments_})` : ""}\n\n${result.stdout}${result.stderr ? `\nErrors: ${result.stderr}` : ""}`
          }],
          isError: result.exitCode !== 0,
        };
      }

      case "evilwinrm_bypass_amsi": {
        const result = await executeCommand("Bypass-4MSI");

        return {
          content: [{
            type: "text",
            text: `Bypass-4MSI (AMSI Patch):\n\n${result.stdout}${result.stderr ? `\nErrors: ${result.stderr}` : ""}`
          }],
          isError: result.exitCode !== 0,
        };
      }

      case "evilwinrm_test_connection": {
        // Test SSH connection and evil-winrm availability
        const sshTest = await executeViaSSH("which evil-winrm && evil-winrm --version 2>/dev/null || echo 'version check failed'");

        if (sshTest.exitCode !== 0) {
          return {
            content: [{
              type: "text",
              text: `Kali Connection Test FAILED:\n\nSSH to ${KALI_USER}@${KALI_HOST} failed.\nError: ${sshTest.stderr}\n\nMake sure:\n1. Kali host is reachable\n2. SSH key is configured (KALI_HOST, KALI_USER, SSH_KEY env vars)\n3. evil-winrm is installed on Kali`
            }],
            isError: true,
          };
        }

        return {
          content: [{
            type: "text",
            text: `Kali Connection Test PASSED:\n\nSSH: ${KALI_USER}@${KALI_HOST}\n${sshTest.stdout}`
          }],
        };
      }

      case "evilwinrm_get_session": {
        if (!currentSession.host) {
          return {
            content: [{
              type: "text",
              text: "No active session. Use evilwinrm_connect to configure a session."
            }],
          };
        }

        return {
          content: [{
            type: "text",
            text: `Current Session:\n- Target: ${currentSession.host}:${currentSession.port || DEFAULT_PORT}\n- User: ${currentSession.user}\n- Auth: ${currentSession.hash ? "NTLM hash" : "password"}\n- SSL: ${currentSession.ssl ? "enabled" : "disabled"}${currentSession.realm ? `\n- Kerberos realm: ${currentSession.realm}` : ""}${currentSession.scriptsPath ? `\n- Scripts path: ${currentSession.scriptsPath}` : ""}${currentSession.execsPath ? `\n- Executables path: ${currentSession.execsPath}` : ""}`
          }],
        };
      }

      case "evilwinrm_clear_session": {
        currentSession = {};

        return {
          content: [{
            type: "text",
            text: "Session cleared."
          }],
        };
      }

      default:
        return {
          content: [{ type: "text", text: `Unknown tool: ${name}` }],
          isError: true,
        };
    }
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return {
      content: [{ type: "text", text: `Error: ${errorMessage}` }],
      isError: true,
    };
  }
});

// Start the server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Evil-WinRM MCP server started");
}

main().catch(console.error);
