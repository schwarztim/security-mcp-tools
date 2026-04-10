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
const SSH_OPTIONS = "-o StrictHostKeyChecking=no -o ConnectTimeout=30";

interface EnumOptions {
  target: string;
  username?: string;
  password?: string;
  domain?: string;
  verbose?: boolean;
  ridRanges?: string;
  knownUsers?: string;
  keepRidSearching?: number;
}

interface CommandResult {
  success: boolean;
  output: string;
  error?: string;
  command?: string;
}

// Execute command via SSH on Kali
async function executeOnKali(command: string, timeout: number = 300): Promise<CommandResult> {
  const sshCommand = `ssh ${SSH_OPTIONS} ${KALI_HOST} "${command.replace(/"/g, '\\"')}"`;

  try {
    const { stdout, stderr } = await execAsync(sshCommand, {
      timeout: timeout * 1000,
      maxBuffer: 10 * 1024 * 1024, // 10MB buffer for large outputs
    });

    return {
      success: true,
      output: stdout,
      error: stderr || undefined,
      command: command,
    };
  } catch (error: any) {
    // Even on non-zero exit, we may have useful output
    return {
      success: error.code === 0,
      output: error.stdout || "",
      error: error.stderr || error.message || String(error),
      command: command,
    };
  }
}

// Build enum4linux command with options (standard Perl version)
function buildCommand(options: EnumOptions, flags: string = ""): string {
  const parts = ["enum4linux"];

  // Authentication
  if (options.username) {
    parts.push(`-u '${options.username}'`);
  }
  if (options.password) {
    parts.push(`-p '${options.password}'`);
  }
  if (options.domain) {
    parts.push(`-w '${options.domain}'`);
  }

  // Verbose
  if (options.verbose) {
    parts.push("-v");
  }

  // RID ranges
  if (options.ridRanges) {
    parts.push(`-R '${options.ridRanges}'`);
  }

  // Known users
  if (options.knownUsers) {
    parts.push(`-k '${options.knownUsers}'`);
  }

  // Keep RID searching
  if (options.keepRidSearching) {
    parts.push(`-K ${options.keepRidSearching}`);
  }

  // Additional flags
  if (flags) {
    parts.push(flags);
  }

  // Target
  parts.push(options.target);

  return parts.join(" ");
}

// Parse enum4linux output into structured data
function parseOutput(output: string): Record<string, any> {
  const result: Record<string, any> = {
    raw_output: output,
    sections: {},
  };

  // Parse known sections
  const sectionPatterns = [
    { name: "target_info", pattern: /={10,}\s*\|\s*Target Information\s*\|[\s\S]*?(?=={10,}|$)/i },
    { name: "workgroup", pattern: /={10,}\s*\|\s*Workgroup.*?\|[\s\S]*?(?=={10,}|$)/i },
    { name: "nbtstat", pattern: /={10,}\s*\|\s*Nbtstat Information.*?\|[\s\S]*?(?=={10,}|$)/i },
    { name: "session_check", pattern: /={10,}\s*\|\s*Session Check.*?\|[\s\S]*?(?=={10,}|$)/i },
    { name: "users", pattern: /={10,}\s*\|\s*Users.*?via.*?\|[\s\S]*?(?=={10,}|$)/i },
    { name: "share_enumeration", pattern: /={10,}\s*\|\s*Share Enumeration.*?\|[\s\S]*?(?=={10,}|$)/i },
    { name: "password_policy", pattern: /={10,}\s*\|\s*Password Policy.*?\|[\s\S]*?(?=={10,}|$)/i },
    { name: "groups", pattern: /={10,}\s*\|\s*Groups.*?via.*?\|[\s\S]*?(?=={10,}|$)/i },
    { name: "os_info", pattern: /={10,}\s*\|\s*OS Information.*?\|[\s\S]*?(?=={10,}|$)/i },
    { name: "rid_cycling", pattern: /={10,}\s*\|\s*Users via RID cycling.*?\|[\s\S]*?(?=={10,}|$)/i },
    { name: "printer_info", pattern: /={10,}\s*\|\s*Getting printer info.*?\|[\s\S]*?(?=={10,}|$)/i },
  ];

  for (const { name, pattern } of sectionPatterns) {
    const match = output.match(pattern);
    if (match) {
      result.sections[name] = match[0].trim();
    }
  }

  // Extract specific data points

  // Users
  const userMatches = output.matchAll(/user:\[(.*?)\]/gi);
  const users: string[] = [];
  for (const match of userMatches) {
    if (match[1] && !users.includes(match[1])) {
      users.push(match[1]);
    }
  }
  if (users.length > 0) {
    result.users = users;
  }

  // Groups
  const groupMatches = output.matchAll(/group:\[(.*?)\]/gi);
  const groups: string[] = [];
  for (const match of groupMatches) {
    if (match[1] && !groups.includes(match[1])) {
      groups.push(match[1]);
    }
  }
  if (groups.length > 0) {
    result.groups = groups;
  }

  // Shares
  const shareMatches = output.matchAll(/\s+([\w$]+)\s+(?:Disk|IPC|Printer)\s+/gi);
  const shares: string[] = [];
  for (const match of shareMatches) {
    if (match[1] && !shares.includes(match[1])) {
      shares.push(match[1]);
    }
  }
  if (shares.length > 0) {
    result.shares = shares;
  }

  // Domain/Workgroup
  const workgroupMatch = output.match(/Domain:\s*\[(.*?)\]/i) || output.match(/Workgroup:\s*\[(.*?)\]/i);
  if (workgroupMatch) {
    result.domain = workgroupMatch[1];
  }

  // OS Info
  const osMatch = output.match(/OS:\s*\[(.*?)\]/i);
  if (osMatch) {
    result.os = osMatch[1];
  }

  // Password policy
  const passwordPolicySection = output.match(/Minimum password length:\s*(\d+)/i);
  if (passwordPolicySection) {
    result.password_policy = {
      min_length: parseInt(passwordPolicySection[1], 10),
    };

    const maxAgeMatch = output.match(/Maximum password age:\s*(.*)/i);
    if (maxAgeMatch) {
      result.password_policy.max_age = maxAgeMatch[1].trim();
    }

    const lockoutThreshold = output.match(/Account Lockout Threshold:\s*(\d+)/i);
    if (lockoutThreshold) {
      result.password_policy.lockout_threshold = parseInt(lockoutThreshold[1], 10);
    }
  }

  return result;
}

// Tool definitions
const tools: Tool[] = [
  {
    name: "enum4linux_all",
    description: "Perform comprehensive SMB enumeration on a target. Includes users, groups, shares, password policies, OS info, NetBIOS lookups, RID cycling, and printer info. This is the most thorough enumeration option (-a flag).",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target IP address or hostname",
        },
        username: {
          type: "string",
          description: "Username for authentication (optional, try anonymous first)",
        },
        password: {
          type: "string",
          description: "Password for authentication (optional)",
        },
        domain: {
          type: "string",
          description: "Workgroup/domain name (optional, usually auto-detected)",
        },
        verbose: {
          type: "boolean",
          description: "Show verbose output including raw commands",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "enum4linux_users",
    description: "Enumerate users on a Windows/Samba system via RPC. Returns usernames and optionally detailed information (-U flag).",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target IP address or hostname",
        },
        username: {
          type: "string",
          description: "Username for authentication (optional)",
        },
        password: {
          type: "string",
          description: "Password for authentication (optional)",
        },
        detailed: {
          type: "boolean",
          description: "Get detailed information for each user (-d flag)",
        },
        domain: {
          type: "string",
          description: "Workgroup/domain name (optional)",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "enum4linux_groups",
    description: "Enumerate groups and their members on a Windows/Samba system via RPC (-G flag).",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target IP address or hostname",
        },
        username: {
          type: "string",
          description: "Username for authentication (optional)",
        },
        password: {
          type: "string",
          description: "Password for authentication (optional)",
        },
        domain: {
          type: "string",
          description: "Workgroup/domain name (optional)",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "enum4linux_shares",
    description: "Enumerate SMB shares on a target. Includes share names, types, comments, and access permissions (-S flag).",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target IP address or hostname",
        },
        username: {
          type: "string",
          description: "Username for authentication (optional)",
        },
        password: {
          type: "string",
          description: "Password for authentication (optional)",
        },
        bruteforce: {
          type: "string",
          description: "Path to file containing share names to brute force (-s flag)",
        },
        detailed: {
          type: "boolean",
          description: "Get detailed share information (-d flag)",
        },
        domain: {
          type: "string",
          description: "Workgroup/domain name (optional)",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "enum4linux_policies",
    description: "Retrieve password policies and account lockout settings from the target. Useful for understanding password requirements before brute force attempts (-P flag).",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target IP address or hostname",
        },
        username: {
          type: "string",
          description: "Username for authentication (optional)",
        },
        password: {
          type: "string",
          description: "Password for authentication (optional)",
        },
        domain: {
          type: "string",
          description: "Workgroup/domain name (optional)",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "enum4linux_os",
    description: "Retrieve operating system information from the target, including OS version, server type, and domain/workgroup membership (-o flag).",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target IP address or hostname",
        },
        username: {
          type: "string",
          description: "Username for authentication (optional)",
        },
        password: {
          type: "string",
          description: "Password for authentication (optional)",
        },
        domain: {
          type: "string",
          description: "Workgroup/domain name (optional)",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "enum4linux_rid",
    description: "Enumerate users via RID cycling. This technique can discover users even when normal enumeration fails. Useful against systems with RestrictAnonymous set (-r flag for basic, -R for custom ranges).",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target IP address or hostname",
        },
        username: {
          type: "string",
          description: "Username for authentication (optional)",
        },
        password: {
          type: "string",
          description: "Password for authentication (optional)",
        },
        ridRanges: {
          type: "string",
          description: "RID ranges to enumerate (default: 500-550,1000-1050). Format: start-end,start-end",
        },
        keepSearching: {
          type: "number",
          description: "Keep searching RIDs until n consecutive RIDs don't correspond to a username. Useful against DCs (-K flag)",
        },
        knownUsers: {
          type: "string",
          description: "Comma-separated list of known users for SID lookup (default: administrator,guest,krbtgt,domain admins,root,bin,none)",
        },
        domain: {
          type: "string",
          description: "Workgroup/domain name (optional)",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "enum4linux_printers",
    description: "Enumerate printers on the target system via RPC (-i flag).",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target IP address or hostname",
        },
        username: {
          type: "string",
          description: "Username for authentication (optional)",
        },
        password: {
          type: "string",
          description: "Password for authentication (optional)",
        },
        domain: {
          type: "string",
          description: "Workgroup/domain name (optional)",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "enum4linux_netbios",
    description: "Perform NetBIOS name lookup on the target (nbtstat equivalent). Returns workgroup/domain name, machine name, and NetBIOS names (-n flag).",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target IP address or hostname",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "enum4linux_ldap",
    description: "Retrieve limited domain information via LDAP on port 389/TCP. Only works on domain controllers (-l flag).",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target IP address or hostname (must be a domain controller)",
        },
        username: {
          type: "string",
          description: "Username for authentication (optional)",
        },
        password: {
          type: "string",
          description: "Password for authentication (optional)",
        },
        domain: {
          type: "string",
          description: "Domain name (optional)",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "enum4linux_machines",
    description: "Enumerate machines/computers in the domain (-M flag).",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target IP address or hostname",
        },
        username: {
          type: "string",
          description: "Username for authentication (optional)",
        },
        password: {
          type: "string",
          description: "Password for authentication (optional)",
        },
        domain: {
          type: "string",
          description: "Workgroup/domain name (optional)",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "enum4linux_aggressive",
    description: "Aggressive enumeration mode. Performs write checks on shares and other intrusive tests (-A flag). Use with caution.",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target IP address or hostname",
        },
        username: {
          type: "string",
          description: "Username for authentication (optional)",
        },
        password: {
          type: "string",
          description: "Password for authentication (optional)",
        },
        domain: {
          type: "string",
          description: "Workgroup/domain name (optional)",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "enum4linux_raw",
    description: "Execute enum4linux with custom flags. Use this for advanced scenarios not covered by other tools.",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target IP address or hostname",
        },
        flags: {
          type: "string",
          description: "Custom flags to pass to enum4linux (e.g., '-U -G -S -P')",
        },
        username: {
          type: "string",
          description: "Username for authentication (optional)",
        },
        password: {
          type: "string",
          description: "Password for authentication (optional)",
        },
        domain: {
          type: "string",
          description: "Workgroup/domain name (optional)",
        },
      },
      required: ["target"],
    },
  },
];

// Create the MCP server
const server = new Server(
  {
    name: "enum4linux-mcp",
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

// Handle tool execution
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  if (!args || typeof args !== "object") {
    throw new Error("Invalid arguments");
  }

  const typedArgs = args as Record<string, any>;

  const baseOptions: EnumOptions = {
    target: typedArgs.target,
    username: typedArgs.username,
    password: typedArgs.password,
    domain: typedArgs.domain,
    verbose: typedArgs.verbose,
    ridRanges: typedArgs.ridRanges,
    knownUsers: typedArgs.knownUsers,
    keepRidSearching: typedArgs.keepSearching,
  };

  let command: string;
  let executionTimeout = 300; // Default 5 minutes

  switch (name) {
    case "enum4linux_all":
      command = buildCommand(baseOptions, "-a");
      executionTimeout = 600; // 10 minutes for full scan
      break;

    case "enum4linux_users":
      const usersFlags = typedArgs.detailed ? "-U -d" : "-U";
      command = buildCommand(baseOptions, usersFlags);
      break;

    case "enum4linux_groups":
      command = buildCommand(baseOptions, "-G");
      break;

    case "enum4linux_shares":
      let sharesFlags = "-S";
      if (typedArgs.detailed) {
        sharesFlags += " -d";
      }
      if (typedArgs.bruteforce) {
        sharesFlags += ` -s '${typedArgs.bruteforce}'`;
      }
      command = buildCommand(baseOptions, sharesFlags);
      break;

    case "enum4linux_policies":
      command = buildCommand(baseOptions, "-P");
      break;

    case "enum4linux_os":
      command = buildCommand(baseOptions, "-o");
      break;

    case "enum4linux_rid":
      let ridFlags = "-r";
      if (typedArgs.ridRanges) {
        ridFlags = `-R '${typedArgs.ridRanges}'`;
      }
      command = buildCommand(baseOptions, ridFlags);
      executionTimeout = 600; // RID cycling can take a while
      break;

    case "enum4linux_printers":
      command = buildCommand(baseOptions, "-i");
      break;

    case "enum4linux_netbios":
      command = buildCommand(baseOptions, "-n");
      break;

    case "enum4linux_ldap":
      command = buildCommand(baseOptions, "-l");
      break;

    case "enum4linux_machines":
      command = buildCommand(baseOptions, "-M");
      break;

    case "enum4linux_aggressive":
      command = buildCommand(baseOptions, "-A");
      executionTimeout = 600;
      break;

    case "enum4linux_raw":
      command = buildCommand(baseOptions, typedArgs.flags || "");
      executionTimeout = 600;
      break;

    default:
      throw new Error(`Unknown tool: ${name}`);
  }

  const result = await executeOnKali(command, executionTimeout);

  // Parse output into structured data
  const parsedOutput = parseOutput(result.output);

  // Format the response
  const response = {
    tool: name,
    target: baseOptions.target,
    success: result.success || result.output.length > 0,
    command_executed: result.command,
    ...parsedOutput,
    ...(result.error && { stderr: result.error }),
  };

  return {
    content: [
      {
        type: "text",
        text: JSON.stringify(response, null, 2),
      },
    ],
  };
});

// Start the server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("enum4linux MCP server running on stdio");
}

main().catch((error) => {
  console.error("Failed to start server:", error);
  process.exit(1);
});
