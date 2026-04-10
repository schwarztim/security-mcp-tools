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
import * as fs from "fs/promises";
import * as path from "path";

const execAsync = promisify(exec);

// Configuration
const KALI_HOST = process.env.KALI_HOST || "kali";
const DEFAULT_OUTPUT_DIR = process.env.LDAP_OUTPUT_DIR || "/tmp/ldapdomaindump";

interface LdapDumpOptions {
  hostname: string;
  username?: string;
  password?: string;
  authType?: "NTLM" | "SIMPLE";
  outputDir?: string;
  noHtml?: boolean;
  noJson?: boolean;
  noGrep?: boolean;
  groupedJson?: boolean;
  resolveDns?: boolean;
  dnsServer?: string;
  minimal?: boolean;
  useSsl?: boolean;
}

// Build the ldapdomaindump command
function buildCommand(options: LdapDumpOptions, additionalArgs: string[] = []): string {
  const args: string[] = ["ldapdomaindump"];

  // Authentication
  if (options.username) {
    args.push("-u", `'${options.username}'`);
  }
  if (options.password) {
    args.push("-p", `'${options.password}'`);
  }
  if (options.authType) {
    args.push("-at", options.authType);
  }

  // Output options
  const outputDir = options.outputDir || DEFAULT_OUTPUT_DIR;
  args.push("-o", outputDir);

  if (options.noHtml) args.push("--no-html");
  if (options.noJson) args.push("--no-json");
  if (options.noGrep) args.push("--no-grep");
  if (options.groupedJson) args.push("--grouped-json");

  // DNS options
  if (options.resolveDns) args.push("-r");
  if (options.dnsServer) args.push("-n", options.dnsServer);

  // Minimal mode
  if (options.minimal) args.push("-m");

  // Additional args
  args.push(...additionalArgs);

  // Hostname (use SSL if specified)
  let host = options.hostname;
  if (options.useSsl && !host.startsWith("ldaps://")) {
    host = `ldaps://${host}`;
  } else if (!options.useSsl && !host.startsWith("ldap://") && !host.startsWith("ldaps://")) {
    host = `ldap://${host}`;
  }
  args.push(host);

  return args.join(" ");
}

// Execute command on Kali via SSH
async function executeOnKali(command: string, timeout: number = 300000): Promise<{ stdout: string; stderr: string }> {
  const sshCommand = `ssh ${KALI_HOST} "${command.replace(/"/g, '\\"')}"`;

  try {
    const result = await execAsync(sshCommand, { timeout });
    return result;
  } catch (error: any) {
    if (error.stdout || error.stderr) {
      return { stdout: error.stdout || "", stderr: error.stderr || error.message };
    }
    throw error;
  }
}

// Read output files from Kali
async function readOutputFiles(outputDir: string, filePattern?: string): Promise<Record<string, string>> {
  const pattern = filePattern || "*.json";
  const listCommand = `ls ${outputDir}/${pattern} 2>/dev/null || echo "NO_FILES"`;

  const { stdout } = await executeOnKali(listCommand);

  if (stdout.trim() === "NO_FILES") {
    return {};
  }

  const files = stdout.trim().split("\n").filter(f => f);
  const contents: Record<string, string> = {};

  for (const file of files) {
    try {
      const { stdout: content } = await executeOnKali(`cat '${file}'`);
      contents[path.basename(file)] = content;
    } catch {
      // Skip files that can't be read
    }
  }

  return contents;
}

// Define MCP tools
const tools: Tool[] = [
  {
    name: "ldapdomaindump_dump",
    description: "Perform a full LDAP domain dump - enumerates users, groups, computers, trusts, and policies. Outputs HTML, JSON, and greppable files.",
    inputSchema: {
      type: "object",
      properties: {
        hostname: {
          type: "string",
          description: "Domain controller hostname or IP address (e.g., '10.10.10.1' or 'dc01.corp.local')"
        },
        username: {
          type: "string",
          description: "Username for authentication in DOMAIN\\username format (e.g., 'CORP\\jsmith')"
        },
        password: {
          type: "string",
          description: "Password or NTLM hash (LM:NT format) for authentication"
        },
        authType: {
          type: "string",
          enum: ["NTLM", "SIMPLE"],
          description: "Authentication type (default: NTLM)"
        },
        outputDir: {
          type: "string",
          description: "Output directory on Kali (default: /tmp/ldapdomaindump)"
        },
        useSsl: {
          type: "boolean",
          description: "Use LDAPS (SSL) connection (default: false)"
        },
        resolveDns: {
          type: "boolean",
          description: "Resolve computer DNS hostnames to IPs (may cause high DC load)"
        },
        groupedJson: {
          type: "boolean",
          description: "Enable grouped JSON output for users_by_group and computers_by_os"
        }
      },
      required: ["hostname", "username", "password"]
    }
  },
  {
    name: "ldapdomaindump_users",
    description: "Enumerate domain users only. Returns user accounts with attributes like name, description, last logon, password expiry, etc.",
    inputSchema: {
      type: "object",
      properties: {
        hostname: {
          type: "string",
          description: "Domain controller hostname or IP"
        },
        username: {
          type: "string",
          description: "Username in DOMAIN\\username format"
        },
        password: {
          type: "string",
          description: "Password or NTLM hash"
        },
        authType: {
          type: "string",
          enum: ["NTLM", "SIMPLE"],
          description: "Authentication type"
        },
        useSsl: {
          type: "boolean",
          description: "Use LDAPS connection"
        },
        outputDir: {
          type: "string",
          description: "Output directory"
        }
      },
      required: ["hostname", "username", "password"]
    }
  },
  {
    name: "ldapdomaindump_groups",
    description: "Enumerate domain groups and their memberships. Returns group names, descriptions, and member lists.",
    inputSchema: {
      type: "object",
      properties: {
        hostname: {
          type: "string",
          description: "Domain controller hostname or IP"
        },
        username: {
          type: "string",
          description: "Username in DOMAIN\\username format"
        },
        password: {
          type: "string",
          description: "Password or NTLM hash"
        },
        authType: {
          type: "string",
          enum: ["NTLM", "SIMPLE"],
          description: "Authentication type"
        },
        useSsl: {
          type: "boolean",
          description: "Use LDAPS connection"
        },
        outputDir: {
          type: "string",
          description: "Output directory"
        }
      },
      required: ["hostname", "username", "password"]
    }
  },
  {
    name: "ldapdomaindump_computers",
    description: "Enumerate domain computers. Returns computer accounts with OS info, hostnames, and descriptions.",
    inputSchema: {
      type: "object",
      properties: {
        hostname: {
          type: "string",
          description: "Domain controller hostname or IP"
        },
        username: {
          type: "string",
          description: "Username in DOMAIN\\username format"
        },
        password: {
          type: "string",
          description: "Password or NTLM hash"
        },
        authType: {
          type: "string",
          enum: ["NTLM", "SIMPLE"],
          description: "Authentication type"
        },
        useSsl: {
          type: "boolean",
          description: "Use LDAPS connection"
        },
        resolveDns: {
          type: "boolean",
          description: "Resolve computer hostnames to IP addresses"
        },
        outputDir: {
          type: "string",
          description: "Output directory"
        }
      },
      required: ["hostname", "username", "password"]
    }
  },
  {
    name: "ldapdomaindump_trusts",
    description: "Enumerate domain trusts. Returns trust relationships between domains including trust direction and type.",
    inputSchema: {
      type: "object",
      properties: {
        hostname: {
          type: "string",
          description: "Domain controller hostname or IP"
        },
        username: {
          type: "string",
          description: "Username in DOMAIN\\username format"
        },
        password: {
          type: "string",
          description: "Password or NTLM hash"
        },
        authType: {
          type: "string",
          enum: ["NTLM", "SIMPLE"],
          description: "Authentication type"
        },
        useSsl: {
          type: "boolean",
          description: "Use LDAPS connection"
        },
        outputDir: {
          type: "string",
          description: "Output directory"
        }
      },
      required: ["hostname", "username", "password"]
    }
  },
  {
    name: "ldapdomaindump_policies",
    description: "Get domain password policies and fine-grained password policies (PSOs). Returns lockout thresholds, password length requirements, etc.",
    inputSchema: {
      type: "object",
      properties: {
        hostname: {
          type: "string",
          description: "Domain controller hostname or IP"
        },
        username: {
          type: "string",
          description: "Username in DOMAIN\\username format"
        },
        password: {
          type: "string",
          description: "Password or NTLM hash"
        },
        authType: {
          type: "string",
          enum: ["NTLM", "SIMPLE"],
          description: "Authentication type"
        },
        useSsl: {
          type: "boolean",
          description: "Use LDAPS connection"
        },
        outputDir: {
          type: "string",
          description: "Output directory"
        }
      },
      required: ["hostname", "username", "password"]
    }
  },
  {
    name: "ldapdomaindump_read_output",
    description: "Read previously generated ldapdomaindump output files from Kali. Use after running a dump to retrieve specific results.",
    inputSchema: {
      type: "object",
      properties: {
        outputDir: {
          type: "string",
          description: "Directory containing the dump output (default: /tmp/ldapdomaindump)"
        },
        fileType: {
          type: "string",
          enum: ["json", "html", "grep", "all"],
          description: "Type of files to read (default: json)"
        },
        fileName: {
          type: "string",
          description: "Specific file to read (e.g., 'domain_users.json')"
        }
      }
    }
  },
  {
    name: "ldapdomaindump_ldd2pretty",
    description: "Convert ldapdomaindump JSON output to enum4linux-like readable format using the ldd2pretty utility.",
    inputSchema: {
      type: "object",
      properties: {
        outputDir: {
          type: "string",
          description: "Directory containing the JSON files from ldapdomaindump"
        }
      }
    }
  },
  {
    name: "ldapdomaindump_check",
    description: "Check if ldapdomaindump is installed and accessible on the Kali host via SSH.",
    inputSchema: {
      type: "object",
      properties: {}
    }
  }
];

// Tool handlers
async function handleDump(args: any): Promise<string> {
  const options: LdapDumpOptions = {
    hostname: args.hostname,
    username: args.username,
    password: args.password,
    authType: args.authType,
    outputDir: args.outputDir || DEFAULT_OUTPUT_DIR,
    useSsl: args.useSsl,
    resolveDns: args.resolveDns,
    groupedJson: args.groupedJson
  };

  // Create output directory
  await executeOnKali(`mkdir -p ${options.outputDir}`);

  const command = buildCommand(options);
  const { stdout, stderr } = await executeOnKali(command);

  // Read the JSON output files
  const files = await readOutputFiles(options.outputDir!, "*.json");

  let result = `## ldapdomaindump Full Dump\n\n`;
  result += `**Target:** ${options.hostname}\n`;
  result += `**Output Directory:** ${options.outputDir}\n\n`;

  if (stderr && stderr.includes("error")) {
    result += `### Errors\n\`\`\`\n${stderr}\n\`\`\`\n\n`;
  }

  result += `### Output Files Generated\n`;
  for (const [filename, content] of Object.entries(files)) {
    const preview = content.length > 1000 ? content.substring(0, 1000) + "..." : content;
    result += `\n#### ${filename}\n\`\`\`json\n${preview}\n\`\`\`\n`;
  }

  if (Object.keys(files).length === 0) {
    result += `\nNo output files found. Command output:\n\`\`\`\n${stdout}\n${stderr}\n\`\`\``;
  }

  return result;
}

async function handleUsers(args: any): Promise<string> {
  const options: LdapDumpOptions = {
    hostname: args.hostname,
    username: args.username,
    password: args.password,
    authType: args.authType,
    outputDir: args.outputDir || DEFAULT_OUTPUT_DIR,
    useSsl: args.useSsl,
    noHtml: true,
    noGrep: true
  };

  await executeOnKali(`mkdir -p ${options.outputDir}`);
  const command = buildCommand(options);
  await executeOnKali(command);

  // Read users file
  const { stdout: usersContent } = await executeOnKali(`cat ${options.outputDir}/domain_users.json 2>/dev/null || echo "[]"`);

  try {
    const users = JSON.parse(usersContent);
    let result = `## Domain Users\n\n**Count:** ${users.length}\n\n`;

    // Summary table
    result += `| SAM Account | Display Name | Description | Last Logon | Enabled |\n`;
    result += `|-------------|--------------|-------------|------------|----------|\n`;

    for (const user of users.slice(0, 50)) {
      const sam = user.attributes?.sAMAccountName || "N/A";
      const display = user.attributes?.displayName || user.attributes?.cn || "N/A";
      const desc = (user.attributes?.description || "N/A").substring(0, 30);
      const lastLogon = user.attributes?.lastLogon || "Never";
      const uac = user.attributes?.userAccountControl || 0;
      const enabled = (uac & 2) === 0 ? "Yes" : "No";
      result += `| ${sam} | ${display} | ${desc} | ${lastLogon} | ${enabled} |\n`;
    }

    if (users.length > 50) {
      result += `\n*Showing first 50 of ${users.length} users. Full data in ${options.outputDir}/domain_users.json*`;
    }

    return result;
  } catch {
    return `## Domain Users\n\nRaw output:\n\`\`\`\n${usersContent}\n\`\`\``;
  }
}

async function handleGroups(args: any): Promise<string> {
  const options: LdapDumpOptions = {
    hostname: args.hostname,
    username: args.username,
    password: args.password,
    authType: args.authType,
    outputDir: args.outputDir || DEFAULT_OUTPUT_DIR,
    useSsl: args.useSsl,
    noHtml: true,
    noGrep: true,
    groupedJson: true
  };

  await executeOnKali(`mkdir -p ${options.outputDir}`);
  const command = buildCommand(options);
  await executeOnKali(command);

  // Read groups file
  const { stdout: groupsContent } = await executeOnKali(`cat ${options.outputDir}/domain_groups.json 2>/dev/null || echo "[]"`);

  try {
    const groups = JSON.parse(groupsContent);
    let result = `## Domain Groups\n\n**Count:** ${groups.length}\n\n`;

    result += `| Group Name | Description | Member Count |\n`;
    result += `|------------|-------------|-------------|\n`;

    for (const group of groups.slice(0, 50)) {
      const name = group.attributes?.sAMAccountName || group.attributes?.cn || "N/A";
      const desc = (group.attributes?.description || "N/A").substring(0, 40);
      const members = group.attributes?.member ?
        (Array.isArray(group.attributes.member) ? group.attributes.member.length : 1) : 0;
      result += `| ${name} | ${desc} | ${members} |\n`;
    }

    if (groups.length > 50) {
      result += `\n*Showing first 50 of ${groups.length} groups. Full data in ${options.outputDir}/domain_groups.json*`;
    }

    return result;
  } catch {
    return `## Domain Groups\n\nRaw output:\n\`\`\`\n${groupsContent}\n\`\`\``;
  }
}

async function handleComputers(args: any): Promise<string> {
  const options: LdapDumpOptions = {
    hostname: args.hostname,
    username: args.username,
    password: args.password,
    authType: args.authType,
    outputDir: args.outputDir || DEFAULT_OUTPUT_DIR,
    useSsl: args.useSsl,
    resolveDns: args.resolveDns,
    noHtml: true,
    noGrep: true
  };

  await executeOnKali(`mkdir -p ${options.outputDir}`);
  const command = buildCommand(options);
  await executeOnKali(command);

  // Read computers file
  const { stdout: computersContent } = await executeOnKali(`cat ${options.outputDir}/domain_computers.json 2>/dev/null || echo "[]"`);

  try {
    const computers = JSON.parse(computersContent);
    let result = `## Domain Computers\n\n**Count:** ${computers.length}\n\n`;

    result += `| Computer Name | Operating System | DNS Hostname | Description |\n`;
    result += `|---------------|------------------|--------------|-------------|\n`;

    for (const computer of computers.slice(0, 50)) {
      const name = computer.attributes?.sAMAccountName || "N/A";
      const os = computer.attributes?.operatingSystem || "Unknown";
      const dns = computer.attributes?.dNSHostName || "N/A";
      const desc = (computer.attributes?.description || "N/A").substring(0, 30);
      result += `| ${name} | ${os} | ${dns} | ${desc} |\n`;
    }

    if (computers.length > 50) {
      result += `\n*Showing first 50 of ${computers.length} computers. Full data in ${options.outputDir}/domain_computers.json*`;
    }

    return result;
  } catch {
    return `## Domain Computers\n\nRaw output:\n\`\`\`\n${computersContent}\n\`\`\``;
  }
}

async function handleTrusts(args: any): Promise<string> {
  const options: LdapDumpOptions = {
    hostname: args.hostname,
    username: args.username,
    password: args.password,
    authType: args.authType,
    outputDir: args.outputDir || DEFAULT_OUTPUT_DIR,
    useSsl: args.useSsl,
    noHtml: true,
    noGrep: true
  };

  await executeOnKali(`mkdir -p ${options.outputDir}`);
  const command = buildCommand(options);
  await executeOnKali(command);

  // Read trusts file
  const { stdout: trustsContent } = await executeOnKali(`cat ${options.outputDir}/domain_trusts.json 2>/dev/null || echo "[]"`);

  try {
    const trusts = JSON.parse(trustsContent);
    let result = `## Domain Trusts\n\n**Count:** ${trusts.length}\n\n`;

    if (trusts.length === 0) {
      result += "*No domain trusts found.*\n";
      return result;
    }

    result += `| Trusted Domain | Trust Direction | Trust Type | Trust Attributes |\n`;
    result += `|----------------|-----------------|------------|------------------|\n`;

    for (const trust of trusts) {
      const name = trust.attributes?.trustPartner || trust.attributes?.cn || "N/A";
      const direction = trust.attributes?.trustDirection || "Unknown";
      const type = trust.attributes?.trustType || "Unknown";
      const attrs = trust.attributes?.trustAttributes || "N/A";
      result += `| ${name} | ${direction} | ${type} | ${attrs} |\n`;
    }

    return result;
  } catch {
    return `## Domain Trusts\n\nRaw output:\n\`\`\`\n${trustsContent}\n\`\`\``;
  }
}

async function handlePolicies(args: any): Promise<string> {
  const options: LdapDumpOptions = {
    hostname: args.hostname,
    username: args.username,
    password: args.password,
    authType: args.authType,
    outputDir: args.outputDir || DEFAULT_OUTPUT_DIR,
    useSsl: args.useSsl,
    noHtml: true,
    noGrep: true
  };

  await executeOnKali(`mkdir -p ${options.outputDir}`);
  const command = buildCommand(options);
  await executeOnKali(command);

  // Read policy file
  const { stdout: policyContent } = await executeOnKali(`cat ${options.outputDir}/domain_policy.json 2>/dev/null || echo "[]"`);

  try {
    const policies = JSON.parse(policyContent);
    let result = `## Domain Password Policies\n\n`;

    if (!policies || policies.length === 0) {
      result += "*No policy information found.*\n";
      return result;
    }

    for (const policy of policies) {
      const attrs = policy.attributes || {};
      result += `### Policy: ${attrs.cn || attrs.name || "Default"}\n\n`;
      result += `| Setting | Value |\n`;
      result += `|---------|-------|\n`;

      if (attrs.minPwdLength !== undefined) result += `| Minimum Password Length | ${attrs.minPwdLength} |\n`;
      if (attrs.pwdHistoryLength !== undefined) result += `| Password History Length | ${attrs.pwdHistoryLength} |\n`;
      if (attrs.maxPwdAge !== undefined) result += `| Maximum Password Age | ${attrs.maxPwdAge} |\n`;
      if (attrs.minPwdAge !== undefined) result += `| Minimum Password Age | ${attrs.minPwdAge} |\n`;
      if (attrs.lockoutThreshold !== undefined) result += `| Lockout Threshold | ${attrs.lockoutThreshold} |\n`;
      if (attrs.lockoutDuration !== undefined) result += `| Lockout Duration | ${attrs.lockoutDuration} |\n`;
      if (attrs.lockOutObservationWindow !== undefined) result += `| Lockout Observation Window | ${attrs.lockOutObservationWindow} |\n`;
      if (attrs.pwdProperties !== undefined) result += `| Password Properties | ${attrs.pwdProperties} |\n`;

      result += `\n`;
    }

    return result;
  } catch {
    return `## Domain Password Policies\n\nRaw output:\n\`\`\`\n${policyContent}\n\`\`\``;
  }
}

async function handleReadOutput(args: any): Promise<string> {
  const outputDir = args.outputDir || DEFAULT_OUTPUT_DIR;
  const fileType = args.fileType || "json";
  const fileName = args.fileName;

  if (fileName) {
    const { stdout } = await executeOnKali(`cat '${outputDir}/${fileName}'`);
    return `## ${fileName}\n\n\`\`\`\n${stdout}\n\`\`\``;
  }

  let pattern = "*";
  if (fileType === "json") pattern = "*.json";
  else if (fileType === "html") pattern = "*.html";
  else if (fileType === "grep") pattern = "*.grep";

  const files = await readOutputFiles(outputDir, pattern);

  let result = `## ldapdomaindump Output Files\n\n**Directory:** ${outputDir}\n\n`;

  for (const [filename, content] of Object.entries(files)) {
    const preview = content.length > 2000 ? content.substring(0, 2000) + "\n...(truncated)" : content;
    const ext = path.extname(filename).substring(1);
    result += `### ${filename}\n\`\`\`${ext}\n${preview}\n\`\`\`\n\n`;
  }

  if (Object.keys(files).length === 0) {
    result += "*No files found matching the criteria.*";
  }

  return result;
}

async function handleLdd2Pretty(args: any): Promise<string> {
  const outputDir = args.outputDir || DEFAULT_OUTPUT_DIR;

  const command = `cd ${outputDir} && ldd2pretty`;
  const { stdout, stderr } = await executeOnKali(command);

  let result = `## ldapdomaindump Pretty Output\n\n`;
  result += `\`\`\`\n${stdout}\n\`\`\`\n`;

  if (stderr) {
    result += `\n### Errors\n\`\`\`\n${stderr}\n\`\`\``;
  }

  return result;
}

async function handleCheck(): Promise<string> {
  let result = `## ldapdomaindump Status Check\n\n`;

  try {
    // Check SSH connectivity
    const { stdout: sshTest } = await executeOnKali("echo 'SSH OK'");
    result += `**SSH Connection:** ${sshTest.includes("OK") ? "Connected" : "Failed"}\n\n`;

    // Check ldapdomaindump installation
    const { stdout: version } = await executeOnKali("ldapdomaindump --help 2>&1 | head -5");
    result += `**ldapdomaindump Installation:**\n\`\`\`\n${version}\n\`\`\`\n\n`;

    // Check ldd2pretty
    const { stdout: pretty } = await executeOnKali("which ldd2pretty 2>/dev/null || echo 'Not found'");
    result += `**ldd2pretty:** ${pretty.trim()}\n\n`;

    // Check ldd2bloodhound
    const { stdout: bloodhound } = await executeOnKali("which ldd2bloodhound 2>/dev/null || echo 'Not found'");
    result += `**ldd2bloodhound:** ${bloodhound.trim()}\n`;

  } catch (error: any) {
    result += `**Error:** ${error.message}\n`;
    result += `\nMake sure:\n1. SSH key is configured for 'kali' host\n2. ldapdomaindump is installed: pip install ldapdomaindump\n`;
  }

  return result;
}

// Create and run the MCP server
const server = new Server(
  {
    name: "ldapdomaindump-mcp",
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
    let result: string;

    switch (name) {
      case "ldapdomaindump_dump":
        result = await handleDump(args);
        break;
      case "ldapdomaindump_users":
        result = await handleUsers(args);
        break;
      case "ldapdomaindump_groups":
        result = await handleGroups(args);
        break;
      case "ldapdomaindump_computers":
        result = await handleComputers(args);
        break;
      case "ldapdomaindump_trusts":
        result = await handleTrusts(args);
        break;
      case "ldapdomaindump_policies":
        result = await handlePolicies(args);
        break;
      case "ldapdomaindump_read_output":
        result = await handleReadOutput(args);
        break;
      case "ldapdomaindump_ldd2pretty":
        result = await handleLdd2Pretty(args);
        break;
      case "ldapdomaindump_check":
        result = await handleCheck();
        break;
      default:
        throw new Error(`Unknown tool: ${name}`);
    }

    return {
      content: [{ type: "text", text: result }],
    };
  } catch (error: any) {
    return {
      content: [
        {
          type: "text",
          text: `Error executing ${name}: ${error.message}\n\nStack: ${error.stack}`,
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
  console.error("ldapdomaindump MCP server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
