#!/usr/bin/env node
/**
 * CrackMapExec / NetExec MCP Server
 *
 * Provides MCP tools to execute CrackMapExec/NetExec commands via SSH to a Kali Linux host.
 *
 * Supported protocols: SMB, WinRM, SSH, MSSQL, LDAP, RDP, WMI, FTP, VNC, NFS
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { exec as execCallback } from "child_process";
import { promisify } from "util";

const exec = promisify(execCallback);

// Configuration
const KALI_HOST = process.env.KALI_HOST || "kali";
const SSH_USER = process.env.SSH_USER || "";
const SSH_KEY = process.env.SSH_KEY || "";
const NXC_BINARY = process.env.NXC_BINARY || "nxc"; // Can be 'nxc' or 'crackmapexec'

/**
 * Execute a command on the Kali host via SSH
 */
async function executeOnKali(command: string): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  const sshOptions = SSH_KEY ? `-i "${SSH_KEY}"` : "";
  const userPrefix = SSH_USER ? `${SSH_USER}@` : "";
  const sshCommand = `ssh ${sshOptions} ${userPrefix}${KALI_HOST} "${command.replace(/"/g, '\\"')}"`;

  try {
    const { stdout, stderr } = await exec(sshCommand, { maxBuffer: 10 * 1024 * 1024 });
    return { stdout, stderr, exitCode: 0 };
  } catch (error: any) {
    return {
      stdout: error.stdout || "",
      stderr: error.stderr || error.message,
      exitCode: error.code || 1,
    };
  }
}

/**
 * Build netexec command string
 */
function buildNxcCommand(
  protocol: string,
  targets: string,
  options: Record<string, any>
): string {
  const parts = [NXC_BINARY, protocol, targets];

  // Authentication options
  if (options.username) parts.push("-u", `'${options.username}'`);
  if (options.password) parts.push("-p", `'${options.password}'`);
  if (options.hash) parts.push("-H", `'${options.hash}'`);
  if (options.domain) parts.push("-d", `'${options.domain}'`);
  if (options.localAuth) parts.push("--local-auth");
  if (options.kerberosAuth) parts.push("-k");

  // Protocol-specific options
  if (options.port) parts.push("--port", options.port.toString());
  if (options.timeout) parts.push("--timeout", options.timeout.toString());
  if (options.threads) parts.push("-t", options.threads.toString());

  // SMB specific
  if (options.shares) parts.push("--shares");
  if (options.users) parts.push("--users");
  if (options.groups) parts.push("--groups");
  if (options.loggedOnUsers) parts.push("--loggedon-users");
  if (options.sessions) parts.push("--sessions");
  if (options.disks) parts.push("--disks");
  if (options.passPolicy) parts.push("--pass-pol");
  if (options.rid) parts.push("--rid-brute");
  if (options.lsa) parts.push("--lsa");
  if (options.sam) parts.push("--sam");
  if (options.ntds) parts.push("--ntds");
  if (options.sprayValues) parts.push("--spider", `'${options.sprayValues}'`);

  // Command execution
  if (options.execCmd) parts.push("-x", `'${options.execCmd}'`);
  if (options.execPowershell) parts.push("-X", `'${options.execPowershell}'`);
  if (options.execMethod) parts.push("--exec-method", options.execMethod);

  // Module options
  if (options.module) {
    parts.push("-M", options.module);
    if (options.moduleOptions) parts.push("-o", options.moduleOptions);
  }

  // Output options
  if (options.verbose) parts.push("--verbose");
  if (options.debug) parts.push("--debug");
  if (options.noProgress) parts.push("--no-progress");

  // MSSQL specific
  if (options.query) parts.push("-q", `'${options.query}'`);
  if (options.database) parts.push("-d", `'${options.database}'`);

  // LDAP specific
  if (options.usersEnabled) parts.push("--users");
  if (options.computers) parts.push("--computers");
  if (options.dc) parts.push("--dc");
  if (options.trustedForDelegation) parts.push("--trusted-for-delegation");
  if (options.passwordNotReqd) parts.push("--password-not-required");
  if (options.adminCount) parts.push("--admin-count");
  if (options.gmsa) parts.push("--gmsa");
  if (options.ldapQuery) parts.push("--ldap-query", `'${options.ldapQuery}'`);

  // SSH specific
  if (options.keyFile) parts.push("--key-file", `'${options.keyFile}'`);
  if (options.sshTimeout) parts.push("--ssh-timeout", options.sshTimeout.toString());

  // WinRM specific
  if (options.checkProto) parts.push("--check-proto", options.checkProto);
  if (options.httpTimeout) parts.push("--http-timeout", options.httpTimeout.toString());
  if (options.dumpMethod) parts.push("--dump-method", options.dumpMethod);

  return parts.join(" ");
}

// Common Zod schemas for tool inputs
const BaseAuthSchema = z.object({
  targets: z.string().describe("Target IP, hostname, CIDR range, or file path (e.g., '192.168.1.0/24', '192.168.1.1-50', 'targets.txt')"),
  username: z.string().optional().describe("Username or file path to usernames"),
  password: z.string().optional().describe("Password or file path to passwords"),
  hash: z.string().optional().describe("NTLM hash for pass-the-hash (LM:NT or just NT)"),
  domain: z.string().optional().describe("Domain name"),
  localAuth: z.boolean().optional().describe("Use local authentication instead of domain"),
  kerberosAuth: z.boolean().optional().describe("Use Kerberos authentication"),
  threads: z.number().optional().describe("Number of concurrent threads (default: 100)"),
  timeout: z.number().optional().describe("Connection timeout in seconds"),
  verbose: z.boolean().optional().describe("Enable verbose output"),
  debug: z.boolean().optional().describe("Enable debug output"),
});

// Tool definitions
const tools: Tool[] = [
  {
    name: "cme_smb",
    description: "Execute SMB protocol operations with NetExec/CrackMapExec. Supports enumeration of shares, users, groups, sessions, credential dumping (SAM, LSA, NTDS), and command execution.",
    inputSchema: {
      type: "object",
      properties: {
        targets: { type: "string", description: "Target IP, hostname, CIDR range, or file path" },
        username: { type: "string", description: "Username or file path to usernames" },
        password: { type: "string", description: "Password or file path to passwords" },
        hash: { type: "string", description: "NTLM hash for pass-the-hash" },
        domain: { type: "string", description: "Domain name" },
        localAuth: { type: "boolean", description: "Use local authentication" },
        kerberosAuth: { type: "boolean", description: "Use Kerberos authentication" },
        port: { type: "number", description: "SMB port (default: 445)" },
        threads: { type: "number", description: "Concurrent threads" },
        shares: { type: "boolean", description: "Enumerate shares" },
        users: { type: "boolean", description: "Enumerate domain users" },
        groups: { type: "boolean", description: "Enumerate domain groups" },
        loggedOnUsers: { type: "boolean", description: "Enumerate logged on users" },
        sessions: { type: "boolean", description: "Enumerate active sessions" },
        disks: { type: "boolean", description: "Enumerate disks" },
        passPolicy: { type: "boolean", description: "Dump password policy" },
        rid: { type: "boolean", description: "RID brute force enumeration" },
        sam: { type: "boolean", description: "Dump SAM hashes" },
        lsa: { type: "boolean", description: "Dump LSA secrets" },
        ntds: { type: "boolean", description: "Dump NTDS.dit hashes (requires DC)" },
        execCmd: { type: "string", description: "Execute cmd command" },
        execPowershell: { type: "string", description: "Execute PowerShell command" },
        execMethod: { type: "string", description: "Execution method: wmiexec, smbexec, atexec, mmcexec" },
        module: { type: "string", description: "Module to run" },
        moduleOptions: { type: "string", description: "Module options (KEY=VALUE format)" },
        verbose: { type: "boolean", description: "Verbose output" },
        debug: { type: "boolean", description: "Debug output" },
      },
      required: ["targets"],
    },
  },
  {
    name: "cme_winrm",
    description: "Execute WinRM protocol operations. Supports remote command execution and credential dumping on hosts with WinRM enabled (ports 5985/5986).",
    inputSchema: {
      type: "object",
      properties: {
        targets: { type: "string", description: "Target IP, hostname, CIDR range, or file path" },
        username: { type: "string", description: "Username or file path to usernames" },
        password: { type: "string", description: "Password or file path to passwords" },
        hash: { type: "string", description: "NTLM hash for pass-the-hash" },
        domain: { type: "string", description: "Domain name" },
        localAuth: { type: "boolean", description: "Use local authentication" },
        kerberosAuth: { type: "boolean", description: "Use Kerberos authentication" },
        port: { type: "number", description: "WinRM port (5985 HTTP, 5986 HTTPS)" },
        checkProto: { type: "string", description: "Check protocol: http or https" },
        httpTimeout: { type: "number", description: "HTTP timeout in seconds" },
        threads: { type: "number", description: "Concurrent threads" },
        execCmd: { type: "string", description: "Execute cmd command" },
        execPowershell: { type: "string", description: "Execute PowerShell command" },
        sam: { type: "boolean", description: "Dump SAM hashes" },
        lsa: { type: "boolean", description: "Dump LSA secrets" },
        dumpMethod: { type: "string", description: "Dump method: cmd or powershell" },
        module: { type: "string", description: "Module to run" },
        moduleOptions: { type: "string", description: "Module options" },
        verbose: { type: "boolean", description: "Verbose output" },
        debug: { type: "boolean", description: "Debug output" },
      },
      required: ["targets"],
    },
  },
  {
    name: "cme_ssh",
    description: "Execute SSH protocol operations. Supports password and key-based authentication for Linux/Unix hosts.",
    inputSchema: {
      type: "object",
      properties: {
        targets: { type: "string", description: "Target IP, hostname, CIDR range, or file path" },
        username: { type: "string", description: "Username or file path to usernames" },
        password: { type: "string", description: "Password or file path to passwords" },
        port: { type: "number", description: "SSH port (default: 22)" },
        keyFile: { type: "string", description: "Path to SSH private key" },
        sshTimeout: { type: "number", description: "SSH timeout in seconds" },
        threads: { type: "number", description: "Concurrent threads" },
        execCmd: { type: "string", description: "Execute command" },
        module: { type: "string", description: "Module to run" },
        moduleOptions: { type: "string", description: "Module options" },
        verbose: { type: "boolean", description: "Verbose output" },
        debug: { type: "boolean", description: "Debug output" },
      },
      required: ["targets"],
    },
  },
  {
    name: "cme_mssql",
    description: "Execute MSSQL protocol operations. Supports SQL query execution and command execution via xp_cmdshell.",
    inputSchema: {
      type: "object",
      properties: {
        targets: { type: "string", description: "Target IP, hostname, CIDR range, or file path" },
        username: { type: "string", description: "Username or file path to usernames" },
        password: { type: "string", description: "Password or file path to passwords" },
        hash: { type: "string", description: "NTLM hash for pass-the-hash" },
        domain: { type: "string", description: "Domain name" },
        localAuth: { type: "boolean", description: "Use local authentication" },
        port: { type: "number", description: "MSSQL port (default: 1433)" },
        threads: { type: "number", description: "Concurrent threads" },
        query: { type: "string", description: "SQL query to execute" },
        database: { type: "string", description: "Database name" },
        execCmd: { type: "string", description: "Execute OS command via xp_cmdshell" },
        module: { type: "string", description: "Module to run" },
        moduleOptions: { type: "string", description: "Module options" },
        verbose: { type: "boolean", description: "Verbose output" },
        debug: { type: "boolean", description: "Debug output" },
      },
      required: ["targets"],
    },
  },
  {
    name: "cme_ldap",
    description: "Execute LDAP protocol operations. Supports Active Directory enumeration including users, computers, groups, delegation, and custom LDAP queries.",
    inputSchema: {
      type: "object",
      properties: {
        targets: { type: "string", description: "Target Domain Controller IP or hostname" },
        username: { type: "string", description: "Username or file path to usernames" },
        password: { type: "string", description: "Password or file path to passwords" },
        hash: { type: "string", description: "NTLM hash for pass-the-hash" },
        domain: { type: "string", description: "Domain name" },
        kerberosAuth: { type: "boolean", description: "Use Kerberos authentication" },
        port: { type: "number", description: "LDAP port (default: 389, 636 for LDAPS)" },
        threads: { type: "number", description: "Concurrent threads" },
        usersEnabled: { type: "boolean", description: "Enumerate enabled users" },
        computers: { type: "boolean", description: "Enumerate computers" },
        dc: { type: "boolean", description: "Enumerate domain controllers" },
        trustedForDelegation: { type: "boolean", description: "Find accounts trusted for delegation" },
        passwordNotReqd: { type: "boolean", description: "Find accounts with PASSWD_NOTREQD flag" },
        adminCount: { type: "boolean", description: "Find accounts with adminCount=1" },
        gmsa: { type: "boolean", description: "Dump gMSA passwords" },
        ldapQuery: { type: "string", description: "Custom LDAP query" },
        module: { type: "string", description: "Module to run" },
        moduleOptions: { type: "string", description: "Module options" },
        verbose: { type: "boolean", description: "Verbose output" },
        debug: { type: "boolean", description: "Debug output" },
      },
      required: ["targets"],
    },
  },
  {
    name: "cme_rdp",
    description: "Execute RDP protocol operations. Check RDP access and screenshot capabilities.",
    inputSchema: {
      type: "object",
      properties: {
        targets: { type: "string", description: "Target IP, hostname, CIDR range, or file path" },
        username: { type: "string", description: "Username or file path to usernames" },
        password: { type: "string", description: "Password or file path to passwords" },
        hash: { type: "string", description: "NTLM hash for pass-the-hash" },
        domain: { type: "string", description: "Domain name" },
        port: { type: "number", description: "RDP port (default: 3389)" },
        threads: { type: "number", description: "Concurrent threads" },
        module: { type: "string", description: "Module to run" },
        moduleOptions: { type: "string", description: "Module options" },
        verbose: { type: "boolean", description: "Verbose output" },
        debug: { type: "boolean", description: "Debug output" },
      },
      required: ["targets"],
    },
  },
  {
    name: "cme_wmi",
    description: "Execute WMI protocol operations. Supports remote command execution via WMI.",
    inputSchema: {
      type: "object",
      properties: {
        targets: { type: "string", description: "Target IP, hostname, CIDR range, or file path" },
        username: { type: "string", description: "Username or file path to usernames" },
        password: { type: "string", description: "Password or file path to passwords" },
        hash: { type: "string", description: "NTLM hash for pass-the-hash" },
        domain: { type: "string", description: "Domain name" },
        localAuth: { type: "boolean", description: "Use local authentication" },
        threads: { type: "number", description: "Concurrent threads" },
        execCmd: { type: "string", description: "Execute cmd command" },
        execPowershell: { type: "string", description: "Execute PowerShell command" },
        module: { type: "string", description: "Module to run" },
        moduleOptions: { type: "string", description: "Module options" },
        verbose: { type: "boolean", description: "Verbose output" },
        debug: { type: "boolean", description: "Debug output" },
      },
      required: ["targets"],
    },
  },
  {
    name: "cme_modules",
    description: "List available modules for a protocol or get options for a specific module.",
    inputSchema: {
      type: "object",
      properties: {
        protocol: { type: "string", description: "Protocol to list modules for: smb, winrm, ssh, mssql, ldap, rdp, wmi, ftp, vnc, nfs" },
        moduleName: { type: "string", description: "Module name to get options for (optional)" },
      },
      required: ["protocol"],
    },
  },
  {
    name: "cme_spray",
    description: "Perform password spraying attacks across multiple targets. Supports jitter and continues on success options.",
    inputSchema: {
      type: "object",
      properties: {
        protocol: { type: "string", description: "Protocol to use: smb, winrm, ssh, mssql, ldap, rdp" },
        targets: { type: "string", description: "Target IP, hostname, CIDR range, or file path" },
        usernames: { type: "string", description: "Username or file path to usernames" },
        passwords: { type: "string", description: "Password or file path to passwords" },
        domain: { type: "string", description: "Domain name (for AD authentication)" },
        localAuth: { type: "boolean", description: "Use local authentication" },
        threads: { type: "number", description: "Concurrent threads" },
        jitter: { type: "string", description: "Jitter interval (e.g., '0-5' for 0-5 seconds between connections)" },
        continueOnSuccess: { type: "boolean", description: "Continue spraying after a successful login" },
        noProgress: { type: "boolean", description: "Disable progress bar" },
        verbose: { type: "boolean", description: "Verbose output" },
      },
      required: ["protocol", "targets", "usernames", "passwords"],
    },
  },
  {
    name: "cme_creds",
    description: "Manage the NetExec credential database. View, search, and export stored credentials from previous scans.",
    inputSchema: {
      type: "object",
      properties: {
        action: { type: "string", description: "Action: list, search, export, clear" },
        searchTerm: { type: "string", description: "Search term for credentials" },
        exportPath: { type: "string", description: "Path to export credentials" },
      },
      required: ["action"],
    },
  },
  {
    name: "cme_raw",
    description: "Execute a raw NetExec/CrackMapExec command. Use this for advanced operations not covered by other tools.",
    inputSchema: {
      type: "object",
      properties: {
        command: { type: "string", description: "Raw nxc/crackmapexec command (without the 'nxc' or 'crackmapexec' prefix)" },
      },
      required: ["command"],
    },
  },
];

// Create the MCP server
const server = new Server(
  {
    name: "crackmapexec-mcp",
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
    let command: string;
    let result: { stdout: string; stderr: string; exitCode: number };

    switch (name) {
      case "cme_smb":
        command = buildNxcCommand("smb", args?.targets as string, args || {});
        result = await executeOnKali(command);
        break;

      case "cme_winrm":
        command = buildNxcCommand("winrm", args?.targets as string, args || {});
        result = await executeOnKali(command);
        break;

      case "cme_ssh":
        command = buildNxcCommand("ssh", args?.targets as string, args || {});
        result = await executeOnKali(command);
        break;

      case "cme_mssql":
        command = buildNxcCommand("mssql", args?.targets as string, args || {});
        result = await executeOnKali(command);
        break;

      case "cme_ldap":
        command = buildNxcCommand("ldap", args?.targets as string, args || {});
        result = await executeOnKali(command);
        break;

      case "cme_rdp":
        command = buildNxcCommand("rdp", args?.targets as string, args || {});
        result = await executeOnKali(command);
        break;

      case "cme_wmi":
        command = buildNxcCommand("wmi", args?.targets as string, args || {});
        result = await executeOnKali(command);
        break;

      case "cme_modules":
        if (args?.moduleName) {
          command = `${NXC_BINARY} ${args.protocol} -M ${args.moduleName} --options`;
        } else {
          command = `${NXC_BINARY} ${args?.protocol} -L`;
        }
        result = await executeOnKali(command);
        break;

      case "cme_spray": {
        const sprayOpts: Record<string, any> = {
          username: args?.usernames,
          password: args?.passwords,
          domain: args?.domain,
          localAuth: args?.localAuth,
          threads: args?.threads,
          verbose: args?.verbose,
          noProgress: args?.noProgress,
        };
        const jitter = args?.jitter as string | undefined;
        const jitterPart = jitter ? `--jitter ${jitter}` : "";
        const continuePart = args?.continueOnSuccess ? "--continue-on-success" : "";
        command = buildNxcCommand(args?.protocol as string, args?.targets as string, sprayOpts);
        command = `${command} ${jitterPart} ${continuePart}`.trim();
        result = await executeOnKali(command);
        break;
      }

      case "cme_creds": {
        const action = args?.action as string;
        switch (action) {
          case "list":
            command = `${NXC_BINARY}db`;
            break;
          case "search":
            command = `${NXC_BINARY}db -s '${args?.searchTerm}'`;
            break;
          case "export":
            command = `${NXC_BINARY}db --export ${args?.exportPath || 'creds.csv'}`;
            break;
          case "clear":
            command = `${NXC_BINARY}db --clear`;
            break;
          default:
            return {
              content: [{ type: "text", text: `Unknown action: ${action}. Use: list, search, export, clear` }],
              isError: true,
            };
        }
        result = await executeOnKali(command);
        break;
      }

      case "cme_raw":
        command = `${NXC_BINARY} ${args?.command}`;
        result = await executeOnKali(command);
        break;

      default:
        return {
          content: [{ type: "text", text: `Unknown tool: ${name}` }],
          isError: true,
        };
    }

    // Format the output
    const output = [
      `**Command executed:**\n\`\`\`\n${command}\n\`\`\`\n`,
      result.stdout ? `**Output:**\n\`\`\`\n${result.stdout}\n\`\`\`` : "",
      result.stderr ? `**Errors:**\n\`\`\`\n${result.stderr}\n\`\`\`` : "",
      `\n**Exit code:** ${result.exitCode}`,
    ].filter(Boolean).join("\n\n");

    return {
      content: [{ type: "text", text: output }],
      isError: result.exitCode !== 0,
    };

  } catch (error: any) {
    return {
      content: [{ type: "text", text: `Error executing tool: ${error.message}` }],
      isError: true,
    };
  }
});

// Main function
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("CrackMapExec MCP server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
