#!/usr/bin/env node
/**
 * Impacket MCP Server
 *
 * Provides MCP tools for Impacket network protocol tools via SSH to Kali Linux.
 * Supports common pentesting operations: psexec, wmiexec, smbexec, secretsdump,
 * GetNPUsers, GetUserSPNs, smbclient, ntlmrelayx, and more.
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
const KALI_HOST = process.env.KALI_HOST || "kali";
const SSH_OPTIONS = ["-o", "StrictHostKeyChecking=no", "-o", "ConnectTimeout=10"];

/**
 * Execute command on Kali via SSH
 */
async function executeOnKali(command: string, timeout: number = 120000): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  return new Promise((resolve, reject) => {
    const ssh = spawn("ssh", [...SSH_OPTIONS, KALI_HOST, command], {
      timeout,
    });

    let stdout = "";
    let stderr = "";

    ssh.stdout.on("data", (data) => {
      stdout += data.toString();
    });

    ssh.stderr.on("data", (data) => {
      stderr += data.toString();
    });

    ssh.on("close", (code) => {
      resolve({
        stdout,
        stderr,
        exitCode: code ?? 1,
      });
    });

    ssh.on("error", (err) => {
      reject(err);
    });

    // Handle timeout
    setTimeout(() => {
      ssh.kill("SIGTERM");
      reject(new Error(`Command timed out after ${timeout}ms`));
    }, timeout);
  });
}

/**
 * Build authentication string for impacket tools
 */
function buildAuthString(params: {
  domain?: string;
  username: string;
  password?: string;
  hashes?: string;
  aesKey?: string;
  kerberos?: boolean;
  dc_ip?: string;
}): string {
  const { domain, username, password, hashes, aesKey, kerberos } = params;

  let auth = "";

  if (domain) {
    auth = `${domain}/`;
  }

  auth += username;

  if (password) {
    auth += `:${password}`;
  } else if (hashes) {
    auth += ` -hashes ${hashes}`;
  } else if (aesKey) {
    auth += ` -aesKey ${aesKey}`;
  }

  return auth;
}

/**
 * Escape shell arguments
 */
function escapeShellArg(arg: string): string {
  return `'${arg.replace(/'/g, "'\\''")}'`;
}

// Tool definitions
const tools: Tool[] = [
  {
    name: "impacket_psexec",
    description: "Execute commands on remote Windows hosts using PsExec-like functionality via SMB. Uploads a service binary and executes commands through SCM.",
    inputSchema: {
      type: "object" as const,
      properties: {
        target: { type: "string", description: "Target host IP or hostname" },
        username: { type: "string", description: "Username for authentication" },
        password: { type: "string", description: "Password (optional if using hashes)" },
        domain: { type: "string", description: "Domain name (optional)" },
        hashes: { type: "string", description: "NTLM hashes in LMHASH:NTHASH format (optional)" },
        command: { type: "string", description: "Command to execute (optional, defaults to cmd.exe)" },
        dc_ip: { type: "string", description: "Domain Controller IP for Kerberos auth" },
        kerberos: { type: "boolean", description: "Use Kerberos authentication" },
      },
      required: ["target", "username"],
    },
  },
  {
    name: "impacket_wmiexec",
    description: "Execute commands on remote Windows hosts via WMI. Semi-interactive shell without installing any service or agent. Stealthier than psexec.",
    inputSchema: {
      type: "object" as const,
      properties: {
        target: { type: "string", description: "Target host IP or hostname" },
        username: { type: "string", description: "Username for authentication" },
        password: { type: "string", description: "Password (optional if using hashes)" },
        domain: { type: "string", description: "Domain name (optional)" },
        hashes: { type: "string", description: "NTLM hashes in LMHASH:NTHASH format (optional)" },
        command: { type: "string", description: "Command to execute" },
        dc_ip: { type: "string", description: "Domain Controller IP for Kerberos auth" },
        kerberos: { type: "boolean", description: "Use Kerberos authentication" },
        nooutput: { type: "boolean", description: "Do not retrieve command output" },
      },
      required: ["target", "username"],
    },
  },
  {
    name: "impacket_smbexec",
    description: "Execute commands on remote Windows hosts via SMB using a local SMB server for output. Useful when target has no writable share.",
    inputSchema: {
      type: "object" as const,
      properties: {
        target: { type: "string", description: "Target host IP or hostname" },
        username: { type: "string", description: "Username for authentication" },
        password: { type: "string", description: "Password (optional if using hashes)" },
        domain: { type: "string", description: "Domain name (optional)" },
        hashes: { type: "string", description: "NTLM hashes in LMHASH:NTHASH format (optional)" },
        command: { type: "string", description: "Command to execute" },
        dc_ip: { type: "string", description: "Domain Controller IP for Kerberos auth" },
        kerberos: { type: "boolean", description: "Use Kerberos authentication" },
        share: { type: "string", description: "Share to use (default: ADMIN$)" },
      },
      required: ["target", "username"],
    },
  },
  {
    name: "impacket_dcomexec",
    description: "Execute commands on remote Windows hosts via DCOM (MMC20.Application, ShellWindows, ShellBrowserWindow). Alternative execution method.",
    inputSchema: {
      type: "object" as const,
      properties: {
        target: { type: "string", description: "Target host IP or hostname" },
        username: { type: "string", description: "Username for authentication" },
        password: { type: "string", description: "Password (optional if using hashes)" },
        domain: { type: "string", description: "Domain name (optional)" },
        hashes: { type: "string", description: "NTLM hashes in LMHASH:NTHASH format (optional)" },
        command: { type: "string", description: "Command to execute" },
        object: { type: "string", description: "DCOM object (MMC20, ShellWindows, ShellBrowserWindow)" },
        dc_ip: { type: "string", description: "Domain Controller IP for Kerberos auth" },
      },
      required: ["target", "username"],
    },
  },
  {
    name: "impacket_atexec",
    description: "Execute commands on remote Windows hosts via Task Scheduler (AT). Creates a scheduled task for command execution.",
    inputSchema: {
      type: "object" as const,
      properties: {
        target: { type: "string", description: "Target host IP or hostname" },
        username: { type: "string", description: "Username for authentication" },
        password: { type: "string", description: "Password (optional if using hashes)" },
        domain: { type: "string", description: "Domain name (optional)" },
        hashes: { type: "string", description: "NTLM hashes in LMHASH:NTHASH format (optional)" },
        command: { type: "string", description: "Command to execute" },
        dc_ip: { type: "string", description: "Domain Controller IP for Kerberos auth" },
      },
      required: ["target", "username", "command"],
    },
  },
  {
    name: "impacket_secretsdump",
    description: "Dump secrets from remote Windows hosts including SAM hashes, LSA secrets, cached credentials, and NTDS.dit. No agent required on target.",
    inputSchema: {
      type: "object" as const,
      properties: {
        target: { type: "string", description: "Target host IP or hostname" },
        username: { type: "string", description: "Username for authentication" },
        password: { type: "string", description: "Password (optional if using hashes)" },
        domain: { type: "string", description: "Domain name (optional)" },
        hashes: { type: "string", description: "NTLM hashes in LMHASH:NTHASH format (optional)" },
        dc_ip: { type: "string", description: "Domain Controller IP for Kerberos auth" },
        kerberos: { type: "boolean", description: "Use Kerberos authentication" },
        just_dc: { type: "boolean", description: "Extract only NTDS.DIT data (DRSUAPI)" },
        just_dc_ntlm: { type: "boolean", description: "Extract only NTDS.DIT NTLM hashes" },
        just_dc_user: { type: "string", description: "Extract only this user from NTDS.DIT" },
        sam: { type: "boolean", description: "Dump local SAM database" },
        lsa: { type: "boolean", description: "Dump LSA secrets" },
        ntds: { type: "string", description: "Path to NTDS.DIT file for offline extraction" },
        system: { type: "string", description: "Path to SYSTEM hive for offline extraction" },
        outputfile: { type: "string", description: "Output file path for results" },
      },
      required: ["target", "username"],
    },
  },
  {
    name: "impacket_getnpusers",
    description: "AS-REP Roasting: Find users with 'Do not require Kerberos preauthentication' set and get their TGTs for offline cracking.",
    inputSchema: {
      type: "object" as const,
      properties: {
        target: { type: "string", description: "Domain/DC to query" },
        username: { type: "string", description: "Username for authentication (optional for unauthenticated)" },
        password: { type: "string", description: "Password (optional)" },
        hashes: { type: "string", description: "NTLM hashes in LMHASH:NTHASH format (optional)" },
        dc_ip: { type: "string", description: "Domain Controller IP" },
        usersfile: { type: "string", description: "File with usernames to check (one per line)" },
        format: { type: "string", description: "Output format: hashcat or john (default: hashcat)" },
        outputfile: { type: "string", description: "Output file for hashes" },
        no_pass: { type: "boolean", description: "No password for unauthenticated enumeration" },
        request: { type: "boolean", description: "Request TGT for users found" },
      },
      required: ["target"],
    },
  },
  {
    name: "impacket_getuserspns",
    description: "Kerberoasting: Find Service Principal Names (SPNs) associated with user accounts and request their TGS tickets for offline cracking.",
    inputSchema: {
      type: "object" as const,
      properties: {
        target: { type: "string", description: "Domain/DC to query" },
        username: { type: "string", description: "Username for authentication" },
        password: { type: "string", description: "Password (optional if using hashes)" },
        domain: { type: "string", description: "Domain name" },
        hashes: { type: "string", description: "NTLM hashes in LMHASH:NTHASH format (optional)" },
        dc_ip: { type: "string", description: "Domain Controller IP" },
        format: { type: "string", description: "Output format: hashcat or john (default: hashcat)" },
        outputfile: { type: "string", description: "Output file for hashes" },
        request: { type: "boolean", description: "Request TGS for users found" },
        request_user: { type: "string", description: "Request TGS for specific user" },
      },
      required: ["target", "username"],
    },
  },
  {
    name: "impacket_smbclient",
    description: "SMB client for file operations: list shares, browse directories, upload/download files, and more.",
    inputSchema: {
      type: "object" as const,
      properties: {
        target: { type: "string", description: "Target host IP or hostname" },
        username: { type: "string", description: "Username for authentication" },
        password: { type: "string", description: "Password (optional if using hashes)" },
        domain: { type: "string", description: "Domain name (optional)" },
        hashes: { type: "string", description: "NTLM hashes in LMHASH:NTHASH format (optional)" },
        dc_ip: { type: "string", description: "Domain Controller IP for Kerberos auth" },
        kerberos: { type: "boolean", description: "Use Kerberos authentication" },
        command: { type: "string", description: "SMB command to execute (shares, use, ls, get, put, etc.)" },
      },
      required: ["target", "username"],
    },
  },
  {
    name: "impacket_ntlmrelayx",
    description: "NTLM relay attack: Set up SMB/HTTP server to capture and relay NTLM credentials to target protocols (SMB, LDAP, HTTP, MSSQL, etc.).",
    inputSchema: {
      type: "object" as const,
      properties: {
        targets: { type: "string", description: "Target(s) to relay to (IP, hostname, or file with -tf)" },
        smb_port: { type: "number", description: "SMB server port (default: 445)" },
        http_port: { type: "number", description: "HTTP server port (default: 80)" },
        socks: { type: "boolean", description: "Enable SOCKS proxy mode" },
        interactive: { type: "boolean", description: "Start interactive mode" },
        command: { type: "string", description: "Command to execute on successful relay" },
        lootdir: { type: "string", description: "Directory to store loot" },
        delegate_access: { type: "boolean", description: "Delegate access for RBCD attack" },
        escalate_user: { type: "string", description: "User to escalate via RBCD" },
        add_computer: { type: "string", description: "Add computer account on successful relay" },
        dump_domain: { type: "boolean", description: "Dump domain info via LDAP" },
        dump_laps: { type: "boolean", description: "Dump LAPS passwords via LDAP" },
      },
      required: ["targets"],
    },
  },
  {
    name: "impacket_getadusers",
    description: "Query Active Directory for user information including last logon, password last set, and account status.",
    inputSchema: {
      type: "object" as const,
      properties: {
        target: { type: "string", description: "Domain/DC to query" },
        username: { type: "string", description: "Username for authentication" },
        password: { type: "string", description: "Password (optional if using hashes)" },
        domain: { type: "string", description: "Domain name" },
        hashes: { type: "string", description: "NTLM hashes in LMHASH:NTHASH format (optional)" },
        dc_ip: { type: "string", description: "Domain Controller IP" },
        all: { type: "boolean", description: "Return all users" },
        user: { type: "string", description: "Query specific user" },
      },
      required: ["target", "username"],
    },
  },
  {
    name: "impacket_getadcomputers",
    description: "Query Active Directory for computer information including operating system, last logon, and DNS hostname.",
    inputSchema: {
      type: "object" as const,
      properties: {
        target: { type: "string", description: "Domain/DC to query" },
        username: { type: "string", description: "Username for authentication" },
        password: { type: "string", description: "Password (optional if using hashes)" },
        domain: { type: "string", description: "Domain name" },
        hashes: { type: "string", description: "NTLM hashes in LMHASH:NTHASH format (optional)" },
        dc_ip: { type: "string", description: "Domain Controller IP" },
        all: { type: "boolean", description: "Return all computers" },
        computer: { type: "string", description: "Query specific computer" },
      },
      required: ["target", "username"],
    },
  },
  {
    name: "impacket_lookupsid",
    description: "Enumerate domain users and groups by bruteforcing SIDs. Useful for initial reconnaissance.",
    inputSchema: {
      type: "object" as const,
      properties: {
        target: { type: "string", description: "Target host IP or hostname" },
        username: { type: "string", description: "Username for authentication" },
        password: { type: "string", description: "Password (optional if using hashes)" },
        domain: { type: "string", description: "Domain name (optional)" },
        hashes: { type: "string", description: "NTLM hashes in LMHASH:NTHASH format (optional)" },
        dc_ip: { type: "string", description: "Domain Controller IP" },
        domain_sids: { type: "boolean", description: "Enumerate Domain SIDs only" },
        max_rid: { type: "number", description: "Maximum RID to enumerate (default: 4000)" },
      },
      required: ["target", "username"],
    },
  },
  {
    name: "impacket_gettgt",
    description: "Request a Kerberos TGT (Ticket Granting Ticket) for a user. Useful for pass-the-ticket attacks.",
    inputSchema: {
      type: "object" as const,
      properties: {
        target: { type: "string", description: "Domain/username format: DOMAIN/username" },
        password: { type: "string", description: "Password (optional if using hashes)" },
        hashes: { type: "string", description: "NTLM hashes in LMHASH:NTHASH format (optional)" },
        aesKey: { type: "string", description: "AES key for authentication" },
        dc_ip: { type: "string", description: "Domain Controller IP" },
      },
      required: ["target"],
    },
  },
  {
    name: "impacket_getst",
    description: "Request a Kerberos Service Ticket (TGS) for a specific SPN. Used for service ticket attacks.",
    inputSchema: {
      type: "object" as const,
      properties: {
        target: { type: "string", description: "Domain/username format: DOMAIN/username" },
        spn: { type: "string", description: "Service Principal Name to request" },
        password: { type: "string", description: "Password (optional if using hashes)" },
        hashes: { type: "string", description: "NTLM hashes in LMHASH:NTHASH format (optional)" },
        aesKey: { type: "string", description: "AES key for authentication" },
        dc_ip: { type: "string", description: "Domain Controller IP" },
        impersonate: { type: "string", description: "User to impersonate via S4U" },
      },
      required: ["target", "spn"],
    },
  },
  {
    name: "impacket_ticketer",
    description: "Create Golden/Silver Kerberos tickets from scratch or based on a template.",
    inputSchema: {
      type: "object" as const,
      properties: {
        domain: { type: "string", description: "Domain name" },
        domain_sid: { type: "string", description: "Domain SID" },
        nthash: { type: "string", description: "NT hash of krbtgt (golden) or service (silver)" },
        aesKey: { type: "string", description: "AES key of krbtgt or service" },
        user: { type: "string", description: "Username for the ticket" },
        user_id: { type: "number", description: "User RID (default: 500)" },
        groups: { type: "string", description: "Group RIDs to include" },
        spn: { type: "string", description: "SPN for silver ticket" },
        duration: { type: "number", description: "Ticket duration in hours" },
      },
      required: ["domain", "domain_sid", "user"],
    },
  },
  {
    name: "impacket_finddelegation",
    description: "Find delegation relationships in Active Directory (unconstrained, constrained, RBCD).",
    inputSchema: {
      type: "object" as const,
      properties: {
        target: { type: "string", description: "Domain/DC to query" },
        username: { type: "string", description: "Username for authentication" },
        password: { type: "string", description: "Password (optional if using hashes)" },
        domain: { type: "string", description: "Domain name" },
        hashes: { type: "string", description: "NTLM hashes in LMHASH:NTHASH format (optional)" },
        dc_ip: { type: "string", description: "Domain Controller IP" },
      },
      required: ["target", "username"],
    },
  },
  {
    name: "impacket_addcomputer",
    description: "Add a computer account to the domain using LDAP or SAMR. Useful for RBCD attacks.",
    inputSchema: {
      type: "object" as const,
      properties: {
        target: { type: "string", description: "Domain/DC to target" },
        username: { type: "string", description: "Username for authentication" },
        password: { type: "string", description: "Password (optional if using hashes)" },
        domain: { type: "string", description: "Domain name" },
        hashes: { type: "string", description: "NTLM hashes in LMHASH:NTHASH format (optional)" },
        dc_ip: { type: "string", description: "Domain Controller IP" },
        computer_name: { type: "string", description: "Name for the new computer" },
        computer_pass: { type: "string", description: "Password for the new computer" },
        method: { type: "string", description: "Method: LDAPS or SAMR" },
      },
      required: ["target", "username", "computer_name"],
    },
  },
  {
    name: "impacket_rbcd",
    description: "Configure Resource-Based Constrained Delegation (RBCD) on a target computer.",
    inputSchema: {
      type: "object" as const,
      properties: {
        target: { type: "string", description: "Domain/DC to target" },
        username: { type: "string", description: "Username for authentication" },
        password: { type: "string", description: "Password (optional if using hashes)" },
        domain: { type: "string", description: "Domain name" },
        hashes: { type: "string", description: "NTLM hashes in LMHASH:NTHASH format (optional)" },
        dc_ip: { type: "string", description: "Domain Controller IP" },
        delegate_to: { type: "string", description: "Computer to configure RBCD on" },
        delegate_from: { type: "string", description: "Computer/user to allow delegation from" },
        action: { type: "string", description: "Action: write, read, remove, flush" },
      },
      required: ["target", "username", "delegate_to"],
    },
  },
  {
    name: "impacket_dpapi",
    description: "Decrypt DPAPI-protected secrets (credentials, vault, etc.) using masterkeys or domain backup key.",
    inputSchema: {
      type: "object" as const,
      properties: {
        target: { type: "string", description: "Target host or path to DPAPI blob" },
        username: { type: "string", description: "Username (optional)" },
        password: { type: "string", description: "User password (optional)" },
        pvk: { type: "string", description: "Path to domain backup key PVK file" },
        masterkey: { type: "string", description: "Path to masterkey file" },
        sid: { type: "string", description: "User SID for masterkey decryption" },
        file: { type: "string", description: "DPAPI blob file to decrypt" },
      },
      required: ["target"],
    },
  },
  {
    name: "impacket_mssqlclient",
    description: "MSSQL client for database operations including xp_cmdshell command execution.",
    inputSchema: {
      type: "object" as const,
      properties: {
        target: { type: "string", description: "Target MSSQL server IP or hostname" },
        username: { type: "string", description: "Username for authentication" },
        password: { type: "string", description: "Password (optional if using hashes)" },
        domain: { type: "string", description: "Domain name (optional)" },
        hashes: { type: "string", description: "NTLM hashes in LMHASH:NTHASH format (optional)" },
        port: { type: "number", description: "MSSQL port (default: 1433)" },
        windows_auth: { type: "boolean", description: "Use Windows authentication" },
        query: { type: "string", description: "SQL query to execute" },
      },
      required: ["target", "username"],
    },
  },
  {
    name: "impacket_reg",
    description: "Remote registry operations via SMB. Query, add, delete registry keys and values.",
    inputSchema: {
      type: "object" as const,
      properties: {
        target: { type: "string", description: "Target host IP or hostname" },
        username: { type: "string", description: "Username for authentication" },
        password: { type: "string", description: "Password (optional if using hashes)" },
        domain: { type: "string", description: "Domain name (optional)" },
        hashes: { type: "string", description: "NTLM hashes in LMHASH:NTHASH format (optional)" },
        dc_ip: { type: "string", description: "Domain Controller IP for Kerberos auth" },
        action: { type: "string", description: "Action: query, add, delete" },
        keyName: { type: "string", description: "Registry key path" },
        valueName: { type: "string", description: "Registry value name" },
        valueData: { type: "string", description: "Data for add operation" },
        valueType: { type: "string", description: "Value type: REG_SZ, REG_DWORD, etc." },
      },
      required: ["target", "username", "action", "keyName"],
    },
  },
  {
    name: "impacket_services",
    description: "Remote service management via SMB. Start, stop, create, delete services.",
    inputSchema: {
      type: "object" as const,
      properties: {
        target: { type: "string", description: "Target host IP or hostname" },
        username: { type: "string", description: "Username for authentication" },
        password: { type: "string", description: "Password (optional if using hashes)" },
        domain: { type: "string", description: "Domain name (optional)" },
        hashes: { type: "string", description: "NTLM hashes in LMHASH:NTHASH format (optional)" },
        dc_ip: { type: "string", description: "Domain Controller IP for Kerberos auth" },
        action: { type: "string", description: "Action: list, start, stop, create, delete, config" },
        service_name: { type: "string", description: "Service name for operations" },
        display_name: { type: "string", description: "Display name for create" },
        binary_path: { type: "string", description: "Binary path for create" },
      },
      required: ["target", "username", "action"],
    },
  },
  {
    name: "impacket_getlapspassword",
    description: "Retrieve LAPS (Local Administrator Password Solution) passwords from Active Directory.",
    inputSchema: {
      type: "object" as const,
      properties: {
        target: { type: "string", description: "Domain/DC to query" },
        username: { type: "string", description: "Username for authentication" },
        password: { type: "string", description: "Password (optional if using hashes)" },
        domain: { type: "string", description: "Domain name" },
        hashes: { type: "string", description: "NTLM hashes in LMHASH:NTHASH format (optional)" },
        dc_ip: { type: "string", description: "Domain Controller IP" },
        computer: { type: "string", description: "Specific computer to query (optional)" },
      },
      required: ["target", "username"],
    },
  },
];

// Tool execution handlers
async function handleToolCall(name: string, args: Record<string, unknown>): Promise<string> {
  let cmd = "";

  switch (name) {
    case "impacket_psexec": {
      const auth = buildAuthString({
        domain: args.domain as string,
        username: args.username as string,
        password: args.password as string,
        hashes: args.hashes as string,
      });
      cmd = `impacket-psexec ${escapeShellArg(auth)}@${escapeShellArg(args.target as string)}`;
      if (args.hashes) cmd += ` -hashes ${escapeShellArg(args.hashes as string)}`;
      if (args.dc_ip) cmd += ` -dc-ip ${escapeShellArg(args.dc_ip as string)}`;
      if (args.kerberos) cmd += " -k";
      if (args.command) cmd += ` ${escapeShellArg(args.command as string)}`;
      break;
    }

    case "impacket_wmiexec": {
      const auth = buildAuthString({
        domain: args.domain as string,
        username: args.username as string,
        password: args.password as string,
        hashes: args.hashes as string,
      });
      cmd = `impacket-wmiexec ${escapeShellArg(auth)}@${escapeShellArg(args.target as string)}`;
      if (args.hashes) cmd += ` -hashes ${escapeShellArg(args.hashes as string)}`;
      if (args.dc_ip) cmd += ` -dc-ip ${escapeShellArg(args.dc_ip as string)}`;
      if (args.kerberos) cmd += " -k";
      if (args.nooutput) cmd += " -nooutput";
      if (args.command) cmd += ` ${escapeShellArg(args.command as string)}`;
      break;
    }

    case "impacket_smbexec": {
      const auth = buildAuthString({
        domain: args.domain as string,
        username: args.username as string,
        password: args.password as string,
        hashes: args.hashes as string,
      });
      cmd = `impacket-smbexec ${escapeShellArg(auth)}@${escapeShellArg(args.target as string)}`;
      if (args.hashes) cmd += ` -hashes ${escapeShellArg(args.hashes as string)}`;
      if (args.dc_ip) cmd += ` -dc-ip ${escapeShellArg(args.dc_ip as string)}`;
      if (args.kerberos) cmd += " -k";
      if (args.share) cmd += ` -share ${escapeShellArg(args.share as string)}`;
      if (args.command) cmd += ` ${escapeShellArg(args.command as string)}`;
      break;
    }

    case "impacket_dcomexec": {
      const auth = buildAuthString({
        domain: args.domain as string,
        username: args.username as string,
        password: args.password as string,
        hashes: args.hashes as string,
      });
      cmd = `impacket-dcomexec ${escapeShellArg(auth)}@${escapeShellArg(args.target as string)}`;
      if (args.hashes) cmd += ` -hashes ${escapeShellArg(args.hashes as string)}`;
      if (args.dc_ip) cmd += ` -dc-ip ${escapeShellArg(args.dc_ip as string)}`;
      if (args.object) cmd += ` -object ${escapeShellArg(args.object as string)}`;
      if (args.command) cmd += ` ${escapeShellArg(args.command as string)}`;
      break;
    }

    case "impacket_atexec": {
      const auth = buildAuthString({
        domain: args.domain as string,
        username: args.username as string,
        password: args.password as string,
        hashes: args.hashes as string,
      });
      cmd = `impacket-atexec ${escapeShellArg(auth)}@${escapeShellArg(args.target as string)}`;
      if (args.hashes) cmd += ` -hashes ${escapeShellArg(args.hashes as string)}`;
      if (args.dc_ip) cmd += ` -dc-ip ${escapeShellArg(args.dc_ip as string)}`;
      cmd += ` ${escapeShellArg(args.command as string)}`;
      break;
    }

    case "impacket_secretsdump": {
      const auth = buildAuthString({
        domain: args.domain as string,
        username: args.username as string,
        password: args.password as string,
        hashes: args.hashes as string,
      });
      cmd = `impacket-secretsdump ${escapeShellArg(auth)}@${escapeShellArg(args.target as string)}`;
      if (args.hashes) cmd += ` -hashes ${escapeShellArg(args.hashes as string)}`;
      if (args.dc_ip) cmd += ` -dc-ip ${escapeShellArg(args.dc_ip as string)}`;
      if (args.kerberos) cmd += " -k";
      if (args.just_dc) cmd += " -just-dc";
      if (args.just_dc_ntlm) cmd += " -just-dc-ntlm";
      if (args.just_dc_user) cmd += ` -just-dc-user ${escapeShellArg(args.just_dc_user as string)}`;
      if (args.sam) cmd += " -sam";
      if (args.lsa) cmd += " -lsa";
      if (args.ntds) cmd += ` -ntds ${escapeShellArg(args.ntds as string)}`;
      if (args.system) cmd += ` -system ${escapeShellArg(args.system as string)}`;
      if (args.outputfile) cmd += ` -outputfile ${escapeShellArg(args.outputfile as string)}`;
      break;
    }

    case "impacket_getnpusers": {
      cmd = `impacket-GetNPUsers ${escapeShellArg(args.target as string)}`;
      if (args.username) cmd += `/${escapeShellArg(args.username as string)}`;
      if (args.password) cmd += `:${escapeShellArg(args.password as string)}`;
      if (args.hashes) cmd += ` -hashes ${escapeShellArg(args.hashes as string)}`;
      if (args.dc_ip) cmd += ` -dc-ip ${escapeShellArg(args.dc_ip as string)}`;
      if (args.usersfile) cmd += ` -usersfile ${escapeShellArg(args.usersfile as string)}`;
      if (args.format) cmd += ` -format ${escapeShellArg(args.format as string)}`;
      if (args.outputfile) cmd += ` -outputfile ${escapeShellArg(args.outputfile as string)}`;
      if (args.no_pass) cmd += " -no-pass";
      if (args.request) cmd += " -request";
      break;
    }

    case "impacket_getuserspns": {
      const auth = buildAuthString({
        domain: args.domain as string,
        username: args.username as string,
        password: args.password as string,
        hashes: args.hashes as string,
      });
      cmd = `impacket-GetUserSPNs ${escapeShellArg(args.target as string)}/${escapeShellArg(auth)}`;
      if (args.hashes) cmd += ` -hashes ${escapeShellArg(args.hashes as string)}`;
      if (args.dc_ip) cmd += ` -dc-ip ${escapeShellArg(args.dc_ip as string)}`;
      if (args.format) cmd += ` -outputfile ${escapeShellArg(args.format as string)}`;
      if (args.outputfile) cmd += ` -outputfile ${escapeShellArg(args.outputfile as string)}`;
      if (args.request) cmd += " -request";
      if (args.request_user) cmd += ` -request-user ${escapeShellArg(args.request_user as string)}`;
      break;
    }

    case "impacket_smbclient": {
      const auth = buildAuthString({
        domain: args.domain as string,
        username: args.username as string,
        password: args.password as string,
        hashes: args.hashes as string,
      });
      cmd = `impacket-smbclient ${escapeShellArg(auth)}@${escapeShellArg(args.target as string)}`;
      if (args.hashes) cmd += ` -hashes ${escapeShellArg(args.hashes as string)}`;
      if (args.dc_ip) cmd += ` -dc-ip ${escapeShellArg(args.dc_ip as string)}`;
      if (args.kerberos) cmd += " -k";
      if (args.command) cmd += ` -c ${escapeShellArg(args.command as string)}`;
      break;
    }

    case "impacket_ntlmrelayx": {
      cmd = `impacket-ntlmrelayx -t ${escapeShellArg(args.targets as string)}`;
      if (args.smb_port) cmd += ` -smb2support --smb-port ${args.smb_port}`;
      if (args.http_port) cmd += ` --http-port ${args.http_port}`;
      if (args.socks) cmd += " -socks";
      if (args.interactive) cmd += " -i";
      if (args.command) cmd += ` -c ${escapeShellArg(args.command as string)}`;
      if (args.lootdir) cmd += ` -l ${escapeShellArg(args.lootdir as string)}`;
      if (args.delegate_access) cmd += " --delegate-access";
      if (args.escalate_user) cmd += ` --escalate-user ${escapeShellArg(args.escalate_user as string)}`;
      if (args.add_computer) cmd += ` --add-computer ${escapeShellArg(args.add_computer as string)}`;
      if (args.dump_domain) cmd += " --dump-domain";
      if (args.dump_laps) cmd += " --dump-laps";
      break;
    }

    case "impacket_getadusers": {
      const auth = buildAuthString({
        domain: args.domain as string,
        username: args.username as string,
        password: args.password as string,
        hashes: args.hashes as string,
      });
      cmd = `impacket-GetADUsers ${escapeShellArg(args.target as string)}/${escapeShellArg(auth)}`;
      if (args.hashes) cmd += ` -hashes ${escapeShellArg(args.hashes as string)}`;
      if (args.dc_ip) cmd += ` -dc-ip ${escapeShellArg(args.dc_ip as string)}`;
      if (args.all) cmd += " -all";
      if (args.user) cmd += ` -user ${escapeShellArg(args.user as string)}`;
      break;
    }

    case "impacket_getadcomputers": {
      const auth = buildAuthString({
        domain: args.domain as string,
        username: args.username as string,
        password: args.password as string,
        hashes: args.hashes as string,
      });
      cmd = `impacket-GetADComputers ${escapeShellArg(args.target as string)}/${escapeShellArg(auth)}`;
      if (args.hashes) cmd += ` -hashes ${escapeShellArg(args.hashes as string)}`;
      if (args.dc_ip) cmd += ` -dc-ip ${escapeShellArg(args.dc_ip as string)}`;
      if (args.all) cmd += " -all";
      if (args.computer) cmd += ` -computer ${escapeShellArg(args.computer as string)}`;
      break;
    }

    case "impacket_lookupsid": {
      const auth = buildAuthString({
        domain: args.domain as string,
        username: args.username as string,
        password: args.password as string,
        hashes: args.hashes as string,
      });
      cmd = `impacket-lookupsid ${escapeShellArg(auth)}@${escapeShellArg(args.target as string)}`;
      if (args.hashes) cmd += ` -hashes ${escapeShellArg(args.hashes as string)}`;
      if (args.dc_ip) cmd += ` -dc-ip ${escapeShellArg(args.dc_ip as string)}`;
      if (args.domain_sids) cmd += " -domain-sids";
      if (args.max_rid) cmd += ` -max-rid ${args.max_rid}`;
      break;
    }

    case "impacket_gettgt": {
      cmd = `impacket-getTGT ${escapeShellArg(args.target as string)}`;
      if (args.password) cmd += `:${escapeShellArg(args.password as string)}`;
      if (args.hashes) cmd += ` -hashes ${escapeShellArg(args.hashes as string)}`;
      if (args.aesKey) cmd += ` -aesKey ${escapeShellArg(args.aesKey as string)}`;
      if (args.dc_ip) cmd += ` -dc-ip ${escapeShellArg(args.dc_ip as string)}`;
      break;
    }

    case "impacket_getst": {
      cmd = `impacket-getST ${escapeShellArg(args.target as string)}`;
      if (args.password) cmd += `:${escapeShellArg(args.password as string)}`;
      cmd += ` -spn ${escapeShellArg(args.spn as string)}`;
      if (args.hashes) cmd += ` -hashes ${escapeShellArg(args.hashes as string)}`;
      if (args.aesKey) cmd += ` -aesKey ${escapeShellArg(args.aesKey as string)}`;
      if (args.dc_ip) cmd += ` -dc-ip ${escapeShellArg(args.dc_ip as string)}`;
      if (args.impersonate) cmd += ` -impersonate ${escapeShellArg(args.impersonate as string)}`;
      break;
    }

    case "impacket_ticketer": {
      cmd = `impacket-ticketer -domain ${escapeShellArg(args.domain as string)}`;
      cmd += ` -domain-sid ${escapeShellArg(args.domain_sid as string)}`;
      cmd += ` ${escapeShellArg(args.user as string)}`;
      if (args.nthash) cmd += ` -nthash ${escapeShellArg(args.nthash as string)}`;
      if (args.aesKey) cmd += ` -aesKey ${escapeShellArg(args.aesKey as string)}`;
      if (args.user_id) cmd += ` -user-id ${args.user_id}`;
      if (args.groups) cmd += ` -groups ${escapeShellArg(args.groups as string)}`;
      if (args.spn) cmd += ` -spn ${escapeShellArg(args.spn as string)}`;
      if (args.duration) cmd += ` -duration ${args.duration}`;
      break;
    }

    case "impacket_finddelegation": {
      const auth = buildAuthString({
        domain: args.domain as string,
        username: args.username as string,
        password: args.password as string,
        hashes: args.hashes as string,
      });
      cmd = `impacket-findDelegation ${escapeShellArg(args.target as string)}/${escapeShellArg(auth)}`;
      if (args.hashes) cmd += ` -hashes ${escapeShellArg(args.hashes as string)}`;
      if (args.dc_ip) cmd += ` -dc-ip ${escapeShellArg(args.dc_ip as string)}`;
      break;
    }

    case "impacket_addcomputer": {
      const auth = buildAuthString({
        domain: args.domain as string,
        username: args.username as string,
        password: args.password as string,
        hashes: args.hashes as string,
      });
      cmd = `impacket-addcomputer ${escapeShellArg(args.target as string)}/${escapeShellArg(auth)}`;
      cmd += ` -computer-name ${escapeShellArg(args.computer_name as string)}`;
      if (args.computer_pass) cmd += ` -computer-pass ${escapeShellArg(args.computer_pass as string)}`;
      if (args.hashes) cmd += ` -hashes ${escapeShellArg(args.hashes as string)}`;
      if (args.dc_ip) cmd += ` -dc-ip ${escapeShellArg(args.dc_ip as string)}`;
      if (args.method) cmd += ` -method ${escapeShellArg(args.method as string)}`;
      break;
    }

    case "impacket_rbcd": {
      const auth = buildAuthString({
        domain: args.domain as string,
        username: args.username as string,
        password: args.password as string,
        hashes: args.hashes as string,
      });
      cmd = `impacket-rbcd ${escapeShellArg(args.target as string)}/${escapeShellArg(auth)}`;
      cmd += ` -delegate-to ${escapeShellArg(args.delegate_to as string)}`;
      if (args.delegate_from) cmd += ` -delegate-from ${escapeShellArg(args.delegate_from as string)}`;
      if (args.action) cmd += ` -action ${escapeShellArg(args.action as string)}`;
      if (args.hashes) cmd += ` -hashes ${escapeShellArg(args.hashes as string)}`;
      if (args.dc_ip) cmd += ` -dc-ip ${escapeShellArg(args.dc_ip as string)}`;
      break;
    }

    case "impacket_dpapi": {
      cmd = `impacket-dpapi ${escapeShellArg(args.target as string)}`;
      if (args.username) cmd += ` -username ${escapeShellArg(args.username as string)}`;
      if (args.password) cmd += ` -password ${escapeShellArg(args.password as string)}`;
      if (args.pvk) cmd += ` -pvk ${escapeShellArg(args.pvk as string)}`;
      if (args.masterkey) cmd += ` -masterkey ${escapeShellArg(args.masterkey as string)}`;
      if (args.sid) cmd += ` -sid ${escapeShellArg(args.sid as string)}`;
      if (args.file) cmd += ` -file ${escapeShellArg(args.file as string)}`;
      break;
    }

    case "impacket_mssqlclient": {
      const auth = buildAuthString({
        domain: args.domain as string,
        username: args.username as string,
        password: args.password as string,
        hashes: args.hashes as string,
      });
      cmd = `impacket-mssqlclient ${escapeShellArg(auth)}@${escapeShellArg(args.target as string)}`;
      if (args.hashes) cmd += ` -hashes ${escapeShellArg(args.hashes as string)}`;
      if (args.port) cmd += ` -port ${args.port}`;
      if (args.windows_auth) cmd += " -windows-auth";
      if (args.query) cmd += ` -Q ${escapeShellArg(args.query as string)}`;
      break;
    }

    case "impacket_reg": {
      const auth = buildAuthString({
        domain: args.domain as string,
        username: args.username as string,
        password: args.password as string,
        hashes: args.hashes as string,
      });
      cmd = `impacket-reg ${escapeShellArg(auth)}@${escapeShellArg(args.target as string)}`;
      if (args.hashes) cmd += ` -hashes ${escapeShellArg(args.hashes as string)}`;
      if (args.dc_ip) cmd += ` -dc-ip ${escapeShellArg(args.dc_ip as string)}`;
      cmd += ` ${escapeShellArg(args.action as string)}`;
      cmd += ` -keyName ${escapeShellArg(args.keyName as string)}`;
      if (args.valueName) cmd += ` -v ${escapeShellArg(args.valueName as string)}`;
      if (args.valueData) cmd += ` -vd ${escapeShellArg(args.valueData as string)}`;
      if (args.valueType) cmd += ` -vt ${escapeShellArg(args.valueType as string)}`;
      break;
    }

    case "impacket_services": {
      const auth = buildAuthString({
        domain: args.domain as string,
        username: args.username as string,
        password: args.password as string,
        hashes: args.hashes as string,
      });
      cmd = `impacket-services ${escapeShellArg(auth)}@${escapeShellArg(args.target as string)}`;
      if (args.hashes) cmd += ` -hashes ${escapeShellArg(args.hashes as string)}`;
      if (args.dc_ip) cmd += ` -dc-ip ${escapeShellArg(args.dc_ip as string)}`;
      cmd += ` ${escapeShellArg(args.action as string)}`;
      if (args.service_name) cmd += ` -name ${escapeShellArg(args.service_name as string)}`;
      if (args.display_name) cmd += ` -display ${escapeShellArg(args.display_name as string)}`;
      if (args.binary_path) cmd += ` -path ${escapeShellArg(args.binary_path as string)}`;
      break;
    }

    case "impacket_getlapspassword": {
      const auth = buildAuthString({
        domain: args.domain as string,
        username: args.username as string,
        password: args.password as string,
        hashes: args.hashes as string,
      });
      cmd = `impacket-GetLAPSPassword ${escapeShellArg(args.target as string)}/${escapeShellArg(auth)}`;
      if (args.hashes) cmd += ` -hashes ${escapeShellArg(args.hashes as string)}`;
      if (args.dc_ip) cmd += ` -dc-ip ${escapeShellArg(args.dc_ip as string)}`;
      if (args.computer) cmd += ` -computer ${escapeShellArg(args.computer as string)}`;
      break;
    }

    default:
      throw new Error(`Unknown tool: ${name}`);
  }

  // Execute on Kali
  const result = await executeOnKali(cmd);

  let output = "";
  if (result.stdout) {
    output += result.stdout;
  }
  if (result.stderr) {
    output += (output ? "\n\n" : "") + `STDERR:\n${result.stderr}`;
  }
  output += `\n\n[Exit code: ${result.exitCode}]`;
  output += `\n[Command: ${cmd}]`;

  return output;
}

// Main server setup
const server = new Server(
  {
    name: "impacket-mcp",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Register tool handlers
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return { tools };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    const result = await handleToolCall(name, args as Record<string, unknown>);
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
  console.error("Impacket MCP server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
