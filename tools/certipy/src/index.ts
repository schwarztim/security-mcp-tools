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
const KALI_HOST = process.env.CERTIPY_KALI_HOST || "kali";
const SSH_OPTIONS = process.env.CERTIPY_SSH_OPTIONS || "-o StrictHostKeyChecking=no -o ConnectTimeout=10";

// Helper to execute certipy commands via SSH on Kali
async function runCertipy(args: string[]): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  const command = `ssh ${SSH_OPTIONS} ${KALI_HOST} "certipy ${args.join(" ")}"`;

  try {
    const { stdout, stderr } = await execAsync(command, {
      maxBuffer: 50 * 1024 * 1024, // 50MB buffer for large outputs
      timeout: 600000 // 10 minute timeout
    });
    return { stdout, stderr, exitCode: 0 };
  } catch (error: any) {
    return {
      stdout: error.stdout || "",
      stderr: error.stderr || error.message,
      exitCode: error.code || 1
    };
  }
}

// Build connection args from common parameters
function buildConnectionArgs(params: {
  username?: string;
  password?: string;
  domain?: string;
  dc_ip?: string;
  hashes?: string;
  kerberos?: boolean;
  no_pass?: boolean;
  aes_key?: string;
  scheme?: string;
  target?: string;
}): string[] {
  const args: string[] = [];

  if (params.username) {
    const user = params.domain ? `${params.username}@${params.domain}` : params.username;
    args.push("-u", `'${user}'`);
  }
  if (params.password) args.push("-p", `'${params.password}'`);
  if (params.dc_ip) args.push("-dc-ip", params.dc_ip);
  if (params.hashes) args.push("-hashes", params.hashes);
  if (params.kerberos) args.push("-k");
  if (params.no_pass) args.push("-no-pass");
  if (params.aes_key) args.push("-aes", params.aes_key);
  if (params.scheme) args.push("-scheme", params.scheme);
  if (params.target) args.push("-target", params.target);

  return args;
}

// Tool definitions
const tools: Tool[] = [
  {
    name: "certipy_find",
    description: "Enumerate AD CS configuration - find Certificate Authorities, templates, and vulnerabilities (ESC1-ESC16). This is typically the first step in AD CS attacks.",
    inputSchema: {
      type: "object",
      properties: {
        username: { type: "string", description: "Username for authentication" },
        password: { type: "string", description: "Password for authentication" },
        domain: { type: "string", description: "Domain name (e.g., corp.local)" },
        dc_ip: { type: "string", description: "Domain controller IP address" },
        hashes: { type: "string", description: "NTLM hash in format [LMHASH:]NTHASH" },
        kerberos: { type: "boolean", description: "Use Kerberos authentication from ccache" },
        no_pass: { type: "boolean", description: "Don't ask for password" },
        aes_key: { type: "string", description: "AES key for Kerberos (128 or 256 bits)" },
        scheme: { type: "string", enum: ["ldap", "ldaps"], description: "LDAP scheme (default: ldaps)" },
        vulnerable: { type: "boolean", description: "Only show vulnerable templates" },
        enabled: { type: "boolean", description: "Only show enabled templates" },
        hide_admins: { type: "boolean", description: "Hide admin-only templates" },
        output: { type: "string", description: "Output file path (without extension)" },
        text: { type: "boolean", description: "Output in text format" },
        json: { type: "boolean", description: "Output in JSON format" },
        stdout: { type: "boolean", description: "Print to stdout" },
        old_bloodhound: { type: "boolean", description: "Use old BloodHound format" }
      },
      required: ["username", "domain", "dc_ip"]
    }
  },
  {
    name: "certipy_req",
    description: "Request a certificate from AD CS. Use after identifying vulnerable templates. Supports multiple enrollment protocols (RPC, DCOM, HTTP).",
    inputSchema: {
      type: "object",
      properties: {
        username: { type: "string", description: "Username for authentication" },
        password: { type: "string", description: "Password for authentication" },
        domain: { type: "string", description: "Domain name" },
        dc_ip: { type: "string", description: "Domain controller IP" },
        hashes: { type: "string", description: "NTLM hash" },
        kerberos: { type: "boolean", description: "Use Kerberos" },
        no_pass: { type: "boolean", description: "No password" },
        ca: { type: "string", description: "Certificate Authority name (required)" },
        template: { type: "string", description: "Certificate template name (required)" },
        target: { type: "string", description: "Target CA server hostname or IP" },
        upn: { type: "string", description: "User Principal Name for certificate (ESC1 exploitation)" },
        dns: { type: "string", description: "DNS name for certificate" },
        subject: { type: "string", description: "Certificate subject" },
        on_behalf_of: { type: "string", description: "Request on behalf of another user (ESC3)" },
        pfx: { type: "string", description: "PFX file for enrollment agent cert (ESC3)" },
        web: { type: "boolean", description: "Use HTTP enrollment" },
        dcom: { type: "boolean", description: "Use DCOM enrollment" },
        dynamic_endpoint: { type: "boolean", description: "Use dynamic RPC endpoint" },
        renew: { type: "boolean", description: "Renew existing certificate" },
        retrieve: { type: "string", description: "Request ID to retrieve" },
        out: { type: "string", description: "Output filename for certificate" }
      },
      required: ["username", "domain", "dc_ip", "ca", "template"]
    }
  },
  {
    name: "certipy_auth",
    description: "Authenticate using a certificate (PKINIT) to obtain Kerberos TGT and NTLM hash. Use after obtaining a certificate.",
    inputSchema: {
      type: "object",
      properties: {
        pfx: { type: "string", description: "Path to PFX certificate file (required)" },
        domain: { type: "string", description: "Domain name" },
        dc_ip: { type: "string", description: "Domain controller IP" },
        username: { type: "string", description: "Username (if not in cert)" },
        no_save: { type: "boolean", description: "Don't save TGT to file" },
        no_hash: { type: "boolean", description: "Don't request NTLM hash" },
        print: { type: "boolean", description: "Print TGT to console" },
        kirbi: { type: "boolean", description: "Save as kirbi format" },
        ldap_shell: { type: "boolean", description: "Start LDAP shell" }
      },
      required: ["pfx", "dc_ip"]
    }
  },
  {
    name: "certipy_forge",
    description: "Forge certificates using compromised CA private key (Golden Certificate attack) or create self-signed certificates.",
    inputSchema: {
      type: "object",
      properties: {
        ca_pfx: { type: "string", description: "CA certificate PFX file (for Golden Certificate)" },
        subject: { type: "string", description: "Certificate subject DN" },
        upn: { type: "string", description: "User Principal Name to impersonate" },
        dns: { type: "string", description: "DNS name for certificate" },
        sid: { type: "string", description: "Security Identifier to include" },
        serial: { type: "string", description: "Certificate serial number" },
        crl: { type: "string", description: "CRL distribution point" },
        key_size: { type: "number", description: "RSA key size (default: 2048)" },
        validity_period: { type: "number", description: "Validity period in years" },
        out: { type: "string", description: "Output filename" },
        self_signed: { type: "boolean", description: "Create self-signed certificate" }
      },
      required: []
    }
  },
  {
    name: "certipy_shadow",
    description: "Abuse Shadow Credentials (Key Credential Link) for account takeover. Allows authenticating as the target without knowing their password.",
    inputSchema: {
      type: "object",
      properties: {
        username: { type: "string", description: "Username for authentication" },
        password: { type: "string", description: "Password for authentication" },
        domain: { type: "string", description: "Domain name" },
        dc_ip: { type: "string", description: "Domain controller IP" },
        hashes: { type: "string", description: "NTLM hash" },
        kerberos: { type: "boolean", description: "Use Kerberos" },
        no_pass: { type: "boolean", description: "No password" },
        account: { type: "string", description: "Target account to attack (required)" },
        action: {
          type: "string",
          enum: ["list", "add", "remove", "clear", "info", "auto"],
          description: "Shadow credential action (default: auto)"
        },
        device_id: { type: "string", description: "Device ID for specific credential" },
        out: { type: "string", description: "Output filename for certificate" }
      },
      required: ["username", "domain", "dc_ip", "account"]
    }
  },
  {
    name: "certipy_relay",
    description: "NTLM relay attack targeting AD CS HTTP/RPC endpoints (ESC8/ESC11). Relays NTLM authentication to request certificates.",
    inputSchema: {
      type: "object",
      properties: {
        target: { type: "string", description: "Target URL (e.g., http://ca.corp.local/certsrv/certfnsh.asp)" },
        ca: { type: "string", description: "Certificate Authority name" },
        template: { type: "string", description: "Certificate template to request" },
        interface: { type: "string", description: "Interface to listen on (default: 0.0.0.0)" },
        port: { type: "number", description: "Port to listen on (default: 445)" },
        forever: { type: "boolean", description: "Run relay indefinitely" },
        enum_templates: { type: "boolean", description: "Enumerate available templates" },
        upn: { type: "string", description: "UPN to request in certificate" }
      },
      required: ["target", "ca"]
    }
  },
  {
    name: "certipy_template",
    description: "Manage certificate templates - view, backup, and modify configurations. Used for ESC4 attacks (template modification).",
    inputSchema: {
      type: "object",
      properties: {
        username: { type: "string", description: "Username for authentication" },
        password: { type: "string", description: "Password for authentication" },
        domain: { type: "string", description: "Domain name" },
        dc_ip: { type: "string", description: "Domain controller IP" },
        hashes: { type: "string", description: "NTLM hash" },
        kerberos: { type: "boolean", description: "Use Kerberos" },
        no_pass: { type: "boolean", description: "No password" },
        template: { type: "string", description: "Template name to modify (required)" },
        save_config: { type: "string", description: "Save current config to file" },
        write_config: { type: "string", description: "Write config from file" },
        write_default: { type: "boolean", description: "Make template ESC1 vulnerable (dangerous!)" }
      },
      required: ["username", "domain", "dc_ip", "template"]
    }
  },
  {
    name: "certipy_ca",
    description: "Manage Certificate Authority - list templates, enable/disable templates, issue/deny requests, manage officers (ESC7).",
    inputSchema: {
      type: "object",
      properties: {
        username: { type: "string", description: "Username for authentication" },
        password: { type: "string", description: "Password for authentication" },
        domain: { type: "string", description: "Domain name" },
        dc_ip: { type: "string", description: "Domain controller IP" },
        hashes: { type: "string", description: "NTLM hash" },
        kerberos: { type: "boolean", description: "Use Kerberos" },
        no_pass: { type: "boolean", description: "No password" },
        ca: { type: "string", description: "Certificate Authority name (required)" },
        target: { type: "string", description: "CA server hostname" },
        list_templates: { type: "boolean", description: "List CA templates" },
        enable_template: { type: "string", description: "Template name to enable" },
        disable_template: { type: "string", description: "Template name to disable" },
        issue_request: { type: "string", description: "Request ID to issue" },
        deny_request: { type: "string", description: "Request ID to deny" },
        add_officer: { type: "string", description: "User to add as officer" },
        remove_officer: { type: "string", description: "User to remove as officer" }
      },
      required: ["username", "domain", "dc_ip", "ca"]
    }
  },
  {
    name: "certipy_cert",
    description: "Manage local certificates and keys - import, export, convert between formats.",
    inputSchema: {
      type: "object",
      properties: {
        pfx: { type: "string", description: "Input PFX file" },
        key: { type: "string", description: "Input private key file" },
        cert: { type: "string", description: "Input certificate file" },
        export: { type: "boolean", description: "Export to PEM format" },
        out: { type: "string", description: "Output filename" },
        nocert: { type: "boolean", description: "Don't export certificate" },
        nokey: { type: "boolean", description: "Don't export private key" },
        password: { type: "string", description: "PFX password" }
      },
      required: []
    }
  },
  {
    name: "certipy_account",
    description: "Manage AD user and computer accounts - create, read, update, delete accounts for attack setup.",
    inputSchema: {
      type: "object",
      properties: {
        username: { type: "string", description: "Username for authentication" },
        password: { type: "string", description: "Password for authentication" },
        domain: { type: "string", description: "Domain name" },
        dc_ip: { type: "string", description: "Domain controller IP" },
        hashes: { type: "string", description: "NTLM hash" },
        kerberos: { type: "boolean", description: "Use Kerberos" },
        no_pass: { type: "boolean", description: "No password" },
        user: { type: "string", description: "Target user account" },
        dns: { type: "string", description: "DNS hostname for account" },
        upn: { type: "string", description: "User Principal Name" },
        sam: { type: "string", description: "SAM account name" },
        spns: { type: "string", description: "Service Principal Names (comma-separated)" },
        new_pass: { type: "string", description: "New password to set" },
        create: { type: "boolean", description: "Create new account" },
        delete: { type: "boolean", description: "Delete account" }
      },
      required: ["username", "domain", "dc_ip"]
    }
  },
  {
    name: "certipy_help",
    description: "Get help for certipy commands - show available options and usage.",
    inputSchema: {
      type: "object",
      properties: {
        command: {
          type: "string",
          enum: ["find", "req", "auth", "forge", "shadow", "relay", "template", "ca", "cert", "account"],
          description: "Command to get help for (optional, shows global help if not specified)"
        }
      },
      required: []
    }
  }
];

// Create server
const server = new Server(
  {
    name: "certipy-mcp",
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
    let cmdArgs: string[] = [];

    switch (name) {
      case "certipy_find": {
        cmdArgs = ["find"];
        cmdArgs.push(...buildConnectionArgs(args as any));
        if (args?.vulnerable) cmdArgs.push("-vulnerable");
        if (args?.enabled) cmdArgs.push("-enabled");
        if (args?.hide_admins) cmdArgs.push("-hide-admins");
        if (args?.output) cmdArgs.push("-output", args.output as string);
        if (args?.text) cmdArgs.push("-text");
        if (args?.json) cmdArgs.push("-json");
        if (args?.stdout) cmdArgs.push("-stdout");
        if (args?.old_bloodhound) cmdArgs.push("-old-bloodhound");
        break;
      }

      case "certipy_req": {
        cmdArgs = ["req"];
        cmdArgs.push(...buildConnectionArgs(args as any));
        if (args?.ca) cmdArgs.push("-ca", `'${args.ca}'`);
        if (args?.template) cmdArgs.push("-template", `'${args.template}'`);
        if (args?.upn) cmdArgs.push("-upn", `'${args.upn}'`);
        if (args?.dns) cmdArgs.push("-dns", `'${args.dns}'`);
        if (args?.subject) cmdArgs.push("-subject", `'${args.subject}'`);
        if (args?.on_behalf_of) cmdArgs.push("-on-behalf-of", `'${args.on_behalf_of}'`);
        if (args?.pfx) cmdArgs.push("-pfx", args.pfx as string);
        if (args?.web) cmdArgs.push("-web");
        if (args?.dcom) cmdArgs.push("-dcom");
        if (args?.dynamic_endpoint) cmdArgs.push("-dynamic-endpoint");
        if (args?.renew) cmdArgs.push("-renew");
        if (args?.retrieve) cmdArgs.push("-retrieve", args.retrieve as string);
        if (args?.out) cmdArgs.push("-out", args.out as string);
        break;
      }

      case "certipy_auth": {
        cmdArgs = ["auth"];
        if (args?.pfx) cmdArgs.push("-pfx", args.pfx as string);
        if (args?.domain) cmdArgs.push("-domain", args.domain as string);
        if (args?.dc_ip) cmdArgs.push("-dc-ip", args.dc_ip as string);
        if (args?.username) cmdArgs.push("-username", `'${args.username}'`);
        if (args?.no_save) cmdArgs.push("-no-save");
        if (args?.no_hash) cmdArgs.push("-no-hash");
        if (args?.print) cmdArgs.push("-print");
        if (args?.kirbi) cmdArgs.push("-kirbi");
        if (args?.ldap_shell) cmdArgs.push("-ldap-shell");
        break;
      }

      case "certipy_forge": {
        cmdArgs = ["forge"];
        if (args?.ca_pfx) cmdArgs.push("-ca-pfx", args.ca_pfx as string);
        if (args?.subject) cmdArgs.push("-subject", `'${args.subject}'`);
        if (args?.upn) cmdArgs.push("-upn", `'${args.upn}'`);
        if (args?.dns) cmdArgs.push("-dns", `'${args.dns}'`);
        if (args?.sid) cmdArgs.push("-sid", args.sid as string);
        if (args?.serial) cmdArgs.push("-serial", args.serial as string);
        if (args?.crl) cmdArgs.push("-crl", `'${args.crl}'`);
        if (args?.key_size) cmdArgs.push("-key-size", String(args.key_size));
        if (args?.validity_period) cmdArgs.push("-validity-period", String(args.validity_period));
        if (args?.out) cmdArgs.push("-out", args.out as string);
        if (args?.self_signed) cmdArgs.push("-self-signed");
        break;
      }

      case "certipy_shadow": {
        cmdArgs = ["shadow"];
        cmdArgs.push(...buildConnectionArgs(args as any));
        if (args?.account) cmdArgs.push("-account", `'${args.account}'`);
        if (args?.action) cmdArgs.push(`-${args.action}`);
        else cmdArgs.push("-auto"); // Default action
        if (args?.device_id) cmdArgs.push("-device-id", args.device_id as string);
        if (args?.out) cmdArgs.push("-out", args.out as string);
        break;
      }

      case "certipy_relay": {
        cmdArgs = ["relay"];
        if (args?.target) cmdArgs.push("-target", `'${args.target}'`);
        if (args?.ca) cmdArgs.push("-ca", `'${args.ca}'`);
        if (args?.template) cmdArgs.push("-template", `'${args.template}'`);
        if (args?.interface) cmdArgs.push("-interface", args.interface as string);
        if (args?.port) cmdArgs.push("-port", String(args.port));
        if (args?.forever) cmdArgs.push("-forever");
        if (args?.enum_templates) cmdArgs.push("-enum-templates");
        if (args?.upn) cmdArgs.push("-upn", `'${args.upn}'`);
        break;
      }

      case "certipy_template": {
        cmdArgs = ["template"];
        cmdArgs.push(...buildConnectionArgs(args as any));
        if (args?.template) cmdArgs.push("-template", `'${args.template}'`);
        if (args?.save_config) cmdArgs.push("-save-configuration", args.save_config as string);
        if (args?.write_config) cmdArgs.push("-write-configuration", args.write_config as string);
        if (args?.write_default) cmdArgs.push("-write-default-configuration");
        break;
      }

      case "certipy_ca": {
        cmdArgs = ["ca"];
        cmdArgs.push(...buildConnectionArgs(args as any));
        if (args?.ca) cmdArgs.push("-ca", `'${args.ca}'`);
        if (args?.list_templates) cmdArgs.push("-list-templates");
        if (args?.enable_template) cmdArgs.push("-enable-template", `'${args.enable_template}'`);
        if (args?.disable_template) cmdArgs.push("-disable-template", `'${args.disable_template}'`);
        if (args?.issue_request) cmdArgs.push("-issue-request", args.issue_request as string);
        if (args?.deny_request) cmdArgs.push("-deny-request", args.deny_request as string);
        if (args?.add_officer) cmdArgs.push("-add-officer", `'${args.add_officer}'`);
        if (args?.remove_officer) cmdArgs.push("-remove-officer", `'${args.remove_officer}'`);
        break;
      }

      case "certipy_cert": {
        cmdArgs = ["cert"];
        if (args?.pfx) cmdArgs.push("-pfx", args.pfx as string);
        if (args?.key) cmdArgs.push("-key", args.key as string);
        if (args?.cert) cmdArgs.push("-cert", args.cert as string);
        if (args?.export) cmdArgs.push("-export");
        if (args?.out) cmdArgs.push("-out", args.out as string);
        if (args?.nocert) cmdArgs.push("-nocert");
        if (args?.nokey) cmdArgs.push("-nokey");
        if (args?.password) cmdArgs.push("-password", `'${args.password}'`);
        break;
      }

      case "certipy_account": {
        cmdArgs = ["account"];
        cmdArgs.push(...buildConnectionArgs(args as any));
        if (args?.user) cmdArgs.push("-user", `'${args.user}'`);
        if (args?.dns) cmdArgs.push("-dns", `'${args.dns}'`);
        if (args?.upn) cmdArgs.push("-upn", `'${args.upn}'`);
        if (args?.sam) cmdArgs.push("-sam", `'${args.sam}'`);
        if (args?.spns) cmdArgs.push("-spns", `'${args.spns}'`);
        if (args?.new_pass) cmdArgs.push("-pass", `'${args.new_pass}'`);
        if (args?.create) cmdArgs.push("-create");
        if (args?.delete) cmdArgs.push("-delete");
        break;
      }

      case "certipy_help": {
        if (args?.command) {
          cmdArgs = [args.command as string, "-h"];
        } else {
          cmdArgs = ["-h"];
        }
        break;
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }

    const result = await runCertipy(cmdArgs);

    // Format output
    let output = "";
    if (result.stdout) output += result.stdout;
    if (result.stderr) output += (output ? "\n\nSTDERR:\n" : "STDERR:\n") + result.stderr;
    if (!output) output = `Command completed with exit code ${result.exitCode}`;

    return {
      content: [
        {
          type: "text",
          text: output,
        },
      ],
      isError: result.exitCode !== 0,
    };
  } catch (error: any) {
    return {
      content: [
        {
          type: "text",
          text: `Error executing certipy: ${error.message}`,
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
  console.error("Certipy MCP server started");
}

main().catch(console.error);
