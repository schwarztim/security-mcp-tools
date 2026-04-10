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

// Kali SSH configuration
const KALI_HOST = process.env.KALI_HOST || "kali";
const KALI_USER = process.env.KALI_USER || "kali";

// Helper to run commands on Kali via SSH
async function runOnKali(command: string, timeout = 300000): Promise<{ stdout: string; stderr: string }> {
  const sshCommand = `ssh ${KALI_USER}@${KALI_HOST} "${command.replace(/"/g, '\\"')}"`;
  try {
    const result = await execAsync(sshCommand, { timeout });
    return result;
  } catch (error: any) {
    return {
      stdout: error.stdout || "",
      stderr: error.stderr || error.message,
    };
  }
}

// Supported protocols in THC-Hydra
const SUPPORTED_PROTOCOLS = [
  "asterisk", "afp", "cisco", "cisco-enable", "cvs", "firebird", "ftp", "ftps",
  "http-form-get", "http-form-post", "http-get", "http-head", "http-post",
  "http-proxy", "https-form-get", "https-form-post", "https-get", "https-head",
  "https-post", "icq", "imap", "imaps", "irc", "ldap2", "ldap3", "ldap3-crammd5",
  "ldap3-digestmd5", "memcached", "mongodb", "mssql", "mysql", "ncp", "nntp",
  "oracle", "oracle-listener", "oracle-sid", "pcanywhere", "pcnfs", "pop3",
  "pop3s", "postgres", "radmin2", "rdp", "redis", "rexec", "rlogin", "rpcap",
  "rsh", "rtsp", "s7-300", "sap-r3", "sip", "smb", "smtp", "smtps", "smtp-enum",
  "snmp", "socks5", "ssh", "sshkey", "svn", "teamspeak", "telnet", "telnets",
  "vmauthd", "vnc", "xmpp"
];

// Common wordlist paths on Kali
const WORDLISTS = {
  rockyou: "/usr/share/wordlists/rockyou.txt",
  common_users: "/usr/share/wordlists/metasploit/unix_users.txt",
  common_passwords: "/usr/share/wordlists/metasploit/unix_passwords.txt",
  fasttrack: "/usr/share/wordlists/fasttrack.txt",
  dirb_common: "/usr/share/wordlists/dirb/common.txt",
  top_usernames: "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
  default_creds: "/usr/share/seclists/Passwords/Default-Credentials/default-passwords.txt",
};

// Define tools
const tools: Tool[] = [
  {
    name: "hydra_attack",
    description: `Start a THC-Hydra brute-force attack against a target. Executes on Kali Linux via SSH.

IMPORTANT: Only use this tool for authorized security testing. Unauthorized access attempts are illegal.

Common protocols: ssh, ftp, http-form-post, rdp, smb, mysql, postgres, vnc, telnet`,
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target host (IP or hostname)"
        },
        protocol: {
          type: "string",
          description: "Protocol to attack (e.g., ssh, ftp, http-form-post, rdp, smb)",
          enum: SUPPORTED_PROTOCOLS
        },
        port: {
          type: "number",
          description: "Target port (optional, uses default for protocol)"
        },
        username: {
          type: "string",
          description: "Single username to try"
        },
        username_file: {
          type: "string",
          description: "Path to username wordlist file on Kali"
        },
        password: {
          type: "string",
          description: "Single password to try"
        },
        password_file: {
          type: "string",
          description: "Path to password wordlist file on Kali"
        },
        tasks: {
          type: "number",
          description: "Number of parallel tasks/threads (default: 16, use 4 for SSH)",
          default: 16
        },
        verbose: {
          type: "boolean",
          description: "Enable verbose output showing each attempt",
          default: false
        },
        exit_on_first: {
          type: "boolean",
          description: "Exit after first valid login found",
          default: true
        },
        try_login_as_pass: {
          type: "boolean",
          description: "Try username as password",
          default: false
        },
        try_empty_pass: {
          type: "boolean",
          description: "Try empty password",
          default: false
        },
        try_reverse: {
          type: "boolean",
          description: "Try reversed username as password",
          default: false
        },
        output_file: {
          type: "string",
          description: "Save results to file on Kali"
        },
        module_options: {
          type: "string",
          description: "Module-specific options (passed to -m flag)"
        },
        timeout: {
          type: "number",
          description: "Connection timeout in seconds",
          default: 30
        }
      },
      required: ["target", "protocol"]
    }
  },
  {
    name: "hydra_http_form",
    description: `Attack HTTP/HTTPS form-based authentication. This is a specialized wrapper for http-form-post/get attacks.

Example: Login forms with username/password fields.`,
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target host"
        },
        port: {
          type: "number",
          description: "Target port (default: 80 for HTTP, 443 for HTTPS)"
        },
        ssl: {
          type: "boolean",
          description: "Use HTTPS",
          default: false
        },
        method: {
          type: "string",
          description: "HTTP method",
          enum: ["GET", "POST"],
          default: "POST"
        },
        path: {
          type: "string",
          description: "Login form path (e.g., /login.php)"
        },
        form_data: {
          type: "string",
          description: "Form data with ^USER^ and ^PASS^ placeholders (e.g., 'username=^USER^&password=^PASS^')"
        },
        failure_string: {
          type: "string",
          description: "String that appears on failed login (F=string)"
        },
        success_string: {
          type: "string",
          description: "String that appears on successful login (S=string)"
        },
        username: {
          type: "string",
          description: "Single username"
        },
        username_file: {
          type: "string",
          description: "Username wordlist path"
        },
        password: {
          type: "string",
          description: "Single password"
        },
        password_file: {
          type: "string",
          description: "Password wordlist path"
        },
        tasks: {
          type: "number",
          description: "Parallel tasks",
          default: 16
        },
        cookies: {
          type: "string",
          description: "Cookies to send (e.g., 'PHPSESSID=abc123')"
        },
        headers: {
          type: "string",
          description: "Additional headers (e.g., 'User-Agent: Mozilla/5.0')"
        }
      },
      required: ["target", "path", "form_data"]
    }
  },
  {
    name: "hydra_protocols",
    description: "List all supported protocols in THC-Hydra with descriptions",
    inputSchema: {
      type: "object",
      properties: {}
    }
  },
  {
    name: "hydra_wordlists",
    description: "List common wordlists available on Kali Linux",
    inputSchema: {
      type: "object",
      properties: {
        check_exists: {
          type: "boolean",
          description: "Check if wordlists actually exist on Kali",
          default: false
        }
      }
    }
  },
  {
    name: "hydra_restore",
    description: "Restore a previous Hydra session from a restore file",
    inputSchema: {
      type: "object",
      properties: {
        restore_file: {
          type: "string",
          description: "Path to hydra.restore file (default: ./hydra.restore)"
        }
      }
    }
  },
  {
    name: "hydra_status",
    description: "Check if Hydra is running and get process information",
    inputSchema: {
      type: "object",
      properties: {}
    }
  },
  {
    name: "hydra_stop",
    description: "Stop running Hydra processes on Kali",
    inputSchema: {
      type: "object",
      properties: {
        force: {
          type: "boolean",
          description: "Force kill with SIGKILL",
          default: false
        }
      }
    }
  },
  {
    name: "hydra_version",
    description: "Get Hydra version and build information",
    inputSchema: {
      type: "object",
      properties: {}
    }
  },
  {
    name: "hydra_module_help",
    description: "Get help for a specific Hydra module/protocol",
    inputSchema: {
      type: "object",
      properties: {
        protocol: {
          type: "string",
          description: "Protocol to get help for",
          enum: SUPPORTED_PROTOCOLS
        }
      },
      required: ["protocol"]
    }
  },
  {
    name: "hydra_generate_command",
    description: "Generate a Hydra command without executing it. Useful for review before running.",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target host"
        },
        protocol: {
          type: "string",
          description: "Protocol to attack"
        },
        port: {
          type: "number",
          description: "Target port"
        },
        username: {
          type: "string",
          description: "Single username"
        },
        username_file: {
          type: "string",
          description: "Username wordlist"
        },
        password: {
          type: "string",
          description: "Single password"
        },
        password_file: {
          type: "string",
          description: "Password wordlist"
        },
        tasks: {
          type: "number",
          description: "Parallel tasks"
        },
        options: {
          type: "object",
          description: "Additional options",
          additionalProperties: true
        }
      },
      required: ["target", "protocol"]
    }
  }
];

// Build Hydra command from parameters
function buildHydraCommand(params: any): string {
  const args: string[] = ["hydra"];

  // Username options
  if (params.username) {
    args.push("-l", params.username);
  } else if (params.username_file) {
    args.push("-L", params.username_file);
  }

  // Password options
  if (params.password) {
    args.push("-p", params.password);
  } else if (params.password_file) {
    args.push("-P", params.password_file);
  }

  // -e options (login variants)
  let eOpts = "";
  if (params.try_login_as_pass) eOpts += "s";
  if (params.try_empty_pass) eOpts += "n";
  if (params.try_reverse) eOpts += "r";
  if (eOpts) args.push("-e", eOpts);

  // Tasks/threads
  if (params.tasks) {
    args.push("-t", String(params.tasks));
  }

  // Verbose
  if (params.verbose) {
    args.push("-vV");
  }

  // Exit on first
  if (params.exit_on_first) {
    args.push("-f");
  }

  // Output file
  if (params.output_file) {
    args.push("-o", params.output_file);
  }

  // Port
  if (params.port) {
    args.push("-s", String(params.port));
  }

  // Timeout
  if (params.timeout) {
    args.push("-w", String(params.timeout));
  }

  // Module options
  if (params.module_options) {
    args.push("-m", params.module_options);
  }

  // Target and protocol
  args.push(`${params.protocol}://${params.target}`);

  return args.join(" ");
}

// Build HTTP form attack command
function buildHttpFormCommand(params: any): string {
  const args: string[] = ["hydra"];

  // Username options
  if (params.username) {
    args.push("-l", params.username);
  } else if (params.username_file) {
    args.push("-L", params.username_file);
  }

  // Password options
  if (params.password) {
    args.push("-p", params.password);
  } else if (params.password_file) {
    args.push("-P", params.password_file);
  }

  // Tasks
  if (params.tasks) {
    args.push("-t", String(params.tasks));
  }

  args.push("-vV"); // Always verbose for HTTP forms
  args.push("-f");  // Exit on first success

  // Port
  if (params.port) {
    args.push("-s", String(params.port));
  }

  // Build the module string
  const protocol = params.ssl ? "https-form" : "http-form";
  const method = (params.method || "POST").toLowerCase();
  const moduleProtocol = `${protocol}-${method === "post" ? "post" : "get"}`;

  // Build form string: /path:form_data:failure_or_success
  let formString = `${params.path}:${params.form_data}:`;
  if (params.failure_string) {
    formString += `F=${params.failure_string}`;
  } else if (params.success_string) {
    formString += `S=${params.success_string}`;
  }

  // Add cookies and headers if provided
  if (params.cookies) {
    formString += `:H=Cookie\\: ${params.cookies}`;
  }
  if (params.headers) {
    formString += `:H=${params.headers}`;
  }

  args.push(`${moduleProtocol}://${params.target}/${formString}`);

  return args.join(" ");
}

// Create server
const server = new Server(
  {
    name: "hydra-mcp",
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
    switch (name) {
      case "hydra_attack": {
        const params = args as any;

        // Validate we have credentials
        if (!params.username && !params.username_file) {
          return {
            content: [{
              type: "text",
              text: "Error: You must provide either 'username' or 'username_file'"
            }]
          };
        }
        if (!params.password && !params.password_file) {
          return {
            content: [{
              type: "text",
              text: "Error: You must provide either 'password' or 'password_file'"
            }]
          };
        }

        const command = buildHydraCommand(params);
        const result = await runOnKali(command);

        return {
          content: [{
            type: "text",
            text: `## Hydra Attack Results\n\n**Command:**\n\`\`\`\n${command}\n\`\`\`\n\n**Output:**\n\`\`\`\n${result.stdout}\n\`\`\`\n${result.stderr ? `\n**Errors:**\n\`\`\`\n${result.stderr}\n\`\`\`` : ""}`
          }]
        };
      }

      case "hydra_http_form": {
        const params = args as any;

        // Validate required fields
        if (!params.form_data || (!params.failure_string && !params.success_string)) {
          return {
            content: [{
              type: "text",
              text: "Error: form_data and either failure_string or success_string are required"
            }]
          };
        }
        if (!params.username && !params.username_file) {
          return {
            content: [{
              type: "text",
              text: "Error: You must provide either 'username' or 'username_file'"
            }]
          };
        }
        if (!params.password && !params.password_file) {
          return {
            content: [{
              type: "text",
              text: "Error: You must provide either 'password' or 'password_file'"
            }]
          };
        }

        const command = buildHttpFormCommand(params);
        const result = await runOnKali(command);

        return {
          content: [{
            type: "text",
            text: `## HTTP Form Attack Results\n\n**Command:**\n\`\`\`\n${command}\n\`\`\`\n\n**Output:**\n\`\`\`\n${result.stdout}\n\`\`\`\n${result.stderr ? `\n**Errors:**\n\`\`\`\n${result.stderr}\n\`\`\`` : ""}`
          }]
        };
      }

      case "hydra_protocols": {
        const protocolDescriptions: Record<string, string> = {
          ssh: "Secure Shell - commonly on port 22",
          ftp: "File Transfer Protocol - port 21",
          "http-form-post": "HTTP POST form authentication",
          "http-form-get": "HTTP GET form authentication",
          "http-get": "HTTP Basic Authentication (GET)",
          "http-post": "HTTP Basic Authentication (POST)",
          "https-form-post": "HTTPS POST form authentication",
          rdp: "Remote Desktop Protocol - port 3389",
          smb: "Server Message Block - ports 139/445",
          mysql: "MySQL Database - port 3306",
          postgres: "PostgreSQL Database - port 5432",
          mssql: "Microsoft SQL Server - port 1433",
          oracle: "Oracle Database - port 1521",
          vnc: "Virtual Network Computing - port 5900",
          telnet: "Telnet Protocol - port 23",
          smtp: "Simple Mail Transfer Protocol - port 25",
          pop3: "Post Office Protocol v3 - port 110",
          imap: "Internet Message Access Protocol - port 143",
          ldap2: "LDAP v2 - port 389",
          ldap3: "LDAP v3 - port 389",
          snmp: "Simple Network Management Protocol - port 161",
          redis: "Redis Database - port 6379",
          mongodb: "MongoDB Database - port 27017",
          "cisco-enable": "Cisco enable mode",
          sip: "Session Initiation Protocol - VoIP",
          socks5: "SOCKS5 Proxy",
          svn: "Subversion - port 3690",
          teamspeak: "TeamSpeak Server",
          xmpp: "XMPP/Jabber Protocol",
        };

        let output = "## Supported Hydra Protocols\n\n";
        output += "| Protocol | Description |\n|----------|-------------|\n";

        for (const proto of SUPPORTED_PROTOCOLS) {
          const desc = protocolDescriptions[proto] || "Network protocol";
          output += `| ${proto} | ${desc} |\n`;
        }

        output += `\n**Total: ${SUPPORTED_PROTOCOLS.length} protocols supported**`;

        return {
          content: [{
            type: "text",
            text: output
          }]
        };
      }

      case "hydra_wordlists": {
        const params = args as any;
        let output = "## Common Wordlists on Kali Linux\n\n";

        if (params.check_exists) {
          output += "| Wordlist | Path | Exists |\n|----------|------|--------|\n";
          for (const [name, path] of Object.entries(WORDLISTS)) {
            const result = await runOnKali(`test -f ${path} && echo "yes" || echo "no"`);
            const exists = result.stdout.trim() === "yes" ? "Yes" : "No";
            output += `| ${name} | ${path} | ${exists} |\n`;
          }
        } else {
          output += "| Wordlist | Path |\n|----------|------|\n";
          for (const [name, path] of Object.entries(WORDLISTS)) {
            output += `| ${name} | ${path} |\n`;
          }
        }

        output += "\n### Other Common Locations\n";
        output += "- `/usr/share/wordlists/` - Main wordlist directory\n";
        output += "- `/usr/share/seclists/` - SecLists collection\n";
        output += "- `/usr/share/wordlists/rockyou.txt.gz` - May need to unzip\n";

        return {
          content: [{
            type: "text",
            text: output
          }]
        };
      }

      case "hydra_restore": {
        const params = args as any;
        const restoreFile = params.restore_file || "./hydra.restore";
        const result = await runOnKali(`hydra -R ${restoreFile}`);

        return {
          content: [{
            type: "text",
            text: `## Session Restore\n\n**Restore file:** ${restoreFile}\n\n**Output:**\n\`\`\`\n${result.stdout}\n\`\`\`\n${result.stderr ? `\n**Errors:**\n\`\`\`\n${result.stderr}\n\`\`\`` : ""}`
          }]
        };
      }

      case "hydra_status": {
        const result = await runOnKali("ps aux | grep -E '[h]ydra' || echo 'No Hydra processes running'");

        return {
          content: [{
            type: "text",
            text: `## Hydra Process Status\n\n\`\`\`\n${result.stdout}\n\`\`\``
          }]
        };
      }

      case "hydra_stop": {
        const params = args as any;
        const signal = params.force ? "SIGKILL" : "SIGTERM";
        const killCmd = params.force ? "pkill -9 hydra" : "pkill hydra";
        const result = await runOnKali(killCmd);

        return {
          content: [{
            type: "text",
            text: `## Stop Hydra\n\nSent ${signal} to all Hydra processes.\n\n**Result:**\n\`\`\`\n${result.stdout || "Signal sent"}\n\`\`\`${result.stderr ? `\n\n**Errors:**\n\`\`\`\n${result.stderr}\n\`\`\`` : ""}`
          }]
        };
      }

      case "hydra_version": {
        const result = await runOnKali("hydra -h 2>&1 | head -5");

        return {
          content: [{
            type: "text",
            text: `## Hydra Version\n\n\`\`\`\n${result.stdout}\n\`\`\``
          }]
        };
      }

      case "hydra_module_help": {
        const params = args as any;
        const result = await runOnKali(`hydra -U ${params.protocol}`);

        return {
          content: [{
            type: "text",
            text: `## Module Help: ${params.protocol}\n\n\`\`\`\n${result.stdout}\n\`\`\`${result.stderr ? `\n\n**Errors:**\n\`\`\`\n${result.stderr}\n\`\`\`` : ""}`
          }]
        };
      }

      case "hydra_generate_command": {
        const params = args as any;
        const command = buildHydraCommand(params);

        return {
          content: [{
            type: "text",
            text: `## Generated Hydra Command\n\n**Command (not executed):**\n\`\`\`bash\n${command}\n\`\`\`\n\n**SSH execution:**\n\`\`\`bash\nssh ${KALI_USER}@${KALI_HOST} "${command}"\n\`\`\`\n\n*Use hydra_attack to execute this command.*`
          }]
        };
      }

      default:
        return {
          content: [{
            type: "text",
            text: `Unknown tool: ${name}`
          }],
          isError: true
        };
    }
  } catch (error: any) {
    return {
      content: [{
        type: "text",
        text: `Error executing ${name}: ${error.message}`
      }],
      isError: true
    };
  }
});

// Main
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Hydra MCP server running on stdio");
}

main().catch(console.error);
