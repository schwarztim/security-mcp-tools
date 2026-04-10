#!/usr/bin/env node
/**
 * Hashcat MCP Server
 *
 * Provides tools for GPU-based password cracking via hashcat on a remote Kali system.
 * All hashcat commands are executed via SSH to the configured Kali host.
 */

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
const SSH_HOST = process.env.HASHCAT_SSH_HOST || "kali";
const SSH_USER = process.env.HASHCAT_SSH_USER || "";
const SSH_OPTIONS = process.env.HASHCAT_SSH_OPTIONS || "-o StrictHostKeyChecking=no -o ConnectTimeout=10";
const HASHCAT_PATH = process.env.HASHCAT_PATH || "hashcat";
const DEFAULT_WORDLIST = process.env.HASHCAT_WORDLIST || "/usr/share/wordlists/rockyou.txt";
const DEFAULT_RULES = process.env.HASHCAT_RULES || "/usr/share/hashcat/rules/best64.rule";

// Common hash modes reference
const HASH_MODES: Record<string, { mode: number; description: string }> = {
  "md5": { mode: 0, description: "MD5" },
  "sha1": { mode: 100, description: "SHA1" },
  "sha256": { mode: 1400, description: "SHA2-256" },
  "sha512": { mode: 1700, description: "SHA2-512" },
  "ntlm": { mode: 1000, description: "NTLM" },
  "netlm": { mode: 3000, description: "LM" },
  "netntlmv1": { mode: 5500, description: "NetNTLMv1" },
  "netntlmv2": { mode: 5600, description: "NetNTLMv2" },
  "wpa": { mode: 22000, description: "WPA-PBKDF2-PMKID+EAPOL" },
  "bcrypt": { mode: 3200, description: "bcrypt" },
  "md5crypt": { mode: 500, description: "md5crypt, MD5 (Unix)" },
  "sha512crypt": { mode: 1800, description: "sha512crypt, SHA512 (Unix)" },
  "sha256crypt": { mode: 7400, description: "sha256crypt, SHA256 (Unix)" },
  "descrypt": { mode: 1500, description: "descrypt, DES (Unix)" },
  "mysql323": { mode: 200, description: "MySQL323" },
  "mysql41": { mode: 300, description: "MySQL4.1/MySQL5" },
  "mssql2000": { mode: 131, description: "MSSQL (2000)" },
  "mssql2005": { mode: 132, description: "MSSQL (2005)" },
  "mssql2012": { mode: 1731, description: "MSSQL (2012, 2014)" },
  "postgres": { mode: 12, description: "PostgreSQL" },
  "oracle11": { mode: 112, description: "Oracle 11g/12c" },
  "kerberos5": { mode: 13100, description: "Kerberos 5 AS-REQ Pre-Auth" },
  "kerberos5tgs": { mode: 13100, description: "Kerberos 5 TGS-REP" },
  "phpass": { mode: 400, description: "phpass (WordPress, Drupal)" },
  "django": { mode: 10000, description: "Django (PBKDF2-SHA256)" },
  "argon2": { mode: 34000, description: "Argon2" },
};

// Attack modes reference
const ATTACK_MODES: Record<string, { mode: number; description: string; example: string }> = {
  "dictionary": { mode: 0, description: "Straight/Dictionary Attack", example: "hashcat -a 0 -m 0 hash.txt wordlist.txt" },
  "combinator": { mode: 1, description: "Combinator Attack (combines two wordlists)", example: "hashcat -a 1 -m 0 hash.txt wordlist1.txt wordlist2.txt" },
  "bruteforce": { mode: 3, description: "Brute-Force/Mask Attack", example: "hashcat -a 3 -m 0 hash.txt ?a?a?a?a?a?a" },
  "hybrid_wordlist_mask": { mode: 6, description: "Hybrid Wordlist + Mask", example: "hashcat -a 6 -m 0 hash.txt wordlist.txt ?d?d?d" },
  "hybrid_mask_wordlist": { mode: 7, description: "Hybrid Mask + Wordlist", example: "hashcat -a 7 -m 0 hash.txt ?d?d?d wordlist.txt" },
  "association": { mode: 9, description: "Association Attack", example: "hashcat -a 9 -m 0 hash.txt wordlist.txt" },
};

// Charset reference for mask attacks
const CHARSETS = {
  "?l": "abcdefghijklmnopqrstuvwxyz",
  "?u": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  "?d": "0123456789",
  "?h": "0123456789abcdef",
  "?H": "0123456789ABCDEF",
  "?s": " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~",
  "?a": "?l?u?d?s (all)",
  "?b": "0x00-0xff",
};

/**
 * Execute a command via SSH on the Kali host
 */
async function sshExec(command: string, timeout: number = 300000): Promise<{ stdout: string; stderr: string }> {
  const sshTarget = SSH_USER ? `${SSH_USER}@${SSH_HOST}` : SSH_HOST;
  const fullCommand = `ssh ${SSH_OPTIONS} ${sshTarget} "${command.replace(/"/g, '\\"')}"`;

  try {
    const result = await execAsync(fullCommand, {
      timeout,
      maxBuffer: 50 * 1024 * 1024 // 50MB buffer for large outputs
    });
    return result;
  } catch (error: any) {
    // Include stderr in the result even on error
    return {
      stdout: error.stdout || "",
      stderr: error.stderr || error.message
    };
  }
}

/**
 * Parse hash mode - can be a number or a known hash type name
 */
function parseHashMode(modeInput: string | number): number {
  if (typeof modeInput === "number") return modeInput;

  const lower = modeInput.toLowerCase();
  if (HASH_MODES[lower]) {
    return HASH_MODES[lower].mode;
  }

  const parsed = parseInt(modeInput, 10);
  if (!isNaN(parsed)) return parsed;

  throw new Error(`Unknown hash mode: ${modeInput}. Use a number or one of: ${Object.keys(HASH_MODES).join(", ")}`);
}

/**
 * Parse attack mode - can be a number or a known attack type name
 */
function parseAttackMode(modeInput: string | number): number {
  if (typeof modeInput === "number") return modeInput;

  const lower = modeInput.toLowerCase();
  if (ATTACK_MODES[lower]) {
    return ATTACK_MODES[lower].mode;
  }

  const parsed = parseInt(modeInput, 10);
  if (!isNaN(parsed)) return parsed;

  throw new Error(`Unknown attack mode: ${modeInput}. Use a number or one of: ${Object.keys(ATTACK_MODES).join(", ")}`);
}

// Define tools
const tools: Tool[] = [
  {
    name: "hashcat_crack",
    description: "Start a hashcat password cracking session. Supports dictionary, brute-force, hybrid, and other attack modes.",
    inputSchema: {
      type: "object",
      properties: {
        hash: {
          type: "string",
          description: "The hash to crack, or path to a file containing hashes on the remote system"
        },
        hash_mode: {
          type: ["string", "number"],
          description: "Hash type (e.g., 0 for MD5, 1000 for NTLM, or names like 'md5', 'ntlm', 'sha256')"
        },
        attack_mode: {
          type: ["string", "number"],
          description: "Attack mode: 'dictionary' (0), 'combinator' (1), 'bruteforce' (3), 'hybrid_wordlist_mask' (6), 'hybrid_mask_wordlist' (7), 'association' (9)"
        },
        wordlist: {
          type: "string",
          description: "Path to wordlist file (for dictionary/hybrid attacks). Default: /usr/share/wordlists/rockyou.txt"
        },
        mask: {
          type: "string",
          description: "Mask pattern for brute-force (e.g., '?l?l?l?l?l?l' for 6 lowercase chars). Charsets: ?l=lower, ?u=upper, ?d=digits, ?s=special, ?a=all"
        },
        rules: {
          type: "string",
          description: "Path to rules file for wordlist mangling"
        },
        session: {
          type: "string",
          description: "Session name for saving progress and resuming later"
        },
        outfile: {
          type: "string",
          description: "Output file for cracked passwords"
        },
        workload: {
          type: "number",
          description: "Workload profile 1-4 (1=low, 2=default, 3=high, 4=nightmare)"
        },
        increment: {
          type: "boolean",
          description: "Enable incremental mode for mask attacks (try shorter lengths first)"
        },
        increment_min: {
          type: "number",
          description: "Minimum length for incremental mode"
        },
        increment_max: {
          type: "number",
          description: "Maximum length for incremental mode"
        },
        extra_args: {
          type: "string",
          description: "Additional hashcat arguments"
        },
        background: {
          type: "boolean",
          description: "Run in background (nohup). Use hashcat_status to check progress."
        }
      },
      required: ["hash", "hash_mode"]
    }
  },
  {
    name: "hashcat_status",
    description: "Check the status of a running or completed hashcat session",
    inputSchema: {
      type: "object",
      properties: {
        session: {
          type: "string",
          description: "Session name to check (default: hashcat)"
        }
      }
    }
  },
  {
    name: "hashcat_show",
    description: "Show cracked passwords from a potfile or completed session",
    inputSchema: {
      type: "object",
      properties: {
        hash: {
          type: "string",
          description: "Hash or hash file to show results for"
        },
        hash_mode: {
          type: ["string", "number"],
          description: "Hash type (required to interpret the potfile correctly)"
        },
        potfile: {
          type: "string",
          description: "Custom potfile path (default: ~/.local/share/hashcat/hashcat.potfile)"
        }
      },
      required: ["hash", "hash_mode"]
    }
  },
  {
    name: "hashcat_benchmark",
    description: "Run hashcat benchmark to test cracking speed for various hash types",
    inputSchema: {
      type: "object",
      properties: {
        hash_mode: {
          type: ["string", "number"],
          description: "Specific hash type to benchmark (optional, benchmarks all if not specified)"
        },
        workload: {
          type: "number",
          description: "Workload profile 1-4"
        }
      }
    }
  },
  {
    name: "hashcat_modes",
    description: "List available hash modes with descriptions. Can filter by keyword.",
    inputSchema: {
      type: "object",
      properties: {
        filter: {
          type: "string",
          description: "Filter modes by keyword (e.g., 'md5', 'sha', 'ntlm', 'wifi')"
        }
      }
    }
  },
  {
    name: "hashcat_attack_modes",
    description: "List and explain available attack modes",
    inputSchema: {
      type: "object",
      properties: {}
    }
  },
  {
    name: "hashcat_rules",
    description: "List available rule files or show rule file contents",
    inputSchema: {
      type: "object",
      properties: {
        show: {
          type: "string",
          description: "Path to rule file to display contents"
        }
      }
    }
  },
  {
    name: "hashcat_restore",
    description: "Restore a previously saved hashcat session",
    inputSchema: {
      type: "object",
      properties: {
        session: {
          type: "string",
          description: "Session name to restore"
        }
      },
      required: ["session"]
    }
  },
  {
    name: "hashcat_stop",
    description: "Stop a running hashcat session (saves progress for later restore)",
    inputSchema: {
      type: "object",
      properties: {
        session: {
          type: "string",
          description: "Session name to stop"
        }
      }
    }
  },
  {
    name: "hashcat_wordlists",
    description: "List available wordlists on the remote system",
    inputSchema: {
      type: "object",
      properties: {
        path: {
          type: "string",
          description: "Directory to search for wordlists (default: /usr/share/wordlists)"
        }
      }
    }
  },
  {
    name: "hashcat_identify",
    description: "Attempt to identify the hash type of a given hash",
    inputSchema: {
      type: "object",
      properties: {
        hash: {
          type: "string",
          description: "The hash to identify"
        }
      },
      required: ["hash"]
    }
  },
  {
    name: "hashcat_sessions",
    description: "List all saved hashcat sessions",
    inputSchema: {
      type: "object",
      properties: {}
    }
  }
];

// Tool handlers
async function handleHashcatCrack(args: any): Promise<string> {
  const hashMode = parseHashMode(args.hash_mode);
  const attackMode = parseAttackMode(args.attack_mode || "dictionary");

  let cmd = `${HASHCAT_PATH} -m ${hashMode} -a ${attackMode}`;

  // Add session name
  if (args.session) {
    cmd += ` --session=${args.session}`;
  }

  // Add workload profile
  if (args.workload) {
    cmd += ` -w ${args.workload}`;
  }

  // Add output file
  if (args.outfile) {
    cmd += ` -o ${args.outfile}`;
  }

  // Add rules
  if (args.rules) {
    cmd += ` -r ${args.rules}`;
  }

  // Handle incremental mode
  if (args.increment) {
    cmd += ` --increment`;
    if (args.increment_min) cmd += ` --increment-min=${args.increment_min}`;
    if (args.increment_max) cmd += ` --increment-max=${args.increment_max}`;
  }

  // Add extra arguments
  if (args.extra_args) {
    cmd += ` ${args.extra_args}`;
  }

  // Add status output flags for better monitoring
  cmd += ` --status --status-timer=10`;

  // Add the hash (inline or file path)
  cmd += ` '${args.hash}'`;

  // Add attack-specific arguments
  if (attackMode === 0 || attackMode === 6 || attackMode === 9) {
    // Dictionary-based attacks need a wordlist
    cmd += ` ${args.wordlist || DEFAULT_WORDLIST}`;
  }

  if (attackMode === 3 || attackMode === 6 || attackMode === 7) {
    // Mask-based attacks need a mask
    if (args.mask) {
      cmd += ` '${args.mask}'`;
    } else if (attackMode === 3) {
      return "Error: Brute-force attack requires a mask pattern. Example: ?l?l?l?l?l?l for 6 lowercase characters.";
    }
  }

  if (attackMode === 1) {
    // Combinator needs two wordlists
    return "Error: Combinator attack requires two wordlists specified. Use extra_args for the second wordlist.";
  }

  if (attackMode === 7) {
    // Hybrid mask+wordlist
    cmd += ` ${args.wordlist || DEFAULT_WORDLIST}`;
  }

  // Run in background if requested
  if (args.background) {
    cmd = `nohup ${cmd} > /tmp/hashcat_output.log 2>&1 &`;
    const result = await sshExec(cmd);
    return `Hashcat started in background.\n\nUse hashcat_status to check progress.\nSession: ${args.session || 'hashcat'}\nLog: /tmp/hashcat_output.log`;
  }

  const result = await sshExec(cmd, 600000); // 10 minute timeout
  return `Command: ${cmd}\n\n${result.stdout}\n${result.stderr}`;
}

async function handleHashcatStatus(args: any): Promise<string> {
  const session = args.session || "hashcat";

  // Try to get status from running process
  const cmd = `${HASHCAT_PATH} --session=${session} --status`;
  const result = await sshExec(cmd, 30000);

  // Also check for background log
  const logResult = await sshExec("tail -50 /tmp/hashcat_output.log 2>/dev/null || echo 'No background log found'", 10000);

  return `Session Status:\n${result.stdout}\n${result.stderr}\n\nBackground Log (last 50 lines):\n${logResult.stdout}`;
}

async function handleHashcatShow(args: any): Promise<string> {
  const hashMode = parseHashMode(args.hash_mode);
  let cmd = `${HASHCAT_PATH} -m ${hashMode} --show '${args.hash}'`;

  if (args.potfile) {
    cmd += ` --potfile-path=${args.potfile}`;
  }

  const result = await sshExec(cmd, 60000);

  if (!result.stdout.trim() && !result.stderr.includes("error")) {
    return "No cracked passwords found for this hash.";
  }

  return `Cracked passwords:\n${result.stdout}\n${result.stderr}`;
}

async function handleHashcatBenchmark(args: any): Promise<string> {
  let cmd = `${HASHCAT_PATH} -b`;

  if (args.hash_mode !== undefined) {
    const hashMode = parseHashMode(args.hash_mode);
    cmd += ` -m ${hashMode}`;
  }

  if (args.workload) {
    cmd += ` -w ${args.workload}`;
  }

  // Benchmark can take a while
  const result = await sshExec(cmd, 600000);
  return `Benchmark Results:\n${result.stdout}\n${result.stderr}`;
}

async function handleHashcatModes(args: any): Promise<string> {
  const cmd = `${HASHCAT_PATH} --help | grep -E "^\\s+[0-9]+"`;
  const result = await sshExec(cmd, 30000);

  let output = result.stdout;

  if (args.filter) {
    const filter = args.filter.toLowerCase();
    const lines = output.split("\n").filter(line =>
      line.toLowerCase().includes(filter)
    );
    output = lines.join("\n");

    if (!output.trim()) {
      return `No hash modes found matching '${args.filter}'.\n\nCommon modes:\n${Object.entries(HASH_MODES).map(([k, v]) => `  ${k}: ${v.mode} - ${v.description}`).join("\n")}`;
    }
  }

  return `Available hash modes${args.filter ? ` matching '${args.filter}'` : ""}:\n${output}\n\nCommon shortcuts:\n${Object.entries(HASH_MODES).map(([k, v]) => `  ${k}: ${v.mode}`).join("\n")}`;
}

async function handleHashcatAttackModes(_args: any): Promise<string> {
  let output = "Hashcat Attack Modes:\n\n";

  for (const [name, info] of Object.entries(ATTACK_MODES)) {
    output += `${info.mode}. ${name.toUpperCase()}\n`;
    output += `   ${info.description}\n`;
    output += `   Example: ${info.example}\n\n`;
  }

  output += "\nCharsets for Mask Attacks:\n";
  for (const [charset, desc] of Object.entries(CHARSETS)) {
    output += `  ${charset} = ${desc}\n`;
  }

  return output;
}

async function handleHashcatRules(args: any): Promise<string> {
  if (args.show) {
    const result = await sshExec(`head -100 '${args.show}'`, 30000);
    return `Rule file contents (first 100 lines):\n${result.stdout}\n${result.stderr}`;
  }

  // List available rule files
  const result = await sshExec("find /usr/share/hashcat/rules -name '*.rule' 2>/dev/null | head -50", 30000);

  return `Available rule files:\n${result.stdout}\n\nPopular rules:\n  /usr/share/hashcat/rules/best64.rule - Fast, best results per time\n  /usr/share/hashcat/rules/rockyou-30000.rule - Large ruleset from RockYou analysis\n  /usr/share/hashcat/rules/d3ad0ne.rule - Community favorite\n  /usr/share/hashcat/rules/dive.rule - Deep dive rules\n  /usr/share/hashcat/rules/OneRuleToRuleThemAll.rule - Comprehensive ruleset`;
}

async function handleHashcatRestore(args: any): Promise<string> {
  const cmd = `${HASHCAT_PATH} --session=${args.session} --restore`;
  const result = await sshExec(cmd, 600000);
  return `Restoring session '${args.session}':\n${result.stdout}\n${result.stderr}`;
}

async function handleHashcatStop(args: any): Promise<string> {
  const session = args.session || "hashcat";

  // Send checkpoint signal to hashcat process
  const result = await sshExec(`pkill -USR1 -f "hashcat.*--session=${session}" && sleep 2 && pkill -f "hashcat.*--session=${session}"`, 30000);

  return `Stop signal sent to session '${session}'. Progress has been saved and can be restored with hashcat_restore.\n${result.stdout}\n${result.stderr}`;
}

async function handleHashcatWordlists(args: any): Promise<string> {
  const path = args.path || "/usr/share/wordlists";
  const result = await sshExec(`find '${path}' -type f \\( -name '*.txt' -o -name '*.lst' -o -name '*.dic' \\) 2>/dev/null | head -100`, 30000);

  // Also check file sizes
  const sizeResult = await sshExec(`ls -lhS '${path}'/*.txt '${path}'/*.gz 2>/dev/null | head -20`, 30000);

  return `Wordlists in ${path}:\n${result.stdout}\n\nLargest files:\n${sizeResult.stdout}\n\nTip: rockyou.txt is typically at /usr/share/wordlists/rockyou.txt (may need to extract from rockyou.txt.gz)`;
}

async function handleHashcatIdentify(args: any): Promise<string> {
  // Use hashid or hash-identifier if available, otherwise do basic pattern matching
  const hash = args.hash;

  // Try hashid first
  const hashidResult = await sshExec(`hashid '${hash}' 2>/dev/null || echo 'hashid not available'`, 30000);

  if (!hashidResult.stdout.includes("not available")) {
    return `Hash Identification:\n${hashidResult.stdout}`;
  }

  // Fallback to pattern-based identification
  let possibleTypes: string[] = [];
  const hashLength = hash.replace(/[^a-fA-F0-9]/g, "").length;

  if (hashLength === 32 && /^[a-fA-F0-9]+$/.test(hash)) {
    possibleTypes.push("MD5 (mode 0)", "NTLM (mode 1000)", "MD4 (mode 900)");
  } else if (hashLength === 40 && /^[a-fA-F0-9]+$/.test(hash)) {
    possibleTypes.push("SHA1 (mode 100)", "MySQL5 (mode 300)");
  } else if (hashLength === 64 && /^[a-fA-F0-9]+$/.test(hash)) {
    possibleTypes.push("SHA256 (mode 1400)", "SHA3-256 (mode 17400)");
  } else if (hashLength === 128 && /^[a-fA-F0-9]+$/.test(hash)) {
    possibleTypes.push("SHA512 (mode 1700)", "SHA3-512 (mode 17600)");
  } else if (hash.startsWith("$1$")) {
    possibleTypes.push("md5crypt (mode 500)");
  } else if (hash.startsWith("$5$")) {
    possibleTypes.push("sha256crypt (mode 7400)");
  } else if (hash.startsWith("$6$")) {
    possibleTypes.push("sha512crypt (mode 1800)");
  } else if (hash.startsWith("$2a$") || hash.startsWith("$2b$") || hash.startsWith("$2y$")) {
    possibleTypes.push("bcrypt (mode 3200)");
  } else if (hash.startsWith("$argon2")) {
    possibleTypes.push("Argon2 (mode 34000)");
  } else if (hash.includes("::") && hash.includes(":")) {
    possibleTypes.push("NetNTLMv2 (mode 5600)", "NetNTLMv1 (mode 5500)");
  }

  if (possibleTypes.length === 0) {
    return `Could not identify hash type.\n\nHash: ${hash}\nLength: ${hash.length} chars\n\nTip: Install hashid on the remote system for better identification:\n  sudo apt install hashid`;
  }

  return `Possible hash types:\n${possibleTypes.map(t => `  - ${t}`).join("\n")}\n\nNote: For accurate identification, install hashid on the remote system.`;
}

async function handleHashcatSessions(_args: any): Promise<string> {
  const result = await sshExec("ls -la ~/.local/share/hashcat/sessions/ 2>/dev/null || ls -la ~/.hashcat/sessions/ 2>/dev/null || echo 'No sessions directory found'", 30000);

  // Also check for .restore files
  const restoreResult = await sshExec("find ~ -name '*.restore' -type f 2>/dev/null | head -20", 30000);

  return `Saved Sessions:\n${result.stdout}\n\nRestore Files:\n${restoreResult.stdout || "None found"}`;
}

// Main server setup
const server = new Server(
  {
    name: "hashcat-mcp",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Register tool handlers
server.setRequestHandler(ListToolsRequestSchema, async () => ({
  tools,
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    let result: string;

    switch (name) {
      case "hashcat_crack":
        result = await handleHashcatCrack(args);
        break;
      case "hashcat_status":
        result = await handleHashcatStatus(args);
        break;
      case "hashcat_show":
        result = await handleHashcatShow(args);
        break;
      case "hashcat_benchmark":
        result = await handleHashcatBenchmark(args);
        break;
      case "hashcat_modes":
        result = await handleHashcatModes(args);
        break;
      case "hashcat_attack_modes":
        result = await handleHashcatAttackModes(args);
        break;
      case "hashcat_rules":
        result = await handleHashcatRules(args);
        break;
      case "hashcat_restore":
        result = await handleHashcatRestore(args);
        break;
      case "hashcat_stop":
        result = await handleHashcatStop(args);
        break;
      case "hashcat_wordlists":
        result = await handleHashcatWordlists(args);
        break;
      case "hashcat_identify":
        result = await handleHashcatIdentify(args);
        break;
      case "hashcat_sessions":
        result = await handleHashcatSessions(args);
        break;
      default:
        throw new Error(`Unknown tool: ${name}`);
    }

    return {
      content: [{ type: "text", text: result }],
    };
  } catch (error: any) {
    return {
      content: [{ type: "text", text: `Error: ${error.message}` }],
      isError: true,
    };
  }
});

// Start the server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Hashcat MCP server running on stdio");
}

main().catch(console.error);
