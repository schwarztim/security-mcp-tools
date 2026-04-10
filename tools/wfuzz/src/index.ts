#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { spawn } from "child_process";

// SSH configuration for Kali
const KALI_HOST = process.env.WFUZZ_KALI_HOST || "kali";
const SSH_OPTIONS = ["-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes"];

interface WfuzzOptions {
  url: string;
  payloads?: PayloadConfig[];
  wordlist?: string;
  method?: string;
  data?: string;
  headers?: Record<string, string>;
  cookies?: string[];
  hideCode?: number[];
  showCode?: number[];
  hideLines?: number;
  hideWords?: number;
  hideChars?: number;
  filter?: string;
  prefilter?: string;
  encoder?: string;
  iterator?: "zip" | "chain" | "product";
  recursion?: number;
  threads?: number;
  delay?: number;
  timeout?: number;
  proxy?: string;
  auth?: { type: "basic" | "ntlm" | "digest"; credentials: string };
  followRedirects?: boolean;
  scripts?: string[];
  recipe?: string;
  outputFormat?: "json" | "csv" | "html" | "raw";
  ignoreErrors?: boolean;
  verbose?: boolean;
}

interface PayloadConfig {
  type: string;
  params?: string;
  encoder?: string;
  slice?: string;
}

interface FuzzResult {
  success: boolean;
  results?: WfuzzResult[];
  command: string;
  stdout: string;
  stderr: string;
  error?: string;
}

interface WfuzzResult {
  id: number;
  code: number;
  lines: number;
  words: number;
  chars: number;
  payload: string;
  url?: string;
}

// Execute command via SSH on Kali
async function executeOnKali(command: string): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  return new Promise((resolve) => {
    const args = [...SSH_OPTIONS, KALI_HOST, command];
    const proc = spawn("ssh", args);

    let stdout = "";
    let stderr = "";

    proc.stdout.on("data", (data) => {
      stdout += data.toString();
    });

    proc.stderr.on("data", (data) => {
      stderr += data.toString();
    });

    proc.on("close", (code) => {
      resolve({ stdout, stderr, exitCode: code ?? 1 });
    });

    proc.on("error", (err) => {
      resolve({ stdout, stderr: err.message, exitCode: 1 });
    });
  });
}

// Build wfuzz command from options
function buildWfuzzCommand(options: WfuzzOptions): string {
  const args: string[] = ["wfuzz"];

  // Output format for parsing
  args.push("-f", "-,json");

  // Payloads
  if (options.payloads && options.payloads.length > 0) {
    for (const payload of options.payloads) {
      let payloadArg = payload.type;
      if (payload.params) {
        payloadArg += `,${payload.params}`;
      }
      if (payload.encoder) {
        payloadArg += `,${payload.encoder}`;
      }
      args.push("-z", payloadArg);
      if (payload.slice) {
        args.push("--slice", payload.slice);
      }
    }
  } else if (options.wordlist) {
    args.push("-w", options.wordlist);
  }

  // HTTP method
  if (options.method) {
    args.push("-X", options.method);
  }

  // POST data
  if (options.data) {
    args.push("-d", `'${options.data}'`);
  }

  // Headers
  if (options.headers) {
    for (const [key, value] of Object.entries(options.headers)) {
      args.push("-H", `'${key}: ${value}'`);
    }
  }

  // Cookies
  if (options.cookies) {
    for (const cookie of options.cookies) {
      args.push("-b", `'${cookie}'`);
    }
  }

  // Hide filters
  if (options.hideCode && options.hideCode.length > 0) {
    args.push("--hc", options.hideCode.join(","));
  }
  if (options.showCode && options.showCode.length > 0) {
    args.push("--sc", options.showCode.join(","));
  }
  if (options.hideLines !== undefined) {
    args.push("--hl", options.hideLines.toString());
  }
  if (options.hideWords !== undefined) {
    args.push("--hw", options.hideWords.toString());
  }
  if (options.hideChars !== undefined) {
    args.push("--hh", options.hideChars.toString());
  }

  // Advanced filter
  if (options.filter) {
    args.push("--filter", `'${options.filter}'`);
  }
  if (options.prefilter) {
    args.push("--prefilter", `'${options.prefilter}'`);
  }

  // Iterator
  if (options.iterator) {
    args.push("-m", options.iterator);
  }

  // Performance options
  if (options.threads) {
    args.push("-t", options.threads.toString());
  }
  if (options.delay) {
    args.push("-s", options.delay.toString());
  }
  if (options.timeout) {
    args.push("--conn-delay", options.timeout.toString());
  }

  // Recursion
  if (options.recursion) {
    args.push("-R", options.recursion.toString());
  }

  // Proxy
  if (options.proxy) {
    args.push("-p", options.proxy);
  }

  // Authentication
  if (options.auth) {
    args.push(`--${options.auth.type}`, `'${options.auth.credentials}'`);
  }

  // Follow redirects
  if (options.followRedirects) {
    args.push("-L");
  }

  // Scripts
  if (options.scripts && options.scripts.length > 0) {
    args.push("--script", options.scripts.join(","));
  }

  // Recipe
  if (options.recipe) {
    args.push("--recipe", options.recipe);
  }

  // Ignore errors
  if (options.ignoreErrors) {
    args.push("-Z");
  }

  // Verbose
  if (options.verbose) {
    args.push("-v");
  }

  // URL (must be last)
  args.push(`'${options.url}'`);

  return args.join(" ");
}

// Parse JSON output from wfuzz
function parseWfuzzOutput(stdout: string): WfuzzResult[] {
  const results: WfuzzResult[] = [];
  const lines = stdout.split("\n").filter(line => line.trim());

  for (const line of lines) {
    try {
      const parsed = JSON.parse(line);
      if (parsed && typeof parsed === "object") {
        results.push({
          id: parsed.id || 0,
          code: parsed.code || 0,
          lines: parsed.lines || 0,
          words: parsed.words || 0,
          chars: parsed.chars || 0,
          payload: parsed.payload || "",
          url: parsed.url,
        });
      }
    } catch {
      // Skip non-JSON lines
    }
  }

  return results;
}

// Define available tools
const tools: Tool[] = [
  {
    name: "wfuzz_fuzz",
    description: "Execute wfuzz fuzzing against a target URL. Supports directory brute-forcing, parameter fuzzing, authentication testing, and more. Use FUZZ keyword in URL, data, or headers where payload should be inserted.",
    inputSchema: {
      type: "object",
      properties: {
        url: {
          type: "string",
          description: "Target URL with FUZZ keyword(s) for payload injection points (e.g., http://target.com/FUZZ or http://target.com/?id=FUZZ)",
        },
        wordlist: {
          type: "string",
          description: "Path to wordlist file (e.g., /usr/share/wordlists/dirb/common.txt)",
        },
        payloads: {
          type: "array",
          items: {
            type: "object",
            properties: {
              type: { type: "string", description: "Payload type (file, range, list, stdin, etc.)" },
              params: { type: "string", description: "Payload parameters (e.g., wordlist path, range values)" },
              encoder: { type: "string", description: "Encoder to apply (md5, sha1, base64, urlencode, etc.)" },
              slice: { type: "string", description: "Filter expression for payload elements" },
            },
            required: ["type"],
          },
          description: "Advanced payload configurations (use instead of wordlist for complex scenarios)",
        },
        method: {
          type: "string",
          enum: ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"],
          description: "HTTP method (default: GET)",
        },
        data: {
          type: "string",
          description: "POST data (e.g., 'username=admin&password=FUZZ')",
        },
        headers: {
          type: "object",
          additionalProperties: { type: "string" },
          description: "Custom HTTP headers as key-value pairs",
        },
        cookies: {
          type: "array",
          items: { type: "string" },
          description: "Cookies to include (e.g., ['session=abc123'])",
        },
        hideCode: {
          type: "array",
          items: { type: "number" },
          description: "Hide responses with these HTTP status codes (e.g., [404, 403])",
        },
        showCode: {
          type: "array",
          items: { type: "number" },
          description: "Only show responses with these HTTP status codes (e.g., [200, 301])",
        },
        hideLines: {
          type: "number",
          description: "Hide responses with this number of lines",
        },
        hideWords: {
          type: "number",
          description: "Hide responses with this number of words",
        },
        hideChars: {
          type: "number",
          description: "Hide responses with this number of characters",
        },
        filter: {
          type: "string",
          description: "Advanced filter expression (e.g., 'c=200 and l>97')",
        },
        iterator: {
          type: "string",
          enum: ["zip", "chain", "product"],
          description: "Iterator for combining multiple payloads (zip=pair, chain=sequential, product=cartesian)",
        },
        threads: {
          type: "number",
          description: "Number of concurrent threads (default: 10)",
        },
        delay: {
          type: "number",
          description: "Delay between requests in seconds",
        },
        proxy: {
          type: "string",
          description: "Proxy URL (e.g., http://127.0.0.1:8080 for Burp Suite)",
        },
        auth: {
          type: "object",
          properties: {
            type: { type: "string", enum: ["basic", "ntlm", "digest"] },
            credentials: { type: "string", description: "user:password format" },
          },
          description: "HTTP authentication configuration",
        },
        followRedirects: {
          type: "boolean",
          description: "Follow HTTP redirects",
        },
        recursion: {
          type: "number",
          description: "Recursion depth for directory discovery",
        },
        scripts: {
          type: "array",
          items: { type: "string" },
          description: "Wfuzz scripts to run (e.g., ['robots', 'links'])",
        },
        ignoreErrors: {
          type: "boolean",
          description: "Continue on network errors (show as XXX code)",
        },
        verbose: {
          type: "boolean",
          description: "Enable verbose output",
        },
        maxResults: {
          type: "number",
          description: "Maximum number of results to return (default: 100)",
        },
      },
      required: ["url"],
    },
  },
  {
    name: "wfuzz_payloads",
    description: "List available wfuzz payload types and their descriptions. Payloads generate the fuzzing values.",
    inputSchema: {
      type: "object",
      properties: {
        filter: {
          type: "string",
          description: "Filter payloads by name or category",
        },
      },
    },
  },
  {
    name: "wfuzz_encoders",
    description: "List available wfuzz encoders for transforming payloads (MD5, SHA1, Base64, URL encoding, etc.)",
    inputSchema: {
      type: "object",
      properties: {
        filter: {
          type: "string",
          description: "Filter encoders by name or category",
        },
      },
    },
  },
  {
    name: "wfuzz_iterators",
    description: "List available wfuzz iterators for combining multiple payloads (zip, chain, product)",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "wfuzz_scripts",
    description: "List available wfuzz scripts for analyzing requests/responses. Scripts can discover content, check for vulnerabilities, etc.",
    inputSchema: {
      type: "object",
      properties: {
        filter: {
          type: "string",
          description: "Filter scripts by name or category",
        },
      },
    },
  },
  {
    name: "wfuzz_filters",
    description: "Get documentation on wfuzz filter language for advanced result filtering. Explains operators, functions, and fields available.",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "wfuzz_recipe",
    description: "Save or load wfuzz recipes (configuration files for reusable fuzzing setups)",
    inputSchema: {
      type: "object",
      properties: {
        action: {
          type: "string",
          enum: ["save", "load", "list"],
          description: "Action to perform",
        },
        name: {
          type: "string",
          description: "Recipe name/path",
        },
        config: {
          type: "object",
          description: "Configuration to save (for save action)",
        },
      },
      required: ["action"],
    },
  },
  {
    name: "wfuzz_wordlists",
    description: "List common wordlists available on Kali for fuzzing",
    inputSchema: {
      type: "object",
      properties: {
        category: {
          type: "string",
          enum: ["directories", "files", "passwords", "usernames", "subdomains", "all"],
          description: "Category of wordlists to list",
        },
      },
    },
  },
  {
    name: "wfuzz_help",
    description: "Get wfuzz help and version information",
    inputSchema: {
      type: "object",
      properties: {
        topic: {
          type: "string",
          enum: ["general", "filter", "version"],
          description: "Help topic",
        },
      },
    },
  },
];

// Create MCP server
const server = new Server(
  {
    name: "wfuzz-mcp",
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

// Handle tool execution
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case "wfuzz_fuzz": {
        const options = args as unknown as WfuzzOptions & { maxResults?: number };

        if (!options.url) {
          return {
            content: [{ type: "text", text: "Error: URL is required" }],
            isError: true,
          };
        }

        if (!options.url.includes("FUZZ") && !options.data?.includes("FUZZ") &&
            !Object.values(options.headers || {}).some(h => h.includes("FUZZ"))) {
          return {
            content: [{ type: "text", text: "Warning: No FUZZ keyword found in URL, data, or headers. Wfuzz needs at least one FUZZ placeholder for payload injection." }],
            isError: true,
          };
        }

        if (!options.wordlist && (!options.payloads || options.payloads.length === 0)) {
          return {
            content: [{ type: "text", text: "Error: Either wordlist or payloads must be specified" }],
            isError: true,
          };
        }

        const command = buildWfuzzCommand(options);
        const { stdout, stderr, exitCode } = await executeOnKali(command);

        const results = parseWfuzzOutput(stdout);
        const maxResults = options.maxResults || 100;
        const limitedResults = results.slice(0, maxResults);

        const response: FuzzResult = {
          success: exitCode === 0,
          results: limitedResults,
          command: command,
          stdout: stdout.substring(0, 5000),
          stderr: stderr,
        };

        if (exitCode !== 0 && !options.ignoreErrors) {
          response.error = `Wfuzz exited with code ${exitCode}`;
        }

        let summary = `## Wfuzz Results\n\n`;
        summary += `**Command:** \`${command}\`\n\n`;
        summary += `**Found:** ${results.length} results`;
        if (results.length > maxResults) {
          summary += ` (showing first ${maxResults})`;
        }
        summary += `\n\n`;

        if (limitedResults.length > 0) {
          summary += `| ID | Code | Lines | Words | Chars | Payload |\n`;
          summary += `|----|------|-------|-------|-------|----------|\n`;
          for (const r of limitedResults) {
            summary += `| ${r.id} | ${r.code} | ${r.lines} | ${r.words} | ${r.chars} | ${r.payload} |\n`;
          }
        }

        if (stderr && stderr.trim()) {
          summary += `\n\n**Warnings/Errors:**\n\`\`\`\n${stderr.substring(0, 1000)}\n\`\`\``;
        }

        return {
          content: [{ type: "text", text: summary }],
        };
      }

      case "wfuzz_payloads": {
        const filter = (args?.filter as string) || "";
        const { stdout, stderr } = await executeOnKali(`wfuzz -e payloads 2>&1 | grep -i '${filter}'`);

        return {
          content: [{
            type: "text",
            text: `## Available Wfuzz Payloads\n\n\`\`\`\n${stdout || stderr}\n\`\`\`\n\n**Common Payloads:**\n- \`file\`: Read from file (wordlist)\n- \`range\`: Generate numeric range (e.g., 1-100)\n- \`list\`: Inline list (e.g., a-b-c)\n- \`stdin\`: Read from stdin\n- \`buffer_overflow\`: Generate overflow strings\n- \`hexrange\`: Generate hex range\n- \`iprange\`: Generate IP address range\n- \`permutation\`: Generate permutations`,
          }],
        };
      }

      case "wfuzz_encoders": {
        const filter = (args?.filter as string) || "";
        const { stdout, stderr } = await executeOnKali(`wfuzz -e encoders 2>&1 | grep -i '${filter}'`);

        return {
          content: [{
            type: "text",
            text: `## Available Wfuzz Encoders\n\n\`\`\`\n${stdout || stderr}\n\`\`\`\n\n**Common Encoders:**\n- \`md5\`, \`sha1\`, \`sha256\`: Hash encoders\n- \`base64\`: Base64 encoding\n- \`urlencode\`, \`urldecode\`: URL encoding\n- \`html_encode\`, \`html_decode\`: HTML encoding\n- \`hexlify\`, \`unhexlify\`: Hex encoding\n- \`random_upper\`: Randomize case\n\n**Chaining Encoders:**\n- Use \`@\` to chain: \`md5@base64\`\n- Use \`-\` for alternatives: \`md5-sha1-none\`\n- Use category name for all in category: \`hashes\``,
          }],
        };
      }

      case "wfuzz_iterators": {
        const { stdout, stderr } = await executeOnKali(`wfuzz -e iterators 2>&1`);

        return {
          content: [{
            type: "text",
            text: `## Available Wfuzz Iterators\n\n\`\`\`\n${stdout || stderr}\n\`\`\`\n\n**Iterator Types:**\n\n### zip (default)\nPairs elements from payloads sequentially:\n- Payload1: [a, b, c]\n- Payload2: [1, 2, 3]\n- Result: [(a,1), (b,2), (c,3)]\n\n### chain\nConcatenates payloads sequentially:\n- Payload1: [a, b]\n- Payload2: [1, 2]\n- Result: [a, b, 1, 2]\n\n### product\nCartesian product (all combinations):\n- Payload1: [a, b]\n- Payload2: [1, 2]\n- Result: [(a,1), (a,2), (b,1), (b,2)]\n\n**Usage:** \`wfuzz -m product -z list,a-b -z list,1-2 http://target/FUZZ/FUZ2Z\``,
          }],
        };
      }

      case "wfuzz_scripts": {
        const filter = (args?.filter as string) || "";
        const { stdout, stderr } = await executeOnKali(`wfuzz -e scripts 2>&1 | grep -i '${filter}'`);

        return {
          content: [{
            type: "text",
            text: `## Available Wfuzz Scripts\n\n\`\`\`\n${stdout || stderr}\n\`\`\`\n\n**Script Categories:**\n- **passive**: Analyze without new requests\n- **active**: Probe with additional requests\n- **discovery**: Auto-enqueue discovered content\n\n**Common Scripts:**\n- \`robots\`: Parse robots.txt\n- \`links\`: Extract links from responses\n- \`headers\`: Analyze HTTP headers\n- \`cookies\`: Analyze cookies\n- \`backups\`: Check for backup files\n\n**Usage:** \`--script=robots,links\` or \`-A\` for default scripts`,
          }],
        };
      }

      case "wfuzz_filters": {
        return {
          content: [{
            type: "text",
            text: `## Wfuzz Filter Language\n\n### Response Fields\n- \`c\`: HTTP response code\n- \`l\`: Number of lines\n- \`w\`: Number of words\n- \`h\`: Number of chars (size)\n- \`r\`: Response text\n- \`url\`: Request URL\n\n### Operators\n- \`and\`, \`or\`, \`not\`: Logical operators\n- \`=\`, \`!=\`, \`<\`, \`>\`, \`<=\`, \`>=\`: Comparison\n- \`=~\`: Regex match\n- \`~\`: Contains substring\n- \`!~\`: Does not contain\n\n### Functions\n- \`|upper()\`: Convert to uppercase\n- \`|lower()\`: Convert to lowercase\n- \`|encode(enc)\`: Apply encoder\n- \`|unique()\`: Remove duplicates\n- \`|startswith(str)\`: Check prefix\n\n### Examples\n\`\`\`bash\n# Show only 200 responses with >100 lines\n--filter "c=200 and l>100"\n\n# Hide responses containing "Not Found"\n--filter "r!~'Not Found'"\n\n# Show redirects\n--filter "c=301 or c=302"\n\n# Complex filter\n--filter "c=200 and (w>50 or h>1000)"\n\`\`\`\n\n### Hide/Show Shortcuts\n- \`--hc 404,403\`: Hide codes\n- \`--sc 200,301\`: Show only codes\n- \`--hl 10\`: Hide by line count\n- \`--hw 50\`: Hide by word count\n- \`--hh 1000\`: Hide by char count`,
          }],
        };
      }

      case "wfuzz_recipe": {
        const action = args?.action as string;
        const recipeName = args?.name as string;

        switch (action) {
          case "list": {
            const { stdout, stderr } = await executeOnKali(`ls -la ~/.wfuzz/*.recipe 2>/dev/null || echo "No recipes found"`);
            return {
              content: [{
                type: "text",
                text: `## Saved Wfuzz Recipes\n\n\`\`\`\n${stdout || stderr}\n\`\`\``,
              }],
            };
          }
          case "load": {
            if (!recipeName) {
              return {
                content: [{ type: "text", text: "Error: Recipe name is required" }],
                isError: true,
              };
            }
            const { stdout, stderr } = await executeOnKali(`cat ~/.wfuzz/${recipeName}.recipe 2>/dev/null || cat ${recipeName} 2>/dev/null || echo "Recipe not found"`);
            return {
              content: [{
                type: "text",
                text: `## Recipe: ${recipeName}\n\n\`\`\`\n${stdout || stderr}\n\`\`\`\n\n**To use:** \`wfuzz --recipe ${recipeName}\``,
              }],
            };
          }
          case "save": {
            const config = args?.config as WfuzzOptions;
            if (!recipeName || !config) {
              return {
                content: [{ type: "text", text: "Error: Recipe name and config are required" }],
                isError: true,
              };
            }
            const command = buildWfuzzCommand(config);
            const saveCommand = `${command} --dump-recipe ~/.wfuzz/${recipeName}.recipe`;
            const { stdout, stderr, exitCode } = await executeOnKali(saveCommand);
            return {
              content: [{
                type: "text",
                text: exitCode === 0
                  ? `## Recipe Saved\n\nRecipe saved to: ~/.wfuzz/${recipeName}.recipe\n\n**Command:** \`${saveCommand}\``
                  : `## Error Saving Recipe\n\n${stderr || stdout}`,
              }],
              isError: exitCode !== 0,
            };
          }
          default:
            return {
              content: [{ type: "text", text: "Error: Invalid action. Use 'list', 'load', or 'save'" }],
              isError: true,
            };
        }
      }

      case "wfuzz_wordlists": {
        const category = (args?.category as string) || "all";
        let command = "";

        const wordlistPaths: Record<string, string[]> = {
          directories: [
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/wordlists/dirb/big.txt",
            "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
            "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
          ],
          files: [
            "/usr/share/wordlists/dirb/extensions_common.txt",
            "/usr/share/seclists/Discovery/Web-Content/raft-medium-files.txt",
            "/usr/share/seclists/Discovery/Web-Content/common.txt",
          ],
          passwords: [
            "/usr/share/wordlists/rockyou.txt",
            "/usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt",
            "/usr/share/seclists/Passwords/darkweb2017-top10000.txt",
          ],
          usernames: [
            "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
            "/usr/share/seclists/Usernames/Names/names.txt",
            "/usr/share/seclists/Usernames/cirt-default-usernames.txt",
          ],
          subdomains: [
            "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
            "/usr/share/seclists/Discovery/DNS/fierce-hostlist.txt",
          ],
        };

        if (category === "all") {
          command = `ls -la /usr/share/wordlists/ /usr/share/seclists/Discovery/Web-Content/ 2>/dev/null | head -50`;
        } else {
          const paths = wordlistPaths[category] || [];
          command = `for f in ${paths.join(" ")}; do ls -lh "$f" 2>/dev/null; done`;
        }

        const { stdout, stderr } = await executeOnKali(command);

        let response = `## Available Wordlists\n\n`;

        if (category !== "all") {
          response += `### ${category.charAt(0).toUpperCase() + category.slice(1)} Wordlists\n\n`;
          const paths = wordlistPaths[category] || [];
          for (const path of paths) {
            response += `- \`${path}\`\n`;
          }
          response += `\n`;
        }

        response += `\`\`\`\n${stdout || stderr}\n\`\`\`\n\n`;
        response += `**Common Wordlist Locations:**\n`;
        response += `- /usr/share/wordlists/\n`;
        response += `- /usr/share/seclists/\n`;
        response += `- /usr/share/dirb/wordlists/\n`;
        response += `- /usr/share/dirbuster/wordlists/\n`;

        return {
          content: [{ type: "text", text: response }],
        };
      }

      case "wfuzz_help": {
        const topic = (args?.topic as string) || "general";
        let command = "";

        switch (topic) {
          case "version":
            command = "wfuzz --version";
            break;
          case "filter":
            command = "wfuzz --filter-help";
            break;
          default:
            command = "wfuzz --help";
        }

        const { stdout, stderr } = await executeOnKali(command);

        return {
          content: [{
            type: "text",
            text: `## Wfuzz Help: ${topic}\n\n\`\`\`\n${stdout || stderr}\n\`\`\``,
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
      content: [{ type: "text", text: `Error executing ${name}: ${errorMessage}` }],
      isError: true,
    };
  }
});

// Start server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Wfuzz MCP server started");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
