#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import * as fs from "fs";
import * as path from "path";
import { execSync } from "child_process";

// SecLists paths to check (in order of preference)
const SECLISTS_PATHS = [
  process.env.SECLISTS_PATH,
  "/usr/share/seclists",
  "/usr/share/wordlists/seclists",
  path.join(process.env.HOME || "", "SecLists"),
  path.join(process.env.HOME || "", "seclists"),
  "/opt/seclists",
  "/opt/SecLists",
].filter(Boolean) as string[];

// Known SecLists categories with descriptions
const CATEGORIES: Record<string, string> = {
  "Discovery": "Web content, DNS, SNMP, and infrastructure discovery wordlists",
  "Discovery/DNS": "DNS enumeration wordlists (subdomains, zone transfers)",
  "Discovery/Web-Content": "Common directories, files, and backup artifacts",
  "Discovery/Infrastructure": "Network and infrastructure discovery",
  "Discovery/SNMP": "SNMP community strings",
  "Fuzzing": "Fuzzing payloads for various injection attacks",
  "Fuzzing/SQLi": "SQL injection payloads (generic and DB-specific)",
  "Fuzzing/XSS": "Cross-site scripting vectors and polyglots",
  "Fuzzing/command-injection-commix": "OS command injection payloads",
  "Fuzzing/LFI": "Local file inclusion payloads",
  "Fuzzing/Databases": "Database-specific fuzzing strings",
  "Passwords": "Password lists for brute force and credential testing",
  "Passwords/Common-Credentials": "Commonly used username/password combos",
  "Passwords/Leaked-Databases": "Passwords from known data breaches",
  "Passwords/Default-Credentials": "Default credentials for various systems",
  "Usernames": "Username wordlists for enumeration",
  "Usernames/Names": "Common names (first, last, full)",
  "Payloads": "Attack payloads and shells",
  "Payloads/Shells": "Web shells and backdoors (analysis purposes)",
  "Pattern-Matching": "Patterns for sensitive data detection (SSN, CC, etc.)",
  "Miscellaneous": "Miscellaneous wordlists and utility files",
  "IOCs": "Indicators of Compromise",
};

// Popular wordlists with descriptions
const POPULAR_WORDLISTS: Record<string, string> = {
  "Discovery/Web-Content/raft-large-directories.txt": "Comprehensive directory names (~62k entries)",
  "Discovery/Web-Content/raft-large-files.txt": "Comprehensive filenames (~37k entries)",
  "Discovery/Web-Content/common.txt": "Common web paths (~4.6k entries)",
  "Discovery/Web-Content/directory-list-2.3-medium.txt": "DirBuster medium list (~220k entries)",
  "Discovery/Web-Content/directory-list-2.3-small.txt": "DirBuster small list (~87k entries)",
  "Discovery/DNS/subdomains-top1million-5000.txt": "Top 5000 subdomains",
  "Discovery/DNS/subdomains-top1million-20000.txt": "Top 20000 subdomains",
  "Discovery/DNS/subdomains-top1million-110000.txt": "Top 110000 subdomains",
  "Passwords/Common-Credentials/10-million-password-list-top-1000.txt": "Top 1000 passwords",
  "Passwords/Common-Credentials/10-million-password-list-top-10000.txt": "Top 10000 passwords",
  "Passwords/Common-Credentials/10-million-password-list-top-100000.txt": "Top 100000 passwords",
  "Passwords/Leaked-Databases/rockyou.txt": "RockYou breach passwords (~14M entries)",
  "Fuzzing/SQLi/Generic-SQLi.txt": "Generic SQL injection payloads",
  "Fuzzing/XSS/XSS-Bypass-Strings-BruteLogic.txt": "XSS filter bypass strings",
  "Fuzzing/LFI/LFI-Jhaddix.txt": "LFI payloads from Jhaddix",
  "Usernames/Names/names.txt": "Common names (~10k entries)",
  "Usernames/xato-net-10-million-usernames.txt": "Large username list",
};

class SecListsMCP {
  private server: Server;
  private seclistsPath: string | null = null;

  constructor() {
    this.server = new Server(
      {
        name: "seclists-mcp",
        version: "1.0.0",
      },
      {
        capabilities: {
          tools: {},
        },
      }
    );

    this.findSecLists();
    this.setupHandlers();
  }

  private findSecLists(): void {
    for (const p of SECLISTS_PATHS) {
      if (fs.existsSync(p) && fs.statSync(p).isDirectory()) {
        // Verify it looks like SecLists (has Discovery or Passwords dir)
        const hasDiscovery = fs.existsSync(path.join(p, "Discovery"));
        const hasPasswords = fs.existsSync(path.join(p, "Passwords"));
        if (hasDiscovery || hasPasswords) {
          this.seclistsPath = p;
          return;
        }
      }
    }
  }

  private setupHandlers(): void {
    this.server.setRequestHandler(ListToolsRequestSchema, async () => ({
      tools: this.getTools(),
    }));

    this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
      const { name, arguments: args } = request.params;

      try {
        switch (name) {
          case "seclists_status":
            return this.handleStatus();
          case "seclists_install":
            return await this.handleInstall(args as { path?: string });
          case "seclists_categories":
            return this.handleCategories();
          case "seclists_list":
            return this.handleList(args as { category?: string; pattern?: string });
          case "seclists_search":
            return this.handleSearch(args as { query: string; category?: string });
          case "seclists_get":
            return this.handleGet(args as { name: string });
          case "seclists_preview":
            return this.handlePreview(args as { name: string; lines?: number; offset?: number });
          case "seclists_count":
            return this.handleCount(args as { name: string });
          case "seclists_combine":
            return this.handleCombine(args as { wordlists: string[]; dedupe?: boolean; output?: string });
          case "seclists_popular":
            return this.handlePopular(args as { category?: string });
          default:
            return {
              content: [{ type: "text", text: `Unknown tool: ${name}` }],
              isError: true,
            };
        }
      } catch (error) {
        const errorMsg = error instanceof Error ? error.message : String(error);
        return {
          content: [{ type: "text", text: `Error: ${errorMsg}` }],
          isError: true,
        };
      }
    });
  }

  private getTools(): Tool[] {
    return [
      {
        name: "seclists_status",
        description: "Check SecLists installation status and path",
        inputSchema: {
          type: "object",
          properties: {},
          required: [],
        },
      },
      {
        name: "seclists_install",
        description: "Install or configure SecLists path. If not installed, clones from GitHub.",
        inputSchema: {
          type: "object",
          properties: {
            path: {
              type: "string",
              description: "Custom path to install SecLists (default: ~/SecLists)",
            },
          },
          required: [],
        },
      },
      {
        name: "seclists_categories",
        description: "List all SecLists categories with descriptions",
        inputSchema: {
          type: "object",
          properties: {},
          required: [],
        },
      },
      {
        name: "seclists_list",
        description: "List available wordlists, optionally filtered by category or pattern",
        inputSchema: {
          type: "object",
          properties: {
            category: {
              type: "string",
              description: "Category to list (e.g., 'Discovery/Web-Content', 'Passwords')",
            },
            pattern: {
              type: "string",
              description: "Glob pattern to filter results (e.g., '*.txt', 'raft-*')",
            },
          },
          required: [],
        },
      },
      {
        name: "seclists_search",
        description: "Search for wordlists by name or content keywords",
        inputSchema: {
          type: "object",
          properties: {
            query: {
              type: "string",
              description: "Search query (searches filenames and paths)",
            },
            category: {
              type: "string",
              description: "Limit search to specific category",
            },
          },
          required: ["query"],
        },
      },
      {
        name: "seclists_get",
        description: "Get the full path to a specific wordlist",
        inputSchema: {
          type: "object",
          properties: {
            name: {
              type: "string",
              description: "Wordlist name or partial path (e.g., 'rockyou.txt' or 'Discovery/Web-Content/common.txt')",
            },
          },
          required: ["name"],
        },
      },
      {
        name: "seclists_preview",
        description: "Preview the contents of a wordlist (first N lines)",
        inputSchema: {
          type: "object",
          properties: {
            name: {
              type: "string",
              description: "Wordlist name or path",
            },
            lines: {
              type: "number",
              description: "Number of lines to preview (default: 20, max: 100)",
            },
            offset: {
              type: "number",
              description: "Line offset to start from (default: 0)",
            },
          },
          required: ["name"],
        },
      },
      {
        name: "seclists_count",
        description: "Count entries in a wordlist",
        inputSchema: {
          type: "object",
          properties: {
            name: {
              type: "string",
              description: "Wordlist name or path",
            },
          },
          required: ["name"],
        },
      },
      {
        name: "seclists_combine",
        description: "Combine multiple wordlists into one, optionally deduplicating",
        inputSchema: {
          type: "object",
          properties: {
            wordlists: {
              type: "array",
              items: { type: "string" },
              description: "Array of wordlist names/paths to combine",
            },
            dedupe: {
              type: "boolean",
              description: "Remove duplicate entries (default: true)",
            },
            output: {
              type: "string",
              description: "Output file path (if not specified, returns content)",
            },
          },
          required: ["wordlists"],
        },
      },
      {
        name: "seclists_popular",
        description: "List popular/recommended wordlists with descriptions",
        inputSchema: {
          type: "object",
          properties: {
            category: {
              type: "string",
              description: "Filter by category (e.g., 'Discovery', 'Passwords', 'Fuzzing')",
            },
          },
          required: [],
        },
      },
    ];
  }

  private handleStatus() {
    if (this.seclistsPath) {
      // Count files
      let fileCount = 0;
      let totalSize = 0;
      const countFiles = (dir: string) => {
        try {
          const entries = fs.readdirSync(dir, { withFileTypes: true });
          for (const entry of entries) {
            const fullPath = path.join(dir, entry.name);
            if (entry.isDirectory() && !entry.name.startsWith(".")) {
              countFiles(fullPath);
            } else if (entry.isFile() && entry.name.endsWith(".txt")) {
              fileCount++;
              totalSize += fs.statSync(fullPath).size;
            }
          }
        } catch { /* ignore permission errors */ }
      };
      countFiles(this.seclistsPath);

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            installed: true,
            path: this.seclistsPath,
            wordlistCount: fileCount,
            totalSize: `${(totalSize / 1024 / 1024).toFixed(2)} MB`,
            categories: Object.keys(CATEGORIES).filter(c => !c.includes("/")).length,
          }, null, 2),
        }],
      };
    }

    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          installed: false,
          message: "SecLists not found. Use seclists_install to install it.",
          searchedPaths: SECLISTS_PATHS,
        }, null, 2),
      }],
    };
  }

  private async handleInstall(args: { path?: string }) {
    const installPath = args.path || path.join(process.env.HOME || "", "SecLists");

    if (fs.existsSync(installPath)) {
      this.seclistsPath = installPath;
      this.findSecLists(); // Re-validate
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            success: true,
            message: `SecLists path set to: ${installPath}`,
            path: this.seclistsPath,
          }, null, 2),
        }],
      };
    }

    // Clone from GitHub (shallow clone for speed)
    try {
      const parentDir = path.dirname(installPath);
      if (!fs.existsSync(parentDir)) {
        fs.mkdirSync(parentDir, { recursive: true });
      }

      execSync(`git clone --depth 1 https://github.com/danielmiessler/SecLists.git "${installPath}"`, {
        stdio: "pipe",
        timeout: 300000, // 5 minute timeout
      });

      this.seclistsPath = installPath;
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            success: true,
            message: "SecLists installed successfully",
            path: this.seclistsPath,
          }, null, 2),
        }],
      };
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : String(error);
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            success: false,
            error: `Failed to install SecLists: ${errorMsg}`,
            suggestion: "Try: git clone --depth 1 https://github.com/danielmiessler/SecLists.git ~/SecLists",
          }, null, 2),
        }],
        isError: true,
      };
    }
  }

  private handleCategories() {
    if (!this.seclistsPath) {
      return this.notInstalledError();
    }

    const result: Record<string, { description: string; exists: boolean; wordlistCount?: number }> = {};

    for (const [category, description] of Object.entries(CATEGORIES)) {
      const categoryPath = path.join(this.seclistsPath, category);
      const exists = fs.existsSync(categoryPath);

      let wordlistCount: number | undefined;
      if (exists && fs.statSync(categoryPath).isDirectory()) {
        try {
          const files = this.findWordlists(categoryPath);
          wordlistCount = files.length;
        } catch { /* ignore */ }
      }

      result[category] = { description, exists, wordlistCount };
    }

    return {
      content: [{
        type: "text",
        text: JSON.stringify(result, null, 2),
      }],
    };
  }

  private handleList(args: { category?: string; pattern?: string }) {
    if (!this.seclistsPath) {
      return this.notInstalledError();
    }

    let searchPath = this.seclistsPath;
    if (args.category) {
      searchPath = path.join(this.seclistsPath, args.category);
      if (!fs.existsSync(searchPath)) {
        return {
          content: [{
            type: "text",
            text: `Category not found: ${args.category}`,
          }],
          isError: true,
        };
      }
    }

    const wordlists = this.findWordlists(searchPath, args.pattern);
    const relativeLists = wordlists.map(w => path.relative(this.seclistsPath!, w));

    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          count: relativeLists.length,
          basePath: this.seclistsPath,
          category: args.category || "all",
          pattern: args.pattern || "*",
          wordlists: relativeLists.slice(0, 500), // Limit to 500 results
          truncated: relativeLists.length > 500,
        }, null, 2),
      }],
    };
  }

  private handleSearch(args: { query: string; category?: string }) {
    if (!this.seclistsPath) {
      return this.notInstalledError();
    }

    const query = args.query.toLowerCase();
    let searchPath = this.seclistsPath;
    if (args.category) {
      searchPath = path.join(this.seclistsPath, args.category);
    }

    const allWordlists = this.findWordlists(searchPath);
    const matches = allWordlists.filter(w => {
      const relativePath = path.relative(this.seclistsPath!, w).toLowerCase();
      return relativePath.includes(query);
    });

    const results = matches.slice(0, 50).map(w => ({
      name: path.basename(w),
      path: path.relative(this.seclistsPath!, w),
      fullPath: w,
    }));

    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          query: args.query,
          count: matches.length,
          results,
          truncated: matches.length > 50,
        }, null, 2),
      }],
    };
  }

  private handleGet(args: { name: string }) {
    if (!this.seclistsPath) {
      return this.notInstalledError();
    }

    const wordlistPath = this.resolveWordlistPath(args.name);
    if (!wordlistPath) {
      return {
        content: [{
          type: "text",
          text: `Wordlist not found: ${args.name}`,
        }],
        isError: true,
      };
    }

    const stats = fs.statSync(wordlistPath);
    const lineCount = this.countLines(wordlistPath);

    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          name: path.basename(wordlistPath),
          path: wordlistPath,
          relativePath: path.relative(this.seclistsPath, wordlistPath),
          size: `${(stats.size / 1024).toFixed(2)} KB`,
          entries: lineCount,
        }, null, 2),
      }],
    };
  }

  private handlePreview(args: { name: string; lines?: number; offset?: number }) {
    if (!this.seclistsPath) {
      return this.notInstalledError();
    }

    const wordlistPath = this.resolveWordlistPath(args.name);
    if (!wordlistPath) {
      return {
        content: [{
          type: "text",
          text: `Wordlist not found: ${args.name}`,
        }],
        isError: true,
      };
    }

    const lines = Math.min(args.lines || 20, 100);
    const offset = args.offset || 0;

    const content = fs.readFileSync(wordlistPath, "utf-8");
    const allLines = content.split("\n");
    const previewLines = allLines.slice(offset, offset + lines);

    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          name: path.basename(wordlistPath),
          totalLines: allLines.length,
          offset,
          showing: previewLines.length,
          preview: previewLines,
        }, null, 2),
      }],
    };
  }

  private handleCount(args: { name: string }) {
    if (!this.seclistsPath) {
      return this.notInstalledError();
    }

    const wordlistPath = this.resolveWordlistPath(args.name);
    if (!wordlistPath) {
      return {
        content: [{
          type: "text",
          text: `Wordlist not found: ${args.name}`,
        }],
        isError: true,
      };
    }

    const lineCount = this.countLines(wordlistPath);
    const stats = fs.statSync(wordlistPath);

    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          name: path.basename(wordlistPath),
          path: wordlistPath,
          entries: lineCount,
          size: `${(stats.size / 1024).toFixed(2)} KB`,
        }, null, 2),
      }],
    };
  }

  private handleCombine(args: { wordlists: string[]; dedupe?: boolean; output?: string }) {
    if (!this.seclistsPath) {
      return this.notInstalledError();
    }

    const dedupe = args.dedupe !== false; // Default to true
    const allEntries: string[] = [];

    for (const wl of args.wordlists) {
      const wordlistPath = this.resolveWordlistPath(wl);
      if (!wordlistPath) {
        return {
          content: [{
            type: "text",
            text: `Wordlist not found: ${wl}`,
          }],
          isError: true,
        };
      }

      const content = fs.readFileSync(wordlistPath, "utf-8");
      const lines = content.split("\n").filter(l => l.trim());
      allEntries.push(...lines);
    }

    const finalEntries = dedupe ? [...new Set(allEntries)] : allEntries;

    if (args.output) {
      const outputDir = path.dirname(args.output);
      if (!fs.existsSync(outputDir)) {
        fs.mkdirSync(outputDir, { recursive: true });
      }
      fs.writeFileSync(args.output, finalEntries.join("\n"));

      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            success: true,
            output: args.output,
            sourceCount: args.wordlists.length,
            totalEntries: allEntries.length,
            finalEntries: finalEntries.length,
            deduped: dedupe,
            duplicatesRemoved: allEntries.length - finalEntries.length,
          }, null, 2),
        }],
      };
    }

    // Return first 1000 entries if no output file specified
    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          sourceCount: args.wordlists.length,
          totalEntries: allEntries.length,
          finalEntries: finalEntries.length,
          deduped: dedupe,
          duplicatesRemoved: allEntries.length - finalEntries.length,
          preview: finalEntries.slice(0, 1000),
          truncated: finalEntries.length > 1000,
        }, null, 2),
      }],
    };
  }

  private handlePopular(args: { category?: string }) {
    const result: Record<string, { description: string; exists: boolean; path?: string }> = {};

    for (const [relativePath, description] of Object.entries(POPULAR_WORDLISTS)) {
      if (args.category && !relativePath.toLowerCase().startsWith(args.category.toLowerCase())) {
        continue;
      }

      let exists = false;
      let fullPath: string | undefined;

      if (this.seclistsPath) {
        fullPath = path.join(this.seclistsPath, relativePath);
        exists = fs.existsSync(fullPath);
      }

      result[relativePath] = {
        description,
        exists,
        path: exists ? fullPath : undefined,
      };
    }

    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          seclistsPath: this.seclistsPath,
          installed: !!this.seclistsPath,
          wordlists: result,
        }, null, 2),
      }],
    };
  }

  private findWordlists(dir: string, pattern?: string): string[] {
    const results: string[] = [];

    const walk = (currentDir: string) => {
      try {
        const entries = fs.readdirSync(currentDir, { withFileTypes: true });
        for (const entry of entries) {
          if (entry.name.startsWith(".")) continue;

          const fullPath = path.join(currentDir, entry.name);
          if (entry.isDirectory()) {
            walk(fullPath);
          } else if (entry.isFile() && entry.name.endsWith(".txt")) {
            if (!pattern || this.matchPattern(entry.name, pattern)) {
              results.push(fullPath);
            }
          }
        }
      } catch { /* ignore permission errors */ }
    };

    walk(dir);
    return results.sort();
  }

  private matchPattern(filename: string, pattern: string): boolean {
    // Simple glob matching for * wildcard
    const regex = new RegExp(
      "^" + pattern.replace(/\*/g, ".*").replace(/\?/g, ".") + "$",
      "i"
    );
    return regex.test(filename);
  }

  private resolveWordlistPath(name: string): string | null {
    if (!this.seclistsPath) return null;

    // Check if it's already a full path
    if (path.isAbsolute(name) && fs.existsSync(name)) {
      return name;
    }

    // Check relative to SecLists root
    const relativePath = path.join(this.seclistsPath, name);
    if (fs.existsSync(relativePath)) {
      return relativePath;
    }

    // Search for the file by name
    const allWordlists = this.findWordlists(this.seclistsPath);
    const match = allWordlists.find(w =>
      path.basename(w) === name ||
      path.basename(w).toLowerCase() === name.toLowerCase()
    );

    return match || null;
  }

  private countLines(filePath: string): number {
    try {
      const content = fs.readFileSync(filePath, "utf-8");
      return content.split("\n").filter(l => l.trim()).length;
    } catch {
      return -1;
    }
  }

  private notInstalledError() {
    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          error: "SecLists not installed",
          message: "Use seclists_install to install SecLists from GitHub",
          suggestion: "Run: seclists_install or seclists_install with path parameter",
        }, null, 2),
      }],
      isError: true,
    };
  }

  async run() {
    const transport = new StdioServerTransport();
    await this.server.connect(transport);
    console.error("SecLists MCP server running on stdio");
  }
}

// Run the server
const server = new SecListsMCP();
server.run().catch(console.error);
