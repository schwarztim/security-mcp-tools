#!/usr/bin/env node

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { exec } from "child_process";
import { promisify } from "util";

const execAsync = promisify(exec);

// Configuration
const KALI_HOST = process.env.KALI_HOST || "kali";
const WPSCAN_API_TOKEN = process.env.WPSCAN_API_TOKEN || "";
const SSH_TIMEOUT = parseInt(process.env.SSH_TIMEOUT || "300000"); // 5 minutes default

// Helper to execute WPScan via SSH on Kali
async function executeWPScan(args: string[]): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  // Build the command with proper escaping
  const escapedArgs = args.map(arg => {
    // Escape single quotes in arguments
    return `'${arg.replace(/'/g, "'\\''")}'`;
  }).join(" ");

  const command = `ssh ${KALI_HOST} "wpscan ${escapedArgs}"`;

  try {
    const { stdout, stderr } = await execAsync(command, {
      maxBuffer: 10 * 1024 * 1024, // 10MB buffer
      timeout: SSH_TIMEOUT,
    });
    return { stdout, stderr, exitCode: 0 };
  } catch (error: any) {
    // WPScan may exit with non-zero for vulnerabilities found
    return {
      stdout: error.stdout || "",
      stderr: error.stderr || error.message,
      exitCode: error.code || 1,
    };
  }
}

// Parse WPScan JSON output
function parseWPScanOutput(stdout: string): any {
  try {
    // Try to find JSON in the output
    const jsonMatch = stdout.match(/\{[\s\S]*\}/);
    if (jsonMatch) {
      return JSON.parse(jsonMatch[0]);
    }
    return { raw_output: stdout };
  } catch {
    return { raw_output: stdout };
  }
}

// Create the MCP server
const server = new McpServer({
  name: "wpscan",
  version: "1.0.0",
});

// Tool: Full WordPress Scan
server.tool(
  "wpscan_scan",
  "Perform a full WordPress security scan on a target URL",
  {
    url: z.string().url().describe("Target WordPress site URL"),
    detection_mode: z.enum(["mixed", "passive", "aggressive"]).optional().describe("Detection mode (default: mixed)"),
    enumerate: z.string().optional().describe("Enumeration options: vp,ap,p,vt,at,t,tt,cb,dbe,u,m (default: vp,vt,tt,cb,dbe,u,m)"),
    random_user_agent: z.boolean().optional().describe("Use random user agent to bypass WAF"),
    force: z.boolean().optional().describe("Force scan even if WordPress not detected"),
    stealthy: z.boolean().optional().describe("Enable stealthy mode (passive + random UA)"),
    threads: z.number().optional().describe("Number of threads (default: 5)"),
    throttle: z.number().optional().describe("Milliseconds to wait between requests"),
    proxy: z.string().optional().describe("Proxy URL (e.g., http://127.0.0.1:8080)"),
  },
  async ({ url, detection_mode, enumerate, random_user_agent, force, stealthy, threads, throttle, proxy }) => {
    const args: string[] = ["--url", url, "--format", "json", "--no-banner"];

    if (WPSCAN_API_TOKEN) {
      args.push("--api-token", WPSCAN_API_TOKEN);
    }

    if (detection_mode) {
      args.push("--detection-mode", detection_mode);
    }

    if (enumerate) {
      args.push("-e", enumerate);
    }

    if (random_user_agent) {
      args.push("--random-user-agent");
    }

    if (force) {
      args.push("--force");
    }

    if (stealthy) {
      args.push("--stealthy");
    }

    if (threads) {
      args.push("--threads", threads.toString());
    }

    if (throttle) {
      args.push("--throttle", throttle.toString());
    }

    if (proxy) {
      args.push("--proxy", proxy);
    }

    const result = await executeWPScan(args);
    const parsed = parseWPScanOutput(result.stdout);

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            success: result.exitCode === 0,
            exit_code: result.exitCode,
            data: parsed,
            stderr: result.stderr || undefined,
          }, null, 2),
        },
      ],
    };
  }
);

// Tool: Enumerate specific items
server.tool(
  "wpscan_enumerate",
  "Enumerate specific WordPress components (users, plugins, themes, etc.)",
  {
    url: z.string().url().describe("Target WordPress site URL"),
    type: z.enum(["users", "plugins", "themes", "all"]).describe("What to enumerate"),
    detection_mode: z.enum(["mixed", "passive", "aggressive"]).optional().describe("Detection mode"),
    include_vulnerable_only: z.boolean().optional().describe("Only show items with known vulnerabilities"),
  },
  async ({ url, type, detection_mode, include_vulnerable_only }) => {
    const args: string[] = ["--url", url, "--format", "json", "--no-banner"];

    if (WPSCAN_API_TOKEN) {
      args.push("--api-token", WPSCAN_API_TOKEN);
    }

    // Set enumeration based on type
    let enumOptions: string;
    switch (type) {
      case "users":
        enumOptions = "u1-100";
        break;
      case "plugins":
        enumOptions = include_vulnerable_only ? "vp" : "ap";
        break;
      case "themes":
        enumOptions = include_vulnerable_only ? "vt" : "at";
        break;
      case "all":
        enumOptions = include_vulnerable_only ? "vp,vt,u" : "ap,at,u";
        break;
    }

    args.push("-e", enumOptions);

    if (detection_mode) {
      args.push("--detection-mode", detection_mode);
    }

    // For plugins enumeration, aggressive mode is often needed
    if (type === "plugins" && !include_vulnerable_only) {
      args.push("--plugins-detection", "aggressive");
    }

    const result = await executeWPScan(args);
    const parsed = parseWPScanOutput(result.stdout);

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            success: result.exitCode === 0,
            enumeration_type: type,
            data: parsed,
            stderr: result.stderr || undefined,
          }, null, 2),
        },
      ],
    };
  }
);

// Tool: Check vulnerabilities
server.tool(
  "wpscan_vulns",
  "Check for known vulnerabilities in WordPress core, plugins, and themes",
  {
    url: z.string().url().describe("Target WordPress site URL"),
    aggressive: z.boolean().optional().describe("Use aggressive detection for more results"),
  },
  async ({ url, aggressive }) => {
    const args: string[] = ["--url", url, "--format", "json", "--no-banner"];

    if (WPSCAN_API_TOKEN) {
      args.push("--api-token", WPSCAN_API_TOKEN);
    }

    // Enumerate vulnerable items only
    args.push("-e", "vp,vt");

    if (aggressive) {
      args.push("--detection-mode", "aggressive");
      args.push("--plugins-detection", "aggressive");
    }

    const result = await executeWPScan(args);
    const parsed = parseWPScanOutput(result.stdout);

    // Extract vulnerability summary
    let vulnerabilities: any[] = [];
    if (parsed && typeof parsed === "object") {
      // WordPress core vulnerabilities
      if (parsed.version?.vulnerabilities) {
        vulnerabilities.push(...parsed.version.vulnerabilities.map((v: any) => ({
          type: "wordpress_core",
          ...v,
        })));
      }

      // Plugin vulnerabilities
      if (parsed.plugins) {
        for (const [name, plugin] of Object.entries(parsed.plugins as Record<string, any>)) {
          if (plugin.vulnerabilities) {
            vulnerabilities.push(...plugin.vulnerabilities.map((v: any) => ({
              type: "plugin",
              plugin_name: name,
              ...v,
            })));
          }
        }
      }

      // Theme vulnerabilities
      if (parsed.themes) {
        for (const [name, theme] of Object.entries(parsed.themes as Record<string, any>)) {
          if (theme.vulnerabilities) {
            vulnerabilities.push(...theme.vulnerabilities.map((v: any) => ({
              type: "theme",
              theme_name: name,
              ...v,
            })));
          }
        }
      }
    }

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            success: result.exitCode === 0,
            vulnerability_count: vulnerabilities.length,
            vulnerabilities,
            full_scan_data: parsed,
          }, null, 2),
        },
      ],
    };
  }
);

// Tool: Plugin enumeration
server.tool(
  "wpscan_plugins",
  "Enumerate WordPress plugins",
  {
    url: z.string().url().describe("Target WordPress site URL"),
    type: z.enum(["all", "vulnerable", "popular"]).optional().describe("Plugin enumeration type (default: vulnerable)"),
    detection_mode: z.enum(["mixed", "passive", "aggressive"]).optional().describe("Detection mode for plugins"),
  },
  async ({ url, type = "vulnerable", detection_mode = "aggressive" }) => {
    const args: string[] = ["--url", url, "--format", "json", "--no-banner"];

    if (WPSCAN_API_TOKEN) {
      args.push("--api-token", WPSCAN_API_TOKEN);
    }

    // Set enumeration type
    let enumOption: string;
    switch (type) {
      case "all":
        enumOption = "ap";
        break;
      case "popular":
        enumOption = "p";
        break;
      case "vulnerable":
      default:
        enumOption = "vp";
        break;
    }

    args.push("-e", enumOption);
    args.push("--plugins-detection", detection_mode);

    const result = await executeWPScan(args);
    const parsed = parseWPScanOutput(result.stdout);

    // Extract plugin information
    let plugins: any[] = [];
    if (parsed?.plugins) {
      for (const [name, plugin] of Object.entries(parsed.plugins as Record<string, any>)) {
        plugins.push({
          name,
          version: plugin.version?.number || "unknown",
          outdated: plugin.version?.status === "outdated",
          vulnerabilities: plugin.vulnerabilities || [],
          location: plugin.location,
        });
      }
    }

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            success: result.exitCode === 0,
            plugin_count: plugins.length,
            plugins,
            raw_data: parsed,
          }, null, 2),
        },
      ],
    };
  }
);

// Tool: Theme enumeration
server.tool(
  "wpscan_themes",
  "Enumerate WordPress themes",
  {
    url: z.string().url().describe("Target WordPress site URL"),
    type: z.enum(["all", "vulnerable", "popular"]).optional().describe("Theme enumeration type (default: vulnerable)"),
    detection_mode: z.enum(["mixed", "passive", "aggressive"]).optional().describe("Detection mode"),
  },
  async ({ url, type = "vulnerable", detection_mode = "mixed" }) => {
    const args: string[] = ["--url", url, "--format", "json", "--no-banner"];

    if (WPSCAN_API_TOKEN) {
      args.push("--api-token", WPSCAN_API_TOKEN);
    }

    // Set enumeration type
    let enumOption: string;
    switch (type) {
      case "all":
        enumOption = "at";
        break;
      case "popular":
        enumOption = "t";
        break;
      case "vulnerable":
      default:
        enumOption = "vt";
        break;
    }

    args.push("-e", enumOption);

    if (detection_mode) {
      args.push("--detection-mode", detection_mode);
    }

    const result = await executeWPScan(args);
    const parsed = parseWPScanOutput(result.stdout);

    // Extract theme information
    let themes: any[] = [];
    if (parsed?.themes) {
      for (const [name, theme] of Object.entries(parsed.themes as Record<string, any>)) {
        themes.push({
          name,
          version: theme.version?.number || "unknown",
          outdated: theme.version?.status === "outdated",
          vulnerabilities: theme.vulnerabilities || [],
          style_url: theme.style_url,
        });
      }
    }

    // Also check main theme
    if (parsed?.main_theme) {
      const mainTheme = parsed.main_theme;
      themes.unshift({
        name: mainTheme.slug || "main_theme",
        version: mainTheme.version?.number || "unknown",
        is_main_theme: true,
        vulnerabilities: mainTheme.vulnerabilities || [],
      });
    }

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            success: result.exitCode === 0,
            theme_count: themes.length,
            themes,
            raw_data: parsed,
          }, null, 2),
        },
      ],
    };
  }
);

// Tool: User enumeration
server.tool(
  "wpscan_users",
  "Enumerate WordPress users",
  {
    url: z.string().url().describe("Target WordPress site URL"),
    range: z.string().optional().describe("User ID range (e.g., '1-100', default: '1-50')"),
    detection_mode: z.enum(["mixed", "passive", "aggressive"]).optional().describe("Detection mode"),
  },
  async ({ url, range = "1-50", detection_mode = "mixed" }) => {
    const args: string[] = ["--url", url, "--format", "json", "--no-banner"];

    if (WPSCAN_API_TOKEN) {
      args.push("--api-token", WPSCAN_API_TOKEN);
    }

    args.push("-e", `u${range}`);

    if (detection_mode) {
      args.push("--detection-mode", detection_mode);
    }

    const result = await executeWPScan(args);
    const parsed = parseWPScanOutput(result.stdout);

    // Extract user information
    let users: any[] = [];
    if (parsed?.users) {
      for (const [username, user] of Object.entries(parsed.users as Record<string, any>)) {
        users.push({
          username,
          id: user.id,
          display_name: user.display_name,
          slug: user.slug,
        });
      }
    }

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            success: result.exitCode === 0,
            user_count: users.length,
            users,
            raw_data: parsed,
          }, null, 2),
        },
      ],
    };
  }
);

// Tool: Password brute-force
server.tool(
  "wpscan_bruteforce",
  "Perform password brute-force attack against WordPress login (use responsibly and only with authorization)",
  {
    url: z.string().url().describe("Target WordPress site URL"),
    usernames: z.string().describe("Comma-separated list of usernames or path to file"),
    passwords: z.string().describe("Path to password wordlist file on Kali"),
    attack_type: z.enum(["wp-login", "xmlrpc", "xmlrpc-multicall"]).optional().describe("Attack type (default: auto-detect)"),
    max_threads: z.number().optional().describe("Maximum threads (default: 5)"),
    multicall_max_passwords: z.number().optional().describe("Max passwords per XMLRPC multicall (default: 500)"),
  },
  async ({ url, usernames, passwords, attack_type, max_threads, multicall_max_passwords }) => {
    const args: string[] = ["--url", url, "--format", "json", "--no-banner"];

    if (WPSCAN_API_TOKEN) {
      args.push("--api-token", WPSCAN_API_TOKEN);
    }

    args.push("-U", usernames);
    args.push("-P", passwords);

    if (attack_type) {
      args.push("--password-attack", attack_type);
    }

    if (max_threads) {
      args.push("--threads", max_threads.toString());
    }

    if (multicall_max_passwords) {
      args.push("--multicall-max-passwords", multicall_max_passwords.toString());
    }

    const result = await executeWPScan(args);
    const parsed = parseWPScanOutput(result.stdout);

    // Extract password findings
    let credentials: any[] = [];
    if (parsed?.password_attack) {
      credentials = parsed.password_attack;
    }

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            success: result.exitCode === 0,
            warning: "Password brute-force completed. Only use with proper authorization.",
            credentials_found: credentials.length,
            credentials,
            raw_data: parsed,
          }, null, 2),
        },
      ],
    };
  }
);

// Tool: Update WPScan database
server.tool(
  "wpscan_update",
  "Update the WPScan database with latest vulnerability data",
  {},
  async () => {
    const args: string[] = ["--update", "--no-banner"];

    if (WPSCAN_API_TOKEN) {
      args.push("--api-token", WPSCAN_API_TOKEN);
    }

    const result = await executeWPScan(args);

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            success: result.exitCode === 0,
            message: result.exitCode === 0 ? "WPScan database updated successfully" : "Update failed",
            output: result.stdout,
            stderr: result.stderr || undefined,
          }, null, 2),
        },
      ],
    };
  }
);

// Tool: Get WPScan version and info
server.tool(
  "wpscan_info",
  "Get WPScan version and configuration information",
  {},
  async () => {
    const args: string[] = ["--version"];

    const result = await executeWPScan(args);

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            success: result.exitCode === 0,
            version: result.stdout.trim(),
            kali_host: KALI_HOST,
            api_token_configured: !!WPSCAN_API_TOKEN,
          }, null, 2),
        },
      ],
    };
  }
);

// Tool: Custom WPScan command
server.tool(
  "wpscan_custom",
  "Execute a custom WPScan command with raw arguments",
  {
    args: z.string().describe("Raw WPScan arguments (e.g., '--url https://example.com -e vp --random-user-agent')"),
    json_output: z.boolean().optional().describe("Force JSON output format (default: true)"),
  },
  async ({ args, json_output = true }) => {
    // Parse the args string into array
    const argArray = args.split(/\s+/).filter(Boolean);

    if (json_output && !args.includes("--format")) {
      argArray.push("--format", "json");
    }

    if (!args.includes("--banner") && !args.includes("--no-banner")) {
      argArray.push("--no-banner");
    }

    if (WPSCAN_API_TOKEN && !args.includes("--api-token")) {
      argArray.push("--api-token", WPSCAN_API_TOKEN);
    }

    const result = await executeWPScan(argArray);
    const parsed = json_output ? parseWPScanOutput(result.stdout) : { raw_output: result.stdout };

    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({
            success: result.exitCode === 0,
            exit_code: result.exitCode,
            data: parsed,
            stderr: result.stderr || undefined,
          }, null, 2),
        },
      ],
    };
  }
);

// Main entry point
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("WPScan MCP server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
