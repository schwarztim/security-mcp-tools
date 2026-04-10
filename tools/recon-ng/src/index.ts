#!/usr/bin/env node

/**
 * Recon-ng MCP Server
 *
 * MCP server for interacting with recon-ng OSINT framework.
 * Executes recon-ng commands via SSH on a remote Kali Linux system.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { Client as SSHClient, ConnectConfig } from "ssh2";

// Configuration from environment variables
const SSH_HOST = process.env.RECONNG_SSH_HOST || "kali";
const SSH_PORT = parseInt(process.env.RECONNG_SSH_PORT || "22", 10);
const SSH_USER = process.env.RECONNG_SSH_USER || "kali";
const SSH_KEY_PATH = process.env.RECONNG_SSH_KEY_PATH || `${process.env.HOME}/.ssh/id_rsa`;
const SSH_PASSWORD = process.env.RECONNG_SSH_PASSWORD;
const RECONNG_PATH = process.env.RECONNG_PATH || "recon-ng";
const DEFAULT_TIMEOUT = parseInt(process.env.RECONNG_TIMEOUT || "60000", 10);

// Read SSH key if available
import { readFileSync, existsSync } from "fs";

function getSSHConfig(): ConnectConfig {
  const config: ConnectConfig = {
    host: SSH_HOST,
    port: SSH_PORT,
    username: SSH_USER,
  };

  if (SSH_PASSWORD) {
    config.password = SSH_PASSWORD;
  } else if (existsSync(SSH_KEY_PATH)) {
    config.privateKey = readFileSync(SSH_KEY_PATH);
  }

  return config;
}

/**
 * Execute a command via SSH
 */
async function executeSSH(command: string, timeout: number = DEFAULT_TIMEOUT): Promise<string> {
  return new Promise((resolve, reject) => {
    const conn = new SSHClient();
    let output = "";
    let errorOutput = "";
    let timeoutId: NodeJS.Timeout;

    conn.on("ready", () => {
      timeoutId = setTimeout(() => {
        conn.end();
        reject(new Error(`Command timed out after ${timeout}ms`));
      }, timeout);

      conn.exec(command, (err, stream) => {
        if (err) {
          clearTimeout(timeoutId);
          conn.end();
          reject(err);
          return;
        }

        stream.on("close", (code: number) => {
          clearTimeout(timeoutId);
          conn.end();
          if (code === 0 || output) {
            resolve(output || errorOutput);
          } else {
            reject(new Error(errorOutput || `Command failed with code ${code}`));
          }
        });

        stream.on("data", (data: Buffer) => {
          output += data.toString();
        });

        stream.stderr.on("data", (data: Buffer) => {
          errorOutput += data.toString();
        });
      });
    });

    conn.on("error", (err) => {
      if (timeoutId) clearTimeout(timeoutId);
      reject(err);
    });

    conn.connect(getSSHConfig());
  });
}

/**
 * Execute a recon-ng command
 */
async function executeReconng(commands: string[], workspace?: string): Promise<string> {
  // Build the recon-ng command with piped input
  const reconngCommands = commands.join("\n");
  let cmd = `echo '${reconngCommands.replace(/'/g, "'\\''")}' | ${RECONNG_PATH}`;

  if (workspace) {
    cmd += ` -w ${workspace}`;
  }

  // Add -r flag to read from stdin in non-interactive mode
  cmd += " --no-analytics";

  return executeSSH(cmd);
}

/**
 * Execute a raw recon-ng CLI command
 */
async function executeReconngRaw(args: string): Promise<string> {
  const cmd = `${RECONNG_PATH} ${args}`;
  return executeSSH(cmd);
}

// Tool definitions
const tools: Tool[] = [
  {
    name: "reconng_workspaces",
    description: "Manage recon-ng workspaces. Workspaces store all reconnaissance data for a project.",
    inputSchema: {
      type: "object",
      properties: {
        action: {
          type: "string",
          enum: ["list", "create", "load", "remove"],
          description: "Action to perform on workspaces",
        },
        name: {
          type: "string",
          description: "Workspace name (required for create, load, remove)",
        },
      },
      required: ["action"],
    },
  },
  {
    name: "reconng_modules",
    description: "List, search, and get info about recon-ng modules from the marketplace.",
    inputSchema: {
      type: "object",
      properties: {
        action: {
          type: "string",
          enum: ["list", "search", "info", "install"],
          description: "Action to perform",
        },
        query: {
          type: "string",
          description: "Search query or module path (for info/install)",
        },
        workspace: {
          type: "string",
          description: "Workspace to use",
        },
      },
      required: ["action"],
    },
  },
  {
    name: "reconng_run",
    description: "Run a recon-ng module with specified options. Results are stored in the workspace database.",
    inputSchema: {
      type: "object",
      properties: {
        module: {
          type: "string",
          description: "Full module path (e.g., recon/domains-hosts/hackertarget)",
        },
        workspace: {
          type: "string",
          description: "Workspace to use",
        },
        options: {
          type: "object",
          additionalProperties: { type: "string" },
          description: "Module options to set (key-value pairs)",
        },
        source: {
          type: "string",
          description: "Source value (e.g., domain name, IP address)",
        },
      },
      required: ["module", "workspace"],
    },
  },
  {
    name: "reconng_db",
    description: "Query the recon-ng database. Supports showing tables and custom SQL queries.",
    inputSchema: {
      type: "object",
      properties: {
        action: {
          type: "string",
          enum: ["schema", "query", "show"],
          description: "Action: schema (show structure), query (run SQL), show (list table contents)",
        },
        workspace: {
          type: "string",
          description: "Workspace to query",
        },
        table: {
          type: "string",
          enum: ["domains", "hosts", "contacts", "credentials", "leaks", "netblocks", "ports", "profiles", "pushpins", "repositories", "vulnerabilities", "companies", "locations"],
          description: "Table name for 'show' action",
        },
        sql: {
          type: "string",
          description: "SQL query for 'query' action",
        },
      },
      required: ["action", "workspace"],
    },
  },
  {
    name: "reconng_add",
    description: "Add targets to the recon-ng database (domains, hosts, companies, contacts, etc.).",
    inputSchema: {
      type: "object",
      properties: {
        table: {
          type: "string",
          enum: ["domains", "hosts", "companies", "contacts", "credentials", "netblocks", "ports", "profiles", "repositories", "vulnerabilities", "locations", "leaks", "pushpins"],
          description: "Target table",
        },
        workspace: {
          type: "string",
          description: "Workspace to use",
        },
        values: {
          type: "array",
          items: { type: "string" },
          description: "Values to add (format depends on table type)",
        },
      },
      required: ["table", "workspace", "values"],
    },
  },
  {
    name: "reconng_delete",
    description: "Delete records from the recon-ng database.",
    inputSchema: {
      type: "object",
      properties: {
        table: {
          type: "string",
          enum: ["domains", "hosts", "companies", "contacts", "credentials", "netblocks", "ports", "profiles", "repositories", "vulnerabilities", "locations", "leaks", "pushpins"],
          description: "Target table",
        },
        workspace: {
          type: "string",
          description: "Workspace to use",
        },
        rowid: {
          type: "number",
          description: "Row ID to delete (optional, deletes all if not specified)",
        },
      },
      required: ["table", "workspace"],
    },
  },
  {
    name: "reconng_report",
    description: "Generate reports from recon-ng data in various formats.",
    inputSchema: {
      type: "object",
      properties: {
        workspace: {
          type: "string",
          description: "Workspace to report on",
        },
        format: {
          type: "string",
          enum: ["html", "csv", "json", "xlsx", "xml", "list", "pushpin"],
          description: "Report format",
        },
        filename: {
          type: "string",
          description: "Output filename (without extension)",
        },
        tables: {
          type: "array",
          items: { type: "string" },
          description: "Tables to include (default: all)",
        },
      },
      required: ["workspace", "format", "filename"],
    },
  },
  {
    name: "reconng_keys",
    description: "Manage API keys for recon-ng modules (Shodan, VirusTotal, etc.).",
    inputSchema: {
      type: "object",
      properties: {
        action: {
          type: "string",
          enum: ["list", "add", "remove"],
          description: "Action to perform",
        },
        name: {
          type: "string",
          description: "API key name (e.g., shodan_api, virustotal_api)",
        },
        value: {
          type: "string",
          description: "API key value (for add action)",
        },
      },
      required: ["action"],
    },
  },
  {
    name: "reconng_snapshots",
    description: "Manage workspace snapshots for saving and restoring database states.",
    inputSchema: {
      type: "object",
      properties: {
        action: {
          type: "string",
          enum: ["list", "take", "load", "remove"],
          description: "Action to perform",
        },
        workspace: {
          type: "string",
          description: "Workspace to use",
        },
        name: {
          type: "string",
          description: "Snapshot name (for take, load, remove)",
        },
      },
      required: ["action", "workspace"],
    },
  },
  {
    name: "reconng_raw",
    description: "Execute raw recon-ng CLI commands. Use for advanced operations not covered by other tools.",
    inputSchema: {
      type: "object",
      properties: {
        commands: {
          type: "array",
          items: { type: "string" },
          description: "Recon-ng commands to execute in sequence",
        },
        workspace: {
          type: "string",
          description: "Workspace to use",
        },
      },
      required: ["commands"],
    },
  },
  {
    name: "reconng_status",
    description: "Get recon-ng installation status and system information.",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
];

// Create MCP server
const server = new Server(
  {
    name: "recon-ng-mcp",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Handle tool listing
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return { tools };
});

// Handle tool execution
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case "reconng_workspaces": {
        const { action, name: wsName } = args as { action: string; name?: string };
        let commands: string[] = [];

        switch (action) {
          case "list":
            commands = ["workspaces list"];
            break;
          case "create":
            if (!wsName) throw new Error("Workspace name required");
            commands = [`workspaces create ${wsName}`];
            break;
          case "load":
            if (!wsName) throw new Error("Workspace name required");
            commands = [`workspaces load ${wsName}`];
            break;
          case "remove":
            if (!wsName) throw new Error("Workspace name required");
            commands = [`workspaces remove ${wsName}`];
            break;
        }

        const result = await executeReconng(commands);
        return { content: [{ type: "text", text: result }] };
      }

      case "reconng_modules": {
        const { action, query, workspace } = args as { action: string; query?: string; workspace?: string };
        let commands: string[] = [];

        switch (action) {
          case "list":
            commands = ["marketplace search"];
            break;
          case "search":
            if (!query) throw new Error("Search query required");
            commands = [`marketplace search ${query}`];
            break;
          case "info":
            if (!query) throw new Error("Module path required");
            commands = [`marketplace info ${query}`];
            break;
          case "install":
            if (!query) throw new Error("Module path required");
            commands = [`marketplace install ${query}`];
            break;
        }

        const result = await executeReconng(commands, workspace);
        return { content: [{ type: "text", text: result }] };
      }

      case "reconng_run": {
        const { module, workspace, options, source } = args as {
          module: string;
          workspace: string;
          options?: Record<string, string>;
          source?: string;
        };

        const commands: string[] = [`modules load ${module}`];

        if (source) {
          commands.push(`options set SOURCE ${source}`);
        }

        if (options) {
          for (const [key, value] of Object.entries(options)) {
            commands.push(`options set ${key} ${value}`);
          }
        }

        commands.push("run");

        const result = await executeReconng(commands, workspace);
        return { content: [{ type: "text", text: result }] };
      }

      case "reconng_db": {
        const { action, workspace, table, sql } = args as {
          action: string;
          workspace: string;
          table?: string;
          sql?: string;
        };

        let commands: string[] = [];

        switch (action) {
          case "schema":
            commands = ["db schema"];
            break;
          case "query":
            if (!sql) throw new Error("SQL query required");
            commands = [`db query ${sql}`];
            break;
          case "show":
            if (!table) throw new Error("Table name required");
            commands = [`show ${table}`];
            break;
        }

        const result = await executeReconng(commands, workspace);
        return { content: [{ type: "text", text: result }] };
      }

      case "reconng_add": {
        const { table, workspace, values } = args as {
          table: string;
          workspace: string;
          values: string[];
        };

        const commands = values.map(v => `db insert ${table} ${v}`);
        const result = await executeReconng(commands, workspace);
        return { content: [{ type: "text", text: result }] };
      }

      case "reconng_delete": {
        const { table, workspace, rowid } = args as {
          table: string;
          workspace: string;
          rowid?: number;
        };

        const cmd = rowid !== undefined
          ? `db delete ${table} ${rowid}`
          : `db delete ${table}`;

        const result = await executeReconng([cmd], workspace);
        return { content: [{ type: "text", text: result }] };
      }

      case "reconng_report": {
        const { workspace, format, filename, tables } = args as {
          workspace: string;
          format: string;
          filename: string;
          tables?: string[];
        };

        // Map format to module
        const formatModules: Record<string, string> = {
          html: "reporting/html",
          csv: "reporting/csv",
          json: "reporting/json",
          xlsx: "reporting/xlsx",
          xml: "reporting/xml",
          list: "reporting/list",
          pushpin: "reporting/pushpin",
        };

        const module = formatModules[format];
        if (!module) throw new Error(`Unsupported format: ${format}`);

        const commands: string[] = [
          `modules load ${module}`,
          `options set FILENAME /tmp/${filename}`,
        ];

        if (tables && tables.length > 0) {
          commands.push(`options set TABLES ${tables.join(",")}`);
        }

        commands.push("run");

        const result = await executeReconng(commands, workspace);

        // Try to read the generated file
        try {
          const fileContent = await executeSSH(`cat /tmp/${filename}.*`);
          return {
            content: [
              { type: "text", text: `Report generated:\n${result}\n\nReport content:\n${fileContent}` }
            ]
          };
        } catch {
          return { content: [{ type: "text", text: result }] };
        }
      }

      case "reconng_keys": {
        const { action, name: keyName, value } = args as {
          action: string;
          name?: string;
          value?: string;
        };

        let commands: string[] = [];

        switch (action) {
          case "list":
            commands = ["keys list"];
            break;
          case "add":
            if (!keyName || !value) throw new Error("Key name and value required");
            commands = [`keys add ${keyName} ${value}`];
            break;
          case "remove":
            if (!keyName) throw new Error("Key name required");
            commands = [`keys remove ${keyName}`];
            break;
        }

        const result = await executeReconng(commands);
        return { content: [{ type: "text", text: result }] };
      }

      case "reconng_snapshots": {
        const { action, workspace, name: snapName } = args as {
          action: string;
          workspace: string;
          name?: string;
        };

        let commands: string[] = [];

        switch (action) {
          case "list":
            commands = ["snapshots list"];
            break;
          case "take":
            if (!snapName) throw new Error("Snapshot name required");
            commands = [`snapshots take ${snapName}`];
            break;
          case "load":
            if (!snapName) throw new Error("Snapshot name required");
            commands = [`snapshots load ${snapName}`];
            break;
          case "remove":
            if (!snapName) throw new Error("Snapshot name required");
            commands = [`snapshots remove ${snapName}`];
            break;
        }

        const result = await executeReconng(commands, workspace);
        return { content: [{ type: "text", text: result }] };
      }

      case "reconng_raw": {
        const { commands, workspace } = args as {
          commands: string[];
          workspace?: string;
        };

        const result = await executeReconng(commands, workspace);
        return { content: [{ type: "text", text: result }] };
      }

      case "reconng_status": {
        // Check recon-ng installation and version
        const versionResult = await executeSSH(`${RECONNG_PATH} --version 2>&1 || echo "recon-ng not found"`);
        const whichResult = await executeSSH(`which ${RECONNG_PATH} 2>/dev/null || echo "not in PATH"`);
        const workspacesResult = await executeReconng(["workspaces list"]).catch(() => "Unable to list workspaces");

        const status = `
Recon-ng Status:
================
Version: ${versionResult.trim()}
Path: ${whichResult.trim()}
SSH Host: ${SSH_HOST}:${SSH_PORT}
SSH User: ${SSH_USER}

Existing Workspaces:
${workspacesResult}
        `.trim();

        return { content: [{ type: "text", text: status }] };
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  } catch (error) {
    const errorMessage = error instanceof Error ? error.message : String(error);
    return {
      content: [{ type: "text", text: `Error: ${errorMessage}` }],
      isError: true,
    };
  }
});

// Start server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Recon-ng MCP server started");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
