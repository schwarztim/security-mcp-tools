#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import axios, { AxiosInstance } from "axios";

// Configuration from environment
const SQLMAP_API_HOST = process.env.SQLMAP_API_HOST || "127.0.0.1";
const SQLMAP_API_PORT = process.env.SQLMAP_API_PORT || "8775";
const SQLMAP_API_USERNAME = process.env.SQLMAP_API_USERNAME || "";
const SQLMAP_API_PASSWORD = process.env.SQLMAP_API_PASSWORD || "";

const baseURL = `http://${SQLMAP_API_HOST}:${SQLMAP_API_PORT}`;

// Create axios client with optional basic auth
function createClient(): AxiosInstance {
  const config: any = {
    baseURL,
    timeout: 30000,
    headers: {
      "Content-Type": "application/json",
    },
  };

  if (SQLMAP_API_USERNAME && SQLMAP_API_PASSWORD) {
    config.auth = {
      username: SQLMAP_API_USERNAME,
      password: SQLMAP_API_PASSWORD,
    };
  }

  return axios.create(config);
}

const client = createClient();

// Tool definitions
const tools: Tool[] = [
  {
    name: "sqlmap_new_task",
    description:
      "Create a new sqlmap scanning task. Returns a taskId that must be used for all subsequent operations.",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "sqlmap_delete_task",
    description: "Delete an existing sqlmap task and free resources.",
    inputSchema: {
      type: "object",
      properties: {
        taskId: {
          type: "string",
          description: "The task ID to delete",
        },
      },
      required: ["taskId"],
    },
  },
  {
    name: "sqlmap_set_options",
    description:
      "Set options for a sqlmap task before starting the scan. Common options include: url, data (POST data), cookie, headers, level (1-5), risk (1-3), dbms, technique (BEUSTQ), threads, dbs (enumerate databases), tables (enumerate tables), columns (enumerate columns), dump (dump data), D (database name), T (table name), C (column name), osShell (OS shell), osCmd (OS command).",
    inputSchema: {
      type: "object",
      properties: {
        taskId: {
          type: "string",
          description: "The task ID",
        },
        options: {
          type: "object",
          description:
            "Key-value pairs of sqlmap options to set. Examples: {url: 'http://target/?id=1', level: 5, risk: 3, dbs: true}",
          additionalProperties: true,
        },
      },
      required: ["taskId", "options"],
    },
  },
  {
    name: "sqlmap_get_options",
    description: "Get current options for a sqlmap task.",
    inputSchema: {
      type: "object",
      properties: {
        taskId: {
          type: "string",
          description: "The task ID",
        },
        options: {
          type: "array",
          items: { type: "string" },
          description:
            "List of option names to retrieve. Leave empty to get all options.",
        },
      },
      required: ["taskId"],
    },
  },
  {
    name: "sqlmap_list_options",
    description:
      "List all available sqlmap options and their current values for a task.",
    inputSchema: {
      type: "object",
      properties: {
        taskId: {
          type: "string",
          description: "The task ID",
        },
      },
      required: ["taskId"],
    },
  },
  {
    name: "sqlmap_start_scan",
    description:
      "Start a SQL injection scan. Must set options (especially 'url') before starting.",
    inputSchema: {
      type: "object",
      properties: {
        taskId: {
          type: "string",
          description: "The task ID",
        },
        url: {
          type: "string",
          description:
            "Optional: Target URL to scan. Can also be set via sqlmap_set_options.",
        },
      },
      required: ["taskId"],
    },
  },
  {
    name: "sqlmap_scan_status",
    description:
      "Get the current status of a running scan. Status can be: 'not running', 'running', or 'terminated'.",
    inputSchema: {
      type: "object",
      properties: {
        taskId: {
          type: "string",
          description: "The task ID",
        },
      },
      required: ["taskId"],
    },
  },
  {
    name: "sqlmap_scan_data",
    description:
      "Get the results/data from a completed scan, including discovered vulnerabilities, databases, tables, columns, and dumped data.",
    inputSchema: {
      type: "object",
      properties: {
        taskId: {
          type: "string",
          description: "The task ID",
        },
      },
      required: ["taskId"],
    },
  },
  {
    name: "sqlmap_scan_log",
    description:
      "Get the log messages from a scan, including INFO, WARNING, and CRITICAL messages.",
    inputSchema: {
      type: "object",
      properties: {
        taskId: {
          type: "string",
          description: "The task ID",
        },
        start: {
          type: "number",
          description: "Start index for log entries (optional)",
        },
        end: {
          type: "number",
          description: "End index for log entries (optional)",
        },
      },
      required: ["taskId"],
    },
  },
  {
    name: "sqlmap_stop_scan",
    description: "Stop a running scan gracefully.",
    inputSchema: {
      type: "object",
      properties: {
        taskId: {
          type: "string",
          description: "The task ID",
        },
      },
      required: ["taskId"],
    },
  },
  {
    name: "sqlmap_kill_scan",
    description: "Forcefully terminate a running scan.",
    inputSchema: {
      type: "object",
      properties: {
        taskId: {
          type: "string",
          description: "The task ID",
        },
      },
      required: ["taskId"],
    },
  },
  {
    name: "sqlmap_version",
    description: "Get the sqlmap server version information.",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "sqlmap_enumerate_dbs",
    description:
      "Convenience tool: Create a task, configure it to enumerate databases, start scan, and wait for results. Returns discovered databases.",
    inputSchema: {
      type: "object",
      properties: {
        url: {
          type: "string",
          description: "Target URL with injectable parameter (e.g., http://target.com/page?id=1)",
        },
        level: {
          type: "number",
          description: "Level of tests to perform (1-5, default: 1)",
          default: 1,
        },
        risk: {
          type: "number",
          description: "Risk of tests to perform (1-3, default: 1)",
          default: 1,
        },
        technique: {
          type: "string",
          description:
            "SQL injection techniques to use: B=Boolean-based, E=Error-based, U=Union, S=Stacked, T=Time-based, Q=Inline queries (default: BEUSTQ)",
        },
        cookie: {
          type: "string",
          description: "HTTP Cookie header value",
        },
        headers: {
          type: "object",
          description: "Additional HTTP headers",
        },
        data: {
          type: "string",
          description: "POST data string",
        },
        dbms: {
          type: "string",
          description:
            "Force back-end DBMS to provided value (e.g., MySQL, PostgreSQL, MSSQL, Oracle)",
        },
      },
      required: ["url"],
    },
  },
  {
    name: "sqlmap_enumerate_tables",
    description:
      "Convenience tool: Enumerate tables from a specific database.",
    inputSchema: {
      type: "object",
      properties: {
        url: {
          type: "string",
          description: "Target URL with injectable parameter",
        },
        database: {
          type: "string",
          description: "Database name to enumerate tables from",
        },
        level: {
          type: "number",
          description: "Level of tests (1-5)",
          default: 1,
        },
        risk: {
          type: "number",
          description: "Risk of tests (1-3)",
          default: 1,
        },
        technique: {
          type: "string",
          description: "SQL injection techniques (BEUSTQ)",
        },
        cookie: {
          type: "string",
          description: "HTTP Cookie header value",
        },
        dbms: {
          type: "string",
          description: "Force back-end DBMS",
        },
      },
      required: ["url", "database"],
    },
  },
  {
    name: "sqlmap_enumerate_columns",
    description:
      "Convenience tool: Enumerate columns from a specific table in a database.",
    inputSchema: {
      type: "object",
      properties: {
        url: {
          type: "string",
          description: "Target URL with injectable parameter",
        },
        database: {
          type: "string",
          description: "Database name",
        },
        table: {
          type: "string",
          description: "Table name to enumerate columns from",
        },
        level: {
          type: "number",
          description: "Level of tests (1-5)",
          default: 1,
        },
        risk: {
          type: "number",
          description: "Risk of tests (1-3)",
          default: 1,
        },
        cookie: {
          type: "string",
          description: "HTTP Cookie header value",
        },
        dbms: {
          type: "string",
          description: "Force back-end DBMS",
        },
      },
      required: ["url", "database", "table"],
    },
  },
  {
    name: "sqlmap_dump_table",
    description:
      "Convenience tool: Dump data from a specific table. Can optionally specify columns to dump.",
    inputSchema: {
      type: "object",
      properties: {
        url: {
          type: "string",
          description: "Target URL with injectable parameter",
        },
        database: {
          type: "string",
          description: "Database name",
        },
        table: {
          type: "string",
          description: "Table name to dump",
        },
        columns: {
          type: "string",
          description: "Comma-separated list of columns to dump (optional)",
        },
        start: {
          type: "number",
          description: "First row to dump (optional)",
        },
        stop: {
          type: "number",
          description: "Last row to dump (optional)",
        },
        level: {
          type: "number",
          description: "Level of tests (1-5)",
          default: 1,
        },
        risk: {
          type: "number",
          description: "Risk of tests (1-3)",
          default: 1,
        },
        cookie: {
          type: "string",
          description: "HTTP Cookie header value",
        },
        dbms: {
          type: "string",
          description: "Force back-end DBMS",
        },
      },
      required: ["url", "database", "table"],
    },
  },
  {
    name: "sqlmap_os_shell",
    description:
      "Attempt to get an operating system shell on the target server. Requires the SQL injection to have sufficient privileges and the right conditions.",
    inputSchema: {
      type: "object",
      properties: {
        url: {
          type: "string",
          description: "Target URL with injectable parameter",
        },
        level: {
          type: "number",
          description: "Level of tests (1-5)",
          default: 5,
        },
        risk: {
          type: "number",
          description: "Risk of tests (1-3)",
          default: 3,
        },
        cookie: {
          type: "string",
          description: "HTTP Cookie header value",
        },
        dbms: {
          type: "string",
          description: "Force back-end DBMS",
        },
        webRoot: {
          type: "string",
          description: "Web server document root directory",
        },
      },
      required: ["url"],
    },
  },
  {
    name: "sqlmap_os_cmd",
    description:
      "Execute an operating system command on the target server via SQL injection.",
    inputSchema: {
      type: "object",
      properties: {
        url: {
          type: "string",
          description: "Target URL with injectable parameter",
        },
        command: {
          type: "string",
          description: "Operating system command to execute",
        },
        level: {
          type: "number",
          description: "Level of tests (1-5)",
          default: 5,
        },
        risk: {
          type: "number",
          description: "Risk of tests (1-3)",
          default: 3,
        },
        cookie: {
          type: "string",
          description: "HTTP Cookie header value",
        },
        dbms: {
          type: "string",
          description: "Force back-end DBMS",
        },
      },
      required: ["url", "command"],
    },
  },
  {
    name: "sqlmap_check_connection",
    description:
      "Check if the sqlmap API server is running and accessible.",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
];

// Helper function to wait for scan completion
async function waitForScan(
  taskId: string,
  maxWaitMs: number = 300000
): Promise<{ status: string; returncode: number }> {
  const startTime = Date.now();
  const pollInterval = 2000; // 2 seconds

  while (Date.now() - startTime < maxWaitMs) {
    const response = await client.get(`/scan/${taskId}/status`);
    const { status, returncode } = response.data;

    if (status === "terminated") {
      return { status, returncode };
    }

    await new Promise((resolve) => setTimeout(resolve, pollInterval));
  }

  throw new Error(`Scan timeout after ${maxWaitMs}ms`);
}

// Helper function to run a complete scan workflow
async function runCompleteScan(options: Record<string, any>): Promise<any> {
  // Create new task
  const taskResponse = await client.get("/task/new");
  const taskId = taskResponse.data.taskid;

  try {
    // Set options
    await client.post(`/option/${taskId}/set`, options);

    // Start scan
    await client.post(`/scan/${taskId}/start`);

    // Wait for completion
    const { status, returncode } = await waitForScan(taskId);

    // Get results
    const dataResponse = await client.get(`/scan/${taskId}/data`);
    const logResponse = await client.get(`/scan/${taskId}/log`);

    return {
      taskId,
      status,
      returncode,
      data: dataResponse.data.data,
      errors: dataResponse.data.error,
      log: logResponse.data.log,
    };
  } finally {
    // Cleanup task
    try {
      await client.get(`/task/${taskId}/delete`);
    } catch (e) {
      // Ignore cleanup errors
    }
  }
}

// Tool handlers
async function handleToolCall(
  name: string,
  args: Record<string, any>
): Promise<any> {
  switch (name) {
    case "sqlmap_new_task": {
      const response = await client.get("/task/new");
      return response.data;
    }

    case "sqlmap_delete_task": {
      const response = await client.get(`/task/${args.taskId}/delete`);
      return response.data;
    }

    case "sqlmap_set_options": {
      const response = await client.post(
        `/option/${args.taskId}/set`,
        args.options
      );
      return response.data;
    }

    case "sqlmap_get_options": {
      if (args.options && args.options.length > 0) {
        const response = await client.post(
          `/option/${args.taskId}/get`,
          args.options
        );
        return response.data;
      } else {
        const response = await client.get(`/option/${args.taskId}/list`);
        return response.data;
      }
    }

    case "sqlmap_list_options": {
      const response = await client.get(`/option/${args.taskId}/list`);
      return response.data;
    }

    case "sqlmap_start_scan": {
      const body: Record<string, any> = {};
      if (args.url) {
        body.url = args.url;
      }
      const response = await client.post(`/scan/${args.taskId}/start`, body);
      return response.data;
    }

    case "sqlmap_scan_status": {
      const response = await client.get(`/scan/${args.taskId}/status`);
      return response.data;
    }

    case "sqlmap_scan_data": {
      const response = await client.get(`/scan/${args.taskId}/data`);
      return response.data;
    }

    case "sqlmap_scan_log": {
      let url = `/scan/${args.taskId}/log`;
      if (args.start !== undefined && args.end !== undefined) {
        url = `/scan/${args.taskId}/log/${args.start}/${args.end}`;
      }
      const response = await client.get(url);
      return response.data;
    }

    case "sqlmap_stop_scan": {
      const response = await client.get(`/scan/${args.taskId}/stop`);
      return response.data;
    }

    case "sqlmap_kill_scan": {
      const response = await client.get(`/scan/${args.taskId}/kill`);
      return response.data;
    }

    case "sqlmap_version": {
      const response = await client.get("/version");
      return response.data;
    }

    case "sqlmap_enumerate_dbs": {
      const options: Record<string, any> = {
        url: args.url,
        dbs: true,
        level: args.level || 1,
        risk: args.risk || 1,
        batch: true,
      };
      if (args.technique) options.technique = args.technique;
      if (args.cookie) options.cookie = args.cookie;
      if (args.headers) options.headers = JSON.stringify(args.headers);
      if (args.data) options.data = args.data;
      if (args.dbms) options.dbms = args.dbms;

      return await runCompleteScan(options);
    }

    case "sqlmap_enumerate_tables": {
      const options: Record<string, any> = {
        url: args.url,
        tables: true,
        D: args.database,
        level: args.level || 1,
        risk: args.risk || 1,
        batch: true,
      };
      if (args.technique) options.technique = args.technique;
      if (args.cookie) options.cookie = args.cookie;
      if (args.dbms) options.dbms = args.dbms;

      return await runCompleteScan(options);
    }

    case "sqlmap_enumerate_columns": {
      const options: Record<string, any> = {
        url: args.url,
        columns: true,
        D: args.database,
        T: args.table,
        level: args.level || 1,
        risk: args.risk || 1,
        batch: true,
      };
      if (args.cookie) options.cookie = args.cookie;
      if (args.dbms) options.dbms = args.dbms;

      return await runCompleteScan(options);
    }

    case "sqlmap_dump_table": {
      const options: Record<string, any> = {
        url: args.url,
        dump: true,
        D: args.database,
        T: args.table,
        level: args.level || 1,
        risk: args.risk || 1,
        batch: true,
      };
      if (args.columns) options.C = args.columns;
      if (args.start !== undefined) options.limitStart = args.start;
      if (args.stop !== undefined) options.limitStop = args.stop;
      if (args.cookie) options.cookie = args.cookie;
      if (args.dbms) options.dbms = args.dbms;

      return await runCompleteScan(options);
    }

    case "sqlmap_os_shell": {
      const options: Record<string, any> = {
        url: args.url,
        osShell: true,
        level: args.level || 5,
        risk: args.risk || 3,
        batch: true,
      };
      if (args.cookie) options.cookie = args.cookie;
      if (args.dbms) options.dbms = args.dbms;
      if (args.webRoot) options.webRoot = args.webRoot;

      return await runCompleteScan(options);
    }

    case "sqlmap_os_cmd": {
      const options: Record<string, any> = {
        url: args.url,
        osCmd: args.command,
        level: args.level || 5,
        risk: args.risk || 3,
        batch: true,
      };
      if (args.cookie) options.cookie = args.cookie;
      if (args.dbms) options.dbms = args.dbms;

      return await runCompleteScan(options);
    }

    case "sqlmap_check_connection": {
      try {
        const response = await client.get("/version");
        return {
          connected: true,
          server: `${SQLMAP_API_HOST}:${SQLMAP_API_PORT}`,
          version: response.data.version,
        };
      } catch (error: any) {
        return {
          connected: false,
          server: `${SQLMAP_API_HOST}:${SQLMAP_API_PORT}`,
          error: error.message,
          hint: "Ensure sqlmapapi.py is running: python sqlmapapi.py -s",
        };
      }
    }

    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

// Create and configure the MCP server
const server = new Server(
  {
    name: "sqlmap-mcp",
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
    const result = await handleToolCall(name, args || {});
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(result, null, 2),
        },
      ],
    };
  } catch (error: any) {
    const errorMessage =
      error.response?.data?.message || error.message || "Unknown error";
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            {
              error: true,
              message: errorMessage,
              details: error.response?.data,
            },
            null,
            2
          ),
        },
      ],
      isError: true,
    };
  }
});

// Start the server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("sqlmap MCP server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
