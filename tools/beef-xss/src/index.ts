#!/usr/bin/env node
/**
 * BeEF (Browser Exploitation Framework) MCP Server
 *
 * Provides tools for interacting with BeEF REST API:
 * - Hook management (list, info, logs)
 * - Module execution (list, execute, results)
 * - DNS management (rules CRUD)
 * - Network discovery
 * - Autorun configuration
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import axios, { AxiosInstance, AxiosError } from "axios";

// Environment configuration
const BEEF_URL = process.env.BEEF_URL || "http://127.0.0.1:3000";
const BEEF_USERNAME = process.env.BEEF_USERNAME || "beef";
const BEEF_PASSWORD = process.env.BEEF_PASSWORD || "beef";

// API client state
let apiToken: string | null = null;
let axiosClient: AxiosInstance;

// Initialize axios client
function initClient() {
  axiosClient = axios.create({
    baseURL: BEEF_URL,
    timeout: 30000,
    headers: {
      "Content-Type": "application/json; charset=UTF-8",
    },
  });
}

// Authenticate and get API token
async function authenticate(): Promise<string> {
  try {
    const response = await axiosClient.post("/api/admin/login", {
      username: BEEF_USERNAME,
      passwd: BEEF_PASSWORD,
    });

    if (response.data.success && response.data.token) {
      apiToken = response.data.token as string;
      return apiToken;
    }
    throw new Error("Authentication failed: " + JSON.stringify(response.data));
  } catch (error) {
    if (error instanceof AxiosError) {
      throw new Error(`Authentication failed: ${error.message}`);
    }
    throw error;
  }
}

// Ensure we have a valid token
async function ensureAuthenticated(): Promise<string> {
  if (!apiToken) {
    return await authenticate();
  }
  return apiToken;
}

// Make authenticated API request
async function apiRequest(
  method: "GET" | "POST" | "DELETE",
  endpoint: string,
  data?: unknown
): Promise<unknown> {
  const token = await ensureAuthenticated();
  const url = `${endpoint}${endpoint.includes("?") ? "&" : "?"}token=${token}`;

  try {
    const response = await axiosClient.request({
      method,
      url,
      data,
    });
    return response.data;
  } catch (error) {
    if (error instanceof AxiosError) {
      // Token might be expired, try re-authenticating
      if (error.response?.status === 401) {
        apiToken = null;
        const newToken = await ensureAuthenticated();
        const retryUrl = `${endpoint}${endpoint.includes("?") ? "&" : "?"}token=${newToken}`;
        const response = await axiosClient.request({
          method,
          url: retryUrl,
          data,
        });
        return response.data;
      }
      throw new Error(`API request failed: ${error.message} - ${JSON.stringify(error.response?.data)}`);
    }
    throw error;
  }
}

// Tool definitions
const tools: Tool[] = [
  {
    name: "beef_status",
    description: "Check BeEF server status and authentication. Returns server version and connection info.",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "beef_hooks",
    description: "List all hooked browsers. Returns online and offline browsers with session IDs, browser info, OS, IP addresses, and hook timestamps.",
    inputSchema: {
      type: "object",
      properties: {
        status: {
          type: "string",
          description: "Filter by status: 'online', 'offline', or 'all' (default: 'all')",
          enum: ["online", "offline", "all"],
        },
      },
      required: [],
    },
  },
  {
    name: "beef_hook_info",
    description: "Get detailed information about a specific hooked browser including plugins, hardware, network details, and capabilities.",
    inputSchema: {
      type: "object",
      properties: {
        session: {
          type: "string",
          description: "The session ID of the hooked browser",
        },
      },
      required: ["session"],
    },
  },
  {
    name: "beef_logs",
    description: "Get logs for hooked browsers. Can retrieve global logs or logs specific to a browser session.",
    inputSchema: {
      type: "object",
      properties: {
        session: {
          type: "string",
          description: "Optional: Session ID to get logs for specific browser. Omit for global logs.",
        },
      },
      required: [],
    },
  },
  {
    name: "beef_modules",
    description: "List all available BeEF command modules with their IDs, names, and categories.",
    inputSchema: {
      type: "object",
      properties: {
        category: {
          type: "string",
          description: "Optional: Filter modules by category (e.g., 'Browser', 'Network', 'Social Engineering')",
        },
      },
      required: [],
    },
  },
  {
    name: "beef_module_info",
    description: "Get detailed information about a specific module including description, options, and required parameters.",
    inputSchema: {
      type: "object",
      properties: {
        module_id: {
          type: "number",
          description: "The ID of the module to get info for",
        },
      },
      required: ["module_id"],
    },
  },
  {
    name: "beef_execute",
    description: "Execute a BeEF command module against a hooked browser. Returns a command ID that can be used to retrieve results.",
    inputSchema: {
      type: "object",
      properties: {
        session: {
          type: "string",
          description: "The session ID of the target hooked browser",
        },
        module_id: {
          type: "number",
          description: "The ID of the module to execute",
        },
        options: {
          type: "object",
          description: "Module-specific options/parameters as key-value pairs",
          additionalProperties: true,
        },
      },
      required: ["session", "module_id"],
    },
  },
  {
    name: "beef_command_result",
    description: "Get the result of a previously executed command module.",
    inputSchema: {
      type: "object",
      properties: {
        session: {
          type: "string",
          description: "The session ID of the hooked browser",
        },
        module_id: {
          type: "number",
          description: "The ID of the module that was executed",
        },
        command_id: {
          type: "number",
          description: "The command ID returned from beef_execute",
        },
      },
      required: ["session", "module_id", "command_id"],
    },
  },
  {
    name: "beef_execute_multi_browser",
    description: "Execute a module against multiple hooked browsers simultaneously.",
    inputSchema: {
      type: "object",
      properties: {
        module_id: {
          type: "number",
          description: "The ID of the module to execute",
        },
        sessions: {
          type: "array",
          items: { type: "string" },
          description: "Array of session IDs to target",
        },
        options: {
          type: "object",
          description: "Module-specific options/parameters",
          additionalProperties: true,
        },
      },
      required: ["module_id", "sessions"],
    },
  },
  {
    name: "beef_execute_multi_module",
    description: "Execute multiple modules against a single hooked browser.",
    inputSchema: {
      type: "object",
      properties: {
        session: {
          type: "string",
          description: "The session ID of the target hooked browser",
        },
        modules: {
          type: "array",
          items: {
            type: "object",
            properties: {
              mod_id: { type: "number" },
              mod_input: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    name: { type: "string" },
                    value: { type: "string" },
                  },
                },
              },
            },
          },
          description: "Array of modules with their parameters",
        },
      },
      required: ["session", "modules"],
    },
  },
  {
    name: "beef_dns_rules",
    description: "List all DNS rules in the BeEF DNS server.",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "beef_dns_rule_info",
    description: "Get details of a specific DNS rule.",
    inputSchema: {
      type: "object",
      properties: {
        rule_id: {
          type: "string",
          description: "The unique ID of the DNS rule",
        },
      },
      required: ["rule_id"],
    },
  },
  {
    name: "beef_dns_add_rule",
    description: "Add a new DNS rule to the BeEF DNS server.",
    inputSchema: {
      type: "object",
      properties: {
        pattern: {
          type: "string",
          description: "DNS pattern to match (e.g., 'example.com' or '*.evil.com')",
        },
        resource: {
          type: "string",
          description: "DNS record type: A, AAAA, CNAME, MX, NS, etc.",
          enum: ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT"],
        },
        response: {
          type: "array",
          items: { type: "string" },
          description: "Array of response values (e.g., ['10.0.2.14'] for A record)",
        },
      },
      required: ["pattern", "resource", "response"],
    },
  },
  {
    name: "beef_dns_delete_rule",
    description: "Delete a DNS rule from the BeEF DNS server.",
    inputSchema: {
      type: "object",
      properties: {
        rule_id: {
          type: "string",
          description: "The unique ID of the DNS rule to delete",
        },
      },
      required: ["rule_id"],
    },
  },
  {
    name: "beef_network_hosts",
    description: "Get network hosts discovered through hooked browsers (requires network discovery modules to have been run).",
    inputSchema: {
      type: "object",
      properties: {
        session: {
          type: "string",
          description: "Optional: Filter by session ID",
        },
      },
      required: [],
    },
  },
  {
    name: "beef_autorun_rules",
    description: "List autorun rules that automatically execute modules on newly hooked browsers.",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "beef_autorun_add",
    description: "Add an autorun rule to automatically execute a module when browsers are hooked.",
    inputSchema: {
      type: "object",
      properties: {
        module_id: {
          type: "number",
          description: "The ID of the module to autorun",
        },
        options: {
          type: "object",
          description: "Module options/parameters",
          additionalProperties: true,
        },
        conditions: {
          type: "object",
          description: "Conditions for when to run (e.g., browser type, OS)",
          additionalProperties: true,
        },
      },
      required: ["module_id"],
    },
  },
];

// Tool handlers
async function handleTool(name: string, args: Record<string, unknown>): Promise<unknown> {
  switch (name) {
    case "beef_status": {
      try {
        const token = await ensureAuthenticated();
        return {
          status: "connected",
          server: BEEF_URL,
          authenticated: true,
          token_preview: token.substring(0, 8) + "...",
        };
      } catch (error) {
        return {
          status: "error",
          server: BEEF_URL,
          authenticated: false,
          error: error instanceof Error ? error.message : String(error),
        };
      }
    }

    case "beef_hooks": {
      const result = await apiRequest("GET", "/api/hooks") as {
        hooked_browsers?: {
          online?: Record<string, unknown>;
          offline?: Record<string, unknown>;
        };
      };
      const status = (args.status as string) || "all";

      if (status === "online") {
        return { online: result.hooked_browsers?.online || {} };
      } else if (status === "offline") {
        return { offline: result.hooked_browsers?.offline || {} };
      }
      return result;
    }

    case "beef_hook_info": {
      const session = args.session as string;
      return await apiRequest("GET", `/api/hooks/${session}`);
    }

    case "beef_logs": {
      const session = args.session as string | undefined;
      if (session) {
        return await apiRequest("GET", `/api/logs/${session}`);
      }
      return await apiRequest("GET", "/api/logs");
    }

    case "beef_modules": {
      const result = await apiRequest("GET", "/api/modules") as Record<string, unknown>;
      const category = args.category as string | undefined;

      if (category) {
        const filtered: Record<string, unknown> = {};
        for (const [id, module] of Object.entries(result)) {
          const mod = module as { category?: string };
          if (mod.category?.toLowerCase().includes(category.toLowerCase())) {
            filtered[id] = module;
          }
        }
        return filtered;
      }
      return result;
    }

    case "beef_module_info": {
      const moduleId = args.module_id as number;
      return await apiRequest("GET", `/api/modules/${moduleId}`);
    }

    case "beef_execute": {
      const session = args.session as string;
      const moduleId = args.module_id as number;
      const options = (args.options as Record<string, unknown>) || {};

      return await apiRequest("POST", `/api/modules/${session}/${moduleId}`, options);
    }

    case "beef_command_result": {
      const session = args.session as string;
      const moduleId = args.module_id as number;
      const commandId = args.command_id as number;

      return await apiRequest("GET", `/api/modules/${session}/${moduleId}/${commandId}`);
    }

    case "beef_execute_multi_browser": {
      const moduleId = args.module_id as number;
      const sessions = args.sessions as string[];
      const options = (args.options as Record<string, unknown>) || {};

      // Get hook IDs from sessions
      const hooksResult = await apiRequest("GET", "/api/hooks") as {
        hooked_browsers?: {
          online?: Record<string, { id?: number; session?: string }>;
          offline?: Record<string, { id?: number; session?: string }>;
        };
      };

      const hbIds: number[] = [];
      const allHooks = {
        ...(hooksResult.hooked_browsers?.online || {}),
        ...(hooksResult.hooked_browsers?.offline || {}),
      };

      for (const [, hook] of Object.entries(allHooks)) {
        if (sessions.includes(hook.session || "")) {
          if (hook.id) hbIds.push(hook.id);
        }
      }

      return await apiRequest("POST", "/api/modules/multi_browser", {
        mod_id: moduleId,
        mod_params: options,
        hb_ids: hbIds,
      });
    }

    case "beef_execute_multi_module": {
      const session = args.session as string;
      const modules = args.modules as Array<{ mod_id: number; mod_input?: Array<{ name: string; value: string }> }>;

      return await apiRequest("POST", "/api/modules/multi_module", {
        hb: session,
        modules: modules,
      });
    }

    case "beef_dns_rules": {
      return await apiRequest("GET", "/api/dns/ruleset");
    }

    case "beef_dns_rule_info": {
      const ruleId = args.rule_id as string;
      return await apiRequest("GET", `/api/dns/rule/${ruleId}`);
    }

    case "beef_dns_add_rule": {
      const pattern = args.pattern as string;
      const resource = args.resource as string;
      const response = args.response as string[];

      return await apiRequest("POST", "/api/dns/rule", {
        pattern,
        resource,
        response,
      });
    }

    case "beef_dns_delete_rule": {
      const ruleId = args.rule_id as string;
      return await apiRequest("DELETE", `/api/dns/rule/${ruleId}`);
    }

    case "beef_network_hosts": {
      // Network hosts are typically gathered via module results
      // This queries the hooks for any network discovery data
      const session = args.session as string | undefined;

      if (session) {
        // Get logs which may contain network discovery results
        return await apiRequest("GET", `/api/logs/${session}`);
      }

      // Return global logs for network-related events
      return await apiRequest("GET", "/api/logs");
    }

    case "beef_autorun_rules": {
      // Autorun rules endpoint
      try {
        return await apiRequest("GET", "/api/autorun");
      } catch {
        return {
          message: "Autorun API may not be enabled. Check BeEF configuration.",
          hint: "Enable autorun in config.yaml: autorun.enable: true",
        };
      }
    }

    case "beef_autorun_add": {
      const moduleId = args.module_id as number;
      const options = (args.options as Record<string, unknown>) || {};
      const conditions = (args.conditions as Record<string, unknown>) || {};

      try {
        return await apiRequest("POST", "/api/autorun/rule", {
          module_id: moduleId,
          options,
          conditions,
        });
      } catch {
        return {
          message: "Autorun API may not be enabled or rule format is incorrect.",
          hint: "Check BeEF documentation for autorun rule format.",
        };
      }
    }

    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

// Create and run the server
async function main() {
  initClient();

  const server = new Server(
    {
      name: "beef-xss-mcp",
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
      const result = await handleTool(name, (args || {}) as Record<string, unknown>);
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify(result, null, 2),
          },
        ],
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      return {
        content: [
          {
            type: "text",
            text: JSON.stringify({ error: errorMessage }, null, 2),
          },
        ],
        isError: true,
      };
    }
  });

  // Start the server
  const transport = new StdioServerTransport();
  await server.connect(transport);

  console.error("BeEF MCP Server started");
  console.error(`Connecting to BeEF at: ${BEEF_URL}`);
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
