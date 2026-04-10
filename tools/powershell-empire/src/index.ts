#!/usr/bin/env node
/**
 * PowerShell Empire MCP Server
 *
 * Provides tools for interacting with Empire C2 framework via its REST API.
 * Supports the BC-Security Empire v5+ API (FastAPI-based).
 *
 * API Reference: https://bc-security.gitbook.io/empire-wiki/restful-api
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import axios, { AxiosInstance, AxiosError } from "axios";

// Configuration from environment variables
const EMPIRE_URL = process.env.EMPIRE_URL || "http://localhost:1337";
const EMPIRE_USERNAME = process.env.EMPIRE_USERNAME || "empireadmin";
const EMPIRE_PASSWORD = process.env.EMPIRE_PASSWORD || "password123";

// Empire API client
class EmpireClient {
  private client: AxiosInstance;
  private token: string | null = null;
  private tokenExpiry: number = 0;

  constructor(baseUrl: string) {
    this.client = axios.create({
      baseURL: baseUrl,
      timeout: 30000,
      headers: {
        "Content-Type": "application/json",
      },
    });
  }

  private async authenticate(): Promise<void> {
    // Check if we have a valid token
    if (this.token && Date.now() < this.tokenExpiry) {
      return;
    }

    try {
      const formData = new URLSearchParams();
      formData.append("username", EMPIRE_USERNAME);
      formData.append("password", EMPIRE_PASSWORD);

      const response = await this.client.post("/token", formData, {
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
      });

      this.token = response.data.access_token;
      // Token valid for 30 minutes, refresh at 25
      this.tokenExpiry = Date.now() + 25 * 60 * 1000;

      this.client.defaults.headers.common["Authorization"] = `Bearer ${this.token}`;
    } catch (error) {
      const axiosError = error as AxiosError;
      throw new Error(`Authentication failed: ${axiosError.message}`);
    }
  }

  async request<T>(method: string, endpoint: string, data?: unknown): Promise<T> {
    await this.authenticate();

    try {
      const response = await this.client.request<T>({
        method,
        url: endpoint,
        data,
      });
      return response.data;
    } catch (error) {
      const axiosError = error as AxiosError;
      if (axiosError.response) {
        throw new Error(
          `Empire API error (${axiosError.response.status}): ${JSON.stringify(axiosError.response.data)}`
        );
      }
      throw new Error(`Empire API request failed: ${axiosError.message}`);
    }
  }

  // Listener operations
  async listListeners(): Promise<unknown> {
    return this.request("GET", "/api/v2/listeners/");
  }

  async getListener(listenerId: string): Promise<unknown> {
    return this.request("GET", `/api/v2/listeners/${listenerId}`);
  }

  async listListenerTemplates(): Promise<unknown> {
    return this.request("GET", "/api/v2/listener-templates/");
  }

  async createListener(template: string, name: string, options: Record<string, unknown>): Promise<unknown> {
    return this.request("POST", "/api/v2/listeners/", {
      template,
      name,
      options,
    });
  }

  async deleteListener(listenerId: string): Promise<unknown> {
    return this.request("DELETE", `/api/v2/listeners/${listenerId}`);
  }

  async enableListener(listenerId: string): Promise<unknown> {
    return this.request("PUT", `/api/v2/listeners/${listenerId}`, { enabled: true });
  }

  async disableListener(listenerId: string): Promise<unknown> {
    return this.request("PUT", `/api/v2/listeners/${listenerId}`, { enabled: false });
  }

  // Stager operations
  async listStagerTemplates(): Promise<unknown> {
    return this.request("GET", "/api/v2/stager-templates/");
  }

  async listStagers(): Promise<unknown> {
    return this.request("GET", "/api/v2/stagers/");
  }

  async createStager(template: string, name: string, options: Record<string, unknown>, save: boolean = true): Promise<unknown> {
    return this.request("POST", `/api/v2/stagers/?save=${save}`, {
      template,
      name,
      options,
    });
  }

  async getStager(stagerId: string): Promise<unknown> {
    return this.request("GET", `/api/v2/stagers/${stagerId}`);
  }

  async deleteStager(stagerId: string): Promise<unknown> {
    return this.request("DELETE", `/api/v2/stagers/${stagerId}`);
  }

  // Agent operations
  async listAgents(): Promise<unknown> {
    return this.request("GET", "/api/v2/agents/");
  }

  async getAgent(agentId: string): Promise<unknown> {
    return this.request("GET", `/api/v2/agents/${agentId}`);
  }

  async killAgent(agentId: string): Promise<unknown> {
    return this.request("DELETE", `/api/v2/agents/${agentId}`);
  }

  async renameAgent(agentId: string, newName: string): Promise<unknown> {
    return this.request("PUT", `/api/v2/agents/${agentId}`, { name: newName });
  }

  async getAgentCheckins(agentId: string): Promise<unknown> {
    return this.request("GET", `/api/v2/agents/${agentId}/checkins/`);
  }

  async getAgentFiles(agentId: string): Promise<unknown> {
    return this.request("GET", `/api/v2/agents/${agentId}/files/`);
  }

  // Task operations (shell commands, etc.)
  async listAgentTasks(agentId: string): Promise<unknown> {
    return this.request("GET", `/api/v2/agents/${agentId}/tasks/`);
  }

  async executeShell(agentId: string, command: string): Promise<unknown> {
    return this.request("POST", `/api/v2/agents/${agentId}/tasks/shell/`, {
      command,
    });
  }

  async getTaskResult(agentId: string, taskId: string): Promise<unknown> {
    return this.request("GET", `/api/v2/agents/${agentId}/tasks/${taskId}`);
  }

  // Module operations
  async listModules(search?: string): Promise<unknown> {
    const params = search ? `?search=${encodeURIComponent(search)}` : "";
    return this.request("GET", `/api/v2/modules/${params}`);
  }

  async getModule(moduleId: string): Promise<unknown> {
    return this.request("GET", `/api/v2/modules/${moduleId}`);
  }

  async executeModule(agentId: string, moduleId: string, options: Record<string, unknown>): Promise<unknown> {
    return this.request("POST", `/api/v2/agents/${agentId}/tasks/module/`, {
      module_id: moduleId,
      options,
    });
  }

  // File operations
  async uploadFile(agentId: string, filePath: string, data: string): Promise<unknown> {
    return this.request("POST", `/api/v2/agents/${agentId}/tasks/upload/`, {
      path_to_file: filePath,
      file_data: data,
    });
  }

  async downloadFile(agentId: string, filePath: string): Promise<unknown> {
    return this.request("POST", `/api/v2/agents/${agentId}/tasks/download/`, {
      path_to_file: filePath,
    });
  }

  // Downloads API (server-side)
  async listDownloads(): Promise<unknown> {
    return this.request("GET", "/api/v2/downloads/");
  }

  async getDownload(downloadId: string): Promise<unknown> {
    return this.request("GET", `/api/v2/downloads/${downloadId}`);
  }

  // Credentials
  async listCredentials(): Promise<unknown> {
    return this.request("GET", "/api/v2/credentials/");
  }

  async createCredential(credType: string, domain: string, username: string, password: string, host?: string, notes?: string): Promise<unknown> {
    return this.request("POST", "/api/v2/credentials/", {
      credtype: credType,
      domain,
      username,
      password,
      host,
      notes,
    });
  }

  // Hosts
  async listHosts(): Promise<unknown> {
    return this.request("GET", "/api/v2/hosts/");
  }

  // Plugins
  async listPlugins(): Promise<unknown> {
    return this.request("GET", "/api/v2/plugins/");
  }

  async executePlugin(pluginId: string, options: Record<string, unknown>): Promise<unknown> {
    return this.request("POST", `/api/v2/plugins/${pluginId}/execute/`, options);
  }

  // Bypasses
  async listBypasses(): Promise<unknown> {
    return this.request("GET", "/api/v2/bypasses/");
  }

  // Obfuscation
  async getObfuscationConfig(language: string): Promise<unknown> {
    return this.request("GET", `/api/v2/obfuscation/global/${language}`);
  }

  // Malleable profiles (for HTTP/S listeners)
  async listMalleableProfiles(): Promise<unknown> {
    return this.request("GET", "/api/v2/malleable-profiles/");
  }
}

// Tool definitions
const tools: Tool[] = [
  {
    name: "empire_listeners",
    description: "Manage Empire listeners - list, create, enable, disable, or delete listeners",
    inputSchema: {
      type: "object",
      properties: {
        action: {
          type: "string",
          enum: ["list", "get", "templates", "create", "delete", "enable", "disable"],
          description: "Action to perform",
        },
        listener_id: {
          type: "string",
          description: "Listener ID (required for get, delete, enable, disable)",
        },
        template: {
          type: "string",
          description: "Listener template name (required for create)",
        },
        name: {
          type: "string",
          description: "Listener name (required for create)",
        },
        options: {
          type: "object",
          description: "Listener options (for create)",
          additionalProperties: true,
        },
      },
      required: ["action"],
    },
  },
  {
    name: "empire_stagers",
    description: "Generate and manage stagers/payloads for Empire agents",
    inputSchema: {
      type: "object",
      properties: {
        action: {
          type: "string",
          enum: ["list", "templates", "create", "get", "delete"],
          description: "Action to perform",
        },
        stager_id: {
          type: "string",
          description: "Stager ID (for get, delete)",
        },
        template: {
          type: "string",
          description: "Stager template name (required for create)",
        },
        name: {
          type: "string",
          description: "Stager name (required for create)",
        },
        options: {
          type: "object",
          description: "Stager options including Listener (for create)",
          additionalProperties: true,
        },
        save: {
          type: "boolean",
          description: "Whether to save the stager (default true)",
          default: true,
        },
      },
      required: ["action"],
    },
  },
  {
    name: "empire_agents",
    description: "List and manage active Empire agents",
    inputSchema: {
      type: "object",
      properties: {
        action: {
          type: "string",
          enum: ["list", "get", "kill", "rename", "checkins", "files", "tasks"],
          description: "Action to perform",
        },
        agent_id: {
          type: "string",
          description: "Agent ID or name (required for get, kill, rename, checkins, files, tasks)",
        },
        new_name: {
          type: "string",
          description: "New name for the agent (required for rename)",
        },
      },
      required: ["action"],
    },
  },
  {
    name: "empire_modules",
    description: "Search and view Empire post-exploitation modules",
    inputSchema: {
      type: "object",
      properties: {
        action: {
          type: "string",
          enum: ["list", "search", "get", "execute"],
          description: "Action to perform",
        },
        search: {
          type: "string",
          description: "Search term for modules (for list/search)",
        },
        module_id: {
          type: "string",
          description: "Module ID (for get, execute)",
        },
        agent_id: {
          type: "string",
          description: "Agent ID to run module on (required for execute)",
        },
        options: {
          type: "object",
          description: "Module options (for execute)",
          additionalProperties: true,
        },
      },
      required: ["action"],
    },
  },
  {
    name: "empire_shell",
    description: "Execute shell commands on an Empire agent",
    inputSchema: {
      type: "object",
      properties: {
        agent_id: {
          type: "string",
          description: "Agent ID or name to execute on",
        },
        command: {
          type: "string",
          description: "Shell command to execute",
        },
      },
      required: ["agent_id", "command"],
    },
  },
  {
    name: "empire_upload",
    description: "Upload a file to an Empire agent",
    inputSchema: {
      type: "object",
      properties: {
        agent_id: {
          type: "string",
          description: "Agent ID or name",
        },
        remote_path: {
          type: "string",
          description: "Path on the target system to upload to",
        },
        file_data: {
          type: "string",
          description: "Base64-encoded file content",
        },
      },
      required: ["agent_id", "remote_path", "file_data"],
    },
  },
  {
    name: "empire_download",
    description: "Download a file from an Empire agent",
    inputSchema: {
      type: "object",
      properties: {
        agent_id: {
          type: "string",
          description: "Agent ID or name",
        },
        remote_path: {
          type: "string",
          description: "Path on the target system to download",
        },
      },
      required: ["agent_id", "remote_path"],
    },
  },
  {
    name: "empire_credentials",
    description: "Manage harvested credentials in Empire",
    inputSchema: {
      type: "object",
      properties: {
        action: {
          type: "string",
          enum: ["list", "create"],
          description: "Action to perform",
        },
        credtype: {
          type: "string",
          description: "Credential type (hash, plaintext, etc.) - for create",
        },
        domain: {
          type: "string",
          description: "Domain - for create",
        },
        username: {
          type: "string",
          description: "Username - for create",
        },
        password: {
          type: "string",
          description: "Password or hash - for create",
        },
        host: {
          type: "string",
          description: "Host where credential was found - for create",
        },
        notes: {
          type: "string",
          description: "Notes - for create",
        },
      },
      required: ["action"],
    },
  },
  {
    name: "empire_hosts",
    description: "List hosts that agents are running on",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "empire_downloads",
    description: "List files downloaded from agents",
    inputSchema: {
      type: "object",
      properties: {
        action: {
          type: "string",
          enum: ["list", "get"],
          description: "Action to perform",
        },
        download_id: {
          type: "string",
          description: "Download ID (for get)",
        },
      },
      required: ["action"],
    },
  },
  {
    name: "empire_plugins",
    description: "Manage Empire plugins",
    inputSchema: {
      type: "object",
      properties: {
        action: {
          type: "string",
          enum: ["list", "execute"],
          description: "Action to perform",
        },
        plugin_id: {
          type: "string",
          description: "Plugin ID (for execute)",
        },
        options: {
          type: "object",
          description: "Plugin execution options (for execute)",
          additionalProperties: true,
        },
      },
      required: ["action"],
    },
  },
  {
    name: "empire_bypasses",
    description: "List available AMSI/AV bypasses",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "empire_profiles",
    description: "List malleable C2 profiles for HTTP listeners",
    inputSchema: {
      type: "object",
      properties: {},
    },
  },
  {
    name: "empire_task_result",
    description: "Get the result of a specific task",
    inputSchema: {
      type: "object",
      properties: {
        agent_id: {
          type: "string",
          description: "Agent ID or name",
        },
        task_id: {
          type: "string",
          description: "Task ID to get result for",
        },
      },
      required: ["agent_id", "task_id"],
    },
  },
];

// Initialize Empire client
const empireClient = new EmpireClient(EMPIRE_URL);

// Create MCP server
const server = new Server(
  {
    name: "powershell-empire-mcp",
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

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    let result: unknown;

    switch (name) {
      case "empire_listeners": {
        const { action, listener_id, template, name: listenerName, options } = args as {
          action: string;
          listener_id?: string;
          template?: string;
          name?: string;
          options?: Record<string, unknown>;
        };

        switch (action) {
          case "list":
            result = await empireClient.listListeners();
            break;
          case "get":
            if (!listener_id) throw new Error("listener_id required for get action");
            result = await empireClient.getListener(listener_id);
            break;
          case "templates":
            result = await empireClient.listListenerTemplates();
            break;
          case "create":
            if (!template || !listenerName) throw new Error("template and name required for create action");
            result = await empireClient.createListener(template, listenerName, options || {});
            break;
          case "delete":
            if (!listener_id) throw new Error("listener_id required for delete action");
            result = await empireClient.deleteListener(listener_id);
            break;
          case "enable":
            if (!listener_id) throw new Error("listener_id required for enable action");
            result = await empireClient.enableListener(listener_id);
            break;
          case "disable":
            if (!listener_id) throw new Error("listener_id required for disable action");
            result = await empireClient.disableListener(listener_id);
            break;
          default:
            throw new Error(`Unknown action: ${action}`);
        }
        break;
      }

      case "empire_stagers": {
        const { action, stager_id, template, name: stagerName, options, save } = args as {
          action: string;
          stager_id?: string;
          template?: string;
          name?: string;
          options?: Record<string, unknown>;
          save?: boolean;
        };

        switch (action) {
          case "list":
            result = await empireClient.listStagers();
            break;
          case "templates":
            result = await empireClient.listStagerTemplates();
            break;
          case "create":
            if (!template || !stagerName) throw new Error("template and name required for create action");
            result = await empireClient.createStager(template, stagerName, options || {}, save !== false);
            break;
          case "get":
            if (!stager_id) throw new Error("stager_id required for get action");
            result = await empireClient.getStager(stager_id);
            break;
          case "delete":
            if (!stager_id) throw new Error("stager_id required for delete action");
            result = await empireClient.deleteStager(stager_id);
            break;
          default:
            throw new Error(`Unknown action: ${action}`);
        }
        break;
      }

      case "empire_agents": {
        const { action, agent_id, new_name } = args as {
          action: string;
          agent_id?: string;
          new_name?: string;
        };

        switch (action) {
          case "list":
            result = await empireClient.listAgents();
            break;
          case "get":
            if (!agent_id) throw new Error("agent_id required for get action");
            result = await empireClient.getAgent(agent_id);
            break;
          case "kill":
            if (!agent_id) throw new Error("agent_id required for kill action");
            result = await empireClient.killAgent(agent_id);
            break;
          case "rename":
            if (!agent_id || !new_name) throw new Error("agent_id and new_name required for rename action");
            result = await empireClient.renameAgent(agent_id, new_name);
            break;
          case "checkins":
            if (!agent_id) throw new Error("agent_id required for checkins action");
            result = await empireClient.getAgentCheckins(agent_id);
            break;
          case "files":
            if (!agent_id) throw new Error("agent_id required for files action");
            result = await empireClient.getAgentFiles(agent_id);
            break;
          case "tasks":
            if (!agent_id) throw new Error("agent_id required for tasks action");
            result = await empireClient.listAgentTasks(agent_id);
            break;
          default:
            throw new Error(`Unknown action: ${action}`);
        }
        break;
      }

      case "empire_modules": {
        const { action, search, module_id, agent_id, options } = args as {
          action: string;
          search?: string;
          module_id?: string;
          agent_id?: string;
          options?: Record<string, unknown>;
        };

        switch (action) {
          case "list":
          case "search":
            result = await empireClient.listModules(search);
            break;
          case "get":
            if (!module_id) throw new Error("module_id required for get action");
            result = await empireClient.getModule(module_id);
            break;
          case "execute":
            if (!module_id || !agent_id) throw new Error("module_id and agent_id required for execute action");
            result = await empireClient.executeModule(agent_id, module_id, options || {});
            break;
          default:
            throw new Error(`Unknown action: ${action}`);
        }
        break;
      }

      case "empire_shell": {
        const { agent_id, command } = args as { agent_id: string; command: string };
        result = await empireClient.executeShell(agent_id, command);
        break;
      }

      case "empire_upload": {
        const { agent_id, remote_path, file_data } = args as {
          agent_id: string;
          remote_path: string;
          file_data: string;
        };
        result = await empireClient.uploadFile(agent_id, remote_path, file_data);
        break;
      }

      case "empire_download": {
        const { agent_id, remote_path } = args as { agent_id: string; remote_path: string };
        result = await empireClient.downloadFile(agent_id, remote_path);
        break;
      }

      case "empire_credentials": {
        const { action, credtype, domain, username, password, host, notes } = args as {
          action: string;
          credtype?: string;
          domain?: string;
          username?: string;
          password?: string;
          host?: string;
          notes?: string;
        };

        switch (action) {
          case "list":
            result = await empireClient.listCredentials();
            break;
          case "create":
            if (!credtype || !domain || !username || !password) {
              throw new Error("credtype, domain, username, and password required for create action");
            }
            result = await empireClient.createCredential(credtype, domain, username, password, host, notes);
            break;
          default:
            throw new Error(`Unknown action: ${action}`);
        }
        break;
      }

      case "empire_hosts": {
        result = await empireClient.listHosts();
        break;
      }

      case "empire_downloads": {
        const { action, download_id } = args as { action: string; download_id?: string };

        switch (action) {
          case "list":
            result = await empireClient.listDownloads();
            break;
          case "get":
            if (!download_id) throw new Error("download_id required for get action");
            result = await empireClient.getDownload(download_id);
            break;
          default:
            throw new Error(`Unknown action: ${action}`);
        }
        break;
      }

      case "empire_plugins": {
        const { action, plugin_id, options } = args as {
          action: string;
          plugin_id?: string;
          options?: Record<string, unknown>;
        };

        switch (action) {
          case "list":
            result = await empireClient.listPlugins();
            break;
          case "execute":
            if (!plugin_id) throw new Error("plugin_id required for execute action");
            result = await empireClient.executePlugin(plugin_id, options || {});
            break;
          default:
            throw new Error(`Unknown action: ${action}`);
        }
        break;
      }

      case "empire_bypasses": {
        result = await empireClient.listBypasses();
        break;
      }

      case "empire_profiles": {
        result = await empireClient.listMalleableProfiles();
        break;
      }

      case "empire_task_result": {
        const { agent_id, task_id } = args as { agent_id: string; task_id: string };
        result = await empireClient.getTaskResult(agent_id, task_id);
        break;
      }

      default:
        throw new Error(`Unknown tool: ${name}`);
    }

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
          text: `Error: ${errorMessage}`,
        },
      ],
      isError: true,
    };
  }
});

// Main entry point
async function main(): Promise<void> {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("PowerShell Empire MCP server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
