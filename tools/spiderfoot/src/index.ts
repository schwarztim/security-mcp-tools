#!/usr/bin/env node
/**
 * SpiderFoot MCP Server
 *
 * Provides OSINT automation capabilities through the Model Context Protocol.
 * Connects to SpiderFoot's CherryPy web API (default port 5001).
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
const SPIDERFOOT_URL = process.env.SPIDERFOOT_URL || "http://127.0.0.1:5001";
const SPIDERFOOT_USERNAME = process.env.SPIDERFOOT_USERNAME || "";
const SPIDERFOOT_PASSWORD = process.env.SPIDERFOOT_PASSWORD || "";

// SpiderFoot API client
class SpiderFootClient {
  private client: AxiosInstance;
  private baseUrl: string;

  constructor(baseUrl: string, username?: string, password?: string) {
    this.baseUrl = baseUrl.replace(/\/$/, "");

    const config: any = {
      baseURL: this.baseUrl,
      timeout: 30000,
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept": "application/json",
      },
    };

    // Add digest auth if credentials provided
    if (username && password) {
      config.auth = {
        username,
        password,
      };
    }

    this.client = axios.create(config);
  }

  async ping(): Promise<any> {
    const response = await this.client.get("/ping");
    return response.data;
  }

  async scanlist(): Promise<any[]> {
    const response = await this.client.get("/scanlist");
    return response.data;
  }

  async scanstatus(scanId: string): Promise<any> {
    const response = await this.client.get("/scanstatus", {
      params: { id: scanId },
    });
    return response.data;
  }

  async startscan(
    scanName: string,
    scanTarget: string,
    modules?: string[],
    types?: string[],
    useCase?: string
  ): Promise<any> {
    const params = new URLSearchParams();
    params.append("scanname", scanName);
    params.append("scantarget", scanTarget);

    if (modules && modules.length > 0) {
      params.append("modulelist", modules.join(","));
    }
    if (types && types.length > 0) {
      params.append("typelist", types.join(","));
    }
    if (useCase) {
      params.append("usecase", useCase);
    }

    const response = await this.client.post("/startscan", params);
    return response.data;
  }

  async stopscan(scanId: string): Promise<any> {
    const response = await this.client.get("/stopscan", {
      params: { id: scanId },
    });
    return response.data;
  }

  async scandelete(scanId: string): Promise<any> {
    const response = await this.client.get("/scandelete", {
      params: { id: scanId },
    });
    return response.data;
  }

  async scansummary(scanId: string, by: string = "type"): Promise<any> {
    const response = await this.client.get("/scansummary", {
      params: { id: scanId, by },
    });
    return response.data;
  }

  async scaneventresults(
    scanId: string,
    eventType?: string,
    filterFp: boolean = false
  ): Promise<any[]> {
    const params: any = { id: scanId };
    if (eventType) params.eventType = eventType;
    if (filterFp) params.filterfp = "1";

    const response = await this.client.get("/scaneventresults", { params });
    return response.data;
  }

  async scaneventresultsunique(
    scanId: string,
    eventType: string,
    filterFp: boolean = false
  ): Promise<any[]> {
    const params: any = { id: scanId, eventType };
    if (filterFp) params.filterfp = "1";

    const response = await this.client.get("/scaneventresultsunique", { params });
    return response.data;
  }

  async modules(): Promise<any[]> {
    const response = await this.client.get("/modules");
    return response.data;
  }

  async eventtypes(): Promise<string[]> {
    const response = await this.client.get("/eventtypes");
    return response.data;
  }

  async correlationrules(): Promise<any[]> {
    const response = await this.client.get("/correlationrules");
    return response.data;
  }

  async scancorrelations(scanId: string): Promise<any[]> {
    const response = await this.client.get("/scancorrelations", {
      params: { id: scanId },
    });
    return response.data;
  }

  async scanlog(scanId: string, limit?: number): Promise<any[]> {
    const params: any = { id: scanId };
    if (limit) params.limit = limit;

    const response = await this.client.get("/scanlog", { params });
    return response.data;
  }

  async scanerrors(scanId: string, limit?: number): Promise<any[]> {
    const params: any = { id: scanId };
    if (limit) params.limit = limit;

    const response = await this.client.get("/scanerrors", { params });
    return response.data;
  }

  async search(
    scanId?: string,
    eventType?: string,
    value?: string
  ): Promise<any[]> {
    const params: any = {};
    if (scanId) params.id = scanId;
    if (eventType) params.eventType = eventType;
    if (value) params.value = value;

    const response = await this.client.get("/search", { params });
    return response.data;
  }

  async scanhistory(scanId: string): Promise<any[]> {
    const response = await this.client.get("/scanhistory", {
      params: { id: scanId },
    });
    return response.data;
  }

  async scanopts(scanId: string): Promise<any> {
    const response = await this.client.get("/scanopts", {
      params: { id: scanId },
    });
    return response.data;
  }

  async optsraw(): Promise<any> {
    const response = await this.client.get("/optsraw");
    return response.data;
  }

  async scanviz(scanId: string, gexf: boolean = false): Promise<string> {
    const response = await this.client.get("/scanviz", {
      params: { id: scanId, gexf: gexf ? "1" : "0" },
    });
    return response.data;
  }

  async scanexportjsonmulti(scanIds: string[]): Promise<any> {
    const response = await this.client.get("/scanexportjsonmulti", {
      params: { ids: scanIds.join(",") },
    });
    return response.data;
  }

  async scanelementtypediscovery(scanId: string, eventType: string): Promise<any> {
    const response = await this.client.get("/scanelementtypediscovery", {
      params: { id: scanId, eventType },
    });
    return response.data;
  }
}

// Tool definitions
const tools: Tool[] = [
  {
    name: "spiderfoot_ping",
    description: "Test connectivity to SpiderFoot server and get version info",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "spiderfoot_scans",
    description: "List all scans on the SpiderFoot server with their status and risk metrics",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "spiderfoot_scan_status",
    description: "Get detailed status of a specific scan including event type counts",
    inputSchema: {
      type: "object",
      properties: {
        scan_id: {
          type: "string",
          description: "The scan ID to check status for",
        },
      },
      required: ["scan_id"],
    },
  },
  {
    name: "spiderfoot_start_scan",
    description: "Start a new OSINT reconnaissance scan against a target. Supports domain names, IP addresses, email addresses, phone numbers, and more.",
    inputSchema: {
      type: "object",
      properties: {
        name: {
          type: "string",
          description: "Name for the scan (for identification)",
        },
        target: {
          type: "string",
          description: "Target to scan (domain, IP, email, phone, etc.)",
        },
        modules: {
          type: "array",
          items: { type: "string" },
          description: "Specific modules to use (optional, uses all by default)",
        },
        types: {
          type: "array",
          items: { type: "string" },
          description: "Event types to collect (optional)",
        },
        use_case: {
          type: "string",
          enum: ["all", "passive", "investigate", "footprint"],
          description: "Predefined scan profile: all (everything), passive (no active probing), investigate (threat investigation), footprint (attack surface mapping)",
        },
      },
      required: ["name", "target"],
    },
  },
  {
    name: "spiderfoot_stop_scan",
    description: "Stop a running scan. The scan will be marked as ABORT-REQUESTED.",
    inputSchema: {
      type: "object",
      properties: {
        scan_id: {
          type: "string",
          description: "The scan ID to stop",
        },
      },
      required: ["scan_id"],
    },
  },
  {
    name: "spiderfoot_delete_scan",
    description: "Delete a scan and all its associated data. Cannot delete running scans.",
    inputSchema: {
      type: "object",
      properties: {
        scan_id: {
          type: "string",
          description: "The scan ID to delete",
        },
      },
      required: ["scan_id"],
    },
  },
  {
    name: "spiderfoot_results",
    description: "Get scan results/findings. Can filter by event type and exclude false positives.",
    inputSchema: {
      type: "object",
      properties: {
        scan_id: {
          type: "string",
          description: "The scan ID to get results for",
        },
        event_type: {
          type: "string",
          description: "Filter by specific event type (e.g., 'EMAILADDR', 'IP_ADDRESS')",
        },
        filter_fp: {
          type: "boolean",
          description: "Exclude results marked as false positives",
          default: false,
        },
        unique: {
          type: "boolean",
          description: "Return only unique values (requires event_type)",
          default: false,
        },
      },
      required: ["scan_id"],
    },
  },
  {
    name: "spiderfoot_summary",
    description: "Get a summary of scan results grouped by type",
    inputSchema: {
      type: "object",
      properties: {
        scan_id: {
          type: "string",
          description: "The scan ID to summarize",
        },
        group_by: {
          type: "string",
          enum: ["type", "module", "entity"],
          description: "How to group the summary",
          default: "type",
        },
      },
      required: ["scan_id"],
    },
  },
  {
    name: "spiderfoot_modules",
    description: "List all available SpiderFoot modules with their descriptions and categories",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "spiderfoot_event_types",
    description: "List all data/event types that SpiderFoot can collect",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "spiderfoot_correlations",
    description: "Get correlation findings from a scan (related entities, patterns)",
    inputSchema: {
      type: "object",
      properties: {
        scan_id: {
          type: "string",
          description: "The scan ID to get correlations for",
        },
      },
      required: ["scan_id"],
    },
  },
  {
    name: "spiderfoot_correlation_rules",
    description: "List available correlation rules and their risk ratings",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "spiderfoot_scan_log",
    description: "Get the execution log for a scan",
    inputSchema: {
      type: "object",
      properties: {
        scan_id: {
          type: "string",
          description: "The scan ID to get logs for",
        },
        limit: {
          type: "number",
          description: "Maximum number of log entries to return",
        },
      },
      required: ["scan_id"],
    },
  },
  {
    name: "spiderfoot_scan_errors",
    description: "Get errors encountered during a scan",
    inputSchema: {
      type: "object",
      properties: {
        scan_id: {
          type: "string",
          description: "The scan ID to get errors for",
        },
        limit: {
          type: "number",
          description: "Maximum number of errors to return",
        },
      },
      required: ["scan_id"],
    },
  },
  {
    name: "spiderfoot_search",
    description: "Search across scans for specific data. Supports regex patterns (wrap in /).",
    inputSchema: {
      type: "object",
      properties: {
        scan_id: {
          type: "string",
          description: "Limit search to specific scan (optional)",
        },
        event_type: {
          type: "string",
          description: "Filter by event type (optional)",
        },
        value: {
          type: "string",
          description: "Search value or regex pattern (wrap in / for regex)",
        },
      },
      required: [],
    },
  },
  {
    name: "spiderfoot_config",
    description: "Get current SpiderFoot configuration settings",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "spiderfoot_scan_config",
    description: "Get the configuration used for a specific scan",
    inputSchema: {
      type: "object",
      properties: {
        scan_id: {
          type: "string",
          description: "The scan ID to get config for",
        },
      },
      required: ["scan_id"],
    },
  },
  {
    name: "spiderfoot_export",
    description: "Export scan data in JSON format for analysis",
    inputSchema: {
      type: "object",
      properties: {
        scan_ids: {
          type: "array",
          items: { type: "string" },
          description: "Scan IDs to export",
        },
      },
      required: ["scan_ids"],
    },
  },
  {
    name: "spiderfoot_graph",
    description: "Get scan data as a graph (for visualization). Returns GEXF or JSON format.",
    inputSchema: {
      type: "object",
      properties: {
        scan_id: {
          type: "string",
          description: "The scan ID to visualize",
        },
        format: {
          type: "string",
          enum: ["json", "gexf"],
          description: "Output format (json or gexf for Gephi)",
          default: "json",
        },
      },
      required: ["scan_id"],
    },
  },
  {
    name: "spiderfoot_discovery_path",
    description: "Trace how a specific data element was discovered (parent-child relationships)",
    inputSchema: {
      type: "object",
      properties: {
        scan_id: {
          type: "string",
          description: "The scan ID",
        },
        event_type: {
          type: "string",
          description: "The event type to trace",
        },
      },
      required: ["scan_id", "event_type"],
    },
  },
  {
    name: "spiderfoot_history",
    description: "Get scan history/timeline",
    inputSchema: {
      type: "object",
      properties: {
        scan_id: {
          type: "string",
          description: "The scan ID to get history for",
        },
      },
      required: ["scan_id"],
    },
  },
];

// Initialize SpiderFoot client
const sfClient = new SpiderFootClient(
  SPIDERFOOT_URL,
  SPIDERFOOT_USERNAME || undefined,
  SPIDERFOOT_PASSWORD || undefined
);

// Error handler
function handleError(error: unknown): string {
  if (axios.isAxiosError(error)) {
    const axiosError = error as AxiosError;
    if (axiosError.response) {
      return `SpiderFoot API error (${axiosError.response.status}): ${JSON.stringify(axiosError.response.data)}`;
    } else if (axiosError.request) {
      return `Cannot connect to SpiderFoot at ${SPIDERFOOT_URL}. Ensure SpiderFoot is running.`;
    }
  }
  if (error instanceof Error) {
    return `Error: ${error.message}`;
  }
  return `Unknown error: ${String(error)}`;
}

// Create MCP server
const server = new Server(
  {
    name: "spiderfoot-mcp",
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
    let result: any;

    switch (name) {
      case "spiderfoot_ping":
        result = await sfClient.ping();
        break;

      case "spiderfoot_scans":
        result = await sfClient.scanlist();
        break;

      case "spiderfoot_scan_status":
        result = await sfClient.scanstatus(args?.scan_id as string);
        break;

      case "spiderfoot_start_scan":
        result = await sfClient.startscan(
          args?.name as string,
          args?.target as string,
          args?.modules as string[] | undefined,
          args?.types as string[] | undefined,
          args?.use_case as string | undefined
        );
        break;

      case "spiderfoot_stop_scan":
        result = await sfClient.stopscan(args?.scan_id as string);
        break;

      case "spiderfoot_delete_scan":
        result = await sfClient.scandelete(args?.scan_id as string);
        break;

      case "spiderfoot_results":
        if (args?.unique && args?.event_type) {
          result = await sfClient.scaneventresultsunique(
            args?.scan_id as string,
            args?.event_type as string,
            args?.filter_fp as boolean
          );
        } else {
          result = await sfClient.scaneventresults(
            args?.scan_id as string,
            args?.event_type as string | undefined,
            args?.filter_fp as boolean
          );
        }
        break;

      case "spiderfoot_summary":
        result = await sfClient.scansummary(
          args?.scan_id as string,
          args?.group_by as string || "type"
        );
        break;

      case "spiderfoot_modules":
        result = await sfClient.modules();
        break;

      case "spiderfoot_event_types":
        result = await sfClient.eventtypes();
        break;

      case "spiderfoot_correlations":
        result = await sfClient.scancorrelations(args?.scan_id as string);
        break;

      case "spiderfoot_correlation_rules":
        result = await sfClient.correlationrules();
        break;

      case "spiderfoot_scan_log":
        result = await sfClient.scanlog(
          args?.scan_id as string,
          args?.limit as number | undefined
        );
        break;

      case "spiderfoot_scan_errors":
        result = await sfClient.scanerrors(
          args?.scan_id as string,
          args?.limit as number | undefined
        );
        break;

      case "spiderfoot_search":
        result = await sfClient.search(
          args?.scan_id as string | undefined,
          args?.event_type as string | undefined,
          args?.value as string | undefined
        );
        break;

      case "spiderfoot_config":
        result = await sfClient.optsraw();
        break;

      case "spiderfoot_scan_config":
        result = await sfClient.scanopts(args?.scan_id as string);
        break;

      case "spiderfoot_export":
        result = await sfClient.scanexportjsonmulti(args?.scan_ids as string[]);
        break;

      case "spiderfoot_graph":
        result = await sfClient.scanviz(
          args?.scan_id as string,
          args?.format === "gexf"
        );
        break;

      case "spiderfoot_discovery_path":
        result = await sfClient.scanelementtypediscovery(
          args?.scan_id as string,
          args?.event_type as string
        );
        break;

      case "spiderfoot_history":
        result = await sfClient.scanhistory(args?.scan_id as string);
        break;

      default:
        return {
          content: [
            {
              type: "text",
              text: `Unknown tool: ${name}`,
            },
          ],
          isError: true,
        };
    }

    return {
      content: [
        {
          type: "text",
          text: typeof result === "string" ? result : JSON.stringify(result, null, 2),
        },
      ],
    };
  } catch (error) {
    return {
      content: [
        {
          type: "text",
          text: handleError(error),
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
  console.error("SpiderFoot MCP server running on stdio");
  console.error(`Connecting to SpiderFoot at: ${SPIDERFOOT_URL}`);
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
