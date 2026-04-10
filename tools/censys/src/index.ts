#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import axios, { AxiosInstance } from "axios";

// Censys API v2 base URL
const CENSYS_API_BASE = "https://search.censys.io/api/v2";

// Environment variables for authentication
const CENSYS_API_ID = process.env.CENSYS_API_ID;
const CENSYS_API_SECRET = process.env.CENSYS_API_SECRET;

// Create axios instance with authentication
function createClient(): AxiosInstance {
  if (!CENSYS_API_ID || !CENSYS_API_SECRET) {
    throw new Error(
      "CENSYS_API_ID and CENSYS_API_SECRET environment variables are required"
    );
  }

  return axios.create({
    baseURL: CENSYS_API_BASE,
    auth: {
      username: CENSYS_API_ID,
      password: CENSYS_API_SECRET,
    },
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
    },
  });
}

// Tool definitions
const tools: Tool[] = [
  {
    name: "censys_search_hosts",
    description:
      "Search for hosts (IP addresses) using Censys Search Language. Returns paginated results of hosts matching the query. Common queries: 'services.port: 22', 'services.service_name: HTTP', 'location.country: US', 'autonomous_system.name: Amazon'",
    inputSchema: {
      type: "object",
      properties: {
        query: {
          type: "string",
          description:
            "Censys Search Language query (e.g., 'services.port: 443 AND location.country: US')",
        },
        per_page: {
          type: "number",
          description: "Results per page (default: 25, max: 100)",
          default: 25,
        },
        cursor: {
          type: "string",
          description: "Pagination cursor for next page of results",
        },
        virtual_hosts: {
          type: "string",
          enum: ["EXCLUDE", "INCLUDE", "ONLY"],
          description: "Virtual hosts filter (default: EXCLUDE)",
          default: "EXCLUDE",
        },
      },
      required: ["query"],
    },
  },
  {
    name: "censys_view_host",
    description:
      "Get detailed information about a specific host (IP address) including services, location, autonomous system, and historical data",
    inputSchema: {
      type: "object",
      properties: {
        ip: {
          type: "string",
          description: "IP address to look up",
        },
        at_time: {
          type: "string",
          description:
            "View host at a specific point in time (RFC3339 format, e.g., '2024-01-15T00:00:00Z')",
        },
      },
      required: ["ip"],
    },
  },
  {
    name: "censys_host_diff",
    description:
      "Compare a host's data between two points in time to see what changed",
    inputSchema: {
      type: "object",
      properties: {
        ip: {
          type: "string",
          description: "IP address to compare",
        },
        ip_b: {
          type: "string",
          description: "Second IP address (optional, for host-to-host comparison)",
        },
        at_time: {
          type: "string",
          description: "First timestamp (RFC3339 format)",
        },
        at_time_b: {
          type: "string",
          description: "Second timestamp (RFC3339 format)",
        },
      },
      required: ["ip"],
    },
  },
  {
    name: "censys_host_events",
    description:
      "Get a timeline of changes/events for a specific host over time",
    inputSchema: {
      type: "object",
      properties: {
        ip: {
          type: "string",
          description: "IP address to get events for",
        },
        start_time: {
          type: "string",
          description: "Start of time range (RFC3339 format)",
        },
        end_time: {
          type: "string",
          description: "End of time range (RFC3339 format)",
        },
        per_page: {
          type: "number",
          description: "Results per page (default: 25)",
          default: 25,
        },
        cursor: {
          type: "string",
          description: "Pagination cursor",
        },
      },
      required: ["ip"],
    },
  },
  {
    name: "censys_host_names",
    description:
      "Get DNS names (hostnames) that resolve to or are associated with an IP address",
    inputSchema: {
      type: "object",
      properties: {
        ip: {
          type: "string",
          description: "IP address to get hostnames for",
        },
        per_page: {
          type: "number",
          description: "Results per page (default: 25)",
          default: 25,
        },
        cursor: {
          type: "string",
          description: "Pagination cursor",
        },
      },
      required: ["ip"],
    },
  },
  {
    name: "censys_aggregate_hosts",
    description:
      "Generate aggregate statistics/reports for hosts matching a query. Get counts by field values (e.g., top countries, top ports, top services)",
    inputSchema: {
      type: "object",
      properties: {
        query: {
          type: "string",
          description: "Censys Search Language query",
        },
        field: {
          type: "string",
          description:
            "Field to aggregate on (e.g., 'location.country', 'services.port', 'autonomous_system.name')",
        },
        num_buckets: {
          type: "number",
          description: "Number of buckets/values to return (default: 50)",
          default: 50,
        },
        virtual_hosts: {
          type: "string",
          enum: ["EXCLUDE", "INCLUDE", "ONLY"],
          description: "Virtual hosts filter (default: EXCLUDE)",
          default: "EXCLUDE",
        },
      },
      required: ["query", "field"],
    },
  },
  {
    name: "censys_search_certs",
    description:
      "Search for SSL/TLS certificates using Censys Search Language. Find certificates by domain, issuer, validity, etc.",
    inputSchema: {
      type: "object",
      properties: {
        query: {
          type: "string",
          description:
            "Censys Search Language query for certificates (e.g., 'names: example.com', 'parsed.issuer.common_name: \"Let's Encrypt\"')",
        },
        per_page: {
          type: "number",
          description: "Results per page (default: 25, max: 100)",
          default: 25,
        },
        cursor: {
          type: "string",
          description: "Pagination cursor for next page of results",
        },
      },
      required: ["query"],
    },
  },
  {
    name: "censys_view_cert",
    description:
      "Get detailed information about a specific certificate by its SHA-256 fingerprint",
    inputSchema: {
      type: "object",
      properties: {
        fingerprint: {
          type: "string",
          description: "SHA-256 fingerprint of the certificate",
        },
      },
      required: ["fingerprint"],
    },
  },
  {
    name: "censys_cert_hosts",
    description:
      "Get the list of hosts that are currently presenting a specific certificate",
    inputSchema: {
      type: "object",
      properties: {
        fingerprint: {
          type: "string",
          description: "SHA-256 fingerprint of the certificate",
        },
        per_page: {
          type: "number",
          description: "Results per page (default: 25)",
          default: 25,
        },
        cursor: {
          type: "string",
          description: "Pagination cursor",
        },
      },
      required: ["fingerprint"],
    },
  },
  {
    name: "censys_aggregate_certs",
    description:
      "Generate aggregate statistics for certificates matching a query",
    inputSchema: {
      type: "object",
      properties: {
        query: {
          type: "string",
          description: "Censys Search Language query for certificates",
        },
        field: {
          type: "string",
          description:
            "Field to aggregate on (e.g., 'parsed.issuer.common_name', 'parsed.validity_period.not_after')",
        },
        num_buckets: {
          type: "number",
          description: "Number of buckets/values to return (default: 50)",
          default: 50,
        },
      },
      required: ["query", "field"],
    },
  },
  {
    name: "censys_list_tags",
    description: "List all available tags in your Censys account",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "censys_create_tag",
    description: "Create a new tag for organizing hosts or certificates",
    inputSchema: {
      type: "object",
      properties: {
        name: {
          type: "string",
          description: "Tag name",
        },
        color: {
          type: "string",
          description: "Tag color in hex format (e.g., '#FF5733')",
        },
      },
      required: ["name"],
    },
  },
  {
    name: "censys_tag_host",
    description: "Add or remove a tag from a host",
    inputSchema: {
      type: "object",
      properties: {
        ip: {
          type: "string",
          description: "IP address of the host",
        },
        tag_id: {
          type: "string",
          description: "Tag ID to add/remove",
        },
        action: {
          type: "string",
          enum: ["add", "remove"],
          description: "Whether to add or remove the tag",
        },
      },
      required: ["ip", "tag_id", "action"],
    },
  },
  {
    name: "censys_host_comments",
    description: "Get, add, or manage comments on a host",
    inputSchema: {
      type: "object",
      properties: {
        ip: {
          type: "string",
          description: "IP address of the host",
        },
        action: {
          type: "string",
          enum: ["list", "add"],
          description: "Action to perform",
        },
        comment: {
          type: "string",
          description: "Comment text (required for 'add' action)",
        },
      },
      required: ["ip", "action"],
    },
  },
  {
    name: "censys_metadata",
    description:
      "Get metadata about the Censys index including available services and data freshness",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
];

// Tool implementations
async function searchHosts(
  client: AxiosInstance,
  params: {
    query: string;
    per_page?: number;
    cursor?: string;
    virtual_hosts?: string;
  }
) {
  const response = await client.get("/hosts/search", {
    params: {
      q: params.query,
      per_page: params.per_page || 25,
      cursor: params.cursor,
      virtual_hosts: params.virtual_hosts || "EXCLUDE",
    },
  });
  return response.data;
}

async function viewHost(
  client: AxiosInstance,
  params: { ip: string; at_time?: string }
) {
  const url = params.at_time
    ? `/hosts/${params.ip}?at_time=${encodeURIComponent(params.at_time)}`
    : `/hosts/${params.ip}`;
  const response = await client.get(url);
  return response.data;
}

async function hostDiff(
  client: AxiosInstance,
  params: { ip: string; ip_b?: string; at_time?: string; at_time_b?: string }
) {
  const queryParams = new URLSearchParams();
  if (params.ip_b) queryParams.append("ip_b", params.ip_b);
  if (params.at_time) queryParams.append("at_time", params.at_time);
  if (params.at_time_b) queryParams.append("at_time_b", params.at_time_b);

  const url = `/hosts/${params.ip}/diff${queryParams.toString() ? "?" + queryParams.toString() : ""}`;
  const response = await client.get(url);
  return response.data;
}

async function hostEvents(
  client: AxiosInstance,
  params: {
    ip: string;
    start_time?: string;
    end_time?: string;
    per_page?: number;
    cursor?: string;
  }
) {
  const response = await client.get(`/hosts/${params.ip}/events`, {
    params: {
      start_time: params.start_time,
      end_time: params.end_time,
      per_page: params.per_page || 25,
      cursor: params.cursor,
    },
  });
  return response.data;
}

async function hostNames(
  client: AxiosInstance,
  params: { ip: string; per_page?: number; cursor?: string }
) {
  const response = await client.get(`/hosts/${params.ip}/names`, {
    params: {
      per_page: params.per_page || 25,
      cursor: params.cursor,
    },
  });
  return response.data;
}

async function aggregateHosts(
  client: AxiosInstance,
  params: {
    query: string;
    field: string;
    num_buckets?: number;
    virtual_hosts?: string;
  }
) {
  const response = await client.get("/hosts/aggregate", {
    params: {
      q: params.query,
      field: params.field,
      num_buckets: params.num_buckets || 50,
      virtual_hosts: params.virtual_hosts || "EXCLUDE",
    },
  });
  return response.data;
}

async function searchCerts(
  client: AxiosInstance,
  params: { query: string; per_page?: number; cursor?: string }
) {
  const response = await client.get("/certificates/search", {
    params: {
      q: params.query,
      per_page: params.per_page || 25,
      cursor: params.cursor,
    },
  });
  return response.data;
}

async function viewCert(
  client: AxiosInstance,
  params: { fingerprint: string }
) {
  const response = await client.get(`/certificates/${params.fingerprint}`);
  return response.data;
}

async function certHosts(
  client: AxiosInstance,
  params: { fingerprint: string; per_page?: number; cursor?: string }
) {
  const response = await client.get(
    `/certificates/${params.fingerprint}/hosts`,
    {
      params: {
        per_page: params.per_page || 25,
        cursor: params.cursor,
      },
    }
  );
  return response.data;
}

async function aggregateCerts(
  client: AxiosInstance,
  params: { query: string; field: string; num_buckets?: number }
) {
  const response = await client.get("/certificates/aggregate", {
    params: {
      q: params.query,
      field: params.field,
      num_buckets: params.num_buckets || 50,
    },
  });
  return response.data;
}

async function listTags(client: AxiosInstance) {
  const response = await client.get("/tags");
  return response.data;
}

async function createTag(
  client: AxiosInstance,
  params: { name: string; color?: string }
) {
  const response = await client.post("/tags", {
    name: params.name,
    color: params.color,
  });
  return response.data;
}

async function tagHost(
  client: AxiosInstance,
  params: { ip: string; tag_id: string; action: "add" | "remove" }
) {
  if (params.action === "add") {
    const response = await client.put(`/hosts/${params.ip}/tags/${params.tag_id}`);
    return response.data;
  } else {
    const response = await client.delete(
      `/hosts/${params.ip}/tags/${params.tag_id}`
    );
    return response.data;
  }
}

async function hostComments(
  client: AxiosInstance,
  params: { ip: string; action: "list" | "add"; comment?: string }
) {
  if (params.action === "list") {
    const response = await client.get(`/hosts/${params.ip}/comments`);
    return response.data;
  } else {
    if (!params.comment) {
      throw new Error("Comment text is required for 'add' action");
    }
    const response = await client.post(`/hosts/${params.ip}/comments`, {
      contents: params.comment,
    });
    return response.data;
  }
}

async function getMetadata(client: AxiosInstance) {
  const response = await client.get("/metadata/hosts");
  return response.data;
}

// Main server setup
async function main() {
  const server = new Server(
    {
      name: "censys-mcp",
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
      const client = createClient();
      let result: unknown;

      switch (name) {
        case "censys_search_hosts":
          result = await searchHosts(client, args as Parameters<typeof searchHosts>[1]);
          break;
        case "censys_view_host":
          result = await viewHost(client, args as Parameters<typeof viewHost>[1]);
          break;
        case "censys_host_diff":
          result = await hostDiff(client, args as Parameters<typeof hostDiff>[1]);
          break;
        case "censys_host_events":
          result = await hostEvents(client, args as Parameters<typeof hostEvents>[1]);
          break;
        case "censys_host_names":
          result = await hostNames(client, args as Parameters<typeof hostNames>[1]);
          break;
        case "censys_aggregate_hosts":
          result = await aggregateHosts(client, args as Parameters<typeof aggregateHosts>[1]);
          break;
        case "censys_search_certs":
          result = await searchCerts(client, args as Parameters<typeof searchCerts>[1]);
          break;
        case "censys_view_cert":
          result = await viewCert(client, args as Parameters<typeof viewCert>[1]);
          break;
        case "censys_cert_hosts":
          result = await certHosts(client, args as Parameters<typeof certHosts>[1]);
          break;
        case "censys_aggregate_certs":
          result = await aggregateCerts(client, args as Parameters<typeof aggregateCerts>[1]);
          break;
        case "censys_list_tags":
          result = await listTags(client);
          break;
        case "censys_create_tag":
          result = await createTag(client, args as Parameters<typeof createTag>[1]);
          break;
        case "censys_tag_host":
          result = await tagHost(client, args as Parameters<typeof tagHost>[1]);
          break;
        case "censys_host_comments":
          result = await hostComments(client, args as Parameters<typeof hostComments>[1]);
          break;
        case "censys_metadata":
          result = await getMetadata(client);
          break;
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
      const errorMessage =
        error instanceof Error ? error.message : "Unknown error occurred";
      const axiosError = error as { response?: { data?: unknown; status?: number } };

      let details = "";
      if (axiosError.response) {
        details = `\nStatus: ${axiosError.response.status}\nResponse: ${JSON.stringify(axiosError.response.data, null, 2)}`;
      }

      return {
        content: [
          {
            type: "text",
            text: `Error: ${errorMessage}${details}`,
          },
        ],
        isError: true,
      };
    }
  });

  // Start the server
  const transport = new StdioServerTransport();
  await server.connect(transport);

  console.error("Censys MCP server started");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
