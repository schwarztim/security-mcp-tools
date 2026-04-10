#!/usr/bin/env node
/**
 * Maltego MCP Server
 *
 * Provides MCP tools for interacting with Maltego:
 * - Transform management and execution
 * - Entity type operations
 * - Graph import/export
 * - Machine automation
 * - Local Transform Distribution Server (TDS) integration
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import axios, { AxiosInstance } from "axios";
import { parseStringPromise, Builder } from "xml2js";
import { MaltegoClient } from "./maltego-client.js";
import { MALTEGO_ENTITY_TYPES, MaltegoEntity, MaltegoTransformRequest, MaltegoTransformResponse, MaltegoGraph } from "./types.js";

// Configuration from environment
const config = {
  tdsUrl: process.env.MALTEGO_TDS_URL || "http://localhost:8081",
  transformServerUrl: process.env.MALTEGO_TRANSFORM_SERVER_URL || "http://localhost:8080",
  apiKey: process.env.MALTEGO_API_KEY || "",
  graphExportPath: process.env.MALTEGO_GRAPH_EXPORT_PATH || "/tmp/maltego-exports",
};

// Initialize Maltego client
const maltegoClient = new MaltegoClient(config);

// Define available tools
const tools: Tool[] = [
  {
    name: "maltego_list_transforms",
    description: "List all available Maltego transforms from the Transform Distribution Server (TDS). Returns transform names, descriptions, input/output entity types, and configuration.",
    inputSchema: {
      type: "object",
      properties: {
        category: {
          type: "string",
          description: "Optional category filter (e.g., 'DNS', 'Email', 'Social', 'Infrastructure')"
        },
        inputEntityType: {
          type: "string",
          description: "Filter transforms by input entity type (e.g., 'maltego.Domain', 'maltego.EmailAddress')"
        }
      }
    }
  },
  {
    name: "maltego_run_transform",
    description: "Execute a Maltego transform on an entity. Transforms take an input entity and return related entities discovered from various data sources.",
    inputSchema: {
      type: "object",
      properties: {
        transformName: {
          type: "string",
          description: "Name of the transform to execute (e.g., 'DNSToIP', 'EmailToPhoneNumbers')"
        },
        entityType: {
          type: "string",
          description: "Type of the input entity (e.g., 'maltego.Domain', 'maltego.EmailAddress', 'maltego.Person')"
        },
        entityValue: {
          type: "string",
          description: "Value of the input entity (e.g., 'example.com', 'user@example.com')"
        },
        entityProperties: {
          type: "object",
          description: "Optional additional properties for the entity",
          additionalProperties: { type: "string" }
        },
        transformSettings: {
          type: "object",
          description: "Optional transform-specific settings (API keys, limits, etc.)",
          additionalProperties: { type: "string" }
        },
        softLimit: {
          type: "number",
          description: "Soft limit on number of results (default: 12)"
        },
        hardLimit: {
          type: "number",
          description: "Hard limit on number of results (default: 10000)"
        }
      },
      required: ["transformName", "entityType", "entityValue"]
    }
  },
  {
    name: "maltego_list_entities",
    description: "List all available Maltego entity types with their properties and display settings.",
    inputSchema: {
      type: "object",
      properties: {
        category: {
          type: "string",
          description: "Filter entities by category (e.g., 'Infrastructure', 'Personal', 'Social')"
        },
        search: {
          type: "string",
          description: "Search term to filter entity types by name or description"
        }
      }
    }
  },
  {
    name: "maltego_create_entity",
    description: "Create a new Maltego entity with specified type, value, and properties.",
    inputSchema: {
      type: "object",
      properties: {
        entityType: {
          type: "string",
          description: "Type of the entity (e.g., 'maltego.Domain', 'maltego.Person')"
        },
        value: {
          type: "string",
          description: "Primary value of the entity"
        },
        properties: {
          type: "object",
          description: "Entity properties as key-value pairs",
          additionalProperties: { type: "string" }
        },
        weight: {
          type: "number",
          description: "Entity weight for graph layout (default: 100)"
        },
        notes: {
          type: "string",
          description: "Notes to attach to the entity"
        },
        bookmark: {
          type: "string",
          enum: ["none", "red", "blue", "green", "purple", "yellow"],
          description: "Bookmark color for the entity"
        }
      },
      required: ["entityType", "value"]
    }
  },
  {
    name: "maltego_export_graph",
    description: "Export a Maltego graph to various formats (GraphML, CSV, or Maltego native format).",
    inputSchema: {
      type: "object",
      properties: {
        entities: {
          type: "array",
          description: "Array of entities to include in the graph export",
          items: {
            type: "object",
            properties: {
              type: { type: "string" },
              value: { type: "string" },
              properties: { type: "object" }
            }
          }
        },
        links: {
          type: "array",
          description: "Array of links between entities",
          items: {
            type: "object",
            properties: {
              source: { type: "string" },
              target: { type: "string" },
              label: { type: "string" },
              properties: { type: "object" }
            }
          }
        },
        format: {
          type: "string",
          enum: ["graphml", "csv", "mtgx", "json"],
          description: "Export format (default: json)"
        },
        filename: {
          type: "string",
          description: "Output filename (without extension)"
        }
      },
      required: ["entities"]
    }
  },
  {
    name: "maltego_import_data",
    description: "Import data into Maltego format from various sources (CSV, JSON, or raw data).",
    inputSchema: {
      type: "object",
      properties: {
        data: {
          type: "array",
          description: "Array of data records to import",
          items: {
            type: "object",
            additionalProperties: true
          }
        },
        mapping: {
          type: "object",
          description: "Field mapping configuration",
          properties: {
            entityType: {
              type: "string",
              description: "Target entity type"
            },
            valueField: {
              type: "string",
              description: "Field to use as entity value"
            },
            propertyMappings: {
              type: "object",
              description: "Map data fields to entity properties",
              additionalProperties: { type: "string" }
            }
          }
        },
        createLinks: {
          type: "boolean",
          description: "Whether to create links between related entities"
        }
      },
      required: ["data", "mapping"]
    }
  },
  {
    name: "maltego_run_machine",
    description: "Run a Maltego machine (automated transform sequence) on an entity. Machines chain multiple transforms together for comprehensive investigation.",
    inputSchema: {
      type: "object",
      properties: {
        machineName: {
          type: "string",
          description: "Name of the machine to run (e.g., 'CompanyFootprint', 'PersonalFootprint', 'DomainRecon')"
        },
        entityType: {
          type: "string",
          description: "Type of the seed entity"
        },
        entityValue: {
          type: "string",
          description: "Value of the seed entity"
        },
        depth: {
          type: "number",
          description: "Maximum depth of transform chain (default: 3)"
        },
        timeout: {
          type: "number",
          description: "Timeout in seconds (default: 300)"
        }
      },
      required: ["machineName", "entityType", "entityValue"]
    }
  },
  {
    name: "maltego_get_transform_settings",
    description: "Get the required settings/configuration for a specific transform (API keys, credentials, options).",
    inputSchema: {
      type: "object",
      properties: {
        transformName: {
          type: "string",
          description: "Name of the transform"
        }
      },
      required: ["transformName"]
    }
  },
  {
    name: "maltego_validate_entity",
    description: "Validate an entity value against its type constraints and return normalized form.",
    inputSchema: {
      type: "object",
      properties: {
        entityType: {
          type: "string",
          description: "Type of the entity to validate"
        },
        value: {
          type: "string",
          description: "Value to validate"
        }
      },
      required: ["entityType", "value"]
    }
  },
  {
    name: "maltego_search_entities",
    description: "Search for entities across a graph by value, type, or properties.",
    inputSchema: {
      type: "object",
      properties: {
        query: {
          type: "string",
          description: "Search query string"
        },
        entityTypes: {
          type: "array",
          items: { type: "string" },
          description: "Filter by entity types"
        },
        properties: {
          type: "object",
          description: "Filter by property values",
          additionalProperties: { type: "string" }
        },
        limit: {
          type: "number",
          description: "Maximum results to return (default: 100)"
        }
      },
      required: ["query"]
    }
  },
  {
    name: "maltego_tds_status",
    description: "Check the status and connectivity of the Transform Distribution Server (TDS).",
    inputSchema: {
      type: "object",
      properties: {}
    }
  }
];

// Create MCP server
const server = new Server(
  {
    name: "maltego-mcp",
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
      case "maltego_list_transforms": {
        const result = await maltegoClient.listTransforms(
          args?.category as string | undefined,
          args?.inputEntityType as string | undefined
        );
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
        };
      }

      case "maltego_run_transform": {
        const transformRequest: MaltegoTransformRequest = {
          transformName: args?.transformName as string,
          entityType: args?.entityType as string,
          entityValue: args?.entityValue as string,
          entityProperties: args?.entityProperties as Record<string, string> | undefined,
          transformSettings: args?.transformSettings as Record<string, string> | undefined,
          softLimit: args?.softLimit as number | undefined,
          hardLimit: args?.hardLimit as number | undefined,
        };
        const result = await maltegoClient.runTransform(transformRequest);
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
        };
      }

      case "maltego_list_entities": {
        const result = await maltegoClient.listEntities(
          args?.category as string | undefined,
          args?.search as string | undefined
        );
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
        };
      }

      case "maltego_create_entity": {
        const entity = await maltegoClient.createEntity({
          type: args?.entityType as string,
          value: args?.value as string,
          properties: args?.properties as Record<string, string> | undefined,
          weight: args?.weight as number | undefined,
          notes: args?.notes as string | undefined,
          bookmark: args?.bookmark as string | undefined,
        });
        return {
          content: [{ type: "text", text: JSON.stringify(entity, null, 2) }]
        };
      }

      case "maltego_export_graph": {
        const result = await maltegoClient.exportGraph({
          entities: args?.entities as any[],
          links: args?.links as any[] | undefined,
          format: (args?.format as string) || "json",
          filename: args?.filename as string | undefined,
        });
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
        };
      }

      case "maltego_import_data": {
        const result = await maltegoClient.importData({
          data: args?.data as any[],
          mapping: args?.mapping as any,
          createLinks: args?.createLinks as boolean | undefined,
        });
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
        };
      }

      case "maltego_run_machine": {
        const result = await maltegoClient.runMachine({
          machineName: args?.machineName as string,
          entityType: args?.entityType as string,
          entityValue: args?.entityValue as string,
          depth: args?.depth as number | undefined,
          timeout: args?.timeout as number | undefined,
        });
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
        };
      }

      case "maltego_get_transform_settings": {
        const result = await maltegoClient.getTransformSettings(
          args?.transformName as string
        );
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
        };
      }

      case "maltego_validate_entity": {
        const result = await maltegoClient.validateEntity(
          args?.entityType as string,
          args?.value as string
        );
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
        };
      }

      case "maltego_search_entities": {
        const result = await maltegoClient.searchEntities({
          query: args?.query as string,
          entityTypes: args?.entityTypes as string[] | undefined,
          properties: args?.properties as Record<string, string> | undefined,
          limit: args?.limit as number | undefined,
        });
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
        };
      }

      case "maltego_tds_status": {
        const result = await maltegoClient.getTdsStatus();
        return {
          content: [{ type: "text", text: JSON.stringify(result, null, 2) }]
        };
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

// Start the server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Maltego MCP server started");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
