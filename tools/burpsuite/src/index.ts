#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  ErrorCode,
  McpError,
} from '@modelcontextprotocol/sdk/types.js';
import { BurpClient, BurpConfig } from './burp-client.js';

// Configuration from environment variables
const BURP_URL = process.env.BURP_URL || 'http://127.0.0.1:1337';
const BURP_API_KEY = process.env.BURP_API_KEY;
const BURP_TIMEOUT = parseInt(process.env.BURP_TIMEOUT || '30000', 10);

// Initialize Burp client
const burpConfig: BurpConfig = {
  baseUrl: BURP_URL,
  apiKey: BURP_API_KEY,
  timeout: BURP_TIMEOUT,
};

const burpClient = new BurpClient(burpConfig);

// Create MCP server
const server = new Server(
  {
    name: 'burpsuite-mcp',
    version: '1.0.0',
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Tool definitions
const tools = [
  {
    name: 'burp_health_check',
    description: 'Check if Burp Suite REST API is accessible and responding',
    inputSchema: {
      type: 'object' as const,
      properties: {},
      required: [],
    },
  },
  {
    name: 'burp_get_version',
    description: 'Get Burp Suite version and edition information',
    inputSchema: {
      type: 'object' as const,
      properties: {},
      required: [],
    },
  },
  {
    name: 'burp_scan_start',
    description: 'Start an active vulnerability scan against a target URL. Returns a scan ID for tracking.',
    inputSchema: {
      type: 'object' as const,
      properties: {
        url: {
          type: 'string',
          description: 'The target URL to scan (e.g., https://example.com)',
        },
        scope: {
          type: 'string',
          description: 'Optional scope pattern to limit the scan (e.g., https://example.com/api/*)',
        },
      },
      required: ['url'],
    },
  },
  {
    name: 'burp_scan_status',
    description: 'Get the status of a running or completed scan',
    inputSchema: {
      type: 'object' as const,
      properties: {
        scanId: {
          type: 'string',
          description: 'The scan ID returned from burp_scan_start. Leave empty to get overall scan status.',
        },
      },
      required: [],
    },
  },
  {
    name: 'burp_scan_pause',
    description: 'Pause the currently running scan',
    inputSchema: {
      type: 'object' as const,
      properties: {},
      required: [],
    },
  },
  {
    name: 'burp_scan_resume',
    description: 'Resume a paused scan',
    inputSchema: {
      type: 'object' as const,
      properties: {},
      required: [],
    },
  },
  {
    name: 'burp_issues_list',
    description: 'List all identified security issues/vulnerabilities from the scanner',
    inputSchema: {
      type: 'object' as const,
      properties: {
        urlPrefix: {
          type: 'string',
          description: 'Optional URL prefix to filter issues (e.g., https://example.com/api)',
        },
      },
      required: [],
    },
  },
  {
    name: 'burp_issue_definitions',
    description: 'Get the knowledge base of issue types that Burp can detect',
    inputSchema: {
      type: 'object' as const,
      properties: {},
      required: [],
    },
  },
  {
    name: 'burp_sitemap_get',
    description: 'Get the sitemap contents showing discovered URLs and resources',
    inputSchema: {
      type: 'object' as const,
      properties: {
        urlPrefix: {
          type: 'string',
          description: 'Optional URL prefix to filter sitemap entries',
        },
      },
      required: [],
    },
  },
  {
    name: 'burp_scope_add',
    description: 'Add a URL to the target scope',
    inputSchema: {
      type: 'object' as const,
      properties: {
        url: {
          type: 'string',
          description: 'The URL to add to scope',
        },
      },
      required: ['url'],
    },
  },
  {
    name: 'burp_scope_remove',
    description: 'Remove a URL from the target scope',
    inputSchema: {
      type: 'object' as const,
      properties: {
        url: {
          type: 'string',
          description: 'The URL to remove from scope',
        },
      },
      required: ['url'],
    },
  },
  {
    name: 'burp_scope_check',
    description: 'Check if a URL is in the target scope',
    inputSchema: {
      type: 'object' as const,
      properties: {
        url: {
          type: 'string',
          description: 'The URL to check',
        },
      },
      required: ['url'],
    },
  },
  {
    name: 'burp_proxy_history',
    description: 'Get the proxy history showing all intercepted HTTP requests/responses',
    inputSchema: {
      type: 'object' as const,
      properties: {
        limit: {
          type: 'number',
          description: 'Maximum number of items to return (default: all)',
        },
      },
      required: [],
    },
  },
  {
    name: 'burp_proxy_history_item',
    description: 'Get details of a specific proxy history item including full request/response',
    inputSchema: {
      type: 'object' as const,
      properties: {
        id: {
          type: 'number',
          description: 'The ID of the proxy history item',
        },
      },
      required: ['id'],
    },
  },
  {
    name: 'burp_spider_start',
    description: 'Start the spider/crawler to discover content from a base URL',
    inputSchema: {
      type: 'object' as const,
      properties: {
        url: {
          type: 'string',
          description: 'The base URL to start crawling from',
        },
      },
      required: ['url'],
    },
  },
  {
    name: 'burp_spider_status',
    description: 'Get the status of the spider/crawler',
    inputSchema: {
      type: 'object' as const,
      properties: {},
      required: [],
    },
  },
  {
    name: 'burp_send_to_repeater',
    description: 'Send an HTTP request to the Repeater tool for manual testing',
    inputSchema: {
      type: 'object' as const,
      properties: {
        request: {
          type: 'string',
          description: 'The raw HTTP request to send',
        },
        host: {
          type: 'string',
          description: 'Target host',
        },
        port: {
          type: 'number',
          description: 'Target port (default: 443)',
        },
        https: {
          type: 'boolean',
          description: 'Use HTTPS (default: true)',
        },
      },
      required: ['request', 'host'],
    },
  },
  {
    name: 'burp_send_to_intruder',
    description: 'Send an HTTP request to the Intruder tool for automated testing',
    inputSchema: {
      type: 'object' as const,
      properties: {
        request: {
          type: 'string',
          description: 'The raw HTTP request to send (with payload positions marked)',
        },
        host: {
          type: 'string',
          description: 'Target host',
        },
        port: {
          type: 'number',
          description: 'Target port (default: 443)',
        },
        https: {
          type: 'boolean',
          description: 'Use HTTPS (default: true)',
        },
      },
      required: ['request', 'host'],
    },
  },
  {
    name: 'burp_send_http_request',
    description: 'Send an HTTP request through Burp and get the response',
    inputSchema: {
      type: 'object' as const,
      properties: {
        request: {
          type: 'string',
          description: 'The raw HTTP request to send',
        },
        host: {
          type: 'string',
          description: 'Target host',
        },
        port: {
          type: 'number',
          description: 'Target port (default: 443)',
        },
        https: {
          type: 'boolean',
          description: 'Use HTTPS (default: true)',
        },
      },
      required: ['request', 'host'],
    },
  },
  {
    name: 'burp_export_state',
    description: 'Export the current Burp project/state to a file',
    inputSchema: {
      type: 'object' as const,
      properties: {
        filePath: {
          type: 'string',
          description: 'Path to save the state file',
        },
      },
      required: ['filePath'],
    },
  },
  {
    name: 'burp_reset_state',
    description: 'Reset/clear the current Burp state (WARNING: clears all data)',
    inputSchema: {
      type: 'object' as const,
      properties: {},
      required: [],
    },
  },
  {
    name: 'burp_shutdown',
    description: 'Shutdown Burp Suite (if supported by the API)',
    inputSchema: {
      type: 'object' as const,
      properties: {},
      required: [],
    },
  },
];

// Register tool handlers
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return { tools };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case 'burp_health_check': {
        const healthy = await burpClient.healthCheck();
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                healthy,
                burpUrl: BURP_URL,
                message: healthy
                  ? 'Burp Suite REST API is accessible'
                  : 'Cannot connect to Burp Suite REST API. Ensure Burp is running and REST API is enabled.',
              }, null, 2),
            },
          ],
        };
      }

      case 'burp_get_version': {
        const version = await burpClient.getVersion();
        return {
          content: [{ type: 'text', text: JSON.stringify(version, null, 2) }],
        };
      }

      case 'burp_scan_start': {
        const { url, scope } = args as { url: string; scope?: string };
        const result = await burpClient.startScan({ baseUrl: url, scope });
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                ...result,
                message: `Scan started for ${url}`,
              }, null, 2),
            },
          ],
        };
      }

      case 'burp_scan_status': {
        const { scanId } = args as { scanId?: string };
        const status = await burpClient.getScanStatus(scanId);
        return {
          content: [{ type: 'text', text: JSON.stringify(status, null, 2) }],
        };
      }

      case 'burp_scan_pause': {
        await burpClient.pauseScan();
        return {
          content: [{ type: 'text', text: JSON.stringify({ status: 'paused' }, null, 2) }],
        };
      }

      case 'burp_scan_resume': {
        await burpClient.resumeScan();
        return {
          content: [{ type: 'text', text: JSON.stringify({ status: 'running' }, null, 2) }],
        };
      }

      case 'burp_issues_list': {
        const { urlPrefix } = args as { urlPrefix?: string };
        const issues = await burpClient.getIssues(urlPrefix);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                count: issues.length,
                issues: issues.map((issue) => ({
                  name: issue.name,
                  severity: issue.severity,
                  confidence: issue.confidence,
                  url: issue.url,
                  path: issue.path,
                })),
              }, null, 2),
            },
          ],
        };
      }

      case 'burp_issue_definitions': {
        const definitions = await burpClient.getIssueDefinitions();
        return {
          content: [{ type: 'text', text: JSON.stringify(definitions, null, 2) }],
        };
      }

      case 'burp_sitemap_get': {
        const { urlPrefix } = args as { urlPrefix?: string };
        const sitemap = await burpClient.getSitemap(urlPrefix);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                count: sitemap.length,
                items: sitemap.slice(0, 100), // Limit to first 100 items
              }, null, 2),
            },
          ],
        };
      }

      case 'burp_scope_add': {
        const { url } = args as { url: string };
        await burpClient.addToScope(url);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({ status: 'added', url }, null, 2),
            },
          ],
        };
      }

      case 'burp_scope_remove': {
        const { url } = args as { url: string };
        await burpClient.removeFromScope(url);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({ status: 'removed', url }, null, 2),
            },
          ],
        };
      }

      case 'burp_scope_check': {
        const { url } = args as { url: string };
        const inScope = await burpClient.isInScope(url);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({ url, inScope }, null, 2),
            },
          ],
        };
      }

      case 'burp_proxy_history': {
        const { limit } = args as { limit?: number };
        const history = await burpClient.getProxyHistory(limit);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                count: history.length,
                items: history.map((item) => ({
                  id: item.id,
                  method: item.method,
                  url: item.url,
                  status: item.status,
                  length: item.length,
                  mimeType: item.mimeType,
                })),
              }, null, 2),
            },
          ],
        };
      }

      case 'burp_proxy_history_item': {
        const { id } = args as { id: number };
        const item = await burpClient.getProxyHistoryItem(id);
        if (!item) {
          throw new McpError(ErrorCode.InvalidRequest, `Proxy history item ${id} not found`);
        }
        return {
          content: [{ type: 'text', text: JSON.stringify(item, null, 2) }],
        };
      }

      case 'burp_spider_start': {
        const { url } = args as { url: string };
        const result = await burpClient.startSpider(url);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({
                ...result,
                message: `Spider started for ${url}`,
              }, null, 2),
            },
          ],
        };
      }

      case 'burp_spider_status': {
        const status = await burpClient.getSpiderStatus();
        return {
          content: [{ type: 'text', text: JSON.stringify(status, null, 2) }],
        };
      }

      case 'burp_send_to_repeater': {
        const { request, host, port = 443, https = true } = args as {
          request: string;
          host: string;
          port?: number;
          https?: boolean;
        };
        const result = await burpClient.sendToRepeater(request, host, port, https);
        return {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        };
      }

      case 'burp_send_to_intruder': {
        const { request, host, port = 443, https = true } = args as {
          request: string;
          host: string;
          port?: number;
          https?: boolean;
        };
        const result = await burpClient.sendToIntruder(request, host, port, https);
        return {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        };
      }

      case 'burp_send_http_request': {
        const { request, host, port = 443, https = true } = args as {
          request: string;
          host: string;
          port?: number;
          https?: boolean;
        };
        const result = await burpClient.sendHttpRequest(request, host, port, https);
        return {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        };
      }

      case 'burp_export_state': {
        const { filePath } = args as { filePath: string };
        await burpClient.exportState(filePath);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({ status: 'exported', filePath }, null, 2),
            },
          ],
        };
      }

      case 'burp_reset_state': {
        await burpClient.resetState();
        return {
          content: [{ type: 'text', text: JSON.stringify({ status: 'reset' }, null, 2) }],
        };
      }

      case 'burp_shutdown': {
        await burpClient.shutdown();
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({ status: 'shutdown initiated' }, null, 2),
            },
          ],
        };
      }

      default:
        throw new McpError(ErrorCode.MethodNotFound, `Unknown tool: ${name}`);
    }
  } catch (error) {
    if (error instanceof McpError) {
      throw error;
    }
    const message = error instanceof Error ? error.message : 'Unknown error';
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({ error: message }, null, 2),
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
  console.error('Burp Suite MCP server running on stdio');
  console.error(`Connecting to Burp at: ${BURP_URL}`);
}

main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});
