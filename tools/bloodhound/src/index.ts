#!/usr/bin/env node

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from '@modelcontextprotocol/sdk/types.js';
import { BloodHoundClient, BloodHoundConfig } from './client.js';

// ============== Configuration ==============

function getConfig(): BloodHoundConfig {
  const baseUrl = process.env.BLOODHOUND_URL || 'http://localhost:8080';
  const tokenId = process.env.BLOODHOUND_TOKEN_ID || '';
  const tokenKey = process.env.BLOODHOUND_TOKEN_KEY || '';

  if (!tokenId || !tokenKey) {
    console.error('Warning: BLOODHOUND_TOKEN_ID and BLOODHOUND_TOKEN_KEY environment variables are required');
  }

  return { baseUrl, tokenId, tokenKey };
}

// ============== Tool Definitions ==============

const tools: Tool[] = [
  // Domain Operations
  {
    name: 'bloodhound_domains',
    description: 'List all available Active Directory domains in BloodHound',
    inputSchema: {
      type: 'object',
      properties: {},
      required: []
    }
  },
  {
    name: 'bloodhound_domain_info',
    description: 'Get detailed information about a specific domain',
    inputSchema: {
      type: 'object',
      properties: {
        domain_id: {
          type: 'string',
          description: 'The domain ID or SID'
        }
      },
      required: ['domain_id']
    }
  },

  // User Operations
  {
    name: 'bloodhound_users',
    description: 'List domain users with optional pagination',
    inputSchema: {
      type: 'object',
      properties: {
        domain_id: {
          type: 'string',
          description: 'The domain ID to list users from'
        },
        skip: {
          type: 'number',
          description: 'Number of records to skip (default: 0)'
        },
        limit: {
          type: 'number',
          description: 'Maximum number of records to return (default: 100)'
        }
      },
      required: ['domain_id']
    }
  },
  {
    name: 'bloodhound_user_info',
    description: 'Get detailed information about a specific user including properties and relationships',
    inputSchema: {
      type: 'object',
      properties: {
        user_id: {
          type: 'string',
          description: 'The user object ID'
        }
      },
      required: ['user_id']
    }
  },
  {
    name: 'bloodhound_user_admin_rights',
    description: 'Get systems where a user has administrative rights',
    inputSchema: {
      type: 'object',
      properties: {
        user_id: {
          type: 'string',
          description: 'The user object ID'
        }
      },
      required: ['user_id']
    }
  },
  {
    name: 'bloodhound_user_memberships',
    description: 'Get group memberships for a user',
    inputSchema: {
      type: 'object',
      properties: {
        user_id: {
          type: 'string',
          description: 'The user object ID'
        }
      },
      required: ['user_id']
    }
  },
  {
    name: 'bloodhound_user_sessions',
    description: 'Get active sessions for a user',
    inputSchema: {
      type: 'object',
      properties: {
        user_id: {
          type: 'string',
          description: 'The user object ID'
        }
      },
      required: ['user_id']
    }
  },

  // Computer Operations
  {
    name: 'bloodhound_computers',
    description: 'List domain computers with optional pagination',
    inputSchema: {
      type: 'object',
      properties: {
        domain_id: {
          type: 'string',
          description: 'The domain ID to list computers from'
        },
        skip: {
          type: 'number',
          description: 'Number of records to skip (default: 0)'
        },
        limit: {
          type: 'number',
          description: 'Maximum number of records to return (default: 100)'
        }
      },
      required: ['domain_id']
    }
  },
  {
    name: 'bloodhound_computer_info',
    description: 'Get detailed information about a specific computer',
    inputSchema: {
      type: 'object',
      properties: {
        computer_id: {
          type: 'string',
          description: 'The computer object ID'
        }
      },
      required: ['computer_id']
    }
  },
  {
    name: 'bloodhound_computer_admins',
    description: 'Get administrators of a computer',
    inputSchema: {
      type: 'object',
      properties: {
        computer_id: {
          type: 'string',
          description: 'The computer object ID'
        }
      },
      required: ['computer_id']
    }
  },
  {
    name: 'bloodhound_computer_sessions',
    description: 'Get active sessions on a computer',
    inputSchema: {
      type: 'object',
      properties: {
        computer_id: {
          type: 'string',
          description: 'The computer object ID'
        }
      },
      required: ['computer_id']
    }
  },

  // Group Operations
  {
    name: 'bloodhound_groups',
    description: 'List domain groups with optional pagination',
    inputSchema: {
      type: 'object',
      properties: {
        domain_id: {
          type: 'string',
          description: 'The domain ID to list groups from'
        },
        skip: {
          type: 'number',
          description: 'Number of records to skip (default: 0)'
        },
        limit: {
          type: 'number',
          description: 'Maximum number of records to return (default: 100)'
        }
      },
      required: ['domain_id']
    }
  },
  {
    name: 'bloodhound_group_info',
    description: 'Get detailed information about a specific group',
    inputSchema: {
      type: 'object',
      properties: {
        group_id: {
          type: 'string',
          description: 'The group object ID'
        }
      },
      required: ['group_id']
    }
  },
  {
    name: 'bloodhound_group_members',
    description: 'Get members of a group',
    inputSchema: {
      type: 'object',
      properties: {
        group_id: {
          type: 'string',
          description: 'The group object ID'
        }
      },
      required: ['group_id']
    }
  },
  {
    name: 'bloodhound_group_admin_rights',
    description: 'Get administrative rights held by a group',
    inputSchema: {
      type: 'object',
      properties: {
        group_id: {
          type: 'string',
          description: 'The group object ID'
        }
      },
      required: ['group_id']
    }
  },

  // Search & Graph Operations
  {
    name: 'bloodhound_search',
    description: 'Search for graph objects by name or object ID',
    inputSchema: {
      type: 'object',
      properties: {
        query: {
          type: 'string',
          description: 'Search query (name or partial name)'
        },
        type: {
          type: 'string',
          description: 'Filter by object type (User, Computer, Group, Domain, etc.)'
        }
      },
      required: ['query']
    }
  },
  {
    name: 'bloodhound_path',
    description: 'Find the shortest attack path between two nodes',
    inputSchema: {
      type: 'object',
      properties: {
        start_node: {
          type: 'string',
          description: 'Starting node object ID (e.g., user SID or name)'
        },
        end_node: {
          type: 'string',
          description: 'Target node object ID (e.g., Domain Admins group)'
        }
      },
      required: ['start_node', 'end_node']
    }
  },
  {
    name: 'bloodhound_cypher',
    description: 'Execute a custom Neo4j Cypher query against the BloodHound database',
    inputSchema: {
      type: 'object',
      properties: {
        query: {
          type: 'string',
          description: 'The Cypher query to execute'
        }
      },
      required: ['query']
    }
  },

  // Attack Path Operations
  {
    name: 'bloodhound_attack_paths',
    description: 'List available attack path types',
    inputSchema: {
      type: 'object',
      properties: {},
      required: []
    }
  },
  {
    name: 'bloodhound_domain_attack_paths',
    description: 'Get attack paths for a specific domain',
    inputSchema: {
      type: 'object',
      properties: {
        domain_id: {
          type: 'string',
          description: 'The domain ID to analyze'
        }
      },
      required: ['domain_id']
    }
  },
  {
    name: 'bloodhound_findings',
    description: 'Get all attack path findings',
    inputSchema: {
      type: 'object',
      properties: {},
      required: []
    }
  },
  {
    name: 'bloodhound_analyze',
    description: 'Start attack path analysis job',
    inputSchema: {
      type: 'object',
      properties: {},
      required: []
    }
  },

  // Domain Entity Operations
  {
    name: 'bloodhound_domain_controllers',
    description: 'Get domain controllers for a domain',
    inputSchema: {
      type: 'object',
      properties: {
        domain_id: {
          type: 'string',
          description: 'The domain ID'
        }
      },
      required: ['domain_id']
    }
  },
  {
    name: 'bloodhound_dcsyncers',
    description: 'Get principals with DCSync rights (can dump domain credentials)',
    inputSchema: {
      type: 'object',
      properties: {
        domain_id: {
          type: 'string',
          description: 'The domain ID'
        }
      },
      required: ['domain_id']
    }
  },
  {
    name: 'bloodhound_trusts',
    description: 'Get domain trust relationships',
    inputSchema: {
      type: 'object',
      properties: {
        domain_id: {
          type: 'string',
          description: 'The domain ID'
        },
        direction: {
          type: 'string',
          enum: ['inbound', 'outbound', 'both'],
          description: 'Trust direction to query (default: both)'
        }
      },
      required: ['domain_id']
    }
  },
  {
    name: 'bloodhound_gpos',
    description: 'Get Group Policy Objects linked to a domain',
    inputSchema: {
      type: 'object',
      properties: {
        domain_id: {
          type: 'string',
          description: 'The domain ID'
        }
      },
      required: ['domain_id']
    }
  },
  {
    name: 'bloodhound_ous',
    description: 'Get Organizational Units in a domain',
    inputSchema: {
      type: 'object',
      properties: {
        domain_id: {
          type: 'string',
          description: 'The domain ID'
        }
      },
      required: ['domain_id']
    }
  },

  // High-Value Target Detection
  {
    name: 'bloodhound_kerberoastable',
    description: 'Find Kerberoastable users (users with SPNs that can be targeted for offline cracking)',
    inputSchema: {
      type: 'object',
      properties: {
        domain_id: {
          type: 'string',
          description: 'The domain SID to search'
        }
      },
      required: ['domain_id']
    }
  },
  {
    name: 'bloodhound_asreproastable',
    description: 'Find AS-REP Roastable users (users with Kerberos pre-authentication disabled)',
    inputSchema: {
      type: 'object',
      properties: {
        domain_id: {
          type: 'string',
          description: 'The domain SID to search'
        }
      },
      required: ['domain_id']
    }
  },
  {
    name: 'bloodhound_unconstrained_delegation',
    description: 'Find computers with unconstrained delegation (high-value targets)',
    inputSchema: {
      type: 'object',
      properties: {
        domain_id: {
          type: 'string',
          description: 'The domain SID to search'
        }
      },
      required: ['domain_id']
    }
  },

  // Data Quality & Info
  {
    name: 'bloodhound_data_quality',
    description: 'Get data collection quality statistics for a domain',
    inputSchema: {
      type: 'object',
      properties: {
        domain_id: {
          type: 'string',
          description: 'The domain ID'
        }
      },
      required: ['domain_id']
    }
  },
  {
    name: 'bloodhound_version',
    description: 'Get BloodHound API version information',
    inputSchema: {
      type: 'object',
      properties: {},
      required: []
    }
  }
];

// ============== Tool Handler ==============

async function handleToolCall(
  client: BloodHoundClient,
  name: string,
  args: Record<string, unknown>
): Promise<unknown> {
  switch (name) {
    // Domain Operations
    case 'bloodhound_domains':
      return client.listDomains();

    case 'bloodhound_domain_info':
      return client.getDomain(args.domain_id as string);

    // User Operations
    case 'bloodhound_users':
      return client.listUsers(
        args.domain_id as string,
        (args.skip as number) || 0,
        (args.limit as number) || 100
      );

    case 'bloodhound_user_info':
      return client.getUser(args.user_id as string);

    case 'bloodhound_user_admin_rights':
      return client.getUserAdminRights(args.user_id as string);

    case 'bloodhound_user_memberships':
      return client.getUserMemberships(args.user_id as string);

    case 'bloodhound_user_sessions':
      return client.getUserSessions(args.user_id as string);

    // Computer Operations
    case 'bloodhound_computers':
      return client.listComputers(
        args.domain_id as string,
        (args.skip as number) || 0,
        (args.limit as number) || 100
      );

    case 'bloodhound_computer_info':
      return client.getComputer(args.computer_id as string);

    case 'bloodhound_computer_admins':
      return client.getComputerAdmins(args.computer_id as string);

    case 'bloodhound_computer_sessions':
      return client.getComputerSessions(args.computer_id as string);

    // Group Operations
    case 'bloodhound_groups':
      return client.listGroups(
        args.domain_id as string,
        (args.skip as number) || 0,
        (args.limit as number) || 100
      );

    case 'bloodhound_group_info':
      return client.getGroup(args.group_id as string);

    case 'bloodhound_group_members':
      return client.getGroupMembers(args.group_id as string);

    case 'bloodhound_group_admin_rights':
      return client.getGroupAdminRights(args.group_id as string);

    // Search & Graph Operations
    case 'bloodhound_search':
      return client.search(args.query as string, args.type as string | undefined);

    case 'bloodhound_path':
      return client.findShortestPath(args.start_node as string, args.end_node as string);

    case 'bloodhound_cypher':
      return client.executeCypher(args.query as string);

    // Attack Path Operations
    case 'bloodhound_attack_paths':
      return client.listAttackPaths();

    case 'bloodhound_domain_attack_paths':
      return client.getDomainAttackPaths(args.domain_id as string);

    case 'bloodhound_findings':
      return client.getAttackPathFindings();

    case 'bloodhound_analyze':
      return client.startAnalysis();

    // Domain Entity Operations
    case 'bloodhound_domain_controllers':
      return client.getDomainControllers(args.domain_id as string);

    case 'bloodhound_dcsyncers':
      return client.getDCSyncers(args.domain_id as string);

    case 'bloodhound_trusts': {
      const direction = (args.direction as string) || 'both';
      const domainId = args.domain_id as string;
      if (direction === 'inbound') {
        return client.getInboundTrusts(domainId);
      } else if (direction === 'outbound') {
        return client.getOutboundTrusts(domainId);
      } else {
        const [inbound, outbound] = await Promise.all([
          client.getInboundTrusts(domainId),
          client.getOutboundTrusts(domainId)
        ]);
        return { inbound, outbound };
      }
    }

    case 'bloodhound_gpos':
      return client.getDomainGPOs(args.domain_id as string);

    case 'bloodhound_ous':
      return client.getDomainOUs(args.domain_id as string);

    // High-Value Target Detection
    case 'bloodhound_kerberoastable':
      return client.findKerberoastableUsers(args.domain_id as string);

    case 'bloodhound_asreproastable':
      return client.findASREPRoastableUsers(args.domain_id as string);

    case 'bloodhound_unconstrained_delegation':
      return client.findUnconstrainedDelegation(args.domain_id as string);

    // Data Quality & Info
    case 'bloodhound_data_quality':
      return client.getDataQuality(args.domain_id as string);

    case 'bloodhound_version':
      return client.getVersion();

    default:
      throw new Error(`Unknown tool: ${name}`);
  }
}

// ============== Main Server ==============

async function main() {
  const config = getConfig();
  let client: BloodHoundClient | null = null;

  // Only create client if credentials are provided
  if (config.tokenId && config.tokenKey) {
    try {
      client = new BloodHoundClient(config);
    } catch (error) {
      console.error('Failed to initialize BloodHound client:', error);
    }
  }

  const server = new Server(
    {
      name: 'bloodhound-mcp',
      version: '1.0.0'
    },
    {
      capabilities: {
        tools: {}
      }
    }
  );

  // List available tools
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return { tools };
  });

  // Handle tool calls
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    if (!client) {
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              error: 'BloodHound client not configured',
              message: 'Please set BLOODHOUND_URL, BLOODHOUND_TOKEN_ID, and BLOODHOUND_TOKEN_KEY environment variables'
            }, null, 2)
          }
        ],
        isError: true
      };
    }

    try {
      const result = await handleToolCall(client, name, args as Record<string, unknown>);
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify(result, null, 2)
          }
        ]
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : String(error);
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({ error: errorMessage }, null, 2)
          }
        ],
        isError: true
      };
    }
  });

  // Start the server
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('BloodHound MCP server started');
}

main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});
