#!/usr/bin/env node
/**
 * Chisel MCP Server
 *
 * An MCP server for managing chisel TCP/UDP tunnels via SSH to Kali.
 * Supports server mode, client mode, reverse tunnels, SOCKS proxy, and port forwarding.
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { spawn, exec } from "child_process";
import { promisify } from "util";

const execAsync = promisify(exec);

// Configuration
const KALI_HOST = process.env.CHISEL_KALI_HOST || "kali";
const DEFAULT_SERVER_PORT = process.env.CHISEL_DEFAULT_PORT || "8080";
const SSH_OPTIONS = "-o StrictHostKeyChecking=no -o ConnectTimeout=10";

// Track active tunnels
interface TunnelInfo {
  id: string;
  type: "server" | "client" | "reverse" | "socks" | "forward";
  pid?: number;
  command: string;
  startTime: Date;
  localPort?: string;
  remoteHost?: string;
  remotePort?: string;
  status: "running" | "stopped" | "unknown";
}

const activeTunnels: Map<string, TunnelInfo> = new Map();

// Generate unique tunnel ID
function generateTunnelId(): string {
  return `chisel-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;
}

// Execute command on Kali via SSH
async function executeOnKali(command: string, background: boolean = false): Promise<{ stdout: string; stderr: string; pid?: number }> {
  const sshCommand = background
    ? `ssh ${SSH_OPTIONS} ${KALI_HOST} "nohup ${command} > /tmp/chisel-\$\$.log 2>&1 & echo \$!"`
    : `ssh ${SSH_OPTIONS} ${KALI_HOST} "${command}"`;

  try {
    const { stdout, stderr } = await execAsync(sshCommand, { timeout: 30000 });
    const pid = background ? parseInt(stdout.trim()) : undefined;
    return { stdout: stdout.trim(), stderr: stderr.trim(), pid };
  } catch (error: any) {
    return {
      stdout: "",
      stderr: error.message || "Command execution failed"
    };
  }
}

// Check if chisel is installed on Kali
async function checkChiselInstalled(): Promise<boolean> {
  const result = await executeOnKali("which chisel || command -v chisel");
  return result.stdout.includes("chisel");
}

// Get chisel version
async function getChiselVersion(): Promise<string> {
  const result = await executeOnKali("chisel --version 2>&1 || echo 'unknown'");
  return result.stdout || "unknown";
}

// Define tools
const tools: Tool[] = [
  {
    name: "chisel_server",
    description: "Start a chisel server on Kali. The server listens for client connections and can enable SOCKS5 proxy and reverse tunneling.",
    inputSchema: {
      type: "object",
      properties: {
        port: {
          type: "string",
          description: `Port to listen on (default: ${DEFAULT_SERVER_PORT})`
        },
        host: {
          type: "string",
          description: "Interface to bind to (default: 0.0.0.0)"
        },
        reverse: {
          type: "boolean",
          description: "Allow reverse port forwarding from clients (default: true)"
        },
        socks5: {
          type: "boolean",
          description: "Enable SOCKS5 proxy for clients (default: true)"
        },
        auth: {
          type: "string",
          description: "Authentication credentials in format user:password"
        },
        keepalive: {
          type: "string",
          description: "Keepalive interval (e.g., '25s', '1m')"
        }
      },
      required: []
    }
  },
  {
    name: "chisel_client",
    description: "Start a chisel client to connect to a chisel server. Creates tunnels for port forwarding.",
    inputSchema: {
      type: "object",
      properties: {
        server: {
          type: "string",
          description: "Chisel server URL (e.g., http://10.0.0.1:8080)"
        },
        remotes: {
          type: "array",
          items: { type: "string" },
          description: "Remote tunnel specifications (e.g., ['3000', '8080:localhost:80', 'R:2222:localhost:22'])"
        },
        auth: {
          type: "string",
          description: "Authentication credentials in format user:password"
        },
        fingerprint: {
          type: "string",
          description: "Server fingerprint for verification"
        },
        keepalive: {
          type: "string",
          description: "Keepalive interval (e.g., '25s', '1m')"
        }
      },
      required: ["server", "remotes"]
    }
  },
  {
    name: "chisel_reverse",
    description: "Set up a reverse tunnel. Starts server on Kali with --reverse flag, ready for clients to connect and create reverse tunnels.",
    inputSchema: {
      type: "object",
      properties: {
        port: {
          type: "string",
          description: `Server port to listen on (default: ${DEFAULT_SERVER_PORT})`
        },
        auth: {
          type: "string",
          description: "Authentication credentials in format user:password"
        }
      },
      required: []
    }
  },
  {
    name: "chisel_socks",
    description: "Set up a SOCKS5 proxy through chisel. Starts server with --socks5 enabled for proxying traffic.",
    inputSchema: {
      type: "object",
      properties: {
        port: {
          type: "string",
          description: `Server port to listen on (default: ${DEFAULT_SERVER_PORT})`
        },
        socksPort: {
          type: "string",
          description: "Local SOCKS5 port (default: 1080)"
        },
        auth: {
          type: "string",
          description: "Authentication credentials in format user:password"
        }
      },
      required: []
    }
  },
  {
    name: "chisel_forward",
    description: "Create a local port forward tunnel. Forwards local port through chisel server to a remote destination.",
    inputSchema: {
      type: "object",
      properties: {
        server: {
          type: "string",
          description: "Chisel server URL (e.g., http://10.0.0.1:8080)"
        },
        localPort: {
          type: "string",
          description: "Local port to listen on"
        },
        remoteHost: {
          type: "string",
          description: "Remote host to forward to (default: localhost)"
        },
        remotePort: {
          type: "string",
          description: "Remote port to forward to"
        },
        auth: {
          type: "string",
          description: "Authentication credentials in format user:password"
        }
      },
      required: ["server", "localPort", "remotePort"]
    }
  },
  {
    name: "chisel_status",
    description: "Check status of chisel tunnels. Lists active tunnels, checks processes, and verifies connectivity.",
    inputSchema: {
      type: "object",
      properties: {
        tunnelId: {
          type: "string",
          description: "Specific tunnel ID to check (optional, checks all if not provided)"
        }
      },
      required: []
    }
  },
  {
    name: "chisel_stop",
    description: "Stop a chisel tunnel or all tunnels.",
    inputSchema: {
      type: "object",
      properties: {
        tunnelId: {
          type: "string",
          description: "Tunnel ID to stop (optional, stops all if not provided)"
        },
        force: {
          type: "boolean",
          description: "Force kill with SIGKILL (default: false, uses SIGTERM)"
        }
      },
      required: []
    }
  },
  {
    name: "chisel_list_processes",
    description: "List all chisel processes running on Kali.",
    inputSchema: {
      type: "object",
      properties: {},
      required: []
    }
  },
  {
    name: "chisel_version",
    description: "Get chisel version and verify installation on Kali.",
    inputSchema: {
      type: "object",
      properties: {},
      required: []
    }
  }
];

// Tool handlers
async function handleChiselServer(args: any): Promise<string> {
  const port = args.port || DEFAULT_SERVER_PORT;
  const host = args.host || "0.0.0.0";
  const reverse = args.reverse !== false;
  const socks5 = args.socks5 !== false;
  const auth = args.auth;
  const keepalive = args.keepalive || "25s";

  let command = `chisel server --host ${host} --port ${port} --keepalive ${keepalive}`;

  if (reverse) command += " --reverse";
  if (socks5) command += " --socks5";
  if (auth) command += ` --auth ${auth}`;

  const tunnelId = generateTunnelId();
  const result = await executeOnKali(command, true);

  if (result.pid) {
    const tunnelInfo: TunnelInfo = {
      id: tunnelId,
      type: "server",
      pid: result.pid,
      command,
      startTime: new Date(),
      localPort: port,
      status: "running"
    };
    activeTunnels.set(tunnelId, tunnelInfo);

    return JSON.stringify({
      success: true,
      tunnelId,
      pid: result.pid,
      message: `Chisel server started on ${host}:${port}`,
      options: { reverse, socks5 },
      command
    }, null, 2);
  }

  return JSON.stringify({
    success: false,
    error: result.stderr || "Failed to start chisel server",
    command
  }, null, 2);
}

async function handleChiselClient(args: any): Promise<string> {
  const { server, remotes, auth, fingerprint, keepalive } = args;

  if (!server || !remotes || remotes.length === 0) {
    return JSON.stringify({
      success: false,
      error: "Server URL and at least one remote specification required"
    }, null, 2);
  }

  let command = `chisel client`;

  if (auth) command += ` --auth ${auth}`;
  if (fingerprint) command += ` --fingerprint ${fingerprint}`;
  if (keepalive) command += ` --keepalive ${keepalive}`;

  command += ` ${server} ${remotes.join(" ")}`;

  const tunnelId = generateTunnelId();
  const result = await executeOnKali(command, true);

  if (result.pid) {
    const tunnelInfo: TunnelInfo = {
      id: tunnelId,
      type: "client",
      pid: result.pid,
      command,
      startTime: new Date(),
      remoteHost: server,
      status: "running"
    };
    activeTunnels.set(tunnelId, tunnelInfo);

    return JSON.stringify({
      success: true,
      tunnelId,
      pid: result.pid,
      message: `Chisel client connected to ${server}`,
      remotes,
      command
    }, null, 2);
  }

  return JSON.stringify({
    success: false,
    error: result.stderr || "Failed to start chisel client",
    command
  }, null, 2);
}

async function handleChiselReverse(args: any): Promise<string> {
  const port = args.port || DEFAULT_SERVER_PORT;
  const auth = args.auth;

  let command = `chisel server --port ${port} --reverse`;
  if (auth) command += ` --auth ${auth}`;

  const tunnelId = generateTunnelId();
  const result = await executeOnKali(command, true);

  if (result.pid) {
    const tunnelInfo: TunnelInfo = {
      id: tunnelId,
      type: "reverse",
      pid: result.pid,
      command,
      startTime: new Date(),
      localPort: port,
      status: "running"
    };
    activeTunnels.set(tunnelId, tunnelInfo);

    return JSON.stringify({
      success: true,
      tunnelId,
      pid: result.pid,
      message: `Chisel reverse server started on port ${port}`,
      usage: `Connect clients with: chisel client <this-host>:${port} R:<local-port>:<remote-host>:<remote-port>`,
      command
    }, null, 2);
  }

  return JSON.stringify({
    success: false,
    error: result.stderr || "Failed to start chisel reverse server",
    command
  }, null, 2);
}

async function handleChiselSocks(args: any): Promise<string> {
  const port = args.port || DEFAULT_SERVER_PORT;
  const socksPort = args.socksPort || "1080";
  const auth = args.auth;

  let command = `chisel server --port ${port} --socks5`;
  if (auth) command += ` --auth ${auth}`;

  const tunnelId = generateTunnelId();
  const result = await executeOnKali(command, true);

  if (result.pid) {
    const tunnelInfo: TunnelInfo = {
      id: tunnelId,
      type: "socks",
      pid: result.pid,
      command,
      startTime: new Date(),
      localPort: port,
      status: "running"
    };
    activeTunnels.set(tunnelId, tunnelInfo);

    return JSON.stringify({
      success: true,
      tunnelId,
      pid: result.pid,
      message: `Chisel SOCKS5 server started on port ${port}`,
      usage: {
        clientConnect: `chisel client <this-host>:${port} socks`,
        proxychains: `Add "socks5 127.0.0.1 ${socksPort}" to /etc/proxychains.conf`,
        curl: `curl --socks5 127.0.0.1:${socksPort} http://target`
      },
      command
    }, null, 2);
  }

  return JSON.stringify({
    success: false,
    error: result.stderr || "Failed to start chisel SOCKS server",
    command
  }, null, 2);
}

async function handleChiselForward(args: any): Promise<string> {
  const { server, localPort, remoteHost, remotePort, auth } = args;

  if (!server || !localPort || !remotePort) {
    return JSON.stringify({
      success: false,
      error: "Server URL, local port, and remote port are required"
    }, null, 2);
  }

  const rHost = remoteHost || "localhost";
  const remote = `${localPort}:${rHost}:${remotePort}`;

  let command = `chisel client`;
  if (auth) command += ` --auth ${auth}`;
  command += ` ${server} ${remote}`;

  const tunnelId = generateTunnelId();
  const result = await executeOnKali(command, true);

  if (result.pid) {
    const tunnelInfo: TunnelInfo = {
      id: tunnelId,
      type: "forward",
      pid: result.pid,
      command,
      startTime: new Date(),
      localPort,
      remoteHost: rHost,
      remotePort,
      status: "running"
    };
    activeTunnels.set(tunnelId, tunnelInfo);

    return JSON.stringify({
      success: true,
      tunnelId,
      pid: result.pid,
      message: `Port forward established: localhost:${localPort} -> ${rHost}:${remotePort}`,
      command
    }, null, 2);
  }

  return JSON.stringify({
    success: false,
    error: result.stderr || "Failed to create port forward",
    command
  }, null, 2);
}

async function handleChiselStatus(args: any): Promise<string> {
  const { tunnelId } = args;

  // Get running chisel processes on Kali
  const processResult = await executeOnKali("ps aux | grep '[c]hisel' || echo 'No chisel processes'");

  // Check specific tunnel or all
  if (tunnelId) {
    const tunnel = activeTunnels.get(tunnelId);
    if (!tunnel) {
      return JSON.stringify({
        success: false,
        error: `Tunnel ${tunnelId} not found in active tunnels`
      }, null, 2);
    }

    // Verify process is still running
    if (tunnel.pid) {
      const pidCheck = await executeOnKali(`ps -p ${tunnel.pid} -o pid= 2>/dev/null || echo 'not running'`);
      tunnel.status = pidCheck.stdout.includes("not running") ? "stopped" : "running";
    }

    return JSON.stringify({
      success: true,
      tunnel: {
        ...tunnel,
        startTime: tunnel.startTime.toISOString()
      }
    }, null, 2);
  }

  // Return all tunnels
  const tunnelList = Array.from(activeTunnels.values()).map(t => ({
    ...t,
    startTime: t.startTime.toISOString()
  }));

  return JSON.stringify({
    success: true,
    activeTunnels: tunnelList,
    totalCount: tunnelList.length,
    chiselProcesses: processResult.stdout
  }, null, 2);
}

async function handleChiselStop(args: any): Promise<string> {
  const { tunnelId, force } = args;
  const signal = force ? "SIGKILL" : "SIGTERM";

  if (tunnelId) {
    const tunnel = activeTunnels.get(tunnelId);
    if (!tunnel) {
      return JSON.stringify({
        success: false,
        error: `Tunnel ${tunnelId} not found`
      }, null, 2);
    }

    if (tunnel.pid) {
      await executeOnKali(`kill -${signal === "SIGKILL" ? "9" : "15"} ${tunnel.pid} 2>/dev/null || true`);
    }

    tunnel.status = "stopped";
    activeTunnels.delete(tunnelId);

    return JSON.stringify({
      success: true,
      message: `Tunnel ${tunnelId} stopped`,
      pid: tunnel.pid
    }, null, 2);
  }

  // Stop all tunnels
  const stoppedTunnels: string[] = [];

  for (const [id, tunnel] of activeTunnels) {
    if (tunnel.pid) {
      await executeOnKali(`kill -${signal === "SIGKILL" ? "9" : "15"} ${tunnel.pid} 2>/dev/null || true`);
    }
    stoppedTunnels.push(id);
  }

  activeTunnels.clear();

  // Also kill any orphaned chisel processes
  await executeOnKali("pkill -f chisel 2>/dev/null || true");

  return JSON.stringify({
    success: true,
    message: `Stopped ${stoppedTunnels.length} tunnel(s)`,
    stoppedTunnels
  }, null, 2);
}

async function handleChiselListProcesses(): Promise<string> {
  const result = await executeOnKali("ps aux | grep '[c]hisel' | awk '{print $2, $11, $12, $13, $14, $15}'");

  if (!result.stdout || result.stdout === "") {
    return JSON.stringify({
      success: true,
      message: "No chisel processes running on Kali",
      processes: []
    }, null, 2);
  }

  const processes = result.stdout.split("\n").filter(line => line.trim()).map(line => {
    const parts = line.trim().split(/\s+/);
    return {
      pid: parts[0],
      command: parts.slice(1).join(" ")
    };
  });

  return JSON.stringify({
    success: true,
    processes,
    count: processes.length
  }, null, 2);
}

async function handleChiselVersion(): Promise<string> {
  const installed = await checkChiselInstalled();
  const version = await getChiselVersion();

  // Test SSH connectivity
  const sshTest = await executeOnKali("echo 'SSH connection OK'");
  const sshOk = sshTest.stdout.includes("OK");

  return JSON.stringify({
    success: true,
    chiselInstalled: installed,
    version: version,
    kaliHost: KALI_HOST,
    sshConnectivity: sshOk,
    defaultPort: DEFAULT_SERVER_PORT
  }, null, 2);
}

// Create and configure server
const server = new Server(
  {
    name: "chisel-mcp",
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
    let result: string;

    switch (name) {
      case "chisel_server":
        result = await handleChiselServer(args || {});
        break;
      case "chisel_client":
        result = await handleChiselClient(args || {});
        break;
      case "chisel_reverse":
        result = await handleChiselReverse(args || {});
        break;
      case "chisel_socks":
        result = await handleChiselSocks(args || {});
        break;
      case "chisel_forward":
        result = await handleChiselForward(args || {});
        break;
      case "chisel_status":
        result = await handleChiselStatus(args || {});
        break;
      case "chisel_stop":
        result = await handleChiselStop(args || {});
        break;
      case "chisel_list_processes":
        result = await handleChiselListProcesses();
        break;
      case "chisel_version":
        result = await handleChiselVersion();
        break;
      default:
        result = JSON.stringify({ error: `Unknown tool: ${name}` });
    }

    return {
      content: [{ type: "text", text: result }],
    };
  } catch (error: any) {
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify({ error: error.message || "Unknown error" }),
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
  console.error("Chisel MCP server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
