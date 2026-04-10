#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { spawn, exec } from "child_process";
import { promisify } from "util";

const execAsync = promisify(exec);

// Configuration - SSH to Kali
const KALI_HOST = process.env.KALI_HOST || "kali";
const SSH_USER = process.env.SSH_USER || "kali";
const SSH_KEY = process.env.SSH_KEY || "";
const CAPTURE_DIR = process.env.CAPTURE_DIR || "/tmp/aircrack-captures";

interface AircrackResult {
  success: boolean;
  output: string;
  error?: string;
}

// Execute command on Kali via SSH
async function sshExec(command: string, timeout: number = 30000): Promise<AircrackResult> {
  const sshKeyArg = SSH_KEY ? `-i ${SSH_KEY}` : "";
  const sshCommand = `ssh ${sshKeyArg} -o StrictHostKeyChecking=no -o ConnectTimeout=10 ${SSH_USER}@${KALI_HOST} "${command.replace(/"/g, '\\"')}"`;

  try {
    const { stdout, stderr } = await execAsync(sshCommand, { timeout });
    return {
      success: true,
      output: stdout,
      error: stderr || undefined,
    };
  } catch (error: any) {
    return {
      success: false,
      output: error.stdout || "",
      error: error.message || error.stderr || "Command failed",
    };
  }
}

// Execute long-running command in background on Kali
async function sshExecBackground(command: string, outputFile: string): Promise<AircrackResult> {
  const bgCommand = `nohup ${command} > ${outputFile} 2>&1 & echo $!`;
  return sshExec(bgCommand);
}

// Check if a process is running
async function checkProcess(pid: string): Promise<boolean> {
  const result = await sshExec(`ps -p ${pid} -o pid=`);
  return result.success && result.output.trim() !== "";
}

// Kill a process
async function killProcess(pid: string): Promise<AircrackResult> {
  return sshExec(`kill -9 ${pid} 2>/dev/null || true`);
}

// Tool implementations
const tools = {
  // Check available wireless interfaces
  async airmon_check(): Promise<AircrackResult> {
    const result = await sshExec("sudo airmon-ng");
    return result;
  },

  // Kill interfering processes
  async airmon_check_kill(): Promise<AircrackResult> {
    return sshExec("sudo airmon-ng check kill");
  },

  // Start monitor mode on interface
  async airmon_start(iface: string, channel?: number): Promise<AircrackResult> {
    const channelArg = channel ? ` ${channel}` : "";
    return sshExec(`sudo airmon-ng start ${iface}${channelArg}`);
  },

  // Stop monitor mode
  async airmon_stop(iface: string): Promise<AircrackResult> {
    return sshExec(`sudo airmon-ng stop ${iface}`);
  },

  // Scan for wireless networks (short scan)
  async airodump_scan(iface: string, duration: number = 10): Promise<AircrackResult> {
    const outputFile = `${CAPTURE_DIR}/scan-${Date.now()}`;
    await sshExec(`mkdir -p ${CAPTURE_DIR}`);

    // Run airodump for specified duration and capture output
    const command = `sudo timeout ${duration} airodump-ng --write ${outputFile} --output-format csv ${iface} 2>&1 || true`;
    await sshExec(command, (duration + 5) * 1000);

    // Read the CSV output
    const csvResult = await sshExec(`cat ${outputFile}-01.csv 2>/dev/null || echo "No data captured"`);

    // Cleanup
    await sshExec(`rm -f ${outputFile}* 2>/dev/null || true`);

    return csvResult;
  },

  // Start packet capture on specific target (background)
  async airodump_capture(
    iface: string,
    bssid: string,
    channel: number,
    outputPrefix: string
  ): Promise<AircrackResult> {
    await sshExec(`mkdir -p ${CAPTURE_DIR}`);
    const outputPath = `${CAPTURE_DIR}/${outputPrefix}`;
    const pidFile = `${CAPTURE_DIR}/${outputPrefix}.pid`;

    const command = `sudo airodump-ng --bssid ${bssid} --channel ${channel} --write ${outputPath} --output-format pcap,csv ${iface}`;
    const result = await sshExecBackground(command, `${outputPath}.log`);

    if (result.success && result.output.trim()) {
      await sshExec(`echo ${result.output.trim()} > ${pidFile}`);
      return {
        success: true,
        output: `Capture started with PID: ${result.output.trim()}\nOutput: ${outputPath}\nPID file: ${pidFile}`,
      };
    }

    return result;
  },

  // Stop a running capture
  async airodump_stop(outputPrefix: string): Promise<AircrackResult> {
    const pidFile = `${CAPTURE_DIR}/${outputPrefix}.pid`;
    const pidResult = await sshExec(`cat ${pidFile} 2>/dev/null`);

    if (pidResult.success && pidResult.output.trim()) {
      await killProcess(pidResult.output.trim());
      await sshExec(`rm -f ${pidFile}`);
      return {
        success: true,
        output: `Capture stopped. Check ${CAPTURE_DIR}/${outputPrefix}* for captured data.`,
      };
    }

    return {
      success: false,
      output: "",
      error: "No capture process found for this prefix",
    };
  },

  // Check capture status
  async airodump_status(outputPrefix: string): Promise<AircrackResult> {
    const pidFile = `${CAPTURE_DIR}/${outputPrefix}.pid`;
    const pidResult = await sshExec(`cat ${pidFile} 2>/dev/null`);

    if (pidResult.success && pidResult.output.trim()) {
      const pid = pidResult.output.trim();
      const isRunning = await checkProcess(pid);

      // Get file stats
      const statsResult = await sshExec(`ls -la ${CAPTURE_DIR}/${outputPrefix}* 2>/dev/null || echo "No files yet"`);

      return {
        success: true,
        output: `Capture PID: ${pid}\nStatus: ${isRunning ? "Running" : "Stopped"}\n\nFiles:\n${statsResult.output}`,
      };
    }

    return {
      success: false,
      output: "",
      error: "No capture found for this prefix",
    };
  },

  // Deauthentication attack
  async aireplay_deauth(
    iface: string,
    bssid: string,
    count: number = 5,
    clientMac?: string
  ): Promise<AircrackResult> {
    const clientArg = clientMac ? ` -c ${clientMac}` : "";
    const command = `sudo aireplay-ng --deauth ${count} -a ${bssid}${clientArg} ${iface}`;
    return sshExec(command, 60000);
  },

  // Fake authentication
  async aireplay_fakeauth(
    iface: string,
    bssid: string,
    sourceMac?: string
  ): Promise<AircrackResult> {
    const sourceArg = sourceMac ? ` -h ${sourceMac}` : "";
    const command = `sudo aireplay-ng --fakeauth 0 -a ${bssid}${sourceArg} ${iface}`;
    return sshExec(command, 60000);
  },

  // Crack WPA/WPA2 handshake
  async aircrack_crack(
    capFile: string,
    wordlist: string,
    bssid?: string
  ): Promise<AircrackResult> {
    const bssidArg = bssid ? ` -b ${bssid}` : "";
    const fullCapPath = capFile.startsWith("/") ? capFile : `${CAPTURE_DIR}/${capFile}`;

    // Check if cap file exists
    const fileCheck = await sshExec(`ls ${fullCapPath}* 2>/dev/null | head -1`);
    if (!fileCheck.success || !fileCheck.output.trim()) {
      return {
        success: false,
        output: "",
        error: `Capture file not found: ${fullCapPath}`,
      };
    }

    const actualFile = fileCheck.output.trim();
    const command = `sudo aircrack-ng${bssidArg} -w ${wordlist} ${actualFile}`;
    return sshExec(command, 600000); // 10 minute timeout for cracking
  },

  // Check if handshake is captured
  async aircrack_check_handshake(capFile: string, bssid?: string): Promise<AircrackResult> {
    const bssidArg = bssid ? ` -b ${bssid}` : "";
    const fullCapPath = capFile.startsWith("/") ? capFile : `${CAPTURE_DIR}/${capFile}`;

    // Find the actual cap file
    const fileCheck = await sshExec(`ls ${fullCapPath}*.cap 2>/dev/null | head -1`);
    if (!fileCheck.success || !fileCheck.output.trim()) {
      return {
        success: false,
        output: "",
        error: `Capture file not found: ${fullCapPath}`,
      };
    }

    const actualFile = fileCheck.output.trim();
    const command = `sudo aircrack-ng${bssidArg} ${actualFile} 2>&1 | head -30`;
    return sshExec(command);
  },

  // List capture files
  async list_captures(): Promise<AircrackResult> {
    await sshExec(`mkdir -p ${CAPTURE_DIR}`);
    return sshExec(`ls -la ${CAPTURE_DIR}/ 2>/dev/null || echo "No captures found"`);
  },

  // Clean up captures
  async cleanup_captures(pattern?: string): Promise<AircrackResult> {
    const filePattern = pattern || "*";
    return sshExec(`rm -f ${CAPTURE_DIR}/${filePattern} 2>/dev/null && echo "Cleanup complete" || echo "Nothing to clean"`);
  },

  // Get WiFi interface info
  async get_interface_info(iface: string): Promise<AircrackResult> {
    const commands = [
      `iwconfig ${iface} 2>/dev/null || echo "Interface not found"`,
      `iw dev ${iface} info 2>/dev/null || true`,
    ];

    let output = "";
    for (const cmd of commands) {
      const result = await sshExec(`sudo ${cmd}`);
      output += result.output + "\n";
    }

    return { success: true, output };
  },

  // Test SSH connection
  async test_connection(): Promise<AircrackResult> {
    const result = await sshExec("echo 'Connection successful' && whoami && hostname && which aircrack-ng");
    return result;
  },
};

// Create MCP Server
const server = new Server(
  {
    name: "aircrack-ng-mcp",
    version: "1.0.0",
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// List available tools
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return {
    tools: [
      {
        name: "test_connection",
        description: "Test SSH connection to Kali Linux and verify aircrack-ng is installed",
        inputSchema: {
          type: "object",
          properties: {},
          required: [],
        },
      },
      {
        name: "airmon_check",
        description: "List wireless interfaces and their status. Shows PHY, Interface, Driver, and Chipset.",
        inputSchema: {
          type: "object",
          properties: {},
          required: [],
        },
      },
      {
        name: "airmon_check_kill",
        description: "Kill processes that might interfere with monitor mode (NetworkManager, wpa_supplicant, etc.)",
        inputSchema: {
          type: "object",
          properties: {},
          required: [],
        },
      },
      {
        name: "airmon_start",
        description: "Enable monitor mode on a wireless interface. Creates a monitor interface (e.g., wlan0mon).",
        inputSchema: {
          type: "object",
          properties: {
            iface: {
              type: "string",
              description: "Wireless interface name (e.g., wlan0)",
            },
            channel: {
              type: "number",
              description: "Optional: Lock to specific channel (1-14 for 2.4GHz)",
            },
          },
          required: ["iface"],
        },
      },
      {
        name: "airmon_stop",
        description: "Disable monitor mode and restore managed mode on interface",
        inputSchema: {
          type: "object",
          properties: {
            iface: {
              type: "string",
              description: "Monitor interface name (e.g., wlan0mon)",
            },
          },
          required: ["iface"],
        },
      },
      {
        name: "airodump_scan",
        description: "Scan for wireless networks. Returns list of access points with BSSID, channel, encryption, and ESSID.",
        inputSchema: {
          type: "object",
          properties: {
            iface: {
              type: "string",
              description: "Monitor mode interface (e.g., wlan0mon)",
            },
            duration: {
              type: "number",
              description: "Scan duration in seconds (default: 10)",
            },
          },
          required: ["iface"],
        },
      },
      {
        name: "airodump_capture",
        description: "Start capturing packets from a specific access point. Runs in background.",
        inputSchema: {
          type: "object",
          properties: {
            iface: {
              type: "string",
              description: "Monitor mode interface (e.g., wlan0mon)",
            },
            bssid: {
              type: "string",
              description: "Target access point MAC address",
            },
            channel: {
              type: "number",
              description: "Channel of the target AP",
            },
            outputPrefix: {
              type: "string",
              description: "Prefix for output files (e.g., 'target1')",
            },
          },
          required: ["iface", "bssid", "channel", "outputPrefix"],
        },
      },
      {
        name: "airodump_stop",
        description: "Stop a running packet capture",
        inputSchema: {
          type: "object",
          properties: {
            outputPrefix: {
              type: "string",
              description: "The output prefix used when starting the capture",
            },
          },
          required: ["outputPrefix"],
        },
      },
      {
        name: "airodump_status",
        description: "Check status of a running capture and list captured files",
        inputSchema: {
          type: "object",
          properties: {
            outputPrefix: {
              type: "string",
              description: "The output prefix used when starting the capture",
            },
          },
          required: ["outputPrefix"],
        },
      },
      {
        name: "aireplay_deauth",
        description: "Send deauthentication frames to disconnect clients from AP (helps capture WPA handshake)",
        inputSchema: {
          type: "object",
          properties: {
            iface: {
              type: "string",
              description: "Monitor mode interface",
            },
            bssid: {
              type: "string",
              description: "Target access point MAC address",
            },
            count: {
              type: "number",
              description: "Number of deauth packets to send (default: 5, 0 for continuous)",
            },
            clientMac: {
              type: "string",
              description: "Optional: Target specific client MAC address",
            },
          },
          required: ["iface", "bssid"],
        },
      },
      {
        name: "aireplay_fakeauth",
        description: "Perform fake authentication with AP (used for WEP attacks)",
        inputSchema: {
          type: "object",
          properties: {
            iface: {
              type: "string",
              description: "Monitor mode interface",
            },
            bssid: {
              type: "string",
              description: "Target access point MAC address",
            },
            sourceMac: {
              type: "string",
              description: "Optional: Source MAC address to use",
            },
          },
          required: ["iface", "bssid"],
        },
      },
      {
        name: "aircrack_crack",
        description: "Attempt to crack WPA/WPA2 handshake using wordlist",
        inputSchema: {
          type: "object",
          properties: {
            capFile: {
              type: "string",
              description: "Capture file path or prefix (will find .cap file)",
            },
            wordlist: {
              type: "string",
              description: "Path to wordlist file on Kali (e.g., /usr/share/wordlists/rockyou.txt)",
            },
            bssid: {
              type: "string",
              description: "Optional: Target BSSID if multiple networks in capture",
            },
          },
          required: ["capFile", "wordlist"],
        },
      },
      {
        name: "aircrack_check_handshake",
        description: "Check if a valid WPA handshake has been captured in a pcap file",
        inputSchema: {
          type: "object",
          properties: {
            capFile: {
              type: "string",
              description: "Capture file path or prefix",
            },
            bssid: {
              type: "string",
              description: "Optional: Specific BSSID to check",
            },
          },
          required: ["capFile"],
        },
      },
      {
        name: "list_captures",
        description: "List all capture files in the captures directory",
        inputSchema: {
          type: "object",
          properties: {},
          required: [],
        },
      },
      {
        name: "cleanup_captures",
        description: "Delete capture files from the captures directory",
        inputSchema: {
          type: "object",
          properties: {
            pattern: {
              type: "string",
              description: "Optional: File pattern to delete (default: all files)",
            },
          },
          required: [],
        },
      },
      {
        name: "get_interface_info",
        description: "Get detailed information about a wireless interface",
        inputSchema: {
          type: "object",
          properties: {
            iface: {
              type: "string",
              description: "Interface name",
            },
          },
          required: ["iface"],
        },
      },
    ],
  };
});

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    let result: AircrackResult;

    switch (name) {
      case "test_connection":
        result = await tools.test_connection();
        break;

      case "airmon_check":
        result = await tools.airmon_check();
        break;

      case "airmon_check_kill":
        result = await tools.airmon_check_kill();
        break;

      case "airmon_start":
        result = await tools.airmon_start(
          args?.iface as string,
          args?.channel as number | undefined
        );
        break;

      case "airmon_stop":
        result = await tools.airmon_stop(args?.iface as string);
        break;

      case "airodump_scan":
        result = await tools.airodump_scan(
          args?.iface as string,
          args?.duration as number | undefined
        );
        break;

      case "airodump_capture":
        result = await tools.airodump_capture(
          args?.iface as string,
          args?.bssid as string,
          args?.channel as number,
          args?.outputPrefix as string
        );
        break;

      case "airodump_stop":
        result = await tools.airodump_stop(args?.outputPrefix as string);
        break;

      case "airodump_status":
        result = await tools.airodump_status(args?.outputPrefix as string);
        break;

      case "aireplay_deauth":
        result = await tools.aireplay_deauth(
          args?.iface as string,
          args?.bssid as string,
          args?.count as number | undefined,
          args?.clientMac as string | undefined
        );
        break;

      case "aireplay_fakeauth":
        result = await tools.aireplay_fakeauth(
          args?.iface as string,
          args?.bssid as string,
          args?.sourceMac as string | undefined
        );
        break;

      case "aircrack_crack":
        result = await tools.aircrack_crack(
          args?.capFile as string,
          args?.wordlist as string,
          args?.bssid as string | undefined
        );
        break;

      case "aircrack_check_handshake":
        result = await tools.aircrack_check_handshake(
          args?.capFile as string,
          args?.bssid as string | undefined
        );
        break;

      case "list_captures":
        result = await tools.list_captures();
        break;

      case "cleanup_captures":
        result = await tools.cleanup_captures(args?.pattern as string | undefined);
        break;

      case "get_interface_info":
        result = await tools.get_interface_info(args?.iface as string);
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

    const outputText = result.success
      ? result.output
      : `Error: ${result.error}\n\nOutput:\n${result.output}`;

    return {
      content: [
        {
          type: "text",
          text: outputText,
        },
      ],
      isError: !result.success,
    };
  } catch (error: any) {
    return {
      content: [
        {
          type: "text",
          text: `Error executing ${name}: ${error.message}`,
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
  console.error("Aircrack-ng MCP server started");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
