#!/usr/bin/env node

/**
 * Nmap MCP Server
 *
 * This MCP server provides tools for network scanning using nmap.
 * Scans are executed via SSH on a remote Kali box for security isolation.
 *
 * Environment Variables:
 * - NMAP_SSH_HOST: SSH host for remote execution (default: kali)
 * - NMAP_SSH_USER: SSH user (optional, uses default SSH config)
 * - NMAP_SSH_KEY: Path to SSH key (optional, uses default SSH config)
 * - NMAP_LOCAL: Set to "true" to run nmap locally instead of via SSH
 */

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { spawn, execFileSync } from "child_process";
import { XMLParser } from "fast-xml-parser";

// Configuration from environment
const config = {
  sshHost: process.env.NMAP_SSH_HOST || "kali",
  sshUser: process.env.NMAP_SSH_USER || "",
  sshKey: process.env.NMAP_SSH_KEY || "",
  runLocal: process.env.NMAP_LOCAL === "true",
};

// XML Parser for nmap output
const xmlParser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: "@_",
  textNodeName: "#text",
  parseAttributeValue: true,
  trimValues: true,
});

// Validate target to prevent command injection
function validateTarget(target: string): boolean {
  // Allow IP addresses, CIDR notation, hostnames, and ranges
  const validPattern = /^[a-zA-Z0-9\-\.\:\/\,\s\*]+$/;
  if (!validPattern.test(target)) {
    return false;
  }
  // Block dangerous characters
  const dangerousChars = /[;&|`$(){}[\]<>!]/;
  if (dangerousChars.test(target)) {
    return false;
  }
  return true;
}

// Validate ports parameter
function validatePorts(ports: string): boolean {
  // Allow port numbers, ranges, and common protocols
  const validPattern = /^[0-9\-\,T:U:]+$/;
  return validPattern.test(ports);
}

// Execute nmap command (via SSH or locally)
async function executeNmap(
  args: string[]
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  return new Promise((resolve) => {
    const stdout: string[] = [];
    const stderr: string[] = [];

    let command: string;
    let cmdArgs: string[];

    if (config.runLocal) {
      // Run nmap locally
      command = "nmap";
      cmdArgs = args;
    } else {
      // Run via SSH on remote Kali box
      command = "ssh";
      cmdArgs = [];

      // Add SSH options
      if (config.sshKey) {
        cmdArgs.push("-i", config.sshKey);
      }

      // Build SSH target
      const sshTarget = config.sshUser
        ? `${config.sshUser}@${config.sshHost}`
        : config.sshHost;
      cmdArgs.push(sshTarget);

      // Add nmap command with proper escaping
      cmdArgs.push("nmap", ...args);
    }

    const proc = spawn(command, cmdArgs, {
      stdio: ["pipe", "pipe", "pipe"],
      shell: false,
    });

    proc.stdout.on("data", (data) => {
      stdout.push(data.toString());
    });

    proc.stderr.on("data", (data) => {
      stderr.push(data.toString());
    });

    proc.on("close", (code) => {
      resolve({
        stdout: stdout.join(""),
        stderr: stderr.join(""),
        exitCode: code ?? 0,
      });
    });

    proc.on("error", (err) => {
      resolve({
        stdout: stdout.join(""),
        stderr: `Error executing nmap: ${err.message}`,
        exitCode: 1,
      });
    });
  });
}

// Parse nmap XML output
interface NmapHost {
  address: string;
  hostname?: string;
  status: string;
  ports: NmapPort[];
  os?: NmapOS[];
  scripts?: NmapScript[];
}

interface NmapPort {
  portId: number;
  protocol: string;
  state: string;
  service?: string;
  version?: string;
  product?: string;
  scripts?: NmapScript[];
}

interface NmapOS {
  name: string;
  accuracy: number;
  family?: string;
  vendor?: string;
}

interface NmapScript {
  id: string;
  output: string;
}

interface NmapScanResult {
  hosts: NmapHost[];
  scanInfo: {
    type: string;
    protocol: string;
    numServices: number;
    startTime: string;
    endTime: string;
    elapsed: string;
  };
  summary: string;
}

function parseNmapXml(xmlOutput: string): NmapScanResult {
  try {
    const parsed = xmlParser.parse(xmlOutput);
    const nmaprun = parsed.nmaprun;

    if (!nmaprun) {
      return {
        hosts: [],
        scanInfo: {
          type: "unknown",
          protocol: "unknown",
          numServices: 0,
          startTime: "",
          endTime: "",
          elapsed: "",
        },
        summary: "Failed to parse nmap output",
      };
    }

    const hosts: NmapHost[] = [];
    const hostData = Array.isArray(nmaprun.host)
      ? nmaprun.host
      : nmaprun.host
      ? [nmaprun.host]
      : [];

    for (const host of hostData) {
      // Get address
      const addresses = Array.isArray(host.address)
        ? host.address
        : host.address
        ? [host.address]
        : [];
      const ipAddr = addresses.find(
        (a: Record<string, unknown>) => a["@_addrtype"] === "ipv4" || a["@_addrtype"] === "ipv6"
      );
      const address = ipAddr ? (ipAddr["@_addr"] as string) : "unknown";

      // Get hostname
      const hostnames = host.hostnames?.hostname;
      const hostname = Array.isArray(hostnames)
        ? hostnames[0]?.["@_name"]
        : hostnames?.["@_name"];

      // Get status
      const status = host.status?.["@_state"] || "unknown";

      // Get ports
      const ports: NmapPort[] = [];
      const portData = host.ports?.port;
      const portList = Array.isArray(portData)
        ? portData
        : portData
        ? [portData]
        : [];

      for (const port of portList) {
        const nmapPort: NmapPort = {
          portId: port["@_portid"],
          protocol: port["@_protocol"],
          state: port.state?.["@_state"] || "unknown",
          service: port.service?.["@_name"],
          product: port.service?.["@_product"],
          version: port.service?.["@_version"],
        };

        // Get port scripts
        const portScripts = port.script;
        if (portScripts) {
          const scriptList = Array.isArray(portScripts)
            ? portScripts
            : [portScripts];
          nmapPort.scripts = scriptList.map((s: Record<string, unknown>) => ({
            id: s["@_id"] as string,
            output: s["@_output"] as string || s["#text"] as string || "",
          }));
        }

        ports.push(nmapPort);
      }

      // Get OS detection
      const osMatches: NmapOS[] = [];
      const osData = host.os?.osmatch;
      const osList = Array.isArray(osData) ? osData : osData ? [osData] : [];

      for (const os of osList) {
        osMatches.push({
          name: os["@_name"],
          accuracy: os["@_accuracy"],
          family: os.osclass?.["@_osfamily"],
          vendor: os.osclass?.["@_vendor"],
        });
      }

      // Get host scripts
      const hostScripts: NmapScript[] = [];
      const hostScriptData = host.hostscript?.script;
      if (hostScriptData) {
        const scriptList = Array.isArray(hostScriptData)
          ? hostScriptData
          : [hostScriptData];
        for (const s of scriptList) {
          hostScripts.push({
            id: s["@_id"],
            output: s["@_output"] || s["#text"] || "",
          });
        }
      }

      hosts.push({
        address,
        hostname,
        status,
        ports,
        os: osMatches.length > 0 ? osMatches : undefined,
        scripts: hostScripts.length > 0 ? hostScripts : undefined,
      });
    }

    // Get scan info
    const scanInfo = {
      type: nmaprun.scaninfo?.["@_type"] || "unknown",
      protocol: nmaprun.scaninfo?.["@_protocol"] || "unknown",
      numServices: nmaprun.scaninfo?.["@_numservices"] || 0,
      startTime: nmaprun["@_startstr"] || "",
      endTime: nmaprun.runstats?.finished?.["@_timestr"] || "",
      elapsed: nmaprun.runstats?.finished?.["@_elapsed"] || "",
    };

    const summary =
      nmaprun.runstats?.finished?.["@_summary"] ||
      `Scanned ${hosts.length} host(s)`;

    return { hosts, scanInfo, summary };
  } catch (error) {
    return {
      hosts: [],
      scanInfo: {
        type: "error",
        protocol: "error",
        numServices: 0,
        startTime: "",
        endTime: "",
        elapsed: "",
      },
      summary: `Parse error: ${error}`,
    };
  }
}

// Format scan results for display
function formatScanResults(result: NmapScanResult): string {
  let output = `# Nmap Scan Results\n\n`;
  output += `**Summary**: ${result.summary}\n`;
  output += `**Scan Type**: ${result.scanInfo.type} (${result.scanInfo.protocol})\n`;
  output += `**Duration**: ${result.scanInfo.elapsed}s\n\n`;

  if (result.hosts.length === 0) {
    output += `No hosts discovered.\n`;
    return output;
  }

  for (const host of result.hosts) {
    output += `## Host: ${host.address}`;
    if (host.hostname) {
      output += ` (${host.hostname})`;
    }
    output += `\n`;
    output += `**Status**: ${host.status}\n\n`;

    // OS Detection
    if (host.os && host.os.length > 0) {
      output += `### OS Detection\n`;
      for (const os of host.os.slice(0, 3)) {
        output += `- ${os.name} (${os.accuracy}% accuracy)`;
        if (os.family) output += ` - ${os.family}`;
        output += `\n`;
      }
      output += `\n`;
    }

    // Ports
    if (host.ports.length > 0) {
      output += `### Open Ports\n`;
      output += `| Port | Protocol | State | Service | Version |\n`;
      output += `|------|----------|-------|---------|--------|\n`;

      for (const port of host.ports) {
        const version = port.product
          ? `${port.product}${port.version ? " " + port.version : ""}`
          : "";
        output += `| ${port.portId} | ${port.protocol} | ${port.state} | ${
          port.service || "-"
        } | ${version || "-"} |\n`;
      }
      output += `\n`;

      // Port scripts
      for (const port of host.ports) {
        if (port.scripts && port.scripts.length > 0) {
          output += `#### Scripts for port ${port.portId}/${port.protocol}\n`;
          for (const script of port.scripts) {
            output += `**${script.id}**:\n\`\`\`\n${script.output}\n\`\`\`\n`;
          }
        }
      }
    }

    // Host scripts
    if (host.scripts && host.scripts.length > 0) {
      output += `### Host Scripts\n`;
      for (const script of host.scripts) {
        output += `**${script.id}**:\n\`\`\`\n${script.output}\n\`\`\`\n`;
      }
    }

    output += `\n---\n\n`;
  }

  return output;
}

// Define MCP tools
const tools: Tool[] = [
  {
    name: "nmap_scan",
    description:
      "Perform a basic nmap port scan on target hosts. Supports IP addresses, hostnames, CIDR ranges. Returns discovered hosts and open ports.",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description:
            "Target to scan (IP address, hostname, CIDR range, or space-separated list)",
        },
        ports: {
          type: "string",
          description:
            "Port specification (e.g., '22,80,443', '1-1000', 'T:80,U:53'). Default: top 1000 ports",
        },
        scanType: {
          type: "string",
          enum: ["syn", "connect", "udp", "ack", "window", "maimon"],
          description:
            "Scan type: syn (default, requires root), connect (TCP), udp, ack, window, maimon",
        },
        timing: {
          type: "number",
          minimum: 0,
          maximum: 5,
          description:
            "Timing template (0-5): 0=paranoid, 1=sneaky, 2=polite, 3=normal, 4=aggressive, 5=insane",
        },
        skipHostDiscovery: {
          type: "boolean",
          description: "Skip host discovery (-Pn), treat all hosts as online",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "nmap_service_scan",
    description:
      "Perform service version detection (-sV). Identifies service names and versions running on open ports.",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target to scan",
        },
        ports: {
          type: "string",
          description: "Port specification",
        },
        intensity: {
          type: "number",
          minimum: 0,
          maximum: 9,
          description:
            "Version detection intensity (0-9). Higher values are more accurate but slower.",
        },
        lightMode: {
          type: "boolean",
          description:
            "Light mode (-sV --version-light): faster but less accurate",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "nmap_os_detect",
    description:
      "Perform OS fingerprinting (-O). Attempts to identify the operating system of target hosts. Requires privileged access.",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target to scan",
        },
        limitRetries: {
          type: "number",
          description: "Max OS detection retries against a target (default: 2)",
        },
        aggressiveMode: {
          type: "boolean",
          description:
            "Aggressive OS detection: makes more guesses but may be less accurate",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "nmap_script_scan",
    description:
      "Run NSE (Nmap Scripting Engine) scripts for advanced reconnaissance and vulnerability assessment. Over 600 scripts available.",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target to scan",
        },
        scripts: {
          type: "string",
          description:
            "Script specification: 'default', 'vuln', 'safe', 'intrusive', or specific script names (e.g., 'http-title,ssh-auth-methods')",
        },
        ports: {
          type: "string",
          description: "Port specification",
        },
        scriptArgs: {
          type: "string",
          description:
            "Arguments to pass to scripts (e.g., 'user=admin,pass=admin')",
        },
      },
      required: ["target", "scripts"],
    },
  },
  {
    name: "nmap_quick_scan",
    description:
      "Fast scan preset (-F). Scans fewer ports than default for quick reconnaissance.",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target to scan",
        },
        topPorts: {
          type: "number",
          description:
            "Scan only the N most common ports (e.g., 100 for top 100)",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "nmap_vuln_scan",
    description:
      "Run vulnerability scanning scripts (--script vuln). Checks for known vulnerabilities on target services.",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target to scan",
        },
        ports: {
          type: "string",
          description: "Port specification",
        },
        category: {
          type: "string",
          enum: ["vuln", "exploit", "auth", "brute", "discovery", "dos", "safe"],
          description:
            "Script category: vuln (default), exploit, auth, brute, discovery, dos, safe",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "nmap_comprehensive_scan",
    description:
      "Comprehensive scan combining multiple techniques: SYN scan, service detection, OS detection, and default scripts (-sS -sV -O -sC). Requires privileged access.",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target to scan",
        },
        ports: {
          type: "string",
          description: "Port specification (default: all 65535 ports with -p-)",
        },
        timing: {
          type: "number",
          minimum: 0,
          maximum: 5,
          description: "Timing template (0-5)",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "nmap_ping_sweep",
    description:
      "Host discovery only (-sn). Find live hosts on a network without port scanning.",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target network (e.g., '192.168.1.0/24')",
        },
        technique: {
          type: "string",
          enum: ["icmp", "tcp-syn", "tcp-ack", "udp", "arp"],
          description:
            "Discovery technique: icmp (ICMP echo), tcp-syn (SYN to port 443), tcp-ack (ACK to port 80), udp, arp (local network only)",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "nmap_stealth_scan",
    description:
      "Stealth scan with evasion techniques. Uses timing options, fragmentation, and decoys to avoid detection.",
    inputSchema: {
      type: "object",
      properties: {
        target: {
          type: "string",
          description: "Target to scan",
        },
        ports: {
          type: "string",
          description: "Port specification",
        },
        decoys: {
          type: "string",
          description:
            "Comma-separated list of decoy IPs (or 'RND:5' for 5 random decoys)",
        },
        sourcePort: {
          type: "number",
          description: "Use specified source port (e.g., 53, 80)",
        },
        fragmentPackets: {
          type: "boolean",
          description: "Fragment packets to evade firewalls",
        },
        maxRatePerSecond: {
          type: "number",
          description: "Maximum packets per second",
        },
      },
      required: ["target"],
    },
  },
  {
    name: "nmap_parse_output",
    description:
      "Parse nmap XML output from a previous scan or file. Useful for analyzing saved scan results.",
    inputSchema: {
      type: "object",
      properties: {
        xmlContent: {
          type: "string",
          description: "Raw XML content from nmap -oX output",
        },
      },
      required: ["xmlContent"],
    },
  },
  {
    name: "nmap_status",
    description:
      "Check nmap availability and configuration. Shows whether nmap is accessible via SSH or locally.",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
];

// Handle tool execution
async function handleToolCall(
  name: string,
  args: Record<string, unknown>
): Promise<string> {
  switch (name) {
    case "nmap_status": {
      try {
        const result = await executeNmap(["--version"]);
        const mode = config.runLocal ? "Local" : `SSH (${config.sshHost})`;

        if (result.exitCode === 0) {
          return `# Nmap Status

**Mode**: ${mode}
**Status**: Available

**Version Info**:
\`\`\`
${result.stdout.trim()}
\`\`\`

## Configuration
- SSH Host: ${config.sshHost}
- SSH User: ${config.sshUser || "(default)"}
- SSH Key: ${config.sshKey || "(default)"}
- Run Local: ${config.runLocal}

## Notes
${
  config.runLocal
    ? "Running nmap locally. Some scans may require root/sudo."
    : `Running nmap via SSH to ${config.sshHost}. Ensure SSH key authentication is configured.`
}
`;
        } else {
          return `# Nmap Status

**Mode**: ${mode}
**Status**: Error

**Error**:
\`\`\`
${result.stderr || "Failed to connect or execute nmap"}
\`\`\`

## Troubleshooting
${
  config.runLocal
    ? "1. Ensure nmap is installed: apt install nmap\n2. Check nmap is in PATH"
    : `1. Ensure SSH access to ${config.sshHost} is configured\n2. Ensure nmap is installed on the remote host\n3. Check: ssh ${config.sshHost} nmap --version`
}
`;
        }
      } catch (error) {
        return `Error checking nmap status: ${error}`;
      }
    }

    case "nmap_scan": {
      const target = args.target as string;
      if (!validateTarget(target)) {
        return "Error: Invalid target format. Use IP addresses, hostnames, or CIDR ranges.";
      }

      const cmdArgs = ["-oX", "-"]; // XML output to stdout

      // Scan type
      const scanType = args.scanType as string;
      if (scanType === "syn") cmdArgs.push("-sS");
      else if (scanType === "connect") cmdArgs.push("-sT");
      else if (scanType === "udp") cmdArgs.push("-sU");
      else if (scanType === "ack") cmdArgs.push("-sA");
      else if (scanType === "window") cmdArgs.push("-sW");
      else if (scanType === "maimon") cmdArgs.push("-sM");

      // Ports
      if (args.ports) {
        const ports = args.ports as string;
        if (!validatePorts(ports)) {
          return "Error: Invalid port specification.";
        }
        cmdArgs.push("-p", ports);
      }

      // Timing
      if (args.timing !== undefined) {
        cmdArgs.push(`-T${args.timing}`);
      }

      // Skip host discovery
      if (args.skipHostDiscovery) {
        cmdArgs.push("-Pn");
      }

      cmdArgs.push(target);

      const result = await executeNmap(cmdArgs);

      if (result.exitCode !== 0 && !result.stdout.includes("<nmaprun")) {
        return `Error executing nmap:\n${result.stderr}`;
      }

      const parsed = parseNmapXml(result.stdout);
      return formatScanResults(parsed);
    }

    case "nmap_service_scan": {
      const target = args.target as string;
      if (!validateTarget(target)) {
        return "Error: Invalid target format.";
      }

      const cmdArgs = ["-oX", "-", "-sV"];

      if (args.ports) {
        const ports = args.ports as string;
        if (!validatePorts(ports)) {
          return "Error: Invalid port specification.";
        }
        cmdArgs.push("-p", ports);
      }

      if (args.intensity !== undefined) {
        cmdArgs.push(`--version-intensity`, String(args.intensity));
      }

      if (args.lightMode) {
        cmdArgs.push("--version-light");
      }

      cmdArgs.push(target);

      const result = await executeNmap(cmdArgs);

      if (result.exitCode !== 0 && !result.stdout.includes("<nmaprun")) {
        return `Error executing nmap:\n${result.stderr}`;
      }

      const parsed = parseNmapXml(result.stdout);
      return formatScanResults(parsed);
    }

    case "nmap_os_detect": {
      const target = args.target as string;
      if (!validateTarget(target)) {
        return "Error: Invalid target format.";
      }

      const cmdArgs = ["-oX", "-", "-O"];

      if (args.limitRetries !== undefined) {
        cmdArgs.push("--max-os-tries", String(args.limitRetries));
      }

      if (args.aggressiveMode) {
        cmdArgs.push("--osscan-guess");
      }

      cmdArgs.push(target);

      const result = await executeNmap(cmdArgs);

      if (result.exitCode !== 0 && !result.stdout.includes("<nmaprun")) {
        return `Error executing nmap:\n${result.stderr}\n\nNote: OS detection requires privileged access (root/sudo).`;
      }

      const parsed = parseNmapXml(result.stdout);
      return formatScanResults(parsed);
    }

    case "nmap_script_scan": {
      const target = args.target as string;
      if (!validateTarget(target)) {
        return "Error: Invalid target format.";
      }

      const scripts = args.scripts as string;
      // Basic validation for script names
      if (!/^[a-zA-Z0-9\-\,\*\s]+$/.test(scripts)) {
        return "Error: Invalid script specification.";
      }

      const cmdArgs = ["-oX", "-", "--script", scripts];

      if (args.ports) {
        const ports = args.ports as string;
        if (!validatePorts(ports)) {
          return "Error: Invalid port specification.";
        }
        cmdArgs.push("-p", ports);
      }

      if (args.scriptArgs) {
        cmdArgs.push("--script-args", args.scriptArgs as string);
      }

      cmdArgs.push(target);

      const result = await executeNmap(cmdArgs);

      if (result.exitCode !== 0 && !result.stdout.includes("<nmaprun")) {
        return `Error executing nmap:\n${result.stderr}`;
      }

      const parsed = parseNmapXml(result.stdout);
      return formatScanResults(parsed);
    }

    case "nmap_quick_scan": {
      const target = args.target as string;
      if (!validateTarget(target)) {
        return "Error: Invalid target format.";
      }

      const cmdArgs = ["-oX", "-"];

      if (args.topPorts) {
        cmdArgs.push("--top-ports", String(args.topPorts));
      } else {
        cmdArgs.push("-F"); // Fast scan
      }

      cmdArgs.push(target);

      const result = await executeNmap(cmdArgs);

      if (result.exitCode !== 0 && !result.stdout.includes("<nmaprun")) {
        return `Error executing nmap:\n${result.stderr}`;
      }

      const parsed = parseNmapXml(result.stdout);
      return formatScanResults(parsed);
    }

    case "nmap_vuln_scan": {
      const target = args.target as string;
      if (!validateTarget(target)) {
        return "Error: Invalid target format.";
      }

      const category = (args.category as string) || "vuln";
      const cmdArgs = ["-oX", "-", "--script", category, "-sV"];

      if (args.ports) {
        const ports = args.ports as string;
        if (!validatePorts(ports)) {
          return "Error: Invalid port specification.";
        }
        cmdArgs.push("-p", ports);
      }

      cmdArgs.push(target);

      const result = await executeNmap(cmdArgs);

      if (result.exitCode !== 0 && !result.stdout.includes("<nmaprun")) {
        return `Error executing nmap:\n${result.stderr}`;
      }

      const parsed = parseNmapXml(result.stdout);
      return formatScanResults(parsed);
    }

    case "nmap_comprehensive_scan": {
      const target = args.target as string;
      if (!validateTarget(target)) {
        return "Error: Invalid target format.";
      }

      const cmdArgs = ["-oX", "-", "-sS", "-sV", "-O", "-sC"];

      if (args.ports) {
        const ports = args.ports as string;
        if (!validatePorts(ports)) {
          return "Error: Invalid port specification.";
        }
        cmdArgs.push("-p", ports);
      } else {
        cmdArgs.push("-p-"); // All ports
      }

      if (args.timing !== undefined) {
        cmdArgs.push(`-T${args.timing}`);
      }

      cmdArgs.push(target);

      const result = await executeNmap(cmdArgs);

      if (result.exitCode !== 0 && !result.stdout.includes("<nmaprun")) {
        return `Error executing nmap:\n${result.stderr}\n\nNote: This scan requires privileged access (root/sudo).`;
      }

      const parsed = parseNmapXml(result.stdout);
      return formatScanResults(parsed);
    }

    case "nmap_ping_sweep": {
      const target = args.target as string;
      if (!validateTarget(target)) {
        return "Error: Invalid target format.";
      }

      const cmdArgs = ["-oX", "-", "-sn"];

      // Discovery technique
      const technique = args.technique as string;
      if (technique === "icmp") cmdArgs.push("-PE");
      else if (technique === "tcp-syn") cmdArgs.push("-PS443");
      else if (technique === "tcp-ack") cmdArgs.push("-PA80");
      else if (technique === "udp") cmdArgs.push("-PU");
      else if (technique === "arp") cmdArgs.push("-PR");

      cmdArgs.push(target);

      const result = await executeNmap(cmdArgs);

      if (result.exitCode !== 0 && !result.stdout.includes("<nmaprun")) {
        return `Error executing nmap:\n${result.stderr}`;
      }

      const parsed = parseNmapXml(result.stdout);

      // Format ping sweep results differently
      let output = `# Ping Sweep Results\n\n`;
      output += `**Target**: ${target}\n`;
      output += `**Summary**: ${parsed.summary}\n\n`;

      if (parsed.hosts.length === 0) {
        output += `No live hosts discovered.\n`;
        return output;
      }

      output += `## Live Hosts\n\n`;
      output += `| IP Address | Hostname | Status |\n`;
      output += `|------------|----------|--------|\n`;

      for (const host of parsed.hosts) {
        output += `| ${host.address} | ${host.hostname || "-"} | ${host.status} |\n`;
      }

      output += `\n**Total**: ${parsed.hosts.filter((h) => h.status === "up").length} host(s) up\n`;

      return output;
    }

    case "nmap_stealth_scan": {
      const target = args.target as string;
      if (!validateTarget(target)) {
        return "Error: Invalid target format.";
      }

      const cmdArgs = ["-oX", "-", "-sS", "-T2"]; // SYN scan with polite timing

      if (args.ports) {
        const ports = args.ports as string;
        if (!validatePorts(ports)) {
          return "Error: Invalid port specification.";
        }
        cmdArgs.push("-p", ports);
      }

      if (args.decoys) {
        cmdArgs.push("-D", args.decoys as string);
      }

      if (args.sourcePort) {
        cmdArgs.push("--source-port", String(args.sourcePort));
      }

      if (args.fragmentPackets) {
        cmdArgs.push("-f");
      }

      if (args.maxRatePerSecond) {
        cmdArgs.push("--max-rate", String(args.maxRatePerSecond));
      }

      cmdArgs.push(target);

      const result = await executeNmap(cmdArgs);

      if (result.exitCode !== 0 && !result.stdout.includes("<nmaprun")) {
        return `Error executing nmap:\n${result.stderr}`;
      }

      const parsed = parseNmapXml(result.stdout);
      return formatScanResults(parsed);
    }

    case "nmap_parse_output": {
      const xmlContent = args.xmlContent as string;

      if (!xmlContent || !xmlContent.includes("<nmaprun")) {
        return "Error: Invalid XML content. Ensure this is nmap XML output (-oX).";
      }

      const parsed = parseNmapXml(xmlContent);
      return formatScanResults(parsed);
    }

    default:
      return `Unknown tool: ${name}`;
  }
}

// Main server setup
async function main() {
  const server = new Server(
    {
      name: "nmap-mcp",
      version: "1.0.0",
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  // Log startup info
  const mode = config.runLocal ? "local" : `SSH to ${config.sshHost}`;
  console.error(`Nmap MCP Server starting (mode: ${mode})`);

  // Handle tool listing
  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return { tools };
  });

  // Handle tool execution
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    try {
      const result = await handleToolCall(
        name,
        (args || {}) as Record<string, unknown>
      );
      return {
        content: [
          {
            type: "text",
            text: result,
          },
        ],
      };
    } catch (error) {
      const errorMessage =
        error instanceof Error ? error.message : String(error);
      return {
        content: [
          {
            type: "text",
            text: `Error executing tool ${name}: ${errorMessage}`,
          },
        ],
        isError: true,
      };
    }
  });

  // Start the server
  const transport = new StdioServerTransport();
  await server.connect(transport);

  console.error("Nmap MCP Server started successfully");
}

main().catch((error) => {
  console.error("Fatal error starting Nmap MCP Server:", error);
  process.exit(1);
});
