#!/usr/bin/env node

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from "@modelcontextprotocol/sdk/types.js";
import { spawn, execSync } from "child_process";
import * as fs from "fs";
import * as path from "path";

// SET installation paths
const SET_PATHS = [
  "/usr/share/set",
  "/opt/set",
  "/usr/share/setoolkit",
  process.env.SET_PATH,
].filter(Boolean) as string[];

// Find SET installation
function findSetPath(): string | null {
  for (const setPath of SET_PATHS) {
    if (fs.existsSync(setPath)) {
      return setPath;
    }
  }
  return null;
}

// Check if SET is installed
function isSetInstalled(): boolean {
  try {
    execSync("which setoolkit", { encoding: "utf-8" });
    return true;
  } catch {
    return findSetPath() !== null;
  }
}

// Execute SET command
async function executeSetCommand(
  args: string[],
  input?: string
): Promise<{ stdout: string; stderr: string; exitCode: number }> {
  return new Promise((resolve) => {
    const setPath = findSetPath();
    const command = setPath ? path.join(setPath, "setoolkit") : "setoolkit";

    const proc = spawn(command, args, {
      env: { ...process.env, TERM: "dumb" },
    });

    let stdout = "";
    let stderr = "";

    proc.stdout.on("data", (data) => {
      stdout += data.toString();
    });

    proc.stderr.on("data", (data) => {
      stderr += data.toString();
    });

    if (input) {
      proc.stdin.write(input);
      proc.stdin.end();
    }

    proc.on("close", (code) => {
      resolve({
        stdout,
        stderr,
        exitCode: code ?? 1,
      });
    });

    proc.on("error", (err) => {
      resolve({
        stdout: "",
        stderr: err.message,
        exitCode: 1,
      });
    });
  });
}

// Tool definitions
const tools: Tool[] = [
  {
    name: "set_status",
    description:
      "Check if SET (Social Engineering Toolkit) is installed and get version information",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "set_list_attacks",
    description:
      "List available attack vectors in SET including spear-phishing, website attacks, and more",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "set_spear_phishing_info",
    description:
      "Get information about spear-phishing attack vectors and email attack capabilities",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "set_website_attack_info",
    description:
      "Get information about website attack vectors including credential harvesting and cloning",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "set_payload_info",
    description:
      "Get information about available payloads and infectious media generator options",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "set_config_info",
    description: "Get SET configuration information and settings",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
  {
    name: "set_run_command",
    description:
      "Run a SET command with specified menu options. Use with caution - for authorized security testing only.",
    inputSchema: {
      type: "object",
      properties: {
        menu_sequence: {
          type: "string",
          description:
            "Newline-separated menu options to send to SET (e.g., '1\\n2\\n3' for menu selections)",
        },
        timeout_seconds: {
          type: "number",
          description: "Timeout in seconds (default: 30)",
          default: 30,
        },
      },
      required: ["menu_sequence"],
    },
  },
  {
    name: "set_clone_website",
    description:
      "Clone a website for credential harvesting (authorized testing only). Returns instructions for manual setup.",
    inputSchema: {
      type: "object",
      properties: {
        target_url: {
          type: "string",
          description: "URL of the website to clone",
        },
        listener_ip: {
          type: "string",
          description:
            "IP address for the credential harvester to listen on",
        },
      },
      required: ["target_url"],
    },
  },
  {
    name: "set_generate_phishing_template",
    description:
      "Generate a phishing email template based on common social engineering techniques",
    inputSchema: {
      type: "object",
      properties: {
        template_type: {
          type: "string",
          enum: [
            "password_reset",
            "invoice",
            "delivery",
            "it_support",
            "hr_notice",
          ],
          description: "Type of phishing template to generate",
        },
        target_company: {
          type: "string",
          description: "Target company name for customization",
        },
        sender_name: {
          type: "string",
          description: "Sender name to use in the template",
        },
      },
      required: ["template_type"],
    },
  },
  {
    name: "set_powershell_attack_info",
    description:
      "Get information about PowerShell-based attack vectors in SET",
    inputSchema: {
      type: "object",
      properties: {},
      required: [],
    },
  },
];

// Attack vector descriptions
const ATTACK_VECTORS = {
  "1": {
    name: "Spear-Phishing Attack Vectors",
    description:
      "Perform targeted phishing attacks via email with malicious attachments or links",
    submenus: {
      "1": "Perform a Mass Email Attack",
      "2": "Create a FileFormat Payload",
      "3": "Create a Social-Engineering Template",
    },
  },
  "2": {
    name: "Website Attack Vectors",
    description:
      "Clone websites for credential harvesting or host malicious payloads",
    submenus: {
      "1": "Java Applet Attack Method",
      "2": "Metasploit Browser Exploit Method",
      "3": "Credential Harvester Attack Method",
      "4": "Tabnabbing Attack Method",
      "5": "Web Jacking Attack Method",
      "6": "Multi-Attack Web Method",
      "7": "HTA Attack Method",
    },
  },
  "3": {
    name: "Infectious Media Generator",
    description:
      "Create payloads for USB/CD/DVD that auto-execute when media is inserted",
  },
  "4": {
    name: "Create a Payload and Listener",
    description:
      "Generate standalone payloads with corresponding Metasploit handlers",
  },
  "5": {
    name: "Mass Mailer Attack",
    description: "Send mass phishing emails to multiple targets",
  },
  "6": {
    name: "Arduino-Based Attack Vector",
    description:
      "Program Arduino devices as HID devices for keyboard injection attacks",
  },
  "7": {
    name: "Wireless Access Point Attack Vector",
    description:
      "Create rogue access points for man-in-the-middle attacks",
  },
  "8": {
    name: "QRCode Generator Attack Vector",
    description: "Generate malicious QR codes that redirect to attack sites",
  },
  "9": {
    name: "PowerShell Attack Vectors",
    description:
      "Generate PowerShell-based payloads and attack scripts",
    submenus: {
      "1": "PowerShell Alphanumeric Shellcode Injector",
      "2": "PowerShell Reverse Shell",
      "3": "PowerShell Bind Shell",
      "4": "PowerShell Dump SAM Database",
    },
  },
  "10": {
    name: "SMS Spoofing Attack Vector",
    description: "Send spoofed SMS messages for social engineering",
  },
  "11": {
    name: "Third Party Modules",
    description: "Additional modules and integrations",
  },
};

// Phishing templates
const PHISHING_TEMPLATES: Record<
  string,
  { subject: string; body: string }
> = {
  password_reset: {
    subject: "Urgent: Password Reset Required - Action Needed",
    body: `Dear {target_name},

We have detected unusual activity on your {company} account. For your security, we require you to reset your password immediately.

Please click the link below to verify your identity and reset your password:
{link}

This link will expire in 24 hours. If you did not request this reset, please contact IT support immediately.

Best regards,
{sender_name}
{company} Security Team`,
  },
  invoice: {
    subject: "Invoice #{invoice_number} - Payment Required",
    body: `Dear Accounts Payable,

Please find attached invoice #{invoice_number} for services rendered.

Payment is due within 30 days. For your convenience, you may also view and pay the invoice online:
{link}

If you have any questions regarding this invoice, please contact our billing department.

Best regards,
{sender_name}
{company} Billing`,
  },
  delivery: {
    subject: "Package Delivery Notification - Action Required",
    body: `Dear {target_name},

We attempted to deliver your package today but were unable to complete the delivery.

Please click the link below to reschedule your delivery or update your shipping address:
{link}

Your package will be returned to sender if not claimed within 5 business days.

Thank you,
{sender_name}
Shipping Department`,
  },
  it_support: {
    subject: "IT Support: System Update Required",
    body: `Dear {target_name},

The IT department is rolling out a critical security update that requires your action.

Please log in to the following portal to complete the update:
{link}

This update is mandatory and must be completed by end of business today.

If you experience any issues, please contact the IT Help Desk.

Best regards,
{sender_name}
{company} IT Support`,
  },
  hr_notice: {
    subject: "Important HR Notice - Employee Benefits Update",
    body: `Dear {target_name},

We are updating our employee benefits portal and need you to verify your information.

Please access the portal below to review and confirm your benefits selections:
{link}

Failure to verify your information may result in a lapse of coverage.

Best regards,
{sender_name}
{company} Human Resources`,
  },
};

// Create the MCP server
const server = new Server(
  {
    name: "social-engineer-toolkit-mcp",
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

// Handle tool calls
server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    switch (name) {
      case "set_status": {
        const installed = isSetInstalled();
        const setPath = findSetPath();

        if (!installed) {
          return {
            content: [
              {
                type: "text",
                text: JSON.stringify(
                  {
                    installed: false,
                    message:
                      "SET (Social Engineering Toolkit) is not installed on this system.",
                    installation_instructions: {
                      kali: "sudo apt install set",
                      manual:
                        "git clone https://github.com/trustedsec/social-engineer-toolkit.git && cd social-engineer-toolkit && python setup.py install",
                    },
                  },
                  null,
                  2
                ),
              },
            ],
          };
        }

        let version = "Unknown";
        try {
          const result = await executeSetCommand(["--version"]);
          version = result.stdout.trim() || "Installed (version check failed)";
        } catch {
          version = "Installed (version check failed)";
        }

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  installed: true,
                  path: setPath,
                  version,
                  note: "SET is installed and ready for authorized security testing.",
                },
                null,
                2
              ),
            },
          ],
        };
      }

      case "set_list_attacks": {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  attack_vectors: ATTACK_VECTORS,
                  note: "These attack vectors are for authorized security testing only. Always obtain proper authorization before conducting any security assessments.",
                },
                null,
                2
              ),
            },
          ],
        };
      }

      case "set_spear_phishing_info": {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  attack_name: "Spear-Phishing Attack Vectors",
                  description:
                    "Targeted email-based attacks using social engineering techniques",
                  capabilities: [
                    "Mass email attacks with malicious attachments",
                    "Custom file format payloads (PDF, DOC, etc.)",
                    "Template-based social engineering emails",
                    "Integration with Metasploit payloads",
                  ],
                  menu_path: "1 (Social-Engineering Attacks) -> 1 (Spear-Phishing)",
                  warning:
                    "Only use for authorized penetration testing with explicit written permission.",
                },
                null,
                2
              ),
            },
          ],
        };
      }

      case "set_website_attack_info": {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  attack_name: "Website Attack Vectors",
                  description:
                    "Web-based attacks including credential harvesting and cloning",
                  methods: {
                    credential_harvester: {
                      description:
                        "Clone a website and capture credentials entered by victims",
                      menu_path: "2 -> 3 (Credential Harvester)",
                      options: [
                        "Web Templates (pre-built common sites)",
                        "Site Cloner (clone any URL)",
                        "Custom Import (use your own HTML)",
                      ],
                    },
                    tabnabbing: {
                      description:
                        "Redirect inactive tabs to phishing pages",
                      menu_path: "2 -> 4 (Tabnabbing)",
                    },
                    web_jacking: {
                      description:
                        "Present link replacement after page load",
                      menu_path: "2 -> 5 (Web Jacking)",
                    },
                    hta_attack: {
                      description:
                        "Serve HTA (HTML Application) files for code execution",
                      menu_path: "2 -> 7 (HTA Attack)",
                    },
                  },
                  warning:
                    "Only use for authorized penetration testing with explicit written permission.",
                },
                null,
                2
              ),
            },
          ],
        };
      }

      case "set_payload_info": {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  payloads: {
                    infectious_media: {
                      description:
                        "Create auto-run payloads for USB/CD/DVD drives",
                      capabilities: [
                        "Metasploit executable payloads",
                        "Auto-run configurations",
                        "Multiple payload formats",
                      ],
                    },
                    standalone: {
                      description:
                        "Create payloads with corresponding listeners",
                      types: [
                        "Windows Shell Reverse TCP",
                        "Windows Meterpreter Reverse TCP",
                        "Windows Meterpreter Reverse HTTPS",
                        "Windows Meterpreter Reverse DNS",
                        "SE Toolkit HTTP Reverse Payload",
                      ],
                    },
                    powershell: {
                      description:
                        "PowerShell-based payloads for Windows targets",
                      types: [
                        "Alphanumeric Shellcode Injector",
                        "Reverse Shell",
                        "Bind Shell",
                        "SAM Database Dump",
                      ],
                    },
                  },
                  note: "All payloads integrate with Metasploit Framework for handling connections.",
                },
                null,
                2
              ),
            },
          ],
        };
      }

      case "set_config_info": {
        const setPath = findSetPath();
        let configInfo: Record<string, unknown> = {
          set_path: setPath,
          config_file: setPath ? path.join(setPath, "config", "set_config") : null,
        };

        if (setPath) {
          const configPath = path.join(setPath, "config", "set_config");
          if (fs.existsSync(configPath)) {
            try {
              const configContent = fs.readFileSync(configPath, "utf-8");
              const configLines = configContent
                .split("\n")
                .filter(
                  (line) => line.trim() && !line.startsWith("#")
                );
              const settings: Record<string, string> = {};
              for (const line of configLines) {
                const [key, value] = line.split("=").map((s) => s.trim());
                if (key && value) {
                  settings[key] = value;
                }
              }
              configInfo = { ...configInfo, settings };
            } catch {
              configInfo.config_error = "Could not read config file";
            }
          }
        }

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(configInfo, null, 2),
            },
          ],
        };
      }

      case "set_run_command": {
        const installed = isSetInstalled();
        if (!installed) {
          return {
            content: [
              {
                type: "text",
                text: JSON.stringify(
                  {
                    error: "SET is not installed",
                    message: "Please install SET before running commands",
                  },
                  null,
                  2
                ),
              },
            ],
          };
        }

        const menuSequence = (args as { menu_sequence: string }).menu_sequence;
        const timeoutSeconds =
          (args as { timeout_seconds?: number }).timeout_seconds || 30;

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  note: "Direct SET execution requires interactive terminal",
                  manual_command: `echo -e "${menuSequence}" | sudo setoolkit`,
                  timeout: timeoutSeconds,
                  warning:
                    "SET commands must be run with sudo privileges. Ensure you have authorization.",
                },
                null,
                2
              ),
            },
          ],
        };
      }

      case "set_clone_website": {
        const targetUrl = (args as { target_url: string }).target_url;
        const listenerIp =
          (args as { listener_ip?: string }).listener_ip || "0.0.0.0";

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  attack: "Website Credential Harvester",
                  target_url: targetUrl,
                  listener_ip: listenerIp,
                  manual_steps: [
                    "1. Run: sudo setoolkit",
                    "2. Select: 1 (Social-Engineering Attacks)",
                    "3. Select: 2 (Website Attack Vectors)",
                    "4. Select: 3 (Credential Harvester Attack Method)",
                    "5. Select: 2 (Site Cloner)",
                    `6. Enter IP for POST back: ${listenerIp}`,
                    `7. Enter URL to clone: ${targetUrl}`,
                    "8. Wait for victims to enter credentials",
                    "9. Credentials will be logged to the terminal",
                  ],
                  output_location: "/var/www/html (default Apache root)",
                  log_location:
                    "~/.set/reports/harvester_*.txt",
                  warning:
                    "Only use for authorized penetration testing. Credential harvesting without authorization is illegal.",
                },
                null,
                2
              ),
            },
          ],
        };
      }

      case "set_generate_phishing_template": {
        const templateType = (args as { template_type: string }).template_type;
        const targetCompany =
          (args as { target_company?: string }).target_company || "[Company Name]";
        const senderName =
          (args as { sender_name?: string }).sender_name || "[Sender Name]";

        const template = PHISHING_TEMPLATES[templateType];
        if (!template) {
          return {
            content: [
              {
                type: "text",
                text: JSON.stringify(
                  {
                    error: "Unknown template type",
                    available_types: Object.keys(PHISHING_TEMPLATES),
                  },
                  null,
                  2
                ),
              },
            ],
          };
        }

        const customizedBody = template.body
          .replace(/{company}/g, targetCompany)
          .replace(/{sender_name}/g, senderName)
          .replace(/{target_name}/g, "[Target Name]")
          .replace(/{link}/g, "[PHISHING_URL]")
          .replace(/{invoice_number}/g, Math.floor(Math.random() * 900000 + 100000).toString());

        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  template_type: templateType,
                  subject: template.subject.replace(
                    /{invoice_number}/g,
                    Math.floor(Math.random() * 900000 + 100000).toString()
                  ),
                  body: customizedBody,
                  placeholders: {
                    "[Target Name]": "Replace with target's name",
                    "[PHISHING_URL]": "Replace with credential harvester URL",
                  },
                  warning:
                    "These templates are for authorized security awareness training and penetration testing only.",
                },
                null,
                2
              ),
            },
          ],
        };
      }

      case "set_powershell_attack_info": {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(
                {
                  attack_name: "PowerShell Attack Vectors",
                  description:
                    "PowerShell-based attacks for Windows systems",
                  vectors: {
                    alphanumeric_shellcode: {
                      description:
                        "Inject shellcode using PowerShell with alphanumeric encoding",
                      use_case: "Bypass basic input filters",
                    },
                    reverse_shell: {
                      description:
                        "Establish reverse PowerShell connection to attacker",
                      use_case: "Remote command execution",
                    },
                    bind_shell: {
                      description:
                        "Open listening port on target for attacker connection",
                      use_case: "When outbound connections are blocked",
                    },
                    sam_dump: {
                      description:
                        "Extract SAM database for offline password cracking",
                      use_case: "Credential extraction from compromised system",
                    },
                  },
                  menu_path: "1 (Social-Engineering Attacks) -> 9 (PowerShell Attack Vectors)",
                  note: "Requires Windows target with PowerShell enabled",
                  warning:
                    "Only use for authorized penetration testing with explicit written permission.",
                },
                null,
                2
              ),
            },
          ],
        };
      }

      default:
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify({ error: `Unknown tool: ${name}` }, null, 2),
            },
          ],
        };
    }
  } catch (error) {
    return {
      content: [
        {
          type: "text",
          text: JSON.stringify(
            {
              error: "Tool execution failed",
              message: error instanceof Error ? error.message : String(error),
            },
            null,
            2
          ),
        },
      ],
    };
  }
});

// Start the server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("Social Engineer Toolkit MCP server running on stdio");
}

main().catch((error) => {
  console.error("Fatal error:", error);
  process.exit(1);
});
