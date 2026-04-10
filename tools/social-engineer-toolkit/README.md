# Social Engineer Toolkit MCP Server

A Model Context Protocol (MCP) server that provides programmatic access to the [Social Engineering Toolkit (SET)](https://github.com/trustedsec/social-engineer-toolkit) for authorized security testing and penetration testing automation.

## Important Security Notice

**This tool is intended for authorized security professionals only.** The Social Engineering Toolkit and this MCP server should only be used:

- With explicit written authorization from the target organization
- In controlled lab environments for security research
- For security awareness training with proper consent
- During authorized penetration tests and red team engagements

Unauthorized use of social engineering tools is illegal and unethical.

## Features

- **Attack Vector Information**: Get detailed information about SET's attack capabilities
- **Phishing Templates**: Generate customizable phishing email templates for security awareness training
- **Website Cloning**: Instructions for credential harvesting setup
- **PowerShell Attacks**: Information on PowerShell-based attack vectors
- **Configuration Access**: Read and understand SET configuration
- **Status Checking**: Verify SET installation and version

## Prerequisites

- Node.js 18 or higher
- [Social Engineering Toolkit](https://github.com/trustedsec/social-engineer-toolkit) installed on the system
- Kali Linux (recommended) or any Linux distribution with SET installed

### Installing SET

**On Kali Linux:**
```bash
sudo apt update
sudo apt install set
```

**Manual Installation:**
```bash
git clone https://github.com/trustedsec/social-engineer-toolkit.git
cd social-engineer-toolkit
sudo python setup.py install
```

## Installation

```bash
# Clone the repository
git clone https://github.com/schwarztim/sec-social-engineer-toolkit-mcp.git
cd sec-social-engineer-toolkit-mcp

# Install dependencies
npm install

# Build the project
npm run build
```

## Usage

### Running the Server

```bash
npm start
```

### Claude Desktop Configuration

Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "social-engineer-toolkit": {
      "command": "node",
      "args": ["/path/to/sec-social-engineer-toolkit-mcp/dist/index.js"]
    }
  }
}
```

## Available Tools

### `set_status`
Check if SET is installed and get version information.

### `set_list_attacks`
List all available attack vectors in SET including:
- Spear-Phishing Attack Vectors
- Website Attack Vectors
- Infectious Media Generator
- Payload and Listener Creation
- Mass Mailer Attack
- Arduino-Based Attacks
- Wireless Access Point Attacks
- QR Code Generator
- PowerShell Attack Vectors
- SMS Spoofing

### `set_spear_phishing_info`
Get detailed information about spear-phishing capabilities.

### `set_website_attack_info`
Get information about website attack vectors including credential harvesting, tabnabbing, and HTA attacks.

### `set_payload_info`
Get information about available payloads for various attack scenarios.

### `set_config_info`
Read SET configuration settings.

### `set_clone_website`
Get step-by-step instructions for cloning a website for credential harvesting.

**Parameters:**
- `target_url` (required): URL of the website to clone
- `listener_ip` (optional): IP address for the credential harvester

### `set_generate_phishing_template`
Generate customizable phishing email templates.

**Parameters:**
- `template_type` (required): One of `password_reset`, `invoice`, `delivery`, `it_support`, `hr_notice`
- `target_company` (optional): Company name for customization
- `sender_name` (optional): Sender name for the template

### `set_powershell_attack_info`
Get information about PowerShell-based attack vectors.

### `set_run_command`
Get the command to run SET with specific menu options.

**Parameters:**
- `menu_sequence` (required): Newline-separated menu options
- `timeout_seconds` (optional): Command timeout (default: 30)

## Example Usage

### Check SET Status
```
Tool: set_status
Result: Shows installation status, path, and version
```

### Generate a Phishing Template
```
Tool: set_generate_phishing_template
Parameters:
  template_type: "password_reset"
  target_company: "Acme Corp"
  sender_name: "IT Security Team"
```

### Get Website Cloning Instructions
```
Tool: set_clone_website
Parameters:
  target_url: "https://example-login.com"
  listener_ip: "192.168.1.100"
```

## Environment Variables

- `SET_PATH`: Custom path to SET installation (optional)

## Legal Disclaimer

This software is provided for educational and authorized security testing purposes only. The authors and contributors are not responsible for any misuse or damage caused by this program. Users must ensure they have proper authorization before using any features of this tool.

By using this software, you agree to:
1. Only use it on systems you own or have explicit permission to test
2. Comply with all applicable local, state, and federal laws
3. Take full responsibility for your actions

## Contributing

Contributions are welcome! Please ensure any pull requests maintain the security-focused nature of this tool and include appropriate warnings.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- [TrustedSec](https://www.trustedsec.com/) for creating and maintaining SET
- The Model Context Protocol team for the MCP SDK
