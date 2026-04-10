#!/usr/bin/env node
/**
 * John the Ripper MCP Server
 *
 * Provides tools for password cracking via John the Ripper on a remote Kali machine.
 * Uses SSH to execute commands on the Kali host.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
  Tool,
} from '@modelcontextprotocol/sdk/types.js';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

// Configuration
const SSH_HOST = process.env.JOHN_SSH_HOST || 'kali';
const SSH_USER = process.env.JOHN_SSH_USER || '';
const SSH_OPTIONS = '-o StrictHostKeyChecking=no -o ConnectTimeout=10';
const JOHN_PATH = process.env.JOHN_PATH || 'john';
const REMOTE_WORK_DIR = process.env.JOHN_WORK_DIR || '/tmp/john-mcp';

// Build SSH command prefix
function sshPrefix(): string {
  const userPart = SSH_USER ? `${SSH_USER}@` : '';
  return `ssh ${SSH_OPTIONS} ${userPart}${SSH_HOST}`;
}

// Execute command on remote Kali machine
async function sshExec(command: string, timeout: number = 30000): Promise<{ stdout: string; stderr: string }> {
  const escapedCommand = command.replace(/'/g, "'\\''");
  const fullCommand = `${sshPrefix()} '${escapedCommand}'`;

  try {
    const result = await execAsync(fullCommand, { timeout });
    return { stdout: result.stdout, stderr: result.stderr };
  } catch (error: any) {
    if (error.killed) {
      throw new Error(`Command timed out after ${timeout}ms`);
    }
    // Return stderr output even on non-zero exit
    return {
      stdout: error.stdout || '',
      stderr: error.stderr || error.message
    };
  }
}

// Define tools
const tools: Tool[] = [
  {
    name: 'john_crack',
    description: 'Start password cracking with John the Ripper. Supports various modes including wordlist, incremental, and single crack.',
    inputSchema: {
      type: 'object',
      properties: {
        hash_file: {
          type: 'string',
          description: 'Path to the file containing password hashes (on remote Kali system)'
        },
        hash_content: {
          type: 'string',
          description: 'Hash content to crack (will be written to a temp file). Use this OR hash_file, not both.'
        },
        format: {
          type: 'string',
          description: 'Hash format (e.g., raw-md5, raw-sha256, bcrypt, ntlm, descrypt). Use john_formats to list available formats.'
        },
        wordlist: {
          type: 'string',
          description: 'Path to wordlist file for dictionary attack (e.g., /usr/share/wordlists/rockyou.txt)'
        },
        rules: {
          type: 'string',
          description: 'Rule set to apply (e.g., Single, Wordlist, Extra, Jumbo, KoreLogic)'
        },
        incremental: {
          type: 'string',
          description: 'Incremental mode name (e.g., ASCII, Alnum, Alpha, Digits, Lower, Upper)'
        },
        session: {
          type: 'string',
          description: 'Session name for this cracking job (allows restore/status)'
        },
        fork: {
          type: 'number',
          description: 'Number of parallel processes to use'
        },
        max_run_time: {
          type: 'number',
          description: 'Maximum run time in seconds'
        }
      },
      required: []
    }
  },
  {
    name: 'john_show',
    description: 'Show cracked passwords from a hash file or pot file',
    inputSchema: {
      type: 'object',
      properties: {
        hash_file: {
          type: 'string',
          description: 'Path to the hash file to show cracked passwords for'
        },
        hash_content: {
          type: 'string',
          description: 'Hash content (will be written to temp file). Use this OR hash_file.'
        },
        format: {
          type: 'string',
          description: 'Hash format to use'
        },
        show_left: {
          type: 'boolean',
          description: 'Show uncracked (left) passwords instead of cracked ones'
        }
      },
      required: []
    }
  },
  {
    name: 'john_status',
    description: 'Check the status of a cracking session',
    inputSchema: {
      type: 'object',
      properties: {
        session: {
          type: 'string',
          description: 'Session name to check status for (default: default session)'
        }
      },
      required: []
    }
  },
  {
    name: 'john_restore',
    description: 'Restore and continue an interrupted cracking session',
    inputSchema: {
      type: 'object',
      properties: {
        session: {
          type: 'string',
          description: 'Session name to restore'
        }
      },
      required: []
    }
  },
  {
    name: 'john_formats',
    description: 'List all supported hash formats. Can filter by keyword.',
    inputSchema: {
      type: 'object',
      properties: {
        filter: {
          type: 'string',
          description: 'Filter formats by keyword (e.g., "md5", "sha", "bcrypt")'
        },
        details: {
          type: 'boolean',
          description: 'Show detailed format information'
        }
      },
      required: []
    }
  },
  {
    name: 'john_identify',
    description: 'Identify the hash type(s) for given hash values',
    inputSchema: {
      type: 'object',
      properties: {
        hash: {
          type: 'string',
          description: 'Hash string to identify'
        },
        hash_file: {
          type: 'string',
          description: 'Path to file containing hashes to identify'
        }
      },
      required: []
    }
  },
  {
    name: 'john_rules',
    description: 'List available mangling rules or test rules against words',
    inputSchema: {
      type: 'object',
      properties: {
        list: {
          type: 'boolean',
          description: 'List available rule sections'
        },
        test_rules: {
          type: 'string',
          description: 'Rule section to test (e.g., Single, Wordlist, Extra)'
        },
        test_words: {
          type: 'array',
          items: { type: 'string' },
          description: 'Words to test the rules against'
        }
      },
      required: []
    }
  },
  {
    name: 'john_benchmark',
    description: 'Run benchmarks to test cracking speed for different hash types',
    inputSchema: {
      type: 'object',
      properties: {
        format: {
          type: 'string',
          description: 'Specific format to benchmark (optional, benchmarks all if not specified)'
        },
        duration: {
          type: 'number',
          description: 'Benchmark duration in seconds per format'
        }
      },
      required: []
    }
  },
  {
    name: 'john_pot',
    description: 'Manage the john.pot file containing cracked passwords',
    inputSchema: {
      type: 'object',
      properties: {
        action: {
          type: 'string',
          enum: ['show', 'clear', 'export'],
          description: 'Action to perform: show (list contents), clear (empty pot), export (output all)'
        },
        search: {
          type: 'string',
          description: 'Search for specific hash or password in pot file'
        }
      },
      required: ['action']
    }
  },
  {
    name: 'john_hash_extract',
    description: 'Extract hashes from various file types using John\'s *2john utilities',
    inputSchema: {
      type: 'object',
      properties: {
        type: {
          type: 'string',
          enum: ['zip', 'rar', 'pdf', 'ssh', 'gpg', 'office', 'keepass', '7z', 'bitlocker', 'luks', 'truecrypt', 'veracrypt', 'ethereum', 'bitcoin'],
          description: 'Type of file to extract hashes from'
        },
        file_path: {
          type: 'string',
          description: 'Path to the file on the remote Kali system'
        }
      },
      required: ['type', 'file_path']
    }
  },
  {
    name: 'john_sessions',
    description: 'List all active and saved John the Ripper sessions',
    inputSchema: {
      type: 'object',
      properties: {},
      required: []
    }
  },
  {
    name: 'john_kill',
    description: 'Kill a running John the Ripper process or session',
    inputSchema: {
      type: 'object',
      properties: {
        session: {
          type: 'string',
          description: 'Session name to kill'
        },
        all: {
          type: 'boolean',
          description: 'Kill all John processes'
        }
      },
      required: []
    }
  }
];

// Tool handlers
async function handleJohnCrack(args: any): Promise<string> {
  let hashFile = args.hash_file;

  // If hash content provided, write to temp file
  if (args.hash_content && !args.hash_file) {
    const tempFile = `${REMOTE_WORK_DIR}/hash_${Date.now()}.txt`;
    await sshExec(`mkdir -p ${REMOTE_WORK_DIR} && echo '${args.hash_content.replace(/'/g, "'\\''")}' > ${tempFile}`);
    hashFile = tempFile;
  }

  if (!hashFile) {
    return 'Error: Either hash_file or hash_content must be provided';
  }

  const cmdParts: string[] = [JOHN_PATH];

  if (args.format) cmdParts.push(`--format=${args.format}`);
  if (args.wordlist) cmdParts.push(`--wordlist=${args.wordlist}`);
  if (args.rules) cmdParts.push(`--rules=${args.rules}`);
  if (args.incremental) cmdParts.push(`--incremental=${args.incremental}`);
  if (args.session) cmdParts.push(`--session=${args.session}`);
  if (args.fork) cmdParts.push(`--fork=${args.fork}`);
  if (args.max_run_time) cmdParts.push(`--max-run-time=${args.max_run_time}`);

  cmdParts.push(hashFile);

  const result = await sshExec(cmdParts.join(' '), args.max_run_time ? (args.max_run_time + 10) * 1000 : 300000);
  return formatResult(result);
}

async function handleJohnShow(args: any): Promise<string> {
  let hashFile = args.hash_file;

  if (args.hash_content && !args.hash_file) {
    const tempFile = `${REMOTE_WORK_DIR}/hash_${Date.now()}.txt`;
    await sshExec(`mkdir -p ${REMOTE_WORK_DIR} && echo '${args.hash_content.replace(/'/g, "'\\''")}' > ${tempFile}`);
    hashFile = tempFile;
  }

  if (!hashFile) {
    return 'Error: Either hash_file or hash_content must be provided';
  }

  const cmdParts: string[] = [JOHN_PATH, '--show'];

  if (args.format) cmdParts.push(`--format=${args.format}`);
  if (args.show_left) cmdParts.push('--left');

  cmdParts.push(hashFile);

  const result = await sshExec(cmdParts.join(' '));
  return formatResult(result);
}

async function handleJohnStatus(args: any): Promise<string> {
  const cmdParts: string[] = [JOHN_PATH, '--status'];

  if (args.session) cmdParts.push(`--session=${args.session}`);

  const result = await sshExec(cmdParts.join(' '));
  return formatResult(result);
}

async function handleJohnRestore(args: any): Promise<string> {
  const cmdParts: string[] = [JOHN_PATH, '--restore'];

  if (args.session) cmdParts.push(`=${args.session}`);

  const result = await sshExec(cmdParts.join(' '), 60000);
  return formatResult(result);
}

async function handleJohnFormats(args: any): Promise<string> {
  let cmd: string;

  if (args.details) {
    cmd = `${JOHN_PATH} --list=format-all-details`;
  } else {
    cmd = `${JOHN_PATH} --list=formats`;
  }

  const result = await sshExec(cmd);
  let output = formatResult(result);

  if (args.filter && output) {
    const lines = output.split('\n');
    const filtered = lines.filter(line =>
      line.toLowerCase().includes(args.filter.toLowerCase())
    );
    output = filtered.join('\n') || `No formats matching '${args.filter}' found`;
  }

  return output;
}

async function handleJohnIdentify(args: any): Promise<string> {
  let hashFile: string | undefined;

  if (args.hash) {
    const tempFile = `${REMOTE_WORK_DIR}/identify_${Date.now()}.txt`;
    await sshExec(`mkdir -p ${REMOTE_WORK_DIR} && echo '${args.hash.replace(/'/g, "'\\''")}' > ${tempFile}`);
    hashFile = tempFile;
  } else if (args.hash_file) {
    hashFile = args.hash_file;
  }

  if (!hashFile) {
    return 'Error: Either hash or hash_file must be provided';
  }

  // Use John's built-in format detection by trying to load without specifying format
  const result = await sshExec(`${JOHN_PATH} --show --format=auto ${hashFile} 2>&1; ${JOHN_PATH} ${hashFile} --test 2>&1 | head -20`);

  // Also try to detect via first line output
  const detectResult = await sshExec(`${JOHN_PATH} ${hashFile} 2>&1 | head -5`);

  return `Hash Identification Results:\n${formatResult(result)}\n\nDetection Output:\n${formatResult(detectResult)}`;
}

async function handleJohnRules(args: any): Promise<string> {
  if (args.list) {
    const result = await sshExec(`${JOHN_PATH} --list=rules`);
    return formatResult(result);
  }

  if (args.test_rules && args.test_words) {
    const words = args.test_words.join('\n');
    const tempFile = `${REMOTE_WORK_DIR}/words_${Date.now()}.txt`;
    await sshExec(`mkdir -p ${REMOTE_WORK_DIR} && echo '${words}' > ${tempFile}`);

    const result = await sshExec(`${JOHN_PATH} --wordlist=${tempFile} --rules=${args.test_rules} --stdout | head -100`);
    return `Rules test output (first 100 results):\n${formatResult(result)}`;
  }

  return 'Usage: Provide either list=true to list rules, or test_rules with test_words to test';
}

async function handleJohnBenchmark(args: any): Promise<string> {
  const cmdParts: string[] = [JOHN_PATH, '--test'];

  if (args.format) cmdParts.push(`--format=${args.format}`);
  if (args.duration) cmdParts.push(`=${args.duration}`);

  const timeout = args.duration ? (args.duration * 10 + 60) * 1000 : 120000;
  const result = await sshExec(cmdParts.join(' '), timeout);
  return formatResult(result);
}

async function handleJohnPot(args: any): Promise<string> {
  switch (args.action) {
    case 'show':
    case 'export': {
      const cmd = args.search
        ? `grep -i '${args.search}' ~/.john/john.pot 2>/dev/null || echo 'No matches found'`
        : `cat ~/.john/john.pot 2>/dev/null || echo 'Pot file is empty or does not exist'`;
      const result = await sshExec(cmd);
      return formatResult(result);
    }
    case 'clear': {
      const result = await sshExec('echo "" > ~/.john/john.pot && echo "Pot file cleared"');
      return formatResult(result);
    }
    default:
      return 'Invalid action. Use: show, clear, or export';
  }
}

async function handleJohnHashExtract(args: any): Promise<string> {
  const extractorMap: Record<string, string> = {
    'zip': 'zip2john',
    'rar': 'rar2john',
    'pdf': 'pdf2john',
    'ssh': 'ssh2john',
    'gpg': 'gpg2john',
    'office': 'office2john',
    'keepass': 'keepass2john',
    '7z': '7z2john',
    'bitlocker': 'bitlocker2john',
    'luks': 'luks2john',
    'truecrypt': 'truecrypt2john',
    'veracrypt': 'veracrypt2john',
    'ethereum': 'ethereum2john',
    'bitcoin': 'bitcoin2john'
  };

  const extractor = extractorMap[args.type];
  if (!extractor) {
    return `Unknown extractor type: ${args.type}. Available: ${Object.keys(extractorMap).join(', ')}`;
  }

  // Try multiple paths for the extractor
  const paths = [
    `/usr/share/john/${extractor}.py`,
    `/usr/share/john/${extractor}`,
    `/usr/bin/${extractor}`,
    extractor
  ];

  for (const path of paths) {
    const checkResult = await sshExec(`which ${path} 2>/dev/null || test -f ${path} && echo "found"`);
    if (checkResult.stdout.includes('found') || checkResult.stdout.trim()) {
      const isScript = path.endsWith('.py');
      const cmd = isScript ? `python3 ${path} "${args.file_path}"` : `${path} "${args.file_path}"`;
      const result = await sshExec(cmd);
      return formatResult(result);
    }
  }

  return `Extractor ${extractor} not found. It may need to be installed or the path configured.`;
}

async function handleJohnSessions(args: any): Promise<string> {
  const result = await sshExec(`ls -la ~/.john/*.rec 2>/dev/null || echo 'No active sessions found'; ps aux | grep john | grep -v grep || echo 'No running John processes'`);
  return formatResult(result);
}

async function handleJohnKill(args: any): Promise<string> {
  if (args.all) {
    const result = await sshExec('pkill -9 john && echo "All John processes killed" || echo "No John processes found"');
    return formatResult(result);
  }

  if (args.session) {
    const result = await sshExec(`pkill -9 -f "session=${args.session}" && echo "Session ${args.session} killed" || echo "Session not found or not running"`);
    return formatResult(result);
  }

  return 'Usage: Provide session name or set all=true to kill all John processes';
}

function formatResult(result: { stdout: string; stderr: string }): string {
  let output = '';
  if (result.stdout.trim()) {
    output += result.stdout.trim();
  }
  if (result.stderr.trim()) {
    output += (output ? '\n\n' : '') + 'Stderr:\n' + result.stderr.trim();
  }
  return output || 'No output';
}

// Create and run server
const server = new Server(
  {
    name: 'john-the-ripper-mcp',
    version: '1.0.0',
  },
  {
    capabilities: {
      tools: {},
    },
  }
);

// Register tool handlers
server.setRequestHandler(ListToolsRequestSchema, async () => {
  return { tools };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const { name, arguments: args } = request.params;

  try {
    let result: string;

    switch (name) {
      case 'john_crack':
        result = await handleJohnCrack(args || {});
        break;
      case 'john_show':
        result = await handleJohnShow(args || {});
        break;
      case 'john_status':
        result = await handleJohnStatus(args || {});
        break;
      case 'john_restore':
        result = await handleJohnRestore(args || {});
        break;
      case 'john_formats':
        result = await handleJohnFormats(args || {});
        break;
      case 'john_identify':
        result = await handleJohnIdentify(args || {});
        break;
      case 'john_rules':
        result = await handleJohnRules(args || {});
        break;
      case 'john_benchmark':
        result = await handleJohnBenchmark(args || {});
        break;
      case 'john_pot':
        result = await handleJohnPot(args || {});
        break;
      case 'john_hash_extract':
        result = await handleJohnHashExtract(args || {});
        break;
      case 'john_sessions':
        result = await handleJohnSessions(args || {});
        break;
      case 'john_kill':
        result = await handleJohnKill(args || {});
        break;
      default:
        result = `Unknown tool: ${name}`;
    }

    return {
      content: [{ type: 'text', text: result }],
    };
  } catch (error: any) {
    return {
      content: [{ type: 'text', text: `Error: ${error.message}` }],
      isError: true,
    };
  }
});

// Start server
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error('John the Ripper MCP server running on stdio');
}

main().catch((error) => {
  console.error('Fatal error:', error);
  process.exit(1);
});
