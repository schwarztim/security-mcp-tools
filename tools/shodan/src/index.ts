#!/usr/bin/env node

import { FastMCP } from "fastmcp";
import { searchTools } from "./tools/search.js";
import { dnsTools } from "./tools/dns.js";
import { scanningTools } from "./tools/scanning.js";
import { alertTools } from "./tools/alerts.js";
import { exploitTools } from "./tools/exploits.js";
import { cvedbTools } from "./tools/cvedb.js";
import { utilityTools } from "./tools/utility.js";

const server = new FastMCP({
  name: "shodan-mcp",
  version: "2.0.0",
});

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const allTools: any[] = [
  ...searchTools,
  ...dnsTools,
  ...scanningTools,
  ...alertTools,
  ...exploitTools,
  ...cvedbTools,
  ...utilityTools,
];

for (const tool of allTools) {
  server.addTool(tool);
}

server.start({
  transportType: "stdio",
});
