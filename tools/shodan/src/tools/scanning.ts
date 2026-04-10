import { z } from "zod";
import { shodanRequest } from "../client.js";
import { formatResponse } from "../response.js";

const scanAnnotations = {
  readOnlyHint: false,
  destructiveHint: false,
  openWorldHint: true,
};

export const scanningTools = [
  {
    name: "shodan_scan",
    description:
      "Request Shodan to scan specific IPs or CIDR ranges. Each IP consumes 1 scan credit.",
    parameters: z.object({
      ips: z
        .string()
        .describe(
          "Comma-separated IPs or CIDR ranges (e.g., '8.8.8.8,1.1.1.1/24')",
        ),
    }),
    annotations: scanAnnotations,
    execute: async (args: { ips: string }) => {
      const result = await shodanRequest(
        "/shodan/scan",
        { ips: args.ips },
        "POST",
      );
      return formatResponse(result);
    },
  },
  {
    name: "shodan_scan_status",
    description: "Check the status of a previously submitted scan.",
    parameters: z.object({
      scan_id: z.string().describe("Scan ID returned from shodan_scan"),
    }),
    annotations: scanAnnotations,
    execute: async (args: { scan_id: string }) => {
      const result = await shodanRequest(`/shodan/scan/${args.scan_id}`);
      return formatResponse(result);
    },
  },
  {
    name: "shodan_list_scans",
    description: "List all active on-demand scans.",
    parameters: z.object({}),
    annotations: scanAnnotations,
    execute: async () => {
      const result = await shodanRequest("/shodan/scans");
      return formatResponse(result, { label: "scans" });
    },
  },
];
