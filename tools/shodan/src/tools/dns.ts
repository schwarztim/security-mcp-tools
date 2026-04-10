import { z } from "zod";
import { shodanRequest } from "../client.js";
import { formatResponse } from "../response.js";

const readOnlyAnnotations = {
  readOnlyHint: true,
  destructiveHint: false,
  openWorldHint: true,
};

export const dnsTools = [
  {
    name: "shodan_dns_resolve",
    description: "Resolve hostnames to IP addresses (forward DNS lookup).",
    parameters: z.object({
      hostnames: z
        .string()
        .describe(
          "Comma-separated hostnames (e.g., 'google.com,facebook.com')",
        ),
    }),
    annotations: readOnlyAnnotations,
    execute: async (args: { hostnames: string }) => {
      const result = await shodanRequest("/dns/resolve", {
        hostnames: args.hostnames,
      });
      return formatResponse(result);
    },
  },
  {
    name: "shodan_dns_reverse",
    description: "Look up hostnames for IP addresses (reverse DNS lookup).",
    parameters: z.object({
      ips: z.string().describe("Comma-separated IP addresses"),
    }),
    annotations: readOnlyAnnotations,
    execute: async (args: { ips: string }) => {
      const result = await shodanRequest("/dns/reverse", { ips: args.ips });
      return formatResponse(result);
    },
  },
  {
    name: "shodan_dns_domain",
    description:
      "Get DNS information for a domain including subdomains. Consumes 1 query credit.",
    parameters: z.object({
      domain: z.string().describe("Domain name (e.g., 'google.com')"),
      history: z.boolean().optional().describe("Include historical DNS data"),
      type: z
        .string()
        .optional()
        .describe("Filter by DNS record type (A, AAAA, CNAME, NS, etc.)"),
      page: z.number().int().positive().optional().describe("Page number"),
      maxResults: z
        .number()
        .int()
        .min(1)
        .max(100)
        .optional()
        .describe("Max records to return (default: 20)"),
    }),
    annotations: readOnlyAnnotations,
    execute: async (args: {
      domain: string;
      history?: boolean;
      type?: string;
      page?: number;
      maxResults?: number;
    }) => {
      const result = await shodanRequest(`/dns/domain/${args.domain}`, {
        history: args.history,
        type: args.type,
        page: args.page,
      });
      return formatResponse(result, {
        maxResults: args.maxResults ?? 20,
        summaryFields: ["subdomain", "type", "value"],
        detailed: true,
        label: "DNS records",
      });
    },
  },
];
