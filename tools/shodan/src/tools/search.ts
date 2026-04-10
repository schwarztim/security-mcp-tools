import { z } from "zod";
import { shodanRequest } from "../client.js";
import { formatResponse, formatHost } from "../response.js";

const readOnlyAnnotations = {
  readOnlyHint: true,
  destructiveHint: false,
  openWorldHint: true,
};

export const searchTools = [
  {
    name: "shodan_search",
    description:
      "Search Shodan for devices matching a query. Uses filters like 'port:', 'country:', 'org:', 'product:', 'os:', 'vuln:'. Returns formatted host summaries.",
    parameters: z.object({
      query: z
        .string()
        .describe(
          "Shodan search query (e.g., 'apache country:US', 'port:22 org:google')",
        ),
      page: z
        .number()
        .int()
        .positive()
        .optional()
        .describe("Page number (default: 1)"),
      facets: z
        .string()
        .optional()
        .describe("Comma-separated facets (e.g., 'country,port,org')"),
      minify: z.boolean().optional().describe("Return minimal host info"),
      maxResults: z
        .number()
        .int()
        .min(1)
        .max(100)
        .optional()
        .describe("Max results to return (default: 10)"),
      detailed: z
        .boolean()
        .optional()
        .describe("Return full host objects instead of summaries"),
    }),
    annotations: readOnlyAnnotations,
    execute: async (args: {
      query: string;
      page?: number;
      facets?: string;
      minify?: boolean;
      maxResults?: number;
      detailed?: boolean;
    }) => {
      const result = await shodanRequest("/shodan/host/search", {
        query: args.query,
        page: args.page,
        facets: args.facets,
        minify: args.minify,
      });
      return formatResponse(result, {
        maxResults: args.maxResults ?? 10,
        summaryFields: [
          "ip_str",
          "port",
          "org",
          "product",
          "os",
          "hostnames",
          "vulns",
        ],
        detailed: args.detailed ?? false,
        label: "hosts",
      });
    },
  },
  {
    name: "shodan_host",
    description:
      "Get all information about a specific IP including open ports, services, banners, vulnerabilities, and SSL certificates.",
    parameters: z.object({
      ip: z.string().describe("IP address to look up (e.g., '8.8.8.8')"),
      history: z.boolean().optional().describe("Include historical banners"),
      minify: z.boolean().optional().describe("Return only basic host info"),
      maxResults: z
        .number()
        .int()
        .min(1)
        .max(100)
        .optional()
        .describe("Max services to show (default: 15)"),
      detailed: z.boolean().optional().describe("Return full service objects"),
    }),
    annotations: readOnlyAnnotations,
    execute: async (args: {
      ip: string;
      history?: boolean;
      minify?: boolean;
      maxResults?: number;
      detailed?: boolean;
    }) => {
      const result = await shodanRequest(`/shodan/host/${args.ip}`, {
        history: args.history,
        minify: args.minify,
      });
      return formatHost(result, args.maxResults ?? 15, args.detailed ?? false);
    },
  },
  {
    name: "shodan_count",
    description:
      "Count search results without consuming query credits. Useful for scoping searches.",
    parameters: z.object({
      query: z.string().describe("Shodan search query"),
      facets: z
        .string()
        .optional()
        .describe("Comma-separated facets (e.g., 'country:10,port:5')"),
    }),
    annotations: readOnlyAnnotations,
    execute: async (args: { query: string; facets?: string }) => {
      const result = await shodanRequest("/shodan/host/count", {
        query: args.query,
        facets: args.facets,
      });
      return formatResponse(result, { label: "results" });
    },
  },
];
