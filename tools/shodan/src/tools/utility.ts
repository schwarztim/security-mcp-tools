import { z } from "zod";
import { shodanRequest } from "../client.js";
import { formatResponse } from "../response.js";

const readOnlyAnnotations = {
  readOnlyHint: true,
  destructiveHint: false,
  openWorldHint: true,
};

export const utilityTools = [
  {
    name: "shodan_ports",
    description: "List all ports that Shodan crawls on the Internet.",
    parameters: z.object({}),
    annotations: readOnlyAnnotations,
    execute: async () => {
      const result = await shodanRequest("/shodan/ports");
      return formatResponse(result, { label: "ports", maxResults: 50 });
    },
  },
  {
    name: "shodan_protocols",
    description: "List all protocols available for on-demand scanning.",
    parameters: z.object({}),
    annotations: readOnlyAnnotations,
    execute: async () => {
      const result = await shodanRequest("/shodan/protocols");
      return formatResponse(result);
    },
  },
  {
    name: "shodan_filters",
    description: "List all search filters available in Shodan.",
    parameters: z.object({}),
    annotations: readOnlyAnnotations,
    execute: async () => {
      const result = await shodanRequest("/shodan/host/search/filters");
      return formatResponse(result, { label: "filters", maxResults: 50 });
    },
  },
  {
    name: "shodan_facets",
    description: "List all facets available for search result breakdowns.",
    parameters: z.object({}),
    annotations: readOnlyAnnotations,
    execute: async () => {
      const result = await shodanRequest("/shodan/host/search/facets");
      return formatResponse(result, { label: "facets", maxResults: 50 });
    },
  },
  {
    name: "shodan_api_info",
    description:
      "Get API plan info including query credits, scan credits, and limits.",
    parameters: z.object({}),
    annotations: readOnlyAnnotations,
    execute: async () => {
      const result = await shodanRequest("/api-info");
      return formatResponse(result);
    },
  },
  {
    name: "shodan_account_profile",
    description: "Get account information associated with the API key.",
    parameters: z.object({}),
    annotations: readOnlyAnnotations,
    execute: async () => {
      const result = await shodanRequest("/account/profile");
      return formatResponse(result);
    },
  },
  {
    name: "shodan_myip",
    description: "Get your current public IP address as seen by Shodan.",
    parameters: z.object({}),
    annotations: readOnlyAnnotations,
    execute: async () => {
      const result = await shodanRequest("/tools/myip");
      return formatResponse(result);
    },
  },
  {
    name: "shodan_honeyscore",
    description:
      "Calculate the probability that an IP is a honeypot. Returns 0.0 (not a honeypot) to 1.0 (honeypot).",
    parameters: z.object({
      ip: z.string().describe("IP address to check"),
    }),
    annotations: readOnlyAnnotations,
    execute: async (args: { ip: string }) => {
      const result = await shodanRequest(`/labs/honeyscore/${args.ip}`);
      return formatResponse(result);
    },
  },
  {
    name: "shodan_saved_queries",
    description: "Browse the directory of saved search queries.",
    parameters: z.object({
      page: z
        .number()
        .int()
        .positive()
        .optional()
        .describe("Page number (10 results per page)"),
      sort: z
        .string()
        .optional()
        .describe("Sort order: 'votes' or 'timestamp'"),
      order: z.string().optional().describe("Sort direction: 'asc' or 'desc'"),
    }),
    annotations: readOnlyAnnotations,
    execute: async (args: { page?: number; sort?: string; order?: string }) => {
      const result = await shodanRequest("/shodan/query", {
        page: args.page,
        sort: args.sort,
        order: args.order,
      });
      return formatResponse(result, { label: "queries", maxResults: 50 });
    },
  },
  {
    name: "shodan_search_queries",
    description: "Search the directory of saved queries.",
    parameters: z.object({
      query: z.string().describe("Search term for query directory"),
      page: z.number().int().positive().optional().describe("Page number"),
    }),
    annotations: readOnlyAnnotations,
    execute: async (args: { query: string; page?: number }) => {
      const result = await shodanRequest("/shodan/query/search", {
        query: args.query,
        page: args.page,
      });
      return formatResponse(result, { label: "queries", maxResults: 50 });
    },
  },
];
