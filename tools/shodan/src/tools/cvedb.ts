import { z } from "zod";
import { cvedbRequest } from "../client.js";
import { formatResponse } from "../response.js";

const readOnlyAnnotations = {
  readOnlyHint: true,
  destructiveHint: false,
  openWorldHint: true,
};

export const cvedbTools = [
  {
    name: "shodan_cve_lookup",
    description:
      "Look up a specific CVE by ID. Returns CVSS, EPSS, references, and affected products.",
    parameters: z.object({
      cve_id: z.string().describe("CVE identifier (e.g., 'CVE-2021-44228')"),
    }),
    annotations: readOnlyAnnotations,
    execute: async (args: { cve_id: string }) => {
      const result = await cvedbRequest(`/cve/${args.cve_id}`);
      return formatResponse(result);
    },
  },
  {
    name: "shodan_cve_search",
    description:
      "Search CVEs by CPE, product name, KEV status, or EPSS score. Cannot specify both cpe23 and product.",
    parameters: z
      .object({
        cpe23: z.string().optional().describe("CPE 2.3 string to filter by"),
        product: z.string().optional().describe("Product name to search"),
        is_kev: z
          .boolean()
          .optional()
          .describe("Filter to CISA KEV entries only"),
        sort_by_epss: z
          .boolean()
          .optional()
          .describe("Sort results by EPSS score"),
        start_date: z
          .string()
          .optional()
          .describe("Start date filter (YYYY-MM-DD)"),
        end_date: z
          .string()
          .optional()
          .describe("End date filter (YYYY-MM-DD)"),
        skip: z
          .number()
          .int()
          .min(0)
          .optional()
          .describe("Number of results to skip"),
        limit: z
          .number()
          .int()
          .min(1)
          .max(100)
          .optional()
          .describe("Max results (default: 10)"),
        maxResults: z
          .number()
          .int()
          .min(1)
          .max(100)
          .optional()
          .describe("Max results to display"),
        detailed: z.boolean().optional().describe("Return full CVE objects"),
      })
      .refine((d) => !(d.cpe23 && d.product), {
        message: "Cannot specify both cpe23 and product",
      }),
    annotations: readOnlyAnnotations,
    execute: async (args: {
      cpe23?: string;
      product?: string;
      is_kev?: boolean;
      sort_by_epss?: boolean;
      start_date?: string;
      end_date?: string;
      skip?: number;
      limit?: number;
      maxResults?: number;
      detailed?: boolean;
    }) => {
      const params: Record<string, unknown> = {};
      if (args.cpe23) params.cpe23 = args.cpe23;
      if (args.product) params.product = args.product;
      if (args.is_kev !== undefined) params.is_kev = args.is_kev;
      if (args.sort_by_epss !== undefined)
        params.sort_by_epss = args.sort_by_epss;
      if (args.start_date) params.start_date = args.start_date;
      if (args.end_date) params.end_date = args.end_date;
      if (args.skip !== undefined) params.skip = args.skip;
      if (args.limit !== undefined) params.limit = args.limit;

      const result = await cvedbRequest("/cves", params);
      return formatResponse(result, {
        maxResults: args.maxResults ?? 10,
        summaryFields: ["cve_id", "summary", "cvss", "epss", "published"],
        detailed: args.detailed ?? false,
        label: "CVEs",
      });
    },
  },
  {
    name: "shodan_cpe_lookup",
    description: "Look up CPE 2.3 identifiers matching a product name.",
    parameters: z.object({
      product: z.string().describe("Product name to search"),
      count: z.boolean().optional().describe("Return only the count"),
      skip: z
        .number()
        .int()
        .min(0)
        .optional()
        .describe("Number of results to skip"),
      limit: z
        .number()
        .int()
        .min(1)
        .max(1000)
        .optional()
        .describe("Max results"),
    }),
    annotations: readOnlyAnnotations,
    execute: async (args: {
      product: string;
      count?: boolean;
      skip?: number;
      limit?: number;
    }) => {
      const params: Record<string, unknown> = { product: args.product };
      if (args.count !== undefined) params.count = args.count;
      if (args.skip !== undefined) params.skip = args.skip;
      if (args.limit !== undefined) params.limit = args.limit;

      const result = await cvedbRequest("/cpes", params);
      return formatResponse(result, { label: "CPEs" });
    },
  },
  {
    name: "shodan_cves_newest",
    description: "Get the most recently published CVEs.",
    parameters: z.object({
      limit: z
        .number()
        .int()
        .min(1)
        .max(100)
        .optional()
        .describe("Number of CVEs to return (default: 10)"),
    }),
    annotations: readOnlyAnnotations,
    execute: async (args: { limit?: number }) => {
      const params: Record<string, unknown> = {};
      if (args.limit !== undefined) params.limit = args.limit;

      const result = await cvedbRequest("/cves/latest", params);
      return formatResponse(result, {
        maxResults: args.limit ?? 10,
        summaryFields: ["cve_id", "summary", "cvss", "epss", "published"],
        detailed: false,
        label: "CVEs",
      });
    },
  },
  {
    name: "shodan_cves_kev",
    description:
      "Get CISA Known Exploited Vulnerabilities (KEV) catalog entries.",
    parameters: z.object({
      skip: z
        .number()
        .int()
        .min(0)
        .optional()
        .describe("Number of results to skip"),
      limit: z
        .number()
        .int()
        .min(1)
        .max(100)
        .optional()
        .describe("Max results"),
      maxResults: z
        .number()
        .int()
        .min(1)
        .max(100)
        .optional()
        .describe("Max results to display"),
    }),
    annotations: readOnlyAnnotations,
    execute: async (args: {
      skip?: number;
      limit?: number;
      maxResults?: number;
    }) => {
      const params: Record<string, unknown> = {};
      if (args.skip !== undefined) params.skip = args.skip;
      if (args.limit !== undefined) params.limit = args.limit;

      const result = await cvedbRequest("/cves/kev", params);
      return formatResponse(result, {
        maxResults: args.maxResults ?? 10,
        summaryFields: ["cve_id", "summary", "cvss", "epss", "published"],
        detailed: false,
        label: "KEV entries",
      });
    },
  },
  {
    name: "shodan_cves_by_epss",
    description:
      "Get CVEs ranked by EPSS (Exploit Prediction Scoring System) score.",
    parameters: z.object({
      min_epss: z
        .number()
        .min(0)
        .max(1)
        .optional()
        .describe("Minimum EPSS score (0-1)"),
      order: z.enum(["asc", "desc"]).optional().describe("Sort order"),
      skip: z
        .number()
        .int()
        .min(0)
        .optional()
        .describe("Number of results to skip"),
      limit: z
        .number()
        .int()
        .min(1)
        .max(100)
        .optional()
        .describe("Max results"),
      maxResults: z
        .number()
        .int()
        .min(1)
        .max(100)
        .optional()
        .describe("Max results to display"),
    }),
    annotations: readOnlyAnnotations,
    execute: async (args: {
      min_epss?: number;
      order?: string;
      skip?: number;
      limit?: number;
      maxResults?: number;
    }) => {
      const params: Record<string, unknown> = {};
      if (args.min_epss !== undefined) params.min_epss = args.min_epss;
      if (args.order) params.order = args.order;
      if (args.skip !== undefined) params.skip = args.skip;
      if (args.limit !== undefined) params.limit = args.limit;

      const result = await cvedbRequest("/cves/epss", params);
      return formatResponse(result, {
        maxResults: args.maxResults ?? 10,
        summaryFields: ["cve_id", "summary", "cvss", "epss", "published"],
        detailed: false,
        label: "CVEs",
      });
    },
  },
];
