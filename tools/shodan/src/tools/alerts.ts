import { z } from "zod";
import { shodanRequest } from "../client.js";
import { formatResponse } from "../response.js";

const readOnlyAnnotations = {
  readOnlyHint: true,
  destructiveHint: false,
  openWorldHint: false,
};

export const alertTools = [
  {
    name: "shodan_alert_create",
    description: "Create a network alert to monitor IP ranges for changes.",
    parameters: z.object({
      name: z.string().describe("Name for the alert"),
      ip: z
        .string()
        .describe("IP range in CIDR notation (e.g., '198.20.0.0/16')"),
      expires: z.number().optional().describe("Expiration time in days"),
    }),
    annotations: {
      readOnlyHint: false,
      destructiveHint: false,
      openWorldHint: false,
    },
    execute: async (args: { name: string; ip: string; expires?: number }) => {
      const params: Record<string, unknown> = {
        name: args.name,
        "filters[ip]": args.ip,
      };
      if (args.expires) params.expires = args.expires;
      const result = await shodanRequest("/shodan/alert", params, "POST");
      return formatResponse(result);
    },
  },
  {
    name: "shodan_alert_list",
    description: "List all active network alerts.",
    parameters: z.object({}),
    annotations: readOnlyAnnotations,
    execute: async () => {
      const result = await shodanRequest("/shodan/alert/info");
      return formatResponse(result, { label: "alerts" });
    },
  },
  {
    name: "shodan_alert_get",
    description: "Get details for a specific alert.",
    parameters: z.object({
      alert_id: z.string().describe("Alert ID"),
    }),
    annotations: readOnlyAnnotations,
    execute: async (args: { alert_id: string }) => {
      const result = await shodanRequest(`/shodan/alert/${args.alert_id}/info`);
      return formatResponse(result);
    },
  },
  {
    name: "shodan_alert_delete",
    description: "Delete a network alert.",
    parameters: z.object({
      alert_id: z.string().describe("Alert ID to delete"),
    }),
    annotations: {
      readOnlyHint: false,
      destructiveHint: true,
      openWorldHint: false,
    },
    execute: async (args: { alert_id: string }) => {
      const result = await shodanRequest(
        `/shodan/alert/${args.alert_id}`,
        {},
        "DELETE",
      );
      return formatResponse(result);
    },
  },
  {
    name: "shodan_alert_triggers",
    description: "List available alert trigger types.",
    parameters: z.object({}),
    annotations: readOnlyAnnotations,
    execute: async () => {
      const result = await shodanRequest("/shodan/alert/triggers");
      return formatResponse(result, { label: "triggers" });
    },
  },
];
