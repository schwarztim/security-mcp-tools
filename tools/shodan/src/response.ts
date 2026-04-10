export interface FormatOptions {
  maxResults?: number;
  summaryFields?: string[];
  detailed?: boolean;
  label?: string;
}

function pick(
  obj: Record<string, unknown>,
  fields: string[],
): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const f of fields) {
    if (obj[f] !== undefined && obj[f] !== null) {
      result[f] = obj[f];
    }
  }
  return result;
}

function formatValue(val: unknown): string {
  if (val === null || val === undefined) return "";
  if (Array.isArray(val)) {
    if (val.length === 0) return "";
    return val.join(", ");
  }
  if (typeof val === "object") return JSON.stringify(val);
  return String(val);
}

function formatItem(
  item: Record<string, unknown>,
  index: number,
  fields?: string[],
): string {
  const obj = fields ? pick(item, fields) : item;
  const parts: string[] = [];
  for (const [key, val] of Object.entries(obj)) {
    const formatted = formatValue(val);
    if (formatted) {
      parts.push(`${key}: ${formatted}`);
    }
  }
  return `  ${index + 1}. ${parts.join(" — ")}`;
}

function formatFacets(
  facets: Record<string, Array<{ value: string; count: number }>>,
): string {
  const lines: string[] = ["Facets:"];
  for (const [name, values] of Object.entries(facets)) {
    if (Array.isArray(values)) {
      const items = values.map((v) => `${v.value} (${v.count})`).join(", ");
      lines.push(`  ${name}: ${items}`);
    }
  }
  return lines.join("\n");
}

export function formatResponse(
  data: unknown,
  options: FormatOptions = {},
): string {
  const {
    maxResults = 50,
    summaryFields,
    detailed = true,
    label = "results",
  } = options;

  if (data === null || data === undefined) {
    return "No data returned.";
  }

  // Primitive values
  if (typeof data !== "object") {
    return String(data);
  }

  // Direct array
  if (Array.isArray(data)) {
    return formatArray(data, maxResults, summaryFields, detailed, label);
  }

  const obj = data as Record<string, unknown>;

  // Object with matches/results array (Shodan search response shape)
  const arrayKey = ["matches", "results", "data"].find((k) =>
    Array.isArray(obj[k]),
  );

  if (arrayKey) {
    const arr = obj[arrayKey] as Record<string, unknown>[];
    const total = (obj.total as number) ?? arr.length;
    const facetsStr = obj.facets
      ? formatFacets(
          obj.facets as Record<string, Array<{ value: string; count: number }>>,
        )
      : "";

    const sliced = arr.slice(0, maxResults);
    const items = sliced.map((item, i) =>
      formatItem(item, i, detailed ? undefined : summaryFields),
    );

    const parts: string[] = [];
    parts.push(`Showing ${sliced.length} of ${total} ${label}.`);
    if (facetsStr) parts.push(facetsStr);
    parts.push(`\nResults:\n${items.join("\n")}`);

    if (sliced.length < total) {
      parts.push(`\n... ${total - sliced.length} more ${label} not shown.`);
    }

    return parts.join("\n");
  }

  // Object with a "data" array for services (host response)
  // or any other object — return as formatted JSON, but truncated
  return JSON.stringify(data, null, 2);
}

function formatArray(
  arr: unknown[],
  maxResults: number,
  summaryFields: string[] | undefined,
  detailed: boolean,
  label: string,
): string {
  const total = arr.length;
  const sliced = arr.slice(0, maxResults);

  // Simple primitive array
  if (sliced.length > 0 && typeof sliced[0] !== "object") {
    const header =
      total > sliced.length
        ? `Showing ${sliced.length} of ${total} ${label}.`
        : `${total} ${label}.`;
    return `${header}\n\n${sliced.join(", ")}`;
  }

  const items = sliced.map((item, i) =>
    formatItem(
      item as Record<string, unknown>,
      i,
      detailed ? undefined : summaryFields,
    ),
  );

  const parts: string[] = [];
  if (total > sliced.length) {
    parts.push(`Showing ${sliced.length} of ${total} ${label}.`);
  }
  parts.push(items.join("\n"));
  if (total > sliced.length) {
    parts.push(`\n... ${total - sliced.length} more ${label} not shown.`);
  }

  return parts.join("\n");
}

// Special formatter for host data with services
export function formatHost(
  data: unknown,
  maxServices: number = 15,
  detailed: boolean = false,
): string {
  if (!data || typeof data !== "object") return String(data);

  const host = data as Record<string, unknown>;
  const services = host.data as Record<string, unknown>[] | undefined;

  const header: string[] = [];
  if (host.ip_str) header.push(`IP: ${host.ip_str}`);
  if (host.org) header.push(`Org: ${host.org}`);
  if (host.os) header.push(`OS: ${host.os}`);
  if (host.country_name) header.push(`Country: ${host.country_name}`);
  if (host.city) header.push(`City: ${host.city}`);
  if (Array.isArray(host.hostnames) && host.hostnames.length > 0) {
    header.push(`Hostnames: ${(host.hostnames as string[]).join(", ")}`);
  }
  if (Array.isArray(host.vulns) && host.vulns.length > 0) {
    header.push(`Vulns: ${(host.vulns as string[]).join(", ")}`);
  }
  if (Array.isArray(host.ports)) {
    header.push(`Ports: ${(host.ports as number[]).join(", ")}`);
  }

  const parts: string[] = [header.join("\n")];

  if (services && services.length > 0) {
    const total = services.length;
    const sliced = services.slice(0, maxServices);
    const summaryFields = ["port", "transport", "product", "version", "vulns"];

    parts.push(`\nServices (${sliced.length} of ${total}):`);
    for (let i = 0; i < sliced.length; i++) {
      parts.push(
        formatItem(sliced[i], i, detailed ? undefined : summaryFields),
      );
    }
    if (total > sliced.length) {
      parts.push(`\n... ${total - sliced.length} more services not shown.`);
    }
  }

  return parts.join("\n");
}
