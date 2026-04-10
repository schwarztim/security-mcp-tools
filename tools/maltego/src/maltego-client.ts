/**
 * Maltego Client
 *
 * Handles communication with Maltego TDS (Transform Distribution Server)
 * and local Transform servers using the Maltego XML protocol.
 */

import axios, { AxiosInstance } from "axios";
import { parseStringPromise, Builder } from "xml2js";
import * as fs from "fs/promises";
import * as path from "path";
import {
  MaltegoConfig,
  MaltegoEntity,
  MaltegoTransform,
  MaltegoTransformRequest,
  MaltegoTransformResponse,
  MaltegoTdsStatus,
  MaltegoGraph,
  MaltegoGraphLink,
  MaltegoImportMapping,
  MaltegoImportResult,
  MaltegoExportResult,
  MaltegoValidationResult,
  MaltegoSearchQuery,
  MaltegoSearchResult,
  MaltegoMachineRequest,
  MaltegoMachineResult,
  MaltegoUIMessage,
  MaltegoTransformSetting,
  MALTEGO_ENTITY_TYPES,
} from "./types.js";

// Built-in standard transforms (available without TDS)
const STANDARD_TRANSFORMS: MaltegoTransform[] = [
  {
    name: "DNSToIP",
    displayName: "DNS to IP Address",
    description: "Resolve DNS name to IP address(es)",
    inputEntityType: "maltego.DNSName",
    outputEntityTypes: ["maltego.IPv4Address", "maltego.IPv6Address"],
    category: "DNS"
  },
  {
    name: "IPToDNS",
    displayName: "IP to DNS Name",
    description: "Reverse DNS lookup",
    inputEntityType: "maltego.IPv4Address",
    outputEntityTypes: ["maltego.DNSName"],
    category: "DNS"
  },
  {
    name: "DomainToMXRecords",
    displayName: "Domain to MX Records",
    description: "Get mail exchange records for domain",
    inputEntityType: "maltego.Domain",
    outputEntityTypes: ["maltego.MXRecord"],
    category: "DNS"
  },
  {
    name: "DomainToNSRecords",
    displayName: "Domain to NS Records",
    description: "Get name server records for domain",
    inputEntityType: "maltego.Domain",
    outputEntityTypes: ["maltego.NSRecord"],
    category: "DNS"
  },
  {
    name: "DomainToWebsite",
    displayName: "Domain to Website",
    description: "Find websites on domain",
    inputEntityType: "maltego.Domain",
    outputEntityTypes: ["maltego.Website"],
    category: "Infrastructure"
  },
  {
    name: "EmailToAlias",
    displayName: "Email to Alias",
    description: "Extract alias from email address",
    inputEntityType: "maltego.EmailAddress",
    outputEntityTypes: ["maltego.Alias"],
    category: "Personal"
  },
  {
    name: "EmailToDomain",
    displayName: "Email to Domain",
    description: "Extract domain from email address",
    inputEntityType: "maltego.EmailAddress",
    outputEntityTypes: ["maltego.Domain"],
    category: "Personal"
  },
  {
    name: "PersonToEmail",
    displayName: "Person to Email",
    description: "Find email addresses for person",
    inputEntityType: "maltego.Person",
    outputEntityTypes: ["maltego.EmailAddress"],
    category: "Personal"
  },
  {
    name: "PersonToPhoneNumber",
    displayName: "Person to Phone Number",
    description: "Find phone numbers for person",
    inputEntityType: "maltego.Person",
    outputEntityTypes: ["maltego.PhoneNumber"],
    category: "Personal"
  },
  {
    name: "CompanyToDomain",
    displayName: "Company to Domain",
    description: "Find domains associated with company",
    inputEntityType: "maltego.Company",
    outputEntityTypes: ["maltego.Domain"],
    category: "Organization"
  },
  {
    name: "DomainToCompany",
    displayName: "Domain to Company",
    description: "Identify company from domain WHOIS",
    inputEntityType: "maltego.Domain",
    outputEntityTypes: ["maltego.Company"],
    category: "Organization"
  },
  {
    name: "IPToNetblock",
    displayName: "IP to Netblock",
    description: "Find netblock containing IP address",
    inputEntityType: "maltego.IPv4Address",
    outputEntityTypes: ["maltego.Netblock"],
    category: "Infrastructure"
  },
  {
    name: "IPToAS",
    displayName: "IP to Autonomous System",
    description: "Find AS number for IP address",
    inputEntityType: "maltego.IPv4Address",
    outputEntityTypes: ["maltego.AS"],
    category: "Infrastructure"
  },
  {
    name: "URLToWebsite",
    displayName: "URL to Website",
    description: "Extract website from URL",
    inputEntityType: "maltego.URL",
    outputEntityTypes: ["maltego.Website"],
    category: "Infrastructure"
  },
  {
    name: "WebsiteToDomain",
    displayName: "Website to Domain",
    description: "Extract domain from website",
    inputEntityType: "maltego.Website",
    outputEntityTypes: ["maltego.Domain"],
    category: "Infrastructure"
  }
];

// Built-in machines
const STANDARD_MACHINES = [
  {
    name: "CompanyFootprint",
    displayName: "Company Footprint",
    description: "Full reconnaissance on a company - domains, IPs, emails, infrastructure",
    transforms: ["CompanyToDomain", "DomainToMXRecords", "DomainToNSRecords", "DomainToWebsite", "DNSToIP"]
  },
  {
    name: "PersonalFootprint",
    displayName: "Personal Footprint",
    description: "Find online presence for a person - emails, aliases, social accounts",
    transforms: ["PersonToEmail", "PersonToPhoneNumber", "EmailToAlias", "EmailToDomain"]
  },
  {
    name: "DomainRecon",
    displayName: "Domain Reconnaissance",
    description: "Full domain enumeration - DNS, websites, IPs, infrastructure",
    transforms: ["DomainToMXRecords", "DomainToNSRecords", "DomainToWebsite", "DNSToIP", "IPToNetblock", "IPToAS"]
  },
  {
    name: "InfrastructureRecon",
    displayName: "Infrastructure Reconnaissance",
    description: "Map network infrastructure from IP",
    transforms: ["IPToDNS", "IPToNetblock", "IPToAS"]
  },
  {
    name: "EmailRecon",
    displayName: "Email Reconnaissance",
    description: "Extract information from email address",
    transforms: ["EmailToAlias", "EmailToDomain", "DomainToMXRecords"]
  }
];

// Entity validation patterns
const ENTITY_VALIDATORS: Record<string, RegExp> = {
  "maltego.Domain": /^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/,
  "maltego.IPv4Address": /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/,
  "maltego.IPv6Address": /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}$|^(?:[0-9a-fA-F]{1,4}:){1,6}:$|^(?:[0-9a-fA-F]{1,4}:){1,7}:$/,
  "maltego.EmailAddress": /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  "maltego.PhoneNumber": /^\+?[0-9\s\-\(\)]{7,20}$/,
  "maltego.URL": /^https?:\/\/.+/i,
  "maltego.Hash": /^[a-fA-F0-9]{32,128}$/,
};

export class MaltegoClient {
  private config: MaltegoConfig;
  private http: AxiosInstance;
  private transforms: MaltegoTransform[] = [...STANDARD_TRANSFORMS];
  private entityStore: MaltegoEntity[] = [];

  constructor(config: MaltegoConfig) {
    this.config = config;
    this.http = axios.create({
      timeout: 30000,
      headers: {
        "Content-Type": "application/xml",
        ...(config.apiKey && { "Authorization": `Bearer ${config.apiKey}` }),
      },
    });
  }

  /**
   * List available transforms
   */
  async listTransforms(
    category?: string,
    inputEntityType?: string
  ): Promise<{ transforms: MaltegoTransform[]; total: number }> {
    // Try to fetch from TDS, fall back to built-in transforms
    let transforms = [...this.transforms];

    try {
      const response = await this.http.get(`${this.config.tdsUrl}/transforms`);
      if (response.data) {
        const parsed = await parseStringPromise(response.data);
        if (parsed?.transforms?.transform) {
          const tdsTransforms = parsed.transforms.transform.map((t: any) => ({
            name: t.name?.[0] || t.$.name,
            displayName: t.displayName?.[0] || t.name?.[0],
            description: t.description?.[0] || "",
            inputEntityType: t.inputEntityType?.[0] || "",
            outputEntityTypes: t.outputEntityTypes?.[0]?.split(",") || [],
            category: t.category?.[0] || "Other",
          }));
          transforms = [...transforms, ...tdsTransforms];
        }
      }
    } catch (error) {
      // TDS not available, use built-in transforms only
    }

    // Apply filters
    if (category) {
      transforms = transforms.filter(t =>
        t.category?.toLowerCase() === category.toLowerCase()
      );
    }
    if (inputEntityType) {
      transforms = transforms.filter(t =>
        t.inputEntityType === inputEntityType
      );
    }

    return {
      transforms,
      total: transforms.length,
    };
  }

  /**
   * Execute a transform
   */
  async runTransform(request: MaltegoTransformRequest): Promise<MaltegoTransformResponse> {
    const transform = this.transforms.find(t => t.name === request.transformName);

    // Build Maltego XML request
    const xmlBuilder = new Builder();
    const xmlRequest = {
      MaltegoMessage: {
        MaltegoTransformRequestMessage: {
          Entities: {
            Entity: {
              $: { Type: request.entityType },
              Value: request.entityValue,
              Weight: 100,
              AdditionalFields: request.entityProperties ? {
                Field: Object.entries(request.entityProperties).map(([name, value]) => ({
                  $: { Name: name },
                  _: value
                }))
              } : undefined
            }
          },
          TransformFields: request.transformSettings ? {
            Field: Object.entries(request.transformSettings).map(([name, value]) => ({
              $: { Name: name },
              _: value
            }))
          } : undefined,
          Limits: {
            $: {
              SoftLimit: request.softLimit || 12,
              HardLimit: request.hardLimit || 10000
            }
          }
        }
      }
    };

    try {
      // Try remote transform server
      const xmlBody = xmlBuilder.buildObject(xmlRequest);
      const response = await this.http.post(
        `${this.config.transformServerUrl}/run/${request.transformName}`,
        xmlBody
      );

      const parsed = await parseStringPromise(response.data);
      return this.parseTransformResponse(parsed);
    } catch (error) {
      // Fall back to local simulation for standard transforms
      if (transform) {
        return this.simulateTransform(request, transform);
      }

      throw new Error(`Transform '${request.transformName}' not available and TDS connection failed`);
    }
  }

  /**
   * Simulate a standard transform locally
   */
  private simulateTransform(
    request: MaltegoTransformRequest,
    transform: MaltegoTransform
  ): MaltegoTransformResponse {
    const entities: MaltegoEntity[] = [];
    const messages: MaltegoUIMessage[] = [];

    // Basic local simulation based on transform type
    switch (request.transformName) {
      case "EmailToDomain": {
        const parts = request.entityValue.split("@");
        if (parts.length === 2) {
          entities.push({
            type: "maltego.Domain",
            value: parts[1],
            weight: 100,
          });
        }
        break;
      }

      case "EmailToAlias": {
        const parts = request.entityValue.split("@");
        if (parts.length === 2) {
          entities.push({
            type: "maltego.Alias",
            value: parts[0],
            weight: 100,
          });
        }
        break;
      }

      case "URLToWebsite": {
        try {
          const url = new URL(request.entityValue);
          entities.push({
            type: "maltego.Website",
            value: url.origin,
            weight: 100,
          });
        } catch {}
        break;
      }

      case "WebsiteToDomain": {
        try {
          const url = new URL(request.entityValue.startsWith("http") ? request.entityValue : `https://${request.entityValue}`);
          entities.push({
            type: "maltego.Domain",
            value: url.hostname,
            weight: 100,
          });
        } catch {}
        break;
      }

      default:
        messages.push({
          type: "Inform",
          message: `Transform '${request.transformName}' simulated locally. Connect to TDS for full functionality.`
        });
    }

    return {
      success: true,
      entities,
      messages,
    };
  }

  /**
   * Parse Maltego XML response
   */
  private parseTransformResponse(parsed: any): MaltegoTransformResponse {
    const entities: MaltegoEntity[] = [];
    const messages: MaltegoUIMessage[] = [];

    try {
      const response = parsed?.MaltegoMessage?.MaltegoTransformResponseMessage;

      if (response?.Entities?.Entity) {
        const entityList = Array.isArray(response.Entities.Entity)
          ? response.Entities.Entity
          : [response.Entities.Entity];

        for (const e of entityList) {
          entities.push({
            type: e.$.Type,
            value: e.Value?.[0] || "",
            weight: parseInt(e.Weight?.[0] || "100"),
            properties: this.parseEntityProperties(e.AdditionalFields),
          });
        }
      }

      if (response?.UIMessages?.UIMessage) {
        const msgList = Array.isArray(response.UIMessages.UIMessage)
          ? response.UIMessages.UIMessage
          : [response.UIMessages.UIMessage];

        for (const m of msgList) {
          messages.push({
            type: m.$.MessageType || "Inform",
            message: m._ || m,
          });
        }
      }

      return {
        success: true,
        entities,
        messages,
      };
    } catch (error) {
      return {
        success: false,
        entities: [],
        messages: [],
        exception: error instanceof Error ? error.message : String(error),
      };
    }
  }

  /**
   * Parse entity additional fields
   */
  private parseEntityProperties(fields: any): Record<string, string> | undefined {
    if (!fields?.Field) return undefined;

    const fieldList = Array.isArray(fields.Field) ? fields.Field : [fields.Field];
    const props: Record<string, string> = {};

    for (const f of fieldList) {
      const name = f.$.Name || f.$.name;
      const value = f._ || f;
      if (name) props[name] = value;
    }

    return Object.keys(props).length > 0 ? props : undefined;
  }

  /**
   * List available entity types
   */
  async listEntities(category?: string, search?: string): Promise<{ entities: any[]; total: number }> {
    const allEntities = Object.entries(MALTEGO_ENTITY_TYPES).map(([name, type]) => ({
      name,
      type,
      category: this.categorizeEntity(type),
      description: this.getEntityDescription(type),
    }));

    let filtered = allEntities;

    if (category) {
      filtered = filtered.filter(e =>
        e.category.toLowerCase() === category.toLowerCase()
      );
    }

    if (search) {
      const searchLower = search.toLowerCase();
      filtered = filtered.filter(e =>
        e.name.toLowerCase().includes(searchLower) ||
        e.type.toLowerCase().includes(searchLower) ||
        e.description.toLowerCase().includes(searchLower)
      );
    }

    return {
      entities: filtered,
      total: filtered.length,
    };
  }

  /**
   * Categorize entity by type
   */
  private categorizeEntity(type: string): string {
    if (type.includes("IPv") || type.includes("Domain") || type.includes("DNS") ||
        type.includes("Website") || type.includes("URL") || type.includes("Port") ||
        type.includes("Netblock") || type.includes("AS") || type.includes("Service")) {
      return "Infrastructure";
    }
    if (type.includes("Person") || type.includes("Email") || type.includes("Phone") ||
        type.includes("Alias") || type.includes("Image") || type.includes("Document") ||
        type.includes("Location")) {
      return "Personal";
    }
    if (type.includes("Facebook") || type.includes("Twitter") || type.includes("Affiliation")) {
      return "Social";
    }
    if (type.includes("Company") || type.includes("Organization")) {
      return "Organization";
    }
    if (type.includes("Hash") || type.includes("File")) {
      return "Files";
    }
    return "Other";
  }

  /**
   * Get entity description
   */
  private getEntityDescription(type: string): string {
    const descriptions: Record<string, string> = {
      "maltego.Domain": "Internet domain name (e.g., example.com)",
      "maltego.DNSName": "DNS hostname (e.g., www.example.com)",
      "maltego.IPv4Address": "IPv4 network address (e.g., 192.168.1.1)",
      "maltego.IPv6Address": "IPv6 network address",
      "maltego.Netblock": "Network address block (CIDR notation)",
      "maltego.AS": "Autonomous System number",
      "maltego.Website": "Website URL (e.g., https://example.com)",
      "maltego.URL": "Full URL with path",
      "maltego.Port": "Network port number",
      "maltego.Service": "Network service (e.g., HTTP, SSH)",
      "maltego.MXRecord": "Mail exchange DNS record",
      "maltego.NSRecord": "Name server DNS record",
      "maltego.Person": "Person's name",
      "maltego.EmailAddress": "Email address",
      "maltego.PhoneNumber": "Telephone number",
      "maltego.Alias": "Username or alias",
      "maltego.Image": "Image file or URL",
      "maltego.Document": "Document file",
      "maltego.Location": "Geographic location",
      "maltego.Company": "Company or business name",
      "maltego.Organization": "Organization name",
      "maltego.Hash": "File hash (MD5, SHA1, SHA256)",
      "maltego.File": "File name or path",
      "maltego.Phrase": "Generic text phrase",
    };
    return descriptions[type] || "Maltego entity";
  }

  /**
   * Create a new entity
   */
  async createEntity(params: {
    type: string;
    value: string;
    properties?: Record<string, string>;
    weight?: number;
    notes?: string;
    bookmark?: string;
  }): Promise<MaltegoEntity> {
    const entity: MaltegoEntity = {
      type: params.type,
      value: params.value,
      weight: params.weight || 100,
      properties: params.properties,
      notes: params.notes,
      bookmark: params.bookmark as any,
    };

    this.entityStore.push(entity);
    return entity;
  }

  /**
   * Export graph data
   */
  async exportGraph(params: {
    entities: MaltegoEntity[];
    links?: MaltegoGraphLink[];
    format: string;
    filename?: string;
  }): Promise<MaltegoExportResult> {
    const graph: MaltegoGraph = {
      entities: params.entities,
      links: params.links || [],
    };

    let data: string;

    switch (params.format) {
      case "graphml":
        data = this.toGraphML(graph);
        break;
      case "csv":
        data = this.toCSV(graph);
        break;
      case "mtgx":
        data = this.toMTGX(graph);
        break;
      case "json":
      default:
        data = JSON.stringify(graph, null, 2);
    }

    let filepath: string | undefined;
    if (params.filename) {
      const ext = params.format === "json" ? "json" : params.format;
      filepath = path.join(this.config.graphExportPath, `${params.filename}.${ext}`);
      await fs.mkdir(this.config.graphExportPath, { recursive: true });
      await fs.writeFile(filepath, data);
    }

    return {
      success: true,
      format: params.format,
      data,
      filepath,
      entityCount: params.entities.length,
      linkCount: params.links?.length || 0,
    };
  }

  /**
   * Convert graph to GraphML format
   */
  private toGraphML(graph: MaltegoGraph): string {
    const nodes = graph.entities.map((e, i) =>
      `    <node id="n${i}">
      <data key="type">${this.escapeXml(e.type)}</data>
      <data key="value">${this.escapeXml(e.value)}</data>
      <data key="weight">${e.weight || 100}</data>
    </node>`
    ).join("\n");

    const edges = graph.links.map((l, i) =>
      `    <edge id="e${i}" source="${l.source}" target="${l.target}">
      <data key="label">${this.escapeXml(l.label || "")}</data>
    </edge>`
    ).join("\n");

    return `<?xml version="1.0" encoding="UTF-8"?>
<graphml xmlns="http://graphml.graphdrawing.org/xmlns">
  <key id="type" for="node" attr.name="type" attr.type="string"/>
  <key id="value" for="node" attr.name="value" attr.type="string"/>
  <key id="weight" for="node" attr.name="weight" attr.type="int"/>
  <key id="label" for="edge" attr.name="label" attr.type="string"/>
  <graph id="G" edgedefault="directed">
${nodes}
${edges}
  </graph>
</graphml>`;
  }

  /**
   * Convert graph to CSV format
   */
  private toCSV(graph: MaltegoGraph): string {
    const header = "Type,Value,Weight,Properties\n";
    const rows = graph.entities.map(e =>
      `"${e.type}","${e.value}",${e.weight || 100},"${JSON.stringify(e.properties || {})}"`
    ).join("\n");
    return header + rows;
  }

  /**
   * Convert graph to Maltego MTGX format (simplified)
   */
  private toMTGX(graph: MaltegoGraph): string {
    const builder = new Builder();
    return builder.buildObject({
      MaltegoGraph: {
        $: { version: "1.0" },
        Entities: {
          Entity: graph.entities.map(e => ({
            $: { Type: e.type },
            Value: e.value,
            Weight: e.weight || 100,
          }))
        },
        Links: {
          Link: graph.links.map(l => ({
            $: { Label: l.label || "" },
            Source: l.source,
            Target: l.target,
          }))
        }
      }
    });
  }

  /**
   * Escape XML special characters
   */
  private escapeXml(str: string): string {
    return str
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&apos;");
  }

  /**
   * Import data and convert to entities
   */
  async importData(params: {
    data: any[];
    mapping: MaltegoImportMapping;
    createLinks?: boolean;
  }): Promise<MaltegoImportResult> {
    const entities: MaltegoEntity[] = [];
    const errors: string[] = [];
    let linksCreated = 0;

    for (let i = 0; i < params.data.length; i++) {
      const record = params.data[i];

      try {
        const value = record[params.mapping.valueField];
        if (!value) {
          errors.push(`Row ${i}: Missing value field '${params.mapping.valueField}'`);
          continue;
        }

        const properties: Record<string, string> = {};
        if (params.mapping.propertyMappings) {
          for (const [entityProp, dataProp] of Object.entries(params.mapping.propertyMappings)) {
            if (record[dataProp]) {
              properties[entityProp] = String(record[dataProp]);
            }
          }
        }

        entities.push({
          type: params.mapping.entityType,
          value: String(value),
          weight: 100,
          properties: Object.keys(properties).length > 0 ? properties : undefined,
        });
      } catch (error) {
        errors.push(`Row ${i}: ${error instanceof Error ? error.message : String(error)}`);
      }
    }

    // Store entities
    this.entityStore.push(...entities);

    return {
      success: errors.length === 0,
      entitiesCreated: entities.length,
      linksCreated,
      errors,
      entities,
    };
  }

  /**
   * Run a machine (transform sequence)
   */
  async runMachine(params: MaltegoMachineRequest): Promise<MaltegoMachineResult> {
    const startTime = Date.now();
    const machine = STANDARD_MACHINES.find(m => m.name === params.machineName);

    if (!machine) {
      throw new Error(`Machine '${params.machineName}' not found`);
    }

    const graph: MaltegoGraph = {
      entities: [],
      links: [],
    };

    const seedEntity: MaltegoEntity = {
      type: params.entityType,
      value: params.entityValue,
      weight: 100,
    };

    graph.entities.push(seedEntity);

    const transformsRun: string[] = [];
    const errors: string[] = [];
    const maxDepth = params.depth || 3;
    const timeout = (params.timeout || 300) * 1000;

    // BFS transform execution
    let currentEntities = [seedEntity];
    let depth = 0;

    while (depth < maxDepth && currentEntities.length > 0 && Date.now() - startTime < timeout) {
      const nextEntities: MaltegoEntity[] = [];

      for (const entity of currentEntities) {
        // Find applicable transforms from machine
        for (const transformName of machine.transforms) {
          const transform = this.transforms.find(t => t.name === transformName);
          if (!transform || transform.inputEntityType !== entity.type) continue;

          try {
            const result = await this.runTransform({
              transformName,
              entityType: entity.type,
              entityValue: entity.value,
            });

            transformsRun.push(transformName);

            for (const newEntity of result.entities) {
              // Check for duplicates
              const exists = graph.entities.some(e =>
                e.type === newEntity.type && e.value === newEntity.value
              );

              if (!exists) {
                graph.entities.push(newEntity);
                nextEntities.push(newEntity);

                // Create link
                graph.links.push({
                  source: entity.value,
                  target: newEntity.value,
                  label: transformName,
                });
              }
            }
          } catch (error) {
            errors.push(`${transformName}: ${error instanceof Error ? error.message : String(error)}`);
          }
        }
      }

      currentEntities = nextEntities;
      depth++;
    }

    return {
      success: errors.length === 0,
      machineName: params.machineName,
      seedEntity,
      graph,
      transformsRun,
      duration: Date.now() - startTime,
      errors,
    };
  }

  /**
   * Get transform settings/configuration
   */
  async getTransformSettings(transformName: string): Promise<{
    transform: MaltegoTransform | null;
    settings: MaltegoTransformSetting[];
  }> {
    const transform = this.transforms.find(t => t.name === transformName);

    // Try to get from TDS
    try {
      const response = await this.http.get(
        `${this.config.tdsUrl}/transform/${transformName}/settings`
      );

      if (response.data) {
        const parsed = await parseStringPromise(response.data);
        const settings: MaltegoTransformSetting[] = [];

        if (parsed?.settings?.setting) {
          const settingList = Array.isArray(parsed.settings.setting)
            ? parsed.settings.setting
            : [parsed.settings.setting];

          for (const s of settingList) {
            settings.push({
              name: s.name?.[0] || s.$.name,
              displayName: s.displayName?.[0] || s.name?.[0],
              type: s.type?.[0] || "string",
              defaultValue: s.defaultValue?.[0],
              required: s.required?.[0] === "true",
              popup: s.popup?.[0] === "true",
            });
          }
        }

        return { transform: transform || null, settings };
      }
    } catch (error) {
      // TDS not available
    }

    return {
      transform: transform || null,
      settings: transform?.settings || [],
    };
  }

  /**
   * Validate an entity value
   */
  async validateEntity(entityType: string, value: string): Promise<MaltegoValidationResult> {
    const errors: string[] = [];
    const suggestions: string[] = [];
    let normalizedValue = value.trim();

    // Check if entity type exists
    const typeExists = Object.values(MALTEGO_ENTITY_TYPES).includes(entityType as any);
    if (!typeExists) {
      errors.push(`Unknown entity type: ${entityType}`);
    }

    // Validate against pattern
    const pattern = ENTITY_VALIDATORS[entityType];
    if (pattern && !pattern.test(normalizedValue)) {
      errors.push(`Value does not match expected pattern for ${entityType}`);

      // Provide suggestions based on type
      if (entityType === "maltego.Domain") {
        // Try to extract domain from URL
        try {
          const url = new URL(normalizedValue.startsWith("http") ? normalizedValue : `https://${normalizedValue}`);
          suggestions.push(`Did you mean: ${url.hostname}?`);
          normalizedValue = url.hostname;
        } catch {}
      }

      if (entityType === "maltego.EmailAddress") {
        if (!normalizedValue.includes("@")) {
          suggestions.push("Email address must contain @ symbol");
        }
      }
    }

    // Normalize value
    if (entityType === "maltego.Domain" || entityType === "maltego.DNSName") {
      normalizedValue = normalizedValue.toLowerCase();
    }
    if (entityType === "maltego.EmailAddress") {
      normalizedValue = normalizedValue.toLowerCase();
    }
    if (entityType === "maltego.Hash") {
      normalizedValue = normalizedValue.toLowerCase();
    }

    return {
      valid: errors.length === 0,
      normalizedValue,
      entityType,
      errors,
      suggestions: suggestions.length > 0 ? suggestions : undefined,
    };
  }

  /**
   * Search entities in store
   */
  async searchEntities(params: MaltegoSearchQuery): Promise<MaltegoSearchResult> {
    let results = [...this.entityStore];
    const queryLower = params.query.toLowerCase();

    // Filter by query
    results = results.filter(e =>
      e.value.toLowerCase().includes(queryLower) ||
      e.type.toLowerCase().includes(queryLower)
    );

    // Filter by entity types
    if (params.entityTypes && params.entityTypes.length > 0) {
      results = results.filter(e => params.entityTypes!.includes(e.type));
    }

    // Filter by properties
    if (params.properties) {
      results = results.filter(e => {
        if (!e.properties) return false;
        for (const [key, value] of Object.entries(params.properties!)) {
          if (e.properties[key] !== value) return false;
        }
        return true;
      });
    }

    // Apply limit
    const limit = params.limit || 100;
    const total = results.length;
    results = results.slice(0, limit);

    return {
      entities: results,
      total,
      query: params.query,
    };
  }

  /**
   * Check TDS status
   */
  async getTdsStatus(): Promise<MaltegoTdsStatus> {
    const status: MaltegoTdsStatus = {
      connected: false,
      lastChecked: new Date().toISOString(),
    };

    try {
      const response = await this.http.get(`${this.config.tdsUrl}/status`, {
        timeout: 5000,
      });

      status.connected = true;

      if (response.data) {
        const parsed = await parseStringPromise(response.data);
        status.version = parsed?.status?.version?.[0];
        status.transforms = parseInt(parsed?.status?.transforms?.[0] || "0");
        status.seeds = parsed?.status?.seeds?.seed || [];
      }
    } catch (error) {
      status.error = error instanceof Error ? error.message : String(error);
    }

    // Add info about built-in transforms
    status.transforms = (status.transforms || 0) + STANDARD_TRANSFORMS.length;

    return status;
  }
}
