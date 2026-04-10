/**
 * Maltego MCP Type Definitions
 */

// Standard Maltego entity types
export const MALTEGO_ENTITY_TYPES = {
  // Infrastructure
  Domain: "maltego.Domain",
  DNSName: "maltego.DNSName",
  IPv4Address: "maltego.IPv4Address",
  IPv6Address: "maltego.IPv6Address",
  Netblock: "maltego.Netblock",
  AS: "maltego.AS",
  Website: "maltego.Website",
  URL: "maltego.URL",
  Port: "maltego.Port",
  Service: "maltego.Service",
  Banner: "maltego.Banner",
  MXRecord: "maltego.MXRecord",
  NSRecord: "maltego.NSRecord",

  // Personal
  Person: "maltego.Person",
  EmailAddress: "maltego.EmailAddress",
  PhoneNumber: "maltego.PhoneNumber",
  Alias: "maltego.Alias",
  Image: "maltego.Image",
  Document: "maltego.Document",
  Location: "maltego.Location",

  // Social
  FacebookObject: "maltego.FacebookObject",
  TwitterAffiliation: "maltego.TwitterAffiliation",
  Affiliation: "maltego.Affiliation",

  // Organization
  Company: "maltego.Company",
  Organization: "maltego.Organization",

  // Hash/Files
  Hash: "maltego.Hash",
  File: "maltego.File",

  // Generic
  Phrase: "maltego.Phrase",
  Sentiment: "maltego.Sentiment",
} as const;

export type MaltegoEntityType = typeof MALTEGO_ENTITY_TYPES[keyof typeof MALTEGO_ENTITY_TYPES];

export interface MaltegoEntity {
  type: string;
  value: string;
  weight?: number;
  properties?: Record<string, string>;
  displayInformation?: string;
  notes?: string;
  bookmark?: "none" | "red" | "blue" | "green" | "purple" | "yellow";
  iconUrl?: string;
  link?: MaltegoLink;
}

export interface MaltegoLink {
  color?: string;
  style?: "normal" | "dashed" | "dotted";
  thickness?: number;
  label?: string;
  properties?: Record<string, string>;
}

export interface MaltegoTransformRequest {
  transformName: string;
  entityType: string;
  entityValue: string;
  entityProperties?: Record<string, string>;
  transformSettings?: Record<string, string>;
  softLimit?: number;
  hardLimit?: number;
}

export interface MaltegoTransformResponse {
  success: boolean;
  entities: MaltegoEntity[];
  messages: MaltegoUIMessage[];
  exception?: string;
}

export interface MaltegoUIMessage {
  type: "Inform" | "Warn" | "Error" | "Debug";
  message: string;
}

export interface MaltegoTransform {
  name: string;
  displayName: string;
  description: string;
  inputEntityType: string;
  outputEntityTypes: string[];
  author?: string;
  category?: string;
  requiresApiKey?: boolean;
  settings?: MaltegoTransformSetting[];
}

export interface MaltegoTransformSetting {
  name: string;
  displayName: string;
  type: "string" | "boolean" | "number";
  defaultValue?: string;
  required?: boolean;
  popup?: boolean;
}

export interface MaltegoGraph {
  entities: MaltegoEntity[];
  links: MaltegoGraphLink[];
  metadata?: Record<string, any>;
}

export interface MaltegoGraphLink {
  source: string;
  target: string;
  label?: string;
  color?: string;
  style?: string;
  thickness?: number;
  properties?: Record<string, string>;
}

export interface MaltegoMachine {
  name: string;
  displayName: string;
  description: string;
  author?: string;
  category?: string;
  transforms: string[];
}

export interface MaltegoConfig {
  tdsUrl: string;
  transformServerUrl: string;
  apiKey: string;
  graphExportPath: string;
}

export interface MaltegoTdsStatus {
  connected: boolean;
  version?: string;
  transforms?: number;
  seeds?: string[];
  lastChecked: string;
  error?: string;
}

export interface MaltegoImportMapping {
  entityType: string;
  valueField: string;
  propertyMappings?: Record<string, string>;
}

export interface MaltegoImportResult {
  success: boolean;
  entitiesCreated: number;
  linksCreated: number;
  errors: string[];
  entities: MaltegoEntity[];
}

export interface MaltegoExportResult {
  success: boolean;
  format: string;
  data: string;
  filepath?: string;
  entityCount: number;
  linkCount: number;
}

export interface MaltegoValidationResult {
  valid: boolean;
  normalizedValue?: string;
  entityType: string;
  errors: string[];
  suggestions?: string[];
}

export interface MaltegoSearchQuery {
  query: string;
  entityTypes?: string[];
  properties?: Record<string, string>;
  limit?: number;
}

export interface MaltegoSearchResult {
  entities: MaltegoEntity[];
  total: number;
  query: string;
}

export interface MaltegoMachineRequest {
  machineName: string;
  entityType: string;
  entityValue: string;
  depth?: number;
  timeout?: number;
}

export interface MaltegoMachineResult {
  success: boolean;
  machineName: string;
  seedEntity: MaltegoEntity;
  graph: MaltegoGraph;
  transformsRun: string[];
  duration: number;
  errors: string[];
}
