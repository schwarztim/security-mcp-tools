import axios, { AxiosInstance, AxiosError, RawAxiosRequestHeaders } from 'axios';
import { BloodHoundAuth, signRequest, validateAuth } from './auth.js';

export interface BloodHoundConfig {
  baseUrl: string;
  tokenId: string;
  tokenKey: string;
}

export interface ApiResponse<T = unknown> {
  data: T;
  count?: number;
  limit?: number;
  skip?: number;
}

export interface Domain {
  id: string;
  sid: string;
  name: string;
  type: string;
  collected: boolean;
  impactValue?: number;
}

export interface User {
  id: string;
  name: string;
  displayName?: string;
  samAccountName?: string;
  distinguishedName?: string;
  enabled?: boolean;
  adminCount?: boolean;
  hasSPN?: boolean;
  pwdLastSet?: string;
  lastLogon?: string;
  properties?: Record<string, unknown>;
}

export interface Computer {
  id: string;
  name: string;
  operatingSystem?: string;
  enabled?: boolean;
  unconstrainedDelegation?: boolean;
  distinguishedName?: string;
  properties?: Record<string, unknown>;
}

export interface Group {
  id: string;
  name: string;
  distinguishedName?: string;
  adminCount?: boolean;
  properties?: Record<string, unknown>;
}

export interface PathResult {
  nodes: unknown[];
  edges: unknown[];
  start_node?: unknown;
  end_node?: unknown;
}

export interface CypherResult {
  data: unknown[];
}

export interface SearchResult {
  id: string;
  name: string;
  type: string;
  objectId?: string;
}

export interface AttackPath {
  id: string;
  title: string;
  severity: string;
  domain_id: string;
  finding_count?: number;
}

export interface AttackPathFinding {
  id: string;
  domain_sid: string;
  principal: string;
  principal_kind: string;
  accepted_until?: string;
}

/**
 * BloodHound CE API Client
 */
export class BloodHoundClient {
  private client: AxiosInstance;
  private auth: BloodHoundAuth;
  private baseUrl: string;

  constructor(config: BloodHoundConfig) {
    this.baseUrl = config.baseUrl.replace(/\/$/, '');
    this.auth = {
      tokenId: config.tokenId,
      tokenKey: config.tokenKey
    };

    if (!validateAuth(this.auth)) {
      throw new Error('Invalid BloodHound authentication configuration');
    }

    this.client = axios.create({
      baseURL: this.baseUrl,
      timeout: 30000
    });
  }

  /**
   * Make authenticated request to BloodHound API
   */
  private async request<T>(
    method: 'GET' | 'POST' | 'PUT' | 'DELETE',
    path: string,
    data?: unknown
  ): Promise<T> {
    const uri = path.startsWith('/') ? path : `/${path}`;
    const body = data ? JSON.stringify(data) : '';
    const signedHeaders = signRequest(this.auth, method, uri, body);

    const headers: RawAxiosRequestHeaders = {
      Authorization: signedHeaders.Authorization,
      RequestDate: signedHeaders.RequestDate,
      Signature: signedHeaders.Signature,
      'Content-Type': signedHeaders['Content-Type']
    };

    try {
      const response = await this.client.request({
        method,
        url: uri,
        headers,
        data: data || undefined
      });
      return response.data as T;
    } catch (error) {
      if (error instanceof AxiosError) {
        const status = error.response?.status;
        const message = error.response?.data?.message || error.message;
        throw new Error(`BloodHound API error (${status}): ${message}`);
      }
      throw error;
    }
  }

  // ============== Domain Operations ==============

  /**
   * List all available domains
   */
  async listDomains(): Promise<ApiResponse<Domain[]>> {
    return this.request<ApiResponse<Domain[]>>('GET', '/api/v2/domains');
  }

  /**
   * Get domain details
   */
  async getDomain(domainId: string): Promise<ApiResponse<Domain>> {
    return this.request<ApiResponse<Domain>>('GET', `/api/v2/ad/domains/${domainId}`);
  }

  // ============== User Operations ==============

  /**
   * List domain users
   */
  async listUsers(domainId: string, skip = 0, limit = 100): Promise<ApiResponse<User[]>> {
    return this.request<ApiResponse<User[]>>(
      'GET',
      `/api/v2/ad/domains/${domainId}/users?skip=${skip}&limit=${limit}`
    );
  }

  /**
   * Get user details
   */
  async getUser(userId: string): Promise<ApiResponse<User>> {
    return this.request<ApiResponse<User>>('GET', `/api/v2/ad/users/${userId}`);
  }

  /**
   * Get user's admin rights
   */
  async getUserAdminRights(userId: string): Promise<ApiResponse<unknown[]>> {
    return this.request<ApiResponse<unknown[]>>('GET', `/api/v2/ad/users/${userId}/admin-rights`);
  }

  /**
   * Get user's group memberships
   */
  async getUserMemberships(userId: string): Promise<ApiResponse<unknown[]>> {
    return this.request<ApiResponse<unknown[]>>('GET', `/api/v2/ad/users/${userId}/memberships`);
  }

  /**
   * Get user's active sessions
   */
  async getUserSessions(userId: string): Promise<ApiResponse<unknown[]>> {
    return this.request<ApiResponse<unknown[]>>('GET', `/api/v2/ad/users/${userId}/sessions`);
  }

  // ============== Computer Operations ==============

  /**
   * List domain computers
   */
  async listComputers(domainId: string, skip = 0, limit = 100): Promise<ApiResponse<Computer[]>> {
    return this.request<ApiResponse<Computer[]>>(
      'GET',
      `/api/v2/ad/domains/${domainId}/computers?skip=${skip}&limit=${limit}`
    );
  }

  /**
   * Get computer details
   */
  async getComputer(computerId: string): Promise<ApiResponse<Computer>> {
    return this.request<ApiResponse<Computer>>('GET', `/api/v2/ad/computers/${computerId}`);
  }

  /**
   * Get computer's administrators
   */
  async getComputerAdmins(computerId: string): Promise<ApiResponse<unknown[]>> {
    return this.request<ApiResponse<unknown[]>>('GET', `/api/v2/ad/computers/${computerId}/admins`);
  }

  /**
   * Get computer's active sessions
   */
  async getComputerSessions(computerId: string): Promise<ApiResponse<unknown[]>> {
    return this.request<ApiResponse<unknown[]>>('GET', `/api/v2/ad/computers/${computerId}/sessions`);
  }

  // ============== Group Operations ==============

  /**
   * List domain groups
   */
  async listGroups(domainId: string, skip = 0, limit = 100): Promise<ApiResponse<Group[]>> {
    return this.request<ApiResponse<Group[]>>(
      'GET',
      `/api/v2/ad/domains/${domainId}/groups?skip=${skip}&limit=${limit}`
    );
  }

  /**
   * Get group details
   */
  async getGroup(groupId: string): Promise<ApiResponse<Group>> {
    return this.request<ApiResponse<Group>>('GET', `/api/v2/ad/groups/${groupId}`);
  }

  /**
   * Get group members
   */
  async getGroupMembers(groupId: string): Promise<ApiResponse<unknown[]>> {
    return this.request<ApiResponse<unknown[]>>('GET', `/api/v2/ad/groups/${groupId}/members`);
  }

  /**
   * Get group's admin rights
   */
  async getGroupAdminRights(groupId: string): Promise<ApiResponse<unknown[]>> {
    return this.request<ApiResponse<unknown[]>>('GET', `/api/v2/ad/groups/${groupId}/admin-rights`);
  }

  // ============== Search & Graph Operations ==============

  /**
   * Search for graph objects by name or object ID
   */
  async search(query: string, type?: string): Promise<ApiResponse<SearchResult[]>> {
    let path = `/api/v2/search?q=${encodeURIComponent(query)}`;
    if (type) {
      path += `&type=${encodeURIComponent(type)}`;
    }
    return this.request<ApiResponse<SearchResult[]>>('GET', path);
  }

  /**
   * Find shortest path between two nodes
   */
  async findShortestPath(startNode: string, endNode: string): Promise<PathResult> {
    return this.request<PathResult>(
      'GET',
      `/api/v2/graph/path?start_node=${encodeURIComponent(startNode)}&end_node=${encodeURIComponent(endNode)}`
    );
  }

  /**
   * Execute custom Cypher query
   */
  async executeCypher(query: string): Promise<CypherResult> {
    return this.request<CypherResult>('POST', '/api/v2/cypher', { query });
  }

  // ============== Attack Path Operations ==============

  /**
   * List available attack path types
   */
  async listAttackPaths(): Promise<ApiResponse<AttackPath[]>> {
    return this.request<ApiResponse<AttackPath[]>>('GET', '/api/v2/attack-paths');
  }

  /**
   * Get domain attack paths
   */
  async getDomainAttackPaths(domainId: string): Promise<ApiResponse<AttackPath[]>> {
    return this.request<ApiResponse<AttackPath[]>>('GET', `/api/v2/attack-paths/${domainId}`);
  }

  /**
   * Get attack path findings
   */
  async getAttackPathFindings(): Promise<ApiResponse<AttackPathFinding[]>> {
    return this.request<ApiResponse<AttackPathFinding[]>>('GET', '/api/v2/attack-paths/findings');
  }

  /**
   * Start attack path analysis
   */
  async startAnalysis(): Promise<{ job_id: string }> {
    return this.request<{ job_id: string }>('POST', '/api/v2/analysis/start');
  }

  // ============== Domain Entity Operations ==============

  /**
   * Get domain controllers
   */
  async getDomainControllers(domainId: string): Promise<ApiResponse<Computer[]>> {
    return this.request<ApiResponse<Computer[]>>('GET', `/api/v2/ad/domains/${domainId}/controllers`);
  }

  /**
   * Get principals with DCSync rights
   */
  async getDCSyncers(domainId: string): Promise<ApiResponse<unknown[]>> {
    return this.request<ApiResponse<unknown[]>>('GET', `/api/v2/ad/domains/${domainId}/dc-syncers`);
  }

  /**
   * Get domain trusts (inbound)
   */
  async getInboundTrusts(domainId: string): Promise<ApiResponse<unknown[]>> {
    return this.request<ApiResponse<unknown[]>>('GET', `/api/v2/ad/domains/${domainId}/inbound-trusts`);
  }

  /**
   * Get domain trusts (outbound)
   */
  async getOutboundTrusts(domainId: string): Promise<ApiResponse<unknown[]>> {
    return this.request<ApiResponse<unknown[]>>('GET', `/api/v2/ad/domains/${domainId}/outbound-trusts`);
  }

  /**
   * Get domain GPOs
   */
  async getDomainGPOs(domainId: string): Promise<ApiResponse<unknown[]>> {
    return this.request<ApiResponse<unknown[]>>('GET', `/api/v2/ad/domains/${domainId}/gpos`);
  }

  /**
   * Get domain OUs
   */
  async getDomainOUs(domainId: string): Promise<ApiResponse<unknown[]>> {
    return this.request<ApiResponse<unknown[]>>('GET', `/api/v2/ad/domains/${domainId}/ous`);
  }

  // ============== File Upload Operations ==============

  /**
   * Create file upload job
   */
  async createUploadJob(): Promise<{ job_id: string }> {
    return this.request<{ job_id: string }>('POST', '/api/v2/file-upload');
  }

  /**
   * Get accepted file types
   */
  async getUploadTypes(): Promise<ApiResponse<string[]>> {
    return this.request<ApiResponse<string[]>>('GET', '/api/v2/file-upload/types');
  }

  // ============== Data Quality ==============

  /**
   * Get domain data quality stats
   */
  async getDataQuality(domainId: string): Promise<ApiResponse<unknown>> {
    return this.request<ApiResponse<unknown>>('GET', `/api/v2/data-quality/ad/${domainId}`);
  }

  // ============== Kerberoasting & High-Value Targets ==============

  /**
   * Find Kerberoastable users (users with SPNs)
   */
  async findKerberoastableUsers(domainId: string): Promise<CypherResult> {
    const query = `MATCH (u:User {hasspn: true, domainsid: "${domainId}"}) WHERE u.enabled = true RETURN u.name AS name, u.serviceprincipalnames AS spns, u.pwdlastset AS pwdLastSet ORDER BY u.pwdlastset ASC`;
    return this.executeCypher(query);
  }

  /**
   * Find AS-REP roastable users
   */
  async findASREPRoastableUsers(domainId: string): Promise<CypherResult> {
    const query = `MATCH (u:User {dontreqpreauth: true, domainsid: "${domainId}"}) WHERE u.enabled = true RETURN u.name AS name, u.distinguishedname AS dn`;
    return this.executeCypher(query);
  }

  /**
   * Find unconstrained delegation computers
   */
  async findUnconstrainedDelegation(domainId: string): Promise<CypherResult> {
    const query = `MATCH (c:Computer {unconstraineddelegation: true, domainsid: "${domainId}"}) RETURN c.name AS name, c.operatingsystem AS os`;
    return this.executeCypher(query);
  }

  // ============== API Info ==============

  /**
   * Get API version
   */
  async getVersion(): Promise<{ version: string }> {
    return this.request<{ version: string }>('GET', '/api/v2/api/version');
  }
}
