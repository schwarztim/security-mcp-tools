import axios, { AxiosInstance, AxiosError } from 'axios';

/**
 * Burp Suite REST API Client
 *
 * Supports two modes:
 * 1. Burp Suite Professional built-in REST API (default port 1337)
 * 2. VMware burp-rest-api extension (default port 8090)
 */

export interface BurpConfig {
  baseUrl: string;
  apiKey?: string;
  timeout?: number;
}

export interface ScanConfig {
  baseUrl: string;
  scope?: string;
  configuration?: string;
}

export interface ScanStatus {
  scanId: string;
  status: string;
  percentComplete?: number;
  itemsScanned?: number;
  itemsTotal?: number;
  errors?: string[];
}

export interface Issue {
  name: string;
  severity: string;
  confidence: string;
  url: string;
  path?: string;
  description?: string;
  remediation?: string;
  issueBackground?: string;
  issueDetail?: string;
  remediationBackground?: string;
  remediationDetail?: string;
  references?: string[];
  vulnerabilityClassifications?: string[];
}

export interface ProxyHistoryItem {
  id: number;
  host: string;
  port: number;
  protocol: string;
  method: string;
  path: string;
  url: string;
  status?: number;
  length?: number;
  mimeType?: string;
  comment?: string;
  request?: string;
  response?: string;
}

export interface SitemapItem {
  host: string;
  port: number;
  protocol: string;
  path: string;
  method: string;
  status?: number;
  length?: number;
  mimeType?: string;
  title?: string;
}

export interface SpiderStatus {
  status: string;
  percentComplete?: number;
  requestsMade?: number;
  errorsEncountered?: number;
}

export class BurpClient {
  private client: AxiosInstance;
  private apiKey?: string;

  constructor(config: BurpConfig) {
    this.apiKey = config.apiKey;
    this.client = axios.create({
      baseURL: config.baseUrl,
      timeout: config.timeout || 30000,
      headers: {
        'Content-Type': 'application/json',
        ...(config.apiKey ? { 'API-KEY': config.apiKey } : {}),
      },
    });
  }

  private async request<T>(method: string, path: string, data?: any): Promise<T> {
    try {
      const response = await this.client.request<T>({
        method,
        url: path,
        data,
      });
      return response.data;
    } catch (error) {
      if (error instanceof AxiosError) {
        const status = error.response?.status;
        const message = error.response?.data?.message || error.message;
        throw new Error(`Burp API Error (${status}): ${message}`);
      }
      throw error;
    }
  }

  // ============ Version/Status ============

  /**
   * Get Burp Suite version and status
   */
  async getVersion(): Promise<{ version: string; edition: string }> {
    return this.request('GET', '/burp/versions');
  }

  /**
   * Check if Burp Suite REST API is accessible
   */
  async healthCheck(): Promise<boolean> {
    try {
      await this.request('GET', '/burp/versions');
      return true;
    } catch {
      return false;
    }
  }

  // ============ Scanning ============

  /**
   * Start an active scan
   */
  async startScan(config: ScanConfig): Promise<{ scanId: string }> {
    // Try Burp Suite Professional native API format
    try {
      const response = await this.request<{ task_id?: string; id?: string }>('POST', '/v0.1/scan', {
        urls: [config.baseUrl],
        scope: config.scope ? { include: [{ rule: config.scope }] } : undefined,
      });
      return { scanId: response.task_id || response.id || 'unknown' };
    } catch {
      // Fallback to burp-rest-api format
      const response = await this.request<{ scanId?: string; taskId?: string }>('POST', '/burp/scanner/scans/active', {
        baseUrl: config.baseUrl,
      });
      return { scanId: response.scanId || response.taskId || 'unknown' };
    }
  }

  /**
   * Get scan status
   */
  async getScanStatus(scanId?: string): Promise<ScanStatus> {
    try {
      // Try native API format
      if (scanId) {
        const response = await this.request<any>('GET', `/v0.1/scan/${scanId}`);
        return {
          scanId,
          status: response.scan_status || response.status || 'unknown',
          percentComplete: response.scan_metrics?.crawl_and_audit_progress,
          itemsScanned: response.scan_metrics?.audit_items_done,
          itemsTotal: response.scan_metrics?.total_audit_items,
        };
      }
      // Get overall scan status
      const response = await this.request<any>('GET', '/burp/scanner/status');
      return {
        scanId: 'current',
        status: response.scanStatus || response.status || 'unknown',
        percentComplete: response.scanPercentComplete || response.percentComplete,
      };
    } catch {
      return {
        scanId: scanId || 'unknown',
        status: 'error',
        errors: ['Failed to get scan status'],
      };
    }
  }

  /**
   * Pause active scanning
   */
  async pauseScan(): Promise<void> {
    await this.request('PUT', '/burp/scanner/status', { scanStatus: 'paused' });
  }

  /**
   * Resume active scanning
   */
  async resumeScan(): Promise<void> {
    await this.request('PUT', '/burp/scanner/status', { scanStatus: 'running' });
  }

  // ============ Issues ============

  /**
   * Get all identified issues/vulnerabilities
   */
  async getIssues(urlPrefix?: string): Promise<Issue[]> {
    try {
      // Try native API
      const response = await this.request<any>('GET', '/v0.1/scan');
      const issues = response.issue_events || response.issues || [];
      return issues.map((issue: any) => ({
        name: issue.issue?.name || issue.name || 'Unknown Issue',
        severity: issue.issue?.severity || issue.severity || 'unknown',
        confidence: issue.issue?.confidence || issue.confidence || 'unknown',
        url: issue.issue?.origin || issue.url || '',
        path: issue.issue?.path || issue.path,
        description: issue.issue?.description || issue.description,
        issueBackground: issue.issue?.issue_background,
        issueDetail: issue.issue?.issue_detail,
        remediation: issue.issue?.remediation || issue.remediation,
        remediationBackground: issue.issue?.remediation_background,
        remediationDetail: issue.issue?.remediation_detail,
      }));
    } catch {
      // Fallback to burp-rest-api format
      const path = urlPrefix ? `/burp/scanner/issues?urlPrefix=${encodeURIComponent(urlPrefix)}` : '/burp/scanner/issues';
      const response = await this.request<any>(
        'GET',
        path
      );
      const issues = response.issues || response || [];
      return Array.isArray(issues) ? issues.map((issue: any) => ({
        name: issue.issueName || issue.name || 'Unknown Issue',
        severity: issue.severity || 'unknown',
        confidence: issue.confidence || 'unknown',
        url: issue.url || '',
        path: issue.path,
        description: issue.issueDetail || issue.description,
        issueBackground: issue.issueBackground,
        remediation: issue.remediationDetail || issue.remediation,
        remediationBackground: issue.remediationBackground,
      })) : [];
    }
  }

  /**
   * Get issue definitions/types
   */
  async getIssueDefinitions(): Promise<any[]> {
    try {
      return await this.request('GET', '/v0.1/knowledge_base/issue_definitions');
    } catch {
      return [];
    }
  }

  // ============ Sitemap ============

  /**
   * Get sitemap contents
   */
  async getSitemap(urlPrefix?: string): Promise<SitemapItem[]> {
    const path = urlPrefix ? `/burp/target/sitemap?urlPrefix=${encodeURIComponent(urlPrefix)}` : '/burp/target/sitemap';
    try {
      const response = await this.request<any>('GET', path);
      const items = response.messages || response.sitemap || response || [];
      return Array.isArray(items) ? items.map((item: any) => ({
        host: item.host || '',
        port: item.port || 443,
        protocol: item.protocol || 'https',
        path: item.path || item.url || '',
        method: item.method || 'GET',
        status: item.statusCode || item.status,
        length: item.length,
        mimeType: item.mimeType,
        title: item.title,
      })) : [];
    } catch (error) {
      return [];
    }
  }

  /**
   * Add URL to scope
   */
  async addToScope(url: string): Promise<void> {
    await this.request('PUT', '/burp/target/scope', { url, inScope: true });
  }

  /**
   * Remove URL from scope
   */
  async removeFromScope(url: string): Promise<void> {
    await this.request('DELETE', '/burp/target/scope', { url });
  }

  /**
   * Check if URL is in scope
   */
  async isInScope(url: string): Promise<boolean> {
    try {
      const response = await this.request<{ inScope: boolean }>('GET', `/burp/target/scope?url=${encodeURIComponent(url)}`);
      return response.inScope;
    } catch {
      return false;
    }
  }

  // ============ Proxy History ============

  /**
   * Get proxy history
   */
  async getProxyHistory(limit?: number): Promise<ProxyHistoryItem[]> {
    try {
      const response = await this.request<any>('GET', '/burp/proxy/history');
      const items = response.messages || response.history || response || [];
      const history = Array.isArray(items) ? items.map((item: any, index: number) => ({
        id: item.id || index,
        host: item.host || '',
        port: item.port || 443,
        protocol: item.protocol || 'https',
        method: item.method || 'GET',
        path: item.path || item.url || '',
        url: item.url || `${item.protocol || 'https'}://${item.host}${item.path || ''}`,
        status: item.statusCode || item.status,
        length: item.length,
        mimeType: item.mimeType,
        comment: item.comment,
        request: item.request,
        response: item.response,
      })) : [];
      return limit ? history.slice(0, limit) : history;
    } catch {
      return [];
    }
  }

  /**
   * Get specific proxy history item
   */
  async getProxyHistoryItem(id: number): Promise<ProxyHistoryItem | null> {
    try {
      const response = await this.request<any>('GET', `/burp/proxy/history/${id}`);
      return {
        id,
        host: response.host || '',
        port: response.port || 443,
        protocol: response.protocol || 'https',
        method: response.method || 'GET',
        path: response.path || '',
        url: response.url || '',
        status: response.statusCode || response.status,
        length: response.length,
        mimeType: response.mimeType,
        comment: response.comment,
        request: response.request,
        response: response.response,
      };
    } catch {
      return null;
    }
  }

  // ============ Spider ============

  /**
   * Start spider/crawler
   */
  async startSpider(baseUrl: string): Promise<{ status: string }> {
    try {
      await this.request('POST', '/burp/spider', { baseUrl });
      return { status: 'started' };
    } catch (error) {
      // Spider might not be available in all versions
      return { status: 'error' };
    }
  }

  /**
   * Get spider status
   */
  async getSpiderStatus(): Promise<SpiderStatus> {
    try {
      const response = await this.request<any>('GET', '/burp/spider/status');
      return {
        status: response.spiderStatus || response.status || 'unknown',
        percentComplete: response.spiderPercentComplete || response.percentComplete,
        requestsMade: response.requestsMade,
        errorsEncountered: response.errorsEncountered,
      };
    } catch {
      return { status: 'unknown' };
    }
  }

  // ============ Repeater/Intruder ============

  /**
   * Send request to Repeater
   */
  async sendToRepeater(request: string, host: string, port: number = 443, https: boolean = true): Promise<{ status: string }> {
    try {
      await this.request('POST', '/burp/repeater/send', {
        request,
        host,
        port,
        https,
      });
      return { status: 'sent' };
    } catch {
      return { status: 'error' };
    }
  }

  /**
   * Send request to Intruder
   */
  async sendToIntruder(request: string, host: string, port: number = 443, https: boolean = true): Promise<{ status: string }> {
    try {
      await this.request('POST', '/burp/intruder/send', {
        request,
        host,
        port,
        https,
      });
      return { status: 'sent' };
    } catch {
      return { status: 'error' };
    }
  }

  // ============ HTTP Requests ============

  /**
   * Send HTTP request through Burp
   */
  async sendHttpRequest(
    request: string,
    host: string,
    port: number = 443,
    https: boolean = true
  ): Promise<{ request: string; response: string }> {
    try {
      const response = await this.request<any>('POST', '/burp/send', {
        request,
        host,
        port,
        https,
      });
      return {
        request: response.request || request,
        response: response.response || '',
      };
    } catch (error) {
      return {
        request,
        response: `Error: ${error instanceof Error ? error.message : 'Unknown error'}`,
      };
    }
  }

  // ============ Configuration ============

  /**
   * Export Burp state/project
   */
  async exportState(filePath: string): Promise<void> {
    await this.request('POST', '/burp/state', { filePath });
  }

  /**
   * Reset/clear Burp state
   */
  async resetState(): Promise<void> {
    await this.request('DELETE', '/burp/state');
  }

  /**
   * Shutdown Burp Suite (if supported)
   */
  async shutdown(): Promise<void> {
    try {
      await this.request('POST', '/burp/stop');
    } catch {
      // Shutdown might cause connection to close
    }
  }
}
