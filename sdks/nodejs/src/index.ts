/**
 * AIPTX SDK for Node.js
 * AI-Powered Penetration Testing Framework
 *
 * @packageDocumentation
 */

import axios, { AxiosInstance, AxiosError } from 'axios';
import EventSource from 'eventsource';

// =============================================================================
// Types & Interfaces
// =============================================================================

export interface AIPTXConfig {
  /** Base URL of the AIPTX API server */
  baseUrl?: string;
  /** API key for authentication (optional) */
  apiKey?: string;
  /** Request timeout in milliseconds */
  timeout?: number;
}

export interface Project {
  id: number;
  name: string;
  target: string;
  description?: string;
  scope?: string[];
  created_at: string;
  updated_at?: string;
}

export interface ProjectCreate {
  name: string;
  target: string;
  description?: string;
  scope?: string[];
}

export interface Session {
  id: number;
  project_id: number;
  name: string;
  phase: 'recon' | 'enum' | 'exploit' | 'post' | 'report';
  status: 'pending' | 'running' | 'paused' | 'completed' | 'error';
  iteration: number;
  max_iterations: number;
  created_at: string;
  started_at?: string;
  completed_at?: string;
}

export interface SessionCreate {
  name: string;
  max_iterations?: number;
}

export interface Finding {
  id: number;
  project_id: number;
  session_id?: number;
  type: 'port' | 'service' | 'vuln' | 'credential' | 'host' | 'path' | 'info';
  value: string;
  description?: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  phase: string;
  tool: string;
  raw_output?: string;
  extra_data?: Record<string, unknown>;
  verified: boolean;
  false_positive: boolean;
  discovered_at: string;
}

export interface ScanRequest {
  target: string;
  mode?: 'quick' | 'standard' | 'full';
  ai?: boolean;
  exploit?: boolean;
  phases?: string[];
}

export interface ScanStatus {
  id: string;
  status: 'pending' | 'running' | 'completed' | 'error';
  phase: string;
  progress: number;
  findings_count: number;
  started_at?: string;
  completed_at?: string;
  error?: string;
}

export interface HealthStatus {
  status: 'healthy' | 'unhealthy';
  version: string;
  uptime: number;
  components: {
    database: boolean;
    llm: boolean;
    scanners: Record<string, boolean>;
  };
}

export interface Tool {
  name: string;
  description: string;
  phase: string;
  keywords: string[];
  available: boolean;
}

export class AIPTXError extends Error {
  public statusCode?: number;
  public response?: unknown;

  constructor(message: string, statusCode?: number, response?: unknown) {
    super(message);
    this.name = 'AIPTXError';
    this.statusCode = statusCode;
    this.response = response;
  }
}

// =============================================================================
// AIPTX Client
// =============================================================================

export class AIPTX {
  private client: AxiosInstance;
  private baseUrl: string;

  constructor(config: AIPTXConfig = {}) {
    this.baseUrl = config.baseUrl || 'http://localhost:8000';

    this.client = axios.create({
      baseURL: this.baseUrl,
      timeout: config.timeout || 30000,
      headers: {
        'Content-Type': 'application/json',
        ...(config.apiKey && { Authorization: `Bearer ${config.apiKey}` }),
      },
    });

    // Add response interceptor for error handling
    this.client.interceptors.response.use(
      (response) => response,
      (error: AxiosError) => {
        if (error.response) {
          throw new AIPTXError(
            error.message,
            error.response.status,
            error.response.data
          );
        }
        throw new AIPTXError(error.message);
      }
    );
  }

  // ===========================================================================
  // Health & Status
  // ===========================================================================

  /**
   * Check the health status of the AIPTX server
   */
  async health(): Promise<HealthStatus> {
    const response = await this.client.get<HealthStatus>('/health');
    return response.data;
  }

  /**
   * Check if the server is ready to accept requests
   */
  async ready(): Promise<boolean> {
    try {
      await this.client.get('/health/ready');
      return true;
    } catch {
      return false;
    }
  }

  // ===========================================================================
  // Projects
  // ===========================================================================

  /**
   * List all projects
   */
  async listProjects(): Promise<Project[]> {
    const response = await this.client.get<Project[]>('/projects');
    return response.data;
  }

  /**
   * Create a new project
   */
  async createProject(data: ProjectCreate): Promise<Project> {
    const response = await this.client.post<Project>('/projects', data);
    return response.data;
  }

  /**
   * Get a project by ID
   */
  async getProject(id: number): Promise<Project> {
    const response = await this.client.get<Project>(`/projects/${id}`);
    return response.data;
  }

  /**
   * Update a project
   */
  async updateProject(id: number, data: Partial<ProjectCreate>): Promise<Project> {
    const response = await this.client.put<Project>(`/projects/${id}`, data);
    return response.data;
  }

  /**
   * Delete a project
   */
  async deleteProject(id: number): Promise<void> {
    await this.client.delete(`/projects/${id}`);
  }

  // ===========================================================================
  // Sessions
  // ===========================================================================

  /**
   * List sessions for a project
   */
  async listSessions(projectId: number): Promise<Session[]> {
    const response = await this.client.get<Session[]>(
      `/projects/${projectId}/sessions`
    );
    return response.data;
  }

  /**
   * Create a new session
   */
  async createSession(projectId: number, data: SessionCreate): Promise<Session> {
    const response = await this.client.post<Session>(
      `/projects/${projectId}/sessions`,
      data
    );
    return response.data;
  }

  /**
   * Get a session by ID
   */
  async getSession(id: number): Promise<Session> {
    const response = await this.client.get<Session>(`/sessions/${id}`);
    return response.data;
  }

  // ===========================================================================
  // Findings
  // ===========================================================================

  /**
   * List all findings (optionally filtered)
   */
  async listFindings(options?: {
    projectId?: number;
    severity?: string;
    type?: string;
  }): Promise<Finding[]> {
    const params = new URLSearchParams();
    if (options?.projectId) params.append('project_id', String(options.projectId));
    if (options?.severity) params.append('severity', options.severity);
    if (options?.type) params.append('type', options.type);

    const response = await this.client.get<Finding[]>('/findings', { params });
    return response.data;
  }

  /**
   * Get findings for a specific project
   */
  async getProjectFindings(projectId: number): Promise<Finding[]> {
    const response = await this.client.get<Finding[]>(
      `/projects/${projectId}/findings`
    );
    return response.data;
  }

  /**
   * Get a finding by ID
   */
  async getFinding(id: number): Promise<Finding> {
    const response = await this.client.get<Finding>(`/findings/${id}`);
    return response.data;
  }

  // ===========================================================================
  // Scanning
  // ===========================================================================

  /**
   * Start a new scan
   */
  async startScan(request: ScanRequest): Promise<ScanStatus> {
    const response = await this.client.post<ScanStatus>('/scan', request);
    return response.data;
  }

  /**
   * Get scan status
   */
  async getScanStatus(scanId: string): Promise<ScanStatus> {
    const response = await this.client.get<ScanStatus>(`/scans/${scanId}`);
    return response.data;
  }

  /**
   * Stream scan events using Server-Sent Events
   */
  streamScan(
    scanId: string,
    callbacks: {
      onProgress?: (progress: number, phase: string) => void;
      onFinding?: (finding: Finding) => void;
      onComplete?: (status: ScanStatus) => void;
      onError?: (error: Error) => void;
    }
  ): () => void {
    const eventSource = new EventSource(`${this.baseUrl}/scans/${scanId}/stream`);

    eventSource.addEventListener('progress', (event) => {
      const data = JSON.parse(event.data);
      callbacks.onProgress?.(data.progress, data.phase);
    });

    eventSource.addEventListener('finding', (event) => {
      const finding = JSON.parse(event.data);
      callbacks.onFinding?.(finding);
    });

    eventSource.addEventListener('complete', (event) => {
      const status = JSON.parse(event.data);
      callbacks.onComplete?.(status);
      eventSource.close();
    });

    eventSource.addEventListener('error', () => {
      callbacks.onError?.(new Error('Stream connection error'));
      eventSource.close();
    });

    // Return cleanup function
    return () => eventSource.close();
  }

  // ===========================================================================
  // Tools
  // ===========================================================================

  /**
   * List available security tools
   */
  async listTools(): Promise<Tool[]> {
    const response = await this.client.get<Tool[]>('/tools');
    return response.data;
  }
}

// =============================================================================
// Default Export
// =============================================================================

export default AIPTX;

// Convenience factory function
export function createClient(config?: AIPTXConfig): AIPTX {
  return new AIPTX(config);
}
