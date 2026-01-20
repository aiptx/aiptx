// Package aiptx provides a Go client for the AIPTX AI-Powered Penetration Testing API.
//
// Installation:
//
//	go get github.com/aiptx/aiptx-go
//
// Quick Start:
//
//	client := aiptx.NewClient("http://localhost:8000", "")
//	health, err := client.Health()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Server version: %s\n", health.Version)
package aiptx

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// =============================================================================
// Types
// =============================================================================

// Client represents an AIPTX API client.
type Client struct {
	BaseURL    string
	APIKey     string
	HTTPClient *http.Client
}

// Project represents a penetration testing project.
type Project struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Target      string    `json:"target"`
	Description string    `json:"description,omitempty"`
	Scope       []string  `json:"scope,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`
}

// ProjectCreate represents data for creating a new project.
type ProjectCreate struct {
	Name        string   `json:"name"`
	Target      string   `json:"target"`
	Description string   `json:"description,omitempty"`
	Scope       []string `json:"scope,omitempty"`
}

// Session represents a scan session.
type Session struct {
	ID            int64     `json:"id"`
	ProjectID     int64     `json:"project_id"`
	Name          string    `json:"name"`
	Phase         string    `json:"phase"`
	Status        string    `json:"status"`
	Iteration     int       `json:"iteration"`
	MaxIterations int       `json:"max_iterations"`
	CreatedAt     time.Time `json:"created_at"`
	StartedAt     time.Time `json:"started_at,omitempty"`
	CompletedAt   time.Time `json:"completed_at,omitempty"`
}

// SessionCreate represents data for creating a new session.
type SessionCreate struct {
	Name          string `json:"name"`
	MaxIterations int    `json:"max_iterations,omitempty"`
}

// Finding represents a discovered vulnerability or information.
type Finding struct {
	ID            int64                  `json:"id"`
	ProjectID     int64                  `json:"project_id"`
	SessionID     int64                  `json:"session_id,omitempty"`
	Type          string                 `json:"type"`
	Value         string                 `json:"value"`
	Description   string                 `json:"description,omitempty"`
	Severity      string                 `json:"severity"`
	Phase         string                 `json:"phase"`
	Tool          string                 `json:"tool"`
	RawOutput     string                 `json:"raw_output,omitempty"`
	ExtraData     map[string]interface{} `json:"extra_data,omitempty"`
	Verified      bool                   `json:"verified"`
	FalsePositive bool                   `json:"false_positive"`
	DiscoveredAt  time.Time              `json:"discovered_at"`
}

// ScanRequest represents a scan request.
type ScanRequest struct {
	Target  string   `json:"target"`
	Mode    string   `json:"mode,omitempty"`
	AI      bool     `json:"ai,omitempty"`
	Exploit bool     `json:"exploit,omitempty"`
	Phases  []string `json:"phases,omitempty"`
}

// ScanStatus represents the status of a scan.
type ScanStatus struct {
	ID            string    `json:"id"`
	Status        string    `json:"status"`
	Phase         string    `json:"phase"`
	Progress      int       `json:"progress"`
	FindingsCount int       `json:"findings_count"`
	StartedAt     time.Time `json:"started_at,omitempty"`
	CompletedAt   time.Time `json:"completed_at,omitempty"`
	Error         string    `json:"error,omitempty"`
}

// HealthStatus represents the server health status.
type HealthStatus struct {
	Status     string `json:"status"`
	Version    string `json:"version"`
	Uptime     int64  `json:"uptime"`
	Components struct {
		Database bool            `json:"database"`
		LLM      bool            `json:"llm"`
		Scanners map[string]bool `json:"scanners,omitempty"`
	} `json:"components"`
}

// Tool represents an available security tool.
type Tool struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Phase       string   `json:"phase"`
	Keywords    []string `json:"keywords"`
	Available   bool     `json:"available"`
}

// APIError represents an API error response.
type APIError struct {
	StatusCode int
	Message    string
	Response   interface{}
}

func (e *APIError) Error() string {
	return fmt.Sprintf("AIPTX API error (status %d): %s", e.StatusCode, e.Message)
}

// =============================================================================
// Client
// =============================================================================

// NewClient creates a new AIPTX API client.
func NewClient(baseURL, apiKey string) *Client {
	if baseURL == "" {
		baseURL = "http://localhost:8000"
	}

	return &Client{
		BaseURL: baseURL,
		APIKey:  apiKey,
		HTTPClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// request makes an HTTP request to the API.
func (c *Client) request(method, path string, body interface{}) ([]byte, error) {
	var reqBody io.Reader
	if body != nil {
		jsonBody, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		reqBody = bytes.NewBuffer(jsonBody)
	}

	req, err := http.NewRequest(method, c.BaseURL+path, reqBody)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode >= 400 {
		return nil, &APIError{
			StatusCode: resp.StatusCode,
			Message:    string(respBody),
		}
	}

	return respBody, nil
}

// =============================================================================
// Health & Status
// =============================================================================

// Health returns the server health status.
func (c *Client) Health() (*HealthStatus, error) {
	body, err := c.request("GET", "/health", nil)
	if err != nil {
		return nil, err
	}

	var health HealthStatus
	if err := json.Unmarshal(body, &health); err != nil {
		return nil, err
	}
	return &health, nil
}

// Ready checks if the server is ready to accept requests.
func (c *Client) Ready() bool {
	_, err := c.request("GET", "/health/ready", nil)
	return err == nil
}

// =============================================================================
// Projects
// =============================================================================

// ListProjects returns all projects.
func (c *Client) ListProjects() ([]Project, error) {
	body, err := c.request("GET", "/projects", nil)
	if err != nil {
		return nil, err
	}

	var projects []Project
	if err := json.Unmarshal(body, &projects); err != nil {
		return nil, err
	}
	return projects, nil
}

// CreateProject creates a new project.
func (c *Client) CreateProject(data *ProjectCreate) (*Project, error) {
	body, err := c.request("POST", "/projects", data)
	if err != nil {
		return nil, err
	}

	var project Project
	if err := json.Unmarshal(body, &project); err != nil {
		return nil, err
	}
	return &project, nil
}

// GetProject returns a project by ID.
func (c *Client) GetProject(id int64) (*Project, error) {
	body, err := c.request("GET", fmt.Sprintf("/projects/%d", id), nil)
	if err != nil {
		return nil, err
	}

	var project Project
	if err := json.Unmarshal(body, &project); err != nil {
		return nil, err
	}
	return &project, nil
}

// UpdateProject updates a project.
func (c *Client) UpdateProject(id int64, data *ProjectCreate) (*Project, error) {
	body, err := c.request("PUT", fmt.Sprintf("/projects/%d", id), data)
	if err != nil {
		return nil, err
	}

	var project Project
	if err := json.Unmarshal(body, &project); err != nil {
		return nil, err
	}
	return &project, nil
}

// DeleteProject deletes a project.
func (c *Client) DeleteProject(id int64) error {
	_, err := c.request("DELETE", fmt.Sprintf("/projects/%d", id), nil)
	return err
}

// =============================================================================
// Sessions
// =============================================================================

// ListSessions returns all sessions for a project.
func (c *Client) ListSessions(projectID int64) ([]Session, error) {
	body, err := c.request("GET", fmt.Sprintf("/projects/%d/sessions", projectID), nil)
	if err != nil {
		return nil, err
	}

	var sessions []Session
	if err := json.Unmarshal(body, &sessions); err != nil {
		return nil, err
	}
	return sessions, nil
}

// CreateSession creates a new session for a project.
func (c *Client) CreateSession(projectID int64, data *SessionCreate) (*Session, error) {
	body, err := c.request("POST", fmt.Sprintf("/projects/%d/sessions", projectID), data)
	if err != nil {
		return nil, err
	}

	var session Session
	if err := json.Unmarshal(body, &session); err != nil {
		return nil, err
	}
	return &session, nil
}

// GetSession returns a session by ID.
func (c *Client) GetSession(id int64) (*Session, error) {
	body, err := c.request("GET", fmt.Sprintf("/sessions/%d", id), nil)
	if err != nil {
		return nil, err
	}

	var session Session
	if err := json.Unmarshal(body, &session); err != nil {
		return nil, err
	}
	return &session, nil
}

// =============================================================================
// Findings
// =============================================================================

// FindingsFilter contains options for filtering findings.
type FindingsFilter struct {
	ProjectID int64
	Severity  string
	Type      string
}

// ListFindings returns all findings, optionally filtered.
func (c *Client) ListFindings(filter *FindingsFilter) ([]Finding, error) {
	path := "/findings"
	if filter != nil {
		params := url.Values{}
		if filter.ProjectID > 0 {
			params.Add("project_id", fmt.Sprintf("%d", filter.ProjectID))
		}
		if filter.Severity != "" {
			params.Add("severity", filter.Severity)
		}
		if filter.Type != "" {
			params.Add("type", filter.Type)
		}
		if len(params) > 0 {
			path += "?" + params.Encode()
		}
	}

	body, err := c.request("GET", path, nil)
	if err != nil {
		return nil, err
	}

	var findings []Finding
	if err := json.Unmarshal(body, &findings); err != nil {
		return nil, err
	}
	return findings, nil
}

// GetProjectFindings returns all findings for a project.
func (c *Client) GetProjectFindings(projectID int64) ([]Finding, error) {
	body, err := c.request("GET", fmt.Sprintf("/projects/%d/findings", projectID), nil)
	if err != nil {
		return nil, err
	}

	var findings []Finding
	if err := json.Unmarshal(body, &findings); err != nil {
		return nil, err
	}
	return findings, nil
}

// GetFinding returns a finding by ID.
func (c *Client) GetFinding(id int64) (*Finding, error) {
	body, err := c.request("GET", fmt.Sprintf("/findings/%d", id), nil)
	if err != nil {
		return nil, err
	}

	var finding Finding
	if err := json.Unmarshal(body, &finding); err != nil {
		return nil, err
	}
	return &finding, nil
}

// =============================================================================
// Scanning
// =============================================================================

// StartScan starts a new security scan.
func (c *Client) StartScan(req *ScanRequest) (*ScanStatus, error) {
	body, err := c.request("POST", "/scan", req)
	if err != nil {
		return nil, err
	}

	var status ScanStatus
	if err := json.Unmarshal(body, &status); err != nil {
		return nil, err
	}
	return &status, nil
}

// GetScanStatus returns the status of a scan.
func (c *Client) GetScanStatus(scanID string) (*ScanStatus, error) {
	body, err := c.request("GET", fmt.Sprintf("/scans/%s", scanID), nil)
	if err != nil {
		return nil, err
	}

	var status ScanStatus
	if err := json.Unmarshal(body, &status); err != nil {
		return nil, err
	}
	return &status, nil
}

// =============================================================================
// Tools
// =============================================================================

// ListTools returns all available security tools.
func (c *Client) ListTools() ([]Tool, error) {
	body, err := c.request("GET", "/tools", nil)
	if err != nil {
		return nil, err
	}

	var tools []Tool
	if err := json.Unmarshal(body, &tools); err != nil {
		return nil, err
	}
	return tools, nil
}
