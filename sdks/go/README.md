# aiptx-go

Official Go SDK for AIPTX - AI-Powered Penetration Testing Framework.

## Installation

```bash
go get github.com/aiptx/aiptx-go
```

## Quick Start

```go
package main

import (
    "fmt"
    "log"

    "github.com/aiptx/aiptx-go"
)

func main() {
    // Create a client
    client := aiptx.NewClient("http://localhost:8000", "")

    // Check server health
    health, err := client.Health()
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Server version: %s\n", health.Version)

    // Create a project
    project, err := client.CreateProject(&aiptx.ProjectCreate{
        Name:   "My Security Assessment",
        Target: "example.com",
        Scope:  []string{"*.example.com"},
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Created project: %s (ID: %d)\n", project.Name, project.ID)

    // Start a scan
    scan, err := client.StartScan(&aiptx.ScanRequest{
        Target: "example.com",
        Mode:   "standard",
        AI:     true,
    })
    if err != nil {
        log.Fatal(err)
    }
    fmt.Printf("Scan started: %s\n", scan.ID)

    // Poll for status
    for {
        status, err := client.GetScanStatus(scan.ID)
        if err != nil {
            log.Fatal(err)
        }

        fmt.Printf("Phase: %s, Progress: %d%%\n", status.Phase, status.Progress)

        if status.Status == "completed" || status.Status == "error" {
            fmt.Printf("Scan finished with %d findings\n", status.FindingsCount)
            break
        }

        time.Sleep(5 * time.Second)
    }
}
```

## API Reference

### Client

```go
// Create a new client
client := aiptx.NewClient(baseURL, apiKey)

// With custom HTTP client
client.HTTPClient = &http.Client{Timeout: 60 * time.Second}
```

### Methods

#### Health & Status
- `Health() (*HealthStatus, error)` - Get server health
- `Ready() bool` - Check if server is ready

#### Projects
- `ListProjects() ([]Project, error)` - List all projects
- `CreateProject(data *ProjectCreate) (*Project, error)` - Create project
- `GetProject(id int64) (*Project, error)` - Get project by ID
- `UpdateProject(id int64, data *ProjectCreate) (*Project, error)` - Update
- `DeleteProject(id int64) error` - Delete project

#### Sessions
- `ListSessions(projectID int64) ([]Session, error)` - List sessions
- `CreateSession(projectID int64, data *SessionCreate) (*Session, error)`
- `GetSession(id int64) (*Session, error)`

#### Findings
- `ListFindings(filter *FindingsFilter) ([]Finding, error)` - List with filters
- `GetProjectFindings(projectID int64) ([]Finding, error)`
- `GetFinding(id int64) (*Finding, error)`

#### Scanning
- `StartScan(req *ScanRequest) (*ScanStatus, error)` - Start scan
- `GetScanStatus(scanID string) (*ScanStatus, error)` - Get status

#### Tools
- `ListTools() ([]Tool, error)` - List available tools

## Scan Modes

| Mode | Description |
|------|-------------|
| `quick` | Fast essential checks (~5 min) |
| `standard` | Balanced assessment (~15-30 min) |
| `full` | Comprehensive with exploitation (~1-2 hours) |

## Error Handling

```go
scan, err := client.StartScan(&aiptx.ScanRequest{Target: "example.com"})
if err != nil {
    if apiErr, ok := err.(*aiptx.APIError); ok {
        fmt.Printf("API Error %d: %s\n", apiErr.StatusCode, apiErr.Message)
    } else {
        fmt.Printf("Error: %s\n", err)
    }
}
```

## Requirements

- Go 1.21+
- AIPTX API server running

## License

MIT - See [LICENSE](LICENSE) for details.

## Links

- [Documentation](https://aiptx.io/docs)
- [GitHub](https://github.com/aiptx/aiptx-go)
- [PyPI (Python)](https://pypi.org/project/aiptx/)
- [npm (Node.js)](https://www.npmjs.com/package/@aiptx/sdk)
