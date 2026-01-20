# @aiptx/sdk

Official Node.js SDK for AIPTX - AI-Powered Penetration Testing Framework.

## Installation

```bash
npm install @aiptx/sdk
# or
yarn add @aiptx/sdk
# or
pnpm add @aiptx/sdk
```

## Quick Start

```typescript
import { AIPTX } from '@aiptx/sdk';

// Create a client
const client = new AIPTX({
  baseUrl: 'http://localhost:8000', // AIPTX API server
  apiKey: 'your-api-key', // Optional
});

// Check server health
const health = await client.health();
console.log(`Server version: ${health.version}`);

// Create a project
const project = await client.createProject({
  name: 'My Security Assessment',
  target: 'example.com',
  scope: ['*.example.com'],
});

// Start a scan
const scan = await client.startScan({
  target: 'example.com',
  mode: 'standard',
  ai: true,
});

// Stream scan progress
client.streamScan(scan.id, {
  onProgress: (progress, phase) => {
    console.log(`[${phase}] Progress: ${progress}%`);
  },
  onFinding: (finding) => {
    console.log(`Found: ${finding.type} - ${finding.value} (${finding.severity})`);
  },
  onComplete: (status) => {
    console.log(`Scan completed with ${status.findings_count} findings`);
  },
});
```

## API Reference

### Client Configuration

```typescript
interface AIPTXConfig {
  baseUrl?: string;   // Default: 'http://localhost:8000'
  apiKey?: string;    // Optional API key for authentication
  timeout?: number;   // Request timeout in ms (default: 30000)
}
```

### Methods

#### Health & Status
- `health()` - Get server health status
- `ready()` - Check if server is ready

#### Projects
- `listProjects()` - List all projects
- `createProject(data)` - Create a new project
- `getProject(id)` - Get project by ID
- `updateProject(id, data)` - Update a project
- `deleteProject(id)` - Delete a project

#### Sessions
- `listSessions(projectId)` - List project sessions
- `createSession(projectId, data)` - Create a session
- `getSession(id)` - Get session by ID

#### Findings
- `listFindings(options?)` - List findings with optional filters
- `getProjectFindings(projectId)` - Get project findings
- `getFinding(id)` - Get finding by ID

#### Scanning
- `startScan(request)` - Start a new scan
- `getScanStatus(scanId)` - Get scan status
- `streamScan(scanId, callbacks)` - Stream scan events

#### Tools
- `listTools()` - List available security tools

## Scan Modes

| Mode | Description |
|------|-------------|
| `quick` | Fast essential checks (~5 min) |
| `standard` | Balanced assessment (~15-30 min) |
| `full` | Comprehensive with exploitation (~1-2 hours) |

## Error Handling

```typescript
import { AIPTX, AIPTXError } from '@aiptx/sdk';

try {
  const project = await client.getProject(999);
} catch (error) {
  if (error instanceof AIPTXError) {
    console.error(`API Error: ${error.message}`);
    console.error(`Status: ${error.statusCode}`);
  }
}
```

## Requirements

- Node.js >= 18.0.0
- AIPTX API server running (Python backend)

## Running the AIPTX Server

```bash
# Install Python package
pip install aiptx

# Start API server
aiptx api
```

## License

MIT - See [LICENSE](LICENSE) for details.

## Links

- [Documentation](https://aiptx.io/docs)
- [GitHub](https://github.com/aiptx/aiptx-js)
- [PyPI (Python)](https://pypi.org/project/aiptx/)
