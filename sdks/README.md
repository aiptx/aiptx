# AIPTX SDKs

This directory contains official SDKs for AIPTX in multiple languages.

## Available SDKs

| Platform | Package | Installation |
|----------|---------|--------------|
| Python | [aiptx](https://pypi.org/project/aiptx/) | `pip install aiptx` |
| Node.js | [@aiptx/sdk](https://npmjs.com/package/@aiptx/sdk) | `npm install @aiptx/sdk` |
| Node.js CLI | [@aiptx/cli](https://npmjs.com/package/@aiptx/cli) | `npm install -g @aiptx/cli` |
| Go | [aiptx-go](https://github.com/aiptx/aiptx-go) | `go get github.com/aiptx/aiptx-go` |
| Docker | [aiptx/aiptx](https://hub.docker.com/r/aiptx/aiptx) | `docker pull aiptx/aiptx` |
| Homebrew | aiptx | `brew install aiptx/tap/aiptx` |

## Directory Structure

```
sdks/
├── nodejs/          # @aiptx/sdk - TypeScript/JavaScript SDK
│   ├── src/
│   ├── package.json
│   └── README.md
│
├── nodejs-cli/      # @aiptx/cli - Command line interface
│   ├── src/
│   ├── package.json
│   └── README.md
│
├── go/              # aiptx-go - Go SDK
│   ├── aiptx.go
│   ├── go.mod
│   └── README.md
│
└── homebrew/        # Homebrew formula
    └── aiptx.rb
```

## Publishing

To publish all SDKs:

```bash
# Using the publish script
./scripts/publish.sh 2.0.6

# Or via GitHub Actions
git tag v2.0.6
git push origin v2.0.6
```

## Required Secrets (GitHub Actions)

| Secret | Description |
|--------|-------------|
| `PYPI_API_TOKEN` | PyPI API token for Python package |
| `NPM_TOKEN` | npm access token for Node.js packages |
| `DOCKERHUB_USERNAME` | Docker Hub username |
| `DOCKERHUB_TOKEN` | Docker Hub access token |
| `HOMEBREW_TAP_TOKEN` | GitHub token for homebrew-tap repo |

## SDK Architecture

All SDKs are thin HTTP clients that communicate with the AIPTX Python backend via REST API:

```
┌─────────────────────────────────────────────────────────────┐
│                    Your Application                          │
└─────────────────────────────────────────────────────────────┘
                              │
        ┌─────────────────────┼─────────────────────┐
        │                     │                     │
        ▼                     ▼                     ▼
┌───────────────┐    ┌───────────────┐    ┌───────────────┐
│  @aiptx/sdk   │    │   aiptx-go    │    │    aiptx      │
│  (Node.js)    │    │     (Go)      │    │   (Python)    │
└───────────────┘    └───────────────┘    └───────────────┘
        │                     │                     │
        └─────────────────────┼─────────────────────┘
                              │
                         HTTP/REST
                              │
                              ▼
                ┌─────────────────────────┐
                │    AIPTX API Server     │
                │   (Python FastAPI)      │
                └─────────────────────────┘
```

## Contributing

1. Make changes to the SDK in its respective directory
2. Update version in package.json/go.mod
3. Run tests: `npm test` or `go test`
4. Submit PR

## License

MIT - See [LICENSE](../LICENSE)
