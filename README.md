<div align="center">

# AIPTX

### AI-Assisted Security Testing Framework

[![PyPI version](https://img.shields.io/pypi/v/aiptx?style=flat-square&logo=pypi&logoColor=white&color=3775A9)](https://pypi.org/project/aiptx/)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9+-3776AB?style=flat-square&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)

</div>

---

AIPTX is a security testing framework that uses LLMs to assist with vulnerability scanning, analysis, and reporting. It integrates with common security tools and provides SAST, DAST, and business logic testing capabilities.

## What It Does

- **Scan Orchestration** — Coordinates multiple security tools (nuclei, nikto, sqlmap, etc.)
- **LLM-Assisted Analysis** — Uses AI to help analyze findings and suggest attack paths
- **SAST** — Static analysis for Python, JavaScript, Java, and Go with 90+ security rules
- **DAST** — Dynamic testing with WebSocket, SPA, and GraphQL scanner support
- **Business Logic Testing** — 29 test patterns for race conditions, IDOR, price manipulation
- **CI/CD Integration** — SARIF output for GitHub Security tab, PR blocking support
- **Reporting** — HTML and JSON reports with findings

## What It Doesn't Do

- It's not fully autonomous — requires configuration and human judgment
- It won't replace manual penetration testing
- AI suggestions need verification before acting on them
- Enterprise scanner integration (Acunetix, Burp, Nessus) requires separate licenses

---

## Installation

```bash
# Basic installation
pip install aiptx

# With SPA/WebSocket testing (requires playwright)
pip install aiptx[modern]

# Full installation
pip install aiptx[full]
```

### Setup

```bash
# Configure LLM API key and preferences
aiptx setup

# Verify configuration
aiptx status
```

---

## Usage

```bash
# Basic scan
aiptx scan example.com

# Quick scan (skip enterprise scanners)
aiptx scan example.com --quick

# With AI assistance
aiptx scan example.com --ai

# SAST analysis on local code
aiptx scan ./my-project --sast

# Output SARIF for CI/CD
aiptx scan example.com --format sarif --output results.sarif

# Fail CI if high severity findings
aiptx scan example.com --format sarif --fail-on-severity high
```

---

## v4.0 Features

### SAST (Static Analysis)
- Python, JavaScript/TypeScript, Java, Go support
- 90+ security rules (SQL injection, XSS, command injection, secrets)
- GitHub repository scanning

### Modern App Testing
- **WebSocket Scanner** — Injection testing, CSWSH, replay attacks
- **SPA Scanner** — Browser-based testing with Playwright, DOM XSS detection
- **GraphQL Scanner** — Mutations, subscriptions, complexity attacks, schema analysis

### Business Logic Testing
- Race conditions (double-spend, TOCTOU)
- Price/amount manipulation
- Workflow bypass
- Access control (IDOR, privilege escalation)
- Rate limit bypass

### CI/CD Integration
- SARIF 2.1.0 output for GitHub Code Scanning
- GitHub Action available
- Exit codes based on finding severity

---

## Configuration

### LLM Provider

AIPTX uses LiteLLM and supports multiple providers:

```bash
# Anthropic (recommended)
export ANTHROPIC_API_KEY="your-key"

# OpenAI
export OPENAI_API_KEY="your-key"

# Local (Ollama)
export OLLAMA_API_BASE="http://localhost:11434"
export AIPT_LLM__MODEL="ollama/llama3"
```

### Enterprise Scanners (Optional)

Requires separate licenses:

```bash
# Acunetix
export ACUNETIX_URL="https://your-acunetix:3443"
export ACUNETIX_API_KEY="your-api-key"

# Burp Suite Enterprise
export BURP_URL="http://your-burp:1337/v0.1/"
export BURP_API_KEY="your-api-key"
```

---

## GitHub Action

```yaml
- name: AIPTX Security Scan
  run: |
    pip install aiptx
    aiptx scan . --sast --format sarif --output results.sarif --fail-on-severity high

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## Architecture

```
┌────────────────────────────────────────────────────────────┐
│                         AIPTX v4.0                         │
├────────────────────────────────────────────────────────────┤
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌──────────────┐  │
│  │  SAST   │  │  DAST   │  │ Business│  │   GraphQL/   │  │
│  │ Engine  │  │ Scanner │  │  Logic  │  │   WebSocket  │  │
│  └────┬────┘  └────┬────┘  └────┬────┘  └──────┬───────┘  │
│       └────────────┴────────────┴───────────────┘         │
│                           │                                │
│                    ┌──────▼──────┐                        │
│                    │  Findings   │                        │
│                    │ Repository  │                        │
│                    └──────┬──────┘                        │
│                           │                                │
│              ┌────────────┼────────────┐                  │
│              ▼            ▼            ▼                  │
│         ┌────────┐  ┌──────────┐  ┌────────┐             │
│         │  HTML  │  │   JSON   │  │  SARIF │             │
│         │ Report │  │  Export  │  │ Output │             │
│         └────────┘  └──────────┘  └────────┘             │
└────────────────────────────────────────────────────────────┘
```

---

## Output Formats

| Format | Use Case |
|--------|----------|
| `--format text` | Terminal output (default) |
| `--format json` | Programmatic processing |
| `--format sarif` | GitHub Security tab |
| `--format html` | Shareable reports |

---

## Integrated Tools

AIPTX can orchestrate these tools (must be installed separately):

| Category | Tools |
|----------|-------|
| Recon | subfinder, httpx, katana, waybackurls |
| Scanning | nuclei, nikto, ffuf |
| Exploitation | sqlmap, commix |
| Secrets | gitleaks, trufflehog |

---

## Requirements

- Python 3.9+
- LLM API key (Anthropic, OpenAI, or local)
- Optional: Security tools for full scanning
- Optional: Playwright for SPA testing (`pip install aiptx[modern]`)

---

## Limitations

- AI analysis quality depends on the LLM used
- Some features require additional tools to be installed
- Enterprise scanner integration requires separate licenses
- Business logic tests may produce false positives
- WebSocket/SPA scanning requires `playwright install`

---

## License

MIT License — See [LICENSE](LICENSE) for details.

---

## Links

- **PyPI**: [pypi.org/project/aiptx](https://pypi.org/project/aiptx/)
- **GitHub**: [github.com/aiptx/aiptx](https://github.com/aiptx/aiptx)
- **Issues**: [GitHub Issues](https://github.com/aiptx/aiptx/issues)
