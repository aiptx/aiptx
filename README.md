<div align="center">

<img src="https://aiptx.io/logo.png" alt="AIPTX Logo" width="200"/>

# AIPTX Beast Mode

### Fully Autonomous AI-Powered Penetration Testing Framework

[![Website](https://img.shields.io/badge/Website-aiptx.io-0066FF?style=for-the-badge&logo=safari&logoColor=white)](https://aiptx.io)
[![PyPI version](https://img.shields.io/pypi/v/aiptx?style=for-the-badge&logo=pypi&logoColor=white&color=3775A9)](https://pypi.org/project/aiptx/)
[![Downloads](https://img.shields.io/pepy/dt/aiptx?style=for-the-badge&logo=python&logoColor=white&color=success)](https://pepy.tech/project/aiptx)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

[![Stars](https://img.shields.io/github/stars/aiptx/aiptx?style=for-the-badge&logo=github&color=gold)](https://github.com/aiptx/aiptx/stargazers)
[![Forks](https://img.shields.io/github/forks/aiptx/aiptx?style=for-the-badge&logo=github&color=silver)](https://github.com/aiptx/aiptx/network/members)
[![Issues](https://img.shields.io/github/issues/aiptx/aiptx?style=for-the-badge&logo=github&color=red)](https://github.com/aiptx/aiptx/issues)

**Enterprise-Grade Autonomous Security Assessment Platform**

[Getting Started](#-quick-start) • [Features](#-key-features) • [Documentation](https://aiptx.io/docs) • [API Reference](https://aiptx.io/api)

---

**AIPTX Beast Mode** is an enterprise-grade, fully autonomous AI-powered penetration testing framework that leverages Large Language Models to conduct comprehensive security assessments. From reconnaissance to post-exploitation, AIPTX orchestrates the complete attack chain with intelligent decision-making, adaptive strategies, and professional reporting.

</div>

---

## Why AIPTX Beast Mode?

| Capability | AIPTX | Traditional Tools |
|------------|:-----:|:-----------------:|
| Autonomous Attack Chains | ✅ | ❌ |
| AI-Guided Decision Making | ✅ | ❌ |
| Exploit Chain Building | ✅ | ❌ |
| Credential Harvesting | ✅ | Manual |
| Lateral Movement | ✅ | Manual |
| Stealth Operations | ✅ | ❌ |
| WAF Detection & Bypass | ✅ | Limited |
| Enterprise Scanner Integration | ✅ | ❌ |
| 100+ LLM Providers | ✅ | ❌ |
| Single Command Execution | ✅ | Multiple Tools |

---

## Key Features

### Intelligence Layer
- **LLM Attack Planning** — AI generates strategic attack plans based on target analysis
- **Chain Discovery** — Automatically identifies novel attack chain combinations
- **Business Logic Analysis** — Detects flaws that automated scanners miss
- **Adaptive Payloads** — Real-time payload generation based on target responses
- **Defense Adaptation** — Monitors and adapts to defensive countermeasures

### Exploitation Engine
- **Autonomous Chain Execution** — Builds and executes multi-step exploit chains
- **WAF Detection & Bypass** — Fingerprints 50+ WAF products with evasion techniques
- **Payload Mutations** — SQLi, XSS, RCE mutations with encoding variations
- **Fallback Strategies** — Intelligent retry with alternative techniques

### Post-Exploitation
- **Credential Harvesting** — Extracts secrets from memory, files, browsers, cloud metadata
- **Privilege Escalation** — Automated privesc for Linux and Windows
- **Lateral Movement** — SSH/SOCKS tunneling, pivot chains, credential spraying
- **Persistence** — Establishes persistence mechanisms (opt-in)

### Stealth Operations
- **Timing Jitter** — Mimics human behavior with configurable delays
- **Traffic Mimicry** — Blends with normal business hours traffic
- **LOLBins** — Living-off-the-land binary usage
- **Payload Obfuscation** — Multiple encoding and fragmentation techniques

### Enterprise Integration
- **Acunetix** — Full scan management and vulnerability import
- **Burp Suite Enterprise** — Automated scan orchestration
- **Nessus** — Network vulnerability assessment integration
- **OWASP ZAP** — Web application security testing

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        AIPTX BEAST MODE                                 │
├─────────────────────────────────────────────────────────────────────────┤
│                       INTELLIGENCE LAYER                                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌─────────────┐ │
│  │ LLM Engine   │  │Attack Planner│  │Chain Builder │  │  Triage     │ │
│  │ (100+ LLMs)  │  │              │  │              │  │  Engine     │ │
│  └──────────────┘  └──────────────┘  └──────────────┘  └─────────────┘ │
├─────────────────────────────────────────────────────────────────────────┤
│                        ATTACK PIPELINE                                  │
│                                                                         │
│   RECON ───► SCAN ───► EXPLOIT ───► POST-EXPLOIT ───► PERSIST          │
│     │          │          │              │               │              │
│     ▼          ▼          ▼              ▼               ▼              │
│  Subdomains  Nuclei    SQLi/XSS    Cred Harvest    Lateral Move        │
│  Tech Stack  Nikto     RCE/SSRF    Priv Escalate   Tunneling           │
│  Endpoints   WAF Scan  Auth Bypass Cloud Secrets   Persistence         │
│                                                                         │
├─────────────────────────────────────────────────────────────────────────┤
│                     ENTERPRISE INTEGRATION                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐               │
│  │ Acunetix │  │Burp Suite│  │  Nessus  │  │OWASP ZAP │               │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘               │
├─────────────────────────────────────────────────────────────────────────┤
│                          OUTPUT                                         │
│      HTML Reports  │  JSON Export  │  REST API  │  Rich TUI            │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Installation

### Quick Install

```bash
# Recommended: Install with pipx (isolated environment)
pipx install aiptx

# Or with pip
pip install aiptx

# Full installation (all features)
pip install aiptx[full]
```

### From Source

```bash
git clone https://github.com/aiptx/aiptx.git
cd aiptx
pip install -e ".[full]"
```

### Setup Wizard

```bash
# Interactive setup (configures LLM, scanners, tools)
aiptx setup
```

---

## Quick Start

```bash
# Basic security scan
aiptx scan example.com

# AI-guided intelligent scanning
aiptx scan example.com --ai

# Full autonomous assessment
aiptx scan example.com --full --ai

# Enable exploitation (authorized testing only)
aiptx scan example.com --full --ai --exploit

# Check configuration status
aiptx status

# Start REST API server
aiptx api
```

---

## Configuration

### LLM Providers

AIPTX supports **100+ LLM providers** via LiteLLM:

```bash
# Anthropic
export ANTHROPIC_API_KEY="your-key"
export AIPT_LLM__MODEL="anthropic/claude-sonnet-4-20250514"

# OpenAI
export OPENAI_API_KEY="your-key"
export AIPT_LLM__MODEL="openai/gpt-4o"

# Azure OpenAI
export AZURE_API_KEY="your-key"
export AZURE_API_BASE="your-endpoint"
export AIPT_LLM__MODEL="azure/gpt-4"

# Local Models (Ollama)
export OLLAMA_API_BASE="http://localhost:11434"
export AIPT_LLM__MODEL="ollama/llama3"

# AWS Bedrock
export AWS_ACCESS_KEY_ID="your-key"
export AWS_SECRET_ACCESS_KEY="your-secret"
export AIPT_LLM__MODEL="bedrock/anthropic.claude-v2"
```

### Enterprise Scanners

```bash
# Acunetix
export ACUNETIX_URL="https://your-acunetix:3443"
export ACUNETIX_API_KEY="your-api-key"

# Burp Suite Enterprise
export BURP_URL="http://your-burp:1337/v0.1/"
export BURP_API_KEY="your-api-key"

# Nessus
export NESSUS_URL="https://your-nessus:8834"
export NESSUS_ACCESS_KEY="your-access-key"
export NESSUS_SECRET_KEY="your-secret-key"

# OWASP ZAP
export ZAP_URL="http://your-zap:8080"
export ZAP_API_KEY="your-api-key"
```

### Remote Execution (VPS)

```bash
# Run scans from remote VPS for OPSEC
export AIPT_VPS__HOST="your-vps-ip"
export AIPT_VPS__USER="ubuntu"
export AIPT_VPS__KEY_PATH="~/.ssh/id_rsa"
```

---

## Command Reference

| Command | Description |
|---------|-------------|
| `aiptx scan <target>` | Basic security scan |
| `aiptx scan <target> --ai` | AI-guided scanning |
| `aiptx scan <target> --full` | Comprehensive assessment |
| `aiptx scan <target> --exploit` | Enable exploitation |
| `aiptx scan <target> --stealth` | Stealth mode (timing jitter) |
| `aiptx scan <target> --container` | Container security |
| `aiptx scan <target> --secrets` | Secret detection |
| `aiptx setup` | Interactive configuration |
| `aiptx status` | Check configuration |
| `aiptx api` | Start REST API |
| `aiptx version` | Show version |

---

## Use Cases

| Scenario | Command |
|----------|---------|
| **Bug Bounty** | `aiptx scan target.com --ai --full` |
| **Penetration Testing** | `aiptx scan client.com --full --exploit` |
| **Red Team Assessment** | `aiptx scan target.corp --full --ai --exploit --stealth` |
| **DevSecOps Pipeline** | `aiptx scan app.com --container --secrets --json` |
| **Compliance Audit** | `aiptx scan system.com --full --html-report` |

---

## Security Tools (82+ Integrated)

AIPTX orchestrates 82+ security tools across categories:

| Category | Tools |
|----------|-------|
| **Reconnaissance** | subfinder, amass, httpx, dnsx, katana, assetfinder, waybackurls |
| **Scanning** | nuclei, nikto, ffuf, gobuster, dalfox, wpscan, trivy |
| **Exploitation** | sqlmap, hydra, commix, crackmapexec, impacket |
| **Post-Exploit** | linpeas, chisel, ligolo-ng, lazagne, mimikatz |
| **Active Directory** | bloodhound, kerbrute, enum4linux-ng, ldapdomaindump |
| **Cloud** | prowler, scoutsuite, pacu, cloudsploit |
| **Container** | trivy, grype, kube-hunter, docker-bench |
| **OSINT** | theHarvester, sherlock, spiderfoot, holehe |
| **Secrets** | gitleaks, trufflehog, detect-secrets |

### Auto-Installation

```bash
# Install all security tools automatically
aiptx setup

# Select option [1] Core tools or [2] Full installation
```

---

## API Reference

### REST API

```bash
# Start API server
aiptx api --host 0.0.0.0 --port 8000
```

### Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/projects` | GET/POST | Manage projects |
| `/projects/{id}/sessions` | POST | Create scan session |
| `/sessions/{id}/scan` | POST | Start scan |
| `/findings` | GET | Retrieve findings |
| `/tools` | GET | List available tools |
| `/cve/lookup` | POST | CVE lookup |

### Python SDK

```python
from aipt_v2 import AIPTClient

client = AIPTClient(base_url="http://localhost:8000")

# Create project
project = client.create_project(name="Test", target="example.com")

# Start scan
session = client.create_session(project_id=project.id)
client.start_scan(session_id=session.id, mode="full")

# Get findings
findings = client.get_findings(project_id=project.id)
```

---

## Output Formats

### HTML Report
Professional executive-ready vulnerability report with:
- Executive summary
- Vulnerability details with CVSS scores
- Remediation recommendations
- Evidence and screenshots

### JSON Export
```json
{
  "findings": [...],
  "metadata": {...},
  "statistics": {...}
}
```

### CI/CD Integration
```yaml
# GitHub Actions
- name: Security Scan
  run: |
    pip install aiptx
    aiptx scan ${{ env.TARGET }} --json > results.json
```

---

## Requirements

- **Python**: 3.9+
- **OS**: Linux, macOS, Windows (WSL recommended)
- **Memory**: 4GB+ recommended
- **Optional**: Docker for sandbox execution

---

## Supported Platforms

| Platform | Status |
|----------|--------|
| Linux (Ubuntu/Debian) | ✅ Full Support |
| Linux (RHEL/CentOS) | ✅ Full Support |
| Linux (Arch) | ✅ Full Support |
| Linux (openSUSE) | ✅ Full Support |
| macOS (Intel) | ✅ Full Support |
| macOS (Apple Silicon) | ✅ Full Support |
| Windows 10/11 | ✅ Full Support |
| Windows (WSL) | ✅ Recommended |

---

## Contributing

Contributions are welcome! Please read our [Contributing Guide](CONTRIBUTING.md) for details.

```bash
# Clone repository
git clone https://github.com/aiptx/aiptx.git
cd aiptx

# Create virtual environment
python -m venv .venv
source .venv/bin/activate

# Install development dependencies
pip install -e ".[dev]"

# Run tests
pytest tests/ -v
```

---

## License

MIT License — Free for commercial and personal use.

See [LICENSE](LICENSE) for details.

---

## Author

<div align="center">

**Satyam Rastogi**

Security Researcher & Developer

[![Website](https://img.shields.io/badge/Website-aiptx.io-blue?style=flat-square)](https://aiptx.io)
[![Email](https://img.shields.io/badge/Email-satyam%40aiptx.io-red?style=flat-square)](mailto:satyam@aiptx.io)
[![GitHub](https://img.shields.io/badge/GitHub-aiptx-black?style=flat-square&logo=github)](https://github.com/aiptx)

</div>

---

## Links

- **Website**: [aiptx.io](https://aiptx.io)
- **Documentation**: [aiptx.io/docs](https://aiptx.io/docs)
- **PyPI**: [pypi.org/project/aiptx](https://pypi.org/project/aiptx/)
- **GitHub**: [github.com/aiptx/aiptx](https://github.com/aiptx/aiptx)
- **Changelog**: [CHANGELOG.md](CHANGELOG.md)
- **Issues**: [GitHub Issues](https://github.com/aiptx/aiptx/issues)

---

<div align="center">

## Star History

[![Star History Chart](https://api.star-history.com/svg?repos=aiptx/aiptx&type=Date)](https://star-history.com/#aiptx/aiptx&Date)

---

**[aiptx.io](https://aiptx.io)** — Fully Autonomous AI-Powered Penetration Testing

Made with ❤️ by **Satyam Rastogi**

</div>
