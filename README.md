<div align="center">

# AIPTX - AI-Powered Penetration Testing Framework

### 🌐 **[aiptx.io](https://aiptx.io)** — Official Website

[![Website](https://img.shields.io/badge/Website-aiptx.io-blue?style=for-the-badge&logo=safari)](https://aiptx.io)
[![PyPI version](https://img.shields.io/pypi/v/aiptx?style=for-the-badge&logo=pypi&logoColor=white)](https://pypi.org/project/aiptx/)
[![Downloads](https://img.shields.io/pepy/dt/aiptx?style=for-the-badge&logo=python&logoColor=white)](https://pepy.tech/project/aiptx)
[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

**AI-Powered Security Assessment & Vulnerability Discovery Platform**

[Getting Started](https://aiptx.io/docs) • [Documentation](https://aiptx.io/docs) • [API Reference](https://aiptx.io/api) • [Community](https://aiptx.io/community)

</div>

---

**AIPTX** is an intelligent penetration testing framework that leverages Large Language Models (LLMs) to autonomously conduct security assessments. It orchestrates comprehensive vulnerability discovery through AI-guided decision making, smart prioritization, and automated reporting.

---

## Key Features

### AI Intelligence Layer
- **LLM-Guided Scanning** — AI decides which techniques to apply based on discovered information
- **Smart Vulnerability Triage** — Prioritizes findings by real-world exploitability, not just severity scores
- **Attack Chain Detection** — Identifies how multiple findings combine into critical attack paths
- **Semantic Tool Selection** — RAG-based matching of objectives to optimal assessment techniques

### Comprehensive Assessment Capabilities
- **Reconnaissance** — Subdomain discovery, DNS enumeration, technology fingerprinting, historical data analysis
- **Vulnerability Scanning** — Web application testing, configuration analysis, secret detection, container security
- **Exploitation Testing** — SQL injection, XSS, command injection, credential testing (opt-in)
- **Post-Exploitation** — Privilege escalation detection, credential extraction, process monitoring

### Enterprise Integration
- Native API support for leading commercial security platforms
- Unified interface for both open-source and enterprise scanning solutions
- Seamless integration into existing security workflows

### Professional Output
- **HTML Reports** — Executive-ready vulnerability documentation
- **JSON Export** — CI/CD pipeline integration
- **REST API** — Programmatic access for automation
- **Terminal UI** — Real-time progress monitoring

---

## Installation

```bash
# Recommended: Install with pipx
pipx install aiptx

# Or with pip
pip install aiptx

# Full installation (ML features, browser automation, proxy)
pip install aiptx[full]
```

**Requirements:** Python 3.9+

---

## Quick Start

```bash
# Basic security scan
aiptx scan example.com

# AI-guided intelligent scanning
aiptx scan example.com --ai

# Comprehensive assessment (all capabilities)
aiptx scan example.com --full

# Container security assessment
aiptx scan example.com --container

# Secret and credential detection
aiptx scan example.com --secrets

# Check configuration
aiptx status

# Start REST API server
aiptx api
```

---

## How It Works

AIPTX operates on a **Think → Select → Execute → Learn** loop:

```
┌─────────────────────────────────────────────────────────────────┐
│                         AIPTX Framework                         │
├─────────────────────────────────────────────────────────────────┤
│                     AI INTELLIGENCE LAYER                       │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐             │
│  │ LLM Engine  │  │   Scoring   │  │Attack Chain │             │
│  │ (100+ LLMs) │  │   Engine    │  │  Detection  │             │
│  └─────────────┘  └─────────────┘  └─────────────┘             │
├─────────────────────────────────────────────────────────────────┤
│                    ASSESSMENT PIPELINE                          │
│  RECON ──────► SCAN ──────► EXPLOIT ──────► POST-EXPLOIT       │
├─────────────────────────────────────────────────────────────────┤
│                         OUTPUT                                  │
│     HTML Reports  │  JSON Export  │  REST API  │  TUI          │
└─────────────────────────────────────────────────────────────────┘
```

1. **Think** — AI analyzes target and current findings
2. **Select** — Chooses appropriate assessment techniques via semantic search
3. **Execute** — Runs assessments in isolated environments
4. **Learn** — Extracts findings and determines next steps

---

## LLM Configuration

AIPTX supports **100+ LLM providers** for AI-guided scanning:

```bash
# Anthropic Claude
export ANTHROPIC_API_KEY="your-key"

# OpenAI
export OPENAI_API_KEY="your-key"

# Azure OpenAI
export AZURE_API_KEY="your-key"
export AZURE_API_BASE="your-endpoint"

# Local models (for offline/private use)
export OLLAMA_API_BASE="http://localhost:11434"
```

---

## Use Cases

| Scenario | Command |
|----------|---------|
| **Bug Bounty** | `aiptx scan target.com --ai --full` |
| **Penetration Testing** | `aiptx scan client.com --full` |
| **DevSecOps Pipeline** | `aiptx scan app.com --container --secrets --json` |
| **Red Team Operations** | `aiptx scan target.corp --ai --exploit --full` |

---

## Command Reference

| Command | Description |
|---------|-------------|
| `aiptx scan <target>` | Run security assessment |
| `aiptx scan <target> --ai` | Enable AI-guided scanning |
| `aiptx scan <target> --full` | Comprehensive assessment |
| `aiptx scan <target> --quick` | Fast essential checks only |
| `aiptx scan <target> --exploit` | Enable exploitation testing |
| `aiptx scan <target> --container` | Container security scanning |
| `aiptx scan <target> --secrets` | Credential/secret detection |
| `aiptx status` | Check configuration |
| `aiptx version` | Show version |
| `aiptx api` | Start REST API server |

---

## Why AIPTX?

| Capability | AIPTX | Traditional Approach |
|------------|-------|---------------------|
| AI-Guided Decisions | ✅ | ❌ Manual |
| Unified Interface | ✅ | ❌ Multiple tools |
| Attack Chain Analysis | ✅ | ❌ Manual correlation |
| Smart Prioritization | ✅ | ❌ CVSS only |
| Professional Reports | ✅ | ❌ Manual documentation |
| Single Command | ✅ | ❌ Complex scripts |

---

## Requirements

- **Python**: 3.9 or higher
- **OS**: Linux, macOS, Windows (WSL recommended)
- **Optional**: Docker for isolated execution

---

## License

MIT License — Free for commercial and personal use.

---

## Author

**Satyam Rastogi** — Security Researcher & Developer

---

## Links

- 🌐 **[aiptx.io](https://aiptx.io)** — Official Website & Documentation
- 📦 [PyPI Package](https://pypi.org/project/aiptx/)
- 💻 [GitHub Repository](https://github.com/satyamrastogi/aiptx)
- 📋 [Changelog](https://github.com/satyamrastogi/aiptx/blob/main/CHANGELOG.md)
- 📖 [Documentation](https://aiptx.io/docs)
- 💬 [Community & Support](https://aiptx.io/community)

---

<div align="center">

**[aiptx.io](https://aiptx.io)** — Intelligent Security Assessment, Simplified.

Made with ❤️ by [Satyam Rastogi](https://aiptx.io)

</div>
