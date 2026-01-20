# Changelog

All notable changes to AIPTX will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.7] - 2025-01-20

### Fixed
- **Windows scan module error** - Fixed `No module named 'orchestrator'` error
  - Improved error handling when optional dependencies are missing
  - Now shows helpful message directing users to install `aiptx[full]`
  - Fixed incorrect entry point reference in pyproject.toml
  - Updated docstring examples to use correct import path

### Changed
- **Better dependency handling** - Scan command now gracefully handles missing optional dependencies
  - Clear error message explaining what's missing
  - Instructions on how to install full dependencies

## [2.0.6] - 2025-01-15

### Added
- **Stunning Terminal UI** - Beautiful branded interactive shell experience
  - ASCII art AIPTX logo with gradient colors (cyan → blue → magenta)
  - Stylish command table with emoji icons
  - Quick links to aiptx.io documentation and community
  - Modern prompt style with `aiptx →` indicator
  - Branded goodbye message with website link
  - Version and website displayed prominently in banner

### Changed
- **Interactive shell** - Complete visual overhaul
  - Professional, eye-catching welcome screen
  - Quick reference command table for new users
  - Consistent branding throughout the experience

## [2.0.5] - 2025-01-15

### Fixed
- **Windows compatibility** - Fixed crash on Windows when running interactive shell
  - `select.select()` doesn't work with stdin on Windows
  - Now uses `msvcrt.kbhit()` for Windows platform
  - Properly detects platform and uses appropriate method

## [2.0.4] - 2025-01-15

### Added
- **Official Website** - [aiptx.io](https://aiptx.io) now featured prominently
  - Updated README with website badges and links
  - Added documentation, community, and support links
  - Homepage URL updated to aiptx.io in package metadata

### Changed
- **README.md** - Enhanced branding and presentation
  - Centered header with official website link
  - Modern badge styling with logos
  - Quick navigation links to docs, API, and community
  - Updated footer with website attribution

## [2.0.3] - 2025-01-14

### Improved
- **First-run user experience** - Clean, helpful guidance for new users
  - Removed noisy urllib3/deprecation warnings
  - Default log level changed from INFO to WARNING for cleaner output
  - Beautiful Rich panels with clear setup instructions
  - First-run detection shows welcome message with quick start guide

### Fixed
- **Configuration errors** - No longer truncated or cryptic
  - Full error messages with actionable fix instructions
  - Clear guidance to run `aiptx setup` or set environment variables
  - Proper Rich formatting for all error displays

### Changed
- **CLI output** - Professional, clean interface
  - `aiptx scan` shows elegant progress and completion messages
  - `aiptx status` displays configuration tables without log noise
  - Verbose mode (`-v`, `-vv`) enables INFO/DEBUG logging when needed

## [2.0.1] - 2024-12-16

### Added
- **LICENSE file** - MIT License now included in package
- **MANIFEST.in** - Proper package data inclusion for PyPI
- **Enhanced SEO** - Improved discoverability on PyPI and search engines
  - Expanded keywords from 9 to 46 terms
  - Increased classifiers from 14 to 37 categories
  - Added comparison tables and use case examples to README

### Changed
- **README.md** - Complete rewrite for better SEO and user experience
  - Added 6 badges (PyPI, Downloads, Python, License, Code Style, Security)
  - Added "Why AIPTX?" comparison table
  - Added detailed tool coverage tables by phase
  - Added architecture diagram
  - Added use case examples (Bug Bounty, Pentest, DevSecOps, Red Team)
  - Added competitor comparison table
  - Added keyword section for search indexing
- **pyproject.toml** - Enhanced metadata
  - License now references LICENSE file
  - Added Python 3.13 support classifier
  - Added Framework :: FastAPI classifier
  - Added multiple OS platform classifiers

### Fixed
- **Python 3.9 compatibility** - Added `from __future__ import annotations` to 16 modules for union type syntax support
- **Import path fixes** - Fixed 15+ incorrect relative imports to use full `aipt_v2.` package prefix
  - `from telemetry.tracer` → `from aipt_v2.telemetry.tracer` (8 locations)
  - `from tools.agents_graph` → `from aipt_v2.tools.agents_graph` (5 locations)
  - `from database.models` → `from aipt_v2.database.models` (1 location)
- **Test imports** - Fixed sys.path configuration in test files
- **Package structure** - Ensured proper src layout packaging

## [2.0.0] - 2024-12-14

### Added
- **AI Intelligence Layer**
  - LLM-guided scanning with LiteLLM (100+ providers)
  - Smart triage based on real-world exploitability
  - Attack chain detection for vulnerability chaining
  - RAG-based tool selection using BGE embeddings

- **36+ Security Tools Integration**
  - Phase 1 RECON: subfinder, assetfinder, amass, httpx, nmap, waybackurls, theHarvester, dnsrecon, wafw00f, whatweb
  - Phase 2 SCAN: nuclei, nikto, wpscan, ffuf, gobuster, dirsearch, sslscan, testssl, gitleaks, trufflehog, trivy
  - Phase 3 EXPLOIT: sqlmap, commix, xsstrike, hydra, searchsploit
  - Phase 4 POST-EXPLOIT: linpeas, winpeas, pspy, lazagne

- **Enterprise Scanner Integration**
  - Acunetix API integration (24KB wrapper)
  - Burp Suite Professional API integration (21KB wrapper)
  - Nessus API integration (18KB wrapper)
  - OWASP ZAP API integration (18KB wrapper)

- **Intelligence Module**
  - CVE scoring and analysis (42KB)
  - Attack chain generation (27KB)
  - Finding triage and prioritization (24KB)
  - Authenticated scanning support (17KB)
  - Scope enforcement (16KB)
  - RAG tool selection (8KB)
  - ExploitDB, GitHub, Google searchers

- **Professional Output**
  - HTML vulnerability reports
  - JSON export for CI/CD
  - REST API server (FastAPI)
  - Rich TUI with real-time progress

- **Runtime Options**
  - Docker container execution
  - Local execution
  - VPS remote execution via SSH

### Architecture
- Modular design with clear separation of concerns
- Async-first implementation for performance
- Plugin system for future extensibility
- Database persistence with SQLAlchemy

## [1.0.0] - 2024-11-01

### Added
- Initial release
- Basic scanning functionality
- Database integration
- REST API

---

## Roadmap

### Planned for v2.1.0
- [ ] Cloud security scanning (AWS, Azure, GCP)
- [ ] Active Directory attack module
- [ ] API security testing suite
- [ ] Compliance reporting (PCI-DSS, HIPAA, SOC2)

### Planned for v2.2.0
- [ ] Web-based dashboard
- [ ] Team collaboration features
- [ ] Scheduled scanning
- [ ] Notification integrations (Slack, Teams, Discord)

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE](LICENSE) for details.
