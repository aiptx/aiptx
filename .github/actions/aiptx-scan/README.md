# AIPTX Security Scan Action

AI-powered security scanning with validated findings and GitHub Security tab integration.

## Features

- **Zero False Positives**: PoC validation confirms exploitability
- **SARIF Output**: Native GitHub Security tab integration
- **Multi-Agent Scanning**: SAST + DAST + Business Logic
- **PR Blocking**: Fail builds based on severity thresholds
- **AI-Native**: Intelligent attack surface analysis

## Usage

### Basic Usage

```yaml
- name: AIPTX Security Scan
  uses: aiptx/aiptx-scan@v4
  with:
    target: 'https://your-app.com'
```

### Full Example

```yaml
name: Security Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: AIPTX Security Scan
        id: scan
        uses: aiptx/aiptx-scan@v4
        with:
          target: 'https://staging.your-app.com'
          source-path: '.'
          mode: 'full'
          fail-on-severity: 'high'
          enable-poc: 'true'

      - name: Check Results
        if: always()
        run: |
          echo "Total findings: ${{ steps.scan.outputs.findings-count }}"
          echo "Critical: ${{ steps.scan.outputs.critical-count }}"
          echo "Validated: ${{ steps.scan.outputs.validated-count }}"
```

### Source Code Only (SAST)

```yaml
- name: AIPTX SAST Scan
  uses: aiptx/aiptx-scan@v4
  with:
    target: '.'
    mode: 'standard'
    fail-on-severity: 'high'
```

### Combined Source + Runtime

```yaml
- name: AIPTX Full Scan
  uses: aiptx/aiptx-scan@v4
  with:
    target: 'https://staging.example.com'
    source-path: '.'
    mode: 'full'
    enable-poc: 'true'
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `target` | Target URL or path to scan | Yes | - |
| `mode` | Scan mode: quick, standard, full, ai | No | `standard` |
| `source-path` | Path to source code for SAST | No | - |
| `fail-on-severity` | Fail if findings >= severity | No | `high` |
| `sarif-output` | SARIF output file path | No | `aiptx-results.sarif` |
| `github-token` | GitHub token for PR comments | No | `${{ github.token }}` |
| `enable-poc` | Enable PoC validation | No | `true` |
| `timeout` | Scan timeout in minutes | No | `30` |
| `config-file` | Path to config file | No | - |

## Outputs

| Output | Description |
|--------|-------------|
| `findings-count` | Total number of findings |
| `critical-count` | Number of critical findings |
| `high-count` | Number of high severity findings |
| `validated-count` | Number of PoC-validated findings |
| `sarif-path` | Path to SARIF report |

## Scan Modes

| Mode | Description | Duration |
|------|-------------|----------|
| `quick` | Fast scan, common vulnerabilities only | ~2 min |
| `standard` | Balanced scan, most vulnerabilities | ~10 min |
| `full` | Comprehensive scan including business logic | ~30 min |
| `ai` | AI-driven adaptive scanning | Variable |

## Severity Levels

| Level | Description | SARIF Level |
|-------|-------------|-------------|
| `critical` | Actively exploitable, immediate risk | error |
| `high` | Significant security risk | error |
| `medium` | Moderate security risk | warning |
| `low` | Minor security concern | note |
| `info` | Informational finding | note |

## Security Tab Integration

Findings are automatically uploaded to GitHub's Security tab:

1. Go to your repository's **Security** tab
2. Click **Code scanning alerts**
3. View AIPTX findings with full details

## PR Comments

When running on pull requests, AIPTX will:

1. Add inline annotations on affected lines
2. Post a summary comment with findings
3. Block merge if severity threshold exceeded

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success, no blocking findings |
| 1 | Critical findings detected |
| 2 | High findings detected |
| 3 | Medium findings detected |
| 10 | Scan failed |
| 11 | Configuration error |

## License

MIT License - See [LICENSE](../../../LICENSE)
