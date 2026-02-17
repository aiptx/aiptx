"""
AIPT HTML Report Template

Generates a standalone HTML report with embedded CSS.

Supports two formats:
- Legacy: generate_html_report(data) - single list of findings
- V2: generate_html_report_v2(data, canonical) - separate sections for
      Confirmed/Needs Review/Suppressed findings
"""

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .generator import ReportData
    from ..pipeline.persistence import CanonicalFindings


def generate_html_report(data: "ReportData") -> str:
    """Generate standalone HTML report"""

    severity_counts = data.get_severity_counts()
    risk_score = data.get_risk_score()
    risk_rating = data.get_risk_rating()

    # Build findings HTML
    findings_html = ""

    for severity_name, findings, color in [
        ("Critical", data.critical_findings, "#dc2626"),
        ("High", data.high_findings, "#ea580c"),
        ("Medium", data.medium_findings, "#ca8a04"),
        ("Low", data.low_findings, "#2563eb"),
        ("Informational", data.info_findings, "#6b7280"),
    ]:
        if findings:
            findings_html += f"""
            <div class="severity-section">
                <h2 style="color: {color};">{severity_name} Severity ({len(findings)})</h2>
            """

            for i, finding in enumerate(findings, 1):
                evidence_html = ""
                if finding.evidence and data.config.include_evidence:
                    evidence_html = f"""
                    <div class="evidence">
                        <strong>Evidence:</strong>
                        <pre>{_escape_html(finding.evidence[:2000])}</pre>
                    </div>
                    """

                remediation_html = ""
                if finding.remediation and data.config.include_remediation:
                    remediation_html = f"""
                    <div class="remediation">
                        <strong>Remediation:</strong>
                        <p>{_escape_html(finding.remediation)}</p>
                    </div>
                    """

                ai_html = ""
                if finding.ai_reasoning and data.config.include_ai_reasoning:
                    ai_html = f"""
                    <div class="ai-reasoning">
                        <strong>AI Analysis:</strong>
                        <p>{_escape_html(finding.ai_reasoning[:500])}</p>
                    </div>
                    """

                findings_html += f"""
                <div class="finding" style="border-left-color: {color};">
                    <h3>{i}. {_escape_html(finding.title)}</h3>
                    <div class="finding-meta">
                        <span class="badge" style="background-color: {color};">{severity_name}</span>
                        <span class="badge source">{finding.source}</span>
                        <span class="vuln-type">{finding.vuln_type.value}</span>
                    </div>
                    <div class="finding-details">
                        <p><strong>URL:</strong> <code>{_escape_html(finding.url)}</code></p>
                        {f'<p><strong>Parameter:</strong> <code>{_escape_html(finding.parameter)}</code></p>' if finding.parameter else ''}
                        {f'<p><strong>Description:</strong> {_escape_html(finding.description)}</p>' if finding.description else ''}
                        {evidence_html}
                        {remediation_html}
                        {ai_html}
                    </div>
                </div>
                """

            findings_html += "</div>"

    # Risk color
    risk_colors = {
        "Critical": "#dc2626",
        "High": "#ea580c",
        "Medium": "#ca8a04",
        "Low": "#2563eb",
        "Informational": "#6b7280",
    }
    risk_color = risk_colors.get(risk_rating, "#6b7280")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report - {_escape_html(data.target)}</title>
    <style>
        :root {{
            --primary: #1e40af;
            --critical: #dc2626;
            --high: #ea580c;
            --medium: #ca8a04;
            --low: #2563eb;
            --info: #6b7280;
            --bg: #f8fafc;
            --card-bg: #ffffff;
            --text: #1e293b;
            --text-muted: #64748b;
            --border: #e2e8f0;
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }}

        header {{
            background: linear-gradient(135deg, var(--primary), #3b82f6);
            color: white;
            padding: 3rem 2rem;
            margin-bottom: 2rem;
            border-radius: 0 0 1rem 1rem;
        }}

        header h1 {{
            font-size: 2rem;
            margin-bottom: 0.5rem;
        }}

        header .meta {{
            opacity: 0.9;
            font-size: 0.95rem;
        }}

        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}

        .summary-card {{
            background: var(--card-bg);
            border-radius: 0.75rem;
            padding: 1.5rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}

        .summary-card h3 {{
            font-size: 0.875rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.5rem;
        }}

        .summary-card .value {{
            font-size: 2rem;
            font-weight: 700;
        }}

        .risk-score {{
            background: {risk_color};
            color: white;
        }}

        .severity-breakdown {{
            display: flex;
            gap: 0.5rem;
            margin-top: 1rem;
        }}

        .severity-dot {{
            display: flex;
            align-items: center;
            gap: 0.25rem;
            font-size: 0.875rem;
        }}

        .severity-dot::before {{
            content: '';
            width: 12px;
            height: 12px;
            border-radius: 50%;
        }}

        .severity-dot.critical::before {{ background: var(--critical); }}
        .severity-dot.high::before {{ background: var(--high); }}
        .severity-dot.medium::before {{ background: var(--medium); }}
        .severity-dot.low::before {{ background: var(--low); }}
        .severity-dot.info::before {{ background: var(--info); }}

        .severity-section {{
            margin-bottom: 2rem;
        }}

        .severity-section h2 {{
            font-size: 1.5rem;
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 2px solid var(--border);
        }}

        .finding {{
            background: var(--card-bg);
            border-radius: 0.75rem;
            padding: 1.5rem;
            margin-bottom: 1rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            border-left: 4px solid;
        }}

        .finding h3 {{
            font-size: 1.125rem;
            margin-bottom: 0.75rem;
        }}

        .finding-meta {{
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
            margin-bottom: 1rem;
        }}

        .badge {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            color: white;
        }}

        .badge.source {{
            background: var(--primary);
        }}

        .vuln-type {{
            font-size: 0.875rem;
            color: var(--text-muted);
        }}

        .finding-details p {{
            margin-bottom: 0.5rem;
        }}

        .finding-details code {{
            background: var(--bg);
            padding: 0.125rem 0.375rem;
            border-radius: 0.25rem;
            font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace;
            font-size: 0.875rem;
        }}

        .evidence, .remediation, .ai-reasoning {{
            margin-top: 1rem;
            padding: 1rem;
            background: var(--bg);
            border-radius: 0.5rem;
        }}

        .evidence pre {{
            white-space: pre-wrap;
            word-wrap: break-word;
            font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace;
            font-size: 0.8rem;
            max-height: 300px;
            overflow-y: auto;
        }}

        .ai-reasoning {{
            border-left: 3px solid var(--primary);
        }}

        footer {{
            text-align: center;
            padding: 2rem;
            color: var(--text-muted);
            font-size: 0.875rem;
        }}

        @media print {{
            body {{ background: white; }}
            .container {{ max-width: 100%; }}
            .finding {{ break-inside: avoid; }}
        }}
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>Security Assessment Report</h1>
            <div class="meta">
                <p><strong>Target:</strong> {_escape_html(data.target)}</p>
                <p><strong>Scan ID:</strong> {data.scan_id}</p>
                <p><strong>Date:</strong> {data.generated_at.strftime('%B %d, %Y at %H:%M UTC')}</p>
                <p><strong>Client:</strong> {_escape_html(data.config.client_name)} | <strong>Project:</strong> {_escape_html(data.config.project_name)}</p>
            </div>
        </div>
    </header>

    <div class="container">
        <section class="summary-grid">
            <div class="summary-card risk-score">
                <h3>Risk Rating</h3>
                <div class="value">{risk_rating}</div>
                <div style="font-size: 0.875rem; opacity: 0.9;">Score: {risk_score}/100</div>
            </div>

            <div class="summary-card">
                <h3>Total Findings</h3>
                <div class="value">{data.total_findings}</div>
                <div class="severity-breakdown">
                    <span class="severity-dot critical">{severity_counts['critical']}</span>
                    <span class="severity-dot high">{severity_counts['high']}</span>
                    <span class="severity-dot medium">{severity_counts['medium']}</span>
                    <span class="severity-dot low">{severity_counts['low']}</span>
                </div>
            </div>

            <div class="summary-card">
                <h3>AI Findings</h3>
                <div class="value">{data.ai_findings_count}</div>
                <div style="font-size: 0.875rem; color: var(--text-muted);">Strix AI-discovered vulnerabilities</div>
            </div>

            <div class="summary-card">
                <h3>Scan Sources</h3>
                <div class="value">{len(data.sources)}</div>
                <div style="font-size: 0.875rem; color: var(--text-muted);">{', '.join(data.sources) if data.sources else 'N/A'}</div>
            </div>
        </section>

        <section class="findings">
            {findings_html if findings_html else '<p style="text-align: center; color: var(--text-muted); padding: 3rem;">No vulnerabilities found.</p>'}
        </section>
    </div>

    <footer>
        <p>Generated by <strong>AIPT</strong> - AI-Powered Penetration Testing Framework</p>
        <p>Report generated on {data.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
    </footer>
</body>
</html>"""

    return html


def _escape_html(text: str) -> str:
    """Escape HTML special characters"""
    if not text:
        return ""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def generate_html_report_v2(
    data: "ReportData",
    canonical: "CanonicalFindings",
) -> str:
    """
    Generate HTML report V2 with separate sections for Confirmed/Needs Review/Suppressed.

    This is the preferred format for the new pipeline.
    """
    from ..models.finding_v2 import SeverityV2, VerificationStatusV2

    severity_counts = data.get_severity_counts()
    risk_score = data.get_risk_score()
    risk_rating = data.get_risk_rating()

    # Get findings by verification status
    confirmed_findings = canonical.get_confirmed_findings()
    needs_review_findings = canonical.get_needs_review_findings()
    suppressed_findings = canonical.get_suppressed_findings()

    # Build confirmed findings HTML (main section)
    confirmed_html = _build_findings_section_v2(
        confirmed_findings,
        "Confirmed Vulnerabilities",
        "confirmed",
        include_evidence=data.config.include_evidence,
        include_remediation=data.config.include_remediation,
        include_ai_reasoning=data.config.include_ai_reasoning,
    )

    # Build needs review HTML (collapsible)
    needs_review_html = _build_findings_section_v2(
        needs_review_findings,
        "Needs Manual Review",
        "needs-review",
        include_evidence=data.config.include_evidence,
        include_remediation=data.config.include_remediation,
        include_ai_reasoning=data.config.include_ai_reasoning,
        collapsed=True,
    )

    # Build suppressed HTML (collapsible, collapsed by default)
    suppressed_html = _build_findings_section_v2(
        suppressed_findings,
        "Suppressed (False Positives)",
        "suppressed",
        include_evidence=False,
        include_remediation=False,
        include_ai_reasoning=False,
        collapsed=True,
    )

    # Risk color
    risk_colors = {
        "Critical": "#dc2626",
        "High": "#ea580c",
        "Medium": "#ca8a04",
        "Low": "#2563eb",
        "Informational": "#6b7280",
    }
    risk_color = risk_colors.get(risk_rating, "#6b7280")

    # Tool status HTML
    tool_status_html = ""
    for name, entry in canonical.tool_status.items():
        status_color = "#22c55e" if entry.status == "completed" else "#dc2626"
        status_icon = "✓" if entry.status == "completed" else "✗"
        error_html = f'<span class="tool-error">{_escape_html(entry.error or "")}</span>' if entry.error else ""
        tool_status_html += f'''
        <div class="tool-status-item">
            <span class="tool-name">{_escape_html(name)}</span>
            <span class="tool-status" style="color: {status_color};">{status_icon} {entry.status}</span>
            <span class="tool-count">{entry.finding_count} findings</span>
            {error_html}
        </div>
        '''

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VAPT Report - {_escape_html(data.target)}</title>
    <style>
        :root {{
            --primary: #1e40af;
            --critical: #dc2626;
            --high: #ea580c;
            --medium: #ca8a04;
            --low: #2563eb;
            --info: #6b7280;
            --confirmed: #22c55e;
            --needs-review: #eab308;
            --suppressed: #9ca3af;
            --bg: #f8fafc;
            --card-bg: #ffffff;
            --text: #1e293b;
            --text-muted: #64748b;
            --border: #e2e8f0;
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: var(--bg);
            color: var(--text);
            line-height: 1.6;
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }}

        header {{
            background: linear-gradient(135deg, var(--primary), #3b82f6);
            color: white;
            padding: 3rem 2rem;
            margin-bottom: 2rem;
            border-radius: 0 0 1rem 1rem;
        }}

        header h1 {{
            font-size: 2rem;
            margin-bottom: 0.5rem;
        }}

        header .meta {{
            opacity: 0.9;
            font-size: 0.95rem;
        }}

        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}

        .summary-card {{
            background: var(--card-bg);
            border-radius: 0.75rem;
            padding: 1.5rem;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}

        .summary-card h3 {{
            font-size: 0.875rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            margin-bottom: 0.5rem;
        }}

        .summary-card .value {{
            font-size: 2rem;
            font-weight: 700;
        }}

        .risk-score {{
            background: {risk_color};
            color: white;
        }}

        .verification-summary {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 0.5rem;
            margin-top: 0.5rem;
        }}

        .verification-item {{
            text-align: center;
            padding: 0.5rem;
            border-radius: 0.5rem;
        }}

        .verification-item.confirmed {{ background: rgba(34, 197, 94, 0.1); color: var(--confirmed); }}
        .verification-item.needs-review {{ background: rgba(234, 179, 8, 0.1); color: var(--needs-review); }}
        .verification-item.suppressed {{ background: rgba(156, 163, 175, 0.1); color: var(--suppressed); }}

        .severity-breakdown {{
            display: flex;
            gap: 0.5rem;
            margin-top: 1rem;
        }}

        .severity-dot {{
            display: flex;
            align-items: center;
            gap: 0.25rem;
            font-size: 0.875rem;
        }}

        .severity-dot::before {{
            content: '';
            width: 12px;
            height: 12px;
            border-radius: 50%;
        }}

        .severity-dot.critical::before {{ background: var(--critical); }}
        .severity-dot.high::before {{ background: var(--high); }}
        .severity-dot.medium::before {{ background: var(--medium); }}
        .severity-dot.low::before {{ background: var(--low); }}
        .severity-dot.info::before {{ background: var(--info); }}

        .findings-section {{
            margin-bottom: 2rem;
        }}

        .section-header {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 1rem 1.5rem;
            background: var(--card-bg);
            border-radius: 0.75rem 0.75rem 0 0;
            border-bottom: 1px solid var(--border);
            cursor: pointer;
        }}

        .section-header h2 {{
            font-size: 1.25rem;
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}

        .section-header .count {{
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.875rem;
            font-weight: 600;
        }}

        .section-header.confirmed .count {{ background: var(--confirmed); color: white; }}
        .section-header.needs-review .count {{ background: var(--needs-review); color: white; }}
        .section-header.suppressed .count {{ background: var(--suppressed); color: white; }}

        .section-content {{
            background: var(--card-bg);
            border-radius: 0 0 0.75rem 0.75rem;
            padding: 1rem;
        }}

        .section-content.collapsed {{
            display: none;
        }}

        .toggle-icon {{
            transition: transform 0.2s;
        }}

        .collapsed .toggle-icon {{
            transform: rotate(-90deg);
        }}

        .finding {{
            background: var(--bg);
            border-radius: 0.75rem;
            padding: 1.5rem;
            margin-bottom: 1rem;
            border-left: 4px solid;
        }}

        .finding.critical {{ border-left-color: var(--critical); }}
        .finding.high {{ border-left-color: var(--high); }}
        .finding.medium {{ border-left-color: var(--medium); }}
        .finding.low {{ border-left-color: var(--low); }}
        .finding.info {{ border-left-color: var(--info); }}

        .finding h3 {{
            font-size: 1.125rem;
            margin-bottom: 0.75rem;
        }}

        .finding-meta {{
            display: flex;
            gap: 0.5rem;
            flex-wrap: wrap;
            margin-bottom: 1rem;
        }}

        .badge {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
            color: white;
        }}

        .badge.critical {{ background: var(--critical); }}
        .badge.high {{ background: var(--high); }}
        .badge.medium {{ background: var(--medium); }}
        .badge.low {{ background: var(--low); }}
        .badge.info {{ background: var(--info); }}

        .badge.source {{
            background: var(--primary);
        }}

        .badge.category {{
            background: var(--text-muted);
        }}

        .finding-details p {{
            margin-bottom: 0.5rem;
        }}

        .finding-details code {{
            background: var(--card-bg);
            padding: 0.125rem 0.375rem;
            border-radius: 0.25rem;
            font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace;
            font-size: 0.875rem;
        }}

        .evidence, .remediation, .ai-reasoning {{
            margin-top: 1rem;
            padding: 1rem;
            background: var(--card-bg);
            border-radius: 0.5rem;
        }}

        .evidence pre {{
            white-space: pre-wrap;
            word-wrap: break-word;
            font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace;
            font-size: 0.8rem;
            max-height: 300px;
            overflow-y: auto;
        }}

        .ai-reasoning {{
            border-left: 3px solid var(--primary);
        }}

        .tool-status {{
            background: var(--card-bg);
            border-radius: 0.75rem;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }}

        .tool-status h3 {{
            margin-bottom: 1rem;
            font-size: 1rem;
            color: var(--text-muted);
        }}

        .tool-status-item {{
            display: flex;
            align-items: center;
            gap: 1rem;
            padding: 0.5rem 0;
            border-bottom: 1px solid var(--border);
        }}

        .tool-status-item:last-child {{
            border-bottom: none;
        }}

        .tool-name {{
            font-weight: 600;
            min-width: 120px;
        }}

        .tool-count {{
            color: var(--text-muted);
            font-size: 0.875rem;
        }}

        .tool-error {{
            color: var(--critical);
            font-size: 0.75rem;
        }}

        footer {{
            text-align: center;
            padding: 2rem;
            color: var(--text-muted);
            font-size: 0.875rem;
        }}

        /* Enhanced Evidence Styles */
        .evidence-section {{
            margin-top: 1rem;
        }}

        .evidence-block, .http-evidence, .poc-block, .verification-evidence, .screenshots {{
            margin-bottom: 1rem;
            padding: 1rem;
            background: var(--card-bg);
            border-radius: 0.5rem;
            border: 1px solid var(--border);
        }}

        .evidence-header {{
            font-weight: 600;
            margin-bottom: 0.75rem;
            color: var(--text);
            font-size: 0.9rem;
        }}

        .evidence-content, .http-content {{
            white-space: pre-wrap;
            word-wrap: break-word;
            font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace;
            font-size: 0.8rem;
            max-height: 300px;
            overflow-y: auto;
            background: var(--bg);
            padding: 0.75rem;
            border-radius: 0.25rem;
            margin: 0;
        }}

        .http-block {{
            margin-bottom: 0.75rem;
        }}

        .http-label {{
            font-size: 0.75rem;
            font-weight: 600;
            color: var(--text-muted);
            text-transform: uppercase;
            margin-bottom: 0.25rem;
        }}

        .poc-block .copy-wrapper {{
            position: relative;
            display: flex;
            gap: 0.5rem;
            align-items: flex-start;
        }}

        .poc-command {{
            flex: 1;
            white-space: pre-wrap;
            word-wrap: break-word;
            font-family: 'SF Mono', Monaco, 'Cascadia Code', monospace;
            font-size: 0.8rem;
            background: #1e293b;
            color: #22c55e;
            padding: 0.75rem;
            border-radius: 0.25rem;
            margin: 0;
        }}

        .copy-btn {{
            background: var(--primary);
            color: white;
            border: none;
            padding: 0.5rem 0.75rem;
            border-radius: 0.25rem;
            cursor: pointer;
            font-size: 0.75rem;
            white-space: nowrap;
            transition: background 0.2s;
        }}

        .copy-btn:hover {{
            background: #1e40af;
        }}

        .copy-btn.copied {{
            background: #22c55e;
        }}

        .v-evidence-list {{
            margin: 0;
            padding-left: 1.5rem;
        }}

        .v-evidence-list li {{
            margin-bottom: 0.25rem;
            font-size: 0.875rem;
        }}

        /* Screenshot Gallery */
        .screenshot-gallery {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 1rem;
        }}

        .screenshot-item {{
            border: 1px solid var(--border);
            border-radius: 0.5rem;
            overflow: hidden;
        }}

        .screenshot-img {{
            width: 100%;
            height: auto;
            cursor: pointer;
            transition: transform 0.2s;
        }}

        .screenshot-img:hover {{
            transform: scale(1.02);
        }}

        .screenshot-caption {{
            padding: 0.5rem;
            font-size: 0.75rem;
            color: var(--text-muted);
            text-align: center;
            background: var(--bg);
        }}

        /* Verification Badge Styles */
        .verification-badge {{
            font-weight: 600;
        }}

        /* References */
        .references {{
            font-size: 0.8rem;
            color: var(--text-muted);
            margin-bottom: 0.75rem;
            padding: 0.5rem;
            background: var(--bg);
            border-radius: 0.25rem;
        }}

        .references a {{
            color: var(--primary);
            text-decoration: none;
        }}

        .references a:hover {{
            text-decoration: underline;
        }}

        .ref-item {{
            margin-right: 0.5rem;
        }}

        /* Confidence Indicator */
        .confidence-indicator {{
            font-size: 0.75rem;
            color: var(--text-muted);
            margin-left: auto;
        }}

        /* Filter Controls */
        .filter-controls {{
            display: flex;
            gap: 0.5rem;
            margin-bottom: 1rem;
            flex-wrap: wrap;
        }}

        .filter-btn {{
            padding: 0.5rem 1rem;
            border: 1px solid var(--border);
            border-radius: 0.5rem;
            background: var(--card-bg);
            cursor: pointer;
            font-size: 0.875rem;
            transition: all 0.2s;
        }}

        .filter-btn:hover {{
            background: var(--bg);
        }}

        .filter-btn.active {{
            background: var(--primary);
            color: white;
            border-color: var(--primary);
        }}

        /* Lightbox */
        .lightbox {{
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.9);
            z-index: 1000;
            justify-content: center;
            align-items: center;
        }}

        .lightbox.active {{
            display: flex;
        }}

        .lightbox img {{
            max-width: 90%;
            max-height: 90%;
            border-radius: 0.5rem;
        }}

        .lightbox-close {{
            position: absolute;
            top: 1rem;
            right: 1rem;
            color: white;
            font-size: 2rem;
            cursor: pointer;
            background: none;
            border: none;
        }}

        /* Finding visibility for filtering */
        .finding.hidden {{
            display: none;
        }}

        @media print {{
            body {{ background: white; }}
            .container {{ max-width: 100%; }}
            .finding {{ break-inside: avoid; }}
            .section-content.collapsed {{ display: block !important; }}
            .filter-controls {{ display: none; }}
            .lightbox {{ display: none !important; }}
        }}
    </style>
    <script>
        function toggleSection(sectionId) {{
            const content = document.getElementById(sectionId + '-content');
            const header = document.getElementById(sectionId + '-header');
            content.classList.toggle('collapsed');
            header.classList.toggle('collapsed');
        }}

        function copyToClipboard(btn) {{
            const text = btn.getAttribute('data-text');
            navigator.clipboard.writeText(text).then(() => {{
                btn.textContent = '✓ Copied!';
                btn.classList.add('copied');
                setTimeout(() => {{
                    btn.textContent = '📋 Copy';
                    btn.classList.remove('copied');
                }}, 2000);
            }});
        }}

        function openLightbox(src) {{
            const lightbox = document.getElementById('lightbox');
            const img = document.getElementById('lightbox-img');
            img.src = src;
            lightbox.classList.add('active');
        }}

        function closeLightbox() {{
            document.getElementById('lightbox').classList.remove('active');
        }}

        function filterFindings(status) {{
            const buttons = document.querySelectorAll('.filter-btn');
            buttons.forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');

            const findings = document.querySelectorAll('.finding');
            findings.forEach(finding => {{
                if (status === 'all') {{
                    finding.classList.remove('hidden');
                }} else {{
                    const verificationStatus = finding.getAttribute('data-verification');
                    if (verificationStatus === status) {{
                        finding.classList.remove('hidden');
                    }} else {{
                        finding.classList.add('hidden');
                    }}
                }}
            }});

            // Update counts
            updateFilteredCounts();
        }}

        function updateFilteredCounts() {{
            const sections = document.querySelectorAll('.findings-section');
            sections.forEach(section => {{
                const visibleFindings = section.querySelectorAll('.finding:not(.hidden)').length;
                const countBadge = section.querySelector('.count');
                if (countBadge) {{
                    const originalCount = section.querySelectorAll('.finding').length;
                    countBadge.textContent = visibleFindings === originalCount ? originalCount : `${{visibleFindings}}/${{originalCount}}`;
                }}
            }});
        }}

        // Close lightbox on escape
        document.addEventListener('keydown', function(e) {{
            if (e.key === 'Escape') closeLightbox();
        }});
    </script>
</head>
<body>
    <header>
        <div class="container">
            <h1>VAPT Security Assessment Report</h1>
            <div class="meta">
                <p><strong>Target:</strong> {_escape_html(data.target)}</p>
                <p><strong>Scan ID:</strong> {data.scan_id}</p>
                <p><strong>Date:</strong> {data.generated_at.strftime('%B %d, %Y at %H:%M UTC')}</p>
                <p><strong>Client:</strong> {_escape_html(data.config.client_name)} | <strong>Project:</strong> {_escape_html(data.config.project_name)}</p>
            </div>
        </div>
    </header>

    <div class="container">
        <section class="summary-grid">
            <div class="summary-card risk-score">
                <h3>Risk Rating</h3>
                <div class="value">{risk_rating}</div>
                <div style="font-size: 0.875rem; opacity: 0.9;">Score: {risk_score}/100</div>
            </div>

            <div class="summary-card">
                <h3>Total Findings</h3>
                <div class="value">{data.total_findings}</div>
                <div class="severity-breakdown">
                    <span class="severity-dot critical">{severity_counts['critical']}</span>
                    <span class="severity-dot high">{severity_counts['high']}</span>
                    <span class="severity-dot medium">{severity_counts['medium']}</span>
                    <span class="severity-dot low">{severity_counts['low']}</span>
                </div>
            </div>

            <div class="summary-card">
                <h3>Verification Status</h3>
                <div class="verification-summary">
                    <div class="verification-item confirmed">
                        <div style="font-size: 1.5rem; font-weight: 700;">{len(confirmed_findings)}</div>
                        <div style="font-size: 0.75rem;">Confirmed</div>
                    </div>
                    <div class="verification-item needs-review">
                        <div style="font-size: 1.5rem; font-weight: 700;">{len(needs_review_findings)}</div>
                        <div style="font-size: 0.75rem;">Needs Review</div>
                    </div>
                    <div class="verification-item suppressed">
                        <div style="font-size: 1.5rem; font-weight: 700;">{len(suppressed_findings)}</div>
                        <div style="font-size: 0.75rem;">Suppressed</div>
                    </div>
                </div>
            </div>

            <div class="summary-card">
                <h3>Pipeline Stats</h3>
                <div style="font-size: 0.875rem;">
                    <p>Raw: {canonical.summary.total_raw} → Deduped: {canonical.summary.after_dedup}</p>
                    <p>FP Rate: {((canonical.summary.suppressed_fp / canonical.summary.after_dedup * 100) if canonical.summary.after_dedup > 0 else 0):.1f}%</p>
                </div>
            </div>
        </section>

        <section class="tool-status">
            <h3>Tool Execution Status</h3>
            {tool_status_html if tool_status_html else '<p style="color: var(--text-muted);">No tool status available</p>'}
        </section>

        <section class="filter-controls">
            <button class="filter-btn active" onclick="filterFindings('all')">All Findings</button>
            <button class="filter-btn" onclick="filterFindings('confirmed')">✓ Confirmed Only</button>
            <button class="filter-btn" onclick="filterFindings('likely')">◐ Likely</button>
            <button class="filter-btn" onclick="filterFindings('needs_review')">? Needs Review</button>
        </section>

        <section class="findings">
            {confirmed_html}
            {needs_review_html}
            {suppressed_html}
        </section>
    </div>

    <!-- Lightbox for screenshots -->
    <div id="lightbox" class="lightbox" onclick="closeLightbox()">
        <button class="lightbox-close" onclick="closeLightbox()">&times;</button>
        <img id="lightbox-img" src="" alt="Screenshot preview"/>
    </div>

    <footer>
        <p>Generated by <strong>AIPTX</strong> - AI-Powered Penetration Testing Framework</p>
        <p>Pipeline Version: {canonical.pipeline_version} | Report generated on {data.generated_at.strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
    </footer>
</body>
</html>"""

    return html


def _build_findings_section_v2(
    findings: list,
    title: str,
    section_id: str,
    include_evidence: bool = True,
    include_remediation: bool = True,
    include_ai_reasoning: bool = True,
    collapsed: bool = False,
) -> str:
    """Build HTML for a findings section with enhanced evidence display"""
    from ..models.finding_v2 import SeverityV2, VerificationStatusV2

    if not findings:
        return ""

    severity_colors = {
        SeverityV2.CRITICAL: "#dc2626",
        SeverityV2.HIGH: "#ea580c",
        SeverityV2.MEDIUM: "#ca8a04",
        SeverityV2.LOW: "#2563eb",
        SeverityV2.INFO: "#6b7280",
    }

    # Verification status styling
    verification_styles = {
        VerificationStatusV2.CONFIRMED: ("✓ Confirmed", "#22c55e", "white"),
        VerificationStatusV2.LIKELY: ("◐ Likely", "#eab308", "white"),
        VerificationStatusV2.NEEDS_REVIEW: ("? Needs Review", "#f97316", "white"),
        VerificationStatusV2.MANUAL_REVIEW: ("⚠ Manual Review", "#f97316", "white"),
        VerificationStatusV2.SUPPRESSED_FP: ("✗ False Positive", "#9ca3af", "white"),
        VerificationStatusV2.PENDING: ("⏳ Pending", "#6b7280", "white"),
        VerificationStatusV2.IN_PROGRESS: ("⟳ Verifying", "#3b82f6", "white"),
    }

    findings_html = ""
    for i, finding in enumerate(findings, 1):
        color = severity_colors.get(finding.severity, "#6b7280")
        severity_class = finding.severity.value

        # Build verification badge with icon
        v_label, v_bg, v_color = verification_styles.get(
            finding.verification_status,
            ("Unknown", "#6b7280", "white")
        )
        verification_badge = f'''
        <span class="badge verification-badge" style="background: {v_bg}; color: {v_color};">
            {v_label}
        </span>
        '''

        # Evidence section with enhanced formatting
        evidence_html = ""
        if include_evidence:
            evidence_parts = []

            # Text evidence
            if finding.evidence:
                evidence_parts.append(f'''
                <div class="evidence-block">
                    <div class="evidence-header">📋 Evidence</div>
                    <pre class="evidence-content">{_escape_html(finding.evidence[:3000])}</pre>
                </div>
                ''')

            # HTTP Request/Response
            if finding.raw_request or finding.raw_response:
                http_evidence = '<div class="http-evidence">'
                http_evidence += '<div class="evidence-header">🔗 HTTP Exchange</div>'

                if finding.raw_request:
                    http_evidence += f'''
                    <div class="http-block">
                        <div class="http-label">Request</div>
                        <pre class="http-content">{_escape_html(finding.raw_request[:2000])}</pre>
                    </div>
                    '''

                if finding.raw_response:
                    http_evidence += f'''
                    <div class="http-block">
                        <div class="http-label">Response</div>
                        <pre class="http-content">{_escape_html(finding.raw_response[:2000])}</pre>
                    </div>
                    '''

                http_evidence += '</div>'
                evidence_parts.append(http_evidence)

            # PoC Command (curl)
            if finding.poc_command:
                evidence_parts.append(f'''
                <div class="poc-block">
                    <div class="evidence-header">🔧 Reproduction Command</div>
                    <div class="copy-wrapper">
                        <pre class="poc-command">{_escape_html(finding.poc_command)}</pre>
                        <button class="copy-btn" onclick="copyToClipboard(this)" data-text="{_escape_html(finding.poc_command)}">📋 Copy</button>
                    </div>
                </div>
                ''')

            # Verification evidence list
            if finding.verification_evidence:
                v_evidence = '<div class="verification-evidence">'
                v_evidence += '<div class="evidence-header">🔍 Verification Evidence</div>'
                v_evidence += '<ul class="v-evidence-list">'
                for ve in finding.verification_evidence[:5]:
                    v_evidence += f'<li>{_escape_html(ve)}</li>'
                v_evidence += '</ul></div>'
                evidence_parts.append(v_evidence)

            # Screenshots (embedded as data URIs)
            if hasattr(finding, 'screenshots') and finding.screenshots:
                screenshot_html = '<div class="screenshots">'
                screenshot_html += '<div class="evidence-header">📸 Screenshots</div>'
                screenshot_html += '<div class="screenshot-gallery">'
                for idx, screenshot in enumerate(finding.screenshots[:3]):
                    if isinstance(screenshot, dict):
                        data_uri = screenshot.get('data_uri', '')
                        caption = screenshot.get('description', f'Screenshot {idx + 1}')
                    else:
                        data_uri = screenshot
                        caption = f'Screenshot {idx + 1}'
                    if data_uri:
                        screenshot_html += f'''
                        <div class="screenshot-item">
                            <img src="{data_uri}" alt="{_escape_html(caption)}" class="screenshot-img" onclick="openLightbox(this.src)"/>
                            <div class="screenshot-caption">{_escape_html(caption)}</div>
                        </div>
                        '''
                screenshot_html += '</div></div>'
                evidence_parts.append(screenshot_html)

            if evidence_parts:
                evidence_html = f'''
                <div class="evidence-section">
                    {''.join(evidence_parts)}
                </div>
                '''

        # Remediation
        remediation_html = ""
        if finding.remediation and include_remediation:
            remediation_html = f'''
            <div class="remediation">
                <div class="evidence-header">🛠 Remediation</div>
                <p>{_escape_html(finding.remediation)}</p>
            </div>
            '''

        # AI Analysis
        ai_html = ""
        if finding.ai_reasoning and include_ai_reasoning:
            ai_html = f'''
            <div class="ai-reasoning">
                <div class="evidence-header">🤖 AI Analysis</div>
                <p>{_escape_html(finding.ai_reasoning[:500])}</p>
            </div>
            '''

        # CVE/CWE references
        refs_html = ""
        if finding.cve_ids or finding.cwe_id:
            refs_parts = []
            if finding.cve_ids:
                cve_links = ', '.join([f'<a href="https://nvd.nist.gov/vuln/detail/{cve}" target="_blank">{cve}</a>' for cve in finding.cve_ids[:3]])
                refs_parts.append(f'<span class="ref-item"><strong>CVE:</strong> {cve_links}</span>')
            if finding.cwe_id:
                refs_parts.append(f'<span class="ref-item"><strong>CWE:</strong> <a href="https://cwe.mitre.org/data/definitions/{finding.cwe_id.replace("CWE-", "")}.html" target="_blank">{finding.cwe_id}</a></span>')
            if finding.cvss_score:
                refs_parts.append(f'<span class="ref-item"><strong>CVSS:</strong> {finding.cvss_score}</span>')
            refs_html = f'<div class="references">{" | ".join(refs_parts)}</div>'

        # Confidence indicator
        confidence_html = ""
        if hasattr(finding, 'ai_confidence') and finding.ai_confidence:
            conf_pct = int(finding.ai_confidence * 100)
            conf_color = "#22c55e" if conf_pct >= 80 else "#eab308" if conf_pct >= 50 else "#f97316"
            confidence_html = f'''
            <div class="confidence-indicator">
                <span style="color: {conf_color};">●</span> Confidence: {conf_pct}%
            </div>
            '''

        findings_html += f'''
        <div class="finding {severity_class}" data-verification="{finding.verification_status.value}">
            <h3>{i}. {_escape_html(finding.title)}</h3>
            <div class="finding-meta">
                <span class="badge {severity_class}">{finding.severity.value.title()}</span>
                <span class="badge source">{_escape_html(finding.source_tool)}</span>
                <span class="badge category">{finding.category.value.replace('_', ' ').title()}</span>
                {verification_badge}
                {confidence_html}
            </div>
            {refs_html}
            <div class="finding-details">
                <p><strong>URL:</strong> <code>{_escape_html(finding.url)}</code></p>
                {f'<p><strong>Parameter:</strong> <code>{_escape_html(finding.parameter)}</code></p>' if finding.parameter else ''}
                {f'<p><strong>Method:</strong> <code>{finding.method}</code></p>' if finding.method and finding.method != 'GET' else ''}
                {f'<p><strong>Description:</strong> {_escape_html(finding.description)}</p>' if finding.description else ''}
                {evidence_html}
                {remediation_html}
                {ai_html}
            </div>
        </div>
        '''

    collapsed_class = "collapsed" if collapsed else ""

    return f'''
    <div class="findings-section">
        <div id="{section_id}-header" class="section-header {section_id} {collapsed_class}" onclick="toggleSection('{section_id}')">
            <h2>
                <span class="toggle-icon">▼</span>
                {title}
            </h2>
            <span class="count">{len(findings)}</span>
        </div>
        <div id="{section_id}-content" class="section-content {collapsed_class}">
            {findings_html}
        </div>
    </div>
    '''
