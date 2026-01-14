"""
Compliance Report Generator

Generates compliance-specific reports from security findings.
Supports multiple formats and frameworks.

Usage:
    from aipt_v2.compliance import generate_compliance_report

    report = generate_compliance_report(
        findings,
        frameworks=["owasp", "pci"],
        format="html"
    )
"""

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional

from aipt_v2.compliance.framework_mapper import ComplianceMapper, ComplianceMapping
from aipt_v2.compliance.owasp_mapping import OWASPMapper, OWASP_TOP_10
from aipt_v2.compliance.pci_mapping import PCIMapper, PCI_DSS_REQUIREMENTS
from aipt_v2.compliance.nist_mapping import NISTMapper, NIST_CONTROLS


@dataclass
class ComplianceScore:
    """Compliance score for a framework."""
    framework: str
    total_controls: int
    compliant_controls: int
    non_compliant_controls: int
    score_percentage: float
    risk_level: str  # Low, Medium, High, Critical


@dataclass
class ComplianceReport:
    """Complete compliance report."""
    generated_at: str
    target: str
    frameworks: List[str]
    total_findings: int
    mapped_findings: int
    scores: Dict[str, ComplianceScore]
    findings_by_framework: Dict[str, List[ComplianceMapping]]
    executive_summary: str
    remediation_priorities: List[Dict]
    metadata: Dict[str, Any] = field(default_factory=dict)


class ComplianceReportGenerator:
    """
    Generates comprehensive compliance reports.

    Maps findings to frameworks and produces
    detailed reports with scores and priorities.
    """

    def __init__(self):
        self.mapper = ComplianceMapper()
        self.owasp_mapper = OWASPMapper()
        self.pci_mapper = PCIMapper()
        self.nist_mapper = NISTMapper()

    def generate(
        self,
        findings: List[Dict],
        frameworks: List[str] = None,
        target: str = ""
    ) -> ComplianceReport:
        """
        Generate compliance report from findings.

        Args:
            findings: List of security findings
            frameworks: Frameworks to include
            target: Target name/URL

        Returns:
            ComplianceReport
        """
        frameworks = frameworks or ["owasp", "pci", "nist"]

        # Map findings
        mappings = self.mapper.map_findings(findings, frameworks)

        # Group by framework
        findings_by_framework = self._group_by_framework(mappings, frameworks)

        # Calculate scores
        scores = {}
        for fw in frameworks:
            scores[fw] = self._calculate_score(fw, findings_by_framework.get(fw, []))

        # Generate executive summary
        executive_summary = self._generate_executive_summary(
            target, scores, len(findings), len(mappings)
        )

        # Prioritize remediation
        priorities = self._prioritize_remediation(mappings)

        return ComplianceReport(
            generated_at=datetime.now(timezone.utc).isoformat(),
            target=target,
            frameworks=frameworks,
            total_findings=len(findings),
            mapped_findings=len(mappings),
            scores=scores,
            findings_by_framework=findings_by_framework,
            executive_summary=executive_summary,
            remediation_priorities=priorities,
            metadata={
                "generator": "AIPTX Compliance Report Generator",
                "version": "1.0"
            }
        )

    def _group_by_framework(
        self,
        mappings: List[ComplianceMapping],
        frameworks: List[str]
    ) -> Dict[str, List[ComplianceMapping]]:
        """Group mappings by framework."""
        grouped = {fw: [] for fw in frameworks}

        for mapping in mappings:
            for fw in frameworks:
                if fw in mapping.frameworks or fw.replace("_", "") in str(mapping.frameworks):
                    grouped[fw].append(mapping)

        return grouped

    def _calculate_score(
        self,
        framework: str,
        mappings: List[ComplianceMapping]
    ) -> ComplianceScore:
        """Calculate compliance score for a framework."""
        if framework == "owasp":
            total_controls = 10  # A01-A10
            controls_with_findings = len(set(
                m.frameworks.get("owasp", type("", (), {"category_id": ""})()).category_id
                for m in mappings if "owasp" in m.frameworks
            ))
        elif framework == "pci":
            total_controls = len(PCI_DSS_REQUIREMENTS)
            controls_with_findings = len(set(
                m.frameworks.get("pci_dss", type("", (), {"category_id": ""})()).category_id
                for m in mappings if "pci_dss" in m.frameworks
            ))
        elif framework == "nist":
            total_controls = len(NIST_CONTROLS)
            controls_with_findings = len(set(
                m.frameworks.get("nist", type("", (), {"category_id": ""})()).category_id
                for m in mappings if "nist" in m.frameworks
            ))
        else:
            total_controls = 100
            controls_with_findings = len(mappings)

        compliant = total_controls - controls_with_findings
        score_pct = (compliant / total_controls * 100) if total_controls > 0 else 100

        # Determine risk level
        if score_pct >= 90:
            risk_level = "Low"
        elif score_pct >= 70:
            risk_level = "Medium"
        elif score_pct >= 50:
            risk_level = "High"
        else:
            risk_level = "Critical"

        return ComplianceScore(
            framework=framework,
            total_controls=total_controls,
            compliant_controls=compliant,
            non_compliant_controls=controls_with_findings,
            score_percentage=round(score_pct, 1),
            risk_level=risk_level
        )

    def _generate_executive_summary(
        self,
        target: str,
        scores: Dict[str, ComplianceScore],
        total_findings: int,
        mapped_findings: int
    ) -> str:
        """Generate executive summary text."""
        summary_parts = [
            f"Compliance Assessment Report for {target or 'Target System'}",
            "",
            f"Assessment Date: {datetime.now().strftime('%Y-%m-%d')}",
            f"Total Security Findings: {total_findings}",
            f"Compliance-Mapped Findings: {mapped_findings}",
            "",
            "Framework Compliance Scores:",
        ]

        for fw, score in scores.items():
            summary_parts.append(
                f"  - {fw.upper()}: {score.score_percentage}% "
                f"({score.compliant_controls}/{score.total_controls} controls compliant) "
                f"- Risk Level: {score.risk_level}"
            )

        # Overall assessment
        avg_score = sum(s.score_percentage for s in scores.values()) / len(scores) if scores else 0

        summary_parts.extend([
            "",
            f"Overall Compliance Score: {avg_score:.1f}%",
            "",
            "Key Observations:"
        ])

        # Add key observations based on scores
        for fw, score in scores.items():
            if score.non_compliant_controls > 0:
                summary_parts.append(
                    f"  - {score.non_compliant_controls} {fw.upper()} "
                    f"controls require attention"
                )

        return "\n".join(summary_parts)

    def _prioritize_remediation(
        self,
        mappings: List[ComplianceMapping]
    ) -> List[Dict]:
        """Prioritize remediation based on risk and compliance impact."""
        priorities = []

        for mapping in mappings:
            priority_score = mapping.risk_score

            # Boost priority for PCI-DSS issues
            if "pci_dss" in mapping.frameworks:
                priority_score += 2

            # Boost priority for critical severity
            if mapping.severity == "critical":
                priority_score += 3
            elif mapping.severity == "high":
                priority_score += 1

            priorities.append({
                "cwe_id": mapping.cwe_id,
                "cwe_name": mapping.cwe_name,
                "severity": mapping.severity,
                "risk_score": mapping.risk_score,
                "priority_score": priority_score,
                "frameworks_affected": list(mapping.frameworks.keys()),
                "remediation_priority": mapping.remediation_priority
            })

        # Sort by priority score descending
        priorities.sort(key=lambda x: x["priority_score"], reverse=True)

        return priorities

    def to_html(self, report: ComplianceReport) -> str:
        """Convert report to HTML format."""
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Compliance Report - {report.target}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #333; border-bottom: 2px solid #666; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .summary {{ background: #f5f5f5; padding: 20px; border-radius: 5px; }}
        .score-card {{ display: inline-block; margin: 10px; padding: 15px;
                      background: #fff; border: 1px solid #ddd; border-radius: 5px; }}
        .score-low {{ border-left: 4px solid #4CAF50; }}
        .score-medium {{ border-left: 4px solid #FFC107; }}
        .score-high {{ border-left: 4px solid #FF9800; }}
        .score-critical {{ border-left: 4px solid #F44336; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; }}
        th {{ background: #f0f0f0; }}
        .severity-critical {{ background: #ffebee; }}
        .severity-high {{ background: #fff3e0; }}
        .severity-medium {{ background: #fff8e1; }}
        .severity-low {{ background: #e8f5e9; }}
        pre {{ background: #f5f5f5; padding: 15px; overflow-x: auto; }}
    </style>
</head>
<body>
    <h1>Compliance Assessment Report</h1>
    <p><strong>Target:</strong> {report.target}</p>
    <p><strong>Generated:</strong> {report.generated_at}</p>

    <h2>Executive Summary</h2>
    <div class="summary">
        <pre>{report.executive_summary}</pre>
    </div>

    <h2>Compliance Scores</h2>
    <div class="scores">
"""

        for fw, score in report.scores.items():
            risk_class = f"score-{score.risk_level.lower()}"
            html += f"""
        <div class="score-card {risk_class}">
            <h3>{fw.upper()}</h3>
            <p><strong>{score.score_percentage}%</strong> Compliant</p>
            <p>{score.compliant_controls}/{score.total_controls} controls</p>
            <p>Risk Level: <strong>{score.risk_level}</strong></p>
        </div>
"""

        html += """
    </div>

    <h2>Remediation Priorities</h2>
    <table>
        <tr>
            <th>Priority</th>
            <th>CWE</th>
            <th>Severity</th>
            <th>Frameworks</th>
            <th>Risk Score</th>
        </tr>
"""

        for i, item in enumerate(report.remediation_priorities[:20], 1):
            severity_class = f"severity-{item['severity']}"
            html += f"""
        <tr class="{severity_class}">
            <td>{i}</td>
            <td>{item['cwe_id']}: {item['cwe_name']}</td>
            <td>{item['severity'].upper()}</td>
            <td>{', '.join(item['frameworks_affected'])}</td>
            <td>{item['risk_score']:.1f}</td>
        </tr>
"""

        html += """
    </table>

    <h2>Framework Details</h2>
"""

        for fw, mappings in report.findings_by_framework.items():
            html += f"""
    <h3>{fw.upper()} Findings ({len(mappings)})</h3>
    <table>
        <tr>
            <th>CWE</th>
            <th>Category</th>
            <th>Severity</th>
        </tr>
"""
            for m in mappings[:10]:
                cat = m.frameworks.get(fw, m.frameworks.get(f"{fw}_dss", {}))
                cat_id = getattr(cat, 'category_id', 'N/A') if cat else 'N/A'
                html += f"""
        <tr>
            <td>{m.cwe_id}</td>
            <td>{cat_id}</td>
            <td>{m.severity}</td>
        </tr>
"""
            html += "    </table>\n"

        html += """
    <footer style="margin-top: 40px; color: #666; font-size: 12px;">
        <p>Generated by AIPTX Compliance Report Generator</p>
    </footer>
</body>
</html>
"""
        return html

    def to_json(self, report: ComplianceReport) -> str:
        """Convert report to JSON format."""
        def serialize(obj):
            if hasattr(obj, "__dict__"):
                return obj.__dict__
            return str(obj)

        return json.dumps({
            "generated_at": report.generated_at,
            "target": report.target,
            "frameworks": report.frameworks,
            "total_findings": report.total_findings,
            "mapped_findings": report.mapped_findings,
            "scores": {k: serialize(v) for k, v in report.scores.items()},
            "executive_summary": report.executive_summary,
            "remediation_priorities": report.remediation_priorities,
            "metadata": report.metadata
        }, indent=2)

    def save(
        self,
        report: ComplianceReport,
        output_path: str,
        format: str = "html"
    ):
        """Save report to file."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        if format == "html":
            content = self.to_html(report)
        elif format == "json":
            content = self.to_json(report)
        else:
            content = report.executive_summary

        path.write_text(content)


# Convenience function
def generate_compliance_report(
    findings: List[Dict],
    frameworks: List[str] = None,
    target: str = "",
    output_format: str = "html",
    output_path: str = None
) -> ComplianceReport:
    """
    Generate compliance report from findings.

    Args:
        findings: List of security findings with CWE IDs
        frameworks: Frameworks to include ("owasp", "pci", "nist")
        target: Target name/URL
        output_format: Output format ("html", "json", "text")
        output_path: Optional path to save report

    Returns:
        ComplianceReport
    """
    generator = ComplianceReportGenerator()
    report = generator.generate(findings, frameworks, target)

    if output_path:
        generator.save(report, output_path, output_format)

    return report
