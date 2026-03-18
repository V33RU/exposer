"""Generate JSON security reports."""

import json
from typing import List, Dict, Any
from pathlib import Path
from datetime import datetime

from rules.base_rule import Finding


class JSONReportGenerator:
    """Generate JSON security reports."""

    def __init__(self, package_name: str, app_name: str = "") -> None:
        """Initialize report generator.

        Args:
            package_name: Target package name.
            app_name: Application name.
        """
        self.package_name = package_name
        self.app_name = app_name

    def generate(self, findings: List[Finding]) -> Dict[str, Any]:
        """Generate JSON report structure.

        Args:
            findings: List of vulnerability findings.

        Returns:
            Dictionary containing the report data.
        """
        # Single-pass: count severities/confidences, serialise, and group by type
        severity_counts = {k: 0 for k in ("critical", "high", "medium", "low", "info")}
        confidence_counts = {k: 0 for k in ("confirmed", "likely", "possible")}
        findings_data: List[Dict] = []
        findings_by_type: Dict[str, List[Dict]] = {}

        for finding in findings:
            severity_counts[finding.severity.value.lower()] += 1
            confidence_counts[finding.confidence.value.lower()] += 1

            finding_dict = {
                "rule_id": finding.rule_id,
                "component_type": finding.component_type,
                "component_name": finding.component_name,
                "severity": finding.severity.value,
                "confidence": finding.confidence.value,
                "cwe": finding.cwe,
                "cvss_score": finding.cvss_score,
                "title": finding.title,
                "description": finding.description,
                "code_snippet": finding.code_snippet,
                "taint_path": finding.taint_path,
                "exploit_commands": finding.exploit_commands,
                "exploit_scenario": finding.exploit_scenario,
                "remediation": finding.remediation,
                "api_level_affected": finding.api_level_affected,
                "references": finding.references,
                "details": finding.details
            }
            findings_data.append(finding_dict)
            findings_by_type.setdefault(finding.component_type, []).append(finding_dict)

        report = {
            "report_metadata": {
                "tool": "ExPoser",
                "version": "1.0.0",
                "scan_date": datetime.now().isoformat(),
                "package_name": self.package_name,
                "app_name": self.app_name
            },
            "summary": {
                "total_findings": len(findings),
                "severity_counts": severity_counts,
                "confidence_counts": confidence_counts
            },
            "findings_by_component_type": findings_by_type,
            "findings": findings_data
        }

        return report

    def to_json(self, findings: List[Finding], indent: int = 2) -> str:
        """Generate JSON report as string.

        Args:
            findings: List of vulnerability findings.
            indent: JSON indentation level.

        Returns:
            JSON string.
        """
        report = self.generate(findings)
        return json.dumps(report, indent=indent, ensure_ascii=False)

    def save(self, findings: List[Finding], output_path: str, indent: int = 2) -> None:
        """Save JSON report to file.

        Args:
            findings: List of vulnerability findings.
            output_path: Path to save the report.
            indent: JSON indentation level.
        """
        json_content = self.to_json(findings, indent)
        Path(output_path).write_text(json_content, encoding='utf-8')
