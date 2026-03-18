"""Generate HTML security reports."""

from typing import List, Dict, Any
from pathlib import Path
from datetime import datetime
from rules.base_rule import Finding, Severity


def _esc(text: str) -> str:
    """HTML-escape a string."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _render_finding(f: Dict[str, Any]) -> str:
    """Render a single finding as an HTML <details> block."""
    sev = f["severity"].value
    sev_lower = sev.lower()

    # Severity colors
    colors = {
        "critical": "#dc2626",
        "high": "#ea580c",
        "medium": "#ca8a04",
        "low": "#16a34a",
        "info": "#0891b2",
    }
    color = colors.get(sev_lower, "#666")

    parts = []
    parts.append(
        f'<details style="border-left:4px solid {color};margin-bottom:12px;'
        f'padding:8px 12px;background:#fafafa;">'
    )
    parts.append(
        f"<summary style=\"cursor:pointer;font-weight:600;\">"
        f'<span style="color:{color};font-size:0.8em;text-transform:uppercase;">'
        f"[{_esc(sev)}]</span> "
        f"{_esc(f['title'])} &mdash; "
        f'<span style="color:#888;font-weight:normal;font-size:0.9em;">'
        f"{_esc(f['component_name'])}</span></summary>"
    )

    parts.append('<div style="margin-top:10px;font-size:0.95em;">')

    # Meta
    parts.append(
        f"<p style=\"color:#666;font-size:0.85em;margin-bottom:8px;\">"
        f"Rule: {_esc(f['rule_id'])} | Type: {_esc(f['component_type'])} | "
        f"CWE: {_esc(f['cwe'])} | Confidence: {_esc(f['confidence'].value)}</p>"
    )

    # Description
    parts.append(f"<p>{_esc(f['description'])}</p>")

    # Code snippet
    if f.get("code_snippet"):
        parts.append(
            f'<pre style="background:#1e293b;color:#e2e8f0;padding:10px;'
            f'border-radius:4px;overflow-x:auto;font-size:0.85em;margin:8px 0;">'
            f"{_esc(f['code_snippet'])}</pre>"
        )

    # Taint path
    if f.get("taint_path"):
        steps = " &rarr; ".join(
            f"<code>{_esc(s.method if hasattr(s, 'method') else str(s))}</code>"
            for s in f["taint_path"]
        )
        parts.append(
            f'<div style="background:#f3f4f6;padding:8px;border-radius:4px;'
            f'margin:8px 0;"><strong>Taint Path:</strong> {steps}</div>'
        )

    # Exploit commands
    if f.get("exploit_commands"):
        parts.append(
            '<div style="background:#fff7ed;border:1px solid #fed7aa;'
            'padding:10px;border-radius:4px;margin:8px 0;">'
            "<strong>Exploit Commands:</strong>"
        )
        for cmd in f["exploit_commands"]:
            parts.append(
                f'<pre style="background:#1e293b;color:#22c55e;padding:6px 10px;'
                f'border-radius:3px;margin:4px 0;font-size:0.85em;">$ {_esc(cmd)}</pre>'
            )
        if f.get("exploit_scenario"):
            parts.append(
                f'<p style="margin-top:6px;color:#9a3412;font-size:0.9em;">'
                f"<strong>Scenario:</strong> {_esc(f['exploit_scenario'])}</p>"
            )
        parts.append("</div>")

    # Remediation
    if f.get("remediation"):
        parts.append(
            f'<div style="background:#ecfdf5;border:1px solid #a7f3d0;'
            f'padding:10px;border-radius:4px;margin:8px 0;">'
            f"<strong>Remediation:</strong> {_esc(f['remediation'])}"
        )
        if f.get("api_level_affected"):
            parts.append(
                f"<br><strong>Affected API Levels:</strong> "
                f"{_esc(f['api_level_affected'])}"
            )
        parts.append("</div>")

    # References
    if f.get("references"):
        links = ", ".join(
            f'<a href="{_esc(r)}" target="_blank">{_esc(r)}</a>'
            for r in f["references"]
        )
        parts.append(f'<p style="font-size:0.85em;"><strong>References:</strong> {links}</p>')

    parts.append("</div></details>")
    return "\n".join(parts)


class HTMLReportGenerator:
    """Generate HTML security reports."""

    def __init__(self, package_name: str) -> None:
        self.package_name = package_name

    def generate(self, findings: List[Finding]) -> str:
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }
        sorted_findings = sorted(
            findings, key=lambda f: severity_order.get(f.severity, 5)
        )

        counts: Dict[str, int] = {k: 0 for k in ("critical", "high", "medium", "low", "info")}
        for f in findings:
            counts[f.severity.value.lower()] += 1

        def to_dict(finding: Finding) -> Dict[str, Any]:
            return {
                "rule_id": finding.rule_id,
                "component_type": finding.component_type,
                "component_name": finding.component_name,
                "severity": finding.severity,
                "confidence": finding.confidence,
                "cwe": finding.cwe,
                "cvss_score": finding.cvss_score,
                "title": finding.title,
                "description": finding.description,
                "code_snippet": finding.code_snippet or "",
                "taint_path": finding.taint_path or [],
                "exploit_commands": finding.exploit_commands or [],
                "exploit_scenario": finding.exploit_scenario or "",
                "remediation": finding.remediation or "",
                "api_level_affected": finding.api_level_affected or "",
                "references": finding.references or [],
            }

        # Group findings
        groups = [
            ("Critical", [to_dict(f) for f in sorted_findings if f.severity == Severity.CRITICAL]),
            ("High", [to_dict(f) for f in sorted_findings if f.severity == Severity.HIGH]),
            ("Medium", [to_dict(f) for f in sorted_findings if f.severity == Severity.MEDIUM]),
            ("Low", [to_dict(f) for f in sorted_findings if f.severity == Severity.LOW]),
            ("Info", [to_dict(f) for f in sorted_findings if f.severity == Severity.INFO]),
        ]

        pkg = _esc(self.package_name)
        scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Build summary badges
        badge_colors = {
            "Critical": "#dc2626",
            "High": "#ea580c",
            "Medium": "#ca8a04",
            "Low": "#16a34a",
            "Info": "#0891b2",
        }
        badges = " &nbsp; ".join(
            f'<span style="color:{badge_colors[label]};font-weight:bold;">'
            f"{label}: {counts[label.lower()]}</span>"
            for label in badge_colors
        )

        # Build sections
        sections = []
        for label, items in groups:
            if not items:
                continue
            rendered = "\n".join(_render_finding(f) for f in items)
            sections.append(
                f"<h2>{label} ({len(items)})</h2>\n{rendered}"
            )

        body_sections = "\n".join(sections) if sections else "<p>No findings.</p>"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ExPoser Report - {pkg}</title>
<style>
  body {{ font-family: sans-serif; max-width: 960px; margin: 20px auto; padding: 0 16px; background: #fff; color: #222; line-height: 1.5; }}
  h1 {{ font-size: 1.4em; }}
  h2 {{ font-size: 1.15em; margin-top: 24px; border-bottom: 1px solid #ddd; padding-bottom: 4px; }}
  summary {{ padding: 4px 0; }}
  summary:hover {{ background: #f5f5f5; }}
  a {{ color: #0969da; }}
  code {{ background: #f0f0f0; padding: 1px 4px; border-radius: 3px; font-size: 0.9em; }}
  pre {{ white-space: pre-wrap; word-break: break-all; }}
</style>
</head>
<body>
<h1>ExPoser Security Report</h1>
<p><strong>Package:</strong> {pkg}<br>
<strong>Date:</strong> {scan_date}<br>
<strong>Total:</strong> {len(findings)}</p>
<p>{badges}</p>
{body_sections}
<hr style="margin-top:24px;">
<p style="color:#888;font-size:0.85em;">Generated by ExPoser - Android APK Security Analyzer</p>
</body>
</html>"""
        return html

    def save(self, findings: List[Finding], output_path: str) -> None:
        html_content = self.generate(findings)
        Path(output_path).write_text(html_content, encoding="utf-8")
