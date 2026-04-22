from __future__ import annotations

import json
from dataclasses import asdict
from html import escape

from .models import ControlResult, FrameworkSummary, ScanReport


def render_json(report: ScanReport) -> str:
    return json.dumps(_report_to_dict(report), indent=2, ensure_ascii=False)


def render_csv(report: ScanReport) -> str:
    header = [
        "control_id",
        "title",
        "status",
        "severity",
        "required",
        "evidence_source",
        "frameworks",
        "message",
    ]
    lines = [
        ",".join(f'"{value}"' for value in header),
    ]
    for result in report.results:
        values = [
            result.control_id,
            result.title,
            result.status.value,
            result.severity.value,
            str(result.required).lower(),
            result.evidence_source,
            "; ".join(f"{framework}:{'|'.join(refs)}" for framework, refs in sorted(result.frameworks.items())),
            result.message.replace('"', "'"),
        ]
        lines.append(",".join(f'"{value}"' for value in values))
    return "\n".join(lines)


def render_markdown(report: ScanReport) -> str:
    lines = [
        f"# {report.lab_name}",
        "",
        report.description or "Security control validation report.",
        "",
        "## Executive summary",
        "",
        f"- Generated at: `{report.generated_at}`",
        f"- Platform: `{report.platform}`",
        f"- Compliance score: `{report.summary.score}%`",
        f"- Posture: `{report.summary.posture}`",
        f"- Compliant: `{str(report.summary.compliant).lower()}`",
        (
            "- Totals: "
            f"`{report.summary.total_controls}` total / "
            f"`{report.summary.applicable_controls}` applicable / "
            f"`{report.summary.counts['pass']}` pass / "
            f"`{report.summary.counts['warn']}` warn / "
            f"`{report.summary.counts['fail']}` fail / "
            f"`{report.summary.counts['error']}` error / "
            f"`{report.summary.counts['not_applicable']}` not applicable / "
            f"`{report.summary.counts['evidence_missing']}` evidence missing"
        ),
        "",
    ]
    if report.summary.blocking_controls:
        lines.append(f"- Blocking controls: {', '.join(f'`{control_id}`' for control_id in report.summary.blocking_controls)}")
        lines.append("")

    if report.summary.frameworks:
        lines.extend(_render_framework_markdown(report.summary.frameworks))

    lines.extend(["## Findings", "", "| ID | Status | Severity | Control |", "| --- | --- | --- | --- |"])
    for result in report.results:
        lines.append(
            f"| `{result.control_id}` | `{result.status.value}` | `{result.severity.value}` | {result.title} |"
        )

    lines.extend(["", "## Technical details", ""])
    for result in report.results:
        lines.extend(_render_result_block(result))

    return "\n".join(lines)


def render_html(report: ScanReport) -> str:
    summary_cards = "\n".join(
        [
            _summary_card("Score", f"{report.summary.score}%"),
            _summary_card("Posture", report.summary.posture),
            _summary_card("Compliant", str(report.summary.compliant).lower()),
            _summary_card("Blocking controls", ", ".join(report.summary.blocking_controls) or "none"),
        ]
    )
    framework_cards = "\n".join(
        _summary_card(
            framework,
            f"{summary.score}% score / {summary.applicable_controls} applicable / compliant={str(summary.compliant).lower()}",
        )
        for framework, summary in sorted(report.summary.frameworks.items())
    )
    findings_rows = "\n".join(
        (
            "<tr>"
            f"<td>{escape(result.control_id)}</td>"
            f"<td>{escape(result.status.value)}</td>"
            f"<td>{escape(result.severity.value)}</td>"
            f"<td>{escape(result.title)}</td>"
            f"<td>{escape(result.message)}</td>"
            "</tr>"
        )
        for result in report.results
    )
    technical_blocks = "\n".join(
        (
            "<details class='detail-card'>"
            f"<summary>{escape(result.control_id)} - {escape(result.title)}</summary>"
            f"<pre>{escape(json.dumps(_result_to_dict(result), indent=2, ensure_ascii=False))}</pre>"
            "</details>"
        )
        for result in report.results
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{escape(report.lab_name)}</title>
  <style>
    :root {{
      --bg: #f4efe5;
      --panel: #fffdf8;
      --panel-strong: #f7e7c9;
      --ink: #1f2933;
      --muted: #5d6b79;
      --line: #d6c8b3;
      --accent: #a0432a;
    }}
    body {{
      margin: 0;
      font-family: Georgia, 'Times New Roman', serif;
      background:
        radial-gradient(circle at top left, #fff9ef 0%, rgba(255, 249, 239, 0.4) 30%, transparent 60%),
        linear-gradient(180deg, #f9f5ed 0%, var(--bg) 100%);
      color: var(--ink);
    }}
    main {{
      max-width: 1180px;
      margin: 0 auto;
      padding: 36px 24px 72px;
    }}
    .hero {{
      background: linear-gradient(135deg, #fffdf8 0%, var(--panel-strong) 100%);
      border: 1px solid var(--line);
      border-radius: 24px;
      padding: 32px;
      box-shadow: 0 18px 42px rgba(31, 41, 51, 0.08);
    }}
    .eyebrow {{
      color: var(--accent);
      letter-spacing: 0.08em;
      text-transform: uppercase;
      font-size: 0.82rem;
      margin-bottom: 10px;
    }}
    .meta-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(210px, 1fr));
      gap: 16px;
      margin-top: 22px;
    }}
    .card {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 16px;
      padding: 16px;
    }}
    .section {{
      margin-top: 28px;
    }}
    h1, h2 {{
      margin: 0;
    }}
    h2 {{
      margin-bottom: 12px;
    }}
    p {{
      color: var(--muted);
      line-height: 1.55;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin-top: 18px;
      background: var(--panel);
      border-radius: 16px;
      overflow: hidden;
      box-shadow: 0 10px 30px rgba(31, 41, 51, 0.05);
    }}
    th, td {{
      border-bottom: 1px solid var(--line);
      padding: 12px;
      text-align: left;
      vertical-align: top;
    }}
    th {{
      background: #efe3cf;
    }}
    .detail-card {{
      margin-top: 14px;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 14px;
      padding: 12px 16px;
    }}
    pre {{
      overflow: auto;
      white-space: pre-wrap;
      word-break: break-word;
      color: var(--muted);
    }}
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <div class="eyebrow">Security Control Validation Lab</div>
      <h1>{escape(report.lab_name)}</h1>
      <p>{escape(report.description or "Security control validation report.")}</p>
      <div class="meta-grid">
        {summary_cards}
      </div>
    </section>
    <section class="section">
      <h2>Executive summary</h2>
      <p>Generated at {escape(report.generated_at)} on {escape(report.platform)}. The current posture is {escape(report.summary.posture)} with a weighted score of {escape(str(report.summary.score))}%.</p>
    </section>
    <section class="section">
      <h2>Framework summary</h2>
      <div class="meta-grid">
        {framework_cards or _summary_card("No framework mappings", "Add framework references to controls to see rollups here.")}
      </div>
    </section>
    <section class="section">
      <h2>Findings</h2>
      <table>
        <thead>
          <tr>
            <th>ID</th>
            <th>Status</th>
            <th>Severity</th>
            <th>Control</th>
            <th>Message</th>
          </tr>
        </thead>
        <tbody>
          {findings_rows}
        </tbody>
      </table>
    </section>
    <section class="section">
      <h2>Technical details</h2>
      {technical_blocks}
    </section>
  </main>
</body>
</html>"""


def render_sarif(report: ScanReport) -> str:
    rules = [
        {
            "id": result.control_id,
            "shortDescription": {"text": result.title},
            "fullDescription": {"text": result.description or result.message},
            "properties": {
                "severity": result.severity.value,
                "required": result.required,
                "evidence_source": result.evidence_source,
                "frameworks": result.frameworks,
            },
        }
        for result in report.results
    ]
    results = []
    for result in report.results:
        if not result.status.is_finding:
            continue
        level = "warning" if result.status.value == "warn" else "error"
        results.append(
            {
                "ruleId": result.control_id,
                "level": level,
                "message": {"text": result.message},
                "properties": {
                    "status": result.status.value,
                    "severity": result.severity.value,
                    "frameworks": result.frameworks,
                    "evidence": result.evidence,
                },
            }
        )

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "controlguard",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)


def _render_framework_markdown(frameworks: dict[str, FrameworkSummary]) -> list[str]:
    lines = ["## Framework summary", "", "| Framework | Score | Applicable | Compliant | Blocking controls |", "| --- | --- | --- | --- | --- |"]
    for framework, summary in sorted(frameworks.items()):
        blockers = ", ".join(summary.blocking_controls) if summary.blocking_controls else "-"
        lines.append(
            f"| `{framework}` | `{summary.score}%` | `{summary.applicable_controls}/{summary.total_controls}` | "
            f"`{str(summary.compliant).lower()}` | {blockers} |"
        )
    lines.extend(["", ""])
    return lines


def _render_result_block(result: ControlResult) -> list[str]:
    block = [
        f"### {result.title}",
        "",
        f"- ID: `{result.control_id}`",
        f"- Type: `{result.control_type}`",
        f"- Status: `{result.status.value}`",
        f"- Severity: `{result.severity.value}`",
        f"- Required: `{str(result.required).lower()}`",
        f"- Evidence source: `{result.evidence_source}`",
        f"- Message: {result.message}",
    ]
    if result.frameworks:
        block.append(
            "- Frameworks: "
            + ", ".join(f"{framework} ({'; '.join(refs)})" for framework, refs in sorted(result.frameworks.items()))
        )
    if result.tags:
        block.append(f"- Tags: {', '.join(result.tags)}")
    if result.supported_platforms:
        block.append(f"- Supported platforms: {', '.join(result.supported_platforms)}")
    if result.references:
        block.append(f"- References: {', '.join(result.references)}")
    if result.rationale:
        block.append(f"- Rationale: {result.rationale}")
    if result.remediation:
        block.append(f"- Remediation: {result.remediation}")
    block.extend(["", "```json", json.dumps(result.evidence, indent=2, ensure_ascii=False), "```", ""])
    return block


def _summary_card(title: str, value: str) -> str:
    return f"<div class='card'><strong>{escape(title)}</strong><br>{escape(value)}</div>"


def _report_to_dict(report: ScanReport) -> dict:
    payload = asdict(report)
    payload["results"] = [_result_to_dict(result) for result in report.results]
    payload["summary"]["frameworks"] = {
        framework: asdict(summary)
        for framework, summary in report.summary.frameworks.items()
    }
    return payload


def _result_to_dict(result: ControlResult) -> dict:
    payload = asdict(result)
    payload["status"] = result.status.value
    payload["severity"] = result.severity.value
    return payload
