from __future__ import annotations

import json
import math
from dataclasses import asdict
from html import escape

from .models import ControlResult, FrameworkSummary, ScanReport

STATUS_COLORS = {
    "pass": "#2d7a46",
    "warn": "#b97a12",
    "fail": "#b03a2e",
    "error": "#7d2338",
    "not_applicable": "#6f7d89",
    "evidence_missing": "#8b5c1e",
}

SEVERITY_COLORS = {
    "low": "#6f7d89",
    "medium": "#d48f1c",
    "high": "#b85a2b",
    "critical": "#8f2b1f",
}


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
        lines.append(
            f"- Blocking controls: {', '.join(f'`{control_id}`' for control_id in report.summary.blocking_controls)}"
        )
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
        _framework_card(framework, summary) for framework, summary in sorted(report.summary.frameworks.items())
    )
    findings_rows = "\n".join(
        (
            "<tr>"
            f"<td><code>{escape(result.control_id)}</code></td>"
            f"<td>{_status_badge(result.status.value)}</td>"
            f"<td>{_severity_badge(result.severity.value)}</td>"
            f"<td>{escape(result.title)}</td>"
            f"<td>{escape(result.message)}</td>"
            "</tr>"
        )
        for result in report.results
    )
    technical_blocks = "\n".join(
        (
            "<details class='detail-card'>"
            f"<summary>{_status_badge(result.status.value)} {escape(result.control_id)} - {escape(result.title)}</summary>"
            f"<div class='detail-meta'>{_severity_badge(result.severity.value)} {_chip('source', result.evidence_source)}</div>"
            f"<pre>{escape(json.dumps(_result_to_dict(result), indent=2, ensure_ascii=False))}</pre>"
            "</details>"
        )
        for result in report.results
    )
    executive_text = (
        f"Generated at {escape(report.generated_at)} on {escape(report.platform)}. "
        f"The current posture is {escape(report.summary.posture)} with a weighted score of {escape(str(report.summary.score))}%."
    )
    status_distribution = _render_status_distribution(report)
    severity_distribution = _render_severity_distribution(report)
    blocking_cards = _render_blocking_cards(report)
    score_ring = _score_ring(
        title="Global compliance score",
        value=report.summary.score,
        subtitle=f"{report.summary.applicable_controls} applicable controls",
        color=_score_color(report.summary.score, report.summary.posture),
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{escape(report.lab_name)}</title>
  <style>
    :root {{
      --bg: #f2ede3;
      --panel: #fffdf8;
      --panel-strong: #f6e5c7;
      --panel-dark: #f0e3d0;
      --ink: #1f2933;
      --muted: #5d6b79;
      --line: #d7c6aa;
      --accent: #a0432a;
      --accent-soft: #ecd6bf;
      --pass: {STATUS_COLORS["pass"]};
      --warn: {STATUS_COLORS["warn"]};
      --fail: {STATUS_COLORS["fail"]};
      --error: {STATUS_COLORS["error"]};
      --na: {STATUS_COLORS["not_applicable"]};
      --missing: {STATUS_COLORS["evidence_missing"]};
    }}
    * {{
      box-sizing: border-box;
    }}
    body {{
      margin: 0;
      font-family: Georgia, 'Times New Roman', serif;
      background:
        radial-gradient(circle at top left, #fff8ed 0%, rgba(255, 248, 237, 0.55) 26%, transparent 58%),
        radial-gradient(circle at bottom right, rgba(202, 141, 90, 0.12) 0%, transparent 38%),
        linear-gradient(180deg, #f8f3eb 0%, var(--bg) 100%);
      color: var(--ink);
    }}
    main {{
      max-width: 1240px;
      margin: 0 auto;
      padding: 36px 24px 72px;
    }}
    .hero {{
      background: linear-gradient(135deg, #fffdf8 0%, var(--panel-strong) 100%);
      border: 1px solid var(--line);
      border-radius: 28px;
      padding: 32px;
      box-shadow: 0 20px 46px rgba(31, 41, 51, 0.08);
      position: relative;
      overflow: hidden;
    }}
    .hero::after {{
      content: "";
      position: absolute;
      inset: auto -80px -120px auto;
      width: 260px;
      height: 260px;
      background: radial-gradient(circle, rgba(160, 67, 42, 0.15) 0%, rgba(160, 67, 42, 0) 70%);
      pointer-events: none;
    }}
    .eyebrow {{
      color: var(--accent);
      letter-spacing: 0.08em;
      text-transform: uppercase;
      font-size: 0.82rem;
      margin-bottom: 10px;
      font-weight: 700;
    }}
    .hero-grid {{
      display: grid;
      grid-template-columns: minmax(0, 1.4fr) minmax(280px, 0.8fr);
      gap: 28px;
      align-items: center;
    }}
    .hero-copy p {{
      font-size: 1.05rem;
      margin-top: 14px;
      max-width: 700px;
    }}
    .meta-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
      gap: 14px;
      margin-top: 24px;
    }}
    .card {{
      background: rgba(255, 253, 248, 0.86);
      border: 1px solid var(--line);
      border-radius: 16px;
      padding: 16px;
      backdrop-filter: blur(4px);
    }}
    .score-wrap {{
      display: flex;
      justify-content: center;
      align-items: center;
    }}
    .section {{
      margin-top: 30px;
    }}
    .section-header {{
      display: flex;
      justify-content: space-between;
      align-items: end;
      gap: 16px;
      margin-bottom: 12px;
    }}
    h1, h2, h3 {{
      margin: 0;
    }}
    p {{
      color: var(--muted);
      line-height: 1.6;
    }}
    .dashboard-grid {{
      display: grid;
      grid-template-columns: 1.05fr 0.95fr;
      gap: 18px;
    }}
    .panel {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 20px;
      padding: 20px;
      box-shadow: 0 12px 30px rgba(31, 41, 51, 0.05);
    }}
    .framework-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
    }}
    .framework-card {{
      background: linear-gradient(180deg, #fffdf8 0%, #f7f1e8 100%);
      border: 1px solid var(--line);
      border-radius: 18px;
      padding: 18px;
    }}
    .framework-score {{
      font-size: 1.4rem;
      font-weight: 700;
      margin-top: 6px;
    }}
    .bars {{
      display: grid;
      gap: 12px;
      margin-top: 10px;
    }}
    .bar-row {{
      display: grid;
      grid-template-columns: 120px 1fr 52px;
      gap: 12px;
      align-items: center;
      font-size: 0.95rem;
    }}
    .bar-track {{
      background: #efe5d8;
      border-radius: 999px;
      overflow: hidden;
      height: 12px;
      position: relative;
    }}
    .bar-fill {{
      height: 100%;
      border-radius: 999px;
    }}
    .chip-row {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 14px;
    }}
    .chip {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      border-radius: 999px;
      padding: 7px 12px;
      font-size: 0.88rem;
      border: 1px solid var(--line);
      background: #f8f2e8;
    }}
    .chip-dot {{
      width: 10px;
      height: 10px;
      border-radius: 50%;
      display: inline-block;
    }}
    .blocker-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
      gap: 14px;
      margin-top: 12px;
    }}
    .blocker-card {{
      background: linear-gradient(180deg, #fff9f8 0%, #faece7 100%);
      border: 1px solid #e4c5bc;
      border-radius: 16px;
      padding: 16px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      margin-top: 18px;
      background: var(--panel);
      border-radius: 18px;
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
      font-size: 0.95rem;
    }}
    .status-pill, .severity-pill {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 6px 10px;
      border-radius: 999px;
      color: #fff;
      font-size: 0.84rem;
      font-weight: 700;
      letter-spacing: 0.01em;
    }}
    .severity-pill {{
      color: #fffdf8;
    }}
    .detail-card {{
      margin-top: 14px;
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 16px;
      padding: 14px 18px;
    }}
    .detail-card summary {{
      cursor: pointer;
      font-weight: 700;
      display: flex;
      align-items: center;
      gap: 10px;
    }}
    .detail-meta {{
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin-top: 12px;
      margin-bottom: 8px;
    }}
    pre {{
      overflow: auto;
      white-space: pre-wrap;
      word-break: break-word;
      color: var(--muted);
      background: #fbf7f0;
      border: 1px solid #eadbc6;
      border-radius: 12px;
      padding: 14px;
      margin-top: 10px;
    }}
    .muted {{
      color: var(--muted);
    }}
    @media (max-width: 920px) {{
      .hero-grid, .dashboard-grid {{
        grid-template-columns: 1fr;
      }}
      .bar-row {{
        grid-template-columns: 100px 1fr 40px;
      }}
    }}
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <div class="hero-grid">
        <div class="hero-copy">
          <div class="eyebrow">Security Control Validation Lab</div>
          <h1>{escape(report.lab_name)}</h1>
          <p>{escape(report.description or "Security control validation report.")}</p>
          <div class="meta-grid">
            {summary_cards}
          </div>
          <div class="chip-row">
            {_chip('generated', report.generated_at)}
            {_chip('platform', report.platform)}
            {_chip('applicable', f"{report.summary.applicable_controls}/{report.summary.total_controls}")}
          </div>
        </div>
        <div class="score-wrap">
          {score_ring}
        </div>
      </div>
    </section>
    <section class="section">
      <div class="section-header">
        <div>
          <h2>Executive summary</h2>
          <p>{executive_text}</p>
        </div>
      </div>
      <div class="dashboard-grid">
        <div class="panel">
          <h3>Status distribution</h3>
          <p class="muted">Visual breakdown of control outcomes across the scan.</p>
          {status_distribution}
        </div>
        <div class="panel">
          <h3>Severity distribution</h3>
          <p class="muted">Where the control population is concentrated by risk level.</p>
          {severity_distribution}
        </div>
      </div>
    </section>
    <section class="section">
      <div class="section-header">
        <div>
          <h2>Framework summary</h2>
          <p>Roll-up by framework so you can read the result like an audit dashboard.</p>
        </div>
      </div>
      <div class="framework-grid">
        {framework_cards or _summary_card("No framework mappings", "Add framework references to controls to see rollups here.")}
      </div>
    </section>
    <section class="section">
      <div class="section-header">
        <div>
          <h2>Blocking controls</h2>
          <p>Required controls currently preventing compliance.</p>
        </div>
      </div>
      <div class="blocker-grid">
        {blocking_cards}
      </div>
    </section>
    <section class="section">
      <div class="section-header">
        <div>
          <h2>Findings</h2>
          <p>Full control table with status and severity indicators.</p>
        </div>
      </div>
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
      <div class="section-header">
        <div>
          <h2>Technical details</h2>
          <p>Expand a control to inspect exact evidence, framework mappings, and remediation context.</p>
        </div>
      </div>
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
    lines = [
        "## Framework summary",
        "",
        "| Framework | Score | Applicable | Compliant | Blocking controls |",
        "| --- | --- | --- | --- | --- |",
    ]
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


def _framework_card(framework: str, summary: FrameworkSummary) -> str:
    accent = _score_color(summary.score, "strong" if summary.compliant else "weak")
    blockers = ", ".join(summary.blocking_controls) if summary.blocking_controls else "none"
    return (
        "<div class='framework-card'>"
        f"<div class='muted'>{escape(framework)}</div>"
        f"<div class='framework-score' style='color:{accent}'>{escape(str(summary.score))}%</div>"
        f"<p>{escape(str(summary.applicable_controls))} applicable / {escape(str(summary.total_controls))} total</p>"
        f"<div class='chip-row'>{_chip('compliant', str(summary.compliant).lower())}{_chip('blockers', blockers)}</div>"
        "</div>"
    )


def _render_status_distribution(report: ScanReport) -> str:
    total = max(report.summary.total_controls, 1)
    rows = []
    for status in ("pass", "warn", "fail", "error", "evidence_missing", "not_applicable"):
        count = report.summary.counts.get(status, 0)
        width = (count / total) * 100
        label = status.replace("_", " ")
        rows.append(
            "<div class='bar-row'>"
            f"<div>{escape(label)}</div>"
            f"<div class='bar-track'><div class='bar-fill' style='width:{width:.1f}%; background:{STATUS_COLORS[status]};'></div></div>"
            f"<div>{count}</div>"
            "</div>"
        )
    return f"<div class='bars'>{''.join(rows)}</div>"


def _render_severity_distribution(report: ScanReport) -> str:
    counts = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    for result in report.results:
        counts[result.severity.value] += 1
    total = max(sum(counts.values()), 1)
    rows = []
    for severity in ("critical", "high", "medium", "low"):
        count = counts[severity]
        width = (count / total) * 100
        rows.append(
            "<div class='bar-row'>"
            f"<div>{escape(severity)}</div>"
            f"<div class='bar-track'><div class='bar-fill' style='width:{width:.1f}%; background:{SEVERITY_COLORS[severity]};'></div></div>"
            f"<div>{count}</div>"
            "</div>"
        )
    return f"<div class='bars'>{''.join(rows)}</div>"


def _render_blocking_cards(report: ScanReport) -> str:
    if not report.summary.blocking_controls:
        return "<div class='blocker-card'><strong>No required blockers</strong><p>The scan is currently compliant.</p></div>"
    cards = []
    result_by_id = {result.control_id: result for result in report.results}
    for control_id in report.summary.blocking_controls:
        result = result_by_id.get(control_id)
        if result is None:
            continue
        cards.append(
            "<div class='blocker-card'>"
            f"<div>{_severity_badge(result.severity.value)}</div>"
            f"<h3 style='margin-top:10px'>{escape(result.title)}</h3>"
            f"<p>{escape(result.message)}</p>"
            f"<div class='chip-row'>{_chip('id', result.control_id)}{_chip('source', result.evidence_source)}</div>"
            "</div>"
        )
    return "".join(cards)


def _score_ring(title: str, value: float, subtitle: str, color: str) -> str:
    radius = 78
    circumference = 2 * math.pi * radius
    clamped = max(0.0, min(value, 100.0))
    dash_offset = circumference * (1 - clamped / 100)
    return f"""
    <div class='panel' style='text-align:center; max-width:320px; width:100%;'>
      <div class='muted' style='margin-bottom:10px'>{escape(title)}</div>
      <svg width='220' height='220' viewBox='0 0 220 220' role='img' aria-label='{escape(title)}'>
        <circle cx='110' cy='110' r='{radius}' fill='none' stroke='#eadbc6' stroke-width='16'></circle>
        <circle
          cx='110'
          cy='110'
          r='{radius}'
          fill='none'
          stroke='{color}'
          stroke-width='16'
          stroke-linecap='round'
          stroke-dasharray='{circumference:.2f}'
          stroke-dashoffset='{dash_offset:.2f}'
          transform='rotate(-90 110 110)'></circle>
        <text x='110' y='103' text-anchor='middle' style='font-size:42px; font-weight:700; fill:#1f2933'>{clamped:.1f}</text>
        <text x='110' y='128' text-anchor='middle' style='font-size:16px; fill:#5d6b79'>score</text>
      </svg>
      <div class='chip-row' style='justify-content:center'>{_chip('detail', subtitle)}</div>
    </div>
    """


def _status_badge(status: str) -> str:
    color = STATUS_COLORS.get(status, "#6f7d89")
    label = status.replace("_", " ")
    return (
        f"<span class='status-pill' style='background:{color}'>"
        f"<span class='chip-dot' style='background:rgba(255,255,255,0.9)'></span>{escape(label)}</span>"
    )


def _severity_badge(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity, "#6f7d89")
    return f"<span class='severity-pill' style='background:{color}'>{escape(severity)}</span>"


def _chip(label: str, value: str) -> str:
    return f"<span class='chip'><strong>{escape(label)}:</strong> {escape(value)}</span>"


def _score_color(score: float, posture: str) -> str:
    if posture == "critical":
        return "#9a3022"
    if score >= 90:
        return "#2d7a46"
    if score >= 70:
        return "#b97a12"
    return "#b03a2e"


def _report_to_dict(report: ScanReport) -> dict:
    payload = asdict(report)
    payload["results"] = [_result_to_dict(result) for result in report.results]
    payload["summary"]["frameworks"] = {
        framework: asdict(summary) for framework, summary in report.summary.frameworks.items()
    }
    return payload


def _result_to_dict(result: ControlResult) -> dict:
    payload = asdict(result)
    payload["status"] = result.status.value
    payload["severity"] = result.severity.value
    return payload
