from __future__ import annotations

import json
import math
from html import escape
from pathlib import Path


def load_report_payload(path: str | Path) -> dict:
    report_path = Path(path)
    if not report_path.exists():
        raise FileNotFoundError(f"Report file not found: {report_path}")
    return json.loads(report_path.read_text(encoding="utf-8"))


def compare_report_payloads(baseline: dict, current: dict) -> dict:
    baseline_results = {item["control_id"]: item for item in baseline.get("results", [])}
    current_results = {item["control_id"]: item for item in current.get("results", [])}

    control_changes = []
    for control_id in sorted(set(baseline_results) | set(current_results)):
        before = baseline_results.get(control_id)
        after = current_results.get(control_id)
        before_status = before["status"] if before else "missing"
        after_status = after["status"] if after else "missing"
        if before_status == after_status:
            continue
        title = (after or before).get("title", control_id)
        severity = (after or before).get("severity", "unknown")
        control_changes.append(
            {
                "control_id": control_id,
                "title": title,
                "severity": severity,
                "baseline_status": before_status,
                "current_status": after_status,
            }
        )

    baseline_summary = baseline.get("summary", {})
    current_summary = current.get("summary", {})
    framework_changes = []
    baseline_frameworks = baseline_summary.get("frameworks", {})
    current_frameworks = current_summary.get("frameworks", {})
    for framework in sorted(set(baseline_frameworks) | set(current_frameworks)):
        before = baseline_frameworks.get(framework, {})
        after = current_frameworks.get(framework, {})
        before_score = before.get("score", 0.0)
        after_score = after.get("score", 0.0)
        if before_score == after_score and before.get("compliant") == after.get("compliant"):
            continue
        framework_changes.append(
            {
                "framework": framework,
                "baseline_score": before_score,
                "current_score": after_score,
                "delta": round(after_score - before_score, 1),
                "baseline_compliant": before.get("compliant"),
                "current_compliant": after.get("compliant"),
            }
        )

    return {
        "baseline_lab_name": baseline.get("lab_name"),
        "current_lab_name": current.get("lab_name"),
        "baseline_generated_at": baseline.get("generated_at"),
        "current_generated_at": current.get("generated_at"),
        "baseline_score": baseline_summary.get("score", 0.0),
        "current_score": current_summary.get("score", 0.0),
        "score_delta": round(current_summary.get("score", 0.0) - baseline_summary.get("score", 0.0), 1),
        "baseline_blocking_controls": baseline_summary.get("blocking_controls", []),
        "current_blocking_controls": current_summary.get("blocking_controls", []),
        "resolved_blocking_controls": sorted(
            set(baseline_summary.get("blocking_controls", [])) - set(current_summary.get("blocking_controls", []))
        ),
        "new_blocking_controls": sorted(
            set(current_summary.get("blocking_controls", [])) - set(baseline_summary.get("blocking_controls", []))
        ),
        "control_changes": control_changes,
        "framework_changes": framework_changes,
    }


def render_compare_json(comparison: dict) -> str:
    return json.dumps(comparison, indent=2, ensure_ascii=False)


def render_compare_markdown(comparison: dict) -> str:
    lines = [
        "# Scan comparison",
        "",
        f"- Baseline: `{comparison['baseline_generated_at']}`",
        f"- Current: `{comparison['current_generated_at']}`",
        f"- Score delta: `{comparison['score_delta']}`",
        f"- Baseline score: `{comparison['baseline_score']}`",
        f"- Current score: `{comparison['current_score']}`",
        f"- Resolved blockers: {', '.join(f'`{item}`' for item in comparison['resolved_blocking_controls']) or 'none'}",
        f"- New blockers: {', '.join(f'`{item}`' for item in comparison['new_blocking_controls']) or 'none'}",
        "",
        "## Control changes",
        "",
        "| ID | Severity | Baseline | Current |",
        "| --- | --- | --- | --- |",
    ]
    for change in comparison["control_changes"]:
        lines.append(
            f"| `{change['control_id']}` | `{change['severity']}` | `{change['baseline_status']}` | `{change['current_status']}` |"
        )

    lines.extend(["", "## Framework changes", "", "| Framework | Baseline score | Current score | Delta |", "| --- | --- | --- | --- |"])
    for change in comparison["framework_changes"]:
        lines.append(
            f"| `{change['framework']}` | `{change['baseline_score']}` | `{change['current_score']}` | `{change['delta']}` |"
        )
    return "\n".join(lines)


def render_compare_html(comparison: dict) -> str:
    baseline_generated_at = comparison.get("baseline_generated_at") or "unknown"
    current_generated_at = comparison.get("current_generated_at") or "unknown"
    control_rows = "\n".join(
        (
            "<tr>"
            f"<td><code>{escape(change['control_id'])}</code></td>"
            f"<td>{_severity_badge(change['severity'])}</td>"
            f"<td>{_status_badge(change['baseline_status'])}</td>"
            f"<td>{_status_badge(change['current_status'])}</td>"
            "</tr>"
        )
        for change in comparison["control_changes"]
    )
    framework_rows = "\n".join(
        (
            "<tr>"
            f"<td>{escape(change['framework'])}</td>"
            f"<td>{escape(str(change['baseline_score']))}</td>"
            f"<td>{escape(str(change['current_score']))}</td>"
            f"<td>{escape(str(change['delta']))}</td>"
            "</tr>"
        )
        for change in comparison["framework_changes"]
    )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Scan comparison</title>
  <style>
    :root {{
      --bg: #f4efe5;
      --panel: #fffdf8;
      --line: #d7c6aa;
      --ink: #1f2933;
      --muted: #5d6b79;
      --accent: #a0432a;
    }}
    body {{
      margin: 0;
      font-family: Georgia, 'Times New Roman', serif;
      background:
        radial-gradient(circle at top right, rgba(160, 67, 42, 0.12) 0%, transparent 34%),
        linear-gradient(180deg, #faf5ed 0%, var(--bg) 100%);
      color: var(--ink);
    }}
    main {{
      max-width: 1160px;
      margin: 0 auto;
      padding: 32px 24px 64px;
    }}
    .hero {{
      background: linear-gradient(135deg, #fffdf8 0%, #f6e5c7 100%);
      border: 1px solid var(--line);
      border-radius: 24px;
      padding: 28px;
      box-shadow: 0 16px 40px rgba(31, 41, 51, 0.07);
    }}
    .hero-grid {{
      display: grid;
      grid-template-columns: minmax(0, 1.1fr) minmax(0, 0.9fr);
      gap: 24px;
      align-items: center;
    }}
    .score-grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(180px, 1fr));
      gap: 16px;
    }}
    .panel {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 18px;
      padding: 18px;
    }}
    .delta {{
      font-size: 2rem;
      font-weight: 700;
      color: { _delta_color(comparison["score_delta"]) };
    }}
    .chip-row {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-top: 14px;
    }}
    .chip {{
      border: 1px solid var(--line);
      border-radius: 999px;
      padding: 6px 11px;
      background: #f8f2e8;
      font-size: 0.88rem;
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
    }}
    th {{
      background: #efe3cf;
    }}
    .status-pill, .severity-pill {{
      display: inline-block;
      padding: 6px 10px;
      border-radius: 999px;
      color: #fff;
      font-size: 0.82rem;
      font-weight: 700;
    }}
    .section {{
      margin-top: 26px;
    }}
    .muted {{
      color: var(--muted);
    }}
    @media (max-width: 900px) {{
      .hero-grid, .score-grid {{
        grid-template-columns: 1fr;
      }}
    }}
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <div class="hero-grid">
        <div>
          <div style="text-transform:uppercase; letter-spacing:.08em; color:var(--accent); font-size:.82rem; font-weight:700;">Scan comparison</div>
          <h1 style="margin:.3rem 0 .5rem;">Progress and regression view</h1>
          <p class="muted">Compare two JSON scan reports to visualize score delta, blocker movement, control transitions, and framework evolution.</p>
          <div class="chip-row">
            <span class="chip">baseline: {escape(str(baseline_generated_at))}</span>
            <span class="chip">current: {escape(str(current_generated_at))}</span>
          </div>
        </div>
        <div class="score-grid">
          <div class="panel" style="text-align:center;">{_score_ring('Baseline', comparison['baseline_score'], '#8b5c1e')}</div>
          <div class="panel" style="text-align:center;">{_score_ring('Current', comparison['current_score'], '#2d7a46')}</div>
        </div>
      </div>
      <div class="chip-row" style="margin-top:20px;">
        <span class="chip">resolved blockers: {escape(', '.join(comparison['resolved_blocking_controls']) or 'none')}</span>
        <span class="chip">new blockers: {escape(', '.join(comparison['new_blocking_controls']) or 'none')}</span>
        <span class="chip">score delta: <span class="delta">{escape(str(comparison['score_delta']))}</span></span>
      </div>
    </section>
    <section class="section">
      <h2>Control changes</h2>
      <table>
        <thead><tr><th>ID</th><th>Severity</th><th>Baseline</th><th>Current</th></tr></thead>
        <tbody>{control_rows}</tbody>
      </table>
    </section>
    <section class="section">
      <h2>Framework changes</h2>
      <table>
        <thead><tr><th>Framework</th><th>Baseline score</th><th>Current score</th><th>Delta</th></tr></thead>
        <tbody>{framework_rows}</tbody>
      </table>
    </section>
  </main>
</body>
</html>"""


def _status_badge(status: str) -> str:
    colors = {
        "pass": "#2d7a46",
        "warn": "#b97a12",
        "fail": "#b03a2e",
        "error": "#7d2338",
        "evidence_missing": "#8b5c1e",
        "not_applicable": "#6f7d89",
        "missing": "#6f7d89",
    }
    return f"<span class='status-pill' style='background:{colors.get(status, '#6f7d89')}'>{escape(status.replace('_', ' '))}</span>"


def _severity_badge(severity: str) -> str:
    colors = {
        "critical": "#8f2b1f",
        "high": "#b85a2b",
        "medium": "#d48f1c",
        "low": "#6f7d89",
        "unknown": "#6f7d89",
    }
    return f"<span class='severity-pill' style='background:{colors.get(severity, '#6f7d89')}'>{escape(severity)}</span>"


def _score_ring(label: str, value: float, color: str) -> str:
    radius = 52
    circumference = 2 * math.pi * radius
    clamped = max(0.0, min(float(value), 100.0))
    dash_offset = circumference * (1 - clamped / 100)
    return f"""
    <svg width='180' height='180' viewBox='0 0 180 180' role='img' aria-label='{escape(label)} score'>
      <circle cx='90' cy='90' r='{radius}' fill='none' stroke='#eadbc6' stroke-width='14'></circle>
      <circle
        cx='90'
        cy='90'
        r='{radius}'
        fill='none'
        stroke='{color}'
        stroke-width='14'
        stroke-linecap='round'
        stroke-dasharray='{circumference:.2f}'
        stroke-dashoffset='{dash_offset:.2f}'
        transform='rotate(-90 90 90)'></circle>
      <text x='90' y='82' text-anchor='middle' style='font-size:13px; fill:#5d6b79'>{escape(label)}</text>
      <text x='90' y='108' text-anchor='middle' style='font-size:30px; font-weight:700; fill:#1f2933'>{clamped:.1f}</text>
    </svg>
    """


def _delta_color(value: float) -> str:
    if value > 0:
        return "#2d7a46"
    if value < 0:
        return "#b03a2e"
    return "#6f7d89"
