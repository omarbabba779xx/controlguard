from __future__ import annotations

import json
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
    control_rows = "\n".join(
        (
            "<tr>"
            f"<td>{escape(change['control_id'])}</td>"
            f"<td>{escape(change['severity'])}</td>"
            f"<td>{escape(change['baseline_status'])}</td>"
            f"<td>{escape(change['current_status'])}</td>"
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
    body {{ font-family: Georgia, serif; background: #f7f2e8; color: #1f2933; margin: 0; }}
    main {{ max-width: 1100px; margin: 0 auto; padding: 32px 24px 60px; }}
    .hero {{ background: #fffdf8; border: 1px solid #d6c8b3; border-radius: 18px; padding: 24px; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; margin-top: 16px; }}
    .card {{ background: #fbf6ee; border: 1px solid #d6c8b3; border-radius: 12px; padding: 14px; }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 18px; background: #fffdf8; }}
    th, td {{ border-bottom: 1px solid #d6c8b3; padding: 10px; text-align: left; }}
    th {{ background: #efe3cf; }}
    section {{ margin-top: 24px; }}
  </style>
</head>
<body>
  <main>
    <section class="hero">
      <h1>Scan comparison</h1>
      <div class="grid">
        <div class="card"><strong>Baseline score</strong><br>{escape(str(comparison['baseline_score']))}</div>
        <div class="card"><strong>Current score</strong><br>{escape(str(comparison['current_score']))}</div>
        <div class="card"><strong>Score delta</strong><br>{escape(str(comparison['score_delta']))}</div>
        <div class="card"><strong>New blockers</strong><br>{escape(', '.join(comparison['new_blocking_controls']) or 'none')}</div>
      </div>
    </section>
    <section>
      <h2>Control changes</h2>
      <table>
        <thead><tr><th>ID</th><th>Severity</th><th>Baseline</th><th>Current</th></tr></thead>
        <tbody>{control_rows}</tbody>
      </table>
    </section>
    <section>
      <h2>Framework changes</h2>
      <table>
        <thead><tr><th>Framework</th><th>Baseline score</th><th>Current score</th><th>Delta</th></tr></thead>
        <tbody>{framework_rows}</tbody>
      </table>
    </section>
  </main>
</body>
</html>"""
