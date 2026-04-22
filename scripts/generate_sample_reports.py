from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from controlguard.comparison import (
    compare_report_payloads,
    render_compare_html,
    render_compare_json,
    render_compare_markdown,
)
from controlguard.models import ControlResult, ControlStatus, FrameworkSummary, ScanReport, ScanSummary, Severity
from controlguard.reporting import render_html, render_json, render_sarif


def main() -> None:
    output_dir = Path("docs") / "samples"
    output_dir.mkdir(parents=True, exist_ok=True)

    baseline_report = _build_baseline_report()
    current_report = _build_current_report()

    baseline_json = render_json(baseline_report)
    current_json = render_json(current_report)
    comparison = compare_report_payloads(
        baseline=__import__("json").loads(baseline_json),
        current=__import__("json").loads(current_json),
    )

    (output_dir / "sample-report.json").write_text(current_json, encoding="utf-8")
    (output_dir / "sample-report.html").write_text(render_html(current_report), encoding="utf-8")
    (output_dir / "sample-report.sarif").write_text(render_sarif(current_report), encoding="utf-8")
    (output_dir / "sample-compare.json").write_text(render_compare_json(comparison), encoding="utf-8")
    (output_dir / "sample-compare.md").write_text(render_compare_markdown(comparison), encoding="utf-8")
    (output_dir / "sample-compare.html").write_text(render_compare_html(comparison), encoding="utf-8")


def _build_current_report() -> ScanReport:
    results = [
        ControlResult(
            control_id="win-firewall-enabled",
            title="Pare-feu Windows actif",
            control_type="windows_firewall_enabled",
            severity=Severity.CRITICAL,
            status=ControlStatus.PASS,
            message="Windows Firewall is enabled on all profiles.",
            required=True,
            evidence_source="powershell",
            frameworks={"CIS Controls v8": ["4.4"], "NIST CSF 2.0": ["PR.PS"]},
            tags=["CIS", "NIST-CSF"],
            evidence={"profiles": ["Domain", "Private", "Public"]},
        ),
        ControlResult(
            control_id="windows-defender-running",
            title="Defender actif",
            control_type="windows_defender_running",
            severity=Severity.HIGH,
            status=ControlStatus.FAIL,
            message="Microsoft Defender core protections are not fully enabled.",
            required=True,
            evidence_source="powershell",
            frameworks={"CIS Controls v8": ["10.4"], "NIST CSF 2.0": ["DE.CM"]},
            tags=["CIS", "NIST-CSF"],
            evidence={"failing_checks": ["AntivirusEnabled"]},
        ),
        ControlResult(
            control_id="security-headers",
            title="Headers de securite conformes",
            control_type="security_headers",
            severity=Severity.HIGH,
            status=ControlStatus.FAIL,
            message="Some required security headers are missing or do not satisfy policy rules.",
            required=True,
            evidence_source="http",
            frameworks={"OWASP": ["A05"], "ISO 27001:2022": ["8.28"]},
            tags=["OWASP", "ISO27001"],
            evidence={"missing_headers": ["content-security-policy"]},
        ),
        ControlResult(
            control_id="admin-mfa",
            title="MFA active pour les acces admin",
            control_type="microsoft_graph_admin_mfa",
            severity=Severity.CRITICAL,
            status=ControlStatus.PASS,
            message="All active Microsoft Entra admin accounts satisfy the MFA requirement.",
            required=True,
            evidence_source="graph",
            frameworks={"CIS Controls v8": ["6"], "ISO 27001:2022": ["5.17"]},
            tags=["CIS", "ISO27001"],
            evidence={"compliant_admin_count": 3},
        ),
    ]
    summary = ScanSummary(
        total_controls=4,
        applicable_controls=4,
        score=61.5,
        counts={
            "pass": 2,
            "warn": 0,
            "fail": 2,
            "error": 0,
            "not_applicable": 0,
            "evidence_missing": 0,
        },
        posture="weak",
        compliant=False,
        frameworks={
            "CIS Controls v8": FrameworkSummary(70.0, 3, 3, False, ["windows-defender-running"]),
            "NIST CSF 2.0": FrameworkSummary(50.0, 2, 2, False, ["windows-defender-running"]),
            "ISO 27001:2022": FrameworkSummary(50.0, 2, 2, False, ["security-headers"]),
            "OWASP": FrameworkSummary(0.0, 1, 1, False, ["security-headers"]),
        },
        blocking_controls=["windows-defender-running", "security-headers"],
    )
    return ScanReport(
        lab_name="controlguard sample report",
        description="Deterministic sample report committed to the repository for demonstration purposes.",
        generated_at="2026-04-22T02:30:00+00:00",
        platform="Windows-11 sample",
        results=results,
        summary=summary,
    )


def _build_baseline_report() -> ScanReport:
    results = [
        ControlResult(
            control_id="win-firewall-enabled",
            title="Pare-feu Windows actif",
            control_type="windows_firewall_enabled",
            severity=Severity.CRITICAL,
            status=ControlStatus.PASS,
            message="Windows Firewall is enabled on all profiles.",
            required=True,
            evidence_source="powershell",
            frameworks={"CIS Controls v8": ["4.4"], "NIST CSF 2.0": ["PR.PS"]},
            evidence={"profiles": ["Domain", "Private", "Public"]},
        ),
        ControlResult(
            control_id="windows-defender-running",
            title="Defender actif",
            control_type="windows_defender_running",
            severity=Severity.HIGH,
            status=ControlStatus.FAIL,
            message="Microsoft Defender core protections are not fully enabled.",
            required=True,
            evidence_source="powershell",
            frameworks={"CIS Controls v8": ["10.4"], "NIST CSF 2.0": ["DE.CM"]},
            evidence={"failing_checks": ["AMServiceEnabled", "AntivirusEnabled"]},
        ),
        ControlResult(
            control_id="security-headers",
            title="Headers de securite conformes",
            control_type="security_headers",
            severity=Severity.HIGH,
            status=ControlStatus.FAIL,
            message="Some required security headers are missing or do not satisfy policy rules.",
            required=True,
            evidence_source="http",
            frameworks={"OWASP": ["A05"], "ISO 27001:2022": ["8.28"]},
            evidence={"missing_headers": ["content-security-policy", "strict-transport-security"]},
        ),
        ControlResult(
            control_id="admin-mfa",
            title="MFA active pour les acces admin",
            control_type="microsoft_graph_admin_mfa",
            severity=Severity.CRITICAL,
            status=ControlStatus.EVIDENCE_MISSING,
            message="Microsoft Graph connector is not configured.",
            required=True,
            evidence_source="graph",
            frameworks={"CIS Controls v8": ["6"], "ISO 27001:2022": ["5.17"]},
            evidence={},
        ),
    ]
    summary = ScanSummary(
        total_controls=4,
        applicable_controls=4,
        score=31.0,
        counts={
            "pass": 1,
            "warn": 0,
            "fail": 2,
            "error": 0,
            "not_applicable": 0,
            "evidence_missing": 1,
        },
        posture="critical",
        compliant=False,
        frameworks={
            "CIS Controls v8": FrameworkSummary(40.0, 3, 3, False, ["windows-defender-running", "admin-mfa"]),
            "NIST CSF 2.0": FrameworkSummary(50.0, 2, 2, False, ["windows-defender-running"]),
            "ISO 27001:2022": FrameworkSummary(0.0, 2, 2, False, ["security-headers", "admin-mfa"]),
            "OWASP": FrameworkSummary(0.0, 1, 1, False, ["security-headers"]),
        },
        blocking_controls=["windows-defender-running", "security-headers", "admin-mfa"],
    )
    return ScanReport(
        lab_name="controlguard sample report",
        description="Baseline sample report used to demonstrate comparison output.",
        generated_at="2026-04-20T02:30:00+00:00",
        platform="Windows-11 sample",
        results=results,
        summary=summary,
    )


if __name__ == "__main__":
    main()
