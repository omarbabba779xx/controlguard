from __future__ import annotations

from collections import Counter
from dataclasses import replace
from datetime import datetime, timezone
import platform

from .checks import CHECKS
from .models import ControlResult, ControlStatus, FrameworkSummary, LabConfig, ScanReport, ScanSummary


class ScanEngine:
    def run(self, config: LabConfig) -> ScanReport:
        results = [self._run_control(control, config) for control in config.controls]
        summary = self._build_summary(results)
        return ScanReport(
            lab_name=config.lab_name,
            description=config.description,
            generated_at=datetime.now(timezone.utc).isoformat(),
            platform=platform.platform(),
            results=results,
            summary=summary,
        )

    def _run_control(self, control, config: LabConfig) -> ControlResult:
        if not _is_control_applicable_to_host(control.supported_platforms):
            return ControlResult(
                control_id=control.id,
                title=control.title,
                control_type=control.type,
                severity=control.severity,
                status=ControlStatus.NOT_APPLICABLE,
                message=f"Control targets {', '.join(control.supported_platforms)} and is not applicable to this host.",
                required=control.required,
                description=control.description,
                rationale=control.rationale,
                remediation=control.remediation or "Control not applicable for this host platform.",
                evidence_source=control.evidence_source,
                supported_platforms=control.supported_platforms,
                references=control.references,
                frameworks=control.frameworks,
                tags=control.tags,
                evidence={},
            )
        check = CHECKS.get(control.type)
        if check is None:
            return ControlResult(
                control_id=control.id,
                title=control.title,
                control_type=control.type,
                severity=control.severity,
                status=ControlStatus.ERROR,
                message=f"Unknown control type: {control.type}",
                required=control.required,
                description=control.description,
                rationale=control.rationale,
                remediation=control.remediation or "Implement or register the missing control type.",
                evidence_source=control.evidence_source,
                supported_platforms=control.supported_platforms,
                references=control.references,
                frameworks=control.frameworks,
                tags=control.tags,
                evidence={},
            )

        try:
            return check(control, config)
        except Exception as exc:
            return ControlResult(
                control_id=control.id,
                title=control.title,
                control_type=control.type,
                severity=control.severity,
                status=ControlStatus.ERROR,
                message=f"Unhandled control error: {exc}",
                required=control.required,
                description=control.description,
                rationale=control.rationale,
                remediation=control.remediation or "Inspect the control implementation and retry the scan.",
                evidence_source=control.evidence_source,
                supported_platforms=control.supported_platforms,
                references=control.references,
                frameworks=control.frameworks,
                tags=control.tags,
                evidence={"error_type": type(exc).__name__},
            )

    def _build_summary(self, results: list[ControlResult]) -> ScanSummary:
        counts = Counter(result.status.value for result in results)
        total_weight = 0
        earned_weight = 0.0
        applicable_controls = 0
        blocking_controls: list[str] = []

        for result in results:
            factor = result.status.score_factor
            if factor is None:
                continue

            applicable_controls += 1
            weight = result.severity.weight
            total_weight += weight
            earned_weight += weight * factor
            if result.required and result.status.is_blocking:
                blocking_controls.append(result.control_id)

        score = round((earned_weight / total_weight) * 100, 1) if total_weight else 100.0
        posture = _posture_from_score(score, results, blocking_controls)
        frameworks = _build_framework_summaries(results)
        return ScanSummary(
            total_controls=len(results),
            applicable_controls=applicable_controls,
            score=score,
            counts={status.value: counts.get(status.value, 0) for status in ControlStatus},
            posture=posture,
            compliant=not blocking_controls,
            frameworks=frameworks,
            blocking_controls=blocking_controls,
        )


def filter_report(report: ScanReport, only_failed: bool = False) -> ScanReport:
    if not only_failed:
        return report
    filtered_results = [result for result in report.results if result.status.is_finding]
    return replace(report, results=filtered_results)


def _posture_from_score(score: float, results: list[ControlResult], blocking_controls: list[str]) -> str:
    if any(result.required and result.status.is_blocking and result.severity.value == "critical" for result in results):
        return "critical"
    if blocking_controls:
        return "weak"
    if score >= 90:
        return "strong"
    if score >= 70:
        return "improving"
    return "weak"


def _is_control_applicable_to_host(supported_platforms: list[str]) -> bool:
    if not supported_platforms or "any" in supported_platforms:
        return True
    os_markers = {"windows", "linux", "macos"}
    targeted_os = [item for item in supported_platforms if item in os_markers]
    if not targeted_os:
        return True
    current_os = platform.system().lower()
    return current_os in targeted_os


def _build_framework_summaries(results: list[ControlResult]) -> dict[str, FrameworkSummary]:
    grouped: dict[str, list[ControlResult]] = {}
    for result in results:
        for framework in result.frameworks:
            grouped.setdefault(framework, []).append(result)

    summaries: dict[str, FrameworkSummary] = {}
    for framework, framework_results in grouped.items():
        total_controls = len(framework_results)
        applicable_controls = 0
        total_weight = 0
        earned_weight = 0.0
        blocking_controls: list[str] = []
        for result in framework_results:
            factor = result.status.score_factor
            if factor is None:
                continue
            applicable_controls += 1
            weight = result.severity.weight
            total_weight += weight
            earned_weight += weight * factor
            if result.required and result.status.is_blocking:
                blocking_controls.append(result.control_id)

        score = round((earned_weight / total_weight) * 100, 1) if total_weight else 100.0
        summaries[framework] = FrameworkSummary(
            score=score,
            total_controls=total_controls,
            applicable_controls=applicable_controls,
            compliant=not blocking_controls,
            blocking_controls=blocking_controls,
        )
    return summaries
