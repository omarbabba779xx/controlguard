from __future__ import annotations

from ..models import ControlDefinition, ControlResult, ControlStatus, LabConfig

_MISSING = object()


def run_manual_assertion(control: ControlDefinition, config: LabConfig) -> ControlResult:
    evidence_key = str(control.params.get("evidence_key"))
    expected = control.params.get("expected", True)
    actual = config.manual_evidence.get(evidence_key, _MISSING)

    if actual is _MISSING:
        return ControlResult(
            control_id=control.id,
            title=control.title,
            control_type=control.type,
            severity=control.severity,
            status=ControlStatus.EVIDENCE_MISSING,
            message=f"No manual evidence was provided for '{evidence_key}'.",
            required=control.required,
            description=control.description,
            rationale=control.rationale,
            remediation=control.remediation or "Record evidence or connect the control to a source system.",
            evidence_source=control.evidence_source,
            supported_platforms=control.supported_platforms,
            references=control.references,
            tags=control.tags,
            evidence={"evidence_key": evidence_key, "expected": expected, "actual": None},
        )

    status = ControlStatus.PASS if actual == expected else ControlStatus.FAIL
    message = (
        f"Manual evidence matches expected value for '{evidence_key}'."
        if status is ControlStatus.PASS
        else f"Manual evidence does not match expected value for '{evidence_key}'."
    )
    return ControlResult(
        control_id=control.id,
        title=control.title,
        control_type=control.type,
        severity=control.severity,
        status=status,
        message=message,
        required=control.required,
        description=control.description,
        rationale=control.rationale,
        remediation=control.remediation or "Update the control evidence or remediate the control itself.",
        evidence_source=control.evidence_source,
        supported_platforms=control.supported_platforms,
        references=control.references,
        tags=control.tags,
        evidence={"evidence_key": evidence_key, "expected": expected, "actual": actual},
    )
