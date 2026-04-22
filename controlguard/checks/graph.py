from __future__ import annotations

from datetime import datetime, timezone

from ..connectors.microsoft_graph import (
    MicrosoftGraphApiError,
    MicrosoftGraphClient,
    MicrosoftGraphConfigurationError,
    MicrosoftGraphSettings,
)
from ..models import ControlDefinition, ControlResult, ControlStatus, LabConfig

GRAPH_REFERENCES = [
    "https://learn.microsoft.com/en-us/graph/api/authenticationmethodsroot-list-userregistrationdetails?view=graph-rest-1.0",
    "https://learn.microsoft.com/en-us/graph/api/resources/userregistrationdetails?view=graph-rest-1.0",
    "https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-client-creds-grant-flow",
    "https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-methods-activity",
]


def run_microsoft_graph_admin_mfa_check(control: ControlDefinition, config: LabConfig) -> ControlResult:
    del config
    requirement = str(control.params.get("mfa_requirement", "capable")).strip().lower()
    minimum_admin_count = int(control.params.get("minimum_admin_count", 1))
    max_report_age_hours = control.params.get("max_report_age_hours")
    max_report_age_hours = float(max_report_age_hours) if max_report_age_hours is not None else None

    try:
        settings = MicrosoftGraphSettings.from_params(control.params)
        details, auth_mode = MicrosoftGraphClient(settings).list_user_registration_details()
    except MicrosoftGraphConfigurationError as exc:
        return _result(
            control,
            ControlStatus.EVIDENCE_MISSING,
            f"Microsoft Graph connector is not configured: {exc}",
            {"requirement": requirement},
        )
    except MicrosoftGraphApiError as exc:
        return _result(
            control,
            ControlStatus.EVIDENCE_MISSING,
            _graph_error_message(exc),
            {"requirement": requirement, "status_code": exc.status_code, "code": exc.code},
        )

    admin_rows = [row for row in details if bool(row.get("isAdmin"))]
    if not details:
        return _result(
            control,
            ControlStatus.EVIDENCE_MISSING,
            "Microsoft Graph returned no registration details. Check tenant licensing and report readiness.",
            {"requirement": requirement, "auth_mode": auth_mode},
        )
    if len(admin_rows) < minimum_admin_count:
        return _result(
            control,
            ControlStatus.EVIDENCE_MISSING,
            f"Expected at least {minimum_admin_count} active admin account(s) in Microsoft Graph, but found {len(admin_rows)}.",
            {
                "requirement": requirement,
                "auth_mode": auth_mode,
                "minimum_admin_count": minimum_admin_count,
                "total_records": len(details),
                "admin_count": len(admin_rows),
            },
        )

    stale_admins = _find_stale_admins(admin_rows, max_report_age_hours)
    non_compliant = [row for row in admin_rows if not _admin_satisfies_requirement(row, requirement)]
    status = ControlStatus.PASS if not non_compliant else ControlStatus.FAIL
    if stale_admins and status is ControlStatus.PASS:
        status = ControlStatus.WARN

    message = (
        "All active Microsoft Entra admin accounts satisfy the MFA requirement."
        if status is ControlStatus.PASS
        else "One or more active Microsoft Entra admin accounts do not satisfy the MFA requirement."
    )
    if status is ControlStatus.WARN:
        message = "Admin MFA state is compliant, but Microsoft Graph registration data is stale."

    evidence = {
        "requirement": requirement,
        "auth_mode": auth_mode,
        "minimum_admin_count": minimum_admin_count,
        "max_report_age_hours": max_report_age_hours,
        "total_records": len(details),
        "admin_count": len(admin_rows),
        "compliant_admin_count": len(admin_rows) - len(non_compliant),
        "non_compliant_admins": [_summarize_admin(row) for row in non_compliant],
        "stale_admins": stale_admins,
        "latest_report_update": _max_timestamp(admin_rows),
        "oldest_report_update": _min_timestamp(admin_rows),
    }
    return _result(control, status, message, evidence)


def _admin_satisfies_requirement(row: dict, requirement: str) -> bool:
    if requirement == "registered":
        return bool(row.get("isMfaRegistered"))
    return bool(row.get("isMfaCapable"))


def _find_stale_admins(admin_rows: list[dict], max_report_age_hours: float | None) -> list[dict]:
    if max_report_age_hours is None:
        return []
    stale_admins: list[dict] = []
    for row in admin_rows:
        updated_raw = row.get("lastUpdatedDateTime")
        parsed = _parse_timestamp(updated_raw)
        if parsed is None:
            stale_admins.append({"userPrincipalName": row.get("userPrincipalName"), "lastUpdatedDateTime": updated_raw})
            continue
        age_hours = (datetime.now(timezone.utc) - parsed).total_seconds() / 3600
        if age_hours > max_report_age_hours:
            stale_admins.append(
                {
                    "userPrincipalName": row.get("userPrincipalName"),
                    "lastUpdatedDateTime": updated_raw,
                    "age_hours": round(age_hours, 2),
                }
            )
    return stale_admins


def _parse_timestamp(value: object) -> datetime | None:
    if not value:
        return None
    try:
        text = str(value).replace("Z", "+00:00")
        return datetime.fromisoformat(text)
    except ValueError:
        return None


def _max_timestamp(admin_rows: list[dict]) -> str | None:
    timestamps = [
        str(row.get("lastUpdatedDateTime")) for row in admin_rows if row.get("lastUpdatedDateTime") is not None
    ]
    return max(timestamps) if timestamps else None


def _min_timestamp(admin_rows: list[dict]) -> str | None:
    timestamps = [
        str(row.get("lastUpdatedDateTime")) for row in admin_rows if row.get("lastUpdatedDateTime") is not None
    ]
    return min(timestamps) if timestamps else None


def _summarize_admin(row: dict) -> dict:
    return {
        "id": row.get("id"),
        "userPrincipalName": row.get("userPrincipalName"),
        "userDisplayName": row.get("userDisplayName"),
        "userType": row.get("userType"),
        "isMfaRegistered": row.get("isMfaRegistered"),
        "isMfaCapable": row.get("isMfaCapable"),
        "methodsRegistered": row.get("methodsRegistered"),
        "lastUpdatedDateTime": row.get("lastUpdatedDateTime"),
    }


def _graph_error_message(exc: MicrosoftGraphApiError) -> str:
    if exc.status_code in {401, 403}:
        return (
            "Microsoft Graph rejected the request. Ensure the app has AuditLog.Read.All application permission, "
            "admin consent was granted, and the credential is valid."
        )
    return f"Microsoft Graph request failed: {exc}"


def _result(
    control: ControlDefinition,
    status: ControlStatus,
    message: str,
    evidence: dict,
) -> ControlResult:
    remediation = control.remediation or (
        "Configure Microsoft Graph app credentials, grant AuditLog.Read.All application permission with admin consent, "
        "and ensure the tenant has Microsoft Entra ID P1 or P2 for authentication methods reporting."
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
        remediation=remediation,
        evidence_source=control.evidence_source,
        supported_platforms=control.supported_platforms,
        references=control.references or GRAPH_REFERENCES,
        frameworks=control.frameworks,
        tags=control.tags,
        evidence=evidence,
    )
