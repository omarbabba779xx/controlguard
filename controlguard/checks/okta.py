from __future__ import annotations

from ..connectors.okta import OktaApiError, OktaClient, OktaConfigurationError, OktaSettings
from ..models import ControlDefinition, ControlResult, ControlStatus, LabConfig

OKTA_REFERENCES = [
    "https://developer.okta.com/docs/api/openapi/okta-management/management/tags/roleassignmentauser",
    "https://developer.okta.com/docs/reference/api/factors/",
    "https://developer.okta.com/docs/guides/set-up-oauth-api/main/",
]

DEFAULT_ALLOWED_FACTOR_TYPES = [
    "push",
    "signed_nonce",
    "webauthn",
    "u2f",
    "token:software:totp",
    "token:hardware",
]


def run_okta_admin_mfa_check(control: ControlDefinition, config: LabConfig) -> ControlResult:
    del config
    minimum_admin_count = int(control.params.get("minimum_admin_count", 1))
    allowed_factor_types = {
        str(item).strip().lower() for item in control.params.get("allowed_factor_types", DEFAULT_ALLOWED_FACTOR_TYPES)
    }

    try:
        settings = OktaSettings.from_params(control.params)
        client = OktaClient(settings)
        admin_users, auth_mode = client.list_admin_users()
    except OktaConfigurationError as exc:
        return _result(
            control,
            ControlStatus.EVIDENCE_MISSING,
            f"Okta connector is not configured: {exc}",
            {"allowed_factor_types": sorted(allowed_factor_types)},
        )
    except OktaApiError as exc:
        return _result(
            control,
            ControlStatus.EVIDENCE_MISSING,
            f"Okta API request failed: {exc}",
            {"allowed_factor_types": sorted(allowed_factor_types), "status_code": exc.status_code},
        )

    if len(admin_users) < minimum_admin_count:
        return _result(
            control,
            ControlStatus.EVIDENCE_MISSING,
            f"Expected at least {minimum_admin_count} Okta admin account(s), but found {len(admin_users)}.",
            {
                "auth_mode": auth_mode,
                "minimum_admin_count": minimum_admin_count,
                "admin_count": len(admin_users),
            },
        )

    compliant_admins: list[dict[str, object]] = []
    non_compliant_admins: list[dict[str, object]] = []
    for admin_user in admin_users:
        user_id = admin_user.get("id")
        if not user_id:
            non_compliant_admins.append({"id": None, "reason": "missing user id"})
            continue
        try:
            factors = client.list_user_factors(str(user_id))
        except OktaApiError as exc:
            return _result(
                control,
                ControlStatus.EVIDENCE_MISSING,
                f"Unable to retrieve Okta factors for admin {user_id}: {exc}",
                {"auth_mode": auth_mode, "status_code": exc.status_code},
            )

        strong_factors = _extract_strong_factors(factors, allowed_factor_types)
        summary = {
            "id": admin_user.get("id"),
            "login": _extract_login(admin_user),
            "strong_factors": strong_factors,
            "factor_types_seen": sorted(
                {factor_type for factor in factors for factor_type in [_factor_type(factor)] if factor_type is not None}
            ),
        }
        if strong_factors:
            compliant_admins.append(summary)
        else:
            non_compliant_admins.append(summary)

    status = ControlStatus.PASS if not non_compliant_admins else ControlStatus.FAIL
    message = (
        "All Okta admin accounts have at least one strong enrolled MFA factor."
        if status is ControlStatus.PASS
        else "One or more Okta admin accounts do not have a strong enrolled MFA factor."
    )
    return _result(
        control,
        status,
        message,
        {
            "auth_mode": auth_mode,
            "minimum_admin_count": minimum_admin_count,
            "admin_count": len(admin_users),
            "allowed_factor_types": sorted(allowed_factor_types),
            "compliant_admin_count": len(compliant_admins),
            "compliant_admins": compliant_admins,
            "non_compliant_admins": non_compliant_admins,
        },
    )


def _extract_strong_factors(factors: list[dict], allowed_factor_types: set[str]) -> list[str]:
    enrolled = []
    for factor in factors:
        status = str(factor.get("status", "")).strip().upper()
        factor_type = _factor_type(factor)
        if status not in {"ACTIVE", "ENROLLED"}:
            continue
        if factor_type and factor_type in allowed_factor_types:
            enrolled.append(factor_type)
    return sorted(set(enrolled))


def _factor_type(factor: dict) -> str | None:
    candidates = [
        factor.get("factorType"),
        factor.get("type"),
        factor.get("key"),
        factor.get("provider"),
    ]
    embedded = factor.get("_embedded", {})
    if isinstance(embedded, dict):
        authenticator = embedded.get("authenticator", {})
        if isinstance(authenticator, dict):
            candidates.extend([authenticator.get("key"), authenticator.get("type")])
    for candidate in candidates:
        if candidate:
            return str(candidate).strip().lower()
    return None


def _extract_login(admin_user: dict) -> str | None:
    profile = admin_user.get("profile", {})
    if isinstance(profile, dict) and profile.get("login"):
        return str(profile.get("login"))
    return admin_user.get("id")


def _result(
    control: ControlDefinition,
    status: ControlStatus,
    message: str,
    evidence: dict,
) -> ControlResult:
    remediation = control.remediation or (
        "Grant the connector okta.roles.read and okta.users.read, then ensure every Okta admin account is enrolled in a strong factor such as push, TOTP, FastPass, or WebAuthn."
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
        references=control.references or OKTA_REFERENCES,
        frameworks=control.frameworks,
        tags=control.tags,
        evidence=evidence,
    )
