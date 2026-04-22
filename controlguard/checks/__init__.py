from __future__ import annotations

from collections.abc import Callable

from .graph import run_microsoft_graph_admin_mfa_check
from .linux import (
    run_linux_auditd_check,
    run_linux_firewall_check,
    run_linux_ssh_password_auth_disabled_check,
)
from .manual import run_manual_assertion
from .network import run_sensitive_ports_check
from .okta import run_okta_admin_mfa_check
from .web import run_security_headers_check
from .windows import (
    run_bitlocker_check,
    run_powershell_script_block_logging_check,
    run_rdp_disabled_check,
    run_secure_boot_enabled_check,
    run_smbv1_disabled_check,
    run_wide_permissions_check,
    run_windows_defender_check,
    run_windows_event_log_check,
    run_windows_firewall_check,
    run_windows_uac_enabled_check,
)

CheckFn = Callable

CHECK_SPECS: dict[str, dict] = {
    "manual_assertion": {
        "runner": run_manual_assertion,
        "required_params": ["evidence_key"],
    },
    "microsoft_graph_admin_mfa": {
        "runner": run_microsoft_graph_admin_mfa_check,
        "required_params": [],
        "validator": lambda control: _validate_graph_admin_mfa(control),
    },
    "okta_admin_mfa": {
        "runner": run_okta_admin_mfa_check,
        "required_params": ["okta_domain"],
        "validator": lambda control: _validate_okta_admin_mfa(control),
    },
    "sensitive_ports_exposed": {
        "runner": run_sensitive_ports_check,
        "required_params": [],
    },
    "security_headers": {
        "runner": run_security_headers_check,
        "required_params": ["url"],
        "validator": lambda control: _validate_security_headers(control),
    },
    "bitlocker_system_drive": {
        "runner": run_bitlocker_check,
        "required_params": [],
    },
    "wide_permissions": {
        "runner": run_wide_permissions_check,
        "required_params": ["path"],
    },
    "linux_firewall_enabled": {
        "runner": run_linux_firewall_check,
        "required_params": [],
    },
    "linux_auditd_running": {
        "runner": run_linux_auditd_check,
        "required_params": [],
    },
    "linux_ssh_password_auth_disabled": {
        "runner": run_linux_ssh_password_auth_disabled_check,
        "required_params": [],
    },
    "windows_defender_running": {
        "runner": run_windows_defender_check,
        "required_params": [],
    },
    "windows_event_log_running": {
        "runner": run_windows_event_log_check,
        "required_params": [],
    },
    "windows_firewall_enabled": {
        "runner": run_windows_firewall_check,
        "required_params": [],
    },
    "windows_uac_enabled": {
        "runner": run_windows_uac_enabled_check,
        "required_params": [],
    },
    "powershell_script_block_logging": {
        "runner": run_powershell_script_block_logging_check,
        "required_params": [],
    },
    "rdp_disabled": {
        "runner": run_rdp_disabled_check,
        "required_params": [],
    },
    "secure_boot_enabled": {
        "runner": run_secure_boot_enabled_check,
        "required_params": [],
    },
    "smbv1_disabled": {
        "runner": run_smbv1_disabled_check,
        "required_params": [],
    },
}

CHECKS: dict[str, CheckFn] = {name: spec["runner"] for name, spec in CHECK_SPECS.items()}


def _validate_security_headers(control) -> list[str]:
    errors: list[str] = []
    header_rules = control.params.get("header_rules", {})
    if header_rules and not isinstance(header_rules, dict):
        errors.append(f"Control '{control.id}' header_rules must be an object.")
    return errors


def _validate_graph_admin_mfa(control) -> list[str]:
    errors: list[str] = []
    has_access_token = bool(control.params.get("access_token") or control.params.get("access_token_env"))
    has_client_credentials = bool(
        (control.params.get("tenant") or control.params.get("tenant_env"))
        and (control.params.get("client_id") or control.params.get("client_id_env"))
        and (control.params.get("client_secret") or control.params.get("client_secret_env"))
    )
    if not has_access_token and not has_client_credentials:
        errors.append(
            f"Control '{control.id}' must define either access_token/access_token_env "
            "or tenant+client_id+client_secret (direct values or *_env variants)."
        )

    requirement = str(control.params.get("mfa_requirement", "capable")).strip().lower()
    if requirement not in {"registered", "capable"}:
        errors.append(f"Control '{control.id}' mfa_requirement must be 'registered' or 'capable'.")

    try:
        minimum_admin_count = int(control.params.get("minimum_admin_count", 1))
        if minimum_admin_count <= 0:
            errors.append(f"Control '{control.id}' minimum_admin_count must be greater than zero.")
    except (TypeError, ValueError):
        errors.append(f"Control '{control.id}' minimum_admin_count must be an integer.")

    max_report_age_hours = control.params.get("max_report_age_hours")
    if max_report_age_hours is not None:
        try:
            if float(max_report_age_hours) <= 0:
                errors.append(f"Control '{control.id}' max_report_age_hours must be greater than zero.")
        except (TypeError, ValueError):
            errors.append(f"Control '{control.id}' max_report_age_hours must be numeric.")

    return errors


def _validate_okta_admin_mfa(control) -> list[str]:
    errors: list[str] = []
    has_access_token = bool(control.params.get("access_token") or control.params.get("access_token_env"))
    has_api_token = bool(control.params.get("api_token") or control.params.get("api_token_env"))
    if not has_access_token and not has_api_token:
        errors.append(
            f"Control '{control.id}' must define access_token/access_token_env or api_token/api_token_env."
        )

    try:
        minimum_admin_count = int(control.params.get("minimum_admin_count", 1))
        if minimum_admin_count <= 0:
            errors.append(f"Control '{control.id}' minimum_admin_count must be greater than zero.")
    except (TypeError, ValueError):
        errors.append(f"Control '{control.id}' minimum_admin_count must be an integer.")

    allowed_factor_types = control.params.get("allowed_factor_types", [])
    if allowed_factor_types and not isinstance(allowed_factor_types, list):
        errors.append(f"Control '{control.id}' allowed_factor_types must be a list.")
    return errors
