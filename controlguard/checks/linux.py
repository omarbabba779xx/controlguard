from __future__ import annotations

from pathlib import Path
import shutil

from ..models import ControlDefinition, ControlResult, ControlStatus, LabConfig
from ..runtime import CheckExecutionError, UnsupportedPlatformError, ensure_linux, run_command


def run_linux_firewall_check(control: ControlDefinition, config: LabConfig) -> ControlResult:
    del config
    try:
        ensure_linux("Linux firewall controls")
        if _command_exists("ufw"):
            output = run_command(["ufw", "status"])
            enabled = "status: active" in output.lower()
            return _result(
                control,
                ControlStatus.PASS if enabled else ControlStatus.FAIL,
                "UFW is active." if enabled else "UFW is not active.",
                {"provider": "ufw", "raw_output": output.strip()},
                "Enable and configure UFW or an equivalent host firewall on the server.",
            )
        if _command_exists("systemctl"):
            firewalld_active = _systemctl_state("firewalld", "is-active") == "active"
            if firewalld_active:
                return _result(
                    control,
                    ControlStatus.PASS,
                    "firewalld is active.",
                    {"provider": "firewalld", "state": "active"},
                    "Keep the firewalld policy aligned with least privilege.",
                )
        if _command_exists("nft"):
            output = run_command(["nft", "list", "ruleset"])
            enabled = bool(output.strip())
            return _result(
                control,
                ControlStatus.PASS if enabled else ControlStatus.FAIL,
                "nftables ruleset is present." if enabled else "nftables ruleset is empty.",
                {"provider": "nftables", "ruleset_present": enabled},
                "Define nftables rules or activate a supported Linux firewall service.",
            )
        return _result(
            control,
            ControlStatus.EVIDENCE_MISSING,
            "No supported Linux firewall provider was detected (ufw, firewalld, nftables).",
            {},
            "Install or expose a supported firewall provider so the control can validate host protection.",
        )
    except UnsupportedPlatformError as exc:
        return _result(control, ControlStatus.NOT_APPLICABLE, str(exc), {}, "Control not applicable.")
    except CheckExecutionError as exc:
        return _result(
            control,
            ControlStatus.EVIDENCE_MISSING,
            f"Unable to determine Linux firewall state: {exc}",
            {},
            "Ensure the firewall service is installed and readable by the scanning process.",
        )


def run_linux_auditd_check(control: ControlDefinition, config: LabConfig) -> ControlResult:
    del config
    try:
        ensure_linux("Linux auditd controls")
        if not _command_exists("systemctl"):
            return _result(
                control,
                ControlStatus.EVIDENCE_MISSING,
                "systemctl is required to validate auditd state on this Linux host.",
                {},
                "Install systemd tooling or adapt the control for your init system.",
            )
        active_state = _systemctl_state("auditd", "is-active")
        enabled_state = _systemctl_state("auditd", "is-enabled")
        passes = active_state == "active" and enabled_state == "enabled"
        return _result(
            control,
            ControlStatus.PASS if passes else ControlStatus.FAIL,
            "auditd is active and enabled." if passes else "auditd is not active and enabled.",
            {"active_state": active_state, "enabled_state": enabled_state},
            "Enable auditd and ensure it starts automatically at boot.",
        )
    except UnsupportedPlatformError as exc:
        return _result(control, ControlStatus.NOT_APPLICABLE, str(exc), {}, "Control not applicable.")
    except CheckExecutionError as exc:
        return _result(
            control,
            ControlStatus.EVIDENCE_MISSING,
            f"Unable to inspect auditd state: {exc}",
            {},
            "Ensure auditd is installed and systemd can report its state.",
        )


def run_linux_ssh_password_auth_disabled_check(control: ControlDefinition, config: LabConfig) -> ControlResult:
    del config
    try:
        ensure_linux("Linux SSH hardening controls")
        config_files = [Path("/etc/ssh/sshd_config")]
        drop_in_dir = Path("/etc/ssh/sshd_config.d")
        if drop_in_dir.exists():
            config_files.extend(sorted(drop_in_dir.glob("*.conf")))

        settings = []
        for config_file in config_files:
            if not config_file.exists():
                continue
            for line_number, line in enumerate(config_file.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if stripped.lower().startswith("passwordauthentication"):
                    parts = stripped.split()
                    if len(parts) >= 2:
                        settings.append(
                            {
                                "file": str(config_file),
                                "line": line_number,
                                "value": parts[1].lower(),
                            }
                        )

        if not settings:
            return _result(
                control,
                ControlStatus.WARN,
                "PasswordAuthentication is not explicitly set in sshd configuration.",
                {"matches": []},
                "Set PasswordAuthentication no explicitly in sshd_config or its drop-in files.",
            )

        effective = settings[-1]
        passes = effective["value"] == "no"
        return _result(
            control,
            ControlStatus.PASS if passes else ControlStatus.FAIL,
            "SSH password authentication is disabled." if passes else "SSH password authentication is enabled.",
            {"matches": settings, "effective": effective},
            "Disable SSH password authentication and require stronger methods such as keys or certificates.",
        )
    except UnsupportedPlatformError as exc:
        return _result(control, ControlStatus.NOT_APPLICABLE, str(exc), {}, "Control not applicable.")
    except OSError as exc:
        return _result(
            control,
            ControlStatus.EVIDENCE_MISSING,
            f"Unable to read SSH configuration: {exc}",
            {},
            "Ensure the scanner can read sshd configuration files.",
        )


def _command_exists(command: str) -> bool:
    return shutil.which(command) is not None


def _systemctl_state(service: str, operation: str) -> str:
    output = run_command(["systemctl", operation, service])
    return output.strip().lower()


def _result(
    control: ControlDefinition,
    status: ControlStatus,
    message: str,
    evidence: dict,
    remediation: str,
) -> ControlResult:
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
        remediation=control.remediation or remediation,
        evidence_source=control.evidence_source,
        supported_platforms=control.supported_platforms,
        references=control.references,
        frameworks=control.frameworks,
        tags=control.tags,
        evidence=evidence,
    )
