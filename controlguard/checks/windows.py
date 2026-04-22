from __future__ import annotations

from pathlib import Path

from ..models import ControlDefinition, ControlResult, ControlStatus, LabConfig
from ..runtime import CheckExecutionError, UnsupportedPlatformError, as_list, run_powershell_json


def run_windows_firewall_check(control: ControlDefinition, config: LabConfig) -> ControlResult:
    del config
    try:
        profiles = as_list(
            run_powershell_json(
                "Get-NetFirewallProfile | "
                "Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction | ConvertTo-Json -Compress"
            )
        )
    except UnsupportedPlatformError as exc:
        return _not_applicable_result(control, str(exc))
    except CheckExecutionError as exc:
        return _error_result(control, f"Failed to query firewall profiles: {exc}")

    disabled_profiles = [profile.get("Name") for profile in profiles if not bool(profile.get("Enabled"))]
    if disabled_profiles:
        return _result(
            control,
            ControlStatus.FAIL,
            "One or more firewall profiles are disabled.",
            {"profiles": profiles, "disabled_profiles": disabled_profiles},
            "Enable Windows Firewall on all profiles and validate inbound rules.",
        )

    return _result(
        control,
        ControlStatus.PASS,
        "Windows Firewall is enabled on all profiles.",
        {"profiles": profiles, "disabled_profiles": []},
        "Keep least-privilege firewall rules and review them regularly.",
    )


def run_windows_event_log_check(control: ControlDefinition, config: LabConfig) -> ControlResult:
    del config
    try:
        service = run_powershell_json(
            "Get-Service -Name EventLog | "
            "Select-Object Name,Status,StartType | ConvertTo-Json -Compress"
        )
    except UnsupportedPlatformError as exc:
        return _not_applicable_result(control, str(exc))
    except CheckExecutionError as exc:
        return _error_result(control, f"Failed to query Windows Event Log service: {exc}")

    status = str(service.get("Status", "")).lower()
    start_type = str(service.get("StartType", "")).lower()
    status_running_values = {"running", "4"}
    automatic_values = {"automatic", "automaticdelayedstart", "2"}
    passes = status in status_running_values and start_type in automatic_values
    return _result(
        control,
        ControlStatus.PASS if passes else ControlStatus.FAIL,
        "Windows Event Log service is running and persistent."
        if passes
        else "Windows Event Log service is not running or not set to automatic startup.",
        {"service": service},
        "Set EventLog service to automatic start and ensure audit policies are enabled.",
    )


def run_bitlocker_check(control: ControlDefinition, config: LabConfig) -> ControlResult:
    del config
    drive = str(control.params.get("drive", "C:"))
    escaped_drive = drive.replace("'", "''")
    try:
        volume = run_powershell_json(
            f"Get-BitLockerVolume -MountPoint '{escaped_drive}' | "
            "Select-Object MountPoint,ProtectionStatus,VolumeStatus,EncryptionPercentage | ConvertTo-Json -Compress"
        )
    except UnsupportedPlatformError as exc:
        return _not_applicable_result(control, str(exc))
    except CheckExecutionError as exc:
        return _evidence_missing_result(control, f"BitLocker information unavailable: {exc}")

    if not volume:
        return _evidence_missing_result(control, f"BitLocker returned no data for drive {drive}.")

    protection_status = str(volume.get("ProtectionStatus", "")).lower()
    encryption_percentage = int(volume.get("EncryptionPercentage") or 0)
    protection_is_on = protection_status in {"on", "1", "true"}

    if protection_is_on and encryption_percentage >= 100:
        status = ControlStatus.PASS
        message = "System drive encryption is fully enabled."
    elif protection_is_on and encryption_percentage > 0:
        status = ControlStatus.WARN
        message = "System drive encryption is enabled but not yet complete."
    else:
        status = ControlStatus.FAIL
        message = "System drive encryption is not fully enabled."

    return _result(
        control,
        status,
        message,
        {"drive": drive, "bitlocker": volume},
        "Enable BitLocker protection on the system drive and verify key escrow.",
    )


def run_wide_permissions_check(control: ControlDefinition, config: LabConfig) -> ControlResult:
    del config
    path = Path(str(control.params["path"]))
    if not path.exists():
        return _error_result(control, f"Target path does not exist: {path}")

    patterns = [pattern.lower() for pattern in control.params.get("principal_patterns", ["everyone", "users"])]
    dangerous_rights = [
        right.lower() for right in control.params.get("dangerous_rights", ["FullControl", "Modify", "Write"])
    ]

    escaped_path = str(path).replace("'", "''")
    try:
        rules = as_list(
            run_powershell_json(
                f"(Get-Acl -Path '{escaped_path}').Access | "
                "Select-Object IdentityReference,FileSystemRights,AccessControlType,IsInherited | ConvertTo-Json -Compress"
            )
        )
    except UnsupportedPlatformError as exc:
        return _not_applicable_result(control, str(exc))
    except CheckExecutionError as exc:
        return _error_result(control, f"Failed to read ACLs for {path}: {exc}")

    findings = []
    for rule in rules:
        identity = str(rule.get("IdentityReference", ""))
        rights = str(rule.get("FileSystemRights", ""))
        access_type = str(rule.get("AccessControlType", "")).lower()
        if access_type != "allow":
            continue
        if not any(pattern in identity.lower() for pattern in patterns):
            continue
        if any(dangerous_right in rights.lower() for dangerous_right in dangerous_rights):
            findings.append(rule)

    status = ControlStatus.FAIL if findings else ControlStatus.PASS
    message = (
        "Broad principals have risky permissions on the target path."
        if findings
        else "No risky broad permissions were found on the target path."
    )
    return _result(
        control,
        status,
        message,
        {"path": str(path), "findings": findings, "principal_patterns": patterns},
        "Tighten ACLs on the path and remove wide write or full control permissions.",
    )


def run_windows_defender_check(control: ControlDefinition, config: LabConfig) -> ControlResult:
    del config
    try:
        status = run_powershell_json(
            "Get-MpComputerStatus | "
            "Select-Object AMServiceEnabled,AntivirusEnabled,RealTimeProtectionEnabled,BehaviorMonitorEnabled,NISEnabled | ConvertTo-Json -Compress"
        )
    except UnsupportedPlatformError as exc:
        return _not_applicable_result(control, str(exc))
    except CheckExecutionError as exc:
        return _evidence_missing_result(control, f"Windows Defender status unavailable: {exc}")

    checks = {
        "AMServiceEnabled": bool(status.get("AMServiceEnabled")),
        "AntivirusEnabled": bool(status.get("AntivirusEnabled")),
        "RealTimeProtectionEnabled": bool(status.get("RealTimeProtectionEnabled")),
    }
    failing_checks = [name for name, enabled in checks.items() if not enabled]
    return _result(
        control,
        ControlStatus.PASS if not failing_checks else ControlStatus.FAIL,
        "Microsoft Defender core protections are enabled."
        if not failing_checks
        else "Microsoft Defender core protections are not fully enabled.",
        {"defender_status": status, "failing_checks": failing_checks},
        "Enable Microsoft Defender Antivirus service and real-time protection.",
    )


def run_windows_uac_enabled_check(control: ControlDefinition, config: LabConfig) -> ControlResult:
    del config
    try:
        data = run_powershell_json(
            "Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
            "-Name EnableLUA | Select-Object EnableLUA | ConvertTo-Json -Compress"
        )
    except UnsupportedPlatformError as exc:
        return _not_applicable_result(control, str(exc))
    except CheckExecutionError as exc:
        return _evidence_missing_result(control, f"UAC registry state unavailable: {exc}")

    enabled = str(data.get("EnableLUA", "")).lower() in {"1", "true"}
    return _result(
        control,
        ControlStatus.PASS if enabled else ControlStatus.FAIL,
        "User Account Control is enabled." if enabled else "User Account Control is disabled.",
        {"uac": data},
        "Enable UAC to reduce silent privilege escalation on the workstation.",
    )


def run_powershell_script_block_logging_check(control: ControlDefinition, config: LabConfig) -> ControlResult:
    del config
    try:
        data = run_powershell_json(
            "$value = (Get-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging' "
            "-Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging; "
            "[pscustomobject]@{ EnableScriptBlockLogging = $value } | ConvertTo-Json -Compress"
        )
    except UnsupportedPlatformError as exc:
        return _not_applicable_result(control, str(exc))
    except CheckExecutionError as exc:
        return _evidence_missing_result(control, f"PowerShell logging policy unavailable: {exc}")

    enabled = str(data.get("EnableScriptBlockLogging", "")).lower() in {"1", "true"}
    return _result(
        control,
        ControlStatus.PASS if enabled else ControlStatus.FAIL,
        "PowerShell Script Block Logging is enabled."
        if enabled
        else "PowerShell Script Block Logging is not enabled.",
        {"script_block_logging": data},
        "Enable Script Block Logging via Group Policy for richer command audit trails.",
    )


def run_rdp_disabled_check(control: ControlDefinition, config: LabConfig) -> ControlResult:
    del config
    try:
        data = run_powershell_json(
            "Get-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' "
            "-Name fDenyTSConnections | Select-Object fDenyTSConnections | ConvertTo-Json -Compress"
        )
    except UnsupportedPlatformError as exc:
        return _not_applicable_result(control, str(exc))
    except CheckExecutionError as exc:
        return _evidence_missing_result(control, f"RDP registry state unavailable: {exc}")

    disabled = str(data.get("fDenyTSConnections", "")).lower() in {"1", "true"}
    return _result(
        control,
        ControlStatus.PASS if disabled else ControlStatus.FAIL,
        "Remote Desktop is disabled." if disabled else "Remote Desktop is enabled.",
        {"rdp": data},
        "Disable RDP where not operationally required or restrict it behind hardened bastions.",
    )


def run_smbv1_disabled_check(control: ControlDefinition, config: LabConfig) -> ControlResult:
    del config
    try:
        data = run_powershell_json(
            "Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol | ConvertTo-Json -Compress"
        )
    except UnsupportedPlatformError as exc:
        return _not_applicable_result(control, str(exc))
    except CheckExecutionError as exc:
        return _evidence_missing_result(control, f"SMB configuration unavailable: {exc}")

    enabled = str(data.get("EnableSMB1Protocol", "")).lower() in {"1", "true"}
    return _result(
        control,
        ControlStatus.FAIL if enabled else ControlStatus.PASS,
        "SMBv1 is enabled." if enabled else "SMBv1 is disabled.",
        {"smb": data},
        "Disable SMBv1 to remove a legacy remote attack surface.",
    )


def run_secure_boot_enabled_check(control: ControlDefinition, config: LabConfig) -> ControlResult:
    del config
    try:
        data = run_powershell_json(
            "$result = $null; "
            "try { "
            "$result = [pscustomobject]@{ Supported = $true; Enabled = (Confirm-SecureBootUEFI); Error = $null } "
            "} catch { "
            "$result = [pscustomobject]@{ Supported = $false; Enabled = $null; Error = $_.Exception.Message } "
            "}; "
            "$result | ConvertTo-Json -Compress"
        )
    except UnsupportedPlatformError as exc:
        return _not_applicable_result(control, str(exc))
    except CheckExecutionError as exc:
        return _evidence_missing_result(control, f"Secure Boot state unavailable: {exc}")

    if not bool(data.get("Supported")):
        return _not_applicable_result(control, f"Secure Boot not supported: {data.get('Error')}")

    enabled = bool(data.get("Enabled"))
    return _result(
        control,
        ControlStatus.PASS if enabled else ControlStatus.FAIL,
        "Secure Boot is enabled." if enabled else "Secure Boot is disabled.",
        {"secure_boot": data},
        "Enable Secure Boot to harden the platform boot chain.",
    )


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
        tags=control.tags,
        evidence=evidence,
    )


def _not_applicable_result(control: ControlDefinition, message: str) -> ControlResult:
    return _result(
        control,
        ControlStatus.NOT_APPLICABLE,
        message,
        {},
        control.remediation or "Control not applicable for this target.",
    )


def _evidence_missing_result(control: ControlDefinition, message: str) -> ControlResult:
    return _result(
        control,
        ControlStatus.EVIDENCE_MISSING,
        message,
        {},
        control.remediation or "Evidence source unavailable or incomplete.",
    )


def _error_result(control: ControlDefinition, message: str) -> ControlResult:
    return _result(control, ControlStatus.ERROR, message, {}, control.remediation or "Control execution failed.")
