from __future__ import annotations

import ipaddress
import shutil

from ..models import ControlDefinition, ControlResult, ControlStatus, LabConfig
from ..runtime import (
    CheckExecutionError,
    UnsupportedPlatformError,
    as_list,
    is_linux,
    run_command,
    run_powershell_json,
)

DEFAULT_SENSITIVE_PORTS = [21, 23, 3389, 445]


def run_sensitive_ports_check(control: ControlDefinition, config: LabConfig) -> ControlResult:
    del config
    ports = [int(port) for port in control.params.get("ports", DEFAULT_SENSITIVE_PORTS)]
    ignore_loopback = bool(control.params.get("ignore_loopback", True))

    try:
        raw_connections = _list_listening_connections()
    except UnsupportedPlatformError as exc:
        return _build_result(
            control,
            ControlStatus.NOT_APPLICABLE,
            str(exc),
            {"ports": ports},
        )
    except CheckExecutionError as exc:
        return _build_result(
            control,
            ControlStatus.ERROR,
            f"Failed to inspect listening ports: {exc}",
            {"ports": ports},
        )

    findings = []
    loopback_only = []
    for connection in as_list(raw_connections):
        local_port = int(connection.get("LocalPort", 0))
        if local_port not in ports:
            continue

        address = str(connection.get("LocalAddress", ""))
        record = {
            "local_address": address,
            "local_port": local_port,
            "owning_process": connection.get("OwningProcess"),
            "process_name": connection.get("ProcessName"),
        }
        if ignore_loopback and _is_loopback(address):
            loopback_only.append(record)
            continue
        findings.append(record)

    if findings:
        message = "Sensitive ports are exposed on non-loopback interfaces."
        status = ControlStatus.FAIL
    else:
        message = "No sensitive ports are exposed on non-loopback interfaces."
        status = ControlStatus.PASS

    return _build_result(
        control,
        status,
        message,
        {
            "sensitive_ports": ports,
            "ignore_loopback": ignore_loopback,
            "findings": findings,
            "loopback_only": loopback_only,
        },
    )


def _list_listening_connections():
    if is_linux():
        return _list_linux_connections()
    return run_powershell_json(
        "Get-NetTCPConnection -State Listen | "
        "Select-Object LocalAddress,LocalPort,OwningProcess,"
        "@{Name='ProcessName';Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} | "
        "ConvertTo-Json -Compress"
    )


def _list_linux_connections() -> list[dict]:
    executable = shutil.which("ss")
    if not executable:
        raise UnsupportedPlatformError("Sensitive port inspection on Linux requires the 'ss' command.")
    output = run_command([executable, "-lntpH"])
    connections = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        fields = line.split()
        if len(fields) < 5:
            continue
        local_field = fields[3]
        process_field = fields[5] if len(fields) > 5 else ""
        local_address, local_port = _parse_local_endpoint(local_field)
        process_name = _parse_linux_process_name(process_field)
        connections.append(
            {
                "LocalAddress": local_address,
                "LocalPort": local_port,
                "OwningProcess": None,
                "ProcessName": process_name,
            }
        )
    return connections


def _parse_local_endpoint(endpoint: str) -> tuple[str, int]:
    if endpoint.startswith("[") and "]:" in endpoint:
        address, port = endpoint.rsplit("]:", 1)
        return address.strip("[]"), int(port)
    address, port = endpoint.rsplit(":", 1)
    return address, int(port)


def _parse_linux_process_name(process_field: str) -> str | None:
    if '"' in process_field:
        parts = process_field.split('"')
        if len(parts) >= 2:
            return parts[1]
    return process_field or None


def _is_loopback(address: str) -> bool:
    if address in {"*", "0.0.0.0", "::"}:
        return False

    try:
        return ipaddress.ip_address(address).is_loopback
    except ValueError:
        return False


def _build_result(
    control: ControlDefinition,
    status: ControlStatus,
    message: str,
    evidence: dict,
) -> ControlResult:
    remediation = control.remediation or "Disable the service, bind it to loopback only, or restrict access with a firewall."
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
        references=control.references,
        tags=control.tags,
        evidence=evidence,
    )
