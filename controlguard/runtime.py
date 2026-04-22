from __future__ import annotations

import json
import platform
import shutil
import subprocess
from typing import Any


class UnsupportedPlatformError(RuntimeError):
    """Raised when a control cannot run on the current platform."""


class CheckExecutionError(RuntimeError):
    """Raised when a platform command cannot be executed or parsed."""


def is_windows() -> bool:
    return platform.system().lower() == "windows"


def is_linux() -> bool:
    return platform.system().lower() == "linux"


def ensure_windows(feature: str) -> None:
    if not is_windows():
        raise UnsupportedPlatformError(f"{feature} is only supported on Windows.")


def ensure_linux(feature: str) -> None:
    if not is_linux():
        raise UnsupportedPlatformError(f"{feature} is only supported on Linux.")


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def run_command(command: list[str], timeout_seconds: int = 15) -> str:
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_seconds,
        )
    except subprocess.TimeoutExpired as exc:
        raise CheckExecutionError(f"Command timed out after {timeout_seconds} seconds: {' '.join(command)}") from exc

    if completed.returncode != 0:
        stderr = completed.stderr.strip() or completed.stdout.strip()
        raise CheckExecutionError(stderr or f"Command failed: {' '.join(command)}")
    return completed.stdout


def run_powershell_json(command: str) -> Any:
    ensure_windows("PowerShell-backed controls")
    executable = shutil.which("powershell") or shutil.which("pwsh")
    if not executable:
        raise CheckExecutionError("PowerShell executable not found.")

    try:
        completed = subprocess.run(
            [executable, "-NoProfile", "-Command", command],
            capture_output=True,
            text=True,
            check=False,
            timeout=15,
        )
    except subprocess.TimeoutExpired as exc:
        raise CheckExecutionError(f"PowerShell command timed out after 15 seconds: {command}") from exc

    if completed.returncode != 0:
        stderr = completed.stderr.strip() or completed.stdout.strip()
        raise CheckExecutionError(stderr or f"PowerShell command failed: {command}")

    raw_output = completed.stdout.strip()
    if not raw_output:
        return None

    try:
        return json.loads(raw_output)
    except json.JSONDecodeError as exc:
        raise CheckExecutionError(f"Invalid JSON returned by PowerShell: {raw_output}") from exc
