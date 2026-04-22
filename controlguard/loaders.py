from __future__ import annotations

import json
from pathlib import Path

from .models import ControlDefinition, LabConfig, Severity
from .validation import validate_config

KNOWN_CONTROL_KEYS = {
    "id",
    "title",
    "type",
    "severity",
    "required",
    "description",
    "rationale",
    "remediation",
    "evidence_source",
    "supported_platforms",
    "references",
    "frameworks",
    "tags",
    "params",
}


def load_config(path: str | Path) -> LabConfig:
    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Configuration file not found: {config_path}")

    payload = json.loads(config_path.read_text(encoding="utf-8"))

    controls = [_parse_control(control_payload) for control_payload in payload.get("controls", [])]
    if not controls:
        raise ValueError("Configuration must contain at least one control.")

    config = LabConfig(
        lab_name=payload.get("lab_name", config_path.stem),
        description=payload.get("description", ""),
        controls=controls,
        manual_evidence=payload.get("manual_evidence", {}),
    )
    validate_config(config)
    return config


def _parse_control(payload: dict) -> ControlDefinition:
    for required_key in ("id", "title", "type"):
        if required_key not in payload:
            raise ValueError(f"Missing required control key: {required_key}")

    params = dict(payload.get("params", {}))
    for key, value in payload.items():
        if key not in KNOWN_CONTROL_KEYS:
            params[key] = value

    return ControlDefinition(
        id=payload["id"],
        title=payload["title"],
        type=payload["type"],
        severity=Severity.from_value(payload.get("severity")),
        required=bool(payload.get("required", True)),
        description=payload.get("description", ""),
        rationale=payload.get("rationale", ""),
        remediation=payload.get("remediation", ""),
        evidence_source=payload.get("evidence_source", "runtime"),
        supported_platforms=list(payload.get("supported_platforms", [])),
        references=list(payload.get("references", [])),
        frameworks=dict(payload.get("frameworks", {})),
        tags=list(payload.get("tags", [])),
        params=params,
    )
