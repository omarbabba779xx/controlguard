from __future__ import annotations

from .checks import CHECK_SPECS
from .models import ControlDefinition, LabConfig

SUPPORTED_PLATFORM_VALUES = {
    "any",
    "windows",
    "linux",
    "macos",
    "web",
    "network",
    "cloud",
}


def validate_config(config: LabConfig) -> None:
    errors: list[str] = []
    if not isinstance(config.manual_evidence, dict):
        errors.append("manual_evidence must be a JSON object.")

    seen_ids: set[str] = set()
    for control in config.controls:
        errors.extend(_validate_control(control, seen_ids))

    if errors:
        raise ValueError("\n".join(errors))


def _validate_control(control: ControlDefinition, seen_ids: set[str]) -> list[str]:
    errors: list[str] = []
    if control.id in seen_ids:
        errors.append(f"Duplicate control id detected: {control.id}")
    seen_ids.add(control.id)

    spec = CHECK_SPECS.get(control.type)
    if spec is None:
        errors.append(f"Unknown control type: {control.type}")
        return errors

    if not control.evidence_source.strip():
        errors.append(f"Control '{control.id}' must define a non-empty evidence_source.")

    if not isinstance(control.frameworks, dict):
        errors.append(f"Control '{control.id}' frameworks must be an object.")
    else:
        for framework, refs in control.frameworks.items():
            if not framework.strip():
                errors.append(f"Control '{control.id}' contains an empty framework name.")
            if not isinstance(refs, list) or not refs:
                errors.append(f"Control '{control.id}' framework '{framework}' must contain at least one reference.")

    invalid_platforms = [
        platform for platform in control.supported_platforms if platform not in SUPPORTED_PLATFORM_VALUES
    ]
    if invalid_platforms:
        errors.append(f"Control '{control.id}' has unsupported platform values: {', '.join(sorted(invalid_platforms))}")

    for param_name in spec["required_params"]:
        if param_name not in control.params:
            errors.append(f"Control '{control.id}' is missing required parameter '{param_name}'.")

    validator = spec.get("validator")
    if validator:
        errors.extend(validator(control))

    return errors
