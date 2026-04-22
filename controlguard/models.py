from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class ControlStatus(str, Enum):
    PASS = "pass"
    WARN = "warn"
    FAIL = "fail"
    ERROR = "error"
    NOT_APPLICABLE = "not_applicable"
    EVIDENCE_MISSING = "evidence_missing"

    @property
    def score_factor(self) -> float | None:
        return {
            ControlStatus.PASS: 1.0,
            ControlStatus.WARN: 0.5,
            ControlStatus.FAIL: 0.0,
            ControlStatus.ERROR: 0.0,
            ControlStatus.NOT_APPLICABLE: None,
            ControlStatus.EVIDENCE_MISSING: 0.0,
        }[self]

    @property
    def is_finding(self) -> bool:
        return self in {
            ControlStatus.WARN,
            ControlStatus.FAIL,
            ControlStatus.ERROR,
            ControlStatus.EVIDENCE_MISSING,
        }

    @property
    def is_blocking(self) -> bool:
        return self in {
            ControlStatus.FAIL,
            ControlStatus.ERROR,
            ControlStatus.EVIDENCE_MISSING,
        }


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @classmethod
    def from_value(cls, value: str | None) -> "Severity":
        normalized = (value or cls.MEDIUM.value).strip().lower()
        for item in cls:
            if item.value == normalized:
                return item
        raise ValueError(f"Unknown severity: {value}")

    @property
    def weight(self) -> int:
        return {
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 5,
        }[self]


@dataclass(frozen=True)
class ControlDefinition:
    id: str
    title: str
    type: str
    severity: Severity = Severity.MEDIUM
    required: bool = True
    description: str = ""
    rationale: str = ""
    remediation: str = ""
    evidence_source: str = "runtime"
    supported_platforms: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    frameworks: dict[str, list[str]] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    params: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "severity", Severity.from_value(self.severity))
        object.__setattr__(self, "tags", list(self.tags))
        object.__setattr__(self, "references", list(self.references))
        object.__setattr__(self, "supported_platforms", [platform.lower() for platform in self.supported_platforms])
        normalized_frameworks = _normalize_frameworks(self.frameworks)
        object.__setattr__(self, "frameworks", normalized_frameworks or _infer_frameworks_from_tags(self.tags))
        object.__setattr__(self, "params", dict(self.params))


@dataclass(frozen=True)
class LabConfig:
    lab_name: str
    description: str
    controls: list[ControlDefinition]
    manual_evidence: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ControlResult:
    control_id: str
    title: str
    control_type: str
    severity: Severity
    status: ControlStatus
    message: str
    required: bool = True
    description: str = ""
    rationale: str = ""
    remediation: str = ""
    evidence_source: str = "runtime"
    supported_platforms: list[str] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    frameworks: dict[str, list[str]] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "severity", Severity.from_value(self.severity))
        if not isinstance(self.status, ControlStatus):
            object.__setattr__(self, "status", ControlStatus(self.status))
        object.__setattr__(self, "tags", list(self.tags))
        object.__setattr__(self, "references", list(self.references))
        object.__setattr__(self, "supported_platforms", [platform.lower() for platform in self.supported_platforms])
        normalized_frameworks = _normalize_frameworks(self.frameworks)
        object.__setattr__(self, "frameworks", normalized_frameworks or _infer_frameworks_from_tags(self.tags))
        object.__setattr__(self, "evidence", dict(self.evidence))


@dataclass(frozen=True)
class FrameworkSummary:
    score: float
    total_controls: int
    applicable_controls: int
    compliant: bool
    blocking_controls: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ScanSummary:
    total_controls: int
    applicable_controls: int
    score: float
    counts: dict[str, int]
    posture: str
    compliant: bool
    frameworks: dict[str, FrameworkSummary] = field(default_factory=dict)
    blocking_controls: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ScanReport:
    lab_name: str
    description: str
    generated_at: str
    platform: str
    results: list[ControlResult]
    summary: ScanSummary


def _normalize_frameworks(value: Any) -> dict[str, list[str]]:
    if value is None:
        return {}
    normalized: dict[str, list[str]] = {}
    for framework, refs in dict(value).items():
        normalized[str(framework)] = [str(ref) for ref in refs]
    return normalized


def _infer_frameworks_from_tags(tags: list[str]) -> dict[str, list[str]]:
    inferred: dict[str, list[str]] = {}
    normalized_tags = {str(tag).strip().lower() for tag in tags}
    tag_map = {
        "cis": ("CIS Controls v8", "Tagged control mapping"),
        "nist-csf": ("NIST CSF 2.0", "Tagged control mapping"),
        "iso27001": ("ISO 27001:2022", "Tagged control mapping"),
        "owasp": ("OWASP", "Tagged control mapping"),
    }
    for tag, (framework, reference) in tag_map.items():
        if tag in normalized_tags:
            inferred.setdefault(framework, []).append(reference)
    return inferred
