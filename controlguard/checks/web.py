from __future__ import annotations

import urllib.error
import urllib.request
from urllib.parse import urlparse

from ..models import ControlDefinition, ControlResult, ControlStatus, LabConfig

DEFAULT_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
]


def run_security_headers_check(control: ControlDefinition, config: LabConfig) -> ControlResult:
    del config
    url = str(control.params["url"])
    required_headers = [header.lower() for header in control.params.get("required_headers", DEFAULT_HEADERS)]
    header_rules = {header.lower(): rule for header, rule in control.params.get("header_rules", {}).items()}

    if urlparse(url).scheme.lower() != "https":
        return _build_result(
            control,
            ControlStatus.FAIL,
            "Target URL is not using HTTPS.",
            {"url": url, "required_headers": required_headers, "header_rules": header_rules},
        )

    try:
        response = _request_headers(url)
    except urllib.error.URLError as exc:
        return _build_result(
            control,
            ControlStatus.ERROR,
            f"Failed to fetch target URL: {exc.reason}",
            {"url": url, "required_headers": required_headers, "header_rules": header_rules},
        )

    present_headers = {key.lower(): value for key, value in response["headers"].items()}
    missing_headers = [header for header in required_headers if header not in present_headers]
    invalid_headers = _evaluate_header_rules(present_headers, header_rules)
    status = ControlStatus.PASS if not missing_headers and not invalid_headers else ControlStatus.FAIL
    message = (
        "All required security headers are present and satisfy policy rules."
        if status is ControlStatus.PASS
        else "Some required security headers are missing or do not satisfy policy rules."
    )

    return _build_result(
        control,
        status,
        message,
        {
            "url": url,
            "request_method": response["request_method"],
            "status_code": response["status_code"],
            "final_url": response["final_url"],
            "required_headers": required_headers,
            "header_rules": header_rules,
            "missing_headers": missing_headers,
            "invalid_headers": invalid_headers,
            "present_headers": present_headers,
        },
    )


def _request_headers(url: str) -> dict:
    headers = {"User-Agent": "controlguard/0.1"}
    for method in ("HEAD", "GET"):
        request = urllib.request.Request(url, method=method, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                return {
                    "request_method": method,
                    "status_code": response.status,
                    "final_url": response.geturl(),
                    "headers": dict(response.headers.items()),
                }
        except urllib.error.HTTPError as exc:
            if method == "HEAD" and exc.code in {405, 501}:
                continue
            return {
                "request_method": method,
                "status_code": exc.code,
                "final_url": exc.geturl(),
                "headers": dict(exc.headers.items()),
            }
        except urllib.error.URLError:
            if method == "GET":
                raise
    raise urllib.error.URLError("Unable to fetch headers")


def _evaluate_header_rules(present_headers: dict[str, str], header_rules: dict[str, object]) -> list[dict[str, object]]:
    invalid_headers: list[dict[str, object]] = []
    for header, rule in header_rules.items():
        actual_value = present_headers.get(header)
        if actual_value is None:
            continue

        rule_payload = rule if isinstance(rule, dict) else {"equals": str(rule)}
        normalized_actual = actual_value.lower()
        equals = rule_payload.get("equals")
        contains = rule_payload.get("contains", [])
        one_of = rule_payload.get("one_of", [])

        rule_ok = True
        if equals is not None:
            rule_ok = normalized_actual == str(equals).lower()
        if rule_ok and contains:
            tokens = contains if isinstance(contains, list) else [contains]
            rule_ok = all(str(token).lower() in normalized_actual for token in tokens)
        if rule_ok and one_of:
            options = one_of if isinstance(one_of, list) else [one_of]
            rule_ok = any(str(option).lower() == normalized_actual for option in options)

        if not rule_ok:
            invalid_headers.append({"header": header, "actual": actual_value, "rule": rule_payload})
    return invalid_headers


def _build_result(
    control: ControlDefinition,
    status: ControlStatus,
    message: str,
    evidence: dict,
) -> ControlResult:
    remediation = (
        control.remediation or "Configure the missing security headers in the reverse proxy or application layer."
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
        references=control.references,
        tags=control.tags,
        evidence=evidence,
    )
