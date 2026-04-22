from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .comparison import (
    compare_report_payloads,
    load_report_payload,
    render_compare_html,
    render_compare_json,
    render_compare_markdown,
)
from .engine import ScanEngine, filter_report
from .loaders import load_config
from .models import ControlStatus
from .profiles import builtin_profiles, resolve_profile_path
from .reporting import render_csv, render_html, render_json, render_markdown, render_sarif


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Security Control Validation Lab")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Run a control validation scan")
    _add_target_arguments(scan_parser)
    scan_parser.add_argument(
        "--format",
        choices=("markdown", "json", "html", "sarif", "csv"),
        default="markdown",
        help="Output format printed to stdout.",
    )
    scan_parser.add_argument(
        "--output",
        help="Optional file path where the rendered report will be written.",
    )
    scan_parser.add_argument(
        "--fail-on-warn",
        action="store_true",
        help="Return a non-zero exit code when a control is in warn state.",
    )
    scan_parser.add_argument(
        "--strict",
        action="store_true",
        help="Return a non-zero exit code when any finding exists, including warnings.",
    )
    scan_parser.add_argument(
        "--only-failed",
        action="store_true",
        help="Only render findings (warn, fail, error, evidence_missing).",
    )

    validate_parser = subparsers.add_parser("validate", help="Validate a profile without running a scan")
    _add_target_arguments(validate_parser)

    compare_parser = subparsers.add_parser("compare", help="Compare two JSON scan reports")
    compare_parser.add_argument("--baseline", required=True, help="Path to the baseline JSON report.")
    compare_parser.add_argument("--current", required=True, help="Path to the current JSON report.")
    compare_parser.add_argument(
        "--format",
        choices=("markdown", "json", "html"),
        default="markdown",
        help="Output format for the comparison report.",
    )
    compare_parser.add_argument("--output", help="Optional file path where the comparison output will be written.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "validate":
        try:
            config_path = resolve_profile_path(getattr(args, "config", None), getattr(args, "profile", None))
            config = load_config(config_path)
        except Exception as exc:
            print(f"Configuration error: {exc}", file=sys.stderr)
            return 2
        print(f"Profile '{config.lab_name}' is valid with {len(config.controls)} controls.")
        return 0
    if args.command == "compare":
        try:
            comparison = compare_report_payloads(
                baseline=load_report_payload(args.baseline),
                current=load_report_payload(args.current),
            )
        except Exception as exc:
            print(f"Comparison error: {exc}", file=sys.stderr)
            return 2
        rendered = _render_comparison(comparison, args.format)
        if args.output:
            output_path = Path(args.output)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(rendered, encoding="utf-8")
        print(rendered)
        return 0
    if args.command != "scan":
        parser.error(f"Unsupported command: {args.command}")

    try:
        config_path = resolve_profile_path(getattr(args, "config", None), getattr(args, "profile", None))
        config = load_config(config_path)
    except Exception as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        return 2

    report = ScanEngine().run(config)
    display_report = filter_report(report, only_failed=args.only_failed)
    rendered = _render_report(display_report, args.format)

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")

    print(rendered)
    return _exit_code(report, fail_on_warn=args.fail_on_warn, strict=args.strict)


def _add_target_arguments(parser: argparse.ArgumentParser) -> None:
    profiles = builtin_profiles()
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--config",
        help="Path to a custom lab configuration JSON file.",
    )
    group.add_argument(
        "--profile",
        choices=sorted(profiles),
        help="Built-in profile name.",
    )


def _render_report(report, output_format: str) -> str:
    renderers = {
        "markdown": render_markdown,
        "json": render_json,
        "html": render_html,
        "sarif": render_sarif,
        "csv": render_csv,
    }
    return renderers[output_format](report)


def _render_comparison(comparison: dict, output_format: str) -> str:
    renderers = {
        "markdown": render_compare_markdown,
        "json": render_compare_json,
        "html": render_compare_html,
    }
    return renderers[output_format](comparison)


def _exit_code(report, fail_on_warn: bool, strict: bool) -> int:
    statuses = {result.status for result in report.results}
    hard_failure_statuses = {
        ControlStatus.FAIL,
        ControlStatus.ERROR,
        ControlStatus.EVIDENCE_MISSING,
    }
    if statuses & hard_failure_statuses:
        return 1
    if fail_on_warn and ControlStatus.WARN in statuses:
        return 1
    if strict and any(status.is_finding for status in statuses):
        return 1
    return 0
