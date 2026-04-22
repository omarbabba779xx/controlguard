from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest.mock import patch

from controlguard.checks.graph import run_microsoft_graph_admin_mfa_check
from controlguard.checks.linux import (
    run_linux_auditd_check,
    run_linux_firewall_check,
    run_linux_ssh_password_auth_disabled_check,
)
from controlguard.checks.network import run_sensitive_ports_check
from controlguard.checks.okta import run_okta_admin_mfa_check
from controlguard.checks.web import run_security_headers_check
from controlguard.checks.windows import (
    run_bitlocker_check,
    run_secure_boot_enabled_check,
    run_windows_defender_check,
    run_windows_event_log_check,
)
from controlguard.cli import main
from controlguard.comparison import compare_report_payloads
from controlguard.connectors.microsoft_graph import MicrosoftGraphClient, MicrosoftGraphSettings
from controlguard.connectors.okta import OktaClient, OktaSettings
from controlguard.engine import ScanEngine, filter_report
from controlguard.loaders import load_config
from controlguard.models import (
    ControlDefinition,
    ControlResult,
    ControlStatus,
    FrameworkSummary,
    LabConfig,
    ScanReport,
    ScanSummary,
    Severity,
)
from controlguard.reporting import render_csv, render_markdown, render_sarif


class ModelAndLoaderTests(unittest.TestCase):
    def test_definition_normalizes_severity_from_string(self) -> None:
        control = ControlDefinition(id="mfa", title="MFA", type="manual_assertion", severity="critical")
        self.assertEqual(control.severity, Severity.CRITICAL)

    def test_duplicate_control_ids_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "bad.json"
            config_path.write_text(
                json.dumps(
                    {
                        "lab_name": "bad",
                        "controls": [
                            {"id": "dup", "title": "A", "type": "manual_assertion", "evidence_key": "x"},
                            {"id": "dup", "title": "B", "type": "manual_assertion", "evidence_key": "y"},
                        ],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "Duplicate control id detected: dup"):
                load_config(config_path)

    def test_missing_required_param_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "bad.json"
            config_path.write_text(
                json.dumps(
                    {
                        "lab_name": "bad",
                        "controls": [
                            {"id": "mfa", "title": "MFA", "type": "manual_assertion"}
                        ],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "missing required parameter 'evidence_key'"):
                load_config(config_path)

    def test_graph_control_requires_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "bad.json"
            config_path.write_text(
                json.dumps(
                    {
                        "lab_name": "bad",
                        "controls": [
                            {
                                "id": "graph",
                                "title": "Graph MFA",
                                "type": "microsoft_graph_admin_mfa",
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "must define either access_token/access_token_env"):
                load_config(config_path)


class SummaryTests(unittest.TestCase):
    def test_evidence_missing_is_blocking_and_scores_zero(self) -> None:
        engine = ScanEngine()
        config = LabConfig(
            lab_name="demo",
            description="",
            manual_evidence={},
            controls=[
                ControlDefinition(
                    id="mfa",
                    title="MFA",
                    type="manual_assertion",
                    severity=Severity.CRITICAL,
                )
            ],
        )

        report = engine.run(config)

        self.assertEqual(report.results[0].status, ControlStatus.EVIDENCE_MISSING)
        self.assertEqual(report.summary.score, 0.0)
        self.assertFalse(report.summary.compliant)
        self.assertEqual(report.summary.blocking_controls, ["mfa"])
        self.assertEqual(report.summary.posture, "critical")

    def test_not_applicable_is_excluded_from_score(self) -> None:
        engine = ScanEngine()
        results = [
            ControlResult(
                control_id="secure-boot",
                title="Secure Boot",
                control_type="secure_boot_enabled",
                severity=Severity.MEDIUM,
                status=ControlStatus.NOT_APPLICABLE,
                message="unsupported",
            ),
            ControlResult(
                control_id="fw",
                title="FW",
                control_type="windows_firewall_enabled",
                severity=Severity.CRITICAL,
                status=ControlStatus.PASS,
                message="ok",
            ),
        ]

        summary = engine._build_summary(results)

        self.assertEqual(summary.score, 100.0)
        self.assertEqual(summary.applicable_controls, 1)
        self.assertTrue(summary.compliant)

    def test_engine_marks_linux_control_not_applicable_on_windows_host(self) -> None:
        config = LabConfig(
            lab_name="linux",
            description="",
            manual_evidence={},
            controls=[
                ControlDefinition(
                    id="linux-only",
                    title="Linux only",
                    type="linux_firewall_enabled",
                    supported_platforms=["linux"],
                )
            ],
        )
        report = ScanEngine().run(config)

        self.assertEqual(report.results[0].status, ControlStatus.NOT_APPLICABLE)

    def test_filter_report_keeps_only_findings(self) -> None:
        report = ScanReport(
            lab_name="Lab",
            description="",
            generated_at="2026-04-22T00:00:00+00:00",
            platform="Windows",
            results=[
                ControlResult(
                    control_id="a",
                    title="A",
                    control_type="manual_assertion",
                    severity=Severity.MEDIUM,
                    status=ControlStatus.PASS,
                    message="ok",
                ),
                ControlResult(
                    control_id="b",
                    title="B",
                    control_type="manual_assertion",
                    severity=Severity.HIGH,
                    status=ControlStatus.FAIL,
                    message="no",
                ),
            ],
            summary=ScanSummary(
                total_controls=2,
                applicable_controls=2,
                score=50.0,
                counts={status.value: 0 for status in ControlStatus},
                posture="weak",
                compliant=False,
                blocking_controls=["b"],
            ),
        )

        filtered = filter_report(report, only_failed=True)

        self.assertEqual(len(filtered.results), 1)
        self.assertEqual(filtered.results[0].control_id, "b")


class NetworkAndWebChecksTests(unittest.TestCase):
    @patch("controlguard.checks.network.run_powershell_json")
    def test_sensitive_ports_ignore_loopback(self, mocked_run) -> None:
        mocked_run.return_value = [
            {"LocalAddress": "127.0.0.1", "LocalPort": 3389, "OwningProcess": 999, "ProcessName": "rdp"},
            {"LocalAddress": "10.0.0.5", "LocalPort": 445, "OwningProcess": 888, "ProcessName": "system"},
        ]
        control = ControlDefinition(
            id="ports",
            title="Ports",
            type="sensitive_ports_exposed",
            params={"ports": [3389, 445], "ignore_loopback": True},
        )

        result = run_sensitive_ports_check(control, LabConfig("lab", "", [], {}))

        self.assertEqual(result.status, ControlStatus.FAIL)
        self.assertEqual(len(result.evidence["findings"]), 1)
        self.assertEqual(result.evidence["findings"][0]["process_name"], "system")
        self.assertEqual(len(result.evidence["loopback_only"]), 1)

    @patch("controlguard.checks.web._request_headers")
    def test_security_headers_detect_invalid_rule(self, mocked_request) -> None:
        mocked_request.return_value = {
            "request_method": "GET",
            "status_code": 200,
            "final_url": "https://demo.local",
            "headers": {
                "Strict-Transport-Security": "max-age=63072000",
                "X-Frame-Options": "ALLOWALL",
                "X-Content-Type-Options": "nosniff",
            },
        }
        control = ControlDefinition(
            id="headers",
            title="Headers",
            type="security_headers",
            params={
                "url": "https://demo.local",
                "required_headers": [
                    "strict-transport-security",
                    "x-content-type-options",
                    "x-frame-options",
                ],
                "header_rules": {
                    "x-frame-options": {"one_of": ["DENY", "SAMEORIGIN"]},
                    "x-content-type-options": "nosniff",
                },
            },
        )

        result = run_security_headers_check(control, LabConfig("lab", "", [], {}))

        self.assertEqual(result.status, ControlStatus.FAIL)
        self.assertEqual(result.evidence["invalid_headers"][0]["header"], "x-frame-options")


class MicrosoftGraphConnectorTests(unittest.TestCase):
    @patch("controlguard.connectors.microsoft_graph._request_json")
    def test_graph_client_follows_next_link(self, mocked_request_json) -> None:
        mocked_request_json.side_effect = [
            {
                "value": [{"id": "1", "isAdmin": True, "isMfaCapable": True}],
                "@odata.nextLink": "https://graph.microsoft.com/v1.0/reports/authenticationMethods/userRegistrationDetails?$skiptoken=abc",
            },
            {
                "value": [{"id": "2", "isAdmin": False, "isMfaCapable": False}],
            },
        ]
        client = MicrosoftGraphClient(MicrosoftGraphSettings(access_token="token"))

        rows, auth_mode = client.list_user_registration_details()

        self.assertEqual(auth_mode, "access_token")
        self.assertEqual([row["id"] for row in rows], ["1", "2"])

    def test_graph_settings_reads_env_credentials(self) -> None:
        settings = MicrosoftGraphSettings(
            tenant_env="TENANT",
            client_id_env="CLIENT_ID",
            client_secret_env="CLIENT_SECRET",
        )
        with patch.dict(
            "os.environ",
            {"TENANT": "tenant-id", "CLIENT_ID": "client-id", "CLIENT_SECRET": "secret"},
            clear=True,
        ):
            with patch("controlguard.connectors.microsoft_graph._request_client_credentials_token", return_value="token"):
                token, auth_mode = settings.resolve_access_token()

        self.assertEqual(token, "token")
        self.assertEqual(auth_mode, "client_credentials")


class OktaConnectorTests(unittest.TestCase):
    @patch("controlguard.connectors.okta._request_json")
    def test_okta_client_follows_next_link(self, mocked_request_json) -> None:
        mocked_request_json.side_effect = [
            (
                {
                    "value": [{"id": "1"}],
                    "_links": {"next": {"href": "https://example.okta.com/api/v1/iam/assignees/users?after=abc"}},
                },
                {},
            ),
            (
                {"value": [{"id": "2"}]},
                {},
            ),
        ]
        client = OktaClient(OktaSettings(okta_domain="https://example.okta.com", access_token="token"))

        users, auth_mode = client.list_admin_users()

        self.assertEqual(auth_mode, "oauth_access_token")
        self.assertEqual([user["id"] for user in users], ["1", "2"])

    def test_okta_settings_reads_api_token_env(self) -> None:
        settings = OktaSettings(okta_domain="https://example.okta.com", api_token_env="OKTA_TOKEN")
        with patch.dict("os.environ", {"OKTA_TOKEN": "secret"}, clear=True):
            header, auth_mode = settings.resolve_auth_header()
        self.assertEqual(header, "SSWS secret")
        self.assertEqual(auth_mode, "api_token")


class GraphControlTests(unittest.TestCase):
    @patch("controlguard.checks.graph.MicrosoftGraphClient.list_user_registration_details")
    def test_graph_admin_mfa_fails_for_non_compliant_admin(self, mocked_list) -> None:
        mocked_list.return_value = (
            [
                {
                    "id": "1",
                    "isAdmin": True,
                    "userPrincipalName": "admin1@contoso.com",
                    "userDisplayName": "Admin 1",
                    "userType": "member",
                    "isMfaRegistered": True,
                    "isMfaCapable": True,
                    "methodsRegistered": ["microsoftAuthenticatorPush"],
                    "lastUpdatedDateTime": "2026-04-21T00:00:00Z",
                },
                {
                    "id": "2",
                    "isAdmin": True,
                    "userPrincipalName": "admin2@contoso.com",
                    "userDisplayName": "Admin 2",
                    "userType": "member",
                    "isMfaRegistered": False,
                    "isMfaCapable": False,
                    "methodsRegistered": [],
                    "lastUpdatedDateTime": "2026-04-21T00:00:00Z",
                },
            ],
            "client_credentials",
        )
        control = ControlDefinition(
            id="admin-mfa",
            title="Admin MFA",
            type="microsoft_graph_admin_mfa",
            params={"access_token": "token", "mfa_requirement": "capable"},
        )

        result = run_microsoft_graph_admin_mfa_check(control, LabConfig("lab", "", [], {}))

        self.assertEqual(result.status, ControlStatus.FAIL)
        self.assertEqual(result.evidence["admin_count"], 2)
        self.assertEqual(result.evidence["non_compliant_admins"][0]["userPrincipalName"], "admin2@contoso.com")

    @patch("controlguard.checks.graph.MicrosoftGraphClient.list_user_registration_details")
    def test_graph_admin_mfa_passes_when_all_admins_are_capable(self, mocked_list) -> None:
        mocked_list.return_value = (
            [
                {
                    "id": "1",
                    "isAdmin": True,
                    "userPrincipalName": "admin1@contoso.com",
                    "userDisplayName": "Admin 1",
                    "userType": "member",
                    "isMfaRegistered": True,
                    "isMfaCapable": True,
                    "methodsRegistered": ["microsoftAuthenticatorPush"],
                    "lastUpdatedDateTime": "2026-04-21T00:00:00Z",
                }
            ],
            "access_token",
        )
        control = ControlDefinition(
            id="admin-mfa",
            title="Admin MFA",
            type="microsoft_graph_admin_mfa",
            params={"access_token": "token", "mfa_requirement": "capable"},
        )

        result = run_microsoft_graph_admin_mfa_check(control, LabConfig("lab", "", [], {}))

        self.assertEqual(result.status, ControlStatus.PASS)
        self.assertEqual(result.evidence["compliant_admin_count"], 1)

    def test_graph_admin_mfa_reports_missing_configuration(self) -> None:
        control = ControlDefinition(
            id="admin-mfa",
            title="Admin MFA",
            type="microsoft_graph_admin_mfa",
            params={},
        )

        result = run_microsoft_graph_admin_mfa_check(control, LabConfig("lab", "", [], {}))

        self.assertEqual(result.status, ControlStatus.EVIDENCE_MISSING)
        self.assertIn("not configured", result.message)


class OktaControlTests(unittest.TestCase):
    @patch("controlguard.checks.okta.OktaClient.list_user_factors")
    @patch("controlguard.checks.okta.OktaClient.list_admin_users")
    def test_okta_admin_mfa_fails_for_admin_without_strong_factor(self, mocked_admins, mocked_factors) -> None:
        mocked_admins.return_value = ([{"id": "1", "profile": {"login": "admin@example.com"}}], "oauth_access_token")
        mocked_factors.return_value = [
            {"factorType": "sms", "status": "ACTIVE"},
        ]
        control = ControlDefinition(
            id="okta-admin-mfa",
            title="Okta admin MFA",
            type="okta_admin_mfa",
            params={"okta_domain": "https://example.okta.com", "access_token": "token"},
        )

        result = run_okta_admin_mfa_check(control, LabConfig("lab", "", [], {}))

        self.assertEqual(result.status, ControlStatus.FAIL)
        self.assertEqual(result.evidence["non_compliant_admins"][0]["login"], "admin@example.com")

    @patch("controlguard.checks.okta.OktaClient.list_user_factors")
    @patch("controlguard.checks.okta.OktaClient.list_admin_users")
    def test_okta_admin_mfa_passes_for_webauthn(self, mocked_admins, mocked_factors) -> None:
        mocked_admins.return_value = ([{"id": "1", "profile": {"login": "admin@example.com"}}], "api_token")
        mocked_factors.return_value = [
            {"factorType": "webauthn", "status": "ACTIVE"},
        ]
        control = ControlDefinition(
            id="okta-admin-mfa",
            title="Okta admin MFA",
            type="okta_admin_mfa",
            params={"okta_domain": "https://example.okta.com", "api_token": "token"},
        )

        result = run_okta_admin_mfa_check(control, LabConfig("lab", "", [], {}))

        self.assertEqual(result.status, ControlStatus.PASS)
        self.assertEqual(result.evidence["compliant_admin_count"], 1)


class LinuxChecksTests(unittest.TestCase):
    @patch("controlguard.checks.linux._command_exists")
    @patch("controlguard.checks.linux.run_command")
    @patch("controlguard.checks.linux.ensure_linux")
    def test_linux_firewall_passes_for_active_ufw(self, mocked_ensure_linux, mocked_run_command, mocked_command_exists) -> None:
        mocked_command_exists.side_effect = lambda name: name == "ufw"
        mocked_run_command.return_value = "Status: active\n"
        control = ControlDefinition(id="linux-fw", title="Linux FW", type="linux_firewall_enabled")

        result = run_linux_firewall_check(control, LabConfig("lab", "", [], {}))

        self.assertEqual(result.status, ControlStatus.PASS)
        self.assertEqual(result.evidence["provider"], "ufw")

    @patch("controlguard.checks.linux._command_exists")
    @patch("controlguard.checks.linux._systemctl_state")
    @patch("controlguard.checks.linux.ensure_linux")
    def test_linux_auditd_fails_when_disabled(self, mocked_ensure_linux, mocked_systemctl_state, mocked_command_exists) -> None:
        mocked_command_exists.return_value = True
        mocked_systemctl_state.side_effect = ["inactive", "disabled"]
        control = ControlDefinition(id="auditd", title="auditd", type="linux_auditd_running")

        result = run_linux_auditd_check(control, LabConfig("lab", "", [], {}))

        self.assertEqual(result.status, ControlStatus.FAIL)

    @patch("controlguard.checks.linux.ensure_linux")
    @patch("controlguard.checks.linux.Path.exists")
    @patch("controlguard.checks.linux.Path.read_text")
    def test_linux_ssh_password_auth_disabled_detects_enabled(self, mocked_read_text, mocked_exists, mocked_ensure_linux) -> None:
        mocked_exists.side_effect = lambda *args, **kwargs: True
        mocked_read_text.return_value = "PasswordAuthentication yes\n"
        control = ControlDefinition(id="ssh", title="ssh", type="linux_ssh_password_auth_disabled")

        result = run_linux_ssh_password_auth_disabled_check(control, LabConfig("lab", "", [], {}))

        self.assertEqual(result.status, ControlStatus.FAIL)
        self.assertEqual(result.evidence["effective"]["value"], "yes")


class WindowsChecksTests(unittest.TestCase):
    @patch("controlguard.checks.windows.run_powershell_json")
    def test_event_log_accepts_numeric_service_states(self, mocked_run) -> None:
        mocked_run.return_value = {"Name": "EventLog", "Status": 4, "StartType": 2}
        control = ControlDefinition(id="event-log", title="Event Log", type="windows_event_log_running")

        result = run_windows_event_log_check(control, LabConfig("lab", "", [], {}))

        self.assertEqual(result.status, ControlStatus.PASS)

    @patch("controlguard.checks.windows.run_powershell_json")
    def test_defender_control_detects_missing_protection(self, mocked_run) -> None:
        mocked_run.return_value = {
            "AMServiceEnabled": True,
            "AntivirusEnabled": False,
            "RealTimeProtectionEnabled": True,
        }
        control = ControlDefinition(id="defender", title="Defender", type="windows_defender_running")

        result = run_windows_defender_check(control, LabConfig("lab", "", [], {}))

        self.assertEqual(result.status, ControlStatus.FAIL)
        self.assertIn("AntivirusEnabled", result.evidence["failing_checks"])

    @patch("controlguard.checks.windows.run_powershell_json")
    def test_secure_boot_not_supported_is_not_applicable(self, mocked_run) -> None:
        mocked_run.return_value = {"Supported": False, "Enabled": None, "Error": "BIOS mode"}
        control = ControlDefinition(id="boot", title="Secure Boot", type="secure_boot_enabled")

        result = run_secure_boot_enabled_check(control, LabConfig("lab", "", [], {}))

        self.assertEqual(result.status, ControlStatus.NOT_APPLICABLE)

    @patch("controlguard.checks.windows.run_powershell_json")
    def test_bitlocker_without_data_is_evidence_missing(self, mocked_run) -> None:
        mocked_run.return_value = None
        control = ControlDefinition(id="bitlocker", title="BitLocker", type="bitlocker_system_drive")

        result = run_bitlocker_check(control, LabConfig("lab", "", [], {}))

        self.assertEqual(result.status, ControlStatus.EVIDENCE_MISSING)


class ReportingTests(unittest.TestCase):
    def test_markdown_report_contains_new_summary_fields(self) -> None:
        report = ScanReport(
            lab_name="Security Lab",
            description="Demo report",
            generated_at="2026-04-22T00:00:00+00:00",
            platform="Windows",
            results=[
                ControlResult(
                    control_id="firewall",
                    title="Pare-feu",
                    control_type="windows_firewall_enabled",
                    severity=Severity.CRITICAL,
                    status=ControlStatus.PASS,
                    message="ok",
                    evidence={"profiles": []},
                )
            ],
            summary=ScanSummary(
                total_controls=1,
                applicable_controls=1,
                score=100.0,
                counts={status.value: 0 for status in ControlStatus} | {"pass": 1},
                posture="strong",
                compliant=True,
                frameworks={
                    "CIS Controls v8": FrameworkSummary(
                        score=100.0,
                        total_controls=1,
                        applicable_controls=1,
                        compliant=True,
                        blocking_controls=[],
                    )
                },
                blocking_controls=[],
            ),
        )

        rendered = render_markdown(report)
        self.assertIn("Compliant: `true`", rendered)
        self.assertIn("not applicable", rendered)
        self.assertIn("Framework summary", rendered)

    def test_sarif_omits_passing_controls(self) -> None:
        report = ScanReport(
            lab_name="Security Lab",
            description="Demo report",
            generated_at="2026-04-22T00:00:00+00:00",
            platform="Windows",
            results=[
                ControlResult(
                    control_id="pass",
                    title="Pass",
                    control_type="manual_assertion",
                    severity=Severity.LOW,
                    status=ControlStatus.PASS,
                    message="ok",
                ),
                ControlResult(
                    control_id="fail",
                    title="Fail",
                    control_type="manual_assertion",
                    severity=Severity.HIGH,
                    status=ControlStatus.FAIL,
                    message="no",
                ),
            ],
            summary=ScanSummary(
                total_controls=2,
                applicable_controls=2,
                score=50.0,
                counts={status.value: 0 for status in ControlStatus},
                posture="weak",
                compliant=False,
                blocking_controls=["fail"],
            ),
        )

        sarif = json.loads(render_sarif(report))
        self.assertEqual(len(sarif["runs"][0]["results"]), 1)
        self.assertEqual(sarif["runs"][0]["results"][0]["ruleId"], "fail")

    def test_csv_contains_status_column(self) -> None:
        report = ScanReport(
            lab_name="Security Lab",
            description="Demo report",
            generated_at="2026-04-22T00:00:00+00:00",
            platform="Windows",
            results=[
                ControlResult(
                    control_id="firewall",
                    title="Pare-feu",
                    control_type="windows_firewall_enabled",
                    severity=Severity.CRITICAL,
                    status=ControlStatus.PASS,
                    message="ok",
                )
            ],
            summary=ScanSummary(
                total_controls=1,
                applicable_controls=1,
                score=100.0,
                counts={status.value: 0 for status in ControlStatus},
                posture="strong",
                compliant=True,
                blocking_controls=[],
            ),
        )

        rendered = render_csv(report)
        self.assertIn('"status"', rendered.splitlines()[0])
        self.assertIn('"pass"', rendered)


class CliTests(unittest.TestCase):
    def test_validate_command_returns_zero_for_builtin_profile(self) -> None:
        stdout = io.StringIO()
        with redirect_stdout(stdout):
            exit_code = main(["validate", "--profile", "windows-workstation"])
        self.assertEqual(exit_code, 0)
        self.assertIn("is valid", stdout.getvalue())

    def test_strict_exit_code_fails_on_warn(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "warn.json"
            config_path.write_text(
                json.dumps(
                    {
                        "lab_name": "warn",
                        "manual_evidence": {"disk": "partial"},
                        "controls": [
                            {
                                "id": "manual",
                                "title": "manual",
                                "type": "manual_assertion",
                                "severity": "medium",
                                "evidence_key": "disk",
                                "expected": "encrypted"
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = main(["scan", "--config", str(config_path), "--strict", "--format", "json"])
            self.assertEqual(exit_code, 1)

    def test_configuration_error_returns_two(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            exit_code = main(["validate", "--config", "missing.json"])
        self.assertEqual(exit_code, 2)
        self.assertIn("Configuration error", stderr.getvalue())

    def test_compare_command_returns_zero(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            baseline = Path(temp_dir) / "baseline.json"
            current = Path(temp_dir) / "current.json"
            baseline.write_text(
                json.dumps(
                    {
                        "lab_name": "lab",
                        "generated_at": "2026-04-20T00:00:00+00:00",
                        "results": [{"control_id": "a", "status": "fail", "severity": "high", "title": "A"}],
                        "summary": {"score": 10.0, "blocking_controls": ["a"], "frameworks": {}},
                    }
                ),
                encoding="utf-8",
            )
            current.write_text(
                json.dumps(
                    {
                        "lab_name": "lab",
                        "generated_at": "2026-04-21T00:00:00+00:00",
                        "results": [{"control_id": "a", "status": "pass", "severity": "high", "title": "A"}],
                        "summary": {"score": 90.0, "blocking_controls": [], "frameworks": {}},
                    }
                ),
                encoding="utf-8",
            )
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = main(["compare", "--baseline", str(baseline), "--current", str(current)])
            self.assertEqual(exit_code, 0)
            self.assertIn("Score delta", stdout.getvalue())


class ComparisonTests(unittest.TestCase):
    def test_compare_report_payloads_detects_resolved_blocker(self) -> None:
        comparison = compare_report_payloads(
            baseline={
                "generated_at": "2026-04-20T00:00:00+00:00",
                "results": [{"control_id": "a", "status": "fail", "severity": "high", "title": "A"}],
                "summary": {"score": 10.0, "blocking_controls": ["a"], "frameworks": {}},
            },
            current={
                "generated_at": "2026-04-21T00:00:00+00:00",
                "results": [{"control_id": "a", "status": "pass", "severity": "high", "title": "A"}],
                "summary": {"score": 90.0, "blocking_controls": [], "frameworks": {}},
            },
        )

        self.assertEqual(comparison["score_delta"], 80.0)
        self.assertEqual(comparison["resolved_blocking_controls"], ["a"])


if __name__ == "__main__":
    unittest.main()
