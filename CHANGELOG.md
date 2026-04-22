# Changelog

All notable changes to `controlguard` will be documented in this file.

The format follows a simple chronological release log.

## [0.1.0] - 2026-04-22

### Added

- strict audit scoring with `pass`, `warn`, `fail`, `error`, `not_applicable`, and `evidence_missing`
- built-in profiles for Windows, Linux, web, Microsoft Entra, and Okta
- Microsoft Graph admin MFA connector
- Okta admin MFA connector
- Windows, Linux, network, web, and IAM control families
- Markdown, JSON, HTML, CSV, and SARIF reporting
- scan comparison command for baseline vs current reports
- framework rollups for `CIS`, `NIST CSF`, `ISO 27001`, and `OWASP`
- GitHub Actions CI and test suite

### Notes

- live tenant validation for Microsoft Graph and Okta is still pending and depends on real credentials plus target environments
