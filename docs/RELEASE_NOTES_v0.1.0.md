# Release Notes v0.1.0

## Highlights

`controlguard` v0.1.0 establishes the first complete public baseline of the project.

This version includes:

- strict audit scoring
- Windows, Linux, web, and IAM profiles
- Microsoft Graph admin MFA validation
- Okta admin MFA validation
- multi-format reporting
- framework rollups
- scan comparison
- sample reports committed to the repository

## Core capabilities

### Scan engine

- weighted severity scoring
- blocking required controls
- applicability-aware execution
- strict `evidence_missing` handling

### Control families

- Windows hardening
- Linux hardening
- web security headers
- network exposure
- Microsoft Entra MFA
- Okta MFA

### Outputs

- Markdown
- JSON
- HTML
- CSV
- SARIF

### Documentation and presentation

- Mermaid diagrams in README
- visual HTML reports
- comparison HTML
- deterministic sample outputs in `docs/samples`

## Validation status

Validated in the repository:

- automated unit test suite
- built-in profile validation
- local generation of HTML/JSON/SARIF examples

Still pending in live environments:

- real Microsoft Graph tenant validation
- real Okta tenant validation

## Recommended next milestones

- `v0.1.1` harden live IAM validation and add release automation
- `v0.2.0` add cloud posture connectors
- `v0.3.0` add historical scans and dashboarding
