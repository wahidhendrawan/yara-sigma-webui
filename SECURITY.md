# Security Policy

## Reporting a Vulnerability

Please report suspected vulnerabilities privately. **Do not open a public issue, include secrets or personal data in a report, or publicly disclose the problem before a fix is available.**

Use one of these channels, in order of preference:

1. [GitHub private vulnerability reporting](https://github.com/wahidhendrawan/yara-sigma-webui/security/advisories/new)
2. Email `wahidhendrawan@proton.me` with the subject ` yar2sig security report`.

Include, where possible:

- the affected version, commit, or Docker image tag;
- a concise description of the impact and attack prerequisites;
- minimal reproduction steps or a safe proof of concept;
- relevant logs, configuration, and environment details with credentials and sensitive indicators redacted; and
- your preferred contact method for follow-up.

We aim to acknowledge reports within 48 hours and provide a status update within 7 days. Critical issues are prioritized for the next available patch release. Please allow reasonable time for investigation and remediation before any coordinated disclosure.

If a report contains sensitive data, ask for a secure upload method rather than sending that data by ordinary email.

## Supported Versions

Security fixes are applied to the latest released version and the `main` branch. Older releases are unsupported unless a security advisory explicitly states otherwise.

| Version | Supported |
| --- | --- |
| Latest release | Yes |
| `main` | Yes |
| Older releases | No |

## Scope

This policy covers the `yar2sig` Python package, CLI, Flask API, web UI, Docker image, and GitHub Actions workflows in this repository. Reports about third-party dependencies are welcome when they create a demonstrable vulnerability in this project; otherwise, please report them to the upstream maintainer as well.

## Recognition

With your permission, valid reporters may be credited in the release notes or security advisory. Anonymous reports are also welcome.
