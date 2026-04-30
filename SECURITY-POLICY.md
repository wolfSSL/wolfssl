# wolfSSL Security Policy

## About This Policy

This document defines how wolfSSL Inc. handles security vulnerabilities in its products: how to report them, how we evaluate them, and how we coordinate disclosure.

## Reporting a Vulnerability

**Use of the wolfSSL Vulnerability Report Template is mandatory.** All security reports must be submitted using [`SECURITY-REPORT-TEMPLATE.md`](SECURITY-REPORT-TEMPLATE.md), with every required field completed. Reports that do not use the template, or that leave required fields incomplete, will not receive CVE consideration.

Submit the completed template to **support@wolfssl.com**.

Non-template submissions may still be reviewed on the merits and, where appropriate, addressed as hardening fixes in a future release. CVE assignment requires a complete template.

We aim to acknowledge reports as they come in and engage with reporters throughout triage. Investigations proceed at the pace the material requires.

## What wolfSSL Treats as a Vulnerability

wolfSSL files a CVE advisory for defects with meaningful security impact on realistic wolfSSL deployments, where exploitability is demonstrated or clearly analyzable. wolfSSL determines whether a finding meets this bar.

We classify confirmed vulnerabilities across four severity tiers:

- **Critical** — Remote, practically exploitable defects in default configurations
- **High** — Serious defects with realistic exploitability
- **Medium** — Defects with meaningful impact under favorable conditions
- **Low** — Defects requiring specialized configurations or narrow deployment scenarios

Reporter-proposed severity is input to the process, not its conclusion.

## What Is Not Considered a Vulnerability

Some defects are typically addressed as bug fixes rather than CVE-eligible vulnerabilities. These include:

- Issues requiring physical access, physical-level side channels, or fault injection
- Issues the attacker can reach only with capabilities that already grant the outcome
- Issues reachable only through unsupported or undocumented API use
- Issues without a working reproducer
- Availability impact outside narrow protocol-facing cases

wolfSSL determines whether a finding meets the CVE threshold. Findings below the threshold are addressed through normal release channels where appropriate; dispositions may be revisited when new information warrants.

## Out of Scope

- Third-party libraries bundled by customers
- Non-library code (example programs, test harnesses, developer tools)
- Documentation errors
- Performance issues without security implications

## Supported Versions

Security fixes are released for the current stable release and the immediately prior stable release. Older releases receive security fixes only under active commercial support agreements.

## Coordinated Disclosure

We investigate and fix confirmed vulnerabilities privately, coordinate disclosure timing with the reporter, and release the fix and security advisory together. Embargo extensions for ecosystem coordination — downstream integrators, certification bodies, or equivalent — are considered case-by-case. CVE records are published consistent with CVE Program rules.

## Credit

Reporters are credited in the advisory and release notes unless anonymity is requested. Reports are welcome from independent security researchers, academic researchers, and organizations conducting authorized security testing.

Credit text is coordinated with the reporter before publication.

## Contact

- **support@wolfssl.com** — security vulnerability reports and general support
- **info@wolfssl.com** — general inquiries

Published CVE advisories: https://www.wolfssl.com/docs/security-vulnerabilities/

## Policy Changes

Material changes to this policy are announced via the wolfSSL blog. The canonical version of this policy is maintained in the wolfSSL GitHub repository.

*Last updated: 2026-04-22*
