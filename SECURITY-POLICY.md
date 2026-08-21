# wolfSSL Security Policy

## About This Policy

This document defines how wolfSSL Inc. handles security vulnerabilities in its products: how to report them, how we evaluate them, and how we coordinate disclosure.

## Products Covered

This policy covers security vulnerabilities in wolfSSL products distributed under commercial license or open source, including but not limited to:

- wolfSSL / wolfCrypt
- wolfBoot
- wolfSSH
- wolfMQTT
- wolfTPM
- wolfGuard
- wolfCOSE

## Reporting a Vulnerability

**Use of the wolfSSL Vulnerability Report Template is mandatory.** All security reports must be submitted using [`SECURITY-REPORT-TEMPLATE.md`](SECURITY-REPORT-TEMPLATE.md), with every required field completed. Reports that do not use the template, or that leave required fields incomplete, will not receive CVE consideration.

Submit the completed template to **secure@wolfssl.com**, optionally encrypted to the [wolfSSL security PGP key](https://www.wolfssl.com/.well-known/pgp-key.asc). This address reaches the security team directly and is the correct channel for anything under embargo.

Non-template submissions may still be reviewed on the merits and, where appropriate, addressed as hardening fixes in a future release. CVE assignment requires a complete template.

We aim to acknowledge reports as they come in and engage with reporters throughout triage. Investigations proceed at the pace the material requires.

### Evidence we require

We require a working proof of concept or concrete reproduction steps that demonstrate real impact. Reports that describe only theoretical weaknesses, scanner output without validation, or bulk-generated findings without evidence of manual analysis will be closed without review. If you used automated tooling, state what you used and show the work you did to confirm the finding is real.

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

### Threat-model boundaries

wolfSSL products assume the integrity of the local execution environment. Reports that require the attacker to already have arbitrary memory write access on the host, or that rely on a compromised operating system kernel, are outside our threat model and will not receive a CVE.

A certificate authority or HSM that returns incorrect, misleading, or malformed results is a compromised trust anchor. wolfSSL's security guarantees depend on the correctness of the trust anchors the deployer has configured. A wrong trust decision caused by a lying CA or a misbehaving HSM is not a vulnerability in wolfSSL; it is the expected consequence of a broken trust anchor. We may choose to add hardening against such scenarios, but they do not warrant a CVE.

However, wolfSSL must handle malformed data from any external source, including CAs, HSMs, and peer TLS endpoints, without memory corruption or privilege escalation. If a crafted or garbage response from an external component triggers a buffer overflow, use-after-free, out-of-bounds read, or other memory-safety defect in wolfSSL code, that is a valid finding regardless of whether the source is trusted.

## Out of Scope

- Third-party libraries bundled by customers
- Non-library code (example programs, test harnesses, developer tools)
- Documentation errors
- Performance issues without security implications

## Supported Versions

Security fixes are released for the current stable release and the immediately prior stable release. Older releases receive security fixes only under active commercial support agreements.

## Coordinated Disclosure

We do not pursue legal action against good-faith security researchers. We ask reporters to allow us reasonable time to develop and distribute a fix before public disclosure.

We investigate and fix confirmed vulnerabilities privately, coordinate disclosure timing with the reporter, and release the fix and security advisory together. Embargo extensions for ecosystem coordination — downstream integrators, certification bodies, or equivalent — are considered case-by-case. CVE records are published consistent with CVE Program rules.

## Credit

Reporters are credited in the advisory and release notes unless anonymity is requested. Reports are welcome from independent security researchers, academic researchers, and organizations conducting authorized security testing.

Credit text is coordinated with the reporter before publication.

## Obligations Under the EU Cyber Resilience Act

wolfSSL Inc. is a manufacturer under the EU Cyber Resilience Act, Regulation (EU) 2024/2847.

Where a vulnerability in one of our products is actively exploited, Article 14 requires notification simultaneously to the CSIRT designated as coordinator and to ENISA, filed through the single reporting platform that ENISA operates under Article 16. The deadlines are an early warning within 24 hours of becoming aware, a fuller notification within 72 hours, and a final report within 14 days of a corrective or mitigating measure becoming available.

Article 14 applies from 11 September 2026. Under Article 69(3) it reaches products placed on the market before the Regulation's general application date of 11 December 2027.

Once a corrective or mitigating measure is available, ENISA adds the notified vulnerability to the European Vulnerability Database, in agreement with the manufacturer, under Article 17(5).

We provide security updates for the support period of each product (Article 13(8)) and document known vulnerabilities in our published advisories.

## Contact

- **secure@wolfssl.com** — security vulnerability reports
- **support@wolfssl.com** — general support; do not send embargoed reports here
- **facts@wolfssl.com** — general inquiries

Reports may be encrypted to the wolfSSL security key:

    Fingerprint: A2A4 8E7B CB96 C5BE CB98 7314 EBC8 0E41 5CA2 9677
    Key server:  keys.openpgp.org
    Armoured:    https://www.wolfssl.com/.well-known/pgp-key.asc

Published CVE advisories: https://www.wolfssl.com/docs/security-vulnerabilities/

## Policy Changes

Material changes to this policy are announced via the wolfSSL blog.

This file is the canonical policy. Reporting addresses also appear in
<https://www.wolfssl.com/.well-known/security.txt>; keep them in step.

*Last updated: 2026-08-21*
