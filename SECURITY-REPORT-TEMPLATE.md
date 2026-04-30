# wolfSSL Vulnerability Report

**Completion of every required field in this template is mandatory for CVE
consideration.** Reports that omit required fields, or that do not use this
template, will not receive CVE consideration.

Non-template or incomplete submissions may still be reviewed on the merits
and, where appropriate, addressed as hardening fixes in a future release.

Submissions that pass automated verification of the claims you make below
enter our triage queue per the Security Policy.

---

## 1. Reporter Information

**Name or handle:** _required_
**Organization (if any):** _optional_
**Contact email:** _required_
**Preferred credit text** (or "anonymous"): _required_

**Discovery method** _required_: describe how you found this defect — manual
code review, fuzzer (name and version), static analysis tool (name), or other
methodology.

**Prior reports:** has this defect been reported to wolfSSL or any other
party previously? If yes, provide details and any prior CVE or ticket
references.

---

## 2. Affected Components

**Product** _required_: wolfSSL, wolfCrypt, wolfSSH, wolfMQTT, wolfBoot,
wolfTPM, wolfSentry, wolfProvider, wolfHSM, wolfIP, wolfPSA, wolfPKCS11, or
the OpenSSL compatibility layer.

**Versions tested** _required_: list the specific released versions you
verified the defect against (e.g., "5.8.4, 5.9.0, 5.9.1").

**Build configuration** _required_: state whether the defect is reachable in
a default `./configure` build. If not, list every `--enable-*` /
`--disable-*` flag, `WOLFSSL_*` macro, compiler version, target architecture,
and optimization level required for reachability.

---

## 3. Defect Location

**Source file** _required_: full path from repo root (e.g.,
`wolfcrypt/src/asn.c`).

**Function name** _required_.

**Line numbers** _required_: the specific lines containing the defect.

**Defect type and technical description** _required_: identify the class of
defect (heap buffer overflow, use-after-free, NULL dereference, signature
verification bypass, timing side channel, etc.) and describe in two to four
sentences what the code does, what it should do, and what goes wrong.

---

## 4. Reachability from a wolfSSL Integration

**Documented integration that routes attacker-controlled bytes to this code
path** _required_: identify the specific integration. Examples of qualifying
integrations include the TLS or DTLS protocol stack, X.509 peer certificate
validation during TLS authentication, OCSP / CRL fetching during TLS
verification, the OpenSSL compatibility layer consumed by a named integration
(nginx, Apache httpd, curl, OpenVPN, stunnel, MySQL, libssh, etc.), PKCS7 /
CMS verify or decrypt paths consumed by EST or SCEP enrollment, or PKCS#12
parsing in dynamic credential provisioning (WPA supplicant, hostapd,
NetworkManager).

**Byte-flow trace** _required_: starting from where attacker bytes enter
wolfSSL's API surface, list each function call (with file and line number)
through which the bytes travel until they reach the defective code. A trace
of three to ten steps is typical.

Example of an acceptable trace:

> Attacker bytes enter via TLS record at `wolfSSL_read()` →
> `ProcessReply` (ssl.c:18742) → `DoTls13HandshakeMessage` (tls13.c:11203)
> → `DoTls13Certificate` (tls13.c:8847) → `ProcessPeerCerts` (internal.c:14228)
> → `ParseCert` (asn.c:32104) → defective code at asn.c:33871.

---

## 5. Attacker Model

**Attacker position** _required_: describe who the attacker is — remote
unauthenticated network peer, on-path network attacker, authenticated remote
peer, local unprivileged user, local privileged user, attacker with prior
code execution on the device, or other. Be specific.

**Prerequisites** _required_: list every capability the attacker must already
possess before the defect can be triggered, including any access, credentials,
configuration control, or environmental conditions.

**New capability gained** _required_: describe the *delta* between what the
attacker can do before exploitation and what they can do after.

**Realistic deployment context** _required_: identify one or more wolfSSL
customer deployment patterns where the attacker position you describe is
plausible. wolfSSL is deployed in embedded, industrial, automotive, medical,
avionics, and IoT contexts.

---

## 6. Security Impact

**Primary security property impacted** _required_ — pick one and justify
below:

- [ ] **Integrity** — memory corruption enabling control-flow hijack,
  arbitrary write, or state corruption with attacker control
- [ ] **Authenticity** — signature verification bypass, certificate
  validation bypass, MAC forgery, algorithm downgrade, trust-chain bypass
- [ ] **Confidentiality of secret material** — disclosure of private keys,
  session keys, password material, or pre-authentication server plaintext
- [ ] **Availability** — denial of service

**Justification** _required_: in two to four sentences, explain how the
defect produces the impact you've selected, with reference to the byte flow
in Section 4 and the attacker model in Section 5.

---

## 7. Working Proof-of-Concept

**A working proof-of-concept is required.** Reports without one will not
receive CVE consideration.

Provide:

- Source code, packet capture, malformed input file, or other artifact that
  triggers the defect
- Exact build and run instructions, including the wolfSSL version and build
  configuration declared in Section 2
- Expected output demonstrating the defect — crash trace, sanitizer report,
  leaked memory contents, forged signature accepted by the verifier, or
  equivalent concrete observable effect

We compile and run submitted PoCs against the affected version. PoCs that do
not reproduce the claimed behavior, or that demonstrate behavior materially
different from the claim, will not receive CVE consideration.

The following are not proofs-of-concept and will not satisfy this requirement:

- Prose claims that the defect "may lead to memory corruption," "could
  potentially crash the process," "is theoretically exploitable," or similar
- A description of an analytical exploitation chain without a runnable
  artifact that produces the claimed effect
- A PoC that demonstrates a different effect than the impact claimed in
  Section 6 (for example, a PoC that produces a NULL dereference accompanied
  by a claim of remote code execution)
- Source code that does not compile, or instructions that do not run as
  written

---

## 8. Related Work Check

**Have you verified this defect is not already being addressed?** _required_:
describe your review of open pull requests and recent commits in the
relevant wolfSSL repository that touch the same file or function. Include
the search terms you used and any specific PRs or commits you examined
(with URLs). AI-assisted tooling makes this search efficient and is a
reasonable way to perform it.

**If related work is ongoing or merged** _required_: explain how your
report is novel relative to that work — e.g., your defect is in a
different code path, a different return value, a different call site,
or a different attacker reachability.

Reports of issues already being addressed in open work are treated as
duplicates and do not receive CVE consideration.

---

## 9. Caller API Usage

**Does triggering the defect require the caller to use wolfSSL APIs outside
their documented behavior?** _required_: answer yes or no, then describe the
specific API calls, options, and sequences used.

---

## 10. Severity Self-Assessment

**Reporter-proposed severity** _required_: Critical, High, Medium, or Low.

**CVSS 3.1 vector string** _optional_: e.g., `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`.

**Justification** _required_: in two to three sentences, map the severity to
the realistic attacker model and impact described above.

wolfSSL performs its own severity assessment per the published rubric. Your
assessment is input, not the final classification.

---

## 11. Disclosure Coordination

**Requested embargo period** _required_: state your preferred embargo
duration. Longer embargoes for ecosystem coordination may be requested.

**Downstream coordination** _required_: identify any downstream integrators,
certification bodies, or other parties whose involvement affects disclosure
timing.

**Public disclosure plans** _required_: describe any planned blog post,
conference talk, paper, or other public disclosure, with tentative timing,
so we can coordinate the advisory release.

---

## 12. Suggested Fix _(optional)_

If you have a proposed patch, attach it. Patches are not required, but they
accelerate the fix timeline.

---

## What Happens Next

1. **Acknowledgment.** We acknowledge receipt as reports arrive.
2. **Automated verification.** Our triage tooling cross-checks the claims
   in your report against the source code: function names, line numbers,
   call paths, version ranges, integration routes, and PoC reproduction.
3. **Initial triage verdict.** Once verification is complete, we provide
   an initial verdict: CVE-eligible, hardening fix, or more information
   needed. Complex or contested reports take longer than straightforward
   ones.
4. **Coordination.** For CVE-eligible reports, we develop a fix privately
   and coordinate disclosure timing with you.
5. **Disclosure.** The fix release and CVE advisory publish together.

For questions about this template or the process, contact
**support@wolfssl.com**.

*Last updated: 2026-04-22*
