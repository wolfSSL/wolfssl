# gen-advisory test fixtures

CVE Program records (CVE JSON 5.x) used by `scripts/test_gen_advisory.py` and
the `.github/workflows/advisory.yml` jobs.  Committed so the tests are hermetic
(no network fetch from cve.org at test time).

| File | Provenance |
|------|------------|
| `CVE-2026-5501.json` | Real published wolfSSL CNA record (CVSS v4 only). |
| `CVE-2026-5778.json` | Real published wolfSSL CNA record (CVSS v4 only). |
| `CVE-2026-5999.json` | **Synthetic fixture, not a real CVE.** Carries a CVSS v3.1 block so the CSAF `scores[]` emission path (and the CVSS-consistency mandatory tests 6.1.8/6.1.9) is exercised; the v4-only records above never populate `scores[]` in CSAF 2.0. |
