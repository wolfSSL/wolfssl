# wolfSSL and the EU Cyber Resilience Act

This guide is for product teams that ship a product containing wolfSSL and
need to satisfy EU Cyber Resilience Act (CRA) obligations related to software
component transparency and build traceability.

## Background

The CRA requires manufacturers of products with digital elements placed on
the EU market to identify and document the software components in those
products.  The practical requirement is a machine-readable Software Bill of
Materials (SBOM) covering all open-source and third-party components,
following the NTIA minimum element guidelines.

wolfSSL provides two complementary artefacts to help you meet this
requirement:

| Artefact | Produced by | What it answers |
|---|---|---|
| SBOM (SPDX 2.3 + CycloneDX 1.6) | `make sbom` | *What* is in wolfSSL (identity, license, CPE, PURL, checksum) |
| OmniBOR artifact graph | `make bomsh` | *How* wolfSSL was built (cryptographic source-to-binary traceability) |

For most CRA use cases the SBOM alone is sufficient.  The OmniBOR graph
provides a deeper audit trail if your compliance posture requires it.

## Quick Start

```sh
./configure
make
make sbom         # produces wolfssl-<version>.spdx.json, .cdx.json, .spdx
make bomsh        # optional: produces omnibor/ + OmniBOR-enriched SPDX
```

See `doc/SBOM.md` for prerequisites and full details on both targets.

## What wolfSSL Provides

After `make sbom`:

```
wolfssl-<version>.spdx.json    SPDX 2.3 JSON (machine processing)
wolfssl-<version>.cdx.json     CycloneDX 1.6 JSON (supply-chain tooling, VEX)
wolfssl-<version>.spdx         SPDX 2.3 tag-value (human review, archival)
```

After `make bomsh` (with `make sbom` already run):

```
omnibor/                            OmniBOR artifact dependency graph
omnibor.wolfssl-<version>.spdx.json SPDX enriched with PERSISTENT-ID gitoid
```

## Integrating wolfSSL into Your Product SBOM

Your product SBOM needs to list wolfSSL as a component.  The two standard
approaches are to reference wolfSSL's SBOM document from yours, or to copy
the wolfSSL package entry directly into your document.

### SPDX: external document reference (recommended)

Reference wolfSSL's SPDX document from your product's SPDX document using
`externalDocumentRefs`.  This keeps the documents separate and lets wolfSSL's
SBOM stand as an independently verifiable artefact.

```json
{
  "externalDocumentRefs": [
    {
      "externalDocumentId": "DocumentRef-wolfssl",
      "spdxDocument": "https://wolfssl.com/sbom/wolfssl-<version>.spdx.json",
      "checksum": {
        "algorithm": "SHA256",
        "checksumValue": "<sha256-of-wolfssl-spdx.json>"
      }
    }
  ]
}
```

Then express the dependency in your `relationships` section:

```json
{
  "spdxElementId": "SPDXRef-Package-YourProduct",
  "relatedSpdxElement": "DocumentRef-wolfssl:SPDXRef-Package-wolfssl",
  "relationshipType": "DYNAMIC_LINK"
}
```

Use `STATIC_LINK` if you link wolfSSL statically, `DYNAMIC_LINK` if you
use the shared library, or `CONTAINS` if you redistribute the source.

Alternatively, copy the wolfSSL package entry from its SPDX document
directly into your own SPDX document and add the `DYNAMIC_LINK` /
`STATIC_LINK` relationship to your product package.

### CycloneDX: component reference

Include wolfSSL as a component in your CycloneDX BOM, referencing the
wolfSSL CycloneDX document via an external reference of type `bom`:

```json
{
  "type": "library",
  "name": "wolfssl",
  "version": "<version>",
  "purl": "pkg:generic/wolfssl@<version>",
  "cpe": "cpe:2.3:a:wolfssl:wolfssl:<version>:*:*:*:*:*:*:*",
  "licenses": [{ "license": { "id": "GPL-3.0-only" } }],
  "externalReferences": [
    {
      "type": "bom",
      "url": "https://wolfssl.com/sbom/wolfssl-<version>.cdx.json",
      "hashes": [
        {
          "alg": "SHA-256",
          "content": "<sha256-of-wolfssl-cdx.json>"
        }
      ]
    }
  ]
}
```

## Commercial License Users

wolfSSL's published SBOM records `licenseConcluded: GPL-3.0-only`, which
reflects the open-source license.  If you are distributing a product under a
wolfSSL commercial license, you have two options:

### Option 1: regenerate the SBOM with your license expression

Pass `SBOM_LICENSE_OVERRIDE` to `make sbom` to bake your SPDX expression
directly into the artefact (preferred — survives re-runs, no manual editing):

```sh
make sbom \
    SBOM_LICENSE_OVERRIDE=LicenseRef-wolfSSL-Commercial \
    SBOM_LICENSE_TEXT=/path/to/wolfssl-commercial-license.txt
```

`SBOM_LICENSE_TEXT` is **required** whenever `SBOM_LICENSE_OVERRIDE` uses a
custom `LicenseRef-*` identifier.  SPDX 2.3 §10.1 requires the actual licence
text to be embedded in `hasExtractedLicensingInfos` for any LicenseRef used in
the document; conformant validators (e.g. `pyspdxtools`, `ntia-conformance-checker`)
will reject the SBOM otherwise.  The file should contain the plain-text
licence agreement you received from wolfSSL.

If you omit `SBOM_LICENSE_TEXT` the generator emits a placeholder and prints
a warning — useful for quick experiments, but the result is **not** valid for
distribution to customers or regulators.

For a stock SPDX-listed identifier (`Apache-2.0`, `MIT`, etc.) the
`SBOM_LICENSE_TEXT` argument is unnecessary because validators already know
the canonical text.

Or invoke the generator directly with `--license-override` /
`--license-text` if you are producing the SBOM outside the standard make
target.

### Option 2: update your product SBOM's reference to wolfSSL

Leave the upstream SBOM file alone and override `licenseConcluded` on the
wolfSSL package entry in *your* product SBOM:

```json
"licenseConcluded": "LicenseRef-wolfSSL-Commercial"
```

Do not modify the wolfSSL-published SBOM file in place; either regenerate it
with the override (Option 1) or override at the consumer level (Option 2).

## Reproducible SBOMs

The generator honors `SOURCE_DATE_EPOCH` for the SBOM creation timestamp and
uses deterministic UUIDs derived from the package name and version, so two
runs of `make sbom` against the same source tree, library binary, and build
options produce byte-identical `.spdx.json` and `.cdx.json` files.  This
matters for downstream attestation pipelines that hash SBOMs as part of a
provenance chain.

`make sbom` will derive `SOURCE_DATE_EPOCH` from `git log -1 --format=%ct` if
you do not set it explicitly and the wolfSSL source tree is a git checkout.

## Build Provenance (OmniBOR)

The CRA also encourages transparency about *how* software is built, not just
*what* it contains.  Running `make bomsh` after `make sbom` produces an
OmniBOR artifact dependency graph and an enriched SPDX document:

```
omnibor.wolfssl-<version>.spdx.json
```

This file is identical to `wolfssl-<version>.spdx.json` except it adds a
`PERSISTENT-ID gitoid` entry to the wolfSSL package's `externalRefs`:

```json
{
  "referenceCategory": "PERSISTENT-ID",
  "referenceType": "gitoid",
  "referenceLocator": "gitoid:blob:sha1:<hash>"
}
```

The `gitoid` is the entry point into the OmniBOR Merkle DAG stored in
`omnibor/`.  A CRA auditor or supply-chain tool can follow that identifier
through the graph to verify that a specific `libwolfssl.so` binary was
produced from a specific, unmodified set of source files.

Use `omnibor.wolfssl-<version>.spdx.json` in place of the plain SPDX file
when you want to include this traceability claim in your product SBOM.

## What to Give Your Auditor

For a CRA conformity assessment, provide:

| File | Purpose |
|---|---|
| `wolfssl-<version>.spdx.json` | Machine-readable component identity (SPDX 2.3) |
| `wolfssl-<version>.cdx.json` | Machine-readable component identity (CycloneDX 1.6) |
| `wolfssl-<version>.spdx` | Human-readable tag-value form |
| `omnibor/` + `omnibor.wolfssl-<version>.spdx.json` | Build traceability (optional, if bomsh was run) |

If you have a product-level SBOM that references wolfSSL via
`ExternalDocumentRef` (SPDX) or a `bom` external reference (CycloneDX),
include that product SBOM alongside the wolfSSL artefacts.

## Further Reading

### wolfSSL documentation

- `doc/SBOM.md` — unified reference covering SBOM generation, OmniBOR/Bomsh
  build provenance, combined workflow, output formats, and implementation notes

### OpenSSF guidance

- [CRA Brief Guide for OSS Developers](https://best.openssf.org/CRA-Brief-Guide-for-OSS-Developers.html)
  — Clarifies when the CRA applies to open source projects and
  maintainers, and what obligations fall on manufacturers integrating
  OSS components into commercial products (i.e., you, if you ship a
  product containing wolfSSL).

- [SBOM in Compliance](https://sbom-catalog.openssf.org/sbom-compliance.html)
  — OpenSSF SBOM Everywhere SIG survey of the global regulatory
  landscape: CRA, NTIA minimum elements, US EO 14028, Germany TR-03183,
  and others.  Useful for understanding how wolfSSL's SBOM artefacts map
  to each framework.

- [Getting Started with SBOMs](https://sbom-catalog.openssf.org/getting-started)
  — OpenSSF SBOM Everywhere SIG guidance on SBOM generation approaches
  (build-integrated vs. separate tooling), phase selection, and
  publication.  wolfSSL's `make sbom` follows the build-integrated
  approach recommended here.

- [OpenSSF CRA Policy Hub](https://openssf.org/category/policy/cra/)
  — Ongoing OpenSSF coverage of CRA developments, implementation
  guidance, and community responses.

- [SBOM Everywhere Wiki](https://sbom-catalog.openssf.org/)
  — OpenSSF SIG home: tooling catalog, working group resources, naming
  conventions, and cross-format guidance for SPDX and CycloneDX.

### Standards

- SPDX 2.3 specification: https://spdx.github.io/spdx-spec/v2.3/
- CycloneDX 1.6 specification: https://cyclonedx.org/specification/overview/
- NTIA minimum elements for an SBOM:
  https://www.ntia.gov/report/2021/minimum-elements-software-bill-materials-sbom
