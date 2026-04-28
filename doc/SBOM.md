# wolfSSL SBOM Generation

wolfSSL generates a Software Bill of Materials (SBOM) to support compliance
with the EU Cyber Resilience Act (CRA), which requires software products
placed on the EU market to provide a machine-readable SBOM identifying all
software components.

## Quick Start

```sh
./configure
make
make sbom
```

This requires `python3` and `pyspdxtools` (`pip install spdx-tools`).
Both are detected by `configure`; `make sbom` fails with a clear error
message if either is missing.

## Output Files

`make sbom` produces three files in the build directory:

| File | Format | Standard | Primary use |
|---|---|---|---|
| `wolfssl-<version>.cdx.json` | JSON | CycloneDX 1.6 | Supply-chain tooling, VEX |
| `wolfssl-<version>.spdx.json` | JSON | SPDX 2.3 | Machine processing |
| `wolfssl-<version>.spdx` | Tag-value | SPDX 2.3 | Human review, archival |

The `.spdx` tag-value file is produced by `pyspdxtools` converting the
`.spdx.json`. If the JSON fails SPDX validation, `make sbom` stops with
a non-zero exit and the tag-value file is not written.

## Installing the SBOM

```sh
make install-sbom        # installs to $(datadir)/doc/wolfssl/
make uninstall-sbom      # removes the installed files
```

The generated files are removed by `make clean`.

## SBOM Contents

Both formats contain the same information:

| Field | Value |
|---|---|
| Name | `wolfssl` |
| Version | from `configure.ac` (`PACKAGE_VERSION`) |
| Type | library |
| Supplier | wolfSSL Inc. |
| License | detected from `LICENSING` file (currently `GPL-3.0-only`) |
| Copyright | `Copyright (C) 2006-<year> wolfSSL Inc.` |
| SHA-256 | hash of the installed `libwolfssl.so.X.Y.Z` |
| CPE | `cpe:2.3:a:wolfssl:wolfssl:<version>:*:*:*:*:*:*:*` |
| PURL | `pkg:generic/wolfssl@<version>` |
| Download location | `https://github.com/wolfSSL/wolfssl` |
| Third-party deps | none (wolfssl has no runtime dependencies in a default build) |

### License detection

The license SPDX identifier is parsed from the `LICENSING` file at SBOM
generation time, not hardcoded. If the `LICENSING` file cannot be parsed,
`make sbom` warns and uses `NOASSERTION` rather than silently emitting a
wrong value.

### Dual licensing

wolfSSL is available under `GPL-3.0-only` for open-source use, with a
commercial license for proprietary products. The SBOM reflects the
open-source license. Commercial licensees should update the `licenseConcluded`
field to `LicenseRef-wolfSSL-Commercial` or their applicable SPDX expression
when distributing under a commercial agreement.

## Validating the SBOM Manually

```sh
# Validate SPDX JSON
pyspdxtools --infile wolfssl-<version>.spdx.json

# Convert to another format (e.g. RDF)
pyspdxtools --infile wolfssl-<version>.spdx.json \
            --outfile wolfssl-<version>.spdx.rdf
```

### External dependency version detection

For dependencies with pkg-config support (`liboqs`, `libz`), the version is
queried via `pkg-config --modversion` at generation time.

For dependencies without pkg-config (`libxmss`, `liblms`), wolfSSL is typically
built against a source checkout rather than an installed package.  The generator
falls back to `git describe --tags --always` on the source tree root (passed via
`configure` as `XMSS_ROOT` / `LIBLMS_ROOT`).  If the source tree has no tags,
`git describe` returns the short commit hash, which is recorded as-is.  If the
source tree is unavailable or `git` is not found, version is recorded as
`NOASSERTION`.

## Implementation Notes

SBOM generation is implemented in `scripts/gen-sbom` (Python 3, stdlib only)
and hooked into the autotools build via `Makefile.am` and `configure.ac`.
The script stages a `make install` into a temporary directory, hashes the
installed library, generates both SBOM formats, then removes the staging
directory.  The `pyspdxtools` validation and conversion step runs after
generation and gates the build on SPDX conformance.
