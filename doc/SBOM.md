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

## Build System Integration

`gen-sbom` supports three build paths.  All produce the same two output files
(CycloneDX 1.6 JSON and SPDX 2.3 JSON).

### autotools / cmake

The standard path.  The build system generates `wolfssl/options.h` at
configure time and a compiled library artifact at link time.  Both are hashed
to produce a deterministic artifact identity.

```sh
# autotools
./configure && make
make sbom

# cmake (out-of-source build)
cmake -B build && cmake --build build
cmake --build build --target sbom
```

### Embedded / custom build systems (IAR, Keil, MPLAB, custom Makefile)

wolfSSL embedded builds configure the library through `user_settings.h`
rather than through autotools or cmake.  There is no generated `options.h`
and no standalone compiled library — the wolfSSL source files are compiled
directly into the application firmware image.

`gen-sbom` handles this with two new argument groups:

**Configuration source** — exactly one of:

| Flag | Description |
|------|-------------|
| `--options-h PATH` | Path to generated `wolfssl/options.h` (autotools/cmake only) |
| `--user-settings PATH` | Path to `user_settings.h`; preprocessed with `pcpp` (preferred) or `CC -dM -E` |
| `--user-settings-include DIR` | Add include directory for preprocessing (repeat as needed) |
| `--user-settings-define MACRO` | Pre-define a macro before preprocessing (repeat as needed) |

**Artifact hash source** — at least one of:

| Flag | Description |
|------|-------------|
| `--lib PATH` | Compiled library (`libwolfssl.so.X.Y.Z`); SHA-256 is recorded |
| `--srcs FILE [FILE …]` | Compiled source files; deterministic combined SHA-256 is recorded |
| `--srcs-file PATH` | File listing sources, one per line; blank and `#` lines ignored |
| `--no-artifact-hash` | No hash available; placeholder recorded with a wolfSSL contact note |

#### Example: embedded build, source file list on the command line

```sh
python3 scripts/gen-sbom \
    --name wolfssl --version 5.9.1 \
    --license-file LICENSING \
    --user-settings /path/to/user_settings.h \
    --user-settings-include /path/to/wolfssl \
    --user-settings-define WOLFSSL_USER_SETTINGS \
    --srcs wolfcrypt/src/aes.c wolfcrypt/src/sha256.c src/tls.c \
    --cdx-out wolfssl-5.9.1.cdx.json \
    --spdx-out wolfssl-5.9.1.spdx.json
```

#### Example: embedded build, source list from a file

Useful when the source list is too long for the command line, or when the
IDE/build system can generate the list automatically (e.g. from a link map):

```sh
python3 scripts/gen-sbom \
    --name wolfssl --version 5.9.1 \
    --license-file LICENSING \
    --user-settings /path/to/user_settings.h \
    --user-settings-include /path/to/wolfssl \
    --user-settings-define WOLFSSL_USER_SETTINGS \
    --srcs-file /path/to/wolfssl-sources.txt \
    --cdx-out wolfssl-5.9.1.cdx.json \
    --spdx-out wolfssl-5.9.1.spdx.json
```

`wolfssl-sources.txt` format — one path per line, comments allowed:

```
# wolfssl core
/path/to/wolfssl/wolfcrypt/src/aes.c
/path/to/wolfssl/wolfcrypt/src/sha256.c
/path/to/wolfssl/src/tls.c
```

#### Source file combined hash

When `--srcs` or `--srcs-file` is used, `gen-sbom` computes a combined
SHA-256 as follows:

1. Hash each file individually with SHA-256.
2. Sort the `(path, digest)` pairs by path.
3. Hash the sorted manifest `<path>:<digest>\n` lines with SHA-256.

The result is deterministic regardless of the order paths were listed.
Consumers can re-verify by reprocessing the same source tree.

The SBOM records `wolfssl:sbom:hash-source=srcs` so downstream tooling
can identify which hash method was used.

#### No hashable artifact available

For binary-only distributions, ROM builds, or HSM firmware where neither a
compiled library nor source files are accessible:

```sh
python3 scripts/gen-sbom \
    --name wolfssl --version 5.9.1 \
    --license-file LICENSING \
    --user-settings /path/to/user_settings.h \
    --user-settings-include /path/to/wolfssl \
    --user-settings-define WOLFSSL_USER_SETTINGS \
    --no-artifact-hash \
    --cdx-out wolfssl-5.9.1.cdx.json \
    --spdx-out wolfssl-5.9.1.spdx.json
```

A placeholder (64 zero digits) is recorded in the hash fields, and a note
directing integrators to contact wolfSSL is embedded in the SBOM properties.
The `wolfssl:sbom:hash-source=none` property signals to downstream tooling
that no real artifact hash was available.

Contact wolfssl@wolfssl.com to discuss integrity verification options for
your specific build system before using `--no-artifact-hash` in production.

#### Preprocessor detection for `--user-settings`

`gen-sbom` tries preprocessors in order:

1. **pcpp** (`pip install pcpp`): pure Python, host-independent.  Preferred
   for cross-compilation scenarios where the host compiler would expand host
   macros rather than target macros.
2. **`CC -dM -E`**: the C compiler from the `CC` environment variable
   (default: `cc`).  Set `CC=arm-none-eabi-gcc` (or your target compiler)
   for cross builds.

If both fail, `gen-sbom` exits with a message that names both fallback
commands and the install path for pcpp.

## Implementation Notes

SBOM generation is implemented in `scripts/gen-sbom` (Python 3, stdlib only)
and hooked into the autotools build via `Makefile.am` and `configure.ac`.
The script stages a `make install` into a temporary directory, hashes the
installed library, generates both SBOM formats, then removes the staging
directory.  The `pyspdxtools` validation and conversion step runs after
generation and gates the build on SPDX conformance.
