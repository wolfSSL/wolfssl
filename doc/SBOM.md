# wolfSSL SBOM and Build Provenance

wolfSSL provides two complementary artefacts for software supply chain
transparency:

| Artefact | Target | Answers |
|---|---|---|
| SBOM (SPDX 2.3 + CycloneDX 1.6) | `make sbom` | *What* wolfSSL is: component identity, license, checksums, CPE, PURL |
| OmniBOR artifact graph | `make bomsh` | *How* wolfSSL was built: cryptographic source-to-binary traceability |

Together they provide full coverage for the EU Cyber Resilience Act (CRA)
and similar supply chain transparency requirements.  Each target is
independently useful; running both produces an enriched SPDX document that
bridges the two artefacts with a single `PERSISTENT-ID gitoid` reference.

## Quick Start

### Component identity only

```sh
./configure
make
make sbom
```

Requires `python3` and `pyspdxtools` (`pip install spdx-tools`).

### Full coverage: component identity + build provenance

```sh
./configure
make
make sbom
make bomsh
```

Additionally requires `bomtrace3` and `bomsh_create_bom.py` in `PATH`.
See [Prerequisites for make bomsh](#prerequisites-for-make-bomsh) below.

All tools are detected by `configure`; either target fails with a clear
error message if a required tool is missing.

---

## make sbom

### Output files

`make sbom` produces three files in the build directory:

| File | Format | Standard | Primary use |
|---|---|---|---|
| `wolfssl-<version>.cdx.json` | JSON | CycloneDX 1.6 | Supply-chain tooling, VEX |
| `wolfssl-<version>.spdx.json` | JSON | SPDX 2.3 | Machine processing |
| `wolfssl-<version>.spdx` | Tag-value | SPDX 2.3 | Human review, archival |

The `.spdx` tag-value file is produced by `pyspdxtools` converting the
`.spdx.json`.  If the JSON fails SPDX validation, `make sbom` stops with
a non-zero exit and the tag-value file is not written.

### SBOM contents

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

#### License detection

The license SPDX identifier is parsed from the `LICENSING` file at SBOM
generation time, not hardcoded.  If the `LICENSING` file cannot be parsed,
`make sbom` warns and uses `NOASSERTION` rather than silently emitting a
wrong value.

#### Dual licensing

wolfSSL is available under `GPL-3.0-only` for open-source use, with a
commercial license for proprietary products.  The SBOM reflects the
open-source license.  Commercial licensees should update the
`licenseConcluded` field to `LicenseRef-wolfSSL-Commercial` or their
applicable SPDX expression when distributing under a commercial agreement.

#### External dependency version detection

For dependencies with pkg-config support (`liboqs`, `libz`), the version is
queried via `pkg-config --modversion` at generation time.

For dependencies without pkg-config (`libxmss`, `liblms`), wolfSSL is
typically built against a source checkout rather than an installed package.
The generator falls back to `git describe --tags --always` on the source
tree root (passed via `configure` as `XMSS_ROOT` / `LIBLMS_ROOT`).  If the
source tree has no tags, `git describe` returns the short commit hash, which
is recorded as-is.  If the source tree is unavailable or `git` is not found,
version is recorded as `NOASSERTION`.

### Validating the SBOM manually

```sh
# Validate SPDX JSON
pyspdxtools --infile wolfssl-<version>.spdx.json

# Convert to another format (e.g. RDF)
pyspdxtools --infile wolfssl-<version>.spdx.json \
            --outfile wolfssl-<version>.spdx.rdf
```

### Installing the SBOM

```sh
make install-sbom        # installs to $(datadir)/doc/wolfssl/
make uninstall-sbom      # removes the installed files
```

The generated files are removed by `make clean`.

### Implementation notes

SBOM generation is implemented in `scripts/gen-sbom` (Python 3, stdlib only)
and hooked into the autotools build via `Makefile.am` and `configure.ac`.
The script stages a `make install` into a temporary directory, hashes the
installed library, generates both SBOM formats, then removes the staging
directory.  The `pyspdxtools` validation and conversion step runs after
generation and gates the build on SPDX conformance.

---

## make bomsh

`make bomsh` uses the [Bomsh](https://github.com/omnibor/bomsh) project to
trace the wolfSSL build under `bomtrace3` (a patched `strace`) and produce
an OmniBOR artifact dependency graph: a content-addressed Merkle DAG mapping
every built binary back to the exact set of source files that produced it.

### Prerequisites for make bomsh

| Tool | Required | Where to get it |
|---|---|---|
| `bomtrace3` | yes | Build from source: [omnibor/bomsh](https://github.com/omnibor/bomsh) |
| `bomsh_create_bom.py` | yes | `scripts/` directory of the bomsh repo, placed in `PATH` |
| `bomsh_sbom.py` | no | Same; needed only for SPDX enrichment step |

`bomtrace3` is a patched `strace` — it is a userspace binary and requires no
kernel modifications.  It uses the standard `ptrace()` syscall available on
any stock Linux kernel.  The only environments where it may be unavailable
are containers running with a hardened seccomp profile or systems with
`kernel.yama.ptrace_scope=3`.

#### Building bomtrace3

```sh
git clone https://github.com/omnibor/bomsh
git clone https://github.com/strace/strace strace3
cd strace3
patch -p1 < ../bomsh/.devcontainer/patches/bomtrace3.patch
cp ../bomsh/.devcontainer/src/*.[hc] src/
./bootstrap && ./configure && make
cp src/strace ~/.local/bin/bomtrace3
```

Place `bomsh_create_bom.py` (and optionally `bomsh_sbom.py`) from the bomsh
`scripts/` directory somewhere in `PATH`.

### What make bomsh does

1. Writes a build-local `_bomsh.conf` redirecting the raw logfile out of
   `/tmp/` to the build directory (avoids collisions between concurrent
   builds).
2. Runs `make clean` to ensure a full rebuild.  This is necessary because
   `bomtrace3` intercepts syscalls live during compilation and cannot
   post-process an already-built tree.
3. Runs `bomtrace3 -c _bomsh.conf make` — rebuilds wolfSSL under strace
   tracing, recording every compiler invocation with its inputs and outputs.
4. Runs `bomsh_create_bom.py` to process the raw logfile and produce the
   OmniBOR artifact graph in `omnibor/`.
5. If `bomsh_sbom.py` is available **and** `wolfssl-<version>.spdx.json`
   exists (from `make sbom`), annotates that SPDX document with OmniBOR
   `ExternalRef` identifiers, producing `omnibor.wolfssl-<version>.spdx.json`.

### Output files

| Path | Description |
|---|---|
| `omnibor/objects/` | OmniBOR artifact objects (SHA-1 content-addressed dependency graph) |
| `omnibor/metadata/bomsh/` | Bomsh build metadata |
| `omnibor.wolfssl-<ver>.spdx.json` | SPDX 2.3 JSON enriched with OmniBOR `ExternalRef` (produced only when both `bomsh_sbom.py` and `wolfssl-<ver>.spdx.json` are present) |

The `PERSISTENT-ID gitoid` entry added to the enriched SPDX looks like:

```json
{
  "referenceCategory": "PERSISTENT-ID",
  "referenceType": "gitoid",
  "referenceLocator": "gitoid:blob:sha1:<hash>"
}
```

This sits alongside the existing CPE and PURL `externalRefs` on the wolfSSL
package entry and is the key into the OmniBOR Merkle DAG in `omnibor/`.

### Installing

```sh
make install-bomsh    # installs omnibor/ and enriched SPDX to $(datadir)/doc/wolfssl/
make uninstall-bomsh  # removes installed files
```

The generated files are removed by `make clean`.

### Implementation notes

`make bomsh` runs a full clean rebuild under `bomtrace3` on every invocation.
The ~20% runtime overhead of `bomtrace3` means the rebuild takes roughly
1.2× the normal build time.

The raw logfile (`bomsh_raw_logfile.sha1`) and conf file (`_bomsh.conf`)
are written to the build directory and removed by `make clean`.  The
`omnibor/` tree is also removed by `make clean`.

---

## Combined workflow

Running both targets produces the complete set of supply chain transparency
artefacts.  `make bomsh` automatically enriches the SPDX document from
`make sbom` if it is present; there is no need to pass any extra flags.

```sh
./configure
make
make sbom    # component identity
make bomsh   # build provenance + enriched SPDX
```

All output files:

| File | From | Description |
|---|---|---|
| `wolfssl-<ver>.cdx.json` | `make sbom` | CycloneDX 1.6 component SBOM |
| `wolfssl-<ver>.spdx.json` | `make sbom` | SPDX 2.3 JSON component SBOM |
| `wolfssl-<ver>.spdx` | `make sbom` | SPDX 2.3 tag-value, validated |
| `omnibor/` | `make bomsh` | OmniBOR artifact dependency graph |
| `omnibor.wolfssl-<ver>.spdx.json` | `make bomsh` | SPDX 2.3 JSON enriched with OmniBOR gitoid |

The enriched SPDX is the document to hand to a CRA auditor or downstream
consumer when you want both component identity and build traceability in one
file.

---

## Using wolfSSL's artefacts in a product

If you are shipping a product that includes wolfSSL and need to satisfy CRA
obligations, see `doc/CRA.md` for guidance on integrating these artefacts
into your product SBOM and what to provide to a conformity assessor.
