# wolfSSL SBOM and Build Provenance

wolfSSL provides two complementary artefacts for software supply chain
transparency:

| Artefact | Target | Answers |
|---|---|---|
| SBOM (SPDX 2.3 + CycloneDX 1.6) | `scripts/gen-sbom` / `make sbom` | *What* wolfSSL is: component identity, license, checksums, CPE, PURL |
| OmniBOR artifact graph | `make bomsh` | *How* wolfSSL was built: cryptographic source-to-binary traceability |

Together they provide full coverage for the EU Cyber Resilience Act (CRA)
and similar supply chain transparency requirements.  Each target is
independently useful; running both produces an enriched SPDX document that
bridges the two artefacts with a single `PERSISTENT-ID gitoid` reference.

The SBOM generator has two entry points so both customer segments are
covered:

| Entry point | Who it is for | Build system |
|---|---|---|
| `python3 scripts/gen-sbom …` (standalone) | Embedded / RTOS customers building with their own Makefile, Keil, IAR, STM32CubeIDE, ESP-IDF, Zephyr, plain CMake, etc. | Any |
| `make sbom` (autotools wrapper) | Linux server / Debian / RPM / Yocto / FIPS-Ready customers running `./configure && make` | Autotools |

Both call the same Python core and produce SBOMs that pass the same SPDX
2.3 / CycloneDX 1.6 / NTIA validators.  Pick whichever matches your build
flow.

---

## 1. Standalone Python tool (recommended for embedded / IDE builds)

`scripts/gen-sbom` is pure Python 3 stdlib (plus an optional `pcpp` dep,
see below).  Customers who configure wolfSSL via a hand-edited
`user_settings.h` and link wolfSSL source files directly into firmware
invoke it directly, without running `./configure` or producing a
standalone `libwolfssl.a`.

### 1.1 Quick start

```sh
python3 scripts/gen-sbom \
    --name wolfssl --version 5.9.1 \
    --license-file LICENSING \
    --user-settings wolfssl/wolfcrypt/settings.h \
    --user-settings-include . \
    --user-settings-include path/to/your/user_settings_dir \
    --user-settings-define WOLFSSL_USER_SETTINGS \
    --srcs wolfcrypt/src/aes.c wolfcrypt/src/sha.c \
           wolfcrypt/src/sha256.c wolfcrypt/src/dh.c \
           wolfcrypt/src/random.c \
    --cdx-out wolfssl-5.9.1.cdx.json \
    --spdx-out wolfssl-5.9.1.spdx.json
```

That command produces the same two SBOM JSON files (CycloneDX 1.6 and SPDX
2.3) that `make sbom` produces, with no autotools involvement.

### 1.2 What you provide

| Flag | What | Where it comes from |
|---|---|---|
| `--name wolfssl` | Component name | Hard-coded; always `wolfssl` |
| `--version 5.9.1` | Component version | Whatever wolfSSL release you pulled |
| `--license-file LICENSING` | wolfSSL's `LICENSING` file | Already in your wolfSSL source tree |
| `--user-settings wolfssl/wolfcrypt/settings.h` | wolfSSL's master settings header | Already in your wolfSSL source tree |
| `--user-settings-include DIR` (repeatable) | Include path containing your `user_settings.h` and the wolfSSL tree | Same as the `-I` flags in your build |
| `--user-settings-define NAME[=VALUE]` (repeatable) | Macros to predefine for preprocessing | Same as the `-D` flags in your build (at minimum: `-D WOLFSSL_USER_SETTINGS`) |
| `--srcs PATH …` | wolfSSL source files compiled into your firmware | The same source list you pass to your compiler |
| `--cdx-out / --spdx-out` | Output paths for the SBOM JSON files | Anywhere you want |

Optional flags:

| Flag | When to use it |
|---|---|
| `--supplier "Acme Inc."` | Override the default `wolfSSL Inc.` (rare) |
| `--dep-libz yes` | If your build links `libz` |
| `--dep-liboqs yes` | If your build links `liboqs` |
| `--dep-version libz=1.3.1` | Explicit dep version when `pkg-config` is unavailable (typical cross-compile) |
| `--license-override LicenseRef-wolfSSL-Commercial` | If you are a commercial licensee, not GPL |
| `--license-text /path/to/commercial-license.txt` | Required when `--license-override` is a `LicenseRef-*` |

### 1.3 Dependencies

- **Python 3**.  Required.  Stdlib only when using `--options-h`.
- **`pcpp`** (`pip install pcpp`).  Required only when using
  `--user-settings`.  pcpp is a pure-Python C preprocessor that walks
  `settings.h` and your `user_settings.h` the same way the C compiler
  does, so the SBOM build properties reflect the actual compiled
  configuration rather than just the literal text of `user_settings.h`.
  If pcpp is not available you can pre-process externally with the
  compiler and pass the result via `--options-h` (see § 1.5).
- **`pyspdxtools`** (`pip install spdx-tools`).  Optional.  Needed only
  if you want to validate the produced SPDX or convert it to tag-value
  form.

### 1.4 What the SBOM checksum represents

In a `make sbom` build the `hashes` / `checksums` field in the SBOM is
the SHA-256 of `libwolfssl.so` / `libwolfssl.a` / `libwolfssl.dylib`.

In an embedded build there is typically no separate library archive —
wolfSSL `.c` files are compiled directly into your firmware.  Asking the
customer to synthesize a `.a` purely for SBOM purposes would be artificial
and would make the build harder.  Instead, the standalone path computes
an OmniBOR-compatible Merkle hash over the wolfSSL source files you list
in `--srcs`:

1. For each source file, compute its OmniBOR `gitoid` (SHA-256 over
   `"blob <size>\0" + filecontents`, byte-identical to
   `git hash-object --object-format=sha256`).
2. Sort by basename.
3. Hash the concatenated `(basename, gitoid)` pairs.

The resulting hash:

- represents *"the wolfSSL source code that is in this firmware"*, which
  is what an auditor actually wants to see;
- is independent of the order you pass `--srcs`, the absolute paths on
  the build host, or the build host's filesystem;
- changes if any compiled-in source byte changes (catches tampering and
  back-ported patches);
- interoperates with bomsh / OmniBOR tooling, which key off the same
  gitoid format.

Each standalone SBOM is annotated with two extra properties so the
checksum's semantics are unambiguous to downstream consumers:

```json
{ "name": "wolfssl:sbom:hash-kind",  "value": "source-merkle-omnibor" },
{ "name": "wolfssl:sbom:source-set", "value": "aes.c,dh.c,sha.c,sha256.c,..." }
```

The autotools `make sbom` path keeps `wolfssl:sbom:hash-kind` implicit
(equal to `library-binary`) so its output stays byte-identical to
previous releases.

### 1.5 Pre-processed defines (no pcpp needed)

If `pcpp` is unavailable on your build host or you prefer to use the
compiler that actually builds wolfSSL, dump its post-preprocessor `#define`
table and pass that to `--options-h`:

```sh
$CC $CFLAGS -dM -E \
    -DWOLFSSL_USER_SETTINGS \
    -include wolfssl/wolfcrypt/settings.h \
    -x c /dev/null > build/wolfssl-defines.h

python3 scripts/gen-sbom \
    --name wolfssl --version 5.9.1 \
    --license-file LICENSING \
    --options-h build/wolfssl-defines.h \
    --srcs wolfcrypt/src/aes.c wolfcrypt/src/sha.c ... \
    --cdx-out wolfssl-5.9.1.cdx.json \
    --spdx-out wolfssl-5.9.1.spdx.json
```

`--options-h` reads any flat C header containing `#define NAME VALUE`
lines, so the GCC / Clang / `armclang` `-dM -E` output drops in directly.
For IAR (`--predef_macros`) or legacy Keil `armcc` (`--list_macros`) the
output may need a one-line `sed` to match the `#define NAME VALUE`
shape.

**Noise filtering.** A raw `$CC -dM -E` dump contains hundreds of
compiler / preprocessor reserved identifiers (`__VERSION__`, `__SSE2__`,
`__INT_FAST32_MAX__`, `_LP64`, …) and on macOS also Apple's entire
`<TargetConditionals.h>` family (`TARGET_OS_MAC=1`, `TARGET_IPHONE_*`,
…) which leak in via system header inclusion.  These describe the
*build host*, not wolfSSL, and would otherwise drown out the wolfSSL
configuration in the SBOM and break reproducibility across hosts.
`gen-sbom` filters them automatically; the SBOM ends up with only the
`HAVE_*` / `WOLFSSL_*` / `NO_*` / etc. macros that actually describe
the wolfSSL build.  See `_is_noise_macro` in `scripts/gen-sbom` for the
exact policy and the test cases in `scripts/test_gen_sbom.py`
(`TestIsNoiseMacro`) for the pinned coverage.

Header-suffix carve-out: the filter also drops include-guard names
(`*_H` like `WOLF_CRYPT_SETTINGS_H`, `WOLFSSL_OPTIONS_H`) but
preserves real wolfSSL configuration that happens to end in `_H`.
The carve-out tokens are `HAVE_`, `NO_`, and `USE_`, which between
them cover every `_H`-suffixed configuration flag in the wolfSSL
tree:

* autoconf header probes — `HAVE_STDINT_H`, `WOLFSSL_HAVE_ATOMIC_H`,
  `WOLFSSL_HAVE_ASSERT_H`, …
* stdlib disablement (NETOS / Telit / similar RTOS profiles) —
  `NO_STDINT_H`, `NO_STDLIB_H`, `NO_LIMITS_H`, `NO_CTYPE_H`,
  `NO_STRING_H`, `NO_STDDEF_H`, `WOLFSSL_NO_ASSERT_H`
* build-mode toggles — `USE_FLAT_TEST_H`, `USE_FLAT_BENCHMARK_H`

Customers using a `_H`-suffixed feature flag that does not carry
one of these tokens (e.g. a debug-only opt-in) should rename it
to drop the `_H` suffix, or open an issue to extend the carve-out.

The `--user-settings` (pcpp) path applies the same filter, so both
entry points produce semantically equivalent build-property sets for
the same effective configuration.

**Hard-fail on preprocessing errors.** When the `--user-settings`
path encounters an `#error` directive, an unbalanced `#if`, or a
missing `#include` while walking `settings.h`, `gen-sbom` exits
non-zero rather than emitting a partial SBOM.  pcpp would otherwise
print a diagnostic and continue, producing an artefact that silently
omits whatever configuration came after the failure — exactly the
kind of silent drift a CRA reviewer cannot detect.  Fix the upstream
issue (or supply the missing `--user-settings-include` /
`--user-settings-define` arguments) and rerun.

### 1.6 Per-IDE / per-toolchain recipes

#### 1.6.1 Custom Makefile (most embedded projects)

Drop these rules into your project Makefile.  The `WOLFCRYPT_OBJS` /
`WOLFCRYPT_SRCS` variables almost certainly already exist in your build
since they list the wolfSSL files you compile.

```makefile
WOLFSSL_DIR ?= ../wolfssl

build/libwolfssl-sbom.a: $(WOLFCRYPT_OBJS)
	$(AR) rcs $@ $^

sbom: build/libwolfssl-sbom.a
	python3 $(WOLFSSL_DIR)/scripts/gen-sbom \
	    --name wolfssl --version 5.9.1 \
	    --license-file $(WOLFSSL_DIR)/LICENSING \
	    --user-settings $(WOLFSSL_DIR)/wolfssl/wolfcrypt/settings.h \
	    --user-settings-include $(WOLFSSL_DIR) \
	    --user-settings-include $(USER_SETTINGS_DIR) \
	    --user-settings-define WOLFSSL_USER_SETTINGS \
	    --srcs $(WOLFCRYPT_SRCS) \
	    --cdx-out wolfssl-5.9.1.cdx.json \
	    --spdx-out wolfssl-5.9.1.spdx.json
```

Note: the `.a` here is optional.  If you prefer to skip it and rely on
`--srcs` for the checksum (the recommended embedded mode), drop the
`build/libwolfssl-sbom.a` rule and remove its dependency from `sbom:`.

#### 1.6.2 ESP-IDF (Espressif)

ESP-IDF builds with CMake/Ninja and exposes a `CMakeLists.txt` per
component.  Add a custom target to `components/wolfssl/CMakeLists.txt`:

```cmake
add_custom_target(wolfssl-sbom
    COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/scripts/gen-sbom
        --name wolfssl --version 5.9.1
        --license-file ${CMAKE_CURRENT_SOURCE_DIR}/LICENSING
        --user-settings ${CMAKE_CURRENT_SOURCE_DIR}/wolfssl/wolfcrypt/settings.h
        --user-settings-include ${CMAKE_CURRENT_SOURCE_DIR}
        --user-settings-include ${WOLFSSL_USER_SETTINGS_DIR}
        --user-settings-define WOLFSSL_USER_SETTINGS
        --srcs ${WOLFSSL_SRCS}
        --cdx-out ${CMAKE_BINARY_DIR}/wolfssl-5.9.1.cdx.json
        --spdx-out ${CMAKE_BINARY_DIR}/wolfssl-5.9.1.spdx.json
    VERBATIM)
```

Then `idf.py wolfssl-sbom` produces both SBOM files in the build
directory.

#### 1.6.3 Zephyr

```cmake
# In your application CMakeLists.txt or a Zephyr module CMake file:
add_custom_target(wolfssl-sbom
    COMMAND ${PYTHON_EXECUTABLE} ${ZEPHYR_WOLFSSL_MODULE_DIR}/scripts/gen-sbom
        --name wolfssl --version 5.9.1
        --license-file ${ZEPHYR_WOLFSSL_MODULE_DIR}/LICENSING
        --user-settings ${ZEPHYR_WOLFSSL_MODULE_DIR}/wolfssl/wolfcrypt/settings.h
        --user-settings-include ${ZEPHYR_WOLFSSL_MODULE_DIR}
        --user-settings-define WOLFSSL_USER_SETTINGS
        --srcs ${WOLFSSL_SOURCES}
        --cdx-out ${CMAKE_BINARY_DIR}/wolfssl.cdx.json
        --spdx-out ${CMAKE_BINARY_DIR}/wolfssl.spdx.json)
```

Run with `west build -t wolfssl-sbom`.

#### 1.6.4 STM32CubeIDE

STM32CubeIDE generates Eclipse CDT-managed Makefiles.  Add the SBOM
recipe as a *post-build step*: **Project → Properties → C/C++ Build →
Settings → Build Steps → Post-build steps**:

```sh
python3 ${ProjDirPath}/Drivers/wolfssl/scripts/gen-sbom \
    --name wolfssl --version 5.9.1 \
    --license-file ${ProjDirPath}/Drivers/wolfssl/LICENSING \
    --user-settings ${ProjDirPath}/Drivers/wolfssl/wolfssl/wolfcrypt/settings.h \
    --user-settings-include ${ProjDirPath}/Drivers/wolfssl \
    --user-settings-include ${ProjDirPath}/Core/Inc \
    --user-settings-define WOLFSSL_USER_SETTINGS \
    --srcs ${ProjDirPath}/Drivers/wolfssl/wolfcrypt/src/aes.c [...] \
    --cdx-out ${ProjDirPath}/wolfssl.cdx.json \
    --spdx-out ${ProjDirPath}/wolfssl.spdx.json
```

#### 1.6.5 Keil μVision (MDK-ARM)

Use **Options for Target → User → Run #1 (After Build)**:

```
python3 .\Drivers\wolfssl\scripts\gen-sbom --name wolfssl --version 5.9.1 ^
    --license-file .\Drivers\wolfssl\LICENSING ^
    --user-settings .\Drivers\wolfssl\wolfssl\wolfcrypt\settings.h ^
    --user-settings-include .\Drivers\wolfssl ^
    --user-settings-define WOLFSSL_USER_SETTINGS ^
    --srcs .\Drivers\wolfssl\wolfcrypt\src\aes.c [...] ^
    --cdx-out .\wolfssl.cdx.json --spdx-out .\wolfssl.spdx.json
```

For legacy `armcc` 5.x toolchains where `-dM -E` is not available, use
the modern `armclang` (Keil v6) which is GCC-flag-compatible.

#### 1.6.6 IAR EWARM

Use **Project → Options → Build Actions → Post-build command line** (one
line, all on one logical line in EWARM):

```
python3 $PROJ_DIR$\..\wolfssl\scripts\gen-sbom --name wolfssl --version 5.9.1
    --license-file $PROJ_DIR$\..\wolfssl\LICENSING
    --user-settings $PROJ_DIR$\..\wolfssl\wolfssl\wolfcrypt\settings.h
    --user-settings-include $PROJ_DIR$\..\wolfssl
    --user-settings-define WOLFSSL_USER_SETTINGS
    --srcs $PROJ_DIR$\..\wolfssl\wolfcrypt\src\aes.c [...]
    --cdx-out $PROJ_DIR$\wolfssl.cdx.json
    --spdx-out $PROJ_DIR$\wolfssl.spdx.json
```

#### 1.6.7 Plain CMake (any project)

```cmake
add_custom_target(wolfssl-sbom
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/wolfssl/scripts/gen-sbom
        --name wolfssl --version 5.9.1
        --license-file ${CMAKE_SOURCE_DIR}/wolfssl/LICENSING
        --user-settings ${CMAKE_SOURCE_DIR}/wolfssl/wolfssl/wolfcrypt/settings.h
        --user-settings-include ${CMAKE_SOURCE_DIR}/wolfssl
        --user-settings-include ${WOLFSSL_USER_SETTINGS_DIR}
        --user-settings-define WOLFSSL_USER_SETTINGS
        --srcs ${WOLFSSL_C_SOURCES}
        --cdx-out ${CMAKE_BINARY_DIR}/wolfssl-${WOLFSSL_VERSION}.cdx.json
        --spdx-out ${CMAKE_BINARY_DIR}/wolfssl-${WOLFSSL_VERSION}.spdx.json)
```

### 1.7 Reproducibility

The standalone path honors `SOURCE_DATE_EPOCH` exactly the same way
`make sbom` does.  Two runs against the same source tree, settings, and
source set with the same `SOURCE_DATE_EPOCH` produce byte-identical
`.spdx.json` and `.cdx.json` files.  This is regression-tested in CI.

---

## 2. Autotools convenience wrapper (`make sbom`)

For Linux server / Debian / RPM / Yocto / FIPS-Ready customers who
already run `./configure && make`, `make sbom` is a one-line shortcut
that wraps `scripts/gen-sbom` with all paths resolved automatically.

### 2.1 Quick start

```sh
./configure
make
make sbom
```

Requires `python3` and `pyspdxtools` (`pip install spdx-tools`).

### 2.2 Full coverage: component identity + build provenance

```sh
./configure
make
make sbom
make bomsh
```

Additionally requires `bomtrace3` and `bomsh_create_bom.py` in `PATH`.
See [Prerequisites for make bomsh](#31-prerequisites-for-make-bomsh) below.

All tools are detected by `configure`; either target fails with a clear
error message if a required tool is missing.

### 2.3 Output files

`make sbom` produces three files in the build directory:

| File | Format | Standard | Primary use |
|---|---|---|---|
| `wolfssl-<version>.cdx.json` | JSON | CycloneDX 1.6 | Supply-chain tooling, VEX |
| `wolfssl-<version>.spdx.json` | JSON | SPDX 2.3 | Machine processing |
| `wolfssl-<version>.spdx` | Tag-value | SPDX 2.3 | Human review, archival |

The `.spdx` tag-value file is produced by `pyspdxtools` converting the
`.spdx.json`.  If the JSON fails SPDX validation, `make sbom` stops with
a non-zero exit and the tag-value file is not written.

### 2.4 SBOM contents

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
commercial license for proprietary products.  The default SBOM reflects the
open-source license.  Commercial licensees should regenerate the SBOM with
`--license-override` set to their applicable SPDX expression — the generator
exposes this directly:

```sh
python3 scripts/gen-sbom \
    --license-override LicenseRef-wolfSSL-Commercial \
    --license-text /path/to/wolfssl-commercial-license.txt \
    ... other flags ...
```

`--license-text` is **required** whenever `--license-override` is a custom
`LicenseRef-*`: SPDX 2.3 mandates that any LicenseRef in `licenseConcluded`
or `licenseDeclared` be backed by a `hasExtractedLicensingInfos` entry that
embeds the actual licence text.  Running without it is a configuration
error and the generator exits non-zero rather than emit a misleading SBOM
that auditors might then circulate.

For an SPDX-listed override (`Apache-2.0`, `MIT`, etc.), `--license-text`
is unnecessary because validators already know the canonical text.

`make sbom` plumbs both knobs through the matching make variables:

```sh
make sbom \
    SBOM_LICENSE_OVERRIDE=LicenseRef-wolfSSL-Commercial \
    SBOM_LICENSE_TEXT=/path/to/wolfssl-commercial-license.txt
```

#### External dependency version detection

The optional external dependencies wolfSSL can link against (`libz` and
`liboqs`) are both installed packages and are queried via
`pkg-config --modversion` at SBOM generation time.  The SBOM records each
linked library by its package name (`zlib`, `liboqs`) so that downstream
vulnerability scanners (OSV, Grype, Trivy, Dependency-Track) match CVEs
against the right component.  Algorithm enablement (e.g. Falcon, which is
reachable only via liboqs) is captured separately as build properties
(`wolfssl:build:HAVE_FALCON` etc.) parsed from `wolfssl/options.h`.

If pkg-config does not report a version (the package is not installed, or
its `.pc` file is missing):

- SPDX records `versionInfo: NOASSERTION` and emits no `purl` external ref.
- CycloneDX omits the `version` and `purl` fields entirely and the generator
  prints a warning to stderr.

For embedded / cross-compile builds without `pkg-config`, the standalone
entry point exposes a `--dep-version libz=1.3.1` override (see § 1.2).

### 2.5 Validating the SBOM manually

```sh
# Validate SPDX JSON
pyspdxtools --infile wolfssl-<version>.spdx.json

# Convert to another format (e.g. RDF)
pyspdxtools --infile wolfssl-<version>.spdx.json \
            --outfile wolfssl-<version>.spdx.rdf
```

### 2.6 Installing the SBOM

```sh
make install-sbom        # installs to $(datadir)/doc/wolfssl/
make uninstall-sbom      # removes the installed files
```

The generated files are removed by `make clean`.

### 2.7 Implementation notes

SBOM generation is implemented in `scripts/gen-sbom` (Python 3, stdlib
only for the autotools path) and hooked into the autotools build via
`Makefile.am` and `configure.ac`.  The script stages a `make install`
into a temporary directory, hashes the installed library, generates both
SBOM formats, then removes the staging directory.  The `pyspdxtools`
validation and conversion step runs after generation and gates the build
on SPDX conformance.

The standalone embedded entry point (§ 1) calls the same script with
different flags; the autotools target is essentially a path-resolver
wrapper that finds the installed library, the autotools-generated
`options.h`, and the `pkg-config` versions of any linked deps.

---

## 3. make bomsh

`make bomsh` uses the [Bomsh](https://github.com/omnibor/bomsh) project to
trace the wolfSSL build under `bomtrace3` (a patched `strace`) and produce
an OmniBOR artifact dependency graph: a content-addressed Merkle DAG mapping
every built binary back to the exact set of source files that produced it.

### 3.1 Prerequisites for make bomsh

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

`make bomsh` is **Linux-host-only by design**.  For non-Linux build hosts
(macOS, Windows), use a Linux CI runner / WSL2 / a Linux container.  The
target running the produced wolfSSL binary can be anything — bomsh traces
the cross-compiler invocation on Linux regardless of what platform the
binary will eventually run on.

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

### 3.2 What make bomsh does

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

### 3.3 Output files

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

### 3.4 Installing

```sh
make install-bomsh    # installs omnibor/ and enriched SPDX to $(datadir)/doc/wolfssl/
make uninstall-bomsh  # removes installed files
```

The generated files are removed by `make clean`.

### 3.5 Implementation notes

`make bomsh` runs a full clean rebuild under `bomtrace3` on every invocation.
The ~20% runtime overhead of `bomtrace3` means the rebuild takes roughly
1.2× the normal build time.

The raw logfile (`bomsh_raw_logfile.sha1`) and conf file (`_bomsh.conf`)
are written to the build directory and removed by `make clean`.  The
`omnibor/` tree is also removed by `make clean`.

---

## 4. Combined workflow

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

## 5. Using wolfSSL's artefacts in a product

If you are shipping a product that includes wolfSSL and need to satisfy CRA
obligations, see `doc/CRA.md` for guidance on integrating these artefacts
into your product SBOM and what to provide to a conformity assessor.
