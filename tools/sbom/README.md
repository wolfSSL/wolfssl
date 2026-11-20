# wolfssl-compliance-tooling SBOM files

These are the SBOM files that a product vendors from
[wolfssl-compliance-tooling](https://github.com/wolfSSL/wolfssl-compliance-tooling).
The source is the `share/` folder of that repository. A product keeps a copy in
`tools/sbom/`, together with the pin files (`VERSION` and
`.wolfssl-compliance-tooling-rev`). Do not edit the copy in a product.

To change the pin, run the sync tool from a checkout of
wolfssl-compliance-tooling. The tool is not vendored into the product:

    <tooling-checkout>/tools/wolfssl-compliance-tooling-sync --dest <product> --prune

Add `--check` to find drift, including lost executable bits, without a copy.

## Contents

| File | Role |
|---|---|
| `sbom-driver.py` | The product-neutral SBOM engine (Python). |
| `sbom-driver` | Thin shell wrapper that runs `sbom-driver.py`. |
| `validate_sbom.py` | Structural validator for CI (`--name-prefix`). |
| `frontends/compdb_sbom.py` | Extractor for any `compile_commands.json`. |
| `frontends/iar_sbom.py` | Extractor for an IAR Embedded Workbench `.ewp`. |
| `frontends/included_sources.py` | Finds the source files a compile command compiles in through `#include` (`compdb_sbom.py --included-sources`). |
| `frontends/zephyr_sbom.py` | Zephyr module, from a west build's `compile_commands.json`. |
| `build/sbom.mk` | Shared plain-Make fragment and `wolfssl_compliance_tooling_sbom_rule` macro. |
| `build/sbom.cmake` | Shared CMake helper: `wolfssl_compliance_tooling_add_sbom()`. |
| `build/sbom-with-sde.cmake` | Runs the driver with `SOURCE_DATE_EPOCH`, after the `STAGE_TARGET` install. |
| `build/sbom-validate.cmake` | `VALIDATE` step: pyspdxtools check and SPDX tag-value file. |
| `build/sbom-fail.cmake` | Target body when python3 or pyspdxtools is missing. |
| `build/install-sbom.cmake`, `build/uninstall-sbom.cmake`, `build/sbom-paths.cmake` | `install-sbom` and `uninstall-sbom`. |
| `gen-sbom` | The vendored SBOM generator. |
| `sbom.am` | Shared autotools fragment. |

## The driver contract

Every front end produces a composition input and a config input and hands them to
the driver.

Composition (pick one):

- `--srcs-file PATH` — the source files compiled into the artifact (tier E).
- `--lib PATH` — the built library to hash (tier R/L/S).
- `--no-artifact-hash` — record a placeholder checksum when no hashable
  artefact exists (a FIPS canister or a kernel module). Do not pass `--lib`
  or `--srcs-file` with it. gen-sbom accepts one checksum source. Never
  substitute a source list for a certified artifact.

Config (choose one):

- `--cflags="..."` — raw CFLAGS; the driver expands the `-D` tokens through the
  host compiler. Use the `=` form so a leading-dash value is not read as a flag.
- `--options-h PATH` — a pre-expanded flat `#define` header, used verbatim.
- `--user-settings PATH` — path to `wolfssl/wolfcrypt/settings.h`. Also pass
  `--user-settings-include DIR` (the directory that contains `user_settings.h`)
  and `--user-settings-define WOLFSSL_USER_SETTINGS`. The autotools fragment
  takes `SBOM_USER_SETTINGS`, `SBOM_USER_SETTINGS_INCLUDES` and
  `SBOM_USER_SETTINGS_DEFINES`.
- `--source-only` — no build-config macros (for example a Kconfig-driven build).

A product that shares one `user_settings.h` with wolfSSL captures wolfSSL's
macros along with its own. Pass `--macro-prefix PREFIX` (repeatable; Make and
autotools `SBOM_MACRO_PREFIX`, CMake `MACRO_PREFIX`) to record only the macros
whose name starts with that prefix, for example `WOLFCERT_`. `--crypto-only auto`
still reads the full capture.

Dependency (for linkers and bindings): `--dep-wolfssl`, `--dep-openssl`, and
`--dep-version` are passed through only when the generator supports them.

Copyright: the line reads `Copyright (C) <start>-<build year> <supplier>`.
`--copyright-start` (Make, autotools: `SBOM_COPYRIGHT_START`; CMake:
`COPYRIGHT_START`) sets the first year, which defaults to 2006.

Timestamp: `SOURCE_DATE_EPOCH` sets the creation time and the build year. When
it is not set and `--root` is passed, the driver uses the last commit time of
the checkout that tracks that directory, so Make, CMake and a front end that
passes `--root` give one checkout the same time. With no `--root`, or a tree
that git does not track, gen-sbom uses the current time.

The driver captures macros with the host compiler, so the SBOM is reproducible
across toolchains. It scrubs absolute host paths from the captured macros unless
you pass `--no-scrub`.

The shared driver is product-neutral and calls the `gen-sbom` file in the same
directory. Pass `--gen-sbom` only when you want to override that copy.

## The manifest contract

A product does not copy logic. It describes itself:

- Make: set `SBOM_NAME`, `SBOM_SRCS`, `SBOM_CFLAGS`, and a version
  (`SBOM_VERSION`, or `SBOM_VERSION_FILE` + `SBOM_VERSION_MACRO`), then
  `include tools/sbom/build/sbom.mk`. For a second target, instantiate
  `$(eval $(call wolfssl_compliance_tooling_sbom_rule,<target>,<prefix>))`.
  If the product's configuration lives in a `user_settings.h`, also set
  `SBOM_SETTINGS_H` (and `SBOM_INCLUDE_DIRS` if that header needs paths the
  CFLAGS do not already carry). `SBOM_CFLAGS` alone records the literal `-D`
  set and nothing it derives, which for a gated header means the SBOM
  describes a configuration nobody built.
- CMake: `include(tools/sbom/build/sbom.cmake)` and call `wolfssl_compliance_tooling_add_sbom()`
  with `NAME`, `VERSION_FILE`, `VERSION_MACRO`, `TARGETS`, `DEFS`, `LICENSE`.
  The same call adds `install-sbom` and `uninstall-sbom`. They copy the
  CycloneDX and SPDX files to `CMAKE_INSTALL_DOCDIR` (or
  `share/doc/<NAME>`) under the install or staging prefix, or to a
  `CMAKE_INSTALL_FULL_DOCDIR` the project set itself, and read `DESTDIR` when
  the target runs.
  Pass `CDX_OUT` / `SPDX_OUT`
  when the file name is not `<name>-<version>` (wolfBoot's config tag).
  To hash the installed library and validate the SPDX file as `make sbom`
  does, pass `STAGE_TARGET <library target>` and `VALIDATE`. Then
  `install-sbom` also installs the tag-value file. The staging installs only
  that target's binaries, through a private `EXCLUDE_FROM_ALL` install
  component in a build directory of its own, so no other target has to be
  built, no other install rule runs and `install_manifest.txt` is left alone. The hash is that of a plain
  `install(TARGETS)`; a product that changes the installed file, with
  `install(CODE)` or `install(FILES)`, passes `LIB` instead. A product that
  packages per component with CPack sets `CPACK_COMPONENTS_ALL`. A missing
  python3 or pyspdxtools does not fail configure; the `sbom` target fails when
  it is built. A product that writes the tag-value file in its own later
  target can pass `NO_INSTALL` and call
  `wolfssl_compliance_tooling_add_sbom_install(DEPENDS sbom TV ...)` after
  that target exists.
  `SBOM_GEN` is the canonical generator override; `GEN_SBOM` remains a legacy
  alias for compatibility.
- Autotools: set the `SBOM_*` variables and `include tools/sbom/sbom.am`.
- Zephyr: call `wolfssl_compliance_tooling_add_sbom(TARGETS
  ${ZEPHYR_CURRENT_LIBRARY} ...)` from the module's own CMakeLists, after its
  last `zephyr_library_sources()`, so the SBOM records the source set west
  actually built. Without that hook, run `zephyr_sbom.py` on the build's
  `compile_commands.json` with `--root` set to the module, and pass
  `--user-settings` with the module's settings header to record its
  configuration. A module that adds its sources with `target_sources(app
  ...)`, as wolfTPM does, needs `--target app`.

Keep only true product knowledge in the product: the route-through script, the
module extractor, and the HAL source selector.
