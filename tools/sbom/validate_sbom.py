#!/usr/bin/env python3
"""Structural validator for wolfssl-compliance-tooling SBOM output.

This is the product-neutral form of wolfBoot's validate_sbom.py. It asserts the
essentials that every SBOM route must satisfy, so CI (and humans) can fail fast
on a broken generator. It is not a full schema validator.

  CycloneDX (*.cdx.json):
    * bomFormat == "CycloneDX"
    * specVersion == "1.6"
    * metadata.component.name starts with --name-prefix (if given)
    * metadata.component has a non-empty version
    * at least one component or component property recorded
    * optional --min-properties N on metadata.component.properties
    * optional --require-dep-version NAME: a components[] entry with that
      name must exist and carry a non-empty version. Nested sub-components
      count, since wolfcrypt ships inside wolfssl. wolfcrypt is provenance
      only (PURL, no CPE); matching rides on the parent wolfssl CPE. Every
      other required dep must also carry a CPE.

  SPDX (*.spdx.json):
    * spdxVersion starts with "SPDX-2"
    * has a name and at least one package
    * optional --require-dep-version NAME: a packages[] entry whose name
      contains NAME must carry a non-empty versionInfo

The file kind is detected by content, so argument order does not matter.

Usage:
  validate_sbom.py [--name-prefix PREFIX] [--min-properties N]
                   [--require-dep-version NAME] FILE [FILE ...]
"""

import argparse
import json
import sys


# Nested wolfcrypt is a provenance component. NVD files crypto CVEs against
# wolfssl, not wolfcrypt; requiring a wolfcrypt CPE would fail a correct
# SBOM and would later double-match. The unique id is the PURL.
_CPE_OPTIONAL_DEPS = frozenset({"wolfcrypt"})


def fail(path, msg):
    print(f"FAIL [{path}]: {msg}", file=sys.stderr)
    sys.exit(1)


def flatten_components(components):
    """Yield every component, including sub-components.

    CycloneDX nests a component that ships inside another one (wolfcrypt
    inside the wolfssl release) under `components[]`. A check that reads only
    the top level would report such a component as missing."""
    for comp in components or []:
        yield comp
        yield from flatten_components(comp.get("components"))


def validate_cyclonedx(path, d, name_prefix, min_properties, require_deps):
    if d.get("bomFormat") != "CycloneDX":
        fail(path, f"bomFormat != CycloneDX (got {d.get('bomFormat')!r})")
    if d.get("specVersion") != "1.6":
        fail(path, f"specVersion != 1.6 (got {d.get('specVersion')!r})")
    comp = d.get("metadata", {}).get("component", {})
    name = comp.get("name", "")
    if name_prefix and not name.startswith(name_prefix):
        fail(path, f"metadata.component.name does not start with "
                   f"{name_prefix!r} (got {name!r})")
    if not comp.get("version"):
        fail(path, "metadata.component.version is empty")
    props = comp.get("properties") or []
    if not d.get("components") and not props:
        fail(path, "no components or component properties recorded")
    if min_properties is not None and len(props) < min_properties:
        fail(path, f"metadata.component.properties has {len(props)} entries, "
                   f"need at least {min_properties} (config capture likely "
                   f"empty — check --options-h vs --cflags)")
    all_comps = list(flatten_components(d.get("components")))
    for dep_name in require_deps:
        if not all_comps:
            fail(path, "components[] is empty but --require-dep-version "
                       f"{dep_name!r} was requested (dependency graph "
                       "missing — check DEP_WOLFSSL / DEP_WOLFCRYPT wiring)")
        matches = [c for c in all_comps if c.get("name") == dep_name]
        if not matches:
            fail(path, f"required dependency component {dep_name!r} missing")
        if not matches[0].get("version"):
            fail(path, f"dependency component {dep_name!r} has no version "
                       f"(pass --dep-version or set WOLFSSL_DIR)")
        if dep_name in _CPE_OPTIONAL_DEPS:
            if not matches[0].get("purl"):
                fail(path, f"dependency component {dep_name!r} has no purl "
                           f"(provenance id; matching uses the wolfssl CPE)")
            continue
        if not matches[0].get("cpe"):
            fail(path, f"dependency component {dep_name!r} has no cpe "
                       f"(CPE-driven scanners cannot match it)")
    print(f"OK   [{path}]: CycloneDX 1.6, component "
          f"{comp.get('name')} {comp.get('version')}, "
          f"{len(props)} properties")


def validate_spdx(path, d, require_deps):
    ver = d.get("spdxVersion", "")
    if not ver.startswith("SPDX-2"):
        fail(path, f"spdxVersion not SPDX-2.x (got {ver!r})")
    if not d.get("name"):
        fail(path, "document name is empty")
    pkgs = d.get("packages") or []
    if not pkgs:
        fail(path, "no packages recorded")
    for dep_name in require_deps:
        matches = [p for p in pkgs
                   if dep_name.lower() in (p.get("name") or "").lower()]
        if not matches:
            fail(path, f"required dependency package matching {dep_name!r} "
                       f"missing")
        if not matches[0].get("versionInfo"):
            fail(path, f"dependency package {matches[0].get('name')!r} has "
                       f"no versionInfo")
    print(f"OK   [{path}]: {ver}, {len(pkgs)} package(s)")


def main(argv):
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--name-prefix", default="",
                    help="Require metadata.component.name to start with this.")
    ap.add_argument("--min-properties", type=int, default=None,
                    help="Require at least N CycloneDX component properties "
                         "(guards empty --cflags captures).")
    ap.add_argument("--require-dep-version", action="append", default=[],
                    metavar="NAME",
                    help="Require a dependency component/package NAME with "
                         "a non-empty version (repeatable).")
    ap.add_argument("files", nargs="+")
    args = ap.parse_args(argv[1:])

    for path in args.files:
        try:
            with open(path) as f:
                d = json.load(f)
        except OSError as e:
            fail(path, f"cannot read file: {e}")
        except json.JSONDecodeError as e:
            fail(path, f"invalid JSON: {e}")
        except UnicodeDecodeError as e:
            fail(path, f"not UTF-8 text: {e}")
        if not isinstance(d, dict):
            fail(path, "top-level JSON is not an object")
        if "bomFormat" in d or path.endswith(".cdx.json"):
            validate_cyclonedx(path, d, args.name_prefix,
                               args.min_properties, args.require_dep_version)
        elif "spdxVersion" in d or path.endswith(".spdx.json"):
            validate_spdx(path, d, args.require_dep_version)
        else:
            fail(path, "unrecognized SBOM format (neither CycloneDX nor SPDX)")
    print("All SBOMs valid.")


if __name__ == "__main__":
    main(sys.argv)
