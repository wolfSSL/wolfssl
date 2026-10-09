#!/usr/bin/env python3
"""Generate a source-inventory SBOM for a Zephyr module.

This is the product-neutral form of wolfBoot's zephyr_sbom.py. A Zephyr module
compiles its sources into a Zephyr application through `zephyr_library_sources(...)`,
built by Zephyr/west rather than by the product's own Makefile or CMake. So
neither the Make nor the CMake SBOM target sees those sources.

This extractor reads the module's source list straight out of its CMakeLists (so
it stays in sync automatically) and hands it to the shared driver.

The module configuration is Kconfig-driven (CONFIG_* symbols), not a `-D` macro
set, so by default this produces a source-inventory SBOM. If you have a real
Zephyr build and want the exact compiled config, generate the SBOM from that
build's compilation database with compdb_sbom.py instead.

Usage:
  zephyr_sbom.py --name NAME --cmakelists path/to/zephyr/CMakeLists.txt [options]
"""

import argparse
import os
import re
import subprocess
import sys
import tempfile

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DRIVER = os.path.join(os.path.dirname(SCRIPT_DIR), "sbom-driver")

SRC_EXTS = ('.c', '.cc', '.cpp', '.cxx', '.s', '.asm')


def parse_library_sources(cmakelists):
    """Extract the file list from the zephyr_library_sources(...) blocks."""
    with open(cmakelists) as f:
        text = f.read()
    module_dir = os.path.dirname(os.path.abspath(cmakelists))

    srcs = []
    for m in re.finditer(r'zephyr_library_sources\s*\((.*?)\)', text, re.DOTALL):
        for raw in m.group(1).split():
            raw = raw.strip()
            if not raw or not raw.lower().endswith(SRC_EXTS):
                continue
            # Resolve the common CMake module-directory variables.
            p = raw.replace('${CMAKE_CURRENT_LIST_DIR}', module_dir)
            p = p.replace('${CMAKE_CURRENT_SOURCE_DIR}', module_dir)
            p = p.replace('${ZEPHYR_CURRENT_MODULE_DIR}', os.path.dirname(module_dir))
            if '${' in p:
                sys.stderr.write(f"WARNING: skipping unresolved source: {raw}\n")
                continue
            if not os.path.isabs(p):
                p = os.path.join(module_dir, p)
            srcs.append(os.path.normpath(p))

    seen, present, missing = set(), [], []
    for s in srcs:
        if s in seen:
            continue
        seen.add(s)
        (present if os.path.isfile(s) else missing).append(s)
    return present, missing


def main():
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--name', required=True, help='Package name for the SBOM.')
    ap.add_argument('--cmakelists', required=True,
                    help='Path to the module CMakeLists.txt.')
    ap.add_argument('--driver', default=DEFAULT_DRIVER)
    ap.add_argument('--gen-sbom', default=None)
    ap.add_argument('--version', default=None)
    ap.add_argument('--version-file', default=None)
    ap.add_argument('--version-macro', default=None)
    ap.add_argument('--root', default=None)
    ap.add_argument('--license-file', default=None)
    # This front end is --source-only: no macros are captured, so the
    # generator cannot read WOLFCRYPT_ONLY and will say so unless the
    # operator states it here.
    ap.add_argument('--crypto-only', default=None,
                    help='auto|yes|no, forwarded to the generator.')
    ap.add_argument('--cdx-out', default=None)
    ap.add_argument('--spdx-out', default=None)
    ap.add_argument('--srcs-out', default=None)
    ap.add_argument('--print-only', action='store_true')
    args = ap.parse_args()

    if not os.path.isfile(args.cmakelists):
        sys.exit(f"ERROR: CMakeLists not found: {args.cmakelists}")

    srcs, missing = parse_library_sources(args.cmakelists)
    if missing:
        sys.stderr.write(
            f"WARNING: {len(missing)} module source(s) not found on disk "
            f"(excluded):\n")
        for m in missing:
            sys.stderr.write(f"  - {m}\n")
    if not srcs:
        sys.exit("ERROR: no zephyr_library_sources found in " + args.cmakelists)

    if args.print_only:
        print(f"# {args.name}: {len(srcs)} sources")
        for s in srcs:
            print(f"  {s}")
        return

    srcs_out, tmp = args.srcs_out, None
    if not srcs_out:
        fd, srcs_out = tempfile.mkstemp(prefix='wolfssl-compliance-tooling-zephyr-srcs-', suffix='.txt')
        os.close(fd)
        tmp = srcs_out
    with open(srcs_out, 'w') as f:
        f.write('\n'.join(srcs) + '\n')

    cmd = [args.driver, '--srcs-file', srcs_out, '--source-only',
           '--name', args.name]
    for flag, val in (('--version', args.version),
                      ('--version-file', args.version_file),
                      ('--version-macro', args.version_macro),
                      ('--root', args.root),
                      ('--license-file', args.license_file),
                      ('--crypto-only', args.crypto_only),
                      ('--gen-sbom', args.gen_sbom),
                      ('--cdx-out', args.cdx_out),
                      ('--spdx-out', args.spdx_out)):
        if val:
            cmd += [flag, val]

    print(f"Zephyr module SBOM: {len(srcs)} sources (source-inventory)")
    try:
        rc = subprocess.call(cmd)
    finally:
        if tmp and os.path.exists(tmp):
            os.remove(tmp)
    sys.exit(rc)


if __name__ == '__main__':
    main()
