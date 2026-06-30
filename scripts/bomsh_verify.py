#!/usr/bin/env python3
"""End-to-end verifier for the bomsh provenance bundle.

Two independent self-consistency checks on the artefacts that
`make bomsh` produces.  The PERSISTENT-ID assertion in the bomsh CI
job only proves the gitoid externalRef *exists* in the enriched SPDX;
neither of these follow-up properties is guaranteed by it:

  (A) Resolvability  -- every gitoid in the SPDX externalRefs resolves
      to a blob present at omnibor/objects/<aa>/<rest>.  Catches the
      `bomsh_sbom.py` regression class that emits a syntactically
      well-formed gitoid which does not actually point at anything in
      the shipped ADG.

  (B) Object-store integrity -- every blob in omnibor/objects/
      round-trips through sha1(b"blob <len>\\0" + content), so a
      corrupt or truncated object store is caught at PR time, not by
      a downstream verifier weeks later.

CLI form (used by `.github/workflows/sbom.yml`):

    python3 scripts/bomsh_verify.py \\
        --spdx-glob 'omnibor.wolfssl-*.spdx.json' \\
        --omnibor-dir omnibor

Library form (used by scripts/test_gen_sbom.py):

    from scripts import bomsh_verify
    ok, messages = bomsh_verify.verify(...)
"""

import argparse
import glob as _glob
import hashlib
import json
import os
import re
import sys
from typing import List


GITOID_LOCATOR_PREFIX = 'gitoid:blob:sha1:'
# An OmniBOR sha1 gitoid is exactly 40 lowercase-hex chars.  Validate before
# the value is used to build an object path: a crafted SPDX with a locator like
# 'gitoid:blob:sha1:../../../etc/shadow' otherwise passes the prefix check and
# turns the os.path.join() below into a path-traversal existence oracle.
_SHA1_HEX_RE = re.compile(r'[0-9a-f]{40}\Z')


def gitoid_sha1(path):
    """OmniBOR `gitoid:blob:sha1:<hex>` is the canonical Git blob hash:
    sha1(b"blob <len>\\0" + content).  Symlinks are followed transparently
    by `open()`, which matches what bomsh records (the trace sees the
    target, not the symlink)."""
    with open(path, 'rb') as f:
        data = f.read()
    h = hashlib.sha1()
    h.update(f'blob {len(data)}\0'.encode())
    h.update(data)
    return h.hexdigest()


def load_spdx_gitoids(spdx_path):
    """Return [(package_name, gitoid_hex), ...] for every externalRef
    of referenceType 'gitoid' in the SPDX document at spdx_path.

    Raises ValueError on a malformed locator (anything that isn't
    `gitoid:blob:sha1:<hex>`).  An sha256 locator would land here too
    if bomsh ever switches; the failure is the right behaviour, since
    a maintainer must update the verifier in lockstep."""
    with open(spdx_path) as f:
        spdx = json.load(f)
    gitoids = []
    for pkg in spdx.get('packages', []):
        for ref in pkg.get('externalRefs', []):
            if ref.get('referenceType') != 'gitoid':
                continue
            loc = ref.get('referenceLocator', '')
            if not loc.startswith(GITOID_LOCATOR_PREFIX):
                raise ValueError(
                    f'unexpected gitoid locator format: {loc!r} '
                    f'(expected {GITOID_LOCATOR_PREFIX}<hex>; if bomsh '
                    f'has switched to sha256 the verifier needs updating)')
            gid = loc[len(GITOID_LOCATOR_PREFIX):]
            if not _SHA1_HEX_RE.match(gid):
                raise ValueError(
                    f'malformed gitoid {gid!r} in locator {loc!r}: expected '
                    f'40 lowercase-hex sha1 characters (refusing to use it in '
                    f'an object path)')
            gitoids.append((pkg.get('name', '<no-name>'), gid))
    return gitoids


def check_resolvability(spdx_gitoids, omnibor_objects_dir):
    """(A) Every SPDX gitoid resolves to a file at
    `<omnibor_objects_dir>/<aa>/<rest>`.  Returns a list of
    (pkg_name, gitoid, expected_path) for the unresolved ones; empty
    list means every gitoid resolved."""
    missing = []
    for pkg_name, gid in spdx_gitoids:
        obj = os.path.join(omnibor_objects_dir, gid[:2], gid[2:])
        if not os.path.isfile(obj):
            missing.append((pkg_name, gid, obj))
    return missing


_HEX_CHARS = frozenset('0123456789abcdef')


def _looks_like_blob_path(parts):
    """True iff `parts` is the canonical `<aa>/<rest>` shape Git uses
    for content-addressed blob fanout: exactly two components, the
    first of which is a 2-char lowercase-hex prefix and the second of
    which is the remaining lowercase-hex of a sha1 digest (38 chars)
    or sha256 digest (62 chars).  Anything else (`info/`, `pack/...`,
    deeper nesting) is housekeeping and must NOT be gitoid-checked."""
    if len(parts) != 2:
        return False
    aa, rest = parts
    if len(aa) != 2 or not all(c in _HEX_CHARS for c in aa):
        return False
    if len(rest) not in (38, 62):
        return False
    return all(c in _HEX_CHARS for c in rest)


def check_object_store_integrity(omnibor_objects_dir):
    """(B) Every blob in <omnibor_objects_dir> round-trips through
    `gitoid_sha1`.  Returns (count_total, [(path, expected, actual), ...]
    for blobs whose content does not match their expected gitoid).

    The directory layout is `<omnibor_objects_dir>/<aa>/<rest>` (Git's
    standard fanout, where <aa> is the first two hex chars of the
    digest); files outside that shape are skipped silently (e.g.
    `info/` or `pack/` siblings, README files, etc.)."""
    bad = []
    obj_count = 0
    for root, _, files in os.walk(omnibor_objects_dir):
        for fname in files:
            obj = os.path.join(root, fname)
            rel = os.path.relpath(obj, omnibor_objects_dir)
            parts = rel.split(os.sep)
            if not _looks_like_blob_path(parts):
                continue
            expected = parts[0] + parts[1]
            obj_count += 1
            actual = gitoid_sha1(obj)
            if actual != expected:
                bad.append((obj, expected, actual))
    return obj_count, bad


def verify(spdx_glob, omnibor_dir):
    """Orchestrate the two checks.  Returns (ok: bool, messages:
    List[str]).  `messages` is appended to in success and failure both,
    so callers can log the success lines ('OK: N gitoid(s) verified' +
    '    objects round-trip: M blobs') even when ok is True."""
    messages: List[str] = []

    spdx_paths = sorted(_glob.glob(spdx_glob))
    if not spdx_paths:
        return False, [f'no SPDX matched {spdx_glob!r}']
    spdx_path = spdx_paths[0]
    try:
        spdx_gitoids = load_spdx_gitoids(spdx_path)
    except (json.JSONDecodeError, ValueError) as e:
        return False, [f'could not load SPDX gitoids: {e}']
    if not spdx_gitoids:
        return False, [f'no gitoid externalRefs in {spdx_path}']

    objects_dir = os.path.join(omnibor_dir, 'objects')

    missing = check_resolvability(spdx_gitoids, objects_dir)
    if missing:
        for pkg_name, gid, obj in missing:
            messages.append(
                f'DANGLING: {pkg_name} gitoid {gid} -> {obj}')
        messages.append(
            f'{len(missing)} SPDX gitoid(s) not present in '
            f'{objects_dir}/ (provenance bundle is broken)')
        return False, messages

    obj_count, bad = check_object_store_integrity(objects_dir)
    if bad:
        for obj, expected, actual in bad[:5]:
            messages.append(
                f'CORRUPT: {obj} expected {expected} got {actual}')
        messages.append(
            f'{len(bad)} object(s) in {objects_dir}/ failed gitoid '
            f'round-trip (object store is corrupt)')
        return False, messages

    messages.append(f'OK: {len(spdx_gitoids)} gitoid(s) verified')
    messages.append(f'    objects round-trip: {obj_count} blobs')
    return True, messages


def main():
    parser = argparse.ArgumentParser(
        description='End-to-end verifier for the bomsh provenance bundle.')
    parser.add_argument('--spdx-glob',
                        default='omnibor.wolfssl-*.spdx.json',
                        help='Glob matching the bomsh-enriched SPDX file '
                             '(default: %(default)s)')
    parser.add_argument('--omnibor-dir', default='omnibor',
                        help='Path to the OmniBOR directory containing '
                             'objects/ (default: %(default)s)')
    args = parser.parse_args()

    ok, messages = verify(args.spdx_glob, args.omnibor_dir)
    for line in messages:
        print(line, file=sys.stderr if not ok else sys.stdout)
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
