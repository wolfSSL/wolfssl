#!/usr/bin/env python3
"""End-to-end verifier for the bomsh provenance bundle.

Three independent self-consistency checks on the artefacts that
`make bomsh` produces.  The PERSISTENT-ID assertion in the bomsh CI
job only proves the gitoid externalRef *exists* in the enriched SPDX;
none of these follow-up properties are guaranteed by it:

  (A) Resolvability  -- every gitoid in the SPDX externalRefs resolves
      to a blob present at omnibor/objects/<aa>/<rest>.

  (B) Object-store integrity -- every blob in omnibor/objects/
      round-trips through sha1(b"blob <len>\\0" + content), so a
      corrupt or truncated object store is caught at PR time, not by
      a downstream verifier weeks later.

  (C) Artefact correspondence -- the gitoid recorded against the
      wolfSSL package equals the gitoid bomsh itself recorded for the
      library it traced (read from the `_bomsh.artefact` manifest the
      bomsh: Makefile target writes as '<path>\\t<gitoid>' BEFORE
      `make sbom` runs).  This is the strongest claim the bomsh
      pipeline alone can make: the SPDX agrees with what bomsh saw.

      Comparing against bomsh's own recorded gitoid (rather than
      against the on-disk file's *current* bytes) is deliberate.
      `make sbom`'s subsequent `make install` step relinks
      src/.libs/lib*.so* in place via libtool to fix RPATH, mutating
      the bytes after bomsh has already gitoid-ed them.  The verifier
      still hashes the on-disk file and emits a NOTE if it has
      diverged, so the install-time relink remains visible without
      causing a false negative on the bomsh<->SPDX agreement.

Without this, a future `bomsh_sbom.py` change that emits a
plausibly-shaped but fictional gitoid (one that does not resolve in
the ADG, or resolves but to a different artefact than bomsh recorded)
would pass the existing PERSISTENT-ID assertion and ship a provenance
bundle whose externalRef is a lie.

CLI form (used by `.github/workflows/sbom.yml`):

    python3 scripts/bomsh_verify.py \\
        --spdx-glob 'omnibor.wolfssl-*.spdx.json' \\
        --omnibor-dir omnibor \\
        --artefact-manifest _bomsh.artefact

Library form (used by scripts/test_gen_sbom.py):

    from scripts import bomsh_verify
    ok, messages = bomsh_verify.verify(...)
"""

import argparse
import glob as _glob
import hashlib
import json
import os
import sys
from typing import List, Tuple


GITOID_LOCATOR_PREFIX = 'gitoid:blob:sha1:'


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
            gitoids.append((pkg.get('name', '<no-name>'),
                            loc[len(GITOID_LOCATOR_PREFIX):]))
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


def parse_artefact_manifest(manifest_path):
    """Parse the `_bomsh.artefact` manifest written by the bomsh:
    recipe.  Format: a single line, `<absolute-path>\\t<gitoid-hex>`
    -- both fields captured by the recipe AFTER bomtrace3 finishes
    but BEFORE `make sbom` relinks the library.

    Returns (path, recorded_gid).  Raises FileNotFoundError if the
    manifest does not exist (bomsh: skipped artefact discovery, e.g.
    no built library); raises ValueError if the line is malformed."""
    if not os.path.isfile(manifest_path):
        raise FileNotFoundError(
            f'{manifest_path} not produced by `make bomsh`; cannot '
            f'verify gitoid <-> artefact correspondence.  This usually '
            f'means the bomsh enrichment step skipped the artefact-'
            f'discovery loop (no built library).')
    with open(manifest_path) as f:
        line = f.readline().rstrip('\n')
    if not line:
        raise ValueError(
            f'{manifest_path} is empty; bomsh: recipe wrote nothing')
    parts = line.split('\t')
    if len(parts) != 2 or not all(parts):
        raise ValueError(
            f'{manifest_path}: expected "<path>\\t<gitoid>", got {line!r}.  '
            f'Re-run `make bomsh` against an up-to-date Makefile.am.')
    return parts[0], parts[1]


def check_artefact_correspondence(spdx_gitoids, recorded_gid,
                                  package_name_substr='wolfssl'):
    """(C) The gitoid bomsh recorded for the traced library matches a
    gitoid externalRef on the wolfSSL SPDX package.  This is the
    bomsh<->SPDX agreement check; it does NOT compare against the
    on-disk file's current bytes (see module docstring).

    Returns (matched, wolfssl_gids).  Raises ValueError if no SPDX
    gitoid is associated with a wolfSSL-named package."""
    wolfssl_gids = [gid for name, gid in spdx_gitoids
                    if package_name_substr in name.lower()]
    if not wolfssl_gids:
        raise ValueError(
            f'no SPDX gitoid externalRef on a package whose name '
            f'contains {package_name_substr!r}; cannot verify '
            f'artefact correspondence')
    return recorded_gid in wolfssl_gids, wolfssl_gids


def verify(spdx_glob, omnibor_dir, artefact_manifest,
           package_name_substr='wolfssl'):
    """Orchestrate the three checks.  Returns (ok: bool, messages:
    List[str]).  `messages` is appended to in success and failure both,
    so callers can log the success line ('OK: N gitoids verified ...')
    even when ok is True."""
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

    try:
        artefact, recorded_gid = parse_artefact_manifest(artefact_manifest)
    except (FileNotFoundError, ValueError) as e:
        messages.append(str(e))
        return False, messages

    try:
        matched, wolfssl_gids = check_artefact_correspondence(
            spdx_gitoids, recorded_gid, package_name_substr)
    except ValueError as e:
        messages.append(str(e))
        return False, messages

    if not matched:
        messages.append(
            f'wolfSSL package SPDX gitoids {wolfssl_gids} do not '
            f'include the gitoid bomsh recorded for the traced '
            f'artefact {artefact} ({recorded_gid}); the SBOM is '
            f'inconsistent with what bomsh actually saw')
        return False, messages

    messages.append(f'OK: {len(spdx_gitoids)} gitoid(s) verified')
    messages.append(f'    objects round-trip: {obj_count} blobs')
    messages.append(
        f'    artefact match: {artefact} -> {recorded_gid} (bomsh-traced)')

    # Diagnostic-only: the on-disk file may have been rewritten since
    # bomsh saw it (the canonical case is `make sbom`'s `make install`
    # step relinking via libtool to fix RPATH).  We do NOT fail on
    # this -- the SBOM<->bomsh agreement above is what matters for
    # the provenance proof -- but surfacing it as a NOTE keeps the
    # divergence visible so it does not silently grow into a
    # bigger gap (e.g. someone adds a strip step that goes unflagged).
    if os.path.isfile(artefact):
        on_disk = gitoid_sha1(artefact)
        if on_disk != recorded_gid:
            messages.append(
                f'NOTE: on-disk {artefact} now has gitoid {on_disk}, '
                f'but bomsh recorded {recorded_gid}.  This is expected '
                f'when `make sbom` runs `make install` (libtool relinks '
                f'src/.libs/lib*.so* in place to fix RPATH).  The SBOM '
                f'attests to the bomsh-traced bytes; if you need it to '
                f'attest to the *installed* bytes, the bomsh: recipe '
                f'must trace `make install` too.')
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
    parser.add_argument('--artefact-manifest', default='_bomsh.artefact',
                        help='Path to the file containing the artefact '
                             'path that bomsh: traced (default: %(default)s)')
    parser.add_argument('--package-name-substr', default='wolfssl',
                        help='Case-insensitive substring used to identify '
                             'the wolfSSL SPDX package among any others in '
                             'the document (default: %(default)s)')
    args = parser.parse_args()

    ok, messages = verify(args.spdx_glob, args.omnibor_dir,
                          args.artefact_manifest, args.package_name_substr)
    for line in messages:
        print(line, file=sys.stderr if not ok else sys.stdout)
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    main()
