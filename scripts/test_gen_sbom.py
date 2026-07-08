#!/usr/bin/env python3
"""Unit tests for the helpers in scripts/gen-sbom.

Run from the repo root:

    python3 -m unittest scripts/test_gen_sbom.py

These tests cover the pure logic in gen-sbom (license expression handling,
deterministic UUID derivation, SOURCE_DATE_EPOCH timestamp parsing).  They
intentionally avoid touching the filesystem-heavy paths (sha256_file,
parse_options_h, pkg-config) which are exercised end-to-end by the
integration tests in .github/workflows/sbom.yml.
"""

import importlib.util
import json
import os
import pathlib
import re
import tempfile
import unittest
import uuid
from datetime import datetime, timedelta, timezone
from importlib.machinery import SourceFileLoader


def _load_gen_sbom():
    """Load gen-sbom (no .py extension) as a module under the name 'gs'.
    spec_from_file_location infers the loader from the suffix; gen-sbom has
    none, so we hand it a SourceFileLoader explicitly."""
    here = pathlib.Path(__file__).resolve().parent
    target = here / 'gen-sbom'
    if not target.is_file():
        raise FileNotFoundError(
            f"expected gen-sbom alongside this test file at {target}"
        )
    loader = SourceFileLoader('gs', str(target))
    spec = importlib.util.spec_from_loader('gs', loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


gs = _load_gen_sbom()


class TestIsSimpleSpdxId(unittest.TestCase):
    def test_listed_ids_are_simple(self):
        for spdx in ('Apache-2.0', 'MIT', 'GPL-3.0-or-later',
                     'GPL-2.0-only', 'BSD-3-Clause', 'CC0-1.0', 'Zlib'):
            self.assertTrue(gs.is_simple_spdx_id(spdx),
                            f"{spdx!r} should be simple")

    def test_license_refs_are_not_simple(self):
        self.assertFalse(gs.is_simple_spdx_id('LicenseRef-wolfSSL-Commercial'))
        self.assertFalse(gs.is_simple_spdx_id('LicenseRef-Foo'))

    def test_compound_expressions_are_not_simple(self):
        self.assertFalse(gs.is_simple_spdx_id('GPL-3.0-only OR MIT'))
        self.assertFalse(gs.is_simple_spdx_id(
            'Apache-2.0 AND LicenseRef-Foo'))
        self.assertFalse(gs.is_simple_spdx_id('(MIT OR Apache-2.0)'))

    def test_noassertion_is_not_simple(self):
        self.assertFalse(gs.is_simple_spdx_id('NOASSERTION'))


class TestExtractLicenseRefs(unittest.TestCase):
    def test_no_refs(self):
        self.assertEqual(gs.extract_license_refs('Apache-2.0'), [])
        self.assertEqual(gs.extract_license_refs('GPL-3.0-only OR MIT'), [])
        self.assertEqual(gs.extract_license_refs(''), [])
        self.assertEqual(gs.extract_license_refs(None), [])

    def test_single_ref(self):
        self.assertEqual(
            gs.extract_license_refs('LicenseRef-X'), ['LicenseRef-X'])
        self.assertEqual(
            gs.extract_license_refs('LicenseRef-wolfSSL-Commercial'),
            ['LicenseRef-wolfSSL-Commercial'])

    def test_multiple_refs_are_sorted_and_deduped(self):
        self.assertEqual(
            gs.extract_license_refs(
                'Apache-2.0 OR LicenseRef-B AND LicenseRef-A'),
            ['LicenseRef-A', 'LicenseRef-B'])
        self.assertEqual(
            gs.extract_license_refs(
                'LicenseRef-X OR LicenseRef-X AND LicenseRef-X'),
            ['LicenseRef-X'])


class TestCdxLicenseBlock(unittest.TestCase):
    def test_listed_id_uses_id_form(self):
        self.assertEqual(
            gs.cdx_license_block('Apache-2.0', None),
            [{'license': {'id': 'Apache-2.0'}}])
        self.assertEqual(
            gs.cdx_license_block('GPL-3.0-or-later', None),
            [{'license': {'id': 'GPL-3.0-or-later'}}])

    def test_single_ref_with_text_uses_name_and_text(self):
        block = gs.cdx_license_block('LicenseRef-Foo', 'BODY')
        self.assertEqual(len(block), 1)
        lic = block[0]['license']
        self.assertEqual(lic['name'], 'LicenseRef-Foo')
        self.assertEqual(lic['text']['content'], 'BODY')
        self.assertEqual(lic['text']['contentType'], 'text/plain')
        self.assertNotIn('id', lic)

    def test_single_ref_without_text_omits_text_field(self):
        block = gs.cdx_license_block('LicenseRef-Foo', None)
        lic = block[0]['license']
        self.assertEqual(lic['name'], 'LicenseRef-Foo')
        self.assertNotIn('text', lic)

    def test_compound_uses_expression(self):
        # Per CDX 1.6 schema, compound SPDX expressions go into `expression`.
        # We must NOT use `id` (only listed IDs allowed) nor `name` (single
        # licence only).
        self.assertEqual(
            gs.cdx_license_block('GPL-3.0-only OR LicenseRef-Foo', 'X'),
            [{'expression': 'GPL-3.0-only OR LicenseRef-Foo'}])
        self.assertEqual(
            gs.cdx_license_block('GPL-3.0-only AND MIT', None),
            [{'expression': 'GPL-3.0-only AND MIT'}])

    def test_noassertion_uses_name_not_expression(self):
        # NOASSERTION is a reserved SPDX literal, not a parseable SPDX
        # expression - shoving it into `expression` makes some CDX
        # validators choke when they try to parse it.
        self.assertEqual(
            gs.cdx_license_block('NOASSERTION', None),
            [{'license': {'name': 'NOASSERTION'}}])
        self.assertEqual(
            gs.cdx_license_block('NOASSERTION', 'ignored'),
            [{'license': {'name': 'NOASSERTION'}}])


class TestBuildExtractedLicensingInfos(unittest.TestCase):
    def test_no_refs_returns_none(self):
        self.assertIsNone(
            gs.build_extracted_licensing_infos('Apache-2.0', None))
        self.assertIsNone(
            gs.build_extracted_licensing_infos('GPL-3.0-only AND MIT', None))

    def test_single_ref_with_text(self):
        infos = gs.build_extracted_licensing_infos(
            'LicenseRef-wolfSSL-Commercial', 'BODY')
        self.assertEqual(len(infos), 1)
        self.assertEqual(infos[0]['licenseId'],
                         'LicenseRef-wolfSSL-Commercial')
        self.assertEqual(infos[0]['extractedText'], 'BODY')
        self.assertIn('name', infos[0])

    def test_placeholder_when_text_missing(self):
        infos = gs.build_extracted_licensing_infos('LicenseRef-X', None)
        self.assertEqual(len(infos), 1)
        # Placeholder must mention how to fix it so reviewers/auditors who
        # inspect the SBOM know what's wrong.
        text = infos[0]['extractedText']
        self.assertIn('--license-text', text)

    def test_multiple_refs_each_get_entry(self):
        infos = gs.build_extracted_licensing_infos(
            'LicenseRef-A OR LicenseRef-B', 'BODY')
        self.assertEqual(
            sorted(i['licenseId'] for i in infos),
            ['LicenseRef-A', 'LicenseRef-B'])
        for i in infos:
            self.assertEqual(i['extractedText'], 'BODY')


class TestDerivedUuid(unittest.TestCase):
    def test_deterministic(self):
        a = gs.derived_uuid('wolfssl', '5.9.1', 'package')
        b = gs.derived_uuid('wolfssl', '5.9.1', 'package')
        self.assertEqual(a, b)

    def test_different_inputs_diverge(self):
        self.assertNotEqual(
            gs.derived_uuid('wolfssl', '5.9.1', 'package'),
            gs.derived_uuid('wolfssl', '5.9.2', 'package'))
        self.assertNotEqual(
            gs.derived_uuid('wolfssl', '5.9.1', 'package'),
            gs.derived_uuid('wolfssl', '5.9.1', 'serial'))

    def test_returns_valid_uuid_string(self):
        s = gs.derived_uuid('a', 'b')
        # Will raise if not a valid UUID.
        parsed = uuid.UUID(s)
        self.assertEqual(str(parsed), s)

    def test_separator_does_not_alias_inputs(self):
        # If the helper joined parts on a printable character (e.g. '/'),
        # then ('a/b', 'c') would collide with ('a', 'b/c').  NUL is not
        # representable in any of the call-site inputs, so the join must
        # be unambiguous.  Regression guard for that contract.
        self.assertNotEqual(
            gs.derived_uuid('a/b', 'c'),
            gs.derived_uuid('a', 'b/c'))
        self.assertNotEqual(
            gs.derived_uuid('a-b', 'c'),
            gs.derived_uuid('a', 'b-c'))


class TestBuildTimestamp(unittest.TestCase):
    def setUp(self):
        self._saved = os.environ.get('SOURCE_DATE_EPOCH')

    def tearDown(self):
        if self._saved is None:
            os.environ.pop('SOURCE_DATE_EPOCH', None)
        else:
            os.environ['SOURCE_DATE_EPOCH'] = self._saved

    def test_honors_source_date_epoch(self):
        os.environ['SOURCE_DATE_EPOCH'] = '1700000000'
        dt, ts = gs.build_timestamp()
        self.assertEqual(dt.year, 2023)
        self.assertEqual(ts, '2023-11-14T22:13:20Z')

    def test_two_calls_with_same_sde_match(self):
        os.environ['SOURCE_DATE_EPOCH'] = '1700000000'
        _, t1 = gs.build_timestamp()
        _, t2 = gs.build_timestamp()
        self.assertEqual(t1, t2)

    def test_invalid_sde_falls_back_to_now(self):
        os.environ['SOURCE_DATE_EPOCH'] = 'not-a-number'
        dt, ts = gs.build_timestamp()
        # Shape check.
        self.assertRegex(
            ts, r'\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z')
        # Freshness check: regression guard against a future change that
        # accidentally hard-codes the fallback (e.g. epoch zero).  Five
        # seconds is generous for a unit test on slow runners.
        self.assertLess(
            abs(dt - datetime.now(tz=timezone.utc)),
            timedelta(seconds=5))

    def test_no_sde_is_current_utc(self):
        os.environ.pop('SOURCE_DATE_EPOCH', None)
        dt, ts = gs.build_timestamp()
        self.assertRegex(
            ts, r'\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z')
        self.assertLess(
            abs(dt - datetime.now(tz=timezone.utc)),
            timedelta(seconds=5))


class TestLoadLicenseText(unittest.TestCase):
    def test_empty_path_returns_none(self):
        self.assertIsNone(gs.load_license_text(''))
        self.assertIsNone(gs.load_license_text(None))

    def test_real_file(self):
        with tempfile.NamedTemporaryFile('w', suffix='.txt',
                                         delete=False) as f:
            f.write('LICENCE BODY\n')
            path = f.name
        try:
            self.assertEqual(gs.load_license_text(path), 'LICENCE BODY\n')
        finally:
            os.unlink(path)

    def test_missing_file_exits(self):
        with self.assertRaises(SystemExit):
            gs.load_license_text('/no/such/path/please.txt')


class TestDetectLicense(unittest.TestCase):
    """detect_license decides the SPDX licenseConcluded / licenseDeclared
    that wolfSSL's SBOM advertises.  A regression here silently flips
    the licence obligations a downstream integrator parses out of the
    SBOM (e.g. GPLv2-or-later misreported as GPLv2-only narrows the
    permitted upgrade path; GPLv3 misreported as GPLv2 entirely
    misstates compatibility with GPLv2-only third-party code).

    Independent oracle: the SPDX licence-list short identifiers
    (https://spdx.org/licenses/), determined for each fixture by
    reading the GPL version stated in the prose and whether 'or later'
    / 'or any later version' wording appears within 100 characters of
    the version mention.  No fixture is round-tripped through
    detect_license to derive its own oracle."""

    def _detect(self, body):
        with tempfile.NamedTemporaryFile('w', suffix='.txt',
                                         delete=False) as f:
            f.write(body)
            path = f.name
        try:
            return gs.detect_license(path)
        finally:
            os.unlink(path)

    def test_gplv2_only(self):
        # Prose mentions GPLv2 with no 'or later' clause.  Oracle:
        # SPDX 'GPL-2.0-only'.
        self.assertEqual(
            self._detect(
                'This program is licensed under the GNU General Public '
                'License version 2.\n'
                'See COPYING for the full text.\n'),
            'GPL-2.0-only')

    def test_gplv2_or_later_any_form(self):
        # 'or any later' immediately after the version mention.
        # Oracle: SPDX 'GPL-2.0-or-later'.
        self.assertEqual(
            self._detect(
                'Licensed under the GNU General Public License version 2, '
                'or any later version.\n'),
            'GPL-2.0-or-later')

    def test_gplv2_or_later_canonical_fsf_preamble(self):
        # The canonical FSF GPL preamble phrase, used verbatim in
        # millions of upstream COPYING files:
        #
        #   'either version N of the License, or (at your option)
        #    any later version.'
        #
        # An earlier regex (`or\s+(any\s+)?later`) failed to match
        # this because the parenthetical '(at your option)'
        # interjects between 'or' and 'any later', so wolfssl-1zj.24
        # silently mis-detected the preamble as GPLv2-only.  Oracle:
        # SPDX 'GPL-2.0-or-later'.
        self.assertEqual(
            self._detect(
                'This program is free software: you can redistribute it '
                'and/or modify it under the terms of the GNU General '
                'Public License version 2, or (at your option) any '
                'later version.\n'),
            'GPL-2.0-or-later')

    def test_gplv3_or_later_canonical_fsf_preamble(self):
        # Same regression guard for GPLv3.
        self.assertEqual(
            self._detect(
                'Licensed under the GNU General Public License version 3, '
                'or (at your option) any later version.\n'),
            'GPL-3.0-or-later')

    def test_gplv2_or_later_short_form(self):
        # 'or later' (without 'any') also matches the regex; this
        # variant appears in some upstream COPYING files.  Oracle:
        # 'GPL-2.0-or-later'.
        self.assertEqual(
            self._detect(
                'Licensed under the GNU General Public License version 2 '
                'or later.\n'),
            'GPL-2.0-or-later')

    def test_gplv3_only(self):
        self.assertEqual(
            self._detect(
                'Released under the terms of the GNU General Public '
                'License version 3.\n'),
            'GPL-3.0-only')

    def test_gplv3_or_later(self):
        self.assertEqual(
            self._detect(
                'Released under the terms of the GNU General Public '
                'License version 3, or any later version.\n'),
            'GPL-3.0-or-later')

    def test_gplv3_abbreviation_only(self):
        # LICENSING that uses only the "GPLv3" abbreviation, with no
        # canonical "GNU General Public License version 3" long form.
        # This is exactly wolfSSH's LICENSING shape, which previously
        # fell back to NOASSERTION.  Oracle: 'GPL-3.0-only'.
        self.assertEqual(
            self._detect(
                'wolfExample is either licensed for use under the GPLv3 '
                'or a standard commercial license.\n'),
            'GPL-3.0-only')

    def test_gplv2_abbreviation_only(self):
        # Same abbreviation path for version 2.  Oracle: 'GPL-2.0-only'.
        self.assertEqual(
            self._detect('Distributed under the GPLv2.\n'),
            'GPL-2.0-only')

    def test_gplv3_plus_abbreviation_is_or_later(self):
        # The "+" suffix on the abbreviated form (GPLv3+) denotes the
        # or-later variant.  Oracle: 'GPL-3.0-or-later'.
        self.assertEqual(
            self._detect('Licensed under GPLv3+ terms.\n'),
            'GPL-3.0-or-later')

    def test_gplv2_abbreviation_or_later_prose(self):
        # Abbreviated form followed by an explicit "or later" clause in
        # prose (no "+") also promotes to or-later.  Oracle:
        # 'GPL-2.0-or-later'.
        self.assertEqual(
            self._detect('Available under GPLv2 or later.\n'),
            'GPL-2.0-or-later')

    def test_real_wolfssh_licensing_shape_is_gpl3_only(self):
        # Regression guard for the exact wolfSSH LICENSING wording: the
        # "or a standard commercial license" clause after the GPLv3
        # abbreviation must NOT be mistaken for an "or later" grant.
        self.assertEqual(
            self._detect(
                '\nwolfSSH is either licensed for use under the GPLv3 or a '
                'standard commercial\nlicense. For our users who cannot use '
                'wolfSSH under GPLv3, a commercial license\nto wolfSSH is '
                'available.\n'),
            'GPL-3.0-only')

    def test_case_insensitive(self):
        # The regex is case-insensitive for both the GPL header line
        # and the 'or later' clause.  Real-world COPYING files use
        # mixed cases ('GNU GENERAL PUBLIC LICENSE Version 2'); a
        # case-sensitive regression here would silently emit None.
        self.assertEqual(
            self._detect(
                'GNU GENERAL PUBLIC LICENSE Version 2\n'
                'Licensee may redistribute under GPLv2 OR LATER.\n'),
            'GPL-2.0-or-later')

    def test_or_later_outside_100_byte_excerpt_does_not_match(self):
        # The 'or later' search is bounded to the 100 chars
        # immediately following the version mention.  An 'or later'
        # phrase appearing in unrelated boilerplate further down the
        # file MUST NOT promote a GPLv2-only declaration to
        # GPLv2-or-later.  This is the regression Mark called out in
        # the review: "someone reworks the regex ... and breaks the
        # GPLv2-or-later detection."
        body = (
            'Licensed under the GNU General Public License version 2.\n'
            + ('Filler not relevant to the license clause. ' * 5)
            + '\nMay be useful or later modified by users.\n'
        )
        self.assertEqual(self._detect(body), 'GPL-2.0-only')

    def test_no_gpl_mention_returns_none_with_warning(self):
        import io, contextlib
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result = self._detect(
                'Copyright (c) 2026 Example Corp.\n'
                'Licensed under the MIT License.\n'
                'Permission is hereby granted, free of charge, ...\n')
        self.assertIsNone(result)
        # Warning must mention the file path so an operator running
        # `make sbom` can see which file was unparsable.
        self.assertIn('no GPL version found', stderr.getvalue())

    def test_missing_file_returns_none_with_warning(self):
        import io, contextlib
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            result = gs.detect_license('/no/such/license/please.txt')
        self.assertIsNone(result)
        self.assertIn('cannot read license file', stderr.getvalue())

    def test_real_wolfssl_licensing_is_gpl3_only(self):
        # Regression guard, not an oracle: lock down the SPDX ID that
        # the shipped LICENSING file produces today.  If wolfSSL ever
        # changes the headline licence in LICENSING, this test must
        # be updated in the same commit so the SBOM emission change
        # does not slip in unreviewed.  The "version 3" mention is
        # first in the file; the 100-char excerpt that follows is
        # `(\u201cGPLv3\u201d) with\nthe following exception: ...`,
        # which contains no 'or later' clause - hence GPL-3.0-only.
        here = pathlib.Path(__file__).resolve().parent.parent
        licensing = here / 'LICENSING'
        if not licensing.is_file():
            self.skipTest(f'LICENSING fixture not found at {licensing}')
        self.assertEqual(
            gs.detect_license(str(licensing)), 'GPL-3.0-only',
            'real wolfSSL LICENSING no longer maps to GPL-3.0-only; '
            'update this regression guard and audit the SBOM '
            'licenseConcluded / licenseDeclared change')


class TestSha256File(unittest.TestCase):
    def test_real_file_hashes_to_known_value(self):
        # Empty file's SHA-256 is well-known; sanity-checks the chunked
        # read path produces the same digest as a one-shot hash.
        with tempfile.NamedTemporaryFile('wb', delete=False) as f:
            path = f.name
        try:
            empty_sha256 = ('e3b0c44298fc1c149afbf4c8996fb924'
                            '27ae41e4649b934ca495991b7852b855')
            self.assertEqual(gs.sha256_file(path), empty_sha256)
        finally:
            os.unlink(path)

    def test_missing_file_exits_cleanly(self):
        # Regression guard: gen-sbom must surface a missing --lib path as
        # a clean non-zero exit, not an unhandled OSError, so `make sbom`
        # fails fast with a useful message instead of a Python traceback.
        with self.assertRaises(SystemExit):
            gs.sha256_file('/no/such/library/please.so')

    def test_chunked_read_path_matches_one_shot(self):
        # The chunked iter(f.read(65536), b'') path in sha256_file is
        # what runs for the real wolfSSL library (.so/.a, multi-MB).
        # The empty-file vector above never executes the loop body at
        # all (size=0).  An off-by-one or chunk-boundary regression
        # would slip through unless we exercise a buffer that crosses
        # the 65536-byte boundary.  Independent oracle: hashlib's
        # one-shot hash on the same bytes.
        import hashlib
        body = (b'A' * 70000) + (b'B' * 1000) + b'tail'
        with tempfile.NamedTemporaryFile('wb', delete=False) as f:
            f.write(body)
            path = f.name
        try:
            expected = hashlib.sha256(body).hexdigest()
            self.assertEqual(gs.sha256_file(path), expected)
        finally:
            os.unlink(path)


class TestParseOptionsH(unittest.TestCase):
    def _parse(self, body):
        with tempfile.NamedTemporaryFile('w', suffix='.h',
                                         delete=False) as f:
            f.write(body)
            path = f.name
        try:
            return gs.parse_options_h(path)
        finally:
            os.unlink(path)

    def test_parses_defines_sorted_and_deduped(self):
        pairs = self._parse(
            "/* fake options.h */\n"
            "#define HAVE_BAR\n"
            "#define HAVE_AAA 1\n"
            "#define HAVE_FOO 42\n"
        )
        names = [k for k, _ in pairs]
        self.assertEqual(names, sorted(set(names)))
        self.assertEqual(dict(pairs)['HAVE_AAA'], '1')
        self.assertEqual(dict(pairs)['HAVE_FOO'], '42')
        self.assertEqual(dict(pairs)['HAVE_BAR'], '')

    def test_strips_trailing_block_comment(self):
        # Regression: an earlier version captured the comment text into
        # the value, polluting the SBOM build properties.
        pairs = dict(self._parse("#define HAVE_FOO 42 /* always */\n"))
        self.assertEqual(pairs['HAVE_FOO'], '42')

    def test_strips_trailing_line_comment(self):
        pairs = dict(self._parse("#define HAVE_FOO 42 // always\n"))
        self.assertEqual(pairs['HAVE_FOO'], '42')

    def test_strips_comment_from_valueless_define(self):
        pairs = dict(self._parse("#define HAVE_BAR  /* set elsewhere */\n"))
        self.assertEqual(pairs['HAVE_BAR'], '')

    def test_preserves_url_in_string_literal(self):
        # Regression guard: an earlier comment-stripper used
        # `re.split(r'/\*|//', raw, maxsplit=1)[0]`, which truncated
        # autoconf-generated PACKAGE_URL / PACKAGE_BUGREPORT defines
        # at the first `//` inside the URL.  Both ended up as
        # `"https:` in the SBOM build properties, falsely showing
        # PACKAGE_URL drifting between releases when nothing changed.
        pairs = dict(self._parse(
            '#define PACKAGE_URL "https://www.wolfssl.com"\n'
            '#define PACKAGE_BUGREPORT '
            '"https://github.com/wolfssl/wolfssl/issues"\n'
        ))
        self.assertEqual(pairs['PACKAGE_URL'],
                         '"https://www.wolfssl.com"')
        self.assertEqual(pairs['PACKAGE_BUGREPORT'],
                         '"https://github.com/wolfssl/wolfssl/issues"')

    def test_strips_comment_after_string_literal(self):
        # Companion to test_preserves_url_in_string_literal: confirm
        # the stripper still works when a comment legitimately follows
        # a string literal.  A regression that disabled stripping
        # entirely (the simplest "fix" for the URL bug) would let
        # comment text leak into the SBOM.
        pairs = dict(self._parse(
            '#define PACKAGE_URL "https://www.wolfssl.com" /* upstream */\n'
        ))
        self.assertEqual(pairs['PACKAGE_URL'],
                         '"https://www.wolfssl.com"')

    def test_preserves_block_comment_inside_string_literal(self):
        # `/*` inside a string literal must not start a comment.
        pairs = dict(self._parse('#define WEIRD "a/*b*/c"\n'))
        self.assertEqual(pairs['WEIRD'], '"a/*b*/c"')

    def test_handles_escaped_quote_in_string_literal(self):
        # An escaped `\"` inside a string literal must not be mistaken
        # for the closing quote; otherwise a comment-marker that
        # follows would be incorrectly treated as outside the string.
        pairs = dict(self._parse(
            '#define EMBEDDED_QUOTE "a\\"b//c" /* tail */\n'))
        self.assertEqual(pairs['EMBEDDED_QUOTE'], '"a\\"b//c"')

    def test_dedup_keeps_last_assignment(self):
        # Last assignment wins (matches C preprocessor semantics for
        # duplicate #defines after redefinition).
        pairs = dict(self._parse(
            "#define HAVE_X 1\n"
            "#define HAVE_X 2\n"
        ))
        self.assertEqual(pairs['HAVE_X'], '2')

    def test_filters_compiler_internals_from_dm_e_dump(self):
        # The no-pcpp escape hatch (`$CC -dM -E -include settings.h ...`)
        # produces a defines file containing hundreds of host/compiler
        # macros - on macOS it includes the entire Apple
        # TargetConditionals family, on Linux it includes __GLIBC_*,
        # everywhere it includes the C compiler's __INT_*_MAX__ /
        # __SSE*__ / __VERSION__ family.  parse_options_h must drop them
        # so the SBOM reflects wolfSSL configuration, not the build
        # host, and is reproducible across hosts.
        pairs = dict(self._parse(
            "/* simulated `clang -dM -E` dump on macOS */\n"
            "#define __VERSION__ \"Homebrew Clang 21.1.4\"\n"
            "#define __APPLE__ 1\n"
            "#define __MACH__ 1\n"
            "#define __SSE2__ 1\n"
            "#define __INT_FAST32_MAX__ 2147483647\n"
            "#define __clang_major__ 21\n"
            "#define _LP64 1\n"
            "#define TARGET_OS_MAC 1\n"
            "#define TARGET_OS_OSX 1\n"
            "#define TARGET_OS_LINUX 0\n"
            "#define TARGET_IPHONE_SIMULATOR 0\n"
            "#define WOLFSSL_OPTIONS_H\n"
            "#define WOLF_CRYPT_SETTINGS_H 1\n"
            "#define HAVE_AESGCM 1\n"
            "#define NO_DES3 1\n"
            "#define WOLFSSL_AES_256 1\n"
        ))
        self.assertEqual(
            set(pairs), {'HAVE_AESGCM', 'NO_DES3', 'WOLFSSL_AES_256'},
            'noise filter let host/compiler macros leak into SBOM')

    def test_real_options_h_template_is_only_a_header_guard(self):
        # Sanity-check that the noise filter handles wolfSSL's own
        # autotools options.h.in: today the template defines exactly
        # one macro - the WOLFSSL_OPTIONS_H header guard - which the
        # filter must drop.  If a future change adds a non-guard macro
        # to options.h.in, this test makes the filter audit explicit.
        here = pathlib.Path(__file__).resolve().parent.parent
        template = here / 'wolfssl' / 'options.h.in'
        if not template.is_file():
            self.skipTest(f'options.h.in fixture not found at {template}')
        body = template.read_text()
        names = re.findall(r'^#define[ \t]+(\w+)', body, re.MULTILINE)
        self.assertIn('WOLFSSL_OPTIONS_H', names,
                      'options.h.in unexpectedly missing its header guard')
        for name in names:
            self.assertTrue(
                gs._is_noise_macro(name),
                f'options.h.in defines {name!r} but the noise filter does '
                'not drop it; either the filter needs widening or '
                'options.h.in now contains a real config macro')

    def test_real_options_h_preserves_autoconf_have_probes(self):
        # An autotools-generated wolfssl/options.h (post-./configure)
        # contains both the WOLFSSL_OPTIONS_H header guard (filtered)
        # and AC_CHECK_HEADER probe results like WOLFSSL_HAVE_ATOMIC_H
        # / WOLFSSL_HAVE_ASSERT_H (must be preserved - they gate
        # `#if defined(...)` branches in wc_port.h and types.h).
        here = pathlib.Path(__file__).resolve().parent.parent
        options_h = here / 'wolfssl' / 'options.h'
        if not options_h.is_file():
            self.skipTest(
                f'no built options.h at {options_h}; run ./configure first')
        names = {k for k, _ in gs.parse_options_h(str(options_h))}
        # WOLFSSL_OPTIONS_H is the header guard for options.h itself
        # and must be filtered out.
        self.assertNotIn(
            'WOLFSSL_OPTIONS_H', names,
            'header guard leaked through into SBOM build properties')
        # The autoconf-detected header-availability flags must survive
        # the filter (regression guard - see
        # TestIsNoiseMacro.test_autoconf_have_header_probes_preserved).
        for cflag in ('WOLFSSL_HAVE_ATOMIC_H', 'WOLFSSL_HAVE_ASSERT_H'):
            if cflag in re.findall(r'^#define[ \t]+(\w+)',
                                   options_h.read_text(), re.MULTILINE):
                self.assertIn(
                    cflag, names,
                    f'{cflag!r} (AC_CHECK_HEADER probe result) was '
                    'incorrectly dropped by the noise filter')


class TestIsNoiseMacro(unittest.TestCase):
    """The shared filter that keeps build-environment artefacts out of
    the SBOM `wolfssl:build:*` properties.  Drives both parse_options_h
    (no-pcpp / autotools) and parse_user_settings (pcpp embedded) to
    the same wolfSSL-only build-property set so the no-pcpp
    `$CC -dM -E` shortcut does not produce host-leaking, non-
    reproducible-across-hosts SBOMs.

    The three macro families this guards against (compiler-reserved,
    Apple TargetConditionals, header guards) are documented in
    `_NOISE_MACRO_RE` in gen-sbom; the assertions below pin each one,
    plus the `_CONFIG_H_TOKENS` carve-out that keeps `*_H`-suffixed
    real configuration flags out of the header-guard branch."""

    def test_compiler_reserved_double_underscore(self):
        # `__*` is reserved-for-implementation per ISO C 7.1.3 and is
        # the bulk of what `clang -dM -E` emits.  Dropping these is
        # what stops `__VERSION__: "Homebrew Clang 21.1.4"` from
        # leaking the developer's laptop into the public SBOM.
        for name in ('__VERSION__', '__SSE2__', '__INT_FAST32_MAX__',
                     '__APPLE__', '__MACH__', '__amd64__',
                     '__GCC_ATOMIC_BOOL_LOCK_FREE',
                     '__clang_major__', '__BLOCKS__',
                     '__OBJC_BOOL_IS_BOOL', '__SIZEOF_LONG__',
                     '__LDBL_DIG__', '__FLT_RADIX__'):
            self.assertTrue(gs._is_noise_macro(name),
                            f'{name!r} should be filtered')

    def test_compiler_reserved_single_underscore_uppercase(self):
        # ISO C 7.1.3 also reserves `_` + uppercase for the
        # implementation; e.g. macOS clang emits `_LP64`, glibc emits
        # `_FORTIFY_SOURCE`.  Same rationale as `__*`.
        for name in ('_LP64', '_FORTIFY_SOURCE', '_LARGEFILE_SOURCE',
                     '_GNU_SOURCE'):
            self.assertTrue(gs._is_noise_macro(name),
                            f'{name!r} should be filtered')

    def test_apple_target_conditionals_filtered(self):
        # `clang -include settings.h -x c /dev/null` on macOS pulls in
        # <TargetConditionals.h>; without this filter a wolfSSL SBOM
        # for an STM32 firmware would falsely show TARGET_OS_MAC=1
        # when generated on a Mac, mis-identifying the target platform
        # to a CRA reviewer.
        for name in ('TARGET_OS_MAC', 'TARGET_OS_OSX', 'TARGET_OS_LINUX',
                     'TARGET_OS_IOS', 'TARGET_OS_EMBEDDED',
                     'TARGET_OS_WIN32', 'TARGET_OS_WINDOWS',
                     'TARGET_IPHONE_SIMULATOR'):
            self.assertTrue(gs._is_noise_macro(name),
                            f'{name!r} (Apple TargetConditionals) should be '
                            'filtered')

    def test_header_guards_filtered(self):
        # Both wolfssl/options.h itself and several internal wolfSSL
        # headers define `WOLFSSL_*_H` / `WOLF_CRYPT_*_H` guards to
        # prevent double inclusion.  These describe "which file was
        # parsed", not configuration choices.
        for name in ('WOLF_CRYPT_SETTINGS_H', 'WOLFSSL_OPTIONS_H',
                     'WOLF_CRYPT_VISIBILITY_H', 'WOLFSSL_USER_SETTINGS_H'):
            self.assertTrue(gs._is_noise_macro(name),
                            f'{name!r} (header guard) should be filtered')

    def test_autoconf_have_header_probes_preserved(self):
        # Regression guard: the `_H$` filter must NOT swallow
        # AC_CHECK_HEADER results from configure.ac.  These live on the
        # wolfSSL CFLAGS as `-DWOLFSSL_HAVE_ATOMIC_H` /
        # `-DWOLFSSL_HAVE_ASSERT_H`, gate `#if defined(...)` branches in
        # wc_port.h / types.h, and so are real configuration flags an
        # auditor or vulnerability scanner needs to see in the SBOM.
        for name in ('WOLFSSL_HAVE_ATOMIC_H', 'WOLFSSL_HAVE_ASSERT_H',
                     'WOLFSSL_HAVE_MLKEM_H', 'HAVE_STDINT_H',
                     'HAVE_SYS_TYPES_H'):
            self.assertFalse(
                gs._is_noise_macro(name),
                f'{name!r} (autoconf AC_CHECK_HEADER probe) must NOT be '
                'filtered - it is real configuration that gates source '
                'code branches')

    def test_no_h_suffixed_disablement_flags_preserved(self):
        # Regression guard for the carve-out specifically.  These flags
        # are set by NETOS / Telit / WOLFSSL_TELIT_M2MB / similar RTOS
        # profiles in wolfssl/wolfcrypt/settings.h to suppress stdlib
        # header inclusion (the firmware ships with vendor stdlib
        # replacements).  They gate real `#if defined(...)` branches:
        #
        #   types.h:398    `#ifndef NO_STDINT_H`
        #   settings.h:3850 `#ifndef NO_STDINT_H`
        #   sp.h:42        `#elif !defined(NO_STDINT_H)`
        #   types.h:2132   `#if !defined(WOLFSSL_NO_ASSERT_H) && ...`
        #
        # An embedded customer who builds against one of these profiles
        # would otherwise get an SBOM that silently omits their
        # stdlib-disablement choices - the exact evidence a CRA reviewer
        # expects to see.
        for name in ('NO_STDINT_H', 'NO_STDLIB_H', 'NO_LIMITS_H',
                     'NO_CTYPE_H', 'NO_STRING_H', 'NO_STDDEF_H',
                     'WOLFSSL_NO_ASSERT_H'):
            self.assertFalse(
                gs._is_noise_macro(name),
                f'{name!r} (NO_*_H disablement flag) must NOT be '
                'filtered - it gates real wolfSSL source branches')

    def test_use_h_suffixed_build_mode_flags_preserved(self):
        # Regression guard for the `USE_` carve-out token.  Gates the
        # flat-vs-tree test/benchmark layout in test.c:165 /
        # benchmark.c:219 / examples/server/server.c:70.  Customers who
        # vendor these example sources select the layout via a `_H`-
        # suffixed flag, so it must survive the filter.
        for name in ('USE_FLAT_TEST_H', 'USE_FLAT_BENCHMARK_H'):
            self.assertFalse(
                gs._is_noise_macro(name),
                f'{name!r} (USE_*_H build-mode toggle) must NOT be '
                'filtered - it gates real wolfSSL source branches')

    def test_real_wolfssl_macros_pass_through(self):
        # The whole point of filtering is to NOT touch real wolfSSL
        # configuration.  If any of these get filtered the SBOM loses
        # auditor-visible build properties that distinguish one
        # wolfSSL configuration from another.
        for name in ('HAVE_AESGCM', 'NO_DES3', 'WOLFSSL_AES_256',
                     'WOLFSSL_USER_SETTINGS', 'WC_RSA_BLINDING',
                     'TFM_ECC256', 'OPENSSL_EXTRA', 'USE_FAST_MATH',
                     'XTIME', 'CUSTOM_RAND_GENERATE', 'FP_MAX_BITS',
                     'BENCH_EMBEDDED', 'SIZEOF_LONG_LONG',
                     'WOLFSSL_SP_NO_DYN_STACK', 'WOLFSSL_SHA512',
                     'NO_FILESYSTEM', 'SINGLE_THREADED'):
            self.assertFalse(gs._is_noise_macro(name),
                             f'{name!r} (real wolfSSL config) should NOT be '
                             'filtered')


class TestDepMetaShape(unittest.TestCase):
    """Lock down the dep-tracking surface so renames/removals don't
    silently regress vulnerability-scanner identifiers in the SBOM.

    These guard against:
      * an external dep being added without a CVE-resolvable identifier
      * a future PR re-introducing the `falcon`/`libxmss`/`liblms`
        keys after they were intentionally removed."""

    def test_only_expected_deps_are_tracked(self):
        # wolfssl is tracked so downstream wolfSSL-stack products (wolfSSH,
        # wolfMQTT, ...) can declare it via --dep-wolfssl; libz/liboqs are
        # wolfSSL's own optional linked deps.
        self.assertEqual(set(gs.DEP_META.keys()),
                         {'wolfssl', 'libz', 'liboqs'})

    def test_wolfssl_dep_entry_describes_the_linked_artefact(self):
        wolfssl = gs.DEP_META['wolfssl']
        self.assertEqual(wolfssl['name'], 'wolfssl')
        self.assertEqual(wolfssl['supplier'], 'wolfSSL Inc.')
        self.assertEqual(wolfssl['pkgconfig'], 'wolfssl')
        # wolfSSL ships under GPLv3 (LICENSING: "version 3 (GPLv3)", no
        # "or later"); the dependency entry must match what
        # detect_license() infers for wolfSSL's own main-package SBOM so a
        # downstream product's wolfssl dep and wolfSSL's self-SBOM agree.
        self.assertEqual(wolfssl['license'], 'GPL-3.0-only')
        self.assertEqual(
            wolfssl['purl']('5.7.4'),
            'pkg:github/wolfSSL/wolfssl@v5.7.4')

    def test_liboqs_entry_describes_the_linked_artefact(self):
        liboqs = gs.DEP_META['liboqs']
        self.assertEqual(liboqs['name'], 'liboqs')
        self.assertEqual(liboqs['supplier'], 'Open Quantum Safe')
        self.assertEqual(liboqs['pkgconfig'], 'liboqs')
        self.assertEqual(
            liboqs['purl']('0.10.0'),
            'pkg:github/open-quantum-safe/liboqs@0.10.0')

    def test_no_stale_dep_keys(self):
        # `falcon` is an algorithm, not a linked package; it must not
        # appear as a dep entry (algorithm enablement lives in
        # build_props parsed from options.h).  `libxmss` and `liblms`
        # were removed upstream; their re-appearance here would
        # silently emit unresolvable identifiers in the SBOM.
        for stale in ('falcon', 'libxmss', 'liblms', 'xmss', 'lms'):
            self.assertNotIn(stale, gs.DEP_META)


class TestEnabledDepsCli(unittest.TestCase):
    """End-to-end test of the argparse plumbing for --dep-* flags.

    Runs gen-sbom in a child process so we exercise the real argparse
    config rather than a re-imported module."""

    def _run(self, *argv):
        import subprocess
        here = pathlib.Path(__file__).resolve().parent
        script = here / 'gen-sbom'
        return subprocess.run(
            ['python3', str(script), *argv],
            capture_output=True, text=True
        )

    def test_dep_liboqs_is_accepted(self):
        result = self._run('--help')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--dep-liboqs', result.stdout)
        self.assertIn('--dep-libz', result.stdout)
        self.assertIn('--dep-wolfssl', result.stdout)

    def test_removed_flags_are_rejected(self):
        # Each of these was either renamed (--dep-falcon -> --dep-liboqs)
        # or removed entirely (--dep-libxmss/--dep-liblms with upstream
        # removal of the libraries).  argparse should reject them as
        # unrecognised, not silently accept them.  We pass the full set
        # of required args (against /dev/null sentinels) so argparse
        # progresses to the unknown-flag check; we never want
        # gen-sbom to actually generate anything in this test.
        required = [
            '--name', 'wolfssl',
            '--version', '0.0.0-test',
            '--lib', '/dev/null',
            '--license-file', '/dev/null',
            '--options-h', '/dev/null',
            '--cdx-out', '/dev/null',
            '--spdx-out', '/dev/null',
        ]
        for stale_flag in ('--dep-falcon', '--dep-libxmss', '--dep-liblms',
                           '--dep-libxmss-root', '--dep-liblms-root',
                           '--git'):
            result = self._run(*required, stale_flag, 'no')
            self.assertNotEqual(result.returncode, 0,
                                f"{stale_flag!r} unexpectedly accepted")
            self.assertIn('unrecognized arguments', result.stderr,
                          f"{stale_flag!r}: {result.stderr!r}")


class TestGitoidBlobSha256(unittest.TestCase):
    """The OmniBOR / git gitoid is content-addressed, well-specified, and
    independently verifiable.  These vectors anchor our implementation
    against the canonical values so a future refactor (e.g. switching
    chunked I/O strategy) cannot silently drift."""

    EMPTY_OID = ('473a0f4c3be8a93681a267e3b1e9a7dcda1185436fe141f7749'
                 '120a303721813')
    HELLO_OID = ('8aec4e4876f854f688d0ebfc8f37598f38e5fd6903cccc850ca'
                 '36591175aeb60')

    def test_empty_blob_matches_canonical_oid(self):
        # The well-known SHA-256 gitoid for an empty blob - matches
        # `git hash-object --object-format=sha256 /dev/null`.
        with tempfile.NamedTemporaryFile('wb', delete=False) as f:
            path = f.name
        try:
            self.assertEqual(gs.gitoid_blob_sha256(path), self.EMPTY_OID)
        finally:
            os.unlink(path)

    def test_hello_matches_canonical_oid(self):
        # `git hash-object --object-format=sha256` on a 5-byte 'hello'
        # blob; equivalently sha256(b'blob 5\x00hello').
        with tempfile.NamedTemporaryFile('wb', delete=False) as f:
            f.write(b'hello')
            path = f.name
        try:
            self.assertEqual(gs.gitoid_blob_sha256(path), self.HELLO_OID)
        finally:
            os.unlink(path)

    def test_chunked_read_path_matches_one_shot(self):
        # The chunked iter-read path is what hashes large source files
        # in real builds; this guards against any off-by-one in the
        # 65536-byte chunk handling.
        import hashlib
        body = (b'A' * 70000) + (b'B' * 1000) + b'tail'
        with tempfile.NamedTemporaryFile('wb', delete=False) as f:
            f.write(body)
            path = f.name
        try:
            expected = hashlib.sha256(
                f'blob {len(body)}\x00'.encode() + body).hexdigest()
            self.assertEqual(gs.gitoid_blob_sha256(path), expected)
        finally:
            os.unlink(path)

    def test_missing_file_exits_cleanly(self):
        with self.assertRaises(SystemExit):
            gs.gitoid_blob_sha256('/no/such/source/please.c')


class TestSrcsMerkleHash(unittest.TestCase):
    """Source-set Merkle hash is the embedded entry point's component
    checksum.  Two contracts matter here:

      1. Order independence: two customers compiling the same files in
         any order get the same hash.  Without this, the SBOM would
         not be portable across build systems with non-deterministic
         file ordering.
      2. Content sensitivity: a one-byte change in any source file
         must change the hash.  Without this, the checksum would
         not detect a tampered build."""

    def _make_files(self, files):
        """files: dict of basename -> bytes contents.
        Returns (tmpdir, list_of_paths)."""
        import tempfile
        tmpdir = tempfile.mkdtemp()
        paths = []
        for name, contents in files.items():
            p = os.path.join(tmpdir, name)
            with open(p, 'wb') as f:
                f.write(contents)
            paths.append(p)
        return tmpdir, paths

    def test_order_independent(self):
        import shutil
        tmpdir, paths = self._make_files({
            'aes.c': b'aes-body',
            'sha.c': b'sha-body',
            'dh.c':  b'dh-body',
        })
        try:
            h1 = gs.srcs_merkle_hash(paths)
            h2 = gs.srcs_merkle_hash(list(reversed(paths)))
            h3 = gs.srcs_merkle_hash(sorted(paths))
            self.assertEqual(h1, h2)
            self.assertEqual(h1, h3)
        finally:
            shutil.rmtree(tmpdir)

    def test_content_change_changes_hash(self):
        import shutil
        tmpdir, paths = self._make_files({
            'aes.c': b'aes-body',
            'sha.c': b'sha-body',
        })
        try:
            h_before = gs.srcs_merkle_hash(paths)
            with open(paths[0], 'ab') as f:
                f.write(b'X')
            h_after = gs.srcs_merkle_hash(paths)
            self.assertNotEqual(h_before, h_after)
        finally:
            shutil.rmtree(tmpdir)

    def test_basename_only_means_path_independent(self):
        """The Merkle hash deliberately uses basename only, not full
        path, so two customers whose wolfSSL trees live at different
        absolute paths get the same hash for the same release."""
        import shutil
        td_a, paths_a = self._make_files({'aes.c': b'aes', 'sha.c': b'sha'})
        td_b, paths_b = self._make_files({'aes.c': b'aes', 'sha.c': b'sha'})
        try:
            self.assertEqual(
                gs.srcs_merkle_hash(paths_a),
                gs.srcs_merkle_hash(paths_b))
        finally:
            shutil.rmtree(td_a)
            shutil.rmtree(td_b)

    def test_missing_file_exits_cleanly(self):
        # Mirrors TestGitoidBlobSha256.test_missing_file_exits_cleanly:
        # silently emitting an SBOM with a stale or zero hash for a
        # missing source would falsify the artefact, so srcs_merkle_hash
        # must propagate the underlying gitoid_blob_sha256 SystemExit.
        with self.assertRaises(SystemExit):
            gs.srcs_merkle_hash(['/no/such/source/please.c'])

    def test_duplicate_basenames_rejected(self):
        # Order independence relies on unique basenames - if two source
        # files in the input collided on basename, sorting on basename
        # would suppress one of them and we would silently lose data.
        # gen-sbom must reject the configuration rather than emit a
        # misleading hash.
        import shutil, tempfile
        td_a = tempfile.mkdtemp()
        td_b = tempfile.mkdtemp()
        try:
            with open(os.path.join(td_a, 'aes.c'), 'wb') as f:
                f.write(b'a')
            with open(os.path.join(td_b, 'aes.c'), 'wb') as f:
                f.write(b'b')
            with self.assertRaises(SystemExit):
                gs.srcs_merkle_hash([
                    os.path.join(td_a, 'aes.c'),
                    os.path.join(td_b, 'aes.c'),
                ])
        finally:
            shutil.rmtree(td_a)
            shutil.rmtree(td_b)


class TestParseUserSettings(unittest.TestCase):
    """Walks a synthetic settings.h + user_settings.h pair through
    parse_user_settings() to confirm:
      * the conditional logic in settings.h is honoured (only the
        taken branch's defines reach the SBOM);
      * pcpp-internal macros (__DATE__/__TIME__/__FILE__/__PCPP__) are
        filtered out (otherwise reproducibility would break);
      * function-like macros are filtered out (they are API surface,
        not build configuration);
      * --user-settings-define KEY=VALUE predefines reach the parser.

    pcpp is a hard prerequisite for these tests, not optional.  An
    earlier revision called self.skipTest on missing pcpp; CI ran the
    suite without pcpp installed and silently skipped all of these
    cases, leaving the embedded entry point unverified at the very
    gate intended to verify it (see review finding wolfssl-1zj.14).
    Now the setUp fails loud with an actionable message."""

    def setUp(self):
        try:
            import pcpp  # noqa: F401
        except ImportError:
            self.fail(
                'pcpp is not installed but is required to test the '
                'standalone embedded entry point '
                '(parse_user_settings).  Install with: '
                "'python3 -m pip install --user pcpp'.  CI installs "
                'this in the unit job; see .github/workflows/sbom.yml.')

    def _run(self, settings_body, user_body, predefines=()):
        import shutil, tempfile
        tmpdir = tempfile.mkdtemp()
        try:
            settings_h = os.path.join(tmpdir, 'settings.h')
            user_h = os.path.join(tmpdir, 'user_settings.h')
            with open(settings_h, 'w') as f:
                f.write(settings_body)
            with open(user_h, 'w') as f:
                f.write(user_body)
            return gs.parse_user_settings(
                settings_h, [tmpdir], list(predefines))
        finally:
            shutil.rmtree(tmpdir)

    def test_conditional_branches_honoured(self):
        # Customer's user_settings.h enables HAVE_X; settings.h then
        # gates HAVE_DEPENDENT on HAVE_X.  Disabled-branch defines
        # must NOT appear.
        settings = (
            '#ifdef WOLFSSL_USER_SETTINGS\n'
            '#include "user_settings.h"\n'
            '#endif\n'
            '#ifdef HAVE_X\n'
            '#define HAVE_DEPENDENT 1\n'
            '#else\n'
            '#define HAVE_DISABLED_BRANCH 1\n'
            '#endif\n'
        )
        user = '#define HAVE_X 1\n'
        pairs = self._run(settings, user, ['WOLFSSL_USER_SETTINGS'])
        names = {k for k, _ in pairs}
        self.assertIn('HAVE_X', names)
        self.assertIn('HAVE_DEPENDENT', names)
        self.assertNotIn('HAVE_DISABLED_BRANCH', names)
        self.assertIn('WOLFSSL_USER_SETTINGS', names)

    def test_pcpp_internal_macros_filtered(self):
        # __DATE__ and __TIME__ are non-deterministic; if they leak
        # into the SBOM, two runs of `make sbom` produce different
        # output and reproducibility CI fails.  __PCPP__ and __FILE__
        # are pcpp implementation detail.
        pairs = self._run('#define HAVE_X 1\n', '', [])
        names = {k for k, _ in pairs}
        for forbidden in ('__DATE__', '__TIME__', '__FILE__', '__PCPP__'):
            self.assertNotIn(forbidden, names,
                             f'{forbidden} leaked into SBOM properties')
        self.assertIn('HAVE_X', names)

    def test_apple_target_conditionals_filtered(self):
        # Defensive: if a customer's user_settings.h transitively
        # includes a macOS system header, the Apple TargetConditionals
        # leak must still be filtered to keep the SBOM target-platform-
        # honest.  pcpp does not auto-include system headers, so this
        # path is uncommon, but the contract with parse_options_h is
        # that the same noise filter applies to both entry points.
        pairs = self._run(
            '#define HAVE_X 1\n'
            '#define TARGET_OS_MAC 1\n'
            '#define TARGET_OS_LINUX 0\n'
            '#define TARGET_IPHONE_SIMULATOR 0\n',
            '', [])
        names = {k for k, _ in pairs}
        self.assertIn('HAVE_X', names)
        for forbidden in ('TARGET_OS_MAC', 'TARGET_OS_LINUX',
                          'TARGET_IPHONE_SIMULATOR'):
            self.assertNotIn(forbidden, names)

    def test_header_guards_filtered(self):
        # wolfSSL's settings.h, visibility.h, etc. all define
        # WOLF_CRYPT_*_H guards; they describe which file was parsed,
        # not configuration choices, and so are filtered out of the
        # SBOM `wolfssl:build:*` property set.
        pairs = self._run(
            '#define WOLF_CRYPT_SETTINGS_H 1\n'
            '#define WOLFSSL_USER_SETTINGS_H 1\n'
            '#define HAVE_X 1\n',
            '', [])
        names = {k for k, _ in pairs}
        self.assertIn('HAVE_X', names)
        self.assertNotIn('WOLF_CRYPT_SETTINGS_H', names)
        self.assertNotIn('WOLFSSL_USER_SETTINGS_H', names)

    def test_no_h_and_use_h_config_flags_preserved(self):
        # End-to-end pcpp regression for the `_CONFIG_H_TOKENS` carve-
        # out: an embedded customer's user_settings.h that disables
        # stdint/stdlib (NETOS / Telit / similar profile) must produce
        # an SBOM that records the disablements.  Mirrors the
        # equivalent unit assertion in TestIsNoiseMacro but exercises
        # the full pcpp + filter pipeline customers actually use.
        user = (
            '#define HAVE_X 1\n'
            '#define NO_STDINT_H 1\n'
            '#define NO_STDLIB_H 1\n'
            '#define WOLFSSL_NO_ASSERT_H 1\n'
            '#define USE_FLAT_TEST_H 1\n'
            '#define USE_FLAT_BENCHMARK_H 1\n'
        )
        settings = (
            '#ifdef WOLFSSL_USER_SETTINGS\n'
            '#include "user_settings.h"\n'
            '#endif\n'
        )
        pairs = self._run(settings, user, ['WOLFSSL_USER_SETTINGS'])
        names = {k for k, _ in pairs}
        for required in ('HAVE_X', 'NO_STDINT_H', 'NO_STDLIB_H',
                         'WOLFSSL_NO_ASSERT_H', 'USE_FLAT_TEST_H',
                         'USE_FLAT_BENCHMARK_H'):
            self.assertIn(
                required, names,
                f'{required!r} (real wolfSSL config) was filtered out '
                'of the SBOM - the noise filter is over-aggressive')

    def test_pcpp_error_directive_is_fatal(self):
        # An `#error` firing inside settings.h or a transitively
        # included header is a hard build failure for the C compiler;
        # gen-sbom must mirror that semantics.  pcpp signals this via
        # pp.return_code (it does NOT raise), which is easy to swallow
        # silently and emit a partial SBOM if not checked.  This test
        # pins the fail-fast contract: any #error must produce a
        # SystemExit, not a partial SBOM.  We deliberately do NOT
        # pin the exact error wording; the contract is fail-fast,
        # not the message's phrasing.
        settings = (
            '#ifdef WOLFSSL_USER_SETTINGS\n'
            '#include "user_settings.h"\n'
            '#endif\n'
            '#define HAVE_X 1\n'
        )
        user = '#error "this configuration is unsupported"\n'
        with self.assertRaises(SystemExit) as ctx:
            self._run(settings, user, ['WOLFSSL_USER_SETTINGS'])
        # Guard against an empty-message regression that would still
        # technically satisfy the SystemExit contract but leave the
        # operator with no idea why their build broke.  Any
        # reasonably useful message will exceed this threshold.
        msg = str(ctx.exception)
        self.assertGreater(len(msg), 20,
                           f'gen-sbom exit message too short to be '
                           f'actionable: {msg!r}')

    def test_function_like_macros_filtered(self):
        # Function-like macros are API surface, not build
        # configuration; their post-expansion body would also break
        # reproducibility under pcpp token-render whitespace drift.
        pairs = self._run(
            '#define HAVE_X 1\n'
            '#define WC_BITS_TO_BYTES(x) (((x) + 7) >> 3)\n',
            '', [])
        names = {k for k, _ in pairs}
        self.assertIn('HAVE_X', names)
        self.assertNotIn('WC_BITS_TO_BYTES', names)

    def test_predefine_with_value(self):
        pairs = self._run(
            '#if VERSION_MAJOR >= 5\n#define ONLY_NEW 1\n#endif\n',
            '', ['VERSION_MAJOR=5'])
        names = {k for k, _ in pairs}
        self.assertIn('ONLY_NEW', names)
        self.assertIn('VERSION_MAJOR', names)

    def test_returns_sorted_pairs_like_parse_options_h(self):
        # The downstream code path is shared between options.h and
        # user_settings.h; both producers must return the exact same
        # shape (sorted list of (name, value) tuples).  A drift here
        # would surface as a mystery diff between the two paths.
        pairs = self._run(
            '#define HAVE_Z 1\n#define HAVE_A 1\n#define HAVE_M 1\n',
            '', [])
        names = [k for k, _ in pairs]
        self.assertEqual(names, sorted(names))


class TestDepVersionOverride(unittest.TestCase):
    """--dep-version is the embedded path's substitute for pkg-config:
    cross-compile hosts have no pkg-config for the target, so the
    customer must supply the linked dep version explicitly.  Without
    this flag a baremetal SBOM that reports `--dep-libz yes` would
    silently emit `versionInfo: NOASSERTION` and lose CVE-tracking
    fidelity for libz."""

    def test_explicit_override_wins_over_pkgconfig(self):
        original = gs.pkgconfig_version
        try:
            gs.pkgconfig_version = lambda *_a, **_k: '99.99.99'
            self.assertEqual(
                gs.dep_version('libz', {'libz': '1.3.1'}),
                '1.3.1')
        finally:
            gs.pkgconfig_version = original

    def test_no_override_falls_back_to_pkgconfig(self):
        original = gs.pkgconfig_version
        try:
            gs.pkgconfig_version = lambda *_a, **_k: '1.0.0'
            self.assertEqual(gs.dep_version('libz'), '1.0.0')
            self.assertEqual(gs.dep_version('libz', {}), '1.0.0')
            self.assertEqual(
                gs.dep_version('libz', {'liboqs': '0.0'}), '1.0.0')
        finally:
            gs.pkgconfig_version = original

    def test_parse_overrides_rejects_unknown_keys(self):
        with self.assertRaises(SystemExit):
            gs._parse_dep_version_overrides(['libssl=3.0.0'])

    def test_parse_overrides_rejects_malformed(self):
        with self.assertRaises(SystemExit):
            gs._parse_dep_version_overrides(['libz'])

    def test_parse_overrides_accepts_known_keys(self):
        out = gs._parse_dep_version_overrides([
            'libz=1.3.1', 'liboqs=0.10.0',
        ])
        self.assertEqual(out, {'libz': '1.3.1', 'liboqs': '0.10.0'})


class TestResolveDepVersionsSingleShot(unittest.TestCase):
    """Each enabled dependency's version must be resolved exactly once (in
    main, via _resolve_dep_versions), not once per output format.  Without
    the precompute, generate_cdx and generate_spdx each call dep_version()
    independently, so a default --with-libz --with-liboqs build would shell
    out to `pkg-config --modversion` four times (2 deps x CDX+SPDX) instead
    of twice -- and the two documents could disagree if pkg-config were ever
    non-deterministic.  These tests lock that single-resolution behaviour in."""

    def test_pkgconfig_called_once_per_dep(self):
        calls = []
        original = gs.pkgconfig_version
        try:
            gs.pkgconfig_version = lambda pkg: (calls.append(pkg), '1.2.3')[1]
            overrides = gs._resolve_dep_versions(['libz', 'liboqs'], {})
            self.assertEqual(len(calls), 2)
            self.assertEqual(overrides['libz'], '1.2.3')
            self.assertEqual(overrides['liboqs'], '1.2.3')
            # The emitters reuse the cached value: a later dep_version() for
            # an already-resolved key must not re-invoke pkg-config.
            gs.dep_version('libz', overrides)
            gs.dep_version('liboqs', overrides)
            self.assertEqual(len(calls), 2)
        finally:
            gs.pkgconfig_version = original

    def test_user_override_skips_pkgconfig(self):
        calls = []
        original = gs.pkgconfig_version
        try:
            gs.pkgconfig_version = lambda pkg: (calls.append(pkg), '9.9.9')[1]
            overrides = gs._resolve_dep_versions(['libz'], {'libz': '1.3.1'})
            self.assertEqual(overrides['libz'], '1.3.1')
            self.assertEqual(calls, [])
        finally:
            gs.pkgconfig_version = original

    def test_none_is_cached_when_pkgconfig_missing(self):
        calls = []
        original = gs.pkgconfig_version
        try:
            gs.pkgconfig_version = lambda pkg: (calls.append(pkg), None)[1]
            overrides = gs._resolve_dep_versions(['liboqs'], {})
            self.assertIn('liboqs', overrides)
            self.assertIsNone(overrides['liboqs'])
            # A cached None must short-circuit later lookups too.
            gs.dep_version('liboqs', overrides)
            self.assertEqual(len(calls), 1)
        finally:
            gs.pkgconfig_version = original


class TestCollectSrcs(unittest.TestCase):
    """_collect_srcs merges --srcs and --srcs-file into one ordered,
    path-deduplicated list.  --srcs-file lets an IDE / build system feed
    a mechanically-generated source list (the only way to get a truly
    complete set) when it is too long for the command line."""

    def _write(self, lines):
        with tempfile.NamedTemporaryFile('w', suffix='.txt',
                                         delete=False) as f:
            f.write(lines)
            return f.name

    def test_srcs_only(self):
        self.assertEqual(
            gs._collect_srcs(['a.c', 'b.c'], None),
            ['a.c', 'b.c'])

    def test_srcs_file_only(self):
        path = self._write('a.c\nb.c\n')
        try:
            self.assertEqual(gs._collect_srcs(None, path), ['a.c', 'b.c'])
        finally:
            os.unlink(path)

    def test_blank_and_comment_lines_ignored(self):
        path = self._write('# header\n\na.c\n  # indented comment\nb.c\n\n')
        try:
            self.assertEqual(gs._collect_srcs(None, path), ['a.c', 'b.c'])
        finally:
            os.unlink(path)

    def test_srcs_and_file_merge_and_dedup_paths(self):
        # A path appearing in both --srcs and --srcs-file collapses to one
        # entry (first occurrence wins) so it does not later trip
        # srcs_merkle_hash's duplicate-basename guard.
        path = self._write('b.c\nc.c\n')
        try:
            self.assertEqual(
                gs._collect_srcs(['a.c', 'b.c'], path),
                ['a.c', 'b.c', 'c.c'])
        finally:
            os.unlink(path)

    def test_whitespace_is_stripped(self):
        path = self._write('  a.c  \n\tb.c\t\n')
        try:
            self.assertEqual(gs._collect_srcs(None, path), ['a.c', 'b.c'])
        finally:
            os.unlink(path)

    def test_empty_result_exits(self):
        path = self._write('# only comments\n\n')
        try:
            with self.assertRaises(SystemExit):
                gs._collect_srcs(None, path)
        finally:
            os.unlink(path)

    def test_unreadable_srcs_file_exits(self):
        with self.assertRaises(SystemExit):
            gs._collect_srcs(None, '/nonexistent/dir/does-not-exist.txt')


class TestCliMutualExclusion(unittest.TestCase):
    """The two entry-point shapes (autotools / standalone) must be
    mutually exclusive.  Mixing them would produce a hash whose
    semantics nobody can interpret (library bytes? source merkle?
    both?), so gen-sbom refuses the combination upfront with a
    clear error."""

    def _run(self, *argv):
        import subprocess
        here = pathlib.Path(__file__).resolve().parent
        script = here / 'gen-sbom'
        return subprocess.run(
            ['python3', str(script), *argv],
            capture_output=True, text=True
        )

    BASE = [
        '--name', 'wolfssl',
        '--version', '0.0.0-test',
        '--license-file', '/dev/null',
        '--cdx-out', '/dev/null',
        '--spdx-out', '/dev/null',
    ]

    def test_options_and_user_settings_together_fail(self):
        result = self._run(
            *self.BASE,
            '--options-h', '/dev/null',
            '--user-settings', '/dev/null',
            '--lib', '/dev/null')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('--options-h or --user-settings', result.stderr)

    def test_neither_options_nor_user_settings_fails(self):
        result = self._run(
            *self.BASE,
            '--lib', '/dev/null')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('--options-h or --user-settings', result.stderr)

    def test_lib_and_srcs_together_fail(self):
        result = self._run(
            *self.BASE,
            '--options-h', '/dev/null',
            '--lib', '/dev/null',
            '--srcs', '/dev/null')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('component-checksum source', result.stderr)

    def test_neither_lib_nor_srcs_fails(self):
        result = self._run(
            *self.BASE,
            '--options-h', '/dev/null')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('component-checksum source', result.stderr)

    def test_no_artifact_hash_with_srcs_fails(self):
        # --no-artifact-hash is the "no hashable artefact" escape hatch;
        # combining it with a real hash source (--srcs here) is a
        # contradiction the operator must resolve, so gen-sbom refuses it.
        result = self._run(
            *self.BASE,
            '--options-h', '/dev/null',
            '--no-artifact-hash',
            '--srcs', '/dev/null')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('component-checksum source', result.stderr)

    def test_no_artifact_hash_with_lib_fails(self):
        result = self._run(
            *self.BASE,
            '--options-h', '/dev/null',
            '--no-artifact-hash',
            '--lib', '/dev/null')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('component-checksum source', result.stderr)

    def test_licenseref_without_license_text_is_rejected(self):
        # Hard contract enforced at gen-sbom main() (see gen-sbom:880):
        # any LicenseRef-* in --license-override must be accompanied by
        # --license-text.  Without this gate, build_extracted_licensing_infos
        # silently emits a placeholder ('NOASSERTION. The text for this
        # LicenseRef has not been embedded...') which technically
        # validates as SPDX but is worthless to a CRA reviewer.
        # TestBuildExtractedLicensingInfos exercises the placeholder
        # path in isolation; this test pins the gate that should make
        # that path unreachable from main().  A refactor that moves
        # the check (e.g. into a helper called by only one entry-point
        # shape) would be caught here.
        result = self._run(
            *self.BASE,
            '--options-h', '/dev/null',
            '--lib', '/dev/null',
            '--license-override', 'LicenseRef-wolfSSL-Commercial')
        self.assertNotEqual(result.returncode, 0,
                            'gen-sbom must reject LicenseRef-* override '
                            'without --license-text; CRA reviewers cannot '
                            'use the placeholder fallback')
        # The error must tell the operator how to fix it; the literal
        # '--license-text' substring is the actionable hint.
        self.assertIn('--license-text', result.stderr)

    def test_licenseref_with_license_text_is_accepted(self):
        # Positive companion to test_licenseref_without_license_text_is_rejected:
        # confirms the gate does NOT fire when --license-text is supplied,
        # so a refactor that flips the predicate sense (e.g. tests
        # `is not None` where it should test `is None`) is also caught.
        # We don't validate the SBOM content here — TestBuildExtractedLicensingInfos
        # already covers the shape — only that the gate permits the run.
        with tempfile.NamedTemporaryFile('w', suffix='.txt',
                                         delete=False) as f:
            f.write('Plain-text wolfSSL commercial licence text.\n')
            license_text_path = f.name
        # --lib must be non-empty (gen-sbom refuses /dev/null as a
        # component checksum); use a tiny stand-in file so we exercise
        # the LicenseRef gate without tripping the empty-lib gate.
        with tempfile.NamedTemporaryFile('wb', suffix='.so',
                                         delete=False) as f:
            f.write(b'\x7fELF stub')
            lib_path = f.name
        try:
            result = self._run(
                *self.BASE,
                '--options-h', '/dev/null',
                '--lib', lib_path,
                '--license-override', 'LicenseRef-wolfSSL-Commercial',
                '--license-text', license_text_path)
            self.assertEqual(
                result.returncode, 0,
                f'gen-sbom rejected a valid LicenseRef + license-text '
                f'pair: stderr={result.stderr!r}')
        finally:
            os.unlink(license_text_path)
            os.unlink(lib_path)

    def test_empty_lib_is_rejected(self):
        # The --lib argument is the wolfSSL component checksum source.
        # An empty file produces the well-known empty-file SHA-256
        # (e3b0c44...b855), which is a valid-looking hash that
        # matches no real wolfSSL build artefact ever shipped.  Both
        # SPDX and CDX validators accept it; nothing else catches
        # the lie.  gen-sbom must refuse zero-byte --lib.
        result = self._run(
            *self.BASE,
            '--options-h', '/dev/null',
            '--lib', '/dev/null')
        self.assertNotEqual(result.returncode, 0,
                            'gen-sbom accepted an empty --lib file; would '
                            'have shipped an SBOM with the empty-file '
                            'SHA-256 as the wolfSSL component checksum')
        self.assertIn('empty', result.stderr.lower())
        self.assertIn('--lib', result.stderr)

    def test_zero_byte_srcs_warn_but_do_not_fail(self):
        # Companion: --srcs may legitimately include zero-byte
        # placeholders in cross-compile setups (a target file the
        # build system creates with touch but doesn't compile yet),
        # so gen-sbom emits a WARNING rather than failing.  This
        # gives the embedded customer a chance to see they have a
        # stub file in the source set without breaking their build.
        with tempfile.NamedTemporaryFile('wb', suffix='.c',
                                         delete=False) as f:
            f.write(b'/* real source */\n')
            real_src = f.name
        with tempfile.NamedTemporaryFile('wb', suffix='.c',
                                         delete=False) as f:
            empty_src = f.name
        # Rename so the basenames are distinct (srcs_merkle_hash
        # rejects duplicate basenames; see TestSrcsMerkleHash).
        # Rename and rebind BEFORE the try-block so the finally
        # clause always references the live filenames even when an
        # assertion fails.
        real_renamed = real_src + '.real.c'
        empty_renamed = empty_src + '.empty.c'
        os.rename(real_src, real_renamed)
        os.rename(empty_src, empty_renamed)
        real_src = real_renamed
        empty_src = empty_renamed
        try:
            result = self._run(
                *self.BASE,
                '--user-settings', '/dev/null',
                '--srcs', real_src, empty_src)
            # The standalone path with /dev/null user-settings should
            # complete; the only thing we care about here is that an
            # empty source did not abort the run.
            self.assertEqual(
                result.returncode, 0,
                f'gen-sbom failed with zero-byte source: stderr={result.stderr!r}')
            self.assertIn('zero-byte source', result.stderr)
        finally:
            for p in (real_src, empty_src):
                try:
                    os.unlink(p)
                except FileNotFoundError:
                    pass

    def test_user_settings_path_in_help(self):
        # Discoverability regression guard - if the standalone entry
        # point is invisible to `--help`, embedded customers will not
        # know it exists.
        result = self._run('--help')
        self.assertEqual(result.returncode, 0, result.stderr)
        for token in ('--user-settings', '--user-settings-include',
                      '--user-settings-define', '--srcs', '--srcs-file',
                      '--no-artifact-hash', '--dep-version'):
            self.assertIn(token, result.stdout, f'{token!r} missing from --help')

    def test_srcs_file_matches_srcs_for_same_list(self):
        # --srcs-file is purely an input convenience: for the same set of
        # files it must produce a byte-identical SBOM to passing the files
        # via --srcs.  This pins that equivalence end-to-end so the two
        # input paths can never silently diverge.
        with tempfile.TemporaryDirectory() as tmp:
            aes = os.path.join(tmp, 'aes.c')
            sha = os.path.join(tmp, 'sha.c')
            with open(aes, 'w') as f:
                f.write('/* aes */\n')
            with open(sha, 'w') as f:
                f.write('/* sha */\n')
            listfile = os.path.join(tmp, 'srcs.txt')
            with open(listfile, 'w') as f:
                f.write(f'# wolfssl sources\n{aes}\n\n{sha}\n')

            cdx_a = os.path.join(tmp, 'a.cdx.json')
            spdx_a = os.path.join(tmp, 'a.spdx.json')
            cdx_b = os.path.join(tmp, 'b.cdx.json')
            spdx_b = os.path.join(tmp, 'b.spdx.json')
            common = [
                '--name', 'wolfssl', '--version', '0.0.0-test',
                '--license-file', '/dev/null',
                '--user-settings', '/dev/null',
            ]
            env = dict(os.environ, SOURCE_DATE_EPOCH='1700000000')
            import subprocess
            here = pathlib.Path(__file__).resolve().parent
            script = str(here / 'gen-sbom')
            r1 = subprocess.run(
                ['python3', script, *common, '--srcs', aes, sha,
                 '--cdx-out', cdx_a, '--spdx-out', spdx_a],
                capture_output=True, text=True, env=env)
            r2 = subprocess.run(
                ['python3', script, *common, '--srcs-file', listfile,
                 '--cdx-out', cdx_b, '--spdx-out', spdx_b],
                capture_output=True, text=True, env=env)
            self.assertEqual(r1.returncode, 0, r1.stderr)
            self.assertEqual(r2.returncode, 0, r2.stderr)
            with open(cdx_a) as f:
                a_cdx = f.read()
            with open(cdx_b) as f:
                b_cdx = f.read()
            self.assertEqual(a_cdx, b_cdx)

    def test_no_artifact_hash_emits_placeholder_and_note(self):
        # End-to-end: --no-artifact-hash must produce a valid SBOM whose
        # checksum is the synthetic 64-zero placeholder, tagged
        # hash-source=none with the contact note, so the "no hashable
        # artefact" path can never silently masquerade as a real digest.
        with tempfile.TemporaryDirectory() as tmp:
            cdx = os.path.join(tmp, 'out.cdx.json')
            spdx = os.path.join(tmp, 'out.spdx.json')
            result = self._run(
                '--name', 'wolfssl', '--version', '0.0.0-test',
                '--license-file', '/dev/null',
                '--user-settings', '/dev/null',
                '--no-artifact-hash',
                '--cdx-out', cdx, '--spdx-out', spdx)
            self.assertEqual(result.returncode, 0, result.stderr)
            with open(cdx) as f:
                doc = json.load(f)
            comp = doc['metadata']['component']
            self.assertEqual(comp['hashes'][0]['content'], '0' * 64)
            props = {p['name']: p['value'] for p in comp['properties']}
            self.assertEqual(props['wolfssl:sbom:hash-source'], 'none')
            self.assertIn('wolfssl:sbom:no-artifact-hash-note', props)


# ---------------------------------------------------------------------------
# SBOM document generators (generate_cdx / generate_spdx + dep helpers).
#
# These four functions emit the actual JSON consumed by vulnerability
# scanners and CRA auditors.  Until this block landed they were entirely
# untested; an SBOM-shape regression that still produced syntactically
# valid JSON would slip through every CI gate.  The independent oracle
# is the CDX 1.6 / SPDX 2.3 schema field names, externally specified.
# ---------------------------------------------------------------------------


class TestCdxDepComponent(unittest.TestCase):
    """gen-sbom:576 cdx_dep_component shapes a single CycloneDX dep entry."""

    def test_returns_bomref_and_component(self):
        # Stub pkgconfig_version so the test does not depend on the
        # build host having libz / liboqs installed.
        original = gs.pkgconfig_version
        try:
            gs.pkgconfig_version = lambda *_a, **_k: '1.3.1'
            ref, comp = gs.cdx_dep_component('wolfssl', '5.9.1', 'libz')
        finally:
            gs.pkgconfig_version = original
        self.assertEqual(comp['bom-ref'], ref)
        self.assertEqual(comp['type'], 'library')
        self.assertEqual(comp['name'], 'zlib')
        self.assertEqual(comp['supplier']['name'],
                         'Jean-loup Gailly and Mark Adler')
        # Per CDX 1.6, listed-id licences go in license.id (not name).
        # A regression that switches to license.name would silently
        # produce an SBOM that some validators reject.
        self.assertEqual(
            comp['licenses'], [{'license': {'id': 'Zlib'}}])
        self.assertEqual(comp['version'], '1.3.1')
        self.assertTrue(comp['purl'].startswith('pkg:'))
        self.assertIn('zlib', comp['purl'])
        self.assertEqual(comp['externalReferences'][0]['type'], 'vcs')

    def test_omits_version_and_purl_when_unknown(self):
        # When pkg-config cannot resolve the dep version, gen-sbom
        # emits the component WITHOUT a version field rather than
        # advertising a wrong one.  CRA scanners distinguish absent
        # version from wrong version.
        original = gs.pkgconfig_version
        try:
            gs.pkgconfig_version = lambda *_a, **_k: None
            ref, comp = gs.cdx_dep_component('wolfssl', '5.9.1', 'libz')
        finally:
            gs.pkgconfig_version = original
        self.assertNotIn('version', comp)
        self.assertNotIn('purl', comp)
        # bom-ref is still present and deterministic.
        self.assertTrue(ref)

    def test_dep_version_override_wins_over_pkgconfig(self):
        # Embedded customers without pkg-config use --dep-version to
        # supply the linked dep version explicitly.  Confirms the
        # override threads through to the emitted CDX component.
        original = gs.pkgconfig_version
        try:
            gs.pkgconfig_version = lambda *_a, **_k: '99.99.99'
            ref, comp = gs.cdx_dep_component(
                'wolfssl', '5.9.1', 'libz', {'libz': '1.3.1'})
        finally:
            gs.pkgconfig_version = original
        self.assertEqual(comp['version'], '1.3.1')

    def test_bomref_is_deterministic_for_same_inputs(self):
        # Two calls with the same inputs must return identical bom-refs;
        # otherwise SBOMs are not byte-identical across reruns and the
        # reproducibility guarantee breaks.
        original = gs.pkgconfig_version
        try:
            gs.pkgconfig_version = lambda *_a, **_k: '1.3.1'
            ref_a, _ = gs.cdx_dep_component('wolfssl', '5.9.1', 'libz')
            ref_b, _ = gs.cdx_dep_component('wolfssl', '5.9.1', 'libz')
        finally:
            gs.pkgconfig_version = original
        self.assertEqual(ref_a, ref_b)


class TestSpdxDepPackage(unittest.TestCase):
    """gen-sbom:599 spdx_dep_package shapes a single SPDX dep package."""

    def test_returns_spdxid_and_package(self):
        original = gs.pkgconfig_version
        try:
            gs.pkgconfig_version = lambda *_a, **_k: '0.10.0'
            spdx_id, pkg = gs.spdx_dep_package('liboqs')
        finally:
            gs.pkgconfig_version = original
        self.assertTrue(spdx_id.startswith('SPDXRef-Package-'))
        # SPDXID must contain only alphanumeric + '.' + '-' (SPDX
        # 2.3 §3.2).  spdx_dep_package strips everything else; a
        # regression that allowed underscores or 'lib' prefixes
        # could produce an SPDXID validators reject.
        import re as _re
        self.assertTrue(
            _re.match(r'\ASPDXRef-[A-Za-z0-9.-]+\Z', spdx_id),
            f'invalid SPDXID shape: {spdx_id!r}')
        self.assertEqual(pkg['SPDXID'], spdx_id)
        self.assertEqual(pkg['name'], 'liboqs')
        self.assertEqual(pkg['versionInfo'], '0.10.0')
        self.assertEqual(pkg['filesAnalyzed'], False)
        # Both license fields must agree; SPDX validators accept
        # divergence but it is semantically meaningless here.
        self.assertEqual(pkg['licenseConcluded'], pkg['licenseDeclared'])
        self.assertEqual(pkg['copyrightText'], 'NOASSERTION')

    def test_unknown_version_uses_NOASSERTION(self):
        # SPDX 2.3 §3.3 requires versionInfo; when truly unknown,
        # 'NOASSERTION' is the spec-compliant placeholder.  Emitting
        # an empty string or omitting the field would fail validation.
        original = gs.pkgconfig_version
        try:
            gs.pkgconfig_version = lambda *_a, **_k: None
            _, pkg = gs.spdx_dep_package('liboqs')
        finally:
            gs.pkgconfig_version = original
        self.assertEqual(pkg['versionInfo'], 'NOASSERTION')
        # externalRefs.purl is only emitted when a version is known
        # (a purl with no @version is meaningless to package-manager
        # tooling); confirm it is absent here.
        self.assertNotIn('externalRefs', pkg)

    def test_purl_externalref_present_when_version_known(self):
        original = gs.pkgconfig_version
        try:
            gs.pkgconfig_version = lambda *_a, **_k: '0.10.0'
            _, pkg = gs.spdx_dep_package('liboqs')
        finally:
            gs.pkgconfig_version = original
        purl_refs = [
            r for r in pkg.get('externalRefs', [])
            if r.get('referenceType') == 'purl'
        ]
        self.assertEqual(len(purl_refs), 1)
        self.assertIn('liboqs', purl_refs[0]['referenceLocator'])
        self.assertIn('0.10.0', purl_refs[0]['referenceLocator'])


class TestGenerateCdx(unittest.TestCase):
    """gen-sbom:624 generate_cdx assembles the full CycloneDX 1.6 doc."""

    BASE_KW = dict(
        name='wolfssl',
        version='5.9.1',
        supplier='wolfSSL Inc.',
        license_id='GPL-2.0-only',
        license_text=None,
        lib_hash='a' * 64,
        timestamp='2024-01-01T00:00:00Z',
        year=2024,
        serial='00000000-0000-0000-0000-000000000001',
        enabled_deps=[],
        build_props=[('HAVE_AESGCM', '1'), ('NO_DES3', '')],
    )

    def test_top_level_shape(self):
        doc = gs.generate_cdx(**self.BASE_KW)
        self.assertEqual(doc['bomFormat'], 'CycloneDX')
        self.assertEqual(doc['specVersion'], '1.6')
        self.assertEqual(
            doc['$schema'],
            'http://cyclonedx.org/schema/bom-1.6.schema.json')
        self.assertEqual(doc['version'], 1)
        # serialNumber is a urn:uuid: prefix per CDX schema.
        self.assertTrue(doc['serialNumber'].startswith('urn:uuid:'))

    def test_main_component_fields(self):
        doc = gs.generate_cdx(**self.BASE_KW)
        comp = doc['metadata']['component']
        self.assertEqual(comp['type'], 'library')
        self.assertEqual(comp['name'], 'wolfssl')
        self.assertEqual(comp['version'], '5.9.1')
        # CPE 2.3 with vendor:product:version - downstream
        # vulnerability scanners key on this format.
        self.assertEqual(
            comp['cpe'],
            'cpe:2.3:a:wolfssl:wolfssl:5.9.1:*:*:*:*:*:*:*')
        # pkg:github resolves to OSV / GHSA / Snyk / Trivy directly,
        # without the vendor:product mapping a pkg:generic PURL would
        # force.  pkg:github tag refs use the upstream `vX.Y.Z` shape
        # (rather than bare `X.Y.Z`), matching wolfSSL's release tags.
        self.assertEqual(comp['purl'], 'pkg:github/wolfSSL/wolfssl@v5.9.1')
        self.assertEqual(comp['hashes'],
                         [{'alg': 'SHA-256', 'content': 'a' * 64}])
        self.assertEqual(comp['licenses'],
                         [{'license': {'id': 'GPL-2.0-only'}}])

    def test_build_properties_emitted(self):
        doc = gs.generate_cdx(**self.BASE_KW)
        props = doc['metadata']['component']['properties']
        names = {p['name']: p['value'] for p in props}
        self.assertEqual(names['wolfssl:build:HAVE_AESGCM'], '1')
        # An empty define value is rendered as '1' so the SBOM
        # consumer can't distinguish '#define X' from '#define X 1'.
        self.assertEqual(names['wolfssl:build:NO_DES3'], '1')

    def test_dependency_refs_match_components(self):
        # Critical invariant: every bom-ref in `dependencies` must
        # appear as a `bom-ref` on either the main component or one
        # of the dep components.  Without this, the dependency graph
        # references dangling IDs and CycloneDX-aware tooling cannot
        # resolve relationships.
        original = gs.pkgconfig_version
        try:
            gs.pkgconfig_version = lambda *_a, **_k: '1.3.1'
            doc = gs.generate_cdx(**{
                **self.BASE_KW,
                'enabled_deps': ['libz'],
            })
        finally:
            gs.pkgconfig_version = original
        all_refs = {doc['metadata']['component']['bom-ref']}
        for c in doc['components']:
            all_refs.add(c['bom-ref'])
        for entry in doc['dependencies']:
            self.assertIn(entry['ref'], all_refs,
                          f"dangling dep ref: {entry['ref']!r}")
            for dep in entry.get('dependsOn', []):
                self.assertIn(dep, all_refs,
                              f"dangling dependsOn ref: {dep!r}")
        # The wolfssl bom-ref must depend on the libz bom-ref.
        wolfssl_ref = doc['metadata']['component']['bom-ref']
        wolfssl_entry = next(
            e for e in doc['dependencies'] if e['ref'] == wolfssl_ref)
        self.assertEqual(len(wolfssl_entry['dependsOn']), 1)

    def test_source_merkle_path_emits_hash_kind_property(self):
        # The OmniBOR / source-merkle entry point annotates the
        # SBOM so an auditor reading the SHA-256 knows it is a hash
        # of the source set, not of the built library.  Without
        # this property the same SHA-256 field carries two
        # incompatible semantic meanings depending on entry point.
        doc = gs.generate_cdx(**{
            **self.BASE_KW,
            'hash_kind': 'source-merkle-omnibor',
            'srcs_basenames': ['aes.c', 'sha.c'],
        })
        props = {p['name']: p['value']
                 for p in doc['metadata']['component']['properties']}
        self.assertEqual(props['wolfssl:sbom:hash-kind'],
                         'source-merkle-omnibor')
        self.assertEqual(props['wolfssl:sbom:source-set'], 'aes.c,sha.c')

    def test_library_binary_path_emits_hash_kind_property(self):
        # The library-binary path now also emits hash-kind: it is the
        # auditor's only structured signal for what the SHA-256 in
        # `hashes` actually represents.  Previously this property was
        # only set on the source-merkle path, leaving an autotools
        # SBOM ambiguous about its checksum semantics.
        doc = gs.generate_cdx(**self.BASE_KW)
        props = {p['name']: p['value']
                 for p in doc['metadata']['component']['properties']}
        self.assertEqual(props['wolfssl:sbom:hash-kind'], 'library-binary')
        # source-set is only meaningful for the merkle path.
        self.assertNotIn('wolfssl:sbom:source-set', props)

    def test_hash_source_property_defaults_to_lib(self):
        # hash-source is the coarse provenance tag downstream tooling
        # filters on. The default (autotools / library-binary path) is
        # 'lib'; pin it so a refactor of the default cannot silently
        # mislabel the autotools SBOM.
        doc = gs.generate_cdx(**self.BASE_KW)
        props = {p['name']: p['value']
                 for p in doc['metadata']['component']['properties']}
        self.assertEqual(props['wolfssl:sbom:hash-source'], 'lib')
        self.assertNotIn('wolfssl:sbom:no-artifact-hash-note', props)

    def test_hash_source_srcs_for_source_set(self):
        doc = gs.generate_cdx(**{
            **self.BASE_KW,
            'hash_kind': 'source-merkle-omnibor',
            'hash_source': 'srcs',
            'srcs_basenames': ['aes.c', 'sha.c'],
        })
        props = {p['name']: p['value']
                 for p in doc['metadata']['component']['properties']}
        self.assertEqual(props['wolfssl:sbom:hash-source'], 'srcs')
        self.assertNotIn('wolfssl:sbom:no-artifact-hash-note', props)

    def test_hash_source_none_carries_contact_note(self):
        # The --no-artifact-hash path must flag the synthetic placeholder
        # so a downstream auditor cannot mistake the 64-zero checksum for
        # a genuine digest. Both the hash-source=none tag and the contact
        # note are required.
        doc = gs.generate_cdx(**{
            **self.BASE_KW,
            'lib_hash': gs._NO_HASH_SENTINEL,
            'hash_kind': 'none',
            'hash_source': 'none',
        })
        props = {p['name']: p['value']
                 for p in doc['metadata']['component']['properties']}
        self.assertEqual(props['wolfssl:sbom:hash-source'], 'none')
        self.assertEqual(props['wolfssl:sbom:no-artifact-hash-note'],
                         gs._NO_HASH_NOTE)
        # The placeholder must be the synthetic 64-zero sentinel.
        self.assertEqual(
            doc['metadata']['component']['hashes'][0]['content'],
            '0' * 64)

    def test_main_component_carries_security_external_refs(self):
        # An auditor reading the CDX needs a single in-document link
        # to the project's security advisories and the RFC 9116
        # security.txt; previously they had to know to go look on
        # GitHub or wolfssl.com.  Pin the set so a regression that
        # drops one of these silently is caught at the cheap CI gate.
        doc = gs.generate_cdx(**self.BASE_KW)
        refs = doc['metadata']['component']['externalReferences']
        types = {r['type'] for r in refs}
        self.assertEqual(
            {'vcs', 'website', 'issue-tracker', 'advisories',
             'security-contact'},
            types)
        sec_url = next(
            r['url'] for r in refs if r['type'] == 'security-contact')
        self.assertEqual(
            sec_url,
            'https://www.wolfssl.com/.well-known/security.txt')

    def test_lib_file_entries_become_subcomponents(self):
        # CycloneDX 1.6 lets a library component nest file-typed
        # sub-components.  When the autotools `--lib` path supplies a
        # file_entries list, the SBOM names the linked binary by file
        # path + SHA-1 + SHA-256 so an auditor / scanner does not have
        # to reason about the bare SHA-256 in `hashes` against a
        # build-system layout they cannot see.
        doc = gs.generate_cdx(**{
            **self.BASE_KW,
            'file_entries': [{
                'name': 'libwolfssl.so.43.0.0',
                'sha1': 'b' * 40,
                'sha256': 'a' * 64,
            }],
        })
        sub = doc['metadata']['component']['components']
        self.assertEqual(len(sub), 1)
        self.assertEqual(sub[0]['type'], 'file')
        self.assertEqual(sub[0]['name'], 'libwolfssl.so.43.0.0')
        algs = {h['alg'] for h in sub[0]['hashes']}
        self.assertEqual(algs, {'SHA-1', 'SHA-256'})

    def test_tool_metadata_uses_module_constants(self):
        # The CDX `metadata.tools.components[]` entry is the only
        # producer-identity field in the document; downstream consumers
        # pin their parser against the (name, version) pair, so the
        # tool name / version must come from the module-level
        # constants and not from a stale string baked into the
        # generator.
        doc = gs.generate_cdx(**self.BASE_KW)
        tool = doc['metadata']['tools']['components'][0]
        self.assertEqual(tool['name'], gs.GEN_SBOM_TOOL_NAME)
        self.assertEqual(tool['version'], gs.GEN_SBOM_VERSION)


class TestGenerateSpdx(unittest.TestCase):
    """gen-sbom:698 generate_spdx assembles the full SPDX 2.3 doc."""

    BASE_KW = dict(
        name='wolfssl',
        version='5.9.1',
        supplier='wolfSSL Inc.',
        license_id='GPL-2.0-only',
        license_text=None,
        lib_hash='a' * 64,
        timestamp='2024-01-01T00:00:00Z',
        year=2024,
        doc_ns_uuid='00000000-0000-0000-0000-000000000002',
        enabled_deps=[],
        build_props=[('HAVE_AESGCM', '1'), ('NO_DES3', '')],
    )

    def test_top_level_shape(self):
        doc = gs.generate_spdx(**self.BASE_KW)
        self.assertEqual(doc['spdxVersion'], 'SPDX-2.3')
        self.assertEqual(doc['dataLicense'], 'CC0-1.0')
        self.assertEqual(doc['SPDXID'], 'SPDXRef-DOCUMENT')
        self.assertEqual(doc['name'], 'wolfssl-5.9.1')
        # SPDX 2.3 §6.5: documentNamespace must be a unique URI; no
        # requirement that it resolve.  Default to `urn:uuid:<derived>`
        # rather than a `https://wolfssl.com/sbom/...` URL the project
        # does not host -- emitting an unresolvable URL would mislead
        # any downstream tool that follows it.  The doc_ns_uuid keeps
        # the namespace per-version unique without making a hosting
        # claim.
        self.assertEqual(
            doc['documentNamespace'],
            f'urn:uuid:{self.BASE_KW["doc_ns_uuid"]}')

    def test_document_namespace_override_is_honoured(self):
        # Downstream packagers who legitimately re-host the SBOM under
        # their own URL pass --document-namespace; the override must
        # win over the urn:uuid default.  Without this knob a packager
        # would have to fork the script to satisfy SPDX 2.3 §6.5
        # uniqueness against a self-hosted mirror.
        custom = 'https://example.com/sbom/wolfssl-5.9.1.spdx.json'
        doc = gs.generate_spdx(**{
            **self.BASE_KW,
            'document_namespace': custom,
        })
        self.assertEqual(doc['documentNamespace'], custom)

    def test_document_namespace_default_is_urn_uuid(self):
        # Negative companion to test_document_namespace_override: when
        # no override is supplied (None or empty), the urn:uuid form is
        # used and the previously-emitted https://wolfssl.com/sbom/
        # URL is NOT reintroduced (regression guard for the M1
        # correction).
        for explicit in (None, ''):
            doc = gs.generate_spdx(**{
                **self.BASE_KW,
                'document_namespace': explicit,
            })
            self.assertTrue(
                doc['documentNamespace'].startswith('urn:uuid:'),
                f'{explicit!r} -> {doc["documentNamespace"]!r}')
            self.assertNotIn('wolfssl.com/sbom', doc['documentNamespace'])

    def test_main_package_fields(self):
        doc = gs.generate_spdx(**self.BASE_KW)
        wolfssl_pkg = next(
            p for p in doc['packages']
            if p['SPDXID'] == 'SPDXRef-Package-wolfssl')
        self.assertEqual(wolfssl_pkg['name'], 'wolfssl')
        self.assertEqual(wolfssl_pkg['versionInfo'], '5.9.1')
        self.assertEqual(
            wolfssl_pkg['checksums'],
            [{'algorithm': 'SHA256', 'checksumValue': 'a' * 64}])
        self.assertEqual(wolfssl_pkg['licenseConcluded'], 'GPL-2.0-only')
        self.assertEqual(wolfssl_pkg['licenseDeclared'], 'GPL-2.0-only')

    def test_describes_relationship(self):
        # SPDX 2.3 §11: every document must DESCRIBE its primary package.
        doc = gs.generate_spdx(**self.BASE_KW)
        describes = [
            r for r in doc['relationships']
            if r['relationshipType'] == 'DESCRIBES'
        ]
        self.assertEqual(len(describes), 1)
        self.assertEqual(describes[0]['spdxElementId'], 'SPDXRef-DOCUMENT')
        self.assertEqual(describes[0]['relatedSpdxElement'],
                         'SPDXRef-Package-wolfssl')

    def test_depends_on_relationship_per_dep(self):
        original = gs.pkgconfig_version
        try:
            gs.pkgconfig_version = lambda *_a, **_k: '1.3.1'
            doc = gs.generate_spdx(**{
                **self.BASE_KW,
                'enabled_deps': ['libz'],
            })
        finally:
            gs.pkgconfig_version = original
        depends_on = [
            r for r in doc['relationships']
            if r['relationshipType'] == 'DEPENDS_ON'
        ]
        self.assertEqual(len(depends_on), 1)
        self.assertEqual(depends_on[0]['spdxElementId'],
                         'SPDXRef-Package-wolfssl')
        # The relatedSpdxElement must be a real SPDXID in the doc;
        # a typo would create a dangling reference.
        all_spdx_ids = {p['SPDXID'] for p in doc['packages']}
        self.assertIn(depends_on[0]['relatedSpdxElement'], all_spdx_ids)

    def test_extracted_licensing_infos_present_for_licenseref(self):
        # Critical SPDX 2.3 §10.1 plumbing: when license_id contains
        # a LicenseRef-* and license_text is supplied, the document
        # MUST carry a hasExtractedLicensingInfos block covering it.
        # A regression that drops the wiring in generate_spdx's tail
        # produces SBOMs that fail SPDX validation -- the autotools
        # path catches this at pyspdxtools time, but the standalone
        # path does not validate, so a customer-shipped SBOM would
        # silently land at an auditor.
        doc = gs.generate_spdx(**{
            **self.BASE_KW,
            'license_id': 'LicenseRef-wolfSSL-Commercial',
            'license_text': 'Commercial licence body.\n',
        })
        self.assertIn('hasExtractedLicensingInfos', doc)
        infos = doc['hasExtractedLicensingInfos']
        self.assertEqual(len(infos), 1)
        self.assertEqual(infos[0]['licenseId'],
                         'LicenseRef-wolfSSL-Commercial')
        self.assertEqual(infos[0]['extractedText'],
                         'Commercial licence body.\n')

    def test_extracted_licensing_infos_absent_for_simple_id(self):
        # Companion to the above: simple SPDX IDs (Apache-2.0,
        # GPL-2.0-only, etc.) MUST NOT generate a
        # hasExtractedLicensingInfos block, since the licence
        # text is well-known and the field is reserved for refs.
        doc = gs.generate_spdx(**self.BASE_KW)
        self.assertNotIn('hasExtractedLicensingInfos', doc)

    def test_source_merkle_path_annotates_via_annotations(self):
        # Mirror of TestGenerateCdx.test_source_merkle_path_emits_hash_kind_property
        # for SPDX.  The hash-kind / source-set used to be stuffed into
        # the package `comment` field as positional `key=value` slugs,
        # forcing anyone reading the SPDX to grep free-form text.
        # SPDX 2.3 §8.5 provides `annotations[]` for exactly this
        # producer metadata, and validators (pyspdxtools, NTIA) treat
        # them as first-class data.
        doc = gs.generate_spdx(**{
            **self.BASE_KW,
            'hash_kind': 'source-merkle-omnibor',
            'srcs_basenames': ['aes.c', 'sha.c'],
        })
        wolfssl_pkg = next(
            p for p in doc['packages']
            if p['SPDXID'] == 'SPDXRef-Package-wolfssl')
        annotation_comments = [
            a['comment'] for a in wolfssl_pkg['annotations']
        ]
        self.assertIn(
            'wolfssl:sbom:hash-kind=source-merkle-omnibor',
            annotation_comments)
        self.assertIn(
            'wolfssl:sbom:source-set=aes.c,sha.c', annotation_comments)
        # `comment` no longer carries the structured hash-kind data --
        # it is reserved for the human-readable build-config defines.
        self.assertNotIn('hash-kind=', wolfssl_pkg['comment'])
        self.assertNotIn('source-set=', wolfssl_pkg['comment'])

    def test_library_binary_path_annotates_via_annotations(self):
        # Companion to the source-merkle test: library-binary also
        # emits hash-kind via annotations[].  The old behaviour of
        # only annotating the merkle path left autotools SBOMs with
        # no machine-readable signal of their checksum semantics.
        doc = gs.generate_spdx(**self.BASE_KW)
        wolfssl_pkg = next(
            p for p in doc['packages']
            if p['SPDXID'] == 'SPDXRef-Package-wolfssl')
        annotation_comments = [
            a['comment'] for a in wolfssl_pkg['annotations']
        ]
        self.assertIn(
            'wolfssl:sbom:hash-kind=library-binary', annotation_comments)
        # No source-set on library-binary path.
        self.assertNotIn('wolfssl:sbom:source-set=',
                         ''.join(annotation_comments))
        # Comment is still build-config defines only.
        self.assertNotIn('hash-kind=', wolfssl_pkg['comment'])

    def test_hash_source_annotation_defaults_to_lib(self):
        doc = gs.generate_spdx(**self.BASE_KW)
        wolfssl_pkg = next(
            p for p in doc['packages']
            if p['SPDXID'] == 'SPDXRef-Package-wolfssl')
        comments = [a['comment'] for a in wolfssl_pkg['annotations']]
        self.assertIn('wolfssl:sbom:hash-source=lib', comments)
        self.assertNotIn('wolfssl:sbom:no-artifact-hash-note=',
                         ''.join(comments))

    def test_hash_source_none_annotates_contact_note(self):
        # The --no-artifact-hash path must record both the hash-source=none
        # tag and the contact note in the SPDX annotations[], mirroring the
        # CycloneDX side, so neither format hides the synthetic placeholder.
        doc = gs.generate_spdx(**{
            **self.BASE_KW,
            'lib_hash': gs._NO_HASH_SENTINEL,
            'hash_kind': 'none',
            'hash_source': 'none',
        })
        wolfssl_pkg = next(
            p for p in doc['packages']
            if p['SPDXID'] == 'SPDXRef-Package-wolfssl')
        comments = [a['comment'] for a in wolfssl_pkg['annotations']]
        self.assertIn('wolfssl:sbom:hash-source=none', comments)
        self.assertIn(
            f'wolfssl:sbom:no-artifact-hash-note={gs._NO_HASH_NOTE}',
            comments)
        self.assertEqual(
            wolfssl_pkg['checksums'][0]['checksumValue'], '0' * 64)

    def test_file_entries_do_not_leak_into_spdx(self):
        # SPDX 2.3 forbids package elements (CONTAINS relationships
        # via hasFiles) when `filesAnalyzed: False`, and flipping
        # `filesAnalyzed: True` would force a packageVerificationCode
        # that hashes every file in the package -- not just the
        # linked binary.  generate_spdx accepts file_entries for
        # parameter symmetry with generate_cdx but must not surface
        # it as `files[]` / `hasFiles[]`; otherwise pyspdxtools rejects
        # the document and `make sbom` fails.  Pin the absence so a
        # future change cannot quietly reintroduce the validator
        # failure that motivated the carve-out.
        doc = gs.generate_spdx(**{
            **self.BASE_KW,
            'file_entries': [{
                'name': 'libwolfssl.so.43.0.0',
                'sha1': 'b' * 40,
                'sha256': 'a' * 64,
            }],
        })
        self.assertNotIn('files', doc)
        wolfssl_pkg = next(
            p for p in doc['packages']
            if p['SPDXID'] == 'SPDXRef-Package-wolfssl')
        self.assertNotIn('hasFiles', wolfssl_pkg)
        self.assertEqual(wolfssl_pkg['filesAnalyzed'], False)
        self.assertNotIn('packageVerificationCode', wolfssl_pkg)
        # CONTAINS relationships are also forbidden under
        # filesAnalyzed=False; ensure none leaked through.
        contains = [
            r for r in doc['relationships']
            if r.get('relationshipType') == 'CONTAINS'
        ]
        self.assertEqual(contains, [])

    def test_main_package_purl_uses_pkg_github(self):
        # PURL parity with the CDX side: pkg:github/<owner>/<repo>@v<v>
        # resolves directly in OSV / GHSA / Snyk / Trivy.  The previous
        # pkg:generic shape forced every scanner into CPE-fallback
        # matching, producing the noisy SBOM behaviour auditors
        # complain about.
        doc = gs.generate_spdx(**self.BASE_KW)
        wolfssl_pkg = next(
            p for p in doc['packages']
            if p['SPDXID'] == 'SPDXRef-Package-wolfssl')
        purl_refs = [
            r for r in wolfssl_pkg['externalRefs']
            if r['referenceType'] == 'purl'
        ]
        self.assertEqual(len(purl_refs), 1)
        self.assertEqual(
            purl_refs[0]['referenceLocator'],
            'pkg:github/wolfSSL/wolfssl@v5.9.1')

    def test_main_package_carries_advisory_external_ref(self):
        # SPDX 2.3 SECURITY/advisory externalRef pointing at the
        # GitHub advisories index.  Same auditor-facing rationale as
        # the CDX side: a single in-document link to the project's
        # security disclosures, no out-of-band knowledge required.
        doc = gs.generate_spdx(**self.BASE_KW)
        wolfssl_pkg = next(
            p for p in doc['packages']
            if p['SPDXID'] == 'SPDXRef-Package-wolfssl')
        adv_refs = [
            r for r in wolfssl_pkg['externalRefs']
            if r['referenceType'] == 'advisory'
        ]
        self.assertEqual(len(adv_refs), 1)
        self.assertEqual(
            adv_refs[0]['referenceLocator'],
            'https://github.com/wolfSSL/wolfssl/security/advisories')
        self.assertEqual(adv_refs[0]['referenceCategory'], 'SECURITY')

    def test_creation_info_uses_module_constants(self):
        # SPDX `creationInfo.creators[]` carries the producer-identity
        # signal that downstream tools key on; must come from the
        # module-level constants and not from a stale string.
        doc = gs.generate_spdx(**self.BASE_KW)
        creators = doc['creationInfo']['creators']
        expected_tool = (
            f'Tool: {gs.GEN_SBOM_TOOL_NAME}-{gs.GEN_SBOM_VERSION}'
        )
        self.assertIn(expected_tool, creators)

    def test_annotations_have_well_formed_metadata(self):
        # SPDX 2.3 §8.5: annotation entries require `annotationDate`
        # (ISO-8601 with timezone), `annotationType` (one of OTHER,
        # REVIEW, ...), `annotator` (Person/Organization/Tool prefix),
        # and `comment` (string).  pyspdxtools rejects malformed
        # annotation entries; pin the shape here at the cheapest CI
        # gate so a regression in generate_spdx surfaces in unit
        # tests rather than in the integration job.
        doc = gs.generate_spdx(**self.BASE_KW)
        wolfssl_pkg = next(
            p for p in doc['packages']
            if p['SPDXID'] == 'SPDXRef-Package-wolfssl')
        for ann in wolfssl_pkg['annotations']:
            self.assertEqual(ann['annotationDate'], self.BASE_KW['timestamp'])
            self.assertEqual(ann['annotationType'], 'OTHER')
            self.assertTrue(ann['annotator'].startswith('Tool: '),
                            f'annotator must use Tool: prefix: {ann!r}')
            self.assertIsInstance(ann['comment'], str)
            self.assertTrue(ann['comment'])


# ---------------------------------------------------------------------------
# Bomsh provenance verifier
#
# The verifier (scripts/bomsh_verify.py) is invoked by the bomsh: CI job
# against a real OmniBOR graph + enriched SPDX, but its two checks --
# resolvability and object-store integrity -- are pure data-shape
# logic.  Exercising them here with synthetic fixtures means a logic
# regression is caught at the cheapest CI gate (the unit job, < 1 s)
# instead of the bomsh integration job (~5 minutes per run, requires
# bomtrace3 + the entire bomsh toolchain to be built).
# ---------------------------------------------------------------------------

class _BomshFixture:
    """Build a self-consistent OmniBOR + SPDX layout in a tmpdir.

    Use as a context manager; the tmpdir is cleaned on exit.  Methods
    let individual tests perturb a single property (delete a blob,
    truncate one, etc.) without rebuilding the whole fixture each
    time."""

    def __init__(self, tmpdir):
        self.tmpdir = pathlib.Path(tmpdir)
        self.objects_dir = self.tmpdir / 'omnibor' / 'objects'
        self.objects_dir.mkdir(parents=True)
        self.spdx_path = self.tmpdir / 'omnibor.wolfssl-5.9.1.spdx.json'
        # Three distinct blobs staged at their gitoid paths.  Stand-in
        # for the OmniBOR documents a real `bomsh_create_bom.py` run
        # would write under omnibor/objects/; the verifier doesn't care
        # whether the content is a doc or an artefact blob, only that
        # the file at <aa>/<rest> round-trips through gitoid_sha1.  We
        # use OmniBOR-doc-shaped bytes here rather than ELF magic so a
        # reader doesn't mistakenly conclude the verifier expects raw
        # library content under objects/ (it does not -- bomsh stores
        # the Input Manifest there, keyed by its bom_id).
        self.wolfssl_blob = b'gitoid:blob:sha1\nblob 0123456789abcdef0123456789abcdef01234567\n'
        self.aux_blobs = [b'/* aes.c */\n', b'/* sha.c */\n']
        self.gitoids = {
            'wolfssl': self._stage_blob(self.wolfssl_blob),
        }
        for i, content in enumerate(self.aux_blobs):
            self.gitoids[f'aux{i}'] = self._stage_blob(content)
        self._write_spdx()

    def _stage_blob(self, content):
        """Write `content` into omnibor/objects/<aa>/<rest> at the
        correct gitoid path; return the gitoid hex.  Uses
        `_gitoid_of_bytes` (an independent reimplementation of the
        canonical Git blob hash) rather than calling into
        bomsh_verify -- two implementations is the point: a bug in
        either is caught by disagreement."""
        gid = _gitoid_of_bytes(content)
        d = self.objects_dir / gid[:2]
        d.mkdir(exist_ok=True)
        (d / gid[2:]).write_bytes(content)
        return gid

    def _write_spdx(self):
        """Emit the enriched SPDX with one gitoid externalRef per
        staged blob."""
        packages = [{
            'name': 'wolfssl',
            'externalRefs': [{
                'referenceCategory': 'PERSISTENT-ID',
                'referenceType': 'gitoid',
                'referenceLocator': f'gitoid:blob:sha1:{self.gitoids["wolfssl"]}',
            }],
        }]
        for i in range(len(self.aux_blobs)):
            packages.append({
                'name': f'wolfssl-aux-{i}',
                'externalRefs': [{
                    'referenceCategory': 'PERSISTENT-ID',
                    'referenceType': 'gitoid',
                    'referenceLocator': f'gitoid:blob:sha1:{self.gitoids[f"aux{i}"]}',
                }],
            })
        self.spdx_path.write_text(json.dumps({'packages': packages}))

    def verify(self):
        """Run the orchestrator with the fixture's paths."""
        return bv.verify(
            spdx_glob=str(self.tmpdir / 'omnibor.wolfssl-*.spdx.json'),
            omnibor_dir=str(self.tmpdir / 'omnibor'))


def _gitoid_of_bytes(data):
    """Reference implementation used in the fixture so blobs are
    placed at the gitoid path the verifier later derives.  Independent
    of bomsh_verify.gitoid_sha1, which reads from a file -- we want
    two implementations so a bug in one is caught by disagreement."""
    import hashlib
    h = hashlib.sha1()
    h.update(f'blob {len(data)}\0'.encode())
    h.update(data)
    return h.hexdigest()


import json  # noqa: E402  (used by the bomsh fixture below)

bv_spec = importlib.util.spec_from_file_location(
    'bomsh_verify',
    pathlib.Path(__file__).resolve().parent / 'bomsh_verify.py')
bv = importlib.util.module_from_spec(bv_spec)
bv_spec.loader.exec_module(bv)


class TestBomshProvenanceVerify(unittest.TestCase):
    """Exercises bomsh_verify.verify against synthetic fixtures.  Each
    test starts from a known-good fixture, perturbs exactly one
    property, and checks the verifier's failure mode is the right one
    -- so a regression that, say, accepts a dangling gitoid as long as
    object-store integrity passes is caught here."""

    def test_happy_path_passes(self):
        # Baseline.  An untouched fixture is valid; the verifier should
        # report OK and the success message should mention the object
        # round-trip count (so a future change that silently drops the
        # success-line content is also caught).
        with tempfile.TemporaryDirectory() as tmpdir:
            fx = _BomshFixture(tmpdir)
            ok, messages = fx.verify()
            self.assertTrue(ok, f'verifier rejected a valid fixture: {messages}')
            joined = '\n'.join(messages)
            self.assertIn('OK:', joined)
            self.assertIn('objects round-trip:', joined)

    def test_dangling_gitoid_fails_check_A(self):
        # Delete one blob from objects/ but leave its externalRef in
        # the SPDX.  Check (A) must reject; the failure message must
        # mention DANGLING and the missing gitoid path so triage isn't
        # just "verifier failed".
        with tempfile.TemporaryDirectory() as tmpdir:
            fx = _BomshFixture(tmpdir)
            target_gid = fx.gitoids['aux0']
            (fx.objects_dir / target_gid[:2] / target_gid[2:]).unlink()
            ok, messages = fx.verify()
            self.assertFalse(ok)
            joined = '\n'.join(messages)
            self.assertIn('DANGLING', joined)
            self.assertIn(target_gid, joined)

    def test_corrupt_blob_fails_check_B(self):
        # Truncate one blob in objects/ so its content no longer
        # matches the gitoid encoded in its path.  Check (B) must
        # reject; check (A) would still pass (the file exists).  This
        # pins that integrity is checked independently of resolvability.
        with tempfile.TemporaryDirectory() as tmpdir:
            fx = _BomshFixture(tmpdir)
            target_gid = fx.gitoids['aux1']
            (fx.objects_dir / target_gid[:2] / target_gid[2:]).write_bytes(b'')
            ok, messages = fx.verify()
            self.assertFalse(ok)
            joined = '\n'.join(messages)
            self.assertIn('CORRUPT', joined)
            self.assertIn('round-trip', joined)

    def test_unexpected_gitoid_locator_format_rejected(self):
        # bomsh upstream switching from sha1 to sha256 would change
        # the locator prefix.  load_spdx_gitoids must raise so the
        # maintainer is forced to update the verifier in lockstep,
        # rather than silently accepting an unparsable value.
        with tempfile.TemporaryDirectory() as tmpdir:
            fx = _BomshFixture(tmpdir)
            spdx = json.loads(fx.spdx_path.read_text())
            spdx['packages'][0]['externalRefs'][0]['referenceLocator'] = (
                'gitoid:blob:sha256:' + 'f' * 64)
            fx.spdx_path.write_text(json.dumps(spdx))
            ok, messages = fx.verify()
            self.assertFalse(ok)
            self.assertTrue(
                any('unexpected gitoid locator format' in m for m in messages),
                messages)

    def test_no_gitoid_externalrefs_fails(self):
        # Negative companion: an SPDX that contains no gitoid
        # externalRefs at all is not a bomsh-enriched document, and
        # the verifier should say so plainly rather than silently
        # report 0 verified.
        with tempfile.TemporaryDirectory() as tmpdir:
            fx = _BomshFixture(tmpdir)
            spdx = json.loads(fx.spdx_path.read_text())
            for pkg in spdx['packages']:
                pkg['externalRefs'] = []
            fx.spdx_path.write_text(json.dumps(spdx))
            ok, messages = fx.verify()
            self.assertFalse(ok)
            self.assertTrue(
                any('no gitoid externalRefs' in m for m in messages),
                messages)

    def test_object_store_integrity_skips_non_blob_files(self):
        # OmniBOR objects/ may contain housekeeping files at the root
        # (info/, pack/, etc.) that are NOT blobs and must not be
        # gitoid-checked.  The fanout is exactly two levels deep
        # (<aa>/<rest>); anything else gets skipped.  Pin this so a
        # future "walk everything" rewrite doesn't start failing on
        # legitimate non-blob content.
        with tempfile.TemporaryDirectory() as tmpdir:
            fx = _BomshFixture(tmpdir)
            # Drop a bogus file at the objects/ root and inside a
            # nested subdir; neither should trigger CORRUPT.
            (fx.objects_dir / 'INFO').write_text('housekeeping')
            (fx.objects_dir / 'pack').mkdir()
            (fx.objects_dir / 'pack' / 'index.idx').write_bytes(b'pack idx')
            ok, messages = fx.verify()
            self.assertTrue(ok, f'verifier flagged non-blob files: {messages}')


if __name__ == '__main__':
    unittest.main(verbosity=2)
