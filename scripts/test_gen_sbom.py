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

    def test_only_libz_and_liboqs_are_tracked(self):
        self.assertEqual(set(gs.DEP_META.keys()), {'libz', 'liboqs'})

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

    Skipped when pcpp is not installed; CI installs it explicitly in
    the standalone job."""

    def setUp(self):
        try:
            import pcpp  # noqa: F401
        except ImportError:
            self.skipTest('pcpp not installed; embedded path not exercised')

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
        # pins the fail-fast contract.
        settings = (
            '#ifdef WOLFSSL_USER_SETTINGS\n'
            '#include "user_settings.h"\n'
            '#endif\n'
            '#define HAVE_X 1\n'
        )
        user = '#error "this configuration is unsupported"\n'
        with self.assertRaises(SystemExit) as ctx:
            self._run(settings, user, ['WOLFSSL_USER_SETTINGS'])
        msg = str(ctx.exception)
        self.assertIn('pcpp', msg)
        self.assertIn('return_code', msg)

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
        self.assertIn('--lib or --srcs', result.stderr)

    def test_neither_lib_nor_srcs_fails(self):
        result = self._run(
            *self.BASE,
            '--options-h', '/dev/null')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('--lib or --srcs', result.stderr)

    def test_user_settings_path_in_help(self):
        # Discoverability regression guard - if the standalone entry
        # point is invisible to `--help`, embedded customers will not
        # know it exists.
        result = self._run('--help')
        self.assertEqual(result.returncode, 0, result.stderr)
        for token in ('--user-settings', '--user-settings-include',
                      '--user-settings-define', '--srcs',
                      '--dep-version'):
            self.assertIn(token, result.stdout, f'{token!r} missing from --help')


if __name__ == '__main__':
    unittest.main(verbosity=2)
