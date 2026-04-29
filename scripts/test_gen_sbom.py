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
import tempfile
import unittest
import uuid
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
        # Should still produce a UTC ISO-Z timestamp; we only check shape.
        self.assertRegex(
            ts, r'\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z')

    def test_no_sde_is_current_utc(self):
        os.environ.pop('SOURCE_DATE_EPOCH', None)
        _, ts = gs.build_timestamp()
        self.assertRegex(
            ts, r'\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z')


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


class TestParseOptionsH(unittest.TestCase):
    def test_parses_defines_sorted_and_deduped(self):
        with tempfile.NamedTemporaryFile('w', suffix='.h',
                                         delete=False) as f:
            f.write(
                "/* fake options.h */\n"
                "#define HAVE_BAR\n"
                "#define HAVE_AAA 1\n"
                "#define HAVE_BAR  /* duplicate */\n"
                "#define HAVE_FOO 42\n"
            )
            path = f.name
        try:
            pairs = gs.parse_options_h(path)
        finally:
            os.unlink(path)
        names = [k for k, _ in pairs]
        self.assertEqual(names, sorted(set(names)))
        self.assertIn(('HAVE_AAA', '1'), pairs)
        self.assertIn(('HAVE_FOO', '42'), pairs)


if __name__ == '__main__':
    unittest.main(verbosity=2)
