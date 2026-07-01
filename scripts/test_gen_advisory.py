#!/usr/bin/env python3
"""Unit + semantic tests for scripts/gen-advisory.

Run from the repo root:

    python3 -m unittest scripts/test_gen_advisory.py

These tests are pure stdlib (no network, no pip deps) so they form the cheap
PR gate, mirroring scripts/test_gen_sbom.py.  They cover three things the
JSON-schema validators in .github/workflows/advisory.yml do NOT:

  1. the pure record->model logic (CVSS priority, CWE extraction, version
     ranges, the FIPS product split, the reachability hedge);
  2. CSAF *semantic* invariants that a bare JSON-schema pass accepts but the
     CSAF mandatory tests reject (every referenced product_id is defined in
     the product_tree, no product is simultaneously affected and not-affected,
     flags only sit on not-affected products, scores only target affected
     products, tracking.version matches the latest revision_history entry);
  3. the two regressions already fixed once (CycloneDX uses `unaffected`
     not `not_affected` in affects[].versions[].status; every CSAF reference
     carries the required `summary`).

The full CSAF 2.0 schema + mandatory-test conformance and the CycloneDX 1.6
strict-schema pass run in CI against csaf-validator-lib / cyclonedx-bom; this
file deliberately avoids those heavyweight deps.
"""

import importlib.util
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from importlib.machinery import SourceFileLoader


HERE = pathlib.Path(__file__).resolve().parent
SCRIPT = HERE / 'gen-advisory'
TESTDATA = HERE / 'testdata'
EXAMPLE_OVERLAY = HERE / 'advisory-vex-overlay.example.json'
OVERLAY_SCHEMA = HERE / 'advisory-vex-overlay.schema.json'

# Pinned epoch -> 2023-11-14T22:13:20Z.  Shared by the reproducibility test
# and the timestamp unit test so the expected string is single-sourced.
PINNED_EPOCH = '1700000000'
PINNED_EPOCH_ISO = '2023-11-14T22:13:20Z'


def _load_gen_advisory():
    """Load gen-advisory (no .py extension) as module 'ga', same trick as
    test_gen_sbom.py uses for gen-sbom."""
    if not SCRIPT.is_file():
        raise FileNotFoundError(f"expected gen-advisory alongside this test at {SCRIPT}")
    loader = SourceFileLoader('ga', str(SCRIPT))
    spec = importlib.util.spec_from_loader('ga', loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


ga = _load_gen_advisory()


def _record(name):
    with open(TESTDATA / name) as f:
        return json.load(f)


def _adv(name):
    return ga.parse_record(_record(name))


def _overlay():
    with open(EXAMPLE_OVERLAY) as f:
        return json.load(f)


def _collect_product_ids(node):
    """Every product_id declared anywhere in a CSAF product_tree branch."""
    pids = set()
    prod = node.get('product')
    if isinstance(prod, dict) and 'product_id' in prod:
        pids.add(prod['product_id'])
    for child in node.get('branches', []):
        pids |= _collect_product_ids(child)
    return pids


def _tree_product_ids(doc):
    pids = set()
    for branch in doc['product_tree'].get('branches', []):
        pids |= _collect_product_ids(branch)
    return pids


# Valid CSAF 2.0 enum subsets we rely on (spec 6.1.* / schema enums).
CSAF_STATUS_BUCKETS = {
    'first_affected', 'first_fixed', 'fixed', 'known_affected',
    'known_not_affected', 'last_affected', 'recommended',
    'under_investigation',
}
CSAF_FLAG_LABELS = {
    'component_not_present', 'inline_mitigations_already_exist',
    'vulnerable_code_cannot_be_controlled_by_adversary',
    'vulnerable_code_not_in_execute_path', 'vulnerable_code_not_present',
}
CSAF_REMEDIATION_CATEGORIES = {
    'mitigation', 'no_fix_planned', 'none_available', 'optional_patch',
    'vendor_fix', 'workaround', 'fix_planned',
}
CDX_AFFECTS_STATUS = {'affected', 'unaffected', 'unknown'}


# --------------------------------------------------------------------------- #
# Pure helpers
# --------------------------------------------------------------------------- #

class TestDerivedUuid(unittest.TestCase):
    def test_deterministic(self):
        self.assertEqual(ga.derived_uuid('a', 'b'), ga.derived_uuid('a', 'b'))

    def test_distinct_inputs_distinct_output(self):
        self.assertNotEqual(ga.derived_uuid('a', 'b'), ga.derived_uuid('a', 'c'))

    def test_no_aliasing_across_separator(self):
        # NUL-separated join: ('a','bc') must not collide with ('ab','c').
        self.assertNotEqual(ga.derived_uuid('a', 'bc'), ga.derived_uuid('ab', 'c'))

    def test_is_uuid(self):
        self.assertRegex(
            ga.derived_uuid('x'),
            r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$')


class TestBuildTimestamp(unittest.TestCase):
    def setUp(self):
        self._saved = os.environ.get('SOURCE_DATE_EPOCH')

    def tearDown(self):
        if self._saved is None:
            os.environ.pop('SOURCE_DATE_EPOCH', None)
        else:
            os.environ['SOURCE_DATE_EPOCH'] = self._saved

    def test_honors_source_date_epoch(self):
        os.environ['SOURCE_DATE_EPOCH'] = PINNED_EPOCH
        _, iso = ga.build_timestamp()
        self.assertEqual(iso, PINNED_EPOCH_ISO)

    def test_invalid_epoch_falls_back_to_now(self):
        os.environ['SOURCE_DATE_EPOCH'] = 'not-a-number'
        _, iso = ga.build_timestamp()
        # Falls back to wallclock; just assert a well-formed Z timestamp.
        self.assertRegex(iso, r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$')


class TestCpePurl(unittest.TestCase):
    def test_cpe(self):
        self.assertEqual(ga.cpe_for('wolfSSL', '5.9.1'),
                         'cpe:2.3:a:wolfssl:wolfssl:5.9.1:*:*:*:*:*:*:*')

    def test_purl(self):
        self.assertEqual(ga.purl_for('wolfSSL', '5.9.1'),
                         'pkg:github/wolfSSL/wolfssl@v5.9.1')


class TestBestCvss(unittest.TestCase):
    def test_priority_v4_over_v3(self):
        metrics = [{'cvssV3_1': {'x': 1}}, {'cvssV4_0': {'y': 2}}]
        best = ga._best_cvss(metrics)
        self.assertEqual(best['csaf_key'], 'cvss_v4')
        self.assertEqual(best['cdx_method'], 'CVSSv4')
        self.assertEqual(best['data'], {'y': 2})

    def test_v31_over_v30_over_v2(self):
        self.assertEqual(
            ga._best_cvss([{'cvssV2_0': {}}, {'cvssV3_0': {}}])['csaf_key'],
            'cvss_v3')
        self.assertEqual(
            ga._best_cvss([{'cvssV2_0': {}}])['csaf_key'], 'cvss_v2')

    def test_none_when_absent(self):
        self.assertIsNone(ga._best_cvss([]))
        self.assertIsNone(ga._best_cvss([{'other': {}}]))


class TestParseRecord(unittest.TestCase):
    def test_core_fields(self):
        adv = _adv('CVE-2026-5501.json')
        self.assertEqual(adv['cve'], 'CVE-2026-5501')
        self.assertTrue(adv['title'].startswith('Improper Certificate'))
        self.assertIn('wolfSSL_X509_verify_cert', adv['description'])
        self.assertEqual(adv['date_published'], '2026-04-10T03:07:39.604Z')
        self.assertEqual(adv['date_updated'], '2026-04-22T13:59:28.514Z')

    def test_cwe_id_and_canonical_name(self):
        adv = _adv('CVE-2026-5501.json')
        self.assertEqual(adv['cwe']['id'], 'CWE-295')
        # Resolved from the official catalogue (exact MITRE casing), NOT the
        # record's lowercase free text -- required by CSAF test 6.1.11.
        self.assertEqual(adv['cwe']['name'], 'Improper Certificate Validation')

    def test_cvss_is_v4_and_no_csaf20_compatible_score(self):
        adv = _adv('CVE-2026-5501.json')
        self.assertEqual(adv['cvss']['csaf_key'], 'cvss_v4')
        self.assertEqual(adv['cvss']['data']['baseSeverity'], 'CRITICAL')
        self.assertEqual(adv['cvss']['data']['baseScore'], 9.3)
        # The record carries only CVSS v4, which CSAF 2.0 scores[] cannot hold.
        self.assertIsNone(adv['cvss_csaf'])

    def test_affected_and_credits(self):
        adv = _adv('CVE-2026-5501.json')
        self.assertEqual(len(adv['affected']), 1)
        a = adv['affected'][0]
        self.assertEqual(a['product'], 'wolfSSL')
        self.assertEqual(a['default_status'], 'unaffected')
        self.assertEqual(a['versions'][0]['lessThanOrEqual'], '5.9.0')
        self.assertEqual(adv['references'],
                         ['https://github.com/wolfSSL/wolfssl/pull/10102'])
        self.assertEqual(len(adv['credits']), 1)

    def test_missing_cveid_exits(self):
        with self.assertRaises(SystemExit):
            ga.parse_record({'containers': {'cna': {}}, 'cveMetadata': {}})

    def test_missing_cna_exits(self):
        with self.assertRaises(SystemExit):
            ga.parse_record({'cveMetadata': {'cveId': 'CVE-1'}})


class TestRangeLabelAndVers(unittest.TestCase):
    def test_less_than_or_equal_from_zero(self):
        v = {'version': '0', 'lessThanOrEqual': '5.9.0'}
        self.assertEqual(ga._range_label(v), '<= 5.9.0')
        self.assertEqual(ga._vers_range(v), 'vers:generic/<=5.9.0')

    def test_less_than_with_base(self):
        v = {'version': '5.0.0', 'lessThan': '5.9.0'}
        self.assertEqual(ga._range_label(v), '5.0.0 <= x < 5.9.0')
        self.assertEqual(ga._vers_range(v), 'vers:generic/>=5.0.0|<5.9.0')

    def test_single_version(self):
        v = {'version': '5.9.0'}
        self.assertEqual(ga._range_label(v), '5.9.0')
        self.assertEqual(ga._vers_range(v), 'vers:generic/5.9.0')


class TestProductModel(unittest.TestCase):
    def test_mainline_only(self):
        adv = _adv('CVE-2026-5501.json')
        prods = ga.product_model(adv, {'state': 'exploitable',
                                       'fixed_versions': ['5.9.1']})
        self.assertEqual(len(prods), 1)
        p = prods[0]
        self.assertEqual(p['product_name'], 'wolfSSL')
        self.assertEqual(p['bucket'], 'known_affected')
        self.assertEqual(len(p['affected_ranges']), 1)
        self.assertEqual(p['fixed'][0]['version'], '5.9.1')
        self.assertEqual(p['remediation_category'], 'vendor_fix')

    def test_not_affected_state_sets_bucket_and_justification(self):
        adv = _adv('CVE-2026-5501.json')
        prods = ga.product_model(
            adv, {'state': 'not_affected', 'justification': 'code_not_present'})
        self.assertEqual(prods[0]['bucket'], 'known_not_affected')
        self.assertEqual(prods[0]['justification'], 'code_not_present')

    def test_fips_modelled_as_second_product(self):
        adv = _adv('CVE-2026-5501.json')
        ov = _overlay()['CVE-2026-5501']
        prods = ga.product_model(adv, ov)
        self.assertEqual(len(prods), 2)
        fips = [p for p in prods if p['cdx_key'] == 'wolfcrypt-fips'][0]
        self.assertEqual(fips['bucket'], 'known_not_affected')
        self.assertEqual(fips['justification'], 'code_not_present')
        self.assertIn('CMVP Certificate #4718', fips['model_numbers'])
        self.assertEqual(fips['module_version'], '5.2.1')
        # not-affected FIPS with no fix => no_fix_planned, not none_available.
        self.assertEqual(fips['remediation_category'], 'no_fix_planned')


class TestHedgeNote(unittest.TestCase):
    def test_renders_defines_and_default_off(self):
        note = ga._hedge_note({'requires_defines': ['WOLFSSL_SNIFFER'],
                               'default_status': 'off'})
        self.assertIn('WOLFSSL_SNIFFER', note)
        self.assertIn('disabled by default', note)

    def test_none_when_empty(self):
        self.assertIsNone(ga._hedge_note({}))


# --------------------------------------------------------------------------- #
# CSAF emitter: structure + semantic invariants
# --------------------------------------------------------------------------- #

class TestGenerateCsaf(unittest.TestCase):
    def setUp(self):
        self.ov = _overlay()
        self.single = ga.generate_csaf(
            [_adv('CVE-2026-5501.json')], self.ov, 'CVE-2026-5501',
            PINNED_EPOCH_ISO)
        self.bundle = ga.generate_csaf(
            [_adv('CVE-2026-5501.json'), _adv('CVE-2026-5778.json')],
            self.ov, 'wolfSSL-SA-5.9.1', PINNED_EPOCH_ISO)

    def test_required_document_skeleton(self):
        d = self.single['document']
        self.assertEqual(d['csaf_version'], '2.0')
        self.assertEqual(d['category'], 'csaf_security_advisory')
        self.assertEqual(d['publisher']['category'], 'vendor')
        self.assertEqual(d['tracking']['id'], 'CVE-2026-5501')
        self.assertEqual(d['tracking']['status'], 'final')
        self.assertIn('initial_release_date', d['tracking'])
        self.assertIn('current_release_date', d['tracking'])
        self.assertTrue(d['distribution']['tlp']['label'])
        self.assertTrue(d['notes'])

    def test_tracking_version_matches_latest_revision(self):
        # CSAF 6.1.x: for a non-draft doc the latest revision_history number
        # must equal tracking.version.
        tr = self.single['document']['tracking']
        latest = tr['revision_history'][-1]['number']
        self.assertEqual(tr['version'], latest)

    def test_document_references_have_summary(self):
        # Regression: CSAF rejects references without `summary`.
        for ref in self.single['document'].get('references', []):
            self.assertIn('summary', ref)
            self.assertTrue(ref['summary'])

    def test_all_product_ids_defined_in_tree(self):
        for doc in (self.single, self.bundle):
            defined = _tree_product_ids(doc)
            self.assertTrue(defined)
            for v in doc['vulnerabilities']:
                for bucket, pids in v.get('product_status', {}).items():
                    self.assertIn(bucket, CSAF_STATUS_BUCKETS)
                    self.assertTrue(set(pids) <= defined,
                                    f'undefined pid in {bucket}')
                for s in v.get('scores', []):
                    self.assertTrue(set(s['products']) <= defined)
                for f in v.get('flags', []):
                    self.assertTrue(set(f['product_ids']) <= defined)
                for r in v.get('remediations', []):
                    self.assertTrue(set(r['product_ids']) <= defined)

    def test_no_product_both_affected_and_not_affected(self):
        for v in self.bundle['vulnerabilities']:
            ps = v.get('product_status', {})
            affected = set(ps.get('known_affected', []))
            not_affected = set(ps.get('known_not_affected', []))
            self.assertEqual(affected & not_affected, set())

    def test_vuln_references_have_summary(self):
        for v in self.bundle['vulnerabilities']:
            for ref in v.get('references', []):
                self.assertIn('summary', ref)

    def test_flags_only_on_not_affected_products(self):
        for v in self.bundle['vulnerabilities']:
            ps = v.get('product_status', {})
            not_affected = set(ps.get('known_not_affected', []))
            for f in v.get('flags', []):
                self.assertIn(f['label'], CSAF_FLAG_LABELS)
                self.assertTrue(set(f['product_ids']) <= not_affected)

    def test_scores_only_target_affected(self):
        for v in self.bundle['vulnerabilities']:
            ps = v.get('product_status', {})
            scoreable = set(ps.get('known_affected', [])) \
                | set(ps.get('under_investigation', []))
            for s in v.get('scores', []):
                self.assertTrue(set(s['products']) <= scoreable)

    def test_no_cvss_v4_in_csaf_scores(self):
        # Regression: CSAF 2.0 scores[] has no cvss_v4 property; a v4 block
        # there fails the strict schema.  These records are v4-only, so no
        # scores[] should be emitted at all.
        for doc in (self.single, self.bundle):
            for v in doc['vulnerabilities']:
                for s in v.get('scores', []):
                    self.assertNotIn('cvss_v4', s)

    def test_v4_only_record_emits_cvss_note(self):
        # The v4 rating must not be silently dropped from CSAF: it is preserved
        # as a note pointing at the CycloneDX VEX for the machine-readable form.
        v = self.single['vulnerabilities'][0]
        titles = [n.get('title') for n in v['notes']]
        self.assertIn('CVSS v4.0', titles)
        note = [n for n in v['notes'] if n.get('title') == 'CVSS v4.0'][0]
        self.assertIn('9.3', note['text'])

    def test_cwe_uses_canonical_catalogue_name(self):
        v = [x for x in self.bundle['vulnerabilities']
             if x['cve'] == 'CVE-2026-5778'][0]
        self.assertEqual(v['cwe']['id'], 'CWE-191')
        self.assertEqual(v['cwe']['name'],
                         'Integer Underflow (Wrap or Wraparound)')

    def test_remediation_categories_valid(self):
        for v in self.bundle['vulnerabilities']:
            for r in v.get('remediations', []):
                self.assertIn(r['category'], CSAF_REMEDIATION_CATEGORIES)

    def test_fips_is_its_own_product_branch(self):
        names = set()

        def walk(node):
            if node.get('category') == 'product_name':
                names.add(node['name'])
            for c in node.get('branches', []):
                walk(c)
        for b in self.single['product_tree']['branches']:
            walk(b)
        self.assertIn('wolfSSL', names)
        self.assertTrue(any('FIPS' in n for n in names),
                        f'expected a FIPS product branch, got {names}')

    def test_bundle_has_two_vulns_and_aggregate_severity(self):
        self.assertEqual(len(self.bundle['vulnerabilities']), 2)
        cves = {v['cve'] for v in self.bundle['vulnerabilities']}
        self.assertEqual(cves, {'CVE-2026-5501', 'CVE-2026-5778'})
        # CRITICAL (5501) outranks HIGH (5778).
        self.assertEqual(self.bundle['document']['aggregate_severity']['text'],
                         'CRITICAL')

    def test_hedge_note_present_for_sniffer_cve(self):
        v = [x for x in self.bundle['vulnerabilities']
             if x['cve'] == 'CVE-2026-5778'][0]
        texts = ' '.join(n['text'] for n in v['notes'])
        self.assertIn('WOLFSSL_SNIFFER', texts)


class TestCsafV3Scores(unittest.TestCase):
    """The v4-only fixtures never populate CSAF scores[]; this exercises the
    positive path with a CVSS v3.1 record (CSAF 2.0 can carry v3)."""

    def setUp(self):
        self.ov = _overlay()
        self.adv = _adv('CVE-2026-5999.json')
        self.doc = ga.generate_csaf([self.adv], self.ov, 'CVE-2026-5999',
                                    PINNED_EPOCH_ISO)

    def test_parse_selects_v3_for_csaf(self):
        self.assertEqual(self.adv['cvss']['csaf_key'], 'cvss_v3')
        self.assertIsNotNone(self.adv['cvss_csaf'])
        self.assertEqual(self.adv['cvss_csaf']['csaf_key'], 'cvss_v3')
        self.assertEqual(self.adv['cvss_csaf']['data']['baseScore'], 7.5)

    def test_csaf_emits_cvss_v3_score(self):
        v = self.doc['vulnerabilities'][0]
        self.assertEqual(len(v['scores']), 1)
        score = v['scores'][0]
        self.assertIn('cvss_v3', score)
        self.assertNotIn('cvss_v4', score)
        self.assertTrue(score['products'])
        # v3 path -> no CVSS v4 fallback note.
        self.assertNotIn('CVSS v4.0', [n.get('title') for n in v['notes']])

    def test_aggregate_severity_from_v3(self):
        self.assertEqual(self.doc['document']['aggregate_severity']['text'],
                         'HIGH')


# --------------------------------------------------------------------------- #
# CycloneDX VEX emitter
# --------------------------------------------------------------------------- #

class TestGenerateCdxVex(unittest.TestCase):
    def setUp(self):
        self.ov = _overlay()
        self.bom = ga.generate_cdx_vex(
            [_adv('CVE-2026-5501.json'), _adv('CVE-2026-5778.json')],
            self.ov, 'wolfSSL-SA-5.9.1', PINNED_EPOCH_ISO)

    def test_bom_skeleton(self):
        self.assertEqual(self.bom['bomFormat'], 'CycloneDX')
        self.assertEqual(self.bom['specVersion'], '1.6')
        self.assertRegex(self.bom['serialNumber'], r'^urn:uuid:[0-9a-f-]{36}$')
        self.assertEqual(self.bom['metadata']['component']['name'], 'wolfssl')

    def test_fips_component_present(self):
        names = {c['name'] for c in self.bom['components']}
        self.assertTrue(any('FIPS' in n for n in names), names)

    def test_affects_status_uses_unaffected_not_not_affected(self):
        # Regression sentinel: CycloneDX affects[].versions[].status only
        # accepts affected/unaffected/unknown; not_affected belongs to
        # analysis.state alone.
        for v in self.bom['vulnerabilities']:
            for aff in v['affects']:
                for ver in aff.get('versions', []):
                    self.assertIn(ver['status'], CDX_AFFECTS_STATUS)

    def test_not_affected_fips_range_is_unaffected(self):
        v = [x for x in self.bom['vulnerabilities']
             if x['id'] == 'CVE-2026-5501'][0]
        # the FIPS component is not_affected -> its range status is unaffected.
        fips_refs = {c['bom-ref'] for c in self.bom['components']}
        fips_affects = [a for a in v['affects'] if a['ref'] in fips_refs]
        self.assertTrue(fips_affects)
        for a in fips_affects:
            for ver in a['versions']:
                self.assertEqual(ver['status'], 'unaffected')

    def test_analysis_state_and_cwe_and_rating(self):
        v = [x for x in self.bom['vulnerabilities']
             if x['id'] == 'CVE-2026-5501'][0]
        self.assertEqual(v['analysis']['state'], 'exploitable')
        self.assertEqual(v['cwes'], [295])
        self.assertEqual(v['ratings'][0]['method'], 'CVSSv4')
        self.assertEqual(v['ratings'][0]['severity'], 'critical')


# --------------------------------------------------------------------------- #
# Overlay matches its own schema vocabulary (lightweight, no jsonschema).
# The authoritative jsonschema pass runs in CI; this guards the committed
# example overlay against drift without adding a pip dep to the unit gate.
# --------------------------------------------------------------------------- #

class TestExampleOverlay(unittest.TestCase):
    def setUp(self):
        with open(OVERLAY_SCHEMA) as f:
            self.schema = json.load(f)
        self.overlay = _overlay()

    def _enum(self, name):
        return set(self.schema['$defs'][name]['enum'])

    def test_states_and_justifications_in_vocab(self):
        states = self._enum('analysisState')
        justifications = self._enum('justification')
        for cve, entry in self.overlay.items():
            if cve.startswith('_'):
                continue
            if 'state' in entry:
                self.assertIn(entry['state'], states)
            if 'justification' in entry:
                self.assertIn(entry['justification'], justifications)
            fips = entry.get('fips', {})
            if 'status' in fips:
                self.assertIn(fips['status'], states)
            if 'justification' in fips:
                self.assertIn(fips['justification'], justifications)

    def test_not_affected_requires_justification(self):
        for cve, entry in self.overlay.items():
            if cve.startswith('_'):
                continue
            if entry.get('state') == 'not_affected':
                self.assertIn('justification', entry)
            if entry.get('fips', {}).get('status') == 'not_affected':
                self.assertIn('justification', entry['fips'])


# --------------------------------------------------------------------------- #
# End-to-end via the CLI: reproducibility + fail-loud behaviour.
# --------------------------------------------------------------------------- #

class TestCliBehaviour(unittest.TestCase):
    def _run(self, args, env=None):
        e = dict(os.environ)
        if env:
            e.update(env)
        return subprocess.run([sys.executable, str(SCRIPT)] + args,
                              capture_output=True, text=True, env=e)

    def test_reproducible_under_source_date_epoch(self):
        with tempfile.TemporaryDirectory() as d:
            outs = []
            for i in (1, 2):
                csaf = os.path.join(d, f'a{i}.csaf.json')
                cdx = os.path.join(d, f'a{i}.cdx.json')
                r = self._run([
                    '--cve-record', str(TESTDATA / 'CVE-2026-5501.json'),
                    '--cve-record', str(TESTDATA / 'CVE-2026-5778.json'),
                    '--vex-overlay', str(EXAMPLE_OVERLAY),
                    '--advisory-id', 'wolfSSL-SA-5.9.1',
                    '--csaf-out', csaf, '--cdx-vex-out', cdx],
                    env={'SOURCE_DATE_EPOCH': PINNED_EPOCH})
                self.assertEqual(r.returncode, 0, r.stderr)
                with open(csaf, 'rb') as f:
                    csaf_b = f.read()
                with open(cdx, 'rb') as f:
                    cdx_b = f.read()
                outs.append((csaf_b, cdx_b))
            self.assertEqual(outs[0][0], outs[1][0], 'CSAF not reproducible')
            self.assertEqual(outs[0][1], outs[1][1], 'CDX not reproducible')

    def test_single_record_defaults_advisory_id_to_cve(self):
        with tempfile.TemporaryDirectory() as d:
            csaf = os.path.join(d, 'one.csaf.json')
            r = self._run([
                '--cve-record', str(TESTDATA / 'CVE-2026-5501.json'),
                '--vex-overlay', str(EXAMPLE_OVERLAY),
                '--csaf-out', csaf])
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(csaf) as f:
                doc = json.load(f)
            self.assertEqual(doc['document']['tracking']['id'],
                             'CVE-2026-5501')

    def test_bundling_without_advisory_id_fails(self):
        with tempfile.TemporaryDirectory() as d:
            csaf = os.path.join(d, 'x.csaf.json')
            r = self._run([
                '--cve-record', str(TESTDATA / 'CVE-2026-5501.json'),
                '--cve-record', str(TESTDATA / 'CVE-2026-5778.json'),
                '--csaf-out', csaf])
            self.assertNotEqual(r.returncode, 0)
            self.assertFalse(os.path.exists(csaf),
                             'no output should be written on error')

    def test_empty_records_dir_fails(self):
        with tempfile.TemporaryDirectory() as d:
            recs = os.path.join(d, 'records')
            os.makedirs(recs)
            r = self._run(['--records-dir', recs, '--out-dir', d])
            self.assertNotEqual(r.returncode, 0)
            self.assertIn('no CVE records found', r.stderr)

    def test_batch_mode_writes_per_cve_documents(self):
        with tempfile.TemporaryDirectory() as d:
            recs = os.path.join(d, 'records')
            os.makedirs(recs)
            shutil.copy(str(TESTDATA / 'CVE-2026-5501.json'),
                        os.path.join(recs, 'CVE-2026-5501.json'))
            shutil.copy(str(TESTDATA / 'CVE-2026-5999.json'),
                        os.path.join(recs, 'CVE-2026-5999.json'))
            out = os.path.join(d, 'out')
            r = self._run(['--records-dir', recs, '--out-dir', out,
                           '--vex-overlay', str(EXAMPLE_OVERLAY)])
            self.assertEqual(r.returncode, 0, r.stderr)
            for cve in ('CVE-2026-5501', 'CVE-2026-5999'):
                csaf = os.path.join(out, f'{cve}.csaf.json')
                cdx = os.path.join(out, f'{cve}.cdx.json')
                self.assertTrue(os.path.exists(csaf), csaf)
                self.assertTrue(os.path.exists(cdx), cdx)
                with open(csaf) as f:
                    doc = json.load(f)
                self.assertEqual(doc['document']['tracking']['id'], cve)

    def test_default_records_dir_is_canonical_tree(self):
        # No --cve-record/--cve-id and no --records-dir: must fall back to the
        # canonical advisories/records/ tree (the same inputs `make advisory`
        # uses). Output is redirected to a temp dir so the repo is untouched.
        with tempfile.TemporaryDirectory() as d:
            r = self._run(['--out-dir', d])
            self.assertEqual(r.returncode, 0, r.stderr)
            produced = sorted(f for f in os.listdir(d)
                              if f.endswith('.csaf.json'))
            self.assertIn('CVE-2026-5501.csaf.json', produced)
            self.assertIn('CVE-2026-5778.csaf.json', produced)

    def test_malformed_record_fails_without_writing(self):
        with tempfile.TemporaryDirectory() as d:
            bad = os.path.join(d, 'bad.json')
            with open(bad, 'w') as f:
                f.write('{ this is not json')
            csaf = os.path.join(d, 'out.csaf.json')
            r = self._run(['--cve-record', bad, '--csaf-out', csaf])
            self.assertNotEqual(r.returncode, 0)
            self.assertFalse(os.path.exists(csaf))


if __name__ == '__main__':
    unittest.main()
