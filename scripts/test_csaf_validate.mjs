// Runner self-test for scripts/csaf_validate.mjs.
//
// csaf_validate.mjs is otherwise only exercised end-to-end in
// .github/workflows/advisory.yml against generated documents, so its own
// logic -- summarize() treating `isValid === false || errors.length > 0` as a
// failure, and the exit-code contract (0 all-pass, 1 any-invalid, 2 usage) --
// has no direct coverage.  A regression there (e.g. mis-reading the validator
// result shape after a @secvisogram/csaf-validator-lib bump) would silently
// turn the gate into a no-op that still exits 0.  This test pins the contract
// so the gate cannot degrade unnoticed.
//
// Usage:  node scripts/test_csaf_validate.mjs [<known-valid.csaf.json>]
//
// The optional argument is a document that passes the gate (e.g. one produced
// by gen-advisory earlier in the CI job); when given it enables the exit-0
// assertion.  Without it, only the usage(2) and invalid(1) contracts run, so
// the test still works offline without generating a document first.
//
// Requires @secvisogram/csaf-validator-lib to be installed (same dependency
// csaf_validate.mjs imports); the advisory.yml csaf-conformance job installs it.

import { spawnSync } from 'node:child_process'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const HERE = dirname(fileURLToPath(import.meta.url))
const RUNNER = join(HERE, 'csaf_validate.mjs')

function run(args) {
  return spawnSync(process.execPath, [RUNNER, ...args], { encoding: 'utf8' })
}

let failures = 0
function check(name, ok) {
  if (ok) {
    console.log(`ok   - ${name}`)
  } else {
    failures++
    console.error(`FAIL - ${name}`)
  }
}

// 1) usage: no arguments -> exit 2.
check('no args exits 2 (usage)', run([]).status === 2)

const tmp = mkdtempSync(join(tmpdir(), 'csaf-selftest-'))
try {
  // 2) invalid: parseable JSON but non-conformant CSAF -> exit 1.  Missing the
  //    required tracking/publisher/vulnerabilities fields, so the strict 2.0
  //    schema test (part of the gate) must reject it.  This exercises the
  //    summarize()/gate path rather than the JSON parse-error path.
  const badDoc = join(tmp, 'bad.csaf.json')
  writeFileSync(badDoc, JSON.stringify({
    document: { category: 'csaf_security_advisory', csaf_version: '2.0' },
  }))
  check('non-conformant document exits 1', run([badDoc]).status === 1)

  // 3) unparseable input -> non-zero (read/parse-failure path).
  const junk = join(tmp, 'junk.csaf.json')
  writeFileSync(junk, '{ not valid json')
  check('unparseable document exits non-zero', run([junk]).status !== 0)

  // 4) valid: a document that passes the gate -> exit 0 (only when provided).
  const validDoc = process.argv[2]
  if (validDoc) {
    check(`valid document exits 0 (${validDoc})`, run([validDoc]).status === 0)
  } else {
    console.log('skip - valid-document exit-0 check (no valid doc path given)')
  }
} finally {
  rmSync(tmp, { recursive: true, force: true })
}

console.log(failures === 0 ? 'PASS' : `FAILED (${failures})`)
process.exit(failures === 0 ? 0 : 1)
