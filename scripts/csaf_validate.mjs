// CSAF 2.0 conformance gate for documents emitted by scripts/gen-advisory.
//
// JSON-schema validity is necessary but NOT sufficient for CSAF: the standard
// defines a battery of *mandatory tests* (section 6.1.*) -- CVSS/vector
// consistency, contradicting product status, product_id defined/used,
// tracking.version vs revision_history, and so on -- that a bare schema pass
// happily accepts.  This runner uses the Secvisogram reference implementation
// (@secvisogram/csaf-validator-lib) which bundles every schema (incl. the
// first.org CVSS schemas) and implements those mandatory tests, so the check
// is fully offline and reproducible once the pinned dependency is installed.
//
// Gate = the strict CSAF 2.0 schema test + all mandatory tests.  Optional and
// informative tests are reported as warnings only (they encode house-style
// preferences, not conformance).
//
// Usage:  node scripts/csaf_validate.mjs <doc.csaf.json> [<doc2.csaf.json> ...]
// Exit 0 if every document passes the gate, 1 otherwise.

import { readFileSync } from 'node:fs'
import validate from '@secvisogram/csaf-validator-lib/validate.js'
import * as schemaTests from '@secvisogram/csaf-validator-lib/schemaTests.js'
import * as mandatoryTests from '@secvisogram/csaf-validator-lib/mandatoryTests.js'
import * as optionalTests from '@secvisogram/csaf-validator-lib/optionalTests.js'

const files = process.argv.slice(2)
if (files.length === 0) {
  console.error('usage: node scripts/csaf_validate.mjs <doc.csaf.json> ...')
  process.exit(2)
}

// The gate: strict 2.0 schema + every mandatory test.
const gateTests = [schemaTests.csaf_2_0_strict, ...Object.values(mandatoryTests)]
// Reported for visibility but non-fatal.
const advisoryTests = [...Object.values(optionalTests)]

function summarize(testResults) {
  // testResults: [{ name, isValid, errors, warnings, infos }]
  const failed = []
  for (const t of testResults) {
    if (t.isValid === false || (t.errors && t.errors.length > 0)) {
      failed.push(t)
    }
  }
  return failed
}

let anyInvalid = false

for (const file of files) {
  let doc
  try {
    doc = JSON.parse(readFileSync(file, 'utf8'))
  } catch (e) {
    console.error(`ERROR: cannot read/parse ${file}: ${e.message}`)
    anyInvalid = true
    continue
  }

  const gate = await validate(gateTests, doc)
  const advisory = await validate(advisoryTests, doc)

  if (gate.isValid) {
    console.log(`OK   ${file}  (strict schema + ${Object.keys(mandatoryTests).length} mandatory tests)`)
  } else {
    anyInvalid = true
    console.error(`FAIL ${file}`)
    for (const t of summarize(gate.tests)) {
      for (const err of t.errors || []) {
        console.error(`       [${t.name}] ${err.instancePath || '/'}: ${err.message}`)
      }
    }
  }

  // Surface optional-test warnings without failing the build.
  const optWarn = summarize(advisory.tests)
  for (const t of optWarn) {
    for (const err of t.errors || []) {
      console.warn(`  warn ${file} [${t.name}] ${err.instancePath || '/'}: ${err.message}`)
    }
  }
}

process.exit(anyInvalid ? 1 : 0)
