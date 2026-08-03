#!/usr/bin/env python3
# Static lint for GitHub Actions workflow and composite-action files.
#
# The check that matters: GitHub caps a single `run:` step at 21000
# characters ("Exceeded max expression length 21000"). Exceeding it does
# not fail the step - GitHub refuses to load the entire workflow file, so
# every run of it ends in failure within 0s with zero jobs, no logs and no
# annotations. That is nearly invisible among a few hundred other checks:
# os-check.yml sat broken on master for ten days in July 2026 after an
# inlined config heredoc pushed one step from 20662 to 21813 characters.
#
# Because the cap is enforced by the Actions service rather than by the
# workflow schema, no YAML validator or actionlint run catches it. Hence
# this script.
#
# Sizes are measured the way GitHub sees them: parse the YAML, then take
# the length of the resulting `run` string. Block-scalar indentation is
# already stripped by the parser, so this needs no guessing about how the
# text was folded in the source file.
#
# Checks per file:
#   * the file parses as YAML at all
#   * every `run:` step is under the hard cap (error) and under the soft
#     warning threshold (warning, so a growing list is noticed with
#     runway left rather than at the cliff)
#
# Findings are emitted as GitHub workflow commands (::error / ::warning)
# so they surface as annotations on the run, and as plain text so the log
# is readable when run locally.

import argparse
import pathlib
import sys

import yaml

# GitHub's hard limit on a single run: expression.
HARD_LIMIT = 21000

# Report anything this large as a warning: enough runway to move the
# offending content out of the workflow before it becomes a failure.
SOFT_LIMIT = 18000


def iter_run_steps(doc: object) -> list[tuple[str, str]]:
    """Yield (location, script) for every `run:` step in a parsed file.

    Covers both workflow files (jobs.<id>.steps[]) and composite actions
    (runs.steps[]). Anything that is not shaped like a step list is
    skipped rather than treated as an error: this script only measures
    run steps, it is not a schema validator.
    """
    found = []

    def scan_steps(steps: object, where: str) -> None:
        if not isinstance(steps, list):
            return
        for i, step in enumerate(steps):
            if not isinstance(step, dict):
                continue
            script = step.get("run")
            if not isinstance(script, str):
                continue
            name = step.get("name") or f"step {i + 1}"
            found.append((f"{where} / {name}", script))

    if not isinstance(doc, dict):
        return found

    jobs = doc.get("jobs")
    if isinstance(jobs, dict):
        for job_id, job in jobs.items():
            if isinstance(job, dict):
                scan_steps(job.get("steps"), f"jobs.{job_id}")

    runs = doc.get("runs")
    if isinstance(runs, dict):
        scan_steps(runs.get("steps"), "runs")

    return found


def check_file(path: pathlib.Path) -> tuple[int, int, int]:
    """Lint one file. Returns (errors, warnings, largest run: step)."""
    errors = 0
    warnings = 0
    biggest = 0

    try:
        doc = yaml.safe_load(path.read_text())
    except yaml.YAMLError as exc:
        print(f"::error file={path}::not valid YAML: {exc}")
        return (1, 0, 0)

    for where, script in iter_run_steps(doc):
        biggest = max(biggest, len(script))
        size = len(script)
        if size >= HARD_LIMIT:
            over = size - HARD_LIMIT
            print(f"::error file={path}::{where}: run: step is {size} "
                  f"characters, {over} over GitHub's {HARD_LIMIT} limit. "
                  f"GitHub will refuse to load this file and every run "
                  f"will fail in 0s with zero jobs. Move the bulk of the "
                  f"step out of the workflow - see .github/configs/ for "
                  f"the pattern used by the parallel-make-check.py "
                  f"workflows.")
            errors += 1
        elif size >= SOFT_LIMIT:
            left = HARD_LIMIT - size
            print(f"::warning file={path}::{where}: run: step is {size} "
                  f"characters, only {left} under GitHub's {HARD_LIMIT} "
                  f"limit. Move content out of the workflow now - at the "
                  f"limit the whole file stops loading.")
            warnings += 1

    return (errors, warnings, biggest)


def main() -> int:
    p = argparse.ArgumentParser(
        description="Lint GitHub Actions workflow files for the 21000 "
                    "character per-run-step limit.")
    p.add_argument("paths", nargs="*", metavar="FILE",
                   help="files to check (default: all workflows and "
                        "composite actions under .github/)")
    opts = p.parse_args()

    if opts.paths:
        paths = [pathlib.Path(f) for f in opts.paths]
    else:
        root = pathlib.Path(".github")
        paths = sorted(root.glob("workflows/*.yml"))
        paths += sorted(root.glob("workflows/*.yaml"))
        paths += sorted(root.glob("actions/*/action.yml"))
        paths += sorted(root.glob("actions/*/action.yaml"))

    paths = [f for f in paths if f.is_file()]
    if not paths:
        print("no workflow files found", file=sys.stderr)
        return 1

    errors = 0
    warnings = 0
    biggest = 0
    for path in paths:
        e, w, b = check_file(path)
        errors += e
        warnings += w
        biggest = max(biggest, b)

    print(f"checked {len(paths)} files; largest run: step is {biggest} "
          f"characters (limit {HARD_LIMIT})")
    if errors:
        print(f"FAILED: {errors} step(s) over the limit")
        return 1
    if warnings:
        print(f"{warnings} step(s) approaching the limit")
    return 0


if __name__ == "__main__":
    sys.exit(main())
