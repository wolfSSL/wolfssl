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
#   * a job's worst-case apt setup fits in its timeout-minutes, and every
#     parallel-make-check.py call has a --deadline that fits after it
#
# Findings are emitted as GitHub workflow commands (::error / ::warning)
# so they surface as annotations on the run, and as plain text so the log
# is readable when run locally.

import argparse
import functools
import pathlib
import re
import sys

import yaml

# GitHub's hard limit on a single run: expression.
HARD_LIMIT = 21000

# Report anything this large as a warning: enough runway to move the
# offending content out of the workflow before it becomes a failure.
SOFT_LIMIT = 18000

# Seconds of timeout-minutes left for checkout and the build after setup.
SETUP_MARGIN = 120

# Seconds left around a parallel-make-check --deadline for the steps before
# it (setup-python, brew) and after it (logs, cache save).
DEADLINE_MARGIN = 300

# apt-install.sh's split_budget() limits and kill grace.
UPDATE_MIN, UPDATE_MAX, INSTALL_MIN, KILL_GRACE = 20, 90, 40, 10

# The apt-install.sh limits ccache-setup falls back to.
CCACHE_APT = {"tries": 2, "update": 60, "install": 90}

ACTIONS = pathlib.Path(__file__).resolve().parent.parent / "actions"
PMC_OPTION = re.compile(r"--(timeout|deadline)[= ]\s*['\"]?([^\s'\"\\]+)")
APT_OPTION = re.compile(r"--(tries|budget|delay|update-timeout|"
                        r"install-timeout)[= ]\s*['\"]?([^\s'\"\\]+)")


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


@functools.cache
def apt_defaults() -> dict:
    """The install-apt-deps input defaults, read from the action itself."""
    doc = yaml.safe_load((ACTIONS / "install-apt-deps" / "action.yml")
                         .read_text())
    return {k: v.get("default", "") for k, v in doc["inputs"].items()}


def apt_install_worst(tries: int, budget: int = 0, delay: int = 5,
                      update: int = 90, install: int = 300) -> int:
    """Worst-case seconds of apt-install.sh, replaying its budget split."""
    spent = 0
    for n in range(1, tries + 1):
        up, inst = update, install
        if budget:
            per = int((budget - spent) / (tries - n + 1))
            up = min(UPDATE_MAX, max(UPDATE_MIN, int(per / 2)))
            inst = max(INSTALL_MIN, per - up)
        spent += up + inst + 2 * KILL_GRACE
        if n < tries:
            spent += delay
            delay *= 2
    return spent


def apt_worst(inputs: dict) -> int:
    """Worst-case seconds of one install-apt-deps step, or -1 if unknown."""
    try:
        pull = int(inputs["pull-timeout"]) + KILL_GRACE
        worst = apt_install_worst(int(inputs["retries"]),
                                  int(inputs["budget-seconds"]),
                                  int(inputs["retry-delay"]))
    except (KeyError, TypeError, ValueError):
        return -1
    return worst + (pull if inputs.get("ghcr-debs-tag") else 0)


def invocations(run: object, name: str) -> list:
    """The rest of the command line after each mention of name in a script."""
    script = "\n".join(line for line in str(run or "").splitlines()
                       if not line.lstrip().startswith("#"))
    return [re.split(r"(?<!\\)\n", part, maxsplit=1)[0]
            for part in script.split(name)[1:]]


def check_timeouts(path: pathlib.Path, doc: object, defaults: dict) -> int:
    """Check each job's apt setup and run deadlines against timeout-minutes."""
    errors = 0
    jobs = doc.get("jobs") if isinstance(doc, dict) else None
    if not isinstance(jobs, dict):
        return 0

    def error(where: str, msg: str) -> None:
        nonlocal errors
        print(f"::error file={path}::{where}: {msg}")
        errors += 1

    for job_id, job in jobs.items():
        if not isinstance(job, dict) or not isinstance(job.get("steps"), list):
            continue
        always = 0
        # install-apt-deps steps behind different if: texts are taken as
        # alternatives; steps behind the same one add up.
        branches: dict[str, int] = {}
        runs = []
        for i, step in enumerate(job["steps"]):
            if not isinstance(step, dict):
                continue
            where = f"jobs.{job_id} / {step.get('name') or f'step {i + 1}'}"
            run = step.get("run")
            for cmd in invocations(run, "parallel-make-check.py"):
                runs.append((where, dict(PMC_OPTION.findall(cmd))))
            for cmd in invocations(run, "apt-install.sh"):
                opts = dict(APT_OPTION.findall(cmd))
                try:
                    always += apt_install_worst(
                        int(opts.pop("tries", 3)),
                        **{k.split("-")[0]: int(v) for k, v in opts.items()})
                except ValueError:
                    error(where, "give apt-install.sh's options literal "
                                 "numbers so the setup budget can be checked")
            uses = str(step.get("uses") or "")
            if uses.endswith("/install-apt-deps"):
                with_ = step.get("with")
                cost = apt_worst({**defaults,
                                  **(with_ if isinstance(with_, dict)
                                     else {})})
                if cost < 0:
                    error(where, "give retries, retry-delay, budget-seconds "
                                 "and pull-timeout literal numbers so the "
                                 "setup budget can be checked")
                elif "if" in step:
                    cond = str(step["if"])
                    branches[cond] = branches.get(cond, 0) + cost
                else:
                    always += cost
            elif uses.endswith("/ccache-setup") \
                    and "macos" not in str(job.get("runs-on", "")):
                always += apt_install_worst(**CCACHE_APT)
        setup = always + max(branches.values(), default=0)

        limit = job.get("timeout-minutes", 360)
        fixed = isinstance(limit, (int, float))
        if fixed and setup and setup + SETUP_MARGIN > limit * 60:
            need = -(-(setup + SETUP_MARGIN) // 60)
            error(f"jobs.{job_id}",
                  f"apt setup can take {setup}s against a slow or dead "
                  f"mirror, which leaves no room in timeout-minutes: {limit}. "
                  f"The job is then cancelled instead of failing with the "
                  f"apt error. Raise timeout-minutes to at least {need}, or "
                  f"lower budget-seconds / pull-timeout.")

        deadlines = 0.0
        for where, opts in runs:
            traw, draw = opts.get("timeout", ""), opts.get("deadline", "")
            if "$" in traw + draw:
                print(f"::warning file={path}::{where}: --timeout/--deadline "
                      f"is not a literal, so it is not checked")
                continue
            try:
                timeout, deadline = float(traw), float(draw)
            except ValueError:
                timeout = deadline = -1.0
            if timeout <= 0 or deadline <= 0 or timeout > deadline:
                error(where, f"parallel-make-check.py needs --timeout and "
                             f"--deadline above 0 with --timeout no larger, "
                             f"got --timeout='{traw}' --deadline='{draw}'. "
                             f"Without them a wedged config runs into "
                             f"timeout-minutes, which cancels the job and "
                             f"loses every config's log.")
                continue
            deadlines += deadline
            need = -(-(setup + deadlines * 60 + DEADLINE_MARGIN) // 60)
            if fixed and need > limit:
                error(where, f"--deadline={draw} plus {setup}s of worst-case "
                             f"apt setup does not fit timeout-minutes: "
                             f"{limit}, so the job can be cancelled before "
                             f"the deadline fires. Raise timeout-minutes to "
                             f"at least {int(need)}, or lower --deadline.")

    return errors


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

    errors += check_timeouts(path, doc, apt_defaults())

    return (errors, warnings, biggest)


def main() -> int:
    p = argparse.ArgumentParser(
        description="Lint GitHub Actions workflow files for the 21000 "
                    "character per-run-step limit and job time budgets.")
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
        print(f"FAILED: {errors} error(s)")
        return 1
    if warnings:
        print(f"{warnings} step(s) approaching the limit")
    return 0


if __name__ == "__main__":
    sys.exit(main())
