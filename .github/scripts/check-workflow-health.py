#!/usr/bin/env python3
# Detect workflows that GitHub is failing to load, and track them in a
# single GitHub issue.
#
# When GitHub cannot load a workflow file it does not report a normal
# failure: the run ends within 0s with zero jobs, no logs, no annotations
# and no check runs. Among a few hundred other checks that is effectively
# invisible - os-check.yml sat broken on master for ten days in July 2026
# before anyone noticed.
#
# .github/scripts/check-workflows.py guards the one cause we know about
# (the 21000 character per-run-step cap) before a change merges. This
# script is the net underneath it: it looks for the *symptom* rather than
# any particular cause, so a workflow that stops loading for a reason
# nobody anticipated still gets caught.
#
# Two signals, both cheap:
#
#   1. An active workflow whose registered name equals its path. GitHub
#      stores a workflow's `name:` field once it has parsed the file, and
#      resets it to the bare path when it cannot. This catches regressions
#      as well as files that never parsed: os-check.yml was registered as
#      "Ubuntu-Macos-Windows Tests" until it broke, then reverted to
#      ".github/workflows/os-check.yml".
#
#   2. A completed run that failed with zero jobs. Prefiltered on
#      created_at == updated_at (a load failure takes no measurable time)
#      so only a handful of runs need the extra jobs lookup.
#
# Findings are reported into one issue, reused across runs: the body is
# rewritten each time, a comment is added only when the set of affected
# workflows actually changes, and the issue is closed automatically once
# everything loads again. That keeps a persistent problem from generating
# daily notification noise while still making a new one loud.
#
# Requires the gh CLI, authenticated (GH_TOKEN / GITHUB_TOKEN).
#
# Exit status:
#   0  every workflow loads
#   1  at least one workflow is failing to load
#   2  the check could not be carried out (gh call failed: no token, a
#      revoked scope, an API outage). Distinct from 1 on purpose - "I
#      found a problem" and "I could not look" need different responses.

import argparse
import json
import subprocess
import sys
import time

MARKER_PREFIX = "<!-- workflow-health:"
MARKER_SUFFIX = "-->"

ISSUE_TITLE = "CI: one or more workflows are failing to load"

# The tracking issue is found by this label through the REST issues
# endpoint, never by searching the title and never via `gh issue list`.
# Title search is unusable outright: it runs off an asynchronous index
# and, worse, ignores --state, so it hands back closed issues and the
# monitor re-closes them forever. `gh issue list` uses GraphQL and can
# read a replica that has not caught up.
#
# The REST endpoint is not instantaneous either - a freshly created issue
# took ~2.4s to appear when measured against a live repository - so
# find_open_issue() re-checks rather than trusting one empty answer.
ISSUE_LABEL = "workflow-health"


def gh_api(path: str) -> object:
    """GET a REST endpoint via the gh CLI and return parsed JSON."""
    out = subprocess.run(["gh", "api", "-H", "Accept: application/vnd.github+json",
                          path],
                         capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f"gh api {path} failed: {out.stderr.strip()}")
    return json.loads(out.stdout)


def gh_json(args: list[str]) -> object:
    out = subprocess.run(["gh"] + args, capture_output=True, text=True)
    if out.returncode != 0:
        raise RuntimeError(f"gh {' '.join(args)} failed: {out.stderr.strip()}")
    return json.loads(out.stdout) if out.stdout.strip() else None


def unloadable_workflows(repo: str) -> list[dict]:
    """Signal 1: active workflows whose name is just their path."""
    bad = []
    page = 1
    while True:
        data = gh_api(f"repos/{repo}/actions/workflows"
                      f"?per_page=100&page={page}")
        items = data.get("workflows", []) if isinstance(data, dict) else []
        for wf in items:
            if wf.get("state") != "active":
                continue
            if wf.get("name") == wf.get("path"):
                bad.append({"path": wf["path"],
                            "why": "registered name is the bare file path, "
                                   "so GitHub has not parsed this file"})
        if len(items) < 100:
            break
        page += 1
    return bad


def zero_job_failures(repo: str, scan: int) -> list[dict]:
    """Signal 2: recent completed runs that failed with no jobs at all."""
    bad = {}
    seen = 0
    page = 1
    # Paginate rather than clamping to one page: a caller asking for more
    # runs than fit in a single response should get them, not a quietly
    # truncated scan that looks like full coverage.
    while seen < scan:
        data = gh_api(f"repos/{repo}/actions/runs"
                      f"?status=completed&per_page=100&page={page}")
        runs = data.get("workflow_runs", []) if isinstance(data, dict) else []
        if not runs:
            break
        for run in runs[:scan - seen]:
            if run.get("conclusion") != "failure":
                continue
            # A load failure never starts: it is created and completed in
            # the same instant. Anything that actually ran is not this.
            if run.get("created_at") != run.get("updated_at"):
                continue
            jobs = gh_api(f"repos/{repo}/actions/runs/{run['id']}/jobs")
            if not isinstance(jobs, dict) or jobs.get("total_count", 1) != 0:
                continue
            path = run.get("path", "?")
            bad.setdefault(path, {
                "path": path,
                "why": f"run {run['id']} on {run.get('head_branch', '?')} "
                       f"completed as a failure with zero jobs",
            })
        seen += len(runs)
        if len(runs) < 100:
            break
        page += 1
    return list(bad.values())


def build_body(findings: list[dict], repo: str) -> str:
    paths = sorted({f["path"] for f in findings})
    marker = f"{MARKER_PREFIX} {','.join(paths)} {MARKER_SUFFIX}"
    lines = [
        marker,
        "",
        "One or more workflow files are not being loaded by GitHub "
        "Actions. A workflow in this state does **not** fail loudly: its "
        "runs complete within 0s with zero jobs, no logs, no annotations "
        "and no check runs, so it looks like unrelated flake among the "
        "other checks while the coverage it provides is silently gone.",
        "",
        "| Workflow | Detected by |",
        "|---|---|",
    ]
    for f in sorted(findings, key=lambda x: x["path"]):
        lines.append(f"| `{f['path']}` | {f['why']} |")
    lines += [
        "",
        "### What to check first",
        "",
        "GitHub caps a single `run:` step at 21000 characters and refuses "
        "to load the whole file past that. Run "
        "`.github/scripts/check-workflows.py` locally to test for it - "
        "that is what broke `os-check.yml` for ten days in July 2026. "
        "If the file is under the cap, the cause is something else; the "
        "Actions service does not report which.",
        "",
        f"Opened automatically by `.github/workflows/workflow-health.yml` "
        f"in {repo}. It closes itself once every workflow loads again.",
    ]
    return "\n".join(lines)


def marker_of(body: str) -> str:
    for line in (body or "").splitlines():
        line = line.strip()
        if line.startswith(MARKER_PREFIX):
            return line
    return ""


def ensure_label(repo: str) -> None:
    """Create the tracking label if the repository does not have it."""
    subprocess.run(["gh", "label", "create", ISSUE_LABEL, "--repo", repo,
                    "--color", "B60205",
                    "--description",
                    "A workflow file is not being loaded by GitHub Actions"],
                   capture_output=True, text=True)


def find_open_issue(repo: str, attempts: int = 1,
                    delay: float = 2.0) -> dict | None:
    """The open tracking issue, or None.

    Looked up by label through the REST issues endpoint - see ISSUE_LABEL
    for why neither search nor `gh issue list` is usable here. The state
    is re-checked on the result so a closed issue can never be picked up
    and re-closed on every subsequent clean run.

    The title must match as well as the label. The label alone is not
    proof of ownership: it is a normal repository label that anyone can
    apply, and an adopted issue has its body overwritten wholesale and is
    then closed, so a mislabelled one would lose its content. Requiring
    the title means the worst case of someone retitling this issue is a
    duplicate being opened, which is recoverable, rather than an
    unrelated issue being destroyed, which is not.

    Even this endpoint is only eventually consistent: a freshly created
    issue took ~2.4s to become visible when measured against a live
    repository, so `attempts` re-checks before concluding nothing is
    open.
    """
    for attempt in range(attempts):
        issues = gh_api(f"repos/{repo}/issues"
                        f"?state=open&labels={ISSUE_LABEL}&per_page=50")
        if isinstance(issues, list):
            for issue in issues:
                # This endpoint returns pull requests as well.
                if "pull_request" in issue:
                    continue
                if str(issue.get("state", "")).lower() != "open":
                    continue
                if issue.get("title") != ISSUE_TITLE:
                    continue
                return {"number": issue["number"],
                        "title": issue.get("title", ""),
                        "body": issue.get("body") or ""}
        if attempt + 1 < attempts:
            time.sleep(delay)
    return None


def manage_issue(repo: str, findings: list[dict]) -> int:
    """Reconcile the tracking issue with the current findings.

    Returns the process exit status: non-zero while anything is still
    failing to load, so the scheduled run itself goes red as a backstop
    behind the issue.
    """
    # Re-check on both paths. A stale "no open issue" opens a duplicate
    # when there are findings, and silently skips closing a just-opened
    # issue when there are none. A few seconds once a day is nothing
    # against either.
    issue = find_open_issue(repo, attempts=4)

    if not findings:
        if issue:
            subprocess.run(["gh", "issue", "comment", str(issue["number"]),
                            "--repo", repo, "--body",
                            "Every workflow loads again. Closing."],
                           check=True, capture_output=True, text=True)
            subprocess.run(["gh", "issue", "close", str(issue["number"]),
                            "--repo", repo],
                           check=True, capture_output=True, text=True)
            print(f"closed issue #{issue['number']}")
        else:
            print("nothing to report and no open issue")
        return 0

    body = build_body(findings, repo)

    if issue is None:
        ensure_label(repo)
        out = subprocess.run(["gh", "issue", "create", "--repo", repo,
                              "--title", ISSUE_TITLE, "--body", body,
                              "--label", ISSUE_LABEL],
                             capture_output=True, text=True)
        if out.returncode != 0:
            print(f"failed to open issue: {out.stderr.strip()}",
                  file=sys.stderr)
            return 1
        print(f"opened issue: {out.stdout.strip()}")
        return 1

    changed = marker_of(issue.get("body", "")) != marker_of(body)
    subprocess.run(["gh", "issue", "edit", str(issue["number"]),
                    "--repo", repo, "--body", body],
                   check=True, capture_output=True, text=True)
    if changed:
        # Only notify when the affected set actually moved - a standing
        # problem should not generate a comment on every scheduled run.
        subprocess.run(["gh", "issue", "comment", str(issue["number"]),
                        "--repo", repo, "--body",
                        "The set of workflows failing to load has changed; "
                        "the issue body above lists the current state."],
                       check=True, capture_output=True, text=True)
        print(f"updated issue #{issue['number']} (set changed)")
    else:
        print(f"issue #{issue['number']} already tracks this; no comment")
    return 1


def run(opts: argparse.Namespace) -> int:
    """Collect findings and reconcile the issue. See main() for exits."""
    findings = unloadable_workflows(opts.repo)
    seen = {f["path"] for f in findings}
    for f in zero_job_failures(opts.repo, opts.scan_runs):
        if f["path"] not in seen:
            findings.append(f)

    if findings:
        print(f"{len(findings)} workflow(s) failing to load:")
        for f in sorted(findings, key=lambda x: x["path"]):
            print(f"  {f['path']}: {f['why']}")
    else:
        print("all workflows load cleanly")

    if opts.report_only:
        return 1 if findings else 0

    return manage_issue(opts.repo, findings)


def main() -> int:
    p = argparse.ArgumentParser(
        description="Detect workflows GitHub is failing to load.")
    p.add_argument("--repo", required=True, metavar="OWNER/REPO")
    p.add_argument("--scan-runs", type=int, default=100,
                   help="how many recent completed runs to inspect for "
                        "zero-job failures (default 100)")
    p.add_argument("--report-only", action="store_true",
                   help="print findings and exit; do not touch issues")
    opts = p.parse_args()

    try:
        return run(opts)
    except (RuntimeError, subprocess.CalledProcessError) as exc:
        # A failed gh call means the monitor could not do its job - a
        # missing token, a revoked scope, an API outage. Say so in one
        # line and exit 2: a traceback here reads like a bug in this
        # script, and exiting 1 would be indistinguishable from having
        # actually found a broken workflow.
        print(f"error: could not query {opts.repo}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
