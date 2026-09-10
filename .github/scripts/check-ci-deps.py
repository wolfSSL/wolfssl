#!/usr/bin/env python3
# Keeps the prebuilt .deb bundles and the workflows that consume them in step.
#
# .github/workflows/ci-deps-image.yml bundles the .debs for each package list
# in .github/ci-deps/ and publishes it to ghcr; .github/actions/install-apt-deps
# installs from that bundle with no network access. The install is
# all-or-nothing, so a single package a workflow asks for that is not in the
# matching list sends that whole job back to the apt mirror - the exact
# 10-40 minute stall the bundles exist to remove. Nothing about that is visible
# in CI: the job still passes, just slowly and at the mirror's mercy.
#
# So the coupling is checked here instead:
#   * every install-apt-deps call names a bundle tag
#   * the tag exists and matches the runner's Ubuntu release
#   * every requested package is in that tag's list
#   * the lists stay sorted and unique, and match ci-deps-image.yml's matrix
#
# .github/membrowse-targets.json feeds the same action through a matrix, so its
# entries are checked the same way.
#
# Findings are emitted as GitHub workflow commands (::error / ::warning) so
# they surface as annotations, and as plain text so the log reads locally.
# Any error exits non-zero, in --matrix and --sets mode too.

import json
import pathlib
import re
import sys

import yaml

ACTION = "install-apt-deps"
CCACHE_ACTION = "ccache-setup"
CI_DEPS = pathlib.Path(".github/ci-deps")
IMAGE_WORKFLOW = pathlib.Path(".github/workflows/ci-deps-image.yml")
MEMBROWSE_TARGETS = pathlib.Path(".github/membrowse-targets.json")

# The kernel-tracking bundle has no packages-*.txt: its package set is defined
# in ci-deps-image.yml because the rebuild gate hashes it. Read it from there.
LINUXKM_TAG = "ubuntu-24.04-linuxkm"

# Staged for ccache-setup, which installs it from the bundle install-apt-deps
# unpacked rather than naming it in a `packages:` input.
ALWAYS_USED = {"ccache"}

EXPR = re.compile(r"\$\{\{(.+?)\}\}")
MATRIX_REF = re.compile(r"^\s*matrix\.([A-Za-z_][A-Za-z0-9_-]*)\s*$")
# A package name, keeping a shell substitution together: the action interpolates
# `packages` into a run: block, so linux-headers-$(uname -r) reaches apt as one
# argument and the bundle carries it under that same expanded name.
PKG_TOKEN = re.compile(r"\S*\$\([^)]*\)\S*|\S+")


def load_lists() -> dict:
    """tag -> set of packages the bundle for that tag is built from."""
    lists = {}
    for path in sorted(CI_DEPS.glob("packages-*.txt")):
        tag = path.name[len("packages-"):-len(".txt")]
        lists[tag] = [ln.strip() for ln in path.read_text().splitlines()
                      if ln.strip() and not ln.strip().startswith("#")]
    text = IMAGE_WORKFLOW.read_text()
    m = re.search(r'^\s*PKGS="([^"]+)"', text, re.M)
    if m:
        lists[LINUXKM_TAG] = m.group(1).split() + ["linux-headers-$(uname -r)"]
    return lists


def matrix_values(job: dict, name: str) -> list:
    """Every literal value matrix.<name> can take in this job."""
    strategy = job.get("strategy")
    if not isinstance(strategy, dict):
        return []
    matrix = strategy.get("matrix")
    if not isinstance(matrix, dict):
        return []
    out = []
    direct = matrix.get(name)
    if isinstance(direct, list):
        out += [v for v in direct if isinstance(v, str)]
    include = matrix.get("include")
    if isinstance(include, list):
        for entry in include:
            if isinstance(entry, dict) and isinstance(entry.get(name), str):
                out.append(entry[name])
    return out


def resolve(value: object, job: dict) -> list:
    """Expand a `with:` value into the literal strings it can take.

    Returns [] when it depends on something this script cannot see (a
    `fromJson(needs...)` matrix, an input of a reusable workflow); the caller
    reports that as unchecked rather than as a failure.
    """
    if not isinstance(value, str):
        return []
    if "${{" not in value:
        return [value]
    m = EXPR.fullmatch(value.strip())
    if not m:
        return []
    ref = MATRIX_REF.match(m.group(1))
    if not ref:
        return []
    return matrix_values(job, ref.group(1))


def series(text: str) -> str:
    """The ubuntu-XX.YY prefix of a runner label or a bundle tag, or ''."""
    m = re.match(r"(ubuntu-\d+\.\d+)", text or "")
    return m.group(1) if m else ""


class Checker:
    def __init__(self, lists: dict, stream=sys.stdout):
        # --matrix and --sets hand stdout to their caller as data, so findings
        # go to stderr there instead of corrupting it.
        self.stream = stream
        self.lists = lists
        self.errors = 0
        self.warnings = 0
        self.checked = 0
        self.unchecked = []
        self.requested = set()
        # By Ubuntu release, not by tag: -full is documented as a superset of
        # -minimal, so a package only the -minimal callers name is still
        # legitimately carried by -full.
        self.requested_series = {}
        # Distinct (tag, runner, packages) triples, for --matrix.
        self.calls = []

    def error(self, where: str, msg: str) -> None:
        print(f"::error file={where}::{msg}", file=self.stream)
        self.errors += 1

    def warn(self, where: str, msg: str) -> None:
        print(f"::warning file={where}::{msg}", file=self.stream)
        self.warnings += 1

    def check_call(self, where: str, tag: str, packages: str,
                   runner: str) -> None:
        """One (tag, packages) pair, both already resolved to literals."""
        self.checked += 1
        self.calls.append({"tag": tag, "runner": runner or series(tag),
                           "packages": " ".join(PKG_TOKEN.findall(packages))})
        known = self.lists.get(tag)
        if known is None:
            self.error(where, f"ghcr-debs-tag '{tag}' has no package list: "
                              f"add .github/ci-deps/packages-{tag}.txt and a "
                              f"matching matrix entry in {IMAGE_WORKFLOW}")
            return
        if runner and series(runner) and series(tag) \
                and series(runner) != series(tag):
            self.error(where, f"runs-on '{runner}' does not match "
                              f"ghcr-debs-tag '{tag}': the bundle holds .debs "
                              f"for {series(tag)}")
        for pkg in PKG_TOKEN.findall(packages):
            self.requested.add((tag, pkg))
            self.requested_series.setdefault(series(tag), set()).add(pkg)
            if pkg not in known:
                self.error(where, f"'{pkg}' is not in the '{tag}' bundle. The "
                                  f"offline install is all-or-nothing, so this "
                                  f"job always falls back to the apt mirror. "
                                  f"Add it to .github/ci-deps/packages-"
                                  f"{tag}.txt (or point this call at a bundle "
                                  f"that has it).")

    def check_ccache(self, label: str, tags: list, job: dict) -> None:
        """ccache-setup installs ccache from whatever bundle the job unpacked.

        A job that pairs it with a bundle missing ccache, or with no bundle at
        all, reaches the mirror for a 700 KB package. macOS jobs use brew and
        are none of this check's business.
        """
        runners = resolve(job.get("runs-on"), job)
        if any(not r.startswith("ubuntu") for r in runners if r):
            return
        if not tags:
            self.warn(label.split(" / ")[0],
                      f"{label}: uses {CCACHE_ACTION} without a bundled "
                      f"{ACTION} in the same job, so ccache comes from the "
                      f"apt mirror")
            return
        for tag in tags:
            known = self.lists.get(tag)
            if known is not None and "ccache" not in known:
                self.error(label.split(" / ")[0],
                           f"{label}: uses {CCACHE_ACTION} with the '{tag}' "
                           f"bundle, which does not carry ccache; add it to "
                           f".github/ci-deps/packages-{tag}.txt")

    def check_step(self, path: pathlib.Path, job_id: str, job: dict,
                   step: dict, index: int) -> list:
        with_ = step.get("with")
        name = step.get("name") or f"step {index + 1}"
        where = f"{path}"
        label = f"{path} / jobs.{job_id} / {name}"
        if not isinstance(with_, dict):
            self.error(where, f"{label}: {ACTION} called without `with:`")
            return []

        tag_raw = with_.get("ghcr-debs-tag")
        if not tag_raw:
            self.error(where, f"{label}: no ghcr-debs-tag, so this job always "
                              f"installs from the apt mirror. Pick the bundle "
                              f"for its runner (see .github/ci-deps/).")
            return []

        tags = resolve(tag_raw, job)
        packages = resolve(with_.get("packages"), job)
        runners = resolve(job.get("runs-on"), job) or [""]
        if not tags or not packages:
            self.unchecked.append(f"{label}: {tag_raw} / "
                                  f"{with_.get('packages')}")
            return tags
        # A matrix pairs a tag with its packages entry-by-entry; checking the
        # cross product is the conservative reading and costs nothing here.
        for tag in tags:
            for pkgs in packages:
                self.check_call(f"{label}", tag, pkgs, runners[0])
        return tags

    def check_file(self, path: pathlib.Path) -> None:
        try:
            doc = yaml.safe_load(path.read_text())
        except yaml.YAMLError as exc:
            self.error(str(path), f"not valid YAML: {exc}")
            return
        if not isinstance(doc, dict):
            return
        jobs = doc.get("jobs")
        if not isinstance(jobs, dict):
            return
        for job_id, job in jobs.items():
            if not isinstance(job, dict):
                continue
            steps = job.get("steps")
            if not isinstance(steps, list):
                continue
            tags = []
            ccache = False
            for i, step in enumerate(steps):
                if not isinstance(step, dict):
                    continue
                uses = str(step.get("uses") or "")
                if ACTION in uses:
                    tags += self.check_step(path, job_id, job, step, i)
                elif CCACHE_ACTION in uses:
                    ccache = True
            if ccache:
                self.check_ccache(f"{path} / jobs.{job_id}", tags, job)

    def check_membrowse(self) -> None:
        if not MEMBROWSE_TARGETS.is_file():
            return
        try:
            targets = json.loads(MEMBROWSE_TARGETS.read_text())
        except json.JSONDecodeError as exc:
            self.error(str(MEMBROWSE_TARGETS), f"not valid JSON: {exc}")
            return
        if not isinstance(targets, list):
            return
        for entry in targets:
            if not isinstance(entry, dict) or "apt_packages" not in entry:
                continue
            name = entry.get("target_name", "?")
            tag = entry.get("ghcr_tag")
            if not tag:
                self.error(str(MEMBROWSE_TARGETS),
                           f"target '{name}' has apt_packages but no ghcr_tag, "
                           f"so it always installs from the apt mirror")
                continue
            self.check_call(f"{MEMBROWSE_TARGETS} / {name}", tag,
                            entry["apt_packages"], "")

    def check_lists(self) -> None:
        """The lists themselves: sorted, unique, and actually built."""
        built = set()
        try:
            doc = yaml.safe_load(IMAGE_WORKFLOW.read_text())
            include = doc["jobs"]["build"]["strategy"]["matrix"]["include"]
            built = {e["tag"] for e in include if isinstance(e, dict)}
        except (yaml.YAMLError, KeyError, TypeError) as exc:
            self.error(str(IMAGE_WORKFLOW),
                       f"cannot read the bundle matrix: {exc}")
        built.add(LINUXKM_TAG)

        for tag, pkgs in sorted(self.lists.items()):
            if tag == LINUXKM_TAG:
                continue
            path = CI_DEPS / f"packages-{tag}.txt"
            if pkgs != sorted(pkgs):
                self.error(str(path), "package list is not sorted")
            if len(pkgs) != len(set(pkgs)):
                dupes = sorted({p for p in pkgs if pkgs.count(p) > 1})
                self.error(str(path), f"duplicate entries: {' '.join(dupes)}")
            if tag not in built:
                self.error(str(path), f"no bundle is built for '{tag}': add it "
                                      f"to the matrix in {IMAGE_WORKFLOW}")
            used = self.requested_series.get(series(tag), set()) | ALWAYS_USED
            unused = [p for p in pkgs if p not in used]
            if unused:
                self.warn(str(path), f"in the bundle but requested by no "
                                     f"workflow: {' '.join(unused)}")

        for tag in sorted(built):
            if tag not in self.lists:
                self.error(str(IMAGE_WORKFLOW),
                           f"matrix builds '{tag}' but "
                           f".github/ci-deps/packages-{tag}.txt is missing")


def distinct_sets(checker: "Checker") -> dict:
    """tag -> {runner, sets}: every distinct package set that bundle must serve.

    Deduplicated, because most of the ~70 call sites ask for one of a handful
    of package sets.
    """
    out = {}
    for call in checker.calls:
        entry = out.setdefault(call["tag"], {"tag": call["tag"],
                                             "runner": call["runner"],
                                             "sets": []})
        if call["packages"] not in entry["sets"]:
            entry["sets"].append(call["packages"])
    for entry in out.values():
        entry["sets"].sort()
        # The widest set, as the one the canary installs for real.
        entry["probe"] = max(entry["sets"], key=lambda s: len(s.split()))
    return out


def emit_matrix(checker: "Checker") -> None:
    """The ci-deps-canary matrix: one entry per bundle tag."""
    entries = [distinct_sets(checker)[t]
               for t in sorted(distinct_sets(checker))]
    for entry in entries:
        entry.pop("sets", None)
    print(json.dumps(entries))


def emit_sets(checker: "Checker", tag: str) -> int:
    """Every distinct package set requested against one tag, one per line."""
    entry = distinct_sets(checker).get(tag)
    if entry is None:
        print(f"no workflow requests the '{tag}' bundle", file=sys.stderr)
        return 1
    for packages in entry["sets"]:
        print(packages)
    return 0


def main() -> int:
    args = sys.argv[1:]
    matrix = "--matrix" in args
    sets_for = args[args.index("--sets") + 1] if "--sets" in args else None
    if not CI_DEPS.is_dir():
        print(f"{CI_DEPS} not found - run from the repository root",
              file=sys.stderr)
        return 1

    data_mode = matrix or sets_for is not None
    checker = Checker(load_lists(),
                      stream=sys.stderr if data_mode else sys.stdout)
    paths = sorted(pathlib.Path(".github/workflows").rglob("*.yml"))
    paths += sorted(pathlib.Path(".github/workflows").rglob("*.yaml"))
    for path in paths:
        checker.check_file(path)
    checker.check_membrowse()
    if data_mode:
        if matrix:
            emit_matrix(checker)
            rc = 0
        else:
            rc = emit_sets(checker, sets_for)
        if checker.errors:
            print(f"FAILED: {checker.errors} problem(s) - see the ::error "
                  f"lines above", file=sys.stderr)
            return 1
        return rc
    # After every call, so "requested by no workflow" sees the full set.
    checker.check_lists()

    print(f"checked {checker.checked} {ACTION} call(s) against "
          f"{len(checker.lists)} bundle(s)")
    for item in checker.unchecked:
        print(f"  not statically checkable: {item}")
    if checker.errors:
        print(f"FAILED: {checker.errors} problem(s) - each one is a job that "
              f"silently falls back to the apt mirror")
        return 1
    if checker.warnings:
        print(f"{checker.warnings} warning(s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
