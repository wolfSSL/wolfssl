#!/usr/bin/env python3
# Build and "make check" a set of configurations, each in its own out-of-tree
# (VPATH) build directory, on a pool of worker threads (default: one per
# CPU); each thread takes the next pending config as soon as it is free.
# The final summary reports how efficiently the pool used the machine
# (thread occupancy and CPU utilization).
#
# The configurations come from a JSON file ("-" for stdin): a list of
# objects, one per configuration. Recognized keys, all optional except
# "name" (unknown keys are an error, so typos do not pass silently):
#
#   name       unique identifier; the config builds in build-<name>/
#              ("aux" and "test" are reserved: build-aux/, build-test/)
#   configure  list of extra ./configure arguments
#   cc         compiler passed to configure as CC=, overriding --cc
#              ("" leaves CC entirely to configure / the environment)
#   cflags     CFLAGS for make, overriding --cflags
#   ldflags    LDFLAGS for make, overriding --ldflags
#   minutes    expected duration, from the Minutes column of a previous
#              run's summary (default 1.0). Schedule weight only - configs
#              run longest-first and --shard balances shards by it; a stale
#              value just packs the schedule a little worse, but a run
#              whose measured time lands more than +/-50% away from it
#              draws a warning (never a failure) so it is easy to spot
#              and update.
#   user_settings  header staged as <builddir>/user_settings.h before
#              configure (path relative to the source root); pair it with
#              --enable-usersettings in "configure"
#   check      false skips the make-check phase entirely (default true)
#   prepare    list of argv lists run in the build dir before configure
#   run        list of argv lists run in the build dir after the build and
#              checks, e.g. [["wolfcrypt/test/testwolfcrypt"]]
#   comment    ignored; JSON has no comment syntax, so notes go here
#
# The pool is not wolfSSL-specific; these keys let any command ride it:
#
#   build      false skips configure/make/check, so the config is just its
#              prepare+run commands (default true). Use it to run an
#              arbitrary command across the pool.
#   netns      true runs each command under "bwrap --unshare-net" (its own
#              network namespace), so parallel network tests can't collide
#              on ports (default false; needs bubblewrap).
#   shards     fan the config out into N instances run as separate jobs,
#              each with $SHARD (1..N) and $SHARDS=N in its environment and
#              its own build-<name>-<k> dir, so a command can split work
#              N ways (default 1). The pool (--threads) still bounds how
#              many run at once, so N>threads load-balances dynamically.
#
# For example:
#
#   [
#     {"name": "default"},
#     {"name": "all-asan", "configure": ["--enable-all"],
#      "cflags": "-fsanitize=address", "ldflags": "-fsanitize=address"}
#   ]
#
# Driven by CI workflows, which keep their config lists next to the
# invocation (see .github/workflows/smoke-test.yml), but also runnable
# locally - copy the JSON block out of the workflow into a file:
#
#   .github/scripts/parallel-make-check.py configs.json     # all configs
#   .github/scripts/parallel-make-check.py configs.json default all-asan
#   .github/scripts/parallel-make-check.py --list configs.json
#
# Concurrent "make check" runs are safe because the test scripts re-exec
# themselves under "bwrap --unshare-net" when bubblewrap is installed (one
# network namespace each) and the remaining test outputs land in the build
# directory; see --private-dir for the exception.
#
# The first failing config aborts the others (pending configs are skipped,
# in-flight ones get SIGTERM, then SIGKILL after a 10 s grace period) so CI
# fails fast; pass --no-fail-fast to run everything and report every
# failure.

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import NoReturn

# cflags/ldflags are applied at make time only (never to ./configure) so
# autoconf feature detection is not poisoned by benign warnings in
# conftest probes. They are omitted entirely when empty so a plain config
# keeps the configure-chosen defaults.
@dataclass
class Config:
    name: str
    configure: list[str] = field(default_factory=list)
    cc: str = ""
    cflags: str = ""
    ldflags: str = ""
    minutes: float = 1.0
    user_settings: str = ""
    check: bool = True
    prepare: list[list[str]] = field(default_factory=list)
    run: list[list[str]] = field(default_factory=list)
    # Whether "minutes" was given in the JSON (vs the 1.0 default); only an
    # explicit estimate is checked for >50% drift against the real time.
    minutes_provided: bool = False
    # Generic-command extensions. Defaults keep a config behaving as a
    # wolfSSL build. With build=false a config is just its prepare+run
    # commands (no configure/make/check), so any command can ride the pool.
    build: bool = True
    # netns=true runs each command under "bwrap --unshare-net" so parallel
    # network tests can't collide on ports (same isolation as the .test scripts).
    netns: bool = False
    # shards>1 fans the config out into that many instances, each run with
    # $SHARD (1..N) and $SHARDS=N in its environment so the command can pick
    # its slice of the work; each instance gets its own build-<name>-<k> dir.
    shards: int = 1
    # Extra environment for the commands (set by the shard fan-out).
    env: dict[str, str] = field(default_factory=dict)

SRCDIR = Path(__file__).resolve().parents[2]
ON_GITHUB = os.environ.get("GITHUB_ACTIONS") == "true"
# Used by configs with "netns": true to give each command its own network
# namespace (so parallel network tests can't collide on ports).
BWRAP = shutil.which("bwrap")
print_lock = threading.Lock()

# Fail-fast state: the first failure sets stop_event (under fail_lock, so
# exactly one config is reported as the origin) and kills the other
# workers' in-flight process groups.
stop_event = threading.Event()
fail_lock = threading.Lock()
live_procs: set[subprocess.Popen] = set()
procs_lock = threading.Lock()


def kill_group(p: subprocess.Popen, sig: signal.Signals) -> None:
    # Every subprocess starts its own session, so signalling the process
    # group takes down the whole make/test tree under it.
    try:
        os.killpg(p.pid, sig)
    except (ProcessLookupError, PermissionError):
        try:
            p.send_signal(sig)
        except ProcessLookupError:
            pass


def abort_others() -> None:
    with procs_lock:
        procs = list(live_procs)
    for p in procs:
        kill_group(p, signal.SIGTERM)
    # Bounded escalation: SIGKILL whatever ignored the SIGTERM, so
    # fail-fast cannot hang behind a test that traps/ignores SIGTERM.
    deadline = time.monotonic() + 10
    while any(p.poll() is None for p in procs):
        if time.monotonic() > deadline:
            for p in procs:
                if p.poll() is None:
                    kill_group(p, signal.SIGKILL)
            break
        time.sleep(0.2)


def nproc() -> int:
    # Like nproc(1): CPUs usable by this process, falling back to all online.
    try:
        return len(os.sched_getaffinity(0))
    except AttributeError:
        return os.cpu_count() or 1


def load_configs(opts: argparse.Namespace,
                 error: Callable[[str], NoReturn]) -> list[Config]:
    try:
        if opts.json == "-":
            entries = json.load(sys.stdin)
        else:
            entries = json.loads(Path(opts.json).read_text())
    except (OSError, ValueError) as e:
        error(f"{opts.json}: {e}")
    if not isinstance(entries, list):
        error(f"{opts.json}: expected a JSON list of config objects")
    configs = []
    for entry in entries:
        if not isinstance(entry, dict):
            error(f"{opts.json}: config entries must be objects: {entry!r}")
        unknown = set(entry) - {"name", "configure", "cc", "cflags",
                                "ldflags", "minutes", "user_settings",
                                "check", "prepare", "run", "comment",
                                "build", "netns", "shards"}
        if unknown:
            error(f"{opts.json}: unknown key(s) in {entry.get('name', entry)!r}: "
                  f"{' '.join(sorted(unknown))}")
        name = entry.get("name")
        if not isinstance(name, str) or not name or "/" in name:
            error(f"{opts.json}: every config needs a \"name\" usable as a "
                  f"directory suffix: {entry!r}")
        # build-<name> dirs that are not ours to wipe: build-aux/ is
        # autotools' aux-script dir (autogen.sh), build-test/ a legacy
        # build dir (.gitignore).
        if name in ("aux", "test"):
            error(f"{opts.json}: reserved config name {name!r}: build-{name}/ "
                  f"belongs to other tooling")
        if any(cfg.name == name for cfg in configs):
            error(f"{opts.json}: duplicate config name {name!r}")
        configure = entry.get("configure", [])
        if not (isinstance(configure, list)
                and all(isinstance(a, str) for a in configure)):
            error(f"{opts.json}: \"configure\" must be a list of argument "
                  f"strings in {name!r}")
        for key in ("cflags", "ldflags"):
            if not isinstance(entry.get(key, ""), str):
                error(f"{opts.json}: \"{key}\" must be a string in {name!r}")
        minutes = entry.get("minutes", 1.0)
        if isinstance(minutes, bool) or not isinstance(minutes, (int, float)) \
                or minutes < 0:
            error(f"{opts.json}: \"minutes\" must be a non-negative number "
                  f"in {name!r}")
        user_settings = entry.get("user_settings", "")
        if not isinstance(user_settings, str):
            error(f"{opts.json}: \"user_settings\" must be a path string "
                  f"in {name!r}")
        check = entry.get("check", True)
        if not isinstance(check, bool):
            error(f"{opts.json}: \"check\" must be a boolean in {name!r}")
        for key in ("build", "netns"):
            if not isinstance(entry.get(key, False), bool):
                error(f"{opts.json}: \"{key}\" must be a boolean in {name!r}")
        shards = entry.get("shards", 1)
        if isinstance(shards, bool) or not isinstance(shards, int) or shards < 1:
            error(f"{opts.json}: \"shards\" must be an integer >= 1 in {name!r}")
        cc = entry.get("cc", opts.cc or "")
        if not isinstance(cc, str):
            error(f"{opts.json}: \"cc\" must be a string in {name!r}")
        for key in ("prepare", "run"):
            cmds = entry.get(key, [])
            if not (isinstance(cmds, list)
                    and all(isinstance(cmd, list) and cmd
                            and all(isinstance(a, str) for a in cmd)
                            for cmd in cmds)):
                error(f"{opts.json}: \"{key}\" must be a list of argv lists "
                      f"in {name!r}")
        configs.append(Config(name, list(configure), cc,
                              entry.get("cflags", opts.cflags),
                              entry.get("ldflags", opts.ldflags),
                              float(minutes), user_settings, check,
                              list(entry.get("prepare", [])),
                              list(entry.get("run", [])),
                              minutes_provided="minutes" in entry,
                              build=entry.get("build", True),
                              netns=entry.get("netns", False),
                              shards=shards))
    if not configs:
        error(f"{opts.json}: no configs")
    return configs


def privatize_dirs(bdir: Path, dirs: list[str]) -> None:
    # Replace build-tree symlinks into the source tree with private
    # per-build-dir copies: tests that write into these directories would
    # otherwise write through the symlink into the shared source tree and
    # race with the other parallel checks. Runs after the build steps so
    # that build rules which (re)create the symlinks have already run.
    for name in dirs:
        d = bdir / name
        if d.is_symlink():
            d.unlink()
            shutil.copytree(SRCDIR / name, d, symlinks=True)


def gh_escape(data: str) -> str:
    # Percent-encode workflow-command data (GitHub's documented encoding)
    # so a stray %, CR or LF - e.g. from a config name or step out of the
    # JSON - can't truncate the command or be parsed as a second one.
    return data.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def gh_prop(value: str) -> str:
    # A workflow-command property value (file=) escapes ":" and "," on top
    # of the data set above.
    return gh_escape(value).replace(":", "%3A").replace(",", "%2C")


# A ::warning::/::error:: with no file= is pinned by GitHub to the .github
# directory (a dead link). Point annotations at the workflow file that
# carries this config list; GITHUB_WORKFLOW_REF is "owner/repo/path@ref".
def gh_file_prop() -> str:
    ref = os.environ.get("GITHUB_WORKFLOW_REF", "")
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    prefix = f"{repo}/"
    if repo and ref.startswith(prefix):
        path = ref[len(prefix):].rsplit("@", 1)[0]
        if path:
            return f" file={gh_prop(path)}"
    return ""


GH_FILE_PROP = gh_file_prop()


def dump(title: str, path: Path) -> None:
    # ::group:: is a workflow command; escape its title like warn() does.
    print(f"::group::{gh_escape(title)}" if ON_GITHUB else f"==== {title} ====")
    try:
        sys.stdout.write(path.read_text(errors="replace"))
    except OSError as e:
        print(e)
    if ON_GITHUB:
        print("::endgroup::")
    sys.stdout.flush()


def warn(msg: str) -> None:
    # GitHub surfaces ::warning:: as an annotation at the top of the run;
    # locally it is just a line. Informational only - never fails the run.
    print(f"::warning{GH_FILE_PROP}::{gh_escape(msg)}" if ON_GITHUB
          else f"WARNING: {msg}")


def stale_estimate(cfg: Config, minutes: float) -> bool:
    # "minutes" is only a scheduling estimate (configs run longest-first;
    # --shard balances by it), never a pass/fail bound. Flag a finished
    # config whose real time drifted past +/-50% of an explicitly given
    # estimate so stale values - which pack the schedule worse - are easy
    # to find and update. Configs that omit "minutes" ride the 1.0 default
    # placeholder and are left alone.
    return (cfg.minutes_provided
            and not 0.5 * cfg.minutes <= minutes <= 1.5 * cfg.minutes)


def run_config(cfg: Config, opts: argparse.Namespace) -> tuple[str | None,
                                                               float]:
    if opts.fail_fast and stop_event.is_set():
        return "aborted", 0.0
    bdir = SRCDIR / f"build-{cfg.name}"
    if bdir.exists():
        shutil.rmtree(bdir)
    bdir.mkdir()
    configure = [str(SRCDIR / "configure")] + cfg.configure
    if cfg.cc:
        configure.append(f"CC={cfg.cc}")
    flags = [f"CFLAGS={cfg.cflags}"] if cfg.cflags else []
    flags += [f"LDFLAGS={cfg.ldflags}"] if cfg.ldflags else []
    # No -j here: wolfSSL's configure enables make's jobserver by default
    # (AX_AM_JOBSERVER adds AM_MAKEFLAGS += -j<nproc+1>), and that explicit
    # -j on every automake sub-make overrides whatever the top-level make
    # was given, so a -j here would only schedule the outermost recursion
    # hop. Measured across this pool, the jobserver default also utilizes
    # the CPUs better than a capped -j (configs' serial phases - configure,
    # link - get backfilled by other configs' compile jobs).
    make = ["make"] + flags
    steps: list[tuple[str, list[str] | Callable[[], object]]] = []
    if cfg.user_settings:
        # Staged before configure; --enable-usersettings builds pick it up
        # from the build dir via the default include path.
        steps.append((f"stage {cfg.user_settings}",
                      lambda: shutil.copy(SRCDIR / cfg.user_settings,
                                          bdir / "user_settings.h")))
    steps += [(" ".join(cmd), cmd) for cmd in cfg.prepare]
    if cfg.build:
        steps += [("configure", configure), ("make", make)]
        if cfg.check:
            steps += [
                # Prebuild the check programs without running any tests so
                # "make check" below is pure test execution.
                ("make check TESTS=", make + ["check", "TESTS="]),
                ("private dirs", lambda: privatize_dirs(bdir, opts.private_dir)),
                ("make check", ["make"] + flags + ["check"]),
            ]
    steps += [(" ".join(cmd), cmd) for cmd in cfg.run]
    # With "netns", each command runs in its own network namespace; --chdir
    # keeps the build dir as cwd inside the sandbox. CAP_NET_ADMIN lets the
    # command configure that netns (bring interfaces up, add addresses).
    netns = ([BWRAP, "--unshare-net", "--cap-add", "CAP_NET_ADMIN",
              "--dev-bind", "/", "/", "--chdir", str(bdir)]
             if cfg.netns and BWRAP else [])
    failed: str | None = None
    start = time.monotonic()
    log = bdir / "make-check.log"

    def record_failure(step: str) -> str:
        # Classify a failed step, doing the fail-fast bookkeeping: the
        # first failure wins and aborts everyone else; any failure after
        # the abort began is reported as aborted instead.
        if not opts.fail_fast:
            return step
        with fail_lock:
            label = "aborted" if stop_event.is_set() else step
            stop_event.set()
        if label != "aborted":
            abort_others()
        return label

    with open(log, "w") as logf:
        for step, cmd in steps:
            if opts.fail_fast and stop_event.is_set():
                failed = "aborted"
                break
            if callable(cmd):
                try:
                    cmd()
                except Exception as e:  # one config's bug, not the run's
                    print(f"+ {step}: {e!r}", file=logf, flush=True)
                    failed = record_failure(step)
                    break
                continue
            cmd = netns + cmd
            print(f"+ {' '.join(cmd)}", file=logf, flush=True)
            # stdin=DEVNULL so a test that reads stdin sees EOF (as in CI)
            # instead of blocking forever on an interactive/socket stdin.
            proc = subprocess.Popen(cmd, cwd=bdir, stdout=logf,
                                    stderr=subprocess.STDOUT,
                                    stdin=subprocess.DEVNULL,
                                    env={**os.environ, **cfg.env},
                                    start_new_session=True)
            with procs_lock:
                live_procs.add(proc)
            if opts.fail_fast and stop_event.is_set():
                # Close the race with abort_others(): if its sweep ran
                # between our stop_event check above and the registration
                # just now, this process escaped the sweep - kill it
                # ourselves (the wait() below then reaps it), escalating
                # like the sweep does if SIGTERM is ignored.
                kill_group(proc, signal.SIGTERM)
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    kill_group(proc, signal.SIGKILL)
            try:
                rc = proc.wait()
            finally:
                with procs_lock:
                    live_procs.discard(proc)
            if rc != 0:
                failed = record_failure(step)
                break
    minutes = (time.monotonic() - start) / 60
    with print_lock:
        if failed == "aborted":
            print(f"{cfg.name}: aborted (fail-fast) [{minutes:.1f} min]")
            sys.stdout.flush()
        elif not failed:
            # One line per passing config; the full logs would bloat the CI
            # log (they stay in build-<name>/make-check.log).
            print(f"{cfg.name}: pass [{minutes:.1f} min]")
            if stale_estimate(cfg, minutes):
                warn(f"{cfg.name}: ran {minutes:.1f} min but \"minutes\" "
                     f"says {cfg.minutes:g} (>50% off) - update it in the "
                     f"config JSON")
            sys.stdout.flush()
        else:
            dump(f"{cfg.name}: FAIL ({failed}) [{minutes:.1f} min]", log)
            if failed == "configure":
                dump(f"{cfg.name}: config.log", bdir / "config.log")
            elif failed == "make check":
                dump(f"{cfg.name}: test-suite.log", bdir / "test-suite.log")
    return failed, minutes


def summarize(results: list[tuple[Config, str | None, float]],
              wall_min: float, cpu_min: float, nthreads: int) -> None:
    lines = ["| Config | Result | Minutes |", "|---|---|---|"]
    for cfg, failed, minutes in results:
        if failed == "aborted":
            ok = ":heavy_minus_sign: aborted (fail-fast)"
        elif failed:
            ok = f":x: FAIL ({failed})"
        else:
            ok = ":white_check_mark: pass"
            if stale_estimate(cfg, minutes):
                # Non-fatal nudge mirroring the per-config warning, kept in
                # the summary next to the Minutes value to copy over.
                ok += (f' :warning: "minutes" {cfg.minutes:g} is >50% off, '
                       f"update to ~{minutes:.1f}")
        lines.append(f"| {cfg.name} | {ok} | {minutes:.1f} |")
    # Two views of how efficiently the pool used the machine: thread
    # occupancy is the time the workers spent running configs out of the
    # thread-minutes available (a long config left for last idles the other
    # workers and drags it down); CPU utilization is the CPU time the build
    # and test children actually consumed out of the CPU-minutes available
    # (serial configure/link/test phases show up here).
    busy_min = sum(minutes for _, _, minutes in results)
    ncpu = nproc()
    thread_min = wall_min * nthreads
    cpu_avail = wall_min * ncpu
    # Guard the ratios against a zero wall time (e.g. every job a no-op, which
    # can happen when there are more shards than work) so the line never
    # divides by zero.
    occupancy = 100 * busy_min / thread_min if thread_min else 0
    cpu_util = 100 * cpu_min / cpu_avail if cpu_avail else 0
    lines += [
        "",
        f"{len(results)} configs in {wall_min:.1f} min on {nthreads} "
        f"threads / {ncpu} CPUs: "
        f"thread occupancy {occupancy:.0f}% "
        f"({busy_min:.1f} of {thread_min:.1f} thread-min), "
        f"CPU utilization {cpu_util:.0f}% "
        f"({cpu_min:.1f} of {cpu_avail:.1f} CPU-min)",
    ]
    table = "\n".join(lines)
    print(table)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as f:
            print(f"### make check\n\n{table}", file=f)


def shard_instances(cfg: Config) -> list[Config]:
    # A config that asks for shards>1 becomes that many independent jobs: each
    # gets its index as $SHARD (1..N) / $SHARDS=N and its own build-<name>-<k>
    # dir, so its command can run one slice of the work. A config with the
    # default shards=1 is left as a single unchanged job.
    if cfg.shards <= 1:
        return [cfg]
    return [replace(cfg, name=f"{cfg.name}-{k}", shards=1,
                    env={**cfg.env, "SHARD": str(k), "SHARDS": str(cfg.shards)})
            for k in range(1, cfg.shards + 1)]


def main() -> int:
    p = argparse.ArgumentParser(
        description="Build and make check every configuration from a JSON "
                    "file in its own out-of-tree build directory, in "
                    "parallel.")
    p.add_argument("json", metavar="CONFIGS.json",
                   help="JSON list of configs (see the script header for "
                        "the format), or - for stdin")
    p.add_argument("configs", nargs="*", metavar="NAME",
                   help="configs to run (default: all)")
    p.add_argument("--list", action="store_true", help="list configs")
    p.add_argument("--threads", type=int, default=nproc(),
                   help="worker threads; each takes the next pending config "
                        "when it is free (default: nproc)")
    p.add_argument("--shard", metavar="K/N",
                   help="run only the K-th (1-based) of N shards; configs "
                        "are dealt to shards greedily by descending "
                        "\"minutes\" so the shards' totals come out even")
    p.add_argument("--fail-fast", action=argparse.BooleanOptionalAction,
                   default=True,
                   help="abort everything after the first failing config: "
                        "pending configs are skipped and in-flight ones "
                        "killed (--no-fail-fast runs everything and "
                        "reports every failure)")
    p.add_argument("--cc", default="ccache gcc" if shutil.which("ccache")
                   else None,
                   help="compiler passed to configure as CC= for configs "
                        "that do not set their own \"cc\"")
    p.add_argument("--cflags", default="",
                   help="CFLAGS for configs that do not set their own")
    p.add_argument("--ldflags", default="",
                   help="LDFLAGS for configs that do not set their own")
    p.add_argument("--private-dir", action="append", default=[],
                   metavar="DIR",
                   help="give each build dir a private copy of this "
                        "symlinked source directory before make check, for "
                        "tests that write into it (repeatable)")
    p.add_argument("--build-only", action="store_true",
                   help="build every config but skip the make-check phase "
                        "and any post-build \"run\" commands: the compile "
                        "still populates ccache, which is the point when "
                        "seeding a shared cache on a schedule")
    opts = p.parse_args()

    all_configs = load_configs(opts, p.error)
    if opts.build_only:
        # Pure build: drop the check phase (and post-build "run" steps) for
        # every config. The compile alone fully populates ccache, so a
        # scheduled --build-only pass on the default branch warms the
        # shared cache that PR runs restore, without spending time on tests.
        for cfg in all_configs:
            cfg.check = False
            cfg.run = []
    selected = all_configs
    if opts.configs:
        by_name = {cfg.name: cfg for cfg in all_configs}
        unknown = [n for n in opts.configs if n not in by_name]
        if unknown:
            p.error(f"unknown config(s): {' '.join(unknown)}")
        selected = [by_name[n] for n in opts.configs]

    # Longest first, so the heavyweights never straggle on an otherwise
    # idle machine. Stable: configs without "minutes" keep list order.
    selected = sorted(selected, key=lambda cfg: -cfg.minutes)
    if opts.shard:
        try:
            k, n = map(int, opts.shard.split("/"))
        except ValueError:
            k = n = 0
        if not 1 <= k <= n:
            p.error(f"--shard: expected K/N with 1 <= K <= N, "
                    f"got {opts.shard!r}")
        # Greedy multiway partition: longest first into the least-loaded
        # shard. Deterministic; if the "minutes" are accurate, the worst
        # shard ends up within about one config's minutes of optimal.
        shards, loads = [[] for _ in range(n)], [0.0] * n
        for cfg in selected:
            i = loads.index(min(loads))
            shards[i].append(cfg)
            loads[i] += cfg.minutes
        selected = shards[k - 1]

    # Replace each config with its shard instances (a no-op for shards=1),
    # then re-sort so the pool still takes the longest jobs first. Done after
    # --shard so a CI-level split and in-job fan-out compose.
    expanded = []
    for cfg in selected:
        expanded.extend(shard_instances(cfg))
    expanded.sort(key=lambda cfg: -cfg.minutes)
    selected = expanded

    # A fanned-out name (<name>-<k>) could collide with another config's name,
    # which would make two jobs share a build-<name> dir and race. Catch it,
    # like the duplicate-name check in load_configs.
    names = [cfg.name for cfg in selected]
    dups = sorted({n for n in names if names.count(n) > 1})
    if dups:
        p.error(f"config names collide after shard fan-out: {' '.join(dups)}")

    # netns needs bwrap; without it commands silently share the host network
    # namespace and parallel network tests collide on ports. On CI that silent
    # degradation is a misconfiguration, so fail loudly; locally just warn and
    # let the run fall back to the shared namespace. --list needs neither bwrap
    # nor a netns, so never block it.
    if not opts.list and any(cfg.netns for cfg in selected) and not BWRAP:
        msg = ("netns requested but bwrap not found; install bubblewrap "
               "(without it commands share the host network namespace and "
               "collide on ports)")
        if ON_GITHUB:
            p.error(msg)
        warn(f"{msg}; falling back to the shared namespace")

    if opts.list:
        for cfg in selected:
            print(f"{cfg.name} [{cfg.minutes:g} min]: "
                  f"{' '.join(cfg.configure)}")
        return 0
    if not selected:
        print(f"shard {opts.shard}: no configs to run")
        return 0

    if any(cfg.build for cfg in selected) and not (SRCDIR / "configure").exists():
        subprocess.run(["./autogen.sh"], cwd=SRCDIR, check=True)

    nthreads = max(1, min(opts.threads, len(selected)))
    wall_start = time.monotonic()
    cpu_start = os.times()
    def run_one(cfg: Config) -> tuple[Config, str | None, float]:
        failed, minutes = run_config(cfg, opts)
        return cfg, failed, minutes

    with ThreadPoolExecutor(max_workers=nthreads) as pool:
        results = list(pool.map(run_one, selected))
    wall_min = (time.monotonic() - wall_start) / 60
    cpu_end = os.times()
    # os.times() child counters cover the waited-for configure/make
    # subprocesses of every worker thread.
    cpu_min = (cpu_end.children_user - cpu_start.children_user
               + cpu_end.children_system - cpu_start.children_system) / 60
    summarize(results, wall_min, cpu_min, nthreads)
    failed = [cfg.name for cfg, failure, _ in results
              if failure and failure != "aborted"]
    aborted = sum(1 for _, failure, _ in results if failure == "aborted")
    if failed or aborted:
        msg = f"make check failed for: {' '.join(failed)}" if failed \
            else "aborted without a recorded failure"
        if aborted:
            msg += f" ({aborted} config(s) aborted by fail-fast)"
        print(f"::error{GH_FILE_PROP}::{gh_escape(msg)}" if ON_GITHUB else msg)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
