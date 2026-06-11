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
#   configure  list of extra ./configure arguments
#   cc         compiler passed to configure as CC=, overriding --cc
#              ("" leaves CC entirely to configure / the environment)
#   cflags     CFLAGS for make, overriding --cflags
#   ldflags    LDFLAGS for make, overriding --ldflags
#   minutes    expected duration, from the Minutes column of a previous
#              run's summary (default 1.0). Schedule weight only - configs
#              run longest-first and --shard balances shards by it; a stale
#              value just packs the schedule a little worse.
#   user_settings  header staged as <builddir>/user_settings.h before
#              configure (path relative to the source root); pair it with
#              --enable-usersettings in "configure"
#   check      false skips the make-check phase entirely (default true)
#   prepare    list of argv lists run in the build dir before configure
#   run        list of argv lists run in the build dir after the build and
#              checks, e.g. [["wolfcrypt/test/testwolfcrypt"]]
#   comment    ignored; JSON has no comment syntax, so notes go here
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
# in-flight ones are killed) so CI fails fast; pass --no-fail-fast to run
# everything and report every failure.

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

# cflags/ldflags are applied at make time only (never to ./configure) so
# autoconf feature detection is not poisoned by benign warnings in
# conftest probes. They are omitted entirely when empty so a plain config
# keeps the configure-chosen defaults.
@dataclass
class Config:
    name: str
    configure: list = field(default_factory=list)
    cc: str = ""
    cflags: str = ""
    ldflags: str = ""
    minutes: float = 1.0
    user_settings: str = ""
    check: bool = True
    prepare: list = field(default_factory=list)
    run: list = field(default_factory=list)

SRCDIR = Path(__file__).resolve().parents[2]
ON_GITHUB = os.environ.get("GITHUB_ACTIONS") == "true"
print_lock = threading.Lock()

# Fail-fast state: the first failure sets stop_event (under fail_lock, so
# exactly one config is reported as the origin) and kills the other
# workers' in-flight process groups.
stop_event = threading.Event()
fail_lock = threading.Lock()
live_procs = set()
procs_lock = threading.Lock()


def abort_others():
    # Every subprocess starts its own session, so killing the process
    # group takes down the whole make/test tree under it.
    with procs_lock:
        procs = list(live_procs)
    for p in procs:
        try:
            os.killpg(p.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass


def nproc():
    # Like nproc(1): CPUs usable by this process, falling back to all online.
    try:
        return len(os.sched_getaffinity(0))
    except AttributeError:
        return os.cpu_count() or 1


def load_configs(opts, error):
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
                                "check", "prepare", "run", "comment"}
        if unknown:
            error(f"{opts.json}: unknown key(s) in {entry.get('name', entry)!r}: "
                  f"{' '.join(sorted(unknown))}")
        name = entry.get("name")
        if not isinstance(name, str) or not name or "/" in name:
            error(f"{opts.json}: every config needs a \"name\" usable as a "
                  f"directory suffix: {entry!r}")
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
                              list(entry.get("run", []))))
    if not configs:
        error(f"{opts.json}: no configs")
    return configs


def privatize_dirs(bdir, dirs):
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


def dump(title, path):
    print(f"::group::{title}" if ON_GITHUB else f"==== {title} ====")
    try:
        sys.stdout.write(path.read_text(errors="replace"))
    except OSError as e:
        print(e)
    if ON_GITHUB:
        print("::endgroup::")
    sys.stdout.flush()


def run_config(cfg, opts):
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
    make = ["make", f"-j{opts.jobs}"] + flags
    steps = []
    if cfg.user_settings:
        # Staged before configure; --enable-usersettings builds pick it up
        # from the build dir via the default include path.
        steps.append((f"stage {cfg.user_settings}",
                      lambda: shutil.copy(SRCDIR / cfg.user_settings,
                                          bdir / "user_settings.h")))
    steps += [(" ".join(cmd), cmd) for cmd in cfg.prepare]
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
    failed = None
    start = time.monotonic()
    log = bdir / "make-check.log"
    with open(log, "w") as logf:
        for step, cmd in steps:
            if opts.fail_fast and stop_event.is_set():
                failed = "aborted"
                break
            if callable(cmd):
                cmd()
                continue
            print(f"+ {' '.join(cmd)}", file=logf, flush=True)
            # stdin=DEVNULL so a test that reads stdin sees EOF (as in CI)
            # instead of blocking forever on an interactive/socket stdin.
            proc = subprocess.Popen(cmd, cwd=bdir, stdout=logf,
                                    stderr=subprocess.STDOUT,
                                    stdin=subprocess.DEVNULL,
                                    start_new_session=True)
            with procs_lock:
                live_procs.add(proc)
            try:
                rc = proc.wait()
            finally:
                with procs_lock:
                    live_procs.discard(proc)
            if rc != 0:
                if opts.fail_fast:
                    # The first failure wins; any nonzero exit after the
                    # abort began was most likely our SIGTERM.
                    with fail_lock:
                        failed = "aborted" if stop_event.is_set() else step
                        stop_event.set()
                    if failed != "aborted":
                        abort_others()
                else:
                    failed = step
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
            sys.stdout.flush()
        else:
            dump(f"{cfg.name}: FAIL ({failed}) [{minutes:.1f} min]", log)
            if failed == "configure":
                dump(f"{cfg.name}: config.log", bdir / "config.log")
            elif failed == "make check":
                dump(f"{cfg.name}: test-suite.log", bdir / "test-suite.log")
    return failed, minutes


def summarize(results, wall_min, cpu_min, nthreads):
    lines = ["| Config | Result | Minutes |", "|---|---|---|"]
    for cfg, failed, minutes in results:
        if failed == "aborted":
            ok = ":heavy_minus_sign: aborted (fail-fast)"
        elif failed:
            ok = f":x: FAIL ({failed})"
        else:
            ok = ":white_check_mark: pass"
        lines.append(f"| {cfg.name} | {ok} | {minutes:.1f} |")
    # Two views of how efficiently the pool used the machine: thread
    # occupancy is the time the workers spent running configs out of the
    # thread-minutes available (a long config left for last idles the other
    # workers and drags it down); CPU utilization is the CPU time the build
    # and test children actually consumed out of the CPU-minutes available
    # (too-shallow make -j and serial test phases show up here).
    busy_min = sum(minutes for _, _, minutes in results)
    ncpu = nproc()
    lines += [
        "",
        f"{len(results)} configs in {wall_min:.1f} min on {nthreads} "
        f"threads / {ncpu} CPUs: "
        f"thread occupancy {100 * busy_min / (wall_min * nthreads):.0f}% "
        f"({busy_min:.1f} of {wall_min * nthreads:.1f} thread-min), "
        f"CPU utilization {100 * cpu_min / (wall_min * ncpu):.0f}% "
        f"({cpu_min:.1f} of {wall_min * ncpu:.1f} CPU-min)",
    ]
    table = "\n".join(lines)
    print(table)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as f:
            print(f"### make check\n\n{table}", file=f)


def main():
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
    p.add_argument("--jobs", type=int, default=2,
                   help="make -j per config (default: 2)")
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
    opts = p.parse_args()

    all_configs = load_configs(opts, p.error)
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
        # shard. Deterministic, and with honest "minutes" within ~the
        # longest config of optimal.
        shards, loads = [[] for _ in range(n)], [0.0] * n
        for cfg in selected:
            i = loads.index(min(loads))
            shards[i].append(cfg)
            loads[i] += cfg.minutes
        selected = shards[k - 1]

    if opts.list:
        for cfg in selected:
            print(f"{cfg.name} [{cfg.minutes:g} min]: "
                  f"{' '.join(cfg.configure)}")
        return 0
    if not selected:
        print(f"shard {opts.shard}: no configs to run")
        return 0

    if not (SRCDIR / "configure").exists():
        subprocess.run(["./autogen.sh"], cwd=SRCDIR, check=True)

    nthreads = max(1, min(opts.threads, len(selected)))
    wall_start = time.monotonic()
    cpu_start = os.times()
    with ThreadPoolExecutor(max_workers=nthreads) as pool:
        results = [(cfg, failed, minutes) for cfg, (failed, minutes)
                   in zip(selected, pool.map(
                       lambda cfg: run_config(cfg, opts), selected))]
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
        print(f"::error::{msg}" if ON_GITHUB else msg)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
