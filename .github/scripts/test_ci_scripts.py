#!/usr/bin/env python3
# Tests for check-workflows.py and parallel-make-check.py.
#
#   python3 -m unittest discover -s .github/scripts -p 'test_*.py'

import contextlib
import importlib.util
import io
import json
import os
import pathlib
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

SCRIPTS = pathlib.Path(__file__).resolve().parent
ACTIONS = SCRIPTS.parent / "actions"


def load(name: str, path: pathlib.Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


cw = load("check_workflows", SCRIPTS / "check-workflows.py")
deps = load("check_ci_deps", SCRIPTS / "check-ci-deps.py")


class AptModel(unittest.TestCase):
    def test_worst_cases(self):
        self.assertEqual(cw.apt_install_worst(2, budget=120), 175)
        self.assertEqual(cw.apt_install_worst(2, budget=600), 620)
        self.assertEqual(cw.apt_install_worst(2), 825)
        self.assertEqual(cw.apt_install_worst(**cw.CCACHE_APT), 345)
        inputs = {**cw.apt_defaults(), "ghcr-debs-tag": "ubuntu-24.04-full"}
        self.assertEqual(cw.apt_worst(inputs), 130 + 620)

    def test_matches_the_scripts(self):
        script = (ACTIONS / "install-apt-deps/apt-install.sh").read_text()
        for line in ("update_timeout=90", "install_timeout=300", "delay=5",
                     f'[ "$update_timeout" -le {cw.UPDATE_MAX} ]',
                     f'[ "$update_timeout" -ge {cw.UPDATE_MIN} ]',
                     f'[ "$install_timeout" -ge {cw.INSTALL_MIN} ]',
                     f"timeout -k {cw.KILL_GRACE} "):
            self.assertIn(line, script)
        ccache = (ACTIONS / "ccache-setup/action.yml").read_text()
        self.assertIn(f"--tries {cw.CCACHE_APT['tries']}", ccache)
        self.assertIn(f"--update-timeout {cw.CCACHE_APT['update']}", ccache)
        self.assertIn(f"--install-timeout {cw.CCACHE_APT['install']}", ccache)


APT = {"uses": "./.github/actions/install-apt-deps",
       "with": {"packages": "p", "ghcr-debs-tag": "ubuntu-24.04-full"}}


def errors(limit: object, steps: list) -> int:
    doc = {"jobs": {"j": {"timeout-minutes": limit, "steps": steps}}}
    # Keep the ::error lines out of a CI log, where they would annotate.
    with contextlib.redirect_stdout(io.StringIO()):
        return cw.check_timeouts(pathlib.Path("t.yml"), doc, cw.apt_defaults())


def run(opts: str) -> dict:
    return {"run": f".github/scripts/parallel-make-check.py {opts} c.json"}


class CheckTimeouts(unittest.TestCase):
    def test_setup(self):
        self.assertEqual(errors(15, [APT]), 0)
        self.assertEqual(errors(14, [APT]), 1)

    def test_conditional_setup(self):
        a = {**APT, "if": "inputs.p == 'a'"}
        b = {**APT, "if": "inputs.p == 'b'"}
        self.assertEqual(errors(15, [a, b]), 0)
        self.assertEqual(errors(27, [a, a]), 0)
        self.assertEqual(errors(26, [a, a]), 1)

    def test_direct_apt_install(self):
        call = {"run": "x/apt-install.sh --tries 2 \\\n"
                       "  --warn-only --budget 600 pkg || true"}
        self.assertEqual(errors(13, [call]), 0)
        self.assertEqual(errors(12, [call]), 1)
        bad = {"run": 'x/apt-install.sh --tries "$N"'}
        self.assertEqual(errors(60, [bad]), 1)

    def test_run_bounds(self):
        ok = run("--timeout=10 --deadline=20")
        self.assertEqual(errors(25, [ok]), 0)
        self.assertEqual(errors(24, [ok]), 1)
        self.assertEqual(errors(45, [ok, ok]), 0)
        self.assertEqual(errors(44, [ok, ok]), 1)
        self.assertEqual(errors(60, [run("--timeout=10")]), 1)
        two = {"run": ok["run"] + "\n" + ok["run"]}
        self.assertEqual(errors(45, [two]), 0)
        self.assertEqual(errors(44, [two]), 1)
        self.assertEqual(errors(60, [{"run": run("")["run"] + "\n"
                                              + ok["run"]}]), 1)
        self.assertEqual(errors(60, [run("--timeout=30 --deadline=20")]), 1)
        noted = {"run": "# parallel-make-check.py runs below\n" + ok["run"]}
        self.assertEqual(errors(25, [noted]), 0)
        self.assertEqual(errors(60, [run("--timeout=${{ m.t }} "
                                         "--deadline=20")]), 0)


class CheckRunners(unittest.TestCase):
    def errors(self, pairs: list, called: set = frozenset()) -> int:
        with mock.patch.object(deps, "bundle_images", dict):
            checker = deps.Checker({}, stream=io.StringIO())
        checker.check_runners("w", "j", pairs, set(called))
        return checker.errors

    def test_runner_matches_tag(self):
        full = "ubuntu-24.04-full"
        self.assertEqual(self.errors([("ubuntu-24.04", full)]), 0)
        self.assertEqual(self.errors([("ubuntu-24.04", full),
                                      ("ubuntu-22.04", full)]), 1)
        self.assertEqual(self.errors([("ubuntu-22.04", full)],
                                     {("ubuntu-22.04", full)}), 0)
        self.assertEqual(self.errors([("ubuntu-latest", full)]), 1)


class Deadline(unittest.TestCase):
    @contextlib.contextmanager
    def tree(self, configs: list, autogen: str = "", configure: str = ""):
        # Yields a fake source tree and the runner's command line for it.
        with tempfile.TemporaryDirectory() as tmp:
            scripts = pathlib.Path(tmp) / ".github/scripts"
            scripts.mkdir(parents=True)
            shutil.copy(SCRIPTS / "parallel-make-check.py", scripts)
            for name, body in (("autogen.sh", autogen),
                               ("configure", configure)):
                if body:
                    script = pathlib.Path(tmp) / name
                    script.write_text(f"#!/bin/sh\n{body}\n")
                    script.chmod(0o755)
            cfg = pathlib.Path(tmp) / "cfg.json"
            cfg.write_text(json.dumps(configs))
            yield pathlib.Path(tmp), [
                sys.executable, str(scripts / "parallel-make-check.py"),
                "--threads", "2", "--timeout", "5", str(cfg)]

    def run_pmc(self, configs: list, *opts: str, autogen: str = "",
                configure: str = "") -> tuple[int, dict]:
        with self.tree(configs, autogen, configure) as (_, argv):
            out = subprocess.run(argv[:-1] + list(opts) + argv[-1:],
                                 capture_output=True, text=True, timeout=120,
                                 env={"PATH": "/usr/bin:/bin"})
        self.stdout = out.stdout
        return out.returncode, dict(re.findall(
            r"^\| (\w+) \| (.+?) \| [\d.]+ \|$", out.stdout, re.M))

    def config(self, name: str, minutes: float, *cmd: str) -> dict:
        return {"name": name, "minutes": minutes, "build": False,
                "run": [list(cmd)]}

    def test_every_config_cut_off_is_labelled(self):
        configs = [self.config("a", 3, "sleep", "600"),
                   self.config("b", 2, "sleep", "600"),
                   self.config("c", 1, "sleep", "1")]
        for mode in ("--fail-fast", "--no-fail-fast"):
            with self.subTest(mode=mode):
                rc, got = self.run_pmc(configs, mode, "--deadline", "0.05")
                self.assertEqual(rc, 1)
                self.assertIn("run deadline in sleep 600", got["a"])
                self.assertIn("run deadline in sleep 600", got["b"])
                self.assertIn("run deadline before", got["c"])

    def test_real_failure_is_not_a_deadline(self):
        configs = [self.config("bad", 3, "bash", "-c", "sleep 1; exit 1"),
                   self.config("b", 2, "sleep", "600"),
                   self.config("c", 1, "sleep", "1")]
        rc, got = self.run_pmc(configs, "--fail-fast", "--deadline", "0.05")
        self.assertEqual(rc, 1)
        self.assertIn("FAIL (bash -c sleep 1; exit 1)", got["bad"])
        self.assertIn("aborted", got["b"])
        self.assertIn("aborted", got["c"])

    def test_failure_seen_after_deadline(self):
        # A step that fails before the deadline but is seen after it keeps
        # its own label.
        step = "kill -STOP $PPID; (sleep 5; kill -CONT $PPID) & exit 9"
        rc, got = self.run_pmc([self.config("a", 1, "sh", "-c", step)],
                               "--deadline", "0.05")
        self.assertEqual(rc, 1)
        self.assertIn("FAIL (sh -c", got["a"])

    def test_timeout_across_deadline_is_not_aborted(self):
        # b's --timeout kill is still in its grace when c hits the deadline.
        slow = "trap 'sleep 3; exit 9' TERM; sleep 600 & wait"
        configs = [self.config("b", 3, "sh", "-c", slow),
                   self.config("a", 2, "sleep", "2"),
                   self.config("c", 1, "sleep", "600")]
        rc, got = self.run_pmc(configs, "--fail-fast", "--timeout", "0.08",
                               "--deadline", "0.1")
        self.assertEqual(rc, 1)
        self.assertIn("timeout in sh -c", got["b"])
        self.assertIn("run deadline in sleep 600", got["c"])

    def test_timeout_dumps_step_log(self):
        rc, got = self.run_pmc([{"name": "a", "minutes": 1}],
                               "--timeout", "0.05", "--deadline", "1",
                               configure="echo marker >config.log; sleep 600")
        self.assertEqual(rc, 1)
        self.assertIn("timeout in configure", got["a"])
        self.assertIn("==== a: config.log ====\nmarker", self.stdout)

    def test_autogen_is_bounded(self):
        configs = [{"name": "a", "minutes": 1}]
        rc, _ = self.run_pmc(configs, "--deadline", "0.05",
                             autogen="sleep 600")
        self.assertEqual(rc, 1)
        self.assertIn("autogen.sh hit --deadline", self.stdout)

    def test_interrupt_stops_autogen(self):
        autogen = "echo $$ >pid.tmp; mv pid.tmp autogen.pid; exec sleep 600"
        with self.tree([{"name": "a", "minutes": 1}], autogen) as (tmp, argv):
            runner = subprocess.Popen(
                argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                env={"PATH": "/usr/bin:/bin"},
                preexec_fn=lambda: signal.signal(signal.SIGINT,
                                                 signal.SIG_DFL))
            try:
                pid_file = tmp / "autogen.pid"
                end = time.monotonic() + 60
                while not pid_file.exists() and time.monotonic() < end:
                    time.sleep(0.1)
                self.assertTrue(pid_file.exists(), "autogen.sh never ran")
                runner.send_signal(signal.SIGINT)
                runner.wait(timeout=60)
            finally:
                if runner.poll() is None:
                    runner.kill()
                    runner.wait()
            pid = int(pid_file.read_text())
        end = time.monotonic() + 10
        while time.monotonic() < end:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                return
            time.sleep(0.1)
        os.kill(pid, signal.SIGKILL)
        self.fail("autogen.sh outlived an interrupted runner")


if __name__ == "__main__":
    unittest.main()
