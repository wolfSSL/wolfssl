"""Shipped integration settings must not select test entropy by default."""

import pathlib
import re
import subprocess
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
WEAK_DEFINES = re.compile(
    r"^[ \t]*#[ \t]*define[ \t]+(?:WOLFSSL_ACCEPT_WEAK_ENTROPY|"
    r"WOLFSSL_GENSEED_FORTEST|USE_TEST_GENSEED)\b", re.MULTILINE
)


class WeakEntropyDefaults(unittest.TestCase):
    def test_integration_settings_do_not_enable_weak_entropy(self):
        offenders = []
        for base in (ROOT / "IDE", ROOT / "RTOS", ROOT / "mcapi"):
            for path in base.rglob("user_settings.h"):
                if path == ROOT / "IDE/MDK5-ARM/Conf/user_settings.h":
                    # This definition is behind an explicit MDK_CONF_RNDSEED=1.
                    continue
                source = path.read_text(errors="replace")
                for match in WEAK_DEFINES.finditer(source):
                    line = source.count("\n", 0, match.start()) + 1
                    offenders.append(f"{path.relative_to(ROOT)}:{line}")
        self.assertEqual(offenders, [], "automatic weak seeds: " + ", ".join(offenders))

    def test_clock_and_prng_seed_branches_require_weak_opt_in(self):
        source = (ROOT / "wolfcrypt/src/random.c").read_text()
        for name in ("WOLFSSL_PB", "MICRIUM", "__MICROBLAZE__"):
            with self.subTest(platform=name):
                start = source.index("#elif defined(" + name + ")", source.index("/* Begin wc_GenerateSeed Implementations */"))
                end = source.index("\n#elif defined(", start + 1)
                branch = "#if" + source[start + len("#elif"):end] + "\n#endif\n"
                result = subprocess.run(
                    ["cc", "-E", "-x", "c", "-", "-D" + name],
                    input=branch, text=True, capture_output=True, check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("WOLFSSL_ACCEPT_WEAK_ENTROPY", result.stderr)

    def test_contiki_does_not_choose_framework_prng(self):
        source = (ROOT / "wolfcrypt/src/random.c").read_text()
        start = source.index("#elif defined(CUSTOM_RAND_GENERATE)\n", source.index("/* Begin wc_GenerateSeed Implementations */"))
        end = source.index("\n#elif defined(", start + 1)
        branch = "#if" + source[start + len("#elif"):end] + "\n#endif\n"
        for extra, expected in (((), False),
                                (("WOLFSSL_ACCEPT_WEAK_ENTROPY",), True),
                                (("WOLFSSL_CONTIKI_SECURE_ENTROPY",), True)):
            with self.subTest(extra=extra):
                result = subprocess.run(
                    ["cc", "-E", "-x", "c", "-", "-DWOLFSSL_CONTIKI",
                     "-DCUSTOM_RAND_GENERATE=random_rand"] +
                    ["-D" + item for item in extra],
                    input=branch, text=True, capture_output=True, check=False,
                )
                self.assertEqual(result.returncode == 0, expected)

    def test_predictable_custom_seed_examples_require_opt_in(self):
        paths = (
            "IDE/AURIX/user_settings.h",
            "IDE/GCC-ARM/Header/user_settings.h",
            "IDE/RISCV/SIFIVE-HIFIVE1/user_settings.h",
            "IDE/STARCORE/user_settings.h",
            "IDE/IAR-MSP430/user_settings.h",
            "IDE/qemu-falcon-neon/user_settings.h",
            "IDE/m33mu-falcon-verify/user_settings.h",
        )
        for path in paths:
            with self.subTest(path=path):
                command = ["cc", "-E", "-x", "c", "-", "-include",
                           str(ROOT / path)]
                result = subprocess.run(command, input="", text=True,
                                        capture_output=True, check=False)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("WOLFSSL_ACCEPT_WEAK_ENTROPY", result.stderr)
                for option in ("WOLFSSL_ACCEPT_WEAK_ENTROPY",
                               "CUSTOM_RAND_GENERATE_SEED=secure_seed"):
                    with self.subTest(path=path, option=option):
                        allowed = subprocess.run(
                            command + ["-D" + option], input="", text=True,
                            capture_output=True, check=False,
                        )
                        self.assertEqual(allowed.returncode, 0, allowed.stderr)


if __name__ == "__main__":
    unittest.main()
