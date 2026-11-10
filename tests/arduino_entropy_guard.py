"""Compile-time checks for the Arduino seed path in random.c."""

import pathlib
import subprocess
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "wolfcrypt/src/random.c").read_text()
START = SOURCE.index("#elif defined(ARDUINO)\n")
END = SOURCE.index("#elif defined(WOLFSSL_ESPIDF)\n", START)
ARDUINO_BRANCH = "#if" + SOURCE[START + len("#elif"):END] + "#endif\n"
SEED_DISPATCH_START = SOURCE.index("#if defined(CUSTOM_RAND_GENERATE_SEED)\n", SOURCE.index("/* Begin wc_GenerateSeed Implementations */"))
SEED_DISPATCH = SOURCE[SEED_DISPATCH_START:END] + "#endif\n"


def preprocess(*defines, code=ARDUINO_BRANCH):
    return subprocess.run(
        ["cc", "-E", "-x", "c", "-"] + ["-D" + name for name in defines],
        input=code,
        text=True,
        capture_output=True,
        check=False,
    )


class ArduinoEntropyGuard(unittest.TestCase):
    def test_generic_arduino_requires_explicit_weak_opt_in(self):
        for board in ((), ("ARDUINO_SAMD_NANO_33_IOT",),
                      ("ARDUINO_ARCH_RP2040",), ("__STM32__",), ("ESP32",)):
            with self.subTest(board=board):
                result = preprocess("ARDUINO", *board)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("WOLFSSL_ACCEPT_WEAK_ENTROPY", result.stderr)

    def test_weak_opt_in_allows_legacy_path(self):
        self.assertEqual(preprocess("ARDUINO", "WOLFSSL_ACCEPT_WEAK_ENTROPY").returncode, 0)

    def test_due_trng_does_not_require_weak_opt_in(self):
        self.assertEqual(preprocess("ARDUINO", "ARDUINO_SAM_DUE", "__SAM3X8E__").returncode, 0)

    def test_custom_seed_takes_priority_over_arduino_fallback(self):
        result = preprocess("ARDUINO", "CUSTOM_RAND_GENERATE_SEED=secure_seed",
                            code=SEED_DISPATCH)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("return secure_seed(output, sz)", result.stdout)


if __name__ == "__main__":
    unittest.main()
