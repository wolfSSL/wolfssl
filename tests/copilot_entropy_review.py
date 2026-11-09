"""Regression checks for PR 12065 entropy configuration review."""

import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]


def macros(source, *defines):
    result = subprocess.run(
        ["cc", "-dM", "-E", "-x", "c", "-"] + ["-D" + d for d in defines],
        input=source, text=True, capture_output=True, check=False,
    )
    return result, {line.split()[1] for line in result.stdout.splitlines()
                    if line.startswith("#define ")}


class EntropyReview(unittest.TestCase):
    def test_mdk_rng_does_not_enable_crypto_accelerators(self):
        header = (ROOT / "IDE/MDK5-ARM/Conf/user_settings.h").read_text()
        result, names = macros(header, "STM32F7xx")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("WOLFSSL_STM32F7", names)
        self.assertIn("NO_STM32_CRYPTO", names)
        self.assertIn("NO_STM32_HASH", names)
        self.assertIn("NO_STM32_HMAC", names)

    def test_c5_v8_software_crypto_keeps_register_rng(self):
        source = (ROOT / "IDE/STM32Cube/MX2/mx_wolfSSL_conf_template.h.hbs").read_text()
        start = source.index("#elif defined(STM32C562xx)")
        end = source.index("#define WOLFSSL_SMALL_STACK", start)
        branch = "#if" + source[start + len("#elif"):end]
        branch += "\n#include <wolfssl/wolfcrypt/settings.h>\n"
        # The SDK headers are absent on this host. Empty stand-ins let the
        # real settings.h prove which features the generated header selects.
        with tempfile.TemporaryDirectory() as directory:
            for header in ("stm32c5xx.h", "stm32v8xx.h"):
                (pathlib.Path(directory) / header).write_text("")
            for family in ("STM32C562xx", "STM32V873xx"):
                with self.subTest(family=family):
                    result = subprocess.run(
                        ["cc", "-dM", "-E", "-x", "c", "-", "-I", directory,
                         "-I", str(ROOT), "-D" + family,
                         "-DWOLF_CONF_HW_CRYPTO=0"],
                        input=branch, text=True, capture_output=True,
                        check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    names = {line.split()[1] for line in result.stdout.splitlines()
                             if line.startswith("#define ")}
                    for name in ("WOLFSSL_STM32_RNG_NOLIB", "STM32_RNG",
                                 "NO_STM32_CRYPTO", "NO_STM32_HASH",
                                 "NO_STM32_HMAC"):
                        self.assertIn(name, names)
                    for name in ("WOLFSSL_STM32_CUBEMX", "STM32_CRYPTO",
                                 "STM32_HASH", "STM32_HMAC", "WOLFSSL_STM32_PKA"):
                        self.assertNotIn(name, names)
                    register = "AHB2ENR" if family == "STM32C562xx" else "AHB3ENR"
                    self.assertIn("WC_STM32_RNG_CLK_ENABLE()", result.stdout)
                    self.assertIn(register, result.stdout)

    def test_rng_disabled_needs_no_seed(self):
        for path in ("IDE/STM32Cube/MX2/mx_wolfSSL_conf_template.h.hbs",
                     "IDE/STM32Cube/default_conf.ftl",
                     "examples/configs/user_settings_stm32.h"):
            with self.subTest(path=path):
                source = (ROOT / path).read_text()
                start = source.index("#if (!defined(WOLF_CONF_RNG) || WOLF_CONF_RNG != 0) &&")
                end = source.index("#endif", start) + len("#endif")
                branch = source[start:end]
                denied, _ = macros(branch, "NO_STM32_RNG", "WOLF_CONF_RNG=1")
                self.assertNotEqual(denied.returncode, 0)
                allowed, _ = macros(branch, "NO_STM32_RNG", "WOLF_CONF_RNG=0")
                self.assertEqual(allowed.returncode, 0, allowed.stderr)

    def test_netos_seed_uses_pool_bytes_directly(self):
        # F-16422: the NET+OS pool is the entropy source; funneling each byte
        # through srand()/rand() added nothing and could lose entropy through
        # libc low-order bits. The function is a source-level check because it
        # needs the NET+OS BSP (tx_api.h, entropy.h) to run.
        source = (ROOT / "IDE/NETOS/wolfssl_netos_custom.c").read_text()
        start = source.index("int my_rng_generate_seed(")
        end = source.index("static void appFipsCb", start)
        function = source[start:end]
        self.assertNotIn("srand(", function)
        self.assertNotIn("rand()", function)
        self.assertIn("output[i] = get_byte_from_pool()", function)

    def test_custom_block_precedes_platform_seed_guards(self):
        source = (ROOT / "wolfcrypt/src/random.c").read_text()
        seed = source[source.index("/* Begin wc_GenerateSeed Implementations */"):]
        self.assertLess(seed.index("#elif defined(CUSTOM_RAND_GENERATE_BLOCK)"),
                        seed.index("#elif defined(HAVE_RTP_SYS)"))
        self.assertLess(seed.index("#elif defined(CUSTOM_RAND_GENERATE_BLOCK)"),
                        seed.index("#elif !defined(WOLFSSL_CAAM)"))
        self.assertIn("!defined(CUSTOM_RAND_GENERATE_BLOCK)",
                      seed[seed.index("#if defined(USE_TEST_GENSEED)"):
                           seed.index("/* End wc_GenerateSeed */")])

        result = subprocess.run(
            ["cc", "-E", "-I", str(ROOT), "-DWOLFSSL_LEANPSK",
             "-DUSE_TEST_GENSEED", "-DCUSTOM_RAND_GENERATE_BLOCK=secure_block",
             str(ROOT / "wolfcrypt/src/random.c"), "-o", "/dev/null"],
            text=True, capture_output=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
