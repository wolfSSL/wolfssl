"""Exercise the Cypress seed implementation with a failing TRNG init."""

import pathlib
import subprocess
import tempfile
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "wolfcrypt/src/random.c").read_text()
START = SOURCE.index("#elif defined(CY_USING_HAL) && defined(COMPONENT_WOLFSSL)\n",
                     SOURCE.index("/* Begin wc_GenerateSeed Implementations */"))
END = SOURCE.index("#elif defined(WOLFSSL_SAFERTOS)", START)
IMPLEMENTATION = SOURCE[START:END].split("\n", 1)[1]

HARNESS = r"""
#include <stdint.h>
#include <string.h>
typedef uint8_t byte;
typedef uint32_t word32;
typedef uintptr_t wc_ptr_t;
typedef struct { int unused; } OS_Seed;
typedef struct { int unused; } cyhal_trng_t;
typedef int cy_rslt_t;
#define CY_RSLT_SUCCESS 0
#define RNG_FAILURE_E -199
static int init_result;
static int free_count;
static cy_rslt_t cyhal_trng_init(cyhal_trng_t* obj)
{ (void)obj; return init_result; }
static uint32_t cyhal_trng_generate(cyhal_trng_t* obj)
{ (void)obj; return 0x12345678U; }
static void cyhal_trng_free(cyhal_trng_t* obj)
{ (void)obj; ++free_count; }
"""

MAIN = r"""
int main(void)
{
    byte output[4] = {0xa5, 0xa5, 0xa5, 0xa5};
    init_result = 1;
    if (wc_GenerateSeed(0, output, sizeof(output)) == 0) return 1;
    if (free_count != 0) return 2;
    if (output[0] != 0xa5 || output[3] != 0xa5) return 3;
    init_result = 0;
    if (wc_GenerateSeed(0, output, sizeof(output)) != 0) return 4;
    if (free_count != 1) return 5;
    if (output[0] == 0xa5 && output[3] == 0xa5) return 6;
    return 0;
}
"""


class CypressTrngFailure(unittest.TestCase):
    def test_failed_init_never_reports_seed_success(self):
        with tempfile.TemporaryDirectory() as directory:
            source = pathlib.Path(directory) / "trng.c"
            binary = pathlib.Path(directory) / "trng"
            source.write_text(HARNESS + IMPLEMENTATION + MAIN)
            compile_result = subprocess.run(
                ["cc", "-std=c99", "-Wall", "-Wextra", "-Werror", str(source),
                 "-o", str(binary)], capture_output=True, text=True, check=False,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            result = subprocess.run([str(binary)], capture_output=True,
                                    text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
