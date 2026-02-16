# wolfCrypt Test

Tool for performing cryptographic algorithm testing.

## Example Output

Run on Intel(R) Core(TM) i7-7920HQ CPU @ 3.10GHz.

```sh
./configure --enable-intelasm --enable-aesni --enable-sp --enable-sp-asm && make

./wolfcrypt/test/testwolfcrypt
------------------------------------------------------------------------------
 wolfSSL version 4.0.0
------------------------------------------------------------------------------
error    test passed!
MEMORY   test passed!
base64   test passed!
asn      test passed!
MD5      test passed!
SHA      test passed!
SHA-224  test passed!
SHA-256  test passed!
SHA-384  test passed!
SHA-512  test passed!
SHA-3    test passed!
Hash     test passed!
HMAC-MD5 test passed!
HMAC-SHA test passed!
HMAC-SHA224 test passed!
HMAC-SHA256 test passed!
HMAC-SHA384 test passed!
HMAC-SHA512 test passed!
HMAC-SHA3   test passed!
GMAC     test passed!
Chacha   test passed!
POLY1305 test passed!
ChaCha20-Poly1305 AEAD test passed!
AES      test passed!
AES192   test passed!
AES256   test passed!
AES-GCM  test passed!
RANDOM   test passed!
RSA      test passed!
DH       test passed!
ECC      test passed!
logging  test passed!
mutex    test passed!
memcb    test passed!
Test complete
```


## Windows Visual Studio

For building wolfCrypt test project in Visual Studio open the `test.sln`. For newer Visual Studio version it may prompt for a one-way upgrade. Then you may have to right-click on the solution and choose `Retarget solution` to update the project files for your Visual Studio version.

If you see an error about `rc.exe` then you'll need to update the "Target Platform Version". You can do this by right-clicking on the test project -> General -> "Target Platform Version" and changing to 8.1 (needs to match the wolfssl library project).

This solution includes the wolfSSL library project at `<wolfssl-root>wolfssl.vcxproj` and will compile the library, then the test project.

--------

Jan 2026 - Reviewing the older FIPS compliant CRNGT test specified in FIPS 140-2
ss 4.9.2 vs the newer replacement tests RCT/ADP that are allowed to replace the
CRNGT under the new FIPS 140-3 / ISO 19790 standard.

================================================================================
DRBG Continuous Health Test Statistical Analysis & Diagnostic Report
================================================================================

OVERVIEW
--------
This document describes the statistical false positive behavior of the DRBG
continuous health test in wc_RNG_TestSeed() and provides diagnostic tools to
distinguish between:
  1. Statistical false positives (expected behavior)
  2. Entropy source depletion (under heavy concurrent load)
  3. Actual stuck entropy source (hardware failure)


BACKGROUND: THE ISSUE
---------------------
The DRBG was experiencing high volumes of (DRBG_CONT_FIPS_E) on wc_InitRng()
calls.

Example error:
  ERROR: wc_InitRng failed at iteration 330788 with code -209

This raises the question: Is this a bug in wc_RNG_TestSeed() or expected
statistical behavior?


STATISTICAL ANALYSIS
--------------------

The wc_RNG_TestSeed() Function Behavior:
  - Compares ALL consecutive SEED_BLOCK_SZ chunks in the seed buffer
  - With FIPS mode (typical configuration):
      SEED_SZ = 256 * 4 / 8 = 128 bytes (1024-bits)
      SEED_BLOCK_SZ = 4 bytes (default) (32-bits)
      seedSz passed to test = 132 bytes (SEED_SZ + SEED_BLOCK_SZ)
      Number of comparisons = ~32 consecutive block pairs

False Positive Probability Calculation:
  - Probability one 4-byte block equals another random 4-byte block: 1/2^32
  - With 32 comparisons per seed: 32/2^32 ≈ 1 in 134 million per wc_InitRng()

Test Configuration (Default):
  - 40 threads × 100M iterations = 4 BILLION total wc_InitRng() calls
  - Expected false positives: 4,000,000,000 × (32/2^32) ≈ 30 failures

Conclusion:
  Seeing failures around 1 in 30-140 million is EXPECTED STATISTICAL BEHAVIOR.
  Under heavy concurrent load (40 threads), entropy source
  depletion can also cause legitimate failures.


TESTING IT
--------------------

Non-FIPS:

    ./configure CFLAGS="-DWC_RNG_SEED_DEBUG -DREALLY_LONG_DRBG_CONTINUOUS_TEST"
    make
    ./wolfcrypt/test/testwolfcrypt

FIPS:

    ./configure --enable-fips=<flavor> CFLAGS="-DWC_RNG_SEED_DEBUG -DREALLY_LONG_DRBG_CONTINUOUS_TEST"
    make
    ./fips-hash.sh
    make
    ./wolfcrypt/test/testwolfcrypt


OUTPUTS EXPECTED
--------------------

Non-FIPS:

    Math: Multi-Precision: Wolf(SP) word-size=64 bits=4096 sp_int.c
    ------------------------------------------------------------------------------
     wolfSSL version 5.8.4
    ------------------------------------------------------------------------------
    macro    test passed!
    error    test passed!
    MEMORY   test passed!
    base64   test passed!
    asn      test passed!
    MD5      test passed!
    SHA      test passed!
    SHA-224  test passed!
    SHA-256  test passed!
    SHA-384  test passed!
    SHA-512  test passed!
    SHA-512/224  test passed!
    SHA-512/256  test passed!
    SHA-3    test passed!
    RNG Entropy Source: getrandom() syscall
    ===============================================
    DRBG Continuous Test Validation Suite
    ===============================================
    FIPS Build: NO

    --- Test 1: Basic RNG Functionality ---
    Generated 32 random bytes successfully
    [PASS] Basic RNG Functionality

    --- Test 2: Multiple RNG Instances ---
    Successfully operated 100 RNG instances concurrently
    [PASS] Multiple RNG Instances

    --- Test 3: FIPS Status Check ---
    SKIPPED: FIPS not enabled
    [PASS] FIPS Status Check

    --- Test 4: RNG ReInit Test (multi-threaded) ---
    Configuration: 40 threads × 100000000 iterations = 4000000000 total
    Test Profile: Default (Aggressive multi-threaded)
    Expected statistical false positive rate: ~29.80 failures
    Duplicate block at offset 4:
      Block 1: E6 E9 D1 7B
      Block 2: E6 E9 D1 7B
    Full seed buffer (52 bytes):
    DA 93 B7 88 E6 E9 D1 7B E6 E9 D1 7B A5 4C C9 E9
    13 EE D8 4C B3 C1 71 DE 32 37 17 F2 E7 A4 29 7D
    9B 02 B0 0C EC 8D AC F5 DA B1 71 05 84 C0 61 75
    59 6D 87 B5
    ERROR: wc_InitRng failed at iteration 778551 with code -209
    ERROR: wc_RNG_GenerateBlock failed at iteration 778551 with code -199
...
    (18 other failures truncated here for brevity)
...
    Duplicate block at offset 16:
      Block 1: C1 19 37 B1
      Block 2: C1 19 37 B1
    Full seed buffer (52 bytes):
    62 66 5B D2 F5 54 47 9B 59 DD 0A 55 4B 52 8C 39
    C1 19 37 B1 C1 19 37 B1 3F 62 CB 2E FE 56 65 4D
    4F 0C A7 7D 1C 09 48 51 30 1B CA 00 56 9F 29 A7
    E3 93 EF 8E
    ERROR: wc_InitRng failed at iteration 90467867 with code -209
    ERROR: wc_RNG_GenerateBlock failed at iteration 90467867 with code -199
    Thread 0 Succeeded
...
    38 other thread results truncated here for brevity (all threads succeeded
        even though they experienced 1 or 2 failures in several of the threads)
...
    Thread 39 Succeeded
    Reinitialized RNG 4000000000 times across 40 threads
    Experienced 0 thread failures and 40 thread successes
    20/4000000000 API calls failed <--- This is the bread and the butter of the
                                        test, we unfortunately expect to see
                                        ~29.80 failures, prior to the newer FIPS
                                        140-3 RCT and ADP tests the CRNGT was
                                        required. Now the CRNGT is replaceable
                                        by the more mathematically robust
                                        RCT/ADP.
    [PASS] RNG Reinitialization



TESTING RESULTS with the CRNGT test:
--------------------

Old implementation non-FIPS:
    Run 1 - 6 failures in 4 billion runs (100M per thread, 40 threads)
    Run 2 - 11 failures in 4 billion (100M per thread, 40 threads)
    Run 3 - 13 failures in 4 billion (100M per thread, 40 threads)

Old implementation with FIPS:
(keeping in mind just a single failure means catastrophic
failure for the entire module until power cycled):
    Run 1 - 3990118689 failures in 4 billion API calls (yikes)

TESTING RESULTS with the RCT/ADP tests in place of the CRNGT test:

New implementation non-FIPS: 4 billion successes
New implementation FIPS: 4 billion successes


