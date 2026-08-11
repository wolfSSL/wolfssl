# Notes on the wolfssl-fips project

First, if you did not get the FIPS files with your archive, you must contact
wolfSSL to obtain them. The wolfssl-fips project will not build from a plain
git checkout: wolfcrypt/src/fips.c and wolfcrypt/src/fips_test.c are listed in
the project but only ship with a licensed FIPS bundle.

The IDE/WIN10/wolfssl-fips.sln solution covers the FIPS v2 #3389 (140-2)
certificate and the FIPS v5 (140-3) certificates and later. Which one you get
is selected in IDE/WIN10/user_settings.h, see "Selecting the FIPS version"
below. For the original FIPS #2425 certificate, use IDE/WIN/wolfssl-fips.sln
instead.

The solution holds two projects:

 * wolfssl-fips - the library itself, built from ../../src and
   ../../wolfcrypt/src.
 * test - a console application built from ../../wolfcrypt/test/test.c that
   links the library and runs wolfcrypt_test(), including the power on self
   test (POS).

Each project has eight configurations: Debug, Release, DLL Debug, and DLL
Release, for Win32 and x64. The Debug and Release configurations build a
static library; the DLL configurations build a DLL. The projects are saved
with platform toolset v110 (Visual Studio 2012); newer versions of Visual
Studio will offer to retarget them.

Use the DLL configurations. Only the DLL builds have been tested against a
validated operational environment, and only they should be used for a FIPS
build. The static library configurations are present in the solution and will
compile, but no OE has been tested with a static wolfCrypt FIPS library, so
the module's validation does not cover them. If that testing is done, this
README will be updated to say so.

The x64 configurations assemble ../../wolfcrypt/src/aes_asm.asm,
aes_gcm_asm.asm, aes_xts_asm.asm, and sp_x86_64_asm.asm with ml64.exe (MASM)
through custom build steps. The Win32 configurations have no assembly and
build the C implementations only.


# Selecting the FIPS version

The wolfssl-fips project does not put HAVE_FIPS on the compiler command line.
It defines only WOLFSSL_USER_SETTINGS (plus BUILDING_WOLFSSL and WOLFSSL_DLL
for the DLL configurations) and picks everything else up from
IDE/WIN10/user_settings.h.

The top of user_settings.h has one block per module version. All of them are
disabled as shipped, so a version must be enabled before the library will
build in FIPS mode:

 * FIPS 140-2 #3389: change the first "#if 0" to "#if 1"
   (HAVE_FIPS_VERSION 2, HAVE_FIPS_VERSION_MINOR 0)
 * FIPS 140-3 #4718: change the second "#if 0" to "#if 1"
   (HAVE_FIPS_VERSION 5, HAVE_FIPS_VERSION_MINOR 2)
    You may optionally add HAVE_FIPS_VERSION_PATCH 1 but is not required to
    achieve the approved build
 * FIPS Ready: uncomment "#define WOLFSSL_FIPS_READY"
   (HAVE_FIPS_VERSION 5, HAVE_FIPS_VERSION_MINOR 3)

For any other module version, define HAVE_FIPS, HAVE_FIPS_VERSION, and
HAVE_FIPS_VERSION_MINOR to the values that came with your FIPS bundle, either
by adding a block to user_settings.h or on the project command line.

Two things in the solution still hardcode a version and must be kept in sync
with what user_settings.h selects:

 * The test project defines HAVE_FIPS, HAVE_FIPS_VERSION=5, and
   HAVE_FIPS_VERSION_MINOR=1 in its preprocessor definitions. A mismatch
   between the application and the library changes struct layouts and will
   corrupt memory at runtime.
 * The x64 ml64.exe custom build steps pass
   /DHAVE_FIPS /DHAVE_FIPS_VERSION=5 /DHAVE_FIPS_VERSION_MINOR=1.


# Building the wolfssl-fips project

The library must be built with Whole Program Optimization disabled. This is
required so that necessary components of the library are not optimized away.
There are two functions added to the library that are used as markers in
memory for the in-core memory check of the code. WPO consolidates them into a
single function. WPO also optimizes away the automatic FIPS entry function.

In the project as shipped, the explicit WPO=false overrides are on the static
library configurations: at the project level for Release|Win32 and
Release|x64, and on fips.c specifically for the Debug and Release
configurations. The DLL Release configurations and DLL Debug|x64 carry
WholeProgramOptimization=true at the configuration level. Before trusting an
in-core memory test result, confirm Whole Program Optimization is set to No
(/GL absent) for the configuration you are building.

Each of the source files inside the FIPS boundary defines their own code and
constant section. The code section names start with ".fipsA$" and the constant
section names start with ".fipsB$". Each subsection has a letter to organize
them in a specific order. This specific ordering puts marker functions and
constants on either end of the boundary so it can be hashed.


# In Core Memory Test

The In Core Memory test calculates a checksum (HMAC-SHA256) of the wolfCrypt
FIPS library code and constant data and compares it with a known value in
the code.

The following linker settings are required on the DLL configurations, which
are the supported ones. A static library does not link, so these settings
would have to come from the application instead, which is one of the reasons
the static configurations are untested.

1) The [Randomized Base Address setting (ASLR)](https://learn.microsoft.com/en-us/cpp/build/reference/dynamicbase-use-address-space-layout-randomization?view=msvc-170)
needs to be disabled on all builds as the feature throws off the in-core memory
calculation causing the test to fail. All four DLL configurations set
RandomizedBaseAddress to false.
2) The [Incremental Link](https://learn.microsoft.com/en-us/cpp/build/reference/incremental-link-incrementally?view=msvc-170)
option needs to be turned off so function pointers go to actual code, not a jump
instruction. All four DLL configurations set LinkIncremental to false.
3) The [FixedBaseAddress](https://learn.microsoft.com/en-us/cpp/build/reference/fixed-fixed-base-address?view=msvc-170)
option is set to YES, which disables the support for ASLR. This is set on the
DLL Win32 configurations, along with a base address of 0x5A000000. /FIXED is
not used on the x64 DLL configurations.

The DLL Debug configurations additionally set DataExecutionPrevention to false.

The "verifyCore" check value in the source fips_test.c needs to be updated when
building the code. The POS performs this check and the default failure callback
will print out the calculated checksum. When developing your code, copy this
value and paste it back into your code in the verifyCore initializer then
rebuild the code.


# Build Options

These are the options user_settings.h sets once a FIPS version is selected.
The "NO" options explicitly disable algorithms that are not allowed in
FIPS mode.

Set for every FIPS version:

 * HAVE_FIPS
 * OPENSSL_EXTRA
 * HAVE_THREAD_LS
 * WOLFSSL_KEY_GEN
 * HAVE_AESGCM
 * HAVE_HASHDRBG
 * WOLFSSL_SHA384
 * WOLFSSL_SHA512
 * NO_PSK
 * NO_RC4
 * NO_DSA
 * NO_MD4

Added at HAVE_FIPS_VERSION 2 and later:

 * WOLFSSL_SHA224
 * WOLFSSL_SHA3
 * WC_RSA_PSS
 * WC_RSA_NO_PADDING
 * HAVE_ECC
 * HAVE_ECC384
 * HAVE_ECC521
 * HAVE_SUPPORTED_CURVES
 * HAVE_TLS_EXTENSIONS
 * ECC_SHAMIR
 * HAVE_ECC_CDH
 * ECC_TIMING_RESISTANT
 * TFM_TIMING_RESISTANT
 * WOLFSSL_AES_COUNTER
 * WOLFSSL_AES_DIRECT
 * HAVE_AES_ECB
 * HAVE_AESCCM
 * WOLFSSL_CMAC
 * HAVE_HKDF
 * WOLFSSL_VALIDATE_ECC_IMPORT
 * WOLFSSL_VALIDATE_FFC_IMPORT
 * HAVE_FFDHE_Q
 * HAVE_PUBLIC_FFDHE
 * FORCE_FAILURE_RDSEED
 * WOLFSSL_AESNI and HAVE_INTEL_RDSEED, on _WIN64 only

Added at HAVE_FIPS_VERSION 5 and later. Note that WOLFSSL_AESNI,
HAVE_INTEL_RDSEED, FORCE_FAILURE_RDSEED, and HAVE_PUBLIC_FFDHE from the v2
block are undefined here. Re-enable WOLFSSL_AESNI if you are building with
PAA (processor algorithm acceleration).

 * NO_DES
 * NO_DES3
 * NO_MD5
 * NO_OLD_TLS
 * WOLFSSL_TLS13
 * HAVE_TLS_EXTENSIONS
 * HAVE_SUPPORTED_CURVES
 * GCM_TABLE_4BIT
 * WOLFSSL_NO_SHAKE256
 * WOLFSSL_VALIDATE_ECC_KEYGEN
 * WOLFSSL_ECDSA_SET_K
 * WOLFSSL_WOLFSSH
 * WOLFSSL_PUBLIC_MP
 * WC_RNG_SEED_CB
 * TFM_ECC256
 * ECC_USER_CURVES
 * HAVE_ECC192
 * HAVE_ECC224
 * HAVE_ECC256
 * HAVE_ECC384
 * HAVE_ECC521
 * HAVE_FFDHE_2048
 * HAVE_FFDHE_3072
 * HAVE_FFDHE_4096
 * HAVE_FFDHE_6144
 * HAVE_FFDHE_8192
 * WOLFSSL_AES_OFB
 * FP_MAX_BITS 16384

Added at HAVE_FIPS_VERSION 6 and later:

 * WOLFSSL_AES_XTS

These settings are defined in IDE/WIN10/user_settings.h. Any application built
against the library must be compiled with the same settings, either by putting
this directory on its include path and defining WOLFSSL_USER_SETTINGS, or by
sharing a copy of user_settings.h.
