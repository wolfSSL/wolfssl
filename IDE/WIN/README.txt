# Notes on the wolfssl-fips project

First, if you did not get the FIPS files with your archive, you must contact
wolfSSL to obtain them.

The IDE/WIN/wolfssl-fips.sln solution is for the original FIPS #2425 certificate.
See IDE/WIN10/wolfssl-fips.sln for the FIPS v2 #3389 or later Visual Studio solution.

# Building the wolfssl-fips project

The wolfCrypt FIPS library for Windows is a part of the wolfSSL library. It
must be built as a static library, for the moment.

The library project is built with Whole Program Optimization disabled. This is
required so that necessary components of the library are not optimized away.
There are two functions added to the library that are used as markers in
memory for the in-core memory check of the code. WPO consolidates them into a
single function. WPO also optimizes away the automatic FIPS entry function.

Each of the source files inside the FIPS boundary defines their own code and
constant section. The code section names start with ".fipsA$" and the constant
section names start with ".fipsB$". Each subsection has a letter to organize
them in a specific order. This specific ordering puts marker functions and
constants on either end of the boundary so it can be hashed.


# In Core Memory Test

The In Core Memory test calculates a checksum (HMAC-SHA256) of the wolfCrypt
FIPS library code and constant data and compares it with a known value in
the code.

The following wolfCrypt FIPS project linker settings are required for the DLL Win32 configuration:
1) The [Randomized Base Address setting (ASLR)](https://learn.microsoft.com/en-us/cpp/build/reference/dynamicbase-use-address-space-layout-randomization?view=msvc-170)
needs to be disabled on all builds as the feature throws off the in-core memory calculation causing the test to fail.
2) The [Incremental Link](https://learn.microsoft.com/en-us/cpp/build/reference/incremental-link-incrementally?view=msvc-170)
option need turned off so function pointers go to actual code, not a jump instruction.
3) The [FixedBaseAddress](https://learn.microsoft.com/en-us/cpp/build/reference/fixed-fixed-base-address?view=msvc-170)
option to YES, which disables the support for ASLR.

The "verifyCore" check value in the source fips_test.c needs to be updated when
building the code. The POS performs this check and the default failure callback
will print out the calculated checksum. When developing your code, copy this
value and paste it back into your code in the verifyCore initializer then
rebuild the code. When statically linking, you may have to recalculate your
check value when changing your application.


# Build Options

The default build options should be the proper default set of options:

 * HAVE_FIPS
 * HAVE_THREAD_LS
 * HAVE_AESGCM
 * HAVE_HASHDRBG
 * WOLFSSL_SHA384
 * WOLFSSL_SHA512
 * NO_RC4
 * NO_DSA
 * NO_MD4

The "NO" options explicitly disable algorithms that are not allowed in
FIPS mode.

Additionally one may enable:

 * HAVE_ECC
 * OPENSSL_EXTRA
 * WOLFSSL_KEY_GEN

These settings are defined in IDE/WIN/user_settings.h.

# Notes on enabling DTLS including DTLS version 1.3

The file IDE/WIN/user_settings_dtls.h contains the needed build options for
enabling DTLS and DTLS version 1.3.

To incorporate the build options:

 * Rename IDE/WIN/user_settings.h to IDE/WIN/user_settings.h.bak
 * Rename IDE/WIN/user_settings_dtls.h to IDE/WIN/user_settings.h

Alternatively, copy the DTLS labeled section from IDE/WIN/user_settings_dtls.h
in to IDE/WIN/user_settings.h.