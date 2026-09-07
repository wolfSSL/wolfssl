# Notes on the wolfSSL FIPS 140-3 v7.0.0 (Post-Quantum) Windows project

First, if you did not get the FIPS files with your archive, you must contact
wolfSSL to obtain them.

The IDE/WIN-PQ-FIPSv7/wolfssl-fips.sln solution is for the FIPS 140-3 v7.0.0
module. In addition to the classical algorithms it includes the post-quantum
algorithms ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205) and the
stateful hash-based signatures LMS and XMSS (SP 800-208).

# Building the wolfssl-fips project

The project has eight configurations: Debug, Release, DLL Debug and DLL
Release, for Win32 and x64. The Debug and Release configurations build a
static library; the DLL configurations build a DLL.

The library must be built with Whole Program Optimization disabled. This is
required so that necessary components of the library are not optimized away.
There are two functions added to the library that are used as markers in
memory for the in-core memory check of the code. WPO consolidates them into a
single function. WPO also optimizes away the automatic FIPS entry function.

In the project as shipped, five configurations set
WholeProgramOptimization=true at the project level: Release|Win32,
Release|x64, DLL Release|Win32, DLL Release|x64 and DLL Debug|x64. Two of
those, Release|Win32 and Release|x64, are overridden back to false in their
ClCompile settings, and fips.c carries its own false override for the four
Debug and Release configurations. That leaves DLL Release|Win32, DLL
Release|x64 and DLL Debug|x64 compiling with WPO on. Before trusting an
in-core memory test result, confirm Whole Program Optimization is set to No
(/GL absent) for the configuration you are building.

Each of the source files inside the FIPS boundary defines their own code and
constant section. The code section names start with ".fipsA$" and the constant
section names start with ".fipsB$". Each subsection has a letter to organize
them in a specific order. This specific ordering puts marker functions and
constants on either end of the boundary so it can be hashed.


# In Core Memory Test

The In Core Memory test calculates a checksum (HMAC-SHA512 for the v7.0.0
module) of the wolfCrypt FIPS library code and constant data and compares it
with a known value in the code.

The following linker settings matter for the in-core memory test. They are set
on the four DLL configurations. A static library does not link, so on the
Debug and Release configurations the application that links the library has
to supply them.

1) The [Randomized Base Address setting (ASLR)](https://learn.microsoft.com/en-us/cpp/build/reference/dynamicbase-use-address-space-layout-randomization?view=msvc-170)
is disabled, because the feature throws off the in-core memory calculation and
the test fails. All four DLL configurations set RandomizedBaseAddress to false.
2) The [Incremental Link](https://learn.microsoft.com/en-us/cpp/build/reference/incremental-link-incrementally?view=msvc-170)
option is turned off so function pointers go to actual code, not a jump
instruction. All four DLL configurations set LinkIncremental to false.
3) The [FixedBaseAddress](https://learn.microsoft.com/en-us/cpp/build/reference/fixed-fixed-base-address?view=msvc-170)
option is set to YES, which drops the base relocation table. All four DLL
configurations set it. The two Win32 configurations and DLL Debug|x64 also
fix the image base at 0x5A000000.

The DLL Debug configurations additionally set DataExecutionPrevention to
false.

The "verifyCore" check value in the source fips_test.c needs to be updated when
building the code. The POS performs this check and the default failure callback
will print out the calculated checksum. When developing your code, copy this
value and paste it back into your code in the verifyCore initializer then
rebuild the code. When statically linking, you may have to recalculate your
check value when changing your application.

# Build Options

The build options are defined in IDE/WIN-PQ-FIPSv7/user_settings.h, which is
the single source of truth for this project.  The "NO" options there disable
algorithms not allowed in FIPS mode.

Optional configurations
-----------------------

user_settings.h is the shipping configuration: no harness, no optest.  Options
are supplied as patches against it rather than as extra copies, so an edit is
only made once:

  user_settings.h.wolfentropy.patch    MemUse (wolfEntropy) entropy source
  user_settings.h.paa.patch            x86_64 AES-NI PAA lane, x64 only
  user_settings.h.harness-optest.patch wolfACVP harness and optest together,
                                       for vector processing and lab testing

They are independent and may be combined.  From the wolfSSL tree root:

  git apply IDE/WIN-PQ-FIPSv7/user_settings.h.harness-optest.patch

Reverse any of them with "git apply -R".

The harness/optest patch also enables MD5, which the optest uses to show that a
non-approved algorithm sits outside the module boundary.
