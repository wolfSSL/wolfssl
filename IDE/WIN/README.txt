# Notes on the wolfssl-fips project

First, if you did not get the FIPS files with your archive, you must contact
wolfSSL to obtain them.

# Building the wolfssl-fips project

The wolfCrypt FIPS library for Windows is a part of the wolfSSL library. It
must be built as a static library.

The library project is built with Whole Program Optimization disabled. This is
required so that necessary components of the library are not optimized away.
There are two functions added to the library that are used as markers in
memory for the in-core memory check of the code. WPO consolidates them into a
single function. WPO also optimizes away the automatic FIPS entry function.

Each of the source files inside the FIPS boundary defines their own code and
constant section. The code section names start with ".fipsA$" and the constant
section names start with ".fipsB$". Each subsection has a letter to organize
them in a secific order. This specific ordering puts marker functions and
constants on either end of the boundary so it can be hashed.

# In Core Memory Test

The In Core Memory test calculates a checksum (HMAC-SHA256) of the wolfCrypt
FIPS library code and constant data and compares it with a known value in
the code.

The Randomized Base Address setting doesn't cause any problems because
(I believe) that the addrsses in the executable are all offsets from the base
rather than absolute addresses.

The "verifyCore" check value in the source fips_test.c needs to be updated when
building the code. The POS performs this check and the default failure callback
will print out the calculated checksum. When developing your code, copy this
value and paste it back into your code in the verifyCore initializer then
rebuild the code. When statically linking, you may have to recalculate your
check value when changing your application.
