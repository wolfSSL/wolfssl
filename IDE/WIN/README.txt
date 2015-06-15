# Notes on the wolfssl-fips project

First, if you did not get the FIPS files with your archive, you must contact
wolfSSL to obtain them.

# On Building the wolfssl-fips project

The wolfCrypt FIPS library for Windows is a part of the wolfSSL library. It
must be built as a static library.

The library project is built with Whole Program Optimization disabled. This is
required so that necessary components of the library are not optimized away.
There are two functions added to the library that are used as markers in
memory for the in-core memory check of the code. WPO consolidates them into a
single function. WPO also optimizes away the automatic FIPS entry function.

A project using the library must disable 

Each of the source files inside the FIPS boundary defines their own code and
constant section. The code section names start with ".fipsA$" and the constant
section names start with ".fipsB$". Each subsection has a letter to organize
them in a secific order. This specific ordering puts marker functions and
constants on either end of the boundary so it can be hashed.
