# wolfSSL and wolfCrypt iOS Xcode Projects

This directory contains two xcodeproj:

1. `wolfssl.xcodeproj` -- builds wolfSSL and wolfCrypt
2. `wolfssl-FIPS.xcodeproj` -- builds wolfSSL and wolfCrypt-FIPS if available

Both projects will build the library `libwolfssl.a` and produce a directory
named `include` with the wolfSSL and wolfCrypt headers, and the CyaSSL and
CtaoCrypt compatibility headers. Specific build options may be added to the
`IPHONE` section of the file `wolfssl/wolfcrypt/settings.h`.

## wolfSSL

This project should build wolfSSL and wolfCrypt using the default settings.

## wolfSSL-FIPS

To use the FIPS version, one must have the FIPS sources. The project won't
build without them. Please contact info@wolfssl.com for more information about
wolfCrypt with FIPS.

By default, this builds the wolfSSL and wolfCrypt with FIPS library. The default
configuration enables the settings required for FIPS. Others may be turned on.
The project also ensures the FIPS related objects are linked in the proper
order.


# Building libwolfssl.a

There are several options of builds. You can make a simulator build, or a
device build. Both are debug builds.

You can make an archive for a device, as well. That is a release build.

# Installing libwolfssl.a

Simply drag the file libwolfssl.a and the directory `include` and drop it into
your project file list pane where it makes sense for you. Allow it to copy the
files over to the project directory. This should automatically add the library
to the list of libraries to link against.

Click on your project target, then the "Build Phases" tab. On the targets list
click your target. Click the disclosure triangle on the section "Link Binary
With Libraries" and verify libwolfssl.a is in the list. If not, click the "+",
and on the "Choose framworks and libraries to add:" dialog, click the
button "Add other..." then find the file libwolfssl.a.

Click on the "Build Settings" tab. Scroll down to the section "Search Paths".
Add the path to the include directory to the list "Header Search Paths".


## When using FIPS

When using the FIPS version, on the target window, in the "Build Settings" tab,
scroll down to the "Apple LLVM 6.0 - Preprocessing" section. Open the disclosure
for "Preprocessor Macros" and add the following under both `Release` and
`Debug`:

* `IPHONE`
* `HAVE_FIPS`
* `HAVE_HASHDRBG`
* `HAVE_AESGCM`
* `WOLFSSL_SHA512`
* `WOLFSSL_SHA384`
* `NO_MD4`
* `NO_HC128`
* `NO_RABBIT`
* `NO_DSA`
* `NO_PWDBASED`

The approved FIPS source files are from the CyaSSL project tag v3.4.8.fips. The
files fips.c and fips_test.c, and the wolfCAVP test app are from the FIPS
project tag v3.4.8a. The wolfSSL/wolfCrypt files are from tag v3.4.8.

# Using the FIPS library

The FIPS library contains a self-check verify hash. Normally, on the desktop or
server build, the library is built as a dynamic library. The library looks the
same to every application that builds against it, and can be verified. For
static libraries, when linking into your application, the addresses are all
fixed, and the verify checksum becomes unusable. iOS does not allow dynamic
libraries like this, so static builds are required. This creates a problem.
Every time the application is changed, the FIPS checksum will change, because
the FIPS library's position in the executable may change.

You need to add something to your application that will output the verifyCore
value to be used. The verifyCore in fips_test.c will need to be updated with
this value, the library rebuilt, and relinked into your application. The
application should not be changed during this process or the verifyCore check
will fail again.
