# CMakeList.txt
#
# Copyright (C) 2006-2020 wolfSSL Inc.
#
# This file is part of wolfSSL. (formerly known as CyaSSL)
#
# Usage:
# $ mkdir build
# $ cd build
# $ cmake ..
# $ cmake --build .
#
# To build with debugging use:
# $ cmake .. -DCMAKE_BUILD_TYPE=Debug
#
# See "Building with CMake" in INSTALL for more.

####################################################
# Project
####################################################

cmake_minimum_required(VERSION 3.2)

if("${CMAKE_SOURCE_DIR}" STREQUAL "${CMAKE_BINARY_DIR}")
    message(FATAL_ERROR "In-source builds are not allowed.\
     Run cmake from a separate directory from where CMakeLists.txt lives.\
     NOTE: cmake will now create CMakeCache.txt and CMakeFiles/*.\
     You must delete them, or cmake will refuse to work.")
endif()

project(wolfssl VERSION 5.1.0 LANGUAGES C)

# shared library versioning
# increment if interfaces have been added, removed or changed
set(LIBTOOL_CURRENT 31)
# increment if source code has changed  set to zero if current is incremented
set(LIBTOOL_REVISION 0)
# increment if interfaces have been added set to zero if interfaces have been
# removed or changed
set(LIBTOOL_AGE 1)

math(EXPR LIBTOOL_SO_VERSION "${LIBTOOL_CURRENT} - ${LIBTOOL_AGE}")
set(LIBTOOL_FULL_VERSION ${LIBTOOL_SO_VERSION}.${LIBTOOL_AGE}.${LIBTOOL_REVISION})

set(WOLFSSL_DEFINITIONS)
set(WOLFSSL_LINK_LIBS)

include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/functions.cmake)

####################################################
# Compiler
####################################################
# Let CMake choose default compiler

# TODO: See gl_VISIBILITY in visibility.m4. Need to perform
#       the same checks.
# TODO: Turn on warnings.

if(APPLE)
    # Silence ranlib warning "has no symbols"
    set(CMAKE_C_ARCHIVE_CREATE   "<CMAKE_AR> Scr <TARGET> <LINK_FLAGS> <OBJECTS>")
    set(CMAKE_CXX_ARCHIVE_CREATE "<CMAKE_AR> Scr <TARGET> <LINK_FLAGS> <OBJECTS>")
    set(CMAKE_C_ARCHIVE_FINISH   "<CMAKE_RANLIB> -no_warning_for_no_symbols -c <TARGET>")
    set(CMAKE_CXX_ARCHIVE_FINISH "<CMAKE_RANLIB> -no_warning_for_no_symbols -c <TARGET>")
endif()

include(CheckIncludeFile)

check_include_file("arpa/inet.h" HAVE_ARPA_INET_H)
check_include_file("fcntl.h" HAVE_FCNTL_H)
check_include_file("limits.h" HAVE_LIMITS_H)
check_include_file("netdb.h" HAVE_NETDB_H)
check_include_file("netinet/in.h" HAVE_NETINET_IN_H)
check_include_file("stddef.h" HAVE_STDDEF_H)
check_include_file("time.h" HAVE_TIME_H)
check_include_file("sys/ioctl.h" HAVE_SYS_IOCTL_H)
check_include_file("sys/socket.h" HAVE_SYS_SOCKET_H)
check_include_file("sys/time.h" HAVE_SYS_TIME_H)
check_include_file("errno.h" HAVE_ERRNO_H)
check_include_file("dlfcn.h" HAVE_DLFCN_H)
check_include_file("inttypes.h" HAVE_INTTYPES_H)
check_include_file("memory.h" HAVE_MEMORY_H)
check_include_file("stdint.h" HAVE_STDINT_H)
check_include_file("stdlib.h" HAVE_STDLIB_H)
check_include_file("string.h" HAVE_STRING_H)
check_include_file("strings.h" HAVE_STRINGS_H)
check_include_file("sys/stat.h" HAVE_SYS_STAT_H)
check_include_file("sys/types.h" HAVE_SYS_TYPES_H)
check_include_file("unistd.h" HAVE_UNISTD_H)

include(CheckFunctionExists)

# TODO: Also check if these functions are declared by the
#       expected headers. See comments around
#       AC_CHECK_FUNCS/AC_CHECK_DECLS in configure.ac.
check_function_exists("gethostbyname" HAVE_GETHOSTBYNAME)
check_function_exists("getaddrinfo" HAVE_GETADDRINFO)
check_function_exists("gettimeofday" HAVE_GETTIMEOFDAY)
check_function_exists("gmtime_r" HAVE_GMTIME_R)
check_function_exists("inet_ntoa" HAVE_INET_NTOA)
check_function_exists("memset" HAVE_MEMSET)
check_function_exists("socket" HAVE_SOCKET)
check_function_exists("strftime" HAVE_STRFTIME)

include(CheckTypeSize)

check_type_size("__uint128_t" __UINT128_T)
check_type_size("long long" SIZEOF_LONG_LONG)
check_type_size("long" SIZEOF_LONG)
check_type_size("time_t" SIZEOF_TIME_T)

# By default, HAVE___UINT128_T gets defined as TRUE,
# but we want it as 1.
if(HAVE___UINT128_T)
    set(HAVE___UINT128_T "1" CACHE INTERNAL "Result of TRY_COMPILE" FORCE)
endif()

include(TestBigEndian)

test_big_endian(WORDS_BIGENDIAN)

# Thread local storage
include(CheckCSourceCompiles)

set(TLS_KEYWORDS "__thread" "__declspec(thread)")
foreach(TLS_KEYWORD IN LISTS TLS_KEYWORDS)
    set(TLS_CODE "#include <stdlib.h>
                  static void foo(void) {
                     static ${TLS_KEYWORD} int bar\;
                     exit(1)\;
                  }

                  int main() {
                    return 0\;
                  }"
    )
    check_c_source_compiles(${TLS_CODE} THREAD_LS_ON)

    if(THREAD_LS_ON)
        list(APPEND WOLFSSL_DEFINITIONS "-DHAVE_THREAD_LS")
        break()
    else()
        # THREAD_LS_ON is cached after each call to
        # check_c_source_compiles, and the function
        # won't run subsequent times if the variable
        # is in the cache. To make it run again, we
        # need to remove the variable from the cache.
        unset(THREAD_LS_ON CACHE)
    endif()
endforeach()

# TODO: AX_PTHREAD does a lot. Need to implement the
#       rest of its logic.
find_package(Threads)

####################################################
# Cross Compile Example
####################################################

#set(CMAKE_SYSTEM_NAME Linux)
#set(CMAKE_SYSTEM_PROCESSOR arm)
#set(CMAKE_C_COMPILER "/opt/arm-linux-musleabihf-cross/bin/arm-linux-musleabihf-gcc")
#set(CMAKE_CXX_COMPILER "/opt/arm-linux-musleabihf-cross/bin/arm-linux-musleabihf-g++")
#set(CMAKE_SYSROOT "/opt/arm-linux-musleabihf-cross/arm-linux-musleabihf/")
# Example for setting CFLAGS
#set(CMAKE_C_FLAGS "-std=gnu89 ${CMAKE_C_FLAGS}")
# Example for map file and custom linker script
#set(CMAKE_EXE_LINKER_FLAGS " -Xlinker -Map=output.map -T\"${CMAKE_CURRENT_SOURCE_DIR}/linker.ld\"")

####################################################
# Build Options
####################################################
# TODO: - Debug
#       - FIPS
#       - Distro
#       - Linux Kernel Module
#       - Single precision math
#       - Enable all
#       - Enable all crypto

# For reproducible build, gate out from the build anything that might
# introduce semantically frivolous jitter, maximizing chance of
# identical object files.
set(WOLFSSL_REPRODUCIBLE_BUILD_HELP_STRING "Enable maximally reproducible build (default: disabled)")
add_option("WOLFSSL_REPRODUCIBLE_BUILD" ${WOLFSSL_REPRODUCIBLE_BUILD_HELP_STRING} "no" "yes;no")

if(WOLFSSL_REPRODUCIBLE_BUILD)
    list(APPEND WOLFSSL_DEFINITIONS "-DHAVE_REPRODUCIBLE_BUILD")
    set(CMAKE_C_ARCHIVE_CREATE "<CMAKE_AR> Dqc <TARGET> <LINK_FLAGS> <OBJECTS>")
    set(CMAKE_C_ARCHIVE_APPEND "<CMAKE_AR> Dq  <TARGET> <LINK_FLAGS> <OBJECTS>")
    set(CMAKE_C_ARCHIVE_FINISH "<CMAKE_RANLIB> -D <TARGET>")
endif()

# Support for forcing 32-bit mode
# TODO: detect platform from other options
set(WOLFSSL_32BIT_HELP_STRING "Enables 32-bit support (default: disabled)")
add_option("WOLFSSL_32BIT" ${WOLFSSL_32BIT_HELP_STRING} "no" "yes;no")

# 16-bit compiler support
set(WOLFSSL_16BIT_HELP_STRING "Enables 16-bit support (default: disabled)")
add_option("WOLFSSL_16BIT" ${WOLFSSL_16BIT_HELP_STRING} "no" "yes;no")
if(WOLFSSL_16BIT)
    list(APPEND WOLFSSL_DEFINITIONS "-DWC_16BIT_CPU")
endif()

# Support for disabling all ASM
set(WOLFSSL_ASM_HELP_STRING "Enables option for assembly (default: enabled)")
add_option("WOLFSSL_ASM" ${WOLFSSL_ASM_HELP_STRING} "yes" "yes;no")

if(NOT WOLFSSL_ASM)
    list(APPEND WOLFSSL_DEFINITIONS
        "-DTFM_NO_ASM"
        "-DWOLFSSL_NO_ASM")
endif()

# Single threaded
set(WOLFSSL_SINGLE_THREADED_HELP_STRING "Enable wolfSSL single threaded (default: disabled)")
add_option("WOLFSSL_SINGLE_THREADED" ${WOLFSSL_SINGLE_THREADED_HELP_STRING} "no" "yes;no")

# TODO: Logic here isn't complete, yet (see AX_PTHREAD)
if(NOT WOLFSSL_SINGLE_THREADED)
    if(CMAKE_USE_PTHREADS_INIT)
        list(APPEND WOLFSSL_LINK_LIBS Threads::Threads)
        list(APPEND WOLFSSL_DEFINITIONS
            "-DHAVE_PTHREAD"
            "-D_POSIX_THREADS")
    endif()
endif()

# TODO: - DTLS
#       - TLS v1.3 Draft 18

# TLS v1.3
set(WOLFSSL_TLS13_HELP_STRING "Enable wolfSSL TLS v1.3 (default: enabled)")
add_option("WOLFSSL_TLS13" ${WOLFSSL_TLS13_HELP_STRING} "yes" "yes;no")

if("${FIPS_VERSION}" STREQUAL "v1")
    override_cache(WOLFSSL_TLS13 "no")
endif()

# TODO: Post-handshake authentication
#       Hello retry request cookie

# RNG
set(WOLFSSL_RNG_HELP_STRING "Enable compiling and using RNG (default: enabled)")
add_option("WOLFSSL_RNG" ${WOLFSSL_RNG_HELP_STRING} "yes" "yes;no")

if(NOT WOLFSSL_RNG)
    list(APPEND WOLFSSL_DEFINITIONS "-DWC_NO_RNG")
endif()

# TODO: - DTLS-SCTP
#       - DTLS multicast
#       - OpenSSH
#       - OpenVPN
#       - Nginx
#       - HAProxy
#       - wpa_supplicant
#       - Fortress
#       - libwebsockets
#       - IP alternative name
#       - Qt
#       - SSL bump
#       - sniffer
#       - Signal
#       - OpenSSL coexist
#       - OpenSSL compatibility all
#       - OpenSSL compatibility extra
#       - Max strength

# Harden, enable Timing Resistance and Blinding by default
set(WOLFSSL_HARDEN_HELP_STRING "Enable Hardened build, Enables Timing Resistance and Blinding (default: enabled)")
add_option("WOLFSSL_HARDEN" ${WOLFSSL_HARDEN_HELP_STRING} "yes" "yes;no")

if(WOLFSSL_HARDEN)
    list(APPEND WOLFSSL_DEFINITIONS "-DTFM_TIMING_RESISTANT" "-DECC_TIMING_RESISTANT")

    if(WOLFSSL_RNG)
        list(APPEND WOLFSSL_DEFINITIONS "-DWC_RSA_BLINDING")
    endif()
else()
    list(APPEND WOLFSSL_DEFINITIONS "-DWC_NO_HARDEN")
endif()

set(WOLFSSL_OPENSSLEXTRA_HELP_STRING "Enable extra OpenSSL API, size+ (default: disabled)")
add_option(WOLFSSL_OPENSSLEXTRA ${WOLFSSL_OPENSSLEXTRA_HELP_STRING} "no" "yes;no")

if (WOLFSSL_OPENSSLEXTRA AND NOT WOLFSSL_OPENSSLCOEXIST)
    list(APPEND WOLFSSL_DEFINITIONS
      "-DOPENSSL_EXTRA"
      "-DWOLFSSL_ALWAYS_VERIFY_CB"
      "-DWOLFSSL_VERIFY_CB_ALL_CERTS"
      "-DWOLFSSL_EXTRA_ALERTS"
      "-DHAVE_EXT_CACHE"
      "-DWOLFSSL_FORCE_CACHE_ON_TICKET")
endif()

# TODO: - IPv6 test apps

set(WOLFSSL_SLOW_MATH "yes")

# TODO: - Lean PSK
#       - Lean TLS
#       - Low resource
#       - Titan cache
#       - Huge cache
#       - Big cache
#       - Small cache
#       - Persistent session cache
#       - Persistent cert cache
#       - Write duplicate
#       - Atomic user record layer
#       - Public key callbacks
#       - Microchip/Atmel CryptoAuthLib

# AES-CBC
set(WOLFSSL_AESCBC_HELP_STRING "Enable wolfSSL AES-CBC support (default: enabled)")
add_option("WOLFSSL_AESCBC" ${WOLFSSL_AESCBC_HELP_STRING} "yes" "yes;no")

if(NOT WOLFSSL_AESCBC)
    list(APPEND WOLFSSL_DEFINITIONS "-DNO_AES_CBC")
endif()

# AES-GCM
set(WOLFSSL_AESGCM_HELP_STRING "Enable wolfSSL AES-GCM support (default: enabled)")
add_option("WOLFSSL_AESGCM" ${WOLFSSL_AESGCM_HELP_STRING} "yes" "yes;no;table;small;word32;4bit")

# leanpsk and leantls don't need gcm
if(WOLFSSL_LEAN_PSK OR (WOLFSSL_LEAN_TLS AND NOT WOLFSSL_TLS13))
    override_cache(WOLFSSL_AESGCM "no")
endif()

if(WOLFSSL_AESGCM AND NOT WORDS_BIGENDIAN)
    override_cache(WOLFSSL_AESGCM "4bit")
endif()

if(WOLFSSL_AESGCM)
    if("${WOLFSSL_AESGCM}" STREQUAL "word32")
        list(APPEND WOLFSSL_DEFINITIONS "-DGCM_WORD32")
        override_cache(WOLFSSL_AESGCM "yes")
    endif()

    if(("${WOLFSSL_AESGCM}" STREQUAL "small") OR WOLFSSL_LOW_RESOURCE)
        list(APPEND WOLFSSL_DEFINITIONS "-DGCM_SMALL")
        override_cache(WOLFSSL_AESGCM "yes")
    endif()

    if("${WOLFSSL_AESGCM}" STREQUAL "table")
        list(APPEND WOLFSSL_DEFINITIONS "-DGCM_TABLE")
        override_cache(WOLFSSL_AESGCM "yes")
    endif()

    if("${WOLFSSL_AESGCM}" STREQUAL "4bit")
        list(APPEND WOLFSSL_DEFINITIONS "-DGCM_TABLE_4BIT")
        override_cache(WOLFSSL_AESGCM "yes")
    endif()

    list(APPEND WOLFSSL_DEFINITIONS "-DHAVE_AESGCM")
endif()

# TODO: - AES-CCM
#       - AES-GCM stream
#       - AES-CTR
#       - AES-OFB
#       - AES-CFB
#       - AES-ARM
#       - Xilinx hardened crypto
#       - Intel AES-NI
#       - Intel ASM
#       - Intel RDRAND
#       - Linux af_alg
#       - Linux dev crpyto calls
#       - Camellia
#       - MD2
#       - NULL cipher
#       - RIPEMD
#       - BLAKE2


# Align data
set(WOLFSSL_ALIGN_DATA_HELP_STRING "Align data for ciphers (default: enabled)")
add_option("WOLFSSL_ALIGN_DATA" ${WOLFSSL_ALIGN_DATA_HELP_STRING} "yes" "yes;no")
if(WOLFSSL_ALIGN_DATA)
    list(APPEND WOLFSSL_DEFINITIONS "-DWOLFSSL_USE_ALIGN")
endif()

# SHA224
set(SHA224_DEFAULT "no")
if(("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "x86_64") OR
    ("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "aarch64"))
    if(NOT WOLFSSL_AFALG AND NOT WOLFSSL_DEVCRYPTO AND
       (NOT WOLFSSL_FIPS OR ("${FIPS_VERSION}" STREQUAL "v2")))
        set(SHA224_DEFAULT "yes")
    endif()
endif()
set(WOLFSSL_SHA224_HELP_STRING "Enable wolfSSL SHA-224 support (default: enabled on x86_64/aarch64)")
add_option("WOLFSSL_SHA224" ${WOLFSSL_SHA224_HELP_STRING} ${SHA224_DEFAULT} "yes;no")

# SHA3
set(SHA3_DEFAULT "no")
if(("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "x86_64") OR
    ("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "aarch64"))
    if(NOT WOLFSSL_FIPS OR ("${FIPS_VERSION}" STREQUAL "v2"))
        set(SHA3_DEFAULT "yes")
    endif()
endif()
set(WOLFSSL_SHA3_HELP_STRING "Enable wolfSSL SHA-3 support (default: enabled on x86_64/aarch64)")
add_option("WOLFSSL_SHA3" ${WOLFSSL_SHA3_HELP_STRING} ${SHA3_DEFAULT} "yes;no;small")

# SHAKE256
set(WOLFSSL_SHAKE256_HELP_STRING "Enable wolfSSL SHAKE256 support (default: enabled on x86_64/aarch64)")
add_option("WOLFSSL_SHAKE256" ${WOLFSSL_SHAKE256_HELP_STRING} "no" "yes;no;small")

# SHA512
set(WOLFSSL_SHA512_HELP_STRING "Enable wolfSSL SHA-512 support (default: enabled)")
add_option("WOLFSSL_SHA512" ${WOLFSSL_SHA512_HELP_STRING} "yes" "yes;no")

# options that don't require sha512
if(WOLFSSL_LEAN_PSK OR
   WOLFSSL_LEAN_TLS OR
   WOLFSSL_32BIT OR
   WOLFSSL_16BIT)
    override_cache(WOLFSSL_SHA512 "no")
endif()

# options that require sha512
if(WOLFSSL_OPENSSH OR
   WOLFSSL_WPAS OR
   WOLFSSL_FORTRESS)
    override_cache(WOLFSSL_SHA512 "yes")
endif()

if(WOLFSSL_SHA512)
    list(APPEND WOLFSSL_DEFINITIONS "-DWOLFSSL_SHA512")
endif()

# SHA384
set(WOLFSSL_SHA384_HELP_STRING "Enable wolfSSL SHA-384 support (default: enabled)")
add_option("WOLFSSL_SHA384" ${WOLFSSL_SHA384_HELP_STRING} "yes" "yes;no")

# options that don't require sha384
if(WOLFSSL_LEAN_PSK OR
   WOLFSSL_LEAN_TLS OR
   WOLFSSL_32BIT OR
   WOLFSSL_16BIT)
    override_cache(WOLFSSL_SHA384 "no")
endif()

# options that require sha384
if(WOLFSSL_OPENSSH OR
   WOLFSSL_WPAS OR
   WOLFSSL_FORTRESS)
    override_cache(WOLFSSL_SHA384 "yes")
endif()

if(WOLFSSL_SHA384)
    list(APPEND WOLFSSL_DEFINITIONS "-DWOLFSSL_SHA384")
endif()

# TODO: - Session certs
#       - Key generation
#       - Cert generation
#       - Cert request generation
#       - Cert request extension
#       - Decoded cert cache
#       - SEP

# HKDF
set(WOLFSSL_HKDF_HELP_STRING "Enable HKDF (HMAC-KDF) support (default: disabled)")
add_option("WOLFSSL_HKDF" ${WOLFSSL_HKDF_HELP_STRING} "no" "yes;no")

if(WOLFSSL_TLS13)
    override_cache(WOLFSSL_HKDF "yes")
endif()

if(WOLFSSL_HKDF)
    list(APPEND WOLFSSL_DEFINITIONS "-DHAVE_HKDF")
endif()

# TODO: - X9.63 KDF

# DSA
set(WOLFSSL_DSA_HELP_STRING "Enable DSA (default: disabled)")
add_option("WOLFSSL_DSA" ${WOLFSSL_DSA_HELP_STRING} "no" "yes;no")

if(NOT WOLFSSL_DSA AND NOT WOLFSSL_OPENSSH)
    list(APPEND WOLFSSL_DEFINITIONS "-DNO_DSA")
endif()

# ECC Shamir
set(WOLFSSL_ECCSHAMIR_HELP_STRING "Enable ECC Shamir (default: enabled)")
add_option("WOLFSSL_ECCSHAMIR" ${WOLFSSL_ECCSHAMIR_HELP_STRING} "yes" "yes;no")

# ECC
set(WOLFSSL_ECC_HELP_STRING "Enable ECC (default: enabled)")
add_option("WOLFSSL_ECC" ${WOLFSSL_ECC_HELP_STRING} "yes" "yes;no;nonblock")

# lean psk doesn't need ecc
if(WOLFSSL_LEAN_PSK)
    override_cache(WOLFSSL_ECC "no")
endif()

if(WOLFSSL_OPENSSH OR
   WOLFSSL_NGINX OR
   WOLFSSL_SIGNAL)
    override_cache(WOLFSSL_ECC "yes")
endif()

if(WOLFSSL_ECC)
    list(APPEND WOLFSSL_DEFINITIONS "-DHAVE_ECC" "-DTFM_ECC256")

    if(WOLFSSL_ECCSHAMIR AND NOT WOLFSSL_LOW_RESOURCE)
        list(APPEND WOLFSSL_DEFINITIONS "-DECC_SHAMIR")
    endif()

    if("${WOLFSSL_ECC}" STREQUAL "nonblock")
        list(APPEND WOLFSSL_DEFINITIONS "-DWC_ECC_NONBLOCK")
    endif()
endif()

# TODO: - ECC custom curves
#       - Compressed key
#       - FP ECC, fixed point cache ECC
#       - ECC encrypt
#       - PSK
#       - Single PSK identity

# CURVE25519
set(WOLFSSL_CURVE25519_SMALL "no")
set(WOLFSSL_CURVE25519_HELP_STRING "Enable Curve25519 (default: disabled)")
add_option("WOLFSSL_CURVE25519" ${WOLFSSL_CURVE25519_HELP_STRING} "no" "yes;no;small;no128bit")

if(WOLFSSL_OPENSSH)
    override_cache(WOLFSSL_CURVE25519 "yes")
endif()

if(WOLFSSL_CURVE25519)
    if("${WOLFSSL_CURVE25519}" STREQUAL "small" OR WOLFSSL_LOW_RESOURCE)
        list(APPEND WOLFSSL_DEFINITIONS "-DCURVE25519_SMALL")
        set(WOLFSSL_CURVE25519_SMALL "yes")
    endif()

    if("${WOLFSSL_CURVE25519}" STREQUAL "no128bit" OR WOLFSSL_32BIT)
        list(APPEND WOLFSSL_DEFINITIONS "-DNO_CURVED25519_128BIT")
    endif()

    list(APPEND WOLFSSL_DEFINITIONS "-DHAVE_CURVE25519")
    set(WOLFSSL_FEMATH "yes")
endif()

# ED25519
set(WOLFSSL_ED25519_SMALL "no")
set(WOLFSSL_ED25519_HELP_STRING "Enable ED25519 (default: disabled)")
add_option("WOLFSSL_ED25519" ${WOLFSSL_ED25519_HELP_STRING} "no" "yes;no")

if(WOLFSSL_OPENSSH)
    override_cache(WOLFSSL_ED25519 "yes")
endif()

if(WOLFSSL_ED25519 AND NOT WOLFSSL_32BIT)
    if("${WOLFSSL_ED25519}" STREQUAL "small" OR WOLFSSL_LOW_RESOURCE)
        list(APPEND WOLFSSL_DEFINITIONS "-DED25519_SMALL")
        set(WOLFSSL_ED25519_SMALL "yes")
        set(WOLFSSL_CURVE25519_SMALL "yes")
    endif()

    if(NOT WOLFSSL_SHA512)
        message(FATAL_ERROR "cannot enable ed25519 without enabling sha512.")
    endif()

    set(WOLFSSL_FEMATH "yes")
    set(WOLFSSL_GEMATH "yes")
    list(APPEND WOLFSSL_DEFINITIONS "-DHAVE_ED25519")
endif()

# CURVE448
set(WOLFSSL_CURVE448_SMALL "no")
set(WOLFSSL_CURVE448_HELP_STRING "Enable Curve448 (default: disabled)")
add_option("WOLFSSL_CURVE448" ${WOLFSSL_CURVE448_HELP_STRING} "no" "yes;no;small")

if(WOLFSSL_CURVE448)
    if("${WOLFSSL_CURVE448}" STREQUAL "small" OR WOLFSSL_LOW_RESOURCE)
        list(APPEND WOLFSSL_DEFINITIONS "-DCURVE448_SMALL")
        set(WOLFSSL_CURVE448_SMALL "yes")
    endif()

    if("${WOLFSSL_CURVE448}" STREQUAL "no128bit" OR WOLFSSL_32BIT)
        list(APPEND WOLFSSL_DEFINITIONS "-DNO_CURVED448_128BIT")
    endif()

    list(APPEND WOLFSSL_DEFINITIONS "-DHAVE_CURVE448")
    set(WOLFSSL_FE448 "yes")
endif()

# ED448
set(WOLFSSL_ED448_SMALL "no")
set(WOLFSSL_ED448_HELP_STRING "Enable ED448 (default: disabled)")
add_option("WOLFSSL_ED448" ${WOLFSSL_ED448_HELP_STRING} "no" "yes;no;small")

if(WOLFSSL_ED448 AND NOT WOLFSSL_32BIT)
    if("${WOLFSSL_ED448}" STREQUAL "small" OR WOLFSSL_LOW_RESOURCE)
        list(APPEND WOLFSSL_DEFINITIONS "-DED448_SMALL")
        set(WOLFSSL_ED448_SMALL "yes")
        set(WOLFSSL_CURVE448_SMALL "yes")
    endif()

    if(NOT WOLFSSL_SHA512)
        message(FATAL_ERROR "cannot enable ed448 without enabling sha512.")
    endif()

    set(WOLFSSL_FE448 "yes")
    set(WOLFSSL_GE448 "yes")
    list(APPEND WOLFSSL_DEFINITIONS "-DHAVE_ED448")

    # EdDSA448 requires SHAKE256 which requires SHA-3
    override_cache(WOLFSSL_SHAKE256 "yes")
endif()

# Error strings
set(WOLFSSL_ERROR_STRINGS_HELP_STRING "Enable error strings table (default: enabled)")
add_option("WOLFSSL_ERROR_STRINGS" ${WOLFSSL_ERROR_STRINGS_HELP_STRING} "yes" "yes;no")

if(NOT WOLFSSL_ERROR_STRINGS)
    list(APPEND WOLFSSL_DEFINITIONS "-DNO_ERROR_STRINGS")
else()
    # turn off error strings if leanpsk or leantls o
    if(WOLFSSL_LEAN_PSK OR WOLFSSL_LEAN_TLS)
        list(APPEND WOLFSSL_DEFINITIONS "-DNO_ERROR_STRINGS")
        override_cache(WOLFSSL_ERROR_STRINGS "no")
    endif()
endif()

# Error queue
set(WOLFSSL_ERROR_QUEUE_HELP_STRING "Enables adding nodes to error queue when compiled with OPENSSL_EXTRA (default: enabled)")
add_option("WOLFSSL_ERROR_QUEUE" ${WOLFSSL_ERROR_QUEUE_HELP_STRING} "yes" "yes;no")

if(NOT WOLFSSL_ERROR_QUEUE)
    list(APPEND WOLFSSL_DEFINITIONS "-DNO_ERROR_QUEUE")
endif()

# Old TLS
set(WOLFSSL_OLD_TLS_HELP_STRING "Enable old TLS versions < 1.2 (default: enabled)")
add_option("WOLFSSL_OLD_TLS" ${WOLFSSL_OLD_TLS_HELP_STRING} "yes" "yes;no")

if(NOT WOLFSSL_OLD_TLS)
    list(APPEND WOLFSSL_DEFINITIONS "-DNO_OLD_TLS")
else()
    # turn off old if leanpsk or leantls on
    if(WOLFSSL_LEAN_PSK OR WOLFSSL_LEAN_TLS)
        list(APPEND WOLFSSL_DEFINITIONS "-DNO_OLD_TLS")
        override_cache(WOLFSSL_OLD_TLS "no")
    endif()
endif()

# TLSv1.2
set(WOLFSSL_TLSV12_HELP_STRING "Enable TLS versions 1.2 (default: enabled)")
add_option("WOLFSSL_TLSV12" ${WOLFSSL_TLSV12_HELP_STRING} "yes" "yes;no")

if(NOT WOLFSSL_TLSV12)
    list(APPEND WOLFSSL_DEFINITIONS
        "-DWOLFSSL_NO_TLS12"
        "-DNO_OLD_TLS")
endif()

# TODO: - TLSv1.0
#       - SSLv3
#       - Stack size
#       - Stack size verbose

# Memory
set(WOLFSSL_MEMORY_HELP_STRING "Enable memory callbacks (default: enabled)")
add_option("WOLFSSL_MEMORY" ${WOLFSSL_MEMORY_HELP_STRING} "yes" "yes;no")

if(NOT WOLFSSL_MEMORY)
    list(APPEND WOLFSSL_DEFINITIONS "-DNO_WOLFSSL_MEMORY")
else()
    # turn off memory cb if leanpsk or leantls on
    if(WOLFSSL_LEAN_PSK OR WOLFSSL_LEAN_TLS)
        # but don't turn on NO_WOLFSSL_MEMORY because using own
        override_cache(WOLFSSL_MEMORY "no")
    endif()
endif()

# TODO: - Track memory
#       - Memory log
#       - Stack log

# RSA
set(WOLFSSL_RSA_HELP_STRING "Enable RSA (default: enabled)")
add_option("WOLFSSL_RSA" ${WOLFSSL_RSA_HELP_STRING} "yes" "yes;no")

if(NOT WOLFSSL_RSA)
    list(APPEND WOLFSSL_DEFINITIONS "-DNO_RSA")
else()
    if(WOLFSSL_LEAN_PSK OR WOLFSSL_LEAN_TLS)
        list(APPEND WOLFSSL_DEFINITIONS "-DNO_RSA")
        override_cache(WOLFSSL_RSA "no")
    endif()
endif()

# OAEP
set(WOLFSSL_OAEP_HELP_STRING "Enable RSA OAEP (default: enabled)")
add_option("WOLFSSL_OAEP" ${WOLFSSL_OAEP_HELP_STRING} "yes" "yes;no")

if(NOT WOLFSSL_OAEP)
    list(APPEND WOLFSSL_DEFINITIONS "-DWC_NO_RSA_OAEP")
endif()

# TODO: - RSA public only
#       - RSA verify inline only

# RSA-PSS
set(WOLFSSL_RSA_PSS_HELP_STRING "Enable RSA-PSS (default: disabled)")
add_option("WOLFSSL_RSA_PSS" ${WOLFSSL_RSA_PSS_HELP_STRING} "no" "yes;no")

if(NOT WOLFSSL_RSA)
    override_cache(WOLFSSL_RSA_PSS "no")
else()
    if(WOLFSSL_TLS13)
        override_cache(WOLFSSL_RSA_PSS "yes")
    endif()
endif()
if(WOLFSSL_RSA_PSS)
    list(APPEND WOLFSSL_DEFINITIONS "-DWC_RSA_PSS")
endif()

# DH
set(WOLFSSL_DH_HELP_STRING "Enable DH (default: enabled)")
add_option("WOLFSSL_DH" ${WOLFSSL_DH_HELP_STRING} "yes" "yes;no")

if(WOLFSSL_OPENSSH)
    override_cache(WOLFSSL_DH "yes")
endif()

if(NOT WOLFSSL_DH)
    list(APPEND WOLFSSL_DEFINITIONS "-DNO_DH")
else()
    if(WOLFSSL_LEAN_PSK OR WOLFSSL_LEAN_TLS)
      list(APPEND WOLFSSL_DEFINITIONS "-DNO_DH")
      override_cache(WOLFSSL_DH "no")
    endif()
endif()

# TODO: - Anonymous

# ASN
# turn off asn, which means no certs, no rsa, no dsa, no ecc,
# and no big int (unless dh is on)
set(WOLFSSL_ASN_HELP_STRING "Enable ASN (default: enabled)")
add_option("WOLFSSL_ASN" ${WOLFSSL_ASN_HELP_STRING} "yes" "yes;no")

if(NOT WOLFSSL_ASN)
    list(APPEND WOLFSSL_DEFINITIONS "-DNO_ASN" "-DNO_CERTS")

    if(NOT WOLFSSL_DH AND NOT WOLFSSL_ECC)
        # DH and ECC need bigint
        list(APPEND WOLFSSL_DEFINITIONS "-DNO_BIG_INT")
    endif()
else()
    # turn off ASN if leanpsk on
    if(WOLFSSL_LEAN_PSK)
        list(APPEND WOLFSSL_DEFINITIONS
            "-DNO_ASN"
            "-DNO_CERTS"
            "-DNO_BIG_INT")
        override_cache(WOLFSSL_ASN "no")
    else()
        if("${WOLFSSL_ASN}" STREQUAL "nocrypt")
            list(APPEND WOLFSSL_DEFINITIONS "-DNO_ASN_CRYPT")
            # TODO: verify that this is correct
            override_cache(WOLFSSL_PWDBASED "no")
        endif()
    endif()
endif()

if(WOLFSSL_RSA AND NOT WOLFSSL_RSA_VFY AND NOT WOLFSSL_ASN)
    message(FATAL_ERROR "please disable rsa if disabling asn.")
endif()

if(WOLFSSL_DSA AND NOT WOLFSSL_ASN)
    message(FATAL_ERROR "please disable dsa if disabling asn.")
endif()

# DH and ECC need bigint
if(NOT WOLFSSL_ASN AND
   NOT WOLFSSL_DH AND
   NOT WOLFSSL_ECC AND
   NOT WOLFSSL_RSA)
    override_cache(WOLFSSL_FAST_MATH "no")
    set(WOLFSSL_SLOWMATH "no")
endif()

# AES
set(WOLFSSL_AES_HELP_STRING "Enable AES (default: enabled)")
add_option("WOLFSSL_AES" ${WOLFSSL_AES_HELP_STRING} "yes" "yes;no")

if(NOT WOLFSSL_AES)
    list(APPEND WOLFSSL_DEFINITIONS "-DNO_AES")

    if(WOLFSSL_FORTRESS)
        message(FATAL_ERROR "fortress requires aes")
    endif()
    if(WOLFSSL_ECC_ENCRYPT)
        message(FATAL_ERROR "cannot enable eccencrypt and hkdf without aes.")
    endif()
    if(WOLFSSL_AESGCM)
        message(FATAL_ERROR "AESGCM requires AES.")
    endif()
    if(WOLFSSL_AESCCM)
        message(FATAL_ERROR "AESCCM requires AES.")
    endif()
    if(WOLFSSL_AESCTR)
        message(FATAL_ERROR "AESCTR requires AES.")
    endif()
else()
    if(WOLFSSL_LEAN_PSK)
        list(APPEND WOLFSSL_DEFINITIONS "-DNO_AES")
        override_cache(WOLFSSL_AES "no")
    endif()
endif()

# Coding
set(WOLFSSL_CODING_HELP_STRING "Enable coding base 16/64 (default: enabled)")
add_option("WOLFSSL_CODING" ${WOLFSSL_CODING_HELP_STRING} "yes" "yes;no")

if(NOT WOLFSSL_CODING)
    list(APPEND WOLFSSL_DEFINITIONS "-DNO_CODING")
else()
    # turn off CODING if leanpsk on
    if(WOLFSSL_LEAN_PSK)
        list(APPEND WOLFSSL_DEFINITIONS "-DNO_CODING")
        override_cache(WOLFSSL_CODING "no")
    endif()
endif()

# Base64
set(BASE64_ENCODE_DEFAULT "no")
if("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "x86_64")
    set(BASE64_ENCODE_DEFAULT "yes")
endif()

set(WOLFSSL_BASE64_ENCODE_HELP_STRING "Enable Base64 encoding (default: enabled on x86_64)")
add_option("WOLFSSL_BASE64_ENCODE" ${WOLFSSL_BASE64_ENCODE_HELP_STRING} ${BASE64_ENCODE_DEFAULT} "yes;no")

if(WOLFSSL_BASE64_ENCODE)
    list(APPEND WOLFSSL_DEFINITIONS "-DWOLFSSL_BASE64_ENCODE")
endif()

# TODO: - Base16

# DES3
set(WOLFSSL_DES3_HELP_STRING "Enable DES3 (default: disabled)")
add_option("WOLFSSL_DES3" ${WOLFSSL_DES3_HELP_STRING} "no" "yes;no")

if(WOLFSSL_OPENSSH OR
   WOLFSSL_QT OR
   WOLFSSL_OPENVPN OR
   WOLFSSL_WPAS)
    override_cache(WOLFSSL_DES3 "yes")
endif()

# TODO: - IDEA

# ARC4
set(WOLFSSL_ARC4_HELP_STRING "Enable ARC4 (default: disabled)")
add_option("WOLFSSL_ARC4" ${WOLFSSL_ARC4_HELP_STRING} "no" "yes;no")

if(WOLFSSL_OPENSSH OR WOLFSSL_WPAS)
    override_cache(WOLFSSL_ARC4 "yes")
endif()

# MD5
set(WOLFSSL_MD5_HELP_STRING "Enable MD5 (default: enabled)")
add_option("WOLFSSL_MD5" ${WOLFSSL_MD5_HELP_STRING} "yes" "yes;no")

if(NOT WOLFSSL_MD5)
    list(APPEND WOLFSSL_DEFINITIONS "-DNO_MD5" "-DNO_OLD_TLS")
else()
    # turn off MD5 if leanpsk or leantls on
    if(WOLFSSL_LEAN_PSK OR WOLFSSL_LEAN_TLS)
        list(APPEND WOLFSSL_DEFINITIONS "-DNO_MD5" "-DNO_OLD_TLS")
        override_cache(WOLFSSL_MD5 "no")
    endif()
endif()

# SHA
set(WOLFSSL_SHA_HELP_STRING "Enable SHA (default: enabled)")
add_option("WOLFSSL_SHA" ${WOLFSSL_SHA_HELP_STRING} "yes" "yes;no")

if(NOT WOLFSSL_SHA)
    list(APPEND WOLFSSL_DEFINITIONS "-DNO_SHA" "-DNO_OLD_TLS")
else()
    # turn off SHA if leanpsk or leantls on
    if(WOLFSSL_LEAN_PSK OR WOLFSSL_LEAN_TLS)
        list(APPEND WOLFSSL_DEFINITIONS "-DNO_SHA" "-DNO_OLD_TLS")
        override_cache(WOLFSSL_SHA "no")
    endif()
endif()

# TODO: - CMAC
#       - AES-XTS
#       - Web server
#       - Web client

# HC128
set(WOLFSSL_HC128_HELP_STRING "Enable HC-128 (default: disabled)")
add_option("WOLFSSL_HC128" ${WOLFSSL_HC128_HELP_STRING} "no" "yes;no")

if(NOT WOLFSSL_HC128)
    list(APPEND WOLFSSL_DEFINITIONS "-DNO_HC128")
else()
    list(APPEND WOLFSSL_DEFINITIONS "-DHAVE_HC128")
endif()

# RABBIT
if(NOT WOLFSSL_RABBIT)
    list(APPEND WOLFSSL_DEFINITIONS "-DNO_RABBIT")
else()
    list(APPEND WOLFSSL_DEFINITIONS "-DHAVE_RABBIT")
endif()

# TODO: - RC2
#       - FIPS, again (there's more logic for FIPS after RABBIT in configure.ac)
#       - Selftest

# SHA224
if(WOLFSSL_SHA224)
    list(APPEND WOLFSSL_DEFINITIONS "-DWOLFSSL_SHA224")
endif()

# SHA3
if("${WOLFSSL_SHA3}" STREQUAL "small")
    list(APPEND WOLFSSL_DEFINITIONS "-DWOLFSSL_SHA3_SMALL")
    override_cache(WOLFSSL_SHA3 "yes")
endif()

if(WOLFSSL_SHA3 AND NOT WOLFSSL_32BIT)
    list(APPEND WOLFSSL_DEFINITIONS "-DWOLFSSL_SHA3")
endif()

# SHAKE256
if(WOLFSSL_SHAKE256)
    if(NOT WOLFSSL_32BIT)
        list(APPEND WOLFSSL_DEFINITIONS "-DWOLFSSL_SHAKE256")

        if(NOT WOLFSSL_SHA3)
            message(FATAL_ERROR "Must have SHA-3 enabled: --enable-sha3")
        endif()
    endif()
endif()

# POLY1305
set(POLY1305_DEFAULT "yes")
if(WOLFSSL_FIPS)
    set(POLY1305_DEFAULT "no")
endif()

set(WOLFSSL_POLY1305_HELP_STRING "Enable wolfSSL POLY1305 support (default: enabled)")
add_option("WOLFSSL_POLY1305" ${WOLFSSL_POLY1305_HELP_STRING} ${POLY1305_DEFAULT} "yes;no")

# leanpsk and leantls don't need poly1305
if(WOLFSSL_LEAN_PSK OR WOLFSSL_LEAN_TLS)
    override_cache(WOLFSSL_POLY1305 "no")
endif()

if(WOLFSSL_POLY1305)
    list(APPEND WOLFSSL_DEFINITIONS
        "-DHAVE_POLY1305"
        "-DHAVE_ONE_TIME_AUTH")
endif()

# CHACHA
set(CHACHA_DEFAULT "yes")
if(WOLFSSL_FIPS)
    set(CHACHA_DEFAULT "no")
endif()

set(WOLFSSL_CHACHA_HELP_STRING "Enable CHACHA (default: enabled). Use `=noasm` to disable ASM AVX/AVX2 speedups")
add_option("WOLFSSL_CHACHA" ${WOLFSSL_CHACHA_HELP_STRING} ${CHACHA_DEFAULT} "yes;no;noasm")

# leanpsk and leantls don't need chacha
if(WOLFSSL_LEAN_PSK OR WOLFSSL_LEAN_TLS)
    override_cache(WOLFSSL_CHACHA "no")
endif()

if(("${WOLFSSL_CHACHA}" STREQUAL "noasm") OR NOT WOLFSSL_ASM)
    list(APPEND WOLFSSL_DEFINITIONS "-DNO_CHACHA_ASM")
endif()

if(NOT ("${WOLFSSL_CHACHA}" STREQUAL "noasm") AND WOLFSSL_CHACHA)
    list(APPEND WOLFSSL_DEFINITIONS "-DHAVE_CHACHA")
endif()

# TODO: - XCHACHA

# Hash DRBG
set(WOLFSSL_HASH_DRBG_HELP_STRING "Enable Hash DRBG support (default: enabled)")
add_option("WOLFSSL_HASH_DRBG" ${WOLFSSL_HASH_DRBG_HELP_STRING} "yes" "yes;no")

if(WOLFSSL_HASH_DRBG)
    list(APPEND WOLFSSL_DEFINITIONS "-DHAVE_HASHDRBG")
else()
    # turn on Hash DRBG if FIPS is on
    if(WOLFSSL_FIPS)
        list(APPEND WOLFSSL_DEFINITIONS "-DHAVE_HASHDRBG")
        override_cache(WOLFSSL_HASH_DRBG "yes")
    else()
        list(APPEND WOLFSSL_DEFINITIONS "-DWC_NO_HASHDRBG")
    endif()
endif()

# Filesystem
if(WOLFSSL_LINUX_KM)
    set(FILESYSTEM_DEFAULT "no")
else()
    set(FILESYSTEM_DEFAULT "yes")
endif()

set(WOLFSSL_FILESYSTEM_HELP_STRING "Enable Filesystem support (default: enabled)")
add_option("WOLFSSL_FILESYSTEM" ${WOLFSSL_FILESYSTEM_HELP_STRING} ${FILESYSTEM_DEFAULT} "yes;no")

if(NOT WOLFSSL_FILESYSTEM)
    list(APPEND WOLFSSL_DEFINITIONS "-DNO_FILESYSTEM")
else()
    if(WOLFSSL_LEAN_PSK OR WOLFSSL_LEAN_TLS)
        list(APPEND WOLFSSL_DEFINITIONS "-DNO_FILESYSTEM")
        override_cache(WOLFSSL_FILESYSTEM "no")
    endif()
endif()

# Inline function support
set(WOLFSSL_INLINE_HELP_STRING "Enable inline functions (default: enabled)")
add_option("WOLFSSL_INLINE" ${WOLFSSL_INLINE_HELP_STRING} "yes" "yes;no")

if(NOT WOLFSSL_INLINE)
    list(APPEND WOLFSSL_DEFINITIONS "-DNO_INLINE")
endif()

# TODO: - OCSP
#       - OCSP stapling
#       - OCSP stapling v2
#       - CRL
#       - CRL monitor
#       - User crypto
#       - Whitewood netRandom client library
#       - SNI
#       - Max fragment length
#       - ALPN
#       - Trusted CA indication
#       - Truncated HMAC
#       - Renegotiation indication
#       - Secure renegotiation
#       - Fallback SCSV

set(WOLFSSL_SNI_HELP_STRING "Enable SNI (default: disabled)")
add_option(WOLFSSL_SNI ${WOLFSSL_SNI_HELP_STRING} "no" "yes;no")

if (WOLFSSL_SNI)
   list(APPEND WOLFSSL_DEFINITIONS "-DHAVE_TLS_EXTENSIONS" "-DHAVE_SNI")
endif()


set(WOLFSSL_TLSX_HELP_STRING "Enable all TLS Extensions (default: disabled)")
add_option(WOLFSSL_TLSX ${WOLFSSL_TLSX_HELP_STRING} "no" "yes;no")

if (WOLFSSL_TLSX)
  list(APPEND WOLFSSL_DEFINITIONS
    "-DHAVE_TLS_EXTENSIONS"
    "-DHAVE_SNI"
    "-DHAVE_MAX_FRAGMENT"
    "-DHAVE_TRUNCATED_HMAC"
    "-DHAVE_ALPN"
    "-DHAVE_TRUSTED_CA")
    if (WOLFSSL_ECC OR WOLFSSL_CURVE25519 OR WOLFSSL_CURVE448 OR WOLFSSL_TLS13)
       list(APPEND WOLFSSL_DEFINITIONS  "-DHAVE_SUPPORTED_CURVES")
    endif()
endif()


# Supported elliptic curves extensions
set(WOLFSSL_SUPPORTED_CURVES_HELP_STRING "Enable Supported Elliptic Curves (default: enabled)")
add_option("WOLFSSL_SUPPORTED_CURVES" ${WOLFSSL_SUPPORTED_CURVES_HELP_STRING} "yes" "yes;no")

if(WOLFSSL_SUPPORTED_CURVES)
    if(NOT WOLFSSL_ECC AND NOT WOLFSSL_CURVE25519 AND NOT WOLFSSL_CURVE448)
        override_cache(WOLFSSL_SUPPORTED_CURVES "no")
    else()
        list(APPEND WOLFSSL_DEFINITIONS
            "-DHAVE_TLS_EXTENSIONS"
            "-DHAVE_SUPPORTED_CURVES")
    endif()
endif()

# Diffie-Hellman
if(WOLFSSL_DH)
    if(WOLFSSL_TLS13 OR WOLFSSL_SUPPORTED_CURVES)
        list(APPEND WOLFSSL_DEFINITIONS "-DHAVE_FFDHE_2048")
    endif()
endif()

# TODO: - FFDHE params only

# TLS 1.3 Requires either ECC or (RSA/DH), or CURVE25519/ED25519 or CURVE448/ED448
if (NOT WOLFSSL_ECC AND
    (NOT WOLFSSL_RSA OR NOT WOLFSSL_DH) AND
    (NOT WOLFSSL_CURVE25519 OR NOT WOLFSSL_ED25519) AND
    (NOT WOLFSSL_CURVE448 AND NOT WOLFSSL_ED448))
    override_cache(WOLFSSL_TLS13 "no")
endif()
if (WOLFSSL_TLS13)
    list(APPEND WOLFSSL_DEFINITIONS
        "-DHAVE_SUPPORTED_CURVES"
        "-DWOLFSSL_TLS13"
        "-DHAVE_TLS_EXTENSIONS"
        )
endif()

# Session Ticket Extension
set(WOLFSSL_SESSION_TICKET_HELP_STRING "Enable Session Ticket (default: disabled)")
add_option("WOLFSSL_SESSION_TICKET" ${WOLFSSL_SESSION_TICKET_HELP_STRING} "no" "yes;no")

if(WOLFSSL_NGINX OR WOLFSSL_WPAS OR WOLFSSL_HAPROXY OR WOLFSSL_LIGHTY)
    override_cache(WOLFSSL_SESSION_TICKET "yes")
endif()

if(WOLFSSL_SESSION_TICKET)
    list(APPEND WOLFSSL_DEFINITIONS
        "-DHAVE_TLS_EXTENSIONS"
        "-DHAVE_SESSION_TICKET")
endif()

# Extended master secret extension
set(WOLFSSL_EXTENDED_MASTER_HELP_STRING "Enable Extended Master Secret (default: enabled)")
add_option("WOLFSSL_EXTENDED_MASTER" ${WOLFSSL_EXTENDED_MASTER_HELP_STRING} "yes" "yes;no")

if(WOLFSSL_EXTENDED_MASTER)
    list(APPEND WOLFSSL_DEFINITIONS "-DHAVE_EXTENDED_MASTER")
endif()


if(NOT WOLFSSL_ARC4)
    list(APPEND WOLFSSL_DEFINITIONS "-DNO_RC4")
else()
    # turn off ARC4 if leanpsk or leantls on
    if(WOLFSSL_LEAN_PSK OR WOLFSSL_LEAN_TLS)
        list(APPEND WOLFSSL_DEFINITIONS "-DNO_RC4")
        override_cache(WOLFSSL_ARC4 "no")
    endif()
endif()

# TODO: - TLS extensions
#       - Early data handshake
#       - PKCS7
#       - wolfSSH options
#       - SCEP
#       - Secure remote password
#       - Indefinite length encoded messages
#       - Small stack cache
#       - Small stack
#       - Valgrind
#       - Test certs
#       - I/O pool example
#       - Certificate service
#       - wolfSSL JNI
#       - lighttpd/lighty
#       - Asio
#       - Apache HTTPD

# Encrypt-then-mac
set(WOLFSSL_ENC_THEN_MAC_HELP_STRING "Enable Encryptr-Then-Mac extension (default: enabled)")
add_option("WOLFSSL_ENC_THEN_MAC" ${WOLFSSL_ENC_THEN_MAC_HELP_STRING} "yes" "yes;no")

if(WOLFSSL_APACHE_HTTPD)
    override_cache(WOLFSSL_ENC_THEN_MAC "no")
endif()

if(WOLFSSL_TLSX)
    override_cache(WOLFSSL_ENC_THEN_MAC "yes")
endif()

if(WOLFSSL_SNIFFER)
    override_cache(WOLFSSL_ENC_THEN_MAC "no")
endif()

# stunnel Support
# TODO: rest of stunnel support
set(WOLFSSL_STUNNEL_HELP_STRING "Enable stunnel (default: disabled)")
add_option("WOLFSSL_STUNNEL" ${WOLFSSL_STUNNEL_HELP_STRING} "no" "yes;no")

if(WOLFSSL_ENC_THEN_MAC)
    list(APPEND WOLFSSL_DEFINITIONS "-DHAVE_ENCRYPT_THEN_MAC")
endif()

if(NOT WOLFSSL_PSK AND
   NOT WOLFSSL_LEAN_PSK AND
   NOT WOLFSSL_STUNNEL)
    list(APPEND WOLFSSL_DEFINITIONS "-DNO_PSK")
endif()

# MD4
set(WOLFSSL_MD4_HELP_STRING "Enable MD4 (default: disabled)")
add_option("WOLFSSL_MD4" ${WOLFSSL_MD4_HELP_STRING} "no" "yes;no")

if(NOT WOLFSSL_MD4)
    # turn on MD4 if using stunnel
    if(WOLFSSL_STUNNEL OR WOLFSSL_WPAS)
        override_cache(WOLFSSL_MD4 "yes")
    else()
        list(APPEND WOLFSSL_DEFINITIONS "-DNO_MD4")
    endif()
endif()

#  Encrypted keys
set(WOLFSSL_ENCKEYS_HELP_STRING "Enable PEM encrypted key support (default: disabled)")
add_option("WOLFSSL_ENCKEYS" ${WOLFSSL_ENCKEYS_HELP_STRING} "no" "yes;no")

if(NOT WOLFSSL_ENCKEYS)
    if(WOLFSSL_OPENSSLEXTRA OR
        WOLFSSL_WEBSERVER OR
        WOLFSSL_WPAS)
        # opensslextra, webserver, and WPAS  needs enckeys
        override_cache(WOLFSSL_ENCKEYS "yes")
    endif()
endif()

if(WOLFSSL_ENCKEYS)
    list(APPEND WOLFSSL_DEFINITIONS "-DWOLFSSL_ENCRYPTED_KEYS")
endif()

# PKCS#12
set(WOLFSSL_PKCS12_HELP_STRING "Enable pkcs12 (default: enabled)")
add_option("WOLFSSL_PKCS12" ${WOLFSSL_PKCS12_HELP_STRING} "yes" "yes;no")
if(NOT WOLFSSL_ASN)
  override_cache(WOLFSSL_PKCS12 "no")
endif()

if(NOT WOLFSSL_PKCS12)
  list(APPEND WOLFSSL_DEFINITIONS "-DNO_PKCS12")
endif()


# PWDBASED has to come after certservice since we want it on w/o explicit on
# PWDBASED
set(WOLFSSL_PWDBASED_HELP_STRING "Enable PWDBASED (default: disabled)")
add_option("WOLFSSL_PWDBASED" ${WOLFSSL_PWDBASED_HELP_STRING} "no" "yes;no")

if(NOT WOLFSSL_PWDBASED)
    if(WOLFSSL_OPENSSLEXTRA OR
        WOLFSSL_OPENSSLALL OR
        WOLFSSL_WEBSERVER OR
        WOLFSSL_ENC_KEYS OR
        WOLFSSL_PKCS12)
        # opensslextra, opensslall, webserver, and enckeys needs pwdbased
        override_cache(WOLFSSL_PWDBASED "yes")
    else()
        list(APPEND WOLFSSL_DEFINITIONS "-DNO_PWDBASED")
    endif()
endif()

# TODO: - SCRYPT
#       - wolfCrypt only

# fastmath
set(FASTMATH_DEFAULT "no")

if(("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "x86_64") OR
    ("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "aarch64"))
    set(FASTMATH_DEFAULT "yes")
endif()

if(WOLFSSL_LINUXKM_DEFAULTS)
    set(FASTMATH_DEFAULT "no")
endif()

if(WOLFSSL_SP_MATH)
    set(FASTMATH_DEFAULT "no")
endif()

set(WOLFSSL_FAST_MATH_HELP_STRING "Enable fast math ops (default: enabled on x86_64/aarch64)")
add_option("WOLFSSL_FAST_MATH" ${WOLFSSL_FAST_MATH_HELP_STRING} ${FASTMATH_DEFAULT} "yes;no")

if(WOLFSSL_FAST_MATH)
    # turn off fastmath if leanpsk on or asn off (w/o DH and ECC)
    if(WOLFSSL_LEAN_PSK OR NOT WOLFSSL_ASN)
        if(NOT WOLFSSL_DH AND
           NOT WOLFSSL_ECC AND
           NOT WOLFSSL_RSA)
            override_cache(WOLFSSL_FAST_MATH "no")
        else()
            list(APPEND WOLFSSL_DEFINITIONS "-DUSE_FAST_MATH")
            set(WOLFSSL_SLOWMATH "no")
        endif()
    else()
        list(APPEND WOLFSSL_DEFINITIONS "-DUSE_FAST_MATH")
        set(WOLFSSL_SLOWMATH "no")
    endif()

    if("${CMAKE_SYSTEM_PROCESSOR}" STREQUAL "x86_64")
        # Have settings.h set FP_MAX_BITS higher if user didn't set directly
        list(APPEND WOLFSSL_DEFINITIONS "-DWOLFSSL_X86_64_BUILD")
    endif()
endif()

# TODO: - Fast huge math

# Enable examples, used to disable examples
if(WOLFSSL_LINUX_KM)
    set(EXAMPLES_DEFAULT "no")
else()
    set(EXAMPLES_DEFAULT "yes")
endif()

set(WOLFSSL_EXAMPLES_HELP_STRING "Enable examples (default: enabled)")
add_option("WOLFSSL_EXAMPLES" ${WOLFSSL_EXAMPLES_HELP_STRING} ${EXAMPLES_DEFAULT} "yes;no")

if(NOT WOLFSSL_FILESYSTEM OR
   NOT WOLFSSL_INLINE OR
   WOLFSSL_CRYPT_ONLY)
    override_cache(WOLFSSL_EXAMPLES "no")
endif()

# Enable wolfCrypt test and benchmark
if(WOLFSSL_LINUX_KM)
    set(CRYPT_TESTS_DEFAULT "no")
else()
    set(CRYPT_TESTS_DEFAULT "yes")
endif()

set(WOLFSSL_CRYPT_TESTS_HELP_STRING "Enable Crypt Bench/Test (default: enabled)")
add_option("WOLFSSL_CRYPT_TESTS" ${WOLFSSL_CRYPT_TESTS_HELP_STRING} ${CRYPT_TESTS_DEFAULT} "yes;no")

set(WOLFSSL_CRYPT_TESTS_LIBS_HELP_STRING "Build static libraries from the wolfCrypt test and benchmark sources (default: disabled)")
add_option("WOLFSSL_CRYPT_TESTS_LIBS" ${WOLFSSL_CRYPT_TESTS_LIBS_HELP_STRING} "no" "yes;no")

# TODO: - LIBZ
#       - PKCS#11
#       - Cavium
#       - Cavium V
#       - Cavium Octeon
#       - Intel QuickAssist
#       - SP ASM (and other SP logic)
#       - Fast RSA
#       - Static memory use
#       - Microchip API
#       - Asynchronous crypto

# Asynchronous threading
set(WOLFSSL_ASYNC_THREADS_HELP_STRING "Enable Asynchronous Threading (default: enabled)")
add_option("WOLFSSL_ASYNC_THREADS" ${WOLFSSL_ASYNC_THREADS_HELP_STRING} "yes" "yes;no")

if(WOLFSSL_ASYNC_CRYPT AND WOLFSSL_ASYNC_THREADS)
    if(CMAKE_USE_PTHREADS_INIT)
        override_cache(WOLFSSL_ASYNC_THREADS "yes")
    else()
        override_cache(WOLFSSL_ASYNC_THREADS "no")
    endif()
else()
    override_cache(WOLFSSL_ASYNC_THREADS "no")
endif()

if(WOLFSSL_ASYNC_THREADS)
    list(APPEND WOLFSSL_LINK_LIBS Threads::Threads)
    list(APPEND WOLFSSL_DEFINITIONS "-D_GNU_SOURCE")
else()
    list(APPEND WOLFSSL_DEFINITIONS "-DWC_NO_ASYNC_THREADING")
endif()

# TODO: - cryptodev
#       - cryptocb
#       - Session export
#       - AES key wrap

set(WOLFSSL_OLD_NAMES_HELP_STRING "Keep backwards compat with old names (default: enabled)")
add_option("WOLFSSL_OLD_NAMES" ${WOLFSSL_OLD_NAMES_HELP_STRING} "yes" "yes;no")

if(NOT WOLFSSL_OLD_NAMES AND NOT WOLFSSL_OPENSSL_COEXIST)
    list(APPEND WOLFSSL_DEFINITIONS
        "-DNO_OLD_RNGNAME"
        "-DNO_OLD_WC_NAMES"
        "-DNO_OLD_SSL_NAMES"
        "-DNO_OLD_SHA_NAMES")
endif()

# TODO: - Memory tests
#       - Hash flags

# Support for enabling setting default DH parameters
set(WOLFSSL_DH_DEFAULT_PARAMS_HELP_STRING "Enables option for default dh parameters (default: disabled)")
add_option("WOLFSSL_DH_DEFAULT_PARAMS" ${WOLFSSL_DH_DEFAULT_PARAMS_HELP_STRING} "no" "yes;no")

if(WOLFSSL_DH_DEFAULT_PARAMS OR NOT WOLFSSL_QT)
    override_cache(WOLFSSL_DH_DEFAULT_PARAMS "yes")
    list(APPEND WOLFSSL_DEFINITIONS "-DHAVE_DH_DEFAULT_PARAMS")
endif()

if(NOT WOLFSSL_DES3)
    list(APPEND WOLFSSL_DEFINITIONS "-DNO_DES3")
else()
    # turn off DES3 if leanpsk or leantls on
    if(WOLFSSL_LEAN_PSK OR WOLFSSL_LEAN_TLS)
        list(APPEND WOLFSSL_DEFINITIONS "-DNO_DES3")
        override_cache(WOLFSSL_DES3 "no")
    endif()
endif()

set(WOLFSSL_USER_SETTINGS_HELP_STRING "Use your own user_settings.h and do not add Makefile CFLAGS (default: disabled)")
add_option("WOLFSSL_USER_SETTINGS" ${WOLFSSL_USER_SETTINGS_HELP_STRING} "no" "yes;no")

set(WOLFSSL_OPTFLAGS_HELP_STRING "Enable default optimization CFLAGS for the compiler (default: enabled)")
add_option("WOLFSSL_OPTFLAGS" ${WOLFSSL_OPTFLAGS_HELP_STRING} "yes" "yes;no")

# Generates the BUILD_* flags. These control what source files are included in
# the library. A series of AM_CONDITIONALs handle this in configure.ac.
generate_build_flags()

# TODO: - Bit of logic after optimization flags option (above)
#       - Check for build-type conflicts section

# USER SETTINGS
if(WOLFSSL_USER_SETTINGS)
    # Replace all options and just use WOLFSSL_USER_SETTINGS
    set(WOLFSSL_DEFINITIONS "-DWOLFSSL_USER_SETTINGS")
endif()

# TODO: Applying definitions to everything like this, rather than
#       individual targets, is discouraged in CMake.
add_definitions(${WOLFSSL_DEFINITIONS})

set(WOLFSSL_CONFIG_H_HELP_STRING "Enable generation of config.h and define HAVE_CONFIG_H (default: enabled)")
add_option("WOLFSSL_CONFIG_H" ${WOLFSSL_CONFIG_H_HELP_STRING} "yes" "yes;no")

if(WOLFSSL_CONFIG_H)
    add_definitions("-DHAVE_CONFIG_H")
    configure_file("${CMAKE_CURRENT_SOURCE_DIR}/cmake/config.in"
                   "${CMAKE_CURRENT_BINARY_DIR}/config.h" )
    set(abs_top_srcdir ${CMAKE_CURRENT_SOURCE_DIR})
    set(abs_top_builddir ${CMAKE_CURRENT_BINARY_DIR})
    configure_file("${CMAKE_CURRENT_SOURCE_DIR}/wolfcrypt/test/test_paths.h.in"
                   "${CMAKE_CURRENT_BINARY_DIR}/wolfcrypt/test/test_paths.h" )
endif()

# Suppress some warnings about separate compilation, inlining
add_definitions("-DWOLFSSL_IGNORE_FILE_WARN")

# Generate user options header
message("Generating user options header...")
set(OPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/wolfssl/options.h")
file(REMOVE ${OPTION_FILE})

file(APPEND ${OPTION_FILE} "/* wolfssl options.h\n")
file(APPEND ${OPTION_FILE} " * generated from configure options\n")
file(APPEND ${OPTION_FILE} " *\n")
file(APPEND ${OPTION_FILE} " * Copyright (C) 2006-2020 wolfSSL Inc.\n")
file(APPEND ${OPTION_FILE} " *\n")
file(APPEND ${OPTION_FILE} " * This file is part of wolfSSL. (formerly known as CyaSSL)\n")
file(APPEND ${OPTION_FILE} " *\n")
file(APPEND ${OPTION_FILE} " */\n\n")
file(APPEND ${OPTION_FILE} "#ifndef WOLFSSL_OPTIONS_H\n")
file(APPEND ${OPTION_FILE} "#define WOLFSSL_OPTIONS_H\n\n\n")
file(APPEND ${OPTION_FILE} "#ifdef __cplusplus\n")
file(APPEND ${OPTION_FILE} "extern \"C\" {\n")
file(APPEND ${OPTION_FILE} "#endif\n\n")

add_to_options_file("${WOLFSSL_DEFINITIONS}" "${OPTION_FILE}")
# CMAKE_C_FLAGS is just a string of space-separated flags to pass to the C
# compiler. We need to replace those spaces with semicolons in order to treat it
# as a CMake list.
string(REPLACE " " ";" CMAKE_C_FLAGS_LIST "${CMAKE_C_FLAGS}")
add_to_options_file("${CMAKE_C_FLAGS_LIST}" "${OPTION_FILE}")

file(APPEND ${OPTION_FILE} "\n#ifdef __cplusplus\n")
file(APPEND ${OPTION_FILE} "}\n")
file(APPEND ${OPTION_FILE} "#endif\n\n\n")
file(APPEND ${OPTION_FILE} "#endif /* WOLFSSL_OPTIONS_H */\n\n")

# backwards compatibility for those who have included options or version
set(CYASSL_OPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/cyassl/options.h")
file(REMOVE ${CYASSL_OPTION_FILE})
file(APPEND ${CYASSL_OPTION_FILE} "/* cyassl options.h\n")
file(APPEND ${CYASSL_OPTION_FILE} " * generated from wolfssl/options.h\n")
file(APPEND ${CYASSL_OPTION_FILE} " */\n")
file(READ ${OPTION_FILE} OPTION_FILE_CONTENTS)
file(APPEND ${CYASSL_OPTION_FILE} ${OPTION_FILE_CONTENTS})

####################################################
# Library Target
####################################################

# TODO: - Build shared/static libs based on enables. Check CMake
#         global flag BUILD_SHARED_LIBS.
option(BUILD_SHARED_LIBS "Build shared libraries (.dll/.so) instead of static ones (.lib/.a)" ON)

set(LIB_SOURCES "")
# Generates a list of sources to include in the library.
# Corresponds to the instances of "src_libwolfssl_la_SOURCES += ..."
# in the *.am files.
generate_lib_src_list("${LIB_SOURCES}")
add_library(wolfssl ${LIB_SOURCES})

set_target_properties(wolfssl
    PROPERTIES
        SOVERSION ${LIBTOOL_SO_VERSION}
        VERSION ${LIBTOOL_FULL_VERSION}
)

target_compile_options(wolfssl PRIVATE "-DBUILDING_WOLFSSL")


####################################################
# Include Directories
####################################################

target_include_directories(wolfssl
    PUBLIC
        $<INSTALL_INTERFACE:wolfssl>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
)

####################################################
# Link Libraries
####################################################

target_link_libraries(wolfssl PUBLIC ${WOLFSSL_LINK_LIBS})

if(WIN32)
    # For Windows link ws2_32
    target_link_libraries(wolfssl PUBLIC
        $<$<PLATFORM_ID:Windows>:ws2_32>)
else()
    # DH requires math (m) library
    target_link_libraries(wolfssl
        PUBLIC
            m)
endif()

####################################################
# Tests and Examples
####################################################

if(WOLFSSL_EXAMPLES)
    # Build wolfSSL client example
    add_executable(client
        ${CMAKE_CURRENT_SOURCE_DIR}/examples/client/client.c)
    target_link_libraries(client wolfssl)
    set_property(TARGET client
                 PROPERTY RUNTIME_OUTPUT_DIRECTORY
                 ${CMAKE_CURRENT_SOURCE_DIR}/examples/client)

    # Build wolfSSL server example
    add_executable(server
        ${CMAKE_CURRENT_SOURCE_DIR}/examples/server/server.c)
    target_link_libraries(server wolfssl)
    set_property(TARGET server
                 PROPERTY RUNTIME_OUTPUT_DIRECTORY
                 ${CMAKE_CURRENT_SOURCE_DIR}/examples/server)

    # Build echo client example
    add_executable(echoclient
        ${CMAKE_CURRENT_SOURCE_DIR}/examples/echoclient/echoclient.c)
    target_include_directories(echoclient PRIVATE
        ${CMAKE_CURRENT_BINARY_DIR})
    target_link_libraries(echoclient wolfssl)
    set_property(TARGET echoclient
                 PROPERTY RUNTIME_OUTPUT_DIRECTORY
                 ${CMAKE_CURRENT_SOURCE_DIR}/examples/echoclient)

    # Build echo server example
    add_executable(echoserver
        ${CMAKE_CURRENT_SOURCE_DIR}/examples/echoserver/echoserver.c)
    target_include_directories(echoserver PRIVATE
        ${CMAKE_CURRENT_BINARY_DIR})
    target_link_libraries(echoserver wolfssl)
    set_property(TARGET echoserver
                 PROPERTY RUNTIME_OUTPUT_DIRECTORY
                 ${CMAKE_CURRENT_SOURCE_DIR}/examples/echoserver)

    if(NOT WIN32)
        # Build TLS benchmark example
        add_executable(tls_bench
            ${CMAKE_CURRENT_SOURCE_DIR}/examples/benchmark/tls_bench.c)
        target_link_libraries(tls_bench wolfssl)
        target_link_libraries(tls_bench Threads::Threads)
        set_property(TARGET tls_bench
                 PROPERTY RUNTIME_OUTPUT_DIRECTORY
                 ${CMAKE_CURRENT_SOURCE_DIR}/examples/benchmark)
    endif()

    # Build unit tests
    add_executable(unit_test
        tests/api.c
        tests/hash.c
        tests/srp.c
        tests/suites.c
        tests/unit.c
        examples/server/server.c
        examples/client/client.c)
    target_include_directories(unit_test PRIVATE
        ${CMAKE_CURRENT_BINARY_DIR})
    target_compile_options(unit_test PUBLIC "-DNO_MAIN_DRIVER")
    target_link_libraries(unit_test wolfssl)
    target_link_libraries(unit_test Threads::Threads)
    set_property(TARGET unit_test
                 PROPERTY RUNTIME_OUTPUT_DIRECTORY
                 ${CMAKE_CURRENT_SOURCE_DIR}/tests/)
    set_property(TARGET unit_test
                 PROPERTY RUNTIME_OUTPUT_NAME
                 unit.test)
endif()

if(WOLFSSL_CRYPT_TESTS)
    if(WOLFSSL_CRYPT_TESTS_LIBS)
        # Build wolfCrypt test as a library. This will compile test.c and make
        # its functions available as a CMake target that other CMake targets can
        # pull in, in addition to producing the library itself. Note that this
        # feature is not enabled by default, and the API of this library and
        # wofcryptbench_lib should NOT be treated as stable.
        add_library(wolfcrypttest_lib
            ${CMAKE_CURRENT_SOURCE_DIR}/wolfcrypt/test/test.c)
        set_target_properties(wolfcrypttest_lib PROPERTIES OUTPUT_NAME "wolfcrypttest")
        target_link_libraries(wolfcrypttest_lib wolfssl)
        target_compile_options(wolfcrypttest_lib PRIVATE "-DNO_MAIN_DRIVER")

        # Make another library for the wolfCrypt benchmark code.
        add_library(wolfcryptbench_lib
            ${CMAKE_CURRENT_SOURCE_DIR}/wolfcrypt/benchmark/benchmark.c)
        set_target_properties(wolfcryptbench_lib PROPERTIES OUTPUT_NAME "wolfcryptbench")
        target_link_libraries(wolfcryptbench_lib wolfssl)
        target_compile_options(wolfcryptbench_lib PRIVATE "-DNO_MAIN_DRIVER")
    endif()

    # Build wolfCrypt test executable.
    add_executable(wolfcrypttest
        ${CMAKE_CURRENT_SOURCE_DIR}/wolfcrypt/test/test.c)
    target_link_libraries(wolfcrypttest wolfssl)
    set_property(TARGET wolfcrypttest
                 PROPERTY RUNTIME_OUTPUT_DIRECTORY
                 ${CMAKE_CURRENT_SOURCE_DIR}/wolfcrypt/test)
    set_property(TARGET wolfcrypttest
                 PROPERTY RUNTIME_OUTPUT_NAME
                 testwolfcrypt)

    # Build wolfCrypt benchmark executable.
    add_executable(wolfcryptbench
        ${CMAKE_CURRENT_SOURCE_DIR}/wolfcrypt/benchmark/benchmark.c)
    target_include_directories(wolfcryptbench PRIVATE
        ${CMAKE_CURRENT_BINARY_DIR})
    target_link_libraries(wolfcryptbench wolfssl)
    set_property(TARGET wolfcryptbench
                 PROPERTY RUNTIME_OUTPUT_DIRECTORY
                 ${CMAKE_CURRENT_SOURCE_DIR}/wolfcrypt/benchmark)
    set_property(TARGET wolfcryptbench
                 PROPERTY RUNTIME_OUTPUT_NAME
                 benchmark)
endif()

####################################################
# Installation
####################################################

include(GNUInstallDirs)

set(HEADER_EXCLUDE
  "internal.h"
  "cyassl/ctaocrypt/port"
  "wolfssl/wolfcrypt/port/nrf51.h"
  "wolfssl/wolfcrypt/port/arm"
  "wolfssl/wolfcrypt/port/cypress"
  "wolfssl/wolfcrypt/port/Espressif"
  "wolfssl/wolfcrypt/port/iotsafe"
  "wolfssl/wolfcrypt/port/nxp"
  "wolfssl/wolfcrypt/port/pic"
  "wolfssl/wolfcrypt/port/Renesas"
  "wolfssl/wolfcrypt/port/silabs"
  "wolfssl/wolfcrypt/port/st"
  "wolfssl/wolfcrypt/port/ti"
  "wolfssl/wolfcrypt/port/xilinx"
  )

# TODO: add support for the various ports

# For distro build don't install options.h.
# It depends on the architecture and conflicts with Multi-Arch.
if(BUILD_DISTRO)
  list(APPEND HEADER_EXCLUDE
    "options.h")
endif()

if(NOT BUILD_CRYPTOAUTHLIB)
  list(APPEND HEADER_EXCLUDE
    "wolfssl/wolfcrypt/port/atmel")
endif()

if(NOT BUILD_AFALG)
  list(APPEND HEADER_EXCLUDE
    "wolfssl/wolfcrypt/port/af_alg")
endif()

if(NOT BUILD_KCAPI)
  list(APPEND HEADER_EXCLUDE
    "wolfssl/wolfcrypt/port/kcapi"
    )
endif()

if(NOT BUILD_DEVCRYPTO)
  list(APPEND HEADER_EXCLUDE
    "wolfssl/wolfcrypt/port/devcrypto")
endif()

if(NOT BUILD_ASYNCCRYPT)
  list(APPEND HEADER_EXCLUDE
    "wolfssl/wolfcrypt/async.h")
endif()

if(NOT BUILD_PKCS11)
    list(APPEND HEADER_EXCLUDE
      "wolfssl/wolfcrypt/wc_pkcs11.h"
      "wolfssl/wolfcrypt/pkcs11.h"
      )
endif()

if(NOT BUILD_CAVIUM AND NOT BUILD_OCTEON_SYNC)
  list(APPEND HEADER_EXCLUDE
    "wolfssl/wolfcrypt/port/cavium")
else()
  if(NOT BUILD_CAVIUM)
    list(APPEND HEADER_EXCLUDE
      "wolfssl/wolfcrypt/port/cavium/cavium_nitrox.h")
  endif()

  if(NOT BUILD_OCTEON_SYNC)
    list(APPEND HEADER_EXCLUDE
      "wolfssl/wolfcrypt/port/cavium/cavium_octeon_sync.h"
      )
  endif()
endif()


if(NOT BUILD_INTEL_QA AND NOT BUILD_INTEL_QA_SYNC)
  list(APPEND HEADER_EXCLUDE
    "wolfssl/wolfcrypt/port/intel")
else()
  if(NOT BUILD_INTEL_QA)
    list(APPEND HEADER_EXCLUDE
      "wolfssl/wolfcrypt/port/intel/quickassist.h"
      "wolfssl/wolfcrypt/port/intel/quickassist_mem.h"
      )
  endif()

  if(NOT BUILD_INTEL_QA_SYNC)
    list(APPEND HEADER_EXCLUDE
      "wolfssl/wolfcrypt/port/intel/quickassist_sync.h")
  endif()
endif()

if(NOT BUILD_SP)
  list(APPEND HEADER_EXCLUDE
    "wolfssl/wolfcrypt/sp.h"
    "wolfssl/wolfcrypt/sp_int.h")
endif()

if(NOT BUILD_SELFTEST)
  list(APPEND HEADER_EXCLUDE
    "wolfssl/wolfcrypt/selftest.h")
endif()

if(NOT BUILD_FIPS OR BUILD_FIPS_V1)
  list(APPEND HEADER_EXCLUDE
    "wolfssl/wolfcrypt/fips.h")
endif()

if(NOT BUILD_QNXCAAM)
  list(APPEND HEADER_EXCLUDE
    "wolfssl/wolfcrypt/port/caam"
    )
endif()

list(JOIN HEADER_EXCLUDE "|" EXCLUDED_HEADERS_REGEX)

string(PREPEND EXCLUDED_HEADERS_REGEX "(")
string(APPEND  EXCLUDED_HEADERS_REGEX ")")

set(INSTALLED_EXAMPLES
    ${CMAKE_CURRENT_SOURCE_DIR}/examples/echoserver/echoserver.c
    ${CMAKE_CURRENT_SOURCE_DIR}/examples/sctp/sctp-server.c
    ${CMAKE_CURRENT_SOURCE_DIR}/examples/sctp/sctp-client-dtls.c
    ${CMAKE_CURRENT_SOURCE_DIR}/examples/sctp/sctp-client.c
    ${CMAKE_CURRENT_SOURCE_DIR}/examples/sctp/sctp-server-dtls.c
    ${CMAKE_CURRENT_SOURCE_DIR}/examples/echoclient/echoclient.c
    ${CMAKE_CURRENT_SOURCE_DIR}/examples/server/server.c
    ${CMAKE_CURRENT_SOURCE_DIR}/examples/benchmark/tls_bench.c
    ${CMAKE_CURRENT_SOURCE_DIR}/examples/client/client.c)

# Install the library
install(TARGETS wolfssl
        DESTINATION ${CMAKE_INSTALL_LIBDIR}
        EXPORT wolfssl-targets
        LIBRARY)
# Install the headers
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/wolfssl/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/wolfssl
        FILES_MATCHING PATTERN "*.h"
        REGEX ${EXCLUDED_HEADERS_REGEX} EXCLUDE)
install(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/cyassl/
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/cyassl
        FILES_MATCHING PATTERN "*.h"
        REGEX ${EXCLUDED_HEADERS_REGEX} EXCLUDE)


# Install the examples
install(FILES ${INSTALLED_EXAMPLES}
        DESTINATION ${CMAKE_INSTALL_DOCDIR}/example)
# Install README.txt and taoCert.txt
install(FILES
        ${CMAKE_CURRENT_SOURCE_DIR}/doc/README.txt
        ${CMAKE_CURRENT_SOURCE_DIR}/certs/taoCert.txt
        DESTINATION ${CMAKE_INSTALL_DOCDIR})
# Install the export set
install(EXPORT wolfssl-targets
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/wolfssl
        FILE wolfssl-config.cmake)

# TODO: Distro build + rules for what to include in the distro.
#       See various include.am files.

set(prefix ${CMAKE_INSTALL_PREFIX})
set(exec_prefix "\${prefix}")
set(libdir "\${exec_prefix}/lib")
set(includedir "\${prefix}/include")
set(VERSION ${PROJECT_VERSION})

configure_file(support/wolfssl.pc.in ${CMAKE_CURRENT_BINARY_DIR}/support/wolfssl.pc @ONLY)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/support/wolfssl.pc
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
