#!/bin/sh
#
# Create configure and makefile stuff...
#

# Check environment
if [ -n "$WSL_DISTRO_NAME" ]; then
    # we found a non-blank WSL environment distro name
    current_path="$(pwd)"
    pattern="/mnt/?"
    if [ "$(echo "$current_path" | grep -E "^$pattern")" ]; then
        # if we are in WSL and shared Windows file system, 'ln' does not work.
        no_links=true
    else
        no_links=
    fi
fi

# if and as needed, create empty dummy versions of various files, mostly
# associated with fips/self-test and asynccrypt:

for dir in \
        ./wolfssl/wolfcrypt/port/intel \
        ./wolfssl/wolfcrypt/port/cavium
do
    if [ ! -e "$dir" ]; then
        mkdir "$dir" || exit $?
    fi
done

for file in \
        ./wolfssl/options.h \
        ./wolfcrypt/src/fips.c \
        ./wolfcrypt/src/fips_test.c \
        ./wolfcrypt/src/wolfcrypt_first.c \
        ./wolfcrypt/src/wolfcrypt_last.c \
        ./wolfssl/wolfcrypt/fips.h \
        ./wolfcrypt/src/selftest.c \
        ./wolfcrypt/src/async.c \
        ./wolfssl/wolfcrypt/async.h \
        ./wolfcrypt/src/port/intel/quickassist.c \
        ./wolfcrypt/src/port/intel/quickassist_mem.c \
        ./wolfcrypt/src/port/cavium/cavium_nitrox.c \
        ./wolfssl/wolfcrypt/port/intel/quickassist.h \
        ./wolfssl/wolfcrypt/port/intel/quickassist_mem.h \
        ./wolfssl/wolfcrypt/port/cavium/cavium_nitrox.h
do
    if [ ! -e "$file" ]; then
        > "$file" || exit $?
    fi
done

# If this is a source checkout then call autoreconf with error as well
if [ -e .git ]; then
    export WARNINGS="all,error"
else
    export WARNINGS="all"
fi

autoreconf --install --force
