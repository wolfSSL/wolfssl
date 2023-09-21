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

# Git hooks should come before autoreconf.
if [ -d .git ]; then
    if [ ! -d .git/hooks ]; then
        mkdir .git/hooks || exit $?
    fi

    if [ -n "$no_links" ]; then
        echo "Linux ln does not work on shared Windows file system in WSL."
        if [ ! -e .git/hooks/pre-commit ]; then
            echo "The pre-commit.sh file will not be copied to .git/hooks/pre-commit"
            # shell scripts do not work on Windows; TODO create equivalent batch file
            # cp ./pre-commit.sh .git/hooks/pre-commit || exit $?
        fi
        if [ ! -e .git/hooks/pre-push ]; then
            echo "The pre-push.sh file will not be copied to .git/hooks/pre-commit"
            # shell scripts do not work on Windows; TODO create equivalent batch file
            # cp ./pre-push.sh .git/hooks/pre-push || exit $?
        fi
    else
        if [ ! -e .git/hooks/pre-commit ]; then
            ln -s ../../pre-commit.sh .git/hooks/pre-commit || exit $?
        fi
        if [ ! -e .git/hooks/pre-push ]; then
            ln -s ../../pre-push.sh .git/hooks/pre-push || exit $?
        fi
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
