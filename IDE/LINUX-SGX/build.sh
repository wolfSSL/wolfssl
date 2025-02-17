#!/bin/sh


CFLAGS_NEW="-DDEBUG_WOLFSSL -I/usr/lib/gcc/x86_64-linux-gnu/$(gcc -dumpversion)/include"
export CFLAGS="${CFLAGS} ${CFLAGS_NEW}"
echo ${CFLAGS}

export C_INCLUDE_PATH="$C_INCLUDE_PATH:/usr/lib/gcc/x86_64-linux-gnu/$(gcc -dumpversion)/include"


# Build without assembly optimizations
#make -f sgx_t_static.mk HAVE_WOLFSSL_BENCHMARK=1 HAVE_WOLFSSL_TEST=1 HAVE_WOLFSSL_SP=1

# Build with assembly optimizations
make -f sgx_t_static.mk HAVE_WOLFSSL_BENCHMARK=1 HAVE_WOLFSSL_TEST=1 HAVE_WOLFSSL_SP=1 HAVE_WOLFSSL_ASSEMBLY=1

