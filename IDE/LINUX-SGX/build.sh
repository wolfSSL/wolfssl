#!/bin/sh


CFLAGS="-DDEBUG_WOLFSSL"
CFLAGS="-DBUILDING_STATIC_LIBRARY"
export CFLAGS=${CFLAGS}

# NOTE: ONLY build one or the other, do not build both libraries together!
# Uncomment the make command for either the default Linux SGX or the SGX FIPS
# Linux solution

# Default
#make -f sgx_t_static.mk HAVE_WOLFSSL_BENCHMARK=1 HAVE_WOLFSSL_TEST=1

# Uncomment for building with SGX-FIPS
#make -f sgx_t_fips_static.mk HAVE_WOLFSSL_BENCHMARK=1 HAVE_WOLFSSL_TEST=1 HAVE_FIPS_LINUX_HARNESS=1

