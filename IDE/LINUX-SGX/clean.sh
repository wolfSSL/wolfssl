#!/bin/sh

# Just clean both always by default

# Default
make -f sgx_t_static.mk clean

# Uncomment for SGX-FIPS
make -f sgx_t_fips_static.mk clean
