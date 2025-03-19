#!/bin/bash
# Script to remove rc4.h include from tests/api.c
sed -i '/#ifndef NO_RC4/,/#endif/ {/#ifndef NO_RC4/d; /#include <wolfssl\/openssl\/rc4.h>/d; /#endif/d;}' tests/api.c
