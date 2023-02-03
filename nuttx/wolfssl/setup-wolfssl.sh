#!/bin/bash

set -e # exit on any command failure
if [ ! -d wolfssl ]; then
    git clone https://github.com/wolfssl/wolfssl
    git clone https://github.com/wolfssl/wolfssl-examples
fi
