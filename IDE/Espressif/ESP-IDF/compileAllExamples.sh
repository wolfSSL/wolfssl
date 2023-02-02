#!/bin/bash

# Example usage:
#   cd wolfssl && docker run --rm -v $PWD:/project -w /project espressif/idf:latest IDE/Espressif/ESP-IDF/compileAllExamples.sh

SCRIPT_DIR=$(builtin cd ${BASH_SOURCE%/*}; pwd)
for file in "benchmark" "client" "server" "test"; do
    pushd ${SCRIPT_DIR}/examples/wolfssl_${file}/ && idf.py build; popd
    if [ $? -ne 0 ]; then
        echo "Failed in ${file}"
        exit 1
    fi
done