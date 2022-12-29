#!/bin/bash

SCRIPT_DIR=$(builtin cd ${BASH_SOURCE%/*}; pwd)
pushd ${SCRIPT_DIR} && ./setup.sh; popd
for file in "benchmark" "client" "server" "test"; do
    cd ${IDF_PATH}/examples/protocols/wolfssl_${file}/ && idf.py build
    if [ $? -ne 0 ]; then
        echo "Failed in ${file}"
        break
    fi
done
