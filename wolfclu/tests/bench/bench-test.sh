#!/bin/bash

run_success() {
    RESULT=`./wolfssl $1`
    if [ $? != 0 ]; then
        echo "Failed on test \"$1\""
        exit 99
    fi
}

run_fail() {
    RESULT=`./wolfssl $1`
    if [ $? == 0 ]; then
        echo "Failed on test \"$1\""
        exit 99
    fi
}

run_success "-bench aes-cbc -time 1"
run_success "-bench sha -time 1"
run_success "-bench md5 -time 1"

echo "Done"
exit 0
