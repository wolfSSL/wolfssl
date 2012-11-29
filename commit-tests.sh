#!/bin/bash

#commit-tests.sh


# make sure current config is ok
echo -e "\n\nTesting current config...\n\n"
make clean; make -j 8 test;
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\nCurrent config make test failed" && exit 1


# make sure basic config is ok
echo -e "\n\nTesting basic config too...\n\n"
./configure;
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\nBasic config ./configure failed" && exit 1

make -j 8 test;
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\nBasic config make test failed" && exit 1


# make sure full config is ok
echo -e "\n\nTesting full config as well...\n\n"
./configure --enable-opensslExtra --enable-fastmath --enable-dtls --enable-aesgcm --enable-hc128 --enable-sniffer --enable-psk --enable-rabbit;
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\nFull config ./configure failed" && exit 1

make -j 8 test;
RESULT=$?
[ $RESULT -ne 0 ] && echo -e "\n\nFull config make test failed" && exit 1

exit 0
