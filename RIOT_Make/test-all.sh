#!/bin/sh

echo "Running wolfssl testsuite with RIOT"
cd testsuite/
./wolf-build-and-run-test.sh
RESULT=$?
if [ $RESULT != 0 ]
then
    echo "testsuite failed"
    echo ""
fi

cd ..

echo "Running wolfcrypt tests with RIOT"
cd wolfcrypt-test
./wolf-build-and-run-test.sh
RESULT=$?
if [ $RESULT != 0 ]
then
    echo "wolfcrypt test failed"
    echo ""
fi

cd ..

exit 0
