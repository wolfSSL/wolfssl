#!/bin/sh

check_status () {
if [ $1 != 0 ]
then
    echo "$2 failed"
    echo ""
fi
}

echo "Running wolfssl testsuite with RIOT"
cd testsuite/
./wolf-build-and-run-test.sh
RESULT=$?
check_status $RESULT "testsuite"
cd ..

echo ""
echo "Running wolfcrypt tests with RIOT"
cd wolfcrypt-test
./wolf-build-and-run-test.sh
RESULT=$?
check_status $RESULT "wolfcrypt test"
cd ..

echo ""
echo "Running wolfcrypt benchmark with RIOT"
cd benchmark
./wolf-build-and-run-test.sh
RESULT=$?
check_status $RESULT "wolfcrypt benchmark"
cd ..

exit 0
