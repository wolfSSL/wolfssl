#!/bin/sh

wolf_riot_setup () {
    #copy the test sources here
    cp ../../wolfcrypt/test/*.c ./

    cp ../../wolfcrypt/src/*.c ./

    cp ../../src/*.c ./
}

wolf_riot_cleanup () {
    rm ./*.c
    #leave this line in for testing. Comment it out when you want to build
    # a .elf for flashing to a device
    make clean &> /dev/null
}

BACKUPCFLAGS=${CFLAGS}
export CFLAGS="${CFLAGS} -DWOLFSSL_RIOT_OS"


# copy the necessary files to this directory
wolf_riot_setup

# build the test
# change next line to just "make" to see verbose output
# NOTE: will throw a warning on every file that is empty if that feature
#       is not enabled in wolfssl.
make &> /dev/null
RESULT=$?
 [ $RESULT != 0 ] && echo "Make FAILED: running verbose make" &&
                     make

if [ $RESULT != 0 ];
then
    wolf_riot_cleanup && echo "cleanup done" && exit 2
fi

# run the test
./bin/native/testwolfcrypt.elf

# confirm success or failure
RESULT=$?
 [ $RESULT != 0 ] && echo "TEST FAILED" && wolf_riot_cleanup && exit 5

echo "ALL TEST PASSED!"

# cleanup. All changes made should be to the files in:
# <wolfssl-root>/src
# <wolfssl-root>/wolfcrypt/src
# or other. Never make changes to the files copied here as they are only
# temporary. Once changes are made, to test them just run this script again.
wolf_riot_cleanup

exit 0


