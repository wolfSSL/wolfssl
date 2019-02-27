#!/bin/bash

# check if IDF_PATH is set
if [ -z "$IDF_PATH" ]; then
    echo "Please follows the instruction of ESP-IDF installation and set IDF_PATH."
    exit 1
fi

RMDCMD='/bin/rm -rf'
MKDCMD='/bin/mkdir'
CPDCMD='/bin/cp'

SCRIPTDIR=`dirname $0`
SCRIPTDIR=`cd $SCRIPTDIR && pwd -P`
WOLFSSL_ESPIDFDIR=${SCRIPTDIR}
WOLFSSL_ESPIDFDIR=`cd $WOLFSSL_ESPIDFDIR && pwd -P`
BASEDIR=${SCRIPTDIR}/../../../
BASEDIR=`cd ${BASEDIR} && pwd -P`

# echo $WOLFSSL_ESPIDFDIR

WOLFSSLLIB_TRG_DIR=${IDF_PATH}/components/wolfssl
WOLFSSLEXP_TRG_DIR=${IDF_PATH}/examples/protocols

if [ ! -d $IDF_PATH ]; then
    echo "ESP-IDF Development Framework doesn't exist.: $IDF_PATH"
    exit 1
fi

# Copy files into ESP-IDF development framework
pushd $IDF_PATH > /dev/null

echo "Copy files into $IDF_PATH"
# Remove/Create directories
${RMDCMD} ${WOLFSSLLIB_TRG_DIR}/
${MKDCMD} ${WOLFSSLLIB_TRG_DIR}/

${MKDCMD} ${WOLFSSLLIB_TRG_DIR}/src
${MKDCMD} ${WOLFSSLLIB_TRG_DIR}/wolfcrypt
${MKDCMD} ${WOLFSSLLIB_TRG_DIR}/wolfcrypt/src
${MKDCMD} ${WOLFSSLLIB_TRG_DIR}/wolfssl
${MKDCMD} ${WOLFSSLLIB_TRG_DIR}/test
${MKDCMD} ${WOLFSSLLIB_TRG_DIR}/include

popd > /dev/null             # $WOLFSSL_ESPIDFDIR
pushd ${BASEDIR} > /dev/null # WOLFSSL TOP DIR

# copying ... files in src/ into $WOLFSSLLIB_TRG_DIR/src
${CPDCMD} ./src/*.c ${WOLFSSLLIB_TRG_DIR}/src/


${CPDCMD} -r ./wolfcrypt/src/*.{c,i} ${WOLFSSLLIB_TRG_DIR}/wolfcrypt/src/
${CPDCMD} -r ./wolfcrypt/src/port  ${WOLFSSLLIB_TRG_DIR}/wolfcrypt/src/port/
${CPDCMD} -r ./wolfcrypt/test ${WOLFSSLLIB_TRG_DIR}/wolfcrypt/
${CPDCMD} -r ./wolfcrypt/benchmark ${WOLFSSLLIB_TRG_DIR}/wolfcrypt/

${CPDCMD} -r ./wolfssl/*.h ${WOLFSSLLIB_TRG_DIR}/wolfssl/
${CPDCMD} -r ./wolfssl/wolfcrypt ${WOLFSSLLIB_TRG_DIR}/wolfssl/
# user_settings.h
${CPDCMD} -r ${WOLFSSL_ESPIDFDIR}/user_settings.h ${WOLFSSLLIB_TRG_DIR}/include/

# unit test app
${CPDCMD} -r ${WOLFSSL_ESPIDFDIR}/test/* ${WOLFSSLLIB_TRG_DIR}/test/

popd > /dev/null # 

${CPDCMD} ./libs/CMakeLists.txt ${WOLFSSLLIB_TRG_DIR}/
${CPDCMD} ./libs/component.mk ${WOLFSSLLIB_TRG_DIR}/

pushd ${BASEDIR} > /dev/null # WOLFSSL TOP DIR

# Benchmark program
${RMDCMD} ${WOLFSSLEXP_TRG_DIR}/wolfssl_benchmark/
${MKDCMD} ${WOLFSSLEXP_TRG_DIR}/wolfssl_benchmark/
${MKDCMD} ${WOLFSSLEXP_TRG_DIR}/wolfssl_benchmark/main/

${CPDCMD} -r ./wolfcrypt/benchmark/benchmark.c ${WOLFSSLEXP_TRG_DIR}/wolfssl_benchmark/main/
${CPDCMD} -r ${WOLFSSL_ESPIDFDIR}/examples/wolfssl_benchmark/* ${WOLFSSLEXP_TRG_DIR}/wolfssl_benchmark/
${CPDCMD} -r ${WOLFSSL_ESPIDFDIR}/examples/wolfssl_benchmark/main/* ${WOLFSSLEXP_TRG_DIR}/wolfssl_benchmark/main/

# Crypt Test program
${RMDCMD} ${WOLFSSLEXP_TRG_DIR}/wolfssl_test/
${MKDCMD} ${WOLFSSLEXP_TRG_DIR}/wolfssl_test/
${MKDCMD} ${WOLFSSLEXP_TRG_DIR}/wolfssl_test/main/

${CPDCMD} -r ./wolfcrypt/test/test.c ${WOLFSSLEXP_TRG_DIR}/wolfssl_test/main/
${CPDCMD} -r ${WOLFSSL_ESPIDFDIR}/examples/wolfssl_test/* ${WOLFSSLEXP_TRG_DIR}/wolfssl_test/
${CPDCMD} -r ${WOLFSSL_ESPIDFDIR}/examples/wolfssl_test/main/* ${WOLFSSLEXP_TRG_DIR}/wolfssl_test/main/

# TLS Client program
${RMDCMD} ${WOLFSSLEXP_TRG_DIR}/wolfssl_client/
${MKDCMD} ${WOLFSSLEXP_TRG_DIR}/wolfssl_client/
${MKDCMD} ${WOLFSSLEXP_TRG_DIR}/wolfssl_client/main/
${MKDCMD} ${WOLFSSLEXP_TRG_DIR}/wolfssl_client/main/include

${CPDCMD} -r ${WOLFSSL_ESPIDFDIR}/examples/wolfssl_client/* ${WOLFSSLEXP_TRG_DIR}/wolfssl_client/
${CPDCMD} -r ${WOLFSSL_ESPIDFDIR}/examples/wolfssl_client/main/* ${WOLFSSLEXP_TRG_DIR}/wolfssl_client/main/
${CPDCMD} -r ${WOLFSSL_ESPIDFDIR}/examples/wolfssl_client/main/include/* ${WOLFSSLEXP_TRG_DIR}/wolfssl_client/main/include/

# TLS Server program
${RMDCMD} ${WOLFSSLEXP_TRG_DIR}/wolfssl_server/
${MKDCMD} ${WOLFSSLEXP_TRG_DIR}/wolfssl_server/
${MKDCMD} ${WOLFSSLEXP_TRG_DIR}/wolfssl_server/main/
${MKDCMD} ${WOLFSSLEXP_TRG_DIR}/wolfssl_server/main/include

${CPDCMD} -r ${WOLFSSL_ESPIDFDIR}/examples/wolfssl_server/* ${WOLFSSLEXP_TRG_DIR}/wolfssl_server/
${CPDCMD} -r ${WOLFSSL_ESPIDFDIR}/examples/wolfssl_server/main/* ${WOLFSSLEXP_TRG_DIR}/wolfssl_server/main/
${CPDCMD} -r ${WOLFSSL_ESPIDFDIR}/examples/wolfssl_server/main/include/* ${WOLFSSLEXP_TRG_DIR}/wolfssl_server/main/include/

popd > /dev/null # 

exit 1
