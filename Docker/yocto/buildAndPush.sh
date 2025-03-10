#!/usr/bin/env bash

# Assume we're in wolfssl/Docker/yocto
WOLFSSL_DIR=$(builtin cd ${BASH_SOURCE%/*}/../..; pwd)

DOCKER_BUILD_OPTIONS="$1"
if [ "${DOCKER_BASE_IMAGE}" != "" ]; then
    DOCKER_BUILD_OPTIONS+=" --build-arg DOCKER_BASE_IMAGE=${DOCKER_BASE_IMAGE}"
fi

NUM_FAILURES=0

CUR_DATE=$(date -u +%F)
for ver in kirkstone langdale scarthgap; do
    echo "Building wolfssl/yocto:${ver}-${CUR_DATE} as ${DOCKER_BUILD_OPTIONS}"
    docker build -t wolfssl/yocto:${ver}-${CUR_DATE} --build-arg YOCTO_VERSION=${ver} --build-arg BUILD_DATE=${CUR_DATE} -f Dockerfile "${WOLFSSL_DIR}/Docker/yocto" && \
        docker tag wolfssl/yocto:${ver}-${CUR_DATE} wolfssl/yocto:${ver}-latest
    if [ $? -eq 0 ]; then
        echo "Pushing containers to DockerHub"
        docker push wolfssl/yocto:${ver}-${CUR_DATE} && docker push wolfssl/yocto:${ver}-latest
    else
        echo "Warning: Build wolfssl/yocto:${ver} failed. Continuing"
        ((NUM_FAILURES++))
    fi
done

echo "Script completed in $SECONDS seconds. Had $NUM_FAILURES failures."
