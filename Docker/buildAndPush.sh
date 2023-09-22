#!/bin/bash

DOCKER_BUILD_OPTIONS="$1"
if [ "${DOCKER_BASE_IMAGE}" != "" ]; then
    DOCKER_BUILD_OPTIONS+=" --build-arg DOCKER_BASE_IMAGE=${DOCKER_BASE_IMAGE}"
fi

CUR_DATE=$(date -u +%F)
echo "Building wolfssl/wolfssl-builder:${CUR_DATE} as ${DOCKER_BUILD_OPTIONS}"
docker build -t wolfssl/wolfssl-builder:${CUR_DATE} ${DOCKER_BUILD_OPTIONS} "${WOLFSSL_DIR}/Docker" && \
    docker push wolfssl/wolfssl-builder:${CUR_DATE} && \
    docker tag wolfssl/wolfssl-builder:${CUR_DATE} wolfssl/wolfssl-builder:latest && \
    docker push wolfssl/wolfssl-builder:latest && \
    docker build -t wolfssl/testing-cross-compiler:${CUR_DATE} "${WOLFSSL_DIR}/Docker" -f Dockerfile.cross-compiler && \
    docker push wolfssl/testing-cross-compiler:${CUR_DATE} && \
    docker tag wolfssl/testing-cross-compiler:${CUR_DATE} wolfssl/testing-cross-compiler:latest && \
    docker push wolfssl/testing-cross-compiler:latest
