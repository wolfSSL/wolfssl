#!/bin/sh

if [ -z "$GITHUB_WORKSPACE" ]; then
    echo '$GITHUB_WORKSPACE is not set'
    exit 1
fi

if [ -z "$HOST_ROOT" ]; then
    echo '$HOST_ROOT is not set'
    exit 1
fi

chroot $HOST_ROOT make -C $GITHUB_WORKSPACE/memcached \
    -j$(nproc) PARALLEL=$(nproc) test_tls
