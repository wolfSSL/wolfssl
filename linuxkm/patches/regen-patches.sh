#!/bin/bash

# This script is an internal tool that regenerates kernel patches for
# WOLFSSL_LINUXKM_HAVE_GET_RANDOM_CALLBACKS, using full kernel sources staged
# for development.

if [[ ! -d 6.15 ]]; then
    echo "6.15 not found -- wrong working dir?" >&2
    exit 1
fi

cd src || exit $?

for v in *; do
    if [[ ! -d "$v" || "$v" == "src" ]]; then
        continue
    fi
    if [[ ! "$v" =~ ^[0-9]+\.[0-9]+([.-].*)?$ ]]; then
        echo "skipping ${v} (malformed version)"
        continue
    fi
    if [[ ! -f "${v}/drivers/char/random.c.dist" ||
          ! -f "${v}/drivers/char/random.c" ||
          ! -f "${v}/include/linux/random.h.dist" ||
          ! -f "${v}/include/linux/random.h" ]]; then
        echo "skipping ${v} (missing src files)"
        continue
    fi

    out_f="../${v}/WOLFSSL_LINUXKM_HAVE_GET_RANDOM_CALLBACKS-${v//./v}.patch"
    diff --minimal -up "${v}/drivers/char/"{random.c.dist,random.c} >| "$out_f"
    if [[ $? != "1" ]]; then
        echo "diff ${v}/src/drivers/char/{random.c.dist,random.c} exited with unexpected status." >&2
        exit 1
    fi
    diff --minimal -up "${v}/include/linux/"{random.h.dist,random.h} >> "$out_f"
    if [[ $? != "1" ]]; then
        echo "diff ${v}/src/include/linux/{random.h.dist,random.h} exited with unexpected status." >&2
        exit 1
    fi
done
