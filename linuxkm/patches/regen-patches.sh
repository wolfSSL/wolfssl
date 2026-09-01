#!/bin/bash

# This script is an internal tool that regenerates kernel patches for
# WOLFSSL_LINUXKM_HAVE_GET_RANDOM_CALLBACKS, using full kernel sources staged
# for development.

if [[ ! -d 6.15 ]]; then
    echo "6.15 not found -- wrong working dir?" >&2
    exit 1
fi

# Patch file naming.  The map is explicit rather than a substitution on $v
# because two directories do not follow the numeric pattern, and the previous
# "${v//./v}" transform silently produced names that did not match the files
# actually checked in for those two.
patch_basename() {
    case "$1" in
        5.14.0-570.58.1.el9_6)   echo "WOLFSSL_KERNELv5_14_el9_6_FIPS.patch" ;;
        5.17-ubuntu-jammy-tegra) echo "WOLFSSL_KERNELv5_17_tegra_FIPS.patch" ;;
        *)                       echo "WOLFSSL_KERNELv${1//./_}_FIPS.patch" ;;
    esac
}

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

    out_f="../${v}/$(patch_basename "$v")"
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
