#!/usr/bin/env bash

# fips-check.sh
# This script checks the current revision of the code against the
# previous release of the FIPS code. While wolfSSL and wolfCrypt
# may be advancing, they must work correctly with the last tested
# copy of our FIPS approved code.
#
# This should check out all the approved flavors. The command line
# option selects the flavor. The keep option keeps the output
# directory.

# These variables may be overridden on the command line.
MAKE="${MAKE:-make}"
GIT="${GIT:-git -c advice.detachedHead=false}"
TEST_DIR="${TEST_DIR:-XXX-fips-test}"
case "$TEST_DIR" in
    /*) ;;
    *) TEST_DIR="${PWD}/${TEST_DIR}"
       ;;
esac
FLAVOR="${FLAVOR:-linux}"
KEEP="${KEEP:-no}"
MAKECHECK=${MAKECHECK:-yes}
DOCONFIGURE=${DOCONFIGURE:-yes}
DOAUTOGEN=${DOAUTOGEN:-yes}
FIPS_REPO="${FIPS_REPO:-git@github.com:wolfssl/fips.git}"
WOLFSSL_REPO="${WOLFSSL_REPO:-git@github.com:wolfssl/wolfssl.git}"

Usage() {
    cat <<usageText
Usage: $0 [flavor] [keep] [nomakecheck] [nodoconfigure] [noautogen]
Flavor is one of:
    linuxv2 (FIPSv2, use for Win10)
    fipsv2-OE-ready (ready FIPSv2)
    solaris
    netbsd-selftest
    marvell-linux-selftest
    linuxv5 (current FIPS 140-3)
    fips-ready (ready FIPS 140-3)
    fips-dev (dev FIPS 140-3)
    wolfrand
    wolfentropy
    v6.0.0
keep: (default off) retains the temp dir $TEST_DIR for inspection.
nomakecheck: (default off) don't run make check
nodoconfigure: (default off) don't run configure
noautogen: (default off) don't run autogen

Example:
    $0 windows keep
usageText
}

while [ "$1" ]; do
  if [ "$1" = 'keep' ]; then KEEP='yes';
  elif [ "$1" = 'nomakecheck' ]; then MAKECHECK='no';
  elif [ "$1" = 'nodoconfigure' ]; then DOCONFIGURE='no';
  elif [ "$1" = 'noautogen' ]; then DOCONFIGURE='no'; DOAUTOGEN='no';
  else FLAVOR="$1"; fi
  shift
done

case "$FLAVOR" in
linuxv2|fipsv2-OE-ready|solaris)
  FIPS_OPTION='v2'
  FIPS_FILES=(
    'wolfcrypt/src/fips.c:WCv4-stable'
    'wolfcrypt/src/fips_test.c:WCv4-stable'
    'wolfcrypt/src/wolfcrypt_first.c:WCv4-stable'
    'wolfcrypt/src/wolfcrypt_last.c:WCv4-stable'
    'wolfssl/wolfcrypt/fips.h:WCv4-stable'
  )
  WOLFCRYPT_FILES=(
    'wolfcrypt/src/aes.c:WCv4-stable'
    'wolfcrypt/src/aes_asm.asm:WCv4-stable'
    'wolfcrypt/src/aes_asm.S:WCv4-stable'
    'wolfcrypt/src/cmac.c:WCv4-stable'
    'wolfcrypt/src/des3.c:WCv4-stable'
    'wolfcrypt/src/dh.c:WCv4-stable'
    'wolfcrypt/src/ecc.c:WCv4-stable'
    'wolfcrypt/src/hmac.c:WCv4-stable'
    'wolfcrypt/src/random.c:WCv4-rng-stable'
    'wolfcrypt/src/rsa.c:WCv4-stable'
    'wolfcrypt/src/sha.c:WCv4-stable'
    'wolfcrypt/src/sha256.c:WCv4-stable'
    'wolfcrypt/src/sha3.c:WCv4-stable'
    'wolfcrypt/src/sha512.c:WCv4-stable'
    'wolfssl/wolfcrypt/aes.h:WCv4-stable'
    'wolfssl/wolfcrypt/cmac.h:WCv4-stable'
    'wolfssl/wolfcrypt/des3.h:WCv4-stable'
    'wolfssl/wolfcrypt/dh.h:WCv4-stable'
    'wolfssl/wolfcrypt/ecc.h:WCv4-stable'
    'wolfssl/wolfcrypt/hmac.h:WCv4-stable'
    'wolfssl/wolfcrypt/random.h:WCv4-rng-stable'
    'wolfssl/wolfcrypt/rsa.h:WCv4-stable'
    'wolfssl/wolfcrypt/sha.h:WCv4-stable'
    'wolfssl/wolfcrypt/sha256.h:WCv4-stable'
    'wolfssl/wolfcrypt/sha3.h:WCv4-stable'
    'wolfssl/wolfcrypt/sha512.h:WCv4-stable'
  )
  if [ "$FLAVOR" = 'solaris' ]; then MAKE='gmake'; fi
  ;;
netbsd-selftest)
  # non-FIPS, CAVP only but pull in selftest
  FIPS_OPTION='cavp-selftest'
  FIPS_FILES=('wolfcrypt/src/selftest.c:v3.14.2b')
  WOLFCRYPT_FILES=(
    'wolfcrypt/src/aes.c:v3.14.2'
    'wolfcrypt/src/dh.c:v3.14.2'
    'wolfcrypt/src/dsa.c:v3.14.2'
    'wolfcrypt/src/ecc.c:v3.14.2'
    'wolfcrypt/src/hmac.c:v3.14.2'
    'wolfcrypt/src/random.c:v3.14.2'
    'wolfcrypt/src/rsa.c:v3.14.2'
    'wolfcrypt/src/sha.c:v3.14.2'
    'wolfcrypt/src/sha256.c:v3.14.2'
    'wolfcrypt/src/sha512.c:v3.14.2'
    'wolfssl/wolfcrypt/aes.h:v3.14.2'
    'wolfssl/wolfcrypt/dh.h:v3.14.2'
    'wolfssl/wolfcrypt/dsa.h:v3.14.2'
    'wolfssl/wolfcrypt/ecc.h:v3.14.2'
    'wolfssl/wolfcrypt/hmac.h:v3.14.2'
    'wolfssl/wolfcrypt/random.h:v3.14.2'
    'wolfssl/wolfcrypt/rsa.h:v3.14.2'
    'wolfssl/wolfcrypt/sha.h:v3.14.2'
    'wolfssl/wolfcrypt/sha256.h:v3.14.2'
    'wolfssl/wolfcrypt/sha512.h:v3.14.2'
  )
  ;;
marvell-linux-selftest)
  # non-FIPS, CAVP only but pull in selftest
  FIPS_OPTION='cavp-selftest-v2'
  FIPS_FILES=('wolfcrypt/src/selftest.c:v3.14.2b')
  WOLFCRYPT_FILES=(
    'wolfcrypt/src/aes.c:v4.1.0-stable'
    'wolfcrypt/src/dh.c:v4.1.0-stable'
    'wolfcrypt/src/dsa.c:v4.1.0-stable'
    'wolfcrypt/src/ecc.c:v4.1.0-stable'
    'wolfcrypt/src/hmac.c:v4.1.0-stable'
    'wolfcrypt/src/random.c:v4.1.0-stable'
    'wolfcrypt/src/rsa.c:v4.1.0-stable'
    'wolfcrypt/src/sha.c:v4.1.0-stable'
    'wolfcrypt/src/sha256.c:v4.1.0-stable'
    'wolfcrypt/src/sha512.c:v4.1.0-stable'
    'wolfssl/wolfcrypt/aes.h:v4.1.0-stable'
    'wolfssl/wolfcrypt/dh.h:v4.1.0-stable'
    'wolfssl/wolfcrypt/dsa.h:v4.1.0-stable'
    'wolfssl/wolfcrypt/ecc.h:v4.1.0-stable'
    'wolfssl/wolfcrypt/hmac.h:v4.1.0-stable'
    'wolfssl/wolfcrypt/random.h:v4.1.0-stable'
    'wolfssl/wolfcrypt/rsa.h:v4.1.0-stable'
    'wolfssl/wolfcrypt/sha.h:v4.1.0-stable'
    'wolfssl/wolfcrypt/sha256.h:v4.1.0-stable'
    'wolfssl/wolfcrypt/sha512.h:v4.1.0-stable'
  )
  ;;
linuxv5-RC12)
  FIPS_OPTION='v5-RC12'
  FIPS_FILES=(
    'wolfcrypt/src/fips.c:WCv5.2.0.1-RC01'
    'wolfcrypt/src/fips_test.c:WCv5.0-RC12'
    'wolfcrypt/src/wolfcrypt_first.c:WCv5.0-RC12'
    'wolfcrypt/src/wolfcrypt_last.c:WCv5.0-RC12'
    'wolfssl/wolfcrypt/fips.h:WCv5.0-RC12'
  )
  WOLFCRYPT_FILES=(
    'wolfcrypt/src/aes.c:WCv5.0-RC12'
    'wolfcrypt/src/aes_asm.asm:WCv5.0-RC12'
    'wolfcrypt/src/aes_asm.S:WCv5.0-RC12'
    'wolfcrypt/src/aes_gcm_asm.S:WCv5.0-RC12'
    'wolfcrypt/src/cmac.c:WCv5.0-RC12'
    'wolfcrypt/src/dh.c:WCv5.0-RC12'
    'wolfcrypt/src/ecc.c:WCv5.0-RC12'
    'wolfcrypt/src/hmac.c:WCv5.0-RC12'
    'wolfcrypt/src/kdf.c:WCv5.0-RC12'
    'wolfcrypt/src/random.c:WCv5.0-RC12'
    'wolfcrypt/src/rsa.c:WCv5.0-RC12'
    'wolfcrypt/src/sha.c:WCv5.0-RC12'
    'wolfcrypt/src/sha256.c:WCv5.0-RC12'
    'wolfcrypt/src/sha256_asm.S:WCv5.0-RC12'
    'wolfcrypt/src/sha3.c:WCv5.0-RC12'
    'wolfcrypt/src/sha512.c:WCv5.0-RC12'
    'wolfcrypt/src/sha512_asm.S:WCv5.0-RC12'
    'wolfssl/wolfcrypt/aes.h:WCv5.0-RC12'
    'wolfssl/wolfcrypt/cmac.h:WCv5.0-RC12'
    'wolfssl/wolfcrypt/dh.h:WCv5.0-RC12'
    'wolfssl/wolfcrypt/ecc.h:WCv5.0-RC12'
    'wolfssl/wolfcrypt/fips_test.h:WCv5.0-RC12'
    'wolfssl/wolfcrypt/hmac.h:WCv5.0-RC12'
    'wolfssl/wolfcrypt/kdf.h:WCv5.0-RC12'
    'wolfssl/wolfcrypt/random.h:WCv5.0-RC12'
    'wolfssl/wolfcrypt/rsa.h:WCv5.0-RC12'
    'wolfssl/wolfcrypt/sha.h:WCv5.0-RC12'
    'wolfssl/wolfcrypt/sha256.h:WCv5.0-RC12'
    'wolfssl/wolfcrypt/sha3.h:WCv5.0-RC12'
    'wolfssl/wolfcrypt/sha512.h:WCv5.0-RC12'
  )
  ;;
linuxv5|linuxv5.2.1)
  FIPS_OPTION='v5'
  FIPS_FILES=(
    'wolfcrypt/src/fips.c:v5.2.1-stable'
    'wolfcrypt/src/fips_test.c:v5.2.1-stable'
    'wolfcrypt/src/wolfcrypt_first.c:v5.2.1-stable'
    'wolfcrypt/src/wolfcrypt_last.c:v5.2.1-stable'
    'wolfssl/wolfcrypt/fips.h:v5.2.1-stable-OS_Seed-HdrOnly'
  )
  WOLFCRYPT_FILES=(
    'wolfcrypt/src/aes.c:v5.2.1-stable'
    'wolfcrypt/src/aes_asm.asm:v5.2.1-stable'
    'wolfcrypt/src/aes_asm.S:v5.2.1-stable'
    'wolfcrypt/src/aes_gcm_asm.S:v5.2.1-stable'
    'wolfcrypt/src/cmac.c:v5.2.1-stable'
    'wolfcrypt/src/dh.c:v5.2.1-stable'
    'wolfcrypt/src/ecc.c:v5.2.1-stable'
    'wolfcrypt/src/hmac.c:v5.2.1-stable'
    'wolfcrypt/src/kdf.c:v5.2.1-stable'
    'wolfcrypt/src/random.c:v5.2.1-stable'
    'wolfcrypt/src/rsa.c:v5.2.1-stable'
    'wolfcrypt/src/sha.c:v5.2.1-stable'
    'wolfcrypt/src/sha256.c:v5.2.1-stable'
    'wolfcrypt/src/sha256_asm.S:v5.2.1-stable'
    'wolfcrypt/src/sha3.c:v5.2.1-stable'
    'wolfcrypt/src/sha512.c:v5.2.1-stable'
    'wolfcrypt/src/sha512_asm.S:v5.2.1-stable'
    'wolfssl/wolfcrypt/aes.h:v5.2.1-stable'
    'wolfssl/wolfcrypt/cmac.h:v5.2.1-stable'
    'wolfssl/wolfcrypt/dh.h:v5.2.1-stable'
    'wolfssl/wolfcrypt/ecc.h:v5.2.1-stable'
    'wolfssl/wolfcrypt/fips_test.h:v5.2.1-stable'
    'wolfssl/wolfcrypt/hmac.h:v5.2.1-stable'
    'wolfssl/wolfcrypt/kdf.h:v5.2.1-stable'
    'wolfssl/wolfcrypt/random.h:v5.2.1-stable-OS_Seed-HdrOnly'
    'wolfssl/wolfcrypt/rsa.h:v5.2.1-stable'
    'wolfssl/wolfcrypt/sha.h:v5.2.1-stable'
    'wolfssl/wolfcrypt/sha256.h:v5.2.1-stable'
    'wolfssl/wolfcrypt/sha3.h:v5.2.1-stable'
    'wolfssl/wolfcrypt/sha512.h:v5.2.1-stable'
  )
  ;;
v6.0.0)
  WOLF_REPO_TAG='WCv6.0.0-RC5'
  FIPS_REPO_TAG='WCv6.0.0-RC4'
  ASM_PICKUPS_TAG='WCv6.0.0-RC4'
  FIPS_OPTION='v6'
  FIPS_FILES=(
    "wolfcrypt/src/fips.c:${FIPS_REPO_TAG}"
    "wolfcrypt/src/fips_test.c:${FIPS_REPO_TAG}"
    "wolfcrypt/src/wolfcrypt_first.c:${FIPS_REPO_TAG}"
    "wolfcrypt/src/wolfcrypt_last.c:${FIPS_REPO_TAG}"
    "wolfssl/wolfcrypt/fips.h:${FIPS_REPO_TAG}"
  )
  WOLFCRYPT_FILES=(
    "wolfcrypt/src/aes_asm.asm:${WOLF_REPO_TAG}"
    "wolfcrypt/src/aes_asm.S:${WOLF_REPO_TAG}"
    "wolfcrypt/src/aes_gcm_asm.S:${WOLF_REPO_TAG}"
    "wolfcrypt/src/aes_gcm_x86_asm.S:${WOLF_REPO_TAG}"
    "wolfcrypt/src/aes_xts_asm.S:${WOLF_REPO_TAG}"
    "wolfcrypt/src/aes.c:${WOLF_REPO_TAG}"
    "wolfcrypt/src/port/arm/armv8-32-aes-asm_c.c:${ASM_PICKUPS_TAG}"
    "wolfcrypt/src/port/arm/armv8-32-aes-asm.S:${WOLF_REPO_TAG}"
    "wolfcrypt/src/port/arm/armv8-32-sha256-asm_c.c:${ASM_PICKUPS_TAG}"
    "wolfcrypt/src/port/arm/armv8-32-sha256-asm.S:${WOLF_REPO_TAG}"
    "wolfcrypt/src/port/arm/armv8-32-sha3-asm_c.c:${WOLF_REPO_TAG}"
    "wolfcrypt/src/port/arm/armv8-32-sha3-asm.S:${WOLF_REPO_TAG}"
    "wolfcrypt/src/port/arm/armv8-32-sha512-asm_c.c:${ASM_PICKUPS_TAG}"
    "wolfcrypt/src/port/arm/armv8-32-sha512-asm.S:${WOLF_REPO_TAG}"
    "wolfcrypt/src/port/arm/armv8-aes.c:${ASM_PICKUPS_TAG}"
    "wolfcrypt/src/port/arm/armv8-sha256.c:${WOLF_REPO_TAG}"
    "wolfcrypt/src/port/arm/armv8-sha3-asm_c.c:${ASM_PICKUPS_TAG}"
    "wolfcrypt/src/port/arm/armv8-sha3-asm.S:${ASM_PICKUPS_TAG}"
    "wolfcrypt/src/port/arm/armv8-sha512-asm_c.c:${ASM_PICKUPS_TAG}"
    "wolfcrypt/src/port/arm/armv8-sha512-asm.S:${WOLF_REPO_TAG}"
    "wolfcrypt/src/port/arm/armv8-sha512.c:${WOLF_REPO_TAG}"
    "wolfcrypt/src/cmac.c:${WOLF_REPO_TAG}"
    "wolfcrypt/src/dh.c:${WOLF_REPO_TAG}"
    "wolfcrypt/src/ecc.c:${WOLF_REPO_TAG}"
    "wolfcrypt/src/ed25519.c:${WOLF_REPO_TAG}"
    "wolfcrypt/src/ed448.c:${WOLF_REPO_TAG}"
    "wolfcrypt/src/hmac.c:${WOLF_REPO_TAG}"
    "wolfcrypt/src/kdf.c:${WOLF_REPO_TAG}"
    "wolfcrypt/src/pwdbased.c:${WOLF_REPO_TAG}"
    "wolfcrypt/src/random.c:${WOLF_REPO_TAG}"
    "wolfcrypt/src/rsa.c:${WOLF_REPO_TAG}"
    "wolfcrypt/src/sha.c:${WOLF_REPO_TAG}"
    "wolfcrypt/src/sha256_asm.S:${WOLF_REPO_TAG}"
    "wolfcrypt/src/sha256.c:${WOLF_REPO_TAG}"
    "wolfcrypt/src/sha3.c:${WOLF_REPO_TAG}"
    "wolfcrypt/src/sha3_asm.S:${WOLF_REPO_TAG}"
    "wolfcrypt/src/sha512_asm.S:${WOLF_REPO_TAG}"
    "wolfcrypt/src/sha512.c:${WOLF_REPO_TAG}"
    "wolfcrypt/src/sp_arm32.c:${ASM_PICKUPS_TAG}"
    "wolfcrypt/src/sp_arm64.c:${ASM_PICKUPS_TAG}"
    "wolfcrypt/src/sp_armthumb.c:${ASM_PICKUPS_TAG}"
    "wolfcrypt/src/sp_c32.c:${ASM_PICKUPS_TAG}"
    "wolfcrypt/src/sp_c64.c:${ASM_PICKUPS_TAG}"
    "wolfcrypt/src/sp_cortexm.c:${ASM_PICKUPS_TAG}"
    "wolfcrypt/src/sp_x86_64_asm.asm:${WOLF_REPO_TAG}"
    "wolfcrypt/src/sp_x86_64_asm.S:${WOLF_REPO_TAG}"
    "wolfcrypt/src/sp_x86_64.c:${ASM_PICKUPS_TAG}"
    "wolfcrypt/src/port/arm/thumb2-aes-asm_c.c:${WOLF_REPO_TAG}"
    "wolfcrypt/src/port/arm/thumb2-aes-asm.S:${WOLF_REPO_TAG}"
    "wolfcrypt/src/port/arm/thumb2-sha256-asm_c.c:${WOLF_REPO_TAG}"
    "wolfcrypt/src/port/arm/thumb2-sha256-asm.S:${WOLF_REPO_TAG}"
    "wolfcrypt/src/port/arm/thumb2-sha3-asm_c.c:${WOLF_REPO_TAG}"
    "wolfcrypt/src/port/arm/thumb2-sha3-asm.S:${WOLF_REPO_TAG}"
    "wolfcrypt/src/port/arm/thumb2-sha512-asm_c.c:${WOLF_REPO_TAG}"
    "wolfcrypt/src/port/arm/thumb2-sha512-asm.S:${WOLF_REPO_TAG}"
    "wolfssl/wolfcrypt/aes.h:${WOLF_REPO_TAG}"
    "wolfssl/wolfcrypt/cmac.h:${WOLF_REPO_TAG}"
    "wolfssl/wolfcrypt/dh.h:${WOLF_REPO_TAG}"
    "wolfssl/wolfcrypt/ecc.h:${WOLF_REPO_TAG}"
    "wolfssl/wolfcrypt/ed25519.h:${WOLF_REPO_TAG}"
    "wolfssl/wolfcrypt/ed448.h:${WOLF_REPO_TAG}"
    "wolfssl/wolfcrypt/fips_test.h:${WOLF_REPO_TAG}"
    "wolfssl/wolfcrypt/hmac.h:${WOLF_REPO_TAG}"
    "wolfssl/wolfcrypt/kdf.h:${WOLF_REPO_TAG}"
    "wolfssl/wolfcrypt/pwdbased.h:${WOLF_REPO_TAG}"
    "wolfssl/wolfcrypt/random.h:${WOLF_REPO_TAG}"
    "wolfssl/wolfcrypt/rsa.h:${WOLF_REPO_TAG}"
    "wolfssl/wolfcrypt/sha.h:${WOLF_REPO_TAG}"
    "wolfssl/wolfcrypt/sha256.h:${WOLF_REPO_TAG}"
    "wolfssl/wolfcrypt/sha3.h:${WOLF_REPO_TAG}"
    "wolfssl/wolfcrypt/sha512.h:${WOLF_REPO_TAG}"
    "wolfcrypt/src/port/riscv/riscv-64-sha256.c:${WOLF_REPO_TAG}"
    "wolfcrypt/src/port/riscv/riscv-64-sha3.c:${WOLF_REPO_TAG}"
    "wolfcrypt/src/port/riscv/riscv-64-sha512.c:${WOLF_REPO_TAG}"
  )
  ;;
fips-ready|fips-dev)
  if [ "$FLAVOR" = 'fips-dev' ]; then
      FIPS_OPTION='dev'
  else
      FIPS_OPTION='ready'
  fi
  FIPS_FILES=(
    'wolfcrypt/src/fips.c:master'
    'wolfcrypt/src/fips_test.c:master'
    'wolfcrypt/src/wolfcrypt_first.c:master'
    'wolfcrypt/src/wolfcrypt_last.c:master'
    'wolfssl/wolfcrypt/fips.h:master'
  )
  WOLFCRYPT_FILES=()
  ;;
wolfrand)
  FIPS_OPTION='rand'
  FIPS_FILES=(
    'wolfcrypt/src/fips.c:WRv4-stable'
    'wolfcrypt/src/fips_test.c:WRv4-stable'
    'wolfcrypt/src/wolfcrypt_first.c:WRv4-stable'
    'wolfcrypt/src/wolfcrypt_last.c:WRv4-stable'
    'wolfssl/wolfcrypt/fips.h:WRv4-stable'
  )
  WOLFCRYPT_FILES=(
    'wolfcrypt/src/hmac.c:WCv4-stable'
    'wolfcrypt/src/random.c:WCv4-rng-stable'
    'wolfcrypt/src/sha256.c:WCv4-stable'
    'wolfssl/wolfcrypt/hmac.h:WCv4-stable'
    'wolfssl/wolfcrypt/random.h:WCv4-rng-stable'
    'wolfssl/wolfcrypt/sha256.h:WCv4-stable'
  )
  ;;
wolfentropy)
  WOLF_REPO_TAG='WCv6.0.0-RC5'
  FIPS_REPO_TAG='WCv6.0.0-RC4'
  ASM_PICKUPS_TAG='WCv6.0.0-RC4'
  WOLF_ENTROPY_TAG='wolfEntropy2'
  FIPS_OPTION='v6'
  FIPS_FILES=(
    "wolfcrypt/src/fips.c:${FIPS_REPO_TAG}"
    "wolfcrypt/src/fips_test.c:${FIPS_REPO_TAG}"
    "wolfcrypt/src/wolfcrypt_first.c:${FIPS_REPO_TAG}"
    "wolfcrypt/src/wolfcrypt_last.c:${FIPS_REPO_TAG}"
    "wolfssl/wolfcrypt/fips.h:${FIPS_REPO_TAG}"
  )
  WOLFCRYPT_FILES=(
    "wolfcrypt/src/aes_asm.asm:${WOLF_REPO_TAG}"
    "wolfcrypt/src/aes_asm.S:${WOLF_REPO_TAG}"
    "wolfcrypt/src/aes_gcm_asm.S:${WOLF_REPO_TAG}"
    "wolfcrypt/src/aes_gcm_x86_asm.S:${WOLF_REPO_TAG}"
    "wolfcrypt/src/aes_xts_asm.S:${WOLF_REPO_TAG}"
    "wolfcrypt/src/aes.c:${WOLF_REPO_TAG}"
    "wolfcrypt/src/port/arm/armv8-32-aes-asm_c.c:${ASM_PICKUPS_TAG}"
    "wolfcrypt/src/port/arm/armv8-32-aes-asm.S:${WOLF_REPO_TAG}"
    "wolfcrypt/src/port/arm/armv8-32-sha256-asm_c.c:${ASM_PICKUPS_TAG}"
    "wolfcrypt/src/port/arm/armv8-32-sha256-asm.S:${WOLF_REPO_TAG}"
    "wolfcrypt/src/port/arm/armv8-32-sha3-asm_c.c:${WOLF_REPO_TAG}"
    "wolfcrypt/src/port/arm/armv8-32-sha3-asm.S:${WOLF_REPO_TAG}"
    "wolfcrypt/src/port/arm/armv8-32-sha512-asm_c.c:${ASM_PICKUPS_TAG}"
    "wolfcrypt/src/port/arm/armv8-32-sha512-asm.S:${WOLF_REPO_TAG}"
    "wolfcrypt/src/port/arm/armv8-aes.c:${ASM_PICKUPS_TAG}"
    "wolfcrypt/src/port/arm/armv8-sha256.c:${WOLF_REPO_TAG}"
    "wolfcrypt/src/port/arm/armv8-sha3-asm_c.c:${ASM_PICKUPS_TAG}"
    "wolfcrypt/src/port/arm/armv8-sha3-asm.S:${ASM_PICKUPS_TAG}"
    "wolfcrypt/src/port/arm/armv8-sha512-asm_c.c:${ASM_PICKUPS_TAG}"
    "wolfcrypt/src/port/arm/armv8-sha512-asm.S:${WOLF_REPO_TAG}"
    "wolfcrypt/src/port/arm/armv8-sha512.c:${WOLF_REPO_TAG}"
    "wolfcrypt/src/cmac.c:${WOLF_REPO_TAG}"
    "wolfcrypt/src/dh.c:${WOLF_REPO_TAG}"
    "wolfcrypt/src/ecc.c:${WOLF_REPO_TAG}"
    "wolfcrypt/src/ed25519.c:${WOLF_REPO_TAG}"
    "wolfcrypt/src/ed448.c:${WOLF_REPO_TAG}"
    "wolfcrypt/src/hmac.c:${WOLF_REPO_TAG}"
    "wolfcrypt/src/kdf.c:${WOLF_REPO_TAG}"
    "wolfcrypt/src/pwdbased.c:${WOLF_REPO_TAG}"
    "wolfcrypt/src/random.c:${WOLF_ENTROPY_TAG}"
    "wolfcrypt/src/rsa.c:${WOLF_REPO_TAG}"
    "wolfcrypt/src/sha.c:${WOLF_REPO_TAG}"
    "wolfcrypt/src/sha256_asm.S:${WOLF_REPO_TAG}"
    "wolfcrypt/src/sha256.c:${WOLF_REPO_TAG}"
    "wolfcrypt/src/sha3.c:${WOLF_REPO_TAG}"
    "wolfcrypt/src/sha3_asm.S:${WOLF_REPO_TAG}"
    "wolfcrypt/src/sha512_asm.S:${WOLF_REPO_TAG}"
    "wolfcrypt/src/sha512.c:${WOLF_REPO_TAG}"
    "wolfcrypt/src/sp_arm32.c:${ASM_PICKUPS_TAG}"
    "wolfcrypt/src/sp_arm64.c:${ASM_PICKUPS_TAG}"
    "wolfcrypt/src/sp_armthumb.c:${ASM_PICKUPS_TAG}"
    "wolfcrypt/src/sp_c32.c:${ASM_PICKUPS_TAG}"
    "wolfcrypt/src/sp_c64.c:${ASM_PICKUPS_TAG}"
    "wolfcrypt/src/sp_cortexm.c:${ASM_PICKUPS_TAG}"
    "wolfcrypt/src/sp_x86_64_asm.asm:${WOLF_REPO_TAG}"
    "wolfcrypt/src/sp_x86_64_asm.S:${WOLF_REPO_TAG}"
    "wolfcrypt/src/sp_x86_64.c:${ASM_PICKUPS_TAG}"
    "wolfcrypt/src/port/arm/thumb2-aes-asm_c.c:${WOLF_REPO_TAG}"
    "wolfcrypt/src/port/arm/thumb2-aes-asm.S:${WOLF_REPO_TAG}"
    "wolfcrypt/src/port/arm/thumb2-sha256-asm_c.c:${WOLF_REPO_TAG}"
    "wolfcrypt/src/port/arm/thumb2-sha256-asm.S:${WOLF_REPO_TAG}"
    "wolfcrypt/src/port/arm/thumb2-sha3-asm_c.c:${WOLF_REPO_TAG}"
    "wolfcrypt/src/port/arm/thumb2-sha3-asm.S:${WOLF_REPO_TAG}"
    "wolfcrypt/src/port/arm/thumb2-sha512-asm_c.c:${WOLF_REPO_TAG}"
    "wolfcrypt/src/port/arm/thumb2-sha512-asm.S:${WOLF_REPO_TAG}"
    "wolfssl/wolfcrypt/aes.h:${WOLF_REPO_TAG}"
    "wolfssl/wolfcrypt/cmac.h:${WOLF_REPO_TAG}"
    "wolfssl/wolfcrypt/dh.h:${WOLF_REPO_TAG}"
    "wolfssl/wolfcrypt/ecc.h:${WOLF_REPO_TAG}"
    "wolfssl/wolfcrypt/ed25519.h:${WOLF_REPO_TAG}"
    "wolfssl/wolfcrypt/ed448.h:${WOLF_REPO_TAG}"
    "wolfssl/wolfcrypt/fips_test.h:${WOLF_REPO_TAG}"
    "wolfssl/wolfcrypt/hmac.h:${WOLF_REPO_TAG}"
    "wolfssl/wolfcrypt/kdf.h:${WOLF_REPO_TAG}"
    "wolfssl/wolfcrypt/pwdbased.h:${WOLF_REPO_TAG}"
    "wolfssl/wolfcrypt/random.h:${WOLF_ENTROPY_TAG}"
    "wolfssl/wolfcrypt/rsa.h:${WOLF_REPO_TAG}"
    "wolfssl/wolfcrypt/sha.h:${WOLF_REPO_TAG}"
    "wolfssl/wolfcrypt/sha256.h:${WOLF_REPO_TAG}"
    "wolfssl/wolfcrypt/sha3.h:${WOLF_REPO_TAG}"
    "wolfssl/wolfcrypt/sha512.h:${WOLF_REPO_TAG}"
    "wolfcrypt/src/port/riscv/riscv-64-sha256.c:${WOLF_REPO_TAG}"
    "wolfcrypt/src/port/riscv/riscv-64-sha3.c:${WOLF_REPO_TAG}"
    "wolfcrypt/src/port/riscv/riscv-64-sha512.c:${WOLF_REPO_TAG}"
  )
  ;;

*)
  Usage
  exit 1
esac

# checkout_files takes an array of pairs of file paths and git tags to
# checkout. It will check to see if mytag exists and if not will make that
# tag a branch.
function checkout_files() {
    local name
    local tag
    for file_entry in "$@"; do
        name=${file_entry%%:*}
        tag=${file_entry#*:}
        if ! $GIT rev-parse -q --verify "my$tag" >/dev/null
        then
            $GIT branch --no-track "my$tag" "$tag" || exit $?
        fi
        $GIT checkout "my$tag" -- "$name" || exit $?
    done
}

# copy_fips_files takes an array of pairs of file paths and git tags to
# checkout. It will check to see if mytag exists and if now will make that
# tag a branch.  It breaks the filepath apart into file name and path, then
# copies it from the file from the fips directory to the path.
function copy_fips_files() {
    local name
    local bname
    local dname
    local tag
    for file_entry in "$@"; do
        name=${file_entry%%:*}
        tag=${file_entry#*:}
        bname=$(basename "$name")
        dname=$(dirname "$name")
        if ! $GIT rev-parse -q --verify "my$tag" >/dev/null; then
            $GIT branch --no-track "my$tag" "$tag" || exit $?
        fi
        $GIT checkout "my$tag" -- "$bname" || exit $?
        cp "$bname" "../$dname"
    done
}

# Note, it would be cleaner to compute the tag lists using associative arrays,
# but those were introduced in bash-4.  It's more important to maintain backward
# compatibility here.

declare -a WOLFCRYPT_TAGS_NEEDED_UNSORTED WOLFCRYPT_TAGS_NEEDED
if [ ${#WOLFCRYPT_FILES[@]} -gt 0 ]; then
    for file_entry in "${WOLFCRYPT_FILES[@]}"; do
        WOLFCRYPT_TAGS_NEEDED_UNSORTED+=("${file_entry#*:}")
    done
    while IFS= read -r tag; do WOLFCRYPT_TAGS_NEEDED+=("$tag"); done < <(IFS=$'\n'; sort -u <<< "${WOLFCRYPT_TAGS_NEEDED_UNSORTED[*]}")
    if [ "${#WOLFCRYPT_TAGS_NEEDED[@]}" = "0" ]; then
        echo "Error -- missing wolfCrypt tags." 1>&2
        exit 1
    fi
fi

declare -a FIPS_TAGS_NEEDED_UNSORTED FIPS_TAGS_NEEDED
for file_entry in "${FIPS_FILES[@]}"; do
    FIPS_TAGS_NEEDED_UNSORTED+=("${file_entry#*:}")
done
while IFS= read -r tag; do FIPS_TAGS_NEEDED+=("$tag"); done < <(IFS=$'\n'; sort -u <<< "${FIPS_TAGS_NEEDED_UNSORTED[*]}")
if [ "${#FIPS_TAGS_NEEDED[@]}" = "0" ]; then
    echo "Error -- missing FIPS tags." 1>&2
    exit 1
fi

if [ ${#WOLFCRYPT_TAGS_NEEDED[@]} -gt 0 ]; then
    echo "wolfCrypt tag$( [[ ${#WOLFCRYPT_TAGS_NEEDED[@]} != "1" ]] && echo -n 's'):"

    # Only use shallow fetch if the repo already has shallow branches, to avoid
    # tainting full repos with shallow objects.
    if [ -f .git/shallow ]; then
        shallow_args=(--depth 1)
    else
        shallow_args=()
    fi

    for tag in "${WOLFCRYPT_TAGS_NEEDED[@]}"; do
        if $GIT describe --long --exact-match "$tag" 2>/dev/null; then
            continue
        fi
        if ! $GIT fetch "${shallow_args[@]}" "$WOLFSSL_REPO" tag "$tag"; then
            echo "Can't fetch wolfCrypt tag: $tag" 1>&2
            exit 1
        fi
        # Make sure the tag is associated:
        $GIT tag "$tag" FETCH_HEAD >/dev/null 2>&1
    done
fi

if ! $GIT clone --shared . "$TEST_DIR"; then
    echo "fips-check: Couldn't clone current working directory." 1>&2
    exit 1
fi

# If there is a FIPS repo under the parent directory, leverage that:
if [ -d ../fips/.git ]; then
    pushd ../fips 1>/dev/null || exit 2

    # Only use shallow fetch if the repo already has shallow branches, to avoid
    # tainting full repos with shallow objects.
    if [ -f .git/shallow ]; then
        shallow_args=(--depth 1)
    else
        shallow_args=()
    fi

    echo "FIPS tag$( [[ ${#FIPS_TAGS_NEEDED[@]} != "1" ]] && echo -n 's'):"
    for tag in "${FIPS_TAGS_NEEDED[@]}"; do
        if [ "$tag" = "master" ]; then
            # master is handled specially below.
            continue
        fi
        if $GIT describe --long --exact-match "$tag" 2>/dev/null; then
            continue
        fi
        if ! $GIT fetch "${shallow_args[@]}" "$FIPS_REPO" tag "$tag"; then
            echo "Can't fetch FIPS tag: $tag" 1>&2
            exit 1
        fi
        # Make sure the tag is associated:
        $GIT tag "$tag" FETCH_HEAD >/dev/null 2>&1
    done

    # The current tooling for the FIPS tests is in the master branch and must be
    # checked out here.
    if ! $GIT clone --shared --branch master . "${TEST_DIR}/fips"; then
        echo "fips-check: Couldn't clone current working directory." 1>&2
        exit 1
    fi

    popd 1>/dev/null || exit 2

    # Make sure master is up-to-date:
    pushd "${TEST_DIR}/fips" 1>/dev/null || exit 2
    if ! $GIT pull "$FIPS_REPO" master; then
        echo "Can't refresh master FIPS tag" 1>&2
        exit 1
    fi
    popd 1>/dev/null || exit 2
fi

pushd "$TEST_DIR" 1>/dev/null || exit 2

if [ ! -d fips ]; then
    # The current tooling for the FIPS tests is in the master branch and must be
    # checked out here.
    if ! $GIT clone --depth 1 --branch master "$FIPS_REPO" fips; then
        echo "fips-check: Couldn't check out FIPS repository."
        exit 1
    fi

    pushd fips 1>/dev/null || exit 2
    echo "FIPS tag$( [[ ${#FIPS_TAGS_NEEDED[@]} != "1" ]] && echo -n 's'):"
    for tag in "${FIPS_TAGS_NEEDED[@]}"; do
        if [ "$tag" = "master" ]; then
            # master was just cloned fresh from $FIPS_REPO above.
            continue
        fi
        if $GIT describe --long --exact-match "$tag" 2>/dev/null; then
            continue
        fi
        # The FIPS repo here is an ephemeral clone, so we can safely use shallow
        # fetch unconditionally.
        if ! $GIT fetch --depth 1 "$FIPS_REPO" tag "$tag"; then
            echo "Can't fetch FIPS tag: $tag" 1>&2
            exit 1
        fi
        # Make sure the tag is associated:
        $GIT tag "$tag" FETCH_HEAD >/dev/null 2>&1
    done
    popd 1>/dev/null || exit 2
fi

checkout_files "${WOLFCRYPT_FILES[@]}" || exit 3
pushd fips 1>/dev/null || exit 2
copy_fips_files "${FIPS_FILES[@]}" || exit 3
popd 1>/dev/null || exit 2

# When checking out cert 3389 ready code, NIST will no longer perform
# new certifications on 140-2 modules. If we were to use the latest files from
# master that would require re-cert due to changes in the module boundary.
# Since OE additions can still be processed for cert3389 we will call 140-2
# ready "fipsv2-OE-ready" indicating it is ready to use for an OE addition but
# would not be good for a new certification effort with the latest files.
if [ "$FLAVOR" = 'fipsv2-OE-ready' ] && [ -s wolfcrypt/src/fips.c ]; then
    cp wolfcrypt/src/fips.c wolfcrypt/src/fips.c.bak
    sed "s/v4.0.0-alpha/fipsv2-OE-ready/" wolfcrypt/src/fips.c.bak >wolfcrypt/src/fips.c
fi

# run the make test
if [ "$DOAUTOGEN" = "yes" ]; then
    ./autogen.sh
fi

if [ "$DOCONFIGURE" = "yes" ]; then
    case "$FIPS_OPTION" in
    cavp-selftest)
        ./configure --enable-selftest
        ;;
    cavp-selftest-v2)
        ./configure --enable-selftest=v2
        ;;
    *)
        ./configure --enable-fips=$FIPS_OPTION
        ;;
    esac

    if ! $MAKE; then
        echo 'fips-check: Make failed. Debris left for analysis.'
        exit 3
    fi

    if [ -s wolfcrypt/src/fips_test.c ]; then
        NEWHASH=$(./wolfcrypt/test/testwolfcrypt | sed -n 's/hash = \(.*\)/\1/p')
        if [ -n "$NEWHASH" ]; then
            cp wolfcrypt/src/fips_test.c wolfcrypt/src/fips_test.c.bak
            sed "s/^\".*\";/\"${NEWHASH}\";/" wolfcrypt/src/fips_test.c.bak >wolfcrypt/src/fips_test.c
            make clean
        fi
    fi

    if [ "$MAKECHECK" = "yes" ]; then
        if ! $MAKE check; then
            echo 'fips-check: Test failed. Debris left for analysis.'
            exit 3
        fi
    fi
fi

# Clean up
popd 1>/dev/null || exit 2
if [ "$KEEP" = 'no' ]; then
    rm -rf "$TEST_DIR"
fi
