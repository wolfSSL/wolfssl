# Makefile
#
# Copyright (C) 2006-2019 wolfSSL Inc.
#
# This file is part of wolfSSL.
#
# wolfSSL is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# wolfSSL is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA

ENVI=UbuntuARM

# default to Ubuntu Release build
ifndef V
V=UbuntuARM_Release_aarch64
endif

SUPPORTED_VS = $(default_VS)
#DEPENDENCIES = \
#  ATOMIC \
#  RPCMEM \
#ATOMIC_DIR = $(HEXAGON_SDK_ROOT)/libs/common/atomic
#RPCMEM_DIR = $(HEXAGON_SDK_ROOT)/libs/common/rpcmem

include $(HEXAGON_SDK_ROOT)/build/make.d/$(ENVI)_vs.min
include $(HEXAGON_SDK_ROOT)/build/defines.min


BUILD_DLLS += libwolfssl

# include files
CC_FLAGS += -I../../
CC_FLAGS += -I./
CC_FLAGS += -DWOLFSSL_USER_SETTINGS

ifdef WOLFSSL_DSP
libwolfssl_QAICIDLS += DSP/sp_int
endif

# wolfSSL crypto source files
libwolfssl_C_SRCS += \
	../../wolfcrypt/src/aes \
	../../wolfcrypt/src/md2 \
	../../wolfcrypt/src/arc4 \
	../../wolfcrypt/src/md4 \
	../../wolfcrypt/src/asm \
	../../wolfcrypt/src/md5 \
	../../wolfcrypt/src/asn \
	../../wolfcrypt/src/memory \
	../../wolfcrypt/src/async \
	../../wolfcrypt/src/blake2b \
	../../wolfcrypt/src/pkcs12 \
	../../wolfcrypt/src/blake2s \
	../../wolfcrypt/src/pkcs7 \
	../../wolfcrypt/src/camellia \
	../../wolfcrypt/src/poly1305 \
	../../wolfcrypt/src/chacha20_poly1305 \
	../../wolfcrypt/src/pwdbased \
	../../wolfcrypt/src/chacha \
	../../wolfcrypt/src/rabbit \
	../../wolfcrypt/src/cmac \
	../../wolfcrypt/src/random \
	../../wolfcrypt/src/coding \
	../../wolfcrypt/src/ripemd \
	../../wolfcrypt/src/compress \
	../../wolfcrypt/src/rsa \
	../../wolfcrypt/src/cpuid \
	../../wolfcrypt/src/selftest \
	../../wolfcrypt/src/cryptocb \
	../../wolfcrypt/src/sha256 \
	../../wolfcrypt/src/curve25519 \
	../../wolfcrypt/src/sha3 \
	../../wolfcrypt/src/des3 \
	../../wolfcrypt/src/sha512 \
	../../wolfcrypt/src/dh \
	../../wolfcrypt/src/sha \
	../../wolfcrypt/src/dsa \
	../../wolfcrypt/src/signature \
	../../wolfcrypt/src/ecc \
	../../wolfcrypt/src/sp_arm32 \
	../../wolfcrypt/src/ecc_fp \
	../../wolfcrypt/src/sp_arm64 \
	../../wolfcrypt/src/ed25519 \
	../../wolfcrypt/src/sp_armthumb \
	../../wolfcrypt/src/error \
	../../wolfcrypt/src/sp_c32 \
	../../wolfcrypt/src/sp_c64 \
	../../wolfcrypt/src/sp_int \
	../../wolfcrypt/src/fe_low_mem \
	../../wolfcrypt/src/sp_cortexm \
	../../wolfcrypt/src/fe_operations \
	../../wolfcrypt/src/fips \
	../../wolfcrypt/src/sp_x86_64 \
	../../wolfcrypt/src/fips_test \
	../../wolfcrypt/src/srp \
	../../wolfcrypt/src/ge_low_mem \
	../../wolfcrypt/src/tfm \
	../../wolfcrypt/src/ge_operations \
	../../wolfcrypt/src/wc_encrypt \
	../../wolfcrypt/src/hash \
	../../wolfcrypt/src/wc_pkcs11 \
	../../wolfcrypt/src/hc128 \
	../../wolfcrypt/src/wc_port \
	../../wolfcrypt/src/hmac \
	../../wolfcrypt/src/wolfcrypt_first \
	../../wolfcrypt/src/idea \
	../../wolfcrypt/src/wolfcrypt_last \
	../../wolfcrypt/src/integer \
	../../wolfcrypt/src/wolfevent \
	../../wolfcrypt/src/logging \
	../../wolfcrypt/src/wolfmath

# wolfSSL TLS source files
libwolfssl_C_SRCS += \
	../../src/ocsp \
	../../src/tls \
	../../src/crl \
	../../src/sniffer \
	../../src/wolfio \
	../../src/internal \
	../../src/ssl \
	../../src/keys \
	../../src/tls13

# build benchmark app
BUILD_EXES += benchmark
benchmark_C_SRCS += ../../wolfcrypt/benchmark/benchmark
benchmark_DLLS += libwolfssl
benchamrk_LD_FLAGS += -lpthread

# build test app
BUILD_EXES += testwolfcrypt 
testwolfcrypt_C_SRCS += ../../wolfcrypt/test/test
testwolfcrypt_DLLS += libwolfssl

include $(RULES_MIN)

