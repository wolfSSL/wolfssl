#
# Copyright (C) 2006-2024 wolfSSL Inc.
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
#

$(info ***********  wolfssl component ************)

#
# Component Makefile
#
#
# The Espressif Managed Components are only for newer versions of the ESP-IDF
# Typically only for ESP32[-x] targets and only for ESP-IDF v4.3 or later:
# See https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/tools/idf-component-manager.html
#     https://components.espressif.com/
#
# Usage:
#
#   make flash
#
#   make flash ESPPORT=/dev/ttyS55
#
#   make flash ESPBAUD=9600
#
#   make monitor ESPPORT=COM1
#
#   make monitor ESPPORT=/dev/ttyS55 MONITORBAUD=115200
#
#   export ESPPORT=/dev/ttyS55
#
# https://docs.espressif.com/projects/esp8266-rtos-sdk/en/latest/get-started/index.html
#

# Although the project should define WOLFSSL_USER_SETTINGS, we'll also
# define it here:
CFLAGS +=-DWOLFSSL_USER_SETTINGS

# Note that 4 source files created by autogen are excluded here.
#
# See these files commented out, below. Adjust as needed for your application:
#
# COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/async.o
# COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/selftest.o
# COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/wolfcrypt_first.o
# COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/wolfcrypt_last.o


# NOTICE: the WOLFSSL_ROOT setting MUST be relative!
# See https://docs.espressif.com/projects/esp8266-rtos-sdk/en/latest/api-guides/build-system.html?highlight=must+relative#optional-component-specific-variables
# In the wolfSSL GitHub examples for Espressif:
#   https://github.com/wolfSSL/wolfssl/tree/master/IDE/Espressif/ESP-IDF/examples
# When this wolfssl component.mk makefile is in [project]/components/wolfssl
# The root is 7 directories up from here (the location of of this component.mk):
WOLFSSL_ROOT := ../../../../../../..

# To set the location of a different location, it is best to use relative paths.
#
# Set WOLFSSL_ROOT to a relative path from the current component directory.
# For example, if the wolfssl_client is copied from the examples to test:
#
# cp -r /IDE/Espressif/ESP-IDF/examples/wolfssl_client/* /mnt/c/test/demo
#
# we run make in   /mnt/c/test/demo
# component is in  /mnt/c/test/demo/components/wolfssl
# wolfssl is in    /mnt/c/workspace/wolfssl-master
#
# "/mnt/c" is 4 directories up:
#             2 for `./test/demo` from where we run `make`, plus
#             2 more from the location of `component.mk` located
#               in `[current directory]/components/wolfssl`.
#
# Thus we need 4 parent reference to find the relative path to wolfSSL:
# WOLFSSL_ROOT := ../../../../workspace/wolfssl-master

# Optional CFLAGS (make works without these; for reference only)
# CFLAGS += -I$(WOLFSSL_ROOT)/wolfssl
# CFLAGS += -I$(WOLFSSL_ROOT)/wolfssl/wolfcrypt
# CFLAGS += -I$(WOLFSSL_ROOT)/wolfssl/wolfcrypt/port/Espressif

abs_WOLFSSL_ROOT := $(shell realpath $(WOLFSSL_ROOT))

# print-wolfssl-path-value:
#	@echo "WOLFSSL_ROOT defined: $(WOLFSSL_ROOT)"
#	@echo "WOLFSSL_ROOT actual:  $(abs_WOLFSSL_ROOT)"

$(info WOLFSSL_ROOT defined: $(WOLFSSL_ROOT))
$(info WOLFSSL_ROOT actual:  $(abs_WOLFSSL_ROOT))

# NOTE: The wolfSSL include directory (e.g. user_settings.h) is
# located HERE in THIS project, and *not* in the wolfSSL root.
COMPONENT_ADD_INCLUDEDIRS := .
COMPONENT_ADD_INCLUDEDIRS += include
COMPONENT_ADD_INCLUDEDIRS += $(WOLFSSL_ROOT)/.
COMPONENT_ADD_INCLUDEDIRS += $(WOLFSSL_ROOT)/wolfssl
COMPONENT_ADD_INCLUDEDIRS += $(WOLFSSL_ROOT)/wolfssl/wolfcrypt
COMPONENT_ADD_INCLUDEDIRS += $(WOLFSSL_ROOT)/wolfssl/wolfcrypt/port/Espressif
# COMPONENT_ADD_INCLUDEDIRS += $ENV(IDF_PATH)/components/freertos/include/freertos
# COMPONENT_ADD_INCLUDEDIRS += "$ENV(IDF_PATH)/soc/esp32s3/include/soc"

# wolfSSL
COMPONENT_SRCDIRS := $(WOLFSSL_ROOT)/src

# wolfcrypt
COMPONENT_SRCDIRS += $(WOLFSSL_ROOT)/wolfcrypt/src

# Espressif
COMPONENT_SRCDIRS += $(WOLFSSL_ROOT)/wolfcrypt/src/port/Espressif
COMPONENT_SRCDIRS += $(WOLFSSL_ROOT)/wolfcrypt/src/port/atmel

COMPONENT_OBJEXCLUDE := $(WOLFSSL_ROOT)/wolfcrypt/src/aes_asm.o
COMPONENT_OBJEXCLUDE += $(WOLFSSL_ROOT)/wolfcrypt/src/evp.o
COMPONENT_OBJEXCLUDE += $(WOLFSSL_ROOT)/wolfcrypt/src/misc.o
COMPONENT_OBJEXCLUDE += $(WOLFSSL_ROOT)/wolfcrypt/src/sha512_asm.o
COMPONENT_OBJEXCLUDE += $(WOLFSSL_ROOT)/wolfcrypt/src/fe_x25519_asm.o
COMPONENT_OBJEXCLUDE += $(WOLFSSL_ROOT)/wolfcrypt/src/aes_gcm_x86_asm.o
COMPONENT_OBJEXCLUDE += $(WOLFSSL_ROOT)/src/bio.o


##
## wolfSSL
##
COMPONENT_OBJS := $(WOLFSSL_ROOT)/src/bio.o
# COMPONENT_OBJS += src/conf.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/src/crl.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/src/dtls.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/src/dtls13.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/src/internal.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/src/keys.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/src/ocsp.o
# COMPONENT_OBJS += src/pk.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/src/quic.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/src/sniffer.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/src/ssl.o
# COMPONENT_OBJS += src/ssl_asn1.o
# COMPONENT_OBJS += src/ssl_bn.o
# COMPONENT_OBJS += src/ssl_certman.o
# COMPONENT_OBJS += src/ssl_crypto.o
# COMPONENT_OBJS += src/ssl_misc.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/src/tls.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/src/tls13.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/src/wolfio.o
# COMPONENT_OBJS += src/x509.o
# COMPONENT_OBJS += src/x509_str.o

##
## wolfcrypt
##
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/aes.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/arc4.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/asm.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/asn.o
# COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/async.o # autogen exclusion
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/blake2b.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/blake2s.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/camellia.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/chacha.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/chacha20_poly1305.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/cmac.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/coding.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/compress.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/cpuid.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/cryptocb.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/curve25519.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/curve448.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/des3.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/dh.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/dilithium.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/dsa.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/ecc.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/eccsi.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/ecc_fp.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/ed25519.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/ed448.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/error.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/evp.o
# COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/ext_kyber.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/ext_lms.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/ext_xmss.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/falcon.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/fe_448.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/fe_low_mem.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/fe_operations.o
# COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/fips.o
# COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/fips_test.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/ge_448.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/ge_low_mem.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/ge_operations.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/hash.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/hmac.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/hpke.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/integer.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/kdf.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/logging.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/md2.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/md4.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/md5.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/memory.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/misc.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/pkcs12.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/pkcs7.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/poly1305.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/pwdbased.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/random.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/rc2.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/ripemd.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/rsa.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/sakke.o
# COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/selftest.o # autogen exclusion
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/sha.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/sha256.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/sha3.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/sha512.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/signature.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/siphash.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/sm2.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/sm3.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/sm4.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/sphincs.o
# COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/sp_arm32.o
# COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/sp_arm64.o
# COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/sp_armthumb.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/sp_c32.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/sp_c64.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/sp_cortexm.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/sp_dsp32.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/sp_int.o
# COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/sp_sm2_arm32.o
# COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/sp_sm2_arm64.o
# COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/sp_sm2_armthumb.o
# COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/sp_sm2_c32.o
# COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/sp_sm2_c64.o
# COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/sp_sm2_cortexm.o
# COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/sp_sm2_x86_64.o
# COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/sp_x86_64.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/srp.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/tfm.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/wc_dsp.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/wc_encrypt.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/wc_kyber.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/wc_kyber_poly.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/wc_lms.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/wc_pkcs11.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/wc_port.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/wc_xmss.o
# COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/wolfcrypt_first.o # autogen exclusion
# COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/wolfcrypt_last.o  # autogen exclusion
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/wolfevent.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/wolfmath.o

##
## Espressif
##
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/port/Espressif/esp32_aes.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/port/Espressif/esp32_mp.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/port/Espressif/esp32_sha.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/port/Espressif/esp32_util.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/port/Espressif/esp_sdk_mem_lib.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/port/Espressif/esp_sdk_time_lib.o
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/src/port/Espressif/esp_sdk_wifi_lib.o

##
## wolfcrypt benchmark  (optional)
##
## COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/benchmark/benchmark.o
## COMPONENT_SRCDIRS += $(WOLFSSL_ROOT)/wolfcrypt/benchmark
## COMPONENT_ADD_INCLUDEDIRS += $(WOLFSSL_ROOT)/wolfcrypt/benchmark


##
## wolfcrypt test (optional)
##
COMPONENT_OBJS += $(WOLFSSL_ROOT)/wolfcrypt/test/test.o
COMPONENT_SRCDIRS += $(WOLFSSL_ROOT)/wolfcrypt/test

##
## wolfcrypt
##
# COMPONENT_PRIV_INCLUDEDIRS += $(PROJECT_PATH)/components/wolfssl/include
COMPONENT_SRCDIRS += $(WOLFSSL_ROOT)/wolfcrypt/src
$(info ********** end wolfssl component **********)
