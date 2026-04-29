 # wolfssl_lib.mk
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



NAME := wolfSSL

$(NAME)_SOURCES +=  wolfssl/src/internal.c                    \
                    wolfssl/src/keys.c                        \
                    wolfssl/src/ssl.c                         \
                    wolfssl/src/tls.c                         \
                    wolfssl/src/wolfio.c                      \
                    wolfssl/wolfcrypt/src/aes.c               \
                    wolfssl/wolfcrypt/src/asn.c               \
                    wolfssl/wolfcrypt/src/chacha.c            \
                    wolfssl/wolfcrypt/src/chacha20_poly1305.c \
                    wolfssl/wolfcrypt/src/coding.c            \
                    wolfssl/wolfcrypt/src/cpuid.c             \
                    wolfssl/wolfcrypt/src/cmac.c              \
                    wolfssl/wolfcrypt/src/des3.c              \
                    wolfssl/wolfcrypt/src/dh.c                \
                    wolfssl/wolfcrypt/src/ecc.c               \
                    wolfssl/wolfcrypt/src/error.c             \
                    wolfssl/wolfcrypt/src/hash.c              \
                    wolfssl/wolfcrypt/src/hmac.c              \
                    wolfssl/wolfcrypt/src/logging.c           \
                    wolfssl/wolfcrypt/src/md4.c               \
                    wolfssl/wolfcrypt/src/md5.c               \
                    wolfssl/wolfcrypt/src/memory.c            \
                    wolfssl/wolfcrypt/src/poly1305.c          \
                    wolfssl/wolfcrypt/src/random.c            \
                    wolfssl/wolfcrypt/src/rsa.c               \
                    wolfssl/wolfcrypt/src/sha.c               \
                    wolfssl/wolfcrypt/src/sha256.c            \
                    wolfssl/wolfcrypt/src/sha3.c              \
                    wolfssl/wolfcrypt/src/sha512.c            \
                    wolfssl/wolfcrypt/src/signature.c         \
                    wolfssl/wolfcrypt/src/tfm.c               \
                    wolfssl/wolfcrypt/src/wc_encrypt.c        \
                    wolfssl/wolfcrypt/src/wc_port.c           \
                    wolfssl/wolfcrypt/src/wolfmath.c          \
                    wolfssl/wolfcrypt/test/test.c             \
                    wolfssl/wolfcrypt/src/ripemd.c            \
                    wolfssl/wolfcrypt/src/dsa.c               \
                    wolfssl/wolfcrypt/src/arc4.c              \
                    wolfssl/wolfcrypt/src/rabbit.c            \
                    wolfssl/wolfcrypt/src/curve25519.c        \
                    wolfssl/wolfcrypt/src/ed25519.c           \
                    wolfssl/wolfcrypt/benchmark/benchmark.c   \
                    wolfssl/src/tls13.c

GLOBAL_INCLUDES +=  wolfssl \
                              user_settings_folder \


GLOBAL_DEFINES  +=  WOLFSSL_WICED_PSEUDO_UNIX_EPOCH_TIME=$(shell $(PERL) -e "print time()")  \
                    WOLFSSL_USER_SETTINGS


GLOBAL_CFLAGS   +=  -g1
