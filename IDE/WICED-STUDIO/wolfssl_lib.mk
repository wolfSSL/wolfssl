#
# Copyright 2018, Cypress Semiconductor Corporation or a subsidiary of 
 # Cypress Semiconductor Corporation. All Rights Reserved.
 # This software, including source code, documentation and related
 # materials ("Software"), is owned by Cypress Semiconductor Corporation
 # or one of its subsidiaries ("Cypress") and is protected by and subject to
 # worldwide patent protection (United States and foreign),
 # United States copyright laws and international treaty provisions.
 # Therefore, you may use this Software only as provided in the license
 # agreement accompanying the software package from which you
 # obtained this Software ("EULA").
 # If no EULA applies, Cypress hereby grants you a personal, non-exclusive,
 # non-transferable license to copy, modify, and compile the Software
 # source code solely for use in connection with Cypress's
 # integrated circuit products. Any reproduction, modification, translation,
 # compilation, or representation of this Software except as specified
 # above is prohibited without the express written permission of Cypress.
 #
 # Disclaimer: THIS SOFTWARE IS PROVIDED AS-IS, WITH NO WARRANTY OF ANY KIND,
 # EXPRESS OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, NONINFRINGEMENT, IMPLIED
 # WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. Cypress
 # reserves the right to make changes to the Software without notice. Cypress
 # does not assume any liability arising out of the application or use of the
 # Software or any product or circuit described in the Software. Cypress does
 # not authorize its products for use in any products where a malfunction or
 # failure of the Cypress product may reasonably be expected to result in
 # significant property damage, injury or death ("High Risk Product"). By
 # including Cypress's product in a High Risk Product, the manufacturer
 # of such system or application assumes all risk of such use and in doing
 # so agrees to indemnify Cypress against all liability.
#


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
                    wolfssl/wolfcrypt/src/rabbit.c

GLOBAL_INCLUDES +=  wolfssl \
					user_settings_folder \


GLOBAL_DEFINES  +=  WOLFSSL_WICED_PSEUDO_UNIX_EPOCH_TIME=$(shell $(PERL) -e "print time()")  \
					WOLFSSL_USER_SETTINGS

                    
GLOBAL_CFLAGS   +=  -g1
