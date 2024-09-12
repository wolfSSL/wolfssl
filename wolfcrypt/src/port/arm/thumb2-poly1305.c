/* armv8-poly1305.c
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>

#ifdef WOLFSSL_ARMASM
#ifdef __thumb__

#ifdef HAVE_POLY1305
#include <wolfssl/wolfcrypt/poly1305.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/cpuid.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif
#ifdef CHACHA_AEAD_TEST
    #include <stdio.h>
#endif

/* Process 16 bytes of message at a time.
 *
 * @param [in] ctx    Poly1305 context.
 * @param [in] m      Message to process.
 * @param [in] bytes  Length of message in bytes.
 */
void poly1305_blocks_thumb2(Poly1305* ctx, const unsigned char* m,
    size_t bytes)
{
    poly1305_blocks_thumb2_16(ctx, m, bytes, 1);
}

/* Process 16 bytes of message.
 *
 * @param [in] ctx    Poly1305 context.
 * @param [in] m      Message to process.
 */
void poly1305_block_thumb2(Poly1305* ctx, const unsigned char* m)
{
    poly1305_blocks_thumb2_16(ctx, m, POLY1305_BLOCK_SIZE, 1);
}

/* Set the key for the Poly1305 operation.
 *
 * @param [in] ctx    Poly1305 context.
 * @param [in] key    Key data to use.
 * @param [in] keySz  Size of key in bytes. Must be 32.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when ctx or key is NULL or keySz is not 32.
 */
int wc_Poly1305SetKey(Poly1305* ctx, const byte* key, word32 keySz)
{
    int ret = 0;

#ifdef CHACHA_AEAD_TEST
    word32 k;
    printf("Poly key used:\n");
    if (key != NULL) {
        for (k = 0; k < keySz; k++) {
            printf("%02x", key[k]);
            if ((k+1) % 8 == 0)
                printf("\n");
        }
    }
    printf("\n");
#endif

    /* Validate parameters. */
    if ((ctx == NULL) || (key == NULL) || (keySz != 32)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        poly1305_set_key(ctx, key);
    }

    return ret;
}

/* Finalize the Poly1305 operation calculating the MAC.
 *
 * @param [in] ctx    Poly1305 context.
 * @param [in] mac    Buffer to hold the MAC. Myst be at least 16 bytes long.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when ctx or mac is NULL.
 */
int wc_Poly1305Final(Poly1305* ctx, byte* mac)
{
    int ret = 0;

    /* Validate parameters. */
    if ((ctx == NULL) || (mac == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    /* Process the remaining partial block - last block. */
    if (ret == 0) {
        if (ctx->leftover) {
             size_t i = ctx->leftover;
             ctx->buffer[i++] = 1;
             for (; i < POLY1305_BLOCK_SIZE; i++) {
                 ctx->buffer[i] = 0;
             }
             poly1305_blocks_thumb2_16(ctx, ctx->buffer, POLY1305_BLOCK_SIZE,
                 0);
        }

        poly1305_final(ctx, mac);
    }

    return ret;
}

#endif /* HAVE_POLY1305 */
#endif /* __aarch64__ */
#endif /* WOLFSSL_ARMASM */
