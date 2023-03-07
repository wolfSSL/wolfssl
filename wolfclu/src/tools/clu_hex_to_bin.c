/* clu_hex_to_bin.c
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
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
#include <stdio.h>

#ifndef WOLFSSL_USER_SETTINGS
#include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#include <wolfclu/wolfclu/clu_header_main.h>

/* free up to 5 binary buffers using wolfssl abstraction layer */
void wolfCLU_freeBins(byte* b1, byte* b2, byte* b3, byte* b4, byte* b5)
{
    if (b1 != NULL)
        XFREE(b1, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (b2 != NULL)
        XFREE(b2, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (b3 != NULL)
        XFREE(b3, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (b4 != NULL)
        XFREE(b4, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (b5 != NULL)
        XFREE(b5, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
}


/* convert hex string to binary, store size, WOLFCLU_SUCCESS success
 * (free mem on failure) */
int wolfCLU_hexToBin(const char* h1, byte** b1, word32* b1Sz,
                    const char* h2, byte** b2, word32* b2Sz,
                    const char* h3, byte** b3, word32* b3Sz,
                    const char* h4, byte** b4, word32* b4Sz)
{
    int ret;

    /* b1 */
    if (h1 && b1 && b1Sz) {
        *b1Sz = (int)XSTRLEN(h1) / 2;
        *b1   = XMALLOC(*b1Sz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (*b1 == NULL)
            return MEMORY_E;
        ret = Base16_Decode((const byte*)h1, (int)XSTRLEN(h1), *b1, b1Sz);
        if (ret != 0) {
            wolfCLU_freeBins(*b1, NULL, NULL, NULL, NULL);
            return ret;
        }
    }

    /* b2 */
    if (h2 && b2 && b2Sz) {
        *b2Sz = (int)XSTRLEN(h2) / 2;
        *b2   = XMALLOC(*b2Sz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (*b2 == NULL) {
            wolfCLU_freeBins(b1 ? *b1 : NULL, NULL, NULL, NULL, NULL);
            return MEMORY_E;
        }
        ret = Base16_Decode((const byte*)h2, (int)XSTRLEN(h2), *b2, b2Sz);
        if (ret != 0) {
            wolfCLU_freeBins(b1 ? *b1 : NULL, *b2, NULL, NULL, NULL);
            return ret;
        }
    }

    /* b3 */
    if (h3 && b3 && b3Sz) {
        *b3Sz = (int)XSTRLEN(h3) / 2;
        *b3   = XMALLOC(*b3Sz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (*b3 == NULL) {
            wolfCLU_freeBins(b1 ? *b1 : NULL, b2 ? *b2 : NULL, NULL, NULL, NULL);
            return MEMORY_E;
        }
        ret = Base16_Decode((const byte*)h3, (int)XSTRLEN(h3), *b3, b3Sz);
        if (ret != 0) {
            wolfCLU_freeBins(b1 ? *b1 : NULL, b2 ? *b2 : NULL, *b3, NULL, NULL);
            return ret;
        }
    }

    /* b4 */
    if (h4 && b4 && b4Sz) {
        *b4Sz = (int)XSTRLEN(h4) / 2;
        *b4   = XMALLOC(*b4Sz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (*b4 == NULL) {
            wolfCLU_freeBins(b1 ? *b1 : NULL,b2 ? *b2 : NULL,b3 ? *b3 :
                                                                NULL,NULL,NULL);
            return MEMORY_E;
        }
        ret = Base16_Decode((const byte*)h4, (int)XSTRLEN(h4), *b4, b4Sz);
        if (ret != 0) {
            wolfCLU_freeBins(b1 ? *b1 : NULL, b2 ? *b2 : NULL, b3 ? *b3 : NULL,
                *b4, NULL);
            return ret;
        }
    }

    return WOLFCLU_SUCCESS;
}
