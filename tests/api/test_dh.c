/* test_dh.c
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

#include <tests/unit.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include <wolfssl/wolfcrypt/dh.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_dh.h>

/*
 * Testing wc_DhPublicKeyDecode
 */
int test_wc_DhPublicKeyDecode(void)
{
    EXPECT_DECLS;
#ifndef NO_DH
#if defined(WOLFSSL_DH_EXTRA) && defined(USE_CERT_BUFFERS_2048)
    DhKey  key;
    word32 inOutIdx;

    XMEMSET(&key, 0, sizeof(DhKey));

    ExpectIntEQ(wc_InitDhKey(&key), 0);

    ExpectIntEQ(wc_DhPublicKeyDecode(NULL,NULL,NULL,0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DhPublicKeyDecode(dh_pub_key_der_2048,NULL,NULL,0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DhPublicKeyDecode(dh_pub_key_der_2048,NULL,NULL,0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    inOutIdx = 0;
    ExpectIntEQ(wc_DhPublicKeyDecode(dh_pub_key_der_2048,&inOutIdx,NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    inOutIdx = 0;
    ExpectIntEQ(wc_DhPublicKeyDecode(dh_pub_key_der_2048,&inOutIdx,&key, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    inOutIdx = 0;
    ExpectIntEQ(wc_DhPublicKeyDecode(dh_pub_key_der_2048,&inOutIdx,&key,
        sizeof_dh_pub_key_der_2048), 0);
    ExpectIntNE(key.p.used, 0);
    ExpectIntNE(key.g.used, 0);
    ExpectIntEQ(key.q.used, 0);
    ExpectIntNE(key.pub.used, 0);
    ExpectIntEQ(key.priv.used, 0);

    DoExpectIntEQ(wc_FreeDhKey(&key), 0);
#endif
#endif /* !NO_DH */
    return EXPECT_RESULT();
}

