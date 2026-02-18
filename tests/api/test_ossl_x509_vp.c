/* test_ossl_x509_vp.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
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

#include <wolfssl/ssl.h>
#include <tests/api/api.h>
#include <tests/api/test_ossl_x509_vp.h>

int test_wolfSSL_X509_VERIFY_PARAM(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA)
    X509_VERIFY_PARAM *paramTo = NULL;
    X509_VERIFY_PARAM *paramFrom = NULL;
    char testIPv4[] = "127.0.0.1";
    char testIPv6[] = "0001:0000:0000:0000:0000:0000:0000:0000/32";
    char testhostName1[] = "foo.hoge.com";
    char testhostName2[] = "foobar.hoge.com";

    ExpectNotNull(paramTo = X509_VERIFY_PARAM_new());
    ExpectNotNull(XMEMSET(paramTo, 0, sizeof(X509_VERIFY_PARAM)));

    ExpectNotNull(paramFrom = X509_VERIFY_PARAM_new());
    ExpectNotNull(XMEMSET(paramFrom, 0, sizeof(X509_VERIFY_PARAM)));

    ExpectIntEQ(X509_VERIFY_PARAM_set1_host(paramFrom, testhostName1,
        (int)XSTRLEN(testhostName1)), 1);
    ExpectIntEQ(0, XSTRNCMP(paramFrom->hostName, testhostName1,
        (int)XSTRLEN(testhostName1)));

    X509_VERIFY_PARAM_set_hostflags(NULL, 0x00);

    X509_VERIFY_PARAM_set_hostflags(paramFrom, 0x01);
    ExpectIntEQ(0x01, paramFrom->hostFlags);

    ExpectIntEQ(X509_VERIFY_PARAM_set1_ip_asc(NULL, testIPv4), 0);

    ExpectIntEQ(X509_VERIFY_PARAM_set1_ip_asc(paramFrom, testIPv4), 1);
    ExpectIntEQ(0, XSTRNCMP(paramFrom->ipasc, testIPv4, WOLFSSL_MAX_IPSTR));

    ExpectIntEQ(X509_VERIFY_PARAM_set1_ip_asc(paramFrom, NULL), 1);

    ExpectIntEQ(X509_VERIFY_PARAM_set1_ip_asc(paramFrom, testIPv6), 1);
    ExpectIntEQ(0, XSTRNCMP(paramFrom->ipasc, testIPv6, WOLFSSL_MAX_IPSTR));

    /* null pointer */
    ExpectIntEQ(X509_VERIFY_PARAM_set1(NULL, paramFrom), 0);
    /* in the case of "from" null, returns success */
    ExpectIntEQ(X509_VERIFY_PARAM_set1(paramTo, NULL), 1);

    ExpectIntEQ(X509_VERIFY_PARAM_set1(NULL, NULL), 0);

    /* inherit flags test : VPARAM_DEFAULT */
    ExpectIntEQ(X509_VERIFY_PARAM_set1(paramTo, paramFrom), 1);
    ExpectIntEQ(0, XSTRNCMP(paramTo->hostName, testhostName1,
                                    (int)XSTRLEN(testhostName1)));
    ExpectIntEQ(0x01, paramTo->hostFlags);
    ExpectIntEQ(0, XSTRNCMP(paramTo->ipasc, testIPv6, WOLFSSL_MAX_IPSTR));

    /* inherit flags test : VPARAM OVERWRITE */
    ExpectIntEQ(X509_VERIFY_PARAM_set1_host(paramTo, testhostName2,
        (int)XSTRLEN(testhostName2)), 1);
    ExpectIntEQ(X509_VERIFY_PARAM_set1_ip_asc(paramTo, testIPv4), 1);
    X509_VERIFY_PARAM_set_hostflags(paramTo, 0x00);

    if (paramTo != NULL) {
        paramTo->inherit_flags = X509_VP_FLAG_OVERWRITE;
    }

    ExpectIntEQ(X509_VERIFY_PARAM_set1(paramTo, paramFrom), 1);
    ExpectIntEQ(0, XSTRNCMP(paramTo->hostName, testhostName1,
        (int)XSTRLEN(testhostName1)));
    ExpectIntEQ(0x01, paramTo->hostFlags);
    ExpectIntEQ(0, XSTRNCMP(paramTo->ipasc, testIPv6, WOLFSSL_MAX_IPSTR));

    /* inherit flags test : VPARAM_RESET_FLAGS */
    ExpectIntEQ(X509_VERIFY_PARAM_set1_host(paramTo, testhostName2,
        (int)XSTRLEN(testhostName2)), 1);
    ExpectIntEQ(X509_VERIFY_PARAM_set1_ip_asc(paramTo, testIPv4), 1);
    X509_VERIFY_PARAM_set_hostflags(paramTo, 0x10);

    if (paramTo != NULL) {
        paramTo->inherit_flags = X509_VP_FLAG_RESET_FLAGS;
    }

    ExpectIntEQ(X509_VERIFY_PARAM_set1(paramTo, paramFrom), 1);
    ExpectIntEQ(0, XSTRNCMP(paramTo->hostName, testhostName1,
                                        (int)XSTRLEN(testhostName1)));
    ExpectIntEQ(0x01, paramTo->hostFlags);
    ExpectIntEQ(0, XSTRNCMP(paramTo->ipasc, testIPv6, WOLFSSL_MAX_IPSTR));
    ExpectIntEQ(0, XSTRNCMP(paramTo->ipasc, testIPv6, WOLFSSL_MAX_IPSTR));

    /* inherit flags test : VPARAM_LOCKED */
    ExpectIntEQ(X509_VERIFY_PARAM_set1_host(paramTo, testhostName2,
        (int)XSTRLEN(testhostName2)), 1);
    ExpectIntEQ(X509_VERIFY_PARAM_set1_ip_asc(paramTo, testIPv4), 1);
    X509_VERIFY_PARAM_set_hostflags(paramTo, 0x00);

    if (paramTo != NULL) {
        paramTo->inherit_flags = X509_VP_FLAG_LOCKED;
    }

    ExpectIntEQ(X509_VERIFY_PARAM_set1(paramTo, paramFrom), 1);
    ExpectIntEQ(0, XSTRNCMP(paramTo->hostName, testhostName2,
                                    (int)XSTRLEN(testhostName2)));
    ExpectIntEQ(0x00, paramTo->hostFlags);
    ExpectIntEQ(0, XSTRNCMP(paramTo->ipasc, testIPv4, WOLFSSL_MAX_IPSTR));

    /* test for incorrect parameters */
    ExpectIntEQ(X509_VERIFY_PARAM_set_flags(NULL, X509_V_FLAG_CRL_CHECK_ALL),
        0);

    ExpectIntEQ(X509_VERIFY_PARAM_set_flags(NULL, 0), 0);

    /* inherit flags test : VPARAM_ONCE, not testable yet */

    ExpectIntEQ(X509_VERIFY_PARAM_set_flags(paramTo, X509_V_FLAG_CRL_CHECK_ALL),
        1);

    ExpectIntEQ(X509_VERIFY_PARAM_get_flags(NULL), 0);
    ExpectIntEQ(X509_VERIFY_PARAM_get_flags(paramTo),
        X509_V_FLAG_CRL_CHECK_ALL);

    ExpectIntEQ(X509_VERIFY_PARAM_clear_flags(NULL, X509_V_FLAG_CRL_CHECK_ALL),
        WOLFSSL_FAILURE);
    ExpectIntEQ(X509_VERIFY_PARAM_clear_flags(paramTo,
        X509_V_FLAG_CRL_CHECK_ALL), 1);

    ExpectIntEQ(X509_VERIFY_PARAM_get_flags(paramTo), 0);

    ExpectNull(wolfSSL_X509_VERIFY_PARAM_lookup(NULL));
    ExpectNull(wolfSSL_X509_VERIFY_PARAM_lookup(""));
    ExpectNotNull(wolfSSL_X509_VERIFY_PARAM_lookup("ssl_client"));
    ExpectNotNull(wolfSSL_X509_VERIFY_PARAM_lookup("ssl_server"));

    X509_VERIFY_PARAM_free(paramTo);
    X509_VERIFY_PARAM_free(paramFrom);
    X509_VERIFY_PARAM_free(NULL); /* to confirm NULL parameter gives no harm */
#endif
    return EXPECT_RESULT();
}

int test_wolfSSL_X509_VERIFY_PARAM_set1_ip(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA) && !defined(NO_FILESYSTEM)
    unsigned char buf[16] = {0};
    WOLFSSL_X509_VERIFY_PARAM* param = NULL;

    ExpectNotNull(param = X509_VERIFY_PARAM_new());

    ExpectIntEQ(X509_VERIFY_PARAM_set1_ip(NULL, NULL, 1), WOLFSSL_FAILURE);
    ExpectIntEQ(X509_VERIFY_PARAM_set1_ip(param, NULL, 1), WOLFSSL_FAILURE);
    ExpectIntEQ(X509_VERIFY_PARAM_set1_ip(NULL, buf, 1), WOLFSSL_FAILURE);
    ExpectIntEQ(X509_VERIFY_PARAM_set1_ip(NULL, NULL, 16), WOLFSSL_FAILURE);
    ExpectIntEQ(X509_VERIFY_PARAM_set1_ip(NULL, NULL, 4), WOLFSSL_FAILURE);
    ExpectIntEQ(X509_VERIFY_PARAM_set1_ip(NULL, NULL, 0), WOLFSSL_FAILURE);
    ExpectIntEQ(X509_VERIFY_PARAM_set1_ip(param, buf, 1), WOLFSSL_FAILURE);
    ExpectIntEQ(X509_VERIFY_PARAM_set1_ip(param, NULL, 16), WOLFSSL_FAILURE);
    ExpectIntEQ(X509_VERIFY_PARAM_set1_ip(param, NULL, 4), WOLFSSL_FAILURE);
    ExpectIntEQ(X509_VERIFY_PARAM_set1_ip(NULL, buf, 16), WOLFSSL_FAILURE);
    ExpectIntEQ(X509_VERIFY_PARAM_set1_ip(NULL, buf, 4), WOLFSSL_FAILURE);
    ExpectIntEQ(X509_VERIFY_PARAM_set1_ip(NULL, buf, 0), WOLFSSL_FAILURE);

    ExpectIntEQ(X509_VERIFY_PARAM_set1_ip(param, NULL, 0), WOLFSSL_SUCCESS);

    /* test 127.0.0.1 */
    buf[0] =0x7f; buf[1] = 0; buf[2] = 0; buf[3] = 1;
    ExpectIntEQ(X509_VERIFY_PARAM_set1_ip(param, &buf[0], 4), SSL_SUCCESS);
    ExpectIntEQ(XSTRNCMP(param->ipasc, "127.0.0.1", sizeof(param->ipasc)), 0);

    /* test 2001:db8:3333:4444:5555:6666:7777:8888 */
    buf[0]=32;buf[1]=1;buf[2]=13;buf[3]=184;
    buf[4]=51;buf[5]=51;buf[6]=68;buf[7]=68;
    buf[8]=85;buf[9]=85;buf[10]=102;buf[11]=102;
    buf[12]=119;buf[13]=119;buf[14]=136;buf[15]=136;
    ExpectIntEQ(X509_VERIFY_PARAM_set1_ip(param, &buf[0], 16), SSL_SUCCESS);
    ExpectIntEQ(XSTRNCMP(param->ipasc,
        "2001:db8:3333:4444:5555:6666:7777:8888", sizeof(param->ipasc)), 0);

    /* test 2001:db8:: */
    buf[0]=32;buf[1]=1;buf[2]=13;buf[3]=184;
    buf[4]=0;buf[5]=0;buf[6]=0;buf[7]=0;
    buf[8]=0;buf[9]=0;buf[10]=0;buf[11]=0;
    buf[12]=0;buf[13]=0;buf[14]=0;buf[15]=0;
    ExpectIntEQ(X509_VERIFY_PARAM_set1_ip(param, &buf[0], 16), SSL_SUCCESS);
    ExpectIntEQ(XSTRNCMP(param->ipasc, "2001:db8::", sizeof(param->ipasc)), 0);

    /* test ::1234:5678 */
    buf[0]=0;buf[1]=0;buf[2]=0;buf[3]=0;
    buf[4]=0;buf[5]=0;buf[6]=0;buf[7]=0;
    buf[8]=0;buf[9]=0;buf[10]=0;buf[11]=0;
    buf[12]=18;buf[13]=52;buf[14]=86;buf[15]=120;
    ExpectIntEQ(X509_VERIFY_PARAM_set1_ip(param, &buf[0], 16), SSL_SUCCESS);
    ExpectIntEQ(XSTRNCMP(param->ipasc, "::1234:5678", sizeof(param->ipasc)), 0);


    /* test 2001:db8::1234:5678 */
    buf[0]=32;buf[1]=1;buf[2]=13;buf[3]=184;
    buf[4]=0;buf[5]=0;buf[6]=0;buf[7]=0;
    buf[8]=0;buf[9]=0;buf[10]=0;buf[11]=0;
    buf[12]=18;buf[13]=52;buf[14]=86;buf[15]=120;
    ExpectIntEQ(X509_VERIFY_PARAM_set1_ip(param, &buf[0], 16), SSL_SUCCESS);
    ExpectIntEQ(XSTRNCMP(param->ipasc, "2001:db8::1234:5678",
                                                sizeof(param->ipasc)), 0);

    /* test 2001:0db8:0001:0000:0000:0ab9:c0a8:0102*/
    /*      2001:db8:1::ab9:c0a8:102 */
    buf[0]=32;buf[1]=1;buf[2]=13;buf[3]=184;
    buf[4]=0;buf[5]=1;buf[6]=0;buf[7]=0;
    buf[8]=0;buf[9]=0;buf[10]=10;buf[11]=185;
    buf[12]=192;buf[13]=168;buf[14]=1;buf[15]=2;
    ExpectIntEQ(X509_VERIFY_PARAM_set1_ip(param, &buf[0], 16), SSL_SUCCESS);
    ExpectIntEQ(XSTRNCMP(param->ipasc, "2001:db8:1::ab9:c0a8:102",
                                                sizeof(param->ipasc)), 0);

    XFREE(param, HEAP_HINT, DYNAMIC_TYPE_OPENSSL);
#endif /* OPENSSL_EXTRA */
    return EXPECT_RESULT();
}

int test_wolfSSL_X509_VERIFY_PARAM_set1_host(void)
{
    EXPECT_DECLS;
#if defined(OPENSSL_EXTRA)
    const char host[] = "www.example.com";
    WOLFSSL_X509_VERIFY_PARAM* pParam = NULL;

    ExpectNotNull(pParam = (WOLFSSL_X509_VERIFY_PARAM*)XMALLOC(
        sizeof(WOLFSSL_X509_VERIFY_PARAM), HEAP_HINT, DYNAMIC_TYPE_OPENSSL));
    if (pParam != NULL) {
        XMEMSET(pParam, 0, sizeof(WOLFSSL_X509_VERIFY_PARAM));

        ExpectIntEQ(X509_VERIFY_PARAM_set1_host(NULL, host, sizeof(host)),
            WOLFSSL_FAILURE);

        X509_VERIFY_PARAM_set1_host(pParam, host, sizeof(host));

        ExpectIntEQ(XMEMCMP(pParam->hostName, host, sizeof(host)), 0);

        XMEMSET(pParam, 0, sizeof(WOLFSSL_X509_VERIFY_PARAM));

        ExpectIntNE(XMEMCMP(pParam->hostName, host, sizeof(host)), 0);

        XFREE(pParam, HEAP_HINT, DYNAMIC_TYPE_OPENSSL);
    }
#endif /* OPENSSL_EXTRA */
    return EXPECT_RESULT();
}

