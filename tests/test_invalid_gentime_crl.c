/* test_invalid_gentime_crl.c
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
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#if defined(OPENSSL_EXTRA) && defined(HAVE_CRL)

#include <wolfssl/openssl/x509.h>
#include <wolfssl/openssl/bio.h>
#include <wolfssl/openssl/pem.h>

#include <stdio.h>

int test_invalid_gentime_crl(void)
{
    int ret = 0;
    XFILE fp = XBADFILE;
    X509_CRL *crl = NULL;
    const char* crlFile = "../certs/crl/invalid/gentime13.pem";

    printf("Testing CRL with invalid GeneralizedTime length (13 characters)...\n");

    /* Try to load CRL with invalid GeneralizedTime length */
    fp = XFOPEN(crlFile, "rb");
    if (fp == XBADFILE) {
        printf("Failed to open CRL file: %s\n", crlFile);
        ret = -1;
        goto done;
    }

    /* This should fail due to invalid GeneralizedTime length */
    crl = (X509_CRL*)PEM_read_X509_CRL(fp, (X509_CRL**)NULL, NULL, NULL);
    
    /* Expect crl to be NULL due to invalid date format */
    if (crl != NULL) {
        printf("ERROR: Successfully parsed CRL with invalid GeneralizedTime length\n");
        ret = -1;
    } else {
        printf("SUCCESS: CRL with invalid GeneralizedTime length was rejected\n");
    }

    if (fp != XBADFILE) {
        XFCLOSE(fp);
    }

done:
    if (crl != NULL) {
        X509_CRL_free(crl);
    }
    
    return ret;
}

int main(void)
{
    int ret = 0;

    ret = test_invalid_gentime_crl();
    
    if (ret != 0) {
        printf("Test failed with error: %d\n", ret);
        return ret;
    }
    
    printf("All tests passed!\n");
    return 0;
}

#else

int main(void)
{
    printf("Test skipped: OPENSSL_EXTRA and HAVE_CRL required\n");
    return 0;
}

#endif /* OPENSSL_EXTRA && HAVE_CRL */
