/* test_x509.c
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

#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_x509.h>
#include <tests/utils.h>
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/openssl/x509.h>
#include <wolfssl/openssl/x509v3.h>

#if defined(OPENSSL_ALL) && \
    defined(HAVE_MANUAL_MEMIO_TESTS_DEPENDENCIES)
#define HAVE_TEST_X509_RFC2818_VERIFICATION_CALLBACK
/* callback taken and simplified from
 * include/boost/asio/ssl/impl/rfc2818_verification.ipp
 * version: boost-1.84.0 */
static int rfc2818_verification_callback(int preverify,
        WOLFSSL_X509_STORE_CTX* store)
{
    EXPECT_DECLS;
    int depth;
    X509* cert;
    GENERAL_NAMES* gens;
    byte address_bytes[] = { 127, 0, 0, 1 };
    X509_NAME* name;
    int i;
    ASN1_STRING* common_name = 0;
    int matches = 0;

    /* Don't bother looking at certificates that have
     * failed pre-verification. */
    if (!preverify)
        return 0;

    /* We're only interested in checking the certificate at
     * the end of the chain. */
    depth = X509_STORE_CTX_get_error_depth(store);
    if (depth > 0)
        return 1;

    /* Try converting the host name to an address. If it is an address then we
     * need to look for an IP address in the certificate rather than a
     * host name. */

    cert = X509_STORE_CTX_get_current_cert(store);

    /* Go through the alternate names in the certificate looking for matching
     * DNS or IP address entries. */
    gens = (GENERAL_NAMES*)X509_get_ext_d2i(
            cert, NID_subject_alt_name, NULL, NULL);
    for (i = 0; i < sk_GENERAL_NAME_num(gens); ++i) {
        GENERAL_NAME* gen = sk_GENERAL_NAME_value(gens, i);
        if (gen->type == GEN_DNS) {
            ASN1_IA5STRING* domain = gen->d.dNSName;
            if (domain->type == V_ASN1_IA5STRING && domain->data &&
                    domain->length &&
                    XSTRCMP(domain->data, "example.com") == 0)
                matches++;
        }
        else if (gen->type == GEN_IPADD)
        {
            ASN1_OCTET_STRING* ip_address = gen->d.iPAddress;
            if (ip_address->type == V_ASN1_OCTET_STRING && ip_address->data &&
                    ip_address->length == sizeof(address_bytes) &&
                    XMEMCMP(address_bytes, ip_address->data, 4) == 0)
                matches++;
        }
    }
    GENERAL_NAMES_free(gens);

    /* No match in the alternate names, so try the common names. We should only
     * use the "most specific" common name, which is the last one in
     * the list. */
    name = X509_get_subject_name(cert);
    i = -1;
    while ((i = X509_NAME_get_index_by_NID(name, NID_commonName, i)) >= 0)
    {
        X509_NAME_ENTRY* name_entry = X509_NAME_get_entry(name, i);
        common_name = X509_NAME_ENTRY_get_data(name_entry);
    }
    if (common_name && common_name->data && common_name->length)
    {
        if (XSTRCMP(common_name->data, "www.wolfssl.com") == 0)
            matches++;
    }

    ExpectIntEQ(matches, 3);
    return matches == 3;
}
#endif

int test_x509_rfc2818_verification_callback(void)
{
    EXPECT_DECLS;
#ifdef HAVE_TEST_X509_RFC2818_VERIFICATION_CALLBACK
    struct test_memio_ctx test_ctx;
    WOLFSSL_CTX *ctx_c = NULL, *ctx_s = NULL;
    WOLFSSL *ssl_c = NULL, *ssl_s = NULL;

    XMEMSET(&test_ctx, 0, sizeof(test_ctx));

    ExpectIntEQ(test_memio_setup(&test_ctx, &ctx_c, &ctx_s, &ssl_c, &ssl_s,
            wolfTLS_client_method, wolfTLS_server_method), 0);

    ExpectIntEQ(wolfSSL_use_certificate_file(ssl_c, cliCertFile,
            WOLFSSL_FILETYPE_PEM), 1);
    ExpectIntEQ(wolfSSL_use_PrivateKey_file(ssl_c, cliKeyFile,
            WOLFSSL_FILETYPE_PEM), 1);

    ExpectIntEQ(wolfSSL_CTX_load_verify_locations(ctx_s, cliCertFile, NULL), 1);
    wolfSSL_set_verify(ssl_s, WOLFSSL_VERIFY_PEER,
            rfc2818_verification_callback);

    ExpectIntEQ(test_memio_do_handshake(ssl_c, ssl_s, 10, NULL), 0);

    wolfSSL_free(ssl_s);
    wolfSSL_free(ssl_c);
    wolfSSL_CTX_free(ctx_s);
    wolfSSL_CTX_free(ctx_c);
#endif
    return EXPECT_RESULT();
}
