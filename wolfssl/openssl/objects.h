/* objects.h
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


#ifndef WOLFSSL_OBJECTS_H_
#define WOLFSSL_OBJECTS_H_

#include <wolfssl/wolfcrypt/types.h>
#ifndef OPENSSL_EXTRA_SSL_GUARD
#define OPENSSL_EXTRA_SSL_GUARD
#include <wolfssl/ssl.h>
#endif /* OPENSSL_EXTRA_SSL_GUARD */

#include <wolfssl/openssl/obj_mac.h>

#ifdef __cplusplus
    extern "C" {
#endif

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)

#define WC_NID_ad_OCSP                     178
#define WC_NID_ad_ca_issuers               179

#ifndef OPENSSL_COEXIST

#define OBJ_NAME_TYPE_UNDEF     WOLFSSL_OBJ_NAME_TYPE_UNDEF
#define OBJ_NAME_TYPE_MD_METH   WOLFSSL_OBJ_NAME_TYPE_MD_METH
#define OBJ_NAME_TYPE_CIPHER_METH   WOLFSSL_OBJ_NAME_TYPE_CIPHER_METH
#define OBJ_NAME_TYPE_PKEY_METH     WOLFSSL_OBJ_NAME_TYPE_PKEY_METH
#define OBJ_NAME_TYPE_COMP_METH     WOLFSSL_OBJ_NAME_TYPE_COMP_METH
#define OBJ_NAME_TYPE_NUM           WOLFSSL_OBJ_NAME_TYPE_NUM
#define OBJ_NAME_ALIAS              WOLFSSL_OBJ_NAME_ALIAS

#define OBJ_nid2sn       wolfSSL_OBJ_nid2sn
#define OBJ_obj2nid      wolfSSL_OBJ_obj2nid
#define OBJ_sn2nid       wolfSSL_OBJ_sn2nid
#define OBJ_length       wolfSSL_OBJ_length
#define OBJ_get0_data    wolfSSL_OBJ_get0_data
#define OBJ_nid2ln       wolfSSL_OBJ_nid2ln
#define OBJ_ln2nid       wolfSSL_OBJ_ln2nid
#define OBJ_txt2nid      wolfSSL_OBJ_txt2nid
#define OBJ_txt2obj      wolfSSL_OBJ_txt2obj
#define OBJ_nid2obj      wolfSSL_OBJ_nid2obj
#define OBJ_obj2txt      wolfSSL_OBJ_obj2txt
#define OBJ_cleanup      wolfSSL_OBJ_cleanup
#define OBJ_cmp          wolfSSL_OBJ_cmp
#define OBJ_create       wolfSSL_OBJ_create
#define ASN1_OBJECT_free wolfSSL_ASN1_OBJECT_free
#define OBJ_NAME_do_all  wolfSSL_OBJ_NAME_do_all
#define i2t_ASN1_OBJECT  wolfSSL_i2t_ASN1_OBJECT

/* not required for wolfSSL */
#define OPENSSL_load_builtin_modules() WC_DO_NOTHING

#define NID_ad_OCSP WC_NID_ad_OCSP
#define NID_ad_ca_issuers WC_NID_ad_ca_issuers

/* OBJ_find_sigid_algs(): map a certificate signature-algorithm NID to its
 * digest and public-key NIDs; returns 0 for unsupported algorithms. */
#ifndef BUILDING_WOLFSSL
static WC_INLINE int
wolfSSL_OBJ_find_sigid_algs(int sigid, int *pdig, int *ppkey)
{
    int dig  = 0;
    int pkey = 0;
    int ret  = 1;

    switch (sigid) {
#ifndef NO_RSA
        case WC_NID_sha1WithRSAEncryption:
            dig = WC_NID_sha1;   pkey = WC_NID_rsaEncryption; break;
        case WC_NID_sha224WithRSAEncryption:
            dig = WC_NID_sha224; pkey = WC_NID_rsaEncryption; break;
        case WC_NID_sha256WithRSAEncryption:
            dig = WC_NID_sha256; pkey = WC_NID_rsaEncryption; break;
        case WC_NID_sha384WithRSAEncryption:
            dig = WC_NID_sha384; pkey = WC_NID_rsaEncryption; break;
        case WC_NID_sha512WithRSAEncryption:
            dig = WC_NID_sha512; pkey = WC_NID_rsaEncryption; break;
#endif /* !NO_RSA */
#ifdef HAVE_ECC
        case WC_NID_ecdsa_with_SHA1:
            dig = WC_NID_sha1;   pkey = WC_NID_X9_62_id_ecPublicKey; break;
        case WC_NID_ecdsa_with_SHA224:
            dig = WC_NID_sha224; pkey = WC_NID_X9_62_id_ecPublicKey; break;
        case WC_NID_ecdsa_with_SHA256:
            dig = WC_NID_sha256; pkey = WC_NID_X9_62_id_ecPublicKey; break;
        case WC_NID_ecdsa_with_SHA384:
            dig = WC_NID_sha384; pkey = WC_NID_X9_62_id_ecPublicKey; break;
        case WC_NID_ecdsa_with_SHA512:
            dig = WC_NID_sha512; pkey = WC_NID_X9_62_id_ecPublicKey; break;
#endif /* HAVE_ECC */
        default:
            ret = 0; break;
    }

    if (ret == 1) {
        if (pdig  != NULL) *pdig  = dig;
        if (ppkey != NULL) *ppkey = pkey;
    }
    return ret;
}
#endif

#endif /* !OPENSSL_COEXIST */

#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */


#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* WOLFSSL_OBJECTS_H_ */
