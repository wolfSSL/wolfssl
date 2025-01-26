/* ec.h
 *
 * Copyright (C) 2006-2025 wolfSSL Inc.
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

/* ec.h for openssl */

#ifndef WOLFSSL_EC_H_
#define WOLFSSL_EC_H_

#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/openssl/compat_types.h>
#include <wolfssl/openssl/bn.h>
#include <wolfssl/openssl/compat_types.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/ecc.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)

/* Map OpenSSL NID value */
enum {
    WC_POINT_CONVERSION_COMPRESSED = 2,
    WC_POINT_CONVERSION_UNCOMPRESSED = 4,

#ifdef HAVE_ECC
    /* Use OpenSSL NIDs. NIDs can be mapped to ecc_curve_id enum values by
        calling NIDToEccEnum() in ssl.c */
    WC_NID_X9_62_prime192v1 = 409,
    WC_NID_X9_62_prime192v2 = 410,
    WC_NID_X9_62_prime192v3 = 411,
    WC_NID_X9_62_prime239v1 = 412,
    WC_NID_X9_62_prime239v2 = 413,
    WC_NID_X9_62_prime239v3 = 418, /* Previous value conflicted with AES128CBCb */
    WC_NID_X9_62_prime256v1 = 415,
    WC_NID_secp112r1 = 704,
    WC_NID_secp112r2 = 705,
    WC_NID_secp128r1 = 706,
    WC_NID_secp128r2 = 707,
    WC_NID_secp160r1 = 709,
    WC_NID_secp160r2 = 710,
    WC_NID_secp224r1 = 713,
    WC_NID_secp384r1 = 715,
    WC_NID_secp521r1 = 716,
    WC_NID_secp160k1 = 708,
    WC_NID_secp192k1 = 711,
    WC_NID_secp224k1 = 712,
    WC_NID_secp256k1 = 714,
    WC_NID_brainpoolP160r1 = 921,
    WC_NID_brainpoolP192r1 = 923,
    WC_NID_brainpoolP224r1 = 925,
    WC_NID_brainpoolP256r1 = 927,
    WC_NID_brainpoolP320r1 = 929,
    WC_NID_brainpoolP384r1 = 931,
    WC_NID_brainpoolP512r1 = 933,
#endif

#ifdef HAVE_ED448
    WC_NID_ED448 = ED448k,
#endif
#ifdef HAVE_CURVE448
    WC_NID_X448 = X448k,
#endif
#ifdef HAVE_ED25519
    WC_NID_ED25519 = ED25519k,
#endif
#ifdef HAVE_CURVE25519
    WC_NID_X25519 = X25519k,
#endif

    WOLFSSL_EC_EXPLICIT_CURVE  = 0x000,
    WOLFSSL_EC_NAMED_CURVE  = 0x001
};

#ifndef OPENSSL_COEXIST

#define POINT_CONVERSION_COMPRESSED WC_POINT_CONVERSION_COMPRESSED
#define POINT_CONVERSION_UNCOMPRESSED WC_POINT_CONVERSION_UNCOMPRESSED

#ifdef HAVE_ECC
#define NID_X9_62_prime192v1 WC_NID_X9_62_prime192v1
#define NID_X9_62_prime192v2 WC_NID_X9_62_prime192v2
#define NID_X9_62_prime192v3 WC_NID_X9_62_prime192v3
#define NID_X9_62_prime239v1 WC_NID_X9_62_prime239v1
#define NID_X9_62_prime239v2 WC_NID_X9_62_prime239v2
#define NID_X9_62_prime239v3 WC_NID_X9_62_prime239v3
#define NID_X9_62_prime256v1 WC_NID_X9_62_prime256v1
#define NID_secp112r1 WC_NID_secp112r1
#define NID_secp112r2 WC_NID_secp112r2
#define NID_secp128r1 WC_NID_secp128r1
#define NID_secp128r2 WC_NID_secp128r2
#define NID_secp160r1 WC_NID_secp160r1
#define NID_secp160r2 WC_NID_secp160r2
#define NID_secp224r1 WC_NID_secp224r1
#define NID_secp384r1 WC_NID_secp384r1
#define NID_secp521r1 WC_NID_secp521r1
#define NID_secp160k1 WC_NID_secp160k1
#define NID_secp192k1 WC_NID_secp192k1
#define NID_secp224k1 WC_NID_secp224k1
#define NID_secp256k1 WC_NID_secp256k1
#define NID_brainpoolP160r1 WC_NID_brainpoolP160r1
#define NID_brainpoolP192r1 WC_NID_brainpoolP192r1
#define NID_brainpoolP224r1 WC_NID_brainpoolP224r1
#define NID_brainpoolP256r1 WC_NID_brainpoolP256r1
#define NID_brainpoolP320r1 WC_NID_brainpoolP320r1
#define NID_brainpoolP384r1 WC_NID_brainpoolP384r1
#define NID_brainpoolP512r1 WC_NID_brainpoolP512r1
#endif

#ifdef HAVE_ED448
#define NID_ED448 WC_NID_ED448
#endif
#ifdef HAVE_CURVE448
#define NID_X448 WC_NID_X448
#endif
#ifdef HAVE_ED25519
#define NID_ED25519 WC_NID_ED25519
#endif
#ifdef HAVE_CURVE25519
#define NID_X25519 WC_NID_X25519
#endif

#define OPENSSL_EC_EXPLICIT_CURVE WOLFSSL_EC_EXPLICIT_CURVE
#define OPENSSL_EC_NAMED_CURVE WOLFSSL_EC_NAMED_CURVE

#endif /* !OPENSSL_COEXIST */

#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */

#ifndef WOLFSSL_EC_TYPE_DEFINED /* guard on redeclaration */
    typedef struct WOLFSSL_EC_KEY           WOLFSSL_EC_KEY;
    typedef struct WOLFSSL_EC_POINT         WOLFSSL_EC_POINT;
    typedef struct WOLFSSL_EC_GROUP         WOLFSSL_EC_GROUP;
    typedef struct WOLFSSL_EC_BUILTIN_CURVE WOLFSSL_EC_BUILTIN_CURVE;
    /* WOLFSSL_EC_METHOD is just an alias of WOLFSSL_EC_GROUP for now */
    typedef struct WOLFSSL_EC_GROUP         WOLFSSL_EC_METHOD;

    #define WOLFSSL_EC_TYPE_DEFINED
#endif

struct WOLFSSL_EC_POINT {
    WOLFSSL_BIGNUM *X;
    WOLFSSL_BIGNUM *Y;
    WOLFSSL_BIGNUM *Z;

    void*          internal;     /* our ECC point */
    char           inSet;        /* internal set from external ? */
    char           exSet;        /* external set from internal ? */
};

struct WOLFSSL_EC_GROUP {
    int curve_idx; /* index of curve, used by WolfSSL as reference */
    int curve_nid; /* NID of curve, used by OpenSSL/OpenSSH as reference */
    int curve_oid; /* OID of curve, used by OpenSSL/OpenSSH as reference */
};

struct WOLFSSL_EC_KEY {
    WOLFSSL_EC_GROUP *group;
    WOLFSSL_EC_POINT *pub_key;
    WOLFSSL_BIGNUM *priv_key;

    void*          internal;     /* our ECC Key */
    void*          heap;
    unsigned char  form;         /* Either POINT_CONVERSION_UNCOMPRESSED or
                                  * POINT_CONVERSION_COMPRESSED */
    word16 pkcs8HeaderSz;

    /* option bits */
    WC_BITFIELD inSet:1;                /* internal set from external ? */
    WC_BITFIELD exSet:1;                /* external set from internal ? */

    wolfSSL_Ref ref;             /* Reference count information. */
};

struct WOLFSSL_EC_BUILTIN_CURVE {
    int nid;
    const char *comment;
};

#define WOLFSSL_EC_KEY_LOAD_PRIVATE 1
#define WOLFSSL_EC_KEY_LOAD_PUBLIC  2

typedef int wc_point_conversion_form_t;
#ifndef OPENSSL_COEXIST
#define point_conversion_form_t wc_point_conversion_form_t
#endif

typedef struct WOLFSSL_EC_KEY_METHOD {
    /* Not implemented */
    /* Just here so that some C compilers don't complain. To be removed. */
    void* dummy_member;
} WOLFSSL_EC_KEY_METHOD;

WOLFSSL_API
size_t wolfSSL_EC_get_builtin_curves(WOLFSSL_EC_BUILTIN_CURVE *r,size_t nitems);

WOLFSSL_API
WOLFSSL_EC_KEY *wolfSSL_EC_KEY_dup(const WOLFSSL_EC_KEY *src);
WOLFSSL_API
int wolfSSL_EC_KEY_up_ref(WOLFSSL_EC_KEY* key);

WOLFSSL_API
int wolfSSL_ECPoint_i2d(const WOLFSSL_EC_GROUP *curve,
                        const WOLFSSL_EC_POINT *p,
                        unsigned char *out, unsigned int *len);
WOLFSSL_API
int wolfSSL_ECPoint_d2i(const unsigned char *in, unsigned int len,
                        const WOLFSSL_EC_GROUP *curve, WOLFSSL_EC_POINT *p);
WOLFSSL_API
size_t wolfSSL_EC_POINT_point2oct(const WOLFSSL_EC_GROUP *group,
                                  const WOLFSSL_EC_POINT *p,
                                  int form,
                                  byte *buf, size_t len, WOLFSSL_BN_CTX *ctx);
WOLFSSL_API
int wolfSSL_EC_POINT_oct2point(const WOLFSSL_EC_GROUP *group,
                               WOLFSSL_EC_POINT *p, const unsigned char *buf,
                               size_t len, WOLFSSL_BN_CTX *ctx);
WOLFSSL_API
WOLFSSL_EC_KEY *wolfSSL_o2i_ECPublicKey(WOLFSSL_EC_KEY **a, const unsigned char **in,
                                        long len);
WOLFSSL_API
int wolfSSL_i2o_ECPublicKey(const WOLFSSL_EC_KEY *in, unsigned char **out);
WOLFSSL_API
WOLFSSL_EC_KEY *wolfSSL_d2i_ECPrivateKey(WOLFSSL_EC_KEY **key, const unsigned char **in,
                                         long len);
WOLFSSL_API
int wolfSSL_i2d_ECPrivateKey(const WOLFSSL_EC_KEY *in, unsigned char **out);
WOLFSSL_API
void wolfSSL_EC_KEY_set_conv_form(WOLFSSL_EC_KEY *eckey, int form);
WOLFSSL_API
wc_point_conversion_form_t wolfSSL_EC_KEY_get_conv_form(const WOLFSSL_EC_KEY* key);
WOLFSSL_API
WOLFSSL_BIGNUM *wolfSSL_EC_POINT_point2bn(const WOLFSSL_EC_GROUP *group,
                                          const WOLFSSL_EC_POINT *p,
                                          int form,
                                          WOLFSSL_BIGNUM *in, WOLFSSL_BN_CTX *ctx);
WOLFSSL_API
int wolfSSL_EC_POINT_is_on_curve(const WOLFSSL_EC_GROUP *group,
                                 const WOLFSSL_EC_POINT *point,
                                 WOLFSSL_BN_CTX *ctx);

WOLFSSL_API
int wolfSSL_EC_KEY_LoadDer(WOLFSSL_EC_KEY* key,
                           const unsigned char* der, int derSz);
WOLFSSL_API
int wolfSSL_EC_KEY_LoadDer_ex(WOLFSSL_EC_KEY* key,
                              const unsigned char* der, int derSz, int opt);
WOLFSSL_API
WOLFSSL_EC_KEY *wolfSSL_d2i_EC_PUBKEY_bio(WOLFSSL_BIO *bio,
        WOLFSSL_EC_KEY **out);
WOLFSSL_API
void wolfSSL_EC_KEY_free(WOLFSSL_EC_KEY *key);
WOLFSSL_API
WOLFSSL_EC_POINT *wolfSSL_EC_KEY_get0_public_key(const WOLFSSL_EC_KEY *key);
WOLFSSL_API
const WOLFSSL_EC_GROUP *wolfSSL_EC_KEY_get0_group(const WOLFSSL_EC_KEY *key);
WOLFSSL_API
int wolfSSL_EC_KEY_set_private_key(WOLFSSL_EC_KEY *key,
                                   const WOLFSSL_BIGNUM *priv_key);
WOLFSSL_API
WOLFSSL_BIGNUM *wolfSSL_EC_KEY_get0_private_key(const WOLFSSL_EC_KEY *key);
WOLFSSL_API
WOLFSSL_EC_KEY *wolfSSL_EC_KEY_new_by_curve_name(int nid);
WOLFSSL_API const char* wolfSSL_EC_curve_nid2nist(int nid);
WOLFSSL_API int wolfSSL_EC_curve_nist2nid(const char* name);
WOLFSSL_API
WOLFSSL_EC_KEY *wolfSSL_EC_KEY_new_ex(void* heap, int devId);
WOLFSSL_API
WOLFSSL_EC_KEY *wolfSSL_EC_KEY_new(void);
WOLFSSL_API
int wolfSSL_EC_KEY_set_group(WOLFSSL_EC_KEY *key, WOLFSSL_EC_GROUP *group);
WOLFSSL_API
int wolfSSL_EC_KEY_generate_key(WOLFSSL_EC_KEY *key);
WOLFSSL_API
void wolfSSL_EC_KEY_set_asn1_flag(WOLFSSL_EC_KEY *key, int asn1_flag);
WOLFSSL_API
int wolfSSL_EC_KEY_set_public_key(WOLFSSL_EC_KEY *key,
                                  const WOLFSSL_EC_POINT *pub);
WOLFSSL_API int wolfSSL_EC_KEY_check_key(const WOLFSSL_EC_KEY *key);
#if !defined(NO_FILESYSTEM) && !defined(NO_STDIO_FILESYSTEM)
WOLFSSL_API int wolfSSL_EC_KEY_print_fp(XFILE fp, WOLFSSL_EC_KEY* key,
                                         int indent);
#endif /* !NO_FILESYSTEM && !NO_STDIO_FILESYSTEM */
WOLFSSL_API int wolfSSL_ECDSA_size(const WOLFSSL_EC_KEY *key);
WOLFSSL_API int wolfSSL_ECDSA_sign(int type, const unsigned char *digest,
                                   int digestSz, unsigned char *sig,
                                   unsigned int *sigSz, WOLFSSL_EC_KEY *key);
WOLFSSL_API int wolfSSL_ECDSA_verify(int type, const unsigned char *digest,
                                   int digestSz, const unsigned char *sig,
                                   int sigSz, WOLFSSL_EC_KEY *key);


#if defined HAVE_ECC && (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL))
WOLFSSL_API int EccEnumToNID(int n);
#endif

WOLFSSL_API
void wolfSSL_EC_GROUP_set_asn1_flag(WOLFSSL_EC_GROUP *group, int flag);
WOLFSSL_API
WOLFSSL_EC_GROUP *wolfSSL_EC_GROUP_new_by_curve_name(int nid);
WOLFSSL_API
int wolfSSL_EC_GROUP_cmp(const WOLFSSL_EC_GROUP *a, const WOLFSSL_EC_GROUP *b,
                         WOLFSSL_BN_CTX *ctx);
WOLFSSL_API
WOLFSSL_EC_GROUP *wolfSSL_EC_GROUP_dup(const WOLFSSL_EC_GROUP *src);
WOLFSSL_API
int wolfSSL_EC_GROUP_get_curve_name(const WOLFSSL_EC_GROUP *group);
WOLFSSL_API
int wolfSSL_EC_GROUP_get_degree(const WOLFSSL_EC_GROUP *group);
WOLFSSL_API
int wolfSSL_EC_GROUP_get_order(const WOLFSSL_EC_GROUP *group,
                               WOLFSSL_BIGNUM *order, WOLFSSL_BN_CTX *ctx);
WOLFSSL_API
int wolfSSL_EC_GROUP_order_bits(const WOLFSSL_EC_GROUP *group);
WOLFSSL_API
void wolfSSL_EC_GROUP_free(WOLFSSL_EC_GROUP *group);
WOLFSSL_API
const WOLFSSL_EC_METHOD* wolfSSL_EC_GROUP_method_of(
                                                const WOLFSSL_EC_GROUP *group);
WOLFSSL_API
int wolfSSL_EC_METHOD_get_field_type(const WOLFSSL_EC_METHOD *meth);
WOLFSSL_API
WOLFSSL_EC_POINT *wolfSSL_EC_POINT_new(const WOLFSSL_EC_GROUP *group);
WOLFSSL_LOCAL
int ec_point_convert_to_affine(const WOLFSSL_EC_GROUP *group,
    WOLFSSL_EC_POINT *point);
WOLFSSL_API
int wolfSSL_EC_POINT_get_affine_coordinates_GFp(const WOLFSSL_EC_GROUP *group,
                                                const WOLFSSL_EC_POINT *p,
                                                WOLFSSL_BIGNUM *x,
                                                WOLFSSL_BIGNUM *y,
                                                WOLFSSL_BN_CTX *ctx);
WOLFSSL_API
int wolfSSL_EC_POINT_set_affine_coordinates_GFp(const WOLFSSL_EC_GROUP *group,
                                                WOLFSSL_EC_POINT *point,
                                                const WOLFSSL_BIGNUM *x,
                                                const WOLFSSL_BIGNUM *y,
                                                WOLFSSL_BN_CTX *ctx);
WOLFSSL_API
int wolfSSL_EC_POINT_add(const WOLFSSL_EC_GROUP *group, WOLFSSL_EC_POINT *r,
                         const WOLFSSL_EC_POINT *p1,
                         const WOLFSSL_EC_POINT *p2, WOLFSSL_BN_CTX *ctx);
WOLFSSL_API
int wolfSSL_EC_POINT_mul(const WOLFSSL_EC_GROUP *group, WOLFSSL_EC_POINT *r,
                         const WOLFSSL_BIGNUM *n,
                         const WOLFSSL_EC_POINT *q, const WOLFSSL_BIGNUM *m,
                         WOLFSSL_BN_CTX *ctx);
WOLFSSL_API
int wolfSSL_EC_POINT_invert(const WOLFSSL_EC_GROUP *group, WOLFSSL_EC_POINT *a,
                            WOLFSSL_BN_CTX *ctx);
WOLFSSL_API
void wolfSSL_EC_POINT_clear_free(WOLFSSL_EC_POINT *point);
WOLFSSL_API
int wolfSSL_EC_POINT_cmp(const WOLFSSL_EC_GROUP *group,
                         const WOLFSSL_EC_POINT *a, const WOLFSSL_EC_POINT *b,
                         WOLFSSL_BN_CTX *ctx);
WOLFSSL_API int wolfSSL_EC_POINT_copy(WOLFSSL_EC_POINT *dest,
                                      const WOLFSSL_EC_POINT *src);
WOLFSSL_API
void wolfSSL_EC_POINT_free(WOLFSSL_EC_POINT *point);
WOLFSSL_API
int wolfSSL_EC_POINT_is_at_infinity(const WOLFSSL_EC_GROUP *group,
                                    const WOLFSSL_EC_POINT *a);

WOLFSSL_API
char* wolfSSL_EC_POINT_point2hex(const WOLFSSL_EC_GROUP* group,
                                 const WOLFSSL_EC_POINT* point, int form,
                                 WOLFSSL_BN_CTX* ctx);
WOLFSSL_API
WOLFSSL_EC_POINT *wolfSSL_EC_POINT_hex2point
                                (const WOLFSSL_EC_GROUP *group, const char *hex,
                                    WOLFSSL_EC_POINT *p, WOLFSSL_BN_CTX *ctx);

WOLFSSL_API const WOLFSSL_EC_KEY_METHOD *wolfSSL_EC_KEY_OpenSSL(void);
WOLFSSL_API WOLFSSL_EC_KEY_METHOD *wolfSSL_EC_KEY_METHOD_new(
        const WOLFSSL_EC_KEY_METHOD *meth);
WOLFSSL_API void wolfSSL_EC_KEY_METHOD_free(WOLFSSL_EC_KEY_METHOD *meth);
/* TODO when implementing change the types to the real callback signatures
 * and use real parameter names */
WOLFSSL_API void wolfSSL_EC_KEY_METHOD_set_init(WOLFSSL_EC_KEY_METHOD *meth,
        void* a1, void* a2, void* a3, void* a4, void* a5, void* a6);
WOLFSSL_API void wolfSSL_EC_KEY_METHOD_set_sign(WOLFSSL_EC_KEY_METHOD *meth,
        void* a1, void* a2, void* a3);
WOLFSSL_API const WOLFSSL_EC_KEY_METHOD *wolfSSL_EC_KEY_get_method(
        const WOLFSSL_EC_KEY *key);
WOLFSSL_API int wolfSSL_EC_KEY_set_method(WOLFSSL_EC_KEY *key,
        const WOLFSSL_EC_KEY_METHOD *meth);

#if !defined(OPENSSL_COEXIST) && (defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL))

typedef WOLFSSL_EC_KEY                EC_KEY;
typedef WOLFSSL_EC_GROUP              EC_GROUP;
typedef WOLFSSL_EC_GROUP              EC_METHOD;
typedef WOLFSSL_EC_POINT              EC_POINT;
typedef WOLFSSL_EC_BUILTIN_CURVE      EC_builtin_curve;
typedef WOLFSSL_EC_KEY_METHOD         EC_KEY_METHOD;

#ifndef HAVE_ECC
#define OPENSSL_NO_EC
#endif

#define EC_KEY_new                      wolfSSL_EC_KEY_new
#define EC_KEY_free                     wolfSSL_EC_KEY_free
#define EC_KEY_up_ref                   wolfSSL_EC_KEY_up_ref
#define EC_KEY_dup                      wolfSSL_EC_KEY_dup
#define EC_KEY_get0_public_key          wolfSSL_EC_KEY_get0_public_key
#define EC_KEY_get0_group               wolfSSL_EC_KEY_get0_group
#define EC_KEY_set_private_key          wolfSSL_EC_KEY_set_private_key
#define EC_KEY_get0_private_key         wolfSSL_EC_KEY_get0_private_key
#define EC_KEY_new_by_curve_name        wolfSSL_EC_KEY_new_by_curve_name
#define EC_KEY_set_group                wolfSSL_EC_KEY_set_group
#define EC_KEY_generate_key             wolfSSL_EC_KEY_generate_key
#define EC_KEY_set_asn1_flag            wolfSSL_EC_KEY_set_asn1_flag
#define EC_KEY_set_public_key           wolfSSL_EC_KEY_set_public_key
#define EC_KEY_check_key                wolfSSL_EC_KEY_check_key
#define EC_KEY_print_fp                 wolfSSL_EC_KEY_print_fp

#define d2i_EC_PUBKEY_bio               wolfSSL_d2i_EC_PUBKEY_bio

#define ECDSA_size                      wolfSSL_ECDSA_size
#define ECDSA_sign                      wolfSSL_ECDSA_sign
#define ECDSA_verify                    wolfSSL_ECDSA_verify

#define EC_GROUP_free                   wolfSSL_EC_GROUP_free
#define EC_GROUP_set_asn1_flag          wolfSSL_EC_GROUP_set_asn1_flag
#define EC_GROUP_new_by_curve_name      wolfSSL_EC_GROUP_new_by_curve_name
#define EC_GROUP_cmp                    wolfSSL_EC_GROUP_cmp
#define EC_GROUP_dup                    wolfSSL_EC_GROUP_dup
#define EC_GROUP_get_curve_name         wolfSSL_EC_GROUP_get_curve_name
#define EC_GROUP_get_degree             wolfSSL_EC_GROUP_get_degree
#define EC_GROUP_get_order              wolfSSL_EC_GROUP_get_order
#define EC_GROUP_order_bits             wolfSSL_EC_GROUP_order_bits
#define EC_GROUP_method_of              wolfSSL_EC_GROUP_method_of
#ifndef NO_WOLFSSL_STUB
#ifdef WOLF_NO_VARIADIC_MACROS
    #define EC_GROUP_set_point_conversion_form() WC_DO_NOTHING
#else
    #define EC_GROUP_set_point_conversion_form(...) WC_DO_NOTHING
#endif
#endif

#define EC_METHOD_get_field_type        wolfSSL_EC_METHOD_get_field_type

#define EC_POINT_new                    wolfSSL_EC_POINT_new
#define EC_POINT_free                   wolfSSL_EC_POINT_free
#define EC_POINT_get_affine_coordinates_GFp \
                                     wolfSSL_EC_POINT_get_affine_coordinates_GFp
#define EC_POINT_get_affine_coordinates \
                                     wolfSSL_EC_POINT_get_affine_coordinates_GFp
#define EC_POINT_set_affine_coordinates_GFp \
                                     wolfSSL_EC_POINT_set_affine_coordinates_GFp
#define EC_POINT_set_affine_coordinates \
                                     wolfSSL_EC_POINT_set_affine_coordinates_GFp
#define EC_POINT_add                    wolfSSL_EC_POINT_add
#define EC_POINT_mul                    wolfSSL_EC_POINT_mul
#define EC_POINT_invert                 wolfSSL_EC_POINT_invert
#define EC_POINT_clear_free             wolfSSL_EC_POINT_clear_free
#define EC_POINT_cmp                    wolfSSL_EC_POINT_cmp
#define EC_POINT_copy                   wolfSSL_EC_POINT_copy
#define EC_POINT_is_at_infinity         wolfSSL_EC_POINT_is_at_infinity

#define EC_get_builtin_curves           wolfSSL_EC_get_builtin_curves

#define ECPoint_i2d                     wolfSSL_ECPoint_i2d
#define ECPoint_d2i                     wolfSSL_ECPoint_d2i
#define EC_POINT_point2oct              wolfSSL_EC_POINT_point2oct
#define EC_POINT_oct2point              wolfSSL_EC_POINT_oct2point
#define EC_POINT_point2bn               wolfSSL_EC_POINT_point2bn
#define EC_POINT_is_on_curve            wolfSSL_EC_POINT_is_on_curve
#define o2i_ECPublicKey                 wolfSSL_o2i_ECPublicKey
#define i2o_ECPublicKey                 wolfSSL_i2o_ECPublicKey
#define i2d_EC_PUBKEY                   wolfSSL_i2o_ECPublicKey
#define d2i_ECPrivateKey                wolfSSL_d2i_ECPrivateKey
#define i2d_ECPrivateKey                wolfSSL_i2d_ECPrivateKey
#define EC_KEY_set_conv_form            wolfSSL_EC_KEY_set_conv_form
#define EC_KEY_get_conv_form            wolfSSL_EC_KEY_get_conv_form
#define d2i_ECPKParameters              wolfSSL_d2i_ECPKParameters
#define i2d_ECPKParameters              wolfSSL_i2d_ECPKParameters

#define EC_POINT_point2hex              wolfSSL_EC_POINT_point2hex
#define EC_POINT_hex2point              wolfSSL_EC_POINT_hex2point

#define EC_POINT_dump                   wolfSSL_EC_POINT_dump
#define EC_get_builtin_curves           wolfSSL_EC_get_builtin_curves

#define EC_curve_nid2nist               wolfSSL_EC_curve_nid2nist
#define EC_curve_nist2nid               wolfSSL_EC_curve_nist2nid

#define EC_KEY_OpenSSL                  wolfSSL_EC_KEY_OpenSSL
#define EC_KEY_METHOD_new               wolfSSL_EC_KEY_METHOD_new
#define EC_KEY_METHOD_free              wolfSSL_EC_KEY_METHOD_free
#define EC_KEY_METHOD_set_init          wolfSSL_EC_KEY_METHOD_set_init
#define EC_KEY_METHOD_set_sign          wolfSSL_EC_KEY_METHOD_set_sign
#define EC_KEY_get_method               wolfSSL_EC_KEY_get_method
#define EC_KEY_set_method               wolfSSL_EC_KEY_set_method

#endif /* !OPENSSL_COEXIST && (OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL) */

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif /* header */
