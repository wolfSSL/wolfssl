/* kcapi_ecc.c
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
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

#if defined(WOLFSSL_KCAPI_ECC) && defined(HAVE_ECC)

#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/port/kcapi/wc_kcapi.h>
#include <wolfssl/wolfcrypt/port/kcapi/kcapi_ecc.h>
#include <wolfssl/wolfcrypt/ecc.h>

#ifndef ECC_CURVE_NIST_P256
#define ECC_CURVE_NIST_P256     2
#endif
#ifndef ECC_CURVE_NIST_P384
#define ECC_CURVE_NIST_P384     3
#endif
#ifndef ECC_CURVE_NIST_P521
#define ECC_CURVE_NIST_P521     4
#endif

#define ECDSA_KEY_VERSION       1
#define ECDH_KEY_VERSION        1

static const char WC_NAME_ECDH[] = "ecdh";
#if defined(HAVE_ECC_SIGN) || defined(HAVE_ECC_VERIFY)
static const char WC_NAME_ECDSA[] = "ecdsa";
#endif

void KcapiEcc_Free(ecc_key* key)
{
    if (key->handle != NULL) {
        kcapi_kpp_destroy(key->handle);
        key->handle = NULL;
    }
}

static int KcapiEcc_CurveId(int curve_id, word32* kcapiCurveId)
{
    int ret = 0;

     switch (curve_id) {
         case ECC_SECP256R1:
             *kcapiCurveId = ECC_CURVE_NIST_P256;
             break;
         case ECC_SECP384R1:
             *kcapiCurveId = ECC_CURVE_NIST_P384;
             break;
         case ECC_SECP521R1:
             *kcapiCurveId = ECC_CURVE_NIST_P521;
             break;
         default:
             ret = BAD_FUNC_ARG;
             break;
     }

     return ret;
}

int KcapiEcc_LoadKey(ecc_key* key, byte* pubkey_raw, word32* pubkey_sz)
{
    int ret = 0;
    word32 kcapiCurveId = 0;

    if (key == NULL || key->dp == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        ret = KcapiEcc_CurveId(key->dp->id, &kcapiCurveId);
    }

    /* if handle doesn't exist create one */
    if (ret == 0 && key->handle == NULL) {
        ret = kcapi_kpp_init(&key->handle, WC_NAME_ECDH, 0);
        if (ret == 0) {
            ret = kcapi_kpp_ecdh_setcurve(key->handle, kcapiCurveId);
            if (ret >= 0) {
                ret = 0;
            }
        }
    }

    /* if a private key value is set, load and use it.
     * otherwise use existing key->handle */
    if (ret == 0 && mp_iszero(&key->k) != MP_YES) {
        byte priv[MAX_ECC_BYTES];
        word32 keySz = key->dp->size;
        ret = wc_export_int(&key->k, priv, &keySz, keySz, WC_TYPE_UNSIGNED_BIN);
        if (ret == 0) {
            ret = kcapi_kpp_setkey(key->handle, priv, keySz);
            if (ret >= 0) {
                ret = 0;
            }
        }
    }

    /* optionally load public key */
    if (ret == 0 && pubkey_raw != NULL && pubkey_sz != NULL) {
        ret = (int)kcapi_kpp_keygen(key->handle, pubkey_raw, *pubkey_sz,
            KCAPI_ACCESS_HEURISTIC);
        if (ret >= 0) {
            *pubkey_sz = ret;
            ret = 0;
        }
    }

    return ret;    
}

int KcapiEcc_MakeKey(ecc_key* key, int keysize, int curve_id)
{
    int ret = 0;
    word32 pubkey_sz = (word32)sizeof(key->pubkey_raw);

    /* free existing handle */
    if (key != NULL && key->handle != NULL) {
        kcapi_kpp_destroy(key->handle);
        key->handle = NULL;
    }

    /* check arguments */
    if (key == NULL || key->dp == NULL) {
        ret = BAD_FUNC_ARG;
    }

    ret = KcapiEcc_LoadKey(key, key->pubkey_raw, &pubkey_sz);
    if (ret == 0) {
        ret = mp_read_unsigned_bin(key->pubkey.x,
            key->pubkey_raw, pubkey_sz / 2);
    }
    if (ret == 0) {
        ret = mp_read_unsigned_bin(key->pubkey.y,
            key->pubkey_raw + pubkey_sz / 2, pubkey_sz / 2);
    }
    if (ret == 0) {
        key->type = ECC_PRIVATEKEY;
    }

    /* if error release handle now */
    if (ret != 0 && key->handle != NULL) {
        kcapi_kpp_destroy(key->handle);
        key->handle = NULL;
    }

    /* These are not used. The key->dp is set */
    (void)keysize;
    (void)curve_id;

    return ret;
}

#ifdef HAVE_ECC_DHE
int KcapiEcc_SharedSecret(ecc_key* private_key, ecc_key* public_key, byte* out,
                          word32* outlen)
{
    int ret;
    word32 kcapiCurveId = 0;
    byte* buf_aligned = NULL;
    byte* pub_aligned = NULL;
    byte* out_aligned = NULL;
    size_t pageSz = (size_t)sysconf(_SC_PAGESIZE);
    byte* pub = public_key->pubkey_raw;

    ret = KcapiEcc_CurveId(private_key->dp->id, &kcapiCurveId);
    if (ret == 0 && private_key->handle == NULL) {
        ret = kcapi_kpp_init(&private_key->handle, WC_NAME_ECDH, 0);
        if (ret == 0) {
            ret = kcapi_kpp_ecdh_setcurve(private_key->handle, kcapiCurveId);
            if (ret >= 0) {
                ret = 0;
            }
        }
    }

    /* if a private key value is set, load and use it */
    if (ret == 0 && mp_iszero(&private_key->k) != MP_YES) {
        byte priv[MAX_ECC_BYTES];
        word32 keySz = private_key->dp->size;
        ret = wc_export_int(&private_key->k, priv, &keySz, keySz,
                            WC_TYPE_UNSIGNED_BIN);
        if (ret == 0) {
            ret = kcapi_kpp_setkey(private_key->handle, priv, keySz);
            if (ret >= 0) {
                ret = 0;
            }
        }
    }
    if (ret == 0) {
        /* setup aligned pointers */
        if (((size_t)pub % pageSz != 0) ||
            ((size_t)out % pageSz != 0)) {
            ret = posix_memalign((void*)&buf_aligned, pageSz, pageSz * 2);
            if (ret < 0) {
                ret = MEMORY_E;
            }
        }
    }
    if (ret == 0) {
        out_aligned = ((size_t)out % pageSz == 0) ? out : buf_aligned;
        if ((size_t)pub % pageSz == 0) {
            pub_aligned = (byte*)pub;
        }
        else {
            pub_aligned = buf_aligned + pageSz;
            XMEMCPY(pub_aligned, pub, public_key->dp->size * 2);
        }

        ret = (int)kcapi_kpp_ssgen(private_key->handle, pub_aligned,
                                   public_key->dp->size * 2, out_aligned,
                                   *outlen, KCAPI_ACCESS_HEURISTIC);
        if (ret >= 0) {
            *outlen = ret/2;
            if (out_aligned != out) {
                XMEMCPY(out, out_aligned, ret);
            }
            ret = 0;
        }
    }

    /* Using free as this is in an environment that will have it
     * available along with posix_memalign. */
    if (buf_aligned != NULL) {
        free(buf_aligned);
    }

    return ret;
}
#endif

#ifdef HAVE_ECC_SIGN
static int KcapiEcc_SetPrivKey(ecc_key* key)
{
    int ret;
    byte priv[KCAPI_PARAM_SZ + MAX_ECC_BYTES];
    word32 keySz = key->dp->size;
    word32 kcapiCurveId;

    ret = KcapiEcc_CurveId(key->dp->id, &kcapiCurveId);
    if (ret == 0) {
        priv[0] = ECDSA_KEY_VERSION;
        priv[1] = kcapiCurveId;
        ret = wc_export_int(&key->k, priv + 2, &keySz, keySz,
                            WC_TYPE_UNSIGNED_BIN);
    }
    if (ret == 0) {
        ret = kcapi_akcipher_setkey(key->handle, priv, KCAPI_PARAM_SZ + keySz);
        if (ret >= 0) {
            ret = 0;
        }
    }

    return ret;
}

int KcapiEcc_Sign(ecc_key* key, const byte* hash, word32 hashLen, byte* sig,
                  word32* sigLen)
{
    int ret = 0;
    byte* buf_aligned = NULL;
    byte* hash_aligned = NULL;
    byte* sig_aligned = NULL;
    size_t pageSz = (size_t)sysconf(_SC_PAGESIZE);
    int handleInit = 0;

    if (key->handle == NULL) {
        ret = kcapi_akcipher_init(&key->handle, WC_NAME_ECDSA, 0);
        if (ret != 0) {
            WOLFSSL_MSG("KcapiEcc_Sign: Failed to initialize");
        }
        if (ret == 0) {
            handleInit = 1;
            ret = KcapiEcc_SetPrivKey(key);
        }
    }
    if (ret == 0) {
        if (((size_t)sig % pageSz != 0) || ((size_t)hash % pageSz != 0)) {
            ret = posix_memalign((void*)&buf_aligned, pageSz, pageSz * 2);
            if (ret < 0) {
                ret = MEMORY_E;
            }
        }
    }
    if (ret == 0) {
        sig_aligned = ((size_t)sig % pageSz == 0) ? sig : buf_aligned;
        if ((size_t)hash % pageSz == 0) {
            hash_aligned = (byte*)hash;
        }
        else {
            hash_aligned = buf_aligned + pageSz;
            XMEMCPY(hash_aligned, hash, hashLen);
        }
        ret = (int)kcapi_akcipher_sign(key->handle, hash_aligned, hashLen,
            sig_aligned, *sigLen, KCAPI_ACCESS_HEURISTIC);
        if (ret >= 0) {
            *sigLen = ret;
            ret = 0;
            if (sig_aligned != sig) {
                XMEMCPY(sig, sig_aligned, ret);
            }
        }
    }
    /* Using free as this is in an environment that will have it
     * available along with posix_memalign. */
    if (buf_aligned != NULL) {
        free(buf_aligned);
    }

    if (handleInit) {
        kcapi_kpp_destroy(key->handle);
        key->handle = NULL;
    }

    return ret;
}
#endif


#ifdef HAVE_ECC_VERIFY
int KcapiEcc_SetPubKey(ecc_key* key)
{
    int ret;
    int len = KCAPI_PARAM_SZ + key->dp->size * 2;
    word32 kcapiCurveId;

    ret = KcapiEcc_CurveId(key->dp->id, &kcapiCurveId);
    if (ret == 0) {
        key->pubkey_raw[0] = ECDSA_KEY_VERSION;
        key->pubkey_raw[1] = kcapiCurveId;

        ret = kcapi_akcipher_setpubkey(key->handle, key->pubkey_raw, len);
        if (ret >= 0) {
            ret = 0;
        }
    }

    return ret;
}

int KcapiEcc_Verify(ecc_key* key, const byte* hash, word32 hashLen, byte* sig,
                    word32 sigLen)
{
    int ret = 0;
    byte* sigHash_aligned = NULL;
    size_t pageSz = (size_t)sysconf(_SC_PAGESIZE);
    int handleInit = 0;

    if (key->handle == NULL) {
        ret = kcapi_akcipher_init(&key->handle, WC_NAME_ECDSA, 0);
        if (ret != 0) {
            WOLFSSL_MSG("KcapiEcc_Verify: Failed to initialize");
        }
        if (ret == 0) {
            handleInit = 1;
            ret = KcapiEcc_SetPubKey(key);
        }
    }
    if (ret == 0) {
        ret = posix_memalign((void*)&sigHash_aligned, pageSz, sigLen + hashLen);
        if (ret < 0) {
            ret = MEMORY_E;
        }
    }
    if (ret == 0) {
        XMEMCPY(sigHash_aligned, sig, sigLen);
        XMEMCPY(sigHash_aligned + sigLen, hash, hashLen);

        ret = (int)kcapi_akcipher_verify(key->handle, sigHash_aligned,
                sigLen + hashLen, NULL, hashLen, KCAPI_ACCESS_HEURISTIC);
        if (ret >= 0) {
            ret = 0;
        }
    }

    /* Using free as this is in an environment that will have it
     * available along with posix_memalign. */
    if (sigHash_aligned != NULL) {
        free(sigHash_aligned);
    }
    
    if (handleInit) {
        kcapi_kpp_destroy(key->handle);
        key->handle = NULL;
    }
    return ret;
}
#endif

#endif /* WOLFSSL_KCAPI_ECC && HAVE_ECC */
