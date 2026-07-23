/* vaultic.c
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

/* WISeKey/SealSQ VaultIC secure element port. Offloads TLS ECC P-256
 * operations (sign / verify / keygen / ECDH shared secret) to the VaultIC via
 * wolfSSL's PK callbacks, and loads the device + CA certificates stored on the
 * chip into a WOLFSSL_CTX. Requires the external SealSQ VaultIC-TLS SDK
 * (vaultic_tls.h and the vlt_tls_* P256 API) on the include/link path. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_VAULTIC

#if !defined(HAVE_PK_CALLBACKS) && !defined(WOLF_CRYPTO_CB)
#error WOLFSSL_VAULTIC requires HAVE_PK_CALLBACKS or WOLF_CRYPTO_CB
#endif

#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/port/sealsq/vaultic.h>
#ifdef WOLF_CRYPTO_CB
    #include <wolfssl/wolfcrypt/cryptocb.h>
#endif

#include "vaultic_tls.h"   /* vendor VaultIC-TLS SDK (external) */

#define P256_BYTE_SZ 32

/* Verify a P-256 ECDSA signature on the VaultIC. Shared by the PK verify
 * callback and the crypto callback. Sets *result=1 and returns 0 on a valid
 * signature; returns WC_HW_E if the device rejects it; returns other wolfCrypt
 * errors on encode/decode failure.
 *
 * Note: the vendor vlt_tls_verify_signature_P256() reports both an invalid
 * signature and a device/comms error the same way, so unlike the software
 * wc_ecc_verify_hash() (which returns 0 with *result=0 for a merely invalid
 * signature) this maps a device rejection to WC_HW_E. All intended callers
 * (the TLS PK verify path and the WC_PK_TYPE_ECDSA_VERIFY crypto callback)
 * treat any non-zero return as verification failure, so the security outcome
 * is correct. */
static int vaultic_p256_verify(ecc_key* key, const byte* hash, word32 hashSz,
    const byte* sig, word32 sigSz, int* result)
{
    int err;
    byte signature[2*P256_BYTE_SZ] = {0};
    byte *r, *s;
    word32 r_len = P256_BYTE_SZ, s_len = P256_BYTE_SZ;
    byte pubKeyX[P256_BYTE_SZ] = {0};
    byte pubKeyY[P256_BYTE_SZ] = {0};
    word32 pubKeyX_len = sizeof(pubKeyX);
    word32 pubKeyY_len = sizeof(pubKeyY);

    *result = 0;

    /* Extract raw X and Y coordinates of the public key */
    if ((err = wc_ecc_export_public_raw(key, pubKeyX, &pubKeyX_len,
            pubKeyY, &pubKeyY_len)) != 0) {
        WOLFSSL_MSG("wc_ecc_export_public_raw");
        return err;
    }
    vlt_tls_left_pad_P256(pubKeyX, pubKeyX_len);
    vlt_tls_left_pad_P256(pubKeyY, pubKeyY_len);

    /* Extract R and S from the signature */
    r = &signature[0];
    s = &signature[sizeof(signature)/2];
    if ((err = wc_ecc_sig_to_rs(sig, sigSz, r, &r_len, s, &s_len)) != 0) {
        WOLFSSL_MSG("wc_ecc_sig_to_rs");
        return err;
    }
    vlt_tls_left_pad_P256(r, r_len);
    vlt_tls_left_pad_P256(s, s_len);

    /* Verify signature with the VaultIC */
    if (vlt_tls_verify_signature_P256(hash, hashSz, signature, pubKeyX,
            pubKeyY) != 0) {
        WOLFSSL_MSG("vlt_tls_verify_signature_P256");
        return WC_HW_E;
    }

    *result = 1;
    return 0;
}

#ifdef HAVE_PK_CALLBACKS

#ifndef VLT_TLS_NO_ECDH
/**
 * \brief Key Gen Callback (used by TLS server)
 */
int WOLFSSL_VAULTIC_EccKeyGenCb(WOLFSSL* ssl, ecc_key* key, word32 keySz,
    int ecc_curve, void* ctx)
{
    int err;
    byte pubKeyX[P256_BYTE_SZ] = {0};
    byte pubKeyY[P256_BYTE_SZ] = {0};

    (void)ssl;
    (void)ctx;

    WOLFSSL_MSG("WOLFSSL_VAULTIC_EccKeyGenCb");

    /* check requested curve params */
    if (ecc_curve != ECC_SECP256R1) {
        WOLFSSL_MSG("ecc_curve != ECC_SECP256R1");
        return NOT_COMPILED_IN;
    }
    if (keySz != P256_BYTE_SZ) {
        WOLFSSL_MSG("keysize != 32. We are supporting ECC P256 case only");
        return NOT_COMPILED_IN;
    }

    /* generate new ephemeral key on device */
    if (vlt_tls_keygen_P256(pubKeyX, pubKeyY) != 0) {
        WOLFSSL_MSG("vlt_tls_keygen_P256");
        return WC_HW_E;
    }

    /* load generated public key into key, used by wolfSSL */
    if ((err = wc_ecc_import_unsigned(key, pubKeyX, pubKeyY, NULL,
            ecc_curve)) != 0) {
        WOLFSSL_MSG("wc_ecc_import_unsigned");
    }

    return err;
}
#endif

/**
 * \brief Verify Certificate Callback.
 *
 */
int WOLFSSL_VAULTIC_EccVerifyCb(WOLFSSL* ssl,
                                const unsigned char* sig, unsigned int sigSz,
                                const unsigned char* hash, unsigned int hashSz,
                                const unsigned char* keyDer, unsigned int keySz,
                                int* result, void* ctx)
{
    int err;
#ifdef WOLFSSL_SMALL_STACK
    ecc_key* key = NULL;
#else
    ecc_key  key[1];
#endif
    word32 inOutIdx = 0;

    WOLFSSL_MSG("WOLFSSL_VAULTIC_EccVerifyCb");

    (void)ssl;
    (void)ctx;

    if (keyDer == NULL || sig == NULL || hash == NULL || result == NULL) {
        return BAD_FUNC_ARG;
    }
    *result = 0;

#ifdef WOLFSSL_SMALL_STACK
    key = (ecc_key*)XMALLOC(sizeof(ecc_key), NULL, DYNAMIC_TYPE_ECC);
    if (key == NULL) {
        return MEMORY_E;
    }
#endif

    if ((err = wc_ecc_init(key)) != 0) {
        WOLFSSL_MSG("wc_ecc_init");
#ifdef WOLFSSL_SMALL_STACK
        XFREE(key, NULL, DYNAMIC_TYPE_ECC);
#endif
        return err;
    }

    /* Decode the public key */
    if ((err = wc_EccPublicKeyDecode(keyDer, &inOutIdx, key, keySz)) != 0) {
        WOLFSSL_MSG("wc_EccPublicKeyDecode");
        goto free_key;
    }

    /* Check requested curve */
    if (key->dp->id != ECC_SECP256R1) {
        WOLFSSL_MSG("id != ECC_SECP256R1");
        err = NOT_COMPILED_IN;
        goto free_key;
    }

    err = vaultic_p256_verify(key, hash, hashSz, sig, sigSz, result);

free_key:
    wc_ecc_free(key);
#ifdef WOLFSSL_SMALL_STACK
    XFREE(key, NULL, DYNAMIC_TYPE_ECC);
#endif

    return err;
}


/**
 * \brief Sign Certificate Callback.
 */
int WOLFSSL_VAULTIC_EccSignCb(WOLFSSL* ssl, const byte* in,
                                 word32 inSz, byte* out, word32* outSz,
                                 const byte* key, word32 keySz, void* ctx)
{
    int err;
    byte sig_R[P256_BYTE_SZ] = {0};
    byte sig_S[P256_BYTE_SZ] = {0};

    (void)ssl;
    (void)ctx;
    (void)key;
    (void)keySz;

    WOLFSSL_MSG("WOLFSSL_VAULTIC_EccSignCb");

    /* Sign input message using VaultIC */
    if (vlt_tls_compute_signature_P256(in, inSz, sig_R, sig_S) != 0) {
        WOLFSSL_MSG("vlt_tls_compute_signature_P256");
        return WC_HW_E;
    }

    /* Convert R and S to signature */
    if ((err = wc_ecc_rs_raw_to_sig(sig_R, P256_BYTE_SZ, sig_S, P256_BYTE_SZ,
            out, outSz)) != 0) {
        WOLFSSL_MSG("wc_ecc_rs_raw_to_sig");
        return err;
    }

    return err;
}

#ifndef VLT_TLS_NO_ECDH
/**
 * \brief Create pre master secret using peer's public key and self private key.
 */
int WOLFSSL_VAULTIC_EccSharedSecretCb(WOLFSSL* ssl, ecc_key* otherPubKey,
                              unsigned char* pubKeyDer, unsigned int* pubKeySz,
                              unsigned char* out, unsigned int* outlen,
                              int side, void* ctx)
{
    int err;
    byte otherPubKeyX[P256_BYTE_SZ] = {0};
    byte otherPubKeyY[P256_BYTE_SZ] = {0};
    word32 otherPubKeyX_len = sizeof(otherPubKeyX);
    word32 otherPubKeyY_len = sizeof(otherPubKeyY);
    byte pubKeyX[P256_BYTE_SZ] = {0};
    byte pubKeyY[P256_BYTE_SZ] = {0};
#ifdef WOLFSSL_SMALL_STACK
    ecc_key* tmpKey = NULL;
#else
    ecc_key  tmpKey[1];
#endif
    int tmpKey_inited = 0;

    (void)ssl;
    (void)ctx;

    WOLFSSL_MSG("WOLFSSL_VAULTIC_EccSharedSecretCb");

    /* check requested curve */
    if (otherPubKey->dp->id != ECC_SECP256R1) {
        WOLFSSL_MSG("id != ECC_SECP256R1");
        return NOT_COMPILED_IN;
    }

#ifdef WOLFSSL_SMALL_STACK
    tmpKey = (ecc_key*)XMALLOC(sizeof(ecc_key), NULL, DYNAMIC_TYPE_ECC);
    if (tmpKey == NULL) {
        return MEMORY_E;
    }
#endif

    /* for client: create and export public key */
    if (side == WOLFSSL_CLIENT_END) {

        /* Export otherPubKey raw X and Y */
        err = wc_ecc_export_public_raw(otherPubKey,
            &otherPubKeyX[0], &otherPubKeyX_len,
            &otherPubKeyY[0], &otherPubKeyY_len);
        if (err != 0) {
            WOLFSSL_MSG("wc_ecc_export_public_raw");
            goto cleanup;
        }
        vlt_tls_left_pad_P256(otherPubKeyX, otherPubKeyX_len);
        vlt_tls_left_pad_P256(otherPubKeyY, otherPubKeyY_len);


        /* TLS v1.2 and older we must generate a key here for the client only.
         * TLS v1.3 calls key gen early with key share */
        if (wolfSSL_GetVersion(ssl) < WOLFSSL_TLSV1_3) {

            if (vlt_tls_keygen_P256(pubKeyX, pubKeyY) != 0) {
                WOLFSSL_MSG("vlt_tls_keygen_P256");
                err = WC_HW_E;
                goto cleanup;
            }

            /* convert raw unsigned public key to X.963 format for TLS */
            if ((err = wc_ecc_init(tmpKey)) != 0) {
                WOLFSSL_MSG("wc_ecc_init");
                goto cleanup;
            }
            tmpKey_inited = 1;

            if ((err = wc_ecc_import_unsigned(tmpKey, pubKeyX, pubKeyY,
                    NULL, ECC_SECP256R1)) != 0) {
                WOLFSSL_MSG("wc_ecc_import_unsigned");
                goto cleanup;
            }

            if ((err = wc_ecc_export_x963(tmpKey, pubKeyDer, pubKeySz)) != 0) {
                WOLFSSL_MSG("wc_ecc_export_x963");
                goto cleanup;
            }
        }
    }

    /* for server: import public key */
    else if (side == WOLFSSL_SERVER_END) {
        if ((err = wc_ecc_init(tmpKey)) != 0) {
            WOLFSSL_MSG("wc_ecc_init");
            goto cleanup;
        }
        tmpKey_inited = 1;

        /* import peer's key and export as raw unsigned for hardware */
        if ((err = wc_ecc_import_x963_ex(pubKeyDer, *pubKeySz, tmpKey,
                ECC_SECP256R1)) != 0) {
            WOLFSSL_MSG("wc_ecc_import_x963_ex");
            goto cleanup;
        }

        if ((err = wc_ecc_export_public_raw(tmpKey, otherPubKeyX,
                &otherPubKeyX_len, otherPubKeyY, &otherPubKeyY_len)) != 0) {
            WOLFSSL_MSG("wc_ecc_export_public_raw");
            goto cleanup;
        }
        vlt_tls_left_pad_P256(otherPubKeyX, otherPubKeyX_len);
        vlt_tls_left_pad_P256(otherPubKeyY, otherPubKeyY_len);
    }
    else {
        err = BAD_FUNC_ARG;
        goto cleanup;
    }

    /* Compute shared secret */
    if (vlt_tls_compute_shared_secret_P256(otherPubKeyX, otherPubKeyY,
            out) != 0) {
        WOLFSSL_MSG("vlt_tls_compute_shared_secret_P256");
        err = WC_HW_E;
        goto cleanup;
    }

    *outlen = P256_BYTE_SZ;
    err = 0;

cleanup:
    if (tmpKey_inited) {
        wc_ecc_free(tmpKey);
    }
#ifdef WOLFSSL_SMALL_STACK
    XFREE(tmpKey, NULL, DYNAMIC_TYPE_ECC);
#endif

    return err;
}
#endif /* VLT_TLS_NO_ECDH */

#endif /* HAVE_PK_CALLBACKS */

/**
 * \brief Read VaultIC Certificates and add them to wolfssl context
 */
int WOLFSSL_VAULTIC_LoadCertificates(WOLFSSL_CTX* ctx)
{
    int ret = WOLFSSL_FATAL_ERROR;

    /* CA certificate */
    unsigned char *ca_cert = NULL;
    int sizeof_ca_cert = 0;

    /* Device certificate */
    unsigned char *device_cert = NULL;
    int sizeof_device_cert = 0;

    /* Read Device certificate in VaultIC */
    WOLFSSL_MSG("Read Device Certificate in VaultIC");

    if ((sizeof_device_cert = vlt_tls_get_cert_size(SSL_VIC_DEVICE_CERT))
            == -1) {
        WOLFSSL_MSG("No Device Certificate found in VaultIC");
        return WC_HW_E;
    }

    device_cert = (unsigned char*)XMALLOC(sizeof_device_cert, NULL,
        DYNAMIC_TYPE_CERT);
    if (device_cert == NULL) {
        WOLFSSL_MSG("malloc device_cert");
        return MEMORY_E;
    }

    if (vlt_tls_read_cert(device_cert, SSL_VIC_DEVICE_CERT) != 0) {
        WOLFSSL_MSG("vlt_tls_read_cert Device");
        ret = WC_HW_E;
        goto free_cert_buffers;
    }

    WOLFSSL_MSG("[Device certificate]");
#ifdef WOLFSSL_VAULTIC_DEBUG
    WOLFSSL_BUFFER(device_cert, sizeof_device_cert);
#endif

    /* Read CA certificate in VaultIC */
    WOLFSSL_MSG("Read CA Certificate in VaultIC");
    if ((sizeof_ca_cert = vlt_tls_get_cert_size(SSL_VIC_CA_CERT)) == -1) {
        WOLFSSL_MSG("No CA Certificate found in VaultIC");
        ret = WC_HW_E;
        goto free_cert_buffers;
    }

    ca_cert = (unsigned char*)XMALLOC(sizeof_ca_cert, NULL,
        DYNAMIC_TYPE_CERT);
    if (ca_cert == NULL) {
        WOLFSSL_MSG("malloc ca_cert");
        ret = MEMORY_E;
        goto free_cert_buffers;
    }

    if (vlt_tls_read_cert(ca_cert, SSL_VIC_CA_CERT) != 0) {
        WOLFSSL_MSG("vlt_tls_read_cert CA");
        ret = WC_HW_E;
        goto free_cert_buffers;
    }

    WOLFSSL_MSG("[CA certificate]");
#ifdef WOLFSSL_VAULTIC_DEBUG
    WOLFSSL_BUFFER(ca_cert, sizeof_ca_cert);
#endif

    /* Load CA certificate into WOLFSSL_CTX */
    if (wolfSSL_CTX_load_verify_buffer(ctx, ca_cert,
            sizeof_ca_cert, WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("failed to load CA certificate");
        ret = WC_HW_E;
        goto free_cert_buffers;
    }

    /* Load Device certificate into WOLFSSL_CTX */
    if (wolfSSL_CTX_use_certificate_buffer(ctx, device_cert,
            sizeof_device_cert, WOLFSSL_FILETYPE_ASN1) != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG("failed to load Device certificate");
        ret = WC_HW_E;
        goto free_cert_buffers;
    }

    /* VaultIC certificates successfully injected into wolfSSL */
    ret = 0;

free_cert_buffers:
    if (ca_cert != NULL)
        XFREE(ca_cert, NULL, DYNAMIC_TYPE_CERT);
    if (device_cert != NULL)
        XFREE(device_cert, NULL, DYNAMIC_TYPE_CERT);

    return ret;
}

#ifdef HAVE_PK_CALLBACKS
int WOLFSSL_VAULTIC_SetupPkCallbacks(WOLFSSL_CTX* ctx)
{
    wolfSSL_CTX_SetEccSignCb(ctx, WOLFSSL_VAULTIC_EccSignCb);
    wolfSSL_CTX_SetEccVerifyCb(ctx, WOLFSSL_VAULTIC_EccVerifyCb);
#ifndef VLT_TLS_NO_ECDH
    wolfSSL_CTX_SetEccKeyGenCb(ctx, WOLFSSL_VAULTIC_EccKeyGenCb);
    wolfSSL_CTX_SetEccSharedSecretCb(ctx, WOLFSSL_VAULTIC_EccSharedSecretCb);
#endif
    return 0;
}

int WOLFSSL_VAULTIC_SetupPkCallbackCtx(WOLFSSL* ssl, void* user_ctx)
{
#ifndef VLT_TLS_NO_ECDH
    wolfSSL_SetEccKeyGenCtx(ssl, user_ctx);
    wolfSSL_SetEccSharedSecretCtx(ssl, user_ctx);
#endif
    wolfSSL_SetEccSignCtx(ssl, user_ctx);
    wolfSSL_SetEccVerifyCtx(ssl, user_ctx);
    return 0;
}
#endif /* HAVE_PK_CALLBACKS */

#ifdef WOLF_CRYPTO_CB

/**
 * \brief wolfCrypt crypto callback. Dispatches ECC P-256 operations to the
 *        VaultIC. Register with WOLFSSL_VAULTIC_RegisterCryptoCb() and select
 *        it with a devId (wolfSSL_CTX_SetDevId / wc_ecc_init_ex). Unsupported
 *        curves and operations return CRYPTOCB_UNAVAILABLE so wolfCrypt falls
 *        back to software. Note: the VaultIC 408 silicon supports P-384, but
 *        the vendor vlt_tls API exposes P-256 only, so P-384 is not offloaded.
 */
int WOLFSSL_VAULTIC_CryptoCb(int devId, wc_CryptoInfo* info, void* ctx)
{
    int rc = CRYPTOCB_UNAVAILABLE;

    (void)devId;
    (void)ctx;

    if (info == NULL) {
        return BAD_FUNC_ARG;
    }

    if (info->algo_type != WC_ALGO_TYPE_PK) {
        return CRYPTOCB_UNAVAILABLE;
    }

    switch (info->pk.type) {
        case WC_PK_TYPE_ECDSA_SIGN:
        {
            byte sig_R[P256_BYTE_SZ] = {0};
            byte sig_S[P256_BYTE_SZ] = {0};

            WOLFSSL_MSG("WOLFSSL_VAULTIC_CryptoCb: ECDSA sign");
            if (info->pk.eccsign.key == NULL ||
                    info->pk.eccsign.key->dp == NULL ||
                    info->pk.eccsign.key->dp->id != ECC_SECP256R1) {
                /* P-384 is a vendor vlt_tls gap; let software handle it */
                break;
            }
            if (vlt_tls_compute_signature_P256(info->pk.eccsign.in,
                    info->pk.eccsign.inlen, sig_R, sig_S) != 0) {
                WOLFSSL_MSG("vlt_tls_compute_signature_P256");
                rc = WC_HW_E;
                break;
            }
            rc = wc_ecc_rs_raw_to_sig(sig_R, P256_BYTE_SZ, sig_S, P256_BYTE_SZ,
                    info->pk.eccsign.out, info->pk.eccsign.outlen);
            break;
        }

        case WC_PK_TYPE_ECDSA_VERIFY:
            WOLFSSL_MSG("WOLFSSL_VAULTIC_CryptoCb: ECDSA verify");
            if (info->pk.eccverify.key == NULL ||
                    info->pk.eccverify.key->dp == NULL ||
                    info->pk.eccverify.key->dp->id != ECC_SECP256R1) {
                break;
            }
            rc = vaultic_p256_verify(info->pk.eccverify.key,
                    info->pk.eccverify.hash, info->pk.eccverify.hashlen,
                    info->pk.eccverify.sig, info->pk.eccverify.siglen,
                    info->pk.eccverify.res);
            break;

#ifndef VLT_TLS_NO_ECDH
        case WC_PK_TYPE_ECDH:
        {
            byte peerX[P256_BYTE_SZ] = {0};
            byte peerY[P256_BYTE_SZ] = {0};
            word32 peerX_len = sizeof(peerX);
            word32 peerY_len = sizeof(peerY);

            WOLFSSL_MSG("WOLFSSL_VAULTIC_CryptoCb: ECDH");
            if (info->pk.ecdh.private_key == NULL ||
                    info->pk.ecdh.private_key->dp == NULL ||
                    info->pk.ecdh.private_key->dp->id != ECC_SECP256R1) {
                break;
            }
            if ((rc = wc_ecc_export_public_raw(info->pk.ecdh.public_key,
                    peerX, &peerX_len, peerY, &peerY_len)) != 0) {
                WOLFSSL_MSG("wc_ecc_export_public_raw");
                break;
            }
            vlt_tls_left_pad_P256(peerX, peerX_len);
            vlt_tls_left_pad_P256(peerY, peerY_len);
            if (vlt_tls_compute_shared_secret_P256(peerX, peerY,
                    info->pk.ecdh.out) != 0) {
                WOLFSSL_MSG("vlt_tls_compute_shared_secret_P256");
                rc = WC_HW_E;
                break;
            }
            *info->pk.ecdh.outlen = P256_BYTE_SZ;
            rc = 0;
            break;
        }

        case WC_PK_TYPE_EC_KEYGEN:
        {
            byte pubKeyX[P256_BYTE_SZ] = {0};
            byte pubKeyY[P256_BYTE_SZ] = {0};

            WOLFSSL_MSG("WOLFSSL_VAULTIC_CryptoCb: EC keygen");
            if (info->pk.eckg.curveId != ECC_SECP256R1) {
                break;
            }
            if (vlt_tls_keygen_P256(pubKeyX, pubKeyY) != 0) {
                WOLFSSL_MSG("vlt_tls_keygen_P256");
                rc = WC_HW_E;
                break;
            }
            rc = wc_ecc_import_unsigned(info->pk.eckg.key, pubKeyX, pubKeyY,
                    NULL, ECC_SECP256R1);
            break;
        }
#endif /* VLT_TLS_NO_ECDH */

        default:
            /* rc stays CRYPTOCB_UNAVAILABLE -> software fallback */
            break;
    }

    return rc;
}

/**
 * \brief Register the VaultIC crypto callback for the given devId.
 */
int WOLFSSL_VAULTIC_RegisterCryptoCb(int devId)
{
    return wc_CryptoCb_RegisterDevice(devId, WOLFSSL_VAULTIC_CryptoCb, NULL);
}

#endif /* WOLF_CRYPTO_CB */

#endif /* WOLFSSL_VAULTIC */
