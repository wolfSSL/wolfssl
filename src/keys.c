/* keys.c
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


/* Name change compatibility layer no longer needs to be included here */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#if !defined(WOLFCRYPT_ONLY) && !defined(NO_TLS)

#include <wolfssl/internal.h>
#include <wolfssl/error-ssl.h>
#if defined(SHOW_SECRETS) || defined(CHACHA_AEAD_TEST)
    #ifndef NO_STDIO_FILESYSTEM
        #include <stdio.h>
    #endif
#endif

#if defined(WOLFSSL_RENESAS_FSPSM_TLS) || defined(WOLFSSL_RENESAS_TSIP_TLS)
#include <wolfssl/wolfcrypt/port/Renesas/renesas_cmn.h>
#endif

int SetCipherSpecs(WOLFSSL* ssl)
{
    int ret = GetCipherSpec(ssl->options.side, ssl->options.cipherSuite0,
                                ssl->options.cipherSuite, &ssl->specs,
                                &ssl->options);
    if (ret == 0) {
        /* set TLS if it hasn't been turned off */
        if (ssl->version.major == SSLv3_MAJOR &&
                ssl->version.minor >= TLSv1_MINOR) {
    #ifndef NO_TLS
            ssl->options.tls = 1;
        #if !defined(WOLFSSL_NO_TLS12) && !defined(WOLFSSL_AEAD_ONLY)
            #if !defined(WOLFSSL_RENESAS_FSPSM_TLS) && \
                !defined(WOLFSSL_RENESAS_TSIP_TLS)
            ssl->hmac = TLS_hmac;
            #else
            ssl->hmac = Renesas_cmn_TLS_hmac;
            #endif
        #endif
            if (ssl->version.minor >= TLSv1_1_MINOR) {
                ssl->options.tls1_1 = 1;
                if (ssl->version.minor >= TLSv1_3_MINOR)
                    ssl->options.tls1_3 = 1;
            }
    #endif
        }

    #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
        if (IsAtLeastTLSv1_3(ssl->version) || ssl->specs.cipher_type != block)
           ssl->options.encThenMac = 0;
    #endif

    #if defined(WOLFSSL_DTLS)
        if (ssl->options.dtls && ssl->version.major == DTLS_MAJOR) {
        #ifndef WOLFSSL_AEAD_ONLY
            #if !defined(WOLFSSL_RENESAS_FSPSM_TLS) && \
                !defined(WOLFSSL_RENESAS_TSIP_TLS)
            ssl->hmac = TLS_hmac;
            #else
            ssl->hmac = Renesas_cmn_TLS_hmac;
            #endif
        #endif
            ssl->options.tls = 1;
            ssl->options.tls1_1 = 1; /* DTLS 1.0 == TLS 1.1 */
        #ifdef WOLFSSL_DTLS13
            if (ssl->version.minor <= DTLSv1_3_MINOR)
                ssl->options.tls1_3 = 1;
        #endif
        }
    #endif
    }
    return ret;
}

/**
 * Populate specs with the specification of the chosen ciphersuite. If opts is
 * not NULL then the appropriate options will also be set.
 *
 * @param side         [in] WOLFSSL_SERVER_END or WOLFSSL_CLIENT_END
 * @param cipherSuite0 [in]
 * @param cipherSuite  [in]
 * @param specs        [out] CipherSpecs
 * @param opts         [in/out] Options can be NULL
 * @return int (less than 0 on fail, 0 on success)
 */
int GetCipherSpec(word16 side, byte cipherSuite0, byte cipherSuite,
                      CipherSpecs* specs, Options* opts)
{
    word16 havePSK = 0;
    (void)havePSK;
    (void)side;
#if defined(HAVE_SESSION_TICKET) || !defined(NO_PSK)
    if (opts != NULL)
        havePSK = opts->havePSK;
#endif
#ifndef NO_WOLFSSL_CLIENT
    if (side == WOLFSSL_CLIENT_END) {
        /* server side verified before SetCipherSpecs call */
        if (VerifyClientSuite(havePSK, cipherSuite0, cipherSuite) != 1) {
            WOLFSSL_MSG("SetCipherSpecs() client has an unusable suite");
            WOLFSSL_ERROR_VERBOSE(UNSUPPORTED_SUITE);
            return UNSUPPORTED_SUITE;
        }
    }
#endif /* NO_WOLFSSL_CLIENT */

    /* Initialize specs */
    XMEMSET(specs, 0, sizeof(CipherSpecs));

    /* Chacha extensions, 0xcc */
    if (cipherSuite0 == CHACHA_BYTE) {

    switch (cipherSuite) {
#ifdef BUILD_TLS_ECDHE_RSA_WITH_CHACHA20_OLD_POLY1305_SHA256
    case TLS_ECDHE_RSA_WITH_CHACHA20_OLD_POLY1305_SHA256:
        specs->bulk_cipher_algorithm = wolfssl_chacha;
        specs->cipher_type           = aead;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = ecc_diffie_hellman_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = CHACHA20_256_KEY_SIZE;
        specs->block_size            = CHACHA20_BLOCK_SIZE;
        specs->iv_size               = CHACHA20_IV_SIZE;
        specs->aead_mac_size         = POLY1305_AUTH_SZ;
        if (opts != NULL)
            opts->oldPoly            = 1; /* use old poly1305 padding */

        break;
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_CHACHA20_OLD_POLY1305_SHA256
    case TLS_ECDHE_ECDSA_WITH_CHACHA20_OLD_POLY1305_SHA256:
        specs->bulk_cipher_algorithm = wolfssl_chacha;
        specs->cipher_type           = aead;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = ecc_diffie_hellman_kea;
        specs->sig_algo              = ecc_dsa_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = CHACHA20_256_KEY_SIZE;
        specs->block_size            = CHACHA20_BLOCK_SIZE;
        specs->iv_size               = CHACHA20_IV_SIZE;
        specs->aead_mac_size         = POLY1305_AUTH_SZ;
        if (opts != NULL)
            opts->oldPoly            = 1; /* use old poly1305 padding */

        break;
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_CHACHA20_OLD_POLY1305_SHA256
    case TLS_DHE_RSA_WITH_CHACHA20_OLD_POLY1305_SHA256:
        specs->bulk_cipher_algorithm = wolfssl_chacha;
        specs->cipher_type           = aead;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = diffie_hellman_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = CHACHA20_256_KEY_SIZE;
        specs->block_size            = CHACHA20_BLOCK_SIZE;
        specs->iv_size               = CHACHA20_IV_SIZE;
        specs->aead_mac_size         = POLY1305_AUTH_SZ;
        if (opts != NULL)
            opts->oldPoly            = 1; /* use old poly1305 padding */

        break;
#endif
#ifdef BUILD_TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    case TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
        specs->bulk_cipher_algorithm = wolfssl_chacha;
        specs->cipher_type           = aead;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = ecc_diffie_hellman_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = CHACHA20_256_KEY_SIZE;
        specs->block_size            = CHACHA20_BLOCK_SIZE;
        specs->iv_size               = CHACHA20_IV_SIZE;
        specs->aead_mac_size         = POLY1305_AUTH_SZ;
        if (opts != NULL)
            opts->oldPoly            = 0; /* use recent padding RFC */

        break;
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
    case TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
        specs->bulk_cipher_algorithm = wolfssl_chacha;
        specs->cipher_type           = aead;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = ecc_diffie_hellman_kea;
        specs->sig_algo              = ecc_dsa_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = CHACHA20_256_KEY_SIZE;
        specs->block_size            = CHACHA20_BLOCK_SIZE;
        specs->iv_size               = CHACHA20_IV_SIZE;
        specs->aead_mac_size         = POLY1305_AUTH_SZ;
        if (opts != NULL)
            opts->oldPoly            = 0; /* use recent padding RFC */

        break;
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    case TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
        specs->bulk_cipher_algorithm = wolfssl_chacha;
        specs->cipher_type           = aead;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = diffie_hellman_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = CHACHA20_256_KEY_SIZE;
        specs->block_size            = CHACHA20_BLOCK_SIZE;
        specs->iv_size               = CHACHA20_IV_SIZE;
        specs->aead_mac_size         = POLY1305_AUTH_SZ;
        if (opts != NULL)
            opts->oldPoly            = 0; /* use recent padding RFC */

        break;
#endif

#ifdef BUILD_TLS_PSK_WITH_CHACHA20_POLY1305_SHA256
    case TLS_PSK_WITH_CHACHA20_POLY1305_SHA256:
        specs->bulk_cipher_algorithm = wolfssl_chacha;
        specs->cipher_type           = aead;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = psk_kea;
        specs->sig_algo              = anonymous_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = CHACHA20_256_KEY_SIZE;
        specs->block_size            = CHACHA20_BLOCK_SIZE;
        specs->iv_size               = CHACHA20_IV_SIZE;
        specs->aead_mac_size         = POLY1305_AUTH_SZ;

        if (opts != NULL) {
            opts->oldPoly            = 0; /* use recent padding RFC */
            opts->usingPSK_cipher    = 1;
        }
        break;
#endif

#ifdef BUILD_TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256
    case TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
        specs->bulk_cipher_algorithm = wolfssl_chacha;
        specs->cipher_type           = aead;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = ecdhe_psk_kea;
        specs->sig_algo              = anonymous_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = CHACHA20_256_KEY_SIZE;
        specs->block_size            = CHACHA20_BLOCK_SIZE;
        specs->iv_size               = CHACHA20_IV_SIZE;
        specs->aead_mac_size         = POLY1305_AUTH_SZ;

        if (opts != NULL) {
            opts->oldPoly            = 0; /* use recent padding RFC */
            opts->usingPSK_cipher    = 1;
        }
        break;
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256
    case TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
        specs->bulk_cipher_algorithm = wolfssl_chacha;
        specs->cipher_type           = aead;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = dhe_psk_kea;
        specs->sig_algo              = anonymous_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = CHACHA20_256_KEY_SIZE;
        specs->block_size            = CHACHA20_BLOCK_SIZE;
        specs->iv_size               = CHACHA20_IV_SIZE;
        specs->aead_mac_size         = POLY1305_AUTH_SZ;

        if (opts != NULL) {
            opts->oldPoly            = 0; /* use recent padding RFC */
            opts->usingPSK_cipher    = 1;
        }
        break;
#endif
    default:
        WOLFSSL_MSG("Unsupported cipher suite, SetCipherSpecs ChaCha");
        return UNSUPPORTED_SUITE;
    }
    }

    /* ECC extensions, AES-CCM or TLS 1.3 Integrity-only */
    if (cipherSuite0 == ECC_BYTE) {

    switch (cipherSuite) {

#if defined(HAVE_ECC) || defined(HAVE_CURVE25519) || defined(HAVE_CURVE448)

#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256
    case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 :
        specs->bulk_cipher_algorithm = wolfssl_aes;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = ecc_diffie_hellman_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_128_KEY_SIZE;
        specs->iv_size               = AES_IV_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;

        break;
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
    case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 :
        specs->bulk_cipher_algorithm = wolfssl_aes;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sha384_mac;
        specs->kea                   = ecc_diffie_hellman_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_SHA384_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_256_KEY_SIZE;
        specs->iv_size               = AES_IV_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;

        break;
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA
    case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA :
        specs->bulk_cipher_algorithm = wolfssl_aes;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sha_mac;
        specs->kea                   = ecc_diffie_hellman_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_SHA_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_128_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AES_IV_SIZE;

        break;
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA
    case TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA :
        specs->bulk_cipher_algorithm = wolfssl_triple_des;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sha_mac;
        specs->kea                   = ecc_diffie_hellman_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_SHA_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = DES3_KEY_SIZE;
        specs->block_size            = DES_BLOCK_SIZE;
/* DES_IV_SIZE is incorrectly 16 in FIPS v2. It should be 8, same as the
 * block size. */
#if defined(HAVE_FIPS) && defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION == 2)
        specs->iv_size               = DES_BLOCK_SIZE;
#else
        specs->iv_size               = DES_IV_SIZE;
#endif

        break;
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_RC4_128_SHA
    case TLS_ECDHE_RSA_WITH_RC4_128_SHA :
        specs->bulk_cipher_algorithm = wolfssl_rc4;
        specs->cipher_type           = stream;
        specs->mac_algorithm         = sha_mac;
        specs->kea                   = ecc_diffie_hellman_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_SHA_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = RC4_KEY_SIZE;
        specs->iv_size               = 0;
        specs->block_size            = 0;

        break;
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
    case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA :
        specs->bulk_cipher_algorithm = wolfssl_aes;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sha_mac;
        specs->kea                   = ecc_diffie_hellman_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_SHA_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_256_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AES_IV_SIZE;

        break;
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 :
        specs->bulk_cipher_algorithm = wolfssl_aes_gcm;
        specs->cipher_type           = aead;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = ecc_diffie_hellman_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_128_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AESGCM_IMP_IV_SZ;
        specs->aead_mac_size         = AES_GCM_AUTH_SZ;

        break;
#endif

#ifdef BUILD_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
    case TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 :
        specs->bulk_cipher_algorithm = wolfssl_aes_gcm;
        specs->cipher_type           = aead;
        specs->mac_algorithm         = sha384_mac;
        specs->kea                   = ecc_diffie_hellman_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_SHA384_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_256_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AESGCM_IMP_IV_SZ;
        specs->aead_mac_size         = AES_GCM_AUTH_SZ;

        break;
#endif

#ifdef BUILD_TLS_ECDHE_PSK_WITH_NULL_SHA256
    case TLS_ECDHE_PSK_WITH_NULL_SHA256 :
        specs->bulk_cipher_algorithm = wolfssl_cipher_null;
        specs->cipher_type           = stream;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = ecdhe_psk_kea;
        specs->sig_algo              = anonymous_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = 0;
        specs->block_size            = 0;
        specs->iv_size               = 0;

        if (opts != NULL)
            opts->usingPSK_cipher    = 1;
        break;
#endif

#ifdef BUILD_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256
    case TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 :
        specs->bulk_cipher_algorithm = wolfssl_aes;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = ecdhe_psk_kea;
        specs->sig_algo              = anonymous_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_128_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AES_IV_SIZE;

        if (opts != NULL)
            opts->usingPSK_cipher    = 1;
        if (opts != NULL)
            opts->usingPSK_cipher    = 1;
        break;
#endif

#endif /* HAVE_ECC || HAVE_CURVE25519 || HAVE_CURVE448 */

#if defined(HAVE_ECC) || (defined(HAVE_CURVE25519) && defined(HAVE_ED25519)) \
                      || (defined(HAVE_CURVE448) && defined(HAVE_ED448))

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256
    case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 :
        specs->bulk_cipher_algorithm = wolfssl_aes;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = ecc_diffie_hellman_kea;
        specs->sig_algo              = ecc_dsa_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_128_KEY_SIZE;
        specs->iv_size               = AES_IV_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;

        break;
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
    case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 :
        specs->bulk_cipher_algorithm = wolfssl_aes;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sha384_mac;
        specs->kea                   = ecc_diffie_hellman_kea;
        specs->sig_algo              = ecc_dsa_sa_algo;
        specs->hash_size             = WC_SHA384_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_256_KEY_SIZE;
        specs->iv_size               = AES_IV_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;

        break;
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA
    case TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA :
        specs->bulk_cipher_algorithm = wolfssl_triple_des;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sha_mac;
        specs->kea                   = ecc_diffie_hellman_kea;
        specs->sig_algo              = ecc_dsa_sa_algo;
        specs->hash_size             = WC_SHA_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = DES3_KEY_SIZE;
        specs->block_size            = DES_BLOCK_SIZE;
#if defined(HAVE_FIPS) && defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION == 2)
        specs->iv_size               = DES_BLOCK_SIZE;
#else
        specs->iv_size               = DES_IV_SIZE;
#endif

        break;
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_RC4_128_SHA
    case TLS_ECDHE_ECDSA_WITH_RC4_128_SHA :
        specs->bulk_cipher_algorithm = wolfssl_rc4;
        specs->cipher_type           = stream;
        specs->mac_algorithm         = sha_mac;
        specs->kea                   = ecc_diffie_hellman_kea;
        specs->sig_algo              = ecc_dsa_sa_algo;
        specs->hash_size             = WC_SHA_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = RC4_KEY_SIZE;
        specs->iv_size               = 0;
        specs->block_size            = 0;

        break;
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA
    case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA :
        specs->bulk_cipher_algorithm = wolfssl_aes;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sha_mac;
        specs->kea                   = ecc_diffie_hellman_kea;
        specs->sig_algo              = ecc_dsa_sa_algo;
        specs->hash_size             = WC_SHA_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_128_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AES_IV_SIZE;

        break;
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA
    case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA :
        specs->bulk_cipher_algorithm = wolfssl_aes;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sha_mac;
        specs->kea                   = ecc_diffie_hellman_kea;
        specs->sig_algo              = ecc_dsa_sa_algo;
        specs->hash_size             = WC_SHA_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_256_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AES_IV_SIZE;

        break;
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 :
        specs->bulk_cipher_algorithm = wolfssl_aes_gcm;
        specs->cipher_type           = aead;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = ecc_diffie_hellman_kea;
        specs->sig_algo              = ecc_dsa_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_128_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AESGCM_IMP_IV_SZ;
        specs->aead_mac_size         = AES_GCM_AUTH_SZ;

        break;
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
    case TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 :
        specs->bulk_cipher_algorithm = wolfssl_aes_gcm;
        specs->cipher_type           = aead;
        specs->mac_algorithm         = sha384_mac;
        specs->kea                   = ecc_diffie_hellman_kea;
        specs->sig_algo              = ecc_dsa_sa_algo;
        specs->hash_size             = WC_SHA384_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_256_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AESGCM_IMP_IV_SZ;
        specs->aead_mac_size         = AES_GCM_AUTH_SZ;

        break;
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_128_CCM
    case TLS_ECDHE_ECDSA_WITH_AES_128_CCM :
        specs->bulk_cipher_algorithm = wolfssl_aes_ccm;
        specs->cipher_type           = aead;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = ecc_diffie_hellman_kea;
        specs->sig_algo              = ecc_dsa_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_128_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AESCCM_IMP_IV_SZ;
        specs->aead_mac_size         = AES_CCM_16_AUTH_SZ;

        break;
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8
    case TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 :
        specs->bulk_cipher_algorithm = wolfssl_aes_ccm;
        specs->cipher_type           = aead;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = ecc_diffie_hellman_kea;
        specs->sig_algo              = ecc_dsa_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_128_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AESCCM_IMP_IV_SZ;
        specs->aead_mac_size         = AES_CCM_8_AUTH_SZ;

        break;
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8
    case TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 :
        specs->bulk_cipher_algorithm = wolfssl_aes_ccm;
        specs->cipher_type           = aead;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = ecc_diffie_hellman_kea;
        specs->sig_algo              = ecc_dsa_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_256_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AESCCM_IMP_IV_SZ;
        specs->aead_mac_size         = AES_CCM_8_AUTH_SZ;

        break;
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_NULL_SHA
    case TLS_ECDHE_ECDSA_WITH_NULL_SHA :
        specs->bulk_cipher_algorithm = wolfssl_cipher_null;
        specs->cipher_type           = stream;
        specs->mac_algorithm         = sha_mac;
        specs->kea                   = ecc_diffie_hellman_kea;
        specs->sig_algo              = ecc_dsa_sa_algo;
        specs->hash_size             = WC_SHA_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = 0;
        specs->block_size            = 0;
        specs->iv_size               = 0;

    break;
#endif

#endif /* HAVE_ECC || (CURVE25519 && ED25519) || (CURVE448 && ED448) */

#if defined(HAVE_ECC)

#ifdef BUILD_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256
    case TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256 :
        specs->bulk_cipher_algorithm = wolfssl_aes;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = ecc_diffie_hellman_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 1;
        specs->key_size              = AES_128_KEY_SIZE;
        specs->iv_size               = AES_IV_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;

        break;
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256
    case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256 :
        specs->bulk_cipher_algorithm = wolfssl_aes;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = ecc_diffie_hellman_kea;
        specs->sig_algo              = ecc_dsa_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 1;
        specs->key_size              = AES_128_KEY_SIZE;
        specs->iv_size               = AES_IV_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;

        break;
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384
    case TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384 :
        specs->bulk_cipher_algorithm = wolfssl_aes;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sha384_mac;
        specs->kea                   = ecc_diffie_hellman_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_SHA384_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 1;
        specs->key_size              = AES_256_KEY_SIZE;
        specs->iv_size               = AES_IV_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;

        break;
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384
    case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384 :
        specs->bulk_cipher_algorithm = wolfssl_aes;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sha384_mac;
        specs->kea                   = ecc_diffie_hellman_kea;
        specs->sig_algo              = ecc_dsa_sa_algo;
        specs->hash_size             = WC_SHA384_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 1;
        specs->key_size              = AES_256_KEY_SIZE;
        specs->iv_size               = AES_IV_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;

        break;
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_AES_128_CBC_SHA
    case TLS_ECDH_RSA_WITH_AES_128_CBC_SHA :
        specs->bulk_cipher_algorithm = wolfssl_aes;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sha_mac;
        specs->kea                   = ecc_diffie_hellman_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_SHA_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 1;
        specs->key_size              = AES_128_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AES_IV_SIZE;

        break;
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
    case TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA :
        specs->bulk_cipher_algorithm = wolfssl_triple_des;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sha_mac;
        specs->kea                   = ecc_diffie_hellman_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_SHA_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 1;
        specs->key_size              = DES3_KEY_SIZE;
        specs->block_size            = DES_BLOCK_SIZE;
#if defined(HAVE_FIPS) && defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION == 2)
        specs->iv_size               = DES_BLOCK_SIZE;
#else
        specs->iv_size               = DES_IV_SIZE;
#endif

        break;
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_RC4_128_SHA
    case TLS_ECDH_RSA_WITH_RC4_128_SHA :
        specs->bulk_cipher_algorithm = wolfssl_rc4;
        specs->cipher_type           = stream;
        specs->mac_algorithm         = sha_mac;
        specs->kea                   = ecc_diffie_hellman_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_SHA_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 1;
        specs->key_size              = RC4_KEY_SIZE;
        specs->iv_size               = 0;
        specs->block_size            = 0;

        break;
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA
    case TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA :
        specs->bulk_cipher_algorithm = wolfssl_triple_des;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sha_mac;
        specs->kea                   = ecc_diffie_hellman_kea;
        specs->sig_algo              = ecc_dsa_sa_algo;
        specs->hash_size             = WC_SHA_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 1;
        specs->key_size              = DES3_KEY_SIZE;
        specs->block_size            = DES_BLOCK_SIZE;
#if defined(HAVE_FIPS) && defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION == 2)
        specs->iv_size               = DES_BLOCK_SIZE;
#else
        specs->iv_size               = DES_IV_SIZE;
#endif

        break;
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_RC4_128_SHA
    case TLS_ECDH_ECDSA_WITH_RC4_128_SHA :
        specs->bulk_cipher_algorithm = wolfssl_rc4;
        specs->cipher_type           = stream;
        specs->mac_algorithm         = sha_mac;
        specs->kea                   = ecc_diffie_hellman_kea;
        specs->sig_algo              = ecc_dsa_sa_algo;
        specs->hash_size             = WC_SHA_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 1;
        specs->key_size              = RC4_KEY_SIZE;
        specs->iv_size               = 0;
        specs->block_size            = 0;

        break;
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_AES_256_CBC_SHA
    case TLS_ECDH_RSA_WITH_AES_256_CBC_SHA :
        specs->bulk_cipher_algorithm = wolfssl_aes;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sha_mac;
        specs->kea                   = ecc_diffie_hellman_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_SHA_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 1;
        specs->key_size              = AES_256_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AES_IV_SIZE;

        break;
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA
    case TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA :
        specs->bulk_cipher_algorithm = wolfssl_aes;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sha_mac;
        specs->kea                   = ecc_diffie_hellman_kea;
        specs->sig_algo              = ecc_dsa_sa_algo;
        specs->hash_size             = WC_SHA_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 1;
        specs->key_size              = AES_128_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AES_IV_SIZE;

        break;
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA
    case TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA :
        specs->bulk_cipher_algorithm = wolfssl_aes;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sha_mac;
        specs->kea                   = ecc_diffie_hellman_kea;
        specs->sig_algo              = ecc_dsa_sa_algo;
        specs->hash_size             = WC_SHA_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 1;
        specs->key_size              = AES_256_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AES_IV_SIZE;

        break;
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256
    case TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256 :
        specs->bulk_cipher_algorithm = wolfssl_aes_gcm;
        specs->cipher_type           = aead;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = ecc_diffie_hellman_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 1;
        specs->key_size              = AES_128_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AESGCM_IMP_IV_SZ;
        specs->aead_mac_size         = AES_GCM_AUTH_SZ;

        break;
#endif

#ifdef BUILD_TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384
    case TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384 :
        specs->bulk_cipher_algorithm = wolfssl_aes_gcm;
        specs->cipher_type           = aead;
        specs->mac_algorithm         = sha384_mac;
        specs->kea                   = ecc_diffie_hellman_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_SHA384_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 1;
        specs->key_size              = AES_256_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AESGCM_IMP_IV_SZ;
        specs->aead_mac_size         = AES_GCM_AUTH_SZ;

        break;
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256
    case TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256 :
        specs->bulk_cipher_algorithm = wolfssl_aes_gcm;
        specs->cipher_type           = aead;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = ecc_diffie_hellman_kea;
        specs->sig_algo              = ecc_dsa_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 1;
        specs->key_size              = AES_128_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AESGCM_IMP_IV_SZ;
        specs->aead_mac_size         = AES_GCM_AUTH_SZ;

        break;
#endif

#ifdef BUILD_TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384
    case TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384 :
        specs->bulk_cipher_algorithm = wolfssl_aes_gcm;
        specs->cipher_type           = aead;
        specs->mac_algorithm         = sha384_mac;
        specs->kea                   = ecc_diffie_hellman_kea;
        specs->sig_algo              = ecc_dsa_sa_algo;
        specs->hash_size             = WC_SHA384_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 1;
        specs->key_size              = AES_256_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AESGCM_IMP_IV_SZ;
        specs->aead_mac_size         = AES_GCM_AUTH_SZ;

        break;
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256
    case TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256 :
        specs->bulk_cipher_algorithm = wolfssl_aria_gcm;
        specs->cipher_type           = aead;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = ecc_diffie_hellman_kea;
        specs->sig_algo              = ecc_dsa_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = ARIA_128_KEY_SIZE;
        specs->block_size            = ARIA_BLOCK_SIZE;
        specs->iv_size               = AESGCM_IMP_IV_SZ;
        specs->aead_mac_size         = ARIA_GCM_AUTH_SZ;

        break;
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384
    case TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384 :
        specs->bulk_cipher_algorithm = wolfssl_aria_gcm;
        specs->cipher_type           = aead;
        specs->mac_algorithm         = sha384_mac;
        specs->kea                   = ecc_diffie_hellman_kea;
        specs->sig_algo              = ecc_dsa_sa_algo;
        specs->hash_size             = WC_SHA384_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = ARIA_256_KEY_SIZE;
        specs->block_size            = ARIA_BLOCK_SIZE;
        specs->iv_size               = AESGCM_IMP_IV_SZ;
        specs->aead_mac_size         = ARIA_GCM_AUTH_SZ;

        break;
#endif

#endif /* HAVE_ECC */

#ifdef BUILD_TLS_RSA_WITH_AES_128_CCM_8
    case TLS_RSA_WITH_AES_128_CCM_8 :
        specs->bulk_cipher_algorithm = wolfssl_aes_ccm;
        specs->cipher_type           = aead;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = rsa_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_128_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AESCCM_IMP_IV_SZ;
        specs->aead_mac_size         = AES_CCM_8_AUTH_SZ;

        break;
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_256_CCM_8
    case TLS_RSA_WITH_AES_256_CCM_8 :
        specs->bulk_cipher_algorithm = wolfssl_aes_ccm;
        specs->cipher_type           = aead;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = rsa_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_256_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AESCCM_IMP_IV_SZ;
        specs->aead_mac_size         = AES_CCM_8_AUTH_SZ;

        break;
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_128_CCM_8
    case TLS_PSK_WITH_AES_128_CCM_8 :
        specs->bulk_cipher_algorithm = wolfssl_aes_ccm;
        specs->cipher_type           = aead;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = psk_kea;
        specs->sig_algo              = anonymous_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_128_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AESCCM_IMP_IV_SZ;
        specs->aead_mac_size         = AES_CCM_8_AUTH_SZ;

        if (opts != NULL)
            opts->usingPSK_cipher    = 1;
        break;
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_256_CCM_8
    case TLS_PSK_WITH_AES_256_CCM_8 :
        specs->bulk_cipher_algorithm = wolfssl_aes_ccm;
        specs->cipher_type           = aead;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = psk_kea;
        specs->sig_algo              = anonymous_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_256_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AESCCM_IMP_IV_SZ;
        specs->aead_mac_size         = AES_CCM_8_AUTH_SZ;

        if (opts != NULL)
            opts->usingPSK_cipher    = 1;
        break;
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_128_CCM
    case TLS_PSK_WITH_AES_128_CCM :
        specs->bulk_cipher_algorithm = wolfssl_aes_ccm;
        specs->cipher_type           = aead;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = psk_kea;
        specs->sig_algo              = anonymous_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_128_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AESCCM_IMP_IV_SZ;
        specs->aead_mac_size         = AES_CCM_16_AUTH_SZ;

        if (opts != NULL)
            opts->usingPSK_cipher    = 1;
        break;
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_256_CCM
    case TLS_PSK_WITH_AES_256_CCM :
        specs->bulk_cipher_algorithm = wolfssl_aes_ccm;
        specs->cipher_type           = aead;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = psk_kea;
        specs->sig_algo              = anonymous_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_256_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AESCCM_IMP_IV_SZ;
        specs->aead_mac_size         = AES_CCM_16_AUTH_SZ;

        if (opts != NULL)
            opts->usingPSK_cipher    = 1;
        break;
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_AES_128_CCM
    case TLS_DHE_PSK_WITH_AES_128_CCM :
        specs->bulk_cipher_algorithm = wolfssl_aes_ccm;
        specs->cipher_type           = aead;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = dhe_psk_kea;
        specs->sig_algo              = anonymous_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_128_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AESCCM_IMP_IV_SZ;
        specs->aead_mac_size         = AES_CCM_16_AUTH_SZ;

        if (opts != NULL)
            opts->usingPSK_cipher    = 1;
        break;
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_AES_256_CCM
    case TLS_DHE_PSK_WITH_AES_256_CCM :
        specs->bulk_cipher_algorithm = wolfssl_aes_ccm;
        specs->cipher_type           = aead;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = dhe_psk_kea;
        specs->sig_algo              = anonymous_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_256_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AESCCM_IMP_IV_SZ;
        specs->aead_mac_size         = AES_CCM_16_AUTH_SZ;

        if (opts != NULL)
            opts->usingPSK_cipher    = 1;
        break;
#endif

#if defined(WOLFSSL_TLS13) && defined(HAVE_NULL_CIPHER)
    #ifdef BUILD_TLS_SHA256_SHA256
    case TLS_SHA256_SHA256 :
        specs->bulk_cipher_algorithm = wolfssl_cipher_null;
        specs->cipher_type           = aead;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = any_kea;
        specs->sig_algo              = any_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = WC_SHA256_DIGEST_SIZE;
        specs->block_size            = 0;
        specs->iv_size               = HMAC_NONCE_SZ;
        specs->aead_mac_size         = WC_SHA256_DIGEST_SIZE;

        break;
    #endif

    #ifdef BUILD_TLS_SHA384_SHA384
    case TLS_SHA384_SHA384 :
        specs->bulk_cipher_algorithm = wolfssl_cipher_null;
        specs->cipher_type           = aead;
        specs->mac_algorithm         = sha384_mac;
        specs->kea                   = any_kea;
        specs->sig_algo              = any_sa_algo;
        specs->hash_size             = WC_SHA384_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = WC_SHA384_DIGEST_SIZE;
        specs->block_size            = 0;
        specs->iv_size               = HMAC_NONCE_SZ;
        specs->aead_mac_size         = WC_SHA384_DIGEST_SIZE;

        break;
    #endif
#endif

    default:
        WOLFSSL_MSG("Unsupported cipher suite, SetCipherSpecs ECC");
        return UNSUPPORTED_SUITE;
    }   /* switch */
    }   /* if     */

    /* TLSi v1.3 cipher suites, 0x13 */
    if (cipherSuite0 == TLS13_BYTE) {
        switch (cipherSuite) {

#ifdef WOLFSSL_TLS13
    #ifdef BUILD_TLS_AES_128_GCM_SHA256
        case TLS_AES_128_GCM_SHA256 :
            specs->bulk_cipher_algorithm = wolfssl_aes_gcm;
            specs->cipher_type           = aead;
            specs->mac_algorithm         = sha256_mac;
            specs->kea                   = any_kea;
            specs->sig_algo              = any_sa_algo;
            specs->hash_size             = WC_SHA256_DIGEST_SIZE;
            specs->pad_size              = PAD_SHA;
            specs->static_ecdh           = 0;
            specs->key_size              = AES_128_KEY_SIZE;
            specs->block_size            = WC_AES_BLOCK_SIZE;
            specs->iv_size               = AESGCM_NONCE_SZ;
            specs->aead_mac_size         = AES_GCM_AUTH_SZ;

            break;
    #endif

    #ifdef BUILD_TLS_AES_256_GCM_SHA384
        case TLS_AES_256_GCM_SHA384 :
            specs->bulk_cipher_algorithm = wolfssl_aes_gcm;
            specs->cipher_type           = aead;
            specs->mac_algorithm         = sha384_mac;
            specs->kea                   = any_kea;
            specs->sig_algo              = any_sa_algo;
            specs->hash_size             = WC_SHA384_DIGEST_SIZE;
            specs->pad_size              = PAD_SHA;
            specs->static_ecdh           = 0;
            specs->key_size              = AES_256_KEY_SIZE;
            specs->block_size            = WC_AES_BLOCK_SIZE;
            specs->iv_size               = AESGCM_NONCE_SZ;
            specs->aead_mac_size         = AES_GCM_AUTH_SZ;

            break;
    #endif

    #ifdef BUILD_TLS_CHACHA20_POLY1305_SHA256
        case TLS_CHACHA20_POLY1305_SHA256 :
            specs->bulk_cipher_algorithm = wolfssl_chacha;
            specs->cipher_type           = aead;
            specs->mac_algorithm         = sha256_mac;
            specs->kea                   = any_kea;
            specs->sig_algo              = any_sa_algo;
            specs->hash_size             = WC_SHA256_DIGEST_SIZE;
            specs->pad_size              = PAD_SHA;
            specs->static_ecdh           = 0;
            specs->key_size              = CHACHA20_256_KEY_SIZE;
            specs->block_size            = CHACHA20_BLOCK_SIZE;
            specs->iv_size               = CHACHA20_IV_SIZE;
            specs->aead_mac_size         = POLY1305_AUTH_SZ;
            if (opts != NULL)
                opts->oldPoly            = 0; /* use recent padding RFC */

            break;
    #endif

    #ifdef BUILD_TLS_AES_128_CCM_SHA256
        case TLS_AES_128_CCM_SHA256 :
            specs->bulk_cipher_algorithm = wolfssl_aes_ccm;
            specs->cipher_type           = aead;
            specs->mac_algorithm         = sha256_mac;
            specs->kea                   = any_kea;
            specs->sig_algo              = any_sa_algo;
            specs->hash_size             = WC_SHA256_DIGEST_SIZE;
            specs->pad_size              = PAD_SHA;
            specs->static_ecdh           = 0;
            specs->key_size              = AES_128_KEY_SIZE;
            specs->block_size            = WC_AES_BLOCK_SIZE;
            specs->iv_size               = AESCCM_NONCE_SZ;
            specs->aead_mac_size         = AES_CCM_16_AUTH_SZ;

            break;
    #endif

    #ifdef BUILD_TLS_AES_128_CCM_8_SHA256
        case TLS_AES_128_CCM_8_SHA256 :
            specs->bulk_cipher_algorithm = wolfssl_aes_ccm;
            specs->cipher_type           = aead;
            specs->mac_algorithm         = sha256_mac;
            specs->kea                   = any_kea;
            specs->sig_algo              = any_sa_algo;
            specs->hash_size             = WC_SHA256_DIGEST_SIZE;
            specs->pad_size              = PAD_SHA;
            specs->static_ecdh           = 0;
            specs->key_size              = AES_128_KEY_SIZE;
            specs->block_size            = WC_AES_BLOCK_SIZE;
            specs->iv_size               = AESCCM_NONCE_SZ;
            specs->aead_mac_size         = AES_CCM_8_AUTH_SZ;

            break;
    #endif
#endif /* WOLFSSL_TLS13 */
        default:
            break;
        }
    }

    if (cipherSuite0 == ECDHE_PSK_BYTE) {

    switch (cipherSuite) {

#if defined(HAVE_ECC) || defined(HAVE_CURVE25519) || defined(HAVE_CURVE448)
#ifdef BUILD_TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256
    case TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256 :
        specs->bulk_cipher_algorithm = wolfssl_aes_gcm;
        specs->cipher_type           = aead;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = ecdhe_psk_kea;
        specs->sig_algo              = anonymous_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_128_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AESGCM_IMP_IV_SZ;
        specs->aead_mac_size         = AES_GCM_AUTH_SZ;

        if (opts != NULL)
            opts->usingPSK_cipher    = 1;
        break;
#endif
#endif

    default:
        break;
    }
    }

    if (cipherSuite0 == SM_BYTE) {

    switch (cipherSuite) {
#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_SM4_CBC_SM3
    case TLS_ECDHE_ECDSA_WITH_SM4_CBC_SM3 :
        specs->bulk_cipher_algorithm = wolfssl_sm4_cbc;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sm3_mac;
        specs->kea                   = ecc_diffie_hellman_kea;
        specs->sig_algo              = sm2_sa_algo;
        specs->hash_size             = WC_SM3_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = SM4_KEY_SIZE;
        specs->iv_size               = SM4_IV_SIZE;
        specs->block_size            = SM4_BLOCK_SIZE;

        break;
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_SM4_GCM_SM3
    case TLS_ECDHE_ECDSA_WITH_SM4_GCM_SM3 :
        specs->bulk_cipher_algorithm = wolfssl_sm4_gcm;
        specs->cipher_type           = aead;
        specs->mac_algorithm         = sm3_mac;
        specs->kea                   = ecc_diffie_hellman_kea;
        specs->sig_algo              = sm2_sa_algo;
        specs->hash_size             = WC_SM3_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = SM4_KEY_SIZE;
        specs->block_size            = SM4_BLOCK_SIZE;
        specs->iv_size               = GCM_IMP_IV_SZ;
        specs->aead_mac_size         = SM4_GCM_AUTH_SZ;

        break;
#endif

#ifdef BUILD_TLS_ECDHE_ECDSA_WITH_SM4_CCM_SM3
    case TLS_ECDHE_ECDSA_WITH_SM4_CCM_SM3 :
        specs->bulk_cipher_algorithm = wolfssl_sm4_ccm;
        specs->cipher_type           = aead;
        specs->mac_algorithm         = sm3_mac;
        specs->kea                   = ecc_diffie_hellman_kea;
        specs->sig_algo              = sm2_sa_algo;
        specs->hash_size             = WC_SM3_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = SM4_KEY_SIZE;
        specs->block_size            = SM4_BLOCK_SIZE;
        specs->iv_size               = CCM_IMP_IV_SZ;
        specs->aead_mac_size         = SM4_CCM_AUTH_SZ;

        break;
#endif

    default:
        break;
    }
    }

    if (cipherSuite0 != ECC_BYTE &&
        cipherSuite0 != ECDHE_PSK_BYTE &&
        cipherSuite0 != CHACHA_BYTE &&
#if defined(WOLFSSL_SM2) && defined(WOLFSSL_SM3) && \
    (defined(WOLFSSL_SM4_CBC) || defined(WOLFSSL_SM4_GCM) || \
     defined(WOLFSSL_SM4_CCM))
        cipherSuite0 != SM_BYTE &&
#endif
        cipherSuite0 != TLS13_BYTE) {   /* normal suites */
    switch (cipherSuite) {

#ifdef BUILD_TLS_SM4_GCM_SM3
    case TLS_SM4_GCM_SM3 :
        specs->bulk_cipher_algorithm = wolfssl_sm4_gcm;
        specs->cipher_type           = aead;
        specs->mac_algorithm         = sm3_mac;
        specs->kea                   = any_kea;
        specs->sig_algo              = any_sa_algo;
        specs->hash_size             = WC_SM3_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = SM4_KEY_SIZE;
        specs->block_size            = SM4_BLOCK_SIZE;
        specs->iv_size               = SM4_GCM_NONCE_SZ;
        specs->aead_mac_size         = SM4_GCM_AUTH_SZ;

        break;
#endif

#ifdef BUILD_TLS_SM4_CCM_SM3
    case TLS_SM4_CCM_SM3 :
        specs->bulk_cipher_algorithm = wolfssl_sm4_ccm;
        specs->cipher_type           = aead;
        specs->mac_algorithm         = sm3_mac;
        specs->kea                   = any_kea;
        specs->sig_algo              = any_sa_algo;
        specs->hash_size             = WC_SM3_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = SM4_KEY_SIZE;
        specs->block_size            = SM4_BLOCK_SIZE;
        specs->iv_size               = SM4_CCM_NONCE_SZ;
        specs->aead_mac_size         = SM4_CCM_AUTH_SZ;

        break;
#endif

#ifdef BUILD_SSL_RSA_WITH_RC4_128_SHA
    case SSL_RSA_WITH_RC4_128_SHA :
        specs->bulk_cipher_algorithm = wolfssl_rc4;
        specs->cipher_type           = stream;
        specs->mac_algorithm         = sha_mac;
        specs->kea                   = rsa_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_SHA_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = RC4_KEY_SIZE;
        specs->iv_size               = 0;
        specs->block_size            = 0;

        break;
#endif

#ifdef BUILD_SSL_RSA_WITH_RC4_128_MD5
    case SSL_RSA_WITH_RC4_128_MD5 :
        specs->bulk_cipher_algorithm = wolfssl_rc4;
        specs->cipher_type           = stream;
        specs->mac_algorithm         = md5_mac;
        specs->kea                   = rsa_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_MD5_DIGEST_SIZE;
        specs->pad_size              = PAD_MD5;
        specs->static_ecdh           = 0;
        specs->key_size              = RC4_KEY_SIZE;
        specs->iv_size               = 0;
        specs->block_size            = 0;

        break;
#endif

#ifdef BUILD_SSL_RSA_WITH_3DES_EDE_CBC_SHA
    case SSL_RSA_WITH_3DES_EDE_CBC_SHA :
        specs->bulk_cipher_algorithm = wolfssl_triple_des;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sha_mac;
        specs->kea                   = rsa_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_SHA_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = DES3_KEY_SIZE;
        specs->block_size            = DES_BLOCK_SIZE;
#if defined(HAVE_FIPS) && defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION == 2)
        specs->iv_size               = DES_BLOCK_SIZE;
#else
        specs->iv_size               = DES_IV_SIZE;
#endif

        break;
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_128_CBC_SHA
    case TLS_RSA_WITH_AES_128_CBC_SHA :
        specs->bulk_cipher_algorithm = wolfssl_aes;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sha_mac;
        specs->kea                   = rsa_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_SHA_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_128_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AES_IV_SIZE;

        break;
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_128_CBC_SHA256
    case TLS_RSA_WITH_AES_128_CBC_SHA256 :
        specs->bulk_cipher_algorithm = wolfssl_aes;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = rsa_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_128_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AES_IV_SIZE;

        break;
#endif

#ifdef BUILD_TLS_RSA_WITH_NULL_MD5
    case TLS_RSA_WITH_NULL_MD5 :
        specs->bulk_cipher_algorithm = wolfssl_cipher_null;
        specs->cipher_type           = stream;
        specs->mac_algorithm         = md5_mac;
        specs->kea                   = rsa_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_MD5_DIGEST_SIZE;
        specs->pad_size              = PAD_MD5;
        specs->static_ecdh           = 0;
        specs->key_size              = 0;
        specs->block_size            = 0;
        specs->iv_size               = 0;

        break;
#endif

#ifdef BUILD_TLS_RSA_WITH_NULL_SHA
    case TLS_RSA_WITH_NULL_SHA :
        specs->bulk_cipher_algorithm = wolfssl_cipher_null;
        specs->cipher_type           = stream;
        specs->mac_algorithm         = sha_mac;
        specs->kea                   = rsa_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_SHA_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = 0;
        specs->block_size            = 0;
        specs->iv_size               = 0;

        break;
#endif

#ifdef BUILD_TLS_RSA_WITH_NULL_SHA256
    case TLS_RSA_WITH_NULL_SHA256 :
        specs->bulk_cipher_algorithm = wolfssl_cipher_null;
        specs->cipher_type           = stream;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = rsa_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = 0;
        specs->block_size            = 0;
        specs->iv_size               = 0;

        break;
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_256_CBC_SHA
    case TLS_RSA_WITH_AES_256_CBC_SHA :
        specs->bulk_cipher_algorithm = wolfssl_aes;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sha_mac;
        specs->kea                   = rsa_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_SHA_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_256_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AES_IV_SIZE;

        break;
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_256_CBC_SHA256
    case TLS_RSA_WITH_AES_256_CBC_SHA256 :
        specs->bulk_cipher_algorithm = wolfssl_aes;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = rsa_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_256_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AES_IV_SIZE;

        break;
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_128_GCM_SHA256
    case TLS_PSK_WITH_AES_128_GCM_SHA256 :
        specs->bulk_cipher_algorithm = wolfssl_aes_gcm;
        specs->cipher_type           = aead;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = psk_kea;
        specs->sig_algo              = anonymous_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_128_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AESGCM_IMP_IV_SZ;
        specs->aead_mac_size         = AES_GCM_AUTH_SZ;

        if (opts != NULL)
            opts->usingPSK_cipher    = 1;
        break;
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_256_GCM_SHA384
    case TLS_PSK_WITH_AES_256_GCM_SHA384 :
        specs->bulk_cipher_algorithm = wolfssl_aes_gcm;
        specs->cipher_type           = aead;
        specs->mac_algorithm         = sha384_mac;
        specs->kea                   = psk_kea;
        specs->sig_algo              = anonymous_sa_algo;
        specs->hash_size             = WC_SHA384_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_256_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AESGCM_IMP_IV_SZ;
        specs->aead_mac_size         = AES_GCM_AUTH_SZ;

        if (opts != NULL)
            opts->usingPSK_cipher    = 1;
        break;
#endif

#ifdef BUILD_TLS_DH_anon_WITH_AES_256_GCM_SHA384
    case TLS_DH_anon_WITH_AES_256_GCM_SHA384:
        specs->bulk_cipher_algorithm = wolfssl_aes_gcm;
        specs->cipher_type           = aead;
        specs->mac_algorithm         = sha384_mac;
        specs->kea                   = diffie_hellman_kea;
        specs->sig_algo              = anonymous_sa_algo;
        specs->hash_size             = WC_SHA384_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_256_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AESGCM_IMP_IV_SZ;
        specs->aead_mac_size         = AES_GCM_AUTH_SZ;

        if (opts != NULL)
            opts->usingAnon_cipher   = 1;
        break;
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_AES_128_GCM_SHA256
    case TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 :
        specs->bulk_cipher_algorithm = wolfssl_aes_gcm;
        specs->cipher_type           = aead;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = dhe_psk_kea;
        specs->sig_algo              = anonymous_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_128_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AESGCM_IMP_IV_SZ;
        specs->aead_mac_size         = AES_GCM_AUTH_SZ;

        if (opts != NULL)
            opts->usingPSK_cipher    = 1;
        break;
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_AES_256_GCM_SHA384
    case TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 :
        specs->bulk_cipher_algorithm = wolfssl_aes_gcm;
        specs->cipher_type           = aead;
        specs->mac_algorithm         = sha384_mac;
        specs->kea                   = dhe_psk_kea;
        specs->sig_algo              = anonymous_sa_algo;
        specs->hash_size             = WC_SHA384_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_256_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AESGCM_IMP_IV_SZ;
        specs->aead_mac_size         = AES_GCM_AUTH_SZ;

        if (opts != NULL)
            opts->usingPSK_cipher    = 1;
        break;
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_128_CBC_SHA256
    case TLS_PSK_WITH_AES_128_CBC_SHA256 :
        specs->bulk_cipher_algorithm = wolfssl_aes;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = psk_kea;
        specs->sig_algo              = anonymous_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_128_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AES_IV_SIZE;

        if (opts != NULL)
            opts->usingPSK_cipher    = 1;
        break;
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_256_CBC_SHA384
    case TLS_PSK_WITH_AES_256_CBC_SHA384 :
        specs->bulk_cipher_algorithm = wolfssl_aes;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sha384_mac;
        specs->kea                   = psk_kea;
        specs->sig_algo              = anonymous_sa_algo;
        specs->hash_size             = WC_SHA384_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_256_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AES_IV_SIZE;

        if (opts != NULL)
            opts->usingPSK_cipher    = 1;
        break;
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_AES_128_CBC_SHA256
    case TLS_DHE_PSK_WITH_AES_128_CBC_SHA256 :
        specs->bulk_cipher_algorithm = wolfssl_aes;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = dhe_psk_kea;
        specs->sig_algo              = anonymous_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_128_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AES_IV_SIZE;

        if (opts != NULL)
            opts->usingPSK_cipher    = 1;
        break;
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_AES_256_CBC_SHA384
    case TLS_DHE_PSK_WITH_AES_256_CBC_SHA384 :
        specs->bulk_cipher_algorithm = wolfssl_aes;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sha384_mac;
        specs->kea                   = dhe_psk_kea;
        specs->sig_algo              = anonymous_sa_algo;
        specs->hash_size             = WC_SHA384_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_256_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AES_IV_SIZE;

        if (opts != NULL)
            opts->usingPSK_cipher    = 1;
        break;
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_128_CBC_SHA
    case TLS_PSK_WITH_AES_128_CBC_SHA :
        specs->bulk_cipher_algorithm = wolfssl_aes;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sha_mac;
        specs->kea                   = psk_kea;
        specs->sig_algo              = anonymous_sa_algo;
        specs->hash_size             = WC_SHA_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_128_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AES_IV_SIZE;

        if (opts != NULL)
            opts->usingPSK_cipher    = 1;
        break;
#endif

#ifdef BUILD_TLS_PSK_WITH_AES_256_CBC_SHA
    case TLS_PSK_WITH_AES_256_CBC_SHA :
        specs->bulk_cipher_algorithm = wolfssl_aes;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sha_mac;
        specs->kea                   = psk_kea;
        specs->sig_algo              = anonymous_sa_algo;
        specs->hash_size             = WC_SHA_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_256_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AES_IV_SIZE;

        if (opts != NULL)
            opts->usingPSK_cipher    = 1;
        break;
#endif

#ifdef BUILD_TLS_PSK_WITH_NULL_SHA256
    case TLS_PSK_WITH_NULL_SHA256 :
        specs->bulk_cipher_algorithm = wolfssl_cipher_null;
        specs->cipher_type           = stream;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = psk_kea;
        specs->sig_algo              = anonymous_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = 0;
        specs->block_size            = 0;
        specs->iv_size               = 0;

        if (opts != NULL)
            opts->usingPSK_cipher    = 1;
        break;
#endif

#ifdef BUILD_TLS_PSK_WITH_NULL_SHA384
    case TLS_PSK_WITH_NULL_SHA384 :
        specs->bulk_cipher_algorithm = wolfssl_cipher_null;
        specs->cipher_type           = stream;
        specs->mac_algorithm         = sha384_mac;
        specs->kea                   = psk_kea;
        specs->sig_algo              = anonymous_sa_algo;
        specs->hash_size             = WC_SHA384_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = 0;
        specs->block_size            = 0;
        specs->iv_size               = 0;

        if (opts != NULL)
            opts->usingPSK_cipher    = 1;
        break;
#endif

#ifdef BUILD_TLS_PSK_WITH_NULL_SHA
    case TLS_PSK_WITH_NULL_SHA :
        specs->bulk_cipher_algorithm = wolfssl_cipher_null;
        specs->cipher_type           = stream;
        specs->mac_algorithm         = sha_mac;
        specs->kea                   = psk_kea;
        specs->sig_algo              = anonymous_sa_algo;
        specs->hash_size             = WC_SHA_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = 0;
        specs->block_size            = 0;
        specs->iv_size               = 0;

        if (opts != NULL)
            opts->usingPSK_cipher    = 1;
        break;
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_NULL_SHA256
    case TLS_DHE_PSK_WITH_NULL_SHA256 :
        specs->bulk_cipher_algorithm = wolfssl_cipher_null;
        specs->cipher_type           = stream;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = dhe_psk_kea;
        specs->sig_algo              = anonymous_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = 0;
        specs->block_size            = 0;
        specs->iv_size               = 0;

        if (opts != NULL)
            opts->usingPSK_cipher    = 1;
        break;
#endif

#ifdef BUILD_TLS_DHE_PSK_WITH_NULL_SHA384
    case TLS_DHE_PSK_WITH_NULL_SHA384 :
        specs->bulk_cipher_algorithm = wolfssl_cipher_null;
        specs->cipher_type           = stream;
        specs->mac_algorithm         = sha384_mac;
        specs->kea                   = dhe_psk_kea;
        specs->sig_algo              = anonymous_sa_algo;
        specs->hash_size             = WC_SHA384_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = 0;
        specs->block_size            = 0;
        specs->iv_size               = 0;

        if (opts != NULL)
            opts->usingPSK_cipher    = 1;
        break;
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
    case TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 :
        specs->bulk_cipher_algorithm = wolfssl_aes;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = diffie_hellman_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_128_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AES_IV_SIZE;

        break;
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
    case TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA :
        specs->bulk_cipher_algorithm = wolfssl_triple_des;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sha_mac;
        specs->kea                   = diffie_hellman_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_SHA_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = DES3_KEY_SIZE;
        specs->block_size            = DES_BLOCK_SIZE;
        specs->iv_size               = DES_IV_SIZE;

        break;
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
    case TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 :
        specs->bulk_cipher_algorithm = wolfssl_aes;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = diffie_hellman_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_256_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AES_IV_SIZE;

        break;
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_128_CBC_SHA
    case TLS_DHE_RSA_WITH_AES_128_CBC_SHA :
        specs->bulk_cipher_algorithm = wolfssl_aes;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sha_mac;
        specs->kea                   = diffie_hellman_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_SHA_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_128_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AES_IV_SIZE;

        break;
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_256_CBC_SHA
    case TLS_DHE_RSA_WITH_AES_256_CBC_SHA :
        specs->bulk_cipher_algorithm = wolfssl_aes;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sha_mac;
        specs->kea                   = diffie_hellman_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_SHA_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_256_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AES_IV_SIZE;

        break;
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_128_GCM_SHA256
    case TLS_RSA_WITH_AES_128_GCM_SHA256 :
        specs->bulk_cipher_algorithm = wolfssl_aes_gcm;
        specs->cipher_type           = aead;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = rsa_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_128_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AESGCM_IMP_IV_SZ;
        specs->aead_mac_size         = AES_GCM_AUTH_SZ;

        break;
#endif

#ifdef BUILD_TLS_RSA_WITH_AES_256_GCM_SHA384
    case TLS_RSA_WITH_AES_256_GCM_SHA384 :
        specs->bulk_cipher_algorithm = wolfssl_aes_gcm;
        specs->cipher_type           = aead;
        specs->mac_algorithm         = sha384_mac;
        specs->kea                   = rsa_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_SHA384_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_256_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AESGCM_IMP_IV_SZ;
        specs->aead_mac_size         = AES_GCM_AUTH_SZ;

        break;
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
    case TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 :
        specs->bulk_cipher_algorithm = wolfssl_aes_gcm;
        specs->cipher_type           = aead;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = diffie_hellman_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_128_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AESGCM_IMP_IV_SZ;
        specs->aead_mac_size         = AES_GCM_AUTH_SZ;

        break;
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
    case TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 :
        specs->bulk_cipher_algorithm = wolfssl_aes_gcm;
        specs->cipher_type           = aead;
        specs->mac_algorithm         = sha384_mac;
        specs->kea                   = diffie_hellman_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_SHA384_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_256_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AESGCM_IMP_IV_SZ;
        specs->aead_mac_size         = AES_GCM_AUTH_SZ;

        break;
#endif

#ifdef BUILD_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA
    case TLS_RSA_WITH_CAMELLIA_128_CBC_SHA :
        specs->bulk_cipher_algorithm = wolfssl_camellia;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sha_mac;
        specs->kea                   = rsa_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_SHA_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = CAMELLIA_128_KEY_SIZE;
        specs->block_size            = WC_CAMELLIA_BLOCK_SIZE;
        specs->iv_size               = CAMELLIA_IV_SIZE;

        break;
#endif

#ifdef BUILD_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA
    case TLS_RSA_WITH_CAMELLIA_256_CBC_SHA :
        specs->bulk_cipher_algorithm = wolfssl_camellia;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sha_mac;
        specs->kea                   = rsa_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_SHA_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = CAMELLIA_256_KEY_SIZE;
        specs->block_size            = WC_CAMELLIA_BLOCK_SIZE;
        specs->iv_size               = CAMELLIA_IV_SIZE;

        break;
#endif

#ifdef BUILD_TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256
    case TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256 :
        specs->bulk_cipher_algorithm = wolfssl_camellia;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = rsa_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = CAMELLIA_128_KEY_SIZE;
        specs->block_size            = WC_CAMELLIA_BLOCK_SIZE;
        specs->iv_size               = CAMELLIA_IV_SIZE;

        break;
#endif

#ifdef BUILD_TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256
    case TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256 :
        specs->bulk_cipher_algorithm = wolfssl_camellia;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = rsa_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = CAMELLIA_256_KEY_SIZE;
        specs->block_size            = WC_CAMELLIA_BLOCK_SIZE;
        specs->iv_size               = CAMELLIA_IV_SIZE;

        break;
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA
    case TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA :
        specs->bulk_cipher_algorithm = wolfssl_camellia;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sha_mac;
        specs->kea                   = diffie_hellman_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_SHA_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = CAMELLIA_128_KEY_SIZE;
        specs->block_size            = WC_CAMELLIA_BLOCK_SIZE;
        specs->iv_size               = CAMELLIA_IV_SIZE;

        break;
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA
    case TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA :
        specs->bulk_cipher_algorithm = wolfssl_camellia;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sha_mac;
        specs->kea                   = diffie_hellman_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_SHA_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = CAMELLIA_256_KEY_SIZE;
        specs->block_size            = WC_CAMELLIA_BLOCK_SIZE;
        specs->iv_size               = CAMELLIA_IV_SIZE;

        break;
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256
    case TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256 :
        specs->bulk_cipher_algorithm = wolfssl_camellia;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = diffie_hellman_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = CAMELLIA_128_KEY_SIZE;
        specs->block_size            = WC_CAMELLIA_BLOCK_SIZE;
        specs->iv_size               = CAMELLIA_IV_SIZE;

        break;
#endif

#ifdef BUILD_TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256
    case TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256 :
        specs->bulk_cipher_algorithm = wolfssl_camellia;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sha256_mac;
        specs->kea                   = diffie_hellman_kea;
        specs->sig_algo              = rsa_sa_algo;
        specs->hash_size             = WC_SHA256_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = CAMELLIA_256_KEY_SIZE;
        specs->block_size            = WC_CAMELLIA_BLOCK_SIZE;
        specs->iv_size               = CAMELLIA_IV_SIZE;

        break;
#endif

#ifdef BUILD_TLS_DH_anon_WITH_AES_128_CBC_SHA
    case TLS_DH_anon_WITH_AES_128_CBC_SHA :
        specs->bulk_cipher_algorithm = wolfssl_aes;
        specs->cipher_type           = block;
        specs->mac_algorithm         = sha_mac;
        specs->kea                   = diffie_hellman_kea;
        specs->sig_algo              = anonymous_sa_algo;
        specs->hash_size             = WC_SHA_DIGEST_SIZE;
        specs->pad_size              = PAD_SHA;
        specs->static_ecdh           = 0;
        specs->key_size              = AES_128_KEY_SIZE;
        specs->block_size            = WC_AES_BLOCK_SIZE;
        specs->iv_size               = AES_IV_SIZE;

        if (opts != NULL)
            opts->usingAnon_cipher   = 1;
        break;
#endif

#ifdef BUILD_WDM_WITH_NULL_SHA256
        case WDM_WITH_NULL_SHA256 :
            specs->bulk_cipher_algorithm = wolfssl_cipher_null;
            specs->cipher_type           = stream;
            specs->mac_algorithm         = sha256_mac;
            specs->kea                   = no_kea;
            specs->sig_algo              = anonymous_sa_algo;
            specs->hash_size             = WC_SHA256_DIGEST_SIZE;
            specs->pad_size              = PAD_SHA;

            break;
#endif

    default:
        WOLFSSL_MSG("Unsupported cipher suite, SetCipherSpecs");
        WOLFSSL_ERROR_VERBOSE(UNSUPPORTED_SUITE);
        return UNSUPPORTED_SUITE;
    }  /* switch */
    }  /* if ECC / Normal suites else */

    if (specs->sig_algo == anonymous_sa_algo && opts != NULL) {
        /* CLIENT/SERVER: No peer authentication to be performed. */
        opts->peerAuthGood = 1;
    }

    return 0;
}


enum KeyStuff {
    MASTER_ROUNDS = 3,
    PREFIX        = 3,     /* up to three letters for master prefix */
    KEY_PREFIX    = 9      /* up to 9 prefix letters for key rounds */


};

#ifndef NO_OLD_TLS
/* true or false, zero for error */
static int SetPrefix(byte* sha_input, int idx)
{
    switch (idx) {
    case 0:
        XMEMCPY(sha_input, "A", 1);
        break;
    case 1:
        XMEMCPY(sha_input, "BB", 2);
        break;
    case 2:
        XMEMCPY(sha_input, "CCC", 3);
        break;
    case 3:
        XMEMCPY(sha_input, "DDDD", 4);
        break;
    case 4:
        XMEMCPY(sha_input, "EEEEE", 5);
        break;
    case 5:
        XMEMCPY(sha_input, "FFFFFF", 6);
        break;
    case 6:
        XMEMCPY(sha_input, "GGGGGGG", 7);
        break;
    case 7:
        XMEMCPY(sha_input, "HHHHHHHH", 8);
        break;
    case 8:
        XMEMCPY(sha_input, "IIIIIIIII", 9);
        break;
    default:
        WOLFSSL_MSG("Set Prefix error, bad input");
        return 0;
    }
    return 1;
}
#endif

/* MALLOC
    -- maybe not appropriate..
    -- would you like me to expand this where it is used?
*/
#define MALLOC(var, ty, heap, type) \
    do {var = (ty*)XMALLOC(sizeof(ty), heap, type); \
        if (var == NULL) return MEMORY_E; }while(0)

#define write_key  server == decode ? keys->client_write_key \
                                    : keys->server_write_key
#define write_IV   server == decode ? keys->client_write_IV  \
                                    : keys->server_write_IV
#define imp_IV     decode ? keys->aead_dec_imp_IV \
                          : keys->aead_enc_imp_IV
#ifdef BUILD_ARC4
#define IF_ARC4(a,b) a
static int rc4_init(Ciphers* c, CipherSpecs* specs,
                    void* heap, int devId, int tls13)
{
    (void)specs;
    (void)tls13;
    if (c->arc4 == NULL)
        MALLOC(c->arc4, Arc4, heap, DYNAMIC_TYPE_CIPHER);
    if (wc_Arc4Init(c->arc4, heap, devId) != 0) {
        WOLFSSL_MSG("Arc4Init failed in rc4_init");
        return ASYNC_INIT_E;
    }
    return 0;
}
static int rc4_setkey(Ciphers* c, int decode, int server, Keys* keys,
    CipherSpecs* specs, WC_RNG* rng, int tls13)
{
    (void)rng;
    (void)tls13;
    wc_Arc4SetKey(c->arc4, write_key, specs->key_size);
    return 0;
}
#else
#define IF_ARC4(a,b) b
#endif /* BUILD_ARC4 */

#if defined(HAVE_CHACHA) && defined(HAVE_POLY1305) && !defined(NO_CHAPOL_AEAD)
    /* Check that the max implicit iv size is sufficient */
    #if (AEAD_MAX_IMP_SZ < 12) /* CHACHA20_IMP_IV_SZ */
        #error AEAD_MAX_IMP_SZ is too small for ChaCha20
    #endif
    #if (MAX_WRITE_IV_SZ < 12) /* CHACHA20_IMP_IV_SZ */
        #error MAX_WRITE_IV_SZ is too small for ChaCha20
    #endif
#define IF_CHACHA(a,b) a
static int chacha_init(Ciphers* c, CipherSpecs* specs,
                       void* heap, int devId, int tls13)
{
    (void)specs;
    (void)tls13;
    (void)devId;
    if (c->chacha == NULL)
        MALLOC(c->chacha, ChaCha, heap, DYNAMIC_TYPE_CIPHER);
#ifdef WOLFSSL_CHECK_MEM_ZERO
    wc_MemZero_Add("SSL keys enc/dec chacha",
                   c->chacha, sizeof(ChaCha));
#endif
    return 0;
}
static int chacha_setkey(Ciphers* c, int decode, int server, Keys* keys,
    CipherSpecs* specs, WC_RNG* rng, int tls13)
{
    (void)rng;
    (void)tls13;
    int ret = wc_Chacha_SetKey(c->chacha, write_key, specs->key_size);
    if (ret != 0)
        return ret;
    XMEMCPY(imp_IV, write_IV, CHACHA20_IMP_IV_SZ);
    return 0;
}
#else
#define IF_CHACHA(a,b) b
#endif

#ifdef BUILD_DES3
    /* check that buffer sizes are sufficient */
    #if (MAX_WRITE_IV_SZ < 8) /* DES_IV_SIZE */
        #error MAX_WRITE_IV_SZ too small for 3DES
    #endif
#define IF_DES3(a,b) a
static int des3_init(Ciphers* c, CipherSpecs* specs,
                     void* heap, int devId, int tls13)
{
    (void)specs;
    (void)tls13;
    if (c->des3 == NULL)
        MALLOC(c->des3, Des3, heap, DYNAMIC_TYPE_CIPHER);
    XMEMSET(c->des3, 0, sizeof(Des3));
    if (wc_Des3Init(c->des3, heap, devId) != 0) {
        WOLFSSL_MSG("Des3Init failed in des3_init");
        return ASYNC_INIT_E;
    }
    return 0;
}
static int des3_setkey(Ciphers* c, int decode, int server, Keys* keys,
    CipherSpecs* specs, WC_RNG* rng, int tls13)
{
    (void)specs;
    (void)rng;
    (void)tls13;
    return wc_Des3_SetKey(c->des3, write_key, write_IV,
        decode ? DES_DECRYPTION : DES_ENCRYPTION);
}
#else
#define IF_DES3(a,b) b
#endif /* BUILD_DES3 */

#ifdef BUILD_AES
    /* check that buffer sizes are sufficient */
    #if (MAX_WRITE_IV_SZ < 16) /* AES_IV_SIZE */
        #error MAX_WRITE_IV_SZ too small for AES
    #endif
#define IF_AES(a,b) a
static int aes_init(Ciphers* c, CipherSpecs* specs,
                    void* heap, int devId, int tls13)
{
    (void)specs;
    (void)tls13;
    if (c->aes == NULL)
        MALLOC(c->aes, Aes, heap, DYNAMIC_TYPE_CIPHER);
    else
        wc_AesFree(c->aes);
    XMEMSET(c->aes, 0, sizeof(Aes));
    if (wc_AesInit(c->aes, heap, devId) != 0) {
        WOLFSSL_MSG("AesInit failed in aes_init");
        return ASYNC_INIT_E;
    }
    return 0;
}
static int aes_setkey(Ciphers* c, int decode, int server, Keys* keys,
    CipherSpecs* specs, WC_RNG* rng, int tls13)
{
    (void)rng;
    (void)tls13;
    return wc_AesSetKey(c->aes, write_key, specs->key_size,
       write_IV, decode ? AES_DECRYPTION : AES_ENCRYPTION);
}
#else
#define IF_AES(a,b) a
#endif /* BUILD_AES */

#ifdef BUILD_AESGCM
    /* check that buffer sizes are sufficient */
    #if (AEAD_MAX_IMP_SZ < 4) /* AESGCM_IMP_IV_SZ */
        #error AEAD_MAX_IMP_SZ too small for AESGCM
    #endif
    #if (AEAD_MAX_EXP_SZ < 8) /* AESGCM_EXP_IV_SZ */
        #error AEAD_MAX_EXP_SZ too small for AESGCM
    #endif
    #if (MAX_WRITE_IV_SZ < 4) /* AESGCM_IMP_IV_SZ */
        #error MAX_WRITE_IV_SZ too small for AESGCM
    #endif
#define IF_AES_GCM(a,b) a
static int aes_gcm_init(Ciphers* c, CipherSpecs* specs,
                        void* heap, int devId, int tls13)
{
    (void)specs;
    (void)tls13;
    (void)devId;
    if (c->aes == NULL)
        MALLOC(c->aes, Aes, heap, DYNAMIC_TYPE_CIPHER);
    else
        wc_AesFree(c->aes);
    XMEMSET(c->aes, 0, sizeof(Aes));
    if (wc_AesInit(c->aes, heap, devId) != 0) {
        WOLFSSL_MSG("AesInit failed in aes_gcm_init");
        return ASYNC_INIT_E;
    }
    return 0;
}
static int aes_gcm_setkey(Ciphers* c, int decode, int server, Keys* keys,
    CipherSpecs* specs, WC_RNG* rng, int tls13)
{
    int ret;
    ret = wc_AesGcmSetKey(c->aes, write_key, specs->key_size);
    if (ret != 0)
        return ret;
    XMEMCPY(imp_IV, write_IV, AEAD_MAX_IMP_SZ);
#if !defined(NO_PUBLIC_GCM_SET_IV) && \
    ((!defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 2)))
    if (!decode && !tls13)
        return wc_AesGcmSetIV(c->aes, AESGCM_NONCE_SZ,
                write_IV, AESGCM_IMP_IV_SZ, rng);
#endif
    return 0;
}
#else
#define IF_AES_GCM(a,b) b
#endif /* BUILD_AESGCM */

#ifdef HAVE_AESCCM
    /* check that buffer sizes are sufficient (CCM is same size as GCM) */
    #if (AEAD_MAX_IMP_SZ < 4) /* AESGCM_IMP_IV_SZ */
        #error AEAD_MAX_IMP_SZ too small for AESCCM
    #endif
    #if (AEAD_MAX_EXP_SZ < 8) /* AESGCM_EXP_IV_SZ */
        #error AEAD_MAX_EXP_SZ too small for AESCCM
    #endif
    #if (MAX_WRITE_IV_SZ < 4) /* AESGCM_IMP_IV_SZ */
        #error MAX_WRITE_IV_SZ too small for AESCCM
    #endif
#define IF_AES_CCM(a,b) a
static int aes_ccm_init(Ciphers* c, CipherSpecs* specs,
                        void* heap, int devId, int tls13)
{
    (void)specs;
    (void)tls13;
    (void)devId;
    if (c->aes == NULL)
        MALLOC(c->aes, Aes, heap, DYNAMIC_TYPE_CIPHER);
    else
        wc_AesFree(c->aes);
    XMEMSET(c->aes, 0, sizeof(Aes));
    if (wc_AesInit(c->aes, heap, devId) != 0) {
        WOLFSSL_MSG("AesInit failed in aes_ccm_init");
        return ASYNC_INIT_E;
    }
    return 0;
}
static int aes_ccm_setkey(Ciphers* c, int decode, int server, Keys* keys,
    CipherSpecs* specs, WC_RNG* rng, int tls13)
{
    (void)rng;
    int ret;
    ret = wc_AesCcmSetKey(c->aes, write_key, specs->key_size);
    if (ret != 0)
        return ret;
    XMEMCPY(imp_IV, write_IV, AEAD_MAX_IMP_SZ);
#if !defined(NO_PUBLIC_CCM_SET_NONCE) && \
    ((!defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 2)))
    if (!decode && !tls13)
        return wc_AesCcmSetNonce(c->aes, write_IV, AEAD_MAX_IMP_SZ);
#endif
    return 0;
}
#else
#define IF_AES_CCM(a,b) b
#endif /* HAVE_AESCCM */

/*
   !! unable to test aria
*/
#if defined(HAVE_ARIA)
    /* check that buffer sizes are sufficient */
    #if (MAX_WRITE_IV_SZ < 16) /* AES_IV_SIZE */
        #error MAX_WRITE_IV_SZ too small for AES
    #endif
#define IF_ARIA(a,b) a
static int aria_init(Ciphers* c, CipherSpecs* specs,
                     void* heap, int devId, int tls13)
{
    (void)tls13;
    MC_ALGID algo;

    switch(specs->key_size) {
        case ARIA_128_KEY_SIZE:
            algo = MC_ALGID_ARIA_128BITKEY;
            break;
        case ARIA_192_KEY_SIZE:
            algo = MC_ALGID_ARIA_192BITKEY;
            break;
        case ARIA_256_KEY_SIZE:
            algo = MC_ALGID_ARIA_256BITKEY;
            break;
        default:
            return WOLFSSL_NOT_IMPLEMENTED; /* This should never happen */
    }

    if (c->aria == NULL)
        MALLOC(c->aria, wc_Aria, heap, DYNAMIC_TYPE_CIPHER);
    else
        wc_AriaFreeCrypt(c->aria);
    XMEMSET(c->aria, 0, sizeof(wc_Aria));
    if (wc_AriaInitCrypt(c->aria, algo) != 0) {
         WOLFSSL_MSG("AriaInit failed in aria_init");
         return ASYNC_INIT_E;
    }
    return 0;
}
static int aria_setkey(Ciphers* c, int decode, int server, Keys* keys,
    CipherSpecs* specs, WC_RNG* rng, int tls13)
{
    (void)specs;
    int ret;
    ret = wc_AriaSetKey(c->aria, write_key);
    if (ret != 0)
        return ret;
    XMEMCPY(imp_IV, write_IV, AEAD_MAX_IMP_SZ);
    if (!decode && !tls13) {
        return wc_AriaGcmSetIV(c->aria, AESGCM_NONCE_SZ,
                server ? keys->server_write_IV : keys->client_write_IV,
                AESGCM_IMP_IV_SZ, rng);
    }
    return 0;
}
#else
#define IF_ARIA(a,b) b
#endif /* HAVE_ARIA */

#ifdef HAVE_CAMELLIA
    /* check that buffer sizes are sufficient */
    #if (MAX_WRITE_IV_SZ < 16) /* CAMELLIA_IV_SIZE */
        #error MAX_WRITE_IV_SZ too small for CAMELLIA
    #endif
#define IF_CAMELLIA(a,b) a
static int camellia_init(Ciphers* c, CipherSpecs* specs,
                         void* heap, int devId, int tls13)
{
    (void)specs;
    (void)tls13;
    (void)devId;
    if (c->cam == NULL)
        MALLOC(c->cam, wc_Camellia, heap, DYNAMIC_TYPE_CIPHER);
    return 0;
}
static int camellia_setkey(Ciphers* c, int decode, int server, Keys* keys,
    CipherSpecs* specs, WC_RNG* rng, int tls13)
{
    (void)rng;
    (void)tls13;
    return wc_CamelliaSetKey(c->cam, write_key, specs->key_size, write_IV);
}
#else
#define IF_CAMELLIA(a,b) b
#endif /* HAVE_CAMELLIA */

#ifdef WOLFSSL_SM4_CBC
    /* check that buffer sizes are sufficient */
    #if (MAX_WRITE_IV_SZ < 16) /* AES_IV_SIZE */
        #error MAX_WRITE_IV_SZ too small for SM4_CBC
    #endif
#define IF_SM4_CBC(a,b) a
static int sm4_cbc_init(Ciphers* c, CipherSpecs* specs,
                        void* heap, int devId, int tls13)
{
    (void)specs;
    (void)tls13;
    if (c->sm4 == NULL)
        MALLOC(c->sm4, wc_Sm4, heap, DYNAMIC_TYPE_CIPHER);
    else
        wc_Sm4Free(c->sm4);
    XMEMSET(c->sm4, 0, sizeof(wc_Sm4));
    if (wc_Sm4Init(c->sm4, heap, devId) != 0) {
        WOLFSSL_MSG("Sm4Init failed in sm4_cbc_init");
        return ASYNC_INIT_E;
    }
    return 0;
}
static int sm4_cbc_setkey(Ciphers* c, int decode, int server, Keys* keys,
    CipherSpecs* specs, WC_RNG* rng, int tls13)
{
    (void)rng;
    (void)tls13;
    int ret;
    ret = wc_Sm4SetKey(c->sm4, write_key, specs->key_size);
    if (ret != 0)
        return ret;
    return wc_Sm4SetIV(c->sm4, write_IV);
}
#else
#define IF_SM4_CBC(a,b) b
#endif /* WOLFSSL_SM4_CBC */

#ifdef WOLFSSL_SM4_GCM
    /* check that buffer sizes are sufficient */
    #if (AEAD_MAX_IMP_SZ < 4) /* SM4-GCM_IMP_IV_SZ */
        #error AEAD_MAX_IMP_SZ too small for SM4-GCM
    #endif
    #if (AEAD_MAX_EXP_SZ < 8) /* SM4-GCM_EXP_IV_SZ */
        #error AEAD_MAX_EXP_SZ too small for SM4-GCM
    #endif
    #if (MAX_WRITE_IV_SZ < 4) /* SM4-GCM_IMP_IV_SZ */
        #error MAX_WRITE_IV_SZ too small for SM4-GCM
    #endif
#define IF_SM4_GCM(a,b) a
static int sm4_gcm_init(Ciphers* c, CipherSpecs* specs,
                        void* heap, int devId, int tls13)
{
    return sm4_cbc_init(c, specs, heap, devId, tls13);
}
static int sm4_gcm_setkey(Ciphers* c, int decode, int server, Keys* keys,
    CipherSpecs* specs, WC_RNG* rng, int tls13)
{
    (void)specs;
    (void)rng;
    (void)tls13;
    int ret;
    ret = wc_Sm4GcmSetKey(c->sm4, write_key, specs->key_size);
    if (ret != 0)
        return ret;
    XMEMCPY(imp_IV, write_IV, AEAD_MAX_IMP_SZ);
    return 0;
}
#else
#define IF_SM4_GCM(a,b) b
#endif /* WOLFSSL_SM4_GCM */

#ifdef WOLFSSL_SM4_CCM
    /* check that buffer sizes are sufficient (CCM is same size as GCM) */
    #if (AEAD_MAX_IMP_SZ < 4) /* SM4-CCM_IMP_IV_SZ */
        #error AEAD_MAX_IMP_SZ too small for SM4-CCM
    #endif
    #if (AEAD_MAX_EXP_SZ < 8) /* SM4-CCM_EXP_IV_SZ */
        #error AEAD_MAX_EXP_SZ too small for SM4-CCM
    #endif
    #if (MAX_WRITE_IV_SZ < 4) /* SM4-CCM_IMP_IV_SZ */
        #error MAX_WRITE_IV_SZ too small for SM4-CCM
    #endif
#define IF_SM4_CCM(a,b) a
static int sm4_ccm_init(Ciphers* c, CipherSpecs* specs,
                        void* heap, int devId, int tls13)
{
    return sm4_cbc_init(c, specs, heap, devId, tls13);
}
static int sm4_ccm_setkey(Ciphers* c, int decode, int server, Keys* keys,
    CipherSpecs* specs, WC_RNG* rng, int tls13)
{
    return sm4_gcm_setkey(c, decode, server, keys, specs, rng, tls13);
}
#else
#define IF_SM4_CCM(a,b) b
#endif /* WOLFSSL_SM4_CCM */

#ifdef HAVE_NULL_CIPHER
#define IF_NULL(a,b) a
static int null_init(Ciphers* c, CipherSpecs* specs,
                     void* heap, int devId, int tls13)
{
    (void)specs;
    #ifdef WOLFSSL_TLS13
    if (tls13) {
        if (c->hmac == NULL) {
            MALLOC(c->hmac, Hmac, heap, DYNAMIC_TYPE_CIPHER);
            if (wc_HmacInit(c->hmac, heap, devId) != 0) {
                WOLFSSL_MSG("HmacInit failed in null_init");
                XFREE(c->hmac, heap, DYNAMIC_TYPE_CIPHER);
                c->hmac = NULL;
                return ASYNC_INIT_E;
            }
        }
    }
    #endif
    return 0;
}
static int null_setkey(Ciphers* c, int decode, int server, Keys* keys,
    CipherSpecs* specs, WC_RNG* rng, int tls13)
{
    (void)rng;
    (void)tls13;
    #ifdef WOLFSSL_TLS13
    if (tls13) {
        int hashType = WC_HASH_TYPE_NONE;

        switch (specs->mac_algorithm) {
            case sha256_mac:
                hashType = WC_SHA256;
                break;
            case sha384_mac:
                hashType = WC_SHA384;
                break;
            default:
                break;
        }

        XMEMCPY(imp_IV, write_IV, AEAD_MAX_IMP_SZ);
        return wc_HmacSetKey(c->hmac, hashType, write_key, specs->key_size);
    }
    #endif
    return 0;
}
#else
#define IF_NULL(a,b) b
#endif

static int (*CipherInits[])(Ciphers*, CipherSpecs* specs, void*, int, int) = {
    IF_NULL(null_init,0),            /*  wolfssl_cipher_null = 0,  */
    IF_ARC4(rc4_init,0),             /*  wolfssl_rc4         = 1,  */
    0,                               /*  wolfssl_rc2         = 2,  */
    0,                               /*  wolfssl_des         = 3,  */
    IF_DES3(des3_init,0),            /*  wolfssl_triple_des  = 4,  */
    0,                               /*  wolfssl_des40       = 5,  */
    IF_AES(aes_init,0),              /*  wolfssl_aes         = 6,  */
    IF_AES_GCM(aes_gcm_init,0),      /*  wolfssl_aes_gcm     = 7,  */
    IF_AES_CCM(aes_ccm_init,0),      /*  wolfssl_aes_ccm     = 8,  */
    IF_CHACHA(chacha_init,0),        /*  wolfssl_chacha      = 9,  */
    IF_CAMELLIA(camellia_init,0),    /*  wolfssl_camellia    = 10, */
    IF_SM4_CBC(sm4_cbc_init,0),      /*  wolfssl_sm4_cbc     = 11, */
    IF_SM4_GCM(sm4_gcm_init,0),      /*  wolfssl_sm4_gcm     = 12, */
    IF_SM4_CCM(sm4_ccm_init,0),      /*  wolfssl_sm4_ccm     = 13, */
    IF_ARIA(aria_init,0)};           /*  wolfssl_aria_gcm    = 14  */

static int (*CipherSetKeys[])(Ciphers*, int, int, Keys*, CipherSpecs*,
                              WC_RNG*, int) = {
    IF_NULL(null_setkey,0),          /*  wolfssl_cipher_null = 0,  */
    IF_ARC4(rc4_setkey,0),           /*  wolfssl_rc4         = 1,  */
    0,                               /*  wolfssl_rc2         = 2,  */
    0,                               /*  wolfssl_des         = 3,  */
    IF_DES3(des3_setkey,0),          /*  wolfssl_triple_des  = 4,  */
    0,                               /*  wolfssl_des40       = 5,  */
    IF_AES(aes_setkey,0),            /*  wolfssl_aes         = 6,  */
    IF_AES_GCM(aes_gcm_setkey,0),    /*  wolfssl_aes_gcm     = 7,  */
    IF_AES_CCM(aes_ccm_setkey,0),    /*  wolfssl_aes_ccm     = 8,  */
    IF_CHACHA(chacha_setkey,0),      /*  wolfssl_chacha      = 9,  */
    IF_CAMELLIA(camellia_setkey,0),  /*  wolfssl_camellia    = 10, */
    IF_SM4_CBC(sm4_cbc_setkey,0),    /*  wolfssl_sm4_cbc     = 11, */
    IF_SM4_CBC(sm4_gcm_setkey,0),    /*  wolfssl_sm4_gcm     = 12, */
    IF_SM4_CBC(sm4_ccm_setkey,0),    /*  wolfssl_sm4_ccm     = 13, */
    IF_ARIA(aria_setkey,0)};         /*  wolfssl_aria_gcm    = 14  */

int SetKeys(Ciphers* enc, Ciphers* dec, Keys* keys, CipherSpecs* specs,
                   int side, void* heap, int devId, WC_RNG* rng, int tls13)
{
    Ciphers* ed[] = {enc, dec};
    int i, ret;
    int server = side != WOLFSSL_CLIENT_END;
    int algo = specs->bulk_cipher_algorithm;
    if (algo < 0 || algo > wolfssl_aria_gcm)
        return BAD_FUNC_ARG;
    for (i = 0; i < 2; i++) {
        if (ed[i]) {
            if (!CipherInits[algo] || !CipherSetKeys[algo])
                return NOT_COMPILED_IN;
            if ((ret = CipherInits[algo](ed[i], specs, heap, devId, tls13)))
                return ret;
            if ((ret = CipherSetKeys[algo](ed[i], i, server, keys, specs,
                                           rng, tls13)))
                return ret;
            ed[i]->setup = 1;
        }
    }
    if (enc) {
        keys->sequence_number_hi      = 0;
        keys->sequence_number_lo      = 0;
    }
    if (dec) {
        keys->peer_sequence_number_hi = 0;
        keys->peer_sequence_number_lo = 0;
    }
    return 0;
}


#ifdef HAVE_ONE_TIME_AUTH
/* set one time authentication keys */
static int SetAuthKeys(OneTimeAuth* authentication, Keys* keys,
                       CipherSpecs* specs, void* heap, int devId)
{

#ifdef HAVE_POLY1305
        /* set up memory space for poly1305 */
        if (authentication && authentication->poly1305 == NULL)
            authentication->poly1305 =
                (Poly1305*)XMALLOC(sizeof(Poly1305), heap, DYNAMIC_TYPE_CIPHER);
        if (authentication && authentication->poly1305 == NULL)
            return MEMORY_E;
    #ifdef WOLFSSL_CHECK_MEM_ZERO
        wc_MemZero_Add("SSL auth keys poly1305", authentication->poly1305,
            sizeof(Poly1305));
    #endif
        if (authentication)
            authentication->setup = 1;
#endif
        (void)authentication;
        (void)heap;
        (void)keys;
        (void)specs;
        (void)devId;

        return 0;
}
#endif /* HAVE_ONE_TIME_AUTH */

#ifdef HAVE_SECURE_RENEGOTIATION
/* function name is for cache_status++
 * This function was added because of error incrementing enum type when
 * compiling with a C++ compiler.
 */
static void CacheStatusPP(SecureRenegotiation* cache)
{
    switch (cache->cache_status) {
        case SCR_CACHE_NULL:
            cache->cache_status = SCR_CACHE_NEEDED;
            break;

        case SCR_CACHE_NEEDED:
            cache->cache_status = SCR_CACHE_COPY;
            break;

        case SCR_CACHE_COPY:
            cache->cache_status = SCR_CACHE_PARTIAL;
            break;

        case SCR_CACHE_PARTIAL:
            cache->cache_status = SCR_CACHE_COMPLETE;
            break;

        case SCR_CACHE_COMPLETE:
            WOLFSSL_MSG("SCR Cache state Complete");
            break;

        default:
            WOLFSSL_MSG("Unknown cache state!!");
    }
}
#endif /* HAVE_SECURE_RENEGOTIATION */


/* Set wc_encrypt/wc_decrypt or both sides of key setup
 * note: use wc_encrypt to avoid shadowing global encrypt
 * declared in unistd.h
 */
int SetKeysSide(WOLFSSL* ssl, enum encrypt_side side)
{
    int ret, copy = 0;
    Ciphers* wc_encrypt = NULL;
    Ciphers* wc_decrypt = NULL;
    Keys*    keys    = &ssl->keys;

    (void)copy;

#ifdef HAVE_SECURE_RENEGOTIATION
    if (ssl->secure_renegotiation &&
            ssl->secure_renegotiation->cache_status != SCR_CACHE_NULL) {
        keys = &ssl->secure_renegotiation->tmp_keys;
#ifdef WOLFSSL_DTLS
        /* For DTLS, copy is done in StoreKeys */
        if (!ssl->options.dtls)
#endif
            copy = 1;
    }
#endif /* HAVE_SECURE_RENEGOTIATION */

    switch (side) {
        case ENCRYPT_SIDE_ONLY:
#ifdef WOLFSSL_DEBUG_TLS
            WOLFSSL_MSG("Provisioning ENCRYPT key");
            if (ssl->options.side == WOLFSSL_CLIENT_END) {
                WOLFSSL_BUFFER(keys->client_write_key, ssl->specs.key_size);
            }
            else {
                WOLFSSL_BUFFER(keys->server_write_key, ssl->specs.key_size);
            }
#endif
            wc_encrypt = &ssl->encrypt;
            break;

        case DECRYPT_SIDE_ONLY:
#ifdef WOLFSSL_DEBUG_TLS
            WOLFSSL_MSG("Provisioning DECRYPT key");
            if (ssl->options.side == WOLFSSL_CLIENT_END) {
                WOLFSSL_BUFFER(keys->server_write_key, ssl->specs.key_size);
            }
            else {
                WOLFSSL_BUFFER(keys->client_write_key, ssl->specs.key_size);
            }
#endif
            wc_decrypt = &ssl->decrypt;
            break;

        case ENCRYPT_AND_DECRYPT_SIDE:
#ifdef WOLFSSL_DEBUG_TLS
            WOLFSSL_MSG("Provisioning ENCRYPT key");
            if (ssl->options.side == WOLFSSL_CLIENT_END) {
                WOLFSSL_BUFFER(keys->client_write_key, ssl->specs.key_size);
            }
            else {
                WOLFSSL_BUFFER(keys->server_write_key, ssl->specs.key_size);
            }
            WOLFSSL_MSG("Provisioning DECRYPT key");
            if (ssl->options.side == WOLFSSL_CLIENT_END) {
                WOLFSSL_BUFFER(keys->server_write_key, ssl->specs.key_size);
            }
            else {
                WOLFSSL_BUFFER(keys->client_write_key, ssl->specs.key_size);
            }
#endif
            wc_encrypt = &ssl->encrypt;
            wc_decrypt = &ssl->decrypt;
            break;

        default:
            return BAD_FUNC_ARG;
    }

#ifdef HAVE_ONE_TIME_AUTH
    if (!ssl->auth.setup && ssl->specs.bulk_cipher_algorithm == wolfssl_chacha){
        ret = SetAuthKeys(&ssl->auth, keys, &ssl->specs, ssl->heap, ssl->devId);
        if (ret != 0)
           return ret;
    }
#endif

#if !defined(NO_CERTS) && defined(HAVE_PK_CALLBACKS)
    ret = PROTOCOLCB_UNAVAILABLE;
    if (ssl->ctx->EncryptKeysCb) {
        void* ctx = wolfSSL_GetEncryptKeysCtx(ssl);
        #if defined(WOLFSSL_RENESAS_FSPSM_TLS)
            FSPSM_ST* cbInfo = (FSPSM_ST*)ctx;
            cbInfo->internal->side = side;
        #elif defined(WOLFSSL_RENESAS_TSIP_TLS)
            TsipUserCtx* cbInfo = (TsipUserCtx*)ctx;
            cbInfo->internal->key_side = side;
        #endif
        ret = ssl->ctx->EncryptKeysCb(ssl, ctx);
    }
    if (!ssl->ctx->EncryptKeysCb ||
        ret == WC_NO_ERR_TRACE(PROTOCOLCB_UNAVAILABLE))
#endif
    {
        ret = SetKeys(wc_encrypt, wc_decrypt, keys, &ssl->specs, ssl->options.side,
                      ssl->heap, ssl->devId, ssl->rng, ssl->options.tls1_3);
    }

#ifdef WOLFSSL_DTLS13
    if (ret == 0 && ssl->options.dtls && IsAtLeastTLSv1_3(ssl->version))
        ret = Dtls13SetRecordNumberKeys(ssl, side);
#endif /* WOLFSSL_DTLS13 */
#ifdef WOLFSSL_QUIC
    if (ret == 0 && WOLFSSL_IS_QUIC(ssl)) {
        ret = wolfSSL_quic_keys_active(ssl, side);
    }
#endif /* WOLFSSL_QUIC */

#ifdef HAVE_SECURE_RENEGOTIATION
#ifdef WOLFSSL_DTLS
    if (ret == 0 && ssl->options.dtls && !ssl->options.tls1_3) {
        if (wc_encrypt)
            wc_encrypt->src = keys == &ssl->keys ? KEYS : SCR;
        if (wc_decrypt)
            wc_decrypt->src = keys == &ssl->keys ? KEYS : SCR;
    }
#endif

    if (copy) {
        int clientCopy = 0;

        /* Sanity check that keys == ssl->secure_renegotiation->tmp_keys.
         * Otherwise the memcpy calls would copy overlapping memory
         * and cause UB. Fail early. */
        if (keys == &ssl->keys)
            return BAD_FUNC_ARG;

        if (ssl->options.side == WOLFSSL_CLIENT_END && wc_encrypt)
            clientCopy = 1;
        else if (ssl->options.side == WOLFSSL_SERVER_END && wc_decrypt)
            clientCopy = 1;

        if (clientCopy) {
    #ifndef WOLFSSL_AEAD_ONLY
            XMEMCPY(ssl->keys.client_write_MAC_secret,
                    keys->client_write_MAC_secret, WC_MAX_DIGEST_SIZE);
    #endif
            XMEMCPY(ssl->keys.client_write_key,
                    keys->client_write_key, AES_256_KEY_SIZE);
            XMEMCPY(ssl->keys.client_write_IV,
                    keys->client_write_IV, MAX_WRITE_IV_SZ);
        } else {
    #ifndef WOLFSSL_AEAD_ONLY
            XMEMCPY(ssl->keys.server_write_MAC_secret,
                    keys->server_write_MAC_secret, WC_MAX_DIGEST_SIZE);
    #endif
            XMEMCPY(ssl->keys.server_write_key,
                    keys->server_write_key, AES_256_KEY_SIZE);
            XMEMCPY(ssl->keys.server_write_IV,
                    keys->server_write_IV, MAX_WRITE_IV_SZ);
        }
        if (wc_encrypt) {
            ssl->keys.sequence_number_hi = keys->sequence_number_hi;
            ssl->keys.sequence_number_lo = keys->sequence_number_lo;
            #ifdef HAVE_AEAD
                if (ssl->specs.cipher_type == aead) {
                    /* Initialize the AES-GCM/CCM explicit IV to a zero. */
                    XMEMCPY(ssl->keys.aead_exp_IV, keys->aead_exp_IV,
                            AEAD_MAX_EXP_SZ);

                    /* Initialize encrypt implicit IV by encrypt side */
                    if (ssl->options.side == WOLFSSL_CLIENT_END) {
                        XMEMCPY(ssl->keys.aead_enc_imp_IV,
                                keys->client_write_IV, AEAD_MAX_IMP_SZ);
                    } else {
                        XMEMCPY(ssl->keys.aead_enc_imp_IV,
                                keys->server_write_IV, AEAD_MAX_IMP_SZ);
                    }
                }
            #endif
        }
        if (wc_decrypt) {
            ssl->keys.peer_sequence_number_hi = keys->peer_sequence_number_hi;
            ssl->keys.peer_sequence_number_lo = keys->peer_sequence_number_lo;
            #ifdef HAVE_AEAD
                if (ssl->specs.cipher_type == aead) {
                    /* Initialize decrypt implicit IV by decrypt side */
                    if (ssl->options.side == WOLFSSL_SERVER_END) {
                        XMEMCPY(ssl->keys.aead_dec_imp_IV,
                                keys->client_write_IV, AEAD_MAX_IMP_SZ);
                    } else {
                        XMEMCPY(ssl->keys.aead_dec_imp_IV,
                                keys->server_write_IV, AEAD_MAX_IMP_SZ);
                    }
                }
            #endif
        }
        CacheStatusPP(ssl->secure_renegotiation);
    }
#endif /* HAVE_SECURE_RENEGOTIATION */

    return ret;
}


/* TLS can call too */
int StoreKeys(WOLFSSL* ssl, const byte* keyData, int side)
{
    size_t sz;
    int i = 0;
    Keys* keys = &ssl->keys;
#ifdef WOLFSSL_DTLS
    /* In case of DTLS, ssl->keys is updated here */
    int scr_copy = 0;
#endif

#ifdef HAVE_SECURE_RENEGOTIATION
    if (ssl->secure_renegotiation &&
            ssl->secure_renegotiation->cache_status == SCR_CACHE_NEEDED) {
        keys = &ssl->secure_renegotiation->tmp_keys;
#ifdef WOLFSSL_DTLS
        if (ssl->options.dtls) {
            /* epoch is incremented after StoreKeys is called */
            ssl->secure_renegotiation->tmp_keys.dtls_epoch = ssl->keys.dtls_epoch + 1;
            /* we only need to copy keys on second and future renegotiations */
            if (ssl->keys.dtls_epoch > 1)
                scr_copy = 1;
            ssl->encrypt.src = KEYS_NOT_SET;
            ssl->decrypt.src = KEYS_NOT_SET;
        }
#endif
        CacheStatusPP(ssl->secure_renegotiation);
    }
#endif /* HAVE_SECURE_RENEGOTIATION */

#ifdef WOLFSSL_MULTICAST
    if (ssl->options.haveMcast) {
        /* Use the same keys for encrypt and decrypt. */
        if (ssl->specs.cipher_type != aead) {
            sz = ssl->specs.hash_size;
    #ifndef WOLFSSL_AEAD_ONLY

    #ifdef WOLFSSL_DTLS
            if (scr_copy) {
                XMEMCPY(ssl->keys.client_write_MAC_secret,
                        keys->client_write_MAC_secret, sz);
                XMEMCPY(ssl->keys.server_write_MAC_secret,
                        keys->server_write_MAC_secret, sz);
            }
    #endif
            XMEMCPY(keys->client_write_MAC_secret,&keyData[i], sz);
            XMEMCPY(keys->server_write_MAC_secret,&keyData[i], sz);
    #endif
            i += (int)sz;
        }
        sz = ssl->specs.key_size;
    #ifdef WOLFSSL_DTLS
        if (scr_copy) {
            XMEMCPY(ssl->keys.client_write_key,
                    keys->client_write_key, sz);
            XMEMCPY(ssl->keys.server_write_key,
                    keys->server_write_key, sz);
        }
    #endif
        XMEMCPY(keys->client_write_key, &keyData[i], sz);
        XMEMCPY(keys->server_write_key, &keyData[i], sz);
        i += (int)sz;

        sz = ssl->specs.iv_size;
    #ifdef WOLFSSL_DTLS
        if (scr_copy) {
            XMEMCPY(ssl->keys.client_write_IV,
                    keys->client_write_IV, sz);
            XMEMCPY(ssl->keys.server_write_IV,
                    keys->server_write_IV, sz);
        }
    #endif
        XMEMCPY(keys->client_write_IV, &keyData[i], sz);
        XMEMCPY(keys->server_write_IV, &keyData[i], sz);

#ifdef HAVE_AEAD
        if (ssl->specs.cipher_type == aead) {
            /* Initialize the AES-GCM/CCM explicit IV to a zero. */
        #ifdef WOLFSSL_DTLS
            if (scr_copy) {
                XMEMCPY(ssl->keys.aead_exp_IV,
                        keys->aead_exp_IV, AEAD_MAX_EXP_SZ);
            }
        #endif
            XMEMSET(keys->aead_exp_IV, 0, AEAD_MAX_EXP_SZ);
        }
#endif /* HAVE_AEAD */

        return 0;
    }
#endif /* WOLFSSL_MULTICAST */

    if (ssl->specs.cipher_type != aead) {
        sz = ssl->specs.hash_size;
        if (side & PROVISION_CLIENT) {
    #ifndef WOLFSSL_AEAD_ONLY
        #ifdef WOLFSSL_DTLS
            if (scr_copy)
                XMEMCPY(ssl->keys.client_write_MAC_secret,
                        keys->client_write_MAC_secret, sz);
        #endif
            XMEMCPY(keys->client_write_MAC_secret,&keyData[i], sz);
    #endif
            i += (int)sz;
        }
        if (side & PROVISION_SERVER) {
    #ifndef WOLFSSL_AEAD_ONLY
        #ifdef WOLFSSL_DTLS
            if (scr_copy)
                XMEMCPY(ssl->keys.server_write_MAC_secret,
                        keys->server_write_MAC_secret, sz);
        #endif
            XMEMCPY(keys->server_write_MAC_secret,&keyData[i], sz);
    #endif
            i += (int)sz;
        }
    }
    sz = ssl->specs.key_size;
    if (side & PROVISION_CLIENT) {
    #ifdef WOLFSSL_DTLS
        if (scr_copy)
            XMEMCPY(ssl->keys.client_write_key,
                    keys->client_write_key, sz);
    #endif
        XMEMCPY(keys->client_write_key, &keyData[i], sz);
        i += (int)sz;
    }
    if (side & PROVISION_SERVER) {
    #ifdef WOLFSSL_DTLS
        if (scr_copy)
            XMEMCPY(ssl->keys.server_write_key,
                    keys->server_write_key, sz);
    #endif
        XMEMCPY(keys->server_write_key, &keyData[i], sz);
        i += (int)sz;
    }

    sz = ssl->specs.iv_size;
    if (side & PROVISION_CLIENT) {
    #ifdef WOLFSSL_DTLS
        if (scr_copy)
            XMEMCPY(ssl->keys.client_write_IV,
                    keys->client_write_IV, sz);
    #endif
        XMEMCPY(keys->client_write_IV, &keyData[i], sz);
        i += (int)sz;
    }
    if (side & PROVISION_SERVER) {
    #ifdef WOLFSSL_DTLS
        if (scr_copy)
            XMEMCPY(ssl->keys.server_write_IV,
                    keys->server_write_IV, sz);
    #endif
        XMEMCPY(keys->server_write_IV, &keyData[i], sz);
    }

#ifdef HAVE_AEAD
    if (ssl->specs.cipher_type == aead) {
        /* Initialize the AES-GCM/CCM explicit IV to a zero. */
    #ifdef WOLFSSL_DTLS
        if (scr_copy)
            XMEMMOVE(ssl->keys.aead_exp_IV,
                    keys->aead_exp_IV, AEAD_MAX_EXP_SZ);
    #endif
        XMEMSET(keys->aead_exp_IV, 0, AEAD_MAX_EXP_SZ);
    }
#endif

    return 0;
}

#ifndef NO_OLD_TLS
int DeriveKeys(WOLFSSL* ssl)
{
    int    length = 2 * ssl->specs.hash_size +
                    2 * ssl->specs.key_size  +
                    2 * ssl->specs.iv_size;
    int    rounds = (length + WC_MD5_DIGEST_SIZE - 1 ) / WC_MD5_DIGEST_SIZE;
    int    ret = 0;

#ifdef WOLFSSL_SMALL_STACK
    byte*  shaOutput;
    byte*  md5Input;
    byte*  shaInput;
    byte*  keyData;
    wc_Md5* md5;
    wc_Sha* sha;
#else
    byte   shaOutput[WC_SHA_DIGEST_SIZE];
    byte   md5Input[SECRET_LEN + WC_SHA_DIGEST_SIZE];
    byte   shaInput[KEY_PREFIX + SECRET_LEN + 2 * RAN_LEN];
    byte   keyData[KEY_PREFIX * WC_MD5_DIGEST_SIZE];
    wc_Md5 md5[1];
    wc_Sha sha[1];
#endif

#ifdef WOLFSSL_SMALL_STACK
    shaOutput = (byte*)XMALLOC(WC_SHA_DIGEST_SIZE,
                                            NULL, DYNAMIC_TYPE_TMP_BUFFER);
    md5Input  = (byte*)XMALLOC(SECRET_LEN + WC_SHA_DIGEST_SIZE,
                                            NULL, DYNAMIC_TYPE_TMP_BUFFER);
    shaInput  = (byte*)XMALLOC(KEY_PREFIX + SECRET_LEN + 2 * RAN_LEN,
                                            NULL, DYNAMIC_TYPE_TMP_BUFFER);
    keyData   = (byte*)XMALLOC(KEY_PREFIX * WC_MD5_DIGEST_SIZE,
                                            NULL, DYNAMIC_TYPE_TMP_BUFFER);
    md5       =  (wc_Md5*)XMALLOC(sizeof(wc_Md5), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    sha       =  (wc_Sha*)XMALLOC(sizeof(wc_Sha), NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (shaOutput == NULL || md5Input == NULL || shaInput == NULL ||
        keyData   == NULL || md5      == NULL || sha      == NULL) {
        XFREE(shaOutput, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(md5Input, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(shaInput, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(keyData, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(md5, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(sha, NULL, DYNAMIC_TYPE_TMP_BUFFER);

        return MEMORY_E;
    }
#endif
    XMEMSET(shaOutput, 0, WC_SHA_DIGEST_SIZE);
    ret = wc_InitMd5(md5);
    if (ret == 0) {
        ret = wc_InitSha(sha);
    }
    if (ret == 0) {
        int i;

        XMEMCPY(md5Input, ssl->arrays->masterSecret, SECRET_LEN);

        for (i = 0; i < rounds; ++i) {
            int j   = i + 1;
            int idx = j;

            if (!SetPrefix(shaInput, i)) {
                ret = PREFIX_ERROR;
                break;
            }

            XMEMCPY(shaInput + idx, ssl->arrays->masterSecret, SECRET_LEN);
            idx += SECRET_LEN;
            XMEMCPY(shaInput + idx, ssl->arrays->serverRandom, RAN_LEN);
            idx += RAN_LEN;
            XMEMCPY(shaInput + idx, ssl->arrays->clientRandom, RAN_LEN);
            if (ret == 0) {
                ret = wc_ShaUpdate(sha, shaInput,
                    (KEY_PREFIX + SECRET_LEN + 2 * RAN_LEN) - KEY_PREFIX +
                        (word32)(j));
            }
            if (ret == 0) {
                ret = wc_ShaFinal(sha, shaOutput);
            }

            XMEMCPY(md5Input + SECRET_LEN, shaOutput, WC_SHA_DIGEST_SIZE);
            if (ret == 0) {
                ret = wc_Md5Update(md5, md5Input, SECRET_LEN + WC_SHA_DIGEST_SIZE);
            }
            if (ret == 0) {
                ret = wc_Md5Final(md5, keyData + i * WC_MD5_DIGEST_SIZE);
            }
        }

        if (ret == 0)
            ret = StoreKeys(ssl, keyData, PROVISION_CLIENT_SERVER);
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(shaOutput, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(md5Input,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(shaInput,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(keyData,   NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(md5,       NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(sha,       NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}


static int CleanPreMaster(WOLFSSL* ssl)
{
    int i, ret, sz = (int)(ssl->arrays->preMasterSz);

    for (i = 0; i < sz; i++)
        ssl->arrays->preMasterSecret[i] = 0;

    ret = wc_RNG_GenerateBlock(ssl->rng, ssl->arrays->preMasterSecret,
                                                            (word32)(sz));
    if (ret != 0)
        return ret;

    for (i = 0; i < sz; i++)
        ssl->arrays->preMasterSecret[i] = 0;

    XFREE(ssl->arrays->preMasterSecret, ssl->heap, DYNAMIC_TYPE_SECRET);
    ssl->arrays->preMasterSecret = NULL;
    ssl->arrays->preMasterSz = 0;

    return 0;
}


/* Create and store the master secret see page 32, 6.1 */
static int MakeSslMasterSecret(WOLFSSL* ssl)
{
    int    i, ret;
    word32 idx;
    word32 pmsSz = ssl->arrays->preMasterSz;

#ifdef WOLFSSL_SMALL_STACK
    byte*  shaOutput;
    byte*  md5Input;
    byte*  shaInput;
    wc_Md5* md5;
    wc_Sha* sha;
#else
    byte   shaOutput[WC_SHA_DIGEST_SIZE];
    byte   md5Input[ENCRYPT_LEN + WC_SHA_DIGEST_SIZE];
    byte   shaInput[PREFIX + ENCRYPT_LEN + 2 * RAN_LEN];
    wc_Md5 md5[1];
    wc_Sha sha[1];
#endif

    if (ssl->arrays->preMasterSecret == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef SHOW_SECRETS
    {
        word32 j;
        printf("pre master secret: ");
        for (j = 0; j < pmsSz; j++)
            printf("%02x", ssl->arrays->preMasterSecret[j]);
        printf("\n");
    }
#endif

#ifdef WOLFSSL_SMALL_STACK
    shaOutput = (byte*)XMALLOC(WC_SHA_DIGEST_SIZE,
                                            NULL, DYNAMIC_TYPE_TMP_BUFFER);
    md5Input  = (byte*)XMALLOC(ENCRYPT_LEN + WC_SHA_DIGEST_SIZE,
                                            NULL, DYNAMIC_TYPE_TMP_BUFFER);
    shaInput  = (byte*)XMALLOC(PREFIX + ENCRYPT_LEN + 2 * RAN_LEN,
                                            NULL, DYNAMIC_TYPE_TMP_BUFFER);
    md5       =  (wc_Md5*)XMALLOC(sizeof(wc_Md5), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    sha       =  (wc_Sha*)XMALLOC(sizeof(wc_Sha), NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (shaOutput == NULL || md5Input == NULL || shaInput == NULL ||
                             md5      == NULL || sha      == NULL) {
        XFREE(shaOutput, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(md5Input, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(shaInput, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(md5, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(sha, NULL, DYNAMIC_TYPE_TMP_BUFFER);

        return MEMORY_E;
    }
#endif
    XMEMSET(shaOutput, 0, WC_SHA_DIGEST_SIZE);

    ret = wc_InitMd5(md5);
    if (ret == 0) {
        ret = wc_InitSha(sha);
    }
    if (ret == 0) {
        XMEMCPY(md5Input, ssl->arrays->preMasterSecret, pmsSz);

        for (i = 0; i < MASTER_ROUNDS; ++i) {
            byte prefix[KEY_PREFIX];      /* only need PREFIX bytes but static */
            if (!SetPrefix(prefix, i)) {  /* analysis thinks will overrun      */
                ret = PREFIX_ERROR;
                break;
            }

            idx = 0;
            XMEMCPY(shaInput, prefix, (size_t)(i + 1));
            idx += (word32)(i + 1);

            XMEMCPY(shaInput + idx, ssl->arrays->preMasterSecret, pmsSz);
            idx += pmsSz;
            XMEMCPY(shaInput + idx, ssl->arrays->clientRandom, RAN_LEN);
            idx += RAN_LEN;
            XMEMCPY(shaInput + idx, ssl->arrays->serverRandom, RAN_LEN);
            idx += RAN_LEN;
            if (ret == 0) {
                ret = wc_ShaUpdate(sha, shaInput, idx);
            }
            if (ret == 0) {
                ret = wc_ShaFinal(sha, shaOutput);
            }
            idx = pmsSz;  /* preSz */
            XMEMCPY(md5Input + idx, shaOutput, WC_SHA_DIGEST_SIZE);
            idx += WC_SHA_DIGEST_SIZE;
            if (ret == 0) {
                ret = wc_Md5Update(md5, md5Input, idx);
            }
            if (ret == 0) {
                ret = wc_Md5Final(md5,
                            &ssl->arrays->masterSecret[i * WC_MD5_DIGEST_SIZE]);
            }
        }

#ifdef SHOW_SECRETS
        {
            word32 j;
            printf("master secret: ");
            for (j = 0; j < SECRET_LEN; j++)
                printf("%02x", ssl->arrays->masterSecret[j]);
            printf("\n");
        }
#endif

        if (ret == 0)
            ret = DeriveKeys(ssl);
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(shaOutput, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(md5Input,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(shaInput,  NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(md5,       NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(sha,       NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    if (ret == 0)
        ret = CleanPreMaster(ssl);
    else
        CleanPreMaster(ssl);

    return ret;
}
#endif


/* Master wrapper, doesn't use SSL stack space in TLS mode */
int MakeMasterSecret(WOLFSSL* ssl)
{
    /* append secret to premaster : premaster | SerSi | CliSi */
#ifndef NO_OLD_TLS
    if (ssl->options.tls) return MakeTlsMasterSecret(ssl);
    return MakeSslMasterSecret(ssl);
#elif !defined(WOLFSSL_NO_TLS12) && !defined(NO_TLS)
    return MakeTlsMasterSecret(ssl);
#else
    (void)ssl;
    return 0;
#endif
}

#endif /* !WOLFCRYPT_ONLY && !NO_TLS */
