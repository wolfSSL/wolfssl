/* renesas_tsip_internal.h
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
#ifndef _RENESAS_TSIP_INTERNAL_H_
#define _RENESAS_TSIP_INTERNAL_H_

#include "renesas-tsip-crypt.h"

struct TsipUserCtx_Internal {
    /* client key pair wrapped by provisioning key */
    byte*                                              wrappedPrivateKey;
    byte*                                              wrappedPublicKey;


#ifdef WOLFSSL_RENESAS_TSIP_TLS
    /* 0:working as a TLS client, 1: as a server */
    byte                    side;
    /* ENCRYPT_SIDE_ONLY:1 DECRYPT_SIDE_ONLY:2 ENCRYPT AND DECRYPT:3 */
    byte                    key_side;
    /* public key index for verification of RootCA cert */
    uint32_t                user_key_id;

    /* WOLFSSL object associated with */
    struct WOLFSSL*         ssl;
    struct WOLFSSL_CTX*     ctx;

    /* HEAP_HINT */
    void*                   heap;

    /* TLSv1.3 handshake related members, mainly keys */

    /* handle is used as work area for Tls13 handshake */
    tsip_tls13_handle_t                                handle13;

#if !defined(NO_RSA)
    /* RSA-2048bit private and public key-index for client authentication */
    tsip_rsa2048_private_key_index_t                   Rsa2048PrivateKeyIdx;
    tsip_rsa2048_public_key_index_t                    Rsa2048PublicKeyIdx;
#endif /* !NO_RSA */
#if defined(HAVE_ECC)
    /* ECC private and public key-index for client authentication */
    tsip_ecc_private_key_index_t                       EcdsaPrivateKeyIdx;
    tsip_ecc_public_key_index_t                        EcdsaPublicKeyIdx;
#endif /* HAVE_ECC */

    /* ECDHE private key index for Tls13 handshake */
    tsip_tls_p256_ecc_key_index_t                      EcdhPrivKey13Idx;

    /* ECDHE pre-master secret */
    tsip_tls13_ephemeral_shared_secret_key_index_t     sharedSecret13Idx;

    /* Handshake secret for Tls13 handshake */
    tsip_tls13_ephemeral_handshake_secret_key_index_t  handshakeSecret13Idx;

    /* the key to decrypt server-finished message */
    tsip_tls13_ephemeral_server_finished_key_index_t   serverFinished13Idx;

    /* key for Sha256-Hmac to gen "Client Finished" */
    tsip_hmac_sha_key_index_t                          clientFinished13Idx;

    /* AES decryption key for handshake */
    tsip_aes_key_index_t                               serverWriteKey13Idx;

    /* AES encryption key for handshake */
    tsip_aes_key_index_t                               clientWriteKey13Idx;

    /* Handshake verified data used for master secret */
    word32                          verifyData13Idx[TSIP_TLS_VERIFY_DATA_WD_SZ];

    /* master secret for TLS1.3 */
    tsip_tls13_ephemeral_master_secret_key_index_t     masterSecret13Idx;

    /* server app traffic secret */
    tsip_tls13_ephemeral_app_secret_key_index_t        serverAppTraffic13Secret;

    /* client app traffic secret */
    tsip_tls13_ephemeral_app_secret_key_index_t        clientAppTraffic13Secret;

    /* server write key */
    tsip_aes_key_index_t                               serverAppWriteKey13Idx;

    /* client write key */
    tsip_aes_key_index_t                               clientAppWriteKey13Idx;

    /* hash handle for transcript hash of handshake messages */
    tsip_hmac_sha_handle_t                             hmacFinished13Handle;

    /* storage for handshake messages */
    MsgBag                                             messageBag;

    /* signature data area for TLS1.3 CertificateVerify message  */
    byte                             sigDataCertVerify[TSIP_TLS_MAX_SIGDATA_SZ];

#if (WOLFSSL_RENESAS_TSIP_VER >=109)
    /* out from R_SCE_TLS_ServerKeyExchangeVerify */
    uint32_t encrypted_ephemeral_ecdh_public_key[ENCRYPTED_ECDHE_PUBKEY_SZ];

    /* ephemeral ECDH pubkey index
     * got from R_TSIP_GenerateTlsP256EccKeyIndex.
     * Input to R_TSIP_TlsGeneratePreMasterSecretWithEccP256Key.
     */
    tsip_tls_p256_ecc_key_index_t ecc_p256_wrapped_key;

    /* ephemeral ECDH pub-key Qx(256bit)||Qy(256bit)
     * got from  R_TSIP_GenerateTlsP256EccKeyIndex.
     * Should be sent to peer(server) in Client Key Exchange msg.
     */
    uint8_t ecc_ecdh_public_key[ECCP256_PUBKEY_SZ];
#endif /* WOLFSSL_RENESAS_TSIP_VER >=109 */

    /* info to generate session key */
    uint32_t    tsip_masterSecret[TSIP_TLS_MASTERSECRET_SIZE/4];
    uint8_t     tsip_clientRandom[TSIP_TLS_CLIENTRANDOM_SZ];
    uint8_t     tsip_serverRandom[TSIP_TLS_SERVERRANDOM_SZ];

    /* TSIP defined cipher suite number */
    uint32_t    tsip_cipher;
        /* flags */
#if !defined(NO_RSA)
    uint8_t ClientRsa2048PrivKey_set:1;
    uint8_t ClientRsa2048PubKey_set:1;
#endif
#if defined(HAVE_ECC)
    uint8_t ClientEccPrivKey_set:1;
    uint8_t ClientEccPubKey_set:1;
#endif

    uint8_t HmacInitialized:1;
    uint8_t RootCAverified:1;
    uint8_t EcdsaPrivKey_set:1;
    uint8_t Dhe_key_set:1;
    uint8_t SharedSecret_set:1;
    uint8_t EarlySecret_set:1;
    uint8_t HandshakeSecret_set:1;
    uint8_t HandshakeClientTrafficKey_set:1;
    uint8_t HandshakeServerTrafficKey_set:1;
    uint8_t HandshakeVerifiedData_set:1;
    uint8_t MasterSecret_set:1;
    uint8_t ServerTrafficSecret_set:1;
    uint8_t ClientTrafficSecret_set:1;
    uint8_t ServerWriteTrafficKey_set:1;
    uint8_t ClientWriteTrafficKey_set:1;
    uint8_t session_key_set:1;
#endif /* WOLFSSL_RENESAS_TSIP_TLS */

};

#endif
