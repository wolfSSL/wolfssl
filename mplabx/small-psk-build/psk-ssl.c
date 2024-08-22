/* psk-ssl.c
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
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

/*
 * WOLFSSL_SMALL_CERT_VERIFY:
 *     Verify the certificate signature without using DecodedCert. Doubles up
 *     on some code but allows smaller peak heap memory usage.
 *     Cannot be used with WOLFSSL_NONBLOCK_OCSP.
 * WOLFSSL_ALT_CERT_CHAINS:
 *     Allows CA's to be presented by peer, but not part of a valid chain.
 *     Default wolfSSL behavior is to require validation of all presented peer
 *     certificates. This also allows loading intermediate CA's as trusted
 *     and ignoring no signer failures for CA's up the chain to root.
 * WOLFSSL_DTLS_RESEND_ONLY_TIMEOUT:
 *     Enable resending the previous DTLS handshake flight only on a network
 *     read timeout. By default we resend in two more cases, when we receive:
 *     - an out of order last msg of the peer's flight
 *     - a duplicate of the first msg from the peer's flight
 * WOLFSSL_NO_DEF_TICKET_ENC_CB:
 *     No default ticket encryption callback.
 *     Server only.
 *     Application must set its own callback to use session tickets.
 * WOLFSSL_TICKET_ENC_CHACHA20_POLY1305
 *     Use ChaCha20-Poly1305 to encrypt/decrypt session tickets in default
 *     callback. Default algorithm if none defined and algorithms compiled in.
 *     Server only.
 * WOLFSSL_TICKET_ENC_AES128_GCM
 *     Use AES128-GCM to encrypt/decrypt session tickets in default callback.
 *     Server only. Default algorithm if ChaCha20/Poly1305 not compiled in.
 * WOLFSSL_TICKET_ENC_AES256_GCM
 *     Use AES256-GCM to encrypt/decrypt session tickets in default callback.
 *     Server only.
 * WOLFSSL_TICKET_DECRYPT_NO_CREATE
 *     Default callback will not request creation of new ticket on successful
 *     decryption.
 *     Server only.
 * WOLFSSL_TLS13_NO_PEEK_HANDSHAKE_DONE
 *     Once a normal TLS 1.3 handshake is complete, a session ticket message
 *     may be received by a client. To support detecting this, peek will
 *     return WOLFSSL_ERROR_WANT_READ.
 *     This define turns off this behaviour.
 * WOLFSSL_HOSTNAME_VERIFY_ALT_NAME_ONLY
 *     Verify hostname/ip address using alternate name (SAN) only and do not
 *     use the common name. Forces use of the alternate name, so certificates
 *     missing SAN will be rejected during the handshake
 * WOLFSSL_CHECK_SIG_FAULTS
 *     Verifies the ECC signature after signing in case of faults in the
 *     calculation of the signature. Useful when signature fault injection is a
 *     possible attack.
 * WOLFSSL_TLS13_IGNORE_AEAD_LIMITS
 *     Ignore the AEAD limits for messages specified in the RFC. After
 *     reaching the limit, we initiate a key update. We enforce the AEAD limits
 *     by default.
 *     https://www.rfc-editor.org/rfc/rfc8446#section-5.5
 *     https://www.rfc-editor.org/rfc/rfc9147.html#name-aead-limits
 * WOLFSSL_HARDEN_TLS
 *     Implement the recommendations specified in RFC9325. This macro needs to
 *     be defined to the desired number of bits of security. The currently
 *     implemented values are 112 and 128 bits. The following macros disable
 *     certain checks.
 *     - WOLFSSL_HARDEN_TLS_ALLOW_TRUNCATED_HMAC
 *     - WOLFSSL_HARDEN_TLS_ALLOW_OLD_TLS
 *     - WOLFSSL_HARDEN_TLS_NO_SCR_CHECK
 *     - WOLFSSL_HARDEN_TLS_NO_PKEY_CHECK
 *     - WOLFSSL_HARDEN_TLS_ALLOW_ALL_CIPHERSUITES
 * WOLFSSL_NO_INIT_CTX_KEY
 *      Allows SSL objects to be created from a CTX without a loaded key/cert
 *      pair
 */


#ifdef EXTERNAL_OPTS_OPENVPN
#error EXTERNAL_OPTS_OPENVPN should not be defined\
    when building wolfSSL
#endif

#ifndef WOLFCRYPT_ONLY

#include <wolfssl/internal.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/dh.h>
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif
#if defined(OPENSSL_EXTRA) && defined(WOLFCRYPT_HAVE_SRP) && !defined(NO_SHA)
    #include <wolfssl/wolfcrypt/srp.h>
#endif

#if defined(DEBUG_WOLFSSL) || defined(SHOW_SECRETS) || \
    defined(CHACHA_AEAD_TEST) || defined(WOLFSSL_SESSION_EXPORT_DEBUG)
    #ifndef NO_STDIO_FILESYSTEM
        #ifdef FUSION_RTOS
            #include <fclstdio.h>
        #else
            #include <stdio.h>
        #endif
    #endif
#endif

#ifdef __sun
    #include <sys/filio.h>
#endif


#define ERROR_OUT(err, eLabel) { ret = (int)(err); goto eLabel; }

#ifdef _MSC_VER
    /* disable for while(0) cases at the .c level for now */
    #pragma warning(disable:4127)
#endif

#if defined(WOLFSSL_CALLBACKS) && !defined(LARGE_STATIC_BUFFERS)
    #error \
WOLFSSL_CALLBACKS needs LARGE_STATIC_BUFFERS, please add LARGE_STATIC_BUFFERS
#endif

#if defined(HAVE_SECURE_RENEGOTIATION) && defined(HAVE_RENEGOTIATION_INDICATION)
    #error Cannot use both secure-renegotiation and renegotiation-indication
#endif

#ifndef WOLFSSL_NO_TLS12

#ifndef NO_WOLFSSL_CLIENT
    static int DoServerKeyExchange(WOLFSSL* ssl, const byte* input,
                                   word32* inOutIdx, word32 size);
#endif

#endif /* !WOLFSSL_NO_TLS12 */

enum processReply {
    doProcessInit = 0,
#ifndef NO_WOLFSSL_SERVER
    runProcessOldClientHello,
#endif
    getRecordLayerHeader,
    getData,
    verifyEncryptedMessage,
    decryptMessage,
    verifyMessage,
    runProcessingOneRecord,
    runProcessingOneMessage
};


#ifndef WOLFSSL_NO_TLS12
#if !defined(NO_WOLFSSL_SERVER) || !defined(NO_WOLFSSL_CLIENT)

#ifdef WOLFSSL_TLS13
/* Server random bytes for TLS v1.3 described downgrade protection mechanism. */
static const byte tls13Downgrade[7] = {
    0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44
};
#define TLS13_DOWNGRADE_SZ  sizeof(tls13Downgrade)
#endif
#endif /* !NO_WOLFSSL_SERVER || !NO_WOLFSSL_CLIENT */

#endif /* !WOLFSSL_NO_TLS12 */


int IsTLS(const WOLFSSL* ssl)
{
    if (ssl->version.major == SSLv3_MAJOR && ssl->version.minor >=TLSv1_MINOR)
        return 1;
#ifdef WOLFSSL_DTLS
    if (ssl->version.major == DTLS_MAJOR)
        return 1;
#endif

    return 0;
}

int IsTLS_ex(const ProtocolVersion pv)
{
    if (pv.major == SSLv3_MAJOR && pv.minor >=TLSv1_MINOR)
        return 1;

    return 0;
}


int IsAtLeastTLSv1_2(const WOLFSSL* ssl)
{
    if (ssl->version.major == SSLv3_MAJOR && ssl->version.minor >=TLSv1_2_MINOR)
        return 1;

    return 0;
}

int IsAtLeastTLSv1_3(ProtocolVersion pv)
{
    int ret;
    ret = (pv.major == SSLv3_MAJOR && pv.minor >= TLSv1_3_MINOR);

    return ret;
}

#ifdef WOLFSSL_LEANPSK
#define IsEncryptionOn(ssl, isSend) (ssl)->keys->encryptionOn && ((isSend) ? (ssl)->encryptSetup : (ssl)->decryptSetup)
#else
int IsEncryptionOn(const WOLFSSL* ssl, int isSend)
{
    return ssl->keys->encryptionOn &&
        (isSend ? ssl->encrypt.setup : ssl->decrypt.setup);
}
#endif

void InitSSL_Method(WOLFSSL_METHOD* method, ProtocolVersion pv)
{
    method->version    = pv;
    method->side       = WOLFSSL_CLIENT_END;
    method->downgrade  = 0;
}


void InitCipherSpecs(CipherSpecs* cs)
{
    XMEMSET(cs, 0, sizeof(CipherSpecs));

    cs->bulk_cipher_algorithm = INVALID_BYTE;
    cs->cipher_type           = INVALID_BYTE;
    cs->mac_algorithm         = INVALID_BYTE;
    cs->kea                   = INVALID_BYTE;
    cs->sig_algo              = INVALID_BYTE;
}


#ifndef WOLFSSL_LEANPSK_STATIC
/* Call this when the ssl object needs to have its own ssl->suites object */
int AllocateSuites(WOLFSSL* ssl)
{
    if (ssl->suites == NULL) {
        ssl->suites = (Suites*)XMALLOC(sizeof(Suites), ssl->heap,
                                       DYNAMIC_TYPE_SUITES);
        if (ssl->suites == NULL) {
            WOLFSSL_MSG("Suites Memory error");
            return MEMORY_ERROR;
        }
        XMEMSET(ssl->suites, 0, sizeof(Suites));
    }
    return 0;
}
#endif


#if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
static word32 MacSize(const WOLFSSL* ssl)
{
#ifdef HAVE_TRUNCATED_HMAC
    word32 digestSz = ssl->truncated_hmac ? (byte)TRUNCATED_HMAC_SZ
                                          : ssl->specs.hash_size;
#else
    word32 digestSz = ssl->specs.hash_size;
#endif

    return digestSz;
}
#endif /* HAVE_ENCRYPT_THEN_MAC && !WOLFSSL_AEAD_ONLY */


int InitSSL_Suites(WOLFSSL* ssl)
{
    if (!ssl)
        return BAD_FUNC_ARG;

    ssl->options.cipherSuite0 = CIPHER_BYTE;
    ssl->options.cipherSuite  = TLS_PSK_WITH_AES_128_CBC_SHA256;

    return WOLFSSL_SUCCESS;
}


int InitHandshakeHashes(WOLFSSL* ssl)
{
    int ret;

    /* make sure existing handshake hashes are free'd */
    if (ssl->hsHashes != NULL) {
        FreeHandshakeHashes(ssl);
    }

    /* allocate handshake hashes */
    ssl->hsHashes = (HS_Hashes*)XMALLOC(sizeof(HS_Hashes), ssl->heap,
                                                           DYNAMIC_TYPE_HASHES);
    if (ssl->hsHashes == NULL) {
        WOLFSSL_MSG("HS_Hashes Memory error");
        return MEMORY_E;
    }
    XMEMSET(ssl->hsHashes, 0, sizeof(HS_Hashes));
#ifndef NO_SHA256
    ret = wc_InitSha256_ex(&ssl->hsHashes->hashSha256, ssl->heap,
#ifdef WOLF_CRYPTO_CB
            ssl->devId);
#else
            INVALID_DEVID);
#endif
    if (ret != 0)
        return ret;
    #ifdef WOLFSSL_HASH_FLAGS
        wc_Sha256SetFlags(&ssl->hsHashes->hashSha256, WC_HASH_FLAG_WILLCOPY);
    #endif
#endif
    return ret;
}

void FreeHandshakeHashes(WOLFSSL* ssl)
{
    if (ssl->hsHashes) {
    #ifndef NO_SHA256
        wc_Sha256Free(&ssl->hsHashes->hashSha256);
    #endif
    #if (defined(HAVE_ED25519) || defined(HAVE_ED448) || \
         (defined(WOLFSSL_SM2) && defined(WOLFSSL_SM3))) && \
        !defined(WOLFSSL_NO_CLIENT_AUTH)
        if (ssl->hsHashes->messages != NULL) {
            ForceZero(ssl->hsHashes->messages, ssl->hsHashes->length);
            XFREE(ssl->hsHashes->messages, ssl->heap, DYNAMIC_TYPE_HASHES);
            ssl->hsHashes->messages = NULL;
         }
    #endif

        XFREE(ssl->hsHashes, ssl->heap, DYNAMIC_TYPE_HASHES);
        ssl->hsHashes = NULL;
    }
}

/* called if user attempts to reuse WOLFSSL object for a new session.
 * For example wolfSSL_clear() is called then wolfSSL_connect or accept */
int ReinitSSL_leanpsk(WOLFSSL* ssl)
{
    int ret = 0;

    WOLFSSL_ENTER("ReinitSSL");

    /* arrays */
    if (ssl->arrays == NULL) {
        ssl->arrays = (Arrays*)XMALLOC(sizeof(Arrays), ssl->heap,
                                                           DYNAMIC_TYPE_ARRAYS);
        if (ssl->arrays == NULL) {
            WOLFSSL_MSG("Arrays Memory error");
            return MEMORY_E;
        }
#ifdef WOLFSSL_CHECK_MEM_ZERO
        wc_MemZero_Add("SSL Arrays", ssl->arrays, sizeof(*ssl->arrays));
#endif
        XMEMSET(ssl->arrays, 0, sizeof(Arrays));
    }

    ssl->options.shutdownDone = 0;
#ifndef WOLFSSL_NO_SESSION_RESUMPTION
    if (ssl->session != NULL)
        ssl->session->side = (byte)ssl->options.side;
#endif
    
    return ret;
}

/* init everything to 0, NULL, default values before calling anything that may
   fail so that destructor has a "good" state to cleanup

   ssl      object to initialize
   ctx      parent factory
   writeDup flag indicating this is a write dup only

   0 on success */
int InitSSL_leanpsk(WOLFSSL* ssl, WOLFSSL_METHOD* method, byte ciphersuite0,
        byte ciphersuite1, void* heap)
{
    int  ret;

    XMEMSET(ssl, 0, sizeof(WOLFSSL));

#if defined(WOLFSSL_STATIC_MEMORY)
    ssl->heap = heap;
#endif

    ssl->keys = (Keys*)XMALLOC(sizeof(Keys), heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (ssl->keys == NULL)
        return MEMORY_E;

    ssl->buffers.inputBuffer.buffer = ssl->buffers.inputBuffer.staticBuffer;
    ssl->buffers.inputBuffer.bufferSize  = STATIC_BUFFER_LEN;

    ssl->buffers.outputBuffer.buffer = ssl->buffers.outputBuffer.staticBuffer;
    ssl->buffers.outputBuffer.bufferSize  = STATIC_BUFFER_LEN;
    
    /* initialize states */
    ssl->options.serverState = NULL_STATE;
    ssl->options.clientState = NULL_STATE;
    ssl->options.connectState = CONNECT_BEGIN;
    ssl->options.acceptState  = ACCEPT_BEGIN;
    ssl->options.handShakeState  = NULL_STATE;
    ssl->options.processReply = doProcessInit;
    ssl->options.asyncState = TLS_ASYNC_BEGIN;
    ssl->options.buildMsgState = BUILD_MSG_BEGIN;

#ifdef HAVE_EXTENDED_MASTER
    ssl->options.haveEMS = ctx->haveEMS;
#endif
    ssl->options.useClientOrder = 0;
    ssl->options.mutualAuth = 0;
    
    /* default alert state (none) */
    ssl->alert_history.last_rx.code  = -1;
    ssl->alert_history.last_rx.level = -1;
    ssl->alert_history.last_tx.code  = -1;
    ssl->alert_history.last_tx.level = -1;

    {

    ssl->encryptSetup = 0;
    ssl->decryptSetup = 0;
    }
    InitCipherSpecs(&ssl->specs);

    /* all done with init, now can return errors, call other stuff */
    if ((ret = ReinitSSL_leanpsk(ssl)) != 0) {
        WOLFSSL_MSG_EX("ReinitSSL failed. err = %d", ret);
        return ret;
    }

    if (method->side != (byte)WOLFSSL_NEITHER_END)
        ssl->options.side      = method->side;
#ifndef WOLFSSL_NO_DOWNGRADE
    ssl->options.downgrade    = method->downgrade;
#endif
    ssl->version = method->version;

    if (ret == 0) {
#ifndef WOLFSSL_LEANPSK_STATIC
        AllocateSuites(ssl);
#endif
        
        /* Defer initializing suites until accept or connect */
        ret = InitSSL_Suites(ssl);
#ifdef HAVE_CHACHA
        ssl->options.cipherSuite0 = CHACHA_BYTE;
        ssl->options.cipherSuite  = TLS_PSK_WITH_CHACHA20_POLY1305_SHA256;
#else
        ssl->options.cipherSuite0 = CIPHER_BYTE;
        ssl->options.cipherSuite  = TLS_PSK_WITH_AES_128_CBC_SHA256;
#endif
    }
    
    /* hsHashes */
    ret = InitHandshakeHashes(ssl);
    if (ret != 0) {
        WOLFSSL_MSG_EX("InitHandshakeHashes failed. err = %d", ret);
        return ret;
    }

#ifndef WOLFSSL_NO_SESSION_RESUMPTION
    ssl->session = wolfSSL_NewSession(ssl->heap);
    if (ssl->session == NULL) {
        WOLFSSL_MSG_EX("SSL Session Memory error. wolfSSL_NewSession "
                       "err = %d", ret);
        return MEMORY_E;
    }
#endif

    /* Returns 0 on success, not WOLFSSL_SUCCESS (1) */
    WOLFSSL_MSG_EX("InitSSL done. return 0 (success)");
    return 0;
}


/* free use of temporary arrays */
void FreeArrays(WOLFSSL* ssl, int keep)
{
    if (ssl->arrays) {
#ifndef WOLFSSL_NO_SESSION_RESUMPTION
        if (keep && !IsAtLeastTLSv1_3(ssl->version)) {
            /* keeps session id for user retrieval */
            XMEMCPY(ssl->session->sessionID, ssl->arrays->sessionID, ID_LEN);
            ssl->session->sessionIDSz = ssl->arrays->sessionIDSz;
        }
#endif
        if (ssl->arrays->preMasterSecret) {
#ifndef WOLFSSL_NO_FORCE_ZERO
            ForceZero(ssl->arrays->preMasterSecret, ENCRYPT_LEN);
#endif
            XFREE(ssl->arrays->preMasterSecret, ssl->heap, DYNAMIC_TYPE_SECRET);
            ssl->arrays->preMasterSecret = NULL;
        }
        XFREE(ssl->arrays->pendingMsg, ssl->heap, DYNAMIC_TYPE_ARRAYS);
        ssl->arrays->pendingMsg = NULL;
#ifndef WOLFSSL_NO_FORCE_ZERO
        ForceZero(ssl->arrays, sizeof(Arrays)); /* clear arrays struct */
#endif
    }
    XFREE(ssl->arrays, ssl->heap, DYNAMIC_TYPE_ARRAYS);
    ssl->arrays = NULL;
}

void FreeKeyExchange(WOLFSSL* ssl)
{
    /* Cleanup signature buffer */
    if (ssl->buffers.sig.buffer) {
        XFREE(ssl->buffers.sig.buffer, ssl->heap, DYNAMIC_TYPE_SIGNATURE);
        ssl->buffers.sig.buffer = NULL;
        ssl->buffers.sig.length = 0;
    }

    /* Cleanup digest buffer */
    if (ssl->buffers.digest.buffer) {
        /* Only free if digest buffer was not set using SetDigest */
        if (!ssl->options.dontFreeDigest) {
            XFREE(ssl->buffers.digest.buffer, ssl->heap, DYNAMIC_TYPE_DIGEST);
        }
        ssl->buffers.digest.buffer = NULL;
        ssl->buffers.digest.length = 0;
        ssl->options.dontFreeDigest = 0;
    }

    /* Free handshake key */
#ifndef WOLFSSL_LEANPSK_STATIC
    FreeKey(ssl, ssl->hsType, &ssl->hsKey);
#endif
#ifdef WOLFSSL_DUAL_ALG_CERTS
    FreeKey(ssl, ssl->hsAltType, &ssl->hsAltKey);
#endif /* WOLFSSL_DUAL_ALG_CERTS */

#ifndef NO_DH
    /* Free temp DH key */
    FreeKey(ssl, DYNAMIC_TYPE_DH, (void**)&ssl->buffers.serverDH_Key);
#endif
}


#ifndef WOLFSSL_LEANPSK_STATIC
/* Free up all memory used by Suites structure from WOLFSSL */
void FreeSuites(WOLFSSL* ssl)
{
    XFREE(ssl->suites, ssl->heap, DYNAMIC_TYPE_SUITES);
    ssl->suites = NULL;
}
#endif

/* In case holding SSL object in array and don't want to free actual ssl */
void SSL_ResourceFree(WOLFSSL* ssl)
{
    /* Note: any resources used during the handshake should be released in the
     * function FreeHandshakeResources(). Be careful with the special cases
     * like the RNG which may optionally be kept for the whole session. (For
     * example with the RNG, it isn't used beyond the handshake except when
     * using stream ciphers where it is retained. */

    if (ssl->options.side == (byte)WOLFSSL_SERVER_END) {
        WOLFSSL_MSG("Free'ing server ssl");
    }
    else {
        WOLFSSL_MSG("Free'ing client ssl");
    }

#ifdef HAVE_EX_DATA_CLEANUP_HOOKS
    wolfSSL_CRYPTO_cleanup_ex_data(&ssl->ex_data);
#endif

    FreeArrays(ssl, 0);
    FreeKeyExchange(ssl);
#ifdef WOLFSSL_ASYNC_IO
    /* Cleanup async */
    FreeAsyncCtx(ssl, 1);
#endif
    if (ssl->options.weOwnRng) {
        wc_FreeRng(ssl->rng);
        XFREE(ssl->rng, ssl->heap, DYNAMIC_TYPE_RNG);
        ssl->rng = NULL;
        ssl->options.weOwnRng = 0;
    }
#ifndef WOLFSSL_LEANPSK_STATIC
    FreeSuites(ssl);
#endif
    FreeHandshakeHashes(ssl);
    if (ssl->keys != NULL) {
        XFREE(ssl->keys, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
    XFREE(ssl->buffers.domainName.buffer, ssl->heap, DYNAMIC_TYPE_DOMAIN);

#ifndef WOLFSSL_NO_FORCE_ZERO
    /* clear keys struct after session */
    ForceZero(&ssl->keys, sizeof(Keys));
#endif
#ifdef WOLFSSL_TLS13
    ForceZero(&ssl->clientSecret, sizeof(ssl->clientSecret));
    ForceZero(&ssl->serverSecret, sizeof(ssl->serverSecret));

#if defined(HAVE_ECH)
    if (ssl->options.useEch == 1) {
        FreeEchConfigs(ssl->echConfigs, ssl->heap);
        ssl->echConfigs = NULL;
        /* free the ech specific hashes */
        ssl->hsHashes = ssl->hsHashesEch;
        FreeHandshakeHashes(ssl);
        ssl->options.useEch = 0;
    }
#endif /* HAVE_ECH */
#endif /* WOLFSSL_TLS13 */
#ifdef WOLFSSL_HAVE_TLS_UNIQUE
    ForceZero(&ssl->clientFinished, TLS_FINISHED_SZ_MAX);
    ForceZero(&ssl->serverFinished, TLS_FINISHED_SZ_MAX);
    ssl->serverFinished_len = 0;
    ssl->clientFinished_len = 0;
#endif
#ifndef NO_DH
    if (ssl->buffers.serverDH_Priv.buffer != NULL) {
        ForceZero(ssl->buffers.serverDH_Priv.buffer,
                                             ssl->buffers.serverDH_Priv.length);
    }
    XFREE(ssl->buffers.serverDH_Priv.buffer, ssl->heap, DYNAMIC_TYPE_PRIVATE_KEY);
    XFREE(ssl->buffers.serverDH_Pub.buffer, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
    /* parameters (p,g) may be owned by ctx */
    if (ssl->buffers.weOwnDH) {
        XFREE(ssl->buffers.serverDH_G.buffer, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
        XFREE(ssl->buffers.serverDH_P.buffer, ssl->heap, DYNAMIC_TYPE_PUBLIC_KEY);
    }
#endif /* !NO_DH */
#ifndef NO_CERTS
    ssl->keepCert = 0; /* make sure certificate is free'd */
    wolfSSL_UnloadCertsKeys(ssl);
#endif
#ifndef NO_RSA
    FreeKey(ssl, DYNAMIC_TYPE_RSA, (void**)&ssl->peerRsaKey);
    ssl->peerRsaKeyPresent = 0;
#endif
#if defined(WOLFSSL_RENESAS_TSIP_TLS) || defined(WOLFSSL_RENESAS_FSPSM_TLS)
    XFREE(ssl->peerSceTsipEncRsaKeyIndex, ssl->heap, DYNAMIC_TYPE_RSA);
    Renesas_cmn_Cleanup(ssl);
#endif
    if (ssl->buffers.inputBuffer.dynamicFlag)
        ShrinkInputBuffer(ssl, FORCED_FREE);
    if (ssl->buffers.outputBuffer.dynamicFlag)
        ShrinkOutputBuffer(ssl);
#if defined(WOLFSSL_SEND_HRR_COOKIE) && !defined(NO_WOLFSSL_SERVER)
    if (ssl->buffers.tls13CookieSecret.buffer != NULL) {
        ForceZero(ssl->buffers.tls13CookieSecret.buffer,
            ssl->buffers.tls13CookieSecret.length);
    }
    XFREE(ssl->buffers.tls13CookieSecret.buffer, ssl->heap,
          DYNAMIC_TYPE_COOKIE_PWD);
#endif
#ifdef WOLFSSL_DTLS
    DtlsMsgPoolReset(ssl);
    if (ssl->dtls_rx_msg_list != NULL) {
        DtlsMsgListDelete(ssl->dtls_rx_msg_list, ssl->heap);
        ssl->dtls_rx_msg_list = NULL;
        ssl->dtls_rx_msg_list_sz = 0;
    }
    XFREE(ssl->buffers.dtlsCtx.peer.sa, ssl->heap, DYNAMIC_TYPE_SOCKADDR);
    ssl->buffers.dtlsCtx.peer.sa = NULL;
#ifndef NO_WOLFSSL_SERVER
    if (ssl->buffers.dtlsCookieSecret.buffer != NULL) {
        ForceZero(ssl->buffers.dtlsCookieSecret.buffer,
            ssl->buffers.dtlsCookieSecret.length);
    }
    XFREE(ssl->buffers.dtlsCookieSecret.buffer, ssl->heap,
          DYNAMIC_TYPE_COOKIE_PWD);
#endif

#ifdef WOLFSSL_DTLS13
    if (ssl->dtls13ClientHello != NULL) {
        XFREE(ssl->dtls13ClientHello, ssl->heap, DYNAMIC_TYPE_DTLS_MSG);
        ssl->dtls13ClientHello = NULL;
        ssl->dtls13ClientHelloSz = 0;
    }
#endif /* WOLFSSL_DTLS13 */

#endif /* WOLFSSL_DTLS */
#ifdef OPENSSL_EXTRA
#ifndef NO_BIO
    /* Don't free if there was/is a previous element in the chain.
     * This means that this BIO was part of a chain that will be
     * free'd separately. */
    if (ssl->biord != ssl->biowr)        /* only free write if different */
        if (ssl->biowr != NULL && ssl->biowr->prev == NULL)
            wolfSSL_BIO_free(ssl->biowr);
    if (ssl->biord != NULL && ssl->biord->prev == NULL)
        wolfSSL_BIO_free(ssl->biord);
    ssl->biowr = NULL;
    ssl->biord = NULL;
#endif
#endif
#ifdef HAVE_LIBZ
    FreeStreams(ssl);
#endif
#ifdef HAVE_ECC
    FreeKey(ssl, DYNAMIC_TYPE_ECC, (void**)&ssl->peerEccKey);
    ssl->peerEccKeyPresent = 0;
    FreeKey(ssl, DYNAMIC_TYPE_ECC, (void**)&ssl->peerEccDsaKey);
    ssl->peerEccDsaKeyPresent = 0;
#endif
#if defined(HAVE_ECC) || defined(HAVE_CURVE25519) ||defined(HAVE_CURVE448)
    {
        int dtype = 0;
    #ifdef HAVE_ECC
        dtype = DYNAMIC_TYPE_ECC;
    #endif
    #ifdef HAVE_CURVE25519
        if (ssl->peerX25519KeyPresent
    #ifdef HAVE_ECC
                           || ssl->eccTempKeyPresent == DYNAMIC_TYPE_CURVE25519
    #endif /* HAVE_ECC */
           )
        {
            dtype = DYNAMIC_TYPE_CURVE25519;
        }
    #endif /* HAVE_CURVE25519 */
    #ifdef HAVE_CURVE448
        if (ssl->peerX448KeyPresent
    #ifdef HAVE_ECC
                             || ssl->eccTempKeyPresent == DYNAMIC_TYPE_CURVE448
    #endif /* HAVE_ECC */
           )
        {
            dtype = DYNAMIC_TYPE_CURVE448;
        }
    #endif /* HAVE_CURVE448 */
        FreeKey(ssl, dtype, (void**)&ssl->eccTempKey);
        ssl->eccTempKeyPresent = 0;
    }
#endif /* HAVE_ECC || HAVE_CURVE25519 || HAVE_CURVE448 */
#ifdef HAVE_CURVE25519
    FreeKey(ssl, DYNAMIC_TYPE_CURVE25519, (void**)&ssl->peerX25519Key);
    ssl->peerX25519KeyPresent = 0;
#endif
#ifdef HAVE_ED25519
    FreeKey(ssl, DYNAMIC_TYPE_ED25519, (void**)&ssl->peerEd25519Key);
    ssl->peerEd25519KeyPresent = 0;
    #ifdef HAVE_PK_CALLBACKS
        if (ssl->buffers.peerEd25519Key.buffer != NULL) {
            XFREE(ssl->buffers.peerEd25519Key.buffer, ssl->heap,
                                                          DYNAMIC_TYPE_ED25519);
            ssl->buffers.peerEd25519Key.buffer = NULL;
        }
    #endif
#endif
#ifdef HAVE_CURVE448
    FreeKey(ssl, DYNAMIC_TYPE_CURVE448, (void**)&ssl->peerX448Key);
    ssl->peerX448KeyPresent = 0;
#endif
#ifdef HAVE_ED448
    FreeKey(ssl, DYNAMIC_TYPE_ED448, (void**)&ssl->peerEd448Key);
    ssl->peerEd448KeyPresent = 0;
    #ifdef HAVE_PK_CALLBACKS
        if (ssl->buffers.peerEd448Key.buffer != NULL) {
            XFREE(ssl->buffers.peerEd448Key.buffer, ssl->heap,
                                                            DYNAMIC_TYPE_ED448);
            ssl->buffers.peerEd448Key.buffer = NULL;
        }
    #endif
#endif
#if defined(HAVE_PQC) && defined(HAVE_FALCON)
    FreeKey(ssl, DYNAMIC_TYPE_FALCON, (void**)&ssl->peerFalconKey);
    ssl->peerFalconKeyPresent = 0;
#endif
#ifdef HAVE_PK_CALLBACKS
    #ifdef HAVE_ECC
        XFREE(ssl->buffers.peerEccDsaKey.buffer, ssl->heap, DYNAMIC_TYPE_ECC);
    #endif /* HAVE_ECC */
    #ifndef NO_RSA
        XFREE(ssl->buffers.peerRsaKey.buffer, ssl->heap, DYNAMIC_TYPE_RSA);
    #endif /* NO_RSA */
#endif /* HAVE_PK_CALLBACKS */
#ifdef HAVE_TLS_EXTENSIONS
#if !defined(NO_TLS)
    TLSX_FreeAll(ssl->extensions, ssl->heap);
#endif /* !NO_TLS */
#ifdef HAVE_ALPN
    if (ssl->alpn_peer_requested != NULL) {
        XFREE(ssl->alpn_peer_requested, ssl->heap, DYNAMIC_TYPE_ALPN);
        ssl->alpn_peer_requested = NULL;
        ssl->alpn_peer_requested_length = 0;
    }
#endif
#endif /* HAVE_TLS_EXTENSIONS */
#if defined(WOLFSSL_APACHE_MYNEWT) && !defined(WOLFSSL_LWIP)
    if (ssl->mnCtx) {
        mynewt_ctx_clear(ssl->mnCtx);
        ssl->mnCtx = NULL;
    }
#endif
#ifdef HAVE_NETX
    if (ssl->nxCtx.nxPacket)
        nx_packet_release(ssl->nxCtx.nxPacket);
#endif
#if defined(OPENSSL_EXTRA) || defined(WOLFSSL_WPAS_SMALL)
    if (ssl->x509_store_pt)
        wolfSSL_X509_STORE_free(ssl->x509_store_pt);
#endif
#ifdef KEEP_PEER_CERT
    FreeX509(&ssl->peerCert);
#endif

#ifndef WOLFSSL_NO_SESSION_RESUMPTION
    if (ssl->session != NULL)
        wolfSSL_FreeSession(ssl->ctx, ssl->session);
#endif
#ifdef HAVE_WRITE_DUP
    if (ssl->dupWrite) {
        FreeWriteDup(ssl);
    }
#endif
#ifdef OPENSSL_EXTRA
    if (ssl->param) {
        XFREE(ssl->param, ssl->heap, DYNAMIC_TYPE_OPENSSL);
    }
#endif
#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_POST_HANDSHAKE_AUTH)
    while (ssl->certReqCtx != NULL) {
        CertReqCtx* curr = ssl->certReqCtx;
        ssl->certReqCtx = curr->next;
        XFREE(curr, ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
#endif
#ifdef WOLFSSL_STATIC_EPHEMERAL
    #ifndef NO_DH
    FreeDer(&ssl->staticKE.dhKey);
    #endif
    #ifdef HAVE_ECC
    FreeDer(&ssl->staticKE.ecKey);
    #endif
    #ifdef HAVE_CURVE25519
    FreeDer(&ssl->staticKE.x25519Key);
    #endif
    #ifdef HAVE_CURVE448
    FreeDer(&ssl->staticKE.x448Key);
    #endif
#endif

#ifdef WOLFSSL_STATIC_MEMORY
    /* check if using fixed io buffers and free them */
    if (ssl->heap != NULL) {
    #ifdef WOLFSSL_HEAP_TEST
    /* avoid dereferencing a test value */
    if (ssl->heap != (void*)WOLFSSL_HEAP_TEST) {
    #endif
        void* heap = ssl->ctx ? ssl->ctx->heap : ssl->heap;
    #ifndef WOLFSSL_STATIC_MEMORY_LEAN
        WOLFSSL_HEAP_HINT* ssl_hint = (WOLFSSL_HEAP_HINT*)ssl->heap;
        WOLFSSL_HEAP*      ctx_heap;

        ctx_heap = ssl_hint->memory;
    #ifndef SINGLE_THREADED
        if (wc_LockMutex(&(ctx_heap->memory_mutex)) != 0) {
            WOLFSSL_MSG("Bad memory_mutex lock");
        }
    #endif
        ctx_heap->curIO--;
        if (FreeFixedIO(ctx_heap, &(ssl_hint->outBuf)) != 1) {
            WOLFSSL_MSG("Error freeing fixed output buffer");
        }
        if (FreeFixedIO(ctx_heap, &(ssl_hint->inBuf)) != 1) {
            WOLFSSL_MSG("Error freeing fixed output buffer");
        }

        /* check if handshake count has been decreased*/
        if (ssl_hint->haFlag && ctx_heap->curHa > 0) {
            ctx_heap->curHa--;
        }
    #ifndef SINGLE_THREADED
        wc_UnLockMutex(&(ctx_heap->memory_mutex));
    #endif

        /* check if tracking stats */
        if (ctx_heap->flag & WOLFMEM_TRACK_STATS) {
            XFREE(ssl_hint->stats, heap, DYNAMIC_TYPE_SSL);
        }
    #endif /* !WOLFSSL_STATIC_MEMORY_LEAN */
        XFREE(ssl->heap, heap, DYNAMIC_TYPE_SSL);
    #ifdef WOLFSSL_HEAP_TEST
    }
    #endif
    }
#endif /* WOLFSSL_STATIC_MEMORY */
}

/* Free any handshake resources no longer needed */
void FreeHandshakeResources(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("FreeHandshakeResources");
    
    /* input buffer */
    if (ssl->buffers.inputBuffer.dynamicFlag)
        ShrinkInputBuffer(ssl, NO_FORCED_FREE);

#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_POST_HANDSHAKE_AUTH)
    if (!ssl->options.tls1_3)
#endif
    {
    #ifndef OPENSSL_EXTRA
        /* free suites unless using compatibility layer */
        #ifndef WOLFSSL_LEANPSK_STATIC
        FreeSuites(ssl);
        #endif
    #endif
        /* hsHashes */
        FreeHandshakeHashes(ssl);
    }

    /* RNG */
    if (ssl->options.tls1_1 == 0u
#ifndef WOLFSSL_AEAD_ONLY
        || ssl->specs.cipher_type == (byte)stream
#endif
            ) {
        if (ssl->options.weOwnRng) {
            wc_FreeRng(ssl->rng);
            XFREE(ssl->rng, ssl->heap, DYNAMIC_TYPE_RNG);
            ssl->rng = NULL;
            ssl->options.weOwnRng = 0;
        }
    }

#if defined(WOLFSSL_TLS13) && defined(WOLFSSL_POST_HANDSHAKE_AUTH) && \
                                                    defined(HAVE_SESSION_TICKET)
    if (!ssl->options.tls1_3)
#endif
        /* arrays */
        if (ssl->options.saveArrays == 0u)
            FreeArrays(ssl, 1);

#ifdef WOLFSSL_STATIC_MEMORY
    /* when done with handshake decrement current handshake count */
    if (ssl->heap != NULL) {
    #ifdef WOLFSSL_HEAP_TEST
    /* avoid dereferencing a test value */
    if (ssl->heap != (void*)WOLFSSL_HEAP_TEST) {
    #endif
        WOLFSSL_HEAP_HINT* ssl_hint = (WOLFSSL_HEAP_HINT*)ssl->heap;
        WOLFSSL_HEAP*      ctx_heap;

        ctx_heap = ssl_hint->memory;
    #ifndef SINGLE_THREADED
        if (wc_LockMutex(&(ctx_heap->memory_mutex)) != 0) {
            WOLFSSL_MSG("Bad memory_mutex lock");
        }
    #endif
    #ifndef WOLFSSL_STATIC_MEMORY_LEAN
        if (ctx_heap->curHa > 0) {
            ctx_heap->curHa--;
        }
        ssl_hint->haFlag = 0; /* set to zero since handshake has been dec */
    #endif
    #ifndef SINGLE_THREADED
        wc_UnLockMutex(&(ctx_heap->memory_mutex));
    #endif
    #ifdef WOLFSSL_HEAP_TEST
    }
    #endif
    }
#endif /* WOLFSSL_STATIC_MEMORY */
}


/* heap argument is the heap hint used when creating SSL */
void FreeSSL(WOLFSSL* ssl, void* heap)
{
    SSL_ResourceFree(ssl);
    XFREE(ssl, heap, DYNAMIC_TYPE_SSL);
    (void)heap;
#ifdef WOLFSSL_CHECK_MEM_ZERO
    wc_MemZero_Check(ssl, sizeof(*ssl));
#endif
}

#if !defined(NO_OLD_TLS) || defined(WOLFSSL_DTLS) || \
    !defined(WOLFSSL_NO_TLS12) || \
    ((defined(HAVE_CHACHA) || defined(HAVE_AESCCM) || defined(HAVE_AESGCM) || \
     defined(WOLFSSL_SM4_GCM) || defined(WOLFSSL_SM4_CCM)) \
     && defined(HAVE_AEAD))

#if defined(WOLFSSL_DTLS) || !defined(WOLFSSL_NO_TLS12)
static WC_INLINE void GetSEQIncrement(WOLFSSL* ssl, int verify, word32 seq[2])
{
    if (verify) {
        seq[0] = ssl->keys->peer_sequence_number_hi;
        seq[1] = ssl->keys->peer_sequence_number_lo++;
        if (seq[1] > ssl->keys->peer_sequence_number_lo) {
            /* handle rollover */
            ssl->keys->peer_sequence_number_hi++;
        }
    }
    else {
        seq[0] = ssl->keys->sequence_number_hi;
        seq[1] = ssl->keys->sequence_number_lo++;
        if (seq[1] > ssl->keys->sequence_number_lo) {
            /* handle rollover */
            ssl->keys->sequence_number_hi++;
        }
    }
}
#endif /* WOLFSSL_DTLS || !WOLFSSL_NO_TLS12 */



#if defined(WOLFSSL_DTLS) || !defined(WOLFSSL_NO_TLS12)
void WriteSEQ(WOLFSSL* ssl, int verifyOrder, byte* out)
{
    word32 seq[2] = {0, 0};

    #ifdef WOLFSSL_DTLS
    if (!ssl->options.dtls)
#endif
    {
        GetSEQIncrement(ssl, verifyOrder, seq);
    }
#ifdef WOLFSSL_DTLS
    else {
        DtlsGetSEQ(ssl, verifyOrder, seq);
    }
    #endif

    c32toa(seq[0], out);
    c32toa(seq[1], out + OPAQUE32_LEN);
}
#endif /* WOLFSSL_DTLS || !WOLFSSL_NO_TLS12 */
#endif /* !NO_OLD_TLS || WOLFSSL_DTLS || !WOLFSSL_NO_TLS12 ||
        *     ((HAVE_CHACHA || HAVE_AESCCM || HAVE_AESGCM || WOLFSSL_SM4_GCM ||
        *       WOLFSSL_SM4_CCM) && HAVE_AEAD) */

/* add record layer header for message */
static void AddRecordHeader(byte* output, word32 length, byte type, WOLFSSL* ssl, int epochOrder)
{
    RecordLayerHeader* rl;

    (void)epochOrder;

    /* record layer header */
    rl = (RecordLayerHeader*)output;
    if (rl == NULL) {
        return;
    }
    rl->type    = type;
    rl->pvMajor = ssl->version.major;       /* type and version same in each */
    rl->pvMinor = ssl->version.minor;

#ifdef WOLFSSL_ALTERNATIVE_DOWNGRADE
    if (ssl->options.side == WOLFSSL_CLIENT_END
    &&  ssl->options.connectState == CONNECT_BEGIN
    && !ssl->options.resuming) {
        rl->pvMinor = ssl->options.downgrade ? ssl->options.minDowngrade
                                             : ssl->version.minor;
    }
#endif

    {
        c16toa((word16)length, rl->length);
    }
}


#if !defined(WOLFSSL_NO_TLS12) || (defined(HAVE_SESSION_TICKET) && \
                                                    !defined(NO_WOLFSSL_SERVER))
/* add handshake header for message */
static void AddHandShakeHeader(byte* output, word32 length,
                               word32 fragOffset, word32 fragLength,
                               byte type, WOLFSSL* ssl)
{
    HandShakeHeader* hs;
    (void)fragOffset;
    (void)fragLength;
    (void)ssl;

    /* handshake header */
    hs = (HandShakeHeader*)output;
    if (hs == NULL)
        return;

    hs->type = type;
    c32to24(length, hs->length);         /* type and length same for each */
#ifdef WOLFSSL_DTLS
    if (ssl->options.dtls) {
        DtlsHandShakeHeader* dtls;

        /* dtls handshake header extensions */
        dtls = (DtlsHandShakeHeader*)output;
        c16toa(ssl->keys->dtls_handshake_number++, dtls->message_seq);
        c32to24(fragOffset, dtls->fragment_offset);
        c32to24(fragLength, dtls->fragment_length);
    }
#endif
}

/* add both headers for handshake message */
static void AddHeaders(byte* output, word32 length, byte type, WOLFSSL* ssl)
{
    word32 lengthAdj = HANDSHAKE_HEADER_SZ;
    word32 outputAdj = RECORD_HEADER_SZ;

#ifdef WOLFSSL_DTLS
    if (ssl->options.dtls) {
        lengthAdj += DTLS_HANDSHAKE_EXTRA;
        outputAdj += DTLS_RECORD_EXTRA;
    }
#endif

    AddRecordHeader(output, length + lengthAdj, handshake, ssl, CUR_ORDER);
    AddHandShakeHeader(output + outputAdj, length, 0, length, type, ssl);
}
#endif /* !WOLFSSL_NO_TLS12 || (HAVE_SESSION_TICKET && !NO_WOLFSSL_SERVER) */


/* return bytes received, -1 on error */
static int wolfSSLReceive(WOLFSSL* ssl, byte* buf, word32 sz)
{
    int recvd;
    int retryLimit = WOLFSSL_MODE_AUTO_RETRY_ATTEMPTS;

#ifdef WOLFSSL_QUIC
    if (WOLFSSL_IS_QUIC(ssl)) {
        /* QUIC only "reads" from data provided by the application
         * via wolfSSL_provide_quic_data(). Transfer from there
         * into the inputBuffer. */
        return wolfSSL_quic_receive(ssl, buf, sz);
    }
#endif

    if (ssl->CBIORecv == NULL) {
        WOLFSSL_MSG("Your IO Recv callback is null, please set");
        return -1;
    }

retry:
    recvd = ssl->CBIORecv(ssl, (char *)buf, (int)sz,
        #ifndef WOLFSSL_LEANPSK_STATIC_IO
        ssl->IOCB_ReadCtx
    #else
         NULL
    #endif
    );
    if (recvd < 0) {
        switch (recvd) {
            case WOLFSSL_CBIO_ERR_GENERAL:        /* general/unknown error */
                #ifdef WOLFSSL_APACHE_HTTPD
                #ifndef NO_BIO
                    if (ssl->biord) {
                        /* If retry and read flags are set, return WANT_READ */
                        if ((ssl->biord->flags & WOLFSSL_BIO_FLAG_READ) &&
                            (ssl->biord->flags & WOLFSSL_BIO_FLAG_RETRY)) {
                            return WANT_READ;
                        }
                    }
                #endif
                #endif
                return -1;

            case WOLFSSL_CBIO_ERR_WANT_READ:      /* want read, would block */
#ifndef WOLFSSL_LEANPSK
                if (retryLimit > 0 && ssl->ctx->autoRetry &&
                        !ssl->options.handShakeDone && !ssl->options.dtls) {
                    retryLimit--;
                    goto retry;
                }
#endif
                return WANT_READ;

            case WOLFSSL_CBIO_ERR_CONN_RST:       /* connection reset */
                #if defined(USE_WINDOWS_API) && defined(WOLFSSL_DTLS)
                if (ssl->options.dtls) {
                    goto retry;
                }
                #endif
                ssl->options.connReset = 1;
                return -1;

            case WOLFSSL_CBIO_ERR_ISR:            /* interrupt */
                /* see if we got our timeout */
                #ifdef WOLFSSL_CALLBACKS
                    if (ssl->toInfoOn) {
                        struct itimerval timeout;
                        getitimer(ITIMER_REAL, &timeout);
                        if (timeout.it_value.tv_sec == 0 &&
                                                timeout.it_value.tv_usec == 0) {
                            XSTRNCPY(ssl->timeoutInfo.timeoutName,
                                    "recv() timeout", MAX_TIMEOUT_NAME_SZ);
                            ssl->timeoutInfo.timeoutName[
                                MAX_TIMEOUT_NAME_SZ] = '\0';

                            WOLFSSL_MSG("Got our timeout");
                            return WANT_READ;
                        }
                    }
                #endif
                goto retry;

            case WOLFSSL_CBIO_ERR_CONN_CLOSE:     /* peer closed connection */
                ssl->options.isClosed = 1;
                return -1;

            case WOLFSSL_CBIO_ERR_TIMEOUT:
            #ifdef WOLFSSL_DTLS
#ifdef WOLFSSL_DTLS13
                if (ssl->options.dtls && IsAtLeastTLSv1_3(ssl->version)) {
                    /* TODO: support WANT_WRITE here */
                    if (Dtls13RtxTimeout(ssl) < 0) {
                        WOLFSSL_MSG(
                            "Error trying to retransmit DTLS buffered message");
                        return -1;
                    }
                    goto retry;
                }
#endif /* WOLFSSL_DTLS13 */

                if (IsDtlsNotSctpMode(ssl) &&
                    ssl->options.handShakeState != HANDSHAKE_DONE &&
                    DtlsMsgPoolTimeout(ssl) == 0 &&
                    DtlsMsgPoolSend(ssl, 0) == 0) {

                    /* retry read for DTLS during handshake only */
                    goto retry;
                }
            #endif
                return -1;

            default:
                WOLFSSL_MSG("Unexpected recv return code");
                return recvd;
        }
    }

    return recvd;
}


/* Switch dynamic output buffer back to static, buffer is assumed clear */
void ShrinkOutputBuffer(WOLFSSL* ssl)
{
    WOLFSSL_MSG("Shrinking output buffer");
    if (ssl->buffers.outputBuffer.dynamicFlag != (byte)WOLFSSL_EXTERNAL_IO_BUFFER) {
        XFREE(ssl->buffers.outputBuffer.buffer - ssl->buffers.outputBuffer.offset,
          ssl->heap, DYNAMIC_TYPE_OUT_BUFFER);
    }
    ssl->buffers.outputBuffer.buffer = ssl->buffers.outputBuffer.staticBuffer;
    ssl->buffers.outputBuffer.bufferSize  = STATIC_BUFFER_LEN;
    ssl->buffers.outputBuffer.dynamicFlag = 0;
    ssl->buffers.outputBuffer.offset      = 0;
    /* idx and length are assumed to be 0. */
}


/* Switch dynamic input buffer back to static, keep any remaining input */
/* forced free means cleaning up */
/* Be *CAREFUL* where this function is called. ProcessReply relies on
 * inputBuffer.idx *NOT* changing inside the ProcessReply function. ProcessReply
 * calls ShrinkInputBuffer itself when it is safe to do so. Don't overuse it. */
void ShrinkInputBuffer(WOLFSSL* ssl, int forcedFree)
{
    int usedLength = ssl->buffers.inputBuffer.length -
                     ssl->buffers.inputBuffer.idx;
    if (!forcedFree && (usedLength > STATIC_BUFFER_LEN ||
            ssl->buffers.clearOutputBuffer.length > 0u))
        return;

    WOLFSSL_MSG("Shrinking input buffer");

    if (!forcedFree && usedLength > 0) {
        XMEMCPY(ssl->buffers.inputBuffer.staticBuffer,
               ssl->buffers.inputBuffer.buffer + ssl->buffers.inputBuffer.idx,
               usedLength);
    }

    if (ssl->buffers.inputBuffer.dynamicFlag != (byte)WOLFSSL_EXTERNAL_IO_BUFFER) {
    #ifndef WOLFSSL_NO_FORCE_ZERO
        ForceZero(ssl->buffers.inputBuffer.buffer,
            ssl->buffers.inputBuffer.length);
    #endif
        XFREE(ssl->buffers.inputBuffer.buffer - ssl->buffers.inputBuffer.offset,
          ssl->heap, DYNAMIC_TYPE_IN_BUFFER);
    }
    ssl->buffers.inputBuffer.buffer = ssl->buffers.inputBuffer.staticBuffer;
    ssl->buffers.inputBuffer.bufferSize  = STATIC_BUFFER_LEN;
    ssl->buffers.inputBuffer.dynamicFlag = 0;
    ssl->buffers.inputBuffer.offset      = 0;
    ssl->buffers.inputBuffer.idx = 0;
    ssl->buffers.inputBuffer.length = (word32)usedLength;
}

int SendBuffered(WOLFSSL* ssl)
{
    int retryLimit = WOLFSSL_MODE_AUTO_RETRY_ATTEMPTS;

    if (ssl->CBIOSend == NULL && !WOLFSSL_IS_QUIC(ssl)) {
        WOLFSSL_MSG("Your IO Send callback is null, please set");
        return SOCKET_ERROR_E;
    }

#ifdef WOLFSSL_DEBUG_TLS
    if (ssl->buffers.outputBuffer.idx == 0) {
        WOLFSSL_MSG("Data to send");
        WOLFSSL_BUFFER(ssl->buffers.outputBuffer.buffer,
                       ssl->buffers.outputBuffer.length);
    }
#endif

#ifdef WOLFSSL_QUIC
    if (WOLFSSL_IS_QUIC(ssl)) {
        return wolfSSL_quic_send(ssl);
    }
#endif

    while (ssl->buffers.outputBuffer.length > 0u) {
        int sent = 0;
retry:
        sent = ssl->CBIOSend(ssl,
                             (char*)ssl->buffers.outputBuffer.buffer +
                             ssl->buffers.outputBuffer.idx,
                             (int)ssl->buffers.outputBuffer.length,
#ifndef WOLFSSL_LEANPSK_STATIC_IO
                             ssl->IOCB_WriteCtx
#else
                            NULL
#endif
                            );
        if (sent < 0) {
            switch (sent) {

                case WOLFSSL_CBIO_ERR_WANT_WRITE:        /* would block */
#ifndef WOLFSSL_LEANPSK
                    if (retryLimit > 0 && ssl->ctx->autoRetry &&
                            !ssl->options.handShakeDone && !ssl->options.dtls) {
                        retryLimit--;
                        goto retry;
                    }
#endif
                    return WANT_WRITE;

                case WOLFSSL_CBIO_ERR_CONN_RST:          /* connection reset */
                    ssl->options.connReset = 1;
                    break;

                case WOLFSSL_CBIO_ERR_ISR:               /* interrupt */
                    /* see if we got our timeout */
                    #ifdef WOLFSSL_CALLBACKS
                        if (ssl->toInfoOn) {
                            struct itimerval timeout;
                            getitimer(ITIMER_REAL, &timeout);
                            if (timeout.it_value.tv_sec == 0 &&
                                                timeout.it_value.tv_usec == 0) {
                                XSTRNCPY(ssl->timeoutInfo.timeoutName,
                                        "send() timeout", MAX_TIMEOUT_NAME_SZ);
                                ssl->timeoutInfo.timeoutName[
                                    MAX_TIMEOUT_NAME_SZ] = '\0';

                                WOLFSSL_MSG("Got our timeout");
                                return WANT_WRITE;
                            }
                        }
                    #endif
                    continue;

                case WOLFSSL_CBIO_ERR_CONN_CLOSE: /* epipe / conn closed */
                    ssl->options.connReset = 1;  /* treat same as reset */
                    break;

                default:
                    return SOCKET_ERROR_E;
            }

            return SOCKET_ERROR_E;
        }

        if (sent > (int)ssl->buffers.outputBuffer.length) {
            WOLFSSL_MSG("SendBuffered() out of bounds read");
            return SEND_OOB_READ_E;
        }

        ssl->buffers.outputBuffer.idx += sent;
        ssl->buffers.outputBuffer.length -= sent;
    }

    ssl->buffers.outputBuffer.idx = 0;

    if (ssl->buffers.outputBuffer.dynamicFlag)
        ShrinkOutputBuffer(ssl);

    return 0;
}


/* returns the current location in the output buffer to start writing to */
byte* GetOutputBuffer(WOLFSSL* ssl)
{
    return ssl->buffers.outputBuffer.buffer + ssl->buffers.outputBuffer.idx +
             ssl->buffers.outputBuffer.length;
}

/* sets the output buffer from an externally provided buffer */
int SetOutputBuffer(WOLFSSL* ssl, byte* buf, int bufSz)
{
    if (ssl == NULL || buf == NULL) {
        return BAD_FUNC_ARG;
    }

    /* data waiting to be sent, don't overwrite it */
    if (ssl->buffers.outputBuffer.length > 0u) {
        return WANT_WRITE;
    }

    ssl->buffers.outputBuffer.dynamicFlag = WOLFSSL_EXTERNAL_IO_BUFFER;
    ssl->buffers.outputBuffer.buffer     = buf;
    ssl->buffers.outputBuffer.bufferSize = bufSz;

    return WOLFSSL_SUCCESS;
}


/* sets the input buffer from an externally provided buffer */
int SetInputBuffer(WOLFSSL* ssl, byte* buf, int bufSz)
{
    if (ssl == NULL || buf == NULL) {
        return BAD_FUNC_ARG;
    }

    ssl->buffers.inputBuffer.dynamicFlag = WOLFSSL_EXTERNAL_IO_BUFFER;
    ssl->buffers.inputBuffer.buffer     = buf;
    ssl->buffers.inputBuffer.bufferSize = bufSz;

    return WOLFSSL_SUCCESS;
}

/* Grow the output buffer */
static WC_INLINE int GrowOutputBuffer(WOLFSSL* ssl, int size)
{
    byte* tmp;
#if WOLFSSL_GENERAL_ALIGNMENT > 0
#ifdef WOLFSSL_DTLS
    byte  hdrSz = ssl->options.dtls ? DTLS_RECORD_HEADER_SZ :
                                      RECORD_HEADER_SZ;
#else
    byte  hdrSz = RECORD_HEADER_SZ;
#endif
    byte align = WOLFSSL_GENERAL_ALIGNMENT;
#else
    const byte align = WOLFSSL_GENERAL_ALIGNMENT;
#endif
    word32 newSz;

#if WOLFSSL_GENERAL_ALIGNMENT > 0
    /* the encrypted data will be offset from the front of the buffer by
       the header, if the user wants encrypted alignment they need
       to define their alignment requirement */

    while (align < hdrSz)
        align *= 2;
#endif

    if (ssl->buffers.outputBuffer.dynamicFlag == (byte)WOLFSSL_EXTERNAL_IO_BUFFER) {
        WOLFSSL_MSG("External output buffer provided was too small");
        return BAD_FUNC_ARG;
    }

    if (! WC_SAFE_SUM_WORD32(ssl->buffers.outputBuffer.idx,
                             ssl->buffers.outputBuffer.length, newSz))
        return BUFFER_E;
    if (! WC_SAFE_SUM_WORD32(newSz, (word32)size, newSz))
        return BUFFER_E;
    if (! WC_SAFE_SUM_WORD32(newSz, align, newSz))
        return BUFFER_E;
    tmp = (byte*)XMALLOC(newSz, ssl->heap, DYNAMIC_TYPE_OUT_BUFFER);
    newSz -= align;
    WOLFSSL_MSG("growing output buffer");

    if (tmp == NULL)
        return MEMORY_E;

#if WOLFSSL_GENERAL_ALIGNMENT > 0
    if (align)
        tmp += align - hdrSz;
#endif

#ifdef WOLFSSL_STATIC_MEMORY
    /* can be from IO memory pool which does not need copy if same buffer */
    if (ssl->buffers.outputBuffer.length &&
            tmp == ssl->buffers.outputBuffer.buffer) {
        ssl->buffers.outputBuffer.bufferSize = newSz;
        return 0;
    }
#endif

    if (ssl->buffers.outputBuffer.length)
        XMEMCPY(tmp, ssl->buffers.outputBuffer.buffer,
               ssl->buffers.outputBuffer.idx +
               ssl->buffers.outputBuffer.length);

    if (ssl->buffers.outputBuffer.dynamicFlag) {
        XFREE(ssl->buffers.outputBuffer.buffer -
              ssl->buffers.outputBuffer.offset, ssl->heap,
              DYNAMIC_TYPE_OUT_BUFFER);
    }
    ssl->buffers.outputBuffer.dynamicFlag = 1;

#if WOLFSSL_GENERAL_ALIGNMENT > 0
    if (align)
        ssl->buffers.outputBuffer.offset = align - hdrSz;
    else
#endif
        ssl->buffers.outputBuffer.offset = 0;

    ssl->buffers.outputBuffer.buffer = tmp;
    ssl->buffers.outputBuffer.bufferSize = newSz;
    return 0;
}


/* Grow the input buffer, should only be to read cert or big app data */
int GrowInputBuffer(WOLFSSL* ssl, int size, int usedLength)
{
    byte* tmp;
#if defined(WOLFSSL_DTLS) || WOLFSSL_GENERAL_ALIGNMENT > 0
#ifdef WOLFSSL_DTLS
    byte  align = ssl->options.dtls ? WOLFSSL_GENERAL_ALIGNMENT : 0;
#else
    byte  align = 0;
#endif
    byte  hdrSz = DTLS_RECORD_HEADER_SZ;
#else
    const byte align = WOLFSSL_GENERAL_ALIGNMENT;
#endif

#if defined(WOLFSSL_DTLS) || WOLFSSL_GENERAL_ALIGNMENT > 0
    /* the encrypted data will be offset from the front of the buffer by
       the dtls record header, if the user wants encrypted alignment they need
       to define their alignment requirement. in tls we read record header
       to get size of record and put actual data back at front, so don't need */

    if (align) {
       while (align < hdrSz)
           align *= 2;
    }
#endif

    if (usedLength < 0 || size < 0) {
        WOLFSSL_MSG("GrowInputBuffer() called with negative number");
        return BAD_FUNC_ARG;
    }

    if (ssl->buffers.inputBuffer.dynamicFlag == (byte)WOLFSSL_EXTERNAL_IO_BUFFER) {
        WOLFSSL_MSG("External input buffer provided was too small");
        return BAD_FUNC_ARG;
    }

    tmp = (byte*)XMALLOC(size + usedLength + align,
                             ssl->heap, DYNAMIC_TYPE_IN_BUFFER);
    WOLFSSL_MSG("growing input buffer");

    if (tmp == NULL)
        return MEMORY_E;

#if defined(WOLFSSL_DTLS) || WOLFSSL_GENERAL_ALIGNMENT > 0
    if (align)
        tmp += align - hdrSz;
#endif

#ifdef WOLFSSL_STATIC_MEMORY
    /* can be from IO memory pool which does not need copy if same buffer */
    if (usedLength && tmp == ssl->buffers.inputBuffer.buffer) {
        ssl->buffers.inputBuffer.bufferSize = size + usedLength;
        ssl->buffers.inputBuffer.idx    = 0;
        ssl->buffers.inputBuffer.length = usedLength;
        return 0;
    }
#endif

    if (usedLength)
        XMEMCPY(tmp, ssl->buffers.inputBuffer.buffer +
                    ssl->buffers.inputBuffer.idx, usedLength);

    if (ssl->buffers.inputBuffer.dynamicFlag) {
#ifndef WOLFSSL_NO_FORCE_ZERO
        if (IsEncryptionOn(ssl, 1)) {
            ForceZero(ssl->buffers.inputBuffer.buffer,
                ssl->buffers.inputBuffer.length);
        }
#endif
        XFREE(ssl->buffers.inputBuffer.buffer - ssl->buffers.inputBuffer.offset,
              ssl->heap, DYNAMIC_TYPE_IN_BUFFER);
    }

    ssl->buffers.inputBuffer.dynamicFlag = 1;
#if defined(WOLFSSL_DTLS) || WOLFSSL_GENERAL_ALIGNMENT > 0
    if (align)
        ssl->buffers.inputBuffer.offset = align - hdrSz;
    else
#endif
        ssl->buffers.inputBuffer.offset = 0;

    ssl->buffers.inputBuffer.buffer = tmp;
    ssl->buffers.inputBuffer.bufferSize = size + usedLength;
    ssl->buffers.inputBuffer.idx    = 0;
    ssl->buffers.inputBuffer.length = (word32)usedLength;

    return 0;
}


/* Check available size into output buffer, make room if needed.
 * This function needs to be called before anything gets put
 * into the output buffers since it flushes pending data if it
 * predicts that the msg will exceed MTU. */
int CheckAvailableSize(WOLFSSL *ssl, int size)
{
    if (size < 0) {
        WOLFSSL_MSG("CheckAvailableSize() called with negative number");
        return BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_DTLS
    if (ssl->options.dtls) {
#if defined(WOLFSSL_SCTP) || defined(WOLFSSL_DTLS_MTU)
        word32 mtu = (word32)ssl->dtlsMtuSz;
#else
        word32 mtu = MAX_MTU;
#endif
        if ((word32)size + ssl->buffers.outputBuffer.length > mtu) {
            int ret;
            WOLFSSL_MSG("CheckAvailableSize() flushing buffer "
                        "to make room for new message");
            if ((ret = SendBuffered(ssl)) != 0) {
                return ret;
            }
        }
        if ((word32)size > mtu
#ifdef WOLFSSL_DTLS13
            /* DTLS1.3 uses the output buffer to store the full message and deal
               with fragmentation later in dtls13HandshakeSend() */
            && !IsAtLeastTLSv1_3(ssl->version)
#endif /* WOLFSSL_DTLS13 */
            ) {
            WOLFSSL_MSG("CheckAvailableSize() called with size greater than MTU.");
            return DTLS_SIZE_ERROR;
        }
    }
#endif

    if ((ssl->buffers.outputBuffer.bufferSize -
             ssl->buffers.outputBuffer.length -
             ssl->buffers.outputBuffer.idx) < (word32)size) {
        if (GrowOutputBuffer(ssl, size) < 0)
            return MEMORY_E;
    }

    return 0;
}

#ifndef WOLFSSL_DISABLE_EARLY_SANITY_CHECKS

int MsgCheckEncryption(WOLFSSL* ssl, byte type, byte encrypted)
{
#ifdef WOLFSSL_QUIC
    /* QUIC protects messages outside of the TLS scope */
    if (WOLFSSL_IS_QUIC(ssl) && IsAtLeastTLSv1_3(ssl->version))
        return 0;
#endif
    /* Verify which messages always have to be encrypted */
    if (IsAtLeastTLSv1_3(ssl->version)) {
        switch ((enum HandShakeType)type) {
            case client_hello:
            case server_hello:
            case hello_verify_request:
            case hello_retry_request:
            case change_cipher_hs:
                if (encrypted) {
                    WOLFSSL_MSG("Message can not be encrypted");
                    WOLFSSL_ERROR_VERBOSE(OUT_OF_ORDER_E);
                    return OUT_OF_ORDER_E;
                }
                break;
            case hello_request:
            case session_ticket:
            case end_of_early_data:
            case encrypted_extensions:
            case certificate:
            case server_key_exchange:
            case certificate_request:
            case server_hello_done:
            case certificate_verify:
            case client_key_exchange:
            case finished:
            case certificate_status:
            case key_update:
                if (!encrypted) {
                    WOLFSSL_MSG("Message always has to be encrypted");
                    WOLFSSL_ERROR_VERBOSE(OUT_OF_ORDER_E);
                    return OUT_OF_ORDER_E;
                }
                break;
            case message_hash:
            case no_shake:
            default:
                WOLFSSL_MSG("Unknown message type");
                WOLFSSL_ERROR_VERBOSE(SANITY_MSG_E);
                return SANITY_MSG_E;
        }
    }
    else {
        switch ((enum HandShakeType)type) {
            case client_hello:
                break;
            case server_hello:
            case hello_verify_request:
            case hello_retry_request:
            case certificate:
            case server_key_exchange:
            case certificate_request:
            case server_hello_done:
            case certificate_verify:
            case client_key_exchange:
            case certificate_status:
            case session_ticket:
            case change_cipher_hs:
		if (encrypted) {
                    WOLFSSL_MSG("Message can not be encrypted in regular "
                                "handshake");
                    WOLFSSL_ERROR_VERBOSE(OUT_OF_ORDER_E);
                    return OUT_OF_ORDER_E;
                }
                break;
            case hello_request:
            case finished:
                if (!encrypted) {
                    WOLFSSL_MSG("Message always has to be encrypted");
                    WOLFSSL_ERROR_VERBOSE(OUT_OF_ORDER_E);
                    return OUT_OF_ORDER_E;
                }
                break;
            case key_update:
            case encrypted_extensions:
            case end_of_early_data:
            case message_hash:
            case no_shake:
            default:
                WOLFSSL_MSG("Unknown message type");
                WOLFSSL_ERROR_VERBOSE(SANITY_MSG_E);
                return SANITY_MSG_E;
        }
    }
    return 0;
}

static WC_INLINE int isLastMsg(const WOLFSSL* ssl, word32 msgSz)
{
    word32 extra = 0;
    if (IsEncryptionOn(ssl, 0)) {
        extra = ssl->keys->padSz;
#if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
        if (ssl->options.startedETMRead)
            extra += MacSize(ssl);
#endif
    }
    return (ssl->buffers.inputBuffer.idx - ssl->curStartIdx) + msgSz + extra
            == ssl->curSize;
}

/* Check if the msg is the last msg in a record. This is also an easy way
 * to check that a record doesn't span different key boundaries. */
static int MsgCheckBoundary(const WOLFSSL* ssl, byte type,
        byte version_negotiated, word32 msgSz)
{
    if (version_negotiated) {
        if (IsAtLeastTLSv1_3(ssl->version)) {
            switch ((enum HandShakeType)type) {
                case hello_request:
                case client_hello:
                case server_hello:
                case hello_verify_request:
                case hello_retry_request:
                case finished:
                case end_of_early_data:
                    if (!isLastMsg(ssl, msgSz)) {
                        WOLFSSL_MSG("Message type is not last in record");
                        WOLFSSL_ERROR_VERBOSE(OUT_OF_ORDER_E);
                        return OUT_OF_ORDER_E;
                    }
                    break;
                case session_ticket:
                case encrypted_extensions:
                case certificate:
                case server_key_exchange:
                case certificate_request:
                case certificate_verify:
                case client_key_exchange:
                case certificate_status:
                case key_update:
                case change_cipher_hs:
                    break;
                case server_hello_done:
                case message_hash:
                case no_shake:
                default:
                    WOLFSSL_MSG("Unknown message type");
                    WOLFSSL_ERROR_VERBOSE(SANITY_MSG_E);
                    return SANITY_MSG_E;
            }
        }
        else {
            switch ((enum HandShakeType)type) {
                case hello_request:
                case client_hello:
                case hello_verify_request:
                    if (!isLastMsg(ssl, msgSz)) {
                        WOLFSSL_MSG("Message type is not last in record");
                        WOLFSSL_ERROR_VERBOSE(OUT_OF_ORDER_E);
                        return OUT_OF_ORDER_E;
                    }
                    break;
                case server_hello:
                case session_ticket:
                case end_of_early_data:
                case certificate:
                case server_key_exchange:
                case certificate_request:
                case server_hello_done:
                case certificate_verify:
                case client_key_exchange:
                case finished:
                case certificate_status:
                case change_cipher_hs:
                    break;
                case hello_retry_request:
                case encrypted_extensions:
                case key_update:
                case message_hash:
                case no_shake:
                default:
                    WOLFSSL_MSG("Unknown message type");
                    WOLFSSL_ERROR_VERBOSE(SANITY_MSG_E);
                    return SANITY_MSG_E;
            }
        }
    }
    else {
        switch ((enum HandShakeType)type) {
            case hello_request:
            case client_hello:
            case hello_verify_request:
                if (!isLastMsg(ssl, msgSz)) {
                    WOLFSSL_MSG("Message type is not last in record");
                    WOLFSSL_ERROR_VERBOSE(OUT_OF_ORDER_E);
                    return OUT_OF_ORDER_E;
                }
                break;
            case server_hello:
            case session_ticket:
            case end_of_early_data:
            case hello_retry_request:
            case encrypted_extensions:
            case certificate:
            case server_key_exchange:
            case certificate_request:
            case server_hello_done:
            case certificate_verify:
            case client_key_exchange:
            case finished:
            case certificate_status:
            case key_update:
            case change_cipher_hs:
                break;
            case message_hash:
            case no_shake:
            default:
                WOLFSSL_MSG("Unknown message type");
                WOLFSSL_ERROR_VERBOSE(SANITY_MSG_E);
                return SANITY_MSG_E;
        }
    }
    return 0;
}

#endif /* WOLFSSL_DISABLE_EARLY_SANITY_CHECKS */

#ifndef WOLFSSL_LEANPSK
/**
 * This check is performed as soon as the handshake message type becomes known.
 * These checks can not be delayed and need to be performed when the msg is
 * received and not when it is processed (fragmentation may cause messages to
 * be processed at a later time). This function CAN NOT be called on stored
 * messages as it relies on the state of the WOLFSSL object right after
 * receiving the message.
 *
 * @param ssl   The current connection
 * @param type  The enum HandShakeType of the current message
 * @param msgSz Size of the current message
 * @return
 */
int EarlySanityCheckMsgReceived(WOLFSSL* ssl, byte type, word32 msgSz)
{
    int ret = 0;
#ifndef WOLFSSL_DISABLE_EARLY_SANITY_CHECKS
    /* Version has only been negotiated after we either send or process a
     * ServerHello message */
    byte version_negotiated = ssl->options.serverState >= SERVER_HELLO_COMPLETE;

    WOLFSSL_ENTER("EarlySanityCheckMsgReceived");

    if (version_negotiated)
        ret = MsgCheckEncryption(ssl, type, ssl->keys->decryptedCur == 1);

    if (ret == 0)
        ret = MsgCheckBoundary(ssl, type, version_negotiated, msgSz);

    if (ret != 0
#ifdef WOLFSSL_DTLS
            && ssl->options.dtls && ssl->options.dtlsStateful
#endif
            )
        SendAlert(ssl, alert_fatal, unexpected_message);

    WOLFSSL_LEAVE("EarlySanityCheckMsgReceived", ret);
#else
    (void)ssl;
    (void)type;
    (void)msgSz;
#endif

    return ret;
}
#endif

/* do all verify and sanity checks on record header */
static int GetRecordHeader(WOLFSSL* ssl, word32* inOutIdx,
                           RecordLayerHeader* rh, word16 *size)
{
    byte tls12minor = 0;

    (void)tls12minor;
    {
        /* Set explicitly rather than make assumptions on struct layout */
        rh->type      = ssl->buffers.inputBuffer.buffer[*inOutIdx];
        rh->pvMajor   = ssl->buffers.inputBuffer.buffer[*inOutIdx + 1];
        rh->pvMinor   = ssl->buffers.inputBuffer.buffer[*inOutIdx + 2];
        rh->length[0] = ssl->buffers.inputBuffer.buffer[*inOutIdx + 3];
        rh->length[1] = ssl->buffers.inputBuffer.buffer[*inOutIdx + 4];

        *inOutIdx += RECORD_HEADER_SZ;
        ato16(rh->length, size);
    }
    /* catch version mismatch */
    if (rh->pvMajor != ssl->version.major || rh->pvMinor != ssl->version.minor)
    {
#ifndef WOLFSSL_NO_DOWNGRADE
        if (ssl->options.side == WOLFSSL_SERVER_END &&
            ssl->options.acceptState < ACCEPT_FIRST_REPLY_DONE)

            WOLFSSL_MSG("Client attempting to connect with different version");
        else if (ssl->options.side == WOLFSSL_CLIENT_END &&
                                 ssl->options.downgrade &&
                                 ssl->options.connectState < FIRST_REPLY_DONE)
            WOLFSSL_MSG("Server attempting to accept with different version");
        else
#endif
        {
            WOLFSSL_MSG("SSL version error");
            WOLFSSL_ERROR_VERBOSE(VERSION_ERROR);
            return VERSION_ERROR;              /* only use requested version */
        }
    }

    /* record layer length check */
#ifdef HAVE_MAX_FRAGMENT
    if (*size > (ssl->max_fragment + MAX_COMP_EXTRA + MAX_MSG_EXTRA)) {
        WOLFSSL_ERROR_VERBOSE(LENGTH_ERROR);
        return LENGTH_ERROR;
    }
#else
    if (*size > (word16)(MAX_RECORD_SIZE + MAX_COMP_EXTRA + MAX_MSG_EXTRA)) {
        WOLFSSL_ERROR_VERBOSE(LENGTH_ERROR);
        return LENGTH_ERROR;
    }
#endif

    if (*size == 0u && rh->type != (byte)application_data) {
        WOLFSSL_MSG("0 length, non-app data record.");
        WOLFSSL_ERROR_VERBOSE(LENGTH_ERROR);
        return LENGTH_ERROR;
    }

    /* verify record type here as well */
    switch (rh->type) {
        case handshake:
        case change_cipher_spec:
        case application_data:
        case alert:
            break;
        case no_type:
        default:
            WOLFSSL_MSG("Unknown Record Type");
            WOLFSSL_ERROR_VERBOSE(UNKNOWN_RECORD_TYPE);
            return UNKNOWN_RECORD_TYPE;
    }

    /* haven't decrypted this record yet */
    ssl->keys->decryptedCur = 0;

    return 0;
}

#ifndef WOLFSSL_NO_TLS12
static int GetHandShakeHeader(WOLFSSL* ssl, const byte* input, word32* inOutIdx,
                              byte *type, word32 *size, word32 totalSz)
{
    const byte *ptr = input + *inOutIdx;
    (void)ssl;

    *inOutIdx += HANDSHAKE_HEADER_SZ;
    if (*inOutIdx > totalSz)
        return BUFFER_E;

    *type = ptr[0];
    c24to32(&ptr[1], size);

    return 0;
}
#endif

#ifndef WOLFSSL_NO_TLS12

static int DoHelloRequest(WOLFSSL* ssl, const byte* input, word32* inOutIdx,
                                                    word32 size, word32 totalSz)
{
    (void)input;

    WOLFSSL_START(WC_FUNC_HELLO_REQUEST_DO);
    WOLFSSL_ENTER("DoHelloRequest");

    if (size) /* must be 0 */
        return BUFFER_ERROR;

    if (IsEncryptionOn(ssl, 0)) {
        /* If size == totalSz then we are in DtlsMsgDrain so no need to worry
         * about padding */
    #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
        if (ssl->options.startedETMRead) {
            word32 digestSz = MacSize(ssl);
            if (size != totalSz &&
                    *inOutIdx + ssl->keys->padSz + digestSz > totalSz)
                return BUFFER_E;
            *inOutIdx += ssl->keys->padSz + digestSz;
        }
        else
    #endif
        {
            /* access beyond input + size should be checked against totalSz */
            if (size != totalSz &&
                    *inOutIdx + ssl->keys->padSz > totalSz)
                return BUFFER_E;

            *inOutIdx += ssl->keys->padSz;
        }
    }

    if (ssl->options.side == (byte)WOLFSSL_SERVER_END) {
        SendAlert(ssl, alert_fatal, unexpected_message); /* try */
        WOLFSSL_ERROR_VERBOSE(FATAL_ERROR);
        return FATAL_ERROR;
    }
#ifdef HAVE_SECURE_RENEGOTIATION
    else if (ssl->secure_renegotiation && ssl->secure_renegotiation->enabled) {
        ssl->secure_renegotiation->startScr = 1;
        WOLFSSL_LEAVE("DoHelloRequest", 0);
        WOLFSSL_END(WC_FUNC_HELLO_REQUEST_DO);
        return 0;
    }
#endif
    else {
        return SendAlert(ssl, alert_warning, no_renegotiation);
    }
}


int DoFinished(WOLFSSL* ssl, const byte* input, word32* inOutIdx, word32 size,
                                                      word32 totalSz, int sniff)
{
    word32 finishedSz = (ssl->options.tls ? TLS_FINISHED_SZ : FINISHED_SZ);

    WOLFSSL_START(WC_FUNC_FINISHED_DO);
    WOLFSSL_ENTER("DoFinished");

    if (finishedSz != size)
        return BUFFER_ERROR;

    /* check against totalSz
     * If size == totalSz then we are in DtlsMsgDrain so no need to worry about
     * padding */
    if (size != totalSz) {
    #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
        if (ssl->options.startedETMRead) {
            if (*inOutIdx + size + ssl->keys->padSz + MacSize(ssl) > totalSz)
                return BUFFER_E;
        }
        else
    #endif
        {
            if (*inOutIdx + size + ssl->keys->padSz > totalSz)
                return BUFFER_E;
        }
    }

    if (sniff == NO_SNIFF) {
        if (XMEMCMP(input + *inOutIdx, &ssl->hsHashes->verifyHashes,size) != 0){
            WOLFSSL_MSG("Verify finished error on hashes");
            WOLFSSL_ERROR_VERBOSE(VERIFY_FINISHED_ERROR);
            return VERIFY_FINISHED_ERROR;
        }
    }

#ifdef HAVE_SECURE_RENEGOTIATION
    if (ssl->secure_renegotiation) {
        /* save peer's state */
        if (ssl->options.side == WOLFSSL_CLIENT_END)
            XMEMCPY(ssl->secure_renegotiation->server_verify_data,
                    input + *inOutIdx, TLS_FINISHED_SZ);
        else
            XMEMCPY(ssl->secure_renegotiation->client_verify_data,
                    input + *inOutIdx, TLS_FINISHED_SZ);
        ssl->secure_renegotiation->verifySet = 1;
    }
#endif
#ifdef WOLFSSL_HAVE_TLS_UNIQUE
    if (ssl->options.side == WOLFSSL_CLIENT_END) {
        XMEMCPY(ssl->serverFinished,
                input + *inOutIdx, TLS_FINISHED_SZ);
        ssl->serverFinished_len = TLS_FINISHED_SZ;
    }
    else {
        XMEMCPY(ssl->clientFinished,
                input + *inOutIdx, TLS_FINISHED_SZ);
        ssl->clientFinished_len = TLS_FINISHED_SZ;
    }
#endif

    /* force input exhaustion at ProcessReply consuming padSz */
    *inOutIdx += size + ssl->keys->padSz;
#if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
    if (ssl->options.startedETMRead)
        *inOutIdx += MacSize(ssl);
#endif

    if (ssl->options.side == (byte)WOLFSSL_CLIENT_END) {
        ssl->options.serverState = SERVER_FINISHED_COMPLETE;
        if (!ssl->options.resuming) {
            ssl->options.handShakeState = HANDSHAKE_DONE;
            ssl->options.handShakeDone  = 1;
        }
    }
    else {
        ssl->options.clientState = CLIENT_FINISHED_COMPLETE;
        if (ssl->options.resuming) {
            ssl->options.handShakeState = HANDSHAKE_DONE;
            ssl->options.handShakeDone  = 1;
        }
    }
    
    WOLFSSL_LEAVE("DoFinished", 0);
    WOLFSSL_END(WC_FUNC_FINISHED_DO);

    return 0;
}

#if 0
/* Make sure no duplicates, no fast forward, or other problems; 0 on success */
static int SanityCheckMsgReceived(WOLFSSL* ssl, byte type)
{
    /* verify not a duplicate, mark received, check state */
    switch (type) {

#ifndef NO_WOLFSSL_CLIENT
        case hello_request:
            if (ssl->msgsReceived.got_hello_request) {
                WOLFSSL_MSG("Duplicate HelloRequest received");
                WOLFSSL_ERROR_VERBOSE(DUPLICATE_MSG_E);
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_hello_request = 1;

            break;
#endif

#ifndef NO_WOLFSSL_CLIENT
        case server_hello:
            if (ssl->msgsReceived.got_server_hello) {
                WOLFSSL_MSG("Duplicate ServerHello received");
                WOLFSSL_ERROR_VERBOSE(DUPLICATE_MSG_E);
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_server_hello = 1;

            break;
#endif

#ifndef NO_WOLFSSL_CLIENT
        case hello_verify_request:
            if (ssl->msgsReceived.got_hello_verify_request) {
                WOLFSSL_MSG("Duplicate HelloVerifyRequest received");
                WOLFSSL_ERROR_VERBOSE(DUPLICATE_MSG_E);
                return DUPLICATE_MSG_E;
            }
            if (ssl->msgsReceived.got_hello_retry_request) {
                WOLFSSL_MSG("Received HelloVerifyRequest after a "
                            "HelloRetryRequest");
                WOLFSSL_ERROR_VERBOSE(VERSION_ERROR);
                return VERSION_ERROR;
            }
            ssl->msgsReceived.got_hello_verify_request = 1;

            break;
#endif

#ifndef NO_WOLFSSL_CLIENT
        case session_ticket:
            if (ssl->msgsReceived.got_session_ticket) {
                WOLFSSL_MSG("Duplicate SessionTicket received");
                WOLFSSL_ERROR_VERBOSE(DUPLICATE_MSG_E);
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_session_ticket = 1;

            break;
#endif

        case certificate:
            if (ssl->msgsReceived.got_certificate) {
                WOLFSSL_MSG("Duplicate Certificate received");
                WOLFSSL_ERROR_VERBOSE(DUPLICATE_MSG_E);
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_certificate = 1;

#ifndef NO_WOLFSSL_CLIENT
            if (ssl->options.side == WOLFSSL_CLIENT_END) {
                if ( ssl->msgsReceived.got_server_hello == 0) {
                    WOLFSSL_MSG("No ServerHello before Cert");
                    WOLFSSL_ERROR_VERBOSE(OUT_OF_ORDER_E);
                    return OUT_OF_ORDER_E;
                }
            }
#endif
            break;

#ifndef NO_WOLFSSL_CLIENT
        case certificate_status:
            if (ssl->msgsReceived.got_certificate_status) {
                WOLFSSL_MSG("Duplicate CertificateStatus received");
                WOLFSSL_ERROR_VERBOSE(DUPLICATE_MSG_E);
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_certificate_status = 1;

            if (ssl->msgsReceived.got_certificate == 0) {
                WOLFSSL_MSG("No Certificate before CertificateStatus");
                WOLFSSL_ERROR_VERBOSE(OUT_OF_ORDER_E);
                return OUT_OF_ORDER_E;
            }
            if (ssl->msgsReceived.got_server_key_exchange != 0) {
                WOLFSSL_MSG("CertificateStatus after ServerKeyExchange");
                WOLFSSL_ERROR_VERBOSE(OUT_OF_ORDER_E);
                return OUT_OF_ORDER_E;
            }

            break;
#endif

#ifndef NO_WOLFSSL_CLIENT
        case server_key_exchange:
            if (ssl->msgsReceived.got_server_key_exchange) {
                WOLFSSL_MSG("Duplicate ServerKeyExchange received");
                WOLFSSL_ERROR_VERBOSE(DUPLICATE_MSG_E);
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_server_key_exchange = 1;

            if (ssl->msgsReceived.got_server_hello == 0) {
                WOLFSSL_MSG("No ServerHello before ServerKeyExchange");
                WOLFSSL_ERROR_VERBOSE(OUT_OF_ORDER_E);
                return OUT_OF_ORDER_E;
            }
            break;
#endif

#ifndef NO_WOLFSSL_CLIENT
        case certificate_request:
        #ifndef NO_WOLFSSL_SERVER
            if (ssl->options.side == WOLFSSL_SERVER_END) {
                WOLFSSL_MSG("CertificateRequest received by server");
                WOLFSSL_ERROR_VERBOSE(SIDE_ERROR);
                return SIDE_ERROR;
            }
        #endif
            if (ssl->msgsReceived.got_certificate_request) {
                WOLFSSL_MSG("Duplicate CertificateRequest received");
                WOLFSSL_ERROR_VERBOSE(DUPLICATE_MSG_E);
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_certificate_request = 1;

            break;
#endif

#ifndef NO_WOLFSSL_CLIENT
        case server_hello_done:
        #ifndef NO_WOLFSSL_SERVER
            if (ssl->options.side == WOLFSSL_SERVER_END) {
                WOLFSSL_MSG("ServerHelloDone received by server");
                WOLFSSL_ERROR_VERBOSE(SIDE_ERROR);
                return SIDE_ERROR;
            }
        #endif
            if (ssl->msgsReceived.got_server_hello_done) {
                WOLFSSL_MSG("Duplicate ServerHelloDone received");
                WOLFSSL_ERROR_VERBOSE(DUPLICATE_MSG_E);
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_server_hello_done = 1;

            if (ssl->msgsReceived.got_certificate == 0) {
                if (ssl->specs.kea == psk_kea ||
                    ssl->specs.kea == dhe_psk_kea ||
                    ssl->specs.kea == ecdhe_psk_kea ||
                    ssl->options.usingAnon_cipher) {
                    WOLFSSL_MSG("No Cert required");
                }
                else {
                    WOLFSSL_MSG("No Certificate before ServerHelloDone");
                    WOLFSSL_ERROR_VERBOSE(OUT_OF_ORDER_E);
                    return OUT_OF_ORDER_E;
                }
            }
            if (ssl->msgsReceived.got_server_key_exchange == 0) {
                int pskNoServerHint = 0;  /* not required in this case */

                #ifndef NO_PSK
                    if (ssl->specs.kea == psk_kea &&
                        ssl->arrays != NULL &&
                        ssl->arrays->server_hint[0] == 0)
                        pskNoServerHint = 1;
                #endif
                if (ssl->specs.static_ecdh == 1 ||
                    ssl->specs.kea == rsa_kea ||
                    pskNoServerHint) {
                    WOLFSSL_MSG("No KeyExchange required");
                }
                else {
                    WOLFSSL_MSG("No ServerKeyExchange before ServerDone");
                    WOLFSSL_ERROR_VERBOSE(OUT_OF_ORDER_E);
                    return OUT_OF_ORDER_E;
                }
            }
            break;
#endif

        case finished:
            if (ssl->msgsReceived.got_finished) {
                WOLFSSL_MSG("Duplicate Finished received");
                WOLFSSL_ERROR_VERBOSE(DUPLICATE_MSG_E);
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_finished = 1;

            if (ssl->msgsReceived.got_change_cipher == 0) {
                WOLFSSL_MSG("Finished received before ChangeCipher");
                WOLFSSL_ERROR_VERBOSE(NO_CHANGE_CIPHER_E);
                return NO_CHANGE_CIPHER_E;
            }
            break;

        case change_cipher_hs:
            if (ssl->msgsReceived.got_change_cipher) {
                WOLFSSL_MSG("Duplicate ChangeCipher received");
                WOLFSSL_ERROR_VERBOSE(DUPLICATE_MSG_E);
                return DUPLICATE_MSG_E;
            }
            /* DTLS is going to ignore the CCS message if the client key
             * exchange message wasn't received yet. */
            if (!ssl->options.dtls)
                ssl->msgsReceived.got_change_cipher = 1;

#ifndef NO_WOLFSSL_CLIENT
            if (ssl->options.side == WOLFSSL_CLIENT_END) {
                if (!ssl->options.resuming) {
                   if (ssl->msgsReceived.got_server_hello_done == 0) {
                        WOLFSSL_MSG("No ServerHelloDone before ChangeCipher");
                        WOLFSSL_ERROR_VERBOSE(OUT_OF_ORDER_E);
                        return OUT_OF_ORDER_E;
                   }
                }
                else {
                    if (ssl->msgsReceived.got_server_hello == 0) {
                        WOLFSSL_MSG("No ServerHello before ChangeCipher on "
                                    "Resume");
                        WOLFSSL_ERROR_VERBOSE(OUT_OF_ORDER_E);
                        return OUT_OF_ORDER_E;
                    }
                }
                #ifdef HAVE_SESSION_TICKET
                    if (ssl->expect_session_ticket) {
                        WOLFSSL_MSG("Expected session ticket missing");
                        #ifdef WOLFSSL_DTLS
                            if (ssl->options.dtls) {
                                WOLFSSL_ERROR_VERBOSE(OUT_OF_ORDER_E);
                                return OUT_OF_ORDER_E;
                            }
                        #endif
                        WOLFSSL_ERROR_VERBOSE(SESSION_TICKET_EXPECT_E);
                        return SESSION_TICKET_EXPECT_E;
                    }
                #endif
            }
#endif
            if (ssl->options.dtls)
                ssl->msgsReceived.got_change_cipher = 1;
            break;

        default:
            WOLFSSL_MSG("Unknown message type");
            WOLFSSL_ERROR_VERBOSE(SANITY_MSG_E);
            return SANITY_MSG_E;
    }

    return 0;
}
#endif

int DoHandShakeMsgType(WOLFSSL* ssl, byte* input, word32* inOutIdx,
                          byte type, word32 size, word32 totalSz)
{
    int ret = 0;
    word32 expectedIdx;

    WOLFSSL_ENTER("DoHandShakeMsgType");

#ifdef WOLFSSL_TLS13
    if (type == hello_retry_request) {
        return DoTls13HandShakeMsgType(ssl, input, inOutIdx, type, size,
                                       totalSz);
    }
#endif

    /* make sure can read the message */
    if (*inOutIdx + size > totalSz) {
        WOLFSSL_MSG("Incomplete Data");
        WOLFSSL_ERROR_VERBOSE(INCOMPLETE_DATA);
        return INCOMPLETE_DATA;
    }

    expectedIdx = *inOutIdx + size +
                  (ssl->keys->encryptionOn ? ssl->keys->padSz : 0);
#if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
    if (ssl->options.startedETMRead && ssl->keys->encryptionOn)
        expectedIdx += MacSize(ssl);
#endif

#if 0
    /* sanity check msg received */
    if ( (ret = SanityCheckMsgReceived(ssl, type)) != 0) {
        WOLFSSL_MSG("Sanity Check on handshake message type received failed");
        return ret;
    }
#endif

    if (ssl->options.handShakeState == (byte)HANDSHAKE_DONE && type != hello_request){
        WOLFSSL_MSG("HandShake message after handshake complete");
        SendAlert(ssl, alert_fatal, unexpected_message);
        WOLFSSL_ERROR_VERBOSE(OUT_OF_ORDER_E);
        return OUT_OF_ORDER_E;
    }

    if (ssl->options.side == (byte)WOLFSSL_CLIENT_END &&
               ssl->options.serverState == (byte)NULL_STATE && type != server_hello &&
               type != hello_request) {
        WOLFSSL_MSG("First server message not server hello or "
                    "hello request");
        SendAlert(ssl, alert_fatal, unexpected_message);
        WOLFSSL_ERROR_VERBOSE(OUT_OF_ORDER_E);
        return OUT_OF_ORDER_E;
    }

    if (ssl->options.side == (byte)WOLFSSL_CLIENT_END &&
            type == server_hello_done &&
            ssl->options.serverState < (byte)SERVER_HELLO_COMPLETE) {
        WOLFSSL_MSG("Server hello done received before server hello in DTLS");
        SendAlert(ssl, alert_fatal, unexpected_message);
        WOLFSSL_ERROR_VERBOSE(OUT_OF_ORDER_E);
        return OUT_OF_ORDER_E;
    }

    if (ssl->options.side == (byte)WOLFSSL_SERVER_END &&
               ssl->options.clientState == (byte)NULL_STATE && type != client_hello) {
        WOLFSSL_MSG("First client message not client hello");
        SendAlert(ssl, alert_fatal, unexpected_message);
        WOLFSSL_ERROR_VERBOSE(OUT_OF_ORDER_E);
        return OUT_OF_ORDER_E;
    }

    /* above checks handshake state */
    /* hello_request not hashed */
    if (type != hello_request) {
        ret = wc_Sha256Update(&ssl->hsHashes->hashSha256,
            input + *inOutIdx - HANDSHAKE_HEADER_SZ,
            size + HANDSHAKE_HEADER_SZ);
        if (ret != 0) {
            WOLFSSL_MSG("Incomplete handshake hashes");
            return ret;
        }
    }

#ifndef WOLFSSL_NO_SESSION_RESUMPTION
    if (ssl->options.side == WOLFSSL_CLIENT_END) {
        switch (type) {
        case certificate:
        case server_key_exchange:
        case certificate_request:
        case server_hello_done:
            if (ssl->options.resuming) {
                /* https://www.rfc-editor.org/rfc/rfc5077.html#section-3.4
                 *   Alternatively, the client MAY include an empty Session ID
                 *   in the ClientHello.  In this case, the client ignores the
                 *   Session ID sent in the ServerHello and determines if the
                 *   server is resuming a session by the subsequent handshake
                 *   messages.
                 */
#ifndef WOLFSSL_WPAS
                if (ssl->session->sessionIDSz != 0) {
                    /* Fatal error. Only try to send an alert. RFC 5246 does not
                     * allow for reverting back to a full handshake after the
                     * server has indicated the intention to do a resumption. */
                    (void)SendAlert(ssl, alert_fatal, unexpected_message);
                    WOLFSSL_ERROR_VERBOSE(OUT_OF_ORDER_E);
                    return OUT_OF_ORDER_E;
                }
#endif
                /* This can occur when ssl->sessionSecretCb is set. EAP-FAST
                 * (RFC 4851) allows for detecting server session resumption
                 * based on the msg received after the ServerHello. */
                WOLFSSL_MSG("Not resuming as thought");
                ssl->options.resuming = 0;
                /* No longer resuming, reset peer authentication state. */
                ssl->options.peerAuthGood = 0;
            }
        }
    }
#endif

    switch (type) {

    case hello_request:
        WOLFSSL_MSG("processing hello request");
        ret = DoHelloRequest(ssl, input, inOutIdx, size, totalSz);
        break;

#ifndef NO_WOLFSSL_CLIENT
    case server_hello:
        WOLFSSL_MSG("processing server hello");
        ret = DoServerHello(ssl, input, inOutIdx, size);
    #if !defined(WOLFSSL_NO_CLIENT_AUTH) && \
               ((defined(WOLFSSL_SM2) && defined(WOLFSSL_SM3)) || \
                (defined(HAVE_ED25519) && !defined(NO_ED25519_CLIENT_AUTH)) || \
                (defined(HAVE_ED448) && !defined(NO_ED448_CLIENT_AUTH)))
        if (ssl->options.resuming || !IsAtLeastTLSv1_2(ssl) ||
                                               IsAtLeastTLSv1_3(ssl->version)) {

        #if defined(WOLFSSL_ASYNC_CRYPT) || defined(WOLFSSL_NONBLOCK_OCSP)
            if (ret != WC_PENDING_E && ret != OCSP_WANT_READ)
        #endif
            {
                ssl->options.cacheMessages = 0;
                if ((ssl->hsHashes != NULL) && (ssl->hsHashes->messages != NULL)) {
                    ForceZero(ssl->hsHashes->messages, ssl->hsHashes->length);
                    XFREE(ssl->hsHashes->messages, ssl->heap,
                        DYNAMIC_TYPE_HASHES);
                    ssl->hsHashes->messages = NULL;
                }
            }
        }
    #endif
        break;

    case server_key_exchange:
        WOLFSSL_MSG("processing server key exchange");
        ret = DoServerKeyExchange(ssl, input, inOutIdx, size);
        break;

#endif
      
    case server_hello_done:
        WOLFSSL_MSG("processing server hello done");
        ssl->options.serverState = SERVER_HELLODONE_COMPLETE;
        if (IsEncryptionOn(ssl, 0)) {
            *inOutIdx += ssl->keys->padSz;
        #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
            if (ssl->options.startedETMRead)
                *inOutIdx += MacSize(ssl);
        #endif
        }
        break;

    case finished:
        WOLFSSL_MSG("processing finished");
        ret = DoFinished(ssl, input, inOutIdx, size, totalSz, NO_SNIFF);
        break;

    default:
        WOLFSSL_MSG("Unknown handshake message type");
        ret = UNKNOWN_HANDSHAKE_TYPE;
        break;
    }
    if (ret == 0 && expectedIdx != *inOutIdx) {
        WOLFSSL_MSG("Extra data in handshake message");
        #ifdef WOLFSSL_DTLS
        if (!ssl->options.dtls)
        #endif
            SendAlert(ssl, alert_fatal, decode_error);
        ret = DECODE_E;
        WOLFSSL_ERROR_VERBOSE(ret);
    }

    WOLFSSL_LEAVE("DoHandShakeMsgType()", ret);
    return ret;
}


static int DoHandShakeMsg(WOLFSSL* ssl, byte* input, word32* inOutIdx,
                          word32 totalSz)
{
    int    ret = 0;
    word32 inputLength;

    WOLFSSL_ENTER("DoHandShakeMsg");

    if (ssl->arrays == NULL) {
        byte   type;
        word32 size;

        if (GetHandShakeHeader(ssl,input,inOutIdx,&type, &size, totalSz) != 0) {
            WOLFSSL_ERROR_VERBOSE(PARSE_ERROR);
            return PARSE_ERROR;
        }

#ifndef WOLFSSL_LEANPSK
        ret = EarlySanityCheckMsgReceived(ssl, type, size);
        if (ret != 0) {
            WOLFSSL_ERROR(ret);
            return ret;
        }
#endif

        if (size > (word32)MAX_HANDSHAKE_SZ) {
            WOLFSSL_MSG("Handshake message too large");
            WOLFSSL_ERROR_VERBOSE(HANDSHAKE_SIZE_ERROR);
            return HANDSHAKE_SIZE_ERROR;
        }

        return DoHandShakeMsgType(ssl, input, inOutIdx, type, size, totalSz);
    }

    inputLength = ssl->buffers.inputBuffer.length - *inOutIdx;

    /* If there is a pending fragmented handshake message,
     * pending message size will be non-zero. */
    if (ssl->arrays->pendingMsgSz == 0u) {
        byte   type;
        word32 size;

        if (GetHandShakeHeader(ssl, input, inOutIdx, &type, &size,
                               totalSz) != 0) {
            WOLFSSL_ERROR_VERBOSE(PARSE_ERROR);
            return PARSE_ERROR;
        }

#ifndef WOLFSSL_LEANPSK
        ret = EarlySanityCheckMsgReceived(ssl, type,
                min(inputLength - HANDSHAKE_HEADER_SZ, size));
        if (ret != 0) {
            WOLFSSL_ERROR(ret);
            return ret;
        }
#endif

        /* Cap the maximum size of a handshake message to something reasonable.
         * By default is the maximum size of a certificate message assuming
         * nine 2048-bit RSA certificates in the chain. */
        if (size > (word32)MAX_HANDSHAKE_SZ) {
            WOLFSSL_MSG("Handshake message too large");
            WOLFSSL_ERROR_VERBOSE(HANDSHAKE_SIZE_ERROR);
            return HANDSHAKE_SIZE_ERROR;
        }

        /* size is the size of the certificate message payload */
        if (inputLength - HANDSHAKE_HEADER_SZ < size) {
            ssl->arrays->pendingMsgType = type;
            ssl->arrays->pendingMsgSz = size + HANDSHAKE_HEADER_SZ;
            ssl->arrays->pendingMsg = (byte*)XMALLOC(size + HANDSHAKE_HEADER_SZ,
                                                     ssl->heap,
                                                     DYNAMIC_TYPE_ARRAYS);
            if (ssl->arrays->pendingMsg == NULL)
                return MEMORY_E;
            XMEMCPY(ssl->arrays->pendingMsg,
                    input + *inOutIdx - HANDSHAKE_HEADER_SZ,
                    inputLength);
            ssl->arrays->pendingMsgOffset = inputLength;
            *inOutIdx += inputLength - HANDSHAKE_HEADER_SZ;
            return 0;
        }

        ret = DoHandShakeMsgType(ssl, input, inOutIdx, type, size, totalSz);
    }
    else {
        word32 pendSz =
            ssl->arrays->pendingMsgSz - ssl->arrays->pendingMsgOffset;

        /* Catch the case where there may be the remainder of a fragmented
         * handshake message and the next handshake message in the same
         * record. */
        if (inputLength > pendSz)
            inputLength = pendSz;

#ifndef WOLFSSL_LEANPSK
        ret = EarlySanityCheckMsgReceived(ssl, ssl->arrays->pendingMsgType,
                inputLength);
        if (ret != 0) {
            WOLFSSL_ERROR(ret);
            return ret;
        }
#endif

    #ifdef WOLFSSL_ASYNC_CRYPT
        if (ssl->error != WC_PENDING_E)
    #endif
        {
            if (ssl->arrays->pendingMsgOffset + inputLength >
                ssl->arrays->pendingMsgSz) {
                return MEMORY_E;
            }
            /* for async this copy was already done, do not replace, since
             * contents may have been changed for inline operations */
            XMEMCPY(ssl->arrays->pendingMsg + ssl->arrays->pendingMsgOffset,
                    input + *inOutIdx, inputLength);
        }
        ssl->arrays->pendingMsgOffset += inputLength;
        *inOutIdx += inputLength;

        if (ssl->arrays->pendingMsgOffset == ssl->arrays->pendingMsgSz)
        {
            word32 idx = HANDSHAKE_HEADER_SZ;
            ret = DoHandShakeMsgType(ssl,
                                     ssl->arrays->pendingMsg,
                                     &idx, ssl->arrays->pendingMsgType,
                                     ssl->arrays->pendingMsgSz - idx,
                                     ssl->arrays->pendingMsgSz);
        #ifdef WOLFSSL_ASYNC_CRYPT
            if (ret == WC_PENDING_E) {
                /* setup to process fragment again */
                ssl->arrays->pendingMsgOffset -= inputLength;
                *inOutIdx -= inputLength;
            }
            else
        #endif
            {
                XFREE(ssl->arrays->pendingMsg, ssl->heap, DYNAMIC_TYPE_ARRAYS);
                ssl->arrays->pendingMsg = NULL;
                ssl->arrays->pendingMsgSz = 0;
            }
        }
    }

    WOLFSSL_LEAVE("DoHandShakeMsg()", ret);
    return ret;
}

#endif /* !WOLFSSL_NO_TLS12 */

#ifdef WOLFSSL_EXTRA_ALERTS
int SendFatalAlertOnly(WOLFSSL *ssl, int error)
{
    int why;

    /* already sent a more specific fatal alert  */
    if (ssl->alert_history.last_tx.level == alert_fatal)
        return 0;

    switch (error) {
        /* not fatal errors */
    case WANT_WRITE:
    case WANT_READ:
    case ZERO_RETURN:
#ifdef WOLFSSL_NONBLOCK_OCSP
    case OCSP_WANT_READ:
#endif
#ifdef WOLFSSL_ASYNC_CRYPT
    case WC_PENDING_E:
#endif
        return 0;

    /* peer already disconnected and ssl is possibly in bad state
     * don't try to send an alert */
    case SOCKET_ERROR_E:
        return error;

    case BUFFER_ERROR:
    case ASN_PARSE_E:
    case COMPRESSION_ERROR:
        why = decode_error;
        break;
    case VERIFY_FINISHED_ERROR:
    case SIG_VERIFY_E:
        why = decrypt_error;
        break;
    case DUPLICATE_MSG_E:
    case NO_CHANGE_CIPHER_E:
    case OUT_OF_ORDER_E:
        why = unexpected_message;
        break;
    case ECC_OUT_OF_RANGE_E:
        why = bad_record_mac;
        break;
    case MATCH_SUITE_ERROR:
    case VERSION_ERROR:
    default:
        why = handshake_failure;
        break;
    }

    return SendAlert(ssl, alert_fatal, why);
}
#else
int SendFatalAlertOnly(WOLFSSL *ssl, int error)
{
    (void)ssl;
    (void)error;
    /* no op */
    return 0;
}
#endif /* WOLFSSL_EXTRA_ALERTS */

#ifndef WOLFSSL_NO_TLS12

#ifdef HAVE_AEAD

#if (!defined(NO_PUBLIC_GCM_SET_IV) && \
    ((defined(HAVE_FIPS) || defined(HAVE_SELFTEST)) && \
    (!defined(HAVE_FIPS_VERSION) || (HAVE_FIPS_VERSION < 2)))) || \
    (defined(HAVE_POLY1305) && defined(HAVE_CHACHA))
static WC_INLINE void AeadIncrementExpIV(WOLFSSL* ssl)
{
    int i;
    for (i = AEAD_MAX_EXP_SZ-1; i >= 0; i--) {
        if (++ssl->keys->aead_exp_IV[i]) return;
    }
}
#endif
#endif /* HAVE_AEAD */


#if defined(BUILD_AESGCM) || defined(HAVE_AESCCM)

#if !defined(NO_GCM_ENCRYPT_EXTRA) && \
    ((!defined(HAVE_FIPS) && !defined(HAVE_SELFTEST)) || \
    (defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION >= 2)))
/* The following type is used to share code between AES-GCM and AES-CCM. */
    typedef int (*AesAuthEncryptFunc)(Aes* aes, byte* out,
                                       const byte* in, word32 sz,
                                       byte* iv, word32 ivSz,
                                       byte* authTag, word32 authTagSz,
                                       const byte* authIn, word32 authInSz);
    #define AES_AUTH_ENCRYPT_FUNC AesAuthEncryptFunc
    #define AES_GCM_ENCRYPT wc_AesGcmEncrypt_ex
    #define AES_CCM_ENCRYPT wc_AesCcmEncrypt_ex
#else
    #define AES_AUTH_ENCRYPT_FUNC wc_AesAuthEncryptFunc
    #define AES_GCM_ENCRYPT wc_AesGcmEncrypt
    #define AES_CCM_ENCRYPT wc_AesCcmEncrypt
#endif

#endif
#endif /* !WOLFSSL_NO_TLS12 */

/* Check conditions for a cipher to have an explicit IV.
 *
 * ssl  The SSL/TLS object.
 * returns 1 if the cipher in use has an explicit IV and 0 otherwise.
 */
static WC_INLINE int CipherHasExpIV(WOLFSSL *ssl)
{
#ifdef WOLFSSL_TLS13
    if (ssl->options.tls1_3)
        return 0;
#endif
    return (ssl->specs.cipher_type == (byte)aead) &&
            (ssl->specs.bulk_cipher_algorithm != (byte)wolfssl_chacha);
}


#ifndef WOLFSSL_LEANPSK_STATIC
/* check cipher text size for sanity */
static int SanityCheckCipherText(WOLFSSL* ssl, word32 encryptSz)
{
#ifdef HAVE_TRUNCATED_HMAC
    word32 minLength = ssl->truncated_hmac ? (byte)TRUNCATED_HMAC_SZ
                                           : ssl->specs.hash_size;
#else
    word32 minLength = ssl->specs.hash_size; /* covers stream */
#endif

#ifndef WOLFSSL_AEAD_ONLY
    if (ssl->specs.cipher_type == block) {
#ifdef HAVE_ENCRYPT_THEN_MAC
        if (ssl->options.startedETMRead) {
            if ((encryptSz - MacSize(ssl)) % ssl->specs.block_size) {
                WOLFSSL_MSG("Block ciphertext not block size");
                WOLFSSL_ERROR_VERBOSE(SANITY_CIPHER_E);
                return SANITY_CIPHER_E;
            }
        }
        else
#endif
        if (encryptSz % ssl->specs.block_size) {
            WOLFSSL_MSG("Block ciphertext not block size");
            WOLFSSL_ERROR_VERBOSE(SANITY_CIPHER_E);
            return SANITY_CIPHER_E;
        }

        minLength++;  /* pad byte */

        if (ssl->specs.block_size > minLength)
            minLength = ssl->specs.block_size;

        if (ssl->options.tls1_1)
            minLength += ssl->specs.block_size;  /* explicit IV */
    }
    else
#endif
    if (ssl->specs.cipher_type == aead) {
        minLength = ssl->specs.aead_mac_size;    /* authTag size */
        if (CipherHasExpIV(ssl))
            minLength += AESGCM_EXP_IV_SZ;       /* explicit IV  */
    }

    if (encryptSz < minLength) {
        WOLFSSL_MSG("Ciphertext not minimum size");
        WOLFSSL_ERROR_VERBOSE(SANITY_CIPHER_E);
        return SANITY_CIPHER_E;
    }

    return 0;
}
#endif /* WOLFSSL_LEANPSK _STATIC */

#ifndef WOLFSSL_AEAD_ONLY
#ifdef WOLSSL_OLD_TIMINGPADVERIFY
#define COMPRESS_LOWER      64
#define COMPRESS_UPPER      55
#define COMPRESS_CONSTANT   13

#ifndef NO_OLD_TLS

static WC_INLINE void Md5Rounds(int rounds, const byte* data, int sz)
{
    wc_Md5 md5;
    int i;

    wc_InitMd5(&md5);   /* no error check on purpose, dummy round */

    for (i = 0; i < rounds; i++)
        wc_Md5Update(&md5, data, sz);
    wc_Md5Free(&md5); /* in case needed to release resources */
}



/* do a dummy sha round */
static WC_INLINE void ShaRounds(int rounds, const byte* data, int sz)
{
    wc_Sha sha;
    int i;

    wc_InitSha(&sha);  /* no error check on purpose, dummy round */

    for (i = 0; i < rounds; i++)
        wc_ShaUpdate(&sha, data, sz);
    wc_ShaFree(&sha); /* in case needed to release resources */
}
#endif


#ifndef NO_SHA256

static WC_INLINE void Sha256Rounds(int rounds, const byte* data, int sz)
{
    wc_Sha256 sha256;
    int i;

    wc_InitSha256(&sha256);  /* no error check on purpose, dummy round */

    for (i = 0; i < rounds; i++) {
        wc_Sha256Update(&sha256, data, sz);
        /* no error check on purpose, dummy round */
    }
    wc_Sha256Free(&sha256); /* in case needed to release resources */
}

#endif


#ifdef WOLFSSL_SHA384

static WC_INLINE void Sha384Rounds(int rounds, const byte* data, int sz)
{
    wc_Sha384 sha384;
    int i;

    wc_InitSha384(&sha384);  /* no error check on purpose, dummy round */

    for (i = 0; i < rounds; i++) {
        wc_Sha384Update(&sha384, data, sz);
        /* no error check on purpose, dummy round */
    }
    wc_Sha384Free(&sha384); /* in case needed to release resources */
}

#endif


#ifdef WOLFSSL_SHA512
static WC_INLINE void Sha512Rounds(int rounds, const byte* data, int sz)
{
    wc_Sha512 sha512;
    int i;

    wc_InitSha512(&sha512);  /* no error check on purpose, dummy round */

    for (i = 0; i < rounds; i++) {
        wc_Sha512Update(&sha512, data, sz);
        /* no error check on purpose, dummy round */
    }
    wc_Sha512Free(&sha512); /* in case needed to release resources */
}

#endif


#ifdef WOLFSSL_RIPEMD

static WC_INLINE void RmdRounds(int rounds, const byte* data, int sz)
{
    RipeMd ripemd;
    int i;

    wc_InitRipeMd(&ripemd);

    for (i = 0; i < rounds; i++)
        wc_RipeMdUpdate(&ripemd, data, sz);
}

#endif


/* Do dummy rounds */
static WC_INLINE void DoRounds(int type, int rounds, const byte* data, int sz)
{
    (void)rounds;
    (void)data;
    (void)sz;

    switch (type) {
        case no_mac :
            break;

#ifndef NO_OLD_TLS
#ifndef NO_MD5
        case md5_mac :
            Md5Rounds(rounds, data, sz);
            break;
#endif

#ifndef NO_SHA
        case sha_mac :
            ShaRounds(rounds, data, sz);
            break;
#endif
#endif

#ifndef NO_SHA256
        case sha256_mac :
            Sha256Rounds(rounds, data, sz);
            break;
#endif

#ifdef WOLFSSL_SHA384
        case sha384_mac :
            Sha384Rounds(rounds, data, sz);
            break;
#endif

#ifdef WOLFSSL_SHA512
        case sha512_mac :
            Sha512Rounds(rounds, data, sz);
            break;
#endif

#ifdef WOLFSSL_RIPEMD
        case rmd_mac :
            RmdRounds(rounds, data, sz);
            break;
#endif

        default:
            WOLFSSL_MSG("Bad round type");
            break;
    }
}


/* do number of compression rounds on dummy data */
static WC_INLINE void CompressRounds(WOLFSSL* ssl, int rounds, const byte* dummy)
{
    if (rounds)
        DoRounds(ssl->specs.mac_algorithm, rounds, dummy, COMPRESS_LOWER);
}


/* check all length bytes for the pad value, return 0 on success */
static int PadCheck(const byte* a, byte pad, int length)
{
    int i;
    int compareSum = 0;

    for (i = 0; i < length; i++) {
        compareSum |= a[i] ^ pad;
    }

    return compareSum;
}


/* get compression extra rounds */
static WC_INLINE int GetRounds(int pLen, int padLen, int t)
{
    int  roundL1 = 1;  /* round up flags */
    int  roundL2 = 1;

    int L1 = COMPRESS_CONSTANT + pLen - t;
    int L2 = COMPRESS_CONSTANT + pLen - padLen - 1 - t;

    L1 -= COMPRESS_UPPER;
    L2 -= COMPRESS_UPPER;

    if ( (L1 % COMPRESS_LOWER) == 0)
        roundL1 = 0;
    if ( (L2 % COMPRESS_LOWER) == 0)
        roundL2 = 0;

    L1 /= COMPRESS_LOWER;
    L2 /= COMPRESS_LOWER;

    L1 += roundL1;
    L2 += roundL2;

    return L1 - L2;
}


/* timing resistant pad/verify check, return 0 on success */
 int TimingPadVerify(WOLFSSL* ssl, const byte* input, int padLen, int t,
                     int pLen, int content)
{
    byte verify[WC_MAX_DIGEST_SIZE];
    byte dmy[sizeof(WOLFSSL) >= MAX_PAD_SIZE ? 1 : MAX_PAD_SIZE] = {0};
    byte* dummy = sizeof(dmy) < MAX_PAD_SIZE ? (byte*) ssl : dmy;
    int  ret = 0;

    (void)dmy;

    if ( (t + padLen + 1) > pLen) {
        WOLFSSL_MSG("Plain Len not long enough for pad/mac");
        PadCheck(dummy, (byte)padLen, MAX_PAD_SIZE);
        /* still compare */
        ssl->hmac(ssl, verify, input, pLen - t, -1, content, 1, PEER_ORDER);
        ConstantCompare(verify, input + pLen - t, t);
        WOLFSSL_ERROR_VERBOSE(VERIFY_MAC_ERROR);
        return VERIFY_MAC_ERROR;
    }

    if (PadCheck(input + pLen - (padLen + 1), (byte)padLen, padLen + 1) != 0) {
        WOLFSSL_MSG("PadCheck failed");
        PadCheck(dummy, (byte)padLen, MAX_PAD_SIZE - padLen - 1);
        /* still compare */
        ssl->hmac(ssl, verify, input, pLen - t, -1, content, 1, PEER_ORDER);
        ConstantCompare(verify, input + pLen - t, t);
        WOLFSSL_ERROR_VERBOSE(VERIFY_MAC_ERROR);
        return VERIFY_MAC_ERROR;
    }

    PadCheck(dummy, (byte)padLen, MAX_PAD_SIZE - padLen - 1);
    ret = ssl->hmac(ssl, verify, input, pLen - padLen - 1 - t, -1, content,
                                                                 1, PEER_ORDER);

    CompressRounds(ssl, GetRounds(pLen, padLen, t), dummy);

    if (ConstantCompare(verify, input + (pLen - padLen - 1 - t), t) != 0) {
        WOLFSSL_MSG("Verify MAC compare failed");
        WOLFSSL_ERROR_VERBOSE(VERIFY_MAC_ERROR);
        return VERIFY_MAC_ERROR;
    }

    /* treat any failure as verify MAC error */
    if (ret != 0) {
        ret = VERIFY_MAC_ERROR;
        WOLFSSL_ERROR_VERBOSE(ret);
    }

    return ret;
}
#else

#if !defined(WOLFSSL_NO_TLS12) && !defined(WOLFSSL_AEAD_ONLY)
 
#ifndef WOLFSSL_LEANPSK_STATIC
/* check all length bytes for the pad value, return 0 on success */
static int PadCheck(const byte* a, byte pad, int length)
{
    int i;
    int compareSum = 0;

    for (i = 0; i < length; i++) {
        compareSum |= a[i] ^ pad;
    }

    return compareSum;
}
#endif /* WOLFSSL_LEANPSK_STATIC */


/* Mask the padding bytes with the expected values.
 * Constant time implementation - does maximum pad size possible.
 *
 * data   Message data.
 * sz     Size of the message including MAC and padding and padding length.
 * macSz  Size of the MAC.
 * returns 0 on success, otherwise failure.
 */
static byte MaskPadding(const byte* data, int sz, int macSz)
{
    int i;
    int checkSz = sz - 1;
    byte paddingSz = data[sz - 1];
    byte good = ctMaskGT(paddingSz, sz - 1 - macSz);

    if (checkSz > TLS_MAX_PAD_SZ)
        checkSz = TLS_MAX_PAD_SZ;

    for (i = 0; i < checkSz; i++) {
        byte mask = ctMaskLTE(i, paddingSz);
        good |= mask & (data[sz - 1 - i] ^ paddingSz);
    }

    return good;
}

/* Mask the MAC in the message with the MAC calculated.
 * Constant time implementation - starts looking for MAC where maximum padding
 * size has it.
 *
 * data    Message data.
 * sz      Size of the message including MAC and padding and padding length.
 * macSz   Size of the MAC data.
 * expMac  Expected MAC value.
 * returns 0 on success, otherwise failure.
 */
static byte MaskMac(const byte* data, int sz, int macSz, byte* expMac)
{
    int i, j;
    unsigned char mac[WC_MAX_DIGEST_SIZE];
    int scanStart = sz - 1 - TLS_MAX_PAD_SZ - macSz;
    int macEnd = sz - 1 - data[sz - 1];
    int macStart = macEnd - macSz;
    int r = 0;
    unsigned char started, notEnded;
    unsigned char good = 0;

    scanStart &= ctMaskIntGTE(scanStart, 0);
    macStart &= ctMaskIntGTE(macStart, 0);

    /* Div on Intel has different speeds depending on value.
     * Use a bitwise AND or mod a specific value (converted to mul). */
    if ((macSz & (macSz - 1)) == 0)
        r = (macSz - (scanStart - macStart)) & (macSz - 1);
#ifndef NO_SHA
    else if (macSz == WC_SHA_DIGEST_SIZE)
        r = (macSz - (scanStart - macStart)) % WC_SHA_DIGEST_SIZE;
#endif
#ifdef WOLFSSL_SHA384
    else if (macSz == WC_SHA384_DIGEST_SIZE)
        r = (macSz - (scanStart - macStart)) % WC_SHA384_DIGEST_SIZE;
#endif

    XMEMSET(mac, 0, macSz);
    for (i = scanStart; i < sz; i += macSz) {
        for (j = 0; j < macSz && j + i < sz; j++) {
            started = ctMaskGTE(i + j, macStart);
            notEnded = ctMaskLT(i + j, macEnd);
            mac[j] |= started & notEnded & data[i + j];
        }
    }

    if ((macSz & (macSz - 1)) == 0) {
        for (i = 0; i < macSz; i++)
            good |= expMac[i] ^ mac[(i + r) & (macSz - 1)];
    }
#ifndef NO_SHA
    else if (macSz == WC_SHA_DIGEST_SIZE) {
        for (i = 0; i < macSz; i++)
            good |= expMac[i] ^ mac[(i + r) % WC_SHA_DIGEST_SIZE];
    }
#endif
#ifdef WOLFSSL_SHA384
    else if (macSz == WC_SHA384_DIGEST_SIZE) {
        for (i = 0; i < macSz; i++)
            good |= expMac[i] ^ mac[(i + r) % WC_SHA384_DIGEST_SIZE];
    }
#endif

    return good;
}

/* timing resistant pad/verify check, return 0 on success */
int TimingPadVerify(WOLFSSL* ssl, const byte* input, int padLen, int macSz,
                    int pLen, int content)
{
    byte verify[WC_MAX_DIGEST_SIZE];
    byte good;
    int  ret = 0;

    good = MaskPadding(input, pLen, macSz);
    /* 4th argument has potential to underflow, ssl->hmac function should
     * either increment the size by (macSz + padLen + 1) before use or check on
     * the size to make sure is valid. */
#if defined(WOLFSSL_RENESAS_FSPSM_TLS) || \
        defined(WOLFSSL_RENESAS_TSIP_TLS)
    ret = ssl->hmac(ssl, verify, input, pLen - macSz - padLen - 1, padLen,
                                                        content, 1, PEER_ORDER);
#else
    ret = TLS_hmac(ssl, verify, input, pLen - macSz - padLen - 1, padLen,
                                                        content, 1, PEER_ORDER);
#endif
    good |= MaskMac(input, pLen, WC_SHA256_DIGEST_SIZE, verify);

    /* Non-zero on failure. */
    good = (byte)~(word32)good;
    good &= good >> 4;
    good &= good >> 2;
    good &= good >> 1;
    /* Make ret negative on masking failure. */
    ret -= 1 - good;

    /* Treat any failure as verify MAC error. */
    if (ret != 0) {
        ret = VERIFY_MAC_ERROR;
        WOLFSSL_ERROR_VERBOSE(ret);
    }

    return ret;
}
#endif /* !WOLFSSL_NO_TLS12 && !WOLFSSL_AEAD_ONLY */
#endif /* WOLSSL_OLD_TIMINGPADVERIFY */
#endif /* WOLFSSL_AEAD_ONLY */

int DoApplicationData(WOLFSSL* ssl, byte* input, word32* inOutIdx, int sniff)
{
    word32 msgSz   = WOLFSSL_IS_QUIC(ssl)? ssl->curSize : ssl->keys->encryptSz;
    word32 idx     = *inOutIdx;
    int    dataSz;
    int    ivExtra = 0;
    byte*  rawData = input + idx;  /* keep current  for hmac */
#ifdef HAVE_LIBZ
    byte   decomp[MAX_RECORD_SIZE + MAX_COMP_EXTRA];
#endif

#ifdef WOLFSSL_EARLY_DATA
    if (ssl->options.tls1_3 && ssl->options.handShakeDone == 0) {
        int process = 0;

        if (ssl->options.side == WOLFSSL_SERVER_END) {
            if ((ssl->earlyData != no_early_data) &&
                          (ssl->options.clientState == CLIENT_HELLO_COMPLETE)) {
                process = 1;
            }
            if (!process) {
                WOLFSSL_MSG("Ignoring EarlyData!");
                *inOutIdx += ssl->curSize;
                if (*inOutIdx > ssl->buffers.inputBuffer.length)
                    return BUFFER_E;

                return 0;
            }
        }
        if (!process) {
            WOLFSSL_MSG("Received App data before a handshake completed");
            if (sniff == NO_SNIFF) {
                SendAlert(ssl, alert_fatal, unexpected_message);
            }
            WOLFSSL_ERROR_VERBOSE(OUT_OF_ORDER_E);
            return OUT_OF_ORDER_E;
        }
    }
    else
#endif
    if (ssl->options.handShakeDone == 0u) {
        WOLFSSL_MSG("Received App data before a handshake completed");
        if (sniff == NO_SNIFF) {
            SendAlert(ssl, alert_fatal, unexpected_message);
        }
        WOLFSSL_ERROR_VERBOSE(OUT_OF_ORDER_E);
        return OUT_OF_ORDER_E;
    }


#if defined(WOLFSSL_DTLS13) && !defined(WOLFSSL_TLS13_IGNORE_AEAD_LIMITS)
    /* Check if we want to invalidate old epochs. If
     * ssl->dtls13InvalidateBefore is set then we want to mark all old
     * epochs as encrypt only. This is done when we detect too many failed
     * decryptions. We do this here to confirm that the peer has updated its
     * keys and we can stop using the old keys-> */
    if (ssl->options.dtls && IsAtLeastTLSv1_3(ssl->version)) {
        if (!w64IsZero(ssl->dtls13InvalidateBefore) &&
                w64Equal(ssl->keys->curEpoch64, ssl->dtls13InvalidateBefore)) {
            Dtls13SetOlderEpochSide(ssl, ssl->dtls13InvalidateBefore,
                                    ENCRYPT_SIDE_ONLY);
            w64Zero(&ssl->dtls13InvalidateBefore);
        }
    }
#endif

#ifndef WOLFSSL_AEAD_ONLY
    if (ssl->specs.cipher_type == (byte)block) {
        if (ssl->options.tls1_1)
            ivExtra = ssl->specs.block_size;
    }
    else
#endif
    if (ssl->specs.cipher_type == (byte)aead) {
        if (CipherHasExpIV(ssl))
            ivExtra = AESGCM_EXP_IV_SZ;
    }

    dataSz = msgSz - ivExtra - ssl->keys->padSz;
#if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
    if (ssl->options.startedETMRead)
        dataSz -= MacSize(ssl);
#endif
    if (dataSz < 0) {
        WOLFSSL_MSG("App data buffer error, malicious input?");
        if (sniff == NO_SNIFF) {
            SendAlert(ssl, alert_fatal, unexpected_message);
        }
        WOLFSSL_ERROR_VERBOSE(BUFFER_ERROR);
        return BUFFER_ERROR;
    }
#ifdef WOLFSSL_EARLY_DATA
    if (ssl->options.side == WOLFSSL_SERVER_END &&
            ssl->earlyData > early_data_ext) {
        if (ssl->earlyDataSz + dataSz > ssl->options.maxEarlyDataSz) {
            if (sniff == NO_SNIFF) {
                SendAlert(ssl, alert_fatal, unexpected_message);
            }
            return WOLFSSL_FATAL_ERROR;
        }
        ssl->earlyDataSz += dataSz;
    }
#endif

    /* read data */
    if (dataSz) {
        int rawSz = dataSz;       /* keep raw size for idx adjustment */

#ifdef HAVE_LIBZ
        if (ssl->options.usingCompression) {
            dataSz = myDeCompress(ssl, rawData, dataSz, decomp, sizeof(decomp));
            if (dataSz < 0) return dataSz;
        }
#endif
        idx += rawSz;

        ssl->buffers.clearOutputBuffer.buffer = rawData;
        ssl->buffers.clearOutputBuffer.length = (unsigned int)dataSz;
    }

    idx += ssl->keys->padSz;
#if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
    if (ssl->options.startedETMRead)
        idx += MacSize(ssl);
#endif

#ifdef HAVE_LIBZ
    /* decompress could be bigger, overwrite after verify */
    if (ssl->options.usingCompression)
        XMEMMOVE(rawData, decomp, dataSz);
#endif

    *inOutIdx = idx;
#ifdef WOLFSSL_DTLS13
    if (ssl->options.connectState == WAIT_FINISHED_ACK) {
        /* DTLS 1.3 is waiting for an ACK but we can still return app data. */
        return APP_DATA_READY;
    }
#endif
    return 0;
}

#ifndef NO_ALERT_STRINGS
const char* AlertTypeToString(int type)
{
    switch (type) {
        case close_notify:
            {
                static const char close_notify_str[] =
                    "close_notify";
                return close_notify_str;
            }

        case unexpected_message:
            {
                static const char unexpected_message_str[] =
                    "unexpected_message";
                return unexpected_message_str;
            }

        case bad_record_mac:
            {
                static const char bad_record_mac_str[] =
                    "bad_record_mac";
                return bad_record_mac_str;
            }

        case record_overflow:
            {
                static const char record_overflow_str[] =
                    "record_overflow";
                return record_overflow_str;
            }

        case decompression_failure:
            {
                static const char decompression_failure_str[] =
                    "decompression_failure";
                return decompression_failure_str;
            }

        case handshake_failure:
            {
                static const char handshake_failure_str[] =
                    "handshake_failure";
                return handshake_failure_str;
            }

        case no_certificate:
            {
                static const char no_certificate_str[] =
                    "no_certificate";
                return no_certificate_str;
            }

        case bad_certificate:
            {
                static const char bad_certificate_str[] =
                    "bad_certificate";
                return bad_certificate_str;
            }

        case unsupported_certificate:
            {
                static const char unsupported_certificate_str[] =
                    "unsupported_certificate";
                return unsupported_certificate_str;
            }

        case certificate_revoked:
            {
                static const char certificate_revoked_str[] =
                    "certificate_revoked";
                return certificate_revoked_str;
            }

        case certificate_expired:
            {
                static const char certificate_expired_str[] =
                    "certificate_expired";
                return certificate_expired_str;
            }

        case certificate_unknown:
            {
                static const char certificate_unknown_str[] =
                    "certificate_unknown";
                return certificate_unknown_str;
            }

        case illegal_parameter:
            {
                static const char illegal_parameter_str[] =
                    "illegal_parameter";
                return illegal_parameter_str;
            }

        case unknown_ca:
            {
                static const char unknown_ca_str[] =
                    "unknown_ca";
                return unknown_ca_str;
            }

        case access_denied:
            {
                static const char access_denied_str[] =
                    "access_denied";
                return access_denied_str;
            }

        case decode_error:
            {
                static const char decode_error_str[] =
                    "decode_error";
                return decode_error_str;
            }

        case decrypt_error:
            {
                static const char decrypt_error_str[] =
                    "decrypt_error";
                return decrypt_error_str;
            }

        case wolfssl_alert_protocol_version:
            {
                static const char protocol_version_str[] =
                    "protocol_version";
                return protocol_version_str;
            }
        case insufficient_security:
            {
                static const char insufficient_security_str[] =
                    "insufficient_security";
                return insufficient_security_str;
            }

        case internal_error:
            {
                static const char internal_error_str[] =
                    "internal_error";
                return internal_error_str;
            }

        case user_canceled:
            {
                static const char user_canceled_str[] =
                    "user_canceled";
                return user_canceled_str;
            }

        case no_renegotiation:
            {
                static const char no_renegotiation_str[] =
                    "no_renegotiation";
                return no_renegotiation_str;
            }

        case unrecognized_name:
            {
                static const char unrecognized_name_str[] =
                    "unrecognized_name";
                return unrecognized_name_str;
            }

        case bad_certificate_status_response:
            {
                static const char bad_certificate_status_response_str[] =
                    "bad_certificate_status_response";
                return bad_certificate_status_response_str;
            }

        case no_application_protocol:
            {
                static const char no_application_protocol_str[] =
                    "no_application_protocol";
                return no_application_protocol_str;
            }
        default:
            WOLFSSL_MSG("Unknown Alert");
            return NULL;
    }
}
#endif /* !NO_ALERT_STRINGS */

#ifndef WOLFSSL_LEANPSK
static void LogAlert(int type)
{
#ifdef DEBUG_WOLFSSL
    const char* typeStr;

    typeStr = AlertTypeToString(type);
    if (typeStr != NULL) {
        char buff[60];
        XSNPRINTF(buff, sizeof(buff), "Alert type: %s", typeStr);
        WOLFSSL_MSG(buff);
    }
#else
    (void)type;
#endif /* DEBUG_WOLFSSL */
}
#endif

/* process alert, return level */
static int DoAlert(WOLFSSL* ssl, byte* input, word32* inOutIdx, int* type)
{
    byte level;
    byte code;
    word32 dataSz = (word32)ssl->curSize;

    #if defined(WOLFSSL_CALLBACKS) || defined(OPENSSL_EXTRA)
        if (ssl->hsInfoOn)
            AddPacketName(ssl, "Alert");
        if (ssl->toInfoOn) {
            /* add record header back on to info + alert bytes level/code */
            int ret = AddPacketInfo(ssl, "Alert", alert, input + *inOutIdx,
                          ALERT_SIZE, READ_PROTO, RECORD_HEADER_SZ, ssl->heap);
            if (ret != 0)
                return ret;
            #ifdef WOLFSSL_CALLBACKS
            AddLateRecordHeader(&ssl->curRL, &ssl->timeoutInfo);
            #endif
        }
    #endif

    if (IsEncryptionOn(ssl, 0)) {
        int ivExtra = 0;
#ifndef WOLFSSL_AEAD_ONLY
        if (ssl->specs.cipher_type == (byte)block) {
            if (ssl->options.tls1_1)
                ivExtra = ssl->specs.block_size;
        }
        else
#endif
        if (ssl->specs.cipher_type == (byte)aead) {
            if (CipherHasExpIV(ssl))
                ivExtra = AESGCM_EXP_IV_SZ;
        }
        dataSz -= ivExtra;
        dataSz -= ssl->keys->padSz;
    #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
        if (ssl->options.startedETMRead)
            dataSz -= MacSize(ssl);
    #endif
    }

    /* make sure can read the message */
    if (dataSz != (word32)ALERT_SIZE) {
#ifdef WOLFSSL_EXTRA_ALERTS
        SendAlert(ssl, alert_fatal, unexpected_message);
#endif
        return BUFFER_E;
    }

    level = input[(*inOutIdx)++];
    code  = input[(*inOutIdx)++];
    ssl->alert_history.last_rx.code = code;
    ssl->alert_history.last_rx.level = level;
    *type = code;
    if (level == (byte)alert_fatal) {
        ssl->options.isClosed = 1;  /* Don't send close_notify */
    }

    if (++ssl->options.alertCount >= (byte)WOLFSSL_ALERT_COUNT_MAX) {
        WOLFSSL_MSG("Alert count exceeded");
#ifdef WOLFSSL_EXTRA_ALERTS
        if (level != alert_warning || code != close_notify)
            SendAlert(ssl, alert_fatal, unexpected_message);
#endif
        WOLFSSL_ERROR_VERBOSE(ALERT_COUNT_E);
        return ALERT_COUNT_E;
    }

#ifndef WOLFSSL_LEANPSK
    LogAlert(*type);
#endif
    if (*type == close_notify) {
        ssl->options.closeNotify = 1;
    }
    else {
        /*
         * A close_notify alert doesn't mean there's been an error, so we only
         * add other types of alerts to the error queue
         */
        WOLFSSL_ERROR(*type);
    }

    if (IsEncryptionOn(ssl, 0)) {
        *inOutIdx += ssl->keys->padSz;
    #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
        if (ssl->options.startedETMRead)
            *inOutIdx += MacSize(ssl);
    #endif
    }

    return level;
}

static int GetInputData(WOLFSSL *ssl, word32 size)
{
    int inSz;
    int maxLength;
    int usedLength;
    int dtlsExtra = 0;


    /* check max input length */
    usedLength = ssl->buffers.inputBuffer.length - ssl->buffers.inputBuffer.idx;
    maxLength  = ssl->buffers.inputBuffer.bufferSize - usedLength;
    inSz       = (int)(size - usedLength);      /* from last partial read */

    /* check that no lengths or size values are negative */
    if (usedLength < 0 || maxLength < 0 || inSz <= 0) {
        return BUFFER_ERROR;
    }

    if (inSz > maxLength) {
        if (GrowInputBuffer(ssl, size + dtlsExtra, usedLength) < 0)
            return MEMORY_E;
    }

    /* Put buffer data at start if not there */
    if (usedLength > 0 && ssl->buffers.inputBuffer.idx != 0u)
        XMEMMOVE(&ssl->buffers.inputBuffer.buffer[0],
                ssl->buffers.inputBuffer.buffer + ssl->buffers.inputBuffer.idx,
                usedLength);

    /* remove processed data */
    ssl->buffers.inputBuffer.idx    = 0;
    ssl->buffers.inputBuffer.length = (word32)usedLength;

    /* read data from network */
    do {
        int in = wolfSSLReceive(ssl,
                     ssl->buffers.inputBuffer.buffer +
                     ssl->buffers.inputBuffer.length,
                     (word32)inSz);
        if (in == WANT_READ)
            return WANT_READ;

        if (in < 0) {
            WOLFSSL_ERROR_VERBOSE(SOCKET_ERROR_E);
            return SOCKET_ERROR_E;
        }

        if (in > inSz) {
            WOLFSSL_ERROR_VERBOSE(RECV_OVERFLOW_E);
            return RECV_OVERFLOW_E;
        }

        ssl->buffers.inputBuffer.length += in;
        inSz -= in;

    } while (ssl->buffers.inputBuffer.length < size);

    return 0;
}

#if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
static WC_INLINE int VerifyMacEnc(WOLFSSL* ssl, const byte* input, word32 msgSz,
                                  int content)
{
    int    ret;
#ifdef HAVE_TRUNCATED_HMAC
    word32 digestSz = ssl->truncated_hmac ? (byte)TRUNCATED_HMAC_SZ
                                          : ssl->specs.hash_size;
#else
    word32 digestSz = ssl->specs.hash_size;
#endif
    byte   verify[WC_MAX_DIGEST_SIZE];

    WOLFSSL_MSG("Verify MAC of Encrypted Data");

    if (msgSz < digestSz) {
        WOLFSSL_ERROR_VERBOSE(VERIFY_MAC_ERROR);
        return VERIFY_MAC_ERROR;
    }

    ret  = ssl->hmac(ssl, verify, input, msgSz - digestSz, -1, content, 1, PEER_ORDER);
    ret |= ConstantCompare(verify, input + msgSz - digestSz, (int)digestSz);
    if (ret != 0) {
        WOLFSSL_ERROR_VERBOSE(VERIFY_MAC_ERROR);
        return VERIFY_MAC_ERROR;
    }

    return 0;
}
#endif

static WC_INLINE int VerifyMac(WOLFSSL* ssl, const byte* input, word32 msgSz,
                            int content, word32* padSz)
{
#if !defined(WOLFSSL_NO_TLS12) && !defined(WOLFSSL_AEAD_ONLY)
    int    ret;
    word32 pad     = 0;
    word32 padByte = 0;
#ifdef HAVE_TRUNCATED_HMAC
    word32 digestSz = ssl->truncated_hmac ? (byte)TRUNCATED_HMAC_SZ
                                          : ssl->specs.hash_size;
#else
    word32 digestSz = WC_SHA256_DIGEST_SIZE;
#endif
    byte   verify[WC_MAX_DIGEST_SIZE];


    if (ssl->specs.cipher_type == (byte)block) {
        int ivExtra = 0;
//#ifndef NO_OLD_TLS
        if (ssl->options.tls1_1)
            ivExtra = ssl->specs.block_size;
//#endif
        pad = *(input + msgSz - ivExtra - 1);
        padByte = 1;

        if (ssl->options.tls) {
            ret = TimingPadVerify(ssl, input, pad, digestSz, msgSz - ivExtra,
                                  content);
            if (ret != 0)
                return ret;
        }
    }
#endif /* !WOLFSSL_NO_TLS12 && !WOLFSSL_AEAD_ONLY */

    if (ssl->specs.cipher_type == (byte)aead) {
        *padSz = ssl->specs.aead_mac_size;
    }
    else 
#if !defined(WOLFSSL_NO_TLS12) && !defined(WOLFSSL_AEAD_ONLY)
    {
        *padSz = digestSz + pad + padByte;
    }
#endif /* !WOLFSSL_NO_TLS12 && !WOLFSSL_AEAD_ONLY */

    (void)input;
    (void)msgSz;
    (void)content;

    return 0;
}


int ProcessReply(WOLFSSL* ssl)
{
    int allowSocketErr = 0;
    int    ret = 0, type = internal_error, readSz;
    int    atomicUser = 0;

    if (ssl->error != 0 && ssl->error != WANT_READ && ssl->error != WANT_WRITE
    #if defined(HAVE_SECURE_RENEGOTIATION) || defined(WOLFSSL_DTLS13)
        && ssl->error != APP_DATA_READY
    #endif
    #ifdef WOLFSSL_ASYNC_CRYPT
        && ssl->error != WC_PENDING_E
    #endif
    #ifdef WOLFSSL_NONBLOCK_OCSP
        && ssl->error != OCSP_WANT_READ
    #endif
        && (allowSocketErr != 1 || ssl->error != SOCKET_ERROR_E)
    ) {
        WOLFSSL_MSG("ProcessReply retry in error state, not allowed");
        return ssl->error;
    }

    /* If checking alert on error (allowSocketErr == 1) do not try and
     * process alerts for async or ocsp non blocking */
#if defined(WOLFSSL_CHECK_ALERT_ON_ERR) && \
    (defined(WOLFSSL_ASYNC_CRYPT) || defined(WOLFSSL_NONBLOCK_OCSP))
    if (allowSocketErr == 1 && \
        (ssl->error == WC_PENDING_E || ssl->error == OCSP_WANT_READ)) {
        return ssl->error;
    }
#endif

    ret = RetrySendAlert(ssl);
    if (ret != 0) {
        WOLFSSL_MSG_EX("RetrySendAlert failed, giving up. err = %d", ret);
        return ret;
    }

    for (;;) {
        switch (ssl->options.processReply) {

        /* in the WOLFSSL_SERVER case, get the first byte for detecting
         * old client hello */
        case doProcessInit:

            readSz = RECORD_HEADER_SZ;

            /* get header or return error */
                if ((ret = GetInputData(ssl, (word32)readSz)) < 0)
                    return ret;

            FALL_THROUGH;

        /* get the record layer header */
        case getRecordLayerHeader:

            /* DTLSv1.3 record numbers in the header are encrypted, and AAD
             * uses the unencrypted form. Because of this we need to modify the
             * header, decrypting the numbers inside
             * DtlsParseUnifiedRecordLayer(). This violates the const attribute
             * of the buffer parameter of GetRecordHeader() used here. */
            ret = GetRecordHeader(ssl, &ssl->buffers.inputBuffer.idx,
                                       &ssl->curRL, &ssl->curSize);

            if (ret != 0) {
                switch (ret) {
                case VERSION_ERROR:
                    /* send alert per RFC5246 Appendix E. Backward
                     * Compatibility */
                    if (ssl->options.side == (byte)WOLFSSL_CLIENT_END)
                        SendAlert(ssl, alert_fatal,
                            wolfssl_alert_protocol_version);
                    break;
#ifdef HAVE_MAX_FRAGMENT
                case LENGTH_ERROR:
                    SendAlert(ssl, alert_fatal, record_overflow);
                    break;
#endif /* HAVE_MAX_FRAGMENT */
default:
                    break;
                }
                return ret;
            }

            ssl->options.processReply = getData;
            FALL_THROUGH;

        /* retrieve record layer data */
        case getData:

            /* get sz bytes or return error */
#ifdef WOLFSSL_DTLS
            if (!ssl->options.dtls) {
#endif
                if ((ret = GetInputData(ssl, ssl->curSize)) < 0) {
#ifdef WOLFSSL_EXTRA_ALERTS
                    if (ret != WANT_READ)
                        SendAlert(ssl, alert_fatal, bad_record_mac);
#endif
                    return ret;
                }

#ifndef WOLFSSL_LEANPSK
            if (IsEncryptionOn(ssl, 0)) {
#if defined(WOLFSSL_TLS13) || defined(WOLFSSL_EXTRA_ALERTS)
                int tooLong = 0;
#endif

#ifdef WOLFSSL_TLS13
                if (IsAtLeastTLSv1_3(ssl->version)) {
                    tooLong  = ssl->curSize > MAX_TLS13_ENC_SZ;
                    tooLong |= ssl->curSize - ssl->specs.aead_mac_size >
                                                             MAX_TLS13_PLAIN_SZ;
                }
#endif
#ifdef WOLFSSL_EXTRA_ALERTS
                if (!IsAtLeastTLSv1_3(ssl->version))
                    tooLong = ssl->curSize > MAX_TLS_CIPHER_SZ;
#endif
#if defined(WOLFSSL_TLS13) || defined(WOLFSSL_EXTRA_ALERTS)
                if (tooLong) {
                    WOLFSSL_MSG("Encrypted data too long");
                    SendAlert(ssl, alert_fatal, record_overflow);
                    return BUFFER_ERROR;
                }
#endif
            }
#endif
            ssl->keys->padSz = 0;

            ssl->options.processReply = verifyEncryptedMessage;
            /* in case > 1 msg per record */
            ssl->curStartIdx = ssl->buffers.inputBuffer.idx;
            FALL_THROUGH;

        /* verify digest of encrypted message */
        case verifyEncryptedMessage:
#if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
            if (IsEncryptionOn(ssl, 0) && ssl->keys->decryptedCur == 0 &&
                                   !atomicUser && ssl->options.startedETMRead) {
                ret = VerifyMacEnc(ssl, ssl->buffers.inputBuffer.buffer +
                                   ssl->buffers.inputBuffer.idx,
                                   ssl->curSize, ssl->curRL.type);
            #ifdef WOLFSSL_ASYNC_CRYPT
                if (ret == WC_PENDING_E)
                    return ret;
            #endif
                if (ret < 0) {
                    WOLFSSL_MSG("VerifyMacEnc failed");
                #ifdef WOLFSSL_DTLS
                    /* If in DTLS mode, if the decrypt fails for any
                     * reason, pretend the datagram never happened. */
                    if (ssl->options.dtls) {
                        ssl->options.processReply = doProcessInit;
                        ssl->buffers.inputBuffer.idx =
                                ssl->buffers.inputBuffer.length;
                        return HandleDTLSDecryptFailed(ssl);
                    }
                #endif /* WOLFSSL_DTLS */
                #ifdef WOLFSSL_EXTRA_ALERTS
                    if (!ssl->options.dtls)
                        SendAlert(ssl, alert_fatal, bad_record_mac);
                #endif
                    WOLFSSL_ERROR_VERBOSE(DECRYPT_ERROR);
                    return DECRYPT_ERROR;
                }
                ssl->keys->encryptSz    = ssl->curSize;
            }
#endif
            ssl->options.processReply = decryptMessage;
            FALL_THROUGH;

        /* decrypt message */
        case decryptMessage:

            if (IsEncryptionOn(ssl, 0) && ssl->keys->decryptedCur == 0u &&
                                        (!IsAtLeastTLSv1_3(ssl->version) ||
                                         ssl->curRL.type != (byte)change_cipher_spec))
            {
                bufferStatic* in = &ssl->buffers.inputBuffer;

#ifndef WOLFSSL_LEANPSK_STATIC
                ret = SanityCheckCipherText(ssl, ssl->curSize);
                if (ret < 0) {
                #ifdef WOLFSSL_EXTRA_ALERTS
                    SendAlert(ssl, alert_fatal, bad_record_mac);
                #endif
                    return ret;
                }
#endif

                if (atomicUser) {
                }
                else {
                    if (!ssl->options.tls1_3) {
        #ifndef WOLFSSL_NO_TLS12
            #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
                    if (ssl->options.startedETMRead) {
                        word32 digestSz = MacSize(ssl);
                        ret = DecryptTls(ssl,
                                      in->buffer + in->idx,
                                      in->buffer + in->idx,
                                      ssl->curSize - (word16)digestSz);
                        if (ret == 0) {
                            byte invalid = 0;
                            byte padding = (byte)-1;
                            word32 i;
                            word32 off = in->idx + ssl->curSize - digestSz - 1;

                            /* Last of padding bytes - indicates length. */
                            ssl->keys->padSz = in->buffer[off];
                            /* Constant time checking of padding - don't leak
                             * the length of the data.
                             */
                            /* Compare max pad bytes or at most data + pad. */
                            for (i = 1; i < MAX_PAD_SIZE && off >= i; i++) {
                                /* Mask on indicates this is expected to be a
                                 * padding byte.
                                 */
                                padding &= ctMaskLTE(i, ssl->keys->padSz);
                                /* When this is a padding byte and not equal
                                 * to length then mask is set.
                                 */
                                invalid |= padding &
                                           ctMaskNotEq(in->buffer[off - i],
                                                       ssl->keys->padSz);
                            }
                            /* If mask is set then there was an error. */
                            if (invalid) {
                                ret = DECRYPT_ERROR;
                            }
                            ssl->keys->padSz += 1;
                            ssl->keys->decryptedCur = 1;
                        }
                    }
                    else
            #endif
                    {
                        Aes  *aes;
                        byte *key;
                        byte *iv;

                        aes = (Aes*)XMALLOC(sizeof(Aes), ssl->heap,
                                DYNAMIC_TYPE_CIPHER);
                        if (aes == NULL) {
                            return MEMORY_E;
                        }

                        if (wc_AesInit(aes, ssl->heap, INVALID_DEVID) != 0) {
                            WOLFSSL_MSG("AesInit failed in SetKeys");
                            return ASYNC_INIT_E;
                        }

                        //If server side this should be keys->client_write_key
                        key = ssl->keys->keys + WC_MAX_DIGEST_SIZE +
                                WC_MAX_DIGEST_SIZE + MAX_SYM_KEY_SIZE;
                        iv  = key + MAX_SYM_KEY_SIZE + MAX_WRITE_IV_SZ;

                        ret = wc_AesSetKey(aes, key, AES_128_KEY_SIZE, iv,
                                       AES_DECRYPTION);
                        if (ret != 0) {
                            XFREE(aes, ssl->heap, DYNAMIC_TYPE_CIPHER);
                            return ret;
                        }

                        ret = wc_AesCbcDecrypt(aes,
                                    in->buffer + in->idx, in->buffer + in->idx,
                                    ssl->curSize);
                        XMEMCPY(iv, aes->reg, AES_BLOCK_SIZE);
                        wc_AesFree(aes);
                        XFREE(aes, ssl->heap, DYNAMIC_TYPE_CIPHER);
                    }
        #else
                        ret = DECRYPT_ERROR;
        #endif
                    }
                    else
                    {
                #ifdef WOLFSSL_TLS13
                        byte *aad = (byte*)&ssl->curRL;
                        word16 aad_size = RECORD_HEADER_SZ;
                    #ifdef WOLFSSL_DTLS13
                        if (ssl->options.dtls) {
                            /* aad now points to the record header */
                            aad = ssl->dtls13CurRL;
                            aad_size = ssl->dtls13CurRlLength;
                        }
                    #endif /* WOLFSSL_DTLS13 */
                        /* Don't send an alert for DTLS. We will just drop it
                         * silently later. */
                        ret = DecryptTls13(ssl,
                                        in->buffer + in->idx,
                                        in->buffer + in->idx,
                                        ssl->curSize,
                                        aad, aad_size);
                #else
                        ret = DECRYPT_ERROR;
                #endif /* WOLFSSL_TLS13 */
                    }
                    (void)in;
                }

                if (ret >= 0) {
            #ifndef WOLFSSL_NO_TLS12
                    /* handle success */
                #ifndef WOLFSSL_AEAD_ONLY
                    if (ssl->options.tls1_1 && ssl->specs.cipher_type == (byte)block)
                        ssl->buffers.inputBuffer.idx += ssl->specs.block_size;
                #endif
                    /* go past TLSv1.1 IV */
                    if (CipherHasExpIV(ssl))
                        ssl->buffers.inputBuffer.idx += AESGCM_EXP_IV_SZ;
            #endif
                }
                else {
                    WOLFSSL_MSG("Decrypt failed");
                    SendAlert(ssl, alert_fatal, bad_record_mac);
                    /* Push error once we know that we will error out here */
                    WOLFSSL_ERROR(ret);
                    return ret;
                }
            }

            ssl->options.processReply = verifyMessage;
            FALL_THROUGH;

        /* verify digest of message */
        case verifyMessage:

            if (IsEncryptionOn(ssl, 0) && ssl->keys->decryptedCur == 0u &&
                                        (!IsAtLeastTLSv1_3(ssl->version) ||
                                         ssl->curRL.type != (byte)change_cipher_spec))
            {
                if (!atomicUser
#if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
                                && !ssl->options.startedETMRead
#endif
                    ) {
                    ret = VerifyMac(ssl, ssl->buffers.inputBuffer.buffer +
                                    ssl->buffers.inputBuffer.idx,
                                    ssl->curSize, ssl->curRL.type,
                                    &ssl->keys->padSz);
                #ifdef WOLFSSL_ASYNC_CRYPT
                    if (ret == WC_PENDING_E)
                        return ret;
                #endif
                    if (ret < 0) {
                    #if defined(WOLFSSL_EXTRA_ALERTS) && !defined(WOLFSSL_NO_ETM_ALERT)
                        if (!ssl->options.dtls)
                            SendAlert(ssl, alert_fatal, bad_record_mac);
                    #endif
                        WOLFSSL_MSG("VerifyMac failed");
                        WOLFSSL_ERROR_VERBOSE(DECRYPT_ERROR);
                        return DECRYPT_ERROR;
                    }
                }

                ssl->keys->encryptSz    = ssl->curSize;
                ssl->keys->decryptedCur = 1;
            }

            ssl->options.processReply = runProcessingOneRecord;
            FALL_THROUGH;

        /* the record layer is here */
        case runProcessingOneRecord:
            ssl->options.processReply = runProcessingOneMessage;
            FALL_THROUGH;

        case runProcessingOneMessage:
            /* can't process a message if we have no data.  */
            if (ssl->buffers.inputBuffer.idx
                    >= ssl->buffers.inputBuffer.length) {
                return BUFFER_ERROR;
            }
       #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
            if (IsEncryptionOn(ssl, 0) && ssl->options.startedETMRead) {
                /* For TLS v1.1 the block size and explicit IV are added to idx,
                 * so it needs to be included in this limit check */
                if ((ssl->curSize - ssl->keys->padSz -
                        (ssl->buffers.inputBuffer.idx - ssl->curStartIdx) -
                        MacSize(ssl) > MAX_PLAINTEXT_SZ)
#ifdef WOLFSSL_ASYNC_CRYPT
                        && ssl->buffers.inputBuffer.length !=
                                ssl->buffers.inputBuffer.idx
#endif
                                ) {
                    WOLFSSL_MSG("Plaintext too long - Encrypt-Then-MAC");
            #if defined(WOLFSSL_EXTRA_ALERTS) && !defined(WOLFSSL_NO_ETM_ALERT)
                    SendAlert(ssl, alert_fatal, record_overflow);
            #endif
                    WOLFSSL_ERROR_VERBOSE(BUFFER_ERROR);
                    return BUFFER_ERROR;
                }
            }
            else
       #endif
            /* TLS13 plaintext limit is checked earlier before decryption */
            /* For TLS v1.1 the block size and explicit IV are added to idx,
             * so it needs to be included in this limit check */
            if (!IsAtLeastTLSv1_3(ssl->version)
                    && ssl->curSize - ssl->keys->padSz -
                        (ssl->buffers.inputBuffer.idx - ssl->curStartIdx)
                            > MAX_PLAINTEXT_SZ
#ifdef WOLFSSL_ASYNC_CRYPT
                    && ssl->buffers.inputBuffer.length !=
                            ssl->buffers.inputBuffer.idx
#endif
                                ) {
                WOLFSSL_MSG("Plaintext too long");
#if defined(WOLFSSL_TLS13) || defined(WOLFSSL_EXTRA_ALERTS)
                SendAlert(ssl, alert_fatal, record_overflow);
#endif
                WOLFSSL_ERROR_VERBOSE(BUFFER_ERROR);
                return BUFFER_ERROR;
            }

            WOLFSSL_MSG("received record layer msg");

            switch (ssl->curRL.type) {
                case handshake :
                    WOLFSSL_MSG("got HANDSHAKE");
                    if (!IsAtLeastTLSv1_3(ssl->version)
#if defined(WOLFSSL_TLS13) && !defined(WOLFSSL_NO_TLS12)
                            || !TLSv1_3_Capable(ssl)
#endif
                            ) {
#ifndef WOLFSSL_NO_TLS12
                        ret = DoHandShakeMsg(ssl,
                                            ssl->buffers.inputBuffer.buffer,
                                            &ssl->buffers.inputBuffer.idx,
                                            ssl->buffers.inputBuffer.length);
                        if (ret != 0) {
                            if (SendFatalAlertOnly(ssl, ret) == SOCKET_ERROR_E)
                                ret = SOCKET_ERROR_E;
                        }
#else
                        ret = BUFFER_ERROR;
#endif
                    }
                    else {
#ifdef WOLFSSL_TLS13
                        ssl->msgsReceived.got_change_cipher = 0;
                        ret = DoTls13HandShakeMsg(ssl,
                                            ssl->buffers.inputBuffer.buffer,
                                            &ssl->buffers.inputBuffer.idx,
                                            ssl->buffers.inputBuffer.length);
    #ifdef WOLFSSL_EARLY_DATA
                        if (ret != 0)
                            return ret;
                        if (ssl->options.side == WOLFSSL_SERVER_END &&
                                ssl->earlyData > early_data_ext &&
                                ssl->options.handShakeState == HANDSHAKE_DONE) {
                            ssl->earlyData = no_early_data;
                            ssl->options.processReply = doProcessInit;
                            return ZERO_RETURN;
                        }
    #endif
#else
                        ret = BUFFER_ERROR;
#endif
                    }
                    if (ret != 0
                            
        #ifdef WOLFSSL_DTLS
                            /* DoDtlsHandShakeMsg can return a WANT_WRITE when
                             * calling DtlsMsgPoolSend. This msg is done
                             * processing so let's move on. */
                        && (!ssl->options.dtls
                            || ret != WANT_WRITE)
#endif
#ifdef WOLFSSL_ASYNC_CRYPT
                    /* In async case, on pending, move onto next message.
                     * Current message should have been DtlsMsgStore'ed and
                     * should be processed with DtlsMsgDrain */
                            && (!ssl->options.dtls
                                || ret != WC_PENDING_E)
#endif
                    ) {
                        WOLFSSL_ERROR(ret);
                        return ret;
                    }
                    break;

                case change_cipher_spec:
                    WOLFSSL_MSG("got CHANGE CIPHER SPEC");
                    #if defined(WOLFSSL_CALLBACKS) || defined(OPENSSL_EXTRA)
                        if (ssl->hsInfoOn)
                            AddPacketName(ssl, "ChangeCipher");
                        /* add record header back on info */
                        if (ssl->toInfoOn) {
                            ret = AddPacketInfo(ssl, "ChangeCipher",
                                change_cipher_spec,
                                ssl->buffers.inputBuffer.buffer +
                                ssl->buffers.inputBuffer.idx,
                                1, READ_PROTO, RECORD_HEADER_SZ, ssl->heap);
                            if (ret != 0)
                                return ret;
                            #ifdef WOLFSSL_CALLBACKS
                            AddLateRecordHeader(&ssl->curRL, &ssl->timeoutInfo);
                            #endif
                        }
                    #endif

#ifdef WOLFSSL_TLS13
                    if (IsAtLeastTLSv1_3(ssl->version)) {
                        word32 i = ssl->buffers.inputBuffer.idx;
                        if (ssl->options.handShakeState == HANDSHAKE_DONE) {
                            SendAlert(ssl, alert_fatal, unexpected_message);
                            WOLFSSL_ERROR_VERBOSE(UNKNOWN_RECORD_TYPE);
                            return UNKNOWN_RECORD_TYPE;
                        }
                        if (ssl->curSize != 1 ||
                                      ssl->buffers.inputBuffer.buffer[i] != 1) {
                            SendAlert(ssl, alert_fatal, illegal_parameter);
                            WOLFSSL_ERROR_VERBOSE(UNKNOWN_RECORD_TYPE);
                            return UNKNOWN_RECORD_TYPE;
                        }
                        ssl->buffers.inputBuffer.idx++;
                        if (!ssl->msgsReceived.got_change_cipher) {
                            ssl->msgsReceived.got_change_cipher = 1;
                        }
                        else {
                            SendAlert(ssl, alert_fatal, illegal_parameter);
                            WOLFSSL_ERROR_VERBOSE(UNKNOWN_RECORD_TYPE);
                            return UNKNOWN_RECORD_TYPE;
                        }
                        break;
                    }
#endif

#ifndef WOLFSSL_NO_TLS12
                    if (ssl->buffers.inputBuffer.idx >=
                            ssl->buffers.inputBuffer.length ||
                            ssl->curSize < 1u) {
                        WOLFSSL_MSG("ChangeCipher msg too short");
                        WOLFSSL_ERROR_VERBOSE(LENGTH_ERROR);
                        return LENGTH_ERROR;
                    }
                    if (ssl->buffers.inputBuffer.buffer[
                            ssl->buffers.inputBuffer.idx] != 1u) {
                        WOLFSSL_MSG("ChangeCipher msg wrong value");
                        WOLFSSL_ERROR_VERBOSE(LENGTH_ERROR);
                        return LENGTH_ERROR;
                    }

                    if (IsEncryptionOn(ssl, 0) && ssl->options.handShakeDone) {
#ifdef HAVE_AEAD
                        if (ssl->specs.cipher_type == aead) {
                            if (ssl->specs.bulk_cipher_algorithm != wolfssl_chacha)
                                ssl->curSize -= AESGCM_EXP_IV_SZ;
                            ssl->buffers.inputBuffer.idx += ssl->specs.aead_mac_size;
                            ssl->curSize -= ssl->specs.aead_mac_size;
                        }
                        else
#endif
                        {
                            ssl->buffers.inputBuffer.idx += ssl->keys->padSz;
                            ssl->curSize -= (word16)ssl->keys->padSz;
                        #ifdef HAVE_CHACHA
                            ssl->curSize -= CHACHA20_IV_SIZE;
                        #else
                            ssl->curSize -= AES_IV_SIZE;
                        #endif
                        }

            #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
                        if (ssl->options.startedETMRead) {
                            word32 digestSz = MacSize(ssl);
                            ssl->buffers.inputBuffer.idx += digestSz;
                            ssl->curSize -= (word16)digestSz;
                        }
            #endif
                    }

                    if (ssl->curSize != 1u) {
                        WOLFSSL_MSG("Malicious or corrupted ChangeCipher msg");
                        WOLFSSL_ERROR_VERBOSE(LENGTH_ERROR);
                        return LENGTH_ERROR;
                    }

                    ssl->buffers.inputBuffer.idx++;

#if 0
                    ret = SanityCheckMsgReceived(ssl, change_cipher_hs);
                    if (ret != 0) {
                        if (!ssl->options.dtls) {
                            return ret;
                        }
                        else {
                        #ifdef WOLFSSL_DTLS
                        /* Check for duplicate CCS message in DTLS mode.
                         * DTLS allows for duplicate messages, and it should be
                         * skipped. Also skip if out of order. */
                            if (ret != DUPLICATE_MSG_E && ret != OUT_OF_ORDER_E)
                                return ret;
                            /* Reset error */
                            ret = 0;
                            break;
                        #endif /* WOLFSSL_DTLS */
                        }
                    }
#endif

                    ssl->keys->encryptionOn = 1;

                    /* setup decrypt keys for following messages */
                    /* XXX This might not be what we want to do when
                     * receiving a CCS with multicast. We update the
                     * key when the application updates them. */
                    //if ((ret = SetKeysSide(ssl, DECRYPT_SIDE_ONLY)) != 0)
                    //    return ret;
                    ssl->decryptSetup = 1;
                    ssl->keys->peer_sequence_number_hi = 0;
                    ssl->keys->peer_sequence_number_lo = 0;

            #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
                    ssl->options.startedETMRead = ssl->options.encThenMac;
            #endif

                    #ifdef WOLFSSL_DTLS
                        if (ssl->options.dtls) {
                            WOLFSSL_DTLS_PEERSEQ* peerSeq = ssl->keys->peerSeq;
#ifdef WOLFSSL_MULTICAST
                            if (ssl->options.haveMcast) {
                                peerSeq += ssl->keys->curPeerId;
                                peerSeq->highwaterMark = UpdateHighwaterMark(0,
                                        ssl->ctx->mcastFirstSeq,
                                        ssl->ctx->mcastSecondSeq,
                                        ssl->ctx->mcastMaxSeq);
                            }
#endif
                            peerSeq->nextEpoch++;
                            peerSeq->prevSeq_lo = peerSeq->nextSeq_lo;
                            peerSeq->prevSeq_hi = peerSeq->nextSeq_hi;
                            peerSeq->nextSeq_lo = 0;
                            peerSeq->nextSeq_hi = 0;
                            XMEMCPY(peerSeq->prevWindow, peerSeq->window,
                                    DTLS_SEQ_SZ);
                            XMEMSET(peerSeq->window, 0, DTLS_SEQ_SZ);
                        }
                    #endif

                    #ifdef HAVE_LIBZ
                        if (ssl->options.usingCompression)
                            if ( (ret = InitStreams(ssl)) != 0)
                                return ret;
                    #endif
                    ret = BuildTlsFinished(ssl, &ssl->hsHashes->verifyHashes,
                                       ssl->options.side == (byte)WOLFSSL_CLIENT_END ?
                                       1 : 0);
                    if (ret != 0)
                        return ret;
#endif /* !WOLFSSL_NO_TLS12 */
                    break;

                case application_data:
                    WOLFSSL_MSG("got app DATA");
                    if ((ret = DoApplicationData(ssl,
                                                ssl->buffers.inputBuffer.buffer,
                                                &ssl->buffers.inputBuffer.idx,
                                                              NO_SNIFF)) != 0) {
                        WOLFSSL_ERROR(ret);
                    #if defined(WOLFSSL_DTLS13) || \
                        defined(HAVE_SECURE_RENEGOTIATION)
                        /* Not really an error. We will return after cleaning
                         * up the processReply state. */
                        if (ret != APP_DATA_READY)
                    #endif
                            return ret;
                    }
                    break;

                case alert:
                    WOLFSSL_MSG("got ALERT!");
                    ret = DoAlert(ssl, ssl->buffers.inputBuffer.buffer,
                                  &ssl->buffers.inputBuffer.idx, &type);
                    if (ret == alert_fatal)
                        return FATAL_ERROR;
                    else if (ret < 0)
                        return ret;

                    /* catch warnings that are handled as errors */
                    if (type == close_notify) {
                        ssl->buffers.inputBuffer.idx =
                            ssl->buffers.inputBuffer.length;
                        ssl->options.processReply = doProcessInit;
                        return ssl->error = ZERO_RETURN;
                    }

                    if (type == decrypt_error)
                        return FATAL_ERROR;

                    /* Reset error if we got an alert level in ret */
                    if (ret > 0)
                        ret = 0;
                    break;

                default:
                    WOLFSSL_ERROR(UNKNOWN_RECORD_TYPE);
                    return UNKNOWN_RECORD_TYPE;
            }

            ssl->options.processReply = doProcessInit;

            /* input exhausted */
            if (ssl->buffers.inputBuffer.idx >= ssl->buffers.inputBuffer.length) {
                /* Shrink input buffer when we successfully finish record
                 * processing */
                if ((ret == 0) && ssl->buffers.inputBuffer.dynamicFlag)
                    ShrinkInputBuffer(ssl, NO_FORCED_FREE);
                return ret;
            }
            /* more messages per record */
            else if ((ssl->buffers.inputBuffer.idx - ssl->curStartIdx)
                    < ssl->curSize) {
                WOLFSSL_MSG("More messages in record");

                ssl->options.processReply = runProcessingOneMessage;

                if (IsEncryptionOn(ssl, 0)) {
                    WOLFSSL_MSG("Bundled encrypted messages, remove middle pad");
            #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
                    if (ssl->options.startedETMRead) {
                        word32 digestSz = MacSize(ssl);
                        if (ssl->buffers.inputBuffer.idx >=
                                                   ssl->keys->padSz + digestSz) {
                            ssl->buffers.inputBuffer.idx -=
                                                     ssl->keys->padSz + digestSz;
                        }
                        else {
                            WOLFSSL_MSG("\tmiddle padding error");
                            WOLFSSL_ERROR_VERBOSE(FATAL_ERROR);
                            return FATAL_ERROR;
                        }
                    }
                    else
             #endif
                    {
                        if (ssl->buffers.inputBuffer.idx >= ssl->keys->padSz) {
                            ssl->buffers.inputBuffer.idx -= ssl->keys->padSz;
                        }
                        else {
                            WOLFSSL_MSG("\tmiddle padding error");
                            WOLFSSL_ERROR_VERBOSE(FATAL_ERROR);
                            return FATAL_ERROR;
                        }
                    }
                }
            }
            /* more records */
            else {
                WOLFSSL_MSG("More records in input");
            }
#ifdef WOLFSSL_ASYNC_CRYPT
            /* We are setup to read next message/record but we had an error
             * (probably WC_PENDING_E) so return that so it can be handled
             * by higher layers. */
            if (ret != 0)
                return ret;
#endif
#if defined(WOLFSSL_DTLS13) || defined(HAVE_SECURE_RENEGOTIATION)
            /* Signal to user that we have application data ready to read */
            if (ret == APP_DATA_READY)
                return ret;
#endif
            /* It is safe to shrink the input buffer here now. local vars will
             * be reset to the new starting value. */
            if (ret == 0 && ssl->buffers.inputBuffer.dynamicFlag)
                ShrinkInputBuffer(ssl, NO_FORCED_FREE);
            continue;
        default:
            WOLFSSL_MSG("Bad process input state, programming error");
            WOLFSSL_ERROR_VERBOSE(INPUT_CASE_ERROR);
            return INPUT_CASE_ERROR;
        }
    }
}

#if !defined(WOLFSSL_NO_TLS12) || !defined(NO_OLD_TLS) || \
             (defined(WOLFSSL_TLS13) && defined(WOLFSSL_TLS13_MIDDLEBOX_COMPAT))
int SendChangeCipher(WOLFSSL* ssl)
{
    byte              *output;
    int                sendSz = RECORD_HEADER_SZ + ENUM_LEN;
    int                idx    = RECORD_HEADER_SZ;
    int                ret;

    /* are we in scr */
    if (IsEncryptionOn(ssl, 1) && ssl->options.handShakeDone) {
        sendSz += MAX_MSG_EXTRA;
    }
    /* Set this in case CheckAvailableSize returns a WANT_WRITE so that state
     * is not advanced yet */
    ssl->options.buildingMsg = 1;

    /* check for available size */
    if ((ret = CheckAvailableSize(ssl, sendSz)) != 0)
        return ret;

    /* get output buffer */
    output = GetOutputBuffer(ssl);

    AddRecordHeader(output, 1, change_cipher_spec, ssl, CUR_ORDER);

    output[idx] = 1;             /* turn it on */

    if (IsEncryptionOn(ssl, 1) && ssl->options.handShakeDone) {
        byte input[ENUM_LEN];
        int  inputSz = ENUM_LEN;

        input[0] = 1;  /* turn it on */
        sendSz = BuildMessage(ssl, output, sendSz, input, inputSz,
                              change_cipher_spec, 0, 0, 0, CUR_ORDER);
        if (sendSz < 0) {
            return sendSz;
        }
    }
    ssl->buffers.outputBuffer.length += sendSz;

#ifdef WOLFSSL_TLS13
    if (!ssl->options.tls1_3)
#endif
    {
        /* setup encrypt keys, hard set here since known */
        ssl->encryptSetup = 1;
        ssl->keys->sequence_number_hi      = 0;
        ssl->keys->sequence_number_lo      = 0;

    #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
        ssl->options.startedETMWrite = ssl->options.encThenMac;
    #endif
    }

    ssl->options.buildingMsg = 0;

    if (ssl->options.groupMessages)
        return 0;
    else
        return SendBuffered(ssl);
}
#endif

/* Build SSL Message, encrypted */
int BuildMessage(WOLFSSL* ssl, byte* output, int outSz, const byte* input,
             int inSz, int type, int hashOutput, int sizeOnly, int asyncOkay,
             int epochOrder)
{
#ifndef WOLFSSL_NO_TLS12
    int ret;
    BuildMsgArgs* args;
    BuildMsgArgs  lcl_args;
#endif
    ALIGN16 byte staticIvBuffer[MAX_IV_SZ];

    WOLFSSL_ENTER("BuildMessage");

    if (ssl == NULL) {
        return BAD_FUNC_ARG;
    }
    /* catch mistaken sizeOnly parameter */
    if (!sizeOnly && (output == NULL || input == NULL) ) {
        return BAD_FUNC_ARG;
    }
    if (sizeOnly && (output || input) ) {
        return BAD_FUNC_ARG;
    }

    (void)epochOrder;

#ifndef NO_TLS
#if defined(WOLFSSL_NO_TLS12) && defined(WOLFSSL_TLS13)
    return BuildTls13Message(ssl, output, outSz, input, inSz, type,
                                               hashOutput, sizeOnly, asyncOkay);
#else
    {
        args = &lcl_args;
    }

    /* Reset state */
    {
        ret = 0;
        ssl->options.buildMsgState = BUILD_MSG_BEGIN;
        XMEMSET(args, 0, sizeof(BuildMsgArgs));

        args->sz = RECORD_HEADER_SZ + inSz;
        args->idx  = RECORD_HEADER_SZ;
        args->headerSz = RECORD_HEADER_SZ;
    }

    switch (ssl->options.buildMsgState) {
        case BUILD_MSG_BEGIN:
        {
            ssl->options.buildMsgState = BUILD_MSG_SIZE;
        }
        FALL_THROUGH;
        case BUILD_MSG_SIZE:
        {
            args->digestSz = WC_SHA256_DIGEST_SIZE;
        #ifdef HAVE_TRUNCATED_HMAC
            if (ssl->truncated_hmac)
                args->digestSz = min(TRUNCATED_HMAC_SZ, args->digestSz);
        #endif
            args->sz += args->digestSz;

        #ifndef WOLFSSL_AEAD_ONLY
            if (ssl->specs.cipher_type == (byte)block) {
                word32 blockSz = ssl->specs.block_size;

                if (blockSz == 0u) {
                    WOLFSSL_MSG("Invalid block size with block cipher type");
                    ERROR_OUT(BAD_STATE_E, exit_buildmsg);
                }

                if (ssl->options.tls1_1) {
                    args->ivSz = blockSz;
                    args->sz  += args->ivSz;

                    if (args->ivSz > (byte)MAX_IV_SZ)
                        ERROR_OUT(BUFFER_E, exit_buildmsg);
                }
                args->sz += 1;       /* pad byte */
            #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
                if (ssl->options.startedETMWrite) {
                    args->pad = (args->sz - args->headerSz -
                                                      args->digestSz) % blockSz;
                }
                else
            #endif
                {
                    args->pad = (args->sz - args->headerSz) % blockSz;
                }
                if (args->pad != 0u)
                    args->pad = blockSz - args->pad;
                args->sz += args->pad;
            }
        #endif /* WOLFSSL_AEAD_ONLY */

        #ifdef HAVE_AEAD
            if (ssl->specs.cipher_type == aead) {
                if (ssl->specs.bulk_cipher_algorithm != wolfssl_chacha)
                    args->ivSz = AESGCM_EXP_IV_SZ;

                args->sz += (args->ivSz + ssl->specs.aead_mac_size - args->digestSz);
            }
        #endif

            /* done with size calculations */
            if (sizeOnly)
                goto exit_buildmsg;

            if (args->sz > (word32)outSz) {
                WOLFSSL_MSG("Oops, want to write past output buffer size");
                ERROR_OUT(BUFFER_E, exit_buildmsg);
            }

            if (args->ivSz > 0u) {
                args->iv = &staticIvBuffer[0];
            }

                if (ssl->options.handShakeState != (byte)HANDSHAKE_DONE) {
                    /* use stored IV for reducing peak heap usage */
                    args->iv = ssl->arrays->csRandom + RAN_LEN + RAN_LEN;
                }
                else {
                    if (ssl->rng == NULL) {
                        ssl->rng = (WC_RNG*)XMALLOC(sizeof(WC_RNG), ssl->heap,DYNAMIC_TYPE_RNG);
                        if (ssl->rng == NULL) {
                            WOLFSSL_MSG("RNG Memory error");
                                        goto exit_buildmsg;
                        }
                        XMEMSET(ssl->rng, 0, sizeof(WC_RNG));
                        ssl->options.weOwnRng = 1;

                        if ( (ret = wc_InitRng_ex(ssl->rng, ssl->heap, INVALID_DEVID)) != 0) {
                            WOLFSSL_MSG("RNG Init error");
                                        goto exit_buildmsg;
                        }
                    }
                    ret = wc_RNG_GenerateBlock(ssl->rng, args->iv, args->ivSz);
                    if (ret != 0)
                        goto exit_buildmsg;
                }
#if !defined(NO_PUBLIC_GCM_SET_IV) && \
    ((defined(HAVE_FIPS) || defined(HAVE_SELFTEST)) && \
    (!defined(HAVE_FIPS_VERSION) || (HAVE_FIPS_VERSION < 2)) && \
    defined(HAVE_AEAD))
            if (ssl->specs.cipher_type == aead) {
                if (ssl->specs.bulk_cipher_algorithm != wolfssl_chacha)
                    XMEMCPY(args->iv, ssl->keys->aead_exp_IV, AESGCM_EXP_IV_SZ);
            }
#endif
 
            /* move plan text data out of record headers way */
            if (ssl->buffers.outputBuffer.dynamicFlag ==
                (byte)WOLFSSL_EXTERNAL_IO_BUFFER) {
                XMEMMOVE(output + args->headerSz + args->ivSz, input, inSz);
            }
            
            args->size = (word16)(args->sz - args->headerSz);    /* include mac and digest */
            AddRecordHeader(output, args->size, (byte)type, ssl, epochOrder);

            /* write to output */
            if (args->ivSz > 0u) {
                XMEMCPY(output + args->idx, args->iv,
                                        min(args->ivSz, MAX_IV_SZ));
                args->idx += min(args->ivSz, MAX_IV_SZ);
            }
            if (ssl->buffers.outputBuffer.dynamicFlag !=
                    (byte)WOLFSSL_EXTERNAL_IO_BUFFER) {
                XMEMCPY(output + args->idx, input, inSz);
            }
            args->idx += inSz;

            ssl->options.buildMsgState = BUILD_MSG_HASH;
        }
        FALL_THROUGH;
        case BUILD_MSG_HASH:
        {
            /* done with size calculations */
            if (sizeOnly)
                goto exit_buildmsg;

            if (type == handshake && hashOutput) {
                ret = wc_Sha256Update(&ssl->hsHashes->hashSha256, output + RECORD_HEADER_SZ + args->ivSz,
                        args->headerSz + inSz - RECORD_HEADER_SZ);
                if (ret != 0)
                    goto exit_buildmsg;
            }
        #ifndef WOLFSSL_AEAD_ONLY
            if (ssl->specs.cipher_type == (byte)block) {
                word32 tmpIdx;
                word32 i;

            #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
                if (ssl->options.startedETMWrite)
                    tmpIdx = args->idx;
                else
            #endif
                    tmpIdx = args->idx + args->digestSz;

                for (i = 0; i <= args->pad; i++)
                    output[tmpIdx++] = (byte)args->pad; /* pad byte gets pad value */
            }
        #endif

            ssl->options.buildMsgState = BUILD_MSG_VERIFY_MAC;
        }
        FALL_THROUGH;
        case BUILD_MSG_VERIFY_MAC:
        {
            /* done with size calculations */
            if (sizeOnly)
                goto exit_buildmsg;

            /* User Record Layer Callback handling */
        #ifndef WOLFSSL_AEAD_ONLY
            if (ssl->specs.cipher_type != (byte)aead
            #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
                                               && !ssl->options.startedETMWrite
            #endif
                ) {
            #ifdef HAVE_TRUNCATED_HMAC
                if (ssl->truncated_hmac &&
                                        ssl->specs.hash_size > args->digestSz) {
                #ifdef WOLFSSL_SMALL_STACK
                    byte* hmac;
                #else
                    byte  hmac[WC_MAX_DIGEST_SIZE];
                #endif

                #ifdef WOLFSSL_SMALL_STACK
                    hmac = (byte*)XMALLOC(WC_MAX_DIGEST_SIZE, ssl->heap,
                                                           DYNAMIC_TYPE_DIGEST);
                    if (hmac == NULL)
                        ERROR_OUT(MEMORY_E, exit_buildmsg);
                #endif

                    ret = ssl->hmac(ssl, hmac,
                                     output + args->headerSz + args->ivSz, (word32)inSz,
                                     -1, type, 0, epochOrder);
                    XMEMCPY(output + args->idx, hmac, args->digestSz);

                #ifdef WOLFSSL_SMALL_STACK
                    XFREE(hmac, ssl->heap, DYNAMIC_TYPE_DIGEST);
                #endif
                }
                else
            #endif
                {
#if defined(WOLFSSL_RENESAS_FSPSM_TLS) || \
        defined(WOLFSSL_RENESAS_TSIP_TLS)
                    ret = ssl->hmac(ssl, output + args->idx, output +
                                args->headerSz + args->ivSz, (word32)inSz, -1, type, 0, epochOrder);
#else
                    ret = TLS_hmac(ssl, output + args->idx, output +
                                args->headerSz + args->ivSz, (word32)inSz, -1, type, 0, epochOrder);
#endif
                }
            }
        #endif /* WOLFSSL_AEAD_ONLY */
            if (ret != 0)
                goto exit_buildmsg;

            ssl->options.buildMsgState = BUILD_MSG_ENCRYPT;
        }
        FALL_THROUGH;
        case BUILD_MSG_ENCRYPT:
        {
            /* done with size calculations */
            if (sizeOnly)
                goto exit_buildmsg;

            {
    #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
            if (ssl->options.startedETMWrite) {
                ret = Encrypt(ssl, output + args->headerSz,
                                          output + args->headerSz,
                                          (word16)(args->size - args->digestSz),
                                          asyncOkay);
            }
            else
    #endif
                {
                    Aes *aes;
                    byte   *key;
                    byte   *iv;

                    aes = (Aes*)XMALLOC(sizeof(Aes), ssl->heap, DYNAMIC_TYPE_CIPHER);
                    if (aes == NULL) {
                        return MEMORY_E;
                    }

                    if (wc_AesInit(aes, ssl->heap, INVALID_DEVID) != 0) {
                        WOLFSSL_MSG("AesInit failed in SetKeys");
                        return ASYNC_INIT_E;
                    }

                    //If server side this should be keys->server_write_key
                    key = ssl->keys->keys + WC_MAX_DIGEST_SIZE + WC_MAX_DIGEST_SIZE;
                    iv  = key + MAX_SYM_KEY_SIZE + MAX_SYM_KEY_SIZE;

                    ret = wc_AesSetKey(aes, key, 16, iv,
                                   AES_ENCRYPTION);
                    if (ret != 0) {
                        XFREE(aes, NULL, DYNAMIC_TYPE_CIPHER);
                        return ret;
                    }

                    ret = wc_AesCbcEncrypt(aes, output + args->headerSz,
                            output + args->headerSz, args->size);
                    XMEMCPY(iv, aes->reg, AES_BLOCK_SIZE);
                    wc_AesFree(aes);
                    XFREE(aes, ssl->heap, DYNAMIC_TYPE_CIPHER);
                }
            }

            if (ret != 0) {
            #ifdef WOLFSSL_ASYNC_CRYPT
                if (ret != WC_PENDING_E)
            #endif
                {
                    /* Zeroize plaintext. */
            #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
                    if (ssl->options.startedETMWrite) {
                        ForceZero(output + args->headerSz,
                            (word16)(args->size - args->digestSz));
                    }
                    else
            #endif
                    {
#ifndef WOLFSSL_NO_FORCE_ZERO
                        ForceZero(output + args->headerSz, (word16)args->size);
#endif
                    }
                }
                goto exit_buildmsg;
            }
            ssl->options.buildMsgState = BUILD_MSG_ENCRYPTED_VERIFY_MAC;
        }
        FALL_THROUGH;
        case BUILD_MSG_ENCRYPTED_VERIFY_MAC:
        {
            /* done with size calculations */
            if (sizeOnly)
                goto exit_buildmsg;

        #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
            if (ssl->options.startedETMWrite) {
                WOLFSSL_MSG("Calculate MAC of Encrypted Data");

            #ifdef HAVE_TRUNCATED_HMAC
                if (ssl->truncated_hmac &&
                                        ssl->specs.hash_size > args->digestSz) {
                #ifdef WOLFSSL_SMALL_STACK
                    byte* hmac = NULL;
                #else
                    byte  hmac[WC_MAX_DIGEST_SIZE];
                #endif

                #ifdef WOLFSSL_SMALL_STACK
                    hmac = (byte*)XMALLOC(WC_MAX_DIGEST_SIZE, ssl->heap,
                                                           DYNAMIC_TYPE_DIGEST);
                    if (hmac == NULL)
                        ERROR_OUT(MEMORY_E, exit_buildmsg);
                #endif

                    ret = ssl->hmac(ssl, hmac, output + args->headerSz,
                                    args->ivSz + inSz + args->pad + 1, -1, type,
                                    0, epochOrder);
                    XMEMCPY(output + args->idx + args->pad + 1, hmac,
                                                                args->digestSz);

                #ifdef WOLFSSL_SMALL_STACK
                    XFREE(hmac, ssl->heap, DYNAMIC_TYPE_DIGEST);
                #endif
                }
                else
            #endif
                {
                    ret = ssl->hmac(ssl, output + args->idx + args->pad + 1,
                                    output + args->headerSz,
                                    args->ivSz + inSz + args->pad + 1, -1, type,
                                    0, epochOrder);
                }
            }
        #endif /* HAVE_ENCRYPT_THEN_MAC && !WOLFSSL_AEAD_ONLY */
        }
        FALL_THROUGH;
        default:
            break;
    }

exit_buildmsg:

    WOLFSSL_LEAVE("BuildMessage", ret);

#ifdef WOLFSSL_ASYNC_CRYPT
    if (ret == WC_PENDING_E) {
        return ret;
    }
#endif

    /* make sure build message state is reset */
    ssl->options.buildMsgState = BUILD_MSG_BEGIN;

    #ifdef WOLFSSL_DTLS
        if (ret == 0 && ssl->options.dtls && !sizeOnly)
            DtlsSEQIncrement(ssl, epochOrder);
    #endif

    /* return sz on success */
    if (ret == 0) {
        ret = (int)args->sz;
    }
    else {
        WOLFSSL_ERROR_VERBOSE(ret);
    }
    
    return ret;
#endif /* !WOLFSSL_NO_TLS12 */
#else
    (void)outSz;
    (void)inSz;
    (void)type;
    (void)hashOutput;
    (void)asyncOkay;
    return NOT_COMPILED_IN;
#endif /* NO_TLS */

}

#ifndef WOLFSSL_NO_TLS12

int SendFinished(WOLFSSL* ssl)
{
    int              sendSz,
                     finishedSz = ssl->options.tls ? TLS_FINISHED_SZ :
                                                     FINISHED_SZ;
    byte             input[FINISHED_SZ + 12];//DTLS_HANDSHAKE_HEADER_SZ];  /* max */
    byte            *output;
    Hashes*          hashes;
    int              ret;
    int              headerSz = HANDSHAKE_HEADER_SZ;
    int              outputSz;

    WOLFSSL_START(WC_FUNC_FINISHED_SEND);
    WOLFSSL_ENTER("SendFinished");

    /* check for available size */
    outputSz = sizeof(input) + MAX_MSG_EXTRA;

    /* Set this in case CheckAvailableSize returns a WANT_WRITE so that state
     * is not advanced yet */
    ssl->options.buildingMsg = 1;

    if ((ret = CheckAvailableSize(ssl, outputSz)) != 0)
        return ret;

    /* get output buffer */
    output = GetOutputBuffer(ssl);
    AddHandShakeHeader(input, finishedSz, 0, finishedSz, finished, ssl);

    /* make finished hashes */
    hashes = (Hashes*)&input[headerSz];
    ret = BuildTlsFinished(ssl, hashes, ssl->options.side == (byte)WOLFSSL_CLIENT_END ?
                                                 0 : 1);
    if (ret != 0) return ret;

#ifdef WOLFSSL_HAVE_TLS_UNIQUE
    if (ssl->options.side == WOLFSSL_CLIENT_END) {
        XMEMCPY(ssl->clientFinished,
                hashes, TLS_FINISHED_SZ);
        ssl->clientFinished_len = TLS_FINISHED_SZ;
    }
    else {
        XMEMCPY(ssl->serverFinished,
                hashes, TLS_FINISHED_SZ);
        ssl->serverFinished_len = TLS_FINISHED_SZ;
    }
#endif

    sendSz = BuildMessage(ssl, output, outputSz, input, headerSz + finishedSz,
                                                 handshake, 1, 0, 0, CUR_ORDER);
    if (sendSz < 0)
        return BUILD_MSG_ERROR;

    if (!ssl->options.resuming) {
    #ifndef WOLFSSL_NO_SESSION_RESUMPTION
        SetupSession(ssl);
    #endif
        if (ssl->options.side == (byte)WOLFSSL_SERVER_END) {
            ssl->options.handShakeState = HANDSHAKE_DONE;
            ssl->options.handShakeDone  = 1;
        }
    }
    else {
        if (ssl->options.side == (byte)WOLFSSL_CLIENT_END) {
            ssl->options.handShakeState = HANDSHAKE_DONE;
            ssl->options.handShakeDone  = 1;
        }
    }
    
    ssl->buffers.outputBuffer.length += sendSz;

    ret = SendBuffered(ssl);

    ssl->options.buildingMsg = 0;

    WOLFSSL_LEAVE("SendFinished", ret);
    WOLFSSL_END(WC_FUNC_FINISHED_SEND);

    return ret;
}
#endif /* WOLFSSL_NO_TLS12 */

int cipherExtraData(WOLFSSL* ssl)
{
    int cipherExtra;
    /* Cipher data that may be added by BuildMessage */
    /* There is always an IV (expect for chacha). For AEAD ciphers,
     * there is the authentication tag (aead_mac_size). For block
     * ciphers we have the hash_size MAC on the message, and one
     * block size for possible padding. */
    if (ssl->specs.cipher_type == (byte)aead) {
        cipherExtra = ssl->specs.aead_mac_size;
        /* CHACHA does not have an explicit IV. */
        if (ssl->specs.bulk_cipher_algorithm != (byte)wolfssl_chacha) {
            cipherExtra += AESGCM_EXP_IV_SZ;
        }
    }
    else {
        cipherExtra = AES_IV_SIZE + ssl->specs.block_size +
            WC_SHA256_DIGEST_SIZE;
    }
    /* Sanity check so we don't ever return negative. */
    return cipherExtra > 0 ? cipherExtra : 0;
}

/**
 * ssl_in_handshake():
 * Invoked in wolfSSL_read/wolfSSL_write to check if wolfSSL_negotiate() is
 * needed in the handshake.
 *
 * In TLSv1.2 negotiate until the end of the handshake, unless:
 * 1 in SCR and sending data or
 * 2 in SCR and we have plain data ready
 * Early data logic may bypass this logic in TLSv1.3 when appropriate.
 */
static int ssl_in_handshake(WOLFSSL *ssl, int send)
{
    if (ssl->options.handShakeState != (byte)HANDSHAKE_DONE)
        return 1;

    if (ssl->options.side == (byte)WOLFSSL_CLIENT_END) {
        if (IsAtLeastTLSv1_3(ssl->version))
            return ssl->options.connectState < FINISHED_DONE;
        if (IsAtLeastTLSv1_2(ssl))
            return ssl->options.connectState < SECOND_REPLY_DONE;
        return 0;
    }

    return 0;
}

int SendData(WOLFSSL* ssl, const void* data, int sz)
{
    int sent = 0,  /* plainText size */
        sendSz,
        ret;
#if defined(WOLFSSL_EARLY_DATA) && defined(WOLFSSL_EARLY_DATA_GROUP)
    int groupMsgs = 0;
#endif

    if (ssl->error == WANT_WRITE
    #ifdef WOLFSSL_ASYNC_CRYPT
        || ssl->error == WC_PENDING_E
    #endif
    ) {
        ssl->error = 0;
    }

    /* don't allow write after decrypt or mac error */
    if (ssl->error == VERIFY_MAC_ERROR || ssl->error == DECRYPT_ERROR) {
        /* For DTLS allow these possible errors and allow the session
            to continue despite them */
        {
            WOLFSSL_MSG("Not allowing write after decrypt or mac error");
            return WOLFSSL_FATAL_ERROR;
        }
    }

    if (ssl_in_handshake(ssl, 1)) {
        return BAD_FUNC_ARG;
    }

    /* last time system socket output buffer was full, try again to send */
    if (ssl->buffers.outputBuffer.length > 0u
    #if defined(WOLFSSL_EARLY_DATA) && defined(WOLFSSL_EARLY_DATA_GROUP)
        && !groupMsgs
    #endif
        ) {
        WOLFSSL_MSG("output buffer was full, trying to send again");
        if ( (ssl->error = SendBuffered(ssl)) < 0) {
            WOLFSSL_ERROR(ssl->error);
            if (ssl->error == SOCKET_ERROR_E && (ssl->options.connReset ||
                                                 ssl->options.isClosed)) {
                ssl->error = SOCKET_PEER_CLOSED_E;
                WOLFSSL_ERROR(ssl->error);
                return 0;  /* peer reset or closed */
            }
            return ssl->error;
        }
        else {
            /* advance sent to previous sent + plain size just sent */
            sent = ssl->buffers.prevSent + ssl->buffers.plainSz;
            WOLFSSL_MSG("sent write buffered data");

            if (sent > sz) {
                WOLFSSL_MSG("error: write() after WANT_WRITE with short size");
                return ssl->error = BAD_FUNC_ARG;
            }
        }
    }

    ret = RetrySendAlert(ssl);
    if (ret != 0) {
        ssl->error = ret;
        return WOLFSSL_FATAL_ERROR;
    }

    for (;;) {
        byte* out;
        byte* sendBuffer = (byte*)data + sent;  /* may switch on comp */
        int   buffSz;                           /* may switch on comp */
        int   outputSz;

        {
            buffSz = wolfSSL_GetMaxFragSize(ssl, sz - sent);

        }

        if (sent == sz) break;

        outputSz = buffSz + COMP_EXTRA + DTLS_RECORD_HEADER_SZ;
        if (IsEncryptionOn(ssl, 1) || ssl->options.tls1_3)
            outputSz += cipherExtraData(ssl);

        /* check for available size */
        if ((ret = CheckAvailableSize(ssl, outputSz)) != 0)
            return ssl->error = ret;

        /* get output buffer */
        out = GetOutputBuffer(ssl);

        if (!ssl->options.tls1_3) {
            sendSz = BuildMessage(ssl, out, outputSz, sendBuffer, buffSz,
                                  application_data, 0, 0, 1, CUR_ORDER);
        }
        else {
#ifdef WOLFSSL_TLS13
            sendSz = BuildTls13Message(ssl, out, outputSz, sendBuffer, buffSz,
                                       application_data, 0, 0, 1);
#else
            sendSz = BUFFER_ERROR;
#endif
        }
        if (sendSz < 0) {
            return BUILD_MSG_ERROR;
        }

        ssl->buffers.outputBuffer.length += sendSz;

        if ( (ssl->error = SendBuffered(ssl)) < 0) {
            WOLFSSL_ERROR(ssl->error);
            /* store for next call if WANT_WRITE or user embedSend() that
               doesn't present like WANT_WRITE */
            ssl->buffers.plainSz  = buffSz;
            ssl->buffers.prevSent = sent;
            if (ssl->error == SOCKET_ERROR_E && (ssl->options.connReset ||
                                                 ssl->options.isClosed)) {
                ssl->error = SOCKET_PEER_CLOSED_E;
                WOLFSSL_ERROR(ssl->error);
                return 0;  /* peer reset or closed */
            }
            return ssl->error;
        }

        sent += buffSz;

        /* only one message per attempt */
        if (ssl->options.partialWrite == 1u) {
            WOLFSSL_MSG("Partial Write on, only sending one record");
            break;
        }
    }

    return sent;
}

/* process input data */
int ReceiveData(WOLFSSL* ssl, byte** output, int sz, int peek)
{
    int size;

    WOLFSSL_ENTER("ReceiveData");

    /* reset error state */
    if (ssl->error == WANT_READ || ssl->error == WOLFSSL_ERROR_WANT_READ) {
        ssl->error = 0;
    }

    if (ssl->error != 0 && ssl->error != WANT_WRITE) {
        WOLFSSL_MSG("User calling wolfSSL_read in error state, not allowed");
        return ssl->error;
    }

    {
        if (ssl_in_handshake(ssl, 0)) {
            return BAD_FUNC_ARG;
        }
    }

    while (ssl->buffers.clearOutputBuffer.length == 0u) {
        if ( (ssl->error = ProcessReply(ssl)) < 0) {
            if (ssl->error == ZERO_RETURN) {
                WOLFSSL_MSG("Zero return, no more data coming");
                return 0; /* no more data coming */
            }
            if (ssl->error == SOCKET_ERROR_E) {
                if (ssl->options.connReset || ssl->options.isClosed) {
                    WOLFSSL_MSG("Peer reset or closed, connection done");
                    ssl->error = SOCKET_PEER_CLOSED_E;
                    WOLFSSL_ERROR(ssl->error);
                    return 0; /* peer reset or closed */
                }
            }
            WOLFSSL_ERROR(ssl->error);
            return ssl->error;
        }
    }

    size = min(sz, (int)ssl->buffers.clearOutputBuffer.length);

    if (ssl->buffers.inputBuffer.dynamicFlag == (byte)WOLFSSL_EXTERNAL_IO_BUFFER) {
       *output = ssl->buffers.clearOutputBuffer.buffer;
    }
    else {
        XMEMCPY(*output, ssl->buffers.clearOutputBuffer.buffer, size);
    }

    if (peek == 0) {
        ssl->buffers.clearOutputBuffer.length -= size;
        ssl->buffers.clearOutputBuffer.buffer += size;
    }

    if (ssl->buffers.inputBuffer.dynamicFlag)
       ShrinkInputBuffer(ssl, NO_FORCED_FREE);

    WOLFSSL_LEAVE("ReceiveData()", size);
    return size;
}

static int SendAlert_ex(WOLFSSL* ssl, int severity, int type)
{
    byte input[ALERT_SIZE];
    byte *output;
    int  sendSz;
    int  ret;
    int  outputSz;
    int  dtlsExtra = 0;

    WOLFSSL_ENTER("SendAlert");

    ssl->pendingAlert.code = type;
    ssl->pendingAlert.level = severity;

    /* check for available size */
    outputSz = ALERT_SIZE + MAX_MSG_EXTRA + dtlsExtra;
    if ((ret = CheckAvailableSize(ssl, outputSz)) != 0) {
        return ret;
    }

    /* Check output buffer */
    if (ssl->buffers.outputBuffer.buffer == NULL)
        return BUFFER_E;

    /* get output buffer */
    output = GetOutputBuffer(ssl);
    input[0] = (byte)severity;
    input[1] = (byte)type;
    ssl->alert_history.last_tx.code = type;
    ssl->alert_history.last_tx.level = severity;
    if (severity == alert_fatal) {
        ssl->options.isClosed = 1;  /* Don't send close_notify */
    }

    /* send encrypted alert if encryption is on - can be a rehandshake over
     * an existing encrypted channel.
     * TLS 1.3 encrypts handshake packets after the ServerHello
     */
    if (IsEncryptionOn(ssl, 1)) {
        sendSz = BuildMessage(ssl, output, outputSz, input, ALERT_SIZE, alert,
                                                                       0, 0, 0, CUR_ORDER);
    }
    else {
            {
                AddRecordHeader(output, ALERT_SIZE, alert, ssl, CUR_ORDER);
            }

        output += RECORD_HEADER_SZ;
        XMEMCPY(output, input, ALERT_SIZE);

        sendSz = RECORD_HEADER_SZ + ALERT_SIZE;
    }
    if (sendSz < 0)
        return BUILD_MSG_ERROR;

    ssl->buffers.outputBuffer.length += sendSz;

    ret = SendBuffered(ssl);

    ssl->pendingAlert.code = 0;
    ssl->pendingAlert.level = alert_none;

    WOLFSSL_LEAVE("SendAlert", ret);

    return ret;
}

int RetrySendAlert(WOLFSSL* ssl)
{
    int type;
    int severity;
    WOLFSSL_ENTER("RetrySendAlert");

    if (ssl == NULL) {
        return BAD_FUNC_ARG;
    }

    type = ssl->pendingAlert.code;
    severity = ssl->pendingAlert.level;

    if (severity == alert_none)
        return 0;

    ssl->pendingAlert.code = 0;
    ssl->pendingAlert.level = alert_none;

    return SendAlert_ex(ssl, severity, type);
}

/* send alert message */
int SendAlert(WOLFSSL* ssl, int severity, int type)
{
    WOLFSSL_ENTER("SendAlert");

    if (ssl == NULL) {
        return BAD_FUNC_ARG;
    }

    if (ssl->pendingAlert.level != alert_none) {
        int ret = RetrySendAlert(ssl);
        if (ret != 0) {
            if (ssl->pendingAlert.level == alert_none ||
                    (ssl->pendingAlert.level != alert_fatal &&
                            severity == alert_fatal)) {
                /* Store current alert if pendingAlert is empty or if current
                 * is fatal and previous was not */
                ssl->pendingAlert.code = type;
                ssl->pendingAlert.level = severity;
            }
            return ret;
        }
    }

    return SendAlert_ex(ssl, severity, type);
}

/* client only parts */
#ifndef NO_WOLFSSL_CLIENT

#ifndef WOLFSSL_NO_TLS12

    /* handle generation of client_hello (1) */
    int SendClientHello(WOLFSSL* ssl)
    {
        byte              *output;
        word32             length, idx = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ;
        int                sendSz;
        int                idSz;
        int                ret;
        word32             extSz = 0;
#ifndef WOLFSSL_LEANPSK_STATIC
        const Suites*      suites;
#endif

        if (ssl == NULL) {
            return BAD_FUNC_ARG;
        }

#ifdef WOLFSSL_NO_SESSION_RESUMPTION
        idSz = 0;
#else
        idSz = ssl->options.resuming ? ssl->session->sessionIDSz : 0;
#endif

        WOLFSSL_START(WC_FUNC_CLIENT_HELLO_SEND);
        WOLFSSL_ENTER("SendClientHello");

#ifndef WOLFSSL_LEANPSK_STATIC
        suites = WOLFSSL_SUITES(ssl);

        if (suites == NULL) {
            WOLFSSL_MSG("Bad suites pointer in SendClientHello");
            return SUITES_ERROR;
        }
#endif

        length = VERSION_SZ + RAN_LEN
               + (word32)idSz + ENUM_LEN
               + SUITE_LEN
               + COMP_LEN + ENUM_LEN;
        length += 2;  /* suiteSz only one cipher suite */

#ifdef HAVE_TLS_EXTENSIONS
        /* auto populate extensions supported unless user defined */
        if ((ret = TLSX_PopulateExtensions(ssl, 0)) != 0)
            return ret;
        extSz = 0;
        ret = TLSX_GetRequestSize(ssl, client_hello, &extSz);
        if (ret != 0)
            return ret;
        length += extSz;
#else
#ifdef HAVE_EXTENDED_MASTER
        if (ssl->options.haveEMS)
            extSz += HELLO_EXT_SZ;
#endif
        if (extSz != 0u)
            length += extSz + HELLO_EXT_SZ_SZ;
#endif
        sendSz = (int)length + HANDSHAKE_HEADER_SZ + RECORD_HEADER_SZ;

        if (ssl->arrays == NULL) {
            return BAD_FUNC_ARG;
        }

        if (IsEncryptionOn(ssl, 1))
            sendSz += MAX_MSG_EXTRA;

        /* Set this in case CheckAvailableSize returns a WANT_WRITE so that state
         * is not advanced yet */
        ssl->options.buildingMsg = 1;

        /* check for available size */
        if ((ret = CheckAvailableSize(ssl, sendSz)) != 0)
            return ret;

        /* get output buffer */
        output = GetOutputBuffer(ssl);

        AddHeaders(output, length, client_hello, ssl);

        /* client hello, first version */
        output[idx++] = ssl->version.major;
        output[idx++] = ssl->version.minor;
        ssl->chVersion = ssl->version;  /* store in case changed */

        /* then random */
        if (ssl->options.connectState == CONNECT_BEGIN) {
            XMEMCPY(output + idx, ssl->arrays->csRandom, RAN_LEN);
        }
        idx += RAN_LEN;

        /* then session id */
        output[idx++] = (byte)idSz;
        
#ifndef WOLFSSL_NO_SESSION_RESUMPTION
        if (idSz) {
            XMEMCPY(output + idx, ssl->session->sessionID,
                                                      ssl->session->sessionIDSz);
            idx += ssl->session->sessionIDSz;
        }
#endif

        {
            /* then cipher suites */
            c16toa(2, output + idx);
            idx += OPAQUE16_LEN;
            output[idx] = ssl->options.cipherSuite0; idx++;
            output[idx] = ssl->options.cipherSuite; idx++;
        }

        /* last, compression */
        output[idx++] = COMP_LEN;
        if (ssl->options.usingCompression)
            output[idx++] = ZLIB_COMPRESSION;
        else
            output[idx++] = NO_COMPRESSION;

        if (IsEncryptionOn(ssl, 1)) {
            byte* input;
            int   inputSz = (int)idx; /* build msg adds rec hdr */
            int   recordHeaderSz = RECORD_HEADER_SZ;

            inputSz -= recordHeaderSz;
            input = (byte*)XMALLOC(inputSz, ssl->heap, DYNAMIC_TYPE_IN_BUFFER);
            if (input == NULL)
                return MEMORY_E;

            XMEMCPY(input, output + recordHeaderSz, inputSz);
            sendSz = BuildMessage(ssl, output, sendSz, input, inputSz,
                                  handshake, 1, 0, 0, CUR_ORDER);
            XFREE(input, ssl->heap, DYNAMIC_TYPE_IN_BUFFER);

            if (sendSz < 0)
                return sendSz;
        } else {
            ret = wc_Sha256Update(&ssl->hsHashes->hashSha256, output + RECORD_HEADER_SZ,
                        sendSz - RECORD_HEADER_SZ);
            if (ret != 0)
                return ret;
        }

        ssl->options.clientState = CLIENT_HELLO_COMPLETE;

        ssl->options.buildingMsg = 0;

        ssl->buffers.outputBuffer.length += sendSz;

        ret = SendBuffered(ssl);

        WOLFSSL_LEAVE("SendClientHello", ret);
        WOLFSSL_END(WC_FUNC_CLIENT_HELLO_SEND);

        return ret;
    }

    /* Check the version in the received message is valid and set protocol
     * version to use.
     *
     * ssl  The SSL/TLS object.
     * pv   The protocol version from the packet.
     * returns 0 on success, otherwise failure.
     */
    int CheckVersion(WOLFSSL *ssl, ProtocolVersion pv)
    {
        byte lowerVersion, higherVersion;

        {
            if (pv.major != SSLv3_MAJOR) {
                WOLFSSL_ERROR_VERBOSE(VERSION_ERROR);
                return VERSION_ERROR;
            }
            lowerVersion = pv.minor < ssl->version.minor;
            higherVersion = pv.minor > ssl->version.minor;
        }

        if (higherVersion) {
            WOLFSSL_MSG("Server using higher version, fatal error");
            WOLFSSL_ERROR_VERBOSE(VERSION_ERROR);
            return VERSION_ERROR;
        }
        if (lowerVersion) {
            WOLFSSL_MSG("server using lower version");
#ifndef WOLFSSL_NO_DOWNGRADE
            /* Check for downgrade attack. */
            if (!ssl->options.downgrade) {
                WOLFSSL_MSG("\tno downgrade allowed, fatal error");
                WOLFSSL_ERROR_VERBOSE(VERSION_ERROR);
                return VERSION_ERROR;
            }

            if ((!ssl->options.dtls && pv.minor < ssl->options.minDowngrade) ||
                (ssl->options.dtls && pv.minor > ssl->options.minDowngrade)) {
                WOLFSSL_MSG("\tversion below minimum allowed, fatal error");
                WOLFSSL_ERROR_VERBOSE(VERSION_ERROR);
                return VERSION_ERROR;
            }


            /* Checks made - OK to downgrade. */
                ssl->version.minor = pv.minor;
                switch(pv.minor) {
                case TLSv1_2_MINOR:
                    WOLFSSL_MSG("\tdowngrading to TLSv1.2");
                    break;
                default:
                    WOLFSSL_MSG("\tbad minor version");
                    WOLFSSL_ERROR_VERBOSE(VERSION_ERROR);
                    return VERSION_ERROR;
                }
#else
            WOLFSSL_ERROR_VERBOSE(VERSION_ERROR);
            return VERSION_ERROR;
#endif
        }

        /* check if option is set to not allow the current version
         * set from either wolfSSL_set_options or wolfSSL_CTX_set_options */
#ifndef WOLFSSL_NO_DOWNGRADE
        if (
#ifdef WOLFSSL_DTLS
            !ssl->options.dtls &&
#endif
            ssl->options.downgrade &&
            ssl->options.mask > 0) {

            if (ssl->version.minor == (byte)TLSv1_2_MINOR &&
               (ssl->options.mask & WOLFSSL_OP_NO_TLSv1_2) ==
                WOLFSSL_OP_NO_TLSv1_2) {
                WOLFSSL_MSG("\tOption set to not allow TLSv1.2, Downgrading");
                ssl->version.minor = TLSv1_1_MINOR;
            }


            if (ssl->version.minor == (byte)TLSv1_MINOR &&
                (ssl->options.mask & WOLFSSL_OP_NO_TLSv1) ==
                WOLFSSL_OP_NO_TLSv1) {
                WOLFSSL_MSG("\tOption set to not allow TLSv1, Downgrading");
                ssl->options.tls    = 0;
                ssl->options.tls1_1 = 0;
                ssl->version.minor = SSLv3_MINOR;
            }

            if (ssl->version.minor == (byte)SSLv3_MINOR &&
                (ssl->options.mask & WOLFSSL_OP_NO_SSLv3) ==
                WOLFSSL_OP_NO_SSLv3) {
                WOLFSSL_MSG("\tError, option set to not allow SSLv3");
                WOLFSSL_ERROR_VERBOSE(VERSION_ERROR);
                return VERSION_ERROR;
            }

            if (ssl->version.minor < ssl->options.minDowngrade) {
                WOLFSSL_MSG("\tversion below minimum allowed, fatal error");
                WOLFSSL_ERROR_VERBOSE(VERSION_ERROR);
                return VERSION_ERROR;
            }
        }
#endif
        return 0;
    }

    /* handle processing of server_hello (2) */
    int DoServerHello(WOLFSSL* ssl, const byte* input, word32* inOutIdx,
                      word32 helloSz)
    {
        byte            cs0;   /* cipher suite bytes 0, 1 */
        byte            cs1;
        ProtocolVersion pv;
        byte            compression;
        word32          i = *inOutIdx;
        word32          begin = i;
        int             ret;

        WOLFSSL_START(WC_FUNC_SERVER_HELLO_DO);
        WOLFSSL_ENTER("DoServerHello");

        /* protocol version, random and session id length check */
        if (OPAQUE16_LEN + RAN_LEN + OPAQUE8_LEN > helloSz)
            return BUFFER_ERROR;

        /* protocol version */
        XMEMCPY(&pv, input + i, OPAQUE16_LEN);
        i += OPAQUE16_LEN;

        ret = CheckVersion(ssl, pv);
        if (ret != 0) {
            SendAlert(ssl, alert_fatal, wolfssl_alert_protocol_version);
            return ret;
        }

        /* random */
        XMEMCPY(ssl->arrays->csRandom + RAN_LEN, input + i, RAN_LEN);
        i += RAN_LEN;

        /* session id */
#ifndef WOLFSSL_NO_SESSION_RESUMPTION
        ssl->arrays->sessionIDSz = input[i++];

        if (ssl->arrays->sessionIDSz > ID_LEN) {
            WOLFSSL_MSG("Invalid session ID size");
            ssl->arrays->sessionIDSz = 0;
            return BUFFER_ERROR;
        }
        else if (ssl->arrays->sessionIDSz) {
            if ((i - begin) + ssl->arrays->sessionIDSz > helloSz)
                return BUFFER_ERROR;

            XMEMCPY(ssl->arrays->sessionID, input + i,
                                                      ssl->arrays->sessionIDSz);
            i += ssl->arrays->sessionIDSz;
            ssl->options.haveSessionId = 1;
        }
#else
        {
            byte idSz = input[i];
            i += 1 + idSz;
        }
#endif


        /* suite and compression */
        if ((i - begin) + OPAQUE16_LEN + OPAQUE8_LEN > helloSz)
            return BUFFER_ERROR;

        cs0 = input[i++];
        cs1 = input[i++];

        ssl->options.cipherSuite0 = cs0;
        ssl->options.cipherSuite  = cs1;

        compression = input[i++];

        if (compression != (byte)NO_COMPRESSION && !ssl->options.usingCompression) {
            WOLFSSL_MSG("Server forcing compression w/o support");
            WOLFSSL_ERROR_VERBOSE(COMPRESSION_ERROR);
            return COMPRESSION_ERROR;
        }

        if (compression != (byte)ZLIB_COMPRESSION && ssl->options.usingCompression) {
            WOLFSSL_MSG("Server refused compression, turning off");
            ssl->options.usingCompression = 0;  /* turn off if server refused */
        }

        *inOutIdx = i;

#ifdef HAVE_TLS_EXTENSIONS
        if ( (i - begin) < helloSz) {
            if (TLSX_SupportExtensions(ssl)) {
                word16 totalExtSz;

                if ((i - begin) + OPAQUE16_LEN > helloSz)
                    return BUFFER_ERROR;

                ato16(&input[i], &totalExtSz);
                i += OPAQUE16_LEN;

                if ((i - begin) + totalExtSz > helloSz)
                    return BUFFER_ERROR;

                if ((ret = TLSX_Parse(ssl, (byte *) input + i, totalExtSz,
                                                           server_hello, NULL)))
                    return ret;

                i += totalExtSz;
                *inOutIdx = i;
            }
            else
                *inOutIdx = begin + helloSz; /* skip extensions */
        }
        else
            ssl->options.haveEMS = 0; /* If no extensions, no EMS */
#else
        {
            byte pendingEMS = 0;

            if ( (i - begin) < helloSz) {
                int allowExt = 0;

                if (ssl->version.major == SSLv3_MAJOR &&
                    ssl->version.minor >= TLSv1_MINOR) {

                    allowExt = 1;
                }
                
                if (allowExt) {
                    word16 totalExtSz;

                    if ((i - begin) + OPAQUE16_LEN > helloSz)
                        return BUFFER_ERROR;

                    ato16(&input[i], &totalExtSz);
                    i += OPAQUE16_LEN;

                    if ((i - begin) + totalExtSz > helloSz)
                        return BUFFER_ERROR;

                    while (totalExtSz) {
                        word16 extId, extSz;

                        if (OPAQUE16_LEN + OPAQUE16_LEN > totalExtSz)
                            return BUFFER_ERROR;

                        ato16(&input[i], &extId);
                        i += OPAQUE16_LEN;
                        ato16(&input[i], &extSz);
                        i += OPAQUE16_LEN;

                        if (OPAQUE16_LEN + OPAQUE16_LEN + extSz > totalExtSz)
                            return BUFFER_ERROR;

                        if (extId == (word16)HELLO_EXT_EXTMS)
                            pendingEMS = 1;
                        else
                            i += extSz;

                        totalExtSz -= OPAQUE16_LEN + OPAQUE16_LEN + extSz;
                    }

                    *inOutIdx = i;
                }
                else
                    *inOutIdx = begin + helloSz; /* skip extensions */
            }

            if (!pendingEMS && ssl->options.haveEMS)
                ssl->options.haveEMS = 0;
        }
#endif

#if defined(WOLFSSL_HARDEN_TLS) && !defined(WOLFSSL_HARDEN_TLS_NO_SCR_CHECK)
        if (ssl->secure_renegotiation == NULL ||
                !ssl->secure_renegotiation->enabled) {
            /* If the server does not acknowledge the extension, the client
             * MUST generate a fatal handshake_failure alert prior to
             * terminating the connection.
             * https://www.rfc-editor.org/rfc/rfc9325#name-renegotiation-in-tls-12 */
            WOLFSSL_MSG("ServerHello did not contain SCR extension");
            return SECURE_RENEGOTIATION_E;
        }
#endif

        ssl->options.serverState = SERVER_HELLO_COMPLETE;

        if (IsEncryptionOn(ssl, 0)) {
            *inOutIdx += ssl->keys->padSz;
        #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
            if (ssl->options.startedETMWrite &&
                                              ssl->specs.cipher_type == block) {
                *inOutIdx += MacSize(ssl);
            }
        #endif
        }
        ret = CompleteServerHello(ssl);

        WOLFSSL_LEAVE("DoServerHello", ret);
        WOLFSSL_END(WC_FUNC_SERVER_HELLO_DO);

        return ret;
    }

    int CompleteServerHello(WOLFSSL* ssl)
    {
        int ret;
        {
//            if (DSH_CheckSessionId(ssl)) {
//                if (SetCipherSpecs(ssl) == 0) {
//                    XMEMCPY(ssl->arrays->masterSecret,
//                            ssl->session->masterSecret, SECRET_LEN);
//                    ret = DeriveTlsKeys(ssl);
//                    /* SERVER: peer auth based on session secret. */
//                    ssl->options.peerAuthGood = (ret == 0);
//                    ssl->options.serverState = SERVER_HELLODONE_COMPLETE;
//
//                    return ret;
//                }
//                else {
//                    WOLFSSL_MSG("Unsupported cipher suite, DoServerHello");
//                    WOLFSSL_ERROR_VERBOSE(UNSUPPORTED_SUITE);
//                    return UNSUPPORTED_SUITE;
//                }
//            }
//            else
            {
                WOLFSSL_MSG("Server denied resumption attempt");
                ssl->options.resuming = 0; /* server denied resumption try */
            }
        }
        return SetCipherSpecs(ssl);
    }

#endif /* !WOLFSSL_NO_TLS12 */

#ifndef WOLFSSL_NO_TLS12

/* Persistable DoServerKeyExchange arguments */
typedef struct DskeArgs {
    byte*  output; /* not allocated */
    word32 idx;
    word32 begin;
    word16 sigSz;
} DskeArgs;

/* handle processing of server_key_exchange (12) */
static int DoServerKeyExchange(WOLFSSL* ssl, const byte* input,
                               word32* inOutIdx, word32 size)
{
    int ret = 0;
    DskeArgs  args[1];

    (void)input;
    (void)size;

    WOLFSSL_START(WC_FUNC_SERVER_KEY_EXCHANGE_DO);
    WOLFSSL_ENTER("DoServerKeyExchange");

    {
        /* Reset state */
        ret = 0;
        ssl->options.asyncState = TLS_ASYNC_BEGIN;
        XMEMSET(args, 0, sizeof(DskeArgs));
        args->idx = *inOutIdx;
        args->begin = *inOutIdx;
        ssl->options.peerSigAlgo = ssl->specs.sig_algo;
        ssl->options.peerHashAlgo = sha_mac;
    }

    switch(ssl->options.asyncState)
    {
        case TLS_ASYNC_BEGIN:
        {
            switch(ssl->specs.kea)
            {
            #ifndef NO_PSK
                case psk_kea:
                {
                    int srvHintLen;
                    word16 length;

                    if ((args->idx - args->begin) + OPAQUE16_LEN > size) {
                        ERROR_OUT(BUFFER_ERROR, exit_dske);
                    }

                    ato16(input + args->idx, &length);
                    args->idx += OPAQUE16_LEN;

                    if ((args->idx - args->begin) + length > size) {
                        ERROR_OUT(BUFFER_ERROR, exit_dske);
                    }

                    /* get PSK server hint from the wire */
                    srvHintLen = (int)min(length, MAX_PSK_ID_LEN);
                    XMEMCPY(ssl->arrays->server_hint, input + args->idx,
                                                                    srvHintLen);
                    ssl->arrays->server_hint[srvHintLen] = '\0'; /* null term */
                    args->idx += length;
                    break;
                }
            #endif /* !NO_PSK */
                default:
                    ret = BAD_KEA_TYPE_E;
            } /* switch(ssl->specs.kea) */

            /* Check for error */
            if (ret != 0) {
                goto exit_dske;
            }

#ifdef WOLFSSL_LEANPSK
            ssl->options.asyncState = TLS_ASYNC_FINALIZE;
#else
            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_BUILD;
#endif
        } /* case TLS_ASYNC_BEGIN */
        FALL_THROUGH;
     
        case TLS_ASYNC_FINALIZE:
        {
            if (IsEncryptionOn(ssl, 0)) {
                args->idx += ssl->keys->padSz;
            #if defined(HAVE_ENCRYPT_THEN_MAC) && !defined(WOLFSSL_AEAD_ONLY)
                if (ssl->options.startedETMRead)
                    args->idx += MacSize(ssl);
            #endif
            }

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_END;
        } /* case TLS_ASYNC_FINALIZE */
        FALL_THROUGH;

        case TLS_ASYNC_END:
        {
            /* return index */
            *inOutIdx = args->idx;

            ssl->options.serverState = SERVER_KEYEXCHANGE_COMPLETE;
            break;
        }
        default:
            ret = INPUT_CASE_ERROR;
    } /* switch(ssl->options.asyncState) */

exit_dske:

    WOLFSSL_LEAVE("DoServerKeyExchange", ret);
    WOLFSSL_END(WC_FUNC_SERVER_KEY_EXCHANGE_DO);

    /* Final cleanup */
    FreeKeyExchange(ssl);

    if (ret != 0) {
        WOLFSSL_ERROR_VERBOSE(ret);
    }
    return ret;
}

typedef struct SckeArgs {
    byte*  output; /* not allocated */
    byte*  encSecret;
    byte*  input;
    word32 encSz;
    word32 length;
    int    sendSz;
    int    inputSz;
} SckeArgs;


/* handle generation client_key_exchange (16) */
int SendClientKeyExchange(WOLFSSL* ssl)
{
    int ret = 0;
    SckeArgs  args[1];
    byte encSecret[MAX_PSK_ID_LEN + NULL_TERM_LEN];

    WOLFSSL_START(WC_FUNC_CLIENT_KEY_EXCHANGE_SEND);
    WOLFSSL_ENTER("SendClientKeyExchange");


    {
        /* Reset state */
        ret = 0;
        ssl->options.asyncState = TLS_ASYNC_BEGIN;
        XMEMSET(args, 0, sizeof(SckeArgs));
        /* Set this in case CheckAvailableSize returns a WANT_WRITE so that state
         * is not advanced yet */
        ssl->options.buildingMsg = 1;
    }

    switch(ssl->options.asyncState)
    {
        case TLS_ASYNC_BEGIN:
        {
            switch (ssl->specs.kea) {
            #ifndef NO_PSK
                case psk_kea:
                    /* sanity check that PSK client callback has been set */
                    if (ssl->options.client_psk_cb == NULL) {
                        WOLFSSL_MSG("No client PSK callback set");
                        ERROR_OUT(PSK_KEY_ERROR, exit_scke);
                    }
                    break;
            #endif /* NO_PSK */
                default:
                    ret = BAD_KEA_TYPE_E;
            } /* switch(ssl->specs.kea) */

            /* Check for error */
            if (ret != 0) {
                goto exit_scke;
            }

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_BUILD;
        } /* case TLS_ASYNC_BEGIN */
        FALL_THROUGH;

        case TLS_ASYNC_BUILD:
        {
            args->encSz = MAX_ENCRYPT_SZ;
            if (ssl->arrays->preMasterSecret == NULL) {
                ssl->arrays->preMasterSz = ENCRYPT_LEN;
                ssl->arrays->preMasterSecret = (byte*)XMALLOC(ENCRYPT_LEN,
                                                ssl->heap, DYNAMIC_TYPE_SECRET);
                if (ssl->arrays->preMasterSecret == NULL) {
                    ERROR_OUT(-1005, exit_scke);
                }
                XMEMSET(ssl->arrays->preMasterSecret, 0, ENCRYPT_LEN);
            }

            switch(ssl->specs.kea)
            {
            #ifndef NO_PSK
                case psk_kea:
                {
                    int psk_keySz = 0;

                    byte* pms = ssl->arrays->preMasterSecret;
                    psk_keySz = ssl->options.client_psk_cb(ssl,
                        ssl->arrays->server_hint, (char*)&encSecret[0],
                        MAX_PSK_ID_LEN, pms + OPAQUE16_LEN + MAX_PSK_KEY_LEN +
                            OPAQUE16_LEN, MAX_PSK_KEY_LEN);
                    if (psk_keySz == 0 ||
                            (psk_keySz > (int)MAX_PSK_KEY_LEN &&
                        (int)psk_keySz != USE_HW_PSK)) {
                        ERROR_OUT(PSK_KEY_ERROR, exit_scke);
                    }

                    /* Ensure the buffer is null-terminated. */
                    encSecret[MAX_PSK_ID_LEN] = '\0';
                    args->encSz = (word32)XSTRLEN((char*)encSecret);
                    if (args->encSz > (word32)MAX_PSK_ID_LEN) {
                        ERROR_OUT(CLIENT_ID_ERROR, exit_scke);
                    }
                    ssl->options.peerAuthGood = 1;
                    if ((int)psk_keySz > 0) {
                        /* CLIENT: Pre-shared Key for peer authentication. */

                        /* make psk pre master secret */
                        /* length of key + length 0s + length of key + key */
                        c16toa((word16)psk_keySz, pms);
                        pms += OPAQUE16_LEN;
                        XMEMSET(pms, 0, psk_keySz);
                        pms += psk_keySz;
                        c16toa((word16)psk_keySz, pms);
                        pms += OPAQUE16_LEN;
                        if (psk_keySz < MAX_PSK_KEY_LEN) {
                            XMEMMOVE(pms, pms + (MAX_PSK_KEY_LEN - psk_keySz),
                                psk_keySz);
                        }
                        ssl->arrays->preMasterSz = (psk_keySz * 2)
                                                   + (2 * OPAQUE16_LEN);
#ifndef WOLFSSL_NO_FORCE_ZERO
                        ForceZero(ssl->arrays->psk_key, ssl->arrays->psk_keySz);
#endif
                    }
                    psk_keySz = 0; /* No further need */
                    break;
                }
            #endif /* !NO_PSK */
                default:
                    ret = BAD_KEA_TYPE_E;
            } /* switch(ssl->specs.kea) */

            /* Check for error */
            if (ret != 0) {
                goto exit_scke;
            }

            /* Advance state and proceed */
#ifdef WOLFSSL_LEANPSK
            ssl->options.asyncState = TLS_ASYNC_FINALIZE;
#else
            ssl->options.asyncState = TLS_ASYNC_DO;
#endif
        } /* case TLS_ASYNC_BUILD */
        FALL_THROUGH;
        case TLS_ASYNC_FINALIZE:
        {
            word32 tlsSz = 0;
            word32 idx = 0;

            if (ssl->options.tls || ssl->specs.kea == (byte)diffie_hellman_kea) {
                tlsSz = 2;
            }

            if (ssl->specs.kea == (byte)ecc_diffie_hellman_kea ||
                ssl->specs.kea == (byte)dhe_psk_kea ||
                ssl->specs.kea == (byte)ecdhe_psk_kea) { /* always off */
                tlsSz = 0;
            }

            idx = HANDSHAKE_HEADER_SZ + RECORD_HEADER_SZ;
            args->sendSz = (int)(args->encSz + tlsSz + idx);

            if (IsEncryptionOn(ssl, 1)) {
                args->sendSz += MAX_MSG_EXTRA;
            }

            /* check for available size */
            if ((ret = CheckAvailableSize(ssl, args->sendSz)) != 0)
                goto exit_scke;

            /* get output buffer */
            args->output = GetOutputBuffer(ssl);

            AddHeaders(args->output, args->encSz + tlsSz, client_key_exchange, ssl);

            if (tlsSz) {
                c16toa((word16)args->encSz, &args->output[idx]);
                idx += OPAQUE16_LEN;
            }
            XMEMCPY(args->output + idx, encSecret, args->encSz);
            idx += args->encSz;

            if (IsEncryptionOn(ssl, 1)) {
                int recordHeaderSz = RECORD_HEADER_SZ;

                args->inputSz = idx - recordHeaderSz; /* buildmsg adds rechdr */
                args->input = (byte*)XMALLOC(args->inputSz, ssl->heap,
                                                       DYNAMIC_TYPE_IN_BUFFER);
                if (args->input == NULL) {
                    ERROR_OUT(-1006, exit_scke);
                }

                XMEMCPY(args->input, args->output + recordHeaderSz,
                                                                args->inputSz);
            }

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_END;
        } /* case TLS_ASYNC_FINALIZE */
        FALL_THROUGH;

        case TLS_ASYNC_END:
        {
            if (IsEncryptionOn(ssl, 1)) {
                ret = BuildMessage(ssl, args->output, args->sendSz,
                            args->input, args->inputSz, handshake, 1, 0, 0, CUR_ORDER);
                XFREE(args->input, ssl->heap, DYNAMIC_TYPE_IN_BUFFER);
                args->input = NULL; /* make sure its not double free'd on cleanup */

                if (ret >= 0) {
                    args->sendSz = ret;
                    ret = 0;
                }
            }
            else {
                ret = wc_Sha256Update(&ssl->hsHashes->hashSha256, args->output + RECORD_HEADER_SZ,
                        args->sendSz - RECORD_HEADER_SZ);
            }

            if (ret != 0) {
                goto exit_scke;
            }
            
            ssl->buffers.outputBuffer.length += (word32)args->sendSz;

            if (!ssl->options.groupMessages) {
                ret = SendBuffered(ssl);
            }
            if (ret == 0 || ret == WANT_WRITE) {
                byte key_label   [KEY_LABEL_SZ + 1]    = "key expansion";
                int tmpRet = MakeMasterSecret(ssl, key_label);
                if (tmpRet != 0) {
                    ret = tmpRet;   /* save WANT_WRITE unless more serious */
                }
                ssl->options.clientState = CLIENT_KEYEXCHANGE_COMPLETE;
                ssl->options.buildingMsg = 0;
            }
            break;
        }
        default:
            ret = INPUT_CASE_ERROR;
    } /* switch(ssl->options.asyncState) */

exit_scke:

    WOLFSSL_LEAVE("SendClientKeyExchange", ret);
    WOLFSSL_END(WC_FUNC_CLIENT_KEY_EXCHANGE_SEND);

#ifndef WOLFSSL_NO_FORCE_ZERO
    /* No further need for PMS */
    if (ssl->arrays->preMasterSecret != NULL) {
        ForceZero(ssl->arrays->preMasterSecret, ssl->arrays->preMasterSz);
    }
#endif
    ssl->arrays->preMasterSz = 0;

    /* Final cleanup */
    if (args->input) {
        XFREE(args->input, ssl->heap, DYNAMIC_TYPE_IN_BUFFER);
        args->input = NULL;
    }
    FreeKeyExchange(ssl);

    if (ret != 0) {
        WOLFSSL_ERROR_VERBOSE(ret);
    }
    return ret;
}

#endif /* !WOLFSSL_NO_TLS12 */
#endif /* NO_WOLFSSL_CLIENT */


/**
 * Return the max fragment size. This is essentially the maximum
 * fragment_length available.
 * @param ssl         WOLFSSL object containing ciphersuite information.
 * @param maxFragment The amount of space we want to check is available. This
 *                    is only the fragment length WITHOUT the (D)TLS headers.
 * @return            Max fragment size
 */
int wolfSSL_GetMaxFragSize(WOLFSSL* ssl, int maxFragment)
{
    (void) ssl; /* Avoid compiler warnings */

    if (maxFragment > MAX_RECORD_SIZE) {
        maxFragment = MAX_RECORD_SIZE;
    }

    return maxFragment;
}

#undef ERROR_OUT

#endif /* WOLFCRYPT_ONLY */

#if 0
#ifndef WOLFCRYPT_ONLY
#define WOLFSSL_SSL_SESS_INCLUDED
#include "src/ssl_sess.c"
#endif
#endif

#ifndef WOLFCRYPT_ONLY

/* prevent multiple mutex initializations */
static volatile WOLFSSL_GLOBAL int initRefCount = 0;
/* init ref count mutex */
static WOLFSSL_GLOBAL wolfSSL_Mutex inits_count_mutex
    WOLFSSL_MUTEX_INITIALIZER_CLAUSE(inits_count_mutex);
#ifndef WOLFSSL_MUTEX_INITIALIZER
static WOLFSSL_GLOBAL int inits_count_mutex_valid = 0;
#endif

#ifdef HAVE_ENCRYPT_THEN_MAC
/**
 * Sets whether Encrypt-Then-MAC extension can be negotiated against context.
 * The default value comes from context.
 *
 * ctx  SSL/TLS context.
 * set  Whether to allow or not: 1 is allow and 0 is disallow.
 * returns WOLFSSL_SUCCESS
 */
int wolfSSL_AllowEncryptThenMac(WOLFSSL *ssl, int set)
{
    ssl->options.disallowEncThenMac = !set;
    return WOLFSSL_SUCCESS;
}
#endif


/* ran array is pregenerated random data, useful to reduce peak heap usage */
WOLFSSL* wolfSSL_new_leanpsk(WOLFSSL_METHOD* method,
        byte ciphersuite0, byte ciphersuite1, unsigned char* ran, int ranSz)
{
    WOLFSSL* ssl = NULL;
    int ret = 0;

    WOLFSSL_ENTER("wolfSSL_new_leanpsk");

    ssl = (WOLFSSL*) XMALLOC(sizeof(WOLFSSL), NULL, DYNAMIC_TYPE_SSL);
    if (ssl == NULL) {
        WOLFSSL_MSG_EX("ssl xmalloc failed to allocate %d bytes",
                        (int)sizeof(WOLFSSL));
    }
    else {
        ret = InitSSL_leanpsk(ssl, method, ciphersuite0, ciphersuite1, NULL);
        if (ret < 0) {
            WOLFSSL_MSG_EX("wolfSSL_new failed during InitSSL. err = %d", ret);
            FreeSSL(ssl, ssl->heap);
            ssl = NULL;
        }
        else if (ret == 0) {
            WOLFSSL_MSG("wolfSSL_new InitSSL success");
        }
        else {
            /* Only success (0) or negative values should ever be seen. */
            WOLFSSL_MSG_EX("WARNING: wolfSSL_new unexpected InitSSL return"
                           " value = %d", ret);
        } /* InitSSL check */
    } /* ssl XMALLOC success */

    if (ssl && ssl->arrays) {
        XMEMCPY(ssl->arrays->csRandom, ran, RAN_LEN); /* copy over client random */
        XMEMCPY(ssl->arrays->csRandom + RAN_LEN + RAN_LEN,
                ran + RAN_LEN, 16); /* copy over first IV */
    }
    
    WOLFSSL_LEAVE("wolfSSL_new InitSSL =", ret);
    (void)ret;

    return ssl;    
}


WOLFSSL_ABI
void wolfSSL_free(WOLFSSL* ssl)
{
    WOLFSSL_ENTER("wolfSSL_free");

    if (ssl) {
        WOLFSSL_MSG_EX("Free SSL: %p", (wc_ptr_t)ssl);
#ifndef WOLFSSL_LEANPSK_STATIC
        FreeSSL(ssl, ssl->ctx->heap);
#else
        FreeSSL(ssl, ssl->heap);
#endif
    }
    else {
        WOLFSSL_MSG("Free SSL: wolfSSL_free already null");
    }
    WOLFSSL_LEAVE("wolfSSL_free", 0);
}


static int wolfSSL_read_internal(WOLFSSL* ssl, void** data, int sz, int peek)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_read_internal");

    if (ssl == NULL || data == NULL || sz < 0)
        return BAD_FUNC_ARG;

    if (ssl->buffers.inputBuffer.dynamicFlag != (byte)WOLFSSL_EXTERNAL_IO_BUFFER
            && *data == NULL)
        return BAD_FUNC_ARG;

#ifdef WOLFSSL_QUIC
    if (WOLFSSL_IS_QUIC(ssl)) {
        WOLFSSL_MSG("SSL_read() on QUIC not allowed");
        return BAD_FUNC_ARG;
    }
#endif
#if defined(WOLFSSL_ERROR_CODE_OPENSSL) && defined(OPENSSL_EXTRA)
    /* This additional logic is meant to simulate following openSSL behavior:
     * After bidirectional SSL_shutdown complete, SSL_read returns 0 and
     * SSL_get_error_code returns SSL_ERROR_ZERO_RETURN.
     * This behavior is used to know the disconnect of the underlying
     * transport layer.
     *
     * In this logic, CBIORecv is called with a read size of 0 to check the
     * transport layer status. It also returns WOLFSSL_FAILURE so that
     * SSL_read does not return a positive number on failure.
     */

    /* make sure bidirectional TLS shutdown completes */
    if (ssl->error == WOLFSSL_ERROR_SYSCALL || ssl->options.shutdownDone) {
        /* ask the underlying transport the connection is closed */
        if (ssl->CBIORecv(ssl, (char*)data, 0, ssl->IOCB_ReadCtx) ==
                                            WOLFSSL_CBIO_ERR_CONN_CLOSE) {
            ssl->options.isClosed = 1;
            ssl->error = WOLFSSL_ERROR_ZERO_RETURN;
        }
        return WOLFSSL_FAILURE;
    }
#endif

#ifdef HAVE_WRITE_DUP
    if (ssl->dupWrite && ssl->dupSide == WRITE_DUP_SIDE) {
        WOLFSSL_MSG("Write dup side cannot read");
        return WRITE_DUP_READ_E;
    }
#endif

#ifdef HAVE_ERRNO_H
        errno = 0;
#endif

    ret = ReceiveData(ssl, (byte**)data, sz, peek);

    WOLFSSL_LEAVE("wolfSSL_read_internal", ret);

    if (ret < 0)
        return WOLFSSL_FATAL_ERROR;
    else
        return ret;
}

WOLFSSL_ABI
int wolfSSL_read(WOLFSSL* ssl, void* data, int sz)
{
    WOLFSSL_ENTER("wolfSSL_read");

    return wolfSSL_read_internal(ssl, &data, sz, FALSE);
}


WOLFSSL_ABI
int wolfSSL_write(WOLFSSL* ssl, const void* data, int sz)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_write");

    if (ssl == NULL || data == NULL || sz < 0)
        return BAD_FUNC_ARG;
    
    ret = SendData(ssl, data, sz);

    WOLFSSL_LEAVE("wolfSSL_write", ret);

    if (ret < 0)
        return WOLFSSL_FATAL_ERROR;
    else
        return ret;
}

/* does encryption and creation of TLS packet inline on buffer 'data'
 * can only handle one fragment at a time */
int wolfSSL_write_inline(WOLFSSL* ssl, const void* data, int dataSz, int maxSz)
{
    int ret;

    WOLFSSL_ENTER("wolfSSL_write_inline");

    if (ssl == NULL || data == NULL || dataSz < 0)
        return BAD_FUNC_ARG;

    /* only support a single TLS fragment */
    if (wolfSSL_GetMaxFragSize(ssl, dataSz) > dataSz)
        return BAD_FUNC_ARG;

    if (SetOutputBuffer(ssl, (byte*)data, maxSz) != WOLFSSL_SUCCESS) {
        return WOLFSSL_FAILURE;
    }

    ret = SendData(ssl, data, dataSz);

    WOLFSSL_LEAVE("wolfSSL_write_inline", ret);

    if (ret < 0)
        return WOLFSSL_FATAL_ERROR;
    else
        return ret;
}


/* 'buf' is the full buffer available when reading data from the peer
 * 'data' pointer gets pointed to the location of 'buf' where the data has been
 *        decrypted on success
 *
 * returns the amount of clear text data available on success and negative
 *         values on failure
 */
int  wolfSSL_read_inline(WOLFSSL* ssl, void* buf, int bufSz, void** data,
        int dataSz)
{
    int ret;
    
    WOLFSSL_ENTER("wolfSSL_read");

    #ifdef OPENSSL_EXTRA
    if (ssl == NULL) {
        return BAD_FUNC_ARG;
    }
    if (ssl->CBIS != NULL) {
        ssl->CBIS(ssl, SSL_CB_READ, WOLFSSL_SUCCESS);
        ssl->cbmode = SSL_CB_READ;
    }
    #endif

    /* ShrinkInputBuffer will reset the internal buffer back to the static
     * buffer and does not zero out or free 'buf' */
    if (SetInputBuffer(ssl, (byte*)buf, bufSz) != WOLFSSL_SUCCESS) {
        return WOLFSSL_FAILURE;
    }

    ret = ReceiveData(ssl, (byte**)data, dataSz, FALSE);
    if (ret < 0)
        return WOLFSSL_FATAL_ERROR;
    else
        return ret;
}

/* WOLFSSL_SUCCESS on ok */
WOLFSSL_ABI
int wolfSSL_shutdown(WOLFSSL* ssl)
{
    int  ret = WOLFSSL_FATAL_ERROR;
    WOLFSSL_ENTER("wolfSSL_shutdown");

    if (ssl == NULL)
        return WOLFSSL_FATAL_ERROR;

    if (ssl->options.quietShutdown) {
        WOLFSSL_MSG("quiet shutdown, no close notify sent");
        ret = WOLFSSL_SUCCESS;
    }
    else {
        /* try to send close notify, not an error if can't */
        if (!ssl->options.isClosed && !ssl->options.connReset &&
                                      !ssl->options.sentNotify) {
            ssl->error = SendAlert(ssl, alert_warning, close_notify);
            if (ssl->error < 0) {
                WOLFSSL_ERROR(ssl->error);
                return WOLFSSL_FATAL_ERROR;
            }
            ssl->options.sentNotify = 1;  /* don't send close_notify twice */
            if (ssl->options.closeNotify) {
                ret = WOLFSSL_SUCCESS;
                ssl->options.shutdownDone = 1;
            }
            else {
                ret = WOLFSSL_SHUTDOWN_NOT_DONE;
                WOLFSSL_LEAVE("wolfSSL_shutdown", ret);
                return ret;
            }
        }

#ifdef WOLFSSL_SHUTDOWNONCE
        if (ssl->options.isClosed || ssl->options.connReset) {
            /* Shutdown has already occurred.
             * Caller is free to ignore this error. */
            return SSL_SHUTDOWN_ALREADY_DONE_E;
        }
#endif

        /* call wolfSSL_shutdown again for bidirectional shutdown */
        if (ssl->options.sentNotify && !ssl->options.closeNotify) {
            ret = ProcessReply(ssl);
            if ((ret == ZERO_RETURN) || (ret == SOCKET_ERROR_E)) {
                /* simulate OpenSSL behavior */
                ssl->options.shutdownDone = 1;
                /* Clear error */
                ssl->error = WOLFSSL_ERROR_NONE;
                ret = WOLFSSL_SUCCESS;
            } else if (ret == MEMORY_E) {
                ret = WOLFSSL_FATAL_ERROR;
            } else if (ssl->error == WOLFSSL_ERROR_NONE) {
                ret = WOLFSSL_SHUTDOWN_NOT_DONE;
            } else {
                WOLFSSL_ERROR(ssl->error);
                ret = WOLFSSL_FATAL_ERROR;
            }
        }
    }

    WOLFSSL_LEAVE("wolfSSL_shutdown", ret);

    return ret;
}


WOLFSSL_ABI
int wolfSSL_get_error(WOLFSSL* ssl, int ret)
{
    WOLFSSL_ENTER("wolfSSL_get_error");

    if (ret > 0)
        return WOLFSSL_ERROR_NONE;
    if (ssl == NULL)
        return BAD_FUNC_ARG;

    WOLFSSL_LEAVE("wolfSSL_get_error", ssl->error);

    /* make sure converted types are handled in SetErrorString() too */
    if (ssl->error == WANT_READ)
        return WOLFSSL_ERROR_WANT_READ;         /* convert to OpenSSL type */
    else if (ssl->error == WANT_WRITE)
        return WOLFSSL_ERROR_WANT_WRITE;        /* convert to OpenSSL type */
    else if (ssl->error == ZERO_RETURN || ssl->options.shutdownDone)
        return WOLFSSL_ERROR_ZERO_RETURN;       /* convert to OpenSSL type */
    return ssl->error;
}

WOLFSSL_ABI
int wolfSSL_Init(void)
{
    int ret = WOLFSSL_SUCCESS;
    
    WOLFSSL_ENTER("wolfSSL_Init");

    if ((ret == WOLFSSL_SUCCESS) && (initRefCount == 0)) {
        /* Initialize crypto for use with TLS connection */

        if (wolfCrypt_Init() != 0) {
            WOLFSSL_MSG("Bad wolfCrypt Init");
            ret = WC_INIT_E;
        }
    }

    if (ret == WOLFSSL_SUCCESS) {
        initRefCount++;
    }
    else {
        initRefCount = 1; /* Force cleanup */
    }

    if (ret != WOLFSSL_SUCCESS) {
        (void)wolfSSL_Cleanup(); /* Ignore any error from cleanup */
    }

    return ret;
}

/* client only parts */
#ifndef NO_WOLFSSL_CLIENT

    /* please see note at top of README if you get an error from connect */
    WOLFSSL_ABI
    int wolfSSL_connect(WOLFSSL* ssl)
    {
    #if !(defined(WOLFSSL_NO_TLS12) && defined(NO_OLD_TLS) && \
          defined(WOLFSSL_TLS13))
        int neededState;
        byte advanceState;
    #endif
        int ret = 0;

        (void)ret;

        #ifdef HAVE_ERRNO_H
            errno = 0;
        #endif

        if (ssl == NULL)
            return BAD_FUNC_ARG;

    #if defined(WOLFSSL_NO_TLS12) && defined(NO_OLD_TLS) && \
        defined(WOLFSSL_TLS13)
        return wolfSSL_connect_TLSv13(ssl);
    #else

        WOLFSSL_MSG("TLS 1.2 or lower");
        WOLFSSL_ENTER("wolfSSL_connect");

        /* make sure this wolfSSL object has arrays and rng setup. Protects
         * case where the WOLFSSL object is reused via wolfSSL_clear() */
        if ((ret = ReinitSSL_leanpsk(ssl)) != 0) {
            return ret;
        }
        
        if (ssl->options.side != (byte)WOLFSSL_CLIENT_END) {
            ssl->error = SIDE_ERROR;
            WOLFSSL_ERROR(ssl->error);
            return WOLFSSL_FATAL_ERROR;
        }
        
        /* fragOffset is non-zero when sending fragments. On the last
         * fragment, fragOffset is zero again, and the state can be
         * advanced. */
        advanceState = ssl->fragOffset == 0u &&
            (ssl->options.connectState == CONNECT_BEGIN ||
             ssl->options.connectState == HELLO_AGAIN ||
             (ssl->options.connectState >= FIRST_REPLY_DONE &&
              ssl->options.connectState <= FIRST_REPLY_FOURTH));

        if (ssl->buffers.outputBuffer.length > 0u) {
            ret = SendBuffered(ssl);
            if (ret == 0) {
                if (ssl->fragOffset == 0u && !ssl->options.buildingMsg) {
                    if (advanceState) {
                        ssl->options.connectState++;
                        WOLFSSL_MSG("connect state: Advanced from last "
                                    "buffered fragment send");
                    #ifdef WOLFSSL_ASYNC_IO
                        /* Cleanup async */
                        FreeAsyncCtx(ssl, 0);
                    #endif
                    }
                }
                else {
                    WOLFSSL_MSG("connect state: "
                                "Not advanced, more fragments to send");
                }
            }
            else {
                ssl->error = ret;
                WOLFSSL_ERROR(ssl->error);
                return WOLFSSL_FATAL_ERROR;
            }
        }

        ret = RetrySendAlert(ssl);
        if (ret != 0) {
            ssl->error = ret;
            WOLFSSL_ERROR(ssl->error);
            return WOLFSSL_FATAL_ERROR;
        }

        switch (ssl->options.connectState) {

        case CONNECT_BEGIN :
            /* always send client hello first */
            if ( (ssl->error = SendClientHello(ssl)) != 0) {
                WOLFSSL_ERROR(ssl->error);
                return WOLFSSL_FATAL_ERROR;
            }
            ssl->options.connectState = CLIENT_HELLO_SENT;
            WOLFSSL_MSG("connect state: CLIENT_HELLO_SENT");
            FALL_THROUGH;

        case CLIENT_HELLO_SENT :
            neededState = ssl->options.resuming ? SERVER_FINISHED_COMPLETE :
                                          SERVER_HELLODONE_COMPLETE;
            /* get response */
            WOLFSSL_MSG("Server state up to needed state.");
            while (ssl->options.serverState < (byte)neededState) {
                WOLFSSL_MSG("Progressing server state...");
                WOLFSSL_MSG("ProcessReply...");
                if ( (ssl->error = ProcessReply(ssl)) < 0) {
                    WOLFSSL_ERROR(ssl->error);
                    return WOLFSSL_FATAL_ERROR;
                }
                /* if resumption failed, reset needed state */
                else if ((unsigned int)neededState == SERVER_FINISHED_COMPLETE) {
                    if (!ssl->options.resuming) {
                            neededState = SERVER_HELLODONE_COMPLETE;
                    }
                }
                WOLFSSL_MSG("ProcessReply done.");

            }

            ssl->options.connectState = HELLO_AGAIN;
            WOLFSSL_MSG("connect state: HELLO_AGAIN");
            FALL_THROUGH;

        case HELLO_AGAIN :
            ssl->options.connectState = HELLO_AGAIN_REPLY;
            WOLFSSL_MSG("connect state: HELLO_AGAIN_REPLY");
            FALL_THROUGH;

        case HELLO_AGAIN_REPLY :
            ssl->options.connectState = FIRST_REPLY_DONE;
            WOLFSSL_MSG("connect state: FIRST_REPLY_DONE");
            FALL_THROUGH;

        case FIRST_REPLY_DONE :
            if (ssl->options.certOnly)
                return WOLFSSL_SUCCESS;
            ssl->options.connectState = FIRST_REPLY_FIRST;
            WOLFSSL_MSG("connect state: FIRST_REPLY_FIRST");
            FALL_THROUGH;

        case FIRST_REPLY_FIRST :
            if (!ssl->options.resuming) {
                if ( (ssl->error = SendClientKeyExchange(ssl)) != 0) {
                    WOLFSSL_ERROR(ssl->error);
                    return WOLFSSL_FATAL_ERROR;
                }
                WOLFSSL_MSG("sent: client key exchange");
            }

            ssl->options.connectState = FIRST_REPLY_SECOND;
            FALL_THROUGH;

    #if !defined(WOLFSSL_NO_TLS12) || !defined(NO_OLD_TLS)
        case FIRST_REPLY_SECOND :
            /* CLIENT: Fail-safe for Server Authentication. */
            if (!ssl->options.peerAuthGood) {
                WOLFSSL_MSG("Server authentication did not happen");
                ssl->error = NO_PEER_VERIFY;
                return WOLFSSL_FATAL_ERROR;
            }

            #if !defined(NO_CERTS) && !defined(WOLFSSL_NO_CLIENT_AUTH)
                if (ssl->options.sendVerify) {
                    if ( (ssl->error = SendCertificateVerify(ssl)) != 0) {
                    #ifdef WOLFSSL_CHECK_ALERT_ON_ERR
                        ProcessReplyEx(ssl, 1); /* See if an alert was sent. */
                    #endif
                        WOLFSSL_ERROR(ssl->error);
                        return WOLFSSL_FATAL_ERROR;
                    }
                    WOLFSSL_MSG("sent: certificate verify");
                }
            #endif /* !NO_CERTS && !WOLFSSL_NO_CLIENT_AUTH */
            ssl->options.connectState = FIRST_REPLY_THIRD;
            WOLFSSL_MSG("connect state: FIRST_REPLY_THIRD");
            FALL_THROUGH;

        case FIRST_REPLY_THIRD :
            if ( (ssl->error = SendChangeCipher(ssl)) != 0) {
            #ifdef WOLFSSL_CHECK_ALERT_ON_ERR
                ProcessReplyEx(ssl, 1); /* See if an alert was sent. */
            #endif
                WOLFSSL_ERROR(ssl->error);
                return WOLFSSL_FATAL_ERROR;
            }
            WOLFSSL_MSG("sent: change cipher spec");
            ssl->options.connectState = FIRST_REPLY_FOURTH;
            WOLFSSL_MSG("connect state: FIRST_REPLY_FOURTH");
            FALL_THROUGH;

        case FIRST_REPLY_FOURTH :
            if ( (ssl->error = SendFinished(ssl)) != 0) {
            #ifdef WOLFSSL_CHECK_ALERT_ON_ERR
                ProcessReplyEx(ssl, 1); /* See if an alert was sent. */
            #endif
                WOLFSSL_ERROR(ssl->error);
                return WOLFSSL_FATAL_ERROR;
            }
            WOLFSSL_MSG("sent: finished");
            ssl->options.connectState = FINISHED_DONE;
            WOLFSSL_MSG("connect state: FINISHED_DONE");
            FALL_THROUGH;

        case FINISHED_DONE :
            /* get response */
            while (ssl->options.serverState < SERVER_FINISHED_COMPLETE) {
                if ( (ssl->error = ProcessReply(ssl)) < 0) {
                    WOLFSSL_ERROR(ssl->error);
                    return WOLFSSL_FATAL_ERROR;
                }
            }
            ssl->options.connectState = SECOND_REPLY_DONE;
            WOLFSSL_MSG("connect state: SECOND_REPLY_DONE");
            FALL_THROUGH;

        case SECOND_REPLY_DONE:
                if (!ssl->options.keepResources) {
                    FreeHandshakeResources(ssl);
                }

            ssl->error = 0; /* clear the error */

            WOLFSSL_LEAVE("wolfSSL_connect", WOLFSSL_SUCCESS);
            return WOLFSSL_SUCCESS;
    #endif /* !WOLFSSL_NO_TLS12 || !NO_OLD_TLS */

        default:
            WOLFSSL_MSG("Unknown connect state ERROR");
            return WOLFSSL_FATAL_ERROR; /* unknown connect state */
        }
    #endif /* !WOLFSSL_NO_TLS12 || !NO_OLD_TLS || !WOLFSSL_TLS13 */
    }

#endif /* NO_WOLFSSL_CLIENT */

WOLFSSL_ABI
int wolfSSL_Cleanup(void)
{
    int ret = WOLFSSL_SUCCESS; /* Only the first error will be returned */
    int release = 0;

    WOLFSSL_ENTER("wolfSSL_Cleanup");

    if (initRefCount > 0) {
        --initRefCount;
        if (initRefCount == 0)
            release = 1;
    }
    
    if (!release)
        return ret;

    if (wolfCrypt_Cleanup() != 0) {
        WOLFSSL_MSG("Error with wolfCrypt_Cleanup call");
        if (ret == WOLFSSL_SUCCESS)
            ret = WC_CLEANUP_E;
    }

#ifdef HAVE_GLOBAL_RNG
#ifndef WOLFSSL_MUTEX_INITIALIZER
    if ((globalRNGMutex_valid == 1) && (wc_FreeMutex(&globalRNGMutex) != 0)) {
        if (ret == WOLFSSL_SUCCESS)
            ret = BAD_MUTEX_E;
    }
    globalRNGMutex_valid = 0;
#endif /* !WOLFSSL_MUTEX_INITIALIZER */

    #if defined(OPENSSL_EXTRA) && defined(HAVE_HASHDRBG)
    wolfSSL_FIPS_drbg_free(gDrbgDefCtx);
    gDrbgDefCtx = NULL;
    #endif
#endif

#if defined(HAVE_EX_DATA) && \
   (defined(OPENSSL_ALL) || defined(WOLFSSL_NGINX) || \
    defined(WOLFSSL_HAPROXY) || defined(OPENSSL_EXTRA) || \
    defined(HAVE_LIGHTY)) || defined(HAVE_EX_DATA) || \
    defined(WOLFSSL_WPAS_SMALL)
    crypto_ex_cb_free(crypto_ex_cb_ctx_session);
    crypto_ex_cb_ctx_session = NULL;
#endif

#ifdef WOLFSSL_MEM_FAIL_COUNT
    wc_MemFailCount_Free();
#endif

    return ret;
}

#ifndef NO_PSK
    void wolfSSL_set_psk_client_callback(WOLFSSL* ssl,wc_psk_client_callback cb)
    {
        WOLFSSL_ENTER("wolfSSL_set_psk_client_callback");

        if (ssl == NULL)
            return;

        ssl->options.havePSK = 1;
        ssl->options.client_psk_cb = cb;
    }

    const char* wolfSSL_get_psk_identity_hint(const WOLFSSL* ssl)
    {
        WOLFSSL_ENTER("wolfSSL_get_psk_identity_hint");

        if (ssl == NULL || ssl->arrays == NULL)
            return NULL;

        return ssl->arrays->server_hint;
    }

    int wolfSSL_use_psk_identity_hint(WOLFSSL* ssl, const char* hint)
    {
        WOLFSSL_ENTER("wolfSSL_use_psk_identity_hint");

        if (ssl == NULL || ssl->arrays == NULL)
            return WOLFSSL_FAILURE;

        if (hint == 0)
            ssl->arrays->server_hint[0] = 0;
        else {
            XSTRNCPY(ssl->arrays->server_hint, hint,
                                            sizeof(ssl->arrays->server_hint)-1);
            ssl->arrays->server_hint[sizeof(ssl->arrays->server_hint)-1] = '\0';
        }
        return WOLFSSL_SUCCESS;
    }

    void* wolfSSL_get_psk_callback_ctx(WOLFSSL* ssl)
    {
        return ssl ? ssl->options.psk_ctx : NULL;
    }

    int wolfSSL_set_psk_callback_ctx(WOLFSSL* ssl, void* psk_ctx)
    {
        if (ssl == NULL)
            return WOLFSSL_FAILURE;
        ssl->options.psk_ctx = psk_ctx;
        return WOLFSSL_SUCCESS;
    }
#endif /* NO_PSK */

int wolfSSL_get_shutdown(const WOLFSSL* ssl)
{
    int isShutdown = 0;

    WOLFSSL_ENTER("wolfSSL_get_shutdown");

    if (ssl) {
        {
            /* in OpenSSL, WOLFSSL_SENT_SHUTDOWN = 1, when closeNotifySent   *
             * WOLFSSL_RECEIVED_SHUTDOWN = 2, from close notify or fatal err */
            if (ssl->options.sentNotify)
                isShutdown |= WOLFSSL_SENT_SHUTDOWN;
            if (ssl->options.closeNotify||ssl->options.connReset)
                isShutdown |= WOLFSSL_RECEIVED_SHUTDOWN;
        }

    }

    WOLFSSL_LEAVE("wolfSSL_get_shutdown", isShutdown);
    return isShutdown;
}

#ifdef WOLFSSL_LEANPSK_STATIC_IO
/* sets the IO callback to use for receives at WOLFSSL level */
void wolfSSL_SSLSetIORecv(WOLFSSL *ssl, CallbackIORecv CBIORecv)
{
    if (ssl) {
        ssl->CBIORecv = CBIORecv;
    #ifdef OPENSSL_EXTRA
        ssl->cbioFlag |= WOLFSSL_CBIO_RECV;
    #endif
    }
}


/* sets the IO callback to use for sends at WOLFSSL level */
void wolfSSL_SSLSetIOSend(WOLFSSL *ssl, CallbackIOSend CBIOSend)
{
    if (ssl) {
        ssl->CBIOSend = CBIOSend;
    #ifdef OPENSSL_EXTRA
        ssl->cbioFlag |= WOLFSSL_CBIO_SEND;
    #endif
    }
}
#endif

#endif /* !WOLFCRYPT_ONLY */

