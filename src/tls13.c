/* tls13.c
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.
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

#ifdef WOLFSSL_TLS13
#if defined(HAVE_SESSION_TICKET)
#include <sys/time.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifndef WOLFCRYPT_ONLY

#ifdef HAVE_ERRNO_H
    #include <errno.h>
#endif

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

#ifdef HAVE_NTRU
    #include "libntruencrypt/ntru_crypto.h"
#endif

#if defined(DEBUG_WOLFSSL) || defined(WOLFSSL_DEBUG) || \
    defined(CHACHA_AEAD_TEST) || defined(WOLFSSL_SESSION_EXPORT_DEBUG)
    #if defined(FREESCALE_MQX) || defined(FREESCALE_KSDK_MQX)
        #if MQX_USE_IO_OLD
            #include <fio.h>
        #else
            #include <nio.h>
        #endif
    #else
        #include <stdio.h>
    #endif
#endif

#ifdef __sun
    #include <sys/filio.h>
#endif

#ifndef TRUE
    #define TRUE  1
#endif
#ifndef FALSE
    #define FALSE 0
#endif

/* Set ret to error value and jump to label.
 *
 * err     The error value to set.
 * eLabel  The label to jump to.
 */
#define ERROR_OUT(err, eLabel) { ret = (err); goto eLabel; }


#ifndef WOLFSSL_HAVE_MIN
#define WOLFSSL_HAVE_MIN
/* Return the minimum of the two values.
 *
 * a  First value.
 * b  Second value.
 * returns the minimum of a and b.
 */
static INLINE word32 min(word32 a, word32 b)
{
    return a > b ? b : a;
}
#endif /* WOLFSSL_HAVE_MIN */

/* Convert 16-bit integer to opaque data.
 *
 * u16  Unsigned 16-bit value.
 * c    The buffer to write to.
 */
static INLINE void c16toa(word16 u16, byte* c)
{
    c[0] = (u16 >> 8) & 0xff;
    c[1] =  u16 & 0xff;
}

/* Convert 32-bit integer to opaque data.
 *
 * u32  Unsigned 32-bit value.
 * c    The buffer to write to.
 */
static INLINE void c32toa(word32 u32, byte* c)
{
    c[0] = (u32 >> 24) & 0xff;
    c[1] = (u32 >> 16) & 0xff;
    c[2] = (u32 >>  8) & 0xff;
    c[3] =  u32 & 0xff;
}


/* Convert 24-bit opaque data into a 32-bit value.
 *
 * u24  The opaque data holding a 24-bit integer.
 * u32  Unsigned 32-bit value.
 */
static INLINE void c24to32(const word24 u24, word32* u32)
{
    *u32 = (u24[0] << 16) | (u24[1] << 8) | u24[2];
}


/* Convert opaque data into a 16-bit value.
 *
 * c    The opaque data.
 * u16  Unsigned 16-bit value.
 */
static INLINE void ato16(const byte* c, word16* u16)
{
    *u16 = (word16) ((c[0] << 8) | (c[1]));
}

#ifndef NO_WOLFSSL_CLIENT
#ifdef HAVE_SESSION_TICKET
/* Convert opaque data into a 32-bit value.
 *
 * c    The opaque data.
 * u32  Unsigned 32-bit value.
 */
static INLINE void ato32(const byte* c, word32* u32)
{
    *u32 = (c[0] << 24) | (c[1] << 16) | (c[2] << 8) | c[3];
}
#endif
#endif

/* Extract data using HMAC, salt and input.
 * RFC 5869 - HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
 *
 * prk      The generated pseudorandom key.
 * salt     The salt.
 * saltLen  The length of the salt.
 * ikm      The input keying material.
 * ikmLen   The length of the input keying material.
 * mac      The type of digest to use.
 * returns 0 on success, otherwise failure.
 */
static int Tls13_HKDF_Extract(byte* prk, const byte* salt, int saltLen,
                             byte* ikm, int ikmLen, int mac)
{
    int ret;
    int hash;
    int len;

    switch (mac) {
        #ifndef NO_SHA256
        case sha256_mac:
            hash = SHA256;
            len = SHA256_DIGEST_SIZE;
            break;
        #endif

        #ifdef WOLFSSL_SHA384
        case sha384_mac:
            hash = SHA384;
            len = SHA384_DIGEST_SIZE;
            break;
        #endif

        #ifdef WOLFSSL_SHA512
        case sha512_mac:
            hash = SHA512;
            len = SHA512_DIGEST_SIZE;
            break;
        #endif

        default:
            return BAD_FUNC_ARG;
    }

    /* When length is 0 then use zeroed data of digest length. */
    if (ikmLen == 0) {
        ikmLen = len;
        XMEMSET(ikm, 0, len);
    }

#ifdef WOLFSSL_DEBUG_TLS
    WOLFSSL_MSG("Salt");
    WOLFSSL_BUFFER(salt, saltLen);
    WOLFSSL_MSG("IKM");
    WOLFSSL_BUFFER(ikm, ikmLen);
#endif

    ret = wc_HKDF_Extract(hash, salt, saltLen, ikm, ikmLen, prk);

#ifdef WOLFSSL_DEBUG_TLS
    WOLFSSL_MSG("PRK");
    WOLFSSL_BUFFER(prk, len);
#endif

    return ret;
}

/* Expand data using HMAC, salt and label and info.
 * TLS v1.3 defines this function.
 *
 * okm          The generated pseudorandom key - output key material.
 * prk          The salt - pseudo-random key.
 * prkLen       The length of the salt - pseudo-random key.
 * protocol     The TLS protocol label.
 * protocolLen  The length of the TLS protocol label.
 * info         The information to expand.
 * infoLen      The length of the information.
 * digest       The type of digest to use.
 * returns 0 on success, otherwise failure.
 */
static int HKDF_Expand_Label(byte* okm, word32 okmLen,
                             const byte* prk, word32 prkLen,
                             const byte* protocol, word32 protocolLen,
                             const byte* label, word32 labelLen,
                             const byte* info, word32 infoLen,
                             int digest)
{
    int    ret = 0;
    int    idx = 0;
    byte   data[MAX_HKDF_LABEL_SZ];

    /* Output length. */
    data[idx++] = okmLen >> 8;
    data[idx++] = okmLen;
    /* Length of protocol | label. */
    data[idx++] = protocolLen + labelLen;
    /* Protocol */
    XMEMCPY(&data[idx], protocol, protocolLen);
    idx += protocolLen;
    /* Label */
    XMEMCPY(&data[idx], label, labelLen);
    idx += labelLen;
    /* Length of hash of messages */
    data[idx++] = infoLen;
    /* Hash of messages */
    XMEMCPY(&data[idx], info, infoLen);
    idx += infoLen;

#ifdef WOLFSSL_DEBUG_TLS
    WOLFSSL_MSG("PRK");
    WOLFSSL_BUFFER(prk, prkLen);
    WOLFSSL_MSG("Info");
    WOLFSSL_BUFFER(data, idx);
#endif

    ret = wc_HKDF_Expand(digest, prk, prkLen, data, idx, okm, okmLen);

#ifdef WOLFSSL_DEBUG_TLS
    WOLFSSL_MSG("OKM");
    WOLFSSL_BUFFER(okm, okmLen);
#endif

    ForceZero(data, idx);

    return ret;
}

/* Size of the TLS v1.3 label use when deriving keys. */
#define TLS13_PROTOCOL_LABEL_SZ    9
/* The protocol label for TLS v1.3. */
static const byte tls13ProtocolLabel[TLS13_PROTOCOL_LABEL_SZ + 1] = "TLS 1.3, ";

/* Derive a key from a message.
 *
 * ssl        The SSL/TLS object.
 * output     The buffer to hold the derived key.
 * outputLen  The length of the derived key.
 * secret     The secret used to derive the key (HMAC secret).
 * label      The label used to distinguish the context.
 * labelLen   The length of the label.
 * msg        The message data to derive key from.
 * msgLen     The length of the message data to derive key from.
 * hashAlgo   The hash algorithm to use in the HMAC.
 * returns 0 on success, otherwise failure.
 */
static int DeriveKeyMsg(WOLFSSL* ssl, byte* output, int outputLen,
                        const byte* secret, const byte* label, word32 labelLen,
                        byte* msg, int msgLen, int hashAlgo)
{
    byte        hash[MAX_DIGEST_SIZE];
    Digest      digest;
    word32      hashSz = 0;
    const byte* protocol;
    word32      protocolLen;
    int         digestAlg;

    switch (hashAlgo) {
#ifndef NO_WOLFSSL_SHA256
        case sha256_mac:
            wc_InitSha256(&digest.sha256);
            wc_Sha256Update(&digest.sha256, msg, msgLen);
            wc_Sha256Final(&digest.sha256, hash);
            wc_Sha256Free(&digest.sha256);
            hashSz = SHA256_DIGEST_SIZE;
            digestAlg = SHA256;
            break;
#endif
#ifdef WOLFSSL_SHA384
        case sha384_mac:
            wc_InitSha384(&digest.sha384);
            wc_Sha384Update(&digest.sha384, msg, msgLen);
            wc_Sha384Final(&digest.sha384, hash);
            wc_Sha384Free(&digest.sha384);
            hashSz = SHA384_DIGEST_SIZE;
            digestAlg = SHA384;
            break;
#endif
#ifdef WOLFSSL_SHA512
        case sha512_mac:
            wc_InitSha512(&digest.sha512);
            wc_Sha512Update(&digest.sha512, msg, msgLen);
            wc_Sha512Final(&digest.sha512, hash);
            wc_Sha512Free(&digest.sha512);
            hashSz = SHA512_DIGEST_SIZE;
            digestAlg = SHA512;
            break;
#endif

        default:
            return BAD_FUNC_ARG;
    }

    switch (ssl->version.minor) {
        case TLSv1_3_MINOR:
            protocol = tls13ProtocolLabel;
            protocolLen = TLS13_PROTOCOL_LABEL_SZ;
            break;

        default:
            return VERSION_ERROR;
    }
    if (outputLen == -1)
        outputLen = hashSz;

    return HKDF_Expand_Label(output, outputLen, secret, hashSz,
                             protocol, protocolLen, label, labelLen,
                             hash, hashSz, digestAlg);
}

/* Derive a key.
 *
 * ssl          The SSL/TLS object.
 * output       The buffer to hold the derived key.
 * outputLen    The length of the derived key.
 * secret       The secret used to derive the key (HMAC secret).
 * label        The label used to distinguish the context.
 * labelLen     The length of the label.
 * hashAlgo     The hash algorithm to use in the HMAC.
 * includeMsgs  Whether to include a hash of the handshake messages so far.
 * returns 0 on success, otherwise failure.
 */
static int DeriveKey(WOLFSSL* ssl, byte* output, int outputLen,
                     const byte* secret, const byte* label, word32 labelLen,
                     int hashAlgo, int includeMsgs)
{
    int         ret = 0;
    byte        hash[MAX_DIGEST_SIZE];
    word32      hashSz = 0;
    word32      hashOutSz = 0;
    const byte* protocol;
    word32      protocolLen;
    int         digestAlg;

    switch (hashAlgo) {
        #ifndef NO_SHA256
            case sha256_mac:
                hashSz    = SHA256_DIGEST_SIZE;
                digestAlg = SHA256;
                if (includeMsgs)
                    ret = wc_Sha256GetHash(&ssl->hsHashes->hashSha256, hash);
            break;
        #endif

        #ifdef WOLFSSL_SHA384
            case sha384_mac:
                hashSz    = SHA384_DIGEST_SIZE;
                digestAlg = SHA384;
                if (includeMsgs)
                    ret = wc_Sha384GetHash(&ssl->hsHashes->hashSha384, hash);
            break;
        #endif

        #ifdef WOLFSSL_SHA512
            case sha512_mac:
                hashSz    = SHA512_DIGEST_SIZE;
                digestAlg = SHA512;
                if (includeMsgs)
                    ret = wc_Sha512GetHash(&ssl->hsHashes->hashSha512, hash);
            break;
        #endif

        default:
            ret = BAD_FUNC_ARG;
            break;
    }
    if (ret != 0)
        return ret;

    /* Only one protocol version defined at this time. */
    protocol = tls13ProtocolLabel;
    protocolLen = TLS13_PROTOCOL_LABEL_SZ;

    if (outputLen == -1)
        outputLen = hashSz;
    if (includeMsgs)
        hashOutSz = hashSz;

    return HKDF_Expand_Label(output, outputLen, secret, hashSz,
                             protocol, protocolLen, label, labelLen,
                             hash, hashOutSz, digestAlg);
}


#if defined(HAVE_SESSION_TICKET) && !defined(NO_PSK)
/* The length of the binder key label. */
#define BINDER_KEY_LABEL_SZ         23
/* The binder key label. */
static const byte binderKeyLabel[BINDER_KEY_LABEL_SZ + 1] =
    "external psk binder key";
/* Derive the binder key.
 *
 * ssl  The SSL/TLS object.
 * key  The derived key.
 * returns 0 on success, otherwise failure.
 */
static int DeriveBinderKey(WOLFSSL* ssl, byte* key)
{
    WOLFSSL_MSG("Derive Binder Key");
    return DeriveKeyMsg(ssl, key, -1, ssl->arrays->secret,
                        binderKeyLabel, BINDER_KEY_LABEL_SZ,
                        NULL, 0, ssl->specs.mac_algorithm);
}

/* The length of the binder key resume label. */
#define BINDER_KEY_RESUME_LABEL_SZ  25
/* The binder key resume label. */
static const byte binderKeyResumeLabel[BINDER_KEY_RESUME_LABEL_SZ + 1] =
    "resumption psk binder key";
/* Derive the binder resumption key.
 *
 * ssl  The SSL/TLS object.
 * key  The derived key.
 * returns 0 on success, otherwise failure.
 */
static int DeriveBinderKeyResume(WOLFSSL* ssl, byte* key)
{
    WOLFSSL_MSG("Derive Binder Key - Resumption");
    return DeriveKeyMsg(ssl, key, -1, ssl->arrays->secret,
                        binderKeyResumeLabel, BINDER_KEY_RESUME_LABEL_SZ,
                        NULL, 0, ssl->specs.mac_algorithm);
}
#endif

#ifdef TLS13_SUPPORTS_0RTT
/* The length of the early traffic label. */
#define EARLY_TRAFFIC_LABEL_SZ      27
/* The early traffic label. */
static const byte earlyTrafficLabel[EARLY_TRAFFIC_LABEL_SZ + 1] =
    "client early traffic secret";
/* Derive the early traffic key.
 *
 * ssl  The SSL/TLS object.
 * key  The derived key.
 * returns 0 on success, otherwise failure.
 */
static int DeriveEarlyTrafficSecret(WOLFSSL* ssl, byte* key)
{
    WOLFSSL_MSG("Derive Early Traffic Secret");
    return DeriveKey(ssl, key, -1, ssl->arrays->secret,
                     earlyTrafficLabel, EARLY_TRAFFIC_LABEL_SZ,
                     ssl->specs.mac_algorithm, 1);
}

    #ifdef TLS13_SUPPORTS_EXPORTERS
/* The length of the early exporter label. */
#define EARLY_EXPORTER_LABEL_SZ     28
/* The early exporter label. */
static const byte earlyExporterLabel[EARLY_EXPORTER_LABEL_SZ + 1] =
    "early exporter master secret";
/* Derive the early exporter key.
 *
 * ssl  The SSL/TLS object.
 * key  The derived key.
 * returns 0 on success, otherwise failure.
 */
static int DeriveEarlyExporterSecret(WOLFSSL* ssl, byte* key)
{
    WOLFSSL_MSG("Derive Early Exporter Secret");
    return DeriveKey(ssl, key, -1, ssl->arrays->secret,
                     earlyExporterLabel, EARLY_EXPORTER_LABEL_SZ,
                     ssl->specs.mac_algorithm, 1);
}
    #endif
#endif

/* The length of the client hanshake label. */
#define CLIENT_HANDSHAKE_LABEL_SZ   31
/* The client hanshake label. */
static const byte clientHandshakeLabel[CLIENT_HANDSHAKE_LABEL_SZ + 1] =
    "client handshake traffic secret";
/* Derive the client handshake key.
 *
 * ssl  The SSL/TLS object.
 * key  The derived key.
 * returns 0 on success, otherwise failure.
 */
static int DeriveClientHandshakeSecret(WOLFSSL* ssl, byte* key)
{
    WOLFSSL_MSG("Derive Client Handshake Secret");
    return DeriveKey(ssl, key, -1, ssl->arrays->preMasterSecret,
                     clientHandshakeLabel, CLIENT_HANDSHAKE_LABEL_SZ,
                     ssl->specs.mac_algorithm, 1);
}

/* The length of the server handshake label. */
#define SERVER_HANDSHAKE_LABEL_SZ   31
/* The server handshake label. */
static const byte serverHandshakeLabel[SERVER_HANDSHAKE_LABEL_SZ + 1] =
    "server handshake traffic secret";
/* Derive the server handshake key.
 *
 * ssl  The SSL/TLS object.
 * key  The derived key.
 * returns 0 on success, otherwise failure.
 */
static int DeriveServerHandshakeSecret(WOLFSSL* ssl, byte* key)
{
    WOLFSSL_MSG("Derive Server Handshake Secret");
    return DeriveKey(ssl, key, -1, ssl->arrays->preMasterSecret,
                     serverHandshakeLabel, SERVER_HANDSHAKE_LABEL_SZ,
                     ssl->specs.mac_algorithm, 1);
}

/* The length of the client application traffic label. */
#define CLIENT_APP_LABEL_SZ         33
/* The client application traffic label. */
static const byte clientAppLabel[CLIENT_APP_LABEL_SZ + 1] =
    "client application traffic secret";
/* Derive the client application traffic key.
 *
 * ssl  The SSL/TLS object.
 * key  The derived key.
 * returns 0 on success, otherwise failure.
 */
static int DeriveClientTrafficSecret(WOLFSSL* ssl, byte* key)
{
    WOLFSSL_MSG("Derive Client Traffic Secret");
    return DeriveKey(ssl, key, -1, ssl->arrays->masterSecret,
                     clientAppLabel, CLIENT_APP_LABEL_SZ,
                     ssl->specs.mac_algorithm, 1);
}

/* The length of the server application traffic label. */
#define SERVER_APP_LABEL_SZ         33
/* The  server application traffic label. */
static const byte serverAppLabel[SERVER_APP_LABEL_SZ + 1] =
    "server application traffic secret";
/* Derive the server application traffic key.
 *
 * ssl  The SSL/TLS object.
 * key  The derived key.
 * returns 0 on success, otherwise failure.
 */
static int DeriveServerTrafficSecret(WOLFSSL* ssl, byte* key)
{
    WOLFSSL_MSG("Derive Server Traffic Secret");
    return DeriveKey(ssl, key, -1, ssl->arrays->masterSecret,
                     serverAppLabel, SERVER_APP_LABEL_SZ,
                     ssl->specs.mac_algorithm, 1);
}

#ifdef TLS13_SUPPORTS_EXPORTERS
/* The length of the exporter master secret label. */
#define EXPORTER_MASTER_LABEL_SZ    22
/* The exporter master secret label. */
static const byte exporterMasterLabel[EXPORTER_MASTER_LABEL_SZ + 1] =
    "exporter master secret";
/* Derive the exporter secret.
 *
 * ssl  The SSL/TLS object.
 * key  The derived key.
 * returns 0 on success, otherwise failure.
 */
static int DeriveExporterSecret(WOLFSSL* ssl, byte* key)
{
    WOLFSSL_MSG("Derive Exporter Secret");
    return DeriveKey(ssl, key, -1, ssl->arrays->masterSecret,
                     exporterMasterLabel, EXPORTER_MASTER_LABEL_SZ,
                     ssl->specs.mac_algorithm, 1);
}
#endif

#ifndef NO_PSK
/* The length of the resumption master secret label. */
#define RESUME_MASTER_LABEL_SZ      24
/* The resumption master secret label. */
static const byte resumeMasterLabel[RESUME_MASTER_LABEL_SZ + 1] =
    "resumption master secret";
/* Derive the resumption secret.
 *
 * ssl  The SSL/TLS object.
 * key  The derived key.
 * returns 0 on success, otherwise failure.
 */
static int DeriveResumptionSecret(WOLFSSL* ssl, byte* key)
{
    WOLFSSL_MSG("Derive Resumption Secret");
    return DeriveKey(ssl, key, -1, ssl->arrays->masterSecret,
                     resumeMasterLabel, RESUME_MASTER_LABEL_SZ,
                     ssl->specs.mac_algorithm, 1);
}
#endif

/* Length of the finished label. */
#define FINISHED_LABEL_SZ           8
/* Finished label for generating finished key. */
static const byte finishedLabel[FINISHED_LABEL_SZ+1] = "finished";
/* Derive the finished secret.
 *
 * ssl     The SSL/TLS object.
 * key     The key to use with the HMAC.
 * secret  The derived secret.
 * returns 0 on success, otherwise failure.
 */
static int DeriveFinishedSecret(WOLFSSL* ssl, byte* key, byte* secret)
{
    WOLFSSL_MSG("Derive Finished Secret");
    return DeriveKey(ssl, secret, -1, key, finishedLabel, FINISHED_LABEL_SZ,
                     ssl->specs.mac_algorithm, 0);
}

/* The length of the application traffic label. */
#define APP_TRAFFIC_LABEL_SZ        26
/* The application traffic label. */
static const byte appTrafficLabel[APP_TRAFFIC_LABEL_SZ + 1] =
    "application traffic secret";
/* Update the traffic secret.
 *
 * ssl     The SSL/TLS object.
 * secret  The previous secret and derived secret.
 * returns 0 on success, otherwise failure.
 */
static int DeriveTrafficSecret(WOLFSSL* ssl, byte* secret)
{
    WOLFSSL_MSG("Derive New Application Traffic Secret");
    return DeriveKeyMsg(ssl, secret, -1, secret,
                        appTrafficLabel, APP_TRAFFIC_LABEL_SZ,
                        NULL, 0, ssl->specs.mac_algorithm);
}

/* Derive the early secret using HKDF Extract.
 *
 * ssl  The SSL/TLS object.
 */
static int DeriveEarlySecret(WOLFSSL* ssl)
{
    WOLFSSL_MSG("Derive Early Secret");
#ifndef NO_PSK
    return Tls13_HKDF_Extract(ssl->arrays->secret, NULL, 0,
            ssl->arrays->psk_key, ssl->arrays->psk_keySz,
            ssl->specs.mac_algorithm);
#else
    return Tls13_HKDF_Extract(ssl->arrays->secret, NULL, 0,
            ssl->arrays->masterSecret, 0, ssl->specs.mac_algorithm);
#endif
}

/* Derive the handshake secret using HKDF Extract.
 *
 * ssl  The SSL/TLS object.
 */
static int DeriveHandshakeSecret(WOLFSSL* ssl)
{
    WOLFSSL_MSG("Derive Handshake Secret");
    return Tls13_HKDF_Extract(ssl->arrays->preMasterSecret,
            ssl->arrays->secret, ssl->specs.hash_size,
            ssl->arrays->preMasterSecret, ssl->arrays->preMasterSz,
            ssl->specs.mac_algorithm);
}

/* Derive the master secret using HKDF Extract.
 *
 * ssl  The SSL/TLS object.
 */
static int DeriveMasterSecret(WOLFSSL* ssl)
{
    WOLFSSL_MSG("Derive Master Secret");
    return Tls13_HKDF_Extract(ssl->arrays->masterSecret,
            ssl->arrays->preMasterSecret, ssl->specs.hash_size,
            ssl->arrays->masterSecret, 0, ssl->specs.mac_algorithm);
}

/* Calculate the HMAC of message data to this point.
 *
 * ssl   The SSL/TLS object.
 * key   The HMAC key.
 * hash  The hash result - verify data.
 * returns length of verify data generated.
 */
static int BuildTls13HandshakeHmac(WOLFSSL* ssl, byte* key, byte* hash)
{
    Hmac verifyHmac;
    int  hashType = SHA256;
    int  hashSz = SHA256_DIGEST_SIZE;

    /* Get the hash of the previous handshake messages. */
    switch (ssl->specs.mac_algorithm) {
    #ifndef NO_SHA256
        case sha256_mac:
            hashType = SHA256;
            hashSz = SHA256_DIGEST_SIZE;
            wc_Sha256GetHash(&ssl->hsHashes->hashSha256, hash);
            break;
    #endif /* !NO_SHA256 */
    #ifdef WOLFSSL_SHA384
        case sha384_mac:
            hashType = SHA384;
            hashSz = SHA384_DIGEST_SIZE;
            wc_Sha384GetHash(&ssl->hsHashes->hashSha384, hash);
            break;
    #endif /* WOLFSSL_SHA384 */
    #ifdef WOLFSSL_SHA512
        case sha512_mac:
            hashType = SHA512;
            hashSz = SHA512_DIGEST_SIZE;
            wc_Sha512GetHash(&ssl->hsHashes->hashSha512, hash);
            break;
    #endif /* WOLFSSL_SHA512 */
    }

    /* Calculate the verify data. */
    wc_HmacSetKey(&verifyHmac, hashType, key, ssl->specs.hash_size);
    wc_HmacUpdate(&verifyHmac, hash, hashSz);
    wc_HmacFinal(&verifyHmac, hash);

    return hashSz;
}

/* The length of the label to use when deriving keys. */
#define WRITE_KEY_LABEL_SZ     3
/* The length of the label to use when deriving IVs. */
#define WRITE_IV_LABEL_SZ      2
/* The label to use when deriving keys. */
static const byte writeKeyLabel[WRITE_KEY_LABEL_SZ+1] = "key";
/* The label to use when deriving IVs. */
static const byte writeIVLabel[WRITE_IV_LABEL_SZ+1]   = "iv";

/* Derive the keys and IVs for TLS v1.3.
 *
 * ssl      The SSL/TLS object.
 * sercret  handshake_key when deriving keys and IVs for encrypting handshake
 *          messages.
 *          traffic_key when deriving first keys and IVs for encrypting
 *          traffic messages.
 *          update_traffic_key when deriving next keys and IVs for encrypting
 *          traffic messages.
 * side     ENCRYPT_SIDE_ONLY when only encryption secret needs to be derived.
 *          DECRYPT_SIDE_ONLY when only decryption secret needs to be derived.
 *          ENCRYPT_AND_DECRYPT_SIDE when both secret needs to be derived.
 * returns 0 on success, otherwise failure.
 */
static int DeriveTls13Keys(WOLFSSL* ssl, int secret, int side)
{
    int   ret;
    int   i = 0;
#ifdef WOLFSSL_SMALL_STACK
    byte* key_data;
#else
    byte  key_data[MAX_PRF_DIG];
#endif
    int   deriveClient = 0;
    int   deriveServer = 0;

#ifdef WOLFSSL_SMALL_STACK
    key_data = (byte*)XMALLOC(MAX_PRF_DIG, ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (key_data == NULL)
        return MEMORY_E;
#endif

    if (side == ENCRYPT_AND_DECRYPT_SIDE) {
        deriveClient = 1;
        deriveServer = 1;
    }
    else {
        deriveClient = (ssl->options.side != WOLFSSL_CLIENT_END) ^
                       (side == ENCRYPT_SIDE_ONLY);
        deriveServer = !deriveClient;
    }

    /* Derive the appropriate secret to use in the HKDF. */
    switch (secret) {
        case handshake_key:
            if (deriveClient) {
                ret = DeriveClientHandshakeSecret(ssl,
                                                  ssl->arrays->clientSecret);
                if (ret != 0)
                    goto end;
            }
            if (deriveServer) {
                ret = DeriveServerHandshakeSecret(ssl,
                                                  ssl->arrays->serverSecret);
                if (ret != 0)
                    goto end;
            }
            break;

        case traffic_key:
            if (deriveClient) {
                ret = DeriveClientTrafficSecret(ssl, ssl->arrays->clientSecret);
                if (ret != 0)
                    goto end;
            }
            if (deriveServer) {
                ret = DeriveServerTrafficSecret(ssl, ssl->arrays->serverSecret);
                if (ret != 0)
                    goto end;
            }
            break;

        case update_traffic_key:
            if (deriveClient) {
                ret = DeriveTrafficSecret(ssl, ssl->arrays->clientSecret);
                if (ret != 0)
                    goto end;
            }
            if (deriveServer) {
                ret = DeriveTrafficSecret(ssl, ssl->arrays->serverSecret);
                if (ret != 0)
                    goto end;
            }
            break;
    }

    /* Key data = client key | server key | client IV | server IV */

    /* Derive the client key.  */
    WOLFSSL_MSG("Derive Client Key");
    ret = DeriveKey(ssl, &key_data[i], ssl->specs.key_size,
                    ssl->arrays->clientSecret, writeKeyLabel,
                    WRITE_KEY_LABEL_SZ, ssl->specs.mac_algorithm, 0);
    if (ret != 0)
        goto end;
    i += ssl->specs.key_size;

    /* Derive the server key.  */
    WOLFSSL_MSG("Derive Server Key");
    ret = DeriveKey(ssl, &key_data[i], ssl->specs.key_size,
                    ssl->arrays->serverSecret, writeKeyLabel,
                    WRITE_KEY_LABEL_SZ, ssl->specs.mac_algorithm, 0);
    if (ret != 0)
        goto end;
    i += ssl->specs.key_size;

    /* Derive the client IV.  */
    WOLFSSL_MSG("Derive Client IV");
    ret = DeriveKey(ssl, &key_data[i], ssl->specs.iv_size,
                    ssl->arrays->clientSecret, writeIVLabel, WRITE_IV_LABEL_SZ,
                    ssl->specs.mac_algorithm, 0);
    if (ret != 0)
        goto end;
    i += ssl->specs.iv_size;

    /* Derive the server IV.  */
    WOLFSSL_MSG("Derive Server IV");
    ret = DeriveKey(ssl, &key_data[i], ssl->specs.iv_size,
                    ssl->arrays->serverSecret, writeIVLabel, WRITE_IV_LABEL_SZ,
                    ssl->specs.mac_algorithm, 0);
    if (ret != 0)
        goto end;

    /* Store keys and IVs but don't activate them. */
    ret = StoreKeys(ssl, key_data);

end:
#ifdef WOLFSSL_SMALL_STACK
    XFREE(serverData, ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(key_data, ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}

#if defined(HAVE_SESSION_TICKET)
#if defined(USER_TICKS)
#if 0
    word32 TimeNowInMilliseconds(void)
    {
        /*
        write your own clock tick function if don't want gettimeofday()
        needs millisecond accuracy but doesn't have to correlated to EPOCH
        */
    }
#endif

#elif defined(TIME_OVERRIDES)
    #ifndef HAVE_TIME_T_TYPE
        typedef long time_t;
    #endif
    extern time_t XTIME(time_t * timer);

    /* The time in milliseconds.
     * Used for tickets to represent difference between when first seen and when
     * sending.
     *
     * returns the time in milliseconds as a 32-bit value.
     */
    word32 TimeNowInMilliseconds(void)
    {
        return (word32) XTIME(0) * 1000;
    }
#elif defined(USE_WINDOWS_API)
    /* The time in milliseconds.
     * Used for tickets to represent difference between when first seen and when
     * sending.
     *
     * returns the time in milliseconds as a 32-bit value.
     */
    word32 TimeNowInMilliseconds(void)
    {
        static int           init = 0;
        static LARGE_INTEGER freq;
        LARGE_INTEGER        count;

        if (!init) {
            QueryPerformanceFrequency(&freq);
            init = 1;
        }

        QueryPerformanceCounter(&count);

        return (word32)(count.QuadPart / (freq.QuadPart / 1000));
    }

#elif defined(HAVE_RTP_SYS)
    #include "rtptime.h"

    /* The time in milliseconds.
     * Used for tickets to represent difference between when first seen and when
     * sending.
     *
     * returns the time in milliseconds as a 32-bit value.
     */
    word32 TimeNowInMilliseconds(void)
    {
        return (word32)rtp_get_system_sec() * 1000;
    }
#elif defined(MICRIUM)
    /* The time in milliseconds.
     * Used for tickets to represent difference between when first seen and when
     * sending.
     *
     * returns the time in milliseconds as a 32-bit value.
     */
    word32 TimeNowInMilliseconds(void)
    {
        NET_SECURE_OS_TICK  clk = 0;

        #if (NET_SECURE_MGR_CFG_EN == DEF_ENABLED)
            clk = NetSecure_OS_TimeGet();
        #endif
        return (word32)clk * 1000;
    }
#elif defined(MICROCHIP_TCPIP_V5)
    /* The time in milliseconds.
     * Used for tickets to represent difference between when first seen and when
     * sending.
     *
     * returns the time in milliseconds as a 32-bit value.
     */
    word32 TimeNowInMilliseconds(void)
    {
        return (word32) (TickGet() / (TICKS_PER_SECOND / 1000));
    }
#elif defined(MICROCHIP_TCPIP)
    #if defined(MICROCHIP_MPLAB_HARMONY)
        #include <system/tmr/sys_tmr.h>

    /* The time in milliseconds.
     * Used for tickets to represent difference between when first seen and when
     * sending.
     *
     * returns the time in milliseconds as a 32-bit value.
     */
    word32 TimeNowInMilliseconds(void)
    {
        return (word32) (SYS_TMR_TickCountGet() /
                         (SYS_TMR_TickCounterFrequencyGet() / 1000));
    }
    #else
    /* The time in milliseconds.
     * Used for tickets to represent difference between when first seen and when
     * sending.
     *
     * returns the time in milliseconds as a 32-bit value.
     */
    word32 TimeNowInMilliseconds(void)
    {
        return (word32) (SYS_TICK_Get() / (SYS_TICK_TicksPerSecondGet() / 1000));
    }

    #endif

#elif defined(FREESCALE_MQX) || defined(FREESCALE_KSDK_MQX)
    /* The time in milliseconds.
     * Used for tickets to represent difference between when first seen and when
     * sending.
     *
     * returns the time in milliseconds as a 32-bit value.
     */
    word32 TimeNowInMilliseconds(void)
    {
        TIME_STRUCT mqxTime;

        _time_get_elapsed(&mqxTime);

        return (word32) mqxTime.SECONDS * 1000;
    }
#elif defined(FREESCALE_FREE_RTOS) || defined(FREESCALE_KSDK_FREERTOS)
    #include "include/task.h"

    /* The time in milliseconds.
     * Used for tickets to represent difference between when first seen and when
     * sending.
     *
     * returns the time in milliseconds as a 32-bit value.
     */
    word32 TimeNowInMilliseconds(void)
    {
        return (unsigned int)(((float)xTaskGetTickCount()) /
                              (configTICK_RATE_HZ / 1000));
    }
#elif defined(FREESCALE_KSDK_BM)
    #include "lwip/sys.h" /* lwIP */

    /* The time in milliseconds.
     * Used for tickets to represent difference between when first seen and when
     * sending.
     *
     * returns the time in milliseconds as a 32-bit value.
     */
    word32 TimeNowInMilliseconds(void)
    {
        return sys_now();
    }
#elif defined(WOLFSSL_TIRTOS)
    /* The time in milliseconds.
     * Used for tickets to represent difference between when first seen and when
     * sending.
     *
     * returns the time in milliseconds as a 32-bit value.
     */
    word32 TimeNowInMilliseconds(void)
    {
        return (word32) Seconds_get() * 1000;
    }
#elif defined(WOLFSSL_UTASKER)
    /* The time in milliseconds.
     * Used for tickets to represent difference between when first seen and when
     * sending.
     *
     * returns the time in milliseconds as a 32-bit value.
     */
    word32 TimeNowInMilliseconds(void)
    {
        return (word32)(uTaskerSystemTick / (TICK_RESOLUTION / 1000));
    }
#else
    /* The time in milliseconds.
     * Used for tickets to represent difference between when first seen and when
     * sending.
     *
     * returns the time in milliseconds as a 32-bit value.
     */
    word32 TimeNowInMilliseconds(void)
    {
        struct timeval now;

        if (gettimeofday(&now, 0) < 0)
            return GETTIME_ERROR;
        /* Convert to milliseconds number. */
        return (word32)(now.tv_sec * 1000 + now.tv_usec / 1000);
    }
#endif
#endif /* HAVE_SESSION_TICKET */


#if !defined(NO_WOLFSSL_SERVER) && (defined(HAVE_SESSION_TICKET) && \
                                    !defined(NO_PSK))
/* Add input to all handshake hashes.
 *
 * ssl    The SSL/TLS object.
 * input  The data to hash.
 * sz     The size of the data to hash.
 * returns 0 on success, otherwise failure.
 */
static int HashInputRaw(WOLFSSL* ssl, const byte* input, int sz)
{
    int ret = 0;

#ifndef NO_OLD_TLS
#ifndef NO_SHA
    wc_ShaUpdate(&ssl->hsHashes->hashSha, input, sz);
#endif
#ifndef NO_MD5
    wc_Md5Update(&ssl->hsHashes->hashMd5, input, sz);
#endif
#endif

#ifndef NO_SHA256
    ret = wc_Sha256Update(&ssl->hsHashes->hashSha256, input, sz);
    if (ret != 0)
        return ret;
#endif
#ifdef WOLFSSL_SHA384
    ret = wc_Sha384Update(&ssl->hsHashes->hashSha384, input, sz);
    if (ret != 0)
        return ret;
#endif
#ifdef WOLFSSL_SHA512
    ret = wc_Sha512Update(&ssl->hsHashes->hashSha512, input, sz);
    if (ret != 0)
        return ret;
#endif

    return ret;
}
#endif

/* Extract the handshake header information.
 *
 * ssl       The SSL/TLS object.
 * input     The buffer holding the message data.
 * inOutIdx  On entry, the index into the buffer of the handshake data.
 *           On exit, the start of the hanshake data.
 * type      Type of handshake message.
 * size      The length of the handshake message data.
 * totalSz   The total size of data in the buffer.
 * returns BUFFER_E if there is not enough input data and 0 on success.
 */
static int GetHandshakeHeader(WOLFSSL* ssl, const byte* input, word32* inOutIdx,
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

/* Add record layer header to message.
 *
 * output  The buffer to write the record layer header into.
 * length  The length of the record data.
 * type    The type of record message.
 * ssl     The SSL/TLS object.
 */
static void AddTls13RecordHeader(byte* output, word32 length, byte type,
                                 WOLFSSL* ssl)
{
    RecordLayerHeader* rl;

    rl = (RecordLayerHeader*)output;
    rl->type    = type;
    rl->pvMajor = ssl->version.major;
    rl->pvMinor = TLSv1_MINOR;
    c16toa((word16)length, rl->length);
}

/* Add handshake header to message.
 *
 * output      The buffer to write the hanshake header into.
 * length      The length of the handshake data.
 * fragOffset  The offset of the fragment data. (DTLS)
 * fragLength  The length of the fragment data. (DTLS)
 * type        The type of handshake message.
 * ssl         The SSL/TLS object. (DTLS)
 */
static void AddTls13HandShakeHeader(byte* output, word32 length,
                                    word32 fragOffset, word32 fragLength,
                                    byte type, WOLFSSL* ssl)
{
    HandShakeHeader* hs;
    (void)fragOffset;
    (void)fragLength;
    (void)ssl;

    /* handshake header */
    hs = (HandShakeHeader*)output;
    hs->type = type;
    c32to24(length, hs->length);
}


/* Add both record layer and handshake header to message.
 *
 * output      The buffer to write the headers into.
 * length      The length of the handshake data.
 * type        The type of record layer message.
 * ssl         The SSL/TLS object. (DTLS)
 */
static void AddTls13Headers(byte* output, word32 length, byte type, WOLFSSL* ssl)
{
    word32 lengthAdj = HANDSHAKE_HEADER_SZ;
    word32 outputAdj = RECORD_HEADER_SZ;

    AddTls13RecordHeader(output, length + lengthAdj, handshake, ssl);
    AddTls13HandShakeHeader(output + outputAdj, length, 0, length, type, ssl);
}


#ifndef NO_CERTS
/* Add both record layer and fragement handshake header to message.
 *
 * output      The buffer to write the headers into.
 * fragOffset  The offset of the fragment data. (DTLS)
 * fragLength  The length of the fragment data. (DTLS)
 * length      The length of the handshake data.
 * type        The type of record layer message.
 * ssl         The SSL/TLS object. (DTLS)
 */
static void AddTls13FragHeaders(byte* output, word32 fragSz, word32 fragOffset,
                                word32 length, byte type, WOLFSSL* ssl)
{
    word32 lengthAdj = HANDSHAKE_HEADER_SZ;
    word32 outputAdj = RECORD_HEADER_SZ;
    (void)fragSz;

    AddTls13RecordHeader(output, fragSz + lengthAdj, handshake, ssl);
    AddTls13HandShakeHeader(output + outputAdj, length, fragOffset, fragSz,
                            type, ssl);
}
#endif /* NO_CERTS */

/* Write the sequence number into the buffer.
 * No DTLS v1.3 support.
 *
 * ssl          The SSL/TLS object.
 * verifyOrder  Which set of sequence numbers to use.
 * out          The buffer to write into.
 */
static INLINE void WriteSEQ(WOLFSSL* ssl, int verifyOrder, byte* out)
{
    word32 seq[2] = {0, 0};

    if (verifyOrder) {
        seq[0] = ssl->keys.peer_sequence_number_hi;
        seq[1] = ssl->keys.peer_sequence_number_lo++;
        /* handle rollover */
        if (seq[1] > ssl->keys.peer_sequence_number_lo)
            ssl->keys.peer_sequence_number_hi++;
    }
    else {
        seq[0] = ssl->keys.sequence_number_hi;
        seq[1] = ssl->keys.sequence_number_lo++;
        /* handle rollover */
        if (seq[1] > ssl->keys.sequence_number_lo)
            ssl->keys.sequence_number_hi++;
    }

    c32toa(seq[0], out);
    c32toa(seq[1], out + OPAQUE32_LEN);
}

/* Build the nonce for TLS v1.3 encryption and decryption.
 *
 * ssl    The SSL/TLS object.
 * nonce  The nonce data to use when encrypting or decrypting.
 * iv     The derived IV.
 * order  The side on which the message is to be or was sent.
 */
static INLINE void BuildTls13Nonce(WOLFSSL* ssl, byte *nonce, const byte* iv,
                                   int order)
{
    int  i;

    /* The nonce is the IV with the sequence XORed into the last bytes. */
    WriteSEQ(ssl, order, nonce + AEAD_NONCE_SZ - SEQ_SZ);
    for (i = 0; i < AEAD_NONCE_SZ - SEQ_SZ; i++)
        nonce[i] = iv[i];
    for (; i < AEAD_NONCE_SZ; i++)
        nonce[i] ^= iv[i];
}

/* Encrypt with ChaCha20 and create authenication tag with Poly1305.
 *
 * ssl     The SSL/TLS object.
 * output  The buffer to write encrypted data and authentication tag into.
 *         May be the same pointer as input.
 * input   The data to encrypt.
 * sz      The number of bytes to encrypt.
 * nonce   The nonce to use with ChaCha20.
 * tag     The authentication tag buffer.
 * returns 0 on success, otherwise failure.
 */
static int ChaCha20Poly1305_Encrypt(WOLFSSL* ssl, byte* output,
                                    const byte* input, word16 sz, byte* nonce,
                                    byte* tag)
{
    int    ret    = 0;
    byte   poly[CHACHA20_256_KEY_SIZE];

    /* Poly1305 key is 256 bits of zero encrypted with ChaCha20. */
    XMEMSET(poly, 0, sizeof(poly));

    /* Set the nonce for ChaCha and get Poly1305 key. */
    ret = wc_Chacha_SetIV(ssl->encrypt.chacha, nonce, 0);
    if (ret != 0)
        return ret;
    /* Create Poly1305 key using ChaCha20 keystream. */
    ret = wc_Chacha_Process(ssl->encrypt.chacha, poly, poly, sizeof(poly));
    if (ret != 0)
        return ret;
    /* Encrypt the plain text. */
    ret = wc_Chacha_Process(ssl->encrypt.chacha, output, input, sz);
    if (ret != 0) {
        ForceZero(poly, sizeof(poly));
        return ret;
    }

    /* Set key for Poly1305. */
    ret = wc_Poly1305SetKey(ssl->auth.poly1305, poly, sizeof(poly));
    ForceZero(poly, sizeof(poly)); /* done with poly1305 key, clear it */
    if (ret != 0)
        return ret;
    /* Add authentication code of encrypted data to end. */
    ret = wc_Poly1305_MAC(ssl->auth.poly1305, NULL, 0, output, sz, tag,
                          POLY1305_AUTH_SZ);

    return ret;
}

/* Encrypt data for TLS v1.3.
 *
 * ssl     The SSL/TLS object.
 * output  The buffer to write encrypted data and authentication tag into.
 *         May be the same pointer as input.
 * input   The data to encrypt.
 * sz      The number of bytes to encrypt.
 * returns 0 on success, otherwise failure.
 */
static int EncryptTls13(WOLFSSL* ssl, byte* output, const byte* input,
                        word16 sz)
{
    int    ret    = 0;
    word16 dataSz = sz - ssl->specs.aead_mac_size;
    word16 macSz  = ssl->specs.aead_mac_size;
    byte   nonce[AEAD_NONCE_SZ];

    (void)output;
    (void)input;
    (void)sz;
    (void)dataSz;
    (void)macSz;

#ifdef WOLFSSL_DEBUG_TLS
    WOLFSSL_MSG("Data to encrypt");
    WOLFSSL_BUFFER(input, dataSz);
#endif

    BuildTls13Nonce(ssl, nonce, ssl->keys.aead_enc_imp_IV, CUR_ORDER);

    switch (ssl->specs.bulk_cipher_algorithm) {
        #ifdef BUILD_AESGCM
        case wolfssl_aes_gcm:
            ret = wc_AesGcmEncrypt(ssl->encrypt.aes, output, input, dataSz,
                nonce, AESGCM_NONCE_SZ, output + dataSz, macSz, NULL, 0);
            break;
        #endif

        #ifdef HAVE_AESCCM
        case wolfssl_aes_ccm:
            ret = wc_AesCcmEncrypt(ssl->encrypt.aes, output, input, dataSz,
                nonce, AESCCM_NONCE_SZ, output + dataSz, macSz, NULL, 0);
            break;
        #endif

        #if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
        case wolfssl_chacha:
            ret = ChaCha20Poly1305_Encrypt(ssl, output, input, dataSz, nonce,
                output + dataSz);
            break;
        #endif

        default:
            WOLFSSL_MSG("wolfSSL Encrypt programming error");
            return ENCRYPT_ERROR;
    }

    ForceZero(nonce, AEAD_NONCE_SZ);

#ifdef WOLFSSL_DEBUG_TLS
    WOLFSSL_MSG("Encrypted data");
    WOLFSSL_BUFFER(output, dataSz);
    WOLFSSL_MSG("Authentication Tag");
    WOLFSSL_BUFFER(output + dataSz, macSz);
#endif

    return ret;
}

/* Decrypt with ChaCha20 and check authenication tag with Poly1305.
 *
 * ssl     The SSL/TLS object.
 * output  The buffer to write decrypted data into.
 *         May be the same pointer as input.
 * input   The data to decrypt.
 * sz      The number of bytes to decrypt.
 * nonce   The nonce to use with ChaCha20.
 * tagIn   The authentication tag data from packet.
 * returns 0 on success, otherwise failure.
 */
static int ChaCha20Poly1305_Decrypt(WOLFSSL *ssl, byte* output,
                                    const byte* input, word16 sz, byte* nonce,
                                    const byte* tagIn)
{
    int ret;
    byte tag[POLY1305_AUTH_SZ];
    byte poly[CHACHA20_256_KEY_SIZE]; /* generated key for mac */

    /* Poly1305 key is 256 bits of zero encrypted with ChaCha20. */
    XMEMSET(poly, 0, sizeof(poly));

    /* Set nonce and get Poly1305 key. */
    ret = wc_Chacha_SetIV(ssl->decrypt.chacha, nonce, 0);
    if (ret != 0)
        return ret;
    /* Use ChaCha20 keystream to get Poly1305 key for tag. */
    ret = wc_Chacha_Process(ssl->decrypt.chacha, poly, poly, sizeof(poly));
    if (ret != 0)
        return ret;

    /* Set key for Poly1305. */
    ret = wc_Poly1305SetKey(ssl->auth.poly1305, poly, sizeof(poly));
    ForceZero(poly, sizeof(poly)); /* done with poly1305 key, clear it */
    if (ret != 0)
        return ret;
    /* Generate authentication tag for encrypted data. */
    if ((ret = wc_Poly1305_MAC(ssl->auth.poly1305, NULL, 0, (byte*)input, sz,
                               tag, sizeof(tag))) != 0) {
        return ret;
    }

    /* Check tag sent along with packet. */
    if (ConstantCompare(tagIn, tag, POLY1305_AUTH_SZ) != 0) {
        WOLFSSL_MSG("MAC did not match");
        return VERIFY_MAC_ERROR;
    }

    /* If the tag was good decrypt message. */
    ret = wc_Chacha_Process(ssl->decrypt.chacha, output, input, sz);

    return ret;
}

/* Decrypt data for TLS v1.3.
 *
 * ssl     The SSL/TLS object.
 * output  The buffer to write decrypted data into.
 *         May be the same pointer as input.
 * input   The data to encrypt and authentication tag.
 * sz      The length of the encrypted data plus authentication tag.
 * returns 0 on success, otherwise failure.
 */
int DecryptTls13(WOLFSSL* ssl, byte* output, const byte* input, word16 sz)
{
    int    ret    = 0;
    word16 dataSz = sz - ssl->specs.aead_mac_size;
    word16 macSz  = ssl->specs.aead_mac_size;
    byte   nonce[AEAD_NONCE_SZ];

    (void)output;
    (void)input;
    (void)sz;
    (void)dataSz;
    (void)macSz;

#ifdef WOLFSSL_DEBUG_TLS
    WOLFSSL_MSG("Data to decrypt");
    WOLFSSL_BUFFER(input, dataSz);
    WOLFSSL_MSG("Authentication tag");
    WOLFSSL_BUFFER(input + dataSz, macSz);
#endif

    BuildTls13Nonce(ssl, nonce, ssl->keys.aead_dec_imp_IV, PEER_ORDER);

    switch (ssl->specs.bulk_cipher_algorithm) {
        #ifdef BUILD_AESGCM
        case wolfssl_aes_gcm:
            ret = wc_AesGcmDecrypt(ssl->decrypt.aes, output, input, dataSz,
                nonce, AESGCM_NONCE_SZ, input + dataSz, macSz, NULL, 0);
            break;
        #endif

        #ifdef HAVE_AESCCM
        case wolfssl_aes_ccm:
            ret = wc_AesCcmDecrypt(ssl->decrypt.aes, output, input, dataSz,
                nonce, AESCCM_NONCE_SZ, input + dataSz, macSz, NULL, 0);
            break;
        #endif

        #if defined(HAVE_CHACHA) && defined(HAVE_POLY1305)
        case wolfssl_chacha:
            ret = ChaCha20Poly1305_Decrypt(ssl, output, input, dataSz, nonce,
                input + dataSz);
            break;
        #endif

        default:
            WOLFSSL_MSG("wolfSSL Decrypt programming error");
            return DECRYPT_ERROR;
    }

    ForceZero(nonce, AEAD_NONCE_SZ);
    if (ret < 0 && !ssl->options.dtls) {
        SendAlert(ssl, alert_fatal, bad_record_mac);
        ret = VERIFY_MAC_ERROR;
    }

#ifdef WOLFSSL_DEBUG_TLS
    WOLFSSL_MSG("Decrypted data");
    WOLFSSL_BUFFER(output, dataSz);
#endif

    return ret;
}

/* Build SSL Message, encrypted.
 * TLS v1.3 encryption is AEAD only.
 *
 * ssl         The SSL/TLS object.
 * output      The buffer to write record message to.
 * outSz       Size of the buffer being written into.
 * input       The record data to encrypt (excluding record header).
 * inSz        The size of the record data.
 * type        The recorder header content type.
 * hashOutput  Whether to hash the unencrypted record data.
 * sizeOnly    Only want the size of the record message.
 * returns the size of the encrypted record message or negative value on error.
 */
int BuildTls13Message(WOLFSSL* ssl, byte* output, int outSz, const byte* input,
                      int inSz, int type, int hashOutput, int sizeOnly)
{
    word32 sz = RECORD_HEADER_SZ + inSz;
    word32 idx  = RECORD_HEADER_SZ;
    word32 headerSz = RECORD_HEADER_SZ;
    word16 size;
    int ret        = 0;
    int atomicUser = 0;

    if (ssl == NULL)
        return BAD_FUNC_ARG;
    if (!sizeOnly && (output == NULL || input == NULL))
        return BAD_FUNC_ARG;
    /* catch mistaken sizeOnly parameter */
    if (sizeOnly && (output || input)) {
        WOLFSSL_MSG("BuildMessage with sizeOnly doesn't need input or output");
        return BAD_FUNC_ARG;
    }

    /* Record layer content type at the end of record data. */
    sz++;
    /* Authentication data at the end. */
    sz += ssl->specs.aead_mac_size;

    if (sizeOnly)
        return sz;

    if (sz > (word32)outSz) {
        WOLFSSL_MSG("Oops, want to write past output buffer size");
        return BUFFER_E;
    }

    /* Record data length. */
    size = (word16)(sz - headerSz);
    /* Write/update the record header with the new size.
     * Always have the content type as application data for encrypted
     * messages in TLS v1.3.
     */
    AddTls13RecordHeader(output, size, application_data, ssl);

    /* TLS v1.3 can do in place encryption. */
    if (input != output + idx)
        XMEMCPY(output + idx, input, inSz);
    idx += inSz;

    if (hashOutput) {
        ret = HashOutput(ssl, output, headerSz + inSz, 0);
        if (ret != 0)
            return ret;
    }

    /* The real record content type goes at the end of the data. */
    output[idx++] = type;

#ifdef ATOMIC_USER
    if (ssl->ctx->MacEncryptCb)
        atomicUser = 1;
#endif

    if (atomicUser) {   /* User Record Layer Callback handling */
#ifdef ATOMIC_USER
        byte* mac = output + idx;
        output += headerSz;

        if ((ret = ssl->ctx->MacEncryptCb(ssl, mac, output, inSz, type, 0,
                output, output, size, ssl->MacEncryptCtx)) != 0) {
            return ret;
        }
#endif
    }
    else {
        output += headerSz;
        if ((ret = EncryptTls13(ssl, output, output, size)) != 0)
            return ret;
    }

    return sz;
}

#ifndef NO_WOLFSSL_CLIENT
#if defined(HAVE_SESSION_TICKET) && !defined(NO_PSK)
/* Get the size of the message hash.
 *
 * ssl   The SSL/TLS object.
 * returns the length of the hash.
 */
static int GetMsgHashSize(WOLFSSL *ssl)
{
    switch (ssl->specs.mac_algorithm) {
    #ifndef NO_SHA256
        case sha256_mac:
            return SHA256_DIGEST_SIZE;
    #endif /* !NO_SHA256 */
    #ifdef WOLFSSL_SHA384
        case sha384_mac:
            return SHA384_DIGEST_SIZE;
    #endif /* WOLFSSL_SHA384 */
    #ifdef WOLFSSL_SHA512
        case sha512_mac:
            return SHA512_DIGEST_SIZE;
    #endif /* WOLFSSL_SHA512 */
    }
    return 0;
}

/* Derive and write the binders into the ClientHello in space left when
 * writing the Pre-Shared Key extension.
 *
 * ssl     The SSL/TLS object.
 * output  The buffer containing the ClientHello.
 * idx     The index at the end of the completed ClientHello.
 * returns 0 on success and otherwise failure.
 */
static int WritePSKBinders(WOLFSSL* ssl, byte* output, word32 idx)
{
    int           ret;
    TLSX*         ext;
    PreSharedKey* current;
    byte          binderKey[MAX_DIGEST_SIZE];
    word16        len;

    ext = TLSX_Find(ssl->extensions, TLSX_PRE_SHARED_KEY);
    if (ext == NULL)
        return SANITY_MSG_E;

    /* Get the size of the binders to determine where to write binders. */
    idx -= TLSX_PreSharedKey_GetSizeBinders(ext->data, client_hello);

    /* Hash truncated ClientHello - up to binders. */
    ret = HashOutput(ssl, output, idx, 0);
    if (ret != 0)
        return ret;

    current = ext->data;
    /* Calculate the binder for each identity based on previous handshake data.
     */
    while (current != NULL) {
        if (current->resumption) {
            /* Set the HMAC to use based on the one for the session (set into
             * the extension data at the start of this function based on the
             * cipher suite in the session information.
             */
            ssl->specs.mac_algorithm = current->hmac;

            /* Resumption PSK is master secret. */
            ssl->arrays->psk_keySz = GetMsgHashSize(ssl);
            XMEMCPY(ssl->arrays->psk_key, ssl->session.masterSecret,
                    ssl->arrays->psk_keySz);
            /* Derive the early secret using the PSK. */
            DeriveEarlySecret(ssl);
            /* Derive the binder key to use to with HMAC. */
            DeriveBinderKeyResume(ssl, binderKey);
        }
        else {
            /* TODO: [TLS13] Support non-ticket PSK. */
            /* Get the pre-shared key. */
            ssl->arrays->psk_keySz = ssl->options.client_psk_cb(ssl,
                    (char *)current->identity, ssl->arrays->client_identity,
                    MAX_PSK_ID_LEN, ssl->arrays->psk_key, MAX_PSK_KEY_LEN);
            /* Derive the early secret using the PSK. */
            DeriveEarlySecret(ssl);
            /* Derive the binder key to use to with HMAC. */
            DeriveBinderKey(ssl, binderKey);
        }

        /* Derive the Finished message secret. */
        DeriveFinishedSecret(ssl, binderKey, ssl->keys.client_write_MAC_secret);
        /* Build the HMAC of the handshake message data = binder. */
        current->binderLen = BuildTls13HandshakeHmac(ssl,
            ssl->keys.client_write_MAC_secret, current->binder);

        current = current->next;
    }

    /* Data entered into extension, now write to message. */
    len = TLSX_PreSharedKey_WriteBinders(ext->data, output + idx, client_hello);

    /* Hash binders to complete the hash of the ClientHello. */
    return HashOutputRaw(ssl, output + idx, len);
}
#endif

/* Send a ClientHello message to the server.
 * Include the information required to start a handshake with servers using
 * protocol versions less than TLS v1.3.
 * Only a client will send this message.
 *
 * ssl  The SSL/TLS object.
 * returns 0 on success and otherwise failure.
 */
int SendTls13ClientHello(WOLFSSL* ssl)
{
    byte*  output;
    word32 length;
    word32 idx = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ;
    int    sendSz;
    int    ret;

#if defined(WOLFSSL_TLS13) && defined(HAVE_SESSION_TICKET) && !defined(NO_PSK)
    if (ssl->options.resuming &&
            (ssl->session.version.major != ssl->version.major ||
             ssl->session.version.minor != ssl->version.minor)) {
        ssl->version.major = ssl->session.version.major;
        ssl->version.minor = ssl->session.version.minor;
        return SendClientHello(ssl);
    }
#endif

    if (ssl->suites == NULL) {
        WOLFSSL_MSG("Bad suites pointer in SendTls13ClientHello");
        return SUITES_ERROR;
    }

    /* Version | Random | Session Id | Cipher Suites | Compression | Ext  */
    length = VERSION_SZ + RAN_LEN + ENUM_LEN + ssl->suites->suiteSz +
             SUITE_LEN + COMP_LEN + ENUM_LEN;

    /* Auto populate extensions supported unless user defined. */
    if ((ret = TLSX_PopulateExtensions(ssl, 0)) != 0)
        return ret;
#ifdef HAVE_QSH
    if (QSH_Init(ssl) != 0)
        return MEMORY_E;
#endif
    /* Include length of TLS extensions. */
    length += TLSX_GetRequestSize(ssl);

    /* Total message size. */
    sendSz = length + HANDSHAKE_HEADER_SZ + RECORD_HEADER_SZ;

    /* Check buffers are big enough and grow if needed. */
    if ((ret = CheckAvailableSize(ssl, sendSz)) != 0)
        return ret;

    /* Get position in output buffer to write new message to. */
    output = ssl->buffers.outputBuffer.buffer +
             ssl->buffers.outputBuffer.length;

    /* Put the record and handshake headers on. */
    AddTls13Headers(output, length, client_hello, ssl);

    /* Protocol version. */
    output[idx++] = ssl->version.major;
    output[idx++] = ssl->version.minor;
    ssl->chVersion = ssl->version;

    /* Client Random */
    if (ssl->options.connectState == CONNECT_BEGIN) {
        ret = wc_RNG_GenerateBlock(ssl->rng, output + idx, RAN_LEN);
        if (ret != 0)
            return ret;

        /* Store random for possible second ClientHello. */
        XMEMCPY(ssl->arrays->clientRandom, output + idx, RAN_LEN);
    }
    else
        XMEMCPY(output + idx, ssl->arrays->clientRandom, RAN_LEN);
    idx += RAN_LEN;

    /* TLS v1.3 does not use session id - 0 length. */
    output[idx++] = 0;

    /* Cipher suites */
    c16toa(ssl->suites->suiteSz, output + idx);
    idx += OPAQUE16_LEN;
    XMEMCPY(output + idx, &ssl->suites->suites, ssl->suites->suiteSz);
    idx += ssl->suites->suiteSz;

    /* Compression not supported in TLS v1.3. */
    output[idx++] = COMP_LEN;
    output[idx++] = NO_COMPRESSION;

    /* Write out extensions for a request. */
    idx += TLSX_WriteRequest(ssl, output + idx);

#if defined(HAVE_SESSION_TICKET) && !defined(NO_PSK)
    /* Resumption has a specific set of extensions and binder is calculated
     * for each identity.
     */
    if (ssl->options.resuming)
        ret = WritePSKBinders(ssl, output, idx);
    else
#endif
        ret = HashOutput(ssl, output, idx, 0);
    if (ret != 0)
        return ret;

    ssl->options.clientState = CLIENT_HELLO_COMPLETE;

#ifdef WOLFSSL_CALLBACKS
    if (ssl->hsInfoOn) AddPacketName("ClientHello", &ssl->handShakeInfo);
    if (ssl->toInfoOn)
        AddPacketInfo("ClientHello", &ssl->timeoutInfo, output, sendSz,
                      ssl->heap);
#endif

    ssl->buffers.outputBuffer.length += sendSz;

    return SendBuffered(ssl);
}

/* Parse and handle a HelloRetryRequest message.
 * Only a client will receive this message.
 *
 * ssl       The SSL/TLS object.
 * input     The message buffer.
 * inOutIdx  On entry, the index into the message buffer of
 *           HelloRetryRequest.
 *           On exit, the index of byte after the HelloRetryRequest message.
 * totalSz   The length of the current handshake message.
 * returns 0 on success and otherwise failure.
 */
static int DoTls13HelloRetryRequest(WOLFSSL* ssl, const byte* input,
                                    word32* inOutIdx, word32 totalSz)
{
    int             ret;
    word32          begin = *inOutIdx;
    word32          i = begin;
    word16          totalExtSz;
    ProtocolVersion pv;

#ifdef WOLFSSL_CALLBACKS
    if (ssl->hsInfoOn) AddPacketName("HelloRetryRequest", &ssl->handShakeInfo);
    if (ssl->toInfoOn) AddLateName("HelloRetryRequest", &ssl->timeoutInfo);
#endif

    /* Version info and length field of extension data. */
    if (totalSz < i - begin + OPAQUE16_LEN + OPAQUE16_LEN)
        return BUFFER_ERROR;

    /* Protocol version. */
    XMEMCPY(&pv, input + i, OPAQUE16_LEN);
    i += OPAQUE16_LEN;
    ret = CheckVersion(ssl, pv);
    if (ret != 0)
        return ret;

    /* Length of extension data. */
    ato16(&input[i], &totalExtSz);
    i += OPAQUE16_LEN;
    if (totalExtSz == 0) {
        WOLFSSL_MSG("HelloRetryRequest must contain extensions");
        return MISSING_HANDSHAKE_DATA;
    }

    /* Extension data. */
    if (i - begin + totalExtSz > totalSz)
        return BUFFER_ERROR;
    if ((ret = TLSX_Parse(ssl, (byte *)(input + i), totalExtSz,
                          hello_retry_request, NULL)))
        return ret;
    /* The KeyShare extension parsing fails when not valid. */

    /* Move index to byte after message. */
    *inOutIdx = i + totalExtSz;

    ssl->options.tls1_3 = 1;
    ssl->options.serverState = SERVER_HELLO_RETRY_REQUEST;

    return 0;
}

/* Handle the ServerHello message from the server.
 * Only a client will receive this message.
 *
 * ssl       The SSL/TLS object.
 * input     The message buffer.
 * inOutIdx  On entry, the index into the message buffer of ServerHello.
 *           On exit, the index of byte after the ServerHello message.
 * helloSz   The length of the current handshake message.
 * returns 0 on success and otherwise failure.
 */
int DoTls13ServerHello(WOLFSSL* ssl, const byte* input, word32* inOutIdx,
                       word32 helloSz)
{
    ProtocolVersion pv;
    word32          i = *inOutIdx;
    word32          begin = i;
    int             ret;
    word16          totalExtSz;

#ifdef WOLFSSL_CALLBACKS
    if (ssl->hsInfoOn) AddPacketName("ServerHello", &ssl->handShakeInfo);
    if (ssl->toInfoOn) AddLateName("ServerHello", &ssl->timeoutInfo);
#endif

    /* Protocol version length check. */
    if (OPAQUE16_LEN > helloSz)
        return BUFFER_ERROR;

    /* Protocol version */
    XMEMCPY(&pv, input + i, OPAQUE16_LEN);
    i += OPAQUE16_LEN;
    ret = CheckVersion(ssl, pv);
    if (ret != 0)
        return ret;
    if (!IsAtLeastTLSv1_3(pv) && pv.major != TLS_DRAFT_MAJOR) {
        ssl->version = pv;
        return DoServerHello(ssl, input, inOutIdx, helloSz);
    }

    /* Random, cipher suite and extensions length check. */
    if ((i - begin) + RAN_LEN + OPAQUE16_LEN + OPAQUE16_LEN > helloSz)
        return BUFFER_ERROR;

    /* Server random - keep for debugging. */
    XMEMCPY(ssl->arrays->serverRandom, input + i, RAN_LEN);
    i += RAN_LEN;
    /* TODO: [TLS13] Check last 8 bytes. */

    /* Set the cipher suite from the message. */
    ssl->options.cipherSuite0 = input[i++];
    ssl->options.cipherSuite  = input[i++];

    /* Get extension length and length check. */
    ato16(&input[i], &totalExtSz);
    i += OPAQUE16_LEN;
    if ((i - begin) + totalExtSz > helloSz)
        return BUFFER_ERROR;

    /* Parse and handle extensions. */
    ret = TLSX_Parse(ssl, (byte *) input + i, totalExtSz, server_hello, NULL);
    if (ret != 0)
        return ret;

    i += totalExtSz;
    *inOutIdx = i;

    ssl->options.serverState = SERVER_HELLO_COMPLETE;

#ifdef HAVE_SECRET_CALLBACK
    if (ssl->sessionSecretCb != NULL) {
        int secretSz = SECRET_LEN, ret;
        ret = ssl->sessionSecretCb(ssl, ssl->session.masterSecret,
                                   &secretSz, ssl->sessionSecretCtx);
        if (ret != 0 || secretSz != SECRET_LEN)
            return SESSION_SECRET_CB_E;
    }
#endif /* HAVE_SECRET_CALLBACK */

    ret = SetCipherSpecs(ssl);
    if (ret != 0)
        return ret;

#ifndef NO_PSK
    if (ssl->options.resuming) {
        PreSharedKey *psk = NULL;
        TLSX* ext = TLSX_Find(ssl->extensions, TLSX_PRE_SHARED_KEY);
        if (ext != NULL)
            psk = (PreSharedKey*)ext->data;
        while (psk != NULL && !psk->chosen)
            psk = psk->next;
        if (psk == NULL) {
            ssl->options.resuming = 0;
            ssl->arrays->psk_keySz = ssl->specs.hash_size;
            XMEMSET(ssl->arrays->psk_key, 0, ssl->arrays->psk_keySz);
        }
    }
#endif

    ssl->keys.encryptionOn = 1;

    return ret;
}

/* Parse and handle an EncryptedExtensions message.
 * Only a client will receive this message.
 *
 * ssl       The SSL/TLS object.
 * input     The message buffer.
 * inOutIdx  On entry, the index into the message buffer of
 *           EncryptedExtensions.
 *           On exit, the index of byte after the EncryptedExtensions
 *           message.
 * totalSz   The length of the current handshake message.
 * returns 0 on success and otherwise failure.
 */
static int DoTls13EncryptedExtensions(WOLFSSL* ssl, const byte* input,
                                      word32* inOutIdx, word32 totalSz)
{
    int    ret;
    word32 begin = *inOutIdx;
    word32 i = begin;
    word16 totalExtSz;

#ifdef WOLFSSL_CALLBACKS
    if (ssl->hsInfoOn) AddPacketName("EncryptedExtensions",
                                     &ssl->handShakeInfo);
    if (ssl->toInfoOn) AddLateName("EncryptedExtensions", &ssl->timeoutInfo);
#endif

    /* Length field of extension data. */
    if (totalSz < i - begin + OPAQUE16_LEN)
        return BUFFER_ERROR;
    ato16(&input[i], &totalExtSz);
    i += OPAQUE16_LEN;

    /* Extension data. */
    if (i - begin + totalExtSz > totalSz)
        return BUFFER_ERROR;
    if ((ret = TLSX_Parse(ssl, (byte *)(input + i), totalExtSz,
                          encrypted_extensions, NULL)))
        return ret;

    /* Move index to byte after message. */
    *inOutIdx = i + totalExtSz;

    /* Always encrypted. */
    *inOutIdx += ssl->keys.padSz;

    return 0;
}

/* Handle a TLS v1.3 CertificateRequest message.
 * This message is always encrypted.
 * Only a client will receive this message.
 *
 * ssl       The SSL/TLS object.
 * input     The message buffer.
 * inOutIdx  On entry, the index into the message buffer of CertificateRequest.
 *           On exit, the index of byte after the CertificateRequest message.
 * size      The length of the current handshake message.
 * returns 0 on success and otherwise failure.
 */
static int DoTls13CertificateRequest(WOLFSSL* ssl, const byte* input,
                                     word32* inOutIdx, word32 size)
{
    word16 len;
    word32 begin = *inOutIdx;

    #ifdef WOLFSSL_CALLBACKS
        if (ssl->hsInfoOn) AddPacketName("CertificateRequest",
                                         &ssl->handShakeInfo);
        if (ssl->toInfoOn) AddLateName("CertificateRequest", &ssl->timeoutInfo);
    #endif

    if ((*inOutIdx - begin) + OPAQUE8_LEN > size)
        return BUFFER_ERROR;

    /* Length of the request context. */
    len = input[(*inOutIdx)++];
    if ((*inOutIdx - begin) + len > size)
        return BUFFER_ERROR;
    if (ssl->options.connectState < FINISHED_DONE && len > 0)
        return BUFFER_ERROR;

    /* Request context parsed here. */
    /* TODO: [TLS13] Request context for post-handshake auth.
     * Store the value and return it in Certificate message.
     * Must be unique in the scope of the connection.
     */
    *inOutIdx += len;

    /* Signature and hash algorithms. */
    if ((*inOutIdx - begin) + OPAQUE16_LEN > size)
        return BUFFER_ERROR;
    ato16(input + *inOutIdx, &len);
    *inOutIdx += OPAQUE16_LEN;
    if ((*inOutIdx - begin) + len > size)
        return BUFFER_ERROR;
    PickHashSigAlgo(ssl, input + *inOutIdx, len);
    *inOutIdx += len;

    /* Length of certificate authority data. */
    if ((*inOutIdx - begin) + OPAQUE16_LEN > size)
        return BUFFER_ERROR;
    ato16(input + *inOutIdx, &len);
    *inOutIdx += OPAQUE16_LEN;
    if ((*inOutIdx - begin) + len > size)
        return BUFFER_ERROR;

    /* Certificate authorities. */
    while (len) {
        word16 dnSz;

        if ((*inOutIdx - begin) + OPAQUE16_LEN > size)
            return BUFFER_ERROR;

        ato16(input + *inOutIdx, &dnSz);
        *inOutIdx += OPAQUE16_LEN;

        if ((*inOutIdx - begin) + dnSz > size)
            return BUFFER_ERROR;

        *inOutIdx += dnSz;
        len -= OPAQUE16_LEN + dnSz;
    }

    /* TODO: [TLS13] Add extension handling. */
    /* Certificate extensions */
    if ((*inOutIdx - begin) + OPAQUE16_LEN > size)
        return BUFFER_ERROR;
    ato16(input + *inOutIdx, &len);
    *inOutIdx += OPAQUE16_LEN;
    if ((*inOutIdx - begin) + len > size)
        return BUFFER_ERROR;
    /* Skip over extensions for now. */
    *inOutIdx += len;

    ssl->options.sendVerify = SEND_CERT;

    /* This message is always encrypted so add encryption padding. */
    *inOutIdx += ssl->keys.padSz;

    return 0;
}

#endif /* !NO_WOLFSSL_CLIENT */

#ifndef NO_WOLFSSL_SERVER
#if defined(HAVE_SESSION_TICKET) && !defined(NO_PSK)
/* Handle any Pre-Shared Key (PSK) extension.
 * Must do this in ClientHello as it requires a hash of the truncated message.
 * Don't know size of binders until Pre-Shared Key extension has been parsed.
 *
 * ssl       The SSL/TLS object.
 * input     The ClientHello message.
 * helloSz   The size of the ClientHello message (including binders if present).
 * usingPSK  Indicates handshake is using Pre-Shared Keys.
 * returns 0 on success and otherwise failure.
 */
static int DoPreSharedKeys(WOLFSSL *ssl, const byte* input, word32 helloSz,
                           int* usingPSK)
{
    int           ret;
    TLSX*         ext;
    word16        bindersLen;
    PreSharedKey* current;
    byte          binderKey[MAX_DIGEST_SIZE];
    byte          binder[MAX_DIGEST_SIZE];
    word16        binderLen;
    word16        modes;

    ext = TLSX_Find(ssl->extensions, TLSX_PRE_SHARED_KEY);
    if (ext == NULL)
        return 0;

    /* Extensions pushed on stack/list and PSK must be last. */
    if (ssl->extensions != ext)
        return PSK_KEY_ERROR;

    /* Assume we are going to resume with a pre-shared key. */
    ssl->options.resuming = 1;

    /* Find the pre-shared key extension and calculate hash of truncated
     * ClientHello for binders.
     */
    bindersLen = TLSX_PreSharedKey_GetSizeBinders(ext->data, client_hello);

    /* Hash data up to binders for deriving binders in PSK extension. */
    ret = HashInput(ssl, input,  helloSz - bindersLen);
    if (ret != 0)
        return ret;

    /* Look through all client's pre-shared keys for a match. */
    current = (PreSharedKey*)ext->data;
    while (current != NULL) {
        /* TODO: [TLS13] Support non-ticket PSK. */
        /* Decode the identity. */
        ret = DoClientTicket(ssl, current->identity, current->identityLen);
        if (ret != WOLFSSL_TICKET_RET_OK)
            continue;

        if (current->resumption) {
            /* Check the ticket isn't too old or new. */
            int diff = TimeNowInMilliseconds() - ssl->session.ticketSeen;
            diff -= current->ticketAge - ssl->session.ticketAdd;
            /* TODO: [TLS13] What should the value be? Configurable? */
            if (diff < -1000 || diff > 1000) {
                /* Invalid difference, fallback to full handshake. */
                ssl->options.resuming = 0;
                break;
            }

            /* Use the same cipher suite as before and set up for use. */
            ssl->options.cipherSuite0 = ssl->session.cipherSuite0;
            ssl->options.cipherSuite  = ssl->session.cipherSuite;
            ret = SetCipherSpecs(ssl);
            if (ret != 0)
                return ret;

            /* Resumption PSK is resumption master secret. */
            ssl->arrays->psk_keySz = ssl->specs.hash_size;
            XMEMCPY(ssl->arrays->psk_key, ssl->session.masterSecret,
                    ssl->specs.hash_size);
            /* Derive the early secret using the PSK. */
            DeriveEarlySecret(ssl);
            /* Derive the binder key to use to with HMAC. */
            DeriveBinderKeyResume(ssl, binderKey);
        }
        else {
            /* PSK age is always zero. */
            if (current->ticketAge != ssl->session.ticketAdd)
                return PSK_KEY_ERROR;

            /* Get the pre-shared key. */
            ssl->arrays->psk_keySz = ssl->options.client_psk_cb(ssl,
                    (char*)current->identity, ssl->arrays->client_identity,
                    MAX_PSK_ID_LEN, ssl->arrays->psk_key, MAX_PSK_KEY_LEN);
            /* Derive the early secret using the PSK. */
            DeriveEarlySecret(ssl);
            /* Derive the binder key to use to with HMAC. */
            DeriveBinderKey(ssl, binderKey);
        }

        /* Derive the Finished message secret. */
        DeriveFinishedSecret(ssl, binderKey, ssl->keys.client_write_MAC_secret);
        /* Derive the binder and compare with the one in the extension. */
        binderLen = BuildTls13HandshakeHmac(ssl,
                ssl->keys.client_write_MAC_secret, binder);
        if (binderLen != current->binderLen ||
                XMEMCMP(binder, current->binder, binderLen) != 0) {
            return BAD_BINDER;
        }

        /* This PSK works, no need to try any more. */
        current->chosen = 1;
        ext->resp = 1;
        break;
    }

    /* Hash the rest of the ClientHello. */
    ret = HashInputRaw(ssl, input + helloSz - bindersLen, bindersLen);
    if (ret != 0)
        return ret;

    /* Get the PSK key exchange modes the client wants to negotiate. */
    ext = TLSX_Find(ssl->extensions, TLSX_PSK_KEY_EXCHANGE_MODES);
    if (ext == NULL)
        return MISSING_HANDSHAKE_DATA;
    modes = ext->val;

    ext = TLSX_Find(ssl->extensions, TLSX_KEY_SHARE);
    /* Use (EC)DHE for forward-security if possible. */
    if (ext != NULL && (modes & (1 << PSK_DHE_KE)) != 0 &&
            !ssl->options.noPskDheKe) {
        /* Only use named group used in last session. */
        ssl->namedGroup = ssl->session.namedGroup;

        /* Try to establish a new secret. */
        ret = TLSX_KeyShare_Establish(ssl);
        if (ret == KEY_SHARE_ERROR)
            return PSK_KEY_ERROR;
        else if (ret > 0)
            ret = 0;

        /* Send new public key to client. */
        ext->resp = 1;
    }
    else if ((modes & (1 << PSK_KE)) != 0) {
        /* Don't send a key share extension back. */
        if (ext != NULL)
            ext->resp = 0;
    }
    else
        return PSK_KEY_ERROR;

    *usingPSK = 1;

    return ret;
}
#endif

/* Handle a ClientHello handshake message.
 * If the protocol version in the message is not TLS v1.3 or higher, use
 * DoClientHello()
 * Only a server will receive this message.
 *
 * ssl       The SSL/TLS object.
 * input     The message buffer.
 * inOutIdx  On entry, the index into the message buffer of ClientHello.
 *           On exit, the index of byte after the ClientHello message and
 *           padding.
 * helloSz   The length of the current handshake message.
 * returns 0 on success and otherwise failure.
 */
static int DoTls13ClientHello(WOLFSSL* ssl, const byte* input, word32* inOutIdx,
                              word32 helloSz)
{
    int             ret;
    byte            b;
    ProtocolVersion pv;
    Suites          clSuites;
    word32          i = *inOutIdx;
    word32          begin = i;
    word16          totalExtSz;
    int             usingPSK = 0;

#ifdef WOLFSSL_CALLBACKS
    if (ssl->hsInfoOn) AddPacketName("ClientHello", &ssl->handShakeInfo);
    if (ssl->toInfoOn) AddLateName("ClientHello", &ssl->timeoutInfo);
#endif

    /* protocol version, random and session id length check */
    if ((i - begin) + OPAQUE16_LEN + RAN_LEN + OPAQUE8_LEN > helloSz)
        return BUFFER_ERROR;

    /* Protocol version */
    XMEMCPY(&pv, input + i, OPAQUE16_LEN);
    ssl->chVersion = pv;   /* store */
    i += OPAQUE16_LEN;

    if ((ssl->version.major == SSLv3_MAJOR &&
         ssl->version.minor < TLSv1_3_MINOR) || ssl->options.dtls) {
        return DoClientHello(ssl, input, inOutIdx, helloSz);
    }

    /* Client random */
    XMEMCPY(ssl->arrays->clientRandom, input + i, RAN_LEN);
    i += RAN_LEN;

#ifdef WOLFSSL_DEBUG_TLS
    WOLFSSL_MSG("client random");
    WOLFSSL_BUFFER(ssl->arrays->clientRandom, RAN_LEN);
#endif


    /* Session id - empty in TLS v1.3 */
    b = input[i++];
    if (b != 0) {
        WOLFSSL_MSG("Client sent session id - not supported");
        return BUFFER_ERROR;
    }

    /* Cipher suites */
    if ((i - begin) + OPAQUE16_LEN > helloSz)
        return BUFFER_ERROR;
    ato16(&input[i], &clSuites.suiteSz);
    i += OPAQUE16_LEN;
    /* suites and compression length check */
    if ((i - begin) + clSuites.suiteSz + OPAQUE8_LEN > helloSz)
        return BUFFER_ERROR;
    if (clSuites.suiteSz > WOLFSSL_MAX_SUITE_SZ)
        return BUFFER_ERROR;
    XMEMCPY(clSuites.suites, input + i, clSuites.suiteSz);
    i += clSuites.suiteSz;
    clSuites.hashSigAlgoSz = 0;

    /* Compression */
    b = input[i++];
    if ((i - begin) + b > helloSz)
        return BUFFER_ERROR;
    if (b != COMP_LEN) {
        WOLFSSL_MSG("Must be one compression type in list");
        return INVALID_PARAMETER;
    }
    b = input[i++];
    if (b != NO_COMPRESSION) {
        WOLFSSL_MSG("Must be no compression type in list");
        return INVALID_PARAMETER;
    }

    /* TLS v1.3 ClientHello messages will have extensions. */
    if ((i - begin) >= helloSz) {
        WOLFSSL_MSG("ClientHello must have extensions in TLS v1.3");
        return BUFFER_ERROR;
    }
    if ((i - begin) + OPAQUE16_LEN > helloSz)
        return BUFFER_ERROR;
    ato16(&input[i], &totalExtSz);
    i += OPAQUE16_LEN;
    if ((i - begin) + totalExtSz > helloSz)
        return BUFFER_ERROR;

#ifdef HAVE_QSH
    QSH_Init(ssl);
#endif

    /* Auto populate extensions supported unless user defined. */
    if ((ret = TLSX_PopulateExtensions(ssl, 1)) != 0)
        return ret;

    /* Parse extensions */
    if ((ret = TLSX_Parse(ssl, (byte*)input + i, totalExtSz, client_hello,
                          &clSuites))) {
        return ret;
    }

#ifdef HAVE_STUNNEL
    if ((ret = SNI_Callback(ssl)) != 0)
        return ret;
#endif /*HAVE_STUNNEL*/

    if (TLSX_Find(ssl->extensions, TLSX_SUPPORTED_VERSIONS) == NULL)
        ssl->version.minor = pv.minor;

#if defined(HAVE_SESSION_TICKET) && !defined(NO_PSK)
    /* Process the Pre-Shared Key extension if present. */
    ret = DoPreSharedKeys(ssl, input + begin, helloSz, &usingPSK);
    if (ret != 0)
        return ret;
#endif

    if (!usingPSK) {
        ret = MatchSuite(ssl, &clSuites);
        if (ret < 0) {
            WOLFSSL_MSG("Unsupported cipher suite, ClientHello");
            return ret;
        }

#ifndef NO_PSK
        if (ssl->options.resuming) {
            ssl->options.resuming = 0;
            XMEMSET(ssl->arrays->psk_key, 0, ssl->specs.hash_size);
            /* May or may not have done any hashing. */
            ret = InitHandshakeHashes(ssl);
            if (ret != 0)
                return ret;
        }
#endif

        ret = HashInput(ssl, input + begin,  helloSz);
        if (ret != 0)
            return ret;
    }

    i += totalExtSz;
    *inOutIdx = i;

    ssl->options.clientState = CLIENT_HELLO_COMPLETE;

    return 0;
}

/* Send the HelloRetryRequest message to indicate the negotiated protocol
 * version and security parameters the server is willing to use.
 * Only a server will send this message.
 *
 * ssl  The SSL/TLS object.
 * returns 0 on success, otherwise failure.
 */
int SendTls13HelloRetryRequest(WOLFSSL *ssl)
{
    int    ret;
    byte*  output;
    word32 length;
    word32 len;
    word32 idx = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ;
    int    sendSz;

    /* Get the length of the extensions that will be written. */
    len = TLSX_GetResponseSize(ssl, hello_retry_request);
    /* There must be extensions sent to indicate what client needs to do. */
    if (len == 0)
        return MISSING_HANDSHAKE_DATA;

    /* Protocol version + Extensions */
    length = OPAQUE16_LEN + len;
    sendSz = idx + length;

    /* Check buffers are big enough and grow if needed. */
    ret = CheckAvailableSize(ssl, sendSz);
    if (ret != 0)
        return ret;

    /* Get position in output buffer to write new message to. */
    output = ssl->buffers.outputBuffer.buffer +
             ssl->buffers.outputBuffer.length;
    /* Add record and hanshake headers. */
    AddTls13Headers(output, length, hello_retry_request, ssl);

    /* TODO: [TLS13] Replace existing code with code in comment.
     * Use the TLS v1.3 draft version for now.
     *
     * Change to:
     * output[idx++] = ssl->version.major;
     * output[idx++] = ssl->version.minor;
     */
    /* The negotiated protocol version. */
    output[idx++] = TLS_DRAFT_MAJOR;
    output[idx++] = TLS_DRAFT_MINOR;

    /* Add TLS extensions. */
    TLSX_WriteResponse(ssl, output + idx, hello_retry_request);
    idx += len;

#ifdef WOLFSSL_CALLBACKS
    if (ssl->hsInfoOn)
        AddPacketName("HelloRetryRequest", &ssl->handShakeInfo);
    if (ssl->toInfoOn)
        AddPacketInfo("HelloRetryRequest", &ssl->timeoutInfo, output, sendSz,
                      ssl->heap);
#endif

    ret = HashOutput(ssl, output, idx, 0);
    if (ret != 0)
        return ret;

    ssl->buffers.outputBuffer.length += sendSz;

    if (ssl->options.groupMessages)
        return 0;
    else
        return SendBuffered(ssl);
}

/* Send TLS v1.3 ServerHello message to client.
 * Only a server will send this message.
 *
 * ssl  The SSL/TLS object.
 * returns 0 on success, otherwise failure.
 */
int SendTls13ServerHello(WOLFSSL* ssl)
{
    byte*  output;
    word32 length;
    word32 idx = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ;
    int    sendSz;
    int    ret;

    /* Protocol version, server random, cipher suite and extensions. */
    length = VERSION_SZ + RAN_LEN + SUITE_LEN +
             TLSX_GetResponseSize(ssl, server_hello);
    sendSz = idx + length;

    /* Check buffers are big enough and grow if needed. */
    if ((ret = CheckAvailableSize(ssl, sendSz)) != 0)
        return ret;

    /* Get position in output buffer to write new message to. */
    output = ssl->buffers.outputBuffer.buffer +
             ssl->buffers.outputBuffer.length;

    /* Put the record and handshake headers on. */
    AddTls13Headers(output, length, server_hello, ssl);

    /* Protocol version. */
    output[idx++] = ssl->version.major;
    output[idx++] = ssl->version.minor;

    /* TODO: [TLS13] Last 8 bytes have special meaning. */
    /* Generate server random. */
    ret = wc_RNG_GenerateBlock(ssl->rng, output + idx, RAN_LEN);
    if (ret != 0)
        return ret;
    /* Store in SSL for debugging. */
    XMEMCPY(ssl->arrays->serverRandom, output + idx, RAN_LEN);
    idx += RAN_LEN;

#ifdef WOLFSSL_DEBUG_TLS
    WOLFSSL_MSG("Server random");
    WOLFSSL_BUFFER(ssl->arrays->serverRandom, RAN_LEN);
#endif

    /* Chosen cipher suite */
    output[idx++] = ssl->options.cipherSuite0;
    output[idx++] = ssl->options.cipherSuite;

    /* Extensions */
    TLSX_WriteResponse(ssl, output + idx, server_hello);

    ssl->buffers.outputBuffer.length += sendSz;

    ret = HashOutput(ssl, output, sendSz, 0);
    if (ret != 0)
        return ret;

    #ifdef WOLFSSL_CALLBACKS
    if (ssl->hsInfoOn)
        AddPacketName("ServerHello", &ssl->handShakeInfo);
    if (ssl->toInfoOn)
        AddPacketInfo("ServerHello", &ssl->timeoutInfo, output, sendSz,
                      ssl->heap);
    #endif

    ssl->options.serverState = SERVER_HELLO_COMPLETE;

    if (ssl->options.groupMessages)
        return 0;
    else
        return SendBuffered(ssl);
}

/* Send the rest of the extensions encrypted under the handshake key.
 * This message is always encrypted in TLS v1.3.
 * Only a server will send this message.
 *
 * ssl  The SSL/TLS object.
 * returns 0 on success, otherwise failure.
 */
int SendTls13EncryptedExtensions(WOLFSSL *ssl)
{
    int    ret;
    byte*  output;
    word32 length;
    word32 idx = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ;
    int    sendSz;

    ssl->keys.encryptionOn = 1;

    /* Derive early secret for handshake secret. */
    if ((ret = DeriveEarlySecret(ssl)) != 0)
        return ret;
    /* Derive the handshake secret now that we are at first message to be
     * encrypted under the keys.
     */
    if ((ret = DeriveHandshakeSecret(ssl)) != 0)
        return ret;
    if ((ret = DeriveTls13Keys(ssl, handshake_key,
                               ENCRYPT_AND_DECRYPT_SIDE)) != 0)
        return ret;

    /* Setup encrypt/decrypt keys for following messages. */
    if ((ret = SetKeysSide(ssl, ENCRYPT_AND_DECRYPT_SIDE)) != 0)
        return ret;

    length = TLSX_GetResponseSize(ssl, encrypted_extensions);
    sendSz = idx + length;
    /* Encryption always on. */
    sendSz += MAX_MSG_EXTRA;

    /* Check buffers are big enough and grow if needed. */
    ret = CheckAvailableSize(ssl, sendSz);
    if (ret != 0)
        return ret;

    /* Get position in output buffer to write new message to. */
    output = ssl->buffers.outputBuffer.buffer +
             ssl->buffers.outputBuffer.length;

    /* Put the record and handshake headers on. */
    AddTls13Headers(output, length, encrypted_extensions, ssl);

    TLSX_WriteResponse(ssl, output + idx, encrypted_extensions);
    idx += length;

#ifdef WOLFSSL_CALLBACKS
    if (ssl->hsInfoOn)
        AddPacketName("EncryptedExtensions", &ssl->handShakeInfo);
    if (ssl->toInfoOn)
        AddPacketInfo("EncryptedExtensions", &ssl->timeoutInfo, output,
                      sendSz, ssl->heap);
#endif

    /* This handshake message is always encrypted. */
    sendSz = BuildTls13Message(ssl, output, sendSz, output + RECORD_HEADER_SZ,
                               idx - RECORD_HEADER_SZ, handshake, 1, 0);
    if (sendSz < 0)
        return sendSz;

    ssl->buffers.outputBuffer.length += sendSz;

    ssl->options.serverState = SERVER_ENCRYPTED_EXTENSIONS_COMPLETE;

    if (ssl->options.groupMessages)
        return 0;
    else
        return SendBuffered(ssl);
}

#ifndef NO_CERTS
/* Send the TLS v1.3 CertificateRequest message.
 * This message is always encrypted in TLS v1.3.
 * Only a server will send this message.
 *
 * ssl  The SSL/TLS object.
 * returns 0 on success, otherwise failure.
 */
int SendTls13CertificateRequest(WOLFSSL* ssl)
{
    byte   *output;
    int    ret;
    int    sendSz;
    int    reqCtxLen = 0;
    word32 i = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ;

    int  reqSz = OPAQUE8_LEN + reqCtxLen + REQ_HEADER_SZ + REQ_HEADER_SZ;

    reqSz += LENGTH_SZ + ssl->suites->hashSigAlgoSz;

    if (ssl->options.usingPSK_cipher || ssl->options.usingAnon_cipher)
        return 0;  /* not needed */

    sendSz = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ + reqSz;
    /* Always encrypted and make room for padding. */
    sendSz += MAX_MSG_EXTRA;

    /* Check buffers are big enough and grow if needed. */
    if ((ret = CheckAvailableSize(ssl, sendSz)) != 0)
        return ret;

    /* Get position in output buffer to write new message to. */
    output = ssl->buffers.outputBuffer.buffer +
             ssl->buffers.outputBuffer.length;

    /* Put the record and handshake headers on. */
    AddTls13Headers(output, reqSz, certificate_request, ssl);

    /* Certificate request context. */
    /* TODO: [TLS13] Request context for post-handshake auth.
     * Must be unique in the scope of the connection.
     */
    output[i++] = reqCtxLen;

    /* supported hash/sig */
    c16toa(ssl->suites->hashSigAlgoSz, &output[i]);
    i += LENGTH_SZ;

    XMEMCPY(&output[i], ssl->suites->hashSigAlgo, ssl->suites->hashSigAlgoSz);
    i += ssl->suites->hashSigAlgoSz;

    /* Certificate authorities not supported yet - empty buffer. */
    c16toa(0, &output[i]);
    i += REQ_HEADER_SZ;

    /* Certificate extensions. */
    /* TODO: [TLS13] Add extension handling. */
    c16toa(0, &output[i]);  /* auth's */
    i += REQ_HEADER_SZ;

    /* Always encrypted. */
    sendSz = BuildTls13Message(ssl, output, sendSz, output + RECORD_HEADER_SZ,
                               i - RECORD_HEADER_SZ, handshake, 1, 0);
    if (sendSz < 0)
        return sendSz;

    #ifdef WOLFSSL_CALLBACKS
        if (ssl->hsInfoOn)
            AddPacketName("CertificateRequest", &ssl->handShakeInfo);
        if (ssl->toInfoOn)
            AddPacketInfo("CertificateRequest", &ssl->timeoutInfo, output,
                          sendSz, ssl->heap);
    #endif

    ssl->buffers.outputBuffer.length += sendSz;
    if (!ssl->options.groupMessages)
        return SendBuffered(ssl);
    return 0;
}
#endif /* NO_CERTS */
#endif /* NO_WOLFSSL_SERVER */

#ifndef NO_CERTS
#if !defined(NO_RSA) || defined(HAVE_ECC)
/* Encode the signature algorithm into buffer.
 *
 * hashalgo  The hash algorithm.
 * hsType   The signature type.
 * output    The buffer to encode into.
 */
static INLINE void EncodeSigAlg(byte hashAlgo, byte hsType, byte* output)
{
    switch (hsType) {
#ifdef HAVE_ECC
        case DYNAMIC_TYPE_ECC:
            output[0] = hashAlgo;
            output[1] = ecc_dsa_sa_algo;
            break;
#endif
#ifndef NO_RSA
        case DYNAMIC_TYPE_RSA:
            output[0] = hashAlgo;
            output[1] = rsa_sa_algo;
            break;
#endif
        /* PSS signatures: 0x080[4-6] */
        /* ED25519: 0x0807 */
        /* ED448: 0x0808 */
    }
}

/* Decode the signature algorithm.
 *
 * input     The encoded signature algorithm.
 * hashalgo  The hash algorithm.
 * hsType   The signature type.
 */
static INLINE void DecodeSigAlg(byte* input, byte* hashAlgo, byte* hsType)
{
    switch (input[0]) {
        /* PSS signatures: 0x080[4-6] */
        /* ED25519: 0x0807 */
        /* ED448: 0x0808 */
        default:
            *hashAlgo = input[0];
            *hsType  = input[1];
            break;
    }
}

/* Get the hash of the messages so far.
 *
 * ssl   The SSL/TLS object.
 * hash  The buffer to write the hash to.
 * returns the length of the hash.
 */
static INLINE int GetMsgHash(WOLFSSL *ssl, byte* hash)
{
    switch (ssl->specs.mac_algorithm) {
    #ifndef NO_SHA256
        case sha256_mac:
            wc_Sha256GetHash(&ssl->hsHashes->hashSha256, hash);
            return SHA256_DIGEST_SIZE;
    #endif /* !NO_SHA256 */
    #ifdef WOLFSSL_SHA384
        case sha384_mac:
            wc_Sha384GetHash(&ssl->hsHashes->hashSha384, hash);
            return SHA384_DIGEST_SIZE;
    #endif /* WOLFSSL_SHA384 */
    #ifdef WOLFSSL_SHA512
        case sha512_mac:
            wc_Sha512GetHash(&ssl->hsHashes->hashSha512, hash);
            return SHA512_DIGEST_SIZE;
    #endif /* WOLFSSL_SHA512 */
    }
    return 0;
}

/* The length of the certificate verification label - client and server. */
#define CERT_VFY_LABEL_SZ    34
/* The server certificate verification label. */
static const byte serverCertVfyLabel[CERT_VFY_LABEL_SZ] =
    "TLS 1.3, server CertificateVerify";
/* The client certificate verification label. */
static const byte clientCertVfyLabel[CERT_VFY_LABEL_SZ] =
    "TLS 1.3, client CertificateVerify";

/* The number of prefix bytes for signature data. */
#define SIGNING_DATA_PREFIX_SZ     64
/* The prefix byte in the signature data. */
#define SIGNING_DATA_PREFIX_BYTE   0x20
/* Maximum length of the signature data. */
#define MAX_SIG_DATA_SZ            (SIGNING_DATA_PREFIX_SZ + \
                                    CERT_VFY_LABEL_SZ      + \
                                    MAX_DIGEST_SIZE)

/* Create the signature data for TLS v1.3 certificate verification.
 *
 * ssl        The SSL/TLS object.
 * sigData    The signature data.
 * sigDataSz  The length of the signature data.
 * check      Indicates this is a check not create.
 */
static void CreateSigData(WOLFSSL* ssl, byte* sigData, word16* sigDataSz,
                          int check)
{
    word16 idx;
    int side = ssl->options.side;

    /* Signature Data = Prefix | Label | Handshake Hash */
    XMEMSET(sigData, SIGNING_DATA_PREFIX_BYTE, SIGNING_DATA_PREFIX_SZ);
    idx = SIGNING_DATA_PREFIX_SZ;

    #ifndef NO_WOLFSSL_SERVER
    if ((side == WOLFSSL_SERVER_END && check) ||
        (side == WOLFSSL_CLIENT_END && !check)) {
        XMEMCPY(&sigData[idx], clientCertVfyLabel, CERT_VFY_LABEL_SZ);
    }
    #endif
    #ifndef NO_WOLFSSL_CLIENT
    if ((side == WOLFSSL_CLIENT_END && check) ||
        (side == WOLFSSL_SERVER_END && !check)) {
        XMEMCPY(&sigData[idx], serverCertVfyLabel, CERT_VFY_LABEL_SZ);
    }
    #endif
    idx += CERT_VFY_LABEL_SZ;

    *sigDataSz = idx + GetMsgHash(ssl, &sigData[idx]);
}

#ifndef NO_RSA
/* Encode the PKCS #1.5 RSA signature.
 *
 * sig        The buffer to place the encoded signature into.
 * sigData    The data to be signed.
 * sigDataSz  The size of the data to be signed.
 * hashAlgo   The hash algorithm to use when signing.
 * returns the length of the encoded signature or negative on error.
 */
static int CreateRSAEncodedSig(byte* sig, byte* sigData, int sigDataSz,
                               int hashAlgo)
{
    Digest digest;
    int    hashSz = 0;
    int    hashOid = 0;

    /* Digest the signature data. */
    switch (hashAlgo) {
#ifndef NO_WOLFSSL_SHA256
        case sha256_mac:
            wc_InitSha256(&digest.sha256);
            wc_Sha256Update(&digest.sha256, sigData, sigDataSz);
            wc_Sha256Final(&digest.sha256, sigData);
            wc_Sha256Free(&digest.sha256);
            hashSz = SHA256_DIGEST_SIZE;
            hashOid = SHA256h;
            break;
#endif
#ifdef WOLFSSL_SHA384
        case sha384_mac:
            wc_InitSha384(&digest.sha384);
            wc_Sha384Update(&digest.sha384, sigData, sigDataSz);
            wc_Sha384Final(&digest.sha384, sigData);
            wc_Sha384Free(&digest.sha384);
            hashSz = SHA384_DIGEST_SIZE;
            hashOid = SHA384h;
            break;
#endif
#ifdef WOLFSSL_SHA512
        case sha512_mac:
            wc_InitSha512(&digest.sha512);
            wc_Sha512Update(&digest.sha512, sigData, sigDataSz);
            wc_Sha512Final(&digest.sha512, sigData);
            wc_Sha512Free(&digest.sha512);
            hashSz = SHA512_DIGEST_SIZE;
            hashOid = SHA512h;
            break;
#endif
    }

    /* Encode the signature data as per PKCS #1.5 */
    return wc_EncodeSignature(sig, sigData, hashSz, hashOid);
}

/* Check that the decrypted signature matches the encoded signature
 * based on the digest of the signature data.
 *
 * ssl       The SSL/TLS object.
 * hashAlgo  The hash algorithm used to generate signature.
 * decSig    The decrypted signature.
 * decSigSz  The size of the decrypted signature.
 * returns 0 on success, otherwise failure.
 */
static int CheckRSASignature(WOLFSSL* ssl, int hashAlgo, byte* decSig,
                             word32 decSigSz)
{
    int    ret = 0;
    byte   sigData[MAX_SIG_DATA_SZ];
    word16 sigDataSz;
#ifdef WOLFSSL_SMALL_STACK
    byte*  encodedSig = NULL;
#else
    byte   encodedSig[MAX_ENCODED_SIG_SZ];
#endif
    word32 sigSz;

#ifdef WOLFSSL_SMALL_STACK
    encodedSig = (byte*)XMALLOC(MAX_ENCODED_SIG_SZ, ssl->heap,
                                DYNAMIC_TYPE_TMP_BUFFER);
    if (encodedSig == NULL) {
        ret = MEMORY_E;
        goto end;
    }
#endif

    CreateSigData(ssl, sigData, &sigDataSz, 1);
    sigSz = CreateRSAEncodedSig(encodedSig, sigData, sigDataSz, hashAlgo);
    /* Check the encoded and decrypted signature data match. */
    if (decSigSz != sigSz || decSig == NULL ||
            XMEMCMP(decSig, encodedSig, sigSz) != 0) {
        ret = VERIFY_CERT_ERROR;
    }

#ifdef WOLFSSL_SMALL_STACK
end:
    if (encodedSig != NULL)
        XFREE(encodedSig, ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}
#endif /* !NO_RSA */
#endif /* !NO_RSA || HAVE_ECC */

/* Get the next certificate from the list for writing into the TLS v1.3
 * Certificate message.
 *
 * data    The certificate list.
 * length  The length of the certificate data in the list.
 * idx     The index of the next certificate.
 * returns the length of the certificate data. 0 indicates no more certificates
 * in the list.
 */
static word32 NextCert(byte* data, word32 length, word32* idx)
{
    word32 len;

    /* Is index at end of list. */
    if (*idx == length)
        return 0;

    /* Length of the current ASN.1 encoded certificate. */
    c24to32(data + *idx, &len);
    /* Include the length field. */
    len += 3;

    /* Move index to next certificate and return the current certificate's
     * length.
     */
    *idx += len;
    return len;
}

/* Add certificate data and empty extension to output up to the fragment size.
 *
 * cert    The certificate data to write out.
 * len     The length of the certificate data.
 * idx     The start of the certificate data to write out.
 * fragSz  The maximum size of this fragment.
 * output  The buffer to write to.
 * returns the number of bytes written.
 */
static word32 AddCertExt(byte* cert, word32 len, word32 idx, word32 fragSz,
                         byte* output)
{
    word32 i = 0;
    word32 copySz = min(len - idx, fragSz);

    if (idx < len) {
        XMEMCPY(output, cert + idx, copySz);
        i = copySz;
    }

    if (copySz + OPAQUE16_LEN <= fragSz) {
        /* Empty extension */
        output[i++] = 0;
        output[i++] = 0;
    }

    return i;
}

/* Send the certificate for this end and any CAs that help with validation.
 * This message is always encrypted in TLS v1.3.
 *
 * ssl  The SSL/TLS object.
 * returns 0 on success, otherwise failure.
 */
int SendTls13Certificate(WOLFSSL* ssl)
{
    int    ret = 0;
    word32 certSz, certChainSz, headerSz, listSz, payloadSz;
    word32 length, maxFragment;
    word32 len = 0;
    word32 idx = 0;
    word32 offset = OPAQUE16_LEN;
    byte*  p = NULL;


    /* TODO: [TLS13] Request context for post-handshake auth.
     * Taken from request if post-handshake.
     */

    if (ssl->options.sendVerify == SEND_BLANK_CERT) {
        certSz = 0;
        certChainSz = 0;
        headerSz = CERT_HEADER_SZ;
        length = CERT_HEADER_SZ;
        listSz = 0;
    }
    else {
        if (!ssl->buffers.certificate) {
            WOLFSSL_MSG("Send Cert missing certificate buffer");
            return BUFFER_ERROR;
        }
        /* Certificate Data */
        certSz = ssl->buffers.certificate->length;
        /* Cert Req Ctx Len | Cert List Len | Cert Data Len */
        headerSz = OPAQUE8_LEN + CERT_HEADER_SZ + CERT_HEADER_SZ;
        /* Length of message data with one certificate and empty extensions. */
        length = headerSz + certSz + OPAQUE16_LEN;
        /* Length of list data with one certificate and empty extensions. */
        listSz = CERT_HEADER_SZ + certSz + OPAQUE16_LEN;

        /* Send rest of chain if sending cert (chain has leading size/s). */
        if (certSz > 0 && ssl->buffers.certChainCnt > 0) {
            /* The pointer to the current spot in the cert chain buffer. */
            p = ssl->buffers.certChain->buffer;
            /* Chain length including extensions. */
            certChainSz = ssl->buffers.certChain->length +
                          OPAQUE16_LEN * ssl->buffers.certChainCnt;
            length += certChainSz;
            listSz += certChainSz;
        }
        else
            certChainSz = 0;
    }

    payloadSz = length;

    if (ssl->fragOffset != 0)
        length -= (ssl->fragOffset + headerSz);

    maxFragment = MAX_RECORD_SIZE;

    #ifdef HAVE_MAX_FRAGMENT
    if (ssl->max_fragment != 0 && maxFragment >= ssl->max_fragment)
        maxFragment = ssl->max_fragment;
    #endif /* HAVE_MAX_FRAGMENT */

    while (length > 0 && ret == 0) {
        byte*  output = NULL;
        word32 fragSz = 0;
        word32 i = RECORD_HEADER_SZ;
        int    sendSz = RECORD_HEADER_SZ;

        if (ssl->fragOffset == 0)  {
            if (headerSz + certSz + OPAQUE16_LEN + certChainSz <=
                maxFragment - HANDSHAKE_HEADER_SZ) {

                fragSz = headerSz + certSz + OPAQUE16_LEN + certChainSz;
            }
            else {
                fragSz = maxFragment - HANDSHAKE_HEADER_SZ;
            }
            sendSz += fragSz + HANDSHAKE_HEADER_SZ;
            i += HANDSHAKE_HEADER_SZ;
        }
        else {
            fragSz = min(length, maxFragment);
            sendSz += fragSz;
        }

        sendSz += MAX_MSG_EXTRA;

        /* Check buffers are big enough and grow if needed. */
        if ((ret = CheckAvailableSize(ssl, sendSz)) != 0)
            return ret;

        /* Get position in output buffer to write new message to. */
        output = ssl->buffers.outputBuffer.buffer +
                 ssl->buffers.outputBuffer.length;

        if (ssl->fragOffset == 0) {
            AddTls13FragHeaders(output, fragSz, 0, payloadSz, certificate, ssl);

            /* Request context. */
            output[i++] = 0;
            length -= 1;
            fragSz -= 1;
            /* Certificate list length. */
            c32to24(listSz, output + i);
            i += CERT_HEADER_SZ;
            length -= CERT_HEADER_SZ;
            fragSz -= CERT_HEADER_SZ;
            /* Leaf certificate data length. */
            if (certSz > 0) {
                c32to24(certSz, output + i);
                i += CERT_HEADER_SZ;
                length -= CERT_HEADER_SZ;
                fragSz -= CERT_HEADER_SZ;
            }
        }
        else
            AddTls13RecordHeader(output, fragSz, handshake, ssl);

        /* TODO: [TLS13] Test with fragments and multiple CA certs */
        if (certSz > 0 && ssl->fragOffset < certSz + OPAQUE16_LEN) {
            /* Put in the leaf certificate and empty extension. */
            word32 copySz = AddCertExt(ssl->buffers.certificate->buffer, certSz,
                                       ssl->fragOffset, fragSz, output + i);

            i += copySz;
            ssl->fragOffset += copySz;
            length -= copySz;
            fragSz -= copySz;
        }
        if (certChainSz > 0 && fragSz > 0) {
            /* Put in the CA certificates with empty extensions. */
            while (fragSz > 0) {
                word32 l;

                if (offset == len + OPAQUE16_LEN) {
                    /* Find next CA certificate to write out. */
                    offset = 0;
                    len = NextCert(ssl->buffers.certChain->buffer,
                                   ssl->buffers.certChain->length, &idx);
                    if (len == 0)
                        break;
                }

                /* Write out certificate and empty extension. */
                l = AddCertExt(p, len, offset, fragSz, output + i);
                i += l;
                ssl->fragOffset += l;
                length -= l;
                fragSz -= l;
                offset += l;
            }
        }

        if ((int)i - RECORD_HEADER_SZ < 0) {
            WOLFSSL_MSG("Send Cert bad inputSz");
            return BUFFER_E;
        }

        /* This message is always encrypted. */
        sendSz = BuildTls13Message(ssl, output, sendSz,
                                   output + RECORD_HEADER_SZ,
                                   i - RECORD_HEADER_SZ, handshake, 1, 0);
        if (sendSz < 0)
            return sendSz;

        #ifdef WOLFSSL_CALLBACKS
            if (ssl->hsInfoOn)
                AddPacketName("Certificate", &ssl->handShakeInfo);
            if (ssl->toInfoOn)
                AddPacketInfo("Certificate", &ssl->timeoutInfo, output, sendSz,
                               ssl->heap);
        #endif

        ssl->buffers.outputBuffer.length += sendSz;
        if (!ssl->options.groupMessages)
            ret = SendBuffered(ssl);
    }

    if (ret != WANT_WRITE) {
        /* Clean up the fragment offset. */
        ssl->fragOffset = 0;
        if (ssl->options.side == WOLFSSL_SERVER_END)
            ssl->options.serverState = SERVER_CERT_COMPLETE;
    }

    return ret;
}

typedef struct Scv13Args {
    byte*  output; /* not allocated */
#ifndef NO_RSA
    byte*  verifySig;
#endif
    byte*  verify; /* not allocated */
    byte*  input;
    word32 idx;
    word32 sigLen;
    int    sendSz;
    word16 length;

    byte*  sigData;
    word16 sigDataSz;
} Scv13Args;

static void FreeScv13Args(WOLFSSL* ssl, void* pArgs)
{
    Scv13Args* args = (Scv13Args*)pArgs;

    (void)ssl;

#ifndef NO_RSA
    if (args->verifySig) {
        XFREE(args->verifySig, ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);
        args->verifySig = NULL;
    }
#endif
    if (args->sigData) {
        XFREE(args->sigData, ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);
        args->sigData = NULL;
    }
    if (args->input) {
        XFREE(args->input, ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);
        args->input = NULL;
    }
}

/* Send the TLS v1.3 CertificateVerify message.
 * A hash of all the message so far is used.
 * The signed data is:
 *     0x20 * 64 | context string | 0x00 | hash of messages
 * This message is always encrypted in TLS v1.3.
 *
 * ssl  The SSL/TLS object.
 * returns 0 on success, otherwise failure.
 */
int SendTls13CertificateVerify(WOLFSSL* ssl)
{
    int ret = 0;
    buffer* sig = &ssl->buffers.sig;
#ifdef WOLFSSL_ASYNC_CRYPT
    Scv13Args* args = (Scv13Args*)ssl->async.args;
    typedef char args_test[sizeof(ssl->async.args) >= sizeof(*args) ? 1 : -1];
    (void)sizeof(args_test);
#else
    Scv13Args  args[1];
#endif

    WOLFSSL_ENTER("SendTls13CertificateVerify");

#ifdef WOLFSSL_ASYNC_CRYPT
    ret = wolfSSL_AsyncPop(ssl, &ssl->options.asyncState);
    if (ret != WC_NOT_PENDING_E) {
        /* Check for error */
        if (ret < 0)
            goto exit_scv;
    }
    else
#endif
    {
        /* Reset state */
        ret = 0;
        ssl->options.asyncState = TLS_ASYNC_BEGIN;
        XMEMSET(args, 0, sizeof(Scv13Args));
    #ifdef WOLFSSL_ASYNC_CRYPT
        ssl->async.freeArgs = FreeScv13Args;
    #endif
    }

    switch(ssl->options.asyncState)
    {
        case TLS_ASYNC_BEGIN:
        {
            if (ssl->options.sendVerify == SEND_BLANK_CERT) {
                return 0;  /* sent blank cert, can't verify */
            }

            args->sendSz = MAX_CERT_VERIFY_SZ;
            /* Always encrypted.  */
            args->sendSz += MAX_MSG_EXTRA;

            /* check for available size */
            if ((ret = CheckAvailableSize(ssl, args->sendSz)) != 0) {
                goto exit_scv;
            }

            /* get output buffer */
            args->output = ssl->buffers.outputBuffer.buffer +
                           ssl->buffers.outputBuffer.length;

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_BUILD;
        } /* case TLS_ASYNC_BEGIN */

        case TLS_ASYNC_BUILD:
        {
            /* idx is used to track verify pointer offset to output */
            args->idx = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ;
            args->verify = &args->output[RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ];

            ret = DecodePrivateKey(ssl, &args->length);
            if (ret != 0)
                goto exit_scv;

            /* Add signature algorithm. */
            EncodeSigAlg(ssl->suites->hashAlgo, ssl->hsType, args->verify);

            /* Create the data to be signed. */
            args->sigData = (byte*)XMALLOC(MAX_SIG_DATA_SZ, ssl->heap,
                                                    DYNAMIC_TYPE_TMP_BUFFER);
            if (args->sigData == NULL) {
                ERROR_OUT(MEMORY_E, exit_scv);
            }

            CreateSigData(ssl, args->sigData, &args->sigDataSz, 0);

        #ifndef NO_RSA
            if (ssl->hsType == DYNAMIC_TYPE_RSA) {
                /* build encoded signature buffer */
                sig->length = MAX_ENCODED_SIG_SZ;
                sig->buffer = (byte*)XMALLOC(sig->length, ssl->heap,
                                                    DYNAMIC_TYPE_TMP_BUFFER);
                if (sig->buffer == NULL)
                    return MEMORY_E;

                /* Digest the signature data and encode. Used in verify too. */
                sig->length = CreateRSAEncodedSig(sig->buffer, args->sigData,
                    args->sigDataSz, ssl->suites->hashAlgo);
                if (ret != 0)
                    goto exit_scv;

                /* Maximum size of RSA Signature. */
                args->sigLen = args->length;
            }
        #endif /* !NO_RSA */
        #ifdef HAVE_ECC
            if (ssl->hsType == DYNAMIC_TYPE_ECC)
                sig->length = args->sendSz - args->idx - HASH_SIG_SIZE - VERIFY_HEADER;
        #endif /* HAVE_ECC */

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_DO;
        } /* case TLS_ASYNC_BUILD */

        case TLS_ASYNC_DO:
        {
        #ifdef HAVE_ECC
           if (ssl->hsType == DYNAMIC_TYPE_ECC) {
                ret = EccSign(ssl, args->sigData, args->sigDataSz,
                    args->verify + HASH_SIG_SIZE + VERIFY_HEADER,
                    &sig->length, (ecc_key*)ssl->hsKey,
            #if defined(HAVE_PK_CALLBACKS)
                    ssl->buffers.key->buffer, ssl->buffers.key->length,
                    ssl->EccSignCtx
            #else
                    NULL, 0, NULL
            #endif
                );
                args->length = sig->length;
            }
        #endif /* HAVE_ECC */
        #ifndef NO_RSA
            if (ssl->hsType == DYNAMIC_TYPE_RSA) {
                /* restore verify pointer */
                args->verify = &args->output[args->idx];

                ret = RsaSign(ssl, sig->buffer, sig->length,
                    args->verify + HASH_SIG_SIZE + VERIFY_HEADER, &args->sigLen,
                    (RsaKey*)ssl->hsKey,
                    ssl->buffers.key->buffer, ssl->buffers.key->length,
                #ifdef HAVE_PK_CALLBACKS
                    ssl->RsaSignCtx
                #else
                    NULL
                #endif
                );
                args->length = args->sigLen;
            }
        #endif /* !NO_RSA */

            /* Check for error */
            if (ret != 0) {
                goto exit_scv;
            }

            /* Add signature length. */
            c16toa(args->length, args->verify + HASH_SIG_SIZE);

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_VERIFY;
        } /* case TLS_ASYNC_DO */

        case TLS_ASYNC_VERIFY:
        {
            /* restore verify pointer */
            args->verify = &args->output[args->idx];

        #ifndef NO_RSA
            if (ssl->hsType == DYNAMIC_TYPE_RSA) {
                if (args->verifySig == NULL) {
                    args->verifySig = (byte*)XMALLOC(args->sigLen, ssl->heap,
                                                   DYNAMIC_TYPE_TMP_BUFFER);
                    if (args->verifySig == NULL) {
                        ERROR_OUT(MEMORY_E, exit_scv);
                    }
                    XMEMCPY(args->verifySig,
                        args->verify + HASH_SIG_SIZE + VERIFY_HEADER,
                        args->sigLen);
                }

                /* check for signature faults */
                ret = VerifyRsaSign(ssl, args->verifySig, args->sigLen,
                    sig->buffer, sig->length, (RsaKey*)ssl->hsKey);
            }
        #endif /* !NO_RSA */

            /* Check for error */
            if (ret != 0) {
                goto exit_scv;
            }

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_FINALIZE;
        } /* case TLS_ASYNC_VERIFY */

        case TLS_ASYNC_FINALIZE:
        {
            /* Put the record and handshake headers on. */
            AddTls13Headers(args->output, args->length + HASH_SIG_SIZE + VERIFY_HEADER,
                            certificate_verify, ssl);

            args->sendSz = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ + args->length +
                     HASH_SIG_SIZE + VERIFY_HEADER;

            /* This message is always encrypted. */
            args->sendSz = BuildTls13Message(ssl, args->output,
                                       MAX_CERT_VERIFY_SZ + MAX_MSG_EXTRA,
                                       args->output + RECORD_HEADER_SZ,
                                       args->sendSz - RECORD_HEADER_SZ, handshake,
                                       1, 0);
            if (args->sendSz < 0) {
                ret = args->sendSz;
                goto exit_scv;
            }

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_END;
        } /* case TLS_ASYNC_FINALIZE */

        case TLS_ASYNC_END:
        {
        #ifdef WOLFSSL_CALLBACKS
            if (ssl->hsInfoOn)
                AddPacketName("CertificateVerify", &ssl->handShakeInfo);
            if (ssl->toInfoOn)
                AddPacketInfo("CertificateVerify", &ssl->timeoutInfo,
                              args->output, args->sendSz, ssl->heap);
        #endif

            ssl->buffers.outputBuffer.length += args->sendSz;

            if (!ssl->options.groupMessages)
                ret = SendBuffered(ssl);
            break;
        }
        default:
            ret = INPUT_CASE_ERROR;
    } /* switch(ssl->options.asyncState) */

exit_scv:

    WOLFSSL_LEAVE("SendTls13CertificateVerify", ret);

#ifdef WOLFSSL_ASYNC_CRYPT
    /* Handle async operation */
    if (ret == WC_PENDING_E) {
        return ret;
    }
#endif /* WOLFSSL_ASYNC_CRYPT */

    /* Final cleanup */
    FreeScv13Args(ssl, args);
    FreeKeyExchange(ssl);

    return ret;
}


/* Parse and handle a TLS v1.3 Certificate message.
 *
 * ssl       The SSL/TLS object.
 * input     The message buffer.
 * inOutIdx  On entry, the index into the message buffer of Certificate.
 *           On exit, the index of byte after the Certificate message.
 * totalSz   The length of the current handshake message.
 * returns 0 on success and otherwise failure.
 */
static int DoTls13Certificate(WOLFSSL* ssl, byte* input, word32* inOutIdx,
                              word32 totalSz)
{
    return ProcessPeerCerts(ssl, input, inOutIdx, totalSz);
}

#if !defined(NO_RSA) || defined(HAVE_ECC)

typedef struct Dcv13Args {
    byte*  output; /* not allocated */
    word32 sendSz;
    word16 sz;
    word32 sigSz;
    word32 idx;
    word32 begin;
    byte   hashAlgo;
    byte   sigAlgo;

    byte*  sigData;
    word16 sigDataSz;
} Dcv13Args;

static void FreeDcv13Args(WOLFSSL* ssl, void* pArgs)
{
    Dcv13Args* args = (Dcv13Args*)pArgs;

    if (args->sigData) {
        XFREE(args->sigData, ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);
        args->sigData = NULL;
    }

    (void)ssl;
}

/* Parse and handle a TLS v1.3 CertificateVerify message.
 *
 * ssl       The SSL/TLS object.
 * input     The message buffer.
 * inOutIdx  On entry, the index into the message buffer of
 *           CertificateVerify.
 *           On exit, the index of byte after the CertificateVerify message.
 * totalSz   The length of the current handshake message.
 * returns 0 on success and otherwise failure.
 */
static int DoTls13CertificateVerify(WOLFSSL* ssl, byte* input,
                                    word32* inOutIdx, word32 totalSz)
{
    int         ret = 0;
    buffer*     sig = &ssl->buffers.sig;
#ifdef WOLFSSL_ASYNC_CRYPT
    Dcv13Args* args = (Dcv13Args*)ssl->async.args;
    typedef char args_test[sizeof(ssl->async.args) >= sizeof(*args) ? 1 : -1];
    (void)sizeof(args_test);
#else
    Dcv13Args  args[1];
#endif

    WOLFSSL_ENTER("DoTls13CertificateVerify");

#ifdef WOLFSSL_ASYNC_CRYPT
    ret = wolfSSL_AsyncPop(ssl, &ssl->options.asyncState);
    if (ret != WC_NOT_PENDING_E) {
        /* Check for error */
        if (ret < 0)
            goto exit_dcv;
    }
    else
#endif
    {
        /* Reset state */
        ret = 0;
        ssl->options.asyncState = TLS_ASYNC_BEGIN;
        XMEMSET(args, 0, sizeof(Dcv13Args));
        args->hashAlgo = sha_mac;
        args->sigAlgo = anonymous_sa_algo;
        args->idx = *inOutIdx;
        args->begin = *inOutIdx;
    #ifdef WOLFSSL_ASYNC_CRYPT
        ssl->async.freeArgs = FreeDcv13Args;
    #endif
    }

    switch(ssl->options.asyncState)
    {
        case TLS_ASYNC_BEGIN:
        {
        #ifdef WOLFSSL_CALLBACKS
            if (ssl->hsInfoOn) AddPacketName("CertificateVerify",
                                             &ssl->handShakeInfo);
            if (ssl->toInfoOn) AddLateName("CertificateVerify",
                                           &ssl->timeoutInfo);
        #endif

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_BUILD;
        } /* case TLS_ASYNC_BEGIN */

        case TLS_ASYNC_BUILD:
        {
            /* Signature algorithm. */
            if ((args->idx - args->begin) + ENUM_LEN + ENUM_LEN > totalSz) {
                ERROR_OUT(BUFFER_ERROR, exit_dcv);
            }
            DecodeSigAlg(input + args->idx, &args->hashAlgo, &args->sigAlgo);
            args->idx += OPAQUE16_LEN;
            /* TODO: [TLS13] was it in SignatureAlgorithms extension? */

            /* Signature length. */
            if ((args->idx - args->begin) + OPAQUE16_LEN > totalSz) {
                ERROR_OUT(BUFFER_ERROR, exit_dcv);
            }
            ato16(input + args->idx, &args->sz);
            args->idx += OPAQUE16_LEN;

            /* Signature data. */
            if ((args->idx - args->begin) + args->sz > totalSz || args->sz > ENCRYPT_LEN) {
                ERROR_OUT(BUFFER_ERROR, exit_dcv);
            }

            /* Check for public key of required type. */
            if (args->sigAlgo == ecc_dsa_sa_algo && !ssl->peerEccDsaKeyPresent) {
                WOLFSSL_MSG("Oops, peer sent ECC key but not in verify");
            }
            if (args->sigAlgo == rsa_sa_algo &&
                (ssl->peerRsaKey == NULL || !ssl->peerRsaKeyPresent)) {
                WOLFSSL_MSG("Oops, peer sent RSA key but not in verify");
            }

            sig->buffer = XMALLOC(args->sz, ssl->heap, DYNAMIC_TYPE_TMP_BUFFER);
            if (sig->buffer == NULL) {
                ERROR_OUT(MEMORY_E, exit_dcv);
            }
            sig->length = args->sz;
            XMEMCPY(sig->buffer, input + args->idx, args->sz);

        #ifdef HAVE_ECC
            if (ssl->peerEccDsaKeyPresent) {
                WOLFSSL_MSG("Doing ECC peer cert verify");

                args->sigData = (byte*)XMALLOC(MAX_SIG_DATA_SZ, ssl->heap,
                                                    DYNAMIC_TYPE_TMP_BUFFER);
                if (args->sigData == NULL) {
                    ERROR_OUT(MEMORY_E, exit_dcv);
                }

                CreateSigData(ssl, args->sigData, &args->sigDataSz, 1);
            }
        #endif

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_DO;
        } /* case TLS_ASYNC_BUILD */

        case TLS_ASYNC_DO:
        {
        #ifndef NO_RSA
            if (ssl->peerRsaKey != NULL && ssl->peerRsaKeyPresent) {
                WOLFSSL_MSG("Doing RSA peer cert verify");

                ret = RsaVerify(ssl, sig->buffer, sig->length, &args->output,
                    ssl->peerRsaKey,
                #ifdef HAVE_PK_CALLBACKS
                    ssl->buffers.peerRsaKey.buffer,
                    ssl->buffers.peerRsaKey.length,
                    ssl->RsaVerifyCtx
                #else
                    NULL, 0, NULL
                #endif
                );
                if (ret >= 0) {
                    args->sendSz = ret;
                    ret = 0;
                }
            }
        #endif /* !NO_RSA */
        #ifdef HAVE_ECC
            if (ssl->peerEccDsaKeyPresent) {
                WOLFSSL_MSG("Doing ECC peer cert verify");

                ret = EccVerify(ssl, input + args->idx, args->sz,
                    args->sigData, args->sigDataSz,
                    ssl->peerEccDsaKey,
                #ifdef HAVE_PK_CALLBACKS
                    ssl->buffers.peerEccDsaKey.buffer,
                    ssl->buffers.peerEccDsaKey.length,
                    ssl->EccVerifyCtx
                #else
                    NULL, 0, NULL
                #endif
                );
            }
        #endif /* HAVE_ECC */

            /* Check for error */
            if (ret != 0) {
                goto exit_dcv;
            }

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_VERIFY;
        } /* case TLS_ASYNC_DO */

        case TLS_ASYNC_VERIFY:
        {
        #ifndef NO_RSA
            if (ssl->peerRsaKey != NULL && ssl->peerRsaKeyPresent != 0) {
                ret = CheckRSASignature(ssl, args->hashAlgo, args->output, args->sendSz);
                if (ret != 0)
                    goto exit_dcv;
            }
        #endif /* !NO_RSA */

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_FINALIZE;
        } /* case TLS_ASYNC_VERIFY */

        case TLS_ASYNC_FINALIZE:
        {
            ssl->options.havePeerVerify = 1;

            /* Set final index */
            args->idx += args->sz;
            *inOutIdx = args->idx;

            /* Encryption is always on: add padding */
            *inOutIdx += ssl->keys.padSz;

            /* Advance state and proceed */
            ssl->options.asyncState = TLS_ASYNC_END;
        } /* case TLS_ASYNC_FINALIZE */

        case TLS_ASYNC_END:
        {
            break;
        }
        default:
            ret = INPUT_CASE_ERROR;
    } /* switch(ssl->options.asyncState) */

exit_dcv:

    WOLFSSL_LEAVE("DoTls13CertificateVerify", ret);

#ifdef WOLFSSL_ASYNC_CRYPT
    /* Handle async operation */
    if (ret == WC_PENDING_E) {
        /* Mark message as not recevied so it can process again */
        ssl->msgsReceived.got_certificate_verify = 0;

        return ret;
    }
#endif /* WOLFSSL_ASYNC_CRYPT */

    /* Final cleanup */
    FreeDcv13Args(ssl, args);
    FreeKeyExchange(ssl);

    return ret;
}
#endif /* !NO_RSA || HAVE_ECC */

/* Parse and handle a TLS v1.3 Finished message.
 *
 * ssl       The SSL/TLS object.
 * input     The message buffer.
 * inOutIdx  On entry, the index into the message buffer of Finished.
 *           On exit, the index of byte after the Finished message and padding.
 * size      Length of message data.
 * totalSz   Length of remaining data in the message buffer.
 * sniff     Indicates whether we are sniffing packets.
 * returns 0 on success and otherwise failure.
 */
static int DoTls13Finished(WOLFSSL* ssl, const byte* input, word32* inOutIdx,
                           word32 size, word32 totalSz, int sniff)
{
    int    ret;
    word32 finishedSz = 0;
    byte*  secret;
    byte   mac[MAX_DIGEST_SIZE];

    /* check against totalSz */
    if (*inOutIdx + size + ssl->keys.padSz > totalSz)
        return BUFFER_E;

    if (ssl->options.side == WOLFSSL_CLIENT_END) {
        /* All the handshake messages have been received to calculate
         * client and server finished keys.
         */
        ret = DeriveFinishedSecret(ssl, ssl->arrays->clientSecret,
                                   ssl->keys.client_write_MAC_secret);
        if (ret != 0)
            return ret;

        ret = DeriveFinishedSecret(ssl, ssl->arrays->serverSecret,
                                   ssl->keys.server_write_MAC_secret);
        if (ret != 0)
            return ret;

        secret = ssl->keys.server_write_MAC_secret;
    }
    else
        secret = ssl->keys.client_write_MAC_secret;
    finishedSz = BuildTls13HandshakeHmac(ssl, secret, mac);
    if (size != finishedSz)
        return BUFFER_ERROR;

    #ifdef WOLFSSL_CALLBACKS
        if (ssl->hsInfoOn) AddPacketName("Finished", &ssl->handShakeInfo);
        if (ssl->toInfoOn) AddLateName("Finished", &ssl->timeoutInfo);
    #endif

    if (sniff == NO_SNIFF) {
        /* Actually check verify data. */
        if (XMEMCMP(input + *inOutIdx, mac, size) != 0){
            WOLFSSL_MSG("Verify finished error on hashes");
            return VERIFY_FINISHED_ERROR;
        }
    }

    /* Force input exhaustion at ProcessReply by consuming padSz. */
    *inOutIdx += size + ssl->keys.padSz;

    if (ssl->options.side == WOLFSSL_SERVER_END) {
        /* Setup keys for application data messages from client. */
        if ((ret = SetKeysSide(ssl, DECRYPT_SIDE_ONLY)) != 0)
            return ret;
    }

#ifndef NO_WOLFSSL_SERVER
    if (ssl->options.side == WOLFSSL_CLIENT_END) {
        ssl->options.serverState = SERVER_FINISHED_COMPLETE;
        if (!ssl->options.resuming) {
            ssl->options.handShakeState = HANDSHAKE_DONE;
            ssl->options.handShakeDone  = 1;
        }
    }
#endif
#ifndef NO_WOLFSSL_CLIENT
    if (ssl->options.side == WOLFSSL_SERVER_END) {
        ssl->options.clientState = CLIENT_FINISHED_COMPLETE;
        ssl->options.handShakeState = HANDSHAKE_DONE;
        ssl->options.handShakeDone  = 1;
    }
#endif

    return 0;
}
#endif /* NO_CERTS */

/* Send the TLS v1.3 Finished message.
 *
 * ssl  The SSL/TLS object.
 * returns 0 on success, otherwise failure.
 */
int SendTls13Finished(WOLFSSL* ssl)
{
    int   sendSz;
    int   finishedSz = ssl->specs.hash_size;
    byte* input;
    byte* output;
    int   ret;
    int   headerSz = HANDSHAKE_HEADER_SZ;
    int   outputSz;
    byte* secret;

    outputSz = MAX_DIGEST_SIZE + DTLS_HANDSHAKE_HEADER_SZ + MAX_MSG_EXTRA;
    /* Check buffers are big enough and grow if needed. */
    if ((ret = CheckAvailableSize(ssl, outputSz)) != 0)
        return ret;

    /* get output buffer */
    output = ssl->buffers.outputBuffer.buffer +
             ssl->buffers.outputBuffer.length;
    input = output + RECORD_HEADER_SZ;

    AddTls13HandShakeHeader(input, finishedSz, 0, finishedSz, finished, ssl);

    /* make finished hashes */
    if (ssl->options.side == WOLFSSL_CLIENT_END)
        secret = ssl->keys.client_write_MAC_secret;
    else {
        /* All the handshake messages have been done to calculate client and
         * server finished keys.
         */
        ret = DeriveFinishedSecret(ssl, ssl->arrays->clientSecret,
                                   ssl->keys.client_write_MAC_secret);
        if (ret != 0)
            return ret;

        ret = DeriveFinishedSecret(ssl, ssl->arrays->serverSecret,
                                   ssl->keys.server_write_MAC_secret);
        if (ret != 0)
            return ret;

        secret = ssl->keys.server_write_MAC_secret;
    }
    BuildTls13HandshakeHmac(ssl, secret, &input[headerSz]);

    /* This message is always encrypted. */
    sendSz = BuildTls13Message(ssl, output, outputSz, input,
                               headerSz + finishedSz, handshake, 1, 0);
    if (sendSz < 0)
        return BUILD_MSG_ERROR;

    if (!ssl->options.resuming) {
#ifndef NO_SESSION_CACHE
        AddSession(ssl);    /* just try */
#endif
    }
    else {
        if (ssl->options.side == WOLFSSL_CLIENT_END) {
            ssl->options.handShakeState = HANDSHAKE_DONE;
            ssl->options.handShakeDone  = 1;
        }
    }

    #ifdef WOLFSSL_CALLBACKS
        if (ssl->hsInfoOn) AddPacketName("Finished", &ssl->handShakeInfo);
        if (ssl->toInfoOn)
            AddPacketInfo("Finished", &ssl->timeoutInfo, output, sendSz,
                          ssl->heap);
    #endif

    ssl->buffers.outputBuffer.length += sendSz;

    ret = SendBuffered(ssl);
    if (ret != 0)
        return ret;

    if (ssl->options.side == WOLFSSL_SERVER_END) {
        /* Can send application data now. */
        if ((ret = DeriveMasterSecret(ssl)) != 0)
            return ret;
        if ((ret = DeriveTls13Keys(ssl, traffic_key,
                                   ENCRYPT_AND_DECRYPT_SIDE)) != 0)
            return ret;
        if ((ret = SetKeysSide(ssl, ENCRYPT_SIDE_ONLY)) != 0)
            return ret;
    }

    if (ssl->options.side == WOLFSSL_CLIENT_END) {
        /* Setup keys for application data messages. */
        if ((ret = SetKeysSide(ssl, ENCRYPT_AND_DECRYPT_SIDE)) != 0)
            return ret;

#ifndef NO_PSK
        ret = DeriveResumptionSecret(ssl, ssl->session.masterSecret);
#endif
    }

    return ret;
}

/* Send the TLS v1.3 KeyUpdate message.
 *
 * ssl  The SSL/TLS object.
 * returns 0 on success, otherwise failure.
 */
static int SendTls13KeyUpdate(WOLFSSL* ssl)
{
    int    sendSz;
    byte*  input;
    byte*  output;
    int    ret;
    int    headerSz = HANDSHAKE_HEADER_SZ;
    int    outputSz;
    word32 i = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ;

    outputSz = OPAQUE8_LEN + MAX_MSG_EXTRA;
    /* Check buffers are big enough and grow if needed. */
    if ((ret = CheckAvailableSize(ssl, outputSz)) != 0)
        return ret;

    /* get output buffer */
    output = ssl->buffers.outputBuffer.buffer +
             ssl->buffers.outputBuffer.length;
    input = output + RECORD_HEADER_SZ;

    AddTls13Headers(output, OPAQUE8_LEN, key_update, ssl);

    /* If:
     *   1. I haven't sent a KeyUpdate requesting a response and
     *   2. This isn't responding to peer KeyUpdate requiring a response then,
     * I want a response.
     */
    ssl->keys.updateResponseReq = output[i++] =
         !ssl->keys.updateResponseReq && !ssl->keys.keyUpdateRespond;
    /* Sent response, no longer need to respond. */
    ssl->keys.keyUpdateRespond = 0;

    /* This message is always encrypted. */
    sendSz = BuildTls13Message(ssl, output, outputSz, input,
                               headerSz + OPAQUE8_LEN, handshake, 0, 0);
    if (sendSz < 0)
        return BUILD_MSG_ERROR;

    #ifdef WOLFSSL_CALLBACKS
        if (ssl->hsInfoOn) AddPacketName("KeyUpdate", &ssl->handShakeInfo);
        if (ssl->toInfoOn)
            AddPacketInfo("KeyUpdate", &ssl->timeoutInfo, output, sendSz,
                          ssl->heap);
    #endif

    ssl->buffers.outputBuffer.length += sendSz;

    ret = SendBuffered(ssl);
    if (ret != 0 && ret != WANT_WRITE)
        return ret;

    /* Future traffic uses new encryption keys. */
    if ((ret = DeriveTls13Keys(ssl, update_traffic_key, ENCRYPT_SIDE_ONLY))
                                                                           != 0)
        return ret;
    if ((ret = SetKeysSide(ssl, ENCRYPT_SIDE_ONLY)) != 0)
        return ret;

    return ret;
}

/* Parse and handle a TLS v1.3 KeyUpdate message.
 *
 * ssl       The SSL/TLS object.
 * input     The message buffer.
 * inOutIdx  On entry, the index into the message buffer of Finished.
 *           On exit, the index of byte after the Finished message and padding.
 * totalSz   The length of the current handshake message.
 * returns 0 on success and otherwise failure.
 */
static int DoTls13KeyUpdate(WOLFSSL* ssl, const byte* input, word32* inOutIdx,
                            word32 totalSz)
{
    int    ret;
    word32 i = *inOutIdx;

    /* check against totalSz */
    if (OPAQUE8_LEN != totalSz)
        return BUFFER_E;

    switch (input[i]) {
        case update_not_requested:
            /* This message in response to any oustanding request. */
            ssl->keys.keyUpdateRespond = 0;
            ssl->keys.updateResponseReq = 0;
            break;
        case update_requested:
            /* New key update requiring a response. */
            ssl->keys.keyUpdateRespond = 1;
            break;
        default:
            return INVALID_PARAMETER;
            break;
    }

    /* Move index to byte after message. */
    *inOutIdx += totalSz;
    /* Always encrypted. */
    *inOutIdx += ssl->keys.padSz;

    /* Future traffic uses new decryption keys. */
    if ((ret = DeriveTls13Keys(ssl, update_traffic_key, DECRYPT_SIDE_ONLY)) != 0)
        return ret;
    if ((ret = SetKeysSide(ssl, DECRYPT_SIDE_ONLY)) != 0)
        return ret;

    if (ssl->keys.keyUpdateRespond)
        return SendTls13KeyUpdate(ssl);
    return 0;
}

#ifndef NO_WOLFSSL_CLIENT
/* Handle a New Session Ticket handshake message.
 * Message contains the information required to perform resumption.
 *
 * ssl       The SSL/TLS object.
 * input     The message buffer.
 * inOutIdx  On entry, the index into the message buffer of Finished.
 *           On exit, the index of byte after the Finished message and padding.
 * size      The length of the current handshake message.
 * retuns 0 on success, otherwise failure.
 */
static int DoTls13NewSessionTicket(WOLFSSL* ssl, const byte* input,
                                   word32* inOutIdx, word32 size)
{
#ifdef HAVE_SESSION_TICKET
    word32  begin = *inOutIdx;
    word32  lifetime;
    word32  ageAdd;
    word16  length;

    /* Lifetime hint. */
    if ((*inOutIdx - begin) + SESSION_HINT_SZ > size)
        return BUFFER_ERROR;
    ato32(input + *inOutIdx, &lifetime);
    *inOutIdx += SESSION_HINT_SZ;
    if (lifetime > MAX_LIFETIME)
        return SERVER_HINT_ERROR;

    /* Age add. */
    if ((*inOutIdx - begin) + SESSION_ADD_SZ > size)
        return BUFFER_ERROR;
    ato32(input + *inOutIdx, &ageAdd);
    *inOutIdx += SESSION_ADD_SZ;

    /* Ticket length. */
    if ((*inOutIdx - begin) + LENGTH_SZ > size)
        return BUFFER_ERROR;
    ato16(input + *inOutIdx, &length);
    *inOutIdx += LENGTH_SZ;
    if ((*inOutIdx - begin) + length > size)
        return BUFFER_ERROR;

    /* Free old dynamic ticket if we already had one. */
    if (ssl->session.isDynamic) {
        XFREE(ssl->session.ticket, ssl->heap, DYNAMIC_TYPE_SESSION_TICK);
        /* Reset back to static by default. */
        ssl->session.ticket = NULL;
        ssl->session.isDynamic = 0;
        ssl->session.ticket = ssl->session.staticTicket;
    }
    /* Use dynamic ticket if required.*/
    if (length > sizeof(ssl->session.staticTicket)) {
        ssl->session.ticket = (byte*)XMALLOC(length, ssl->heap,
                                             DYNAMIC_TYPE_SESSION_TICK);
        if (ssl->session.ticket == NULL)
            return MEMORY_E;
        ssl->session.isDynamic = 1;
    }

    /* Copy in ticket data (server identity). */
    XMEMCPY(ssl->session.ticket, input + *inOutIdx, length);
    *inOutIdx += length;
    ssl->timeout = lifetime;
    ssl->session.ticketLen = length;
    ssl->session.timeout = lifetime;
    ssl->session.ticketAdd = ageAdd;
    ssl->session.ticketSeen = TimeNowInMilliseconds();
    if (ssl->session_ticket_cb != NULL) {
        ssl->session_ticket_cb(ssl, ssl->session.ticket,
                               ssl->session.ticketLen,
                               ssl->session_ticket_ctx);
    }
    ssl->options.haveSessionId = 1;
    XMEMCPY(ssl->arrays->sessionID, ssl->session.ticket + length - ID_LEN,
            ID_LEN);
    ssl->session.cipherSuite0 = ssl->options.cipherSuite0;
    ssl->session.cipherSuite = ssl->options.cipherSuite;
    #ifndef NO_SESSION_CACHE
    AddSession(ssl);
    #endif

    /* No extension support - skip over extensions. */
    if ((*inOutIdx - begin) + EXTS_SZ > size)
        return BUFFER_ERROR;
    ato16(input + *inOutIdx, &length);
    *inOutIdx += EXTS_SZ;
    if ((*inOutIdx - begin) + length != size)
        return BUFFER_ERROR;
    *inOutIdx += length;

    /* Always encrypted. */
    *inOutIdx += ssl->keys.padSz;

    ssl->expect_session_ticket = 0;
#else
    (void)ssl;
    (void)input;
    *inOutIdx += size + ssl->keys.padSz;
#endif /* HAVE_SESSION_TICKET */

    return 0;
}
#endif /* NO_WOLFSSL_CLIENT */

#ifndef NO_WOLFSSL_SERVER
    #ifdef HAVE_SESSION_TICKET
/* Send New Session Ticket handshake message.
 * Message contains the information required to perform resumption.
 *
 * ssl  The SSL/TLS object.
 * retuns 0 on success, otherwise failure.
 */
int SendTls13NewSessionTicket(WOLFSSL* ssl)
{
    byte*  output;
    int    ret;
    int    sendSz;
    word32 length;
    word32 idx = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ;

    if (!ssl->options.noTicketTls13) {
        ret = CreateTicket(ssl);
        if (ret != 0) return ret;
    }

    /* Lifetime | Age Add | Ticket | Extensions */
    length = SESSION_HINT_SZ + SESSION_ADD_SZ + LENGTH_SZ +
             ssl->session.ticketLen + EXTS_SZ;
    sendSz = idx + length + MAX_MSG_EXTRA;

    /* Check buffers are big enough and grow if needed. */
    if ((ret = CheckAvailableSize(ssl, sendSz)) != 0)
        return ret;

    /* Get position in output buffer to write new message to. */
    output = ssl->buffers.outputBuffer.buffer +
             ssl->buffers.outputBuffer.length;

    /* Put the record and handshake headers on. */
    AddTls13Headers(output, length, session_ticket, ssl);

    /* Lifetime hint */
    c32toa(ssl->ctx->ticketHint, output + idx);
    idx += SESSION_HINT_SZ;
    /* Age add - obfuscator */
    c32toa(ssl->session.ticketAdd, output + idx);
    idx += SESSION_ADD_SZ;

    /* length */
    c16toa(ssl->session.ticketLen, output + idx);
    idx += LENGTH_SZ;
    /* ticket */
    XMEMCPY(output + idx, ssl->session.ticket, ssl->session.ticketLen);
    idx += ssl->session.ticketLen;

    /* No extension support - empty extensions. */
    c16toa(0, output + idx);
    idx += EXTS_SZ;

    ssl->options.haveSessionId = 1;

    #ifndef NO_SESSION_CACHE
    AddSession(ssl);
    #endif

    /* This message is always encrypted. */
    sendSz = BuildTls13Message(ssl, output, sendSz, output + RECORD_HEADER_SZ,
                               idx - RECORD_HEADER_SZ, handshake, 0, 0);
    if (sendSz < 0)
        return sendSz;

    ssl->buffers.outputBuffer.length += sendSz;

    return SendBuffered(ssl);
}
    #endif /* HAVE_SESSION_TICKET */
#endif /* NO_WOLFSSL_SERVER */

/* Make sure no duplicates, no fast forward, or other problems
 *
 * ssl   The SSL/TLS object.
 * type  Type of handshake message received.
 * returns 0 on success, otherwise failure.
 */
static int SanityCheckTls13MsgReceived(WOLFSSL* ssl, byte type)
{
    /* verify not a duplicate, mark received, check state */
    switch (type) {

#ifndef NO_WOLFSSL_SERVER
        case client_hello:
            if (ssl->msgsReceived.got_client_hello == 2) {
                WOLFSSL_MSG("Too many ClientHello received");
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_client_hello++;

            break;
#endif

#ifndef NO_WOLFSSL_CLIENT
        case server_hello:
            if (ssl->msgsReceived.got_server_hello) {
                WOLFSSL_MSG("Duplicate ServerHello received");
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_server_hello = 1;

            break;
#endif

#ifndef NO_WOLFSSL_CLIENT
        case session_ticket:
            if (ssl->msgsReceived.got_session_ticket) {
                WOLFSSL_MSG("Duplicate SessionTicket received");
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_session_ticket = 1;

            break;
#endif

#ifndef NO_WOLFSSL_CLIENT
        case hello_retry_request:
            if (ssl->msgsReceived.got_hello_retry_request) {
                WOLFSSL_MSG("Duplicate HelloRetryRequest received");
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_hello_retry_request = 1;

            break;
#endif

#ifndef NO_WOLFSSL_CLIENT
        case encrypted_extensions:
            if (ssl->msgsReceived.got_encrypted_extensions) {
                WOLFSSL_MSG("Duplicate EncryptedExtensions received");
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_encrypted_extensions = 1;

            break;
#endif

        case certificate:
            if (ssl->msgsReceived.got_certificate) {
                WOLFSSL_MSG("Duplicate Certificate received");
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_certificate = 1;

#ifndef NO_WOLFSSL_CLIENT
            if (ssl->options.side == WOLFSSL_CLIENT_END) {
                if ( ssl->msgsReceived.got_server_hello == 0) {
                    WOLFSSL_MSG("No ServerHello before Cert");
                    return OUT_OF_ORDER_E;
                }
            }
#endif
#ifndef NO_WOLFSSL_SERVER
            if (ssl->options.side == WOLFSSL_SERVER_END) {
                if ( ssl->msgsReceived.got_client_hello == 0) {
                    WOLFSSL_MSG("No ClientHello before Cert");
                    return OUT_OF_ORDER_E;
                }
            }
#endif
            break;

#ifndef NO_WOLFSSL_CLIENT
        case certificate_request:
            if (ssl->msgsReceived.got_certificate_request) {
                WOLFSSL_MSG("Duplicate CertificateRequest received");
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_certificate_request = 1;

            break;
#endif

        case certificate_verify:
            if (ssl->msgsReceived.got_certificate_verify) {
                WOLFSSL_MSG("Duplicate CertificateVerify received");
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_certificate_verify = 1;

            if (ssl->msgsReceived.got_certificate == 0) {
                WOLFSSL_MSG("No Cert before CertVerify");
                return OUT_OF_ORDER_E;
            }
            break;

        case finished:
            if (ssl->msgsReceived.got_finished) {
                WOLFSSL_MSG("Duplicate Finished received");
                return DUPLICATE_MSG_E;
            }
            ssl->msgsReceived.got_finished = 1;

            break;

        case key_update:
            if (!ssl->msgsReceived.got_finished) {
                WOLFSSL_MSG("No KeyUpdate before Finished");
                return OUT_OF_ORDER_E;
            }
            break;

        default:
            WOLFSSL_MSG("Unknown message type");
            return SANITY_MSG_E;
    }

    return 0;
}

/* Handle a type of handshake message that has been received.
 *
 * ssl       The SSL/TLS object.
 * input     The message buffer.
 * inOutIdx  On entry, the index into the buffer of the current message.
 *           On exit, the index into the buffer of the next message.
 * size      The length of the current handshake message.
 * totalSz   Length of remaining data in the message buffer.
 * returns 0 on success and otherwise failure.
 */
int DoTls13HandShakeMsgType(WOLFSSL* ssl, byte* input, word32* inOutIdx,
                            byte type, word32 size, word32 totalSz)
{
    int ret = 0;
    (void)totalSz;
    word32 inIdx = *inOutIdx;

    WOLFSSL_ENTER("DoTls13HandShakeMsgType");

    /* make sure can read the message */
    if (*inOutIdx + size > totalSz)
        return INCOMPLETE_DATA;

    /* sanity check msg received */
    if ( (ret = SanityCheckTls13MsgReceived(ssl, type)) != 0) {
        WOLFSSL_MSG("Sanity Check on handshake message type received failed");
        return ret;
    }

#ifdef WOLFSSL_CALLBACKS
    /* add name later, add on record and handshake header part back on */
    if (ssl->toInfoOn) {
        int add = RECORD_HEADER_SZ + HANDSHAKE_HEADER_SZ;
        AddPacketInfo(0, &ssl->timeoutInfo, input + *inOutIdx - add,
                      size + add, ssl->heap);
        AddLateRecordHeader(&ssl->curRL, &ssl->timeoutInfo);
    }
#endif

    if (ssl->options.handShakeState == HANDSHAKE_DONE &&
            type != session_ticket && type != certificate_request &&
            type != key_update) {
        WOLFSSL_MSG("HandShake message after handshake complete");
        SendAlert(ssl, alert_fatal, unexpected_message);
        return OUT_OF_ORDER_E;
    }

    if (ssl->options.side == WOLFSSL_CLIENT_END && !ssl->options.dtls &&
               ssl->options.serverState == NULL_STATE &&
               type != server_hello && type != hello_retry_request) {
        WOLFSSL_MSG("First server message not server hello");
        SendAlert(ssl, alert_fatal, unexpected_message);
        return OUT_OF_ORDER_E;
    }

    if (ssl->options.side == WOLFSSL_CLIENT_END && ssl->options.dtls &&
            type == server_hello_done &&
            ssl->options.serverState < SERVER_HELLO_COMPLETE) {
        WOLFSSL_MSG("Server hello done received before server hello in DTLS");
        SendAlert(ssl, alert_fatal, unexpected_message);
        return OUT_OF_ORDER_E;
    }

    if (ssl->options.side == WOLFSSL_SERVER_END &&
               ssl->options.clientState == NULL_STATE && type != client_hello) {
        WOLFSSL_MSG("First client message not client hello");
        SendAlert(ssl, alert_fatal, unexpected_message);
        return OUT_OF_ORDER_E;
    }

    /* above checks handshake state */
    switch (type) {

#ifndef NO_WOLFSSL_CLIENT
    case hello_retry_request:
        WOLFSSL_MSG("processing hello rety request");
        ret = DoTls13HelloRetryRequest(ssl, input, inOutIdx, size);
        break;

    case server_hello:
        WOLFSSL_MSG("processing server hello");
        ret = DoTls13ServerHello(ssl, input, inOutIdx, size);
        break;

#ifndef NO_CERTS
    case certificate_request:
        WOLFSSL_MSG("processing certificate request");
        ret = DoTls13CertificateRequest(ssl, input, inOutIdx, size);
        break;
#endif

    case session_ticket:
        WOLFSSL_MSG("processing new session ticket");
        ret = DoTls13NewSessionTicket(ssl, input, inOutIdx, size);
        break;

    case encrypted_extensions:
        WOLFSSL_MSG("processing encrypted extensions");
        ret = DoTls13EncryptedExtensions(ssl, input, inOutIdx, size);
        break;
#endif /* !NO_WOLFSSL_CLIENT */

#ifndef NO_CERTS
    case certificate:
        WOLFSSL_MSG("processing certificate");
        ret = DoTls13Certificate(ssl, input, inOutIdx, size);
        break;
#endif

#if !defined(NO_RSA) || defined(HAVE_ECC)
    case certificate_verify:
        WOLFSSL_MSG("processing certificate verify");
        ret = DoTls13CertificateVerify(ssl, input, inOutIdx, size);
        break;
#endif /* !NO_RSA || HAVE_ECC */

    case finished:
        WOLFSSL_MSG("processing finished");
        ret = DoTls13Finished(ssl, input, inOutIdx, size, totalSz, NO_SNIFF);
        break;

    case key_update:
        WOLFSSL_MSG("processing finished");
        ret = DoTls13KeyUpdate(ssl, input, inOutIdx, size);
        break;

#ifndef NO_WOLFSSL_SERVER
    case client_hello:
        WOLFSSL_MSG("processing client hello");
        ret = DoTls13ClientHello(ssl, input, inOutIdx, size);
        break;
#endif /* !NO_WOLFSSL_SERVER */

    default:
        WOLFSSL_MSG("Unknown handshake message type");
        ret = UNKNOWN_HANDSHAKE_TYPE;
        break;
    }

    if (ret == 0 && type != client_hello && type != session_ticket &&
        type != key_update && ssl->error != WC_PENDING_E) {
        ret = HashInput(ssl, input + inIdx, size);
    }

    if (ret == BUFFER_ERROR || ret == MISSING_HANDSHAKE_DATA)
        SendAlert(ssl, alert_fatal, decode_error);

    if (ret == EXT_NOT_ALLOWED || ret == PEER_KEY_ERROR ||
            ret == ECC_PEERKEY_ERROR || ret == BAD_KEY_SHARE_DATA ||
            ret == PSK_KEY_ERROR || ret == INVALID_PARAMETER) {
        SendAlert(ssl, alert_fatal, illegal_parameter);
    }

    if (ssl->options.tls1_3) {
        if (type == server_hello && ssl->options.side == WOLFSSL_CLIENT_END) {
            if ((ret = DeriveEarlySecret(ssl)) != 0)
                return ret;
            if ((ret = DeriveHandshakeSecret(ssl)) != 0)
                return ret;
            if ((ret = DeriveTls13Keys(ssl, handshake_key,
                                       ENCRYPT_AND_DECRYPT_SIDE)) != 0)
                return ret;

            /* setup decrypt keys for following messages */
            if ((ret = SetKeysSide(ssl, DECRYPT_SIDE_ONLY)) != 0)
                return ret;
            if ((ret = SetKeysSide(ssl, ENCRYPT_SIDE_ONLY)) != 0)
                return ret;
        }

        if (type == finished && ssl->options.side == WOLFSSL_CLIENT_END) {
            if ((ret = DeriveMasterSecret(ssl)) != 0)
                return ret;
            if ((ret = DeriveTls13Keys(ssl, traffic_key,
                                       ENCRYPT_AND_DECRYPT_SIDE)) != 0)
                return ret;
        }

#ifndef NO_PSK
        if (type == finished && ssl->options.side == WOLFSSL_SERVER_END)
            DeriveResumptionSecret(ssl, ssl->session.masterSecret);
#endif
    }

#ifdef WOLFSSL_ASYNC_CRYPT
    /* if async, offset index so this msg will be processed again */
    if (ret == WC_PENDING_E) {
        *inOutIdx -= HANDSHAKE_HEADER_SZ;
    }
#endif

    WOLFSSL_LEAVE("DoTls13HandShakeMsgType()", ret);
    return ret;
}


/* Handle a handshake message that has been received.
 *
 * ssl       The SSL/TLS object.
 * input     The message buffer.
 * inOutIdx  On entry, the index into the buffer of the current message.
 *           On exit, the index into the buffer of the next message.
 * totalSz   Length of remaining data in the message buffer.
 * returns 0 on success and otherwise failure.
 */
int DoTls13HandShakeMsg(WOLFSSL* ssl, byte* input, word32* inOutIdx,
                        word32 totalSz)
{
    int    ret = 0;
    word32 inputLength;

    WOLFSSL_ENTER("DoTls13HandShakeMsg()");

    if (ssl->arrays == NULL) {
        byte   type;
        word32 size;

        if (GetHandshakeHeader(ssl,input,inOutIdx,&type, &size, totalSz) != 0)
            return PARSE_ERROR;

        return DoTls13HandShakeMsgType(ssl, input, inOutIdx, type, size,
                                       totalSz);
    }

    inputLength = ssl->buffers.inputBuffer.length - *inOutIdx;

    /* If there is a pending fragmented handshake message,
     * pending message size will be non-zero. */
    if (ssl->arrays->pendingMsgSz == 0) {
        byte   type;
        word32 size;

        if (GetHandshakeHeader(ssl,input, inOutIdx, &type, &size, totalSz) != 0)
            return PARSE_ERROR;

        /* Cap the maximum size of a handshake message to something reasonable.
         * By default is the maximum size of a certificate message assuming
         * nine 2048-bit RSA certificates in the chain. */
        if (size > MAX_HANDSHAKE_SZ) {
            WOLFSSL_MSG("Handshake message too large");
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

        ret = DoTls13HandShakeMsgType(ssl, input, inOutIdx, type, size,
                                      totalSz);
    }
    else {
        if (inputLength + ssl->arrays->pendingMsgOffset >
                ssl->arrays->pendingMsgSz) {
            return BUFFER_ERROR;
        }

        XMEMCPY(ssl->arrays->pendingMsg + ssl->arrays->pendingMsgOffset,
                input + *inOutIdx, inputLength);
        ssl->arrays->pendingMsgOffset += inputLength;
        *inOutIdx += inputLength;

        if (ssl->arrays->pendingMsgOffset == ssl->arrays->pendingMsgSz)
        {
            word32 idx = 0;
            ret = DoTls13HandShakeMsgType(ssl,
                                ssl->arrays->pendingMsg + HANDSHAKE_HEADER_SZ,
                                &idx, ssl->arrays->pendingMsgType,
                                ssl->arrays->pendingMsgSz - HANDSHAKE_HEADER_SZ,
                                ssl->arrays->pendingMsgSz);
            XFREE(ssl->arrays->pendingMsg, ssl->heap, DYNAMIC_TYPE_ARRAYS);
            ssl->arrays->pendingMsg = NULL;
            ssl->arrays->pendingMsgSz = 0;
        }
    }

    WOLFSSL_LEAVE("DoTls13HandShakeMsg()", ret);
    return ret;
}

/* The client connecting to the server.
 * The protocol version is expecting to be TLS v1.3.
 * If the server downgrades, and older versions of the protocol are compiled
 * in, the client will fallback to wolfSSL_connect().
 * Please see note at top of README if you get an error from connect.
 *
 * ssl  The SSL/TLS object.
 * returns SSL_SUCCESS on successful handshake, SSL_FATAL_ERROR when
 * unrecoverable error occurs and 0 otherwise.
 * For more error information use wolfSSL_get_error().
 */
int wolfSSL_connect_TLSv13(WOLFSSL* ssl)
{
    int neededState;

    WOLFSSL_ENTER("wolfSSL_connect_TLSv13()");

    #ifdef HAVE_ERRNO_H
    errno = 0;
    #endif

    if (ssl->options.side != WOLFSSL_CLIENT_END) {
        WOLFSSL_ERROR(ssl->error = SIDE_ERROR);
        return SSL_FATAL_ERROR;
    }

    if (ssl->buffers.outputBuffer.length > 0) {
        if ((ssl->error = SendBuffered(ssl)) == 0) {
            /* fragOffset is non-zero when sending fragments. On the last
             * fragment, fragOffset is zero again, and the state can be
             * advanced. */
            if (ssl->fragOffset == 0) {
                ssl->options.connectState++;
                WOLFSSL_MSG("connect state: "
                            "Advanced from last buffered fragment send");
            }
            else {
                WOLFSSL_MSG("connect state: "
                            "Not advanced, more fragments to send");
            }
        }
        else {
            WOLFSSL_ERROR(ssl->error);
            return SSL_FATAL_ERROR;
        }
    }

    switch (ssl->options.connectState) {

        case CONNECT_BEGIN:
            /* Always send client hello first. */
            if ((ssl->error = SendTls13ClientHello(ssl)) != 0) {
                WOLFSSL_ERROR(ssl->error);
                return SSL_FATAL_ERROR;
            }

            ssl->options.connectState = CLIENT_HELLO_SENT;
            WOLFSSL_MSG("connect state: CLIENT_HELLO_SENT");

        case CLIENT_HELLO_SENT:
            neededState = ssl->options.resuming ? SERVER_FINISHED_COMPLETE :
                                                  SERVER_HELLODONE_COMPLETE;
            /* Get the response/s from the server. */
            while (ssl->options.serverState < neededState) {
                if ((ssl->error = ProcessReply(ssl)) < 0) {
                    WOLFSSL_ERROR(ssl->error);
                    return SSL_FATAL_ERROR;
                }
                /* if resumption failed, reset needed state. */
                if (neededState == SERVER_FINISHED_COMPLETE &&
                        !ssl->options.resuming) {
                    neededState = SERVER_HELLODONE_COMPLETE;
                }
            }

            ssl->options.connectState = HELLO_AGAIN;
            WOLFSSL_MSG("connect state: HELLO_AGAIN");
        case HELLO_AGAIN:
            if (ssl->options.certOnly)
                return SSL_SUCCESS;

            if (!ssl->options.tls1_3)
                return wolfSSL_connect(ssl);

            if (ssl->options.serverState == SERVER_HELLO_RETRY_REQUEST) {
                ssl->options.serverState = NULL_STATE;
                /* Try again with different security parameters. */
                if ((ssl->error = SendTls13ClientHello(ssl)) != 0) {
                    WOLFSSL_ERROR(ssl->error);
                    return SSL_FATAL_ERROR;
                }
            }

            ssl->options.connectState = HELLO_AGAIN_REPLY;
            WOLFSSL_MSG("connect state: HELLO_AGAIN_REPLY");

        case HELLO_AGAIN_REPLY:
            if (ssl->options.serverState == NULL_STATE) {
                neededState = ssl->options.resuming ? SERVER_FINISHED_COMPLETE :
                                                      SERVER_HELLODONE_COMPLETE;

                /* Get the response/s from the server. */
                while (ssl->options.serverState < neededState) {
                    if ((ssl->error = ProcessReply(ssl)) < 0) {
                            WOLFSSL_ERROR(ssl->error);
                            return SSL_FATAL_ERROR;
                    }
                    /* if resumption failed, reset needed state */
                    else if (neededState == SERVER_FINISHED_COMPLETE) {
                        if (!ssl->options.resuming)
                            neededState = SERVER_HELLODONE_COMPLETE;
                    }
                }
            }

            ssl->options.connectState = FIRST_REPLY_DONE;
            WOLFSSL_MSG("connect state: FIRST_REPLY_DONE");

        case FIRST_REPLY_DONE:
            #ifndef NO_CERTS
            if (!ssl->options.resuming && ssl->options.sendVerify) {
                ssl->error = SendTls13Certificate(ssl);
                if (ssl->error != 0) {
                    WOLFSSL_ERROR(ssl->error);
                    return SSL_FATAL_ERROR;
                }
                WOLFSSL_MSG("sent: certificate");
            }
            #endif

            ssl->options.connectState = FIRST_REPLY_FIRST;
            WOLFSSL_MSG("connect state: FIRST_REPLY_FIRST");

        case FIRST_REPLY_FIRST:
            #ifndef NO_CERTS
            if (!ssl->options.resuming && ssl->options.sendVerify) {
                ssl->error = SendTls13CertificateVerify(ssl);
                if (ssl->error != 0) {
                    WOLFSSL_ERROR(ssl->error);
                    return SSL_FATAL_ERROR;
                }
                WOLFSSL_MSG("sent: certificate verify");
            }
            #endif

            ssl->options.connectState = FIRST_REPLY_SECOND;
            WOLFSSL_MSG("connect state: FIRST_REPLY_SECOND");

        case FIRST_REPLY_SECOND:
            if ((ssl->error = SendTls13Finished(ssl)) != 0) {
                WOLFSSL_ERROR(ssl->error);
                return SSL_FATAL_ERROR;
            }
            WOLFSSL_MSG("sent: finished");

            ssl->options.connectState = FINISHED_DONE;
            WOLFSSL_MSG("connect state: FINISHED_DONE");

        case FINISHED_DONE:
#ifndef NO_HANDSHAKE_DONE_CB
            if (ssl->hsDoneCb != NULL) {
                int cbret = ssl->hsDoneCb(ssl, ssl->hsDoneCtx);
                if (cbret < 0) {
                    ssl->error = cbret;
                    WOLFSSL_MSG("HandShake Done Cb don't continue error");
                    return SSL_FATAL_ERROR;
                }
            }
#endif /* NO_HANDSHAKE_DONE_CB */

            WOLFSSL_LEAVE("SSL_connect()", SSL_SUCCESS);
            return SSL_SUCCESS;

        default:
            WOLFSSL_MSG("Unknown connect state ERROR");
            return SSL_FATAL_ERROR; /* unknown connect state */
    }
}

/* Create a key share entry from group.
 * Generates a key pair.
 *
 * ssl    The SSL/TLS object.
 * group  The named group.
 * returns 0 on success, otherwise failure.
 */
int wolfSSL_UseKeyShare(WOLFSSL* ssl, word16 group)
{
    int ret = BAD_FUNC_ARG;

    if (ssl == NULL)
        return BAD_FUNC_ARG;

    ret = TLSX_KeyShare_Use(ssl, group, 0, NULL, NULL);
    if (ret != 0)
        return ret;

    return SSL_SUCCESS;
}

/* Send no key share entries - use HelloRetryRequest to negotiate shared group.
 *
 * ssl    The SSL/TLS object.
 * returns 0 on success, otherwise failure.
 */
int wolfSSL_NoKeyShares(WOLFSSL* ssl)
{
    int ret = BAD_FUNC_ARG;

    if (ssl == NULL)
        return BAD_FUNC_ARG;

    ret = TLSX_KeyShare_Empty(ssl);
    if (ret != 0)
        return ret;

    return SSL_SUCCESS;
}

/* Do not send a ticket after TLS v1.3 handshake for resumption.
 *
 * ctx  The SSL/TLS CTX object.
 * returns BAD_FUNC_ARG when ctx is NULL and 0 on success.
 */
int wolfSSL_CTX_no_ticket_TLSv13(WOLFSSL_CTX* ctx)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

#ifdef HAVE_SESSION_TICKET
    ctx->noTicketTls13 = 1;
#endif

    return 0;
}

/* Do not send a ticket after TLS v1.3 handshake for resumption.
 *
 * ssl  The SSL/TLS object.
 * returns BAD_FUNC_ARG when ssl is NULL, not using TLS v1.3, or called on
 * a client and 0 on success.
 */
int wolfSSL_no_ticket_TLSv13(WOLFSSL* ssl)
{
    if (ssl == NULL || !IsAtLeastTLSv1_3(ssl->version) ||
            ssl->options.side == WOLFSSL_CLIENT_END)
        return BAD_FUNC_ARG;

#ifdef HAVE_SESSION_TICKET
    ssl->options.noTicketTls13 = 1;
#endif

    return 0;
}

/* Disallow (EC)DHE key exchange when using pre-shared keys.
 *
 * ctx  The SSL/TLS CTX object.
 * returns BAD_FUNC_ARG when ctx is NULL and 0 on success.
 */
int wolfSSL_CTX_no_dhe_psk(WOLFSSL_CTX* ctx)
{
    if (ctx == NULL)
        return BAD_FUNC_ARG;

    ctx->noPskDheKe = 1;

    return 0;
}

/* Disallow (EC)DHE key exchange when using pre-shared keys.
 *
 * ssl  The SSL/TLS object.
 * returns BAD_FUNC_ARG when ssl is NULL, or not using TLS v1.3 and 0 on
 * success.
 */
int wolfSSL_no_dhe_psk(WOLFSSL* ssl)
{
    if (ssl == NULL || !IsAtLeastTLSv1_3(ssl->version))
        return BAD_FUNC_ARG;

    ssl->options.noPskDheKe = 1;

    return 0;
}

/* Update the keys for encryption and decryption.
 * If using non-blocking I/O and SSL_ERROR_WANT_WRITE is returned then
 * calling wolfSSL_write() will have the message sent when ready.
 *
 * ssl  The SSL/TLS object.
 * returns BAD_FUNC_ARG when ssl is NULL, or not using TLS v1.3,
 * SSL_ERROR_WANT_WRITE when non-blocking I/O is not ready to write,
 * SSL_SUCCESS on success and otherwise failure.
 */
int wolfSSL_update_keys(WOLFSSL* ssl)
{
    int ret;

    if (ssl == NULL || !IsAtLeastTLSv1_3(ssl->version))
        return BAD_FUNC_ARG;

    ret = SendTls13KeyUpdate(ssl);
    if (ret == WANT_WRITE)
        ret = SSL_ERROR_WANT_WRITE;
    else if (ret == 0)
        ret = SSL_SUCCESS;
    return ret;
}

/* The server accepting a connection from a client.
 * The protocol version is expecting to be TLS v1.3.
 * If the client downgrades, and older versions of the protocol are compiled
 * in, the server will fallback to wolfSSL_accept().
 * Please see note at top of README if you get an error from accept.
 *
 * ssl  The SSL/TLS object.
 * returns SSL_SUCCESS on successful handshake, SSL_FATAL_ERROR when
 * unrecoverable error occurs and 0 otherwise.
 * For more error information use wolfSSL_get_error().
 */
int wolfSSL_accept_TLSv13(WOLFSSL* ssl)
{
    word16 havePSK = 0;
    word16 haveAnon = 0;
    WOLFSSL_ENTER("SSL_accept_TLSv13()");

#ifdef HAVE_ERRNO_H
    errno = 0;
#endif

#ifndef NO_PSK
    havePSK = ssl->options.havePSK;
#endif
    (void)havePSK;

#ifdef HAVE_ANON
    haveAnon = ssl->options.haveAnon;
#endif
    (void)haveAnon;

    if (ssl->options.side != WOLFSSL_SERVER_END) {
        WOLFSSL_ERROR(ssl->error = SIDE_ERROR);
        return SSL_FATAL_ERROR;
    }

#ifndef NO_CERTS
    /* in case used set_accept_state after init */
    if (!havePSK && !haveAnon &&
        (!ssl->buffers.certificate ||
         !ssl->buffers.certificate->buffer ||
         !ssl->buffers.key ||
         !ssl->buffers.key->buffer)) {
        WOLFSSL_MSG("accept error: don't have server cert and key");
        ssl->error = NO_PRIVATE_KEY;
        WOLFSSL_ERROR(ssl->error);
        return SSL_FATAL_ERROR;
    }
#endif
#ifdef WOLFSSL_DTLS
    if (ssl->version.major == DTLS_MAJOR) {
        ssl->options.dtls   = 1;
        ssl->options.tls    = 1;
        ssl->options.tls1_1 = 1;
    }
#endif

    if (ssl->buffers.outputBuffer.length > 0) {
        if ((ssl->error = SendBuffered(ssl)) == 0) {
            /* fragOffset is non-zero when sending fragments. On the last
             * fragment, fragOffset is zero again, and the state can be
             * advanced. */
            if (ssl->fragOffset == 0) {
                ssl->options.acceptState++;
                WOLFSSL_MSG("accept state: "
                            "Advanced from last buffered fragment send");
            }
            else {
                WOLFSSL_MSG("accept state: "
                            "Not advanced, more fragments to send");
            }
        }
        else {
            WOLFSSL_ERROR(ssl->error);
            return SSL_FATAL_ERROR;
        }
    }

    switch (ssl->options.acceptState) {

        case ACCEPT_BEGIN :
            /* get response */
            while (ssl->options.clientState < CLIENT_HELLO_COMPLETE)
                if ((ssl->error = ProcessReply(ssl)) < 0) {
                    WOLFSSL_ERROR(ssl->error);
                    return SSL_FATAL_ERROR;
                }

            ssl->options.acceptState = ACCEPT_CLIENT_HELLO_DONE;
            WOLFSSL_MSG("accept state ACCEPT_CLIENT_HELLO_DONE");

        case ACCEPT_CLIENT_HELLO_DONE :
            if (ssl->options.serverState == SERVER_HELLO_RETRY_REQUEST) {
                if ((ssl->error = SendTls13HelloRetryRequest(ssl)) != 0) {
                    WOLFSSL_ERROR(ssl->error);
                    return SSL_FATAL_ERROR;
                }
            }
            ssl->options.acceptState = ACCEPT_HELLO_RETRY_REQUEST_DONE;
            WOLFSSL_MSG("accept state ACCEPT_HELLO_RETRY_REQUEST_DONE");

        case ACCEPT_HELLO_RETRY_REQUEST_DONE :
            if (ssl->options.serverState == SERVER_HELLO_RETRY_REQUEST) {
                if ( (ssl->error = ProcessReply(ssl)) < 0) {
                    WOLFSSL_ERROR(ssl->error);
                    return SSL_FATAL_ERROR;
                }
            }
            ssl->options.acceptState = ACCEPT_FIRST_REPLY_DONE;
            WOLFSSL_MSG("accept state ACCEPT_FIRST_REPLY_DONE");

        case ACCEPT_FIRST_REPLY_DONE :
            if ((ssl->error = SendTls13ServerHello(ssl)) != 0) {
                WOLFSSL_ERROR(ssl->error);
                return SSL_FATAL_ERROR;
            }
            ssl->options.acceptState = SERVER_HELLO_SENT;
            WOLFSSL_MSG("accept state SERVER_HELLO_SENT");

        case SERVER_HELLO_SENT :
            if ((ssl->error = SendTls13EncryptedExtensions(ssl)) != 0) {
                WOLFSSL_ERROR(ssl->error);
                return SSL_FATAL_ERROR;
            }
            ssl->options.acceptState = SERVER_EXTENSIONS_SENT;
            WOLFSSL_MSG("accept state SERVER_EXTENSIONS_SENT");
        case SERVER_EXTENSIONS_SENT :
#ifndef NO_CERTS
            if (!ssl->options.resuming)
                if (ssl->options.verifyPeer)
                    ssl->error = SendTls13CertificateRequest(ssl);
                    if (ssl->error != 0) {
                        WOLFSSL_ERROR(ssl->error);
                        return SSL_FATAL_ERROR;
                    }
#endif
            ssl->options.acceptState = CERT_REQ_SENT;
            WOLFSSL_MSG("accept state CERT_REQ_SENT");

        case CERT_REQ_SENT :
            ssl->options.acceptState = KEY_EXCHANGE_SENT;
#ifndef NO_CERTS
            if (!ssl->options.resuming) {
                if ((ssl->error = SendTls13Certificate(ssl)) != 0) {
                    WOLFSSL_ERROR(ssl->error);
                    return SSL_FATAL_ERROR;
                }
            }
#endif
            ssl->options.acceptState = CERT_SENT;
            WOLFSSL_MSG("accept state CERT_SENT");

        case CERT_SENT :
#ifndef NO_CERTS
            if (!ssl->options.resuming) {
                if ((ssl->error = SendTls13CertificateVerify(ssl)) != 0) {
                    WOLFSSL_ERROR(ssl->error);
                    return SSL_FATAL_ERROR;
                }
            }
#endif
            ssl->options.acceptState = CERT_STATUS_SENT;
            WOLFSSL_MSG("accept state CERT_STATUS_SENT");

        case CERT_VERIFY_SENT :
            if ((ssl->error = SendTls13Finished(ssl)) != 0) {
                WOLFSSL_ERROR(ssl->error);
                return SSL_FATAL_ERROR;
            }

            ssl->options.acceptState = ACCEPT_FINISHED_DONE;
            WOLFSSL_MSG("accept state ACCEPT_FINISHED_DONE");

        case ACCEPT_FINISHED_DONE :
#ifdef HAVE_SESSION_TICKET
            /* TODO: [TLS13] Section 4.5.1 Note.  */
            if (!ssl->options.resuming && !ssl->options.verifyPeer &&
                !ssl->options.noTicketTls13 && ssl->ctx->ticketEncCb != NULL) {
                if ((ssl->error = SendTls13NewSessionTicket(ssl)) != 0) {
                    WOLFSSL_ERROR(ssl->error);
                    return SSL_FATAL_ERROR;
                }
            }
#endif /* HAVE_SESSION_TICKET */
            ssl->options.acceptState = TICKET_SENT;
            WOLFSSL_MSG("accept state  TICKET_SENT");

        case TICKET_SENT:
            while (ssl->options.clientState < CLIENT_FINISHED_COMPLETE)
                if ( (ssl->error = ProcessReply(ssl)) < 0) {
                    WOLFSSL_ERROR(ssl->error);
                    return SSL_FATAL_ERROR;
                }

            ssl->options.acceptState = ACCEPT_SECOND_REPLY_DONE;
            WOLFSSL_MSG("accept state ACCEPT_SECOND_REPLY_DONE");
        case ACCEPT_SECOND_REPLY_DONE :
#ifdef HAVE_SESSION_TICKET
            if (!ssl->options.resuming && ssl->options.verifyPeer &&
                !ssl->options.noTicketTls13 && ssl->ctx->ticketEncCb != NULL) {
                if ((ssl->error = SendTls13NewSessionTicket(ssl)) != 0) {
                    WOLFSSL_ERROR(ssl->error);
                    return SSL_FATAL_ERROR;
                }
            }
#endif /* HAVE_SESSION_TICKET */
            ssl->options.acceptState = ACCEPT_THIRD_REPLY_DONE;
            WOLFSSL_MSG("accept state ACCEPT_THIRD_REPLY_DONE");

        case ACCEPT_THIRD_REPLY_DONE:
#ifndef NO_HANDSHAKE_DONE_CB
            if (ssl->hsDoneCb) {
                int cbret = ssl->hsDoneCb(ssl, ssl->hsDoneCtx);
                if (cbret < 0) {
                    ssl->error = cbret;
                    WOLFSSL_MSG("HandShake Done Cb don't continue error");
                    return SSL_FATAL_ERROR;
                }
            }
#endif /* NO_HANDSHAKE_DONE_CB */

#ifdef WOLFSSL_SESSION_EXPORT
            if (ssl->dtls_export) {
                if ((ssl->error = wolfSSL_send_session(ssl)) != 0) {
                    WOLFSSL_MSG("Export DTLS session error");
                    WOLFSSL_ERROR(ssl->error);
                    return SSL_FATAL_ERROR;
                }
            }
#endif

            WOLFSSL_LEAVE("SSL_accept()", SSL_SUCCESS);
            return SSL_SUCCESS;

        default :
            WOLFSSL_MSG("Unknown accept state ERROR");
            return SSL_FATAL_ERROR;
    }
}


#undef ERROR_OUT

#endif /* WOLFCRYPT_ONLY */

#endif /* WOLFSSL_TLS13 */
