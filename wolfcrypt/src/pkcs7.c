/* pkcs7.c
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

#ifdef HAVE_PKCS7

#include <wolfssl/wolfcrypt/pkcs7.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/hash.h>
#ifndef NO_RSA
    #include <wolfssl/wolfcrypt/rsa.h>
#endif
#ifdef HAVE_ECC
    #include <wolfssl/wolfcrypt/ecc.h>
#endif
#ifdef HAVE_LIBZ
    #include <wolfssl/wolfcrypt/compress.h>
#endif
#ifndef NO_PWDBASED
    #include <wolfssl/wolfcrypt/pwdbased.h>
#endif
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/* direction for processing, encoding or decoding */
typedef enum {
    WC_PKCS7_ENCODE,
    WC_PKCS7_DECODE
} pkcs7Direction;

#define NO_USER_CHECK 0

/* holds information about the signers */
struct PKCS7SignerInfo {
    int version;
    byte  *sid;
    word32 sidSz;
};


#ifndef WOLFSSL_PKCS7_MAX_DECOMPRESSION
    /* 1031 comes from "Maximum Compression Factor" in the zlib tech document,
     * typical compression is from 2:1 to 5:1 but there is rare cases where
     * 1030.3:1 could happen (like a file with all 0's)
     */
    #define WOLFSSL_PKCS7_MAX_DECOMPRESSION 1031
#endif

#ifndef NO_PKCS7_STREAM

#define MAX_PKCS7_STREAM_BUFFER 256
struct PKCS7State {
    byte* tmpCert;
    byte* bufferPt;
    byte* key;
    byte* nonce;    /* stored nonce */
    byte* aad;      /* additional data for AEAD algos */
    byte* tag;      /* tag data for AEAD algos */
    byte* content;
    byte* buffer;   /* main internal read buffer */

    wc_HashAlg hashAlg;
    int   hashType;
    int   cntIdfCnt; /* count of in-definite length in content info */

    /* stack variables to store for when returning */
    word32 varOne;
    int    varTwo;
    int    varThree;

    word32 vers;
    word32 idx;      /* index read into current input buffer */
    word32 maxLen;   /* sanity cap on maximum amount of data to allow
                      * needed for GetSequence and other calls */
    word32 length;   /* amount of data stored */
    word32 bufferSz; /* size of internal buffer */
    word32 expected; /* next amount of data expected, if needed */
    word32 totalRd;  /* total amount of bytes read */
    word32 nonceSz;  /* size of nonce stored */
    word32 aadSz;    /* size of additional AEAD data */
    word32 tagSz;    /* size of tag for AEAD */
    word32 contentSz;
    word32 currContIdx;   /* index of current content */
    word32 currContSz;    /* size of current content */
    word32 currContRmnSz; /* remaining size of current content */
    word32 accumContSz;   /* size of accumulated content size */
    byte tmpIv[MAX_CONTENT_IV_SIZE]; /* store IV if needed */
#ifdef WC_PKCS7_STREAM_DEBUG
    word32 peakUsed; /* most bytes used for struct at any one time */
    word32 peakRead; /* most bytes used by read buffer */
#endif
    WC_BITFIELD multi:1;  /* flag for if content is in multiple parts */
    WC_BITFIELD flagOne:1;
    WC_BITFIELD detached:1; /* flag to indicate detached signature is present */
    WC_BITFIELD noContent:1;/* indicates content isn't included in bundle */
    WC_BITFIELD degenerate:1;
    WC_BITFIELD indefLen:1; /* flag to indicate indef-length encoding used */
};


/* creates a PKCS7State structure and returns 0 on success */
static int wc_PKCS7_CreateStream(wc_PKCS7* pkcs7)
{
    WOLFSSL_MSG("creating PKCS7 stream structure");
    pkcs7->stream = (PKCS7State*)XMALLOC(sizeof(PKCS7State), pkcs7->heap,
        DYNAMIC_TYPE_PKCS7);
    if (pkcs7->stream == NULL) {
        return MEMORY_E;
    }
    XMEMSET(pkcs7->stream, 0, sizeof(PKCS7State));
#ifdef WC_PKCS7_STREAM_DEBUG
    printf("\nCreating new PKCS#7 stream %p\n", pkcs7->stream);
#endif
    return 0;
}


static void wc_PKCS7_ResetStream(wc_PKCS7* pkcs7)
{
    if (pkcs7 != NULL && pkcs7->stream != NULL) {
#ifdef WC_PKCS7_STREAM_DEBUG
        /* collect final data point in case more was read right before reset */
        if (pkcs7->stream->length > pkcs7->stream->peakRead) {
            pkcs7->stream->peakRead = pkcs7->stream->length;
        }
        if (pkcs7->stream->bufferSz + pkcs7->stream->aadSz +
                pkcs7->stream->nonceSz + pkcs7->stream->tagSz >
                pkcs7->stream->peakUsed) {
            pkcs7->stream->peakUsed = pkcs7->stream->bufferSz +
                pkcs7->stream->aadSz + pkcs7->stream->nonceSz +
                pkcs7->stream->tagSz;
        }

        /* print out debugging statistics */
        if (pkcs7->stream->peakUsed > 0 || pkcs7->stream->peakRead > 0) {
            printf("PKCS#7 STREAM:\n\tPeak heap used by struct = %d"
                                 "\n\tPeak read buffer bytes   = %d"
                                 "\n\tTotal bytes read         = %d"
                                 "\n",
                   pkcs7->stream->peakUsed, pkcs7->stream->peakRead,
                   pkcs7->stream->totalRd);
        }
        printf("PKCS#7 stream reset : Address [%p]\n", pkcs7->stream);
    #endif

        /* free any buffers that may be allocated */
        XFREE(pkcs7->stream->aad, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        XFREE(pkcs7->stream->tag, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        XFREE(pkcs7->stream->nonce, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        XFREE(pkcs7->stream->buffer, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        XFREE(pkcs7->stream->key, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        pkcs7->stream->aad    = NULL;
        pkcs7->stream->tag    = NULL;
        pkcs7->stream->nonce  = NULL;
        pkcs7->stream->buffer = NULL;
        pkcs7->stream->key    = NULL;

        /* reset values, note that content and tmpCert are saved */
        pkcs7->stream->maxLen   = 0;
        pkcs7->stream->length   = 0;
        pkcs7->stream->idx      = 0;
        pkcs7->stream->expected = 0;
        pkcs7->stream->totalRd  = 0;
        pkcs7->stream->bufferSz = 0;

        pkcs7->stream->multi    = 0;
        pkcs7->stream->flagOne  = 0;
        pkcs7->stream->detached = 0;
        pkcs7->stream->varOne   = 0;
        pkcs7->stream->varTwo   = 0;
        pkcs7->stream->varThree = 0;
        pkcs7->stream->noContent    = 0;
        pkcs7->stream->indefLen     = 0;
        pkcs7->stream->cntIdfCnt    = 0;
        pkcs7->stream->currContIdx  = 0;
        pkcs7->stream->currContSz   = 0;
        pkcs7->stream->currContRmnSz= 0;
        pkcs7->stream->accumContSz  = 0;
        pkcs7->stream->contentSz    = 0;
        pkcs7->stream->hashType     = WC_HASH_TYPE_NONE;
    }
}


static void wc_PKCS7_FreeStream(wc_PKCS7* pkcs7)
{
    if (pkcs7 != NULL && pkcs7->stream != NULL) {
        wc_PKCS7_ResetStream(pkcs7);

        XFREE(pkcs7->stream->content, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        XFREE(pkcs7->stream->tmpCert, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        pkcs7->stream->content = NULL;
        pkcs7->stream->tmpCert = NULL;
        XFREE(pkcs7->stream, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        pkcs7->stream = NULL;
    }
}


/* used to increase the max size for internal buffer
 * returns 0 on success  */
static int wc_PKCS7_GrowStream(wc_PKCS7* pkcs7, word32 newSz)
{
    byte* pt;
    pt = (byte*)XMALLOC(newSz, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
    if (pt == NULL) {
        return MEMORY_E;
    }

    if (pkcs7->stream->buffer != NULL && pkcs7->stream->bufferSz > 0) {
        XMEMCPY(pt, pkcs7->stream->buffer, pkcs7->stream->bufferSz);
    }

#ifdef WC_PKCS7_STREAM_DEBUG
    printf("PKCS7 increasing internal stream buffer %d -> %d\n",
            pkcs7->stream->bufferSz, newSz);
#endif
    pkcs7->stream->bufferSz = newSz;
    XFREE(pkcs7->stream->buffer, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
    pkcs7->stream->buffer = pt;
    return 0;
}


/* pt gets set to the buffer that is holding data in the case that stream struct
 *    is used.
 *
 * Sets idx to be the current offset into "pt" buffer
 * returns 0 on success
 */
static int wc_PKCS7_AddDataToStream(wc_PKCS7* pkcs7, byte* in, word32 inSz,
        word32 expected, byte** pt, word32* idx)
{
    word32 rdSz = pkcs7->stream->idx;

    /* If the input size minus current index into input buffer is greater than
     * the expected size then use the input buffer. If data is already stored
     * in stream buffer or if there is not enough input data available then use
     * the stream buffer. */
    if (inSz - rdSz >= expected && pkcs7->stream->length == 0) {
        /* storing input buffer is not needed */
        *pt  = in; /* reset in case previously used internal buffer */
        *idx = rdSz;
        return 0;
    }

    /* is there enough stored in buffer already? */
    if (pkcs7->stream->length >= expected) {
        *idx = 0; /* start reading from beginning of stream buffer */
        *pt  = pkcs7->stream->buffer;
        return 0;
    }

    /* check if all data has been read from input */
    if (rdSz >= inSz) {
        /* no more input to read, reset input index and request more data */
        pkcs7->stream->idx = 0;
        return WC_NO_ERR_TRACE(WC_PKCS7_WANT_READ_E);
    }

    /* try to store input data into stream buffer */
    if (inSz - rdSz > 0 && pkcs7->stream->length < expected) {
        word32 len = min(inSz - rdSz, expected - pkcs7->stream->length);

        /* sanity check that the input buffer is not internal buffer */
        if (in == pkcs7->stream->buffer) {
            return WC_PKCS7_WANT_READ_E;
        }

        /* check if internal buffer size needs to be increased */
        if (len + pkcs7->stream->length > pkcs7->stream->bufferSz) {
            int ret = wc_PKCS7_GrowStream(pkcs7, expected);
            if (ret < 0) {
                return ret;
            }
        }
        XMEMCPY(pkcs7->stream->buffer + pkcs7->stream->length, in + rdSz, len);
        pkcs7->stream->length  += len;
        pkcs7->stream->idx     += len;
        pkcs7->stream->totalRd += len;
    }

#ifdef WC_PKCS7_STREAM_DEBUG
    /* collects memory usage for debugging */
    if (pkcs7->stream->length > pkcs7->stream->peakRead) {
        pkcs7->stream->peakRead = pkcs7->stream->length;
    }
    if (pkcs7->stream->bufferSz + pkcs7->stream->aadSz + pkcs7->stream->nonceSz +
        pkcs7->stream->tagSz > pkcs7->stream->peakUsed) {
        pkcs7->stream->peakUsed = pkcs7->stream->bufferSz +
           pkcs7->stream->aadSz + pkcs7->stream->nonceSz + pkcs7->stream->tagSz;
    }
#endif

    /* if not enough data was read in then request more */
    if (pkcs7->stream->length < expected) {
        pkcs7->stream->idx = 0;
        return WC_NO_ERR_TRACE(WC_PKCS7_WANT_READ_E);
    }

    /* adjust pointer to read from stored buffer */
    *idx = 0;
    *pt  = pkcs7->stream->buffer;
    return 0;
}


/* setter function for stored variables */
static void wc_PKCS7_StreamStoreVar(wc_PKCS7* pkcs7, word32 var1, int var2,
        int var3)
{
    if (pkcs7 != NULL && pkcs7->stream != NULL) {
        pkcs7->stream->varOne   = var1;
        pkcs7->stream->varTwo   = var2;
        pkcs7->stream->varThree = var3;
    }
}

/* Tries to peek at the SEQ and get the length
 * returns 0 on success
 */
static int wc_PKCS7_SetMaxStream(wc_PKCS7* pkcs7, byte* in, word32 defSz)
{
    /* check there is a buffer to read from */
    if (pkcs7) {
        int     length = 0, ret;
        word32  idx = 0, maxIdx;
        byte*   pt;

        if (pkcs7->stream->length > 0) {
            length = (int)pkcs7->stream->length;
            pt     = pkcs7->stream->buffer;
        }
        else {
            length = (int)defSz;
            pt     = in;
        }
        maxIdx = (word32)length;

        if (length < MAX_SEQ_SZ) {
            WOLFSSL_MSG("PKCS7 Error not enough data for SEQ peek");
            return 0;
        }

        if ((ret = GetSequence_ex(pt, &idx, &length, maxIdx, NO_USER_CHECK))
                < 0) {
            return ret;
        }

    #ifdef ASN_BER_TO_DER
        if (length == 0 && ret == 0) {
            idx = 0;
            if ((ret = wc_BerToDer(pt, maxIdx, NULL, (word32*)&length))
                != WC_NO_ERR_TRACE(LENGTH_ONLY_E)) {
                return ret;
            }
        }
    #endif /* ASN_BER_TO_DER */
        pkcs7->stream->maxLen = (word32)length + idx;

        if (pkcs7->stream->maxLen == 0) {
            pkcs7->stream->maxLen = defSz;
        }
    }

    return 0;
}


/* getter function for stored variables */
static void wc_PKCS7_StreamGetVar(wc_PKCS7* pkcs7, word32* var1, int* var2,
        int* var3)
{
    if (pkcs7 != NULL && pkcs7->stream != NULL) {
        if (var1 != NULL) *var1 = pkcs7->stream->varOne;
        if (var2 != NULL) *var2 = pkcs7->stream->varTwo;
        if (var3 != NULL) *var3 = pkcs7->stream->varThree;
    }
}


/* common update of index and total read after section complete
 * returns 0 on success */
static int wc_PKCS7_StreamEndCase(wc_PKCS7* pkcs7, word32* tmpIdx, word32* idx)
{
    int ret = 0;

    if (pkcs7->stream->length > 0) {
        if (pkcs7->stream->length < *idx) {
            WOLFSSL_MSG("PKCS7 read too much data from internal buffer");
            ret = BUFFER_E;
        }
        else {
            XMEMMOVE(pkcs7->stream->buffer, pkcs7->stream->buffer + *idx,
                 pkcs7->stream->length - *idx);
            pkcs7->stream->length -= *idx;
        }
    }
    else {
        pkcs7->stream->totalRd += *idx - *tmpIdx;
        pkcs7->stream->idx = *idx; /* adjust index into input buffer */
        *tmpIdx = *idx;
    }

    return ret;
}
#endif /* NO_PKCS7_STREAM */

#ifdef WC_PKCS7_STREAM_DEBUG
/* used to print out human readable state for debugging */
static const char* wc_PKCS7_GetStateName(int in)
{
    switch (in) {
        case WC_PKCS7_START: return "WC_PKCS7_START";

        case WC_PKCS7_STAGE2: return "WC_PKCS7_STAGE2";
        case WC_PKCS7_STAGE3: return "WC_PKCS7_STAGE3";
        case WC_PKCS7_STAGE4: return "WC_PKCS7_STAGE4";
        case WC_PKCS7_STAGE5: return "WC_PKCS7_STAGE5";
        case WC_PKCS7_STAGE6: return "WC_PKCS7_STAGE6";

        /* parse info set */
        case WC_PKCS7_INFOSET_START:  return "WC_PKCS7_INFOSET_START";
        case WC_PKCS7_INFOSET_BER:    return "WC_PKCS7_INFOSET_BER";
        case WC_PKCS7_INFOSET_STAGE1: return "WC_PKCS7_INFOSET_STAGE1";
        case WC_PKCS7_INFOSET_STAGE2: return "WC_PKCS7_INFOSET_STAGE2";
        case WC_PKCS7_INFOSET_END:    return "WC_PKCS7_INFOSET_END";

        /* decode enveloped data */
        case WC_PKCS7_ENV_2: return "WC_PKCS7_ENV_2";
        case WC_PKCS7_ENV_3: return "WC_PKCS7_ENV_3";
        case WC_PKCS7_ENV_4: return "WC_PKCS7_ENV_4";
        case WC_PKCS7_ENV_5: return "WC_PKCS7_ENV_5";

        /* decode auth enveloped */
        case WC_PKCS7_AUTHENV_2: return "WC_PKCS7_AUTHENV_2";
        case WC_PKCS7_AUTHENV_3: return "WC_PKCS7_AUTHENV_3";
        case WC_PKCS7_AUTHENV_4: return "WC_PKCS7_AUTHENV_4";
        case WC_PKCS7_AUTHENV_5: return "WC_PKCS7_AUTHENV_5";
        case WC_PKCS7_AUTHENV_6: return "WC_PKCS7_AUTHENV_6";
        case WC_PKCS7_AUTHENV_ATRB: return "WC_PKCS7_AUTHENV_ATRB";
        case WC_PKCS7_AUTHENV_ATRBEND: return "WC_PKCS7_AUTHENV_ATRBEND";
        case WC_PKCS7_AUTHENV_7: return "WC_PKCS7_AUTHENV_7";

        /* decryption state types */
        case WC_PKCS7_DECRYPT_KTRI:   return "WC_PKCS7_DECRYPT_KTRI";
        case WC_PKCS7_DECRYPT_KTRI_2: return "WC_PKCS7_DECRYPT_KTRI_2";
        case WC_PKCS7_DECRYPT_KTRI_3: return "WC_PKCS7_DECRYPT_KTRI_3";

        case WC_PKCS7_DECRYPT_KARI:  return "WC_PKCS7_DECRYPT_KARI";
        case WC_PKCS7_DECRYPT_KEKRI: return "WC_PKCS7_DECRYPT_KEKRI";
        case WC_PKCS7_DECRYPT_PWRI:  return "WC_PKCS7_DECRYPT_PWRI";
        case WC_PKCS7_DECRYPT_ORI:   return "WC_PKCS7_DECRYPT_ORI";
        case WC_PKCS7_DECRYPT_DONE:  return "WC_PKCS7_DECRYPT_DONE";

        case WC_PKCS7_VERIFY_STAGE2: return "WC_PKCS7_VERIFY_STAGE2";
        case WC_PKCS7_VERIFY_STAGE3: return "WC_PKCS7_VERIFY_STAGE3";
        case WC_PKCS7_VERIFY_STAGE4: return "WC_PKCS7_VERIFY_STAGE4";
        case WC_PKCS7_VERIFY_STAGE5: return "WC_PKCS7_VERIFY_STAGE5";
        case WC_PKCS7_VERIFY_STAGE6: return "WC_PKCS7_VERIFY_STAGE6";
        case WC_PKCS7_VERIFY_STAGE7: return "WC_PKCS7_VERIFY_STAGE7";

        default:
            return "Unknown state";
    }
}
#endif

/* Used to change the PKCS7 state. Having state change as a function allows
 * for easier debugging */
static void wc_PKCS7_ChangeState(wc_PKCS7* pkcs7, int newState)
{
#ifdef WC_PKCS7_STREAM_DEBUG
    printf("\tChanging from state [%02d] %s to [%02d] %s\n",
            pkcs7->state, wc_PKCS7_GetStateName(pkcs7->state),
            newState, wc_PKCS7_GetStateName(newState));
#endif
    pkcs7->state = (word32)newState;
}

#define MAX_PKCS7_DIGEST_SZ (MAX_SEQ_SZ + MAX_ALGO_SZ + \
                             MAX_OCTET_STR_SZ + WC_MAX_DIGEST_SIZE)


/* placed ASN.1 contentType OID into *output, return idx on success,
 * 0 upon failure */
static int wc_SetContentType(int pkcs7TypeOID, byte* output, word32 outputSz)
{
    /* PKCS#7 content types, RFC 2315, section 14 */
    static const byte pkcs7[]              =
        { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07 };
    static const byte data[]               =
        { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x01 };
    static const byte signedData[]         =
        { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x02};
    static const byte envelopedData[]      =
        { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x03 };
    static const byte authEnvelopedData[]  =
        { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x17};
    static const byte signedAndEnveloped[] =
        { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x04 };
    static const byte digestedData[]       =
        { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x05 };
#ifndef NO_PKCS7_ENCRYPTED_DATA
    static const byte encryptedData[]      =
        { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x07, 0x06 };
#endif
    /* FirmwarePkgData (1.2.840.113549.1.9.16.1.16), RFC 4108 */
    static const byte firmwarePkgData[]    =
        { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x10 };
#if defined(HAVE_LIBZ) && !defined(NO_PKCS7_COMPRESSED_DATA)
    /* id-ct-compressedData (1.2.840.113549.1.9.16.1.9), RFC 3274 */
    static const byte compressedData[]     =
       { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x01, 0x09 };
#endif

#if !defined(NO_PWDBASED) && !defined(NO_SHA)
    static const byte pwriKek[]            =
       { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x10, 0x03, 0x09 };
    static const byte pbkdf2[]             =
       { 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x05, 0x0C };
#endif

    word32 idSz, idx = 0;
    word32 typeSz = 0;
    const byte* typeName = 0;
    byte ID_Length[MAX_LENGTH_SZ];

    switch (pkcs7TypeOID) {
        case PKCS7_MSG:
            typeSz = sizeof(pkcs7);
            typeName = pkcs7;
            break;

        case DATA:
            typeSz = sizeof(data);
            typeName = data;
            break;

        case SIGNED_DATA:
            typeSz = sizeof(signedData);
            typeName = signedData;
            break;

        case ENVELOPED_DATA:
            typeSz = sizeof(envelopedData);
            typeName = envelopedData;
            break;

        case AUTH_ENVELOPED_DATA:
            typeSz = sizeof(authEnvelopedData);
            typeName = authEnvelopedData;
            break;

        case SIGNED_AND_ENVELOPED_DATA:
            typeSz = sizeof(signedAndEnveloped);
            typeName = signedAndEnveloped;
            break;

        case DIGESTED_DATA:
            typeSz = sizeof(digestedData);
            typeName = digestedData;
            break;

#ifndef NO_PKCS7_ENCRYPTED_DATA
        case ENCRYPTED_DATA:
            typeSz = sizeof(encryptedData);
            typeName = encryptedData;
            break;
#endif
#if defined(HAVE_LIBZ) && !defined(NO_PKCS7_COMPRESSED_DATA)
        case COMPRESSED_DATA:
            typeSz = sizeof(compressedData);
            typeName = compressedData;
            break;
#endif
        case FIRMWARE_PKG_DATA:
            typeSz = sizeof(firmwarePkgData);
            typeName = firmwarePkgData;
            break;

#if !defined(NO_PWDBASED) && !defined(NO_SHA)
        case PWRI_KEK_WRAP:
            typeSz = sizeof(pwriKek);
            typeName = pwriKek;
            break;

        case PBKDF2_OID:
            typeSz = sizeof(pbkdf2);
            typeName = pbkdf2;
            break;
#endif

        default:
            WOLFSSL_MSG("Unknown PKCS#7 Type");
            return 0;
    };

    if (outputSz < (MAX_LENGTH_SZ + 1 + typeSz)) {
        WOLFSSL_MSG("CMS content type buffer too small");
        return BAD_FUNC_ARG;
    }

    idSz  = SetLength(typeSz, ID_Length);
    output[idx++] = ASN_OBJECT_ID;
    XMEMCPY(output + idx, ID_Length, idSz);
    idx += idSz;
    XMEMCPY(output + idx, typeName, typeSz);
    idx += typeSz;

    return (int)idx;
}


/* get ASN.1 contentType OID sum, return 0 on success, <0 on failure */
static int wc_GetContentType(const byte* input, word32* inOutIdx, word32* oid,
                             word32 maxIdx)
{
    WOLFSSL_ENTER("wc_GetContentType");
    if (GetObjectId(input, inOutIdx, oid, oidIgnoreType, maxIdx) < 0) {
        WOLFSSL_LEAVE("wc_GetContentType", ASN_PARSE_E);
        return ASN_PARSE_E;
    }

    return 0;
}


/* return block size for algorithm represented by oid, or <0 on error */
static int wc_PKCS7_GetOIDBlockSize(int oid)
{
    int blockSz;

    switch (oid) {
#ifndef NO_AES
    #ifdef WOLFSSL_AES_128
        #ifdef HAVE_AES_CBC
        case AES128CBCb:
        #endif
        #ifdef HAVE_AESGCM
        case AES128GCMb:
        #endif
        #ifdef HAVE_AESCCM
        case AES128CCMb:
        #endif
    #endif
    #ifdef WOLFSSL_AES_192
        #ifdef HAVE_AES_CBC
        case AES192CBCb:
        #endif
        #ifdef HAVE_AESGCM
        case AES192GCMb:
        #endif
        #ifdef HAVE_AESCCM
        case AES192CCMb:
        #endif
    #endif
    #ifdef WOLFSSL_AES_256
        #ifdef HAVE_AES_CBC
        case AES256CBCb:
        #endif
        #ifdef HAVE_AESGCM
        case AES256GCMb:
        #endif
        #ifdef HAVE_AESCCM
        case AES256CCMb:
        #endif
    #endif
            blockSz = WC_AES_BLOCK_SIZE;
            break;
#endif /* !NO_AES */

#ifndef NO_DES3
        case DESb:
        case DES3b:
            blockSz = DES_BLOCK_SIZE;
            break;
#endif
        default:
            WOLFSSL_MSG("Unsupported content cipher type");
            return ALGO_ID_E;
    };

    return blockSz;
}


/* get key size for algorithm represented by oid, or <0 on error */
static int wc_PKCS7_GetOIDKeySize(int oid)
{
    int blockKeySz;

    switch (oid) {
#ifndef NO_AES
    #ifdef WOLFSSL_AES_128
        #ifdef HAVE_AES_CBC
        case AES128CBCb:
        #endif
        #ifdef HAVE_AESGCM
        case AES128GCMb:
        #endif
        #ifdef HAVE_AESCCM
        case AES128CCMb:
        #endif
        case AES128_WRAP:
            blockKeySz = 16;
            break;
    #endif
    #ifdef WOLFSSL_AES_192
        #ifdef HAVE_AES_CBC
        case AES192CBCb:
        #endif
        #ifdef HAVE_AESGCM
        case AES192GCMb:
        #endif
        #ifdef HAVE_AESCCM
        case AES192CCMb:
        #endif
        case AES192_WRAP:
            blockKeySz = 24;
            break;
    #endif
    #ifdef WOLFSSL_AES_256
        #ifdef HAVE_AES_CBC
        case AES256CBCb:
        #endif
        #ifdef HAVE_AESGCM
        case AES256GCMb:
        #endif
        #ifdef HAVE_AESCCM
        case AES256CCMb:
        #endif
        case AES256_WRAP:
            blockKeySz = 32;
            break;
    #endif
#endif /* !NO_AES */

#ifndef NO_DES3
        case DESb:
            blockKeySz = DES_KEYLEN;
            break;
        case DES3b:
            blockKeySz = DES3_KEYLEN;
            break;
#endif
        default:
            WOLFSSL_MSG("Unsupported content cipher type");
            return ALGO_ID_E;
    };

    return blockKeySz;
}


wc_PKCS7* wc_PKCS7_New(void* heap, int devId)
{
    wc_PKCS7* pkcs7 = (wc_PKCS7*)XMALLOC(sizeof(wc_PKCS7), heap, DYNAMIC_TYPE_PKCS7);
    if (pkcs7) {
        XMEMSET(pkcs7, 0, sizeof(wc_PKCS7));
        if (wc_PKCS7_Init(pkcs7, heap, devId) == 0) {
            pkcs7->isDynamic = 1;
        }
        else {
            XFREE(pkcs7, heap, DYNAMIC_TYPE_PKCS7);
            pkcs7 = NULL;
        }
    }
    return pkcs7;
}

/* This is to initialize a PKCS7 structure. It sets all values to 0 and can be
 * used to set the heap hint.
 *
 * pkcs7 PKCS7 structure to initialize
 * heap  memory heap hint for PKCS7 structure to use
 * devId currently not used but a place holder for async operations
 *
 * returns 0 on success or a negative value for failure
 */
int wc_PKCS7_Init(wc_PKCS7* pkcs7, void* heap, int devId)
{
    word16 isDynamic;

    WOLFSSL_ENTER("wc_PKCS7_Init");

    if (pkcs7 == NULL) {
        return BAD_FUNC_ARG;
    }

    isDynamic = pkcs7->isDynamic;
    XMEMSET(pkcs7, 0, sizeof(wc_PKCS7));
    pkcs7->isDynamic = (isDynamic != 0);
#ifdef WOLFSSL_HEAP_TEST
    pkcs7->heap = (void*)WOLFSSL_HEAP_TEST;
#else
    pkcs7->heap = heap;
#endif
    pkcs7->devId = devId;

    return 0;
}

#ifdef WC_ASN_UNKNOWN_EXT_CB
void wc_PKCS7_SetUnknownExtCallback(wc_PKCS7* pkcs7, wc_UnknownExtCallback cb)
{
    if (pkcs7 != NULL) {
        pkcs7->unknownExtCallback = cb;
    }
}
#endif

/* Certificate structure holding der pointer, size, and pointer to next
 * Pkcs7Cert struct. Used when creating SignedData types with multiple
 * certificates. */
struct Pkcs7Cert {
    byte*  der;
    word32 derSz;
    Pkcs7Cert* next;
};


/* Linked list of ASN.1 encoded RecipientInfos */
struct Pkcs7EncodedRecip {
    byte recip[MAX_RECIP_SZ];
    word32 recipSz;
    int recipType;
    int recipVersion;
    Pkcs7EncodedRecip* next;
};


/* free all members of Pkcs7Cert linked list */
static void wc_PKCS7_FreeCertSet(wc_PKCS7* pkcs7)
{
    Pkcs7Cert* curr = NULL;
    Pkcs7Cert* next = NULL;

    if (pkcs7 == NULL)
        return;

    curr = pkcs7->certList;
    pkcs7->certList = NULL;

    while (curr != NULL) {
        next = curr->next;
        curr->next = NULL;
        XFREE(curr, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        curr = next;
    }

    return;
}


/* Get total size of all recipients in recipient list.
 *
 * Returns total size of recipients, or negative upon error */
static int wc_PKCS7_GetRecipientListSize(wc_PKCS7* pkcs7)
{
    word32 totalSz = 0;
    Pkcs7EncodedRecip* tmp = NULL;

    if (pkcs7 == NULL)
        return BAD_FUNC_ARG;

    tmp = pkcs7->recipList;

    while (tmp != NULL) {
        totalSz += tmp->recipSz;
        tmp = tmp->next;
    }

    return (int)totalSz;
}


/* free all members of Pkcs7EncodedRecip linked list */
static void wc_PKCS7_FreeEncodedRecipientSet(wc_PKCS7* pkcs7)
{
    Pkcs7EncodedRecip* curr = NULL;
    Pkcs7EncodedRecip* next = NULL;

    if (pkcs7 == NULL)
        return;

    curr = pkcs7->recipList;
    pkcs7->recipList = NULL;

    while (curr != NULL) {
        next = curr->next;
        curr->next = NULL;
        XFREE(curr, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        curr = next;
    }

    return;
}


/* search through RecipientInfo list for specific type.
 * return 1 if ANY recipient of type specified is present, otherwise
 * return 0 */
static int wc_PKCS7_RecipientListIncludesType(wc_PKCS7* pkcs7, int type)
{
    Pkcs7EncodedRecip* tmp = NULL;

    if (pkcs7 == NULL)
        return BAD_FUNC_ARG;

    tmp = pkcs7->recipList;

    while (tmp != NULL) {
        if (tmp->recipType == type)
            return 1;

        tmp = tmp->next;
    }

    return 0;
}


/* searches through RecipientInfo list, returns 1 if all structure
 * versions are set to 0, otherwise returns 0 */
static int wc_PKCS7_RecipientListVersionsAllZero(wc_PKCS7* pkcs7)
{
    Pkcs7EncodedRecip* tmp = NULL;

    if (pkcs7 == NULL)
        return BAD_FUNC_ARG;

    tmp = pkcs7->recipList;

    while (tmp != NULL) {
        if (tmp->recipVersion != 0)
            return 0;

        tmp = tmp->next;
    }

    return 1;
}

/* Verify RSA/ECC key is correctly formatted, used as sanity check after
 * import of key/cert.
 *
 * keyOID - key OID (ex: RSAk, ECDSAk)
 * key    - key in DER
 * keySz  - size of key, octets
 *
 * Returns 0 on success, negative on error */
static int wc_PKCS7_CheckPublicKeyDer(wc_PKCS7* pkcs7, int keyOID,
                                      const byte* key, word32 keySz)
{
    int ret = 0;
    word32 scratch = 0;
#ifdef WOLFSSL_SMALL_STACK
    #ifndef NO_RSA
        RsaKey* rsa;
    #endif
    #ifdef HAVE_ECC
        ecc_key* ecc;
    #endif
#else
    #ifndef NO_RSA
        RsaKey rsa[1];
    #endif
    #ifdef HAVE_ECC
        ecc_key ecc[1];
    #endif
#endif

    if (pkcs7 == NULL || key == NULL || keySz == 0) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_SMALL_STACK
    #ifndef NO_RSA
        rsa = (RsaKey*)XMALLOC(sizeof(RsaKey), pkcs7->heap,
                               DYNAMIC_TYPE_TMP_BUFFER);
        if (rsa == NULL) {
            return MEMORY_E;
        }
    #endif

    #ifdef HAVE_ECC
        ecc = (ecc_key*)XMALLOC(sizeof(ecc_key), pkcs7->heap,
                                DYNAMIC_TYPE_TMP_BUFFER);
        if (ecc == NULL) {
            #ifndef NO_RSA
                XFREE(rsa, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
            #endif
            return MEMORY_E;
        }
    #endif
#endif

    switch (keyOID) {
#ifndef NO_RSA
        case RSAk:
            ret = wc_InitRsaKey_ex(rsa, pkcs7->heap, pkcs7->devId);
            if (ret != 0) {
                break;
            }

            /* Try to decode public key as sanity check. wc_CheckRsaKey()
               only checks private key not public. */
            ret = wc_RsaPublicKeyDecode(key, &scratch, rsa, keySz);
            wc_FreeRsaKey(rsa);

            break;
#endif
#ifdef HAVE_ECC
        case ECDSAk:
            ret = wc_ecc_init_ex(ecc, pkcs7->heap, pkcs7->devId);
            if (ret != 0) {
                break;
            }

            /* Try to decode public key and check with wc_ecc_check_key() */
            ret = wc_EccPublicKeyDecode(key, &scratch, ecc, keySz);
        #if defined(WOLFSSL_VALIDATE_ECC_IMPORT)
            if (ret == 0) {
                ret = wc_ecc_check_key(ecc);
            }
        #endif
            wc_ecc_free(ecc);

            break;
#endif
    }

#ifdef WOLFSSL_SMALL_STACK
    #ifndef NO_RSA
        XFREE(rsa, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
    #endif
    #ifdef HAVE_ECC
        XFREE(ecc, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
    #endif
#endif

    return ret;
}


/* Init PKCS7 struct with recipient cert, decode into DecodedCert
 * NOTE: keeps previously set pkcs7 heap hint, devId and isDynamic */
int wc_PKCS7_InitWithCert(wc_PKCS7* pkcs7, byte* derCert, word32 derCertSz)
{
    int ret = 0;
    void* heap;
    int devId;
    Pkcs7Cert* cert;
    Pkcs7Cert* lastCert;
#ifdef WC_ASN_UNKNOWN_EXT_CB
    wc_UnknownExtCallback cb;
#endif

    if (pkcs7 == NULL || (derCert == NULL && derCertSz != 0)) {
        return BAD_FUNC_ARG;
    }

    heap = pkcs7->heap;
    devId = pkcs7->devId;
    cert = pkcs7->certList;
#ifdef WC_ASN_UNKNOWN_EXT_CB
    cb = pkcs7->unknownExtCallback; /* save / restore callback */
#endif
    ret = wc_PKCS7_Init(pkcs7, heap, devId);
    if (ret != 0)
        return ret;

#ifdef WC_ASN_UNKNOWN_EXT_CB
    pkcs7->unknownExtCallback = cb;
#endif
    pkcs7->certList = cert;

    if (derCert != NULL && derCertSz > 0) {
#ifdef WOLFSSL_SMALL_STACK
        DecodedCert* dCert;

        dCert = (DecodedCert*)XMALLOC(sizeof(DecodedCert), pkcs7->heap,
                                                       DYNAMIC_TYPE_DCERT);
        if (dCert == NULL)
            return MEMORY_E;
#else
        DecodedCert dCert[1];
#endif

        pkcs7->singleCert = derCert;
        pkcs7->singleCertSz = derCertSz;
        pkcs7->cert[0] = derCert;
        pkcs7->certSz[0] = derCertSz;

        /* create new Pkcs7Cert for recipient, freed during cleanup */
        cert = (Pkcs7Cert*)XMALLOC(sizeof(Pkcs7Cert), pkcs7->heap,
                                   DYNAMIC_TYPE_PKCS7);
        if (cert == NULL) {
#ifdef WOLFSSL_SMALL_STACK
            XFREE(dCert, pkcs7->heap, DYNAMIC_TYPE_DCERT);
#endif
            return MEMORY_E;
        }
        XMEMSET(cert, 0, sizeof(Pkcs7Cert));
        cert->der = derCert;
        cert->derSz = derCertSz;
        cert->next = NULL;

        /* free existing cert list if existing */
        wc_PKCS7_FreeCertSet(pkcs7);

        /* add cert to list */
        if (pkcs7->certList == NULL) {
            pkcs7->certList = cert;
        } else {
           lastCert = pkcs7->certList;
           while (lastCert->next != NULL) {
               lastCert = lastCert->next;
           }
           lastCert->next = cert;
        }

        InitDecodedCert(dCert, derCert, derCertSz, pkcs7->heap);
#ifdef WC_ASN_UNKNOWN_EXT_CB
        if (pkcs7->unknownExtCallback != NULL)
            wc_SetUnknownExtCallback(dCert, pkcs7->unknownExtCallback);
#endif
        ret = ParseCert(dCert, CA_TYPE, NO_VERIFY, 0);
        if (ret < 0) {
            FreeDecodedCert(dCert);
#ifdef WOLFSSL_SMALL_STACK
            XFREE(dCert, pkcs7->heap, DYNAMIC_TYPE_DCERT);
#endif
            return ret;
        }

        /* verify extracted public key is valid before storing */
        ret = wc_PKCS7_CheckPublicKeyDer(pkcs7, (int)dCert->keyOID,
                                         dCert->publicKey, dCert->pubKeySize);
        if (ret != 0) {
            WOLFSSL_MSG("Invalid public key, check pkcs7->cert");
            FreeDecodedCert(dCert);
#ifdef WOLFSSL_SMALL_STACK
            XFREE(dCert, pkcs7->heap, DYNAMIC_TYPE_DCERT);
#endif
            return ret;
        }

        if (dCert->pubKeySize > (MAX_RSA_INT_SZ + MAX_RSA_E_SZ) ||
            dCert->serialSz > MAX_SN_SZ) {
            WOLFSSL_MSG("Invalid size in certificate");
            FreeDecodedCert(dCert);
#ifdef WOLFSSL_SMALL_STACK
            XFREE(dCert, pkcs7->heap, DYNAMIC_TYPE_DCERT);
#endif
            return ASN_PARSE_E;
        }

        XMEMCPY(pkcs7->publicKey, dCert->publicKey, dCert->pubKeySize);
        pkcs7->publicKeySz = dCert->pubKeySize;
        pkcs7->publicKeyOID = dCert->keyOID;
        XMEMCPY(pkcs7->issuerHash, dCert->issuerHash, KEYID_SIZE);
        pkcs7->issuer = dCert->issuerRaw;
        pkcs7->issuerSz = (word32)dCert->issuerRawLen;
        XMEMCPY(pkcs7->issuerSn, dCert->serial, (word32)dCert->serialSz);
        pkcs7->issuerSnSz = (word32)dCert->serialSz;
        XMEMCPY(pkcs7->issuerSubjKeyId, dCert->extSubjKeyId, KEYID_SIZE);

        /* default to IssuerAndSerialNumber for SignerIdentifier */
        pkcs7->sidType = CMS_ISSUER_AND_SERIAL_NUMBER;

        /* free existing recipient list if existing */
        wc_PKCS7_FreeEncodedRecipientSet(pkcs7);

        FreeDecodedCert(dCert);

#ifdef WOLFSSL_SMALL_STACK
        XFREE(dCert, pkcs7->heap, DYNAMIC_TYPE_DCERT);
#endif
    }

    return ret;
}


/* Adds one DER-formatted certificate to the internal PKCS7/CMS certificate
 * list, to be added as part of the certificates CertificateSet. Currently
 * used in SignedData content type.
 *
 * Must be called after wc_PKCS7_Init() or wc_PKCS7_InitWithCert().
 *
 * Does not represent the recipient/signer certificate, only certificates that
 * are part of the certificate chain used to build and verify signer
 * certificates.
 *
 * This API does not currently validate certificates.
 *
 * Returns 0 on success, negative upon error */
int wc_PKCS7_AddCertificate(wc_PKCS7* pkcs7, byte* derCert, word32 derCertSz)
{
    Pkcs7Cert* cert;

    if (pkcs7 == NULL || derCert == NULL || derCertSz == 0)
        return BAD_FUNC_ARG;

    cert = (Pkcs7Cert*)XMALLOC(sizeof(Pkcs7Cert), pkcs7->heap,
                               DYNAMIC_TYPE_PKCS7);
    if (cert == NULL)
        return MEMORY_E;
    XMEMSET(cert, 0, sizeof(Pkcs7Cert));

    cert->der = derCert;
    cert->derSz = derCertSz;

    if (pkcs7->certList == NULL) {
        pkcs7->certList = cert;
    } else {
        cert->next = pkcs7->certList;
        pkcs7->certList = cert;
    }

    return 0;
}


/* free linked list of PKCS7DecodedAttrib structs */
static void wc_PKCS7_FreeDecodedAttrib(PKCS7DecodedAttrib* attrib, void* heap)
{
    PKCS7DecodedAttrib* current;

    if (attrib == NULL) {
        return;
    }

    current = attrib;
    while (current != NULL) {
        PKCS7DecodedAttrib* next = current->next;
        XFREE(current->oid, heap, DYNAMIC_TYPE_PKCS7);
        XFREE(current->value, heap, DYNAMIC_TYPE_PKCS7);
        XFREE(current, heap, DYNAMIC_TYPE_PKCS7);
        current = next;
    }

    (void)heap;
}


/* return 0 on success */
static int wc_PKCS7_SignerInfoNew(wc_PKCS7* pkcs7)
{
    XFREE(pkcs7->signerInfo, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
    pkcs7->signerInfo = NULL;

    pkcs7->signerInfo = (PKCS7SignerInfo*)XMALLOC(sizeof(PKCS7SignerInfo),
            pkcs7->heap, DYNAMIC_TYPE_PKCS7);
    if (pkcs7->signerInfo == NULL) {
        WOLFSSL_MSG("Unable to malloc memory for signer info");
        return MEMORY_E;
    }
    XMEMSET(pkcs7->signerInfo, 0, sizeof(PKCS7SignerInfo));
    return 0;
}


static void wc_PKCS7_SignerInfoFree(wc_PKCS7* pkcs7)
{
    if (pkcs7->signerInfo != NULL) {
        XFREE(pkcs7->signerInfo->sid, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        pkcs7->signerInfo->sid = NULL;
        XFREE(pkcs7->signerInfo, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        pkcs7->signerInfo = NULL;
    }
}


/* free's any current SID and sets it to "in"
 * returns 0 on success
 */
static int wc_PKCS7_SignerInfoSetSID(wc_PKCS7* pkcs7, byte* in, int inSz)
{
    if (pkcs7 == NULL || in == NULL || inSz < 0) {
        return BAD_FUNC_ARG;
    }

    XFREE(pkcs7->signerInfo->sid, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
    pkcs7->signerInfo->sid = NULL;
    pkcs7->signerInfo->sid = (byte*)XMALLOC((word32)inSz, pkcs7->heap,
            DYNAMIC_TYPE_PKCS7);
    if (pkcs7->signerInfo->sid == NULL) {
        return MEMORY_E;
    }
    XMEMCPY(pkcs7->signerInfo->sid, in, (word32)inSz);
    pkcs7->signerInfo->sidSz = (word32)inSz;
    return 0;
}


/* releases any memory allocated by a PKCS7 initializer */
void wc_PKCS7_Free(wc_PKCS7* pkcs7)
{
    if (pkcs7 == NULL)
        return;

#ifndef NO_PKCS7_STREAM
    wc_PKCS7_FreeStream(pkcs7);
#endif

    wc_PKCS7_SignerInfoFree(pkcs7);
    wc_PKCS7_FreeDecodedAttrib(pkcs7->decodedAttrib, pkcs7->heap);
    pkcs7->decodedAttrib = NULL;
    wc_PKCS7_FreeCertSet(pkcs7);

#ifdef ASN_BER_TO_DER
    XFREE(pkcs7->der, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
    pkcs7->der = NULL;
#endif
    XFREE(pkcs7->contentDynamic, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
    pkcs7->contentDynamic = NULL;

    if (pkcs7->cek != NULL) {
        ForceZero(pkcs7->cek, pkcs7->cekSz);
        XFREE(pkcs7->cek, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        pkcs7->cek = NULL;
    }

    pkcs7->contentTypeSz = 0;

    if (pkcs7->signature) {
        XFREE(pkcs7->signature, pkcs7->heap, DYNAMIC_TYPE_SIGNATURE);
        pkcs7->signature = NULL;
        pkcs7->signatureSz = 0;
    }
    if (pkcs7->plainDigest) {
        XFREE(pkcs7->plainDigest, pkcs7->heap, DYNAMIC_TYPE_DIGEST);
        pkcs7->plainDigest = NULL;
        pkcs7->plainDigestSz = 0;
    }
    if (pkcs7->pkcs7Digest) {
        XFREE(pkcs7->pkcs7Digest, pkcs7->heap, DYNAMIC_TYPE_DIGEST);
        pkcs7->pkcs7Digest = NULL;
        pkcs7->pkcs7DigestSz = 0;
    }
    if (pkcs7->cachedEncryptedContent != NULL) {
        XFREE(pkcs7->cachedEncryptedContent, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        pkcs7->cachedEncryptedContent = NULL;
        pkcs7->cachedEncryptedContentSz = 0;
    }

    if (pkcs7->customSKID) {
        XFREE(pkcs7->customSKID, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        pkcs7->customSKID = NULL;
        pkcs7->customSKIDSz = 0;
    }

    if (pkcs7->isDynamic) {
        pkcs7->isDynamic = 0;
        XFREE(pkcs7, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
    }
}


/* helper function for parsing through attributes and finding a specific one.
 * returns PKCS7DecodedAttrib pointer on success */
static PKCS7DecodedAttrib* findAttrib(wc_PKCS7* pkcs7, const byte* oid, word32 oidSz)
{
    PKCS7DecodedAttrib* list;

    if (pkcs7 == NULL || oid == NULL) {
        return NULL;
    }

    /* search attributes for pkiStatus */
    list = pkcs7->decodedAttrib;
    while (list != NULL) {
        word32 sz  = oidSz;
        word32 idx = 0;
        int    length = 0;
        byte   tag;

        if (GetASNTag(list->oid, &idx, &tag, list->oidSz) < 0) {
            return NULL;
        }
        if (tag != ASN_OBJECT_ID) {
            WOLFSSL_MSG("Bad attribute ASN1 syntax");
            return NULL;
        }

        if (GetLength(list->oid, &idx, &length, list->oidSz) < 0) {
            WOLFSSL_MSG("Bad attribute length");
            return NULL;
        }

        sz = (sz < (word32)length)? sz : (word32)length;
        if (XMEMCMP(oid, list->oid + idx, sz) == 0) {
            return list;
        }
        list = list->next;
    }
    return NULL;
}


/* Searches through decoded attributes and returns the value for the first one
 * matching the oid passed in. Note that this value includes the leading ASN1
 * syntax. So for a printable string of "3" this would be something like
 *
 * 0x13, 0x01, 0x33
 *  ID   SIZE  "3"
 *
 * pkcs7  structure to get value from
 * oid    OID value to search for with attributes
 * oidSz  size of oid buffer
 * out    buffer to hold result
 * outSz  size of out buffer (if out is NULL this is set to needed size and
          LENGTH_ONLY_E is returned)
 *
 * returns size of value on success
 */
int wc_PKCS7_GetAttributeValue(wc_PKCS7* pkcs7, const byte* oid, word32 oidSz,
        byte* out, word32* outSz)
{
    PKCS7DecodedAttrib* attrib;

    if (pkcs7 == NULL || oid == NULL || outSz == NULL) {
        return BAD_FUNC_ARG;
    }

    attrib = findAttrib(pkcs7, oid, oidSz);
    if (attrib == NULL) {
        return ASN_PARSE_E;
    }

    if (out == NULL) {
        *outSz = attrib->valueSz;
        return WC_NO_ERR_TRACE(LENGTH_ONLY_E);
    }

    if (*outSz < attrib->valueSz) {
        return BUFFER_E;
    }

    XMEMCPY(out, attrib->value, attrib->valueSz);
    return (int)attrib->valueSz;
}


/* build PKCS#7 data content type */
int wc_PKCS7_EncodeData(wc_PKCS7* pkcs7, byte* output, word32 outputSz)
{
    static const byte oid[] =
        { ASN_OBJECT_ID, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01,
                         0x07, 0x01 };
    byte seq[MAX_SEQ_SZ];
    byte octetStr[MAX_OCTET_STR_SZ];
    word32 seqSz;
    word32 octetStrSz;
    word32 oidSz = (word32)sizeof(oid);
    word32 idx = 0;

    if (pkcs7 == NULL || output == NULL) {
        return BAD_FUNC_ARG;
    }

    octetStrSz = SetOctetString(pkcs7->contentSz, octetStr);
    seqSz = SetSequence(pkcs7->contentSz + octetStrSz + oidSz, seq);

    if (outputSz < pkcs7->contentSz + octetStrSz + oidSz + seqSz)
        return BUFFER_E;

    XMEMCPY(output, seq, seqSz);
    idx += seqSz;
    XMEMCPY(output + idx, oid, oidSz);
    idx += oidSz;
    XMEMCPY(output + idx, octetStr, octetStrSz);
    idx += octetStrSz;
    XMEMCPY(output + idx, pkcs7->content, pkcs7->contentSz);
    idx += pkcs7->contentSz;

    return (int)idx;
}


typedef struct EncodedAttrib {
    byte valueSeq[MAX_SEQ_SZ];
        const byte* oid;
        byte valueSet[MAX_SET_SZ];
        const byte* value;
    word32 valueSeqSz, oidSz, idSz, valueSetSz, valueSz, totalSz;
} EncodedAttrib;


typedef struct ESD {
    wc_HashAlg  hash;
    enum wc_HashType hashType;
    byte contentDigest[WC_MAX_DIGEST_SIZE + 2]; /* content only + ASN.1 heading */
    WC_BITFIELD contentDigestSet:1;
    byte contentAttribsDigest[WC_MAX_DIGEST_SIZE];
    byte encContentDigest[MAX_ENCRYPTED_KEY_SZ];

    byte outerSeq[MAX_SEQ_SZ];
        byte outerContent[MAX_EXP_SZ];
            byte innerSeq[MAX_SEQ_SZ];
                byte version[MAX_VERSION_SZ];
                byte digAlgoIdSet[MAX_SET_SZ];
                    byte singleDigAlgoId[MAX_ALGO_SZ];

                byte contentInfoSeq[MAX_SEQ_SZ];
                    byte innerContSeq[MAX_EXP_SZ];
                        byte innerOctets[MAX_OCTET_STR_SZ];

                byte certsSet[MAX_SET_SZ];

                byte signerInfoSet[MAX_SET_SZ];
                    byte signerInfoSeq[MAX_SEQ_SZ];
                        byte signerVersion[MAX_VERSION_SZ];
                        /* issuerAndSerialNumber ...*/
                        byte issuerSnSeq[MAX_SEQ_SZ];
                            byte issuerName[MAX_SEQ_SZ];
                            byte issuerSn[MAX_SN_SZ];
                        /* OR subjectKeyIdentifier */
                        byte issuerSKIDSeq[MAX_SEQ_SZ];
                            byte issuerSKID[MAX_OCTET_STR_SZ];
                        byte signerDigAlgoId[MAX_ALGO_SZ];
                        byte digEncAlgoId[MAX_ALGO_SZ];
                        byte signedAttribSet[MAX_SET_SZ];
                            EncodedAttrib signedAttribs[7];
                        byte signerDigest[MAX_OCTET_STR_SZ];
    word32 innerOctetsSz, innerContSeqSz, contentInfoSeqSz;
    word32 outerSeqSz, outerContentSz, innerSeqSz, versionSz, digAlgoIdSetSz,
           singleDigAlgoIdSz, certsSetSz;
    word32 signerInfoSetSz, signerInfoSeqSz, signerVersionSz,
           issuerSnSeqSz, issuerNameSz, issuerSnSz, issuerSKIDSz,
           issuerSKIDSeqSz, signerDigAlgoIdSz, digEncAlgoIdSz, signerDigestSz;
    word32 encContentDigestSz, signedAttribsSz, signedAttribsCount,
           signedAttribSetSz;
} ESD;


static int EncodeAttributes(EncodedAttrib* ea, int eaSz,
                                            PKCS7Attrib* attribs, int attribsSz)
{
    int i;
    int maxSz = (int)min((word32)eaSz, (word32)attribsSz);
    int allAttribsSz = 0;

    for (i = 0; i < maxSz; i++)
    {
        word32 attribSz = 0;

        ea[i].value = attribs[i].value;
        ea[i].valueSz = attribs[i].valueSz;
        attribSz += ea[i].valueSz;
        ea[i].valueSetSz = SetSet(attribSz, ea[i].valueSet);
        attribSz += ea[i].valueSetSz;
        ea[i].oid = attribs[i].oid;
        ea[i].oidSz = attribs[i].oidSz;
        attribSz += ea[i].oidSz;
        ea[i].valueSeqSz = SetSequence(attribSz, ea[i].valueSeq);
        attribSz += ea[i].valueSeqSz;
        ea[i].totalSz = attribSz;

        allAttribsSz += (int)attribSz;
    }
    return allAttribsSz;
}


typedef struct FlatAttrib {
    byte* data;
    word32 dataSz;
} FlatAttrib;

/* Returns a pointer to FlatAttrib whose members are initialized to 0.
*  Caller is expected to free.
*/
static FlatAttrib* NewAttrib(void* heap)
{
    FlatAttrib* fb = (FlatAttrib*) XMALLOC(sizeof(FlatAttrib), heap,
                                                   DYNAMIC_TYPE_TMP_BUFFER);
    if (fb != NULL) {
        ForceZero(fb, sizeof(FlatAttrib));
    }
    (void)heap;
    return fb;
}

/* Free FlatAttrib array and memory allocated to internal struct members */
static void FreeAttribArray(wc_PKCS7* pkcs7, FlatAttrib** arr, int rows)
{
    int i;

    if (arr) {
        for (i = 0; i < rows; i++) {
            if (arr[i]) {
                if (arr[i]->data) {
                    ForceZero(arr[i]->data, arr[i]->dataSz);
                    XFREE(arr[i]->data, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
                }
                ForceZero(arr[i], sizeof(FlatAttrib));
                XFREE(arr[i], pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
            }
        }
        ForceZero(arr, (word32)rows);
        XFREE(arr, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
    (void)pkcs7;
}


/* Sort FlatAttrib array in ascending order */
static int SortAttribArray(FlatAttrib** arr, int rows)
{
    int i, j;
    word32 minSz, minIdx;
    FlatAttrib* a   = NULL;
    FlatAttrib* b   = NULL;
    FlatAttrib* tmp = NULL;

    if (arr == NULL) {
        return BAD_FUNC_ARG;
    }

    for (i = 0; i < rows; i++) {
        a = arr[i];
        minSz = a->dataSz;
        minIdx = (word32)i;
        for (j = i+1; j < rows; j++) {
            b = arr[j];
            if (b->dataSz < minSz) {
                minSz = b->dataSz;
                minIdx = (word32)j;
            }
        }
        if (minSz < a->dataSz) {
            /* swap array positions */
            tmp = arr[i];
            arr[i] = arr[minIdx];
            arr[minIdx] = tmp;
        }
    }

    return 0;
}


/* Build up array of FlatAttrib structs from EncodedAttrib ones. FlatAttrib
 * holds flattened DER encoding of each attribute */
static int FlattenEncodedAttribs(wc_PKCS7* pkcs7, FlatAttrib** derArr, int rows,
                                 EncodedAttrib* ea, int eaSz)
{
    int i;
    word32 idx, sz;
    byte* output   = NULL;
    FlatAttrib* fa = NULL;

    if (pkcs7 == NULL || derArr == NULL || ea == NULL) {
        WOLFSSL_MSG("Invalid arguments to FlattenEncodedAttribs");
        return BAD_FUNC_ARG;
    }

    if (rows != eaSz) {
        WOLFSSL_MSG("DER array not large enough to hold attribute count");
        return BAD_FUNC_ARG;
    }

    for (i = 0; i < eaSz; i++) {
        sz = ea[i].valueSeqSz + ea[i].oidSz + ea[i].valueSetSz + ea[i].valueSz;

        output = (byte*)XMALLOC(sz, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (output == NULL) {
            return MEMORY_E;
        }

        idx = 0;
        XMEMCPY(output + idx, ea[i].valueSeq, ea[i].valueSeqSz);
        idx += ea[i].valueSeqSz;
        XMEMCPY(output + idx, ea[i].oid, ea[i].oidSz);
        idx += ea[i].oidSz;
        XMEMCPY(output + idx, ea[i].valueSet, ea[i].valueSetSz);
        idx += ea[i].valueSetSz;
        XMEMCPY(output + idx, ea[i].value, ea[i].valueSz);

        fa = derArr[i];
        fa->data = output;
        fa->dataSz = sz;
    }

    return 0;
}


/* Sort and Flatten EncodedAttrib attributes into output buffer */
static int FlattenAttributes(wc_PKCS7* pkcs7, byte* output, EncodedAttrib* ea,
                             int eaSz)
{
    int i, ret;
    word32 idx;
    FlatAttrib** derArr = NULL;
    FlatAttrib*  fa     = NULL;

    if (pkcs7 == NULL || output == NULL || ea == NULL) {
        return BAD_FUNC_ARG;
    }

    /* create array of FlatAttrib struct pointers to hold DER attribs */
    derArr = (FlatAttrib**) XMALLOC((unsigned long)eaSz * sizeof(FlatAttrib*), pkcs7->heap,
                                    DYNAMIC_TYPE_TMP_BUFFER);
    if (derArr == NULL) {
        return MEMORY_E;
    }
    XMEMSET(derArr, 0, (unsigned long)eaSz * sizeof(FlatAttrib*));

    for (i = 0; i < eaSz; i++) {
        derArr[i] = NewAttrib(pkcs7->heap);
        if (derArr[i] == NULL) {
            FreeAttribArray(pkcs7, derArr, eaSz);
            return MEMORY_E;
        }
        ForceZero(derArr[i], sizeof(FlatAttrib));
    }

    /* flatten EncodedAttrib into DER byte arrays */
    ret = FlattenEncodedAttribs(pkcs7, derArr, eaSz, ea, eaSz);
    if (ret != 0) {
        FreeAttribArray(pkcs7, derArr, eaSz);
        return ret;
    }

    /* SET OF DER signed attributes must be sorted in ascending order */
    ret = SortAttribArray(derArr, eaSz);
    if (ret != 0) {
        FreeAttribArray(pkcs7, derArr, eaSz);
        return ret;
    }

    /* copy sorted DER attribute arrays into output buffer */
    idx = 0;
    for (i = 0; i < eaSz; i++) {
        fa = derArr[i];
        XMEMCPY(output + idx, fa->data, fa->dataSz);
        idx += fa->dataSz;
    }

    FreeAttribArray(pkcs7, derArr, eaSz);

    return 0;
}


#ifndef NO_RSA

static int wc_PKCS7_ImportRSA(wc_PKCS7* pkcs7, RsaKey* privKey)
{
    int ret;
    word32 idx;

    ret = wc_InitRsaKey_ex(privKey, pkcs7->heap, pkcs7->devId);
    if (ret == 0) {
        if (pkcs7->privateKey != NULL && pkcs7->privateKeySz > 0) {
            idx = 0;
            ret = wc_RsaPrivateKeyDecode(pkcs7->privateKey, &idx, privKey,
                                         pkcs7->privateKeySz);
            /* If not using old FIPS or CAVP selftest, or not using FAST,
             * or USER RSA, able to check RSA key. */
            if (ret == 0) {
        #ifdef WOLFSSL_RSA_KEY_CHECK
                /* verify imported private key is a valid key before using it */
                ret = wc_CheckRsaKey(privKey);
                if (ret != 0) {
                    WOLFSSL_MSG("Invalid RSA private key, check "
                                "pkcs7->privateKey");
                }
        #endif
            }
        #ifdef WOLF_CRYPTO_CB
            else if (ret == WC_NO_ERR_TRACE(ASN_PARSE_E) &&
                     pkcs7->devId != INVALID_DEVID) {
                /* if using crypto callbacks, try public key decode */
                idx = 0;
                ret = wc_RsaPublicKeyDecode(pkcs7->privateKey, &idx, privKey,
                                            pkcs7->privateKeySz);
            }
        #endif
        }
        else if (pkcs7->devId == INVALID_DEVID) {
            ret = BAD_FUNC_ARG;
        }
    }

    return ret;
}


/* returns size of signature put into out, negative on error */
static int wc_PKCS7_RsaSign(wc_PKCS7* pkcs7, byte* in, word32 inSz, ESD* esd)
{
    int ret;
#ifdef WOLFSSL_SMALL_STACK
    RsaKey* privKey;
#else
    RsaKey  privKey[1];
#endif

    if (pkcs7 == NULL || pkcs7->rng == NULL || in == NULL || esd == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_SMALL_STACK
    privKey = (RsaKey*)XMALLOC(sizeof(RsaKey), pkcs7->heap,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (privKey == NULL)
        return MEMORY_E;
#endif

    ret = wc_PKCS7_ImportRSA(pkcs7, privKey);
    if (ret == 0) {
    #ifdef WOLFSSL_ASYNC_CRYPT
        do {
            ret = wc_AsyncWait(ret, &privKey->asyncDev,
                WC_ASYNC_FLAG_CALL_AGAIN);
            if (ret >= 0)
    #endif
            {
                ret = wc_RsaSSL_Sign(in, inSz, esd->encContentDigest,
                                     sizeof(esd->encContentDigest),
                                     privKey, pkcs7->rng);
            }
    #ifdef WOLFSSL_ASYNC_CRYPT
        } while (ret == WC_NO_ERR_TRACE(WC_PENDING_E));
    #endif
    }

    wc_FreeRsaKey(privKey);
#ifdef WOLFSSL_SMALL_STACK
    XFREE(privKey, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}

#endif /* NO_RSA */


#ifdef HAVE_ECC

static int wc_PKCS7_ImportECC(wc_PKCS7* pkcs7, ecc_key* privKey)
{
    int ret;
    word32 idx;

    ret = wc_ecc_init_ex(privKey, pkcs7->heap, pkcs7->devId);
    if (ret == 0) {
        if (pkcs7->privateKey != NULL && pkcs7->privateKeySz > 0) {
            idx = 0;
            ret = wc_EccPrivateKeyDecode(pkcs7->privateKey, &idx, privKey,
                                         pkcs7->privateKeySz);
            /* verify imported private key is a valid key before using it */
            if (ret == 0) {
                ret = wc_ecc_check_key(privKey);
                if (ret != 0) {
                    WOLFSSL_MSG("Invalid ECC private key, check "
                                "pkcs7->privateKey");
                }
            }
        #ifdef WOLF_CRYPTO_CB
            else if (ret == WC_NO_ERR_TRACE(ASN_PARSE_E) &&
                     pkcs7->devId != INVALID_DEVID) {
                /* if using crypto callbacks, try public key decode */
                idx = 0;
                ret = wc_EccPublicKeyDecode(pkcs7->privateKey, &idx, privKey,
                                            pkcs7->privateKeySz);
            }
        #endif
        }
        else if (pkcs7->devId == INVALID_DEVID) {
            ret = BAD_FUNC_ARG;
        }
    }

    return ret;
}


/* returns size of signature put into out, negative on error */
static int wc_PKCS7_EcdsaSign(wc_PKCS7* pkcs7, byte* in, word32 inSz, ESD* esd)
{
    int ret;
    word32 outSz;
#ifdef WOLFSSL_SMALL_STACK
    ecc_key* privKey;
#else
    ecc_key  privKey[1];
#endif

    if (pkcs7 == NULL || pkcs7->rng == NULL || in == NULL || esd == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_SMALL_STACK
    privKey = (ecc_key*)XMALLOC(sizeof(ecc_key), pkcs7->heap,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (privKey == NULL)
        return MEMORY_E;
#endif

    ret = wc_PKCS7_ImportECC(pkcs7, privKey);
    if (ret == 0) {
        outSz = sizeof(esd->encContentDigest);
    #ifdef WOLFSSL_ASYNC_CRYPT
        do {
            ret = wc_AsyncWait(ret, &privKey->asyncDev,
                WC_ASYNC_FLAG_CALL_AGAIN);
            if (ret >= 0)
    #endif
            {
                ret = wc_ecc_sign_hash(in, inSz, esd->encContentDigest,
                                       &outSz, pkcs7->rng, privKey);
            }
    #ifdef WOLFSSL_ASYNC_CRYPT
        } while (ret == WC_NO_ERR_TRACE(WC_PENDING_E));
    #endif
        if (ret == 0)
            ret = (int)outSz;
    }

    wc_ecc_free(privKey);
#ifdef WOLFSSL_SMALL_STACK
    XFREE(privKey, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return ret;
}

#endif /* HAVE_ECC */

/* returns encContentDigestSz based on the signature set to be used */
static int wc_PKCS7_GetSignSize(wc_PKCS7* pkcs7)
{
    int ret = 0;

    switch (pkcs7->publicKeyOID) {

    #ifndef NO_RSA
        case RSAk:
        {
        #ifndef WOLFSSL_SMALL_STACK
            RsaKey  privKey[1];
        #else
            RsaKey* privKey;
            privKey = (RsaKey*)XMALLOC(sizeof(RsaKey), pkcs7->heap,
                DYNAMIC_TYPE_TMP_BUFFER);
            if (privKey == NULL)
                return MEMORY_E;
        #endif

            ret = wc_PKCS7_ImportRSA(pkcs7, privKey);
            if (ret == 0) {
                ret = wc_RsaEncryptSize(privKey);
            }
            wc_FreeRsaKey(privKey);
        #ifdef WOLFSSL_SMALL_STACK
            XFREE(privKey, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        #endif
        }
        break;
    #endif

    #ifdef HAVE_ECC
        case ECDSAk:
        {
        #ifndef WOLFSSL_SMALL_STACK
            ecc_key  privKey[1];
        #else
            ecc_key* privKey;
            privKey = (ecc_key*)XMALLOC(sizeof(ecc_key), pkcs7->heap,
                DYNAMIC_TYPE_TMP_BUFFER);
            if (privKey == NULL)
                return MEMORY_E;
        #endif

            ret = wc_PKCS7_ImportECC(pkcs7, privKey);
            if (ret == 0) {
                ret = wc_ecc_sig_size(privKey);
            }
            wc_ecc_free(privKey);
        #ifdef WOLFSSL_SMALL_STACK
            XFREE(privKey, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        #endif
        }
        break;
    #endif
    }

    return ret;
}


/* builds up SignedData signed attributes, including default ones.
 *
 * pkcs7 - pointer to initialized PKCS7 structure
 * esd   - pointer to initialized ESD structure, used for output
 *
 * return 0 on success, negative on error */
static int wc_PKCS7_BuildSignedAttributes(wc_PKCS7* pkcs7, ESD* esd,
                    const byte* contentType, word32 contentTypeSz,
                    const byte* contentTypeOid, word32 contentTypeOidSz,
                    const byte* messageDigestOid, word32 messageDigestOidSz,
                    const byte* signingTimeOid, word32 signingTimeOidSz,
                    byte* signingTime, word32 signingTimeSz)
{
    int hashSz;
#ifdef NO_ASN_TIME
    PKCS7Attrib cannedAttribs[2];
#else
    time_t tm;
    int timeSz;
    PKCS7Attrib cannedAttribs[3];
#endif
    word32 idx    = 0;
    word32 atrIdx = 0;
    word32 cannedAttribsCount;

    if (pkcs7 == NULL || esd == NULL || contentType == NULL ||
        contentTypeOid == NULL || messageDigestOid == NULL ||
        signingTimeOid == NULL) {
        return BAD_FUNC_ARG;
    }

    if (pkcs7->defaultSignedAttribs != WOLFSSL_NO_ATTRIBUTES) {
        hashSz = wc_HashGetDigestSize(esd->hashType);
        if (hashSz < 0)
            return hashSz;

    #ifndef NO_ASN_TIME
        if (signingTime == NULL || signingTimeSz == 0)
            return BAD_FUNC_ARG;

        tm = wc_Time(0);
        timeSz = GetAsnTimeString(&tm, signingTime, signingTimeSz);
        if (timeSz < 0)
            return timeSz;
    #endif

        cannedAttribsCount = sizeof(cannedAttribs)/sizeof(PKCS7Attrib);

        if ((pkcs7->defaultSignedAttribs & WOLFSSL_CONTENT_TYPE_ATTRIBUTE) ||
            pkcs7->defaultSignedAttribs == 0) {
            cannedAttribs[idx].oid     = contentTypeOid;
            cannedAttribs[idx].oidSz   = contentTypeOidSz;
            cannedAttribs[idx].value   = contentType;
            cannedAttribs[idx].valueSz = contentTypeSz;
            idx++;
        }

    #ifndef NO_ASN_TIME
        if ((pkcs7->defaultSignedAttribs & WOLFSSL_SIGNING_TIME_ATTRIBUTE) ||
            pkcs7->defaultSignedAttribs == 0) {
            cannedAttribs[idx].oid     = signingTimeOid;
            cannedAttribs[idx].oidSz   = signingTimeOidSz;
            cannedAttribs[idx].value   = signingTime;
            cannedAttribs[idx].valueSz = (word32)timeSz;
            idx++;
        }
    #endif

        if ((pkcs7->defaultSignedAttribs & WOLFSSL_MESSAGE_DIGEST_ATTRIBUTE) ||
            pkcs7->defaultSignedAttribs == 0) {
            cannedAttribs[idx].oid     = messageDigestOid;
            cannedAttribs[idx].oidSz   = messageDigestOidSz;
            cannedAttribs[idx].value   = esd->contentDigest;
            cannedAttribs[idx].valueSz = (word32)hashSz + 2;  /* ASN.1 heading */
            idx++;
        }

        esd->signedAttribsCount += cannedAttribsCount;
        esd->signedAttribsSz += (word32)EncodeAttributes(
            &esd->signedAttribs[atrIdx], (int)idx, cannedAttribs,
            (int)cannedAttribsCount);
        atrIdx += idx;
    } else {
        esd->signedAttribsCount = 0;
        esd->signedAttribsSz = 0;
    }

    /* add custom signed attributes if set */
    if (pkcs7->signedAttribsSz > 0 && pkcs7->signedAttribs != NULL) {
        esd->signedAttribsCount += pkcs7->signedAttribsSz;
        esd->signedAttribsSz += (word32)EncodeAttributes(
            &esd->signedAttribs[atrIdx], (int)esd->signedAttribsCount,
            pkcs7->signedAttribs, (int)pkcs7->signedAttribsSz);
    }

#ifdef NO_ASN_TIME
    (void)signingTimeOidSz;
    (void)signingTime;
    (void)signingTimeSz;
#endif

    return 0;
}


/* gets correct encryption algo ID for SignedData, either CTC_<hash>wRSA or
 * CTC_<hash>wECDSA, from pkcs7->publicKeyOID and pkcs7->hashOID.
 *
 * pkcs7          - pointer to PKCS7 structure
 * digEncAlgoId   - [OUT] output int to store correct algo ID in
 * digEncAlgoType - [OUT] output for algo ID type
 *
 * return 0 on success, negative on error */
static int wc_PKCS7_SignedDataGetEncAlgoId(wc_PKCS7* pkcs7, int* digEncAlgoId,
                                           int* digEncAlgoType)
{
    int algoId   = 0;
    int algoType = 0;

    if (pkcs7 == NULL || digEncAlgoId == NULL || digEncAlgoType == NULL)
        return BAD_FUNC_ARG;

    if (pkcs7->publicKeyOID == RSAk) {

        algoType = oidSigType;

        switch (pkcs7->hashOID) {
        #ifndef NO_SHA
            case SHAh:
                algoId = CTC_SHAwRSA;
                break;
        #endif
        #ifdef WOLFSSL_SHA224
            case SHA224h:
                algoId = CTC_SHA224wRSA;
                break;
        #endif
        #ifndef NO_SHA256
            case SHA256h:
                algoId = CTC_SHA256wRSA;
                break;
        #endif
        #ifdef WOLFSSL_SHA384
            case SHA384h:
                algoId = CTC_SHA384wRSA;
                break;
        #endif
        #ifdef WOLFSSL_SHA512
            case SHA512h:
                algoId = CTC_SHA512wRSA;
                break;
        #endif
        #ifdef WOLFSSL_SHA3
        #ifndef WOLFSSL_NOSHA3_224
            case SHA3_224h:
                algoId = CTC_SHA3_224wRSA;
                break;
        #endif
        #ifndef WOLFSSL_NOSHA3_256
            case SHA3_256h:
                algoId = CTC_SHA3_256wRSA;
                break;
        #endif
        #ifndef WOLFSSL_NOSHA3_384
            case SHA3_384h:
                algoId = CTC_SHA3_384wRSA;
                break;
        #endif
        #ifndef WOLFSSL_NOSHA3_512
            case SHA3_512h:
                algoId = CTC_SHA3_512wRSA;
                break;
        #endif
        #endif
        }

    }
#ifdef HAVE_ECC
    else if (pkcs7->publicKeyOID == ECDSAk) {

        algoType = oidSigType;

        switch (pkcs7->hashOID) {
        #ifndef NO_SHA
            case SHAh:
                algoId = CTC_SHAwECDSA;
                break;
        #endif
        #ifdef WOLFSSL_SHA224
            case SHA224h:
                algoId = CTC_SHA224wECDSA;
                break;
        #endif
        #ifndef NO_SHA256
            case SHA256h:
                algoId = CTC_SHA256wECDSA;
                break;
        #endif
        #ifdef WOLFSSL_SHA384
            case SHA384h:
                algoId = CTC_SHA384wECDSA;
                break;
        #endif
        #ifdef WOLFSSL_SHA512
            case SHA512h:
                algoId = CTC_SHA512wECDSA;
                break;
        #endif
        #ifdef WOLFSSL_SHA3
        #ifndef WOLFSSL_NOSHA3_224
            case SHA3_224h:
                algoId = CTC_SHA3_224wECDSA;
                break;
        #endif
        #ifndef WOLFSSL_NOSHA3_256
            case SHA3_256h:
                algoId = CTC_SHA3_256wECDSA;
                break;
        #endif
        #ifndef WOLFSSL_NOSHA3_384
            case SHA3_384h:
                algoId = CTC_SHA3_384wECDSA;
                break;
        #endif
        #ifndef WOLFSSL_NOSHA3_512
            case SHA3_512h:
                algoId = CTC_SHA3_512wECDSA;
                break;
        #endif
        #endif
        }
    }
#endif /* HAVE_ECC */

    if (algoId == 0) {
        WOLFSSL_MSG("Invalid signature algorithm type");
        return BAD_FUNC_ARG;
    }

    *digEncAlgoId = algoId;
    *digEncAlgoType = algoType;

    return 0;
}


/* build SignedData DigestInfo for use with PKCS#7/RSA
 *
 * pkcs7 - pointer to initialized PKCS7 struct
 * flatSignedAttribs - flattened, signed attributes
 * flatSignedAttrbsSz - size of flatSignedAttribs, octets
 * esd - pointer to initialized ESD struct
 * digestInfo - [OUT] output array for DigestInfo
 * digestInfoSz - [IN/OUT] - input size of array, size of digestInfo
 *
 * return 0 on success, negative on error */
static int wc_PKCS7_BuildDigestInfo(wc_PKCS7* pkcs7, byte* flatSignedAttribs,
                                    word32 flatSignedAttribsSz, ESD* esd,
                                    byte* digestInfo, word32* digestInfoSz)
{
    int ret, digIdx = 0;
    byte digestInfoSeq[MAX_SEQ_SZ];
    byte digestStr[MAX_OCTET_STR_SZ];
    byte attribSet[MAX_SET_SZ];
    byte algoId[MAX_ALGO_SZ];
    word32 digestInfoSeqSz, digestStrSz, algoIdSz, dgstInfoSz, hashSz;
    word32 attribSetSz;

    if (pkcs7 == NULL || esd == NULL || digestInfo == NULL ||
        digestInfoSz == NULL) {
        return BAD_FUNC_ARG;
    }

    ret = wc_HashGetDigestSize(esd->hashType);
    if (ret < 0)
        return ret;
    hashSz = (word32)ret;

    if (flatSignedAttribsSz != 0) {

        if (flatSignedAttribs == NULL)
            return BAD_FUNC_ARG;

        attribSetSz = SetSet(flatSignedAttribsSz, attribSet);

        ret = wc_HashInit(&esd->hash, esd->hashType);
        if (ret < 0)
            return ret;

        ret = wc_HashUpdate(&esd->hash, esd->hashType,
                            attribSet, attribSetSz);
        if (ret == 0)
            ret = wc_HashUpdate(&esd->hash, esd->hashType,
                                flatSignedAttribs, flatSignedAttribsSz);
        if (ret == 0)
            ret = wc_HashFinal(&esd->hash, esd->hashType,
                               esd->contentAttribsDigest);
        wc_HashFree(&esd->hash, esd->hashType);

        if (ret < 0)
            return ret;

    } else {
        /* when no attrs, digest is contentDigest without tag and length */
        XMEMCPY(esd->contentAttribsDigest, esd->contentDigest + 2, hashSz);
    }

    /* Set algoID, allow absent hash params */
    algoIdSz = SetAlgoIDEx(pkcs7->hashOID, algoId, oidHashType,
                           0, pkcs7->hashParamsAbsent);

    digestStrSz = SetOctetString(hashSz, digestStr);
    dgstInfoSz = algoIdSz + digestStrSz + hashSz;
    digestInfoSeqSz = SetSequence(dgstInfoSz, digestInfoSeq);

    if (*digestInfoSz < (digestInfoSeqSz + dgstInfoSz)) {
        return BUFFER_E;
    }

    XMEMCPY(digestInfo + digIdx, digestInfoSeq, digestInfoSeqSz);
    digIdx += (int)digestInfoSeqSz;
    XMEMCPY(digestInfo + digIdx, algoId, algoIdSz);
    digIdx += (int)algoIdSz;
    XMEMCPY(digestInfo + digIdx, digestStr, digestStrSz);
    digIdx += (int)digestStrSz;
    XMEMCPY(digestInfo + digIdx, esd->contentAttribsDigest, hashSz);
    digIdx += (int)hashSz;

    *digestInfoSz = (word32)digIdx;

    return 0;
}


/* build SignedData signature over DigestInfo or content digest
 *
 * pkcs7 - pointer to initialized PKCS7 struct
 * flatSignedAttribs - flattened, signed attributes
 * flatSignedAttribsSz - size of flatSignedAttribs, octets
 * esd - pointer to initialized ESD struct
 *
 * returns length of signature on success, negative on error */
static int wc_PKCS7_SignedDataBuildSignature(wc_PKCS7* pkcs7,
                                             byte* flatSignedAttribs,
                                             word32 flatSignedAttribsSz,
                                             ESD* esd)
{
    int ret = 0;
#if defined(HAVE_ECC) || \
    (defined(HAVE_PKCS7_RSA_RAW_SIGN_CALLBACK) && !defined(NO_RSA))
    int hashSz = 0;
#endif
#if defined(HAVE_PKCS7_RSA_RAW_SIGN_CALLBACK) && !defined(NO_RSA)
    int hashOID;
#endif
    word32 digestInfoSz = MAX_PKCS7_DIGEST_SZ;
#ifdef WOLFSSL_SMALL_STACK
    byte* digestInfo;
#else
    byte  digestInfo[MAX_PKCS7_DIGEST_SZ];
#endif

    if (pkcs7 == NULL || esd == NULL)
        return BAD_FUNC_ARG;

#ifdef WOLFSSL_SMALL_STACK
    digestInfo = (byte*)XMALLOC(digestInfoSz, pkcs7->heap,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (digestInfo == NULL) {
        return MEMORY_E;
    }
#endif
    XMEMSET(digestInfo, 0, digestInfoSz);

    ret = wc_PKCS7_BuildDigestInfo(pkcs7, flatSignedAttribs,
                                   flatSignedAttribsSz, esd, digestInfo,
                                   &digestInfoSz);
    if (ret < 0) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(digestInfo, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return ret;
    }

#if defined(HAVE_ECC) || \
    (defined(HAVE_PKCS7_RSA_RAW_SIGN_CALLBACK) && !defined(NO_RSA))
    /* get digest size from hash type */
    hashSz = wc_HashGetDigestSize(esd->hashType);
    if (hashSz < 0) {
    #ifdef WOLFSSL_SMALL_STACK
        XFREE(digestInfo, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
    #endif
        return hashSz;
    }
#endif

    /* sign digestInfo */
    switch (pkcs7->publicKeyOID) {

#ifndef NO_RSA
        case RSAk:
        #ifdef HAVE_PKCS7_RSA_RAW_SIGN_CALLBACK
            if (pkcs7->rsaSignRawDigestCb != NULL) {
                /* get hash OID */
                hashOID = wc_HashGetOID(esd->hashType);

                /* user signing plain digest, build DigestInfo themselves */
                ret = pkcs7->rsaSignRawDigestCb(pkcs7,
                           esd->contentAttribsDigest, hashSz,
                           esd->encContentDigest, sizeof(esd->encContentDigest),
                           pkcs7->privateKey, pkcs7->privateKeySz, pkcs7->devId,
                           hashOID);
                break;
            }
        #endif
            ret = wc_PKCS7_RsaSign(pkcs7, digestInfo, digestInfoSz, esd);
            break;
#endif

#ifdef HAVE_ECC
        case ECDSAk:
            /* CMS with ECDSA does not sign DigestInfo structure
             * like PKCS#7 with RSA does */
            ret = wc_PKCS7_EcdsaSign(pkcs7, esd->contentAttribsDigest,
                                     (word32)hashSz, esd);
            break;
#endif

        default:
            WOLFSSL_MSG("Unsupported public key type");
            ret = BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(digestInfo, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    if (ret >= 0) {
        esd->encContentDigestSz = (word32)ret;
    }

    return ret;
}

#ifndef BER_OCTET_LENGTH
    #define BER_OCTET_LENGTH 4096
#endif

/**
 * This helper function encodes a chunk of content stream and writes it out.
 *
 * @param pkcs7 Pointer to a PKCS7 structure.
 * @param cipherType The type of cipher to use for encryption.
 * @param aes Optional pointer to an Aes structure for AES encryption.
 * @param encContentOut Buffer to hold the encrypted content.
 * @param contentData Buffer holding the content to be encrypted.
 * @param contentDataSz Size of the content to be encrypted.
 * @param out Buffer to hold the output data.
 * @param outIdx Pointer to an index into the output buffer.
 * @param esd Pointer to an ESD structure for digest calculation.
 * @return Returns 0 on success, and a negative value on failure.
 */
static int wc_PKCS7_EncodeContentStreamHelper(wc_PKCS7* pkcs7, int cipherType,
    Aes* aes, byte* encContentOut, byte* contentData, int contentDataSz,
    byte* out, word32* outIdx, ESD* esd)
{
    int ret = WC_NO_ERR_TRACE(BAD_FUNC_ARG);
    byte   encContentOutOct[MAX_OCTET_STR_SZ];
    word32 encContentOutOctSz = 0;

    switch (cipherType) {
        case WC_CIPHER_NONE:
            XMEMCPY(encContentOut, contentData, (word32)contentDataSz);
            if (esd && esd->contentDigestSet != 1) {
                ret = wc_HashUpdate(&esd->hash, esd->hashType,
                    contentData, (word32)contentDataSz);
            }
            break;

    #ifndef NO_AES
        case WC_CIPHER_AES_CBC:
            ret = wc_AesCbcEncrypt(aes, encContentOut,
                contentData, (word32)contentDataSz);
            break;
    #endif

    #ifdef WOLFSSL_AESGCM_STREAM
        case WC_CIPHER_AES_GCM:
            ret = wc_AesGcmEncryptUpdate(aes, encContentOut,
                    contentData, (word32)contentDataSz, NULL, 0);
            break;
    #endif
    }

    #ifdef WOLFSSL_ASYNC_CRYPT
        /* async encrypt not available here, so block till done */
        if (ret == WC_NO_ERR_TRACE(WC_PENDING_E) &&
            cipherType != WC_CIPHER_NONE) {
            ret = wc_AsyncWait(ret, &aes->asyncDev, WC_ASYNC_FLAG_NONE);
        }
    #endif

    if (ret == 0) {
        encContentOutOctSz = SetOctetString((word32)contentDataSz, encContentOutOct);
        wc_PKCS7_WriteOut(pkcs7, (out)? out + *outIdx: NULL,
                          encContentOutOct, encContentOutOctSz);
        *outIdx += encContentOutOctSz;
        wc_PKCS7_WriteOut(pkcs7, (out)? out + *outIdx : NULL,
                                            encContentOut, (word32)contentDataSz);
        *outIdx += (word32)contentDataSz;
    }

    return ret;
}


/* Used for encoding the content, potentially one octet chunk at a time if
 * in streaming mode with IO callbacks set.
 * Can handle the cipher types:
 *      - WC_CIPHER_NONE, used for encoding signed bundle where no encryption is
 *                        done.
 *      - WC_CIPHER_AES_CBC
 *      - WC_CIPHER_AES_GCM, requires WOLFSSL_AESGCM_STREAM for streaming
 *                           encryption
 * If ESD is passed in then hash of the conentet is collected as processed.
 *
 * Returns 0 on success */
#ifndef NO_AES
static int wc_PKCS7_EncodeContentStream(wc_PKCS7* pkcs7, ESD* esd, Aes* aes,
    byte* in, int inSz, byte* out, int cipherType)
#else
static int wc_PKCS7_EncodeContentStream(wc_PKCS7* pkcs7, ESD* esd, void* aes,
    byte* in, int inSz, byte* out, int cipherType)
#endif
{
    int ret = 0;
    int devId  = pkcs7->devId;
    void* heap = pkcs7->heap;

    if (pkcs7->encodeStream) {
        int    sz;
        word32 totalSz = 0;
        byte*  buf;
        byte*  encContentOut;
        byte*  contentData;
        word32 idx = 0, outIdx = 0;
        word32 padSz = 0;

        if (cipherType != WC_CIPHER_NONE) {
            padSz = (word32)wc_PKCS7_GetPadSize(pkcs7->contentSz,
                   (word32)wc_PKCS7_GetOIDBlockSize(pkcs7->encryptOID));
        }

        if (cipherType == WC_CIPHER_NONE && esd && esd->contentDigestSet != 1) {
            /* calculate hash for content */
            ret = wc_HashInit(&esd->hash, esd->hashType);
            if (ret != 0) {
                return ret;
            }
        }

        encContentOut = (byte *)XMALLOC(BER_OCTET_LENGTH + MAX_OCTET_STR_SZ,
                heap, DYNAMIC_TYPE_PKCS7);
        contentData = (byte *)XMALLOC(BER_OCTET_LENGTH + padSz,
                heap, DYNAMIC_TYPE_PKCS7);

        if (encContentOut == NULL || contentData == NULL) {
            XFREE(encContentOut, heap, DYNAMIC_TYPE_PKCS7);
            XFREE(contentData, heap, DYNAMIC_TYPE_PKCS7);
            WOLFSSL_MSG("Memory allocation failed for content data");
            return MEMORY_E;
        }

        /* keep pulling from content until empty */
        do {
            int contentDataRead = 0;

        #ifdef ASN_BER_TO_DER
            if (pkcs7->getContentCb) {
                contentDataRead = pkcs7->getContentCb(pkcs7,
                                                      &buf, pkcs7->streamCtx);

                if (buf == NULL) {
                    WOLFSSL_MSG("Get content callback returned null "
                        "buffer pointer");
                    XFREE(encContentOut, heap, DYNAMIC_TYPE_PKCS7);
                    XFREE(contentData, heap, DYNAMIC_TYPE_PKCS7);
                    return BAD_FUNC_ARG;
                }
            }
            else
        #endif
            {
                int szLeft = BER_OCTET_LENGTH;

                if (in == NULL) {
                    XFREE(encContentOut, heap, DYNAMIC_TYPE_PKCS7);
                    XFREE(contentData, heap, DYNAMIC_TYPE_PKCS7);
                    return BAD_FUNC_ARG;
                }

                if ((word32)szLeft + totalSz > (word32)inSz)
                    szLeft = inSz - (int)totalSz;

                contentDataRead = szLeft;
                buf = in + totalSz;
            }

            if (contentDataRead <= 0) {
                /* no more data returned from callback */
                break;
            }
            totalSz += (word32)contentDataRead;

            /* check and handle octet boundary */
            sz = contentDataRead;
            if ((int)idx + sz > BER_OCTET_LENGTH) {
                sz = BER_OCTET_LENGTH - (int)idx;
                contentDataRead -= sz;

                XMEMCPY(contentData + idx, buf, (word32)sz);
                ret = wc_PKCS7_EncodeContentStreamHelper(pkcs7, cipherType,
                    aes, encContentOut, contentData, BER_OCTET_LENGTH, out,
                    &outIdx, esd);
                if (ret != 0) {
                    XFREE(encContentOut, heap, DYNAMIC_TYPE_PKCS7);
                    XFREE(contentData, heap, DYNAMIC_TYPE_PKCS7);
                    return ret;
                }

                /* copy over any remaining data */
                XMEMCPY(contentData, buf + sz, (word32)contentDataRead);
                idx = (word32)contentDataRead;
            }
            else {
                /* was not on an octet boundary, copy full
                 * amount over */
                XMEMCPY(contentData + idx, buf, (word32)sz);
                idx += (word32)sz;
            }
        } while (totalSz < pkcs7->contentSz);

        /* add in padding to the end */
        if ((cipherType != WC_CIPHER_NONE) && (totalSz == pkcs7->contentSz)) {
            word32 i;

            if (BER_OCTET_LENGTH < idx) {
                XFREE(encContentOut, heap, DYNAMIC_TYPE_PKCS7);
                XFREE(contentData, heap, DYNAMIC_TYPE_PKCS7);
                return BAD_FUNC_ARG;
            }

            for (i = 0; i < padSz; i++) {
                contentData[idx + i] = (byte)padSz;
            }
            idx += (word32)padSz;
        }

        /* encrypt and flush out remainder of content data */
        ret = wc_PKCS7_EncodeContentStreamHelper(pkcs7, cipherType, aes,
                    encContentOut, contentData, (int)idx, out, &outIdx, esd);
        if (ret == 0) {
            if (cipherType == WC_CIPHER_NONE && esd &&
                    esd->contentDigestSet != 1) {
                ret = wc_HashFinal(&esd->hash, esd->hashType,
                    esd->contentDigest + 2);
                wc_HashFree(&esd->hash, esd->hashType);
            }
        }

        XFREE(encContentOut, heap, DYNAMIC_TYPE_PKCS7);
        XFREE(contentData, heap, DYNAMIC_TYPE_PKCS7);
    }
    else {
        if (in == NULL || out == NULL) {
            return BAD_FUNC_ARG;
        }

        switch (cipherType) {
            case WC_CIPHER_NONE:
                if (!pkcs7->detached) {
                    XMEMCPY(out, in, (word32)inSz);
                }
                if (esd && esd->contentDigestSet != 1) {
                    ret = wc_HashInit(&esd->hash, esd->hashType);
                    if (ret == 0)
                        ret = wc_HashUpdate(&esd->hash, esd->hashType, in,
                                            (word32)inSz);
                    if (ret == 0)
                        ret = wc_HashFinal(&esd->hash, esd->hashType,
                                           esd->contentDigest + 2);
                    wc_HashFree(&esd->hash, esd->hashType);
                }
                break;

        #ifndef NO_AES
            case WC_CIPHER_AES_CBC:
                ret = wc_AesCbcEncrypt(aes, out, in, (word32)inSz);
                break;
        #endif

        #ifdef WOLFSSL_AESGCM_STREAM
            case WC_CIPHER_AES_GCM:
                ret = wc_AesGcmEncryptUpdate(aes, out, in, (word32)inSz, NULL, 0);
                break;
        #endif
        }
    #ifdef WOLFSSL_ASYNC_CRYPT
        /* async encrypt not available here, so block till done */
        if (cipherType != WC_CIPHER_NONE) {
            ret = wc_AsyncWait(ret, &aes->asyncDev, WC_ASYNC_FLAG_NONE);
        }
    #endif
    }

    (void)devId;
    (void)heap;

    return ret;
}


/* build PKCS#7 signedData content type */
/* To get the output size then set output = 0 and *outputSz = 0 */
static int PKCS7_EncodeSigned(wc_PKCS7* pkcs7,
    const byte* hashBuf, word32 hashSz, byte* output, word32* outputSz,
    byte* output2, word32* output2Sz)
{
    /* contentType OID (1.2.840.113549.1.9.3) */
    static const byte contentTypeOid[] =
            { ASN_OBJECT_ID, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xF7, 0x0d, 0x01,
                             0x09, 0x03 };

    /* messageDigest OID (1.2.840.113549.1.9.4) */
    static const byte messageDigestOid[] =
            { ASN_OBJECT_ID, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
                             0x09, 0x04 };

    /* signingTime OID () */
    static const byte signingTimeOid[] =
            { ASN_OBJECT_ID, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01,
                             0x09, 0x05};

    Pkcs7Cert* certPtr = NULL;
    word32 certSetSz = 0;

    word32 signerInfoSz = 0;
    word32 totalSz, total2Sz;
    int idx = 0, ret = 0;
    int digEncAlgoId, digEncAlgoType;
    int keyIdSize;
    byte* flatSignedAttribs = NULL;
    word32 flatSignedAttribsSz = 0;

#ifdef WOLFSSL_SMALL_STACK
    ESD* esd = NULL;
#else
    ESD  esd[1];
#endif
#ifdef ASN_BER_TO_DER
    word32 streamSz = 0;
#endif
#ifdef WOLFSSL_SMALL_STACK
    byte *signedDataOid = NULL;
#else
    byte signedDataOid[MAX_OID_SZ];
#endif
    word32 signedDataOidSz;

    byte signingTime[MAX_TIME_STRING_SZ];

    if (pkcs7 == NULL || pkcs7->hashOID == 0 ||
        outputSz == NULL) {
        WOLFSSL_MSG("PKCS7 struct / outputSz null, or hashOID is 0");
        return BAD_FUNC_ARG;
    }

    if (hashSz == 0 && hashBuf != NULL) {
        return BAD_FUNC_ARG;
    }

    /* signature size varies with ECDSA, with a varying sign size the content
     * hash must be known in order to create the surrounding ASN1 syntax
     * properly before writing out the content and generating the hash on the
     * fly and then creating the signature */
    if (hashBuf == NULL && pkcs7->publicKeyOID == ECDSAk) {
        WOLFSSL_MSG("Pre-calculated content hash is needed in this case");
        return BAD_FUNC_ARG;
    }

#if defined(WOLFSSL_SM2) && defined(WOLFSSL_SM3)
    keyIdSize = wc_HashGetDigestSize(wc_HashTypeConvert(HashIdAlg(
           pkcs7->publicKeyOID)));
#else
    keyIdSize = KEYID_SIZE;
#endif

    /* use custom SKID if set */
    if (pkcs7->customSKIDSz > 0) {
        if (pkcs7->customSKID == NULL) {
            WOLFSSL_MSG("Bad custom SKID setup, size > 0 and was NULL");
            return BAD_FUNC_ARG;
        }
        keyIdSize = pkcs7->customSKIDSz;
    }

#ifdef WOLFSSL_SMALL_STACK
    signedDataOid = (byte *)XMALLOC(MAX_OID_SZ, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (signedDataOid == NULL) {
        idx = MEMORY_E;
        goto out;
    }

    esd = (ESD*)XMALLOC(sizeof(ESD), pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (esd == NULL) {
        idx = MEMORY_E;
        goto out;
    }
#endif

    XMEMSET(esd, 0, sizeof(ESD));

    /* set content type based on contentOID, unless user has set custom one
       with wc_PKCS7_SetContentType() */
    if (pkcs7->contentTypeSz == 0) {

        /* default to DATA content type if user has not set */
        if (pkcs7->contentOID == 0) {
            pkcs7->contentOID = DATA;
        }

        ret = wc_SetContentType(pkcs7->contentOID, pkcs7->contentType,
                                sizeof(pkcs7->contentType));
        if (ret < 0) {
            idx = ret;
            goto out;
        }
        pkcs7->contentTypeSz = (word32)ret;
    }

    /* set signedData outer content type */
    ret = wc_SetContentType(SIGNED_DATA, signedDataOid, MAX_OID_SZ);
    if (ret < 0) {
        idx = ret;
        goto out;
    }
    signedDataOidSz = (word32)ret;

    if (pkcs7->sidType != DEGENERATE_SID) {
        esd->hashType = wc_OidGetHash(pkcs7->hashOID);
        if (hashBuf != NULL &&
                wc_HashGetDigestSize(esd->hashType) != (int)hashSz) {
            WOLFSSL_MSG("hashSz did not match hashOID");
            idx = BUFFER_E;
            goto out;
        }

        /* include hash if provided, otherwise create hash when processing
         * content data */
        esd->contentDigest[0] = ASN_OCTET_STRING;
        if (hashBuf != NULL) {
            esd->contentDigestSet = 1;
            esd->contentDigest[1] = (byte)hashSz;
            XMEMCPY(&esd->contentDigest[2], hashBuf, hashSz);
        }
        else {
            esd->contentDigest[1] = (byte)wc_HashGetDigestSize(esd->hashType);
        }
    }

    if (pkcs7->detached == 1) {
        /* do not include content if generating detached signature */
        esd->innerOctetsSz = 0;
        esd->innerContSeqSz = 0;
        esd->contentInfoSeqSz = SetSequence(pkcs7->contentTypeSz,
                                            esd->contentInfoSeq);
    }
    else {
        esd->innerOctetsSz = SetOctetStringEx(pkcs7->contentSz, esd->innerOctets,
                                    pkcs7->encodeStream);
        esd->innerContSeqSz = SetExplicit(0, esd->innerOctetsSz +
                                    pkcs7->contentSz, esd->innerContSeq,
                                    pkcs7->encodeStream);
        esd->contentInfoSeqSz = SetSequenceEx(pkcs7->contentSz +
                                    esd->innerOctetsSz + pkcs7->contentTypeSz +
                                    esd->innerContSeqSz, esd->contentInfoSeq,
                                    pkcs7->encodeStream);
    }

    /* SignerIdentifier */
    if (pkcs7->sidType == CMS_ISSUER_AND_SERIAL_NUMBER) {
        /* IssuerAndSerialNumber */
        esd->issuerSnSz = (word32)SetSerialNumber(pkcs7->issuerSn, pkcs7->issuerSnSz,
                                          esd->issuerSn, MAX_SN_SZ, MAX_SN_SZ);
        signerInfoSz += esd->issuerSnSz;
        esd->issuerNameSz = SetSequence(pkcs7->issuerSz, esd->issuerName);
        signerInfoSz += esd->issuerNameSz + pkcs7->issuerSz;
        esd->issuerSnSeqSz = SetSequence(signerInfoSz, esd->issuerSnSeq);
        signerInfoSz += esd->issuerSnSeqSz;

        if (pkcs7->version == 3) {
            /* RFC 4108 version MUST be 3 for firmware package signer */
            esd->signerVersionSz = (word32)SetMyVersion(3, esd->signerVersion, 0);
        }
        else {
            /* version MUST be 1 otherwise*/
            esd->signerVersionSz = (word32)SetMyVersion(1, esd->signerVersion, 0);
        }

    } else if (pkcs7->sidType == CMS_SKID) {
        /* SubjectKeyIdentifier */
        esd->issuerSKIDSz = SetOctetString((word32)keyIdSize, esd->issuerSKID);
        esd->issuerSKIDSeqSz = SetExplicit(0, esd->issuerSKIDSz +
                                           (word32)keyIdSize,
                                           esd->issuerSKIDSeq, 0);
        signerInfoSz += (esd->issuerSKIDSz + esd->issuerSKIDSeqSz +
                         (word32)keyIdSize);

        /* version MUST be 3 */
        esd->signerVersionSz = (word32)SetMyVersion(3, esd->signerVersion, 0);
    } else if (pkcs7->sidType == DEGENERATE_SID) {
        /* no signer info added */
    } else {
        idx = SKID_E;
        goto out;
    }

    if (pkcs7->sidType != DEGENERATE_SID) {
        signerInfoSz += esd->signerVersionSz;
        esd->signerDigAlgoIdSz = SetAlgoIDEx(pkcs7->hashOID, esd->signerDigAlgoId,
                                          oidHashType, 0, pkcs7->hashParamsAbsent);
        signerInfoSz += esd->signerDigAlgoIdSz;

        /* set signatureAlgorithm */
        ret = wc_PKCS7_SignedDataGetEncAlgoId(pkcs7, &digEncAlgoId,
                                              &digEncAlgoType);
        if (ret < 0) {
            idx = ret;
            goto out;
        }
        esd->digEncAlgoIdSz = SetAlgoIDEx(digEncAlgoId, esd->digEncAlgoId,
                                        digEncAlgoType, 0, pkcs7->hashParamsAbsent);
        signerInfoSz += esd->digEncAlgoIdSz;

        /* build up signed attributes, include contentType, signingTime, and
           messageDigest by default */
        ret = wc_PKCS7_BuildSignedAttributes(pkcs7, esd, pkcs7->contentType,
                                     pkcs7->contentTypeSz,
                                     contentTypeOid, sizeof(contentTypeOid),
                                     messageDigestOid, sizeof(messageDigestOid),
                                     signingTimeOid, sizeof(signingTimeOid),
                                     signingTime, sizeof(signingTime));
        if (ret < 0) {
            idx = ret;
            goto out;
        }

        if (esd->signedAttribsSz > 0) {
            flatSignedAttribs = (byte*)XMALLOC(esd->signedAttribsSz, pkcs7->heap,
                                                             DYNAMIC_TYPE_PKCS7);
            if (flatSignedAttribs == NULL) {
                idx = MEMORY_E;
                goto out;
            }

            flatSignedAttribsSz = esd->signedAttribsSz;

            FlattenAttributes(pkcs7, flatSignedAttribs, esd->signedAttribs,
                                                  (int)esd->signedAttribsCount);
            esd->signedAttribSetSz = SetImplicit(ASN_SET, 0, esd->signedAttribsSz,
                                                              esd->signedAttribSet, 0);
        } else {
            esd->signedAttribSetSz = 0;
        }

        if (pkcs7->publicKeyOID != ECDSAk && hashBuf == NULL) {
            ret = wc_PKCS7_GetSignSize(pkcs7);
            esd->encContentDigestSz = (word32)ret;
        }
        else {
            ret = wc_PKCS7_SignedDataBuildSignature(pkcs7, flatSignedAttribs,
                                            flatSignedAttribsSz, esd);
        }
        if (ret < 0) {
            idx = ret;
            goto out;
        }

        signerInfoSz += flatSignedAttribsSz + esd->signedAttribSetSz;

        esd->signerDigestSz = SetOctetString(esd->encContentDigestSz,
                                                                 esd->signerDigest);
        signerInfoSz += esd->signerDigestSz + esd->encContentDigestSz;

        esd->signerInfoSeqSz = SetSequence(signerInfoSz, esd->signerInfoSeq);
        signerInfoSz += esd->signerInfoSeqSz;
    }
    esd->signerInfoSetSz = SetSet(signerInfoSz, esd->signerInfoSet);
    signerInfoSz += esd->signerInfoSetSz;

    /* certificates [0] IMPLICIT CertificateSet */
    /* get total certificates size */
    if (pkcs7->noCerts != 1) {
        certPtr = pkcs7->certList;
        while (certPtr != NULL) {
            certSetSz += certPtr->derSz;
            certPtr = certPtr->next;
        }
    }
    certPtr = NULL;

    if (certSetSz > 0)
        esd->certsSetSz = SetImplicit(ASN_SET, 0, certSetSz, esd->certsSet, 0);

    if (pkcs7->sidType != DEGENERATE_SID) {
        esd->singleDigAlgoIdSz = SetAlgoIDEx(pkcs7->hashOID, esd->singleDigAlgoId,
                                      oidHashType, 0, pkcs7->hashParamsAbsent);
    }
    esd->digAlgoIdSetSz = SetSet(esd->singleDigAlgoIdSz, esd->digAlgoIdSet);

    if (pkcs7->version == 3) {
        /* RFC 4108 version MUST be 3 for firmware package signer */
        esd->versionSz = (word32)SetMyVersion(3, esd->version, 0);
    }
    else {
        esd->versionSz = (word32)SetMyVersion(1, esd->version, 0);
    }

    totalSz = esd->versionSz + esd->singleDigAlgoIdSz + esd->digAlgoIdSetSz +
              esd->contentInfoSeqSz + pkcs7->contentTypeSz +
              esd->innerContSeqSz + esd->innerOctetsSz;

#ifdef ASN_BER_TO_DER
    if (pkcs7->encodeStream) {
        word32 tmpIdx = 0;
        totalSz += (3 * ASN_INDEF_END_SZ) ; /* 00's for BER with inner content */

        StreamOctetString(pkcs7->content, pkcs7->contentSz, NULL, &streamSz,
            &tmpIdx);
        totalSz += streamSz + (3 * ASN_INDEF_END_SZ);
    }
    else
#endif
    {
        totalSz += pkcs7->contentSz;
    }
    total2Sz = esd->certsSetSz + certSetSz + signerInfoSz;

    if (pkcs7->detached) {
        totalSz -= pkcs7->contentSz;
    }

    esd->innerSeqSz = SetSequenceEx(totalSz + total2Sz, esd->innerSeq,
        pkcs7->encodeStream);
    totalSz += esd->innerSeqSz;
    if (pkcs7->encodeStream) {
        totalSz += ASN_INDEF_END_SZ;
    }

    esd->outerContentSz = SetExplicit(0, totalSz + total2Sz,
        esd->outerContent, pkcs7->encodeStream);
    totalSz += esd->outerContentSz + signedDataOidSz;
    if (pkcs7->encodeStream) {
        totalSz += ASN_INDEF_END_SZ;
    }

    esd->outerSeqSz = SetSequenceEx(totalSz + total2Sz, esd->outerSeq,
        pkcs7->encodeStream);
    totalSz += esd->outerSeqSz;
    if (pkcs7->encodeStream) {
        totalSz += ASN_INDEF_END_SZ;
    }

    /* if using header/footer, we are not returning the content */
    if (output2 && output2Sz) {
        if (total2Sz > *output2Sz) {
            if (*outputSz == 0 && *output2Sz == 0) {
                *outputSz = totalSz;
                *output2Sz = total2Sz;
                idx = 0;
                goto out;
            }
            idx = BUFFER_E;
            goto out;
        }

        if (!pkcs7->detached) {
            totalSz -= pkcs7->contentSz;
        }
    }
    else {
        /* if using single output buffer include content and footer */
        totalSz += total2Sz;
    }

    if (totalSz > *outputSz
    #ifdef ASN_BER_TO_DER
        && pkcs7->streamOutCb == NULL
    #endif
    ) {
        if (*outputSz == 0) {
        #ifdef HAVE_ECC
            if (pkcs7->publicKeyOID == ECDSAk) {
                totalSz += ECC_MAX_PAD_SZ; /* signatures size can vary */
            }
        #endif
            *outputSz = totalSz;
            idx = (int)totalSz;
            goto out;
        }
        idx = BUFFER_E;
        goto out;
    }

#ifdef ASN_BER_TO_DER
    if (output == NULL && pkcs7->streamOutCb == NULL) {
#else
    if (output == NULL) {
#endif
        idx = BUFFER_E;
        goto out;
    }

    idx = 0;
    wc_PKCS7_WriteOut(pkcs7, (output)? (output + idx) : NULL,
            esd->outerSeq, esd->outerSeqSz);
    idx += (int)esd->outerSeqSz;
    wc_PKCS7_WriteOut(pkcs7, (output)? (output + idx) : NULL,
            signedDataOid, signedDataOidSz);
    idx += (int)signedDataOidSz;
    wc_PKCS7_WriteOut(pkcs7, (output)? (output + idx) : NULL,
            esd->outerContent, esd->outerContentSz);
    idx += (int)esd->outerContentSz;
    wc_PKCS7_WriteOut(pkcs7, (output)? (output + idx) : NULL,
            esd->innerSeq, esd->innerSeqSz);
    idx += (int)esd->innerSeqSz;
    wc_PKCS7_WriteOut(pkcs7, (output)? (output + idx) : NULL,
            esd->version, esd->versionSz);
    idx += (int)esd->versionSz;
    wc_PKCS7_WriteOut(pkcs7, (output)? (output + idx) : NULL,
            esd->digAlgoIdSet, esd->digAlgoIdSetSz);
    idx += (int)esd->digAlgoIdSetSz;
    wc_PKCS7_WriteOut(pkcs7, (output)? (output + idx) : NULL,
            esd->singleDigAlgoId, esd->singleDigAlgoIdSz);
    idx += (int)esd->singleDigAlgoIdSz;
    wc_PKCS7_WriteOut(pkcs7, (output)? (output + idx) : NULL,
            esd->contentInfoSeq, esd->contentInfoSeqSz);
    idx += (int)esd->contentInfoSeqSz;
    wc_PKCS7_WriteOut(pkcs7, (output)? (output + idx) : NULL,
            pkcs7->contentType, pkcs7->contentTypeSz);
    idx += (int)pkcs7->contentTypeSz;
    wc_PKCS7_WriteOut(pkcs7, (output)? (output + idx) : NULL,
            esd->innerContSeq, esd->innerContSeqSz);
    idx += (int)esd->innerContSeqSz;
    wc_PKCS7_WriteOut(pkcs7, (output)? (output + idx) : NULL,
            esd->innerOctets, esd->innerOctetsSz);
    idx += (int)esd->innerOctetsSz;

    /* support returning header and footer without content */
    if (output2 && output2Sz) {
        *outputSz = (word32)idx;
        idx = 0;
    }
    else {
        if (
        #ifdef ASN_BER_TO_DER
            (pkcs7->content != NULL || pkcs7->getContentCb != NULL)
        #else
            pkcs7->content != NULL
        #endif
             && pkcs7->contentSz > 0) {
            wc_PKCS7_EncodeContentStream(pkcs7, esd, NULL, pkcs7->content,
                (int)pkcs7->contentSz, (output)? output + idx : NULL,
                WC_CIPHER_NONE);
            if (!pkcs7->detached) {
            #ifdef ASN_BER_TO_DER
                if (pkcs7->encodeStream) {
                    byte indefEnd[ASN_INDEF_END_SZ * 3];
                    word32 localIdx = 0;

                    idx += (int)streamSz;

                    /* end of content octet string */
                    localIdx += SetIndefEnd(indefEnd + localIdx);

                    /* end of inner content seq */
                    localIdx += SetIndefEnd(indefEnd + localIdx);

                    /* end of inner content info seq */
                    localIdx += SetIndefEnd(indefEnd + localIdx);

                    wc_PKCS7_WriteOut(pkcs7, (output)? (output + idx) : NULL,
                        indefEnd, localIdx);
                    idx += (int)localIdx;
                }
                else
            #endif
                {
                        idx += (int)pkcs7->contentSz;
                }
            }
        }
        output2 = output;
    }

    /* certificates */
    wc_PKCS7_WriteOut(pkcs7, (output2)? (output2 + idx) : NULL,
        esd->certsSet, esd->certsSetSz);
    idx += (int)esd->certsSetSz;

    if (pkcs7->noCerts != 1) {
        certPtr = pkcs7->certList;
        while (certPtr != NULL) {
            wc_PKCS7_WriteOut(pkcs7, (output2)? (output2 + idx) : NULL,
                certPtr->der, certPtr->derSz);
            idx += (int)certPtr->derSz;
            certPtr = certPtr->next;
        }
    }

    wc_PKCS7_FreeCertSet(pkcs7);

    wc_PKCS7_WriteOut(pkcs7, (output2)? (output2 + idx) : NULL,
                esd->signerInfoSet, esd->signerInfoSetSz);
    idx += (int)esd->signerInfoSetSz;
    wc_PKCS7_WriteOut(pkcs7, (output2)? (output2 + idx) : NULL,
                esd->signerInfoSeq, esd->signerInfoSeqSz);
    idx += (int)esd->signerInfoSeqSz;
    wc_PKCS7_WriteOut(pkcs7, (output2)? (output2 + idx) : NULL,
                esd->signerVersion, esd->signerVersionSz);
    idx += (int)esd->signerVersionSz;
    /* SignerIdentifier */
    if (pkcs7->sidType == CMS_ISSUER_AND_SERIAL_NUMBER) {
        /* IssuerAndSerialNumber */
        wc_PKCS7_WriteOut(pkcs7, (output2)? (output2 + idx) : NULL,
                esd->issuerSnSeq, esd->issuerSnSeqSz);
        idx += (int)esd->issuerSnSeqSz;
        wc_PKCS7_WriteOut(pkcs7, (output2)? (output2 + idx) : NULL,
                esd->issuerName, esd->issuerNameSz);
        idx += (int)esd->issuerNameSz;
        wc_PKCS7_WriteOut(pkcs7, (output2)? (output2 + idx) : NULL,
                pkcs7->issuer, pkcs7->issuerSz);
        idx += (int)pkcs7->issuerSz;
        wc_PKCS7_WriteOut(pkcs7, (output2)? (output2 + idx) : NULL,
                esd->issuerSn, esd->issuerSnSz);
        idx += (int)esd->issuerSnSz;
    } else if (pkcs7->sidType == CMS_SKID) {
        /* SubjectKeyIdentifier */
        wc_PKCS7_WriteOut(pkcs7, (output2)? (output2 + idx) : NULL,
                esd->issuerSKIDSeq, esd->issuerSKIDSeqSz);
        idx += (int)esd->issuerSKIDSeqSz;
        wc_PKCS7_WriteOut(pkcs7, (output2)? (output2 + idx) : NULL,
                esd->issuerSKID, esd->issuerSKIDSz);
        idx += (int)esd->issuerSKIDSz;

        if (pkcs7->customSKID) {
            wc_PKCS7_WriteOut(pkcs7, (output2)? (output2 + idx) : NULL,
                pkcs7->customSKID, (word32)keyIdSize);
        }
        else {
            wc_PKCS7_WriteOut(pkcs7, (output2)? (output2 + idx) : NULL,
                pkcs7->issuerSubjKeyId, (word32)keyIdSize);
        }
        idx += keyIdSize;
    } else if (pkcs7->sidType == DEGENERATE_SID) {
        /* no signer infos in degenerate case */
    } else {
        idx = SKID_E;
        goto out;
    }
    wc_PKCS7_WriteOut(pkcs7, (output2)? (output2 + idx) : NULL,
                esd->signerDigAlgoId, esd->signerDigAlgoIdSz);
    idx += (int)esd->signerDigAlgoIdSz;

    /* SignerInfo:Attributes */
    if (flatSignedAttribsSz > 0) {
        /* if the original hash buffer passed in was null then recreate the
        * signature */
        if (hashBuf == NULL && pkcs7->sidType != DEGENERATE_SID) {
            /* recreate flat attribs after the content hash is known if needed
             * build up signed attributes, include contentType, signingTime, and
               messageDigest by default */
            esd->signedAttribsCount = 0;
            esd->signedAttribsSz = 0;
            ret = wc_PKCS7_BuildSignedAttributes(pkcs7, esd, pkcs7->contentType,
                                     pkcs7->contentTypeSz,
                                     contentTypeOid, sizeof(contentTypeOid),
                                     messageDigestOid, sizeof(messageDigestOid),
                                     signingTimeOid, sizeof(signingTimeOid),
                                     signingTime, sizeof(signingTime));
            if (ret < 0) {
                idx = ret;
                goto out;
            }

            if (esd->signedAttribsSz > 0) {
                if (flatSignedAttribs == NULL) {
                    idx = MEMORY_E;
                    goto out;
                }

                flatSignedAttribsSz = esd->signedAttribsSz;
                FlattenAttributes(pkcs7, flatSignedAttribs,
                                  esd->signedAttribs,
                                  (int)esd->signedAttribsCount);
            } else {
                esd->signedAttribSetSz = 0;
            }
        }

        wc_PKCS7_WriteOut(pkcs7, (output2)? (output2 + idx) : NULL,
                esd->signedAttribSet, esd->signedAttribSetSz);
        idx += (int)esd->signedAttribSetSz;
        wc_PKCS7_WriteOut(pkcs7, (output2)? (output2 + idx) : NULL,
                flatSignedAttribs, flatSignedAttribsSz);
        idx += (int)flatSignedAttribsSz;
    }

    if (hashBuf == NULL && pkcs7->sidType != DEGENERATE_SID) {
        /* Calculate the final hash and encrypt it. */
        WOLFSSL_MSG("Recreating signature with new hash");
        ret = wc_PKCS7_SignedDataBuildSignature(pkcs7, flatSignedAttribs,
                                                flatSignedAttribsSz, esd);
        if (ret < 0) {
            idx = ret;
            goto out;
        }
    }

    wc_PKCS7_WriteOut(pkcs7, (output2)? (output2 + idx) : NULL,
                esd->digEncAlgoId, esd->digEncAlgoIdSz);
    idx += (int)esd->digEncAlgoIdSz;
    wc_PKCS7_WriteOut(pkcs7, (output2)? (output2 + idx) : NULL,
                esd->signerDigest, esd->signerDigestSz);
    idx += (int)esd->signerDigestSz;

    wc_PKCS7_WriteOut(pkcs7, (output2)? (output2 + idx) : NULL,
                esd->encContentDigest, esd->encContentDigestSz);
    idx += (int)esd->encContentDigestSz;

#ifdef ASN_BER_TO_DER
    if (pkcs7->encodeStream) {
        byte indefEnd[ASN_INDEF_END_SZ * 3];
        word32 localIdx = 0;

        /* end of signedData seq */
        localIdx += SetIndefEnd(indefEnd + localIdx);

        /* end of outer content set */
        localIdx += SetIndefEnd(indefEnd + localIdx);

        /* end of outer content info seq */
        localIdx += SetIndefEnd(indefEnd + localIdx);

        wc_PKCS7_WriteOut(pkcs7, (output2)? (output2 + idx) : NULL,
                    indefEnd, localIdx);
        idx += (int)localIdx;
    }
#endif

    if (output2Sz) {
        *output2Sz = (word32)idx;
        idx = 0; /* success */
    }
    else {
        *outputSz = (word32)idx;
    }

  out:

    XFREE(flatSignedAttribs, pkcs7->heap, DYNAMIC_TYPE_PKCS7);

#ifdef WOLFSSL_SMALL_STACK
    XFREE(esd, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(signedDataOid, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return idx;
}

/* hashBuf: The computed digest for the pkcs7->content
 * hashSz: The size of computed digest for the pkcs7->content based on hashOID
 * outputHead: The PKCS7 header that goes on top of the raw data signed.
 * outputFoot: The PKCS7 footer that goes at the end of the raw data signed.
 * pkcs7->content: Not used
 * pkcs7->contentSz: Must be provided as actual sign of raw data
 * return codes: 0=success, negative=error
 */
int wc_PKCS7_EncodeSignedData_ex(wc_PKCS7* pkcs7, const byte* hashBuf,
    word32 hashSz, byte* outputHead, word32* outputHeadSz, byte* outputFoot,
    word32* outputFootSz)
{
    int ret;

    /* other args checked in wc_PKCS7_EncodeSigned_ex */
    if (pkcs7 == NULL) {
        return BAD_FUNC_ARG;
    }

#ifndef ASN_BER_TO_DER
    if (outputFoot == NULL || outputFootSz == NULL)
#else
    if (pkcs7->getContentCb == NULL &&
        (outputFoot == NULL || outputFootSz == NULL))
#endif
    {
        return BAD_FUNC_ARG;
    }

    ret = PKCS7_EncodeSigned(pkcs7, hashBuf, hashSz,
        outputHead, outputHeadSz, outputFoot, outputFootSz);

    return ret;
}


/* Sets a custom SKID in PKCS7 struct, used before calling an encode operation
 * Returns 0 on success, negative upon error. */
int wc_PKCS7_SetCustomSKID(wc_PKCS7* pkcs7, const byte* in, word16 inSz)
{
    int ret = 0;

    if (pkcs7 == NULL || (in == NULL && inSz > 0)) {
        return BAD_FUNC_ARG;
    }

    if (in == NULL) {
        if (pkcs7->customSKID != NULL) {
            XFREE(pkcs7->customSKID, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        }
        pkcs7->customSKIDSz = 0;
        pkcs7->customSKID   = NULL;
    }
    else {
        pkcs7->customSKID = (byte*)XMALLOC(inSz, pkcs7->heap,
            DYNAMIC_TYPE_PKCS7);
        if (pkcs7->customSKID == NULL) {
            ret = MEMORY_E;
        }
        else {
            XMEMCPY(pkcs7->customSKID, in, inSz);
            pkcs7->customSKIDSz = inSz;
        }
    }

    return ret;
}


/* Toggle detached signature mode on/off for PKCS#7/CMS SignedData content type.
 * By default wolfCrypt includes the data to be signed in the SignedData
 * bundle. This data can be omitted in the case when a detached signature is
 * being created. To enable generation of detached signatures, set flag to "1",
 * otherwise set to "0":
 *
 *     flag 1 turns on support
 *     flag 0 turns off support
 *
 * pkcs7 - pointer to initialized PKCS7 structure
 * flag  - turn on/off detached signature generation (1 or 0)
 *
 * Returns 0 on success, negative upon error. */
int wc_PKCS7_SetDetached(wc_PKCS7* pkcs7, word16 flag)
{
    if (pkcs7 == NULL || (flag != 0 && flag != 1))
        return BAD_FUNC_ARG;

    pkcs7->detached = (flag != 0);

    return 0;
}

/* By default, SignedData bundles have the following signed attributes attached:
 *     contentType (1.2.840.113549.1.9.3)
 *     signingTime (1.2.840.113549.1.9.5)
 *     messageDigest (1.2.840.113549.1.9.4)
 *
 * Calling this API before wc_PKCS7_EncodeSignedData() will disable the
 * inclusion of those attributes.
 *
 * pkcs7 - pointer to initialized PKCS7 structure
 *
 * Returns 0 on success, negative upon error. */
int wc_PKCS7_NoDefaultSignedAttribs(wc_PKCS7* pkcs7)
{
    return wc_PKCS7_SetDefaultSignedAttribs(pkcs7, WOLFSSL_NO_ATTRIBUTES);
}


/* By default, SignedData bundles have the following signed attributes attached:
 *     contentType (1.2.840.113549.1.9.3)
 *     signingTime (1.2.840.113549.1.9.5)
 *     messageDigest (1.2.840.113549.1.9.4)
 *
 * Calling this API before wc_PKCS7_EncodeSignedData() allows control over which
 * default attributes are added.
 *
 * pkcs7 - pointer to initialized PKCS7 structure
 *
 * Returns 0 on success, negative upon error. */
int  wc_PKCS7_SetDefaultSignedAttribs(wc_PKCS7* pkcs7, word16 flag)
{
    if (pkcs7 == NULL) {
        return BAD_FUNC_ARG;
    }

    if (flag & WOLFSSL_NO_ATTRIBUTES) {
        if (flag ^ WOLFSSL_NO_ATTRIBUTES) {
            WOLFSSL_MSG("Error, can not have additional flags with no "
                "attributes flag set");
            return BAD_FUNC_ARG;
        }
        pkcs7->defaultSignedAttribs = 0;
    }

    /* check for unknown flags */
    if (flag & ~(WOLFSSL_CONTENT_TYPE_ATTRIBUTE |
                WOLFSSL_SIGNING_TIME_ATTRIBUTE |
                WOLFSSL_MESSAGE_DIGEST_ATTRIBUTE | WOLFSSL_NO_ATTRIBUTES)) {
        WOLFSSL_MSG("Unknown attribute flags found");
        return BAD_FUNC_ARG;
    }

    pkcs7->defaultSignedAttribs |= flag;
    return 0;
}


/* return codes: >0: Size of signed PKCS7 output buffer, negative: error */
int wc_PKCS7_EncodeSignedData(wc_PKCS7* pkcs7, byte* output, word32 outputSz)
{
    int ret;

    /* other args checked in wc_PKCS7_EncodeSigned_ex */
    if (pkcs7 == NULL || (pkcs7->contentSz > 0 &&
    #ifdef ASN_BER_TO_DER
        (pkcs7->content == NULL && pkcs7->getContentCb == NULL))
    #else
        pkcs7->content == NULL)
    #endif
    ) {
        return BAD_FUNC_ARG;
    }

    /* pre-calculate hash for ECC signatures */
    if (pkcs7->publicKeyOID == ECDSAk) {
        int hashSz;
        enum wc_HashType hashType;
        byte hashBuf[WC_MAX_DIGEST_SIZE];
        wc_HashAlg hash;

        /* get hash type and size, validate hashOID */
        hashType = wc_OidGetHash(pkcs7->hashOID);
        hashSz = wc_HashGetDigestSize(hashType);
        if (hashSz < 0)
            return hashSz;

        /* calculate hash for content */
        ret = wc_HashInit(&hash, hashType);
        if (ret == 0) {
            ret = wc_HashUpdate(&hash, hashType,
                            pkcs7->content, pkcs7->contentSz);
            if (ret == 0) {
                ret = wc_HashFinal(&hash, hashType, hashBuf);
            }
            wc_HashFree(&hash, hashType);
        }
        if (ret == 0) {
            ret = PKCS7_EncodeSigned(pkcs7, hashBuf, (word32)hashSz,
                output, &outputSz, NULL, NULL);
        }
    }
    else {
        ret = PKCS7_EncodeSigned(pkcs7, NULL, 0, output, &outputSz,
            NULL, NULL);
    }
    return ret;
}


/* Single-shot API to generate a CMS SignedData bundle that encapsulates a
 * content of type FirmwarePkgData. Any recipient certificates should be
 * loaded into the PKCS7 structure prior to calling this function, using
 * wc_PKCS7_InitWithCert() and/or wc_PKCS7_AddCertificate().
 *
 * pkcs7                - pointer to initialized PKCS7 struct
 * privateKey           - private RSA/ECC key, used for signing SignedData
 * privateKeySz         - size of privateKey, octets
 * signOID              - public key algorithm OID, used for sign operation
 * hashOID              - hash algorithm OID, used for signature generation
 * content              - content to be encapsulated, of type FirmwarePkgData
 * contentSz            - size of content, octets
 * signedAttribs        - optional signed attributes
 * signedAttribsSz      - number of PKCS7Attrib members in signedAttribs
 * output               - output buffer for final bundle
 * outputSz             - size of output buffer, octets
 *
 * Returns length of generated bundle on success, negative upon error. */
int wc_PKCS7_EncodeSignedFPD(wc_PKCS7* pkcs7, byte* privateKey,
                             word32 privateKeySz, int signOID, int hashOID,
                             byte* content, word32 contentSz,
                             PKCS7Attrib* signedAttribs, word32 signedAttribsSz,
                             byte* output, word32 outputSz)
{
    int ret = 0;
    WC_RNG rng;

    if (pkcs7 == NULL || privateKey == NULL || privateKeySz == 0 ||
        content == NULL || contentSz == 0 || output == NULL || outputSz == 0)
        return BAD_FUNC_ARG;

    ret = wc_InitRng_ex(&rng, pkcs7->heap, pkcs7->devId);
    if (ret != 0)
        return ret;

    pkcs7->rng = &rng;
    pkcs7->content = content;
    pkcs7->contentSz = contentSz;
    pkcs7->contentOID = FIRMWARE_PKG_DATA;
    pkcs7->hashOID = hashOID;
    pkcs7->encryptOID = signOID;
    pkcs7->privateKey = privateKey;
    pkcs7->privateKeySz = privateKeySz;
    pkcs7->signedAttribs = signedAttribs;
    pkcs7->signedAttribsSz = signedAttribsSz;
    pkcs7->version = 3;

    ret = wc_PKCS7_EncodeSignedData(pkcs7, output, outputSz);
    if (ret <= 0) {
        WOLFSSL_MSG("Error encoding CMS SignedData content type");
    }

    pkcs7->rng = NULL;
    wc_FreeRng(&rng);

    return ret;
}

#ifndef NO_PKCS7_ENCRYPTED_DATA

/* Single-shot API to generate a CMS SignedData bundle that encapsulates a
 * CMS EncryptedData bundle. Content of inner EncryptedData is set to that
 * of FirmwarePkgData. Any recipient certificates should be loaded into the
 * PKCS7 structure prior to calling this function, using wc_PKCS7_InitWithCert()
 * and/or wc_PKCS7_AddCertificate().
 *
 * pkcs7                - pointer to initialized PKCS7 struct
 * encryptKey           - encryption key used for encrypting EncryptedData
 * encryptKeySz         - size of encryptKey, octets
 * privateKey           - private RSA/ECC key, used for signing SignedData
 * privateKeySz         - size of privateKey, octets
 * encryptOID           - encryption algorithm OID, to be used as encryption
 *                        algorithm for EncryptedData
 * signOID              - public key algorithm OID, to be used for sign
 *                        operation in SignedData generation
 * hashOID              - hash algorithm OID, to be used for signature in
 *                        SignedData generation
 * content              - content to be encapsulated
 * contentSz            - size of content, octets
 * unprotectedAttribs   - optional unprotected attributes, for EncryptedData
 * unprotectedAttribsSz - number of PKCS7Attrib members in unprotectedAttribs
 * signedAttribs        - optional signed attributes, for SignedData
 * signedAttribsSz      - number of PKCS7Attrib members in signedAttribs
 * output               - output buffer for final bundle
 * outputSz             - size of output buffer, octets
 *
 * Returns length of generated bundle on success, negative upon error. */
int wc_PKCS7_EncodeSignedEncryptedFPD(wc_PKCS7* pkcs7, byte* encryptKey,
                                      word32 encryptKeySz, byte* privateKey,
                                      word32 privateKeySz, int encryptOID,
                                      int signOID, int hashOID,
                                      byte* content, word32 contentSz,
                                      PKCS7Attrib* unprotectedAttribs,
                                      word32 unprotectedAttribsSz,
                                      PKCS7Attrib* signedAttribs,
                                      word32 signedAttribsSz,
                                      byte* output, word32 outputSz)
{
    int ret = 0, encryptedSz = 0;
    byte* encrypted = NULL;
    WC_RNG rng;

    if (pkcs7 == NULL || encryptKey == NULL || encryptKeySz == 0 ||
        privateKey == NULL || privateKeySz == 0 || content == NULL ||
        contentSz == 0 || output == NULL || outputSz == 0) {
        return BAD_FUNC_ARG;
    }

    /* 1: build up EncryptedData using FirmwarePkgData type, use output
     *    buffer as tmp for storage and to get size */

    /* set struct elements, inner content type is FirmwarePkgData */
    pkcs7->content = content;
    pkcs7->contentSz = contentSz;
    pkcs7->contentOID = FIRMWARE_PKG_DATA;
    pkcs7->encryptOID = encryptOID;
    pkcs7->encryptionKey = encryptKey;
    pkcs7->encryptionKeySz = encryptKeySz;
    pkcs7->unprotectedAttribs = unprotectedAttribs;
    pkcs7->unprotectedAttribsSz = unprotectedAttribsSz;
    pkcs7->version = 3;

    encryptedSz = wc_PKCS7_EncodeEncryptedData(pkcs7, output, outputSz);
    if (encryptedSz < 0) {
        WOLFSSL_MSG("Error encoding CMS EncryptedData content type");
        return encryptedSz;
    }

    /* save encryptedData, reset output buffer and struct */
    encrypted = (byte*)XMALLOC((word32)encryptedSz, pkcs7->heap,
                               DYNAMIC_TYPE_PKCS7);
    if (encrypted == NULL) {
        ForceZero(output, outputSz);
        return MEMORY_E;
    }

    XMEMCPY(encrypted, output, (word32)encryptedSz);
    ForceZero(output, outputSz);

    ret = wc_InitRng_ex(&rng, pkcs7->heap, pkcs7->devId);
    if (ret != 0) {
        ForceZero(encrypted, (word32)encryptedSz);
        XFREE(encrypted, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return ret;
    }

    /* 2: build up SignedData, encapsulating EncryptedData */
    pkcs7->rng = &rng;
    pkcs7->content = encrypted;
    pkcs7->contentSz = (word32)encryptedSz;
    pkcs7->contentOID = ENCRYPTED_DATA;
    pkcs7->hashOID = hashOID;
    pkcs7->encryptOID = signOID;
    pkcs7->privateKey = privateKey;
    pkcs7->privateKeySz = privateKeySz;
    pkcs7->signedAttribs = signedAttribs;
    pkcs7->signedAttribsSz = signedAttribsSz;

    ret = wc_PKCS7_EncodeSignedData(pkcs7, output, outputSz);
    if (ret <= 0) {
        WOLFSSL_MSG("Error encoding CMS SignedData content type");
    }

    ForceZero(encrypted, (word32)encryptedSz);
    XFREE(encrypted, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
    pkcs7->rng = NULL;
    wc_FreeRng(&rng);

    return ret;
}

#endif /* NO_PKCS7_ENCRYPTED_DATA */

#if defined(HAVE_LIBZ) && !defined(NO_PKCS7_COMPRESSED_DATA)
/* Single-shot API to generate a CMS SignedData bundle that encapsulates a
 * CMS CompressedData bundle. Content of inner CompressedData is set to that
 * of FirmwarePkgData. Any recipient certificates should be loaded into the
 * PKCS7 structure prior to calling this function, using wc_PKCS7_InitWithCert()
 * and/or wc_PKCS7_AddCertificate().
 *
 * pkcs7                - pointer to initialized PKCS7 struct
 * privateKey           - private RSA/ECC key, used for signing SignedData
 * privateKeySz         - size of privateKey, octets
 * signOID              - public key algorithm OID, to be used for sign
 *                        operation in SignedData generation
 * hashOID              - hash algorithm OID, to be used for signature in
 *                        SignedData generation
 * content              - content to be encapsulated
 * contentSz            - size of content, octets
 * signedAttribs        - optional signed attributes, for SignedData
 * signedAttribsSz      - number of PKCS7Attrib members in signedAttribs
 * output               - output buffer for final bundle
 * outputSz             - size of output buffer, octets
 *
 * Returns length of generated bundle on success, negative upon error. */
int wc_PKCS7_EncodeSignedCompressedFPD(wc_PKCS7* pkcs7, byte* privateKey,
                                       word32 privateKeySz, int signOID,
                                       int hashOID, byte* content,
                                       word32 contentSz,
                                       PKCS7Attrib* signedAttribs,
                                       word32 signedAttribsSz, byte* output,
                                       word32 outputSz)
{
    int ret = 0, compressedSz = 0;
    byte* compressed = NULL;
    WC_RNG rng;

    if (pkcs7 == NULL || privateKey == NULL || privateKeySz == 0 ||
        content == NULL || contentSz == 0 || output == NULL || outputSz == 0) {
        return BAD_FUNC_ARG;
    }

    /* 1: build up CompressedData using FirmwarePkgData type, use output
     *    buffer as tmp for storage and to get size */

    /* set struct elements, inner content type is FirmwarePkgData */
    pkcs7->content = content;
    pkcs7->contentSz = contentSz;
    pkcs7->contentOID = FIRMWARE_PKG_DATA;
    pkcs7->version = 3;

    compressedSz = wc_PKCS7_EncodeCompressedData(pkcs7, output, outputSz);
    if (compressedSz < 0) {
        WOLFSSL_MSG("Error encoding CMS CompressedData content type");
        return compressedSz;
    }

    /* save compressedData, reset output buffer and struct */
    compressed = (byte*)XMALLOC(compressedSz, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
    if (compressed == NULL) {
        ForceZero(output, outputSz);
        return MEMORY_E;
    }

    XMEMCPY(compressed, output, compressedSz);
    ForceZero(output, outputSz);

    ret = wc_InitRng_ex(&rng, pkcs7->heap, pkcs7->devId);
    if (ret != 0) {
        ForceZero(compressed, compressedSz);
        XFREE(compressed, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return ret;
    }

    /* 2: build up SignedData, encapsulating EncryptedData */
    pkcs7->rng = &rng;
    pkcs7->content = compressed;
    pkcs7->contentSz = compressedSz;
    pkcs7->contentOID = COMPRESSED_DATA;
    pkcs7->hashOID = hashOID;
    pkcs7->encryptOID = signOID;
    pkcs7->privateKey = privateKey;
    pkcs7->privateKeySz = privateKeySz;
    pkcs7->signedAttribs = signedAttribs;
    pkcs7->signedAttribsSz = signedAttribsSz;

    ret = wc_PKCS7_EncodeSignedData(pkcs7, output, outputSz);
    if (ret <= 0) {
        WOLFSSL_MSG("Error encoding CMS SignedData content type");
    }

    ForceZero(compressed, compressedSz);
    XFREE(compressed, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
    pkcs7->rng = NULL;
    wc_FreeRng(&rng);

    return ret;
}

#ifndef NO_PKCS7_ENCRYPTED_DATA

/* Single-shot API to generate a CMS SignedData bundle that encapsulates a
 * CMS EncryptedData bundle, which then encapsulates a CMS CompressedData
 * bundle. Content of inner CompressedData is set to that of FirmwarePkgData.
 * Any recipient certificates should be loaded into the PKCS7 structure prior
 * to calling this function, using wc_PKCS7_InitWithCert() and/or
 * wc_PKCS7_AddCertificate().
 *
 * pkcs7                - pointer to initialized PKCS7 struct
 * encryptKey           - encryption key used for encrypting EncryptedData
 * encryptKeySz         - size of encryptKey, octets
 * privateKey           - private RSA/ECC key, used for signing SignedData
 * privateKeySz         - size of privateKey, octets
 * encryptOID           - encryption algorithm OID, to be used as encryption
 *                        algorithm for EncryptedData
 * signOID              - public key algorithm OID, to be used for sign
 *                        operation in SignedData generation
 * hashOID              - hash algorithm OID, to be used for signature in
 *                        SignedData generation
 * content              - content to be encapsulated
 * contentSz            - size of content, octets
 * unprotectedAttribs   - optional unprotected attributes, for EncryptedData
 * unprotectedAttribsSz - number of PKCS7Attrib members in unprotectedAttribs
 * signedAttribs        - optional signed attributes, for SignedData
 * signedAttribsSz      - number of PKCS7Attrib members in signedAttribs
 * output               - output buffer for final bundle
 * outputSz             - size of output buffer, octets
 *
 * Returns length of generated bundle on success, negative upon error. */
int  wc_PKCS7_EncodeSignedEncryptedCompressedFPD(wc_PKCS7* pkcs7, byte* encryptKey,
                                       word32 encryptKeySz, byte* privateKey,
                                       word32 privateKeySz, int encryptOID,
                                       int signOID, int hashOID, byte* content,
                                       word32 contentSz,
                                       PKCS7Attrib* unprotectedAttribs,
                                       word32 unprotectedAttribsSz,
                                       PKCS7Attrib* signedAttribs,
                                       word32 signedAttribsSz,
                                       byte* output, word32 outputSz)
{
    int ret = 0, compressedSz = 0, encryptedSz = 0;
    byte* compressed = NULL;
    byte* encrypted = NULL;
    WC_RNG rng;

    if (pkcs7 == NULL || encryptKey == NULL || encryptKeySz == 0 ||
        privateKey == NULL || privateKeySz == 0 || content == NULL ||
        contentSz == 0 || output == NULL || outputSz == 0) {
        return BAD_FUNC_ARG;
    }

    /* 1: build up CompressedData using FirmwarePkgData type, use output
     *    buffer as tmp for storage and to get size */
    pkcs7->content = content;
    pkcs7->contentSz = contentSz;
    pkcs7->contentOID = FIRMWARE_PKG_DATA;
    pkcs7->version = 3;

    compressedSz = wc_PKCS7_EncodeCompressedData(pkcs7, output, outputSz);
    if (compressedSz < 0) {
        WOLFSSL_MSG("Error encoding CMS CompressedData content type");
        return compressedSz;
    }

    /* save compressedData, reset output buffer and struct */
    compressed = (byte*)XMALLOC(compressedSz, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
    if (compressed == NULL)
        return MEMORY_E;

    XMEMCPY(compressed, output, compressedSz);
    ForceZero(output, outputSz);

    /* 2: build up EncryptedData using CompressedData, use output
     *    buffer as tmp for storage and to get size */
    pkcs7->content = compressed;
    pkcs7->contentSz = compressedSz;
    pkcs7->contentOID = COMPRESSED_DATA;
    pkcs7->encryptOID = encryptOID;
    pkcs7->encryptionKey = encryptKey;
    pkcs7->encryptionKeySz = encryptKeySz;
    pkcs7->unprotectedAttribs = unprotectedAttribs;
    pkcs7->unprotectedAttribsSz = unprotectedAttribsSz;

    encryptedSz = wc_PKCS7_EncodeEncryptedData(pkcs7, output, outputSz);
    if (encryptedSz < 0) {
        WOLFSSL_MSG("Error encoding CMS EncryptedData content type");
        XFREE(compressed, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return encryptedSz;
    }

    /* save encryptedData, reset output buffer and struct */
    encrypted = (byte*)XMALLOC(encryptedSz, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
    if (encrypted == NULL) {
        ForceZero(compressed, compressedSz);
        XFREE(compressed, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return MEMORY_E;
    }

    XMEMCPY(encrypted, output, encryptedSz);
    ForceZero(compressed, compressedSz);
    XFREE(compressed, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
    ForceZero(output, outputSz);

    ret = wc_InitRng_ex(&rng, pkcs7->heap, pkcs7->devId);
    if (ret != 0) {
        ForceZero(encrypted, encryptedSz);
        XFREE(encrypted, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return ret;
    }

    /* 3: build up SignedData, encapsulating EncryptedData */
    pkcs7->rng = &rng;
    pkcs7->content = encrypted;
    pkcs7->contentSz = encryptedSz;
    pkcs7->contentOID = ENCRYPTED_DATA;
    pkcs7->hashOID = hashOID;
    pkcs7->encryptOID = signOID;
    pkcs7->privateKey = privateKey;
    pkcs7->privateKeySz = privateKeySz;
    pkcs7->signedAttribs = signedAttribs;
    pkcs7->signedAttribsSz = signedAttribsSz;

    ret = wc_PKCS7_EncodeSignedData(pkcs7, output, outputSz);
    if (ret <= 0) {
        WOLFSSL_MSG("Error encoding CMS SignedData content type");
    }

    ForceZero(encrypted, encryptedSz);
    XFREE(encrypted, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
    pkcs7->rng = NULL;
    wc_FreeRng(&rng);

    return ret;
}

#endif /* !NO_PKCS7_ENCRYPTED_DATA */
#endif /* HAVE_LIBZ && !NO_PKCS7_COMPRESSED_DATA */


#ifndef NO_RSA

#ifdef HAVE_PKCS7_RSA_RAW_SIGN_CALLBACK
/* register raw RSA sign digest callback */
int wc_PKCS7_SetRsaSignRawDigestCb(wc_PKCS7* pkcs7, CallbackRsaSignRawDigest cb)
{
    if (pkcs7 == NULL || cb == NULL) {
        return BAD_FUNC_ARG;
    }

    pkcs7->rsaSignRawDigestCb = cb;

    return 0;
}
#endif

/* returns size of signature put into out, negative on error */
static int wc_PKCS7_RsaVerify(wc_PKCS7* pkcs7, byte* sig, int sigSz,
                              byte* hash, word32 hashSz)
{
    int ret = 0, i;
    word32 scratch = 0, verified = 0;
#ifdef WOLFSSL_SMALL_STACK
    byte* digest;
    RsaKey* key;
    DecodedCert* dCert;
#else
#ifdef WOLFSSL_NO_MALLOC
    byte digest[RSA_MAX_SIZE / WOLFSSL_BIT_SIZE]; /* accessed in-place with size
                                                   * key->dataLen
                                                   */
#else
    byte digest[MAX_PKCS7_DIGEST_SZ];
#endif
    RsaKey key[1];
    DecodedCert stack_dCert;
    DecodedCert* dCert = &stack_dCert;
#endif

    if (pkcs7 == NULL || sig == NULL || hash == NULL) {
        return BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_SMALL_STACK
    digest = (byte*)XMALLOC(MAX_PKCS7_DIGEST_SZ, pkcs7->heap,
                            DYNAMIC_TYPE_TMP_BUFFER);
    if (digest == NULL)
        return MEMORY_E;

    key = (RsaKey*)XMALLOC(sizeof(RsaKey), pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (key == NULL) {
        XFREE(digest, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }

    dCert = (DecodedCert*)XMALLOC(sizeof(DecodedCert), pkcs7->heap,
                                  DYNAMIC_TYPE_DCERT);
    if (dCert == NULL) {
        XFREE(digest, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(key, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }
#endif

    XMEMSET(digest, 0, MAX_PKCS7_DIGEST_SZ);

    /* loop over certs received in certificates set, try to find one
     * that will validate signature */
    for (i = 0; i < MAX_PKCS7_CERTS; i++) {

        verified = 0;
        scratch  = 0;

        if (pkcs7->certSz[i] == 0)
            continue;

        ret = wc_InitRsaKey_ex(key, pkcs7->heap, pkcs7->devId);
        if (ret != 0) {
#ifdef WOLFSSL_SMALL_STACK
            XFREE(digest, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(key,    pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(dCert,  pkcs7->heap, DYNAMIC_TYPE_DCERT);
#endif
            return ret;
        }

        InitDecodedCert(dCert, pkcs7->cert[i], pkcs7->certSz[i], pkcs7->heap);
        /* not verifying, only using this to extract public key */
        ret = ParseCert(dCert, CA_TYPE, NO_VERIFY, 0);
        if (ret < 0) {
            WOLFSSL_MSG("ASN RSA cert parse error");
            FreeDecodedCert(dCert);
            wc_FreeRsaKey(key);
            continue;
        }

        if (wc_RsaPublicKeyDecode(dCert->publicKey, &scratch, key,
                                  dCert->pubKeySize) < 0) {
            WOLFSSL_MSG("ASN RSA key decode error");
            FreeDecodedCert(dCert);
            wc_FreeRsaKey(key);
            continue;
        }

    #ifdef WOLFSSL_ASYNC_CRYPT
        do {
            ret = wc_AsyncWait(ret, &key->asyncDev,
                WC_ASYNC_FLAG_CALL_AGAIN);
    #endif
            if (ret >= 0) {
                ret = wc_RsaSSL_Verify(sig, (word32)sigSz, digest, MAX_PKCS7_DIGEST_SZ,
                    key);
            }
    #ifdef WOLFSSL_ASYNC_CRYPT
        } while (ret == WC_NO_ERR_TRACE(WC_PENDING_E));
    #endif
        FreeDecodedCert(dCert);
        wc_FreeRsaKey(key);

        if ((ret > 0) && (hashSz == (word32)ret)) {
            if (XMEMCMP(digest, hash, hashSz) == 0) {
                /* found signer that successfully verified signature */
                verified = 1;
                pkcs7->verifyCert   = pkcs7->cert[i];
                pkcs7->verifyCertSz = pkcs7->certSz[i];
                break;
            }
        }
    }

    if (verified == 0) {
        ret = SIG_VERIFY_E;
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(digest, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(key,    pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(dCert,  pkcs7->heap, DYNAMIC_TYPE_DCERT);
#endif

    return ret;
}

#endif /* NO_RSA */


#ifdef HAVE_ECC

/* returns size of signature put into out, negative on error */
static int wc_PKCS7_EcdsaVerify(wc_PKCS7* pkcs7, byte* sig, int sigSz,
                                byte* hash, word32 hashSz)
{
    int ret = 0, i;
    int res = 0;
    int verified = 0;
#ifdef WOLFSSL_SMALL_STACK
    byte* digest;
    ecc_key* key;
    DecodedCert* dCert;
#else
    byte digest[MAX_PKCS7_DIGEST_SZ];
    ecc_key key[1];
    DecodedCert stack_dCert;
    DecodedCert* dCert = &stack_dCert;
#endif
    word32 idx = 0;

    if (pkcs7 == NULL || sig == NULL)
        return BAD_FUNC_ARG;

#ifdef WOLFSSL_SMALL_STACK
    digest = (byte*)XMALLOC(MAX_PKCS7_DIGEST_SZ, pkcs7->heap,
                            DYNAMIC_TYPE_TMP_BUFFER);
    if (digest == NULL)
        return MEMORY_E;

    key = (ecc_key*)XMALLOC(sizeof(ecc_key), pkcs7->heap,
                            DYNAMIC_TYPE_TMP_BUFFER);
    if (key == NULL) {
        XFREE(digest, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }

    dCert = (DecodedCert*)XMALLOC(sizeof(DecodedCert), pkcs7->heap,
                                  DYNAMIC_TYPE_DCERT);
    if (dCert == NULL) {
        XFREE(digest, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(key,    pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }
#endif

    XMEMSET(digest, 0, MAX_PKCS7_DIGEST_SZ);

    /* loop over certs received in certificates set, try to find one
     * that will validate signature */
    for (i = 0; i < MAX_PKCS7_CERTS; i++) {

        verified = 0;
        idx = 0;

        if (pkcs7->certSz[i] == 0)
            continue;

        ret = wc_ecc_init_ex(key, pkcs7->heap, pkcs7->devId);
        if (ret != 0) {
#ifdef WOLFSSL_SMALL_STACK
            XFREE(digest, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(key,    pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(dCert,  pkcs7->heap, DYNAMIC_TYPE_DCERT);
#endif
            return ret;
        }

        InitDecodedCert(dCert, pkcs7->cert[i], pkcs7->certSz[i], pkcs7->heap);
        /* not verifying, only using this to extract public key */
        ret = ParseCert(dCert, CA_TYPE, NO_VERIFY, 0);
        if (ret < 0) {
            WOLFSSL_MSG("ASN ECC cert parse error");
            FreeDecodedCert(dCert);
            wc_ecc_free(key);
            continue;
        }

        if (wc_EccPublicKeyDecode(dCert->publicKey, &idx, key,
                                  dCert->pubKeySize) < 0) {
            WOLFSSL_MSG("ASN ECC key decode error");
            FreeDecodedCert(dCert);
            wc_ecc_free(key);
            continue;
        }

    #ifdef WOLFSSL_ASYNC_CRYPT
        do {
            ret = wc_AsyncWait(ret, &key->asyncDev,
                WC_ASYNC_FLAG_CALL_AGAIN);
    #endif
            if (ret >= 0) {
                ret = wc_ecc_verify_hash(sig, (word32)sigSz, hash, hashSz, &res, key);
            }
    #ifdef WOLFSSL_ASYNC_CRYPT
        } while (ret == WC_NO_ERR_TRACE(WC_PENDING_E));
    #endif

        if (ret == 0 && res == 1) {
            /* found signer that successfully verified signature */
            verified = 1;
            XMEMCPY(pkcs7->issuerSubjKeyId, dCert->extSubjKeyId, KEYID_SIZE);
            pkcs7->verifyCert   = pkcs7->cert[i];
            pkcs7->verifyCertSz = pkcs7->certSz[i];
        }

        wc_ecc_free(key);
        FreeDecodedCert(dCert);

        if (ret == 0 && res == 1) {
            break;
        }
    }

    if (verified == 0) {
        ret = SIG_VERIFY_E;
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(digest, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(key,    pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(dCert,  pkcs7->heap, DYNAMIC_TYPE_DCERT);
#endif

    return ret;
}

#endif /* HAVE_ECC */


/* build SignedData digest, both in PKCS#7 DigestInfo format and
 * as plain digest for CMS.
 *
 * pkcs7          - pointer to initialized PKCS7 struct
 * signedAttrib   - signed attributes
 * signedAttribSz - size of signedAttrib, octets
 * pkcs7Digest    - [OUT] PKCS#7 DigestInfo
 * pkcs7DigestSz  - [IN/OUT] size of pkcs7Digest
 * plainDigest    - [OUT] pointer to plain digest, offset into pkcs7Digest
 * plainDigestSz  - [OUT] size of digest at plainDigest
 *
 * returns 0 on success, negative on error */
static int wc_PKCS7_BuildSignedDataDigest(wc_PKCS7* pkcs7, byte* signedAttrib,
                                      word32 signedAttribSz, byte* pkcs7Digest,
                                      word32* pkcs7DigestSz, byte** plainDigest,
                                      word32* plainDigestSz,
                                      const byte* hashBuf, word32 hashBufSz)
{
    int ret = 0, digIdx = 0;
    word32 attribSetSz = 0, hashSz = 0;
    byte attribSet[MAX_SET_SZ];
    byte digest[WC_MAX_DIGEST_SIZE];
    byte digestInfoSeq[MAX_SEQ_SZ];
    byte digestStr[MAX_OCTET_STR_SZ];
    byte algoId[MAX_ALGO_SZ];
    word32 digestInfoSeqSz, digestStrSz, algoIdSz;
#ifdef WOLFSSL_SMALL_STACK
    byte* digestInfo;
#else
    byte  digestInfo[MAX_PKCS7_DIGEST_SZ];
#endif

    wc_HashAlg hash;
    enum wc_HashType hashType;

    /* check arguments */
    if (pkcs7 == NULL || pkcs7Digest == NULL ||
        pkcs7DigestSz == NULL || plainDigest == NULL) {
        return BAD_FUNC_ARG;
    }

    hashType = wc_OidGetHash(pkcs7->hashOID);
    ret = wc_HashGetDigestSize(hashType);
    if (ret < 0)
        return ret;
    hashSz = (word32)ret;

    if (signedAttribSz > 0) {
        if (signedAttrib == NULL)
            return BAD_FUNC_ARG;
    }
    else {
        if (hashBuf && hashBufSz > 0) {
            if (hashSz != hashBufSz)
                return BAD_FUNC_ARG;
        }
        else if (pkcs7->content == NULL)
            return BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_SMALL_STACK
    digestInfo = (byte*)XMALLOC(MAX_PKCS7_DIGEST_SZ, pkcs7->heap,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (digestInfo == NULL)
        return MEMORY_E;
#endif

    XMEMSET(pkcs7Digest, 0, *pkcs7DigestSz);
    XMEMSET(digest,      0, WC_MAX_DIGEST_SIZE);
    XMEMSET(digestInfo,  0, MAX_PKCS7_DIGEST_SZ);


    /* calculate digest */
    if (hashBuf && hashBufSz > 0 && signedAttribSz == 0) {
        XMEMCPY(digest, hashBuf, hashBufSz);
    }
    else {
        ret = wc_HashInit(&hash, hashType);
        if (ret < 0) {
    #ifdef WOLFSSL_SMALL_STACK
            XFREE(digestInfo, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
    #endif
            return ret;
        }

        if (signedAttribSz > 0) {
            attribSetSz = SetSet(signedAttribSz, attribSet);

            /* calculate digest */
            ret = wc_HashUpdate(&hash, hashType, attribSet, attribSetSz);
            if (ret == 0)
                ret = wc_HashUpdate(&hash, hashType, signedAttrib, signedAttribSz);
            if (ret == 0)
                ret = wc_HashFinal(&hash, hashType, digest);
        } else {
            ret = wc_HashUpdate(&hash, hashType, pkcs7->content, pkcs7->contentSz);
            if (ret == 0)
                ret = wc_HashFinal(&hash, hashType, digest);
        }

        wc_HashFree(&hash, hashType);
        if (ret < 0) {
    #ifdef WOLFSSL_SMALL_STACK
            XFREE(digestInfo, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
    #endif
            return ret;
        }
    }

    /* Set algoID, match whatever was input to match either NULL or absent */
    algoIdSz = SetAlgoIDEx(pkcs7->hashOID, algoId, oidHashType,
                            0, pkcs7->hashParamsAbsent);

    digestStrSz = SetOctetString(hashSz, digestStr);
    digestInfoSeqSz = SetSequence(algoIdSz + digestStrSz + hashSz,
                                  digestInfoSeq);

    XMEMCPY(digestInfo + digIdx, digestInfoSeq, digestInfoSeqSz);
    digIdx += (int)digestInfoSeqSz;
    XMEMCPY(digestInfo + digIdx, algoId, algoIdSz);
    digIdx += (int)algoIdSz;
    XMEMCPY(digestInfo + digIdx, digestStr, digestStrSz);
    digIdx += (int)digestStrSz;
    XMEMCPY(digestInfo + digIdx, digest, hashSz);
    digIdx += (int)hashSz;

    XMEMCPY(pkcs7Digest, digestInfo, (word32)digIdx);
    *pkcs7DigestSz = (word32)digIdx;

    /* set plain digest pointer */
    *plainDigest = pkcs7Digest + digIdx - hashSz;
    *plainDigestSz = hashSz;

#ifdef WOLFSSL_SMALL_STACK
    XFREE(digestInfo, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return 0;
}


/* Verifies CMS/PKCS7 SignedData content digest matches that which is
 * included in the messageDigest signed attribute. Only called when
 * signed attributes are present, otherwise original signature verification
 * is done over content.
 *
 * pkcs7          - pointer to initialized PKCS7 struct
 * hashBuf        - pointer to user-provided hash buffer, used with
 *                  wc_PKCS7_VerifySignedData_ex()
 * hashBufSz      - size of hashBuf, octets
 *
 * return 0 on success, negative on error */
static int wc_PKCS7_VerifyContentMessageDigest(wc_PKCS7* pkcs7,
                                               const byte* hashBuf,
                                               word32 hashSz)
{
    int ret = 0, digestSz = 0, innerAttribSz = 0;
    int contentLen = 0;
    word32 idx = 0;
    word32 contentIdx = 0;
    byte* content = NULL;
    byte* digestBuf = NULL;
#ifdef WOLFSSL_SMALL_STACK
    byte* digest = NULL;
#else
    byte  digest[MAX_PKCS7_DIGEST_SZ];
#endif
    PKCS7DecodedAttrib* attrib;
    enum wc_HashType hashType;

    /* messageDigest OID (1.2.840.113549.1.9.4) */
    const byte mdOid[] =
            { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x04 };

    if (pkcs7 == NULL)
        return BAD_FUNC_ARG;

    if ((pkcs7->content == NULL || pkcs7->contentSz == 0) &&
        (hashBuf == NULL || hashSz == 0)) {
        WOLFSSL_MSG("SignedData bundle has no content or hash to verify");
        return BAD_FUNC_ARG;
    }

    /* lookup messageDigest attribute */
    attrib = findAttrib(pkcs7, mdOid, sizeof(mdOid));
    if (attrib == NULL) {
        WOLFSSL_MSG("messageDigest attribute not in bundle, must be when "
                    "signed attribs are present");
        return ASN_PARSE_E;
    }

    /* advance past attrib->value ASN.1 header and length */
    if (attrib->value == NULL || attrib->valueSz == 0)
        return ASN_PARSE_E;

    if (attrib->value[idx++] != ASN_OCTET_STRING)
        return ASN_PARSE_E;

    if (GetLength(attrib->value, &idx, &innerAttribSz, attrib->valueSz) < 0)
        return ASN_PARSE_E;

    /* get hash type and size */
    hashType = wc_OidGetHash(pkcs7->hashOID);
    if (hashType == WC_HASH_TYPE_NONE) {
        WOLFSSL_MSG("Error getting hash type for PKCS7 content verification");
        return BAD_FUNC_ARG;
    }

    /* build content hash if needed, or use existing hash value */
    if (hashBuf == NULL) {

#ifdef WOLFSSL_SMALL_STACK
        digest = (byte*)XMALLOC(MAX_PKCS7_DIGEST_SZ, pkcs7->heap,
                                DYNAMIC_TYPE_TMP_BUFFER);
        if (digest == NULL)
            return MEMORY_E;
#endif
        XMEMSET(digest, 0, MAX_PKCS7_DIGEST_SZ);

        content = pkcs7->content;
        contentLen = (int)pkcs7->contentSz;

        if (pkcs7->contentIsPkcs7Type == 1) {
            /* Content follows PKCS#7 RFC, which defines type as ANY. CMS
             * mandates OCTET_STRING which has already been stripped off.
             * For PKCS#7 message digest calculation, digest is calculated
             * only on the "value" of the DER encoding. As such, advance past
             * the tag and length */
            if (contentLen > 1) {
                contentIdx++;
            }

            if (GetLength_ex(content, &contentIdx, &contentLen,
                    (word32)contentLen, 1) < 0) {
                #ifdef WOLFSSL_SMALL_STACK
                    XFREE(digest, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
                #endif
                return ASN_PARSE_E;
            }
        }

        ret = wc_Hash(hashType, content + contentIdx, (word32)contentLen, digest,
                      MAX_PKCS7_DIGEST_SZ);
        if (ret < 0) {
            WOLFSSL_MSG("Error hashing PKCS7 content for verification");
#ifdef WOLFSSL_SMALL_STACK
            XFREE(digest, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
            return ret;
        }

        digestBuf = digest;
        digestSz = wc_HashGetDigestSize(hashType);
        if (digestSz < 0) {
            WOLFSSL_MSG("Invalid hash type");
#ifdef WOLFSSL_SMALL_STACK
            XFREE(digest, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
            return digestSz;
        }
    } else {

        /* user passed in pre-computed hash */
        digestBuf = (byte*)hashBuf;
        digestSz  = (int)hashSz;
    }

    /* compare generated to hash in messageDigest attribute */
    if ((innerAttribSz != digestSz) ||
        (XMEMCMP(attrib->value + idx, digestBuf, (size_t)digestSz) != 0)) {
        WOLFSSL_MSG("Content digest does not match messageDigest attrib value");
#ifdef WOLFSSL_SMALL_STACK
        XFREE(digest, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return SIG_VERIFY_E;
    }

    if (hashBuf == NULL) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(digest, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    }

    return 0;
}


/* verifies SignedData signature, over either PKCS#7 DigestInfo or
 * content digest.
 *
 * pkcs7          - pointer to initialized PKCS7 struct
 * sig            - signature to verify
 * sigSz          - size of sig
 * signedAttrib   - signed attributes, or null if empty
 * signedAttribSz - size of signedAttributes
 *
 * return 0 on success, negative on error */
static int wc_PKCS7_SignedDataVerifySignature(wc_PKCS7* pkcs7, byte* sig,
                                             word32 sigSz, byte* signedAttrib,
                                             word32 signedAttribSz,
                                             const byte* hashBuf, word32 hashSz)
{
    int ret = 0;
    word32 plainDigestSz = 0, pkcs7DigestSz;
    byte* plainDigest = NULL; /* offset into pkcs7Digest */
#ifdef WOLFSSL_SMALL_STACK
    byte* pkcs7Digest;
#else
    byte  pkcs7Digest[MAX_PKCS7_DIGEST_SZ];
#endif

    if (pkcs7 == NULL)
        return BAD_FUNC_ARG;

    /* allocate space to build hash */
    pkcs7DigestSz = MAX_PKCS7_DIGEST_SZ;
#ifdef WOLFSSL_SMALL_STACK
    pkcs7Digest = (byte*)XMALLOC(pkcs7DigestSz, pkcs7->heap,
                                 DYNAMIC_TYPE_TMP_BUFFER);
    if (pkcs7Digest == NULL)
        return MEMORY_E;
#endif

    XMEMSET(pkcs7Digest, 0, pkcs7DigestSz);

    /* verify signed attrib digest matches that of content */
    if (signedAttrib != NULL) {
        ret = wc_PKCS7_VerifyContentMessageDigest(pkcs7, hashBuf, hashSz);
        if (ret != 0) {
#ifdef WOLFSSL_SMALL_STACK
            XFREE(pkcs7Digest, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
            return ret;
        }
    }

    /* build hash to verify against */
    ret = wc_PKCS7_BuildSignedDataDigest(pkcs7, signedAttrib,
                                         signedAttribSz, pkcs7Digest,
                                         &pkcs7DigestSz, &plainDigest,
                                         &plainDigestSz, hashBuf, hashSz);
    if (ret < 0) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(pkcs7Digest, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return ret;
    }

    /* If no certificates are available then store the signature and hash for
     * user to verify. Make sure that different return value than success is
     * returned because the signature was not verified here. */
    if (ret == 0) {
        byte haveCert = 0;
        int  i;

        for (i = 0; i < MAX_PKCS7_CERTS; i++) {
            if (pkcs7->certSz[i] == 0)
                continue;
            haveCert = 1;
        }

        if (!haveCert) {
            WOLFSSL_MSG("No certificates in bundle to verify signature");

            /* store signature */
            XFREE(pkcs7->signature, pkcs7->heap, DYNAMIC_TYPE_SIGNATURE);
            pkcs7->signature = NULL;
            pkcs7->signatureSz = 0;
            pkcs7->signature = (byte*)XMALLOC(sigSz, pkcs7->heap,
                    DYNAMIC_TYPE_SIGNATURE);
            if (pkcs7->signature == NULL) {
            #ifdef WOLFSSL_SMALL_STACK
                XFREE(pkcs7Digest, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
            #endif
                return MEMORY_E;
            }
            XMEMCPY(pkcs7->signature, sig, sigSz);
            pkcs7->signatureSz = sigSz;

            /* store plain digest (CMS and ECC) */
            XFREE(pkcs7->plainDigest, pkcs7->heap, DYNAMIC_TYPE_DIGEST);
            pkcs7->plainDigest = NULL;
            pkcs7->plainDigestSz = 0;
            pkcs7->plainDigest = (byte*)XMALLOC(plainDigestSz, pkcs7->heap,
                    DYNAMIC_TYPE_DIGEST);
            if (pkcs7->plainDigest == NULL) {
            #ifdef WOLFSSL_SMALL_STACK
                XFREE(pkcs7Digest, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
            #endif
                return MEMORY_E;
            }
            XMEMCPY(pkcs7->plainDigest, plainDigest, plainDigestSz);
            pkcs7->plainDigestSz = plainDigestSz;

            /* store pkcs7 digest (default RSA) */
            XFREE(pkcs7->pkcs7Digest, pkcs7->heap, DYNAMIC_TYPE_DIGEST);
            pkcs7->pkcs7Digest = NULL;
            pkcs7->pkcs7DigestSz = 0;
            pkcs7->pkcs7Digest = (byte*)XMALLOC(pkcs7DigestSz, pkcs7->heap,
                    DYNAMIC_TYPE_DIGEST);
            if (pkcs7->pkcs7Digest == NULL) {
            #ifdef WOLFSSL_SMALL_STACK
                XFREE(pkcs7Digest, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
            #endif
                return MEMORY_E;
            }
            XMEMCPY(pkcs7->pkcs7Digest, pkcs7Digest, pkcs7DigestSz);
            pkcs7->pkcs7DigestSz = pkcs7DigestSz;

            #ifdef WOLFSSL_SMALL_STACK
            XFREE(pkcs7Digest, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
            #endif
            return PKCS7_SIGNEEDS_CHECK;
        }
    }



    switch (pkcs7->publicKeyOID) {

#ifndef NO_RSA
        case RSAk:
            ret = wc_PKCS7_RsaVerify(pkcs7, sig, (int)sigSz, pkcs7Digest,
                                     pkcs7DigestSz);
            if (ret < 0) {
                WOLFSSL_MSG("PKCS#7 verification failed, trying CMS");
                ret = wc_PKCS7_RsaVerify(pkcs7, sig, (int)sigSz, plainDigest,
                                         plainDigestSz);
            }
            break;
#endif

#ifdef HAVE_ECC
        case ECDSAk:
            ret = wc_PKCS7_EcdsaVerify(pkcs7, sig, (int)sigSz, plainDigest,
                                       plainDigestSz);
            break;
#endif

        default:
            WOLFSSL_MSG("Unsupported public key type");
            ret = BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_SMALL_STACK
     XFREE(pkcs7Digest, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return ret;
}


/* set correct public key OID based on signature OID, stores in
 * pkcs7->publicKeyOID and returns same value */
static int wc_PKCS7_SetPublicKeyOID(wc_PKCS7* pkcs7, int sigOID)
{
    if (pkcs7 == NULL)
        return BAD_FUNC_ARG;

    pkcs7->publicKeyOID = 0;

    switch (sigOID) {

    #ifndef NO_RSA
        /* RSA signature types */
        case CTC_MD2wRSA:
        case CTC_MD5wRSA:
        case CTC_SHAwRSA:
        case CTC_SHA224wRSA:
        case CTC_SHA256wRSA:
        case CTC_SHA384wRSA:
        case CTC_SHA512wRSA:
        case CTC_SHA3_224wRSA:
        case CTC_SHA3_256wRSA:
        case CTC_SHA3_384wRSA:
        case CTC_SHA3_512wRSA:
            pkcs7->publicKeyOID = RSAk;
            break;

        /* if sigOID is already RSAk */
        case RSAk:
            pkcs7->publicKeyOID = (word32)sigOID;
            break;
    #endif

    #ifndef NO_DSA
        /* DSA signature types */
        case CTC_SHAwDSA:
            pkcs7->publicKeyOID = DSAk;
            break;

        /* if sigOID is already DSAk */
        case DSAk:
            pkcs7->publicKeyOID = (word32)sigOID;
            break;
    #endif

    #ifdef HAVE_ECC
        /* ECDSA signature types */
        case CTC_SHAwECDSA:
        case CTC_SHA224wECDSA:
        case CTC_SHA256wECDSA:
        case CTC_SHA384wECDSA:
        case CTC_SHA512wECDSA:
        case CTC_SHA3_224wECDSA:
        case CTC_SHA3_256wECDSA:
        case CTC_SHA3_384wECDSA:
        case CTC_SHA3_512wECDSA:
            pkcs7->publicKeyOID = ECDSAk;
            break;

        /* if sigOID is already ECDSAk */
        case ECDSAk:
            pkcs7->publicKeyOID = (word32)sigOID;
            break;
    #endif

        default:
            WOLFSSL_MSG("Unsupported public key algorithm");
            return ASN_SIG_KEY_E;
    }

    return (int)pkcs7->publicKeyOID;
}


/* Parses through the attributes and adds them to the PKCS7 structure
 * Creates dynamic attribute structures that are free'd with calling
 * wc_PKCS7_Free()
 *
 * NOTE: An attribute has the ASN1 format of
 ** Sequence
 ****** Object ID
 ****** Set
 ********** {PrintableString, UTCTime, OCTET STRING ...}
 *
 * pkcs7  the PKCS7 structure to put the parsed attributes into
 * in     buffer holding all attributes
 * inSz   size of in buffer
 *
 * returns the number of attributes parsed on success
 */
static int wc_PKCS7_ParseAttribs(wc_PKCS7* pkcs7, byte* in, int inSz)
{
    int    found = 0;
    word32 idx   = 0;
    word32 oid;

    if (pkcs7 == NULL || in == NULL || inSz < 0) {
        return BAD_FUNC_ARG;
    }

    while (idx < (word32)inSz) {
        int length  = 0;
        word32 oidIdx;
        PKCS7DecodedAttrib* attrib;

        if (GetSequence(in, &idx, &length, (word32)inSz) < 0)
            return ASN_PARSE_E;

        attrib = (PKCS7DecodedAttrib*)XMALLOC(sizeof(PKCS7DecodedAttrib),
                pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        if (attrib == NULL) {
            return MEMORY_E;
        }
        XMEMSET(attrib, 0, sizeof(PKCS7DecodedAttrib));

        oidIdx = idx;
        if (GetObjectId(in, &idx, &oid, oidIgnoreType, (word32)inSz)
                < 0) {
            XFREE(attrib, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
            return ASN_PARSE_E;
        }
        attrib->oidSz = idx - oidIdx;
        attrib->oid = (byte*)XMALLOC(attrib->oidSz, pkcs7->heap,
                                     DYNAMIC_TYPE_PKCS7);
        if (attrib->oid == NULL) {
            XFREE(attrib, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
            return MEMORY_E;
        }
        XMEMCPY(attrib->oid, in + oidIdx, attrib->oidSz);

        /* Get Set that contains the printable string value */
        if (GetSet(in, &idx, &length, (word32)inSz) < 0) {
            XFREE(attrib->oid, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
            XFREE(attrib, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
            return ASN_PARSE_E;
        }

        if ((inSz - (int)idx) < length) {
            XFREE(attrib->oid, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
            XFREE(attrib, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
            return ASN_PARSE_E;
        }

        attrib->valueSz = (word32)length;
        attrib->value = (byte*)XMALLOC(attrib->valueSz, pkcs7->heap,
                                       DYNAMIC_TYPE_PKCS7);
        if (attrib->value == NULL) {
            XFREE(attrib->oid, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
            XFREE(attrib, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
            return MEMORY_E;
        }
        XMEMCPY(attrib->value, in + idx, attrib->valueSz);
        idx += (word32)length;

        /* store attribute in linked list */
        if (pkcs7->decodedAttrib != NULL) {
            attrib->next = pkcs7->decodedAttrib;
            pkcs7->decodedAttrib = attrib;
        } else {
            pkcs7->decodedAttrib = attrib;
        }
        found++;
    }

    return found;
}


/* option to turn off support for degenerate cases
 * flag 0 turns off support
 * flag 1 turns on support
 *
 * by default support for SignedData degenerate cases is on
 */
void wc_PKCS7_AllowDegenerate(wc_PKCS7* pkcs7, word16 flag)
{
    if (pkcs7) {
        if (flag) { /* flag of 1 turns on support for degenerate */
            pkcs7->noDegenerate = 0;
        }
        else { /* flag of 0 turns off support */
            pkcs7->noDegenerate = 1;
        }
    }
}

/* Parses through a signerInfo set. Reads buffer "in" from "idxIn" to "idxIn" +
 * length treating the current "idxIn" plus the length of set as max possible
 * index.
 *
 * In the case that signed attributes are found "signedAttrib" gets set to point
 *  at their location in the buffer "in". Also in this case signedAttribSz gets
 *  set to the size of the signedAttrib buffer.
 *
 * returns 0 on success
 */
static int wc_PKCS7_ParseSignerInfo(wc_PKCS7* pkcs7, byte* in, word32 inSz,
        word32* idxIn, int degenerate, byte** signedAttrib, int* signedAttribSz)
{
    int ret = 0;
    int length = 0;
    int version = 0;
    word32 sigOID = 0, hashOID = 0;
    word32 idx = *idxIn, localIdx;
    byte tag;
    byte absentParams = FALSE;

    WOLFSSL_ENTER("wc_PKCS7_ParseSignerInfo");
    /* require a signer if degenerate case not allowed */
    if (inSz == 0 && pkcs7->noDegenerate == 1) {
        WOLFSSL_MSG("Set to not allow degenerate cases");
        return PKCS7_NO_SIGNER_E;
    }

    if (inSz == 0 && degenerate == 0) {
        WOLFSSL_MSG("PKCS7 signers expected");
        return PKCS7_NO_SIGNER_E;
    }

    /* not a degenerate case and there is elements in the set */
    if (inSz > 0 && degenerate == 0) {
        ret = wc_PKCS7_SignerInfoNew(pkcs7);

        /* Get the sequence of the first signerInfo */
        if (ret == 0 && GetSequence(in, &idx, &length, inSz) < 0)
            ret = ASN_PARSE_E;

        /* Get the version */
        if (ret == 0 && GetMyVersion(in, &idx, &version, inSz) < 0)
            ret = ASN_PARSE_E;

        if (ret == 0) {
            pkcs7->signerInfo->version = version;
        }

        if (ret == 0 && version == 1) {
            /* Get the sequence of IssuerAndSerialNumber */
            if (GetSequence(in, &idx, &length, inSz) < 0)
                ret = ASN_PARSE_E;

            if (ret == 0) {
                ret = wc_PKCS7_SignerInfoSetSID(pkcs7, in + idx, length);
                idx += (word32)length;
            }

        } else if (ret == 0 && version == 3) {
            /* Get the sequence of SubjectKeyIdentifier */
            if (idx + 1 > inSz)
                ret = BUFFER_E;

            localIdx = idx;
            if (ret == 0 && GetASNTag(in, &localIdx, &tag, inSz) == 0 &&
                   tag == (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 0)) {
                idx++;

                if (GetLength(in, &idx, &length, inSz) <= 0)
                    ret = ASN_PARSE_E;

                if (ret == 0 && idx + 1 > inSz)
                    ret = BUFFER_E;

                if (ret == 0 && GetASNTag(in, &idx, &tag, inSz) < 0)
                    ret = ASN_PARSE_E;

                if (ret == 0 && tag != ASN_OCTET_STRING)
                    ret = ASN_PARSE_E;

                if (ret == 0 && GetLength(in, &idx, &length, inSz) < 0)
                    ret = ASN_PARSE_E;
            }
            else {
                /* check if SKID with ASN_CONTEXT_SPECIFIC otherwise in version
                 * 3 try to get issuerAndSerial */
                localIdx = idx;
                if (GetASNTag(in, &localIdx, &tag, inSz) == 0 &&
                        tag == ASN_CONTEXT_SPECIFIC) {
                    idx++;
                    if (ret == 0 && GetLength(in, &idx, &length, inSz) < 0)
                        ret = ASN_PARSE_E;
                }
                else {
                    if (pkcs7->version != 3) {
                        WOLFSSL_MSG("Unexpected signer info found with version");
                        ret = ASN_PARSE_E;
                    }

                    if (ret == 0 && GetSequence(in, &idx, &length, inSz) < 0)
                        ret = ASN_PARSE_E;
                }
            }

            if (ret == 0) {
                if (length > (int)inSz - (int)idx)
                    ret = BUFFER_E;
            }

            if (ret == 0) {
                ret = wc_PKCS7_SignerInfoSetSID(pkcs7, in + idx, length);
                idx += (word32)length;
            }

        } else {
            WOLFSSL_MSG("PKCS#7 signerInfo version must be 1 or 3");
            ret = ASN_VERSION_E;
        }

        /* Get the sequence of digestAlgorithm */
        if (ret == 0 && GetAlgoIdEx(in, &idx, &hashOID, oidHashType,
                                    inSz, &absentParams) < 0) {
            ret = ASN_PARSE_E;
        }
        pkcs7->hashOID = (int)hashOID;
        pkcs7->hashParamsAbsent = (absentParams != 0);

        /* Get the IMPLICIT[0] SET OF signedAttributes */
        localIdx = idx;
        if (ret == 0 && GetASNTag(in, &localIdx, &tag, inSz) == 0 &&
                tag == (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 0)) {
            idx++;

            if (GetLength(in, &idx, &length, inSz) < 0)
                ret = ASN_PARSE_E;

            /* save pointer and length */
            *signedAttrib = &in[idx];
            *signedAttribSz = length;

            if (ret == 0 && wc_PKCS7_ParseAttribs(pkcs7, *signedAttrib,
                        *signedAttribSz) < 0) {
                WOLFSSL_MSG("Error parsing signed attributes");
                ret = ASN_PARSE_E;
            }

            idx += (word32)length;
        }

        /* Get digestEncryptionAlgorithm - key type or signature type */
        if (ret == 0 && GetAlgoId(in, &idx, &sigOID, oidIgnoreType, inSz) < 0) {
            ret = ASN_PARSE_E;
        }

        /* store public key type based on digestEncryptionAlgorithm */
        if (ret == 0) {
            ret = wc_PKCS7_SetPublicKeyOID(pkcs7, (int)sigOID);
            if (ret < 0) {
                WOLFSSL_MSG("Failed to set public key OID from signature");
            }
            else {
                /* if previous return was positive then was success */
                ret = 0;
            }
        }
    }

    /* update index on success */
    if (ret == 0) {
        *idxIn = idx;
    }

    return ret;
}

/* parse input to get single/multiple octet strings.
 * get each octet string from stream up to the size defined by
 * MAX_PKCS7_STREAM_BUFFER then hash and store them to the content buffer.
 * hash is stored to pkcs7->stream->hashBuf and its size in
 * pkcs7->stream->hashBufSz if keepContent is true, accumulates content into
 * pkcs7->stream->content and stores its size in pkcs7->stream->contentSz.
 */
#ifndef NO_PKCS7_STREAM
static int wc_PKCS7_HandleOctetStrings(wc_PKCS7* pkcs7, byte* in, word32 inSz,
                                word32* tmpIdx, word32* idx, int keepContent)
{
    int ret, length = 0;
    word32 msgSz, i, contBufSz;
    byte tag;
    byte* msg = NULL;
    byte* tempBuf = NULL;

    /* allow 0 for inSz in streaming */
    if (inSz == 0) {
        return WC_PKCS7_WANT_READ_E;
    }

    if (pkcs7 == NULL || in == NULL || idx == NULL)
        return BAD_FUNC_ARG;

    /* no content case, do nothing */
    if (pkcs7->stream->noContent) {
        if (pkcs7->content && pkcs7->contentSz > 0) {
            XFREE(pkcs7->stream->content, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
            pkcs7->stream->content = NULL;

            pkcs7->stream->content = (byte*)XMALLOC(pkcs7->contentSz,
                                            pkcs7->heap, DYNAMIC_TYPE_PKCS7);
            if (pkcs7->stream->content == NULL) {
                WOLFSSL_MSG("Failed to grow content buffer.");
                return MEMORY_E;
            }
            XMEMCPY(pkcs7->stream->content, pkcs7->content, pkcs7->contentSz);
            pkcs7->stream->contentSz = pkcs7->contentSz;
        }
        return 0;
    }

    /* free pkcs7->contentDynamic buffer */
    XFREE(pkcs7->contentDynamic, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
    pkcs7->contentDynamic = NULL;

    while(1) {
        if ((ret = wc_PKCS7_AddDataToStream(pkcs7, in, inSz,
                            pkcs7->stream->expected, &msg, idx)) != 0) {
            break;
        }

        msgSz = (pkcs7->stream->length > 0)? pkcs7->stream->length:inSz;

        if (pkcs7->stream->currContRmnSz == 0) {

            /* processed single OCTET STRING, try to find another one. */
            if ((ret = GetASNTag(msg, idx, &tag, msgSz)) < 0) {
                break;
            }

            /* if another OCTET STRING is found, get its length */
            if (ret == 0 && tag == ASN_OCTET_STRING) {

                if (ret == 0 && GetLength_ex(msg, idx, &length, msgSz,
                                                            NO_USER_CHECK) < 0){
                    ret = ASN_PARSE_E;
                    break;
                }

                /* set up for next octet string */
                pkcs7->stream->currContSz    = (word32)length;
                pkcs7->stream->currContRmnSz = (word32)length;
                pkcs7->stream->expected      = min(pkcs7->stream->currContRmnSz,
                                                   MAX_PKCS7_STREAM_BUFFER);

                /* advance read index */
                if (wc_PKCS7_StreamEndCase(pkcs7, tmpIdx, idx) != 0) {
                    break;
                }

                /* check if expected data is available in stream */
                ret = wc_PKCS7_AddDataToStream(pkcs7, in, inSz,
                            pkcs7->stream->expected, &msg, idx);
                if (ret == WC_NO_ERR_TRACE(WC_PKCS7_WANT_READ_E)) {
                    break;  /* ask user more input */
                }

                /* data available, continue processing */
                continue;
            }
            /* reached to the end of contents. trailing zeros may follow. */
            else if (ret == 0 && tag == ASN_EOC) {

                /* ASN_EOC tag and one zero follows to show the end of
                 * in-definite length encoding.
                 * number of indef is stored in pkcs7->stream->cntIdfCnt.
                 */
                pkcs7->stream->expected = (word32)(ASN_TAG_SZ + TRAILING_ZERO) *
                                               (word32)pkcs7->stream->cntIdfCnt;

                /* dec idx by one since already consumed to get ASN_EOC */
                (*idx)--;

                if (wc_PKCS7_StreamEndCase(pkcs7, tmpIdx, idx) != 0) {
                    break;
                }

                /* check if expected data is available in stream */
                ret = wc_PKCS7_AddDataToStream(pkcs7, in, inSz,
                            pkcs7->stream->expected, &msg, idx);
                if (ret == WC_NO_ERR_TRACE(WC_PKCS7_WANT_READ_E)) {
                    break;  /* ask user more input */
                }

                /* data available, continue processing trailing zeros */
                for (i = 0; i < pkcs7->stream->expected; i++) {
                    if (msg[*idx + i] != 0) {
                        ret = ASN_PARSE_E;
                        break;
                    }
                }
                /* reset indef-length count */
                pkcs7->stream->cntIdfCnt = 0;

                /* advance read index */
                *idx += pkcs7->stream->expected;

                if (wc_PKCS7_StreamEndCase(pkcs7, tmpIdx, idx) != 0) {
                    break;
                }

                /* handled OCTET STRINGs successfully */
                ret = 0;
                break;
            }
            /* reached to the end of contents without trailing zeros */
            else if (ret == 0) {

                /* dec idx by one since already consumed to get ASN_EOC */
                (*idx)--;

                if (wc_PKCS7_StreamEndCase(pkcs7, tmpIdx, idx) != 0) {
                    break;
                }

                ret = wc_PKCS7_AddDataToStream(pkcs7, in, inSz,
                            pkcs7->stream->expected, &msg, idx);
                if (ret == WC_NO_ERR_TRACE(WC_PKCS7_WANT_READ_E)) {
                    break;
                }

                /* handled OCTET STRINGs successfully */
                ret = 0;
                break;
            }
            else {
                break;
            }
        }
        else {
            /* got partial octet string data */
            /* accumulate partial octet string to buffer */
            if (keepContent) {

                /* store current content buffer temporarily */
                tempBuf = pkcs7->stream->content;
                pkcs7->stream->content = NULL;

                /* grow content buffer */
                contBufSz = pkcs7->stream->accumContSz;
                pkcs7->stream->accumContSz += pkcs7->stream->expected;

                pkcs7->stream->content =
                                (byte*)XMALLOC(pkcs7->stream->accumContSz,
                                            pkcs7->heap, DYNAMIC_TYPE_PKCS7);

                if (pkcs7->stream->content == NULL) {
                    WOLFSSL_MSG("failed to grow content buffer.");
                    XFREE(tempBuf, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
                    tempBuf = NULL;
                    ret = MEMORY_E;
                    break;
                }
                else {
                    /* accumulate content */
                    if (tempBuf != NULL && contBufSz != 0) {
                        XMEMCPY(pkcs7->stream->content, tempBuf, contBufSz);
                    }
                    XMEMCPY(pkcs7->stream->content + contBufSz, msg + *idx,
                                                    pkcs7->stream->expected);
                    XFREE(tempBuf, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
                    tempBuf = NULL;
                }
            }

            *idx                         += pkcs7->stream->expected;
            pkcs7->stream->currContRmnSz -= pkcs7->stream->expected;
            pkcs7->stream->contentSz     += pkcs7->stream->expected;

            if (wc_PKCS7_StreamEndCase(pkcs7, tmpIdx, idx) != 0) {
                break;
            }

            if (pkcs7->stream->currContRmnSz > 0) {
                pkcs7->stream->expected = min(pkcs7->stream->currContRmnSz,
                                              MAX_PKCS7_STREAM_BUFFER);
            }
            else {
                /* Processed current OCTET STRING. Proceed to the next one. */
                pkcs7->stream->currContRmnSz = 0;
                pkcs7->stream->currContSz    = 0;
                pkcs7->stream->expected= ASN_TAG_SZ + MAX_LENGTH_SZ;

                if (pkcs7->stream->maxLen > 0 &&
                    (pkcs7->stream->maxLen - pkcs7->stream->totalRd)
                                                < ASN_TAG_SZ + MAX_LENGTH_SZ) {
                    /* seems reached to end of content */
                    ret = 0;
                    break;
                }
            }

            /* data available */
            continue;
        }
    }
    return ret;
}
#endif /* !NO_PKCS7_STREAM */
/* Finds the certificates in the message and saves it. By default allows
 * degenerate cases which can have no signer.
 *
 * By default expects type SIGNED_DATA (SignedData) which can have any number of
 * elements in signerInfos collection, including zero. (RFC2315 section 9.1)
 * When adding support for the case of SignedAndEnvelopedData content types a
 * signer is required. In this case the PKCS7 flag noDegenerate could be set.
 */
static int PKCS7_VerifySignedData(wc_PKCS7* pkcs7, const byte* hashBuf,
    word32 hashSz, byte* in, word32 inSz,
    byte* in2, word32 in2Sz)
{
    word32 idx, maxIdx = inSz, outerContentType = 0, contentTypeSz = 0, totalSz = 0;
    int length = 0, version = 0, ret = 0;
    byte* content = NULL;
    byte* contentDynamic = NULL;
    byte* sig = NULL;
    byte* cert = NULL;
    byte* signedAttrib = NULL;
    byte* contentType = NULL;
    int encapContentInfoLen = 0;
    int contentSz = 0, sigSz = 0, certSz = 0, signedAttribSz = 0;
    word32 localIdx, start;
    word32 certIdx, certIdx2;
    byte degenerate = 0;
    byte detached = 0;
    byte tag = 0;
    word16 contentIsPkcs7Type = 0;
#ifdef ASN_BER_TO_DER
    byte* der;
#endif
    int multiPart = 0, keepContent;
    int contentLen = 0;

    byte* pkiMsg    = in;
    word32 pkiMsgSz = inSz;
#ifndef NO_PKCS7_STREAM
    word32 stateIdx = 0;
    word32 hashOID = 0;
    enum wc_HashType hashType = WC_HASH_TYPE_NONE;
    byte*   src = NULL;
    word32  srcSz;
#endif
    byte* pkiMsg2 = in2;
    word32 pkiMsg2Sz = in2Sz;
    (void)keepContent;
    if (pkcs7 == NULL)
        return BAD_FUNC_ARG;

#ifndef NO_PKCS7_STREAM
    /* allow for 0 size inputs with stream mode */
    if (pkiMsg == NULL && pkiMsgSz > 0)
        return BAD_FUNC_ARG;

#else
    if (pkiMsg == NULL || pkiMsgSz == 0)
        return BAD_FUNC_ARG;
#endif

    if ((hashSz > 0 && hashBuf == NULL) || (pkiMsg2Sz > 0 && pkiMsg2 == NULL)) {
        return BAD_FUNC_ARG;
    }
    idx = 0;

#ifdef ASN_BER_TO_DER
    if (pkcs7->derSz > 0 && pkcs7->der) {
        pkiMsg = pkcs7->der;
    }
#endif

#ifndef NO_PKCS7_STREAM
    if (pkcs7->stream == NULL) {
        if ((ret = wc_PKCS7_CreateStream(pkcs7)) != 0) {
            return ret;
        }
    }
#endif

    switch (pkcs7->state) {
        case WC_PKCS7_START:
        #ifndef NO_PKCS7_STREAM
            /* The expected size calculation originally assumed digest OID
             * with NULL params, -2 to also accept with absent params */
            if ((ret = wc_PKCS7_AddDataToStream(pkcs7, in, inSz, (MAX_SEQ_SZ +
                            MAX_VERSION_SZ + MAX_SEQ_SZ + MAX_LENGTH_SZ +
                            ASN_TAG_SZ + MAX_OID_SZ + MAX_SEQ_SZ) - 2,
                            &pkiMsg, &idx)) != 0) {
                break;
            }

            pkiMsgSz = (pkcs7->stream->length > 0)? pkcs7->stream->length: inSz;

            /* get content info size */
            localIdx = 0;
            if (GetSequence_ex(pkiMsg, &localIdx, &length, pkiMsgSz,
                                        NO_USER_CHECK) < 0) {
                break;
            }
            if (ret == 0 && length > 0)
                pkcs7->stream->maxLen = (word32)length + localIdx;
            else
                pkcs7->stream->maxLen = inSz;

        #endif

            /* determine total message size */
            totalSz = pkiMsgSz;
            if (pkiMsg2 && pkiMsg2Sz > 0) {
                totalSz += pkiMsg2Sz + pkcs7->contentSz;
            }

            /* Get the contentInfo sequence */
            if (ret == 0 && GetSequence_ex(pkiMsg, &idx, &length, totalSz,
                        NO_USER_CHECK) < 0)
                ret = ASN_PARSE_E;

            if (ret == 0 && length == 0 && pkiMsg[idx-1] == ASN_INDEF_LENGTH) {

    #if defined(NO_PKCS7_STREAM)
        #ifdef ASN_BER_TO_DER
                word32 len = 0;

                ret = wc_BerToDer(pkiMsg, pkiMsgSz, NULL, &len);
                if (ret != WC_NO_ERR_TRACE(LENGTH_ONLY_E))
                    return ret;
                pkcs7->der = (byte*)XMALLOC(len, pkcs7->heap,
                                                        DYNAMIC_TYPE_PKCS7);
                if (pkcs7->der == NULL)
                    return MEMORY_E;
                ret = wc_BerToDer(pkiMsg, pkiMsgSz, pkcs7->der, &len);
                if (ret < 0)
                    return ret;

                pkiMsg   = in = pkcs7->der;
                inSz = pkcs7->derSz = len;
                idx = 0;
            #ifdef NO_PKCS7_STREAM
                pkiMsgSz = len;
            #else
                wc_PKCS7_ResetStream(pkcs7);
                if ((ret = wc_PKCS7_AddDataToStream(pkcs7, in, inSz,
                                MAX_SEQ_SZ + MAX_VERSION_SZ + MAX_SEQ_SZ +
                                MAX_LENGTH_SZ + ASN_TAG_SZ + MAX_OID_SZ +
                                MAX_SEQ_SZ, &pkiMsg, &idx)) != 0) {
                    break;
                }

                pkiMsgSz = (pkcs7->stream->length > 0)? pkcs7->stream->length:
                                                        inSz;

                totalSz = pkiMsgSz;
                if (pkiMsg2 && pkiMsg2Sz > 0) {
                    totalSz += pkiMsg2Sz + pkcs7->contentSz;
                }

                if ((ret = wc_PKCS7_SetMaxStream(pkcs7, in, len)) != 0) {
                    break;
                }
            #endif
                if (GetSequence_ex(pkiMsg, &idx, &length, pkiMsgSz,
                            NO_USER_CHECK) < 0)
                    return ASN_PARSE_E;
        #else
                ret = BER_INDEF_E;
        #endif
    #else
                /* the bundle has indefinite length encoding */
                pkcs7->stream->indefLen = 1;

    #endif /* NO_PKCS7_STREAM */
            }

            /* Get the contentInfo contentType */
            if (ret == 0 && wc_GetContentType(pkiMsg, &idx, &outerContentType,
                        pkiMsgSz) < 0)
                ret = ASN_PARSE_E;

            if (ret == 0 && outerContentType != SIGNED_DATA) {
                WOLFSSL_MSG("PKCS#7 input not of type SignedData");
                ret = PKCS7_OID_E;
            }

            /* get the ContentInfo content */
            if (ret == 0 && GetASNTag(pkiMsg, &idx, &tag, totalSz) != 0)
                ret = ASN_PARSE_E;

            if (ret == 0 && tag != (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 0))
                ret = ASN_PARSE_E;

            if (ret == 0 && GetLength_ex(pkiMsg, &idx, &length, totalSz,
                        NO_USER_CHECK) < 0)
                ret = ASN_PARSE_E;

            /* Get the signedData sequence */
            if (ret == 0 && GetSequence_ex(pkiMsg, &idx, &length, totalSz,
                        NO_USER_CHECK) < 0)
                ret = ASN_PARSE_E;

            /* Get the version */
            if (ret == 0 && GetMyVersion(pkiMsg, &idx, &version, pkiMsgSz) < 0)
                ret = ASN_PARSE_E;


            /* version 1 follows RFC 2315 */
            /* version 3 follows RFC 4108 */
            if (ret == 0 && (version != 1 && version != 3)) {
                WOLFSSL_MSG("PKCS#7 signedData needs to be version 1 or 3");
                ret = ASN_VERSION_E;
            }
            pkcs7->version = (byte)version;

            /* Get the set of DigestAlgorithmIdentifiers */
            if (ret == 0 && GetSet(pkiMsg, &idx, &length, pkiMsgSz) < 0)
                ret = ASN_PARSE_E;

            localIdx = idx;

        #ifndef NO_PKCS7_STREAM
            /* initialize hashType*/
            pkcs7->stream->hashType = WC_HASH_TYPE_NONE;

            /* Get the first DigestAlgorithmIdentifier from the SET */
            if (ret == 0 && length > 0) {
                if (GetAlgoId(pkiMsg, &idx, &hashOID, oidHashType, pkiMsgSz)
                                                                          < 0)
                    ret = ASN_PARSE_E;

                pkcs7->hashOID = (int)hashOID;
                /* get hash type */
                hashType = wc_OidGetHash(pkcs7->hashOID);

                if (hashType == WC_HASH_TYPE_NONE) {
                    WOLFSSL_MSG("Error getting hash type for PKCS7 content"
                                                            " verification");
                    ret = ASN_PARSE_E;
                }
                if (wc_HashGetDigestSize(hashType) < 0) {
                    WOLFSSL_MSG("Error getting digest size");
                    ret = ASN_PARSE_E;
                }
                /* store hashType for later hashing */
                pkcs7->stream->hashType = (int)hashType;

                /* restore idx */
                idx = localIdx;

                WOLFSSL_MSG("DigestAlgorithmIdentifier found in bundle");
            }
        #endif /* !NO_PKCS7_STREAM */

            /* Skip the set. */
            idx += (word32)length;
            degenerate = (length == 0) ? 1 : 0;
        #ifndef NO_PKCS7_STREAM
            pkcs7->stream->degenerate = (degenerate != 0);
        #endif /* !NO_PKCS7_STREAM */
            if (pkcs7->noDegenerate == 1 && degenerate != 0) {
                ret = PKCS7_NO_SIGNER_E;
            }

            if (ret != 0)
                break;

        #ifndef NO_PKCS7_STREAM
            if ((ret = wc_PKCS7_StreamEndCase(pkcs7, &stateIdx, &idx)) != 0) {
                break;
            }
            if (pkiMsg2 && pkiMsg2Sz > 0) {
                pkcs7->stream->maxLen += pkiMsg2Sz + pkcs7->contentSz;
            }
            wc_PKCS7_StreamStoreVar(pkcs7, totalSz, 0, 0);

        #endif

            wc_PKCS7_ChangeState(pkcs7, WC_PKCS7_VERIFY_STAGE2);

        #ifndef NO_PKCS7_STREAM
            pkcs7->stream->expected = MAX_SEQ_SZ + MAX_OID_SZ + ASN_TAG_SZ +
                                    MAX_LENGTH_SZ + ASN_TAG_SZ + MAX_LENGTH_SZ;
        #endif /* !NO_PKCS7_STREAM */
            FALL_THROUGH;

        case WC_PKCS7_VERIFY_STAGE2:
        #ifndef NO_PKCS7_STREAM
            if ((ret = wc_PKCS7_AddDataToStream(pkcs7, in, inSz + in2Sz,
                           pkcs7->stream->expected, &pkiMsg, &idx)) != 0) {
                break;
            }
            degenerate = pkcs7->stream->degenerate;

            wc_PKCS7_StreamGetVar(pkcs7, &totalSz, 0, 0);
            if (pkcs7->stream->length > 0)
                pkiMsgSz = pkcs7->stream->length;
        #ifdef ASN_BER_TO_DER
            else if (pkcs7->der)
                pkiMsgSz = pkcs7->derSz;
        #endif
            else
                pkiMsgSz = inSz;

        #endif
            /* Get the inner ContentInfo sequence */
            if (GetSequence_ex(pkiMsg, &idx, &encapContentInfoLen, pkiMsgSz,
                        NO_USER_CHECK) < 0)
                ret = ASN_PARSE_E;

            /* Get the inner ContentInfo contentType */
            if (ret == 0) {
                int isIndef = 0;
                word32 tmpIdx = idx;
                if (encapContentInfoLen == 0 &&
                    pkiMsg[idx-1] == ASN_INDEF_LENGTH) {
                    isIndef = 1;
            #ifndef NO_PKCS7_STREAM
                    /* count up indef-length count  */
                    pkcs7->stream->cntIdfCnt++;
            #endif
                }
                if (GetASNObjectId(pkiMsg, &idx, &length, pkiMsgSz) == 0) {
                    contentType = pkiMsg + tmpIdx;
                    contentTypeSz = (word32)length + (idx - tmpIdx);
                    idx += (word32)length;
                }
                else {
                    ret = ASN_PARSE_E;
                }
                /* if indef, skip EOF */
                if (isIndef) {
                    if (idx + 1 >= pkiMsgSz) {
                        ret = ASN_PARSE_E;
                    }
                    else if (pkiMsg[idx] == ASN_EOC && pkiMsg[idx+1] == 0) {
                        idx += 2; /* skip EOF + zero byte */
            #ifndef NO_PKCS7_STREAM
                        pkcs7->stream->cntIdfCnt--;
            #endif
                    }
                }
            }

            if (ret != 0)
                break;

            /* Check for content, it could be omitted when degenerate */
            localIdx = idx;
            ret = 0;
            if (localIdx + 1 > pkiMsgSz) {
                ret = BUFFER_E;
                break;
            }

            /* Set error state if no more data left in ContentInfo, meaning
             * no content - may be detached. Will recover from error below */
            if ((encapContentInfoLen != 0) &&
                ((word32)encapContentInfoLen - contentTypeSz == 0)) {
                ret = ASN_PARSE_E;
            #ifndef NO_PKCS7_STREAM
                pkcs7->stream->noContent = 1;
            #endif
            }

            /* PKCS#7 spec:
             *     content [0] EXPLICIT ANY DEFINED BY contentType OPTIONAL
             * CMS spec:
             *     eContent [0] EXPLICIT OCTET STRING OPTIONAL
             */
            if (ret == 0 && GetASNTag(pkiMsg, &localIdx, &tag, pkiMsgSz) != 0)
                ret = ASN_PARSE_E;

            if (ret == 0 && tag != (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 0))
                ret = ASN_PARSE_E;

            /* Get length of inner eContent payload. For CMS, spec defines
             * OCTET_STRING will be next. If so, we use the length retrieved
             * there. PKCS#7 spec defines ANY as eContent type. In this case
             * we fall back and save this content length for use later */
            if (ret == 0 && pkiMsg[localIdx] != ASN_INDEF_LENGTH) {
                if (GetLength_ex(pkiMsg, &localIdx, &length, pkiMsgSz,
                        NO_USER_CHECK) <= 0) {
                    ret = ASN_PARSE_E;
                }

                if (localIdx >= pkiMsgSz) {
                    ret = BUFFER_E;
                }
            }
            else if (ret == 0 && pkiMsg[localIdx] == ASN_INDEF_LENGTH) {
        #ifndef NO_PKCS7_STREAM
                pkcs7->stream->cntIdfCnt++;    /* count up indef-length count */
        #endif
                length = 0;
                localIdx++;
            }
            else {
                length = 0;
                localIdx++;
            }

            /* Save idx to back up in case of PKCS#7 eContent */
            start = localIdx;

            /* get length of content in the case that there is multiple parts */
            if (ret == 0 && GetASNTag(pkiMsg, &localIdx, &tag, pkiMsgSz) < 0)
                ret = ASN_PARSE_E;

            if (ret == 0 &&
                (tag != (ASN_OCTET_STRING | ASN_CONSTRUCTED) &&
                (tag != ASN_OCTET_STRING))) {

                /* If reached end of ContentInfo, or we see the next element
                 * ([0] IMPLICIT CertificateSet), set error state. Either
                 * true error or detached */
                if (tag == (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 0)) {
                    ret = ASN_PARSE_E;
                }

                /* Back up before getting tag, process as PKCS#7 ANY and use
                 * this as start of content. */
                localIdx = start;
                pkcs7->contentIsPkcs7Type = 1;
            }
            else {
                /* CMS eContent OCTET_STRING */
                if (ret == 0 && tag == (ASN_OCTET_STRING | ASN_CONSTRUCTED)) {
                    multiPart = 1;

                    /* Get length of all OCTET_STRINGs. */
                    if (GetLength_ex(pkiMsg, &localIdx, &contentLen, pkiMsgSz,
                                NO_USER_CHECK) < 0)
                        ret = ASN_PARSE_E;
                #ifndef NO_PKCS7_STREAM
                    if (ret == 0 && pkiMsg[localIdx - 1] == ASN_INDEF_LENGTH) {
                        pkcs7->stream->cntIdfCnt++;  /* indef-length count  */
                    }
                #endif
                    /* Check whether there is one OCTET_STRING inside. */
                    start = localIdx;
                    if (localIdx >= pkiMsgSz) {
                        ret = BUFFER_E;
                    }

                    if (ret == 0 && GetASNTag(pkiMsg, &localIdx, &tag, pkiMsgSz)
                            != 0)
                        ret = ASN_PARSE_E;

                    if (ret == 0 && tag != ASN_OCTET_STRING)
                        ret = ASN_PARSE_E;

                    if (ret == 0 && GetLength_ex(pkiMsg, &localIdx, &length,
                                pkiMsgSz, NO_USER_CHECK) < 0)
                        ret = ASN_PARSE_E;

                    if (ret == 0) {
                        /* Use single OCTET_STRING directly, or reset length. */
                        if (localIdx - start + (word32)length ==
                                                           (word32)contentLen) {
                            multiPart = 0;
                        } else {
                        #ifndef NO_PKCS7_STREAM
                            pkcs7->stream->multi         = (multiPart != 0);
                            pkcs7->stream->currContIdx   = localIdx;
                            pkcs7->stream->currContSz    = (word32)length;
                            pkcs7->stream->currContRmnSz = (word32)length;
                        #endif
                            /* reset length to outer OCTET_STRING for bundle
                             * size check below */
                            length = contentLen;
                        }
                        localIdx = start;
                    }

                    if (ret != 0) {
                        /* failed ASN1 parsing during OCTET_STRING checks */
                        break;
                    }
                }

                /* get length of content in case of single part */
                if (ret == 0 && !multiPart) {
                    if (tag != ASN_OCTET_STRING)
                        ret = ASN_PARSE_E;

                    if (ret == 0 && GetLength_ex(pkiMsg, &localIdx,
                                &length, pkiMsgSz, NO_USER_CHECK) < 0)
                        ret = ASN_PARSE_E;
                #ifndef NO_PKCS7_STREAM
                    if (ret == 0) {
                        pkcs7->stream->multi         = (multiPart != 0);
                        pkcs7->stream->currContIdx   = localIdx;
                        pkcs7->stream->currContSz    = (word32)length;
                        pkcs7->stream->currContRmnSz = (word32)length;
                    }
                #endif
                }
            }

            /* update idx if successful */
            if (ret == 0) {
                /* support using header and footer without content */
                if (pkiMsg2 && pkiMsg2Sz > 0 && hashBuf && hashSz > 0) {
                    localIdx = 0;
            #ifndef NO_PKCS7_STREAM
                    pkcs7->stream->noContent = 1;
            #endif

                }
                idx = localIdx;
            }
            else {

                /* If either pkcs7->content and pkcs7->contentSz are set
                 * (detached signature where user has set content explicitly
                 * into pkcs7->content/contentSz) OR pkcs7->hashBuf and
                 * pkcs7->hashSz are set (user has pre-computed content
                 * digest and passed in instead of content directly), try to
                 * process as a detached signature */
                if (!degenerate &&
                    ((pkcs7->content != NULL && pkcs7->contentSz != 0) ||
                     (hashBuf != NULL && hashSz > 0)) ) {
                    WOLFSSL_MSG("Trying to process as detached signature");
                    detached = 1;
                }

                if (!degenerate && !detached && ret != 0)
                    break;

                /* no content to read */
                length = 0;
                contentLen = 0;

                pkiMsg2   = pkiMsg;
                pkiMsg2Sz = pkiMsgSz;

                /* reset ret */
                ret = 0;
            }

        #ifndef NO_PKCS7_STREAM
            /* save detached flag value */
            pkcs7->stream->detached = (detached != 0);

            /* save contentType */
            pkcs7->stream->nonce = (byte*)XMALLOC(contentTypeSz, pkcs7->heap,
                    DYNAMIC_TYPE_PKCS7);
            if (pkcs7->stream->nonce == NULL) {
                ret = MEMORY_E;
                break;
            }
            else {
                pkcs7->stream->nonceSz = contentTypeSz;
                XMEMCPY(pkcs7->stream->nonce, contentType, contentTypeSz);
            }
            if (ret < 0)
                break;

            if (pkcs7->stream->noContent) {
                pkcs7->stream->expected = 0;
            }
            else {
                if (multiPart) {
                    idx = pkcs7->stream->currContIdx;
                }
                if (in2Sz > 0 && hashSz > 0) {
                    /* seems no content included */
                    pkcs7->stream->expected = + ASN_TAG_SZ + MAX_LENGTH_SZ;
                }
                else {
                    pkcs7->stream->expected = pkcs7->stream->currContSz;
                }
            }

            if ((ret = wc_PKCS7_StreamEndCase(pkcs7, &stateIdx, &idx)) != 0) {
                break;
            }
            wc_PKCS7_StreamStoreVar(pkcs7, pkiMsg2Sz, (int)localIdx, length);


        #endif /* !NO_PKCS7_STREAM */

            wc_PKCS7_ChangeState(pkcs7, WC_PKCS7_VERIFY_STAGE3);

        #ifndef NO_PKCS7_STREAM
        /* free pkcs7->stream->content buffer */
        XFREE(pkcs7->stream->content, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        pkcs7->stream->content = NULL;
        #endif /* !NO_PKCS7_STREAM */

            FALL_THROUGH;

        case WC_PKCS7_VERIFY_STAGE3:
            keepContent = !(pkiMsg2 && pkiMsg2Sz > 0 && hashBuf && hashSz > 0);
        #ifndef NO_PKCS7_STREAM
            ret = wc_PKCS7_HandleOctetStrings(pkcs7, in, inSz,
                                                &stateIdx, &idx, keepContent);
            if (ret != 0)
                break;

            /* copy content to pkcs7->contentDynamic */
            if (keepContent && pkcs7->stream->content &&
                                            pkcs7->stream->contentSz >0) {
                pkcs7->contentDynamic = (byte*)XMALLOC(pkcs7->stream->contentSz,
                                              pkcs7->heap, DYNAMIC_TYPE_PKCS7);
                if (pkcs7->contentDynamic == NULL) {
                    ret = MEMORY_E;
                    break;
                }
                XMEMCPY(pkcs7->contentDynamic, pkcs7->stream->content,
                                               pkcs7->stream->contentSz);

                pkcs7->contentSz = pkcs7->stream->contentSz;
                pkcs7->content   = pkcs7->contentDynamic;
            }

            /* check if bundle has more elements or footer, if not, set content
             * to pkcs7->content and hash to pkcs7->hash.
             */
            if (ret == 0 && pkcs7->stream->maxLen > 0 &&
                    (pkcs7->stream->maxLen - pkcs7->stream->totalRd)
                                                < ASN_TAG_SZ + MAX_LENGTH_SZ) {

                ret = 0;
                break;
            }
            /* expect data length to be enough to check set and seq of certs */
            pkcs7->stream->expected = (ASN_TAG_SZ + MAX_LENGTH_SZ) * 2;

        #else
            /* Break out before content because it can be optional in degenerate
             * cases. */
            if (ret != 0 && !degenerate)
                break;

            /* get parts of content */
            if (ret == 0 && multiPart) {
                int i = 0;
                keepContent = !(pkiMsg2 && pkiMsg2Sz > 0 && hashBuf &&
                                                                hashSz > 0);

                if (keepContent) {
                    /* Create a buffer to hold content of OCTET_STRINGs. */
                    pkcs7->contentDynamic = (byte*)XMALLOC(contentLen,
                                            pkcs7->heap, DYNAMIC_TYPE_PKCS7);
                    if (pkcs7->contentDynamic == NULL)
                        ret = MEMORY_E;
                }

                start = localIdx;
                /* Use the data from each OCTET_STRING. */
                while (ret == 0 && localIdx < start + contentLen) {
                    if (GetASNTag(pkiMsg, &localIdx, &tag, totalSz) < 0)
                        ret = ASN_PARSE_E;
                    if (ret == 0 && tag != ASN_OCTET_STRING)
                        ret = ASN_PARSE_E;

                    if (ret == 0 && GetLength(pkiMsg, &localIdx, &length,
                                                                totalSz) < 0)
                        ret = ASN_PARSE_E;
                    if (ret == 0 && length + localIdx > start + contentLen)
                        ret = ASN_PARSE_E;

                    if (ret == 0) {
                        if (keepContent) {
                            XMEMCPY(pkcs7->contentDynamic + i,
                                                    pkiMsg + localIdx, length);
                        }
                        i += length;
                        localIdx += length;
                    }
                }
                localIdx = start; /* reset for sanity check, increment later */
                length = i;
            }

            /* Save the inner data as the content. */
            if (ret == 0 && length > 0) {
                contentSz = length;

                /* support using header and footer without content */
                if (pkiMsg2 && pkiMsg2Sz > 0 && hashBuf && hashSz > 0) {
                    /* Content not provided, use provided pkiMsg2 footer */
                    content = NULL;
                    localIdx = 0;
                    if (contentSz != (int)pkcs7->contentSz) {
                        WOLFSSL_MSG("Data signed does not match contentSz"
                                                                " provided");
                        ret = BUFFER_E;
                    }
                }
                else {
                    if ((word32)length > pkiMsgSz - localIdx) {
                        ret = BUFFER_E;
                    }

                    /* Content pointer for calculating hashes later */
                    if (ret == 0 && !multiPart) {
                        content = &pkiMsg[localIdx];
                    }
                    if (ret == 0 && multiPart) {
                        content = pkcs7->contentDynamic;
                    }

                    if (ret == 0) {
                        idx += length;
                    }

                    pkiMsg2   = pkiMsg;
                    pkiMsg2Sz = pkiMsgSz;
                }
            }
            else {
                pkiMsg2 = pkiMsg;
                pkiMsg2Sz = pkiMsgSz;
            }

            /* If getting the content info failed with non degenerate then
             * return the error case. Otherwise with a degenerate it is ok
             * if the content info was omitted */
            if (!degenerate && !detached && (ret != 0)) {
                break;
            }
            else {
                ret = 0; /* reset ret state on degenerate case */
            }

            /* save content */
            if (detached == 1) {
                /* if detached, use content from user in pkcs7 struct */
                content = pkcs7->content;
                contentSz = pkcs7->contentSz;
            }
        #endif /* !NO_PKCS7_STREAM */
            wc_PKCS7_ChangeState(pkcs7, WC_PKCS7_VERIFY_STAGE4);

            FALL_THROUGH;

       case WC_PKCS7_VERIFY_STAGE4:
        #ifndef NO_PKCS7_STREAM
            if (in2 && in2Sz > 0) {
                src     = in2;
                srcSz   = in2Sz;
                pkiMsg2 = in2;
            }
            else {
                src     = in;
                srcSz   = inSz;
                pkiMsg2 = in;
            }
            if ((ret = wc_PKCS7_AddDataToStream(pkcs7, src, srcSz,
                            pkcs7->stream->expected, &pkiMsg2, &idx)) != 0) {
                break;
            }

        #ifdef ASN_BER_TO_DER
            if (pkcs7->derSz != 0)
                pkiMsg2Sz = pkcs7->derSz;
            else
        #endif
                pkiMsg2Sz = (pkcs7->stream->length > 0)? pkcs7->stream->length:
                    srcSz;

            if (pkcs7->stream->length > 0) {
                localIdx = 0;
            }

            maxIdx = idx + pkcs7->stream->expected;
        #endif /* !NO_PKCS7_STREAM */

            if (pkiMsg2 == NULL || pkiMsg2Sz == 0) {
                pkiMsg2Sz = pkiMsgSz;
                pkiMsg2   = pkiMsg;
            }

            /* Certificates begin "footer" section (ie pkiMsg2) if being used */
            /* Get the implicit[0] set of certificates */
            if (ret == 0 && idx >= pkiMsg2Sz)
                ret = BUFFER_E;

            length = 0; /* set length to 0 to check if reading in any certs */
            localIdx = idx;

            if (ret == 0 && GetASNTag(pkiMsg2, &localIdx, &tag, pkiMsg2Sz) == 0
                    && tag == (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 0)) {
                idx++;

                /* if certificates set has indefinite length, try to get
                 * the first certificate length of the set.
                 */
                if (ret == 0 && pkiMsg2[localIdx] == ASN_INDEF_LENGTH) {

                    localIdx++;
                    certIdx = localIdx;
                #ifndef NO_PKCS7_STREAM
                /* set indef-length count. used for skipping trailing zeros */
                    pkcs7->stream->cntIdfCnt = 1;
                #endif
                    ret = GetASNTag(pkiMsg2, &localIdx, &tag, pkiMsg2Sz);
                    if (ret == 0 && tag == (ASN_CONSTRUCTED | ASN_SEQUENCE)) {
                        if (GetLength_ex(pkiMsg2, &localIdx, &length, maxIdx,
                                                NO_USER_CHECK) < 0)
                    ret = ASN_PARSE_E;

                        WOLFSSL_MSG("certificate set found");

                        /* adjust cert length */
                        length += (int)(localIdx - certIdx);
                        idx = certIdx;
                    }
                }
                /* in case certificates set has definite length  */
                else {

                    if (GetLength_ex(pkiMsg2, &localIdx, &length, maxIdx,
                                                NO_USER_CHECK) < 0)
                        ret = ASN_PARSE_E;

                    idx = localIdx;
                }
            }

            if (ret != 0) {
                break;
            }
        #ifndef NO_PKCS7_STREAM
            if (in2 && in2Sz > 0 && hashBuf && hashSz > 0) {
                stateIdx = idx; /* case where all data was read from in2 */
            }

            if ((ret = wc_PKCS7_StreamEndCase(pkcs7, &stateIdx, &idx)) != 0) {
                break;
            }
            wc_PKCS7_StreamStoreVar(pkcs7, pkiMsg2Sz, 0, length);
            if (length > 0) {
                pkcs7->stream->expected = (word32)length;
            }
            else {
                pkcs7->stream->expected = MAX_SEQ_SZ;
                if (pkcs7->stream->expected > (pkcs7->stream->maxLen -
                            pkcs7->stream->totalRd) + pkcs7->stream->length) {
                    pkcs7->stream->expected = (pkcs7->stream->maxLen -
                                pkcs7->stream->totalRd) + pkcs7->stream->length;
                }
            }
        #endif
            wc_PKCS7_ChangeState(pkcs7, WC_PKCS7_VERIFY_STAGE5);
            FALL_THROUGH;

        case WC_PKCS7_VERIFY_STAGE5:
        #ifndef NO_PKCS7_STREAM
            if (in2 && in2Sz > 0) {
                src     = in2;
                srcSz   = in2Sz;
                pkiMsg2 = in2;
            }
            else {
                src     = in;
                srcSz   = inSz;
                pkiMsg2 = in;
            }

            if ((ret = wc_PKCS7_AddDataToStream(pkcs7, src, srcSz,
                            pkcs7->stream->expected, &pkiMsg2, &idx)) != 0) {
                break;
            }
            pkiMsg2Sz = (pkcs7->stream->length > 0)? pkcs7->stream->length:
                                                                        srcSz;

            wc_PKCS7_StreamGetVar(pkcs7, &pkiMsg2Sz, 0, &length);

            /* restore content */
            content   = pkcs7->stream->content;
            contentSz = (int)pkcs7->stream->contentSz;

            /* restore detached flag */
            detached = pkcs7->stream->detached;

            /* store current index to get the signerInfo index later  */
            certIdx2 = idx;

            /* store certificate if needed */
            if (length > 0 && in2Sz == 0) {
                /* free tmpCert if not NULL */
                XFREE(pkcs7->stream->tmpCert, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
                pkcs7->stream->tmpCert = (byte*)XMALLOC((word32)length,
                        pkcs7->heap, DYNAMIC_TYPE_PKCS7);
                if ((pkiMsg2 == NULL) || (pkcs7->stream->tmpCert == NULL)) {
                    ret = MEMORY_E;
                    break;
                }
                XMEMCPY(pkcs7->stream->tmpCert, pkiMsg2 + idx, (word32)length);
                pkiMsg2 = pkcs7->stream->tmpCert;
                pkiMsg2Sz = (word32)length;
                idx = 0;
            }
        #else
            /* store current index to get the signerInfo index later  */
            certIdx2 = idx;
        #endif

                if (length > 0) {
                    /* At this point, idx is at the first certificate in
                     * a set of certificates. There may be more than one,
                     * or none, or they may be a PKCS 6 extended
                     * certificate. We want to save the first cert if it
                     * is X.509. */

                    certIdx = idx;

                    if (length < MAX_LENGTH_SZ + ASN_TAG_SZ)
                        ret = BUFFER_E;

                    if (ret == 0)
                        ret = GetASNTag(pkiMsg2, &certIdx, &tag, pkiMsg2Sz);

                    if (ret == 0 && tag == (ASN_CONSTRUCTED | ASN_SEQUENCE)) {
                        if (GetLength_ex(pkiMsg2, &certIdx, &certSz, pkiMsg2Sz,
                                                        NO_USER_CHECK) < 0)
                            ret = ASN_PARSE_E;

                        cert = &pkiMsg2[idx];
                        certSz += (int)(certIdx - idx);
                        if (certSz > length) {
                            ret = BUFFER_E;
                            break;
                        }
                    }
        #ifdef ASN_BER_TO_DER
                    der = pkcs7->der;
                    pkcs7->der = NULL;
        #endif
                    version = pkcs7->version;
                    contentIsPkcs7Type = pkcs7->contentIsPkcs7Type;

                    if (ret == 0) {
                        byte isDynamic = (byte)pkcs7->isDynamic;
                    #ifndef NO_PKCS7_STREAM
                        PKCS7State* stream = pkcs7->stream;
                        pkcs7->stream = NULL;
                    #endif

                        /* Save dynamic content before freeing PKCS7 struct */
                        if (pkcs7->contentDynamic != NULL) {
                            contentDynamic = (byte*)XMALLOC((word32)contentSz,
                                               pkcs7->heap, DYNAMIC_TYPE_PKCS7);
                            if (contentDynamic == NULL) {
                            #ifndef NO_PKCS7_STREAM
                                pkcs7->stream = stream;
                            #endif
                                ret = MEMORY_E;
                                break;
                            }
                            XMEMCPY(contentDynamic, pkcs7->contentDynamic,
                                    (word32)contentSz);
                        }

                        /* Free pkcs7 resources but not the structure itself */
                        pkcs7->isDynamic = 0;
                        wc_PKCS7_Free(pkcs7);
                        pkcs7->isDynamic = (isDynamic != 0);
                        /* This will reset PKCS7 structure and then set the
                         * certificate */
                        ret = wc_PKCS7_InitWithCert(pkcs7, cert, (word32)certSz);

                        /* Restore pkcs7->contentDynamic from above, will be
                         * freed by application with wc_PKCS7_Free() */
                        if (contentDynamic != NULL) {
                            pkcs7->contentDynamic = contentDynamic;
                            contentDynamic = NULL;
                        }

                        /* Restore content is PKCS#7 flag */
                        pkcs7->contentIsPkcs7Type = (contentIsPkcs7Type != 0);

                    #ifndef NO_PKCS7_STREAM
                        pkcs7->stream = stream;
                    #endif
                    }
                    pkcs7->version = (byte)version;
        #ifdef ASN_BER_TO_DER
                    pkcs7->der = der;
        #endif
                    if (ret != 0)
                        break;

                    /* iterate through any additional certificates */
                    if (ret == 0 && MAX_PKCS7_CERTS > 0) {
                        int sz = 0;
                        int i;

                        pkcs7->cert[0]   = cert;
                        pkcs7->certSz[0] = (word32)certSz;
                        certIdx = idx + (word32)certSz;

                        for (i = 1; i < MAX_PKCS7_CERTS &&
                                certIdx + 1 < pkiMsg2Sz &&
                                certIdx + 1 < (word32)length; i++) {
                            localIdx = certIdx;

                            if (ret == 0 && GetASNTag(pkiMsg2, &certIdx, &tag,
                                        pkiMsg2Sz) < 0) {
                                ret = ASN_PARSE_E;
                                break;
                            }

                            if (ret == 0 &&
                                    tag == (ASN_CONSTRUCTED | ASN_SEQUENCE)) {
                                if (GetLength(pkiMsg2, &certIdx, &sz,
                                            pkiMsg2Sz) < 0) {
                                    ret = ASN_PARSE_E;
                                    break;
                                }

                                pkcs7->cert[i]   = &pkiMsg2[localIdx];
                                pkcs7->certSz[i] = (word32)sz +
                                                   (certIdx - localIdx);
                                certIdx += (word32)sz;
                            }
                        }
                    }
                }
                idx += (word32)length;

            if (!detached) {
                /* set content and size after init of PKCS7 structure */
                pkcs7->content   = content;
                pkcs7->contentSz = (word32)contentSz;
            }

            idx = certIdx2 + (word32)length;

            if (ret != 0) {
                break;
            }
        #ifndef NO_PKCS7_STREAM
            /* factor in that recent idx was in cert buffer. If in2 buffer was
             * used then don't advance idx. */
            if (length > 0 && pkcs7->stream->flagOne &&
                    pkcs7->stream->length == 0) {
                idx = stateIdx + idx;
                if (idx > inSz) {
                    /* index is more than input size */
                    ret = BUFFER_E;
                    break;
                }
            }
            if ((ret = wc_PKCS7_StreamEndCase(pkcs7, &stateIdx, &idx)) != 0) {
                break;
            }

            pkcs7->stream->expected = MAX_OID_SZ + ASN_TAG_SZ + MAX_LENGTH_SZ +
                                      MAX_SET_SZ;
            /* if certificate set has indef-length, there maybe trailing zeros.
             * add expected size to include size of zeros. */
            if (pkcs7->stream->cntIdfCnt > 0) {
                pkcs7->stream->expected += (word32)pkcs7->stream->cntIdfCnt * 2;
            }

            if (pkcs7->stream->expected > (pkcs7->stream->maxLen -
                                pkcs7->stream->totalRd) + pkcs7->stream->length)
                pkcs7->stream->expected = (pkcs7->stream->maxLen -
                                pkcs7->stream->totalRd) + pkcs7->stream->length;

            wc_PKCS7_StreamGetVar(pkcs7, &pkiMsg2Sz,  0, 0);
            wc_PKCS7_StreamStoreVar(pkcs7, pkiMsg2Sz, 0, length);
        #endif
            wc_PKCS7_ChangeState(pkcs7, WC_PKCS7_VERIFY_STAGE6);
            FALL_THROUGH;

        case WC_PKCS7_VERIFY_STAGE6:
        #ifndef NO_PKCS7_STREAM

            if (in2 && in2Sz > 0) {
                src     = in2;
                srcSz   = in2Sz;
                pkiMsg2 = in2;
            }
            else {
                src     = in;
                srcSz   = inSz;
                pkiMsg2 = in;
            }
            if ((ret = wc_PKCS7_AddDataToStream(pkcs7, src, srcSz,
                            pkcs7->stream->expected, &pkiMsg2, &idx)) != 0) {
                break;
            }
            wc_PKCS7_StreamGetVar(pkcs7, &pkiMsg2Sz, 0, &length);

            /* check if using internal stream buffer and should adjust sz */
            pkiMsg2Sz = (pkcs7->stream->length > 0)? pkcs7->stream->length:
                                                                        srcSz;

            /* restore content type */
            contentType   = pkcs7->stream->nonce;
            contentTypeSz = pkcs7->stream->nonceSz;

            maxIdx = idx + pkcs7->stream->expected;
            if (maxIdx > pkiMsg2Sz) {
                ret = BUFFER_E;
                break;
            }
            stateIdx = idx;
        #else
            /* if not streaming, maxIdx is just pkiMsg2Sz */
            maxIdx = pkiMsg2Sz;
        #endif

            /* set contentType and size after init of PKCS7 structure */
            if (ret == 0 && wc_PKCS7_SetContentType(pkcs7, contentType,
                        contentTypeSz) < 0)
                ret = ASN_PARSE_E;
        #ifndef NO_PKCS7_STREAM
            /* prior to find set of crls, remove trailing zeros of
             * set of certificates */
            if (ret == 0 && pkcs7->stream->cntIdfCnt > 0) {
                word32 i;
                word32 sz = (word32)pkcs7->stream->cntIdfCnt * ASN_INDEF_END_SZ;
                localIdx = idx;
                for (i = 0; i < sz; i++) {
                    if (pkiMsg2[localIdx + i] == 0)
                        continue;
                    else {
                        ret = ASN_PARSE_E;
                        break;
                    }
                }
                if (ret == 0) {
                    idx += (word32)pkcs7->stream->cntIdfCnt * ASN_INDEF_END_SZ;
                    pkcs7->stream->cntIdfCnt = 0;
                }
            }
        #endif /* !NO_PKCS7_STREAM */
            /* Get the implicit[1] set of crls */
            if (ret == 0 && idx >= maxIdx)
                ret = BUFFER_E;

            localIdx = idx;
            if (ret == 0 && GetASNTag(pkiMsg2, &localIdx, &tag, pkiMsg2Sz) == 0
                    && tag == (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 1)) {
                idx++;
                if (GetLength(pkiMsg2, &idx, &length, pkiMsg2Sz) < 0)
                    ret = ASN_PARSE_E;

                /* Skip the set */
                idx += (word32)length;
            }

            /* Get the set of signerInfos */
            if (ret == 0 && GetSet_ex(pkiMsg2, &idx, &length, maxIdx,
                        NO_USER_CHECK) < 0)
                ret = ASN_PARSE_E;

            if (ret != 0)
                break;
        #ifndef NO_PKCS7_STREAM
            if (!pkcs7->stream->flagOne) {
                stateIdx = idx; /* didn't read any from internal buffer */
            }
            if ((ret = wc_PKCS7_StreamEndCase(pkcs7, &stateIdx, &idx)) != 0) {
                break;
            }
            wc_PKCS7_StreamStoreVar(pkcs7, pkiMsg2Sz, 0, length);

            if (in2 && in2Sz > 0 && hashBuf && hashSz > 0) {
                if (length > 0) {
                    pkcs7->stream->expected = (word32)length;
                }
                else {
                    pkcs7->stream->expected = 0;
                }
            }
            else {
                /* last state expect the rest of the buffer */
                pkcs7->stream->expected = (pkcs7->stream->maxLen -
                    pkcs7->stream->totalRd) + pkcs7->stream->length;
            }
            /* In case of indefinite length used in the bundle, terminating
             * zero's should exist at the end of the bundle.
             */
            if (pkcs7->stream->indefLen == 1) {
                pkcs7->stream->expected = (word32)length + 3 * ASN_INDEF_END_SZ;
            }
            else  {
                pkcs7->stream->expected = (word32)length;
            }

            wc_PKCS7_ChangeState(pkcs7, WC_PKCS7_VERIFY_STAGE7);
        #endif /* !NO_PKCS7_STREAM */
            FALL_THROUGH;

        case WC_PKCS7_VERIFY_STAGE7:
        #ifndef NO_PKCS7_STREAM
            if (in2 && in2Sz > 0) {
                src     = in2;
                srcSz   = in2Sz;
                pkiMsg2 = in2;
            }
            else {
                src     = in;
                srcSz   = inSz;
                pkiMsg2 = in;
            }
            if ((ret = wc_PKCS7_AddDataToStream(pkcs7, src, srcSz,
                            pkcs7->stream->expected, &pkiMsg2, &idx)) != 0) {
                break;
            }

            wc_PKCS7_StreamGetVar(pkcs7, &pkiMsg2Sz, 0, &length);
            pkiMsg2Sz = (pkcs7->stream->length > 0)? pkcs7->stream->length:
                                                                        srcSz;
            degenerate = pkcs7->stream->degenerate;

            /* restore content */
            content   = pkcs7->stream->content;
            contentSz = (int)pkcs7->stream->contentSz;
        #endif

            ret = wc_PKCS7_ParseSignerInfo(pkcs7, pkiMsg2, pkiMsg2Sz, &idx,
                    degenerate, &signedAttrib, &signedAttribSz);

            /* parse out the signature if present and verify it */
            if (ret == 0 && length > 0 && degenerate == 0) {
                WOLFSSL_MSG("Parsing signature and verifying");
                if (idx >= pkiMsg2Sz)
                    ret = BUFFER_E;

                /* Get the signature */
                localIdx = idx;
                if (ret == 0 && GetASNTag(pkiMsg2, &localIdx, &tag,
                            pkiMsg2Sz) == 0 && tag == ASN_OCTET_STRING) {
                    idx++;

                    if (GetLength(pkiMsg2, &idx, &length, pkiMsg2Sz) < 0)
                        ret = ASN_PARSE_E;

                    /* save pointer and length */
                    sig = &pkiMsg2[idx];
                    sigSz = length;

                    idx += (word32)length;
                }

                pkcs7->content = content;
                pkcs7->contentSz = (word32)contentSz;

                if (ret == 0) {
                    ret = wc_PKCS7_SignedDataVerifySignature(pkcs7, sig, (word32)sigSz,
                                                   signedAttrib, (word32)signedAttribSz,
                                                   hashBuf, hashSz);
                }
            }

        #ifndef NO_PKCS7_STREAM
            /* make sure that terminating zero's follow */
            if ((ret == WC_NO_ERR_TRACE(PKCS7_SIGNEEDS_CHECK) || ret >= 0) &&
                    pkcs7->stream->indefLen == 1) {
                word32 i;
                for (i = 0; i < 3 * ASN_INDEF_END_SZ; i++) {
                    if (pkiMsg2[idx + i] != 0) {
                        ret = ASN_PARSE_E;
                        break;
                    }
                }
            }
        #endif /* NO_PKCS7_STREAM */

            if (ret < 0)
                break;


            ret = 0; /* success */
        #ifndef NO_PKCS7_STREAM
            wc_PKCS7_ResetStream(pkcs7);
        #endif
            wc_PKCS7_ChangeState(pkcs7, WC_PKCS7_START);
            break;

        default:
            WOLFSSL_MSG("PKCS7 Unknown verify state");
            ret = BAD_FUNC_ARG;
    }

    if (ret != 0 && ret != WC_NO_ERR_TRACE(WC_PKCS7_WANT_READ_E)) {
    #ifndef NO_PKCS7_STREAM
        wc_PKCS7_ResetStream(pkcs7);
    #endif
        wc_PKCS7_ChangeState(pkcs7, WC_PKCS7_START);
    }
    return ret;
}


/* Gets a copy of the SID parsed from signerInfo. This can be called after
 * wc_PKCS7_VerifySignedData has been called. SID can be SKID in version 3 case
 * or issuerAndSerialNumber.
 *
 * return 0 on success and LENGTH_ONLY_E if just setting "outSz" for buffer
 *  length needed.
 */
int wc_PKCS7_GetSignerSID(wc_PKCS7* pkcs7, byte* out, word32* outSz)
{
    if (outSz == NULL || pkcs7 == NULL) {
        return BAD_FUNC_ARG;
    }

    if (pkcs7->signerInfo == NULL) {
        WOLFSSL_MSG("Either the bundle had no signers or"
                "wc_PKCS7_VerifySignedData needs called yet");
        return PKCS7_NO_SIGNER_E;
    }

    if (pkcs7->signerInfo->sidSz == 0) {
        WOLFSSL_MSG("Bundle had no signer SID set");
        return PKCS7_NO_SIGNER_E;
    }

    if (out == NULL) {
        *outSz = pkcs7->signerInfo->sidSz;
        return WC_NO_ERR_TRACE(LENGTH_ONLY_E);
    }

    if (*outSz < pkcs7->signerInfo->sidSz) {
        WOLFSSL_MSG("Buffer being passed in is not large enough for SKID");
        return BUFFER_E;
    }
    XMEMCPY(out, pkcs7->signerInfo->sid, pkcs7->signerInfo->sidSz);
    *outSz = pkcs7->signerInfo->sidSz;
    return 0;
}


/* SignedData verification function variant that allows pre-computed content
 * message digest and optional PKCS7/CMS bundle content header/footer to be
 * used for verification. Useful for large data signing.
 *
 * pkcs7 - pointer to initialized PKCS7 structure
 * hashBuf - message digest of content
 * hashSz - size of hashBuf, octets
 * pkiMsgHead - PKCS7/CMS header that goes on top of the raw data signed,
 *              as output from wc_PKCS7_EncodeSignedData_ex (if also using
 *              pkiMsgFoot). Otherwise, PKCS7/CMS bundle with
 *              detached signature - will use hashBuf/hashSz to verify.
 * pkiMsgHeadSz - size of pkiMsgHead, octets
 * pkiMsgFoot - PKCS7/CMS footer that goes at the end of the raw data signed,
 *              as output from wc_PKCS7_EncodeSignedData_ex. Can be NULL
 *              if pkiMsgHead is a direct detached signature bundle to be used
 *              with hashBuf/hashSz.
 * pkiMsgFootSz - size of pkiMsgFoot, octets. Should be 0 if pkiMsgFoot is NULL.
 *
 * Returns 0 on success, negative upon error.
 *
 */
int wc_PKCS7_VerifySignedData_ex(wc_PKCS7* pkcs7, const byte* hashBuf,
    word32 hashSz, byte* pkiMsgHead, word32 pkiMsgHeadSz, byte* pkiMsgFoot,
    word32 pkiMsgFootSz)
{
    return PKCS7_VerifySignedData(pkcs7, hashBuf, hashSz,
        pkiMsgHead, pkiMsgHeadSz, pkiMsgFoot, pkiMsgFootSz);
}

int wc_PKCS7_VerifySignedData(wc_PKCS7* pkcs7, byte* pkiMsg, word32 pkiMsgSz)
{
    return PKCS7_VerifySignedData(pkcs7, NULL, 0, pkiMsg, pkiMsgSz, NULL, 0);
}


/* Generate random content encryption key, store into pkcs7->cek and
 * pkcs7->cekSz.
 *
 * pkcs7 - pointer to initialized PKCS7 structure
 * len   - length of key to be generated
 *
 * Returns 0 on success, negative upon error */
static int PKCS7_GenerateContentEncryptionKey(wc_PKCS7* pkcs7, word32 len)
{
    int ret;
    WC_RNG rng;
    byte* tmpKey;

    if (pkcs7 == NULL || len == 0)
        return BAD_FUNC_ARG;

    /* if key already exists, don't need to re-generate */
    if (pkcs7->cek != NULL && pkcs7->cekSz != 0) {

        /* if key exists, but is different size, return error */
        if (pkcs7->cekSz != len) {
            WOLFSSL_MSG("Random content-encryption key size is inconsistent "
                        "between CMS recipients");
            return WC_KEY_SIZE_E;
        }

        return 0;
    }

    /* allocate space for cek */
    tmpKey = (byte*)XMALLOC(len, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
    if (tmpKey == NULL)
        return MEMORY_E;

    XMEMSET(tmpKey, 0, len);

    ret = wc_InitRng_ex(&rng, pkcs7->heap, pkcs7->devId);
    if (ret != 0) {
        XFREE(tmpKey, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return ret;
    }

    ret = wc_RNG_GenerateBlock(&rng, tmpKey, len);
    if (ret != 0) {
        wc_FreeRng(&rng);
        XFREE(tmpKey, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return ret;
    }

    /* store into PKCS7, memory freed during final cleanup */
    pkcs7->cek = tmpKey;
    pkcs7->cekSz = len;

    wc_FreeRng(&rng);

    return 0;
}


/* wrap CEK (content encryption key) with KEK, 0 on success, < 0 on error */
static int wc_PKCS7_KeyWrap(byte* cek, word32 cekSz, byte* kek,
                            word32 kekSz, byte* out, word32 outSz,
                            int keyWrapAlgo, int direction)
{
    int ret = 0;

    if (cek == NULL || kek == NULL || out == NULL)
        return BAD_FUNC_ARG;

    switch (keyWrapAlgo) {
#ifndef NO_AES
    #ifdef WOLFSSL_AES_128
        case AES128_WRAP:
    #endif
    #ifdef WOLFSSL_AES_192
        case AES192_WRAP:
    #endif
    #ifdef WOLFSSL_AES_256
        case AES256_WRAP:
    #endif

            if (direction == AES_ENCRYPTION) {

                ret = wc_AesKeyWrap(kek, kekSz, cek, cekSz,
                                    out, outSz, NULL);

            } else if (direction == AES_DECRYPTION) {

                ret = wc_AesKeyUnWrap(kek, kekSz, cek, cekSz,
                                      out, outSz, NULL);
            } else {
                WOLFSSL_MSG("Bad key un/wrap direction");
                return BAD_FUNC_ARG;
            }

            if (ret <= 0)
                return ret;
            break;
#endif /* NO_AES */

        default:
            WOLFSSL_MSG("Unsupported key wrap algorithm");
            return BAD_KEYWRAP_ALG_E;
    };

    (void)cekSz;
    (void)kekSz;
    (void)outSz;
    (void)direction;
    return ret;
}


#ifdef HAVE_ECC

/* KARI == KeyAgreeRecipientInfo (key agreement) */
typedef struct WC_PKCS7_KARI {
    DecodedCert* decoded;          /* decoded recip cert */
    void*    heap;                 /* user heap, points to PKCS7->heap */
    int      devId;                /* device ID for HW based private key */
    ecc_key* recipKey;             /* recip key  (pub | priv) */
    ecc_key* senderKey;            /* sender key (pub | priv) */
    byte*    senderKeyExport;      /* sender ephemeral key DER */
    byte*    kek;                  /* key encryption key */
    byte*    ukm;                  /* OPTIONAL user keying material */
    byte*    sharedInfo;           /* ECC-CMS-SharedInfo ASN.1 encoded blob */
    word32   senderKeyExportSz;    /* size of sender ephemeral key DER */
    word32   kekSz;                /* size of key encryption key */
    word32   ukmSz;                /* size of user keying material */
    word32   sharedInfoSz;         /* size of ECC-CMS-SharedInfo encoded */
    byte     ukmOwner;             /* do we own ukm buffer? 1:yes, 0:no */
    byte     direction;            /* WC_PKCS7_ENCODE | WC_PKCS7_DECODE */
    WC_BITFIELD decodedInit:1;     /* indicates decoded was initialized */
    WC_BITFIELD recipKeyInit:1;    /* indicates recipKey was initialized */
    WC_BITFIELD senderKeyInit:1;   /* indicates senderKey was initialized */
} WC_PKCS7_KARI;


/* allocate and create new WC_PKCS7_KARI struct,
 * returns struct pointer on success, NULL on failure */
static WC_PKCS7_KARI* wc_PKCS7_KariNew(wc_PKCS7* pkcs7, byte direction)
{
    WC_PKCS7_KARI* kari = NULL;

    if (pkcs7 == NULL)
        return NULL;

    kari = (WC_PKCS7_KARI*)XMALLOC(sizeof(WC_PKCS7_KARI), pkcs7->heap,
                                   DYNAMIC_TYPE_PKCS7);
    if (kari == NULL) {
        WOLFSSL_MSG("Failed to allocate WC_PKCS7_KARI");
        return NULL;
    }

    kari->decoded = (DecodedCert*)XMALLOC(sizeof(DecodedCert), pkcs7->heap,
                                          DYNAMIC_TYPE_PKCS7);
    if (kari->decoded == NULL) {
        WOLFSSL_MSG("Failed to allocate DecodedCert");
        XFREE(kari, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return NULL;
    }
    XMEMSET(kari->decoded, 0, sizeof(DecodedCert));

    kari->recipKey = (ecc_key*)XMALLOC(sizeof(ecc_key), pkcs7->heap,
                                       DYNAMIC_TYPE_PKCS7);
    if (kari->recipKey == NULL) {
        WOLFSSL_MSG("Failed to allocate recipient ecc_key");
        XFREE(kari->decoded, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        XFREE(kari, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return NULL;
    }

    kari->senderKey = (ecc_key*)XMALLOC(sizeof(ecc_key), pkcs7->heap,
                                        DYNAMIC_TYPE_PKCS7);
    if (kari->senderKey == NULL) {
        WOLFSSL_MSG("Failed to allocate sender ecc_key");
        XFREE(kari->recipKey, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        XFREE(kari->decoded, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        XFREE(kari, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return NULL;
    }

    kari->senderKeyExport = NULL;
    kari->senderKeyExportSz = 0;
    kari->kek = NULL;
    kari->kekSz = 0;
    kari->ukm = NULL;
    kari->ukmSz = 0;
    kari->ukmOwner = 0;
    kari->sharedInfo = NULL;
    kari->sharedInfoSz = 0;
    kari->direction = direction;
    kari->decodedInit = 0;
    kari->recipKeyInit = 0;
    kari->senderKeyInit = 0;

    kari->heap = pkcs7->heap;
    kari->devId = pkcs7->devId;

    return kari;
}


/* free WC_PKCS7_KARI struct, return 0 on success */
static int wc_PKCS7_KariFree(WC_PKCS7_KARI* kari)
{
    void* heap;

    if (kari) {
        heap = kari->heap;

        if (kari->decoded) {
            if (kari->decodedInit)
                FreeDecodedCert(kari->decoded);
            XFREE(kari->decoded, heap, DYNAMIC_TYPE_PKCS7);
        }
        if (kari->senderKey) {
            if (kari->senderKeyInit)
                wc_ecc_free(kari->senderKey);
            XFREE(kari->senderKey, heap, DYNAMIC_TYPE_PKCS7);
        }
        if (kari->recipKey) {
            if (kari->recipKeyInit)
                wc_ecc_free(kari->recipKey);
            XFREE(kari->recipKey, heap, DYNAMIC_TYPE_PKCS7);
        }
        if (kari->senderKeyExport) {
            ForceZero(kari->senderKeyExport, kari->senderKeyExportSz);
            XFREE(kari->senderKeyExport, heap, DYNAMIC_TYPE_PKCS7);
            kari->senderKeyExportSz = 0;
        }
        if (kari->kek) {
            ForceZero(kari->kek, kari->kekSz);
            XFREE(kari->kek, heap, DYNAMIC_TYPE_PKCS7);
            kari->kekSz = 0;
        }
        if (kari->ukm) {
            if (kari->ukmOwner == 1) {
                XFREE(kari->ukm, heap, DYNAMIC_TYPE_PKCS7);
            }
            kari->ukmSz = 0;
        }
        if (kari->sharedInfo) {
            ForceZero(kari->sharedInfo, kari->sharedInfoSz);
            XFREE(kari->sharedInfo, heap, DYNAMIC_TYPE_PKCS7);
            kari->sharedInfoSz = 0;
        }
        XFREE(kari, heap, DYNAMIC_TYPE_PKCS7);
    }

    (void)heap;

    return 0;
}


/* parse recipient cert/key, return 0 on success, negative on error
 * key/keySz only needed during decoding (WC_PKCS7_DECODE) */
static int wc_PKCS7_KariParseRecipCert(WC_PKCS7_KARI* kari, const byte* cert,
                                       word32 certSz, const byte* key,
                                       word32 keySz)
{
    int ret;
    word32 idx;

    if (kari == NULL || kari->decoded == NULL) {
        return BAD_FUNC_ARG;
    }

    /* decode certificate */
    if (cert != NULL) {
        InitDecodedCert(kari->decoded, (byte*)cert, certSz, kari->heap);
        kari->decodedInit = 1;
        ret = ParseCert(kari->decoded, CA_TYPE, NO_VERIFY, 0);
        if (ret < 0)
            return ret;

        /* only supports ECDSA for now */
        if (kari->decoded->keyOID != ECDSAk) {
            WOLFSSL_MSG("CMS KARI only supports ECDSA key types");
            return BAD_FUNC_ARG;
        }

        /* make sure subject key id was read from cert */
        if (kari->decoded->extSubjKeyIdSet == 0) {
            WOLFSSL_MSG("Failed to read subject key ID from recipient cert");
            return BAD_FUNC_ARG;
        }
    }
    ret = wc_ecc_init_ex(kari->recipKey, kari->heap, kari->devId);
    if (ret != 0)
        return ret;

    kari->recipKeyInit = 1;

    /* get recip public key */
    if (kari->direction == WC_PKCS7_ENCODE) {
        if (cert == NULL) {
            WOLFSSL_MSG("Error recipient cert can not be null with encode");
            return BAD_FUNC_ARG;
        }

        idx = 0;
        ret = wc_EccPublicKeyDecode(kari->decoded->publicKey, &idx,
                                    kari->recipKey, kari->decoded->pubKeySize);
        if (ret != 0)
            return ret;
    }
    /* get recip private key */
    else if (kari->direction == WC_PKCS7_DECODE) {
        if (key != NULL && keySz > 0) {
            idx = 0;
            ret = wc_EccPrivateKeyDecode(key, &idx, kari->recipKey, keySz);
        }
        else if (kari->devId == INVALID_DEVID) {
            ret = BAD_FUNC_ARG;
        }
        if (ret != 0)
            return ret;

    } else {
        /* bad direction */
        return BAD_FUNC_ARG;
    }

    (void)idx;

    return 0;
}


/* create ephemeral ECC key, places ecc_key in kari->senderKey,
 * DER encoded in kari->senderKeyExport. return 0 on success,
 * negative on error */
static int wc_PKCS7_KariGenerateEphemeralKey(WC_PKCS7_KARI* kari)
{
    int ret;
    WC_RNG rng;

    if (kari == NULL || kari->decoded == NULL ||
        kari->recipKey == NULL || kari->recipKey->dp == NULL)
        return BAD_FUNC_ARG;

    kari->senderKeyExport = (byte*)XMALLOC(kari->decoded->pubKeySize,
                                           kari->heap, DYNAMIC_TYPE_PKCS7);
    if (kari->senderKeyExport == NULL)
        return MEMORY_E;

    kari->senderKeyExportSz = kari->decoded->pubKeySize;

    ret = wc_ecc_init_ex(kari->senderKey, kari->heap, kari->devId);
    if (ret != 0) {
        XFREE(kari->senderKeyExport, kari->heap, DYNAMIC_TYPE_PKCS7);
        kari->senderKeyExportSz = 0;
        kari->senderKeyExport   = NULL;
        return ret;
    }

    kari->senderKeyInit = 1;

    ret = wc_InitRng_ex(&rng, kari->heap, kari->devId);
    if (ret != 0) {
        XFREE(kari->senderKeyExport, kari->heap, DYNAMIC_TYPE_PKCS7);
        kari->senderKeyExportSz = 0;
        kari->senderKeyExport   = NULL;
        return ret;
    }

    ret = wc_ecc_make_key_ex(&rng, kari->recipKey->dp->size,
                             kari->senderKey, kari->recipKey->dp->id);
    if (ret != 0) {
        XFREE(kari->senderKeyExport, kari->heap, DYNAMIC_TYPE_PKCS7);
        kari->senderKeyExportSz = 0;
        kari->senderKeyExport   = NULL;
        wc_FreeRng(&rng);
        return ret;
    }

    wc_FreeRng(&rng);

    /* dump generated key to X.963 DER for output in CMS bundle */
    PRIVATE_KEY_UNLOCK();
    ret = wc_ecc_export_x963(kari->senderKey, kari->senderKeyExport,
                             &kari->senderKeyExportSz);
    PRIVATE_KEY_LOCK();
    if (ret != 0) {
        XFREE(kari->senderKeyExport, kari->heap, DYNAMIC_TYPE_PKCS7);
        kari->senderKeyExportSz = 0;
        kari->senderKeyExport   = NULL;
        return ret;
    }

    return 0;
}


/* create ASN.1 encoded ECC-CMS-SharedInfo using specified key wrap algorithm,
 * place in kari->sharedInfo. returns 0 on success, negative on error */
static int wc_PKCS7_KariGenerateSharedInfo(WC_PKCS7_KARI* kari, int keyWrapOID)
{
    int idx = 0;
    int sharedInfoSeqSz = 0;
    int keyInfoSz = 0;
    int suppPubInfoSeqSz = 0;
    int entityUInfoOctetSz = 0;
    int entityUInfoExplicitSz = 0;
    int kekOctetSz = 0;
    int sharedInfoSz = 0;

    word32 kekBitSz = 0;

    byte sharedInfoSeq[MAX_SEQ_SZ];
    byte keyInfo[MAX_ALGO_SZ];
    byte suppPubInfoSeq[MAX_SEQ_SZ];
    byte entityUInfoOctet[MAX_OCTET_STR_SZ];
    byte entityUInfoExplicitSeq[MAX_SEQ_SZ];
    byte kekOctet[MAX_OCTET_STR_SZ];

    if (kari == NULL)
        return BAD_FUNC_ARG;

    if ((kari->ukmSz > 0) && (kari->ukm == NULL))
        return BAD_FUNC_ARG;

    /* kekOctet */
    kekOctetSz = (int)SetOctetString(sizeof(word32), kekOctet);
    sharedInfoSz += (kekOctetSz + (int)sizeof(word32));

    /* suppPubInfo */
    suppPubInfoSeqSz = (int)SetImplicit(ASN_SEQUENCE, 2,
                                        (word32)kekOctetSz + (word32)sizeof(word32),
                                        suppPubInfoSeq, 0);
    sharedInfoSz += suppPubInfoSeqSz;

    /* optional ukm/entityInfo */
    if (kari->ukmSz > 0) {
        entityUInfoOctetSz = (int)SetOctetString(kari->ukmSz, entityUInfoOctet);
        sharedInfoSz += (entityUInfoOctetSz + (int)kari->ukmSz);

        entityUInfoExplicitSz = (int)SetExplicit(0,
                                       (word32)entityUInfoOctetSz + kari->ukmSz,
                                       entityUInfoExplicitSeq, 0);
        sharedInfoSz += entityUInfoExplicitSz;
    }

    /* keyInfo */
    keyInfoSz = (int)SetAlgoID(keyWrapOID, keyInfo, oidKeyWrapType, 0);
    sharedInfoSz += keyInfoSz;

    /* sharedInfo */
    sharedInfoSeqSz = (int)SetSequence((word32)sharedInfoSz, sharedInfoSeq);
    sharedInfoSz += sharedInfoSeqSz;

    kari->sharedInfo = (byte*)XMALLOC((word32)sharedInfoSz, kari->heap,
                                      DYNAMIC_TYPE_PKCS7);
    if (kari->sharedInfo == NULL)
        return MEMORY_E;

    kari->sharedInfoSz = (word32)sharedInfoSz;

    XMEMCPY(kari->sharedInfo + idx, sharedInfoSeq, (word32)sharedInfoSeqSz);
    idx += sharedInfoSeqSz;
    XMEMCPY(kari->sharedInfo + idx, keyInfo, (word32)keyInfoSz);
    idx += keyInfoSz;
    if (kari->ukmSz > 0) {
        XMEMCPY(kari->sharedInfo + idx, entityUInfoExplicitSeq,
                (word32)entityUInfoExplicitSz);
        idx += entityUInfoExplicitSz;
        XMEMCPY(kari->sharedInfo + idx, entityUInfoOctet,
                (word32)entityUInfoOctetSz);
        idx += entityUInfoOctetSz;
        XMEMCPY(kari->sharedInfo + idx, kari->ukm, kari->ukmSz);
        idx += (int)kari->ukmSz;
    }
    XMEMCPY(kari->sharedInfo + idx, suppPubInfoSeq, (word32)suppPubInfoSeqSz);
    idx += suppPubInfoSeqSz;
    XMEMCPY(kari->sharedInfo + idx, kekOctet, (word32)kekOctetSz);
    idx += kekOctetSz;

    kekBitSz = (kari->kekSz) * 8;              /* convert to bits */
#ifdef LITTLE_ENDIAN_ORDER
    kekBitSz = ByteReverseWord32(kekBitSz);    /* network byte order */
#endif
    XMEMCPY(kari->sharedInfo + idx, &kekBitSz, sizeof(kekBitSz));

    return 0;
}


/* create key encryption key (KEK) using key wrap algorithm and key encryption
 * algorithm, place in kari->kek. return 0 on success, <0 on error. */
static int wc_PKCS7_KariGenerateKEK(WC_PKCS7_KARI* kari, WC_RNG* rng,
                                    int keyWrapOID, int keyEncOID)
{
    int ret;
    int kSz;
    enum wc_HashType kdfType;
    byte*  secret;
    word32 secretSz;

    if (kari == NULL || kari->recipKey == NULL ||
        kari->senderKey == NULL || kari->senderKey->dp == NULL)
        return BAD_FUNC_ARG;

    /* get KEK size, allocate buff */
    kSz = wc_PKCS7_GetOIDKeySize(keyWrapOID);
    if (kSz < 0)
        return kSz;

    kari->kek = (byte*)XMALLOC((word32)kSz, kari->heap, DYNAMIC_TYPE_PKCS7);
    if (kari->kek == NULL)
        return MEMORY_E;

    kari->kekSz = (word32)kSz;

    /* generate ECC-CMS-SharedInfo */
    ret = wc_PKCS7_KariGenerateSharedInfo(kari, keyWrapOID);
    if (ret != 0)
        return ret;

    /* generate shared secret */
    secretSz = (word32)kari->senderKey->dp->size;
    secret = (byte*)XMALLOC(secretSz, kari->heap, DYNAMIC_TYPE_PKCS7);
    if (secret == NULL)
        return MEMORY_E;

#if defined(ECC_TIMING_RESISTANT) && (!defined(HAVE_FIPS) || \
    (!defined(HAVE_FIPS_VERSION) || (HAVE_FIPS_VERSION != 2))) && \
    !defined(HAVE_SELFTEST)
    ret = wc_ecc_set_rng(kari->senderKey, rng);
    if (ret != 0) {
        XFREE(secret, kari->heap, DYNAMIC_TYPE_PKCS7);
        return ret;
    }
    ret = wc_ecc_set_rng(kari->recipKey, rng);
    if (ret != 0) {
        XFREE(secret, kari->heap, DYNAMIC_TYPE_PKCS7);
        return ret;
    }
#else
    (void)rng;
#endif

    if (kari->direction == WC_PKCS7_ENCODE) {
        PRIVATE_KEY_UNLOCK();
        ret = wc_ecc_shared_secret(kari->senderKey, kari->recipKey,
                                   secret, &secretSz);
        PRIVATE_KEY_LOCK();
    } else if (kari->direction == WC_PKCS7_DECODE) {
        PRIVATE_KEY_UNLOCK();
        ret = wc_ecc_shared_secret(kari->recipKey, kari->senderKey,
                                   secret, &secretSz);
        PRIVATE_KEY_LOCK();
    } else {
        /* bad direction */
        XFREE(secret, kari->heap, DYNAMIC_TYPE_PKCS7);
        return BAD_FUNC_ARG;
    }

    if (ret != 0) {
        XFREE(secret, kari->heap, DYNAMIC_TYPE_PKCS7);
        return ret;
    }

    /* run through KDF */
    switch (keyEncOID) {

    #ifndef NO_SHA
        case dhSinglePass_stdDH_sha1kdf_scheme:
            kdfType = WC_HASH_TYPE_SHA;
            break;
    #endif
    #ifndef WOLFSSL_SHA224
        case dhSinglePass_stdDH_sha224kdf_scheme:
            kdfType = WC_HASH_TYPE_SHA224;
            break;
    #endif
    #ifndef NO_SHA256
        case dhSinglePass_stdDH_sha256kdf_scheme:
            kdfType = WC_HASH_TYPE_SHA256;
            break;
    #endif
    #ifdef WOLFSSL_SHA384
        case dhSinglePass_stdDH_sha384kdf_scheme:
            kdfType = WC_HASH_TYPE_SHA384;
            break;
    #endif
    #ifdef WOLFSSL_SHA512
        case dhSinglePass_stdDH_sha512kdf_scheme:
            kdfType = WC_HASH_TYPE_SHA512;
            break;
    #endif
        default:
            WOLFSSL_MSG("Unsupported key agreement algorithm");
            XFREE(secret, kari->heap, DYNAMIC_TYPE_PKCS7);
            return BAD_FUNC_ARG;
    };

    ret = wc_X963_KDF(kdfType, secret, secretSz, kari->sharedInfo,
                      kari->sharedInfoSz, kari->kek, kari->kekSz);
    if (ret != 0) {
        XFREE(secret, kari->heap, DYNAMIC_TYPE_PKCS7);
        return ret;
    }

    XFREE(secret, kari->heap, DYNAMIC_TYPE_PKCS7);

    return 0;
}


/* Encode and add CMS EnvelopedData KARI (KeyAgreeRecipientInfo) RecipientInfo
 * to CMS/PKCS#7 EnvelopedData structure.
 *
 * Returns 0 on success, negative upon error */
int wc_PKCS7_AddRecipient_KARI(wc_PKCS7* pkcs7, const byte* cert, word32 certSz,
                               int keyWrapOID, int keyAgreeOID, byte* ukm,
                               word32 ukmSz, int options)
{
    Pkcs7EncodedRecip* recip;
    Pkcs7EncodedRecip* lastRecip = NULL;
    WC_PKCS7_KARI* kari = NULL;

    word32 idx = 0;
    word32 encryptedKeySz = MAX_ENCRYPTED_KEY_SZ;

    int ret = 0;
    int keySz, direction = 0;
    int blockKeySz = 0;
    int keyIdSize;

    /* ASN.1 layout */
    int totalSz = 0;
    int kariSeqSz = 0;
    byte kariSeq[MAX_SEQ_SZ];           /* IMPLICIT [1] */
    int verSz = 0;
    byte ver[MAX_VERSION_SZ];

    int origIdOrKeySeqSz = 0;
    byte origIdOrKeySeq[MAX_SEQ_SZ];    /* IMPLICIT [0] */
    int origPubKeySeqSz = 0;
    byte origPubKeySeq[MAX_SEQ_SZ];     /* IMPLICIT [1] */
    int origAlgIdSz = 0;
    byte origAlgId[MAX_ALGO_SZ];
    int origPubKeyStrSz = 0;
    byte origPubKeyStr[MAX_OCTET_STR_SZ];

    /* optional user keying material */
    int ukmOctetSz = 0;
    byte ukmOctetStr[MAX_OCTET_STR_SZ];
    int ukmExplicitSz = 0;
    byte ukmExplicitSeq[MAX_SEQ_SZ];

    int keyEncryptAlgoIdSz = 0;
    byte keyEncryptAlgoId[MAX_ALGO_SZ];
    int keyWrapAlgSz = 0;
    byte keyWrapAlg[MAX_ALGO_SZ];

    int recipEncKeysSeqSz = 0;
    byte recipEncKeysSeq[MAX_SEQ_SZ];
    int recipEncKeySeqSz = 0;
    byte recipEncKeySeq[MAX_SEQ_SZ];
    int recipKeyIdSeqSz = 0;
    byte recipKeyIdSeq[MAX_SEQ_SZ];     /* IMPLICIT [0] */
    int subjKeyIdOctetSz = 0;
    byte subjKeyIdOctet[MAX_OCTET_STR_SZ];
    int encryptedKeyOctetSz = 0;
    byte encryptedKeyOctet[MAX_OCTET_STR_SZ];

#ifdef WOLFSSL_SMALL_STACK
    byte* encryptedKey;

    encryptedKey = (byte*)XMALLOC(MAX_ENCRYPTED_KEY_SZ, pkcs7->heap,
                                  DYNAMIC_TYPE_TMP_BUFFER);
    if (encryptedKey == NULL) {
        return MEMORY_E;
    }
#else
    byte encryptedKey[MAX_ENCRYPTED_KEY_SZ];
#endif

#if defined(WOLFSSL_SM2) && defined(WOLFSSL_SM3)
    keyIdSize = wc_HashGetDigestSize(wc_HashTypeConvert(HashIdAlg(
           pkcs7->publicKeyOID)));
#else
    keyIdSize = KEYID_SIZE;
#endif

    /* allocate and init memory for recipient */
    recip = (Pkcs7EncodedRecip*)XMALLOC(sizeof(Pkcs7EncodedRecip), pkcs7->heap,
                                 DYNAMIC_TYPE_PKCS7);
    if (recip == NULL) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return MEMORY_E;
    }
    XMEMSET(recip, 0, sizeof(Pkcs7EncodedRecip));

    /* get key size for content-encryption key based on algorithm */
    blockKeySz = wc_PKCS7_GetOIDKeySize(pkcs7->encryptOID);
    if (blockKeySz < 0) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        XFREE(recip, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return blockKeySz;
    }

    /* generate random content encryption key, if needed */
    ret = PKCS7_GenerateContentEncryptionKey(pkcs7, (word32)blockKeySz);
    if (ret < 0) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        XFREE(recip, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return ret;
    }

    /* set direction based on keyWrapAlgo */
    switch (keyWrapOID) {
#ifndef NO_AES
    #ifdef WOLFSSL_AES_128
        case AES128_WRAP:
    #endif
    #ifdef WOLFSSL_AES_192
        case AES192_WRAP:
    #endif
    #ifdef WOLFSSL_AES_256
        case AES256_WRAP:
    #endif
            direction = AES_ENCRYPTION;
            break;
#endif
        default:
            WOLFSSL_MSG("Unsupported key wrap algorithm");
#ifdef WOLFSSL_SMALL_STACK
            XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
            XFREE(recip, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
            return BAD_KEYWRAP_ALG_E;
    }

    kari = wc_PKCS7_KariNew(pkcs7, WC_PKCS7_ENCODE);
    if (kari == NULL) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        XFREE(recip, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return MEMORY_E;
    }

    /* set user keying material if available */
    if (ukmSz > 0 && ukm != NULL) {
        kari->ukm = ukm;
        kari->ukmSz = ukmSz;
        kari->ukmOwner = 0;
    }

    /* parse recipient cert, get public key */
    ret = wc_PKCS7_KariParseRecipCert(kari, cert, certSz, NULL, 0);
    if (ret != 0) {
        wc_PKCS7_KariFree(kari);
#ifdef WOLFSSL_SMALL_STACK
        XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        XFREE(recip, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return ret;
    }

    /* generate sender ephemeral ECC key */
    ret = wc_PKCS7_KariGenerateEphemeralKey(kari);
    if (ret != 0) {
        wc_PKCS7_KariFree(kari);
#ifdef WOLFSSL_SMALL_STACK
        XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        XFREE(recip, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return ret;
    }

    /* generate KEK (key encryption key) */
    ret = wc_PKCS7_KariGenerateKEK(kari, pkcs7->rng, keyWrapOID, keyAgreeOID);
    if (ret != 0) {
        wc_PKCS7_KariFree(kari);
#ifdef WOLFSSL_SMALL_STACK
        XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        XFREE(recip, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return ret;
    }

    /* encrypt CEK with KEK */
    keySz = wc_PKCS7_KeyWrap(pkcs7->cek, pkcs7->cekSz, kari->kek,
                             kari->kekSz, encryptedKey, encryptedKeySz,
                             keyWrapOID, direction);
    if (keySz <= 0) {
        wc_PKCS7_KariFree(kari);
#ifdef WOLFSSL_SMALL_STACK
        XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        XFREE(recip, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return keySz;
    }
    encryptedKeySz = (word32)keySz;

    /* Start of RecipientEncryptedKeys */

    /* EncryptedKey */
    encryptedKeyOctetSz = (int)SetOctetString(encryptedKeySz,
                                              encryptedKeyOctet);
    totalSz += (encryptedKeyOctetSz + (int)encryptedKeySz);

    /* SubjectKeyIdentifier */
    subjKeyIdOctetSz = (int)SetOctetString((word32)keyIdSize, subjKeyIdOctet);
    totalSz += (subjKeyIdOctetSz + keyIdSize);

    /* RecipientKeyIdentifier IMPLICIT [0] */
    recipKeyIdSeqSz = (int)SetImplicit(ASN_SEQUENCE, 0,
                                       (word32)(subjKeyIdOctetSz + keyIdSize),
                                       recipKeyIdSeq, 0);
    totalSz += recipKeyIdSeqSz;

    /* RecipientEncryptedKey */
    recipEncKeySeqSz = (int)SetSequence((word32)totalSz, recipEncKeySeq);
    totalSz += recipEncKeySeqSz;

    /* RecipientEncryptedKeys */
    recipEncKeysSeqSz = (int)SetSequence((word32)totalSz, recipEncKeysSeq);
    totalSz += recipEncKeysSeqSz;

    /* Start of optional UserKeyingMaterial */

    if (kari->ukmSz > 0) {
        ukmOctetSz = (int)SetOctetString(kari->ukmSz, ukmOctetStr);
        totalSz += (ukmOctetSz + (int)kari->ukmSz);

        ukmExplicitSz = (int)SetExplicit(1, (word32)ukmOctetSz + kari->ukmSz,
                                    ukmExplicitSeq, 0);
        totalSz += ukmExplicitSz;
    }

    /* Start of KeyEncryptionAlgorithmIdentifier */

    /* KeyWrapAlgorithm */
    keyWrapAlgSz = (int)SetAlgoID(keyWrapOID, keyWrapAlg, oidKeyWrapType, 0);
    totalSz += keyWrapAlgSz;

    /* KeyEncryptionAlgorithmIdentifier */
    keyEncryptAlgoIdSz = (int)SetAlgoID(keyAgreeOID, keyEncryptAlgoId,
                                   oidCmsKeyAgreeType, keyWrapAlgSz);
    totalSz += keyEncryptAlgoIdSz;

    /* Start of OriginatorIdentifierOrKey */

    /* recipient ECPoint, public key */
    XMEMSET(origPubKeyStr, 0, sizeof(origPubKeyStr)); /* no unused bits */
    origPubKeyStr[0] = ASN_BIT_STRING;
    origPubKeyStrSz = (int)SetLength(kari->senderKeyExportSz + 1,
                                origPubKeyStr + 1) + 2;
    totalSz += (origPubKeyStrSz + (int)kari->senderKeyExportSz);

    /* Originator AlgorithmIdentifier, params set to NULL for interop
       compatibility */
    origAlgIdSz = (int)SetAlgoID(ECDSAk, origAlgId, oidKeyType, 2);
    origAlgId[origAlgIdSz++] = ASN_TAG_NULL;
    origAlgId[origAlgIdSz++] = 0;
    totalSz += origAlgIdSz;

    /* outer OriginatorPublicKey IMPLICIT [1] */
    origPubKeySeqSz = (int)SetImplicit(ASN_SEQUENCE, 1,
                               (word32)(origAlgIdSz + origPubKeyStrSz +
                               (int)kari->senderKeyExportSz), origPubKeySeq, 0);
    totalSz += origPubKeySeqSz;

    /* outer OriginatorIdentifierOrKey IMPLICIT [0] */
    origIdOrKeySeqSz = (int)SetImplicit(ASN_SEQUENCE, 0,
                                (word32)(origPubKeySeqSz + origAlgIdSz +
                                origPubKeyStrSz + (int)kari->senderKeyExportSz),
                                origIdOrKeySeq, 0);
    totalSz += origIdOrKeySeqSz;

    /* version, always 3 */
    verSz = SetMyVersion(3, ver, 0);
    totalSz += verSz;
    recip->recipVersion = 3;

    /* outer IMPLICIT [1] kari */
    kariSeqSz = (int)SetImplicit(ASN_SEQUENCE, 1, (word32)totalSz, kariSeq, 0);
    totalSz += kariSeqSz;

    if (totalSz > MAX_RECIP_SZ) {
        WOLFSSL_MSG("KeyAgreeRecipientInfo output buffer too small");
        wc_PKCS7_KariFree(kari);
#ifdef WOLFSSL_SMALL_STACK
        XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        XFREE(recip, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return BUFFER_E;
    }

    XMEMCPY(recip->recip + idx, kariSeq, (word32)kariSeqSz);
    idx += (word32)kariSeqSz;
    XMEMCPY(recip->recip + idx, ver, (word32)verSz);
    idx += (word32)verSz;

    XMEMCPY(recip->recip + idx, origIdOrKeySeq, (word32)origIdOrKeySeqSz);
    idx += (word32)origIdOrKeySeqSz;
    XMEMCPY(recip->recip + idx, origPubKeySeq, (word32)origPubKeySeqSz);
    idx += (word32)origPubKeySeqSz;

    /* AlgorithmIdentifier with NULL parameter */
    XMEMCPY(recip->recip + idx, origAlgId, (word32)origAlgIdSz);
    idx += (word32)origAlgIdSz;

    XMEMCPY(recip->recip + idx, origPubKeyStr, (word32)origPubKeyStrSz);
    idx += (word32)origPubKeyStrSz;
    /* ephemeral public key */
    XMEMCPY(recip->recip + idx, kari->senderKeyExport, kari->senderKeyExportSz);
    idx += kari->senderKeyExportSz;

    if (kari->ukmSz > 0) {
        XMEMCPY(recip->recip + idx, ukmExplicitSeq, (word32)ukmExplicitSz);
        idx += (word32)ukmExplicitSz;
        XMEMCPY(recip->recip + idx, ukmOctetStr, (word32)ukmOctetSz);
        idx += (word32)ukmOctetSz;
        XMEMCPY(recip->recip + idx, kari->ukm, kari->ukmSz);
        idx += kari->ukmSz;
    }

    XMEMCPY(recip->recip + idx, keyEncryptAlgoId, (word32)keyEncryptAlgoIdSz);
    idx += (word32)keyEncryptAlgoIdSz;
    XMEMCPY(recip->recip + idx, keyWrapAlg, (word32)keyWrapAlgSz);
    idx += (word32)keyWrapAlgSz;

    XMEMCPY(recip->recip + idx, recipEncKeysSeq, (word32)recipEncKeysSeqSz);
    idx += (word32)recipEncKeysSeqSz;
    XMEMCPY(recip->recip + idx, recipEncKeySeq, (word32)recipEncKeySeqSz);
    idx += (word32)recipEncKeySeqSz;
    XMEMCPY(recip->recip + idx, recipKeyIdSeq, (word32)recipKeyIdSeqSz);
    idx += (word32)recipKeyIdSeqSz;
    XMEMCPY(recip->recip + idx, subjKeyIdOctet, (word32)subjKeyIdOctetSz);
    idx += (word32)subjKeyIdOctetSz;
    /* subject key id */
    XMEMCPY(recip->recip + idx, kari->decoded->extSubjKeyId, (word32)keyIdSize);
    idx += (word32)keyIdSize;
    XMEMCPY(recip->recip + idx, encryptedKeyOctet, (word32)encryptedKeyOctetSz);
    idx += (word32)encryptedKeyOctetSz;
    /* encrypted CEK */
    XMEMCPY(recip->recip + idx, encryptedKey, encryptedKeySz);
    idx += encryptedKeySz;

    wc_PKCS7_KariFree(kari);
#ifdef WOLFSSL_SMALL_STACK
    XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    /* store recipient size */
    recip->recipSz = idx;
    recip->recipType = PKCS7_KARI;

    /* add recipient to recip list */
    if (pkcs7->recipList == NULL) {
        pkcs7->recipList = recip;
    } else {
        lastRecip = pkcs7->recipList;
        while (lastRecip->next != NULL) {
            lastRecip = lastRecip->next;
        }
        lastRecip->next = recip;
    }

    (void)options;

    return (int)idx;
}

#endif /* HAVE_ECC */

#ifndef NO_RSA

/* Encode and add CMS EnvelopedData KTRI (KeyTransRecipientInfo) RecipientInfo
 * to CMS/PKCS#7 EnvelopedData structure.
 *
 * Returns 0 on success, negative upon error */
int wc_PKCS7_AddRecipient_KTRI(wc_PKCS7* pkcs7, const byte* cert, word32 certSz,
                               int options)
{
    Pkcs7EncodedRecip* recip = NULL;
    Pkcs7EncodedRecip* lastRecip = NULL;

    WC_RNG rng;
    word32 idx = 0;
    word32 encryptedKeySz = 0;
    int keyIdSize;

    int ret = 0, blockKeySz;
    int verSz = 0, issuerSz = 0, snSz = 0, keyEncAlgSz = 0;
    int issuerSeqSz = 0, recipSeqSz = 0, issuerSerialSeqSz = 0;
    int encKeyOctetStrSz;
    int sidType;

    byte ver[MAX_VERSION_SZ];
    byte issuerSerialSeq[MAX_SEQ_SZ];
    byte recipSeq[MAX_SEQ_SZ];
    byte issuerSeq[MAX_SEQ_SZ];
    byte encKeyOctetStr[MAX_OCTET_STR_SZ];

    byte issuerSKID[MAX_LENGTH_SZ];
    word32 issuerSKIDSz = 0;

    byte*   encryptedKey;

#ifdef WOLFSSL_SMALL_STACK
    byte*   serial;
    byte*   keyAlgArray;
    RsaKey* pubKey;
    DecodedCert* decoded;

    serial = (byte*)XMALLOC(MAX_SN_SZ, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
    keyAlgArray = (byte*)XMALLOC(MAX_ALGO_SZ, pkcs7->heap,
                                 DYNAMIC_TYPE_TMP_BUFFER);
    decoded = (DecodedCert*)XMALLOC(sizeof(DecodedCert), pkcs7->heap,
                                    DYNAMIC_TYPE_TMP_BUFFER);

    if (decoded == NULL || serial == NULL || keyAlgArray == NULL) {
        XFREE(serial, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(keyAlgArray, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(decoded, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }
#else
    byte serial[MAX_SN_SZ];
    byte keyAlgArray[MAX_ALGO_SZ];
    RsaKey pubKey[1];
    DecodedCert decoded[1];
#endif

    /* Always allocate to ensure aligned use with RSA */
    encryptedKey = (byte*)XMALLOC(MAX_ENCRYPTED_KEY_SZ, pkcs7->heap,
                                  DYNAMIC_TYPE_WOLF_BIGINT);
    if (encryptedKey == NULL) {
    #ifdef WOLFSSL_SMALL_STACK
        XFREE(serial, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(keyAlgArray, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(decoded, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
    #endif
        return MEMORY_E;
    }

    encryptedKeySz = MAX_ENCRYPTED_KEY_SZ;
    XMEMSET(encryptedKey, 0, encryptedKeySz);

    /* default to IssuerAndSerialNumber if not set */
    if (pkcs7->sidType != 0) {
        sidType = pkcs7->sidType;
    } else {
        sidType = CMS_ISSUER_AND_SERIAL_NUMBER;
    }

    /* allow options to override SubjectIdentifier type if set */
    if (options & CMS_SKID) {
        sidType = CMS_SKID;
    } else if (options & CMS_ISSUER_AND_SERIAL_NUMBER) {
        sidType = CMS_ISSUER_AND_SERIAL_NUMBER;
    }

    /* allocate recipient struct */
    recip = (Pkcs7EncodedRecip*)XMALLOC(sizeof(Pkcs7EncodedRecip), pkcs7->heap,
                                 DYNAMIC_TYPE_PKCS7);
    if (recip == NULL) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(serial,       pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(keyAlgArray,  pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(decoded,      pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_WOLF_BIGINT);
        return MEMORY_E;
    }
    XMEMSET(recip, 0, sizeof(Pkcs7EncodedRecip));

    /* get key size for content-encryption key based on algorithm */
    blockKeySz = wc_PKCS7_GetOIDKeySize(pkcs7->encryptOID);
    if (blockKeySz < 0) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(serial,       pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(keyAlgArray,  pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(decoded,      pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_WOLF_BIGINT);
        XFREE(recip, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return blockKeySz;
    }

    /* generate random content encryption key, if needed */
    ret = PKCS7_GenerateContentEncryptionKey(pkcs7, (word32)blockKeySz);
    if (ret < 0) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(serial,       pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(keyAlgArray,  pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(decoded,      pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_WOLF_BIGINT);
        XFREE(recip, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return ret;
    }

    InitDecodedCert(decoded, (byte*)cert, certSz, pkcs7->heap);
    ret = ParseCert(decoded, CA_TYPE, NO_VERIFY, 0);
    if (ret < 0) {
        FreeDecodedCert(decoded);
#ifdef WOLFSSL_SMALL_STACK
        XFREE(serial,       pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(keyAlgArray,  pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(decoded,      pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_WOLF_BIGINT);
        XFREE(recip, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return ret;
    }

#if defined(WOLFSSL_SM2) && defined(WOLFSSL_SM3)
    keyIdSize = wc_HashGetDigestSize(wc_HashTypeConvert(HashIdAlg(
           decoded->signatureOID)));
#else
    keyIdSize = KEYID_SIZE;
#endif

    if (sidType == CMS_ISSUER_AND_SERIAL_NUMBER) {

        /* version, must be 0 for IssuerAndSerialNumber */
        verSz = SetMyVersion(0, ver, 0);
        recip->recipVersion = 0;

        /* IssuerAndSerialNumber */
        if (decoded->issuerRaw == NULL || decoded->issuerRawLen == 0) {
            WOLFSSL_MSG("DecodedCert lacks raw issuer pointer and length");
            FreeDecodedCert(decoded);
#ifdef WOLFSSL_SMALL_STACK
            XFREE(serial,       pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(keyAlgArray,  pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(decoded,      pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
            XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_WOLF_BIGINT);
            XFREE(recip, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
            return -1;
        }
        issuerSz    = decoded->issuerRawLen;
        issuerSeqSz = (int)SetSequence((word32)issuerSz, issuerSeq);

        if (decoded->serialSz == 0) {
            WOLFSSL_MSG("DecodedCert missing serial number");
            FreeDecodedCert(decoded);
#ifdef WOLFSSL_SMALL_STACK
            XFREE(serial,       pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(keyAlgArray,  pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(decoded,      pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
            XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_WOLF_BIGINT);
            XFREE(recip, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
            return -1;
        }
        snSz = SetSerialNumber(decoded->serial, (word32)decoded->serialSz,
                               serial, MAX_SN_SZ, MAX_SN_SZ);
        if (snSz < 0) {
            WOLFSSL_MSG("Error setting the serial number");
            FreeDecodedCert(decoded);
#ifdef WOLFSSL_SMALL_STACK
            XFREE(serial,       pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(keyAlgArray,  pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(decoded,      pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
            XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_WOLF_BIGINT);
            XFREE(recip, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
            return -1;
        }
        issuerSerialSeqSz = (int)SetSequence((word32)(issuerSeqSz + issuerSz +
                                             snSz), issuerSerialSeq);
    } else if (sidType == CMS_SKID) {

        /* version, must be 2 for SubjectKeyIdentifier */
        verSz = SetMyVersion(2, ver, 0);
        recip->recipVersion = 2;

        issuerSKIDSz = SetLength((word32)keyIdSize, issuerSKID);
    } else {
        FreeDecodedCert(decoded);
#ifdef WOLFSSL_SMALL_STACK
        XFREE(serial,       pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(keyAlgArray,  pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(decoded,      pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_WOLF_BIGINT);
        XFREE(recip, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return PKCS7_RECIP_E;
    }

    pkcs7->publicKeyOID = decoded->keyOID;

    /* KeyEncryptionAlgorithmIdentifier, only support RSA now */
    if (pkcs7->publicKeyOID != RSAk) {
        FreeDecodedCert(decoded);
#ifdef WOLFSSL_SMALL_STACK
        XFREE(serial,       pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(keyAlgArray,  pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(decoded,      pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_WOLF_BIGINT);
        XFREE(recip, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return ALGO_ID_E;
    }

    keyEncAlgSz = (int)SetAlgoID((int)pkcs7->publicKeyOID, keyAlgArray,
                                 oidKeyType, 0);
    if (keyEncAlgSz == 0) {
        FreeDecodedCert(decoded);
#ifdef WOLFSSL_SMALL_STACK
        XFREE(serial,       pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(keyAlgArray,  pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(decoded,      pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_WOLF_BIGINT);
        XFREE(recip, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_SMALL_STACK
    pubKey = (RsaKey*)XMALLOC(sizeof(RsaKey), pkcs7->heap,
            DYNAMIC_TYPE_TMP_BUFFER);
    if (pubKey == NULL) {
        FreeDecodedCert(decoded);
        XFREE(serial,       pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(keyAlgArray,  pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_WOLF_BIGINT);
        XFREE(decoded,      pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(recip, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return MEMORY_E;
    }
#endif

    /* EncryptedKey */
    ret = wc_InitRsaKey_ex(pubKey, pkcs7->heap, pkcs7->devId);
    if (ret != 0) {
        FreeDecodedCert(decoded);
#ifdef WOLFSSL_SMALL_STACK
        XFREE(pubKey,       pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(serial,       pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(keyAlgArray,  pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(decoded,      pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_WOLF_BIGINT);
        XFREE(recip, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return ret;
    }

    if (wc_RsaPublicKeyDecode(decoded->publicKey, &idx, pubKey,
                              decoded->pubKeySize) < 0) {
        WOLFSSL_MSG("ASN RSA key decode error");
        wc_FreeRsaKey(pubKey);
        FreeDecodedCert(decoded);
#ifdef WOLFSSL_SMALL_STACK
        XFREE(pubKey,       pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(serial,       pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(keyAlgArray,  pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(decoded,      pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_WOLF_BIGINT);
        XFREE(recip, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return PUBLIC_KEY_E;
    }

    ret = wc_InitRng_ex(&rng, pkcs7->heap, pkcs7->devId);
    if (ret != 0) {
        wc_FreeRsaKey(pubKey);
        FreeDecodedCert(decoded);
#ifdef WOLFSSL_SMALL_STACK
        XFREE(pubKey,       pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(serial,       pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(keyAlgArray,  pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(decoded,      pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_WOLF_BIGINT);
        XFREE(recip, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return MEMORY_E;
    }


#ifdef WOLFSSL_ASYNC_CRYPT
    /* Currently the call to RSA public encrypt here is blocking @TODO */
    do {
        ret = wc_AsyncWait(ret, &pubKey->asyncDev, WC_ASYNC_FLAG_CALL_AGAIN);
        if (ret >= 0)
#endif
        {
            ret = wc_RsaPublicEncrypt(pkcs7->cek, pkcs7->cekSz, encryptedKey,
                              encryptedKeySz, pubKey, &rng);
        }
#ifdef WOLFSSL_ASYNC_CRYPT
    } while (ret == WC_NO_ERR_TRACE(WC_PENDING_E));
#endif
    wc_FreeRsaKey(pubKey);
    wc_FreeRng(&rng);

#ifdef WOLFSSL_SMALL_STACK
    XFREE(pubKey, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    if (ret < 0) {
        WOLFSSL_MSG("RSA Public Encrypt failed");
        FreeDecodedCert(decoded);
#ifdef WOLFSSL_SMALL_STACK
        XFREE(serial,       pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(keyAlgArray,  pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(decoded,      pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_WOLF_BIGINT);
        XFREE(recip, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return ret;
    }
    encryptedKeySz = (word32)ret;

    encKeyOctetStrSz = (int)SetOctetString(encryptedKeySz, encKeyOctetStr);

    /* RecipientInfo */
    if (sidType == CMS_ISSUER_AND_SERIAL_NUMBER) {
        int recipLen =  verSz + (int)issuerSerialSeqSz + issuerSeqSz +
            issuerSz + snSz + keyEncAlgSz + encKeyOctetStrSz +
            (int)encryptedKeySz;
        recipSeqSz = (int)SetSequence((word32)recipLen, recipSeq);

        if ((recipSeqSz + recipLen) > MAX_RECIP_SZ) {
            WOLFSSL_MSG("RecipientInfo output buffer too small");
            FreeDecodedCert(decoded);
#ifdef WOLFSSL_SMALL_STACK
            XFREE(serial,       pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(keyAlgArray,  pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(decoded,      pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
            XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_WOLF_BIGINT);
            XFREE(recip, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
            return BUFFER_E;
        }

    } else {
        int recipLen =  verSz + ASN_TAG_SZ + (int)issuerSKIDSz + keyIdSize +
                keyEncAlgSz + encKeyOctetStrSz + (int)encryptedKeySz;
        recipSeqSz = (int)SetSequence((word32)recipLen, recipSeq);
        if ((recipSeqSz + recipLen) > MAX_RECIP_SZ) {
            WOLFSSL_MSG("RecipientInfo output buffer too small");
            FreeDecodedCert(decoded);
#ifdef WOLFSSL_SMALL_STACK
            XFREE(serial,       pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(keyAlgArray,  pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(decoded,      pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
            XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_WOLF_BIGINT);
            XFREE(recip, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
            return BUFFER_E;
        }
    }

    idx = 0;
    XMEMCPY(recip->recip + idx, recipSeq, (word32)recipSeqSz);
    idx += (word32)recipSeqSz;
    XMEMCPY(recip->recip + idx, ver, (word32)verSz);
    idx += (word32)verSz;
    if (sidType == CMS_ISSUER_AND_SERIAL_NUMBER) {
        XMEMCPY(recip->recip + idx, issuerSerialSeq, (word32)issuerSerialSeqSz);
        idx += (word32)issuerSerialSeqSz;
        XMEMCPY(recip->recip + idx, issuerSeq, (word32)issuerSeqSz);
        idx += (word32)issuerSeqSz;
        XMEMCPY(recip->recip + idx, decoded->issuerRaw, (word32)issuerSz);
        idx += (word32)issuerSz;
        XMEMCPY(recip->recip + idx, serial, (word32)snSz);
        idx += (word32)snSz;
    } else {
        recip->recip[idx] = ASN_CONTEXT_SPECIFIC;
        idx += ASN_TAG_SZ;
        XMEMCPY(recip->recip + idx, issuerSKID, issuerSKIDSz);
        idx += issuerSKIDSz;
        XMEMCPY(recip->recip + idx, pkcs7->issuerSubjKeyId, (word32)keyIdSize);
        idx += (word32)keyIdSize;
    }
    XMEMCPY(recip->recip + idx, keyAlgArray, (word32)keyEncAlgSz);
    idx += (word32)keyEncAlgSz;
    XMEMCPY(recip->recip + idx, encKeyOctetStr, (word32)encKeyOctetStrSz);
    idx += (word32)encKeyOctetStrSz;
    XMEMCPY(recip->recip + idx, encryptedKey, encryptedKeySz);
    idx += encryptedKeySz;

    FreeDecodedCert(decoded);

#ifdef WOLFSSL_SMALL_STACK
    XFREE(serial,       pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(keyAlgArray,  pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(decoded,      pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_WOLF_BIGINT);

    /* store recipient size */
    recip->recipSz = idx;
    recip->recipType = PKCS7_KTRI;

    /* add recipient to recip list */
    if (pkcs7->recipList == NULL) {
        pkcs7->recipList = recip;
    } else {
        lastRecip = pkcs7->recipList;
        while (lastRecip->next != NULL) {
            lastRecip = lastRecip->next;
        }
        lastRecip->next = recip;
    }

    return (int)idx;
}

#endif /* !NO_RSA */

/* abstraction for writing out PKCS7 bundle during creation
   returns 0 on success
 */
int wc_PKCS7_WriteOut(wc_PKCS7* pkcs7, byte* output, const byte* input,
    word32 inputSz)
{
    int ret = 0;

    if (inputSz == 0)
        return 0;

    if (input == NULL) {
        WOLFSSL_MSG("Internal error, trying to write out NULL buffer");
        return -1;
    }

#ifdef ASN_BER_TO_DER
    if (pkcs7->streamOutCb) {
        ret = pkcs7->streamOutCb(pkcs7, input, inputSz, pkcs7->streamCtx);
        /* sanity check on user provided ret value */
        if (ret < 0) {
            WOLFSSL_MSG("Return value error from stream out callback");
            ret = BUFFER_E;
        }
    }
    else
#endif
    if (output) {
        XMEMCPY(output, input, inputSz);
    }
    else {
        WOLFSSL_MSG("No way provided to output bundle");
        ret = BUFFER_E;
    }

    (void)pkcs7;
    return ret;
}


/* encrypt content using encryptOID algo */
static int wc_PKCS7_EncryptContent(wc_PKCS7* pkcs7, int encryptOID, byte* key,
                                   int keySz,
                                   byte* iv, int ivSz, byte* aad, word32 aadSz,
                                   byte* authTag, word32 authTagSz, byte* in,
                                   int inSz, byte* out)
{
    int ret;
#ifndef NO_AES
#ifdef WOLFSSL_SMALL_STACK
    Aes* aes;
#else
    Aes  aes[1];
#endif
#endif
#ifndef NO_DES3
    Des  des;
    Des3 des3;
#endif
    int devId  = pkcs7->devId;
    void* heap = pkcs7->heap;

    if (key == NULL || iv == NULL)
        return BAD_FUNC_ARG;

#ifdef ASN_BER_TO_DER
    if ((in == NULL && pkcs7->getContentCb == NULL) ||
        (out == NULL && pkcs7->streamOutCb == NULL)) {
        WOLFSSL_MSG("No input or output set for encrypt");
        return BAD_FUNC_ARG;
    }
#else
    if (in == NULL || out == NULL)
        return BAD_FUNC_ARG;
#endif

    switch (encryptOID) {
#ifndef NO_AES
    #ifdef HAVE_AES_CBC
    #ifdef WOLFSSL_AES_128
        case AES128CBCb:
    #endif
    #ifdef WOLFSSL_AES_192
        case AES192CBCb:
    #endif
    #ifdef WOLFSSL_AES_256
        case AES256CBCb:
    #endif
            if (
                #ifdef WOLFSSL_AES_128
                    (encryptOID == AES128CBCb && keySz != 16 ) ||
                #endif
                #ifdef WOLFSSL_AES_192
                    (encryptOID == AES192CBCb && keySz != 24 ) ||
                #endif
                #ifdef WOLFSSL_AES_256
                    (encryptOID == AES256CBCb && keySz != 32 ) ||
                #endif
                    (ivSz  != WC_AES_BLOCK_SIZE) )
                return BAD_FUNC_ARG;

#ifdef WOLFSSL_SMALL_STACK
            if ((aes = (Aes *)XMALLOC(sizeof *aes, NULL,
                                      DYNAMIC_TYPE_AES)) == NULL)
                return MEMORY_E;
#endif
            ret = wc_AesInit(aes, heap, devId);
            if (ret == 0) {
                ret = wc_AesSetKey(aes, key, (word32)keySz, iv, AES_ENCRYPTION);
                if (ret == 0) {
                    ret = wc_PKCS7_EncodeContentStream(pkcs7, NULL, aes, in,
                        inSz, out, WC_CIPHER_AES_CBC);
                }
                wc_AesFree(aes);
            }
#ifdef WOLFSSL_SMALL_STACK
            XFREE(aes, NULL, DYNAMIC_TYPE_AES);
#endif
            break;
    #endif /* HAVE_AES_CBC */
    #ifdef HAVE_AESGCM
        #ifdef WOLFSSL_AES_128
        case AES128GCMb:
        #endif
        #ifdef WOLFSSL_AES_192
        case AES192GCMb:
        #endif
        #ifdef WOLFSSL_AES_256
        case AES256GCMb:
        #endif
        #if defined(WOLFSSL_AES_128) || defined(WOLFSSL_AES_192) || \
            defined(WOLFSSL_AES_256)
            if (authTag == NULL)
                return BAD_FUNC_ARG;

#ifdef WOLFSSL_SMALL_STACK
            if ((aes = (Aes *)XMALLOC(sizeof *aes, NULL,
                                      DYNAMIC_TYPE_AES)) == NULL)
                return MEMORY_E;
#endif
            ret = wc_AesInit(aes, heap, devId);
            if (ret == 0) {
                ret = wc_AesGcmSetKey(aes, key, (word32)keySz);
                if (ret == 0) {
                #ifndef WOLFSSL_AESGCM_STREAM
                    if (pkcs7->encodeStream) {
                        WOLFSSL_MSG("Not AES-GCM stream support compiled in");
                        ret = NOT_COMPILED_IN;
                    }
                    else {
                        ret = wc_AesGcmEncrypt(aes, out, in, (word32)inSz, iv,
                                  (word32)ivSz, authTag, authTagSz, aad, aadSz);
                    #ifdef WOLFSSL_ASYNC_CRYPT
                        /* async encrypt not available here, so block till done
                         */
                        ret = wc_AsyncWait(ret, &aes->asyncDev,
                            WC_ASYNC_FLAG_NONE);
                    #endif
                    }
                #else
                    ret = wc_AesGcmEncryptInit(aes, key, (word32)keySz, iv,
                        (word32)ivSz);
                    if (ret == 0) {
                        ret = wc_AesGcmEncryptUpdate(aes, NULL, NULL, 0, aad,
                            aadSz);
                    }
                    if (ret == 0) {
                        ret = wc_PKCS7_EncodeContentStream(pkcs7, NULL, aes, in,
                            inSz, out, WC_CIPHER_AES_GCM);
                    }

                    if (ret == 0) {
                        ret = wc_AesGcmEncryptFinal(aes, authTag, authTagSz);
                    }
                #endif
                }
                wc_AesFree(aes);
            }
#ifdef WOLFSSL_SMALL_STACK
            XFREE(aes, NULL, DYNAMIC_TYPE_AES);
#endif
            break;
        #endif
    #endif /* HAVE_AESGCM */
    #ifdef HAVE_AESCCM
        #ifdef WOLFSSL_AES_128
        case AES128CCMb:
        #endif
        #ifdef WOLFSSL_AES_192
        case AES192CCMb:
        #endif
        #ifdef WOLFSSL_AES_256
        case AES256CCMb:
        #endif
        #if defined(WOLFSSL_AES_128) || defined(WOLFSSL_AES_192) || \
            defined(WOLFSSL_AES_256)
            if (authTag == NULL)
                return BAD_FUNC_ARG;

            if (pkcs7->encodeStream) {
                WOLFSSL_MSG("Streaming encoding not supported with AES-CCM");
                return BAD_FUNC_ARG;
            }

#ifdef WOLFSSL_SMALL_STACK
            if ((aes = (Aes *)XMALLOC(sizeof *aes, NULL,
                                      DYNAMIC_TYPE_AES)) == NULL)
                return MEMORY_E;
#endif
            ret = wc_AesInit(aes, heap, devId);
            if (ret == 0) {
                ret = wc_AesCcmSetKey(aes, key, (word32)keySz);
                if (ret == 0) {
                    ret = wc_AesCcmEncrypt(aes, out, in, (word32)inSz, iv,
                                           (word32)ivSz, authTag, authTagSz,
                                           aad, aadSz);
                #ifdef WOLFSSL_ASYNC_CRYPT
                    /* async encrypt not available here, so block till done */
                    ret = wc_AsyncWait(ret, &aes->asyncDev, WC_ASYNC_FLAG_NONE);
                #endif
                }
                wc_AesFree(aes);
            }
#ifdef WOLFSSL_SMALL_STACK
            XFREE(aes, NULL, DYNAMIC_TYPE_AES);
#endif
            break;
        #endif
    #endif /* HAVE_AESCCM */
#endif /* !NO_AES */
#ifndef NO_DES3
        case DESb:
            if (keySz != DES_KEYLEN || ivSz != DES_BLOCK_SIZE)
                return BAD_FUNC_ARG;

            if (pkcs7->encodeStream) {
                WOLFSSL_MSG("Streaming encoding not supported with DES3");
                return BAD_FUNC_ARG;
            }

            ret = wc_Des_SetKey(&des, key, iv, DES_ENCRYPTION);
            if (ret == 0)
                ret = wc_Des_CbcEncrypt(&des, out, in, (word32)inSz);

            break;

        case DES3b:
            if (keySz != DES3_KEYLEN || ivSz != DES_BLOCK_SIZE)
                return BAD_FUNC_ARG;

            if (pkcs7->encodeStream) {
                WOLFSSL_MSG("Streaming encoding not supported with DES3");
                return BAD_FUNC_ARG;
            }

            ret = wc_Des3Init(&des3, heap, devId);
            if (ret == 0) {
                ret = wc_Des3_SetKey(&des3, key, iv, DES_ENCRYPTION);
                if (ret == 0) {
                    ret = wc_Des3_CbcEncrypt(&des3, out, in, (word32)inSz);
                #ifdef WOLFSSL_ASYNC_CRYPT
                    /* async encrypt not available here, so block till done */
                    ret = wc_AsyncWait(ret, &des3.asyncDev, WC_ASYNC_FLAG_NONE);
                #endif
                }
                wc_Des3Free(&des3);
            }
            break;
#endif /* !NO_DES3 */
        default:
            WOLFSSL_MSG("Unsupported content cipher type");
            return ALGO_ID_E;
    };

#if defined(NO_AES) || (!defined(HAVE_AESGCM) && !defined(HAVE_AESCCM))
    (void)authTag;
    (void)authTagSz;
    (void)aad;
    (void)aadSz;
#endif
    return ret;
}


/* decrypt content using encryptOID algo
 * returns 0 on success */
static int wc_PKCS7_DecryptContent(wc_PKCS7* pkcs7, int encryptOID, byte* key,
        int keySz, byte* iv, int ivSz, byte* aad, word32 aadSz, byte* authTag,
        word32 authTagSz, byte* in, int inSz, byte* out, int devId, void* heap)
{
    int ret;
#ifndef NO_AES
#ifdef WOLFSSL_SMALL_STACK
    Aes  *aes;
#else
    Aes  aes[1];
#endif
#endif
#ifndef NO_DES3
    Des  des;
    Des3 des3;
#endif

    if (iv == NULL || in == NULL || out == NULL)
        return BAD_FUNC_ARG;

    if (pkcs7->decryptionCb != NULL) {
        return pkcs7->decryptionCb(pkcs7, encryptOID, iv, ivSz,
                                      aad, aadSz, authTag, authTagSz, in,
                                      inSz, out, pkcs7->decryptionCtx);
    }

    if (key == NULL)
        return BAD_FUNC_ARG;

    switch (encryptOID) {
#ifndef NO_AES
    #ifdef HAVE_AES_CBC
    #ifdef WOLFSSL_AES_128
        case AES128CBCb:
    #endif
    #ifdef WOLFSSL_AES_192
        case AES192CBCb:
    #endif
    #ifdef WOLFSSL_AES_256
        case AES256CBCb:
    #endif
            if (
                #ifdef WOLFSSL_AES_128
                    (encryptOID == AES128CBCb && keySz != 16 ) ||
                #endif
                #ifdef WOLFSSL_AES_192
                    (encryptOID == AES192CBCb && keySz != 24 ) ||
                #endif
                #ifdef WOLFSSL_AES_256
                    (encryptOID == AES256CBCb && keySz != 32 ) ||
                #endif
                    (ivSz  != WC_AES_BLOCK_SIZE) )
                return BAD_FUNC_ARG;
#ifdef WOLFSSL_SMALL_STACK
            if ((aes = (Aes *)XMALLOC(sizeof *aes, NULL,
                                      DYNAMIC_TYPE_AES)) == NULL)
                return MEMORY_E;
#endif
            ret = wc_AesInit(aes, heap, devId);
            if (ret == 0) {
                ret = wc_AesSetKey(aes, key, (word32)keySz, iv, AES_DECRYPTION);
                if (ret == 0) {
                    ret = wc_AesCbcDecrypt(aes, out, in, (word32)inSz);
                #ifdef WOLFSSL_ASYNC_CRYPT
                    /* async decrypt not available here, so block till done */
                    ret = wc_AsyncWait(ret, &aes->asyncDev, WC_ASYNC_FLAG_NONE);
                #endif
                }
                wc_AesFree(aes);
            }
#ifdef WOLFSSL_SMALL_STACK
            XFREE(aes, NULL, DYNAMIC_TYPE_AES);
#endif
            break;
    #endif /* HAVE_AES_CBC */
    #ifdef HAVE_AESGCM
        #ifdef WOLFSSL_AES_128
        case AES128GCMb:
        #endif
        #ifdef WOLFSSL_AES_192
        case AES192GCMb:
        #endif
        #ifdef WOLFSSL_AES_256
        case AES256GCMb:
        #endif
        #if defined(WOLFSSL_AES_128) || defined(WOLFSSL_AES_192) || \
            defined(WOLFSSL_AES_256)
            if (authTag == NULL)
                return BAD_FUNC_ARG;

#ifdef WOLFSSL_SMALL_STACK
            if ((aes = (Aes *)XMALLOC(sizeof *aes, NULL,
                                      DYNAMIC_TYPE_AES)) == NULL)
                return MEMORY_E;
#endif
            ret = wc_AesInit(aes, heap, devId);
            if (ret == 0) {
                ret = wc_AesGcmSetKey(aes, key, (word32)keySz);
                if (ret == 0) {
                    ret = wc_AesGcmDecrypt(aes, out, in, (word32)inSz, iv,
                                           (word32)ivSz, authTag, authTagSz,
                                           aad, aadSz);
                #ifdef WOLFSSL_ASYNC_CRYPT
                    /* async decrypt not available here, so block till done */
                    ret = wc_AsyncWait(ret, &aes->asyncDev, WC_ASYNC_FLAG_NONE);
                #endif
                }
                wc_AesFree(aes);
            }
#ifdef WOLFSSL_SMALL_STACK
            XFREE(aes, NULL, DYNAMIC_TYPE_AES);
#endif
            break;
        #endif
    #endif /* HAVE_AESGCM */
    #ifdef HAVE_AESCCM
        #ifdef WOLFSSL_AES_128
        case AES128CCMb:
        #endif
        #ifdef WOLFSSL_AES_192
        case AES192CCMb:
        #endif
        #ifdef WOLFSSL_AES_256
        case AES256CCMb:
        #endif
        #if defined(WOLFSSL_AES_128) || defined(WOLFSSL_AES_192) || \
            defined(WOLFSSL_AES_256)
            if (authTag == NULL)
                return BAD_FUNC_ARG;

#ifdef WOLFSSL_SMALL_STACK
            if ((aes = (Aes *)XMALLOC(sizeof *aes, NULL,
                                      DYNAMIC_TYPE_AES)) == NULL)
                return MEMORY_E;
#endif
            ret = wc_AesInit(aes, heap, devId);
            if (ret == 0) {
                ret = wc_AesCcmSetKey(aes, key, (word32)keySz);
                if (ret == 0) {
                    ret = wc_AesCcmDecrypt(aes, out, in, (word32)inSz, iv,
                                           (word32)ivSz, authTag, authTagSz,
                                           aad, aadSz);
                #ifdef WOLFSSL_ASYNC_CRYPT
                    /* async decrypt not available here, so block till done */
                    ret = wc_AsyncWait(ret, &aes->asyncDev, WC_ASYNC_FLAG_NONE);
                #endif
                }
                wc_AesFree(aes);
            }
#ifdef WOLFSSL_SMALL_STACK
            XFREE(aes, NULL, DYNAMIC_TYPE_AES);
#endif
            break;
        #endif
    #endif /* HAVE_AESCCM */
#endif /* !NO_AES */
#ifndef NO_DES3
        case DESb:
            if (keySz != DES_KEYLEN || ivSz != DES_BLOCK_SIZE)
                return BAD_FUNC_ARG;

            ret = wc_Des_SetKey(&des, key, iv, DES_DECRYPTION);
            if (ret == 0)
                ret = wc_Des_CbcDecrypt(&des, out, in, (word32)inSz);

            break;
        case DES3b:
            if (keySz != DES3_KEYLEN || ivSz != DES_BLOCK_SIZE)
                return BAD_FUNC_ARG;

            ret = wc_Des3Init(&des3, heap, devId);
            if (ret == 0) {
                ret = wc_Des3_SetKey(&des3, key, iv, DES_DECRYPTION);
                if (ret == 0) {
                    ret = wc_Des3_CbcDecrypt(&des3, out, in, (word32)inSz);
                #ifdef WOLFSSL_ASYNC_CRYPT
                    /* async decrypt not available here, so block till done */
                    ret = wc_AsyncWait(ret, &des3.asyncDev, WC_ASYNC_FLAG_NONE);
                #endif
                }
                wc_Des3Free(&des3);
            }

            break;
#endif /* !NO_DES3 */
        default:
            WOLFSSL_MSG("Unsupported content cipher type");
            return ALGO_ID_E;
    };

#if defined(NO_AES) || (!defined(HAVE_AESGCM) && !defined(HAVE_AESCCM))
    (void)authTag;
    (void)authTagSz;
    (void)aad;
    (void)aadSz;
#endif

    return ret;
}


/* Generate random block, place in out, return 0 on success negative on error.
 * Used for generation of IV, nonce, etc */
static int wc_PKCS7_GenerateBlock(wc_PKCS7* pkcs7, WC_RNG* rng, byte* out,
                                  word32 outSz)
{
    int ret;
    WC_RNG* rnd = NULL;

    if (out == NULL || outSz == 0)
        return BAD_FUNC_ARG;

    /* input RNG is optional, init local one if input rng is NULL */
    if (rng == NULL) {
        rnd = (WC_RNG*)XMALLOC(sizeof(WC_RNG), pkcs7->heap, DYNAMIC_TYPE_RNG);
        if (rnd == NULL)
            return MEMORY_E;

        ret = wc_InitRng_ex(rnd, pkcs7->heap, pkcs7->devId);
        if (ret != 0) {
            XFREE(rnd, pkcs7->heap, DYNAMIC_TYPE_RNG);
            return ret;
        }

    } else {
        rnd = rng;
    }

    ret = wc_RNG_GenerateBlock(rnd, out, outSz);

    if (rng == NULL) {
        wc_FreeRng(rnd);
        XFREE(rnd, pkcs7->heap, DYNAMIC_TYPE_RNG);
    }

    return ret;
}


/* Set default SignerIdentifier type to be used. Is either
 * IssuerAndSerialNumber or SubjectKeyIdentifier. Encoding defaults to using
 * IssuerAndSerialNumber unless set with this function or explicitly
 * overridden via options when adding RecipientInfo type.
 *
 * Using the type DEGENERATE_SID skips over signer information. In degenerate
 * cases there are no signers.
 *
 * pkcs7 - pointer to initialized PKCS7 structure
 * type  - either CMS_ISSUER_AND_SERIAL_NUMBER, CMS_SKID or DEGENERATE_SID
 *
 * return 0 on success, negative upon error */
int wc_PKCS7_SetSignerIdentifierType(wc_PKCS7* pkcs7, int type)
{
    if (pkcs7 == NULL)
        return BAD_FUNC_ARG;

    if (type != CMS_ISSUER_AND_SERIAL_NUMBER &&
        type != CMS_SKID &&
        type != DEGENERATE_SID) {
        return BAD_FUNC_ARG;
    }

    pkcs7->sidType = type;

    return 0;
}


/* Set custom contentType, currently supported with SignedData type
 *
 * pkcs7       - pointer to initialized PKCS7 structure
 * contentType - pointer to array with ASN.1 encoded OID value
 * sz          - length of contentType array, octets
 *
 * return 0 on success, negative upon error */
int wc_PKCS7_SetContentType(wc_PKCS7* pkcs7, byte* contentType, word32 sz)
{
    if (pkcs7 == NULL || contentType == NULL || sz == 0)
        return BAD_FUNC_ARG;

    if (sz > MAX_OID_SZ) {
        WOLFSSL_MSG("input array too large, bounded by MAX_OID_SZ");
        return BAD_FUNC_ARG;
    }

    XMEMCPY(pkcs7->contentType, contentType, sz);
    pkcs7->contentTypeSz = sz;

    return 0;
}


/* return size of padded data, padded to blockSz chunks, or negative on error */
int wc_PKCS7_GetPadSize(word32 inputSz, word32 blockSz)
{
    word32 padSz;

    if (blockSz == 0)
        return BAD_FUNC_ARG;

    padSz = blockSz - (inputSz % blockSz);

    return (int)padSz;
}


/* pad input data to blockSz chunk, place in outSz. out must be big enough
 * for input + pad bytes. See wc_PKCS7_GetPadSize() helper. */
int wc_PKCS7_PadData(byte* in, word32 inSz, byte* out, word32 outSz,
                     word32 blockSz)
{
    int ret;
    word32 i, padSz;

    if (in == NULL  || inSz == 0 ||
        out == NULL || outSz == 0)
        return BAD_FUNC_ARG;

    ret = wc_PKCS7_GetPadSize(inSz, blockSz);
    if (ret < 0)
        return ret;
    padSz = (word32)ret;

    if (outSz < (inSz + padSz))
        return BAD_FUNC_ARG;

    XMEMCPY(out, in, inSz);

    for (i = 0; i < padSz; i++) {
        out[inSz + i] = (byte)padSz;
    }

    return (int)(inSz + padSz);
}


/* Encode and add CMS EnvelopedData ORI (OtherRecipientInfo) RecipientInfo
 * to CMS/PKCS#7 EnvelopedData structure.
 *
 * Return 0 on success, negative upon error */
int wc_PKCS7_AddRecipient_ORI(wc_PKCS7* pkcs7, CallbackOriEncrypt oriEncryptCb,
                              int options)
{
    int oriTypeLenSz, blockKeySz, ret;
    word32 idx, recipSeqSz;

    Pkcs7EncodedRecip* recip = NULL;
    Pkcs7EncodedRecip* lastRecip = NULL;

    byte recipSeq[MAX_SEQ_SZ];
    byte oriTypeLen[MAX_LENGTH_SZ];

    byte oriType[MAX_ORI_TYPE_SZ];
    byte oriValue[MAX_ORI_VALUE_SZ];
    word32 oriTypeSz = MAX_ORI_TYPE_SZ;
    word32 oriValueSz = MAX_ORI_VALUE_SZ;

    if (pkcs7 == NULL || oriEncryptCb == NULL) {
        return BAD_FUNC_ARG;
    }

    /* allocate memory for RecipientInfo, KEK, encrypted key */
    recip = (Pkcs7EncodedRecip*)XMALLOC(sizeof(Pkcs7EncodedRecip),
                                        pkcs7->heap, DYNAMIC_TYPE_PKCS7);
    if (recip == NULL)
        return MEMORY_E;
    XMEMSET(recip, 0, sizeof(Pkcs7EncodedRecip));

    /* get key size for content-encryption key based on algorithm */
    blockKeySz = wc_PKCS7_GetOIDKeySize(pkcs7->encryptOID);
    if (blockKeySz < 0) {
        XFREE(recip, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return blockKeySz;
    }

    /* generate random content encryption key, if needed */
    ret = PKCS7_GenerateContentEncryptionKey(pkcs7, (word32)blockKeySz);
    if (ret < 0) {
        XFREE(recip, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return ret;
    }

    /* call user callback to encrypt CEK and get oriType and oriValue
       values back */
    ret = oriEncryptCb(pkcs7, pkcs7->cek, pkcs7->cekSz, oriType, &oriTypeSz,
                       oriValue, &oriValueSz, pkcs7->oriEncryptCtx);
    if (ret != 0) {
        XFREE(recip, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return ret;
    }

    oriTypeLenSz = (int)SetLength(oriTypeSz, oriTypeLen);

    recipSeqSz = SetImplicit(ASN_SEQUENCE, 4, 1 + (word32)oriTypeLenSz +
                             oriTypeSz + oriValueSz, recipSeq, 0);

    idx = 0;
    XMEMCPY(recip->recip + idx, recipSeq, recipSeqSz);
    idx += recipSeqSz;
    /* oriType */
    recip->recip[idx] = ASN_OBJECT_ID;
    idx += 1;
    XMEMCPY(recip->recip + idx, oriTypeLen, (word32)oriTypeLenSz);
    idx += (word32)oriTypeLenSz;
    XMEMCPY(recip->recip + idx, oriType, oriTypeSz);
    idx += oriTypeSz;
    /* oriValue, input MUST already be ASN.1 encoded */
    XMEMCPY(recip->recip + idx, oriValue, oriValueSz);
    idx += oriValueSz;

    /* store recipient size */
    recip->recipSz = idx;
    recip->recipType = PKCS7_ORI;
    recip->recipVersion = 4;

    /* add recipient to recip list */
    if (pkcs7->recipList == NULL) {
        pkcs7->recipList = recip;
    } else {
        lastRecip = pkcs7->recipList;
        while (lastRecip->next != NULL) {
            lastRecip = lastRecip->next;
        }
        lastRecip->next = recip;
    }

    (void)options;

    return (int)idx;
}

#if !defined(NO_PWDBASED) && !defined(NO_SHA)


static int wc_PKCS7_GenerateKEK_PWRI(wc_PKCS7* pkcs7, byte* passwd, word32 pLen,
                                     byte* salt, word32 saltSz, int kdfOID,
                                     int prfOID, int iterations, byte* out,
                                     word32 outSz)
{
    int ret;

    if (pkcs7 == NULL || passwd == NULL || salt == NULL || out == NULL)
        return BAD_FUNC_ARG;

    switch (kdfOID) {

        case PBKDF2_OID:

            ret = wc_PBKDF2(out, passwd, (int)pLen, salt, (int)saltSz,
                            iterations, (int)outSz, prfOID);
            if (ret != 0) {
                return ret;
            }

            break;

        default:
            WOLFSSL_MSG("Unsupported KDF OID");
            return PKCS7_OID_E;
    }

    return 0;
}


/* RFC3211 (Section 2.3.1) key wrap algorithm (id-alg-PWRI-KEK).
 *
 * Returns output size on success, negative upon error */
static int wc_PKCS7_PwriKek_KeyWrap(wc_PKCS7* pkcs7, const byte* kek, word32 kekSz,
                                    const byte* cek, word32 cekSz,
                                    byte* out, word32 *outSz,
                                    const byte* iv, word32 ivSz, int algID)
{
    WC_RNG rng;
    int blockSz, outLen, ret;
    word32 padSz;
    byte* lastBlock;

    if (kek == NULL || cek == NULL || iv == NULL || outSz == NULL)
        return BAD_FUNC_ARG;

    /* get encryption algorithm block size */
    blockSz = wc_PKCS7_GetOIDBlockSize(algID);
    if (blockSz <= 0) {
        if (blockSz < 0)
            return blockSz;
        else
            return ALGO_ID_E;
    }

    /* get pad bytes needed to block boundary */
    padSz = (word32)blockSz - ((4 + cekSz) % (word32)blockSz);
    outLen = (int)(4 + cekSz + padSz);

    /* must be at least two blocks long */
    if (outLen < 2 * blockSz)
        padSz += (word32)blockSz;

    /* if user set out to NULL, give back required length */
    if (out == NULL) {
        *outSz = (word32)outLen;
        return WC_NO_ERR_TRACE(LENGTH_ONLY_E);
    }

    /* verify output buffer is large enough */
    if (*outSz < (word32)outLen)
        return BUFFER_E;

    out[0] = (byte)cekSz;
    out[1] = (byte)~cek[0];
    out[2] = (byte)~cek[1];
    out[3] = (byte)~cek[2];
    XMEMCPY(out + 4, cek, cekSz);

    /* random padding of size padSz */
    ret = wc_InitRng_ex(&rng, pkcs7->heap, pkcs7->devId);
    if (ret != 0)
        return ret;

    ret = wc_RNG_GenerateBlock(&rng, out + 4 + cekSz, padSz);

    if (ret == 0) {
        /* encrypt, normal */
        ret = wc_PKCS7_EncryptContent(pkcs7, algID, (byte*)kek, (int)kekSz,
                                      (byte*)iv, (int)ivSz, NULL, 0, NULL, 0, out,
                                      outLen, out);
    }

    if (ret == 0) {
        /* encrypt again, using last ciphertext block as IV */
        lastBlock = out + (((outLen / blockSz) - 1) * blockSz);
        ret = wc_PKCS7_EncryptContent(pkcs7, algID, (byte*)kek, (int)kekSz,
                                      lastBlock, blockSz, NULL, 0, NULL, 0, out,
                                      outLen, out);
    }

    if (ret == 0) {
        *outSz = (word32)outLen;
    } else {
        outLen = ret;
    }

    wc_FreeRng(&rng);

    return outLen;
}


/* RFC3211 (Section 2.3.2) key unwrap algorithm (id-alg-PWRI-KEK).
 *
 * Returns cek size on success, negative upon error */
static int wc_PKCS7_PwriKek_KeyUnWrap(wc_PKCS7* pkcs7, const byte* kek,
                                      word32 kekSz, const byte* in, word32 inSz,
                                      byte* out, word32 outSz, const byte* iv,
                                      word32 ivSz, int algID)
{
    int blockSz, cekLen, ret;
    byte* tmpIv     = NULL;
    byte* lastBlock = NULL;
    byte* outTmp    = NULL;

    if (pkcs7 == NULL || kek == NULL || in == NULL ||
        out == NULL || iv == NULL) {
        return BAD_FUNC_ARG;
    }

    outTmp = (byte*)XMALLOC(inSz, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (outTmp == NULL)
        return MEMORY_E;

    /* get encryption algorithm block size */
    blockSz = wc_PKCS7_GetOIDBlockSize(algID);
    if (blockSz <= 0) {
        XFREE(outTmp, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (blockSz < 0)
            return blockSz;
        else
            return ALGO_ID_E;
    }

    /* input needs to be blockSz multiple and at least 2 * blockSz */
    if (((inSz % (word32)blockSz) != 0) || (inSz < (2 * (word32)blockSz))) {
        WOLFSSL_MSG("PWRI-KEK unwrap input must of block size and >= 2 "
                    "times block size");
        XFREE(outTmp, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        return BAD_FUNC_ARG;
    }

    /* use block out[n-1] as IV to decrypt block out[n] */
    lastBlock = (byte*)in + inSz - blockSz;
    tmpIv = lastBlock - blockSz;

    /* decrypt last block */
    ret = wc_PKCS7_DecryptContent(pkcs7, algID, (byte*)kek, (int)kekSz, tmpIv,
            blockSz, NULL, 0, NULL, 0, lastBlock, blockSz,
            outTmp + inSz - blockSz, pkcs7->devId, pkcs7->heap);

    if (ret == 0) {
        /* using last decrypted block as IV, decrypt [0 ... n-1] blocks */
        lastBlock = outTmp + inSz - blockSz;
        ret = wc_PKCS7_DecryptContent(pkcs7, algID, (byte*)kek, (int)kekSz,
                lastBlock, blockSz, NULL, 0, NULL, 0, (byte*)in,
                (int)inSz - blockSz, outTmp, pkcs7->devId, pkcs7->heap);
    }

    if (ret == 0) {
        /* decrypt using original kek and iv */
        ret = wc_PKCS7_DecryptContent(pkcs7, algID, (byte*)kek, (int)kekSz,
                (byte*)iv, (int)ivSz, NULL, 0, NULL, 0, outTmp, (int)inSz,
                outTmp, pkcs7->devId, pkcs7->heap);
    }

    if (ret != 0) {
        ForceZero(outTmp, inSz);
        XFREE(outTmp, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }

    cekLen = outTmp[0];

    /* verify length */
    if ((word32)cekLen > inSz) {
        ForceZero(outTmp, inSz);
        XFREE(outTmp, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        return BAD_FUNC_ARG;
    }

    /* verify check bytes */
    if ((outTmp[1] ^ outTmp[4]) != 0xFF ||
        (outTmp[2] ^ outTmp[5]) != 0xFF ||
        (outTmp[3] ^ outTmp[6]) != 0xFF) {
        ForceZero(outTmp, inSz);
        XFREE(outTmp, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        return BAD_FUNC_ARG;
    }

    if (outSz < (word32)cekLen) {
        ForceZero(outTmp, inSz);
        XFREE(outTmp, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        return BUFFER_E;
    }

    XMEMCPY(out, outTmp + 4, outTmp[0]);
    ForceZero(outTmp, inSz);
    XFREE(outTmp, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);

    return cekLen;
}


/* Encode and add CMS EnvelopedData PWRI (PasswordRecipientInfo) RecipientInfo
 * to CMS/PKCS#7 EnvelopedData structure.
 *
 * Return 0 on success, negative upon error */
int wc_PKCS7_AddRecipient_PWRI(wc_PKCS7* pkcs7, byte* passwd, word32 pLen,
                               byte* salt, word32 saltSz, int kdfOID,
                               int hashOID, int iterations, int kekEncryptOID,
                               int options)
{
    Pkcs7EncodedRecip* recip = NULL;
    Pkcs7EncodedRecip* lastRecip = NULL;

    /* PasswordRecipientInfo */
    byte recipSeq[MAX_SEQ_SZ];
    byte ver[MAX_VERSION_SZ];
    word32 recipSeqSz, verSz;

    /* KeyDerivationAlgorithmIdentifier */
    byte kdfAlgoIdSeq[MAX_SEQ_SZ];
    byte kdfAlgoId[MAX_OID_SZ];
    byte kdfParamsSeq[MAX_SEQ_SZ];              /* PBKDF2-params */
    byte kdfSaltOctetStr[MAX_OCTET_STR_SZ];     /* salt OCTET STRING */
    byte kdfIterations[MAX_VERSION_SZ];
    word32 kdfAlgoIdSeqSz, kdfAlgoIdSz;
    word32 kdfParamsSeqSz, kdfSaltOctetStrSz, kdfIterationsSz;
    /* OPTIONAL: keyLength, not supported yet */
    /* OPTIONAL: prf AlgorithmIdentifier, not supported yet */

    /* KeyEncryptionAlgorithmIdentifier */
    byte keyEncAlgoIdSeq[MAX_SEQ_SZ];
    byte keyEncAlgoId[MAX_OID_SZ];              /* id-alg-PWRI-KEK */
    byte pwriEncAlgoId[MAX_ALGO_SZ];
    byte ivOctetString[MAX_OCTET_STR_SZ];
    word32 keyEncAlgoIdSeqSz, keyEncAlgoIdSz;
    word32 pwriEncAlgoIdSz, ivOctetStringSz;

    /* EncryptedKey */
    byte encKeyOctetStr[MAX_OCTET_STR_SZ];
    word32 encKeyOctetStrSz;

    byte tmpIv[MAX_CONTENT_IV_SIZE];
    byte* encryptedKey = NULL;
    byte* kek = NULL;

    int cekKeySz = 0, kekKeySz = 0, kekBlockSz = 0, ret = 0;
    int encryptOID;
    word32 idx, totalSz = 0, encryptedKeySz;

    if (pkcs7 == NULL || passwd == NULL || pLen == 0 ||
        salt == NULL || saltSz == 0) {
        return BAD_FUNC_ARG;
    }

    /* allow user to use different KEK encryption algorithm than used for
     * main content encryption algorithm, if passed in */
    if (kekEncryptOID != 0) {
        encryptOID = kekEncryptOID;
    } else {
        encryptOID = pkcs7->encryptOID;
    }

    /* get content-encryption key size, based on algorithm */
    cekKeySz = wc_PKCS7_GetOIDKeySize(pkcs7->encryptOID);
    if (cekKeySz < 0)
        return cekKeySz;

    /* get KEK encryption key size, based on algorithm */
    if (encryptOID != pkcs7->encryptOID) {
        kekKeySz = wc_PKCS7_GetOIDKeySize(encryptOID);
    } else {
        kekKeySz = cekKeySz;
    }

    /* get KEK encryption block size */
    kekBlockSz = wc_PKCS7_GetOIDBlockSize(encryptOID);
    if (kekBlockSz < 0)
        return kekBlockSz;

    /* generate random CEK */
    ret = PKCS7_GenerateContentEncryptionKey(pkcs7, (word32)cekKeySz);
    if (ret < 0)
        return ret;

    /* generate random IV */
    ret = wc_PKCS7_GenerateBlock(pkcs7, NULL, tmpIv, (word32)kekBlockSz);
    if (ret != 0)
        return ret;

    /* allocate memory for RecipientInfo, KEK, encrypted key */
    recip = (Pkcs7EncodedRecip*)XMALLOC(sizeof(Pkcs7EncodedRecip),
                                        pkcs7->heap, DYNAMIC_TYPE_PKCS7);
    if (recip == NULL)
        return MEMORY_E;

    kek = (byte*)XMALLOC((word32)kekKeySz, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
    if (kek == NULL) {
        XFREE(recip, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return MEMORY_E;
    }

    encryptedKey = (byte*)XMALLOC(MAX_ENCRYPTED_KEY_SZ,
                                  pkcs7->heap, DYNAMIC_TYPE_PKCS7);
    if (encryptedKey == NULL) {
        XFREE(recip, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        XFREE(kek, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return MEMORY_E;
    }

    encryptedKeySz = MAX_ENCRYPTED_KEY_SZ;
    XMEMSET(recip, 0, sizeof(Pkcs7EncodedRecip));
    XMEMSET(kek, 0, (word32)kekKeySz);
    XMEMSET(encryptedKey, 0, encryptedKeySz);

    /* generate KEK: expand password into KEK */
    ret = wc_PKCS7_GenerateKEK_PWRI(pkcs7, passwd, pLen, salt, saltSz,
                                    kdfOID, hashOID, iterations, kek,
                                    (word32)kekKeySz);
    if (ret < 0) {
        XFREE(recip, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        XFREE(kek, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return ret;
    }

    /* generate encrypted key: encrypt CEK with KEK */
    ret = wc_PKCS7_PwriKek_KeyWrap(pkcs7, kek, (word32)kekKeySz, pkcs7->cek,
                                   pkcs7->cekSz, encryptedKey, &encryptedKeySz,
                                   tmpIv, (word32)kekBlockSz, encryptOID);
    if (ret < 0) {
        XFREE(recip, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        XFREE(kek, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return ret;
    }
    encryptedKeySz = (word32)ret;

    /* put together encrypted key OCTET STRING */
    encKeyOctetStrSz = SetOctetString(encryptedKeySz, encKeyOctetStr);
    totalSz += (encKeyOctetStrSz + encryptedKeySz);

    /* put together IV OCTET STRING */
    ivOctetStringSz = SetOctetString((word32)kekBlockSz, ivOctetString);
    totalSz += (ivOctetStringSz + (word32)kekBlockSz);

    /* set PWRIAlgorithms AlgorithmIdentifier, adding (ivOctetStringSz +
       blockKeySz) for IV OCTET STRING */
    pwriEncAlgoIdSz = SetAlgoID(encryptOID, pwriEncAlgoId,
                                oidBlkType, (int)ivOctetStringSz + kekBlockSz);
    totalSz += pwriEncAlgoIdSz;

    /* set KeyEncryptionAlgorithms OID */
    ret = wc_SetContentType(PWRI_KEK_WRAP, keyEncAlgoId, sizeof(keyEncAlgoId));
    if (ret <= 0) {
        XFREE(recip, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        XFREE(kek, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return ret;
    }
    keyEncAlgoIdSz = (word32)ret;
    totalSz += keyEncAlgoIdSz;

    /* KeyEncryptionAlgorithm SEQ */
    keyEncAlgoIdSeqSz = SetSequence(keyEncAlgoIdSz + pwriEncAlgoIdSz +
                                    ivOctetStringSz + (word32)kekBlockSz,
                                    keyEncAlgoIdSeq);
    totalSz += keyEncAlgoIdSeqSz;

    /* set KDF salt */
    kdfSaltOctetStrSz = SetOctetString(saltSz, kdfSaltOctetStr);
    totalSz += (kdfSaltOctetStrSz + saltSz);

    /* set KDF iteration count */
    kdfIterationsSz = (word32)SetMyVersion((word32)iterations, kdfIterations, 0);
    totalSz += kdfIterationsSz;

    /* set KDF params SEQ */
    kdfParamsSeqSz = SetSequence(kdfSaltOctetStrSz + saltSz + kdfIterationsSz,
                                 kdfParamsSeq);
    totalSz += kdfParamsSeqSz;

    /* set KDF algo OID */
    ret = wc_SetContentType(kdfOID, kdfAlgoId, sizeof(kdfAlgoId));
    if (ret <= 0) {
        XFREE(recip, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        XFREE(kek, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return ret;
    }
    kdfAlgoIdSz = (word32)ret;
    totalSz += kdfAlgoIdSz;

    /* set KeyDerivationAlgorithmIdentifier EXPLICIT [0] SEQ */
    kdfAlgoIdSeqSz = SetExplicit(0, kdfAlgoIdSz + kdfParamsSeqSz +
                                 kdfSaltOctetStrSz + saltSz + kdfIterationsSz,
                                 kdfAlgoIdSeq, 0);
    totalSz += kdfAlgoIdSeqSz;

    /* set PasswordRecipientInfo CMSVersion, MUST be 0 */
    verSz = (word32)SetMyVersion(0, ver, 0);
    totalSz += verSz;
    recip->recipVersion = 0;

    /* set PasswordRecipientInfo SEQ */
    recipSeqSz = SetImplicit(ASN_SEQUENCE, 3, totalSz, recipSeq, 0);
    totalSz += recipSeqSz;

    if (totalSz > MAX_RECIP_SZ) {
        WOLFSSL_MSG("CMS Recipient output buffer too small");
        XFREE(recip, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        XFREE(kek, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return BUFFER_E;
    }

    idx = 0;
    XMEMCPY(recip->recip + idx, recipSeq, recipSeqSz);
    idx += recipSeqSz;
    XMEMCPY(recip->recip + idx, ver, verSz);
    idx += verSz;
    XMEMCPY(recip->recip + idx, kdfAlgoIdSeq, kdfAlgoIdSeqSz);
    idx += kdfAlgoIdSeqSz;
    XMEMCPY(recip->recip + idx, kdfAlgoId, kdfAlgoIdSz);
    idx += kdfAlgoIdSz;
    XMEMCPY(recip->recip + idx, kdfParamsSeq, kdfParamsSeqSz);
    idx += kdfParamsSeqSz;
    XMEMCPY(recip->recip + idx, kdfSaltOctetStr, kdfSaltOctetStrSz);
    idx += kdfSaltOctetStrSz;
    XMEMCPY(recip->recip + idx, salt, saltSz);
    idx += saltSz;
    XMEMCPY(recip->recip + idx, kdfIterations, kdfIterationsSz);
    idx += kdfIterationsSz;
    XMEMCPY(recip->recip + idx, keyEncAlgoIdSeq, keyEncAlgoIdSeqSz);
    idx += keyEncAlgoIdSeqSz;
    XMEMCPY(recip->recip + idx, keyEncAlgoId, keyEncAlgoIdSz);
    idx += keyEncAlgoIdSz;
    XMEMCPY(recip->recip + idx, pwriEncAlgoId, pwriEncAlgoIdSz);
    idx += pwriEncAlgoIdSz;
    XMEMCPY(recip->recip + idx, ivOctetString, ivOctetStringSz);
    idx += ivOctetStringSz;
    XMEMCPY(recip->recip + idx, tmpIv, (word32)kekBlockSz);
    idx += (word32)kekBlockSz;
    XMEMCPY(recip->recip + idx, encKeyOctetStr, encKeyOctetStrSz);
    idx += encKeyOctetStrSz;
    XMEMCPY(recip->recip + idx, encryptedKey, encryptedKeySz);
    idx += encryptedKeySz;

    ForceZero(kek, (word32)kekBlockSz);
    ForceZero(encryptedKey, encryptedKeySz);
    XFREE(kek, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
    XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_PKCS7);

    /* store recipient size */
    recip->recipSz = idx;
    recip->recipType = PKCS7_PWRI;

    /* add recipient to recip list */
    if (pkcs7->recipList == NULL) {
        pkcs7->recipList = recip;
    } else {
        lastRecip = pkcs7->recipList;
        while (lastRecip->next != NULL) {
            lastRecip = lastRecip->next;
        }
        lastRecip->next = recip;
    }

    (void)options;

    return (int)idx;
}

/* Import password and KDF settings into a PKCS7 structure. Used for setting
 * the password info for decryption a EnvelopedData PWRI RecipientInfo.
 *
 * Returns 0 on success, negative upon error */
int wc_PKCS7_SetPassword(wc_PKCS7* pkcs7, byte* passwd, word32 pLen)
{
    if (pkcs7 == NULL || passwd == NULL || pLen == 0)
        return BAD_FUNC_ARG;

    pkcs7->pass = passwd;
    pkcs7->passSz = pLen;

    return 0;
}

#endif /* NO_PWDBASED */


/* Encode and add CMS EnvelopedData KEKRI (KEKRecipientInfo) RecipientInfo
 * to CMS/PKCS#7 EnvelopedData structure.
 *
 * pkcs7 - pointer to initialized PKCS7 structure
 * keyWrapOID - OID sum of key wrap algorithm identifier
 * kek        - key encryption key
 * kekSz      - size of kek, bytes
 * keyID      - key-encryption key identifier, pre-distributed to endpoints
 * keyIDSz    - size of keyID, bytes
 * timePtr    - pointer to "time_t", which is typically "long" (OPTIONAL)
 * otherOID   - ASN.1 encoded OID of other attribute (OPTIONAL)
 * otherOIDSz - size of otherOID, bytes (OPTIONAL)
 * other      - other attribute (OPTIONAL)
 * otherSz    - size of other (OPTIONAL)
 *
 * Returns 0 on success, negative upon error */
int wc_PKCS7_AddRecipient_KEKRI(wc_PKCS7* pkcs7, int keyWrapOID, byte* kek,
                                word32 kekSz, byte* keyId, word32 keyIdSz,
                                void* timePtr, byte* otherOID,
                                word32 otherOIDSz, byte* other, word32 otherSz,
                                int options)
{
    Pkcs7EncodedRecip* recip = NULL;
    Pkcs7EncodedRecip* lastRecip = NULL;

    byte recipSeq[MAX_SEQ_SZ];
    byte ver[MAX_VERSION_SZ];
    byte kekIdSeq[MAX_SEQ_SZ];
    byte kekIdOctetStr[MAX_OCTET_STR_SZ];
    byte genTime[ASN_GENERALIZED_TIME_SIZE];
    byte otherAttSeq[MAX_SEQ_SZ];
    byte encAlgoId[MAX_ALGO_SZ];
    byte encKeyOctetStr[MAX_OCTET_STR_SZ];
#ifdef WOLFSSL_SMALL_STACK
    byte* encryptedKey;
#else
    byte encryptedKey[MAX_ENCRYPTED_KEY_SZ];
#endif

    int blockKeySz = 0, ret = 0, direction;
    word32 idx = 0;
    word32 totalSz = 0;
    word32 recipSeqSz = 0, verSz = 0;
    word32 kekIdSeqSz = 0, kekIdOctetStrSz = 0;
    word32 otherAttSeqSz = 0, encAlgoIdSz = 0, encKeyOctetStrSz = 0;
    int encryptedKeySz;

    int timeSz = 0;
#ifndef NO_ASN_TIME
    time_t* tm = NULL;
#endif

    if (pkcs7 == NULL || kek == NULL || keyId == NULL)
        return BAD_FUNC_ARG;

    recip = (Pkcs7EncodedRecip*)XMALLOC(sizeof(Pkcs7EncodedRecip), pkcs7->heap,
                                 DYNAMIC_TYPE_PKCS7);
    if (recip == NULL)
        return MEMORY_E;

    XMEMSET(recip, 0, sizeof(Pkcs7EncodedRecip));

    /* get key size for content-encryption key based on algorithm */
    blockKeySz = wc_PKCS7_GetOIDKeySize(pkcs7->encryptOID);
    if (blockKeySz < 0) {
        XFREE(recip, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return blockKeySz;
    }

    /* generate random content encryption key, if needed */
    ret = PKCS7_GenerateContentEncryptionKey(pkcs7, (word32)blockKeySz);
    if (ret < 0) {
        XFREE(recip, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return ret;
    }

    /* EncryptedKey */
#ifdef WOLFSSL_SMALL_STACK
    encryptedKey = (byte*)XMALLOC(MAX_ENCRYPTED_KEY_SZ, pkcs7->heap,
                                  DYNAMIC_TYPE_PKCS7);
    if (encryptedKey == NULL) {
        XFREE(recip, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return MEMORY_E;
    }
#endif
    encryptedKeySz = MAX_ENCRYPTED_KEY_SZ;
    XMEMSET(encryptedKey, 0, (word32)encryptedKeySz);

    #ifndef NO_AES
        direction = AES_ENCRYPTION;
    #else
        direction = DES_ENCRYPTION;
    #endif

    encryptedKeySz = wc_PKCS7_KeyWrap(pkcs7->cek, pkcs7->cekSz, kek, kekSz,
                                      encryptedKey, (word32)encryptedKeySz, keyWrapOID,
                                      direction);
    if (encryptedKeySz < 0) {
    #ifdef WOLFSSL_SMALL_STACK
        XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
    #endif
        XFREE(recip, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return encryptedKeySz;
    }
    /* handle a zero size encKey case as WC_KEY_SIZE_E */
    if (encryptedKeySz == 0 || encryptedKeySz > MAX_ENCRYPTED_KEY_SZ) {
    #ifdef WOLFSSL_SMALL_STACK
        XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
    #endif
        XFREE(recip, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return WC_KEY_SIZE_E;
    }

    encKeyOctetStrSz = SetOctetString((word32)encryptedKeySz, encKeyOctetStr);
    totalSz += (encKeyOctetStrSz + (word32)encryptedKeySz);

    /* KeyEncryptionAlgorithmIdentifier */
    encAlgoIdSz = SetAlgoID(keyWrapOID, encAlgoId, oidKeyWrapType, 0);
    totalSz += encAlgoIdSz;

    /* KEKIdentifier: keyIdentifier */
    kekIdOctetStrSz = SetOctetString(keyIdSz, kekIdOctetStr);
    totalSz += (kekIdOctetStrSz + keyIdSz);

    /* KEKIdentifier: GeneralizedTime (OPTIONAL) */
#ifndef NO_ASN_TIME
    if (timePtr != NULL) {
        tm = (time_t*)timePtr;
        timeSz = GetAsnTimeString(tm, genTime, sizeof(genTime));
        if (timeSz < 0) {
            XFREE(recip, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        #ifdef WOLFSSL_SMALL_STACK
            XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        #endif
            return timeSz;
        }
        totalSz += (word32)timeSz;
    }
#endif

    /* KEKIdentifier: OtherKeyAttribute SEQ (OPTIONAL) */
    if (other != NULL && otherSz > 0) {
        otherAttSeqSz = SetSequence(otherOIDSz + otherSz, otherAttSeq);
        totalSz += otherAttSeqSz + otherOIDSz + otherSz;
    }

    /* KEKIdentifier SEQ */
    kekIdSeqSz = SetSequence(kekIdOctetStrSz + keyIdSz + (word32)timeSz +
                             otherAttSeqSz + otherOIDSz + otherSz, kekIdSeq);
    totalSz += kekIdSeqSz;

    /* version */
    verSz = (word32)SetMyVersion(4, ver, 0);
    totalSz += verSz;
    recip->recipVersion = 4;

    /* KEKRecipientInfo SEQ */
    recipSeqSz = SetImplicit(ASN_SEQUENCE, 2, totalSz, recipSeq, 0);
    totalSz += recipSeqSz;

    if (totalSz > MAX_RECIP_SZ) {
        WOLFSSL_MSG("CMS Recipient output buffer too small");
        XFREE(recip, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
    #ifdef WOLFSSL_SMALL_STACK
        XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
    #endif
        return BUFFER_E;
    }

    XMEMCPY(recip->recip + idx, recipSeq, recipSeqSz);
    idx += recipSeqSz;
    XMEMCPY(recip->recip + idx, ver, verSz);
    idx += verSz;
    XMEMCPY(recip->recip + idx, kekIdSeq, kekIdSeqSz);
    idx += kekIdSeqSz;
    XMEMCPY(recip->recip + idx, kekIdOctetStr, kekIdOctetStrSz);
    idx += kekIdOctetStrSz;
    XMEMCPY(recip->recip + idx, keyId, keyIdSz);
    idx += keyIdSz;
    if (timePtr != NULL) {
        XMEMCPY(recip->recip + idx, genTime, (word32)timeSz);
        idx += (word32)timeSz;
    }
    if (other != NULL && otherSz > 0) {
        XMEMCPY(recip->recip + idx, otherAttSeq, otherAttSeqSz);
        idx += otherAttSeqSz;
        XMEMCPY(recip->recip + idx, otherOID, otherOIDSz);
        idx += otherOIDSz;
        XMEMCPY(recip->recip + idx, other, otherSz);
        idx += otherSz;
    }
    XMEMCPY(recip->recip + idx, encAlgoId, encAlgoIdSz);
    idx += encAlgoIdSz;
    XMEMCPY(recip->recip + idx, encKeyOctetStr, encKeyOctetStrSz);
    idx += encKeyOctetStrSz;
    XMEMCPY(recip->recip + idx, encryptedKey, (word32)encryptedKeySz);
    idx += (word32)encryptedKeySz;

#ifdef WOLFSSL_SMALL_STACK
    XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
#endif

    /* store recipient size */
    recip->recipSz = idx;
    recip->recipType = PKCS7_KEKRI;

    /* add recipient to recip list */
    if (pkcs7->recipList == NULL) {
        pkcs7->recipList = recip;
    } else {
        lastRecip = pkcs7->recipList;
        while(lastRecip->next != NULL) {
            lastRecip = lastRecip->next;
        }
        lastRecip->next = recip;
    }

    (void)options;

    return (int)idx;
}


static int wc_PKCS7_GetCMSVersion(wc_PKCS7* pkcs7, int cmsContentType)
{
    int version = -1;

    if (pkcs7 == NULL)
        return BAD_FUNC_ARG;

    switch (cmsContentType) {
        case ENVELOPED_DATA:

            /* NOTE: EnvelopedData does not currently support
               originatorInfo or unprotectedAttributes. When either of these
               are added, version checking below needs to be updated to match
               Section 6.1 of RFC 5652 */

            /* if RecipientInfos include pwri or ori, version is 3 */
            if (wc_PKCS7_RecipientListIncludesType(pkcs7, PKCS7_PWRI) ||
                wc_PKCS7_RecipientListIncludesType(pkcs7, PKCS7_ORI)) {
                version = 3;
                break;
            }

            /* if unprotectedAttrs is absent AND all RecipientInfo structs
               are version 0, version is 0 */
            if (wc_PKCS7_RecipientListVersionsAllZero(pkcs7)) {
                version = 0;
                break;
            }

            /* otherwise, version is 2 */
            version = 2;
            break;

        default:
            break;
    }

    return version;
}


/* build PKCS#7 envelopedData content type, return enveloped size */
int wc_PKCS7_EncodeEnvelopedData(wc_PKCS7* pkcs7, byte* output, word32 outputSz)
{
    int ret, idx = 0;
    int totalSz, padSz, encryptedOutSz;

    int contentInfoSeqSz = 0, outerContentTypeSz = 0, outerContentSz;
    byte contentInfoSeq[MAX_SEQ_SZ];
    byte outerContentType[MAX_ALGO_SZ];
    byte outerContent[MAX_SEQ_SZ];

    int kariVersion;
    int envDataSeqSz, verSz;
    byte envDataSeq[MAX_SEQ_SZ];
    byte ver[MAX_VERSION_SZ];

    WC_RNG rng;
    int blockSz, blockKeySz;
    byte* plain            = NULL;
    byte* encryptedContent = NULL;

    Pkcs7EncodedRecip* tmpRecip = NULL;
    int recipSz, recipSetSz;
    byte recipSet[MAX_SET_SZ];

    int encContentOctetSz, encContentSeqSz, contentTypeSz;
    int contentEncAlgoSz, ivOctetStringSz;
    byte encContentSeq[MAX_SEQ_SZ];
    byte contentType[MAX_ALGO_SZ];
    byte contentEncAlgo[MAX_ALGO_SZ];
    byte tmpIv[MAX_CONTENT_IV_SIZE];
    byte ivOctetString[MAX_OCTET_STR_SZ];
    byte encContentOctet[MAX_OCTET_STR_SZ];
#ifdef ASN_BER_TO_DER
    word32 streamSz = 0;
#endif

    if (pkcs7 == NULL
        #ifndef ASN_BER_TO_DER
            || pkcs7->content == NULL
        #endif
            || pkcs7->contentSz == 0) {
        return BAD_FUNC_ARG;
    }

#ifndef ASN_BER_TO_DER
    if (output == NULL || outputSz == 0) {
        return BAD_FUNC_ARG;
    }
#else
    /* if both output and callback are not set then error out */
    if ((output == NULL || outputSz == 0) && (pkcs7->streamOutCb == NULL)) {
        return BAD_FUNC_ARG;
    }
#endif

    blockKeySz = wc_PKCS7_GetOIDKeySize(pkcs7->encryptOID);
    if (blockKeySz < 0)
        return blockKeySz;

    blockSz = wc_PKCS7_GetOIDBlockSize(pkcs7->encryptOID);
    if (blockSz < 0)
        return blockSz;

    if (pkcs7->contentOID != FIRMWARE_PKG_DATA) {
        /* outer content type */
        ret = wc_SetContentType(ENVELOPED_DATA, outerContentType,
                                sizeof(outerContentType));
        if (ret < 0)
            return ret;

        outerContentTypeSz = ret;
    }

    /* generate random content encryption key */
    ret = PKCS7_GenerateContentEncryptionKey(pkcs7, (word32)blockKeySz);
    if (ret != 0) {
        return ret;
    }

    /* build RecipientInfo, only if user manually set singleCert and size */
    if (pkcs7->singleCert != NULL && pkcs7->singleCertSz > 0) {
        switch (pkcs7->publicKeyOID) {
        #ifndef NO_RSA
            case RSAk:
                ret = wc_PKCS7_AddRecipient_KTRI(pkcs7, pkcs7->singleCert,
                                                 pkcs7->singleCertSz, 0);
                break;
        #endif
        #ifdef HAVE_ECC
            case ECDSAk:
                ret = wc_PKCS7_AddRecipient_KARI(pkcs7, pkcs7->singleCert,
                                                 pkcs7->singleCertSz,
                                                 pkcs7->keyWrapOID,
                                                 pkcs7->keyAgreeOID, pkcs7->ukm,
                                                 pkcs7->ukmSz, 0);
                break;
        #endif

            default:
                WOLFSSL_MSG("Unsupported RecipientInfo public key type");
                return BAD_FUNC_ARG;
        };

        if (ret < 0) {
            WOLFSSL_MSG("Failed to create RecipientInfo");
            return ret;
        }
    }

    recipSz = wc_PKCS7_GetRecipientListSize(pkcs7);
    if (recipSz < 0) {
        return ret;

    } else if (recipSz == 0) {
        WOLFSSL_MSG("You must add at least one CMS recipient");
        return PKCS7_RECIP_E;
    }
    recipSetSz = (int)SetSet((word32)recipSz, recipSet);

    /* version, defined in Section 6.1 of RFC 5652 */
    kariVersion = wc_PKCS7_GetCMSVersion(pkcs7, ENVELOPED_DATA);
    if (kariVersion < 0) {
        wc_PKCS7_FreeEncodedRecipientSet(pkcs7);
        WOLFSSL_MSG("Failed to set CMS EnvelopedData version");
        return PKCS7_RECIP_E;
    }

    verSz = SetMyVersion((word32)kariVersion, ver, 0);

    ret = wc_InitRng_ex(&rng, pkcs7->heap, pkcs7->devId);
    if (ret != 0) {
        wc_PKCS7_FreeEncodedRecipientSet(pkcs7);
        return ret;
    }

    /* generate IV for block cipher */
    ret = wc_PKCS7_GenerateBlock(pkcs7, &rng, tmpIv, (word32)blockSz);
    wc_FreeRng(&rng);
    if (ret != 0) {
        wc_PKCS7_FreeEncodedRecipientSet(pkcs7);
        return ret;
    }

    /* EncryptedContentInfo */
    ret = wc_SetContentType(pkcs7->contentOID, contentType,
                            sizeof(contentType));
    if (ret < 0) {
        wc_PKCS7_FreeEncodedRecipientSet(pkcs7);
        return ret;
    }

    contentTypeSz = ret;

    /* allocate encrypted content buffer and PKCS#7 padding */
    padSz = wc_PKCS7_GetPadSize(pkcs7->contentSz, (word32)blockSz);
    if (padSz < 0) {
        wc_PKCS7_FreeEncodedRecipientSet(pkcs7);
        return padSz;
    }

    encryptedOutSz = (int)pkcs7->contentSz + padSz;

#ifdef ASN_BER_TO_DER
    if (pkcs7->getContentCb == NULL)
#endif
    {
        plain = (byte*)XMALLOC((word32)encryptedOutSz, pkcs7->heap,
                               DYNAMIC_TYPE_PKCS7);
        if (plain == NULL) {
            wc_PKCS7_FreeEncodedRecipientSet(pkcs7);
            return MEMORY_E;
        }

        ret = wc_PKCS7_PadData(pkcs7->content, pkcs7->contentSz, plain,
                               (word32)encryptedOutSz, (word32)blockSz);
        if (ret < 0) {
            XFREE(plain, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
            wc_PKCS7_FreeEncodedRecipientSet(pkcs7);
            return ret;
        }

    }

#ifdef ASN_BER_TO_DER
    if (pkcs7->streamOutCb == NULL)
#endif
    {
        encryptedContent = (byte*)XMALLOC((word32)encryptedOutSz, pkcs7->heap,
                                          DYNAMIC_TYPE_PKCS7);
        if (encryptedContent == NULL) {
            XFREE(plain, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
            wc_PKCS7_FreeEncodedRecipientSet(pkcs7);
            return MEMORY_E;
        }
    }

    /* put together IV OCTET STRING */
    ivOctetStringSz = (int)SetOctetString((word32)blockSz, ivOctetString);

    /* build up our ContentEncryptionAlgorithmIdentifier sequence,
     * adding (ivOctetStringSz + blockSz) for IV OCTET STRING */
    contentEncAlgoSz = (int)SetAlgoID(pkcs7->encryptOID, contentEncAlgo,
                                 oidBlkType, ivOctetStringSz + blockSz);

    if (contentEncAlgoSz == 0) {
        XFREE(encryptedContent, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        XFREE(plain, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        wc_PKCS7_FreeEncodedRecipientSet(pkcs7);
        return BAD_FUNC_ARG;
    }

    encContentOctetSz = (int)SetImplicit(ASN_OCTET_STRING, 0, (word32)encryptedOutSz,
                                encContentOctet, pkcs7->encodeStream);
    encContentSeqSz = (int)SetSequenceEx((word32)(contentTypeSz +
                              contentEncAlgoSz + ivOctetStringSz + blockSz +
                              encContentOctetSz + encryptedOutSz),
                              encContentSeq, pkcs7->encodeStream);

    /* keep track of sizes for outer wrapper layering */
    totalSz = verSz + recipSetSz + recipSz + encContentSeqSz + contentTypeSz +
              contentEncAlgoSz + ivOctetStringSz + blockSz +
              encContentOctetSz + encryptedOutSz;

    /* EnvelopedData */
#ifdef ASN_BER_TO_DER
    if (pkcs7->encodeStream) {
        word32 tmpIdx = 0;

        /* account for ending of encContentOctet */
        totalSz += ASN_INDEF_END_SZ;

        /* account for ending of encContentSeq */
        totalSz += ASN_INDEF_END_SZ;

        /* account for asn1 syntax around octet strings */
        StreamOctetString(NULL, (word32)encryptedOutSz, NULL, &streamSz,
                                                                       &tmpIdx);
        totalSz += ((int)streamSz - encryptedOutSz);

        /* resize encrypted content buffer */
        if (encryptedContent != NULL) {
        XFREE(encryptedContent, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        encryptedContent = (byte*)XMALLOC(streamSz, pkcs7->heap,
                                          DYNAMIC_TYPE_PKCS7);
        if (encryptedContent == NULL) {
            XFREE(plain, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
            wc_PKCS7_FreeEncodedRecipientSet(pkcs7);
            return MEMORY_E;
        }
        }
    }
#endif
    envDataSeqSz = (int)SetSequenceEx((word32)totalSz, envDataSeq, pkcs7->encodeStream);
    totalSz += envDataSeqSz;
#ifdef ASN_BER_TO_DER
    if (pkcs7->encodeStream) {
        totalSz += ASN_INDEF_END_SZ;
    }
#endif

    /* outer content */
    outerContentSz = (int)SetExplicit(0, (word32)totalSz, outerContent, pkcs7->encodeStream);
#ifdef ASN_BER_TO_DER
    if (pkcs7->encodeStream) {
        totalSz += ASN_INDEF_END_SZ;
    }
#endif
    totalSz += outerContentTypeSz;
    totalSz += outerContentSz;

    if (pkcs7->contentOID != FIRMWARE_PKG_DATA) {
        /* ContentInfo */
        contentInfoSeqSz = (int)SetSequenceEx((word32)totalSz, contentInfoSeq,
            pkcs7->encodeStream);
        totalSz += contentInfoSeqSz;
    #ifdef ASN_BER_TO_DER
        if (pkcs7->encodeStream) {
            totalSz += ASN_INDEF_END_SZ;
        }
    #endif
    }

    if ((totalSz > (int)outputSz)
    #ifdef ASN_BER_TO_DER
         && (pkcs7->streamOutCb == NULL)
    #endif
    ) {
        WOLFSSL_MSG("Pkcs7_encrypt output buffer too small");
        XFREE(encryptedContent, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        XFREE(plain, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        wc_PKCS7_FreeEncodedRecipientSet(pkcs7);
        return BUFFER_E;
    }

    /* begin writing out PKCS7 bundle */
    if (pkcs7->contentOID != FIRMWARE_PKG_DATA) {
        wc_PKCS7_WriteOut(pkcs7, (output)? (output + idx) : NULL,
            contentInfoSeq, (word32)contentInfoSeqSz);
        idx += contentInfoSeqSz;
        wc_PKCS7_WriteOut(pkcs7, (output)? (output + idx) : NULL,
            outerContentType, (word32)outerContentTypeSz);
        idx += outerContentTypeSz;
        wc_PKCS7_WriteOut(pkcs7, (output)? (output + idx) : NULL,
            outerContent, (word32)outerContentSz);
        idx += outerContentSz;
    }

    wc_PKCS7_WriteOut(pkcs7, (output)? (output + idx) : NULL,
            envDataSeq, (word32)envDataSeqSz);
    idx += envDataSeqSz;
    wc_PKCS7_WriteOut(pkcs7, (output)? (output + idx) : NULL,
            ver, (word32)verSz);
    idx += verSz;
    wc_PKCS7_WriteOut(pkcs7, (output)? (output + idx) : NULL,
            recipSet, (word32)recipSetSz);
    idx += recipSetSz;
    /* copy in recipients from list */
    tmpRecip = pkcs7->recipList;
    while (tmpRecip != NULL) {
        wc_PKCS7_WriteOut(pkcs7, (output)? (output + idx) : NULL,
            tmpRecip->recip, tmpRecip->recipSz);
        idx += (int)tmpRecip->recipSz;
        tmpRecip = tmpRecip->next;
    }
    wc_PKCS7_FreeEncodedRecipientSet(pkcs7);

    wc_PKCS7_WriteOut(pkcs7, (output)? (output + idx) : NULL,
            encContentSeq, (word32)encContentSeqSz);
    idx += encContentSeqSz;
    wc_PKCS7_WriteOut(pkcs7, (output)? (output + idx) : NULL,
            contentType, (word32)contentTypeSz);
    idx += contentTypeSz;
    wc_PKCS7_WriteOut(pkcs7, (output)? (output + idx) : NULL,
            contentEncAlgo, (word32)contentEncAlgoSz);
    idx += contentEncAlgoSz;
    wc_PKCS7_WriteOut(pkcs7, (output)? (output + idx) : NULL,
            ivOctetString, (word32)ivOctetStringSz);
    idx += ivOctetStringSz;
    wc_PKCS7_WriteOut(pkcs7, (output)? (output + idx) : NULL,
            tmpIv, (word32)blockSz);
    idx += blockSz;
    wc_PKCS7_WriteOut(pkcs7, (output)? (output + idx) : NULL,
            encContentOctet, (word32)encContentOctetSz);
    idx += encContentOctetSz;

    /* encrypt content */
    ret = wc_PKCS7_EncryptContent(pkcs7, pkcs7->encryptOID, pkcs7->cek,
            (int)pkcs7->cekSz, tmpIv, blockSz, NULL, 0, NULL, 0, plain,
            encryptedOutSz, encryptedContent);
    if (ret != 0) {
        XFREE(encryptedContent, pkcs7->heap, DYNAMIC_TYPE_PKCS7);

        XFREE(plain, pkcs7->heap, DYNAMIC_TYPE_PKCS7);

        wc_PKCS7_FreeEncodedRecipientSet(pkcs7);
        return ret;
    }

#ifdef ASN_BER_TO_DER
    /* stream the content (octet string with multiple octet elements) */
    if (pkcs7->encodeStream) {
        byte indefEnd[ASN_INDEF_END_SZ * 5];
        word32 localIdx = 0;

        /* advance index past encrypted content */
        if (!pkcs7->streamOutCb) {
            wc_PKCS7_WriteOut(pkcs7, (output)? output + idx : NULL,
                encryptedContent, streamSz);
        }
        idx += (int)streamSz;

        /* end of encrypted content */
        localIdx += SetIndefEnd(indefEnd + localIdx);

        /* end of encrypted content info */
        localIdx += SetIndefEnd(indefEnd + localIdx);

        /* end of Enveloped Data seq */
        localIdx += SetIndefEnd(indefEnd + localIdx);

        /* end of outer content set */
        localIdx += SetIndefEnd(indefEnd + localIdx);

        /* end of outer content info seq */
        localIdx += SetIndefEnd(indefEnd + localIdx);

        wc_PKCS7_WriteOut(pkcs7, (output)? (output + idx) : NULL,
            indefEnd, localIdx);
        idx += (int)localIdx;
    }
    else
#endif
    {
        wc_PKCS7_WriteOut(pkcs7, (output)? (output + idx) : NULL,
            encryptedContent, (word32)encryptedOutSz);
        idx += encryptedOutSz;
    }

    XFREE(plain, pkcs7->heap, DYNAMIC_TYPE_PKCS7);

    XFREE(encryptedContent, pkcs7->heap, DYNAMIC_TYPE_PKCS7);

    return idx;
}

#ifndef NO_RSA
/* decode KeyTransRecipientInfo (ktri), return 0 on success, <0 on error */
static int wc_PKCS7_DecryptKtri(wc_PKCS7* pkcs7, byte* in, word32 inSz,
                               word32* idx, byte* decryptedKey,
                               word32* decryptedKeySz, int* recipFound)
{
    int length, encryptedKeySz = 0, ret = 0;
    int keySz, version, sidType = 0;
    int keyIdSize;
    word32 encOID = 0;
    word32 keyIdx;
    byte   issuerHash[KEYID_SIZE];
    byte*  outKey   = NULL;
    byte* pkiMsg    = in;
    word32 pkiMsgSz = inSz;
    byte   tag;


#ifndef NO_PKCS7_STREAM
    word32 tmpIdx = *idx;
#endif
#ifdef WC_RSA_BLINDING
    WC_RNG rng;
#endif

    byte* encryptedKey = NULL;

#ifdef WOLFSSL_SMALL_STACK
    mp_int* serialNum  = NULL;
    RsaKey* privKey    = NULL;
#else
    mp_int serialNum[1];
    RsaKey privKey[1];
#endif
    XMEMSET(issuerHash, 0, sizeof(issuerHash));

#if defined(WOLFSSL_SM2) && defined(WOLFSSL_SM3)
    keyIdSize = wc_HashGetDigestSize(wc_HashTypeConvert(HashIdAlg(
           pkcs7->publicKeyOID)));
#else
    keyIdSize = KEYID_SIZE;
#endif

    switch (pkcs7->state) {
        case WC_PKCS7_DECRYPT_KTRI:
        #ifndef NO_PKCS7_STREAM
            if ((ret = wc_PKCS7_AddDataToStream(pkcs7, in, inSz, MAX_VERSION_SZ,
                            &pkiMsg, idx)) != 0) {
                return ret;
            }
            pkiMsgSz = (pkcs7->stream->length > 0)? pkcs7->stream->length: inSz;
        #endif
            if (GetMyVersion(pkiMsg, idx, &version, pkiMsgSz) < 0)
                return ASN_PARSE_E;

            if (version == 0) {
                sidType = CMS_ISSUER_AND_SERIAL_NUMBER;
            } else if (version == 2) {
                sidType = CMS_SKID;
            } else {
                return ASN_VERSION_E;
            }

        #ifndef NO_PKCS7_STREAM
            if ((ret = wc_PKCS7_StreamEndCase(pkcs7, &tmpIdx, idx)) != 0) {
                    break;
            }
            wc_PKCS7_StreamStoreVar(pkcs7, 0, sidType, version);

            /* @TODO getting total amount left because of GetInt call later on
             * this could be optimized to stream better */
            if (pkcs7->stream->totalRd > pkcs7->stream->maxLen) {
                WOLFSSL_MSG("PKCS7 read more than expected");
                ret = BUFFER_E;
                break;
            }
            pkcs7->stream->expected = (pkcs7->stream->maxLen -
                                pkcs7->stream->totalRd) + pkcs7->stream->length;
        #endif
            wc_PKCS7_ChangeState(pkcs7, WC_PKCS7_DECRYPT_KTRI_2);
            FALL_THROUGH;

        case WC_PKCS7_DECRYPT_KTRI_2:
        #ifndef NO_PKCS7_STREAM

            if ((ret = wc_PKCS7_AddDataToStream(pkcs7, in, inSz,
                            pkcs7->stream->expected, &pkiMsg, idx)) != 0) {
                return ret;
            }

            if (in != pkiMsg) {
                pkiMsgSz =  pkcs7->stream->length;
            }

            wc_PKCS7_StreamGetVar(pkcs7, NULL, &sidType, &version);

            /* @TODO get expected size for next part, does not account for
             * GetInt call well */
            if (pkcs7->stream->expected == MAX_SEQ_SZ) {
                int sz;
                word32 lidx;

                if (sidType == CMS_ISSUER_AND_SERIAL_NUMBER) {
                    lidx = *idx;
                    ret = GetSequence(pkiMsg, &lidx, &sz, pkiMsgSz);
                    if (ret < 0)
                        return ret;
                }
                else {
                    lidx = *idx + ASN_TAG_SZ;
                    ret = GetLength(pkiMsg, &lidx, &sz, pkiMsgSz);
                    if (ret < 0)
                        return ret;
                }

                pkcs7->stream->expected = (word32)sz + MAX_ALGO_SZ + ASN_TAG_SZ +
                                          MAX_LENGTH_SZ;
                if (pkcs7->stream->length > 0 &&
                        pkcs7->stream->length < pkcs7->stream->expected) {
                    return WC_PKCS7_WANT_READ_E;
                }
            }
        #endif /* !NO_PKCS7_STREAM */

            if (sidType == CMS_ISSUER_AND_SERIAL_NUMBER) {

                /* remove IssuerAndSerialNumber */
                if (GetSequence(pkiMsg, idx, &length, pkiMsgSz) < 0)
                    return ASN_PARSE_E;

                if (GetNameHash_ex(pkiMsg, idx, issuerHash, (int)pkiMsgSz,
                                   pkcs7->publicKeyOID) < 0)
                    return ASN_PARSE_E;

                /* if we found correct recipient, issuer hashes will match */
                if (XMEMCMP(issuerHash, pkcs7->issuerHash,
                            (word32)keyIdSize) == 0) {
                    *recipFound = 1;
                }

        #ifdef WOLFSSL_SMALL_STACK
                serialNum = (mp_int*)XMALLOC(sizeof(mp_int), pkcs7->heap,
                                             DYNAMIC_TYPE_TMP_BUFFER);
                if (serialNum == NULL)
                    return MEMORY_E;
        #endif

                if (GetInt(serialNum, pkiMsg, idx, pkiMsgSz) < 0) {
        #ifdef WOLFSSL_SMALL_STACK
                    XFREE(serialNum, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        #endif
                    return ASN_PARSE_E;
                }

                mp_clear(serialNum);

        #ifdef WOLFSSL_SMALL_STACK
                XFREE(serialNum, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        #endif

            } else {
                /* parse SubjectKeyIdentifier
                 * RFC 5652 lists SubjectKeyIdentifier as [0] followed by
                 * simple type of octet string
                 *
                 *  RecipientIdentifier ::= CHOICE {
                 *  issuerAndSerialNumber IssuerAndSerialNumber,
                 *  subjectKeyIdentifier [0] SubjectKeyIdentifier }
                 *
                 * The choice of subjectKeyIdentifier (where version was 2) is
                 * context specific with tag number 0 within the class.
                 */

                if (GetASNTag(pkiMsg, idx, &tag, pkiMsgSz) < 0)
                    return ASN_PARSE_E;

                /* should be context specific and tag number 0: [0] (0x80) */
                if (tag != ASN_CONTEXT_SPECIFIC) {
                    return ASN_PARSE_E;
                }

                if (GetLength(pkiMsg, idx, &length, pkiMsgSz) < 0)
                    return ASN_PARSE_E;

                if ((word32)keyIdSize > pkiMsgSz - (*idx))
                    return BUFFER_E;

                /* if we found correct recipient, SKID will match */
                if (XMEMCMP(pkiMsg + (*idx), pkcs7->issuerSubjKeyId,
                            (word32)keyIdSize) == 0) {
                    *recipFound = 1;
                }
                (*idx) += (word32)keyIdSize;
            }

            if (GetAlgoId(pkiMsg, idx, &encOID, oidKeyType, pkiMsgSz) < 0)
                return ASN_PARSE_E;

            /* key encryption algorithm must be RSA for now */
            if (encOID != RSAk
            #ifndef WC_NO_RSA_OAEP
                && encOID != RSAESOAEPk
            #endif
                )
                return ALGO_ID_E;

        #ifndef WC_NO_RSA_OAEP
            if (encOID == RSAESOAEPk) {
                if (GetSequence(pkiMsg, idx, &length, pkiMsgSz) < 0) {
                    return ASN_PARSE_E;
                }
                if (length > 0) {
                    WOLFSSL_MSG("only supported default OAEP");
                    WOLFSSL_ERROR(ALGO_ID_E);
                    return ALGO_ID_E;
                }
            }
        #endif

            /* read encryptedKey */
            if (GetASNTag(pkiMsg, idx, &tag, pkiMsgSz) < 0)
                return ASN_PARSE_E;

            if (tag != ASN_OCTET_STRING)
                return ASN_PARSE_E;

            if (GetLength(pkiMsg, idx, &encryptedKeySz, pkiMsgSz) < 0) {
                return ASN_PARSE_E;
            }
            if (encryptedKeySz > MAX_ENCRYPTED_KEY_SZ) {
               return BUFFER_E;
            }

        #ifndef NO_PKCS7_STREAM
            if ((ret = wc_PKCS7_StreamEndCase(pkcs7, &tmpIdx, idx)) != 0) {
                    break;
            }
            wc_PKCS7_StreamStoreVar(pkcs7, (word32)encryptedKeySz, sidType, version);
            pkcs7->stream->expected = (word32)encryptedKeySz;
        #endif
            wc_PKCS7_ChangeState(pkcs7, WC_PKCS7_DECRYPT_KTRI_3);
            FALL_THROUGH;

        case WC_PKCS7_DECRYPT_KTRI_3:
        #ifndef NO_PKCS7_STREAM
            if ((ret = wc_PKCS7_AddDataToStream(pkcs7, in, inSz,
                            pkcs7->stream->expected, &pkiMsg, idx)) != 0) {
                return ret;
            }
            encryptedKeySz = (int)pkcs7->stream->expected;
        #endif

            /* Always allocate to ensure aligned use with RSA */
            encryptedKey = (byte*)XMALLOC((word32)encryptedKeySz, pkcs7->heap,
                                          DYNAMIC_TYPE_WOLF_BIGINT);
            if (encryptedKey == NULL)
                return MEMORY_E;

            if (*recipFound == 1)
                XMEMCPY(encryptedKey, &pkiMsg[*idx], (word32)encryptedKeySz);
            *idx += (word32)encryptedKeySz;

            /* load private key */
        #ifdef WOLFSSL_SMALL_STACK
            privKey = (RsaKey*)XMALLOC(sizeof(RsaKey), pkcs7->heap,
                DYNAMIC_TYPE_TMP_BUFFER);
            if (privKey == NULL) {
                XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_WOLF_BIGINT);
                return MEMORY_E;
            }
        #endif

            ret = wc_InitRsaKey_ex(privKey, pkcs7->heap, pkcs7->devId);
            if (ret != 0) {
                XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_WOLF_BIGINT);
        #ifdef WOLFSSL_SMALL_STACK
                XFREE(privKey, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        #endif
                return ret;
            }

            if (pkcs7->privateKey != NULL && pkcs7->privateKeySz > 0) {
                keyIdx = 0;
                ret = wc_RsaPrivateKeyDecode(pkcs7->privateKey, &keyIdx,
                        privKey, pkcs7->privateKeySz);
            }
            else if (pkcs7->devId == INVALID_DEVID) {
                ret = BAD_FUNC_ARG;
            }
            if (ret != 0) {
                WOLFSSL_MSG("Failed to decode RSA private key");
                wc_FreeRsaKey(privKey);
                XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_WOLF_BIGINT);
        #ifdef WOLFSSL_SMALL_STACK
                XFREE(privKey, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        #endif
                return ret;
            }

            /* decrypt encryptedKey */
            #ifdef WC_RSA_BLINDING
            ret = wc_InitRng_ex(&rng, pkcs7->heap, pkcs7->devId);
            if (ret == 0) {
                ret = wc_RsaSetRNG(privKey, &rng);
            }
            #endif
            if (ret == 0) {
            #ifdef WOLFSSL_ASYNC_CRYPT
                /* Currently the call to RSA decrypt here is blocking @TODO */
                keySz = 0; /* set initial "ret" value to 0 */
                do {
                    keySz = wc_AsyncWait(keySz, &privKey->asyncDev,
                                         WC_ASYNC_FLAG_CALL_AGAIN);
                if (keySz >= 0)
            #endif
                {
            #ifndef WC_NO_RSA_OAEP
                    if (encOID != RSAESOAEPk) {
            #endif
                        keySz = wc_RsaPrivateDecryptInline(encryptedKey,
                                                        (word32)encryptedKeySz, &outKey,
                                                        privKey);
            #ifndef WC_NO_RSA_OAEP
                    }
                    else {
                        word32 outLen = (word32)wc_RsaEncryptSize(privKey);
                        outKey = (byte*)XMALLOC(outLen, pkcs7->heap,
                                                    DYNAMIC_TYPE_TMP_BUFFER);
                        if (!outKey) {
                            WOLFSSL_MSG("Failed to allocate out key buffer");
                            wc_FreeRsaKey(privKey);
                            XFREE(encryptedKey, pkcs7->heap,
                                                    DYNAMIC_TYPE_WOLF_BIGINT);
                            #ifdef WOLFSSL_SMALL_STACK
                                    XFREE(privKey, pkcs7->heap,
                                                    DYNAMIC_TYPE_TMP_BUFFER);
                            #endif
                            WOLFSSL_ERROR_VERBOSE(MEMORY_E);
                            return MEMORY_E;
                        }

                        keySz = wc_RsaPrivateDecrypt_ex(encryptedKey,
                                (word32)encryptedKeySz, outKey, outLen, privKey,
                                WC_RSA_OAEP_PAD,
                                WC_HASH_TYPE_SHA, WC_MGF1SHA1, NULL, 0);
                    }
            #endif
                }
            #ifdef WOLFSSL_ASYNC_CRYPT
                } while (keySz == WC_NO_ERR_TRACE(WC_PENDING_E));
            #endif
                #ifdef WC_RSA_BLINDING
                    wc_FreeRng(&rng);
                #endif
            } else {
                keySz = ret;
            }
            wc_FreeRsaKey(privKey);

            if (keySz <= 0 || outKey == NULL) {
                ForceZero(encryptedKey, (word32)encryptedKeySz);
                XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_WOLF_BIGINT);
        #ifdef WOLFSSL_SMALL_STACK
                XFREE(privKey, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        #endif
        #ifndef WC_NO_RSA_OAEP
                if (encOID == RSAESOAEPk) {
                    if (!outKey) {
                        XFREE(outKey, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
                    }
                }
        #endif
                return keySz;
            } else {
                *decryptedKeySz = (word32)keySz;
                XMEMCPY(decryptedKey, outKey, (word32)keySz);
                ForceZero(encryptedKey, (word32)encryptedKeySz);
            }

            XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_WOLF_BIGINT);
        #ifdef WOLFSSL_SMALL_STACK
            XFREE(privKey, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        #endif
        #ifndef WC_NO_RSA_OAEP
            if (encOID == RSAESOAEPk) {
                if (!outKey) {
                    XFREE(outKey, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
                }
            }
        #endif
        #ifndef NO_PKCS7_STREAM
            if ((ret = wc_PKCS7_StreamEndCase(pkcs7, &tmpIdx, idx)) != 0) {
                break;
            }
        #endif
            ret = 0; /* success */
            break;

        default:
            WOLFSSL_MSG("PKCS7 Unknown KTRI decrypt state");
            ret = BAD_FUNC_ARG;
    }

    return ret;
}
#endif /* !NO_RSA */

#ifdef HAVE_ECC

/* remove ASN.1 OriginatorIdentifierOrKey, return 0 on success, <0 on error */
static int wc_PKCS7_KariGetOriginatorIdentifierOrKey(WC_PKCS7_KARI* kari,
                        byte* pkiMsg, word32 pkiMsgSz, word32* idx)
{
    int ret, length;
    word32 keyOID, oidSum = 0;
    int curve_id = ECC_CURVE_DEF;
    byte tag;

    if (kari == NULL || pkiMsg == NULL || idx == NULL)
        return BAD_FUNC_ARG;

    /* remove OriginatorIdentifierOrKey */
    if (GetASNTag(pkiMsg, idx, &tag, pkiMsgSz) == 0 &&
            tag == (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 0)) {
        if (GetLength(pkiMsg, idx, &length, pkiMsgSz) < 0)
            return ASN_PARSE_E;

    } else {
        return ASN_PARSE_E;
    }

    /* remove OriginatorPublicKey */
    if (GetASNTag(pkiMsg, idx, &tag, pkiMsgSz) == 0 &&
            tag == (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 1)) {
        if (GetLength(pkiMsg, idx, &length, pkiMsgSz) < 0)
            return ASN_PARSE_E;

    } else {
        return ASN_PARSE_E;
    }

    /* remove AlgorithmIdentifier */
    if (GetAlgoId(pkiMsg, idx, &keyOID, oidKeyType, pkiMsgSz) < 0)
        return ASN_PARSE_E;

    if (keyOID != ECDSAk)
        return ASN_PARSE_E;

    /* optional algorithm parameters */
    ret = GetObjectId(pkiMsg, idx, &oidSum, oidIgnoreType, pkiMsgSz);
    if (ret == 0) {
        /* get curve id */
        curve_id = wc_ecc_get_oid(oidSum, NULL, 0);
        if (curve_id < 0)
            return ECC_CURVE_OID_E;
    }

    /* remove ECPoint BIT STRING */
    if (GetASNTag(pkiMsg, idx, &tag, pkiMsgSz) < 0)
        return ASN_PARSE_E;

    if (tag != ASN_BIT_STRING)
        return ASN_PARSE_E;

    if (GetLength(pkiMsg, idx, &length, pkiMsgSz) < 0)
        return ASN_PARSE_E;

    if (GetASNTag(pkiMsg, idx, &tag, pkiMsgSz) < 0)
        return ASN_EXPECT_0_E;

    if (tag != ASN_OTHER_TYPE)
        return ASN_EXPECT_0_E;

    /* get sender ephemeral public ECDSA key */
    ret = wc_ecc_init_ex(kari->senderKey, kari->heap, kari->devId);
    if (ret != 0)
        return ret;

    kari->senderKeyInit = 1;

    /* length-1 for unused bits counter */
    ret = wc_ecc_import_x963_ex(pkiMsg + (*idx), (word32)length - 1,
            kari->senderKey, curve_id);
    if (ret != 0) {
        ret = wc_EccPublicKeyDecode(pkiMsg, idx, kari->senderKey,
            *idx + (word32)length - 1);
        if (ret != 0)
            return ret;
    }
    else {
        (*idx) += (word32)(length - 1);
    }

    return 0;
}


/* remove optional UserKeyingMaterial if available, return 0 on success,
 * < 0 on error */
static int wc_PKCS7_KariGetUserKeyingMaterial(WC_PKCS7_KARI* kari,
                        byte* pkiMsg, word32 pkiMsgSz, word32* idx)
{
    int length;
    word32 savedIdx;
    byte tag;

    if (kari == NULL || pkiMsg == NULL || idx == NULL)
        return BAD_FUNC_ARG;

    savedIdx = *idx;

    /* starts with EXPLICIT [1] */
    if (GetASNTag(pkiMsg, idx, &tag, pkiMsgSz) < 0) {
        *idx = savedIdx;
        return 0;
    }
    if (tag != (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 1)) {
        *idx = savedIdx;
        return 0;
    }

    if (GetLength(pkiMsg, idx, &length, pkiMsgSz) < 0) {
        *idx = savedIdx;
        return 0;
    }

    /* get OCTET STRING */
    if (GetASNTag(pkiMsg, idx, &tag, pkiMsgSz) < 0) {
        *idx = savedIdx;
        return 0;
    }
    if (tag != ASN_OCTET_STRING) {
        *idx = savedIdx;
        return 0;
    }

    if (GetLength(pkiMsg, idx, &length, pkiMsgSz) < 0) {
        *idx = savedIdx;
        return 0;
    }

    kari->ukm = NULL;
    if (length > 0) {
        kari->ukm = (byte*)XMALLOC((word32)length, kari->heap,
                                                            DYNAMIC_TYPE_PKCS7);
        if (kari->ukm == NULL)
            return MEMORY_E;

        XMEMCPY(kari->ukm, pkiMsg + (*idx), (word32)length);
        kari->ukmOwner = 1;
    }

    (*idx) += (word32)length;
    kari->ukmSz = (word32)length;

    return 0;
}


/* remove ASN.1 KeyEncryptionAlgorithmIdentifier, return 0 on success,
 * < 0 on error */
static int wc_PKCS7_KariGetKeyEncryptionAlgorithmId(WC_PKCS7_KARI* kari,
        byte* pkiMsg, word32 pkiMsgSz, word32* idx,
        word32* keyAgreeOID, word32* keyWrapOID)
{
    int length = 0;
    word32 localIdx;

    if (kari == NULL || pkiMsg == NULL || idx == NULL ||
        keyAgreeOID == NULL || keyWrapOID == NULL)
        return BAD_FUNC_ARG;

    localIdx = *idx;

    /* remove KeyEncryptionAlgorithmIdentifier */
    if (GetSequence(pkiMsg, &localIdx, &length, pkiMsgSz) < 0)
        return ASN_PARSE_E;

    localIdx = *idx;
    if (GetAlgoId(pkiMsg, &localIdx, keyAgreeOID, oidCmsKeyAgreeType,
              pkiMsgSz) < 0) {
        return ASN_PARSE_E;
    }

    if (localIdx < *idx + (word32)length) {
        *idx = localIdx;
    }
    /* remove KeyWrapAlgorithm, stored in parameter of KeyEncAlgoId */
    if (GetAlgoId(pkiMsg, idx, keyWrapOID, oidKeyWrapType, pkiMsgSz) < 0)
        return ASN_PARSE_E;

    return 0;
}


/* remove ASN.1 SubjectKeyIdentifier, return 0 on success, < 0 on error
 * if subject key ID matches, recipFound is set to 1 */
static int wc_PKCS7_KariGetSubjectKeyIdentifier(WC_PKCS7_KARI* kari,
                        byte* pkiMsg, word32 pkiMsgSz, word32* idx,
                        int* recipFound, byte* rid)
{
    int length;
    byte tag;
    int keyIdSize;

    if (kari == NULL || pkiMsg == NULL || idx == NULL || recipFound == NULL ||
            rid == NULL)
        return BAD_FUNC_ARG;

#if defined(WOLFSSL_SM2) && defined(WOLFSSL_SM3)
    keyIdSize = wc_HashGetDigestSize(wc_HashTypeConvert(HashIdAlg(
           kari->decoded->signatureOID)));
#else
    keyIdSize = KEYID_SIZE;
#endif

    /* remove RecipientKeyIdentifier IMPLICIT [0] */
    if (GetASNTag(pkiMsg, idx, &tag, pkiMsgSz) < 0) {
        return ASN_PARSE_E;
    }

    if (tag == (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 0)) {
        if (GetLength(pkiMsg, idx, &length, pkiMsgSz) < 0)
            return ASN_PARSE_E;

    } else {
        return ASN_PARSE_E;
    }

    /* remove SubjectKeyIdentifier */
    if (GetASNTag(pkiMsg, idx, &tag, pkiMsgSz) < 0) {
        return ASN_PARSE_E;
    }

    if (tag != ASN_OCTET_STRING)
        return ASN_PARSE_E;

    if (GetLength(pkiMsg, idx, &length, pkiMsgSz) < 0)
        return ASN_PARSE_E;

    if (length != keyIdSize)
        return ASN_PARSE_E;

    XMEMCPY(rid, pkiMsg + (*idx), (word32)keyIdSize);
    (*idx) += (word32)length;

    /* subject key id should match if recipient found */
    if (XMEMCMP(rid, kari->decoded->extSubjKeyId, (word32)keyIdSize) == 0) {
        *recipFound = 1;
    }

    return 0;
}


/* remove ASN.1 IssuerAndSerialNumber, return 0 on success, < 0 on error
 * if issuer and serial number match, recipFound is set to 1 */
static int wc_PKCS7_KariGetIssuerAndSerialNumber(WC_PKCS7_KARI* kari,
                        byte* pkiMsg, word32 pkiMsgSz, word32* idx,
                        int* recipFound, byte* rid)
{
    int length, ret;
    int keyIdSize;
#ifdef WOLFSSL_SMALL_STACK
    mp_int* serial;
    mp_int* recipSerial;
#else
    mp_int  serial[1];
    mp_int  recipSerial[1];
#endif

    if (rid == NULL) {
        return BAD_FUNC_ARG;
    }

#if defined(WOLFSSL_SM2) && defined(WOLFSSL_SM3)
    keyIdSize = wc_HashGetDigestSize(wc_HashTypeConvert(HashIdAlg(
           kari->decoded->signatureOID)));
#else
    keyIdSize = KEYID_SIZE;
#endif

    /* remove IssuerAndSerialNumber */
    if (GetSequence(pkiMsg, idx, &length, pkiMsgSz) < 0)
        return ASN_PARSE_E;

    if (GetNameHash_ex(pkiMsg, idx, rid, (int)pkiMsgSz,
                       kari->decoded->signatureOID) < 0) {
        return ASN_PARSE_E;
    }

    /* if we found correct recipient, issuer hashes will match */
    if (kari->decodedInit == 1) {
        if (XMEMCMP(rid, kari->decoded->issuerHash, (word32)keyIdSize) == 0) {
            *recipFound = 1;
        }
    }
    else {
        /* can not confirm recipient serial number with no cert provided */
        WOLFSSL_MSG("No recipient cert loaded to match with CMS serial number");
        *recipFound = 1;
    }

#ifdef WOLFSSL_SMALL_STACK
    serial = (mp_int*)XMALLOC(sizeof(mp_int), kari->heap,
                              DYNAMIC_TYPE_TMP_BUFFER);
    if (serial == NULL)
        return MEMORY_E;

    recipSerial = (mp_int*)XMALLOC(sizeof(mp_int), kari->heap,
                                   DYNAMIC_TYPE_TMP_BUFFER);
    if (recipSerial == NULL) {
        XFREE(serial, kari->heap, DYNAMIC_TYPE_TMP_BUFFER);
        return MEMORY_E;
    }
#endif

    if (GetInt(serial, pkiMsg, idx, pkiMsgSz) < 0) {
#ifdef WOLFSSL_SMALL_STACK
        XFREE(serial,      kari->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(recipSerial, kari->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return ASN_PARSE_E;
    }

    ret = mp_init(recipSerial);
    if (ret == MP_OKAY)
        ret = mp_read_unsigned_bin(recipSerial, kari->decoded->serial,
                             (word32)kari->decoded->serialSz);
    if (ret != MP_OKAY) {
        mp_clear(serial);
        WOLFSSL_MSG("Failed to parse CMS recipient serial number");
#ifdef WOLFSSL_SMALL_STACK
        XFREE(serial,      kari->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(recipSerial, kari->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return ret;
    }

    if (kari->decodedInit == 1 &&
            mp_cmp(recipSerial, serial) != MP_EQ) {
        mp_clear(serial);
        mp_clear(recipSerial);
        WOLFSSL_MSG("CMS serial number does not match recipient");
#ifdef WOLFSSL_SMALL_STACK
        XFREE(serial,      kari->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(recipSerial, kari->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif
        return PKCS7_RECIP_E;
    }

    mp_clear(serial);
    mp_clear(recipSerial);

#ifdef WOLFSSL_SMALL_STACK
    XFREE(serial,      kari->heap, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(recipSerial, kari->heap, DYNAMIC_TYPE_TMP_BUFFER);
#endif

    return 0;
}


/* remove ASN.1 RecipientEncryptedKeys, return 0 on success, < 0 on error */
static int wc_PKCS7_KariGetRecipientEncryptedKeys(WC_PKCS7_KARI* kari,
                        byte* pkiMsg, word32 pkiMsgSz, word32* idx,
                        int* recipFound, byte* encryptedKey,
                        int* encryptedKeySz, byte* rid)
{
    int length;
    int ret = 0;
    byte tag;
    word32 localIdx;

    if (kari == NULL || pkiMsg == NULL || idx == NULL ||
        recipFound == NULL || encryptedKey == NULL)
        return BAD_FUNC_ARG;

    /* remove RecipientEncryptedKeys */
    if (GetSequence(pkiMsg, idx, &length, pkiMsgSz) < 0)
        return ASN_PARSE_E;

    /* remove RecipientEncryptedKeys */
    if (GetSequence(pkiMsg, idx, &length, pkiMsgSz) < 0)
        return ASN_PARSE_E;

    /* KeyAgreeRecipientIdentifier is CHOICE of IssuerAndSerialNumber
     * or [0] IMPLICIT RecipientKeyIdentifier */
    localIdx = *idx;
    if (GetASNTag(pkiMsg, &localIdx, &tag, pkiMsgSz) < 0)
        return ASN_PARSE_E;

    if (tag == (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 0)) {
        /* try to get RecipientKeyIdentifier */
        ret = wc_PKCS7_KariGetSubjectKeyIdentifier(kari, pkiMsg, pkiMsgSz,
                                                   idx, recipFound, rid);
    } else {
        /* try to get IssuerAndSerialNumber */
        ret = wc_PKCS7_KariGetIssuerAndSerialNumber(kari, pkiMsg, pkiMsgSz,
                                                    idx, recipFound, rid);
    }

    /* if we don't have either option, malformed CMS */
    if (ret != 0)
        return ret;

    /* remove EncryptedKey */
    if (GetASNTag(pkiMsg, idx, &tag, pkiMsgSz) < 0)
        return ASN_PARSE_E;

    if (tag != ASN_OCTET_STRING)
        return ASN_PARSE_E;

    if (GetLength(pkiMsg, idx, &length, pkiMsgSz) < 0)
        return ASN_PARSE_E;

    /* put encrypted CEK in decryptedKey buffer for now, decrypt later */
    if (length > *encryptedKeySz)
        return BUFFER_E;

    XMEMCPY(encryptedKey, pkiMsg + (*idx), (word32)length);
    *encryptedKeySz = length;
    (*idx) += (word32)length;

    return 0;
}

#endif /* HAVE_ECC */


int wc_PKCS7_SetOriEncryptCtx(wc_PKCS7* pkcs7, void* ctx)
{
    if (pkcs7 == NULL)
        return BAD_FUNC_ARG;

    pkcs7->oriEncryptCtx = ctx;

    return 0;
}


int wc_PKCS7_SetOriDecryptCtx(wc_PKCS7* pkcs7, void* ctx)
{

    if (pkcs7 == NULL)
        return BAD_FUNC_ARG;

    pkcs7->oriDecryptCtx = ctx;

    return 0;
}


int wc_PKCS7_SetOriDecryptCb(wc_PKCS7* pkcs7, CallbackOriDecrypt cb)
{
    if (pkcs7 == NULL)
        return BAD_FUNC_ARG;

    pkcs7->oriDecryptCb = cb;

    return 0;
}


/* return 0 on success */
int wc_PKCS7_SetWrapCEKCb(wc_PKCS7* pkcs7, CallbackWrapCEK cb)
{
    if (pkcs7 == NULL)
        return BAD_FUNC_ARG;

    pkcs7->wrapCEKCb = cb;

    return 0;
}

/* Decrypt ASN.1 OtherRecipientInfo (ori), as defined by:
 *
 *   OtherRecipientInfo ::= SEQUENCE {
 *     oriType OBJECT IDENTIFIER,
 *     oriValue ANY DEFINED BY oriType }
 *
 * pkcs7          - pointer to initialized PKCS7 structure
 * pkiMsg         - pointer to encoded CMS bundle
 * pkiMsgSz       - size of pkiMsg, bytes
 * idx            - [IN/OUT] pointer to index into pkiMsg
 * decryptedKey   - [OUT] output buf for decrypted content encryption key
 * decryptedKeySz - [IN/OUT] size of buffer, size of decrypted key
 * recipFound     - [OUT] 1 if recipient has been found, 0 if not
 *
 * Return 0 on success, negative upon error.
 */
static int wc_PKCS7_DecryptOri(wc_PKCS7* pkcs7, byte* in, word32 inSz,
                               word32* idx, byte* decryptedKey,
                               word32* decryptedKeySz, int* recipFound)
{
    int ret, seqSz, oriOIDSz;
    word32 oriValueSz, tmpIdx;
    byte* oriValue;
    byte oriOID[MAX_OID_SZ];

    byte* pkiMsg    = in;
    word32 pkiMsgSz = inSz;
#ifndef NO_PKCS7_STREAM
    word32 stateIdx = *idx;
#endif

    if (pkcs7->oriDecryptCb == NULL) {
        WOLFSSL_MSG("You must register an ORI Decrypt callback");
        return BAD_FUNC_ARG;
    }

    switch (pkcs7->state) {

        case WC_PKCS7_DECRYPT_ORI:
        #ifndef NO_PKCS7_STREAM
            /* @TODO for now just get full buffer, needs divided up */
            if ((ret = wc_PKCS7_AddDataToStream(pkcs7, in, inSz,
                   (pkcs7->stream->maxLen - pkcs7->stream->totalRd) +
                   pkcs7->stream->length, &pkiMsg, idx)) != 0) {
                return ret;
            }
            pkiMsgSz = (pkcs7->stream->length > 0)? pkcs7->stream->length: inSz;
        #endif
            /* get OtherRecipientInfo sequence length */
            if (GetLength(pkiMsg, idx, &seqSz, pkiMsgSz) < 0)
                return ASN_PARSE_E;

            tmpIdx = *idx;

            /* remove and store oriType OBJECT IDENTIFIER */
            if (GetASNObjectId(pkiMsg, idx, &oriOIDSz, pkiMsgSz) != 0)
                return ASN_PARSE_E;

            XMEMCPY(oriOID, pkiMsg + *idx, (word32)oriOIDSz);
            *idx += (word32)oriOIDSz;

            /* get oriValue, increment idx */
            oriValue = pkiMsg + *idx;
            oriValueSz = (word32)seqSz - (*idx - tmpIdx);
            *idx += oriValueSz;

            /* pass oriOID and oriValue to user callback, expect back
               decryptedKey and size */
            ret = pkcs7->oriDecryptCb(pkcs7, oriOID, (word32)oriOIDSz, oriValue,
                                      oriValueSz, decryptedKey, decryptedKeySz,
                                      pkcs7->oriDecryptCtx);

            if (ret != 0 || decryptedKey == NULL || *decryptedKeySz == 0) {
                /* decrypt operation failed */
                *recipFound = 0;
                return PKCS7_RECIP_E;
            }

            /* mark recipFound, since we only support one RecipientInfo for now */
            *recipFound = 1;

        #ifndef NO_PKCS7_STREAM
            if ((ret = wc_PKCS7_StreamEndCase(pkcs7, &stateIdx, idx)) != 0) {
                break;
            }
        #endif
            ret = 0; /* success */
            break;

        default:
            WOLFSSL_MSG("PKCS7 ORI unknown state");
            ret = BAD_FUNC_ARG;

    }

    return ret;
}

#if !defined(NO_PWDBASED) && !defined(NO_SHA)

/* decode ASN.1 PasswordRecipientInfo (pwri), return 0 on success,
 * < 0 on error */
static int wc_PKCS7_DecryptPwri(wc_PKCS7* pkcs7, byte* in, word32 inSz,
                               word32* idx, byte* decryptedKey,
                               word32* decryptedKeySz, int* recipFound)
{
    byte* salt;
    byte* cek;
    byte* kek;

    byte tmpIv[MAX_CONTENT_IV_SIZE];

    int ret = 0, length, saltSz, iterations, blockSz, kekKeySz;
    int hashOID = WC_SHA; /* default to SHA1 */
    word32 kdfAlgoId, pwriEncAlgoId, keyEncAlgoId, cekSz;
    byte* pkiMsg = in;
    word32 pkiMsgSz = inSz;
    byte  tag;
#ifndef NO_PKCS7_STREAM
    word32 tmpIdx = *idx;
#endif

    switch (pkcs7->state) {
        case WC_PKCS7_DECRYPT_PWRI:
        #ifndef NO_PKCS7_STREAM
            /*@TODO for now just get full buffer, needs divided up */
            if ((ret = wc_PKCS7_AddDataToStream(pkcs7, in, inSz,
                   (pkcs7->stream->maxLen - pkcs7->stream->totalRd) +
                   pkcs7->stream->length, &pkiMsg, idx)) != 0) {
                return ret;
            }
            #ifdef ASN_BER_TO_DER
            /* check if pkcs7->der is being used after BER to DER */
            if (pkcs7->derSz > 0) {
                pkiMsgSz = pkcs7->derSz;
            }
            else
            #endif
            {
                pkiMsgSz = (pkcs7->stream->length > 0)? pkcs7->stream->length:
                                                        inSz;
            }
        #endif
            /* remove KeyDerivationAlgorithmIdentifier */
            if (GetASNTag(pkiMsg, idx, &tag, pkiMsgSz) < 0)
                return ASN_PARSE_E;

            if (tag != (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 0))
                return ASN_PARSE_E;

            if (GetLength(pkiMsg, idx, &length, pkiMsgSz) < 0)
                return ASN_PARSE_E;

            /* get KeyDerivationAlgorithmIdentifier */
            if (wc_GetContentType(pkiMsg, idx, &kdfAlgoId, pkiMsgSz) < 0)
                return ASN_PARSE_E;

            /* get KDF params SEQ */
            if (GetSequence(pkiMsg, idx, &length, pkiMsgSz) < 0)
                return ASN_PARSE_E;

            /* get KDF salt OCTET STRING */
            if (GetASNTag(pkiMsg, idx, &tag, pkiMsgSz) < 0)
                return ASN_PARSE_E;

            if (tag != ASN_OCTET_STRING)
                return ASN_PARSE_E;

            if (GetLength(pkiMsg, idx, &saltSz, pkiMsgSz) < 0)
                return ASN_PARSE_E;

            salt = (byte*)XMALLOC((word32)saltSz, pkcs7->heap,
                                                            DYNAMIC_TYPE_PKCS7);
            if (salt == NULL)
                return MEMORY_E;

            XMEMCPY(salt, pkiMsg + (*idx), (word32)saltSz);
            *idx += (word32)saltSz;

            /* get KDF iterations */
            if (GetMyVersion(pkiMsg, idx, &iterations, pkiMsgSz) < 0) {
                XFREE(salt, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
                return ASN_PARSE_E;
            }

            /* get KeyEncAlgoId SEQ */
            if (GetSequence(pkiMsg, idx, &length, pkiMsgSz) < 0) {
                XFREE(salt, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
                return ASN_PARSE_E;
            }

            /* get KeyEncAlgoId */
            if (wc_GetContentType(pkiMsg, idx, &keyEncAlgoId, pkiMsgSz) < 0) {
                XFREE(salt, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
                return ASN_PARSE_E;
            }

            /* get pwriEncAlgoId */
            if (GetAlgoId(pkiMsg, idx, &pwriEncAlgoId, oidBlkType,
                                                                pkiMsgSz) < 0) {
                XFREE(salt, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
                return ASN_PARSE_E;
            }

            blockSz = wc_PKCS7_GetOIDBlockSize((int)pwriEncAlgoId);
            if (blockSz < 0) {
                XFREE(salt, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
                return blockSz;
            }

            /* get content-encryption key size, based on algorithm */
            kekKeySz = wc_PKCS7_GetOIDKeySize((int)pwriEncAlgoId);
            if (kekKeySz < 0) {
                XFREE(salt, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
                return kekKeySz;
            }

            /* get block cipher IV, stored in OPTIONAL parameter of AlgoID */
            if (GetASNTag(pkiMsg, idx, &tag, pkiMsgSz) < 0) {
                XFREE(salt, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
                return ASN_PARSE_E;
            }

            if (tag != ASN_OCTET_STRING) {
                XFREE(salt, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
                return ASN_PARSE_E;
            }

            if (GetLength(pkiMsg, idx, &length, pkiMsgSz) < 0) {
                XFREE(salt, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
                return ASN_PARSE_E;
            }

            if (length != blockSz) {
                WOLFSSL_MSG("Incorrect IV length, must be of content alg block size");
                XFREE(salt, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
                return ASN_PARSE_E;
            }

            XMEMCPY(tmpIv, pkiMsg + (*idx), (word32)length);
            *idx += (word32)length;

            /* get EncryptedKey */
            if (GetASNTag(pkiMsg, idx, &tag, pkiMsgSz) < 0) {
                XFREE(salt, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
                return ASN_PARSE_E;
            }

            if (tag != ASN_OCTET_STRING) {
                XFREE(salt, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
                return ASN_PARSE_E;
            }

            if (GetLength(pkiMsg, idx, &length, pkiMsgSz) < 0) {
                XFREE(salt, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
                return ASN_PARSE_E;
            }

            /* allocate temporary space for decrypted key */
            cekSz = (word32)length;
            cek = (byte*)XMALLOC(cekSz, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
            if (cek == NULL) {
                XFREE(salt, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
                return MEMORY_E;
            }

            /* generate KEK */
            kek = (byte*)XMALLOC((word32)kekKeySz, pkcs7->heap,
                                                            DYNAMIC_TYPE_PKCS7);
            if (kek == NULL) {
                XFREE(salt, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
                XFREE(cek, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
                return MEMORY_E;
            }

            ret = wc_PKCS7_GenerateKEK_PWRI(pkcs7, pkcs7->pass, pkcs7->passSz,
                                  salt, (word32)saltSz, (int)kdfAlgoId, hashOID,
                                  iterations, kek, (word32)kekKeySz);
            if (ret < 0) {
                XFREE(salt, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
                XFREE(kek, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
                XFREE(cek, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
                return ASN_PARSE_E;
            }

            /* decrypt CEK with KEK */
            ret = wc_PKCS7_PwriKek_KeyUnWrap(pkcs7, kek, (word32)kekKeySz,
                                             pkiMsg + (*idx), (word32)length,
                                             cek, cekSz, tmpIv, (word32)blockSz,
                                             (int)pwriEncAlgoId);
            if (ret < 0) {
                XFREE(salt, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
                XFREE(kek, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
                XFREE(cek, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
                return ret;
            }
            cekSz = (word32)ret;

            if (*decryptedKeySz < cekSz) {
                WOLFSSL_MSG("Decrypted key buffer too small for CEK");
                XFREE(salt, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
                XFREE(kek, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
                XFREE(cek, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
                return BUFFER_E;
            }

            XMEMCPY(decryptedKey, cek, cekSz);
            *decryptedKeySz = cekSz;

            XFREE(salt, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
            XFREE(kek, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
            XFREE(cek, pkcs7->heap, DYNAMIC_TYPE_PKCS7);

            /* mark recipFound, since we only support one RecipientInfo for now */
            *recipFound = 1;
            *idx += (word32)length;
        #ifndef NO_PKCS7_STREAM
            if ((ret = wc_PKCS7_StreamEndCase(pkcs7, &tmpIdx, idx)) != 0) {
                break;
            }
        #endif
            ret = 0; /* success */
            break;

        default:
            WOLFSSL_MSG("PKCS7 PWRI unknown state");
            ret = BAD_FUNC_ARG;
    }

    return ret;
}

#endif /* NO_PWDBASED | NO_SHA */

/* decode ASN.1 KEKRecipientInfo (kekri), return 0 on success,
 * < 0 on error */
static int wc_PKCS7_DecryptKekri(wc_PKCS7* pkcs7, byte* in, word32 inSz,
                               word32* idx, byte* decryptedKey,
                               word32* decryptedKeySz, int* recipFound)
{
    int length, keySz, dateLen, direction;
    byte* keyId = NULL;
    const byte* datePtr = NULL;
    byte  dateFormat, tag;
    word32 keyIdSz, kekIdSz, keyWrapOID, localIdx;

    int ret = 0;
    byte* pkiMsg    = in;
    word32 pkiMsgSz = inSz;
#ifndef NO_PKCS7_STREAM
    word32 tmpIdx = *idx;
#endif

    WOLFSSL_ENTER("wc_PKCS7_DecryptKekri");
    switch (pkcs7->state) {
        case WC_PKCS7_DECRYPT_KEKRI:
        #ifndef NO_PKCS7_STREAM
            /* @TODO for now just get full buffer, needs divided up */
            if ((ret = wc_PKCS7_AddDataToStream(pkcs7, in, inSz,
                   (pkcs7->stream->maxLen - pkcs7->stream->totalRd) +
                   pkcs7->stream->length, &pkiMsg, idx)) != 0) {
                return ret;
            }
            pkiMsgSz = (pkcs7->stream->length > 0)? pkcs7->stream->length: inSz;
        #endif
            /* remove KEKIdentifier */
            if (GetSequence(pkiMsg, idx, &length, pkiMsgSz) < 0)
                return ASN_PARSE_E;

            kekIdSz = (word32)length;

            if (GetASNTag(pkiMsg, idx, &tag, pkiMsgSz) < 0)
                return ASN_PARSE_E;

            if (tag != ASN_OCTET_STRING)
                return ASN_PARSE_E;

            if (GetLength(pkiMsg, idx, &length, pkiMsgSz) < 0)
                return ASN_PARSE_E;

            /* save keyIdentifier and length */
            keyId = pkiMsg + *idx;
            keyIdSz = (word32)length;
            *idx += keyIdSz;

            /* may have OPTIONAL GeneralizedTime */
            localIdx = *idx;
            if ((*idx < kekIdSz) && GetASNTag(pkiMsg, &localIdx, &tag,
                        pkiMsgSz) == 0 && tag == ASN_GENERALIZED_TIME) {
                if (wc_GetDateInfo(pkiMsg + *idx, (int)pkiMsgSz, &datePtr, &dateFormat,
                                   &dateLen) != 0) {
                    return ASN_PARSE_E;
                }
                *idx += (word32)(dateLen + 1);
            }

            if (*idx > pkiMsgSz) {
                return ASN_PARSE_E;
            }

            /* may have OPTIONAL OtherKeyAttribute */
            localIdx = *idx;
            if ((*idx < kekIdSz) && GetASNTag(pkiMsg, &localIdx, &tag,
                            pkiMsgSz) == 0 && tag == (ASN_SEQUENCE |
                            ASN_CONSTRUCTED)) {
                if (GetSequence(pkiMsg, idx, &length, pkiMsgSz) < 0)
                    return ASN_PARSE_E;

                /* skip it */
                *idx += (word32)length;
            }

            if (*idx > pkiMsgSz) {
                return ASN_PARSE_E;
            }

            /* get KeyEncryptionAlgorithmIdentifier */
            if (GetAlgoId(pkiMsg, idx, &keyWrapOID, oidKeyWrapType, pkiMsgSz) < 0)
                return ASN_PARSE_E;

            /* get EncryptedKey */
            if (GetASNTag(pkiMsg, idx, &tag, pkiMsgSz) < 0)
                return ASN_PARSE_E;

            if (tag != ASN_OCTET_STRING)
                return ASN_PARSE_E;

            if (GetLength(pkiMsg, idx, &length, pkiMsgSz) < 0)
                return ASN_PARSE_E;

            #ifndef NO_AES
                direction = AES_DECRYPTION;
            #else
                direction = DES_DECRYPTION;
            #endif

            /* decrypt CEK with KEK */
            if (pkcs7->wrapCEKCb) {
                keySz = pkcs7->wrapCEKCb(pkcs7, pkiMsg + *idx, (word32)length, keyId,
                                     keyIdSz, NULL, 0, decryptedKey,
                                     *decryptedKeySz, (int)keyWrapOID,
                                     (int)PKCS7_KEKRI, direction);
            }
            else {
                keySz = wc_PKCS7_KeyWrap(pkiMsg + *idx, (word32)length, pkcs7->privateKey,
                                     pkcs7->privateKeySz, decryptedKey, *decryptedKeySz,
                                     (int)keyWrapOID, direction);
            }
            if (keySz <= 0)
                return keySz;

            *decryptedKeySz = (word32)keySz;

            /* mark recipFound, since we only support one RecipientInfo for now */
            *recipFound = 1;
            *idx += (word32)length;

        #ifndef NO_PKCS7_STREAM
            if ((ret = wc_PKCS7_StreamEndCase(pkcs7, &tmpIdx, idx)) != 0) {
                break;
            }
        #endif
            ret = 0; /* success */
            break;

        default:
            WOLFSSL_MSG("PKCS7 KEKRI unknown state");
            ret = BAD_FUNC_ARG;

    }

    (void)keyId;
    return ret;
}


/* decode ASN.1 KeyAgreeRecipientInfo (kari), return 0 on success,
 * < 0 on error */
static int wc_PKCS7_DecryptKari(wc_PKCS7* pkcs7, byte* in, word32 inSz,
                               word32* idx, byte* decryptedKey,
                               word32* decryptedKeySz, int* recipFound)
{
#ifdef HAVE_ECC
    int ret, keySz;
    int encryptedKeySz;
    int direction = 0;
    int keyIdSize;
    word32 keyAgreeOID, keyWrapOID;
    byte rid[KEYID_SIZE];

#ifdef WOLFSSL_SMALL_STACK
    byte* encryptedKey;
#else
    byte  encryptedKey[MAX_ENCRYPTED_KEY_SZ];
#endif

    byte* pkiMsg    = in;
    word32 pkiMsgSz = inSz;
#ifndef NO_PKCS7_STREAM
    word32 tmpIdx = (idx) ? *idx : 0;
#endif

    WOLFSSL_ENTER("wc_PKCS7_DecryptKari");
    if (pkcs7 == NULL || pkiMsg == NULL ||
        idx == NULL || decryptedKey == NULL || decryptedKeySz == NULL) {
        return BAD_FUNC_ARG;
    }

#if defined(WOLFSSL_SM2) && defined(WOLFSSL_SM3)
    keyIdSize = wc_HashGetDigestSize(wc_HashTypeConvert(HashIdAlg(
           pkcs7->publicKeyOID)));
#else
    keyIdSize = KEYID_SIZE;
#endif

    switch (pkcs7->state) {
        case WC_PKCS7_DECRYPT_KARI: {
            WC_PKCS7_KARI* kari;

        #ifndef NO_PKCS7_STREAM
            /* @TODO for now just get full buffer, needs divided up */
            if ((ret = wc_PKCS7_AddDataToStream(pkcs7, in, inSz,
                   (pkcs7->stream->maxLen - pkcs7->stream->totalRd) +
                   pkcs7->stream->length, &pkiMsg, idx)) != 0) {
                return ret;
            }
            pkiMsgSz = (pkcs7->stream->length > 0)? pkcs7->stream->length: inSz;
        #endif

            kari = wc_PKCS7_KariNew(pkcs7, WC_PKCS7_DECODE);
            if (kari == NULL)
                return MEMORY_E;

        #ifdef WOLFSSL_SMALL_STACK
            encryptedKey = (byte*)XMALLOC(MAX_ENCRYPTED_KEY_SZ, pkcs7->heap,
                                          DYNAMIC_TYPE_PKCS7);
            if (encryptedKey == NULL) {
                wc_PKCS7_KariFree(kari);
                return MEMORY_E;
            }
        #endif
            encryptedKeySz = MAX_ENCRYPTED_KEY_SZ;

            /* parse cert and key */
            ret = wc_PKCS7_KariParseRecipCert(kari, (byte*)pkcs7->singleCert,
                                          pkcs7->singleCertSz, pkcs7->privateKey,
                                          pkcs7->privateKeySz);
            if (ret != 0) {
                wc_PKCS7_KariFree(kari);
            #ifdef WOLFSSL_SMALL_STACK
                XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
            #endif
                return ret;
            }

            /* remove OriginatorIdentifierOrKey */
            ret = wc_PKCS7_KariGetOriginatorIdentifierOrKey(kari, pkiMsg,
                                                            pkiMsgSz, idx);
            if (ret != 0) {
                wc_PKCS7_KariFree(kari);
                #ifdef WOLFSSL_SMALL_STACK
                    XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
                #endif
                return ret;
            }

            /* try and remove optional UserKeyingMaterial */
            ret = wc_PKCS7_KariGetUserKeyingMaterial(kari, pkiMsg, pkiMsgSz, idx);
            if (ret != 0) {
                wc_PKCS7_KariFree(kari);
                #ifdef WOLFSSL_SMALL_STACK
                    XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
                #endif
                return ret;
            }

            /* remove KeyEncryptionAlgorithmIdentifier */
            ret = wc_PKCS7_KariGetKeyEncryptionAlgorithmId(kari, pkiMsg,
                    pkiMsgSz, idx, &keyAgreeOID, &keyWrapOID);
            if (ret != 0) {
                wc_PKCS7_KariFree(kari);
                #ifdef WOLFSSL_SMALL_STACK
                    XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
                #endif
                return ret;
            }

            /* if user has not explicitly set keyAgreeOID, set from one in bundle */
            if (pkcs7->keyAgreeOID == 0)
                pkcs7->keyAgreeOID = (int)keyAgreeOID;

            /* set direction based on key wrap algorithm */
            switch (keyWrapOID) {
        #ifndef NO_AES
            #ifdef WOLFSSL_AES_128
                case AES128_WRAP:
            #endif
            #ifdef WOLFSSL_AES_192
                case AES192_WRAP:
            #endif
            #ifdef WOLFSSL_AES_256
                case AES256_WRAP:
            #endif
                    direction = AES_DECRYPTION;
                    break;
        #endif
                default:
                    WOLFSSL_MSG("AES key wrap algorithm unsupported");
                    if (pkcs7->wrapCEKCb) {
                        WOLFSSL_MSG("Direction not set!");
                        break; /* if unwrapping callback is set then do not
                                * force restriction of supported wrap
                                * algorithms */
                    }

                    wc_PKCS7_KariFree(kari);
                    #ifdef WOLFSSL_SMALL_STACK
                        XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
                    #endif
                    return BAD_KEYWRAP_ALG_E;
            }

            /* remove RecipientEncryptedKeys */
            ret = wc_PKCS7_KariGetRecipientEncryptedKeys(kari, pkiMsg, pkiMsgSz,
                           idx, recipFound, encryptedKey, &encryptedKeySz, rid);
            if (ret != 0) {
                wc_PKCS7_KariFree(kari);
                #ifdef WOLFSSL_SMALL_STACK
                    XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
                #endif
                return ret;
            }

            /* decrypt CEK with KEK */
            if (pkcs7->wrapCEKCb) {
                word32 tmpKeySz = 0;
                byte* tmpKeyDer = NULL;

                PRIVATE_KEY_UNLOCK();
                ret = wc_ecc_export_x963(kari->senderKey, NULL, &tmpKeySz);
                PRIVATE_KEY_LOCK();
                if (ret != WC_NO_ERR_TRACE(LENGTH_ONLY_E)) {
                    return ret;
                }

                /* buffer space for algorithm/curve */
                tmpKeySz += MAX_SEQ_SZ;
                tmpKeySz += 2 * MAX_ALGO_SZ;

                /* buffer space for public key sequence */
                tmpKeySz += MAX_SEQ_SZ;
                tmpKeySz += TRAILING_ZERO;

                tmpKeyDer = (byte*)XMALLOC(tmpKeySz, pkcs7->heap,
                        DYNAMIC_TYPE_TMP_BUFFER);
                if (tmpKeyDer == NULL) {
                    return MEMORY_E;
                }

                ret = wc_EccPublicKeyToDer(kari->senderKey, tmpKeyDer,
                                         tmpKeySz, 1);
                if (ret < 0) {
                    XFREE(tmpKeyDer, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
                    return ret;
                }
                tmpKeySz = (word32)ret;

                keySz = pkcs7->wrapCEKCb(pkcs7, encryptedKey, (word32)encryptedKeySz,
                        rid, (word32)keyIdSize, tmpKeyDer, tmpKeySz,
                        decryptedKey, *decryptedKeySz,
                        (int)keyWrapOID, (int)PKCS7_KARI, direction);
                XFREE(tmpKeyDer, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);

                if (keySz  > 0) {
                    /* If unwrapping was successful then consider recipient
                     * found. Checking for NULL singleCert to confirm previous
                     * SID check was not done */
                    if (pkcs7->singleCert == NULL)
                        *recipFound = 1;
                }
            }
            else {
                /* create KEK */
                ret = wc_PKCS7_KariGenerateKEK(kari, pkcs7->rng, (int)keyWrapOID,
                                               pkcs7->keyAgreeOID);
                if (ret != 0) {
                    wc_PKCS7_KariFree(kari);
                    #ifdef WOLFSSL_SMALL_STACK
                        XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
                    #endif
                    return ret;
                }

                /* decrypt CEK with KEK */
                keySz = wc_PKCS7_KeyWrap(encryptedKey, (word32)encryptedKeySz, kari->kek,
                                         kari->kekSz, decryptedKey, *decryptedKeySz,
                                         (int)keyWrapOID, direction);
            }
            if (keySz <= 0) {
                wc_PKCS7_KariFree(kari);
                #ifdef WOLFSSL_SMALL_STACK
                    XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
                #endif
                return keySz;
            }
            *decryptedKeySz = (word32)keySz;

            wc_PKCS7_KariFree(kari);
            #ifdef WOLFSSL_SMALL_STACK
                XFREE(encryptedKey, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
            #endif
            #ifndef NO_PKCS7_STREAM
            if ((ret = wc_PKCS7_StreamEndCase(pkcs7, &tmpIdx, idx)) != 0) {
                break;
            }
            #endif
            ret = 0; /* success */
        }
        break;

        default:
            WOLFSSL_MSG("PKCS7 kari unknown state");
            ret = BAD_FUNC_ARG;

    }

    (void)pkiMsg;
    (void)pkiMsgSz;

    return ret;
#else
    (void)in;
    (void)inSz;
    (void)pkcs7;
    (void)idx;
    (void)decryptedKey;
    (void)decryptedKeySz;
    (void)recipFound;

    return NOT_COMPILED_IN;
#endif /* HAVE_ECC */
}


/* decode ASN.1 RecipientInfos SET, return 0 on success, < 0 on error */
static int wc_PKCS7_DecryptRecipientInfos(wc_PKCS7* pkcs7, byte* in,
                            word32  inSz, word32* idx, byte* decryptedKey,
                            word32* decryptedKeySz, int* recipFound)
{
    word32 savedIdx;
    int version, ret = 0, length;
    byte* pkiMsg = in;
    word32 pkiMsgSz = inSz;
    byte  tag;
#ifndef NO_PKCS7_STREAM
    word32 tmpIdx;
#endif

    if (pkcs7 == NULL || pkiMsg == NULL || idx == NULL ||
        decryptedKey == NULL || decryptedKeySz == NULL ||
        recipFound == NULL) {
        return BAD_FUNC_ARG;
    }

    WOLFSSL_ENTER("wc_PKCS7_DecryptRecipientInfos");
#ifndef NO_PKCS7_STREAM
    tmpIdx = *idx;
#endif

    /* check if in the process of decrypting */
    switch (pkcs7->state) {
        case WC_PKCS7_DECRYPT_KTRI:
        case WC_PKCS7_DECRYPT_KTRI_2:
        case WC_PKCS7_DECRYPT_KTRI_3:
        #ifndef NO_RSA
            ret = wc_PKCS7_DecryptKtri(pkcs7, in, inSz, idx,
                                      decryptedKey, decryptedKeySz, recipFound);
        #else
            return NOT_COMPILED_IN;
        #endif
            break;

        case WC_PKCS7_DECRYPT_KARI:
                ret = wc_PKCS7_DecryptKari(pkcs7, in, inSz, idx,
                                      decryptedKey, decryptedKeySz, recipFound);
                break;

        case WC_PKCS7_DECRYPT_KEKRI:
                ret = wc_PKCS7_DecryptKekri(pkcs7, in, inSz, idx,
                                      decryptedKey, decryptedKeySz, recipFound);
                break;

        case WC_PKCS7_DECRYPT_PWRI:
        #if !defined(NO_PWDBASED) && !defined(NO_SHA)
                ret = wc_PKCS7_DecryptPwri(pkcs7, in, inSz, idx,
                                      decryptedKey, decryptedKeySz, recipFound);
                break;
        #else
                return NOT_COMPILED_IN;
        #endif

        case WC_PKCS7_DECRYPT_ORI:
            ret = wc_PKCS7_DecryptOri(pkcs7, in, inSz, idx,
                                      decryptedKey, decryptedKeySz, recipFound);
            break;

        default:
            /* not in decrypting state */
            break;
    }

    if (ret < 0) {
        return ret;
    }

    savedIdx = *idx;
#ifndef NO_PKCS7_STREAM
    pkiMsgSz = (pkcs7->stream->length > 0)? pkcs7->stream->length: inSz;
    if (pkcs7->stream->length > 0)
        pkiMsg = pkcs7->stream->buffer;
#endif

    /* when looking for next recipient, use first sequence and version to
     * indicate there is another, if not, move on */
    while(*recipFound == 0) {

        /* remove RecipientInfo, if we don't have a SEQUENCE, back up idx to
         * last good saved one */
        if (GetSequence_ex(pkiMsg, idx, &length, pkiMsgSz, NO_USER_CHECK) > 0) {

        #ifndef NO_RSA
            /* found ktri */
            #ifndef NO_PKCS7_STREAM
            if ((ret = wc_PKCS7_StreamEndCase(pkcs7, &tmpIdx, idx)) != 0) {
                break;
            }
            #endif
            wc_PKCS7_ChangeState(pkcs7, WC_PKCS7_DECRYPT_KTRI);
            ret = wc_PKCS7_DecryptKtri(pkcs7, in, inSz, idx,
                                      decryptedKey, decryptedKeySz,
                                      recipFound);
            if (ret != 0)
                return ret;
        #else
            return NOT_COMPILED_IN;
        #endif
        }
        else {
            word32 localIdx;
            /* kari is IMPLICIT[1] */
            *idx = savedIdx;
            localIdx = *idx;

            if (GetASNTag(pkiMsg, &localIdx, &tag, pkiMsgSz) != 0) {
                /* no room for recipient info */
                break;
            }

            if (tag == (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 1)) {
                (*idx)++;
                if (GetLength_ex(pkiMsg, idx, &length, pkiMsgSz,
                            NO_USER_CHECK) < 0)
                    return ASN_PARSE_E;

                if (GetMyVersion(pkiMsg, idx, &version, pkiMsgSz) < 0) {
                    *idx = savedIdx;
                    break;
                }

                if (version != 3)
                    return ASN_VERSION_E;

                /* found kari */
            #ifndef NO_PKCS7_STREAM
                if ((ret = wc_PKCS7_StreamEndCase(pkcs7, &tmpIdx, idx)) != 0) {
                    break;
                }
            #endif
                wc_PKCS7_ChangeState(pkcs7, WC_PKCS7_DECRYPT_KARI);
                ret = wc_PKCS7_DecryptKari(pkcs7, in, inSz, idx,
                                          decryptedKey, decryptedKeySz,
                                          recipFound);
                if (ret != 0)
                    return ret;

            /* kekri is IMPLICIT[2] */
            } else if (tag == (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 2)) {
                (*idx)++;

                if (GetLength_ex(pkiMsg, idx, &version, pkiMsgSz,
                            NO_USER_CHECK) < 0)
                    return ASN_PARSE_E;

                if (GetMyVersion(pkiMsg, idx, &version, pkiMsgSz) < 0) {
                    *idx = savedIdx;
                    break;
                }

                if (version != 4)
                    return ASN_VERSION_E;

                /* found kekri */
            #ifndef NO_PKCS7_STREAM
                if ((ret = wc_PKCS7_StreamEndCase(pkcs7, &tmpIdx, idx)) != 0) {
                    break;
                }
            #endif
                wc_PKCS7_ChangeState(pkcs7, WC_PKCS7_DECRYPT_KEKRI);
                ret = wc_PKCS7_DecryptKekri(pkcs7, in, inSz, idx,
                                           decryptedKey, decryptedKeySz,
                                           recipFound);
                if (ret != 0)
                    return ret;

            /* pwri is IMPLICIT[3] */
            } else if (tag == (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 3)) {
        #if !defined(NO_PWDBASED) && !defined(NO_SHA)
                (*idx)++;

                if (GetLength_ex(pkiMsg, idx, &version, pkiMsgSz,
                            NO_USER_CHECK) < 0)
                    return ASN_PARSE_E;

                if (GetMyVersion(pkiMsg, idx, &version, pkiMsgSz) < 0) {
                    *idx = savedIdx;
                    break;
                }

                if (version != 0)
                    return ASN_VERSION_E;

                /* found pwri */
            #ifndef NO_PKCS7_STREAM
                if ((ret = wc_PKCS7_StreamEndCase(pkcs7, &tmpIdx, idx)) != 0) {
                    break;
                }
            #endif
                wc_PKCS7_ChangeState(pkcs7, WC_PKCS7_DECRYPT_PWRI);
                ret = wc_PKCS7_DecryptPwri(pkcs7, in, inSz, idx,
                                           decryptedKey, decryptedKeySz,
                                           recipFound);
                if (ret != 0)
                    return ret;
        #else
                return NOT_COMPILED_IN;
        #endif

            /* ori is IMPLICIT[4] */
            } else if (tag == (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 4)) {
                (*idx)++;

                /* found ori */
            #ifndef NO_PKCS7_STREAM
                if ((ret = wc_PKCS7_StreamEndCase(pkcs7, &tmpIdx, idx)) != 0) {
                    break;
                }
            #endif
                wc_PKCS7_ChangeState(pkcs7, WC_PKCS7_DECRYPT_ORI);
                ret = wc_PKCS7_DecryptOri(pkcs7, in, inSz, idx,
                                          decryptedKey, decryptedKeySz,
                                          recipFound);
                if (ret != 0)
                    return ret;

            } else {
                /* failed to find RecipientInfo, restore idx and continue */
                *idx = savedIdx;
                break;
            }
        }

        /* update good idx */
        savedIdx = *idx;
    }

    return ret;
}


/* Parse encoded EnvelopedData bundle up to RecipientInfo set.
 *
 * return size of RecipientInfo SET on success, negative upon error */
static int wc_PKCS7_ParseToRecipientInfoSet(wc_PKCS7* pkcs7, byte* in,
                                            word32 inSz, word32* idx,
                                            int type)
{
    int version = 0, length = 0, ret = 0;
    word32 contentType= 0;
    word32 pkiMsgSz = inSz;
    byte*  pkiMsg = in;
    byte   tag = 0;
#ifndef NO_PKCS7_STREAM
    word32 tmpIdx = 0;
#endif

    if (pkcs7 == NULL || pkiMsg == NULL || pkiMsgSz == 0 || idx == NULL)
        return BAD_FUNC_ARG;

    if ((type != ENVELOPED_DATA) && (type != AUTH_ENVELOPED_DATA) &&
            pkcs7->contentOID != FIRMWARE_PKG_DATA
        #if defined(HAVE_LIBZ) && !defined(NO_PKCS7_COMPRESSED_DATA)
            && pkcs7->contentOID != COMPRESSED_DATA
        #endif
       )
        return BAD_FUNC_ARG;

#ifndef NO_PKCS7_STREAM
    if (pkcs7->stream == NULL) {
        if ((ret = wc_PKCS7_CreateStream(pkcs7)) != 0) {
            return ret;
        }
    }
#endif

    switch (pkcs7->state) {
        case WC_PKCS7_INFOSET_START:
        case WC_PKCS7_INFOSET_BER:
        case WC_PKCS7_INFOSET_STAGE1:
        case WC_PKCS7_INFOSET_STAGE2:
        case WC_PKCS7_INFOSET_END:
            break;

        default:
            WOLFSSL_MSG("Warning, setting PKCS7 info state to start");
            wc_PKCS7_ChangeState(pkcs7, WC_PKCS7_INFOSET_START);
    }

    switch (pkcs7->state) {
        case WC_PKCS7_INFOSET_START:
        #ifndef NO_PKCS7_STREAM
            if ((ret = wc_PKCS7_AddDataToStream(pkcs7, in, inSz, MAX_SEQ_SZ +
                            ASN_TAG_SZ, &pkiMsg, idx)) != 0) {
                return ret;
            }
            if ((ret = wc_PKCS7_SetMaxStream(pkcs7, in, inSz)) != 0) {
                break;
            }
            pkiMsgSz = (pkcs7->stream->length > 0)? pkcs7->stream->length: inSz;
        #endif
            /* read past ContentInfo, verify type is envelopedData */
            if (ret == 0 && GetSequence_ex(pkiMsg, idx, &length, pkiMsgSz,
                        NO_USER_CHECK) < 0)
            {
                ret = ASN_PARSE_E;
            }

            if (ret == 0 && length == 0 && pkiMsg[(*idx)-1] == 0x80) {
        #ifdef ASN_BER_TO_DER
                word32 len;

                wc_PKCS7_ChangeState(pkcs7, WC_PKCS7_INFOSET_BER);
                FALL_THROUGH;

                /* full buffer is needed for conversion */
                case WC_PKCS7_INFOSET_BER:
                #ifndef NO_PKCS7_STREAM
                if ((ret = wc_PKCS7_AddDataToStream(pkcs7, in, inSz,
                            pkcs7->stream->maxLen - pkcs7->stream->length,
                            &pkiMsg, idx)) != 0) {
                    return ret;
                }
                pkiMsgSz = (pkcs7->stream->length > 0)? pkcs7->stream->length:
                    inSz;
                #endif

                len = 0;

                ret = wc_BerToDer(pkiMsg, pkiMsgSz, NULL, &len);
                if (ret != WC_NO_ERR_TRACE(LENGTH_ONLY_E))
                    return ret;
                pkcs7->der = (byte*)XMALLOC(len, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
                if (pkcs7->der == NULL)
                    return MEMORY_E;
                ret = wc_BerToDer(pkiMsg, pkiMsgSz, pkcs7->der, &len);
                if (ret < 0)
                    return ret;

                pkiMsg = in = pkcs7->der;
                pkiMsgSz = pkcs7->derSz = inSz = len;
                *idx = 0;

                if (GetSequence(pkiMsg, idx, &length, pkiMsgSz) < 0)
                    return ASN_PARSE_E;
        #else
                return BER_INDEF_E;
        #endif
            }
        #ifndef NO_PKCS7_STREAM
            if ((ret = wc_PKCS7_StreamEndCase(pkcs7, &tmpIdx, idx)) != 0) {
                break;
            }
        #endif
            wc_PKCS7_ChangeState(pkcs7, WC_PKCS7_INFOSET_STAGE1);
            FALL_THROUGH;

        case WC_PKCS7_INFOSET_STAGE1:
        #ifndef NO_PKCS7_STREAM
            if ((ret = wc_PKCS7_AddDataToStream(pkcs7, in, inSz, MAX_OID_SZ +
                            MAX_LENGTH_SZ + ASN_TAG_SZ, &pkiMsg, idx)) != 0) {
                return ret;
            }

            pkiMsgSz = (pkcs7->stream->length > 0)? pkcs7->stream->length :inSz;
        #endif
            if (pkcs7->contentOID != FIRMWARE_PKG_DATA ||
                    type == AUTH_ENVELOPED_DATA) {
                if (ret == 0 && wc_GetContentType(pkiMsg, idx, &contentType,
                            pkiMsgSz) < 0)
                    ret = ASN_PARSE_E;

                if (ret == 0) {
                    if (type == ENVELOPED_DATA && contentType != ENVELOPED_DATA) {
                        WOLFSSL_MSG("PKCS#7 input not of type EnvelopedData");
                        ret = PKCS7_OID_E;
                    } else if (type == AUTH_ENVELOPED_DATA &&
                           contentType != AUTH_ENVELOPED_DATA) {
                        WOLFSSL_MSG("PKCS#7 input not of type AuthEnvelopedData");
                        ret = PKCS7_OID_E;
                    }
                }

                if (ret == 0 && GetASNTag(pkiMsg, idx, &tag, pkiMsgSz) != 0)
                    ret = ASN_PARSE_E;

                if (ret == 0 && tag != (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC
                            | 0))
                    ret = ASN_PARSE_E;

                if (ret == 0 && GetLength_ex(pkiMsg, idx, &length, pkiMsgSz,
                            NO_USER_CHECK) < 0)
                    ret = ASN_PARSE_E;
            }

            if (ret < 0)
                break;

        #ifndef NO_PKCS7_STREAM
            if ((ret = wc_PKCS7_StreamEndCase(pkcs7, &tmpIdx, idx)) != 0) {
                    break;
            }
        #endif
            wc_PKCS7_ChangeState(pkcs7, WC_PKCS7_INFOSET_STAGE2);
            FALL_THROUGH;

        case WC_PKCS7_INFOSET_STAGE2:
        #ifndef NO_PKCS7_STREAM
            if ((ret = wc_PKCS7_AddDataToStream(pkcs7, in, inSz, MAX_SEQ_SZ +
                            MAX_VERSION_SZ, &pkiMsg, idx)) != 0) {
                return ret;
            }
            pkiMsgSz = (pkcs7->stream->length > 0)? pkcs7->stream->length: inSz;
        #endif
            /* remove EnvelopedData and version */
            if (pkcs7->contentOID != FIRMWARE_PKG_DATA ||
                    type == AUTH_ENVELOPED_DATA) {
                if (ret == 0 && GetSequence_ex(pkiMsg, idx, &length, pkiMsgSz,
                            NO_USER_CHECK) < 0)
                    ret = ASN_PARSE_E;
            }

            if (ret == 0 && GetMyVersion(pkiMsg, idx, &version, pkiMsgSz) < 0)
                ret = ASN_PARSE_E;

            if (ret < 0)
                break;

        #ifndef NO_PKCS7_STREAM
            if ((ret = wc_PKCS7_StreamEndCase(pkcs7, &tmpIdx, idx)) != 0) {
                break;
            }

            pkcs7->stream->varOne = (word32)version;
        #endif
            wc_PKCS7_ChangeState(pkcs7, WC_PKCS7_INFOSET_END);
            FALL_THROUGH;

        case WC_PKCS7_INFOSET_END:
        #ifndef NO_PKCS7_STREAM
            if ((ret = wc_PKCS7_AddDataToStream(pkcs7, in, inSz,
                            MAX_SET_SZ, &pkiMsg, idx)) != 0) {
                return ret;
            }
            pkiMsgSz = (pkcs7->stream->length > 0)? pkcs7->stream->length: inSz;
            version = (int)pkcs7->stream->varOne;
        #endif

            if (type == ENVELOPED_DATA) {
                /* TODO :: make this more accurate */
                if ((pkcs7->publicKeyOID == RSAk &&
                     (version != 0 && version != 2))
                #ifdef HAVE_ECC
                        || (pkcs7->publicKeyOID == ECDSAk &&
                            (version != 0 && version != 2 && version != 3))
                #endif
                        ) {
                    WOLFSSL_MSG("PKCS#7 envelopedData version incorrect");
                    ret = ASN_VERSION_E;
                }
            } else {
                /* AuthEnvelopedData version MUST be 0 */
                if (version != 0) {
                    WOLFSSL_MSG("PKCS#7 AuthEnvelopedData needs to be of version 0");
                    ret = ASN_VERSION_E;
                }
            }

            /* remove RecipientInfo set, get length of set */
            if (ret == 0 && GetSet_ex(pkiMsg, idx, &length, pkiMsgSz,
                        NO_USER_CHECK) < 0)
                ret = ASN_PARSE_E;

            if (ret < 0)
                break;

        #ifndef NO_PKCS7_STREAM
            if ((ret = wc_PKCS7_StreamEndCase(pkcs7, &tmpIdx, idx)) != 0) {
                break;
            }
        #endif

            if (ret == 0)
                ret = length;

            break;

        default:
            WOLFSSL_MSG("Bad PKCS7 info set state");
            ret = BAD_FUNC_ARG;
            break;
    }

    return ret;
}


/* Import secret/private key into a PKCS7 structure. Used for setting
 * the secret key for decryption a EnvelopedData KEKRI RecipientInfo.
 *
 * Returns 0 on success, negative upon error */
WOLFSSL_API int wc_PKCS7_SetKey(wc_PKCS7* pkcs7, byte* key, word32 keySz)
{
    if (pkcs7 == NULL || key == NULL || keySz == 0)
        return BAD_FUNC_ARG;

    pkcs7->privateKey = key;
    pkcs7->privateKeySz = keySz;

    return 0;
}


/* append data to encrypted content cache in PKCS7 structure
 * return 0 on success, negative on error */
static int PKCS7_CacheEncryptedContent(wc_PKCS7* pkcs7, byte* in, word32 inSz)
{
    byte* oldCache;
    word32 oldCacheSz;

    if (pkcs7 == NULL || in == NULL)
        return BAD_FUNC_ARG;

    /* save pointer to old cache */
    oldCache = pkcs7->cachedEncryptedContent;
    oldCacheSz = pkcs7->cachedEncryptedContentSz;

    /* re-allocate new buffer to fit appended data */
    pkcs7->cachedEncryptedContent = (byte*)XMALLOC(oldCacheSz + inSz,
            pkcs7->heap, DYNAMIC_TYPE_PKCS7);
    if (pkcs7->cachedEncryptedContent == NULL) {
        pkcs7->cachedEncryptedContentSz = 0;
        XFREE(oldCache, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return MEMORY_E;
    }

    if (oldCache != NULL) {
        XMEMCPY(pkcs7->cachedEncryptedContent, oldCache, oldCacheSz);
    }
    XMEMCPY(pkcs7->cachedEncryptedContent + oldCacheSz, in, inSz);
    pkcs7->cachedEncryptedContentSz += inSz;

    XFREE(oldCache, pkcs7->heap, DYNAMIC_TYPE_PKCS7);

    return 0;
}


/* unwrap and decrypt PKCS#7 envelopedData object, return decoded size */
WOLFSSL_API int wc_PKCS7_DecodeEnvelopedData(wc_PKCS7* pkcs7, byte* in,
                                         word32 inSz, byte* output,
                                         word32 outputSz)
{
    int recipFound = 0;
    int ret, length = 0;
    word32 idx = 0;
#ifndef NO_PKCS7_STREAM
    word32 tmpIdx = 0;
#endif
    word32 contentType = 0, encOID = 0;
    word32 decryptedKeySz = MAX_ENCRYPTED_KEY_SZ;

    int expBlockSz = 0, blockKeySz = 0;
    byte  tmpIvBuf[MAX_CONTENT_IV_SIZE];
    byte* tmpIv = tmpIvBuf;

    byte* pkiMsg    = in;
    word32 pkiMsgSz = inSz;
    byte* decryptedKey = NULL;
    int encryptedContentTotalSz = 0;
    int encryptedContentSz = 0;
    byte padLen;
    byte* encryptedContent = NULL;
    int explicitOctet = 0;
    word32 localIdx;
    byte   tag = 0;

    if (pkcs7 == NULL)
        return BAD_FUNC_ARG;

    if (pkiMsg == NULL || pkiMsgSz == 0 ||
        output == NULL || outputSz == 0)
        return BAD_FUNC_ARG;

#ifndef NO_PKCS7_STREAM
    (void)tmpIv; /* help out static analysis */
    if (pkcs7->stream == NULL) {
        if ((ret = wc_PKCS7_CreateStream(pkcs7)) != 0) {
            return ret;
        }
    }
#endif

    switch (pkcs7->state) {
        case WC_PKCS7_START:
        case WC_PKCS7_INFOSET_START:
        case WC_PKCS7_INFOSET_BER:
        case WC_PKCS7_INFOSET_STAGE1:
        case WC_PKCS7_INFOSET_STAGE2:
        case WC_PKCS7_INFOSET_END:
            ret = wc_PKCS7_ParseToRecipientInfoSet(pkcs7, pkiMsg, pkiMsgSz,
                    &idx, ENVELOPED_DATA);
            if (ret < 0) {
                break;
            }

        #ifdef ASN_BER_TO_DER
            /* check if content was BER and has been converted to DER */
            if (pkcs7->derSz > 0) {
                pkiMsg = in = pkcs7->der;
                inSz = pkcs7->derSz;
            #ifdef NO_PKCS7_STREAM
                pkiMsgSz = pkcs7->derSz;
            #endif
            }
        #endif

            decryptedKey = (byte*)XMALLOC(MAX_ENCRYPTED_KEY_SZ, pkcs7->heap,
                                                       DYNAMIC_TYPE_PKCS7);
            if (decryptedKey == NULL)
                return MEMORY_E;
            wc_PKCS7_ChangeState(pkcs7, WC_PKCS7_ENV_2);
        #ifndef NO_PKCS7_STREAM
            tmpIdx = idx;
            pkcs7->stream->aad = decryptedKey;
        #endif
            FALL_THROUGH;

        case WC_PKCS7_ENV_2:
        #ifndef NO_PKCS7_STREAM
            /* store up enough buffer for initial info set decode */
            if ((ret = wc_PKCS7_AddDataToStream(pkcs7, in, inSz, MAX_LENGTH_SZ +
                            MAX_VERSION_SZ + ASN_TAG_SZ, &pkiMsg, &idx)) != 0) {
                return ret;
            }
        #endif
            FALL_THROUGH;

        case WC_PKCS7_DECRYPT_KTRI:
        case WC_PKCS7_DECRYPT_KTRI_2:
        case WC_PKCS7_DECRYPT_KTRI_3:
        case WC_PKCS7_DECRYPT_KARI:
        case WC_PKCS7_DECRYPT_KEKRI:
        case WC_PKCS7_DECRYPT_PWRI:
        case WC_PKCS7_DECRYPT_ORI:
        #ifndef NO_PKCS7_STREAM
            decryptedKey   = pkcs7->stream->aad;
            decryptedKeySz = MAX_ENCRYPTED_KEY_SZ;
        #endif

            ret = wc_PKCS7_DecryptRecipientInfos(pkcs7, in, inSz, &idx,
                                        decryptedKey, &decryptedKeySz,
                                        &recipFound);
            if (ret == 0 && recipFound == 0) {
                WOLFSSL_MSG("No recipient found in envelopedData that matches input");
                ret = PKCS7_RECIP_E;
            }

            if (ret != 0)
                break;
        #ifndef NO_PKCS7_STREAM
            tmpIdx               = idx;
            pkcs7->stream->aadSz = decryptedKeySz;
        #endif
            wc_PKCS7_ChangeState(pkcs7, WC_PKCS7_ENV_3);
            FALL_THROUGH;

        case WC_PKCS7_ENV_3:

        #ifndef NO_PKCS7_STREAM
            if ((ret = wc_PKCS7_AddDataToStream(pkcs7, in, inSz, MAX_LENGTH_SZ +
                                                MAX_VERSION_SZ + ASN_TAG_SZ +
                                                MAX_LENGTH_SZ, &pkiMsg, &idx))
                                                != 0) {
                return ret;
            }
            pkiMsgSz = (pkcs7->stream->length > 0)? pkcs7->stream->length: inSz;
        #else
            ret = 0;
        #endif

            /* remove EncryptedContentInfo */
            if (GetSequence_ex(pkiMsg, &idx, &length, pkiMsgSz,
                        NO_USER_CHECK) < 0) {
                ret = ASN_PARSE_E;
            }

            if (ret == 0 && wc_GetContentType(pkiMsg, &idx, &contentType,
                        pkiMsgSz) < 0) {
                ret = ASN_PARSE_E;
            }

            if (ret == 0) {
                pkcs7->contentOID = (int)contentType;
            }

            if (ret == 0 && GetAlgoId(pkiMsg, &idx, &encOID, oidBlkType,
                        pkiMsgSz) < 0) {
                ret = ASN_PARSE_E;
            }

            blockKeySz = wc_PKCS7_GetOIDKeySize((int)encOID);
            if (ret == 0 && blockKeySz < 0) {
                ret = blockKeySz;
            }

            expBlockSz = wc_PKCS7_GetOIDBlockSize((int)encOID);
            if (ret == 0 && expBlockSz < 0) {
                ret = expBlockSz;
            }

            /* get block cipher IV, stored in OPTIONAL parameter of AlgoID */
            if (ret == 0 && GetASNTag(pkiMsg, &idx, &tag, pkiMsgSz) != 0) {
                ret = ASN_PARSE_E;
            }

            if (ret == 0 && tag != ASN_OCTET_STRING) {
                ret = ASN_PARSE_E;
            }

            if (ret == 0 && GetLength_ex(pkiMsg, &idx, &length, pkiMsgSz,
                        NO_USER_CHECK) < 0) {
                ret = ASN_PARSE_E;
            }

            if (ret == 0 && length != expBlockSz) {
                WOLFSSL_MSG("Incorrect IV length, must be of content alg block size");
                ret = ASN_PARSE_E;
            }

            if (ret != 0)
                break;
        #ifndef NO_PKCS7_STREAM
            if ((ret = wc_PKCS7_StreamEndCase(pkcs7, &tmpIdx, &idx)) != 0) {
                break;
            }
            wc_PKCS7_StreamStoreVar(pkcs7, encOID, expBlockSz, length);
            pkcs7->stream->contentSz = (word32)blockKeySz;
            pkcs7->stream->expected = (word32)length + MAX_LENGTH_SZ + MAX_LENGTH_SZ +
                ASN_TAG_SZ + ASN_TAG_SZ;
        #endif
            wc_PKCS7_ChangeState(pkcs7, WC_PKCS7_ENV_4);
            FALL_THROUGH;

        case WC_PKCS7_ENV_4:

        #ifndef NO_PKCS7_STREAM
            if ((ret = wc_PKCS7_AddDataToStream(pkcs7, in, inSz,
                            pkcs7->stream->expected, &pkiMsg, &idx)) != 0) {
                return ret;
            }
            pkiMsgSz = (pkcs7->stream->length > 0)? pkcs7->stream->length: inSz;

            wc_PKCS7_StreamGetVar(pkcs7, 0, 0, &length);
            tmpIv = pkcs7->stream->tmpIv;
            if (tmpIv == NULL) {
                /* check added to help out static analysis tool */
                ret = MEMORY_E;
                break;
            }
        #else
            ret = 0;
        #endif

            XMEMCPY(tmpIv, &pkiMsg[idx], (word32)length);
            idx += (word32)length;

            explicitOctet = 0;
            localIdx = idx;
            if (GetASNTag(pkiMsg, &localIdx, &tag, pkiMsgSz) == 0 &&
                    tag == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 0)) {
                explicitOctet = 1;
            }

            /* read encryptedContent, cont[0] */
            if (tag != (ASN_CONTEXT_SPECIFIC | 0) &&
                          tag != (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 0)) {
                ret = ASN_PARSE_E;
            }
            idx++;

            if (ret == 0 && GetLength(pkiMsg, &idx, &encryptedContentTotalSz,
                                                               pkiMsgSz) <= 0) {
                ret = ASN_PARSE_E;
            }

            if (ret != 0)
                break;

        #ifndef NO_PKCS7_STREAM
            if ((ret = wc_PKCS7_StreamEndCase(pkcs7, &tmpIdx, &idx)) != 0) {
                break;
            }
            pkcs7->stream->expected = (word32)encryptedContentTotalSz;
            wc_PKCS7_StreamGetVar(pkcs7, &encOID, &expBlockSz, 0);
            wc_PKCS7_StreamStoreVar(pkcs7, encOID, expBlockSz, explicitOctet);
        #endif
            wc_PKCS7_ChangeState(pkcs7, WC_PKCS7_ENV_5);
            FALL_THROUGH;

        case WC_PKCS7_ENV_5:

        #ifndef NO_PKCS7_STREAM
            if ((ret = wc_PKCS7_AddDataToStream(pkcs7, in, inSz,
                            pkcs7->stream->expected, &pkiMsg, &idx)) != 0) {
                return ret;
            }

            wc_PKCS7_StreamGetVar(pkcs7, &encOID, &expBlockSz, &explicitOctet);
            tmpIv = pkcs7->stream->tmpIv;
            encryptedContentTotalSz = (int)pkcs7->stream->expected;

            /* restore decrypted key */
            decryptedKey   = pkcs7->stream->aad;
            decryptedKeySz = pkcs7->stream->aadSz;
            blockKeySz = (int)pkcs7->stream->contentSz;
        #else
            ret = 0;
        #endif

            if (explicitOctet) {
                /* encrypted content may be fragmented into multiple
                 * consecutive OCTET STRINGs, if so loop through
                 * collecting and caching encrypted content bytes */
                localIdx = idx;
                while (idx < (localIdx + (word32)encryptedContentTotalSz)) {

                    if (GetASNTag(pkiMsg, &idx, &tag, pkiMsgSz) < 0) {
                        ret = ASN_PARSE_E;
                    }

                    if (ret == 0 && (tag != ASN_OCTET_STRING)) {
                        ret = ASN_PARSE_E;
                    }

                    if (ret == 0 && GetLength(pkiMsg, &idx,
                                &encryptedContentSz, pkiMsgSz) <= 0) {
                        ret = ASN_PARSE_E;
                    }

                    if (ret == 0) {
                        ret = PKCS7_CacheEncryptedContent(pkcs7, &pkiMsg[idx],
                                                          (word32)encryptedContentSz);
                    }

                    if (ret != 0) {
                        break;
                    }

                    /* advance idx past encrypted content */
                    idx += (word32)encryptedContentSz;
                }

                if (ret != 0) {
                    break;
                }

            } else {
                /* cache encrypted content, no OCTET STRING */
                ret = PKCS7_CacheEncryptedContent(pkcs7, &pkiMsg[idx],
                                                  (word32)encryptedContentTotalSz);
                if (ret != 0) {
                    break;
                }
                idx += (word32)encryptedContentTotalSz;
            }

            /* use cached content */
            encryptedContent = pkcs7->cachedEncryptedContent;
            encryptedContentSz = (int)pkcs7->cachedEncryptedContentSz;

            /* decrypt encryptedContent */
            ret = wc_PKCS7_DecryptContent(pkcs7, (int)encOID, decryptedKey,
                    blockKeySz, tmpIv, expBlockSz, NULL, 0, NULL, 0,
                    encryptedContent, encryptedContentSz, encryptedContent,
                    pkcs7->devId, pkcs7->heap);
            if (ret != 0) {
                break;
            }

            padLen = encryptedContent[encryptedContentSz-1];

            /* copy plaintext to output */
            if (padLen > encryptedContentSz ||
                    (word32)(encryptedContentSz - padLen) > outputSz) {
                ret = BUFFER_E;
                break;
            }
            XMEMCPY(output, encryptedContent,
                                           (word32)encryptedContentSz - padLen);

            /* free memory, zero out keys */
            ForceZero(decryptedKey, MAX_ENCRYPTED_KEY_SZ);
            XFREE(decryptedKey, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
            if (pkcs7->cachedEncryptedContent != NULL) {
                XFREE(pkcs7->cachedEncryptedContent, pkcs7->heap,
                      DYNAMIC_TYPE_PKCS7);
                pkcs7->cachedEncryptedContent = NULL;
                pkcs7->cachedEncryptedContentSz = 0;
            }

            ret = encryptedContentSz - padLen;
        #ifndef NO_PKCS7_STREAM
            pkcs7->stream->aad = NULL;
            pkcs7->stream->aadSz = 0;
            wc_PKCS7_ResetStream(pkcs7);
        #endif
            wc_PKCS7_ChangeState(pkcs7, WC_PKCS7_START);
            break;

        default:
            WOLFSSL_MSG("PKCS#7 unknown decode enveloped state");
            ret = BAD_FUNC_ARG;
    }

#ifndef NO_PKCS7_STREAM
    if (ret < 0 && ret != WC_NO_ERR_TRACE(WC_PKCS7_WANT_READ_E)) {
        wc_PKCS7_ResetStream(pkcs7);
        wc_PKCS7_ChangeState(pkcs7, WC_PKCS7_START);
        if (pkcs7->cachedEncryptedContent != NULL) {
            XFREE(pkcs7->cachedEncryptedContent, pkcs7->heap,
                  DYNAMIC_TYPE_PKCS7);
            pkcs7->cachedEncryptedContent = NULL;
            pkcs7->cachedEncryptedContentSz = 0;
        }
    }
#else
    if (decryptedKey != NULL && ret < 0) {
        ForceZero(decryptedKey, MAX_ENCRYPTED_KEY_SZ);
        XFREE(decryptedKey, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
    }
    if (pkcs7->cachedEncryptedContent != NULL && ret < 0) {
        XFREE(pkcs7->cachedEncryptedContent, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        pkcs7->cachedEncryptedContent = NULL;
        pkcs7->cachedEncryptedContentSz = 0;
    }
#endif
    return ret;
}


/* build PKCS#7 authEnvelopedData content type, return enveloped size */
int wc_PKCS7_EncodeAuthEnvelopedData(wc_PKCS7* pkcs7, byte* output,
                                     word32 outputSz)
{
#if defined(HAVE_AESGCM) || defined(HAVE_AESCCM)
    int ret, idx = 0;
    int totalSz, encryptedAllocSz, encryptedOutSz;

    int contentInfoSeqSz, outerContentTypeSz, outerContentSz;
    byte contentInfoSeq[MAX_SEQ_SZ];
    byte outerContentType[MAX_ALGO_SZ];
    byte outerContent[MAX_SEQ_SZ];

    int envDataSeqSz, verSz;
    byte envDataSeq[MAX_SEQ_SZ];
    byte ver[MAX_VERSION_SZ];

    WC_RNG rng;
    int blockSz, blockKeySz;
    byte* plain;
    byte* encryptedContent;

    Pkcs7EncodedRecip* tmpRecip = NULL;
    int recipSz, recipSetSz;
    byte recipSet[MAX_SET_SZ];

    int encContentOctetSz, encContentSeqSz, contentTypeSz;
    int contentEncAlgoSz, nonceOctetStringSz, macOctetStringSz;
    byte encContentSeq[MAX_SEQ_SZ];
    byte contentType[MAX_ALGO_SZ];
    byte contentEncAlgo[MAX_ALGO_SZ];
    byte nonceOctetString[MAX_OCTET_STR_SZ];
    byte encContentOctet[MAX_OCTET_STR_SZ];
    byte macOctetString[MAX_OCTET_STR_SZ];

    byte authTag[WC_AES_BLOCK_SIZE];
    byte nonce[GCM_NONCE_MID_SZ];   /* GCM nonce is larger than CCM */
    byte macInt[MAX_VERSION_SZ];
    byte algoParamSeq[MAX_SEQ_SZ];
    word32 nonceSz = 0, macIntSz = 0, algoParamSeqSz = 0;

    /* authAttribs */
    byte* flatAuthAttribs = NULL;
    byte authAttribSet[MAX_SET_SZ];
    EncodedAttrib authAttribs[MAX_AUTH_ATTRIBS_SZ];
    word32 authAttribsSz = 0, authAttribsCount = 0;
    word32 authAttribsSetSz = 0;

    byte* aadBuffer = NULL;
    word32 aadBufferSz = 0;
    byte authAttribAadSet[MAX_SET_SZ];
    word32 authAttribsAadSetSz = 0;

    /* unauthAttribs */
    byte* flatUnauthAttribs = NULL;
    byte unauthAttribSet[MAX_SET_SZ];
    EncodedAttrib unauthAttribs[MAX_UNAUTH_ATTRIBS_SZ];
    word32 unauthAttribsSz = 0, unauthAttribsCount = 0;
    word32 unauthAttribsSetSz = 0;


    PKCS7Attrib contentTypeAttrib;
    byte contentTypeValue[MAX_OID_SZ];
    /* contentType OID (1.2.840.113549.1.9.3) */
    const byte contentTypeOid[] =
            { ASN_OBJECT_ID, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xF7, 0x0d, 0x01,
                             0x09, 0x03 };
    if (pkcs7 == NULL || pkcs7->content == NULL || pkcs7->contentSz == 0)
        return BAD_FUNC_ARG;

    if (output == NULL || outputSz == 0)
        return BAD_FUNC_ARG;

    switch (pkcs7->encryptOID) {
#ifdef HAVE_AESGCM
    #ifdef WOLFSSL_AES_128
        case AES128GCMb:
            break;
    #endif
    #ifdef WOLFSSL_AES_192
        case AES192GCMb:
            break;
    #endif
    #ifdef WOLFSSL_AES_256
        case AES256GCMb:
            break;
    #endif
#endif
#ifdef HAVE_AESCCM
    #ifdef WOLFSSL_AES_128
        case AES128CCMb:
            break;
    #endif
    #ifdef WOLFSSL_AES_192
        case AES192CCMb:
            break;
    #endif
    #ifdef WOLFSSL_AES_256
        case AES256CCMb:
            break;
    #endif
#endif
        default:
            WOLFSSL_MSG("CMS AuthEnvelopedData must use AES-GCM or AES-CCM");
            return BAD_FUNC_ARG;
    }

    blockKeySz = wc_PKCS7_GetOIDKeySize(pkcs7->encryptOID);
    if (blockKeySz < 0)
        return blockKeySz;

    blockSz = wc_PKCS7_GetOIDBlockSize(pkcs7->encryptOID);
    if (blockSz < 0)
        return blockSz;

    /* outer content type */
    ret = wc_SetContentType(AUTH_ENVELOPED_DATA, outerContentType,
                            sizeof(outerContentType));
    if (ret < 0)
        return ret;

    outerContentTypeSz = ret;

    /* version, defined as 0 in RFC 5083 */
    verSz = SetMyVersion(0, ver, 0);

    /* generate random content encryption key */
    ret = PKCS7_GenerateContentEncryptionKey(pkcs7, (word32)blockKeySz);
    if (ret != 0) {
        return ret;
    }

    /* build RecipientInfo, only if user manually set singleCert and size */
    if (pkcs7->singleCert != NULL && pkcs7->singleCertSz > 0) {
        switch (pkcs7->publicKeyOID) {
        #ifndef NO_RSA
            case RSAk:
                ret = wc_PKCS7_AddRecipient_KTRI(pkcs7, pkcs7->singleCert,
                                                 pkcs7->singleCertSz, 0);
                break;
        #endif
        #ifdef HAVE_ECC
            case ECDSAk:
                ret = wc_PKCS7_AddRecipient_KARI(pkcs7, pkcs7->singleCert,
                                                 pkcs7->singleCertSz,
                                                 pkcs7->keyWrapOID,
                                                 pkcs7->keyAgreeOID, pkcs7->ukm,
                                                 pkcs7->ukmSz, 0);
                break;
        #endif

            default:
                WOLFSSL_MSG("Unsupported RecipientInfo public key type");
                return BAD_FUNC_ARG;
        };

        if (ret < 0) {
            WOLFSSL_MSG("Failed to create RecipientInfo");
            return ret;
        }
    }

    recipSz = wc_PKCS7_GetRecipientListSize(pkcs7);
    if (recipSz < 0) {
        return ret;

    } else if (recipSz == 0) {
        WOLFSSL_MSG("You must add at least one CMS recipient");
        return PKCS7_RECIP_E;
    }
    recipSetSz = (int)SetSet((word32)recipSz, recipSet);

    /* generate random nonce and IV for encryption */
    switch (pkcs7->encryptOID) {
#ifdef HAVE_AESGCM
    #ifdef WOLFSSL_AES_128
        case AES128GCMb:
            FALL_THROUGH;
    #endif
    #ifdef WOLFSSL_AES_192
        case AES192GCMb:
            FALL_THROUGH;
    #endif
    #ifdef WOLFSSL_AES_256
        case AES256GCMb:
    #endif
    #if defined(WOLFSSL_AES_128) || defined(WOLFSSL_AES_192) || \
        defined(WOLFSSL_AES_256)
            /* GCM nonce is GCM_NONCE_MID_SZ (12) */
            nonceSz = GCM_NONCE_MID_SZ;
            break;
    #endif
#endif /* HAVE_AESGCM */
#ifdef HAVE_AESCCM
    #ifdef WOLFSSL_AES_128
        case AES128CCMb:
            FALL_THROUGH;
    #endif
    #ifdef WOLFSSL_AES_192
        case AES192CCMb:
            FALL_THROUGH;
    #endif
    #ifdef WOLFSSL_AES_256
        case AES256CCMb:
    #endif
    #if defined(WOLFSSL_AES_128) || defined(WOLFSSL_AES_192) || \
        defined(WOLFSSL_AES_256)
            /* CCM nonce is CCM_NONCE_MIN_SZ (7) */
            nonceSz = CCM_NONCE_MIN_SZ;
            break;
    #endif
#endif /* HAVE_AESCCM */
    }

    ret = wc_InitRng_ex(&rng, pkcs7->heap, pkcs7->devId);
    if (ret != 0) {
        wc_PKCS7_FreeEncodedRecipientSet(pkcs7);
        return ret;
    }

    ret = wc_PKCS7_GenerateBlock(pkcs7, &rng, nonce, nonceSz);
    wc_FreeRng(&rng);
    if (ret != 0) {
        wc_PKCS7_FreeEncodedRecipientSet(pkcs7);
        return ret;
    }


    /* authAttribs: add contentType attrib if needed */
    if (pkcs7->contentOID != DATA) {

        XMEMSET(&contentTypeAttrib, 0, sizeof contentTypeAttrib);

        /* if type is not id-data, contentType attribute MUST be added */
        contentTypeAttrib.oid = contentTypeOid;
        contentTypeAttrib.oidSz = sizeof(contentTypeOid);

        /* try to set from contentOID first, known types */
        ret = wc_SetContentType(pkcs7->contentOID, contentTypeValue,
                                sizeof(contentTypeValue));
        if (ret > 0) {
            contentTypeAttrib.value = contentTypeValue;
            contentTypeAttrib.valueSz = (word32)ret;

        /* otherwise, try to set from custom content type */
        } else {
            if (pkcs7->contentTypeSz == 0) {
                WOLFSSL_MSG("CMS pkcs7->contentType must be set if "
                            "contentOID is not");
                wc_PKCS7_FreeEncodedRecipientSet(pkcs7);
                return BAD_FUNC_ARG;
            }
            contentTypeAttrib.value = pkcs7->contentType;
            contentTypeAttrib.valueSz = pkcs7->contentTypeSz;
        }

        authAttribsSz += (word32)EncodeAttributes(authAttribs, 1,
                                                         &contentTypeAttrib, 1);
        authAttribsCount += 1;
    }

    /* authAttribs: add in user authenticated attributes */
    if (pkcs7->authAttribs != NULL && pkcs7->authAttribsSz > 0) {
        authAttribsSz += (word32)EncodeAttributes(
                                 authAttribs + authAttribsCount,
                                 (int)(MAX_AUTH_ATTRIBS_SZ - authAttribsCount),
                                 pkcs7->authAttribs,
                                 (int)pkcs7->authAttribsSz);
        authAttribsCount += pkcs7->authAttribsSz;
    }

    /* authAttribs: flatten authAttribs */
    if (authAttribsSz > 0 && authAttribsCount > 0) {
        flatAuthAttribs = (byte*)XMALLOC(authAttribsSz, pkcs7->heap,
                                         DYNAMIC_TYPE_PKCS7);
        if (flatAuthAttribs == NULL) {
            wc_PKCS7_FreeEncodedRecipientSet(pkcs7);
            return MEMORY_E;
        }

        ret = FlattenAttributes(pkcs7, flatAuthAttribs, authAttribs,
                          (int)authAttribsCount);
        if (ret != 0) {
            wc_PKCS7_FreeEncodedRecipientSet(pkcs7);
            XFREE(flatAuthAttribs, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
            return ret;
        }

        authAttribsSetSz = SetImplicit(ASN_SET, 1, authAttribsSz,
                                       authAttribSet, 0);

        /* From RFC5083, "For the purpose of constructing the AAD, the
         * IMPLICIT [1] tag in the authAttrs field is not used for the
         * DER encoding: rather a universal SET OF tag is used. */
        authAttribsAadSetSz = SetSet(authAttribsSz, authAttribAadSet);

        /* allocate temp buffer to hold alternate attrib encoding for aad */
        aadBuffer = (byte*)XMALLOC(authAttribsSz + authAttribsAadSetSz,
                                   pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (aadBuffer == NULL) {
            wc_PKCS7_FreeEncodedRecipientSet(pkcs7);
            XFREE(flatAuthAttribs, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
            return MEMORY_E;
        }

        /* build up alternate attrib encoding for aad */
        aadBufferSz = 0;
        XMEMCPY(aadBuffer + aadBufferSz, authAttribAadSet, authAttribsAadSetSz);
        aadBufferSz += authAttribsAadSetSz;
        XMEMCPY(aadBuffer + aadBufferSz, flatAuthAttribs, authAttribsSz);
        aadBufferSz += authAttribsSz;
    }

    /* build up unauthenticated attributes (unauthAttrs) */
    if (pkcs7->unauthAttribsSz > 0) {
        unauthAttribsSz = (word32)EncodeAttributes(
                              unauthAttribs + unauthAttribsCount,
                              (int)(MAX_UNAUTH_ATTRIBS_SZ - unauthAttribsCount),
                              pkcs7->unauthAttribs,
                              (int)pkcs7->unauthAttribsSz);
        unauthAttribsCount = pkcs7->unauthAttribsSz;

        flatUnauthAttribs = (byte*)XMALLOC(unauthAttribsSz, pkcs7->heap,
                                            DYNAMIC_TYPE_PKCS7);
        if (flatUnauthAttribs == NULL) {
            wc_PKCS7_FreeEncodedRecipientSet(pkcs7);
            XFREE(aadBuffer, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
            XFREE(flatAuthAttribs, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
            return MEMORY_E;
        }

        FlattenAttributes(pkcs7, flatUnauthAttribs, unauthAttribs,
                          (int)unauthAttribsCount);
        unauthAttribsSetSz = SetImplicit(ASN_SET, 2, unauthAttribsSz,
                                         unauthAttribSet, 0);
    }

    /* AES-GCM/CCM does NOT require padding for plaintext content or
     * AAD inputs RFC 5084 section 3.1 and 3.2, but we must alloc
     * full blocks to ensure crypto only gets full blocks */
    encryptedOutSz = (int)pkcs7->contentSz;
    encryptedAllocSz = (encryptedOutSz % blockSz) ?
                           encryptedOutSz + blockSz -
                           (encryptedOutSz % blockSz) :
                           encryptedOutSz;

    /* Copy content to plain buffer (zero-padded) to encrypt in full,
     * contiguous blocks */
    plain = (byte*)XMALLOC((word32)encryptedAllocSz, pkcs7->heap,
        DYNAMIC_TYPE_PKCS7);
    if (plain == NULL) {
        wc_PKCS7_FreeEncodedRecipientSet(pkcs7);
        XFREE(aadBuffer, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(flatUnauthAttribs, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        XFREE(flatAuthAttribs, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return MEMORY_E;
    }

    XMEMCPY(plain, pkcs7->content, pkcs7->contentSz);
    if ((encryptedAllocSz - encryptedOutSz) > 0) {
        XMEMSET(plain + encryptedOutSz, 0,
            (word32)(encryptedAllocSz - encryptedOutSz));
    }

    encryptedContent = (byte*)XMALLOC((word32)encryptedAllocSz, pkcs7->heap,
                                      DYNAMIC_TYPE_PKCS7);
    if (encryptedContent == NULL) {
        XFREE(plain, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        wc_PKCS7_FreeEncodedRecipientSet(pkcs7);
        XFREE(aadBuffer, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(flatUnauthAttribs, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        XFREE(flatAuthAttribs, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return MEMORY_E;
    }

    /* encrypt content */
    ret = wc_PKCS7_EncryptContent(pkcs7, pkcs7->encryptOID, pkcs7->cek,
            (int)pkcs7->cekSz, nonce, (int)nonceSz, aadBuffer, aadBufferSz,
            authTag, sizeof(authTag), plain, encryptedOutSz, encryptedContent);

    XFREE(plain, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
    plain = NULL;

    XFREE(aadBuffer, pkcs7->heap, DYNAMIC_TYPE_TMP_BUFFER);
    aadBuffer = NULL;

    if (ret != 0) {
        wc_PKCS7_FreeEncodedRecipientSet(pkcs7);
        XFREE(flatUnauthAttribs, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        XFREE(flatAuthAttribs, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        XFREE(encryptedContent, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return ret;
    }

    /* EncryptedContentInfo */
    ret = wc_SetContentType(pkcs7->contentOID, contentType,
                            sizeof(contentType));
    if (ret < 0) {
        wc_PKCS7_FreeEncodedRecipientSet(pkcs7);
        XFREE(flatUnauthAttribs, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        XFREE(flatAuthAttribs, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        XFREE(encryptedContent, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return ret;
    }

    contentTypeSz = ret;

    /* put together nonce OCTET STRING */
    nonceOctetStringSz = (int)SetOctetString(nonceSz, nonceOctetString);

    /* put together aes-ICVlen INTEGER */
    macIntSz = (word32)SetMyVersion(sizeof(authTag), macInt, 0);

    /* add nonce and icv len into parameters string RFC5084 */
    algoParamSeqSz = SetSequence((word32)nonceOctetStringSz + nonceSz +
            macIntSz, algoParamSeq);

    /* build up our ContentEncryptionAlgorithmIdentifier sequence,
     * adding (nonceOctetStringSz + blockSz + macIntSz) for nonce OCTET STRING
     * and tag size */
    contentEncAlgoSz = (int)SetAlgoID(pkcs7->encryptOID, contentEncAlgo,
                                 oidBlkType, nonceOctetStringSz + (int)nonceSz +
                                 (int)macIntSz + (int)algoParamSeqSz);

    if (contentEncAlgoSz == 0) {
        wc_PKCS7_FreeEncodedRecipientSet(pkcs7);
        XFREE(flatUnauthAttribs, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        XFREE(flatAuthAttribs, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        XFREE(encryptedContent, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return BAD_FUNC_ARG;
    }

    encContentOctetSz = (int)SetImplicit(ASN_OCTET_STRING, 0, (word32)encryptedOutSz,
                                    encContentOctet, 0);
    encContentSeqSz = (int)SetSequence((word32)contentTypeSz +
                               (word32)contentEncAlgoSz +
                               (word32)nonceOctetStringSz + nonceSz + macIntSz +
                               algoParamSeqSz + (word32)encContentOctetSz +
                               (word32)encryptedOutSz, encContentSeq);

    macOctetStringSz = (int)SetOctetString(sizeof(authTag), macOctetString);

    /* keep track of sizes for outer wrapper layering */
    totalSz = verSz + recipSetSz + recipSz + encContentSeqSz +
              contentTypeSz + contentEncAlgoSz + nonceOctetStringSz +
              (int)nonceSz + (int)macIntSz + (int)algoParamSeqSz +
              encContentOctetSz + encryptedOutSz + (int)authAttribsSz +
              (int)authAttribsSetSz + macOctetStringSz + (int)sizeof(authTag) +
              (int)unauthAttribsSz + (int)unauthAttribsSetSz;

    /* EnvelopedData */
    envDataSeqSz = (int)SetSequence((word32)totalSz, envDataSeq);
    totalSz += envDataSeqSz;

    /* outer content */
    outerContentSz = (int)SetExplicit(0, (word32)totalSz, outerContent, 0);
    totalSz += outerContentTypeSz;
    totalSz += outerContentSz;

    /* ContentInfo */
    contentInfoSeqSz = (int)SetSequence((word32)totalSz, contentInfoSeq);
    totalSz += contentInfoSeqSz;

    if (totalSz > (int)outputSz) {
        WOLFSSL_MSG("Pkcs7_encrypt output buffer too small");
        wc_PKCS7_FreeEncodedRecipientSet(pkcs7);
        XFREE(flatUnauthAttribs, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        XFREE(flatAuthAttribs, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        XFREE(encryptedContent, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return BUFFER_E;
    }

    XMEMCPY(output + idx, contentInfoSeq, (word32)contentInfoSeqSz);
    idx += contentInfoSeqSz;
    XMEMCPY(output + idx, outerContentType, (word32)outerContentTypeSz);
    idx += outerContentTypeSz;
    XMEMCPY(output + idx, outerContent, (word32)outerContentSz);
    idx += outerContentSz;
    XMEMCPY(output + idx, envDataSeq, (word32)envDataSeqSz);
    idx += envDataSeqSz;
    XMEMCPY(output + idx, ver, (word32)verSz);
    idx += verSz;
    XMEMCPY(output + idx, recipSet, (word32)recipSetSz);
    idx += recipSetSz;
    /* copy in recipients from list */
    tmpRecip = pkcs7->recipList;
    while (tmpRecip != NULL) {
        XMEMCPY(output + idx, tmpRecip->recip, tmpRecip->recipSz);
        idx += (int)tmpRecip->recipSz;
        tmpRecip = tmpRecip->next;
    }
    wc_PKCS7_FreeEncodedRecipientSet(pkcs7);
    XMEMCPY(output + idx, encContentSeq, (word32)encContentSeqSz);
    idx += encContentSeqSz;
    XMEMCPY(output + idx, contentType, (word32)contentTypeSz);
    idx += contentTypeSz;
    XMEMCPY(output + idx, contentEncAlgo, (word32)contentEncAlgoSz);
    idx += contentEncAlgoSz;
    XMEMCPY(output + idx, algoParamSeq, algoParamSeqSz);
    idx += (int)algoParamSeqSz;
    XMEMCPY(output + idx, nonceOctetString, (word32)nonceOctetStringSz);
    idx += nonceOctetStringSz;
    XMEMCPY(output + idx, nonce, nonceSz);
    idx += (int)nonceSz;
    XMEMCPY(output + idx, macInt, macIntSz);
    idx += (int)macIntSz;


    XMEMCPY(output + idx, encContentOctet, (word32)encContentOctetSz);
    idx += encContentOctetSz;
    XMEMCPY(output + idx, encryptedContent, (word32)encryptedOutSz);
    idx += encryptedOutSz;

    /* authenticated attributes */
    if (flatAuthAttribs && authAttribsSz > 0) {
        XMEMCPY(output + idx, authAttribSet, authAttribsSetSz);
        idx += (int)authAttribsSetSz;
        XMEMCPY(output + idx, flatAuthAttribs, authAttribsSz);
        idx += (int)authAttribsSz;
        XFREE(flatAuthAttribs, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
    }

    XMEMCPY(output + idx, macOctetString, (word32)macOctetStringSz);
    idx += macOctetStringSz;
    XMEMCPY(output + idx, authTag, sizeof(authTag));
    idx += (int)sizeof(authTag);

    /* unauthenticated attributes */
    if (unauthAttribsSz > 0) {
        XMEMCPY(output + idx, unauthAttribSet, unauthAttribsSetSz);
        idx += (int)unauthAttribsSetSz;
        XMEMCPY(output + idx, flatUnauthAttribs, unauthAttribsSz);
        idx += (int)unauthAttribsSz;
    }

    XFREE(flatUnauthAttribs, pkcs7->heap, DYNAMIC_TYPE_PKCS7);

    XFREE(encryptedContent, pkcs7->heap, DYNAMIC_TYPE_PKCS7);

    return idx;

#else
    WOLFSSL_MSG("AuthEnvelopedData requires AES-GCM or AES-CCM to be enabled");
    (void)pkcs7;
    (void)output;
    (void)outputSz;

    return NOT_COMPILED_IN;
#endif /* HAVE_AESGCM | HAVE_AESCCM */
}


/* unwrap and decrypt PKCS#7 AuthEnvelopedData object, return decoded size */
WOLFSSL_API int wc_PKCS7_DecodeAuthEnvelopedData(wc_PKCS7* pkcs7, byte* in,
                                                 word32 inSz, byte* output,
                                                 word32 outputSz)
{
#if defined(HAVE_AESGCM) || defined(HAVE_AESCCM)
    int recipFound = 0;
    int ret = 0, length = 0;
    word32 idx = 0;
#ifndef NO_PKCS7_STREAM
    word32 tmpIdx = 0;
#endif
    word32 contentType = 0, encOID = 0;
    word32 decryptedKeySz = 0;
    byte* pkiMsg = in;
    word32 pkiMsgSz = inSz;

    int expBlockSz = 0, blockKeySz = 0;
    byte authTag[WC_AES_BLOCK_SIZE];
    byte nonce[GCM_NONCE_MID_SZ];       /* GCM nonce is larger than CCM */
    int nonceSz = 0, authTagSz = 0, macSz = 0;

#ifdef WOLFSSL_SMALL_STACK
    byte* decryptedKey = NULL;
#else
    byte  decryptedKey[MAX_ENCRYPTED_KEY_SZ];
#endif
    int encryptedContentSz = 0;
    int encryptedAllocSz = 0;
    byte* encryptedContent = NULL;
    int explicitOctet = 0;

    byte authAttribSetByte = 0;
    byte* encodedAttribs = NULL;
    word32 encodedAttribIdx = 0, encodedAttribSz = 0;
    byte* authAttrib = NULL;
    int authAttribSz = 0;
    word32 localIdx;
    byte tag = 0;

    if (pkcs7 == NULL)
        return BAD_FUNC_ARG;

    if (pkiMsg == NULL || pkiMsgSz == 0 ||
        output == NULL || outputSz == 0)
        return BAD_FUNC_ARG;
#ifndef NO_PKCS7_STREAM
    if (pkcs7->stream == NULL) {
        if ((ret = wc_PKCS7_CreateStream(pkcs7)) != 0) {
            return ret;
        }
    }
#endif

    switch (pkcs7->state) {
        case WC_PKCS7_START:
        case WC_PKCS7_INFOSET_START:
        case WC_PKCS7_INFOSET_STAGE1:
        case WC_PKCS7_INFOSET_STAGE2:
        case WC_PKCS7_INFOSET_END:
            ret = wc_PKCS7_ParseToRecipientInfoSet(pkcs7, pkiMsg, pkiMsgSz,
                    &idx, AUTH_ENVELOPED_DATA);
            if (ret < 0)
                break;

        #ifndef NO_PKCS7_STREAM
            tmpIdx = idx;
        #endif
            wc_PKCS7_ChangeState(pkcs7, WC_PKCS7_AUTHENV_2);
            FALL_THROUGH;

        case WC_PKCS7_AUTHENV_2:
        #ifndef NO_PKCS7_STREAM
            if ((ret = wc_PKCS7_AddDataToStream(pkcs7, in, inSz, MAX_LENGTH_SZ +
                            MAX_VERSION_SZ + ASN_TAG_SZ, &pkiMsg, &idx)) != 0) {
                break;
            }
        #endif
        #ifdef WOLFSSL_SMALL_STACK
            decryptedKey = (byte*)XMALLOC(MAX_ENCRYPTED_KEY_SZ, pkcs7->heap,
                                                               DYNAMIC_TYPE_PKCS7);
            if (decryptedKey == NULL) {
                ret = MEMORY_E;
                break;
            }
            else {
                XMEMSET(decryptedKey, 0, MAX_ENCRYPTED_KEY_SZ);
            }
        #ifndef NO_PKCS7_STREAM
            pkcs7->stream->key = decryptedKey;
        #endif
        #endif
            XMEMSET(decryptedKey, 0, MAX_ENCRYPTED_KEY_SZ);
            FALL_THROUGH;

        case WC_PKCS7_DECRYPT_KTRI:
        case WC_PKCS7_DECRYPT_KTRI_2:
        case WC_PKCS7_DECRYPT_KTRI_3:
        case WC_PKCS7_DECRYPT_KARI:
        case WC_PKCS7_DECRYPT_KEKRI:
        case WC_PKCS7_DECRYPT_PWRI:
        case WC_PKCS7_DECRYPT_ORI:

            decryptedKeySz = MAX_ENCRYPTED_KEY_SZ;
        #ifdef WOLFSSL_SMALL_STACK
            #ifndef NO_PKCS7_STREAM
            decryptedKey = pkcs7->stream->key;
            #endif
        #endif

            ret = wc_PKCS7_DecryptRecipientInfos(pkcs7, in, inSz, &idx,
                                                decryptedKey, &decryptedKeySz,
                                                &recipFound);
            if (ret != 0) {
                break;
            }

            if (recipFound == 0) {
                WOLFSSL_MSG("No recipient found in envelopedData that matches input");
                ret = PKCS7_RECIP_E;
                break;
            }

        #ifndef NO_PKCS7_STREAM
            tmpIdx = idx;
        #endif
            wc_PKCS7_ChangeState(pkcs7, WC_PKCS7_AUTHENV_3);
            FALL_THROUGH;

        case WC_PKCS7_AUTHENV_3:
        #ifndef NO_PKCS7_STREAM
            if ((ret = wc_PKCS7_AddDataToStream(pkcs7, in, inSz, MAX_SEQ_SZ +
                            MAX_ALGO_SZ + MAX_ALGO_SZ + ASN_TAG_SZ,
                            &pkiMsg, &idx)) != 0) {
                break;
            }
            pkiMsgSz = (pkcs7->stream->length > 0)? pkcs7->stream->length: inSz;
        #endif

            /* remove EncryptedContentInfo */
            if (ret == 0 && GetSequence(pkiMsg, &idx, &length, pkiMsgSz) < 0) {
                ret = ASN_PARSE_E;
            }

            if (ret == 0 && wc_GetContentType(pkiMsg, &idx, &contentType,
                        pkiMsgSz) < 0) {
                ret = ASN_PARSE_E;
            }

            if (ret == 0) {
                pkcs7->contentOID = (int)contentType;
            }

            if (ret == 0 && GetAlgoId(pkiMsg, &idx, &encOID, oidBlkType,
                        pkiMsgSz) < 0) {
                ret = ASN_PARSE_E;
            }

            if (ret == 0) {
                blockKeySz = wc_PKCS7_GetOIDKeySize((int)encOID);
                if (blockKeySz < 0) {
                    ret = blockKeySz;
                }
            }

            if (ret == 0) {
                expBlockSz = wc_PKCS7_GetOIDBlockSize((int)encOID);
                if (expBlockSz < 0) {
                    ret = expBlockSz;
                }
            }

            /* get nonce, stored in OPTIONAL parameter of AlgoID
             * RFC 5084 Appendix lists GCM parameters as
             * seq
             * ---->octet string with nonce
             * ---->aes gcm icvlen
             */
            if (ret == 0 && GetASNTag(pkiMsg, &idx, &tag, pkiMsgSz) < 0) {
                ret = ASN_PARSE_E;
            }


            if (ret == 0 && tag != (ASN_CONSTRUCTED | ASN_SEQUENCE)) {
                WOLFSSL_MSG("Optional parameters is not wrapped in a sequence");
                ret = ASN_PARSE_E;
            }

            if (ret < 0)
                break;

        #ifndef NO_PKCS7_STREAM
            if ((ret = wc_PKCS7_StreamEndCase(pkcs7, &tmpIdx, &idx)) != 0) {
                break;
            }
            wc_PKCS7_StreamStoreVar(pkcs7, encOID, blockKeySz, 0);
        #endif
            wc_PKCS7_ChangeState(pkcs7, WC_PKCS7_AUTHENV_4);
            FALL_THROUGH;

        case WC_PKCS7_AUTHENV_4:

        #ifndef NO_PKCS7_STREAM
            if ((ret = wc_PKCS7_AddDataToStream(pkcs7, in, inSz, MAX_LENGTH_SZ +
                            MAX_VERSION_SZ + ASN_TAG_SZ + MAX_LENGTH_SZ,
                            &pkiMsg, &idx)) != 0) {
                break;
            }
            pkiMsgSz = (pkcs7->stream->length > 0)? pkcs7->stream->length: inSz;
        #endif
            /* get length of optional parameter sequence */
            if (ret == 0 && GetLength(pkiMsg, &idx, &length, pkiMsgSz) < 0) {
                ret = ASN_PARSE_E;
            }

            /* get nonce from octet string */
            if (ret == 0 &&
                GetOctetString(pkiMsg, &idx, &nonceSz, pkiMsgSz) < 0) {
                ret = ASN_PARSE_E;
            }

            if (ret == 0 && nonceSz > (int)sizeof(nonce)) {
                WOLFSSL_MSG("AuthEnvelopedData nonce too large for buffer");
                ret = ASN_PARSE_E;
            }

            if (ret == 0) {
                XMEMCPY(nonce, &pkiMsg[idx], (word32)nonceSz);
                idx += (word32)nonceSz;
            }

            /* get mac size, also stored in OPTIONAL parameter of AlgoID */
            if (ret == 0 && GetMyVersion(pkiMsg, &idx, &macSz, pkiMsgSz) < 0) {
                ret = ASN_PARSE_E;
            }

            if (ret == 0) {
                explicitOctet = 0;
                localIdx = idx;
                if (GetASNTag(pkiMsg, &localIdx, &tag, pkiMsgSz) == 0 &&
                        tag == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 0))
                    explicitOctet = 1;

                /* read encryptedContent, cont[0] */
                ret = GetASNTag(pkiMsg, &idx, &tag, pkiMsgSz);
            }

            if (ret == 0 &&
                    tag != (ASN_CONTEXT_SPECIFIC | 0) &&
                    tag != (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED | 0)) {
                ret = ASN_PARSE_E;
            }

            if (ret == 0 && GetLength(pkiMsg, &idx, &encryptedContentSz,
                        pkiMsgSz) <= 0) {
                ret = ASN_PARSE_E;
            }

            if (explicitOctet) {
                if (ret == 0 && GetASNTag(pkiMsg, &idx, &tag, pkiMsgSz) < 0) {
                    ret = ASN_PARSE_E;
                }
                if (ret == 0 && tag != ASN_OCTET_STRING) {
                    ret = ASN_PARSE_E;
                }

                if (ret == 0 && GetLength(pkiMsg, &idx, &encryptedContentSz,
                            pkiMsgSz) <= 0) {
                    ret = ASN_PARSE_E;
                }
            }

            if (ret < 0)
                break;

        #ifndef NO_PKCS7_STREAM
            if ((ret = wc_PKCS7_StreamEndCase(pkcs7, &tmpIdx, &idx)) != 0) {
                break;
            }

            /* store nonce for later */
            if (nonceSz > 0) {
                pkcs7->stream->nonceSz = (word32)nonceSz;
                pkcs7->stream->nonce = (byte*)XMALLOC((word32)nonceSz,
                        pkcs7->heap, DYNAMIC_TYPE_PKCS7);
                if (pkcs7->stream->nonce == NULL) {
                    ret = MEMORY_E;
                    break;
                }
                else {
                    XMEMCPY(pkcs7->stream->nonce, nonce, (word32)nonceSz);
                }
            }

            pkcs7->stream->expected = (word32)encryptedContentSz;
            wc_PKCS7_StreamStoreVar(pkcs7, encOID, blockKeySz,
                    encryptedContentSz);
        #endif

            wc_PKCS7_ChangeState(pkcs7, WC_PKCS7_AUTHENV_5);
            FALL_THROUGH;

        case WC_PKCS7_AUTHENV_5:
        #ifndef NO_PKCS7_STREAM
            if ((ret = wc_PKCS7_AddDataToStream(pkcs7, in, inSz, MAX_LENGTH_SZ +
                            ASN_TAG_SZ + ASN_TAG_SZ + pkcs7->stream->expected,
                            &pkiMsg, &idx)) != 0) {
                break;
            }
            pkiMsgSz = (pkcs7->stream->length > 0)? pkcs7->stream->length: inSz;

            encryptedContentSz = (int)pkcs7->stream->expected;
        #else
            pkiMsgSz = inSz;
        #endif

            if (expBlockSz == 0) {
        #ifndef NO_PKCS7_STREAM
                wc_PKCS7_StreamGetVar(pkcs7, &encOID, NULL, NULL);
        #endif
                if (encOID == 0)
                    expBlockSz = 1;
                else {
                    expBlockSz = wc_PKCS7_GetOIDBlockSize((int)encOID);
                    if (expBlockSz < 0) {
                        ret = expBlockSz;
                        break;
                    } else if (expBlockSz == 0)
                        expBlockSz = 1;
                }
            }

            /* AES-GCM/CCM does NOT require padding for plaintext content or
             * AAD inputs RFC 5084 section 3.1 and 3.2, but we must alloc
             * full blocks to ensure crypto only gets full blocks */
            encryptedAllocSz = (encryptedContentSz % expBlockSz) ?
                                   encryptedContentSz + expBlockSz -
                                   (encryptedContentSz % expBlockSz) :
                                   encryptedContentSz;
            encryptedContent = (byte*)XMALLOC((word32)encryptedAllocSz,
                                               pkcs7->heap, DYNAMIC_TYPE_PKCS7);
            if (ret == 0 && encryptedContent == NULL) {
                ret = MEMORY_E;
            }

            if (ret == 0) {
                XMEMCPY(encryptedContent, &pkiMsg[idx],
                                                    (word32)encryptedContentSz);
                idx += (word32)encryptedContentSz;
            }
        #ifndef NO_PKCS7_STREAM
                pkcs7->stream->bufferPt = encryptedContent;
        #endif

            /* may have IMPLICIT [1] authenticatedAttributes */
            localIdx = idx;
            if (ret == 0 && GetASNTag(pkiMsg, &localIdx, &tag, pkiMsgSz) == 0 &&
                    tag == (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 1)) {
                encodedAttribIdx = idx;
                encodedAttribs = pkiMsg + idx;
                idx++;

                if (GetLength(pkiMsg, &idx, &length, pkiMsgSz) <= 0)
                    ret = ASN_PARSE_E;
            #ifndef NO_PKCS7_STREAM
                pkcs7->stream->expected = (word32)length;
            #endif
                encodedAttribSz = (word32)length + (idx - encodedAttribIdx);

                if (ret != 0)
                    break;

            #ifndef NO_PKCS7_STREAM
                if (encodedAttribSz > 0) {
                    pkcs7->stream->aadSz = encodedAttribSz;
                    pkcs7->stream->aad = (byte*)XMALLOC(encodedAttribSz,
                            pkcs7->heap, DYNAMIC_TYPE_PKCS7);
                    if (pkcs7->stream->aad == NULL) {
                        ret = MEMORY_E;
                        break;
                    }
                    else {
                        XMEMCPY(pkcs7->stream->aad, encodedAttribs,
                                (idx - encodedAttribIdx));
                    }
                }

                if ((ret = wc_PKCS7_StreamEndCase(pkcs7, &tmpIdx, &idx)) != 0) {
                    break;
                }
            #endif
                wc_PKCS7_ChangeState(pkcs7, WC_PKCS7_AUTHENV_ATRB);
            }
            else {
            #ifndef NO_PKCS7_STREAM
                if ((ret = wc_PKCS7_StreamEndCase(pkcs7, &tmpIdx, &idx)) != 0) {
                    break;
                }
            #endif
                goto authenv_atrbend; /* jump over attribute cases */
            }
            FALL_THROUGH;

        case WC_PKCS7_AUTHENV_ATRB:
    #ifndef NO_PKCS7_STREAM
            if ((ret = wc_PKCS7_AddDataToStream(pkcs7, in, inSz,
                            pkcs7->stream->expected, &pkiMsg, &idx)) != 0) {
                return ret;
            }

            length = (int)pkcs7->stream->expected;
            encodedAttribs = pkcs7->stream->aad;
    #endif

            /* save pointer and length */
            authAttrib = &pkiMsg[idx];
            authAttribSz = length;

            if (ret == 0 && wc_PKCS7_ParseAttribs(pkcs7, authAttrib, authAttribSz) < 0) {
                WOLFSSL_MSG("Error parsing authenticated attributes");
                ret = ASN_PARSE_E;
                break;
            }

            idx += (word32)length;

    #ifndef NO_PKCS7_STREAM
            if (encodedAttribSz > 0) {
                XMEMCPY(pkcs7->stream->aad + (encodedAttribSz - (word32)length),
                        authAttrib, (word32)authAttribSz);
            }
            if ((ret = wc_PKCS7_StreamEndCase(pkcs7, &tmpIdx, &idx)) != 0) {
                break;
            }

    #endif
            wc_PKCS7_ChangeState(pkcs7, WC_PKCS7_AUTHENV_ATRBEND);
            FALL_THROUGH;

        case WC_PKCS7_AUTHENV_ATRBEND:
authenv_atrbend:
        #ifndef NO_PKCS7_STREAM
            if ((ret = wc_PKCS7_AddDataToStream(pkcs7, in, inSz, MAX_LENGTH_SZ +
                            ASN_TAG_SZ, &pkiMsg, &idx)) != 0) {
                return ret;
            }
            pkiMsgSz = (pkcs7->stream->length > 0)? pkcs7->stream->length: inSz;

            if (pkcs7->stream->aadSz > 0) {
                encodedAttribSz = pkcs7->stream->aadSz;
                encodedAttribs  = pkcs7->stream->aad;
            }
        #endif


            /* get authTag OCTET STRING */
            if (ret == 0 && GetASNTag(pkiMsg, &idx, &tag, pkiMsgSz) < 0) {
                ret = ASN_PARSE_E;
            }
            if (ret == 0 && tag != ASN_OCTET_STRING) {
                ret = ASN_PARSE_E;
            }

            if (ret == 0 && GetLength(pkiMsg, &idx, &authTagSz, pkiMsgSz) < 0) {
                ret = ASN_PARSE_E;
            }

            if (ret == 0 && authTagSz > (int)sizeof(authTag)) {
                WOLFSSL_MSG("AuthEnvelopedData authTag too large for buffer");
                ret = ASN_PARSE_E;
            }

            if (ret == 0) {
                XMEMCPY(authTag, &pkiMsg[idx], (word32)authTagSz);
                idx += (word32)authTagSz;
            }

            if (ret == 0 && authAttrib != NULL) {
                /* temporarily swap authAttribs byte[0] to SET OF instead of
                 * IMPLICIT [1], for aad calculation */
                authAttribSetByte = encodedAttribs[0];

                encodedAttribs[0] = ASN_SET | ASN_CONSTRUCTED;
            }

            if (ret < 0)
                break;

        #ifndef NO_PKCS7_STREAM
            if ((ret = wc_PKCS7_StreamEndCase(pkcs7, &tmpIdx, &idx)) != 0) {
                break;
            }
            pkcs7->stream->expected = (pkcs7->stream->maxLen -
                pkcs7->stream->totalRd) + pkcs7->stream->length;


            /* store tag for later */
            if (authTagSz > 0) {
                pkcs7->stream->tagSz = (word32)authTagSz;
                pkcs7->stream->tag = (byte*)XMALLOC((word32)authTagSz,
                        pkcs7->heap, DYNAMIC_TYPE_PKCS7);
                if (pkcs7->stream->tag == NULL) {
                    ret = MEMORY_E;
                    break;
                }
                else {
                    XMEMCPY(pkcs7->stream->tag, authTag, (word32)authTagSz);
                }
            }

        #endif
            wc_PKCS7_ChangeState(pkcs7, WC_PKCS7_AUTHENV_6);
            FALL_THROUGH;

        case WC_PKCS7_AUTHENV_6:
        #ifndef NO_PKCS7_STREAM
            if ((ret = wc_PKCS7_AddDataToStream(pkcs7, in, inSz,
                            pkcs7->stream->expected, &pkiMsg, &idx)) != 0) {
                break;
            }

            /* restore all variables needed */
            if (pkcs7->stream->nonceSz > 0) {
                nonceSz = (int)pkcs7->stream->nonceSz;
                if (nonceSz > GCM_NONCE_MID_SZ) {
                    WOLFSSL_MSG("PKCS7 saved nonce is too large");
                    ret = BUFFER_E;
                    break;
                }
                else {
                    XMEMCPY(nonce, pkcs7->stream->nonce, (word32)nonceSz);
                }
            }

            if (pkcs7->stream->tagSz > 0) {
                authTagSz = (int)pkcs7->stream->tagSz;
                if (authTagSz > WC_AES_BLOCK_SIZE) {
                    WOLFSSL_MSG("PKCS7 saved tag is too large");
                    ret = BUFFER_E;
                    break;
                }
                else {
                    XMEMCPY(authTag, pkcs7->stream->tag, (word32)authTagSz);
                }
            }

            if (pkcs7->stream->aadSz > 0) {
                encodedAttribSz = pkcs7->stream->aadSz;
                encodedAttribs  = pkcs7->stream->aad;
            }

            wc_PKCS7_StreamGetVar(pkcs7, &encOID, &blockKeySz,
                                  &encryptedContentSz);
            encryptedContent   = pkcs7->stream->bufferPt;
        #ifdef WOLFSSL_SMALL_STACK
            decryptedKey = pkcs7->stream->key;
        #endif
        #endif

            /* decrypt encryptedContent */
            ret = wc_PKCS7_DecryptContent(pkcs7, (int)encOID, decryptedKey,
                    blockKeySz, nonce, nonceSz, encodedAttribs, encodedAttribSz,
                    authTag, (word32)authTagSz, encryptedContent,
                    encryptedContentSz, encryptedContent, pkcs7->devId,
                    pkcs7->heap);
            if (ret != 0) {
                XFREE(encryptedContent, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
                return ret;
            }

            if (authAttrib != NULL) {
                /* restore authAttrib IMPLICIT [1] */
                encodedAttribs[0] = authAttribSetByte;
            }

            /* copy plaintext to output */
            XMEMCPY(output, encryptedContent, (word32)encryptedContentSz);

            /* free memory, zero out keys */
            ForceZero(encryptedContent, (word32)encryptedContentSz);
            XFREE(encryptedContent, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
            encryptedContent = NULL;
            ForceZero(decryptedKey, MAX_ENCRYPTED_KEY_SZ);
        #ifdef WOLFSSL_SMALL_STACK
            XFREE(decryptedKey, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
            decryptedKey = NULL;
            #ifndef NO_PKCS7_STREAM
            pkcs7->stream->key = NULL;
            #endif
        #endif
            ret = encryptedContentSz;
        #ifndef NO_PKCS7_STREAM
            wc_PKCS7_ResetStream(pkcs7);
        #endif
            wc_PKCS7_ChangeState(pkcs7, WC_PKCS7_START);
            break;
        default:
            WOLFSSL_MSG("Unknown PKCS7 state");
            ret = BAD_FUNC_ARG;
    }

#ifdef WOLFSSL_SMALL_STACK
    if (ret != 0 && ret != WC_NO_ERR_TRACE(WC_PKCS7_WANT_READ_E)) {
        if (decryptedKey != NULL) {
            ForceZero(decryptedKey, MAX_ENCRYPTED_KEY_SZ);
        }
        XFREE(decryptedKey, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
    }
#else
    if (ret < 0) {
        if (encryptedContent != NULL) {
            ForceZero(encryptedContent, (word32)encryptedContentSz);
            XFREE(encryptedContent, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
            encryptedContent = NULL;
        }
        ForceZero(decryptedKey, MAX_ENCRYPTED_KEY_SZ);
    }
#endif

#ifndef NO_PKCS7_STREAM
    if (ret != 0 && ret != WC_NO_ERR_TRACE(WC_PKCS7_WANT_READ_E)) {
        wc_PKCS7_ResetStream(pkcs7);
    }
#endif

    return ret;

#else
    WOLFSSL_MSG("AuthEnvelopedData requires AES-GCM or AES-CCM to be enabled");
    (void)pkcs7;
    (void)in;
    (void)inSz;
    (void)output;
    (void)outputSz;

    return NOT_COMPILED_IN;
#endif /* HAVE_AESGCM | HAVE_AESCCM */
}


#ifndef NO_PKCS7_ENCRYPTED_DATA

/* build PKCS#7 encryptedData content type, return encrypted size */
int wc_PKCS7_EncodeEncryptedData(wc_PKCS7* pkcs7, byte* output, word32 outputSz)
{
    int ret, idx = 0;
    int totalSz, padSz, encryptedOutSz;

    int contentInfoSeqSz, outerContentTypeSz, outerContentSz;
    byte contentInfoSeq[MAX_SEQ_SZ];
    byte outerContentType[MAX_ALGO_SZ];
    byte outerContent[MAX_SEQ_SZ];

    int encDataSeqSz, verSz, blockSz;
    byte encDataSeq[MAX_SEQ_SZ];
    byte ver[MAX_VERSION_SZ];

    byte* plain = NULL;
    byte* encryptedContent = NULL;

    int encContentOctetSz, encContentSeqSz, contentTypeSz;
    int contentEncAlgoSz, ivOctetStringSz;
    byte encContentSeq[MAX_SEQ_SZ];
    byte contentType[MAX_OID_SZ];
    byte contentEncAlgo[MAX_ALGO_SZ];
    byte tmpIv[MAX_CONTENT_IV_SIZE];
    byte ivOctetString[MAX_OCTET_STR_SZ];
    byte encContentOctet[MAX_OCTET_STR_SZ];

    byte attribSet[MAX_SET_SZ];
    EncodedAttrib* attribs = NULL;
    word32 attribsSz;
    word32 attribsCount;
    word32 attribsSetSz;

    byte* flatAttribs = NULL;

    if (pkcs7 == NULL || pkcs7->content == NULL || pkcs7->contentSz == 0 ||
        pkcs7->encryptOID == 0 || pkcs7->encryptionKey == NULL ||
        pkcs7->encryptionKeySz == 0)
        return BAD_FUNC_ARG;

    if (output == NULL || outputSz == 0)
        return BAD_FUNC_ARG;

    if (pkcs7->version == 3) {
        verSz = SetMyVersion(0, ver, 0);
        outerContentTypeSz = 0;
    }
    else {
        /* outer content type */
        ret = wc_SetContentType(ENCRYPTED_DATA, outerContentType,
                                sizeof(outerContentType));
        if (ret < 0)
            return ret;

        outerContentTypeSz = ret;

        /* version, 2 if unprotectedAttrs present, 0 if absent */
        if (pkcs7->unprotectedAttribsSz > 0) {
            verSz = SetMyVersion(2, ver, 0);
        } else {
            verSz = SetMyVersion(0, ver, 0);
        }
    }

    /* EncryptedContentInfo */
    ret = wc_SetContentType(pkcs7->contentOID, contentType,
                            sizeof(contentType));
    if (ret < 0)
        return ret;

    contentTypeSz = ret;

    /* allocate encrypted content buffer, do PKCS#7 padding */
    blockSz = wc_PKCS7_GetOIDBlockSize(pkcs7->encryptOID);
    if (blockSz < 0)
        return blockSz;

    padSz = wc_PKCS7_GetPadSize(pkcs7->contentSz, (word32)blockSz);
    if (padSz < 0)
        return padSz;

    encryptedOutSz = (int)pkcs7->contentSz + padSz;

    plain = (byte*)XMALLOC((word32)encryptedOutSz, pkcs7->heap,
                           DYNAMIC_TYPE_PKCS7);
    if (plain == NULL)
        return MEMORY_E;

    ret = wc_PKCS7_PadData(pkcs7->content, pkcs7->contentSz, plain,
                           (word32)encryptedOutSz, (word32)blockSz);
    if (ret < 0) {
        XFREE(plain, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return ret;
    }

    encryptedContent = (byte*)XMALLOC((word32)encryptedOutSz, pkcs7->heap,
                                      DYNAMIC_TYPE_PKCS7);
    if (encryptedContent == NULL) {
        XFREE(plain, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return MEMORY_E;
    }

    /* put together IV OCTET STRING */
    ivOctetStringSz = (int)SetOctetString((word32)blockSz, ivOctetString);

    /* build up ContentEncryptionAlgorithmIdentifier sequence,
       adding (ivOctetStringSz + blockSz) for IV OCTET STRING */
    contentEncAlgoSz = (int)SetAlgoID(pkcs7->encryptOID, contentEncAlgo,
                                 oidBlkType, ivOctetStringSz + blockSz);
    if (contentEncAlgoSz == 0) {
        XFREE(encryptedContent, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        XFREE(plain, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return BAD_FUNC_ARG;
    }

    /* encrypt content */
    WOLFSSL_MSG("Encrypting the content");
    ret = wc_PKCS7_GenerateBlock(pkcs7, NULL, tmpIv, (word32)blockSz);
    if (ret != 0) {
        XFREE(encryptedContent, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        XFREE(plain, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return ret;
    }

    ret = wc_PKCS7_EncryptContent(pkcs7, pkcs7->encryptOID,
            pkcs7->encryptionKey, (int)pkcs7->encryptionKeySz, tmpIv, blockSz,
            NULL, 0, NULL, 0, plain, encryptedOutSz, encryptedContent);
    if (ret != 0) {
        XFREE(encryptedContent, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        XFREE(plain, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return ret;
    }

    encContentOctetSz = (int)SetImplicit(ASN_OCTET_STRING, 0,
                                    (word32)encryptedOutSz, encContentOctet, 0);

    encContentSeqSz = (int)SetSequence((word32)(contentTypeSz +
                                  contentEncAlgoSz + ivOctetStringSz + blockSz +
                                  encContentOctetSz + encryptedOutSz),
                                  encContentSeq);

    /* optional UnprotectedAttributes */
    if (pkcs7->unprotectedAttribsSz != 0) {

        if (pkcs7->unprotectedAttribs == NULL) {
            XFREE(encryptedContent, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
            XFREE(plain, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
            return BAD_FUNC_ARG;
        }

        attribs = (EncodedAttrib*)XMALLOC(
                sizeof(EncodedAttrib) * pkcs7->unprotectedAttribsSz,
                pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        if (attribs == NULL) {
            XFREE(encryptedContent, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
            XFREE(plain, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
            return MEMORY_E;
        }

        attribsCount = pkcs7->unprotectedAttribsSz;
        attribsSz = (word32)EncodeAttributes(attribs,
                                     (int)pkcs7->unprotectedAttribsSz,
                                     pkcs7->unprotectedAttribs,
                                     (int)pkcs7->unprotectedAttribsSz);

        flatAttribs = (byte*)XMALLOC(attribsSz, pkcs7->heap,
                                                            DYNAMIC_TYPE_PKCS7);
        if (flatAttribs == NULL) {
            XFREE(attribs, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
            XFREE(encryptedContent, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
            XFREE(plain, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
            return MEMORY_E;
        }

        ret = FlattenAttributes(pkcs7, flatAttribs, attribs, (int)attribsCount);
        if (ret != 0) {
            XFREE(attribs, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
            XFREE(encryptedContent, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
            XFREE(plain, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
            XFREE(flatAttribs, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
            return ret;
        }
        attribsSetSz = SetImplicit(ASN_SET, 1, attribsSz, attribSet, 0);

    } else {
        attribsSz = 0;
        attribsSetSz = 0;
    }

    /* keep track of sizes for outer wrapper layering */
    totalSz = verSz + encContentSeqSz + contentTypeSz + contentEncAlgoSz +
              ivOctetStringSz + blockSz + encContentOctetSz + encryptedOutSz +
              (int)attribsSz + (int)attribsSetSz;

    /* EncryptedData */
    encDataSeqSz = (int)SetSequence((word32)totalSz, encDataSeq);
    totalSz += encDataSeqSz;

    if (pkcs7->version != 3) {
        /* outer content */
        outerContentSz = (int)SetExplicit(0, (word32)totalSz, outerContent, 0);
        totalSz += outerContentTypeSz;
        totalSz += outerContentSz;
        /* ContentInfo */
        contentInfoSeqSz = (int)SetSequence((word32)totalSz, contentInfoSeq);
        totalSz += contentInfoSeqSz;
    } else {
        contentInfoSeqSz = 0;
        outerContentSz = 0;
    }

    if (totalSz > (int)outputSz) {
        WOLFSSL_MSG("PKCS#7 output buffer too small");
        XFREE(attribs, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        XFREE(flatAttribs, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        XFREE(encryptedContent, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        XFREE(plain, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return BUFFER_E;
    }

    XMEMCPY(output + idx, contentInfoSeq, (word32)contentInfoSeqSz);
    idx += contentInfoSeqSz;
    XMEMCPY(output + idx, outerContentType, (word32)outerContentTypeSz);
    idx += outerContentTypeSz;
    XMEMCPY(output + idx, outerContent, (word32)outerContentSz);
    idx += outerContentSz;
    XMEMCPY(output + idx, encDataSeq, (word32)encDataSeqSz);
    idx += encDataSeqSz;
    XMEMCPY(output + idx, ver, (word32)verSz);
    idx += verSz;
    XMEMCPY(output + idx, encContentSeq, (word32)encContentSeqSz);
    idx += encContentSeqSz;
    XMEMCPY(output + idx, contentType, (word32)contentTypeSz);
    idx += contentTypeSz;
    XMEMCPY(output + idx, contentEncAlgo, (word32)contentEncAlgoSz);
    idx += contentEncAlgoSz;
    XMEMCPY(output + idx, ivOctetString, (word32)ivOctetStringSz);
    idx += ivOctetStringSz;
    XMEMCPY(output + idx, tmpIv, (word32)blockSz);
    idx += blockSz;
    XMEMCPY(output + idx, encContentOctet, (word32)encContentOctetSz);
    idx += encContentOctetSz;
    XMEMCPY(output + idx, encryptedContent, (word32)encryptedOutSz);
    idx += encryptedOutSz;

    if (pkcs7->unprotectedAttribsSz != 0) {
        XMEMCPY(output + idx, attribSet, attribsSetSz);
        idx += (int)attribsSetSz;
        XMEMCPY(output + idx, flatAttribs, attribsSz);
        idx += (int)attribsSz;
    }

    XFREE(attribs, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
    XFREE(flatAttribs, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
    XFREE(encryptedContent, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
    XFREE(plain, pkcs7->heap, DYNAMIC_TYPE_PKCS7);

    return idx;
}


/* decode and store unprotected attributes in PKCS7->decodedAttrib. Return
 * 0 on success, negative on error. User must call wc_PKCS7_Free(). */
static int wc_PKCS7_DecodeUnprotectedAttributes(wc_PKCS7* pkcs7, byte* pkiMsg,
                                             word32 pkiMsgSz, word32* inOutIdx)
{
    int ret, attribLen;
    word32 idx;
    byte tag;

    if (pkcs7 == NULL || pkiMsg == NULL ||
        pkiMsgSz == 0 || inOutIdx == NULL)
        return BAD_FUNC_ARG;

    idx = *inOutIdx;

    if (GetASNTag(pkiMsg, &idx, &tag, pkiMsgSz) < 0)
        return ASN_PARSE_E;

    if (tag != (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 1))
        return ASN_PARSE_E;

    if (GetLength(pkiMsg, &idx, &attribLen, pkiMsgSz) < 0)
        return ASN_PARSE_E;

    /* loop through attributes */
    if ((ret = wc_PKCS7_ParseAttribs(pkcs7, pkiMsg + idx, attribLen)) < 0) {
        return ret;
    }

    *inOutIdx = idx;

    return 0;
}


/* unwrap and decrypt PKCS#7/CMS encrypted-data object, returned decoded size */
int wc_PKCS7_DecodeEncryptedData(wc_PKCS7* pkcs7, byte* in, word32 inSz,
                                 byte* output, word32 outputSz)
{
    int ret = 0, version = 0, length = 0, haveAttribs = 0;
    word32 idx = 0;

#ifndef NO_PKCS7_STREAM
    word32 tmpIdx = 0;
#endif
    word32 contentType = 0, encOID = 0;

    int expBlockSz = 0;
    byte tmpIvBuf[MAX_CONTENT_IV_SIZE];
    byte *tmpIv = tmpIvBuf;

    int encryptedContentSz = 0;
    byte padLen = 0;
    byte* encryptedContent = NULL;

    byte* pkiMsg = in;
    word32 pkiMsgSz = inSz;
    byte  tag = 0;

    if (pkcs7 == NULL ||
            ((pkcs7->encryptionKey == NULL || pkcs7->encryptionKeySz == 0) &&
              pkcs7->decryptionCb == NULL))
        return BAD_FUNC_ARG;

    if (pkiMsg == NULL || pkiMsgSz == 0 ||
        output == NULL || outputSz == 0)
        return BAD_FUNC_ARG;

#ifndef NO_PKCS7_STREAM
    (void)tmpIv; /* help out static analysis */
    if (pkcs7->stream == NULL) {
        if ((ret = wc_PKCS7_CreateStream(pkcs7)) != 0) {
            return ret;
        }
    }
#endif

    switch (pkcs7->state) {
        case WC_PKCS7_START:
#ifndef NO_PKCS7_STREAM
            if ((ret = wc_PKCS7_AddDataToStream(pkcs7, in, inSz, MAX_SEQ_SZ +
                            MAX_ALGO_SZ, &pkiMsg, &idx)) != 0) {
                return ret;
            }

            if ((ret = wc_PKCS7_SetMaxStream(pkcs7, in, inSz)) != 0) {
                return ret;
            }
            pkiMsgSz = (pkcs7->stream->length > 0)? pkcs7->stream->length: inSz;
#endif

            if (GetSequence_ex(pkiMsg, &idx, &length, pkiMsgSz,
                        NO_USER_CHECK) < 0)
                ret = ASN_PARSE_E;

            if (pkcs7->version != 3) { /* ContentInfo not in firmware bundles */
                /* read past ContentInfo, verify type is encrypted-data */
                if (ret == 0 && wc_GetContentType(pkiMsg, &idx, &contentType,
                            pkiMsgSz) < 0)
                    ret = ASN_PARSE_E;

                if (ret == 0 && contentType != ENCRYPTED_DATA) {
                    WOLFSSL_MSG("PKCS#7 input not of type EncryptedData");
                    ret = PKCS7_OID_E;
                }
            }
            if (ret != 0) break;
#ifndef NO_PKCS7_STREAM
            if ((ret = wc_PKCS7_StreamEndCase(pkcs7, &tmpIdx, &idx)) != 0) {
                break;
            }
#endif
            wc_PKCS7_ChangeState(pkcs7, WC_PKCS7_STAGE2);
            FALL_THROUGH;
            /* end of stage 1 */

        case WC_PKCS7_STAGE2:
#ifndef NO_PKCS7_STREAM
            if ((ret = wc_PKCS7_AddDataToStream(pkcs7, in, inSz,
                            MAX_LENGTH_SZ + MAX_SEQ_SZ + ASN_TAG_SZ, &pkiMsg,
                            &idx)) != 0) {
                return ret;
            }
            pkiMsgSz = (pkcs7->stream->length > 0)? pkcs7->stream->length: inSz;
#endif
            if (pkcs7->version != 3) {
                if (ret == 0 && GetASNTag(pkiMsg, &idx, &tag, pkiMsgSz) < 0)
                    ret = ASN_PARSE_E;
                if (ret == 0 && tag !=
                        (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 0))
                    ret = ASN_PARSE_E;

                if (ret == 0 && GetLength_ex(pkiMsg, &idx, &length, pkiMsgSz,
                            NO_USER_CHECK) < 0)
                    ret = ASN_PARSE_E;

                /* remove EncryptedData and version */
                if (ret == 0 && GetSequence_ex(pkiMsg, &idx, &length, pkiMsgSz,
                            NO_USER_CHECK) < 0)
                    ret = ASN_PARSE_E;
            }

            if (ret != 0) break;
#ifndef NO_PKCS7_STREAM
            if ((ret = wc_PKCS7_StreamEndCase(pkcs7, &tmpIdx, &idx)) != 0) {
                break;
            }
#endif
            wc_PKCS7_ChangeState(pkcs7, WC_PKCS7_STAGE3);
            FALL_THROUGH;
            /* end of stage 2 */

       case WC_PKCS7_STAGE3:
#ifndef NO_PKCS7_STREAM
            if ((ret = wc_PKCS7_AddDataToStream(pkcs7, in, inSz,
                            MAX_VERSION_SZ + MAX_SEQ_SZ + MAX_ALGO_SZ * 2,
                            &pkiMsg, &idx)) != 0) {
                return ret;
            }
            pkiMsgSz = (pkcs7->stream->length > 0)? pkcs7->stream->length: inSz;
#endif
            /* get version, check later */
            haveAttribs = 0;
            if (ret == 0 && GetMyVersion(pkiMsg, &idx, &version, pkiMsgSz) < 0)
                ret = ASN_PARSE_E;

            /* remove EncryptedContentInfo */
            if (ret == 0 && GetSequence_ex(pkiMsg, &idx, &length, pkiMsgSz,
                        NO_USER_CHECK) < 0)
                ret = ASN_PARSE_E;

            if (ret == 0 && wc_GetContentType(pkiMsg, &idx, &contentType,
                        pkiMsgSz) < 0)
                ret = ASN_PARSE_E;

            if (ret == 0) {
                pkcs7->contentOID = (int)contentType;
            }

            if (ret == 0 && (ret = GetAlgoId(pkiMsg, &idx, &encOID, oidBlkType,
                        pkiMsgSz)) < 0)
                ret = ASN_PARSE_E;
            if (ret == 0 && (expBlockSz = wc_PKCS7_GetOIDBlockSize((int)encOID)) < 0)
                ret = expBlockSz;

            if (ret != 0) break;
#ifndef NO_PKCS7_STREAM
            /* store expBlockSz for later */
            pkcs7->stream->varOne = (word32)expBlockSz;
            pkcs7->stream->varTwo = (int)encOID;

            if ((ret = wc_PKCS7_StreamEndCase(pkcs7, &tmpIdx, &idx)) != 0) {
                break;
            }

            /* store version for later */
            pkcs7->stream->vers = (word32)version;
#endif
            wc_PKCS7_ChangeState(pkcs7, WC_PKCS7_STAGE4);
            FALL_THROUGH;
            /* end of stage 3 */

        /* get block cipher IV, stored in OPTIONAL parameter of AlgoID */
       case WC_PKCS7_STAGE4:
#ifndef NO_PKCS7_STREAM
            if ((ret = wc_PKCS7_AddDataToStream(pkcs7, in, inSz,
                            ASN_TAG_SZ + MAX_LENGTH_SZ, &pkiMsg, &idx)) != 0) {
                return ret;
            }
            pkiMsgSz = (pkcs7->stream->length > 0)? pkcs7->stream->length: inSz;

            /* restore saved variables */
            expBlockSz = (int)pkcs7->stream->varOne;
#endif
            if (ret == 0 && GetASNTag(pkiMsg, &idx, &tag, pkiMsgSz) < 0)
                ret = ASN_PARSE_E;
            if (ret == 0 && tag != ASN_OCTET_STRING)
                ret = ASN_PARSE_E;

            if (ret == 0 && GetLength(pkiMsg, &idx, &length, pkiMsgSz) < 0)
                ret = ASN_PARSE_E;

            if (ret == 0 && length != expBlockSz) {
                WOLFSSL_MSG("Incorrect IV length, must be of content alg block size");
                ret = ASN_PARSE_E;
            }

            if (ret != 0) break;
#ifndef NO_PKCS7_STREAM
            /* next chunk of data expected should have the IV */
            pkcs7->stream->expected = (word32)length;

            if ((ret = wc_PKCS7_StreamEndCase(pkcs7, &tmpIdx, &idx)) != 0) {
                break;
            }
#endif
            wc_PKCS7_ChangeState(pkcs7, WC_PKCS7_STAGE5);
            FALL_THROUGH;
            /* end of stage 4 */

       case WC_PKCS7_STAGE5:
#ifndef NO_PKCS7_STREAM
            if ((ret = wc_PKCS7_AddDataToStream(pkcs7, in, inSz,
                            pkcs7->stream->expected + ASN_TAG_SZ +
                            MAX_LENGTH_SZ, &pkiMsg, &idx)) != 0) {
                return ret;
            }
            pkiMsgSz = (pkcs7->stream->length > 0)? pkcs7->stream->length: inSz;

            /* use IV buffer from stream structure */
            tmpIv  = pkcs7->stream->tmpIv;
            length = (int)pkcs7->stream->expected;
#endif
            XMEMCPY(tmpIv, &pkiMsg[idx], (word32)length);
            idx += (word32)length;
            /* read encryptedContent, cont[0] */
            if (ret == 0 && GetASNTag(pkiMsg, &idx, &tag, pkiMsgSz) < 0)
                ret = ASN_PARSE_E;
            if (ret == 0 && tag != (ASN_CONTEXT_SPECIFIC | 0))
                ret = ASN_PARSE_E;

            if (ret == 0 && GetLength_ex(pkiMsg, &idx, &encryptedContentSz,
                        pkiMsgSz, NO_USER_CHECK) <= 0)
                ret = ASN_PARSE_E;

            if (ret < 0)
                break;
#ifndef NO_PKCS7_STREAM
            /* next chunk of data should contain encrypted content */
            pkcs7->stream->varThree = encryptedContentSz;
            if ((ret = wc_PKCS7_StreamEndCase(pkcs7, &tmpIdx, &idx)) != 0) {
                break;
            }

            if (pkcs7->stream->totalRd + (word32)encryptedContentSz <
                    pkcs7->stream->maxLen) {
                pkcs7->stream->flagOne = 1;
            }

            pkcs7->stream->expected = (pkcs7->stream->maxLen -
                pkcs7->stream->totalRd) + pkcs7->stream->length;

#endif
            wc_PKCS7_ChangeState(pkcs7, WC_PKCS7_STAGE6);
            FALL_THROUGH;
            /* end of stage 5 */

        case WC_PKCS7_STAGE6:
#ifndef NO_PKCS7_STREAM
            if ((ret = wc_PKCS7_AddDataToStream(pkcs7, in, inSz,
                            pkcs7->stream->expected, &pkiMsg, &idx)) != 0) {
                return ret;
            }
            pkiMsgSz = (pkcs7->stream->length > 0)? pkcs7->stream->length: inSz;

            /* restore saved variables */
            expBlockSz = (int)pkcs7->stream->varOne;
            encOID     = (word32)pkcs7->stream->varTwo;
            encryptedContentSz = pkcs7->stream->varThree;
            version    = (int)pkcs7->stream->vers;
            tmpIv      = pkcs7->stream->tmpIv;
#endif
            if (ret == 0 && (encryptedContent = (byte*)XMALLOC(
                                  (unsigned int)encryptedContentSz, pkcs7->heap,
                                  DYNAMIC_TYPE_PKCS7)) == NULL) {
                ret = MEMORY_E;
                break;
            }

            if (ret == 0) {
                XMEMCPY(encryptedContent, &pkiMsg[idx],
                    (unsigned int)encryptedContentSz);
                idx += (word32)encryptedContentSz;

                /* decrypt encryptedContent */
                ret = wc_PKCS7_DecryptContent(pkcs7, (int)encOID,
                              pkcs7->encryptionKey, (int)pkcs7->encryptionKeySz,
                              tmpIv, expBlockSz, NULL, 0, NULL, 0,
                              encryptedContent, encryptedContentSz,
                              encryptedContent, pkcs7->devId, pkcs7->heap);
                if (ret != 0) {
                    XFREE(encryptedContent, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
                }
            }

            if (ret == 0) {
                padLen = encryptedContent[encryptedContentSz-1];

                if (padLen > encryptedContentSz) {
                    WOLFSSL_MSG("Bad padding size found");
                    ret = BUFFER_E;
                    XFREE(encryptedContent, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
                    break;
                }

                /* copy plaintext to output */
                XMEMCPY(output, encryptedContent,
                    (unsigned int)(encryptedContentSz - padLen));

                /* get implicit[1] unprotected attributes, optional */
                wc_PKCS7_FreeDecodedAttrib(pkcs7->decodedAttrib, pkcs7->heap);
                pkcs7->decodedAttrib = NULL;
            #ifndef NO_PKCS7_STREAM
                if (pkcs7->stream->flagOne)
            #else
                if (idx < pkiMsgSz)
            #endif
                {
                    haveAttribs = 1;

                    ret = wc_PKCS7_DecodeUnprotectedAttributes(pkcs7, pkiMsg,
                                                       pkiMsgSz, &idx);
                    if (ret != 0) {
                        ForceZero(encryptedContent, (word32)encryptedContentSz);
                        XFREE(encryptedContent, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
                        ret = ASN_PARSE_E;
                    }
                }
            }

            if (ret == 0) {
                ForceZero(encryptedContent, (word32)encryptedContentSz);
                XFREE(encryptedContent, pkcs7->heap, DYNAMIC_TYPE_PKCS7);

                /* go back and check the version now that attribs have been processed */
                if (pkcs7->version == 3 && version != 0) {
                    WOLFSSL_MSG("Wrong PKCS#7 FirmwareEncryptedData version");
                    return ASN_VERSION_E;
                }

                if (pkcs7->version != 3 &&
                   ((haveAttribs == 0 && version != 0) ||
                    (haveAttribs == 1 && version != 2))) {
                    WOLFSSL_MSG("Wrong PKCS#7 EncryptedData version");
                    return ASN_VERSION_E;
                }
                ret = encryptedContentSz - padLen;
            }

            if (ret != 0) break;
        #ifndef NO_PKCS7_STREAM
            wc_PKCS7_ResetStream(pkcs7);
        #endif
            wc_PKCS7_ChangeState(pkcs7, WC_PKCS7_START);
            break;

        default:
            WOLFSSL_MSG("Error in unknown PKCS#7 Decode Encrypted Data state");
            return BAD_STATE_E;
    }

    if (ret != 0) {
    #ifndef NO_PKCS7_STREAM
        /* restart in error case */
        wc_PKCS7_ResetStream(pkcs7);
    #endif
        wc_PKCS7_ChangeState(pkcs7, WC_PKCS7_START);
    }
    return ret;
}


/* Function to set callback during decryption, this overrides the default
 * decryption function and can be used for choosing a key at run time based
 * on the parsed bundle so far.
 * returns 0 on success
 */
int wc_PKCS7_SetDecodeEncryptedCb(wc_PKCS7* pkcs7,
        CallbackDecryptContent decryptionCb)
{
    if (pkcs7 != NULL) {
        pkcs7->decryptionCb = decryptionCb;
    }
    return 0;
}


/* Set an optional user context that gets passed to callback
 * returns 0 on success
 */
int wc_PKCS7_SetDecodeEncryptedCtx(wc_PKCS7* pkcs7, void* ctx)
{
    if (pkcs7 != NULL) {
        pkcs7->decryptionCtx = ctx;
    }
    return 0;
}
#endif /* NO_PKCS7_ENCRYPTED_DATA */


/* set stream mode for encoding and signing
 * returns 0 on success */
int wc_PKCS7_SetStreamMode(wc_PKCS7* pkcs7, byte flag,
    CallbackGetContent getContentCb,
    CallbackStreamOut streamOutCb, void* ctx)
{
    if (pkcs7 == NULL) {
        return BAD_FUNC_ARG;
    }
#ifdef ASN_BER_TO_DER
    pkcs7->encodeStream = (flag != 0);
    pkcs7->getContentCb = getContentCb;
    pkcs7->streamOutCb  = streamOutCb;
    pkcs7->streamCtx    = ctx;
    return 0;
#else
    (void)flag;
    (void)getContentCb;
    (void)streamOutCb;
    (void)ctx;
    return NOT_COMPILED_IN;
#endif
}


/* returns to current stream mode flag on success, negative values on fail */
int wc_PKCS7_GetStreamMode(wc_PKCS7* pkcs7)
{
    if (pkcs7 == NULL) {
        return BAD_FUNC_ARG;
    }
#ifdef ASN_BER_TO_DER
    return pkcs7->encodeStream;
#else
    return 0;
#endif
}


/* set option to not include certificates when creating a bundle
 * returns 0 on success */
int wc_PKCS7_SetNoCerts(wc_PKCS7* pkcs7, byte flag)
{
    if (pkcs7 == NULL) {
        return BAD_FUNC_ARG;
    }
    pkcs7->noCerts = (flag != 0);
    return 0;
}


/* returns the current noCerts flag value on success, negative values on fail */
int wc_PKCS7_GetNoCerts(wc_PKCS7* pkcs7)
{
    if (pkcs7 == NULL) {
        return BAD_FUNC_ARG;
    }
    return pkcs7->noCerts;
}


#if defined(HAVE_LIBZ) && !defined(NO_PKCS7_COMPRESSED_DATA)

/* build PKCS#7 compressedData content type, return encrypted size */
int wc_PKCS7_EncodeCompressedData(wc_PKCS7* pkcs7, byte* output, word32 outputSz)
{
    byte contentInfoSeq[MAX_SEQ_SZ];
    byte contentInfoTypeOid[MAX_OID_SZ];
    byte contentInfoContentSeq[MAX_SEQ_SZ]; /* EXPLICIT [0] */
    byte compressedDataSeq[MAX_SEQ_SZ];
    byte cmsVersion[MAX_VERSION_SZ];
    byte compressAlgId[MAX_ALGO_SZ];
    byte encapContentInfoSeq[MAX_SEQ_SZ];
    byte contentTypeOid[MAX_OID_SZ];
    byte contentSeq[MAX_SEQ_SZ];            /* EXPLICIT [0] */
    byte contentOctetStr[MAX_OCTET_STR_SZ];

    int ret;
    word32 totalSz, idx;
    word32 contentInfoSeqSz, contentInfoContentSeqSz, contentInfoTypeOidSz;
    word32 compressedDataSeqSz, cmsVersionSz, compressAlgIdSz;
    word32 encapContentInfoSeqSz, contentTypeOidSz, contentSeqSz;
    word32 contentOctetStrSz;

    byte* compressed;
    word32 compressedSz;

    if (pkcs7 == NULL || pkcs7->content == NULL || pkcs7->contentSz == 0 ||
        output == NULL || outputSz == 0) {
        return BAD_FUNC_ARG;
    }

    /* allocate space for compressed content. The libz code says the compressed
     * buffer should be srcSz + 0.1% + 12. */
    compressedSz = (pkcs7->contentSz + (word32)(pkcs7->contentSz * 0.001) + 12);
    compressed = (byte*)XMALLOC(compressedSz, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
    if (compressed == NULL) {
        WOLFSSL_MSG("Error allocating memory for CMS compressed content");
        return MEMORY_E;
    }

    /* compress content */
    ret = wc_Compress(compressed, compressedSz, pkcs7->content,
                      pkcs7->contentSz, 0);
    if (ret < 0) {
        XFREE(compressed, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return ret;
    }
    compressedSz = (word32)ret;

    /* eContent OCTET STRING, working backwards */
    contentOctetStrSz = SetOctetString(compressedSz, contentOctetStr);
    totalSz = contentOctetStrSz + compressedSz;

    /* EXPLICIT [0] eContentType */
    contentSeqSz = SetExplicit(0, totalSz, contentSeq, 0);
    totalSz += contentSeqSz;

    /* eContentType OBJECT IDENTIFIER */
    ret = wc_SetContentType(pkcs7->contentOID, contentTypeOid,
                            sizeof(contentTypeOid));
    if (ret < 0) {
        XFREE(compressed, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return ret;
    }

    contentTypeOidSz = ret;
    totalSz += contentTypeOidSz;

    /* EncapsulatedContentInfo SEQUENCE */
    encapContentInfoSeqSz = SetSequence(totalSz, encapContentInfoSeq);
    totalSz += encapContentInfoSeqSz;

    /* compressionAlgorithm AlgorithmIdentifier */
    /* Only supports zlib for compression currently:
     * id-alg-zlibCompress (1.2.840.113549.1.9.16.3.8) */
    compressAlgIdSz = SetAlgoID(ZLIBc, compressAlgId, oidCompressType, 0);
    totalSz += compressAlgIdSz;

    /* version */
    cmsVersionSz = SetMyVersion(0, cmsVersion, 0);
    totalSz += cmsVersionSz;

    /* CompressedData SEQUENCE */
    compressedDataSeqSz = SetSequence(totalSz, compressedDataSeq);
    totalSz += compressedDataSeqSz;

    if (pkcs7->version == 3) {
        /* RFC 4108 section 2
         * When the SignedData is version 3 and eContent is compressedData then
         * the encoding is :
         * CompressedData {
         *   version
         *   compressionAlgorithm
         *   encapContentInfo
         * }
         */
        contentInfoSeqSz        = 0;
        contentInfoTypeOidSz    = 0;
        contentInfoContentSeqSz = 0;
    }
    else {
        /* EncryptedData eContent type is encoded with:
         * EncryptedData {
         *  version
         *  EncryptedContentInfo {
         *      contentType (i.e id-ct-compressedData)
         *      contentEncryptionAlgorithm
         *      octet string of CompressedData or FirmwarePkgData
         *  }
         *  attributes
         * }
         */

        /* ContentInfo content EXPLICIT SEQUENCE */
        contentInfoContentSeqSz = SetExplicit(0, totalSz, contentInfoContentSeq, 0);
        totalSz += contentInfoContentSeqSz;

        ret = wc_SetContentType(COMPRESSED_DATA, contentInfoTypeOid,
                                sizeof(contentInfoTypeOid));
        if (ret < 0) {
            XFREE(compressed, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
            return ret;
        }

        contentInfoTypeOidSz = ret;
        totalSz += contentInfoTypeOidSz;

        /* ContentInfo SEQUENCE */
        contentInfoSeqSz = SetSequence(totalSz, contentInfoSeq);
        totalSz += contentInfoSeqSz;
    }

    if (outputSz < totalSz) {
        XFREE(compressed, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return BUFFER_E;
    }

    idx = 0;
    if (contentInfoSeqSz > 0) {
        XMEMCPY(output + idx, contentInfoSeq, contentInfoSeqSz);
        idx += contentInfoSeqSz;
    }
    if (contentInfoTypeOidSz > 0) {
        XMEMCPY(output + idx, contentInfoTypeOid, contentInfoTypeOidSz);
        idx += contentInfoTypeOidSz;
    }
    if (contentInfoContentSeqSz > 0) {
        XMEMCPY(output + idx, contentInfoContentSeq, contentInfoContentSeqSz);
        idx += contentInfoContentSeqSz;
    }
    XMEMCPY(output + idx, compressedDataSeq, compressedDataSeqSz);
    idx += compressedDataSeqSz;
    XMEMCPY(output + idx, cmsVersion, cmsVersionSz);
    idx += cmsVersionSz;
    XMEMCPY(output + idx, compressAlgId, compressAlgIdSz);
    idx += compressAlgIdSz;
    XMEMCPY(output + idx, encapContentInfoSeq, encapContentInfoSeqSz);
    idx += encapContentInfoSeqSz;
    XMEMCPY(output + idx, contentTypeOid, contentTypeOidSz);
    idx += contentTypeOidSz;
    XMEMCPY(output + idx, contentSeq, contentSeqSz);
    idx += contentSeqSz;
    XMEMCPY(output + idx, contentOctetStr, contentOctetStrSz);
    idx += contentOctetStrSz;
    XMEMCPY(output + idx, compressed, compressedSz);
    idx += compressedSz;

    XFREE(compressed, pkcs7->heap, DYNAMIC_TYPE_PKCS7);

    return idx;
}

/* unwrap and decompress PKCS#7/CMS compressedData object,
 * Handles content wrapped compressed data and raw compressed data packet
 * returned decoded size */
int wc_PKCS7_DecodeCompressedData(wc_PKCS7* pkcs7, byte* pkiMsg, word32 pkiMsgSz,
                                  byte* output, word32 outputSz)
{
    int length, version, ret;
    word32 idx = 0, algOID, contentType;
    byte tag;

    byte* decompressed;
    word32 decompressedSz;

    if (pkcs7 == NULL || pkiMsg == NULL || pkiMsgSz == 0 ||
        output == NULL || outputSz == 0) {
        return BAD_FUNC_ARG;
    }

    /* unwarp content surrounding if found */
    {
        word32 localIdx = idx;
        int err = 0;

        /* get ContentInfo SEQUENCE */
        if (GetSequence(pkiMsg, &localIdx, &length, pkiMsgSz) < 0)
            err = ASN_PARSE_E;

        if (err == 0 && pkcs7->version != 3) {
            /* get ContentInfo contentType */
            if (wc_GetContentType(pkiMsg, &localIdx, &contentType, pkiMsgSz)
                    < 0)
                err = ASN_PARSE_E;

            if (err == 0 && contentType != COMPRESSED_DATA)
                err = ASN_PARSE_E;
        }

        /* get ContentInfo content EXPLICIT SEQUENCE */
        if (err == 0) {
            if (GetASNTag(pkiMsg, &localIdx, &tag, pkiMsgSz) < 0)
                err = ASN_PARSE_E;
        }

        if (err == 0) {
            if (tag != (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 0))
                err = ASN_PARSE_E;
        }

        if (err == 0) {
            if (GetLength(pkiMsg, &localIdx, &length, pkiMsgSz) < 0)
                err = ASN_PARSE_E;
        }

        /* successful content unwrap, update index */
        if (err == 0) {
            idx = localIdx;
        }
    }

    /* get CompressedData SEQUENCE */
    if (GetSequence(pkiMsg, &idx, &length, pkiMsgSz) < 0)
        return ASN_PARSE_E;

    /* get version */
    if (GetMyVersion(pkiMsg, &idx, &version, pkiMsgSz) < 0)
        return ASN_PARSE_E;

    if (version != 0) {
        WOLFSSL_MSG("CMS CompressedData version MUST be 0, but is not");
        return ASN_PARSE_E;
    }

    /* get CompressionAlgorithmIdentifier */
    if (GetAlgoId(pkiMsg, &idx, &algOID, oidIgnoreType, pkiMsgSz) < 0)
        return ASN_PARSE_E;

    /* Only supports zlib for compression currently:
     * id-alg-zlibCompress (1.2.840.113549.1.9.16.3.8) */
    if (algOID != ZLIBc) {
        WOLFSSL_MSG("CMS CompressedData only supports zlib algorithm");
        return ASN_PARSE_E;
    }

    /* get EncapsulatedContentInfo SEQUENCE */
    if (GetSequence(pkiMsg, &idx, &length, pkiMsgSz) < 0)
        return ASN_PARSE_E;

    /* get ContentType OID */
    if (wc_GetContentType(pkiMsg, &idx, &contentType, pkiMsgSz) < 0)
        return ASN_PARSE_E;

    pkcs7->contentOID = contentType;

    /* get eContent EXPLICIT SEQUENCE */
    if (GetASNTag(pkiMsg, &idx, &tag, pkiMsgSz) < 0)
        return ASN_PARSE_E;

    if (tag != (ASN_CONSTRUCTED | ASN_CONTEXT_SPECIFIC | 0))
        return ASN_PARSE_E;

    if (GetLength(pkiMsg, &idx, &length, pkiMsgSz) < 0)
        return ASN_PARSE_E;

    /* get content OCTET STRING */
    if (GetASNTag(pkiMsg, &idx, &tag, pkiMsgSz) < 0)
        return ASN_PARSE_E;

    if (tag != ASN_OCTET_STRING)
        return ASN_PARSE_E;

    if (GetLength(pkiMsg, &idx, &length, pkiMsgSz) < 0)
        return ASN_PARSE_E;

    /* decompress content */
    ret = wc_DeCompressDynamic(&decompressed, WOLFSSL_PKCS7_MAX_DECOMPRESSION,
            DYNAMIC_TYPE_PKCS7, &pkiMsg[idx], length, 0, pkcs7->heap);
    if (ret < 0) {
        return ret;
    }
    decompressedSz = (word32)ret;

    /* get content */
    if (outputSz < decompressedSz) {
        WOLFSSL_MSG("CMS output buffer too small to hold decompressed data");
        XFREE(decompressed, pkcs7->heap, DYNAMIC_TYPE_PKCS7);
        return BUFFER_E;
    }

    XMEMCPY(output, decompressed, decompressedSz);
    XFREE(decompressed, pkcs7->heap, DYNAMIC_TYPE_PKCS7);

    return decompressedSz;
}

#endif /* HAVE_LIBZ && !NO_PKCS7_COMPRESSED_DATA */

#else  /* HAVE_PKCS7 */


#ifdef _MSC_VER
    /* 4206 warning for blank file */
    #pragma warning(disable: 4206)
#endif


#endif /* HAVE_PKCS7 */

