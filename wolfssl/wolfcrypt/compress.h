/* compress.h
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

/*!
    \file wolfssl/wolfcrypt/compress.h
*/


#ifndef WOLF_CRYPT_COMPRESS_H
#define WOLF_CRYPT_COMPRESS_H

#include <wolfssl/wolfcrypt/types.h>


#ifdef __cplusplus
    extern "C" {
#endif

enum wc_CompressionAlgs {
/* compression alg Ids used by tls certificate compression defined
 * in RFC 8879, They cannot change but are defined here so they are consitent
 * accross wolfSSL */
    WC_NO_COMPRESSION = 0,
    WC_ZLIB           = 1,
    WC_BROTLI         = 2,
    WC_ZSTD           = 3,

    /* RFC 8879 Section 7.3 reserves 16384-65535 for private use; 4-16383 are
     * allocated by IANA under standards action. An ID at or above this value
     * will never be assigned to a registered algorithm. */
    WC_CUSTOM_COMPRESSION = 16384,
};

/**
 * @breif Check if a compression alg is supported
 *
 * @param alg alg you want to check is supported or not
 * @return 1 if is supported 0 of not
 */
WOLFSSL_API byte wc_isCompressionAlgSupported(word16 alg);


#define COMPRESS_FIXED 1

#define LIBZ_WINBITS_GZIP 16

/* Used in highlevel interfaces for compression backends
 *
 * This struct tracks memory and state of the data as it is compressed and
 * decompressed */
typedef struct wc_CompressionData {
    byte* data;
    void* heap;
    word32 compressedSz;
    word32 uncompressedSz;
    enum wc_CompressionAlgs compressionAlg; /* 0 is no compression is set */
    /* is this a buffer that was allocated during comp/decomp */
    byte dataIsOwned;
    /* is the data compressed */
    byte isCompressed;
}wc_CompressionData;

/* These are a set of highlevel functions that dispactch to prefered default
 * settings for avaible compression algorithm "backends"
 *
 * Current they are used in TLS cert compression */
WOLFSSL_API wc_CompressionData* wc_CompressionData_newCompressed(byte* data,
        word32 compressedSz, word32 uncompressedSz, word32 alg, void* heap);
WOLFSSL_API wc_CompressionData* wc_CompressionData_newUnCompressed(
        byte* data, word32 dataSz, word32 alg, void* heap);
WOLFSSL_API void wc_CompressionData_Free(wc_CompressionData* cd);
WOLFSSL_API int wc_CompressData(wc_CompressionData* data);
WOLFSSL_API int wc_DeCompressData(wc_CompressionData* data);

#ifdef HAVE_LIBZ

/* These are a set of zlib interface functions. They provide access to
 * setting flags and behavior for when the highlevel functions are
 * not set up for your usecase
 *
 * These are called by the highlevel interface */
WOLFSSL_API int wc_Compress(byte*, word32, const byte*, word32, word32);
WOLFSSL_API int wc_Compress_ex(byte* out, word32 outSz, const byte* in,
    word32 inSz, word32 flags, word32 windowBits);
WOLFSSL_API int wc_DeCompress(byte*, word32, const byte*, word32);
WOLFSSL_API int wc_DeCompress_ex(byte* out, word32 outSz, const byte* in,
    word32 inSz, int windowBits);
WOLFSSL_API int wc_DeCompressDynamic(byte** out, int max, int memoryType,
        const byte* in, word32 inSz, int windowBits, void* heap);

#endif /* HAVE_LIBZ */

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLF_CRYPT_COMPRESS_H */

