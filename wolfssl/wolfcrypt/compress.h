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

/*! \file wolfssl/wolfcrypt/compress.h
*/


#ifndef WOLF_CRYPT_COMPRESS_H
#define WOLF_CRYPT_COMPRESS_H

#include <wolfssl/wolfcrypt/types.h>


#ifdef __cplusplus
    extern "C" {
#endif


enum {
/* compression alg Ids used by tls certificate compression defined
 * in RFC 8879, They cannot change but are defined here so they are consistent
 * across wolfSSL */
    WC_NO_COMPRESSION = 0,
    WC_ZLIB           = 1
};

#if defined (HAVE_LIBZ) /* || defined (future backend) */
    #define WOLFSSL_HAVE_COMPRESSION_BACKEND
#endif

#ifdef HAVE_LIBZ


#define COMPRESS_FIXED 1

#define LIBZ_WINBITS_GZIP 16


/* These are a set of zlib interface functions. They provide access to
 * setting flags and behavior for when the high-level functions are
 * not set up for your use case
 *
 * These are called by the high-level interface */
WOLFSSL_API int wc_Compress(byte*, word32, const byte*, word32, word32);
WOLFSSL_API int wc_Compress_ex(byte* out, word32 outSz, const byte* in,
    word32 inSz, word32 flags, word32 windowBits);
WOLFSSL_API int wc_DeCompress(byte*, word32, const byte*, word32);
WOLFSSL_API int wc_DeCompress_ex(byte* out, word32 outSz, const byte* in,
    word32 inSz, int windowBits);
WOLFSSL_API int wc_DeCompressDynamic(byte** out, int max, int memoryType,
        const byte* in, word32 inSz, int windowBits, void* heap);

#endif

#ifdef WOLFSSL_HAVE_COMPRESSION_BACKEND
/**
 * Check if a compression alg is supported
 *
 * @param alg alg you want to check is supported or not
 * @return 1 if supported, 0 if not
 */
WOLFSSL_API byte wc_IsCompressionAlgSupported(word16 alg);

/* Used in high-level interfaces for compression backends
 *
 * This struct tracks memory and state of the data as it is compressed and
 * decompressed */
typedef struct wc_CompressionData {
    byte* data;
    /* this is the heap that all allocated data that CompressionData is
     * related to will use */
    void* heap;
    word32 compressedSz;
    word32 uncompressedSz;
    word16 compressionAlg; /* 0 is no compression is set, WC_ZLIB is zlib */
    /* if true then the data buffer is freed when replaced by
     * new compressed/uncompressed data when *_[De]Compress is called
     *
     * This also determines if the data buffer will be freed when
     * wc_CompressionData_Free is called */
    byte dataIsOwned;
    /* is the data compressed */
    byte isCompressed;
}wc_CompressionData;

/* Init a new wc_CompressionData object from compressed data. This initial data
 * buffer is not owned by the wc_CompressionData object and is the
 * responsibility of the caller
 * Note: if reusing a wc_CompressionData object it must have
 * wc_CompressionData_Free called on it before reiniting
 *
 * @param cd wc_CompressionData object to initialize
 * @param data This is a buffer of data already compressed.
 * @param compSz The size of the data buffer.
 * @param uncompSz The exact size of the data buffer when uncompressed
 * @param alg The id of the compression algorithm used to compress the data
 * Options-{WC_ZLIB}
 * @return 0 if success, negative value on error
 * */
WOLFSSL_API int wc_CompressionData_InitDeComp(wc_CompressionData* cd,
        const byte* data, word32 compSz, word32 uncompSz,
        word16 alg);

/* Init a new wc_CompressionData object from decompressed data. This initial data
 * buffer is not owned by the wc_CompressionData object and is the
 * responsibility of the caller.
 *
 * Note: if reusing a wc_CompressionData object it must have
 * wc_CompressionData_Free called on it before reiniting
 *
 * @param cd wc_CompressionData object to initialize
 * @param data This is a buffer of data that is uncompressed.
 * @param uncompSz The exact size of the data buffer
 * @param alg The id of the compression algorithm used to compress the data
 * Options-{WC_ZLIB}
 * @return 0 if success, negative value on error
 * */
WOLFSSL_API int wc_CompressionData_InitComp(wc_CompressionData* cd,
        const byte* data, word32 uncompSz, word16 alg);

/* set the heap that *_Compress and *_DeCompress will use output buffer
 * allocation */
WOLFSSL_API int wc_CompressionData_SetHeap(wc_CompressionData* cd,
        void* heap);

/* release all internal data that is owned by the wc_CompressionData object */
WOLFSSL_API void wc_CompressionData_Free(wc_CompressionData* cd);

/* Compress data inside of wc_CompressionData object. This call allocates a
 * new buffer to Compress into; if the buffer already in the object is
 * from a previous *_DeCompress call it is owned by this object and is freed.
 * If it is the buffer from the *_InitComp call it is not freed.
 *
 * @param data initialized wc_CompressionData object that set for compression
 * @return 0 on success or negative value on error.
 * Compressed data is in wc_CompressionData on success along with context
 * about the compression.
 */
WOLFSSL_API int wc_CompressionData_Compress(wc_CompressionData* data);

/* Compressed data into the output buffer owned by the caller. The
 * wc_CompressionData object is left un-touched.
 *
 * @param data initialized wc_CompressionData object that set for compression
 * @param out output buffer compressed data will land in with space for
 * compressed data
 * @param outSz size of output buffer
 * @returns number of bytes written on success or negaitve error code otherwise
 */
WOLFSSL_API int wc_CompressionData_CompToBuf(const wc_CompressionData* data,
        byte* out, word32 outSz);

/* Decompress data inside of wc_CompressionData object. This call allocates a
 * new buffer to decompress into; if the buffer already in the object is
 * from a previous *_Compress call it is owned by this object and is freed.
 * If it is the buffer from the *_InitDeComp call it is not freed.
 *
 * @param data initialized wc_CompressionData object that set for compression
 * @return 0 on success or negative value on error.
 * Compressed data is in wc_CompressionData on success along with context
 * about the compression.
 */
WOLFSSL_API int wc_CompressionData_DeCompress(wc_CompressionData* data);

/* Decompressed data into the output buffer owned by the caller. The
 * wc_CompressionData object is left un-touched.
 *
 * @param data initialized wc_CompressionData object that set for compression
 * @param out output buffer decompressed data will land in with space for
 * decompressed data
 * @param outSz size of output buffer
 * @returns number of bytes written on success or negaitve error code otherwise
 */
WOLFSSL_API int wc_CompressionData_DeCompToBuf(const wc_CompressionData* data,
        byte* out, word32 outSz);

#endif /* WOLFSSL_HAVE_COMPRESSION_BACKEND */

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLF_CRYPT_COMPRESS_H */

