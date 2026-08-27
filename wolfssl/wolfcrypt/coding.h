/* coding.h
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
    \file wolfssl/wolfcrypt/coding.h
*/

#ifndef WOLF_CRYPT_CODING_H
#define WOLF_CRYPT_CODING_H

#include <wolfssl/wolfcrypt/types.h>

#ifdef __cplusplus
    extern "C" {
#endif

#ifndef NO_CODING

#ifdef WOLFSSL_API_PREFIX_MAP
    #define Base64_Decode wc_Base64_Decode
    #define Base64_Decode_nonCT wc_Base64_Decode_nonCT
#endif

WOLFSSL_API int Base64_Decode(const byte* in, word32 inLen, byte* out,
                               word32* outLen);

WOLFSSL_API int Base64_Decode_nonCT(const byte* in, word32 inLen, byte* out,
                               word32* outLen);

#if defined(OPENSSL_EXTRA) || defined(SESSION_CERTS) || defined(WOLFSSL_KEY_GEN) \
   || defined(WOLFSSL_CERT_GEN) || defined(HAVE_WEBSERVER) || !defined(NO_DSA)
    #ifndef WOLFSSL_BASE64_ENCODE
        #define WOLFSSL_BASE64_ENCODE
    #endif
#endif


#ifdef WOLFSSL_BASE64_ENCODE
    enum Escaped {
        WC_STD_ENC = 0,       /* normal \n line ending encoding */
        WC_ESC_NL_ENC,        /* use escape sequence encoding   */
        WC_NO_NL_ENC          /* no encoding at all             */
    }; /* Encoding types */

    #ifdef WOLFSSL_API_PREFIX_MAP
        #define Base64_Encode wc_Base64_Encode
        #define Base64_EncodeEsc wc_Base64_EncodeEsc
        #define Base64_Encode_NoNl wc_Base64_Encode_NoNl
    #endif

    /* encode isn't */
    WOLFSSL_API
    int Base64_Encode(const byte* in, word32 inLen, byte* out,
                                  word32* outLen);
    WOLFSSL_API
    int Base64_EncodeEsc(const byte* in, word32 inLen, byte* out,
                                  word32* outLen);
    WOLFSSL_API
    int Base64_Encode_NoNl(const byte* in, word32 inLen, byte* out,
                                  word32* outLen);
#endif

#ifdef WOLFSSL_BASE16
    #ifdef WOLFSSL_API_PREFIX_MAP
        #define Base16_Decode wc_Base16_Decode
        #define Base16_Encode wc_Base16_Encode
    #endif
    WOLFSSL_API
    int Base16_Decode(const byte* in, word32 inLen, byte* out, word32* outLen);
    WOLFSSL_API
    int Base16_Encode(const byte* in, word32 inLen, byte* out, word32* outLen);
#endif

WOLFSSL_LOCAL int Base64_SkipNewline(const byte* in, word32* inLen,
            word32* outJ);

#endif /* !NO_CODING */

/* Largest code point Unicode assigns. */
#define WC_UNICODE_MAX_CODEPOINT    0x10FFFF
/* Code points reserved for the UTF-16 surrogate pairs. They are not
 * characters and never appear in a well formed UTF-8 encoding. */
#define WC_UTF16_HI_SURROGATE_MIN   0xD800
#define WC_UTF16_HI_SURROGATE_MAX   0xDBFF
#define WC_UTF16_LO_SURROGATE_MIN   0xDC00
#define WC_UTF16_LO_SURROGATE_MAX   0xDFFF

/* Certificate name comparison decodes UTF8String attribute values. */
#if !defined(NO_ASN) && !defined(NO_CERTS) && \
        !defined(IGNORE_NAME_CONSTRAINTS)
    #ifndef WOLFSSL_UTF8_DECODE
        #define WOLFSSL_UTF8_DECODE
    #endif
#endif

#ifdef WOLFSSL_UTF8_DECODE
    WOLFSSL_API
    int wc_Utf8_DecodeChar(const byte* in, word32 inLen, word32* inOutIdx,
                           word32* cp);
#endif

#ifdef __cplusplus
    } /* extern "C" */
#endif

#endif /* WOLF_CRYPT_CODING_H */
