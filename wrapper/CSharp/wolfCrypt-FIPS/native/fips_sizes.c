/* fips_sizes.c
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

/* Size helper for the C# FIPS wrapper.
 *
 * The v5.2.3 FIPS boundary exposes only initializers that operate on
 * caller-allocated structures (wc_InitRng_fips, wc_InitRsaKey_fips, ...).
 * C# cannot know those structure sizes, and they depend on the configure
 * options of the library build. This file is compiled against the same
 * installed headers (including wolfssl/options.h) as the FIPS library and
 * reports sizeof() for each structure the wrapper allocates.
 *
 * This code is outside the FIPS module boundary. It contains no
 * cryptographic functionality and does not link against libwolfssl, so it
 * has no effect on the module or its in-core integrity hash. */

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/dh.h>
#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/sha3.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/cmac.h>
#include <wolfssl/wolfcrypt/kdf.h>
#include <stddef.h>

/* user_settings.h FIPS builds may define only HAVE_FIPS_VERSION */
#if !defined(HAVE_FIPS_VERSION_MAJOR) && defined(HAVE_FIPS_VERSION)
    #define HAVE_FIPS_VERSION_MAJOR HAVE_FIPS_VERSION
#endif
#if !defined(HAVE_FIPS_VERSION_MINOR) && defined(HAVE_FIPS_VERSION)
    #define HAVE_FIPS_VERSION_MINOR 0
#endif

#if defined(_WIN32)
    #define WC_CSHARP_FIPS_API __declspec(dllexport)
#else
    #define WC_CSHARP_FIPS_API __attribute__((visibility("default")))
#endif

/* Keep in sync with FipsStructType in Native.cs. Values are part of the
 * ABI between this helper and the C# wrapper; append only. */
enum wc_csharp_fips_struct {
    WC_CSHARP_FIPS_RNG     = 0,
    WC_CSHARP_FIPS_AES     = 1,
    WC_CSHARP_FIPS_RSA     = 2,
    WC_CSHARP_FIPS_ECC     = 3,
    WC_CSHARP_FIPS_DH      = 4,
    WC_CSHARP_FIPS_SHA     = 5,
    WC_CSHARP_FIPS_SHA224  = 6,
    WC_CSHARP_FIPS_SHA256  = 7,
    WC_CSHARP_FIPS_SHA384  = 8,
    WC_CSHARP_FIPS_SHA512  = 9,
    WC_CSHARP_FIPS_SHA3    = 10,
    WC_CSHARP_FIPS_HMAC    = 11,
    WC_CSHARP_FIPS_CMAC    = 12,
    /* not a struct: capacity of the HkdfLabel buffer in
     * wc_Tls13_HKDF_Expand_Label (MAX_TLS13_HKDF_LABEL_SZ) */
    WC_CSHARP_FIPS_TLS13_LABEL_MAX = 13,
    /* not a struct: FIPS version the helper was built for, as
     * major * 100 + minor (build fingerprint) */
    WC_CSHARP_FIPS_VERSION_MM = 14,
    /* not a struct: POSIX cksum CRC and size of the libwolfssl file this
     * helper was built for (set by build-native.sh; 0 if unknown) */
    WC_CSHARP_FIPS_LIB_CRC  = 15,
    WC_CSHARP_FIPS_LIB_SIZE = 16,
    /* not a struct: offset of the devId member of Aes and Hmac, which
     * exist only with WOLF_CRYPTO_CB (0 otherwise; devId is never the
     * first member). The boundary has no wc_AesInit_fips or
     * wc_HmacInit_fips, so the wrapper sets INVALID_DEVID there itself. */
    WC_CSHARP_FIPS_AES_DEVID_OFFSET  = 17,
    WC_CSHARP_FIPS_HMAC_DEVID_OFFSET = 18,
    /* not a struct: RNG_MAX_BLOCK_LEN (largest single DRBG request) */
    WC_CSHARP_FIPS_RNG_MAX_BLOCK_LEN = 19
};

/* Returns sizeof() of the requested structure, or 0 when the structure is
 * not available in this build. */
WC_CSHARP_FIPS_API int wc_csharp_fips_sizeof(int type);

int wc_csharp_fips_sizeof(int type)
{
    switch (type) {
        case WC_CSHARP_FIPS_RNG:    return (int)sizeof(WC_RNG);
    #ifndef NO_AES
        case WC_CSHARP_FIPS_AES:    return (int)sizeof(Aes);
    #endif
    #ifndef NO_RSA
        case WC_CSHARP_FIPS_RSA:    return (int)sizeof(RsaKey);
    #endif
    #ifdef HAVE_ECC
        case WC_CSHARP_FIPS_ECC:    return (int)sizeof(ecc_key);
    #endif
    #ifndef NO_DH
        case WC_CSHARP_FIPS_DH:     return (int)sizeof(DhKey);
    #endif
    #ifndef NO_SHA
        case WC_CSHARP_FIPS_SHA:    return (int)sizeof(wc_Sha);
    #endif
    #ifdef WOLFSSL_SHA224
        case WC_CSHARP_FIPS_SHA224: return (int)sizeof(wc_Sha224);
    #endif
    #ifndef NO_SHA256
        case WC_CSHARP_FIPS_SHA256: return (int)sizeof(wc_Sha256);
    #endif
    #ifdef WOLFSSL_SHA384
        case WC_CSHARP_FIPS_SHA384: return (int)sizeof(wc_Sha384);
    #endif
    #ifdef WOLFSSL_SHA512
        case WC_CSHARP_FIPS_SHA512: return (int)sizeof(wc_Sha512);
    #endif
    #ifdef WOLFSSL_SHA3
        case WC_CSHARP_FIPS_SHA3:   return (int)sizeof(wc_Sha3);
    #endif
    #ifndef NO_HMAC
        case WC_CSHARP_FIPS_HMAC:   return (int)sizeof(Hmac);
    #endif
    #ifdef WOLFSSL_CMAC
        case WC_CSHARP_FIPS_CMAC:   return (int)sizeof(Cmac);
    #endif
    #ifdef HAVE_HKDF
        case WC_CSHARP_FIPS_TLS13_LABEL_MAX:
            return (int)MAX_TLS13_HKDF_LABEL_SZ;
    #endif
    #if defined(HAVE_FIPS_VERSION_MAJOR) && defined(HAVE_FIPS_VERSION_MINOR)
        case WC_CSHARP_FIPS_VERSION_MM:
            return HAVE_FIPS_VERSION_MAJOR * 100 + HAVE_FIPS_VERSION_MINOR;
    #endif
    #if defined(WC_CSHARP_FIPS_BUILT_LIB_CRC) && \
        defined(WC_CSHARP_FIPS_BUILT_LIB_SIZE)
        case WC_CSHARP_FIPS_LIB_CRC:
            return (int)(unsigned int)WC_CSHARP_FIPS_BUILT_LIB_CRC;
        case WC_CSHARP_FIPS_LIB_SIZE:
            return (int)WC_CSHARP_FIPS_BUILT_LIB_SIZE;
    #endif
    #if !defined(NO_AES) && defined(WOLF_CRYPTO_CB)
        case WC_CSHARP_FIPS_AES_DEVID_OFFSET:
            return (int)offsetof(Aes, devId);
    #endif
    #if !defined(NO_HMAC) && defined(WOLF_CRYPTO_CB)
        case WC_CSHARP_FIPS_HMAC_DEVID_OFFSET:
            return (int)offsetof(Hmac, devId);
    #endif
        case WC_CSHARP_FIPS_RNG_MAX_BLOCK_LEN:
            return (int)RNG_MAX_BLOCK_LEN;
        default:                    return 0;
    }
}
