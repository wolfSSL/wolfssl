/* test_frodokem.c
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

#include <tests/unit.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#ifdef WOLFSSL_HAVE_FRODOKEM
    #include <wolfssl/wolfcrypt/wc_frodokem.h>
    #include <wolfssl/wolfcrypt/hash.h>
    #include <wolfssl/wolfcrypt/sha256.h>
#endif
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_frodokem.h>

#ifdef WOLFSSL_HAVE_FRODOKEM

/* The set of compiled-in key types, used to drive the functional tests. */
static const int frodokem_types[] = {
#ifdef WOLFSSL_FRODOKEM_SHAKE
#ifdef WOLFSSL_WC_FRODOKEM_640
    WC_FRODOKEM_640_SHAKE,
#endif
#ifdef WOLFSSL_WC_FRODOKEM_976
    WC_FRODOKEM_976_SHAKE,
#endif
#ifdef WOLFSSL_WC_FRODOKEM_1344
    WC_FRODOKEM_1344_SHAKE,
#endif
#endif /* WOLFSSL_FRODOKEM_SHAKE */
#ifdef WOLFSSL_FRODOKEM_AES
#ifdef WOLFSSL_WC_FRODOKEM_640
    WC_FRODOKEM_640_AES,
#endif
#ifdef WOLFSSL_WC_FRODOKEM_976
    WC_FRODOKEM_976_AES,
#endif
#ifdef WOLFSSL_WC_FRODOKEM_1344
    WC_FRODOKEM_1344_AES,
#endif
#endif /* WOLFSSL_FRODOKEM_AES */
#ifdef WOLFSSL_FRODOKEM_EPHEMERAL
#ifdef WOLFSSL_FRODOKEM_SHAKE
#ifdef WOLFSSL_WC_FRODOKEM_640
    WC_EFRODOKEM_640_SHAKE,
#endif
#ifdef WOLFSSL_WC_FRODOKEM_976
    WC_EFRODOKEM_976_SHAKE,
#endif
#ifdef WOLFSSL_WC_FRODOKEM_1344
    WC_EFRODOKEM_1344_SHAKE,
#endif
#endif /* WOLFSSL_FRODOKEM_SHAKE */
#ifdef WOLFSSL_FRODOKEM_AES
#ifdef WOLFSSL_WC_FRODOKEM_640
    WC_EFRODOKEM_640_AES,
#endif
#ifdef WOLFSSL_WC_FRODOKEM_976
    WC_EFRODOKEM_976_AES,
#endif
#ifdef WOLFSSL_WC_FRODOKEM_1344
    WC_EFRODOKEM_1344_AES,
#endif
#endif /* WOLFSSL_FRODOKEM_AES */
#endif /* WOLFSSL_FRODOKEM_EPHEMERAL */
    0 /* sentinel so the array is never empty */
};

#define FRODOKEM_TYPE_CNT \
    ((int)(sizeof(frodokem_types) / sizeof(frodokem_types[0])) - 1)

/* The KAT data is only used by the make-key/encapsulate/decapsulate KAT tests,
 * all of which need key generation to reconstruct the key. */
#if !defined(NO_SHA256) && !defined(WOLFSSL_FRODOKEM_NO_MAKE_KEY)

/* Known-answer test data derived from the official FrodoKEM and eFrodoKEM
 * KAT vectors (PQCkemKAT_*.rsp, count 0), for both the SHAKE and AES matrix A
 * generation variants. To keep the data compact the public key, secret key and
 * ciphertext are stored as SHA-256 digests; the shared secret is stored in
 * full. The seed randomness (kr = s || seedSE || z for key generation, er =
 * u || salt for encapsulation) is what the NIST AES-CTR DRBG produces for KAT
 * count 0. */

#if defined(WOLFSSL_WC_FRODOKEM_640) && defined(WOLFSSL_FRODOKEM_SHAKE)
static const byte frodokem_kr_640_SHAKE[] = {
    0x7c,0x99,0x35,0xa0,0xb0,0x76,0x94,0xaa,0x0c,0x6d,0x10,0xe4,
    0xdb,0x6b,0x1a,0xdd,0x2f,0xd8,0x1a,0x25,0xcc,0xb1,0x48,0x03,
    0x2d,0xcd,0x73,0x99,0x36,0x73,0x7f,0x2d,0xb5,0x05,0xd7,0xcf,
    0xad,0x1b,0x49,0x74,0x99,0x32,0x3c,0x86,0x86,0x32,0x5e,0x47,
    0x92,0xf2,0x67,0xaa,0xfa,0x3f,0x87,0xca,0x60,0xd0,0x1c,0xb5,
    0x4f,0x29,0x20,0x2a,
};
static const byte frodokem_er_640_SHAKE[] = {
    0xeb,0x4a,0x7c,0x66,0xef,0x4e,0xba,0x2d,0xdb,0x38,0xc8,0x8d,
    0x8b,0xc7,0x06,0xb1,0xd6,0x39,0x00,0x21,0x98,0x17,0x2a,0x7b,
    0x19,0x42,0xec,0xa8,0xf6,0xc0,0x01,0xba,0x26,0x20,0x2b,0xee,
    0x59,0xac,0x27,0x54,0x84,0xea,0x76,0x7d,0x41,0xd8,0xd3,0x57,
};
static const byte frodokem_hpk_640_SHAKE[] = {
    0x10,0xe6,0x3e,0xfe,0x34,0x0a,0x73,0xd4,0x6d,0x78,0xf7,0x68,
    0xcf,0xea,0x23,0x5d,0x0d,0x7d,0xa1,0xe9,0xc6,0x36,0xd6,0xed,
    0xc3,0x2d,0x2a,0x4e,0xd4,0xb1,0x3c,0xdc,
};
static const byte frodokem_hsk_640_SHAKE[] = {
    0x23,0x3a,0x52,0xe7,0x3b,0xf5,0xf1,0x6d,0xaa,0xd0,0x03,0xdd,
    0x15,0xce,0xa2,0x8e,0x30,0xdb,0xe6,0x42,0x61,0x58,0xbe,0x48,
    0x67,0x95,0x6a,0xff,0x03,0xd1,0x26,0x91,
};
static const byte frodokem_hct_640_SHAKE[] = {
    0x27,0x11,0xc7,0xe8,0x63,0xc9,0xd8,0x1c,0x08,0x18,0x2b,0x3e,
    0xe1,0xe1,0xc9,0x53,0xcb,0xff,0xb1,0x5d,0xd5,0x0b,0xff,0x88,
    0x25,0xc6,0xc2,0xa7,0x1a,0x4f,0xd0,0x1d,
};
static const byte frodokem_ss_640_SHAKE[] = {
    0x2e,0xd4,0x2c,0xe7,0xd5,0xdb,0xfb,0x11,0x5f,0x2e,0x2b,0xdc,
    0xb6,0x50,0xb3,0xfa,
};
#define FKAT_640_SHAKE \
    { WC_FRODOKEM_640_SHAKE, \
      frodokem_kr_640_SHAKE, \
      (word32)sizeof(frodokem_kr_640_SHAKE), \
      frodokem_er_640_SHAKE, \
      (word32)sizeof(frodokem_er_640_SHAKE), \
      frodokem_hpk_640_SHAKE, \
      frodokem_hsk_640_SHAKE, \
      frodokem_hct_640_SHAKE, \
      frodokem_ss_640_SHAKE, \
      (word32)sizeof(frodokem_ss_640_SHAKE) },
#else
#define FKAT_640_SHAKE
#endif

#if defined(WOLFSSL_WC_FRODOKEM_976) && defined(WOLFSSL_FRODOKEM_SHAKE)
static const byte frodokem_kr_976_SHAKE[] = {
    0x7c,0x99,0x35,0xa0,0xb0,0x76,0x94,0xaa,0x0c,0x6d,0x10,0xe4,
    0xdb,0x6b,0x1a,0xdd,0x2f,0xd8,0x1a,0x25,0xcc,0xb1,0x48,0x03,
    0x2d,0xcd,0x73,0x99,0x36,0x73,0x7f,0x2d,0xb5,0x05,0xd7,0xcf,
    0xad,0x1b,0x49,0x74,0x99,0x32,0x3c,0x86,0x86,0x32,0x5e,0x47,
    0x92,0xf2,0x67,0xaa,0xfa,0x3f,0x87,0xca,0x60,0xd0,0x1c,0xb5,
    0x4f,0x29,0x20,0x2a,0x3e,0x78,0x4c,0xcb,0x7e,0xbc,0xdc,0xfd,
    0x45,0x54,0x2b,0x7f,0x6a,0xf7,0x78,0x74,0x2e,0x0f,0x44,0x79,
    0x17,0x50,0x84,0xaa,
};
static const byte frodokem_er_976_SHAKE[] = {
    0xee,0x71,0x67,0x62,0xc1,0x5e,0x3b,0x72,0xaa,0x76,0x50,0xa6,
    0x3b,0x9a,0x51,0x00,0x40,0xb0,0x3c,0x0f,0xe7,0x04,0x75,0xc0,
    0x46,0x3b,0xbc,0x45,0xa0,0xba,0x5b,0x79,0x80,0xdd,0x46,0xee,
    0xf8,0x2f,0xb0,0x62,0x03,0x50,0x77,0xd0,0x42,0xf3,0x06,0xbb,
    0x63,0x91,0x04,0x0e,0x0d,0xd9,0x65,0xf1,0xfd,0xa9,0xd1,0x83,
    0xca,0x9f,0xcc,0xb4,0x8f,0xc0,0x10,0xb1,0x84,0xab,0x00,0x33,
};
static const byte frodokem_hpk_976_SHAKE[] = {
    0x75,0xed,0x58,0xdd,0x9c,0xb2,0x50,0x1a,0xf1,0x3e,0x56,0xbb,
    0xd8,0x57,0x9b,0x73,0x17,0x99,0x8d,0x82,0x8c,0xa2,0x93,0xe3,
    0x98,0x09,0xf4,0x00,0x44,0x04,0xe7,0x89,
};
static const byte frodokem_hsk_976_SHAKE[] = {
    0x2e,0x79,0x47,0x64,0xc6,0xa3,0xe7,0xc1,0xa1,0x6f,0x00,0xa3,
    0xc3,0x45,0x59,0x1f,0xea,0x97,0x7c,0x21,0x3c,0x87,0x32,0xad,
    0x37,0x1a,0xb9,0x60,0x3e,0x5d,0x63,0xa9,
};
static const byte frodokem_hct_976_SHAKE[] = {
    0x6e,0x35,0x8f,0x98,0xcf,0x02,0xec,0xbf,0x38,0xb8,0xdf,0x50,
    0x61,0x49,0x1d,0xec,0x1e,0xae,0x05,0x2e,0xa6,0x80,0x65,0x61,
    0xc3,0xa4,0xaa,0x5e,0xd2,0x15,0xf7,0xa3,
};
static const byte frodokem_ss_976_SHAKE[] = {
    0x5b,0x6e,0x5a,0x69,0xa3,0xd5,0xf8,0xe7,0x5e,0xea,0x3a,0x6e,
    0x95,0x59,0x5e,0xd0,0x27,0x8d,0xa5,0x5b,0x8b,0x37,0x31,0x42,
};
#define FKAT_976_SHAKE \
    { WC_FRODOKEM_976_SHAKE, \
      frodokem_kr_976_SHAKE, \
      (word32)sizeof(frodokem_kr_976_SHAKE), \
      frodokem_er_976_SHAKE, \
      (word32)sizeof(frodokem_er_976_SHAKE), \
      frodokem_hpk_976_SHAKE, \
      frodokem_hsk_976_SHAKE, \
      frodokem_hct_976_SHAKE, \
      frodokem_ss_976_SHAKE, \
      (word32)sizeof(frodokem_ss_976_SHAKE) },
#else
#define FKAT_976_SHAKE
#endif

#if defined(WOLFSSL_WC_FRODOKEM_1344) && defined(WOLFSSL_FRODOKEM_SHAKE)
static const byte frodokem_kr_1344_SHAKE[] = {
    0x7c,0x99,0x35,0xa0,0xb0,0x76,0x94,0xaa,0x0c,0x6d,0x10,0xe4,
    0xdb,0x6b,0x1a,0xdd,0x2f,0xd8,0x1a,0x25,0xcc,0xb1,0x48,0x03,
    0x2d,0xcd,0x73,0x99,0x36,0x73,0x7f,0x2d,0xb5,0x05,0xd7,0xcf,
    0xad,0x1b,0x49,0x74,0x99,0x32,0x3c,0x86,0x86,0x32,0x5e,0x47,
    0x92,0xf2,0x67,0xaa,0xfa,0x3f,0x87,0xca,0x60,0xd0,0x1c,0xb5,
    0x4f,0x29,0x20,0x2a,0x3e,0x78,0x4c,0xcb,0x7e,0xbc,0xdc,0xfd,
    0x45,0x54,0x2b,0x7f,0x6a,0xf7,0x78,0x74,0x2e,0x0f,0x44,0x79,
    0x17,0x50,0x84,0xaa,0x48,0x8b,0x3b,0x74,0x34,0x06,0x78,0xaa,
    0x38,0xe2,0x2e,0x96,0x28,0xb0,0xa1,0x61,0xfd,0xeb,0x0b,0xd2,
    0x52,0x17,0x3b,0x9c,
};
static const byte frodokem_er_1344_SHAKE[] = {
    0x9f,0x08,0x58,0x76,0x87,0xff,0x66,0x76,0x5c,0x67,0x1d,0xe7,
    0x3e,0x91,0x8d,0x28,0x23,0xca,0x57,0x3f,0xf4,0xe7,0xa3,0x1a,
    0x91,0x60,0x32,0x40,0x26,0xe5,0x40,0xea,0xcb,0x3a,0x04,0xe0,
    0xd5,0x4c,0x75,0xde,0xb9,0x70,0x5b,0xfd,0xfb,0xdf,0x93,0x5a,
    0x75,0x28,0x80,0x2e,0xe6,0xe5,0xb0,0xc6,0xa7,0x3b,0x2b,0x76,
    0x1d,0x9b,0xd0,0x84,0x8a,0x6e,0x4c,0xf3,0xfc,0x4c,0xa8,0x4f,
    0x14,0xe0,0x33,0x1a,0xf3,0x5b,0xfe,0xf4,0x1e,0x42,0xb1,0x3a,
    0x6d,0xae,0x6d,0xf9,0x37,0xf7,0x38,0xc1,0x85,0x7b,0xa1,0xca,
};
static const byte frodokem_hpk_1344_SHAKE[] = {
    0x97,0x4d,0x55,0x14,0xfb,0x13,0x11,0x4b,0xb6,0x67,0x52,0x7e,
    0x84,0x09,0x0b,0x6d,0xe0,0xdf,0xee,0xa0,0x14,0x35,0xc6,0x0a,
    0x3e,0xdc,0x57,0x0d,0x33,0x1a,0x5b,0xd6,
};
static const byte frodokem_hsk_1344_SHAKE[] = {
    0x02,0xd4,0xf7,0x10,0x96,0xb3,0x6f,0x46,0xa9,0x03,0xf7,0x7f,
    0xcc,0x9b,0x77,0x64,0x36,0x6d,0x9a,0x8f,0x84,0xf0,0x6c,0x9f,
    0x86,0xc4,0x64,0xcf,0x69,0x52,0x6d,0x8f,
};
static const byte frodokem_hct_1344_SHAKE[] = {
    0xaa,0x07,0x79,0x97,0x59,0xe8,0x7a,0xd1,0xd0,0x80,0xb2,0xd1,
    0xeb,0x31,0xd1,0x1e,0x3e,0xf9,0x3e,0x66,0x5d,0xf9,0xa8,0xba,
    0xe5,0x02,0x7f,0x4e,0x40,0xfc,0x7a,0x46,
};
static const byte frodokem_ss_1344_SHAKE[] = {
    0x8d,0x20,0xf9,0x71,0x46,0x4d,0xf1,0x9e,0x05,0x61,0xbd,0xd3,
    0x85,0xaf,0xd0,0xe2,0xef,0x0c,0xe2,0x12,0xef,0xd4,0x5a,0x63,
    0x2f,0x5d,0x2c,0x64,0xf3,0xd6,0x6a,0xac,
};
#define FKAT_1344_SHAKE \
    { WC_FRODOKEM_1344_SHAKE, \
      frodokem_kr_1344_SHAKE, \
      (word32)sizeof(frodokem_kr_1344_SHAKE), \
      frodokem_er_1344_SHAKE, \
      (word32)sizeof(frodokem_er_1344_SHAKE), \
      frodokem_hpk_1344_SHAKE, \
      frodokem_hsk_1344_SHAKE, \
      frodokem_hct_1344_SHAKE, \
      frodokem_ss_1344_SHAKE, \
      (word32)sizeof(frodokem_ss_1344_SHAKE) },
#else
#define FKAT_1344_SHAKE
#endif

#if defined(WOLFSSL_WC_FRODOKEM_640) && defined(WOLFSSL_FRODOKEM_AES)
static const byte frodokem_kr_640_AES[] = {
    0x7c,0x99,0x35,0xa0,0xb0,0x76,0x94,0xaa,0x0c,0x6d,0x10,0xe4,
    0xdb,0x6b,0x1a,0xdd,0x2f,0xd8,0x1a,0x25,0xcc,0xb1,0x48,0x03,
    0x2d,0xcd,0x73,0x99,0x36,0x73,0x7f,0x2d,0xb5,0x05,0xd7,0xcf,
    0xad,0x1b,0x49,0x74,0x99,0x32,0x3c,0x86,0x86,0x32,0x5e,0x47,
    0x92,0xf2,0x67,0xaa,0xfa,0x3f,0x87,0xca,0x60,0xd0,0x1c,0xb5,
    0x4f,0x29,0x20,0x2a,
};
static const byte frodokem_er_640_AES[] = {
    0xeb,0x4a,0x7c,0x66,0xef,0x4e,0xba,0x2d,0xdb,0x38,0xc8,0x8d,
    0x8b,0xc7,0x06,0xb1,0xd6,0x39,0x00,0x21,0x98,0x17,0x2a,0x7b,
    0x19,0x42,0xec,0xa8,0xf6,0xc0,0x01,0xba,0x26,0x20,0x2b,0xee,
    0x59,0xac,0x27,0x54,0x84,0xea,0x76,0x7d,0x41,0xd8,0xd3,0x57,
};
static const byte frodokem_hpk_640_AES[] = {
    0x44,0x19,0xf4,0xf1,0x4c,0x33,0x63,0x55,0x11,0x86,0xb9,0x93,
    0x82,0xbf,0x3e,0x62,0xac,0x23,0x82,0xb7,0xb5,0xd4,0xca,0x70,
    0x39,0x2d,0xda,0x58,0x69,0xc8,0xbd,0xa1,
};
static const byte frodokem_hsk_640_AES[] = {
    0x1e,0xfb,0x89,0xe5,0xfc,0x52,0xd2,0xbb,0xab,0x4a,0xdb,0xbb,
    0x65,0xda,0xfb,0x49,0x73,0xd8,0xbf,0x09,0x7f,0x86,0x7e,0xf8,
    0x6d,0xbe,0xa2,0xfd,0x51,0xe5,0xe3,0xea,
};
static const byte frodokem_hct_640_AES[] = {
    0x56,0xd2,0xbd,0xd0,0xc6,0xe9,0x2b,0xc3,0x65,0xf2,0x86,0xbe,
    0x75,0x7e,0x46,0xa0,0xe0,0x40,0xc8,0x75,0xef,0x50,0x20,0xbb,
    0xbf,0xab,0xee,0x00,0x28,0x52,0xe7,0xe4,
};
static const byte frodokem_ss_640_AES[] = {
    0xee,0x5b,0xa8,0xce,0xbb,0x0b,0x41,0xe9,0x03,0x0c,0xa1,0xfb,
    0xc3,0xbe,0xad,0xb9,
};
#define FKAT_640_AES \
    { WC_FRODOKEM_640_AES, \
      frodokem_kr_640_AES, \
      (word32)sizeof(frodokem_kr_640_AES), \
      frodokem_er_640_AES, \
      (word32)sizeof(frodokem_er_640_AES), \
      frodokem_hpk_640_AES, \
      frodokem_hsk_640_AES, \
      frodokem_hct_640_AES, \
      frodokem_ss_640_AES, \
      (word32)sizeof(frodokem_ss_640_AES) },
#else
#define FKAT_640_AES
#endif

#if defined(WOLFSSL_WC_FRODOKEM_976) && defined(WOLFSSL_FRODOKEM_AES)
static const byte frodokem_kr_976_AES[] = {
    0x7c,0x99,0x35,0xa0,0xb0,0x76,0x94,0xaa,0x0c,0x6d,0x10,0xe4,
    0xdb,0x6b,0x1a,0xdd,0x2f,0xd8,0x1a,0x25,0xcc,0xb1,0x48,0x03,
    0x2d,0xcd,0x73,0x99,0x36,0x73,0x7f,0x2d,0xb5,0x05,0xd7,0xcf,
    0xad,0x1b,0x49,0x74,0x99,0x32,0x3c,0x86,0x86,0x32,0x5e,0x47,
    0x92,0xf2,0x67,0xaa,0xfa,0x3f,0x87,0xca,0x60,0xd0,0x1c,0xb5,
    0x4f,0x29,0x20,0x2a,0x3e,0x78,0x4c,0xcb,0x7e,0xbc,0xdc,0xfd,
    0x45,0x54,0x2b,0x7f,0x6a,0xf7,0x78,0x74,0x2e,0x0f,0x44,0x79,
    0x17,0x50,0x84,0xaa,
};
static const byte frodokem_er_976_AES[] = {
    0xee,0x71,0x67,0x62,0xc1,0x5e,0x3b,0x72,0xaa,0x76,0x50,0xa6,
    0x3b,0x9a,0x51,0x00,0x40,0xb0,0x3c,0x0f,0xe7,0x04,0x75,0xc0,
    0x46,0x3b,0xbc,0x45,0xa0,0xba,0x5b,0x79,0x80,0xdd,0x46,0xee,
    0xf8,0x2f,0xb0,0x62,0x03,0x50,0x77,0xd0,0x42,0xf3,0x06,0xbb,
    0x63,0x91,0x04,0x0e,0x0d,0xd9,0x65,0xf1,0xfd,0xa9,0xd1,0x83,
    0xca,0x9f,0xcc,0xb4,0x8f,0xc0,0x10,0xb1,0x84,0xab,0x00,0x33,
};
static const byte frodokem_hpk_976_AES[] = {
    0x47,0x7d,0x38,0x49,0x0e,0x9c,0xf9,0x67,0xdd,0x03,0x8a,0xf6,
    0xb9,0x34,0xd0,0x75,0x12,0x7c,0x0d,0x05,0x15,0x9d,0xe0,0x4f,
    0xc9,0x37,0xb6,0x16,0x5b,0x3d,0xf2,0x1d,
};
static const byte frodokem_hsk_976_AES[] = {
    0x01,0x6e,0xbc,0x6e,0x61,0xcd,0xcf,0x75,0xac,0xf2,0x17,0xe3,
    0x7b,0xc9,0x2c,0xb5,0x57,0x7f,0x61,0xd1,0x4f,0x2c,0x83,0x8b,
    0xd1,0xa2,0x67,0x5a,0x4d,0x34,0x26,0xe8,
};
static const byte frodokem_hct_976_AES[] = {
    0x64,0x1f,0xa3,0x00,0x89,0xd3,0x97,0x82,0x8c,0xa9,0xd1,0xc0,
    0xf2,0x80,0x7b,0xeb,0xe8,0x70,0xa3,0xbd,0xc7,0xdc,0x5b,0xa8,
    0x86,0x6c,0x54,0x3e,0xbf,0x47,0xbc,0x98,
};
static const byte frodokem_ss_976_AES[] = {
    0xd9,0x38,0x8d,0x1b,0x0f,0x97,0xc5,0xdb,0x5f,0x9b,0x4a,0x7e,
    0x99,0x42,0x7c,0xfe,0x90,0xe3,0xe1,0x0c,0x5c,0x56,0x9d,0x02,
};
#define FKAT_976_AES \
    { WC_FRODOKEM_976_AES, \
      frodokem_kr_976_AES, \
      (word32)sizeof(frodokem_kr_976_AES), \
      frodokem_er_976_AES, \
      (word32)sizeof(frodokem_er_976_AES), \
      frodokem_hpk_976_AES, \
      frodokem_hsk_976_AES, \
      frodokem_hct_976_AES, \
      frodokem_ss_976_AES, \
      (word32)sizeof(frodokem_ss_976_AES) },
#else
#define FKAT_976_AES
#endif

#if defined(WOLFSSL_WC_FRODOKEM_1344) && defined(WOLFSSL_FRODOKEM_AES)
static const byte frodokem_kr_1344_AES[] = {
    0x7c,0x99,0x35,0xa0,0xb0,0x76,0x94,0xaa,0x0c,0x6d,0x10,0xe4,
    0xdb,0x6b,0x1a,0xdd,0x2f,0xd8,0x1a,0x25,0xcc,0xb1,0x48,0x03,
    0x2d,0xcd,0x73,0x99,0x36,0x73,0x7f,0x2d,0xb5,0x05,0xd7,0xcf,
    0xad,0x1b,0x49,0x74,0x99,0x32,0x3c,0x86,0x86,0x32,0x5e,0x47,
    0x92,0xf2,0x67,0xaa,0xfa,0x3f,0x87,0xca,0x60,0xd0,0x1c,0xb5,
    0x4f,0x29,0x20,0x2a,0x3e,0x78,0x4c,0xcb,0x7e,0xbc,0xdc,0xfd,
    0x45,0x54,0x2b,0x7f,0x6a,0xf7,0x78,0x74,0x2e,0x0f,0x44,0x79,
    0x17,0x50,0x84,0xaa,0x48,0x8b,0x3b,0x74,0x34,0x06,0x78,0xaa,
    0x38,0xe2,0x2e,0x96,0x28,0xb0,0xa1,0x61,0xfd,0xeb,0x0b,0xd2,
    0x52,0x17,0x3b,0x9c,
};
static const byte frodokem_er_1344_AES[] = {
    0x9f,0x08,0x58,0x76,0x87,0xff,0x66,0x76,0x5c,0x67,0x1d,0xe7,
    0x3e,0x91,0x8d,0x28,0x23,0xca,0x57,0x3f,0xf4,0xe7,0xa3,0x1a,
    0x91,0x60,0x32,0x40,0x26,0xe5,0x40,0xea,0xcb,0x3a,0x04,0xe0,
    0xd5,0x4c,0x75,0xde,0xb9,0x70,0x5b,0xfd,0xfb,0xdf,0x93,0x5a,
    0x75,0x28,0x80,0x2e,0xe6,0xe5,0xb0,0xc6,0xa7,0x3b,0x2b,0x76,
    0x1d,0x9b,0xd0,0x84,0x8a,0x6e,0x4c,0xf3,0xfc,0x4c,0xa8,0x4f,
    0x14,0xe0,0x33,0x1a,0xf3,0x5b,0xfe,0xf4,0x1e,0x42,0xb1,0x3a,
    0x6d,0xae,0x6d,0xf9,0x37,0xf7,0x38,0xc1,0x85,0x7b,0xa1,0xca,
};
static const byte frodokem_hpk_1344_AES[] = {
    0xe2,0x83,0xbf,0xd5,0x9b,0xcc,0xa4,0xda,0x53,0x80,0xbc,0xa9,
    0xe4,0x3c,0x0d,0xfc,0xc3,0xb3,0xb2,0xb4,0xd3,0xf3,0xa0,0x2c,
    0x64,0x2e,0x0d,0x43,0x92,0x03,0xee,0x81,
};
static const byte frodokem_hsk_1344_AES[] = {
    0xee,0x4a,0x33,0x60,0x94,0x5b,0x71,0x8f,0xb1,0x04,0x74,0xe9,
    0xc6,0x64,0xe2,0xc3,0x9b,0xd7,0x7d,0xfd,0x6b,0xfe,0xba,0x73,
    0x3c,0x10,0xd2,0x69,0x50,0xf4,0x62,0xce,
};
static const byte frodokem_hct_1344_AES[] = {
    0x4a,0x37,0x7d,0xba,0x12,0xe3,0x78,0xeb,0x9a,0x82,0x32,0x02,
    0x81,0xc9,0xe8,0x61,0x08,0xd8,0x31,0xb2,0xde,0xba,0xe1,0xe1,
    0x9c,0xc5,0x19,0x5f,0xe8,0x6d,0x73,0x20,
};
static const byte frodokem_ss_1344_AES[] = {
    0x37,0x69,0x55,0x16,0x12,0x73,0xfc,0x66,0x7f,0x3f,0xea,0xe5,
    0xec,0x98,0x68,0x18,0x20,0xdb,0xd7,0x59,0x97,0x1b,0xb0,0xa2,
    0xd2,0xbe,0xc4,0x51,0x0f,0x55,0x7e,0x83,
};
#define FKAT_1344_AES \
    { WC_FRODOKEM_1344_AES, \
      frodokem_kr_1344_AES, \
      (word32)sizeof(frodokem_kr_1344_AES), \
      frodokem_er_1344_AES, \
      (word32)sizeof(frodokem_er_1344_AES), \
      frodokem_hpk_1344_AES, \
      frodokem_hsk_1344_AES, \
      frodokem_hct_1344_AES, \
      frodokem_ss_1344_AES, \
      (word32)sizeof(frodokem_ss_1344_AES) },
#else
#define FKAT_1344_AES
#endif

#if defined(WOLFSSL_WC_FRODOKEM_640) && defined(WOLFSSL_FRODOKEM_SHAKE) && \
    defined(WOLFSSL_FRODOKEM_EPHEMERAL)
static const byte frodokem_kr_E640_SHAKE[] = {
    0x7c,0x99,0x35,0xa0,0xb0,0x76,0x94,0xaa,0x0c,0x6d,0x10,0xe4,
    0xdb,0x6b,0x1a,0xdd,0x2f,0xd8,0x1a,0x25,0xcc,0xb1,0x48,0x03,
    0x2d,0xcd,0x73,0x99,0x36,0x73,0x7f,0x2d,0xb5,0x05,0xd7,0xcf,
    0xad,0x1b,0x49,0x74,0x99,0x32,0x3c,0x86,0x86,0x32,0x5e,0x47,
};
static const byte frodokem_er_E640_SHAKE[] = {
    0x33,0xb3,0xc0,0x75,0x07,0xe4,0x20,0x17,0x48,0x49,0x4d,0x83,
    0x2b,0x6e,0xe2,0xa6,
};
static const byte frodokem_hpk_E640_SHAKE[] = {
    0x49,0xa3,0x03,0x46,0x0f,0x09,0x77,0x33,0x9c,0xbd,0x2c,0x1b,
    0x5a,0xa0,0xe7,0xaf,0x44,0xc5,0x02,0x49,0x17,0xf5,0xf7,0xac,
    0xed,0x47,0x25,0xe9,0xd4,0xa2,0xc6,0x14,
};
static const byte frodokem_hsk_E640_SHAKE[] = {
    0x85,0xd0,0xe3,0x16,0x3f,0x8c,0xae,0xbe,0xe1,0xb5,0x48,0x37,
    0xa4,0x70,0xe6,0xb0,0x49,0x83,0x78,0x4e,0x3c,0x3d,0x2b,0x2f,
    0x03,0x6b,0x7f,0x95,0x87,0x55,0x08,0xaa,
};
static const byte frodokem_hct_E640_SHAKE[] = {
    0x88,0xba,0x53,0x7b,0x53,0x6d,0x89,0xfd,0x0b,0x84,0xf8,0x60,
    0x4a,0x60,0x40,0xa9,0xdd,0x96,0x11,0x4e,0xe6,0xad,0x43,0x23,
    0x5c,0x95,0x1e,0xdf,0x42,0x6c,0x68,0x0d,
};
static const byte frodokem_ss_E640_SHAKE[] = {
    0x72,0x97,0x80,0xfc,0x51,0x65,0x7e,0x21,0x35,0x7f,0x03,0xa3,
    0x38,0x11,0x65,0x69,
};
#define FKAT_E640_SHAKE \
    { WC_EFRODOKEM_640_SHAKE, \
      frodokem_kr_E640_SHAKE, \
      (word32)sizeof(frodokem_kr_E640_SHAKE), \
      frodokem_er_E640_SHAKE, \
      (word32)sizeof(frodokem_er_E640_SHAKE), \
      frodokem_hpk_E640_SHAKE, \
      frodokem_hsk_E640_SHAKE, \
      frodokem_hct_E640_SHAKE, \
      frodokem_ss_E640_SHAKE, \
      (word32)sizeof(frodokem_ss_E640_SHAKE) },
#else
#define FKAT_E640_SHAKE
#endif

#if defined(WOLFSSL_WC_FRODOKEM_976) && defined(WOLFSSL_FRODOKEM_SHAKE) && \
    defined(WOLFSSL_FRODOKEM_EPHEMERAL)
static const byte frodokem_kr_E976_SHAKE[] = {
    0x7c,0x99,0x35,0xa0,0xb0,0x76,0x94,0xaa,0x0c,0x6d,0x10,0xe4,
    0xdb,0x6b,0x1a,0xdd,0x2f,0xd8,0x1a,0x25,0xcc,0xb1,0x48,0x03,
    0x2d,0xcd,0x73,0x99,0x36,0x73,0x7f,0x2d,0xb5,0x05,0xd7,0xcf,
    0xad,0x1b,0x49,0x74,0x99,0x32,0x3c,0x86,0x86,0x32,0x5e,0x47,
    0x92,0xf2,0x67,0xaa,0xfa,0x3f,0x87,0xca,0x60,0xd0,0x1c,0xb5,
    0x4f,0x29,0x20,0x2a,
};
static const byte frodokem_er_E976_SHAKE[] = {
    0xeb,0x4a,0x7c,0x66,0xef,0x4e,0xba,0x2d,0xdb,0x38,0xc8,0x8d,
    0x8b,0xc7,0x06,0xb1,0xd6,0x39,0x00,0x21,0x98,0x17,0x2a,0x7b,
};
static const byte frodokem_hpk_E976_SHAKE[] = {
    0x94,0x9c,0xe7,0x6a,0xae,0x38,0xde,0xcd,0x41,0xe2,0x32,0x06,
    0x23,0x62,0xad,0xb8,0x92,0x46,0xba,0xce,0xfe,0x22,0x1f,0x80,
    0x32,0x5d,0x45,0x49,0x02,0x63,0x1c,0xe4,
};
static const byte frodokem_hsk_E976_SHAKE[] = {
    0x3d,0x5a,0x3a,0x15,0x0f,0xee,0xd6,0x4a,0x86,0x1f,0x7e,0x87,
    0xd4,0xee,0x83,0xb1,0x35,0xc8,0xb1,0xbe,0x43,0x9e,0x14,0x21,
    0xc4,0x19,0xbf,0x86,0xac,0x15,0xdc,0x50,
};
static const byte frodokem_hct_E976_SHAKE[] = {
    0xdf,0x84,0x22,0xbf,0xda,0xe4,0xe3,0x13,0x55,0x22,0x54,0xd4,
    0xc2,0x91,0xeb,0x17,0xf0,0xc6,0x0d,0x5c,0x46,0x01,0x3a,0x26,
    0x79,0x21,0x45,0xa4,0xc4,0x6f,0x4b,0x0e,
};
static const byte frodokem_ss_E976_SHAKE[] = {
    0xa9,0x81,0x65,0x53,0x9a,0x4a,0xad,0x97,0x90,0x23,0xd6,0x7b,
    0x43,0x5d,0x31,0x6f,0x00,0x7c,0x86,0xee,0xaf,0xdb,0x63,0xc7,
};
#define FKAT_E976_SHAKE \
    { WC_EFRODOKEM_976_SHAKE, \
      frodokem_kr_E976_SHAKE, \
      (word32)sizeof(frodokem_kr_E976_SHAKE), \
      frodokem_er_E976_SHAKE, \
      (word32)sizeof(frodokem_er_E976_SHAKE), \
      frodokem_hpk_E976_SHAKE, \
      frodokem_hsk_E976_SHAKE, \
      frodokem_hct_E976_SHAKE, \
      frodokem_ss_E976_SHAKE, \
      (word32)sizeof(frodokem_ss_E976_SHAKE) },
#else
#define FKAT_E976_SHAKE
#endif

#if defined(WOLFSSL_WC_FRODOKEM_1344) && defined(WOLFSSL_FRODOKEM_SHAKE) && \
    defined(WOLFSSL_FRODOKEM_EPHEMERAL)
static const byte frodokem_kr_E1344_SHAKE[] = {
    0x7c,0x99,0x35,0xa0,0xb0,0x76,0x94,0xaa,0x0c,0x6d,0x10,0xe4,
    0xdb,0x6b,0x1a,0xdd,0x2f,0xd8,0x1a,0x25,0xcc,0xb1,0x48,0x03,
    0x2d,0xcd,0x73,0x99,0x36,0x73,0x7f,0x2d,0xb5,0x05,0xd7,0xcf,
    0xad,0x1b,0x49,0x74,0x99,0x32,0x3c,0x86,0x86,0x32,0x5e,0x47,
    0x92,0xf2,0x67,0xaa,0xfa,0x3f,0x87,0xca,0x60,0xd0,0x1c,0xb5,
    0x4f,0x29,0x20,0x2a,0x3e,0x78,0x4c,0xcb,0x7e,0xbc,0xdc,0xfd,
    0x45,0x54,0x2b,0x7f,0x6a,0xf7,0x78,0x74,
};
static const byte frodokem_er_E1344_SHAKE[] = {
    0x8b,0xf0,0xf4,0x59,0xf0,0xfb,0x3e,0xa8,0xd3,0x27,0x64,0xc2,
    0x59,0xae,0x63,0x11,0x78,0x97,0x6b,0xaf,0x36,0x83,0xd3,0x33,
    0x83,0x18,0x8a,0x65,0xa4,0xc2,0x44,0x9b,
};
static const byte frodokem_hpk_E1344_SHAKE[] = {
    0x45,0x4d,0x55,0x2f,0x3c,0x25,0xaa,0xf0,0xe5,0xac,0xc1,0xa4,
    0xfc,0x43,0x10,0x98,0xb9,0x0c,0xe3,0x99,0x3e,0x86,0x42,0x68,
    0xa2,0x79,0x5a,0xe7,0xff,0x3c,0xe5,0xca,
};
static const byte frodokem_hsk_E1344_SHAKE[] = {
    0xbe,0x73,0xb2,0x19,0x69,0x05,0x4a,0x4f,0xd4,0x45,0x25,0x08,
    0x23,0xbe,0xd8,0xec,0x91,0xe6,0xa2,0x52,0x1b,0xce,0x0a,0xd0,
    0x97,0x49,0xdd,0x1e,0x6c,0xb8,0xd6,0x6f,
};
static const byte frodokem_hct_E1344_SHAKE[] = {
    0x2c,0x76,0xc5,0x40,0xee,0xba,0x95,0x1c,0x7e,0x16,0x68,0x99,
    0x3d,0x13,0xa3,0xe3,0xcc,0xfd,0xc8,0xbc,0xba,0x29,0x44,0x68,
    0x54,0x80,0xc2,0xb8,0x82,0x50,0xcc,0xf9,
};
static const byte frodokem_ss_E1344_SHAKE[] = {
    0x6d,0x69,0xdf,0x1a,0x90,0x96,0x8e,0xab,0xad,0xa6,0x9c,0xd3,
    0x0e,0xc6,0x81,0x3a,0x44,0x06,0x30,0x9d,0xac,0x17,0x44,0x29,
    0xa0,0x12,0x08,0x52,0xbf,0x82,0x64,0x60,
};
#define FKAT_E1344_SHAKE \
    { WC_EFRODOKEM_1344_SHAKE, \
      frodokem_kr_E1344_SHAKE, \
      (word32)sizeof(frodokem_kr_E1344_SHAKE), \
      frodokem_er_E1344_SHAKE, \
      (word32)sizeof(frodokem_er_E1344_SHAKE), \
      frodokem_hpk_E1344_SHAKE, \
      frodokem_hsk_E1344_SHAKE, \
      frodokem_hct_E1344_SHAKE, \
      frodokem_ss_E1344_SHAKE, \
      (word32)sizeof(frodokem_ss_E1344_SHAKE) },
#else
#define FKAT_E1344_SHAKE
#endif

#if defined(WOLFSSL_WC_FRODOKEM_640) && defined(WOLFSSL_FRODOKEM_AES) && \
    defined(WOLFSSL_FRODOKEM_EPHEMERAL)
static const byte frodokem_kr_E640_AES[] = {
    0x7c,0x99,0x35,0xa0,0xb0,0x76,0x94,0xaa,0x0c,0x6d,0x10,0xe4,
    0xdb,0x6b,0x1a,0xdd,0x2f,0xd8,0x1a,0x25,0xcc,0xb1,0x48,0x03,
    0x2d,0xcd,0x73,0x99,0x36,0x73,0x7f,0x2d,0xb5,0x05,0xd7,0xcf,
    0xad,0x1b,0x49,0x74,0x99,0x32,0x3c,0x86,0x86,0x32,0x5e,0x47,
};
static const byte frodokem_er_E640_AES[] = {
    0x33,0xb3,0xc0,0x75,0x07,0xe4,0x20,0x17,0x48,0x49,0x4d,0x83,
    0x2b,0x6e,0xe2,0xa6,
};
static const byte frodokem_hpk_E640_AES[] = {
    0x3d,0x9e,0xc6,0x83,0x5b,0x6e,0x15,0xd8,0x15,0xc2,0xf8,0x45,
    0x48,0x42,0x79,0xa7,0xcc,0x4b,0xf3,0xcc,0xc7,0x7d,0x00,0x29,
    0xd3,0xb6,0x95,0x47,0x34,0x19,0xf3,0x29,
};
static const byte frodokem_hsk_E640_AES[] = {
    0x80,0x96,0xbd,0x18,0x6c,0xf9,0x9d,0xfa,0x98,0x9a,0x78,0xe2,
    0x95,0xe9,0x58,0xcc,0x83,0x39,0xaf,0x24,0x5d,0x7b,0xe3,0x8d,
    0x88,0x70,0x4f,0x32,0x9a,0x00,0xba,0x66,
};
static const byte frodokem_hct_E640_AES[] = {
    0xa2,0xdb,0xb4,0xa4,0xbc,0x4b,0x72,0x92,0xf3,0x68,0xe7,0x1a,
    0x34,0x51,0xad,0x8d,0xcd,0x10,0x12,0x32,0x68,0x0c,0x24,0xa6,
    0x92,0xcc,0xe8,0xca,0xd4,0x03,0x48,0xea,
};
static const byte frodokem_ss_E640_AES[] = {
    0x9f,0x54,0x37,0x7d,0x45,0x20,0x90,0xf3,0x63,0x1e,0x45,0xb9,
    0x39,0x9a,0x28,0x92,
};
#define FKAT_E640_AES \
    { WC_EFRODOKEM_640_AES, \
      frodokem_kr_E640_AES, \
      (word32)sizeof(frodokem_kr_E640_AES), \
      frodokem_er_E640_AES, \
      (word32)sizeof(frodokem_er_E640_AES), \
      frodokem_hpk_E640_AES, \
      frodokem_hsk_E640_AES, \
      frodokem_hct_E640_AES, \
      frodokem_ss_E640_AES, \
      (word32)sizeof(frodokem_ss_E640_AES) },
#else
#define FKAT_E640_AES
#endif

#if defined(WOLFSSL_WC_FRODOKEM_976) && defined(WOLFSSL_FRODOKEM_AES) && \
    defined(WOLFSSL_FRODOKEM_EPHEMERAL)
static const byte frodokem_kr_E976_AES[] = {
    0x7c,0x99,0x35,0xa0,0xb0,0x76,0x94,0xaa,0x0c,0x6d,0x10,0xe4,
    0xdb,0x6b,0x1a,0xdd,0x2f,0xd8,0x1a,0x25,0xcc,0xb1,0x48,0x03,
    0x2d,0xcd,0x73,0x99,0x36,0x73,0x7f,0x2d,0xb5,0x05,0xd7,0xcf,
    0xad,0x1b,0x49,0x74,0x99,0x32,0x3c,0x86,0x86,0x32,0x5e,0x47,
    0x92,0xf2,0x67,0xaa,0xfa,0x3f,0x87,0xca,0x60,0xd0,0x1c,0xb5,
    0x4f,0x29,0x20,0x2a,
};
static const byte frodokem_er_E976_AES[] = {
    0xeb,0x4a,0x7c,0x66,0xef,0x4e,0xba,0x2d,0xdb,0x38,0xc8,0x8d,
    0x8b,0xc7,0x06,0xb1,0xd6,0x39,0x00,0x21,0x98,0x17,0x2a,0x7b,
};
static const byte frodokem_hpk_E976_AES[] = {
    0xc6,0xc9,0x25,0x07,0xc1,0xf4,0x8c,0x20,0x89,0x76,0x8d,0xe0,
    0x14,0x22,0xa5,0x9c,0x2b,0xb8,0x5c,0xe5,0x6e,0x09,0x56,0x5c,
    0x5f,0x07,0xa9,0x0f,0x84,0x9c,0x45,0xc0,
};
static const byte frodokem_hsk_E976_AES[] = {
    0x07,0x74,0x6e,0x26,0x0b,0x4c,0x11,0x01,0x15,0x58,0xa9,0xb5,
    0x5e,0x1c,0x27,0xa3,0x76,0x0a,0x3b,0x98,0x0e,0x76,0xab,0x22,
    0x19,0xaf,0x01,0x85,0x41,0xff,0x00,0x45,
};
static const byte frodokem_hct_E976_AES[] = {
    0x16,0x05,0x08,0xa0,0xd9,0x3e,0x28,0xcd,0xd7,0xd7,0xf3,0xac,
    0x31,0x66,0x79,0x20,0x4e,0x24,0xf7,0x7d,0x57,0x1d,0x6d,0x31,
    0x8f,0x41,0x41,0xf2,0x51,0x87,0xfd,0xc2,
};
static const byte frodokem_ss_E976_AES[] = {
    0x59,0x4d,0xe8,0x44,0x73,0xb3,0x40,0x8e,0x35,0xf6,0xc4,0xd1,
    0xf2,0xf2,0xec,0x3b,0x56,0xd2,0xdd,0xa9,0x6f,0xa2,0x34,0x96,
};
#define FKAT_E976_AES \
    { WC_EFRODOKEM_976_AES, \
      frodokem_kr_E976_AES, \
      (word32)sizeof(frodokem_kr_E976_AES), \
      frodokem_er_E976_AES, \
      (word32)sizeof(frodokem_er_E976_AES), \
      frodokem_hpk_E976_AES, \
      frodokem_hsk_E976_AES, \
      frodokem_hct_E976_AES, \
      frodokem_ss_E976_AES, \
      (word32)sizeof(frodokem_ss_E976_AES) },
#else
#define FKAT_E976_AES
#endif

#if defined(WOLFSSL_WC_FRODOKEM_1344) && defined(WOLFSSL_FRODOKEM_AES) && \
    defined(WOLFSSL_FRODOKEM_EPHEMERAL)
static const byte frodokem_kr_E1344_AES[] = {
    0x7c,0x99,0x35,0xa0,0xb0,0x76,0x94,0xaa,0x0c,0x6d,0x10,0xe4,
    0xdb,0x6b,0x1a,0xdd,0x2f,0xd8,0x1a,0x25,0xcc,0xb1,0x48,0x03,
    0x2d,0xcd,0x73,0x99,0x36,0x73,0x7f,0x2d,0xb5,0x05,0xd7,0xcf,
    0xad,0x1b,0x49,0x74,0x99,0x32,0x3c,0x86,0x86,0x32,0x5e,0x47,
    0x92,0xf2,0x67,0xaa,0xfa,0x3f,0x87,0xca,0x60,0xd0,0x1c,0xb5,
    0x4f,0x29,0x20,0x2a,0x3e,0x78,0x4c,0xcb,0x7e,0xbc,0xdc,0xfd,
    0x45,0x54,0x2b,0x7f,0x6a,0xf7,0x78,0x74,
};
static const byte frodokem_er_E1344_AES[] = {
    0x8b,0xf0,0xf4,0x59,0xf0,0xfb,0x3e,0xa8,0xd3,0x27,0x64,0xc2,
    0x59,0xae,0x63,0x11,0x78,0x97,0x6b,0xaf,0x36,0x83,0xd3,0x33,
    0x83,0x18,0x8a,0x65,0xa4,0xc2,0x44,0x9b,
};
static const byte frodokem_hpk_E1344_AES[] = {
    0xf4,0xc8,0x3f,0xd6,0xbd,0xbd,0xd1,0x49,0x30,0x7f,0x72,0xd6,
    0x7b,0xdd,0x83,0xaa,0x49,0xcd,0xa6,0xde,0xa6,0x9b,0xf3,0x64,
    0xe7,0xef,0x27,0x76,0xc3,0xb7,0x21,0xff,
};
static const byte frodokem_hsk_E1344_AES[] = {
    0xe4,0x99,0x44,0x64,0x5a,0xa1,0x19,0xb7,0x53,0xe1,0xdd,0x48,
    0x68,0xb4,0x19,0xc4,0x21,0xe9,0x04,0x61,0xde,0x23,0xbb,0xdc,
    0xd5,0x5e,0xa2,0x8c,0xa8,0xd1,0x59,0xf9,
};
static const byte frodokem_hct_E1344_AES[] = {
    0x25,0x27,0xe2,0xb6,0x22,0xec,0xa7,0x6d,0xc8,0xea,0x48,0x9d,
    0x51,0x6c,0x68,0x5c,0x4c,0x67,0x75,0x11,0x27,0xfd,0x3f,0x49,
    0x25,0xc6,0x91,0x55,0x60,0xe9,0xe8,0x43,
};
static const byte frodokem_ss_E1344_AES[] = {
    0xb2,0x43,0xfe,0x6d,0x7c,0x9b,0x38,0x29,0x25,0x2d,0x5a,0xec,
    0x09,0x0a,0x47,0x09,0xf5,0xe3,0x96,0xfd,0xef,0xe4,0xef,0x1a,
    0xa4,0xae,0x6c,0x94,0x98,0xcb,0xce,0x15,
};
#define FKAT_E1344_AES \
    { WC_EFRODOKEM_1344_AES, \
      frodokem_kr_E1344_AES, \
      (word32)sizeof(frodokem_kr_E1344_AES), \
      frodokem_er_E1344_AES, \
      (word32)sizeof(frodokem_er_E1344_AES), \
      frodokem_hpk_E1344_AES, \
      frodokem_hsk_E1344_AES, \
      frodokem_hct_E1344_AES, \
      frodokem_ss_E1344_AES, \
      (word32)sizeof(frodokem_ss_E1344_AES) },
#else
#define FKAT_E1344_AES
#endif


/* One known-answer entry per compiled parameter set / variant. */
typedef struct FrodoKemKat {
    int type;
    const byte* kr;
    word32 krLen;
    const byte* er;
    word32 erLen;
    const byte* hpk;
    const byte* hsk;
    const byte* hct;
    const byte* ss;
    word32 ssLen;
} FrodoKemKat;

static const FrodoKemKat frodokem_kats[] = {
    FKAT_640_SHAKE FKAT_976_SHAKE FKAT_1344_SHAKE
    FKAT_640_AES FKAT_976_AES FKAT_1344_AES
    FKAT_E640_SHAKE FKAT_E976_SHAKE FKAT_E1344_SHAKE
    FKAT_E640_AES FKAT_E976_AES FKAT_E1344_AES
};

#define FRODOKEM_KAT_CNT \
    ((int)(sizeof(frodokem_kats) / sizeof(frodokem_kats[0])))

#endif /* !NO_SHA256 && !WOLFSSL_FRODOKEM_NO_MAKE_KEY */
#endif /* WOLFSSL_HAVE_FRODOKEM */

/* KAT: key generation. Regenerate each key from fixed randomness and check the
 * encoded public and private keys against the expected SHA-256 digests. */
int test_wc_frodokem_make_key_kats(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_FRODOKEM) && !defined(NO_SHA256) && \
    !defined(WOLFSSL_FRODOKEM_NO_MAKE_KEY)
    int i;
    FrodoKemKey* key = NULL;
    byte* buf = NULL;
    byte hash[WC_SHA256_DIGEST_SIZE];
    word32 pkLen = 0;
    word32 skLen = 0;

    key = (FrodoKemKey*)XMALLOC(sizeof(*key), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(key);
    buf = (byte*)XMALLOC(FRODOKEM_MAX_PRIVATE_KEY_SIZE, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(buf);

    for (i = 0; (i < FRODOKEM_KAT_CNT) && EXPECT_SUCCESS(); i++) {
        const FrodoKemKat* k = &frodokem_kats[i];

        ExpectIntEQ(wc_FrodoKemKey_Init(key, k->type, NULL, INVALID_DEVID), 0);
        ExpectIntEQ(wc_FrodoKemKey_MakeKeyWithRandom(key, k->kr,
            (int)k->krLen), 0);

        ExpectIntEQ(wc_FrodoKemKey_PublicKeySize(key, &pkLen), 0);
        ExpectIntEQ(wc_FrodoKemKey_EncodePublicKey(key, buf, pkLen), 0);
        ExpectIntEQ(wc_Sha256Hash(buf, pkLen, hash), 0);
        ExpectIntEQ(XMEMCMP(hash, k->hpk, WC_SHA256_DIGEST_SIZE), 0);

        ExpectIntEQ(wc_FrodoKemKey_PrivateKeySize(key, &skLen), 0);
        ExpectIntEQ(wc_FrodoKemKey_EncodePrivateKey(key, buf, skLen), 0);
        ExpectIntEQ(wc_Sha256Hash(buf, skLen, hash), 0);
        ExpectIntEQ(XMEMCMP(hash, k->hsk, WC_SHA256_DIGEST_SIZE), 0);

        wc_FrodoKemKey_Free(key);
    }

    XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return EXPECT_RESULT();
}

/* KAT: encapsulation. Recreate the key, encapsulate with fixed randomness and
 * check the ciphertext digest and shared secret against expected values. */
int test_wc_frodokem_encapsulate_kats(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_FRODOKEM) && !defined(NO_SHA256) && \
    !defined(WOLFSSL_FRODOKEM_NO_MAKE_KEY) && \
    !defined(WOLFSSL_FRODOKEM_NO_ENCAPSULATE)
    int i;
    FrodoKemKey* key = NULL;
    byte* ct = NULL;
    byte hash[WC_SHA256_DIGEST_SIZE];
    byte ss[FRODOKEM_MAX_LENSEC];
    word32 ctLen = 0;
    word32 ssLen = 0;

    key = (FrodoKemKey*)XMALLOC(sizeof(*key), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(key);
    ct = (byte*)XMALLOC(FRODOKEM_MAX_CIPHER_TEXT_SIZE, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(ct);

    for (i = 0; (i < FRODOKEM_KAT_CNT) && EXPECT_SUCCESS(); i++) {
        const FrodoKemKat* k = &frodokem_kats[i];

        ExpectIntEQ(wc_FrodoKemKey_Init(key, k->type, NULL, INVALID_DEVID), 0);
        ExpectIntEQ(wc_FrodoKemKey_MakeKeyWithRandom(key, k->kr,
            (int)k->krLen), 0);
        ExpectIntEQ(wc_FrodoKemKey_CipherTextSize(key, &ctLen), 0);
        ExpectIntEQ(wc_FrodoKemKey_SharedSecretSize(key, &ssLen), 0);

        ExpectIntEQ(wc_FrodoKemKey_EncapsulateWithRandom(key, ct, ss, k->er,
            (int)k->erLen), 0);
        ExpectIntEQ(wc_Sha256Hash(ct, ctLen, hash), 0);
        ExpectIntEQ(XMEMCMP(hash, k->hct, WC_SHA256_DIGEST_SIZE), 0);
        ExpectIntEQ(XMEMCMP(ss, k->ss, ssLen), 0);

        wc_FrodoKemKey_Free(key);
    }

    XFREE(ct, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return EXPECT_RESULT();
}

/* KAT: decapsulation. Recreate the key and ciphertext, decapsulate and check
 * the recovered shared secret against the expected value. */
int test_wc_frodokem_decapsulate_kats(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_FRODOKEM) && !defined(NO_SHA256) && \
    !defined(WOLFSSL_FRODOKEM_NO_MAKE_KEY) && \
    !defined(WOLFSSL_FRODOKEM_NO_ENCAPSULATE) && \
    !defined(WOLFSSL_FRODOKEM_NO_DECAPSULATE)
    int i;
    FrodoKemKey* key = NULL;
    byte* ct = NULL;
    byte ss[FRODOKEM_MAX_LENSEC];
    byte ssDec[FRODOKEM_MAX_LENSEC];
    word32 ctLen = 0;
    word32 ssLen = 0;

    key = (FrodoKemKey*)XMALLOC(sizeof(*key), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(key);
    ct = (byte*)XMALLOC(FRODOKEM_MAX_CIPHER_TEXT_SIZE, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(ct);

    for (i = 0; (i < FRODOKEM_KAT_CNT) && EXPECT_SUCCESS(); i++) {
        const FrodoKemKat* k = &frodokem_kats[i];

        ExpectIntEQ(wc_FrodoKemKey_Init(key, k->type, NULL, INVALID_DEVID), 0);
        ExpectIntEQ(wc_FrodoKemKey_MakeKeyWithRandom(key, k->kr,
            (int)k->krLen), 0);
        ExpectIntEQ(wc_FrodoKemKey_CipherTextSize(key, &ctLen), 0);
        ExpectIntEQ(wc_FrodoKemKey_SharedSecretSize(key, &ssLen), 0);
        ExpectIntEQ(wc_FrodoKemKey_EncapsulateWithRandom(key, ct, ss, k->er,
            (int)k->erLen), 0);

        ExpectIntEQ(wc_FrodoKemKey_Decapsulate(key, ssDec, ct, ctLen), 0);
        ExpectIntEQ(XMEMCMP(ssDec, k->ss, ssLen), 0);

        wc_FrodoKemKey_Free(key);
    }

    XFREE(ct, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return EXPECT_RESULT();
}

/* Full RNG-based round trip for every compiled variant: the decapsulated
 * shared secret must equal the encapsulated one. */
int test_wc_frodokem_roundtrip(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_FRODOKEM) && !defined(WC_NO_RNG) && \
    !defined(WOLFSSL_FRODOKEM_NO_MAKE_KEY) && \
    !defined(WOLFSSL_FRODOKEM_NO_ENCAPSULATE) && \
    !defined(WOLFSSL_FRODOKEM_NO_DECAPSULATE)
    int i;
    FrodoKemKey* key = NULL;
    WC_RNG rng;
    byte* ct = NULL;
    byte ss[FRODOKEM_MAX_LENSEC];
    byte ssDec[FRODOKEM_MAX_LENSEC];
    word32 ctLen = 0;
    word32 ssLen = 0;
    int rngInit = 0;

    XMEMSET(&rng, 0, sizeof(rng));
    key = (FrodoKemKey*)XMALLOC(sizeof(*key), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(key);
    ct = (byte*)XMALLOC(FRODOKEM_MAX_CIPHER_TEXT_SIZE, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(ct);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    if (EXPECT_SUCCESS()) {
        rngInit = 1;
    }

    for (i = 0; (i < FRODOKEM_TYPE_CNT) && EXPECT_SUCCESS(); i++) {
        ExpectIntEQ(wc_FrodoKemKey_Init(key, frodokem_types[i], NULL,
            INVALID_DEVID), 0);
        ExpectIntEQ(wc_FrodoKemKey_CipherTextSize(key, &ctLen), 0);
        ExpectIntEQ(wc_FrodoKemKey_SharedSecretSize(key, &ssLen), 0);
        ExpectIntEQ(wc_FrodoKemKey_MakeKey(key, &rng), 0);
        ExpectIntEQ(wc_FrodoKemKey_Encapsulate(key, ct, ss, &rng), 0);
        ExpectIntEQ(wc_FrodoKemKey_Decapsulate(key, ssDec, ct, ctLen), 0);
        ExpectIntEQ(XMEMCMP(ss, ssDec, ssLen), 0);
        wc_FrodoKemKey_Free(key);
    }

    if (rngInit) {
        DoExpectIntEQ(wc_FreeRng(&rng), 0);
    }
    XFREE(ct, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return EXPECT_RESULT();
}

/* Encode then decode the public and private keys and confirm the decoded key
 * pair still produces matching shared secrets. */
int test_wc_frodokem_encode_decode(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_FRODOKEM) && !defined(WC_NO_RNG) && \
    !defined(WOLFSSL_FRODOKEM_NO_MAKE_KEY) && \
    !defined(WOLFSSL_FRODOKEM_NO_ENCAPSULATE) && \
    !defined(WOLFSSL_FRODOKEM_NO_DECAPSULATE)
    int i;
    FrodoKemKey* key = NULL;
    FrodoKemKey* pubKey = NULL;
    FrodoKemKey* privKey = NULL;
    WC_RNG rng;
    byte* pkBuf = NULL;
    byte* skBuf = NULL;
    byte* ct = NULL;
    byte ss[FRODOKEM_MAX_LENSEC];
    byte ssDec[FRODOKEM_MAX_LENSEC];
    word32 pkLen = 0;
    word32 skLen = 0;
    word32 ctLen = 0;
    word32 ssLen = 0;
    int rngInit = 0;

    XMEMSET(&rng, 0, sizeof(rng));
    key = (FrodoKemKey*)XMALLOC(sizeof(*key), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(key);
    pubKey = (FrodoKemKey*)XMALLOC(sizeof(*pubKey), NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(pubKey);
    privKey = (FrodoKemKey*)XMALLOC(sizeof(*privKey), NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(privKey);
    pkBuf = (byte*)XMALLOC(FRODOKEM_MAX_PUBLIC_KEY_SIZE, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(pkBuf);
    skBuf = (byte*)XMALLOC(FRODOKEM_MAX_PRIVATE_KEY_SIZE, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(skBuf);
    ct = (byte*)XMALLOC(FRODOKEM_MAX_CIPHER_TEXT_SIZE, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(ct);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    if (EXPECT_SUCCESS()) {
        rngInit = 1;
    }

    for (i = 0; (i < FRODOKEM_TYPE_CNT) && EXPECT_SUCCESS(); i++) {
        int type = frodokem_types[i];

        ExpectIntEQ(wc_FrodoKemKey_Init(key, type, NULL, INVALID_DEVID), 0);
        ExpectIntEQ(wc_FrodoKemKey_Init(pubKey, type, NULL, INVALID_DEVID), 0);
        ExpectIntEQ(wc_FrodoKemKey_Init(privKey, type, NULL, INVALID_DEVID), 0);
        ExpectIntEQ(wc_FrodoKemKey_PublicKeySize(key, &pkLen), 0);
        ExpectIntEQ(wc_FrodoKemKey_PrivateKeySize(key, &skLen), 0);
        ExpectIntEQ(wc_FrodoKemKey_CipherTextSize(key, &ctLen), 0);
        ExpectIntEQ(wc_FrodoKemKey_SharedSecretSize(key, &ssLen), 0);

        ExpectIntEQ(wc_FrodoKemKey_MakeKey(key, &rng), 0);
        ExpectIntEQ(wc_FrodoKemKey_EncodePublicKey(key, pkBuf, pkLen), 0);
        ExpectIntEQ(wc_FrodoKemKey_EncodePrivateKey(key, skBuf, skLen), 0);
        ExpectIntEQ(wc_FrodoKemKey_DecodePublicKey(pubKey, pkBuf, pkLen), 0);
        ExpectIntEQ(wc_FrodoKemKey_DecodePrivateKey(privKey, skBuf, skLen), 0);

        /* Encapsulate to the decoded public key, decapsulate with the decoded
         * private key. */
        ExpectIntEQ(wc_FrodoKemKey_Encapsulate(pubKey, ct, ss, &rng), 0);
        ExpectIntEQ(wc_FrodoKemKey_Decapsulate(privKey, ssDec, ct, ctLen), 0);
        ExpectIntEQ(XMEMCMP(ss, ssDec, ssLen), 0);

        wc_FrodoKemKey_Free(privKey);
        wc_FrodoKemKey_Free(pubKey);
        wc_FrodoKemKey_Free(key);
    }

    if (rngInit) {
        DoExpectIntEQ(wc_FreeRng(&rng), 0);
    }
    XFREE(ct, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(skBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(pkBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(privKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(pubKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return EXPECT_RESULT();
}

/* A modified ciphertext must decapsulate (implicit rejection) to a shared
 * secret different from the one produced for the valid ciphertext. */
int test_wc_frodokem_decap_implicit_reject(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_FRODOKEM) && !defined(WC_NO_RNG) && \
    !defined(WOLFSSL_FRODOKEM_NO_MAKE_KEY) && \
    !defined(WOLFSSL_FRODOKEM_NO_ENCAPSULATE) && \
    !defined(WOLFSSL_FRODOKEM_NO_DECAPSULATE)
    int i;
    FrodoKemKey* key = NULL;
    WC_RNG rng;
    byte* ct = NULL;
    byte ss[FRODOKEM_MAX_LENSEC];
    byte ssDec[FRODOKEM_MAX_LENSEC];
    byte ssDec2[FRODOKEM_MAX_LENSEC];
    byte exp[FRODOKEM_MAX_LENSEC];
    wc_Shake sh;
    word32 ctLen = 0;
    word32 ssLen = 0;
    int rngInit = 0;

    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(&sh, 0, sizeof(sh));
    key = (FrodoKemKey*)XMALLOC(sizeof(*key), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(key);
    ct = (byte*)XMALLOC(FRODOKEM_MAX_CIPHER_TEXT_SIZE, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(ct);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    if (EXPECT_SUCCESS()) {
        rngInit = 1;
    }

    /* Every compiled variant: a modified ciphertext must decapsulate to an
     * implicit-rejection secret, deterministically. */
    for (i = 0; (i < FRODOKEM_TYPE_CNT) && EXPECT_SUCCESS(); i++) {
        ExpectIntEQ(wc_FrodoKemKey_Init(key, frodokem_types[i], NULL,
            INVALID_DEVID), 0);
        ExpectIntEQ(wc_FrodoKemKey_CipherTextSize(key, &ctLen), 0);
        ExpectIntEQ(wc_FrodoKemKey_SharedSecretSize(key, &ssLen), 0);
        ExpectIntEQ(wc_FrodoKemKey_MakeKey(key, &rng), 0);
        ExpectIntEQ(wc_FrodoKemKey_Encapsulate(key, ct, ss, &rng), 0);
        /* Flip a bit in the ciphertext. */
        if (EXPECT_SUCCESS()) {
            ct[0] ^= 0xff;
        }
        ExpectIntEQ(wc_FrodoKemKey_Decapsulate(key, ssDec, ct, ctLen), 0);
        ExpectIntNE(XMEMCMP(ss, ssDec, ssLen), 0);
        /* Implicit rejection is deterministic: decapsulating the same modified
         * ciphertext again yields the same shared secret (the SHAKE(c' || s)
         * value), not uninitialized/garbage data. */
        ExpectIntEQ(wc_FrodoKemKey_Decapsulate(key, ssDec2, ct, ctLen), 0);
        ExpectIntEQ(XMEMCMP(ssDec, ssDec2, ssLen), 0);
        /* Isolate the implicit-rejection property: the rejected secret must be
         * SHAKE(c1 || c2 || salt || s) over the STORED rejection secret s (not
         * k'). Recompute it (640 hashes with SHAKE128, 976/1344 with SHAKE256)
         * and confirm it matches - a select that used k' would not. */
        if ((frodokem_types[i] & FRODOKEM_BASE_MASK) == WC_FRODOKEM_640) {
            ExpectIntEQ(wc_InitShake128(&sh, NULL, INVALID_DEVID), 0);
            ExpectIntEQ(wc_Shake128_Update(&sh, ct, ctLen), 0);
            ExpectIntEQ(wc_Shake128_Update(&sh, key->s, ssLen), 0);
            ExpectIntEQ(wc_Shake128_Final(&sh, exp, ssLen), 0);
            wc_Shake128_Free(&sh);
        }
        else {
            ExpectIntEQ(wc_InitShake256(&sh, NULL, INVALID_DEVID), 0);
            ExpectIntEQ(wc_Shake256_Update(&sh, ct, ctLen), 0);
            ExpectIntEQ(wc_Shake256_Update(&sh, key->s, ssLen), 0);
            ExpectIntEQ(wc_Shake256_Final(&sh, exp, ssLen), 0);
            wc_Shake256_Free(&sh);
        }
        ExpectIntEQ(XMEMCMP(ssDec, exp, ssLen), 0);
        wc_FrodoKemKey_Free(key);
    }

    if (rngInit) {
        DoExpectIntEQ(wc_FreeRng(&rng), 0);
    }
    XFREE(ct, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return EXPECT_RESULT();
}

/* Decapsulating with a public-key-only object must fail. */
int test_wc_frodokem_decapsulate_pubonly_fails(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_FRODOKEM) && !defined(WC_NO_RNG) && \
    !defined(WOLFSSL_FRODOKEM_NO_MAKE_KEY) && \
    !defined(WOLFSSL_FRODOKEM_NO_ENCAPSULATE) && \
    !defined(WOLFSSL_FRODOKEM_NO_DECAPSULATE)
    int i;
    FrodoKemKey* key = NULL;
    FrodoKemKey* pubKey = NULL;
    WC_RNG rng;
    byte* pkBuf = NULL;
    byte* ct = NULL;
    byte ss[FRODOKEM_MAX_LENSEC];
    byte ssDec[FRODOKEM_MAX_LENSEC];
    word32 pkLen = 0;
    word32 ctLen = 0;
    int rngInit = 0;

    XMEMSET(&rng, 0, sizeof(rng));
    key = (FrodoKemKey*)XMALLOC(sizeof(*key), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(key);
    pubKey = (FrodoKemKey*)XMALLOC(sizeof(*pubKey), NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(pubKey);
    pkBuf = (byte*)XMALLOC(FRODOKEM_MAX_PUBLIC_KEY_SIZE, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(pkBuf);
    ct = (byte*)XMALLOC(FRODOKEM_MAX_CIPHER_TEXT_SIZE, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(ct);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    if (EXPECT_SUCCESS()) {
        rngInit = 1;
    }

    /* Every compiled variant: a public-key-only object cannot decapsulate. */
    for (i = 0; (i < FRODOKEM_TYPE_CNT) && EXPECT_SUCCESS(); i++) {
        ExpectIntEQ(wc_FrodoKemKey_Init(key, frodokem_types[i], NULL,
            INVALID_DEVID), 0);
        ExpectIntEQ(wc_FrodoKemKey_Init(pubKey, frodokem_types[i], NULL,
            INVALID_DEVID), 0);
        ExpectIntEQ(wc_FrodoKemKey_PublicKeySize(key, &pkLen), 0);
        ExpectIntEQ(wc_FrodoKemKey_CipherTextSize(key, &ctLen), 0);
        ExpectIntEQ(wc_FrodoKemKey_MakeKey(key, &rng), 0);
        ExpectIntEQ(wc_FrodoKemKey_Encapsulate(key, ct, ss, &rng), 0);
        ExpectIntEQ(wc_FrodoKemKey_EncodePublicKey(key, pkBuf, pkLen), 0);
        ExpectIntEQ(wc_FrodoKemKey_DecodePublicKey(pubKey, pkBuf, pkLen), 0);
        /* Public-key-only object cannot decapsulate. */
        ExpectIntEQ(wc_FrodoKemKey_Decapsulate(pubKey, ssDec, ct, ctLen),
            WC_NO_ERR_TRACE(BAD_STATE_E));
        wc_FrodoKemKey_Free(pubKey);
        wc_FrodoKemKey_Free(key);
    }

    if (rngInit) {
        DoExpectIntEQ(wc_FreeRng(&rng), 0);
    }
    XFREE(ct, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(pkBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(pubKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return EXPECT_RESULT();
}

/* A private key whose embedded public-key hash does not match the public key
 * must be rejected by decode. */
int test_wc_frodokem_decode_privkey_bad_pkh(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_FRODOKEM) && !defined(WC_NO_RNG) && \
    !defined(WOLFSSL_FRODOKEM_NO_MAKE_KEY)
    int i;
    FrodoKemKey* key = NULL;
    WC_RNG rng;
    byte* sk = NULL;
    word32 skLen = 0;
    int rngInit = 0;

    XMEMSET(&rng, 0, sizeof(rng));
    key = (FrodoKemKey*)XMALLOC(sizeof(*key), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(key);
    sk = (byte*)XMALLOC(FRODOKEM_MAX_PRIVATE_KEY_SIZE, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(sk);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    if (EXPECT_SUCCESS()) {
        rngInit = 1;
    }

    /* Every compiled variant: a corrupted embedded pkh is rejected. */
    for (i = 0; (i < FRODOKEM_TYPE_CNT) && EXPECT_SUCCESS(); i++) {
        ExpectIntEQ(wc_FrodoKemKey_Init(key, frodokem_types[i], NULL,
            INVALID_DEVID), 0);
        ExpectIntEQ(wc_FrodoKemKey_PrivateKeySize(key, &skLen), 0);
        ExpectIntEQ(wc_FrodoKemKey_MakeKey(key, &rng), 0);
        ExpectIntEQ(wc_FrodoKemKey_EncodePrivateKey(key, sk, skLen), 0);

        /* A correctly encoded private key decodes. */
        ExpectIntEQ(wc_FrodoKemKey_DecodePrivateKey(key, sk, skLen), 0);

        /* Corrupt the stored public-key hash (the final lenSec bytes). */
        if (EXPECT_SUCCESS()) {
            sk[skLen - 1] ^= 0xff;
        }
        ExpectIntEQ(wc_FrodoKemKey_DecodePrivateKey(key, sk, skLen),
            WC_NO_ERR_TRACE(WC_KEY_MISMATCH_E));
        wc_FrodoKemKey_Free(key);
    }

    if (rngInit) {
        DoExpectIntEQ(wc_FreeRng(&rng), 0);
    }
    XFREE(sk, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return EXPECT_RESULT();
}

/* Bad-argument and bad-length handling. */
int test_wc_frodokem_bad_args(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_FRODOKEM)
    FrodoKemKey* key = NULL;
    word32 len = 0;
    word32 pkLen = 0;
    word32 skLen = 0;
    int type = frodokem_types[0];
    byte small[8];

    XMEMSET(small, 0, sizeof(small));
    key = (FrodoKemKey*)XMALLOC(sizeof(*key), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(key);

    /* Constructor / destructor NULL handling. */
#ifndef WC_NO_CONSTRUCTORS
    ExpectIntEQ(wc_FrodoKemKey_Delete(NULL, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    ExpectIntEQ(wc_FrodoKemKey_Free(NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Init argument checks: NULL key, unknown type bits. */
    ExpectIntEQ(wc_FrodoKemKey_Init(NULL, type, NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_FrodoKemKey_Init(key, -1, NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Size queries reject NULL key and NULL output. */
    ExpectIntEQ(wc_FrodoKemKey_Init(key, type, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_FrodoKemKey_PublicKeySize(NULL, &len),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_FrodoKemKey_PublicKeySize(key, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_FrodoKemKey_PrivateKeySize(NULL, &len),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_FrodoKemKey_PrivateKeySize(key, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_FrodoKemKey_CipherTextSize(NULL, &len),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_FrodoKemKey_CipherTextSize(key, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_FrodoKemKey_SharedSecretSize(NULL, &len),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_FrodoKemKey_SharedSecretSize(key, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    ExpectIntEQ(wc_FrodoKemKey_PublicKeySize(key, &pkLen), 0);
    ExpectIntEQ(wc_FrodoKemKey_PrivateKeySize(key, &skLen), 0);

    /* Make key argument and length checks. */
#ifndef WOLFSSL_FRODOKEM_NO_MAKE_KEY
    ExpectIntEQ(wc_FrodoKemKey_MakeKeyWithRandom(NULL, small, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_FrodoKemKey_MakeKeyWithRandom(key, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_FrodoKemKey_MakeKeyWithRandom(key, small, 1),
        WC_NO_ERR_TRACE(BUFFER_E));
#ifndef WC_NO_RNG
    ExpectIntEQ(wc_FrodoKemKey_MakeKey(NULL, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_FrodoKemKey_MakeKey(key, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
#endif /* !WOLFSSL_FRODOKEM_NO_MAKE_KEY */

    /* Encapsulate argument checks. */
#ifndef WOLFSSL_FRODOKEM_NO_ENCAPSULATE
#ifndef WC_NO_RNG
    ExpectIntEQ(wc_FrodoKemKey_Encapsulate(NULL, small, small, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    ExpectIntEQ(wc_FrodoKemKey_EncapsulateWithRandom(NULL, small, small,
        small, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* NULL ct / ss are rejected independently of key state. */
    ExpectIntEQ(wc_FrodoKemKey_EncapsulateWithRandom(key, NULL, small,
        small, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_FrodoKemKey_EncapsulateWithRandom(key, small, NULL,
        small, 0), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#ifndef WC_NO_RNG
    /* Encapsulate rejects a NULL rng in isolation (ct and ss valid). */
    ExpectIntEQ(wc_FrodoKemKey_Encapsulate(key, small, small, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif
    /* Encapsulate on a key with no public key set reports bad state. */
    ExpectIntEQ(wc_FrodoKemKey_EncapsulateWithRandom(key, small, small,
        small, 0), WC_NO_ERR_TRACE(BAD_STATE_E));
#endif /* !WOLFSSL_FRODOKEM_NO_ENCAPSULATE */

    /* Decapsulate argument checks. */
#ifndef WOLFSSL_FRODOKEM_NO_DECAPSULATE
    ExpectIntEQ(wc_FrodoKemKey_Decapsulate(NULL, small, small, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* NULL ss / ct are rejected independently of key state and length. */
    ExpectIntEQ(wc_FrodoKemKey_Decapsulate(key, NULL, small, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_FrodoKemKey_Decapsulate(key, small, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
#endif

    /* Encode / decode NULL handling. */
    ExpectIntEQ(wc_FrodoKemKey_EncodePublicKey(NULL, small, pkLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_FrodoKemKey_EncodePublicKey(key, NULL, pkLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_FrodoKemKey_EncodePrivateKey(NULL, small, skLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_FrodoKemKey_EncodePrivateKey(key, NULL, skLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_FrodoKemKey_DecodePublicKey(NULL, small, pkLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_FrodoKemKey_DecodePublicKey(key, NULL, pkLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_FrodoKemKey_DecodePrivateKey(NULL, small, skLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_FrodoKemKey_DecodePrivateKey(key, NULL, skLen),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Encoding before any key material is set must report bad state. */
    ExpectIntEQ(wc_FrodoKemKey_EncodePublicKey(key, small, pkLen),
        WC_NO_ERR_TRACE(BAD_STATE_E));
    ExpectIntEQ(wc_FrodoKemKey_EncodePrivateKey(key, small, skLen),
        WC_NO_ERR_TRACE(BAD_STATE_E));

    /* Wrong encoded lengths on decode must report a buffer error. */
    ExpectIntEQ(wc_FrodoKemKey_DecodePublicKey(key, small, pkLen - 1),
        WC_NO_ERR_TRACE(BUFFER_E));
    ExpectIntEQ(wc_FrodoKemKey_DecodePrivateKey(key, small, skLen - 1),
        WC_NO_ERR_TRACE(BUFFER_E));

    wc_FrodoKemKey_Free(key);
    XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return EXPECT_RESULT();
}

/* Encapsulate and decapsulate length checks on a fully made key. */
int test_wc_frodokem_op_len_checks(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_FRODOKEM) && !defined(WC_NO_RNG) && \
    !defined(WOLFSSL_FRODOKEM_NO_MAKE_KEY) && \
    !defined(WOLFSSL_FRODOKEM_NO_ENCAPSULATE) && \
    !defined(WOLFSSL_FRODOKEM_NO_DECAPSULATE)
    FrodoKemKey* key = NULL;
    WC_RNG rng;
    byte* ct = NULL;
    byte ss[FRODOKEM_MAX_LENSEC];
    byte rnd[8];
    word32 ctLen = 0;
    int rngInit = 0;
    int i = 0;

    XMEMSET(&rng, 0, sizeof(rng));
    XMEMSET(rnd, 0, sizeof(rnd));
    key = (FrodoKemKey*)XMALLOC(sizeof(*key), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(key);
    ct = (byte*)XMALLOC(FRODOKEM_MAX_CIPHER_TEXT_SIZE, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(ct);
    ExpectIntEQ(wc_InitRng(&rng), 0);
    if (EXPECT_SUCCESS()) {
        rngInit = 1;
    }

    /* Repeat for every compiled variant: the bad-length thresholds differ
     * across the parameter sets and the standard/ephemeral split (encapsulate
     * checks lenSec + lenSalt, decapsulate checks ctSize), so a single variant
     * would not exercise them all. */
    for (i = 0; (i < FRODOKEM_TYPE_CNT) && EXPECT_SUCCESS(); i++) {
        ExpectIntEQ(wc_FrodoKemKey_Init(key, frodokem_types[i], NULL,
            INVALID_DEVID), 0);
        ExpectIntEQ(wc_FrodoKemKey_CipherTextSize(key, &ctLen), 0);
        ExpectIntEQ(wc_FrodoKemKey_MakeKey(key, &rng), 0);

        /* Encapsulate with the wrong random length reports a buffer error (the
         * public key is set, so this reaches the length check, not bad
         * state). */
        ExpectIntEQ(wc_FrodoKemKey_EncapsulateWithRandom(key, ct, ss, rnd, 1),
            WC_NO_ERR_TRACE(BUFFER_E));
        /* Decapsulate with the wrong ciphertext length reports a buffer
         * error. */
        ExpectIntEQ(wc_FrodoKemKey_Decapsulate(key, ss, ct, ctLen - 1),
            WC_NO_ERR_TRACE(BUFFER_E));

        wc_FrodoKemKey_Free(key);
    }

    if (rngInit) {
        DoExpectIntEQ(wc_FreeRng(&rng), 0);
    }
    XFREE(ct, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return EXPECT_RESULT();
}

/* Constructor and destructor happy path. */
int test_wc_frodokem_new_delete(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_FRODOKEM) && !defined(WC_NO_CONSTRUCTORS)
    FrodoKemKey* key = NULL;
    word32 pkLen = 0;

    /* New allocates and initializes the object. */
    key = wc_FrodoKemKey_New(frodokem_types[0], NULL, INVALID_DEVID);
    ExpectNotNull(key);
    /* Initialized: a size query on it succeeds and returns a non-zero size. */
    ExpectIntEQ(wc_FrodoKemKey_PublicKeySize(key, &pkLen), 0);
    ExpectIntGT(pkLen, 0);
    /* Delete frees the object and clears the caller's pointer. */
    ExpectIntEQ(wc_FrodoKemKey_Delete(key, &key), 0);
    ExpectNull(key);
#endif
    return EXPECT_RESULT();
}

/* A validly-formed type whose parameter set or A-generation method is not
 * compiled in must report NOT_COMPILED_IN (an ill-formed type is
 * BAD_FUNC_ARG). The compiled-variant list is the source of truth, so this
 * exercises the not-compiled path in single-variant / method-restricted builds
 * and is a self-consistent no-op when every variant is enabled. */
int test_wc_frodokem_not_compiled_in(void)
{
    EXPECT_DECLS;
#if defined(WOLFSSL_HAVE_FRODOKEM)
    /* All twelve validly-formed variant types. These are bit combinations,
     * always defined regardless of what is compiled in. */
    static const int allTypes[] = {
        WC_FRODOKEM_640_SHAKE, WC_FRODOKEM_976_SHAKE, WC_FRODOKEM_1344_SHAKE,
        WC_FRODOKEM_640_AES, WC_FRODOKEM_976_AES, WC_FRODOKEM_1344_AES,
        WC_EFRODOKEM_640_SHAKE, WC_EFRODOKEM_976_SHAKE, WC_EFRODOKEM_1344_SHAKE,
        WC_EFRODOKEM_640_AES, WC_EFRODOKEM_976_AES, WC_EFRODOKEM_1344_AES
    };
    FrodoKemKey* key = NULL;
    int i, j, compiled;

    key = (FrodoKemKey*)XMALLOC(sizeof(*key), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    ExpectNotNull(key);

    for (i = 0; (i < (int)(sizeof(allTypes) / sizeof(allTypes[0]))) &&
            EXPECT_SUCCESS(); i++) {
        /* Is this type one of the compiled-in variants? */
        compiled = 0;
        for (j = 0; j < FRODOKEM_TYPE_CNT; j++) {
            if (frodokem_types[j] == allTypes[i]) {
                compiled = 1;
                break;
            }
        }
        if (compiled) {
            /* A compiled variant initializes. */
            ExpectIntEQ(wc_FrodoKemKey_Init(key, allTypes[i], NULL,
                INVALID_DEVID), 0);
            wc_FrodoKemKey_Free(key);
        }
        else {
            /* A valid but not-compiled variant reports NOT_COMPILED_IN. */
            ExpectIntEQ(wc_FrodoKemKey_Init(key, allTypes[i], NULL,
                INVALID_DEVID), WC_NO_ERR_TRACE(NOT_COMPILED_IN));
        }
    }

    XFREE(key, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif
    return EXPECT_RESULT();
}
