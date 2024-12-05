/* wc_lms_impl.c
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

/* Implementation based on:
 *   RFC 8554: Leighton-Micali Hash-Based Signatures
 *   https://datatracker.ietf.org/doc/html/rfc8554
 * Implementation by Sean Parkinson.
 */

/* Possible LMS options:
 *
 * WC_LMS_FULL_HASH                                      Default: OFF
 *   Performs a full hash instead of assuming internals.
 *   Enable when using hardware SHA-256.
 * WOLFSSL_LMS_VERIFY_ONLY                               Default: OFF
 *   Only compiles in verification code.
 * WOLFSSL_WC_LMS_SMALL                                  Default: OFF
 *   Implementation is smaller code size with slow signing.
 *   Enable when memory is limited.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/wc_lms.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#if defined(WOLFSSL_HAVE_LMS) && defined(WOLFSSL_WC_LMS)

/* Length of R in bytes. */
#define LMS_R_LEN           4
/* Length of D in bytes. */
#define LMS_D_LEN           2
/* Length of checksum in bytes. */
#define LMS_CKSM_LEN        2

/* Predefined values used in hashes to make them unique. */
/* Fixed value for calculating x. */
#define LMS_D_FIXED         0xff
/* D value when computing public key. */
#define LMS_D_PBLC          0x8080
/* D value when computing message. */
#define LMS_D_MESG          0x8181
/* D value when computing leaf node. */
#define LMS_D_LEAF          0x8282
/* D value when computing interior node. */
#define LMS_D_INTR          0x8383
/* D value when computing C, randomizer value. */
#define LMS_D_C             0xfffd
/* D value when computing child SEED for private key. */
#define LMS_D_CHILD_SEED    0xfffe
/* D value when computing child I for private key. */
#define LMS_D_CHILD_I       0xffff

/* Length of data to hash when computing seed:
 *   16 + 4 + 2 + 32/24 = 54/46 */
#define LMS_SEED_HASH_LEN(hLen)     \
    (LMS_I_LEN + LMS_R_LEN + LMS_D_LEN + (hLen))

/* Length of data to hash when computing a node:
 *   16 + 4 + 2 + 32/24 + 32/24 = 86/70 */
#define LMS_NODE_HASH_LEN(hLen)     \
    (LMS_I_LEN + LMS_R_LEN + LMS_D_LEN + 2 * (hLen))

/* Length of data to hash when computing most results:
 *   16 + 4 + 2 + 1 + 32/24 = 55/47 */
#define LMS_HASH_BUFFER_LEN(hLen)   \
    (LMS_I_LEN + LMS_Q_LEN + LMS_P_LEN + LMS_W_LEN + (hLen))

/* Length of preliminary data to hash when computing K:
 *   16 + 4 + 2 = 22 */
#define LMS_K_PRE_LEN       (LMS_I_LEN + LMS_Q_LEN + LMS_P_LEN)

/* Length of preliminary data to hash when computing message hash:
 *   16 + 4 + 2 = 22 */
#define LMS_MSG_PRE_LEN     (LMS_I_LEN + LMS_Q_LEN + LMS_P_LEN)


#ifdef WC_LMS_DEBUG_PRINT_DATA
/* Print data when debugging implementation.
 *
 * @param [in] name  String to print before data.
 * @param [in] data  Array of bytes.
 * @param [in] len   Length of data in array.
 */
static void print_data(const char* name, const byte* data, int len)
{
    int i;

    fprintf(stderr, "%6s: ", name);
    for (i = 0; i < len; i++) {
        fprintf(stderr, "%02x", data[i]);
    }
    fprintf(stderr, "\n");
}
#endif

/***************************************
 * Index APIs
 **************************************/

#ifndef WOLFSSL_LMS_VERIFY_ONLY
/* Zero index.
 *
 * @param [out] a    Byte array. Big-endian encoding.
 * @param [in]  len  Length of array in bytes.
 */
static WC_INLINE void wc_lms_idx_zero(unsigned char* a, int len)
{
    XMEMSET(a, 0, len);
}

/* Increment big-endian value.
 *
 * @param [in, out] a    Byte array. Big-endian encoding.
 * @param [in]      len  Length of array in bytes.
 */
static WC_INLINE void wc_lms_idx_inc(unsigned char* a, int len)
{
    int i;

    /* Starting at least-significant byte up to most. */
    for (i = len - 1; i >= 0; i--) {
        /* Add one/carry to byte. */
        if ((++a[i]) != 0) {
            /* No more carry. */
            break;
        }
    }
}
#endif /* !WOLFSSL_LMS_VERIFY_ONLY */

/***************************************
 * Hash APIs
 **************************************/

/* Set hash data and length into SHA-256 digest.
 *
 * @param [in, out] state  SHA-256 digest object.
 * @param [in]      data   Data to add to hash.
 * @param [in]      len    Number of bytes in data. Must be less than a block.
 */
#define LMS_SHA256_SET_DATA(sha256, data, len)  \
do {                                            \
    XMEMCPY((sha256)->buffer, (data), (len));   \
    (sha256)->buffLen = (len);                  \
    (sha256)->loLen = (len);                    \
} while (0)

/* Add hash data and length into SHA-256 digest.
 *
 * @param [in, out] state  SHA-256 digest object.
 * @param [in]      data   Data to add to hash.
 * @param [in]      len    Number of bytes in data. Must be less than a block.
 */
#define LMS_SHA256_ADD_DATA(sha256, data, len)                              \
do {                                                                        \
    XMEMCPY((byte*)(sha256)->buffer + (sha256)->buffLen, (data), (len));    \
    (sha256)->buffLen += (len);                                             \
    (sha256)->loLen += (len);                                               \
} while (0)

/* Set the length of 54 bytes in buffer as per SHA-256 final operation.
 *
 * @param [in, out] buffer  Hash data buffer to add length to.
 */
#define LMS_SHA256_SET_LEN_54(buffer)   \
do {                                    \
    (buffer)[54] = 0x80;                \
    (buffer)[55] = 0x00;                \
    (buffer)[56] = 0x00;                \
    (buffer)[57] = 0x00;                \
    (buffer)[58] = 0x00;                \
    (buffer)[59] = 0x00;                \
    (buffer)[60] = 0x00;                \
    (buffer)[61] = 0x00;                \
    (buffer)[62] = 0x01;                \
    (buffer)[63] = 0xb0;                \
} while (0)

/* Set the length of 55 bytes in buffer as per SHA-256 final operation.
 *
 * @param [in, out] buffer  Hash data buffer to add length to.
 */
#define LMS_SHA256_SET_LEN_55(buffer)   \
do {                                    \
    (buffer)[55] = 0x80;                \
    (buffer)[56] = 0x00;                \
    (buffer)[57] = 0x00;                \
    (buffer)[58] = 0x00;                \
    (buffer)[59] = 0x00;                \
    (buffer)[60] = 0x00;                \
    (buffer)[61] = 0x00;                \
    (buffer)[62] = 0x01;                \
    (buffer)[63] = 0xb8;                \
} while (0)

#ifndef WOLFSSL_NO_LMS_SHA256_256
#ifndef WC_LMS_FULL_HASH
/* Hash one full block of data and compute result.
 *
 * @param [in]  sha256  SHA-256 hash object.
 * @param [in]  data    Data to hash.
 * @param [out] hash    Hash output.
 * @return  0 on success.
 */
static WC_INLINE int wc_lms_hash_block(wc_Sha256* sha256, const byte* data,
    byte* hash)
{
    /* Hash the block and reset SHA-256 state. */
    return wc_Sha256HashBlock(sha256, data, hash);
}
#endif /* !WC_LMS_FULL_HASH */

/* Hash data and compute result.
 *
 * @param [in]  sha256  SHA-256 hash object.
 * @param [in]  data    Data to hash.
 * @param [in]  len     Length of data to hash.
 * @param [out] hash    Hash output.
 * @return  0 on success.
 */
static WC_INLINE int wc_lms_hash(wc_Sha256* sha256, byte* data, word32 len,
    byte* hash)
{
    int ret;

#ifndef WC_LMS_FULL_HASH
    if (len < WC_SHA256_BLOCK_SIZE) {
        /* Store data into SHA-256 object's buffer. */
        LMS_SHA256_SET_DATA(sha256, data, len);
        ret = wc_Sha256Final(sha256, hash);
    }
    else if (len < WC_SHA256_BLOCK_SIZE + WC_SHA256_PAD_SIZE) {
        ret = wc_Sha256HashBlock(sha256, data, NULL);
        if (ret == 0) {
            byte* buffer = (byte*)sha256->buffer;
            int rem = len - WC_SHA256_BLOCK_SIZE;

            XMEMCPY(buffer, data + WC_SHA256_BLOCK_SIZE, rem);
            buffer[rem++] = 0x80;
            XMEMSET(buffer + rem, 0, WC_SHA256_BLOCK_SIZE - 2 - rem);
            buffer[WC_SHA256_BLOCK_SIZE - 2] = (byte)(len >> 5);
            buffer[WC_SHA256_BLOCK_SIZE - 1] = (byte)(len << 3);
            ret = wc_Sha256HashBlock(sha256, buffer, hash);
        }
    }
    else {
        ret = wc_Sha256Update(sha256, data, len);
        if (ret == 0) {
            ret = wc_Sha256Final(sha256, hash);
        }
    }
#else
    ret = wc_Sha256Update(sha256, data, len);
    if (ret == 0) {
        ret = wc_Sha256Final(sha256, hash);
    }
#endif /* !WC_LMS_FULL_HASH */

    return ret;
}
#endif /* !WOLFSSL_NO_LMS_SHA256_256 */

/* Update hash with first data.
 *
 * Sets the data directly into SHA-256's buffer if valid.
 *
 * @param [in]  sha256  SHA-256 hash object.
 * @param [in]  data    Data to hash.
 * @param [in]  len     Length of data to hash.
 * @return  0 on success.
 */
static WC_INLINE int wc_lms_hash_first(wc_Sha256* sha256, const byte* data,
    word32 len)
{
    int ret = 0;

#ifndef WC_LMS_FULL_HASH
    if (len < WC_SHA256_BLOCK_SIZE) {
        /* Store data into SHA-256 object's buffer. */
        LMS_SHA256_SET_DATA(sha256, data, len);
    }
    else
#endif /* !WC_LMS_FULL_HASH */
    {
        ret = wc_Sha256Update(sha256, data, len);
    }

    return ret;
}

/* Update hash with further data.
 *
 * Adds the data directly into SHA-256's buffer if valid.
 *
 * @param [in]  sha256  SHA-256 hash object.
 * @param [in]  data    Data to hash.
 * @param [in]  len     Length of data to hash.
 * @return  0 on success.
 */
static WC_INLINE int wc_lms_hash_update(wc_Sha256* sha256, const byte* data,
    word32 len)
{
    int ret = 0;

#ifndef WC_LMS_FULL_HASH
    if (sha256->buffLen + len < WC_SHA256_BLOCK_SIZE) {
        /* Add data to SHA-256 object's buffer. */
        LMS_SHA256_ADD_DATA(sha256, data, len);
    }
    else if (sha256->buffLen + len < 2 * WC_SHA256_BLOCK_SIZE) {
        byte* buffer = (byte*)sha256->buffer;

        XMEMCPY(buffer + sha256->buffLen, data,
            WC_SHA256_BLOCK_SIZE - sha256->buffLen);
        ret = wc_Sha256HashBlock(sha256, buffer, NULL);
        if (ret == 0) {
            int rem = len - (WC_SHA256_BLOCK_SIZE - sha256->buffLen);
            XMEMCPY(buffer, data + WC_SHA256_BLOCK_SIZE - sha256->buffLen, rem);
            sha256->buffLen = rem;
            sha256->loLen += len;
        }
    }
    else {
        ret = wc_Sha256Update(sha256, data, len);
    }
#else
    ret = wc_Sha256Update(sha256, data, len);
#endif /* !WC_LMS_FULL_HASH */

    return ret;
}

#ifndef WOLFSSL_NO_LMS_SHA256_256
/* Finalize hash.
 *
 * @param [in]  sha256  SHA-256 hash object.
 * @param [out] hash    Hash output.
 * @return  0 on success.
 */
static WC_INLINE int wc_lms_hash_final(wc_Sha256* sha256, byte* hash)
{
#ifndef WC_LMS_FULL_HASH
    int ret = 0;
    byte* buffer = (byte*)sha256->buffer;

    buffer[sha256->buffLen++] = 0x80;
    if (sha256->buffLen > WC_SHA256_PAD_SIZE) {
        XMEMSET(buffer + sha256->buffLen, 0,
            WC_SHA256_BLOCK_SIZE - sha256->buffLen);
        ret = wc_Sha256HashBlock(sha256, buffer, NULL);
        sha256->buffLen = 0;
    }
    if (ret == 0) {
        XMEMSET(buffer + sha256->buffLen, 0,
            WC_SHA256_BLOCK_SIZE - 8 - sha256->buffLen);
        sha256->hiLen = (sha256->hiLen << 3) + (sha256->loLen >> 29);
        sha256->loLen = sha256->loLen << 3;
    #ifdef LITTLE_ENDIAN_ORDER
        sha256->buffer[14] = ByteReverseWord32(sha256->hiLen);
        sha256->buffer[15] = ByteReverseWord32(sha256->loLen);
    #else
        sha256->buffer[14] = sha256->hiLen;
        sha256->buffer[15] = sha256->loLen;
    #endif
        ret = wc_Sha256HashBlock(sha256, buffer, hash);
        sha256->buffLen = 0;
        sha256->hiLen = 0;
        sha256->loLen = 0;
    }

    return ret;
#else
    return wc_Sha256Final(sha256, hash);
#endif
}
#endif /* !WOLFSSL_NO_LMS_SHA256_256 */

#ifdef WOLFSSL_LMS_SHA256_192
/* Set the length of 46 bytes in buffer as per SHA-256 final operation.
 *
 * @param [in, out] buffer  Hash data buffer to add length to.
 */
#define LMS_SHA256_SET_LEN_46(buffer)   \
do {                                    \
    (buffer)[46] = 0x80;                \
    (buffer)[47] = 0x00;                \
    (buffer)[48] = 0x00;                \
    (buffer)[49] = 0x00;                \
    (buffer)[50] = 0x00;                \
    (buffer)[51] = 0x00;                \
    (buffer)[52] = 0x00;                \
    (buffer)[53] = 0x00;                \
    (buffer)[54] = 0x00;                \
    (buffer)[55] = 0x00;                \
    (buffer)[56] = 0x00;                \
    (buffer)[57] = 0x00;                \
    (buffer)[58] = 0x00;                \
    (buffer)[59] = 0x00;                \
    (buffer)[60] = 0x00;                \
    (buffer)[61] = 0x00;                \
    (buffer)[62] = 0x01;                \
    (buffer)[63] = 0x70;                \
} while (0)

/* Set the length of 47 bytes in buffer as per SHA-256 final operation.
 *
 * @param [in, out] buffer  Hash data buffer to add length to.
 */
#define LMS_SHA256_SET_LEN_47(buffer)   \
do {                                    \
    (buffer)[47] = 0x80;                \
    (buffer)[48] = 0x00;                \
    (buffer)[49] = 0x00;                \
    (buffer)[50] = 0x00;                \
    (buffer)[51] = 0x00;                \
    (buffer)[52] = 0x00;                \
    (buffer)[53] = 0x00;                \
    (buffer)[54] = 0x00;                \
    (buffer)[55] = 0x00;                \
    (buffer)[56] = 0x00;                \
    (buffer)[57] = 0x00;                \
    (buffer)[58] = 0x00;                \
    (buffer)[59] = 0x00;                \
    (buffer)[60] = 0x00;                \
    (buffer)[61] = 0x00;                \
    (buffer)[62] = 0x01;                \
    (buffer)[63] = 0x78;                \
} while (0)

#ifndef WC_LMS_FULL_HASH
/* Hash one full block of data and compute result.
 *
 * @param [in]  sha256  SHA-256 hash object.
 * @param [in]  data    Data to hash.
 * @param [out] hash    Hash output.
 * @return  0 on success.
 */
static WC_INLINE int wc_lms_sha256_192_hash_block(wc_Sha256* sha256,
    const byte* data, byte* hash)
{
    int ret;
    unsigned char output[WC_SHA256_DIGEST_SIZE];

    /* Hash the block and reset SHA-256 state. */
    ret = wc_Sha256HashBlock(sha256, data, output);
    if (ret == 0) {
        XMEMCPY(hash, output, WC_SHA256_192_DIGEST_SIZE);
    }

    return ret;
}
#endif /* !WC_LMS_FULL_HASH */

/* Hash data and compute result.
 *
 * @param [in]  sha256  SHA-256 hash object.
 * @param [in]  data    Data to hash.
 * @param [in]  len     Length of data to hash.
 * @param [out] hash    Hash output.
 * @return  0 on success.
 */
static WC_INLINE int wc_lms_hash_sha256_192(wc_Sha256* sha256, byte* data,
    word32 len, byte* hash)
{
    int ret;
    unsigned char output[WC_SHA256_DIGEST_SIZE];

#ifndef WC_LMS_FULL_HASH
    if (len < WC_SHA256_BLOCK_SIZE) {
        /* Store data into SHA-256 object's buffer. */
        LMS_SHA256_SET_DATA(sha256, data, len);
        ret = wc_Sha256Final(sha256, output);
        if (ret == 0) {
            XMEMCPY(hash, output, WC_SHA256_192_DIGEST_SIZE);
        }
    }
    else if (len < WC_SHA256_BLOCK_SIZE + WC_SHA256_PAD_SIZE) {
        ret = wc_Sha256HashBlock(sha256, data, NULL);
        if (ret == 0) {
            byte* buffer = (byte*)sha256->buffer;
            int rem = len - WC_SHA256_BLOCK_SIZE;

            XMEMCPY(buffer, data + WC_SHA256_BLOCK_SIZE, rem);
            buffer[rem++] = 0x80;
            XMEMSET(buffer + rem, 0, WC_SHA256_BLOCK_SIZE - 2 - rem);
            buffer[WC_SHA256_BLOCK_SIZE - 2] = (byte)(len >> 5);
            buffer[WC_SHA256_BLOCK_SIZE - 1] = (byte)(len << 3);
            ret = wc_Sha256HashBlock(sha256, buffer, output);
            if (ret == 0) {
                XMEMCPY(hash, output, WC_SHA256_192_DIGEST_SIZE);
            }
        }
    }
    else {
        ret = wc_Sha256Update(sha256, data, len);
        if (ret == 0) {
            ret = wc_Sha256Final(sha256, output);
            if (ret == 0) {
                XMEMCPY(hash, output, WC_SHA256_192_DIGEST_SIZE);
            }
        }
    }
#else
    ret = wc_Sha256Update(sha256, data, len);
    if (ret == 0) {
        ret = wc_Sha256Final(sha256, output);
        if (ret == 0) {
            XMEMCPY(hash, output, WC_SHA256_192_DIGEST_SIZE);
        }
    }
#endif /* !WC_LMS_FULL_HASH */

    return ret;
}

/* Finalize hash.
 *
 * @param [in]  sha256  SHA-256 hash object.
 * @param [out] hash    Hash output.
 * @return  0 on success.
 */
static WC_INLINE int wc_lms_hash_sha256_192_final(wc_Sha256* sha256, byte* hash)
{
#ifndef WC_LMS_FULL_HASH
    int ret = 0;
    byte* buffer = (byte*)sha256->buffer;
    unsigned char output[WC_SHA256_DIGEST_SIZE];

    buffer[sha256->buffLen++] = 0x80;
    if (sha256->buffLen > WC_SHA256_PAD_SIZE) {
        XMEMSET(buffer + sha256->buffLen, 0,
            WC_SHA256_BLOCK_SIZE - sha256->buffLen);
        ret = wc_Sha256HashBlock(sha256, buffer, NULL);
        sha256->buffLen = 0;
    }
    if (ret == 0) {
        XMEMSET(buffer + sha256->buffLen, 0,
            WC_SHA256_BLOCK_SIZE - 8 - sha256->buffLen);
        sha256->hiLen = (sha256->hiLen << 3) + (sha256->loLen >> 29);
        sha256->loLen = sha256->loLen << 3;
    #ifdef LITTLE_ENDIAN_ORDER
        sha256->buffer[14] = ByteReverseWord32(sha256->hiLen);
        sha256->buffer[15] = ByteReverseWord32(sha256->loLen);
    #else
        sha256->buffer[14] = sha256->hiLen;
        sha256->buffer[15] = sha256->loLen;
    #endif
        ret = wc_Sha256HashBlock(sha256, buffer, output);
        if (ret == 0) {
            XMEMCPY(hash, output, WC_SHA256_192_DIGEST_SIZE);
        }
        sha256->buffLen = 0;
        sha256->hiLen = 0;
        sha256->loLen = 0;
    }

    return ret;
#else
    int ret;
    unsigned char output[WC_SHA256_DIGEST_SIZE];

    ret = wc_Sha256Final(sha256, output);
    if (ret == 0) {
        XMEMCPY(hash, output, WC_SHA256_192_DIGEST_SIZE);
    }

    return ret;
#endif
}
#endif /* WOLFSSL_LMS_SHA256_192 */

/***************************************
 * LM-OTS APIs
 **************************************/

/* Expand Q to and array of Winternitz width bits values plus checksum.
 *
 * Supported Winternitz widths: 8, 4, 2, 1.
 *
 * Algorithm 2: Checksum Calculation
 *   sum = 0
 *   for ( i = 0; i < (n*8/w); i = i + 1 ) {
 *     sum = sum + (2^w - 1) - coef(S, i, w)
 *   }
 *   return (sum << ls)
 * Section 3.1.3: Strings of w-Bit Elements
 *   coef(S, i, w) = (2^w - 1) AND
 *                   ( byte(S, floor(i * w / 8)) >>
 *                     (8 - (w * (i % (8 / w)) + w)) )
 * Combine coefficient expansion with checksum calculation.
 *
 * @param [in]  q   Q array of bytes.
 * @param [in]  n   Number of bytes in Q.
 * @param [in]  w   Winternitz width in bits.
 * @param [in]  ls  Left shift of checksum.
 * @param [out] qe  Expanded Q with checksum.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when Winternitz width is not supported.
 */
static WC_INLINE int wc_lmots_q_expand(byte* q, word8 n, word8 w, word8 ls,
    byte* qe)
{
    int ret = 0;
    word16 sum;
    unsigned int i;

#ifndef WOLFSSL_WC_LMS_SMALL
    switch (w) {
        /* Winternitz width of 8. */
        case 8:
            /* No expansion required, just copy. */
            XMEMCPY(qe, q, n);
            /* Start sum with all 2^w - 1s and subtract from that. */
            sum = 0xff * n;
            /* For each byte of the hash. */
            for (i = 0; i < n; i++) {
                /* Subtract coefficient from sum. */
                sum -= q[i];
            }
            /* Put coefficients of checksum on the end. */
            qe[n + 0] = (word8)(sum >> 8);
            qe[n + 1] = (word8)(sum     );
            break;
        /* Winternitz width of 4. */
        case 4:
            sum = 2 * 0xf * n;
            /* For each byte of the hash. */
            for (i = 0; i < n; i++) {
                /* Get coefficient. */
                qe[0] = (q[i] >> 4)      ;
                qe[1] = (q[i]     ) & 0xf;
                /* Subtract coefficients from sum. */
                sum -= qe[0];
                sum -= qe[1];
                /* Move to next coefficients. */
                qe += 2;
            }
            /* Put coefficients of checksum on the end. */
            qe[0] = (word8)((sum >> 8) & 0xf);
            qe[1] = (word8)((sum >> 4) & 0xf);
            qe[2] = (word8)((sum     ) & 0xf);
            break;
        /* Winternitz width of 2. */
        case 2:
            sum = 4 * 0x3 * n;
            /* For each byte of the hash. */
            for (i = 0; i < n; i++) {
                /* Get coefficients. */
                qe[0] = (q[i] >> 4)      ;
                qe[0] = (q[i] >> 6)      ;
                qe[1] = (q[i] >> 4) & 0x3;
                qe[2] = (q[i] >> 2) & 0x3;
                qe[3] = (q[i]     ) & 0x3;
                /* Subtract coefficients from sum. */
                sum -= qe[0];
                sum -= qe[1];
                sum -= qe[2];
                sum -= qe[3];
                /* Move to next coefficients. */
                qe += 4;
            }
            /* Put coefficients of checksum on the end. */
            qe[0] = (word8)((sum >>  8) & 0x3);
            qe[1] = (word8)((sum >>  6) & 0x3);
            qe[2] = (word8)((sum >>  4) & 0x3);
            qe[3] = (word8)((sum >>  2) & 0x3);
            qe[4] = (word8)((sum      ) & 0x3);
            break;
        /* Winternitz width of 1. */
        case 1:
            sum = 8 * 0x01 * n;
            /* For each byte of the hash. */
            for (i = 0; i < n; i++) {
                /* Get coefficients. */
                qe[0] = (q[i] >> 4)      ;
                qe[0] = (q[i] >> 7)      ;
                qe[1] = (q[i] >> 6) & 0x1;
                qe[2] = (q[i] >> 5) & 0x1;
                qe[3] = (q[i] >> 4) & 0x1;
                qe[4] = (q[i] >> 3) & 0x1;
                qe[5] = (q[i] >> 2) & 0x1;
                qe[6] = (q[i] >> 1) & 0x1;
                qe[7] = (q[i]     ) & 0x1;
                /* Subtract coefficients from sum. */
                sum -= qe[0];
                sum -= qe[1];
                sum -= qe[2];
                sum -= qe[3];
                sum -= qe[4];
                sum -= qe[5];
                sum -= qe[6];
                sum -= qe[7];
                /* Move to next coefficients. */
                qe += 8;
            }
            /* Put coefficients of checksum on the end. */
            qe[0] = (word8)((sum >>  8)      );
            qe[1] = (word8)((sum >>  7) & 0x1);
            qe[2] = (word8)((sum >>  6) & 0x1);
            qe[3] = (word8)((sum >>  5) & 0x1);
            qe[4] = (word8)((sum >>  4) & 0x1);
            qe[5] = (word8)((sum >>  3) & 0x1);
            qe[6] = (word8)((sum >>  2) & 0x1);
            qe[7] = (word8)((sum >>  1) & 0x1);
            qe[8] = (word8)((sum      ) & 0x1);
            break;
        default:
            ret = BAD_FUNC_ARG;
            break;
    }

    (void)ls;
#else
    int j;

    if ((w != 8) && (w != 4) && (w != 2) && (w != 1)) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        /* Start sum with all 2^w - 1s and subtract from that. */
        sum = ((1 << w) - 1) * ((n * 8) / w);
        /* For each byte of the hash. */
        for (i = 0; i < n; i++) {
            /* Get next byte. */
            byte a = *(q++);
            /* For each width bits of byte. */
            for (j = 8 - w; j >= 0; j -= w) {
                /* Get coefficient. */
                *qe = a >> (8 - w);
                /* Subtract coefficient from sum. */
                sum -= *qe;
                /* Move to next coefficient. */
                qe++;
                /* Remove width bits. */
                a <<= w;
            }
        }
        /* Shift sum up as required to pack it on the end of hash. */
        sum <<= ls;
        /* For each width buts of checksum. */
        for (j = 16 - w; j >= ls; j--) {
            /* Get coefficient. */
            *(qe++) = sum >> (16 - w);
            /* Remove width bits. */
            sum <<= w;
        }
    }
#endif /* !WOLFSSL_WC_LMS_SMALL */

    return ret;
}

/* Calculate the hash for the message.
 *
 * Algorithm 3: Generating a One-Time Signature From a Private Key and a
 * Message
 *   ...
 *   5. Compute the array y as follows:
 *      Q = H(I || u32str(q) || u16str(D_MESG) || C || message)
 * Algorithm 4b: Computing a Public Key Candidate Kc from a Signature,
 * Message, Signature Typecode pubtype, and Identifiers I, q
 *   ...
 *   3. Compute the string Kc as follows:
 *      Q = H(I || u32str(q) || u16str(D_MESG) || C || message)
 *
 * @param [in, out]  state  LMS state.
 * @param [in]       msg    Message to hash.
 * @param [in]       msgSz  Length of message in bytes.
 * @param [in]       c      C or randomizer value.
 * @param [out]      q      Computed Q value.
 * @return  0 on success.
 */
static int wc_lmots_msg_hash(LmsState* state, const byte* msg, word32 msgSz,
    const byte* c, byte* q)
{
    int ret;
    byte* buffer = state->buffer;
    byte* ip = buffer + LMS_I_LEN + LMS_Q_LEN;

    /* I || u32str(q) || u16str(D_MESG) */
    c16toa(LMS_D_MESG, ip);
    /* H(I || u32str(q) || u16str(D_MESG) || ...) */
    ret = wc_lms_hash_first(&state->hash, buffer, LMS_MSG_PRE_LEN);
    if (ret == 0) {
        /* H(... || C || ...) */
        ret = wc_lms_hash_update(&state->hash, c, state->params->hash_len);
    }
    if (ret == 0) {
        /* H(... || message) */
        ret = wc_lms_hash_update(&state->hash, msg, msgSz);
    }
#ifdef WOLFSSL_LMS_SHA256_192
    if ((ret == 0) &&
            ((state->params->lmOtsType & LMS_HASH_MASK) == LMS_SHA256_192)) {
        /* Q = H(...) */
        ret = wc_lms_hash_sha256_192_final(&state->hash, q);
    }
    else
#endif
#ifndef WOLFSSL_NO_LMS_SHA256_256
    if (ret == 0) {
        /* Q = H(...) */
        ret = wc_lms_hash_final(&state->hash, q);
    }
    else
#endif
    {
        ret = NOT_COMPILED_IN;
    }

    return ret;
}

#ifndef WOLFSSL_LMS_VERIFY_ONLY
/* Compute array y, intermediates of public key calculation, for signature.
 *
 * Verification will perform the remaining iterations of hashing.
 *
 * Algorithm 3: Generating a One-Time Signature From a Private Key and a
 * Message
 *   ...
 *   5. Compute the array y as follows:
 *      Q = H(I || u32str(q) || u16str(D_MESG) || C || message)
 *      for ( i = 0; i < p; i = i + 1 ) {
 *        a = coef(Q || Cksm(Q), i, w)
 *        tmp = x[i]
 *        for ( j = 0; j < a; j = j + 1 ) {
 *          tmp = H(I || u32str(q) || u16str(i) || u8str(j) || tmp)
 *        }
 *        y[i] = tmp
 *      }
 * x[i] can be calculated on the fly using pseudo key generation in Appendix A.
 * Appendix A, The elements of the LM-OTS private keys are computed as:
 *   x_q[i] = H(I || u32str(q) || u16str(i) || u8str(0xff) || SEED).
 *
 * @param [in, out]  state  LMS state.
 * @param [in]       seed   Seed to hash.
 * @param [in]       msg    Message to sign.
 * @param [in]       msgSZ  Length of message in bytes.
 * @param [in]       c      C or randomizer value to hash.
 * @param [out]      y      Calculated intermediate hashes.
 * @return  0 on success.
 */
static int wc_lmots_compute_y_from_seed(LmsState* state, const byte* seed,
    const byte* msg, word32 msgSz, const byte* c, byte* y)
{
    const LmsParams* params = state->params;
    int ret;
    word16 i;
    byte q[LMS_MAX_NODE_LEN + LMS_CKSM_LEN];
#ifdef WOLFSSL_SMALL_STACK
    byte* a = state->a;
#else
    byte a[LMS_MAX_P];
#endif /* WOLFSSL_SMALL_STACK */
    byte* buffer = state->buffer;
    byte* ip = buffer + LMS_I_LEN + LMS_Q_LEN;
    byte* jp = ip + LMS_P_LEN;
    byte* tmp = jp + LMS_W_LEN;

    /* Q = H(I || u32str(q) || u16str(D_MESG) || C || message) */
    ret = wc_lmots_msg_hash(state, msg, msgSz, c, q);
    if (ret == 0) {
        /* Calculate checksum list all coefficients. */
        ret = wc_lmots_q_expand(q, (word8)params->hash_len, params->width,
            params->ls, a);
    }
#ifndef WC_LMS_FULL_HASH
    if (ret == 0) {
    #ifdef WOLFSSL_LMS_SHA256_192
        if ((params->lmOtsType & LMS_HASH_MASK) == LMS_SHA256_192) {
            /* Put in padding for final block. */
            LMS_SHA256_SET_LEN_47(buffer);
        }
        else
    #endif
        {
        #ifndef WOLFSSL_NO_LMS_SHA256_256
            /* Put in padding for final block. */
            LMS_SHA256_SET_LEN_55(buffer);
        #endif
        }
    }
#endif /* !WC_LMS_FULL_HASH */

    /* Compute y for each coefficient. */
    for (i = 0; (ret == 0) && (i < params->p); i++) {
        unsigned int j;

        /* tmp = x[i]
         *     = H(I || u32str(q) || u16str(i) || u8str(0xff) || SEED). */
        c16toa(i, ip);
        *jp = LMS_D_FIXED;
#ifndef WC_LMS_FULL_HASH
    #ifdef WOLFSSL_LMS_SHA256_192
        if ((params->lmOtsType & LMS_HASH_MASK) == LMS_SHA256_192) {
            XMEMCPY(tmp, seed, WC_SHA256_192_DIGEST_SIZE);
            ret = wc_lms_sha256_192_hash_block(&state->hash, buffer, tmp);
        }
        else
    #endif
        {
        #ifndef WOLFSSL_NO_LMS_SHA256_256
            XMEMCPY(tmp, seed, WC_SHA256_DIGEST_SIZE);
            ret = wc_lms_hash_block(&state->hash, buffer, tmp);
        #else
            ret = NOT_COMPILED_IN;
        #endif
        }
#else
    #ifdef WOLFSSL_LMS_SHA256_192
        if ((params->lmOtsType & LMS_HASH_MASK) == LMS_SHA256_192) {
            XMEMCPY(tmp, seed, WC_SHA256_192_DIGEST_SIZE);
            ret = wc_lms_hash_sha256_192(&state->hash, buffer,
                LMS_HASH_BUFFER_LEN(WC_SHA256_192_DIGEST_SIZE), tmp);
        }
        else
    #endif
        {
        #ifndef WOLFSSL_NO_LMS_SHA256_256
            XMEMCPY(tmp, seed, WC_SHA256_DIGEST_SIZE);
            ret = wc_lms_hash(&state->hash, buffer,
                LMS_HASH_BUFFER_LEN(WC_SHA256_DIGEST_SIZE), tmp);
        #else
            ret = NOT_COMPILED_IN;
        #endif
        }
#endif /* !WC_LMS_FULL_HASH */

        /* Apply the hash function coefficient number of times. */
        for (j = 0; (ret == 0) && (j < a[i]); j++) {
            /* I || u32str(q) || u16str(i) || u8str(j) || tmp */
            *jp = j;
            /* tmp = H(I || u32str(q) || u16str(i) || u8str(j) || tmp) */
    #ifndef WC_LMS_FULL_HASH
        #ifdef WOLFSSL_LMS_SHA256_192
            if ((params->lmOtsType & LMS_HASH_MASK) == LMS_SHA256_192) {
                ret = wc_lms_sha256_192_hash_block(&state->hash, buffer, tmp);
            }
            else
        #endif
            {
            #ifndef WOLFSSL_NO_LMS_SHA256_256
                ret = wc_lms_hash_block(&state->hash, buffer, tmp);
            #else
                ret = NOT_COMPILED_IN;
            #endif
            }
    #else
        #ifdef WOLFSSL_LMS_SHA256_192
            if ((params->lmOtsType & LMS_HASH_MASK) == LMS_SHA256_192) {
                ret = wc_lms_hash_sha256_192(&state->hash, buffer,
                    LMS_HASH_BUFFER_LEN(WC_SHA256_192_DIGEST_SIZE), tmp);
            }
            else
        #endif
            {
            #ifndef WOLFSSL_NO_LMS_SHA256_256
                ret = wc_lms_hash(&state->hash, buffer,
                    LMS_HASH_BUFFER_LEN(WC_SHA256_DIGEST_SIZE), tmp);
            #else
                ret = NOT_COMPILED_IN;
            #endif
            }
    #endif /* !WC_LMS_FULL_HASH */
        }

        if (ret == 0) {
            /* y[i] = tmp */
            XMEMCPY(y, tmp, params->hash_len);
            y += params->hash_len;
        }
    }

    return ret;
}
#endif /* !WOLFSSL_LMS_VERIFY_ONLY */

/* Compute public key candidate K from signature.
 *
 * Signing performed the first coefficient number of iterations of hashing.
 *
 * Algorithm 4b: Computing a Public Key Candidate Kc from a Signature,
 * Message, Signature Typecode pubtype, and Identifiers I, q
 *   ...
 *   3. Compute the string Kc as follows:
 *      Q = H(I || u32str(q) || u16str(D_MESG) || C || message)
 *      for ( i = 0; i < p; i = i + 1 ) {
 *        a = coef(Q || Cksm(Q), i, w)
 *        tmp = y[i]
 *        for ( j = a; j < 2^w - 1; j = j + 1 ) {
 *          tmp = H(I || u32str(q) || u16str(i) || u8str(j) || tmp)
 *        }
 *        z[i] = tmp
 *      }
 *      Kc = H(I || u32str(q) || u16str(D_PBLC) ||
 *                                    z[0] || z[1] || ... || z[p-1])
 *   4, Return Kc.
 *
 * @param [in, out] state  LMS state.
 * @param [in]      msg    Message to compute Kc for.
 * @param [in]      msgSz  Length of message in bytes.
 * @param [in]      c      C or randomizer value from signature.
 * @param [in]      sig_y  Part of signature containing array y.
 * @param [out]     kc     Kc or public key candidate K.
 * @return  0 on success.
 */
static int wc_lmots_compute_kc_from_sig(LmsState* state, const byte* msg,
    word32 msgSz, const byte* c, const byte* sig_y, byte* kc)
{
    const LmsParams* params = state->params;
    int ret;
    word16 i;
    byte q[LMS_MAX_NODE_LEN + LMS_CKSM_LEN];
#ifdef WOLFSSL_SMALL_STACK
    byte* a = state->a;
#else
    byte a[LMS_MAX_P];
#endif /* WOLFSSL_SMALL_STACK */
    byte* buffer = state->buffer;
    byte* ip = buffer + LMS_I_LEN + LMS_Q_LEN;
    byte* jp = ip + LMS_P_LEN;
    byte* tmp = jp + LMS_W_LEN;
    unsigned int max = ((unsigned int)1 << params->width) - 1;

    /* I || u32str(q) || u16str(D_PBLC). */
    c16toa(LMS_D_PBLC, ip);
    /* H(I || u32str(q) || u16str(D_PBLC) || ...). */
    ret = wc_lms_hash_first(&state->hash_k, buffer, LMS_K_PRE_LEN);
    if (ret == 0) {
        /* Q = H(I || u32str(q) || u16str(D_MESG) || C || message) */
        ret = wc_lmots_msg_hash(state, msg, msgSz, c, q);
    }
    if (ret == 0) {
        /* Calculate checksum list all coefficients. */
        ret = wc_lmots_q_expand(q, (word8)params->hash_len, params->width,
            params->ls, a);
    }
#ifndef WC_LMS_FULL_HASH
    if (ret == 0) {
    #ifdef WOLFSSL_LMS_SHA256_192
        if ((params->lmOtsType & LMS_HASH_MASK) == LMS_SHA256_192) {
            /* Put in padding for final block. */
            LMS_SHA256_SET_LEN_47(buffer);
        }
        else
    #endif
        {
        #ifndef WOLFSSL_NO_LMS_SHA256_256
            /* Put in padding for final block. */
            LMS_SHA256_SET_LEN_55(buffer);
        #endif
        }
    }
#endif /* !WC_LMS_FULL_HASH */

    /* Compute z for each coefficient. */
    for (i = 0; (ret == 0) && (i < params->p); i++) {
        unsigned int j;

        /* I || u32(str) || u16str(i) || ... */
        c16toa(i, ip);

        /* tmp = y[i].
         * I || u32(str) || u16str(i) || ... || tmp */
        XMEMCPY(tmp, sig_y, params->hash_len);
        sig_y += params->hash_len;

        /* Finish iterations of hash from coefficient to max. */
        for (j = a[i]; (ret == 0) && (j < max); j++) {
            /* I || u32str(q) || u16str(i) || u8str(j) || tmp */
            *jp = (word8)j;
            /* tmp = H(I || u32str(q) || u16str(i) || u8str(j) || tmp) */
    #ifndef WC_LMS_FULL_HASH
        #ifdef WOLFSSL_LMS_SHA256_192
            if ((params->lmOtsType & LMS_HASH_MASK) == LMS_SHA256_192) {
                ret = wc_lms_sha256_192_hash_block(&state->hash, buffer, tmp);
            }
            else
        #endif
            {
            #ifndef WOLFSSL_NO_LMS_SHA256_256
                ret = wc_lms_hash_block(&state->hash, buffer, tmp);
            #else
                ret = NOT_COMPILED_IN;
            #endif
            }
            /* Apply the hash function coefficient number of times. */
    #else
        #ifdef WOLFSSL_LMS_SHA256_192
            if ((params->lmOtsType & LMS_HASH_MASK) == LMS_SHA256_192) {
                ret = wc_lms_hash_sha256_192(&state->hash, buffer,
                    LMS_HASH_BUFFER_LEN(WC_SHA256_192_DIGEST_SIZE), tmp);
            }
            else
        #endif
            {
            #ifndef WOLFSSL_NO_LMS_SHA256_256
                ret = wc_lms_hash(&state->hash, buffer,
                    LMS_HASH_BUFFER_LEN(WC_SHA256_DIGEST_SIZE), tmp);
            #else
                ret = NOT_COMPILED_IN;
            #endif
            }
    #endif /* !WC_LMS_FULL_HASH */
        }

        if (ret == 0) {
            /* H(... || z[i] || ...) (for calculating Kc). */
            ret = wc_lms_hash_update(&state->hash_k, tmp, params->hash_len);
        }
    }

#ifdef WOLFSSL_LMS_SHA256_192
    if ((ret == 0) &&
            ((params->lmOtsType & LMS_HASH_MASK) == LMS_SHA256_192)) {
        /* Kc = H(...) */
        ret = wc_lms_hash_sha256_192_final(&state->hash_k, kc);
    }
    else
#endif
    if (ret == 0) {
    #ifndef WOLFSSL_NO_LMS_SHA256_256
        /* Kc = H(...) */
        ret = wc_lms_hash_final(&state->hash_k, kc);
    #else
        ret = NOT_COMPILED_IN;
    #endif
    }

    return ret;
}

#ifndef WOLFSSL_LMS_VERIFY_ONLY
/* Generate LM-OTS public key.
 *
 * Caller set: state->buffer = I || u32str(q)
 *
 * Algorithm 1: Generating a One-Time Signature Public Key From a Private Key
 *   ...
 *   4. Compute the string K as follows:
 *      for ( i = 0; i < p; i = i + 1 ) {
 *        tmp = x[i]
 *        for ( j = 0; j < 2^w - 1; j = j + 1 ) {
 *          tmp = H(I || u32str(q) || u16str(i) || u8str(j) || tmp)
 *        }
 *        y[i] = tmp
 *      }
 *      K = H(I || u32str(q) || u16str(D_PBLC) || y[0] || ... || y[p-1])
 *   ...
 * x[i] can be calculated on the fly using pseudo key generation in Appendix A.
 * Appendix A, The elements of the LM-OTS private keys are computed as:
 *   x_q[i] = H(I || u32str(q) || u16str(i) || u8str(0xff) || SEED).
 *
 * @param [in, out]  state   LMS state.
 * @param [in]       seed    Seed to hash.
 * @param [out]      k       K, the public key hash, or OTS_PUB_HASH
 */
static int wc_lmots_make_public_hash(LmsState* state, const byte* seed, byte* k)
{
    const LmsParams* params = state->params;
    int ret;
    word16 i;
    byte* buffer = state->buffer;
    byte* ip = buffer + LMS_I_LEN + LMS_Q_LEN;
    byte* jp = ip + LMS_P_LEN;
    byte* tmp = jp + LMS_W_LEN;
    unsigned int max = ((unsigned int)1 << params->width) - 1;

    /* I || u32str(q) || u16str(D_PBLC). */
    c16toa(LMS_D_PBLC, ip);
    /* K = H(I || u32str(q) || u16str(D_PBLC) || ...) */
    ret = wc_lms_hash_first(&state->hash_k, buffer, LMS_K_PRE_LEN);

#ifndef WC_LMS_FULL_HASH
#ifdef WOLFSSL_LMS_SHA256_192
    if ((params->lmOtsType & LMS_HASH_MASK) == LMS_SHA256_192) {
        /* Put in padding for final block. */
        LMS_SHA256_SET_LEN_47(buffer);
    }
    else
#endif
    {
    #ifndef WOLFSSL_NO_LMS_SHA256_256
        /* Put in padding for final block. */
        LMS_SHA256_SET_LEN_55(buffer);
    #endif
    }
#endif /* !WC_LMS_FULL_HASH */

    for (i = 0; (ret == 0) && (i < params->p); i++) {
        unsigned int j;

        /* tmp = x[i]
         *     = H(I || u32str(q) || u16str(i) || u8str(0xff) || SEED). */
        c16toa(i, ip);
        *jp = LMS_D_FIXED;
#ifndef WC_LMS_FULL_HASH
    #ifdef WOLFSSL_LMS_SHA256_192
        if ((params->lmOtsType & LMS_HASH_MASK) == LMS_SHA256_192) {
            XMEMCPY(tmp, seed, WC_SHA256_192_DIGEST_SIZE);
            ret = wc_lms_sha256_192_hash_block(&state->hash, buffer, tmp);
        }
        else
    #endif
        {
        #ifndef WOLFSSL_NO_LMS_SHA256_256
            XMEMCPY(tmp, seed, WC_SHA256_DIGEST_SIZE);
            ret = wc_lms_hash_block(&state->hash, buffer, tmp);
        #else
            ret = NOT_COMPILED_IN;
        #endif
        }
#else
    #ifdef WOLFSSL_LMS_SHA256_192
        if ((params->lmOtsType & LMS_HASH_MASK) == LMS_SHA256_192) {
            XMEMCPY(tmp, seed, WC_SHA256_192_DIGEST_SIZE);
            ret = wc_lms_hash_sha256_192(&state->hash, buffer,
                LMS_HASH_BUFFER_LEN(WC_SHA256_192_DIGEST_SIZE), tmp);
        }
        else
    #endif
        {
        #ifndef WOLFSSL_NO_LMS_SHA256_256
            XMEMCPY(tmp, seed, WC_SHA256_DIGEST_SIZE);
            ret = wc_lms_hash(&state->hash, buffer,
                LMS_HASH_BUFFER_LEN(WC_SHA256_DIGEST_SIZE), tmp);
        #else
            ret = NOT_COMPILED_IN;
        #endif
        }
#endif /* !WC_LMS_FULL_HASH */
        /* Do all iterations to calculate y. */
        for (j = 0; (ret == 0) && (j < max); j++) {
            /* I || u32str(q) || u16str(i) || u8str(j) || tmp */
            *jp = (word8)j;
            /* tmp = H(I || u32str(q) || u16str(i) || u8str(j) || tmp) */
    #ifndef WC_LMS_FULL_HASH
        #ifdef WOLFSSL_LMS_SHA256_192
            if ((params->lmOtsType & LMS_HASH_MASK) == LMS_SHA256_192) {
                ret = wc_lms_sha256_192_hash_block(&state->hash, buffer, tmp);
            }
            else
        #endif
            {
            #ifndef WOLFSSL_NO_LMS_SHA256_256
                ret = wc_lms_hash_block(&state->hash, buffer, tmp);
            #else
                ret = NOT_COMPILED_IN;
            #endif
            }
    #else
        #ifdef WOLFSSL_LMS_SHA256_192
            if ((params->lmOtsType & LMS_HASH_MASK) == LMS_SHA256_192) {
                ret = wc_lms_hash_sha256_192(&state->hash, buffer,
                    LMS_HASH_BUFFER_LEN(WC_SHA256_192_DIGEST_SIZE), tmp);
            }
            else
        #endif
            {
            #ifndef WOLFSSL_NO_LMS_SHA256_256
                ret = wc_lms_hash(&state->hash, buffer,
                    LMS_HASH_BUFFER_LEN(WC_SHA256_DIGEST_SIZE), tmp);
            #else
                ret = NOT_COMPILED_IN;
            #endif
            }
    #endif /* !WC_LMS_FULL_HASH */
        }
        if (ret == 0) {
            /* K = H(... || y[i] || ...) */
            ret = wc_lms_hash_update(&state->hash_k, tmp, params->hash_len);
        }
    }
#ifdef WOLFSSL_LMS_SHA256_192
    if ((ret == 0) && ((params->lmOtsType & LMS_HASH_MASK) == LMS_SHA256_192)) {
        /* K = H(I || u32str(q) || u16str(D_PBLC) || y[0] || ... || y[p-1]) */
        ret = wc_lms_hash_sha256_192_final(&state->hash_k, k);
    }
    else
#endif
    if (ret == 0) {
    #ifndef WOLFSSL_NO_LMS_SHA256_256
        /* K = H(I || u32str(q) || u16str(D_PBLC) || y[0] || ... || y[p-1]) */
        ret = wc_lms_hash_final(&state->hash_k, k);
    #else
        ret = NOT_COMPILED_IN;
    #endif
    }

    return ret;
}

/* Encode the LM-OTS public key.
 *
 * Encoded into public key and signature if more than one level.
 * T[1] is already in place. Putting in: type, ostype and I.
 *
 * Section 4.3:
 *   u32str(type) || u32str(otstype) || I || T[1]
 *
 * @param [in]  params  LMS parameters.
 * @param [in]  priv    LMS private ley.
 * @param [out] pub     LMS public key.
 */
static void wc_lmots_public_key_encode(const LmsParams* params,
    const byte* priv, byte* pub)
{
    const byte* priv_i = priv + LMS_Q_LEN + params->hash_len;

    /* u32str(type) || ... || T(1) */
    c32toa(params->lmsType, pub);
    pub += 4;
    /* u32str(type) || u32str(otstype) || ... || T(1) */
    c32toa(params->lmOtsType, pub);
    pub += 4;
    /* u32str(type) || u32str(otstype) || I || T(1) */
    XMEMCPY(pub, priv_i, LMS_I_LEN);
}
#endif /* !WOLFSSL_LMS_VERIFY_ONLY */

/* Check the public key matches the parameters.
 *
 * @param [in] params  LMS parameters.
 * @param [in] pub     Public key.
 * @return  0 on success.
 * @return  PUBLIC_KEY_E when LMS or LM-OTS type doesn't match.
 */
static int wc_lmots_public_key_check(const LmsParams* params, const byte* pub)
{
    int ret = 0;
    word32 type;

    /* Get message hash and height type. */
    ato32(pub, &type);
    pub += 4;
    /* Compare with parameters. */
    if (type != params->lmsType) {
        ret = PUBLIC_KEY_E;
    }
    if (ret == 0) {
        /* Get node hash and Winternitz width type. */
        ato32(pub, &type);
        /* Compare with parameters. */
        if (type != params->lmOtsType) {
            ret = PUBLIC_KEY_E;
        }
    }

    return ret;
}

/* Calculate public key candidate K from signature.
 *
 * Algorithm 4b: Computing a Public Key Candidate Kc from a Signature,
 * Message, Signature Typecode pubtype, and Identifiers I, q
 *   ...
 *   2. Parse sigtype, C, and y from the signature as follows:
 *      a. sigtype = strTou32(first 4 bytes of signature)
 *      b. If sigtype is not equal to pubtype, return INVALID.
 *      ...
 *      d. C = next n bytes of signature
 *      e.   y[0] = next n bytes of signature
 *           y[1] = next n bytes of signature
 *           ...
 *         y[p-1] = next n bytes of signature
 *   3. Compute the string Kc as follows:
 *   ...
 *
 * @param [in, out] state  LMS state.
 * @param [in]      pub    LMS public key.
 * @param [in]      msg    Message/next private key to verify.
 * @param [in]      msgSz  Length of message in bytes.
 * @param [in]      sig    Signature including type, C and y[0..p-1].
 * @param [out]     kc     Public key candidate Kc.
 */
static int wc_lmots_calc_kc(LmsState* state, const byte* pub, const byte* msg,
    word32 msgSz, const byte* sig, byte* kc)
{
    int ret = 0;

    /* Check signature type. */
    if (XMEMCMP(pub, sig, LMS_TYPE_LEN) != 0) {
        ret = SIG_TYPE_E;
    }
    if (ret == 0) {
        /* Get C or randomizer value from signature. */
        const byte* c = sig + LMS_TYPE_LEN;
        /* Get array y from signature. */
        const byte* y = c + state->params->hash_len;

        /* Compute the public key candidate Kc from the signature. */
        ret = wc_lmots_compute_kc_from_sig(state, msg, msgSz, c, y, kc);
    }

    return ret;
}

#ifndef WOLFSSL_LMS_VERIFY_ONLY
/* Generate LM-OTS private key.
 *
 * Algorithm 5: Computing an LMS Private Key
 * But use Appendix A to generate x on the fly.
 *   PRIV = SEED | I
 *
 * @param [in]  rng       Random number generator.
 * @param [in]  seed_len  Length of seed to generate.
 * @param [out] priv      Private key data.
 */
static int wc_lmots_make_private_key(WC_RNG* rng, word16 seed_len, byte* priv)
{
    return wc_RNG_GenerateBlock(rng, priv, seed_len + LMS_I_LEN);
}

/* Generate LM-OTS signature.
 *
 * Algorithm 3: Generating a One-Time Signature From a Private Key and a
 * Message
 *   ...
 *   4. Set C to a uniformly random n-byte string
 *   5. Compute the array y as follows:
 *      ...
 *   6. Return u32str(type) || C || y[0] || ... || y[p-1]
 *
 * @param [in, out] state  LMS state.
 * @param [in]      seed   Private key seed.
 * @param [in]      msg    Message to be signed.
 * @param [in]      msgSz  Length of message in bytes.
 * @param [out]     sig    Signature buffer.
 * @return  0 on success.
 */
static int wc_lmots_sign(LmsState* state, const byte* seed, const byte* msg,
    word32 msgSz, byte* sig)
{
    int ret;
    byte* buffer = state->buffer;
    byte* ip = buffer + LMS_I_LEN + LMS_Q_LEN;
    byte* jp = ip + LMS_P_LEN;
    byte* tmp = jp + LMS_W_LEN;
    byte* sig_c = sig;

    /* I || u32str(q) || u16str(0xFFFD) || ... */
    c16toa(LMS_D_C, ip);
    /* I || u32str(q) || u16str(0xFFFD) || u8str(0xFF) || ... */
    *jp = LMS_D_FIXED;
#ifndef WC_LMS_FULL_HASH
#ifdef WOLFSSL_LMS_SHA256_192
    if ((state->params->lmOtsType & LMS_HASH_MASK) == LMS_SHA256_192) {
        /* I || u32str(q) || u16str(0xFFFD) || u8str(0xFF) || SEED */
        XMEMCPY(tmp, seed, WC_SHA256_192_DIGEST_SIZE);
        /* C = H(I || u32str(q) || u16str(0xFFFD) || u8str(0xFF) || SEED)
         * sig = u32str(type) || C || ... */
        /* Put in padding for final block. */
        LMS_SHA256_SET_LEN_47(buffer);
        ret = wc_lms_sha256_192_hash_block(&state->hash, buffer, sig_c);
    }
    else
#endif
    {
    #ifndef WOLFSSL_NO_LMS_SHA256_256
        /* I || u32str(q) || u16str(0xFFFD) || u8str(0xFF) || SEED */
        XMEMCPY(tmp, seed, WC_SHA256_DIGEST_SIZE);
        /* C = H(I || u32str(q) || u16str(0xFFFD) || u8str(0xFF) || SEED)
         * sig = u32str(type) || C || ... */
        /* Put in padding for final block. */
        LMS_SHA256_SET_LEN_55(buffer);
        ret = wc_lms_hash_block(&state->hash, buffer, sig_c);
    #else
        ret = NOT_COMPILED_IN;
    #endif
    }
#else
#ifdef WOLFSSL_LMS_SHA256_192
    if ((state->params->lmOtsType & LMS_HASH_MASK) == LMS_SHA256_192) {
        /* I || u32str(q) || u16str(0xFFFD) || u8str(0xFF) || SEED */
        XMEMCPY(tmp, seed, WC_SHA256_192_DIGEST_SIZE);
        /* C = H(I || u32str(q) || u16str(0xFFFD) || u8str(0xFF) || SEED)
         * sig = u32str(type) || C || ... */
        ret = wc_lms_hash_sha256_192(&state->hash, buffer,
            LMS_HASH_BUFFER_LEN(WC_SHA256_192_DIGEST_SIZE), sig_c);
    }
    else
#endif
    {
    #ifndef WOLFSSL_NO_LMS_SHA256_256
        /* I || u32str(q) || u16str(0xFFFD) || u8str(0xFF) || SEED */
        XMEMCPY(tmp, seed, WC_SHA256_DIGEST_SIZE);
        /* C = H(I || u32str(q) || u16str(0xFFFD) || u8str(0xFF) || SEED)
         * sig = u32str(type) || C || ... */
        ret = wc_lms_hash(&state->hash, buffer,
            LMS_HASH_BUFFER_LEN(WC_SHA256_DIGEST_SIZE), sig_c);
    #else
        ret = NOT_COMPILED_IN;
    #endif
    }
#endif /* !WC_LMS_FULL_HASH */

    if (ret == 0) {
        byte* sig_y = sig_c + state->params->hash_len;

        /* Compute array y.
         * sig = u32str(type) || C || y[0] || ... || y[p-1] */
        ret = wc_lmots_compute_y_from_seed(state, seed, msg, msgSz, sig_c,
            sig_y);
    }

    return ret;
}
#endif /* WOLFSSL_LMS_VERIFY_ONLY */

/***************************************
 * LMS APIs
 **************************************/

#ifndef WOLFSSL_LMS_VERIFY_ONLY
#ifndef WOLFSSL_WC_LMS_SMALL
/* Load the LMS private state from data.
 *
 * @param [in]  params     LMS parameters.
 * @param [out] state      Private key state.
 * @param [in]  priv_data  Private key data.
 */
static void wc_lms_priv_state_load(const LmsParams* params, LmsPrivState* state,
    byte* priv_data)
{
    /* Authentication path data. */
    state->auth_path = priv_data;
    priv_data += params->height * params->hash_len;

    /* Stack of nodes. */
    state->stack.stack = priv_data;
    priv_data += (params->height + 1) * params->hash_len;
    ato32(priv_data, &state->stack.offset);
    priv_data += 4;

    /* Cached root nodes. */
    state->root = priv_data;
    priv_data += LMS_ROOT_CACHE_LEN(params->rootLevels, params->hash_len);

    /* Cached leaf nodes. */
    state->leaf.cache = priv_data;
    priv_data += LMS_LEAF_CACHE_LEN(params->cacheBits, params->hash_len);
    ato32(priv_data, &state->leaf.idx);
    priv_data += 4;
    ato32(priv_data, &state->leaf.offset);
    /* priv_data += 4; */
}

/* Store the LMS private state into data.
 *
 * @param [in]      params     LMS parameters.
 * @param [in]      state      Private key state.
 * @param [in, out] priv_data  Private key data.
 */
static void wc_lms_priv_state_store(const LmsParams* params,
    LmsPrivState* state, byte* priv_data)
{
    /* Authentication path data. */
    priv_data += params->height * params->hash_len;

    /* Stack of nodes. */
    priv_data += (params->height + 1) * params->hash_len;
    c32toa(state->stack.offset, priv_data);
    priv_data += 4;

    /* Cached root nodes. */
    priv_data += LMS_ROOT_CACHE_LEN(params->rootLevels, params->hash_len);

    /* Cached leaf nodes. */
    priv_data += LMS_LEAF_CACHE_LEN(params->cacheBits, params->hash_len);
    c32toa(state->leaf.idx, priv_data);
    priv_data += 4;
    c32toa(state->leaf.offset, priv_data);
    /* priv_data += 4; */
}

#ifndef WOLFSSL_LMS_NO_SIGN_SMOOTHING
/* Copy LMS private key state.
 *
 * @param [in]  params  LMS parameters.
 * @param [out] dst     LMS private state destination.
 * @param [in]  src     LMS private state source.
 */
static void wc_lms_priv_state_copy(const LmsParams* params,
    LmsPrivState* dst, const LmsPrivState* src)
{
    XMEMCPY(dst->auth_path, src->auth_path, LMS_PRIV_STATE_LEN(params->height,
        params->rootLevels, params->cacheBits, params->hash_len));
    dst->stack.offset = src->stack.offset;
    dst->leaf.idx = src->leaf.idx;
    dst->leaf.offset = src->leaf.offset;
}
#endif /* !WOLFSSL_LMS_NO_SIGN_SMOOTHING */
#endif /* !WOLFSSL_WC_LMS_SMALL */

/* Calculate the leaf node hash.
 *
 * Assumes buffer already contains : I
 *
 * Appendix C.
 *   ...
 *     temp = H(I || u32str(r)|| u16str(D_LEAF) || OTS_PUB_HASH[i])
 *   ...
 * Section 5.3. LMS Public Key
 *                                        ... where we denote the public
 *   key final hash value (namely, the K value computed in Algorithm 1)
 *   associated with the i-th LM-OTS private key as OTS_PUB_HASH[i], ...
 * Algorithm 1: Generating a One-Time Signature Public Key From a
 * Private Key
 *   ...
 *   K = H(I || u32str(q) || u16str(D_PBLC) || y[0] || ... || y[p-1])
 *   ...
 * Therefore:
 *   OTS_PUB_HASH[i] = H(I || u32str(i) || u16str(D_PBLC) ||
 *                       y[0] || ... || y[p-1])
 *
 * @param [in, out] state  LMS state.
 * @param [in]      seed   Private seed to generate x.
 * @param [in]      i      Index of leaf.
 * @param [in]      r      Leaf hash index.
 * @param [out]     leaf   Leaf node hash.
 */
static int wc_lms_leaf_hash(LmsState* state, const byte* seed, word32 i,
    word32 r, byte* leaf)
{
    int ret;
    byte* buffer = state->buffer;
    byte* rp = buffer + LMS_I_LEN;
    byte* dp = rp + LMS_R_LEN;
    byte* ots_pub_hash = dp + LMS_D_LEN;

    /* I || u32str(i) || ... */
    c32toa(i, rp);
    /* OTS_PUB_HASH[i] = H(I || u32str(i) || u16str(D_PBLC) ||
     *                     y[0] || ... || y[p-1])
     */
    ret = wc_lmots_make_public_hash(state, seed, ots_pub_hash);
    if (ret == 0) {
        /* I || u32str(r) || ... || OTS_PUB_HASH[i] */
        c32toa(r, rp);
        /* I || u32str(r) || u16str(D_LEAF) || OTS_PUB_HASH[i] */
        c16toa(LMS_D_LEAF, dp);
        /* temp = H(I || u32str(r) || u16str(D_LEAF) || OTS_PUB_HASH[i]) */
#ifndef WC_LMS_FULL_HASH
        /* Put in padding for final block. */
    #ifdef WOLFSSL_LMS_SHA256_192
        if ((state->params->lmOtsType & LMS_HASH_MASK) == LMS_SHA256_192) {
            LMS_SHA256_SET_LEN_46(buffer);
            ret = wc_lms_sha256_192_hash_block(&state->hash, buffer, leaf);
        }
        else
    #endif
        {
        #ifndef WOLFSSL_NO_LMS_SHA256_256
            LMS_SHA256_SET_LEN_54(buffer);
            ret = wc_lms_hash_block(&state->hash, buffer, leaf);
        #else
            ret = NOT_COMPILED_IN;
        #endif
        }
#else
    #ifdef WOLFSSL_LMS_SHA256_192
        if ((state->params->lmOtsType & LMS_HASH_MASK) == LMS_SHA256_192) {
            ret = wc_lms_hash_sha256_192(&state->hash, buffer,
                LMS_SEED_HASH_LEN(WC_SHA256_192_DIGEST_SIZE), leaf);
        }
        else
    #endif
        {
        #ifndef WOLFSSL_NO_LMS_SHA256_256
            ret = wc_lms_hash(&state->hash, buffer,
                LMS_SEED_HASH_LEN(WC_SHA256_DIGEST_SIZE), leaf);
        #else
            ret = NOT_COMPILED_IN;
        #endif
        }
#endif /* !WC_LMS_FULL_HASH */
    }

    return ret;
}

/* Calculate interior node hash.
 *
 * Appendix C. n Iterative Algorithm for Computing an LMS Public Key
 * Generating an LMS Public Key from an LMS Private Key
 *   ...
 *   left_side = pop(data stack);
 *   temp = H(I || u32str(r) || u16str(D_INTR) || left_side || temp)
 *   ...
 * Popping the stack is done in the caller.
 *
 * @param [in, out] state  LMS state.
 * @param [in]      sp     Stack pointer to left nodes.
 * @param [in]      r      Node hash index.
 * @param [out]     node   Interior node hash.
 */
static int wc_lms_interior_hash(LmsState* state, byte* sp, word32 r,
    byte* node)
{
    int ret;
    byte* buffer = state->buffer;
    byte* rp = buffer + LMS_I_LEN;
    byte* left = rp + LMS_R_LEN + LMS_D_LEN;

    /* I || u32str(r) || u16str(D_INTR) || ... || temp */
    c32toa(r, rp);
#ifdef WOLFSSL_LMS_SHA256_192
    if ((state->params->lmOtsType & LMS_HASH_MASK) == LMS_SHA256_192) {
        /* left_side = pop(data stack)
         * I || u32str(r) || u16str(D_INTR) || left_side || temp */
        XMEMCPY(left, sp, WC_SHA256_192_DIGEST_SIZE);
        /* temp = H(I || u32str(r) || u16str(D_INTR) || left_side || temp) */
        ret = wc_lms_hash_sha256_192(&state->hash, buffer,
            LMS_NODE_HASH_LEN(WC_SHA256_192_DIGEST_SIZE), node);
    }
    else
#endif
    {
    #ifndef WOLFSSL_NO_LMS_SHA256_256
        /* left_side = pop(data stack)
         * I || u32str(r) || u16str(D_INTR) || left_side || temp */
        XMEMCPY(left, sp, WC_SHA256_DIGEST_SIZE);
        /* temp = H(I || u32str(r) || u16str(D_INTR) || left_side || temp) */
        ret = wc_lms_hash(&state->hash, buffer,
            LMS_NODE_HASH_LEN(WC_SHA256_DIGEST_SIZE), node);
    #else
        ret = NOT_COMPILED_IN;
    #endif
    }

    return ret;
}

#ifdef WOLFSSL_WC_LMS_SMALL
/* Computes hash of the Merkle tree and gets the authentication path for q.
 *
 * Appendix C: An Iterative Algorithm for Computing an LMS Public Key
 *    for ( i = 0; i < 2^h; i = i + 1 ) {
 *      r = i + num_lmots_keys;
 *      temp = H(I || u32str(r) || u16str(D_LEAF) || OTS_PUB_HASH[i])
 *      j = i;
 *      while (j % 2 == 1) {
 *        r = (r - 1)/2;
 *        j = (j-1) / 2;
 *        left_side = pop(data stack);
 *        temp = H(I || u32str(r) || u16str(D_INTR) || left_side || temp)
 *      }
 *      push temp onto the data stack
 *   }
 *   public_key = pop(data stack)
 *
 * @param [in, out] state      LMS state.
 * @param [in]      id         Unique tree identifier, I.
 * @param [in]      seed       Private seed to generate x.
 * @param [in]      max        Count of leaf nodes to calculate. Must be greater
 *                             than q. Must be a power of 2.
 * @param [in]      q          Index for authentication path.
 * @param [out]     auth_path  Authentication path for index.
 * @param [out]     pub        LMS public key.
 * @param [out]     stack_d    Where to store stack data.
 * @return  0 on success.
 */
static int wc_lms_treehash(LmsState* state, const byte* id, const byte* seed,
    word32 q, byte* auth_path, byte* pub)
{
    int ret = 0;
    const LmsParams* params = state->params;
    byte* buffer = state->buffer;
    byte* rp = buffer + LMS_I_LEN;
    byte* dp = rp + LMS_R_LEN;
    byte* left = dp + LMS_D_LEN;
    byte* temp = left + params->hash_len;
#ifdef WOLFSSL_SMALL_STACK
    byte* stack = NULL;
#else
    byte stack[(LMS_MAX_HEIGHT + 1) * LMS_MAX_NODE_LEN];
#endif /* WOLFSSL_SMALL_STACK */
    byte* sp;
    word32 i;

    /* I || ... */
    XMEMCPY(buffer, id, LMS_I_LEN);

#ifdef WOLFSSL_SMALL_STACK
    /* Allocate stack of left side hashes. */
    stack = XMALLOC((params->height + 1) * params->hash_len, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (stack == NULL) {
        ret = MEMORY_E;
    }
#endif /* WOLFSSL_SMALL_STACK */
    sp = stack;

    /* Compute all nodes requested. */
    for (i = 0; (ret == 0) && (i < ((word32)1 << params->height)); i++) {
        word32 j = i;
        word16 h = 0;
        /* r = i + num_lmots_keys */
        word32 r = i + ((word32)1 << (params->height));

        /* Calculate leaf node hash. */
        ret = wc_lms_leaf_hash(state, seed, i, r, temp);

        /* Store the node if on the authentication path. */
        if ((ret == 0) && (auth_path != NULL) && ((q ^ 0x1) == i)) {
            XMEMCPY(auth_path, temp, params->hash_len);
        }

        /* I || ... || u16str(D_INTR) || ... || temp */
        c16toa(LMS_D_INTR, dp);
        /* Calculate parent node is we have both left and right. */
        while ((ret == 0) && ((j & 0x1) == 1)) {
            /* Get parent node index. r and j are odd. */
            r >>= 1;
            j >>= 1;
            h++;

            /* Calculate interior node hash.
             * temp = H(I || u32str(r) || u16str(D_INTR) || left_side || temp)
             */
            sp -= params->hash_len;
            ret = wc_lms_interior_hash(state, sp, r, temp);

            /* Copy out node to authentication path if on path. */
            if ((ret == 0) && (auth_path != NULL) && ((q >> h) ^ 0x1) == j) {
                XMEMCPY(auth_path + h * params->hash_len, temp,
                    params->hash_len);
            }
        }
        /* Push temp onto the data stack. */
        XMEMCPY(sp, temp, params->hash_len);
        sp += params->hash_len;
    }

    if ((ret == 0) && (pub != NULL)) {
        /* Public key, root node, is top of data stack. */
        XMEMCPY(pub, stack, params->hash_len);
    }
#ifdef WOLFSSL_SMALL_STACK
    XFREE(stack, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif /* WOLFSSL_SMALL_STACK */
    return ret;
}

/* Compute the LMS public key - root node of tree.
 *
 * @param [in, out] state  LMS state.
 * @param [in]      id     Unique tree identifier, I.
 * @param [in]      seed   Private seed to generate x.
 * @param [out]     pub    LMS public key.
 * @return  0 on success.
 */
static int wc_lms_make_public_key(LmsState* state, const byte* id,
    const byte* seed, byte* pub)
{
    return wc_lms_treehash(state, id, seed, 0, NULL, pub);
}

/* Calculate the authentication path.
 *
 * @param [in, out] state  LMS state.
 * @param [in]      id     Public random: I.
 * @param [in]      seed   Private random: SEED.
 * @param [in]      q      Index of leaf.
 * @param [out]     sig    Signature buffer to place authentication path into.
 * @param [out]     root   Root node of tree.
 * @return  0 on success.
 */
static int wc_lms_auth_path(LmsState* state, const byte* id, const byte* seed,
    word32 q, byte* sig, byte* root)
{
    return wc_lms_treehash(state, id, seed, q, sig, root);
}
#else
/* Computes hash of the Merkle tree and gets the authentication path for q.
 *
 * Appendix C: An Iterative Algorithm for Computing an LMS Public Key
 *    for ( i = 0; i < 2^h; i = i + 1 ) {
 *      r = i + num_lmots_keys;
 *      temp = H(I || u32str(r) || u16str(D_LEAF) || OTS_PUB_HASH[i])
 *      j = i;
 *      while (j % 2 == 1) {
 *        r = (r - 1)/2;
 *        j = (j-1) / 2;
 *        left_side = pop(data stack);
 *        temp = H(I || u32str(r) || u16str(D_INTR) || left_side || temp)
 *      }
 *      push temp onto the data stack
 *   }
 *   public_key = pop(data stack)
 *
 * @param [in, out] state      LMS state.
 * @param [in, out] privState  LMS state of the private key.
 * @param [in]      id         Unique tree identifier, I.
 * @param [in]      seed       Private seed to generate x.
 * @param [in]      q          Index for authentication path.
 * @return  0 on success.
 */
static int wc_lms_treehash_init(LmsState* state, LmsPrivState* privState,
    const byte* id, const byte* seed, word32 q)
{
    int ret = 0;
    const LmsParams* params = state->params;
    byte* buffer = state->buffer;
    byte* auth_path = privState->auth_path;
    byte* root = privState->root;
    HssLeafCache* leaf = &privState->leaf;
    byte* rp = buffer + LMS_I_LEN;
    byte* dp = rp + LMS_R_LEN;
    byte* left = dp + LMS_D_LEN;
    byte* temp = left + params->hash_len;
#ifdef WOLFSSL_SMALL_STACK
    byte* stack = NULL;
#else
    byte stack[(LMS_MAX_HEIGHT + 1) * LMS_MAX_NODE_LEN];
#endif /* WOLFSSL_SMALL_STACK */
    word32 spi = 0;
    word32 i;
    word32 max_h = (word32)1 << params->height;
    word32 max_cb = (word32)1 << params->cacheBits;

    privState->stack.offset = 0;
    /* Reset the cached stack. */
    leaf->offset = 0;
    leaf->idx = q;
    if ((q + max_cb) > max_h) {
        leaf->idx = max_h - max_cb;
    }

    /* I || ... */
    XMEMCPY(buffer, id, LMS_I_LEN);

#ifdef WOLFSSL_SMALL_STACK
    /* Allocate stack of left side hashes. */
    stack = (byte*)XMALLOC((params->height + 1) * params->hash_len, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (stack == NULL) {
        ret = MEMORY_E;
    }
#endif /* WOLFSSL_SMALL_STACK */

    /* Compute all nodes requested. */
    for (i = 0; (ret == 0) && (i < max_h); i++) {
        word32 j = i;
        word16 h = 0;
        /* r = i + num_lmots_keys */
        word32 r = i + max_h;

        /* Calculate leaf node hash. */
        ret = wc_lms_leaf_hash(state, seed, i, r, temp);

        /* Cache leaf node if in range. */
        if ((ret == 0) && (i >= leaf->idx) && (i < leaf->idx + max_cb)) {
            XMEMCPY(leaf->cache + i * params->hash_len, temp, params->hash_len);
        }

        /* Store the node if on the authentication path. */
        if ((ret == 0) && (auth_path != NULL) && ((q ^ 0x1) == i)) {
            XMEMCPY(auth_path, temp, params->hash_len);
        }

        /* I || ... || u16str(D_INTR) || ... || temp */
        c16toa(LMS_D_INTR, dp);
        /* Calculate parent node is we have both left and right. */
        while ((ret == 0) && ((j & 0x1) == 1)) {
            /* Get parent node index. r and j are odd. */
            r >>= 1;
            j >>= 1;
            h++;

            /* Calculate interior node hash.
             * temp = H(I || u32str(r) || u16str(D_INTR) || left_side || temp)
             */
            spi -= params->hash_len;
            ret = wc_lms_interior_hash(state, stack + spi, r, temp);

            /* Copy out top root nodes. */
            if ((h > params->height - params->rootLevels) &&
                    ((i >> (h-1)) != ((i + 1) >> (h - 1)))) {
                int off = (1 << (params->height - h)) + (i >> h) - 1;
                XMEMCPY(root + off * params->hash_len, temp, params->hash_len);
            }

            /* Copy out node to authentication path if on path. */
            if ((ret == 0) && (auth_path != NULL) && ((q >> h) ^ 0x1) == j) {
                XMEMCPY(auth_path + h * params->hash_len, temp,
                    params->hash_len);
            }
        }
        /* Push temp onto the data stack. */
        XMEMCPY(stack + spi, temp, params->hash_len);
        spi += params->hash_len;

        if (i == q - 1) {
            XMEMCPY(privState->stack.stack, stack, spi);
            privState->stack.offset = spi;
        }
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(stack, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif /* WOLFSSL_SMALL_STACK */
    return ret;
}

/* Computes hash of the Merkle tree and gets the authentication path for q.
 *
 * Appendix C: An Iterative Algorithm for Computing an LMS Public Key
 *    for ( i = 0; i < 2^h; i = i + 1 ) {
 *      r = i + num_lmots_keys;
 *      temp = H(I || u32str(r) || u16str(D_LEAF) || OTS_PUB_HASH[i])
 *      j = i;
 *      while (j % 2 == 1) {
 *        r = (r - 1)/2;
 *        j = (j-1) / 2;
 *        left_side = pop(data stack);
 *        temp = H(I || u32str(r) || u16str(D_INTR) || left_side || temp)
 *      }
 *      push temp onto the data stack
 *   }
 *   public_key = pop(data stack)
 *
 * @param [in, out] state       LMS state.
 * @param [in, out] privState   LMS state of the private key.
 * @param [in]      id          Unique tree identifier, I.
 * @param [in]      seed        Private seed to generate x.
 * @param [in]      min_idx     Minimum leaf index to process.
 * @param [in]      max_idx     Maximum leaf index to process.
 * @param [in]      q           Index for authentication path.
 * @param [in]      useRoot     Whether to use nodes from root cache.
 * @return  0 on success.
 */
static int wc_lms_treehash_update(LmsState* state, LmsPrivState* privState,
    const byte* id, const byte* seed, word32 min_idx, word32 max_idx, word32 q,
    int useRoot)
{
    int ret = 0;
    const LmsParams* params = state->params;
    byte* buffer = state->buffer;
    byte* auth_path = privState->auth_path;
    LmsStack* stackCache = &privState->stack;
    HssLeafCache* leaf = &privState->leaf;
    byte* rp = buffer + LMS_I_LEN;
    byte* dp = rp + LMS_R_LEN;
    byte* left = dp + LMS_D_LEN;
    byte* temp = left + params->hash_len;
#ifdef WOLFSSL_SMALL_STACK
    byte* stack = NULL;
#else
    byte stack[(LMS_MAX_HEIGHT + 1) * LMS_MAX_NODE_LEN];
#endif /* WOLFSSL_SMALL_STACK */
    byte* sp;
    word32 max_cb = (word32)1 << params->cacheBits;
    word32 i;

    /* I || ... */
    XMEMCPY(buffer, id, LMS_I_LEN);

#ifdef WOLFSSL_SMALL_STACK
    /* Allocate stack of left side hashes. */
    stack = (byte*)XMALLOC((params->height + 1) * params->hash_len, NULL,
        DYNAMIC_TYPE_TMP_BUFFER);
    if (stack == NULL) {
        ret = MEMORY_E;
    }
#endif /* WOLFSSL_SMALL_STACK */

    /* Public key, root node, is top of data stack. */
    XMEMCPY(stack, stackCache->stack, params->height * params->hash_len);
    sp = stack + stackCache->offset;

    /* Compute all nodes requested. */
    for (i = min_idx; (ret == 0) && (i <= max_idx); i++) {
        word32 j = i;
        word16 h = 0;
        /* r = i + num_lmots_keys */
        word32 r = i + ((word32)1 << (params->height));

        if ((i >= leaf->idx) && (i < leaf->idx + max_cb)) {
            /* Calculate offset of node in cache. */
            word32 off = ((i - (leaf->idx + max_cb) + leaf->offset) % max_cb) *
                params->hash_len;
            /* Copy cached node into working buffer. */
            XMEMCPY(temp, leaf->cache + off, params->hash_len);
            /* I || u32str(i) || ... */
            c32toa(i, rp);
        }
        else {
            /* Calculate leaf node hash. */
            ret = wc_lms_leaf_hash(state, seed, i, r, temp);

            /* Check if this is at the end of the cache and not beyond q plus
             * the number of leaf nodes. */
            if ((i == leaf->idx + max_cb) && (i < (q + max_cb))) {
                /* Copy working node into cache over old first node. */
                XMEMCPY(leaf->cache + leaf->offset * params->hash_len, temp,
                    params->hash_len);
                /* Increase start index as first node replaced. */
                leaf->idx++;
                /* Update offset of first leaf node. */
                leaf->offset = (leaf->offset + 1) & (max_cb - 1);
            }
        }

        /* Store the node if on the authentication path. */
        if ((ret == 0) && ((q ^ 0x1) == i)) {
            XMEMCPY(auth_path, temp, params->hash_len);
        }

        /* I || ... || u16str(D_INTR) || ... || temp */
        c16toa(LMS_D_INTR, dp);
        /* Calculate parent node if we have both left and right. */
        while ((ret == 0) && ((j & 0x1) == 1)) {
            /* Get parent node index. r and j are odd. */
            r >>= 1;
            j >>= 1;
            h++;

            sp -= params->hash_len;
            if (useRoot && (h > params->height - params->rootLevels) &&
                    (h <= params->height)) {
                /* Calculate offset of cached root node. */
                word32 off = ((word32)1U << (params->height - h)) +
                    (i >> h) - 1;
                XMEMCPY(temp, privState->root + (off * params->hash_len),
                    params->hash_len);
            }
            else {
                /* Calculate interior node hash.
                 * temp = H(I || u32str(r) || u16str(D_INTR) || left_side ||
                 *          temp)
                 */
                ret = wc_lms_interior_hash(state, sp, r, temp);
            }

            /* Copy out top root nodes. */
            if ((ret == 0) && (q == 0) && (!useRoot) &&
                    (h > params->height - params->rootLevels) &&
                    ((i >> (h-1)) != ((i + 1) >> (h - 1)))) {
                int off = (1 << (params->height - h)) + (i >> h) - 1;
                XMEMCPY(privState->root + off * params->hash_len, temp,
                    params->hash_len);
            }

            /* Copy out node to authentication path if on path. */
            if ((ret == 0) && (((q >> h) ^ 0x1) == j)) {
                XMEMCPY(auth_path + h * params->hash_len, temp,
                    params->hash_len);
            }
        }
        if (ret == 0) {
            /* Push temp onto the data stack. */
            XMEMCPY(sp, temp, params->hash_len);
            sp += params->hash_len;

            /* Save stack after updating first node. */
            if (i == min_idx) {
                /* Copy stack back. */
                stackCache->offset = (word32)((size_t)sp - (size_t)stack);
                XMEMCPY(stackCache->stack, stack, stackCache->offset);
            }
        }
    }

    if (!useRoot) {
        /* Copy stack back. */
        XMEMCPY(stackCache->stack, stack, params->height * params->hash_len);
        stackCache->offset = (word32)((size_t)sp - (size_t)stack);
    }

#ifdef WOLFSSL_SMALL_STACK
    XFREE(stack, NULL, DYNAMIC_TYPE_TMP_BUFFER);
#endif /* WOLFSSL_SMALL_STACK */
    return ret;
}
#endif /* WOLFSSL_WC_LMS_SMALL */

/* Sign message using LMS.
 *
 * Appendix D. Method for Deriving Authentication Path for a Signature.
 * Generating an LMS Signature
 *   ...
 *   3. Create the LM-OTS signature for the message:
 *      ots_signature = lmots_sign(message, LMS_PRIV[q])
 *   4. Compute the array path as follows:
 *      ...
 *   5. S = u32str(q) || ots_signature || u32str(type) ||
 *                           path[0] || path[1] || ... || path[h-1]
 *   ...
 * path[] added by caller as it can come from cache.
 *
 * @param [in, out] state  LMS state.
 * @param [in]      priv   LMS private key.
 * @param [in]      msg    Message/public key to sign.
 * @param [in]      msgSz  Length of message in bytes.
 * @param [out]     sig    LMS signature.
 * @return  0 on success.
 */
static int wc_lms_sign(LmsState* state, const byte* priv, const byte* msg,
    word32 msgSz, byte* sig)
{
    int ret;
    const LmsParams* params = state->params;
    byte* buffer = state->buffer;
    byte* s = sig;
    const byte* priv_q = priv;
    const byte* priv_seed = priv_q + LMS_Q_LEN;
    const byte* priv_i = priv_seed + params->hash_len;

    /* Setup for hashing: I || Q */
    XMEMCPY(buffer, priv_i, LMS_I_LEN);
    XMEMCPY(buffer + LMS_I_LEN, priv_q, LMS_Q_LEN);

    /* Copy q from private key.
     * S = u32str(q) || ... */
    XMEMCPY(s, priv_q, LMS_Q_LEN);
    s += LMS_Q_LEN;

    /* ots_signature = sig = u32str(type) || ... */
    c32toa(state->params->lmOtsType, s);
    s += LMS_TYPE_LEN;
    /* Sign this level.
     * S = u32str(q) || ots_signature || ... */
    ret = wc_lmots_sign(state, priv_seed, msg, msgSz, s);
    if (ret == 0) {
        /* Skip over ots_signature. */
        s += params->hash_len + params->p * params->hash_len;
        /* S = u32str(q) || ots_signature || u32str(type) || ... */
        c32toa(params->lmsType, s);
    }

    return ret;
}

#if !defined(WOLFSSL_WC_LMS_SMALL) && !defined(WOLFSSL_LMS_NO_SIG_CACHE)
/* Copy in the cached signature data.
 *
 * @param [in]  params    LMS parameters.
 * @param [in]  y         y cache.
 * @param [in]  priv      Private key data.
 * @param [out] sig       Signature data.
 */
static void wc_lms_sig_copy(const LmsParams* params, const byte* y,
    const byte* priv, byte* sig)
{
    /* Put in q. */
    XMEMCPY(sig, priv, LMS_Q_LEN);
    sig += LMS_Q_LEN;
    /* S = u32str(q) || ... */
    c32toa(params->lmOtsType, sig);
    sig += LMS_TYPE_LEN;
    /* S = u32str(q) || ots_signature || ... */
    XMEMCPY(sig, y, params->hash_len + params->p * params->hash_len);
    sig += params->hash_len + params->p * params->hash_len;
    /* S = u32str(q) || ots_signature || u32str(type) || ... */
    c32toa(params->lmsType, sig);
}
#endif /* !WOLFSSL_WC_LMS_SMALL && !WOLFSSL_LMS_NO_SIG_CACHE */
#endif /* !WOLFSSL_LMS_VERIFY_ONLY */

/* Compute the root node of the LMS tree.
 *
 * Algorithm 6a: Computing an LMS Public Key Candidate from a Signature,
 * Message, Identifier, and Algorithm Typecodes
 *   ...
 *   4. Compute the candidate LMS root value Tc as follows:
 *      node_num = 2^h + q
 *      tmp = H(I || u32str(node_num) || u16str(D_LEAF) || Kc)
 *      i = 0
 *      while (node_num > 1) {
 *        if (node_num is odd):
 *          tmp = H(I||u32str(node_num/2)||u16str(D_INTR)||path[i]||tmp)
 *        else:
 *          tmp = H(I||u32str(node_num/2)||u16str(D_INTR)||tmp||path[i])
 *        node_num = node_num/2
 *        i = i + 1
 *      }
 *      Tc = tmp
 *   5. Return Tc.
 *
 * @param [in, out]  state  LMS state.
 * @param [in]       q      Index of node.
 * @param [in]       kc     K candidate.
 * @param [in]       path   Authentication path from signature.
 * @param [out]      tc     T candidate.
 * @return  0 on success.
 */
static int wc_lms_compute_root(LmsState* state, word32 q, const byte* kc,
    const byte* path, byte* tc)
{
    int ret;
    const LmsParams* params = state->params;
    byte* buffer = state->buffer;
    byte* rp = buffer + LMS_I_LEN;
    byte* ip = rp + LMS_Q_LEN;
    byte* node = ip + LMS_P_LEN;
    byte* b[2][2];
    /* node_num = 2^h + q */
    word32 r = (1 << params->height) + q;

    /* tmp = H(I || u32str(node_num) || u16str(D_LEAF) || Kc) */
    c32toa(r, rp);
    c16toa(LMS_D_LEAF, ip);
    XMEMCPY(node, kc, params->hash_len);
    /* Put tmp into offset required for first iteration. */
#ifndef WC_LMS_FULL_HASH
    /* Put in padding for final block. */
#ifdef WOLFSSL_LMS_SHA256_192
    if ((params->lmOtsType & LMS_HASH_MASK) == LMS_SHA256_192) {
        b[0][0] = node;
        b[0][1] = node + WC_SHA256_192_DIGEST_SIZE;
        b[1][0] = node + WC_SHA256_192_DIGEST_SIZE;
        b[1][1] = node;
        LMS_SHA256_SET_LEN_46(buffer);
        ret = wc_lms_sha256_192_hash_block(&state->hash, buffer, b[r & 1][0]);
    }
    else
#endif
    {
    #ifndef WOLFSSL_NO_LMS_SHA256_256
        b[0][0] = node;
        b[0][1] = node + WC_SHA256_DIGEST_SIZE;
        b[1][0] = node + WC_SHA256_DIGEST_SIZE;
        b[1][1] = node;
        LMS_SHA256_SET_LEN_54(buffer);
        ret = wc_lms_hash_block(&state->hash, buffer, b[r & 1][0]);
    #else
        ret = NOT_COMPILED_IN;
    #endif
    }
#else
#ifdef WOLFSSL_LMS_SHA256_192
    if ((params->lmOtsType & LMS_HASH_MASK) == LMS_SHA256_192) {
        b[0][0] = node;
        b[0][1] = node + WC_SHA256_192_DIGEST_SIZE;
        b[1][0] = node + WC_SHA256_192_DIGEST_SIZE;
        b[1][1] = node;
        ret = wc_lms_hash_sha256_192(&state->hash, buffer,
            LMS_SEED_HASH_LEN(WC_SHA256_192_DIGEST_SIZE), b[r & 1][0]);
    }
    else
#endif
    {
    #ifndef WOLFSSL_NO_LMS_SHA256_256
        b[0][0] = node;
        b[0][1] = node + WC_SHA256_DIGEST_SIZE;
        b[1][0] = node + WC_SHA256_DIGEST_SIZE;
        b[1][1] = node;
        ret = wc_lms_hash(&state->hash, buffer,
            LMS_SEED_HASH_LEN(WC_SHA256_DIGEST_SIZE), b[r & 1][0]);
    #else
        ret = NOT_COMPILED_IN;
    #endif
    }
#endif /* !WC_LMS_FULL_HASH */

    if (ret == 0) {
        int i;

        /* I||...||u16str(D_INT)||... */
        c16toa(LMS_D_INTR, ip);

        /* Do all but last height. */
    #ifdef WOLFSSL_LMS_SHA256_192
        if ((params->lmOtsType & LMS_HASH_MASK) == LMS_SHA256_192) {
            for (i = 0; (ret == 0) && (i < params->height - 1); i++) {
                /* Put path into offset required. */
                XMEMCPY(b[r & 1][1], path, WC_SHA256_192_DIGEST_SIZE);
                path += WC_SHA256_192_DIGEST_SIZE;

                /* node_num = node_num / 2 */
                r >>= 1;
                /*  H(...||u32str(node_num/2)||..) */
                c32toa(r, rp);
                /* tmp = H(I||u32str(node_num/2)||u16str(D_INTR)||path[i]||tmp)
                 * or
                 * tmp = H(I||u32str(node_num/2)||u16str(D_INTR)||tmp||path[i])
                 * Put tmp result into offset required for next iteration. */
                ret = wc_lms_hash_sha256_192(&state->hash, buffer,
                    LMS_NODE_HASH_LEN(WC_SHA256_192_DIGEST_SIZE), b[r & 1][0]);
            }
            if (ret == 0) {
                /* Last height. */
                /* Put path into offset required. */
                XMEMCPY(b[r & 1][1], path, WC_SHA256_192_DIGEST_SIZE);
                /* node_num = node_num / 2 */
                r >>= 1;
                /*  H(...||u32str(node_num/2)||..) */
                c32toa(r, rp);
                /* tmp = H(I||u32str(node_num/2)||u16str(D_INTR)||path[i]||tmp)
                 * or
                 * tmp = H(I||u32str(node_num/2)||u16str(D_INTR)||tmp||path[i])
                 * Put tmp result into Tc.*/
                ret = wc_lms_hash_sha256_192(&state->hash, buffer,
                    LMS_NODE_HASH_LEN(WC_SHA256_192_DIGEST_SIZE), tc);
            }
        }
        else
    #endif
        {
        #ifndef WOLFSSL_NO_LMS_SHA256_256
            for (i = 0; (ret == 0) && (i < params->height - 1); i++) {
                /* Put path into offset required. */
                XMEMCPY(b[r & 1][1], path, WC_SHA256_DIGEST_SIZE);
                path += WC_SHA256_DIGEST_SIZE;

                /* node_num = node_num / 2 */
                r >>= 1;
                /*  H(...||u32str(node_num/2)||..) */
                c32toa(r, rp);
                /* tmp = H(I||u32str(node_num/2)||u16str(D_INTR)||path[i]||tmp)
                 * or
                 * tmp = H(I||u32str(node_num/2)||u16str(D_INTR)||tmp||path[i])
                 * Put tmp result into offset required for next iteration. */
                ret = wc_lms_hash(&state->hash, buffer,
                    LMS_NODE_HASH_LEN(WC_SHA256_DIGEST_SIZE), b[r & 1][0]);
            }
            if (ret == 0) {
                /* Last height. */
                /* Put path into offset required. */
                XMEMCPY(b[r & 1][1], path, WC_SHA256_DIGEST_SIZE);
                /* node_num = node_num / 2 */
                r >>= 1;
                /*  H(...||u32str(node_num/2)||..) */
                c32toa(r, rp);
                /* tmp = H(I||u32str(node_num/2)||u16str(D_INTR)||path[i]||tmp)
                 * or
                 * tmp = H(I||u32str(node_num/2)||u16str(D_INTR)||tmp||path[i])
                 * Put tmp result into Tc.*/
                ret = wc_lms_hash(&state->hash, buffer,
                    LMS_NODE_HASH_LEN(WC_SHA256_DIGEST_SIZE), tc);
            }
        #else
            ret = NOT_COMPILED_IN;
        #endif
        }
    }

    return ret;
}

/* LMS verify message using public key and signature.
 *
 * Algorithm 6a: Computing an LMS Public Key Candidate from a Signature,
 * Message, Identifier, and Algorithm Typecodes
 *   ...
 *   2. Parse sigtype, q, lmots_signature, and path from the signature
 *      as follows:
 *      a. q = strTou32(first 4 bytes of signature)
 *      ...
 *      e. lmots_signature = bytes 4 through 7 + n * (p + 1)
 *         of signature
 *      ...
 *      j. Set path as follows:
 *           path[0] = next m bytes of signature
 *           path[1] = next m bytes of signature
 *              ...
 *         path[h-1] = next m bytes of signature
 *   3. Kc = candidate public key computed by applying Algorithm 4b
 *      to the signature lmots_signature, the message, and the
 *      identifiers I, q
 *   4. Compute the candidate LMS root value Tc as follows:
 *      ...
 *   5. Return Tc
 * Algorithm 6: LMS Signature Verification
 *   ...
 *   3. Compute the LMS Public Key Candidate Tc from the signature,
 *      message, identifier, pubtype, and ots_typecode, using
 *      Algorithm 6a.
 *   4. If Tc is equal to T[1], return VALID; otherwise, return INVALID.
 *
 * @param [in, out] state  LMS state.
 * @param [in]      pub    LMS public key.
 * @param [in]      msg    Message/public key to verify.
 * @param [in]      msgSz  Length of message in bytes.
 * @param [in]      sig    LMS signature.
 */
static int wc_lms_verify(LmsState* state, const byte* pub, const byte* msg,
    word32 msgSz, const byte* sig)
{
    int ret;
    const LmsParams* params = state->params;
    byte* buffer = state->buffer;
    const byte* pub_i = pub + LMS_TYPE_LEN + LMS_TYPE_LEN;
    const byte* pub_k = pub_i + LMS_I_LEN;
    const byte* sig_q = sig;
    byte tc[LMS_MAX_NODE_LEN];
    byte* kc = tc;

    /* Algorithm 6. Step 3. */
    /* Check the public key LMS type matches parameters. */
    ret = wc_lmots_public_key_check(params, pub);
    if (ret == 0) {
        /* Algorithm 6a. Step 2.e. */
        const byte* sig_lmots = sig + LMS_Q_LEN;

        /* Setup buffer with I || Q. */
        XMEMCPY(buffer, pub_i, LMS_I_LEN);
        XMEMCPY(buffer + LMS_I_LEN, sig_q, LMS_Q_LEN);

        /* Algorithm 6a. Step 3. */
        ret = wc_lmots_calc_kc(state, pub + LMS_TYPE_LEN, msg, msgSz,
            sig_lmots, kc);
    }
    if (ret == 0) {
        /* Algorithm 6a. Step 2.j. */
        const byte* sig_path = sig + LMS_Q_LEN + LMS_TYPE_LEN +
            params->hash_len + params->p * params->hash_len + LMS_TYPE_LEN;
        word32 q;

        /* Algorithm 6a. Step 2.a. */
        ato32(sig_q, &q);

        /* Algorithm 6a. Steps 4-5. */
        ret = wc_lms_compute_root(state, q, kc, sig_path, tc);
    }
    /* Algorithm 6. Step 4. */
    if ((ret == 0) && (XMEMCMP(pub_k, tc, params->hash_len) != 0)) {
        ret = SIG_VERIFY_E;
    }

    return ret;
}

/***************************************
 * HSS APIs
 **************************************/

#ifndef WOLFSSL_LMS_VERIFY_ONLY
/* Derive the seed and i for child.
 *
 * @param [in, out] state   LMS state.
 * @param [in]      id      Parent's I.
 * @param [in]      seed    Parent's SEED.
 * @param [in]      q       Parent's q.
 * @param [out]     seed_i  Derived SEED and I.
 * @return  0 on success.
 */
static int wc_hss_derive_seed_i(LmsState* state, const byte* id,
    const byte* seed, const byte* q, byte* seed_i)
{
    int ret = 0;
    byte buffer[WC_SHA256_BLOCK_SIZE];
    byte* idp = buffer;
    byte* qp = idp + LMS_I_LEN;
    byte* ip = qp + LMS_Q_LEN;
    byte* jp = ip + LMS_P_LEN;
    byte* tmp = jp + LMS_W_LEN;

    /* parent's I || ... */
    XMEMCPY(idp, id, LMS_I_LEN);
    /* parent's I || q || ... */
    XMEMCPY(qp, q, LMS_Q_LEN);
    /* parent's I || q || D_CHILD_SEED || ... */
    c16toa(LMS_D_CHILD_SEED, ip);
    /* parent's I || q || D_CHILD_SEED || D_FIXED || ... */
    *jp = LMS_D_FIXED;
    /* parent's I || q || D_CHILD_SEED || D_FIXED || parent's SEED */
    XMEMCPY(tmp, seed, state->params->hash_len);
    /* SEED = H(parent's I || q || D_CHILD_SEED || D_FIXED || parent's SEED) */
#ifndef WC_LMS_FULL_HASH
#ifdef WOLFSSL_LMS_SHA256_192
    if ((state->params->lmOtsType & LMS_HASH_MASK) == LMS_SHA256_192) {
        /* Put in padding for final block. */
        LMS_SHA256_SET_LEN_47(buffer);
        ret = wc_lms_sha256_192_hash_block(&state->hash, buffer, seed_i);
        if (ret == 0) {
            seed_i += WC_SHA256_192_DIGEST_SIZE;
        }
    }
    else
#endif
    {
    #ifndef WOLFSSL_NO_LMS_SHA256_256
        /* Put in padding for final block. */
        LMS_SHA256_SET_LEN_55(buffer);
        ret = wc_lms_hash_block(&state->hash, buffer, seed_i);
        if (ret == 0) {
            seed_i += WC_SHA256_DIGEST_SIZE;
        }
    #else
        ret = NOT_COMPILED_IN;
    #endif
    }
#else
#ifdef WOLFSSL_LMS_SHA256_192
    if ((state->params->lmOtsType & LMS_HASH_MASK) == LMS_SHA256_192) {
        ret = wc_lms_hash_sha256_192(&state->hash, buffer,
            LMS_HASH_BUFFER_LEN(WC_SHA256_192_DIGEST_SIZE), seed_i);
    }
    else
#endif
    {
    #ifndef WOLFSSL_NO_LMS_SHA256_256
        ret = wc_lms_hash(&state->hash, buffer,
            LMS_HASH_BUFFER_LEN(WC_SHA256_DIGEST_SIZE), seed_i);
    #else
        ret = NOT_COMPILED_IN;
    #endif
    }
#endif /* !WC_LMS_FULL_HASH */

    if (ret == 0) {
        /* parent's I || q || D_CHILD_I || D_FIXED || parent's SEED */
        c16toa(LMS_D_CHILD_I, ip);
        /* I = H(parent's I || q || D_CHILD_I || D_FIXED || parent's SEED) */
#ifndef WC_LMS_FULL_HASH
    #ifdef WOLFSSL_LMS_SHA256_192
        if ((state->params->lmOtsType & LMS_HASH_MASK) == LMS_SHA256_192) {
            ret = wc_lms_sha256_192_hash_block(&state->hash, buffer, tmp);
        }
        else
    #endif
        {
        #ifndef WOLFSSL_NO_LMS_SHA256_256
            ret = wc_lms_hash_block(&state->hash, buffer, tmp);
        #else
            ret = NOT_COMPILED_IN;
        #endif
        }
#else
    #ifdef WOLFSSL_LMS_SHA256_192
        if ((state->params->lmOtsType & LMS_HASH_MASK) == LMS_SHA256_192) {
            ret = wc_lms_hash_sha256_192(&state->hash, buffer,
                LMS_HASH_BUFFER_LEN(WC_SHA256_192_DIGEST_SIZE), tmp);
        }
        else
    #endif
        {
        #ifndef WOLFSSL_NO_LMS_SHA256_256
            ret = wc_lms_hash(&state->hash, buffer,
                LMS_HASH_BUFFER_LEN(WC_SHA256_DIGEST_SIZE), tmp);
        #else
            ret = NOT_COMPILED_IN;
        #endif
        }
#endif /* !WC_LMS_FULL_HASH */
        /* Copy part of hash as new I into private key. */
        XMEMCPY(seed_i, tmp, LMS_I_LEN);
    }

    return ret;
}

/* Get q, index, of leaf at the specified level. */
#define LMS_Q_AT_LEVEL(q, ls, l, h)                                 \
    (w64GetLow32(w64ShiftRight((q), (((ls) - 1 - (l)) * (h)))) &    \
     (((word32)1 << (h)) - 1))

/* Expand the seed and I for further levels and set q for each level.
 *
 * @param [in, out] state     LMS state.
 * @param [in, out] priv      Private key for use in signing.
 * @param [in]      priv_raw  Private key read.
 * @param [in]      inc       Whether this is an incremental expansion.
 * @return  0 on success.
 */
static int wc_hss_expand_private_key(LmsState* state, byte* priv,
    const byte* priv_raw, int inc)
{
    const LmsParams* params = state->params;
    int ret = 0;
    w64wrapper q;
    w64wrapper qm1;
    word32 q32;
    byte* priv_q;
    byte* priv_seed_i;
    int i;

    /* Get the 64-bit q value from the raw private key. */
    ato64(priv_raw, &q);
    /* Step over q and parameter set. */
    priv_raw += HSS_Q_LEN + HSS_PRIV_KEY_PARAM_SET_LEN;

    /* Get q of highest level. */
    q32 = LMS_Q_AT_LEVEL(q, params->levels, 0, params->height);
    /* Set q of highest tree. */
    c32toa(q32, priv);

    /* Incremental expansion needs q-1. */
    if (inc) {
        /* Calculate q-1 for comparison. */
        qm1 = q;
        w64Decrement(&qm1);
    }
    else {
        /* Copy out SEED and I into private key. */
        XMEMCPY(priv + LMS_Q_LEN, priv_raw, params->hash_len + LMS_I_LEN);
    }

    /* Compute SEED and I for rest of levels. */
    for (i = 1; (ret == 0) && (i < params->levels); i++) {
        /* Don't skip calculating SEED and I. */
        int skip = 0;

        /* Incremental means q, SEED and I already present if q unchanged. */
        if (inc) {
            /* Calculate previous levels q for previous 64-bit q value. */
            word32 qm1_32 = LMS_Q_AT_LEVEL(qm1, params->levels, i - 1,
                params->height);
            /* Same q at previous level means no need to re-compute. */
            if (q32 == qm1_32) {
                /* Do skip calculating SEED and I. */
                skip = 1;
            }
        }

        /* Get pointers into private q to write q and seed + I. */
        priv_q = priv;
        priv += LMS_Q_LEN;
        priv_seed_i = priv;
        priv += params->hash_len + LMS_I_LEN;

        /* Get q for level from 64-bit composite. */
        q32 = w64GetLow32(w64ShiftRight(q, (params->levels - 1 - i) *
            params->height)) & (((word32)1 << params->height) - 1);
        /* Set q of tree. */
        c32toa(q32, priv);

        if (!skip) {
            /* Derive SEED and I into private key. */
            ret = wc_hss_derive_seed_i(state, priv_seed_i + params->hash_len,
                priv_seed_i, priv_q, priv + LMS_Q_LEN);
        }
    }

    return ret;
}

#ifndef WOLFSSL_WC_LMS_SMALL
#ifndef WOLFSSL_LMS_NO_SIGN_SMOOTHING
/* Initialize the next subtree.
 *
 * @param [in] state      LMS state.
 * @param [in] privState  LMS private state.
 * @param [in] curr       Current private key.
 * @param [in] priv       Next private key.
 * @param [in] q          q for this level.
 * @return  0 on success.
 */
static int wc_lms_next_subtree_init(LmsState* state, LmsPrivState* privState,
    byte* curr, byte* priv, word32 q)
{
    int ret;
    const LmsParams* params = state->params;
    byte* priv_q;
    byte* priv_seed;
    byte* priv_i;
    word32 pq;

    priv_q = priv;
    priv += LMS_Q_LEN;
    priv_seed = curr + LMS_Q_LEN;
    priv += params->hash_len;
    priv_i = curr + LMS_Q_LEN + params->hash_len;
    priv += LMS_I_LEN;

    ato32(curr, &pq);
    pq = (pq + 1) & ((1 << params->height) - 1);
    c32toa(pq, priv_q);

    privState->stack.offset = 0;
    privState->leaf.idx = (word32)-(1 << params->cacheBits);
    privState->leaf.offset = 0;

    /* Derive SEED and I for next tree. */
    ret = wc_hss_derive_seed_i(state, priv_i, priv_seed, priv_q,
        priv + LMS_Q_LEN);
    if (ret == 0) {
        /* Update treehash for first leaf. */
        ret = wc_lms_treehash_update(state, privState,
            priv + LMS_Q_LEN + params->hash_len, priv + LMS_Q_LEN, 0, q, 0, 0);
    }

    return ret;
}

/* Increment count on next subtree.
 *
 * @param [in] state     LMS state.
 * @param [in] priv_key  HSS private key.
 * @param [in] q64       64-bit q for all levels.
 * @return  0 on success.
 */
static int wc_hss_next_subtree_inc(LmsState* state, HssPrivKey* priv_key,
    w64wrapper q64)
{
    int ret = 0;
    const LmsParams* params = state->params;
    byte* curr = priv_key->priv;
    byte* priv = priv_key->next_priv;
    int i;
    w64wrapper p64 = q64;
    byte tmp_priv[LMS_PRIV_LEN(LMS_MAX_NODE_LEN)];
    int use_tmp = 0;
    int lastQMax = 0;
    w64wrapper p64_hi;
    w64wrapper q64_hi;

    /* Get previous index. */
    w64Decrement(&p64);
    /* Get index of previous and current parent. */
    p64_hi = w64ShiftRight(p64, (params->levels - 1) * params->height);
    q64_hi = w64ShiftRight(q64, (params->levels - 1) * params->height);
    for (i = 1; (ret == 0) && (i < params->levels); i++) {
        word32 qc;
        w64wrapper cp64_hi;
        w64wrapper cq64_hi;

        /* Get index of previous and current child. */
        cp64_hi = w64ShiftRight(p64, (params->levels - i - 1) * params->height);
        cq64_hi = w64ShiftRight(q64, (params->levels - i - 1) * params->height);
        /* Get the q for the child. */
        ato32(curr + LMS_PRIV_LEN(params->hash_len), &qc);

        /* Compare index of parent node with previous value. */
        if (w64LT(p64_hi, q64_hi)) {
            wc_lms_priv_state_copy(params, &priv_key->state[i],
                &priv_key->next_state[i-1]);
            ret = wc_lms_next_subtree_init(state, &priv_key->next_state[i - 1],
                use_tmp ? tmp_priv : curr, priv, 0);
            use_tmp = 0;
        }
        /* Check whether the child is in a new subtree. */
        else if ((qc == ((word32)1 << params->height) - 1) &&
                w64LT(cp64_hi, cq64_hi)) {
            XMEMSET(tmp_priv, 0, LMS_Q_LEN);
            /* Check whether the node at the previous level is also in a new
             * subtree. */
            if (lastQMax) {
                /* Calculate new SEED and I based on new subtree. */
                ret = wc_hss_derive_seed_i(state,
                    priv + LMS_Q_LEN + params->hash_len, priv + LMS_Q_LEN,
                    tmp_priv, tmp_priv + LMS_Q_LEN);
            }
            else {
                /* Calculate new SEED and I based on parent. */
                ret = wc_hss_derive_seed_i(state,
                    curr + LMS_Q_LEN + params->hash_len, curr + LMS_Q_LEN, priv,
                    tmp_priv + LMS_Q_LEN);
            }
            /* Values not stored so note that they are in temporary. */
            use_tmp = 1;

            /* Set the the q. */
            XMEMCPY(tmp_priv, curr + LMS_PRIV_LEN(params->hash_len), LMS_Q_LEN);
        }

        lastQMax = (qc == ((word32)1 << params->height) - 1);
        curr += LMS_PRIV_LEN(params->hash_len);
        priv += LMS_PRIV_LEN(params->hash_len);
        p64_hi = cp64_hi;
        q64_hi = cq64_hi;
    }

    return ret;
}

/* Initialize the next subtree for each level bar the highest.
 *
 * @param [in, out] state     LMS state.
 * @param [out]     priv_key  Private key data.
 * @return  0 on success.
 */
static int wc_hss_next_subtrees_init(LmsState* state, HssPrivKey* priv_key)
{
    int ret = 0;
    const LmsParams* params = state->params;
    byte* curr = priv_key->priv;
    byte* priv = priv_key->next_priv;
    int i;

    XMEMCPY(priv, curr, LMS_PRIV_LEN(params->hash_len));
    wc_lms_idx_inc(priv, LMS_Q_LEN);

    for (i = 1; (ret == 0) && (i < params->levels); i++) {
        word32 q;

        ato32(curr + LMS_PRIV_LEN(params->hash_len), &q);
        ret = wc_lms_next_subtree_init(state, &priv_key->next_state[i - 1],
            curr, priv, q);

        curr += LMS_PRIV_LEN(params->hash_len);
        priv += LMS_PRIV_LEN(params->hash_len);
    }

    return ret;
}
#endif

/* Update the authentication path and caches.
 *
 * @param [in, out] state     LMS state.
 * @param [in, out] priv_key  Private key information.
 * @param [in]      levels    Number of level to start at.
 * @param [out]     pub_root  Public root.
 * @return  0 on success.
 */
static int wc_hss_init_auth_path(LmsState* state, HssPrivKey* priv_key,
    byte* pub_root)
{
    int ret = 0;
    int levels = state->params->levels;
    byte* priv = priv_key->priv +
        LMS_PRIV_LEN(state->params->hash_len) * (levels - 1);
    int l;

    for (l = levels - 1; (ret == 0) && (l >= 0); l--) {
        word32 q;
        const byte* priv_q = priv;
        const byte* priv_seed = priv_q + LMS_Q_LEN;
        const byte* priv_i = priv_seed + state->params->hash_len;

        /* Get current q for tree at level. */
        ato32(priv_q, &q);
        /* Set cache start to a value that indicates no numbers available. */
        ret = wc_lms_treehash_init(state, &priv_key->state[l], priv_i,
             priv_seed, q);

        /* Move onto next level's data. */
        priv -= LMS_PRIV_LEN(state->params->hash_len);
    }

    if ((ret == 0) && (pub_root != NULL)) {
        XMEMCPY(pub_root, priv_key->state[0].root, state->params->hash_len);
    }

    return ret;
}

/* Calculate the corresponding authentication path index at that height.
 *
 * @param [in] i  Leaf node index.
 * @param [in] h  Height to calculate for.
 * @return  Index on authentication path.
 */
#define LMS_AUTH_PATH_IDX(i, h)                                 \
    (((i) ^ ((word32)1U << (h))) | (((word32)1U << (h)) - 1))

/* Update the authentication path.
 *
 * @param [in, out] state     LMS state.
 * @param [in, out] priv_key  Private key information.
 * @param [in]      levels    Number of level to start at.
 * @return  0 on success.
 */
static int wc_hss_update_auth_path(LmsState* state, HssPrivKey* priv_key,
    byte* priv_raw, int levels)
{
    const LmsParams* params = state->params;
    int ret = 0;
    byte* priv = priv_key->priv + LMS_PRIV_LEN(params->hash_len) * (levels - 1);
    int i;
#ifndef WOLFSSL_LMS_NO_SIGN_SMOOTHING
    w64wrapper q64;
#endif

    (void)priv_raw;
#ifndef WOLFSSL_LMS_NO_SIGN_SMOOTHING
    ato64(priv_raw, &q64);
#endif

    for (i = levels - 1; (ret == 0) && (i >= 0); i--) {
        word32 q;
        const byte* priv_q = priv;
        const byte* priv_seed = priv_q + LMS_Q_LEN;
        const byte* priv_i = priv_seed + params->hash_len;
        LmsPrivState* privState = &priv_key->state[i];

        /* Get q for tree at level. */
        ato32(priv_q, &q);
    #ifndef WOLFSSL_LMS_NO_SIGN_SMOOTHING
        if ((levels > 1) && (i == levels - 1) && (q == 0)) {
            /* New sub-tree. */
            ret = wc_hss_next_subtree_inc(state, priv_key, q64);
        }
        if ((ret == 0) && (q != 0))
    #else
        if (q == 0) {
            /* New sub-tree. */
            ret = wc_lms_treehash_init(state, privState, priv_i, priv_seed, 0);
        }
        else
    #endif
        {
            word32 maxq = q - 1;
            int h;
            int maxh = params->height;

            /* Check each index at each height needed for the auth path. */
            for (h = 0; (h < maxh) && (h <= maxh - params->rootLevels); h++) {
                /* Calculate the index for current q and q-1. */
                word32 qa = LMS_AUTH_PATH_IDX(q, h);
                word32 qm1a = LMS_AUTH_PATH_IDX(q - 1, h);
                /* If different then needs to be computed so keep highest. */
                if ((qa != qm1a) && (qa > maxq)) {
                    maxq = qa;
                }
            }
            for (; h < maxh; h++) {
                /* Calculate the index for current q and q-1. */
                word32 qa = LMS_AUTH_PATH_IDX(q, h);
                word32 qm1a = LMS_AUTH_PATH_IDX(q - 1, h);
                /* If different then copy in cached hash. */
                if ((qa != qm1a) && (qa > maxq)) {
                    int off = (1 << (params->height - h)) + (qa >> h) - 1;
                    XMEMCPY(privState->auth_path + h * params->hash_len,
                        privState->root + off * params->hash_len,
                        params->hash_len);
                }
            }
            /* Update the treehash and calculate the extra indices for
             * authentication path. */
            ret = wc_lms_treehash_update(state, privState, priv_i, priv_seed,
                q - 1, maxq, q, 1);
        #ifndef WOLFSSL_LMS_NO_SIGN_SMOOTHING
            if ((ret == 0) && (i > 0)) {
                w64wrapper tmp64 = w64ShiftRight(q64,
                    (levels - i) * params->height);
                w64Increment(&tmp64);
                tmp64 = w64ShiftLeft(tmp64, 64 - (i * params->height));
                if (!w64IsZero(tmp64)) {
                    priv_seed = priv_key->next_priv +
                        i * LMS_PRIV_LEN(params->hash_len) + LMS_Q_LEN;
                    priv_i = priv_seed + params->hash_len;
                    privState = &priv_key->next_state[i - 1];

                    ret = wc_lms_treehash_update(state, privState, priv_i,
                        priv_seed, q, q, 0, 0);
                }
            }
        #endif
            break;
        }

        /* Move onto next level's data. */
        priv -= LMS_PRIV_LEN(params->hash_len);
    }

    return ret;
}

#if !defined(WOLFSSL_LMS_NO_SIG_CACHE) && (LMS_MAX_LEVELS > 1)
/* Pre-sign for current q so that it isn't needed in signing.
 *
 * @param [in, out] state     LMS state.
 * @param [in, out] priv_key  Private key.
 */
static int wc_hss_presign(LmsState* state, HssPrivKey* priv_key)
{
    int ret = 0;
    const LmsParams* params = state->params;
    byte* buffer = state->buffer;
    byte pub[LMS_PUBKEY_LEN(LMS_MAX_NODE_LEN)];
    byte* root = pub + LMS_PUBKEY_LEN(LMS_MAX_NODE_LEN) - params->hash_len;
    byte* priv = priv_key->priv;
    int i;

    for (i = params->levels - 2; i >= 0; i--) {
        const byte* p = priv + i * (LMS_Q_LEN + params->hash_len + LMS_I_LEN);
        const byte* priv_q = p;
        const byte* priv_seed = priv_q + LMS_Q_LEN;
        const byte* priv_i = priv_seed + params->hash_len;

        /* ... || T(1) */
        XMEMCPY(root, priv_key->state[i + 1].root, params->hash_len);
        /* u32str(type) || u32str(otstype) || I || T(1) */
        p = priv + (i + 1) * (LMS_Q_LEN + params->hash_len + LMS_I_LEN);
        wc_lmots_public_key_encode(params, p, pub);

        /* Setup for hashing: I || Q || ... */
        XMEMCPY(buffer, priv_i, LMS_I_LEN);
        XMEMCPY(buffer + LMS_I_LEN, priv_q, LMS_Q_LEN);

        /* LM-OTS Sign this level. */
        ret = wc_lmots_sign(state, priv_seed, pub,
            LMS_PUBKEY_LEN(params->hash_len),
            priv_key->y + i * LMS_PRIV_Y_TREE_LEN(params->p, params->hash_len));
    }

    return ret;
}
#endif /* !WOLFSSL_LMS_NO_SIG_CACHE && LMS_MAX_LEVELS > 1 */
#endif /* !WOLFSSL_WC_LMS_SMALL */

/* Load the private key data into HSS private key structure.
 *
 * @param [in]      params     LMS parameters.
 * @param [in, out] key        HSS private key.
 * @param [in]      priv_data  Private key data.
 */
static void wc_hss_priv_data_load(const LmsParams* params, HssPrivKey* key,
    byte* priv_data)
{
#ifndef WOLFSSL_WC_LMS_SMALL
    int l;
#endif

    /* Expanded private keys. */
    key->priv = priv_data;
    priv_data += LMS_PRIV_KEY_LEN(params->levels, params->hash_len);

#ifndef WOLFSSL_WC_LMS_SMALL
    for (l = 0; l < params->levels; l++) {
        /* Caches for subtree. */
        wc_lms_priv_state_load(params, &key->state[l], priv_data);
        priv_data += LMS_PRIV_STATE_LEN(params->height, params->rootLevels,
            params->cacheBits, params->hash_len);
    }

#ifndef WOLFSSL_LMS_NO_SIGN_SMOOTHING
    /* Next subtree's expanded private keys. */
    key->next_priv = priv_data;
    priv_data += LMS_PRIV_KEY_LEN(params->levels, params->hash_len);
    for (l = 0; l < params->levels - 1; l++) {
        /* Next subtree's caches. */
        wc_lms_priv_state_load(params, &key->next_state[l], priv_data);
        priv_data += LMS_PRIV_STATE_LEN(params->height, params->rootLevels,
            params->cacheBits, params->hash_len);
    }
#endif /* WOLFSSL_LMS_NO_SIGN_SMOOTHING */

#ifndef WOLFSSL_LMS_NO_SIG_CACHE
    /* Signature cache. */
    key->y = priv_data;
#endif /* WOLFSSL_LMS_NO_SIG_CACHE */
#endif /* WOLFSSL_WC_LMS_SMALL */
}

#ifndef WOLFSSL_WC_LMS_SMALL
/* Store the private key data from HSS private key structure.
 *
 * @param [in]      params     LMS parameters.
 * @param [in]      key        HSS private key.
 * @param [in, out] priv_data  Private key data.
 */
static void wc_hss_priv_data_store(const LmsParams* params, HssPrivKey* key,
    byte* priv_data)
{
    int l;

    (void)key;

    /* Expanded private keys. */
    priv_data += LMS_PRIV_KEY_LEN(params->levels, params->hash_len);

    for (l = 0; l < params->levels; l++) {
        /* Caches for subtrees. */
        wc_lms_priv_state_store(params, &key->state[l], priv_data);
        priv_data += LMS_PRIV_STATE_LEN(params->height, params->rootLevels,
            params->cacheBits, params->hash_len);
    }
#ifndef WOLFSSL_LMS_NO_SIGN_SMOOTHING
    /* Next subtree's expanded private keys. */
    priv_data += LMS_PRIV_KEY_LEN(params->levels, params->hash_len);
    for (l = 0; l < params->levels - 1; l++) {
        /* Next subtree's caches. */
        wc_lms_priv_state_store(params, &key->next_state[l], priv_data);
        priv_data += LMS_PRIV_STATE_LEN(params->height, params->rootLevels,
            params->cacheBits, params->hash_len);
    }
#endif /* WOLFSSL_LMS_NO_SIGN_SMOOTHING */

#ifndef WOLFSSL_LMS_NO_SIG_CACHE
    /* Signature cache. */
#endif /* WOLFSSL_LMS_NO_SIG_CACHE */
}
#endif /* WOLFSSL_WC_LMS_SMALL */

/* Expand private key for each level and calculating auth path..
 *
 * @param [in, out] state      LMS state.
 * @param [in]      priv_raw   Raw private key bytes.
 * @param [out]     priv_key   Private key data.
 * @param [out]     priv_data  Private key data.
 * @param [out]     pub_root   Public key root node.
 * @return  0 on success.
 */
int wc_hss_reload_key(LmsState* state, const byte* priv_raw,
    HssPrivKey* priv_key, byte* priv_data, byte* pub_root)
{
    int ret;

    (void)pub_root;

    wc_hss_priv_data_load(state->params, priv_key, priv_data);
#ifndef WOLFSSL_WC_LMS_SMALL
    priv_key->inited = 0;
#endif

    /* Expand the raw private key into the private key data. */
    ret = wc_hss_expand_private_key(state, priv_key->priv, priv_raw, 0);
#ifndef WOLFSSL_WC_LMS_SMALL
    if ((ret == 0) && (!priv_key->inited)) {
        /* Initialize the authentication paths and caches for all trees. */
        ret = wc_hss_init_auth_path(state, priv_key, pub_root);
    #ifndef WOLFSSL_LMS_NO_SIGN_SMOOTHING
        if (ret == 0) {
            ret = wc_hss_next_subtrees_init(state, priv_key);
        }
    #endif
    #if !defined(WOLFSSL_LMS_NO_SIG_CACHE) && (LMS_MAX_LEVELS > 1)
        if (ret == 0) {
            /* Calculate signatures for trees not at bottom. */
            ret = wc_hss_presign(state, priv_key);
        }
    #endif /* !WOLFSSL_LMS_NO_SIG_CACHE */
        /* Set initialized flag. */
        priv_key->inited = (ret == 0);
    }
#endif /* WOLFSSL_WC_LMS_SMALL */

    return ret;
}

/* Make an HSS key pair.
 *
 * @param [in, out] state      LMS state.
 * @param [in]      rng        Random number generator.
 * @param [out]     priv_raw   Private key to write.
 * @param [out]     priv_key   Private key.
 * @param [out]     priv_data  Private key data.
 * @param [out]     pub        Public key.
 * @return  0 on success.
 */
int wc_hss_make_key(LmsState* state, WC_RNG* rng, byte* priv_raw,
    HssPrivKey* priv_key, byte* priv_data, byte* pub)
{
    const LmsParams* params = state->params;
    int ret = 0;
    int i;
    byte* p = priv_raw;
    byte* pub_root = pub + LMS_L_LEN + LMS_TYPE_LEN + LMS_TYPE_LEN + LMS_I_LEN;

    /* The 64-bit q starts at 0 - set into raw private key. */
    wc_lms_idx_zero(p, HSS_Q_LEN);
    p += HSS_Q_LEN;

    /* Set the LMS and LM-OTS types for each level. */
    for (i = 0; i < params->levels; i++) {
        p[i] = ((params->lmsType & LMS_H_W_MASK) << 4) +
               (params->lmOtsType & LMS_H_W_MASK);
    }
    /* Set rest of levels to an invalid value. */
    for (; i < HSS_MAX_LEVELS; i++) {
        p[i] = 0xff;
    }
    p += HSS_PRIV_KEY_PARAM_SET_LEN;

    /* Make the private key. */
    ret = wc_lmots_make_private_key(rng, params->hash_len, p);

    if (ret == 0) {
        /* Set the levels into the public key data. */
        c32toa(params->levels, pub);
        pub += LMS_L_LEN;

        ret = wc_hss_reload_key(state, priv_raw, priv_key, priv_data, pub_root);
    }
    #ifdef WOLFSSL_WC_LMS_SMALL
    if (ret == 0) {
        byte* priv_seed = priv_key->priv + LMS_Q_LEN;
        byte* priv_i = priv_seed + params->hash_len;

        /* Compute the root of the highest tree to get the root for public key.
         */
        ret = wc_lms_make_public_key(state, priv_i, priv_seed, pub_root);
    }
    #endif /* !WOLFSSL_WC_LMS_SMALL */
    if (ret == 0) {
        /* Encode the public key with remaining fields from the private key. */
        wc_lmots_public_key_encode(params, priv_key->priv, pub);
    }

    return ret;
}

#ifdef WOLFSSL_WC_LMS_SMALL
/* Sign message using HSS.
 *
 * Algorithm 8: Generating an HSS signature
 *   1. If the message-signing key prv[L-1] is exhausted, regenerate
 *      that key pair, together with any parent key pairs that might
 *      be necessary.
 *      If the root key pair is exhausted, then the HSS key pair is
 *      exhausted and MUST NOT generate any more signatures.
 *      d = L
 *      while (prv[d-1].q == 2^(prv[d-1].h)) {
 *        d = d - 1
 *        if (d == 0)
 *          return FAILURE
 *      }
 *      while (d < L) {
 *        create lms key pair pub[d], prv[d]
 *        sig[d-1] = lms_signature( pub[d], prv[d-1] )
 *        d = d + 1
 *      }
 *   2. Sign the message.
 *      sig[L-1] = lms_signature( msg, prv[L-1] )
 *   3. Create the list of signed public keys.
 *      i = 0;
 *      while (i < L-1) {
 *        signed_pub_key[i] = sig[i] || pub[i+1]
 *        i = i + 1
 *      }
 *   4. Return u32str(L-1) || signed_pub_key[0] || ...
 *                               || signed_pub_key[L-2] || sig[L-1]
 *
 * @param [in, out] state     LMS state.
 * @param [in, out] priv_raw  Raw private key bytes.
 * @param [in, out] priv_key  Private key data.
 * @param [in]      msg       Message to sign.
 * @param [in]      msgSz     Length of message in bytes.
 * @param [out]     sig       Signature of message.
 * @return  0 on success.
 */
int wc_hss_sign(LmsState* state, byte* priv_raw, HssPrivKey* priv_key,
    byte* priv_data, const byte* msg, word32 msgSz, byte* sig)
{
    const LmsParams* params = state->params;
    int ret = 0;
    byte* priv = priv_key->priv;

    (void)priv_data;

    /* Step 1. Part 2: Check for total key exhaustion. */
    if (!wc_hss_sigsleft(params, priv_raw)) {
        ret = KEY_EXHAUSTED_E;
    }

    if (ret == 0) {
        /* Expand the raw private key into the private key data. */
        ret = wc_hss_expand_private_key(state, priv, priv_raw, 0);
    }
    if (ret == 0) {
        int i;
        w64wrapper q;
        w64wrapper qm1;

        /* Get 64-bit q from raw private key. */
        ato64(priv_raw, &q);
        /* Calculate q-1 for comparison. */
        qm1 = q;
        w64Decrement(&qm1);

        /* Set number of signed public keys. */
        c32toa(params->levels - 1, sig);
        sig += params->sig_len;

        /* Build from bottom up. */
        for (i = params->levels - 1; (ret == 0) && (i >= 0); i--) {
            byte* p = priv + i * (LMS_Q_LEN + params->hash_len + LMS_I_LEN);
            byte* root = NULL;

            /* Move to start of next signature at this level. */
            sig -= LMS_SIG_LEN(params->height, params->p, params->hash_len);
            if (i != 0) {
                /* Put root node into signature at this index. */
                root = sig - params->hash_len;
            }

            /* Sign using LMS for this level. */
            ret = wc_lms_sign(state, p, msg, msgSz, sig);
            if (ret == 0) {
                byte* s = sig + LMS_Q_LEN + LMS_TYPE_LEN + params->hash_len +
                    params->p * params->hash_len + LMS_TYPE_LEN;
                byte* priv_q = p;
                byte* priv_seed = priv_q + LMS_Q_LEN;
                byte* priv_i = priv_seed + params->hash_len;
                word32 q32;

                /* Get Q from private key as a number. */
                ato32(priv_q, &q32);
                /* Calculate authentication path. */
                ret = wc_lms_auth_path(state, priv_i, priv_seed, q32, s, root);
            }
            if ((ret == 0) && (i != 0)) {
                /* Create public data for this level if there is another. */
                sig -= LMS_PUBKEY_LEN(params->hash_len);
                msg = sig;
                msgSz = LMS_PUBKEY_LEN(params->hash_len);
                wc_lmots_public_key_encode(params, p, sig);
            }
        }
    }
    if (ret == 0) {
        /* Increment index of leaf node to sign with in raw data. */
        wc_lms_idx_inc(priv_raw, HSS_Q_LEN);
    }

    return ret;
}
#else
/* Build signature for HSS signed message.
 *
 * Algorithm 8: Generating an HSS signature
 *   1. ...
 *      while (prv[d-1].q == 2^(prv[d-1].h)) {
 *        d = d - 1
 *        if (d == 0)
 *          return FAILURE
 *      }
 *      while (d < L) {
 *        create lms key pair pub[d], prv[d]
 *        sig[d-1] = lms_signature( pub[d], prv[d-1] )
 *        d = d + 1
 *      }
 *   2. Sign the message.
 *      sig[L-1] = lms_signature( msg, prv[L-1] )
 *   3. Create the list of signed public keys.
 *      i = 0;
 *      while (i < L-1) {
 *        signed_pub_key[i] = sig[i] || pub[i+1]
 *        i = i + 1
 *      }
 *   4. Return u32str(L-1) || signed_pub_key[0] || ...
 *                               || signed_pub_key[L-2] || sig[L-1]
 *
 * @param [in, out] state      LMS state.
 * @param [in, out] priv_raw   Raw private key bytes.
 * @param [in, out] priv_key   Private key data.
 * @param [in]      msg        Message to sign.
 * @param [in]      msgSz      Length of message in bytes.
 * @param [out]     sig        Signature of message.
 * @return  0 on success.
 */
static int wc_hss_sign_build_sig(LmsState* state, byte* priv_raw,
    HssPrivKey* priv_key, const byte* msg, word32 msgSz, byte* sig)
{
    const LmsParams* params = state->params;
    int ret = 0;
    int i;
    w64wrapper q;
    w64wrapper qm1;
    byte* priv = priv_key->priv;

    /* Get 64-bit q from raw private key. */
    ato64(priv_raw, &q);
    /* Calculate q-1 for comparison. */
    qm1 = q;
    w64Decrement(&qm1);

    /* Set number of signed public keys. */
    c32toa(params->levels - 1, sig);
    sig += params->sig_len;

    /* Build from bottom up. */
    for (i = params->levels - 1; (ret == 0) && (i >= 0); i--) {
        byte* p = priv + i * (LMS_Q_LEN + params->hash_len + LMS_I_LEN);
        byte* root = NULL;
    #ifndef WOLFSSL_LMS_NO_SIG_CACHE
        int store_p = 0;
        word32 q_32 = LMS_Q_AT_LEVEL(q, params->levels, i,
            params->height);
        word32 qm1_32 = LMS_Q_AT_LEVEL(qm1, params->levels, i,
            params->height);
    #endif /* !WOLFSSL_LMS_NO_SIG_CACHE */

        /* Move to start of next signature at this level. */
        sig -= LMS_SIG_LEN(params->height, params->p, params->hash_len);
        if (i != 0) {
            /* Put root node into signature at this index. */
            root = sig - params->hash_len;
        }

    #ifndef WOLFSSL_LMS_NO_SIG_CACHE
        /* Check if we have a cached version of C and the p hashes that we
         * can reuse. */
        if ((i < params->levels - 1) && (q_32 == qm1_32)) {
            wc_lms_sig_copy(params, priv_key->y +
                i * LMS_PRIV_Y_TREE_LEN(params->p, params->hash_len), p, sig);
        }
        else
    #endif /* !WOLFSSL_LMS_NO_SIG_CACHE */
        {
            /* Sign using LMS for this level. */
            ret = wc_lms_sign(state, p, msg, msgSz, sig);
        #ifndef WOLFSSL_LMS_NO_SIG_CACHE
            store_p = (i < params->levels - 1);
        #endif /* !WOLFSSL_LMS_NO_SIG_CACHE */
        }
        if (ret == 0) {
            byte* s = sig + LMS_Q_LEN + LMS_TYPE_LEN;

        #ifndef WOLFSSL_LMS_NO_SIG_CACHE
            /* Check if we computed new C and p hashes. */
            if (store_p) {
                /* Cache the C and p hashes. */
                XMEMCPY(priv_key->y +
                    i * LMS_PRIV_Y_TREE_LEN(params->p, params->hash_len), s,
                    LMS_PRIV_Y_TREE_LEN(params->p, params->hash_len));
            }
        #endif /* !WOLFSSL_LMS_NO_SIG_CACHE */
            s += params->hash_len + params->p * params->hash_len +
                LMS_TYPE_LEN;

            /* Copy the authentication path out of the private key. */
            XMEMCPY(s, priv_key->state[i].auth_path,
                params->height * params->hash_len);
            /* Copy the root node into signature unless at top. */
            if (i != 0) {
                XMEMCPY(root, priv_key->state[i].root, params->hash_len);
            }
        }
        if ((ret == 0) && (i != 0)) {
            /* Create public data for this level if there is another. */
            sig -= LMS_PUBKEY_LEN(params->hash_len);
            msg = sig;
            msgSz = LMS_PUBKEY_LEN(params->hash_len);
            wc_lmots_public_key_encode(params, p, sig);
        }
    }

    return ret;
}

/* Sign message using HSS.
 *
 * Algorithm 8: Generating an HSS signature
 *   1. If the message-signing key prv[L-1] is exhausted, regenerate
 *      that key pair, together with any parent key pairs that might
 *      be necessary.
 *      If the root key pair is exhausted, then the HSS key pair is
 *      exhausted and MUST NOT generate any more signatures.
 *      d = L
 *      while (prv[d-1].q == 2^(prv[d-1].h)) {
 *        d = d - 1
 *        if (d == 0)
 *          return FAILURE
 *      }
 *      while (d < L) {
 *        create lms key pair pub[d], prv[d]
 *        sig[d-1] = lms_signature( pub[d], prv[d-1] )
 *        d = d + 1
 *      }
 *   2. Sign the message.
 *      sig[L-1] = lms_signature( msg, prv[L-1] )
 *   3. Create the list of signed public keys.
 *      i = 0;
 *      while (i < L-1) {
 *        signed_pub_key[i] = sig[i] || pub[i+1]
 *        i = i + 1
 *      }
 *   4. Return u32str(L-1) || signed_pub_key[0] || ...
 *                               || signed_pub_key[L-2] || sig[L-1]
 *
 * @param [in, out] state      LMS state.
 * @param [in, out] priv_raw   Raw private key bytes.
 * @param [in, out] priv_key   Private key data.
 * @param [in, out] priv_data  Private key data.
 * @param [in]      msg        Message to sign.
 * @param [in]      msgSz      Length of message in bytes.
 * @param [out]     sig        Signature of message.
 * @return  0 on success.
 */
int wc_hss_sign(LmsState* state, byte* priv_raw, HssPrivKey* priv_key,
    byte* priv_data, const byte* msg, word32 msgSz, byte* sig)
{
    const LmsParams* params = state->params;
    int ret = 0;

    /* Validate fixed parameters for static code analyzers. */
    if ((params->rootLevels == 0) || (params->rootLevels > params->height)) {
        ret = BAD_FUNC_ARG;
    }

    /* Step 1. Part 2: Check for total key exhaustion. */
    if ((ret == 0) && (!wc_hss_sigsleft(params, priv_raw))) {
        ret = KEY_EXHAUSTED_E;
    }

    if ((ret == 0) && (!priv_key->inited)) {
        /* Initialize the authentication paths and caches for all trees. */
        ret = wc_hss_init_auth_path(state, priv_key, NULL);
    #if !defined(WOLFSSL_LMS_NO_SIG_CACHE) && (LMS_MAX_LEVELS > 1)
        if (ret == 0) {
            ret = wc_hss_presign(state, priv_key);
        }
    #endif /* !WOLFSSL_LMS_NO_SIG_CACHE */
        /* Set initialized flag. */
        priv_key->inited = (ret == 0);
    }
    if (ret == 0) {
        ret = wc_hss_sign_build_sig(state, priv_raw, priv_key, msg, msgSz, sig);
    }
    if (ret == 0) {
        /* Increment index of leaf node to sign with in raw data. */
        wc_lms_idx_inc(priv_raw, HSS_Q_LEN);
    }
    /* Check we will produce another signature. */
    if ((ret == 0) && wc_hss_sigsleft(params, priv_raw)) {
        /* Update the expanded private key data. */
        ret = wc_hss_expand_private_key(state, priv_key->priv, priv_raw, 1);
        if (ret == 0) {
            /* Update authentication path and caches for all trees. */
            ret = wc_hss_update_auth_path(state, priv_key, priv_raw,
                params->levels);
        }
    }
    if (ret == 0) {
        /* Store the updated private key data. */
        wc_hss_priv_data_store(state->params, priv_key, priv_data);
    }

    return ret;
}
#endif

/* Check whether key is exhausted.
 *
 * First 8 bytes of raw key is the index.
 * Check index is less than count of leaf nodes.
 *
 * @param [in] params    LMS parameters.
 * @param [in] priv_raw  HSS raw private key.
 * @return  1 when signature possible.
 * @return  0 when private key exhausted.
 */
int wc_hss_sigsleft(const LmsParams* params, const byte* priv_raw)
{
    w64wrapper q;
    w64wrapper cnt;

    /* Get current q - next leaf index to sign with. */
    ato64(priv_raw, &q);
    /* 1 << total_height = total leaf nodes. */
    cnt = w64ShiftLeft(w64From32(0, 1), params->levels * params->height);
    /* Check q is less than total leaf node count. */
    return w64LT(q, cnt);
}
#endif /* !WOLFSSL_LMS_VERIFY_ONLY */

/* Verify message using HSS.
 *
 * Section 6.3. Signature Verification
 *  1. Nspk = strTou32(first four bytes of S)
 *  2. if Nspk+1 is not equal to the number of levels L in pub:
 *  3.   return INVALID
 *  4. key = pub
 *  5. for (i = 0; i < Nspk; i = i + 1) {
 *  6.   sig = siglist[i]
 *  7.   msg = publist[i]
 *  8.   if (lms_verify(msg, key, sig) != VALID):
 *  9.     return INVALID
 * 10.   key = msg
 * 11. }
 * 12. return lms_verify(message, key, siglist[Nspk])
 *
 * @param [in, out] state  LMS state.
 * @param [in]      pub    HSS public key.
 * @param [in]      msg    Message to verify.
 * @param [in]      msgSz  Length of message in bytes.
 * @param [in]      sig    Signature of message.
 * @return  0 on success.
 * @return  SIG_VERIFY_E on failure.
 */
int wc_hss_verify(LmsState* state, const byte* pub, const byte* msg,
    word32 msgSz, const byte* sig)
{
    const LmsParams* params = state->params;
    int ret = 0;
    word32 nspk;
    const byte* key = pub + LMS_L_LEN;
    word32 levels;

    /* Get number of levels from public key. */
    ato32(pub, &levels);
    /* Line 1: Get number of signed public keys from signature. */
    ato32(sig, &nspk);
    /* Line 6 (First iteration): Move to start of next signature. */
    sig += LMS_L_LEN;

    /* Line 2: Verify that pub and signature match in levels. */
    if (nspk + 1 != levels) {
        /* Line 3: Return invalid signature. */
        ret = SIG_VERIFY_E;
    }
    if (ret == 0) {
        word32 i;

        /* Line 5: For all but last LMS signature. */
        for (i = 0; (ret == 0) && (i < nspk); i++) {
            /* Line 7: Get start of public key in signature. */
            const byte* pubList = sig + LMS_Q_LEN + LMS_TYPE_LEN +
                params->hash_len + params->p * params->hash_len + LMS_TYPE_LEN +
                params->height * params->hash_len;
            /* Line 8: Verify the LMS signature with public key as message. */
            ret = wc_lms_verify(state, key, pubList,
                LMS_PUBKEY_LEN(params->hash_len), sig);
            /* Line 10: Next key is from signature. */
            key = pubList;
            /* Line 6: Move to start of next signature. */
            sig = pubList + LMS_PUBKEY_LEN(params->hash_len);
        }
    }
    if (ret == 0) {
        /* Line 12: Verify bottom tree with real message. */
        ret = wc_lms_verify(state, key, msg, msgSz, sig);
    }

    return ret;
}

#endif /* WOLFSSL_HAVE_LMS && WOLFSSL_WC_LMS */

