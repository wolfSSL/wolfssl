/* sec_qoriq_hash.c
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

/*
 * Message digests on the QorIQ SEC, driven through the MDHA.
 *
 * Only the single shot form is implemented here: one descriptor that
 * initialises, absorbs the whole message and finalises. Streaming update or
 * final needs the class 2 context loaded and stored around each call, which
 * is a later addition.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_SEC_QORIQ

#include <wolfssl/wolfcrypt/port/nxp/sec_qoriq.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>

/* Largest byte count a single FIFO LOAD can carry without the extended
 * length form. */
#define SEC_QORIQ_FIFO_MAX 0xFFFF

/* MD5, SHA-1, SHA-224 and SHA-256 absorb 64 byte blocks; SHA-384 and
 * SHA-512 absorb 128. A non final chunk must be a whole number of blocks,
 * so the chunk size has to follow the algorithm rather than a fixed 64. */
static word32 secHashBlockSz(word32 algo)
{
    switch (algo) {
        case SEC_QORIQ_SHA384:
        case SEC_QORIQ_SHA512:
            return 128;
        default:
            return 64;
    }
}

int wc_SecQoriqHash(word32 algo, word32 digestSz, const byte* in, word32 inSz,
    byte* out)
{
    SecQoriqDev* dev = wc_SecQoriqGetDev();
    SecQoriqDesc desc;
    word32 offset = 0;
    word32 blockSz;
    int ret;

    if (out == NULL || digestSz == 0) {
        return BAD_FUNC_ARG;
    }
    if (in == NULL && inSz > 0) {
        return BAD_FUNC_ARG;
    }
    if (dev == NULL) {
        return WC_HW_E;
    }

    ret = wc_SecQoriqDescInit(&desc);
    if (ret != 0) {
        return ret;
    }

    /* Init and final in one pass over the message. */
    ret = wc_SecQoriqDescAddWord(&desc, SEC_QORIQ_CMD_OP | SEC_QORIQ_CLASS2 |
        algo | SEC_QORIQ_ALG_INITF);
    if (ret != 0) {
        return ret;
    }

    /* The engine reads the message straight out of memory. */
    if (inSz > 0) {
        ret = wc_SecQoriqCacheFlush((void*)in, inSz);
        if (ret != 0) {
            return ret;
        }
    }

    blockSz = secHashBlockSz(algo);

    /* Feed the message in chunks a single command can describe. Only the
     * last chunk carries LC2, which is what tells the MDHA to finalise.
     * The loop is pre-tested so an empty message never emits a data load. */
    while (offset < inSz) {
        word32 chunk = inSz - offset;
        word32 cmd   = SEC_QORIQ_CMD_FIFO_L | SEC_QORIQ_CLASS2 |
                       SEC_QORIQ_FIFOL_TYPE_MSG;

        if (chunk > SEC_QORIQ_FIFO_MAX) {
            /* a non final chunk must be a whole number of blocks */
            chunk = SEC_QORIQ_FIFO_MAX - (SEC_QORIQ_FIFO_MAX % blockSz);
        }
        else {
            cmd |= SEC_QORIQ_FIFOL_TYPE_LC2;
        }

        ret = wc_SecQoriqDescAddBuf(&desc, cmd, in + offset, chunk);
        if (ret != 0) {
            return ret;
        }
        offset += chunk;
    }

    /* An empty message still needs the class 2 stream terminated so the
     * digest of the empty string comes out. An immediate load of zero
     * length does that without referencing a buffer, which is why in may
     * legitimately be NULL here. */
    if (inSz == 0) {
        ret = wc_SecQoriqDescAddWord(&desc, SEC_QORIQ_CMD_FIFO_L |
            SEC_QORIQ_CLASS2 | SEC_QORIQ_FIFOL_TYPE_MSG |
            SEC_QORIQ_FIFOL_TYPE_LC2 | SEC_QORIQ_CMD_IMM);
        if (ret != 0) {
            return ret;
        }
    }

    /* Pull the digest out of the class 2 context register. Routed through
     * AddBuf so the address translation is checked; a hand-rolled AddPtr
     * would happily append a failed translation of 0 and let the engine DMA
     * the digest to physical address 0. */
    ret = wc_SecQoriqDescAddBuf(&desc, SEC_QORIQ_CMD_STORE_CTX |
        SEC_QORIQ_CLASS2, out, digestSz);
    if (ret != 0) {
        return ret;
    }

    /* Push any dirty lines covering the output buffer out of the way before
     * the engine writes it. */
    ret = wc_SecQoriqCacheFlush(out, digestSz);
    if (ret != 0) {
        return ret;
    }

    ret = wc_SecQoriqRun(dev, &desc);
    if (ret != 0) {
        return ret;
    }

    return wc_SecQoriqCacheInval(out, digestSz);
}

int wc_SecQoriqSha1(const byte* in, word32 inSz, byte* out)
{
    return wc_SecQoriqHash(SEC_QORIQ_SHA1, 20, in, inSz, out);
}

int wc_SecQoriqSha224(const byte* in, word32 inSz, byte* out)
{
    return wc_SecQoriqHash(SEC_QORIQ_SHA224, 28, in, inSz, out);
}

int wc_SecQoriqSha256(const byte* in, word32 inSz, byte* out)
{
    return wc_SecQoriqHash(SEC_QORIQ_SHA256, 32, in, inSz, out);
}

int wc_SecQoriqSha384(const byte* in, word32 inSz, byte* out)
{
    return wc_SecQoriqHash(SEC_QORIQ_SHA384, 48, in, inSz, out);
}

int wc_SecQoriqSha512(const byte* in, word32 inSz, byte* out)
{
    return wc_SecQoriqHash(SEC_QORIQ_SHA512, 64, in, inSz, out);
}

#endif /* WOLFSSL_SEC_QORIQ */
