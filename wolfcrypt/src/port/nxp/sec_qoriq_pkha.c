/* sec_qoriq_pkha.c
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
 * Public key on the QorIQ SEC, driven through the PKHA.
 *
 * These are protocol descriptors: the engine reads a protocol data block
 * (PDB) of parameters and pointers, and the HEADER's start index tells it to
 * begin executing at the OPERATION word after the block. Every operation has
 * the same shape (a size word, a list of buffers, an OPERATION), which is
 * what secPkhaRun() implements once for all of them.
 *
 * Domain parameters are supplied explicitly; the built-in curve shortcut is
 * refused by this silicon. See the note above SEC_QORIQ_PKHA_PDB_L_SHIFT in
 * sec_qoriq.h.
 *
 * Block layouts, all fields big endian and left padded to a fixed width:
 *
 *   ECDSA sign    L|N, q, r, G(x||y), s, f, c, d, a||b
 *   ECDSA verify  L|N, q, r, G(x||y), W(x||y), f, c, d, tmp, a||b
 *   ECDH          L|N, q, r, W(x||y), s, z, a||b
 *   RSA public    e|n, f, g, n, e, f_len
 *   RSA private   d|n, g, f, n, d              (key form 1)
 *
 * where q is the field prime, r the group order, G the base point, s a
 * private scalar, W a public point, f the message representative, c and d
 * the signature halves, z the shared secret and tmp a scratch block.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_SEC_QORIQ

#include <wolfssl/wolfcrypt/port/nxp/sec_qoriq.h>

#if defined(WOLFSSL_SEC_QORIQ_PKHA) || defined(WOLFSSL_SEC_QORIQ_RSA)

#ifdef WOLFSSL_SEC_QORIQ_PKHA
    #include <wolfssl/wolfcrypt/ecc.h>
#endif
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/* Longest block above is verify: nine pointers plus room for a length. */
#define SEC_PKHA_MAX_ITEMS 10

/* A buffer when buf is set, otherwise the literal value in sz. */
typedef struct SecPkhaItem {
    const byte* buf;
    word32      sz;
    byte        out; /* engine writes it, so invalidate afterwards */
} SecPkhaItem;

/* Assemble the block, submit it, and do cache maintenance both ways.
 * Everything the engine touches is flushed first, outputs included, so no
 * dirty line can later be written back over what it produced. */
static int secPkhaRun(word32 pdbWord0, word32 op, const SecPkhaItem* items,
    int count, word32* statusOut)
{
    SecQoriqDev* dev = wc_SecQoriqGetDev();
    SecQoriqDesc desc;
    word64 phys;
    int ret;
    int i;

    if (dev == NULL) {
        return WC_HW_E;
    }

    ret = wc_SecQoriqDescInit(&desc);
    if (ret == 0) {
        ret = wc_SecQoriqDescAddWord(&desc, pdbWord0);
    }

    for (i = 0; (ret == 0) && (i < count); i++) {
        if (items[i].buf == NULL) {
            ret = wc_SecQoriqDescAddWord(&desc, items[i].sz);
            continue;
        }
        /* No length accompanies a PDB pointer, so the size only confirms
         * contiguity. Refusing beats appending a failed translation of zero,
         * which would have the engine touch physical address 0. */
        phys = wc_SecQoriqVirtToPhysLen((void*)items[i].buf, items[i].sz);
        if (phys == 0) {
            WOLFSSL_MSG("sec_qoriq: PKHA buffer not translatable");
            ret = BAD_FUNC_ARG;
            break;
        }
        ret = wc_SecQoriqDescAddPtr(&desc, phys);
    }

    if (ret == 0) {
        /* Execution starts at the OPERATION; everything above is the PDB. */
        desc.startIdx = desc.idx;
        ret = wc_SecQoriqDescAddWord(&desc, SEC_QORIQ_CMD_OP |
            SEC_QORIQ_PROT_UNIDI | op);
    }

    for (i = 0; (ret == 0) && (i < count); i++) {
        if (items[i].buf != NULL) {
            ret = wc_SecQoriqCacheFlush((void*)items[i].buf, items[i].sz);
        }
    }

    if (ret == 0) {
        ret = wc_SecQoriqRunEx(dev, &desc, statusOut);
    }

    for (i = 0; i < count; i++) {
        if ((items[i].buf != NULL) && items[i].out) {
            (void)wc_SecQoriqCacheInval((void*)items[i].buf, items[i].sz);
        }
    }

    return ret;
}

#ifdef WOLFSSL_SEC_QORIQ_PKHA

/* The PKHA is a 1023 bit engine, so P-521 is the largest curve it takes. */
#define SEC_QORIQ_PKHA_MAX_BYTES 128

/* Working set in units of the field size L: q + r + 2 G + 2 ab + f + 2 tmp. */
#define SEC_QORIQ_PKHA_UNITS 9

/* Domain parameters and per-operation buffers in one contiguous block. */
typedef struct SecPkhaCurve {
    byte*  q;   /* field prime,     L */
    byte*  r;   /* group order,     L */
    byte*  g;   /* base point,     2L */
    byte*  ab;  /* a and b,        2L */
    byte*  f;   /* message rep,     L */
    byte*  tmp; /* verify scratch, 2L */
    word32 L;
    word32 sz;
} SecPkhaCurve;

/* Stack resident by default, bounded by the largest curve the build carries:
 * 288 bytes for a P-256 only build, 594 for P-521. */
#ifdef WOLFSSL_SMALL_STACK
    #define SEC_PKHA_DECL(name)    byte* name = NULL
    #define SEC_PKHA_ALLOC(name, keySz)                                   \
        do {                                                              \
            (name) = (byte*)XMALLOC((keySz) * SEC_QORIQ_PKHA_UNITS, NULL, \
                DYNAMIC_TYPE_TMP_BUFFER);                                 \
            if ((name) == NULL) {                                         \
                return MEMORY_E;                                          \
            }                                                             \
        } while (0)
    #define SEC_PKHA_FREE(name, sz)                                       \
        do {                                                              \
            wc_SecQoriqForceZeroDma((name), (sz));                        \
            XFREE((name), NULL, DYNAMIC_TYPE_TMP_BUFFER);                 \
        } while (0)
#else
    #define SEC_PKHA_DECL(name)                                           \
        byte name[MAX_ECC_BYTES * SEC_QORIQ_PKHA_UNITS]
    #define SEC_PKHA_ALLOC(name, keySz) do { (void)(keySz); } while (0)
    #define SEC_PKHA_FREE(name, sz)     wc_SecQoriqForceZeroDma((name), (sz))
#endif

static int secPkhaHexVal(char c)
{
    if ((c >= '0') && (c <= '9')) {
        return c - '0';
    }
    if ((c >= 'A') && (c <= 'F')) {
        return (c - 'A') + 10;
    }
    if ((c >= 'a') && (c <= 'f')) {
        return (c - 'a') + 10;
    }

    return -1;
}

/* Convert a wolfCrypt hex parameter string to fixed width big endian, right
 * aligned and zero padded. Done directly rather than via mp_read_radix() so
 * no multi-precision temporary is needed: under SP math an mp_int is sized
 * for the build's largest number, hundreds of stack bytes for a string. */
static int secPkhaParam(const char* hex, byte* out, word32 len)
{
    word32 hlen;
    word32 pad;
    word32 i;
    int v;

    if ((hex == NULL) || (out == NULL) || (len == 0)) {
        return BAD_FUNC_ARG;
    }

    hlen = (word32)XSTRLEN(hex);
    if ((hlen == 0) || (hlen > (len * 2))) {
        return BAD_FUNC_ARG; /* wider than the field it has to fit */
    }

    XMEMSET(out, 0, len);
    pad = (len * 2) - hlen;

    for (i = 0; i < hlen; i++) {
        word32 nib = pad + i;

        v = secPkhaHexVal(hex[i]);
        if (v < 0) {
            return BAD_FUNC_ARG;
        }
        if ((nib & 1) == 0) {
            out[nib / 2] |= (byte)(v << 4);
        }
        else {
            out[nib / 2] |= (byte)v;
        }
    }

    return 0;
}

int wc_SecQoriqEccSupported(int curveId, word32 keySz)
{
    const ecc_set_type* dp;
    int idx;

    if ((keySz == 0) || (keySz > SEC_QORIQ_PKHA_MAX_BYTES) ||
            (keySz > MAX_ECC_BYTES)) {
        return NOT_COMPILED_IN;
    }

    idx = wc_ecc_get_curve_idx(curveId);
    if (idx < 0) {
        return NOT_COMPILED_IN;
    }
    dp = wc_ecc_get_curve_params(idx);
    if (dp == NULL) {
        return NOT_COMPILED_IN;
    }

    /* Every parameter goes into a fixed keySz-wide slot, keySz being the
     * field size. A few curves have a group order wider than the field
     * (SECP160R1/R2/K1, SECP224K1) that would not fit. Refuse here, where
     * the answer becomes a software fallback. */
    if ((XSTRLEN(dp->prime) > (keySz * 2)) ||
            (XSTRLEN(dp->order) > (keySz * 2)) ||
            (XSTRLEN(dp->Gx) > (keySz * 2)) ||
            (XSTRLEN(dp->Gy) > (keySz * 2)) ||
            (XSTRLEN(dp->Af) > (keySz * 2)) ||
            (XSTRLEN(dp->Bf) > (keySz * 2))) {
        WOLFSSL_MSG("sec_qoriq: curve parameters do not fit the fixed block");
        return NOT_COMPILED_IN;
    }

    return 0;
}

/* Lay the working block over caller storage and fill in the parameters. */
static int secPkhaLoadCurve(int curveId, word32 keySz, byte* buf,
    SecPkhaCurve* c)
{
    const ecc_set_type* dp;
    int idx;
    int ret;

    XMEMSET(c, 0, sizeof(SecPkhaCurve));

    idx = wc_ecc_get_curve_idx(curveId);
    if (idx < 0) {
        return NOT_COMPILED_IN;
    }
    dp = wc_ecc_get_curve_params(idx);
    if (dp == NULL) {
        return NOT_COMPILED_IN;
    }

    c->L  = keySz;
    c->sz = keySz * SEC_QORIQ_PKHA_UNITS;

    XMEMSET(buf, 0, c->sz);
    c->q   = buf;
    c->r   = c->q + keySz;
    c->g   = c->r + keySz;
    c->ab  = c->g + (keySz * 2);
    c->f   = c->ab + (keySz * 2);
    c->tmp = c->f + keySz;

    ret = secPkhaParam(dp->prime, c->q, keySz);
    if (ret == 0) {
        ret = secPkhaParam(dp->order, c->r, keySz);
    }
    if (ret == 0) {
        ret = secPkhaParam(dp->Gx, c->g, keySz);
    }
    if (ret == 0) {
        ret = secPkhaParam(dp->Gy, c->g + keySz, keySz);
    }
    if (ret == 0) {
        ret = secPkhaParam(dp->Af, c->ab, keySz);
    }
    if (ret == 0) {
        ret = secPkhaParam(dp->Bf, c->ab + keySz, keySz);
    }

    return ret;
}

/* Bit length of a fixed width big endian value. */
static word32 secPkhaBitLen(const byte* val, word32 len)
{
    word32 i;
    word32 bits;
    byte   b;

    for (i = 0; (i < len) && (val[i] == 0); i++) {
        /* skip the zero padding */
    }
    if (i == len) {
        return 0;
    }

    bits = (len - i - 1) * 8;
    for (b = val[i]; b != 0; b >>= 1) {
        bits++;
    }

    return bits;
}

/* Reduce the digest to the group size as ECDSA prescribes: the leftmost
 * orderBits bits when the digest is longer, otherwise a left pad with zeros.
 * order is the group order, in the same fixed width block as out.
 *
 * Returns 1 when the caller must fall back to software, for either of two
 * reasons. The representative can come out zero, which makes the ECDSA
 * equation degenerate; the engine refuses that, but wolfCrypt's tests sign an
 * all-zero digest, so it has to be a fallback rather than a failure. Or a
 * truncation is needed and the order does not fill the block: wolfCrypt
 * finishes that case with a sub-byte shift, and copying whole bytes here
 * would build a different representative and so a signature its own verifier
 * rejects. P-256 and P-384 have byte aligned orders and take the fast path;
 * P-521 never truncates, no digest being wider than its 521 bit order. */
static int secPkhaMsgRep(const byte* hash, word32 hashSz, const byte* order,
    byte* out, word32 len)
{
    byte   acc = 0;
    word32 i;
    word32 orderBits = secPkhaBitLen(order, len);

    if ((hashSz * 8) > orderBits) {
        if (orderBits != (len * 8)) {
            return 1;
        }
        XMEMCPY(out, hash, len);
    }
    else {
        XMEMSET(out, 0, len - hashSz);
        XMEMCPY(out + (len - hashSz), hash, hashSz);
    }

    for (i = 0; i < len; i++) {
        acc |= out[i];
    }

    return acc == 0;
}

/* First PDB word for the curve protocols: field and order sizes. */
static word32 secPkhaSizes(word32 L)
{
    return ((L & SEC_QORIQ_PKHA_PDB_L_MASK) << SEC_QORIQ_PKHA_PDB_L_SHIFT) |
           (L & SEC_QORIQ_PKHA_PDB_N_MASK);
}

/* Fill one PDB entry. */
static void secPkhaSet(SecPkhaItem* it, const byte* buf, word32 sz, int out)
{
    it->buf = buf;
    it->sz  = sz;
    it->out = (byte)out;
}

int wc_SecQoriqEccSign(int curveId, const byte* priv, const byte* hash,
    word32 hashSz, byte* r, byte* s, word32 keySz)
{
    SecQoriqDev* dev = wc_SecQoriqGetDev();
    SecPkhaCurve c;
    SecPkhaItem it[SEC_PKHA_MAX_ITEMS];
    SEC_PKHA_DECL(buf);
    int ret;

    if ((priv == NULL) || (hash == NULL) || (r == NULL) || (s == NULL) ||
            (hashSz == 0)) {
        return BAD_FUNC_ARG;
    }
    if (dev == NULL) {
        return WC_HW_E;
    }
    ret = wc_SecQoriqEccSupported(curveId, keySz);
    if (ret != 0) {
        return ret;
    }

#ifndef WC_NO_RNG
    /* The nonce comes from RNG4; without a live state handle the job
     * returns a CCB "RNG not instantiated" error. */
    if (dev->rngReady == 0) {
        ret = wc_SecQoriqRngInit();
        if (ret != 0) {
            return ret;
        }
    }
#else
    return NOT_COMPILED_IN;
#endif

    SEC_PKHA_ALLOC(buf, keySz);

    ret = secPkhaLoadCurve(curveId, keySz, buf, &c);
    if ((ret == 0) && secPkhaMsgRep(hash, hashSz, c.r, c.f, keySz)) {
        ret = CRYPTOCB_UNAVAILABLE;
    }

    if (ret == 0) {
        secPkhaSet(&it[0], c.q,  keySz,     0);
        secPkhaSet(&it[1], c.r,  keySz,     0);
        secPkhaSet(&it[2], c.g,  keySz * 2, 0);
        secPkhaSet(&it[3], priv, keySz,     0);
        secPkhaSet(&it[4], c.f,  keySz,     0);
        secPkhaSet(&it[5], r,    keySz,     1);
        secPkhaSet(&it[6], s,    keySz,     1);
        secPkhaSet(&it[7], c.ab, keySz * 2, 0);

        ret = secPkhaRun(secPkhaSizes(keySz),
            SEC_QORIQ_ECDSA_SIGN | SEC_QORIQ_PKHA_ECC, it, 8, NULL);
    }

    SEC_PKHA_FREE(buf, keySz * SEC_QORIQ_PKHA_UNITS);

    return ret;
}

int wc_SecQoriqEccVerify(int curveId, const byte* pubXY, const byte* hash,
    word32 hashSz, const byte* r, const byte* s, word32 keySz, int* res)
{
    SecPkhaCurve c;
    SecPkhaItem it[SEC_PKHA_MAX_ITEMS];
    SEC_PKHA_DECL(buf);
    word32 status = 0;
    int ret;

    if ((pubXY == NULL) || (hash == NULL) || (r == NULL) || (s == NULL) ||
            (res == NULL) || (hashSz == 0)) {
        return BAD_FUNC_ARG;
    }

    *res = 0; /* fail closed: only a clean job sets this */

    ret = wc_SecQoriqEccSupported(curveId, keySz);
    if (ret != 0) {
        return ret;
    }

    SEC_PKHA_ALLOC(buf, keySz);

    ret = secPkhaLoadCurve(curveId, keySz, buf, &c);
    if ((ret == 0) && secPkhaMsgRep(hash, hashSz, c.r, c.f, keySz)) {
        ret = CRYPTOCB_UNAVAILABLE;
    }

    if (ret == 0) {
        secPkhaSet(&it[0], c.q,   keySz,     0);
        secPkhaSet(&it[1], c.r,   keySz,     0);
        secPkhaSet(&it[2], c.g,   keySz * 2, 0);
        secPkhaSet(&it[3], pubXY, keySz * 2, 0);
        secPkhaSet(&it[4], c.f,   keySz,     0);
        secPkhaSet(&it[5], r,     keySz,     0);
        secPkhaSet(&it[6], s,     keySz,     0);
        secPkhaSet(&it[7], c.tmp, keySz * 2, 1);
        secPkhaSet(&it[8], c.ab,  keySz * 2, 0);

        ret = secPkhaRun(secPkhaSizes(keySz),
            SEC_QORIQ_ECDSA_VERIFY | SEC_QORIQ_PKHA_ECC, it, 9, &status);

        if (ret == 0) {
            *res = 1;
        }
        else if ((((status & SEC_QORIQ_SSRC_MASK) >> SEC_QORIQ_SSRC_SHIFT) ==
                    SEC_QORIQ_SSRC_DECO) &&
                 ((status & 0xFFU) == SEC_QORIQ_DECOERR_SIGVERIFY)) {
            /* The engine ran the verify and rejected it: an answer, not a
             * failure. The caller reads it from res. */
            WOLFSSL_MSG("sec_qoriq: ECDSA signature rejected");
            ret = 0;
        }
    }

    SEC_PKHA_FREE(buf, keySz * SEC_QORIQ_PKHA_UNITS);

    return ret;
}

int wc_SecQoriqEcdh(int curveId, const byte* priv, const byte* peerXY,
    byte* out, word32 keySz)
{
    SecPkhaCurve c;
    SecPkhaItem it[SEC_PKHA_MAX_ITEMS];
    SEC_PKHA_DECL(buf);
    int ret;

    if ((priv == NULL) || (peerXY == NULL) || (out == NULL)) {
        return BAD_FUNC_ARG;
    }
    ret = wc_SecQoriqEccSupported(curveId, keySz);
    if (ret != 0) {
        return ret;
    }

    SEC_PKHA_ALLOC(buf, keySz);

    ret = secPkhaLoadCurve(curveId, keySz, buf, &c);
    if (ret == 0) {
        /* No base point: the peer's public point stands in for it. */
        secPkhaSet(&it[0], c.q,    keySz,     0);
        secPkhaSet(&it[1], c.r,    keySz,     0);
        secPkhaSet(&it[2], peerXY, keySz * 2, 0);
        secPkhaSet(&it[3], priv,   keySz,     0);
        secPkhaSet(&it[4], out,    keySz,     1);
        secPkhaSet(&it[5], c.ab,   keySz * 2, 0);

        ret = secPkhaRun(secPkhaSizes(keySz),
            SEC_QORIQ_ECDSA_ECDH | SEC_QORIQ_PKHA_ECC, it, 6, NULL);
    }
    if (ret != 0) {
        wc_SecQoriqForceZeroDma(out, keySz); /* no partial secrets */
    }

    SEC_PKHA_FREE(buf, keySz * SEC_QORIQ_PKHA_UNITS);

    return ret;
}

#endif /* WOLFSSL_SEC_QORIQ_PKHA */

#ifdef WOLFSSL_SEC_QORIQ_RSA

/* RSA block word 0: exponent length at bit 12, modulus at bit 0. */
static word32 secRsaSizes(word32 expSz, word32 nSz)
{
    return ((expSz & SEC_QORIQ_RSA_PDB_LEN_MASK) <<
                SEC_QORIQ_RSA_PDB_E_SHIFT) |
           (nSz & SEC_QORIQ_RSA_PDB_LEN_MASK);
}

int wc_SecQoriqRsaPublic(const byte* in, word32 inSz, const byte* n,
    word32 nSz, const byte* e, word32 eSz, byte* out)
{
    SecPkhaItem it[SEC_PKHA_MAX_ITEMS];

    if ((in == NULL) || (n == NULL) || (e == NULL) || (out == NULL)) {
        return BAD_FUNC_ARG;
    }
    if ((inSz == 0) || (eSz == 0) || (nSz == 0) ||
            (nSz > SEC_QORIQ_PKHA_MAX_RSA_BYTES) ||
            (inSz > nSz) || (eSz > nSz)) {
        return BAD_FUNC_ARG;
    }

    it[0].buf = in;   it[0].sz = inSz; it[0].out = 0;
    it[1].buf = out;  it[1].sz = nSz;  it[1].out = 1;
    it[2].buf = n;    it[2].sz = nSz;  it[2].out = 0;
    it[3].buf = e;    it[3].sz = eSz;  it[3].out = 0;
    it[4].buf = NULL; it[4].sz = inSz; it[4].out = 0; /* f_len, inline */

    return secPkhaRun(secRsaSizes(eSz, nSz), SEC_QORIQ_RSA_ENCRYPT, it, 5,
        NULL);
}

int wc_SecQoriqModExp(const byte* in, const byte* d, word32 dSz,
    const byte* n, word32 nSz, byte* out)
{
    SecPkhaItem it[SEC_PKHA_MAX_ITEMS];

    if ((in == NULL) || (d == NULL) || (n == NULL) || (out == NULL)) {
        return BAD_FUNC_ARG;
    }
    if ((dSz == 0) || (nSz == 0) || (nSz > SEC_QORIQ_PKHA_MAX_RSA_BYTES) ||
            (dSz > nSz)) {
        return BAD_FUNC_ARG;
    }

    it[0].buf = in;  it[0].sz = nSz; it[0].out = 0;
    it[1].buf = out; it[1].sz = nSz; it[1].out = 1;
    it[2].buf = n;   it[2].sz = nSz; it[2].out = 0;
    it[3].buf = d;   it[3].sz = dSz; it[3].out = 0;

    /* Deliberately no zeroization of out on failure: wolfCrypt calls
     * wc_RsaFunction in place, so out aliases in at every call site, and
     * wiping it would destroy the ciphertext the software fallback needs. */
    return secPkhaRun(secRsaSizes(dSz, nSz),
        SEC_QORIQ_RSA_DECRYPT | SEC_QORIQ_RSA_PRIV_FRM_1, it, 4, NULL);
}

#endif /* WOLFSSL_SEC_QORIQ_RSA */

#endif /* WOLFSSL_SEC_QORIQ_PKHA || WOLFSSL_SEC_QORIQ_RSA */
#endif /* WOLFSSL_SEC_QORIQ */
