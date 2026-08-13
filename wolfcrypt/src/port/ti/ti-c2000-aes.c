/* port/ti/ti-c2000-aes.c
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

/* AES offload to the TI C2000 "AESA" block (EIP-120t) via crypto callbacks.
 * Model and build options: wolfssl/wolfcrypt/port/ti/ti-c2000.h.
 *
 * Octet/word contract, confirmed against driverlib's own vectors in
 * driverlib/f28p55x/examples/aes/aes_ex1_ecb_encrypt.c (FIPS-197 key
 * 2b7e1516... is written {0x16157e2b, ...}): word j holds octets 4j..4j+3,
 * little-endian within the word, index increasing with octet offset.  The
 * register-index reversal inside AES_writeDataBlocking() is internal to
 * driverlib - do not compensate for it.
 *
 * This matters because CHAR_BIT == 16 here: a byte buffer is one octet per
 * 16-bit cell and sizeof(word32) is 2, so the (uint32_t*) casts the TivaWare
 * port uses are wrong.  Every transfer stages through a local word32 block,
 * which also makes alignment and short trailing blocks non-issues.
 *
 * Build options (all #ifndef-guarded in ti-c2000.h, see IDE/C2000/README.md):
 *   WOLFSSL_C2000_AES          enable this port (needs WOLF_CRYPTO_CB)
 *   WOLFSSL_C2000_DEVID        devId for wc_AesInit()/RegisterDevice (0x2000)
 *   WOLFSSL_C2000_AES_BASE     AESA register base       (0x00042000)
 *   WOLFSSL_C2000_AES_SS_BASE  AESA wrapper base        (0x00042C00)
 *   WOLFSSL_C2000_AES_NO_LOCK  assert an external lock instead of requiring
 *                              SINGLE_THREADED
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_C2000_AES) && !defined(NO_AES)

#if !defined(WOLF_CRYPTO_CB)
    #error "WOLFSSL_C2000_AES requires WOLF_CRYPTO_CB"
#endif

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/port/ti/ti-c2000.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/* C2000Ware driverlib.  No name collisions with wolfssl/wolfcrypt/aes.h:
 * driverlib prefixes AES_DIRECTION_/AES_KEY_SIZE_/AES_OPMODE_, wolfCrypt uses
 * AES_ENCRYPTION/AES_128_KEY_SIZE. */
#include "aes.h"
#include "sysctl.h"

/* Words per AES block.  Not sizeof-based: sizeof(word32) is 2 here, so
 * WC_AES_BLOCK_SIZE / sizeof(word32) would be 8. */
#define C2000_BLOCK_WORDS 4

/* Largest key in words (AES-256). */
#define C2000_MAX_KEY_WORDS 8


/* Pack octets into words, little-endian within each word.
 *
 * Deliberately uint32_t, not wolfSSL's word32: word32 is only 32-bit under
 * WC_16BIT_CPU, and driverlib writes uint32_t either way - a word32 staging
 * array would be half the size the hardware fills.  Accumulates with <<= 8
 * because cl2000 miscompiles a single (uint32_t)octet << 24 as a 16-bit
 * shift (see misc.c WordsFromBytesBE32). */
static void c2000_WordsFromOctets(uint32_t* w, const byte* b, word32 wordCnt)
{
    word32 i;
    uint32_t r;
    for (i = 0; i < wordCnt; i++) {
        r  = (uint32_t)(b[(i * 4) + 3] & 0xFF); r <<= 8;
        r |= (uint32_t)(b[(i * 4) + 2] & 0xFF); r <<= 8;
        r |= (uint32_t)(b[(i * 4) + 1] & 0xFF); r <<= 8;
        r |= (uint32_t)(b[(i * 4) + 0] & 0xFF);
        w[i] = r;
    }
}
static void c2000_OctetsFromWords(byte* b, const uint32_t* w, word32 byteCnt)
{
    word32 i;
    for (i = 0; i < byteCnt; i++) {
        b[i] = WC_OCTET(w[i >> 2] >> ((i & 0x3) * 8));
    }
}
#define C2000_WORDS_FROM_OCTETS(w, b, n) c2000_WordsFromOctets((w), (b), (n))
#define C2000_OCTETS_FROM_WORDS(b, w, n) c2000_OctetsFromWords((b), (w), (n))


/* Stage one block, zero-padding a short tail.  The zeros are what make the
 * unused part of a CTR output block equal the raw keystream. */
static void c2000_LoadBlock(uint32_t blk[C2000_BLOCK_WORDS], const byte* b,
    word32 nOctets)
{
    byte tmp[WC_AES_BLOCK_SIZE];

    if (nOctets >= WC_AES_BLOCK_SIZE) {
        C2000_WORDS_FROM_OCTETS(blk, b, C2000_BLOCK_WORDS);
    }
    else {
        XMEMSET(tmp, 0, WC_AES_BLOCK_SIZE);
        XMEMCPY(tmp, b, nOctets);
        C2000_WORDS_FROM_OCTETS(blk, tmp, C2000_BLOCK_WORDS);
        ForceZero(tmp, WC_AES_BLOCK_SIZE);
    }
}


/* The context must actually be bound to this device.  Under
 * WOLF_CRYPTO_CB_FIND wolfCrypt offers contexts of any devId, including ones
 * whose devKey the backend never populated - encrypting with that all-zero
 * key would be silent and catastrophic.  Defined ahead of its callers: an
 * implicit declaration here would defeat the guard's own prototype. */
static int c2000_DevIdOk(int devId, const Aes* aes)
{
    if (aes == NULL) {
        return 0;
    }
    if (aes->devId == INVALID_DEVID) {
        return 0;
    }
    return (aes->devId == devId);
}


/* Key length (octets) -> driverlib enum; CRYPTOCB_UNAVAILABLE otherwise so
 * software takes the operation. */
static int c2000_KeySize(const Aes* aes, AES_KeySize* ks)
{
    switch (aes->keylen) {
        case 16:
            *ks = AES_KEY_SIZE_128BIT;
            break;
        case 24:
            *ks = AES_KEY_SIZE_192BIT;
            break;
        case 32:
            *ks = AES_KEY_SIZE_256BIT;
            break;
        default:
            return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    return 0;
}


#ifdef WOLFSSL_AES_COUNTER
/* Big-endian 128-bit increment, matching the static IncrementAesCounter() in
 * aes.c.  aes->reg stays authoritative in software so a caller can interleave
 * hardware and software CTR calls on one context. */
static void c2000_IncrCounter(byte* ctr)
{
    int i;
    for (i = WC_AES_BLOCK_SIZE - 1; i >= 0; i--) {
        /* WC_OCTET, not a bare ++: a byte cell here is 16 bits, so 0xFF + 1
         * is 0x100 and the carry would never propagate. */
        ctr[i] = WC_OCTET(ctr[i] + 1);
        if (ctr[i] != 0) {
            return;
        }
    }
}
#endif /* WOLFSSL_AES_COUNTER */


/* Program the block for one operation.  Order is load-bearing: a soft reset
 * clears CTRL, KEY1 and IV, so it must be reset -> configure -> IV -> key ->
 * length, and the length write starts the engine.  dataLen is padded to whole
 * blocks so the hardware always emits a complete final block. */
static int c2000_AesSetup(Aes* aes, AES_Direction dir, AES_OpMode mode,
    AES_CounterWidth ctrWidth, const byte* iv16, word32 dataLen)
{
    AES_ConfigParams cfg;
    AES_KeySize ks;
    uint32_t kw[C2000_MAX_KEY_WORDS];
    uint32_t ivw[C2000_BLOCK_WORDS];
    int ret;

    ret = c2000_KeySize(aes, &ks);
    if (ret != 0) {
        return ret;
    }

    AES_disableGlobalInterrupt(WOLFSSL_C2000_AES_SS_BASE);
    AES_performSoftReset(WOLFSSL_C2000_AES_BASE);

    XMEMSET(&cfg, 0, sizeof(cfg));
    cfg.direction       = dir;
    cfg.keySize         = ks;
    cfg.opMode          = mode;
    cfg.ctrWidth        = ctrWidth;
    cfg.ccmLenWidth     = AES_CCM_L_1;
    cfg.ccmAuthLenWidth = AES_CCM_M_0;
    AES_configureModule(WOLFSSL_C2000_AES_BASE, &cfg);

    if (iv16 != NULL) {
        C2000_WORDS_FROM_OCTETS(ivw, iv16, C2000_BLOCK_WORDS);
        AES_setInitializationVector(WOLFSSL_C2000_AES_BASE,
            (const uint32_t*)ivw);
        ForceZero(ivw, sizeof(ivw));
    }

    XMEMSET(kw, 0, sizeof(kw));
    C2000_WORDS_FROM_OCTETS(kw, (const byte*)aes->devKey,
        (word32)aes->keylen / 4);
    AES_setKey1(WOLFSSL_C2000_AES_BASE, (const uint32_t*)kw, ks);
    ForceZero(kw, sizeof(kw));

    AES_setDataLength(WOLFSSL_C2000_AES_BASE, (uint64_t)dataLen);

    return 0;
}


/* Straight in -> out loop for the modes the hardware chains itself (ECB, CBC).
 * Not AES_processData(): that redoes a 64-bit division every iteration, which
 * is costly on a C28x, and we need per-block marshalling anyway. */
static int c2000_AesProcess(Aes* aes, byte* out, const byte* in, word32 sz,
    AES_Direction dir, AES_OpMode mode, const byte* iv16)
{
    uint32_t blk[C2000_BLOCK_WORDS];
    uint32_t outw[C2000_BLOCK_WORDS];
    word32 off;
    word32 n;
    int ret;

    ret = c2000_AesSetup(aes, dir, mode, AES_CTR_WIDTH_32BIT, iv16, sz);
    if (ret != 0) {
        return ret;
    }

    for (off = 0; off < sz; off += WC_AES_BLOCK_SIZE) {
        n = sz - off;
        if (n > WC_AES_BLOCK_SIZE) {
            n = WC_AES_BLOCK_SIZE;
        }

        c2000_LoadBlock(blk, in + off, n);
        AES_writeDataBlocking(WOLFSSL_C2000_AES_BASE, (const uint32_t*)blk);
        AES_readDataBlocking(WOLFSSL_C2000_AES_BASE, (uint32_t*)outw);
        C2000_OCTETS_FROM_WORDS(out + off, outw, n);
    }

    ForceZero(blk, sizeof(blk));
    ForceZero(outw, sizeof(outw));

    return 0;
}


#if defined(HAVE_AES_ECB) || defined(WOLFSSL_AES_DIRECT) || \
    defined(WOLF_CRYPTO_CB_ONLY_AES)
static int c2000_Ecb(int devId, struct wc_CryptoInfo* info)
{
    Aes* aes = info->cipher.aesecb.aes;
    byte* out = info->cipher.aesecb.out;
    const byte* in = info->cipher.aesecb.in;
    word32 sz = info->cipher.aesecb.sz;

    if (aes == NULL || out == NULL || in == NULL) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    if (!c2000_DevIdOk(devId, aes)) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    if (sz == 0) {
        return 0;
    }
    if ((sz % WC_AES_BLOCK_SIZE) != 0) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    return c2000_AesProcess(aes, out, in, sz,
        info->cipher.enc ? AES_DIRECTION_ENCRYPT : AES_DIRECTION_DECRYPT,
        AES_OPMODE_ECB, NULL);
}
#endif /* HAVE_AES_ECB || WOLFSSL_AES_DIRECT || WOLF_CRYPTO_CB_ONLY_AES */


#ifdef HAVE_AES_CBC
static int c2000_Cbc(int devId, struct wc_CryptoInfo* info)
{
    Aes* aes = info->cipher.aescbc.aes;
    byte* out = info->cipher.aescbc.out;
    const byte* in = info->cipher.aescbc.in;
    word32 sz = info->cipher.aescbc.sz;
    byte lastIn[WC_AES_BLOCK_SIZE];
    int enc = info->cipher.enc;
    int ret;

    if (aes == NULL || out == NULL || in == NULL) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    if (!c2000_DevIdOk(devId, aes)) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    if (sz == 0) {
        return 0;
    }
    /* Non-block-multiple means a ciphertext-stealing caller; leave to SW. */
    if ((sz % WC_AES_BLOCK_SIZE) != 0) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    /* Saved before processing so an in-place call (in == out) still has it. */
    if (!enc) {
        XMEMCPY(lastIn, in + sz - WC_AES_BLOCK_SIZE, WC_AES_BLOCK_SIZE);
    }

    ret = c2000_AesProcess(aes, out, in, sz,
        enc ? AES_DIRECTION_ENCRYPT : AES_DIRECTION_DECRYPT,
        AES_OPMODE_CBC, (const byte*)aes->reg);
    if (ret != 0) {
        ForceZero(lastIn, sizeof(lastIn));
        return ret;
    }

    /* aes->reg must hold the last ciphertext block so successive calls chain.
     * Derived in software, not via AES_readInitializationVector(): IV_IN_OUT
     * only holds saved context when CTRL.SAVE_CONTEXT is set (which
     * AES_configureModule() does not do), and driverlib's reader does not poll
     * CTRL.SVCTXTRDY the way AES_readTag() does. */
    if (enc) {
        XMEMCPY(aes->reg, out + sz - WC_AES_BLOCK_SIZE, WC_AES_BLOCK_SIZE);
    }
    else {
        XMEMCPY(aes->reg, lastIn, WC_AES_BLOCK_SIZE);
        ForceZero(lastIn, WC_AES_BLOCK_SIZE);
    }

    return 0;
}
#endif /* HAVE_AES_CBC */


#ifdef WOLFSSL_AES_COUNTER
static int c2000_Ctr(int devId, struct wc_CryptoInfo* info)
{
    Aes* aes = info->cipher.aesctr.aes;
    byte* out = info->cipher.aesctr.out;
    const byte* in = info->cipher.aesctr.in;
    word32 sz = info->cipher.aesctr.sz;
    uint32_t lastOut[C2000_BLOCK_WORDS];
    uint32_t ctrw[C2000_BLOCK_WORDS];
    AES_KeySize ksz;
    byte ks[WC_AES_BLOCK_SIZE];
    word32 blocks;
    word32 used;
    word32 tail;
    word32 off;
    word32 n;
    word32 i;
    int ret;

    if (aes == NULL || out == NULL || in == NULL) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }
    if (!c2000_DevIdOk(devId, aes)) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    /* Decide before mutating state: CRYPTOCB_UNAVAILABLE makes wolfCrypt redo
     * the operation in software from the original pointers, so consuming
     * leftover keystream first would double-consume it. */
    ret = c2000_KeySize(aes, &ksz);
    if (ret != 0) {
        return ret;
    }
    (void)ksz;  /* only the accept/reject verdict is needed here */

    /* Consume leftover keystream: the callback fires before wc_AesCtrEncrypt
     * does this itself, so the state is ours. */
    if (aes->left > 0) {
        used = (aes->left < sz) ? aes->left : sz;
        xorbufout(out, in,
            (byte*)aes->tmp + WC_AES_BLOCK_SIZE - aes->left, used);
        out += used;
        in += used;
        sz -= used;
        aes->left -= used;
    }
    if (sz == 0) {
        return 0;
    }

    /* sz is bounded by RAM on this part, so this cannot overflow in practice;
     * the division is written to be safe anyway. */
    blocks = (sz / WC_AES_BLOCK_SIZE) +
             (((sz % WC_AES_BLOCK_SIZE) != 0) ? 1U : 0U);

    /* Keystream comes from hardware ECB with the counter kept in software,
     * not AES_OPMODE_CTR.  Measured on a LAUNCHXL-F28P55X: with
     * AES_CTR_WIDTH_128BIT the first block matches NIST SP800-38A F.5.1 but
     * later blocks diverge once an increment carries across an octet boundary
     * (F.5 starts at ...fe ff, so block 2 already does) - the hardware counter
     * disagrees with wolfCrypt's IncrementAesCounter().  ECB costs the same
     * number of hardware block operations and is correct by construction. */
    ret = c2000_AesSetup(aes, AES_DIRECTION_ENCRYPT, AES_OPMODE_ECB,
        AES_CTR_WIDTH_32BIT, NULL, blocks * WC_AES_BLOCK_SIZE);
    if (ret != 0) {
        return ret;
    }

    for (i = 0; i < blocks; i++) {
        off = i * WC_AES_BLOCK_SIZE;
        n = sz - off;
        if (n > WC_AES_BLOCK_SIZE) {
            n = WC_AES_BLOCK_SIZE;
        }

        /* Encrypt the counter block to get this block's keystream. */
        C2000_WORDS_FROM_OCTETS(ctrw, (const byte*)aes->reg,
            C2000_BLOCK_WORDS);
        AES_writeDataBlocking(WOLFSSL_C2000_AES_BASE, (const uint32_t*)ctrw);
        AES_readDataBlocking(WOLFSSL_C2000_AES_BASE, (uint32_t*)lastOut);
        C2000_OCTETS_FROM_WORDS(ks, lastOut, WC_AES_BLOCK_SIZE);

        xorbufout(out + off, in + off, ks, n);
        c2000_IncrCounter((byte*)aes->reg);
    }

    tail = sz % WC_AES_BLOCK_SIZE;
    if (tail != 0) {
        /* Octets tail..15 are unconsumed keystream.  Store the whole block;
         * software reads it from the end (tmp + BLOCK - left). */
        XMEMCPY(aes->tmp, ks, WC_AES_BLOCK_SIZE);
        aes->left = WC_AES_BLOCK_SIZE - tail;
    }
    else {
        aes->left = 0;
    }

    ForceZero(ks, sizeof(ks));
    ForceZero(ctrw, sizeof(ctrw));
    ForceZero(lastOut, sizeof(lastOut));

    return 0;
}
#endif /* WOLFSSL_AES_COUNTER */


int wc_C2000_CryptoCb(int devId, struct wc_CryptoInfo* info, void* ctx)
{
    (void)ctx;

    if (info == NULL) {
        return BAD_FUNC_ARG;
    }
    if (info->algo_type != WC_ALGO_TYPE_CIPHER) {
        return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
    }

    switch (info->cipher.type) {
#ifdef HAVE_AES_CBC
        case WC_CIPHER_AES_CBC:
            return c2000_Cbc(devId, info);
#endif
#ifdef WOLFSSL_AES_COUNTER
        case WC_CIPHER_AES_CTR:
            return c2000_Ctr(devId, info);
#endif
#if defined(HAVE_AES_ECB) || defined(WOLFSSL_AES_DIRECT) || \
    defined(WOLF_CRYPTO_CB_ONLY_AES)
        case WC_CIPHER_AES_ECB:
            return c2000_Ecb(devId, info);
#endif
        default:
            break;
    }

    /* CFB, OFB, XTS, GCM, CCM and DES3 fall through to software. */
    return WC_NO_ERR_TRACE(CRYPTOCB_UNAVAILABLE);
}


int wc_C2000_Init(int devId)
{
    /* Device_init() already does this on the LaunchPad BSP; repeated so the
     * port works without that BSP. */
    SysCtl_enablePeripheral(SYSCTL_PERIPH_CLK_AESA);
    SysCtl_delay(10);
    SysCtl_resetPeripheral(SYSCTL_PERIPH_RES_AESA);

    AES_disableGlobalInterrupt(WOLFSSL_C2000_AES_SS_BASE);
    AES_performSoftReset(WOLFSSL_C2000_AES_BASE);

    return wc_CryptoCb_RegisterDevice(devId, wc_C2000_CryptoCb, NULL);
}


int wc_C2000_Cleanup(int devId)
{
    /* A soft reset clears KEY1, so the last key used does not linger in the
     * peripheral after the device is unregistered. */
    AES_performSoftReset(WOLFSSL_C2000_AES_BASE);
    wc_CryptoCb_UnRegisterDevice(devId);
    return 0;
}

#endif /* WOLFSSL_C2000_AES && !NO_AES */
