/* caliptra_sim.c — software simulation of the Caliptra cryptographic mailbox
 *
 * Implements caliptra_mailbox_exec() for use in test harnesses and as the
 * default backend for --enable-caliptra builds without integrator-supplied
 * mailbox hardware (see --enable-caliptra-sim in configure.ac).
 *
 * All internal crypto uses wolfSSL software (WC_NO_DEVID) to avoid recursion
 * through the CryptoCb framework.  Random bytes use wc_RNG_GenerateBlock so
 * the sim is portable across every platform wolfSSL itself supports rather
 * than relying on /dev/urandom.
 *
 * THREAD SAFETY: concurrent calls to caliptra_mailbox_exec() are now
 * serialized by an internal mutex (sim_mailbox_lock), initialised by
 * wc_caliptra_init() and torn down by wc_caliptra_cleanup().  This matches
 * the real Caliptra hardware behaviour, which serialises requests via the
 * mailbox lock semaphore (see Caliptra Cryptographic Mailbox spec), and
 * makes the sim safe to use under the default multi-threaded wolfSSL
 * builds.  The mutex itself is initialised idempotently from a non-atomic
 * flag, so callers MUST invoke wc_caliptra_init() before issuing the
 * first mailbox operation from any thread (caliptra_test does this); a
 * race during first-init itself is not defended against.  Integrators
 * needing a different concurrency model should build with
 * --disable-caliptra-sim and link against a real (or differently-
 * implemented) mailbox backend.
 */

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/port/caliptra/caliptra_port.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/wc_port.h>

/* The body of this file only contributes to the link when the simulator
 * backend is selected.  Guard everything past the unconditional include
 * block so that build systems (e.g., CMake or user_settings.h-driven
 * tree builds) that compile every .c file unconditionally still get an
 * empty translation unit when WOLFSSL_CALIPTRA_SIM is not defined. */
#ifdef WOLFSSL_CALIPTRA_SIM

/* misc.h normally forward-declares ConstantCompare/ForceZero only under
 * NO_INLINE; otherwise the implementations live in wolfcrypt/src/misc.c
 * and callers include that translation unit directly.  Match the pattern
 * used by src/tls.c and friends so we get the real symbols at link time. */
#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include <string.h>

/* Make every build of the software simulator visibly noisy: this file
 * implements caliptra_mailbox_exec() in software for offline test/dev
 * usage only.  Production deployments MUST link against the real
 * Caliptra hardware mailbox via --disable-caliptra-sim plus an
 * integrator-supplied caliptra_mailbox_exec().
 *
 * Uses #pragma message rather than #warning so that builds running with
 * -Werror=cpp (the default for wolfSSL) still surface the advisory
 * without aborting the build. */
#if defined(__GNUC__) || defined(__clang__)
#pragma message ("caliptra_sim.c: software simulator only -- must --disable-caliptra-sim for production")
#endif

/* =========================================================================
 * Single mailbox-serialization mutex (HIGH-46 mitigation).
 *
 * The sim holds process-wide mutable state (sim_keys[], sim_sha[],
 * sim_aes[]); wrapping every caliptra_mailbox_exec() call in this mutex
 * makes those statics safe under default multi-threaded wolfSSL builds.
 * sim_mailbox_lock_init is a plain (non-atomic) flag: first-init must be
 * driven from a single thread via wc_caliptra_init() before any worker
 * thread calls caliptra_mailbox_exec().  See file header THREAD SAFETY.
 * ========================================================================= */
static wolfSSL_Mutex sim_mailbox_lock;
static int           sim_mailbox_lock_init = 0;

int  sim_mailbox_lock_init_once(void);
void sim_mailbox_lock_free_once(void);

int sim_mailbox_lock_init_once(void)
{
    if (sim_mailbox_lock_init)
        return 0;
    if (wc_InitMutex(&sim_mailbox_lock) != 0)
        return BAD_MUTEX_E;
    sim_mailbox_lock_init = 1;
    return 0;
}

void sim_mailbox_lock_free_once(void)
{
    if (!sim_mailbox_lock_init)
        return;
    (void)wc_FreeMutex(&sim_mailbox_lock);
    sim_mailbox_lock_init = 0;
}

/* Use INVALID_DEVID for all internal wolfSSL calls to avoid CryptoCb recursion.
 * WC_NO_DEVID is not defined in this wolfSSL build; INVALID_DEVID (-2) has
 * the same effect: bypass the CryptoCb framework. */
#ifndef WC_NO_DEVID
#define WC_NO_DEVID INVALID_DEVID
#endif

/* The Caliptra mailbox wire format uses little-endian byte order for all
 * multi-byte integer fields.  HTOLE32/LE32TOH convert between host byte order
 * and the LE wire format; on a LE host they are no-ops (zero overhead). */
#ifdef BIG_ENDIAN_ORDER
    #define HTOLE32(x)  ByteReverseWord32(x)
    #define LE32TOH(x)  ByteReverseWord32(x)
#else
    #define HTOLE32(x)  (x)
    #define LE32TOH(x)  (x)
#endif

/* SHA-256 is not a real Caliptra firmware command (CMB_SHA_ALG_SHA384=1,
 * CMB_SHA_ALG_SHA512=2 only).  The simulator accepts SHA-256 so that the
 * software-fallback path (CRYPTOCB_UNAVAILABLE returned by the port) can be
 * exercised; this local constant is never sent to real hardware. */
#define SIM_SHA_ALG_SHA256  0

/* =========================================================================
 * Internal helper: write LE uint32 to a byte buffer
 * ========================================================================= */

static void put_le32(byte* buf, word32 v)
{
    buf[0] = (byte)(v & 0xFF);
    buf[1] = (byte)((v >> 8)  & 0xFF);
    buf[2] = (byte)((v >> 16) & 0xFF);
    buf[3] = (byte)((v >> 24) & 0xFF);
}

static word32 get_le32(const byte* buf)
{
    return (word32)buf[0]
         | ((word32)buf[1] << 8)
         | ((word32)buf[2] << 16)
         | ((word32)buf[3] << 24);
}

/* =========================================================================
 * Key table (CMK simulation)
 * ========================================================================= */

#define SIM_MAX_KEYS      16
#define SIM_KEY_TYPE_NONE    0
#define SIM_KEY_TYPE_SYM     1   /* AES/HMAC symmetric key */
#define SIM_KEY_TYPE_ECC_PUB 2   /* P-384 public key: 48+48 bytes */
#define SIM_KEY_TYPE_ECC_PRV 3   /* P-384 private key: 48 bytes */

typedef struct {
    int    in_use;
    int    key_type;
    byte   key_data[96];  /* max P-384 pub key = 48+48 */
    word32 key_len;
} SimKey;

static SimKey sim_keys[SIM_MAX_KEYS];

/* CMK encodes key index: bytes[0..3] = LE uint32 index (1-based, 0=invalid)
 * rest of 128 bytes = 0 */

static int sim_key_alloc(void)
{
    int i;
    for (i = 0; i < SIM_MAX_KEYS; i++) {
        if (!sim_keys[i].in_use) {
            XMEMSET(&sim_keys[i], 0, sizeof(SimKey));
            sim_keys[i].in_use = 1;
            return i;   /* 0-based index */
        }
    }
    return -1;
}

static SimKey* sim_key_lookup(const byte cmk[128])
{
    word32 idx = get_le32(cmk);
    if (idx == 0 || idx > (word32)SIM_MAX_KEYS)
        return NULL;
    if (!sim_keys[idx - 1].in_use)
        return NULL;
    return &sim_keys[idx - 1];
}

static void sim_cmk_from_index(byte cmk[128], int idx_0based)
{
    XMEMSET(cmk, 0, 128);
    put_le32(cmk, (word32)(idx_0based + 1));
}

/* =========================================================================
 * SHA state table (streaming SHA)
 * ========================================================================= */

#define SIM_MAX_SHA_SLOTS 8

typedef enum { SHA_NONE = 0, SHA_256, SHA_384, SHA_512 } SimShaType;

typedef struct {
    int        in_use;
    SimShaType type;
    union {
        wc_Sha256 sha256;
        wc_Sha384 sha384;
        wc_Sha512 sha512;
    } u;
} SimShaSlot;

static SimShaSlot sim_sha[SIM_MAX_SHA_SLOTS];

/* context[0..3] = LE uint32 slot index (1-based) */

static int sim_sha_alloc(void)
{
    int i;
    for (i = 0; i < SIM_MAX_SHA_SLOTS; i++) {
        if (!sim_sha[i].in_use) {
            XMEMSET(&sim_sha[i], 0, sizeof(SimShaSlot));
            sim_sha[i].in_use = 1;
            return i;
        }
    }
    return -1;
}

static SimShaSlot* sim_sha_lookup(const byte ctx[200])
{
    word32 idx = get_le32(ctx);
    if (idx == 0 || idx > (word32)SIM_MAX_SHA_SLOTS)
        return NULL;
    if (!sim_sha[idx - 1].in_use)
        return NULL;
    return &sim_sha[idx - 1];
}

static void sim_sha_ctx_from_index(byte ctx[200], int idx_0based)
{
    XMEMSET(ctx, 0, 200);
    put_le32(ctx, (word32)(idx_0based + 1));
}

static void sim_sha_free(int idx_0based)
{
    SimShaSlot* slot = &sim_sha[idx_0based];
    if (!slot->in_use) return;
    switch (slot->type) {
        case SHA_256:  wc_Sha256Free(&slot->u.sha256); break;
        case SHA_384:  wc_Sha384Free(&slot->u.sha384); break;
        case SHA_512:  wc_Sha512Free(&slot->u.sha512); break;
        case SHA_NONE: break;
    }
    XMEMSET(slot, 0, sizeof(*slot));
}

/* =========================================================================
 * AES-GCM state table (streaming AES-GCM)
 * ========================================================================= */

#define SIM_MAX_AES_SLOTS   4
#define SIM_AES_MAX_AAD     4096
#define SIM_AES_MAX_DATA   (4096 * 4)

/* The sim's AAD buffer must be at least as large as the wire-format AAD
 * field (CMB_MAX_DATA_SIZE bytes); otherwise sim_handle_aes_*_init would
 * have to truncate or reject every maximum-sized AAD the real protocol
 * permits.  Trips at compile time if either constant drifts. */
wc_static_assert2(SIM_AES_MAX_AAD >= CMB_MAX_DATA_SIZE,
                  "sim AAD buffer smaller than wire-format AAD max");

typedef struct {
    int    in_use;
    int    enc;           /* 1=encrypt, 0=decrypt */
    byte   raw_key[32];
    byte   iv[12];
    byte   aad[SIM_AES_MAX_AAD];
    word32 aad_len;
    byte   data[SIM_AES_MAX_DATA];    /* ciphertext (dec) or plaintext (enc) */
    word32 data_len;
    /* For decrypt: accumulate decrypted plaintext so FINAL can re-verify */
    byte   plaintext[SIM_AES_MAX_DATA];
    word32 pt_len;
} SimAesSlot;

static SimAesSlot sim_aes[SIM_MAX_AES_SLOTS];

/* AES context[0..3] = LE uint32 slot index (1-based)
 * context[4..15] = IV (12 bytes) */

static int sim_aes_alloc(void)
{
    int i;
    for (i = 0; i < SIM_MAX_AES_SLOTS; i++) {
        if (!sim_aes[i].in_use) {
            XMEMSET(&sim_aes[i], 0, sizeof(SimAesSlot));
            sim_aes[i].in_use = 1;
            return i;
        }
    }
    return -1;
}

static SimAesSlot* sim_aes_lookup(const byte ctx[128])
{
    word32 idx = get_le32(ctx);
    if (idx == 0 || idx > (word32)SIM_MAX_AES_SLOTS)
        return NULL;
    if (!sim_aes[idx - 1].in_use)
        return NULL;
    return &sim_aes[idx - 1];
}

static void sim_aes_ctx_from_index(byte ctx[128], int idx_0based, const byte iv[12])
{
    XMEMSET(ctx, 0, 128);
    put_le32(ctx, (word32)(idx_0based + 1));
    if (iv != NULL)
        XMEMCPY(ctx + 4, iv, 12);
}

static void sim_aes_free(int idx_0based)
{
    /* Slot holds raw_key and recovered plaintext; ForceZero so an
     * optimising compiler cannot drop the wipe as dead-store. */
    wc_ForceZero(&sim_aes[idx_0based], sizeof(SimAesSlot));
}

/* =========================================================================
 * Random bytes via wolfSSL's RNG (portable across all supported platforms).
 * Returns 0 on success, non-zero on failure.
 * ========================================================================= */

static int sim_get_random(byte* buf, word32 len)
{
    WC_RNG rng;
    int    ret;

    if (buf == NULL && len > 0) return -1;
    if (len == 0)               return 0;

    ret = wc_InitRng_ex(&rng, NULL, WC_NO_DEVID);
    if (ret != 0) return -1;

    ret = wc_RNG_GenerateBlock(&rng, buf, len);
    (void)wc_FreeRng(&rng);
    return (ret == 0) ? 0 : -1;
}

/* =========================================================================
 * CM_IMPORT handler
 * ========================================================================= */

static int sim_handle_import(const CmImportReq* req, word32 req_len,
                             CmImportResp* resp)
{
    int idx;
    word32 key_len;

    (void)req_len;

    XMEMSET(resp, 0, sizeof(*resp));

    idx = sim_key_alloc();
    if (idx < 0) {
        resp->hdr.fips_status = HTOLE32(0xFF);
        return -1;
    }

    key_len = LE32TOH(req->input_size);
    if (key_len > 96) key_len = 96;  /* safety cap */

    sim_keys[idx].key_len = key_len;
    if (key_len > 0)
        XMEMCPY(sim_keys[idx].key_data, req->input, key_len);

    {
    word32 key_usage = LE32TOH(req->key_usage);
    switch (key_usage) {
        case 0:                   /* sim-internal "SYM" (Reserved on real hw) */
        case CMB_KEY_USAGE_HMAC:  /* 1 */
        case CMB_KEY_USAGE_AES:   /* 2 */
            sim_keys[idx].key_type = SIM_KEY_TYPE_SYM;
            break;
        case CMB_KEY_USAGE_ECDSA: /* 3: private = 48 bytes, public = 96 bytes */
            sim_keys[idx].key_type = (key_len <= 48)
                                     ? SIM_KEY_TYPE_ECC_PRV
                                     : SIM_KEY_TYPE_ECC_PUB;
            break;
        default:
            sim_keys[idx].key_type = SIM_KEY_TYPE_SYM;
            break;
    }
    }

    sim_cmk_from_index(resp->cmk.bytes, idx);
    return 0;
}

/* =========================================================================
 * CM_DELETE handler
 * ========================================================================= */

static int sim_handle_delete(const CmDeleteReq* req, word32 req_len,
                             CmDeleteResp* resp)
{
    word32 idx;
    (void)req_len;

    XMEMSET(resp, 0, sizeof(*resp));

    idx = get_le32(req->cmk.bytes);
    if (idx == 0 || idx > (word32)SIM_MAX_KEYS) {
        resp->hdr.fips_status = HTOLE32(0xFF);
        return -1;
    }
    idx--;  /* convert to 0-based */
    /* SimKey holds raw key material; ForceZero so an optimising compiler
     * cannot drop the wipe as dead-store. */
    wc_ForceZero(&sim_keys[idx], sizeof(SimKey));
    return 0;
}

/* =========================================================================
 * CM_SHA_INIT handler
 * ========================================================================= */

static int sim_handle_sha_init(const CmShaInitReq* req, word32 req_len,
                               CmShaInitResp* resp)
{
    int idx;
    SimShaSlot* slot;
    int ret = 0;

    (void)req_len;

    XMEMSET(resp, 0, sizeof(*resp));

    idx = sim_sha_alloc();
    if (idx < 0) {
        resp->hdr.fips_status = HTOLE32(0xFF);
        return -1;
    }
    slot = &sim_sha[idx];

    {
    word32 hash_alg = LE32TOH(req->hash_algorithm);
    word32 input_sz = LE32TOH(req->input_size);
    switch (hash_alg) {
        case SIM_SHA_ALG_SHA256:
            slot->type = SHA_256;
            ret = wc_InitSha256_ex(&slot->u.sha256, NULL, WC_NO_DEVID);
            if (ret == 0 && input_sz > 0)
                ret = wc_Sha256Update(&slot->u.sha256, req->input, input_sz);
            break;
        case CMB_SHA_ALG_SHA384:
            slot->type = SHA_384;
            ret = wc_InitSha384_ex(&slot->u.sha384, NULL, WC_NO_DEVID);
            if (ret == 0 && input_sz > 0)
                ret = wc_Sha384Update(&slot->u.sha384, req->input, input_sz);
            break;
        case CMB_SHA_ALG_SHA512:
            slot->type = SHA_512;
            ret = wc_InitSha512_ex(&slot->u.sha512, NULL, WC_NO_DEVID);
            if (ret == 0 && input_sz > 0)
                ret = wc_Sha512Update(&slot->u.sha512, req->input, input_sz);
            break;
        default:
            sim_sha_free(idx);
            resp->hdr.fips_status = HTOLE32(0xFF);
            return -1;
    }
    }

    if (ret != 0) {
        sim_sha_free(idx);
        resp->hdr.fips_status = HTOLE32(0xFF);
        return ret;
    }

    sim_sha_ctx_from_index(resp->context, idx);
    return 0;
}

/* =========================================================================
 * CM_SHA_UPDATE handler
 * ========================================================================= */

static int sim_handle_sha_update(const CmShaUpdateReq* req, word32 req_len,
                                 CmShaUpdateResp* resp)
{
    SimShaSlot* slot;
    int ret = 0;

    (void)req_len;

    XMEMSET(resp, 0, sizeof(*resp));

    slot = sim_sha_lookup(req->context);
    if (slot == NULL) {
        resp->hdr.fips_status = HTOLE32(0xFF);
        return -1;
    }

    {
    word32 input_sz = LE32TOH(req->input_size);
    if (input_sz > 0) {
        switch (slot->type) {
            case SHA_256:
                ret = wc_Sha256Update(&slot->u.sha256, req->input, input_sz);
                break;
            case SHA_384:
                ret = wc_Sha384Update(&slot->u.sha384, req->input, input_sz);
                break;
            case SHA_512:
                ret = wc_Sha512Update(&slot->u.sha512, req->input, input_sz);
                break;
            case SHA_NONE:
                resp->hdr.fips_status = HTOLE32(0xFF);
                return -1;
        }
    }
    }

    if (ret != 0) {
        resp->hdr.fips_status = HTOLE32(0xFF);
        return ret;
    }

    /* Copy context through (slot index preserved) */
    XMEMCPY(resp->context, req->context, CMB_SHA_CONTEXT_SIZE);
    return 0;
}

/* =========================================================================
 * CM_SHA_FINAL handler
 * ========================================================================= */

static int sim_handle_sha_final(const CmShaFinalReq* req, word32 req_len,
                                CmShaFinalResp* resp)
{
    SimShaSlot* slot;
    int slot_idx;
    int ret = 0;
    word32 digest_len = 0;

    (void)req_len;

    XMEMSET(resp, 0, sizeof(*resp));

    slot = sim_sha_lookup(req->context);
    if (slot == NULL) {
        resp->hdr.fips_status = HTOLE32(0xFF);
        return -1;
    }

    /* Get 0-based index for freeing later */
    slot_idx = (int)(get_le32(req->context) - 1);

    /* Process final chunk if any */
    {
    word32 input_sz = LE32TOH(req->input_size);
    if (input_sz > 0) {
        switch (slot->type) {
            case SHA_256:
                ret = wc_Sha256Update(&slot->u.sha256, req->input, input_sz);
                break;
            case SHA_384:
                ret = wc_Sha384Update(&slot->u.sha384, req->input, input_sz);
                break;
            case SHA_512:
                ret = wc_Sha512Update(&slot->u.sha512, req->input, input_sz);
                break;
            case SHA_NONE:
                resp->hdr.fips_status = HTOLE32(0xFF);
                return -1;
        }
        if (ret != 0) {
            resp->hdr.fips_status = HTOLE32(0xFF);
            return ret;
        }
    }
    }

    switch (slot->type) {
        case SHA_256:
            ret = wc_Sha256Final(&slot->u.sha256, resp->hash);
            digest_len = 32;
            break;
        case SHA_384:
            ret = wc_Sha384Final(&slot->u.sha384, resp->hash);
            digest_len = 48;
            break;
        case SHA_512:
            ret = wc_Sha512Final(&slot->u.sha512, resp->hash);
            digest_len = 64;
            break;
        case SHA_NONE:
            resp->hdr.fips_status = HTOLE32(0xFF);
            return -1;
    }

    sim_sha_free(slot_idx);

    if (ret != 0) {
        resp->hdr.fips_status = HTOLE32(0xFF);
        return ret;
    }

    resp->hdr.data_len = HTOLE32(digest_len);
    return 0;
}

/* =========================================================================
 * CM_RANDOM_GENERATE handler
 * ========================================================================= */

static int sim_handle_random_generate(const CmRandomGenerateReq* req,
                                      word32 req_len,
                                      CmRandomGenerateResp* resp)
{
    word32 size;
    (void)req_len;

    XMEMSET(resp, 0, sizeof(*resp));

    size = LE32TOH(req->size);
    if (size > (word32)CMB_MAX_DATA_SIZE)
        size = (word32)CMB_MAX_DATA_SIZE;

    if (sim_get_random(resp->data, size) != 0) {
        resp->hdr.fips_status = HTOLE32(0xFF);
        return -1;
    }

    resp->hdr.data_len = HTOLE32(size);
    return 0;
}

/* =========================================================================
 * CM_AES_GCM_ENCRYPT_INIT handler
 * ========================================================================= */

static int sim_handle_aes_enc_init(const CmAesGcmEncryptInitReq* req,
                                   word32 req_len,
                                   CmAesGcmEncryptInitResp* resp)
{
    SimKey* key;
    int idx;
    SimAesSlot* slot;
    byte iv[12];

    (void)req_len;

    XMEMSET(resp, 0, sizeof(*resp));

    key = sim_key_lookup(req->cmk.bytes);
    if (key == NULL) {
        resp->hdr.fips_status = HTOLE32(0xFF);
        return -1;
    }

    if (key->key_len != 32) {  /* Real Caliptra hw is AES-256 only */
        resp->hdr.fips_status = HTOLE32(0xFF);
        return -1;
    }

    idx = sim_aes_alloc();
    if (idx < 0) {
        resp->hdr.fips_status = HTOLE32(0xFF);
        return -1;
    }
    slot = &sim_aes[idx];
    slot->enc = 1;

    XMEMCPY(slot->raw_key, key->key_data, key->key_len);

    /* Generate random IV */
    if (sim_get_random(iv, 12) != 0) {
        sim_aes_free(idx);
        resp->hdr.fips_status = HTOLE32(0xFF);
        return -1;
    }
    XMEMCPY(slot->iv, iv, 12);

    /* Copy AAD; reject (don't silently truncate) oversized AAD so that
     * aad_len always reflects what's actually in slot->aad. */
    slot->aad_len = LE32TOH(req->aad_size);
    if (slot->aad_len > (word32)SIM_AES_MAX_AAD) {
        sim_aes_free(idx);
        resp->hdr.fips_status = HTOLE32(0xFF);
        return -1;
    }
    if (slot->aad_len > 0)
        XMEMCPY(slot->aad, req->aad, slot->aad_len);

    /* Write context: slot index + IV */
    sim_aes_ctx_from_index(resp->context, idx, iv);

    /* Return IV as u32[3] (raw bytes, same as the 12-byte IV) */
    XMEMCPY(resp->iv, iv, 12);

    return 0;
}

/* =========================================================================
 * CM_AES_GCM_ENCRYPT_UPDATE handler
 * ========================================================================= */

static int sim_handle_aes_enc_update(const CmAesGcmEncryptUpdateReq* req,
                                     word32 req_len,
                                     CmAesGcmEncryptUpdateResp* resp)
{
    SimAesSlot* slot;

    (void)req_len;

    XMEMSET(resp, 0, sizeof(*resp));

    slot = sim_aes_lookup(req->context);
    if (slot == NULL) {
        resp->hdr.fips_status = HTOLE32(0xFF);
        return -1;
    }

    /* Buffer plaintext */
    {
    word32 pt_sz = LE32TOH(req->plaintext_size);
    if (pt_sz > 0) {
        if (slot->data_len + pt_sz > (word32)SIM_AES_MAX_DATA) {
            resp->hdr.fips_status = HTOLE32(0xFF);
            return -1;
        }
        XMEMCPY(slot->data + slot->data_len, req->plaintext, pt_sz);
        slot->data_len += pt_sz;
    }
    }

    /* Defer encryption to FINAL; return empty ciphertext */
    XMEMCPY(resp->context, req->context, CMB_AES_GCM_ENCRYPTED_CTX_SIZE);
    resp->ciphertext_size = HTOLE32(0);
    return 0;
}

/* =========================================================================
 * CM_AES_GCM_ENCRYPT_FINAL handler
 * ========================================================================= */

static int sim_handle_aes_enc_final(const CmAesGcmEncryptFinalReq* req,
                                    word32 req_len,
                                    CmAesGcmEncryptFinalResp* resp)
{
    SimAesSlot* slot;
    int slot_idx;
    Aes aes;
    int ret;
    byte tag[16];
    word32 total_len;

    (void)req_len;

    XMEMSET(resp, 0, sizeof(*resp));

    slot = sim_aes_lookup(req->context);
    if (slot == NULL) {
        resp->hdr.fips_status = HTOLE32(0xFF);
        return -1;
    }
    slot_idx = (int)(get_le32(req->context) - 1);

    /* Append final plaintext chunk */
    {
    word32 pt_sz = LE32TOH(req->plaintext_size);
    if (pt_sz > 0) {
        if (slot->data_len + pt_sz > (word32)SIM_AES_MAX_DATA) {
            resp->hdr.fips_status = HTOLE32(0xFF);
            return -1;
        }
        XMEMCPY(slot->data + slot->data_len, req->plaintext, pt_sz);
        slot->data_len += pt_sz;
    }
    }

    total_len = slot->data_len;

    /* resp->ciphertext is sized for a single mailbox response, not the
     * full streaming-input cap.  The port always batches a single ENCRYPT
     * up-front (so total_len fits CMB_MAX_DATA_SIZE), but a misbehaving
     * direct caller could buffer more than that across multiple UPDATEs.
     * Reject before the wc_AesGcmEncrypt write overflows resp->ciphertext. */
    if (total_len > (word32)CMB_MAX_DATA_SIZE) {
        sim_aes_free(slot_idx);
        resp->hdr.fips_status = HTOLE32(0xFF);
        return -1;
    }

    /* Encrypt all buffered data at once */
    ret = wc_AesInit(&aes, NULL, WC_NO_DEVID);
    if (ret == 0) {
        ret = wc_AesGcmSetKey(&aes, slot->raw_key, 32);
    }
    if (ret == 0) {
        ret = wc_AesGcmEncrypt(&aes,
                               resp->ciphertext,
                               slot->data, total_len,
                               slot->iv, 12,
                               tag, 16,
                               slot->aad_len > 0 ? slot->aad : NULL,
                               slot->aad_len);
    }
    wc_AesFree(&aes);

    sim_aes_free(slot_idx);

    if (ret != 0) {
        resp->hdr.fips_status = HTOLE32(0xFF);
        return ret;
    }

    /* Write tag as u32[4] (raw bytes) */
    XMEMCPY(resp->tag, tag, 16);
    resp->ciphertext_size = HTOLE32(total_len);
    return 0;
}

/* =========================================================================
 * CM_AES_GCM_DECRYPT_INIT handler
 * ========================================================================= */

static int sim_handle_aes_dec_init(const CmAesGcmDecryptInitReq* req,
                                   word32 req_len,
                                   CmAesGcmDecryptInitResp* resp)
{
    SimKey* key;
    int idx;
    SimAesSlot* slot;

    (void)req_len;

    XMEMSET(resp, 0, sizeof(*resp));

    key = sim_key_lookup(req->cmk.bytes);
    if (key == NULL) {
        resp->hdr.fips_status = HTOLE32(0xFF);
        return -1;
    }

    if (key->key_len != 32) {  /* Real Caliptra hw is AES-256 only */
        resp->hdr.fips_status = HTOLE32(0xFF);
        return -1;
    }

    idx = sim_aes_alloc();
    if (idx < 0) {
        resp->hdr.fips_status = HTOLE32(0xFF);
        return -1;
    }
    slot = &sim_aes[idx];
    slot->enc = 0;

    XMEMCPY(slot->raw_key, key->key_data, key->key_len);

    /* IV supplied by caller as byte[12] stored in iv[3] (u32[3]) */
    XMEMCPY(slot->iv, req->iv, 12);

    /* Copy AAD; reject (don't silently truncate) oversized AAD so that
     * aad_len always reflects what's actually in slot->aad. */
    slot->aad_len = LE32TOH(req->aad_size);
    if (slot->aad_len > (word32)SIM_AES_MAX_AAD) {
        sim_aes_free(idx);
        resp->hdr.fips_status = HTOLE32(0xFF);
        return -1;
    }
    if (slot->aad_len > 0)
        XMEMCPY(slot->aad, req->aad, slot->aad_len);

    sim_aes_ctx_from_index(resp->context, idx, NULL);
    return 0;
}

/* =========================================================================
 * CM_AES_GCM_DECRYPT_UPDATE handler
 * ========================================================================= */

static int sim_handle_aes_dec_update(const CmAesGcmDecryptUpdateReq* req,
                                     word32 req_len,
                                     CmAesGcmDecryptUpdateResp* resp)
{
    SimAesSlot* slot;
    word32 chunk_sz;

    (void)req_len;

    XMEMSET(resp, 0, sizeof(*resp));

    slot = sim_aes_lookup(req->context);
    if (slot == NULL) {
        resp->hdr.fips_status = HTOLE32(0xFF);
        return -1;
    }

    chunk_sz = LE32TOH(req->ciphertext_size);

    /* The wire format caps a single UPDATE chunk at CMB_MAX_DATA_SIZE; the
     * response struct's plaintext field is sized accordingly.  Reject
     * oversized chunks before they reach the memcpy into resp->plaintext
     * below, which would otherwise overflow a 4096-byte buffer. */
    if (chunk_sz > (word32)CMB_MAX_DATA_SIZE) {
        resp->hdr.fips_status = HTOLE32(0xFF);
        return -1;
    }

    if (chunk_sz > 0) {
        Aes  aes;
        byte throwaway_tag[16];
        int  ret;

        /* Buffer ciphertext for later tag verification at FINAL */
        if (slot->data_len + chunk_sz > (word32)SIM_AES_MAX_DATA) {
            resp->hdr.fips_status = HTOLE32(0xFF);
            return -1;
        }
        XMEMCPY(slot->data + slot->data_len, req->ciphertext, chunk_sz);
        slot->data_len += chunk_sz;

        /* Recover plaintext via the GCM CTR-mode symmetry: feeding the
         * ciphertext back through wc_AesGcmEncrypt with the same key, IV,
         * and AAD produces the original plaintext as its output (because
         * the GCM keystream depends only on key+IV+counter, not on
         * direction).  The tag this call computes is over the ciphertext-
         * shaped input, not over the real ciphertext, so we discard it —
         * the real tag check happens at DECRYPT_FINAL by re-encrypting
         * the recovered plaintext (unchanged).
         *
         * This replaces an earlier approach that called wc_AesGcmDecrypt
         * with an all-zero tag and suppressed AES_GCM_AUTH_E, which relied
         * on the undocumented "output before auth" behaviour of
         * wc_AesGcmDecrypt.  The encrypt-based path has no such
         * dependency. */
        ret = wc_AesInit(&aes, NULL, WC_NO_DEVID);
        if (ret == 0)
            ret = wc_AesGcmSetKey(&aes, slot->raw_key, 32);
        if (ret == 0) {
            /* "Encrypt" the entire accumulated ciphertext to recover
             * plaintext.  (The port currently sends all data in one UPDATE,
             * so this also works for the streaming case.) */
            ret = wc_AesGcmEncrypt(&aes,
                                   slot->plaintext,
                                   slot->data, slot->data_len,
                                   slot->iv, 12,
                                   throwaway_tag, 16,
                                   slot->aad_len > 0 ? slot->aad : NULL,
                                   slot->aad_len);
            if (ret == 0)
                slot->pt_len = slot->data_len;
        }
        wc_AesFree(&aes);

        if (ret != 0) {
            resp->hdr.fips_status = HTOLE32(0xFF);
            return ret;
        }

        /* Return decrypted plaintext for the current chunk */
        resp->plaintext_size = HTOLE32(chunk_sz);
        XMEMCPY(resp->plaintext, slot->plaintext, chunk_sz);
    }

    XMEMCPY(resp->context, req->context, CMB_AES_GCM_ENCRYPTED_CTX_SIZE);
    return 0;
}

/* =========================================================================
 * CM_AES_GCM_DECRYPT_FINAL handler
 * ========================================================================= */

static int sim_handle_aes_dec_final(const CmAesGcmDecryptFinalReq* req,
                                     word32 req_len,
                                     CmAesGcmDecryptFinalResp* resp)
{
    SimAesSlot* slot;
    int slot_idx;
    Aes aes;
    int ret;
    byte tag[16];
    byte computed_tag[16];
    /* dummy_ct holds the re-encrypted ciphertext used solely as the
     * destination buffer for wc_AesGcmEncrypt during tag verification —
     * its contents are never read.  At SIM_AES_MAX_DATA (16 KB) it is too
     * large to live on the stack on constrained hosts.  Concurrent access
     * is serialised by sim_mailbox_lock (see file header THREAD SAFETY),
     * so a function-local static is safe and cheaper than per-call
     * heap allocation.  Not zero-initialised: any prior contents are
     * always fully overwritten by wc_AesGcmEncrypt below before any
     * subsequent read could occur (and even if not, the buffer is
     * never read at all). */
    static byte dummy_ct[SIM_AES_MAX_DATA];

    (void)req_len;

    XMEMSET(resp, 0, sizeof(*resp));

    slot = sim_aes_lookup(req->context);
    if (slot == NULL) {
        resp->hdr.fips_status = HTOLE32(0xFF);
        return -1;
    }
    slot_idx = (int)(get_le32(req->context) - 1);

    /* Note: the port sends ciphertext_size=0 in FINAL (no remaining data).
     * If there IS a final ciphertext chunk, handle it. */
    {
    word32 ct_sz = LE32TOH(req->ciphertext_size);
    if (ct_sz > 0) {
        if (slot->data_len + ct_sz > (word32)SIM_AES_MAX_DATA) {
            sim_aes_free(slot_idx);
            resp->hdr.fips_status = HTOLE32(0xFF);
            return -1;
        }
        XMEMCPY(slot->data + slot->data_len, req->ciphertext, ct_sz);
        slot->data_len += ct_sz;
    }
    }

    /* Extract the tag the caller wants us to verify */
    XMEMCPY(tag, req->tag, 16);

    /* Verify the tag by re-encrypting the plaintext we already computed
     * during DECRYPT_UPDATE.  The resulting computed_tag must match tag. */
    ret = wc_AesInit(&aes, NULL, WC_NO_DEVID);
    if (ret == 0)
        ret = wc_AesGcmSetKey(&aes, slot->raw_key, 32);
    if (ret == 0 && slot->pt_len > 0) {
        ret = wc_AesGcmEncrypt(&aes,
                               dummy_ct,
                               slot->plaintext, slot->pt_len,
                               slot->iv, 12,
                               computed_tag, 16,
                               slot->aad_len > 0 ? slot->aad : NULL,
                               slot->aad_len);
    } else if (ret == 0) {
        /* No plaintext (empty message): encrypt empty data to get tag */
        ret = wc_AesGcmEncrypt(&aes,
                               NULL,
                               NULL, 0,
                               slot->iv, 12,
                               computed_tag, 16,
                               slot->aad_len > 0 ? slot->aad : NULL,
                               slot->aad_len);
    }
    wc_AesFree(&aes);

    sim_aes_free(slot_idx);

    if (ret != 0) {
        /* Intentionally returns 0 (not ret) even though the re-encrypt
         * failed.  This matches real Caliptra firmware's behaviour for
         * CM_AES_GCM_DECRYPT_FINAL: errors are conveyed in the response
         * header's fips_status field, not in the mailbox transport-level
         * return code.  The caliptra_port.c decrypt handler reads
         * fips_status after the mailbox call (caliptra_port.c around
         * line 1013: WC_HW_E if fips_status != 0), so signalling via
         * fips_status=0xFF here is the correct simulation of the HW
         * error path.  Differs from other sim handlers that return the
         * error code directly because those handlers correspond to HW
         * commands that DO use the transport return for errors. */
        resp->hdr.fips_status = HTOLE32(0xFF);
        return 0;
    }

    /* Compare computed tag with provided tag in constant time so that the
     * sim does not leak the mismatch position via timing.  Mirrors real
     * firmware: fips_status=0 in both cases; tag_verified encodes the
     * result (1=match, 0=mismatch).
     * Source: cryptographic_mailbox.rs: resp.tag_verified = (computed==expected) as u32 */
    resp->tag_verified = HTOLE32((ConstantCompare(computed_tag, tag, 16) == 0) ? 1 : 0);

    return 0;
}

/* =========================================================================
 * CM_ECDSA_SIGN handler
 * ========================================================================= */

static int sim_handle_ecdsa_sign(const CmEcdsaSignReq* req, word32 req_len,
                                 CmEcdsaSignResp* resp)
{
    SimKey* key;
    ecc_key ecc;
    WC_RNG rng;
    byte sig_der[160];
    word32 sig_len = sizeof(sig_der);
    byte r[48], s[48];
    word32 rLen = 48, sLen = 48;
    int ret;

    (void)req_len;

    XMEMSET(resp, 0, sizeof(*resp));

    key = sim_key_lookup(req->cmk.bytes);
    if (key == NULL || key->key_type != SIM_KEY_TYPE_ECC_PRV) {
        resp->hdr.fips_status = HTOLE32(0xFF);
        return -1;
    }

    ret = wc_ecc_init_ex(&ecc, NULL, WC_NO_DEVID);
    if (ret != 0) {
        resp->hdr.fips_status = HTOLE32(0xFF);
        return ret;
    }

    /* Import private key for P-384 */
    ret = wc_ecc_import_private_key_ex(key->key_data, key->key_len,
                                       NULL, 0, &ecc, ECC_SECP384R1);
    if (ret != 0) {
        wc_ecc_free(&ecc);
        resp->hdr.fips_status = HTOLE32(0xFF);
        return ret;
    }

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        wc_ecc_free(&ecc);
        resp->hdr.fips_status = HTOLE32(0xFF);
        return ret;
    }

    {
    word32 msg_sz = LE32TOH(req->message_size);
    ret = wc_ecc_sign_hash(req->message, msg_sz,
                           sig_der, &sig_len, &rng, &ecc);
    }
    wc_FreeRng(&rng);
    wc_ecc_free(&ecc);

    if (ret != 0) {
        resp->hdr.fips_status = HTOLE32(0xFF);
        return ret;
    }

    /* Decode DER to raw r, s */
    XMEMSET(r, 0, 48);
    XMEMSET(s, 0, 48);
    ret = wc_ecc_sig_to_rs(sig_der, sig_len, r, &rLen, s, &sLen);
    if (ret != 0) {
        resp->hdr.fips_status = HTOLE32(0xFF);
        return ret;
    }

    /* Zero-pad r and s to 48 bytes (big-endian, left-pad with zeros) */
    if (rLen < 48) {
        byte tmp[48];
        XMEMSET(tmp, 0, 48);
        XMEMCPY(tmp + (48 - rLen), r, rLen);
        XMEMCPY(r, tmp, 48);
    }
    if (sLen < 48) {
        byte tmp[48];
        XMEMSET(tmp, 0, 48);
        XMEMCPY(tmp + (48 - sLen), s, sLen);
        XMEMCPY(s, tmp, 48);
    }

    XMEMCPY(resp->signature_r, r, 48);
    XMEMCPY(resp->signature_s, s, 48);
    return 0;
}

/* =========================================================================
 * CM_ECDSA_VERIFY handler
 * ========================================================================= */

static int sim_handle_ecdsa_verify(const CmEcdsaVerifyReq* req, word32 req_len,
                                   CmEcdsaVerifyResp* resp)
{
    SimKey* key;
    ecc_key ecc;
    byte sig_der[160];
    word32 sig_len = sizeof(sig_der);
    byte r[48], s[48];
    int verify_res = 0;
    int ret;

    (void)req_len;

    XMEMSET(resp, 0, sizeof(*resp));

    key = sim_key_lookup(req->cmk.bytes);
    if (key == NULL || key->key_type != SIM_KEY_TYPE_ECC_PUB) {
        resp->hdr.fips_status = HTOLE32(0xFF);
        return -1;
    }

    /* Encode raw r, s to DER */
    XMEMCPY(r, req->signature_r, 48);
    XMEMCPY(s, req->signature_s, 48);

    ret = wc_ecc_rs_raw_to_sig(r, 48, s, 48, sig_der, &sig_len);
    if (ret != 0) {
        resp->hdr.fips_status = HTOLE32(0xFF);
        return ret;
    }

    /* Import public key: x||y from key_data */
    ret = wc_ecc_init_ex(&ecc, NULL, WC_NO_DEVID);
    if (ret != 0) {
        resp->hdr.fips_status = HTOLE32(0xFF);
        return ret;
    }

    /* P-384 public key: first 48 bytes = x, next 48 bytes = y */
    if (key->key_len >= 96) {
        ret = wc_ecc_import_unsigned(&ecc,
                                     key->key_data,       /* Qx */
                                     key->key_data + 48,  /* Qy */
                                     NULL,                /* private (none) */
                                     ECC_SECP384R1);
    }
    else {
        wc_ecc_free(&ecc);
        resp->hdr.fips_status = HTOLE32(0xFF);
        return -1;
    }

    if (ret != 0) {
        wc_ecc_free(&ecc);
        resp->hdr.fips_status = HTOLE32(0xFF);
        return ret;
    }

    {
    word32 msg_sz = LE32TOH(req->message_size);
    ret = wc_ecc_verify_hash(sig_der, sig_len,
                             req->message, msg_sz,
                             &verify_res, &ecc);
    }
    wc_ecc_free(&ecc);

    if (ret != 0) {
        resp->hdr.fips_status = HTOLE32(0xFF);
        return ret;
    }

    if (verify_res != 1) {
        /* Real Caliptra firmware returns CmdFailure for invalid signatures
         * (Ecc384Result::SigVerifyFailed → RUNTIME_MAILBOX_SIGNATURE_MISMATCH).
         * The transport layer maps CmdFailure to SIG_VERIFY_E.
         * Simulate that behavior so the port exercises the same code path. */
        return SIG_VERIFY_E;
    }

    /* Valid signature: fips_status = 0 (FIPS_STATUS_APPROVED). */
    resp->hdr.fips_status = 0;
    return 0;
}

/* =========================================================================
 * CM_HMAC handler
 * ========================================================================= */

static int sim_handle_hmac(const CmHmacReq* req, word32 req_len,
                           CmHmacResp* resp)
{
    SimKey* key;
    Hmac hmac;
    int hmac_type;
    word32 mac_len;
    int ret;

    (void)req_len;

    XMEMSET(resp, 0, sizeof(*resp));

    key = sim_key_lookup(req->cmk.bytes);
    if (key == NULL) {
        resp->hdr.fips_status = HTOLE32(0xFF);
        return -1;
    }

    {
    word32 hash_alg = LE32TOH(req->hash_algorithm);
    switch (hash_alg) {
        case SIM_SHA_ALG_SHA256: hmac_type = WC_SHA256; mac_len = 32; break;
        case CMB_SHA_ALG_SHA384: hmac_type = WC_SHA384; mac_len = 48; break;
        case CMB_SHA_ALG_SHA512: hmac_type = WC_SHA512; mac_len = 64; break;
        default:
            resp->hdr.fips_status = HTOLE32(0xFF);
            return -1;
    }
    }

    ret = wc_HmacInit(&hmac, NULL, WC_NO_DEVID);
    if (ret != 0) {
        resp->hdr.fips_status = HTOLE32(0xFF);
        return ret;
    }

    {
    word32 data_sz = LE32TOH(req->data_size);
    ret = wc_HmacSetKey(&hmac, hmac_type, key->key_data, key->key_len);
    if (ret == 0 && data_sz > 0)
        ret = wc_HmacUpdate(&hmac, req->data, data_sz);
    }
    if (ret == 0)
        ret = wc_HmacFinal(&hmac, resp->mac);
    wc_HmacFree(&hmac);

    if (ret != 0) {
        resp->hdr.fips_status = HTOLE32(0xFF);
        return ret;
    }

    resp->hdr.data_len = HTOLE32(mac_len);
    return 0;
}

/* =========================================================================
 * caliptra_mailbox_exec — main dispatch (mutex-wrapped)
 *
 * The public entry point holds sim_mailbox_lock for the duration of the
 * command so the static slot tables (sim_keys/sim_sha/sim_aes) and the
 * function-local statics in handlers are accessed by at most one thread
 * at a time.  The mutex is initialised by wc_caliptra_init() — callers
 * must invoke that before the first concurrent mailbox operation.
 * ========================================================================= */

static int sim_mailbox_exec_locked(word32 cmd_id,
                                   const void* req, word32 req_len,
                                   void*       resp, word32 resp_len)
{
    /* MEDIUM-37: reject callers passing a too-small resp buffer for the
     * command they invoked.  The handlers below XMEMSET(resp, 0,
     * sizeof(*resp)) and dereference resp as a specific concrete type;
     * an undersized buffer would overflow into adjacent memory.  Real
     * Caliptra firmware reports a Mailbox::IncorrectResponseSize error
     * for this case — returning -1 is the closest sim-side analogue. */
    word32 expected_resp_sz;
    switch (cmd_id) {
        case CM_IMPORT:              expected_resp_sz = sizeof(CmImportResp); break;
        case CM_DELETE:              expected_resp_sz = sizeof(CmDeleteResp); break;
        case CM_SHA_INIT:            expected_resp_sz = sizeof(CmShaInitResp); break;
        case CM_SHA_UPDATE:          expected_resp_sz = sizeof(CmShaUpdateResp); break;
        case CM_SHA_FINAL:           expected_resp_sz = sizeof(CmShaFinalResp); break;
        case CM_RANDOM_GENERATE:     expected_resp_sz = sizeof(CmRandomGenerateResp); break;
        case CM_AES_GCM_ENCRYPT_INIT:    expected_resp_sz = sizeof(CmAesGcmEncryptInitResp); break;
        case CM_AES_GCM_ENCRYPT_UPDATE:  expected_resp_sz = sizeof(CmAesGcmEncryptUpdateResp); break;
        case CM_AES_GCM_ENCRYPT_FINAL:   expected_resp_sz = sizeof(CmAesGcmEncryptFinalResp); break;
        case CM_AES_GCM_DECRYPT_INIT:    expected_resp_sz = sizeof(CmAesGcmDecryptInitResp); break;
        case CM_AES_GCM_DECRYPT_UPDATE:  expected_resp_sz = sizeof(CmAesGcmDecryptUpdateResp); break;
        case CM_AES_GCM_DECRYPT_FINAL:   expected_resp_sz = sizeof(CmAesGcmDecryptFinalResp); break;
        case CM_ECDSA_SIGN:          expected_resp_sz = sizeof(CmEcdsaSignResp); break;
        case CM_ECDSA_VERIFY:        expected_resp_sz = sizeof(CmEcdsaVerifyResp); break;
        case CM_HMAC:                expected_resp_sz = sizeof(CmHmacResp); break;
        default:                     expected_resp_sz = 0; break;  /* unknown cmd; falls through */
    }
    if (expected_resp_sz != 0 && resp_len < expected_resp_sz)
        return -1;

    switch (cmd_id) {
        case CM_IMPORT:
            return sim_handle_import((const CmImportReq*)req, req_len,
                                     (CmImportResp*)resp);

        case CM_DELETE:
            return sim_handle_delete((const CmDeleteReq*)req, req_len,
                                     (CmDeleteResp*)resp);

        case CM_SHA_INIT:
            return sim_handle_sha_init((const CmShaInitReq*)req, req_len,
                                       (CmShaInitResp*)resp);

        case CM_SHA_UPDATE:
            return sim_handle_sha_update((const CmShaUpdateReq*)req, req_len,
                                         (CmShaUpdateResp*)resp);

        case CM_SHA_FINAL:
            return sim_handle_sha_final((const CmShaFinalReq*)req, req_len,
                                        (CmShaFinalResp*)resp);

        case CM_RANDOM_GENERATE:
            return sim_handle_random_generate((const CmRandomGenerateReq*)req,
                                              req_len,
                                              (CmRandomGenerateResp*)resp);

        case CM_AES_GCM_ENCRYPT_INIT:
            return sim_handle_aes_enc_init((const CmAesGcmEncryptInitReq*)req,
                                           req_len,
                                           (CmAesGcmEncryptInitResp*)resp);

        case CM_AES_GCM_ENCRYPT_UPDATE:
            return sim_handle_aes_enc_update((const CmAesGcmEncryptUpdateReq*)req,
                                             req_len,
                                             (CmAesGcmEncryptUpdateResp*)resp);

        case CM_AES_GCM_ENCRYPT_FINAL:
            return sim_handle_aes_enc_final((const CmAesGcmEncryptFinalReq*)req,
                                            req_len,
                                            (CmAesGcmEncryptFinalResp*)resp);

        case CM_AES_GCM_DECRYPT_INIT:
            return sim_handle_aes_dec_init((const CmAesGcmDecryptInitReq*)req,
                                           req_len,
                                           (CmAesGcmDecryptInitResp*)resp);

        case CM_AES_GCM_DECRYPT_UPDATE:
            return sim_handle_aes_dec_update((const CmAesGcmDecryptUpdateReq*)req,
                                             req_len,
                                             (CmAesGcmDecryptUpdateResp*)resp);

        case CM_AES_GCM_DECRYPT_FINAL:
            return sim_handle_aes_dec_final((const CmAesGcmDecryptFinalReq*)req,
                                            req_len,
                                            (CmAesGcmDecryptFinalResp*)resp);

        case CM_ECDSA_SIGN:
            return sim_handle_ecdsa_sign((const CmEcdsaSignReq*)req, req_len,
                                         (CmEcdsaSignResp*)resp);

        case CM_ECDSA_VERIFY:
            return sim_handle_ecdsa_verify((const CmEcdsaVerifyReq*)req, req_len,
                                           (CmEcdsaVerifyResp*)resp);

        case CM_HMAC:
            return sim_handle_hmac((const CmHmacReq*)req, req_len,
                                   (CmHmacResp*)resp);

        default:
            WOLFSSL_MSG_EX("caliptra_sim: unknown cmd_id 0x%08X", cmd_id);
            return -1;
    }
}

int caliptra_mailbox_exec(word32 cmd_id,
                          const void* req, word32 req_len,
                          void*       resp, word32 resp_len)
{
    int ret;

    if (!sim_mailbox_lock_init)
        return BAD_MUTEX_E;
    if (wc_LockMutex(&sim_mailbox_lock) != 0)
        return BAD_MUTEX_E;

    ret = sim_mailbox_exec_locked(cmd_id, req, req_len, resp, resp_len);

    (void)wc_UnLockMutex(&sim_mailbox_lock);
    return ret;
}

#endif /* WOLFSSL_CALIPTRA_SIM */
