/* caliptra_port.c — wolfSSL CryptoCb port for Caliptra Cryptographic Mailbox
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
 * wolfSSL CryptoCb port for the Caliptra hardware security module.
 *
 * Build guards: WOLFSSL_CALIPTRA && WOLF_CRYPTO_CB
 *
 * The integrator must supply:
 *   int caliptra_mailbox_exec(word32 cmd_id,
 *                             const void* req,  word32 req_len,
 *                             void*       resp, word32 resp_len);
 *
 * Keys for AES-GCM, HMAC, and ECDSA sign are supplied as CaliptraCmk handles
 * stored in the relevant object's devCtx field before the first operation.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_CALIPTRA) && defined(WOLF_CRYPTO_CB)

#include <wolfssl/wolfcrypt/port/caliptra/caliptra_port.h>
#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/hmac.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/misc.h>

/* aes->reg is wolfSSL's per-object IV register, used consistently across
 * AES streaming modes (CBC, CTR, etc.) to carry IV state between calls.
 * The Caliptra port stores the 12-byte server-generated IV here so it
 * survives wc_AesGcmEncrypt() and can be retrieved via
 * wc_caliptra_aesgcm_get_iv().  Verify at compile time that the field is
 * wide enough.  If this fires, the Aes struct layout has changed; update
 * wc_caliptra_aesgcm_get_iv() and the XMEMCPY into aes->reg below. */
wc_static_assert2(sizeof(((Aes*)0)->reg) >= 12u,
                  "Aes.reg too small for 12-byte Caliptra IV; "
                  "update wc_caliptra_aesgcm_get_iv");

/* The Caliptra mailbox wire format uses little-endian byte order for all
 * multi-byte integer fields.  HTOLE32/LE32TOH convert between host byte order
 * and the LE wire format; on a LE host they are no-ops (zero overhead).
 * Byte-blob fields (CaliptraCmk, context arrays, IV, tags, plaintext, keys)
 * are always accessed via XMEMCPY and are endian-neutral.
 * The checksum is also endian-neutral (it sums individual bytes). */
#ifdef BIG_ENDIAN_ORDER
    #define HTOLE32(x)  ByteReverseWord32(x)
    #define LE32TOH(x)  ByteReverseWord32(x)
#else
    #define HTOLE32(x)  (x)
    #define LE32TOH(x)  (x)
#endif

/* Safety invariant: caliptra_hmac() must return WC_HW_E, not
 * CRYPTOCB_UNAVAILABLE, so wolfSSL's wc_HmacUpdate/wc_HmacFinal never
 * silently fall through to software HMAC when a Caliptra key is loaded.
 *
 * Both functions gate software fallback on a single test (hmac.c):
 *   if (ret != CRYPTOCB_UNAVAILABLE) return ret;
 * WC_HW_E passes this test (WC_HW_E != CRYPTOCB_UNAVAILABLE), so both
 * calls return WC_HW_E immediately and the software path is never reached.
 * If the two values were ever equal, Update would return the error but
 * Final could fall through and produce a MAC over an unkeyed, empty state
 * — a silent authentication bypass.  The assertion below makes this
 * invariant a hard compile-time failure rather than a latent trap. */
wc_static_assert2(WC_HW_E != CRYPTOCB_UNAVAILABLE,
                  "WC_HW_E and CRYPTOCB_UNAVAILABLE must be distinct; "
                  "caliptra_hmac() relies on this for HMAC fallback safety");

#ifndef WOLF_CRYPTO_CB_FREE
#warning "WOLFSSL_CALIPTRA requires WOLF_CRYPTO_CB_FREE to avoid CaliptraShaCtx leaks; add it to user_settings.h or use --enable-caliptra"
#endif

/* =========================================================================
 * Internal helper: Caliptra mailbox request checksum
 *
 * The firmware verifies: sum(cmd_id.le_bytes) + sum(req[4..req_len]) + chksum == 0
 * i.e. chksum = -(sum(cmd_id.le_bytes) + sum(req[4..req_len])) mod 2^32
 *
 * Must be called with the final (possibly trimmed) req_len, after all
 * payload fields have been populated, and stored into req->hdr.chksum
 * immediately before caliptra_mailbox_exec().
 * ========================================================================= */

static word32 caliptra_req_chksum(word32 cmd_id, const void *req, word32 req_len)
{
    const byte *buf = (const byte*)req;
    word32 sum = 0;
    word32 i;
    sum += (byte)(cmd_id);
    sum += (byte)(cmd_id >> 8);
    sum += (byte)(cmd_id >> 16);
    sum += (byte)(cmd_id >> 24);
    for (i = sizeof(word32); i < req_len; i++)
        sum += buf[i];
    return 0u - sum;
}

/* Response checksum verification — deliberately omitted.
 *
 * Why not verified here:
 *   The Caliptra firmware guarantees integrity at the FIPS boundary.  The
 *   mailbox transport is memory-mapped (not a network interface), so a
 *   bit-flip attack on the response buffer requires physical access to RAM,
 *   which is outside this port's threat model.
 *
 * Formula (for integrators who want to add it in caliptra_mailbox_exec()):
 *   sum(resp[0..resp_len]) == 0  (mod 2^32)
 *   i.e. resp->hdr.chksum + sum of all bytes after the chksum field == 0.
 *   This differs from the request checksum in that there is no cmd_id term;
 *   the command ID is not echoed in the response header.
 *
 * If response integrity checking is required, verify inside
 * caliptra_mailbox_exec() after reading the response buffer, before
 * returning to this port. */

/* =========================================================================
 * CALIPTRA_ALLOC / CALIPTRA_FREE / CALIPTRA_OOM — mailbox buffer helpers
 *
 * Temporary request/response structs are 144–4232 B each, and each
 * operation issues 1–3 mailbox calls.  By default they are heap-allocated
 * (XMALLOC/XFREE) so large objects are not placed on the stack.
 *
 * Define WOLFSSL_CALIPTRA_STATIC_BUFFERS at build time to stack-allocate
 * instead, eliminating per-call heap pressure at the cost of stack depth:
 *   SHA-384/512 Init+Update+Final: up to ~8 KB (two buffers live at once)
 *   AES-GCM Encrypt/Decrypt:       up to ~4 KB per Init/Update/Final frame
 *   All other operations:           up to ~4 KB
 * Thread safety is unaffected — stack buffers are per-invocation.
 *
 * Usage pattern in each function:
 *
 *   #ifdef WOLFSSL_CALIPTRA_STATIC_BUFFERS
 *       TypeA req_s;   TypeB resp_s;   <-- stack buffers (stack path only)
 *   #endif
 *       TypeA* req  = NULL;            <-- pointer always declared
 *       TypeB* resp = NULL;
 *   ...
 *   CALIPTRA_ALLOC(TypeA, req_s,  req);
 *   CALIPTRA_ALLOC(TypeB, resp_s, resp);
 *   if (CALIPTRA_OOM(req) || CALIPTRA_OOM(resp)) { ret = MEMORY_E; goto lbl; }
 *   ...
 *   lbl:
 *       CALIPTRA_FREE(req);
 *       CALIPTRA_FREE(resp);
 *
 * In the stack path, CALIPTRA_ALLOC(T, buf, ptr) assigns ptr = &buf.
 * The T and buf arguments are silently discarded in the heap path.
 * ========================================================================= */
#ifdef WOLFSSL_CALIPTRA_STATIC_BUFFERS
    #define CALIPTRA_ALLOC(T, buf, ptr)   (ptr) = &(buf)
    #define CALIPTRA_FREE(ptr)            ((void)(ptr))
    #define CALIPTRA_OOM(ptr)             (0)
#else
    #define CALIPTRA_ALLOC(T, buf, ptr) \
        (ptr) = (T*)XMALLOC(sizeof(T), NULL, DYNAMIC_TYPE_TMP_BUFFER)
    #define CALIPTRA_FREE(ptr) \
        do { if ((ptr) != NULL) { \
            XFREE((ptr), NULL, DYNAMIC_TYPE_TMP_BUFFER); (ptr) = NULL; \
        } } while(0)
    #define CALIPTRA_OOM(ptr)             ((ptr) == NULL)
#endif

/* =========================================================================
 * Internal helper: SHA algorithm ID from wolfSSL hash type
 * ========================================================================= */

static int caliptra_sha_alg_from_type(enum wc_HashType hash_type)
{
    int type = (int)hash_type;
    /* SHA-256 is not supported by Caliptra firmware; return -1 so the caller
     * returns CRYPTOCB_UNAVAILABLE and wolfSSL falls back to software. */
    if (type == (int)WC_HASH_TYPE_SHA384) return CMB_SHA_ALG_SHA384;
    if (type == (int)WC_HASH_TYPE_SHA512) return CMB_SHA_ALG_SHA512;
    return -1;
}

/* =========================================================================
 * Internal helper: extract devCtx pointer from hash object
 *
 * All supported hash structs (wc_Sha256, wc_Sha512 = wc_Sha384) include
 * a void* devCtx field when WOLF_CRYPTO_CB is defined.  This helper hides
 * the type-specific casting.
 * ========================================================================= */

static void** caliptra_hash_devctx_ptr(wc_CryptoInfo* info)
{
    /* SHA-256 is intentionally absent: Caliptra firmware does not support it.
     * caliptra_sha_alg_from_type() returns -1 for SHA-256, so caliptra_hash()
     * returns CRYPTOCB_UNAVAILABLE before this function is ever reached for
     * that type. */
    switch (info->hash.type) {
#ifdef WOLFSSL_SHA384
        case WC_HASH_TYPE_SHA384:
            if (info->hash.sha384 != NULL)
                return (void**)&info->hash.sha384->devCtx;
            break;
#endif
#ifdef WOLFSSL_SHA512
        case WC_HASH_TYPE_SHA512:
            if (info->hash.sha512 != NULL)
                return (void**)&info->hash.sha512->devCtx;
            break;
#endif
        default:
            break;
    }
    return NULL;
}

/* =========================================================================
 * RNG handler
 * ========================================================================= */

static int caliptra_rng(wc_CryptoInfo* info)
{
    byte*   output    = info->rng.out;
    word32  remaining = info->rng.sz;
    word32  chunk;
    int     ret;

#ifdef WOLFSSL_CALIPTRA_STATIC_BUFFERS
    CmRandomGenerateReq  req_s;
    CmRandomGenerateResp resp_s;
#endif
    CmRandomGenerateReq*  req  = NULL;
    CmRandomGenerateResp* resp = NULL;

    if (output == NULL || remaining == 0)
        return BAD_FUNC_ARG;

    CALIPTRA_ALLOC(CmRandomGenerateReq,  req_s,  req);
    CALIPTRA_ALLOC(CmRandomGenerateResp, resp_s, resp);
    if (CALIPTRA_OOM(req) || CALIPTRA_OOM(resp)) {
        ret = MEMORY_E;
        goto rng_done;
    }

    ret = 0;
    while (remaining > 0) {
        chunk = (remaining < (word32)CMB_MAX_DATA_SIZE)
                    ? remaining
                    : (word32)CMB_MAX_DATA_SIZE;

        XMEMSET(req, 0, sizeof(*req));
        req->size       = HTOLE32(chunk);

        req->hdr.chksum = HTOLE32(caliptra_req_chksum(CM_RANDOM_GENERATE, req,
                                              (word32)sizeof(*req)));
        XMEMSET(resp, 0, sizeof(*resp));
        ret = caliptra_mailbox_exec(CM_RANDOM_GENERATE,
                                    req,  (word32)sizeof(*req),
                                    resp, (word32)sizeof(*resp));
        if (ret != 0)
            goto rng_done;

        if (LE32TOH(resp->hdr.fips_status) != 0) {
            ret = WC_HW_E;
            goto rng_done;
        }

        /* Firmware may return fewer bytes than requested; trust data_len.
         * The upper bound check (data_len > chunk) also bounds data_len
         * below sizeof(resp->data): chunk <= CMB_MAX_DATA_SIZE and
         * resp->data is exactly CMB_MAX_DATA_SIZE bytes, so the XMEMCPY
         * below cannot read past the end of resp->data. */
        {
            word32 rx_len = LE32TOH(resp->hdr.data_len);
            if (rx_len == 0 || rx_len > chunk) {
                ret = WC_HW_E;
                goto rng_done;
            }
            XMEMCPY(output, resp->data, rx_len);
            output    += rx_len;
            remaining -= rx_len;
        }
    }

rng_done:
    CALIPTRA_FREE(req);
    CALIPTRA_FREE(resp);
    return ret;
}

/* =========================================================================
 * SHA streaming handler — helpers
 *
 * caliptra_sha_do_init: allocate CaliptraShaCtx, send CM_SHA_INIT with an
 * optional first data chunk, store the opaque context cookie returned by
 * the firmware.  Owns init_req/init_resp entirely; frees them before return.
 * On failure *devctx_ptr is cleared and the allocated sha_ctx is freed.
 * ========================================================================= */

static int caliptra_sha_do_init(void** devctx_ptr, int alg_id,
                                const byte* data, word32 data_sz)
{
    CaliptraShaCtx* sha_ctx;
#ifdef WOLFSSL_CALIPTRA_STATIC_BUFFERS
    CmShaInitReq    init_req_s;
    CmShaInitResp   init_resp_s;
#endif
    CmShaInitReq*   init_req  = NULL;
    CmShaInitResp*  init_resp = NULL;
    word32          actual_len;
    int             ret;

    if (data_sz > 0 && data == NULL)
        return BAD_FUNC_ARG;

    /* sha_ctx persists beyond this function (stored in hash->devCtx);
     * it is always heap-allocated regardless of WOLFSSL_CALIPTRA_STATIC_BUFFERS. */
    sha_ctx = (CaliptraShaCtx*)XMALLOC(sizeof(CaliptraShaCtx),
                                        NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (sha_ctx == NULL)
        return MEMORY_E;
    XMEMSET(sha_ctx, 0, sizeof(*sha_ctx));

    CALIPTRA_ALLOC(CmShaInitReq,  init_req_s,  init_req);
    CALIPTRA_ALLOC(CmShaInitResp, init_resp_s, init_resp);
    if (CALIPTRA_OOM(init_req) || CALIPTRA_OOM(init_resp)) {
        ret = MEMORY_E;
        goto do_init_done;
    }

    XMEMSET(init_req, 0, sizeof(*init_req));
    init_req->hash_algorithm = HTOLE32((word32)alg_id);
    init_req->input_size     = HTOLE32(data_sz);
    if (data_sz > 0 && data != NULL)
        XMEMCPY(init_req->input, data, data_sz);

    actual_len = (word32)(sizeof(*init_req) - CMB_MAX_DATA_SIZE + data_sz);

    init_req->hdr.chksum = HTOLE32(caliptra_req_chksum(CM_SHA_INIT,
                                                init_req, actual_len));
    XMEMSET(init_resp, 0, sizeof(*init_resp));
    ret = caliptra_mailbox_exec(CM_SHA_INIT,
                                init_req,  actual_len,
                                init_resp, (word32)sizeof(*init_resp));
    if (ret != 0) goto do_init_done;
    if (LE32TOH(init_resp->hdr.fips_status) != 0) { ret = WC_HW_E; goto do_init_done; }

    XMEMCPY(sha_ctx->context, init_resp->context, CMB_SHA_CONTEXT_SIZE);

do_init_done:
    CALIPTRA_FREE(init_req);
    CALIPTRA_FREE(init_resp);
    if (ret == 0)
        *devctx_ptr = sha_ctx;
    else
        XFREE(sha_ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

/* =========================================================================
 * SHA streaming handler
 *
 * State machine uses CaliptraShaCtx* stored in hash_obj->devCtx.
 *   in != NULL                    → update (has_input): CM_SHA_INIT or CM_SHA_UPDATE
 *   in == NULL && digest != NULL  → final: CM_SHA_FINAL; free devCtx
 * ========================================================================= */

static int caliptra_hash(wc_CryptoInfo* info)
{
    void**          devctx_ptr;
    CaliptraShaCtx* sha_ctx;
    int             alg_id;
    int             ret = 0;
    int             has_input;

#ifdef WOLFSSL_CALIPTRA_STATIC_BUFFERS
    CmShaUpdateReq   upd_req_s;
    CmShaUpdateResp  upd_resp_s;
    CmShaFinalReq    final_req_s;
    CmShaFinalResp   final_resp_s;
#endif
    CmShaUpdateReq*  upd_req    = NULL;
    CmShaUpdateResp* upd_resp   = NULL;
    CmShaFinalReq*   final_req  = NULL;
    CmShaFinalResp*  final_resp = NULL;

    word32 actual_len;

    alg_id = caliptra_sha_alg_from_type(info->hash.type);
    if (alg_id < 0)
        return CRYPTOCB_UNAVAILABLE;

    devctx_ptr = caliptra_hash_devctx_ptr(info);
    if (devctx_ptr == NULL)
        return BAD_FUNC_ARG;

    sha_ctx   = (CaliptraShaCtx*)*devctx_ptr;
    has_input = (info->hash.in != NULL);
    /* has_input true  → Update path: add data (inSz may be 0 for empty chunk).
     * has_input false → Final path if digest != NULL; no-op if both are NULL. */

    if (has_input && info->hash.inSz > (word32)CMB_MAX_DATA_SIZE)
        return BAD_FUNC_ARG;

    if (has_input) {
        /* ---- Update path ---- */
        if (sha_ctx == NULL) {
            /* First update: send CM_SHA_INIT carrying the first data chunk. */
            ret = caliptra_sha_do_init(devctx_ptr, alg_id,
                                       info->hash.in, info->hash.inSz);
            if (ret != 0) goto hash_done;
            sha_ctx = (CaliptraShaCtx*)*devctx_ptr;
        }
        else {
            /* Subsequent update: call CM_SHA_UPDATE. */
            CALIPTRA_ALLOC(CmShaUpdateReq,  upd_req_s,  upd_req);
            CALIPTRA_ALLOC(CmShaUpdateResp, upd_resp_s, upd_resp);
            if (CALIPTRA_OOM(upd_req) || CALIPTRA_OOM(upd_resp)) {
                ret = MEMORY_E;
                goto hash_done;
            }

            XMEMSET(upd_req, 0, sizeof(*upd_req));
            XMEMCPY(upd_req->context, sha_ctx->context, CMB_SHA_CONTEXT_SIZE);
            upd_req->input_size = HTOLE32(info->hash.inSz);
            if (info->hash.inSz > 0)
                XMEMCPY(upd_req->input, info->hash.in, info->hash.inSz);

            actual_len = (word32)(sizeof(*upd_req) - CMB_MAX_DATA_SIZE
                                  + info->hash.inSz);

            upd_req->hdr.chksum = HTOLE32(caliptra_req_chksum(CM_SHA_UPDATE,
                                                       upd_req, actual_len));
            XMEMSET(upd_resp, 0, sizeof(*upd_resp));
            ret = caliptra_mailbox_exec(CM_SHA_UPDATE,
                                        upd_req,  actual_len,
                                        upd_resp, (word32)sizeof(*upd_resp));
            if (ret == 0 && LE32TOH(upd_resp->hdr.fips_status) != 0)
                ret = WC_HW_E;
            if (ret == 0)
                XMEMCPY(sha_ctx->context, upd_resp->context,
                        CMB_SHA_CONTEXT_SIZE);

            if (ret != 0) goto hash_done;
        }
    }
    else if (info->hash.digest != NULL) {
        /* ---- Final path ---- */
        word32 digest_len;

        /* sha_ctx is NULL when Final is called without any prior Update
         * (empty message).  Send CM_SHA_INIT with empty data first. */
        if (sha_ctx == NULL) {
            ret = caliptra_sha_do_init(devctx_ptr, alg_id, NULL, 0);
            if (ret != 0) goto hash_done;
            sha_ctx = (CaliptraShaCtx*)*devctx_ptr;
        }

        CALIPTRA_ALLOC(CmShaFinalReq,  final_req_s,  final_req);
        CALIPTRA_ALLOC(CmShaFinalResp, final_resp_s, final_resp);
        if (CALIPTRA_OOM(final_req) || CALIPTRA_OOM(final_resp)) {
            ret = MEMORY_E;
            goto hash_done;
        }

        XMEMSET(final_req, 0, sizeof(*final_req));
        XMEMCPY(final_req->context, sha_ctx->context, CMB_SHA_CONTEXT_SIZE);
        final_req->input_size = 0;  /* no last-chunk data */

        /* Trim: no trailing data bytes */
        actual_len = (word32)(sizeof(*final_req) - CMB_MAX_DATA_SIZE);

        final_req->hdr.chksum = HTOLE32(caliptra_req_chksum(CM_SHA_FINAL,
                                                     final_req, actual_len));
        XMEMSET(final_resp, 0, sizeof(*final_resp));
        ret = caliptra_mailbox_exec(CM_SHA_FINAL,
                                    final_req,  actual_len,
                                    final_resp, (word32)sizeof(*final_resp));
        if (ret != 0) goto hash_done;
        if (LE32TOH(final_resp->hdr.fips_status) != 0) { ret = WC_HW_E; goto hash_done; }

        /* Copy digest to caller's output buffer */
        {
            word32 expected_digest_len = (info->hash.type == WC_HASH_TYPE_SHA384)
                                    ? 48u : 64u;
            digest_len = LE32TOH(final_resp->hdr.data_len);
            if (digest_len != expected_digest_len) {
                ret = WC_HW_E;
                goto hash_done;
            }
            XMEMCPY(info->hash.digest, final_resp->hash, expected_digest_len);
        }

        /* Clean up per-object state */
        XFREE(sha_ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        *devctx_ptr = NULL;
        sha_ctx = NULL;
    }

hash_done:
    CALIPTRA_FREE(upd_req);
    CALIPTRA_FREE(upd_resp);
    CALIPTRA_FREE(final_req);
    CALIPTRA_FREE(final_resp);

    if (ret != 0) {
        /* On any error, release sha_ctx and clear the devCtx pointer so
         * subsequent calls do not use stale state.  The WC_ALGO_TYPE_FREE
         * handler covers the abort-before-final case when the application
         * frees the hash object without completing the digest. */
        if (*devctx_ptr != NULL) {
            XFREE(*devctx_ptr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            *devctx_ptr = NULL;
        }
    }

    return ret;
}

/* =========================================================================
 * HMAC handler (single-shot)
 *
 * The CaliptraCmk for the HMAC key must be stored in hmac->devCtx by the
 * application before calling wc_HmacUpdate/Final.
 * ========================================================================= */

static int caliptra_hmac(wc_CryptoInfo* info)
{
    /* CryptoCb convention: digest == NULL → Update call; digest != NULL → Final call. */
    Hmac* hmac = info->hmac.hmac;

    if (hmac == NULL)
        return BAD_FUNC_ARG;
    if (hmac->devCtx == NULL)
        return CRYPTOCB_UNAVAILABLE;
    /* devCtx is set: a Caliptra key is loaded.  Caliptra HMAC is single-shot
     * only; streaming via wc_HmacUpdate/Final is not supported.
     *
     * This function MUST return WC_HW_E, not CRYPTOCB_UNAVAILABLE.
     * wc_HmacUpdate() and wc_HmacFinal() (hmac.c) gate software fallback on:
     *   if (ret != CRYPTOCB_UNAVAILABLE) return ret;
     * WC_HW_E satisfies that test, so both calls return WC_HW_E immediately
     * without executing any software HMAC.  Returning CRYPTOCB_UNAVAILABLE
     * instead would let Final fall through to software HMAC over an unkeyed,
     * empty state — a silent authentication bypass.  See the static_assert
     * above (WC_HW_E != CRYPTOCB_UNAVAILABLE) which makes this a compile-time
     * guarantee rather than a documented assumption.
     *
     * wc_HmacFree() does not reach this function: the dispatcher handles
     * WC_ALGO_TYPE_FREE independently (returns 0 for non-hash types). */
    WOLFSSL_MSG("caliptra_hmac: Caliptra HMAC requires a single-shot "
                "request; streaming via CryptoCb is not supported. "
                "Use wc_caliptra_hmac() instead.");
    return WC_HW_E;
}

/* =========================================================================
 * wc_caliptra_hmac — public single-shot HMAC API
 * ========================================================================= */

int wc_caliptra_hmac(const CaliptraCmk* cmk,
                     int                hash_type,
                     const byte*        msg,
                     word32             msg_len,
                     byte*              mac_out,
                     word32*            mac_len)
{
#ifdef WOLFSSL_CALIPTRA_STATIC_BUFFERS
    CmHmacReq   req_s;
    CmHmacResp  resp_s;
#endif
    CmHmacReq*  req  = NULL;
    CmHmacResp* resp = NULL;
    word32      alg;
    word32      digest_sz;
    word32      actual_len;
    int         ret  = 0;

    if (cmk == NULL || mac_out == NULL || mac_len == NULL)
        return BAD_FUNC_ARG;
    if (msg == NULL && msg_len > 0)
        return BAD_FUNC_ARG;
    if (msg_len > (word32)CMB_MAX_DATA_SIZE)
        return BUFFER_E;

    switch (hash_type) {
#ifdef WOLFSSL_SHA384
        case WC_SHA384:
            alg       = CMB_SHA_ALG_SHA384;
            digest_sz = WC_SHA384_DIGEST_SIZE;
            break;
#endif
#ifdef WOLFSSL_SHA512
        case WC_SHA512:
            alg       = CMB_SHA_ALG_SHA512;
            digest_sz = WC_SHA512_DIGEST_SIZE;
            break;
#endif
        default:
            return BAD_FUNC_ARG;
    }
    if (*mac_len < digest_sz)
        return BUFFER_E;

    CALIPTRA_ALLOC(CmHmacReq,  req_s,  req);
    CALIPTRA_ALLOC(CmHmacResp, resp_s, resp);
    if (CALIPTRA_OOM(req) || CALIPTRA_OOM(resp)) {
        ret = MEMORY_E;
        goto hmac_done;
    }

    XMEMSET(req, 0, sizeof(*req));
    XMEMCPY(&req->cmk, cmk, sizeof(CaliptraCmk));
    req->hash_algorithm = HTOLE32(alg);
    req->data_size      = HTOLE32(msg_len);
    if (msg_len > 0)
        XMEMCPY(req->data, msg, msg_len);

    actual_len = (word32)(sizeof(*req) - CMB_MAX_DATA_SIZE + msg_len);
    req->hdr.chksum = HTOLE32(caliptra_req_chksum(CM_HMAC, req, actual_len));

    XMEMSET(resp, 0, sizeof(*resp));
    ret = caliptra_mailbox_exec(CM_HMAC, req, actual_len,
                                resp, (word32)sizeof(*resp));
    if (ret != 0) goto hmac_done;
    if (LE32TOH(resp->hdr.fips_status) != 0) { ret = WC_HW_E; goto hmac_done; }

    XMEMCPY(mac_out, resp->mac, digest_sz);
    *mac_len = digest_sz;

hmac_done:
    CALIPTRA_FREE(req);
    CALIPTRA_FREE(resp);
    if (ret != 0)
        XMEMSET(mac_out, 0, digest_sz);
    return ret;
}

/* =========================================================================
 * AES-GCM encrypt (single wolfSSL call → 3 Caliptra mailbox calls)
 *
 * The CaliptraCmk for the AES key must be stored in aes->devCtx.
 * Caliptra generates the IV; the server-generated IV is stored in
 * aes->reg[0..2] for the caller to retrieve (see README.md limitation).
 * ========================================================================= */

static int caliptra_aesgcm_encrypt(wc_CryptoInfo* info)
{
    Aes*         aes    = info->cipher.aesgcm_enc.aes;
    const byte*  in     = info->cipher.aesgcm_enc.in;
    byte*        out    = info->cipher.aesgcm_enc.out;
    word32       sz     = info->cipher.aesgcm_enc.sz;
    const byte*  iv     = info->cipher.aesgcm_enc.iv;
    word32       ivSz   = info->cipher.aesgcm_enc.ivSz;
    const byte*  authIn = info->cipher.aesgcm_enc.authIn;
    word32       authInSz = info->cipher.aesgcm_enc.authInSz;
    byte*        authTag  = info->cipher.aesgcm_enc.authTag;
    word32       authTagSz = info->cipher.aesgcm_enc.authTagSz;

#ifdef WOLFSSL_CALIPTRA_STATIC_BUFFERS
    CmAesGcmEncryptInitReq    init_req_s;
    CmAesGcmEncryptInitResp   init_resp_s;
    CmAesGcmEncryptUpdateReq  upd_req_s;
    CmAesGcmEncryptUpdateResp upd_resp_s;
    CmAesGcmEncryptFinalReq   final_req_s;
    CmAesGcmEncryptFinalResp  final_resp_s;
#endif
    CmAesGcmEncryptInitReq*    init_req    = NULL;
    CmAesGcmEncryptInitResp*   init_resp   = NULL;
    CmAesGcmEncryptUpdateReq*  upd_req     = NULL;
    CmAesGcmEncryptUpdateResp* upd_resp    = NULL;
    CmAesGcmEncryptFinalReq*   final_req   = NULL;
    CmAesGcmEncryptFinalResp*  final_resp  = NULL;

    const byte* ctx_for_final = NULL;  /* points to context to pass to Final */
    word32  actual_len;
    word32  out_offset = 0;
    int     ret = 0;

    if (aes == NULL)
        return BAD_FUNC_ARG;
    if (aes->devCtx == NULL)
        return CRYPTOCB_UNAVAILABLE;
    if (authInSz > (word32)CMB_MAX_DATA_SIZE)
        return BAD_FUNC_ARG;
    if (sz > (word32)CMB_MAX_DATA_SIZE)
        return BUFFER_E; /* Caliptra single-Update limit; chunked input not yet supported */
    if (sz > 0 && in == NULL)
        return BAD_FUNC_ARG;

    /* Caliptra generates the IV server-side; the caller-supplied iv/ivSz are
     * silently ignored.  wolfSSL's wc_AesGcmEncrypt requires ivSz > 0 as a
     * precondition, so callers must pass a placeholder (e.g., a 12-byte
     * zero buffer).  After a successful return, call wc_caliptra_aesgcm_get_iv()
     * to retrieve the actual 12-byte firmware-generated IV before passing it
     * to wc_AesGcmDecrypt(). */
    (void)iv;
    (void)ivSz;

    /* --- Step 1: Encrypt Init (AAD, CMK; IV generated by Caliptra) --- */
    CALIPTRA_ALLOC(CmAesGcmEncryptInitReq,  init_req_s,  init_req);
    CALIPTRA_ALLOC(CmAesGcmEncryptInitResp, init_resp_s, init_resp);
    if (CALIPTRA_OOM(init_req) || CALIPTRA_OOM(init_resp)) { ret = MEMORY_E; goto enc_done; }

    XMEMSET(init_req, 0, sizeof(*init_req));
    init_req->flags      = 0;
    XMEMCPY(&init_req->cmk, aes->devCtx, sizeof(CaliptraCmk));
    init_req->aad_size   = HTOLE32(authInSz);
    if (authInSz > 0 && authIn != NULL)
        XMEMCPY(init_req->aad, authIn, authInSz);

    actual_len = (word32)(sizeof(*init_req) - CMB_MAX_DATA_SIZE + authInSz);

    init_req->hdr.chksum = HTOLE32(caliptra_req_chksum(CM_AES_GCM_ENCRYPT_INIT,
                                                init_req, actual_len));
    XMEMSET(init_resp, 0, sizeof(*init_resp));
    ret = caliptra_mailbox_exec(CM_AES_GCM_ENCRYPT_INIT,
                                init_req,  actual_len,
                                init_resp, (word32)sizeof(*init_resp));
    if (ret != 0) goto enc_done;
    if (LE32TOH(init_resp->hdr.fips_status) != 0) { ret = WC_HW_E; goto enc_done; }

    /* Write the Caliptra-generated IV into aes->reg (wolfSSL's per-object
     * IV register) so it is available via wc_caliptra_aesgcm_get_iv().
     * Byte order: init_resp->iv is word32[3] typed [u32; 3] in the Rust API,
     * serialised via zerocopy #[repr(C)] on RISC-V LE with no byte-swapping.
     * LE u32 words in memory == the underlying byte sequence, so copying 12
     * raw bytes is correct.  The caller retrieves these bytes unchanged via
     * wc_caliptra_aesgcm_get_iv() and passes them back verbatim on decrypt.
     * Confirmed: caliptra/api/src/mailbox.rs CmAesGcmEncryptInitResp.iv */
    XMEMCPY(aes->reg, init_resp->iv, sizeof(init_resp->iv));

    /* --- Step 2: Encrypt Update (plaintext → ciphertext chunks) --- */
    if (sz > 0) {
        CALIPTRA_ALLOC(CmAesGcmEncryptUpdateReq,  upd_req_s,  upd_req);
        CALIPTRA_ALLOC(CmAesGcmEncryptUpdateResp, upd_resp_s, upd_resp);
        if (CALIPTRA_OOM(upd_req) || CALIPTRA_OOM(upd_resp)) { ret = MEMORY_E; goto enc_done; }

        XMEMSET(upd_req, 0, sizeof(*upd_req));
        XMEMCPY(upd_req->context, init_resp->context,
                CMB_AES_GCM_ENCRYPTED_CTX_SIZE);
        upd_req->plaintext_size = HTOLE32(sz);
        if (in != NULL)
            XMEMCPY(upd_req->plaintext, in, sz);

        actual_len = (word32)(sizeof(*upd_req) - CMB_MAX_DATA_SIZE + sz);

        upd_req->hdr.chksum = HTOLE32(caliptra_req_chksum(CM_AES_GCM_ENCRYPT_UPDATE,
                                                   upd_req, actual_len));
        XMEMSET(upd_resp, 0, sizeof(*upd_resp));
        ret = caliptra_mailbox_exec(CM_AES_GCM_ENCRYPT_UPDATE,
                                    upd_req,  actual_len,
                                    upd_resp, (word32)sizeof(*upd_resp));
        if (ret != 0) goto enc_done;
        if (LE32TOH(upd_resp->hdr.fips_status) != 0) { ret = WC_HW_E; goto enc_done; }
        {
            word32 ct_sz = LE32TOH(upd_resp->ciphertext_size);
            if (ct_sz > (word32)CMB_MAX_AES_GCM_OUTPUT_SIZE) {
                ret = WC_HW_E; goto enc_done;
            }

            /* Copy ciphertext to output */
            if (ct_sz > 0 && out != NULL) {
                word32 copy_sz = ct_sz;
                if (copy_sz > sz) copy_sz = sz;
                XMEMCPY(out, upd_resp->ciphertext, copy_sz);
                out_offset = copy_sz;
            }
        }
        ctx_for_final = upd_resp->context;
    }
    else {
        /* No plaintext: pass Init context directly to Final; skip Update
         * entirely to avoid a ~4 KB heap allocation for an empty message. */
        ctx_for_final = init_resp->context;
    }

    /* --- Step 3: Encrypt Final (last block, get tag) --- */
    CALIPTRA_ALLOC(CmAesGcmEncryptFinalReq,  final_req_s,  final_req);
    CALIPTRA_ALLOC(CmAesGcmEncryptFinalResp, final_resp_s, final_resp);
    if (CALIPTRA_OOM(final_req) || CALIPTRA_OOM(final_resp)) { ret = MEMORY_E; goto enc_done; }

    XMEMSET(final_req, 0, sizeof(*final_req));
    XMEMCPY(final_req->context, ctx_for_final,
            CMB_AES_GCM_ENCRYPTED_CTX_SIZE);
    final_req->plaintext_size = 0;  /* no remaining plaintext */

    actual_len = (word32)(sizeof(*final_req) - CMB_MAX_DATA_SIZE);

    final_req->hdr.chksum = HTOLE32(caliptra_req_chksum(CM_AES_GCM_ENCRYPT_FINAL,
                                                 final_req, actual_len));
    XMEMSET(final_resp, 0, sizeof(*final_resp));
    ret = caliptra_mailbox_exec(CM_AES_GCM_ENCRYPT_FINAL,
                                final_req,  actual_len,
                                final_resp, (word32)sizeof(*final_resp));
    if (ret != 0) goto enc_done;
    if (LE32TOH(final_resp->hdr.fips_status) != 0) { ret = WC_HW_E; goto enc_done; }

    /* Copy any final ciphertext bytes */
    {
        word32 fin_ct_sz = LE32TOH(final_resp->ciphertext_size);
        if (fin_ct_sz > 0 && out != NULL) {
            /* out_offset <= sz is guaranteed: copy_sz on line ~592 is capped to sz.
             * A firmware bug reporting more Final bytes than (sz - out_offset)
             * indicates a protocol violation; reject it. */
            if (fin_ct_sz > (word32)CMB_MAX_AES_GCM_OUTPUT_SIZE ||
                fin_ct_sz > sz - out_offset) {
                ret = WC_HW_E;
                goto enc_done;
            }
            XMEMCPY(out + out_offset, final_resp->ciphertext, fin_ct_sz);
        }
    }

    /* Copy authentication tag (tag[4] = u32[4] = 16 bytes) */
    if (authTag != NULL && authTagSz >= 16) {
        XMEMCPY(authTag, final_resp->tag, 16);
    }
    else if (authTag != NULL && authTagSz > 0 && authTagSz < 16) {
        XMEMCPY(authTag, final_resp->tag, authTagSz);
    }

enc_done:
    CALIPTRA_FREE(init_req);
    CALIPTRA_FREE(init_resp);
    CALIPTRA_FREE(upd_req);
    CALIPTRA_FREE(upd_resp);
    CALIPTRA_FREE(final_req);
    CALIPTRA_FREE(final_resp);
    return ret;
}

/* =========================================================================
 * AES-GCM decrypt (single wolfSSL call → 3 Caliptra mailbox calls)
 *
 * The CaliptraCmk for the AES key must be stored in aes->devCtx.
 * The caller provides the IV (12 bytes) in aesgcm_dec.iv.
 * ========================================================================= */

static int caliptra_aesgcm_decrypt(wc_CryptoInfo* info)
{
    Aes*         aes    = info->cipher.aesgcm_dec.aes;
    const byte*  in     = info->cipher.aesgcm_dec.in;
    byte*        out    = info->cipher.aesgcm_dec.out;
    word32       sz     = info->cipher.aesgcm_dec.sz;
    const byte*  iv     = info->cipher.aesgcm_dec.iv;
    const byte*  authIn = info->cipher.aesgcm_dec.authIn;
    word32       authInSz = info->cipher.aesgcm_dec.authInSz;
    const byte*  authTag  = info->cipher.aesgcm_dec.authTag;
    word32       authTagSz = info->cipher.aesgcm_dec.authTagSz;

#ifdef WOLFSSL_CALIPTRA_STATIC_BUFFERS
    CmAesGcmDecryptInitReq    init_req_s;
    CmAesGcmDecryptInitResp   init_resp_s;
    CmAesGcmDecryptUpdateReq  upd_req_s;
    CmAesGcmDecryptUpdateResp upd_resp_s;
    CmAesGcmDecryptFinalReq   final_req_s;
    CmAesGcmDecryptFinalResp  final_resp_s;
#endif
    CmAesGcmDecryptInitReq*    init_req    = NULL;
    CmAesGcmDecryptInitResp*   init_resp   = NULL;
    CmAesGcmDecryptUpdateReq*  upd_req     = NULL;
    CmAesGcmDecryptUpdateResp* upd_resp    = NULL;
    CmAesGcmDecryptFinalReq*   final_req   = NULL;
    CmAesGcmDecryptFinalResp*  final_resp  = NULL;

    const byte* ctx_for_final = NULL;
    word32  actual_len;
    int     ret = 0;

    if (aes == NULL)
        return BAD_FUNC_ARG;
    if (aes->devCtx == NULL)
        return CRYPTOCB_UNAVAILABLE;
    if (authInSz > (word32)CMB_MAX_DATA_SIZE)
        return BAD_FUNC_ARG;
    if (sz > (word32)CMB_MAX_DATA_SIZE)
        return BUFFER_E; /* Caliptra single-Update limit; chunked input not yet supported */
    if (sz > 0 && in == NULL)
        return BAD_FUNC_ARG;
    if (authTag == NULL && authTagSz > 0)
        return BAD_FUNC_ARG;
    if (iv == NULL)
        return BAD_FUNC_ARG;

    /* --- Step 1: Decrypt Init (IV, AAD, CMK) --- */
    CALIPTRA_ALLOC(CmAesGcmDecryptInitReq,  init_req_s,  init_req);
    CALIPTRA_ALLOC(CmAesGcmDecryptInitResp, init_resp_s, init_resp);
    if (CALIPTRA_OOM(init_req) || CALIPTRA_OOM(init_resp)) { ret = MEMORY_E; goto dec_done; }

    XMEMSET(init_req, 0, sizeof(*init_req));
    init_req->flags      = 0;
    XMEMCPY(&init_req->cmk, aes->devCtx, sizeof(CaliptraCmk));

    /* Copy 12-byte caller IV into iv[3] (three u32 words).
     * Byte order: the firmware reads init_req->iv as LEArray4x3 via a direct
     * bitwise copy with no byte-swapping (cryptographic_mailbox.rs:
     * `let cmd_iv: LEArray4x3 = cmd.iv.into()`).  On RISC-V LE, raw memcpy
     * of 12 bytes into a word32[3] field produces the correct LE u32 values.
     * A caller who obtained the IV from wc_caliptra_aesgcm_get_iv() and passes
     * it back here verbatim will have the IV interpreted identically to how
     * Caliptra generated it.
     * Confirmed: caliptra/api/src/mailbox.rs CmAesGcmDecryptInitReq.iv,
     *            caliptra/runtime/src/cryptographic_mailbox.rs cmd.iv.into() */
    XMEMCPY(init_req->iv, iv, 12);

    init_req->aad_size = HTOLE32(authInSz);
    if (authInSz > 0 && authIn != NULL)
        XMEMCPY(init_req->aad, authIn, authInSz);

    actual_len = (word32)(sizeof(*init_req) - CMB_MAX_DATA_SIZE + authInSz);

    init_req->hdr.chksum = HTOLE32(caliptra_req_chksum(CM_AES_GCM_DECRYPT_INIT,
                                                init_req, actual_len));
    XMEMSET(init_resp, 0, sizeof(*init_resp));
    ret = caliptra_mailbox_exec(CM_AES_GCM_DECRYPT_INIT,
                                init_req,  actual_len,
                                init_resp, (word32)sizeof(*init_resp));
    if (ret != 0) goto dec_done;
    if (LE32TOH(init_resp->hdr.fips_status) != 0) { ret = WC_HW_E; goto dec_done; }

    /* --- Step 2: Decrypt Update (ciphertext → plaintext) --- */
    if (sz > 0) {
        CALIPTRA_ALLOC(CmAesGcmDecryptUpdateReq,  upd_req_s,  upd_req);
        CALIPTRA_ALLOC(CmAesGcmDecryptUpdateResp, upd_resp_s, upd_resp);
        if (CALIPTRA_OOM(upd_req) || CALIPTRA_OOM(upd_resp)) { ret = MEMORY_E; goto dec_done; }

        XMEMSET(upd_req, 0, sizeof(*upd_req));
        XMEMCPY(upd_req->context, init_resp->context,
                CMB_AES_GCM_ENCRYPTED_CTX_SIZE);
        upd_req->ciphertext_size  = HTOLE32(sz);
        if (in != NULL)
            XMEMCPY(upd_req->ciphertext, in, sz);

        actual_len = (word32)(sizeof(*upd_req) - CMB_MAX_DATA_SIZE + sz);

        upd_req->hdr.chksum = HTOLE32(caliptra_req_chksum(CM_AES_GCM_DECRYPT_UPDATE,
                                                   upd_req, actual_len));
        XMEMSET(upd_resp, 0, sizeof(*upd_resp));
        ret = caliptra_mailbox_exec(CM_AES_GCM_DECRYPT_UPDATE,
                                    upd_req,  actual_len,
                                    upd_resp, (word32)sizeof(*upd_resp));
        if (ret != 0) goto dec_done;
        if (LE32TOH(upd_resp->hdr.fips_status) != 0) { ret = WC_HW_E; goto dec_done; }

        /* Copy plaintext to output */
        {
            word32 pt_sz = LE32TOH(upd_resp->plaintext_size);
            if (pt_sz > 0 && out != NULL) {
                word32 copy_sz = pt_sz;
                if (copy_sz > sz) copy_sz = sz;
                XMEMCPY(out, upd_resp->plaintext, copy_sz);
            }
        }
        ctx_for_final = upd_resp->context;
    }
    else {
        /* No ciphertext: pass Init context directly to Final; skip Update
         * entirely to avoid a ~4 KB allocation for an empty message. */
        ctx_for_final = init_resp->context;
    }

    /* --- Step 3: Decrypt Final (tag verification) --- */
    CALIPTRA_ALLOC(CmAesGcmDecryptFinalReq,  final_req_s,  final_req);
    CALIPTRA_ALLOC(CmAesGcmDecryptFinalResp, final_resp_s, final_resp);
    if (CALIPTRA_OOM(final_req) || CALIPTRA_OOM(final_resp)) { ret = MEMORY_E; goto dec_done; }

    XMEMSET(final_req, 0, sizeof(*final_req));
    XMEMCPY(final_req->context, ctx_for_final,
            CMB_AES_GCM_ENCRYPTED_CTX_SIZE);
    final_req->tag_len         = HTOLE32((authTagSz <= 16) ? authTagSz : 16);
    if (authTag != NULL)
        XMEMCPY(final_req->tag, authTag, (authTagSz <= 16) ? authTagSz : 16);
    final_req->ciphertext_size = 0;  /* no remaining ciphertext */

    /* Fixed size (no trailing data array to trim for empty final chunk) */
    actual_len = (word32)sizeof(*final_req) - CMB_MAX_DATA_SIZE;

    final_req->hdr.chksum = HTOLE32(caliptra_req_chksum(CM_AES_GCM_DECRYPT_FINAL,
                                                 final_req, actual_len));
    XMEMSET(final_resp, 0, sizeof(*final_resp));
    ret = caliptra_mailbox_exec(CM_AES_GCM_DECRYPT_FINAL,
                                final_req,  actual_len,
                                final_resp, (word32)sizeof(*final_resp));
    if (ret != 0) goto dec_done;
    if (LE32TOH(final_resp->hdr.fips_status) != 0) { ret = WC_HW_E; goto dec_done; }

    /* tag_verified == 0 means authentication failure (1 = tags match). */
    if (LE32TOH(final_resp->tag_verified) == 0)
        ret = AES_GCM_AUTH_E;

dec_done:
    CALIPTRA_FREE(init_req);
    CALIPTRA_FREE(init_resp);
    CALIPTRA_FREE(upd_req);
    CALIPTRA_FREE(upd_resp);
    CALIPTRA_FREE(final_req);
    CALIPTRA_FREE(final_resp);
    return ret;
}

/* =========================================================================
 * Cipher dispatcher
 * ========================================================================= */

static int caliptra_cipher(wc_CryptoInfo* info)
{
#ifdef HAVE_AESGCM
    if (info->cipher.type == WC_CIPHER_AES_GCM) {
        if (info->cipher.enc)
            return caliptra_aesgcm_encrypt(info);
        else
            return caliptra_aesgcm_decrypt(info);
    }
#endif
    return CRYPTOCB_UNAVAILABLE;
}

/* =========================================================================
 * ECDSA Sign handler
 *
 * key->devCtx must hold a CaliptraCmk* for the private key.
 * Output is DER-encoded: raw r||s from Caliptra is converted via
 * wc_ecc_rs_raw_to_sig().
 * ========================================================================= */

static int caliptra_ecdsa_sign(wc_CryptoInfo* info)
{
    ecc_key*     key    = info->pk.eccsign.key;
    const byte*  hash   = info->pk.eccsign.in;
    word32       hashSz = info->pk.eccsign.inlen;
    byte*        sigOut = info->pk.eccsign.out;
    word32*      sigLen = info->pk.eccsign.outlen;

#ifdef WOLFSSL_CALIPTRA_STATIC_BUFFERS
    CmEcdsaSignReq  req_s;
    CmEcdsaSignResp resp_s;
#endif
    CmEcdsaSignReq*  req  = NULL;
    CmEcdsaSignResp* resp = NULL;
    word32           actual_len;
    int              ret = 0;

    if (key == NULL || hash == NULL || sigOut == NULL || sigLen == NULL)
        return BAD_FUNC_ARG;
    if (key->devCtx == NULL)
        return CRYPTOCB_UNAVAILABLE;
    if (hashSz > (word32)CMB_MAX_DATA_SIZE)
        return BAD_FUNC_ARG;

    CALIPTRA_ALLOC(CmEcdsaSignReq,  req_s,  req);
    CALIPTRA_ALLOC(CmEcdsaSignResp, resp_s, resp);
    if (CALIPTRA_OOM(req) || CALIPTRA_OOM(resp)) { ret = MEMORY_E; goto sign_done; }

    XMEMSET(req, 0, sizeof(*req));
    XMEMCPY(&req->cmk, key->devCtx, sizeof(CaliptraCmk));
    req->message_size = HTOLE32(hashSz);
    if (hashSz > 0)
        XMEMCPY(req->message, hash, hashSz);

    actual_len = (word32)(sizeof(*req) - CMB_MAX_DATA_SIZE + hashSz);

    req->hdr.chksum = HTOLE32(caliptra_req_chksum(CM_ECDSA_SIGN, req, actual_len));
    XMEMSET(resp, 0, sizeof(*resp));
    ret = caliptra_mailbox_exec(CM_ECDSA_SIGN,
                                req,  actual_len,
                                resp, (word32)sizeof(*resp));
    if (ret != 0) goto sign_done;
    if (LE32TOH(resp->hdr.fips_status) != 0) { ret = WC_HW_E; goto sign_done; }

    /* Convert raw r||s (each 48 bytes, P-384) to DER-encoded signature. */
    ret = wc_ecc_rs_raw_to_sig(resp->signature_r, 48,
                                resp->signature_s, 48,
                                sigOut, sigLen);

sign_done:
    CALIPTRA_FREE(req);
    CALIPTRA_FREE(resp);
    return ret;
}

/* =========================================================================
 * ECDSA Verify handler
 *
 * Caliptra requires a CMK reference for the public key.  There are two paths:
 *
 * (a) key->devCtx holds a CaliptraCmk*: the pre-imported CMK is used directly.
 *     The application must call wc_caliptra_import_key(Qx||Qy, 96,
 *     CMB_KEY_USAGE_ECDSA, &cmk) and store the resulting CaliptraCmk in
 *     key->devCtx before calling wc_EccVerify().
 *
 * (b) key->devCtx is NULL: returns CRYPTOCB_UNAVAILABLE so wolfSSL falls back
 *     to software ECC verify using the raw public key coordinates in key.
 * ========================================================================= */

static int caliptra_ecdsa_verify(wc_CryptoInfo* info)
{
    ecc_key*     key    = info->pk.eccverify.key;
    const byte*  sig    = info->pk.eccverify.sig;
    word32       sigLen = info->pk.eccverify.siglen;
    const byte*  hash   = info->pk.eccverify.hash;
    word32       hashSz = info->pk.eccverify.hashlen;
    int*         res    = info->pk.eccverify.res;

    /* r and s raw buffers (P-384: 48 bytes each) */
    byte r[48], s[48];
    word32 rLen = 48, sLen = 48;

#ifdef WOLFSSL_CALIPTRA_STATIC_BUFFERS
    CmEcdsaVerifyReq  ver_req_s;
    CmEcdsaVerifyResp ver_resp_s;
#endif
    CmEcdsaVerifyReq*  ver_req  = NULL;
    CmEcdsaVerifyResp* ver_resp = NULL;

    word32       actual_len;
    int          ret = 0;

    if (key == NULL || sig == NULL || hash == NULL || res == NULL)
        return BAD_FUNC_ARG;
    if (hashSz > (word32)CMB_MAX_DATA_SIZE)
        return BAD_FUNC_ARG;

    /* Return CRYPTOCB_UNAVAILABLE before any work if no CMK is loaded.
     * Import the public key with wc_caliptra_import_key(Qx||Qy, 96,
     * CMB_KEY_USAGE_ECDSA, &cmk) and store the CaliptraCmk in key->devCtx
     * before calling wc_EccVerify().  If key->devCtx is NULL, wolfSSL
     * performs software ECC verification instead.
     * See README.md §"ECDSA verify" for the full workflow. */
    if (key->devCtx == NULL) {
        WOLFSSL_MSG("caliptra_ecdsa_verify: no pre-imported CMK; "
                    "falling back to software verify");
        return CRYPTOCB_UNAVAILABLE;
    }

    *res = 0;  /* default: invalid */

    /* Decode DER signature to raw r, s (pure ASN operation; no CryptoCb dispatch). */
    XMEMSET(r, 0, sizeof(r));
    XMEMSET(s, 0, sizeof(s));
    ret = wc_ecc_sig_to_rs(sig, sigLen, r, &rLen, s, &sLen);
    if (ret != 0)
        return ret;
    if (rLen > 48 || sLen > 48)
        return BAD_FUNC_ARG;

    /* Left-pad r and s to exactly 48 bytes if shorter */
    if (rLen < 48) {
        byte tmp[48];
        XMEMSET(tmp, 0, 48);
        XMEMCPY(tmp + (48 - rLen), r, rLen);
        XMEMCPY(r, tmp, 48);
        rLen = 48;
    }
    if (sLen < 48) {
        byte tmp[48];
        XMEMSET(tmp, 0, 48);
        XMEMCPY(tmp + (48 - sLen), s, sLen);
        XMEMCPY(s, tmp, 48);
        sLen = 48;
    }
    /* --- Verify --- */
    CALIPTRA_ALLOC(CmEcdsaVerifyReq,  ver_req_s,  ver_req);
    CALIPTRA_ALLOC(CmEcdsaVerifyResp, ver_resp_s, ver_resp);
    if (CALIPTRA_OOM(ver_req) || CALIPTRA_OOM(ver_resp)) { ret = MEMORY_E; goto ver_cleanup; }

    XMEMSET(ver_req, 0, sizeof(*ver_req));
    XMEMCPY(&ver_req->cmk, key->devCtx, sizeof(CaliptraCmk));
    XMEMCPY(ver_req->signature_r, r, 48);
    XMEMCPY(ver_req->signature_s, s, 48);
    ver_req->message_size = HTOLE32(hashSz);
    if (hashSz > 0 && hash != NULL)
        XMEMCPY(ver_req->message, hash, hashSz);

    actual_len = (word32)(sizeof(*ver_req) - CMB_MAX_DATA_SIZE + hashSz);

    ver_req->hdr.chksum = HTOLE32(caliptra_req_chksum(CM_ECDSA_VERIFY,
                                               ver_req, actual_len));
    XMEMSET(ver_resp, 0, sizeof(*ver_resp));
    ret = caliptra_mailbox_exec(CM_ECDSA_VERIFY,
                                ver_req,  actual_len,
                                ver_resp, (word32)sizeof(*ver_resp));

    /* Caliptra firmware signals ECDSA verification failure in two ways:
     *
     *  Real hardware: cm_ecdsa_verify() returns
     *    Err(CaliptraError::RUNTIME_MAILBOX_SIGNATURE_MISMATCH), which the
     *    runtime translates to MboxStatusE::CmdFailure with no response
     *    written.  The transport layer (caliptra_mailbox_exec) detects
     *    CmdFailure and MUST return SIG_VERIFY_E (not a generic error) so
     *    the port can distinguish verification failure from transport errors.
     *
     *  Simulator / transports that mimic response-header style:
     *    caliptra_mailbox_exec returns 0 and the result is encoded in
     *    ver_resp->hdr.fips_status (0 = valid, non-zero = invalid).
     *
     * Source: caliptra/runtime/src/cryptographic_mailbox.rs: cm_ecdsa_verify()
     *         (Ecc384Result::Success / Ecc384Result::SigVerifyFailed paths)
     *         caliptra/api/src/mailbox.rs: MailboxRespHeader::FIPS_STATUS_APPROVED = 0 */
    if (ret == SIG_VERIFY_E) {
        /* Hardware transport: signature cryptographically invalid.
         * Translate to CryptoCb convention: ret=0, *res=0. */
        *res = 0;
        ret  = 0;
        goto ver_cleanup;
    }
    if (ret != 0) goto ver_cleanup;

    /* Simulator / response-header path: result in fips_status. */
    *res = (LE32TOH(ver_resp->hdr.fips_status) == 0) ? 1 : 0;

ver_cleanup:
    CALIPTRA_FREE(ver_req);
    CALIPTRA_FREE(ver_resp);
    return ret;
}

/* =========================================================================
 * PK dispatcher
 * ========================================================================= */

static int caliptra_pk(wc_CryptoInfo* info)
{
    switch (info->pk.type) {
#if defined(HAVE_ECC) && defined(HAVE_ECC_SIGN)
        case WC_PK_TYPE_ECDSA_SIGN:
            return caliptra_ecdsa_sign(info);
#endif
#if defined(HAVE_ECC) && defined(HAVE_ECC_VERIFY)
        case WC_PK_TYPE_ECDSA_VERIFY:
            return caliptra_ecdsa_verify(info);
#endif
        /* ECDH is explicitly unsupported: Caliptra ECDH returns an opaque
         * Cmk, not raw shared-secret bytes required by the wolfSSL interface.
         * See README.md for details. */
        default:
            return CRYPTOCB_UNAVAILABLE;
    }
}

/* =========================================================================
 * Hash object free handler (WOLF_CRYPTO_CB_FREE)
 *
 * Called when the application frees a hash object (e.g. wc_Sha384Free())
 * that was using the Caliptra device.  If a CaliptraShaCtx was allocated
 * during a streaming hash that was aborted before Final, it must be freed
 * here to avoid a heap leak.
 *
 * info->free.type is the wc_HashType; info->free.obj is the hash struct ptr.
 * ========================================================================= */

/* WOLF_CRYPTO_CB_FREE: required to free CaliptraShaCtx on hash abort.
 * Without this, wc_Sha384Free/wc_Sha512Free before Final leaks devCtx. */
#ifdef WOLF_CRYPTO_CB_FREE
static int caliptra_hash_free(wc_CryptoInfo* info)
{
    void** devctx_ptr = NULL;

    /* SHA-256 is intentionally absent: see caliptra_hash_devctx_ptr(). */
    switch (info->free.type) {
#ifdef WOLFSSL_SHA384
        case WC_HASH_TYPE_SHA384: {
            wc_Sha384* s = (wc_Sha384*)info->free.obj;
            if (s != NULL) devctx_ptr = (void**)&s->devCtx;
            break;
        }
#endif
#ifdef WOLFSSL_SHA512
        case WC_HASH_TYPE_SHA512: {
            wc_Sha512* s = (wc_Sha512*)info->free.obj;
            if (s != NULL) devctx_ptr = (void**)&s->devCtx;
            break;
        }
#endif
        default:
            break;
    }

    if (devctx_ptr != NULL && *devctx_ptr != NULL) {
        XFREE(*devctx_ptr, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        *devctx_ptr = NULL;
    }
    return 0;
}
#endif /* WOLF_CRYPTO_CB_FREE */

/* =========================================================================
 * Top-level dispatcher
 * ========================================================================= */

int wc_caliptra_cb(int devId, wc_CryptoInfo* info, void* ctx)
{
    if (info == NULL)
        return BAD_FUNC_ARG;
    (void)devId;
    (void)ctx;

    switch (info->algo_type) {
        case WC_ALGO_TYPE_RNG:    return caliptra_rng(info);
        case WC_ALGO_TYPE_HASH:   return caliptra_hash(info);
        /* WC_ALGO_TYPE_HMAC is handled (not CRYPTOCB_UNAVAILABLE) so that
         * when a Caliptra CMK is loaded in hmac->devCtx a streaming call
         * returns WC_HW_E rather than silently falling back to software
         * HMAC with no key.  Use wc_caliptra_hmac() for the actual MAC. */
        case WC_ALGO_TYPE_HMAC:   return caliptra_hmac(info);
        case WC_ALGO_TYPE_CIPHER: return caliptra_cipher(info);
        case WC_ALGO_TYPE_PK:     return caliptra_pk(info);
#ifdef WOLF_CRYPTO_CB_FREE
        case WC_ALGO_TYPE_FREE:
            /* Free any per-object state allocated for streaming operations. */
            if (info->free.algo == WC_ALGO_TYPE_HASH)
                return caliptra_hash_free(info);
            return 0;
#endif /* WOLF_CRYPTO_CB_FREE */
        default:                  return CRYPTOCB_UNAVAILABLE;
    }
}

/* =========================================================================
 * Init / Cleanup
 * ========================================================================= */

/* wc_caliptra_init / wc_caliptra_cleanup are defined as weak symbols so that
 * platform-specific BSP code can override them without modifying wolfSSL.
 * A platform that must open a device file, map MMIO, or verify mailbox
 * reachability before first use should provide its own strong-linked
 * definitions.  The default no-op is correct for simulator and bare-metal
 * environments where the mailbox is available unconditionally.
 *
 * Note: device registration is NOT performed here.  After wc_caliptra_init()
 * succeeds, the application must register the callback:
 *   ret = wc_CryptoCb_RegisterDevice(WOLF_CALIPTRA_DEVID, wc_caliptra_cb, NULL);
 * Separating registration from init lets the integrator supply a custom
 * ctx pointer if needed. */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((weak))
#endif
int wc_caliptra_init(void)
{
    return 0;
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((weak))
#endif
int wc_caliptra_cleanup(void)
{
    return 0;
}

word32 wc_caliptra_req_chksum(word32 cmd_id, const void* req, word32 req_len)
{
    return HTOLE32(caliptra_req_chksum(cmd_id, req, req_len));
}

/* =========================================================================
 * Key Import / Delete utilities
 * ========================================================================= */

int wc_caliptra_aesgcm_get_iv(const Aes* aes, byte* iv_out, word32 iv_len)
{
    if (aes == NULL || iv_out == NULL || iv_len < 12)
        return BAD_FUNC_ARG;
    XMEMCPY(iv_out, aes->reg, 12);
    return 0;
}

int wc_caliptra_import_key(const byte*  key_data,
                            word32       key_len,
                            word32       key_usage,
                            CaliptraCmk* out_cmk)
{
#ifdef WOLFSSL_CALIPTRA_STATIC_BUFFERS
    CmImportReq  req_s;
    CmImportResp resp_s;
#endif
    CmImportReq*  req  = NULL;
    CmImportResp* resp = NULL;
    word32        actual_len;
    int           ret  = 0;

    if (key_data == NULL || out_cmk == NULL)
        return BAD_FUNC_ARG;
    if (key_len > (word32)CMB_MAX_DATA_SIZE)
        return BAD_FUNC_ARG;
    if (key_len == 0)
        return BAD_FUNC_ARG;

    CALIPTRA_ALLOC(CmImportReq,  req_s,  req);
    CALIPTRA_ALLOC(CmImportResp, resp_s, resp);
    if (CALIPTRA_OOM(req) || CALIPTRA_OOM(resp)) {
        ret = MEMORY_E;
        goto import_done;
    }

    XMEMSET(req, 0, sizeof(*req));
    req->key_usage  = HTOLE32(key_usage);
    req->input_size = HTOLE32(key_len);
    XMEMCPY(req->input, key_data, key_len);

    actual_len = (word32)(sizeof(*req) - CMB_MAX_DATA_SIZE + key_len);

    req->hdr.chksum = HTOLE32(caliptra_req_chksum(CM_IMPORT, req, actual_len));
    XMEMSET(resp, 0, sizeof(*resp));
    ret = caliptra_mailbox_exec(CM_IMPORT,
                                req,  actual_len,
                                resp, (word32)sizeof(*resp));
    if (ret != 0) goto import_done;
    if (LE32TOH(resp->hdr.fips_status) != 0) { ret = WC_HW_E; goto import_done; }

    XMEMCPY(out_cmk, &resp->cmk, sizeof(CaliptraCmk));

import_done:
    CALIPTRA_FREE(req);
    CALIPTRA_FREE(resp);
    return ret;
}

int wc_caliptra_delete_key(const CaliptraCmk* cmk)
{
#ifdef WOLFSSL_CALIPTRA_STATIC_BUFFERS
    CmDeleteReq  req_s;
    CmDeleteResp resp_s;
#endif
    CmDeleteReq*  req  = NULL;
    CmDeleteResp* resp = NULL;
    int           ret  = 0;

    if (cmk == NULL)
        return BAD_FUNC_ARG;

    CALIPTRA_ALLOC(CmDeleteReq,  req_s,  req);
    CALIPTRA_ALLOC(CmDeleteResp, resp_s, resp);
    if (CALIPTRA_OOM(req) || CALIPTRA_OOM(resp)) {
        ret = MEMORY_E;
        goto delete_done;
    }

    XMEMSET(req, 0, sizeof(*req));
    XMEMCPY(&req->cmk, cmk, sizeof(CaliptraCmk));

    req->hdr.chksum = HTOLE32(caliptra_req_chksum(CM_DELETE, req, (word32)sizeof(*req)));
    XMEMSET(resp, 0, sizeof(*resp));
    ret = caliptra_mailbox_exec(CM_DELETE,
                                req,  (word32)sizeof(*req),
                                resp, (word32)sizeof(*resp));
    if (ret != 0) goto delete_done;
    if (LE32TOH(resp->hdr.fips_status) != 0) ret = WC_HW_E;

delete_done:
    CALIPTRA_FREE(req);
    CALIPTRA_FREE(resp);
    return ret;
}

#endif /* defined(WOLFSSL_CALIPTRA) && defined(WOLF_CRYPTO_CB) */
