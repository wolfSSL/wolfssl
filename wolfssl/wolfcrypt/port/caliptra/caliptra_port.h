/* caliptra_port.h
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
 * wolfSSL CryptoCb port for Caliptra hardware security module.
 *
 * Struct layouts match the Caliptra mailbox.rs Rust API exactly:
 *  - CMK_SIZE_BYTES = 128 (NOT 64 — the opaque Cmk wrapper is 128 bytes)
 *  - No 'cmd' field in request structs — command ID sent via mailbox cmd register
 *  - CmShaFinalReq includes input_size + input[] (last data chunk)
 *  - AES-GCM encrypt: IV is generated server-side, returned in Init response
 *  - AES-GCM decrypt: IV is provided by caller in Init request as iv[3] (u32 words)
 *  - ECDH context is 76 bytes (CMB_ECDH_ENCRYPTED_CTX_SIZE)
 */

#ifndef WOLFSSL_PORT_CALIPTRA_H
#define WOLFSSL_PORT_CALIPTRA_H

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_CALIPTRA) && defined(WOLF_CRYPTO_CB)

#include <wolfssl/wolfcrypt/cryptocb.h>
#include <wolfssl/wolfcrypt/types.h>

/* =========================================================================
 * Device ID
 * ========================================================================= */

/* CryptoCb device ID for the Caliptra port.
 *
 * wolfSSL device IDs are int; the only reserved value is INVALID_DEVID (-2).
 * In-tree ports use small positive integers (1, 2, 3...) for named hardware;
 * this port uses 0x43414C50 ("CALP" in ASCII, 1128808528 as a signed int) to
 * avoid guessing a small integer that might collide with another port.
 *
 * Integrators who need a different value can override before including this
 * header:
 *   #define WOLF_CALIPTRA_DEVID  <your_value>
 *   #include <wolfssl/wolfcrypt/port/caliptra/caliptra_port.h> */
#ifndef WOLF_CALIPTRA_DEVID
#define WOLF_CALIPTRA_DEVID  0x43414C50
#endif

/* =========================================================================
 * CMK size
 * ========================================================================= */

/* Caliptra opaque key handle size in bytes.
 * Source: mailbox.rs: pub const CMK_SIZE_BYTES: usize = 128;
 * NOTE: older C references incorrectly used 64 — the correct value is 128. */
#define CMK_SIZE_BYTES       128

/* =========================================================================
 * Mailbox command IDs
 * These are sent via the mailbox command register, NOT embedded in structs.
 * ========================================================================= */

#define CM_IMPORT                  0x434D494D  /* "CMim" */
#define CM_DELETE                  0x434D444C  /* "CMdl" */
#define CM_SHA_INIT                0x434D5349  /* "CMSI" */
#define CM_SHA_UPDATE              0x434D5355  /* "CMSU" */
#define CM_SHA_FINAL               0x434D5346  /* "CMSF" */
#define CM_RANDOM_GENERATE         0x434D5247  /* "CMRG" */
#define CM_AES_GCM_ENCRYPT_INIT    0x434D4749  /* "CMGI" */
#define CM_AES_GCM_ENCRYPT_UPDATE  0x434D4755  /* "CMGU" */
#define CM_AES_GCM_ENCRYPT_FINAL   0x434D4746  /* "CMGF" */
#define CM_AES_GCM_DECRYPT_INIT    0x434D4449  /* "CMDI" */
#define CM_AES_GCM_DECRYPT_UPDATE  0x434D4455  /* "CMDU" */
#define CM_AES_GCM_DECRYPT_FINAL   0x434D4446  /* "CMDF" */
#define CM_ECDSA_PUBLIC_KEY        0x434D4550  /* "CMEP" */
#define CM_ECDSA_SIGN              0x434D4553  /* "CMES" */
#define CM_ECDSA_VERIFY            0x434D4556  /* "CMEV" */
#define CM_ECDH_GENERATE           0x434D4547  /* "CMEG" */
#define CM_ECDH_FINISH             0x434D4546  /* "CMEF" */
#define CM_HMAC                    0x434D484D  /* "CMHM" */
#define CM_HKDF_EXTRACT            0x434D4B54  /* "CMKT" */
#define CM_HKDF_EXPAND             0x434D4B50  /* "CMKP" */

/* =========================================================================
 * Mailbox protocol constants
 * ========================================================================= */

/* Maximum data payload per mailbox message (MAX_CMB_DATA_SIZE in Rust). */
#define CMB_MAX_DATA_SIZE               4096

/* SHA opaque context blob size returned by Init/Update, consumed by Update/Final. */
#define CMB_SHA_CONTEXT_SIZE            200

/* AES-GCM opaque encrypted context size (CMB_AES_GCM_ENCRYPTED_CONTEXT_SIZE). */
#define CMB_AES_GCM_ENCRYPTED_CTX_SIZE  128

/* ECDH opaque encrypted ephemeral keypair context size.
 * 76 bytes. Source: mailbox.rs CMB_ECDH_ENCRYPTED_CTX_SIZE. */
#define CMB_ECDH_ENCRYPTED_CTX_SIZE      76

/* Maximum HMAC output size (SHA-512 produces 64 bytes). */
#define CMB_HMAC_MAX_SIZE                64

/* ECDH public key exchange data: Qx || Qy for P-384 = 48 + 48 = 96 bytes. */
#define CMB_ECDH_EXCHANGE_DATA_SIZE      96

/* Maximum AES-GCM output size = plaintext + 16-byte authentication tag. */
#define CMB_MAX_AES_GCM_OUTPUT_SIZE    4112


/* Hash algorithm identifiers used in hash_algorithm fields.
 * Values match CmHashAlgorithm in Caliptra mailbox.rs:
 *   Sha384 = 1, Sha512 = 2.  SHA-256 is not supported by the firmware. */
#define CMB_SHA_ALG_SHA384  1
#define CMB_SHA_ALG_SHA512  2

/* Key usage identifiers matching CmKeyUsage in Caliptra mailbox.rs:
 *   Hmac = 1, Aes = 2, Ecdsa = 3, Mldsa = 4, Mlkem = 5.
 * NOTE: 0 (Reserved) is invalid and will be rejected by the firmware.
 * Firmware key size constraints:
 *   Aes:   32 bytes; Hmac: 48 or 64 bytes; Ecdsa: 48 bytes; Mlkem: 64 bytes */
#define CMB_KEY_USAGE_HMAC    1
#define CMB_KEY_USAGE_AES     2
#define CMB_KEY_USAGE_ECDSA   3
#define CMB_KEY_USAGE_MLDSA   4
#define CMB_KEY_USAGE_MLKEM   5

/* =========================================================================
 * Header types
 * These map directly to MailboxReqHeader / MailboxRespHeader in mailbox.rs.
 * ========================================================================= */

/* Request header: checksum only. Command ID is in the mailbox command register. */
typedef struct {
    word32 chksum;
} CmReqHeader;

/* Fixed-size response header. */
typedef struct {
    word32 chksum;
    word32 fips_status;
} CmRespHeader;

/* Variable-size response header; data_len carries the useful byte count. */
typedef struct {
    word32 chksum;
    word32 fips_status;
    word32 data_len;
} CmRespHeaderVarSize;

/* =========================================================================
 * Opaque key handle (Cmk)
 * ========================================================================= */

/* 128-byte opaque Caliptra key reference (returned by CM_IMPORT, etc.).
 * Treat as an opaque blob; do not interpret the internal layout. */
typedef struct {
    byte bytes[CMK_SIZE_BYTES];
} CaliptraCmk;

/* =========================================================================
 * SHA streaming structures
 * =========================================================================
 *
 * Three-phase protocol: Init -> zero or more Updates -> Final.
 * The 'context' blob is an opaque server-side cookie passed back
 * on every subsequent call.  No 'cmd' field — see command register.
 */

/* CM_SHA_INIT request. */
typedef struct {
    CmReqHeader hdr;
    word32      hash_algorithm;         /* CMB_SHA_ALG_SHA384/512 */
    word32      input_size;
    byte        input[CMB_MAX_DATA_SIZE];
} CmShaInitReq;

/* CM_SHA_INIT response (also reused for CM_SHA_UPDATE response). */
typedef struct {
    CmRespHeader hdr;
    byte         context[CMB_SHA_CONTEXT_SIZE];
} CmShaInitResp;

/* Alias: CM_SHA_UPDATE response reuses the same layout as Init response. */
typedef CmShaInitResp CmShaUpdateResp;

/* CM_SHA_UPDATE request. */
typedef struct {
    CmReqHeader hdr;
    byte        context[CMB_SHA_CONTEXT_SIZE];
    word32      input_size;
    byte        input[CMB_MAX_DATA_SIZE];
} CmShaUpdateReq;

/* CM_SHA_FINAL request.
 * Final also carries the last data chunk (input_size + input[]).
 * The C reference that omits these fields is incorrect. */
typedef struct {
    CmReqHeader hdr;
    byte        context[CMB_SHA_CONTEXT_SIZE];
    word32      input_size;             /* byte count of last input chunk */
    byte        input[CMB_MAX_DATA_SIZE];
} CmShaFinalReq;

/* CM_SHA_FINAL response.
 * hdr.data_len carries the digest length; field name is 'hash' not 'digest'. */
typedef struct {
    CmRespHeaderVarSize hdr;            /* hdr.data_len = digest length in bytes */
    byte                hash[64];       /* SHA-512 max; smaller digests use prefix */
} CmShaFinalResp;

/* =========================================================================
 * AES-GCM streaming structures
 * =========================================================================
 *
 * Encrypt: IV is generated server-side and returned in EncryptInitResp.
 * Decrypt: caller provides IV as three big-endian u32 words in DecryptInitReq.
 * Both paths use an opaque encrypted context blob between calls.
 */

/* CM_AES_GCM_ENCRYPT_INIT request.
 * IV is NOT provided by caller — Caliptra generates it and returns it. */
typedef struct {
    CmReqHeader  hdr;
    word32       flags;                 /* opaque flags field (present in Rust API) */
    CaliptraCmk  cmk;                  /* 128-byte key vault reference */
    word32       aad_size;
    byte         aad[CMB_MAX_DATA_SIZE];
} CmAesGcmEncryptInitReq;

/* CM_AES_GCM_ENCRYPT_INIT response.
 * iv[3]: server-generated IV as three u32 words (12 bytes total).
 *
 * Endianness: Caliptra is RISC-V little-endian; iv is typed [u32; 3] in the
 * Rust API and serialised via zerocopy #[repr(C)] with no byte-swapping.
 * On a LE host, LE u32 words in memory are identical to the underlying byte
 * sequence, so XMEMCPY(dst, iv, 12) copies the 12 IV bytes in the correct
 * order regardless of whether dst is typed as byte[] or word32[].
 * Source: caliptra/api/src/mailbox.rs CmAesGcmEncryptInitResp ([u32; 3]),
 *         caliptra/runtime/src/cryptographic_mailbox.rs (resp.iv assignment) */
typedef struct {
    CmRespHeader hdr;
    byte         context[CMB_AES_GCM_ENCRYPTED_CTX_SIZE];
    word32       iv[3];                 /* Caliptra-generated IV; caller must save */
} CmAesGcmEncryptInitResp;

/* CM_AES_GCM_DECRYPT_INIT request.
 * Caller provides the IV used during encryption (must match).
 *
 * Endianness: iv[3] is typed [u32; 3] in the Rust API (same as EncryptInitResp).
 * The firmware converts it to LEArray4x3 via a direct bitwise copy with no
 * byte-swapping (cryptographic_mailbox.rs: `let cmd_iv: LEArray4x3 = cmd.iv.into()`).
 * Copying the 12 IV bytes received from wc_caliptra_aesgcm_get_iv back into
 * this field with XMEMCPY(iv, caller_iv, 12) is byte-order-correct.
 * Source: caliptra/api/src/mailbox.rs CmAesGcmDecryptInitReq ([u32; 3]),
 *         caliptra/runtime/src/cryptographic_mailbox.rs (cmd.iv.into()) */
typedef struct {
    CmReqHeader  hdr;
    word32       flags;
    CaliptraCmk  cmk;
    word32       iv[3];                 /* caller-supplied IV for decryption */
    word32       aad_size;
    byte         aad[CMB_MAX_DATA_SIZE];
} CmAesGcmDecryptInitReq;

/* CM_AES_GCM_DECRYPT_INIT response.
 * firmware also returns iv[3] (12 bytes) after the context, making
 * the layout identical to CmAesGcmEncryptInitResp (148 bytes total). */
typedef struct {
    CmRespHeader hdr;
    byte         context[CMB_AES_GCM_ENCRYPTED_CTX_SIZE];
    word32       iv[3];                 /* echo of caller-supplied IV */
} CmAesGcmDecryptInitResp;

/* CM_AES_GCM_ENCRYPT_UPDATE request. */
typedef struct {
    CmReqHeader  hdr;
    byte         context[CMB_AES_GCM_ENCRYPTED_CTX_SIZE];
    word32       plaintext_size;
    byte         plaintext[CMB_MAX_DATA_SIZE];
} CmAesGcmEncryptUpdateReq;

/* CM_AES_GCM_ENCRYPT_UPDATE response.
 * ciphertext buffer is CMB_MAX_AES_GCM_OUTPUT_SIZE (4112) to accommodate tag. */
typedef struct {
    CmRespHeader hdr;
    byte         context[CMB_AES_GCM_ENCRYPTED_CTX_SIZE];
    word32       ciphertext_size;
    byte         ciphertext[CMB_MAX_AES_GCM_OUTPUT_SIZE];
} CmAesGcmEncryptUpdateResp;

/* CM_AES_GCM_DECRYPT_UPDATE request. */
typedef struct {
    CmReqHeader  hdr;
    byte         context[CMB_AES_GCM_ENCRYPTED_CTX_SIZE];
    word32       ciphertext_size;
    byte         ciphertext[CMB_MAX_DATA_SIZE];
} CmAesGcmDecryptUpdateReq;

/* CM_AES_GCM_DECRYPT_UPDATE response. */
typedef struct {
    CmRespHeader hdr;
    byte         context[CMB_AES_GCM_ENCRYPTED_CTX_SIZE];
    word32       plaintext_size;
    byte         plaintext[CMB_MAX_DATA_SIZE];
} CmAesGcmDecryptUpdateResp;

/* CM_AES_GCM_ENCRYPT_FINAL request.
 * Carries the last plaintext chunk; the authentication tag is returned in the
 * Final response, not sent by the caller. */
typedef struct {
    CmReqHeader  hdr;
    byte         context[CMB_AES_GCM_ENCRYPTED_CTX_SIZE];
    word32       plaintext_size;        /* byte count of last plaintext chunk */
    byte         plaintext[CMB_MAX_DATA_SIZE];
} CmAesGcmEncryptFinalReq;

/* CM_AES_GCM_ENCRYPT_FINAL response.
 * tag[4]: 16-byte authentication tag as four u32 words.
 * Also returns the final ciphertext block. */
typedef struct {
    CmRespHeader hdr;
    word32       tag[4];                /* 16-byte auth tag as u32[4] */
    word32       ciphertext_size;
    byte         ciphertext[CMB_MAX_AES_GCM_OUTPUT_SIZE];
} CmAesGcmEncryptFinalResp;

/* CM_AES_GCM_DECRYPT_FINAL request.
 * Caller provides the tag plus the last ciphertext chunk. */
typedef struct {
    CmReqHeader  hdr;
    byte         context[CMB_AES_GCM_ENCRYPTED_CTX_SIZE];
    word32       tag_len;
    word32       tag[4];                /* 16-byte auth tag as u32[4] */
    word32       ciphertext_size;       /* last ciphertext chunk */
    byte         ciphertext[CMB_MAX_DATA_SIZE];
} CmAesGcmDecryptFinalReq;

/* CM_AES_GCM_DECRYPT_FINAL response.
 * firmware returns tag_verified + plaintext_size after the header.
 * tag_verified: 1 = authentication OK, 0 = authentication failure.
 * Source: cryptographic_mailbox.rs: resp.tag_verified = (computed==expected) as u32 */
typedef struct {
    CmRespHeader hdr;
    word32       tag_verified;          /* 1 = auth OK, 0 = auth failure */
    word32       plaintext_size;        /* informational: total plaintext bytes
                                         * returned across Update calls; no
                                         * plaintext data follows this field.
                                         * All decrypted bytes are returned in
                                         * the preceding Update response(s). */
} CmAesGcmDecryptFinalResp;

/* =========================================================================
 * ECDSA (P-384) structures
 * =========================================================================
 *
 * All key material is referenced via CaliptraCmk handles (128-byte opaque).
 * Public key components are always 48 bytes (P-384 field size).
 * Signature r and s are always 48 bytes each (implicit, no size fields).
 *
 * Note: CmEcdsaVerifyReq uses a Cmk for the public key.  The port must
 * import raw public key material via CM_IMPORT before verifying.
 */

/* CM_ECDSA_SIGN request. */
typedef struct {
    CmReqHeader  hdr;
    CaliptraCmk  cmk;                  /* private key vault reference */
    word32       message_size;
    byte         message[CMB_MAX_DATA_SIZE];
} CmEcdsaSignReq;

/* CM_ECDSA_SIGN response.
 * signature_r and signature_s are each exactly 48 bytes (P-384). */
typedef struct {
    CmRespHeader hdr;
    byte         signature_r[48];
    byte         signature_s[48];
} CmEcdsaSignResp;

/* CM_ECDSA_VERIFY request. */
typedef struct {
    CmReqHeader  hdr;
    CaliptraCmk  cmk;                  /* public key vault reference */
    byte         signature_r[48];
    byte         signature_s[48];
    word32       message_size;
    byte         message[CMB_MAX_DATA_SIZE];
} CmEcdsaVerifyReq;

/* CM_ECDSA_VERIFY response.
 * Verify result is encoded in hdr.fips_status; no separate verify_result field. */
typedef struct {
    CmRespHeader hdr;
} CmEcdsaVerifyResp;

/* CM_ECDSA_PUBLIC_KEY request — retrieve public key for a private key Cmk. */
typedef struct {
    CmReqHeader  hdr;
    CaliptraCmk  cmk;
} CmEcdsaPublicKeyReq;

/* CM_ECDSA_PUBLIC_KEY response.
 * public_key_x and public_key_y are each exactly 48 bytes (P-384). */
typedef struct {
    CmRespHeader hdr;
    byte         public_key_x[48];
    byte         public_key_y[48];
} CmEcdsaPublicKeyResp;

/* =========================================================================
 * ECDH structures
 * =========================================================================
 *
 * Protocol: Generate -> Finish.
 * Generate: Caliptra creates a fresh ephemeral P-384 keypair; returns the
 *   opaque context (76 bytes) and the public exchange data (Qx||Qy, 96 bytes).
 * Finish: caller provides peer's exchange data; Caliptra returns derived key
 *   as a 128-byte Cmk.
 */

/* CM_ECDH_GENERATE request.
 * No fields — Caliptra generates a fresh ephemeral keypair internally. */
typedef struct {
    CmReqHeader  hdr;
} CmEcdhGenerateReq;

/* CM_ECDH_GENERATE response.
 * context: 76-byte encrypted ephemeral private key.
 * exchange_data: Qx || Qy = 96 bytes (two 48-byte P-384 coordinates). */
typedef struct {
    CmRespHeader hdr;
    byte         context[CMB_ECDH_ENCRYPTED_CTX_SIZE];     /* 76 bytes */
    byte         exchange_data[CMB_ECDH_EXCHANGE_DATA_SIZE]; /* 96 bytes */
} CmEcdhGenerateResp;

/* CM_ECDH_FINISH request. */
typedef struct {
    CmReqHeader  hdr;
    byte         context[CMB_ECDH_ENCRYPTED_CTX_SIZE];
    word32       key_usage;             /* extra field present in Rust API */
    byte         incoming_exchange_data[CMB_ECDH_EXCHANGE_DATA_SIZE]; /* peer Qx||Qy */
} CmEcdhFinishReq;

/* CM_ECDH_FINISH response — derived key returned as 128-byte Cmk. */
typedef struct {
    CmRespHeader hdr;
    CaliptraCmk  output;
} CmEcdhFinishResp;

/* =========================================================================
 * HMAC structure
 * ========================================================================= */

/* CM_HMAC request. */
typedef struct {
    CmReqHeader  hdr;
    CaliptraCmk  cmk;
    word32       hash_algorithm;        /* CMB_SHA_ALG_SHA384/512 */
    word32       data_size;
    byte         data[CMB_MAX_DATA_SIZE];
} CmHmacReq;

/* CM_HMAC response.
 * hdr.data_len = MAC byte count; field name is 'mac' not 'hmac'. */
typedef struct {
    CmRespHeaderVarSize hdr;
    byte                mac[CMB_HMAC_MAX_SIZE];
} CmHmacResp;

/* =========================================================================
 * HKDF structures
 * ========================================================================= */

/* CM_HKDF_EXTRACT request.
 * Both salt and IKM are Cmk references (128 bytes each). */
typedef struct {
    CmReqHeader  hdr;
    word32       hash_algorithm;
    CaliptraCmk  salt;                  /* salt key vault reference */
    CaliptraCmk  ikm;                   /* input keying material Cmk reference */
} CmHkdfExtractReq;

/* CM_HKDF_EXTRACT response — pseudorandom key returned as Cmk. */
typedef struct {
    CmRespHeader hdr;
    CaliptraCmk  prk;
} CmHkdfExtractResp;

/* CM_HKDF_EXPAND request. */
typedef struct {
    CmReqHeader  hdr;
    CaliptraCmk  prk;                   /* pseudorandom key Cmk reference */
    word32       hash_algorithm;
    word32       key_usage;
    word32       key_size;              /* desired output length in bytes */
    word32       info_size;
    byte         info[CMB_MAX_DATA_SIZE];
} CmHkdfExpandReq;

/* CM_HKDF_EXPAND response — output key material returned as Cmk. */
typedef struct {
    CmRespHeader hdr;
    CaliptraCmk  okm;
} CmHkdfExpandResp;

/* =========================================================================
 * RNG / Key management structures
 * ========================================================================= */

/* CM_RANDOM_GENERATE request. */
typedef struct {
    CmReqHeader  hdr;
    word32       size;                  /* number of random bytes to generate */
} CmRandomGenerateReq;

/* CM_RANDOM_GENERATE response.
 * hdr.data_len = actual byte count returned. */
typedef struct {
    CmRespHeaderVarSize hdr;
    byte                data[CMB_MAX_DATA_SIZE];
} CmRandomGenerateResp;

/* CM_IMPORT request — import raw key material into Caliptra key vault.
 * input[] is variable-length; send the trimmed wire length via actual_len.
 * Maximum key sizes: AES-256: 32 B; ECDSA private: 48 B; HMAC: 48/64 B;
 * ECDSA public (Qx||Qy): 96 B; MLKEM: 64 B. */
typedef struct {
    CmReqHeader  hdr;
    word32       key_usage;
    word32       input_size;            /* byte count of raw key material */
    byte         input[CMB_MAX_DATA_SIZE]; /* raw key material; send trimmed length */
} CmImportReq;

/* CM_IMPORT response — opaque 128-byte key reference for future operations. */
typedef struct {
    CmRespHeader hdr;
    CaliptraCmk  cmk;
} CmImportResp;

/* CM_DELETE request. */
typedef struct {
    CmReqHeader  hdr;
    CaliptraCmk  cmk;
} CmDeleteReq;

/* CM_DELETE response. */
typedef struct {
    CmRespHeader hdr;
} CmDeleteResp;

/* =========================================================================
 * Per-object SHA streaming state
 * =========================================================================
 *
 * Stored in the hash object's devCtx (or a side table keyed on the hash
 * object pointer).  The 'context' blob is the opaque cookie returned by
 * CM_SHA_INIT and CM_SHA_UPDATE and consumed by the next call.
 *
 * IMPORTANT: This context is freed by caliptra_hash_free() which is only
 * compiled when WOLF_CRYPTO_CB_FREE is defined.  Without WOLF_CRYPTO_CB_FREE,
 * calling wc_Sha384Free() or wc_Sha512Free() before the corresponding Final
 * will leak this allocation.  Define WOLF_CRYPTO_CB_FREE in your build to
 * enable context cleanup on hash object free.
 */
typedef struct {
    byte context[CMB_SHA_CONTEXT_SIZE]; /* opaque context cookie from Caliptra */
} CaliptraShaCtx;

/* =========================================================================
 * Transport hook
 * =========================================================================
 *
 * The integrator must provide this function.  It marshals the request
 * struct to the Caliptra mailbox (writing cmd_id to the command register,
 * req bytes to the data FIFO, ringing the doorbell, then reading the
 * response), and returns 0 on success or a negative wolfSSL error code.
 *
 * Special convention for CM_ECDSA_VERIFY:
 *   Real Caliptra hardware does not write a response when ECDSA verification
 *   fails; instead it sets mailbox status to CmdFailure and writes
 *   CaliptraError::RUNTIME_MAILBOX_SIGNATURE_MISMATCH to cptra_fw_error_non_fatal.
 *   The transport MUST detect this condition and return SIG_VERIFY_E (not a
 *   generic negative error code) so the port can translate it to the wolfSSL
 *   CryptoCb convention of (ret=0, *res=0) for a cryptographically invalid
 *   signature.  Returning any other non-zero code for this condition will cause
 *   the caller to receive a system-error rather than a verify-failed result.
 *   Transports that write a response with fips_status != 0 for invalid
 *   signatures (as caliptra_sim.c does) may return 0; fips_status is
 *   checked as a fallback.
 */
extern int caliptra_mailbox_exec(word32 cmd_id,
                                 const void* req,  word32 req_len,
                                 void*       resp, word32 resp_len);

/* =========================================================================
 * Public API
 * ========================================================================= */

/* Compute the Caliptra mailbox request checksum for a prepared request struct.
 *
 * The firmware verifies: sum(cmd_id bytes LE) + sum(req[4..req_len]) + chksum == 0
 * This function returns the chksum value that satisfies that equation.
 *
 * Integrators who call caliptra_mailbox_exec() directly (e.g., for operations
 * not covered by the CryptoCb layer) must compute and store this checksum into
 * req->hdr.chksum AFTER populating all request fields and BEFORE calling
 * caliptra_mailbox_exec().  Pass the actual wire length (trimmed, not the full
 * struct sizeof) as req_len. */
WOLFSSL_API word32 wc_caliptra_req_chksum(word32       cmd_id,
                                           const void*  req,
                                           word32       req_len);

/* Perform any platform-level initialization required before using Caliptra.
 * This is a hook for platform-specific transport initialization, such as
 * opening a device file descriptor to the Caliptra driver, mapping MMIO
 * regions, or verifying the mailbox is reachable before first use.  If the
 * platform requires no such setup, it returns 0 immediately.
 * This function does NOT register the device with the CryptoCb framework.
 * The application must call wc_CryptoCb_RegisterDevice() separately:
 *   wc_CryptoCb_RegisterDevice(WOLF_CALIPTRA_DEVID, wc_caliptra_cb, NULL);
 * Returns 0 on success, negative wolfSSL error code on failure. */
WOLFSSL_API int wc_caliptra_init(void);

/* Symmetric counterpart to wc_caliptra_init; releases any resources acquired
 * during init (e.g., close fd, unmap MMIO regions).  On platforms with no
 * platform-level init, this is a no-op and returns 0. */
WOLFSSL_API int wc_caliptra_cleanup(void);

/* CryptoCb callback — register with:
 *   wc_CryptoCb_RegisterDevice(WOLF_CALIPTRA_DEVID, wc_caliptra_cb, NULL);
 * then set aes->devId / hmac->devId / ecc->devId = WOLF_CALIPTRA_DEVID to
 * route those operations through Caliptra.
 *
 * IMPORTANT — AES-GCM encrypt IV:
 *   Caliptra generates the nonce server-side.  The caller-supplied iv/ivSz
 *   passed to wc_AesGcmEncrypt() are silently ignored (but wc_AesGcmEncrypt
 *   requires ivSz > 0, so pass a placeholder, e.g. a 12-byte zero buffer).
 *   After a successful return call wc_caliptra_aesgcm_get_iv() to retrieve
 *   the actual 12-byte firmware-generated IV before passing it to
 *   wc_AesGcmDecrypt().  The IV must be transmitted alongside the ciphertext.
 *
 * IMPORTANT — HMAC:
 *   Caliptra HMAC is single-shot only.  wc_HmacUpdate/Final with a Caliptra
 *   key always returns WC_HW_E.  Use wc_caliptra_hmac() directly instead.
 *
 * Input size limit:
 *   AES-GCM and HMAC inputs are limited to CMB_MAX_DATA_SIZE (4096) bytes
 *   per call.  Larger inputs return BUFFER_E.  Chunked streaming is not yet
 *   implemented; this limit comes from the Caliptra mailbox protocol. */
WOLFSSL_API int wc_caliptra_cb(int devId, wc_CryptoInfo* info, void* ctx);

/* Import raw key bytes into the Caliptra key vault.
 * key_data:  pointer to raw key material.
 * key_len:   byte count of key_data.  Maximum CMB_MAX_DATA_SIZE bytes.
 *            Typical sizes: AES-256: 32 B; ECDSA private: 48 B;
 *            HMAC: 48 or 64 B; ECDSA public (Qx||Qy): 96 B.
 * key_usage: CMB_KEY_USAGE_* constant matching the intended algorithm.
 * out_cmk:   on success, receives the 128-byte opaque key handle. */
WOLFSSL_API int wc_caliptra_import_key(const byte*   key_data,
                                       word32        key_len,
                                       word32        key_usage,
                                       CaliptraCmk*  out_cmk);

/* Delete a previously imported key from the Caliptra key vault. */
WOLFSSL_API int wc_caliptra_delete_key(const CaliptraCmk* cmk);

/* Retrieve the IV that Caliptra generated during the most recent
 * wc_AesGcmEncrypt() call on this Aes object.
 *
 * Call wc_AesGcmEncrypt() with a placeholder iv (ivSz > 0 required by
 * wolfSSL, but the value is ignored by Caliptra).  Then call this function
 * to retrieve the actual 12-byte IV before passing it to wc_AesGcmDecrypt().
 *
 * iv_out must point to a buffer of at least 12 bytes; iv_len must be >= 12.
 * Returns 0 on success, BAD_FUNC_ARG on bad args.
 *
 * Storage: the IV is held in aes->reg, wolfSSL's per-object IV register.
 * The CryptoCb AES-GCM encrypt callback has no IV output parameter, so
 * aes->reg is the correct place to preserve the Caliptra-generated IV for
 * retrieval after wc_AesGcmEncrypt() returns.  A compile-time assertion in
 * caliptra_port.c verifies the field is wide enough to hold 12 bytes. */
WOLFSSL_API int wc_caliptra_aesgcm_get_iv(const Aes* aes,
                                           byte*      iv_out,
                                           word32     iv_len);

/* Perform a single-shot HMAC using a Caliptra key vault handle.
 *
 * Caliptra HMAC is inherently single-shot; it cannot be used via the
 * wolfSSL streaming Hmac API (wc_HmacUpdate/Final).  Use this function
 * directly when a Caliptra CMK is the HMAC key.
 *
 * cmk:       Key handle returned by wc_caliptra_import_key() with
 *            key_usage = CMB_KEY_USAGE_HMAC.
 * hash_type: WC_SHA384 or WC_SHA512.
 * msg:       Input message; may be NULL when msg_len == 0.
 * msg_len:   Byte count of msg; must be <= CMB_MAX_DATA_SIZE (4096).
 * mac_out:   Caller-supplied output buffer; must be >= digest size.
 * mac_len:   On entry: mac_out buffer capacity.
 *            On success: updated to the actual MAC byte count.
 *            On failure: mac_out is zeroed; *mac_len is unchanged.
 *
 * Returns 0 on success, negative wolfSSL error code on failure. */
WOLFSSL_API int wc_caliptra_hmac(const CaliptraCmk* cmk,
                                 int                hash_type,
                                 const byte*        msg,
                                 word32             msg_len,
                                 byte*              mac_out,
                                 word32*            mac_len);

#endif /* defined(WOLFSSL_CALIPTRA) && defined(WOLF_CRYPTO_CB) */

#endif /* WOLFSSL_PORT_CALIPTRA_H */
