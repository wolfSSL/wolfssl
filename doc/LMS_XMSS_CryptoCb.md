# LMS / XMSS Crypto Callback support

This document describes the wolfSSL-side groundwork that lets LMS / HSS
(RFC 8554) and XMSS / XMSS^MT (RFC 8391, both profiled in NIST SP 800-208)
participate in the `WOLF_CRYPTO_CB` framework. With this layer in place, the
wolfSSL PKCS#11 provider and the wolfHSM client can host stateful
hash-based keys on a device without the wolfSSL public API changing.

No HSM-side or PKCS#11-provider code lives in this layer. It only adds the
dispatcher surface, the per-key device binding, and the helpers a backend
needs to answer the request.

## Why route stateful hash-based keys through a device

LMS and XMSS are one-time-signature trees: the private key holds a counter
that must be incremented on every signature, and signing the same index twice
breaks the security proof. Moving that counter to a hardware module is the
clean way to make the scheme operationally safe — the HSM is the natural
owner of the index, and an attacker who steals a host snapshot cannot replay
old indices.

## PKCS#11 mapping

PKCS#11 v3.1 standardised HSS and v3.2 added XMSS / XMSS^MT. The CryptoCb
surface mirrors what those mechanisms expose:

| wolfSSL API           | PKCS#11 analog                                 | CryptoCb dispatcher                          |
|-----------------------|------------------------------------------------|----------------------------------------------|
| `wc_LmsKey_MakeKey`   | `CKM_HSS_KEY_PAIR_GEN`                         | `wc_CryptoCb_PqcStatefulSigKeyGen`           |
| `wc_LmsKey_Sign`      | `CKM_HSS` (sign)                               | `wc_CryptoCb_PqcStatefulSigSign`             |
| `wc_LmsKey_Verify`    | `CKM_HSS` (verify)                             | `wc_CryptoCb_PqcStatefulSigVerify`           |
| `wc_LmsKey_SigsLeft`  | `CKA_HSS_KEYS_REMAINING` attribute             | `wc_CryptoCb_PqcStatefulSigSigsLeft`         |
| `wc_XmssKey_MakeKey`  | `CKM_XMSS_KEY_PAIR_GEN` / `CKM_XMSSMT_KEY_PAIR_GEN` | `wc_CryptoCb_PqcStatefulSigKeyGen`      |
| `wc_XmssKey_Sign`     | `CKM_XMSS` / `CKM_XMSSMT` (sign)               | `wc_CryptoCb_PqcStatefulSigSign`             |
| `wc_XmssKey_Verify`   | `CKM_XMSS` / `CKM_XMSSMT` (verify)             | `wc_CryptoCb_PqcStatefulSigVerify`           |
| `wc_XmssKey_SigsLeft` | XMSS remaining-sigs attribute                  | `wc_CryptoCb_PqcStatefulSigSigsLeft`         |

The four dispatchers are shared between LMS and XMSS, following the
`wc_CryptoCb_PqcSign*` family used for Dilithium and Falcon. A new
discriminator enum `wc_PqcStatefulSignatureType` (`WC_PQC_STATEFUL_SIG_TYPE_LMS`,
`WC_PQC_STATEFUL_SIG_TYPE_XMSS`) tells the callback which of `LmsKey*` or
`XmssKey*` the `void* key` field is. XMSS vs XMSS^MT is decided inside the
callback via the existing `XmssKey::is_xmssmt` field.

`Reload`, `GetKid`, and `ExportPub` are not routed through CryptoCb, but each
is aware of HSM-backed keys: `Reload` short-circuits because state lives in
the device, `GetKid` logs a warning since `priv_raw` may be uninitialised,
and `ExportPub` preserves the source key's `devId` so the verify-only copy
keeps dispatching through the same device. The external-backend variants
(`ext_lms.c` / `ext_xmss.c`, selected by `--with-liblms` / `--with-libxmss`)
are intentionally outside the scope of this layer and execute purely in
software.

## Per-key device binding

Each key carries the device-binding fields that other key types
(`RsaKey`, `ecc_key`, `dilithium_key`) already expose:

```c
struct LmsKey {
    /* ... existing fields ... */
#ifdef WOLF_CRYPTO_CB
    int   devId;     /* device identifier */
    void* devCtx;    /* opaque per-device state, owned by the callback */
#endif
#ifdef WOLF_PRIVATE_KEY_ID
    byte  id[LMS_MAX_ID_LEN];        /* device-side key identifier */
    int   idLen;
    char  label[LMS_MAX_LABEL_LEN];  /* device-side key label */
    int   labelLen;
#endif
};
```

`XmssKey` carries the equivalent set under the same macro guards, with
`XMSS_MAX_ID_LEN` / `XMSS_MAX_LABEL_LEN`. The `*_MAX_ID_LEN` and
`*_MAX_LABEL_LEN` constants default to 32 and can be overridden by
predefining the macros.

`devCtx`, `id`, and `label` are storage only — wolfSSL never reads or writes
them internally. Backends populate `devCtx` from the callback (typically the
first time they touch the key) and consume `id` / `label` to resolve the
on-device handle.

## Public API additions

```c
/* Bind a key to a device-side identifier or label. */
#ifdef WOLF_PRIVATE_KEY_ID
WOLFSSL_API int wc_LmsKey_InitId   (LmsKey * key, const unsigned char * id,
                                    int len, void * heap, int devId);
WOLFSSL_API int wc_LmsKey_InitLabel(LmsKey * key, const char * label,
                                    void * heap, int devId);
WOLFSSL_API int wc_XmssKey_InitId   (XmssKey* key, const unsigned char* id,
                                     int len, void* heap, int devId);
WOLFSSL_API int wc_XmssKey_InitLabel(XmssKey* key, const char* label,
                                     void* heap, int devId);
#endif

/* Compute the digest of a message with the hash function dictated by
 * the parameter set. Useful for backends that follow the PKCS#11 v3.2
 * CKM_HSS / CKM_XMSS / CKM_XMSSMT convention of operating on a
 * pre-computed digest (see "Sign / verify input format" below). */
WOLFSSL_API int wc_LmsKey_HashMsg (const LmsKey * key, const byte * msg,
                                   word32 msgSz, byte * hash,
                                   word32 * hashSz);
WOLFSSL_API int wc_XmssKey_HashMsg(const XmssKey* key, const byte* msg,
                                   word32 msgSz, byte* hash,
                                   word32* hashSz);
```

The `Init*` helpers follow the `wc_InitRsaKey_Id` / `wc_InitRsaKey_Label`
shape: they validate length bounds, delegate the rest of init to
`wc_LmsKey_Init` / `wc_XmssKey_Init`, then copy id / label onto the key.

The `HashMsg` helpers honour the parameter set:

| Algorithm | Hash families covered                                           |
|-----------|-----------------------------------------------------------------|
| LMS / HSS | SHA-256 (32 bytes), SHA-256/192 (24 bytes), SHAKE256 (32 / 24)  |
| XMSS / MT | SHA-256, SHA-512, SHAKE128, SHAKE256 (per `params->hash`)       |

`*hashSz` is in / out: callers pass the buffer size and receive the digest
length on success.

## Sign / verify input format

The CryptoCb dispatcher forwards the raw message to the callback. PKCS#11
v3.2 section 6.66.8 ("XMSS and XMSSMT without hashing") and the analogous
text for HSS specify that those mechanisms take a pre-computed digest
rather than the message. Backends that need that behaviour — typically
PKCS#11 providers — call `wc_LmsKey_HashMsg` or `wc_XmssKey_HashMsg` from
inside the callback to produce the algorithm-dictated digest. Backends
that take the full message (typically wolfHSM) consume `msg` / `msgSz`
directly. Picking one or the other is a callback decision; the dispatcher
is agnostic.

## Build configuration

| `./configure` flag(s)                                  | Effect                                                |
|--------------------------------------------------------|-------------------------------------------------------|
| `--enable-lms --enable-xmss --enable-cryptocb`         | Primary target. Full dispatcher and round-trip tests. |
| `--enable-lms --enable-xmss`                           | New dispatcher code is fully `#ifdef`-elided.         |
| `--enable-cryptocb`                                    | LMS / XMSS-less build; nothing CryptoCb-side breaks.  |
| `CPPFLAGS=-DWOLF_PRIVATE_KEY_ID …`                     | Adds `id` / `label` fields and the `Init*` helpers.   |

## Verification

`./wolfcrypt/test/testwolfcrypt` exercises the full dispatcher round trip:
inside `cryptocb_test`, `lms_test` and `xmss_test` run with the harness's
registered `myCryptoDevCb`, which clears the key's `devId`, invokes the
software API recursively, then restores `devId`. Sign and verify both go
through the dispatcher, so the produced signatures self-verify within the
harness. With no device registered, `lms_test` and `xmss_test` remain on the
software path and produce bit-identical KAT output.

## Design notes

- **Shared dispatcher, separate type tag.** The eight LMS / XMSS operations
  collapse to four shared dispatchers (`KeyGen`, `Sign`, `Verify`,
  `SigsLeft`) keyed on `wc_PqcStatefulSignatureType`. The pattern matches
  the `PqcSign` family used for Dilithium / Falcon and reduces the surface
  area a backend has to implement.
- **Verify carries `int* res`.** Following the Ed25519 / ECC / PqcVerify
  convention, the verify dispatcher reports validity through a separate
  `*res` flag, so a backend can distinguish a transport error from a
  forged signature. The wrapping wolfSSL function still translates
  `res != 1` to `SIG_VERIFY_E` for callers that do not see `res`.
- **`SigsLeft` carries `word32* sigsLeft`.** PKCS#11 defines
  `CKA_HSS_KEYS_REMAINING` as a `CK_ULONG`-sized attribute; the callback
  uses `word32*` so an HSS key at its 2^32 limit can be expressed
  unambiguously. The wolfSSL public API still returns `int` and clamps at
  `0x7FFFFFFF`.
- **HSM-backed keys skip the software write / read callbacks.**
  `wc_LmsKey_MakeKey` / `_Sign` and the XMSS equivalents dispatch through
  CryptoCb *before* validating `write_private_key` / `read_private_key` /
  `context`. A device-backed key does not need dummy software callbacks.
  On `CRYPTOCB_UNAVAILABLE` fall-through the software validations are
  re-applied as normal.
