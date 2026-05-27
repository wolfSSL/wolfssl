/* crypto_policy_granular.h
 *
 * Internal header for the granular allowlist crypto-policy back-end.
 * Not part of the wolfSSL public API. See src/crypto_policy_granular.c.
 */
#ifndef WOLFSSL_CRYPTO_POLICY_GRANULAR_H
#define WOLFSSL_CRYPTO_POLICY_GRANULAR_H

#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_SYS_CRYPTO_POLICY)

#include <wolfssl/ssl.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WOLF_CP_MAX_TOKENS      64
#define WOLF_CP_MAX_TOKEN_LEN   48
#define WOLF_CP_MAX_LINE       256

#define WOLF_CP_OK                  0
#define WOLF_CP_ERR_SYNTAX         -1
#define WOLF_CP_ERR_NOT_ALLOWLIST  -2
#define WOLF_CP_ERR_OVERFLOW       -3
#define WOLF_CP_ERR_EMPTY          -4

typedef struct {
    char tok[WOLF_CP_MAX_TOKENS][WOLF_CP_MAX_TOKEN_LEN];
    int  count;
} WolfCPList;

typedef struct {
    int        version;
    int        allowlist;
    WolfCPList protocols;
    WolfCPList ciphers;
    WolfCPList kx;
    WolfCPList macs;
    WolfCPList hashes;
    WolfCPList groups;
    WolfCPList sigs;
    long       min_rsa_bits;
    long       min_dh_bits;
    long       min_dsa_bits;
    int        security_level;
} WolfGranularPolicy;

/* Header sniff: 1 if buffer looks like a granular allowlist file,
 *               0 if legacy single-line @SECLEVEL= format. */
WOLFSSL_LOCAL int wolfSSL_crypto_policy_is_granular(const char *buf);

/* Parse a granular allowlist buffer into a WolfGranularPolicy. */
WOLFSSL_LOCAL int wolfSSL_crypto_policy_parse_granular(
    const char *buf, WolfGranularPolicy *out, char *err, size_t errlen);

/* Derive a wolfSSL-style cipher list string from the parsed policy. */
WOLFSSL_LOCAL int wolfSSL_crypto_policy_derive_cipher_list(
    const WolfGranularPolicy *p, char *out, size_t outlen);

/* Derive a wolfSSL sigalgs list string from the parsed policy. */
WOLFSSL_LOCAL int wolfSSL_crypto_policy_derive_sigalgs_list(
    const WolfGranularPolicy *p, char *out, size_t outlen);

/* Lowest TLS/DTLS version enabled. Returns -1 if none. */
WOLFSSL_LOCAL int wolfSSL_crypto_policy_min_version(
    const WolfGranularPolicy *p);

/* Apply the parsed policy to a CTX: drive SetMinVersion,
 * set_cipher_list, UseSupportedCurve, set1_sigalgs_list and
 * SetMin{Rsa,Dh,Ecc}Key_Sz. */
WOLFSSL_LOCAL int wolfSSL_crypto_policy_apply_granular(
    WOLFSSL_CTX *ctx, const WolfGranularPolicy *p);

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_SYS_CRYPTO_POLICY */

#endif /* WOLFSSL_CRYPTO_POLICY_GRANULAR_H */
