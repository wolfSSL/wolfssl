/* crypto_policy_granular.c
 *
 * Granular allowlist crypto-policy parser and applier for wolfSSL.
 *
 * Consumes the file emitted by the Fedora `crypto-policies` wolfSSL
 * back-end generator (a sectioned allowlist with explicit primitive
 * names) and drives the wolfSSL public API to configure a WOLFSSL_CTX
 * accordingly. Coexists with the legacy single-line `@SECLEVEL=N:...`
 * parser in src/ssl.c; the routing decision lives in
 * wolfSSL_crypto_policy_enable*().
 *
 * Vocabulary owned by crypto-policies. Mapping tables owned by wolfSSL.
 *
 * Reentrancy / threading: the helpers in this file are pure (no global
 * state). The applier calls back into the wolfSSL public API and
 * temporarily lifts the `wolfSSL_CTX_SetMinVersion` policy guard via
 * the `crypto_policy_applying` flag in src/ssl.c -- that is the only
 * coupling. Like the legacy crypto-policy parser, the apply step is
 * documented as init-time only and is not thread-safe.
 *
 * Forward compatibility: unknown vocabulary tokens are tolerated
 * silently so a wolfSSL build can consume a newer Fedora file without
 * upgrading; the intersection of "policy-enabled intersect build-supported"
 * is what actually reaches a WOLFSSL_CTX. The file *format* version
 * (`version = 1`) is conversely strict: a higher version is rejected
 * outright because it may redefine the meaning of existing keys.
 *
 * Best-effort apply: SetMinVersion / set1_sigalgs_list failures (a
 * build that lacks TLS 1.0 support, or rejects an rsa_pss sigalg the
 * policy lists) downgrade to a logged warning instead of tearing
 * down the CTX. The cipher list and key-size floors still enforce
 * the essential security level, so a partial apply is safer than
 * none.
 */

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#if defined(WOLFSSL_SYS_CRYPTO_POLICY)

#include <wolfssl/ssl.h>
#include <wolfssl/internal.h>

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "crypto_policy_granular.h"

/* -------------------------------------------------------------------- */
/* small helpers                                                        */
/* -------------------------------------------------------------------- */

static char *wcp_trim(char *s)
{
    char *end;
    while (*s && isspace((unsigned char)*s)) {
        s++;
    }
    end = s + XSTRLEN(s);
    while (end > s && isspace((unsigned char)end[-1])) {
        *--end = '\0';
    }
    return s;
}

static int wcp_list_add(WolfCPList *l, const char *tok)
{
    if (l->count >= WOLF_CP_MAX_TOKENS) {
        return WOLF_CP_ERR_OVERFLOW;
    }
    if (XSTRLEN(tok) >= WOLF_CP_MAX_TOKEN_LEN) {
        return WOLF_CP_ERR_OVERFLOW;
    }
    XSTRNCPY(l->tok[l->count], tok, WOLF_CP_MAX_TOKEN_LEN - 1);
    l->tok[l->count][WOLF_CP_MAX_TOKEN_LEN - 1] = '\0';
    l->count++;
    return WOLF_CP_OK;
}

static int wcp_has(const WolfCPList *l, const char *tok)
{
    int i;
    for (i = 0; i < l->count; i++) {
        if (XSTRCMP(l->tok[i], tok) == 0) {
            return 1;
        }
    }
    return 0;
}

/* -------------------------------------------------------------------- */
/* header sniff: is this an allowlist file?                             */
/* -------------------------------------------------------------------- */

/* A minimal, cheap test. We do not parse fully here; we just look at
 * the first non-blank, non-comment line. The legacy format starts with
 * `@SECLEVEL=`. The granular format starts with `version = 1`. */
int wolfSSL_crypto_policy_is_granular(const char *buf)
{
    const char *p = buf;

    if (buf == NULL) {
        return 0;
    }

    while (*p != '\0') {
        const char *line_start = p;
        size_t      n = 0;
        const char *cursor;

        while (*p != '\0' && *p != '\n') {
            p++;
        }

        cursor = line_start;
        while (cursor < p && isspace((unsigned char)*cursor)) {
            cursor++;
            n++;
        }

        if (cursor == p) {
            /* blank line */
        }
        else if (*cursor == '#') {
            /* comment */
        }
        else {
            /* first real line */
            if (XSTRNCMP(cursor, "version", 7) == 0
                || XSTRNCMP(cursor, "override-mode", 13) == 0
                || *cursor == '[') {
                return 1;
            }
            return 0;
        }

        if (*p == '\n') {
            p++;
        }
        (void)n;
    }

    return 0;
}

/* -------------------------------------------------------------------- */
/* parser                                                               */
/* -------------------------------------------------------------------- */

int wolfSSL_crypto_policy_parse_granular(const char *buf,
                                         WolfGranularPolicy *out,
                                         char *err, size_t errlen)
{
    char        line[WOLF_CP_MAX_LINE];
    const char *p = buf;
    int         lineno = 0;
    int         directives = 0;

    if (buf == NULL || out == NULL) {
        if (err && errlen) XSNPRINTF(err, errlen, "null argument");
        return WOLF_CP_ERR_SYNTAX;
    }
    XMEMSET(out, 0, sizeof(*out));
    out->security_level = -1;

    while (*p != '\0') {
        const char *nl = strchr(p, '\n');
        size_t      len = nl ? (size_t)(nl - p) : XSTRLEN(p);
        char       *key, *val, *eq, *content;

        lineno++;
        if (len >= sizeof(line)) {
            if (err && errlen) {
                XSNPRINTF(err, errlen, "line %d too long", lineno);
            }
            return WOLF_CP_ERR_SYNTAX;
        }
        XMEMCPY(line, p, len);
        line[len] = '\0';
        p += len + (nl ? 1 : 0);

        content = strchr(line, '#');
        if (content) {
            *content = '\0';
        }
        content = wcp_trim(line);
        if (*content == '\0') {
            continue;                       /* blank / comment-only    */
        }
        if (*content == '[') {
            continue;                       /* section header, cosmetic */
        }

        eq = strchr(content, '=');
        if (eq == NULL) {
            if (err && errlen) {
                XSNPRINTF(err, errlen,
                          "line %d: expected 'key = value'", lineno);
            }
            return WOLF_CP_ERR_SYNTAX;
        }
        *eq = '\0';
        key = wcp_trim(content);
        val = wcp_trim(eq + 1);
        if (*key == '\0' || *val == '\0') {
            if (err && errlen) {
                XSNPRINTF(err, errlen,
                          "line %d: empty key or value", lineno);
            }
            return WOLF_CP_ERR_SYNTAX;
        }
        directives++;

        if (XSTRCMP(key, "version") == 0) {
            out->version = XATOI(val);
        } else if (XSTRCMP(key, "override-mode") == 0) {
            out->allowlist = (XSTRCMP(val, "allowlist") == 0);
        } else if (XSTRCMP(key, "enabled-version") == 0) {
            if (wcp_list_add(&out->protocols, val)) goto overflow;
        } else if (XSTRCMP(key, "enabled-cipher") == 0) {
            if (wcp_list_add(&out->ciphers, val)) goto overflow;
        } else if (XSTRCMP(key, "enabled-kx") == 0) {
            if (wcp_list_add(&out->kx, val)) goto overflow;
        } else if (XSTRCMP(key, "enabled-mac") == 0) {
            if (wcp_list_add(&out->macs, val)) goto overflow;
        } else if (XSTRCMP(key, "enabled-hash") == 0) {
            if (wcp_list_add(&out->hashes, val)) goto overflow;
        } else if (XSTRCMP(key, "enabled-group") == 0) {
            if (wcp_list_add(&out->groups, val)) goto overflow;
        } else if (XSTRCMP(key, "enabled-sig") == 0) {
            if (wcp_list_add(&out->sigs, val)) goto overflow;
        } else if (XSTRCMP(key, "min-rsa-bits") == 0) {
            out->min_rsa_bits = XATOI(val);
        } else if (XSTRCMP(key, "min-dh-bits") == 0) {
            out->min_dh_bits = XATOI(val);
        } else if (XSTRCMP(key, "min-dsa-bits") == 0) {
            out->min_dsa_bits = XATOI(val);
        } else if (XSTRCMP(key, "security-level") == 0) {
            out->security_level = XATOI(val);
        }
        /* Unknown key: tolerate for forward compatibility. */
        continue;

overflow:
        if (err && errlen) {
            XSNPRINTF(err, errlen,
                      "line %d: too many '%s' entries", lineno, key);
        }
        return WOLF_CP_ERR_OVERFLOW;
    }

    if (!out->allowlist) {
        if (err && errlen) {
            XSNPRINTF(err, errlen, "override-mode is not 'allowlist'");
        }
        return WOLF_CP_ERR_NOT_ALLOWLIST;
    }
    /* `version = 1` is the only format this parser knows. A newer file
     * may add directives that change the *meaning* of existing keys --
     * silently consuming them would be unsafe, so we refuse the file
     * outright. Forward compatibility is the file-format author's job
     * (bump the version) and ours (ship a parser that handles it). */
    if (out->version != 1) {
        if (err && errlen) {
            XSNPRINTF(err, errlen,
                      "unsupported policy file version: %d (expect 1)",
                      out->version);
        }
        return WOLF_CP_ERR_SYNTAX;
    }
    if (directives < 2) {
        if (err && errlen) {
            XSNPRINTF(err, errlen, "policy has no usable directives");
        }
        return WOLF_CP_ERR_EMPTY;
    }
    if (err && errlen) err[0] = '\0';
    return WOLF_CP_OK;
}

/* -------------------------------------------------------------------- */
/* mapping tables: crypto-policies vocabulary -> wolfSSL                */
/* -------------------------------------------------------------------- */

struct wcp_kv_int { const char *cp; int wolf; };
struct wcp_kv_str { const char *cp; const char *wolf; };

/* TLS named groups (wolfSSL_CTX_UseSupportedCurve). */
static const struct wcp_kv_int wcp_group_map[] = {
    { "X25519",          WOLFSSL_ECC_X25519        },
    { "X448",            WOLFSSL_ECC_X448          },
    { "SECP256R1",       WOLFSSL_ECC_SECP256R1     },
    { "SECP384R1",       WOLFSSL_ECC_SECP384R1     },
    { "SECP521R1",       WOLFSSL_ECC_SECP521R1     },
#ifdef HAVE_FFDHE_2048
    { "FFDHE-2048",      WOLFSSL_FFDHE_2048        },
#endif
#ifdef HAVE_FFDHE_3072
    { "FFDHE-3072",      WOLFSSL_FFDHE_3072        },
#endif
#ifdef HAVE_FFDHE_4096
    { "FFDHE-4096",      WOLFSSL_FFDHE_4096        },
#endif
#ifdef HAVE_FFDHE_6144
    { "FFDHE-6144",      WOLFSSL_FFDHE_6144        },
#endif
#ifdef HAVE_FFDHE_8192
    { "FFDHE-8192",      WOLFSSL_FFDHE_8192        },
#endif
    { NULL, 0 }
};

/* TLS protocol versions for SetMinVersion / max-version pin. */
static const struct wcp_kv_int wcp_version_map[] = {
    { "TLS1.0",  WOLFSSL_TLSV1     },
    { "TLS1.1",  WOLFSSL_TLSV1_1   },
    { "TLS1.2",  WOLFSSL_TLSV1_2   },
    { "TLS1.3",  WOLFSSL_TLSV1_3   },
    { "DTLS1.0", WOLFSSL_DTLSV1    },
    { "DTLS1.2", WOLFSSL_DTLSV1_2  },
    { "DTLS1.3", WOLFSSL_DTLSV1_3  },
    { NULL, 0 }
};

/* TLS signature schemes (wolfSSL_CTX_set1_sigalgs_list). */
static const struct wcp_kv_str wcp_sig_map[] = {
    { "ECDSA-SHA2-256",        "ECDSA+SHA256"        },
    { "ECDSA-SHA2-384",        "ECDSA+SHA384"        },
    { "ECDSA-SHA2-512",        "ECDSA+SHA512"        },
    { "RSA-PSS-SHA2-256",      "rsa_pss_pss_sha256"  },
    { "RSA-PSS-SHA2-384",      "rsa_pss_pss_sha384"  },
    { "RSA-PSS-SHA2-512",      "rsa_pss_pss_sha512"  },
    { "RSA-PSS-RSAE-SHA2-256", "rsa_pss_rsae_sha256" },
    { "RSA-PSS-RSAE-SHA2-384", "rsa_pss_rsae_sha384" },
    { "RSA-PSS-RSAE-SHA2-512", "rsa_pss_rsae_sha512" },
    { "RSA-SHA2-256",          "RSA+SHA256"          },
    { "RSA-SHA2-384",          "RSA+SHA384"          },
    { "RSA-SHA2-512",          "RSA+SHA512"          },
    { "EDDSA-ED25519",         "ed25519"             },
    { "EDDSA-ED448",           "ed448"               },
    { NULL, NULL }
};

/* A TLS cipher suite is emitted only if every component it needs is
 * allowlisted. kx == "" marks a TLS 1.3 suite. mac == "AEAD" for AEAD
 * suites; an HMAC token otherwise. */
struct wcp_suite {
    const char *name;
    const char *cipher;
    const char *kx;
    const char *mac;
    const char *version;
};
static const struct wcp_suite wcp_suite_table[] = {
    /* TLS 1.3 */
    { "TLS13-AES256-GCM-SHA384",        "AES-256-GCM",       "", "AEAD", "TLS1.3" },
    { "TLS13-CHACHA20-POLY1305-SHA256", "CHACHA20-POLY1305", "", "AEAD", "TLS1.3" },
    { "TLS13-AES128-GCM-SHA256",        "AES-128-GCM",       "", "AEAD", "TLS1.3" },
    { "TLS13-AES128-CCM-SHA256",        "AES-128-CCM",       "", "AEAD", "TLS1.3" },
    /* TLS 1.2 AEAD */
    { "ECDHE-ECDSA-AES256-GCM-SHA384",  "AES-256-GCM",       "ECDHE",   "AEAD", "TLS1.2" },
    { "ECDHE-RSA-AES256-GCM-SHA384",    "AES-256-GCM",       "ECDHE",   "AEAD", "TLS1.2" },
    { "DHE-RSA-AES256-GCM-SHA384",      "AES-256-GCM",       "DHE-RSA", "AEAD", "TLS1.2" },
    { "ECDHE-ECDSA-CHACHA20-POLY1305",  "CHACHA20-POLY1305", "ECDHE",   "AEAD", "TLS1.2" },
    { "ECDHE-RSA-CHACHA20-POLY1305",    "CHACHA20-POLY1305", "ECDHE",   "AEAD", "TLS1.2" },
    { "DHE-RSA-CHACHA20-POLY1305",      "CHACHA20-POLY1305", "DHE-RSA", "AEAD", "TLS1.2" },
    { "ECDHE-ECDSA-AES128-GCM-SHA256",  "AES-128-GCM",       "ECDHE",   "AEAD", "TLS1.2" },
    { "ECDHE-RSA-AES128-GCM-SHA256",    "AES-128-GCM",       "ECDHE",   "AEAD", "TLS1.2" },
    { "DHE-RSA-AES128-GCM-SHA256",      "AES-128-GCM",       "DHE-RSA", "AEAD", "TLS1.2" },
    /* TLS 1.2 CBC (HMAC) */
    { "ECDHE-ECDSA-AES256-SHA384",      "AES-256-CBC", "ECDHE",   "HMAC-SHA2-384", "TLS1.2" },
    { "ECDHE-RSA-AES256-SHA384",        "AES-256-CBC", "ECDHE",   "HMAC-SHA2-384", "TLS1.2" },
    { "ECDHE-ECDSA-AES128-SHA256",      "AES-128-CBC", "ECDHE",   "HMAC-SHA2-256", "TLS1.2" },
    { "ECDHE-RSA-AES128-SHA256",        "AES-128-CBC", "ECDHE",   "HMAC-SHA2-256", "TLS1.2" },
    { "AES256-GCM-SHA384",              "AES-256-GCM", "RSA",     "AEAD",          "TLS1.2" },
    { "AES128-GCM-SHA256",              "AES-128-GCM", "RSA",     "AEAD",          "TLS1.2" },
    { NULL, NULL, NULL, NULL, NULL }
};

static int wcp_lookup_int(const struct wcp_kv_int *m, const char *cp)
{
    int i;
    for (i = 0; m[i].cp != NULL; i++) {
        if (XSTRCMP(m[i].cp, cp) == 0) {
            return m[i].wolf;
        }
    }
    return -1;
}

static const char *wcp_lookup_str(const struct wcp_kv_str *m, const char *cp)
{
    int i;
    for (i = 0; m[i].cp != NULL; i++) {
        if (XSTRCMP(m[i].cp, cp) == 0) {
            return m[i].wolf;
        }
    }
    return NULL;
}

/* -------------------------------------------------------------------- */
/* derive cipher list                                                   */
/* -------------------------------------------------------------------- */

/* The IANA cipher suites used by TLS 1.x and DTLS 1.x at the same minor
 * version are identical (the DTLS variant is encoded as an alias of the
 * TLS code-point). The suite table tags each row with its TLS label, so
 * a DTLS-only allowlist (e.g. enabled-version = DTLS1.2) must still
 * enable every TLS 1.2 row that survives the other constraints -- and
 * vice versa. Treat the protocol token as "TLS 1.x family" rather than
 * exact string match. */
static int wcp_protocol_family_enabled(const WolfCPList *protocols,
                                       const char       *suite_version)
{
    static const struct { const char *tls; const char *dtls; } pair[] = {
        { "TLS1.2", "DTLS1.2" },
        { "TLS1.3", "DTLS1.3" },
        { NULL,     NULL      }
    };
    int i;

    if (wcp_has(protocols, suite_version)) {
        return 1;
    }
    for (i = 0; pair[i].tls != NULL; i++) {
        if (XSTRCMP(suite_version, pair[i].tls) == 0
            && wcp_has(protocols, pair[i].dtls)) {
            return 1;
        }
        if (XSTRCMP(suite_version, pair[i].dtls) == 0
            && wcp_has(protocols, pair[i].tls)) {
            return 1;
        }
    }
    return 0;
}

int wolfSSL_crypto_policy_derive_cipher_list(const WolfGranularPolicy *p,
                                             char *out, size_t outlen)
{
    int    i;
    size_t off = 0;
    int    first = 1;

    if (p == NULL || out == NULL || outlen == 0) {
        return WOLF_CP_ERR_SYNTAX;
    }

    out[0] = '\0';

    for (i = 0; wcp_suite_table[i].name != NULL; i++) {
        const struct wcp_suite *s = &wcp_suite_table[i];
        size_t need;

        if (!wcp_has(&p->ciphers, s->cipher))   continue;
        if (!wcp_protocol_family_enabled(&p->protocols, s->version)) continue;
        if (s->kx[0] != '\0' && !wcp_has(&p->kx, s->kx)) continue;
        if (!wcp_has(&p->macs, s->mac))         continue;

        need = XSTRLEN(s->name) + (first ? 0 : 1);
        if (off + need + 1 >= outlen) {
            return WOLF_CP_ERR_OVERFLOW;
        }
        if (!first) {
            out[off++] = ':';
        }
        XMEMCPY(out + off, s->name, XSTRLEN(s->name));
        off += XSTRLEN(s->name);
        out[off] = '\0';
        first = 0;
    }

    return WOLF_CP_OK;
}

/* -------------------------------------------------------------------- */
/* derive sigalgs list                                                  */
/* -------------------------------------------------------------------- */

int wolfSSL_crypto_policy_derive_sigalgs_list(const WolfGranularPolicy *p,
                                              char *out, size_t outlen)
{
    int    i;
    size_t off = 0;
    int    first = 1;

    if (p == NULL || out == NULL || outlen == 0) {
        return WOLF_CP_ERR_SYNTAX;
    }

    out[0] = '\0';

    for (i = 0; i < p->sigs.count; i++) {
        const char *w = wcp_lookup_str(wcp_sig_map, p->sigs.tok[i]);
        size_t      need;

        if (w == NULL) continue;

        need = XSTRLEN(w) + (first ? 0 : 1);
        if (off + need + 1 >= outlen) {
            return WOLF_CP_ERR_OVERFLOW;
        }
        if (!first) {
            out[off++] = ':';
        }
        XMEMCPY(out + off, w, XSTRLEN(w));
        off += XSTRLEN(w);
        out[off] = '\0';
        first = 0;
    }

    return WOLF_CP_OK;
}

/* -------------------------------------------------------------------- */
/* lowest enabled TLS/DTLS version                                      */
/* -------------------------------------------------------------------- */

/* `wolfSSL_CTX_SetMinVersion` rejects a TLS constant on a DTLS CTX (and
 * vice versa). The min-version computation must therefore be scoped to
 * the CTX's protocol family, otherwise a policy that enables both TLS
 * and DTLS would pass a TLS constant into a DTLS CTX and the floor
 * would be silently dropped. is_dtls != 0 restricts the search to DTLS
 * tokens, is_dtls == 0 restricts it to TLS tokens. */
int wolfSSL_crypto_policy_min_version(const WolfGranularPolicy *p,
                                      int is_dtls)
{
    int i;
    int best = -1;
    int best_pri = 1 << 30;

    if (p == NULL) return -1;

    for (i = 0; i < p->protocols.count; i++) {
        const char *tok = p->protocols.tok[i];
        int         v;
        int         tok_is_dtls = (XSTRNCMP(tok, "DTLS", 4) == 0);
        if (tok_is_dtls != (is_dtls != 0)) {
            continue;
        }
        v = wcp_lookup_int(wcp_version_map, tok);
        if (v < 0) continue;
        /* Pin "min" to numerically lowest within the family. The
         * wolfSSL public enum is monotonic per family: TLSV1=1 <
         * TLSV1_1=2 < TLSV1_2=3 < TLSV1_3=4, and DTLSV1=5 <
         * DTLSV1_2=6 < DTLSV1_3=7. We've already filtered by family
         * above, so the smallest value is the oldest version in that
         * family -- the right floor. */
        if (v < best_pri) {
            best_pri = v;
            best = v;
        }
    }
    return best;
}

/* -------------------------------------------------------------------- */
/* apply: drive real wolfSSL public API on a WOLFSSL_CTX                */
/* -------------------------------------------------------------------- */

int wolfSSL_crypto_policy_apply_granular(WOLFSSL_CTX *ctx,
                                         const WolfGranularPolicy *p)
{
    int        rc;
    int        i;
    char       buf[2048];
    int        min_ver;
    int        is_dtls;

    if (ctx == NULL || p == NULL) {
        return BAD_FUNC_ARG;
    }

    WOLFSSL_ENTER("wolfSSL_crypto_policy_apply_granular");

    is_dtls = (ctx->method != NULL
               && ctx->method->version.major == DTLS_MAJOR);

    /* 1. Protocol min version. Best-effort: a TLS 1.0 floor against a
     * build that lacks WOLFSSL_ALLOW_TLSV10 must not tear down the CTX
     * -- we keep the wolfSSL-default downgrade floor and let the cipher
     * list + key-size floors carry the policy. The caller will still
     * negotiate within the build's supported version range.
     *
     * We resolve the floor inside the CTX's protocol family. Passing a
     * TLS constant to a DTLS CTX (or vice versa) makes SetMinVersion
     * fail and the floor would be silently dropped. */
    min_ver = wolfSSL_crypto_policy_min_version(p, is_dtls);
    if (min_ver >= 0) {
        rc = wolfSSL_CTX_SetMinVersion(ctx, min_ver);
        if (rc != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG_EX("granular policy: SetMinVersion(%d) rejected by "
                           "build: %d (continuing)", min_ver, rc);
        }
    }

    /* 2. Cipher list. An allowlist is authoritative: if the
     * intersection of policy-enabled cipher suites and the suite table
     * is empty, the CTX would silently keep its default cipher list
     * and the policy would not actually constrain anything. Refuse
     * outright in that case. */
    rc = wolfSSL_crypto_policy_derive_cipher_list(p, buf, sizeof(buf));
    if (rc != WOLF_CP_OK) {
        WOLFSSL_MSG("granular policy: cipher list derivation failed");
        return WOLFSSL_FAILURE;
    }
    if (buf[0] == '\0') {
        WOLFSSL_MSG("granular policy: derived cipher list is empty -- "
                    "policy enables no suites this build can serve");
        return WOLFSSL_FAILURE;
    }
    rc = wolfSSL_CTX_set_cipher_list(ctx, buf);
    if (rc != WOLFSSL_SUCCESS) {
        WOLFSSL_MSG_EX("granular policy: set_cipher_list failed: %d", rc);
        return rc;
    }

    /* 3. Supported groups (TLS named groups). */
    for (i = 0; i < p->groups.count; i++) {
        int g = wcp_lookup_int(wcp_group_map, p->groups.tok[i]);
        if (g < 0) {
            WOLFSSL_MSG_EX("granular policy: group not in wolfSSL map: %s",
                           p->groups.tok[i]);
            continue;
        }
        rc = wolfSSL_CTX_UseSupportedCurve(ctx, (word16)g);
        if (rc != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG_EX("granular policy: UseSupportedCurve(%s=%d) "
                           "failed: %d", p->groups.tok[i], g, rc);
            /* Non-fatal: a group not supported by this build should not
             * tear down the entire policy. */
        }
    }

    /* 4. Signature algorithms. Best-effort: if wolfSSL rejects the
     * derived list (for instance because the build lacks rsa_pss
     * support), keep the policy applied without sigalg pinning rather
     * than tearing the CTX down. The cipher list and key-size floors
     * already enforce the essential security level. */
    rc = wolfSSL_crypto_policy_derive_sigalgs_list(p, buf, sizeof(buf));
    if (rc != WOLF_CP_OK) {
        WOLFSSL_MSG("granular policy: sigalgs list derivation failed");
    }
    else if (buf[0] != '\0') {
        rc = wolfSSL_CTX_set1_sigalgs_list(ctx, buf);
        if (rc != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG_EX("granular policy: set1_sigalgs_list rejected by "
                           "build: %d (continuing)", rc);
        }
    }

    /* 5. Asymmetric key-size floors. */
#if !defined(NO_RSA)
    if (p->min_rsa_bits > 0) {
        rc = wolfSSL_CTX_SetMinRsaKey_Sz(ctx, (short)p->min_rsa_bits);
        if (rc != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG_EX("granular policy: SetMinRsaKey_Sz(%ld) failed: %d",
                           p->min_rsa_bits, rc);
            return rc;
        }
    }
#endif
#if !defined(NO_DH)
    if (p->min_dh_bits > 0) {
        rc = wolfSSL_CTX_SetMinDhKey_Sz(ctx, (word16)p->min_dh_bits);
        if (rc != WOLFSSL_SUCCESS) {
            WOLFSSL_MSG_EX("granular policy: SetMinDhKey_Sz(%ld) failed: %d",
                           p->min_dh_bits, rc);
            return rc;
        }
    }
#endif
#ifdef HAVE_ECC
    {
        /* Map RSA-equivalent strength to ECC bits: 2048->224, 3072->256,
         * 4096->384, 7680->384, 15360->521. Conservative. */
        short ecc_bits = 0;
        if (p->min_rsa_bits >= 15360)      ecc_bits = 521;
        else if (p->min_rsa_bits >= 7680)  ecc_bits = 384;
        else if (p->min_rsa_bits >= 3072)  ecc_bits = 256;
        else if (p->min_rsa_bits >= 2048)  ecc_bits = 224;
        if (ecc_bits > 0) {
            rc = wolfSSL_CTX_SetMinEccKey_Sz(ctx, ecc_bits);
            if (rc != WOLFSSL_SUCCESS) {
                WOLFSSL_MSG_EX("granular policy: SetMinEccKey_Sz(%d) failed: "
                               "%d", ecc_bits, rc);
                return rc;
            }
        }
    }
#endif

    return WOLFSSL_SUCCESS;
}

#endif /* WOLFSSL_SYS_CRYPTO_POLICY */
