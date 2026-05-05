/* tests/swdev/user_settings.h -- settings for wc_swdev.
 *
 * The swdev software backend must stay ABI-identical to the main library:
 * every wolfCrypt struct that crosses the cryptocb boundary (wc_Sha256,
 * Aes, RsaKey, ecc_key, ...) is allocated by one compilation and used by
 * the other. The only macros that may differ between the two compilations
 * are the WOLF_CRYPTO_CB_ONLY_* gates below -- those strip the software
 * implementations from the main library so every operation routes through
 * the crypto callback; swdev needs the software paths intact.
 *
 * Config source depends on how the parent library was built:
 *   - autotools build:       wolfssl/options.h carries the full feature set.
 *   - WOLFSSL_USER_SETTINGS: the parent's user_settings.h is the source of
 *     truth; The swdev Makefile locates that file via a compiler probe (-E -H)
 * and passes its absolute path as SWDEV_PARENT_USER_SETTINGS_H. */
#ifndef WC_SWDEV_USER_SETTINGS_H
#define WC_SWDEV_USER_SETTINGS_H

#ifdef SWDEV_PARENT_USER_SETTINGS_H
    #include SWDEV_PARENT_USER_SETTINGS_H
#else
    #include <wolfssl/options.h>
#endif

#undef WOLF_CRYPTO_CB_ONLY_RSA
#undef WOLF_CRYPTO_CB_ONLY_ECC
#undef WOLF_CRYPTO_CB_ONLY_SHA256
#undef WOLF_CRYPTO_CB_ONLY_AES

#ifndef WOLF_CRYPTO_CB
    #error "wc_swdev requires the main build to define WOLF_CRYPTO_CB"
#endif

#endif /* WC_SWDEV_USER_SETTINGS_H */
