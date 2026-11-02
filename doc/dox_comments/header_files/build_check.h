/*!
    \ingroup BuildCheck

    \brief Fills cfg with the build configuration that the wolfSSL library
    was compiled with, in the same form as wc_BuildConfig_Local() gives for
    the caller. See wc_BuildConfig_Local() for what the fingerprint holds.

    Available when HAVE_WC_INTROSPECTION is defined: on by default with
    autotools (except lean and reproducible builds) and with CMake
    (-DWOLFSSL_INTROSPECTION, except reproducible builds); user_settings.h
    builds define it themselves.

    At most cfgSz bytes are written, so a library newer than the caller's
    header, with a larger wc_BuildConfig, fills only the fields the caller's
    struct has. cfg->structSz is set to the number of bytes written; read
    only the fields it covers.

    \return 0 on success.
    \return BAD_FUNC_ARG if cfg is NULL or cfgSz is less than
    WC_BUILD_CONFIG_V1_SZ, the size of the version 1 layout.

    \param cfg structure that receives the library's configuration.
    \param cfgSz size of the caller's structure in bytes, normally
    sizeof(*cfg).

    _Example_
    \code
    #include <wolfssl/options.h>
    #include <wolfssl/wolfcrypt/build_check.h>

    wc_BuildConfig libCfg;
    if (wc_GetBuildConfig(&libCfg, sizeof(libCfg)) == 0) {
        printf("library options hash: 0x%08x\n", libCfg.optionsHash);
    }
    \endcode

    \sa wc_BuildConfig_Local
    \sa wc_CompareBuildConfig
    \sa wc_CheckBuildConfig
    \sa wolfSSL_configure_args
*/
int wc_GetBuildConfig(wc_BuildConfig* cfg, word32 cfgSz);

/*!
    \ingroup BuildCheck

    \brief Fills cfg with the build configuration seen by the source file
    that calls it. This function is static inline in
    wolfssl/wolfcrypt/build_check.h, so called from an application it
    describes the application's configuration (its options.h or
    user_settings.h and compiler flags), not the library's. Pass the result
    to wc_CompareBuildConfig() or wc_BuildConfigMismatchString();
    wc_CheckBuildConfig() and wc_CheckBuildConfigEx() do both steps.

    The fingerprint, a wc_BuildConfig, holds:
     - structSz and cfgVersion: the number of bytes filled in and the layout
       version (WC_BUILD_CONFIG_VERSION). The struct is append-only, so a
       newer header's larger struct is still understood by an older library,
       and an older header's smaller struct by a newer one.
     - libVersionHex: LIBWOLFSSL_VERSION_HEX.
     - optionsHash: WOLFSSL_OPTIONS_HASH, a hash of the generated
       wolfssl/options.h written by configure or CMake; 0 for
       user_settings.h builds.
     - features: WC_BUILD_FEATURE_WORDS words of bits, one per macro that
       changes a public struct layout, which APIs exist, or the math
       backend. Decode them with wc_BuildConfigFeatureName().
     - sizes: WC_BUILD_SIZE_COUNT sizes of public structures that
       applications allocate or read fields of: wolfCrypt keys and contexts,
       Cert, DecodedCert, wc_PKCS7, wc_CryptoInfo, the non-blocking
       contexts, driver contexts (Pkcs11Dev, wc_PufCtx, wc_SHE,
       struct wc_rng_bank), DNS_entry, WOLFSSL_X509_STORE_CTX (in every TLS
       build) and, with OPENSSL_EXTRA, the OpenSSL compatibility
       structures (WOLFSSL_EVP_MD_CTX, WOLFSSL_HMAC_CTX, WOLFSSL_SHA256_CTX,
       WOLFSSL_EVP_PKEY, ...); 0 for types compiled out. Two slots hold
       values rather than struct sizes: sizeof(mp_digit) and DIGIT_BIT
       (as wc_BuildDigitBits), since a heap-math mp_int's size does not
       show its digit width. Decode them with
       wc_BuildConfigSizeName(). Unused slots are 0. A slot is
       WC_BUILD_SIZE_UNKNOWN when the
       type exists but the calling file cannot see it: DecodedCert and
       DecodedAcert, when wolfssl/openssl/obj_mac.h was included before
       anything else that pulls in wolfssl/wolfcrypt/asn.h.

    The bit and slot assignments are in wolfssl/wolfcrypt/build_check_list.h.
    WOLFSSL and WOLFSSL_CTX are not measured: they are opaque to
    applications, defined only in wolfssl/internal.h and allocated by the
    library.

    \return none No returns.

    \param cfg structure to fill.

    _Example_
    \code
    #include <wolfssl/options.h>
    #include <wolfssl/wolfcrypt/build_check.h>

    wc_BuildConfig appCfg;
    wc_BuildConfig_Local(&appCfg);
    // e.g. store appCfg with a crash report, or compare it later
    \endcode

    \sa wc_GetBuildConfig
    \sa wc_CompareBuildConfig
    \sa wc_CheckBuildConfig
*/
void wc_BuildConfig_Local(wc_BuildConfig* cfg);

/*!
    \ingroup BuildCheck

    \brief Compares a build configuration with the one compiled into the
    library. cfg is normally filled by wc_BuildConfig_Local(), a header
    inline function, so it describes the configuration the application was
    compiled with. Fields compared: library version, feature bits and
    structure sizes. A size slot that either side recorded as
    WC_BUILD_SIZE_UNKNOWN is skipped. The options hashes are compared only
    if both sides have one; user_settings.h builds have none.

    A larger cfg->structSz from a newer build_check.h is accepted: the
    struct is append-only, and fields this library does not know about are
    ignored.

    \return 0 if the configurations match.
    \return BUILD_CONFIG_MISMATCH_E if they differ. The details are in
    mismatch and, with DEBUG_WOLFSSL, in the debug log.
    \return BAD_FUNC_ARG if cfg is NULL, cfg->structSz is too small or
    cfg->cfgVersion is 0.

    \param cfg configuration to check, usually the application's.
    \param mismatch optional (may be NULL). Receives a bitmask of what
    differs: WC_BUILD_MISMATCH_VERSION (library version),
    WC_BUILD_MISMATCH_FEATURES (feature macros), WC_BUILD_MISMATCH_SIZES
    (structure sizes) and WC_BUILD_MISMATCH_OPTIONS_HASH (options.h hash);
    0 on a match.

    _Example_
    \code
    wc_BuildConfig appCfg;
    word32 mismatch;

    wc_BuildConfig_Local(&appCfg);
    if (wc_CompareBuildConfig(&appCfg, &mismatch) != 0) {
        // Tolerate a different library version, but not different features
        if (mismatch & ~WC_BUILD_MISMATCH_VERSION) {
            abort();
        }
    }
    \endcode

    \sa wc_CheckBuildConfig
    \sa wc_GetBuildConfig
*/
int wc_CompareBuildConfig(const wc_BuildConfig* cfg, word32* mismatch);

/*!
    \ingroup BuildCheck

    \brief Checks that the application was compiled with the same wolfSSL
    build configuration as the library it is running with. This function is
    static inline in wolfssl/wolfcrypt/build_check.h. It fingerprints the
    calling source file's view of the configuration (its options.h or
    user_settings.h and compiler flags), then passes that fingerprint to
    wc_CompareBuildConfig() in the loaded library.

    Call it once at start-up, before wolfSSL_Init(). Mismatched feature
    defines change structure layouts and API availability, and otherwise
    lead to memory corruption at run time.

    \return 0 if the configurations match.
    \return BUILD_CONFIG_MISMATCH_E if they differ.

    \param mismatch optional (may be NULL). Receives a WC_BUILD_MISMATCH_*
    bitmask; see wc_CompareBuildConfig().

    _Example_
    \code
    #include <wolfssl/options.h>
    #include <wolfssl/wolfcrypt/build_check.h>

    word32 mismatch = 0;
    if (wc_CheckBuildConfig(&mismatch) != 0) {
        fprintf(stderr, "wolfSSL build mismatch (0x%x): rebuild against the "
                        "installed wolfSSL headers\n", mismatch);
        exit(EXIT_FAILURE);
    }
    \endcode

    \sa wc_CheckBuildConfigEx
    \sa wc_CompareBuildConfig
    \sa wc_GetBuildConfig
*/
int wc_CheckBuildConfig(word32* mismatch);

/*!
    \ingroup BuildCheck

    \brief Same as wc_CheckBuildConfig(), and on a mismatch also writes a
    description of every difference to buf (see
    wc_BuildConfigMismatchString()). Static inline in
    wolfssl/wolfcrypt/build_check.h.

    \return 0 if the configurations match. buf, if given, is set to "".
    \return BUILD_CONFIG_MISMATCH_E if they differ.

    \param mismatch optional (may be NULL). Receives a WC_BUILD_MISMATCH_*
    bitmask.
    \param buf optional (may be NULL). Receives the description.
    \param bufSz size of buf in bytes. A mismatch between two builds a few
    configure options apart runs to about 1.5 KB, so 2048 is a comfortable
    size. A longer description is cut short and ends in "..." (when bufSz
    is at least 4).

    _Example_
    \code
    #include <wolfssl/options.h>
    #include <wolfssl/wolfcrypt/build_check.h>

    char why[2048];
    if (wc_CheckBuildConfigEx(NULL, why, sizeof(why)) != 0) {
        // e.g. "WOLFSSL_SHA3: app=on lib=off; sizeof(Aes): app=880 lib=848"
        fprintf(stderr, "wolfSSL build mismatch: %s\n", why);
        exit(EXIT_FAILURE);
    }
    \endcode

    \sa wc_CheckBuildConfig
    \sa wc_BuildConfigMismatchString
*/
int wc_CheckBuildConfigEx(word32* mismatch, char* buf, word32 bufSz);

/*!
    \ingroup BuildCheck

    \brief Describes how a build configuration differs from the library's,
    naming each difference. The result is a NUL-terminated list of items
    separated by "; ":

     - "version: app=0x05009004 lib=0x05009005"
     - "<MACRO>: app=on lib=off" for each differing feature macro, e.g.
       "OPENSSL_EXTRA: app=on lib=off"
     - "sizeof(<type>): app=<n> lib=<n>" for each differing structure size,
       e.g. "sizeof(Aes): app=880 lib=848" (0 means compiled out)
     - "options.h hash: app=0x... lib=0x..."
     - "feature word <w> bit <b>: ..." for a bit with no name, as an older
       library reports a bit only a newer header knows about

    The function doesn't use snprintf(), so it is available wherever the
    library builds. With DEBUG_WOLFSSL, wc_CompareBuildConfig() logs the same
    items one by one.

    \return The length of the description (0, with buf set to "", when the
    configurations match).
    \return BUFFER_E if buf was too small. buf then holds as many items as
    fit, NUL-terminated and ending in "..." (when bufSz is at least 4).
    \return BAD_FUNC_ARG if cfg or buf is NULL, bufSz is 0, or cfg's layout
    is not recognized.

    \param cfg configuration to describe, usually the application's (from
    wc_BuildConfig_Local()).
    \param buf receives the description.
    \param bufSz size of buf in bytes.

    _Example_
    \code
    wc_BuildConfig appCfg;
    char why[2048];

    wc_BuildConfig_Local(&appCfg);
    if (wc_CompareBuildConfig(&appCfg, NULL) != 0 &&
            wc_BuildConfigMismatchString(&appCfg, why, sizeof(why)) >= 0) {
        log_error("wolfSSL build mismatch: %s", why);
    }
    \endcode

    \sa wc_CheckBuildConfigEx
    \sa wc_BuildConfigFeatureName
    \sa wc_BuildConfigSizeName
*/
int wc_BuildConfigMismatchString(const wc_BuildConfig* cfg, char* buf,
    word32 bufSz);

/*!
    \ingroup BuildCheck

    \brief Returns the name of the macro behind a feature bit of
    wc_BuildConfig.features, e.g. "WOLFSSL_SHA3". Useful for tools that
    decode a stored or transmitted fingerprint. The bit assignments are in
    wolfssl/wolfcrypt/build_check_list.h.

    \return The macro name.
    \return NULL for an unused bit, or a word or bit out of range.

    \param word feature word index, less than WC_BUILD_FEATURE_WORDS.
    \param bit bit index, less than 32.

    _Example_
    \code
    wc_BuildConfig cfg;
    word32 w, b;

    wc_GetBuildConfig(&cfg, sizeof(cfg));
    for (w = 0; w < WC_BUILD_FEATURE_WORDS; w++)
        for (b = 0; b < 32; b++)
            if (cfg.features[w] & WC_BUILD_BIT(b))
                printf("%s\n", wc_BuildConfigFeatureName(w, b));
    \endcode

    \sa wc_BuildConfigSizeName
    \sa wc_BuildConfigMismatchString
*/
const char* wc_BuildConfigFeatureName(word32 word, word32 bit);

/*!
    \ingroup BuildCheck

    \brief Returns the type recorded in a size slot of wc_BuildConfig.sizes,
    e.g. "Aes" or "struct WOLFSSL_EVP_MD_CTX".

    \return The type name.
    \return NULL for an unused slot, or one not less than
    WC_BUILD_SIZE_COUNT.

    \param slot size slot index.

    _Example_
    \code
    wc_BuildConfig cfg;
    word32 i;

    wc_GetBuildConfig(&cfg, sizeof(cfg));
    for (i = 0; i < WC_BUILD_SIZE_COUNT; i++)
        if (wc_BuildConfigSizeName(i) != NULL)
            printf("sizeof(%s) = %u\n", wc_BuildConfigSizeName(i),
                cfg.sizes[i]);
    \endcode

    \sa wc_BuildConfigFeatureName
*/
const char* wc_BuildConfigSizeName(word32 slot);
