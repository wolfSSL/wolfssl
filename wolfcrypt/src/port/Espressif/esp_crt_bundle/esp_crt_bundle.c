/* esp_crt_bundle.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#if defined(WOLFSSL_ESPIDF) /* Entire file is only for Espressif EDP-IDF */

/* wolfSSL */
/* Always include wolfcrypt/settings.h before any other wolfSSL file.    */
/* Be sure to define WOLFSSL_USER_SETTINGS, typically in CMakeLists.txt  */
/* Reminder: settings.h pulls in user_settings.h                         */
/*   Do not explicitly include user_settings.h here.                     */
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/port/Espressif/esp_crt_bundle.h>
#include <wolfssl/wolfcrypt/port/Espressif/esp-sdk-lib.h>

#ifndef SHOW_WOLFSSL_BUNDLE_ERROR
    #define SHOW_WOLFSSL_BUNDLE_ERROR(X) ESP_LOGV(TAG, \
           "SHOW_WOLFSSL_BUNDLE_ERROR not enabled, details suppressed.");
#endif

/* Espressif */
#include <esp_log.h>

#if defined(CONFIG_ESP_TLS_USING_WOLFSSL)
#include <wolfssl/wolfcrypt/logging.h>

static const char *TAG = "esp_crt_bundle-wolfssl";


#if defined(CONFIG_WOLFSSL_CERTIFICATE_BUNDLE) && \
    defined(CONFIG_WOLFSSL_CERTIFICATE_BUNDLE_DEFAULT_NONE) && \
    (CONFIG_WOLFSSL_CERTIFICATE_BUNDLE_DEFAULT_NONE == 1)

/* esp_crt_bundle_attach() used by ESP-IDF esp-tls layer.
 * When there's no bundle selected, but a call is made, return a warning: */
esp_err_t esp_crt_bundle_attach(void *conf)
{
    esp_err_t ret = ESP_OK;
    ESP_LOGW(TAG, "No certificate bundle was selected");
    return ret;
}
#else
/* Certificate Bundles are enabled, and something other than NONE selected. */
#include <wolfssl/internal.h>
#include <wolfssl/ssl.h>

#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifdef WOLFSSL_CMAKE_REQUIRED_ESP_TLS
    /* We're already here since CONFIG_ESP_TLS_USING_WOLFSSL is enabled,    */
    /* but do we have a recent version of wolfSSL CMakeLists.txt to support */
    /* using wolfSSL in ESP-IDF? If so, include the esp-tls component here: */
    #include <esp_tls.h> /* needed only for esp_tls_free_global_ca_store()  */
#endif

/* There's a minimum version of wolfSSL needed for Certificate Bundle Support.
 *
 * See the latest code at:
 * https://github.com/wolfSSL/wolfssl or Managed Components at
 * https://www.wolfssl.com/wolfssl-now-available-in-espressif-component-registry/
 */
#if defined(WOLFSSL_ESPIDF_COMPONENT_VERSION)
    #if (WOLFSSL_ESPIDF_COMPONENT_VERSION > 0)
        #define WOLFSSL_ESPIDF_COMPONENT_VERSION_VALID 1
    #else
        #define WOLFSSL_ESPIDF_COMPONENT_VERSION_VALID 0
        #warning "This library depends on a recent version of wolfSSL config"
    #endif
#else
    #warning "This library depends on a recent version of wolfSSL config"
    #define WOLFSSL_ESPIDF_COMPONENT_VERSION_VALID -1
#endif

#include <wolfssl/wolfcrypt/port/Espressif/esp_crt_bundle.h>

/* Bundle debug may come from user_settings.h and/or sdkconfig.h */
#if defined(CONFIG_WOLFSSL_DEBUG_CERT_BUNDLE) || \
    defined(       WOLFSSL_DEBUG_CERT_BUNDLE)
    /* someplace to store result of wc_ErrorString(err, string) */
    char last_esp_crt_bundle_error[WOLFSSL_MAX_ERROR_SZ];
    /* We'll only locally check this one: */
    #undef         WOLFSSL_DEBUG_CERT_BUNDLE
    #define        WOLFSSL_DEBUG_CERT_BUNDLE
    /* Only display certificate bundle debugging messages when enabled: */
    #define ESP_LOGCBI ESP_LOGI
    #define ESP_LOGCBW ESP_LOGW
    #define ESP_LOGCBV ESP_LOGV
    /* Always show bundle name debugging when cert bundle debugging. */
    #define ESP_LOGCBNI ESP_LOGI
    #define ESP_LOGCBNW ESP_LOGW
    #define ESP_LOGCBNV ESP_LOGV
#else
    /* Only display certificate bundle messages for most verbose setting.
     * Note that the delays will likely cause TLS connection failures. */
    #define ESP_LOGCBI ESP_LOGV
    #define ESP_LOGCBW ESP_LOGV
    #define ESP_LOGCBV ESP_LOGV
    /* Optionally debug only certificate bundle names: */
    /* #define WOLFSSL_DEBUG_CERT_BUNDLE_NAME          */
    #ifdef WOLFSSL_DEBUG_CERT_BUNDLE_NAME
        #define ESP_LOGCBNI ESP_LOGI
        #define ESP_LOGCBNW ESP_LOGW
        #define ESP_LOGCBNV ESP_LOGV
    #else
        #define ESP_LOGCBNI ESP_LOGV
        #define ESP_LOGCBNW ESP_LOGV
        #define ESP_LOGCBNV ESP_LOGV
    #endif
#endif

#if defined(WOLFSSL_EXAMPLE_VERBOSITY)
    #define ESP_LOGXI ESP_LOGI
    #define ESP_LOGXW ESP_LOGW
    #define ESP_LOGXV ESP_LOGW
#else
    #define ESP_LOGXI ESP_LOGV
    #define ESP_LOGXI ESP_LOGV
    #define ESP_LOGXI ESP_LOGV
#endif

#ifndef X509_MAX_SUBJECT_LEN
    #define X509_MAX_SUBJECT_LEN 255
#endif

#ifndef CTC_DATE_SIZE
    #define CTC_DATE_SIZE 32
#endif

#define IS_WOLFSSL_CERT_BUNDLE_FORMAT
#ifndef IS_WOLFSSL_CERT_BUNDLE_FORMAT
    /* For reference only, the other cert bundles are structured differently!
     * The others contain only a PARTIAL certificate, along with a name. */
    #define BUNDLE_HEADER_OFFSET 2
    #define CRT_HEADER_OFFSET 4
#else
    /* Note these are also set in [ESP-IDF]/components/esp-tls/esp_tls_wolfssl.c
     * to avoid conflicts with other cert bundles that may, in theory,
     * be enabled concurrently (NOT recommended).
     *
     * Ensure they exactly match here: */
    #define BUNDLE_HEADER_OFFSET 2
    #define CRT_HEADER_OFFSET 2
#endif

/* NOTE: Manually edit sort order in gen_crt_bundle.py
 *
 * The default is having the bundle pre-sorted in the python script
 * to allow for rapid binary cert match search at runtime. The unsorted
 * search ALWAYS works, but when expecting a sorted search the python
 * script MUST presort the data, otherwise the connection will likely fail.
 *
 * When debugging and using an unsorted bundle, define CERT_BUNDLE_UNSORTED
 * Reminder: the actual sort occurs in gen_crt_bundly.py call from CMake. */
/* #define CERT_BUNDLE_UNSORTED */

/* Inline cert bundle functions performance hint unless otherwise specified. */
#ifndef CB_INLINE
    #define CB_INLINE inline
#endif

/* A "Certificate Bundle" is this array of [size] + [x509 CA List]
 * certs that the client trusts: */
#if !defined(NO_WOLFSSL_USE_ASM_CERT)
    extern const uint8_t x509_crt_imported_bundle_wolfssl_bin_start[]
                         asm("_binary_x509_crt_bundle_wolfssl_start");

    extern const uint8_t x509_crt_imported_bundle_wolfssl_bin_end[]
                         asm("_binary_x509_crt_bundle_wolfssl_end");
#else
    extern const unsigned char _binary_x509_crt_bundle_wolfssl_start[];
    extern const unsigned char _binary_x509_crt_bundle_wolfssl_end[];
#endif
/* This crt_bundle_t type must match other providers in esp-tls from ESP-IDF.
 * TODO: Move to common header in ESP-IDF. (requires ESP-IDF modification).
 * For now, it is here: */
typedef struct crt_bundle_t {
    const uint8_t **crts;
    uint16_t num_certs;
    size_t x509_crt_bundle_wolfssl_len;
} crt_bundle_t;

static WOLFSSL_X509* store_cert = NULL; /* will point to existing param values*/

#ifdef CONFIG_WOLFSSL_CERTIFICATE_BUNDLE
    static const uint8_t **crts = NULL;
    static uint16_t num_certs = 0;
#endif

#ifdef CONFIG_WOLFSSL_CERTIFICATE_BUNDLE
static esp_err_t wolfssl_esp_crt_bundle_init(const uint8_t *x509_bundle,
                                             size_t bundle_size);
static esp_err_t _esp_crt_bundle_is_valid = ESP_FAIL;
#endif /* CONFIG_WOLFSSL_CERTIFICATE_BUNDLE */

static crt_bundle_t s_crt_bundle = { 0 };

static int _cert_bundle_loaded = 0;

static int _need_bundle_cert = 0;

/* API for determining if the wolfSSL cert bundle is loaded. */
int wolfssl_cert_bundle_loaded(void)
{
    return _cert_bundle_loaded;
}

/* API for determining if the wolfSSL cert bundle is needed. */
int wolfssl_need_bundle_cert(void)
{
    return _need_bundle_cert;
}

/* Public API wolfSSL_X509_get_cert_items() */
int wolfSSL_X509_get_cert_items(char* CERT_TAG,
                                WOLFSSL_X509* cert,
                                WOLFSSL_X509_NAME** issuer,
                                WOLFSSL_X509_NAME** subject)
{
    char stringVaue[X509_MAX_SUBJECT_LEN + 1];
#ifdef WOLFSSL_DEBUG_CERT_BUNDLE
    char before_str[CTC_DATE_SIZE];
    char after_str[CTC_DATE_SIZE];
    WOLFSSL_ASN1_TIME *notBefore = NULL, *notAfter = NULL;
#endif
    int ret = WOLFSSL_SUCCESS; /* Not ESP value! Success = 1, fail = 0 */

    *issuer  = wolfSSL_X509_get_issuer_name(cert);
    if (wolfSSL_X509_NAME_oneline(*issuer,
                                  stringVaue, sizeof(stringVaue)) == NULL) {
        ESP_LOGE(TAG, "%s Error converting subject name to string.", CERT_TAG);
        ret = WOLFSSL_FAILURE;
    }
    else {
        ESP_LOGCBI(TAG, "%s Store Cert Issuer: %s", CERT_TAG, stringVaue);
    }

    *subject = wolfSSL_X509_get_subject_name(cert);
    if (wolfSSL_X509_NAME_oneline(*subject,
                                  stringVaue, sizeof(stringVaue)) == NULL) {
        ESP_LOGE(TAG, "%s Error converting subject name to string.", CERT_TAG);
        ret = WOLFSSL_FAILURE;
    }
    else {
        ESP_LOGCBI(TAG, "%s Store Cert Subject: %s", CERT_TAG, stringVaue );
    }

#ifdef WOLFSSL_DEBUG_CERT_BUNDLE
    notBefore = wolfSSL_X509_get_notBefore(cert);
    if (wolfSSL_ASN1_TIME_to_string(notBefore, before_str,
                                    sizeof(before_str)) == NULL) {
        ESP_LOGCBW(TAG, "%s Not Before value not valid", CERT_TAG);
    }
    else {
        ESP_LOGCBI(TAG, "%s Not Before: %s", CERT_TAG, before_str);
    }

    esp_show_current_datetime();

    notAfter = wolfSSL_X509_get_notAfter(cert);
    if (wolfSSL_ASN1_TIME_to_string(notAfter, after_str,
                                    sizeof(after_str)) == NULL) {
        ESP_LOGCBW(TAG, "%s Not After value not valid", CERT_TAG);
    }
    else {
        ESP_LOGCBI(TAG, "%s Not After: %s", CERT_TAG, after_str);
    }

#endif

    return ret;
} /* wolfSSL_X509_show_cert */


/* wolfSSL_X509_verify_cert() for the cert the store is reporting an error for.
 * The peer certs above it, up to index `last`, are passed in as untrusted
 * intermediates: with alt cert chains ProcessPeerCerts() keeps them out of
 * the Certificate Manager, leaving nothing to build a path from. Certs above
 * `last` are left out, so the path can't go past the bundle root issuing
 * `last` to an expired cross-sign above it. The store ctx given to the
 * callback belongs to the TLS layer, so verify through a private one. */
static CB_INLINE int store_verify_peer(WOLFSSL_X509_STORE_CTX* store, int last)
{
    int ret = WOLFSSL_FAILURE;
    int i;
    WOLFSSL_X509* this_cert;
    WOLFSSL_X509_STORE_CTX* peer_store;
    WOLF_STACK_OF(WOLFSSL_X509)* untrusted;

    untrusted = wolfSSL_sk_X509_new_null();
    peer_store = wolfSSL_X509_STORE_CTX_new();
    if ((untrusted == NULL) || (peer_store == NULL)) {
        ESP_LOGE(TAG, "store_verify_peer out of memory");
    }
    else {
        for (i = store->error_depth + 1;
             (i <= last) && (i < store->totalCerts); i++) {
            /* A cert missing here can only make the verify below fail. */
            this_cert = wolfSSL_X509_d2i(NULL, store->certs[i].buffer,
                                         (int)store->certs[i].length);
            if ((this_cert != NULL) &&
                (wolfSSL_sk_X509_push(untrusted, this_cert) <= 0)) {
                wolfSSL_X509_free(this_cert);
            }
        }

        if (wolfSSL_X509_STORE_CTX_init(peer_store, store->store,
                        store->current_cert, untrusted) == WOLFSSL_SUCCESS) {
            ret = wolfSSL_X509_verify_cert(peer_store);
        }
    }

    wolfSSL_X509_STORE_CTX_free(peer_store);
    wolfSSL_sk_X509_pop_free(untrusted, NULL);

    return ret;
}

/*
 * cert_manager_load()
 *
 * returns preverify value.
 *
 * WARNING: It is the caller's responsibility to confirm the der cert should be
 *          added. (Typically during a callback error override).
 *
 * Verify Callback Arguments:
 * preverify:           1=Verify Okay, 0=Failure
 * store->error:        Failure error code (0 indicates no failure)
 * store->current_cert: Current WOLFSSL_X509 object (only with OPENSSL_EXTRA)
 * store->error_depth:  Current Index
 * store->domain:       Subject CN as string (null term)
 * store->totalCerts:   Number of certs presented by peer
 * store->certs[i]:     A `WOLFSSL_BUFFER_INFO` with plain DER for each cert
 * store->store:        WOLFSSL_X509_STORE with CA cert chain
 * store->store->cm:    WOLFSSL_CERT_MANAGER
 * store->ex_data:      The WOLFSSL object pointer
 * store->discardSessionCerts: When set to non-zero value session certs
                               will be discarded (only with SESSION_CERTS)
 *
 * last:                Index of the highest peer cert that store_verify_peer()
 *                      passes as an untrusted intermediate. */
static CB_INLINE int cert_manager_load(int preverify,
                                       WOLFSSL_X509_STORE_CTX* store,
                                       const unsigned char * der, long derSz,
                                       int last)
{
    int ret;
    WOLFSSL_CERT_MANAGER* cm = NULL; /* points to wolfSSL cm, no cleanup need */
    WOLFSSL_X509_NAME *issuer = NULL;
    WOLFSSL_X509_NAME *subject = NULL;

    WOLFSSL_X509* peer = NULL; /* points to wolfSSL cm store, no cleanup need */

    if (der == NULL) {
        ESP_LOGE(TAG, "cert_manager_load der is null");
        return 0; /* preverify */
    }

    if (store == NULL) {
        ESP_LOGE(TAG, "cert_manager_load store is null");
        return 0; /* preverify */
    }

    if (store->current_cert == NULL) {
        ESP_LOGE(TAG, "cert_manager_load store->current_cert is null");
        return 0; /* preverify */
    }

    cm = store->store->cm;
    peer = store->current_cert;
    wolfSSL_X509_get_cert_items("peer", peer, &issuer, &subject);

    /* It is the caller's responsibility to check conditions to add cert. */
    if ((preverify == 0)  && (store->error == ASN_NO_SIGNER_E)) {
        ESP_LOGCBI(TAG, "Confirmed call for ASN_NO_SIGNER_E");
    }
    else {
        ESP_LOGW(TAG, "Warning: calling for non ASN_NO_SIGNER_E error.");
    }

    /* Some interesting cert bundle debug details: */
    ESP_LOGCBI(TAG, "Cert %d:\n\tIssuer: %s\n\tSubject: %s\n",
        store->error_depth,
        issuer->name != NULL ? issuer->name : "[none]",
        subject->name != NULL ? subject->name : "[none]");

    /* Load the der cert to Certificate Manager:*/
    ret = wolfSSL_CertManagerLoadCABuffer(cm, der, derSz,
                                          WOLFSSL_FILETYPE_ASN1);
    if (ret == WOLFSSL_SUCCESS) {
        /* Attempt to validate the peer certificate again */
        ret = store_verify_peer(store, last);

        if (ret == WOLFSSL_SUCCESS) {
            ESP_LOGCBI(TAG, "Successfully validated cert: %s\n", subject->name);

            /* If verification is successful then override error. */
            preverify = 1;
        }
        else {
            ESP_LOGCBW(TAG, "Failed to verify cert after loading new CA. "
                          "err = %d", ret);
        }
    }
    else {
        ESP_LOGCBW(TAG, "Failed to load CA, ret = %d", ret);
        SHOW_WOLFSSL_BUNDLE_ERROR(ret);
    }

    /* We don't free the issue and subject, as they are
     * pointers to current store->current_cert values. */
    return preverify;
}

/* Search the bundle for the cert whose subject name is `name`.
 * dcert is scratch space for parsing bundle certs.
 * Returns 1 and sets der, derSz and isCa when found, otherwise 0. */
static int wolfssl_bundle_find(DecodedCert* dcert, const char* name,
                               const unsigned char** der, int* derSz,
                               int* isCa)
{
    const unsigned char* cert_data = NULL;
    int cert_len = 0;
    int start = 0;
    int end = (int)s_crt_bundle.num_certs - 1;
    int middle;
    int i;
    int cmp_res;
    int found = 0;
    int ret = 0;

    while ((found == 0) && (start <= end)) {
#ifndef CERT_BUNDLE_UNSORTED
        /* When sorted (not unsorted), binary search: */
        middle = start + ((end - start) / 2);
#else
        /* When not sorted, typically during debugging, look at each: */
        middle = start;
#endif
        ESP_LOGCBNW(TAG, "Looking at CA #%d; start = %d, end = %d",
                         middle, start, end);

        /* Compare with the first entry from middle on that parses. An entry
         * that doesn't parse, e.g. with a key type this build lacks, can't
         * be the match, so each pass drops the entries it looked at. */
        for (i = middle; i <= end; i++) {
            /* Each cert length was saved by gen_crt_bundle.py: */
            cert_len = (s_crt_bundle.crts[i][0] << 8) |
                        s_crt_bundle.crts[i][1];
            cert_data = s_crt_bundle.crts[i] + CRT_HEADER_OFFSET;

            /* Parse the bundle cert as a CA. Some trusted roots have serial
             * number 0, which strict ASN checking only accepts in a
             * self-signed CA loaded as a trust anchor. */
            wc_InitDecodedCert(dcert, cert_data, (word32)cert_len, NULL);
            ret = wc_ParseCert(dcert, CA_TYPE, NO_VERIFY, NULL);
            if (ret == 0) {
                break;
            }
            wc_FreeDecodedCert(dcert);
            if (ret == WC_NO_ERR_TRACE(MEMORY_E)) {
                ESP_LOGE(TAG, "Out of memory parsing bundle cert #%d", i);
                break;
            }
            ESP_LOGCBW(TAG, "Skipping certificate #%d from bundle: %d",
                            i, ret);
        }
        if (ret == WC_NO_ERR_TRACE(MEMORY_E)) {
            /* Not a property of the entry: stop instead of searching on as
             * if it were absent. */
            break;
        }
        if (i > end) {
            /* Nothing from middle to end parses. */
            end = middle - 1;
            continue;
        }

        ESP_LOGCBNI(TAG, "This Bundle Item Subject Name: %s",
                         dcert->subject);
        /* gen_crt_bundle.py sorts with its own key, which only approximates
         * this name string. The binary search needs both orders to agree;
         * test_esp_crt_bundle.sh checks that. */
        cmp_res = XSTRCMP(dcert->subject, name);
        if (cmp_res == 0) {
            *der = cert_data;
            *derSz = cert_len;
            *isCa = dcert->isCA;
            found = 1;
        }
        wc_FreeDecodedCert(dcert);

#ifndef CERT_BUNDLE_UNSORTED
        if (cmp_res < 0) {
            start = i + 1;
        }
        else {
            /* Entries middle to i - 1 don't parse. */
            end = middle - 1;
        }
#else
        start = i + 1;
#endif
    }

    ESP_LOGCBI(TAG, "%s in bundle: %s", found ? "Found" : "Not found", name);
    return found;
}

#ifndef WOLFSSL_ALT_CERT_CHAINS
/* Returns 1 when root is a self-issued CA with no path length, name or policy
 * constraints, and cross has the same subject, public key and key ID.
 *
 * Once the callback accepts cross, wolfSSL keeps it only on this connection's
 * waived-CA list, not in the Certificate Manager. Signers are looked up in the
 * Certificate Manager first, and cross has the root's key ID, so the next cert
 * down is verified with the root loaded here. Allowing only roots without
 * constraints keeps this safe whichever of the two is used. */
static int wolfssl_bundle_same_root_key(const DecodedCert* root,
                                        const DecodedCert* cross)
{
    int ret = 1;

    if ((!root->selfIssued) || (!root->isCA)) {
        ESP_LOGCBW(TAG, "Bundle cert is not a self-issued CA.");
        ret = 0;
    }
    /* Only roots without constraints: whatever is accepted on the root's
     * key then can't be held to more than the root itself. */
    else if (root->pathLengthSet || root->extPolicyConstSet
#ifndef IGNORE_NAME_CONSTRAINTS
             || root->extNameConstraintSet
#endif
            ) {
        ESP_LOGCBW(TAG, "Bundle root has constraints.");
        ret = 0;
    }
    else if (!cross->isCA) {
        ESP_LOGCBW(TAG, "Cross-signed cert is not a CA.");
        ret = 0;
    }
    else if ((XMEMCMP(root->subjectHash, cross->subjectHash,
                      sizeof(root->subjectHash)) != 0) ||
             (root->keyOID != cross->keyOID) ||
#ifdef HAVE_ECC
             (root->pkCurveOID != cross->pkCurveOID) ||
#endif
             (root->pubKeySize != cross->pubKeySize) ||
             (XMEMCMP(root->publicKey, cross->publicKey,
                      root->pubKeySize) != 0)) {
        ESP_LOGCBW(TAG, "Bundle root has a different public key.");
        ret = 0;
    }
#ifndef NO_SKID
    /* The key ID is the subject key identifier, or else a hash of the key. */
    else if (XMEMCMP(root->extSubjKeyId, cross->extSubjKeyId,
                     sizeof(root->extSubjKeyId)) != 0) {
        ESP_LOGCBW(TAG, "Bundle root has a different subject key ID.");
        ret = 0;
    }
#endif

    return ret;
}

/* Accept `cross` when it is a cross-signed copy of a bundle root (same
 * subject and key), e.g. GTS Root R4 by GlobalSign Root CA. The bundle root
 * is loaded as the CA. Not needed with alt cert chains, which check the next
 * cert down against the root. dcert is scratch space. Returns preverify. */
static int wolfssl_bundle_cross_sign(int preverify,
                                     WOLFSSL_X509_STORE_CTX* store,
                                     WOLFSSL_X509* cross,
                                     DecodedCert* dcert)
{
    WOLFSSL_X509_NAME* cross_subject;
    WC_DECLARE_VAR(cross_dcert, DecodedCert, 1, NULL);
    const unsigned char* root_der = NULL;
    const unsigned char* cross_der = NULL;
    int root_sz = 0;
    int cross_sz = 0;
    int is_ca = 0;
    int same_key = 0;
    int ret;

    cross_subject = wolfSSL_X509_get_subject_name(cross);
    if ((cross_subject == NULL) || (cross_subject->name == NULL) ||
        (wolfssl_bundle_find(dcert, cross_subject->name, &root_der, &root_sz,
                             &is_ca) == 0)) {
        return preverify;
    }

    cross_der = wolfSSL_X509_get_der(cross, &cross_sz);
    if (cross_der == NULL) {
        ESP_LOGE(TAG, "Cross-signed cert check failed.");
        return preverify;
    }
    WC_ALLOC_VAR_EX(cross_dcert, DecodedCert, 1, NULL, DYNAMIC_TYPE_DCERT,
    {
        ESP_LOGE(TAG, "Cross-signed cert check failed.");
        return preverify;
    });

    wc_InitDecodedCert(dcert, root_der, (word32)root_sz, NULL);
    wc_InitDecodedCert(cross_dcert, cross_der, (word32)cross_sz, NULL);
    if ((wc_ParseCert(dcert, CA_TYPE, NO_VERIFY, NULL) == 0) &&
        (wc_ParseCert(cross_dcert, CERT_TYPE, NO_VERIFY, NULL) == 0)) {
        same_key = wolfssl_bundle_same_root_key(dcert, cross_dcert);
    }
    wc_FreeDecodedCert(cross_dcert);
    wc_FreeDecodedCert(dcert);
    WC_FREE_VAR_EX(cross_dcert, NULL, DYNAMIC_TYPE_DCERT);

    if (same_key) {
        ESP_LOGCBI(TAG, "Cross-signed cert has the key of a bundle root.");
        /* The store reports the cross-signed cert itself. Its signature is
         * from an issuer outside the bundle, so accept it on its key. */
        ret = wolfSSL_CertManagerLoadCABuffer(store->store->cm, root_der,
                                              root_sz, WOLFSSL_FILETYPE_ASN1);
        if (ret == WOLFSSL_SUCCESS) {
            preverify = 1;
        }
        else {
            ESP_LOGCBW(TAG, "Failed to load CA, ret = %d", ret);
        }
    }

    return preverify;
}
#endif /* !WOLFSSL_ALT_CERT_CHAINS */

/* Look for a bundle root that `cert` leads to: the bundle cert that issued
 * it, or else (without alt cert chains) a bundle root that `cert` is a
 * cross-signed copy of.
 * `last` is the index of `cert` in the peer chain.
 * Sets found when the issuer is in the bundle, and cross_signed when the
 * cross-signed copy was accepted.
 * dcert is scratch space for parsing bundle certs.
 * Returns preverify. */
static int wolfssl_bundle_check_cert(int preverify,
                                     WOLFSSL_X509_STORE_CTX* store,
                                     WOLFSSL_X509* cert, int last,
                                     DecodedCert* dcert, int* found,
                                     int* is_ca, int* cross_signed)
{
    WOLFSSL_X509_NAME* issuer;
    const unsigned char* der = NULL;
    int der_sz = 0;

    *found = 0;
    *cross_signed = 0;

    issuer = wolfSSL_X509_get_issuer_name(cert);
    if ((issuer == NULL) || (issuer->name == NULL)) {
        ESP_LOGE(TAG, "Error getting the cert issuer.");
        return preverify;
    }
    ESP_LOGCBI(TAG, "Store Cert Issuer:  %s", issuer->name);

    /* Look for the bundle cert whose subject is the cert's issuer: */
    *found = wolfssl_bundle_find(dcert, issuer->name, &der, &der_sz, is_ca);

    /* After searching the bundle for an appropriate CA, if found then
     * load into the provided cert manager. */
    if (*found) {
        ESP_LOGCBW(TAG, "Found a Matching Certificate Name in the bundle!");
        preverify = cert_manager_load(preverify, store, der, der_sz, last);
        if (preverify == WC_NO_ERR_TRACE(WOLFSSL_FAILURE)) {
            /* cert_manager_load() logged whether the load or the verify
             * failed. */
            ESP_LOGCBW(TAG, "Warning: found a matching cert, but it did not "
                            "verify the peer cert.");
        }
        else {
            ESP_LOGCBI(TAG, "New CA verified the peer cert.");
        }
    }
    else {
        ESP_LOGCBW(TAG, "Matching Certificate Name not found in bundle!");
    }

#ifndef WOLFSSL_ALT_CERT_CHAINS
    /* The cert may be a cross-signed copy of a bundle root. Try that also
     * when its issuer is in the bundle but no longer verifies it, such as
     * GTS Root R4 issued by GlobalSign Root CA after both expire. */
    if (preverify != WOLFSSL_SUCCESS) {
        preverify = wolfssl_bundle_cross_sign(preverify, store, cert, dcert);
        *cross_signed = (preverify == WOLFSSL_SUCCESS);
    }
#endif

    return preverify;
}

/* Not a Best Practice, but in dev one can ignore cert date/time: */
#if defined(WOLFSSL_DEBUG_CERT_BUNDLE) && defined(WOLFSSL_DEBUG_IGNORE_ASN_TIME)
static CB_INLINE int wolfssl_ssl_conf_verify_cb_before_date(int preverify,
                                                WOLFSSL_X509_STORE_CTX* store)
{
    if (store == NULL) {
        ESP_LOGE(TAG, "wolfssl_ssl_conf_verify_cb_before_date store is null");
        preverify = 0;
    }
    else if ((preverify == 0) && (store->error == ASN_BEFORE_DATE_E)) {
        ESP_LOGW(TAG, "Overriding ASN_BEFORE_DATE_E!");
        preverify = 1;
    }

    return preverify;
}

static CB_INLINE int wolfssl_ssl_conf_verify_cb_after_date(int preverify,
                                                WOLFSSL_X509_STORE_CTX* store)
{
    if (store == NULL) {
        ESP_LOGE(TAG, "wolfssl_ssl_conf_verify_cb_after_date store is null");
        preverify = 0;
    }
    else if ((preverify == 0) && (store->error == ASN_AFTER_DATE_E)) {
        ESP_LOGW(TAG, "Overriding ASN_AFTER_DATE_E!");
        preverify = 1;
    }

    return preverify;
}
#endif /* WOLFSSL_DEBUG_CERT_BUNDLE && WOLFSSL_DEBUG_IGNORE_ASN_TIME */

#ifdef CONFIG_WOLFSSL_DEBUG_CERT_BUNDLE
void print_cert_subject_and_issuer(WOLFSSL_X509_STORE_CTX* store)
{
    char subjectStr[X509_MAX_SUBJECT_LEN + 1];
    char issuerStr[X509_MAX_SUBJECT_LEN + 1];
    WOLFSSL_BUFFER_INFO buffer;
    WOLFSSL_X509_NAME* subject;
    WOLFSSL_X509_NAME* issuer;
    WOLFSSL_X509* cert;
    int totalCerts;
    int i;

    if (store == NULL) {
        ESP_LOGCBI(TAG, "store is NULL");
        totalCerts = 0;
    }
    else {
        totalCerts = store->totalCerts;
    }

    for (i = 0; i < totalCerts; i++) {
        buffer = store->certs[i];
        cert = wolfSSL_X509_d2i(NULL,
                                            (const unsigned char*)buffer.buffer,
                                              buffer.length);
        if (cert == NULL) {
            ESP_LOGCBI(TAG, "Failed to parse certificate at index %d\n", i);
            continue;
        }

        subject = wolfSSL_X509_get_subject_name(cert);
        issuer = wolfSSL_X509_get_issuer_name(cert);

        if (subject != NULL && issuer != NULL) {
            wolfSSL_X509_NAME_oneline(subject, subjectStr, sizeof(subjectStr));
            wolfSSL_X509_NAME_oneline(issuer, issuerStr, sizeof(issuerStr));

            ESP_LOGCBI(TAG, "Certificate at index %d:\n", i);
            ESP_LOGCBI(TAG, "  Subject: %s\n", subjectStr);
            ESP_LOGCBI(TAG, "  Issuer: %s\n", issuerStr);
        }
        else {
            ESP_LOGCBI(TAG, "Failed to extract subject or issuer at index "
                            "%d\n", i);
        }

        /* Clean up and exit */
        wolfSSL_X509_free(cert);
    }
} /* print_cert_subject_and_issuer */
#endif

/* wolfssl_ssl_conf_verify_cb_no_signer() should only be called
 *  from wolfssl_ssl_conf_verify_cb, handling the special case of
 *  TLS handshake preverify failure for the "No Signer" condition. */
static CB_INLINE int wolfssl_ssl_conf_verify_cb_no_signer(int preverify,
                                                 WOLFSSL_X509_STORE_CTX* store)
{
    char subjectName[X509_MAX_SUBJECT_LEN + 1];

    WOLFSSL_X509_NAME* store_cert_subject = NULL; /* part of store_cert*/
    /* the bundle cert being looked at */
    WC_DECLARE_VAR(bundle_dcert, DecodedCert, 1, NULL);
    int bundle_is_ca = 0;
    /* per call: tasks can verify chains at the same time */
    int crt_found = 0;

    int cross_signed = 0;

#ifdef WOLFSSL_ALT_CERT_CHAINS
    WOLFSSL_BUFFER_INFO buffer;
    WOLFSSL_X509* chain_cert;
    int i;
#endif
#ifdef CONFIG_WOLFSSL_DEBUG_CERT_BUNDLE
    WOLFSSL_STACK* chain;
    int numCerts;
#endif

    int ret = WOLFSSL_SUCCESS;

    WOLFSSL_ENTER("wolfssl_ssl_conf_verify_cb_no_signer");
    ESP_LOGCBI(TAG, "\n\nBegin callback: "
                    "wolfssl_ssl_conf_verify_cb_no_signer\n");

    /* Debugging section for viewing preverify values. */
#ifndef NO_SKIP_PREVIEW
    if (preverify == WOLFSSL_SUCCESS) {
        ESP_LOGCBI(TAG, "Success: Detected prior Pre-verification == 1.");
        /* So far, so good... we need to now check cert against alt */
    }
    else {
        ESP_LOGCBW(TAG, "Detected prior Pre-verification Failure.");
    }
#else
    /* Skip pre-verification, so we'll start with success. */
    ret = WOLFSSL_SUCCESS;
#endif

    /* Check how many CA Certs in our bundle. Need at least one to proceed. */
    if (ret == WOLFSSL_SUCCESS) {
        if (s_crt_bundle.crts == NULL) {
            ESP_LOGE(TAG, "No certificates in bundle.");
            ret = WOLFSSL_FAILURE;
        }
        else {
            ESP_LOGCBI(TAG, "%d certificates in bundle.",
                            s_crt_bundle.num_certs);
            ret = WOLFSSL_SUCCESS;
        }
    }

    if (ret == WOLFSSL_SUCCESS) {
        WC_ALLOC_VAR_EX(bundle_dcert, DecodedCert, 1, NULL, DYNAMIC_TYPE_DCERT,
        {
            ESP_LOGE(TAG, "Out of memory for bundle certificate lookup.");
            ret = WOLFSSL_FAILURE;
        });
    }

    /* Get the current cert from the store. */
    if (ret == WOLFSSL_SUCCESS) {
        /* Get the current certificate being verified during the certificate
         * chain validation process. */
#ifdef OPENSSL_EXTRA
    #ifdef WOLFSSL_ALT_CERT_CHAINS
            /*  Retrieve the last WOLFSSL_BUFFER_INFO struct with alt chains */
            buffer = store->certs[store->totalCerts - 1];
            store_cert = wolfSSL_X509_d2i(NULL,
                                          (const unsigned char*)buffer.buffer,
                                          buffer.length);
    #else
            store_cert = wolfSSL_X509_STORE_CTX_get_current_cert(store);
    #endif

    #ifdef CONFIG_WOLFSSL_DEBUG_CERT_BUNDLE
        chain = wolfSSL_X509_STORE_CTX_get_chain(store);
        numCerts = wolfSSL_sk_X509_num(chain);
        if (!chain) {
            numCerts = 0; /* Verification failed. */
        }
        ESP_LOGI(TAG, "Number of certificates in chain: %d", numCerts);
        print_cert_subject_and_issuer(store);
    #endif
#else
        store_cert = store->current_cert;
#endif
        if (store_cert == NULL) {
            ESP_LOGE(TAG, "Failed to get current certificate.\n");
            ret = WOLFSSL_FAILURE;
        }
        else {
            ret = WOLFSSL_SUCCESS;
        }
    } /* this (ret == WOLFSSL_SUCCESS) step to get cert from store */


    /* Get the target name and subject from the current_cert(store) */
    if (ret == WOLFSSL_SUCCESS) {
        store_cert_subject = wolfSSL_X509_get_subject_name(store_cert);
        if (wolfSSL_X509_NAME_oneline(store_cert_subject, subjectName,
                                      sizeof(subjectName)) == NULL) {
            ESP_LOGE(TAG, "Error converting subject name to string.");
            ret = WOLFSSL_FAILURE;
        }
        else {
            ESP_LOGCBNI(TAG, "Store Cert Subject: %s", subjectName );
        }
    }

    /* When the server presents its certificate, the client checks if this
     * certificate can be traced back to one of the CA certificates in the
     * bundle. */
    if (ret == WOLFSSL_SUCCESS) {
        _cert_bundle_loaded = 1;

#ifdef WOLFSSL_ALT_CERT_CHAINS
        /* The path may end at any cert the server sent (RFC 4158), so try
         * each one from the top down, until a bundle root issued it. This
         * passes over a cross-sign whose issuer is not in the bundle, and a
         * root the server sent that is not in the bundle, such as AAA
         * Certificate Services above the USERTrust cross-sign. Each try
         * verifies the reported cert through the bundle root, so nothing is
         * accepted without a path to that root. With alt cert chains,
         * store_cert is the top cert, certs[totalCerts - 1]. */
        ret = wolfssl_bundle_check_cert(preverify, store, store_cert,
                                        store->totalCerts - 1, bundle_dcert,
                                        &crt_found, &bundle_is_ca,
                                        &cross_signed);
        for (i = store->totalCerts - 2;
             (ret != WOLFSSL_SUCCESS) && (i >= store->error_depth); i--) {
            chain_cert = wolfSSL_X509_d2i(NULL, store->certs[i].buffer,
                                          (int)store->certs[i].length);
            if (chain_cert != NULL) {
                ret = wolfssl_bundle_check_cert(preverify, store, chain_cert,
                                                i, bundle_dcert, &crt_found,
                                                &bundle_is_ca, &cross_signed);
                wolfSSL_X509_free(chain_cert);
            }
        }
#else
        /* wolfSSL trusts each chain CA the callback accepts for the rest of
         * this connection, so only the reported cert can be tried: skipping
         * an untrusted root here would make it a trusted signer for the rest
         * of the chain. */
        ret = wolfssl_bundle_check_cert(preverify, store, store_cert,
                                        store->error_depth, bundle_dcert,
                                        &crt_found, &bundle_is_ca,
                                        &cross_signed);
#endif

        if ((crt_found == 1) && (ret == WOLFSSL_SUCCESS) && !cross_signed) {
            if (bundle_is_ca) {
                ESP_LOGCBI(TAG, "Added Certificate Authority.");
            }
            else {
                ESP_LOGCBW(TAG, "Warning: Added end-entity leaf certificate.");
            }

            /* cert_manager_load() added the bundle cert to the Certificate
             * Manager of this store, which is where wolfSSL looks for it. */
#ifdef WOLFSSL_ALT_CERT_CHAINS
            /* Store verify will fail when alt certs enabled. */
            ESP_LOGCBI(TAG, "Skipping store verify with "
                            "WOLFSSL_ALT_CERT_CHAINS enabled.");
#else
            ESP_LOGCBI(TAG, "wolfSSL_X509_verify_cert(store)");
            ret = wolfSSL_X509_verify_cert(store);
            if (ret == WOLFSSL_SUCCESS) {
                ESP_LOGCBI(TAG, "Successfully verified cert in updated store!");
            }
            else {
                ESP_LOGE(TAG, "Failed to verify cert in updated store! "
                              "ret = %d", ret);
                ret = WOLFSSL_FAILURE;
            }
#endif
        } /* crt_found */
        else if (cross_signed) {
            ESP_LOGCBI(TAG, "Accepted a cross-signed copy of a bundle root.");
        }
        else {
            ESP_LOGE(TAG, "No certificate bundle root verifies the chain.");
#ifndef WOLFSSL_ALT_CERT_CHAINS
            ESP_LOGE(TAG, "If the server sends a root that is not in the "
                          "bundle, enable WOLFSSL_ALT_CERT_CHAINS.");
#endif
            ret = WOLFSSL_FAILURE;
        }
    } /* Did not find a cert */
    else {
        /* not successful, so return zero for failure. */
        ret = WOLFSSL_FAILURE;
    } /* Failed to init, didn't even try to search. */


    /* Clean up and exit */
    WC_FREE_VAR_EX(bundle_dcert, NULL, DYNAMIC_TYPE_DCERT);

    /* We don't clean up the store_cert and x509 as we are in a callback,
     * and it is just a pointer into the actual ctx store cert.
     *
     * See wolfSSL_bundle_cleanup() called after connection completed. */
    ESP_LOGCBI(TAG, "Exit wolfssl_ssl_conf_verify_cb ret = %d", ret);

    WOLFSSL_LEAVE( "wolfssl_ssl_conf_verify_cb complete", ret);

    return ret; /* preverify */
}

/* wolfssl_ssl_conf_verify_cb()
 *   for reference:
 *     typedef int (*VerifyCallback)(int, WOLFSSL_X509_STORE_CTX*);
 *
 * This is the callback for TLS handshake verify / validation. See related:
 *   wolfssl_ssl_conf_verify_cb_no_signer
 *   wolfssl_ssl_conf_verify_cb_before_date
 *   wolfssl_ssl_conf_verify_cb_after_date
 *
 * This callback is called FOR EACH cert in the store.
 * Not all certs in the store will have a match for a cert in the bundle,
 * but we NEED ONE to match when a preverify error occurs.
 *
 * See wolfssl_ssl_conf_verify() for setting callback to this function.
 * Typically set when calling esp_crt_bundle_attach(). Specifically:
 *    cfg->crt_bundle_attach(&tls->conf) in esp_tls_wolfssl.c
 *    from the ESP-IDF esp-tls component.
 *
 * See esp_tls.h file: esp_err_t (*crt_bundle_attach)(void *conf)
 *   and initialization in esp_transport_ssl_crt_bundle_attach
 *       from the tcp_transport component: (transport_ssl.c)
 *
 * Functions in esp_crt_bundle are same names as other providers and
 * gated in as appropriate when enabling CONFIG_ESP_TLS_USING_WOLFSSL.
 *
 * Note the wolfSSL component CMakeLists.txt *MUST* be properly linked in the
 * file to be used within the ESP-IDF. Something like this:
 *
 *   target_link_libraries(${COMPONENT_LIB} PUBLIC ${wolfssl})
 *
 * Returns:
 * 0 if the verification process should stop immediately with an error.
 * 1 if the verification process should continue with the rest of handshake. */
static CB_INLINE int wolfssl_ssl_conf_verify_cb(int preverify,
                                      WOLFSSL_X509_STORE_CTX* store)
{
#ifdef WOLFSSL_DEBUG_CERT_BUNDLE
    char before_str[CTC_DATE_SIZE];
    char after_str[CTC_DATE_SIZE];
    WOLFSSL_ASN1_TIME *notBefore = NULL;
    WOLFSSL_ASN1_TIME *notAfter = NULL;

    int initial_preverify;
    initial_preverify = preverify;

    if (store == NULL) {
        ESP_LOGCBW(TAG, "wolfssl_ssl_conf_verify_cb store is Null. Abort");
        return initial_preverify;
    }

    /* Show the interesting preverify & error state upon entry to callback. */
    if (preverify == 1) {
        ESP_LOGCBI(TAG, "preverify == 1\n");
    }
    else {
        ESP_LOGCBW(TAG, "preverify == %d\n", preverify);
    }

    if (store->error == 0) {
        ESP_LOGCBI(TAG, "store->error == 0");
    }
    else {
        ESP_LOGCBW(TAG, "store->error: %d", store->error);
    }

    notBefore = wolfSSL_X509_get_notBefore(store->current_cert);
    if (wolfSSL_ASN1_TIME_to_string(notBefore, before_str,
                                    sizeof(before_str)) == NULL) {
        ESP_LOGCBW(TAG, "Not Before value not valid");
    }
    else {
        ESP_LOGCBI(TAG, "Not Before: %s", before_str);
    }

    esp_show_current_datetime();

    notAfter = wolfSSL_X509_get_notAfter(store->current_cert);
    if (wolfSSL_ASN1_TIME_to_string(notAfter, after_str,
                                    sizeof(after_str)) == NULL) {
        ESP_LOGCBW(TAG, "Not After value not valid");
    }
    else {
        ESP_LOGCBI(TAG, "Not After: %s", after_str);
    }
#endif

    /* One possible condition is the error "Failed to find signer".
     * This is where we search the bundle for a matching needed CA cert. */
    if ((preverify == 0) && (store->error == ASN_NO_SIGNER_E)) {
        ESP_LOGCBW(TAG, "Setting _need_bundle_cert!");
        _need_bundle_cert = 1;

        preverify = wolfssl_ssl_conf_verify_cb_no_signer(preverify, store);
    }

    /* Another common issue is the date/timestamp.
     * During debugging, we can ignore cert ASN before/after limits: */
#if defined(WOLFSSL_DEBUG_CERT_BUNDLE) && defined(WOLFSSL_DEBUG_IGNORE_ASN_TIME)
    esp_show_current_datetime();

    if ((preverify == 0) && (store->error == ASN_BEFORE_DATE_E)) {
        preverify = wolfssl_ssl_conf_verify_cb_before_date(preverify, store);
    }

    if ((preverify == 0) && (store->error == ASN_AFTER_DATE_E)) {
        preverify = wolfssl_ssl_conf_verify_cb_after_date(preverify, store);
    }
#endif

    /* Insert any other callback handlers here. */

#ifdef WOLFSSL_DEBUG_CERT_BUNDLE
    /* When debugging, show if have we resolved any error. */
    if (preverify == 1) {
        ESP_LOGCBI(TAG, "Returning preverify == 1\n");
        if (preverify != initial_preverify) {
            /* Here we assume wolfssl_ssl_conf_verify_cb_no_signer
             * properly found and validated the problem: such as
             * a new cert from the bundled needed for signing. */
            ESP_LOGCBW(TAG, "Callback overriding error initial preverify = %d, "
                            "returning preverify = %d",
                            initial_preverify, preverify );
        }
    }
    else {
        ESP_LOGCBW(TAG, "Warning; returning preverify == %d\n", preverify);
    }
#endif

    return preverify;
} /* wolfssl_ssl_conf_verify_cb */

/* wolfssl_ssl_conf_verify() patterned after ESP-IDF.
 * Used locally here only. Not used directly by esp-tls.
 *
 * This is typically called during esp_crt_bundle_attach() in
 * *this* file, which has same-name functions gated with the macro:
 *   CONFIG_ESP_TLS_USING_WOLFSSL
 *
 * See also ESP-IDF transport_ssl component. */
void CB_INLINE wolfssl_ssl_conf_verify(wolfssl_ssl_config *conf,
                             int (*f_vrfy) WOLFSSL_X509_VERIFY_CALLBACK,
                             void (*p_vrfy) )
{
    /* Other Cryptographic providers for reference:
    conf->f_vrfy      = f_vrfy;  (verification function callback)
    conf->p_vrfy      = p_vrfy;  (pre-verification value)
    */

    /* typedef int (*VerifyCallback)(int, WOLFSSL_X509_STORE_CTX*); */
    wolfSSL_CTX_set_verify( (WOLFSSL_CTX *)(conf->priv_ctx),
                            WOLFSSL_VERIFY_PEER, wolfssl_ssl_conf_verify_cb);
}

/* esp_crt_verify_callback() patterned after ESP-IDF.
 * Used locally here only. Not used directly by esp-tls.
 *
 * This callback is called for every certificate in the chain. If the chain
 * is proper each intermediate certificate is validated through its parent
 * in the x509_crt_verify_chain() function. So this callback should
 * only verify the first untrusted link in the chain is signed by the
 * root certificate in the trusted bundle
*/
int esp_crt_verify_callback(void *buf, WOLFSSL_X509 *crt, int depth,
                            uint32_t *flags)
{
    WOLFSSL_X509 *child;
    const uint8_t *crt_name;
    int start = 0;
    int middle = 0;
    int end  = 0;
    int crt_found = 0;
    int ret = -1;
    size_t name_len = 0;
    size_t key_len  = 0;

    child = crt;

    if (s_crt_bundle.crts == NULL) {
        ESP_LOGE(TAG, "No certificates in bundle");
        return -1;
    }

    ESP_LOGCBI(TAG, "esp_crt_verify_callback: %d certificates in bundle",
                  s_crt_bundle.num_certs);

    name_len = 0;

    crt_found = false;
    start = 0;
    if (s_crt_bundle.num_certs > 0) {
        end = s_crt_bundle.num_certs - 1;
        middle = (end - start) / 2;
    }
    else {
        end = -1;
        middle = -1;
    }
    /* Look for the certificate using binary search on subject name */
    while (start <= end) {
        name_len = (s_crt_bundle.crts[middle][0] << 8) |
                   (s_crt_bundle.crts[middle][1]);
        crt_name = s_crt_bundle.crts[middle] + CRT_HEADER_OFFSET;

        int cmp_res = memcmp(child->altNames, crt_name, name_len);
        if (cmp_res == 0) {
            ESP_LOGCBI(TAG, "crt found %s", crt_name);
            crt_found = true;
            break;
        }
        else if (cmp_res < 0) {
            end = middle + 1;
        }
        else {
            start = middle - 1;
        }
        middle = (start + end) / 2;
    }

    ret = -1; /* WOLFSSL_ERR_X509_FATAL_ERROR; */
    if (crt_found) {
        key_len = (s_crt_bundle.crts[middle][2] << 8) |
                  (s_crt_bundle.crts[middle][3]);
        /* This is the wolfssl_ssl_conf_verify callback to attach bundle.
         * We'll verify at certificate attachment time. */
        ESP_LOGV(TAG, "Found key. Len = %d", key_len);
        /* Optional validation not implemented at this time. */
        /* See wolfssl_ssl_conf_verify_cb() */
    }
    else {
        ESP_LOGW(TAG, "crt not found!");
    }

    if (ret == 0) {
        ESP_LOGCBI(TAG, "Certificate validated (2)");
        *flags = 0;
        return 0;
    }

    ESP_LOGW(TAG, "Deprecated; this API for compiler compatibility only.");
    ESP_LOGW(TAG, "Please use wolfssl_ssl_conf_verify_cb() .");
    ESP_LOGE(TAG, "Failed to verify certificate");
    return -1; /* WOLFSSL_ERR_X509_FATAL_ERROR; */
} /* esp_crt_verify_callback */

/* wolfssl_ssl_conf_authmode() patterned after ESP-IDF. */
void wolfssl_ssl_conf_authmode(wolfssl_ssl_config *conf, int authmode)
{
    wolfSSL_CTX_set_verify( (WOLFSSL_CTX *)conf->priv_ctx, authmode, NULL);
}

/* API wolfssl_x509_crt_init */
void wolfssl_x509_crt_init(WOLFSSL_X509 *crt)
{
    InitX509(crt, 0, NULL);
}

/* cert buffer compatibility helper */
void wolfssl_ssl_conf_ca_chain(wolfssl_ssl_config *conf,
                               WOLFSSL_X509       *ca_chain,
                               WOLFSSL_X509_CRL   *ca_crl)
{
    conf->ca_chain   = ca_chain;
    conf->ca_crl     = ca_crl;

#if defined(WOLFSSL_X509_TRUSTED_CERTIFICATE_CALLBACK)
    /* wolfssl_ssl_conf_ca_chain() and wolfsslssl_ssl_conf_ca_cb()
     * cannot be used together. */
    conf->f_ca_cb = NULL;
    conf->p_ca_cb = NULL;
#endif /* WOLFSSL_X509_TRUSTED_CERTIFICATE_CALLBACK */
}

#ifdef CONFIG_WOLFSSL_CERTIFICATE_BUNDLE
esp_err_t esp_crt_bundle_is_valid(void)
{
    return _esp_crt_bundle_is_valid;
}

/* Initialize the bundle into an array so we can do binary
 * search for certs; the bundle generated by the python utility is
 * normally already presorted by subject name attributes in ARBITRARY order!
 *
 * See gen_crt_bundle.py regarding element extraction sort.
 *
 * To used as unsorted list, see above:
 *    `#define CERT_BUNDLE_UNSORTED`
 */
static esp_err_t wolfssl_esp_crt_bundle_init(const uint8_t *x509_bundle,
                                             size_t bundle_size)
{
    const uint8_t *bundle_end = NULL;
    const uint8_t *cur_crt = NULL;
    uint16_t i;
    size_t cert_len;
    int ret = ESP_OK;

    WOLFSSL_ENTER("wolfssl_esp_crt_bundle_init");
    _esp_crt_bundle_is_valid = ESP_OK; /* Assume valid until proven otherwise. */

    _cert_bundle_loaded = 0;
    _need_bundle_cert = 0;

    /* Basic check of bundle size. */
    if (ret == ESP_OK) {
        if (bundle_size < BUNDLE_HEADER_OFFSET + CRT_HEADER_OFFSET) {
            ESP_LOGE(TAG, "Invalid certificate bundle size");
            _esp_crt_bundle_is_valid = ESP_FAIL;
            ret = ESP_ERR_INVALID_ARG;
        }
    }

    /* Number of certificates pre-calculated in python script, extract value: */
    if (ret == ESP_OK) {
        num_certs = (x509_bundle[0] << 8) | x509_bundle[1];
        if (num_certs > CONFIG_WOLFSSL_CERTIFICATE_BUNDLE_MAX_CERTS) {
            ESP_LOGE(TAG, "Number of certs in the certificate bundle = %d "
                          "exceeds\nMax allowed certificates in certificate "
                          "bundle = %d\nPlease update the menuconfig option",
                          num_certs,
                          CONFIG_WOLFSSL_CERTIFICATE_BUNDLE_MAX_CERTS);
            _esp_crt_bundle_is_valid = ESP_FAIL;
            ret = ESP_ERR_INVALID_ARG;
        }
        else {
            ESP_LOGCBI(TAG, "No. of certs in certificate bundle = % d",
                            num_certs);
            ESP_LOGCBI(TAG, "Max allowed certificates in certificate bundle = "
                            "%d", CONFIG_WOLFSSL_CERTIFICATE_BUNDLE_MAX_CERTS);
        }
    } /* ret == ESP_OK */

    if (ret == ESP_OK) {
#ifdef DEBUG_WOLFSSL_MALLOC
        ESP_LOGW(TAG, "calloc certs: %d bytes", (uint)sizeof(x509_bundle));
#endif
        /* Contiguous allocation is important to our cert extraction. */
        crts = calloc(num_certs, sizeof(x509_bundle));
        if (crts == NULL) {
            ESP_LOGE(TAG, "Unable to allocate memory for bundle pointers");
            _esp_crt_bundle_is_valid = ESP_FAIL;
            ret = ESP_ERR_NO_MEM;
        }
    } /* ret == ESP_OK */

    /* If all is ok, proceed with initialization of Certificate Bundle */
    if (ret == ESP_OK) {
        bundle_end = x509_bundle + bundle_size;
        /* This is the maximum region that is allowed to access */
        ESP_LOGCBI(TAG, "Bundle Start 0x%x", (intptr_t)x509_bundle);
        ESP_LOGCBI(TAG, "Bundle End   0x%x", (intptr_t)bundle_end);
        ESP_LOGCBI(TAG, "Bundle Size    %u bytes", bundle_size);
        cur_crt = x509_bundle + BUNDLE_HEADER_OFFSET;

        for (i = 0; i < num_certs; i++) {
            ESP_LOGCBI(TAG, "Init Cert %d", i);
            if (cur_crt + CRT_HEADER_OFFSET > bundle_end) {
                ESP_LOGE(TAG, "Invalid certificate bundle current offset");
                _esp_crt_bundle_is_valid = ESP_FAIL;
                ret = ESP_ERR_INVALID_ARG;
                break;
            }

            crts[i] = cur_crt;

#ifndef IS_WOLFSSL_CERT_BUNDLE_FORMAT
            ESP_LOGE("err", "Error: not IS_WOLFSSL_CERT_BUNDLE_FORMAT");
            /* For reference only */
            size_t name_len = cur_crt[0] << 8 | cur_crt[1];
            size_t key_len = cur_crt[2] << 8 | cur_crt[3];
            cur_crt = cur_crt + CRT_HEADER_OFFSET + name_len + key_len;
#else
            cert_len = cur_crt[0] << 8 | cur_crt[1];
            ESP_LOGCBI(TAG, "- This certificate at 0x%x, length: %u",
                             (intptr_t)cur_crt, cert_len);

            if (cur_crt + CRT_HEADER_OFFSET + cert_len > bundle_end) {
                ESP_LOGE(TAG, "Invalid certificate bundle cert length");
                _esp_crt_bundle_is_valid = ESP_FAIL;
                ret = ESP_ERR_INVALID_ARG;
                break;
            }

            /* look at next cert */
            cur_crt = cur_crt + (CRT_HEADER_OFFSET + cert_len);
#endif
        } /* for certs 0 to num_certs - 1 in the order found */
    } /* ret == ESP_OK */

    /* One final validation check. */
    if (cur_crt > bundle_end) {
        ESP_LOGE(TAG, "Invalid certificate bundle after end");
        _esp_crt_bundle_is_valid = ESP_FAIL;
        ret = ESP_ERR_INVALID_ARG;
    }

    if (_esp_crt_bundle_is_valid ==  ESP_FAIL) {
        if (crts == NULL) {
#ifdef DEBUG_WOLFSSL_MALLOC
            ESP_LOGW(TAG, "Free certs after invalid bundle");
#endif
            free(crts);
            crts = NULL;
            s_crt_bundle.num_certs = 0;
            s_crt_bundle.crts = NULL;
        }
    }
    else {
        /* The previous crt bundle is only updated when initialization of the
         * current crt_bundle is successful */
        /* Free previous crt_bundle */
        if (s_crt_bundle.crts != NULL) {
#ifdef DEBUG_WOLFSSL_MALLOC
            ESP_LOGI(TAG, "Free crts");
#endif
            free(s_crt_bundle.crts);
        }
        s_crt_bundle.num_certs = num_certs;
        s_crt_bundle.crts = crts;
    }

    WOLFSSL_LEAVE("wolfssl_esp_crt_bundle_init", ret);
    return ret;
} /* esp_crt_bundle_init */

/* esp_crt_bundle_attach() used by ESP-IDF esp-tls layer. */
esp_err_t esp_crt_bundle_attach(void *conf)
{
    esp_err_t ret = ESP_OK;
    size_t bundle_size = 0;
    ESP_LOGCBI(TAG, "Enter esp_crt_bundle_attach");
    /* If no bundle has been set by the user,
     * then use the bundle embedded in the binary */
#ifdef PLATFORMIO
    ESP_LOGCBW(TAG, "Found PLATFORMIO, beware of alternate cert bundles.");
#endif
    if (s_crt_bundle.crts == NULL) {
        ESP_LOGCBI(TAG, "No bundle set by user; using the embedded binary.");
        ESP_LOGCBI(TAG, "x509_crt_imported_bundle_wolfssl_bin_start 0x%x",
               (intptr_t)x509_crt_imported_bundle_wolfssl_bin_start);
        ESP_LOGCBI(TAG, "x509_crt_imported_bundle_wolfssl_bin_end   0x%x",
               (intptr_t)x509_crt_imported_bundle_wolfssl_bin_end);
        if ((intptr_t)x509_crt_imported_bundle_wolfssl_bin_end <
            (intptr_t)x509_crt_imported_bundle_wolfssl_bin_start) {
            ESP_LOGE(TAG, "Imported bundle end less than starting address");
            ret = ESP_FAIL;
        }
        else {
            bundle_size = (x509_crt_imported_bundle_wolfssl_bin_end
                           - x509_crt_imported_bundle_wolfssl_bin_start);
            if (bundle_size == 0) {
                ESP_LOGE(TAG, "Imported bundle size is zero. Empty?");
                ret = ESP_FAIL;
            }
            else {
                ESP_LOGCBI(TAG, "Importing x509 wolfSSL bundle, %u bytes",
                                 bundle_size);
                ret = wolfssl_esp_crt_bundle_init(
                                 x509_crt_imported_bundle_wolfssl_bin_start,
                                 bundle_size);
            }
        }
    }
    else {
        ESP_LOGCBI(TAG, "Cert bundle set by user at 0x%x.",
                       (intptr_t)s_crt_bundle.crts);
    }

    if (((uintptr_t)x509_crt_imported_bundle_wolfssl_bin_start % 4) == 0) {
        ESP_LOGCBI(TAG, "Confirmed alignment x509_crt_imported_bundle_wolfssl");
    }
    else {
        ESP_LOGCBI(TAG, "Not aligned: x509_crt_imported_bundle_wolfssl");
    }

    if (ret == ESP_OK) {
        if (conf) {
            wolfssl_ssl_config *ssl_conf = (wolfssl_ssl_config *)conf;
            wolfssl_ssl_conf_verify(ssl_conf, esp_crt_verify_callback, NULL);
        }
        else {
            ESP_LOGCBI(TAG, "esp_crt_bundle_attach no conf object supplied");
        }
    }
    else {
        ESP_LOGE(TAG, "Failed to attach bundle");
    }
    ESP_LOGCBI(TAG, "esp_crt_bundle_attach completed for wolfSSL");

    _esp_crt_bundle_is_valid = ret;
    return ret;
} /* esp_crt_bundle_attach */

/* esp_crt_bundle_detach() used by ESP-IDF esp-tls layer. */
void esp_crt_bundle_detach(wolfssl_ssl_config *conf)
{
    ESP_LOGI(TAG, "esp_crt_bundle_detach");
    _cert_bundle_loaded = 0;
    _need_bundle_cert = 0;

    if (s_crt_bundle.crts != NULL) {
#ifdef DEBUG_WOLFSSL_MALLOC
        ESP_LOGI(TAG, "Free s_crt_bundle.crts");
#endif
        free(s_crt_bundle.crts);
        s_crt_bundle.crts = NULL;
    }
    if (conf) {
        wolfssl_ssl_conf_verify(conf, NULL, NULL);
        ESP_LOGE(TAG, "esp_crt_bundle_detach not implemented for wolfSSL");
    }
    ESP_LOGE(TAG, "Not implemented: esp_crt_bundle_detach");

    /* If there's no cert bundle attached, it is not valid: */
    _esp_crt_bundle_is_valid = ESP_FAIL;
}

/* The name esp_crt_bundle_set() used by ESP-IDF esp-tls layer,
 * but called wolfssl_esp_crt_bundle_init here. */
esp_err_t esp_crt_bundle_set(const uint8_t *x509_bundle, size_t bundle_size)
{
    return wolfssl_esp_crt_bundle_init(x509_bundle, bundle_size);
}

/* Clean up bundle when closing connection from ESP-TLS layer. */
esp_err_t wolfSSL_bundle_cleanup(void)
{
#ifdef DEBUG_WOLFSSL_MALLOC
    size_t free_heap_size;
    size_t min_free_heap_size;
    size_t free_internal_heap_size;
#endif

    ESP_LOGV(TAG, "Enter wolfSSL_bundle_cleanup");

    if (s_crt_bundle.crts != NULL) {
#ifdef DEBUG_WOLFSSL_MALLOC
        ESP_LOGI(TAG, "Free s_crt_bundle.crts in wolfSSL_bundle_cleanup");
#endif
        free(s_crt_bundle.crts);
        s_crt_bundle.crts = NULL;
    }

#ifdef WOLFSSL_CMAKE_REQUIRED_ESP_TLS
    /* When the esp-tls is linked as a requirement in CMake and used by the
     * ESP-IDF in the esp-tls component, call at cleanup time: */
    esp_tls_free_global_ca_store();
#endif

    if (store_cert != NULL) {
#ifdef DEBUG_WOLFSSL_MALLOC
        ESP_LOGI(TAG, "Free store_cert in wolfSSL_bundle_cleanup");
#endif
        wolfSSL_X509_free(store_cert);
        store_cert = NULL;
    }

    memset(&s_crt_bundle, 0, sizeof(s_crt_bundle));

#ifdef DEBUG_WOLFSSL_MALLOC
    /* Get total free heap size */
    free_heap_size = esp_get_free_heap_size();
    ESP_LOGI(TAG, "Free heap size: %u bytes", free_heap_size);

    /* Get minimum ever free heap size (since boot) */
    min_free_heap_size = esp_get_minimum_free_heap_size();
    ESP_LOGI(TAG, "Minimum ever free heap size: %u bytes", min_free_heap_size);

    /* Get the amount of free memory in internal RAM */
    free_internal_heap_size = heap_caps_get_free_size(MALLOC_CAP_INTERNAL);
    ESP_LOGI(TAG, "Free internal heap size: %u bytes", free_internal_heap_size);
#endif /* DEBUG_WOLFSSL_MALLOC */

    return ESP_OK;
}
#endif /* CONFIG_WOLFSSL_CERTIFICATE_BUNDLE */

/* Sanity checks: */
#if defined(CONFIG_WOLFSSL_NO_ASN_STRICT) && !defined(WOLFSSL_NO_ASN_STRICT)
    /* The settings.h and/or user_settings.h should have detected config
     * values from Kconfig and set the appropriate wolfSSL macro: */
    #error "CONFIG_WOLFSSL_NO_ASN_STRICT found without WOLFSSL_NO_ASN_STRICT"
#endif /* CONFIG_WOLFSSL_NO_ASN_STRICT && ! WOLFSSL_NO_ASN_STRICT */

#endif /* CONFIG_WOLFSSL_CERTIFICATE_BUNDLE && !(NONE cert) */
#endif /* CONFIG_ESP_TLS_USING_WOLFSSL */
#endif /* WOLFSSL_ESPIDF */
