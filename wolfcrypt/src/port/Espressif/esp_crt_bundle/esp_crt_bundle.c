/* esp_crt_bundle.c
 *
 * Copyright (C) 2006-2024 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
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
extern const uint8_t x509_crt_imported_bundle_wolfssl_bin_start[]
                     asm("_binary_x509_crt_bundle_wolfssl_start");

extern const uint8_t x509_crt_imported_bundle_wolfssl_bin_end[]
                     asm("_binary_x509_crt_bundle_wolfssl_end");

/* This crt_bundle_t type must match other providers in esp-tls from ESP-IDF.
 * TODO: Move to common header in ESP-IDF. (requires ESP-IDF modification).
 * For now, it is here: */
typedef struct crt_bundle_t {
    const uint8_t **crts;
    uint16_t num_certs;
    size_t x509_crt_bundle_wolfssl_len;
} crt_bundle_t;

static WOLFSSL_X509* store_cert = NULL; /* will point to existing param values*/
static WOLFSSL_X509* bundle_cert = NULL; /* the iterating cert being reviewed.*/

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
static esp_err_t _wolfssl_found_zero_serial = ESP_OK;

static int _cert_bundle_loaded = 0;

static int _crt_found = 0;

static int _added_cert = 0;

static int _need_bundle_cert = 0;


/* Returns ESP_OK if there are no zero serial numbers in the bundle,
 * OR there may be zeros, but */
static CB_INLINE int wolfssl_found_zero_serial(void)
{
    return _wolfssl_found_zero_serial;
}

/* Returns:
 *   1 if the cert has a zero serial number
 *   0 if the cert has a non-zero serial number
 * < 0 for error wolfssl\wolfcrypt\error-crypt.h values  */
static CB_INLINE int wolfssl_is_zero_serial_number(const uint8_t *der_cert,
                                                             int sz)
{
    DecodedCert cert;
    int ret = 0;

    wc_InitDecodedCert(&cert, der_cert, sz, NULL);

    ret = wc_ParseCert(&cert, CERT_TYPE, NO_VERIFY, 0);

    /* Check the special case of parse error with strict checking. */
    if ((cert.serialSz == 1) && (cert.serial[0] == 0x0)) {
        /* If we find a zero serial number, a parse error may still occur. */
        if (ret == ASN_PARSE_E) {
            /* Issuer amd subject will only be non-blank with relaxed check */
            ESP_LOGW(TAG, "Encountered ASN Parse error with zero serial");
            ESP_LOGCBI(TAG, "Issuer: %s", cert.issuer);
            ESP_LOGCBI(TAG, "Subject: %s", cert.subject);
#if defined(CONFIG_WOLFSSL_NO_ASN_STRICT) || \
    defined(       WOLFSSL_NO_ASN_STRICT)
            ESP_LOGW(TAG, "WOLFSSL_NO_ASN_STRICT enabled. Ignoring error.");

            /* We'll force the return result to one for a "valid"
             * parsing result, but not strict and found zero serial num. */
            ret = 1;
#else
    #if defined(CONFIG_WOLFSSL_ASN_ALLOW_0_SERIAL) || \
        defined(       WOLFSSL_ASN_ALLOW_0_SERIAL)
            /* Issuer amd subject will only be non-blank with relaxed check */
            ESP_LOGCBW(TAG, "WOLFSSL_ASN_ALLOW_0_SERIAL enabled. "
                            "Ignoring error.");

            /* We'll force the return result for a "valid" parsing result,
             * not strict and found zero serial num. */
            ret = 1;
    #else
            ESP_LOGE(TAG, "ERROR: Certificate must have a Serial Number.");
            ESP_LOGE(TAG, "Define WOLFSSL_NO_ASN_STRICT or "
                          "WOLFSSL_ASN_ALLOW_0_SERIALto relax checks.");
            /* ret (Keep ASN_PARSE_E)  */
    #endif
#endif
        } /* special ASN_PARSE_E handling */
        else {
            /* Not an ASN Parse Error; the zero configured to be allowed. */
            ESP_LOGV(TAG, "WARNING: Certificate has no Serial Number.");

            /* If we found a zero, and the result of wc_ParseCert is zero,
             * we'll return that zero as "cert has a zero serial number". */
        }
    }
    else {
        ESP_LOGV(TAG, "Not a special case zero serial number.");
    }

    if (ret > -1) {
        ESP_LOGV(TAG, "Issuer: %s", cert.issuer);
        ESP_LOGV(TAG, "Subject: %s", cert.subject);
        ESP_LOGV(TAG, "Serial Number: %.*s", cert.serialSz, cert.serial);
    }
    else {
        ESP_LOGCBV(TAG, "wolfssl_is_zero_serial_number exit  = %d", ret);
    }

    /* Clean up and exit */
    wc_FreeDecodedCert(&cert);

    return ret;
}

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
                               will be discarded (only with SESSION_CERTS) */
static CB_INLINE int cert_manager_load(int preverify,
                                       WOLFSSL_X509_STORE_CTX* store,
                                       const unsigned char * der, long derSz)
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
        /* Attempt to validate the certificate again */
        ret = wolfSSL_CertManagerVerifyBuffer(cm, der, derSz,
            WOLFSSL_FILETYPE_ASN1);

        if (ret == WOLFSSL_SUCCESS) {
            ESP_LOGCBI(TAG, "Successfully validated cert: %s\n", subject->name);

            /* If verification is successful then override error. */
            preverify = 1;
        }
        else {
            ESP_LOGE(TAG, "Failed to verify cert after loading new CA. "
                          "err = %d", ret);
        }
    }
    else {
        ESP_LOGE(TAG, "Failed to load CA");
    }

    /* We don't free the issue and subject, as they are
     * pointers to current store->current_cert values. */
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

    const unsigned char* cert_data = NULL;
    const unsigned char* cert_bundle_data = NULL;

    WOLFSSL_X509_NAME* store_cert_subject = NULL; /* part of store_cert*/
    WOLFSSL_X509_NAME* store_cert_issuer = NULL;  /* part of store_cert*/
    WOLFSSL_X509_NAME* this_subject = NULL;     /* part of bundle_cert.*/
    WOLFSSL_X509_NAME* this_issuer = NULL;      /* part of bundle_cert.*/

    intptr_t this_addr = 0; /* Beginning of the bundle object: [size][cert]  */
    int derCertLength = 0; /* The [size] value: length of [cert] budnle item */
    int cmp_res = 0;
    int last_cmp = -1;

    int start = 0;  /* Beginning of search; only changes if binary search.   */
    int end = 0;    /* End of bunndle search; only changes if binary search. */
    int middle = 0; /* Middle value for binary search, otherwise increments. */

#ifdef WOLFSSL_ALT_CERT_CHAINS
    WOLFSSL_BUFFER_INFO buffer;
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
        store_cert_issuer = wolfSSL_X509_get_issuer_name(store_cert);
        if (store_cert_issuer == NULL) {
            ESP_LOGE(TAG, "Error converting Store Cert Issuer to string");
            ret = WOLFSSL_FAILURE;
        }
        else {
            ESP_LOGCBI(TAG, "Store Cert Issuer:  %s", store_cert_issuer->name );
        }
    }

    /* When the server presents its certificate, the client checks if this
     * certificate can be traced back to one of the CA certificates in the
     * bundle.
     *
     * NOTE: To save memory, the store `cert` from above is overwritten below.
     * Any details needed from the store `cert` should have been saved.
     *
     * We'll proceed by assigning `cert` to each of the respective items in
     * bundle as we attempt to find the desired cert: */
    if (ret == WOLFSSL_SUCCESS) {
        _cert_bundle_loaded = 1;
        start = 0;
        if (s_crt_bundle.num_certs > 0) {
            end = s_crt_bundle.num_certs - 1;
        }
        else {
            ESP_LOGCBW(TAG, "The certificate bundle is empty.");
            end = -1;
        }

#ifndef CERT_BUNDLE_UNSORTED
        /* When sorted (not unsorted), binary search: */
        middle = (end - start) / 2;
#else
        /* When not sorted, we start at beginning and look at each: */
        ESP_LOGCBW(TAG, "Looking at CA indexed. Start = %d, end = %d",
                         start, end);
        middle = 0;
#endif
        /* Look for the certificate searching on subject name: */
        while (start <= end) {
#ifndef CERT_BUNDLE_UNSORTED
            ESP_LOGCBNW(TAG, "Looking at CA #%d; Binary Search start = %d,"
                            "end = %d", middle, start, end);
#else
            ESP_LOGCBNW(TAG, "Looking at CA index #%d", middle);
#endif
#ifndef IS_WOLFSSL_CERT_BUNDLE_FORMAT
            /* For reference only */
            name_len = s_crt_bundle.crts[middle][0] << 8 |
                       s_crt_bundle.crts[middle][1];
            crt_name = s_crt_bundle.crts[middle] + CRT_HEADER_OFFSET;
            ESP_LOGI(TAG, "String: %.*s", name_len, crt_name);
            int cmp_res =  memcmp(subject, crt_name, name_len);
#else
            /* Each cert length should have been saved via python script: */
            derCertLength = (s_crt_bundle.crts[middle][0] << 8) |
                             s_crt_bundle.crts[middle][1];
            this_addr = (intptr_t)s_crt_bundle.crts[middle];
            ESP_LOGCBI(TAG, "This addr = 0x%x", this_addr);

            cert_data = (const unsigned char*)(this_addr + CRT_HEADER_OFFSET);

            if (wolfssl_is_zero_serial_number(cert_data, derCertLength)) {
                ESP_LOGW(TAG, "Warning: No Certificate Serial Number: "
                              "for Certificate #%d", middle);
            }

            ESP_LOGCBI(TAG, "s_crt_bundle ptr = 0x%x", (intptr_t)cert_data);
            ESP_LOGCBI(TAG, "derCertLength    = %d", derCertLength);

            /* Convert the DER format in the Cert Bundle to x509.
             * Reminder: Cert PEM files converted to DER by gen_crt_bundle.py */
            cert_bundle_data = cert_data; /* wolfSSL_d2i_X509 changes address */

            /* Ensure we don't keep adding new bundle_certs to the heap. */
            if (bundle_cert != NULL) {
                wolfSSL_X509_free(bundle_cert);
            }
            bundle_cert = wolfSSL_d2i_X509(NULL, &cert_bundle_data,
                                                  derCertLength);

            if (bundle_cert == NULL) {
                ESP_LOGE(TAG, "Error loading DER Certificate Authority (CA)"
                              "from bundle #%d.", middle);
        #if !defined(WOLFSSL_NO_ASN_STRICT) && \
            !defined(WOLFSSL_ASN_ALLOW_0_SERIAL)
                /* Suggestion only when relevant: */
                if (wolfssl_found_zero_serial()) {
                    ESP_LOGE(TAG, "Try turning on WOLFSSL_NO_ASN_STRICT "
                                  "or WOLFSSL_ASN_ALLOW_0_SERIAL");
                }
        #endif
                ret = WOLFSSL_FAILURE;
            }
            else {
                ESP_LOGCBI(TAG, "Successfully loaded DER certificate!");
                ret = WOLFSSL_SUCCESS;
            }

            if (ret == WOLFSSL_SUCCESS) {
                this_issuer = wolfSSL_X509_get_issuer_name(bundle_cert);
                if (this_issuer == NULL) {
                    ESP_LOGE(TAG, "Error getting issuer name.");
                    ret = WOLFSSL_FAILURE;
                }
                else {
                    ESP_LOGCBNI(TAG, "This Bundle Item Issuer Name:  %s",
                                  this_issuer->name);
                }

                this_subject = wolfSSL_X509_get_subject_name(bundle_cert);
                if (this_subject == NULL) {
                    ESP_LOGE(TAG, "Error getting subject name.");
                    ret = WOLFSSL_FAILURE;
                }
                else {
                    if (wolfSSL_X509_NAME_oneline(this_subject, subjectName,
                                                 sizeof(subjectName)) == NULL) {
                        ESP_LOGE(TAG, "Error converting subject name "
                                      "to string.");
                        ret = WOLFSSL_FAILURE;
                    }
                    ESP_LOGCBI(TAG, "This Bundle Item Subject Name: %s",
                                   subjectName);
                }
            }

            /* subject == issuer */
            if (ret == WOLFSSL_SUCCESS) {
                /* Compare the current store cert issuer saved above, to the
                 * current one being inspected in the bundle loop. We want to
                 * match this bundle item issuer with the store certificate
                 * subject name, as later we'll call wolfSSL_X509_check_issued()
                 * which compares these fields. */

                cmp_res = strcmp(this_subject->name,
                                 store_cert_issuer->name);
                last_cmp = cmp_res; /* in case we have to skip an item, save */
            }
            else {
                ESP_LOGCBW(TAG, "Skipping CA #%d due to failure", middle);
                cmp_res = last_cmp;
            }
    #ifdef CERT_BUNDLE_UNSORTED
            if (cmp_res != last_cmp) {
                ESP_LOGE(TAG, "Warning: unsorted!");
            }
    #endif
#endif
            ESP_LOGCBV(TAG, "This cmp_res = %d", cmp_res);
            if (cmp_res == 0) {
                ESP_LOGCBI(TAG, "Found a cert issuer match: %s",
                                this_issuer->name);
                _crt_found = 1;
                break;
            }

            /* The next indexed cert item to look at: [middle] value: */
#ifndef CERT_BUNDLE_UNSORTED
            /* If the list is presorted, we can use a binary search. */
            else if (cmp_res < 0) {
                start = middle + 1;
            }
            else {
                end = middle - 1;
            }
            middle = start + ((end - start) / 2);
#else
            /* When the list is NOT presorted, typically during debugging,
             * just step though in the order found until one is found: */
            else {
                middle++;
                start = middle;
            }
#endif
            ESP_LOGCBV(TAG, "Item = %d; start: %d, end: %d",
                             middle, start, end);
            if (!_crt_found) {
                /* this_issuer and this_subject are parts of this bundle_cert
                 * so we don't need to clean them up explicitly.
                 *
                 * However, we'll start over with a freash bundle_cert for the
                 * next search iteration. */
                if (bundle_cert != NULL) {
                    wolfSSL_X509_free(bundle_cert);
                }
                bundle_cert = wolfSSL_X509_new();
            }
        } /* while (start <= end) */

        /************************* END Bundle Search. *************************/

        /* After searching the bundle for an appropriate CA, if found then
         * load into the provided cert manager. */
        if (_crt_found) {
            ESP_LOGCBW(TAG, "Found a Matching Certificate Name in the bundle!");
            ret = cert_manager_load(preverify, store, cert_data, derCertLength);
            if (ret == WOLFSSL_FAILURE) {
                ESP_LOGW(TAG, "Warning: found a matching cert, but not added "
                              "to the Certificate Manager. error: %d", ret);
            }
            else {
                ESP_LOGCBI(TAG, "New CA added to the Certificate Manager.");
            }
        }
        else {
            ESP_LOGCBW(TAG, "Matching Certificate Name not found in bundle!");
            ret = WOLFSSL_FAILURE;
        } /* crt search result */

        if ((_crt_found == 1) && (ret == WOLFSSL_SUCCESS)) {
#ifdef WOLFSSL_ALT_CERT_CHAINS
            /* Store verify will fail when alt certs enabled. */
            ESP_LOGCBI(TAG, "Skipping pre-update store verify with "
                            "WOLFSSL_ALT_CERT_CHAINS enabled.");
#else
            /* Unlikely to work without alt cert chains, try to verify: */
            ret = wolfSSL_X509_verify_cert(store);
            if (ret == WOLFSSL_SUCCESS) {
                ESP_LOGCBI(TAG, "Successfully verified store before "
                                "making changes");
            }
            else {
                ESP_LOGE(TAG, "Failed to verify store before making changes! "
                              "ret = %d", ret);
            }
#endif

#if defined(OPENSSL_EXTRA)
            ESP_LOGCBI(TAG, "Checking wolfSSL_X509_check_issued(bundle_cert, "
                            "store_cert)");
            if (store_cert && wolfSSL_X509_check_issued(bundle_cert,
                                                     store_cert) == X509_V_OK) {
                ESP_LOGCBI(TAG, "wolfSSL_X509_check_issued == X509_V_OK");

            }
            else {
                /* This is ok, we may have others */
                ESP_LOGCBI(TAG, "wolfSSL_X509_check_issued failed. "
                                "(there may be others)");
            }
#else
            ESP_LOGW(TAG, "Warning: skipping wolfSSL_X509_check_issued, "
                          "OPENSSL_EXTRA not enabled.");
#endif

            if (_added_cert == 0) {
                /* Is this a CA or Leaf? */
                if (bundle_cert->isCa == 1) {
                        ESP_LOGCBI(TAG, "Adding Certificate Authority.");
                    }
                else {
                        ESP_LOGCBW(TAG, "Warning: Adding end-entity leaf "
                                        "certificate.");
                }

                /* Note that although we are adding a certificate to the store
                 * now, it is too late to be used in the current TLS connection
                 * that caused the callback. See the Cerfiicate Manager for
                 * validation and possible overriding of preverify values. */
                ESP_LOGCBI(TAG, "\n\nAdding Cert for Certificate Store!\n");
                ret = wolfSSL_X509_STORE_add_cert(store->store, bundle_cert);
                if (ret == WOLFSSL_SUCCESS) {
                    ESP_LOGCBI(TAG, "Successfully added cert to wolfSSL "
                                    "Certificate Store!");
                    _added_cert = 1;
                }
                else {
                    ESP_LOGE(TAG, "Failed to add cert to store! ret = %d", ret);
                    ret = WOLFSSL_FAILURE;
                }
            }
            else {
                ESP_LOGCBI(TAG, "Already added a matching cert!");
            } /* _added_cert */

#ifdef WOLFSSL_ALT_CERT_CHAINS
            /* Store verify will fail when alt certs enabled. */
            ESP_LOGCBI(TAG, "Skipping post-update store verify with "
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
        else {
            ESP_LOGE(TAG, "Did not find a matching crt");
            ret = WOLFSSL_FAILURE;
        }
    } /* Did not find a cert */
    else {
        /* not successful, so return zero for failure. */
        ret = WOLFSSL_FAILURE;
    } /* Failed to init, didn't even try to search. */


    /* Clean up and exit */
    if ((_crt_found == 0) && (bundle_cert != NULL)) {
        ESP_LOGW(TAG, "Cert not found, free bundle_cert");
        wolfSSL_X509_free(bundle_cert);
        bundle_cert = NULL;
        /* this_subject and this_issuer are pointers into cert used.
         * Don't free if the cert was found. */
        wolfSSL_X509_NAME_free(this_subject);
        this_subject = NULL;
        wolfSSL_X509_NAME_free(this_issuer);
        this_issuer = NULL;
    }

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
    _crt_found = 0;
    _added_cert = 0;
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
        /* This is the maximum region that is allowed to access */
        ESP_LOGV(TAG, "Bundle Start 0x%x", (intptr_t)x509_bundle);
        ESP_LOGV(TAG, "Bundle Size  %d", bundle_size);
        bundle_end = x509_bundle + bundle_size;
        ESP_LOGV(TAG, "Bundle End   0x%x", (intptr_t)bundle_end);
        cur_crt = x509_bundle + BUNDLE_HEADER_OFFSET;

        for (i = 0; i < num_certs; i++) {
            ESP_LOGV(TAG, "Init Cert %d", i);
            if (cur_crt + CRT_HEADER_OFFSET > bundle_end) {
                ESP_LOGE(TAG, "Invalid certificate bundle current offset");
                _esp_crt_bundle_is_valid = ESP_FAIL;
                ret = ESP_ERR_INVALID_ARG;
                break;
            }

            crts[i] = cur_crt;

#ifndef IS_WOLFSSL_CERT_BUNDLE_FORMAT
            /* For reference only */
            size_t name_len = cur_crt[0] << 8 | cur_crt[1];
            size_t key_len = cur_crt[2] << 8 | cur_crt[3];
            cur_crt = cur_crt + CRT_HEADER_OFFSET + name_len + key_len;
#else
            cert_len = cur_crt[0] << 8 | cur_crt[1];
    #if defined(CONFIG_WOLFSSL_ASN_ALLOW_0_SERIAL) || \
            defined(       WOLFSSL_ASN_ALLOW_0_SERIAL) || \
            defined(CONFIG_WOLFSSL_NO_ASN_STRICT)      || \
            defined(       WOLFSSL_NO_ASN_STRICT)
            if (wolfssl_is_zero_serial_number(cur_crt + CRT_HEADER_OFFSET,
                                                 cert_len) > 0) {
                ESP_LOGW(TAG, "Warning: found zero value for serial number in "
                              "certificate #%d", i);
                ESP_LOGW(TAG, "Enable WOLFSSL_NO_ASN_STRICT to allow zero in "
                              "serial number.");
            }
    #endif
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

    /* Consider using WOLFSSL_ASN_ALLOW_0_SERIAL or WOLFSSL_NO_ASN_STRICT
     * to relax checks. Use with caution. See wolfSSL documentation. */
    if (wolfssl_found_zero_serial()) {
        ESP_LOGCBW(TAG, "Warning: At least one certificate in the bundle "
                        "is missing a serial number.");
    }

    WOLFSSL_LEAVE("wolfssl_esp_crt_bundle_init", ret);
    return ret;
} /* esp_crt_bundle_init */

/* esp_crt_bundle_attach() used by ESP-IDF esp-tls layer. */
esp_err_t esp_crt_bundle_attach(void *conf)
{
    esp_err_t ret = ESP_OK;
    ESP_LOGCBI(TAG, "Enter esp_crt_bundle_attach");
    /* If no bundle has been set by the user,
     * then use the bundle embedded in the binary */
    if (s_crt_bundle.crts == NULL) {
        ESP_LOGCBI(TAG, "No bundle set by user; using the embedded binary.");
        ESP_LOGCBI(TAG, "x509_crt_imported_bundle_wolfssl_bin_start 0x%x",
               (intptr_t)x509_crt_imported_bundle_wolfssl_bin_start);
        ESP_LOGCBI(TAG, "x509_crt_imported_bundle_wolfssl_bin_end 0x%x",
               (intptr_t)x509_crt_imported_bundle_wolfssl_bin_end);
        ret = wolfssl_esp_crt_bundle_init(
                         x509_crt_imported_bundle_wolfssl_bin_start,
                        (x509_crt_imported_bundle_wolfssl_bin_end
                       - x509_crt_imported_bundle_wolfssl_bin_start));
    }
    else {
        ESP_LOGCBI(TAG, "Cert bundle set by user at 0x%x.",
                       (intptr_t)s_crt_bundle.crts);
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
    _wolfssl_found_zero_serial = ESP_OK;
    _cert_bundle_loaded = 0;
    _crt_found = 0;
    _added_cert = 0;
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

    /* Be sure to free the bundle_cert first, as it may be part of store. */
    if (bundle_cert != NULL) {
#ifdef DEBUG_WOLFSSL_MALLOC
        ESP_LOGI(TAG, "Free bundle_cert in wolfSSL_bundle_cleanup");
#endif
        wolfSSL_X509_free(bundle_cert);
        bundle_cert = NULL;
    }

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
