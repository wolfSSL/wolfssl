/* esp_crt_bundle.h
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

#ifndef __ESP_CRT_BUNDLE_wolfssl_LIB_H__

#define __ESP_CRT_BUNDLE_wolfssl_LIB_H__

/* This file is typically NOT directly used by applications utilizing the
 * wolfSSL libraries. It is used when the wolfssl library component is
 * configured to be utilized by the Espressif ESP-IDF, specifically the
 * esp-tls layer.
 *
 * See: esp-idf api-reference for esp_tls.
 * https://github.com/espressif/esp-idf/blob/master/components/esp-tls/esp_tls.h
 *
 *******************************************************************************
 ** Optional Settings:
 *******************************************************************************
 * WOLFSSL_DEBUG_CERT_BUNDLE_NAME
 *   Optionally show certificate bundle debugging info.
 *
 * WOLFSSL_DEBUG_CERT_BUNDLE_NAME
 *   Optionally show certificate bundle name debugging info.
 *
 * WOLFSSL_EXAMPLE_VERBOSITY
 *   Optionally print example application information that may be interesting.
 *
 * IS_WOLFSSL_CERT_BUNDLE_FORMAT
 *   This should be left on as no other bundle format is supported at this time.
 *
 * CB_INLINE
 *   Normally on, this uses the compiler `inline` decorator for bundle functions
 *   to be optimized, since they are called during a TLS connection.
 *
 * See Kconfig file (or use idy.py menuconfig) for other bundle settings.
 *
 *******************************************************************************
 ** Other Settings:
 *******************************************************************************
 * WOLFSSL_CMAKE_REQUIRED_ESP_TLS
 *  This is defined in the wolfssl component cmake file when the esp-tls
 *  component is required. This is typically when Certificate Bundles are
 *  enabled, and the esp_tls_free_global_ca_store() in the esp-tls needs
 *  to be called from the wolfSSL wolfSSL_bundle_cleanup().
 */

/* wolfSSL */
/* Always include wolfcrypt/settings.h before any other wolfSSL file.    */
/* Be sure to define WOLFSSL_USER_SETTINGS, typically in CMakeLists.txt  */
/* Reminder: settings.h pulls in user_settings.h                         */
/*   Do not explicitly include user_settings.h here.                     */
#include <wolfssl/wolfcrypt/settings.h>

#if defined(WOLFSSL_ESPIDF) /* Entire file is only for Espressif EDP-IDF   */

#ifndef WOLFSSL_USER_SETTINGS
    #error "WOLFSSL_USER_SETTINGS must be defined for Espressif targets"
#endif

#if defined(CONFIG_ESP_TLS_USING_WOLFSSL) || \
    defined(CONFIG_WOLFSSL_CERTIFICATE_BUNDLE)


#ifdef __cplusplus
extern "C" {
#endif

#define WOLFSSL_X509_VERIFY_CALLBACK (void *, WOLFSSL_X509 *, int, uint32_t *)
#include <wolfssl/ssl.h>

typedef struct wolfssl_ssl_config wolfssl_ssl_config;

struct wolfssl_ssl_config
{
    WOLFSSL_X509* ca_chain;
    WOLFSSL_X509_CRL* ca_crl;
    void *priv_ctx;
    void *priv_ssl;
};

/**
 * @brief      Attach and enable use of a bundle for certificate verification
 *
 * Attach and enable use of a bundle for certificate verification through a
 * verification callback.If no specific bundle has been set through
 * esp_crt_bundle_set() it will default to the bundle defined in menuconfig
 * and embedded in the binary.
 *
 * Note this must be visible for both the regular bundles, as well as the
 *"none" option.
 *
 * Other code gated out, below, when the "none" option is selected.
 *
 * @param[in]  conf      The config struct for the SSL connection.
 *
 * @return
 *             - ESP_OK  if adding certificates was successful.
 *             - Other   if an error occurred or an action must be taken by the
 *                       calling process.
 */
esp_err_t esp_crt_bundle_attach(void *conf);


#if defined(CONFIG_WOLFSSL_CERTIFICATE_BUNDLE) && \
    defined(CONFIG_WOLFSSL_CERTIFICATE_BUNDLE_DEFAULT_NONE) && \
    (CONFIG_WOLFSSL_CERTIFICATE_BUNDLE_DEFAULT_NONE == 1)

/* Certificate bundles are enabled, but the "none" option selected */

#else
/**
 * @brief      Return ESP_OK for valid bundle, otherwise ESP_FAIL.
 *
 * Specific to wolfSSL. Not used by ESP-IDF esp-tls layer.
 */
esp_err_t esp_crt_bundle_is_valid(void);

/**
 * @brief      Return 1 if Cert Bundle loaded, otherwise 0.
 *
 * Specific to wolfSSL. Not used by ESP-IDF esp-tls layer.
 */
int wolfssl_cert_bundle_loaded(void);

/**
 * @brief      Return 1 is a cert from the bundle was needed
 *             at connection time, otherwise 0.
 *
 * Specific to wolfSSL. Not used by ESP-IDF esp-tls layer.
 */
int wolfssl_need_bundle_cert(void);

/**
 * @brief      Disable and dealloc the certification bundle
 *
 * Used by ESP-IDF esp-tls layer.
 *
 * Removes the certificate verification callback and deallocates used resources
 *
 * @param[in]  conf      The config struct for the SSL connection.
 */
void esp_crt_bundle_detach(wolfssl_ssl_config *conf);

/**
 * @brief      Set the default certificate bundle used for verification
 *
 * Used by ESP-IDF esp-tls layer.
 *
 * Overrides the default certificate bundle only in case of successful
 * initialization. In most use cases the bundle should be set through
 * menuconfig. The bundle needs to be sorted by subject name since binary
 * search is used to find certificates.
 *
 * @param[in]  x509_bundle     A pointer to the certificate bundle.
 *
 * @param[in]  bundle_size     Size of the certificate bundle in bytes.
 *
 * @return
 *             - ESP_OK  if adding certificates was successful.
 *             - Other   if an error occurred or an action must be taken
 *                       by the calling process.
 */
esp_err_t esp_crt_bundle_set(const uint8_t *x509_bundle, size_t bundle_size);


/**
 * @brief      Set the issuer and subject values given the current cert.
 *
 * Used internally by ESP-IDF esp-tls layer. Also helpful for debugging
 * and general visibility to certificate attributes.
 *
 * The CERT_TAG can be used at the esp-tls or application layer to indicate
 * the usage of the respective cert (e.g. the string "peer").
 *
 * Turn on WOLFSSL_DEBUG_CERT_BUNDLE to also see ASN1 before/after values.
 *
 * @return
 *             - WOLFSSL_SUCCESS (1)
 *             - WOLFSSL_FAILURE (0) if unable to get issues and/or subject.
 */
int wolfSSL_X509_get_cert_items(char* CERT_TAG,
                                WOLFSSL_X509* cert,
                                WOLFSSL_X509_NAME** issuer,
                                WOLFSSL_X509_NAME** subject);

esp_err_t wolfSSL_bundle_cleanup(void);

WOLFSSL_LOCAL void wolfssl_ssl_conf_verify(wolfssl_ssl_config *conf,
                             int (*f_vrfy) WOLFSSL_X509_VERIFY_CALLBACK,
                             void *p_vrfy);

WOLFSSL_LOCAL void wolfssl_ssl_conf_authmode(wolfssl_ssl_config *conf,
                                             int authmode);

WOLFSSL_LOCAL void wolfssl_ssl_conf_ca_chain(wolfssl_ssl_config *conf,
                                             WOLFSSL_X509 *ca_chain,
                                             WOLFSSL_X509_CRL *ca_crl);

WOLFSSL_LOCAL void wolfssl_x509_crt_init(WOLFSSL_X509 *crt);

WOLFSSL_LOCAL int esp_crt_verify_callback(void *buf, WOLFSSL_X509 *crt,
                                          int depth, uint32_t *flags);

#ifdef __cplusplus
}
#endif

/* Detect if wolfSSL is enabled, but so are mbedTLS bundles */
#if defined(CONFIG_MBEDTLS_CERTIFICATE_BUNDLE) && \
            CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
    #error "wolfSSL cannot use mbedTLS certificate bundles. Please disable them"
#endif

#endif /* CONFIG_WOLFSSL_CERTIFICATE_BUNDLE */

#endif /* CONFIG_ESP_TLS_USING_WOLFSSL */

#endif /* WOLFSSL_ESPIDF */

#endif /* __ESP_CRT_BUNDLE_wolfssl_LIB_H__ */
