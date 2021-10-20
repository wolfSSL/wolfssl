/* Custom build settings for Android */

#ifndef _WOLF_USER_SETTINGS_H_
#define _WOLF_USER_SETTINGS_H_

#if 0
    #define HAVE_FIPS_VERSION 2
    #define HAVE_FIPS
#endif

/* WPA Supplicant Support */
#define WOLFSSL_WPAS_SMALL
#define OPENSSL_ALL
#define HAVE_THREAD_LS

#define USE_FAST_MATH
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING

#define HAVE_HASHDRBG

#if 1
    #define WOLFSSL_TLS13
    #define WC_RSA_PSS
#endif
#define HAVE_SESSION_TICKET
#define HAVE_TLS_EXTENSIONS
#define HAVE_SUPPORTED_CURVES
#define HAVE_EXTENDED_MASTER
#define HAVE_ENCRYPT_THEN_MAC
#define WOLFSSL_ENCRYPTED_KEYS
#define HAVE_KEYING_MATERIAL
#define NO_OLD_TLS
#define NO_CHECK_PRIVATE_KEY

/* enable PK callback support for signing operations to key store */
#define HAVE_PK_CALLBACKS
/* crypto callback support is not in FIPS 3389 */
#ifndef HAVE_FIPS
    #define WOLF_CRYPTO_CB 
#endif

#define KEEP_OUR_CERT
#define KEEP_PEER_CERT
#define WOLFSSL_ALWAYS_VERIFY_CB
#define WOLFSSL_ALWAYS_KEEP_SNI
#define HAVE_EX_DATA
#define HAVE_EXT_CACHE
#define WOLFSSL_EITHER_SIDE
#define WOLFSSL_PUBLIC_MP
#define WOLFSSL_DER_LOAD

#define WOLFSSL_CERT_GEN
#define WOLFSSL_CERT_EXT
#define WOLFSSL_CERT_REQ

#define WOLFSSL_KEY_GEN
#define WC_RSA_NO_PADDING

#define HAVE_FFDHE_2048
#define HAVE_DH_DEFAULT_PARAMS
#ifdef HAVE_FIPS
    #define WOLFSSL_VALIDATE_FFC_IMPORT
    #define HAVE_FFDHE_Q
#endif

#define WOLFSSL_SHA224
#define WOLFSSL_SHA512
#define WOLFSSL_SHA384

#define HAVE_HKDF
#define HAVE_PKCS8

#define HAVE_ECC
#define TFM_ECC256
#define ECC_SHAMIR
#define HAVE_COMP_KEY
#ifdef HAVE_FIPS
    #define HAVE_ECC_CDH
    #define WOLFSSL_VALIDATE_ECC_IMPORT
#endif

#define HAVE_AESGCM
#define HAVE_AESCCM
#define WOLFSSL_AES_DIRECT
#define WOLFSSL_AES_COUNTER
#define HAVE_AES_ECB
#define WOLFSSL_CMAC

#define WOLFSSL_BASE64_ENCODE
#define HAVE_CRL

#define NO_DSA
#define NO_RC4
#define NO_HC128
#define NO_RABBIT
#define NO_RC4
#define NO_PSK
#define WOLFSSL_NO_SHAKE256
#define NO_MD4
#define NO_OLD_MD5_NAME
#define NO_OLD_SHA_NAMES
#define NO_OLD_SHA256_NAMES
#define NO_OLD_WC_NAMES

#if 0
    #define DEBUG_WOLFSSL
    #define WOLFSSL_ANDROID_DEBUG
#endif

#endif /* _WOLF_USER_SETTINGS_H_ */
