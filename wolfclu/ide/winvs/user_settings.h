#ifndef _WIN_USER_SETTINGS_H_
#define _WIN_USER_SETTINGS_H_

/* Verify this is Windows */
#ifndef _WIN32
#error This user_settings.h header is only designed for Windows
#endif

#define WC_RSA_BLINDING
#define NO_MULTIBYTE_PRINT
#define WC_NO_HARDEN

#define WOLFSSL_KEY_GEN
#define WOLFSSL_CERT_GEN
#define WOLFSSL_CERT_REQ
#define WOLFSSL_CERT_EXT
#define HAVE_ECC
#define HAVE_DH
#define HAVE_ED25519
#define WOLFSSL_AES_COUNTER
#define WOLFSSL_AES_DIRECT
#define HAVE_AESGCM
#define WOLFSSL_SHA224
#define WOLFSSL_SHA384
#define WOLFSSL_SHA512

#define HAVE_TLS_EXTENSIONS
#define OPENSSL_ALL
#define OPENSSL_EXTRA

#endif /* _WIN_USER_SETTINGS_H_ */
