/* crypto.h for openSSL */

#ifndef WOLFSSL_CRYPTO_H_
#define WOLFSSL_CRYPTO_H_


#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_PREFIX
#include "prefix_crypto.h"
#endif


WOLFSSL_API const char*   wolfSSLeay_version(int type);
WOLFSSL_API unsigned long wolfSSLeay(void);

#define SSLeay_version wolfSSLeay_version
#define SSLeay wolfSSLeay


#define SSLEAY_VERSION 0x0090600fL
#define SSLEAY_VERSION_NUMBER SSLEAY_VERSION

#ifdef HAVE_STUNNEL
#define CRYPTO_set_mem_ex_functions      wolfSSL_CRYPTO_set_mem_ex_functions
#define FIPS_mode                        wolfSSL_FIPS_mode
#define FIPS_mode_set                    wolfSSL_FIPS_mode_set
#endif /* HAVE_STUNNEL */

#endif /* header */

