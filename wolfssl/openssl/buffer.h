/* buffer.h for openssl */

#ifndef WOLFSSL_BUFFER_H_
#define WOLFSSL_BUFFER_H_

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#ifdef __cplusplus
    extern "C" {
#endif

typedef struct WOLFSSL_BUF_MEM {
    char*  data;
    size_t length; /* current length */
    size_t max;    /* maximum length */
} WOLFSSL_BUF_MEM;


WOLFSSL_API WOLFSSL_BUF_MEM* wolfSSL_BUF_MEM_new(void);
WOLFSSL_API int wolfSSL_BUF_MEM_grow(WOLFSSL_BUF_MEM* buf, size_t len);
WOLFSSL_API void wolfSSL_BUF_MEM_free(WOLFSSL_BUF_MEM* buf);


#define BUF_MEM_new  wolfSSL_BUF_MEM_new
#define BUF_MEM_grow wolfSSL_BUF_MEM_grow
#define BUF_MEM_free wolfSSL_BUF_MEM_free

/* error codes */
#define ERR_R_MALLOC_FAILURE  MEMORY_E


#ifdef __cplusplus
    }  /* extern "C" */
#endif

#endif /* WOLFSSL_BUFFER_H_ */
