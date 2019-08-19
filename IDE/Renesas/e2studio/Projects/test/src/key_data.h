
#ifndef KEY_DATA_H_
#define KEY_DATA_H_
#include <wolfssl/wolfcrypt/settings.h>

#ifdef WOLFSSL_RENESAS_TSIP
#include "r_tsip_rx_if.h"

/** user key datas */
typedef struct key_block_data
{
    uint8_t  encrypted_session_key[R_TSIP_AES_CBC_IV_BYTE_SIZE * 2];
    uint8_t  iv[R_TSIP_AES_CBC_IV_BYTE_SIZE];
    uint8_t  encrypted_user_rsa2048_ne_key[R_TSIP_RSA2048_NE_KEY_BYTE_SIZE + 16];
} st_key_block_data_t;

extern const st_key_block_data_t g_key_block_data;
extern const uint32_t s_flash[];
extern const unsigned char ca_cert_der[];
extern const int sizeof_ca_cert_der;
extern const unsigned char ca_cert_sig[];
extern const unsigned char client_cert_der_sign[];

#endif /* WOLFSSL_RENESAS_TSIP */
#endif /* KEY_DATA_H_ */

