
#ifndef __KEY_DATA_H__

#include "r_sce.h"

/** Firmware update data and user key datas */
typedef struct user_key_block_data
{
    uint8_t encrypted_provisioning_key[HW_SCE_AES_CBC_IV_BYTE_SIZE * 2];
    uint8_t iv[HW_SCE_AES_CBC_IV_BYTE_SIZE];
    uint8_t encrypted_user_rsa2048_ne_key[HW_SCE_RSA2048_NE_KEY_BYTE_SIZE + 16];
    uint8_t encrypted_user_update_key[HW_SCE_AES256_KEY_BYTE_SIZE + 16];
} st_user_key_block_data_t;


 extern const unsigned char     ca_cert_der_sign[];
 extern const unsigned char     ca_ecc_cert_der_sign[];

#endif /* __KEY_DATA_H__ */