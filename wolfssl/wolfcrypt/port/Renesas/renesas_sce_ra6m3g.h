#ifndef WOLFSSL_RENESAS_RA6M3G_SCE_H
#define WOLFSSL_RENESAS_RA6M3G_SCE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/aes.h>

/* Renesas RA6M3G Secure Cryptogrpahy Engine (SCE) drivers for wolfCrypt */
int wc_Renesas_SCE_init(void);
int wc_Renesas_GenerateSeed(OS_Seed* os, byte* output, word32 sz);
int wc_Renesas_Sha256Transform(wc_Sha256*, const byte*);
int wc_Renesas_AesCbcEncrypt(Aes* aes, byte* out, const byte* in, word32 sz);
int wc_Renesas_AesCbcDecrypt(Aes* aes, byte* out, const byte* in, word32 sz);
int wc_Renesas_AesEcbEncrypt(Aes* aes, byte* out, const byte* in, word32 sz);
int wc_Renesas_AesEcbDecrypt(Aes* aes, byte* out, const byte* in, word32 sz);
int wc_Renesas_AesCtrEncrypt(Aes* aes, byte* out, const byte* in, word32 sz);

#ifdef __cplusplus
}
#endif

#endif /* WOLFSSL_RA6M3G_SCE_H */
