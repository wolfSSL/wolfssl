/* evp.c
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.
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

static unsigned int cipherType(const WOLFSSL_EVP_CIPHER *cipher);

WOLFSSL_API int  wolfSSL_EVP_EncryptInit(WOLFSSL_EVP_CIPHER_CTX* ctx,
                                        const WOLFSSL_EVP_CIPHER* type,
                                        unsigned char* key, unsigned char* iv)
{
    return wolfSSL_EVP_CipherInit(ctx, type, key, iv, 1);
}

WOLFSSL_API int  wolfSSL_EVP_EncryptInit_ex(WOLFSSL_EVP_CIPHER_CTX* ctx,
                                        const WOLFSSL_EVP_CIPHER* type,
                                        WOLFSSL_ENGINE *impl,
                                        unsigned char* key, unsigned char* iv)
{
    (void) impl;
    return wolfSSL_EVP_CipherInit(ctx, type, key, iv, 1);
}

WOLFSSL_API int  wolfSSL_EVP_DecryptInit(WOLFSSL_EVP_CIPHER_CTX* ctx,
                                        const WOLFSSL_EVP_CIPHER* type,
                                        unsigned char* key, unsigned char* iv)
{
    WOLFSSL_ENTER("wolfSSL_EVP_CipherInit");
    return wolfSSL_EVP_CipherInit(ctx, type, key, iv, 0);
}

WOLFSSL_API int  wolfSSL_EVP_DecryptInit_ex(WOLFSSL_EVP_CIPHER_CTX* ctx,
                                        const WOLFSSL_EVP_CIPHER* type,
                                        WOLFSSL_ENGINE *impl,
                                        unsigned char* key, unsigned char* iv)
{
    (void) impl;
    WOLFSSL_ENTER("wolfSSL_EVP_DecryptInit");
    return wolfSSL_EVP_CipherInit(ctx, type, key, iv, 0);
}

WOLFSSL_API WOLFSSL_EVP_CIPHER_CTX *wolfSSL_EVP_CIPHER_CTX_new(void)
{
	WOLFSSL_EVP_CIPHER_CTX *ctx = (WOLFSSL_EVP_CIPHER_CTX*)XMALLOC(sizeof *ctx,
                                                 NULL, DYNAMIC_TYPE_TMP_BUFFER);
	if (ctx){
      WOLFSSL_ENTER("wolfSSL_EVP_CIPHER_CTX_new");  
		  wolfSSL_EVP_CIPHER_CTX_init(ctx);
  }
	return ctx;
}

WOLFSSL_API void wolfSSL_EVP_CIPHER_CTX_free(WOLFSSL_EVP_CIPHER_CTX *ctx)
{
    if (ctx) {
        WOLFSSL_ENTER("wolfSSL_EVP_CIPHER_CTX_free");
		    wolfSSL_EVP_CIPHER_CTX_cleanup(ctx);
		    XFREE(ctx, NULL, DYNAMIC_TYPE_TMP_BUFFER);
		}
}

WOLFSSL_API unsigned long wolfSSL_EVP_CIPHER_CTX_mode(const WOLFSSL_EVP_CIPHER_CTX *ctx)
{
  if (ctx == NULL) return 0;
  return ctx->flags & WOLFSSL_EVP_CIPH_MODE;
}

WOLFSSL_API int  wolfSSL_EVP_EncryptFinal(WOLFSSL_EVP_CIPHER_CTX *ctx,
                                   unsigned char *out, int *outl)
{
    if (ctx && ctx->enc){
        WOLFSSL_ENTER("wolfSSL_EVP_EncryptFinal");
        return wolfSSL_EVP_CipherFinal(ctx, out, outl);
    }
    else
        return 0;
}


WOLFSSL_API int  wolfSSL_EVP_CipherInit_ex(WOLFSSL_EVP_CIPHER_CTX* ctx,
                                    const WOLFSSL_EVP_CIPHER* type,
                                    WOLFSSL_ENGINE *impl,
                                    unsigned char* key, unsigned char* iv,
                                    int enc)
{
    (void)impl;
    return wolfSSL_EVP_CipherInit(ctx, type, key, iv, enc);
}

WOLFSSL_API int  wolfSSL_EVP_EncryptFinal_ex(WOLFSSL_EVP_CIPHER_CTX *ctx,
                                   unsigned char *out, int *outl)
{
    if (ctx && ctx->enc){
        WOLFSSL_ENTER("wolfSSL_EVP_EncryptFinal_ex");
        return wolfSSL_EVP_CipherFinal(ctx, out, outl);
    }
    else
        return 0;
}

WOLFSSL_API int  wolfSSL_EVP_DecryptFinal(WOLFSSL_EVP_CIPHER_CTX *ctx,
                                   unsigned char *out, int *outl)
{
  if (ctx && ctx->enc)
      return 0;
  else{
      WOLFSSL_ENTER("wolfSSL_EVP_DecryptFinal");
      return wolfSSL_EVP_CipherFinal(ctx, out, outl);
  }
}

WOLFSSL_API int  wolfSSL_EVP_DecryptFinal_ex(WOLFSSL_EVP_CIPHER_CTX *ctx,
                                   unsigned char *out, int *outl)
{
    if (ctx && ctx->enc)
        return 0;
    else{
        WOLFSSL_ENTER("wolfSSL_EVP_CipherFinal_ex");
        return wolfSSL_EVP_CipherFinal(ctx, out, outl);
    }
}


WOLFSSL_API int wolfSSL_EVP_DigestInit_ex(WOLFSSL_EVP_MD_CTX* ctx,
                                     const WOLFSSL_EVP_MD* type,
                                     WOLFSSL_ENGINE *impl)
{
    (void) impl;
    WOLFSSL_ENTER("wolfSSL_EVP_DigestInit_ex");
    return wolfSSL_EVP_DigestInit(ctx, type);
}

#ifdef DEBUG_WOLFSSL_EVP
#define PRINT_BUF(b, sz) { int i; for(i=0; i<(sz); i++){printf("%02x(%c),", (b)[i], (b)[i]); if((i+1)%8==0)printf("\n");}}
#else
#define PRINT_BUF(b, sz)
#endif

static int fillBuff(WOLFSSL_EVP_CIPHER_CTX *ctx, const unsigned char *in, int sz)
{
    int fill;

    if (sz > 0) {
        if ((sz+ctx->bufUsed) > ctx->block_size) {
            fill = ctx->block_size - ctx->bufUsed;
        } else {
            fill = sz;
        }
        XMEMCPY(&(ctx->buf[ctx->bufUsed]), in, fill);
        ctx->bufUsed += fill;
        return fill;
    } else return 0;
}

static int evpCipherBlock(WOLFSSL_EVP_CIPHER_CTX *ctx,
                                   unsigned char *out,
                                   const unsigned char *in, int inl)
{
    switch (ctx->cipherType) {
    #if !defined(NO_AES) && defined(HAVE_AES_CBC)
        case AES_128_CBC_TYPE:
        case AES_192_CBC_TYPE:
        case AES_256_CBC_TYPE:
            if (ctx->enc)
                wc_AesCbcEncrypt(&ctx->cipher.aes, out, in, inl);
            else
                wc_AesCbcDecrypt(&ctx->cipher.aes, out, in, inl);
            break;
    #endif
    #if !defined(NO_AES) && defined(WOLFSSL_AES_COUNTER)
        case AES_128_CTR_TYPE:
        case AES_192_CTR_TYPE:
        case AES_256_CTR_TYPE:
            if (ctx->enc)
                wc_AesCtrEncrypt(&ctx->cipher.aes, out, in, inl);
            else
                wc_AesCtrEncrypt(&ctx->cipher.aes, out, in, inl);
            break;
    #endif
    #if !defined(NO_AES) && defined(HAVE_AES_ECB)
        case AES_128_ECB_TYPE:
        case AES_192_ECB_TYPE:
        case AES_256_ECB_TYPE:
            if (ctx->enc)
                wc_AesEcbEncrypt(&ctx->cipher.aes, out, in, inl);
            else
                wc_AesEcbDecrypt(&ctx->cipher.aes, out, in, inl);
            break;
    #endif
    #ifndef NO_DES3
        case DES_CBC_TYPE:
            if (ctx->enc)
                wc_Des_CbcEncrypt(&ctx->cipher.des, out, in, inl);
            else
                wc_Des_CbcDecrypt(&ctx->cipher.des, out, in, inl);
            break;
        case DES_EDE3_CBC_TYPE:
            if (ctx->enc)
                wc_Des3_CbcEncrypt(&ctx->cipher.des3, out, in, inl);
            else
                wc_Des3_CbcDecrypt(&ctx->cipher.des3, out, in, inl);
            break;
        #if defined(WOLFSSL_DES_ECB)
        case DES_ECB_TYPE:
            wc_Des_EcbEncrypt(&ctx->cipher.des, out, in, inl);
            break;
        case DES_EDE3_ECB_TYPE:
            if (ctx->enc)
                wc_Des3_EcbEncrypt(&ctx->cipher.des3, out, in, inl);
            else
                wc_Des3_EcbEncrypt(&ctx->cipher.des3, out, in, inl);
            break;
        #endif
    #endif
        default:
            return 0;
        }
        (void)in;
        (void)inl;
        (void)out;
        return 1;
}

WOLFSSL_API int wolfSSL_EVP_CipherUpdate(WOLFSSL_EVP_CIPHER_CTX *ctx,
                                   unsigned char *out, int *outl,
                                   const unsigned char *in, int inl)
{
    int blocks;
    int fill;

    if (ctx == NULL) return BAD_FUNC_ARG;
    WOLFSSL_ENTER("wolfSSL_EVP_CipherUpdate");
    *outl = 0;
    if (ctx->bufUsed > 0) { /* concatinate them if there is anything */
        fill = fillBuff(ctx, in, inl);
        inl -= fill;
        in  += fill;
    }
    if((ctx->enc == 0)&& (ctx->lastUsed == 1)){
        PRINT_BUF(ctx->lastBlock, ctx->block_size);
        XMEMCPY(out, ctx->lastBlock, ctx->block_size);
        *outl+= ctx->block_size;
        out  += ctx->block_size;
    }
    if ((ctx->bufUsed == ctx->block_size) || (ctx->flags & WOLFSSL_EVP_CIPH_NO_PADDING)){
        /* the buff is full, flash out */
        PRINT_BUF(ctx->buf, ctx->block_size);
        if (evpCipherBlock(ctx, out, ctx->buf, ctx->block_size) == 0)
            return 0;
        PRINT_BUF(out, ctx->block_size);
        if(ctx->enc == 0){
            ctx->lastUsed = 1;
            XMEMCPY(ctx->lastBlock, out, ctx->block_size);
        } else {
            *outl+= ctx->block_size;
            out  += ctx->block_size;
        }
        ctx->bufUsed = 0;
    }

    blocks = inl / ctx->block_size;
    if (blocks > 0) {
        /* process blocks */
        if (evpCipherBlock(ctx, out, ctx->buf, blocks) == 0)
            return 0;
        PRINT_BUF(ctx->buf, ctx->block_size);
        PRINT_BUF(out,      ctx->block_size);
        inl  -= ctx->block_size * blocks;
        in   += ctx->block_size * blocks;
        if(ctx->enc == 0){
            ctx->lastUsed = 1;
            XMEMCPY(ctx->lastBlock, &out[ctx->block_size * (blocks-1)], ctx->block_size);
            *outl+= ctx->block_size * (blocks-1);
        } else {
            *outl+= ctx->block_size * blocks;
        }
    }
    if (inl > 0) {
        /* put fraction into buff */
        fillBuff(ctx, in, inl);
        /* no increase of outl */
    }

    (void)out; /* silence warning in case not read */

    return 1;
}

static void padBlock(WOLFSSL_EVP_CIPHER_CTX *ctx)
{
    int i;
    for (i = ctx->bufUsed; i < ctx->block_size; i++)
        ctx->buf[i] = (byte)(ctx->block_size - ctx->bufUsed);
}

static int checkPad(WOLFSSL_EVP_CIPHER_CTX *ctx, unsigned char *buff)
{
    int i;
    int n;
    n = buff[ctx->block_size-1];

    if (n > ctx->block_size) return FALSE;
    for (i = 0; i < n; i++){
        if (buff[ctx->block_size-i-1] != n)
            return FALSE;
    }
    return ctx->block_size - n;
}

WOLFSSL_API int  wolfSSL_EVP_CipherFinal(WOLFSSL_EVP_CIPHER_CTX *ctx,
                                   unsigned char *out, int *outl)
{
    int fl ;
    if (ctx == NULL) return BAD_FUNC_ARG;
    WOLFSSL_ENTER("wolfSSL_EVP_CipherFinal");
    if (ctx->flags & WOLFSSL_EVP_CIPH_NO_PADDING) {
        *outl = 0;
        return 1;
    }
    if (ctx->enc) {
        if (ctx->bufUsed > 0) {
            padBlock(ctx);
            PRINT_BUF(ctx->buf, ctx->block_size);
            if (evpCipherBlock(ctx, out, ctx->buf, ctx->block_size) == 0)
                return 0;
            PRINT_BUF(out, ctx->block_size);
            *outl = ctx->block_size;
        }
    } else {
        if (ctx->lastUsed){
            PRINT_BUF(ctx->lastBlock, ctx->block_size);
            if ((fl = checkPad(ctx, ctx->lastBlock)) >= 0) {
                XMEMCPY(out, ctx->lastBlock, fl);
                *outl = fl;
            } else return 0;
        }
    }
    return 1;
}

WOLFSSL_API int wolfSSL_EVP_CIPHER_CTX_block_size(const WOLFSSL_EVP_CIPHER_CTX *ctx)
{
    if (ctx == NULL) return BAD_FUNC_ARG;
    switch (ctx->cipherType) {

#if !defined(NO_AES) && defined(HAVE_AES_CBC)
    case AES_128_CBC_TYPE:
    case AES_192_CBC_TYPE:
    case AES_256_CBC_TYPE:
#endif
#if !defined(NO_AES) && defined(WOLFSSL_AES_COUNTER)
    case AES_128_CTR_TYPE:
    case AES_192_CTR_TYPE:
    case AES_256_CTR_TYPE:
#endif
#if !defined(NO_AES)
    case AES_128_ECB_TYPE:
    case AES_192_ECB_TYPE:
    case AES_256_ECB_TYPE:
#endif
#ifndef NO_DES3
    case DES_CBC_TYPE:
    case DES_ECB_TYPE:
    case DES_EDE3_CBC_TYPE:
    case DES_EDE3_ECB_TYPE:
#endif
        return ctx->block_size;
    default:
        return 0;
    }
}

static unsigned int cipherType(const WOLFSSL_EVP_CIPHER *cipher)
{
    if (cipher == NULL) return 0; /* dummy for #ifdef */
  #ifndef NO_DES3
      else if (XSTRNCMP(cipher, EVP_DES_CBC, EVP_DES_SIZE) == 0)
          return DES_CBC_TYPE;
      else if (XSTRNCMP(cipher, EVP_DES_EDE3_CBC, EVP_DES_EDE3_SIZE) == 0)
          return DES_EDE3_CBC_TYPE;
  #if !defined(NO_DES3)
      else if (XSTRNCMP(cipher, EVP_DES_ECB, EVP_DES_SIZE) == 0)
          return DES_ECB_TYPE;
      else if (XSTRNCMP(cipher, EVP_DES_EDE3_ECB, EVP_DES_EDE3_SIZE) == 0)
          return DES_EDE3_ECB_TYPE;
  #endif /* NO_DES3 && HAVE_AES_ECB */
  #endif

  #if !defined(NO_AES) && defined(HAVE_AES_CBC)
      else if (XSTRNCMP(cipher, EVP_AES_128_CBC, EVP_AES_SIZE) == 0)
          return AES_128_CBC_TYPE;
      else if (XSTRNCMP(cipher, EVP_AES_192_CBC, EVP_AES_SIZE) == 0)
          return AES_192_CBC_TYPE;
      else if (XSTRNCMP(cipher, EVP_AES_256_CBC, EVP_AES_SIZE) == 0)
          return AES_256_CBC_TYPE;
  #endif /* !NO_AES && HAVE_AES_CBC */
  #if !defined(NO_AES) && defined(WOLFSSL_AES_COUNTER)
      else if (XSTRNCMP(cipher, EVP_AES_128_CTR, EVP_AES_SIZE) == 0)
          return AES_128_CTR_TYPE;
      else if (XSTRNCMP(cipher, EVP_AES_192_CTR, EVP_AES_SIZE) == 0)
          return AES_192_CTR_TYPE;
      else if (XSTRNCMP(cipher, EVP_AES_256_CTR, EVP_AES_SIZE) == 0)
          return AES_256_CTR_TYPE;
  #endif /* !NO_AES && HAVE_AES_CBC */
  #if !defined(NO_AES) && defined(HAVE_AES_ECB)
      else if (XSTRNCMP(cipher, EVP_AES_128_ECB, EVP_AES_SIZE) == 0)
          return AES_128_ECB_TYPE;
      else if (XSTRNCMP(cipher, EVP_AES_192_ECB, EVP_AES_SIZE) == 0)
          return AES_192_ECB_TYPE;
      else if (XSTRNCMP(cipher, EVP_AES_256_ECB, EVP_AES_SIZE) == 0)
          return AES_256_ECB_TYPE;
  #endif /* !NO_AES && HAVE_AES_CBC */
      else return 0;
}

WOLFSSL_API int wolfSSL_EVP_CIPHER_block_size(const WOLFSSL_EVP_CIPHER *cipher)
{
  if (cipher == NULL) return BAD_FUNC_ARG;
  switch (cipherType(cipher)) {
  #if !defined(NO_AES) && defined(HAVE_AES_CBC)
      case AES_128_CBC_TYPE:
      case AES_192_CBC_TYPE:
      case AES_256_CBC_TYPE:
                             return AES_BLOCK_SIZE;
  #endif
  #if !defined(NO_AES) && defined(WOLFSSL_AES_COUNTER)
      case AES_128_CTR_TYPE:
      case AES_192_CTR_TYPE:
      case AES_256_CTR_TYPE:
                             return AES_BLOCK_SIZE;
  #endif
  #if !defined(NO_AES) && defined(HAVE_AES_ECB)
      case AES_128_ECB_TYPE:
      case AES_192_ECB_TYPE:
      case AES_256_ECB_TYPE:
                             return AES_BLOCK_SIZE;
  #endif
  #ifndef NO_DES3
      case DES_CBC_TYPE: return 8;
      case DES_EDE3_CBC_TYPE: return 8;
      case DES_ECB_TYPE: return 8;
      case DES_EDE3_ECB_TYPE: return 8;
  #endif
      default:
          return 0;
      }
}

unsigned long WOLFSSL_CIPHER_mode(const WOLFSSL_EVP_CIPHER *cipher)
{
    switch (cipherType(cipher)) {
    #if !defined(NO_AES) && defined(HAVE_AES_CBC)
        case AES_128_CBC_TYPE:
        case AES_192_CBC_TYPE:
        case AES_256_CBC_TYPE:
            return WOLFSSL_EVP_CIPH_CBC_MODE ;
    #endif
    #if !defined(NO_AES) && defined(WOLFSSL_AES_COUNTER)
        case AES_128_CTR_TYPE:
        case AES_192_CTR_TYPE:
        case AES_256_CTR_TYPE:
            return WOLFSSL_EVP_CIPH_CTR_MODE ;
    #endif
    #if !defined(NO_AES)
        case AES_128_ECB_TYPE:
        case AES_192_ECB_TYPE:
        case AES_256_ECB_TYPE:
            return WOLFSSL_EVP_CIPH_ECB_MODE ;
    #endif
    #ifndef NO_DES3
        case DES_CBC_TYPE:
        case DES_EDE3_CBC_TYPE:
            return WOLFSSL_EVP_CIPH_CBC_MODE ;
        case DES_ECB_TYPE:
        case DES_EDE3_ECB_TYPE:
            return WOLFSSL_EVP_CIPH_ECB_MODE ;
    #endif
        default:
            return 0;
        }
}

WOLFSSL_API unsigned long WOLFSSL_EVP_CIPHER_mode(const WOLFSSL_EVP_CIPHER *cipher)
{
  if (cipher == NULL) return 0;
  return WOLFSSL_CIPHER_mode(cipher);
}

WOLFSSL_API void wolfSSL_EVP_CIPHER_CTX_set_flags(WOLFSSL_EVP_CIPHER_CTX *ctx, int flags)
{
    if (ctx != NULL) {
        ctx->flags = flags;
    }
}

WOLFSSL_API unsigned long wolfSSL_EVP_CIPHER_flags(const WOLFSSL_EVP_CIPHER *cipher)
{
  if (cipher == NULL) return 0;
  return WOLFSSL_CIPHER_mode(cipher);
}

WOLFSSL_API int  wolfSSL_EVP_CIPHER_CTX_set_padding(WOLFSSL_EVP_CIPHER_CTX *ctx, int padding)
{
  if (ctx == NULL) return BAD_FUNC_ARG;
  if (padding) {
      ctx->flags &= ~WOLFSSL_EVP_CIPH_NO_PADDING;
  }
  else {
      ctx->flags |=  WOLFSSL_EVP_CIPH_NO_PADDING;
  }
  return 1;
}

WOLFSSL_API int wolfSSL_EVP_add_digest(const WOLFSSL_EVP_MD *digest)
{
    (void)digest;
    /* nothing to do */
    return 0;
}
