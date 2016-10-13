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
    return wolfSSL_EVP_CipherInit(ctx, type, key, iv, 0);
}

WOLFSSL_API int  wolfSSL_EVP_DecryptInit_ex(WOLFSSL_EVP_CIPHER_CTX* ctx,
                                        const WOLFSSL_EVP_CIPHER* type,
                                        WOLFSSL_ENGINE *impl,
                                        unsigned char* key, unsigned char* iv)
{
    (void) impl;
    return wolfSSL_EVP_CipherInit(ctx, type, key, iv, 0);
}

WOLFSSL_API int wolfSSL_EVP_DigestInit_ex(WOLFSSL_EVP_MD_CTX* ctx,
                                     const WOLFSSL_EVP_MD* type,
                                     WOLFSSL_ENGINE *impl)
{
    (void) impl;
    return wolfSSL_EVP_DigestInit(ctx, type);
}


WOLFSSL_API int wolfSSL_EVP_CIPHER_CTX_block_size(const WOLFSSL_EVP_CIPHER_CTX *ctx)
{
    switch(ctx->cipherType){

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

static unsigned char cipherType(const WOLFSSL_EVP_CIPHER *cipher)
{
      if(0)return 0; /* dummy for #ifdef */
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
  switch(cipherType(cipher)){
  #if !defined(NO_AES) && defined(HAVE_AES_CBC)
      case AES_128_CBC_TYPE: return 16;
      case AES_192_CBC_TYPE: return 24;
      case AES_256_CBC_TYPE: return 32;
  #endif
  #if !defined(NO_AES) && defined(WOLFSSL_AES_COUNTER)
      case AES_128_CTR_TYPE: return 16;
      case AES_192_CTR_TYPE: return 24;
      case AES_256_CTR_TYPE: return 32;
  #endif
  #if !defined(NO_AES) && defined(HAVE_AES_ECB)
      case AES_128_ECB_TYPE: return 16;
      case AES_192_ECB_TYPE: return 24;
      case AES_256_ECB_TYPE: return 32;
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

WOLFSSL_API unsigned long WOLFSSL_CIPHER_mode(const WOLFSSL_EVP_CIPHER *cipher)
{
    switch(cipherType(cipher)){
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

WOLFSSL_API unsigned long wolfSSL_EVP_CIPHER_flags(const WOLFSSL_EVP_CIPHER *cipher)
{
  return WOLFSSL_CIPHER_mode(cipher);
}

WOLFSSL_API int  wolfSSL_EVP_CIPHER_CTX_set_padding(WOLFSSL_EVP_CIPHER_CTX *ctx, int padding)
{
  (void) ctx;
  (void) padding;
  /*
  if(padding)ctx->flags &= ~WOLFSSL_EVP_CIPH_NO_PADDING;
  else       ctx->flags |=  WOLFSSL_EVP_CIPH_NO_PADDING;
  */
  return 0;
}
