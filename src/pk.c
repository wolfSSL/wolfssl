/* pk.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#include <wolfssl/internal.h>
#ifndef WC_NO_RNG
    #include <wolfssl/wolfcrypt/random.h>
#endif

#if !defined(WOLFSSL_PK_INCLUDED)
    #ifndef WOLFSSL_IGNORE_FILE_WARN
        #warning pk.c does not need to be compiled separately from ssl.c
    #endif
#else

#ifndef NO_RSA
    #include <wolfssl/wolfcrypt/rsa.h>
#endif

/*******************************************************************************
 * COMMON FUNCTIONS
 ******************************************************************************/

/* Calculate the number of bytes require to represent a length value in ASN.
 *
 * @param [in] l  Length value to use.
 * @return  Number of bytes required to represent length value.
 */
#define ASN_LEN_SIZE(l)             \
    (((l) < 128) ? 1 : (((l) < 256) ? 2 : 3))

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)

#ifndef NO_ASN

#if (!defined(NO_FILESYSTEM) && (defined(OPENSSL_EXTRA) || \
     defined(OPENSSL_ALL))) || (!defined(NO_BIO) && defined(OPENSSL_EXTRA))
/* Convert the PEM encoding in the buffer to DER.
 *
 * @param [in]  pem        Buffer containing PEM encoded data.
 * @param [in]  pemSz      Size of data in buffer in bytes.
 * @param [in]  cb         Password callback when PEM encrypted.
 * @param [in]  pass       NUL terminated string for passphrase when PEM
 *                         encrypted.
 * @param [in]  keyType    Type of key to match against PEM header/footer.
 * @param [out] keyFormat  Format of key.
 * @param [out] der        Buffer holding DER encoding.
 * @return  Negative on failure.
 * @return  Number of bytes consumed on success.
 */
static int pem_mem_to_der(const char* pem, int pemSz, wc_pem_password_cb* cb,
    void* pass, int keyType, int* keyFormat, DerBuffer** der)
{
    WC_DECLARE_VAR(info, EncryptedInfo, 1, 0);
    wc_pem_password_cb* localCb = NULL;
    int ret = 0;

    if (cb != NULL) {
        localCb = cb;
    }
    else if (pass != NULL) {
        localCb = wolfSSL_PEM_def_callback;
    }

#ifdef WOLFSSL_SMALL_STACK
    info = (EncryptedInfo*)XMALLOC(sizeof(EncryptedInfo), NULL,
        DYNAMIC_TYPE_ENCRYPTEDINFO);
    if (info == NULL) {
        WOLFSSL_ERROR_MSG("Error getting memory for EncryptedInfo structure");
        ret = MEMORY_E;
    }
#endif /* WOLFSSL_SMALL_STACK */

    if (ret == 0) {
        XMEMSET(info, 0, sizeof(EncryptedInfo));
        info->passwd_cb       = localCb;
        info->passwd_userdata = pass;

        /* Do not strip PKCS8 header */
        ret = PemToDer((const unsigned char *)pem, pemSz, keyType, der, NULL,
            info, keyFormat);
        if (ret < 0) {
            WOLFSSL_ERROR_MSG("Bad PEM To DER");
        }
    }
    if (ret >= 0) {
        ret = (int)info->consumed;
    }

    WC_FREE_VAR_EX(info, NULL, DYNAMIC_TYPE_ENCRYPTEDINFO);

    return ret;
}
#endif

#if defined(OPENSSL_EXTRA) && (!defined(NO_RSA) || !defined(WOLFCRYPT_ONLY))
#ifndef NO_BIO
/* Read PEM data from a BIO and decode to DER in a new buffer.
 *
 * @param [in, out] bio        BIO object to read with.
 * @param [in]      cb         Password callback when PEM encrypted.
 * @param [in]      pass       NUL terminated string for passphrase when PEM
 *                             encrypted.
 * @param [in]      keyType    Type of key to match against PEM header/footer.
 * @param [out]     keyFormat  Format of key.
 * @param [out]     der        Buffer holding DER encoding.
 * @return  Negative on failure.
 * @return  Number of bytes consumed on success.
 */
static int pem_read_bio_key(WOLFSSL_BIO* bio, wc_pem_password_cb* cb,
    void* pass, int keyType, int* keyFormat, DerBuffer** der)
{
    int ret;
    char* mem = NULL;
    int memSz;
    int alloced = 0;

    ret = wolfssl_read_bio(bio, &mem, &memSz, &alloced);
    if (ret == 0) {
        ret = pem_mem_to_der(mem, memSz, cb, pass, keyType, keyFormat, der);
        /* Write left over data back to BIO if not a file BIO */
        if ((ret > 0) && ((memSz - ret) > 0) &&
                 (bio->type != WOLFSSL_BIO_FILE)) {
            int res;
            if (!alloced) {
                /* If wolfssl_read_bio() points mem at the buffer internal to
                 * bio, we need to dup it before calling wolfSSL_BIO_write(),
                 * because the latter may reallocate the bio, invalidating the
                 * mem pointer before reading from it.
                 */
                char *mem_dup = (char *)XMALLOC((size_t)(memSz - ret),
                                                NULL, DYNAMIC_TYPE_TMP_BUFFER);
                if (mem_dup != NULL) {
                    XMEMCPY(mem_dup, mem + ret, (size_t)(memSz - ret));
                    res = wolfSSL_BIO_write(bio, mem_dup, memSz - ret);
                    mem = mem_dup;
                    alloced = 1;
                }
                else
                    res = MEMORY_E;
            }
            else
                res = wolfSSL_BIO_write(bio, mem + ret, memSz - ret);
            if (res != memSz - ret) {
                WOLFSSL_ERROR_MSG("Unable to write back excess data");
                if (res < 0) {
                    ret = res;
                }
                else {
                    ret = MEMORY_E;
                }
            }
        }
        if (alloced) {
            XFREE(mem, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
    }

    return ret;
}
#endif /* !NO_BIO */

#if !defined(NO_FILESYSTEM)
/* Read PEM data from a file and decode to DER in a new buffer.
 *
 * @param [in]  fp         File pointer to read with.
 * @param [in]  cb         Password callback when PEM encrypted.
 * @param [in]  pass       NUL terminated string for passphrase when PEM
 *                         encrypted.
 * @param [in]  keyType    Type of key to match against PEM header/footer.
 * @param [out] keyFormat  Format of key.
 * @param [out] der        Buffer holding DER encoding.
 * @return  Negative on failure.
 * @return  Number of bytes consumed on success.
 */
static int pem_read_file_key(XFILE fp, wc_pem_password_cb* cb, void* pass,
    int keyType, int* keyFormat, DerBuffer** der)
{
    int ret;
    char* mem = NULL;
    int memSz;

    ret = wolfssl_read_file(fp, &mem, &memSz);
    if (ret == 0) {
        ret = pem_mem_to_der(mem, memSz, cb, pass, keyType, keyFormat, der);
        XFREE(mem, NULL, DYNAMIC_TYPE_OPENSSL);
    }

    return ret;
}
#endif /* !NO_FILESYSTEM */
#endif

#if defined(OPENSSL_EXTRA) && ((!defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)) \
    || !defined(WOLFCRYPT_ONLY))
/* Convert DER data to PEM in an allocated buffer.
 *
 * @param [in]  der    Buffer containing DER data.
 * @param [in]  derSz  Size of DER data in bytes.
 * @param [in]  type   Type of key being encoded.
 * @param [in]  heap   Heap hint for dynamic memory allocation.
 * @param [out] out    Allocated buffer containing PEM.
 * @param [out] outSz  Size of PEM encoding.
 * @return  1 on success.
 * @return  0 on error.
 */
static int der_to_pem_alloc(const unsigned char* der, int derSz, int type,
    void* heap, byte** out, int* outSz)
{
    int ret = 1;
    int pemSz;
    byte* pem = NULL;

    (void)heap;

    /* Convert DER to PEM - to get size. */
    pemSz = wc_DerToPem(der, (word32)derSz, NULL, 0, type);
    if (pemSz < 0) {
        ret = 0;
    }

    if (ret == 1) {
        /* Allocate memory for PEM to be encoded into. */
        pem = (byte*)XMALLOC((size_t)pemSz, heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (pem == NULL) {
            ret = 0;
        }
    }

    /* Convert DER to PEM. */
    if ((ret == 1) && (wc_DerToPem(der, (word32)derSz, pem, (word32)pemSz,
            type) < 0)) {
        ret = 0;
        XFREE(pem, heap, DYNAMIC_TYPE_TMP_BUFFER);
        pem = NULL;
    }

    *out = pem;
    *outSz = pemSz;
    return ret;
}

#ifndef NO_BIO
/* Write the DER data as PEM into BIO.
 *
 * @param [in]      der    Buffer containing DER data.
 * @param [in]      derSz  Size of DER data in bytes.
 * @param [in, out] bio    BIO object to write with.
 * @param [in]      type   Type of key being encoded.
 * @return  1 on success.
 * @return  0 on error.
 */
static int der_write_to_bio_as_pem(const unsigned char* der, int derSz,
    WOLFSSL_BIO* bio, int type)
{
    int ret;
    int pemSz;
    byte* pem = NULL;

    ret = der_to_pem_alloc(der, derSz, type, bio->heap, &pem, &pemSz);
    if (ret == 1) {
        int len = wolfSSL_BIO_write(bio, pem, pemSz);
        if (len != pemSz) {
            WOLFSSL_ERROR_MSG("Unable to write full PEM to BIO");
            ret = 0;
        }
    }

    XFREE(pem, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}
#endif
#endif

#if defined(OPENSSL_EXTRA) && \
    ((!defined(NO_RSA) && defined(WOLFSSL_KEY_GEN)) || \
     (!defined(NO_DH) && defined(WOLFSSL_DH_EXTRA)) || \
     (defined(HAVE_ECC) && defined(WOLFSSL_KEY_GEN)))
#if !defined(NO_FILESYSTEM)
/* Write the DER data as PEM into file pointer.
 *
 * @param [in] der    Buffer containing DER data.
 * @param [in] derSz  Size of DER data in bytes.
 * @param [in] fp     File pointer to write with.
 * @param [in] type   Type of key being encoded.
 * @param [in] heap   Heap hint for dynamic memory allocation.
 * @return  1 on success.
 * @return  0 on error.
 */
static int der_write_to_file_as_pem(const unsigned char* der, int derSz,
    XFILE fp, int type, void* heap)
{
    int ret;
    int pemSz;
    byte* pem = NULL;

    ret = der_to_pem_alloc(der, derSz, type, heap, &pem, &pemSz);
    if (ret == 1) {
        int len = (int)XFWRITE(pem, 1, (size_t)pemSz, fp);
        if (len != pemSz) {
            WOLFSSL_ERROR_MSG("Unable to write full PEM to BIO");
            ret = 0;
        }
    }

    XFREE(pem, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}
#endif
#endif

#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_KEY_GEN) && \
    defined(WOLFSSL_PEM_TO_DER)
/* Encrypt private key into PEM format.
 *
 * DER is encrypted in place.
 *
 * @param [in]  der         DER encoding of private key.
 * @param [in]  derSz       Size of DER in bytes.
 * @param [in]  cipher      EVP cipher.
 * @param [in]  passwd      Password to use with encryption.
 * @param [in]  passedSz    Size of password in bytes.
 * @param [out] cipherInfo  PEM cipher information lines.
 * @param [in]  maxDerSz    Maximum size of DER buffer.
 * @param [in]  hashType    Hash algorithm
 * @return  1 on success.
 * @return  0 on error.
 */
int EncryptDerKey(byte *der, int *derSz, const WOLFSSL_EVP_CIPHER* cipher,
    unsigned char* passwd, int passwdSz, byte **cipherInfo, int maxDerSz,
    int hashType)
{
    int ret = 0;
    int paddingSz = 0;
    word32 idx;
    word32 cipherInfoSz = 0;
    WC_DECLARE_VAR(info, EncryptedInfo, 1, 0);

    WOLFSSL_ENTER("EncryptDerKey");

    /* Validate parameters. */
    if ((der == NULL) || (derSz == NULL) || (cipher == NULL) ||
            (passwd == NULL) || (cipherInfo == NULL)) {
        ret = BAD_FUNC_ARG;
    }

    #ifdef WOLFSSL_SMALL_STACK
    if (ret == 0) {
        /* Allocate encrypted info. */
        info = (EncryptedInfo*)XMALLOC(sizeof(EncryptedInfo), NULL,
            DYNAMIC_TYPE_ENCRYPTEDINFO);
        if (info == NULL) {
            WOLFSSL_MSG("malloc failed");
            ret = MEMORY_E;
        }
    }
    #endif
    if (ret == 0) {
        /* Clear the encrypted info and set name. */
        XMEMSET(info, 0, sizeof(EncryptedInfo));
        XSTRNCPY(info->name, cipher, NAME_SZ - 1);
        info->name[NAME_SZ - 1] = '\0'; /* null term */

        /* Get encrypted info from name. */
        ret = wc_EncryptedInfoGet(info, info->name);
        if (ret != 0) {
            WOLFSSL_MSG("unsupported cipher");
        }
    }

    if (ret == 0) {
        /* Generate a random salt. */
        if (wolfSSL_RAND_bytes(info->iv, (int)info->ivSz) != 1) {
            WOLFSSL_MSG("generate iv failed");
            ret = WOLFSSL_FATAL_ERROR;
        }
    }

    if (ret == 0) {
        /* Calculate padding size - always a padding block. */
        paddingSz = (int)info->ivSz - ((*derSz) % (int)info->ivSz);
        /* Check der is big enough. */
        if (maxDerSz < (*derSz) + paddingSz) {
            WOLFSSL_MSG("not enough DER buffer allocated");
            ret = BAD_FUNC_ARG;
        }
    }
    if (ret == 0) {
        /* Set padding bytes to padding length. */
        XMEMSET(der + (*derSz), (byte)paddingSz, (size_t)paddingSz);
        /* Add padding to DER size. */
        (*derSz) += (int)paddingSz;

        /* Encrypt DER buffer. */
        ret = wc_BufferKeyEncrypt(info, der, (word32)*derSz, passwd, passwdSz,
            hashType);
        if (ret != 0) {
            WOLFSSL_MSG("encrypt key failed");
        }
    }

    if (ret == 0) {
        /* Create cipher info : 'cipher_name,Salt(hex)' */
        cipherInfoSz = (word32)(2 * info->ivSz + XSTRLEN(info->name) + 2);
        /* Allocate memory for PEM encryption lines. */
        *cipherInfo = (byte*)XMALLOC(cipherInfoSz, NULL, DYNAMIC_TYPE_STRING);
        if (*cipherInfo == NULL) {
            WOLFSSL_MSG("malloc failed");
            ret = MEMORY_E;
        }
    }
    if (ret == 0) {
        /* Copy in name and add on comma. */
        XSTRLCPY((char*)*cipherInfo, info->name, cipherInfoSz);
        XSTRLCAT((char*)*cipherInfo, ",", cipherInfoSz);

        /* Find end of string. */
        idx = (word32)XSTRLEN((char*)*cipherInfo);
        /* Calculate remaining bytes. */
        cipherInfoSz -= idx;

        /* Encode IV into PEM encryption lines. */
        ret = Base16_Encode(info->iv, info->ivSz, *cipherInfo + idx,
            &cipherInfoSz);
        if (ret != 0) {
            WOLFSSL_MSG("Base16_Encode failed");
            XFREE(*cipherInfo, NULL, DYNAMIC_TYPE_STRING);
            *cipherInfo = NULL;
        }
    }

    WC_FREE_VAR_EX(info, NULL, DYNAMIC_TYPE_ENCRYPTEDINFO);
    return ret == 0;
}
#endif /* OPENSSL_EXTRA && WOLFSSL_KEY_GEN && WOLFSSL_PEM_TO_DER */


#if defined(OPENSSL_EXTRA) && defined(WOLFSSL_KEY_GEN) && \
    (defined(WOLFSSL_PEM_TO_DER) || defined(WOLFSSL_DER_TO_PEM)) && \
    (!defined(NO_RSA) || defined(HAVE_ECC))
/* Encrypt the DER in PEM format.
 *
 * @param [in]  der       DER encoded private key.
 * @param [in]  derSz     Size of DER in bytes.
 * @param [in]  cipher    EVP cipher.
 * @param [in]  passwd    Password to use in encryption.
 * @param [in]  passwdSz  Size of password in bytes.
 * @param [in]  type      PEM type of write out.
 * @param [in]  heap      Dynamic memory hint.
 * @param [out] out       Allocated buffer containing PEM encoding.
 *                        heap was NULL and dynamic type is DYNAMIC_TYPE_KEY.
 * @param [out] outSz     Size of PEM encoding in bytes.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int der_to_enc_pem_alloc(unsigned char* der, int derSz,
    const WOLFSSL_EVP_CIPHER *cipher, unsigned char *passwd, int passwdSz,
    int type, void* heap, byte** out, int* outSz)
{
    int ret = 1;
    byte* tmp = NULL;
    byte* cipherInfo = NULL;
    int pemSz = 0;
    int hashType = WC_HASH_TYPE_NONE;
#if !defined(NO_MD5)
    hashType = WC_MD5;
#elif !defined(NO_SHA)
    hashType = WC_SHA;
#endif

    /* Macro doesn't always use it. */
    (void)heap;

    /* Encrypt DER buffer if required. */
    if ((ret == 1) && (passwd != NULL) && (passwdSz > 0) && (cipher != NULL)) {
        int blockSz = wolfSSL_EVP_CIPHER_block_size(cipher);
        byte *tmpBuf;

        /* Add space for padding. */
    #ifdef WOLFSSL_NO_REALLOC
        tmpBuf = (byte*)XMALLOC((size_t)(derSz + blockSz), heap,
            DYNAMIC_TYPE_TMP_BUFFER);
        if (tmpBuf != NULL && der != NULL)
        {
                XMEMCPY(tmpBuf, der, (size_t)(derSz));
                XFREE(der, heap, DYNAMIC_TYPE_TMP_BUFFER);
                der = NULL;
        }
    #else
        tmpBuf = (byte*)XREALLOC(der, (size_t)(derSz + blockSz), heap,
            DYNAMIC_TYPE_TMP_BUFFER);
    #endif
        if (tmpBuf == NULL) {
            WOLFSSL_ERROR_MSG("Extending DER buffer failed");
            ret = 0; /* der buffer is free'd at the end of the function */
        }
        else {
            der = tmpBuf;

            /* Encrypt DER inline. */
            ret = EncryptDerKey(der, &derSz, cipher, passwd, passwdSz,
                &cipherInfo, derSz + blockSz, hashType);
            if (ret != 1) {
                WOLFSSL_ERROR_MSG("EncryptDerKey failed");
            }
        }
    }

    if (ret == 1) {
        /* Calculate PEM encoding size. */
        pemSz = wc_DerToPemEx(der, (word32)derSz, NULL, 0, cipherInfo, type);
        if (pemSz <= 0) {
            WOLFSSL_ERROR_MSG("wc_DerToPemEx failed");
            ret = 0;
        }
    }
    if (ret == 1) {
        /* Allocate space for PEM encoding plus a NUL terminator. */
        tmp = (byte*)XMALLOC((size_t)(pemSz + 1), NULL, DYNAMIC_TYPE_KEY);
        if (tmp == NULL) {
            WOLFSSL_ERROR_MSG("malloc failed");
            ret = 0;
        }
    }
    if (ret == 1) {
        /* DER to PEM */
        pemSz = wc_DerToPemEx(der, (word32)derSz, tmp, (word32)pemSz,
            cipherInfo, type);
        if (pemSz <= 0) {
            WOLFSSL_ERROR_MSG("wc_DerToPemEx failed");
            ret = 0;
        }
    }
    if (ret == 1) {
        /* NUL terminate string - PEM.  */
        tmp[pemSz] = 0x00;
        /* Return allocated buffer and size. */
        *out = tmp;
        *outSz = pemSz;
        /* Don't free returning buffer. */
        tmp = NULL;
    }

    XFREE(tmp, NULL, DYNAMIC_TYPE_KEY);
    XFREE(cipherInfo, NULL, DYNAMIC_TYPE_STRING);
    XFREE(der, heap, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}
#endif

#endif /* !NO_ASN */

#if !defined(NO_CERTS) && defined(XFPRINTF) && !defined(NO_FILESYSTEM) && \
    !defined(NO_STDIO_FILESYSTEM) && (!defined(NO_RSA) || !defined(NO_DSA) || \
    defined(HAVE_ECC)) && defined(OPENSSL_EXTRA)
/* Print the number bn in hex with name field and indentation indent to file fp.
 *
 * Used by wolfSSL_DSA_print_fp, wolfSSL_RSA_print_fp and
 * wolfSSL_EC_KEY_print_fp to print DSA, RSA and ECC keys and parameters.
 *
 * @param [in] fp      File pointer to write to.
 * @param [in] indent  Number of spaces to prepend to each line.
 * @param [in] field   Name of field.
 * @param [in] bn      Big number to print.
 * @return  1 on success.
 * @return  0 on failure.
 * @return  BAD_FUNC_ARG when fp is invalid, indent is less than 0, or field or
 *          bn or NULL.
 */
static int pk_bn_field_print_fp(XFILE fp, int indent, const char* field,
    const WOLFSSL_BIGNUM* bn)
{
    static const int HEX_INDENT = 4;
    static const int MAX_DIGITS_PER_LINE = 30;

    int ret = 1;
    int i = 0;
    char* buf = NULL;

    /* Internal function - assume parameters are valid. */

    /* Convert BN to hexadecimal character array (allocates buffer). */
    buf = wolfSSL_BN_bn2hex(bn);
    if (buf == NULL) {
        ret = 0;
    }
    if (ret == 1) {
        /* Print leading spaces, name and spaces before data. */
        if (indent > 0) {
            if (XFPRINTF(fp, "%*s", indent, "") < 0)
                ret = 0;
        }
    }
    if (ret == 1) {
        if (XFPRINTF(fp, "%s:\n", field) < 0)
            ret = 0;
    }
    if (ret == 1) {
        if (indent > 0) {
            if (XFPRINTF(fp, "%*s", indent, "") < 0)
                ret = 0;
        }
    }
    if (ret == 1) {
        if (XFPRINTF(fp, "%*s", HEX_INDENT, "") < 0)
            ret = 0;
    }
    if (ret == 1) {
        /* Print first byte - should always exist. */
        if ((buf[i] != '\0') && (buf[i+1] != '\0')) {
            if (XFPRINTF(fp, "%c", buf[i++]) < 0)
                ret = 0;
            else if (XFPRINTF(fp, "%c", buf[i++]) < 0)
                    ret = 0;
        }
    }
    if (ret == 1) {
        /* Print each hexadecimal character with byte separator. */
        while ((buf[i] != '\0') && (buf[i+1] != '\0')) {
            /* Byte separator every two nibbles - one byte. */
            if (XFPRINTF(fp, ":") < 0) {
                ret = 0;
                break;
            }
            /* New line after every 15 bytes - 30 nibbles. */
            if (i % MAX_DIGITS_PER_LINE == 0) {
                if (XFPRINTF(fp, "\n") < 0) {
                    ret = 0;
                    break;
                }
                if (indent > 0) {
                    if (XFPRINTF(fp, "%*s", indent, "") < 0) {
                        ret = 0;
                        break;
                    }
                }
                if (XFPRINTF(fp, "%*s", HEX_INDENT, "") < 0) {
                    ret = 0;
                    break;
                }
            }
            /* Print two nibbles - one byte. */
            if (XFPRINTF(fp, "%c", buf[i++]) < 0) {
                ret = 0;
                break;
            }
            if (XFPRINTF(fp, "%c", buf[i++]) < 0) {
                ret = 0;
                break;
            }
        }
        /* Ensure on new line after data. */
        if (XFPRINTF(fp, "\n") < 0) {
            ret = 0;
        }
    }

    /* Dispose of any allocated character array. */
    XFREE(buf, NULL, DYNAMIC_TYPE_OPENSSL);

    return ret;
}
#endif /* !NO_CERTS && XFPRINTF && !NO_FILESYSTEM && !NO_STDIO_FILESYSTEM &&
        * (!NO_DSA || !NO_RSA || HAVE_ECC) */

#if defined(OPENSSL_EXTRA) && defined(XSNPRINTF) && !defined(NO_BIO) && \
    !defined(NO_RSA)
/* snprintf() must be available */

/* Maximum number of extra indent spaces on each line. */
#define PRINT_NUM_MAX_INDENT        48
/* Maximum size of a line containing a value. */
#define PRINT_NUM_MAX_VALUE_LINE    PRINT_NUM_MAX_INDENT
/* Number of leading spaces on each line. */
#define PRINT_NUM_INDENT_CNT        4
/* Indent spaces for number lines. */
#define PRINT_NUM_INDENT            "    "
/* 4 leading spaces and 15 bytes with colons is a complete line. */
#define PRINT_NUM_MAX_DIGIT_LINE   (PRINT_NUM_INDENT_CNT + 3 * 15)

/* Print indent to BIO.
 *
 * @param [in] bio      BIO object to write to.
 * @param [in] line     Buffer to put characters to before writing to BIO.
 * @param [in] lineLen  Length of buffer.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wolfssl_print_indent(WOLFSSL_BIO* bio, char* line, int lineLen,
    int indent)
{
    int ret = 1;

    if (indent > 0) {
        int len_wanted;
        /* Cap indent to buffer size to avoid format truncation warning */
        if (indent >= lineLen) {
            indent = lineLen - 1;
        }
        /* Print indent spaces. */
        len_wanted = XSNPRINTF(line, (size_t)lineLen, "%*s", indent, " ");
        if ((len_wanted < 0) || (len_wanted >= lineLen)) {
            WOLFSSL_ERROR_MSG("Buffer overflow formatting indentation");
            ret = 0;
        }
        else {
            /* Write indents string to BIO */
            if (wolfSSL_BIO_write(bio, line, len_wanted) <= 0) {
                ret = 0;
            }
        }
    }

    return ret;
}

/* Print out name, and value in decimal and hex to BIO.
 *
 * @param [in] bio     BIO object to write to.
 * @param [in] value   MP integer to write.
 * @param [in] name    Name of value.
 * @param [in] indent  Number of leading spaces before line.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wolfssl_print_value(WOLFSSL_BIO* bio, mp_int* value,
    const char* name, int indent)
{
    int ret = 1;
    int len;
    char line[PRINT_NUM_MAX_VALUE_LINE + 1];

    /* Get the length of hex encoded value. */
    len = mp_unsigned_bin_size(value);
    /* Value must no more than 32-bits - 4 bytes. */
    if ((len < 0) || (len > 4)) {
        WOLFSSL_ERROR_MSG("Error getting exponent size");
        ret = 0;
    }
    if (ret == 1) {
        /* Print any indent spaces. */
        ret = wolfssl_print_indent(bio, line, sizeof(line), indent);
    }
    if (ret == 1) {
        /* Get 32-bits of value. */
        word32 v = (word32)value->dp[0];
        /* Print the line to the string. */
        len = (int)XSNPRINTF(line, sizeof(line), "%s %u (0x%x)\n", name, v,
            v);
        if (len >= (int)sizeof(line)) {
            WOLFSSL_ERROR_MSG("Buffer overflow while formatting value");
            ret = 0;
        } else {
            /* Write string to BIO */
            if (wolfSSL_BIO_write(bio, line, len) <= 0) {
                ret = 0;
            }
        }
    }

    return ret;
}

/* Print out name and multi-precision number to BIO.
 *
 * @param [in] bio     BIO object to write to.
 * @param [in] num     MP integer to write.
 * @param [in] name    Name of value.
 * @param [in] indent  Number of leading spaces before each line.
 * @return  1 on success.
 * @return  0 on failure.
 */
static int wolfssl_print_number(WOLFSSL_BIO* bio, mp_int* num, const char* name,
    int indent)
{
    int ret = 1;
    int rawLen = 0;
    byte* rawKey = NULL;
    char line[PRINT_NUM_MAX_DIGIT_LINE + 1];
    int li = 0; /* Line index. */
    int i;

    /* Allocate a buffer to hold binary encoded data. */
    rawLen = mp_unsigned_bin_size(num);
    if (rawLen == 0) {
        WOLFSSL_ERROR_MSG("Invalid number");
        ret = 0;
    }
    if (ret == 1) {
        rawKey = (byte*)XMALLOC((size_t)rawLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (rawKey == NULL) {
            WOLFSSL_ERROR_MSG("Memory allocation error");
            ret = 0;
        }
    }
    /* Encode number as big-endian byte array. */
    if ((ret == 1) && (mp_to_unsigned_bin(num, rawKey) < 0)) {
        ret = 0;
    }

    if (ret == 1) {
        /* Print any indent spaces. */
        ret = wolfssl_print_indent(bio, line, sizeof(line), indent);
    }
    if (ret == 1) {
        /* Print header string line to string. */
        li = XSNPRINTF(line, sizeof(line), "%s\n", name);
        if (li >= (int)sizeof(line)) {
            WOLFSSL_ERROR_MSG("Buffer overflow formatting name");
            ret = 0;
        }
        else {
            if (wolfSSL_BIO_write(bio, line, li) <= 0) {
                ret = 0;
            }
        }
    }
    if (ret == 1) {
        /* Print any indent spaces. */
        ret = wolfssl_print_indent(bio, line, sizeof(line), indent);
    }
    if (ret == 1) {
        /* Start first digit line with spaces.
         * Writing out zeros ensures number is a positive value. */
        li = XSNPRINTF(line, sizeof(line), PRINT_NUM_INDENT "%s",
            mp_leading_bit(num) ?  "00:" : "");
        if (li >= (int)sizeof(line)) {
            WOLFSSL_ERROR_MSG("Buffer overflow formatting spaces");
            ret = 0;
        }
    }

    /* Put out each line of numbers. */
    for (i = 0; (ret == 1) && (i < rawLen); i++) {
        /* Encode another byte as 2 hex digits and append colon. */
        int len_wanted = XSNPRINTF(line + li, sizeof(line) - (size_t)li,
                                   "%02x:", rawKey[i]);
        /* Check if there was room -- if not, print the current line, not
         * including the newest octet.
         */
        if (len_wanted >= (int)sizeof(line) - li) {
            /* bump current octet to the next line. */
            --i;
            /* More bytes coming so add a line break. */
            line[li++] = '\n';
            /* Write out the line. */
            if (wolfSSL_BIO_write(bio, line, li) <= 0) {
                ret = 0;
            }
            if (ret == 1) {
                /* Print any indent spaces. */
                ret = wolfssl_print_indent(bio, line, sizeof(line), indent);
            }
            /* Put the leading spaces on new line. */
            XSTRNCPY(line, PRINT_NUM_INDENT, PRINT_NUM_INDENT_CNT + 1);
            li = PRINT_NUM_INDENT_CNT;
        }
        else {
            li += len_wanted;
        }
    }

    if (ret == 1) {
        /* Put out last line - replace last colon with carriage return. */
        line[li-1] = '\n';
        if (wolfSSL_BIO_write(bio, line, li) <= 0) {
            ret = 0;
        }
    }

    /* Dispose of any allocated data. */
    XFREE(rawKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

#endif /* OPENSSL_EXTRA && XSNPRINTF && !NO_BIO && !NO_RSA */

#endif /* OPENSSL_EXTRA */

#if !defined(NO_CERTS) || (defined(OPENSSL_EXTRA) && (!defined(NO_RSA) || \
    (!defined(NO_DH) && defined(HAVE_FIPS) && !FIPS_VERSION_GT(2,0)) || \
    defined(HAVE_ECC)))

/* Uses the DER SEQUENCE to determine size of DER data.
 *
 * Outer SEQUENCE encapsulates all the DER encoding.
 * Add the length of the SEQUENCE data to the length of the SEQUENCE header.
 *
 * @param [in] seq  Buffer holding DER encoded sequence.
 * @param [in] len  Length of data in buffer (may be larger than SEQ).
 * @return  Size of complete DER encoding on success.
 * @return  0 on failure.
 */
static int wolfssl_der_length(const unsigned char* seq, int len)
{
    int ret = 0;
    word32 i = 0;

    /* Check it is a SEQUENCE and get the length of the underlying data.
     * i is updated to be after SEQUENCE header bytes.
     */
    if (GetSequence_ex(seq, &i, &ret, (word32)len, 0) >= 0) {
        /* Add SEQUENCE header length to underlying data length. */
        ret += (int)i;
    }

    return ret;
}

#endif


#define WOLFSSL_PK_RSA_INCLUDED
#include "src/pk_rsa.c"


/*******************************************************************************
 * START OF DSA API
 ******************************************************************************/

#ifndef NO_DSA

#if defined(OPENSSL_EXTRA) && defined(XFPRINTF) && !defined(NO_FILESYSTEM) && \
    !defined(NO_STDIO_FILESYSTEM)
/* return code compliant with OpenSSL :
 *   1 if success, 0 if error
 */
int wolfSSL_DSA_print_fp(XFILE fp, WOLFSSL_DSA* dsa, int indent)
{
    int ret = 1;

    WOLFSSL_ENTER("wolfSSL_DSA_print_fp");

    if (fp == XBADFILE || dsa == NULL) {
        ret = 0;
    }

    if (ret == 1 && dsa->p != NULL) {
        int pBits = wolfSSL_BN_num_bits(dsa->p);
        if (pBits == 0) {
            ret = 0;
        }
        else {
            if (XFPRINTF(fp, "%*s", indent, "") < 0)
                ret = 0;
            else if (XFPRINTF(fp, "Private-Key: (%d bit)\n", pBits) < 0)
                ret = 0;
        }
    }
    if (ret == 1 && dsa->priv_key != NULL) {
        ret = pk_bn_field_print_fp(fp, indent, "priv", dsa->priv_key);
    }
    if (ret == 1 && dsa->pub_key != NULL) {
        ret = pk_bn_field_print_fp(fp, indent, "pub", dsa->pub_key);
    }
    if (ret == 1 && dsa->p != NULL) {
        ret = pk_bn_field_print_fp(fp, indent, "P", dsa->p);
    }
    if (ret == 1 && dsa->q != NULL) {
        ret = pk_bn_field_print_fp(fp, indent, "Q", dsa->q);
    }
    if (ret == 1 && dsa->g != NULL) {
        ret = pk_bn_field_print_fp(fp, indent, "G", dsa->g);
    }

    WOLFSSL_LEAVE("wolfSSL_DSA_print_fp", ret);

    return ret;
}
#endif /* OPENSSL_EXTRA && XSNPRINTF && !NO_FILESYSTEM && NO_STDIO_FILESYSTEM */

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
static void InitwolfSSL_DSA(WOLFSSL_DSA* dsa)
{
    if (dsa) {
        dsa->p        = NULL;
        dsa->q        = NULL;
        dsa->g        = NULL;
        dsa->pub_key  = NULL;
        dsa->priv_key = NULL;
        dsa->internal = NULL;
        dsa->inSet    = 0;
        dsa->exSet    = 0;
    }
}


WOLFSSL_DSA* wolfSSL_DSA_new(void)
{
    WOLFSSL_DSA* external;
    DsaKey*     key;

    WOLFSSL_MSG("wolfSSL_DSA_new");

    key = (DsaKey*) XMALLOC(sizeof(DsaKey), NULL, DYNAMIC_TYPE_DSA);
    if (key == NULL) {
        WOLFSSL_MSG("wolfSSL_DSA_new malloc DsaKey failure");
        return NULL;
    }

    external = (WOLFSSL_DSA*) XMALLOC(sizeof(WOLFSSL_DSA), NULL,
                                    DYNAMIC_TYPE_DSA);
    if (external == NULL) {
        WOLFSSL_MSG("wolfSSL_DSA_new malloc WOLFSSL_DSA failure");
        XFREE(key, NULL, DYNAMIC_TYPE_DSA);
        return NULL;
    }

    InitwolfSSL_DSA(external);
    if (wc_InitDsaKey(key) != 0) {
        WOLFSSL_MSG("wolfSSL_DSA_new InitDsaKey failure");
        XFREE(key, NULL, DYNAMIC_TYPE_DSA);
        wolfSSL_DSA_free(external);
        return NULL;
    }
    external->internal = key;

    return external;
}


void wolfSSL_DSA_free(WOLFSSL_DSA* dsa)
{
    WOLFSSL_MSG("wolfSSL_DSA_free");

    if (dsa) {
        if (dsa->internal) {
            FreeDsaKey((DsaKey*)dsa->internal);
            XFREE(dsa->internal, NULL, DYNAMIC_TYPE_DSA);
            dsa->internal = NULL;
        }
        wolfSSL_BN_free(dsa->priv_key);
        wolfSSL_BN_free(dsa->pub_key);
        wolfSSL_BN_free(dsa->g);
        wolfSSL_BN_free(dsa->q);
        wolfSSL_BN_free(dsa->p);
        InitwolfSSL_DSA(dsa);  /* set back to NULLs for safety */

        XFREE(dsa, NULL, DYNAMIC_TYPE_DSA);

        /* dsa = NULL, don't try to access or double free it */
    }
}

/* wolfSSL -> OpenSSL */
int SetDsaExternal(WOLFSSL_DSA* dsa)
{
    DsaKey* key;
    WOLFSSL_MSG("Entering SetDsaExternal");

    if (dsa == NULL || dsa->internal == NULL) {
        WOLFSSL_MSG("dsa key NULL error");
        return WOLFSSL_FATAL_ERROR;
    }

    key = (DsaKey*)dsa->internal;

    if (wolfssl_bn_set_value(&dsa->p, &key->p) != 1) {
        WOLFSSL_MSG("dsa p key error");
        return WOLFSSL_FATAL_ERROR;
    }

    if (wolfssl_bn_set_value(&dsa->q, &key->q) != 1) {
        WOLFSSL_MSG("dsa q key error");
        return WOLFSSL_FATAL_ERROR;
    }

    if (wolfssl_bn_set_value(&dsa->g, &key->g) != 1) {
        WOLFSSL_MSG("dsa g key error");
        return WOLFSSL_FATAL_ERROR;
    }

    if (wolfssl_bn_set_value(&dsa->pub_key, &key->y) != 1) {
        WOLFSSL_MSG("dsa y key error");
        return WOLFSSL_FATAL_ERROR;
    }

    if (wolfssl_bn_set_value(&dsa->priv_key, &key->x) != 1) {
        WOLFSSL_MSG("dsa x key error");
        return WOLFSSL_FATAL_ERROR;
    }

    dsa->exSet = 1;

    return 1;
}
#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */

#ifdef OPENSSL_EXTRA
/* Openssl -> WolfSSL */
int SetDsaInternal(WOLFSSL_DSA* dsa)
{
    DsaKey* key;
    WOLFSSL_MSG("Entering SetDsaInternal");

    if (dsa == NULL || dsa->internal == NULL) {
        WOLFSSL_MSG("dsa key NULL error");
        return WOLFSSL_FATAL_ERROR;
    }

    key = (DsaKey*)dsa->internal;

    if (dsa->p != NULL &&
        wolfssl_bn_get_value(dsa->p, &key->p) != 1) {
        WOLFSSL_MSG("rsa p key error");
        return WOLFSSL_FATAL_ERROR;
    }

    if (dsa->q != NULL &&
        wolfssl_bn_get_value(dsa->q, &key->q) != 1) {
        WOLFSSL_MSG("rsa q key error");
        return WOLFSSL_FATAL_ERROR;
    }

    if (dsa->g != NULL &&
        wolfssl_bn_get_value(dsa->g, &key->g) != 1) {
        WOLFSSL_MSG("rsa g key error");
        return WOLFSSL_FATAL_ERROR;
    }

    if (dsa->pub_key != NULL) {
        if (wolfssl_bn_get_value(dsa->pub_key, &key->y) != 1) {
            WOLFSSL_MSG("rsa pub_key error");
            return WOLFSSL_FATAL_ERROR;
        }

        /* public key */
        key->type = DSA_PUBLIC;
    }

    if (dsa->priv_key != NULL) {
        if (wolfssl_bn_get_value(dsa->priv_key, &key->x) != 1) {
            WOLFSSL_MSG("rsa priv_key error");
            return WOLFSSL_FATAL_ERROR;
        }

        /* private key */
        key->type = DSA_PRIVATE;
    }

    dsa->inSet = 1;

    return 1;
}

/* return code compliant with OpenSSL :
 *   1 if success, 0 if error
 */
int wolfSSL_DSA_generate_key(WOLFSSL_DSA* dsa)
{
    int ret = 0;

    WOLFSSL_ENTER("wolfSSL_DSA_generate_key");

    if (dsa == NULL || dsa->internal == NULL) {
        WOLFSSL_MSG("Bad arguments");
        return 0;
    }

    if (dsa->inSet == 0) {
        WOLFSSL_MSG("No DSA internal set, do it");

        if (SetDsaInternal(dsa) != 1) {
            WOLFSSL_MSG("SetDsaInternal failed");
            return ret;
        }
    }

#ifdef WOLFSSL_KEY_GEN
    {
        int initTmpRng = 0;
        WC_RNG *rng = NULL;
        WC_DECLARE_VAR(tmpRng, WC_RNG, 1, 0);

        WC_ALLOC_VAR_EX(tmpRng, WC_RNG, 1, NULL, DYNAMIC_TYPE_RNG,
            return WOLFSSL_FATAL_ERROR);
        if (wc_InitRng(tmpRng) == 0) {
            rng = tmpRng;
            initTmpRng = 1;
        }
        else {
            WOLFSSL_MSG("Bad RNG Init, trying global");
            rng = wolfssl_get_global_rng();
        }

        if (rng) {
            /* These were allocated above by SetDsaInternal(). They should
             * be cleared before wc_MakeDsaKey() which reinitializes
             * x and y. */
            mp_clear(&((DsaKey*)dsa->internal)->x);
            mp_clear(&((DsaKey*)dsa->internal)->y);

            if (wc_MakeDsaKey(rng, (DsaKey*)dsa->internal) != MP_OKAY)
                WOLFSSL_MSG("wc_MakeDsaKey failed");
            else if (SetDsaExternal(dsa) != 1)
                WOLFSSL_MSG("SetDsaExternal failed");
            else
                ret = 1;
        }

        if (initTmpRng)
            wc_FreeRng(tmpRng);

        WC_FREE_VAR_EX(tmpRng, NULL, DYNAMIC_TYPE_RNG);
    }
#else /* WOLFSSL_KEY_GEN */
    WOLFSSL_MSG("No Key Gen built in");
#endif
    return ret;
}


/* Returns a pointer to a new WOLFSSL_DSA structure on success and NULL on fail
 */
WOLFSSL_DSA* wolfSSL_DSA_generate_parameters(int bits, unsigned char* seed,
        int seedLen, int* counterRet, unsigned long* hRet,
        WOLFSSL_BN_CB cb, void* CBArg)
{
    WOLFSSL_DSA* dsa;

    WOLFSSL_ENTER("wolfSSL_DSA_generate_parameters");

    (void)cb;
    (void)CBArg;
    dsa = wolfSSL_DSA_new();
    if (dsa == NULL) {
        return NULL;
    }

    if (wolfSSL_DSA_generate_parameters_ex(dsa, bits, seed, seedLen,
                                  counterRet, hRet, NULL) != 1) {
        wolfSSL_DSA_free(dsa);
        return NULL;
    }

    return dsa;
}


/* return code compliant with OpenSSL :
 *   1 if success, 0 if error
 */
int wolfSSL_DSA_generate_parameters_ex(WOLFSSL_DSA* dsa, int bits,
                                       unsigned char* seed, int seedLen,
                                       int* counterRet,
                                       unsigned long* hRet, void* cb)
{
    int ret = 0;

    (void)bits;
    (void)seed;
    (void)seedLen;
    (void)counterRet;
    (void)hRet;
    (void)cb;

    WOLFSSL_ENTER("wolfSSL_DSA_generate_parameters_ex");

    if (dsa == NULL || dsa->internal == NULL) {
        WOLFSSL_MSG("Bad arguments");
        return 0;
    }

#ifdef WOLFSSL_KEY_GEN
    {
        int initTmpRng = 0;
        WC_RNG *rng = NULL;
        WC_DECLARE_VAR(tmpRng, WC_RNG, 1, 0);

        WC_ALLOC_VAR_EX(tmpRng, WC_RNG, 1, NULL, DYNAMIC_TYPE_RNG,
            return WOLFSSL_FATAL_ERROR);
        if (wc_InitRng(tmpRng) == 0) {
            rng = tmpRng;
            initTmpRng = 1;
        }
        else {
            WOLFSSL_MSG("Bad RNG Init, trying global");
            rng = wolfssl_get_global_rng();
        }

        if (rng) {
            if (wc_MakeDsaParameters(rng, bits,
                                     (DsaKey*)dsa->internal) != MP_OKAY)
                WOLFSSL_MSG("wc_MakeDsaParameters failed");
            else if (SetDsaExternal(dsa) != 1)
                WOLFSSL_MSG("SetDsaExternal failed");
            else
                ret = 1;
        }

        if (initTmpRng)
            wc_FreeRng(tmpRng);

        WC_FREE_VAR_EX(tmpRng, NULL, DYNAMIC_TYPE_RNG);
    }
#else /* WOLFSSL_KEY_GEN */
    WOLFSSL_MSG("No Key Gen built in");
#endif

    return ret;
}

void wolfSSL_DSA_get0_pqg(const WOLFSSL_DSA *d, const WOLFSSL_BIGNUM **p,
        const WOLFSSL_BIGNUM **q, const WOLFSSL_BIGNUM **g)
{
    WOLFSSL_ENTER("wolfSSL_DSA_get0_pqg");
    if (d != NULL) {
        if (p != NULL)
            *p = d->p;
        if (q != NULL)
            *q = d->q;
        if (g != NULL)
            *g = d->g;
    }
}

int wolfSSL_DSA_set0_pqg(WOLFSSL_DSA *d, WOLFSSL_BIGNUM *p,
        WOLFSSL_BIGNUM *q, WOLFSSL_BIGNUM *g)
{
    WOLFSSL_ENTER("wolfSSL_DSA_set0_pqg");
    if (d == NULL || p == NULL || q == NULL || g == NULL) {
        WOLFSSL_MSG("Bad parameter");
        return 0;
    }
    wolfSSL_BN_free(d->p);
    wolfSSL_BN_free(d->q);
    wolfSSL_BN_free(d->g);
    d->p = p;
    d->q = q;
    d->g = g;
    return 1;
}

void wolfSSL_DSA_get0_key(const WOLFSSL_DSA *d,
        const WOLFSSL_BIGNUM **pub_key, const WOLFSSL_BIGNUM **priv_key)
{
    WOLFSSL_ENTER("wolfSSL_DSA_get0_key");
    if (d != NULL) {
        if (pub_key != NULL)
            *pub_key = d->pub_key;
        if (priv_key != NULL)
            *priv_key = d->priv_key;
    }
}

int wolfSSL_DSA_set0_key(WOLFSSL_DSA *d, WOLFSSL_BIGNUM *pub_key,
        WOLFSSL_BIGNUM *priv_key)
{
    WOLFSSL_ENTER("wolfSSL_DSA_set0_key");

    /* The private key may be NULL */
    if (d->pub_key == NULL && pub_key == NULL) {
        WOLFSSL_MSG("Bad parameter");
        return 0;
    }

    if (pub_key != NULL) {
        wolfSSL_BN_free(d->pub_key);
        d->pub_key = pub_key;
    }
    if (priv_key != NULL) {
        wolfSSL_BN_free(d->priv_key);
        d->priv_key = priv_key;
    }

    return 1;
}

WOLFSSL_DSA_SIG* wolfSSL_DSA_SIG_new(void)
{
    WOLFSSL_DSA_SIG* sig;
    WOLFSSL_ENTER("wolfSSL_DSA_SIG_new");
    sig = (WOLFSSL_DSA_SIG*)XMALLOC(sizeof(WOLFSSL_DSA_SIG), NULL,
        DYNAMIC_TYPE_OPENSSL);
    if (sig)
        XMEMSET(sig, 0, sizeof(WOLFSSL_DSA_SIG));
    return sig;
}

void wolfSSL_DSA_SIG_free(WOLFSSL_DSA_SIG *sig)
{
    WOLFSSL_ENTER("wolfSSL_DSA_SIG_free");
    if (sig) {
        if (sig->r) {
            wolfSSL_BN_free(sig->r);
        }
        if (sig->s) {
            wolfSSL_BN_free(sig->s);
        }
        XFREE(sig, NULL, DYNAMIC_TYPE_OPENSSL);
    }
}

void wolfSSL_DSA_SIG_get0(const WOLFSSL_DSA_SIG *sig,
        const WOLFSSL_BIGNUM **r, const WOLFSSL_BIGNUM **s)
{
    WOLFSSL_ENTER("wolfSSL_DSA_SIG_get0");
    if (sig != NULL) {
        *r = sig->r;
        *s = sig->s;
    }
}

int wolfSSL_DSA_SIG_set0(WOLFSSL_DSA_SIG *sig, WOLFSSL_BIGNUM *r,
        WOLFSSL_BIGNUM *s)
{
    WOLFSSL_ENTER("wolfSSL_DSA_SIG_set0");
    if (r == NULL || s == NULL) {
        WOLFSSL_MSG("Bad parameter");
        return 0;
    }

    wolfSSL_BN_clear_free(sig->r);
    wolfSSL_BN_clear_free(sig->s);
    sig->r = r;
    sig->s = s;

    return 1;
}

#ifndef HAVE_SELFTEST
/**
 *
 * @param sig The input signature to encode
 * @param out The output buffer. If *out is NULL then a new buffer is
 *            allocated. Otherwise the output is written to the buffer.
 * @return length on success and -1 on error
 */
int wolfSSL_i2d_DSA_SIG(const WOLFSSL_DSA_SIG *sig, byte **out)
{
    /* Space for sequence + two asn ints */
    byte buf[MAX_SEQ_SZ + 2*(ASN_TAG_SZ + MAX_LENGTH_SZ + DSA_MAX_HALF_SIZE)];
    word32 bufLen = sizeof(buf);

    WOLFSSL_ENTER("wolfSSL_i2d_DSA_SIG");

    if (sig == NULL || sig->r == NULL || sig->s == NULL ||
            out == NULL) {
        WOLFSSL_MSG("Bad function arguments");
        return WOLFSSL_FATAL_ERROR;
    }

    if (StoreECC_DSA_Sig(buf, &bufLen,
            (mp_int*)sig->r->internal, (mp_int*)sig->s->internal) != 0) {
        WOLFSSL_MSG("StoreECC_DSA_Sig error");
        return WOLFSSL_FATAL_ERROR;
    }

    if (*out == NULL) {
        byte* tmp = (byte*)XMALLOC(bufLen, NULL, DYNAMIC_TYPE_ASN1);
        if (tmp == NULL) {
            WOLFSSL_MSG("malloc error");
            return WOLFSSL_FATAL_ERROR;
        }
        *out = tmp;
    }

   XMEMCPY(*out, buf, bufLen);

    return (int)bufLen;
}

/**
 * Same as wolfSSL_DSA_SIG_new but also initializes the internal bignums.
 * @return New WOLFSSL_DSA_SIG with r and s created as well
 */
static WOLFSSL_DSA_SIG* wolfSSL_DSA_SIG_new_bn(void)
{
    WOLFSSL_DSA_SIG* ret;

    if ((ret = wolfSSL_DSA_SIG_new()) == NULL) {
        WOLFSSL_MSG("wolfSSL_DSA_SIG_new error");
        return NULL;
    }

    if ((ret->r = wolfSSL_BN_new()) == NULL) {
        WOLFSSL_MSG("wolfSSL_BN_new error");
        wolfSSL_DSA_SIG_free(ret);
        return NULL;
    }

    if ((ret->s = wolfSSL_BN_new()) == NULL) {
        WOLFSSL_MSG("wolfSSL_BN_new error");
        wolfSSL_DSA_SIG_free(ret);
        return NULL;
    }

    return ret;
}

/**
 * This parses a DER encoded ASN.1 structure. The ASN.1 encoding is:
 * ASN1_SEQUENCE
 *   ASN1_INTEGER (DSA r)
 *   ASN1_INTEGER (DSA s)
 * Alternatively, if the input is DSA_160_SIG_SIZE or DSA_256_SIG_SIZE in
 * length then this API interprets this as two unsigned binary numbers.
 * @param sig    If non-null then free'd first and then newly created
 *               WOLFSSL_DSA_SIG is assigned
 * @param pp     Input buffer that is moved forward on success
 * @param length Length of input buffer
 * @return Newly created WOLFSSL_DSA_SIG on success or NULL on failure
 */
WOLFSSL_DSA_SIG* wolfSSL_d2i_DSA_SIG(WOLFSSL_DSA_SIG **sig,
        const unsigned char **pp, long length)
{
    WOLFSSL_DSA_SIG* ret;
    mp_int* r;
    mp_int* s;

    WOLFSSL_ENTER("wolfSSL_d2i_DSA_SIG");

    if (pp == NULL || *pp == NULL || length < 0) {
        WOLFSSL_MSG("Bad function arguments");
        return NULL;
    }

    if ((ret = wolfSSL_DSA_SIG_new_bn()) == NULL) {
        WOLFSSL_MSG("wolfSSL_DSA_SIG_new_bn error");
        return NULL;
    }

    r = (mp_int*)ret->r->internal;
    s = (mp_int*)ret->s->internal;

    if (DecodeECC_DSA_Sig(*pp, (word32)length, r, s) != 0) {
        if (length == DSA_160_SIG_SIZE || length == DSA_256_SIG_SIZE) {
            /* Two raw numbers of length/2 size each */
            if (mp_read_unsigned_bin(r, *pp, (word32)length/2) != 0) {
                WOLFSSL_MSG("r mp_read_unsigned_bin error");
                wolfSSL_DSA_SIG_free(ret);
                return NULL;
            }

            if (mp_read_unsigned_bin(s, *pp + (length/2), (word32)length/2) !=
                    0) {
                WOLFSSL_MSG("s mp_read_unsigned_bin error");
                wolfSSL_DSA_SIG_free(ret);
                return NULL;
            }

            *pp += length;
        }
        else {
            WOLFSSL_MSG("DecodeECC_DSA_Sig error");
            wolfSSL_DSA_SIG_free(ret);
            return NULL;
        }
    }
    else {
        /* DecodeECC_DSA_Sig success move pointer forward */
#ifndef NO_STRICT_ECDSA_LEN
        *pp += length;
#else
        {
            /* We need to figure out how much to move by ourselves */
            word32 idx = 0;
            int len = 0;
            if (GetSequence(*pp, &idx, &len, (word32)length) < 0) {
                WOLFSSL_MSG("GetSequence error");
                wolfSSL_DSA_SIG_free(ret);
                return NULL;
            }
            *pp += len;
        }
#endif
    }

    if (sig != NULL) {
        if (*sig != NULL)
            wolfSSL_DSA_SIG_free(*sig);
        *sig = ret;
    }

    return ret;
}

#endif /* !HAVE_SELFTEST */

static int dsa_do_sign(const unsigned char* d, int dLen, unsigned char* sigRet,
        WOLFSSL_DSA* dsa)
{
    int     ret = WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR);
    int     initTmpRng = 0;
    WC_RNG* rng = NULL;
    WC_DECLARE_VAR(tmpRng, WC_RNG, 1, 0);

    if (d == NULL || sigRet == NULL || dsa == NULL) {
        WOLFSSL_MSG("Bad function arguments");
        return WOLFSSL_FATAL_ERROR;
    }

    if (dsa->inSet == 0) {
        WOLFSSL_MSG("No DSA internal set, do it");
        if (SetDsaInternal(dsa) != 1) {
            WOLFSSL_MSG("SetDsaInternal failed");
            return WOLFSSL_FATAL_ERROR;
        }
    }

    WC_ALLOC_VAR_EX(tmpRng, WC_RNG, 1, NULL, DYNAMIC_TYPE_RNG,
        return WOLFSSL_FATAL_ERROR);

    if (wc_InitRng(tmpRng) == 0) {
        rng = tmpRng;
        initTmpRng = 1;
    }
    else {
        WOLFSSL_MSG("Bad RNG Init, trying global");
#ifdef WOLFSSL_SMALL_STACK
        XFREE(tmpRng, NULL, DYNAMIC_TYPE_RNG);
        tmpRng = NULL;
#endif
        rng = wolfssl_get_global_rng();
        if (! rng)
            return WOLFSSL_FATAL_ERROR;
    }

    if (rng) {
#ifdef HAVE_SELFTEST
        if (dLen != WC_SHA_DIGEST_SIZE ||
                wc_DsaSign(d, sigRet, (DsaKey*)dsa->internal, rng) < 0) {
            WOLFSSL_MSG("wc_DsaSign failed or dLen wrong length");
            ret = WOLFSSL_FATAL_ERROR;
        }
#else
        if (wc_DsaSign_ex(d, dLen, sigRet, (DsaKey*)dsa->internal, rng) < 0) {
            WOLFSSL_MSG("wc_DsaSign_ex failed");
            ret = WOLFSSL_FATAL_ERROR;
        }
#endif
        else
            ret = WOLFSSL_SUCCESS;
    }

    if (initTmpRng)
        wc_FreeRng(tmpRng);
    WC_FREE_VAR_EX(tmpRng, NULL, DYNAMIC_TYPE_RNG);

    return ret;
}

/* return 1 on success, < 0 otherwise */
int wolfSSL_DSA_do_sign(const unsigned char* d, unsigned char* sigRet,
                       WOLFSSL_DSA* dsa)
{
    WOLFSSL_ENTER("wolfSSL_DSA_do_sign");

    return dsa_do_sign(d, WC_SHA_DIGEST_SIZE, sigRet, dsa);
}

#ifndef HAVE_SELFTEST
WOLFSSL_DSA_SIG* wolfSSL_DSA_do_sign_ex(const unsigned char* digest,
                                        int inLen, WOLFSSL_DSA* dsa)
{
    byte sigBin[DSA_MAX_SIG_SIZE];
    const byte *tmp = sigBin;
    int sigLen;

    WOLFSSL_ENTER("wolfSSL_DSA_do_sign_ex");

    if (!digest || !dsa) {
        WOLFSSL_MSG("Bad function arguments");
        return NULL;
    }

    if (dsa_do_sign(digest, inLen, sigBin, dsa) != 1) {
        WOLFSSL_MSG("wolfSSL_DSA_do_sign error");
        return NULL;
    }

    if (dsa->internal == NULL) {
        WOLFSSL_MSG("dsa->internal is null");
        return NULL;
    }

    sigLen = mp_unsigned_bin_size(&((DsaKey*)dsa->internal)->q);
    if (sigLen <= 0) {
        WOLFSSL_MSG("mp_unsigned_bin_size error");
        return NULL;
    }

    /* 2 * sigLen for the two points r and s */
    return wolfSSL_d2i_DSA_SIG(NULL, &tmp, 2 * sigLen);
}
#endif

static int dsa_do_verify(const unsigned char* d, int dLen, unsigned char* sig,
                        WOLFSSL_DSA* dsa, int *dsacheck)
{
    int    ret;

    if (d == NULL || sig == NULL || dsa == NULL) {
        WOLFSSL_MSG("Bad function arguments");
        return WOLFSSL_FATAL_ERROR;
    }
    if (dsa->inSet == 0)
    {
        WOLFSSL_MSG("No DSA internal set, do it");

        if (SetDsaInternal(dsa) != 1) {
            WOLFSSL_MSG("SetDsaInternal failed");
            return WOLFSSL_FATAL_ERROR;
        }
    }

#ifdef HAVE_SELFTEST
    ret = dLen == WC_SHA_DIGEST_SIZE ?
          wc_DsaVerify(d, sig, (DsaKey*)dsa->internal, dsacheck) : BAD_FUNC_ARG;
#else
    ret = wc_DsaVerify_ex(d, (word32)dLen, sig, (DsaKey*)dsa->internal,
        dsacheck);
#endif
    if (ret != 0) {
        WOLFSSL_MSG("DsaVerify failed");
        return WOLFSSL_FATAL_ERROR;
    }
    if (*dsacheck != 1) {
        WOLFSSL_MSG("DsaVerify sig failed");
        return WOLFSSL_FAILURE;
    }

    return WOLFSSL_SUCCESS;
}

int wolfSSL_DSA_do_verify(const unsigned char* d, unsigned char* sig,
                        WOLFSSL_DSA* dsa, int *dsacheck)
{
    WOLFSSL_ENTER("wolfSSL_DSA_do_verify");

    return dsa_do_verify(d, WC_SHA_DIGEST_SIZE, sig, dsa, dsacheck);
}


int wolfSSL_DSA_bits(const WOLFSSL_DSA *d)
{
    if (!d)
        return 0;
    if (!d->exSet && SetDsaExternal((WOLFSSL_DSA*)d) != 1)
        return 0;
    return wolfSSL_BN_num_bits(d->p);
}

#ifndef HAVE_SELFTEST
int wolfSSL_DSA_do_verify_ex(const unsigned char* digest, int digest_len,
                             WOLFSSL_DSA_SIG* sig, WOLFSSL_DSA* dsa)
{
    int dsacheck, sz;
    byte sigBin[DSA_MAX_SIG_SIZE];
    byte* sigBinPtr = sigBin;
    DsaKey* key;
    int qSz;

    WOLFSSL_ENTER("wolfSSL_DSA_do_verify_ex");

    if (!digest || !sig || !dsa) {
        WOLFSSL_MSG("Bad function arguments");
        return 0;
    }

    if (!sig->r || !sig->s) {
        WOLFSSL_MSG("No signature found in DSA_SIG");
        return 0;
    }

    if (dsa->inSet == 0) {
        WOLFSSL_MSG("No DSA internal set, do it");
        if (SetDsaInternal(dsa) != 1) {
            WOLFSSL_MSG("SetDsaInternal failed");
            return 0;
        }
    }

    key = (DsaKey*)dsa->internal;

    if (key == NULL) {
        WOLFSSL_MSG("dsa->internal is null");
        return 0;
    }

    qSz = mp_unsigned_bin_size(&key->q);
    if (qSz < 0 || qSz > DSA_MAX_HALF_SIZE) {
        WOLFSSL_MSG("mp_unsigned_bin_size error");
        return 0;
    }

    /* read r */
    /* front pad with zeros */
    if ((sz = wolfSSL_BN_num_bytes(sig->r)) < 0 || sz > DSA_MAX_HALF_SIZE)
        return 0;
    while (sz++ < qSz)
        *sigBinPtr++ = 0;
    if (wolfSSL_BN_bn2bin(sig->r, sigBinPtr) == -1)
        return 0;

    /* Move to s */
    sigBinPtr = sigBin + qSz;

    /* read s */
    /* front pad with zeros */
    if ((sz = wolfSSL_BN_num_bytes(sig->s)) < 0 || sz > DSA_MAX_HALF_SIZE)
        return 0;
    while (sz++ < qSz)
        *sigBinPtr++ = 0;
    if (wolfSSL_BN_bn2bin(sig->s, sigBinPtr) == -1)
        return 0;

    if ((dsa_do_verify(digest, digest_len, sigBin, dsa, &dsacheck)
                                         != 1) || dsacheck != 1) {
        return 0;
    }

    return 1;
}
#endif

int wolfSSL_i2d_DSAparams(const WOLFSSL_DSA* dsa,
    unsigned char** out)
{
    int ret = 0;
    word32 derLen = 0;
    int preAllocated = 1;
    DsaKey* key = NULL;

    WOLFSSL_ENTER("wolfSSL_i2d_DSAparams");

    if (dsa == NULL || dsa->internal == NULL || out == NULL) {
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        key = (DsaKey*)dsa->internal;
        ret = wc_DsaKeyToParamsDer_ex(key, NULL, &derLen);
        if (ret == WC_NO_ERR_TRACE(LENGTH_ONLY_E)) {
            ret = 0;
        }
    }
    if (ret == 0 && *out == NULL) {
        /* If we're allocating out for the caller, we don't increment out just
           past the end of the DER buffer. If out is already allocated, we do.
           (OpenSSL convention) */
        preAllocated = 0;
        *out = (unsigned char*)XMALLOC(derLen, key->heap, DYNAMIC_TYPE_OPENSSL);
        if (*out == NULL) {
            ret = MEMORY_E;
        }
    }
    if (ret == 0) {
        ret = wc_DsaKeyToParamsDer_ex(key, *out, &derLen);
    }
    if (ret >= 0 && preAllocated == 1) {
        *out += derLen;
    }

    if (ret < 0 && preAllocated == 0) {
        XFREE(*out, key ? key->heap : NULL, DYNAMIC_TYPE_OPENSSL);
    }

    WOLFSSL_LEAVE("wolfSSL_i2d_DSAparams", ret);

    return ret;
}

WOLFSSL_DSA* wolfSSL_d2i_DSAparams(WOLFSSL_DSA** dsa, const unsigned char** der,
    long derLen)
{
    WOLFSSL_DSA* ret = NULL;
    int err = 0;
    word32 idx = 0;
    int asnLen;
    DsaKey* internalKey = NULL;

    WOLFSSL_ENTER("wolfSSL_d2i_DSAparams");

    if (der == NULL || *der == NULL || derLen <= 0) {
        err = 1;
    }
    if (err == 0) {
        ret = wolfSSL_DSA_new();
        err = ret == NULL;
    }
    if (err == 0) {
        err = GetSequence(*der, &idx, &asnLen, (word32)derLen) <= 0;
    }
    if (err == 0) {
        internalKey = (DsaKey*)ret->internal;
        err = GetInt(&internalKey->p, *der, &idx, (word32)derLen) != 0;
    }
    if (err == 0) {
        err = GetInt(&internalKey->q, *der, &idx, (word32)derLen) != 0;
    }
    if (err == 0) {
        err = GetInt(&internalKey->g, *der, &idx, (word32)derLen) != 0;
    }
    if (err == 0) {
        err = wolfssl_bn_set_value(&ret->p, &internalKey->p)
                != 1;
    }
    if (err == 0) {
        err = wolfssl_bn_set_value(&ret->q, &internalKey->q)
                != 1;
    }
    if (err == 0) {
        err = wolfssl_bn_set_value(&ret->g, &internalKey->g)
                != 1;
    }
    if (err == 0 && dsa != NULL) {
        *dsa = ret;
    }

    if (err != 0 && ret != NULL) {
        wolfSSL_DSA_free(ret);
        ret = NULL;
    }

    return ret;
}

#if defined(WOLFSSL_KEY_GEN)
#ifndef NO_BIO

/* Takes a DSA Privatekey and writes it out to a WOLFSSL_BIO
 * Returns 1 or 0
 */
int wolfSSL_PEM_write_bio_DSAPrivateKey(WOLFSSL_BIO* bio, WOLFSSL_DSA* dsa,
    const WOLFSSL_EVP_CIPHER* cipher, unsigned char* passwd, int passwdSz,
    wc_pem_password_cb* cb, void* arg)
{
    int ret = 1;
    byte *pem = NULL;
    int pLen = 0;

    WOLFSSL_ENTER("wolfSSL_PEM_write_bio_DSAPrivateKey");

    (void)cb;
    (void)arg;

    /* Validate parameters. */
    if ((bio == NULL) || (dsa == NULL)) {
        WOLFSSL_MSG("Bad Function Arguments");
        ret = 0;
    }

    if (ret == 1) {
        ret = wolfSSL_PEM_write_mem_DSAPrivateKey(dsa, cipher, passwd, passwdSz,
            &pem, &pLen);
    }

    /* Write PEM to BIO. */
    if ((ret == 1) && (wolfSSL_BIO_write(bio, pem, pLen) != pLen)) {
        WOLFSSL_ERROR_MSG("DSA private key BIO write failed");
        ret = 0;
    }

    XFREE(pem, NULL, DYNAMIC_TYPE_KEY);
    return ret;
}

#ifndef HAVE_SELFTEST
/* Encode the DSA public key as DER.
 *
 * @param [in]  key   DSA key to encode.
 * @param [out] der   Pointer through which buffer is returned.
 * @param [in]  heap  Heap hint.
 * @return  Size of encoding on success.
 * @return  0 on error.
 */
static int wolfssl_dsa_key_to_pubkey_der(WOLFSSL_DSA* key, unsigned char** der,
    void* heap)
{
    int sz;
    unsigned char* buf = NULL;

    /* Use maximum encoded size to allocate. */
    sz = MAX_DSA_PUBKEY_SZ;
    /* Allocate memory to hold encoding. */
    buf = (byte*)XMALLOC((size_t)sz, heap, DYNAMIC_TYPE_TMP_BUFFER);
    if (buf == NULL) {
        WOLFSSL_MSG("malloc failed");
        sz = 0;
    }
    if (sz > 0) {
        /* Encode public key to DER using wolfSSL.  */
        sz = wc_DsaKeyToPublicDer((DsaKey*)key->internal, buf, (word32)sz);
        if (sz < 0) {
            WOLFSSL_MSG("wc_DsaKeyToPublicDer failed");
            sz = 0;
        }
    }

    /* Return buffer on success. */
    if (sz > 0) {
        *der = buf;
    }
    else {
        /* Dispose of any dynamically allocated data not returned. */
        XFREE(buf, heap, DYNAMIC_TYPE_TMP_BUFFER);
    }

    return sz;
}

/* Takes a DSA public key and writes it out to a WOLFSSL_BIO
 * Returns 1 or 0
 */
int wolfSSL_PEM_write_bio_DSA_PUBKEY(WOLFSSL_BIO* bio, WOLFSSL_DSA* dsa)
{
    int ret = 1;
    unsigned char* derBuf = NULL;
    int derSz = 0;

    WOLFSSL_ENTER("wolfSSL_PEM_write_bio_DSA_PUBKEY");

    /* Validate parameters. */
    if ((bio == NULL) || (dsa == NULL)) {
        WOLFSSL_MSG("Bad Function Arguments");
        return 0;
    }

    /* Encode public key in EC key as DER. */
    derSz = wolfssl_dsa_key_to_pubkey_der(dsa, &derBuf, bio->heap);
    if (derSz == 0) {
        ret = 0;
    }

    /* Write out to BIO the PEM encoding of the DSA public key. */
    if ((ret == 1) && (der_write_to_bio_as_pem(derBuf, derSz, bio,
            PUBLICKEY_TYPE) != 1)) {
        ret = 0;
    }

    /* Dispose of any dynamically allocated data. */
    XFREE(derBuf, bio->heap, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}
#endif /* HAVE_SELFTEST */
#endif /* !NO_BIO */

/* return code compliant with OpenSSL :
 *   1 if success, 0 if error
 */
int wolfSSL_PEM_write_mem_DSAPrivateKey(WOLFSSL_DSA* dsa,
                                        const WOLFSSL_EVP_CIPHER* cipher,
                                        unsigned char* passwd, int passwdSz,
                                        unsigned char **pem, int *pLen)
{
#if (defined(WOLFSSL_PEM_TO_DER) || defined(WOLFSSL_DER_TO_PEM)) && \
    !defined(NO_MD5)
    byte *derBuf, *tmp, *cipherInfo = NULL;
    int  der_max_len = 0, derSz = 0;
    const int type = DSA_PRIVATEKEY_TYPE;
    const char* header = NULL;
    const char* footer = NULL;

    WOLFSSL_MSG("wolfSSL_PEM_write_mem_DSAPrivateKey");

    if (pem == NULL || pLen == NULL || dsa == NULL || dsa->internal == NULL) {
        WOLFSSL_MSG("Bad function arguments");
        return 0;
    }

    if (wc_PemGetHeaderFooter(type, &header, &footer) != 0)
        return 0;

    if (dsa->inSet == 0) {
        WOLFSSL_MSG("No DSA internal set, do it");

        if (SetDsaInternal(dsa) != 1) {
            WOLFSSL_MSG("SetDsaInternal failed");
            return 0;
        }
    }

    der_max_len = MAX_DSA_PRIVKEY_SZ;

    derBuf = (byte*)XMALLOC((size_t)der_max_len, NULL, DYNAMIC_TYPE_DER);
    if (derBuf == NULL) {
        WOLFSSL_MSG("malloc failed");
        return 0;
    }

    /* Key to DER */
    derSz = wc_DsaKeyToDer((DsaKey*)dsa->internal, derBuf, (word32)der_max_len);
    if (derSz < 0) {
        WOLFSSL_MSG("wc_DsaKeyToDer failed");
        XFREE(derBuf, NULL, DYNAMIC_TYPE_DER);
        return 0;
    }

    /* encrypt DER buffer if required */
    if (passwd != NULL && passwdSz > 0 && cipher != NULL) {
        int ret;

        ret = EncryptDerKey(derBuf, &derSz, cipher, passwd, passwdSz,
            &cipherInfo, der_max_len, WC_MD5);
        if (ret != 1) {
            WOLFSSL_MSG("EncryptDerKey failed");
            XFREE(derBuf, NULL, DYNAMIC_TYPE_DER);
            return ret;
        }
        /* tmp buffer with a max size */
        *pLen = (derSz * 2) + (int)XSTRLEN(header) + 1 +
            (int)XSTRLEN(footer) + 1 + HEADER_ENCRYPTED_KEY_SIZE;
    }
    else { /* tmp buffer with a max size */
        *pLen = (derSz * 2) + (int)XSTRLEN(header) + 1 +
            (int)XSTRLEN(footer) + 1;
    }

    tmp = (byte*)XMALLOC((size_t)*pLen, NULL, DYNAMIC_TYPE_PEM);
    if (tmp == NULL) {
        WOLFSSL_MSG("malloc failed");
        XFREE(derBuf, NULL, DYNAMIC_TYPE_DER);
        XFREE(cipherInfo, NULL, DYNAMIC_TYPE_STRING);
        return 0;
    }

    /* DER to PEM */
    *pLen = wc_DerToPemEx(derBuf, (word32)derSz, tmp, (word32)*pLen, cipherInfo,
        type);
    if (*pLen <= 0) {
        WOLFSSL_MSG("wc_DerToPemEx failed");
        XFREE(derBuf, NULL, DYNAMIC_TYPE_DER);
        XFREE(tmp, NULL, DYNAMIC_TYPE_PEM);
        XFREE(cipherInfo, NULL, DYNAMIC_TYPE_STRING);
        return 0;
    }
    XFREE(derBuf, NULL, DYNAMIC_TYPE_DER);
    XFREE(cipherInfo, NULL, DYNAMIC_TYPE_STRING);

    *pem = (byte*)XMALLOC((size_t)((*pLen)+1), NULL, DYNAMIC_TYPE_KEY);
    if (*pem == NULL) {
        WOLFSSL_MSG("malloc failed");
        XFREE(tmp, NULL, DYNAMIC_TYPE_PEM);
        return 0;
    }
    XMEMSET(*pem, 0, (size_t)((*pLen)+1));

    if (XMEMCPY(*pem, tmp, (size_t)*pLen) == NULL) {
        WOLFSSL_MSG("XMEMCPY failed");
        XFREE(pem, NULL, DYNAMIC_TYPE_KEY);
        XFREE(tmp, NULL, DYNAMIC_TYPE_PEM);
        return 0;
    }
    XFREE(tmp, NULL, DYNAMIC_TYPE_PEM);

    return 1;
#else
    (void)dsa;
    (void)cipher;
    (void)passwd;
    (void)passwdSz;
    (void)pem;
    (void)pLen;
    return 0;
#endif /* (WOLFSSL_PEM_TO_DER || WOLFSSL_DER_TO_PEM) && !NO_MD5 */
}

#ifndef NO_FILESYSTEM
/* return code compliant with OpenSSL :
 *   1 if success, 0 if error
 */
int wolfSSL_PEM_write_DSAPrivateKey(XFILE fp, WOLFSSL_DSA *dsa,
                                    const WOLFSSL_EVP_CIPHER *enc,
                                    unsigned char *kstr, int klen,
                                    wc_pem_password_cb *cb, void *u)
{
    byte *pem;
    int  pLen, ret;

    (void)cb;
    (void)u;

    WOLFSSL_MSG("wolfSSL_PEM_write_DSAPrivateKey");

    if (fp == XBADFILE || dsa == NULL || dsa->internal == NULL) {
        WOLFSSL_MSG("Bad function arguments");
        return 0;
    }

    ret = wolfSSL_PEM_write_mem_DSAPrivateKey(dsa, enc, kstr, klen, &pem,
        &pLen);
    if (ret != 1) {
        WOLFSSL_MSG("wolfSSL_PEM_write_mem_DSAPrivateKey failed");
        return 0;
    }

    ret = (int)XFWRITE(pem, (size_t)pLen, 1, fp);
    if (ret != 1) {
        WOLFSSL_MSG("DSA private key file write failed");
        return 0;
    }

    XFREE(pem, NULL, DYNAMIC_TYPE_KEY);
    return 1;
}

#endif /* NO_FILESYSTEM */
#endif /* defined(WOLFSSL_KEY_GEN) */

#ifndef NO_FILESYSTEM
/* return code compliant with OpenSSL :
 *   1 if success, 0 if error
 */
#ifndef NO_WOLFSSL_STUB
int wolfSSL_PEM_write_DSA_PUBKEY(XFILE fp, WOLFSSL_DSA *x)
{
    (void)fp;
    (void)x;
    WOLFSSL_STUB("PEM_write_DSA_PUBKEY");
    WOLFSSL_MSG("wolfSSL_PEM_write_DSA_PUBKEY not implemented");

    return 0;
}
#endif
#endif /* NO_FILESYSTEM */

#ifndef NO_BIO

#if (defined(OPENSSL_EXTRA) || defined(OPENSSL_ALL)) && (!defined(NO_CERTS) && \
       !defined(NO_FILESYSTEM) && defined(WOLFSSL_KEY_GEN))
/* Uses the same format of input as wolfSSL_PEM_read_bio_PrivateKey but expects
 * the results to be an DSA key.
 *
 * bio  structure to read DSA private key from
 * dsa  if not null is then set to the result
 * cb   password callback for reading PEM
 * pass password string
 *
 * returns a pointer to a new WOLFSSL_DSA structure on success and NULL on fail
 */
WOLFSSL_DSA* wolfSSL_PEM_read_bio_DSAPrivateKey(WOLFSSL_BIO* bio,
                                                WOLFSSL_DSA** dsa,
                                                wc_pem_password_cb* cb,
                                                void* pass)
{
    WOLFSSL_EVP_PKEY* pkey = NULL;
    WOLFSSL_DSA* local;
    WOLFSSL_ENTER("wolfSSL_PEM_read_bio_DSAPrivateKey");


    pkey = wolfSSL_PEM_read_bio_PrivateKey(bio, NULL, cb, pass);
    if (pkey == NULL) {
        WOLFSSL_MSG("Error in PEM_read_bio_PrivateKey");
         return NULL;
     }
     /* Since the WOLFSSL_DSA structure is being taken from WOLFSSL_EVP_PKEY the
     * flag indicating that the WOLFSSL_DSA structure is owned should be FALSE
     * to avoid having it free'd */
    pkey->ownDsa = 0;
    local = pkey->dsa;
    if (dsa != NULL) {
        *dsa = local;
    }
     wolfSSL_EVP_PKEY_free(pkey);
    return local;
}

/* Reads an DSA public key from a WOLFSSL_BIO into a WOLFSSL_DSA.
 * Returns 1 or 0
 */
WOLFSSL_DSA *wolfSSL_PEM_read_bio_DSA_PUBKEY(WOLFSSL_BIO* bio,WOLFSSL_DSA** dsa,
                                             wc_pem_password_cb* cb, void* pass)
{
    WOLFSSL_EVP_PKEY* pkey;
    WOLFSSL_DSA* local;
    WOLFSSL_ENTER("wolfSSL_PEM_read_bio_DSA_PUBKEY");

    pkey = wolfSSL_PEM_read_bio_PUBKEY(bio, NULL, cb, pass);
    if (pkey == NULL) {
        WOLFSSL_MSG("wolfSSL_PEM_read_bio_PUBKEY failed");
        return NULL;
    }

    /* Since the WOLFSSL_DSA structure is being taken from WOLFSSL_EVP_PKEY the
     * flag indicating that the WOLFSSL_DSA structure is owned should be FALSE
     * to avoid having it free'd */
    pkey->ownDsa = 0;
    local = pkey->dsa;
    if (dsa != NULL) {
        *dsa = local;
    }

    wolfSSL_EVP_PKEY_free(pkey);
    return local;
}
#endif /* (OPENSSL_EXTRA || OPENSSL_ALL) && (!NO_CERTS &&
          !NO_FILESYSTEM && WOLFSSL_KEY_GEN) */

#endif /* NO_BIO */

#endif /* OPENSSL_EXTRA */

#if defined(OPENSSL_EXTRA) || defined(OPENSSL_EXTRA_X509_SMALL)
/* return 1 if success, -1 if error */
int wolfSSL_DSA_LoadDer(WOLFSSL_DSA* dsa, const unsigned char* derBuf,
    int derSz)
{
    word32 idx = 0;
    int    ret;

    WOLFSSL_ENTER("wolfSSL_DSA_LoadDer");

    if (dsa == NULL || dsa->internal == NULL || derBuf == NULL || derSz <= 0) {
        WOLFSSL_MSG("Bad function arguments");
        return WOLFSSL_FATAL_ERROR;
    }

    ret = DsaPrivateKeyDecode(derBuf, &idx, (DsaKey*)dsa->internal,
        (word32)derSz);
    if (ret < 0) {
        WOLFSSL_MSG("DsaPrivateKeyDecode failed");
        return WOLFSSL_FATAL_ERROR;
    }

    if (SetDsaExternal(dsa) != 1) {
        WOLFSSL_MSG("SetDsaExternal failed");
        return WOLFSSL_FATAL_ERROR;
    }

    dsa->inSet = 1;

    return 1;
}

/* Loads DSA key from DER buffer. opt = DSA_LOAD_PRIVATE or DSA_LOAD_PUBLIC.
    returns 1 on success, or 0 on failure.  */
int wolfSSL_DSA_LoadDer_ex(WOLFSSL_DSA* dsa, const unsigned char* derBuf,
                                                            int derSz, int opt)
{
    word32 idx = 0;
    int    ret;

    WOLFSSL_ENTER("wolfSSL_DSA_LoadDer");

    if (dsa == NULL || dsa->internal == NULL || derBuf == NULL || derSz <= 0) {
        WOLFSSL_MSG("Bad function arguments");
        return WOLFSSL_FATAL_ERROR;
    }

    if (opt == WOLFSSL_DSA_LOAD_PRIVATE) {
        ret = DsaPrivateKeyDecode(derBuf, &idx, (DsaKey*)dsa->internal,
            (word32)derSz);
    }
    else {
        ret = DsaPublicKeyDecode(derBuf, &idx, (DsaKey*)dsa->internal,
            (word32)derSz);
    }

    if (ret < 0 && opt == WOLFSSL_DSA_LOAD_PRIVATE) {
        WOLFSSL_ERROR_VERBOSE(ret);
        WOLFSSL_MSG("DsaPrivateKeyDecode failed");
        return WOLFSSL_FATAL_ERROR;
    }
    else if (ret < 0 && opt == WOLFSSL_DSA_LOAD_PUBLIC) {
        WOLFSSL_ERROR_VERBOSE(ret);
        WOLFSSL_MSG("DsaPublicKeyDecode failed");
        return WOLFSSL_FATAL_ERROR;
    }

    if (SetDsaExternal(dsa) != 1) {
        WOLFSSL_MSG("SetDsaExternal failed");
        return WOLFSSL_FATAL_ERROR;
    }

    dsa->inSet = 1;

    return 1;
}
#endif /* OPENSSL_EXTRA || OPENSSL_EXTRA_X509_SMALL */

#ifdef OPENSSL_EXTRA
#ifndef NO_BIO
WOLFSSL_DSA *wolfSSL_PEM_read_bio_DSAparams(WOLFSSL_BIO *bp, WOLFSSL_DSA **x,
        wc_pem_password_cb *cb, void *u)
{
    WOLFSSL_DSA* dsa;
    DsaKey* key;
    int    length;
    unsigned char*  buf;
    word32 bufSz;
    int ret;
    word32 idx = 0;
    DerBuffer* pDer;

    WOLFSSL_ENTER("wolfSSL_PEM_read_bio_DSAparams");

    ret = wolfSSL_BIO_get_mem_data(bp, &buf);
    if (ret <= 0) {
        WOLFSSL_LEAVE("wolfSSL_PEM_read_bio_DSAparams", ret);
        return NULL;
    }

    bufSz = (word32)ret;

    if (cb != NULL || u != NULL) {
        /*
         * cb is for a call back when encountering encrypted PEM files
         * if cb == NULL and u != NULL then u = null terminated password string
         */
        WOLFSSL_MSG("Not supporting callback or password for encrypted PEM");
    }

    if (PemToDer(buf, (long)bufSz, DSA_PARAM_TYPE, &pDer, NULL, NULL,
                    NULL) < 0 ) {
        WOLFSSL_MSG("Issue converting from PEM to DER");
        return NULL;
    }

    if (GetSequence(pDer->buffer, &idx, &length, pDer->length) < 0) {
        WOLFSSL_LEAVE("wolfSSL_PEM_read_bio_DSAparams", ret);
        FreeDer(&pDer);
        return NULL;
    }

    dsa = wolfSSL_DSA_new();
    if (dsa == NULL) {
        FreeDer(&pDer);
        WOLFSSL_MSG("Error creating DSA struct");
        return NULL;
    }

    key = (DsaKey*)dsa->internal;
    if (key == NULL) {
        FreeDer(&pDer);
        wolfSSL_DSA_free(dsa);
        WOLFSSL_MSG("Error finding DSA key struct");
        return NULL;
    }

    if (GetInt(&key->p,  pDer->buffer, &idx, pDer->length) < 0 ||
        GetInt(&key->q,  pDer->buffer, &idx, pDer->length) < 0 ||
        GetInt(&key->g,  pDer->buffer, &idx, pDer->length) < 0 ) {
        WOLFSSL_MSG("dsa key error");
        FreeDer(&pDer);
        wolfSSL_DSA_free(dsa);
        return NULL;
    }

    if (wolfssl_bn_set_value(&dsa->p, &key->p) != 1) {
        WOLFSSL_MSG("dsa p key error");
        FreeDer(&pDer);
        wolfSSL_DSA_free(dsa);
        return NULL;
    }

    if (wolfssl_bn_set_value(&dsa->q, &key->q) != 1) {
        WOLFSSL_MSG("dsa q key error");
        FreeDer(&pDer);
        wolfSSL_DSA_free(dsa);
        return NULL;
    }

    if (wolfssl_bn_set_value(&dsa->g, &key->g) != 1) {
        WOLFSSL_MSG("dsa g key error");
        FreeDer(&pDer);
        wolfSSL_DSA_free(dsa);
        return NULL;
    }

    if (x != NULL) {
        *x = dsa;
    }

    FreeDer(&pDer);
    return dsa;
}
#endif /* !NO_BIO */

#if !defined(NO_DH)
WOLFSSL_DH *wolfSSL_DSA_dup_DH(const WOLFSSL_DSA *dsa)
{
    WOLFSSL_DH* dh;
    DhKey*      key;

    WOLFSSL_ENTER("wolfSSL_DSA_dup_DH");

    if (dsa == NULL) {
        return NULL;
    }

    dh = wolfSSL_DH_new();
    if (dh == NULL) {
        return NULL;
    }
    key = (DhKey*)dh->internal;

    if (dsa->p != NULL &&
        wolfssl_bn_get_value(((WOLFSSL_DSA*)dsa)->p, &key->p)
                                                           != 1) {
        WOLFSSL_MSG("rsa p key error");
        wolfSSL_DH_free(dh);
        return NULL;
    }
    if (dsa->g != NULL &&
        wolfssl_bn_get_value(((WOLFSSL_DSA*)dsa)->g, &key->g)
                                                           != 1) {
        WOLFSSL_MSG("rsa g key error");
        wolfSSL_DH_free(dh);
        return NULL;
    }

    if (wolfssl_bn_set_value(&dh->p, &key->p) != 1) {
        WOLFSSL_MSG("dsa p key error");
        wolfSSL_DH_free(dh);
        return NULL;
    }
    if (wolfssl_bn_set_value(&dh->g, &key->g) != 1) {
        WOLFSSL_MSG("dsa g key error");
        wolfSSL_DH_free(dh);
        return NULL;
    }

    return dh;
}
#endif /* !NO_DH */

#endif /* OPENSSL_EXTRA */

#endif /* !NO_DSA */

/*******************************************************************************
 * END OF DSA API
 ******************************************************************************/


/*******************************************************************************
 * START OF DH API
 ******************************************************************************/

#ifndef NO_DH

#ifdef OPENSSL_EXTRA

/*
 * DH constructor/deconstructor APIs
 */

/* Allocate and initialize a new DH key.
 *
 * @return  DH key on success.
 * @return  NULL on failure.
 */
WOLFSSL_DH* wolfSSL_DH_new(void)
{
    int err = 0;
    WOLFSSL_DH* dh = NULL;
    DhKey* key = NULL;

    WOLFSSL_ENTER("wolfSSL_DH_new");

    /* Allocate OpenSSL DH key. */
    dh = (WOLFSSL_DH*)XMALLOC(sizeof(WOLFSSL_DH), NULL, DYNAMIC_TYPE_DH);
    if (dh == NULL) {
        WOLFSSL_ERROR_MSG("wolfSSL_DH_new malloc WOLFSSL_DH failure");
        err = 1;
    }

    if (!err) {
        /* Clear key data. */
        XMEMSET(dh, 0, sizeof(WOLFSSL_DH));
        /* Initialize reference counting. */
        wolfSSL_RefInit(&dh->ref, &err);
#ifdef WOLFSSL_REFCNT_ERROR_RETURN
    }
    if (!err) {
#endif
        /* Allocate wolfSSL DH key. */
        key = (DhKey*)XMALLOC(sizeof(DhKey), NULL, DYNAMIC_TYPE_DH);
        if (key == NULL) {
            WOLFSSL_ERROR_MSG("wolfSSL_DH_new malloc DhKey failure");
            err = 1;
        }
    }
    if (!err) {
        /* Set and initialize wolfSSL DH key. */
        dh->internal = key;
        if (wc_InitDhKey(key) != 0) {
            WOLFSSL_ERROR_MSG("wolfSSL_DH_new InitDhKey failure");
            err = 1;
        }
    }

    if (err && (dh != NULL)) {
        /* Dispose of the allocated memory. */
        XFREE(key, NULL, DYNAMIC_TYPE_DH);
        wolfSSL_RefFree(&dh->ref);
        XFREE(dh, NULL, DYNAMIC_TYPE_DH);
        dh = NULL;
    }
    return dh;
}

#if defined(HAVE_PUBLIC_FFDHE) || (defined(HAVE_FIPS) && FIPS_VERSION_EQ(2,0))
/* Set the DH parameters based on the NID.
 *
 * @param [in, out] dh   DH key to set.
 * @param [in]      nid  Numeric ID of predefined DH parameters.
 * @return  0 on success.
 * @return  1 on failure.
 */
static int wolfssl_dh_set_nid(WOLFSSL_DH* dh, int nid)
{
    int err = 0;
    const DhParams* params = NULL;

    /* HAVE_PUBLIC_FFDHE not required to expose wc_Dh_ffdhe* functions in
     * FIPS v2 module */
    switch (nid) {
#ifdef HAVE_FFDHE_2048
    case WC_NID_ffdhe2048:
        params = wc_Dh_ffdhe2048_Get();
        break;
#endif /* HAVE_FFDHE_2048 */
#ifdef HAVE_FFDHE_3072
    case WC_NID_ffdhe3072:
        params = wc_Dh_ffdhe3072_Get();
        break;
#endif /* HAVE_FFDHE_3072 */
#ifdef HAVE_FFDHE_4096
    case WC_NID_ffdhe4096:
        params = wc_Dh_ffdhe4096_Get();
        break;
#endif /* HAVE_FFDHE_4096 */
    default:
        break;
    }
    if (params == NULL) {
        WOLFSSL_ERROR_MSG("Unable to find DH params for nid.");
        err = 1;
    }

    if (!err) {
        /* Set prime from data retrieved. */
        dh->p = wolfSSL_BN_bin2bn(params->p, (int)params->p_len, NULL);
        if (dh->p == NULL) {
            WOLFSSL_ERROR_MSG("Error converting p hex to WOLFSSL_BIGNUM.");
            err = 1;
        }
    }
    if (!err) {
        /* Set generator from data retrieved. */
        dh->g = wolfSSL_BN_bin2bn(params->g, (int)params->g_len, NULL);
        if (dh->g == NULL) {
            WOLFSSL_ERROR_MSG("Error converting g hex to WOLFSSL_BIGNUM.");
            err = 1;
        }
    }
#ifdef HAVE_FFDHE_Q
    if (!err) {
        /* Set order from data retrieved. */
        dh->q = wolfSSL_BN_bin2bn(params->q, params->q_len, NULL);
        if (dh->q == NULL) {
            WOLFSSL_ERROR_MSG("Error converting q hex to WOLFSSL_BIGNUM.");
            err = 1;
        }
    }
#endif

    /* Synchronize the external into internal DH key's parameters. */
    if ((!err) && (SetDhInternal(dh) != 1)) {
        WOLFSSL_ERROR_MSG("Failed to set internal DH params.");
        err = 1;
    }
    if (!err) {
        /* External DH key parameters were set. */
        dh->exSet = 1;
    }

    if (err == 1) {
        /* Dispose of any external parameters. */
    #ifdef HAVE_FFDHE_Q
        wolfSSL_BN_free(dh->q);
        dh->q = NULL;
    #endif
        wolfSSL_BN_free(dh->p);
        dh->p = NULL;
        wolfSSL_BN_free(dh->g);
        dh->g = NULL;
    }

    return err;
}
#elif !defined(HAVE_PUBLIC_FFDHE) && (!defined(HAVE_FIPS) || \
      FIPS_VERSION_GT(2,0))
/* Set the DH parameters based on the NID.
 *
 * FIPS v2 and lower doesn't support wc_DhSetNamedKey.
 *
 * @param [in, out] dh   DH key to set.
 * @param [in]      nid  Numeric ID of predefined DH parameters.
 * @return  0 on success.
 * @return  1 on failure.
 */
static int wolfssl_dh_set_nid(WOLFSSL_DH* dh, int nid)
{
    int err = 0;
    int name = 0;
#ifdef HAVE_FFDHE_Q
    int elements = ELEMENT_P | ELEMENT_G | ELEMENT_Q;
#else
    int elements = ELEMENT_P | ELEMENT_G;
#endif /* HAVE_FFDHE_Q */

    switch (nid) {
#ifdef HAVE_FFDHE_2048
    case WC_NID_ffdhe2048:
        name = WC_FFDHE_2048;
        break;
#endif /* HAVE_FFDHE_2048 */
#ifdef HAVE_FFDHE_3072
    case WC_NID_ffdhe3072:
        name = WC_FFDHE_3072;
        break;
#endif /* HAVE_FFDHE_3072 */
#ifdef HAVE_FFDHE_4096
    case WC_NID_ffdhe4096:
        name = WC_FFDHE_4096;
        break;
#endif /* HAVE_FFDHE_4096 */
    default:
        err = 1;
        WOLFSSL_ERROR_MSG("Unable to find DH params for nid.");
        break;
    }
    /* Set the internal DH key's parameters based on name. */
    if ((!err) && (wc_DhSetNamedKey((DhKey*)dh->internal, name) != 0)) {
        WOLFSSL_ERROR_MSG("wc_DhSetNamedKey failed.");
        err = 1;
    }
    /* Synchronize the internal into external DH key's parameters. */
    if (!err && (SetDhExternal_ex(dh, elements) != 1)) {
        WOLFSSL_ERROR_MSG("Failed to set external DH params.");
        err = 1;
    }

    return err;
}
#else
/* Set the DH parameters based on the NID.
 *
 * Pre-defined DH parameters not available.
 *
 * @param [in, out] dh   DH key to set.
 * @param [in]      nid  Numeric ID of predefined DH parameters.
 * @return  1 for failure.
 */
static int wolfssl_dh_set_nid(WOLFSSL_DH* dh, int nid)
{
    return 1;
}
#endif

/* Allocate and initialize a new DH key with the parameters based on the NID.
 *
 * @param [in] nid  Numeric ID of DH parameters.
 *
 * @return  DH key on success.
 * @return  NULL on failure.
 */
WOLFSSL_DH* wolfSSL_DH_new_by_nid(int nid)
{
    WOLFSSL_DH* dh = NULL;
    int err = 0;

    WOLFSSL_ENTER("wolfSSL_DH_new_by_nid");

    /* Allocate a new DH key. */
    dh = wolfSSL_DH_new();
    if (dh == NULL) {
        WOLFSSL_ERROR_MSG("Failed to create WOLFSSL_DH.");
        err = 1;
    }
    if (!err) {
        /* Set the parameters based on NID. */
        err = wolfssl_dh_set_nid(dh, nid);
    }

    if (err && (dh != NULL)) {
        /* Dispose of the key on failure to set. */
        wolfSSL_DH_free(dh);
        dh = NULL;
    }

    WOLFSSL_LEAVE("wolfSSL_DH_new_by_nid", err);

    return dh;
}

/* Dispose of DH key and allocated data.
 *
 * Cannot use dh after this call.
 *
 * @param [in] dh  DH key to free.
 */
void wolfSSL_DH_free(WOLFSSL_DH* dh)
{
    int doFree = 0;

    WOLFSSL_ENTER("wolfSSL_DH_free");

    if (dh != NULL) {
        int err;

        /* Only free if all references to it are done */
        wolfSSL_RefDec(&dh->ref, &doFree, &err);
        /* Ignore errors - doFree will be 0 on error. */
        (void)err;
    }
    if (doFree) {
        /* Dispose of allocated reference counting data. */
        wolfSSL_RefFree(&dh->ref);

        /* Dispose of wolfSSL DH key. */
        if (dh->internal) {
            wc_FreeDhKey((DhKey*)dh->internal);
            XFREE(dh->internal, NULL, DYNAMIC_TYPE_DH);
            dh->internal = NULL;
        }

        /* Dispose of any allocated BNs. */
        wolfSSL_BN_free(dh->priv_key);
        wolfSSL_BN_free(dh->pub_key);
        wolfSSL_BN_free(dh->g);
        wolfSSL_BN_free(dh->p);
        wolfSSL_BN_free(dh->q);
        /* Set back to NULLs for safety. */
        XMEMSET(dh, 0, sizeof(WOLFSSL_DH));

        XFREE(dh, NULL, DYNAMIC_TYPE_DH);
    }
}

/* Increments ref count of DH key.
 *
 * @param [in, out] dh  DH key.
 * @return  1 on success
 * @return  0 on error
 */
int wolfSSL_DH_up_ref(WOLFSSL_DH* dh)
{
    int err = 1;

    WOLFSSL_ENTER("wolfSSL_DH_up_ref");

    if (dh != NULL) {
        wolfSSL_RefInc(&dh->ref, &err);
    }

    return !err;
}

#if defined(WOLFSSL_QT) || defined(OPENSSL_ALL) || defined(WOLFSSL_OPENSSH) || \
    defined(OPENSSL_EXTRA)

#ifdef WOLFSSL_DH_EXTRA
/* Duplicate the DH key.
 *
 * Internal DH key in 'dh' is updated if necessary.
 *
 * @param [in, out] dh  DH key to duplicate.
 * @return  NULL on failure.
 * @return  DH key on success.
 */
WOLFSSL_DH* wolfSSL_DH_dup(WOLFSSL_DH* dh)
{
    WOLFSSL_DH* ret = NULL;
    int err = 0;

    WOLFSSL_ENTER("wolfSSL_DH_dup");

    /* Validate parameters. */
    if (dh == NULL) {
        WOLFSSL_ERROR_MSG("Bad parameter");
        err = 1;
    }

    /* Ensure internal DH key is set. */
    if ((!err) && (dh->inSet == 0) && (SetDhInternal(dh) != 1)) {
        WOLFSSL_ERROR_MSG("Bad DH set internal");
        err = 1;
    }

    /* Create a new DH key object. */
    if ((!err) && (!(ret = wolfSSL_DH_new()))) {
        WOLFSSL_ERROR_MSG("wolfSSL_DH_new error");
        err = 1;
    }
    /* Copy internal DH key from original to new. */
    if ((!err) && (wc_DhKeyCopy((DhKey*)dh->internal, (DhKey*)ret->internal) !=
            MP_OKAY)) {
        WOLFSSL_ERROR_MSG("wc_DhKeyCopy error");
        err = 1;
    }
    if (!err) {
        ret->inSet = 1;

         /* Synchronize the internal into external DH key's parameters. */
        if (SetDhExternal(ret) != 1) {
            WOLFSSL_ERROR_MSG("SetDhExternal error");
            err = 1;
        }
    }

    /* Dispose of any allocated DH key on error. */
    if (err && (ret != NULL)) {
        wolfSSL_DH_free(ret);
        ret = NULL;
    }
    return ret;
}
#endif /* WOLFSSL_DH_EXTRA */

#endif

/* Allocate and initialize a new DH key with 2048-bit parameters.
 *
 * See RFC 5114 section 2.3, "2048-bit MODP Group with 256-bit Prime Order
 * Subgroup."
 *
 * @return  NULL on failure.
 * @return  DH Key on success.
 */
WOLFSSL_DH* wolfSSL_DH_get_2048_256(void)
{
    WOLFSSL_DH* dh;
    int err = 0;
    static const byte pHex[] = {
        0x87, 0xA8, 0xE6, 0x1D, 0xB4, 0xB6, 0x66, 0x3C, 0xFF, 0xBB, 0xD1, 0x9C,
        0x65, 0x19, 0x59, 0x99, 0x8C, 0xEE, 0xF6, 0x08, 0x66, 0x0D, 0xD0, 0xF2,
        0x5D, 0x2C, 0xEE, 0xD4, 0x43, 0x5E, 0x3B, 0x00, 0xE0, 0x0D, 0xF8, 0xF1,
        0xD6, 0x19, 0x57, 0xD4, 0xFA, 0xF7, 0xDF, 0x45, 0x61, 0xB2, 0xAA, 0x30,
        0x16, 0xC3, 0xD9, 0x11, 0x34, 0x09, 0x6F, 0xAA, 0x3B, 0xF4, 0x29, 0x6D,
        0x83, 0x0E, 0x9A, 0x7C, 0x20, 0x9E, 0x0C, 0x64, 0x97, 0x51, 0x7A, 0xBD,
        0x5A, 0x8A, 0x9D, 0x30, 0x6B, 0xCF, 0x67, 0xED, 0x91, 0xF9, 0xE6, 0x72,
        0x5B, 0x47, 0x58, 0xC0, 0x22, 0xE0, 0xB1, 0xEF, 0x42, 0x75, 0xBF, 0x7B,
        0x6C, 0x5B, 0xFC, 0x11, 0xD4, 0x5F, 0x90, 0x88, 0xB9, 0x41, 0xF5, 0x4E,
        0xB1, 0xE5, 0x9B, 0xB8, 0xBC, 0x39, 0xA0, 0xBF, 0x12, 0x30, 0x7F, 0x5C,
        0x4F, 0xDB, 0x70, 0xC5, 0x81, 0xB2, 0x3F, 0x76, 0xB6, 0x3A, 0xCA, 0xE1,
        0xCA, 0xA6, 0xB7, 0x90, 0x2D, 0x52, 0x52, 0x67, 0x35, 0x48, 0x8A, 0x0E,
        0xF1, 0x3C, 0x6D, 0x9A, 0x51, 0xBF, 0xA4, 0xAB, 0x3A, 0xD8, 0x34, 0x77,
        0x96, 0x52, 0x4D, 0x8E, 0xF6, 0xA1, 0x67, 0xB5, 0xA4, 0x18, 0x25, 0xD9,
        0x67, 0xE1, 0x44, 0xE5, 0x14, 0x05, 0x64, 0x25, 0x1C, 0xCA, 0xCB, 0x83,
        0xE6, 0xB4, 0x86, 0xF6, 0xB3, 0xCA, 0x3F, 0x79, 0x71, 0x50, 0x60, 0x26,
        0xC0, 0xB8, 0x57, 0xF6, 0x89, 0x96, 0x28, 0x56, 0xDE, 0xD4, 0x01, 0x0A,
        0xBD, 0x0B, 0xE6, 0x21, 0xC3, 0xA3, 0x96, 0x0A, 0x54, 0xE7, 0x10, 0xC3,
        0x75, 0xF2, 0x63, 0x75, 0xD7, 0x01, 0x41, 0x03, 0xA4, 0xB5, 0x43, 0x30,
        0xC1, 0x98, 0xAF, 0x12, 0x61, 0x16, 0xD2, 0x27, 0x6E, 0x11, 0x71, 0x5F,
        0x69, 0x38, 0x77, 0xFA, 0xD7, 0xEF, 0x09, 0xCA, 0xDB, 0x09, 0x4A, 0xE9,
        0x1E, 0x1A, 0x15, 0x97
    };
    static const byte gHex[] = {
        0x3F, 0xB3, 0x2C, 0x9B, 0x73, 0x13, 0x4D, 0x0B, 0x2E, 0x77, 0x50, 0x66,
        0x60, 0xED, 0xBD, 0x48, 0x4C, 0xA7, 0xB1, 0x8F, 0x21, 0xEF, 0x20, 0x54,
        0x07, 0xF4, 0x79, 0x3A, 0x1A, 0x0B, 0xA1, 0x25, 0x10, 0xDB, 0xC1, 0x50,
        0x77, 0xBE, 0x46, 0x3F, 0xFF, 0x4F, 0xED, 0x4A, 0xAC, 0x0B, 0xB5, 0x55,
        0xBE, 0x3A, 0x6C, 0x1B, 0x0C, 0x6B, 0x47, 0xB1, 0xBC, 0x37, 0x73, 0xBF,
        0x7E, 0x8C, 0x6F, 0x62, 0x90, 0x12, 0x28, 0xF8, 0xC2, 0x8C, 0xBB, 0x18,
        0xA5, 0x5A, 0xE3, 0x13, 0x41, 0x00, 0x0A, 0x65, 0x01, 0x96, 0xF9, 0x31,
        0xC7, 0x7A, 0x57, 0xF2, 0xDD, 0xF4, 0x63, 0xE5, 0xE9, 0xEC, 0x14, 0x4B,
        0x77, 0x7D, 0xE6, 0x2A, 0xAA, 0xB8, 0xA8, 0x62, 0x8A, 0xC3, 0x76, 0xD2,
        0x82, 0xD6, 0xED, 0x38, 0x64, 0xE6, 0x79, 0x82, 0x42, 0x8E, 0xBC, 0x83,
        0x1D, 0x14, 0x34, 0x8F, 0x6F, 0x2F, 0x91, 0x93, 0xB5, 0x04, 0x5A, 0xF2,
        0x76, 0x71, 0x64, 0xE1, 0xDF, 0xC9, 0x67, 0xC1, 0xFB, 0x3F, 0x2E, 0x55,
        0xA4, 0xBD, 0x1B, 0xFF, 0xE8, 0x3B, 0x9C, 0x80, 0xD0, 0x52, 0xB9, 0x85,
        0xD1, 0x82, 0xEA, 0x0A, 0xDB, 0x2A, 0x3B, 0x73, 0x13, 0xD3, 0xFE, 0x14,
        0xC8, 0x48, 0x4B, 0x1E, 0x05, 0x25, 0x88, 0xB9, 0xB7, 0xD2, 0xBB, 0xD2,
        0xDF, 0x01, 0x61, 0x99, 0xEC, 0xD0, 0x6E, 0x15, 0x57, 0xCD, 0x09, 0x15,
        0xB3, 0x35, 0x3B, 0xBB, 0x64, 0xE0, 0xEC, 0x37, 0x7F, 0xD0, 0x28, 0x37,
        0x0D, 0xF9, 0x2B, 0x52, 0xC7, 0x89, 0x14, 0x28, 0xCD, 0xC6, 0x7E, 0xB6,
        0x18, 0x4B, 0x52, 0x3D, 0x1D, 0xB2, 0x46, 0xC3, 0x2F, 0x63, 0x07, 0x84,
        0x90, 0xF0, 0x0E, 0xF8, 0xD6, 0x47, 0xD1, 0x48, 0xD4, 0x79, 0x54, 0x51,
        0x5E, 0x23, 0x27, 0xCF, 0xEF, 0x98, 0xC5, 0x82, 0x66, 0x4B, 0x4C, 0x0F,
        0x6C, 0xC4, 0x16, 0x59
    };
    static const byte qHex[] = {
        0x8C, 0xF8, 0x36, 0x42, 0xA7, 0x09, 0xA0, 0x97, 0xB4, 0x47, 0x99, 0x76,
        0x40, 0x12, 0x9D, 0xA2, 0x99, 0xB1, 0xA4, 0x7D, 0x1E, 0xB3, 0x75, 0x0B,
        0xA3, 0x08, 0xB0, 0xFE, 0x64, 0xF5, 0xFB, 0xD3
    };

    /* Create a new DH key to return. */
    dh = wolfSSL_DH_new();
    if (dh == NULL) {
        err = 1;
    }
    if (!err) {
        /* Set prime. */
        dh->p = wolfSSL_BN_bin2bn(pHex, (int)sizeof(pHex), NULL);
        if (dh->p == NULL) {
            WOLFSSL_ERROR_MSG("Error converting p hex to WOLFSSL_BIGNUM.");
            err = 1;
        }
    }
    if (!err) {
        /* Set generator. */
        dh->g = wolfSSL_BN_bin2bn(gHex, (int)sizeof(gHex), NULL);
        if (dh->g == NULL) {
            WOLFSSL_ERROR_MSG("Error converting g hex to WOLFSSL_BIGNUM.");
            err = 1;
        }
    }
    if (!err) {
        /* Set order. */
        dh->q = wolfSSL_BN_bin2bn(qHex, (int)sizeof(qHex), NULL);
        if (dh->q == NULL) {
            WOLFSSL_ERROR_MSG("Error converting q hex to WOLFSSL_BIGNUM.");
            err = 1;
        }
    }
    /* Set values into wolfSSL DH key. */
    if ((!err) && (SetDhInternal(dh) != 1)) {
        WOLFSSL_ERROR_MSG("Error setting DH parameters.");
        err = 1;
    }
    if (!err) {
        /* External DH key parameters were set. */
        dh->exSet = 1;
    }

    /* Dispose of any allocated DH key on error. */
    if (err && (dh != NULL)) {
        wolfSSL_DH_free(dh);
        dh = NULL;
    }

    return dh;
}

/* TODO: consider changing strings to byte arrays. */

/* Returns a big number with the 768-bit prime from RFC 2409.
 *
 * @param [in, out] bn  If not NULL then this BN is set and returned.
 *                      If NULL then a new BN is created, set and returned.
 *
 * @return  NULL on failure.
 * @return  WOLFSSL_BIGNUM with value set to 768-bit prime on success.
 */
WOLFSSL_BIGNUM* wolfSSL_DH_768_prime(WOLFSSL_BIGNUM* bn)
{
#if WOLFSSL_MAX_BN_BITS >= 768
    static const char prm[] = {
        "FFFFFFFFFFFFFFFFC90FDAA22168C234"
        "C4C6628B80DC1CD129024E088A67CC74"
        "020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F1437"
        "4FE1356D6D51C245E485B576625E7EC6"
        "F44C42E9A63A3620FFFFFFFFFFFFFFFF"
    };

    WOLFSSL_ENTER("wolfSSL_DH_768_prime");

    /* Set prime into BN. Creates a new BN when bn is NULL. */
    if (wolfSSL_BN_hex2bn(&bn, prm) != 1) {
        WOLFSSL_ERROR_MSG("Error converting DH 768 prime to big number");
        bn = NULL;
    }

    return bn;
#else
    (void)bn;
    return NULL;
#endif
}

/* Returns a big number with the 1024-bit prime from RFC 2409.
 *
 * @param [in, out] bn  If not NULL then this BN is set and returned.
 *                      If NULL then a new BN is created, set and returned.
 *
 * @return  NULL on failure.
 * @return  WOLFSSL_BIGNUM with value set to 1024-bit prime on success.
 */
WOLFSSL_BIGNUM* wolfSSL_DH_1024_prime(WOLFSSL_BIGNUM* bn)
{
#if WOLFSSL_MAX_BN_BITS >= 1024
    static const char prm[] = {
        "FFFFFFFFFFFFFFFFC90FDAA22168C234"
        "C4C6628B80DC1CD129024E088A67CC74"
        "020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F1437"
        "4FE1356D6D51C245E485B576625E7EC6"
        "F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE6"
        "49286651ECE65381FFFFFFFFFFFFFFFF"
    };

    WOLFSSL_ENTER("wolfSSL_DH_1024_prime");

    /* Set prime into BN. Creates a new BN when bn is NULL. */
    if (wolfSSL_BN_hex2bn(&bn, prm) != 1) {
        WOLFSSL_ERROR_MSG("Error converting DH 1024 prime to big number");
        bn = NULL;
    }

    return bn;
#else
    (void)bn;
    return NULL;
#endif
}

/* Returns a big number with the 1536-bit prime from RFC 3526.
 *
 * @param [in, out] bn  If not NULL then this BN is set and returned.
 *                      If NULL then a new BN is created, set and returned.
 *
 * @return  NULL on failure.
 * @return  WOLFSSL_BIGNUM with value set to 1536-bit prime on success.
 */
WOLFSSL_BIGNUM* wolfSSL_DH_1536_prime(WOLFSSL_BIGNUM* bn)
{
#if WOLFSSL_MAX_BN_BITS >= 1536
    static const char prm[] = {
        "FFFFFFFFFFFFFFFFC90FDAA22168C234"
        "C4C6628B80DC1CD129024E088A67CC74"
        "020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F1437"
        "4FE1356D6D51C245E485B576625E7EC6"
        "F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE6"
        "49286651ECE45B3DC2007CB8A163BF05"
        "98DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB"
        "9ED529077096966D670C354E4ABC9804"
        "F1746C08CA237327FFFFFFFFFFFFFFFF"
    };

    WOLFSSL_ENTER("wolfSSL_DH_1536_prime");

    /* Set prime into BN. Creates a new BN when bn is NULL. */
    if (wolfSSL_BN_hex2bn(&bn, prm) != 1) {
        WOLFSSL_ERROR_MSG("Error converting DH 1536 prime to big number");
        bn = NULL;
    }

    return bn;
#else
    (void)bn;
    return NULL;
#endif
}

/* Returns a big number with the 2048-bit prime from RFC 3526.
 *
 * @param [in, out] bn  If not NULL then this BN is set and returned.
 *                      If NULL then a new BN is created, set and returned.
 *
 * @return  NULL on failure.
 * @return  WOLFSSL_BIGNUM with value set to 2048-bit prime on success.
 */
WOLFSSL_BIGNUM* wolfSSL_DH_2048_prime(WOLFSSL_BIGNUM* bn)
{
#if WOLFSSL_MAX_BN_BITS >= 2048
    static const char prm[] = {
        "FFFFFFFFFFFFFFFFC90FDAA22168C234"
        "C4C6628B80DC1CD129024E088A67CC74"
        "020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F1437"
        "4FE1356D6D51C245E485B576625E7EC6"
        "F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE6"
        "49286651ECE45B3DC2007CB8A163BF05"
        "98DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB"
        "9ED529077096966D670C354E4ABC9804"
        "F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28F"
        "B5C55DF06F4C52C9DE2BCBF695581718"
        "3995497CEA956AE515D2261898FA0510"
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF"
    };

    WOLFSSL_ENTER("wolfSSL_DH_2048_prime");

    /* Set prime into BN. Creates a new BN when bn is NULL. */
    if (wolfSSL_BN_hex2bn(&bn, prm) != 1) {
        WOLFSSL_ERROR_MSG("Error converting DH 2048 prime to big number");
        bn = NULL;
    }

    return bn;
#else
    (void)bn;
    return NULL;
#endif
}

/* Returns a big number with the 3072-bit prime from RFC 3526.
 *
 * @param [in, out] bn  If not NULL then this BN is set and returned.
 *                      If NULL then a new BN is created, set and returned.
 *
 * @return  NULL on failure.
 * @return  WOLFSSL_BIGNUM with value set to 3072-bit prime on success.
 */
WOLFSSL_BIGNUM* wolfSSL_DH_3072_prime(WOLFSSL_BIGNUM* bn)
{
#if WOLFSSL_MAX_BN_BITS >= 3072
    static const char prm[] = {
        "FFFFFFFFFFFFFFFFC90FDAA22168C234"
        "C4C6628B80DC1CD129024E088A67CC74"
        "020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F1437"
        "4FE1356D6D51C245E485B576625E7EC6"
        "F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE6"
        "49286651ECE45B3DC2007CB8A163BF05"
        "98DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB"
        "9ED529077096966D670C354E4ABC9804"
        "F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28F"
        "B5C55DF06F4C52C9DE2BCBF695581718"
        "3995497CEA956AE515D2261898FA0510"
        "15728E5A8AAAC42DAD33170D04507A33"
        "A85521ABDF1CBA64ECFB850458DBEF0A"
        "8AEA71575D060C7DB3970F85A6E1E4C7"
        "ABF5AE8CDB0933D71E8C94E04A25619D"
        "CEE3D2261AD2EE6BF12FFA06D98A0864"
        "D87602733EC86A64521F2B18177B200C"
        "BBE117577A615D6C770988C0BAD946E2"
        "08E24FA074E5AB3143DB5BFCE0FD108E"
        "4B82D120A93AD2CAFFFFFFFFFFFFFFFF"
    };

    WOLFSSL_ENTER("wolfSSL_DH_3072_prime");

    /* Set prime into BN. Creates a new BN when bn is NULL. */
    if (wolfSSL_BN_hex2bn(&bn, prm) != 1) {
        WOLFSSL_ERROR_MSG("Error converting DH 3072 prime to big number");
        bn = NULL;
    }

    return bn;
#else
    (void)bn;
    return NULL;
#endif
}

/* Returns a big number with the 4096-bit prime from RFC 3526.
 *
 * @param [in, out] bn  If not NULL then this BN is set and returned.
 *                      If NULL then a new BN is created, set and returned.
 *
 * @return  NULL on failure.
 * @return  WOLFSSL_BIGNUM with value set to 4096-bit prime on success.
 */
WOLFSSL_BIGNUM* wolfSSL_DH_4096_prime(WOLFSSL_BIGNUM* bn)
{
#if WOLFSSL_MAX_BN_BITS >= 4096
    static const char prm[] = {
        "FFFFFFFFFFFFFFFFC90FDAA22168C234"
        "C4C6628B80DC1CD129024E088A67CC74"
        "020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F1437"
        "4FE1356D6D51C245E485B576625E7EC6"
        "F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE6"
        "49286651ECE45B3DC2007CB8A163BF05"
        "98DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB"
        "9ED529077096966D670C354E4ABC9804"
        "F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28F"
        "B5C55DF06F4C52C9DE2BCBF695581718"
        "3995497CEA956AE515D2261898FA0510"
        "15728E5A8AAAC42DAD33170D04507A33"
        "A85521ABDF1CBA64ECFB850458DBEF0A"
        "8AEA71575D060C7DB3970F85A6E1E4C7"
        "ABF5AE8CDB0933D71E8C94E04A25619D"
        "CEE3D2261AD2EE6BF12FFA06D98A0864"
        "D87602733EC86A64521F2B18177B200C"
        "BBE117577A615D6C770988C0BAD946E2"
        "08E24FA074E5AB3143DB5BFCE0FD108E"
        "4B82D120A92108011A723C12A787E6D7"
        "88719A10BDBA5B2699C327186AF4E23C"
        "1A946834B6150BDA2583E9CA2AD44CE8"
        "DBBBC2DB04DE8EF92E8EFC141FBECAA6"
        "287C59474E6BC05D99B2964FA090C3A2"
        "233BA186515BE7ED1F612970CEE2D7AF"
        "B81BDD762170481CD0069127D5B05AA9"
        "93B4EA988D8FDDC186FFB7DC90A6C08F"
        "4DF435C934063199FFFFFFFFFFFFFFFF"
    };

    WOLFSSL_ENTER("wolfSSL_DH_4096_prime");

    /* Set prime into BN. Creates a new BN when bn is NULL. */
    if (wolfSSL_BN_hex2bn(&bn, prm) != 1) {
        WOLFSSL_ERROR_MSG("Error converting DH 4096 prime to big number");
        bn = NULL;
    }

    return bn;
#else
    (void)bn;
    return NULL;
#endif
}

/* Returns a big number with the 6144-bit prime from RFC 3526.
 *
 * @param [in, out] bn  If not NULL then this BN is set and returned.
 *                      If NULL then a new BN is created, set and returned.
 *
 * @return  NULL on failure.
 * @return  WOLFSSL_BIGNUM with value set to 6144-bit prime on success.
 */
WOLFSSL_BIGNUM* wolfSSL_DH_6144_prime(WOLFSSL_BIGNUM* bn)
{
#if WOLFSSL_MAX_BN_BITS >= 6144
    static const char prm[] = {
        "FFFFFFFFFFFFFFFFC90FDAA22168C234"
        "C4C6628B80DC1CD129024E088A67CC74"
        "020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F1437"
        "4FE1356D6D51C245E485B576625E7EC6"
        "F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE6"
        "49286651ECE45B3DC2007CB8A163BF05"
        "98DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB"
        "9ED529077096966D670C354E4ABC9804"
        "F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28F"
        "B5C55DF06F4C52C9DE2BCBF695581718"
        "3995497CEA956AE515D2261898FA0510"
        "15728E5A8AAAC42DAD33170D04507A33"
        "A85521ABDF1CBA64ECFB850458DBEF0A"
        "8AEA71575D060C7DB3970F85A6E1E4C7"
        "ABF5AE8CDB0933D71E8C94E04A25619D"
        "CEE3D2261AD2EE6BF12FFA06D98A0864"
        "D87602733EC86A64521F2B18177B200C"
        "BBE117577A615D6C770988C0BAD946E2"
        "08E24FA074E5AB3143DB5BFCE0FD108E"
        "4B82D120A92108011A723C12A787E6D7"
        "88719A10BDBA5B2699C327186AF4E23C"
        "1A946834B6150BDA2583E9CA2AD44CE8"
        "DBBBC2DB04DE8EF92E8EFC141FBECAA6"
        "287C59474E6BC05D99B2964FA090C3A2"
        "233BA186515BE7ED1F612970CEE2D7AF"
        "B81BDD762170481CD0069127D5B05AA9"
        "93B4EA988D8FDDC186FFB7DC90A6C08F"
        "4DF435C93402849236C3FAB4D27C7026"
        "C1D4DCB2602646DEC9751E763DBA37BD"
        "F8FF9406AD9E530EE5DB382F413001AE"
        "B06A53ED9027D831179727B0865A8918"
        "DA3EDBEBCF9B14ED44CE6CBACED4BB1B"
        "DB7F1447E6CC254B332051512BD7AF42"
        "6FB8F401378CD2BF5983CA01C64B92EC"
        "F032EA15D1721D03F482D7CE6E74FEF6"
        "D55E702F46980C82B5A84031900B1C9E"
        "59E7C97FBEC7E8F323A97A7E36CC88BE"
        "0F1D45B7FF585AC54BD407B22B4154AA"
        "CC8F6D7EBF48E1D814CC5ED20F8037E0"
        "A79715EEF29BE32806A1D58BB7C5DA76"
        "F550AA3D8A1FBFF0EB19CCB1A313D55C"
        "DA56C9EC2EF29632387FE8D76E3C0468"
        "043E8F663F4860EE12BF2D5B0B7474D6"
        "E694F91E6DCC4024FFFFFFFFFFFFFFFF"
    };

    WOLFSSL_ENTER("wolfSSL_DH_6144_prime");

    /* Set prime into BN. Creates a new BN when bn is NULL. */
    if (wolfSSL_BN_hex2bn(&bn, prm) != 1) {
        WOLFSSL_ERROR_MSG("Error converting DH 6144 prime to big number");
        bn = NULL;
    }

    return bn;
#else
    (void)bn;
    return NULL;
#endif
}


/* Returns a big number with the 8192-bit prime from RFC 3526.
 *
 * @param [in, out] bn  If not NULL then this BN is set and returned.
 *                      If NULL then a new BN is created, set and returned.
 *
 * @return  NULL on failure.
 * @return  WOLFSSL_BIGNUM with value set to 8192-bit prime on success.
 */
WOLFSSL_BIGNUM* wolfSSL_DH_8192_prime(WOLFSSL_BIGNUM* bn)
{
#if WOLFSSL_MAX_BN_BITS >= 8192
    static const char prm[] = {
        "FFFFFFFFFFFFFFFFC90FDAA22168C234"
        "C4C6628B80DC1CD129024E088A67CC74"
        "020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F1437"
        "4FE1356D6D51C245E485B576625E7EC6"
        "F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE6"
        "49286651ECE45B3DC2007CB8A163BF05"
        "98DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB"
        "9ED529077096966D670C354E4ABC9804"
        "F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28F"
        "B5C55DF06F4C52C9DE2BCBF695581718"
        "3995497CEA956AE515D2261898FA0510"
        "15728E5A8AAAC42DAD33170D04507A33"
        "A85521ABDF1CBA64ECFB850458DBEF0A"
        "8AEA71575D060C7DB3970F85A6E1E4C7"
        "ABF5AE8CDB0933D71E8C94E04A25619D"
        "CEE3D2261AD2EE6BF12FFA06D98A0864"
        "D87602733EC86A64521F2B18177B200C"
        "BBE117577A615D6C770988C0BAD946E2"
        "08E24FA074E5AB3143DB5BFCE0FD108E"
        "4B82D120A92108011A723C12A787E6D7"
        "88719A10BDBA5B2699C327186AF4E23C"
        "1A946834B6150BDA2583E9CA2AD44CE8"
        "DBBBC2DB04DE8EF92E8EFC141FBECAA6"
        "287C59474E6BC05D99B2964FA090C3A2"
        "233BA186515BE7ED1F612970CEE2D7AF"
        "B81BDD762170481CD0069127D5B05AA9"
        "93B4EA988D8FDDC186FFB7DC90A6C08F"
        "4DF435C93402849236C3FAB4D27C7026"
        "C1D4DCB2602646DEC9751E763DBA37BD"
        "F8FF9406AD9E530EE5DB382F413001AE"
        "B06A53ED9027D831179727B0865A8918"
        "DA3EDBEBCF9B14ED44CE6CBACED4BB1B"
        "DB7F1447E6CC254B332051512BD7AF42"
        "6FB8F401378CD2BF5983CA01C64B92EC"
        "F032EA15D1721D03F482D7CE6E74FEF6"
        "D55E702F46980C82B5A84031900B1C9E"
        "59E7C97FBEC7E8F323A97A7E36CC88BE"
        "0F1D45B7FF585AC54BD407B22B4154AA"
        "CC8F6D7EBF48E1D814CC5ED20F8037E0"
        "A79715EEF29BE32806A1D58BB7C5DA76"
        "F550AA3D8A1FBFF0EB19CCB1A313D55C"
        "DA56C9EC2EF29632387FE8D76E3C0468"
        "043E8F663F4860EE12BF2D5B0B7474D6"
        "E694F91E6DBE115974A3926F12FEE5E4"
        "38777CB6A932DF8CD8BEC4D073B931BA"
        "3BC832B68D9DD300741FA7BF8AFC47ED"
        "2576F6936BA424663AAB639C5AE4F568"
        "3423B4742BF1C978238F16CBE39D652D"
        "E3FDB8BEFC848AD922222E04A4037C07"
        "13EB57A81A23F0C73473FC646CEA306B"
        "4BCBC8862F8385DDFA9D4B7FA2C087E8"
        "79683303ED5BDD3A062B3CF5B3A278A6"
        "6D2A13F83F44F82DDF310EE074AB6A36"
        "4597E899A0255DC164F31CC50846851D"
        "F9AB48195DED7EA1B1D510BD7EE74D73"
        "FAF36BC31ECFA268359046F4EB879F92"
        "4009438B481C6CD7889A002ED5EE382B"
        "C9190DA6FC026E479558E4475677E9AA"
        "9E3050E2765694DFC81F56E880B96E71"
        "60C980DD98EDD3DFFFFFFFFFFFFFFFFF"
    };

    WOLFSSL_ENTER("wolfSSL_DH_8192_prime");

    /* Set prime into BN. Creates a new BN when bn is NULL. */
    if (wolfSSL_BN_hex2bn(&bn, prm) != 1) {
        WOLFSSL_ERROR_MSG("Error converting DH 8192 prime to big number");
        bn = NULL;
    }

    return bn;
#else
    (void)bn;
    return NULL;
#endif
}

/*
 * DH to/from bin APIs
 */

#ifndef NO_CERTS

/* Load the DER encoded DH parameters into DH key.
 *
 * @param [in, out] dh      DH key to load parameters into.
 * @param [in]      der     Buffer holding DER encoded parameters data.
 * @param [in, out] idx     On in, index at which DH key DER data starts.
 *                          On out, index after DH key DER data.
 * @param [in]      derSz   Size of DER buffer in bytes.
 *
 * @return  0 on success.
 * @return  1 when decoding DER or setting the external key fails.
 */
static int wolfssl_dh_load_params(WOLFSSL_DH* dh, const unsigned char* der,
    word32* idx, word32 derSz)
{
    int err = 0;

#if !defined(HAVE_FIPS) || FIPS_VERSION_GT(2,0)
    int ret;

    /* Decode DH parameters/key from DER. */
    ret = wc_DhKeyDecode(der, idx, (DhKey*)dh->internal, derSz);
    if (ret != 0) {
        WOLFSSL_ERROR_MSG("DhKeyDecode() failed");
        err = 1;
    }
    if (!err) {
        /* wolfSSL DH key set. */
        dh->inSet = 1;

        /* Set the external DH key based on wolfSSL DH key. */
        if (SetDhExternal(dh) != 1) {
            WOLFSSL_ERROR_MSG("SetDhExternal failed");
            err = 1;
        }
    }
#else
    byte* p;
    byte* g;
    word32 pSz = MAX_DH_SIZE;
    word32 gSz = MAX_DH_SIZE;

    /* Only DH parameters supported. */
    /* Load external and set internal. */
    p = (byte*)XMALLOC(pSz, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
    g = (byte*)XMALLOC(gSz, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
    if ((p == NULL) || (g == NULL)) {
        err = 1;
    }
    /* Extract the p and g as data from the DER encoded DH parameters. */
    if ((!err) && (wc_DhParamsLoad(der + *idx, derSz - *idx, p, &pSz, g,
            &gSz) < 0)) {
        err = 1;
    }
    if (!err) {
        /* Put p and g in as big numbers - free existing BNs. */
        if (dh->p != NULL) {
            wolfSSL_BN_free(dh->p);
            dh->p = NULL;
        }
        if (dh->g != NULL) {
            wolfSSL_BN_free(dh->g);
            dh->g = NULL;
        }
        dh->p = wolfSSL_BN_bin2bn(p, (int)pSz, NULL);
        dh->g = wolfSSL_BN_bin2bn(g, (int)gSz, NULL);
        if (dh->p == NULL || dh->g == NULL) {
            err = 1;
        }
        else {
            /* External DH key parameters were set. */
            dh->exSet = 1;
        }
    }

    /* Set internal as the outside has been updated. */
    if ((!err) && (SetDhInternal(dh) != 1)) {
        WOLFSSL_ERROR_MSG("Unable to set internal DH structure");
        err = 1;
    }

    if (!err) {
        *idx += wolfssl_der_length(der + *idx, derSz - *idx);
    }

    XFREE(p, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
    XFREE(g, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
#endif

    return err;
}

#ifdef OPENSSL_ALL

#if !defined(HAVE_FIPS) || FIPS_VERSION_GT(2,0)
/* Convert DER encoded DH parameters to a WOLFSSL_DH structure.
 *
 * @param [out]     dh      DH key to put parameters into. May be NULL.
 * @param [in, out] pp      Pointer to DER encoded DH parameters.
 *                          Value updated to end of data when dh is not NULL.
 * @param [in]      length  Length of data available in bytes.
 *
 * @return  DH key on success.
 * @return  NULL on failure.
 */
WOLFSSL_DH *wolfSSL_d2i_DHparams(WOLFSSL_DH** dh, const unsigned char** pp,
    long length)
{
    WOLFSSL_DH *newDh = NULL;
    word32 idx = 0;
    int err = 0;

    WOLFSSL_ENTER("wolfSSL_d2i_DHparams");

    /* Validate parameters. */
    if ((pp == NULL) || (length <= 0)) {
        WOLFSSL_ERROR_MSG("bad argument");
        err = 1;
    }

    /* Create new DH key to return. */
    if ((!err) && ((newDh = wolfSSL_DH_new()) == NULL)) {
        WOLFSSL_ERROR_MSG("wolfSSL_DH_new() failed");
        err = 1;
    }
    if ((!err) && (wolfssl_dh_load_params(newDh, *pp, &idx,
            (word32)length) != 0)) {
        WOLFSSL_ERROR_MSG("Loading DH parameters failed");
        err = 1;
    }

    if ((!err) && (dh != NULL)) {
        /* Return through parameter too. */
        *dh = newDh;
        /* Move buffer on by the used amount. */
        *pp += idx;
    }

    if (err && (newDh != NULL)) {
        /* Dispose of any created DH key. */
        wolfSSL_DH_free(newDh);
        newDh = NULL;
    }
    return newDh;
}
#endif /* !HAVE_FIPS || FIPS_VERSION_GT(2,0) */

/* Converts internal WOLFSSL_DH structure to DER encoded DH parameters.
 *
 * @params [in]      dh   DH key with parameters to encode.
 * @params [in, out] out  Pointer to buffer to encode into.
 *                        When NULL or pointer to NULL, only length returned.
 * @return  0 on error.
 * @return  Size of DER encoding in bytes on success.
 */
int wolfSSL_i2d_DHparams(const WOLFSSL_DH *dh, unsigned char **out)
{
#if (!defined(HAVE_FIPS) || FIPS_VERSION_GT(5,0)) && defined(WOLFSSL_DH_EXTRA)
    /* Set length to an arbitrarily large value for wc_DhParamsToDer(). */
    word32 len = (word32)-1;
    int err = 0;

    /* Validate parameters. */
    if (dh == NULL) {
        WOLFSSL_ERROR_MSG("Bad parameters");
        err = 1;
    }

    /* Push external DH data into internal DH key if not set. */
    if ((!err) && (!dh->inSet) && (SetDhInternal((WOLFSSL_DH*)dh) != 1)) {
        WOLFSSL_ERROR_MSG("Bad DH set internal");
        err = 1;
    }
    if (!err) {
        int ret;
        unsigned char* der = NULL;

        /* Use *out when available otherwise NULL. */
        if (out != NULL) {
            der = *out;
        }
        /* Get length and/or encode. */
        ret = wc_DhParamsToDer((DhKey*)dh->internal, der, &len);
        /* Length of encoded data is returned on success. */
        if (ret > 0) {
            *out += len;
        }
        /* An error occurred unless only length returned. */
        else if (ret != WC_NO_ERR_TRACE(LENGTH_ONLY_E)) {
            err = 1;
        }
    }

    /* Set return to 0 on error. */
    if (err) {
        len = 0;
    }
    return (int)len;
#else
    word32 len;
    int ret = 0;
    int pSz;
    int gSz;

    WOLFSSL_ENTER("wolfSSL_i2d_DHparams");

    /* Validate parameters. */
    if (dh == NULL) {
        WOLFSSL_ERROR_MSG("Bad parameters");
        len = 0;
    }
    else {
        /* SEQ <len>
         *   INT <len> [0x00] <prime>
         *   INT <len> [0x00] <generator>
         * Integers have 0x00 prepended if the top bit of positive number is
         * set.
         */
        /* Get total length of prime including any prepended zeros. */
        pSz = mp_unsigned_bin_size((mp_int*)dh->p->internal) +
              mp_leading_bit((mp_int*)dh->p->internal);
        /* Get total length of generator including any prepended zeros. */
        gSz = mp_unsigned_bin_size((mp_int*)dh->g->internal) +
              mp_leading_bit((mp_int*)dh->g->internal);
        /* Calculate length of data in sequence. */
        len = 1 + ASN_LEN_SIZE(pSz) + pSz +
              1 + ASN_LEN_SIZE(gSz) + gSz;
        /* Add in the length of the SEQUENCE. */
        len += 1 + ASN_LEN_SIZE(len);

        if ((out != NULL) && (*out != NULL)) {
            /* Encode parameters. */
            ret = StoreDHparams(*out, &len, (mp_int*)dh->p->internal,
                (mp_int*)dh->g->internal);
            if (ret != MP_OKAY) {
                WOLFSSL_ERROR_MSG("StoreDHparams error");
                len = 0;
            }
            else {
                /* Move pointer on if encoded. */
                *out += len;
            }
        }
    }

    return (int)len;
#endif
}

#endif /* OPENSSL_ALL */

#endif /* !NO_CERTS */

#endif /* OPENSSL_EXTRA */

#if defined(OPENSSL_EXTRA) ||  \
 ((!defined(NO_BIO) || !defined(NO_FILESYSTEM)) && \
  defined(HAVE_LIGHTY) || defined(HAVE_STUNNEL) || \
  defined(WOLFSSL_MYSQL_COMPATIBLE))

/* Load the DER encoded DH parameters into DH key.
 *
 * @param [in, out] dh      DH key to load parameters into.
 * @param [in]      derBuf  Buffer holding DER encoded parameters data.
 * @param [in]      derSz   Size of DER data in buffer in bytes.
 *
 * @return  1 on success.
 * @return  -1 when DH or derBuf is NULL,
 *                  internal DH key in DH is NULL,
 *                  derSz is 0 or less,
 *                  error decoding DER data or
 *                  setting external parameter values fails.
 */
int wolfSSL_DH_LoadDer(WOLFSSL_DH* dh, const unsigned char* derBuf, int derSz)
{
    int    ret = 1;
    word32 idx = 0;

    /* Validate parameters. */
    if ((dh == NULL) || (dh->internal == NULL) || (derBuf == NULL) ||
            (derSz <= 0)) {
        WOLFSSL_ERROR_MSG("Bad function arguments");
        ret = WOLFSSL_FATAL_ERROR;
    }

    if ((ret == 1) && (wolfssl_dh_load_params(dh, derBuf, &idx,
            (word32)derSz) != 0)) {
        WOLFSSL_ERROR_MSG("DH key decode failed");
        ret = WOLFSSL_FATAL_ERROR;
    }

    return ret;
}

#endif

/*
 * DH PEM APIs
 */

#if defined(HAVE_LIGHTY) || defined(HAVE_STUNNEL) \
    || defined(WOLFSSL_MYSQL_COMPATIBLE) || defined(OPENSSL_EXTRA)

#if !defined(NO_BIO) || !defined(NO_FILESYSTEM)
/* Create a DH key by reading the PEM encoded data from the BIO.
 *
 * @param [in]      bio         BIO object to read from.
 * @param [in, out] dh          DH key to use. May be NULL.
 * @param [in]      pem         PEM data to decode.
 * @param [in]      pemSz       Size of PEM data in bytes.
 * @param [in]      memAlloced  Indicates that pem was allocated and is to be
 *                              freed after use.
 * @return  DH key on success.
 * @return  NULL on failure.
 */
static WOLFSSL_DH *wolfssl_dhparams_read_pem(WOLFSSL_DH **dh,
    unsigned char* pem, int pemSz, int memAlloced)
{
    WOLFSSL_DH* localDh = NULL;
    DerBuffer *der = NULL;
    int err = 0;

    /* Convert PEM to DER assuming DH Parameter format. */
    if ((!err) && (PemToDer(pem, pemSz, DH_PARAM_TYPE, &der, NULL, NULL,
            NULL) < 0)) {
        /* Convert PEM to DER assuming X9.42 DH Parameter format. */
        if (PemToDer(pem, pemSz, X942_PARAM_TYPE, &der, NULL, NULL, NULL)
                != 0) {
            err = 1;
        }
        /* If Success on X9.42 DH format, clear error from failed DH format */
        else {
            unsigned long error;
            CLEAR_ASN_NO_PEM_HEADER_ERROR(error);
        }
    }
    if (memAlloced) {
        /* PEM data no longer needed.  */
        XFREE(pem, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    if (!err) {
        /* Use the DH key passed in or allocate a new one. */
        if (dh != NULL) {
            localDh = *dh;
        }
        if (localDh == NULL) {
            localDh = wolfSSL_DH_new();
            if (localDh == NULL) {
                err = 1;
            }
        }
    }
    /* Load the DER encoded DH parameters from buffer into a DH key. */
    if ((!err) && (wolfSSL_DH_LoadDer(localDh, der->buffer, (int)der->length)
            != 1)) {
        /* Free an allocated DH key. */
        if ((dh == NULL) || (localDh != *dh)) {
            wolfSSL_DH_free(localDh);
        }
        localDh = NULL;
        err = 1;
    }
    /* Return the DH key on success. */
    if ((!err) && (dh != NULL)) {
        *dh = localDh;
    }

    /* Dispose of DER data. */
    if (der != NULL) {
        FreeDer(&der);
    }
    return localDh;
}
#endif /* !NO_BIO || !NO_FILESYSTEM */

#ifndef NO_BIO
/* Create a DH key by reading the PEM encoded data from the BIO.
 *
 * DH parameters are public data and are not expected to be encrypted.
 *
 * @param [in]      bio   BIO object to read from.
 * @param [in, out] dh    DH key to   When pointer to
 *                        NULL, a new DH key is created.
 * @param [in]      cb    Password callback when PEM encrypted. Not used.
 * @param [in]      pass  NUL terminated string for passphrase when PEM
 *                        encrypted. Not used.
 * @return  DH key on success.
 * @return  NULL on failure.
 */
WOLFSSL_DH *wolfSSL_PEM_read_bio_DHparams(WOLFSSL_BIO *bio, WOLFSSL_DH **dh,
    wc_pem_password_cb *cb, void *pass)
{
    WOLFSSL_DH* localDh = NULL;
    int err = 0;
    unsigned char* mem = NULL;
    int size = 0;
    int memAlloced = 0;

    WOLFSSL_ENTER("wolfSSL_PEM_read_bio_DHparams");

    (void)cb;
    (void)pass;

    /* Validate parameters. */
    if (bio == NULL) {
        WOLFSSL_ERROR_MSG("Bad Function Argument bio is NULL");
        err = 1;
    }

    /* Get buffer of data from BIO or read data from the BIO into a new buffer.
     */
    if ((!err) && (wolfssl_read_bio(bio, (char**)&mem, &size, &memAlloced)
            != 0)) {
        err = 1;
    }
    if (!err) {
        /* Create a DH key from the PEM - try two different headers. */
        localDh = wolfssl_dhparams_read_pem(dh, mem, size, memAlloced);
    }

    return localDh;
}

#endif /* !NO_BIO */

#ifndef NO_FILESYSTEM
/* Read DH parameters from a file pointer into DH key.
 *
 * DH parameters are public data and are not expected to be encrypted.
 *
 * @param [in]      fp    File pointer to read DH parameter file from.
 * @param [in, out] dh    DH key with parameters if not NULL. When pointer to
 *                        NULL, a new DH key is created.
 * @param [in]      cb    Password callback when PEM encrypted. Not used.
 * @param [in]      pass  NUL terminated string for passphrase when PEM
 *                        encrypted. Not used.
 *
 * @return  NULL on failure.
 * @return  DH key with parameters set on success.
 */
WOLFSSL_DH* wolfSSL_PEM_read_DHparams(XFILE fp, WOLFSSL_DH** dh,
    wc_pem_password_cb* cb, void* pass)
{
    WOLFSSL_DH* localDh = NULL;
    int err = 0;
    unsigned char* mem = NULL;
    int size = 0;

    (void)cb;
    (void)pass;

    /* Read data from file pointer. */
    if (wolfssl_read_file(fp, (char**)&mem, &size) != 0) {
        err = 1;
    }
    if (!err) {
        localDh = wolfssl_dhparams_read_pem(dh, mem, size, 1);
    }

    return localDh;
}
#endif /* !NO_FILESYSTEM */

#if defined(WOLFSSL_DH_EXTRA) && !defined(NO_FILESYSTEM)
/* Encoded parameter data in DH key as DER.
 *
 * @param [in, out] dh    DH key object to encode.
 * @param [out]     out   Buffer containing DER encoding.
 * @param [in]      heap  Heap hint.
 * @return  <0 on error.
 * @return  Length of DER encoded DH parameters in bytes.
 */
static int wolfssl_dhparams_to_der(WOLFSSL_DH* dh, unsigned char** out,
    void* heap)
{
    int ret = WC_NO_ERR_TRACE(WOLFSSL_FATAL_ERROR);
    int err = 0;
    byte* der = NULL;
    word32 derSz = 0;
    DhKey* key = NULL;

    (void)heap;

    /* Set internal parameters based on external parameters. */
    if ((dh->inSet == 0) && (SetDhInternal(dh) != 1)) {
        WOLFSSL_ERROR_MSG("Unable to set internal DH structure");
        err = 1;
    }
    if (!err) {
        /* Use wolfSSL API to get length of DER encode DH parameters. */
        key = (DhKey*)dh->internal;
        ret = wc_DhParamsToDer(key, NULL, &derSz);
        if (ret != WC_NO_ERR_TRACE(LENGTH_ONLY_E)) {
            WOLFSSL_ERROR_MSG("Failed to get size of DH params");
            err = 1;
        }
    }

    if (!err) {
        /* Allocate memory for DER encoding. */
        der = (byte*)XMALLOC(derSz, heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (der == NULL) {
            WOLFSSL_LEAVE("wolfssl_dhparams_to_der", MEMORY_E);
            err = 1;
        }
    }
    if (!err) {
        /* Encode DH parameters into DER buffer. */
        ret = wc_DhParamsToDer(key, der, &derSz);
        if (ret < 0) {
            WOLFSSL_ERROR_MSG("Failed to export DH params");
            err = 1;
        }
    }

    if (!err) {
        *out = der;
        der = NULL;
    }
    XFREE(der, heap, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}

/* Writes the DH parameters in PEM format from "dh" out to the file pointer
 * passed in.
 *
 * @param [in]  fp  File pointer to write to.
 * @param [in]  dh  DH key to write.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_PEM_write_DHparams(XFILE fp, WOLFSSL_DH* dh)
{
    int ret = 1;
    int derSz = 0;
    byte* derBuf = NULL;
    void* heap = NULL;

    WOLFSSL_ENTER("wolfSSL_PEM_write_DHparams");

    /* Validate parameters. */
    if ((fp == XBADFILE) || (dh == NULL)) {
        WOLFSSL_ERROR_MSG("Bad Function Arguments");
        ret = 0;
    }

    if (ret == 1) {
        DhKey* key = (DhKey*)dh->internal;
        if (key)
            heap = key->heap;
        if ((derSz = wolfssl_dhparams_to_der(dh, &derBuf, heap)) < 0) {
            WOLFSSL_ERROR_MSG("DER encoding failed");
            ret = 0;
        }
        if (derBuf == NULL) {
            WOLFSSL_ERROR_MSG("DER encoding failed to get buffer");
            ret = 0;
        }
    }
    if ((ret == 1) && (der_write_to_file_as_pem(derBuf, derSz, fp,
            DH_PARAM_TYPE, NULL) != 1)) {
        ret = 0;
    }

    /* Dispose of DER buffer. */
    XFREE(derBuf, heap, DYNAMIC_TYPE_TMP_BUFFER);

    WOLFSSL_LEAVE("wolfSSL_PEM_write_DHparams", ret);

    return ret;
}
#endif /* WOLFSSL_DH_EXTRA && !NO_FILESYSTEM */

#endif /* HAVE_LIGHTY || HAVE_STUNNEL || WOLFSSL_MYSQL_COMPATIBLE ||
        * OPENSSL_EXTRA */

/*
 * DH get/set APIs
 */

#ifdef OPENSSL_EXTRA

#if defined(WOLFSSL_QT) || defined(OPENSSL_ALL) \
    || defined(WOLFSSL_OPENSSH) || defined(OPENSSL_EXTRA)

/* Set the members of DhKey into WOLFSSL_DH
 * Specify elements to set via the 2nd parameter
 *
 * @param [in, out] dh   DH key to synchronize.
 * @param [in]      elm  Elements to synchronize.
 * @return  1 on success.
 * @return  -1 on failure.
 */
int SetDhExternal_ex(WOLFSSL_DH *dh, int elm)
{
    int ret = 1;
    DhKey *key = NULL;

    WOLFSSL_ENTER("SetDhExternal_ex");

    /* Validate parameters. */
    if ((dh == NULL) || (dh->internal == NULL)) {
        WOLFSSL_ERROR_MSG("dh key NULL error");
        ret = WOLFSSL_FATAL_ERROR;
    }

    if (ret == 1) {
        /* Get the wolfSSL DH key. */
        key = (DhKey*)dh->internal;
    }

    if ((ret == 1) && (elm & ELEMENT_P)) {
        /* Set the prime. */
        if (wolfssl_bn_set_value(&dh->p, &key->p) != 1) {
            WOLFSSL_ERROR_MSG("dh param p error");
            ret = WOLFSSL_FATAL_ERROR;
        }
    }
    if ((ret == 1) && (elm & ELEMENT_G)) {
        /* Set the generator. */
        if (wolfssl_bn_set_value(&dh->g, &key->g) != 1) {
            WOLFSSL_ERROR_MSG("dh param g error");
            ret = WOLFSSL_FATAL_ERROR;
        }
    }
    if ((ret == 1) && (elm & ELEMENT_Q)) {
        /* Set the order. */
        if (wolfssl_bn_set_value(&dh->q, &key->q) != 1) {
            WOLFSSL_ERROR_MSG("dh param q error");
            ret = WOLFSSL_FATAL_ERROR;
        }
    }
#ifdef WOLFSSL_DH_EXTRA
    if ((ret == 1) && (elm & ELEMENT_PRV)) {
        /* Set the private key. */
        if (wolfssl_bn_set_value(&dh->priv_key, &key->priv) != 1) {
            WOLFSSL_ERROR_MSG("No DH Private Key");
            ret = WOLFSSL_FATAL_ERROR;
        }
    }
    if ((ret == 1) && (elm & ELEMENT_PUB)) {
        /* Set the public key. */
        if (wolfssl_bn_set_value(&dh->pub_key, &key->pub) != 1) {
            WOLFSSL_ERROR_MSG("No DH Public Key");
            ret = WOLFSSL_FATAL_ERROR;
        }
    }
#endif /* WOLFSSL_DH_EXTRA */

    if (ret == 1) {
        /* On success record that the external values have been set. */
        dh->exSet = 1;
    }

    return ret;
}
/* Set the members of DhKey into WOLFSSL_DH
 * DhKey was populated from wc_DhKeyDecode
 * p, g, pub_key and priv_key are set.
 *
 * @param [in, out] dh   DH key to synchronize.
 * @return  1 on success.
 * @return  -1 on failure.
 */
int SetDhExternal(WOLFSSL_DH *dh)
{
    /* Assuming Q not required when using this API. */
    int elements = ELEMENT_P | ELEMENT_G | ELEMENT_PUB | ELEMENT_PRV;
    WOLFSSL_ENTER("SetDhExternal");
    return SetDhExternal_ex(dh, elements);
}
#endif /* WOLFSSL_QT || OPENSSL_ALL || WOLFSSL_OPENSSH || OPENSSL_EXTRA */

/* Set the internal/wolfSSL DH key with data from the external parts.
 *
 * @param [in, out] dh   DH key to synchronize.
 * @return  1 on success.
 * @return  -1 on failure.
 */
int SetDhInternal(WOLFSSL_DH* dh)
{
    int ret = 1;
    DhKey *key = NULL;

    WOLFSSL_ENTER("SetDhInternal");

    /* Validate parameters. */
    if ((dh == NULL) || (dh->p == NULL) || (dh->g == NULL)) {
        WOLFSSL_ERROR_MSG("Bad function arguments");
        ret = WOLFSSL_FATAL_ERROR;
    }
    if (ret == 1) {
        /* Get the wolfSSL DH key. */
        key = (DhKey*)dh->internal;

        /* Clear out key and initialize. */
        wc_FreeDhKey(key);
        if (wc_InitDhKey(key) != 0) {
            ret = WOLFSSL_FATAL_ERROR;
        }
    }
    if (ret == 1) {
        /* Transfer prime. */
        if (wolfssl_bn_get_value(dh->p, &key->p) != 1) {
            ret = WOLFSSL_FATAL_ERROR;
        }
    }
    if (ret == 1) {
        /* Transfer generator. */
        if (wolfssl_bn_get_value(dh->g, &key->g) != 1) {
            ret = WOLFSSL_FATAL_ERROR;
        }
    }
#ifdef HAVE_FFDHE_Q
    /* Transfer order if available. */
    if ((ret == 1) && (dh->q != NULL)) {
        if (wolfssl_bn_get_value(dh->q, &key->q) != 1) {
            ret = WOLFSSL_FATAL_ERROR;
        }
    }
#endif
#ifdef WOLFSSL_DH_EXTRA
    /* Transfer private key if available. */
    if ((ret == 1) && (dh->priv_key != NULL) &&
            (!wolfSSL_BN_is_zero(dh->priv_key))) {
        if (wolfssl_bn_get_value(dh->priv_key, &key->priv) != 1) {
            ret = WOLFSSL_FATAL_ERROR;
        }
    }
    /* Transfer public key if available. */
    if ((ret == 1) && (dh->pub_key != NULL) &&
            (!wolfSSL_BN_is_zero(dh->pub_key))) {
        if (wolfssl_bn_get_value(dh->pub_key, &key->pub) != 1) {
            ret = WOLFSSL_FATAL_ERROR;
        }
    }
#endif /* WOLFSSL_DH_EXTRA */

    if (ret == 1) {
        /* On success record that the internal values have been set. */
        dh->inSet = 1;
    }

    return ret;
}

/* Get the size, in bytes, of the DH key.
 *
 * Return code compliant with OpenSSL.
 *
 * @param [in] dh  DH key.
 * @return  -1 on error.
 * @return  Size of DH key in bytes on success.
 */
int wolfSSL_DH_size(WOLFSSL_DH* dh)
{
    WOLFSSL_ENTER("wolfSSL_DH_size");

    if (dh == NULL)
        return WOLFSSL_FATAL_ERROR;

    /* Validate parameter. */
    /* Size of key is size of prime in bytes. */
    return wolfSSL_BN_num_bytes(dh->p);
}

/**
 * Return parameters p, q and/or g of the DH key.
 *
 * @param [in]  dh  DH key to retrieve parameters from.
 * @param [out] p   Pointer to return prime in. May be NULL.
 * @param [out] q   Pointer to return order in. May be NULL.
 * @param [out] g   Pointer to return generator in. May be NULL.
 */
void wolfSSL_DH_get0_pqg(const WOLFSSL_DH *dh, const WOLFSSL_BIGNUM **p,
    const WOLFSSL_BIGNUM **q, const WOLFSSL_BIGNUM **g)
{
    WOLFSSL_ENTER("wolfSSL_DH_get0_pqg");

    if (dh != NULL) {
        /* Return prime if required. */
        if (p != NULL) {
            *p = dh->p;
        }
        /* Return order if required. */
        if (q != NULL) {
            *q = dh->q;
        }
        /* Return generator if required. */
        if (g != NULL) {
            *g = dh->g;
        }
    }
}

#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS) && !defined(WOLFSSL_DH_EXTRA)) \
 || (defined(HAVE_FIPS_VERSION) && FIPS_VERSION_GT(2,0))
#if defined(OPENSSL_ALL) || \
    defined(OPENSSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x10100000L
/* Sets the parameters p, g and optionally q into the DH key.
 *
 * Ownership of p, q and g get taken over by "dh" on success and should be
 * free'd with a call to wolfSSL_DH_free -- not individually.
 *
 * @param [in, out] dh   DH key to set.
 * @param [in]      p    Prime value to set. May be NULL when value already
 *                       present.
 * @param [in]      q    Order value to set. May be NULL.
 * @param [in]      g    Generator value to set. May be NULL when value already
 *                       present.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_DH_set0_pqg(WOLFSSL_DH *dh, WOLFSSL_BIGNUM *p,
    WOLFSSL_BIGNUM *q, WOLFSSL_BIGNUM *g)
{
    int ret = 1;

    WOLFSSL_ENTER("wolfSSL_DH_set0_pqg");

    /* Validate parameters - q is optional. */
    if (dh == NULL) {
        WOLFSSL_ERROR_MSG("Bad function arguments");
        ret = 0;
    }
    /* p can be NULL if we already have one set. */
    if ((ret == 1) && (p == NULL) && (dh->p == NULL)) {
        WOLFSSL_ERROR_MSG("Bad function arguments");
        ret = 0;
    }
    /* g can be NULL if we already have one set. */
    if ((ret == 1) && (g == NULL) && (dh->g == NULL)) {
        WOLFSSL_ERROR_MSG("Bad function arguments");
        ret = 0;
    }

    if (ret == 1) {
        /* Invalidate internal key. */
        dh->inSet = 0;

        /* Free external representation of parameters and set with those passed
         * in. */
        if (p != NULL) {
            wolfSSL_BN_free(dh->p);
            dh->p = p;
        }
        if (q != NULL) {
            wolfSSL_BN_free(dh->q);
            dh->q = q;
        }
        if (g != NULL) {
            wolfSSL_BN_free(dh->g);
            dh->g = g;
        }
        /* External DH key parameters were set. */
        dh->exSet = 1;

        /* Set internal/wolfSSL DH key as well. */
        if (SetDhInternal(dh) != 1) {
            WOLFSSL_ERROR_MSG("Unable to set internal DH key");
            /* Don't keep parameters on failure. */
            dh->p = NULL;
            dh->q = NULL;
            dh->g = NULL;
            /* Internal and external DH key not set. */
            dh->inSet = 0;
            dh->exSet = 0;
            ret = 0;
        }
    }

    return ret;
}

/* Set the length of the DH private key in bits.
 *
 * Length field is checked at generation.
 *
 * @param [in, out] dh   DH key to set.
 * @param [in]      len  Length of DH private key in bytes.
 * @return  0 on failure.
 * @return  1 on success.
 */
int wolfSSL_DH_set_length(WOLFSSL_DH *dh, long len)
{
    int ret = 1;

    WOLFSSL_ENTER("wolfSSL_DH_set_length");

    /* Validate parameter. */
    if (dh == NULL) {
        WOLFSSL_ERROR_MSG("Bad function arguments");
        ret = 0;
    }
    else {
        /* Store length. */
        dh->length = (int)len;
    }

    return ret;
}
#endif /* OPENSSL_ALL || (v1.1.0 or later) */
#endif

/* Get the public and private keys requested.
 *
 * @param [in]  dh         DH key to get keys from.
 * @param [out] pub_key    Pointer to return public key in. May be NULL.
 * @param [out] priv_key   Pointer to return private key in. May be NULL.
 */
void wolfSSL_DH_get0_key(const WOLFSSL_DH *dh, const WOLFSSL_BIGNUM **pub_key,
    const WOLFSSL_BIGNUM **priv_key)
{
    WOLFSSL_ENTER("wolfSSL_DH_get0_key");

    /* Get only when valid DH passed in. */
    if (dh != NULL) {
        /* Return public key if required and available. */
        if ((pub_key != NULL) && (dh->pub_key != NULL)) {
            *pub_key = dh->pub_key;
        }
        /* Return private key if required and available. */
        if ((priv_key != NULL) && (dh->priv_key != NULL)) {
            *priv_key = dh->priv_key;
        }
    }
}

/* Set the public and/or private key.
 *
 * @param [in, out] dh        DH key to have keys set into.
 * @param [in]      pub_key   Public key to set. May be NULL.
 * @param [in]      priv_key  Private key to set. May be NULL.
 * @return  0 on failure.
 * @return  1 on success.
 */
int wolfSSL_DH_set0_key(WOLFSSL_DH *dh, WOLFSSL_BIGNUM *pub_key,
    WOLFSSL_BIGNUM *priv_key)
{
    int ret = 1;
#ifdef WOLFSSL_DH_EXTRA
    DhKey *key = NULL;
#endif

    WOLFSSL_ENTER("wolfSSL_DH_set0_key");

    /* Validate parameters. */
    if (dh == NULL) {
        ret = 0;
    }
#ifdef WOLFSSL_DH_EXTRA
    else {
        key = (DhKey*)dh->internal;
    }
#endif

    /* Replace public key when one passed in. */
    if ((ret == 1) && (pub_key != NULL)) {
        wolfSSL_BN_free(dh->pub_key);
        dh->pub_key = pub_key;
    #ifdef WOLFSSL_DH_EXTRA
        if (wolfssl_bn_get_value(dh->pub_key, &key->pub) != 1) {
            ret = 0;
        }
    #endif
    }

    /* Replace private key when one passed in. */
    if ((ret == 1) && (priv_key != NULL)) {
        wolfSSL_BN_clear_free(dh->priv_key);
        dh->priv_key = priv_key;
    #ifdef WOLFSSL_DH_EXTRA
        if (wolfssl_bn_get_value(dh->priv_key, &key->priv) != 1) {
            ret = 0;
        }
    #endif
    }

    return ret;
}

#endif /* OPENSSL_EXTRA */

/*
 * DH check APIs
 */

#ifdef OPENSSL_EXTRA

#ifndef NO_CERTS

#ifdef OPENSSL_ALL
/* Check whether BN number is a prime.
 *
 * @param [in]  n        Number to check.
 * @param [out] isPrime  MP_YES when prime and MP_NO when not.
 * @return  1 on success.
 * @return  0 on error.
 */
static int wolfssl_dh_check_prime(WOLFSSL_BIGNUM* n, int* isPrime)
{
    int ret = 1;
    WC_DECLARE_VAR(tmpRng, WC_RNG, 1, 0);
    WC_RNG* rng;
    int localRng;

    /* Make an RNG with tmpRng or get global. */
    rng = wolfssl_make_rng(tmpRng, &localRng);
    if (rng == NULL) {
        ret = 0;
    }
    if (ret == 1) {
        mp_int* prime = (mp_int*)n->internal;

        if (mp_prime_is_prime_ex(prime, 8, isPrime, rng) != 0) {
            ret = 0;
        }
        /* Free local random number generator if created. */
        if (localRng) {
            wc_FreeRng(rng);
            WC_FREE_VAR_EX(rng, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
    }

    return ret;
}

/* Checks the Diffie-Hellman parameters.
 *
 * Checks that the generator and prime are available.
 * Checks that the prime is prime.
 * OpenSSL expects codes to be non-NULL.
 *
 * @param [in]  dh     DH key to check.
 * @param [out] codes  Codes of checks that failed.
 * @return  1 on success.
 * @return  0 when DH is NULL, there were errors or failed to create a random
 *          number generator.
 */
int wolfSSL_DH_check(const WOLFSSL_DH *dh, int *codes)
{
    int ret = 1;
    int errors = 0;

    WOLFSSL_ENTER("wolfSSL_DH_check");

    /* Validate parameters. */
    if (dh == NULL) {
        ret = 0;
    }

    /* Check generator available. */
    if ((ret == 1) && ((dh->g == NULL) || (dh->g->internal == NULL))) {
        errors |= DH_NOT_SUITABLE_GENERATOR;
    }

    if (ret == 1) {
        /* Check prime available. */
        if ((dh->p == NULL) || (dh->p->internal == NULL)) {
            errors |= DH_CHECK_P_NOT_PRIME;
        }
        else {
            /* Test if dh->p is prime. */
            int isPrime = MP_NO;
            ret = wolfssl_dh_check_prime(dh->p, &isPrime);
            /* Set error code if parameter p is not prime. */
            if ((ret == 1) && (isPrime != MP_YES)) {
                errors |= DH_CHECK_P_NOT_PRIME;
            }
        }
    }

    /* Return errors when user wants exact issues. */
    if (codes != NULL) {
        *codes = errors;
    }
    else if (errors) {
        ret = 0;
    }

    return ret;
}

#endif /* OPENSSL_ALL */

#endif /* !NO_CERTS */

#endif /* OPENSSL_EXTRA */

/*
 * DH generate APIs
 */

#if defined(OPENSSL_ALL) || (defined(OPENSSL_EXTRA) && \
    (defined(HAVE_STUNNEL) || defined(WOLFSSL_NGINX) || \
    defined(HAVE_LIGHTY) || defined(WOLFSSL_HAPROXY) || \
    defined(WOLFSSL_OPENSSH) || defined(HAVE_SBLIM_SFCB)))

#if defined(WOLFSSL_KEY_GEN) && !defined(HAVE_SELFTEST)
/* Generate DH parameters.
 *
 * @param [in] prime_len  Length of prime in bits.
 * @param [in] generator  Generator value to use.
 * @param [in] callback   Called with progress information. Unused.
 * @param [in] cb_arg     User callback argument. Unused.
 * @return  NULL on failure.
 * @return  DH key on success.
 */
WOLFSSL_DH *wolfSSL_DH_generate_parameters(int prime_len, int generator,
                           void (*callback) (int, int, void *), void *cb_arg)
{
    WOLFSSL_DH* dh = NULL;

    WOLFSSL_ENTER("wolfSSL_DH_generate_parameters");
    /* Not supported by wolfSSl APIs. */
    (void)callback;
    (void)cb_arg;

    /* Create an empty DH key. */
    if ((dh = wolfSSL_DH_new()) == NULL) {
        WOLFSSL_ERROR_MSG("wolfSSL_DH_new error");
    }
    /* Generate parameters into DH key. */
    else if (wolfSSL_DH_generate_parameters_ex(dh, prime_len, generator, NULL)
            != 1) {
        WOLFSSL_ERROR_MSG("wolfSSL_DH_generate_parameters_ex error");
        wolfSSL_DH_free(dh);
        dh = NULL;
    }

    return dh;
}

/* Generate DH parameters.
 *
 * @param [in] dh         DH key to generate parameters into.
 * @param [in] prime_len  Length of prime in bits.
 * @param [in] generator  Generator value to use.
 * @param [in] callback   Called with progress information. Unused.
 * @param [in] cb_arg     User callback argument. Unused.
 * @return  0 on failure.
 * @return  1 on success.
 */
int wolfSSL_DH_generate_parameters_ex(WOLFSSL_DH* dh, int prime_len,
    int generator, void (*callback) (int, int, void *))
{
    int ret = 1;
    DhKey* key = NULL;
    WC_DECLARE_VAR(tmpRng, WC_RNG, 1, 0);
    WC_RNG* rng = NULL;
    int localRng = 0;

    WOLFSSL_ENTER("wolfSSL_DH_generate_parameters_ex");
    /* Not supported by wolfSSL APIs. */
    (void)callback;
    (void)generator;

    /* Validate parameters. */
    if (dh == NULL) {
        WOLFSSL_ERROR_MSG("Bad parameter");
        ret = 0;
    }

    if (ret == 1) {
        /* Make an RNG with tmpRng or get global. */
        rng = wolfssl_make_rng(tmpRng, &localRng);
        if (rng == NULL) {
            WOLFSSL_ERROR_MSG("No RNG to use");
            ret = 0;
        }
    }

    if (ret == 1) {
        /* Get internal/wolfSSL DH key. */
        key = (DhKey*)dh->internal;

        /* Clear out data from internal DH key. */
        wc_FreeDhKey(key);
        /* Re-initialize internal DH key. */
        if (wc_InitDhKey(key) != 0) {
            ret = 0;
        }
    }
    if (ret == 1) {
        /* Generate parameters into internal DH key. */
        if (wc_DhGenerateParams(rng, prime_len, key) != 0) {
            WOLFSSL_ERROR_MSG("wc_DhGenerateParams error");
            ret = 0;
        }
    }

    /* Free local random number generator if created. */
    if (localRng) {
        wc_FreeRng(rng);
        WC_FREE_VAR_EX(rng, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    if (ret == 1) {
        /* Internal parameters set by generation. */
        dh->inSet = 1;

        WOLFSSL_MSG("wolfSSL does not support using a custom generator.");

        /* Synchronize the external to the internal parameters. */
        if (SetDhExternal(dh) != 1) {
            WOLFSSL_ERROR_MSG("SetDhExternal error");
            ret = 0;
        }
    }

    return ret;
}
#endif /* WOLFSSL_KEY_GEN && !HAVE_SELFTEST */

#endif /* OPENSSL_ALL || (OPENSSL_EXTRA && (HAVE_STUNNEL || WOLFSSL_NGINX ||
        * HAVE_LIGHTY || WOLFSSL_HAPROXY || WOLFSSL_OPENSSH ||
        * HAVE_SBLIM_SFCB)) */

#ifdef OPENSSL_EXTRA

#if !defined(HAVE_FIPS) || (defined(HAVE_FIPS) && !defined(WOLFSSL_DH_EXTRA)) \
 || (defined(HAVE_FIPS_VERSION) && FIPS_VERSION_GT(2,0))
/* Generate a public/private key pair base on parameters.
 *
 * @param [in, out] dh  DH key to generate keys into.
 * @return  1 on success.
 * @return  0 on error.
 */
int wolfSSL_DH_generate_key(WOLFSSL_DH* dh)
{
    int     ret    = 1;
    word32  pubSz  = 0;
    word32  privSz = 0;
    int     localRng = 0;
    WC_RNG* rng    = NULL;
    WC_DECLARE_VAR(tmpRng, WC_RNG, 1, 0);
    unsigned char* pub    = NULL;
    unsigned char* priv   = NULL;

    WOLFSSL_ENTER("wolfSSL_DH_generate_key");

    /* Validate parameters. */
    if ((dh == NULL) || (dh->p == NULL) || (dh->g == NULL)) {
        WOLFSSL_ERROR_MSG("Bad function arguments");
        ret = 0;
    }

    /* Synchronize the external and internal parameters. */
    if ((ret == 1) && (dh->inSet == 0) && (SetDhInternal(dh) != 1)) {
        WOLFSSL_ERROR_MSG("Bad DH set internal");
        ret = 0;
    }

    if (ret == 1) {
        /* Make a new RNG or use global. */
        rng = wolfssl_make_rng(tmpRng, &localRng);
        /* Check we have a random number generator. */
        if (rng == NULL) {
            ret = 0;
        }
    }

    if (ret == 1) {
        /* Get the size of the prime in bytes. */
        pubSz = (word32)wolfSSL_BN_num_bytes(dh->p);
        if (pubSz == 0) {
            WOLFSSL_ERROR_MSG("Prime parameter invalid");
            ret = 0;
        }
    }
    if (ret == 1) {
        /* Private key size can be as much as the size of the prime. */
        if (dh->length) {
            privSz = (word32)(dh->length / 8); /* to bytes */
            /* Special case where priv key is larger than dh->length / 8
             * See GeneratePrivateDh */
            if (dh->length == 128)
                privSz = 21;
        }
        else {
            privSz = pubSz;
        }
        /* Allocate public and private key arrays. */
        pub = (unsigned char*)XMALLOC(pubSz, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
        priv = (unsigned char*)XMALLOC(privSz, NULL, DYNAMIC_TYPE_PRIVATE_KEY);
        if (pub == NULL || priv == NULL) {
            WOLFSSL_ERROR_MSG("Unable to malloc memory");
            ret = 0;
        }
    }
    if (ret == 1) {
        /* Dispose of old public and private keys. */
        wolfSSL_BN_free(dh->pub_key);
        wolfSSL_BN_free(dh->priv_key);

        /* Allocate new public and private keys. */
        dh->pub_key = wolfSSL_BN_new();
        dh->priv_key = wolfSSL_BN_new();
        if (dh->pub_key == NULL) {
            WOLFSSL_ERROR_MSG("Bad DH new pub");
            ret = 0;
        }
        if (dh->priv_key == NULL) {
            WOLFSSL_ERROR_MSG("Bad DH new priv");
            ret = 0;
        }
    }

    PRIVATE_KEY_UNLOCK();
    /* Generate public and private keys into arrays. */
    if ((ret == 1) && (wc_DhGenerateKeyPair((DhKey*)dh->internal, rng, priv,
            &privSz, pub, &pubSz) < 0)) {
        WOLFSSL_ERROR_MSG("Bad wc_DhGenerateKeyPair");
        ret = 0;
    }
    /* Set public key from array. */
    if ((ret == 1) && (wolfSSL_BN_bin2bn(pub, (int)pubSz, dh->pub_key) ==
            NULL)) {
        WOLFSSL_ERROR_MSG("Bad DH bn2bin error pub");
        ret = 0;
    }
    /* Set private key from array. */
    if ((ret == 1) && (wolfSSL_BN_bin2bn(priv, (int)privSz, dh->priv_key) ==
            NULL)) {
        WOLFSSL_ERROR_MSG("Bad DH bn2bin error priv");
        ret = 0;
    }
    PRIVATE_KEY_LOCK();

    if (localRng) {
        /* Free an initialized local random number generator. */
        wc_FreeRng(rng);
        WC_FREE_VAR_EX(rng, NULL, DYNAMIC_TYPE_RNG);
    }
    /* Dispose of allocated data. */
    XFREE(pub,  NULL, DYNAMIC_TYPE_PUBLIC_KEY);
    XFREE(priv, NULL, DYNAMIC_TYPE_PRIVATE_KEY);

    return ret;
}


static int _DH_compute_key(unsigned char* key, const WOLFSSL_BIGNUM* otherPub,
    WOLFSSL_DH* dh, int ct)
{
    int            ret    = 0;
    word32         keySz  = 0;
    int            pubSz  = MAX_DHKEY_SZ;
    int            privSz = MAX_DHKEY_SZ;
    int            sz     = 0;
#ifdef WOLFSSL_SMALL_STACK
    unsigned char* pub    = NULL;
    unsigned char* priv   = NULL;
#else
    unsigned char  pub [MAX_DHKEY_SZ];
    unsigned char  priv[MAX_DHKEY_SZ];
#endif

    WOLFSSL_ENTER("wolfSSL_DH_compute_key");

    /* Validate parameters. */
    if ((dh == NULL) || (dh->priv_key == NULL) || (otherPub == NULL)) {
        WOLFSSL_ERROR_MSG("Bad function arguments");
        ret = WOLFSSL_FATAL_ERROR;
    }
    /* Get the maximum size of computed DH key. */
    if ((ret == 0) && ((keySz = (word32)wolfSSL_DH_size(dh)) == 0)) {
        WOLFSSL_ERROR_MSG("Bad DH_size");
        ret = WOLFSSL_FATAL_ERROR;
    }
    if (ret == 0) {
        /* Validate the size of the private key. */
        sz = wolfSSL_BN_num_bytes(dh->priv_key);
        if (sz > privSz) {
            WOLFSSL_ERROR_MSG("Bad priv internal size");
            ret = WOLFSSL_FATAL_ERROR;
        }
    }
    if (ret == 0) {
    #ifdef WOLFSSL_SMALL_STACK
        /* Keep real private key size to minimize amount allocated. */
        privSz = sz;
    #endif

        /* Validate the size of the public key. */
        sz = wolfSSL_BN_num_bytes(otherPub);
        if (sz > pubSz) {
            WOLFSSL_ERROR_MSG("Bad otherPub size");
            ret = WOLFSSL_FATAL_ERROR;
        }
    }

    if (ret == 0) {
    #ifdef WOLFSSL_SMALL_STACK
        /* Allocate memory for the public key array. */
        pub = (unsigned char*)XMALLOC((size_t)sz, NULL,
            DYNAMIC_TYPE_PUBLIC_KEY);
        if (pub == NULL)
            ret = WOLFSSL_FATAL_ERROR;
    }
    if (ret == 0) {
        /* Allocate memory for the private key array. */
        priv = (unsigned char*)XMALLOC((size_t)privSz, NULL,
            DYNAMIC_TYPE_PRIVATE_KEY);
        if (priv == NULL) {
            ret = WOLFSSL_FATAL_ERROR;
        }
    }
    if (ret == 0) {
    #endif
        /* Get the private key into the array. */
        privSz = wolfSSL_BN_bn2bin(dh->priv_key, priv);
        if (privSz <= 0) {
            ret = WOLFSSL_FATAL_ERROR;
        }
    }
    if (ret == 0) {
        /* Get the public key into the array. */
        pubSz  = wolfSSL_BN_bn2bin(otherPub, pub);
        if (pubSz <= 0) {
            ret = WOLFSSL_FATAL_ERROR;
        }
    }
    /* Synchronize the external into the internal parameters. */
    if ((ret == 0) && ((dh->inSet == 0) && (SetDhInternal(dh) != 1))) {
        WOLFSSL_ERROR_MSG("Bad DH set internal");
        ret = WOLFSSL_FATAL_ERROR;
    }

    PRIVATE_KEY_UNLOCK();
    /* Calculate shared secret from private and public keys. */
    if (ret == 0) {
        word32 padded_keySz = keySz;
#if (!defined(HAVE_FIPS) || FIPS_VERSION_GE(7,0)) && !defined(HAVE_SELFTEST)
        if (ct) {
            if (wc_DhAgree_ct((DhKey*)dh->internal, key, &keySz, priv,
                           (word32)privSz, pub, (word32)pubSz) < 0) {
                WOLFSSL_ERROR_MSG("wc_DhAgree_ct failed");
                ret = WOLFSSL_FATAL_ERROR;
            }
        }
        else
#endif /* (!HAVE_FIPS || FIPS_VERSION_GE(7,0)) && !HAVE_SELFTEST */
        {
            if (wc_DhAgree((DhKey*)dh->internal, key, &keySz, priv,
                           (word32)privSz, pub, (word32)pubSz) < 0) {
                WOLFSSL_ERROR_MSG("wc_DhAgree failed");
                ret = WOLFSSL_FATAL_ERROR;
            }
        }

        if ((ret == 0) && ct) {
            /* Arrange for correct fixed-length, right-justified key, even if
             * the crypto back end doesn't support it.  With some crypto back
             * ends this forgoes formal constant-timeness on the key agreement,
             * but assured that wolfSSL_DH_compute_key_padded() functions
             * correctly.
             */
            if (keySz < padded_keySz) {
                XMEMMOVE(key, key + (padded_keySz - keySz),
                         padded_keySz - keySz);
                XMEMSET(key, 0, padded_keySz - keySz);
                keySz = padded_keySz;
            }
        }
    }
    if (ret == 0) {
        /* Return actual length. */
        ret = (int)keySz;
    }
    PRIVATE_KEY_LOCK();

    if (privSz > 0) {
#ifdef WOLFSSL_SMALL_STACK
        if (priv != NULL)
#endif
        {
            /* Zeroize sensitive data. */
            ForceZero(priv, (word32)privSz);
        }
    }
    WC_FREE_VAR_EX(pub, NULL, DYNAMIC_TYPE_PUBLIC_KEY);
    WC_FREE_VAR_EX(priv, NULL, DYNAMIC_TYPE_PRIVATE_KEY);

    WOLFSSL_LEAVE("wolfSSL_DH_compute_key", ret);

    return ret;
}

/* Compute the shared key from the private key and peer's public key.
 *
 * Return code compliant with OpenSSL.
 * OpenSSL returns 0 when number of bits in p are smaller than minimum
 * supported.
 *
 * @param [out] key       Buffer to place shared key.
 * @param [in]  otherPub  Peer's public key.
 * @param [in]  dh        DH key containing private key.
 * @return  -1 on error.
 * @return  Size of shared secret in bytes on success.
 */
int wolfSSL_DH_compute_key(unsigned char* key, const WOLFSSL_BIGNUM* otherPub,
    WOLFSSL_DH* dh)
{
    return _DH_compute_key(key, otherPub, dh, 0);
}

/* Compute the shared key from the private key and peer's public key as in
 * wolfSSL_DH_compute_key, but using constant time processing, with an output
 * key length fixed at the nominal DH key size.  Leading zeros are retained.
 *
 * Return code compliant with OpenSSL.
 * OpenSSL returns 0 when number of bits in p are smaller than minimum
 * supported.
 *
 * @param [out] key       Buffer to place shared key.
 * @param [in]  otherPub  Peer's public key.
 * @param [in]  dh        DH key containing private key.
 * @return  -1 on error.
 * @return  Size of shared secret in bytes on success.
 */
int wolfSSL_DH_compute_key_padded(unsigned char* key,
    const WOLFSSL_BIGNUM* otherPub, WOLFSSL_DH* dh)
{
    return _DH_compute_key(key, otherPub, dh, 1);
}

#endif /* !HAVE_FIPS || (HAVE_FIPS && !WOLFSSL_DH_EXTRA) ||
        * HAVE_FIPS_VERSION > 2 */

#endif /* OPENSSL_EXTRA */

#endif /* NO_DH */

/*******************************************************************************
 * END OF DH API
 ******************************************************************************/


#define WOLFSSL_PK_EC_INCLUDED
#include "src/pk_ec.c"


/*******************************************************************************
 * START OF EC25519 API
 ******************************************************************************/

#if defined(OPENSSL_EXTRA) && defined(HAVE_CURVE25519)

/* Generate an EC25519 key pair.
 *
 * Output keys are in little endian format.
 *
 * @param [out]     priv    EC25519 private key data.
 * @param [in, out] privSz  On in, the size of priv in bytes.
 *                          On out, the length of the private key data in bytes.
 * @param [out]     pub     EC25519 public key data.
 * @param [in, out] pubSz   On in, the size of pub in bytes.
 *                          On out, the length of the public key data in bytes.
 * @return  1 on success
 * @return  0 on failure.
 */
int wolfSSL_EC25519_generate_key(unsigned char *priv, unsigned int *privSz,
    unsigned char *pub, unsigned int *pubSz)
{
#ifdef WOLFSSL_KEY_GEN
    int res = 1;
    int initTmpRng = 0;
    WC_RNG *rng = NULL;
    WC_DECLARE_VAR(tmpRng, WC_RNG, 1, 0);
    curve25519_key key;

    WOLFSSL_ENTER("wolfSSL_EC25519_generate_key");

    /* Validate parameters. */
    if ((priv == NULL) || (privSz == NULL) || (*privSz < CURVE25519_KEYSIZE) ||
            (pub == NULL) || (pubSz == NULL) || (*pubSz < CURVE25519_KEYSIZE)) {
        WOLFSSL_MSG("Bad arguments");
        res = 0;
    }

    if (res) {
        /* Create a random number generator. */
        rng = wolfssl_make_rng(tmpRng, &initTmpRng);
        if (rng == NULL) {
            WOLFSSL_MSG("wolfSSL_EC_KEY_generate_key failed to make RNG");
            res = 0;
        }
    }

    /* Initialize a Curve25519 key. */
    if (res && (wc_curve25519_init(&key) != 0)) {
        WOLFSSL_MSG("wc_curve25519_init failed");
        res = 0;
    }
    if (res) {
        /* Make a Curve25519 key pair. */
        int ret = wc_curve25519_make_key(rng, CURVE25519_KEYSIZE, &key);
        if (ret != MP_OKAY) {
            WOLFSSL_MSG("wc_curve25519_make_key failed");
            res = 0;
        }
        if (res) {
            /* Export Curve25519 key pair to buffers. */
            ret = wc_curve25519_export_key_raw_ex(&key, priv, privSz, pub,
                pubSz, EC25519_LITTLE_ENDIAN);
            if (ret != MP_OKAY) {
                WOLFSSL_MSG("wc_curve25519_export_key_raw_ex failed");
                res = 0;
            }
        }

        /* Dispose of key. */
        wc_curve25519_free(&key);
    }

    if (initTmpRng) {
        wc_FreeRng(rng);
        WC_FREE_VAR_EX(rng, NULL, DYNAMIC_TYPE_RNG);
    }

    return res;
#else
    WOLFSSL_MSG("No Key Gen built in");

    (void)priv;
    (void)privSz;
    (void)pub;
    (void)pubSz;

    return 0;
#endif /* WOLFSSL_KEY_GEN */
}

/* Compute a shared secret from private and public EC25519 keys.
 *
 * Input and output keys are in little endian format
 *
 * @param [out]     shared    Shared secret buffer.
 * @param [in, out] sharedSz  On in, the size of shared in bytes.
 *                            On out, the length of the secret in bytes.
 * @param [in]      priv      EC25519 private key data.
 * @param [in]      privSz    Length of the private key data in bytes.
 * @param [in]      pub       EC25519 public key data.
 * @param [in]      pubSz     Length of the public key data in bytes.
 * @return  1 on success
 * @return  0 on failure.
 */
int wolfSSL_EC25519_shared_key(unsigned char *shared, unsigned int *sharedSz,
    const unsigned char *priv, unsigned int privSz, const unsigned char *pub,
    unsigned int pubSz)
{
#ifdef WOLFSSL_KEY_GEN
    int res = 1;
    curve25519_key privkey;
    curve25519_key pubkey;

    WOLFSSL_ENTER("wolfSSL_EC25519_shared_key");

    /* Validate parameters. */
    if ((shared == NULL) || (sharedSz == NULL) ||
            (*sharedSz < CURVE25519_KEYSIZE) || (priv == NULL) ||
            (privSz < CURVE25519_KEYSIZE) || (pub == NULL) ||
            (pubSz < CURVE25519_KEYSIZE)) {
        WOLFSSL_MSG("Bad arguments");
        res = 0;
    }

    /* Initialize private key object. */
    if (res && (wc_curve25519_init(&privkey) != 0)) {
        WOLFSSL_MSG("wc_curve25519_init privkey failed");
        res = 0;
    }
    if (res) {
    #ifdef WOLFSSL_CURVE25519_BLINDING
        /* An RNG is needed. */
        if (wc_curve25519_set_rng(&privkey, wolfssl_make_global_rng()) != 0) {
            res = 0;
        }
        else
    #endif
        /* Initialize public key object. */
        if (wc_curve25519_init(&pubkey) != MP_OKAY) {
            WOLFSSL_MSG("wc_curve25519_init pubkey failed");
            res = 0;
        }
        if (res) {
            /* Import our private key. */
            int ret = wc_curve25519_import_private_ex(priv, privSz, &privkey,
                EC25519_LITTLE_ENDIAN);
            if (ret != 0) {
                WOLFSSL_MSG("wc_curve25519_import_private_ex failed");
                res = 0;
            }

            if (res) {
                /* Import peer's public key. */
                ret = wc_curve25519_import_public_ex(pub, pubSz, &pubkey,
                    EC25519_LITTLE_ENDIAN);
                if (ret != 0) {
                    WOLFSSL_MSG("wc_curve25519_import_public_ex failed");
                    res = 0;
                }
            }
            if (res) {
                /* Compute shared secret. */
                ret = wc_curve25519_shared_secret_ex(&privkey, &pubkey, shared,
                    sharedSz, EC25519_LITTLE_ENDIAN);
                if (ret != 0) {
                    WOLFSSL_MSG("wc_curve25519_shared_secret_ex failed");
                    res = 0;
                }
            }

            wc_curve25519_free(&pubkey);
        }
        wc_curve25519_free(&privkey);
    }

    return res;
#else
    WOLFSSL_MSG("No Key Gen built in");

    (void)shared;
    (void)sharedSz;
    (void)priv;
    (void)privSz;
    (void)pub;
    (void)pubSz;

    return 0;
#endif /* WOLFSSL_KEY_GEN */
}
#endif /* OPENSSL_EXTRA && HAVE_CURVE25519 */

/*******************************************************************************
 * END OF EC25519 API
 ******************************************************************************/

/*******************************************************************************
 * START OF ED25519 API
 ******************************************************************************/

#if defined(OPENSSL_EXTRA) && defined(HAVE_ED25519)
/* Generate an ED25519 key pair.
 *
 * Output keys are in little endian format.
 *
 * @param [out]     priv    ED25519 private key data.
 * @param [in, out] privSz  On in, the size of priv in bytes.
 *                          On out, the length of the private key data in bytes.
 * @param [out]     pub     ED25519 public key data.
 * @param [in, out] pubSz   On in, the size of pub in bytes.
 *                          On out, the length of the public key data in bytes.
 * @return  1 on success
 * @return  0 on failure.
 */
int wolfSSL_ED25519_generate_key(unsigned char *priv, unsigned int *privSz,
    unsigned char *pub, unsigned int *pubSz)
{
#if defined(WOLFSSL_KEY_GEN) && defined(HAVE_ED25519_KEY_EXPORT)
    int res = 1;
    int initTmpRng = 0;
    WC_RNG *rng = NULL;
    WC_DECLARE_VAR(tmpRng, WC_RNG, 1, 0);
    ed25519_key key;

    WOLFSSL_ENTER("wolfSSL_ED25519_generate_key");

    /* Validate parameters. */
    if ((priv == NULL) || (privSz == NULL) ||
            (*privSz < ED25519_PRV_KEY_SIZE) || (pub == NULL) ||
            (pubSz == NULL) || (*pubSz < ED25519_PUB_KEY_SIZE)) {
        WOLFSSL_MSG("Bad arguments");
        res = 0;
    }

    if (res) {
        /* Create a random number generator. */
        rng = wolfssl_make_rng(tmpRng, &initTmpRng);
        if (rng == NULL) {
            WOLFSSL_MSG("wolfSSL_EC_KEY_generate_key failed to make RNG");
            res = 0;
        }
    }

    /* Initialize an Ed25519 key. */
    if (res && (wc_ed25519_init(&key) != 0)) {
        WOLFSSL_MSG("wc_ed25519_init failed");
        res = 0;
    }
    if (res) {
        /* Make an Ed25519 key pair. */
        int ret = wc_ed25519_make_key(rng, ED25519_KEY_SIZE, &key);
        if (ret != 0) {
            WOLFSSL_MSG("wc_ed25519_make_key failed");
            res = 0;
        }
        if (res) {
            /* Export Curve25519 key pair to buffers. */
            ret = wc_ed25519_export_key(&key, priv, privSz, pub, pubSz);
            if (ret != 0) {
                WOLFSSL_MSG("wc_ed25519_export_key failed");
                res = 0;
            }
        }

        wc_ed25519_free(&key);
    }

    if (initTmpRng) {
        wc_FreeRng(rng);
        WC_FREE_VAR_EX(rng, NULL, DYNAMIC_TYPE_RNG);
    }

    return res;
#else
#ifndef WOLFSSL_KEY_GEN
    WOLFSSL_MSG("No Key Gen built in");
#else
    WOLFSSL_MSG("No ED25519 key export built in");
#endif

    (void)priv;
    (void)privSz;
    (void)pub;
    (void)pubSz;

    return 0;
#endif /* WOLFSSL_KEY_GEN && HAVE_ED25519_KEY_EXPORT */
}

/* Sign a message with Ed25519 using the private key.
 *
 * Input and output keys are in little endian format.
 * Priv is a buffer containing private and public part of key.
 *
 * @param [in]      msg     Message to be signed.
 * @param [in]      msgSz   Length of message in bytes.
 * @param [in]      priv    ED25519 private key data.
 * @param [in]      privSz  Length in bytes of private key data.
 * @param [out]     sig     Signature buffer.
 * @param [in, out] sigSz   On in, the length of the signature buffer in bytes.
 *                          On out, the length of the signature in bytes.
 * @return  1 on success
 * @return  0 on failure.
 */
int wolfSSL_ED25519_sign(const unsigned char *msg, unsigned int msgSz,
    const unsigned char *priv, unsigned int privSz, unsigned char *sig,
    unsigned int *sigSz)
{
#if defined(HAVE_ED25519_SIGN) && defined(WOLFSSL_KEY_GEN) && \
    defined(HAVE_ED25519_KEY_IMPORT)
    ed25519_key key;
    int res = 1;

    WOLFSSL_ENTER("wolfSSL_ED25519_sign");

    /* Validate parameters. */
    if ((priv == NULL) || (privSz != ED25519_PRV_KEY_SIZE) ||
            (msg == NULL) || (sig == NULL) || (sigSz == NULL) ||
            (*sigSz < ED25519_SIG_SIZE)) {
        WOLFSSL_MSG("Bad arguments");
        res = 0;
    }

    /* Initialize Ed25519 key. */
    if (res && (wc_ed25519_init(&key) != 0)) {
        WOLFSSL_MSG("wc_curve25519_init failed");
        res = 0;
    }
    if (res) {
        /* Import private and public key. */
        int ret = wc_ed25519_import_private_key(priv, privSz / 2,
            priv + (privSz / 2), ED25519_PUB_KEY_SIZE, &key);
        if (ret != 0) {
            WOLFSSL_MSG("wc_ed25519_import_private failed");
            res = 0;
        }

        if (res) {
            /* Sign message with Ed25519. */
            ret = wc_ed25519_sign_msg(msg, msgSz, sig, sigSz, &key);
            if (ret != 0) {
                WOLFSSL_MSG("wc_curve25519_shared_secret_ex failed");
                res = 0;
            }
        }

        wc_ed25519_free(&key);
    }

    return res;
#else
#if !defined(HAVE_ED25519_SIGN)
    WOLFSSL_MSG("No ED25519 sign built in");
#elif !defined(WOLFSSL_KEY_GEN)
    WOLFSSL_MSG("No Key Gen built in");
#elif !defined(HAVE_ED25519_KEY_IMPORT)
    WOLFSSL_MSG("No ED25519 Key import built in");
#endif

    (void)msg;
    (void)msgSz;
    (void)priv;
    (void)privSz;
    (void)sig;
    (void)sigSz;

    return 0;
#endif /* HAVE_ED25519_SIGN && WOLFSSL_KEY_GEN && HAVE_ED25519_KEY_IMPORT */
}

/* Verify a message with Ed25519 using the public key.
 *
 * Input keys are in little endian format.
 *
 * @param [in] msg     Message to be verified.
 * @param [in] msgSz   Length of message in bytes.
 * @param [in] pub     ED25519 public key data.
 * @param [in] privSz  Length in bytes of public key data.
 * @param [in] sig     Signature buffer.
 * @param [in] sigSz   Length of the signature in bytes.
 * @return  1 on success
 * @return  0 on failure.
 */
int wolfSSL_ED25519_verify(const unsigned char *msg, unsigned int msgSz,
    const unsigned char *pub, unsigned int pubSz, const unsigned char *sig,
    unsigned int sigSz)
{
#if defined(HAVE_ED25519_VERIFY) && defined(WOLFSSL_KEY_GEN) && \
    defined(HAVE_ED25519_KEY_IMPORT)
    ed25519_key key;
    int res = 1;

    WOLFSSL_ENTER("wolfSSL_ED25519_verify");

    /* Validate parameters. */
    if ((pub == NULL) || (pubSz != ED25519_PUB_KEY_SIZE) || (msg == NULL) ||
            (sig == NULL) || (sigSz != ED25519_SIG_SIZE)) {
        WOLFSSL_MSG("Bad arguments");
        res = 0;
    }

    /* Initialize Ed25519 key. */
    if (res && (wc_ed25519_init(&key) != 0)) {
        WOLFSSL_MSG("wc_curve25519_init failed");
        res = 0;
    }
    if (res) {
        /* Import public key. */
        int ret = wc_ed25519_import_public(pub, pubSz, &key);
        if (ret != 0) {
            WOLFSSL_MSG("wc_ed25519_import_public failed");
            res = 0;
        }

        if (res) {
            int check = 0;

            /* Verify signature with message and public key. */
            ret = wc_ed25519_verify_msg((byte*)sig, sigSz, msg, msgSz, &check,
                &key);
            /* Check for errors in verification process. */
            if (ret != 0) {
                WOLFSSL_MSG("wc_ed25519_verify_msg failed");
                res = 0;
            }
            /* Check signature is valid. */
            else if (!check) {
                WOLFSSL_MSG("wc_ed25519_verify_msg failed (signature invalid)");
                res = 0;
            }
        }

        wc_ed25519_free(&key);
    }

    return res;
#else
#if !defined(HAVE_ED25519_VERIFY)
    WOLFSSL_MSG("No ED25519 verify built in");
#elif !defined(WOLFSSL_KEY_GEN)
    WOLFSSL_MSG("No Key Gen built in");
#elif !defined(HAVE_ED25519_KEY_IMPORT)
    WOLFSSL_MSG("No ED25519 Key import built in");
#endif

    (void)msg;
    (void)msgSz;
    (void)pub;
    (void)pubSz;
    (void)sig;
    (void)sigSz;

    return 0;
#endif /* HAVE_ED25519_VERIFY && WOLFSSL_KEY_GEN && HAVE_ED25519_KEY_IMPORT */
}

#endif /* OPENSSL_EXTRA && HAVE_ED25519 */

/*******************************************************************************
 * END OF ED25519 API
 ******************************************************************************/

/*******************************************************************************
 * START OF EC448 API
 ******************************************************************************/

#if defined(OPENSSL_EXTRA) && defined(HAVE_CURVE448)
/* Generate an EC448 key pair.
 *
 * Output keys are in little endian format.
 *
 * @param [out]     priv    EC448 private key data.
 * @param [in, out] privSz  On in, the size of priv in bytes.
 *                          On out, the length of the private key data in bytes.
 * @param [out]     pub     EC448 public key data.
 * @param [in, out] pubSz   On in, the size of pub in bytes.
 *                          On out, the length of the public key data in bytes.
 * @return  1 on success
 * @return  0 on failure.
 */
int wolfSSL_EC448_generate_key(unsigned char *priv, unsigned int *privSz,
                               unsigned char *pub, unsigned int *pubSz)
{
#ifdef WOLFSSL_KEY_GEN
    int res = 1;
    int initTmpRng = 0;
    WC_RNG *rng = NULL;
    WC_DECLARE_VAR(tmpRng, WC_RNG, 1, 0);
    curve448_key key;

    WOLFSSL_ENTER("wolfSSL_EC448_generate_key");

    /* Validate parameters. */
    if ((priv == NULL) || (privSz == NULL) || (*privSz < CURVE448_KEY_SIZE) ||
            (pub == NULL) || (pubSz == NULL) || (*pubSz < CURVE448_KEY_SIZE)) {
        WOLFSSL_MSG("Bad arguments");
        res = 0;
    }

    if (res) {
        /* Create a random number generator. */
        rng = wolfssl_make_rng(tmpRng, &initTmpRng);
        if (rng == NULL) {
            WOLFSSL_MSG("wolfSSL_EC_KEY_generate_key failed to make RNG");
            res = 0;
        }
    }

    /* Initialize a Curve448 key. */
    if (res && (wc_curve448_init(&key) != 0)) {
        WOLFSSL_MSG("wc_curve448_init failed");
        res = 0;
    }
    if (res) {
        /* Make a Curve448 key pair. */
        int ret = wc_curve448_make_key(rng, CURVE448_KEY_SIZE, &key);
        if (ret != 0) {
            WOLFSSL_MSG("wc_curve448_make_key failed");
            res = 0;
        }
        if (res) {
            /* Export Curve448 key pair to buffers. */
            ret = wc_curve448_export_key_raw_ex(&key, priv, privSz, pub, pubSz,
                EC448_LITTLE_ENDIAN);
            if (ret != 0) {
                WOLFSSL_MSG("wc_curve448_export_key_raw_ex failed");
                res = 0;
            }
        }

        /* Dispose of key. */
        wc_curve448_free(&key);
    }

    if (initTmpRng) {
        wc_FreeRng(rng);
        WC_FREE_VAR_EX(rng, NULL, DYNAMIC_TYPE_RNG);
    }

    return res;
#else
    WOLFSSL_MSG("No Key Gen built in");

    (void)priv;
    (void)privSz;
    (void)pub;
    (void)pubSz;

    return 0;
#endif /* WOLFSSL_KEY_GEN */
}

/* Compute a shared secret from private and public EC448 keys.
 *
 * Input and output keys are in little endian format
 *
 * @param [out]     shared    Shared secret buffer.
 * @param [in, out] sharedSz  On in, the size of shared in bytes.
 *                            On out, the length of the secret in bytes.
 * @param [in]      priv      EC448 private key data.
 * @param [in]      privSz    Length of the private key data in bytes.
 * @param [in]      pub       EC448 public key data.
 * @param [in]      pubSz     Length of the public key data in bytes.
 * @return  1 on success
 * @return  0 on failure.
 */
int wolfSSL_EC448_shared_key(unsigned char *shared, unsigned int *sharedSz,
                             const unsigned char *priv, unsigned int privSz,
                             const unsigned char *pub, unsigned int pubSz)
{
#ifdef WOLFSSL_KEY_GEN
    int res = 1;
    curve448_key privkey;
    curve448_key pubkey;

    WOLFSSL_ENTER("wolfSSL_EC448_shared_key");

    /* Validate parameters. */
    if ((shared == NULL) || (sharedSz == NULL) ||
            (*sharedSz < CURVE448_KEY_SIZE) || (priv == NULL) ||
            (privSz < CURVE448_KEY_SIZE) || (pub == NULL) ||
            (pubSz < CURVE448_KEY_SIZE)) {
        WOLFSSL_MSG("Bad arguments");
        res = 0;
    }

    /* Initialize private key object. */
    if (res && (wc_curve448_init(&privkey) != 0)) {
        WOLFSSL_MSG("wc_curve448_init privkey failed");
        res = 0;
    }
    if (res) {
        /* Initialize public key object. */
        if (wc_curve448_init(&pubkey) != MP_OKAY) {
            WOLFSSL_MSG("wc_curve448_init pubkey failed");
            res = 0;
        }
        if (res) {
            /* Import our private key. */
            int ret = wc_curve448_import_private_ex(priv, privSz, &privkey,
                EC448_LITTLE_ENDIAN);
            if (ret != 0) {
                WOLFSSL_MSG("wc_curve448_import_private_ex failed");
                res = 0;
            }

            if (res) {
                /* Import peer's public key. */
                ret = wc_curve448_import_public_ex(pub, pubSz, &pubkey,
                    EC448_LITTLE_ENDIAN);
                if (ret != 0) {
                    WOLFSSL_MSG("wc_curve448_import_public_ex failed");
                    res = 0;
                }
            }
            if (res) {
                /* Compute shared secret. */
                ret = wc_curve448_shared_secret_ex(&privkey, &pubkey, shared,
                    sharedSz, EC448_LITTLE_ENDIAN);
                if (ret != 0) {
                    WOLFSSL_MSG("wc_curve448_shared_secret_ex failed");
                    res = 0;
                }
            }

            wc_curve448_free(&pubkey);
        }
        wc_curve448_free(&privkey);
    }

    return res;
#else
    WOLFSSL_MSG("No Key Gen built in");

    (void)shared;
    (void)sharedSz;
    (void)priv;
    (void)privSz;
    (void)pub;
    (void)pubSz;

    return 0;
#endif /* WOLFSSL_KEY_GEN */
}
#endif /* OPENSSL_EXTRA && HAVE_CURVE448 */

/*******************************************************************************
 * END OF EC448 API
 ******************************************************************************/

/*******************************************************************************
 * START OF ED448 API
 ******************************************************************************/

#if defined(OPENSSL_EXTRA) && defined(HAVE_ED448)
/* Generate an ED448 key pair.
 *
 * Output keys are in little endian format.
 *
 * @param [out]     priv    ED448 private key data.
 * @param [in, out] privSz  On in, the size of priv in bytes.
 *                          On out, the length of the private key data in bytes.
 * @param [out]     pub     ED448 public key data.
 * @param [in, out] pubSz   On in, the size of pub in bytes.
 *                          On out, the length of the public key data in bytes.
 * @return  1 on success
 * @return  0 on failure.
 */
int wolfSSL_ED448_generate_key(unsigned char *priv, unsigned int *privSz,
    unsigned char *pub, unsigned int *pubSz)
{
#if defined(WOLFSSL_KEY_GEN) && defined(HAVE_ED448_KEY_EXPORT)
    int res = 1;
    int initTmpRng = 0;
    WC_RNG *rng = NULL;
    WC_DECLARE_VAR(tmpRng, WC_RNG, 1, 0);
    ed448_key key;

    WOLFSSL_ENTER("wolfSSL_ED448_generate_key");

    /* Validate parameters. */
    if ((priv == NULL) || (privSz == NULL) ||
            (*privSz < ED448_PRV_KEY_SIZE) || (pub == NULL) ||
            (pubSz == NULL) || (*pubSz < ED448_PUB_KEY_SIZE)) {
        WOLFSSL_MSG("Bad arguments");
        res = 0;
    }

    if (res) {
        /* Create a random number generator. */
        rng = wolfssl_make_rng(tmpRng, &initTmpRng);
        if (rng == NULL) {
            WOLFSSL_MSG("wolfSSL_EC_KEY_generate_key failed to make RNG");
            res = 0;
        }
    }

    /* Initialize an Ed448 key. */
    if (res && (wc_ed448_init(&key) != 0)) {
        WOLFSSL_MSG("wc_ed448_init failed");
        res = 0;
    }
    if (res) {
        /* Make an Ed448 key pair. */
        int ret = wc_ed448_make_key(rng, ED448_KEY_SIZE, &key);
        if (ret != 0) {
            WOLFSSL_MSG("wc_ed448_make_key failed");
            res = 0;
        }
        if (res) {
            /* Export Curve448 key pair to buffers. */
            ret = wc_ed448_export_key(&key, priv, privSz, pub, pubSz);
            if (ret != 0) {
                WOLFSSL_MSG("wc_ed448_export_key failed");
                res = 0;
            }
        }

        wc_ed448_free(&key);
    }

    if (initTmpRng) {
        wc_FreeRng(rng);
        WC_FREE_VAR_EX(rng, NULL, DYNAMIC_TYPE_RNG);
    }

    return res;
#else
#ifndef WOLFSSL_KEY_GEN
    WOLFSSL_MSG("No Key Gen built in");
#else
    WOLFSSL_MSG("No ED448 key export built in");
#endif

    (void)priv;
    (void)privSz;
    (void)pub;
    (void)pubSz;

    return 0;
#endif /* WOLFSSL_KEY_GEN && HAVE_ED448_KEY_EXPORT */
}

/* Sign a message with Ed448 using the private key.
 *
 * Input and output keys are in little endian format.
 * Priv is a buffer containing private and public part of key.
 *
 * @param [in]      msg     Message to be signed.
 * @param [in]      msgSz   Length of message in bytes.
 * @param [in]      priv    ED448 private key data.
 * @param [in]      privSz  Length in bytes of private key data.
 * @param [out]     sig     Signature buffer.
 * @param [in, out] sigSz   On in, the length of the signature buffer in bytes.
 *                          On out, the length of the signature in bytes.
 * @return  1 on success
 * @return  0 on failure.
 */
int wolfSSL_ED448_sign(const unsigned char *msg, unsigned int msgSz,
    const unsigned char *priv, unsigned int privSz, unsigned char *sig,
    unsigned int *sigSz)
{
#if defined(HAVE_ED448_SIGN) && defined(WOLFSSL_KEY_GEN) && \
    defined(HAVE_ED448_KEY_IMPORT)
    ed448_key key;
    int res = 1;

    WOLFSSL_ENTER("wolfSSL_ED448_sign");

    /* Validate parameters. */
    if ((priv == NULL) || (privSz != ED448_PRV_KEY_SIZE) ||
            (msg == NULL) || (sig == NULL) || (sigSz == NULL) ||
            (*sigSz < ED448_SIG_SIZE)) {
        WOLFSSL_MSG("Bad arguments");
        res = 0;
    }

    /* Initialize Ed448 key. */
    if (res && (wc_ed448_init(&key) != 0)) {
        WOLFSSL_MSG("wc_curve448_init failed");
        res = 0;
    }
    if (res) {
        /* Import private and public key. */
        int ret = wc_ed448_import_private_key(priv, privSz / 2,
            priv + (privSz / 2), ED448_PUB_KEY_SIZE, &key);
        if (ret != 0) {
            WOLFSSL_MSG("wc_ed448_import_private failed");
            res = 0;
        }

        if (res) {
            /* Sign message with Ed448 - no context. */
            ret = wc_ed448_sign_msg(msg, msgSz, sig, sigSz, &key, NULL, 0);
            if (ret != 0) {
                WOLFSSL_MSG("wc_curve448_shared_secret_ex failed");
                res = 0;
            }
        }

        wc_ed448_free(&key);
    }

    return res;
#else
#if !defined(HAVE_ED448_SIGN)
    WOLFSSL_MSG("No ED448 sign built in");
#elif !defined(WOLFSSL_KEY_GEN)
    WOLFSSL_MSG("No Key Gen built in");
#elif !defined(HAVE_ED448_KEY_IMPORT)
    WOLFSSL_MSG("No ED448 Key import built in");
#endif

    (void)msg;
    (void)msgSz;
    (void)priv;
    (void)privSz;
    (void)sig;
    (void)sigSz;

    return 0;
#endif /* HAVE_ED448_SIGN && WOLFSSL_KEY_GEN && HAVE_ED448_KEY_IMPORT */
}

/* Verify a message with Ed448 using the public key.
 *
 * Input keys are in little endian format.
 *
 * @param [in] msg     Message to be verified.
 * @param [in] msgSz   Length of message in bytes.
 * @param [in] pub     ED448 public key data.
 * @param [in] privSz  Length in bytes of public key data.
 * @param [in] sig     Signature buffer.
 * @param [in] sigSz   Length of the signature in bytes.
 * @return  1 on success
 * @return  0 on failure.
 */
int wolfSSL_ED448_verify(const unsigned char *msg, unsigned int msgSz,
    const unsigned char *pub, unsigned int pubSz, const unsigned char *sig,
    unsigned int sigSz)
{
#if defined(HAVE_ED448_VERIFY) && defined(WOLFSSL_KEY_GEN) && \
    defined(HAVE_ED448_KEY_IMPORT)
    ed448_key key;
    int res = 1;

    WOLFSSL_ENTER("wolfSSL_ED448_verify");

    /* Validate parameters. */
    if ((pub == NULL) || (pubSz != ED448_PUB_KEY_SIZE) || (msg == NULL) ||
            (sig == NULL) || (sigSz != ED448_SIG_SIZE)) {
        WOLFSSL_MSG("Bad arguments");
        res = 0;
    }

    /* Initialize Ed448 key. */
    if (res && (wc_ed448_init(&key) != 0)) {
        WOLFSSL_MSG("wc_curve448_init failed");
        res = 0;
    }
    if (res) {
        /* Import public key. */
        int ret = wc_ed448_import_public(pub, pubSz, &key);
        if (ret != 0) {
            WOLFSSL_MSG("wc_ed448_import_public failed");
            res = 0;
        }

        if (res) {
            int check = 0;

            /* Verify signature with message and public key - no context. */
            ret = wc_ed448_verify_msg((byte*)sig, sigSz, msg, msgSz, &check,
                &key, NULL, 0);
            /* Check for errors in verification process. */
            if (ret != 0) {
                WOLFSSL_MSG("wc_ed448_verify_msg failed");
                res = 0;
            }
            /* Check signature is valid. */
            else if (!check) {
                WOLFSSL_MSG("wc_ed448_verify_msg failed (signature invalid)");
                res = 0;
            }
        }

        wc_ed448_free(&key);
    }

    return res;
#else
#if !defined(HAVE_ED448_VERIFY)
    WOLFSSL_MSG("No ED448 verify built in");
#elif !defined(WOLFSSL_KEY_GEN)
    WOLFSSL_MSG("No Key Gen built in");
#elif !defined(HAVE_ED448_KEY_IMPORT)
    WOLFSSL_MSG("No ED448 Key import built in");
#endif

    (void)msg;
    (void)msgSz;
    (void)pub;
    (void)pubSz;
    (void)sig;
    (void)sigSz;

    return 0;
#endif /* HAVE_ED448_VERIFY && WOLFSSL_KEY_GEN && HAVE_ED448_KEY_IMPORT */
}
#endif /* OPENSSL_EXTRA && HAVE_ED448 */

/*******************************************************************************
 * END OF ED448 API
 ******************************************************************************/

/*******************************************************************************
 * START OF GENERIC PUBLIC KEY PEM APIs
 ******************************************************************************/

#ifdef OPENSSL_EXTRA
/* Sets default callback password for PEM.
 *
 * @param [out] buf       Buffer to hold password.
 * @param [in]  num       Number of characters in buffer.
 * @param [in]  rwFlag    Read/write flag. Ignored.
 * @param [in]  userData  User data - assumed to be default password.
 * @return  Password size on success.
 * @return  0 on failure.
 */
int wolfSSL_PEM_def_callback(char* buf, int num, int rwFlag, void* userData)
{
    int sz = 0;

    WOLFSSL_ENTER("wolfSSL_PEM_def_callback");

    (void)rwFlag;

    /* We assume that the user passes a default password as userdata */
    if ((buf != NULL) && (userData != NULL)) {
        sz = (int)XSTRLEN((const char*)userData);
        sz = (int)min((word32)sz, (word32)num);
        XMEMCPY(buf, userData, (size_t)sz);
    }
    else {
        WOLFSSL_MSG("Error, default password cannot be created.");
    }

    return sz;
}

#ifndef NO_BIO
/* Writes a public key to a WOLFSSL_BIO encoded in PEM format.
 *
 * @param [in] bio  BIO to write to.
 * @param [in] key  Public key to write in PEM format.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_PEM_write_bio_PUBKEY(WOLFSSL_BIO* bio, WOLFSSL_EVP_PKEY* key)
{
    int ret = 0;

    WOLFSSL_ENTER("wolfSSL_PEM_write_bio_PUBKEY");

    if ((bio != NULL) && (key != NULL)) {
        switch (key->type) {
#if defined(WOLFSSL_KEY_GEN) && !defined(NO_RSA)
            case WC_EVP_PKEY_RSA:
                ret = wolfSSL_PEM_write_bio_RSA_PUBKEY(bio, key->rsa);
                break;
#endif /* WOLFSSL_KEY_GEN && !NO_RSA */
#if !defined(NO_DSA) && !defined(HAVE_SELFTEST) && \
    (defined(WOLFSSL_KEY_GEN) || defined(WOLFSSL_CERT_GEN))
            case WC_EVP_PKEY_DSA:
                ret = wolfSSL_PEM_write_bio_DSA_PUBKEY(bio, key->dsa);
                break;
#endif /* !NO_DSA && !HAVE_SELFTEST && (WOLFSSL_KEY_GEN || WOLFSSL_CERT_GEN) */
#if defined(HAVE_ECC) && defined(HAVE_ECC_KEY_EXPORT) && \
    defined(WOLFSSL_KEY_GEN)
            case WC_EVP_PKEY_EC:
                ret = wolfSSL_PEM_write_bio_EC_PUBKEY(bio, key->ecc);
                break;
#endif /* HAVE_ECC && HAVE_ECC_KEY_EXPORT */
#if !defined(NO_DH) && (defined(WOLFSSL_QT) || defined(OPENSSL_ALL))
            case WC_EVP_PKEY_DH:
                /* DH public key not supported. */
                WOLFSSL_MSG("Writing DH PUBKEY not supported!");
                break;
#endif /* !NO_DH && (WOLFSSL_QT || OPENSSL_ALL) */
            default:
                /* Key type not supported. */
                WOLFSSL_MSG("Unknown Key type!");
                break;
        }
    }

    return ret;
}

/* Writes a private key to a WOLFSSL_BIO encoded in PEM format.
 *
 * @param [in] bio     BIO to write to.
 * @param [in] key     Public key to write in PEM format.
 * @param [in] cipher  Encryption cipher to use.
 * @param [in] passwd  Password to use when encrypting.
 * @param [in] len     Length of password.
 * @param [in] cb      Password callback.
 * @param [in] arg     Password callback argument.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_PEM_write_bio_PrivateKey(WOLFSSL_BIO* bio, WOLFSSL_EVP_PKEY* key,
    const WOLFSSL_EVP_CIPHER* cipher, unsigned char* passwd, int len,
    wc_pem_password_cb* cb, void* arg)
{
    int ret = 1;

    WOLFSSL_ENTER("wolfSSL_PEM_write_bio_PrivateKey");

    (void)cipher;
    (void)passwd;
    (void)len;
    (void)cb;
    (void)arg;

    /* Validate parameters. */
    if ((bio == NULL) || (key == NULL)) {
        WOLFSSL_MSG("Bad Function Arguments");
        ret = 0;
    }

    if (ret == 1) {
    #ifdef WOLFSSL_KEY_GEN
        switch (key->type) {
        #ifndef NO_RSA
            case WC_EVP_PKEY_RSA:
                /* Write using RSA specific API. */
                ret = wolfSSL_PEM_write_bio_RSAPrivateKey(bio, key->rsa,
                    cipher, passwd, len, cb, arg);
                break;
        #endif
        #ifndef NO_DSA
            case WC_EVP_PKEY_DSA:
                /* Write using DSA specific API. */
                ret = wolfSSL_PEM_write_bio_DSAPrivateKey(bio, key->dsa,
                    cipher, passwd, len, cb, arg);
                break;
        #endif
        #ifdef HAVE_ECC
            case WC_EVP_PKEY_EC:
            #if defined(HAVE_ECC_KEY_EXPORT)
                /* Write using EC specific API. */
                ret = wolfSSL_PEM_write_bio_ECPrivateKey(bio, key->ecc,
                    cipher, passwd, len, cb, arg);
            #else
                ret = der_write_to_bio_as_pem((byte*)key->pkey.ptr,
                    key->pkey_sz, bio, EC_PRIVATEKEY_TYPE);
            #endif
                break;
        #endif
        #ifndef NO_DH
            case WC_EVP_PKEY_DH:
                /* Write using generic API with DH type. */
                ret = der_write_to_bio_as_pem((byte*)key->pkey.ptr,
                    key->pkey_sz, bio, DH_PRIVATEKEY_TYPE);
                break;
        #endif
            default:
                WOLFSSL_MSG("Unknown Key type!");
                ret = 0;
                break;
        }
    #else
        int type = 0;

        switch (key->type) {
        #ifndef NO_DSA
            case WC_EVP_PKEY_DSA:
                type = DSA_PRIVATEKEY_TYPE;
                break;
        #endif
        #ifdef HAVE_ECC
            case WC_EVP_PKEY_EC:
                type = ECC_PRIVATEKEY_TYPE;
                break;
        #endif
        #ifndef NO_DH
            case WC_EVP_PKEY_DH:
                type = DH_PRIVATEKEY_TYPE;
                break;
        #endif
        #ifndef NO_RSA
            case WC_EVP_PKEY_RSA:
                type = PRIVATEKEY_TYPE;
                break;
        #endif
            default:
                ret = 0;
                break;
        }
        if (ret == 1) {
            /* Write using generic API with generic type. */
            ret = der_write_to_bio_as_pem((byte*)key->pkey.ptr, key->pkey_sz,
                bio, type);
        }
    #endif
    }

    return ret;
}
#endif /* !NO_BIO */

#ifndef NO_BIO
/* Create a private key object from the data in the BIO.
 *
 * @param [in]      bio   BIO to read from.
 * @param [in, out] key   Public key object. Object used if passed in.
 * @param [in]      cb    Password callback.
 * @param [in]      arg   Password callback argument.
 * @return  A WOLFSSL_EVP_PKEY object on success.
 * @return  NULL on failure.
 */
WOLFSSL_EVP_PKEY* wolfSSL_PEM_read_bio_PUBKEY(WOLFSSL_BIO* bio,
    WOLFSSL_EVP_PKEY **key, wc_pem_password_cb *cb, void *arg)
{
    int err = 0;
    WOLFSSL_EVP_PKEY* pkey = NULL;
    DerBuffer* der = NULL;

    WOLFSSL_ENTER("wolfSSL_PEM_read_bio_PUBKEY");

    if (bio == NULL) {
        err = 1;
    }

    /* Read the PEM public key from the BIO and convert to DER. */
    if ((!err) && (pem_read_bio_key(bio, cb, arg, PUBLICKEY_TYPE, NULL,
            &der) < 0)) {
        err = 1;
    }

    if (!err) {
        const unsigned char* ptr = der->buffer;

        /* Use key passed in if set. */
        if ((key != NULL) && (*key != NULL)) {
            pkey = *key;
        }

        /* Convert DER data to a public key object. */
        if (wolfSSL_d2i_PUBKEY(&pkey, &ptr, der->length) == NULL) {
            WOLFSSL_MSG("Error loading DER buffer into WOLFSSL_EVP_PKEY");
            pkey = NULL;
            err = 1;
        }
    }

    /* Return the key if possible. */
    if ((!err) && (key != NULL) && (pkey != NULL)) {
        *key = pkey;
    }
    /* Dispose of the DER encoding. */
    FreeDer(&der);

    WOLFSSL_LEAVE("wolfSSL_PEM_read_bio_PUBKEY", 0);

    return pkey;
}

/* Create a private key object from the data in the BIO.
 *
 * @param [in]      bio   BIO to read from.
 * @param [in, out] key   Private key object. Object used if passed in.
 * @param [in]      cb    Password callback.
 * @param [in]      arg   Password callback argument.
 * @return  A WOLFSSL_EVP_PKEY object on success.
 * @return  NULL on failure.
 */
WOLFSSL_EVP_PKEY* wolfSSL_PEM_read_bio_PrivateKey(WOLFSSL_BIO* bio,
    WOLFSSL_EVP_PKEY** key, wc_pem_password_cb* cb, void* arg)
{
    int err = 0;
    WOLFSSL_EVP_PKEY* pkey = NULL;
    DerBuffer* der = NULL;
    int keyFormat = 0;

    WOLFSSL_ENTER("wolfSSL_PEM_read_bio_PrivateKey");

    /* Validate parameters. */
    if (bio == NULL) {
        err = 1;
    }

    /* Read the PEM private key from the BIO and convert to DER. */
    if ((!err) && (pem_read_bio_key(bio, cb, arg, PRIVATEKEY_TYPE, &keyFormat,
            &der) < 0)) {
        err = 1;
    }

    if (!err) {
        const unsigned char* ptr = der->buffer;
        int type;

        /* Set key type based on format returned. */
        switch (keyFormat) {
            /* No key format set - default to RSA. */
            case 0:
            case RSAk:
                type = WC_EVP_PKEY_RSA;
                break;
            case DSAk:
                type = WC_EVP_PKEY_DSA;
                break;
            case ECDSAk:
                type = WC_EVP_PKEY_EC;
                break;
            case DHk:
                type = WC_EVP_PKEY_DH;
                break;
            default:
                type = WOLFSSL_FATAL_ERROR;
                break;
        }

        /* Use key passed in if set. */
        if ((key != NULL) && (*key != NULL)) {
            pkey = *key;
        }

        /* Convert DER data to a private key object. */
        if (wolfSSL_d2i_PrivateKey(type, &pkey, &ptr, der->length) == NULL) {
            WOLFSSL_MSG("Error loading DER buffer into WOLFSSL_EVP_PKEY");
            pkey = NULL;
            err = 1;
        }
    }

    /* Return the key if possible. */
    if ((!err) && (key != NULL) && (pkey != NULL)) {
        *key = pkey;
    }
    /* Dispose of the DER encoding. */
    FreeDer(&der);

    WOLFSSL_LEAVE("wolfSSL_PEM_read_bio_PrivateKey", err);

    return pkey;
}


WOLFSSL_PKCS8_PRIV_KEY_INFO* wolfSSL_PEM_read_bio_PKCS8_PRIV_KEY_INFO(
    WOLFSSL_BIO* bio, WOLFSSL_PKCS8_PRIV_KEY_INFO** key, wc_pem_password_cb* cb,
    void* arg)
{
    return wolfSSL_PEM_read_bio_PrivateKey(bio, key, cb, arg);
}
#endif /* !NO_BIO */

#if !defined(NO_FILESYSTEM)
/* Create a private key object from the data in a file.
 *
 * @param [in]      fp    File pointer.
 * @param [in, out] key   Public key object. Object used if passed in.
 * @param [in]      cb    Password callback.
 * @param [in]      arg   Password callback argument.
 * @return  A WOLFSSL_EVP_PKEY object on success.
 * @return  NULL on failure.
 */
WOLFSSL_EVP_PKEY *wolfSSL_PEM_read_PUBKEY(XFILE fp, WOLFSSL_EVP_PKEY **key,
    wc_pem_password_cb *cb, void *arg)
{
    int err = 0;
    WOLFSSL_EVP_PKEY* pkey = NULL;
    DerBuffer* der = NULL;

    WOLFSSL_ENTER("wolfSSL_PEM_read_PUBKEY");

    /* Validate parameters. */
    if (fp == XBADFILE) {
        err = 1;
    }

    /* Read the PEM public key from the file and convert to DER. */
    if ((!err) && ((pem_read_file_key(fp, cb, arg, PUBLICKEY_TYPE, NULL,
            &der) < 0) || (der == NULL))) {
        err = 1;
    }
    if (!err) {
        const unsigned char* ptr = der->buffer;

        /* Use key passed in if set. */
        if ((key != NULL) && (*key != NULL)) {
            pkey = *key;
        }

        /* Convert DER data to a public key object. */
        if (wolfSSL_d2i_PUBKEY(&pkey, &ptr, der->length) == NULL) {
            WOLFSSL_MSG("Error loading DER buffer into WOLFSSL_EVP_PKEY");
            pkey = NULL;
            err = 1;
        }
    }

    /* Return the key if possible. */
    if ((!err) && (key != NULL) && (pkey != NULL)) {
        *key = pkey;
    }
    /* Dispose of the DER encoding. */
    FreeDer(&der);

    WOLFSSL_LEAVE("wolfSSL_PEM_read_PUBKEY", 0);

    return pkey;
}

#ifndef NO_CERTS
/* Create a private key object from the data in a file.
 *
 * @param [in]      fp    File pointer.
 * @param [in, out] key   Private key object. Object used if passed in.
 * @param [in]      cb    Password callback.
 * @param [in]      arg   Password callback argument.
 * @return  A WOLFSSL_EVP_PKEY object on success.
 * @return  NULL on failure.
 */
WOLFSSL_EVP_PKEY* wolfSSL_PEM_read_PrivateKey(XFILE fp, WOLFSSL_EVP_PKEY **key,
    wc_pem_password_cb *cb, void *arg)
{
    int err = 0;
    WOLFSSL_EVP_PKEY* pkey = NULL;
    DerBuffer* der = NULL;
    int keyFormat = 0;

    WOLFSSL_ENTER("wolfSSL_PEM_read_PrivateKey");

    /* Validate parameters. */
    if (fp == XBADFILE) {
        err = 1;
    }

    /* Read the PEM private key from the file and convert to DER. */
    if ((!err) && (pem_read_file_key(fp, cb, arg, PRIVATEKEY_TYPE, &keyFormat,
            &der)) < 0) {
        err = 1;
    }

    if (!err) {
        const unsigned char* ptr = der->buffer;
        int type;

        /* Set key type based on format returned. */
        switch (keyFormat) {
            /* No key format set - default to RSA. */
            case 0:
            case RSAk:
                type = WC_EVP_PKEY_RSA;
                break;
            case DSAk:
                type = WC_EVP_PKEY_DSA;
                break;
            case ECDSAk:
                type = WC_EVP_PKEY_EC;
                break;
            case DHk:
                type = WC_EVP_PKEY_DH;
                break;
            default:
                type = WOLFSSL_FATAL_ERROR;
                break;
        }

        /* Use key passed in if set. */
        if ((key != NULL) && (*key != NULL)) {
            pkey = *key;
        }

        /* Convert DER data to a private key object. */
        if (wolfSSL_d2i_PrivateKey(type, &pkey, &ptr, der->length) == NULL) {
            WOLFSSL_MSG("Error loading DER buffer into WOLFSSL_EVP_PKEY");
            pkey = NULL;
            err = 1;
        }
    }

    /* Return the key if possible. */
    if ((!err) && (key != NULL) && (pkey != NULL)) {
        *key = pkey;
    }
    /* Dispose of the DER encoding. */
    FreeDer(&der);

    WOLFSSL_LEAVE("wolfSSL_PEM_read_PrivateKey", 0);

    return pkey;
}
#endif /* !NO_CERTS */
#endif /* !NO_FILESYSTEM */

#ifndef NO_CERTS

#if !defined(NO_BIO) || !defined(NO_FILESYSTEM)
#define PEM_BEGIN              "-----BEGIN "
#define PEM_BEGIN_SZ           11
#define PEM_END                "-----END "
#define PEM_END_SZ             9
#define PEM_HDR_FIN            "-----"
#define PEM_HDR_FIN_SZ         5
#define PEM_HDR_FIN_EOL_NEWLINE   "-----\n"
#define PEM_HDR_FIN_EOL_NULL_TERM "-----\0"
#define PEM_HDR_FIN_EOL_SZ     6

/* Find strings and return middle offsets.
 *
 * Find first string in pem as a prefix and then locate second string as a
 * postfix.
 * len returning with 0 indicates not found.
 *
 * @param [in]  pem      PEM data.
 * @param [in]  pemLen   Length of PEM data.
 * @param [in]  idx      Current index.
 * @param [in]  prefix   First string to find.
 * @param [in]  postfix  Second string to find after first.
 * @param [out] start    Start index of data between strings.
 * @param [out] len      Length of data between strings.
 */
static void pem_find_pattern(char* pem, int pemLen, int idx, const char* prefix,
    const char* postfix, int* start, int* len)
{
    int prefixLen = (int)XSTRLEN(prefix);
    int postfixLen = (int)XSTRLEN(postfix);

    *start = *len = 0;
    /* Find prefix part. */
    for (; idx < pemLen - prefixLen; idx++) {
        if ((pem[idx] == prefix[0]) &&
                (XMEMCMP(pem + idx, prefix, (size_t)prefixLen) == 0)) {
            idx += prefixLen;
            *start = idx;
            break;
        }
    }
    /* Find postfix part. */
    for (; idx < pemLen - postfixLen; idx++) {
        if ((pem[idx] == postfix[0]) &&
                (XMEMCMP(pem + idx, postfix, (size_t)postfixLen) == 0)) {
            *len = idx - *start;
            break;
        }
    }
}

/* Parse out content type name, any encryption headers and DER encoding.
 *
 * @param [in]  pem     PEM data.
 * @param [in]  pemLen  Length of PEM data.
 * @param [out] name    Name of content type.
 * @param [out] header  Encryption headers.
 * @param [out] data    DER encoding from PEM.
 * @param [out] len     Length of DER data.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation fails.
 * @return  ASN_NO_PEM_HEADER when no header found or different names found.
 */
static int pem_read_data(char* pem, int pemLen, char **name, char **header,
    unsigned char **data, long *len)
{
    int ret = 0;
    int start;
    int nameLen;
    int startHdr = 0;
    int hdrLen = 0;
    int startEnd = 0;
    int endLen;

    *name = NULL;
    *header = NULL;

    /* Find header. */
    pem_find_pattern(pem, pemLen, 0, PEM_BEGIN, PEM_HDR_FIN, &start, &nameLen);
    /* Allocate memory for header name. */
    *name = (char*)XMALLOC((size_t)nameLen + 1, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (*name == NULL) {
        ret = MEMORY_E;
    }
    if (ret == 0) {
        /* Put in header name. */
        (*name)[nameLen] = '\0';
        if (nameLen == 0) {
            ret = ASN_NO_PEM_HEADER;
        }
        else {
            XMEMCPY(*name, pem + start, (size_t)nameLen);
        }
    }
    if (ret == 0) {
        /* Find encryption headers after header. */
        start += nameLen + PEM_HDR_FIN_SZ;
        pem_find_pattern(pem, pemLen, start, "\n", "\n\n", &startHdr, &hdrLen);
        if (hdrLen > 0) {
            /* Include first of two '\n' characters. */
            hdrLen++;
        }
        /* Allocate memory for encryption header string. */
        *header = (char*)XMALLOC((size_t)hdrLen + 1, NULL,
                                    DYNAMIC_TYPE_TMP_BUFFER);
        if (*header == NULL) {
            ret = MEMORY_E;
        }
    }
    if (ret == 0) {
        /* Put in encryption header string. */
        (*header)[hdrLen] = '\0';
        if (hdrLen > 0) {
            XMEMCPY(*header, pem + startHdr, (size_t)hdrLen);
            start = startHdr + hdrLen + 1;
        }

        /* Find footer. */
        pem_find_pattern(pem, pemLen, start, PEM_END, PEM_HDR_FIN, &startEnd,
            &endLen);
        /* Validate header name and footer name are the same. */
        if ((endLen != nameLen) ||
                 (XMEMCMP(*name, pem + startEnd, (size_t)nameLen) != 0)) {
            ret = ASN_NO_PEM_HEADER;
        }
    }
    if (ret == 0) {
        unsigned char* der = (unsigned char*)pem;
        word32 derLen;

        /* Convert PEM body to DER. */
        derLen = (word32)(startEnd - PEM_END_SZ - start);
        ret = Base64_Decode(der + start, derLen, der, &derLen);
        if (ret == 0) {
            /* Return the DER data. */
            *data = der;
            *len = derLen;
        }
    }

    return ret;
}

/* Encode the DER data in PEM format into a newly allocated buffer.
 *
 * @param [in]  name       Header/footer name.
 * @param [in]  header     Encryption header.
 * @param [in]  data       DER data.
 * @param [in]  len        Length of DER data.
 * @param [out] pemOut     PEM encoded data.
 * @param [out] pemOutLen  Length of PEM encoded data.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation fails.
 */
static int pem_write_data(const char *name, const char *header,
    const unsigned char *data, long len, char** pemOut, word32* pemOutLen)
{
    int ret = 0;
    int nameLen;
    int headerLen;
    char* pem = NULL;
    word32 pemLen;
    word32 derLen = (word32)len;
    byte* p;

    nameLen = (int)XSTRLEN(name);
    headerLen = (int)XSTRLEN(header);

    /* DER encode for PEM. */
    pemLen  = (derLen + 2) / 3 * 4;
    pemLen += (pemLen + 63) / 64;
    /* Header */
    pemLen += (word32)(PEM_BEGIN_SZ + nameLen + PEM_HDR_FIN_EOL_SZ);
    if (headerLen > 0) {
        /* Encryption lines plus extra carriage return. */
        pemLen += (word32)headerLen + 1;
    }
    /* Trailer */
    pemLen += (word32)(PEM_END_SZ + nameLen + PEM_HDR_FIN_EOL_SZ);

    pem = (char*)XMALLOC(pemLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (pem == NULL) {
        ret = MEMORY_E;
    }
    p = (byte*)pem;

    if (ret == 0) {
        /* Add header. */
        XMEMCPY(p, PEM_BEGIN, PEM_BEGIN_SZ);
        p += PEM_BEGIN_SZ;
        XMEMCPY(p, name, (size_t)nameLen);
        p += nameLen;
        XMEMCPY(p, PEM_HDR_FIN_EOL_NEWLINE, PEM_HDR_FIN_EOL_SZ);
        p += PEM_HDR_FIN_EOL_SZ;

        if (headerLen > 0) {
            /* Add encryption header. */
            XMEMCPY(p, header, (size_t)headerLen);
            p += headerLen;
            /* Blank line after a header and before body. */
            *(p++) = '\n';
        }

        /* Add DER data as PEM. */
        pemLen -= (word32)((size_t)p - (size_t)pem);
        ret = Base64_Encode(data, derLen, p, &pemLen);
    }
    if (ret == 0) {
        p += pemLen;

        /* Add trailer. */
        XMEMCPY(p, PEM_END, PEM_END_SZ);
        p += PEM_END_SZ;
        XMEMCPY(p, name, (size_t)nameLen);
        p += nameLen;
        XMEMCPY(p, PEM_HDR_FIN_EOL_NEWLINE, PEM_HDR_FIN_EOL_SZ);
        p += PEM_HDR_FIN_EOL_SZ;

        /* Return buffer and length of data. */
        *pemOut = pem;
        *pemOutLen = (word32)((size_t)p - (size_t)pem);
    }
    else {
        /* Dispose of any allocated memory. */
        XFREE(pem, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        pem = NULL;
    }

    return ret;
}
#endif /* !NO_BIO || !NO_FILESYSTEM */

#ifndef NO_BIO
/* Read PEM encoded data from a BIO.
 *
 * Reads the entire contents in.
 *
 * @param [in]  bio     BIO to read from.
 * @param [out] name    Name of content type.
 * @param [out] header  Encryption headers.
 * @param [out] data    DER encoding from PEM.
 * @param [out] len     Length of DER data.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_PEM_read_bio(WOLFSSL_BIO* bio, char **name, char **header,
    unsigned char **data, long *len)
{
    int res = 1;
    char* pem = NULL;
    int pemLen = 0;
    int memAlloced = 1;

    /* Validate parameters. */
    if ((bio == NULL) || (name == NULL) || (header == NULL) || (data == NULL) ||
            (len == NULL)) {
        res = 0;
    }

    /* Load all the data from the BIO. */
    if ((res == 1) && (wolfssl_read_bio(bio, &pem, &pemLen, &memAlloced) !=
             0)) {
        res = 0;
    }
    if ((res == 1) && (!memAlloced)) {
        /* Need to return allocated memory - make sure it is allocated. */
        char* p = (char*)XMALLOC((size_t)pemLen, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (p == NULL) {
            res = 0;
        }
        else {
            /* Copy the data into new buffer. */
            XMEMCPY(p, pem, (size_t)pemLen);
            pem = p;
        }
    }

    /* Read the PEM data. */
    if ((res == 1) && (pem_read_data(pem, pemLen, name, header, data, len) !=
            0)) {
        /* Dispose of any allocated memory. */
        XFREE(pem, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(*name, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(*header, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        *name = NULL;
        *header = NULL;
        res = 0;
    }

    return res;
}

/* Encode the DER data in PEM format into a BIO.
 *
 * @param [in] bio     BIO to write to.
 * @param [in] name    Header/footer name.
 * @param [in] header  Encryption header.
 * @param [in] data    DER data.
 * @param [in] len     Length of DER data.
 * @return  0 on failure.
 */
int wolfSSL_PEM_write_bio(WOLFSSL_BIO* bio, const char *name,
    const char *header, const unsigned char *data, long len)
{
    int err = 0;
    char* pem = NULL;
    word32 pemLen = 0;

    /* Validate parameters. */
    if ((bio == NULL) || (name == NULL) || (header == NULL) || (data == NULL)) {
        err = BAD_FUNC_ARG;
    }

    /* Encode into a buffer. */
    if (!err) {
        err = pem_write_data(name, header, data, len, &pem, &pemLen);
    }

    /* Write PEM into BIO. */
    if ((!err) && (wolfSSL_BIO_write(bio, pem, (int)pemLen) != (int)pemLen)) {
        err = IO_FAILED_E;
    }

    XFREE(pem, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return (!err) ? (int)pemLen : 0;
}
#endif /* !NO_BIO */

#if !defined(NO_FILESYSTEM)
/* Read PEM encoded data from a file.
 *
 * Reads the entire contents in.
 *
 * @param [in]  bio     BIO to read from.
 * @param [out] name    Name of content type.
 * @param [out] header  Encryption headers.
 * @param [out] data    DER encoding from PEM.
 * @param [out] len     Length of DER data.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_PEM_read(XFILE fp, char **name, char **header, unsigned char **data,
    long *len)
{
    int res = 1;
    char* pem = NULL;
    int pemLen = 0;

    /* Validate parameters. */
    if ((fp == XBADFILE) || (name == NULL) || (header == NULL) ||
            (data == NULL) || (len == NULL)) {
        res = 0;
    }

    /* Load all the data from the file. */
    if ((res == 1) && (wolfssl_read_file(fp, &pem, &pemLen) != 0)) {
        res = 0;
    }

    /* Read the PEM data. */
    if ((res == 1) && (pem_read_data(pem, pemLen, name, header, data, len) !=
            0)) {
        /* Dispose of any allocated memory. */
        XFREE(pem, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(*name, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(*header, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        *name = NULL;
        *header = NULL;
        res = 0;
    }

    return res;
}

/* Encode the DER data in PEM format into a file.
 *
 * @param [in] fp      File pointer to write to.
 * @param [in] name    Header/footer name.
 * @param [in] header  Encryption header.
 * @param [in] data    DER data.
 * @param [in] len     Length of DER data.
 * @return  0 on success.
 * @return  MEMORY_E when dynamic memory allocation fails.
 */
int wolfSSL_PEM_write(XFILE fp, const char *name, const char *header,
    const unsigned char *data, long len)
{
    int err = 0;
    char* pem = NULL;
    word32 pemLen = 0;

    /* Validate parameters. */
    if ((fp == XBADFILE) || (name == NULL) || (header == NULL) ||
            (data == NULL)) {
        err = 1;
    }

    /* Encode into a buffer. */
    if ((!err) && (pem_write_data(name, header, data, len, &pem, &pemLen) !=
            0)) {
        pemLen = 0;
        err = 1;
    }

    /* Write PEM to a file. */
    if ((!err) && (XFWRITE(pem, 1, pemLen, fp) != pemLen)) {
        pemLen = 0;
    }

    XFREE(pem, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return (int)pemLen;
}
#endif

/* Get EVP cipher info from encryption header string.
 *
 * @param [in]  header  Encryption header.
 * @param [out] cipher  EVP Cipher info.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_PEM_get_EVP_CIPHER_INFO(const char* header, EncryptedInfo* cipher)
{
    int res = 1;

    /* Validate parameters. */
    if ((header == NULL) || (cipher == NULL)) {
        res = 0;
    }

    if (res == 1) {
        XMEMSET(cipher, 0, sizeof(*cipher));

        if (wc_EncryptedInfoParse(cipher, &header, XSTRLEN(header)) != 0) {
            res = 0;
        }
    }

    return res;
}

/* Apply cipher to DER data.
 *
 * @param [in]      cipher  EVP cipher info.
 * @param [in, out] data    On in, encrypted DER data.
 *                          On out, unencrypted DER data.
 * @param [in, out] len     On in, length of encrypted DER data.
 *                          On out, length of unencrypted DER data.
 * @param [in]      cb      Password callback.
 * @param [in]      ctx     Context for password callback.
 * @return  1 on success.
 * @return  0 on failure.
 */
int wolfSSL_PEM_do_header(EncryptedInfo* cipher, unsigned char* data, long* len,
    wc_pem_password_cb* cb, void* ctx)
{
    int ret = 1;
    char password[NAME_SZ];
    int passwordSz = 0;

    /* Validate parameters. */
    if ((cipher == NULL) || (data == NULL) || (len == NULL) || (cb == NULL)) {
        ret = 0;
    }

    if (ret == 1) {
        /* Get password and length. */
        passwordSz = cb(password, sizeof(password), PEM_PASS_READ, ctx);
        if (passwordSz < 0) {
            ret = 0;
        }
    }

    if (ret == 1) {
        /* Decrypt the data using password and MD5. */
        if (wc_BufferKeyDecrypt(cipher, data, (word32)*len, (byte*)password,
                passwordSz, WC_MD5) != 0) {
            ret = WOLFSSL_FAILURE;
        }
    }

    if (passwordSz > 0) {
        /* Ensure password is erased from memory. */
        ForceZero(password, (word32)passwordSz);
    }

    return ret;
}

#endif /* !NO_CERTS */
#endif /* OPENSSL_EXTRA */

#ifdef OPENSSL_ALL
#if !defined(NO_PWDBASED) && defined(HAVE_PKCS8)

/* Encrypt the key into a buffer using PKCS$8 and a password.
 *
 * @param [in]      pkey      Private key to encrypt.
 * @param [in]      enc       EVP cipher.
 * @param [in]      passwd    Password to encrypt with.
 * @param [in]      passwdSz  Number of bytes in password.
 * @param [in]      key       Buffer to hold encrypted key.
 * @param [in, out] keySz     On in, size of buffer in bytes.
 *                            On out, size of encrypted key in bytes.
 * @return  0 on success.
 * @return  BAD_FUNC_ARG when EVP cipher not supported.
 */
int pkcs8_encrypt(WOLFSSL_EVP_PKEY* pkey,
    const WOLFSSL_EVP_CIPHER* enc, char* passwd, int passwdSz, byte* key,
    word32* keySz)
{
    int ret;
    WC_RNG rng;

    /* Initialize a new random number generator. */
    ret = wc_InitRng(&rng);
    if (ret == 0) {
        int encAlgId = 0;

        /* Convert EVP cipher to a support encryption id. */
    #ifndef NO_DES3
        if (enc == EVP_DES_CBC) {
            encAlgId = DESb;
        }
        else if (enc == EVP_DES_EDE3_CBC) {
            encAlgId = DES3b;
        }
        else
    #endif
#if !defined(NO_AES) && defined(HAVE_AES_CBC)
    #ifdef WOLFSSL_AES_128
        if (enc == EVP_AES_128_CBC) {
            encAlgId = AES128CBCb;
        }
        else
     #endif
    #ifdef WOLFSSL_AES_256
        if (enc == EVP_AES_256_CBC) {
            encAlgId = AES256CBCb;
        }
        else
     #endif
#endif
        {
            ret = BAD_FUNC_ARG;
        }

        if (ret == 0) {
            /* Encrypt private into buffer. */
            ret = TraditionalEnc((byte*)pkey->pkey.ptr + pkey->pkcs8HeaderSz,
                (word32)pkey->pkey_sz - pkey->pkcs8HeaderSz,
                key, keySz, passwd, passwdSz, PKCS5, PBES2, encAlgId,
                NULL, 0, WC_PKCS12_ITT_DEFAULT, &rng, NULL);
            if (ret > 0) {
                *keySz = (word32)ret;
            }
        }
        /* Dispose of random number generator. */
        wc_FreeRng(&rng);
    }

    return ret;
}

/* Encode private key in PKCS#8 format.
 *
 * @param [in]      pkey   Private key.
 * @param [out]     key    Buffer to hold encoding.
 * @param [in, out] keySz  On in, size of buffer in bytes.
 * @param                  On out, size of encoded key in bytes.
 * @return  0 on success.
 */
int pkcs8_encode(WOLFSSL_EVP_PKEY* pkey, byte* key, word32* keySz)
{
    int ret = 0;
    int algId = 0;
    const byte* curveOid = 0;
    word32 oidSz = 0;

    /* Get the details of the private key. */
#ifdef HAVE_ECC
    if (pkey->type == WC_EVP_PKEY_EC) {
        /* ECC private and get curve OID information. */
        algId = ECDSAk;
        ret = wc_ecc_get_oid((word32)pkey->ecc->group->curve_oid, &curveOid,
            &oidSz);
    }
    else
#endif
    if (pkey->type == WC_EVP_PKEY_RSA) {
        /* RSA private has no curve information. */
        algId = RSAk;
        curveOid = NULL;
        oidSz = 0;
    }
    else if (pkey->type == WC_EVP_PKEY_DSA) {
        /* DSA has no curve information. */
        algId = DSAk;
        curveOid = NULL;
        oidSz = 0;
    }
#ifndef NO_DH
    else if (pkey->type == WC_EVP_PKEY_DH) {
        if (pkey->dh == NULL)
            return BAD_FUNC_ARG;

        if (pkey->dh->priv_key != NULL || pkey->dh->pub_key != NULL) {
            /* Special case. DH buffer is always in PKCS8 format */
            if (keySz == NULL)
                return BAD_FUNC_ARG;

            *keySz = (word32)pkey->pkey_sz;
            if (key == NULL)
                return LENGTH_ONLY_E;

            XMEMCPY(key, pkey->pkey.ptr, pkey->pkey_sz);
            return pkey->pkey_sz;
        }

        /* DH has no curve information. */
        algId = DHk;
        curveOid = NULL;
        oidSz = 0;
    }
#endif
    else {
        ret = NOT_COMPILED_IN;
    }

    if (ret >= 0) {
        /* Encode private key in PKCS#8 format. */
        ret = wc_CreatePKCS8Key(key, keySz, (byte*)pkey->pkey.ptr +
            pkey->pkcs8HeaderSz, (word32)pkey->pkey_sz - pkey->pkcs8HeaderSz,
            algId, curveOid, oidSz);
    }

    return ret;
}

#if !defined(NO_BIO) || (!defined(NO_FILESYSTEM) && \
    !defined(NO_STDIO_FILESYSTEM))
/* Write PEM encoded, PKCS#8 formatted private key to BIO.
 *
 * @param [out] pem       Buffer holding PEM encoding.
 * @param [out] pemSz     Size of data in buffer in bytes.
 * @param [in]  pkey      Private key to write.
 * @param [in]  enc       Encryption information to use. May be NULL.
 * @param [in]  passwd    Password to use when encrypting. May be NULL.
 * @param [in]  passwdSz  Size of password in bytes.
 * @param [in]  cb        Password callback. Used when passwd is NULL. May be
 *                        NULL.
 * @param [in]  ctx       Context for password callback.
 * @return  Length of PEM encoding on success.
 * @return  0 on failure.
 */
static int pem_write_mem_pkcs8privatekey(byte** pem, int* pemSz,
    WOLFSSL_EVP_PKEY* pkey, const WOLFSSL_EVP_CIPHER* enc, char* passwd,
    int passwdSz, wc_pem_password_cb* cb, void* ctx)
{
    int res = 1;
    int ret = 0;
    char password[NAME_SZ];
    byte* key = NULL;
    word32 keySz = 0;
    int type = PKCS8_PRIVATEKEY_TYPE;

    /* Validate parameters. */
    if (pkey == NULL) {
        res = 0;
    }

    if (res == 1) {
        /* Guestimate key size and PEM size. */
        if (pkcs8_encode(pkey, NULL, &keySz) !=
                WC_NO_ERR_TRACE(LENGTH_ONLY_E)) {
            res = 0;
        }
    }
    if (res == 1) {
        if (enc != NULL) {
            /* Add on enough for extra DER data when encrypting. */
            keySz += 128;
        }
        /* PEM encoding size from DER size. */
        *pemSz  = (int)(keySz + 2) / 3 * 4;
        *pemSz += (*pemSz + 63) / 64;
        /* Header and footer. */
        if (enc != NULL) {
            /* Name is: 'ENCRYPTED PRIVATE KEY'. */
            *pemSz += 74;
        }
        else {
            /* Name is: 'PRIVATE KEY'. */
            *pemSz += 54;
        }

        /* Allocate enough memory to hold PEM encoded encrypted key. */
        *pem = (byte*)XMALLOC((size_t)*pemSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (*pem == NULL) {
            res = 0;
        }
        else {
            /* Use end of PEM buffer for key data. */
            key = *pem + *pemSz - keySz;
        }
    }

    if ((res == 1) && (enc != NULL)) {
        /* Set type for PEM. */
        type = PKCS8_ENC_PRIVATEKEY_TYPE;

        if (passwd == NULL) {
            /* Get the password by using callback. */
            passwdSz = cb(password, sizeof(password), 1, ctx);
            if (passwdSz < 0) {
                res = 0;
            }
            passwd = password;
        }

        if (res == 1) {
            /* Encrypt the private key. */
            ret = pkcs8_encrypt(pkey, enc, passwd, passwdSz, key, &keySz);
            if (ret <= 0) {
                res = 0;
            }
        }

        /* Zeroize the password from memory. */
        if ((password == passwd) && (passwdSz > 0)) {
            ForceZero(password, (word32)passwdSz);
        }
    }
    else if ((res == 1) && (enc == NULL)) {
        /* Set type for PEM. */
        type = PKCS8_PRIVATEKEY_TYPE;

        /* Encode private key in PKCS#8 format. */
        ret = pkcs8_encode(pkey, key, &keySz);
        if (ret < 0) {
            res = 0;
        }
    }

    if (res == 1) {
        /* Encode PKCS#8 formatted key to PEM. */
        ret = wc_DerToPemEx(key, keySz, *pem, (word32)*pemSz, NULL, type);
        if (ret < 0) {
            res = 0;
        }
        else {
            *pemSz = ret;
        }
    }

    /* Return appropriate return code. */
    return (res == 0) ? 0 : ret;

}
#endif /* !NO_BIO || (!NO_FILESYSTEM && !NO_STDIO_FILESYSTEM) */

#ifndef NO_BIO
/* Write PEM encoded, PKCS#8 formatted private key to BIO.
 *
 * TODO: OpenSSL returns 1 and 0 only.
 *
 * @param [in] bio       BIO to write to.
 * @param [in] pkey      Private key to write.
 * @param [in] enc       Encryption information to use. May be NULL.
 * @param [in] passwd    Password to use when encrypting. May be NULL.
 * @param [in] passwdSz  Size of password in bytes.
 * @param [in] cb        Password callback. Used when passwd is NULL. May be
 *                       NULL.
 * @param [in] ctx       Context for password callback.
 * @return  Length of PEM encoding on success.
 * @return  0 on failure.
 */
int wolfSSL_PEM_write_bio_PKCS8PrivateKey(WOLFSSL_BIO* bio,
    WOLFSSL_EVP_PKEY* pkey, const WOLFSSL_EVP_CIPHER* enc, char* passwd,
    int passwdSz, wc_pem_password_cb* cb, void* ctx)
{
    byte* pem = NULL;
    int pemSz = 0;
    int res = 1;

    /* Validate parameters. */
    if (bio == NULL) {
        res = 0;
    }
    if (res == 1) {
        /* Write private key to memory. */
        res = pem_write_mem_pkcs8privatekey(&pem, &pemSz, pkey, enc, passwd,
            passwdSz, cb, ctx);
    }

    /* Write encoded key to BIO. */
    if ((res >= 1) && (wolfSSL_BIO_write(bio, pem, pemSz) != pemSz)) {
        res = 0;
    }

    /* Dispose of dynamically allocated memory (pem and key). */
    XFREE(pem, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return res;
}

int wolfSSL_PEM_write_bio_PKCS8_PRIV_KEY_INFO(WOLFSSL_BIO* bio,
        PKCS8_PRIV_KEY_INFO* keyInfo)
{
    return wolfSSL_PEM_write_bio_PKCS8PrivateKey(bio, keyInfo, NULL, NULL, 0,
            NULL, NULL);
}
#endif /* !NO_BIO */

#if !defined(NO_FILESYSTEM) && !defined(NO_STDIO_FILESYSTEM)
/* Write PEM encoded, PKCS#8 formatted private key to BIO.
 *
 * TODO: OpenSSL returns 1 and 0 only.
 *
 * @param [in] f         File pointer.
 * @param [in] pkey      Private key to write.
 * @param [in] enc       Encryption information to use. May be NULL.
 * @param [in] passwd    Password to use when encrypting. May be NULL.
 * @param [in] passwdSz  Size of password in bytes.
 * @param [in] cb        Password callback. Used when passwd is NULL. May be
 *                       NULL.
 * @param [in] ctx       Context for password callback.
 * @return  Length of PEM encoding on success.
 * @return  0 on failure.
 */
int wolfSSL_PEM_write_PKCS8PrivateKey(XFILE f, WOLFSSL_EVP_PKEY* pkey,
    const WOLFSSL_EVP_CIPHER* enc, char* passwd, int passwdSz,
    wc_pem_password_cb* cb, void* ctx)
{
    byte* pem = NULL;
    int pemSz = 0;
    int res = 1;

    /* Validate parameters. */
    if (f == XBADFILE) {
        res = 0;
    }
    if (res == 1) {
        /* Write private key to memory. */
        res = pem_write_mem_pkcs8privatekey(&pem, &pemSz, pkey, enc, passwd,
            passwdSz, cb, ctx);
    }

    /* Write encoded key to file. */
    if ((res >= 1) && (XFWRITE(pem, 1, (size_t)pemSz, f) != (size_t)pemSz)) {
        res = 0;
    }

    /* Dispose of dynamically allocated memory (pem and key). */
    XFREE(pem, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return res;
}
#endif /* !NO_FILESYSTEM && !NO_STDIO_FILESYSTEM */

#endif /* !NO_PWDBASED && HAVE_PKCS8 */
#endif /* OPENSSL_ALL */

/*******************************************************************************
 * END OF GENERIC PUBLIC KEY PEM APIs
 ******************************************************************************/

#endif /* !WOLFSSL_PK_INCLUDED */
