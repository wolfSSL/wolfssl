/* clu_pkey_setup.c
 *
 * Copyright (C) 2006-2021 wolfSSL Inc.
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

#include <wolfclu/wolfclu/clu_header_main.h>
#include <wolfclu/wolfclu/clu_log.h>
#include <wolfclu/wolfclu/clu_optargs.h>
#include <wolfclu/wolfclu/pkey/clu_pkey.h>
#include <wolfclu/wolfclu/genkey/clu_genkey.h>
#include <wolfclu/wolfclu/x509/clu_cert.h>
#include <wolfclu/wolfclu/x509/clu_parse.h>

#ifndef WOLFCLU_NO_FILESYSTEM

static const struct option pkey_options[] = {
    {"-in",        required_argument, 0, WOLFCLU_INFILE    },
    {"-out",       required_argument, 0, WOLFCLU_OUTFILE   },
    {"-inform",    required_argument, 0, WOLFCLU_INFORM    },
    {"-outform",   required_argument, 0, WOLFCLU_OUTFORM   },
    {"-pubout",    no_argument,       0, WOLFCLU_PUBOUT    },
    {"-pubin",     no_argument,       0, WOLFCLU_PUBIN     },
    {"-help",      no_argument,       0, WOLFCLU_HELP      },
    {"-h",         no_argument,       0, WOLFCLU_HELP      },

    {0, 0, 0, 0} /* terminal element */
};


static void wolfCLU_pKeyHelp(void)
{
    WOLFCLU_LOG(WOLFCLU_L0, "./wolfssl pkey");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-in file input for key to read");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-out file to output to (default stdout)");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-inform pem/der");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-outform pem/der");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-pubout output the public key");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-pubin  expect to read public key in");
}


/* helper function for ECC EVP_PKEY
 * return WOLFSSL_SUCCESS on success */
static int _ECCpKeyPEMtoKey(WOLFSSL_BIO* bio, WOLFSSL_EVP_PKEY* pkey,
        int isPrivate)
{
    int ret;
    WOLFSSL_EVP_PKEY *tmpPkey = NULL;
    WOLFSSL_EC_KEY *key;

    key = wolfSSL_EVP_PKEY_get0_EC_KEY(pkey);
    if (key == NULL) {
        unsigned char *der = NULL;
        int derSz;

        if (isPrivate) {
            derSz = wolfSSL_i2d_PrivateKey(pkey, &der);
        }
        else {
        #if LIBWOLFSSL_VERSION_HEX > 0x05001000
            derSz = wolfSSL_i2d_PublicKey(pkey, &der);
        #else
            wolfCLU_LogError("not supported by version of wolfSSL");
            derSz = WOLFCLU_FATAL_ERROR;
        #endif
        }

        if (derSz >= 0) {
            if (isPrivate) {
                tmpPkey = wolfSSL_d2i_PrivateKey_EVP(NULL, &der, derSz);
            }
            else {
                const unsigned char *p = der;
                tmpPkey = wolfSSL_d2i_PUBKEY(NULL, &p, derSz);
            }

            key = wolfSSL_EVP_PKEY_get0_EC_KEY(tmpPkey);
        }

        if (der != NULL) {
            wolfCLU_ForceZero(der, derSz);
            XFREE(der, NULL, DYNAMIC_TYPE_OPENSSL);
        }
    }

    if (isPrivate) {
        ret = wolfSSL_PEM_write_bio_ECPrivateKey(bio, key, NULL, NULL, 0, NULL,
                NULL);
    }
    else {
        ret = wolfSSL_PEM_write_bio_EC_PUBKEY(bio, key);
    }

    if (tmpPkey != NULL) {
        wolfSSL_EVP_PKEY_free(tmpPkey);
    }

    return ret;
}


/* print out PEM public key
 * returns WOLFCLU_SUCCESS on success other return values are considered
 * 'not success'
 */
static int wolfCLU_pKeyPEMtoPubKey(WOLFSSL_BIO* bio, WOLFSSL_EVP_PKEY* pkey)
{
    int type;
    int ret = WOLFCLU_FAILURE;

    type = wolfSSL_EVP_PKEY_id(pkey);
    switch (type) {
        case EVP_PKEY_RSA:
            ret = wolfSSL_PEM_write_bio_RSA_PUBKEY(bio,
                    wolfSSL_EVP_PKEY_get0_RSA(pkey));
            break;
        case EVP_PKEY_EC:
            ret = _ECCpKeyPEMtoKey(bio, pkey, 0);
            break;

        case EVP_PKEY_DSA:
            FALL_THROUGH;
        default:
            wolfCLU_LogError("unknown / unsupported key type");
    }

    if (ret == WOLFSSL_SUCCESS) {
        return WOLFCLU_SUCCESS;
    }
    else {
        return WOLFCLU_FATAL_ERROR;
    }
}


/* return WOLFCLU_SUCCESS on success */
static int wolfCLU_DerToEncryptedPEM(WOLFSSL_BIO* bio, byte* key, word32 keySz,
        int encAlgId, byte* password, word32 passwordSz)
{
    int ret = WOLFCLU_SUCCESS;
    byte* out    = NULL;
    word32 outSz = 0;
    WC_RNG rng;

    byte* pemBuf  = NULL;
    int   pemBufSz;
    byte* salt    = NULL;
    word32 saltSz = 0;
    int itt       = WC_PKCS12_ITT_DEFAULT;
    void* heap    = NULL;

    if (wc_InitRng(&rng) != 0) {
        ret = WOLFCLU_FATAL_ERROR;
    }


    if (ret == WOLFCLU_SUCCESS) {
        if (wc_CreateEncryptedPKCS8Key(key, keySz, NULL, &outSz,
                    (const char*)password, passwordSz, PKCS5, PBES2, encAlgId,
                    salt, saltSz, itt, &rng, heap) != LENGTH_ONLY_E) {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        out = (byte*)XMALLOC(outSz, heap, DYNAMIC_TYPE_TMP_BUFFER);
        if (out == NULL) {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        int err;
        err = wc_CreateEncryptedPKCS8Key(key, keySz, out, &outSz,
                    (const char*)password, passwordSz, PKCS5, PBES2, encAlgId,
                    salt, saltSz, itt, &rng, heap);
        if (err <= 0) {
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            outSz = err;
        }
    }

    /* convert to PEM format and output */
    if (ret == WOLFCLU_SUCCESS) {
        pemBufSz = wolfCLU_KeyDerToPem(out, outSz, &pemBuf,
                PKCS8_ENC_PRIVATEKEY_TYPE, DYNAMIC_TYPE_PRIVATE_KEY);
        if (pemBufSz <= 0) {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        if (wolfSSL_BIO_write(bio, pemBuf, pemBufSz) <= 0) {
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (pemBuf != NULL) {
        XFREE(pemBuf, HEAP_HINT, DYNAMIC_TYPE_PRIVATE_KEY);
    }
    if (out != NULL) {
        XFREE(out, heap, DYNAMIC_TYPE_TMP_BUFFER);
    }
    wc_FreeRng(&rng);
    return ret;
}


/* print out PEM private key
 * returns WOLFCLU_SUCCESS on success other return values are considered
 * 'not success'
 */
int wolfCLU_pKeyPEMtoPriKey(WOLFSSL_BIO* bio, WOLFSSL_EVP_PKEY* pkey)
{
    int type;
    int ret = WOLFCLU_FAILURE;

    type = wolfSSL_EVP_PKEY_id(pkey);
    switch (type) {
        case EVP_PKEY_RSA:
            ret = wolfSSL_PEM_write_bio_RSAPrivateKey(bio,
                    wolfSSL_EVP_PKEY_get0_RSA(pkey), NULL, NULL, 0, NULL, NULL);
            break;
        case EVP_PKEY_EC:
            ret = _ECCpKeyPEMtoKey(bio, pkey, 1);
            break;

        case EVP_PKEY_DSA:
            FALL_THROUGH;
        default:
            wolfCLU_LogError("unknown / unsupported key type");
    }

    if (ret == WOLFSSL_SUCCESS) {
        return WOLFCLU_SUCCESS;
    }
    else {
        return WOLFCLU_FATAL_ERROR;
    }
}


/* return WOLFCLU_SUCCESS on success */
int wolfCLU_pKeyPEMtoPriKeyEnc(WOLFSSL_BIO* bio, WOLFSSL_EVP_PKEY* pkey,
        int encAlgId, byte* password, word32 passwordSz)
{
    unsigned char* der = NULL;
    int derSz;
    int ret = WOLFCLU_FATAL_ERROR;

    derSz = wolfSSL_i2d_PrivateKey(pkey, &der);
    if (derSz > 0) {
        ret = wolfCLU_DerToEncryptedPEM(bio, der, (word32)derSz, encAlgId,
                password, passwordSz);
    }
    if (der != NULL)
        XFREE(der, HEAP_HINT, DYNAMIC_TYPE_OPENSSL);
    return ret;
}


/* return key size on success */
static int wolfCLU_pKeyToKeyECC(WOLFSSL_EVP_PKEY* pkey, unsigned char** out,
        int isPrivateKey)
{
    int ret   = 0;
    int derSz = 0;
    unsigned char *der = NULL;
    WOLFSSL_EC_KEY *ec = NULL;

    ec = wolfSSL_EVP_PKEY_get0_EC_KEY(pkey);
    if (ec == NULL) {
        wolfCLU_LogError("No ecc key found in pkey");
        ret = BAD_FUNC_ARG;
    }

    if (ret == 0) {
        if (isPrivateKey) {
            derSz = wc_EccKeyDerSize((ecc_key*)ec->internal, 1);
        }
        else {
            derSz = wc_EccPublicKeyDerSize((ecc_key*)ec->internal, 1);
        }

        if (derSz < 0) {
            wolfCLU_LogError("Unable to get ecc der size");
            ret = BAD_FUNC_ARG;
        }
    }

    if (ret == 0) {
        der = (unsigned char*)XMALLOC(derSz, HEAP_HINT,
                DYNAMIC_TYPE_TMP_BUFFER);
        if (der == NULL) {
            wolfCLU_LogError("Unable to malloc der buffer");
            ret = MEMORY_E;
        }
    }

    if (ret == 0) {
        if (isPrivateKey) {
            ret = wc_EccKeyToDer((ecc_key*)ec->internal, der, derSz);
        }
        else {
            ret = wc_EccPublicKeyToDer((ecc_key*)ec->internal, der, derSz, 1);
        }

        if (ret > 0) {
            *out = der;
        }
        else {
            ret = BAD_FUNC_ARG;
            WOLFCLU_LOG(WOLFCLU_E0,
                    "Decoding der from internal structure failed");
        }
    }

    if (ret < 0 && der != NULL) {
        wolfCLU_ForceZero(der, derSz);
        XFREE(der, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        *out = NULL;
    }

    return ret;
}


/* creates an out buffer containing only the public key from the pkey
 * returns size of buffer on success
 */
int wolfCLU_pKeytoPubKey(WOLFSSL_EVP_PKEY* pkey, unsigned char** out)
{
    int type;
    int ret = 0;

    type   = wolfSSL_EVP_PKEY_id(pkey);
    switch (type) {
        case EVP_PKEY_RSA:
            ret = wolfSSL_i2d_RSAPublicKey(
                    wolfSSL_EVP_PKEY_get0_RSA(pkey), out);
            break;

        case EVP_PKEY_DSA:
            wolfCLU_LogError("DSA key not yet supported");
            ret = USER_INPUT_ERROR;
            break;

        case EVP_PKEY_EC:
            ret = wolfCLU_pKeyToKeyECC(pkey, out, 0);
            break;

        default:
            wolfCLU_LogError("unknown / unsupported key type");
            ret = USER_INPUT_ERROR;
    }

    return ret;
}


/* creates an out buffer containing the private key from the pkey
 * returns size of buffer on success
 */
int wolfCLU_pKeytoPriKey(WOLFSSL_EVP_PKEY* pkey, unsigned char** out)
{
    int type;
    int ret = 0;

    type = wolfSSL_EVP_PKEY_id(pkey);
    switch (type) {
        case EVP_PKEY_RSA:
            ret = wolfSSL_i2d_RSAPrivateKey(
                    wolfSSL_EVP_PKEY_get0_RSA(pkey), out);
            break;

        case EVP_PKEY_DSA:
            wolfCLU_LogError("DSA key not yet supported");
            ret = USER_INPUT_ERROR;
            break;

        case EVP_PKEY_EC:
            ret = wolfCLU_pKeyToKeyECC(pkey, out, 1);
            break;

        default:
            wolfCLU_LogError("unknown / unsupported key type");
            ret = USER_INPUT_ERROR;
    }

    return ret;
}
#endif /* !WOLFCLU_NO_FILESYSTEM */

int wolfCLU_pKeySetup(int argc, char** argv)
{
#ifndef WOLFCLU_NO_FILESYSTEM
    int ret    = WOLFCLU_SUCCESS;
    int inForm  = PEM_FORM;
    int outForm = PEM_FORM;
    int pubIn  = 0;
    int pubOut = 0;
    int option;
    int longIndex = 1;
    WOLFSSL_EVP_PKEY *pkey = NULL;
    WOLFSSL_BIO *bioIn  = NULL;
    WOLFSSL_BIO *bioOut = NULL;

    optind = 0; /* start at indent 0 */
    while ((option = wolfCLU_GetOpt(argc, argv, "",
                   pkey_options, &longIndex )) != -1) {
        switch (option) {
            case WOLFCLU_PUBOUT:
                pubOut = 1;
                break;

            case WOLFCLU_PUBIN:
                pubIn  = 1;
                pubOut = 1;
                break;

            case WOLFCLU_INFILE:
                bioIn = wolfSSL_BIO_new_file(optarg, "rb");
                if (bioIn == NULL) {
                    wolfCLU_LogError("Unable to open public key file %s",
                            optarg);
                    ret = WOLFCLU_FATAL_ERROR;
                }
                break;

            case WOLFCLU_OUTFILE:
                bioOut = wolfSSL_BIO_new_file(optarg, "wb");
                if (bioOut == NULL) {
                    wolfCLU_LogError("Unable to open output file %s",
                            optarg);
                    ret = WOLFCLU_FATAL_ERROR;
                }
                break;

            case WOLFCLU_INFORM:
                inForm = wolfCLU_checkInform(optarg);
                break;

            case WOLFCLU_OUTFORM:
                outForm = wolfCLU_checkOutform(optarg);
                break;

            case WOLFCLU_HELP:
                wolfCLU_pKeyHelp();
                return WOLFCLU_SUCCESS;

            case ':':
            case '?':
                wolfCLU_LogError("Bad argument");
                ret = USER_INPUT_ERROR;
                break;

            default:
                wolfCLU_LogError("Bad argument");
                ret = USER_INPUT_ERROR;
        }
    }


    if (ret == WOLFCLU_SUCCESS && bioIn != NULL) {
        if (inForm == PEM_FORM) {
            if (pubIn) {
                pkey = wolfSSL_PEM_read_bio_PUBKEY(bioIn, NULL, NULL, NULL);
            }
            else {
                pkey = wolfSSL_PEM_read_bio_PrivateKey(bioIn, NULL, NULL, NULL);
            }
        }
        else {
            if (pubIn) {
                pkey = wolfSSL_d2i_PUBKEY_bio(bioIn, NULL);
            }
            else {
                pkey = wolfSSL_d2i_PrivateKey_bio(bioIn, NULL);
            }
        }
        if (pkey == NULL) {
            wolfCLU_LogError("Error reading key from file");
            ret = USER_INPUT_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS && bioOut == NULL) {
        bioOut = wolfSSL_BIO_new(wolfSSL_BIO_s_file());
        if (bioOut == NULL) {
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            if (wolfSSL_BIO_set_fp(bioOut, stdout, BIO_NOCLOSE)
                    != WOLFSSL_SUCCESS) {
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
    }

    /* print out the public key only */
    if (ret == WOLFCLU_SUCCESS && pubOut == 1) {
        if (pkey != NULL) {
            unsigned char *der = NULL;
            int derSz = 0;

            if (inForm == PEM_FORM) {
                if (outForm == PEM_FORM) {
                    ret = wolfCLU_pKeyPEMtoPubKey(bioOut, pkey);
                    if (ret != WOLFCLU_SUCCESS) {
                        WOLFCLU_LOG(WOLFCLU_E0,
                                "Error getting pubkey from pem key");
                    }
                }
                else {
                    if ((derSz = wolfCLU_pKeytoPubKey(pkey, &der)) <= 0) {
                        WOLFCLU_LOG(WOLFCLU_E0,
                                "Error converting der found to public key");
                        ret = WOLFCLU_FATAL_ERROR;
                    }
                    if (ret == WOLFCLU_SUCCESS) {
                        wolfSSL_BIO_write(bioOut, der, derSz);
                    }
                }
            }
            else {
                if ((derSz = wolfCLU_pKeytoPubKey(pkey, &der)) <= 0) {
                    WOLFCLU_LOG(WOLFCLU_E0,
                            "Error converting der found to public key");
                    ret = WOLFCLU_FATAL_ERROR;
                }
                else {
                    if (outForm == PEM_FORM) {
                        if (wolfCLU_printDerPubKey(bioOut, der, derSz) !=
                            WOLFCLU_SUCCESS) {
                            wolfCLU_LogError("Error printing out pubkey");
                            ret = WOLFCLU_FATAL_ERROR;
                        }
                    }
                    else {
                        wolfSSL_BIO_write(bioOut, der, derSz);
                    }
                }
            }
            if (der != NULL)
                XFREE(der, HEAP_HINT, DYNAMIC_TYPE_OPENSSL);
        }
    }

    /* print out the private key */
    if (ret == WOLFCLU_SUCCESS && pubOut == 0) {
        if (pkey != NULL) {
            if (outForm == DER_FORM) {
                unsigned char *der = NULL;
                int derSz = 0;

                if ((derSz = wolfCLU_pKeytoPriKey(pkey, &der)) <= 0) {
                    WOLFCLU_LOG(WOLFCLU_E0,
                            "Error converting der found to private key");
                    ret = WOLFCLU_FATAL_ERROR;
                }

                if (ret == WOLFCLU_SUCCESS) {
                    wolfSSL_BIO_write(bioOut, der, derSz);

                }

                if (der != NULL) {
                    XFREE(der, HEAP_HINT, DYNAMIC_TYPE_OPENSSL);
                }
            }

            if (outForm == PEM_FORM){
                ret = wolfCLU_pKeyPEMtoPriKey(bioOut, pkey);
                if (ret != WOLFCLU_SUCCESS) {
                    WOLFCLU_LOG(WOLFCLU_E0,
                            "Error getting private key from pem key");
                    ret = WOLFCLU_FATAL_ERROR;
                }
            }
        }
    }

    wolfSSL_BIO_free(bioIn);
    wolfSSL_BIO_free(bioOut);
    wolfSSL_EVP_PKEY_free(pkey);

    return ret;
#else
    (void)argc;
    (void)argv;
    WOLFCLU_LOG(WOLFCLU_E0, "No filesystem support");
    return WOLFCLU_FATAL_ERROR;
#endif
}

