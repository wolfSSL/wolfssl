/* clu_dgst_setup.c
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
#include <wolfclu/wolfclu/sign-verify/clu_sign.h>
#include <wolfclu/wolfclu/sign-verify/clu_verify.h>
#include <wolfclu/wolfclu/sign-verify/clu_sign_verify_setup.h>
#include <wolfclu/wolfclu/pkey/clu_pkey.h>

#ifndef WOLFCLU_NO_FILESYSTEM

static const struct option dgst_options[] = {

    {"-md5",       no_argument,       0, WOLFCLU_MD5        },
    {"-sha",       no_argument,       0, WOLFCLU_CERT_SHA   },
    {"-sha224",    no_argument,       0, WOLFCLU_CERT_SHA224},
    {"-sha256",    no_argument,       0, WOLFCLU_CERT_SHA256},
    {"-sha384",    no_argument,       0, WOLFCLU_CERT_SHA384},
    {"-sha512",    no_argument,       0, WOLFCLU_CERT_SHA512},

    {"-out",       required_argument, 0, WOLFCLU_INFILE    },
    {"-signature", required_argument, 0, WOLFCLU_INFILE    },
    {"-verify",    required_argument, 0, WOLFCLU_VERIFY    },
    {"-sign",     required_argument, 0, WOLFCLU_SIGN      },
    {"-h",        no_argument,       0, WOLFCLU_HELP      },
    {"-help",     no_argument,       0, WOLFCLU_HELP      },

    {0, 0, 0, 0} /* terminal element */
};


static void wolfCLU_dgstHelp(void)
{
    WOLFCLU_LOG(WOLFCLU_L0, "dgst: (the last argument is the data that was signed)");
    WOLFCLU_LOG(WOLFCLU_L0, "Hash algos supported:");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-md5");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-sha");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-sha224");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-sha256");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-sha384");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-sha512");
    WOLFCLU_LOG(WOLFCLU_L0, "Parameters:");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-signature file containing the signature");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-verify key used to verify the signature");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-sign   private key used to create the signature");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-out    output file for signature");
    WOLFCLU_LOG(WOLFCLU_L0, "Example:");
    WOLFCLU_LOG(WOLFCLU_L0, "\twolfssl dgst -signature test.sig -verify key.pem test");
}


/* return WOLFCLU_SUCCESS on success */
static int ExtractKey(void* key, WOLFSSL_EVP_PKEY* pkey, int* keySz,
        enum wc_SignatureType* sigType, int signing)
{
    ecc_key* ecc = NULL;
    RsaKey*  rsa = NULL;
    byte* der = NULL;
    int   derSz = 0;
    int ret = WOLFCLU_SUCCESS;
    word32 idx = 0;

    if (signing == 0) { /* expecting public key */
        derSz = wolfCLU_pKeytoPubKey(pkey, &der);
    }
    else { /* expecting private key */
        derSz = wolfCLU_pKeytoPriKey(pkey, &der);
    }
    if (derSz <= 0) {
        wolfCLU_LogError("Unable to extract der key");
        ret = WOLFCLU_FATAL_ERROR;
    }

    switch (wolfSSL_EVP_PKEY_id(pkey)) {
        case EVP_PKEY_RSA:
            *keySz   = (int)sizeof(RsaKey);
            *sigType = WC_SIGNATURE_TYPE_RSA_W_ENC;
            rsa = (RsaKey*)key;

            if (wc_InitRsaKey(rsa, NULL) != 0) {
                wolfCLU_LogError("Unable to initialize rsa key");
                ret = WOLFCLU_FATAL_ERROR;
            }

            /* expecting public key */
            if (ret == WOLFCLU_SUCCESS && signing == 0 &&
                    wc_RsaPublicKeyDecode(der, &idx, rsa, derSz) != 0) {
                wolfCLU_LogError("Error decoding public rsa key");
                ret = WOLFCLU_FATAL_ERROR;
            }

            /* expecting private key */
            if (ret == WOLFCLU_SUCCESS && signing == 1 &&
                    wc_RsaPrivateKeyDecode(der, &idx, rsa, derSz) != 0) {
                wolfCLU_LogError("Error decoding public rsa key");
                ret = WOLFCLU_FATAL_ERROR;
            }
            break;

        case EVP_PKEY_EC:
            *keySz   = (int)sizeof(ecc_key);
            *sigType = WC_SIGNATURE_TYPE_ECC;
            ecc = (ecc_key*)key;

            if (wc_ecc_init(ecc) != 0) {
                wolfCLU_LogError("Error initializing ecc key");
                ret = WOLFCLU_FATAL_ERROR;
            }

            /* expecting public key */
            if (ret == WOLFCLU_SUCCESS && signing == 0 &&
                    wc_EccPublicKeyDecode(der, &idx, ecc, derSz) != 0) {
                wolfCLU_LogError("Error decoding public ecc key");
                ret = WOLFCLU_FATAL_ERROR;
            }

            /* expecting private key */
            if (ret == WOLFCLU_SUCCESS && signing == 1 &&
                    wc_EccPrivateKeyDecode(der, &idx, ecc, derSz) != 0) {
                wolfCLU_LogError("Error decoding private ecc key");
                ret = WOLFCLU_FATAL_ERROR;
            }
            break;

        default:
            wolfCLU_LogError("Key type not yet supported");
            ret = WOLFCLU_FATAL_ERROR;
    }

    if (der != NULL)
        XFREE(der, NULL, DYNAMIC_TYPE_OPENSSL);

    return ret;
}
#endif /* !WOLFCLU_NO_FILESYSTEM */

/* return WOLFCLU_SUCCESS on success */
int wolfCLU_dgst_setup(int argc, char** argv)
{
#ifndef WOLFCLU_NO_FILESYSTEM
    ecc_key ecc;
    RsaKey  rsa;
    WOLFSSL_BIO *sigBio = NULL;
    WOLFSSL_BIO *pubKeyBio = NULL;
    WOLFSSL_BIO *dataBio = NULL;
    WOLFSSL_EVP_PKEY *pkey = NULL;
    int     ret = WOLFCLU_SUCCESS;
    byte* sig  = NULL;
    char* data = NULL;
    char* sigFile = NULL;
    void* key  = NULL;
    word32 dataSz = 0;
    word32 sigSz  = 0;
    int keySz  = 0;
    int option;
    int longIndex = 2;
    byte signing = 0;

    enum wc_HashType      hashType = WC_HASH_TYPE_NONE;
    enum wc_SignatureType sigType  = WC_SIGNATURE_TYPE_NONE;

    /* signed file should be the last arg */
    if (XSTRNCMP("-h", argv[argc-1], 2) == 0) {
        wolfCLU_dgstHelp();
        return WOLFCLU_SUCCESS;
    }
    else {
        dataBio = wolfSSL_BIO_new_file(argv[argc-1], "rb");
        if (dataBio == NULL) {
            wolfCLU_LogError("Unable to open data file %s",
                    argv[argc-1]);
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    opterr = 0; /* do not display unrecognized options */
    optind = 0; /* start at indent 0 */
    while ((option = wolfCLU_GetOpt(argc, argv, "",
                   dgst_options, &longIndex )) != -1) {

        switch (option) {

            case WOLFCLU_MD5:
                hashType = WC_HASH_TYPE_MD5;
                break;

            case WOLFCLU_CERT_SHA:
                hashType = WC_HASH_TYPE_SHA;
                break;

            case WOLFCLU_CERT_SHA224:
                hashType = WC_HASH_TYPE_SHA224;
                break;

            case WOLFCLU_CERT_SHA256:
                hashType = WC_HASH_TYPE_SHA256;
                break;

            case WOLFCLU_CERT_SHA384:
                hashType = WC_HASH_TYPE_SHA384;
                break;

            case WOLFCLU_CERT_SHA512:
                hashType = WC_HASH_TYPE_SHA512;
                break;

            case WOLFCLU_SIGN:
                signing = 1;
                FALL_THROUGH;
            case WOLFCLU_VERIFY:
                pubKeyBio = wolfSSL_BIO_new_file(optarg, "rb");
                if (pubKeyBio == NULL) {
                    wolfCLU_LogError("Unable to open key file %s",
                            optarg);
                    ret = WOLFCLU_FATAL_ERROR;
                }
                break;

            case WOLFCLU_INFILE:
                sigFile = optarg;
                break;

            case WOLFCLU_HELP:
                wolfCLU_dgstHelp();
                return WOLFCLU_SUCCESS;

            case ':':
            case '?':
                break;

            default:
                /* do nothing. */
                (void)ret;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        if (dataBio == NULL || sigFile == NULL) {
            wolfCLU_LogError("error with reading signature or data");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        XFILE f;

        /* get data size using raw FILE pointer and seek */
        if (wolfSSL_BIO_get_fp(dataBio, &f) != WOLFSSL_SUCCESS) {
            wolfCLU_LogError("Unable to get raw file pointer");
            ret = WOLFCLU_FATAL_ERROR;
        }

        if (ret == WOLFCLU_SUCCESS && XFSEEK(f, 0, XSEEK_END) != 0) {
            wolfCLU_LogError("Unable to seek end of file");
            ret = WOLFCLU_FATAL_ERROR;
        }

        if (ret == WOLFCLU_SUCCESS) {
            dataSz = (word32)XFTELL(f);
            wolfSSL_BIO_reset(dataBio);
        }

        if (signing == 0) {
            sigBio = wolfSSL_BIO_new_file(sigFile, "rb");
            if (sigBio == NULL) {
                wolfCLU_LogError("Unable to read signature file %s",
                        sigFile);
                ret = WOLFCLU_FATAL_ERROR;
            }

            if (ret == WOLFCLU_SUCCESS) {
                ret = wolfSSL_BIO_get_len(sigBio);
                if (ret <= 0) {
                    wolfCLU_LogError("Unable to get signature size");
                    ret = WOLFCLU_FATAL_ERROR;
                }
                else {
                    sigSz = (word32)ret;
                    ret = WOLFCLU_SUCCESS;
                }
            }
        }

        if (dataSz <= 0 || (sigSz <= 0 && signing == 0)) {
            wolfCLU_LogError("No signature or data");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* create buffers and fill them */
    if (ret == WOLFCLU_SUCCESS) {
        data = (char*)XMALLOC(dataSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (data == NULL) {
            ret = MEMORY_E;
        }
        else {
            word32 totalRead = 0;

            /* read in 4k at a time because file could be larger than int type
             * restriction on size input for wolfSSL_BIO_read */
            while (totalRead < dataSz) {
                int sz = min(dataSz - totalRead, 4096);
                if (wolfSSL_BIO_read(dataBio, data + totalRead, sz) != sz) {
                    wolfCLU_LogError("Error reading data");
                    ret = WOLFCLU_FATAL_ERROR;
                    break;
                }
                totalRead += sz;
            }
        }
    }

    if (ret == WOLFCLU_SUCCESS && signing == 0) {
        sig = (byte*)XMALLOC(sigSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        if (sig == NULL) {
            ret = MEMORY_E;
        }
        else {
            if (wolfSSL_BIO_read(sigBio, sig, sigSz) <= 0) {
                wolfCLU_LogError("Error reading sig");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
    }

    /* get type of key and size of structure */
    if (ret == WOLFCLU_SUCCESS && signing == 0) {
        pkey = wolfSSL_PEM_read_bio_PUBKEY(pubKeyBio, NULL, NULL, NULL);
        if (pkey == NULL) {
            wolfCLU_LogError("Unable to decode public key");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS && signing == 1) {
        pkey = wolfSSL_PEM_read_bio_PrivateKey(pubKeyBio, NULL, NULL, NULL);
        if (pkey == NULL) {
            wolfCLU_LogError("Unable to decode public key");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        switch (wolfSSL_EVP_PKEY_id(pkey)) {
            case EVP_PKEY_RSA:
                key = (void*)&rsa;
                break;

            case EVP_PKEY_EC:
                key = (void*)&ecc;
                break;
        }

        if (ExtractKey(key, pkey, &keySz, &sigType, signing) !=
                WOLFCLU_SUCCESS) {
            wolfCLU_LogError("Unable to extract key");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* if not signing then do verification */
    if (ret == WOLFCLU_SUCCESS && signing == 0) {
        if (wc_SignatureVerify(hashType, sigType, (const byte*)data, dataSz,
                    (const byte*)sig, sigSz, key, keySz) == 0) {
            WOLFCLU_LOG(WOLFCLU_L0, "Verify OK");
        }
        else {
            wolfCLU_LogError("Verification failure");
            ret = WOLFCLU_FATAL_ERROR;
        }
    }

    /* create the signature if requested */
    if (ret == WOLFCLU_SUCCESS && signing == 1) {
        WC_RNG rng;

        if (wc_InitRng(&rng) != 0) {
            wolfCLU_LogError("Error initializing RNG");
            ret = WOLFCLU_FATAL_ERROR;
        }

        /* get expected signature size */
        if (ret == WOLFCLU_SUCCESS) {
            ret = wc_SignatureGetSize(sigType, key, keySz);
            if (ret <= 0) {
                wolfCLU_LogError("Error getting signature size");
                ret = WOLFCLU_FATAL_ERROR;
            }
            else {
                sigSz = (word32)ret;
                ret = WOLFCLU_SUCCESS;
            }
        }

        if (ret == WOLFCLU_SUCCESS) {
            sig = (byte*)XMALLOC(sigSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            if (sig == NULL) {
                ret = MEMORY_E;
            }
        }

        if (ret == WOLFCLU_SUCCESS &&
                wc_SignatureGenerate(hashType, sigType, (const byte*)data,
                    dataSz, sig, &sigSz, key, keySz, &rng) != 0) {
            wolfCLU_LogError("Error getting signature");
            ret = WOLFCLU_FATAL_ERROR;
        }

        /* write out the signature */
        if (ret == WOLFCLU_SUCCESS) {
            sigBio = wolfSSL_BIO_new_file(sigFile, "wb");
            if (sigBio == NULL) {
                wolfCLU_LogError("Unable to create signature file %s",
                        sigFile);
                ret = WOLFCLU_FATAL_ERROR;
            }
        }

        if (ret == WOLFCLU_SUCCESS &&
                wolfSSL_BIO_write(sigBio, sig, sigSz) <= 0) {
            wolfCLU_LogError("Error writing out signature");
            ret = WOLFCLU_FATAL_ERROR;
        }
        wc_FreeRng(&rng);
    }

    /* if any key size has been set then try to free the key struct */
    if (keySz > 0) {
        switch (sigType) {
            case WC_SIGNATURE_TYPE_RSA:
            case WC_SIGNATURE_TYPE_RSA_W_ENC:
                wc_FreeRsaKey(&rsa);
                break;

            case WC_SIGNATURE_TYPE_ECC:
                wc_ecc_free(&ecc);
                break;

            case WC_SIGNATURE_TYPE_NONE:
                FALL_THROUGH;

            default:
                wolfCLU_LogError("Key type not yet supported");
                ret = WOLFCLU_FATAL_ERROR;
        }
    }

    if (data != NULL)
        XFREE(data, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (sig != NULL)
        XFREE(sig, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);

    wolfSSL_EVP_PKEY_free(pkey);
    wolfSSL_BIO_free(sigBio);
    wolfSSL_BIO_free(pubKeyBio);
    wolfSSL_BIO_free(dataBio);

    return ret;
#else
    (void)argc;
    (void)argv;
    WOLFCLU_LOG(WOLFCLU_E0, "No filesystem support");
    return WOLFCLU_FATAL_ERROR;
#endif
}

