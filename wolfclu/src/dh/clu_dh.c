/* clu_dh.c
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

#if !defined(NO_DH) && !defined(WOLFSSL_DH_EXTRA)
/* Older FIPS builds do not have DH functions gated by WOLFSSL_DH_EXTRA.
 * Add copy of basic implementation here, taken from wolfSSL 5.5.4
 * (asn.c, dh.c) */

#ifndef WOLFSSL_PUBLIC_MP
    #error WOLFSSL_PUBLIC_MP needs defined if not using WOLFSSL_DH_EXTRA
#endif


static const byte keyDhOid[] = {42, 134, 72, 134, 247, 13, 1, 3, 1};

static word32 BytePrecisionCopy(word32 value)
{
    word32 i;
    for (i = (word32)sizeof(value) - 1; i; --i)
        if (value >> ((i - 1) * WOLFSSL_BIT_SIZE))
            break;

    return i;
}

static word32 SetLengthCopy(word32 length, byte* output)
{
    /* Start encoding at start of buffer. */
    word32 i = 0;

    if (length < ASN_LONG_LENGTH) {
        /* Only one byte needed to encode. */
        if (output) {
            /* Write out length value. */
            output[i] = (byte)length;
        }
        /* Skip over length. */
        i++;
    }
    else {
        /* Calculate the number of bytes required to encode value. */
        byte j = (byte)BytePrecisionCopy(length);

        if (output) {
            /* Encode count byte. */
            output[i] = j | ASN_LONG_LENGTH;
        }
        /* Skip over count byte. */
        i++;

        /* Encode value as a big-endian byte array. */
        for (; j > 0; --j) {
            if (output) {
                /* Encode next most-significant byte. */
                output[i] = (byte)(length >> ((j - 1) * WOLFSSL_BIT_SIZE));
            }
            /* Skip over byte. */
            i++;
        }
    }

    /* Return number of bytes in encoded length. */
    return i;
}


static int SetMyVersionCopy(word32 version, byte* output, int header)
{
    int i = 0;

    if (output == NULL)
        return BAD_FUNC_ARG;

    if (header) {
        output[i++] = ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED;
        output[i++] = 3;
    }
    output[i++] = ASN_INTEGER;
    output[i++] = 0x01;
    output[i++] = (byte)version;

    return i;
}


static int SetObjectIdCopy(int len, byte* output)
{
    int idx = 0;

    if (output) {
        /* Write out tag. */
        output[idx] = ASN_OBJECT_ID;
    }
    /* Skip tag. */
    idx += ASN_TAG_SZ;
    /* Encode length - passing NULL for output will not encode. */
    idx += SetLengthCopy(len, output ? output + idx : NULL);

    /* Return index after header. */
    return idx;
}


static word32 SetSequenceCopy(word32 len, byte* output)
{
    if (output) {
        output[0] = ASN_SEQUENCE | ASN_CONSTRUCTED;
    }

    return SetLengthCopy(len, output ? output + ASN_TAG_SZ : NULL) + ASN_TAG_SZ;
}


static word32 SetOctetStringCopy(word32 len, byte* output)
{
    if (output) {
        output[0] = ASN_OCTET_STRING;
    }

    return SetLengthCopy(len, output ? output + ASN_TAG_SZ : NULL) + ASN_TAG_SZ;
}


static int SetASNIntCopy(int len, byte firstByte, byte* output)
{
    word32 idx = 0;

    if (output) {
        /* Write out tag. */
        output[idx] = ASN_INTEGER;
    }
    /* Step over tag. */
    idx += ASN_TAG_SZ;
    /* Check if first byte has top bit set in which case a 0 is needed to
     * maintain positive value. */
    if (firstByte & 0x80) {
        /* Add pre-prepended byte to length of data in INTEGER. */
        len++;
    }
    /* Encode length - passing NULL for output will not encode. */
    idx += SetLengthCopy(len, output ? output + idx : NULL);
    /* Put out pre-pended 0 as well. */
    if (firstByte & 0x80) {
        if (output) {
            /* Write out 0 byte. */
            output[idx] = 0x00;
        }
        /* Update index. */
        idx++;
    }

    /* Return index after header. */
    return idx;
}


static int SetASNIntMPCopy(mp_int* n, int maxSz, byte* output)
{
    int idx = 0;
    int leadingBit;
    int length;
    int err;

    leadingBit = mp_leading_bit(n);
    length = mp_unsigned_bin_size(n);
    if (maxSz >= 0 && (1 + length + (leadingBit ? 1 : 0)) > maxSz)
        return BUFFER_E;
    idx = SetASNIntCopy(length, leadingBit ? 0x80 : 0x00, output);
    if (maxSz >= 0 && (idx + length) > maxSz)
        return BUFFER_E;

    if (output) {
        err = mp_to_unsigned_bin(n, output + idx);
        if (err != MP_OKAY)
            return MP_TO_E;
    }
    idx += length;

    return idx;
}


int wc_DhParamsToDer(DhKey* key, byte* output, word32* outSz);
int wc_DhParamsToDer(DhKey* key, byte* output, word32* outSz)
{
    word32 idx, total;

    if (key == NULL || outSz == NULL) {
        return BAD_FUNC_ARG;
    }

    /* determine size */
    /* integer - g */
    idx = SetASNIntMPCopy(&key->g, -1, NULL);
    /* integer - p */
    idx += SetASNIntMPCopy(&key->p, -1, NULL);
    total = idx;
     /* sequence */
    idx += SetSequenceCopy(idx, NULL);

    if (output == NULL) {
        *outSz = idx;
        return LENGTH_ONLY_E;
    }
    /* make sure output fits in buffer */
    if (idx > *outSz) {
        return BUFFER_E;
    }

    /* write DH parameters */
    /* sequence - for P and G only */
    idx = SetSequenceCopy(total, output);
    /* integer - p */
    idx += SetASNIntMPCopy(&key->p, -1, output + idx);
    /* integer - g */
    idx += SetASNIntMPCopy(&key->g, -1, output + idx);
    *outSz = idx;

    return idx;
}


int wc_DhPrivKeyToDer(DhKey* key, byte* priv, word32 privSz, byte* output,
        word32* outSz);
int wc_DhPrivKeyToDer(DhKey* key, byte* prv, word32 prvSz, byte* output,
        word32* outSz)
{
    int ret, privSz = 0, keySz;
    word32 idx, len, total;
    mp_int mpPriv;

    if (key == NULL || outSz == NULL) {
        return BAD_FUNC_ARG;
    }

    mp_init(&mpPriv);
    if (mp_read_unsigned_bin(&mpPriv, prv, prvSz) != 0) {
        mp_free(&mpPriv);
        return BAD_FUNC_ARG;
    }

    /* determine size */
    /* octect string: priv */
    privSz = SetASNIntMPCopy(&mpPriv, -1, NULL);
    idx = 1 + SetLengthCopy(privSz, NULL) + privSz; /* +1 for ASN_OCTET_STRING */
    keySz = idx;

    /* DH Parameters sequence with P and G */
    total = 0;
    ret = wc_DhParamsToDer(key, NULL, &total);
    if (ret != LENGTH_ONLY_E) {
        mp_free(&mpPriv);
        return ret;
    }
    idx += total;

    /* object dhKeyAgreement 1.2.840.113549.1.3.1 */
    idx += SetObjectIdCopy(sizeof(keyDhOid), NULL);
    idx += sizeof(keyDhOid);
    len = idx - keySz;
    /* sequence - all but pub/priv */
    idx += SetSequenceCopy(len, NULL);
    /* version: 0 (ASN_INTEGER, 0x01, 0x00) */
    idx += 3;
    /* sequence */
    total = idx + SetSequenceCopy(idx, NULL);

    /* if no output, then just getting size */
    if (output == NULL) {
        *outSz = total;
        mp_free(&mpPriv);
        return LENGTH_ONLY_E;
    }

    /* make sure output fits in buffer */
    if (total > *outSz) {
        mp_free(&mpPriv);
        return BUFFER_E;
    }
    total = idx;

    /* sequence */
    idx = SetSequenceCopy(total, output);
    /* version: 0 */
    idx += SetMyVersionCopy(0, output + idx, 0);
    /* sequence - all but pub/priv */
    idx += SetSequenceCopy(len, output + idx);
    /* object dhKeyAgreement 1.2.840.113549.1.3.1 */
    idx += SetObjectIdCopy(sizeof(keyDhOid), output + idx);
    XMEMCPY(output + idx, keyDhOid, sizeof(keyDhOid));
    idx += sizeof(keyDhOid);

    /* DH Parameters sequence with P and G */
    total = *outSz - idx;
    ret = wc_DhParamsToDer(key, output + idx, &total);
    if (ret < 0) {
        mp_free(&mpPriv);
        return ret;
    }
    idx += total;

    /* octect string: priv */
    idx += SetOctetStringCopy(privSz, output + idx);
    idx += SetASNIntMPCopy(&mpPriv, -1, output + idx);
    *outSz = idx;

    mp_free(&mpPriv);
    return idx;
}

#endif /* !WOLFSSL_DH_EXTRA */


#if !defined(NO_DH)

#ifndef WOLFSSL_MAX_DH_BITS
    #define WOLFSSL_MAX_DH_BITS       4096
#endif

#ifndef WOLFSSL_MAX_DH_Q_SIZE
    #define WOLFSSL_MAX_DH_Q_SIZE     256
#endif

static const struct option dh_options[] = {
    {"-in",        required_argument, 0, WOLFCLU_INFILE    },
    {"-out",       required_argument, 0, WOLFCLU_OUTFILE   },
    {"-genkey",    no_argument,       0, WOLFCLU_GEN_KEY   },
    {"-check",     no_argument,       0, WOLFCLU_CHECK     },
    {"-noout",     no_argument,       0, WOLFCLU_NOOUT     },
    {"-help",      no_argument,       0, WOLFCLU_HELP      },
    {"-h",         no_argument,       0, WOLFCLU_HELP      },

    {0, 0, 0, 0} /* terminal element */
};


static void wolfCLU_DhHelp(void)
{
    WOLFCLU_LOG(WOLFCLU_L0, "./wolfssl dhparam [options] [numbits]");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-in file input for key to read");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-out file to output to (default stdout)");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-genkey generate DH key using param input");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-check  check if parameters are valid");
    WOLFCLU_LOG(WOLFCLU_L0, "\t-noout  do not print out the params");
}
#endif /* !NO_DH */


int wolfCLU_DhParamSetup(int argc, char** argv)
{
#if !defined(NO_DH)
    WC_RNG rng;
    DhKey dh;
    int modSz = -1;
    int ret   = WOLFCLU_SUCCESS;
    int option;
    int longIndex = 1;
    char* out = NULL;
    byte genKey = 0;
    byte check  = 0;
    byte noOut  = 0;
    WOLFSSL_BIO *bioIn  = NULL;
    WOLFSSL_BIO *bioOut = NULL;

    optind = 0; /* start at indent 0 */
    while ((option = wolfCLU_GetOpt(argc, argv, "",
                   dh_options, &longIndex )) != -1) {
        switch (option) {
            case WOLFCLU_INFILE:
#ifdef WOLFCLU_NO_FILESYSTEM
            WOLFCLU_LOG(WOLFCLU_E0, "No filesystem support. Unable to open input file");
            ret = WOLFCLU_FATAL_ERROR;
#else
                bioIn = wolfSSL_BIO_new_file(optarg, "rb");
                if (bioIn == NULL) {
                    wolfCLU_LogError("Unable to open input file %s",
                            optarg);
                    ret = WOLFCLU_FATAL_ERROR;
                }
#endif
                break;

            case WOLFCLU_OUTFILE:
                out = optarg;
                break;

            case WOLFCLU_GEN_KEY:
                genKey = 1;
                break;

            case WOLFCLU_CHECK:
                check = 1;
                break;

            case WOLFCLU_NOOUT:
                noOut = 1;
                break;

            case WOLFCLU_HELP:
                wolfCLU_DhHelp();
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

    /* go to the item directly after dhparam, this will be the first non '-'
     * option found in the arguments passed in */

    if (ret == WOLFCLU_SUCCESS) {
        int i = 2; // start at 2 because wolfssl & dhparam will be in first and second
        int found = 0;
        while (i + 1 <= argc && !found) {
            /* confirm arg is a non '-' option that does not correspond
             * to an '-in' or '-out' file */
            if (argv[i][0] != '-' && XSTRCMP(argv[i-1], "-in") != 0
                    && XSTRCMP(argv[i-1], "-out") != 0){
                found = 1;
                modSz = XATOI(argv[i]);
                if (modSz <= 0) {
                    wolfCLU_LogError("Can not parse %s as a number",
                            argv[i]);
                    ret = USER_INPUT_ERROR;
                }
            }
            i++;
        }
    }

    /* try initializing both because both get free'd regardless at the end */
    if (wc_InitRng(&rng) != 0 || wc_InitDhKey(&dh) != 0) {
        wolfCLU_LogError("Unable to initialize rng and dh");
        ret = WOLFCLU_FATAL_ERROR;
    }

    /* read in parameters */
    if (ret == WOLFCLU_SUCCESS && bioIn != NULL) {
        DerBuffer* pDer = NULL;
        byte* in = NULL;
        word32 inSz = 0;
        word32 idx  = 0;

        inSz = wolfSSL_BIO_get_len(bioIn);
        if (inSz > 0) {
            in = (byte*)XMALLOC(inSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (in == NULL) {
                ret = WOLFCLU_FATAL_ERROR;
            }

            if (ret == WOLFCLU_SUCCESS &&
                    wolfSSL_BIO_read(bioIn, in, inSz) <= 0) {
                ret = WOLFCLU_FATAL_ERROR;
            }

            if (ret == WOLFCLU_SUCCESS &&
                    wc_PemToDer(in, inSz, DH_PARAM_TYPE, &pDer, NULL, NULL,
                        NULL) != 0) {
                ret = WOLFCLU_FATAL_ERROR;
            }

            /* der should always be smaller then pem but check just in case */
            if (ret == WOLFCLU_SUCCESS && inSz < pDer->length) {
                ret = WOLFCLU_FATAL_ERROR;
            }

            if (ret == WOLFCLU_SUCCESS) {
                inSz = pDer->length;
                XMEMCPY(in, pDer->buffer, pDer->length);
            }

            if (ret == WOLFCLU_SUCCESS &&
                    wc_DhKeyDecode(in, &idx, &dh, inSz) != 0) {
                wolfCLU_LogError("Unable to decode input params");
                ret = WOLFCLU_FATAL_ERROR;
            }

            if (in != NULL)
                XFREE(in, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (pDer != NULL)
                wc_FreeDer(&pDer);
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        if (out != NULL) {
#ifdef WOLFCLU_NO_FILESYSTEM
            WOLFCLU_LOG(WOLFCLU_E0, "No filesystem support. Unable to open output file");
            ret = WOLFCLU_FATAL_ERROR;
#else
            bioOut = wolfSSL_BIO_new_file(out, "wb");
            if (bioOut == NULL) {
                wolfCLU_LogError("Unable to open output file %s",
                        optarg);
                ret = WOLFCLU_FATAL_ERROR;
            }
#endif
        }
        else {
            /* use stdout by default */
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
    }

    /* generate the dh parameters */
    if (ret == WOLFCLU_SUCCESS && bioIn == NULL) {
    #if defined(HAVE_FFDHE_4096)
        #if defined(HAVE_FIPS) && FIPS_VERSION_LE(2,0)
        if (modSz == 4096) {
            const DhParams* params = wc_Dh_ffdhe4096_Get();
            if (wc_DhSetKey(&dh, (byte*)params->p, params->p_len,
                        (byte*)params->g, params->g_len) != 0) {
                wolfCLU_LogError("Error setting named 4096 parameters");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
        else
        #elif (LIBWOLFSSL_VERSION_HEX > 0x05001000)
        if (modSz == 4096) {
            if (wc_DhSetNamedKey(&dh, WC_FFDHE_4096) != 0) {
                wolfCLU_LogError("Error setting named 4096 parameters");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
        else
        #else
        if (modSz == 4096) {
            const DhParams* params = wc_Dh_ffdhe4096_Get();
            if (wc_DhSetKey(&dh, (byte*)params->p, params->p_len,
                        (byte*)params->g, params->g_len) != 0) {
                wolfCLU_LogError("Error setting named 4096 parameters");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
        else
        #endif /* end of version check for using named parameters */
    #endif /* have 4096 named parameters */
        {
            #if defined(HAVE_FIPS) && FIPS_VERSION_LE(2,0)
            /* extra sanity check in FIPS v2 because a clear on sp_int for
             * unsupported mod size with wc_DhGenerateParams can cause issues */
            if (modSz != 1024 && modSz != 2048 && modSz != 3072) {
                wolfCLU_LogError("Unsupported parameters size");
                ret = WOLFCLU_FATAL_ERROR;
            }
            #endif

            if (ret == WOLFCLU_SUCCESS &&
                    wc_DhGenerateParams(&rng, modSz, &dh) != 0) {
                wolfCLU_LogError("Error generating parameters");
            #if !defined(HAVE_FFDHE_4096)
                if (modSz == 4096) {
                    wolfCLU_LogError("HAVE_FFDHE_4096 macro possibly needs "
                            "defined when building wolfSSL for 4096 params");
                }
            #endif
                ret = WOLFCLU_FATAL_ERROR;
            }
        }
    }

    /* print out the dh parameters */
    if (ret == WOLFCLU_SUCCESS && !noOut) {
        byte* outBuf = NULL;
        byte* pem    = NULL;
        word32 outBufSz = 0;
        int pemSz       = 0;

        if (wc_DhParamsToDer(&dh, NULL, &outBufSz) != LENGTH_ONLY_E) {
            wolfCLU_LogError("Unable to get output buffer size");
            ret = WOLFCLU_FATAL_ERROR;
        }

        if (ret == WOLFCLU_SUCCESS) {
            outBuf = (byte*)XMALLOC(outBufSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (outBuf == NULL) {
                ret = WOLFCLU_FATAL_ERROR;
            }
        }

        if (ret == WOLFCLU_SUCCESS &&
                wc_DhParamsToDer(&dh, outBuf, &outBufSz) <= 0) {
            ret = WOLFCLU_FATAL_ERROR;
        }

        if (ret == WOLFCLU_SUCCESS) {
            pemSz = wc_DerToPem(outBuf, outBufSz, NULL, 0, DH_PARAM_TYPE);
            if (pemSz > 0) {
                pem = (byte*)XMALLOC(pemSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                if (pem == NULL) {
                    ret = WOLFCLU_FATAL_ERROR;
                }
            }
            else {
                ret = WOLFCLU_FATAL_ERROR;
            }
        }

        if (ret == WOLFCLU_SUCCESS) {
            pemSz = wc_DerToPem(outBuf, outBufSz, pem, pemSz, DH_PARAM_TYPE);
            if (pemSz <= 0) {
                ret = WOLFCLU_FATAL_ERROR;
            }
        }

        if (ret == WOLFCLU_SUCCESS &&
                wolfSSL_BIO_write(bioOut, pem, pemSz) <= 0) {
            ret = WOLFCLU_FATAL_ERROR;
        }

        if (pem != NULL)
            XFREE(pem, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (outBuf != NULL)
            XFREE(outBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

     /* Check if parameters are valid */
    if (ret == WOLFCLU_SUCCESS && check){
        byte *p = NULL;
        byte *g = NULL;
        byte *q = NULL;
        word32 p_len = 0, g_len = 0, q_len = 0;

        /* Export DH parameters */
        if (wc_DhExportParamsRaw(&dh, p, &p_len, q, &q_len, g, &g_len) !=
                LENGTH_ONLY_E) {
            wolfCLU_LogError("Failed to get sizes for export DH params");
            ret = WOLFCLU_FATAL_ERROR;
        }

        if (ret == WOLFCLU_SUCCESS) {
            p = (byte*)XMALLOC(p_len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            q = (byte*)XMALLOC(q_len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            g = (byte*)XMALLOC(g_len, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (p == NULL || q == NULL || g == NULL) {
                wolfCLU_LogError("Failed to malloc DH params buffer");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }

        if (ret == WOLFCLU_SUCCESS) {
            if (wc_DhExportParamsRaw(&dh, p, &p_len, q, &q_len, g, &g_len) !=
                    0) {
                wolfCLU_LogError("Failed to export DH params");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }

        if (ret == WOLFCLU_SUCCESS) {
            if (wc_DhSetKey_ex(&dh, p, p_len, g, g_len, q, q_len) != 0) {
                wolfCLU_LogError("Failed to set/check DH params");
                ret = WOLFCLU_FATAL_ERROR;
            }
            else {
                WOLFCLU_LOG(WOLFCLU_L0, "DH params are valid.");
            }
        }

        if (p != NULL)
            XFREE(p, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (q != NULL)
            XFREE(q, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (g != NULL)
            XFREE(g, NULL, DYNAMIC_TYPE_TMP_BUFFER);
     }

    /* print out the dh key */
    if (ret == WOLFCLU_SUCCESS && genKey) {
        byte priv[WOLFSSL_MAX_DH_BITS/8];
        byte pub[WOLFSSL_MAX_DH_BITS/8];
        word32 privSz   = (word32)sizeof(priv);
        word32 pubSz    = (word32)sizeof(pub);
        byte* outBuf    = NULL;
        byte* pem       = NULL;
        word32 outBufSz = 0;
        word32 pemSz    = 0;

        if (wc_DhGenerateKeyPair(&dh, &rng, priv, &privSz, pub, &pubSz) != 0) {
            wolfCLU_LogError("Error making DH key");
            ret = WOLFCLU_FATAL_ERROR;
        }

        if (ret == WOLFCLU_SUCCESS) {
            /* get DER size (param has p,q,g and key has p,q,g,y,x) */
            if (wc_DhParamsToDer(&dh, NULL, &outBufSz) != LENGTH_ONLY_E) {
                wolfCLU_LogError("Unable to get output buffer size");
                ret = WOLFCLU_FATAL_ERROR;
            }
        }

        if (ret == WOLFCLU_SUCCESS) {
            /* size is p,q,g + x,y
             * x will be q size plus 64 bits
             * y will be result of g^x mod p */
            outBufSz = outBufSz + outBufSz + (64/WOLFSSL_BIT_SIZE);
            outBuf = (byte*)XMALLOC(outBufSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            if (outBuf == NULL) {
                ret = WOLFCLU_FATAL_ERROR;
            }

        }

        if (ret == WOLFCLU_SUCCESS) {
        #ifndef WOLFSSL_DH_EXTRA
            ret = wc_DhPrivKeyToDer(&dh, priv, privSz, outBuf, &outBufSz);
        #else
            ret = wc_DhPrivKeyToDer(&dh, outBuf, &outBufSz);
        #endif
            if (ret <= 0) {
                wolfCLU_LogError("Error converting DH key to buffer");
                ret = WOLFCLU_FATAL_ERROR;
            }
            else {
                outBufSz = (word32)ret;
                ret = WOLFCLU_SUCCESS;
            }
        }

        if (ret == WOLFCLU_SUCCESS) {
            pemSz = wc_DerToPem(outBuf, outBufSz, NULL, 0, DH_PRIVATEKEY_TYPE);
            if (pemSz > 0) {
                pem = (byte*)XMALLOC(pemSz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
                if (pem == NULL) {
                    ret = WOLFCLU_FATAL_ERROR;
                }
            }
            else {
                ret = WOLFCLU_FATAL_ERROR;
            }
        }

        if (ret == WOLFCLU_SUCCESS) {
            pemSz = wc_DerToPem(outBuf, outBufSz, pem, pemSz,
                    DH_PRIVATEKEY_TYPE);
            if (pemSz <= 0) {
                ret = WOLFCLU_FATAL_ERROR;
            }
        }

        if (ret == WOLFCLU_SUCCESS &&
                wolfSSL_BIO_write(bioOut, pem, pemSz) <= 0) {
            ret = WOLFCLU_FATAL_ERROR;
        }

        if (pem != NULL)
            XFREE(pem, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (outBuf != NULL)
            XFREE(outBuf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    wolfSSL_BIO_free(bioIn);
    wolfSSL_BIO_free(bioOut);

    wc_FreeDhKey(&dh);
    wc_FreeRng(&rng);

    return ret;
#else
    (void)argc;
    (void)argv;
    wolfCLU_LogError("DH support not compiled into wolfSSL");
    return WOLFCLU_FATAL_ERROR;
#endif
}


