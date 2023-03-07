/* clu_certgen_ed25519.c
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
#include <wolfclu/wolfclu/certgen/clu_certgen.h>

#ifndef WOLFCLU_NO_FILESYSTEM 

void free_things_ed25519(byte** a, byte** b, byte** c, ed25519_key* d, ed25519_key* e,
                                                                     WC_RNG* f);

int make_self_signed_ed25519_certificate(char* keyPath, char* certOut)
{
    int ret = 0;

    Cert newCert;
    ed25519_key key;
    WC_RNG rng;

    int keyFileSz;
    XFILE keyFile;
    XFILE file = NULL;
    byte* keyBuf = NULL;
    int certBufSz;
    byte* certBuf = NULL;

    int pemBufSz;
    byte* pemBuf = NULL;
    XFILE pemFile = NULL;

    keyFile = XFOPEN(keyPath, "rb");
    if (keyFile == NULL) {
        wolfCLU_LogError("unable to open key file %s", keyPath);
        return BAD_FUNC_ARG;
    }

    XFSEEK(keyFile, 0, SEEK_END);
    keyFileSz = (int)XFTELL(keyFile);
    keyBuf = (byte*)XMALLOC(keyFileSz, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (keyBuf == NULL) {
        return MEMORY_E;
    }
    if (XFSEEK(keyFile, 0, SEEK_SET) != 0 || (int)XFREAD(keyBuf, 1, keyFileSz, keyFile) != keyFileSz) {
        XFCLOSE(keyFile);
        return WOLFCLU_FAILURE;
    }
    XFCLOSE(keyFile);

    ret = wc_ed25519_init(&key);
    if (ret != 0) {
        wolfCLU_LogError("Failed to initialize ed25519 key\nRET: %d", ret);
        XFREE(keyBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }

    ret = wc_InitRng(&rng);
    if (ret != 0) {
        wolfCLU_LogError("Failed to initialize rng.\nRET: %d", ret);
        XFREE(keyBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }

    ret = wc_ed25519_import_private_key(keyBuf,
                                        ED25519_KEY_SIZE,
                                        keyBuf + ED25519_KEY_SIZE,
                                        ED25519_KEY_SIZE, &key);
    XFREE(keyBuf, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (ret != 0 ) {
        wolfCLU_LogError("Failed to decode private key.\nRET: %d", ret);
        return ret;
    }

    wc_InitCert(&newCert);
    char country[CTC_NAME_SIZE];
    char province[CTC_NAME_SIZE];
    char city[CTC_NAME_SIZE];
    char org[CTC_NAME_SIZE];
    char unit[CTC_NAME_SIZE];
    char commonName[CTC_NAME_SIZE];
    char email[CTC_NAME_SIZE];
    char daysValid[CTC_NAME_SIZE];

    WOLFCLU_LOG(WOLFCLU_L0, "Enter your countries 2 digit code (ex: United States -> US): ");
    if (XFGETS(country,CTC_NAME_SIZE, stdin) == NULL) {
        return WOLFCLU_FAILURE;
    }
    country[CTC_NAME_SIZE-1] = '\0';
    WOLFCLU_LOG(WOLFCLU_L0, "Enter the name of the province you are located at: ");
    if (XFGETS(province,CTC_NAME_SIZE, stdin) == NULL) {
        return WOLFCLU_FAILURE;
    }
    WOLFCLU_LOG(WOLFCLU_L0, "Enter the name of the city you are located at: ");
    if (XFGETS(city,CTC_NAME_SIZE, stdin) == NULL) {
        return WOLFCLU_FAILURE;
    }
    WOLFCLU_LOG(WOLFCLU_L0, "Enter the name of your orginization: ");
    if (XFGETS(org,CTC_NAME_SIZE, stdin) == NULL) {
        return WOLFCLU_FAILURE;
    }
    WOLFCLU_LOG(WOLFCLU_L0, "Enter the name of your unit: ");
    if (XFGETS(unit,CTC_NAME_SIZE, stdin) == NULL) {
        return WOLFCLU_FAILURE;
    }
    WOLFCLU_LOG(WOLFCLU_L0, "Enter the common name of your domain: ");
    if (XFGETS(commonName,CTC_NAME_SIZE, stdin) == NULL) {
        return WOLFCLU_FAILURE;
    }
    WOLFCLU_LOG(WOLFCLU_L0, "Enter your email address: ");
    if (XFGETS(email,CTC_NAME_SIZE, stdin) == NULL) {
        return WOLFCLU_FAILURE;
    }
    WOLFCLU_LOG(WOLFCLU_L0, "Enter the number of days this certificate should be valid: ");
    if (XFGETS(daysValid,CTC_NAME_SIZE, stdin) == NULL) {
        return WOLFCLU_FAILURE;
    }

    XSTRNCPY(newCert.subject.country, country, CTC_NAME_SIZE);
    XSTRNCPY(newCert.subject.state, province, CTC_NAME_SIZE);
    XSTRNCPY(newCert.subject.locality, city, CTC_NAME_SIZE);
    XSTRNCPY(newCert.subject.org, org, CTC_NAME_SIZE);
    XSTRNCPY(newCert.subject.unit, unit, CTC_NAME_SIZE);
    XSTRNCPY(newCert.subject.commonName, commonName, CTC_NAME_SIZE);
    XSTRNCPY(newCert.subject.email, email, CTC_NAME_SIZE);
    newCert.daysValid = XATOI(daysValid);
    newCert.isCA    = 0;
    newCert.sigType = CTC_ED25519;

    certBuf = (byte*)XMALLOC(FOURK_SZ, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (certBuf == NULL) {
        wolfCLU_LogError("Failed to initialize buffer to stort certificate.");
        return -1;
    }
    XMEMSET(certBuf, 0, FOURK_SZ);

    ret = wc_MakeCert_ex(&newCert, certBuf, FOURK_SZ, ED25519_TYPE, &key, &rng);
    if (ret < 0) {
        wolfCLU_LogError("Failed to make certificate.");
        return ret;
    }
    WOLFCLU_LOG(WOLFCLU_L0, "MakeCert returned %d", ret);

    ret = wc_SignCert_ex(newCert.bodySz, newCert.sigType, certBuf, FOURK_SZ,
                                                      ED25519_TYPE, &key, &rng);
    if (ret < 0) {
        wolfCLU_LogError("Failed to sign certificate.");
        return ret;
    }
    WOLFCLU_LOG(WOLFCLU_L0, "SignCert returned %d", ret);

    certBufSz = ret;

    WOLFCLU_LOG(WOLFCLU_L0, "Successfully created new certificate");
    WOLFCLU_LOG(WOLFCLU_L0, "Writing newly generated certificate to file \"%s\"",
                                                                 certOut);
    file = XFOPEN(certOut, "wb");
    if (!file) {
        wolfCLU_LogError("failed to open file: %s", certOut);
        return -1;
    }

    ret = (int)XFWRITE(certBuf, 1, certBufSz, file);
    XFCLOSE(file);
    WOLFCLU_LOG(WOLFCLU_L0, "Successfully output %d bytes", ret);

/*---------------------------------------------------------------------------*/
/* convert the der to a pem and write it to a file */
/*---------------------------------------------------------------------------*/

    WOLFCLU_LOG(WOLFCLU_L0, "Convert the der cert to pem formatted cert");

    pemBuf = (byte*)XMALLOC(FOURK_SZ, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
    if (pemBuf == NULL) {
        wolfCLU_LogError("Failed to initialize pem buffer.");
        return -1;
    }
    XMEMSET(pemBuf, 0, FOURK_SZ);

    pemBufSz = wc_DerToPem(certBuf, certBufSz, pemBuf, FOURK_SZ, CERT_TYPE);
    if (pemBufSz < 0) {
        wolfCLU_LogError("Failed to convert from der to pem.");
        return -1;
    }

    WOLFCLU_LOG(WOLFCLU_L0, "Resulting pem buffer is %d bytes", pemBufSz);

    pemFile = XFOPEN(certOut, "wb");
    if (!pemFile) {
        wolfCLU_LogError("failed to open file: %s", certOut);
        return -1;
    }
    XFWRITE(pemBuf, 1, pemBufSz, pemFile);
    XFCLOSE(pemFile);
    WOLFCLU_LOG(WOLFCLU_L0, "Successfully converted the der to pem. Result is in:  %s\n",
                                                                 certOut);

    free_things_ed25519(&pemBuf, &certBuf, NULL, &key, NULL, &rng);
    return 1;
}

void free_things_ed25519(byte** a, byte** b, byte** c, ed25519_key* d, ed25519_key* e,
                                                                      WC_RNG* f)
{
    if (a != NULL) {
        if (*a != NULL) {
            XFREE(*a, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            *a = NULL;
        }
    }
    if (b != NULL) {
        if (*b != NULL) {
            XFREE(*b, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            *b = NULL;
        }
    }
    if (c != NULL) {
        if (*c != NULL) {
            XFREE(*c, HEAP_HINT, DYNAMIC_TYPE_TMP_BUFFER);
            *c = NULL;
        }
    }

    wc_ed25519_free(d);
    wc_ed25519_free(e);
    wc_FreeRng(f);

}
#endif
