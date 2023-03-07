/* clu_config.c
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
#include <wolfclu/wolfclu/clu_error_codes.h>
#include <wolfclu/wolfclu/x509/clu_parse.h>
#include <wolfclu/wolfclu/x509/clu_x509_sign.h>

#ifndef WOLFCLU_NO_FILESYSTEM

/* return WOLFCLU_SUCCESS on success */
static int wolfCLU_setAttributes(WOLFSSL_X509* x509, WOLFSSL_CONF* conf,
            char* sect)
{
    const char* current;
    int currentSz;

    currentSz = 0;
    current = wolfSSL_NCONF_get_string(conf, sect, "challengePassword");
    if (current != NULL) {
        currentSz = (int)XSTRLEN(current);
        wolfSSL_X509_REQ_add1_attr_by_NID(x509, NID_pkcs9_challengePassword,
                MBSTRING_ASC, (const unsigned char*)current, currentSz);
    }

    current = wolfSSL_NCONF_get_string(conf, sect, "unstructuredName");
    if (current != NULL) {
        currentSz = (int)XSTRLEN(current);
        wolfSSL_X509_REQ_add1_attr_by_NID(x509, NID_pkcs9_unstructuredName,
                MBSTRING_ASC, (const unsigned char*)current, currentSz);
    }

    return WOLFCLU_FAILURE;
}


#ifdef WOLFSSL_CERT_EXT
WOLFSSL_ASN1_OBJECT* wolfCLU_extenstionGetObjectNID(WOLFSSL_X509_EXTENSION *ext, int nid, int crit) {
    WOLFSSL_ASN1_OBJECT *obj;
    if (ext == NULL)
        return NULL;

    wolfSSL_X509_EXTENSION_set_critical(ext, crit);
    obj = wolfSSL_OBJ_nid2obj(nid);
    if (wolfSSL_X509_EXTENSION_set_object(ext, obj) != WOLFSSL_SUCCESS) {
        wolfSSL_X509_EXTENSION_free(ext);
        wolfSSL_ASN1_OBJECT_free(obj);
        return NULL;
    }
    wolfSSL_ASN1_OBJECT_free(obj);

    obj = wolfSSL_X509_EXTENSION_get_object(ext);
    if (obj == NULL) {
        wolfSSL_X509_EXTENSION_free(ext);
        return NULL;
    }

    return obj;
}

static WOLFSSL_X509_EXTENSION* wolfCLU_parseBasicConstraint(char* in, int crit)
{
    int   idx = 0; /* offset into string */
    char* word, *end, *str = in;
    char* deli = (char*)":";
    WOLFSSL_X509_EXTENSION *ext;
    WOLFSSL_ASN1_OBJECT *obj;

    if (str == NULL) {
        return NULL;
    }

    /* if critical key word was found, then advance string pointer past
     * 'critical,' */
    if (crit) {
        int inSz = (int)XSTRLEN(in);

        for (idx = 0; idx < inSz; idx++) {
            if (str[idx] == ',') break;
        }

        if (idx + 1 >= inSz) {
            WOLFCLU_LOG(WOLFCLU_E0, "bad basic constraint string in conf file");
            return NULL;
        }

        /* advance past any white spaces */
        for (idx = idx + 1; idx < inSz; idx++) {
            if (str[idx] != ' ') break;
        }
    }

    ext = wolfSSL_X509_EXTENSION_new();
    obj = wolfCLU_extenstionGetObjectNID(ext, NID_basic_constraints, crit);
    if (obj == NULL) {
        return NULL;
    }


    for (word = XSTRTOK(str + idx, deli, &end); word != NULL;
            word = XSTRTOK(NULL, deli, &end)) {
        if (word != NULL && XSTRNCMP(word, "CA", XSTRLEN(word)) == 0) {
            word = XSTRTOK(NULL, deli, &end);
            if (word != NULL) {
                int z, wordSz;

                wordSz = (int)XSTRLEN(word);
                for (z = 0; z < wordSz; z++)
                    word[z] = toupper(word[z]);
                if (XSTRNCMP(word, "TRUE", XSTRLEN(word)) == 0) {
                    obj->ca = 1;
                }
            }
        }

        if (word != NULL && XSTRNCMP(word, "pathlen", XSTRLEN(word)) == 0) {
            word = XSTRTOK(NULL, deli, &end);
            if (word != NULL) {
                if (obj->pathlen != NULL)
                    wolfSSL_ASN1_INTEGER_free(obj->pathlen);
                obj->pathlen = wolfSSL_ASN1_INTEGER_new();
                wolfSSL_ASN1_INTEGER_set(obj->pathlen, XATOI(word));
            }
        }
    }

    return ext;
}


static WOLFSSL_X509_EXTENSION* wolfCLU_parseSubjectKeyID(char* str, int crit,
        WOLFSSL_X509* x509)
{
    Cert cert; /* temporary to use existing subject key id api */
    WOLFSSL_X509_EXTENSION *ext = NULL;
    WOLFSSL_EVP_PKEY *pkey = NULL;
    char* word, *end;
    char* deli = (char*)",";

    if (x509 == NULL || str == NULL)
        return NULL;

    for (word = XSTRTOK(str, deli, &end); word != NULL;
            word = XSTRTOK(NULL, deli, &end)) {

        if (XSTRNCMP(word, "hash", XSTRLEN(word)) == 0) {
            WOLFSSL_ASN1_STRING *data;
            int  keyType;
            void *key = NULL;

            XMEMSET(&cert, 0, sizeof(Cert));
            keyType = wolfSSL_X509_get_pubkey_type(x509);

            pkey = wolfSSL_X509_get_pubkey(x509);
            if (pkey == NULL) {
                wolfCLU_LogError("no public key set to hash for subject key id");
                return NULL;
            }

            switch (keyType) {
                case RSAk:
                    key = pkey->rsa->internal;
                    keyType = RSA_TYPE;
                    break;

                case ECDSAk:
                    key = pkey->ecc->internal;
                    keyType = ECC_TYPE;
                    break;

                default:
                    wolfCLU_LogError("key type not yet supported");
            }

            if (wc_SetSubjectKeyIdFromPublicKey_ex(&cert, keyType, key) < 0) {
                wolfCLU_LogError("error hashing public key");
            }
            else {
                data = wolfSSL_ASN1_STRING_new();
                if (data != NULL) {
                    if (wolfSSL_ASN1_STRING_set(data, cert.skid, cert.skidSz)
                            != WOLFSSL_SUCCESS) {
                        wolfCLU_LogError("error setting the skid");
                    }
                    else {
                        ext = wolfSSL_X509V3_EXT_i2d(NID_subject_key_identifier,
                                crit, data);
                    }
                    wolfSSL_ASN1_STRING_free(data);
                }
            }
	    wolfSSL_EVP_PKEY_free(pkey);
        }
    }

    return ext;
}


static WOLFSSL_X509_EXTENSION* wolfCLU_parseKeyUsage(char* str, int crit,
        WOLFSSL_X509* x509)
{
    WOLFSSL_ASN1_STRING *data;
    WOLFSSL_X509_EXTENSION *ext = NULL;
    char* word, *end;
    char* deli = (char*)",";
    word16 keyUseFlag = 0;

    if (x509 == NULL || str == NULL)
        return NULL;

    for (word = XSTRTOK(str, deli, &end); word != NULL;
            word = XSTRTOK(NULL, deli, &end)) {

        /* remove empty spaces at beginning of word */
        int mxSz = (int)XSTRLEN(word);
        while (word[0] == ' ' && mxSz > 0) {
            word++;
            mxSz--;
        }

        if (XSTRNCMP(word, "digitalSignature", XSTRLEN(word)) == 0) {
            keyUseFlag |= KEYUSE_DIGITAL_SIG;
        }

        if (XSTRNCMP(word, "nonRepudiation", XSTRLEN(word)) == 0 ||
                XSTRNCMP(word, "contentCommitment", XSTRLEN(word)) == 0) {
            keyUseFlag |= KEYUSE_CONTENT_COMMIT;
        }

        if (XSTRNCMP(word, "keyEncipherment", XSTRLEN(word)) == 0) {
            keyUseFlag |= KEYUSE_KEY_ENCIPHER;
        }

        if (XSTRNCMP(word, "dataEncipherment", XSTRLEN(word)) == 0) {
            keyUseFlag |= KEYUSE_DATA_ENCIPHER;
        }

        if (XSTRNCMP(word, "keyAgreement", XSTRLEN(word)) == 0) {
            keyUseFlag |= KEYUSE_KEY_AGREE;
        }

        if (XSTRNCMP(word, "keyCertSign", XSTRLEN(word)) == 0) {
            keyUseFlag |= KEYUSE_KEY_CERT_SIGN;
        }

        if (XSTRNCMP(word, "cRLSign", XSTRLEN(word)) == 0) {
            keyUseFlag |= KEYUSE_CRL_SIGN;
        }

        if (XSTRNCMP(word, "encipherOnly", XSTRLEN(word)) == 0) {
            keyUseFlag |= KEYUSE_ENCIPHER_ONLY;
        }

        if (XSTRNCMP(word, "decipherOnly", XSTRLEN(word)) == 0) {
            keyUseFlag |= KEYUSE_DECIPHER_ONLY;
        }
    }

    data = wolfSSL_ASN1_STRING_new();
    if (data != NULL) {
        if (wolfSSL_ASN1_STRING_set(data, (byte*)&keyUseFlag, sizeof(word16))
                        != WOLFSSL_SUCCESS) {
            wolfCLU_LogError("error setting the key use");
        }
        else {
            ext = wolfSSL_X509V3_EXT_i2d(NID_key_usage, crit, data);
        }
        wolfSSL_ASN1_STRING_free(data);
    }
    return ext;
}


/* return WOLFCLU_SUCCESS on success */
static int wolfCLU_parseExtension(WOLFSSL_X509* x509, char* str, int nid,
        int* idx)
{
    WOLFSSL_X509_EXTENSION *ext = NULL;
    int   ret, crit = 0;

    if (XSTRSTR(str, "critical") != NULL) {
        crit = 1;
    }
    switch (nid) {
        case NID_basic_constraints:
            ext = wolfCLU_parseBasicConstraint(str, crit);
            break;
        case NID_subject_key_identifier:
            ext = wolfCLU_parseSubjectKeyID(str, crit, x509);
            break;
        case NID_authority_key_identifier:
            /* @TODO */
            break;
        case NID_key_usage:
            ext = wolfCLU_parseKeyUsage(str, crit, x509);
            break;

        default:
            WOLFCLU_LOG(WOLFCLU_L0, "unknown / supported nid %d value for extension",
                    nid);
    }

    if (ext != NULL) {
        ret = wolfSSL_X509_add_ext(x509, ext, -1);
        if (ret != WOLFSSL_SUCCESS) {
            wolfCLU_LogError("error %d adding extesion", ret);
        }
        *idx = *idx + 1;
        wolfSSL_X509_EXTENSION_free(ext);
    }
    return WOLFCLU_SUCCESS;
}


/* return WOLFCLU_SUCCESS on success, searches for IP's and DNS's */
static int wolfCLU_setAltNames(WOLFSSL_X509* x509, WOLFSSL_CONF* conf,
            char* sect)
{
    WOLFSSL_STACK *altNames;
    int i, ret = WOLFCLU_SUCCESS;

    if (sect == NULL) {
        return WOLFCLU_SUCCESS; /* none set */
    }

#ifndef WOLFSSL_ALT_NAMES
    WOLFCLU_LOG(WOLFCLU_L0, "Skipping alt names, recompile wolfSSL with WOLFSSL_ALT_NAMES...");
#else

    altNames = wolfSSL_NCONF_get_section(conf, sect);
    if (altNames != NULL) {
        int total;

        total = wolfSSL_sk_CONF_VALUE_num(altNames);
        for (i = 0; i < total; i++) {
            WOLFSSL_CONF_VALUE *c;
            WOLFSSL_ASN1_STRING *ipStr = NULL;
            char *s   = NULL;
            int   sSz = 0;
            int   type= 0;

            c = wolfSSL_sk_CONF_VALUE_value(altNames, i);
            if (c == NULL) {
                WOLFCLU_LOG(WOLFCLU_L0, "Unexpected null value found in alt "
                        "names stack");
                ret = WOLFCLU_FATAL_ERROR;
                break;
            }

            if (XSTRNCMP(c->name, "IP", 2) == 0) {
                ipStr = wolfSSL_a2i_IPADDRESS(c->value);

                if (ipStr != NULL) {
                    s   = (char*)wolfSSL_ASN1_STRING_data(ipStr);
                    sSz = wolfSSL_ASN1_STRING_length(ipStr);
                    type = ASN_IP_TYPE;

                }
                else {
                    wolfCLU_LogError("bad IP found %s", c->value);
                    ret = WOLFCLU_FATAL_ERROR;
                    break;
                }

            }

            if (XSTRNCMP(c->name, "DNS", 3) == 0) {
                type = ASN_DNS_TYPE;
                s = c->value;
                sSz = (int)XSTRLEN(c->value);
            }

            if (type == 0) {
                ret = WOLFCLU_FATAL_ERROR;
                break;
            }

            if (wolfSSL_X509_add_altname_ex(x509, s, sSz, type)
                    != WOLFSSL_SUCCESS) {
                wolfCLU_LogError("error adding alt name %s", c->value);
                if (ipStr != NULL)
                    wolfSSL_ASN1_STRING_free(ipStr);
                ret = WOLFCLU_FATAL_ERROR;
                break;
            }

            if (ipStr != NULL)
                wolfSSL_ASN1_STRING_free(ipStr);
        }
    }
#endif

    return ret;
}


/* return WOLFCLU_SUCCESS on success */
int wolfCLU_setExtensions(WOLFSSL_X509* x509, WOLFSSL_CONF* conf, char* sect)
{
    char *current;
    int  idx = 1;
    int  ret = WOLFCLU_SUCCESS;

    if (sect == NULL) {
        return WOLFCLU_SUCCESS; /* none set */
    }

    current = wolfSSL_NCONF_get_string(conf, sect, "basicConstraints");
    if (current != NULL) {
        wolfCLU_parseExtension(x509, current, NID_basic_constraints, &idx);
    }

    current = wolfSSL_NCONF_get_string(conf, sect, "subjectKeyIdentifier");
    if (current != NULL) {
        wolfCLU_parseExtension(x509, current, NID_subject_key_identifier, &idx);
    }

    current = wolfSSL_NCONF_get_string(conf, sect, "authorityKeyIdentifier");
    if (current != NULL) {
        wolfCLU_parseExtension(x509, current, NID_authority_key_identifier,
                &idx);
    }

    current = wolfSSL_NCONF_get_string(conf, sect, "keyUsage");
    if (current != NULL) {
        wolfCLU_parseExtension(x509, current, NID_key_usage, &idx);
    }

    current = wolfSSL_NCONF_get_string(conf, sect, "subjectAltName");
    if (current != NULL && current[0] == '@') {
        current = current+1;
        ret = wolfCLU_setAltNames(x509, conf, current);
    }
    return ret;
}
#else
int wolfCLU_setExtensions(WOLFSSL_X509* x509, WOLFSSL_CONF* conf, char* sect)
{
    (void)x509;
    (void)conf;
    (void)sect;

    wolfCLU_LogError("wolfSSL not compiled with cert extensions");
    return NOT_COMPILED_IN;
}
#endif /* WOLFSSL_CERT_EXT */


#define MAX_DIST_NAME 80
#define DEFAULT_STR_SZ 9
#define MIN_MAX_STR_SZ 5

static int CheckDisName(WOLFSSL_CONF* conf, char* sect, WOLFSSL_X509_NAME* name,
        const char* str, int nid, int strType, int noPrompt)
{
    int  ret = WOLFCLU_SUCCESS;
    long mn = 0;
    long mx = 0;
    FILE *fout = stdout;
    FILE *fin = stdin; /* defaulting to stdin but using a fd variable to make it
                        * easy for expanding to other inputs */
    char* curnt = NULL;
    char* deflt = NULL;
    char   *in = NULL;
    size_t  inSz;

    char* deflt_str = NULL;
    char* mn_str = NULL;
    char* mx_str = NULL;

    if (noPrompt) {
        curnt = wolfSSL_NCONF_get_string(conf, sect, str);
        if (curnt != NULL) {
            wolfCLU_AddNameEntry(name, strType, nid, curnt);
        }
        return ret;
    }

    inSz = (int)XSTRLEN(str);
    deflt_str = (char*)XMALLOC(inSz + DEFAULT_STR_SZ, NULL,
            DYNAMIC_TYPE_TMP_BUFFER);
    if (deflt_str == NULL) {
        ret = WOLFCLU_FATAL_ERROR;
    }
    else {
        XMEMSET(deflt_str, 0, inSz + DEFAULT_STR_SZ);
        XSTRNCPY(deflt_str, str, inSz);
        XSTRNCAT(deflt_str, "_default", inSz + DEFAULT_STR_SZ);
    }

    mn_str = (char*)XMALLOC(inSz + MIN_MAX_STR_SZ, NULL,
            DYNAMIC_TYPE_TMP_BUFFER);
    if (mn_str == NULL) {
        ret = WOLFCLU_FATAL_ERROR;
    }
    else {
        XMEMSET(mn_str, 0, inSz + MIN_MAX_STR_SZ);
        XSTRNCPY(mn_str, str, inSz);
        XSTRNCAT(mn_str, "_min", inSz + MIN_MAX_STR_SZ);
    }

    mx_str = (char*)XMALLOC(inSz + MIN_MAX_STR_SZ, NULL,
            DYNAMIC_TYPE_TMP_BUFFER);
    if (mx_str == NULL) {
        ret = WOLFCLU_FATAL_ERROR;
    }
    else {
        XMEMSET(mx_str, 0, inSz + MIN_MAX_STR_SZ);
        XSTRNCPY(mx_str, str, inSz);
        XSTRNCAT(mx_str, "_max", inSz + MIN_MAX_STR_SZ);
    }

    if (ret == WOLFCLU_SUCCESS) {
        curnt = wolfSSL_NCONF_get_string(conf, sect, str);
        if (curnt != NULL) {
            deflt = wolfSSL_NCONF_get_string(conf, sect, deflt_str);
            fprintf(fout, "%s [%s] : ", curnt, (deflt)?deflt:"");

            if (wolfCLU_getline(&in, &inSz, fin) > 1) {
                deflt = in;
            }

            if (deflt && XSTRCMP(deflt, ".") != 0) {
                if (wolfSSL_NCONF_get_number(conf, sect, mx_str, &mx) ==
                        WOLFSSL_SUCCESS && (long)XSTRLEN(deflt) > mx) {
                    WOLFCLU_LOG(WOLFCLU_E0,
                            "Name %s is larger than max %ld", deflt, mx);
                    ret = WOLFCLU_FATAL_ERROR;
                }

                if (wolfSSL_NCONF_get_number(conf, sect, mn_str, &mn) ==
                        WOLFSSL_SUCCESS && (long)XSTRLEN(deflt) < mn) {
                    WOLFCLU_LOG(WOLFCLU_E0,
                            "Name %s is smaller than min %ld", deflt, mn);
                    ret = WOLFCLU_FATAL_ERROR;
                }

                if (ret == WOLFCLU_SUCCESS) {
                    wolfCLU_AddNameEntry(name, strType, nid, deflt);
                }
            }
            free(in); in = NULL;
        }
    }

    XFREE(deflt_str, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(mn_str, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    XFREE(mx_str, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

/* extracts the distinguished names from the conf file and puts them into
 * the x509
 * returns WOLFCLU_SUCCESS on success */
static int wolfCLU_setDisNames(WOLFSSL_X509* x509, WOLFSSL_CONF* conf,
        char* sect, int noPrompt)
{
    int  i;
    int ret = WOLFCLU_SUCCESS;
    char buf[MAX_DIST_NAME];
    WOLFSSL_X509_NAME *name;
    FILE *fout = stdout;

    if (sect == NULL) {
        return WOLFCLU_SUCCESS; /* none set */
    }

    name = wolfSSL_X509_NAME_new();
    if (name == NULL) {
        return WOLFCLU_FATAL_ERROR;
    }

    fprintf(fout, "Enter '.' will result in the field being "
            "skipped.\nExamples of inputs are provided as [*]\n");

    ret = CheckDisName(conf, sect, name, "countryName", NID_countryName,
            CTC_PRINTABLE, noPrompt);
    if (ret == WOLFCLU_SUCCESS) {
        ret = CheckDisName(conf, sect, name, "stateOrProvinceName",
                NID_stateOrProvinceName, CTC_UTF8, noPrompt);
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = CheckDisName(conf, sect, name, "localityName", NID_localityName,
                CTC_UTF8, noPrompt);
    }


    /* check for additional organization names, keep going while successfully
     * finding an entry */
    if (ret == WOLFCLU_SUCCESS) {
        ret = CheckDisName(conf, sect, name, "organizationName",
                NID_organizationName, CTC_UTF8, noPrompt);
    }

    if (ret == WOLFCLU_SUCCESS) {
        for (i = 0; i < 10; i++) {
            XSNPRINTF(buf, sizeof(buf), "%d.organizationName", i);
            ret = CheckDisName(conf, sect, name, buf, NID_organizationName,
                    CTC_UTF8, noPrompt);
            if (ret != WOLFCLU_SUCCESS) {
                break;
            }
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = CheckDisName(conf, sect, name, "organizationalUnitName",
                NID_organizationalUnitName, CTC_UTF8, noPrompt);
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = CheckDisName(conf, sect, name, "commonName", NID_commonName,
                CTC_UTF8, noPrompt);
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = CheckDisName(conf, sect, name, "CN", NID_commonName, CTC_UTF8,
                noPrompt);
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = CheckDisName(conf, sect, name, "emailAddress", NID_emailAddress,
                CTC_UTF8, noPrompt);
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = CheckDisName(conf, sect, name, "name", NID_name,
                CTC_UTF8, noPrompt);
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = CheckDisName(conf, sect, name, "surname", NID_surname,
                CTC_UTF8, noPrompt);
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = CheckDisName(conf, sect, name, "initials", NID_initials,
                CTC_UTF8, noPrompt);
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = CheckDisName(conf, sect, name, "givenName", NID_givenName,
                CTC_UTF8, noPrompt);
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = CheckDisName(conf, sect, name, "dnQualifier", NID_dnQualifier,
                CTC_UTF8, noPrompt);
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = wolfSSL_X509_REQ_set_subject_name(x509, name);
    }

    wolfSSL_X509_NAME_free(name);
    return ret;
}


/* Make a new WOLFSSL_X509 based off of the config file read */
int wolfCLU_readConfig(WOLFSSL_X509* x509, char* config, char* sect, char* ext)
{
    int ret = WOLFCLU_SUCCESS;
    WOLFSSL_CONF *conf = NULL;
    long line = 0;
    long defaultBits = 0;
    char *defaultKey = NULL;
    int noPrompt = 0;
    char *curnt;

    conf = wolfSSL_NCONF_new(NULL);
    wolfSSL_NCONF_load(conf, config, &line);

    /* check if no prompting */
    curnt = wolfSSL_NCONF_get_string(conf, sect, "prompt");
    if (curnt != NULL && XSTRSTR(curnt, "no")) {
        noPrompt = 1;
    }

    wolfSSL_NCONF_get_number(conf, sect, "default_bits", &defaultBits);
    defaultKey = wolfSSL_NCONF_get_string(conf, sect, "default_keyfile");

    wolfCLU_setAttributes(x509, conf,
            wolfSSL_NCONF_get_string(conf, sect, "attributes"));
    if (ext == NULL) {
        (void)wolfCLU_setExtensions(x509, conf,
            wolfSSL_NCONF_get_string(conf, sect, "x509_extensions"));
    }
    else {
        /* extension was specifically set, error out if not found */
        if (wolfSSL_NCONF_get_section(conf, ext) == NULL) {
            wolfCLU_LogError("Unable to find certificate extension "
                    "section %s", ext);
            ret = WOLFCLU_FATAL_ERROR;
        }
        else {
            ret = wolfCLU_setExtensions(x509, conf, ext);
        }
    }

    if (ret == WOLFCLU_SUCCESS) {
        ret = wolfCLU_setDisNames(x509, conf,
            wolfSSL_NCONF_get_string(conf, sect, "distinguished_name"),
            noPrompt);
    }

    (void)defaultKey;
    wolfSSL_NCONF_free(conf);
    return ret;
}


int wolfCLU_GetTypeFromPKEY(WOLFSSL_EVP_PKEY* key)
{
    int keyType = 0;

    switch (wolfSSL_EVP_PKEY_base_id(key)) {
        case EVP_PKEY_RSA:
            keyType = RSAk;
            break;

        case EVP_PKEY_DSA:
            keyType = DSAk;
            break;

        case EVP_PKEY_EC:
            keyType = ECDSAk;
            break;

        case EVP_PKEY_DH:
            keyType = DHk;
            break;
    }
    return keyType;
}

#endif /* !WOLFCLU_NO_FILESYSTEM */
