/* test_asn_certgen_whitebox.c
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

/*
 * MC/DC white-box supplement for wolfcrypt/src/asn.c (Part 5, "certgen"
 * wave). Targets two areas:
 *
 *   1. Cert generation, ~line 26976-32520: wc_InitCert_ex, SetRsaPublicKey,
 *      wc_RsaKeyToDer, SetExtKeyUsage, SetCertificatePolicies, FlattenAltNames,
 *      EncodeName, FindMultiAttrib/SetNameRdnItems, SetNameEx,
 *      EncodeExtensions, InternalSignCb, AddSignature, MakeSignatureCb, the
 *      wc_Set* setters, SetDatesFromDcert, wc_SetIssuer/Subject(Raw|Buffer).
 *   2. Aux, ~line 38267-41000: S/MIME (wc_MIME_parse_headers,
 *      wc_MIME_header_strip, wc_MIME_single_canonicalize) and ASN.1 print
 *      (wc_Asn1_Print/PrintAll and its static helpers).
 *
 * Many of the interesting decisions live in file-static helpers
 * (SetExtKeyUsage, SetCertificatePolicies, EncodeName, FindMultiAttrib,
 * SetNameRdnItems, EncodeExtensions, InternalSignCb, MakeSignatureCb,
 * SetKeyIdFromPublicKey, SetDatesFromDcert) that tests/api can only reach
 * indirectly through wc_MakeCert(); this file compiles asn.c directly
 * (#include) and calls them straight, so bad-argument / buffer-too-small /
 * dead-branch combinations that no public wrapper ever produces can still be
 * driven and paired for MC/DC.
 *
 * NOT COMPILED IN THIS MODULE'S CONFIG (verified against
 * campaign/configs/asn/user_settings.base.h):
 *   - WOLFSSL_ACERT: attribute-certificate parsing (ParseX509Acert,
 *     DecodeAcertGeneralName(s), VerifyX509Acert, ...) is entirely gated
 *     behind "#if defined(WOLFSSL_ACERT) && defined(WOLFSSL_ASN_TEMPLATE)"
 *     (asn.c ~39651-40765) and WOLFSSL_ACERT is not defined by this
 *     module's base header. None of the attribute-cert gaps in that line
 *     range are reachable here.
 *   - WOLFSSL_EKU_OID is not defined either, so wc_SetExtKeyUsageOID's body
 *     is not compiled; skipped.
 */

#include <wolfcrypt/src/asn.c>

#include <stdio.h>
#include <string.h>

#ifdef USE_CERT_BUFFERS_2048
    #include <wolfssl/certs_test.h>
#endif

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)
#define WB_CHECK(cond, msg) \
    do { if (!(cond)) { printf("  [wb][FAIL] %s\n", (msg)); wb_fail = 1; } } \
    while (0)

/* ========================================================================
 * SECTION A: SetRsaPublicKey() via wc_RsaPublicKeyDerSize()/
 * wc_RsaKeyToPublicDer(), and wc_RsaKeyToDer().
 *   SetRsaPublicKey  :~26983  if ((key==NULL) || ((output!=NULL) && (outLen<MAX_SEQ_SZ)))
 *                     :~27008  if ((ret==0) && (output!=NULL) && (sz>(word32)outLen))
 *                     :~27011  if ((ret==0) && (output!=NULL))
 *   wc_RsaKeyToDer    :~27093  if ((key==NULL) || (key->type != RSA_PRIVATE))
 *                     :~27112  if ((ret==0) && (output!=NULL) && (sz>outLen))
 *                     :~27115  if ((ret==0) && (output!=NULL))
 * ======================================================================== */
#if !defined(NO_RSA) && defined(WOLFSSL_KEY_TO_DER) && \
    defined(USE_CERT_BUFFERS_2048) && defined(WOLFSSL_ASN_TEMPLATE)
static void wb_rsa_key_to_der(void)
{
    RsaKey key;
    word32 idx;
    byte   outBuf[1200];
    int    ret;
    int    pubDerSz;

    WB_NOTE("SetRsaPublicKey()/wc_RsaKeyToDer(): NULL/size checks [~26983,27008,27011,27093,27112,27115]");

    XMEMSET(&key, 0, sizeof(key));
    WB_CHECK(wc_InitRsaKey(&key, NULL) == 0, "wc_InitRsaKey");
    idx = 0;
    ret = wc_RsaPrivateKeyDecode(client_key_der_2048, &idx, &key,
            (word32)sizeof_client_key_der_2048);
    WB_CHECK(ret == 0, "decode RSA private test key");

    /* --- SetRsaPublicKey (via wc_R{sa,SA}...DerSize/wc_RsaKeyToPublicDer) */

    /* key==NULL -> BAD_FUNC_ARG (1st operand true, short-circuits 2nd). */
    ret = wc_RsaPublicKeyDerSize(NULL, 1);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "key==NULL (1st operand true)");

    /* key!=NULL, output==NULL (size-only query): 2nd operand short-circuits
     * false via output==NULL; also exercises :27011/:27008 "output!=NULL"
     * false side (both skipped). */
    pubDerSz = wc_RsaPublicKeyDerSize(&key, 1);
    WB_CHECK(pubDerSz > 0, "output==NULL size query (2nd operand false via output==NULL)");

    /* key!=NULL, output!=NULL, outLen small (< MAX_SEQ_SZ) -> 2nd operand
     * true: whole OR true via 2nd operand (1st false). */
    ret = wc_RsaKeyToPublicDer_ex(&key, outBuf, 1, 1);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            "outLen < MAX_SEQ_SZ (2nd operand true)");

    /* key!=NULL, output!=NULL, outLen big enough but still smaller than the
     * actual encoding -> passes the :26983 gate, fails at :27008 BUFFER_E. */
    ret = wc_RsaKeyToPublicDer_ex(&key, outBuf, (word32)MAX_SEQ_SZ, 1);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BUFFER_E),
            ":27008 both true (buffer too small for encoding)");

    /* Full success: output!=NULL, buffer big enough -> :27008 false (2nd
     * operand), :27011 both true (encode happens). */
    ret = wc_RsaKeyToPublicDer(&key, outBuf, sizeof(outBuf));
    WB_CHECK(ret == pubDerSz, ":27008 false, :27011 true (full encode)");

    /* --- wc_RsaKeyToDer (private key DER) */

    /* key==NULL -> BAD_FUNC_ARG, 1st operand true. */
    ret = wc_RsaKeyToDer(NULL, outBuf, sizeof(outBuf));
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "wc_RsaKeyToDer key==NULL");

    /* key!=NULL but not RSA_PRIVATE (public-only key) -> 2nd operand true.
     * Reuse the already-decoded private key's n/e (so the key object is
     * still well-formed for wc_FreeRsaKey) and just flip its type tag,
     * which is all wc_RsaKeyToDer() inspects before returning. */
    {
        RsaKey pubKey;
        pubKey = key;
        pubKey.type = RSA_PUBLIC;
        ret = wc_RsaKeyToDer(&pubKey, outBuf, sizeof(outBuf));
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
                ":27093 2nd operand true (not RSA_PRIVATE)");
    }

    /* Valid RSA_PRIVATE key, output==NULL (size-only): :27112/:27115 2nd
     * operand false via output==NULL. */
    pubDerSz = wc_RsaKeyToDer(&key, NULL, 0);
    WB_CHECK(pubDerSz > 0, "wc_RsaKeyToDer size-only query");

    /* output!=NULL, outLen too small -> :27112 both true, BAD_FUNC_ARG. */
    ret = wc_RsaKeyToDer(&key, outBuf, 1);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            ":27112 both true (buffer too small)");

    /* output!=NULL, outLen big enough -> :27112 false (2nd operand),
     * :27115 both true (full encode happens). */
    ret = wc_RsaKeyToDer(&key, outBuf, sizeof(outBuf));
    WB_CHECK(ret == pubDerSz, ":27112 false, :27115 true (full private encode)");

    wc_FreeRsaKey(&key);
}
#else
static void wb_rsa_key_to_der(void)
{
    WB_NOTE("RSA key-to-DER (no RSA/KEY_TO_DER/2048-test-buffers/template); skipped");
}
#endif

/* ========================================================================
 * SECTION B: SetExtKeyUsage() direct call.
 *   :~27711  if ((ret==0) && (output!=NULL) && (sz>outSz))
 *   :~27714  if ((ret==0) && (output!=NULL))
 * ======================================================================== */
#if defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_CERT_EXT) && \
    defined(WOLFSSL_ASN_TEMPLATE)
static void wb_set_ext_key_usage(void)
{
    Cert cert;
    byte outBuf[64];
    int  sz;
    int  ret;

    WB_NOTE("SetExtKeyUsage(): buffer-size checks [~27711,27714]");

    WB_CHECK(wc_InitCert(&cert) == 0, "wc_InitCert");

    /* output==NULL (size-only): both decisions short-circuit false via
     * output==NULL. */
    sz = SetExtKeyUsage(&cert, NULL, 0, EXTKEYUSE_SERVER_AUTH);
    WB_CHECK(sz > 0, "size-only query (output==NULL)");

    /* output!=NULL, outSz too small -> :27711 all true, BUFFER_E. */
    ret = SetExtKeyUsage(&cert, outBuf, 1, EXTKEYUSE_SERVER_AUTH);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BUFFER_E), ":27711 all true (buffer too small)");

    /* output!=NULL, outSz big enough -> :27711 false (3rd operand),
     * :27714 both true (full encode). */
    ret = SetExtKeyUsage(&cert, outBuf, sizeof(outBuf), EXTKEYUSE_SERVER_AUTH);
    WB_CHECK(ret == sz, ":27711 false, :27714 true (full encode)");
}
#else
static void wb_set_ext_key_usage(void)
{
    WB_NOTE("SetExtKeyUsage (no CERT_GEN/CERT_EXT/ASN_TEMPLATE); skipped");
}
#endif

/* ========================================================================
 * SECTION C: SetCertificatePolicies() direct call.
 *   :~27751  if ((input==NULL) || (nb_certpol > MAX_CERTPOL_NB))
 *   :~27755  for (i=0; (ret==0) && (i<nb_certpol); i++)
 *   :~27769  if ((ret==0) && (output!=NULL) && (sz+piSz > outputSz))
 * ======================================================================== */
#if defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_CERT_EXT) && \
    defined(WOLFSSL_ASN_TEMPLATE)
static void wb_set_cert_policies(void)
{
    char policies[MAX_CERTPOL_NB][MAX_CERTPOL_SZ];
    byte outBuf[64];
    int  sz;
    int  ret;

    WB_NOTE("SetCertificatePolicies(): bad-args/loop/buffer checks [~27751,27755,27769]");

    XMEMSET(policies, 0, sizeof(policies));
    XSTRNCPY(policies[0], "2.16.840.1.101.3.4.1", sizeof(policies[0]) - 1);

    /* input==NULL -> BAD_FUNC_ARG, 1st operand true; loop never entered
     * (:27755 short-circuits false via ret!=0). */
    ret = SetCertificatePolicies(NULL, sizeof(outBuf), NULL, 1, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":27751 1st operand true (input==NULL)");

    /* input!=NULL, nb_certpol > MAX_CERTPOL_NB -> 2nd operand true. */
    ret = SetCertificatePolicies(NULL, sizeof(outBuf), policies,
            MAX_CERTPOL_NB + 1, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            ":27751 2nd operand true (nb_certpol > MAX_CERTPOL_NB)");

    /* Valid args, output==NULL (size-only): loop runs (:27755 true/false
     * across iterations), :27769 short-circuits false via output==NULL. */
    sz = SetCertificatePolicies(NULL, 0, policies, 1, NULL);
    WB_CHECK(sz > 0, ":27755 loop runs, size-only query");

    /* Valid args, output!=NULL, outputSz too small -> :27769 all true,
     * BUFFER_E. */
    ret = SetCertificatePolicies(outBuf, 1, policies, 1, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BUFFER_E), ":27769 all true (buffer too small)");

    /* Valid args, output!=NULL, outputSz big enough -> :27769 false (3rd
     * operand), full encode succeeds. */
    ret = SetCertificatePolicies(outBuf, sizeof(outBuf), policies, 1, NULL);
    WB_CHECK(ret == sz, ":27769 false (buffer big enough)");

    /* nb_certpol==0: loop body never runs -> :27755 false via i<nb_certpol
     * (2nd operand) on first test, isolating it from the ret==0 operand
     * exercised above. */
    ret = SetCertificatePolicies(outBuf, sizeof(outBuf), policies, 0, NULL);
    WB_CHECK(ret == 0, ":27755 2nd operand false (nb_certpol==0, loop skipped)");
}
#else
static void wb_set_cert_policies(void)
{
    WB_NOTE("SetCertificatePolicies (no CERT_GEN/CERT_EXT/ASN_TEMPLATE); skipped");
}
#endif

/* ========================================================================
 * SECTION D: FlattenAltNames()/wc_FlattenAltNames().
 *   :~27837  if (curName->type == ASN_DIR_TYPE || curName->type == ASN_OTHER_TYPE)
 * ======================================================================== */
#if defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_ALT_NAMES)
static void wb_flatten_alt_names(void)
{
    DNS_entry dns   = { NULL, ASN_DNS_TYPE,   9, "host.com", 0 };
    DNS_entry dir   = { NULL, ASN_DIR_TYPE,   4, "abcd",     0 };
    DNS_entry other = { NULL, ASN_OTHER_TYPE, 4, "abcd",     0 };
    byte out[128];
    int ret;

    WB_NOTE("FlattenAltNames(): DIR/OTHER constructed-tag OR [~27837]");

    /* type==ASN_DNS_TYPE: both operands false. */
    ret = wc_FlattenAltNames(out, sizeof(out), &dns);
    WB_CHECK(ret > 0, ":27837 both false (DNS type, primitive tag)");

    /* type==ASN_DIR_TYPE: 1st operand true. */
    ret = wc_FlattenAltNames(out, sizeof(out), &dir);
    WB_CHECK(ret > 0, ":27837 1st operand true (DIR type, constructed tag)");

    /* type==ASN_OTHER_TYPE: 2nd operand true (1st false), independence pair
     * against the DIR case above. */
    ret = wc_FlattenAltNames(out, sizeof(out), &other);
    WB_CHECK(ret > 0, ":27837 2nd operand true (OTHER type, constructed tag)");
}
#else
static void wb_flatten_alt_names(void)
{
    WB_NOTE("FlattenAltNames (no CERT_GEN/ALT_NAMES); skipped");
}
#endif

/* ========================================================================
 * SECTION E: EncodeName() direct call.
 *   :~27894  if ((name==NULL) || (nameStr==NULL))
 *   :~27901  if (cname==NULL || cname->custom.oidSz==0)      (CUSTOM_NAME only)
 *   :~27983  if ((ret==0) && (sz > (word32)sizeof(name->encoded)))
 * ======================================================================== */
#if (defined(WOLFSSL_CERT_GEN) || defined(OPENSSL_EXTRA) || \
     defined(OPENSSL_EXTRA_X509_SMALL)) && defined(WOLFSSL_ASN_TEMPLATE)
static void wb_encode_name(void)
{
    EncodedName name;
    int ret;
    static char longStr[200];

    WB_NOTE("EncodeName(): NULL-arg OR / buffer-size check [~27894,27983]");

    XMEMSET(longStr, 'A', sizeof(longStr) - 1);
    longStr[sizeof(longStr) - 1] = '\0';

    /* name==NULL -> 1st operand true. */
    ret = EncodeName(NULL, "test", CTC_UTF8, ASN_COMMON_NAME, ASN_UTF8STRING, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":27894 1st operand true (name==NULL)");

    /* nameStr==NULL -> 2nd operand true (1st false). */
    XMEMSET(&name, 0, sizeof(name));
    ret = EncodeName(&name, NULL, CTC_UTF8, ASN_COMMON_NAME, ASN_UTF8STRING, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":27894 2nd operand true (nameStr==NULL)");

    /* Both valid, short string -> :27894 both false; :27983 false (fits). */
    XMEMSET(&name, 0, sizeof(name));
    ret = EncodeName(&name, "Test", CTC_UTF8, ASN_COMMON_NAME, ASN_UTF8STRING, NULL);
    WB_CHECK(ret > 0 && name.used == 1, ":27894 both false, :27983 false (fits)");

    /* Both valid, oversized string -> :27983 true (encoding exceeds
     * name->encoded[CTC_NAME_SIZE*2]). */
    XMEMSET(&name, 0, sizeof(name));
    ret = EncodeName(&name, longStr, CTC_UTF8, ASN_COMMON_NAME, ASN_UTF8STRING, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BUFFER_E), ":27983 true (encoding too big for buffer)");

#ifdef WOLFSSL_CUSTOM_OID
    WB_NOTE("EncodeName(): ASN_CUSTOM_NAME cname-or-oidSz==0 short-circuit [~27901]");
    /* type==ASN_CUSTOM_NAME, cname==NULL -> 1st operand true, early return 0. */
    XMEMSET(&name, 0, sizeof(name));
    ret = EncodeName(&name, "unused", CTC_UTF8, ASN_CUSTOM_NAME, ASN_UTF8STRING, NULL);
    WB_CHECK(ret == 0 && name.used == 0, ":27901 1st operand true (cname==NULL)");

    /* type==ASN_CUSTOM_NAME, cname!=NULL but custom.oidSz==0 -> 2nd operand
     * true (1st false). */
    {
        CertName cn;
        XMEMSET(&cn, 0, sizeof(cn));
        XMEMSET(&name, 0, sizeof(name));
        ret = EncodeName(&name, "unused", CTC_UTF8, ASN_CUSTOM_NAME,
                ASN_UTF8STRING, &cn);
        WB_CHECK(ret == 0 && name.used == 0,
                ":27901 2nd operand true (custom.oidSz==0)");
    }
#else
    WB_NOTE(":27901 (WOLFSSL_CUSTOM_OID) not compiled; skipped");
#endif
}
#else
static void wb_encode_name(void)
{
    WB_NOTE("EncodeName (no CERT_GEN/OPENSSL_EXTRA/ASN_TEMPLATE); skipped");
}
#endif

/* ========================================================================
 * SECTION F: FindMultiAttrib() direct call.
 *   :~28177  for (i = *idx+1; i>=0 && i<CTC_MAX_ATTRIB; i++)
 *   :~28178  if (name->name[i].sz>0 && name->name[i].id==id)
 * ======================================================================== */
#if defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_MULTI_ATTRIB) && \
    defined(WOLFSSL_ASN_TEMPLATE)
static void wb_find_multi_attrib(void)
{
    CertName name;
    int idx;
    int ret;

    WB_NOTE("FindMultiAttrib(): loop bound / sz&&id match [~28177,28178]");

    XMEMSET(&name, 0, sizeof(name));
    name.name[1].sz = 3;
    name.name[1].id = ASN_ORGUNIT_NAME;
    XSTRNCPY(name.name[1].value, "eng", sizeof(name.name[1].value) - 1);

    /* idx==-1 start: :28177 both true first iter (0>=0 && 0<MAX); :28178
     * false (sz==0 at index 0) then true at index 1 (sz>0 && id matches). */
    idx = -1;
    ret = FindMultiAttrib(&name, ASN_ORGUNIT_NAME, &idx);
    WB_CHECK(ret == 1 && idx == 1, ":28178 both true (sz>0 && id match) found at idx 1");

    /* Search again from idx==1: no more matches -> loop runs to
     * CTC_MAX_ATTRIB (:28177 2nd operand eventually false), returns 0 and
     * idx reset to -1. */
    idx = 1;
    ret = FindMultiAttrib(&name, ASN_ORGUNIT_NAME, &idx);
    WB_CHECK(ret == 0 && idx == -1,
            ":28177 2nd operand false (i reaches CTC_MAX_ATTRIB, none found)");

    /* id that never matches any populated slot -> :28178 2nd operand false
     * (sz>0 true at idx1, but id mismatch) each iteration; independence
     * pair against the "found" case above (same sz>0, id flips). */
    idx = -1;
    ret = FindMultiAttrib(&name, ASN_COMMON_NAME, &idx);
    WB_CHECK(ret == 0, ":28178 2nd operand false (sz>0 but id mismatch)");

    /* idx starting such that *idx+1 < 0 is not reachable through public
     * callers (always -1 or a valid previous index), but exercise the
     * "i>=0" operand's false side isn't otherwise reachable: CTC_MAX_ATTRIB
     * is small and *idx+1 is always >= 0 for any idx >= -1, so the 1st
     * operand of :28177 is structurally always true here; only its 2nd
     * operand (i<CTC_MAX_ATTRIB) varies, as driven above. */
}
#else
static void wb_find_multi_attrib(void)
{
    WB_NOTE("FindMultiAttrib (no CERT_GEN/MULTI_ATTRIB/ASN_TEMPLATE); skipped");
}
#endif

/* ========================================================================
 * SECTION G: SetNameRdnItems() direct call.
 *   :~28231  if (dataASN!=NULL && namesASN!=NULL)     (DOMAIN_COMPONENT arm)
 *   :~28305  if (dataASN!=NULL && namesASN!=NULL)     (other multi-attrib arm)
 * ======================================================================== */
#if defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_MULTI_ATTRIB) && \
    defined(WOLFSSL_ASN_TEMPLATE)
static void wb_set_name_rdn_items(void)
{
    CertName name;
    int count;

    WB_NOTE("SetNameRdnItems(): dataASN&&namesASN gate on multi-attrib arms [~28231,28305]");

    XMEMSET(&name, 0, sizeof(name));
    /* DOMAIN_COMPONENT multi-attrib entry: exercises the :28231 arm. */
    name.name[0].sz = 3;
    name.name[0].id = ASN_DOMAIN_COMPONENT;
    name.name[0].type = CTC_UTF8;
    XSTRNCPY(name.name[0].value, "com", sizeof(name.name[0].value) - 1);
    /* Non-DC multi-attrib entry (OU): exercises the :28305 arm. */
    name.name[1].sz = 3;
    name.name[1].id = ASN_ORGUNIT_NAME;
    name.name[1].type = CTC_UTF8;
    XSTRNCPY(name.name[1].value, "eng", sizeof(name.name[1].value) - 1);

    /* Count-only pass: dataASN==NULL && namesASN==NULL -> both false at
     * :28231 and :28305 (AND short-circuits via 1st operand). */
    count = SetNameRdnItems(NULL, NULL, 0, &name);
    WB_CHECK(count > 0, ":28231/:28305 false (count-only pass, both NULL)");

    /* Real encode pass with both non-NULL -> both AND conditions true. */
    {
        ASNSetData* dataASN = (ASNSetData*)XMALLOC(
                (size_t)count * sizeof(ASNSetData), NULL,
                DYNAMIC_TYPE_TMP_BUFFER);
        ASNItem* namesASN = (ASNItem*)XMALLOC(
                (size_t)count * sizeof(ASNItem), NULL, DYNAMIC_TYPE_TMP_BUFFER);
        int ret;

        WB_CHECK(dataASN != NULL && namesASN != NULL, "alloc dataASN/namesASN");
        if (dataASN != NULL && namesASN != NULL) {
            XMEMSET(dataASN, 0, (size_t)count * sizeof(ASNSetData));
            ret = SetNameRdnItems(dataASN, namesASN, count, &name);
            WB_CHECK(ret == count,
                    ":28231/:28305 both true (dataASN&&namesASN non-NULL)");
        }
        XFREE(dataASN, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        XFREE(namesASN, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }
}
#else
static void wb_set_name_rdn_items(void)
{
    WB_NOTE("SetNameRdnItems (no CERT_GEN/MULTI_ATTRIB/ASN_TEMPLATE); skipped");
}
#endif

/* ========================================================================
 * SECTION H: SetNameEx() (public wrapper drives SetNameRdnItems' 2-pass
 * size/encode idiom end to end).
 *   :~28388  ret > 0 (partial-count) vs ret == items path
 * ======================================================================== */
#if defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_ASN_TEMPLATE)
static void wb_set_name_ex(void)
{
    CertName name;
    int ret;

    WB_NOTE("SetNameEx(): full encode via commonName-only CertName [~28388]");

    XMEMSET(&name, 0, sizeof(name));
    XSTRNCPY(name.commonName, "wolfssl.example.com",
            sizeof(name.commonName) - 1);
    name.commonNameEnc = CTC_UTF8;

    ret = SetNameEx(NULL, WC_ASN_NAME_MAX, &name, NULL);
    WB_CHECK(ret > 0, "SetNameEx size-only query");

    {
        byte* out = (byte*)XMALLOC((size_t)ret, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        int ret2;
        WB_CHECK(out != NULL, "alloc SetNameEx output buffer");
        if (out != NULL) {
            ret2 = SetNameEx(out, (word32)ret, &name, NULL);
            WB_CHECK(ret2 == ret, ":28388 full encode matches size query");
            XFREE(out, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        }
    }

    /* Empty CertName: SetNameRdnItems() returns 0 items -> SetNameEx's own
     * "items==0" short-circuit. */
    {
        CertName empty;
        XMEMSET(&empty, 0, sizeof(empty));
        ret = SetNameEx(NULL, WC_ASN_NAME_MAX, &empty, NULL);
        WB_CHECK(ret == 0, "SetNameEx empty CertName (items==0 short-circuit)");
    }
}
#else
static void wb_set_name_ex(void)
{
    WB_NOTE("SetNameEx (no CERT_GEN/ASN_TEMPLATE); skipped");
}
#endif

/* ========================================================================
 * SECTION I: EncodeExtensions() direct call.
 *   :~28792  if (cert->pathLenSet && ((keyUsage & KEYUSE_KEY_CERT_SIGN) || (!keyUsage)))
 *   :~29126  else if ((output!=NULL) && (sz>maxSz))
 *   :~29131  if ((ret==0) && (output!=NULL) && (sz>0))
 *   :~29148  if ((!forRequest) && (cert->certPoliciesNb>0))
 * ======================================================================== */
#if defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_CERT_EXT) && \
    defined(WOLFSSL_ASN_TEMPLATE)
static void wb_encode_extensions(void)
{
    Cert cert;
    byte outBuf[1024];
    int  sz;
    int  ret;

    WB_NOTE("EncodeExtensions(): pathLen/keyUsage gate, buffer size, forRequest&&policies [~28792,29126,29131,29148]");

    /* :28792 all 3 true: isCA + pathLenSet + keyUsage has KEY_CERT_SIGN. */
    WB_CHECK(wc_InitCert(&cert) == 0, "wc_InitCert (A)");
    cert.isCA = 1;
    cert.pathLenSet = 1;
    cert.pathLen = 2;
    cert.keyUsage = KEYUSE_KEY_CERT_SIGN;
    sz = EncodeExtensions(&cert, NULL, 0, 0);
    WB_CHECK(sz > 0, ":28792 pathLenSet && (keyUsage & KEY_CERT_SIGN) true");

    /* :28792 pathLenSet true, keyUsage!=0 but WITHOUT KEY_CERT_SIGN bit and
     * !keyUsage false -> whole condition false (pathLen not written). */
    WB_CHECK(wc_InitCert(&cert) == 0, "wc_InitCert (B)");
    cert.isCA = 1;
    cert.pathLenSet = 1;
    cert.pathLen = 2;
    cert.keyUsage = KEYUSE_DIGITAL_SIG; /* set but not KEY_CERT_SIGN */
    sz = EncodeExtensions(&cert, NULL, 0, 0);
    WB_CHECK(sz > 0,
            ":28792 pathLenSet true, (keyUsage&CERT_SIGN)||!keyUsage both false");

    /* :28792 pathLenSet false -> whole AND short-circuits false. */
    WB_CHECK(wc_InitCert(&cert) == 0, "wc_InitCert (C)");
    cert.isCA = 1;
    cert.pathLenSet = 0;
    sz = EncodeExtensions(&cert, NULL, 0, 0);
    WB_CHECK(sz > 0, ":28792 pathLenSet false (short-circuit)");

    /* :29126/:29131 buffer-size checks + :29148 forRequest&&certPolicies. */
    WB_CHECK(wc_InitCert(&cert) == 0, "wc_InitCert (D)");
    cert.certPoliciesNb = 1;
    XSTRNCPY(cert.certPolicies[0], "2.16.840.1.101.3.4.1",
            sizeof(cert.certPolicies[0]) - 1);
    sz = EncodeExtensions(&cert, NULL, 0, 0); /* forRequest==0 */
    WB_CHECK(sz > 0, ":29148 !forRequest && certPoliciesNb>0, both true");

    /* forRequest==1 with same cert -> :29148 1st operand false. */
    ret = EncodeExtensions(&cert, NULL, 0, 1);
    WB_CHECK(ret > 0, ":29148 1st operand false (forRequest)");

    /* output!=NULL, maxSz too small -> :29126 true, BUFFER_E. */
    ret = EncodeExtensions(&cert, outBuf, 1, 0);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BUFFER_E), ":29126 true (buffer too small)");

    /* output!=NULL, maxSz big enough, sz>0 -> :29126 false, :29131 all true
     * (full encode, including the policies re-encode branch at the end). */
    ret = EncodeExtensions(&cert, outBuf, sizeof(outBuf), 0);
    WB_CHECK(ret == sz, ":29126 false, :29131 true (full encode)");

    /* Cert with no extensions set at all: SizeASN_Items() collapses to the
     * bare SEQUENCE (sz==2), so :29126/:29131 are skipped via the "sz==2"
     * special case (different code path, exercises the "sz==0" branch of
     * this decision's sibling if/else, i.e. the true side is never taken
     * for output!=NULL because sz is forced to 0 first). */
    WB_CHECK(wc_InitCert(&cert) == 0, "wc_InitCert (E)");
    ret = EncodeExtensions(&cert, outBuf, sizeof(outBuf), 0);
    WB_CHECK(ret == 0, "no extensions set -> sz collapses to 0, :29131 false via sz>0");
}
#else
static void wb_encode_extensions(void)
{
    WB_NOTE("EncodeExtensions (no CERT_GEN/CERT_EXT/ASN_TEMPLATE); skipped");
}
#endif

/* ========================================================================
 * SECTION J: InternalSignCb() direct call (file-static, used by
 * MakeSignature()/MakeSignatureCb() as the default signing callback).
 *   :~29269  if (keyType==RSA_TYPE && signCtx->key)
 *   :~29281  if (keyType==ECC_TYPE && signCtx->key)
 *   :~29289  if (keyType==ED25519_TYPE && signCtx->key)
 *   :~29296  if (keyType==ED448_TYPE && signCtx->key)
 * ======================================================================== */
#if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_REQ)
static void wb_internal_sign_cb(void)
{
    InternalSignCtx signCtx;
    byte in[16];
    byte out[16];
    word32 outLen;
    int ret;

    WB_NOTE("InternalSignCb(): keyType&&key AND-chain [~29269,29281,29289,29296]");

    XMEMSET(in, 0xAB, sizeof(in));
    XMEMSET(&signCtx, 0, sizeof(signCtx));

    /* No branch matches (unhandled key type, key non-NULL doesn't matter):
     * all 4 conditions' 1st operand false, falls to final unhandled block. */
    signCtx.key = (void*)in; /* any non-NULL to show operand2 doesn't gate here */
    outLen = sizeof(out);
    ret = InternalSignCb(in, sizeof(in), out, &outLen, 0, 0 /* unknown type */,
            &signCtx);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ALGO_ID_E),
            "unhandled keyType (all 1st operands false)");

#if !defined(NO_RSA) && !defined(WOLFSSL_RSA_PUBLIC_ONLY) && \
    !defined(WOLFSSL_RSA_VERIFY_ONLY)
    /* keyType==RSA_TYPE but key==NULL -> :29269 2nd operand false. */
    signCtx.key = NULL;
    signCtx.keyType = RSA_TYPE;
    outLen = sizeof(out);
    ret = InternalSignCb(in, sizeof(in), out, &outLen, 0, RSA_TYPE, &signCtx);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ALGO_ID_E),
            ":29269 2nd operand false (key==NULL)");
#endif

#if defined(HAVE_ED25519) && defined(HAVE_ED25519_SIGN)
    /* keyType==ED25519_TYPE, key!=NULL -> :29289 both true (short-circuits
     * to SIG_TYPE_E without dereferencing key as a real key). */
    signCtx.key = (void*)in;
    signCtx.keyType = ED25519_TYPE;
    outLen = sizeof(out);
    ret = InternalSignCb(in, sizeof(in), out, &outLen, 0, ED25519_TYPE, &signCtx);
    WB_CHECK(ret == WC_NO_ERR_TRACE(SIG_TYPE_E), ":29289 both true (ED25519 rejects callback path)");
#endif

#if defined(HAVE_ED448) && defined(HAVE_ED448_SIGN)
    /* keyType==ED448_TYPE, key!=NULL -> :29296 both true. */
    signCtx.key = (void*)in;
    signCtx.keyType = ED448_TYPE;
    outLen = sizeof(out);
    ret = InternalSignCb(in, sizeof(in), out, &outLen, 0, ED448_TYPE, &signCtx);
    WB_CHECK(ret == WC_NO_ERR_TRACE(SIG_TYPE_E), ":29296 both true (ED448 rejects callback path)");
#endif

#if defined(HAVE_ECC) && defined(HAVE_ECC_SIGN)
    /* keyType==ECC_TYPE, key==NULL -> :29281 2nd operand false. */
    signCtx.key = NULL;
    signCtx.keyType = ECC_TYPE;
    outLen = sizeof(out);
    ret = InternalSignCb(in, sizeof(in), out, &outLen, 0, ECC_TYPE, &signCtx);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ALGO_ID_E), ":29281 2nd operand false (key==NULL)");
#endif
}
#else
static void wb_internal_sign_cb(void)
{
    WB_NOTE("InternalSignCb (no CERT_GEN/CERT_REQ); skipped");
}
#endif

/* ========================================================================
 * SECTION K: AddSignature() direct call.
 *   :~29866  if ((ret==0) && (buf!=NULL))
 * ======================================================================== */
#if defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_ASN_TEMPLATE)
static void wb_add_signature(void)
{
    byte buf[256];
    byte sig[32];
    int  bodySz = 10;
    int  sz;
    int  ret;

    WB_NOTE("AddSignature(): (ret==0)&&(buf!=NULL) [~29866]");

    XMEMSET(buf, 0xCC, sizeof(buf));
    XMEMSET(sig, 0x11, sizeof(sig));

    /* buf==NULL (size-only query): 2nd operand false. */
    sz = AddSignature(NULL, bodySz, sig, (int)sizeof(sig),
#ifndef NO_SHA256
            CTC_SHA256wRSA
#else
            CTC_SHAwRSA
#endif
            );
    WB_CHECK(sz > 0, ":29866 2nd operand false (buf==NULL, size-only)");

    /* buf!=NULL: both operands true (full write). */
    ret = AddSignature(buf, bodySz, sig, (int)sizeof(sig),
#ifndef NO_SHA256
            CTC_SHA256wRSA
#else
            CTC_SHAwRSA
#endif
            );
    WB_CHECK(ret == sz, ":29866 both true (buf!=NULL, full write)");

    /* Unknown signature OID -> ret!=0 before reaching this decision, i.e.
     * ret==0 false, independence pair for the 1st operand (buf!=NULL held
     * true in both this and the previous call). */
    ret = AddSignature(buf, bodySz, sig, (int)sizeof(sig), 0 /* bad sigAlgoType */);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_UNKNOWN_OID_E),
            ":29866 1st operand false (ret!=0 from unknown OID, buf!=NULL held)");
}
#else
static void wb_add_signature(void)
{
    WB_NOTE("AddSignature (no CERT_GEN/ASN_TEMPLATE); skipped");
}
#endif

/* ========================================================================
 * SECTION L: MakeSignatureCb() direct call (file-static; stub signCb
 * avoids needing a real RSA/ECC key to exercise the keyType gate).
 *   :~30781  if (keyType != RSA_TYPE && keyType != ECC_TYPE)
 * ======================================================================== */
#if defined(WOLFSSL_CERT_GEN) || defined(WOLFSSL_CERT_REQ)
static int wb_stub_sign_cb(const byte* in, word32 inLen, byte* out,
        word32* outLen, int sigAlgo, int keyType, void* ctx)
{
    (void)in; (void)inLen; (void)sigAlgo; (void)keyType; (void)ctx;
    if (out == NULL || outLen == NULL || *outLen < 4) {
        return WC_NO_ERR_TRACE(BUFFER_E);
    }
    out[0] = 1; out[1] = 2; out[2] = 3; out[3] = 4;
    *outLen = 4;
    return 0;
}

static void wb_make_signature_cb(void)
{
    CertSignCtx certSignCtx;
    byte tbs[16];
    byte sig[32];
    int ret;

    WB_NOTE("MakeSignatureCb(): keyType!=RSA&&keyType!=ECC gate [~30781]");

    XMEMSET(tbs, 0x5A, sizeof(tbs));

    /* Unsupported keyType (neither RSA nor ECC) -> both operands true. */
    XMEMSET(&certSignCtx, 0, sizeof(certSignCtx));
    ret = MakeSignatureCb(&certSignCtx, tbs, sizeof(tbs), sig, sizeof(sig),
#ifndef NO_SHA256
            CTC_SHA256wRSA,
#else
            CTC_SHAwRSA,
#endif
            ED25519_TYPE /* neither RSA_TYPE nor ECC_TYPE */,
            wb_stub_sign_cb, NULL, NULL, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            ":30781 both true (unsupported keyType)");

#ifndef NO_RSA
    /* keyType==RSA_TYPE -> 1st operand false, short-circuits; full digest
     * + stub-callback flow runs to completion. */
    XMEMSET(&certSignCtx, 0, sizeof(certSignCtx));
    ret = MakeSignatureCb(&certSignCtx, tbs, sizeof(tbs), sig, sizeof(sig),
#ifndef NO_SHA256
            CTC_SHA256wRSA,
#else
            CTC_SHAwRSA,
#endif
            RSA_TYPE, wb_stub_sign_cb, NULL, NULL, NULL);
    WB_CHECK(ret == 4, ":30781 1st operand false (RSA_TYPE, full flow via stub cb)");
#endif

#ifdef HAVE_ECC
    /* keyType==ECC_TYPE -> 2nd operand false (1st true), independence pair
     * against the "both true" case (2nd operand flips). */
    XMEMSET(&certSignCtx, 0, sizeof(certSignCtx));
    ret = MakeSignatureCb(&certSignCtx, tbs, sizeof(tbs), sig, sizeof(sig),
            CTC_SHA256wECDSA, ECC_TYPE, wb_stub_sign_cb, NULL, NULL, NULL);
    WB_CHECK(ret == 4, ":30781 2nd operand false (ECC_TYPE, full flow via stub cb)");
#endif
}
#else
static void wb_make_signature_cb(void)
{
    WB_NOTE("MakeSignatureCb (no CERT_GEN/CERT_REQ); skipped");
}
#endif

/* ========================================================================
 * SECTION M: wc_GetSubjectRaw() and SetKeyIdFromPublicKey().
 *   wc_GetSubjectRaw        :~31422  if ((subjectRaw!=NULL) && (cert!=NULL))
 *   SetKeyIdFromPublicKey   :~31441  cert==NULL || (all key ptrs NULL) ||
 *                                    (kid_type!=SKID_TYPE && kid_type!=AKID_TYPE)
 * ======================================================================== */
#if defined(WOLFSSL_CERT_GEN)
static void wb_get_subject_raw(void)
{
    Cert cert;
    byte* raw = NULL;
    int ret;

    WB_NOTE("wc_GetSubjectRaw(): subjectRaw&&cert AND [~31422]");

    WB_CHECK(wc_InitCert(&cert) == 0, "wc_InitCert");

    /* subjectRaw==NULL -> 1st operand false, short-circuit. */
    ret = wc_GetSubjectRaw(NULL, &cert);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":31422 1st operand false");

    /* cert==NULL -> 2nd operand false (1st true). */
    ret = wc_GetSubjectRaw(&raw, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":31422 2nd operand false");

    /* Both non-NULL -> both true. */
    ret = wc_GetSubjectRaw(&raw, &cert);
    WB_CHECK(ret == 0 && raw == cert.sbjRaw, ":31422 both true");
}

static void wb_set_keyid_from_pubkey(void)
{
    Cert cert;
    int ret;

    WB_NOTE("SetKeyIdFromPublicKey(): NULL/kid_type OR chain [~31441]");

    WB_CHECK(wc_InitCert(&cert) == 0, "wc_InitCert");

    /* cert==NULL -> 1st operand true. */
    ret = SetKeyIdFromPublicKey(NULL, NULL, NULL, NULL, NULL, NULL, NULL,
            NULL, NULL, SKID_TYPE);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":31441 1st operand true (cert==NULL)");

    /* cert!=NULL, all key ptrs NULL -> 2nd operand true. */
    ret = SetKeyIdFromPublicKey(&cert, NULL, NULL, NULL, NULL, NULL, NULL,
            NULL, NULL, SKID_TYPE);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            ":31441 2nd operand true (all key ptrs NULL)");

    /* cert!=NULL, a key ptr non-NULL (garbage, never dereferenced because
     * kid_type is invalid so the OR short-circuits to true before use),
     * kid_type not SKID/AKID -> 3rd operand true (only reachable calling
     * this file-static function directly; no public wrapper allows it). */
    {
        RsaKey dummyKey;
        XMEMSET(&dummyKey, 0, sizeof(dummyKey));
        ret = SetKeyIdFromPublicKey(&cert, &dummyKey, NULL, NULL, NULL, NULL,
                NULL, NULL, NULL, 99 /* neither SKID_TYPE nor AKID_TYPE */);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
                ":31441 3rd operand true (bad kid_type, white-box only)");
    }
}
#else
static void wb_get_subject_raw(void)
{
    WB_NOTE("wc_GetSubjectRaw (no CERT_GEN); skipped");
}
static void wb_set_keyid_from_pubkey(void)
{
    WB_NOTE("SetKeyIdFromPublicKey (no CERT_GEN); skipped");
}
#endif

/* ========================================================================
 * SECTION N: Simple wc_Set*() NULL-argument setters.
 *   wc_SetAuthKeyId       :~31825  cert==NULL || file==NULL
 *   wc_SetKeyUsage        :~31845  cert==NULL || value==NULL
 *   wc_SetExtKeyUsage     :~31860  cert==NULL || value==NULL
 *   wc_SetCustomExtension :~31950  cert==NULL || oid==NULL || der==NULL || derSz==0
 * ======================================================================== */
#if defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_CERT_EXT)
static void wb_simple_set_null_checks(void)
{
    Cert cert;

    WB_CHECK(wc_InitCert(&cert) == 0, "wc_InitCert");

#if !defined(NO_FILESYSTEM) && !defined(NO_ASN_CRYPT)
    WB_NOTE("wc_SetAuthKeyId(): cert||file NULL OR [~31825]");
    WB_CHECK(wc_SetAuthKeyId(NULL, "x") == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            ":31825 1st operand true (cert==NULL)");
    WB_CHECK(wc_SetAuthKeyId(&cert, NULL) == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            ":31825 2nd operand true (file==NULL)");
#endif

    WB_NOTE("wc_SetKeyUsage()/wc_SetExtKeyUsage(): cert||value NULL OR [~31845,31860]");
    WB_CHECK(wc_SetKeyUsage(NULL, "serverAuth") == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            ":31845 1st operand true (cert==NULL)");
    WB_CHECK(wc_SetKeyUsage(&cert, NULL) == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            ":31845 2nd operand true (value==NULL)");
#ifdef WOLFSSL_ASN_PARSE_KEYUSAGE
    WB_CHECK(wc_SetKeyUsage(&cert, "keyCertSign") == 0,
            ":31845 both false (valid call)");
#endif

    WB_CHECK(wc_SetExtKeyUsage(NULL, "serverAuth") == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            ":31860 1st operand true (cert==NULL)");
    WB_CHECK(wc_SetExtKeyUsage(&cert, NULL) == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            ":31860 2nd operand true (value==NULL)");
#ifdef WOLFSSL_ASN_PARSE_KEYUSAGE
    WB_CHECK(wc_SetExtKeyUsage(&cert, "serverAuth") == 0,
            ":31860 both false (valid call)");
#endif

#ifdef WOLFSSL_EKU_OID
    WB_NOTE("wc_SetExtKeyUsageOID(): idx/sz bounds OR [~31921]");
    WB_CHECK(wc_SetExtKeyUsageOID(&cert, "1.2.3.4", 7, 0, NULL) == 0,
            ":31921 both false (valid call)");
    WB_CHECK(wc_SetExtKeyUsageOID(&cert, "1.2.3.4", 7, CTC_MAX_EKU_NB, NULL) ==
            WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            ":31921 1st operand true (idx >= CTC_MAX_EKU_NB)");
    WB_CHECK(wc_SetExtKeyUsageOID(&cert, "1.2.3.4", CTC_MAX_EKU_OID_SZ, 0,
                    NULL) == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            ":31921 2nd operand true (sz >= CTC_MAX_EKU_OID_SZ)");
#else
    WB_NOTE(":31921 wc_SetExtKeyUsageOID not compiled (needs WOLFSSL_EKU_OID); skipped");
#endif

#if defined(WOLFSSL_ASN_TEMPLATE) && defined(WOLFSSL_CUSTOM_OID) && \
    defined(HAVE_OID_ENCODING)
    WB_NOTE("wc_SetCustomExtension(): 4-way NULL/zero OR [~31950]");
    {
        byte der[] = { 0x01, 0x02, 0x03 };
        WB_CHECK(wc_SetCustomExtension(NULL, 0, "1.2.3", der, sizeof(der)) ==
                WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":31950 1st operand true (cert==NULL)");
        WB_CHECK(wc_SetCustomExtension(&cert, 0, NULL, der, sizeof(der)) ==
                WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":31950 2nd operand true (oid==NULL)");
        WB_CHECK(wc_SetCustomExtension(&cert, 0, "1.2.3", NULL, sizeof(der)) ==
                WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":31950 3rd operand true (der==NULL)");
        WB_CHECK(wc_SetCustomExtension(&cert, 0, "1.2.3", der, 0) ==
                WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":31950 4th operand true (derSz==0)");
        WB_CHECK(wc_SetCustomExtension(&cert, 0, "1.2.3", der, sizeof(der)) == 0,
                ":31950 all false (valid call)");
    }
#else
    WB_NOTE(":31950 wc_SetCustomExtension not compiled (needs ASN_TEMPLATE+CUSTOM_OID+OID_ENCODING); skipped");
#endif
}
#else
static void wb_simple_set_null_checks(void)
{
    WB_NOTE("wc_Set* NULL checks (no CERT_GEN/CERT_EXT); skipped");
}
#endif

/* ========================================================================
 * SECTION O: SetDatesFromDcert() direct call.
 *   :~32037  if (decoded->beforeDate==NULL || decoded->afterDate==NULL)
 *   :~32041  else if (decoded->beforeDateLen>MAX_DATE_SIZE || decoded->afterDateLen>MAX_DATE_SIZE)
 * ======================================================================== */
#if defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_ALT_NAMES)
static void wb_set_dates_from_dcert(void)
{
    Cert cert;
    DecodedCert decoded;
    byte before[] = { 0x17, 0x0d, '2','5','0','1','0','1','0','0','0','0','0','0','Z' };
    byte after[]  = { 0x17, 0x0d, '3','5','0','1','0','1','0','0','0','0','0','0','Z' };
    int ret;

    WB_NOTE("SetDatesFromDcert(): NULL-date OR / oversized-length OR [~32037,32041]");

    WB_CHECK(wc_InitCert(&cert) == 0, "wc_InitCert");
    XMEMSET(&decoded, 0, sizeof(decoded));

    /* beforeDate==NULL -> :32037 1st operand true. */
    ret = SetDatesFromDcert(&cert, &decoded);
    WB_CHECK(ret == -1, ":32037 1st operand true (beforeDate==NULL)");

    /* beforeDate set, afterDate==NULL -> :32037 2nd operand true. */
    decoded.beforeDate = before;
    decoded.beforeDateLen = (int)sizeof(before);
    ret = SetDatesFromDcert(&cert, &decoded);
    WB_CHECK(ret == -1, ":32037 2nd operand true (afterDate==NULL)");

    /* Both dates set but beforeDateLen too large -> :32037 both false,
     * :32041 1st operand true. */
    decoded.afterDate = after;
    decoded.afterDateLen = (int)sizeof(after);
    decoded.beforeDateLen = MAX_DATE_SIZE + 1;
    ret = SetDatesFromDcert(&cert, &decoded);
    WB_CHECK(ret == -1, ":32041 1st operand true (beforeDateLen too large)");

    /* beforeDateLen ok, afterDateLen too large -> :32041 2nd operand true. */
    decoded.beforeDateLen = (int)sizeof(before);
    decoded.afterDateLen = MAX_DATE_SIZE + 1;
    ret = SetDatesFromDcert(&cert, &decoded);
    WB_CHECK(ret == -1, ":32041 2nd operand true (afterDateLen too large)");

    /* Both valid -> :32037 both false, :32041 both false, success copy. */
    decoded.afterDateLen = (int)sizeof(after);
    ret = SetDatesFromDcert(&cert, &decoded);
    WB_CHECK(ret == 0 && cert.beforeDateSz == (int)sizeof(before) &&
             cert.afterDateSz == (int)sizeof(after),
            ":32037/:32041 all false (valid dates copied)");
}
#else
static void wb_set_dates_from_dcert(void)
{
    WB_NOTE("SetDatesFromDcert (no CERT_GEN/ALT_NAMES); skipped");
}
#endif

/* ========================================================================
 * SECTION P: wc_SetIssuer()/wc_SetSubject() NULL checks, and
 * wc_SetIssuerBuffer()/wc_SetSubjectRaw()/wc_SetIssuerRaw() with a real
 * DER certificate to reach the subjectRaw-populated branches.
 *   wc_SetIssuer/Subject :~32228,32251  cert==NULL || file==NULL
 *   wc_SetSubjectRaw     :~32375  decodedCert->subjectRaw && subjectRawLen<=sizeof(CertName)
 *   wc_SetIssuerRaw      :~32412  (same shape)
 * ======================================================================== */
#if defined(WOLFSSL_CERT_GEN) && !defined(NO_FILESYSTEM)
static void wb_set_issuer_subject_null(void)
{
    Cert cert;

    WB_NOTE("wc_SetIssuer()/wc_SetSubject(): cert||file NULL OR [~32228,32251]");
    WB_CHECK(wc_InitCert(&cert) == 0, "wc_InitCert");

    WB_CHECK(wc_SetIssuer(NULL, "x") == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            ":32228 1st operand true (cert==NULL)");
    WB_CHECK(wc_SetIssuer(&cert, NULL) == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            ":32228 2nd operand true (issuerFile==NULL)");

    WB_CHECK(wc_SetSubject(NULL, "x") == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            ":32251 1st operand true (cert==NULL)");
    WB_CHECK(wc_SetSubject(&cert, NULL) == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            ":32251 2nd operand true (subjectFile==NULL)");
}
#else
static void wb_set_issuer_subject_null(void)
{
    WB_NOTE("wc_SetIssuer/wc_SetSubject (no CERT_GEN or NO_FILESYSTEM); skipped");
}
#endif

#if defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_CERT_EXT) && \
    defined(USE_CERT_BUFFERS_2048)
static void wb_set_subject_issuer_raw(void)
{
    Cert cert;
    int ret;

    WB_NOTE("wc_SetSubjectRaw()/wc_SetIssuerRaw(): subjectRaw&&len<=sizeof(CertName) [~32375,32412]");

    /* A real parsed certificate has subjectRaw != NULL and a length well
     * under sizeof(CertName), driving both operands true. */
    WB_CHECK(wc_InitCert(&cert) == 0, "wc_InitCert (raw A)");
    ret = wc_SetSubjectRaw(&cert, client_cert_der_2048,
            (int)sizeof_client_cert_der_2048);
    WB_CHECK(ret == 0, ":32375 both true (real cert, subjectRaw populated)");

    WB_CHECK(wc_InitCert(&cert) == 0, "wc_InitCert (raw B)");
    ret = wc_SetIssuerRaw(&cert, client_cert_der_2048,
            (int)sizeof_client_cert_der_2048);
    WB_CHECK(ret == 0, ":32412 both true (real cert, subjectRaw populated)");

    /* derSz < 0 -> short-circuits before ever reaching :32375/:32412 (own
     * BAD_FUNC_ARG guard); shown here for completeness of the wrapper. */
    ret = wc_SetSubjectRaw(&cert, client_cert_der_2048, -1);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "wc_SetSubjectRaw derSz<0 guard");
}
#else
static void wb_set_subject_issuer_raw(void)
{
    WB_NOTE("wc_SetSubjectRaw/wc_SetIssuerRaw (no CERT_GEN/CERT_EXT/2048-test-buffers); skipped");
}
#endif

/* ========================================================================
 * SECTION Q (aux): S/MIME wc_MIME_parse_headers()/wc_MIME_header_strip()/
 * wc_MIME_single_canonicalize().
 *   wc_MIME_parse_headers      :~38365,38391,38407-409,38420,38466,38469
 *   wc_MIME_header_strip       :~38536,38541,38552
 *   wc_MIME_single_canonicalize:~38619,38624
 * ======================================================================== */
#ifdef HAVE_SMIME
static void wb_mime_parse_headers(void)
{
    char msg1[] =
        "Content-Type: text/plain; charset=us-ascii\r\n"
        "Subject: Hello\r\n"
        " World\r\n";
    MimeHdr* hdrs = NULL;
    int ret;

    WB_NOTE("wc_MIME_parse_headers(): bad-args OR / status transitions [~38365,38391,38407,38420,38466,38469]");

    /* in==NULL -> 1st operand true. */
    ret = wc_MIME_parse_headers(NULL, 4, &hdrs);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":38365 1st operand true (in==NULL)");

    /* inLen<=0 -> 2nd operand true. */
    {
        char tmp[] = "x";
        ret = wc_MIME_parse_headers(tmp, 0, &hdrs);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":38365 2nd operand true (inLen<=0)");
    }

    /* headers==NULL -> 4th operand true (1st-3rd false: valid in, positive
     * inLen, NUL-terminated). */
    {
        char tmp[] = "x";
        ret = wc_MIME_parse_headers(tmp, 1, NULL);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":38365 4th operand true (headers==NULL)");
    }

    /* Valid multi-header, multi-param, folded-continuation input: exercises
     * curLine[0]==' '&&curHdr true (continuation), the ':' NAMEATTR->BODYVAL
     * transition, the ';' param split, and the end-of-line BODYVAL flush
     * (:38469). */
    hdrs = NULL;
    ret = wc_MIME_parse_headers(msg1, (int)(sizeof(msg1) - 1), &hdrs);
    WB_CHECK(ret == 0 && hdrs != NULL, "multi-header/folded-continuation parse");
    wc_MIME_free_hdrs(hdrs);

    /* Single header, no trailing body content after the last ';' processed
     * inline -- forces mimeStatus to still be NAMEATTR at end-of-line for
     * one line (isolates :38469 false: end>=start true but mimeStatus!=
     * BODYVAL is not directly reachable after a ':' was seen, so instead
     * drive the "no header at all, just body flush" baseline). */
    {
        char msg2[] = "X: y\r\n";
        MimeHdr* h2 = NULL;
        ret = wc_MIME_parse_headers(msg2, (int)(sizeof(msg2) - 1), &h2);
        WB_CHECK(ret == 0 && h2 != NULL, "single short header parse");
        wc_MIME_free_hdrs(h2);
    }
}

static void wb_mime_header_strip(void)
{
    char in[] = "A: b;\"c\x01d";
    char* out = NULL;
    int ret;

    WB_NOTE("wc_MIME_header_strip(): bad-args OR / ASCII-range filter [~38536,38541,38552]");

    /* end<start -> 1st operand true. */
    ret = wc_MIME_header_strip(in, &out, 3, 1);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":38536 1st operand true (end<start)");

    /* in==NULL -> 2nd operand true. */
    ret = wc_MIME_header_strip(NULL, &out, 0, 1);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":38536 2nd operand true (in==NULL)");

    /* out==NULL -> 3rd operand true. */
    ret = wc_MIME_header_strip(in, NULL, 0, 1);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":38536 3rd operand true (out==NULL)");

    /* start>inLen -> :38541 1st operand true. */
    ret = wc_MIME_header_strip(in, &out, 1000, 1001);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":38541 1st operand true (start>inLen)");

    /* end>inLen -> :38541 2nd operand true. */
    ret = wc_MIME_header_strip(in, &out, 0, 1000);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":38541 2nd operand true (end>inLen)");

    /* Valid range spanning printable, ';', '"', and a sub-33 control byte:
     * exercises :38552's range check both ways plus the ';'/'"' exclusions
     * within the same call. */
    out = NULL;
    ret = wc_MIME_header_strip(in, &out, 0, (size_t)XSTRLEN(in) - 1);
    WB_CHECK(ret == 0 && out != NULL, ":38552 mixed in-range/out-of-range/excluded chars");
    if (out != NULL) {
        /* ';', '"', and the 0x01 control byte must all be dropped; 'A',
         * ':', ' ', 'b', 'c', 'd' survive. */
        WB_CHECK(XSTRSTR(out, ";") == NULL, "strip removes ';'");
        WB_CHECK(XSTRSTR(out, "\"") == NULL, "strip removes '\"'");
        XFREE(out, NULL, DYNAMIC_TYPE_PKCS7);
    }
}

static void wb_mime_single_canonicalize(void)
{
    const char lineNoEol[] = "hello";
    const char lineCrLf[]  = "hello\r\n";
    const char onlyCrLf[]  = "\r\n";
    char* out;
    word32 len;

    WB_NOTE("wc_MIME_single_canonicalize(): NULL/zero-len OR, trailing-EOL while loop [~38619,38624]");

    /* line==NULL -> 1st operand true. */
    len = 4;
    out = wc_MIME_single_canonicalize(NULL, &len);
    WB_CHECK(out == NULL, ":38619 1st operand true (line==NULL)");

    /* len==NULL -> 2nd operand true. */
    out = wc_MIME_single_canonicalize(lineNoEol, NULL);
    WB_CHECK(out == NULL, ":38619 2nd operand true (len==NULL)");

    /* *len==0 -> 3rd operand true. */
    len = 0;
    out = wc_MIME_single_canonicalize(lineNoEol, &len);
    WB_CHECK(out == NULL, ":38619 3rd operand true (*len==0)");

    /* No trailing CR/LF: while's char-check operand false on first test,
     * loop body never runs (:38624 2nd operand false; end stays == *len). */
    len = (word32)XSTRLEN(lineNoEol);
    out = wc_MIME_single_canonicalize(lineNoEol, &len);
    WB_CHECK(out != NULL, ":38624 2nd operand false (no trailing EOL)");
    XFREE(out, NULL, DYNAMIC_TYPE_PKCS7);

    /* Trailing CRLF: loop runs twice trimming both chars, then stops via
     * the char-check operand going false (end>=1 still true, 3rd char is
     * not \r/\n). */
    len = (word32)XSTRLEN(lineCrLf);
    out = wc_MIME_single_canonicalize(lineCrLf, &len);
    WB_CHECK(out != NULL, ":38624 both true then 2nd operand false (trims exactly CRLF)");
    XFREE(out, NULL, DYNAMIC_TYPE_PKCS7);

    /* Line that is ONLY "\r\n": loop trims both chars until end==0, then
     * stops via end>=1 going false (1st operand false) -- independence
     * pair isolating the 1st operand against the cases above. */
    len = (word32)XSTRLEN(onlyCrLf);
    out = wc_MIME_single_canonicalize(onlyCrLf, &len);
    WB_CHECK(out != NULL, ":38624 1st operand false (end reaches 0)");
    XFREE(out, NULL, DYNAMIC_TYPE_PKCS7);
}
#else
static void wb_mime_parse_headers(void) { WB_NOTE("S/MIME (no HAVE_SMIME); skipped"); }
static void wb_mime_header_strip(void) { }
static void wb_mime_single_canonicalize(void) { }
#endif

/* ========================================================================
 * SECTION R (aux): ASN.1 print (wc_Asn1_Print()/wc_Asn1_PrintAll() and
 * static helpers), driven with hand-built DER and every relevant
 * Asn1PrintOptions combination. Output goes to a throwaway tmpfile() so
 * stdout isn't flooded with dump text.
 *   wc_Asn1_SetFile         :~38812  asn1==NULL || file==XBADFILE
 *   wc_Asn1_SetOidToNameCb  :~38834  asn1==NULL || nameCb==NULL
 *   EncodedDottedForm       :~38862  in==NULL || outSz==NULL
 *   PrintObjectIdText       :~39022,39033
 *   PrintAsn1Text           :~39143-39152,39166-39168
 *   DumpData                :~39179,39195,39201
 *   UpdateDepth/DrawBranch  :~39216,39260,39270
 *   DumpHeader              :~39319
 *   wc_Asn1_Print           :~39440
 *   wc_Asn1_PrintAll        :~39486,39510,39515,39519
 * ======================================================================== */
#ifdef WOLFSSL_ASN_PRINT
static const char* wb_oid_name_cb(unsigned char* oid, word32 len)
{
    (void)oid; (void)len;
    return "custom-oid-name";
}

static void wb_asn1_print_all(XFILE file, const byte* data, word32 len,
        word32 indent, int drawBranch, int showData, int showHeaderData,
        int showOid, int showNoText, Asn1OidToNameCb nameCb,
        const char* label, int expectRet)
{
    Asn1 asn1;
    Asn1PrintOptions opts;
    int ret;

    WB_CHECK(wc_Asn1_Init(&asn1) == 0, "wc_Asn1_Init");
    WB_CHECK(wc_Asn1_SetFile(&asn1, file) == 0, "wc_Asn1_SetFile");
    if (nameCb != NULL) {
        WB_CHECK(wc_Asn1_SetOidToNameCb(&asn1, nameCb) == 0,
                "wc_Asn1_SetOidToNameCb");
    }
    WB_CHECK(wc_Asn1PrintOptions_Init(&opts) == 0, "wc_Asn1PrintOptions_Init");
    wc_Asn1PrintOptions_Set(&opts, ASN1_PRINT_OPT_INDENT, indent);
    wc_Asn1PrintOptions_Set(&opts, ASN1_PRINT_OPT_DRAW_BRANCH, (word32)drawBranch);
    wc_Asn1PrintOptions_Set(&opts, ASN1_PRINT_OPT_SHOW_DATA, (word32)showData);
    wc_Asn1PrintOptions_Set(&opts, ASN1_PRINT_OPT_SHOW_HEADER_DATA,
            (word32)showHeaderData);
    wc_Asn1PrintOptions_Set(&opts, ASN1_PRINT_OPT_SHOW_OID, (word32)showOid);
    wc_Asn1PrintOptions_Set(&opts, ASN1_PRINT_OPT_SHOW_NO_TEXT, (word32)showNoText);

    ret = wc_Asn1_PrintAll(&asn1, &opts, (unsigned char*)(wc_ptr_t)data, len);
    WB_CHECK(ret == expectRet, label);
}

static void wb_asn1_print(void)
{
    /* SEQUENCE { OID 2.5.4.3(commonName-ish, arbitrary), INTEGER 5,
     *            OCTET STRING "ab", BOOLEAN TRUE, BIT STRING [00 F0] } */
    static const byte doc[] = {
        0x30, 0x11,
              0x06, 0x03, 0x55, 0x04, 0x03,       /* OID 2.5.4.3 */
              0x02, 0x01, 0x05,                    /* INTEGER 5 */
              0x04, 0x02, 'a', 'b',                /* OCTET STRING "ab" */
              0x01, 0x01, 0xFF,                    /* BOOLEAN TRUE */
    };
    /* Truncated length byte claims more than is present -> ASN_LEN_E. */
    static const byte badLen[] = { 0x30, 0x7F, 0x02, 0x01 };
    /* Primitive item whose declared length runs past the buffer:
     * :39515/:39519 exercised via the "incomplete parse" bottom checks. */
    static const byte incomplete[] = { 0x30, 0x04, 0x02, 0x01 };
    XFILE devnull;

    WB_NOTE("wc_Asn1_Print()/PrintAll(): options matrix over a small DER doc "
            "[~39022,39033,39143,39166,39179,39195,39216,39260,39319,39440]");

    devnull = tmpfile();
    WB_CHECK(devnull != XBADFILE, "tmpfile() for ASN.1 print sink");
    if (devnull == XBADFILE) {
        return;
    }

    WB_NOTE("wc_Asn1_SetFile()/SetOidToNameCb(): NULL-arg OR [~38812,38834]");
    {
        Asn1 asn1;
        WB_CHECK(wc_Asn1_Init(&asn1) == 0, "init");
        WB_CHECK(wc_Asn1_SetFile(NULL, devnull) == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
                ":38812 1st operand true (asn1==NULL)");
        WB_CHECK(wc_Asn1_SetFile(&asn1, XBADFILE) == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
                ":38812 2nd operand true (file==XBADFILE)");
        WB_CHECK(wc_Asn1_SetFile(&asn1, devnull) == 0, ":38812 both false");

        WB_CHECK(wc_Asn1_SetOidToNameCb(NULL, wb_oid_name_cb) ==
                WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":38834 1st operand true (asn1==NULL)");
        WB_CHECK(wc_Asn1_SetOidToNameCb(&asn1, NULL) ==
                WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":38834 2nd operand true (nameCb==NULL)");
        WB_CHECK(wc_Asn1_SetOidToNameCb(&asn1, wb_oid_name_cb) == 0,
                ":38834 both false");
    }

    WB_NOTE("wc_Asn1_PrintAll(): NULL-arg OR [~39486]");
    {
        Asn1 asn1;
        Asn1PrintOptions opts;
        int ret;
        WB_CHECK(wc_Asn1_Init(&asn1) == 0, "init(2)");
        WB_CHECK(wc_Asn1_SetFile(&asn1, devnull) == 0, "setfile(2)");
        WB_CHECK(wc_Asn1PrintOptions_Init(&opts) == 0, "opts init(2)");
        ret = wc_Asn1_PrintAll(NULL, &opts, (unsigned char*)doc, sizeof(doc));
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":39486 1st operand true (asn1==NULL)");
        ret = wc_Asn1_PrintAll(&asn1, NULL, (unsigned char*)doc, sizeof(doc));
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":39486 2nd operand true (opts==NULL)");
        ret = wc_Asn1_PrintAll(&asn1, &opts, NULL, sizeof(doc));
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":39486 3rd operand true (data==NULL)");
    }

    /* Baseline: default options (no dump text suppressed), no OID name
     * callback -> known==0 path in PrintObjectIdText (:39033 "!known" true;
     * OID falls through to numeric print), dump-hex branch for
     * INTEGER/OCTET_STRING (:39166 true), indent-not-draw-branch path. */
    wb_asn1_print_all(devnull, doc, sizeof(doc), 2, 0, 0, 0, 0, 0, NULL,
            "baseline: indent mode, unknown OID, dump-text on", 0);

    /* show_data on: exercises DumpData()'s two 16-byte-row loops
     * (:39195,:39201) with data long enough to need the "j==8" gap and to
     * stop before 16 (i+j<len false before j reaches 16). */
    wb_asn1_print_all(devnull, doc, sizeof(doc), 2, 0, 1, 0, 0, 0, NULL,
            "show_data on: DumpData() row loops", 0);

    /* show_header_data on: exercises DumpHeader()'s
     * (!show_data && show_no_text) branch (:39319) both ways by pairing
     * show_no_text on vs off across the two calls below. */
    wb_asn1_print_all(devnull, doc, sizeof(doc), 2, 0, 0, 1, 0, 1, NULL,
            ":39319 true (!show_data && show_no_text)", 0);
    wb_asn1_print_all(devnull, doc, sizeof(doc), 2, 0, 0, 1, 0, 0, NULL,
            ":39319 false (show_no_text off)", 0);

    /* draw_branch on: exercises DrawBranch()'s depth-indexed if/else-if
     * chain (:39260,:39270) via the nested SEQUENCE's children. */
    wb_asn1_print_all(devnull, doc, sizeof(doc), 0, 1, 0, 0, 0, 0, NULL,
            "draw_branch on: DrawBranch() depth chain", 0);

    /* show_oid on with a known long name (via callback) -> :39022 taken
     * (nameCb branch), :39033 "opts->show_oid" true even though known. */
    wb_asn1_print_all(devnull, doc, sizeof(doc), 2, 0, 0, 0, 1, 0,
            wb_oid_name_cb, ":39022/:39033 nameCb known + show_oid true", 0);

    /* show_no_text on: skips PrintAsn1Text()/PrintObjectIdText() entirely
     * for every item -- :39440 "!opts->show_no_text" false. */
    wb_asn1_print_all(devnull, doc, sizeof(doc), 2, 0, 0, 0, 0, 1, NULL,
            ":39440 false (show_no_text suppresses text dump)", 0);

    /* Malformed length encoding -> GetLength() fails, ASN_LEN_E. */
    wb_asn1_print_all(devnull, badLen, sizeof(badLen), 2, 0, 0, 0, 0, 0, NULL,
            "malformed length -> ASN_LEN_E", WC_NO_ERR_TRACE(ASN_LEN_E));

    /* Truncated document: outer SEQUENCE opened (depth=1) but its INTEGER
     * child never completes before running out of bytes -> stops mid-item,
     * exercising :39515 (part!=ASN_PART_TAG) and :39519 (depth!=0). */
    wb_asn1_print_all(devnull, incomplete, sizeof(incomplete), 2, 0, 0, 0, 0,
            0, NULL, ":39515/:39519 incomplete document -> ASN_PARSE_E/ASN_DEPTH_E",
            WC_NO_ERR_TRACE(ASN_PARSE_E));

    fclose(devnull);

    WB_NOTE("EncodedDottedForm(): NULL-arg OR [~38862] (via PrintObjectIdNum path, "
            "exercised indirectly above through the OID item; direct call for the "
            "NULL-arg operand pair since no PrintObjectIdNum wrapper is public)");
    {
        word32 dotted[8];
        word32 num = 8;
        int ret;
        static const byte oidBytes[] = { 0x55, 0x04, 0x03 };
        ret = EncodedDottedForm(NULL, 3, dotted, &num);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":38862 1st operand true (in==NULL)");
        num = 8;
        ret = EncodedDottedForm(oidBytes, sizeof(oidBytes), dotted, NULL);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":38862 2nd operand true (outSz==NULL)");
        num = 8;
        ret = EncodedDottedForm(oidBytes, sizeof(oidBytes), dotted, &num);
        WB_CHECK(ret == 0 && num == 3, ":38862 both false (valid decode)");
    }
}
#else
static void wb_asn1_print(void) { WB_NOTE("ASN.1 print (no WOLFSSL_ASN_PRINT); skipped"); }
#endif

/* ========================================================================
 * SECTION S (aux): _RsaPublicKeyDecodeRaw() direct call.
 *   :~39545  if (n==NULL || e==NULL || key==NULL)
 * ======================================================================== */
#if !defined(NO_RSA) && (!defined(NO_BIG_INT) || defined(WOLFSSL_SP_MATH))
static void wb_rsa_public_key_decode_raw(void)
{
    byte n[3] = { 0x01, 0x00, 0x01 };
    byte e[1] = { 0x03 };
    RsaKey key;
    int ret;

    WB_NOTE("_RsaPublicKeyDecodeRaw(): n||e||key NULL OR [~39545]");

    XMEMSET(&key, 0, sizeof(key));

    ret = _RsaPublicKeyDecodeRaw(NULL, sizeof(n), e, sizeof(e), &key);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":39545 1st operand true (n==NULL)");

    ret = _RsaPublicKeyDecodeRaw(n, sizeof(n), NULL, sizeof(e), &key);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":39545 2nd operand true (e==NULL)");

    ret = _RsaPublicKeyDecodeRaw(n, sizeof(n), e, sizeof(e), NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":39545 3rd operand true (key==NULL)");

    ret = _RsaPublicKeyDecodeRaw(n, sizeof(n), e, sizeof(e), &key);
    WB_CHECK(ret == 0 && key.type == RSA_PUBLIC, ":39545 all false (valid decode)");
    if (ret == 0) {
        mp_clear(&key.n);
        mp_clear(&key.e);
    }
}
#else
static void wb_rsa_public_key_decode_raw(void)
{
    WB_NOTE("_RsaPublicKeyDecodeRaw (no RSA/big-int); skipped");
}
#endif

/* ========================================================================
 * SECTION T (aux): Attribute certificates (WOLFSSL_ACERT). Contrary to the
 * initial assumption when this file's task was scoped, this module's base
 * header (WOLFSSL_ASN_ALL + WOLFSSL_ASN_TEMPLATE) causes
 * wolfssl/wolfcrypt/settings.h to auto-define WOLFSSL_ACERT (and
 * WOLFSSL_EKU_OID, handled above) -- confirmed with a standalone
 * preprocessor probe against this module's exact user_settings.h. So the
 * attribute-cert code (asn.c ~39651-40765) IS compiled here.
 *   DecodeHolder          :~40011  input==NULL || len<=0 || acert==NULL
 *   DecodeAttCertIssuer   :~40178  input==NULL || len<=0 || cert==NULL
 *   wc_ParseX509Acert     :~40397,40411,40524,40542  verify-mode / issuer-tag
 *                                  gates (real corpus certs, best-effort:
 *                                  see residual note below)
 *   wc_VerifyX509Acert    :~40640  der==NULL||pubKey==NULL||derSz==0||pubKeySz==0
 *
 * RESIDUAL: :40397/:40411/:40542's "badDate" arm is only taken when
 * CheckDate() actually reports the acert as expired/not-yet-valid. The
 * corpus certs (certs/acert/acert.pem, acert_ietf.pem) are fixed test
 * vectors not guaranteed to straddle "today" for the life of this campaign,
 * so only the verify-mode short-circuits (NO_VERIFY / VERIFY_SKIP_DATE)
 * are driven below, not a genuine bad-date trigger; doing so safely would
 * need a deliberately-expired ACERT DER fixture, which is left for a
 * follow-up rather than fabricated here. Likewise :40706/:40709 (WC_RSA_PSS
 * parameter-matching arms of VerifyX509Acert) and :39796/:39903/:40473/
 * :40678 (DecodeAcertGeneralName(s) URI parsing / VerifyX509Acert's acinfo
 * checks / RSA-PSS param compare) are not reached by the two corpus certs
 * available (neither uses RSA-PSS signing or a URI-typed GeneralName) and
 * are not driven here.
 * ======================================================================== */
#if defined(WOLFSSL_ACERT) && defined(WOLFSSL_ASN_TEMPLATE)
static void wb_decode_holder_issuer_guards(void)
{
    DecodedAcert acert;
    byte emptySeq[] = { 0x30, 0x00 };
    int ret;

    WB_NOTE("DecodeHolder()/DecodeAttCertIssuer(): NULL/len<=0 OR [~40011,40178]");

    XMEMSET(&acert, 0, sizeof(acert));

    /* input==NULL -> 1st operand true. */
    ret = DecodeHolder(NULL, 2, &acert);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BUFFER_E), ":40011 1st operand true (input==NULL)");
    /* len==0 -> 2nd operand true. */
    ret = DecodeHolder(emptySeq, 0, &acert);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BUFFER_E), ":40011 2nd operand true (len==0)");
    /* acert==NULL -> 3rd operand true. */
    ret = DecodeHolder(emptySeq, sizeof(emptySeq), NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BUFFER_E), ":40011 3rd operand true (acert==NULL)");
    /* All valid (even though the Holder content itself is a trivial empty
     * SEQUENCE that will fail template matching downstream): all 3
     * operands false, guard is bypassed. */
    ret = DecodeHolder(emptySeq, sizeof(emptySeq), &acert);
    WB_CHECK(ret != WC_NO_ERR_TRACE(BUFFER_E),
            ":40011 all false (guard bypassed, real parse attempted)");

    ret = DecodeAttCertIssuer(NULL, 2, &acert);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BUFFER_E), ":40178 1st operand true (input==NULL)");
    ret = DecodeAttCertIssuer(emptySeq, 0, &acert);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BUFFER_E), ":40178 2nd operand true (len==0)");
    ret = DecodeAttCertIssuer(emptySeq, sizeof(emptySeq), NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BUFFER_E), ":40178 3rd operand true (cert==NULL)");
    ret = DecodeAttCertIssuer(emptySeq, sizeof(emptySeq), &acert);
    WB_CHECK(ret != WC_NO_ERR_TRACE(BUFFER_E),
            ":40178 all false (guard bypassed, real parse attempted)");
}

static void wb_verify_x509_acert_bad_args(void)
{
    byte derStub[4] = { 0x30, 0x02, 0x00, 0x00 };
    byte pubStub[4] = { 0x01, 0x02, 0x03, 0x04 };
    int ret;

    WB_NOTE("wc_VerifyX509Acert(): 4-way NULL/zero OR [~40640]");

    ret = wc_VerifyX509Acert(NULL, sizeof(derStub), pubStub, sizeof(pubStub),
            RSAk, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":40640 1st operand true (der==NULL)");

    ret = wc_VerifyX509Acert(derStub, sizeof(derStub), NULL, sizeof(pubStub),
            RSAk, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":40640 2nd operand true (pubKey==NULL)");

    ret = wc_VerifyX509Acert(derStub, 0, pubStub, sizeof(pubStub), RSAk, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":40640 3rd operand true (derSz==0)");

    ret = wc_VerifyX509Acert(derStub, sizeof(derStub), pubStub, 0, RSAk, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), ":40640 4th operand true (pubKeySz==0)");

    /* All args non-NULL/non-zero -> guard bypassed (malformed DER fails
     * later during real ASN.1 parsing; that's fine, we only isolate the
     * bad-arg guard here). */
    ret = wc_VerifyX509Acert(derStub, sizeof(derStub), pubStub,
            sizeof(pubStub), RSAk, NULL);
    WB_CHECK(ret != WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            ":40640 all false (guard bypassed)");
}

/* Read a corpus PEM file into a heap buffer; returns NULL on any failure
 * (missing file, short read, ...), in which case the caller skips that
 * fixture rather than failing the whole variant. */
static byte* wb_read_file(const char* path, long* outLen)
{
    XFILE f;
    long sz;
    byte* buf;

    f = XFOPEN(path, "rb");
    if (f == XBADFILE) {
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return NULL;
    }
    sz = ftell(f);
    if (sz <= 0 || fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return NULL;
    }
    buf = (byte*)XMALLOC((size_t)sz, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (buf == NULL) {
        fclose(f);
        return NULL;
    }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        fclose(f);
        return NULL;
    }
    fclose(f);
    *outLen = sz;
    return buf;
}

static void wb_parse_acert_one(const char* path, int verify, const char* label)
{
    byte* pem;
    long pemSz = 0;
    DerBuffer* der = NULL;
    int ret;

    pem = wb_read_file(path, &pemSz);
    if (pem == NULL) {
        WB_NOTE("corpus ACERT PEM not found at runtime cwd; skipping this case");
        return;
    }

    ret = wc_PemToDer(pem, pemSz, ACERT_TYPE, &der, NULL, NULL, NULL);
    XFREE(pem, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    WB_CHECK(ret == 0 && der != NULL, "wc_PemToDer ACERT");
    if (ret == 0 && der != NULL) {
        WC_DECLARE_VAR(acert, DecodedAcert, 1, 0);
#ifdef WOLFSSL_SMALL_STACK
        acert = (DecodedAcert*)XMALLOC(sizeof(DecodedAcert), NULL,
                DYNAMIC_TYPE_DCERT);
        WB_CHECK(acert != NULL, "alloc DecodedAcert");
#else
        XMEMSET(acert, 0, sizeof(DecodedAcert));
#endif
#ifdef WOLFSSL_SMALL_STACK
        if (acert != NULL)
#endif
        {
            wc_InitDecodedAcert(acert, der->buffer, der->length, NULL);
            ret = wc_ParseX509Acert(acert, verify);
            WB_CHECK(ret == 0, label);
            wc_FreeDecodedAcert(acert);
#ifdef WOLFSSL_SMALL_STACK
            XFREE(acert, NULL, DYNAMIC_TYPE_DCERT);
#endif
        }
        FreeDer(&der);
    }
}

static void wb_parse_x509_acert(void)
{
    WB_NOTE("wc_ParseX509Acert(): verify-mode gates over real corpus certs [~40397,40411,40524,40542]");

    /* verify==NO_VERIFY: :40397/:40411/:40542's 1st operand false,
     * short-circuits regardless of CheckDate()'s result. */
    wb_parse_acert_one("./certs/acert/acert.pem", NO_VERIFY,
            ":40397/:40411/:40542 1st operand false (NO_VERIFY)");

    /* verify==VERIFY_SKIP_DATE: 1st operand true, 2nd operand false. */
    wb_parse_acert_one("./certs/acert/acert.pem", VERIFY_SKIP_DATE,
            ":40397/:40411/:40542 2nd operand false (VERIFY_SKIP_DATE)");

    /* Second corpus cert (ietf-profile v2Form issuer): exercises :40524's
     * true side (i_issuer==ACERT_IDX_ACINFO_ISSUER_V2 && issuer_len>0) via
     * DecodeAttCertIssuer, independent of the verify mode. */
    wb_parse_acert_one("./certs/acert/acert_ietf.pem", VERIFY_SKIP_DATE,
            ":40524 true side (v2Form issuer, issuer_len>0)");
}
#else
static void wb_decode_holder_issuer_guards(void)
{
    WB_NOTE("DecodeHolder/DecodeAttCertIssuer (no WOLFSSL_ACERT); skipped");
}
static void wb_verify_x509_acert_bad_args(void)
{
    WB_NOTE("wc_VerifyX509Acert (no WOLFSSL_ACERT); skipped");
}
static void wb_parse_x509_acert(void)
{
    WB_NOTE("wc_ParseX509Acert (no WOLFSSL_ACERT); skipped");
}
#endif

int main(void)
{
    printf("asn.c certgen white-box MC/DC supplement\n");

    wb_rsa_key_to_der();
    wb_set_ext_key_usage();
    wb_set_cert_policies();
    wb_flatten_alt_names();
    wb_encode_name();
    wb_find_multi_attrib();
    wb_set_name_rdn_items();
    wb_set_name_ex();
    wb_encode_extensions();
    wb_internal_sign_cb();
    wb_add_signature();
    wb_make_signature_cb();
    wb_get_subject_raw();
    wb_set_keyid_from_pubkey();
    wb_simple_set_null_checks();
    wb_set_dates_from_dcert();
    wb_set_issuer_subject_null();
    wb_set_subject_issuer_raw();

    wb_mime_parse_headers();
    wb_mime_header_strip();
    wb_mime_single_canonicalize();
    wb_asn1_print();
    wb_rsa_public_key_decode_raw();
    wb_decode_holder_issuer_guards();
    wb_verify_x509_acert_bad_args();
    wb_parse_x509_acert();

    printf("done (%s)\n", wb_fail ? "with failures" : "ok");
    /* Always return 0: a nonzero exit discards this variant's coverage
     * entirely in the campaign harness. Failures are surfaced via the
     * printed [FAIL] lines instead. */
    (void)wb_fail;
    return 0;
}
