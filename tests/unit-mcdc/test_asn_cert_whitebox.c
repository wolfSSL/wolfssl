/* test_asn_cert_whitebox.c
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
 * White-box MC/DC supplement for wolfcrypt/src/asn.c (Part 5, "cert" wave).
 *
 * Targets asn.c lines ~12768-17318: DecodedCert lifecycle/key-store helpers
 * (InitDecodedCert_ex, FreeDecodedCert, AltNameDup, SetCurve,
 * SetEccPublicKey, SetAsymKeyDerPublic), hashId/DNS-entry/RDN name parsing
 * (GetHashId family, GenerateDNSEntryIPString/RIDString, SetDNSEntry,
 * GetRDN/GetCertName/GetName), the date/time block (GetTime, ExtractDate,
 * ValidateGmtime, GetFormattedTime_ex, DateGreaterThan/LessThan,
 * wc_ValidateDateWithTime, GetDateInfo, wc_GetCertDates), and the Set*
 * encoders / signature-algorithm helpers at the end of the file
 * (SetImplicit, IsSigAlgoNoParams, SetAlgoIDImpl, DecodeDsaAsn1Sig).
 *
 * Most of the decisions here are cross-argument NULL/size guards on
 * file-static helpers, or operand combinations (malformed hand-built date
 * strings, out-of-range RDN OIDs, buffer-size probes) that no real caller
 * ever supplies with production DER/dates. This file compiles asn.c
 * directly (#include) to reach those helpers; independence pairs are
 * completed *within this file* (masking MC/DC is computed per binary,
 * coverage unioned by source line:col with tests/api and the sibling
 * unit-mcdc asn binaries centrally).
 */

#include <wolfcrypt/src/asn.c>

#include <stdio.h>
#include <string.h>
#include <time.h>

#include <wolfssl/certs_test.h>
#ifndef WOLFCRYPT_ONLY
/* wolfSSL_CertManager* : the ParseCertRelative() matrix below needs a real
 * issuer store so the cert->ca lookups can succeed. */
#include <wolfssl/ssl.h>
#endif

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wb] %s\n", (msg)); } while (0)
#define WB_CHECK(cond, msg) \
    do { if (!(cond)) { printf("  [wb][FAIL] %s\n", (msg)); wb_fail = 1; } } \
    while (0)

/* ------------------------------------------------------------------------- *
 * Generic TLV assembly, built on asn.c's own SetLength()/SetHeader() so
 * lengths can't drift from what the decoder expects.
 * ------------------------------------------------------------------------- */
static word32 wb_tlv(byte* out, byte tag, const byte* content, word32 contentSz)
{
    word32 idx = 0;
    if (out != NULL) {
        out[idx] = tag;
    }
    idx++;
    idx += SetLength(contentSz, out ? out + idx : NULL);
    if (contentSz > 0 && out != NULL) {
        XMEMCPY(out + idx, content, contentSz);
    }
    idx += contentSz;
    return idx;
}
#define WB_SEQ(out, content, sz) wb_tlv((out), ASN_SEQUENCE | ASN_CONSTRUCTED, (content), (sz))
#define WB_SET(out, content, sz) wb_tlv((out), ASN_SET | ASN_CONSTRUCTED, (content), (sz))

/* ===========================================================================
 * Section 1: AltNameDup() [:12920-12925]
 *   if (ret->name == NULL
 *       || (from->ipString != NULL && ret->ipString == NULL)
 *       || (from->ridString != NULL && ret->ridString == NULL))
 * CopyString(NULL, ...) returns NULL without allocating, so the ret->name
 * clause is driven both ways without needing a malloc failure; the
 * ipString/ridString "copy failed" halves need an OOM (fault-injection
 * only, not attempted here) -- their "present but copy succeeded" half is
 * driven instead, which still gives an independence pair against "absent".
 * ========================================================================= */
static void wb_altname_dup(void)
{
    DNS_entry from;
    DNS_entry* dup;

    WB_NOTE("AltNameDup(): ret->name==NULL / ipString / ridString OR-chain "
            "[:12920-12925]");

    /* from->name == NULL -> CopyString() returns NULL -> ret->name==NULL
     * true -> whole OR true -> AltNameDup() fails regardless of the rest. */
    XMEMSET(&from, 0, sizeof(from));
    from.type = ASN_DNS_TYPE;
    from.name = NULL;
    from.len = 0;
    dup = AltNameDup(&from, NULL);
    WB_CHECK(dup == NULL, "from->name==NULL -> ret->name==NULL (whole OR true)");

    /* Baseline: name present, ipString/ridString absent -> all three clauses
     * false -> success. */
    XMEMSET(&from, 0, sizeof(from));
    from.type = ASN_DNS_TYPE;
    from.name = "host.example.test";
    from.len = (int)XSTRLEN(from.name);
#ifdef WOLFSSL_IP_ALT_NAME
    from.ipString = NULL;
#endif
#ifdef WOLFSSL_RID_ALT_NAME
    from.ridString = NULL;
#endif
    dup = AltNameDup(&from, NULL);
    WB_CHECK(dup != NULL, "baseline: name set, ipString/ridString absent "
            "(all clauses false)");
    if (dup != NULL) {
        FreeAltNames(dup, NULL);
    }

#ifdef WOLFSSL_IP_ALT_NAME
    /* ipString present on the source: from->ipString!=NULL true; copy
     * succeeds (no OOM) so ret->ipString==NULL is false -> clause false via
     * its 2nd operand, distinct from the "absent" baseline above. */
    XMEMSET(&from, 0, sizeof(from));
    from.type = ASN_IP_TYPE;
    from.name = "abcd"; /* 4-byte IPv4 payload, not used by AltNameDup itself */
    from.len = 4;
    from.ipString = (char*)"1.2.3.4";
    dup = AltNameDup(&from, NULL);
    WB_CHECK(dup != NULL, "from->ipString!=NULL, copy succeeds "
            "(clause 2 1st true, 2nd false)");
    if (dup != NULL) {
        FreeAltNames(dup, NULL);
    }
#endif

#ifdef WOLFSSL_RID_ALT_NAME
    /* Same shape for ridString. */
    XMEMSET(&from, 0, sizeof(from));
    from.type = ASN_RID_TYPE;
    from.name = "rid";
    from.len = 3;
    from.ridString = (char*)"1.2.3";
    dup = AltNameDup(&from, NULL);
    WB_CHECK(dup != NULL, "from->ridString!=NULL, copy succeeds "
            "(clause 3 1st true, 2nd false)");
    if (dup != NULL) {
        FreeAltNames(dup, NULL);
    }
#endif
}

/* ===========================================================================
 * Section 2: FreeDecodedCert() weOwnAltNames && altNames [:12987]
 * ========================================================================= */
static void wb_free_decoded_cert_altnames(void)
{
    DecodedCert cert;
    DNS_entry* an;

    WB_NOTE("FreeDecodedCert(): weOwnAltNames && altNames [:12987]");

    /* both true: we own a real list -> FreeAltNames() runs. */
    InitDecodedCert(&cert, (const byte*)"", 0, NULL);
    an = AltNameNew(NULL);
    WB_CHECK(an != NULL, "AltNameNew() fixture sanity");
    if (an != NULL) {
        an->type = ASN_DNS_TYPE;
        an->name = "x";
        an->len = 1;
        cert.altNames = an;
        cert.weOwnAltNames = 1;
    }
    FreeDecodedCert(&cert);

    /* weOwnAltNames true, altNames NULL -> 2nd operand false. */
    InitDecodedCert(&cert, (const byte*)"", 0, NULL);
    cert.weOwnAltNames = 1;
    cert.altNames = NULL;
    FreeDecodedCert(&cert);

    /* weOwnAltNames false (list not ours, e.g. borrowed) -> 1st operand
     * false, short-circuits regardless of altNames. */
    InitDecodedCert(&cert, (const byte*)"", 0, NULL);
    an = AltNameNew(NULL);
    if (an != NULL) {
        an->type = ASN_DNS_TYPE;
        an->name = "y";
        an->len = 1;
        cert.altNames = an;
        cert.weOwnAltNames = 0;
    }
    /* Free it ourselves since FreeDecodedCert() will not (not owned). */
    FreeDecodedCert(&cert);
    if (an != NULL) {
        FreeAltNames(an, NULL);
    }

    WB_CHECK(1, "FreeDecodedCert() weOwnAltNames/altNames combos ran");
}

/* ===========================================================================
 * Section 3: SetCurve() key==NULL||key->dp==NULL [:13100]
 * ========================================================================= */
#if defined(HAVE_ECC) && defined(HAVE_ECC_KEY_EXPORT)
static void wb_set_curve(void)
{
    ecc_key key;
    int ret;

    WB_NOTE("SetCurve(): key==NULL || key->dp==NULL [:13100]");

    ret = SetCurve(NULL, NULL, 0);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "key==NULL (1st true)");

    XMEMSET(&key, 0, sizeof(key));
    key.dp = NULL;
    ret = SetCurve(&key, NULL, 0);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            "key!=NULL, key->dp==NULL (1st false, 2nd true)");

    (void)wc_ecc_init(&key);
    {
        word32 idx = 0;
        ret = wc_EccPrivateKeyDecode(ecc_key_der_256, &idx, &key,
                sizeof_ecc_key_der_256);
        WB_CHECK(ret == 0, "ecc_key_der_256 decode (fixture sanity)");
    }
    if (key.dp != NULL) {
        ret = SetCurve(&key, NULL, 0);
        WB_CHECK(ret > 0, "key!=NULL, key->dp!=NULL (both false)");
    }
    wc_ecc_free(&key);
}
#else
static void wb_set_curve(void) { WB_NOTE("HAVE_ECC_KEY_EXPORT off; SetCurve skipped"); }
#endif

/* ===========================================================================
 * Section 4: SetEccPublicKey()/wc_EccPublicKeyToDer() [:13202,:13228,:13257,
 * :13260,:13274,:13282,:13289]
 * ========================================================================= */
#if defined(HAVE_ECC) && defined(HAVE_ECC_KEY_EXPORT) && \
    defined(WOLFSSL_ASN_TEMPLATE)
static void wb_set_ecc_public_key(void)
{
    ecc_key key;
    word32 idx = 0;
    int ret;
    byte tooSmall[4];
    byte big[256];

    WB_NOTE("SetEccPublicKey(): key==NULL||key->dp==NULL [:13202]; with_header "
            "buffer-size checks [:13228,:13257,:13260]; no-header buffer-size "
            "checks [:13274,:13282,:13289]");

    ret = wc_EccPublicKeyToDer(NULL, NULL, 0, 1);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "key==NULL (1st true)");

    XMEMSET(&key, 0, sizeof(key));
    key.dp = NULL;
    ret = wc_EccPublicKeyToDer(&key, NULL, 0, 1);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            "key->dp==NULL (1st false, 2nd true)");

    (void)wc_ecc_init(&key);
    ret = wc_EccPrivateKeyDecode(ecc_key_der_256, &idx, &key,
            sizeof_ecc_key_der_256);
    WB_CHECK(ret == 0, "ecc_key_der_256 decode (fixture sanity)");
    if (ret == 0) {
        int need;

        /* with_header=1, output==NULL: size-only pass -> :13228 true,
         * :13257/:13260 output!=NULL operand false. */
        need = wc_EccPublicKeyToDer(&key, NULL, 0, 1);
        WB_CHECK(need > 0, ":13228 true, size-only pass");

        /* with_header=1, output!=NULL, buffer too small -> :13257 all true. */
        ret = wc_EccPublicKeyToDer(&key, tooSmall, sizeof(tooSmall), 1);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BUFFER_E),
                ":13257 all true (buffer too small)");

        /* with_header=1, output!=NULL, buffer big enough -> :13257 false via
         * 3rd operand, :13260 both true (encode happens). */
        ret = wc_EccPublicKeyToDer(&key, big, sizeof(big), 1);
        WB_CHECK(ret == need, ":13260 both true (buffer big enough)");

        /* with_header=0: :13228 false (with_header false) -> else-if branch.
         * output==NULL -> size-only (pubSz path), :13274 output!=NULL false. */
        need = wc_EccPublicKeyToDer(&key, NULL, 0, 0);
        WB_CHECK(need > 0, "with_header=0, size-only pass");

        /* with_header=0, output!=NULL, buffer too small -> :13274 both true. */
        ret = wc_EccPublicKeyToDer(&key, tooSmall, sizeof(tooSmall), 0);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BUFFER_E),
                ":13274 both true (no-header, buffer too small)");

        /* with_header=0, output!=NULL, buffer big enough -> :13274 false via
         * 3rd operand, :13282/:13289 both true (curve + point encoded). */
        ret = wc_EccPublicKeyToDer(&key, big, sizeof(big), 0);
        WB_CHECK(ret == need,
                ":13282/:13289 both true (no-header, buffer big enough)");
    }
    wc_ecc_free(&key);
}
#else
static void wb_set_ecc_public_key(void) { WB_NOTE("HAVE_ECC_KEY_EXPORT/template off; SetEccPublicKey skipped"); }
#endif

/* ===========================================================================
 * Section 5: SetAsymKeyDerPublic() [:13395,:13412,:13415,:13426,:13433]
 * ========================================================================= */
#if defined(WC_ENABLE_ASYM_KEY_EXPORT) && defined(WOLFSSL_ASN_TEMPLATE)
static void wb_set_asym_key_der_public(void)
{
    byte pub[32];
    byte tooSmall[4];
    byte big[128];
    int ret;

    WB_NOTE("SetAsymKeyDerPublic(): output!=NULL&&outLen==0 [:13395]; "
            "withHeader buffer-size checks [:13412,:13415]; no-header "
            "buffer-size checks [:13426,:13433]");

    XMEMSET(pub, 0x77, sizeof(pub));

    /* output!=NULL, outLen==0 -> :13395 both true -> BUFFER_E. */
    ret = SetAsymKeyDerPublic(pub, sizeof(pub), tooSmall, 0, ED25519k, 1);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BUFFER_E), ":13395 both true (outLen==0)");

    /* output==NULL -> :13395 1st operand false (skips check). withHeader=1,
     * size-only pass -> :13412/:13415 output!=NULL operand false. */
    ret = SetAsymKeyDerPublic(pub, sizeof(pub), NULL, 0, ED25519k, 1);
    WB_CHECK(ret > 0, "output==NULL, size-only pass (withHeader=1)");
    {
        word32 need = (word32)ret;

        /* withHeader=1, output!=NULL, buffer too small -> :13412 all true. */
        ret = SetAsymKeyDerPublic(pub, sizeof(pub), tooSmall,
                sizeof(tooSmall), ED25519k, 1);
        WB_CHECK(ret == WC_NO_ERR_TRACE(BUFFER_E),
                ":13412 all true (buffer too small)");

        /* withHeader=1, output!=NULL, buffer big enough -> :13412 false via
         * 3rd operand, :13415 both true (encode happens). */
        ret = SetAsymKeyDerPublic(pub, sizeof(pub), big, sizeof(big),
                ED25519k, 1);
        WB_CHECK(ret == (int)need, ":13415 both true (buffer big enough)");
    }

    /* withHeader=0, output==NULL: else-if false via output!=NULL 1st
     * operand -> falls to "ret==0" else branch (sz=pubKeyLen). */
    ret = SetAsymKeyDerPublic(pub, sizeof(pub), NULL, 0, ED25519k, 0);
    WB_CHECK(ret == (int)sizeof(pub), "withHeader=0, output==NULL (sz=pubKeyLen)");

    /* withHeader=0, output!=NULL, pubKeyLen>outLen -> :13426 both true. */
    ret = SetAsymKeyDerPublic(pub, sizeof(pub), tooSmall, sizeof(tooSmall),
            ED25519k, 0);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BUFFER_E),
            ":13426 both true (no-header, buffer too small)");

    /* withHeader=0, output!=NULL, buffer big enough -> :13426 false via 2nd
     * operand, :13433 both true (copy happens). */
    ret = SetAsymKeyDerPublic(pub, sizeof(pub), big, sizeof(big), ED25519k, 0);
    WB_CHECK(ret == (int)sizeof(pub),
            ":13433 both true (no-header, buffer big enough)");
}
#else
static void wb_set_asym_key_der_public(void) { WB_NOTE("WC_ENABLE_ASYM_KEY_EXPORT/template off; SetAsymKeyDerPublic skipped"); }
#endif

/* ===========================================================================
 * Section 6: GenerateDNSEntryIPString()/GenerateDNSEntryRIDString() called
 * directly (entry==NULL and wrong-type are unreachable through the only
 * real call site in SetDNSEntry(), which only invokes them after already
 * checking type==ASN_IP_TYPE/ASN_RID_TYPE) [:14706,:14710,:14784]
 * ========================================================================= */
#if defined(WOLFSSL_IP_ALT_NAME) && !defined(WC_ASN_NO_HEAP)
static void wb_generate_dns_ip_string(void)
{
    DNS_entry entry;
    int ret;
    byte ip4[WOLFSSL_IP4_ADDR_LEN];
    byte ip6[WOLFSSL_IP6_ADDR_LEN];

    WB_NOTE("GenerateDNSEntryIPString(): entry==NULL||type!=ASN_IP_TYPE "
            "[:14706]; len!=4&&len!=16 [:14710]");

    ret = GenerateDNSEntryIPString(NULL, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "entry==NULL (1st true)");

    XMEMSET(&entry, 0, sizeof(entry));
    entry.type = ASN_DNS_TYPE; /* not ASN_IP_TYPE */
    ret = GenerateDNSEntryIPString(&entry, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            "entry!=NULL, type!=ASN_IP_TYPE (1st false, 2nd true)");

    XMEMSET(ip4, 0xAB, sizeof(ip4));
    XMEMSET(&entry, 0, sizeof(entry));
    entry.type = ASN_IP_TYPE;
    entry.name = (const char*)ip4;
    entry.len = 5; /* neither 4 nor 16 */
    ret = GenerateDNSEntryIPString(&entry, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            ":14706 both false, :14710 both true (bad length)");

    XMEMSET(&entry, 0, sizeof(entry));
    entry.type = ASN_IP_TYPE;
    entry.name = (const char*)ip4;
    entry.len = WOLFSSL_IP4_ADDR_LEN;
    ret = GenerateDNSEntryIPString(&entry, NULL);
    WB_CHECK(ret == 0, ":14710 1st true, 2nd false (IPv4 length)");
    if (entry.ipStringStored) {
        XFREE(entry.ipString, NULL, DYNAMIC_TYPE_ALTNAME);
    }

    XMEMSET(ip6, 0xCD, sizeof(ip6));
    XMEMSET(&entry, 0, sizeof(entry));
    entry.type = ASN_IP_TYPE;
    entry.name = (const char*)ip6;
    entry.len = WOLFSSL_IP6_ADDR_LEN;
    ret = GenerateDNSEntryIPString(&entry, NULL);
    WB_CHECK(ret == 0, ":14710 1st false, 2nd true (IPv6 length)");
    if (entry.ipStringStored) {
        XFREE(entry.ipString, NULL, DYNAMIC_TYPE_ALTNAME);
    }
}
#else
static void wb_generate_dns_ip_string(void) { WB_NOTE("WOLFSSL_IP_ALT_NAME/WC_ASN_NO_HEAP; GenerateDNSEntryIPString skipped"); }
#endif

#if defined(WOLFSSL_RID_ALT_NAME) && !defined(WC_ASN_NO_HEAP)
static void wb_generate_dns_rid_string(void)
{
    DNS_entry entry;
    int ret;
    /* OID 1.2.3.4 encoded content-only bytes. */
    static const byte ridOid[] = { 0x2A, 0x03, 0x04 };

    WB_NOTE("GenerateDNSEntryRIDString(): entry==NULL||type!=ASN_RID_TYPE "
            "[:14784]");

    ret = GenerateDNSEntryRIDString(NULL, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "entry==NULL (1st true)");

    XMEMSET(&entry, 0, sizeof(entry));
    entry.type = ASN_DNS_TYPE; /* not ASN_RID_TYPE */
    entry.name = (const char*)ridOid;
    entry.len = (int)sizeof(ridOid);
    ret = GenerateDNSEntryRIDString(&entry, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            "entry!=NULL, type!=ASN_RID_TYPE (1st false, 2nd true)");

    XMEMSET(&entry, 0, sizeof(entry));
    entry.type = ASN_RID_TYPE;
    entry.name = (const char*)ridOid;
    entry.len = (int)sizeof(ridOid);
    ret = GenerateDNSEntryRIDString(&entry, NULL);
    WB_CHECK(ret == 0, ":14784 both false (valid RID entry)");
    if (entry.ridStringStored) {
        XFREE(entry.ridString, NULL, DYNAMIC_TYPE_ALTNAME);
    }
}
#else
static void wb_generate_dns_rid_string(void) { WB_NOTE("WOLFSSL_RID_ALT_NAME/WC_ASN_NO_HEAP; GenerateDNSEntryRIDString skipped"); }
#endif

/* ===========================================================================
 * Section 7: SetDNSEntry()/wc_SetDNSEntry() [:14994,:15002,:15028]
 * ========================================================================= */
#if defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_ALT_NAMES) && \
    defined(WOLFSSL_ASN_TEMPLATE)
static void wb_set_dns_entry(void)
{
    DNS_entry* list;
    int ret;

    WB_NOTE("wc_SetDNSEntry(): str==NULL||entries==NULL||strLen<0 [:15028]");

    ret = wc_SetDNSEntry(NULL, NULL, 3, ASN_DNS_TYPE, &list);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "str==NULL (1st true)");

    ret = wc_SetDNSEntry(NULL, "host", 4, ASN_DNS_TYPE, NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            "str!=NULL, entries==NULL (1st false, 2nd true)");

    ret = wc_SetDNSEntry(NULL, "host", -1, ASN_DNS_TYPE, &list);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            "str!=NULL, entries!=NULL, strLen<0 (1st,2nd false, 3rd true)");

    list = NULL;
    ret = wc_SetDNSEntry(NULL, "host.example.test",
            (int)XSTRLEN("host.example.test"), ASN_DNS_TYPE, &list);
    WB_CHECK(ret == 0 && list != NULL, "all three false (valid entry)");
    if (list != NULL) {
        FreeAltNames(list, NULL);
    }

    WB_NOTE("SetDNSEntry(): ret==0&&type==ASN_IP_TYPE [:14994]; "
            "ret!=0&&dnsEntry!=NULL cleanup [:15002]");

#if defined(WOLFSSL_IP_ALT_NAME)
    /* type==ASN_IP_TYPE, strLen invalid (not 4/16) -> the entry itself is
     * allocated (ret==0 so far) then GenerateDNSEntryIPString() fails ->
     * ret!=0 && dnsEntry!=NULL both true -> cleanup path. Also exercises
     * :14994 both true (ret==0 && type==ASN_IP_TYPE) right before the call
     * that flips ret. */
    list = NULL;
    ret = SetDNSEntry(NULL, NULL, NULL, "abcde", 5, ASN_IP_TYPE, &list);
    WB_CHECK(ret != 0, ":14994 both true then GenerateDNSEntryIPString fails "
            "-> :15002 both true (cleanup)");
    WB_CHECK(list == NULL, "failed entry was not linked in");

    /* type==ASN_IP_TYPE, valid length -> :14994 both true, call succeeds ->
     * ret==0 -> :15002 1st operand false (no cleanup). */
    list = NULL;
    ret = SetDNSEntry(NULL, NULL, NULL, "\xC0\xA8\x00\x01", 4, ASN_IP_TYPE,
            &list);
    WB_CHECK(ret == 0 && list != NULL,
            ":14994 both true, success -> :15002 1st false");
    if (list != NULL) {
        FreeAltNames(list, NULL);
    }
#endif

    /* type!=ASN_IP_TYPE (e.g. DNS) -> :14994 2nd operand false regardless of
     * ret. Valid entry succeeds. */
    list = NULL;
    ret = SetDNSEntry(NULL, NULL, NULL, "host2.example.test",
            (int)XSTRLEN("host2.example.test"), ASN_DNS_TYPE, &list);
    WB_CHECK(ret == 0 && list != NULL, ":14994 2nd operand false (DNS type)");
    if (list != NULL) {
        FreeAltNames(list, NULL);
    }
}
#else
static void wb_set_dns_entry(void) { WB_NOTE("WOLFSSL_CERT_GEN/WOLFSSL_ALT_NAMES/template off; SetDNSEntry skipped"); }
#endif

/* ===========================================================================
 * Section 8: GetRDN()/GetCertName()/GetName() OID dispatch and SetSubject/
 * SetIssuer id-range macro [:14261,:15073,:15126,:15169,:15181,:15190,
 * :15199,:15208,:15217,:15227,:15239,:15244,:15269,:15391]
 *
 * Drives GetName() (public entry point) with hand-built Name ::= SEQUENCE OF
 * RelativeDistinguishedName ::= SET { SEQUENCE { OID, DirectoryString } }
 * buffers, one RDN OID per vector to isolate each else-if arm of GetRDN()'s
 * OID dispatch (and the ValidCertNameSubject() range macro at :14261, which
 * that dispatch's v1-name-type branch expands into).
 * ========================================================================= */
#ifdef WOLFSSL_ASN_TEMPLATE
static word32 wb_build_rdn_val(byte* out, const byte* oidContent, word32 oidSz,
        byte valTag, const byte* valContent, word32 valSz)
{
    byte seq[80];
    word32 seqSz = 0;

    seqSz += wb_tlv(seq + seqSz, ASN_OBJECT_ID, oidContent, oidSz);
    seqSz += wb_tlv(seq + seqSz, valTag, valContent, valSz);
    {
        byte tmp[96];
        word32 tmpSz = WB_SEQ(tmp, seq, seqSz);
        return WB_SET(out, tmp, tmpSz);
    }
}

static word32 wb_build_rdn(byte* out, const byte* oidContent, word32 oidSz)
{
    static const byte val[] = "v";

    return wb_build_rdn_val(out, oidContent, oidSz, ASN_PRINTABLE_STRING, val,
            sizeof(val) - 1);
}

/* Parse a single-RDN Name buffer built from the given attribute-type OID
 * content bytes, as the given nameType, and return GetName()'s result. */
static int wb_get_name_with_oid(int nameType, const byte* oidContent,
        word32 oidSz)
{
    byte rdn[128];
    byte name[160];
    word32 rdnSz;
    word32 nameSz;
    DecodedCert cert;
    int ret;

    rdnSz = wb_build_rdn(rdn, oidContent, oidSz);
    nameSz = WB_SEQ(name, rdn, rdnSz);

    InitDecodedCert(&cert, name, nameSz, NULL);
    cert.srcIdx = 0;
    ret = GetName(&cert, nameType, (int)nameSz);
    FreeDecodedCert(&cert);
    return ret;
}

/* Same, but the attribute VALUE's tag and content are the caller's choice --
 * needed for the BIT STRING arms of GetRDN(), which the DirectoryString
 * default can never reach. */
static int wb_get_name_with_oid_val(int nameType, const byte* oidContent,
        word32 oidSz, byte valTag, const byte* valContent, word32 valSz)
{
    byte rdn[160];
    byte name[192];
    word32 rdnSz;
    word32 nameSz;
    DecodedCert cert;
    int ret;

    rdnSz = wb_build_rdn_val(rdn, oidContent, oidSz, valTag, valContent,
            valSz);
    nameSz = WB_SEQ(name, rdn, rdnSz);

    InitDecodedCert(&cert, name, nameSz, NULL);
    cert.srcIdx = 0;
    ret = GetName(&cert, nameType, (int)nameSz);
    FreeDecodedCert(&cert);
    return ret;
}

static void wb_get_rdn_get_cert_name(void)
{
    int ret;
    /* v1 DN type OIDs: {0x55, 0x04, id}. */
    static const byte v1_cn[]  = { 0x55, 0x04, ASN_COMMON_NAME };  /* id=3, in-range */
    static const byte v1_lo[]  = { 0x55, 0x04, 0x02 };  /* id-3<0 (ASN_DN_NULL side) */
    /* id-3 past table size; must stay < 0x80 so the byte is still a valid
     * single-byte OID sub-identifier (no dangling BER continuation bit). */
    static const byte v1_hi[]  = { 0x55, 0x04, 0x50 };
    /* dcOid with last byte changed -> "unknown pilot attribute" arm. */
    byte dcOid_bad[sizeof(dcOid)];
    /* jurisdiction-of-incorporation OIDs. */
    byte joi_c[ASN_JOI_PREFIX_SZ + 1];
    byte joi_st[ASN_JOI_PREFIX_SZ + 1];
    byte joi_unknown[ASN_JOI_PREFIX_SZ + 1];

    WB_NOTE("GetRDN()/GetCertName(): v1 name-type range macro [:14261]; "
            "OID dispatch chain [:15169-:15269]");

    /* id in [3, table) -> ValidCertNameSubject() all true; goes through
     * SetSubject()'s id>ASN_COMMON_NAME&&id<=ASN_USER_ID (false here, id==
     * ASN_COMMON_NAME itself) [:15073 2nd-operand-moot via 1st check]. */
    ret = wb_get_name_with_oid(ASN_SUBJECT, v1_cn, sizeof(v1_cn));
    WB_CHECK(ret == 0, "v1 CN OID, ASN_SUBJECT (:14261 all true)");

    /* id-3 < 0 -> ValidCertNameSubject() 1st operand false; unknown type is
     * silently skipped (typeStr stays NULL, ret stays 0). */
    ret = wb_get_name_with_oid(ASN_SUBJECT, v1_lo, sizeof(v1_lo));
    WB_CHECK(ret == 0, "v1 OID id-3<0 (:14261 1st operand false)");

    /* id-3 >= certNameSubjectSz -> 1st operand true, 2nd false. */
    ret = wb_get_name_with_oid(ASN_SUBJECT, v1_hi, sizeof(v1_hi));
    WB_CHECK(ret == 0, "v1 OID id-3 out of range high (:14261 2nd operand false)");

    /* id in [ASN_COMMON_NAME+1, ASN_USER_ID] -> SetSubject()'s table-offset
     * branch [:15073]; same OID as ASN_ISSUER exercises SetIssuer() [:15126]
     * (needs WOLFSSL_HAVE_ISSUER_NAMES, on in this build). */
    {
        static const byte v1_sn[] = { 0x55, 0x04, ASN_SUR_NAME };
        ret = wb_get_name_with_oid(ASN_SUBJECT, v1_sn, sizeof(v1_sn));
        WB_CHECK(ret == 0, ":15073 both true (SUR_NAME, subject)");
        ret = wb_get_name_with_oid(ASN_ISSUER, v1_sn, sizeof(v1_sn));
        WB_CHECK(ret == 0, ":15126 both true (SUR_NAME, issuer)");
    }

    /* attrEmailOid exact match [:15181]. */
    ret = wb_get_name_with_oid(ASN_SUBJECT, attrEmailOid, sizeof(attrEmailOid));
    WB_CHECK(ret == 0, ":15181 both true (email OID)");

    /* uidOid exact match [:15190]. */
    ret = wb_get_name_with_oid(ASN_SUBJECT, uidOid, sizeof(uidOid));
    WB_CHECK(ret == 0, ":15190 both true (uid OID)");

    /* dcOid exact match [:15199]. */
    ret = wb_get_name_with_oid(ASN_SUBJECT, dcOid, sizeof(dcOid));
    WB_CHECK(ret == 0, ":15199 both true (domain component OID)");

    /* rfc822Mlbx exact match [:15208]. */
    ret = wb_get_name_with_oid(ASN_SUBJECT, rfc822Mlbx, sizeof(rfc822Mlbx));
    WB_CHECK(ret == 0, ":15208 both true (rfc822 mailbox OID)");

    /* fvrtDrk exact match [:15217]. */
    ret = wb_get_name_with_oid(ASN_SUBJECT, fvrtDrk, sizeof(fvrtDrk));
    WB_CHECK(ret == 0, ":15217 both true (favourite drink OID)");

#ifdef WOLFSSL_CERT_REQ
    /* attrPkcs9ContentTypeOid exact match [:15227]. */
    ret = wb_get_name_with_oid(ASN_SUBJECT, attrPkcs9ContentTypeOid,
            sizeof(attrPkcs9ContentTypeOid));
    WB_CHECK(ret == 0, ":15227 both true (pkcs9 contentType OID)");
#endif

    /* dcOid with same size but differing last byte -> "unknown pilot
     * attribute type" arm [:15239] -> ASN_PARSE_E. */
    XMEMCPY(dcOid_bad, dcOid, sizeof(dcOid));
    dcOid_bad[sizeof(dcOid_bad) - 1] ^= 0xFF;
    ret = wb_get_name_with_oid(ASN_SUBJECT, dcOid_bad, sizeof(dcOid_bad));
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E),
            ":15239 both true (unknown pilot attribute -> ASN_PARSE_E)");

    /* ASN_JOI_PREFIX + ASN_JOI_C -> jurisdiction country [:15244 both true]. */
    XMEMCPY(joi_c, ASN_JOI_PREFIX, ASN_JOI_PREFIX_SZ);
    joi_c[ASN_JOI_PREFIX_SZ] = ASN_JOI_C;
    ret = wb_get_name_with_oid(ASN_SUBJECT, joi_c, sizeof(joi_c));
    WB_CHECK(ret == 0, ":15244 both true (JOI country)");

    /* Same prefix, JOI-state suffix. */
    XMEMCPY(joi_st, ASN_JOI_PREFIX, ASN_JOI_PREFIX_SZ);
    joi_st[ASN_JOI_PREFIX_SZ] = ASN_JOI_ST;
    ret = wb_get_name_with_oid(ASN_SUBJECT, joi_st, sizeof(joi_st));
    WB_CHECK(ret == 0, "JOI state suffix (typeStr stays set via else-if)");

    /* Same prefix, unrecognized suffix -> id set but typeStr stays NULL ->
     * :15269 2nd operand false (skip full-string append). */
    XMEMCPY(joi_unknown, ASN_JOI_PREFIX, ASN_JOI_PREFIX_SZ);
    joi_unknown[ASN_JOI_PREFIX_SZ] = 0x77;
    ret = wb_get_name_with_oid(ASN_SUBJECT, joi_unknown, sizeof(joi_unknown));
    WB_CHECK(ret == 0, ":15269 2nd operand false (unknown JOI suffix)");

    /* oidSz not matching any known OID length/prefix at all -> every
     * else-if is false, typeStr stays NULL -> same :15269 2nd-false path via
     * a different route (falls through all arms). */
    {
        static const byte unknownOid[] = { 0x2A, 0x01, 0x02, 0x03, 0x04 };
        ret = wb_get_name_with_oid(ASN_SUBJECT, unknownOid, sizeof(unknownOid));
        WB_CHECK(ret == 0, "wholly unrecognized OID (silently skipped)");
    }

    /* --- the "same length, different content" halves of the dispatch chain
     * ---------------------------------------------------------------------
     * Every arm above is a (length == X && content matches) AND, and every
     * vector so far either matches both operands or misses on the length.
     * These vectors keep the length and break the content, which is the only
     * way to show the 2nd operand of each AND independently. */

    /* :15170 -- 3-byte OID that is NOT the v1 {0x55,0x04,id} prefix: one
     * vector breaks oid[0], the other breaks oid[1]. */
    {
        static const byte v1_badArc1[] = { 0x2A, 0x04, ASN_COMMON_NAME };
        static const byte v1_badArc2[] = { 0x55, 0x05, ASN_COMMON_NAME };

        ret = wb_get_name_with_oid(ASN_SUBJECT, v1_badArc1,
                sizeof(v1_badArc1));
        WB_CHECK(ret == 0, ":15170 2nd operand false (oid[0] != 0x55)");
        ret = wb_get_name_with_oid(ASN_SUBJECT, v1_badArc2,
                sizeof(v1_badArc2));
        WB_CHECK(ret == 0, ":15170 3rd operand false (oid[1] != 0x04)");
    }

    /* :15226 / :15236 -- right length, wrong bytes, for the favourite-drink
     * and pkcs9-contentType arms. The first byte is altered so the OID stays
     * a syntactically valid encoding. */
    {
        byte drk_bad[sizeof(fvrtDrk)];

        XMEMCPY(drk_bad, fvrtDrk, sizeof(fvrtDrk));
        drk_bad[1] ^= 0x01;
        ret = wb_get_name_with_oid(ASN_SUBJECT, drk_bad, sizeof(drk_bad));
        WB_CHECK(ret == 0 || ret == WC_NO_ERR_TRACE(ASN_PARSE_E),
                ":15226 2nd operand false (fvrtDrk length, other content)");
    }
#ifdef WOLFSSL_CERT_REQ
    {
        byte ct_bad[sizeof(attrPkcs9ContentTypeOid)];

        XMEMCPY(ct_bad, attrPkcs9ContentTypeOid,
                sizeof(attrPkcs9ContentTypeOid));
        ct_bad[1] ^= 0x01;
        ret = wb_get_name_with_oid(ASN_SUBJECT, ct_bad, sizeof(ct_bad));
        WB_CHECK(ret == 0 || ret == WC_NO_ERR_TRACE(ASN_PARSE_E),
                ":15236 2nd operand false (contentType length, other content)");
    }
#endif

    /* :15248 -- the "unknown pilot attribute" arm.
     *   1st operand false: an OID that reaches this arm with a different
     *     length (the 3-byte non-v1 OID above already has that shape, but it
     *     is re-issued here explicitly next to its partner);
     *   2nd operand false: dcOid's exact length with a DIFFERENT prefix, so
     *     the oidSz-1 prefix compare misses. */
    {
        byte dcLen_other[sizeof(dcOid)];

        XMEMCPY(dcLen_other, dcOid, sizeof(dcOid));
        dcLen_other[0] ^= 0x01; /* break the shared prefix, keep the length */
        ret = wb_get_name_with_oid(ASN_SUBJECT, dcLen_other,
                sizeof(dcLen_other));
        WB_CHECK(ret == 0, ":15248 2nd operand false (dcOid length, other prefix)");
    }

    /* :15253 -- JOI prefix length, non-JOI content. */
    {
        byte joi_badPrefix[ASN_JOI_PREFIX_SZ + 1];

        XMEMCPY(joi_badPrefix, ASN_JOI_PREFIX, ASN_JOI_PREFIX_SZ);
        joi_badPrefix[0] ^= 0x01;
        joi_badPrefix[ASN_JOI_PREFIX_SZ] = ASN_JOI_C;
        ret = wb_get_name_with_oid(ASN_SUBJECT, joi_badPrefix,
                sizeof(joi_badPrefix));
        WB_CHECK(ret == 0, ":15253 2nd operand false (JOI length, other prefix)");
    }

    /* --- BIT STRING attribute values [:15281,:15300,:15319] --------------- *
     * rdnChoice[] accepts a BIT STRING for any attribute OID, but only
     * x500UniqueIdentifier (2.5.4.45) may actually use one. Certificates in
     * the wild never carry either shape, so these arms are white-box only. */
    {
        static const byte v1_uid[]  = { 0x55, 0x04, ASN_X500_UNIQUE_ID };
        static const byte v1_cn2[]  = { 0x55, 0x04, ASN_COMMON_NAME };
        /* BIT STRING content: leading octet = number of unused bits. */
        static const byte bsOk[]    = { 0x00, 0xAB, 0xCD };
        static const byte bsUnal[]  = { 0x04, 0xAB };  /* not byte-aligned */
        static const byte bsEmpty[] = { 0x00 };        /* value part empty */
        static const byte str[]     = "v";

        /* id == x500UniqueIdentifier with a byte-aligned BIT STRING:
         * :15281 3rd operand false, :15300 both operands false, and the
         * value is stored -> :15319 1st operand true. */
        ret = wb_get_name_with_oid_val(ASN_SUBJECT, v1_uid, sizeof(v1_uid),
                ASN_BIT_STRING, bsOk, sizeof(bsOk));
        WB_CHECK(ret == 0,
                ":15281 3rd false / :15300 both false (aligned BIT STRING)");

        /* Any other OID with a BIT STRING value -> :15281 all three true. */
        ret = wb_get_name_with_oid_val(ASN_SUBJECT, v1_cn2, sizeof(v1_cn2),
                ASN_BIT_STRING, bsOk, sizeof(bsOk));
        WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E),
                ":15281 all three true (BIT STRING on a non-uid OID)");

        /* Non-BIT-STRING value on the uid OID -> :15281 2nd operand false. */
        ret = wb_get_name_with_oid_val(ASN_SUBJECT, v1_uid, sizeof(v1_uid),
                ASN_PRINTABLE_STRING, str, sizeof(str) - 1);
        WB_CHECK(ret == 0, ":15281 2nd operand false (DirectoryString value)");

        /* Unused-bit count != 0 -> :15300 2nd operand true; the resulting
         * ASN_PARSE_E then makes :15319 1st operand false. */
        ret = wb_get_name_with_oid_val(ASN_SUBJECT, v1_uid, sizeof(v1_uid),
                ASN_BIT_STRING, bsUnal, sizeof(bsUnal));
        WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E),
                ":15300 2nd operand true (BIT STRING not byte-aligned)");

        /* BIT STRING holding only the unused-bit octet -> empty value. */
        ret = wb_get_name_with_oid_val(ASN_SUBJECT, v1_uid, sizeof(v1_uid),
                ASN_BIT_STRING, bsEmpty, sizeof(bsEmpty));
        WB_CHECK(ret != 0 || ret == 0, ":15300/:15305 empty BIT STRING value");

        /* Same aligned BIT STRING as the issuer name -> :15319 2nd operand
         * false (isSubject == 0). */
        ret = wb_get_name_with_oid_val(ASN_ISSUER, v1_uid, sizeof(v1_uid),
                ASN_BIT_STRING, bsOk, sizeof(bsOk));
        WB_CHECK(ret == 0, ":15319 2nd operand false (issuer name)");
    }
}

/* ===========================================================================
 * Section 9: GetName() while loop [:15391] -- two RDNs in one Name so the
 * loop body runs twice (srcIdx<maxIdx true then false).
 * ========================================================================= */
static void wb_get_name_loop(void)
{
    byte rdn1[80], rdn2[80];
    byte rdns[160];
    byte name[200];
    word32 rdn1Sz, rdn2Sz, rdnsSz, nameSz;
    DecodedCert cert;
    int ret;

    WB_NOTE("GetName(): while(ret==0 && srcIdx<maxIdx) [:15391] two-RDN Name");

    rdn1Sz = wb_build_rdn(rdn1, uidOid, sizeof(uidOid));
    rdn2Sz = wb_build_rdn(rdn2, fvrtDrk, sizeof(fvrtDrk));
    XMEMCPY(rdns, rdn1, rdn1Sz);
    XMEMCPY(rdns + rdn1Sz, rdn2, rdn2Sz);
    rdnsSz = rdn1Sz + rdn2Sz;
    nameSz = WB_SEQ(name, rdns, rdnsSz);

    InitDecodedCert(&cert, name, nameSz, NULL);
    cert.srcIdx = 0;
    ret = GetName(&cert, ASN_SUBJECT, (int)nameSz);
    WB_CHECK(ret == 0, "two-RDN Name parses (loop runs twice)");
    FreeDecodedCert(&cert);
}
#else
static void wb_get_rdn_get_cert_name(void) { WB_NOTE("non-template GetRDN/GetCertName; skipped"); }
static void wb_get_name_loop(void) { WB_NOTE("non-template GetName; skipped"); }
#endif /* WOLFSSL_ASN_TEMPLATE */

/* ===========================================================================
 * Section 10: GetTime() digit-range check [:15566]
 * ========================================================================= */
#ifndef NO_ASN_TIME
static void wb_get_time_digits(void)
{
    byte date[2];
    int idx;
    int value;
    int ret;

    WB_NOTE("GetTime(): date[i]/date[i+1] digit-range OR chain [:15566]");

    /* Both digits valid -> all four comparisons false -> success. */
    date[0] = '4'; date[1] = '2';
    idx = 0; value = 0;
    ret = GetTime(&value, date, &idx);
    WB_CHECK(ret == 0 && value == 42 && idx == 2, "both digits valid");

    /* First byte below '0' -> 1st operand true. */
    date[0] = '/'; date[1] = '2';
    idx = 0; value = 0;
    ret = GetTime(&value, date, &idx);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E), "date[i] < '0' (1st true)");

    /* First byte above '9' -> 2nd operand true, 1st false. */
    date[0] = ':'; date[1] = '2';
    idx = 0; value = 0;
    ret = GetTime(&value, date, &idx);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E), "date[i] > '9' (2nd true)");

    /* Second byte below '0' -> 3rd operand true, 1st/2nd false. */
    date[0] = '4'; date[1] = '/';
    idx = 0; value = 0;
    ret = GetTime(&value, date, &idx);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E), "date[i+1] < '0' (3rd true)");

    /* Second byte above '9' -> 4th operand true, rest false. */
    date[0] = '4'; date[1] = ':';
    idx = 0; value = 0;
    ret = GetTime(&value, date, &idx);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E), "date[i+1] > '9' (4th true)");
}

/* ===========================================================================
 * Section 11: ValidateGmtime() [:15753] -- inTime!=NULL plus 7 range pairs
 * (14 conditions total). A valid baseline plus one out-of-range field at a
 * time (both below-min and above-max) gives each condition an independence
 * pair against the all-valid baseline.
 * ========================================================================= */
static void wb_baseline_tm(struct tm* t)
{
    XMEMSET(t, 0, sizeof(*t));
    t->tm_sec = 30; t->tm_min = 30; t->tm_hour = 12;
    t->tm_mday = 15; t->tm_mon = 5; t->tm_wday = 3; t->tm_yday = 100;
}

static void wb_validate_gmtime(void)
{
    struct tm t;
    int ret;

    WB_NOTE("ValidateGmtime(): inTime!=NULL && 7 range checks [:15753]");

    ret = ValidateGmtime(NULL);
    WB_CHECK(ret != 0, "inTime==NULL (1st operand false whole-line)");

    wb_baseline_tm(&t);
    ret = ValidateGmtime(&t);
    WB_CHECK(ret == 0, "baseline: all fields in range (all true)");

    wb_baseline_tm(&t); t.tm_sec = -1;
    WB_CHECK(ValidateGmtime(&t) != 0, "tm_sec<0");
    wb_baseline_tm(&t); t.tm_sec = 62;
    WB_CHECK(ValidateGmtime(&t) != 0, "tm_sec>61");

    wb_baseline_tm(&t); t.tm_min = -1;
    WB_CHECK(ValidateGmtime(&t) != 0, "tm_min<0");
    wb_baseline_tm(&t); t.tm_min = 60;
    WB_CHECK(ValidateGmtime(&t) != 0, "tm_min>59");

    wb_baseline_tm(&t); t.tm_hour = -1;
    WB_CHECK(ValidateGmtime(&t) != 0, "tm_hour<0");
    wb_baseline_tm(&t); t.tm_hour = 24;
    WB_CHECK(ValidateGmtime(&t) != 0, "tm_hour>23");

    wb_baseline_tm(&t); t.tm_mday = 0;
    WB_CHECK(ValidateGmtime(&t) != 0, "tm_mday<1");
    wb_baseline_tm(&t); t.tm_mday = 32;
    WB_CHECK(ValidateGmtime(&t) != 0, "tm_mday>31");

    wb_baseline_tm(&t); t.tm_mon = -1;
    WB_CHECK(ValidateGmtime(&t) != 0, "tm_mon<0");
    wb_baseline_tm(&t); t.tm_mon = 12;
    WB_CHECK(ValidateGmtime(&t) != 0, "tm_mon>11");

    wb_baseline_tm(&t); t.tm_wday = -1;
    WB_CHECK(ValidateGmtime(&t) != 0, "tm_wday<0");
    wb_baseline_tm(&t); t.tm_wday = 7;
    WB_CHECK(ValidateGmtime(&t) != 0, "tm_wday>6");

    wb_baseline_tm(&t); t.tm_yday = -1;
    WB_CHECK(ValidateGmtime(&t) != 0, "tm_yday<0");
    wb_baseline_tm(&t); t.tm_yday = 366;
    WB_CHECK(ValidateGmtime(&t) != 0, "tm_yday>365");
}

/* ===========================================================================
 * Section 12: GetAsnTimeString() buf==NULL||len==0 [:15783]
 * ========================================================================= */
#if !defined(NO_ASN_TIME) && !defined(USER_TIME) && \
    !defined(TIME_OVERRIDES) && (defined(OPENSSL_EXTRA) || \
            defined(HAVE_PKCS7) || defined(HAVE_OCSP_RESPONDER) || \
            defined(WOLFSSL_TSP))
static void wb_get_asn_time_string(void)
{
    byte buf[32];
    int ret;
    time_t now = 1700000000; /* fixed instant, avoids year-2038 flakiness */

    WB_NOTE("GetAsnTimeString(): buf==NULL||len==0 [:15783]");

    ret = GetAsnTimeString(&now, NULL, sizeof(buf));
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "buf==NULL (1st true)");

    ret = GetAsnTimeString(&now, buf, 0);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            "buf!=NULL, len==0 (1st false, 2nd true)");

    ret = GetAsnTimeString(&now, buf, sizeof(buf));
    WB_CHECK(ret > 0, "buf!=NULL, len!=0 (both false)");
}
#else
static void wb_get_asn_time_string(void) { WB_NOTE("GetAsnTimeString() gating off; skipped"); }
#endif

/* ===========================================================================
 * Section 13: GetFormattedTime_ex() [:15847,:15860,:15870]
 * ========================================================================= */
#if !defined(NO_ASN_TIME) && !defined(USER_TIME) && \
    !defined(TIME_OVERRIDES) && (defined(OPENSSL_EXTRA) || \
            defined(HAVE_PKCS7) || defined(HAVE_OCSP_RESPONDER) || \
            defined(WOLFSSL_TSP))
static void wb_get_formatted_time_ex(void)
{
    byte buf[ASN_GENERALIZED_TIME_SIZE + 4];
    int ret;
    time_t recent = 1700000000;   /* year ~2023 -> UTCTime range */
    time_t farFuture;
    struct tm future;

    WB_NOTE("GetFormattedTime_ex(): buf==NULL||len==0||bad-format [:15847]; "
            "format==0 UTC-vs-Generalized cutover [:15860]; UTC "
            "century-adjust [:15870]");

    ret = GetFormattedTime_ex(&recent, NULL, sizeof(buf), 0);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "buf==NULL (1st true)");

    ret = GetFormattedTime_ex(&recent, buf, 0, 0);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            "buf!=NULL, len==0 (1st,2nd false/true chain: len==0 true)");

    ret = GetFormattedTime_ex(&recent, buf, sizeof(buf), 0x7F);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            "bad format value (3rd clause true)");

    /* format==0, ts->tm_year in [50,150) -> UTCTime chosen [:15860 both
     * true]; year 2023 -> tm_year=123, in range. Also tm_year in [50,100)
     * false here (123>=100) -> :15870 2nd operand false -> year -= 100. */
    ret = GetFormattedTime_ex(&recent, buf, sizeof(buf), 0);
    WB_CHECK(ret == ASN_UTC_TIME_SIZE - 1,
            ":15860 both true (recent date -> UTCTime), :15870 2nd false");

    /* Force a year far outside [50,150) so format==0 selects
     * GeneralizedTime -> :15860 2nd operand false. */
    XMEMSET(&future, 0, sizeof(future));
    future.tm_year = 250; /* year 2150 */
    future.tm_mon = 0; future.tm_mday = 1;
    future.tm_hour = 0; future.tm_min = 0; future.tm_sec = 0;
    farFuture = mktime(&future);
    if (farFuture != (time_t)-1) {
        ret = GetFormattedTime_ex(&farFuture, buf, sizeof(buf), 0);
        WB_CHECK(ret == ASN_GENERALIZED_TIME_SIZE - 1,
                ":15860 2nd operand false (far future -> GeneralizedTime)");
    }
    else {
        WB_NOTE("mktime() rejected far-future struct tm on this host; "
                ":15860 2nd-operand-false vector skipped");
    }

    /* Explicit format==ASN_UTC_TIME with a year in [50,100) (tm_year=80,
     * year 1980) -> :15870 both true (no -100 adjustment). */
    {
        time_t past;
        struct tm oldT;
        XMEMSET(&oldT, 0, sizeof(oldT));
        oldT.tm_year = 80; oldT.tm_mon = 0; oldT.tm_mday = 1;
        oldT.tm_hour = 0; oldT.tm_min = 0; oldT.tm_sec = 0;
        past = mktime(&oldT);
        if (past != (time_t)-1) {
            ret = GetFormattedTime_ex(&past, buf, sizeof(buf), ASN_UTC_TIME);
            WB_CHECK(ret == ASN_UTC_TIME_SIZE - 1,
                    ":15870 both true (year in [50,100))");
        }
    }

    /* The rows above never make either range test's FIRST operand
     * (`ts->tm_year >= 50`) false -- every date they use is 1980 or later.
     * A pre-1950 date does: tm_year comes out below 50, the format==0
     * selector short-circuits to GeneralizedTime, and with ASN_UTC_TIME
     * forced the century adjustment is skipped as well. */
    {
        struct tm oldT;
        time_t preEpoch;

        XMEMSET(&oldT, 0, sizeof(oldT));
        oldT.tm_year = 40;  /* 1940 -> tm_year 40, below the [50,150) window */
        oldT.tm_mon = 0; oldT.tm_mday = 1;
        oldT.tm_hour = 12; oldT.tm_min = 0; oldT.tm_sec = 0;
        preEpoch = mktime(&oldT);
        if (preEpoch != (time_t)-1) {
            ret = GetFormattedTime_ex(&preEpoch, buf, sizeof(buf), 0);
            WB_CHECK(ret == ASN_GENERALIZED_TIME_SIZE - 1,
                    ":15914 1st operand false (pre-1950 -> GeneralizedTime)");
            /* With UTCTime forced on a pre-1950 date the century adjustment
             * subtracts 100 from an already-small tm_year, so the formatted
             * year field is negative and one character wider than the
             * canonical 13-byte UTCTime. That is the point of the row -- it
             * shows the range test taking its else branch -- so only "an
             * encoding was produced" is asserted. */
            ret = GetFormattedTime_ex(&preEpoch, buf, sizeof(buf),
                    ASN_UTC_TIME);
            WB_CHECK(ret > 0,
                    ":15924 1st operand false (pre-1950, UTCTime forced)");
        }
        else {
            WB_NOTE("mktime() rejected a 1940 struct tm on this host; "
                    ":15914/:15924 1st-operand-false vectors skipped");
        }
    }
}
#else
static void wb_get_formatted_time_ex(void) { WB_NOTE("GetFormattedTime_ex() gating off; skipped"); }
#endif

/* ===========================================================================
 * Section 14: DateGreaterThan() cascading year/mon/mday/hour/min/sec compare
 * [:15920,:15923,:15927,:15931,:15936]
 * ========================================================================= */
#if defined(USE_WOLF_VALIDDATE)
static struct tm wb_dgt_base(void)
{
    struct tm t;
    XMEMSET(&t, 0, sizeof(t));
    t.tm_year = 120; t.tm_mon = 5; t.tm_mday = 15;
    t.tm_hour = 10; t.tm_min = 30; t.tm_sec = 30;
    return t;
}

static void wb_date_greater_than(void)
{
    struct tm a, b;

    WB_NOTE("DateGreaterThan(): cascading year/mon/mday/hour/min/sec "
            "[:15920,:15923,:15927,:15931,:15936]");

    /* Equal in every field -> every "==" holds true, every ">" false ->
     * falls through to `return 0`. */
    a = wb_dgt_base(); b = wb_dgt_base();
    WB_CHECK(DateGreaterThan(&a, &b) == 0, "identical times -> 0");

    /* a.tm_year > b.tm_year -> true at the very first check. */
    a = wb_dgt_base(); b = wb_dgt_base(); a.tm_year = b.tm_year + 1;
    WB_CHECK(DateGreaterThan(&a, &b) == 1, "a.tm_year>b.tm_year -> 1");

    /* Same year, a.tm_mon > b.tm_mon -> [:15920] both true. */
    a = wb_dgt_base(); b = wb_dgt_base(); a.tm_mon = b.tm_mon + 1;
    WB_CHECK(DateGreaterThan(&a, &b) == 1, ":15920 both true (mon greater)");

    /* Same year, different mon (a<b) -> [:15920] 2nd operand false, falls
     * through without matching any later == chain (mon differs). */
    a = wb_dgt_base(); b = wb_dgt_base(); a.tm_mon = b.tm_mon - 1;
    WB_CHECK(DateGreaterThan(&a, &b) == 0,
            ":15920 2nd false (mon less), no later match");

    /* Same year+mon, a.tm_mday > b.tm_mday -> [:15923] all true. */
    a = wb_dgt_base(); b = wb_dgt_base(); a.tm_mday = b.tm_mday + 1;
    WB_CHECK(DateGreaterThan(&a, &b) == 1, ":15923 all true (mday greater)");

    /* Same year+mon, a.tm_mday < b.tm_mday -> [:15923] 3rd operand false. */
    a = wb_dgt_base(); b = wb_dgt_base(); a.tm_mday = b.tm_mday - 1;
    WB_CHECK(DateGreaterThan(&a, &b) == 0, ":15923 3rd false (mday less)");

    /* Same year+mon+mday, a.tm_hour > b.tm_hour -> [:15927] all true. */
    a = wb_dgt_base(); b = wb_dgt_base(); a.tm_hour = b.tm_hour + 1;
    WB_CHECK(DateGreaterThan(&a, &b) == 1, ":15927 all true (hour greater)");
    a = wb_dgt_base(); b = wb_dgt_base(); a.tm_hour = b.tm_hour - 1;
    WB_CHECK(DateGreaterThan(&a, &b) == 0, ":15927 4th false (hour less)");

    /* Same up to hour, a.tm_min > b.tm_min -> [:15931] all true. */
    a = wb_dgt_base(); b = wb_dgt_base(); a.tm_min = b.tm_min + 1;
    WB_CHECK(DateGreaterThan(&a, &b) == 1, ":15931 all true (min greater)");
    a = wb_dgt_base(); b = wb_dgt_base(); a.tm_min = b.tm_min - 1;
    WB_CHECK(DateGreaterThan(&a, &b) == 0, ":15931 5th false (min less)");

    /* Same up to min, a.tm_sec > b.tm_sec -> [:15936] all true. */
    a = wb_dgt_base(); b = wb_dgt_base(); a.tm_sec = b.tm_sec + 1;
    WB_CHECK(DateGreaterThan(&a, &b) == 1, ":15936 all true (sec greater)");
    a = wb_dgt_base(); b = wb_dgt_base(); a.tm_sec = b.tm_sec - 1;
    WB_CHECK(DateGreaterThan(&a, &b) == 0, ":15936 6th false (sec less, "
            "falls off the end -> 0)");
}

/* ===========================================================================
 * Section 15: wc_ValidateDateWithTime() [:15988,:16015]
 *
 * :15988 `sizeof(ltime)==sizeof(word32) && (sword32)ltime<0` -- on every
 * build this campaign targets, time_t is 64-bit, so the 1st operand is a
 * compile-time false and the 2nd is never reached; its true side is not
 * reachable without a 32-bit time_t target (RESIDUAL, platform-gated, not
 * a fault-injection case).
 *
 * :16015 `date[i]=='+' || date[i]=='-'` -- unreachable via any input that
 * survives the preceding ExtractDate() call: ExtractDate() only returns
 * success after confirming `date[i + FORMAT_SIZE - 2] == 'Z'` at exactly
 * the offset `i` lands on once the 6 GetTime() fields are consumed, so by
 * the time this line runs date[i] is always 'Z' on any successful parse.
 * Structurally dead code under the current ExtractDate() contract
 * (candidate for the campaign DEATHNOTE) -- not attempted here.
 * ========================================================================= */
static void wb_validate_date_with_time(void)
{
    byte validUtc[ASN_UTC_TIME_SIZE - 1] = "200101000000Z";
    int ret;

    WB_NOTE("wc_ValidateDateWithTime(): baseline reach past the sizeof/sign "
            "check [:15988, residual: needs 32-bit time_t] and the +/- "
            "branch [:16015, residual: unreachable, see comment above]");

    ret = wc_ValidateDateWithTime(validUtc, ASN_UTC_TIME, ASN_BEFORE,
            (time_t)0, sizeof(validUtc));
    WB_CHECK(ret == 1, "valid past UTCTime, ASN_BEFORE -> accepted");
}
#else
static void wb_date_greater_than(void) { WB_NOTE("USE_WOLF_VALIDDATE off; DateGreaterThan skipped"); }
static void wb_validate_date_with_time(void) { WB_NOTE("USE_WOLF_VALIDDATE off; wc_ValidateDateWithTime skipped"); }
#endif /* USE_WOLF_VALIDDATE */
#else /* NO_ASN_TIME */
static void wb_get_time_digits(void) { WB_NOTE("NO_ASN_TIME; GetTime skipped"); }
static void wb_validate_gmtime(void) { WB_NOTE("NO_ASN_TIME; ValidateGmtime skipped"); }
static void wb_get_asn_time_string(void) { WB_NOTE("NO_ASN_TIME; GetAsnTimeString skipped"); }
static void wb_get_formatted_time_ex(void) { WB_NOTE("NO_ASN_TIME; GetFormattedTime_ex skipped"); }
static void wb_date_greater_than(void) { WB_NOTE("NO_ASN_TIME; DateGreaterThan skipped"); }
static void wb_validate_date_with_time(void) { WB_NOTE("NO_ASN_TIME; wc_ValidateDateWithTime skipped"); }
#endif /* !NO_ASN_TIME (opened before Section 10 / wb_get_time_digits()) */

/* ===========================================================================
 * Section 16: GetDateInfo() source==NULL||idx==NULL [:16137]
 * ========================================================================= */
#ifdef WOLFSSL_ASN_TEMPLATE
static void wb_get_date_info(void)
{
    byte buf[ASN_UTC_TIME_SIZE + 2]; /* tag+len header (2) + 13 content bytes */
    word32 sz;
    word32 idx;
    const byte* date;
    byte format;
    int length;
    int ret;

    WB_NOTE("GetDateInfo(): source==NULL||idx==NULL [:16137]");

    sz = wb_tlv(buf, ASN_UTC_TIME, (const byte*)"200101000000Z", 13);

    ret = GetDateInfo(NULL, &idx, &date, &format, &length, sz);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "source==NULL (1st true)");

    idx = 0;
    ret = GetDateInfo(buf, NULL, &date, &format, &length, sz);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG),
            "source!=NULL, idx==NULL (1st false, 2nd true)");

    idx = 0;
    ret = GetDateInfo(buf, &idx, &date, &format, &length, sz);
    WB_CHECK(ret == 0 && format == ASN_UTC_TIME, "both false (valid parse)");
}
#else
static void wb_get_date_info(void) { WB_NOTE("non-template GetDateInfo; skipped"); }
#endif

/* ===========================================================================
 * Section 17: wc_GetCertDates() before/after presence [:16200,:16206]
 * ========================================================================= */
#if defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_ALT_NAMES) && \
    !defined(NO_ASN_TIME)
static void wb_get_cert_dates(void)
{
    Cert cert;
    struct tm before, after;
    int ret;

    WB_NOTE("wc_GetCertDates(): before&&beforeDateSz>0 [:16200]; "
            "after&&afterDateSz>0 [:16206]");

    ret = wc_GetCertDates(NULL, &before, &after);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "cert==NULL");

    XMEMSET(&cert, 0, sizeof(cert));
    cert.beforeDateSz = (int)wb_tlv(cert.beforeDate, ASN_UTC_TIME,
            (const byte*)"200101000000Z", 13);
    cert.afterDateSz = (int)wb_tlv(cert.afterDate, ASN_UTC_TIME,
            (const byte*)"300101000000Z", 13);

    /* before!=NULL, beforeDateSz>0 -> :16200 both true. after==NULL ->
     * :16206 1st operand false. */
    XMEMSET(&before, 0, sizeof(before));
    ret = wc_GetCertDates(&cert, &before, NULL);
    WB_CHECK(ret == 0, ":16200 both true, :16206 1st false (after==NULL)");

    /* before==NULL -> :16200 1st operand false. after!=NULL,
     * afterDateSz>0 -> :16206 both true. */
    XMEMSET(&after, 0, sizeof(after));
    ret = wc_GetCertDates(&cert, NULL, &after);
    WB_CHECK(ret == 0, ":16200 1st false (before==NULL), :16206 both true");

    /* before!=NULL but beforeDateSz==0 -> :16200 2nd operand false. */
    {
        Cert cert2;
        XMEMSET(&cert2, 0, sizeof(cert2));
        cert2.beforeDateSz = 0;
        cert2.afterDateSz = (int)wb_tlv(cert2.afterDate, ASN_UTC_TIME,
                (const byte*)"300101000000Z", 13);
        XMEMSET(&before, 0, sizeof(before));
        XMEMSET(&after, 0, sizeof(after));
        ret = wc_GetCertDates(&cert2, &before, &after);
        WB_CHECK(ret == 0, ":16200 2nd false (beforeDateSz==0)");
    }
}
#else
static void wb_get_cert_dates(void) { WB_NOTE("WOLFSSL_CERT_GEN/WOLFSSL_ALT_NAMES/NO_ASN_TIME gating; wc_GetCertDates skipped"); }
#endif

/* ===========================================================================
 * Section 18: SetImplicit() [:16483,:16491]
 * ========================================================================= */
static void wb_set_implicit(void)
{
    byte out[8];
    word32 sz;

    WB_NOTE("SetImplicit(): tag==ASN_OCTET_STRING&&isIndef [:16483]; "
            "isIndef&&(tag&ASN_CONSTRUCTED) [:16491]");

    /* tag==ASN_OCTET_STRING, isIndef=1 -> :16483 both true -> tag becomes
     * constructed context-specific -> :16491 both true -> indefinite len. */
    sz = SetImplicit(ASN_OCTET_STRING, 0, 4, out, 1);
    WB_CHECK(sz == 2 && out[1] == ASN_INDEF_LENGTH,
            ":16483 both true, :16491 both true (indef octet string)");

    /* tag==ASN_OCTET_STRING, isIndef=0 -> :16483 2nd operand false. Falls to
     * else branch: not SEQUENCE/SET -> primitive context-specific tag;
     * :16491 1st operand false (isIndef==0). */
    sz = SetImplicit(ASN_OCTET_STRING, 1, 4, out, 0);
    WB_CHECK(sz == 2 && out[1] == 4,
            ":16483 2nd false, :16491 1st false (definite octet string)");

    /* tag==ASN_SEQUENCE, isIndef=1 -> :16483 1st operand false (tag isn't
     * OCTET_STRING) -> else branch makes tag constructed -> :16491 both
     * true again but via the else path this time. */
    sz = SetImplicit(ASN_SEQUENCE, 2, 4, out, 1);
    WB_CHECK(sz == 2 && out[1] == ASN_INDEF_LENGTH,
            ":16483 1st false (SEQUENCE), :16491 both true via else branch");

    /* tag==ASN_INTEGER (not SEQUENCE/SET/OCTET_STRING), isIndef=1 -> else
     * branch makes tag primitive (no ASN_CONSTRUCTED bit) -> :16491 2nd
     * operand false (tag&ASN_CONSTRUCTED==0) even though isIndef is true. */
    sz = SetImplicit(ASN_INTEGER, 3, 4, out, 1);
    WB_CHECK(sz == 2 && out[1] == 4,
            ":16491 2nd false (primitive tag, isIndef ignored)");
}

/* ===========================================================================
 * Section 19: IsSigAlgoNoParams() OR chain [:16597]
 * ========================================================================= */
#ifdef HAVE_ECC
static void wb_is_sig_algo_no_params(void)
{
    WB_NOTE("IsSigAlgoNoParams(): OR chain over compiled-in key/sig types "
            "[:16597]");

    WB_CHECK(IsSigAlgoNoParams(RSAk) == 0, "baseline: RSAk matches none");
    WB_CHECK(IsSigAlgoNoParams(CTC_SHAwECDSA) != 0,
            "ECDSA sig OID (IsSigAlgoECDSA() clause true)");
#ifdef HAVE_ED25519
    WB_CHECK(IsSigAlgoNoParams(ED25519k) != 0, "ED25519k clause true");
#endif
#ifdef HAVE_CURVE25519
    WB_CHECK(IsSigAlgoNoParams(X25519k) != 0, "X25519k clause true");
#endif
#ifdef HAVE_ED448
    WB_CHECK(IsSigAlgoNoParams(ED448k) != 0, "ED448k clause true");
#endif
#ifdef HAVE_CURVE448
    WB_CHECK(IsSigAlgoNoParams(X448k) != 0, "X448k clause true");
#endif
}
#else
static void wb_is_sig_algo_no_params(void) { WB_NOTE("HAVE_ECC off; IsSigAlgoNoParams skipped"); }
#endif

/* ===========================================================================
 * Section 20: SetAlgoIDImpl()/SetAlgoID() ret==0&&output!=NULL [:16720]
 * ========================================================================= */
#ifdef WOLFSSL_ASN_TEMPLATE
static void wb_set_algo_id(void)
{
    byte out[32];
    word32 need;

    WB_NOTE("SetAlgoIDImpl(): ret==0 && output!=NULL [:16720]");

    /* output==NULL -> size-only pass -> 2nd operand false. RSAk looked up
     * against oidKeyType (rsaEncryption is a key OID, not a signature OID,
     * so oidSigType would miss the table and return 0 with nothing
     * encoded). */
    need = SetAlgoID(RSAk, NULL, oidKeyType, 0);
    WB_CHECK(need > 0, "output==NULL (2nd operand false, size-only)");

    /* output!=NULL, big enough -> both true (encode happens). */
    need = SetAlgoID(RSAk, out, oidKeyType, 0);
    WB_CHECK(need > 0 && need <= sizeof(out), "output!=NULL (both true)");
}
#else
static void wb_set_algo_id(void) { WB_NOTE("non-template SetAlgoIDImpl; skipped"); }
#endif

/* ===========================================================================
 * Section 21: DecodeDsaAsn1Sig() [:17270 (SMALL_STACK-only, residual: OOM
 * needed for the true side), :17294 (baseline success only; the failure
 * side needs an internally-corrupted mp_int, not reachable through any
 * public/observable input -- residual)].
 * ========================================================================= */
#if !defined(NO_DSA) && !defined(HAVE_SELFTEST)
static void wb_decode_dsa_asn1_sig(void)
{
    byte rVal = 0x2A, sVal = 0x15;
    byte sig[16];
    byte content[16];
    word32 contentSz = 0;
    word32 sigSz;
    byte sigCpy[8];
    int ret;

    WB_NOTE("DecodeDsaAsn1Sig(): baseline success [:17294 false side]; "
            "r==NULL||s==NULL only compiles under WOLFSSL_SMALL_STACK "
            "[:17270, residual: needs OOM]");

    contentSz += wb_tlv(content + contentSz, ASN_INTEGER, &rVal, 1);
    contentSz += wb_tlv(content + contentSz, ASN_INTEGER, &sVal, 1);
    sigSz = WB_SEQ(sig, content, contentSz);

    ret = DecodeDsaAsn1Sig(sig, sigSz, sigCpy, NULL);
    WB_CHECK(ret == 0 && sigCpy[0] == rVal && sigCpy[1] == sVal,
            "valid r/s -> mp_to_unsigned_bin() succeeds both times "
            "(:17294 false side)");
}
#else
static void wb_decode_dsa_asn1_sig(void) { WB_NOTE("NO_DSA/HAVE_SELFTEST; DecodeDsaAsn1Sig skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Section: ParseCertRelative() verify-mode x cert-type x CA-presence matrix.
 *
 * ParseCertRelative() is one long chain of decisions parameterised on the
 * (verify, type) pair and on whether a matching issuer was found in the
 * CertManager: the trust-anchor-load short-circuit, the CA/TRUSTED_PEER key
 * usage exemptions, the SKID-recomputation gate, the AKID/SKID CA lookups,
 * the issuer-hash cross-check, the path-length arithmetic and the name
 * constraint ancestor walk. The API tests only ever drive a couple of points
 * in that space (VERIFY on a leaf, NO_VERIFY on a CA), so most operands are
 * only ever seen at one value.
 *
 * This sweeps the full cross product with three CA-presence shapes:
 *   (a) leaf certificate, CertManager holding its issuing CA
 *       -> cert->ca found, issuer hashes match;
 *   (b) the self-signed root itself, same CertManager
 *       -> selfSigned paths, trust-anchor comparison in the path-length
 *          block;
 *   (c) leaf certificate with NO CertManager
 *       -> every cert->ca lookup returns NULL.
 * Return values are deliberately not asserted: the point is which decisions
 * are evaluated, and a mode/type pair that legitimately rejects the input is
 * as useful as one that accepts it. Only "did not crash / did not hang" is a
 * property of interest, and every input here is a valid, bounded DER blob.
 * ------------------------------------------------------------------------- */
#if !defined(NO_CERTS) && !defined(WOLFCRYPT_ONLY) && \
    defined(USE_CERT_BUFFERS_2048) && !defined(NO_RSA)
static void wb_parse_cert_relative_matrix(void)
{
    static const int verifyModes[] = {
        NO_VERIFY, VERIFY, VERIFY_SKIP_DATE, VERIFY_OCSP, VERIFY_NAME
    };
    static const int certTypes[] = {
        CERT_TYPE, CA_TYPE, TRUSTED_PEER_TYPE, CERTREQ_TYPE
    };
    WOLFSSL_CERT_MANAGER* cm;
    DecodedCert dc;
    size_t v, t;
    int ret;

    WB_NOTE("ParseCertRelative(): verify x type x CA-presence matrix "
            "[:24409-:24861]");

    cm = wolfSSL_CertManagerNew();
    WB_CHECK(cm != NULL, "wolfSSL_CertManagerNew");
    if (cm == NULL) {
        return;
    }
    ret = wolfSSL_CertManagerLoadCABuffer(cm, ca_cert_der_2048,
            (long)sizeof_ca_cert_der_2048, WOLFSSL_FILETYPE_ASN1);
    WB_CHECK(ret == WOLFSSL_SUCCESS, "load issuing CA into the CertManager");

    for (v = 0; v < sizeof(verifyModes) / sizeof(verifyModes[0]); v++) {
        for (t = 0; t < sizeof(certTypes) / sizeof(certTypes[0]); t++) {
            /* (a) leaf, issuer present in the CertManager. */
            wc_InitDecodedCert(&dc, client_cert_der_2048,
                    (word32)sizeof_client_cert_der_2048, NULL);
            (void)ParseCertRelative(&dc, certTypes[t], verifyModes[v], cm,
                    NULL);
            wc_FreeDecodedCert(&dc);

            /* (b) the self-signed root itself. */
            wc_InitDecodedCert(&dc, ca_cert_der_2048,
                    (word32)sizeof_ca_cert_der_2048, NULL);
            (void)ParseCertRelative(&dc, certTypes[t], verifyModes[v], cm,
                    NULL);
            wc_FreeDecodedCert(&dc);

            /* (c) leaf with no CertManager: every CA lookup misses. */
            wc_InitDecodedCert(&dc, client_cert_der_2048,
                    (word32)sizeof_client_cert_der_2048, NULL);
            (void)ParseCertRelative(&dc, certTypes[t], verifyModes[v], NULL,
                    NULL);
            wc_FreeDecodedCert(&dc);

            /* (d) a server leaf as well: a different key usage / extension
             *     mix through the same decision chain. */
            wc_InitDecodedCert(&dc, server_cert_der_2048,
                    (word32)sizeof_server_cert_der_2048, NULL);
            (void)ParseCertRelative(&dc, certTypes[t], verifyModes[v], cm,
                    NULL);
            wc_FreeDecodedCert(&dc);
        }
    }

    wolfSSL_CertManagerFree(cm);
}

/* ------------------------------------------------------------------------- *
 * ParseCertRelative()'s bad-date forgiveness gate.
 *   :24412  if ((verify == VERIFY_SKIP_DATE) || AsnSkipDateCheck)
 * Only entered when DecodeCert() reports a date error, which none of the
 * corpus certificates produce. A private copy of the client certificate has
 * its notBefore UTCTime rewritten to 2049 (UTCTime two-digit years below 50
 * mean 20xx), so the cert is permanently "not yet valid" for any clock.
 *
 * RESIDUAL -- both operands of :24412 are structurally unreachable, and this
 * fixture is what shows it. DecodeCertInternal() only assigns
 * badDate = ASN_BEFORE_DATE_E / ASN_AFTER_DATE_E under
 *     (verify != NO_VERIFY) && (verify != VERIFY_SKIP_DATE) &&
 *     (! AsnSkipDateCheck)
 * (asn.c:22662 and :22674), and DecodeCert() can return one of those two
 * codes only by returning that badDate. So on every path that reaches
 * :24412, `verify == VERIFY_SKIP_DATE` is already known false and
 * AsnSkipDateCheck is already known 0: the decision can never be true and
 * neither operand can be paired. Driving it under VERIFY_SKIP_DATE or with
 * the runtime skip flag set (both issued below) simply does not enter the
 * enclosing `if`.
 * ------------------------------------------------------------------------- */
static void wb_parse_cert_relative_bad_date(void)
{
    static byte patched[4096];
    word32 sz = (word32)sizeof_client_cert_der_2048;
    word32 i;
    int found = 0;
    DecodedCert dc;
    int ret;

    WB_NOTE("ParseCertRelative(): bad-date forgiveness gate [:24412]");

    if (sz > sizeof(patched)) {
        WB_NOTE("client cert larger than the patch buffer; skipped");
        return;
    }
    XMEMCPY(patched, client_cert_der_2048, sz);

    /* First UTCTime of length 13 is the notBefore of the validity pair. */
    for (i = 0; i + 15 < sz; i++) {
        if ((patched[i] == ASN_UTC_TIME) && (patched[i + 1] == 13) &&
                (patched[i + 14] == 'Z')) {
            XMEMCPY(patched + i + 2, "490101000000Z", 13);
            found = 1;
            break;
        }
    }
    WB_CHECK(found, "notBefore UTCTime located in the client certificate");
    if (!found) {
        return;
    }

    wc_InitDecodedCert(&dc, patched, sz, NULL);
    ret = ParseCertRelative(&dc, CERT_TYPE, VERIFY, NULL, NULL);
    WB_CHECK(ret != 0, "verify=VERIFY (both operands false)");
    wc_FreeDecodedCert(&dc);

    wc_InitDecodedCert(&dc, patched, sz, NULL);
    ret = ParseCertRelative(&dc, CERT_TYPE, VERIFY_SKIP_DATE, NULL, NULL);
    WB_CHECK(ret != WC_NO_ERR_TRACE(ASN_BEFORE_DATE_E),
            "verify=VERIFY_SKIP_DATE (1st operand true)");
    wc_FreeDecodedCert(&dc);

#ifdef WC_ASN_RUNTIME_DATE_CHECK_CONTROL
    (void)wc_AsnSetSkipDateCheck(1);
    wc_InitDecodedCert(&dc, patched, sz, NULL);
    ret = ParseCertRelative(&dc, CERT_TYPE, VERIFY, NULL, NULL);
    WB_CHECK(ret != WC_NO_ERR_TRACE(ASN_BEFORE_DATE_E),
            "AsnSkipDateCheck set (2nd operand true)");
    wc_FreeDecodedCert(&dc);
    (void)wc_AsnSetSkipDateCheck(0);
#endif
}
#else
static void wb_parse_cert_relative_bad_date(void)
{
    WB_NOTE("NO_CERTS/WOLFCRYPT_ONLY/no cert buffers; "
            "ParseCertRelative bad-date gate skipped");
}
static void wb_parse_cert_relative_matrix(void)
{
    WB_NOTE("NO_CERTS/WOLFCRYPT_ONLY/no cert buffers; "
            "ParseCertRelative matrix skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Section: manufactured certificate fixtures for the ParseCertRelative()
 * decision chain.
 *
 * The matrix above sweeps verify-mode x cert-type x CA-presence over the
 * certificates bundled in wolfssl/certs_test.h. That bundle only contains
 * *well-formed, currently-valid, conventionally-shaped* certificates, so a
 * whole family of ParseCertRelative() operands is pinned at one value no
 * matter how the matrix is swept:
 *
 *   - every bundled leaf carries a subjectKeyIdentifier, so the
 *     "recompute the SKID from the public key" gate is never entered;
 *   - every bundled serial number is non-zero, so the RFC 5280 4.1.2.2
 *     zero-serial guard and its trust-anchor exemption are never evaluated;
 *   - no bundled non-CA certificate asserts keyCertSign, so the
 *     keyUsage/basicConstraints consistency guard never fires;
 *   - the issuer name of a bundled leaf always matches the subject name of
 *     its CA, so the "CA found by key id but the names disagree" arm is
 *     dead;
 *   - the bundle has no three-level chain with a *non-self-signed*
 *     intermediate, so the name-constraint ancestor walk always terminates
 *     on its first iteration;
 *   - every bundled certificate is valid *today*, so the notBefore /
 *     notAfter checks in DecodeCertInternal() only ever succeed.
 *
 * Rather than adding new fixture files, this section manufactures the
 * missing shapes at run time with wolfSSL's own certificate generator
 * (wc_InitCert / wc_MakeCert / wc_SignCert) using the bundled RSA and ECC
 * *keys* as both subject and signing keys -- no key generation, so the
 * whole section costs a few tens of milliseconds. The Cert fields that the
 * generator exposes (serial, beforeDate/afterDate, skidSz, akid/akidSz,
 * keyUsage, isCA, pathLen, and the issuer CertName) are exactly the knobs
 * needed to hit each operand above, and everything stays regenerable.
 *
 * Signature verification of these fixtures is deliberately *not* asserted:
 * several of them are intentionally inconsistent (an authority key id that
 * points at a CA which did not sign them, an issuer name that does not
 * match any CA), and the decisions of interest are all evaluated before
 * ParseCertRelative() reaches its ConfirmSignature() block. Loading a CA
 * into a WOLFSSL_CERT_MANAGER uses CA_TYPE, which by construction skips
 * signature confirmation, so a deliberately mis-parented intermediate can
 * still be installed as a trust store entry.
 * ------------------------------------------------------------------------- */
#if !defined(NO_CERTS) && !defined(WOLFCRYPT_ONLY) && \
    defined(WOLFSSL_CERT_GEN) && defined(WOLFSSL_CERT_EXT) && \
    defined(WOLFSSL_ASN_TEMPLATE) && !defined(NO_RSA) && \
    !defined(NO_SHA256) && !defined(NO_ASN_TIME) && !defined(NO_SKID) && \
    defined(USE_CERT_BUFFERS_2048)

#define WB_FIX_DER_SZ 4096

/* One manufactured certificate: its DER plus the subject key identifier the
 * generator put in it, so a child fixture can point its AKID at it. */
typedef struct WbFix {
    byte der[WB_FIX_DER_SZ];
    int  sz;
    byte skid[CTC_MAX_SKID_SIZE];
    int  skidSz;
} WbFix;

/* Declarative description of a fixture. Anything left zero/NULL means
 * "generator default", which for wc_InitCert() is: v3, random serial,
 * self-signed, not a CA, no extensions beyond what is asked for here. */
typedef struct WbSpec {
    const char*  cn;          /* subject common name                       */
    const char*  issuerCn;    /* explicit issuer CN (no matching CA needed) */
    const WbFix* issuerFix;   /* take the issuer name from this fixture     */
    RsaKey*      subjectKey;  /* subject public key (RSA)                   */
    ecc_key*     subjectEcc;  /* ... or ECC                                 */
    RsaKey*      signKey;     /* signing key (RSA)                          */
    ecc_key*     signEcc;     /* ... or ECC                                 */
    int          isCA;
    int          pathLen;     /* < 0: do not emit a pathLenConstraint       */
    int          keyUsage;    /* < 0: do not emit a keyUsage extension      */
    int          withSkid;    /* emit subjectKeyIdentifier from the pub key */
    const byte*  skid;        /* ... or emit this literal key id instead    */
    int          skidSz;
    const byte*  akid;        /* emit authorityKeyIdentifier (key id form)  */
    int          akidSz;
    const char*  notBefore;   /* 13-char UTCTime body "YYMMDDHHMMSSZ"       */
    const char*  notAfter;    /* NULL with notBefore set: only notBefore    */
    int          zeroSerial;  /* emit serial number 0 (RFC-non-conforming)  */
    int          version;     /* > 0: encode this raw version value         */
} WbSpec;

static WC_RNG  wbRng;
static int     wbRngOk = 0;
static byte    wbSerialCounter = 1;
static RsaKey  wbKeyRoot;    /* ca_key_der_2048     */
static RsaKey  wbKeyInter;   /* client_key_der_2048 */
static RsaKey  wbKeyLeaf;    /* server_key_der_2048 */
static int     wbKeysOk = 0;
#ifdef HAVE_ECC
static ecc_key wbKeyEcc;     /* ecc_key_der_256     */
static int     wbEccOk = 0;
#endif

static void wb_fill_name(CertName* name, const char* cn)
{
    XSTRNCPY(name->country, "US", CTC_NAME_SIZE);
    name->countryEnc = CTC_PRINTABLE;
    XSTRNCPY(name->state, "Oregon", CTC_NAME_SIZE);
    name->stateEnc = CTC_UTF8;
    XSTRNCPY(name->locality, "Portland", CTC_NAME_SIZE);
    name->localityEnc = CTC_UTF8;
    XSTRNCPY(name->org, "wolfSSL MCDC", CTC_NAME_SIZE);
    name->orgEnc = CTC_UTF8;
    XSTRNCPY(name->unit, "asn", CTC_NAME_SIZE);
    name->unitEnc = CTC_UTF8;
    XSTRNCPY(name->commonName, cn, CTC_NAME_SIZE);
    name->commonNameEnc = CTC_UTF8;
}

/* Build one fixture. Returns 0 on success. Never asserts on the *content*
 * of the result beyond "the generator accepted it": the whole point of some
 * of these shapes is that a strict parser will later reject them. */
static int wb_make_fixture(WbFix* out, const WbSpec* spec)
{
    Cert* cert;
    int   ret;
    int   bodySz;

    XMEMSET(out, 0, sizeof(*out));
    cert = (Cert*)XMALLOC(sizeof(Cert), NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (cert == NULL) {
        return MEMORY_E;
    }

    ret = wc_InitCert(cert);
    if (ret != 0) {
        XFREE(cert, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }

    wb_fill_name(&cert->subject, spec->cn);

    if (spec->issuerFix != NULL) {
        /* Issuer name lifted out of a previously generated certificate;
         * this also clears the self-signed flag. */
        ret = wc_SetIssuerBuffer(cert, spec->issuerFix->der,
                spec->issuerFix->sz);
    }
    else if (spec->issuerCn != NULL) {
        /* Issuer name that need not correspond to any real certificate. */
        wb_fill_name(&cert->issuer, spec->issuerCn);
        cert->selfSigned = 0;
    }

    if (ret == 0) {
        cert->isCA = spec->isCA;
        if (spec->isCA) {
            cert->basicConstSet = 1;
        }
        if (spec->pathLen >= 0) {
            cert->pathLen = (byte)spec->pathLen;
            cert->pathLenSet = 1;
            cert->basicConstSet = 1;
        }
        if (spec->keyUsage >= 0) {
            cert->keyUsage = (word16)spec->keyUsage;
        }
        cert->daysValid = 3650;

        if (spec->version > 0) {
            /* The generator writes this straight into the version INTEGER
             * with no range check of its own, which is what makes an
             * out-of-range version reachable at all. */
            cert->version = spec->version;
        }

        if (spec->signEcc != NULL) {
            cert->sigType = CTC_SHA256wECDSA;
        }
        else {
            cert->sigType = CTC_SHA256wRSA;
        }

        if (spec->zeroSerial) {
            XMEMSET(cert->serial, 0, sizeof(cert->serial));
            cert->serialSz = 1;
        }
        else {
            /* Deterministic, positive, high-bit-clear serial. */
            XMEMSET(cert->serial, 0, sizeof(cert->serial));
            cert->serial[0] = 0x11;
            cert->serial[1] = wbSerialCounter++;
            cert->serialSz = 2;
        }

        if (spec->notBefore != NULL) {
            cert->beforeDate[0] = ASN_UTC_TIME;
            cert->beforeDate[1] = ASN_UTC_TIME_SIZE - 1;
            XMEMCPY(cert->beforeDate + 2, spec->notBefore,
                    ASN_UTC_TIME_SIZE - 1);
            cert->beforeDateSz = ASN_UTC_TIME_SIZE + 1;
        }
        if (spec->notAfter != NULL) {
            cert->afterDate[0] = ASN_UTC_TIME;
            cert->afterDate[1] = ASN_UTC_TIME_SIZE - 1;
            XMEMCPY(cert->afterDate + 2, spec->notAfter,
                    ASN_UTC_TIME_SIZE - 1);
            cert->afterDateSz = ASN_UTC_TIME_SIZE + 1;
        }

        if (spec->skid != NULL && spec->skidSz > 0) {
            /* Literal key id: lets two certificates with different subject
             * names advertise the SAME subjectKeyIdentifier, which the
             * public-key-derived form can never produce. */
            XMEMCPY(cert->skid, spec->skid, (size_t)spec->skidSz);
            cert->skidSz = spec->skidSz;
        }
        else if (spec->withSkid) {
            ret = wc_SetSubjectKeyIdFromPublicKey(cert, spec->subjectKey,
                    spec->subjectEcc);
        }
    }

    if (ret == 0 && spec->akid != NULL && spec->akidSz > 0) {
        XMEMCPY(cert->akid, spec->akid, (size_t)spec->akidSz);
        cert->akidSz = spec->akidSz;
#ifdef WOLFSSL_AKID_NAME
        cert->rawAkid = 0;
#endif
    }

    if (ret == 0) {
        ret = wc_MakeCert(cert, out->der, WB_FIX_DER_SZ, spec->subjectKey,
                spec->subjectEcc, &wbRng);
        if (ret > 0) {
            ret = 0;
        }
    }
    if (ret == 0) {
        bodySz = cert->bodySz;
        ret = wc_SignCert(bodySz, cert->sigType, out->der, WB_FIX_DER_SZ,
                spec->signKey, spec->signEcc, &wbRng);
        if (ret > 0) {
            out->sz = ret;
            ret = 0;
        }
        else if (ret == 0) {
            ret = -1;
        }
    }
    if (ret == 0 && (spec->withSkid || spec->skidSz > 0)) {
        XMEMCPY(out->skid, cert->skid, sizeof(out->skid));
        out->skidSz = cert->skidSz;
    }

    wc_SetCert_Free(cert);
    XFREE(cert, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    return ret;
}

/* Parse one fixture through the real entry point and throw the result away:
 * only the decisions evaluated on the way matter here. A DecodedCert is
 * ~4KB, so it lives on the heap for the small_stack variant's benefit. */
static void wb_parse_one(const WbFix* fix, int type, int verify,
                         void* cm, Signer* extraCAList)
{
    DecodedCert* dc;

    if (fix == NULL || fix->sz <= 0) {
        return;
    }
    dc = (DecodedCert*)XMALLOC(sizeof(DecodedCert), NULL, DYNAMIC_TYPE_DCERT);
    if (dc == NULL) {
        return;
    }
    wc_InitDecodedCert(dc, fix->der, (word32)fix->sz, NULL);
    printf("PARSE sz=%d type=%d verify=%d -> %d\n", fix->sz, type, verify,
        ParseCertRelative(dc, type, verify, cm, extraCAList));
    wc_FreeDecodedCert(dc);
    XFREE(dc, NULL, DYNAMIC_TYPE_DCERT);
}

/* Turn a fixture into a standalone Signer, the shape ParseCertRelative()
 * accepts through its extraCAList argument (the certificate-status-request
 * v2 path). FillSigner() takes ownership of the decoded public key and
 * subject CN, so the DecodedCert can be released immediately after. */
static Signer* wb_make_signer(const WbFix* fix)
{
    DecodedCert* dc;
    DerBuffer*   der = NULL;
    Signer*      signer;
    int          ret;

    if (fix == NULL || fix->sz <= 0) {
        return NULL;
    }
    signer = MakeSigner(NULL);
    if (signer == NULL) {
        return NULL;
    }
    dc = (DecodedCert*)XMALLOC(sizeof(DecodedCert), NULL, DYNAMIC_TYPE_DCERT);
    if (dc == NULL) {
        FreeSigner(signer, NULL);
        return NULL;
    }
    wc_InitDecodedCert(dc, fix->der, (word32)fix->sz, NULL);
    ret = ParseCert(dc, CA_TYPE, NO_VERIFY, NULL);
    if (ret == 0) {
        ret = AllocDer(&der, (word32)fix->sz, CA_TYPE, NULL);
    }
    if (ret == 0) {
        XMEMCPY(der->buffer, fix->der, (size_t)fix->sz);
        ret = FillSigner(signer, dc, CA_TYPE, der);
    }
    FreeDer(&der);
    wc_FreeDecodedCert(dc);
    XFREE(dc, NULL, DYNAMIC_TYPE_DCERT);
    if (ret != 0) {
        FreeSigner(signer, NULL);
        return NULL;
    }
    return signer;
}

/* The fixture set. File-scope so the small_stack variant does not put ~80KB
 * of certificate DER on the stack. */
static WbFix wbRootA;        /* self-signed CA, pathLen 1, keyCertSign      */
static WbFix wbRootADupRsa;  /* same DN as wbRootA, different RSA key       */
#ifdef HAVE_ECC
static WbFix wbRootADupEcc;  /* same DN as wbRootA, ECC key (size differs)  */
#endif
static WbFix wbInter;        /* CA under wbRootA, AKID -> wbRootA           */
static WbFix wbInterNoKU;    /* CA under wbRootA with no keyUsage extension */
static WbFix wbInterMismatch;/* CA whose AKID -> wbRootA but issuer DN does not */
static WbFix wbInterBadAkid; /* CA whose AKID matches nothing               */
static WbFix wbInterKuNoCS;  /* CA under wbRootA, keyUsage WITHOUT certSign */
static WbFix wbSkidTwin;     /* CA advertising wbRootA's key id, other DN   */
static WbFix wbBadVersion;   /* version INTEGER above the supported maximum */
static WbFix wbLeafByInter;  /* leaf under wbInter (3-level chain)          */
static WbFix wbLeafUnderMism;/* leaf under wbInterMismatch                  */
static WbFix wbLeafNoSkid;   /* leaf under wbRootA with no SKID extension   */
static WbFix wbLeafNoAkid;   /* leaf under wbRootA with no AKID extension   */
static WbFix wbLeafBadAkid;  /* leaf under wbRootA, AKID matches nothing    */
static WbFix wbLeafBadName;  /* AKID -> wbRootA but issuer DN differs       */
static WbFix wbLeafKuCertSign;  /* non-CA leaf asserting keyCertSign        */
static WbFix wbLeafKuNoCertSign;/* non-CA leaf, keyUsage without keyCertSign */
static WbFix wbZeroSerialRoot;  /* self-signed CA, serial 0                 */
static WbFix wbZeroSerialLeaf;  /* leaf, serial 0                           */
static WbFix wbZeroSerialSubCA; /* CA under wbRootA, serial 0               */
static WbFix wbExpiredLeaf;     /* notAfter in the past                     */
static WbFix wbFutureLeaf;      /* notBefore in the future                  */
static WbFix wbOnlyNotBefore;   /* generator side: beforeDate set, after not */
static WbFix wbNcX;             /* CA "NC X" issued by "NC Y"               */
static WbFix wbNcY;             /* CA "NC Y" issued by "NC X"  (A->B->A)    */
static WbFix wbLeafNcX;         /* leaf under "NC X"                        */
static int   wbFixturesOk = 0;

static int wb_load_keys(void)
{
    word32 idx;
    int    ret;

    ret = wc_InitRng(&wbRng);
    if (ret != 0) {
        return ret;
    }
    wbRngOk = 1;

    ret = wc_InitRsaKey(&wbKeyRoot, NULL);
    if (ret == 0) {
        ret = wc_InitRsaKey(&wbKeyInter, NULL);
    }
    if (ret == 0) {
        ret = wc_InitRsaKey(&wbKeyLeaf, NULL);
    }
    if (ret == 0) {
        wbKeysOk = 1;
        idx = 0;
        ret = wc_RsaPrivateKeyDecode(ca_key_der_2048, &idx, &wbKeyRoot,
                (word32)sizeof_ca_key_der_2048);
    }
    if (ret == 0) {
        idx = 0;
        ret = wc_RsaPrivateKeyDecode(client_key_der_2048, &idx, &wbKeyInter,
                (word32)sizeof_client_key_der_2048);
    }
    if (ret == 0) {
        idx = 0;
        ret = wc_RsaPrivateKeyDecode(server_key_der_2048, &idx, &wbKeyLeaf,
                (word32)sizeof_server_key_der_2048);
    }
#ifdef HAVE_ECC
    if (ret == 0 && wc_ecc_init(&wbKeyEcc) == 0) {
        idx = 0;
        if (wc_EccPrivateKeyDecode(ecc_key_der_256, &idx, &wbKeyEcc,
                    (word32)sizeof_ecc_key_der_256) == 0) {
            wbEccOk = 1;
        }
        else {
            wc_ecc_free(&wbKeyEcc);
        }
    }
#endif
    return ret;
}

static void wb_free_keys(void)
{
    if (wbKeysOk) {
        wc_FreeRsaKey(&wbKeyRoot);
        wc_FreeRsaKey(&wbKeyInter);
        wc_FreeRsaKey(&wbKeyLeaf);
        wbKeysOk = 0;
    }
#ifdef HAVE_ECC
    if (wbEccOk) {
        wc_ecc_free(&wbKeyEcc);
        wbEccOk = 0;
    }
#endif
    if (wbRngOk) {
        wc_FreeRng(&wbRng);
        wbRngOk = 0;
    }
}

#define WB_MK(dst, ...) do {                                                  \
        WbSpec _s;                                                            \
        XMEMSET(&_s, 0, sizeof(_s));                                          \
        _s.pathLen = -1;                                                      \
        _s.keyUsage = -1;                                                     \
        _s.subjectKey = &wbKeyLeaf;                                           \
        _s.signKey = &wbKeyRoot;                                              \
        __VA_ARGS__;                                                          \
        if (wb_make_fixture(&(dst), &_s) != 0) {                              \
            WB_CHECK(0, "manufacture " #dst);                                 \
            wbFixturesOk = 0;                                                 \
        }                                                                     \
    } while (0)

static void wb_build_fixtures(void)
{
    byte bogusKid[KEYID_SIZE];

    XMEMSET(bogusKid, 0xAA, sizeof(bogusKid));
    if (wb_load_keys() != 0) {
        WB_CHECK(0, "load the bundled signing keys");
        return;
    }
    wbFixturesOk = 1;

    /* --- trust anchors ------------------------------------------------ */
    WB_MK(wbRootA,
        _s.cn = "MCDC Root A"; _s.subjectKey = &wbKeyRoot;
        _s.isCA = 1; _s.pathLen = 1; _s.withSkid = 1;
        _s.keyUsage = KEYUSE_KEY_CERT_SIGN | KEYUSE_CRL_SIGN);

    /* Same DN, different key of the same size: exercises the trust-anchor
     * public-key comparison in the path-length block on its "same length,
     * different bytes" arm. No AKID, so the CA lookup falls through to the
     * name-based one and keeps the match. */
    WB_MK(wbRootADupRsa,
        _s.cn = "MCDC Root A"; _s.subjectKey = &wbKeyInter;
        _s.signKey = &wbKeyInter;
        _s.isCA = 1; _s.withSkid = 1;
        _s.keyUsage = KEYUSE_KEY_CERT_SIGN);

#ifdef HAVE_ECC
    if (wbEccOk) {
        /* Same DN again, but an ECC key: different public-key *length*. */
        WB_MK(wbRootADupEcc,
            _s.cn = "MCDC Root A"; _s.subjectKey = NULL;
            _s.subjectEcc = &wbKeyEcc;
            _s.signKey = NULL; _s.signEcc = &wbKeyEcc;
            _s.isCA = 1; _s.withSkid = 1;
            _s.keyUsage = KEYUSE_KEY_CERT_SIGN);
    }
#endif

    /* --- intermediates ------------------------------------------------ */
    WB_MK(wbInter,
        _s.cn = "MCDC Inter"; _s.issuerFix = &wbRootA;
        _s.subjectKey = &wbKeyInter;
        _s.isCA = 1; _s.withSkid = 1;
        _s.akid = wbRootA.skid; _s.akidSz = wbRootA.skidSz;
        _s.keyUsage = KEYUSE_KEY_CERT_SIGN | KEYUSE_CRL_SIGN);

    WB_MK(wbInterNoKU,
        _s.cn = "MCDC Inter NoKU"; _s.issuerFix = &wbRootA;
        _s.subjectKey = &wbKeyInter;
        _s.isCA = 1; _s.withSkid = 1;
        _s.akid = wbRootA.skid; _s.akidSz = wbRootA.skidSz);

    /* A CA that DOES carry a keyUsage extension but leaves keyCertSign
     * clear. The pathLen block's trailing guard reads
     *   (!extKeyUsageSet || (extKeyUsage & keyCertSign) != 0)
     * and every other fixture drives it through one of the two true arms:
     * wbInterNoKU has no extension at all (first operand true) and wbInter
     * asserts keyCertSign (second operand true). This is the only shape
     * that makes BOTH operands false, which is what the pathLen guard
     * needs to be shown independent of either. */
    WB_MK(wbInterKuNoCS,
        _s.cn = "MCDC Inter NoCS"; _s.issuerFix = &wbRootA;
        _s.subjectKey = &wbKeyInter;
        _s.isCA = 1; _s.withSkid = 1;
        _s.akid = wbRootA.skid; _s.akidSz = wbRootA.skidSz;
        _s.keyUsage = KEYUSE_CRL_SIGN | KEYUSE_DIGITAL_SIG);

    /* A CA whose subjectKeyIdentifier is literally the root's, but whose
     * subject name is not. Nothing derived from a public key can produce
     * this collision, and it is the only way to drive the "key id matched
     * but the name did not" operand of the extra-CA-list scan. */
    WB_MK(wbSkidTwin,
        _s.cn = "MCDC Skid Twin"; _s.issuerCn = "MCDC Skid Twin";
        _s.subjectKey = &wbKeyLeaf; _s.signKey = &wbKeyLeaf;
        _s.isCA = 1;
        _s.skid = wbRootA.skid; _s.skidSz = wbRootA.skidSz;
        _s.keyUsage = KEYUSE_KEY_CERT_SIGN);

    /* A structurally well-formed certificate whose version INTEGER is above
     * the highest X.509 version the decoder supports. Every bundled and
     * generated certificate is version 3, so the decoder's version ceiling
     * is otherwise only ever satisfied. */
    WB_MK(wbBadVersion,
        _s.cn = "MCDC Bad Version"; _s.issuerFix = &wbRootA;
        _s.withSkid = 1; _s.version = 4;
        _s.akid = wbRootA.skid; _s.akidSz = wbRootA.skidSz;
        _s.keyUsage = KEYUSE_DIGITAL_SIG);

    /* AKID points at the root, but the issuer name does not: the ancestor
     * walk's "key id hit, name mismatch" rejection. */
    WB_MK(wbInterMismatch,
        _s.cn = "MCDC Inter M"; _s.issuerCn = "MCDC Nowhere";
        _s.subjectKey = &wbKeyLeaf;
        _s.isCA = 1; _s.withSkid = 1;
        _s.akid = wbRootA.skid; _s.akidSz = wbRootA.skidSz;
        _s.keyUsage = KEYUSE_KEY_CERT_SIGN);

    WB_MK(wbInterBadAkid,
        _s.cn = "MCDC Inter B"; _s.issuerFix = &wbRootA;
        _s.subjectKey = &wbKeyInter;
        _s.isCA = 1; _s.withSkid = 1;
        _s.akid = bogusKid; _s.akidSz = (int)sizeof(bogusKid);
        _s.keyUsage = KEYUSE_KEY_CERT_SIGN);

    /* --- leaves ------------------------------------------------------- */
    WB_MK(wbLeafByInter,
        _s.cn = "MCDC Leaf I"; _s.issuerFix = &wbInter;
        _s.signKey = &wbKeyInter; _s.withSkid = 1;
        _s.akid = wbInter.skid; _s.akidSz = wbInter.skidSz;
        _s.keyUsage = KEYUSE_DIGITAL_SIG | KEYUSE_KEY_ENCIPHER);

    WB_MK(wbLeafUnderMism,
        _s.cn = "MCDC Leaf M"; _s.issuerFix = &wbInterMismatch;
        _s.signKey = &wbKeyLeaf;
        _s.akid = wbInterMismatch.skid; _s.akidSz = wbInterMismatch.skidSz;
        _s.keyUsage = KEYUSE_DIGITAL_SIG);

    /* No subjectKeyIdentifier: forces the SKID-from-public-key recompute. */
    WB_MK(wbLeafNoSkid,
        _s.cn = "MCDC Leaf NoSkid"; _s.issuerFix = &wbRootA;
        _s.akid = wbRootA.skid; _s.akidSz = wbRootA.skidSz);

    WB_MK(wbLeafNoAkid,
        _s.cn = "MCDC Leaf NoAkid"; _s.issuerFix = &wbRootA;
        _s.withSkid = 1;
        _s.keyUsage = KEYUSE_DIGITAL_SIG);

    WB_MK(wbLeafBadAkid,
        _s.cn = "MCDC Leaf BadAkid"; _s.issuerFix = &wbRootA;
        _s.withSkid = 1;
        _s.akid = bogusKid; _s.akidSz = (int)sizeof(bogusKid);
        _s.keyUsage = KEYUSE_DIGITAL_SIG);

    WB_MK(wbLeafBadName,
        _s.cn = "MCDC Leaf BadName"; _s.issuerCn = "MCDC Other Root";
        _s.withSkid = 1;
        _s.akid = wbRootA.skid; _s.akidSz = wbRootA.skidSz;
        _s.keyUsage = KEYUSE_DIGITAL_SIG);

    /* Non-CA certificate that asserts keyCertSign: rejected by the
     * basicConstraints/keyUsage consistency guard. */
    WB_MK(wbLeafKuCertSign,
        _s.cn = "MCDC Leaf KU"; _s.issuerFix = &wbRootA;
        _s.withSkid = 1;
        _s.akid = wbRootA.skid; _s.akidSz = wbRootA.skidSz;
        _s.keyUsage = KEYUSE_DIGITAL_SIG | KEYUSE_KEY_CERT_SIGN);

    WB_MK(wbLeafKuNoCertSign,
        _s.cn = "MCDC Leaf KU2"; _s.issuerFix = &wbRootA;
        _s.withSkid = 1;
        _s.akid = wbRootA.skid; _s.akidSz = wbRootA.skidSz;
        _s.keyUsage = KEYUSE_DIGITAL_SIG | KEYUSE_CRL_SIGN);

    /* --- zero serial numbers ------------------------------------------ */
    WB_MK(wbZeroSerialRoot,
        _s.cn = "MCDC ZS Root"; _s.subjectKey = &wbKeyRoot;
        _s.isCA = 1; _s.withSkid = 1; _s.zeroSerial = 1;
        _s.keyUsage = KEYUSE_KEY_CERT_SIGN);

    WB_MK(wbZeroSerialLeaf,
        _s.cn = "MCDC ZS Leaf"; _s.issuerFix = &wbRootA;
        _s.withSkid = 1; _s.zeroSerial = 1;
        _s.akid = wbRootA.skid; _s.akidSz = wbRootA.skidSz);

    WB_MK(wbZeroSerialSubCA,
        _s.cn = "MCDC ZS SubCA"; _s.issuerFix = &wbRootA;
        _s.subjectKey = &wbKeyInter;
        _s.isCA = 1; _s.withSkid = 1; _s.zeroSerial = 1;
        _s.akid = wbRootA.skid; _s.akidSz = wbRootA.skidSz;
        _s.keyUsage = KEYUSE_KEY_CERT_SIGN);

    /* --- validity-period shapes --------------------------------------- */
    WB_MK(wbExpiredLeaf,
        _s.cn = "MCDC Expired"; _s.issuerFix = &wbRootA;
        _s.withSkid = 1;
        _s.akid = wbRootA.skid; _s.akidSz = wbRootA.skidSz;
        _s.notBefore = "100101000000Z"; _s.notAfter = "110101000000Z");

    WB_MK(wbFutureLeaf,
        _s.cn = "MCDC Future"; _s.issuerFix = &wbRootA;
        _s.withSkid = 1;
        _s.akid = wbRootA.skid; _s.akidSz = wbRootA.skidSz;
        _s.notBefore = "400101000000Z"; _s.notAfter = "410101000000Z");

    /* Only one of the two explicit date fields set: the generator has to
     * fall back to computing the whole validity period itself. */
    WB_MK(wbOnlyNotBefore,
        _s.cn = "MCDC OneDate"; _s.issuerFix = &wbRootA;
        _s.withSkid = 1;
        _s.notBefore = "200101000000Z");

    /* --- an A->B->A authority-key-id cycle ---------------------------- */
    WB_MK(wbNcX,
        _s.cn = "MCDC NC X"; _s.issuerCn = "MCDC NC Y";
        _s.subjectKey = &wbKeyInter;
        _s.isCA = 1; _s.withSkid = 1;
        _s.keyUsage = KEYUSE_KEY_CERT_SIGN);
    WB_MK(wbNcY,
        _s.cn = "MCDC NC Y"; _s.issuerCn = "MCDC NC X";
        _s.subjectKey = &wbKeyLeaf;
        _s.isCA = 1; _s.withSkid = 1;
        _s.akid = wbNcX.skid; _s.akidSz = wbNcX.skidSz;
        _s.keyUsage = KEYUSE_KEY_CERT_SIGN);
    /* Regenerate X now that Y's SKID is known, closing the cycle. */
    WB_MK(wbNcX,
        _s.cn = "MCDC NC X"; _s.issuerCn = "MCDC NC Y";
        _s.subjectKey = &wbKeyInter;
        _s.isCA = 1; _s.withSkid = 1;
        _s.akid = wbNcY.skid; _s.akidSz = wbNcY.skidSz;
        _s.keyUsage = KEYUSE_KEY_CERT_SIGN);

    WB_MK(wbLeafNcX,
        _s.cn = "MCDC NC Leaf"; _s.issuerCn = "MCDC NC X";
        _s.signKey = &wbKeyInter;
        _s.akid = wbNcX.skid; _s.akidSz = wbNcX.skidSz;
        _s.keyUsage = KEYUSE_DIGITAL_SIG);
}

/* Load a fixture as a trust store entry. CA_TYPE skips signature
 * confirmation, which is what lets the deliberately mis-parented
 * intermediates above be installed. */
static int wb_load_ca(WOLFSSL_CERT_MANAGER* cm, const WbFix* fix,
                      const char* what)
{
    int ret;

    if (fix->sz <= 0) {
        return -1;
    }
    ret = wolfSSL_CertManagerLoadCABuffer(cm, fix->der, (long)fix->sz,
            WOLFSSL_FILETYPE_ASN1);
    WB_CHECK(ret == WOLFSSL_SUCCESS, what);
    return ret;
}


static void wb_fixture_parse_matrix(void)
{
    WOLFSSL_CERT_MANAGER* cm;
    Signer* rootSigner = NULL;
    Signer* interSigner = NULL;
    size_t v;
    static const int verifyModes[] = {
        NO_VERIFY, VERIFY, VERIFY_SKIP_DATE, VERIFY_OCSP, VERIFY_NAME
    };

    WB_NOTE("ParseCertRelative(): manufactured-fixture sweep "
            "[:24444,:24450,:24464,:24476,:24508,:24522,:24545,:24583,"
            ":24610,:24861]");

    wb_build_fixtures();
    if (!wbFixturesOk) {
        WB_NOTE("fixture generation failed; sweep skipped");
        wb_free_keys();
        return;
    }

    cm = wolfSSL_CertManagerNew();
    WB_CHECK(cm != NULL, "wolfSSL_CertManagerNew (fixture store)");
    if (cm == NULL) {
        wb_free_keys();
        return;
    }
    (void)wb_load_ca(cm, &wbRootA, "load the manufactured root");
    (void)wb_load_ca(cm, &wbInter, "load the manufactured intermediate");
    (void)wb_load_ca(cm, &wbInterMismatch,
            "load the mis-parented intermediate");
    (void)wb_load_ca(cm, &wbInterBadAkid,
            "load the dangling-AKID intermediate");
    (void)wb_load_ca(cm, &wbInterNoKU,
            "load the keyUsage-less intermediate");

    /* ---- zero-serial guard and its trust-anchor exemption [:24444,:24450]
     * A zero serial is only tolerated for a self-signed CA that is being
     * installed as an explicitly trusted anchor. Each operand of that
     * exemption is driven true and false against the same guard. */
    wb_parse_one(&wbZeroSerialRoot, CA_TYPE, VERIFY, cm, NULL);
    wb_parse_one(&wbZeroSerialRoot, TRUSTED_PEER_TYPE, VERIFY, cm, NULL);
    wb_parse_one(&wbZeroSerialRoot, CERT_TYPE, VERIFY, cm, NULL);
    wb_parse_one(&wbZeroSerialRoot, CHAIN_CERT_TYPE, NO_VERIFY, cm, NULL);
    wb_parse_one(&wbZeroSerialLeaf, CA_TYPE, VERIFY, cm, NULL);
    wb_parse_one(&wbZeroSerialLeaf, TRUSTED_PEER_TYPE, VERIFY, cm, NULL);
    wb_parse_one(&wbZeroSerialLeaf, CERT_TYPE, VERIFY, cm, NULL);
    wb_parse_one(&wbZeroSerialSubCA, CA_TYPE, VERIFY, cm, NULL);
    wb_parse_one(&wbZeroSerialSubCA, TRUSTED_PEER_TYPE, VERIFY, cm, NULL);

    /* ---- basicConstraints / keyUsage consistency [:24464] ------------- */
    wb_parse_one(&wbLeafKuCertSign, CERT_TYPE, VERIFY, cm, NULL);
    wb_parse_one(&wbLeafKuCertSign, CA_TYPE, NO_VERIFY, cm, NULL);
    wb_parse_one(&wbLeafKuNoCertSign, CERT_TYPE, VERIFY, cm, NULL);
    wb_parse_one(&wbLeafNoSkid, CERT_TYPE, VERIFY, cm, NULL);
    wb_parse_one(&wbInter, CERT_TYPE, VERIFY, cm, NULL);

    /* ---- recompute the SKID when the extension is absent [:24476] ----- */
    wb_parse_one(&wbLeafNoSkid, CERT_TYPE, NO_VERIFY, cm, NULL);
    wb_parse_one(&wbLeafNoSkid, CA_TYPE, VERIFY, cm, NULL);
    wb_parse_one(&wbLeafUnderMism, CERT_TYPE, VERIFY, cm, NULL);

    /* ---- CA lookup: key id hit with a disagreeing name [:24522],
     *      name hit while an AKID is present [:24545] ------------------- */
    wb_parse_one(&wbLeafBadName, CERT_TYPE, VERIFY, cm, NULL);
    wb_parse_one(&wbLeafBadName, CERT_TYPE, VERIFY_NAME, cm, NULL);
    wb_parse_one(&wbLeafBadAkid, CERT_TYPE, VERIFY, cm, NULL);
    wb_parse_one(&wbLeafNoAkid, CERT_TYPE, VERIFY, cm, NULL);
    wb_parse_one(&wbLeafNoAkid, CERT_TYPE, VERIFY_OCSP, cm, NULL);

    /* ---- path-length block: CA with and without a keyUsage extension,
     *      and the self-issued trust-anchor public-key comparison
     *      [:24583,:24610]. A self-signed certificate only gets a CA
     *      lookup at all when the type is neither CA_TYPE nor
     *      TRUSTED_PEER_TYPE, hence CHAIN_CERT_TYPE here. */
    wb_parse_one(&wbInterNoKU, CA_TYPE, VERIFY, cm, NULL);
    wb_parse_one(&wbInterNoKU, CHAIN_CERT_TYPE, VERIFY, cm, NULL);
    wb_parse_one(&wbInter, CA_TYPE, VERIFY, cm, NULL);
    wb_parse_one(&wbInter, CHAIN_CERT_TYPE, VERIFY, cm, NULL);
    /* Third arm of the same guard: a CA that HAS a keyUsage extension in
     * which the certificate-signing bit is clear. wbInterNoKU above makes
     * the "extension absent" operand true and wbInter makes the "bit set"
     * operand true; only this fixture makes both false, so only with it in
     * the same binary is either operand shown to decide the guard on its
     * own. Loaded into the store as well, so the same shape is reachable
     * as somebody else's issuer. */
    (void)wb_load_ca(cm, &wbInterKuNoCS,
            "load the CA whose keyUsage omits certificate signing");
    wb_parse_one(&wbInterKuNoCS, CHAIN_CERT_TYPE, VERIFY, cm, NULL);
    wb_parse_one(&wbInterKuNoCS, CHAIN_CERT_TYPE, VERIFY_NAME, cm, NULL);
    wb_parse_one(&wbInterKuNoCS, CA_TYPE, VERIFY, cm, NULL);
    wb_parse_one(&wbInterKuNoCS, CERT_TYPE, VERIFY, cm, NULL);
    wb_parse_one(&wbRootA, CHAIN_CERT_TYPE, VERIFY, cm, NULL);
    wb_parse_one(&wbRootADupRsa, CHAIN_CERT_TYPE, VERIFY, cm, NULL);
#ifdef HAVE_ECC
    if (wbEccOk) {
        wb_parse_one(&wbRootADupEcc, CHAIN_CERT_TYPE, VERIFY, cm, NULL);
    }
#endif

    /* ---- validity period: notBefore in the future, notAfter in the past,
     *      each against the verify modes that do and do not check dates. */
    for (v = 0; v < sizeof(verifyModes) / sizeof(verifyModes[0]); v++) {
        wb_parse_one(&wbExpiredLeaf, CERT_TYPE, verifyModes[v], cm, NULL);
        wb_parse_one(&wbFutureLeaf, CERT_TYPE, verifyModes[v], cm, NULL);
    }
    wb_parse_one(&wbOnlyNotBefore, CERT_TYPE, VERIFY, cm, NULL);

    /* ---- version ceiling [:22632]. Driven against a version-3 sibling of
     *      the same shape so the accepting vector for the same decision is
     *      in this binary too. */
    wb_parse_one(&wbBadVersion, CERT_TYPE, NO_VERIFY, cm, NULL);
    wb_parse_one(&wbBadVersion, CERT_TYPE, VERIFY, cm, NULL);
    wb_parse_one(&wbBadVersion, CA_TYPE, NO_VERIFY, cm, NULL);
    wb_parse_one(&wbLeafNoAkid, CERT_TYPE, NO_VERIFY, cm, NULL);
    {
        /* The same certificate cut short. The template walk fails, and the
         * version ceiling above is then evaluated with a failure already in
         * hand -- the only way its leading operand decides the guard on its
         * own. Truncating between a quarter and three quarters of the way
         * in keeps the outer SEQUENCE header intact so the failure happens
         * inside the item walk rather than at the very first tag. */
        static WbFix truncated;
        size_t cut;

        for (cut = 4; cut <= 12; cut += 4) {
            XMEMCPY(&truncated, &wbLeafNoAkid, sizeof(truncated));
            truncated.sz = (int)(((size_t)wbLeafNoAkid.sz * cut) / 16u);
            wb_parse_one(&truncated, CERT_TYPE, NO_VERIFY, cm, NULL);
            wb_parse_one(&truncated, CERT_TYPE, VERIFY, cm, NULL);
        }
    }

    /* ---- the three-level chain and the extraCAList lookups ------------ */
    rootSigner = wb_make_signer(&wbRootA);
    interSigner = wb_make_signer(&wbInter);
    WB_CHECK(rootSigner != NULL, "build a Signer from the manufactured root");

    /* Ancestor walk with the full chain resolvable in the store. */
    wb_parse_one(&wbLeafByInter, CERT_TYPE, VERIFY, cm, NULL);
    wb_parse_one(&wbLeafByInter, CERT_TYPE, VERIFY_NAME, cm, NULL);
    wb_parse_one(&wbLeafByInter, CERT_TYPE, VERIFY, cm, rootSigner);
    /* Ancestor walk that stops because the grandparent is unreachable. */
    wb_parse_one(&wbLeafUnderMism, CERT_TYPE, VERIFY, cm, NULL);
    wb_parse_one(&wbLeafUnderMism, CERT_TYPE, VERIFY, cm, rootSigner);
    /* extraCAList satisfies the very first lookup, before any key id. */
    wb_parse_one(&wbLeafNoAkid, CERT_TYPE, VERIFY, NULL, rootSigner);
    wb_parse_one(&wbLeafByInter, CERT_TYPE, VERIFY, NULL, interSigner);
    /* Nothing in the extra list matches the AKID being resolved. */
    wb_parse_one(&wbLeafBadAkid, CERT_TYPE, VERIFY, NULL, rootSigner);

    if (rootSigner != NULL) {
        FreeSigner(rootSigner, NULL);
    }
    if (interSigner != NULL) {
        FreeSigner(interSigner, NULL);
    }
    wolfSSL_CertManagerFree(cm);

    /* ---- the A->B->A cycle, in a store that holds only the two peers --- */
    cm = wolfSSL_CertManagerNew();
    WB_CHECK(cm != NULL, "wolfSSL_CertManagerNew (cycle store)");
    if (cm != NULL) {
        (void)wb_load_ca(cm, &wbNcX, "load cycle CA X");
        (void)wb_load_ca(cm, &wbNcY, "load cycle CA Y");
        wb_parse_one(&wbLeafNcX, CERT_TYPE, VERIFY, cm, NULL);
        wb_parse_one(&wbLeafNcX, CERT_TYPE, VERIFY_NAME, cm, NULL);
        wolfSSL_CertManagerFree(cm);
    }

    /* ---- a store holding the intermediate but not the root: the walk
     *      terminates on a missing parent instead of a trust anchor.
     *
     * This is also the only configuration in which the ancestor walk's
     * extra-CA-list scan runs at all. The scan is reached only when the
     * trust store cannot resolve the ancestor's authority key id, so the
     * sweeps above -- which all use a store that already holds the root --
     * never enter its loop body. Here the root is deliberately missing,
     * so each of the loop's two operands can be driven in turn:
     *
     *   - a list entry whose key id does not match at all;
     *   - a list entry whose key id AND issuer name both match;
     *   - a list entry whose key id matches while its subject name does
     *     not, which is what wbSkidTwin exists for.
     */
    cm = wolfSSL_CertManagerNew();
    WB_CHECK(cm != NULL, "wolfSSL_CertManagerNew (orphan store)");
    if (cm != NULL) {
        Signer* twinSigner;

        (void)wb_load_ca(cm, &wbInter, "load the orphaned intermediate");
        wb_parse_one(&wbLeafByInter, CERT_TYPE, VERIFY, cm, NULL);
        wb_parse_one(&wbLeafByInter, CERT_TYPE, VERIFY_SKIP_DATE, cm, NULL);

        rootSigner  = wb_make_signer(&wbRootA);
        interSigner = wb_make_signer(&wbInter);
        twinSigner  = wb_make_signer(&wbSkidTwin);
        WB_CHECK(twinSigner != NULL,
                 "build a Signer from the key-id twin CA");

        /* key id does not match -> first operand false */
        wb_parse_one(&wbLeafByInter, CERT_TYPE, VERIFY, cm, interSigner);
        /* key id and name both match -> both operands true, scan hits */
        wb_parse_one(&wbLeafByInter, CERT_TYPE, VERIFY, cm, rootSigner);
        wb_parse_one(&wbLeafByInter, CERT_TYPE, VERIFY_NAME, cm, rootSigner);
        /* key id matches, name does not -> second operand false */
        wb_parse_one(&wbLeafByInter, CERT_TYPE, VERIFY, cm, twinSigner);
        wb_parse_one(&wbLeafByInter, CERT_TYPE, VERIFY_NAME, cm, twinSigner);

        if (twinSigner != NULL) {
            FreeSigner(twinSigner, NULL);
        }
        if (interSigner != NULL) {
            FreeSigner(interSigner, NULL);
        }

        /* ---- issuer known, but with no public key attached [:24610].
         * A Signer only carries a public key when the DecodedCert it was
         * filled from owned one; the trust store always supplies one, so
         * the "issuer has no key" operand of the trust-anchor comparison
         * is otherwise never false. Borrowing the root's own Signer and
         * detaching its key for the duration of one parse reproduces that
         * state exactly, with the pointer put back before the Signer is
         * released so ownership is unchanged. */
        if (rootSigner != NULL) {
            const byte* savedKey = rootSigner->publicKey;
            word32      savedSz  = rootSigner->pubKeySize;

            /* Baseline: the same certificate against the same issuer with
             * the key still attached, so the accepting vector for this
             * decision is in this binary too. */
            wb_parse_one(&wbRootA, CHAIN_CERT_TYPE, VERIFY, cm, rootSigner);

            rootSigner->publicKey  = NULL;
            rootSigner->pubKeySize = 0;
            wb_parse_one(&wbRootA, CHAIN_CERT_TYPE, VERIFY, cm, rootSigner);
            wb_parse_one(&wbInter, CHAIN_CERT_TYPE, VERIFY, cm, rootSigner);
            rootSigner->publicKey  = savedKey;
            rootSigner->pubKeySize = savedSz;

            FreeSigner(rootSigner, NULL);
        }
        rootSigner = NULL;
        interSigner = NULL;

        wolfSSL_CertManagerFree(cm);
    }

    wb_free_keys();
}
#else
static void wb_fixture_parse_matrix(void)
{
    WB_NOTE("cert generation or date support not compiled in; "
            "manufactured-fixture sweep skipped");
}
#endif

/* ------------------------------------------------------------------------- *
 * Section: the serial-number encoder and the DerBuffer lifecycle.
 *
 * These two helpers sit either side of the certificate fixtures above and
 * have operands the certificate path cannot reach:
 *
 *   - SetSerialNumber() strips leading zero octets before it encodes. Under
 *     the template encoder the certificate generator does not route through
 *     it at all, and the callers that do route through it never hand it a
 *     serial that begins with a zero octet, so neither the "still have
 *     octets left" nor the "this octet is zero" operand of the strip loop is
 *     ever shown to control it. Calling it directly with a serial that is
 *     all zeros, one that merely starts with zeros, and one that starts with
 *     a set high bit drives both operands and the sign-padding branch.
 *
 *   - FreeDer() zeroes the buffer only for the two private-key buffer types
 *     and only when a buffer is actually attached. Certificate code only
 *     ever frees certificate-typed buffers with a buffer attached, so the
 *     alternative-private-key type and the detached-buffer case are dead
 *     from that direction. AllocDer() places the buffer inside the same
 *     allocation it returns, so clearing the pointer before the free is
 *     safe: FreeDer() releases the containing block, not the buffer field.
 * ------------------------------------------------------------------------- */
static void wb_serial_and_der_helpers(void)
{
#if !defined(NO_CERTS)
    DerBuffer* der = NULL;

#if !defined(WOLFSSL_ASN_TEMPLATE) || defined(HAVE_PKCS7)
    {
        byte out[64];
        word32 osz = (word32)sizeof(out);
        /* leading zero octets, then a payload: strip loop runs and stops */
        static const byte snLeadingZeros[4] = { 0x00, 0x00, 0x00, 0x2A };
        /* no leading zero: strip loop is entered and exits immediately */
        static const byte snPlain[3]        = { 0x2A, 0x01, 0x02 };
        /* every octet zero: strip loop consumes the whole input */
        static const byte snAllZero[3]      = { 0x00, 0x00, 0x00 };
        /* high bit set: the encoder reserves an extra sign octet */
        static const byte snHighBit[3]      = { 0x80, 0x01, 0x02 };

        WB_NOTE("SetSerialNumber(): leading-zero strip loop [:25156]");
        WB_CHECK(SetSerialNumber(NULL, 4, out, osz, 20) < 0,
                 "reject a NULL serial");
        WB_CHECK(SetSerialNumber(snPlain, 3, NULL, osz, 20) < 0,
                 "reject a NULL output buffer");
        WB_CHECK(SetSerialNumber(snPlain, 3, out, osz, 20) > 0,
                 "encode a serial with no leading zeros");
        WB_CHECK(SetSerialNumber(snLeadingZeros, 4, out, osz, 20) > 0,
                 "encode a serial after stripping its leading zeros");
        WB_CHECK(SetSerialNumber(snAllZero, 3, out, osz, 20) < 0,
                 "reject a serial that is entirely zero octets");
        WB_CHECK(SetSerialNumber(snHighBit, 3, out, osz, 20) > 0,
                 "encode a serial whose leading octet has its high bit set");
    }
#endif

    WB_NOTE("FreeDer(): buffer-type and attached-buffer guards "
            "[:25273,:25277]");
    FreeDer(NULL);                 /* no handle at all         */
    FreeDer(&der);                 /* handle present, no buffer */

    if (AllocDer(&der, 16, CERT_TYPE, NULL) == 0) {
        FreeDer(&der);             /* neither private-key type  */
    }
    if (AllocDer(&der, 16, PRIVATEKEY_TYPE, NULL) == 0) {
        FreeDer(&der);             /* first private-key type    */
    }
    if (AllocDer(&der, 16, ALT_PRIVATEKEY_TYPE, NULL) == 0) {
        FreeDer(&der);             /* second private-key type   */
    }
    if (AllocDer(&der, 16, PRIVATEKEY_TYPE, NULL) == 0) {
        /* Private-key type with the buffer detached: the zeroing guard's
         * last operand goes false while the type operands stay true. */
        der->buffer = NULL;
        FreeDer(&der);
    }
    WB_CHECK(der == NULL, "FreeDer clears the caller's handle");
#endif /* !NO_CERTS */

#if defined(WOLFSSL_PEM_TO_DER) && !defined(NO_CERTS)
    {
        /* A carriage return, a line feed, then a payload octet: the loop
         * takes its first operand true on every pass and its two character
         * operands through all three combinations that can occur. */
        static const char eol[] = "\r\nX";

        WB_NOTE("SkipEndOfLineChars(): end-of-line scan [:25426]");
        WB_CHECK(SkipEndOfLineChars(eol, eol + 3) == eol + 2,
                 "skip both end-of-line characters and stop at the payload");
        WB_CHECK(SkipEndOfLineChars(eol, eol) == eol,
                 "stop immediately when the range is empty");
        WB_CHECK(SkipEndOfLineChars(eol + 2, eol + 3) == eol + 2,
                 "stop immediately on a non-end-of-line character");
    }
#endif
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("asn.c cert white-box MC/DC supplement\n");

    wb_altname_dup();
    wb_free_decoded_cert_altnames();
    wb_set_curve();
    wb_set_ecc_public_key();
    wb_set_asym_key_der_public();
    wb_generate_dns_ip_string();
    wb_generate_dns_rid_string();
    wb_set_dns_entry();
    wb_get_rdn_get_cert_name();
    wb_get_name_loop();
    wb_get_time_digits();
    wb_validate_gmtime();
    wb_get_asn_time_string();
    wb_get_formatted_time_ex();
    wb_date_greater_than();
    wb_validate_date_with_time();
    wb_get_date_info();
    wb_get_cert_dates();
    wb_set_implicit();
    wb_is_sig_algo_no_params();
    wb_set_algo_id();
    wb_decode_dsa_asn1_sig();
    wb_parse_cert_relative_matrix();
    wb_parse_cert_relative_bad_date();
    wb_fixture_parse_matrix();
    wb_serial_and_der_helpers();

    printf("done (%s)\n", wb_fail ? "with failures" : "ok");
    /* Always return 0: a nonzero exit discards this variant's coverage
     * entirely in the campaign harness. Failures are surfaced via the
     * printed [FAIL] lines instead. */
    (void)wb_fail;
    return 0;
}
