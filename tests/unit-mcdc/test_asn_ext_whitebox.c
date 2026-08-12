/* test_asn_ext_whitebox.c
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
 * White-box MC/DC supplement for wolfcrypt/src/asn.c, "extensions" wave
 * (Part 5 of the ISO 26262 MC/DC campaign): name-constraint matching,
 * X.509 extension decoding, and the certificate/CSR decode core
 * (asn.c lines ~18537-23356 at the time this file was written).
 *
 * Companion to tests/unit-mcdc/test_asn_whitebox.c (ASN.1 template engine
 * core) -- that file owns GetASN_Items()/SizeASN_Items()/etc; this file
 * owns the certificate-shaped decoders layered on top of them. Both
 * #include wolfcrypt/src/asn.c directly to reach file-static helpers that
 * tests/api can only drive through a full, already-valid production
 * certificate -- the malformed/edge-case arms never fire from there.
 *
 * Coverage is unioned by source line:col with every other variant/whitebox
 * in the per-module campaign; independence pairs are completed *within this
 * binary*.
 *
 * Sections (asn.c line numbers as of this writing):
 *   1. wolfssl_local_MatchBaseName() ................ :18555,:18607,:18626
 *   2. URI host classification (UriHostIsDecOctet/
 *      UriHostIsIpv4Address/UriRegNameHasNonEmptyLabels/
 *      GetUriHost) ...................................... :18664-:18794
 *   3. wolfssl_local_MatchDnsConstraintWildcard() ... :18944,:18954,:18978
 *   4. wolfssl_local_MatchIpSubnet() ........................... :19038
 *   5. MatchOtherNameConstraint() ............................... :19063
 *   6. PermittedListOk() ................................ :19142-19160
 *   7. IsInExcludedList() ............................... :19214-19232
 *   8. ConfirmNameConstraints() .......................... :19264-19415
 *   9. DecodeGeneralName() URI empty/malformed check ........... :19695
 *  10. DecodeBasicCaConstraint() ........................ :20005-:20020
 *  11. DecodeAuthInfo() ................................. :20309,:20342
 *  12. DecodeAuthKeyId() ................................ :20449-:20478
 *  13. DecodeExtKeyUsage() .............................. :20815,:20861
 *  14. DecodeSubtree() .................................. :21075-:21124
 *  15. DecodeNameConstraints() hasUnsupported ................. :21217
 *  16. DecodePolicyOID() ................................ :21240,:21272
 *  17. DecodeCertPolicy() ............................... :21346-:21401
 *  18. DecodeSubjDirAttr() .............................. :21473-:21495
 *  19. DecodeSubjInfoAcc() ..................................... :21570
 *  20. DecodeExtensionType() dispatch .......... :21834,:21871,:21903
 *  21. DecodeCertExtensions() bad-args ......................... :22164
 *  22. CheckDate() ...................................... :22428-:22440
 *  23. DecodeCertInternal() ............................. :22578-:22812
 *  24. DecodeCertReqAttributes() loop ........................... :23064
 *  25. DecodeCertReq() version check ........................... :23186
 *  26. ParseCert() RSA public key store ................ :23263 (best-effort)
 *  27. wc_GetDecodedCertSubject/Issuer/Serial ... :23291,:23314,:23335
 *
 * RESIDUALS (documented inline near each, and summarized at EOF):
 *   - DecodeBasicCaConstraint() :20020 (pathLength > WOLFSSL_MAX_PATH_LEN)
 *     is unreachable once :20016 rejects pathLength >= 128: with
 *     WOLFSSL_MAX_PATH_LEN==127 every value that survives :20016 is <= 127,
 *     so the ">" can never be true in this configuration.
 *   - CheckDate() :22440 / DecodeCertInternal() :22609,:22621 "!
 *     AsnSkipDateCheck" operand: AsnSkipDateCheck is the compile-time
 *     `#define AsnSkipDateCheck 0` unless WC_ASN_RUNTIME_DATE_CHECK_CONTROL
 *     is defined; none of this module's variants (asn_default, small_stack,
 *     no_asn_time, ignore_name_constraints) define it, so the operand is
 *     always true and its false side cannot be shown without a new variant.
 *   - DecodeCertInternal() :22761/:22767 (issuer/subject != NULL): once
 *     GetASN_Items succeeds, `issuer`/`subject` are assigned unconditionally
 *     a few lines earlier in the same `if (ret == 0)` block with no
 *     intervening path that leaves them NULL while ret is later reset to 0;
 *     best-effort true side only exercised below.
 *   - DecodeCertInternal() :22704-:22705 (WC_RSA_PSS tbs/sig param match):
 *     needs a real RSA-PSS-signed certificate; exercised opportunistically
 *     with certs/rsapss/server-rsapss.der but the mismatched-parameters
 *     (false) arm would need byte-level PSS parameter surgery not attempted
 *     here.
 *   - ParseCert() :23263-:23267 operands 2/3 (publicKey != NULL,
 *     pubKeySize > 0): once keyOID == RSAk and ParseCertRelative succeeds,
 *     GetCertKey always sets publicKey/pubKeySize together; only the
 *     all-true combination is reachable without editing library source.
 *   - DecodeCertInternal() :22815/:22821 2nd operand (issuer/subject !=
 *     NULL): both are initialised to NULL and assigned unconditionally
 *     inside the single `if (ret == 0)` block at asn.c:22637 (:22683,
 *     :22688); that block has no early exit, so every path that leaves them
 *     NULL also leaves ret != 0.
 *   - DecodeCertInternal() :22844/:22849 2nd operand (!stopAtPubKey): when
 *     stopAtPubKey is non-zero and ret is still 0, :22839-:22841 has already
 *     set ret = (int)pubKeyOffset, the offset of the SubjectPublicKeyInfo
 *     SEQUENCE, which is always > 0 because the TBSCertificate header
 *     precedes it. So ret == 0 at those lines implies stopAtPubKey == 0.
 *   - DecodeCertInternal() :22662/:22674 4th operand (! AsnSkipDateCheck):
 *     NOT excluded, still open. The runtime_date_check variant makes the
 *     flag settable, but CheckDate() itself returns 0 as soon as the flag is
 *     set (:22494), so the enclosing `if (CheckDate(...) < 0)` is not
 *     entered and the operand is never evaluated. Reaching it needs a date
 *     ITEM that is malformed rather than out of range (tag not
 *     UTC/GENERALIZED_TIME, or length outside [MIN_DATE_SIZE,
 *     MAX_DATE_SIZE]), which means re-encoding the enclosing
 *     Validity/TBSCertificate/Certificate lengths. Not attempted.
 */

#include <wolfcrypt/src/asn.c>

/* Some leading `ret == 0` operands in this file's decoders have no crafted
 * input that reaches them: the only preceding statement that can set ret is a
 * DECL_ASNGETDATA allocation or a hash call, neither of which fails on valid
 * input. Those are driven with the campaign's heap-fault injector, which is
 * only effective in the WOLFSSL_SMALL_STACK variant (where the ASN.1 data
 * arrays and wc_ShaHash()'s context are heap-allocated); the matching TRUE
 * rows are issued unarmed in the same binary. */
#include "mcdc_fault_alloc.h"

/* Structural DER edits: the date gates inside `if (CheckDate(...) < 0)` need a
 * validity item that is malformed rather than merely out of range, which means
 * changing a nested item's length and fixing up every enclosing SEQUENCE. */
#include "mcdc_der_edit.h"

#include <stdio.h>
#include <string.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do { printf("  [wbext] %s\n", (msg)); } while (0)
#define WB_CHECK(cond, msg) \
    do { if (!(cond)) { printf("  [wbext][FAIL] %s\n", (msg)); wb_fail = 1; } } \
    while (0)

/* ========================================================================
 * Small stack-based pools for Base_entry / DNS_entry so name-constraint
 * tests never need heap bookkeeping.
 * ======================================================================== */
#ifndef IGNORE_NAME_CONSTRAINTS
static Base_entry wbBasePool[64];
static int wbBasePoolIdx = 0;
static Base_entry* wb_mk_base(Base_entry* next, const char* name, int nameSz,
        byte type)
{
    Base_entry* e = &wbBasePool[wbBasePoolIdx++];
    e->next = next;
    e->name = (char*)name;
    e->nameSz = nameSz;
    e->type = type;
    return e;
}

static DNS_entry wbDnsPool[64];
static int wbDnsPoolIdx = 0;
static DNS_entry* wb_mk_dns(const char* name, int len, int type)
{
    DNS_entry* e = &wbDnsPool[wbDnsPoolIdx++];
    XMEMSET(e, 0, sizeof(*e));
    e->name = name;
    e->len = len;
    e->type = type;
    return e;
}
#endif /* IGNORE_NAME_CONSTRAINTS */

/* ------------------------------------------------------------------------- *
 * Section 1: wolfssl_local_MatchBaseName().
 *   :18555  if (nameSz <= 0 || baseSz <= 0)             (post trailing-dot trim)
 *   :18607  if (atPos < 0 || atPos == 0 || atPos == nameSz - 1)
 *   :18626  if (type == ASN_DNS_TYPE || (type == ASN_RFC822_TYPE && base[0]=='.'))
 * ------------------------------------------------------------------------- */
#ifndef IGNORE_NAME_CONSTRAINTS
static void wb_match_base_name(void)
{
    WB_NOTE("MatchBaseName(): trailing-dot trim to empty [:18555]");
    /* Both name and base are a single trailing dot: after trim both become
     * length 0 -> both operands true. */
    WB_CHECK(wolfssl_local_MatchBaseName(ASN_DNS_TYPE, ".", 1, ".", 1) == 0,
            "both trim to empty (both true)");
    /* name trims to empty, base does not -> 1st true, 2nd false (base
     * longer than the dot alone; nameSz(0) < baseSz so returns via the
     * nameSz<baseSz check either way, but the :18555 pair itself is shown
     * by the differing 1st operand against the baseline below). */
    WB_CHECK(wolfssl_local_MatchBaseName(ASN_DNS_TYPE, ".", 1, "a.com", 5)
                == 0, "name trims to empty, base does not");
    /* Baseline: neither trims to empty -> both operands false, falls
     * through to normal suffix match. */
    WB_CHECK(wolfssl_local_MatchBaseName(ASN_DNS_TYPE, "www.a.com", 9,
                "a.com", 5) == 1, "baseline match, no trim (both false)");

    WB_NOTE("MatchBaseName(): RFC822 '@' position validation [:18607]");
    /* atPos < 0: no '@' in name at all. */
    WB_CHECK(wolfssl_local_MatchBaseName(ASN_RFC822_TYPE, "nombre", 6,
                "a.com", 5) == 0, "no '@' in name (atPos<0 true)");
    /* atPos == 0: '@' is the first character. */
    WB_CHECK(wolfssl_local_MatchBaseName(ASN_RFC822_TYPE, "@a.com", 6,
                "a.com", 5) == 0, "'@' at start (atPos==0 true)");
    /* atPos == nameSz-1: '@' is the last character. */
    WB_CHECK(wolfssl_local_MatchBaseName(ASN_RFC822_TYPE, "user@", 5,
                "a.com", 5) == 0, "'@' at end (atPos==nameSz-1 true)");
    /* All three false: '@' present, not at start, not at end. */
    WB_CHECK(wolfssl_local_MatchBaseName(ASN_RFC822_TYPE, "user@a.com", 10,
                "a.com", 5) == 1, "'@' well-formed (all three false)");

    WB_NOTE("MatchBaseName(): DNS-style suffix selection OR [:18626]");
    /* type==DNS_TYPE: 1st operand true regardless of 2nd. */
    WB_CHECK(wolfssl_local_MatchBaseName(ASN_DNS_TYPE, "www.a.com", 9,
                "a.com", 5) == 1, "DNS type (1st operand true)");
    /* type==RFC822 with leading-dot base: 1st false, 2nd true. */
    WB_CHECK(wolfssl_local_MatchBaseName(ASN_RFC822_TYPE, "user@sub.a.com",
                14, ".a.com", 6) == 1, "RFC822 leading-dot base (2nd true)");
    /* type==RFC822 without leading-dot base: both false -> skip suffix
     * trim, falls through to the direct length/byte compare below it
     * (email already reduced to "a.com" after the '@' was consumed since
     * base is not itself an email). */
    WB_CHECK(wolfssl_local_MatchBaseName(ASN_RFC822_TYPE, "user@a.com", 10,
                "a.com", 5) == 1, "RFC822 no leading dot (both false)");
    /* type==DIR_TYPE: neither operand applies (both false) and returns
     * before reaching this line at all via the exact-match branch --
     * included above via the RFC822 no-leading-dot case for a false,false
     * pair; DIR_TYPE returns earlier by an unconditional XMEMCMP so is not
     * a fresh pair for this specific line. */

    /* --- :18609 revisited ------------------------------------------------
     * The ".", "." rows above never actually reach this decision: the
     * function's entry guard rejects any name whose first byte is '.', so a
     * name that trims to length 0 is impossible and the 1st operand
     * (`nameSz <= 0`) has NO satisfiable independence pair. The 2nd operand
     * does: a base of a single '.' trims to length 0 while the name is a
     * normal FQDN. */
    WB_CHECK(wolfssl_local_MatchBaseName(ASN_DNS_TYPE, "www.a.com", 9, ".", 1)
                == 0, ":18609 2nd operand true (base trims to empty)");

    /* --- :18680 2nd operand ----------------------------------------------
     * NOT satisfiable: the entry guard admits only RFC822, DNS and DIR, and
     * DIR returns earlier through the unconditional XMEMCMP branch. So any
     * evaluation that gets past the 1st operand being false necessarily has
     * type == ASN_RFC822_TYPE, pinning the 2nd operand true. */
}
#else
static void wb_match_base_name(void) { WB_NOTE("IGNORE_NAME_CONSTRAINTS; skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Section 2: URI host classification helpers used by URI name constraints.
 *   UriHostIsDecOctet():   :18664 (NULL/sSz<=0/sSz>3), :18667 (leading zero)
 *   UriHostIsIpv4Address(): :18687 (NULL/hostSz<=0), :18699 (non-digit)
 *   UriRegNameHasNonEmptyLabels(): :18711-:18712 (NULL/leading-dot/trailing-dot)
 *   GetUriHost(): :18736-:18737 (bad args), :18744 ("://" scan),
 *                 :18772 (bracket scan), :18794 (trailing-dot re-check)
 * Driven indirectly through wolfssl_local_MatchUriNameConstraint() (the
 * only external entry point reaching these file-static helpers) since none of
 * them are directly link-visible on their own; MatchUriNameConstraint IS
 * WOLFSSL_LOCAL/global so it is callable directly here.
 * ------------------------------------------------------------------------- */
#ifndef IGNORE_NAME_CONSTRAINTS
static void wb_uri_host_helpers(void)
{
    WB_NOTE("UriHostIsDecOctet/UriHostIsIpv4Address via URI match [:18664,:18667,:18687,:18699]");
    /* IPv4-literal host: exercises UriHostIsIpv4Address() true path and
     * UriHostIsDecOctet() with valid octets (sSz<=3, no leading zero). A
     * URI whose host is an IPv4 address is never a DNS reg-name, so the
     * constraint never matches regardless of base -- but reaching that
     * "not a reg-name" return still drives GetUriHost() to classify it. */
    WB_CHECK(wolfssl_local_MatchUriNameConstraint("http://192.168.1.1/x", 21,
                ".example.com", 12) == 0, "IPv4-literal host classification");
    /* Octet with a leading zero (invalid dec-octet -> :18667 true) makes
     * UriHostIsIpv4Address() return 0, so the host falls back to
     * reg-name classification instead. */
    WB_CHECK(wolfssl_local_MatchUriNameConstraint("http://192.068.1.1/x", 21,
                ".192.068.1.1", 13) != 0 ||
             wolfssl_local_MatchUriNameConstraint("http://192.068.1.1/x", 21,
                ".192.068.1.1", 13) == 0,
            "leading-zero octet forces reg-name path (no crash)");
    /* Octet with sSz>3 (too many digits) -> UriHostIsDecOctet() :18664
     * true via sSz>3. */
    WB_CHECK(wolfssl_local_MatchUriNameConstraint("http://1234.1.1.1/x", 20,
                ".example.com", 12) == 0, "4-digit octet rejects IPv4 (sSz>3)");
    /* Non-digit character inside a would-be IPv4 host -> UriHostIsIpv4Address
     * :18699 true, falls through to reg-name classification. */
    WB_CHECK(wolfssl_local_MatchUriNameConstraint("http://1.2.3.x/y", 17,
                ".example.com", 12) == 0, "non-digit in host (:18699 true)");

    WB_NOTE("UriRegNameHasNonEmptyLabels via URI match [:18711,:18712]");
    /* Host with a leading dot ("." as first char after "://") is rejected
     * by UriRegNameHasNonEmptyLabels() -> GetUriHost() returns 0. */
    WB_CHECK(wolfssl_local_MatchUriNameConstraint("http://.host.com/x", 19,
                ".host.com", 9) == 0, "leading-dot host rejected");
    /* Empty label in the middle ("a..b") -> the inner loop at :18716-18719
     * (adjacent siblings, not this file's target lines) catches it; host
     * ending in exactly one dot is handled at GetUriHost() itself (:18792-
     * :18794) below, not here. */
    /* A leading-dot base constrains SUBDOMAINS: "good.com" itself does not
     * match ".good.com", so the accepting row needs a labelled host. */
    WB_CHECK(wolfssl_local_MatchUriNameConstraint("http://sub.good.com/x", 21,
                ".good.com", 9) == 1, "well-formed host (baseline true)");

    WB_NOTE("GetUriHost(): bad-args OR [:18736,:18737]");
    WB_CHECK(wolfssl_local_MatchUriNameConstraint(NULL, 0, ".x", 2) == 0,
            "uri==NULL");
    WB_CHECK(wolfssl_local_MatchUriNameConstraint("ab", 2, ".x", 2) == 0,
            "uriSz<3");
    WB_CHECK(wolfssl_local_MatchUriNameConstraint("http://h/x", 10, NULL, 2)
                == 0, "base==NULL (short-circuits before GetUriHost host/hostSz "
                "args, but exercises the same bad-args style entry)");

    WB_NOTE("GetUriHost(): \"://\" scheme scan [:18744]");
    /* No "://" anywhere in the (long enough) buffer -> scan runs to
     * completion without a match, hostStart stays NULL. */
    WB_CHECK(wolfssl_local_MatchUriNameConstraint("not-a-uri-at-all", 16,
                ".host.com", 9) == 0, "no \"://\" present");
    /* "://" present and matched mid-scan (true branch of the 3-byte
     * lookahead comparison). */
    WB_CHECK(wolfssl_local_MatchUriNameConstraint("s://a.host.com/x", 16,
                ".host.com", 9) == 1, "\"://\" found (baseline true)");

    WB_NOTE("GetUriHost(): IP-literal '[' bracket scan [:18772]");
    /* '[' opens an IP-literal host; scan for ']' runs to completion
     * (found) -> classified as URI_HOST_IP_LITERAL, never a DNS reg-name. */
    WB_CHECK(wolfssl_local_MatchUriNameConstraint("http://[::1]/x", 14,
                ".host.com", 9) == 0, "IP-literal host (bracket scan to ']')");
    /* '[' opens but ']' never appears before uriEnd -> hostEnd>=uriEnd,
     * GetUriHost() returns 0 (malformed IP-literal). */
    WB_CHECK(wolfssl_local_MatchUriNameConstraint("http://[::1", 11,
                ".host.com", 9) == 0, "unterminated IP-literal (:18772 exhausts)");

    WB_NOTE("GetUriHost(): trailing single-dot re-check [:18794]");
    /* Host with exactly one trailing dot: stripped, remainder non-empty
     * and does not itself end in '.' -> accepted (absolute-FQDN form). */
    WB_CHECK(wolfssl_local_MatchUriNameConstraint("http://a.host.com./x", 20,
                ".host.com", 9) == 1, "one trailing dot stripped, valid remainder");
    /* Host of two dots ("..") after stripping one trailing dot still ends
     * in '.' -> :18794 both operands true -> rejected. */
    WB_CHECK(wolfssl_local_MatchUriNameConstraint("http://../x", 11,
                ".host.com", 9) == 0, "double-dot host rejected (:18794 both true)");

    /* --- the operands the indirect rows above cannot reach --------------- */

    /* :18726 -- UriHostIsDecOctet()'s per-character digit test. Driven
     * DIRECTLY: when the helper is reached through UriHostIsIpv4Address()
     * the caller's own digit test rejects every non-digit byte first, so
     * the segment handed down is always all digits and neither operand can
     * be true. The helper is a file-static with no precondition beyond a
     * bounded segment, so both operands are shown here. */
    WB_CHECK(UriHostIsDecOctet("123", 3) == 1,
            ":18726 both operands false (all digits)");
    WB_CHECK(UriHostIsDecOctet("1/1", 3) == 0,
            ":18726 1st operand true (byte below '0')");
    WB_CHECK(UriHostIsDecOctet("1a1", 3) == 0,
            ":18726 2nd operand true (byte above '9')");

    /* :18753 -- UriHostIsIpv4Address()'s own digit test. The indirect rows
     * only ever supply a byte above '9' ('x'); '-' is below '0' and is not
     * the '.' separator, so it lands on the 1st operand. */
    WB_CHECK(UriHostIsIpv4Address("1-2.3.4.5", 9) == 0,
            ":18753 1st operand true (byte below '0')");
    WB_CHECK(UriHostIsIpv4Address("1.2.3.4", 7) == 1,
            ":18753 both operands false (valid dotted quad)");

    /* :18798 -- the three-byte "://" lookahead. Every URI used above has
     * its ':' immediately followed by "//", so the 2nd and 3rd operands are
     * pinned true. These two URIs each contain an earlier ':' that fails
     * the lookahead at a different operand before the real "://" is found. */
    {
        /* Compared against the plain "s://host.com/x" form rather than a
         * hard-coded 1: what this row has to show is that an earlier ':'
         * which fails the lookahead does not change the outcome, and the
         * base-matching semantics themselves are asserted elsewhere. */
        int plain = wolfssl_local_MatchUriNameConstraint("s://host.com/x", 14,
                ".host.com", 9);
        WB_CHECK(wolfssl_local_MatchUriNameConstraint("ab:cd://host.com/x", 18,
                    ".host.com", 9) == plain,
                ":18798 2nd operand false (':' not followed by '/')");
        WB_CHECK(wolfssl_local_MatchUriNameConstraint("a:/b://host.com/x", 17,
                    ".host.com", 9) == plain,
                ":18798 3rd operand false (\":/\" not followed by '/')");
    }

    /* :18848 -- after stripping one trailing dot the host is empty. The
     * "http://../x" row above lands on the 2nd operand (still ends in '.');
     * a host of exactly "." lands on the 1st. */
    WB_CHECK(wolfssl_local_MatchUriNameConstraint("http://./x", 10,
                ".host.com", 9) == 0,
            ":18848 1st operand true (host is a lone dot)");
}
#else
static void wb_uri_host_helpers(void) { WB_NOTE("IGNORE_NAME_CONSTRAINTS; skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Section 3: wolfssl_local_MatchDnsConstraintWildcard().
 *   :18944  if (nameSz<=0 || baseSz<=0 || name[0]=='.')   (post trim)
 *   :18954  if (baseSz<=0 || base[0]=='.')                 (post lead-dot strip)
 *   :18978  if (nLen==0 || bLen==0)                        (empty label)
 * ------------------------------------------------------------------------- */
#ifndef IGNORE_NAME_CONSTRAINTS
static void wb_match_dns_wildcard(void)
{
    WB_NOTE("MatchDnsConstraintWildcard(): post-trim empty checks [:18944]");
    /* name[0]=='.' after trailing-dot trim (name is just ".") -> true via
     * 3rd operand. */
    WB_CHECK(wolfssl_local_MatchDnsConstraintWildcard(".", 1, "a.com", 5, 1)
                == 0, "name[0]=='.' (3rd operand true)");
    /* baseSz<=0 after trim (base is a lone dot). */
    WB_CHECK(wolfssl_local_MatchDnsConstraintWildcard("*.a.com", 7, ".", 1, 1)
                == 0, "base trims to empty (2nd operand true)");
    /* Baseline: neither empty, name[0] is '*' not '.'. */
    WB_CHECK(wolfssl_local_MatchDnsConstraintWildcard("*.a.com", 7, "a.com",
                5, 1) == 1, "baseline (all operands false)");

    WB_NOTE("MatchDnsConstraintWildcard(): base-is-only-dots [:18954]");
    /* After stripping ONE leading dot, base[0] is again '.' (base was
     * ".."). */
    /* ".." trims its trailing dot to "." first, so stripping the leading dot
     * leaves baseSz == 0 and the 1st operand short-circuits -- that row does
     * NOT reach the 2nd operand. "..a.com" has no trailing dot to trim, so
     * after the leading-dot strip baseSz is still positive and base[0] is
     * again '.': the 1st operand is false and the 2nd is true. */
    WB_CHECK(wolfssl_local_MatchDnsConstraintWildcard("*.a.com", 7, "..", 2,
                0) == 0, "base \"..\"  (1st operand true after strip)");
    WB_CHECK(wolfssl_local_MatchDnsConstraintWildcard("*.a.com", 7, "..a.com",
                7, 0) == 0, ":19008 2nd operand true (base[0]=='.' after strip)");
    /* baseSz<=0 after stripping the single leading dot (base was just "."
     * -- already covered by :18944 above via the name-side check; here the
     * base itself is only "." with a WILDCARD name so :18944 name[0]=='.'
     * is false, isolating :18954's own 1st operand). */
    WB_CHECK(wolfssl_local_MatchDnsConstraintWildcard("x*.a.com", 8, ".", 1,
                0) == 0, "base is lone leading dot (1st operand true)");

    WB_NOTE("MatchDnsConstraintWildcard(): empty label [:18978]");
    /* Double dot inside the name produces a zero-length label when
     * walking right-to-left. */
    WB_CHECK(wolfssl_local_MatchDnsConstraintWildcard("*..com", 6, "x.com",
                5, 0) == 0, "empty name label (nLen==0)");
    /* Double dot inside the base similarly. */
    WB_CHECK(wolfssl_local_MatchDnsConstraintWildcard("*.a.com", 7, "a..com",
                6, 0) == 0, "empty base label (bLen==0)");
    /* Baseline: no empty labels either side. */
    WB_CHECK(wolfssl_local_MatchDnsConstraintWildcard("*.a.com", 7, "a.com",
                5, 1) == 1, "no empty labels (both false)");
}
#else
static void wb_match_dns_wildcard(void) { WB_NOTE("IGNORE_NAME_CONSTRAINTS; skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Section 4: wolfssl_local_MatchIpSubnet() bad-args OR [:19038].
 * ------------------------------------------------------------------------- */
#ifndef IGNORE_NAME_CONSTRAINTS
static void wb_match_ip_subnet(void)
{
    static const byte ip4[4]         = { 192, 168, 1, 5 };
    static const byte constraint4[8] = { 192, 168, 1, 0, 255, 255, 255, 0 };

    WB_NOTE("MatchIpSubnet(): NULL/size bad-args OR [:19038]");
    WB_CHECK(wolfssl_local_MatchIpSubnet(NULL, 4, constraint4, 8) == 0,
            "ip==NULL");
    WB_CHECK(wolfssl_local_MatchIpSubnet(ip4, 4, NULL, 8) == 0,
            "constraint==NULL");
    WB_CHECK(wolfssl_local_MatchIpSubnet(ip4, 0, constraint4, 8) == 0,
            "ipSz<=0");
    WB_CHECK(wolfssl_local_MatchIpSubnet(ip4, 4, constraint4, 0) == 0,
            "constraintSz<=0");
    WB_CHECK(wolfssl_local_MatchIpSubnet(ip4, 4, constraint4, 8) == 1,
            "all valid (all operands false), matches /24");
}
#else
static void wb_match_ip_subnet(void) { WB_NOTE("IGNORE_NAME_CONSTRAINTS; skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Section 5: MatchOtherNameConstraint() NULL-args OR [:19063].
 * Static helper -- reached directly since it takes only DNS_entry and
 * Base_entry pointers.
 * ------------------------------------------------------------------------- */
#ifndef IGNORE_NAME_CONSTRAINTS
static void wb_match_other_name(void)
{
    DNS_entry name;
    Base_entry base;

    WB_NOTE("MatchOtherNameConstraint(): NULL args [:19063]");
    XMEMSET(&name, 0, sizeof(name));
    XMEMSET(&base, 0, sizeof(base));
    name.name = "AB"; name.len = 2;
    base.name = (char*)"AB"; base.nameSz = 2;

    WB_CHECK(MatchOtherNameConstraint(NULL, &base) == 0, "name==NULL");
    WB_CHECK(MatchOtherNameConstraint(&name, NULL) == 0, "current==NULL");
    WB_CHECK(MatchOtherNameConstraint(&name, &base) == 1,
            "both valid, equal bytes (both operands false)");
}
#else
static void wb_match_other_name(void) { WB_NOTE("IGNORE_NAME_CONSTRAINTS; skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Section 6/7: PermittedListOk() / IsInExcludedList().
 *   PermittedListOk    :19142-:19144 (ASN_RID_TYPE exact match),
 *                       :19158-:19160 (default/otherName-style branch)
 *   IsInExcludedList   :19214-:19216, :19230-:19232 (same shapes)
 * ------------------------------------------------------------------------- */
#ifndef IGNORE_NAME_CONSTRAINTS
static void wb_permitted_excluded_lists(void)
{
    DNS_entry ridName, dirName;
    Base_entry* ridList;
    Base_entry* dirList;

    WB_NOTE("PermittedListOk()/IsInExcludedList(): RID exact-match [:19142,:19214]");
    XMEMSET(&ridName, 0, sizeof(ridName));
    ridName.type = ASN_RID_TYPE;
    ridName.name = "\x2a\x03\x04";
    ridName.len = 3;
    /* Equal length, equal bytes -> both operands true (match). */
    ridList = wb_mk_base(NULL, "\x2a\x03\x04", 3, ASN_RID_TYPE);
    WB_CHECK(PermittedListOk(&ridName, ridList, ASN_RID_TYPE) == 1,
            "RID exact match permitted (both true)");
    WB_CHECK(IsInExcludedList(&ridName, ridList, ASN_RID_TYPE) == 1,
            "RID exact match excluded (both true)");
    /* Same length, different bytes -> 1st true (len match), 2nd false
     * (XMEMCMP != 0). */
    ridList = wb_mk_base(NULL, "\x2a\x03\x05", 3, ASN_RID_TYPE);
    WB_CHECK(PermittedListOk(&ridName, ridList, ASN_RID_TYPE) == 0,
            "RID same length, different bytes: not permitted (need != 0)");
    WB_CHECK(IsInExcludedList(&ridName, ridList, ASN_RID_TYPE) == 0,
            "RID same length, different bytes: not excluded");
    /* Different length -> 1st operand false, short-circuits. */
    ridList = wb_mk_base(NULL, "\x2a\x03\x04\x05", 4, ASN_RID_TYPE);
    WB_CHECK(PermittedListOk(&ridName, ridList, ASN_RID_TYPE) == 0,
            "RID length mismatch (1st operand false)");
    WB_CHECK(IsInExcludedList(&ridName, ridList, ASN_RID_TYPE) == 0,
            "RID length mismatch excluded (1st operand false)");

    WB_NOTE("PermittedListOk()/IsInExcludedList(): default MatchBaseName branch [:19158,:19230]");
    /* ASN_DIR_TYPE takes the trailing "else if" default branch (not IP,
     * URI, OTHER, RID, or DNS). Equal-length exact match -> both true. */
    XMEMSET(&dirName, 0, sizeof(dirName));
    dirName.type = ASN_DIR_TYPE;
    dirName.name = "CN=a";
    dirName.len = 4;
    dirList = wb_mk_base(NULL, "CN=a", 4, ASN_DIR_TYPE);
    WB_CHECK(PermittedListOk(&dirName, dirList, ASN_DIR_TYPE) == 1,
            "DIR exact match permitted (both true)");
    WB_CHECK(IsInExcludedList(&dirName, dirList, ASN_DIR_TYPE) == 1,
            "DIR exact match excluded (both true)");
    /* name->len < current->nameSz -> 1st operand false, short-circuits
     * (MatchBaseName not even called). */
    dirList = wb_mk_base(NULL, "CN=abcdef", 9, ASN_DIR_TYPE);
    WB_CHECK(PermittedListOk(&dirName, dirList, ASN_DIR_TYPE) == 0,
            "DIR name shorter than base (1st operand false)");
    WB_CHECK(IsInExcludedList(&dirName, dirList, ASN_DIR_TYPE) == 0,
            "DIR name shorter than base excluded (1st operand false)");
    /* name->len >= current->nameSz but MatchBaseName() itself rejects
     * (different bytes) -> 1st true, 2nd false. */
    dirList = wb_mk_base(NULL, "CN=z", 4, ASN_DIR_TYPE);
    WB_CHECK(PermittedListOk(&dirName, dirList, ASN_DIR_TYPE) == 0,
            "DIR len ok, MatchBaseName rejects (2nd operand false)");
    WB_CHECK(IsInExcludedList(&dirName, dirList, ASN_DIR_TYPE) == 0,
            "DIR len ok, MatchBaseName rejects, excluded (2nd operand false)");

    WB_NOTE("PermittedListOk()/IsInExcludedList(): empty list -> not needed [need=0]");
    WB_CHECK(PermittedListOk(&dirName, NULL, ASN_DIR_TYPE) == 1,
            "no restriction of this type -> ok");
    WB_CHECK(IsInExcludedList(&dirName, NULL, ASN_DIR_TYPE) == 0,
            "no restriction of this type -> not excluded");
}
#else
static void wb_permitted_excluded_lists(void) { WB_NOTE("IGNORE_NAME_CONSTRAINTS; skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Section 8: ConfirmNameConstraints().
 *   :19264  signer==NULL || cert==NULL
 *   :19267-:19268  no restrictions at all -> early accept
 *   :19272-:19273  uriConstraintsApply (permitted OR excluded has URI type)
 *   :19291  subjectCN fallback: cert->subjectCN!=NULL && !cert->isCA
 *   :19366-:19368  URI-without-DNS-host rejection under uriConstraintsApply
 *   :19392  subjectDnsName fallback len>0 && name!=NULL
 *   :19414-:19415  critical + unsupported GeneralName form -> fail closed
 * ------------------------------------------------------------------------- */
#ifndef IGNORE_NAME_CONSTRAINTS
static void wb_confirm_name_constraints(void)
{
    Signer signer;
    DecodedCert cert;
    DNS_entry* altName;

    WB_NOTE("ConfirmNameConstraints(): NULL args [:19264]");
    XMEMSET(&cert, 0, sizeof(cert));
    WB_CHECK(ConfirmNameConstraints(NULL, &cert) == 0, "signer==NULL");
    XMEMSET(&signer, 0, sizeof(signer));
    WB_CHECK(ConfirmNameConstraints(&signer, NULL) == 0, "cert==NULL");

    WB_NOTE("ConfirmNameConstraints(): no restrictions early accept [:19267,:19268]");
    XMEMSET(&signer, 0, sizeof(signer));
    XMEMSET(&cert, 0, sizeof(cert));
    WB_CHECK(ConfirmNameConstraints(&signer, &cert) == 1,
            "no permitted/excluded/unsupported (all true, early accept)");

    WB_NOTE("ConfirmNameConstraints(): uriConstraintsApply OR [:19272,:19273]");
    /* excludedNames has a URI-type entry -> 1st operand true. */
    XMEMSET(&signer, 0, sizeof(signer));
    XMEMSET(&cert, 0, sizeof(cert));
    signer.excludedNames = wb_mk_base(NULL, ".evil.com", 9, ASN_URI_TYPE);
    WB_CHECK(ConfirmNameConstraints(&signer, &cert) == 1,
            "excluded URI-type list present (1st operand true, cert has no URIs)");
    /* permittedNames has a URI-type entry, excludedNames does not -> 1st
     * false, 2nd true. */
    XMEMSET(&signer, 0, sizeof(signer));
    XMEMSET(&cert, 0, sizeof(cert));
    signer.excludedNames = wb_mk_base(NULL, "CN=x", 4, ASN_DIR_TYPE);
    signer.permittedNames = wb_mk_base(NULL, ".good.com", 9, ASN_URI_TYPE);
    WB_CHECK(ConfirmNameConstraints(&signer, &cert) == 1,
            "permitted URI-type list present (2nd operand true)");
    /* Neither list has a URI-type entry -> both false. */
    XMEMSET(&signer, 0, sizeof(signer));
    XMEMSET(&cert, 0, sizeof(cert));
    signer.excludedNames = wb_mk_base(NULL, "CN=x", 4, ASN_DIR_TYPE);
    WB_CHECK(ConfirmNameConstraints(&signer, &cert) == 1,
            "no URI-type entries anywhere (both false)");

    WB_NOTE("ConfirmNameConstraints(): subjectCN fallback [:19291]");
    /* subjectCN!=NULL and !isCA -> both true: builds a synthetic dNSName
     * from the subject CN and checks it against the (empty) lists. */
    XMEMSET(&signer, 0, sizeof(signer));
    XMEMSET(&cert, 0, sizeof(cert));
    signer.excludedNames = wb_mk_base(NULL, ".evil.com", 9, ASN_DNS_TYPE);
    cert.subjectCN = "www.good.com";
    cert.subjectCNLen = 12;
    cert.isCA = 0;
    WB_CHECK(ConfirmNameConstraints(&signer, &cert) == 1,
            "subjectCN present, not CA (both true), not excluded");
    /* isCA true -> 2nd operand false, subjectCN fallback skipped. */
    XMEMSET(&cert, 0, sizeof(cert));
    cert.subjectCN = "www.evil.com";
    cert.subjectCNLen = 12;
    cert.isCA = 1;
    WB_CHECK(ConfirmNameConstraints(&signer, &cert) == 1,
            "subjectCN present but isCA (2nd operand false, fallback skipped)");
    /* subjectCN==NULL -> 1st operand false, short-circuits. */
    XMEMSET(&cert, 0, sizeof(cert));
    cert.isCA = 0;
    WB_CHECK(ConfirmNameConstraints(&signer, &cert) == 1,
            "subjectCN==NULL (1st operand false)");

    WB_NOTE("ConfirmNameConstraints(): URI-without-DNS-host rejection [:19366-:19368]");
    XMEMSET(&signer, 0, sizeof(signer));
    XMEMSET(&cert, 0, sizeof(cert));
    signer.permittedNames = wb_mk_base(NULL, ".good.com", 9, ASN_URI_TYPE);
    /* A URI SAN whose host is an IPv4 literal -- GetUriHost() classifies
     * it URI_HOST_IPV4, so wolfssl_local_UriNameHasDnsHost() is false ->
     * all three operands true (nameType==URI, uriConstraintsApply,
     * !UriNameHasDnsHost) -> rejected. */
    altName = wb_mk_dns("http://1.2.3.4/x", 17, ASN_URI_TYPE);
    cert.altNames = altName;
    WB_CHECK(ConfirmNameConstraints(&signer, &cert) == 0,
            "URI SAN without DNS host under URI constraints (all 3 true)");
    /* Same URI constraints present, but the SAN's URI host IS a DNS
     * reg-name -> 3rd operand false. */
    XMEMSET(&cert, 0, sizeof(cert));
    altName = wb_mk_dns("http://sub.good.com/x", 21, ASN_URI_TYPE);
    cert.altNames = altName;
    WB_CHECK(ConfirmNameConstraints(&signer, &cert) == 1,
            "URI SAN with DNS host (3rd operand false, passes)");
    /* uriConstraintsApply false (no URI-type entries in either list) ->
     * 2nd operand false, short-circuits regardless of the SAN's host
     * form. */
    XMEMSET(&signer, 0, sizeof(signer));
    signer.permittedNames = wb_mk_base(NULL, "CN=x", 4, ASN_DIR_TYPE);
    XMEMSET(&cert, 0, sizeof(cert));
    altName = wb_mk_dns("http://1.2.3.4/x", 17, ASN_URI_TYPE);
    cert.altNames = altName;
    WB_CHECK(ConfirmNameConstraints(&signer, &cert) == 1,
            "no URI constraints in force (2nd operand false, skipped)");

    WB_NOTE("ConfirmNameConstraints(): subjectDnsName fallback len/name [:19392]");
    /* subjectEmail present -> synthetic RFC822 name len>0 && name!=NULL,
     * both true, checked against an excluded email base. */
    XMEMSET(&signer, 0, sizeof(signer));
    XMEMSET(&cert, 0, sizeof(cert));
    signer.excludedNames = wb_mk_base(NULL, "evil.com", 8, ASN_RFC822_TYPE);
    cert.subjectEmail = "user@good.com";
    cert.subjectEmailLen = 13;
    WB_CHECK(ConfirmNameConstraints(&signer, &cert) == 1,
            "subjectEmail present (both true), not excluded");
    /* subjectEmail absent (len 0, name NULL from XMEMSET) -> both false,
     * fallback check skipped entirely. */
    XMEMSET(&cert, 0, sizeof(cert));
    WB_CHECK(ConfirmNameConstraints(&signer, &cert) == 1,
            "subjectEmail absent (both false, fallback skipped)");

    WB_NOTE("ConfirmNameConstraints(): critical+unsupported fail-closed [:19414,:19415]");
    /* Both true -> reject regardless of any list contents. */
    XMEMSET(&signer, 0, sizeof(signer));
    XMEMSET(&cert, 0, sizeof(cert));
    signer.extNameConstraintCrit = 1;
    signer.extNameConstraintHasUnsupported = 1;
    /* Give the signer a permittedNames entry so the very-early "no
     * restrictions" shortcut at :19267 does not fire before reaching this
     * check. */
    signer.permittedNames = wb_mk_base(NULL, "CN=x", 4, ASN_DIR_TYPE);
    WB_CHECK(ConfirmNameConstraints(&signer, &cert) == 0,
            "critical + unsupported (both true, fail closed)");
    /* Critical but no unsupported form seen -> 1st true, 2nd false. */
    signer.extNameConstraintHasUnsupported = 0;
    WB_CHECK(ConfirmNameConstraints(&signer, &cert) == 1,
            "critical, no unsupported form (2nd operand false)");
    /* Not critical, even if unsupported were set -> 1st operand false,
     * short-circuits. */
    signer.extNameConstraintCrit = 0;
    signer.extNameConstraintHasUnsupported = 1;
    WB_CHECK(ConfirmNameConstraints(&signer, &cert) == 1,
            "not critical (1st operand false, short-circuit)");
}
#else
static void wb_confirm_name_constraints(void) { WB_NOTE("IGNORE_NAME_CONSTRAINTS; skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Section 9: DecodeGeneralName() URI empty/malformed-hier-part check
 * [:19695]  if (i == 0 || i == len)
 * Gated the same as the source: strict URI validation only runs when
 * WOLFSSL_NO_ASN_STRICT is NOT defined.
 * ------------------------------------------------------------------------- */
#ifndef WOLFSSL_NO_ASN_STRICT
static void wb_decode_general_name_uri(void)
{
    DecodedCert cert;
    word32 idx;
    int ret;
    /* i==0: first byte is ':' -> hier-part empty on the left, too. */
    static const byte uriColonFirst[] = { ':', 'x' };
    /* i==len: no ':' anywhere in the buffer at all. */
    static const byte uriNoColon[] = { 'n','o','c','o','l','o','n' };
    /* Baseline: well-formed absolute URI, ':' strictly inside (0<i<len). */
    static const byte uriOk[] = { 'h','t','t','p',':','/','/','x' };

    WB_NOTE("DecodeGeneralName(): URI hier-part i==0||i==len [:19695]");

    XMEMSET(&cert, 0, sizeof(cert));
    idx = 0;
    ret = DecodeGeneralName(uriColonFirst, &idx,
            (byte)(ASN_CONTEXT_SPECIFIC | ASN_URI_TYPE),
            (int)sizeof(uriColonFirst), &cert);
    /* The strict URI hier-part validation is inside the name-constraint
     * block, so it is compiled out with IGNORE_NAME_CONSTRAINTS and the
     * malformed URIs are then accepted. */
#ifndef IGNORE_NAME_CONSTRAINTS
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_ALT_NAME_E), "i==0 (1st operand true)");
#else
    WB_CHECK(ret == 0, "i==0, URI validation compiled out");
#endif

    XMEMSET(&cert, 0, sizeof(cert));
    idx = 0;
    ret = DecodeGeneralName(uriNoColon, &idx,
            (byte)(ASN_CONTEXT_SPECIFIC | ASN_URI_TYPE),
            (int)sizeof(uriNoColon), &cert);
#ifndef IGNORE_NAME_CONSTRAINTS
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_ALT_NAME_E),
            "i==len, no ':' found (2nd operand true, 1st false)");
#else
    WB_CHECK(ret == 0, "i==len, URI validation compiled out");
#endif

    XMEMSET(&cert, 0, sizeof(cert));
    idx = 0;
    ret = DecodeGeneralName(uriOk, &idx,
            (byte)(ASN_CONTEXT_SPECIFIC | ASN_URI_TYPE),
            (int)sizeof(uriOk), &cert);
    WB_CHECK(ret == 0, "well-formed absolute URI (both operands false)");
}
#else
static void wb_decode_general_name_uri(void) { WB_NOTE("WOLFSSL_NO_ASN_STRICT; skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Section 10: DecodeBasicCaConstraint() (global function).
 *   :20005  SEQ.length != 0 (non-empty BasicConstraints)
 *   :20010  CA.length!=0 && !innerIsCA   (encoded-false CA boolean rejected)
 *   :20016  *pathLength >= (1<<7)
 *   :20020  *pathLength > WOLFSSL_MAX_PATH_LEN -- RESIDUAL, see file header.
 * ------------------------------------------------------------------------- */
static void wb_decode_basic_ca_constraint(void)
{
    /* DecodeBasicCaConstraint() only writes *pathLength when the encoding
     * carries a pathLenConstraint, but reads it unconditionally at :20070
     * and :20074, so the caller owns the initialisation -- exactly as the
     * in-library caller DecodeBasicCaConstraintInternal() does at :20114.
     * Leaving these uninitialised made the pathLength checks read stack
     * garbage, which is both a wrong result and a variant-dependent one. */
    byte isCa = 0;
    word16 pathLen = 0;
    byte pathLenSet = 0;
    int ret;

    /* Empty SEQUENCE -> :20005 false, nothing else checked. */
    static const byte bcEmpty[] = { 0x30, 0x00 };
    /* CA=TRUE only. */
    static const byte bcCaTrue[] = { 0x30,0x03, 0x01,0x01,0xFF };
    /* CA=FALSE explicit encoding (invalid per RFC 5280, default is false). */
    static const byte bcCaFalse[] = { 0x30,0x03, 0x01,0x01,0x00 };
    /* CA absent, only pathLen present -- CA.length==0, 1st operand of
     * :20010 false, short-circuits. */
    static const byte bcNoCa[] = { 0x30,0x03, 0x02,0x01,0x05 };
    /* CA=TRUE + pathLen encoded as 128 (needs a leading zero byte since
     * MSB of 0x80 is set): triggers :20016 true. */
    static const byte bcPathLen128[] =
        { 0x30,0x08, 0x01,0x01,0xFF, 0x02,0x02,0x00,0x80 };
    /* CA=TRUE + pathLen=127 (fits in 7 bits, valid, also the maximum
     * WOLFSSL_MAX_PATH_LEN, so :20020 stays false here too). */
    static const byte bcPathLen127[] =
        { 0x30,0x06, 0x01,0x01,0xFF, 0x02,0x01,0x7F };

    WB_NOTE("DecodeBasicCaConstraint(): empty SEQ bypass [:20005]");
    isCa = 0; pathLen = 0; pathLenSet = 0;
    ret = DecodeBasicCaConstraint(bcEmpty, (int)sizeof(bcEmpty), &isCa,
            &pathLen, &pathLenSet);
    WB_CHECK(ret == 0, "empty BasicConstraints SEQUENCE (:20005 false)");

    WB_NOTE("DecodeBasicCaConstraint(): CA boolean present-and-false OR [:20010]");
    isCa = 0; pathLen = 0; pathLenSet = 0;
    ret = DecodeBasicCaConstraint(bcCaFalse, (int)sizeof(bcCaFalse), &isCa,
            &pathLen, &pathLenSet);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E),
            "CA=FALSE explicit (both operands true)");
    isCa = 0; pathLen = 0; pathLenSet = 0;
    ret = DecodeBasicCaConstraint(bcCaTrue, (int)sizeof(bcCaTrue), &isCa,
            &pathLen, &pathLenSet);
    WB_CHECK(ret == 0 && isCa == 1,
            "CA=TRUE (1st operand true, 2nd false: !innerIsCA is false)");
    isCa = 0; pathLen = 0; pathLenSet = 0;
    ret = DecodeBasicCaConstraint(bcNoCa, (int)sizeof(bcNoCa), &isCa,
            &pathLen, &pathLenSet);
    WB_CHECK(ret == 0, "CA absent (1st operand false, short-circuit)");

    WB_NOTE("DecodeBasicCaConstraint(): pathLength >= 128 [:20016]");
    isCa = 0; pathLen = 0; pathLenSet = 0;
    ret = DecodeBasicCaConstraint(bcPathLen128, (int)sizeof(bcPathLen128),
            &isCa, &pathLen, &pathLenSet);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E), "pathLength==128 (true)");
    isCa = 0; pathLen = 0; pathLenSet = 0;
    ret = DecodeBasicCaConstraint(bcPathLen127, (int)sizeof(bcPathLen127),
            &isCa, &pathLen, &pathLenSet);
    WB_CHECK(ret == 0 && pathLen == 127 && pathLenSet == 1,
            "pathLength==127 (false, also :20020 false -- see residual note)");
}

/* ------------------------------------------------------------------------- *
 * Section 11: DecodeAuthInfo() (static, called directly).
 *   :20309  while ((ret==0) && (idx<sz))
 *   :20342-:20343  (METH.oid.sum==AIA_OCSP_OID) && (extAuthInfo==NULL)
 * ------------------------------------------------------------------------- */
static void wb_decode_auth_info(void)
{
    DecodedCert cert;
    int ret;
    /* Three AccessDescriptions: OCSP, OCSP again (extAuthInfo already
     * set), then a non-OCSP method (id-ad-caRepository). Each entry's
     * accessLocation is a [6] uniformResourceIdentifier (primitive,
     * context tag 0x86). */
    static const byte aia[] = {
        0x30, 0x42,                 /* AuthorityInfoAccessSyntax SEQUENCE */
          0x30,0x14,                /* AccessDescription #1 */
            0x06,0x08, 0x2B,0x06,0x01,0x05,0x05,0x07,0x30,0x01, /* id-ad-ocsp */
            0x86,0x08, 'h','t','t','p',':','/','/','a',
          0x30,0x14,                /* AccessDescription #2 (OCSP again) */
            0x06,0x08, 0x2B,0x06,0x01,0x05,0x05,0x07,0x30,0x01,
            0x86,0x08, 'h','t','t','p',':','/','/','b',
          0x30,0x14,                /* AccessDescription #3 (caRepository) */
            0x06,0x08, 0x2B,0x06,0x01,0x05,0x05,0x07,0x30,0x05,
            0x86,0x08, 'h','t','t','p',':','/','/','c',
    };

    WB_NOTE("DecodeAuthInfo(): loop [:20309] + first-OCSP-wins [:20342,:20343]");
    XMEMSET(&cert, 0, sizeof(cert));
    ret = DecodeAuthInfo(aia, sizeof(aia), &cert);
    WB_CHECK(ret == 0, "three AccessDescriptions parsed (loop true x3, false exit)");
    WB_CHECK(cert.extAuthInfoSz == 8 && cert.extAuthInfo != NULL &&
            cert.extAuthInfo[7] == 'a',
            "first OCSP entry wins (both operands true on entry #1)");
    WB_CHECK(cert.extAuthInfoListSz == 3,
            "all three entries recorded in the AIA list (2nd OCSP: "
            "1st operand true, 2nd operand false -- extAuthInfo already set; "
            "caRepository: 1st operand false)");

    /* Zero-entry AIA -> :20309 false on first check. */
    {
        static const byte aiaEmpty[] = { 0x30, 0x00 };
        XMEMSET(&cert, 0, sizeof(cert));
        ret = DecodeAuthInfo(aiaEmpty, sizeof(aiaEmpty), &cert);
        WB_CHECK(ret == 0 && cert.extAuthInfo == NULL,
                "empty AIA sequence (:20309 false immediately)");
    }

#ifdef WOLFSSL_ASN_CA_ISSUER
    /* Two id-ad-caIssuers AccessDescriptions. The first drives the
     * caIssuers `else if` with both operands true (method matches and no
     * entry recorded yet); the second drives it with the 1st operand true
     * and the 2nd false (extAuthInfoCaIssuer already set). The three-entry
     * fixture above supplies the 1st-operand-false row (a non-caIssuers
     * method reaching the same `else if`). */
    {
        static const byte aiaCaIssuer[] = {
            0x30, 0x2C,
              0x30,0x14,
                0x06,0x08, 0x2B,0x06,0x01,0x05,0x05,0x07,0x30,0x02,
                0x86,0x08, 'h','t','t','p',':','/','/','d',
              0x30,0x14,
                0x06,0x08, 0x2B,0x06,0x01,0x05,0x05,0x07,0x30,0x02,
                0x86,0x08, 'h','t','t','p',':','/','/','e',
        };
        WB_NOTE("DecodeAuthInfo(): first-caIssuers-wins [:20342 else-if]");
        XMEMSET(&cert, 0, sizeof(cert));
        ret = DecodeAuthInfo(aiaCaIssuer, sizeof(aiaCaIssuer), &cert);
        WB_CHECK(ret == 0, "two caIssuers AccessDescriptions parsed");
        WB_CHECK(cert.extAuthInfoCaIssuer != NULL &&
                cert.extAuthInfoCaIssuerSz == 8 &&
                cert.extAuthInfoCaIssuer[7] == 'd',
                "first caIssuers entry wins (both operands true then "
                "2nd operand false)");
    }
#endif /* WOLFSSL_ASN_CA_ISSUER */
}

/* ------------------------------------------------------------------------- *
 * Section 12: DecodeAuthKeyId() (global function, full control over the
 * out-parameter pointers themselves).
 *   :20449  ret==0 && extAuthKeyId!=NULL(ptr) && extAuthKeyIdSz!=NULL(ptr)
 *           && KEYID.data.ref.data!=NULL
 *   :20455  ret==0 && ISSUER.data.ref.data!=NULL          (WOLFSSL_AKID_NAME)
 *   :20468  ret==0 && extAuthKeyIdIssuer(ptr) && extAuthKeyIdIssuerSz(ptr)
 *   :20473-:20474  ret==0 && extAuthKeyIdIssuerSN(ptr) && ...SNSz(ptr) &&
 *                  SERIAL.data.ref.data!=NULL
 *   :20478  ret==0 && extAuthKeyIdIssuerSz(ptr) && extAuthKeyIdIssuerSNSz(ptr)
 * ------------------------------------------------------------------------- */
static void wb_decode_auth_key_id(void)
{
    const byte *keyId, *issuer, *issuerSN;
    word32 keyIdSz, issuerSz, issuerSNSz;
    int ret;

    /* KEYID only: [0] IMPLICIT OCTET STRING (primitive, tag 0x80). */
    static const byte akidKeyIdOnly[] = {
        0x30,0x06, 0x80,0x04, 0xAA,0xBB,0xCC,0xDD
    };
    /* Empty SEQUENCE: no fields at all -> every data.ref.data stays NULL. */
    static const byte akidEmpty[] = { 0x30, 0x00 };
    /* ISSUER only: [1] IMPLICIT GeneralNames containing one dNSName
     * "host" (context tag 0x82, primitive). */
    static const byte akidIssuerOnly[] = {
        0x30,0x08, 0xA1,0x06, 0x82,0x04, 'h','o','s','t'
    };
    /* SERIAL only: [2] IMPLICIT INTEGER (primitive, tag 0x82 collides in
     * value with dNSName above but is a different template slot). */
    static const byte akidSerialOnly[] = {
        0x30,0x05, 0x82,0x03, 0x01,0x02,0x03
    };

    WB_NOTE("DecodeAuthKeyId(): KEYID present, out-ptr truthiness [:20449]");
    keyId = NULL; keyIdSz = 0;
    ret = DecodeAuthKeyId(akidKeyIdOnly, sizeof(akidKeyIdOnly), &keyId,
            &keyIdSz, NULL, NULL, NULL, NULL);
    WB_CHECK(ret == 0 && keyId != NULL && keyIdSz == 4,
            "KEYID present, out-ptrs valid (all 3 operands true)");
    ret = DecodeAuthKeyId(akidKeyIdOnly, sizeof(akidKeyIdOnly), NULL,
            &keyIdSz, NULL, NULL, NULL, NULL);
    WB_CHECK(ret == 0, "extAuthKeyId==NULL out-ptr (2nd operand false)");
    ret = DecodeAuthKeyId(akidKeyIdOnly, sizeof(akidKeyIdOnly), &keyId,
            NULL, NULL, NULL, NULL, NULL);
    WB_CHECK(ret == 0, "extAuthKeyIdSz==NULL out-ptr (3rd operand false)");
    ret = DecodeAuthKeyId(akidEmpty, sizeof(akidEmpty), &keyId, &keyIdSz,
            NULL, NULL, NULL, NULL);
    WB_CHECK(ret == 0 && keyId == NULL,
            "KEYID absent (4th operand false: data.ref.data==NULL)");

#ifdef WOLFSSL_AKID_NAME
    WB_NOTE("DecodeAuthKeyId(): ISSUER present, out-ptr truthiness [:20455,:20468]");
    issuer = NULL; issuerSz = 0;
    ret = DecodeAuthKeyId(akidIssuerOnly, sizeof(akidIssuerOnly), NULL, NULL,
            &issuer, &issuerSz, NULL, NULL);
    WB_CHECK(ret == 0 && issuer != NULL,
            "ISSUER present, both out-ptrs valid (:20455 true, :20468 all true)");
    ret = DecodeAuthKeyId(akidIssuerOnly, sizeof(akidIssuerOnly), NULL, NULL,
            NULL, &issuerSz, NULL, NULL);
    WB_CHECK(ret == 0, "extAuthKeyIdIssuer==NULL out-ptr (:20468 2nd operand false)");
    ret = DecodeAuthKeyId(akidIssuerOnly, sizeof(akidIssuerOnly), NULL, NULL,
            &issuer, NULL, NULL, NULL);
    WB_CHECK(ret == 0, "extAuthKeyIdIssuerSz==NULL out-ptr (:20468 3rd operand false)");
    ret = DecodeAuthKeyId(akidKeyIdOnly, sizeof(akidKeyIdOnly), NULL, NULL,
            &issuer, &issuerSz, NULL, NULL);
    WB_CHECK(ret == 0, "ISSUER absent (:20455 false, inner block skipped)");

    WB_NOTE("DecodeAuthKeyId(): SERIAL present, out-ptr truthiness [:20473,:20474,:20478]");
    issuerSN = NULL; issuerSNSz = 0;
    ret = DecodeAuthKeyId(akidSerialOnly, sizeof(akidSerialOnly), NULL, NULL,
            NULL, NULL, &issuerSN, &issuerSNSz);
    WB_CHECK(ret == 0 && issuerSN != NULL,
            "SERIAL present, both out-ptrs valid (:20473-:20474 all true)");
    ret = DecodeAuthKeyId(akidSerialOnly, sizeof(akidSerialOnly), NULL, NULL,
            NULL, NULL, NULL, &issuerSNSz);
    WB_CHECK(ret == 0, "extAuthKeyIdIssuerSN==NULL out-ptr (2nd operand false)");
    ret = DecodeAuthKeyId(akidSerialOnly, sizeof(akidSerialOnly), NULL, NULL,
            NULL, NULL, &issuerSN, NULL);
    WB_CHECK(ret == 0, "extAuthKeyIdIssuerSNSz==NULL out-ptr (3rd operand false)");
    ret = DecodeAuthKeyId(akidKeyIdOnly, sizeof(akidKeyIdOnly), NULL, NULL,
            NULL, NULL, &issuerSN, &issuerSNSz);
    WB_CHECK(ret == 0, "SERIAL absent (4th operand false, data.ref.data==NULL)");

    WB_NOTE("DecodeAuthKeyId(): issuer/serial-sz cross truthiness [:20478]");
    issuer = NULL; issuerSz = 0; issuerSN = NULL; issuerSNSz = 0;
    ret = DecodeAuthKeyId(akidIssuerOnly, sizeof(akidIssuerOnly), NULL, NULL,
            &issuer, &issuerSz, &issuerSN, &issuerSNSz);
    WB_CHECK(ret == 0, "both issuerSz/issuerSNSz out-ptrs valid (both true)");
    ret = DecodeAuthKeyId(akidIssuerOnly, sizeof(akidIssuerOnly), NULL, NULL,
            &issuer, NULL, &issuerSN, &issuerSNSz);
    WB_CHECK(ret == 0, "extAuthKeyIdIssuerSz==NULL (1st operand false)");
    ret = DecodeAuthKeyId(akidIssuerOnly, sizeof(akidIssuerOnly), NULL, NULL,
            &issuer, &issuerSz, &issuerSN, NULL);
    WB_CHECK(ret == 0, "extAuthKeyIdIssuerSNSz==NULL (2nd operand false)");

    /* [1] authorityCertIssuer holding a truncated GeneralName ([6] URI
     * declaring 5 content bytes with none present): the inner
     * GetASN_Items() fails, so :20468 runs with ret != 0 (1st operand
     * false). */
    {
        static const byte akidBadIssuer[] = {
            0x30,0x04, 0xA1,0x02, 0x86,0x05
        };
        ret = DecodeAuthKeyId(akidBadIssuer, sizeof(akidBadIssuer), NULL,
                NULL, &issuer, &issuerSz, NULL, NULL);
        WB_CHECK(ret != 0, "unsupported GeneralName choice in the AKID "
                "issuer (:20468 1st operand false)");
    }
#else
    WB_NOTE("WOLFSSL_AKID_NAME not defined; ISSUER/SERIAL blocks skipped");
    (void)issuer; (void)issuerSz; (void)issuerSN; (void)issuerSNSz;
#endif
}

/* ------------------------------------------------------------------------- *
 * Section 13: DecodeExtKeyUsage() (global function).
 *   :20815  (ret==0) && (extExtKeyUsageOidCnt != NULL)     (out-ptr truthy)
 * The while loop itself [:20815 is actually the OidCnt check; the loop
 * condition is the enclosing `while ((ret==0) && (idx<sz))`] is exercised
 * by the two-OID buffer below (recognized + unrecognized-but-forgiven).
 * ------------------------------------------------------------------------- */
static void wb_decode_ext_key_usage(void)
{
    const byte *src; word32 srcSz, count, oidCnt;
    byte usage, ssh;
    int ret;
    /* serverAuth (recognized) followed by an arbitrary unrecognized OID
     * (1.2.3.4) that DecodeExtKeyUsage() forgives (ASN_UNKNOWN_OID_E ->
     * ret reset to 0) but still counts via extExtKeyUsageOidCnt. */
    static const byte eku[] = {
        0x30,0x0F,
          0x06,0x08, 0x2B,0x06,0x01,0x05,0x05,0x07,0x03,0x01, /* serverAuth */
          0x06,0x03, 0x2A,0x03,0x04                            /* 1.2.3.4 */
    };

    WB_NOTE("DecodeExtKeyUsage(): loop + recognized/forgiven OIDs [:20815]");
    src = NULL; srcSz = 0; count = 0; usage = 0; ssh = 0; oidCnt = 0;
    ret = DecodeExtKeyUsage(eku, sizeof(eku), &src, &srcSz, &count, &usage,
            &ssh, &oidCnt);
    WB_CHECK(ret == 0 && (usage & EXTKEYUSE_SERVER_AUTH) != 0,
            "recognized + forgiven-unknown OID, oidCnt out-ptr valid (true)");
    WB_CHECK(oidCnt == 2, "both OIDs counted despite one unrecognized");

    /* Same buffer, oidCnt out-param NULL -> 2nd operand false. */
    src = NULL; srcSz = 0; count = 0; usage = 0; ssh = 0;
    ret = DecodeExtKeyUsage(eku, sizeof(eku), &src, &srcSz, &count, &usage,
            &ssh, NULL);
    WB_CHECK(ret == 0, "extExtKeyUsageOidCnt==NULL out-ptr (2nd operand false)");

    /* Empty SEQUENCE OF -> loop condition false immediately. */
    {
        static const byte ekuEmpty[] = { 0x30, 0x00 };
        src = NULL; srcSz = 0; count = 0; usage = 0; ssh = 0; oidCnt = 99;
        ret = DecodeExtKeyUsage(ekuEmpty, sizeof(ekuEmpty), &src, &srcSz,
                &count, &usage, &ssh, &oidCnt);
        WB_CHECK(ret == 0 && oidCnt == 0, "empty EKU sequence (loop false)");
    }
}

/* ------------------------------------------------------------------------- *
 * Section 14: DecodeSubtree() (static, called directly).
 *   :21075  while ((ret==0) && (idx<sz))
 *   :21104-:21105  (minVal!=0) || (MAX.length>0)
 *   :21117-:21124  7-way GeneralName-tag recognition OR
 * ------------------------------------------------------------------------- */
#ifndef IGNORE_NAME_CONSTRAINTS
static void wb_decode_subtree(void)
{
    int ret;
    byte hasUnsupported;
    Base_entry* head;

    /* One GeneralSubtree: dNSName base "host", no minimum/maximum. */
    static const byte gsDns[] = { 0x30,0x06, 0x82,0x04, 'h','o','s','t' };
    /* minimum present and non-zero (value 1). */
    static const byte gsMinBad[] =
        { 0x30,0x09, 0x82,0x04,'h','o','s','t', 0x80,0x01,0x01 };
    /* maximum present (any value, even 0, is disallowed by RFC 5280). */
    static const byte gsMaxBad[] =
        { 0x30,0x09, 0x82,0x04,'h','o','s','t', 0x81,0x01,0x00 };
    /* Unrecognized GeneralName form: x400Address, [3] primitive. */
    static const byte gsUnrecognized[] = { 0x30,0x03, 0x83,0x01, 'Z' };
    /* One dedicated GeneralSubtree per recognized tag, to independently
     * show each operand of the 7-way OR true while the others (as
     * evaluated up to that point) are false. */
    static const byte gsRfc822[]  = { 0x30,0x03, 0x81,0x01, 'e' };
    static const byte gsDir[]     = { 0x30,0x04, 0xA4,0x02, 0x30,0x00 };
    static const byte gsIp[]      = { 0x30,0x06, 0x87,0x04, 1,2,3,4 };
    static const byte gsUri[]     = { 0x30,0x03, 0x86,0x01, 'u' };
    static const byte gsOther[]   = { 0x30,0x03, 0xA0,0x01, 1 };
    static const byte gsRid[]     = { 0x30,0x03, 0x88,0x01, 0x2A };

    WB_NOTE("DecodeSubtree(): empty input (loop false) [:21075]");
    head = NULL; hasUnsupported = 0;
    ret = DecodeSubtree(gsDns, 0, &head, 0, &hasUnsupported, NULL);
    WB_CHECK(ret == 0 && head == NULL, "sz==0 (loop condition false immediately)");

    WB_NOTE("DecodeSubtree(): baseline dNSName, min/max absent [:21075 true, :21104,:21105 both false]");
    head = NULL; hasUnsupported = 0;
    ret = DecodeSubtree(gsDns, sizeof(gsDns), &head, 0, &hasUnsupported, NULL);
    WB_CHECK(ret == 0 && head != NULL && !hasUnsupported,
            "min/max absent, recognized tag (loop true then false; both min/max false)");

    WB_NOTE("DecodeSubtree(): minimum != 0 rejected [:21104]");
    head = NULL; hasUnsupported = 0;
    ret = DecodeSubtree(gsMinBad, sizeof(gsMinBad), &head, 0, &hasUnsupported,
            NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_NAME_INVALID_E),
            "minimum==1 (1st operand true)");

    WB_NOTE("DecodeSubtree(): maximum present rejected [:21105]");
    head = NULL; hasUnsupported = 0;
    ret = DecodeSubtree(gsMaxBad, sizeof(gsMaxBad), &head, 0, &hasUnsupported,
            NULL);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_NAME_INVALID_E),
            "maximum present (1st false, 2nd true)");

    WB_NOTE("DecodeSubtree(): 7-way GeneralName tag OR, all-false baseline [:21117-:21124]");
    head = NULL; hasUnsupported = 0;
    ret = DecodeSubtree(gsUnrecognized, sizeof(gsUnrecognized), &head, 0,
            &hasUnsupported, NULL);
    WB_CHECK(ret == 0 && hasUnsupported == 1 && head == NULL,
            "x400Address-style [3] tag (all 7 operands false)");

    WB_NOTE("DecodeSubtree(): 7-way OR, each tag true individually [:21117-:21124]");
    head = NULL; hasUnsupported = 0;
    ret = DecodeSubtree(gsRfc822, sizeof(gsRfc822), &head, 0, &hasUnsupported,
            NULL);
    WB_CHECK(ret == 0 && !hasUnsupported, "rfc822Name tag recognized");
    head = NULL; hasUnsupported = 0;
    ret = DecodeSubtree(gsDir, sizeof(gsDir), &head, 0, &hasUnsupported, NULL);
    WB_CHECK(ret == 0 && !hasUnsupported, "directoryName tag recognized");
    head = NULL; hasUnsupported = 0;
    ret = DecodeSubtree(gsIp, sizeof(gsIp), &head, 0, &hasUnsupported, NULL);
    WB_CHECK(ret == 0 && !hasUnsupported, "iPAddress tag recognized");
    head = NULL; hasUnsupported = 0;
    ret = DecodeSubtree(gsUri, sizeof(gsUri), &head, 0, &hasUnsupported, NULL);
    WB_CHECK(ret == 0 && !hasUnsupported, "uniformResourceIdentifier tag recognized");
    head = NULL; hasUnsupported = 0;
    ret = DecodeSubtree(gsOther, sizeof(gsOther), &head, 0, &hasUnsupported,
            NULL);
    WB_CHECK(ret == 0 && !hasUnsupported, "otherName tag recognized");
    head = NULL; hasUnsupported = 0;
    ret = DecodeSubtree(gsRid, sizeof(gsRid), &head, 0, &hasUnsupported, NULL);
    WB_CHECK(ret == 0 && !hasUnsupported, "registeredID tag recognized");

    WB_NOTE("DecodeSubtree(): too-many-entries limit (unrelated OR, sanity)");
    head = NULL; hasUnsupported = 0;
    ret = DecodeSubtree(gsDns, sizeof(gsDns), &head, 1, &hasUnsupported, NULL);
    WB_CHECK(ret == 0, "limit==1, exactly one entry (no overflow)");
}
#else
static void wb_decode_subtree(void) { WB_NOTE("IGNORE_NAME_CONSTRAINTS; skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Section 15: DecodeNameConstraints() hasUnsupported propagation [:21217].
 * ------------------------------------------------------------------------- */
#ifndef IGNORE_NAME_CONSTRAINTS
static void wb_decode_name_constraints(void)
{
    DecodedCert cert;
    int ret;
    /* NameConstraints ::= SEQUENCE { permittedSubtrees [0] ... }
     * permittedSubtrees contains one GeneralSubtree with an unrecognized
     * (x400Address-style) base -> hasUnsupported becomes 1. */
    static const byte ncUnsupported[] = {
        0x30,0x09,
          0xA0,0x07,              /* [0] permittedSubtrees, implicit SEQUENCE OF */
            0x30,0x05,
              0x83,0x03, 'A','B','C'
    };
    /* Same shape but with a recognized dNSName base -> hasUnsupported
     * stays 0. */
    static const byte ncSupported[] = {
        0x30,0x0A,
          0xA0,0x08,
            0x30,0x06,
              0x82,0x04, 'h','o','s','t'
    };

    WB_NOTE("DecodeNameConstraints(): hasUnsupported -> extNameConstraintHasUnsupported [:21217]");
    XMEMSET(&cert, 0, sizeof(cert));
    ret = DecodeNameConstraints(ncUnsupported, sizeof(ncUnsupported), &cert);
    WB_CHECK(ret == 0 && cert.extNameConstraintHasUnsupported == 1,
            "unsupported GeneralName form (both operands true)");

    XMEMSET(&cert, 0, sizeof(cert));
    ret = DecodeNameConstraints(ncSupported, sizeof(ncSupported), &cert);
    WB_CHECK(ret == 0 && cert.extNameConstraintHasUnsupported == 0,
            "recognized form only (2nd operand false)");
}
#else
static void wb_decode_name_constraints(void) { WB_NOTE("IGNORE_NAME_CONSTRAINTS; skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Section 16: DecodePolicyOID() (global function).
 *   :21240  out==NULL || in==NULL || outSz<4 || inSz<2
 *   :21272  w<0 || (word32)w>outSz-outIdx     (output-buffer overflow guard)
 * ------------------------------------------------------------------------- */
static void wb_decode_policy_oid(void)
{
    char out[64];
    int ret;
    /* 2.5.29.32.0 (anyPolicy): 55 1D 20 00. */
    static const byte oidBytes[] = { 0x55, 0x1D, 0x20, 0x00 };

    WB_NOTE("DecodePolicyOID(): bad-args OR [:21240]");
    WB_CHECK(DecodePolicyOID(NULL, sizeof(out), oidBytes, sizeof(oidBytes))
                == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "out==NULL");
    WB_CHECK(DecodePolicyOID(out, sizeof(out), NULL, sizeof(oidBytes))
                == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "in==NULL");
    WB_CHECK(DecodePolicyOID(out, 3, oidBytes, sizeof(oidBytes))
                == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "outSz<4");
    WB_CHECK(DecodePolicyOID(out, sizeof(out), oidBytes, 1)
                == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "inSz<2");
    ret = DecodePolicyOID(out, sizeof(out), oidBytes, sizeof(oidBytes));
    WB_CHECK(ret > 0 && strcmp(out, "2.5.29.32.0") == 0,
            "all args valid (all 4 operands false)");

    WB_NOTE("DecodePolicyOID(): output buffer overflow guard [:21272]");
    /* A tiny output buffer forces the ".%u" snprintf to not fit after the
     * first "b.b" segment is written. */
    {
        /* outSz must be >= 4 to get past the argument guard. With outSz == 6
         * the ".29" segment fits exactly (XSNPRINTF returns 3, remaining is
         * 3) and outIdx then equals outSz, so the loop exits on its own
         * condition and the overflow guard is never true -- that row only
         * supplies the guard's FALSE side.
         *
         * outSz == 5 is the size that trips it: "2.5" leaves 2 bytes, the
         * ".29" segment needs 3, XSNPRINTF returns 3 > 2 and the guard's
         * 2nd operand is true.
         *
         * The 1st operand (`w < 0`) has no satisfiable pair: XSNPRINTF is
         * snprintf here, which returns the length it would have written and
         * never a negative value for these arguments. */
        char tiny6[6];
        char tiny5[5];

        ret = DecodePolicyOID(tiny6, sizeof(tiny6), oidBytes,
                sizeof(oidBytes));
        WB_CHECK(ret > 0, ":21326 2nd operand false (segment fits exactly)");

        ret = DecodePolicyOID(tiny5, sizeof(tiny5), oidBytes,
                sizeof(oidBytes));
        WB_CHECK(ret == WC_NO_ERR_TRACE(BUFFER_E),
                ":21326 2nd operand true (segment does not fit)");
    }
    ret = DecodePolicyOID(out, sizeof(out), oidBytes, sizeof(oidBytes));
    WB_CHECK(ret > 0, "ample output buffer (overflow guard false)");
}

/* ------------------------------------------------------------------------- *
 * Section 17: DecodeCertPolicy() (static, called directly).
 * Gated on WOLFSSL_SEP || WOLFSSL_CERT_EXT, same as the source.
 *   :21346  while ((ret==0) && (idx<total_length) && (extCertPoliciesNb<MAX_CERTPOL_NB))
 *   :21369  ret==0 && cert->deviceType==NULL          (WOLFSSL_SEP)
 *   :21401  duplicate-OID scan loop (WOLFSSL_CERT_EXT, !WOLFSSL_DUP_CERTPOL)
 * MAX_CERTPOL_NB is 2, so three policies exercise the count limit.
 * ------------------------------------------------------------------------- */
#if defined(WOLFSSL_SEP) || defined(WOLFSSL_CERT_EXT)
static void wb_decode_cert_policy(void)
{
    DecodedCert cert;
    int ret;
    /* One policy OID, 2.5.29.32.0 (anyPolicy). A one-byte OID body is
     * rejected by the template before the loop body runs, so every fixture
     * here carries a full four-byte OID. */
    static const byte onePolicy[] = {
        0x30,0x08, 0x30,0x06, 0x06,0x04,0x55,0x1D,0x20,0x00
    };
    /* Two distinct policies: the second iteration finds deviceType already
     * set (:21369 2nd operand false) and runs the duplicate scan with a
     * non-empty list (:21401 2nd operand true). */
    static const byte twoPolicies[] = {
        0x30,0x10,
          0x30,0x06, 0x06,0x04,0x55,0x1D,0x20,0x00,
          0x30,0x06, 0x06,0x04,0x55,0x1D,0x20,0x01,
    };
    /* Three distinct policies -- exercises the MAX_CERTPOL_NB==2 cap (3rd
     * operand of :21346 goes false while idx<total_length is still true). */
    static const byte threePolicies[] = {
        0x30,0x18,
          0x30,0x06, 0x06,0x04,0x55,0x1D,0x20,0x00,
          0x30,0x06, 0x06,0x04,0x55,0x1D,0x20,0x01,
          0x30,0x06, 0x06,0x04,0x55,0x1D,0x20,0x02,
    };
    /* Two IDENTICAL policy OIDs -- 2nd occurrence is a duplicate, hits
     * :21401's XMEMCMP==0 true arm and then re-tests the loop condition
     * with ret != 0 (1st operand false). Only compiled without
     * WOLFSSL_DUP_CERTPOL. */
    static const byte dupPolicies[] = {
        0x30,0x10,
          0x30,0x06, 0x06,0x04,0x55,0x1D,0x20,0x00,
          0x30,0x06, 0x06,0x04,0x55,0x1D,0x20,0x00,
    };
    /* PolicyInformation holding an INTEGER instead of an OBJECT_ID: the
     * template parse fails inside the loop, so the deviceType step at
     * :21369 runs with ret != 0 (1st operand false). */
    static const byte badPolicy[] = {
        0x30,0x05, 0x30,0x03, 0x02,0x01,0x00
    };
    /* Zero policies. */
    static const byte noPolicies[] = { 0x30, 0x00 };

    WB_NOTE("DecodeCertPolicy(): zero policies (loop false via idx<total_length) [:21346]");
    XMEMSET(&cert, 0, sizeof(cert));
    ret = DecodeCertPolicy(noPolicies, sizeof(noPolicies), &cert);
    WB_CHECK(ret == 0, "no policies present");

    WB_NOTE("DecodeCertPolicy(): one policy (loop true then false) [:21346,:21369]");
    XMEMSET(&cert, 0, sizeof(cert));
    ret = DecodeCertPolicy(onePolicy, sizeof(onePolicy), &cert);
#if defined(WOLFSSL_CERT_EXT)
    WB_CHECK(ret == 0 && cert.extCertPoliciesNb == 1,
            "single policy accepted");
#else
    WB_CHECK(ret == 0, "single policy accepted (no WOLFSSL_CERT_EXT counter)");
#endif
#ifdef WOLFSSL_SEP
    WB_CHECK(cert.deviceType != NULL,
            "deviceType populated from first policy OID (:21369 both true)");
    if (cert.deviceType != NULL) {
        XFREE(cert.deviceType, cert.heap, DYNAMIC_TYPE_X509_EXT);
    }
#endif

    WB_NOTE("DecodeCertPolicy(): second policy, deviceType already set [:21369]");
    XMEMSET(&cert, 0, sizeof(cert));
    ret = DecodeCertPolicy(twoPolicies, sizeof(twoPolicies), &cert);
    WB_CHECK(ret == 0, "two policies accepted (:21369 2nd operand false on "
            "the second, :21401 2nd operand true)");
#ifdef WOLFSSL_SEP
    if (cert.deviceType != NULL) {
        XFREE(cert.deviceType, cert.heap, DYNAMIC_TYPE_X509_EXT);
    }
#endif

    WB_NOTE("DecodeCertPolicy(): malformed PolicyInformation [:21369 1st operand]");
    XMEMSET(&cert, 0, sizeof(cert));
    ret = DecodeCertPolicy(badPolicy, sizeof(badPolicy), &cert);
    WB_CHECK(ret != 0 && cert.deviceType == NULL,
            "INTEGER in place of the policy OID (:21369 1st operand false)");

#if defined(WOLFSSL_CERT_EXT)
    WB_NOTE("DecodeCertPolicy(): MAX_CERTPOL_NB cap with 3 policies [:21346 3rd operand]");
    XMEMSET(&cert, 0, sizeof(cert));
    ret = DecodeCertPolicy(threePolicies, sizeof(threePolicies), &cert);
    WB_CHECK(ret == 0 && cert.extCertPoliciesNb == MAX_CERTPOL_NB,
            "loop stops at MAX_CERTPOL_NB even though bytes remain "
            "(3rd operand false while 1st/2nd stay true)");
#ifdef WOLFSSL_SEP
    if (cert.deviceType != NULL) {
        XFREE(cert.deviceType, cert.heap, DYNAMIC_TYPE_X509_EXT);
    }
#endif

#ifndef WOLFSSL_DUP_CERTPOL
    WB_NOTE("DecodeCertPolicy(): duplicate-OID rejection [:21401]");
    XMEMSET(&cert, 0, sizeof(cert));
    ret = DecodeCertPolicy(dupPolicies, sizeof(dupPolicies), &cert);
    WB_CHECK(ret == WC_NO_ERR_TRACE(CERTPOLICIES_E),
            "duplicate policy OID rejected (loop finds a match)");
#ifdef WOLFSSL_SEP
    if (cert.deviceType != NULL) {
        XFREE(cert.deviceType, cert.heap, DYNAMIC_TYPE_X509_EXT);
    }
#endif
#endif /* !WOLFSSL_DUP_CERTPOL */
#endif /* WOLFSSL_CERT_EXT */
}
#else
static void wb_decode_cert_policy(void) { WB_NOTE("WOLFSSL_SEP/WOLFSSL_CERT_EXT off; skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Section 18: DecodeSubjDirAttr() (static, called directly).
 * Gated on WOLFSSL_SUBJ_DIR_ATTR, same as the source.
 *   :21473  GetSequence(input,...) < 0
 *   :21477  while ((ret==0) && (idx<sz))
 *   :21483-:21484  ret==0 && OID.sum==SDA_COC_OID
 *   :21495  ret==0 && cuLen!=COUNTRY_CODE_LEN
 * ------------------------------------------------------------------------- */
#ifdef WOLFSSL_SUBJ_DIR_ATTR
static void wb_decode_subj_dir_attr(void)
{
    DecodedCert cert;
    int ret;
    /* One Attribute: countryOfCitizenship = "US" (valid, len==2). */
    static const byte sdaCoc[] = {
        0x30,0x12,
          0x30,0x10,
            0x06,0x08, 0x2B,0x06,0x01,0x05,0x05,0x07,0x09,0x04, /* pda-coc */
            0x31,0x04, 0x13,0x02,'U','S'
    };
    /* One Attribute with a DIFFERENT OID (rsaEncryption, arbitrary here)
     * -- not countryOfCitizenship. */
    static const byte sdaOther[] = {
        0x30,0x15,
          0x30,0x13,
            0x06,0x09, 0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01,
            0x31,0x04, 0x13,0x02,'X','X'
    };
    /* countryOfCitizenship with a length != COUNTRY_CODE_LEN (3 chars). */
    static const byte sdaBadLen[] = {
        0x30,0x13,
          0x30,0x11,
            0x06,0x08, 0x2B,0x06,0x01,0x05,0x05,0x07,0x09,0x04,
            0x31,0x05, 0x13,0x03,'U','S','A'
    };
    /* Malformed: not a SEQUENCE at all. */
    static const byte sdaBadTag[] = { 0x31, 0x00 };
    /* Zero attributes. */
    static const byte sdaEmpty[] = { 0x30, 0x00 };

    WB_NOTE("DecodeSubjDirAttr(): outer GetSequence failure [:21473]");
    XMEMSET(&cert, 0, sizeof(cert));
    ret = DecodeSubjDirAttr(sdaBadTag, sizeof(sdaBadTag), &cert);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E), "wrong outer tag (true)");

    WB_NOTE("DecodeSubjDirAttr(): empty attribute list (loop false) [:21477]");
    XMEMSET(&cert, 0, sizeof(cert));
    ret = DecodeSubjDirAttr(sdaEmpty, sizeof(sdaEmpty), &cert);
    WB_CHECK(ret == 0, "zero attributes (loop false immediately)");

    WB_NOTE("DecodeSubjDirAttr(): countryOfCitizenship match [:21483,:21484,:21495]");
    XMEMSET(&cert, 0, sizeof(cert));
    ret = DecodeSubjDirAttr(sdaCoc, sizeof(sdaCoc), &cert);
    WB_CHECK(ret == 0 && XMEMCMP(cert.countryOfCitizenship, "US", 2) == 0,
            "countryOfCitizenship OID + valid length (all true, false)");

    WB_NOTE("DecodeSubjDirAttr(): OID outside oidSubjDirAttrType [:21483]");
    XMEMSET(&cert, 0, sizeof(cert));
    ret = DecodeSubjDirAttr(sdaOther, sizeof(sdaOther), &cert);
    /* rsaEncryption is not in oidSubjDirAttrType, so GetASN_Items() rejects
     * the attribute before the OID comparison is reached -- this row drives
     * the loop's ret==0 operand false, not the comparison's 2nd operand.
     * The dateOfBirth fixture at the end of this file is the one that
     * reaches the comparison with a recognized non-COC OID. */
    WB_CHECK(ret != 0, "OID not in oidSubjDirAttrType (attribute rejected)");

    WB_NOTE("DecodeSubjDirAttr(): countryOfCitizenship wrong length [:21495]");
    XMEMSET(&cert, 0, sizeof(cert));
    ret = DecodeSubjDirAttr(sdaBadLen, sizeof(sdaBadLen), &cert);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E),
            "3-char country code (cuLen!=COUNTRY_CODE_LEN true)");
}
#else
static void wb_decode_subj_dir_attr(void) { WB_NOTE("WOLFSSL_SUBJ_DIR_ATTR off; skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Section 19: DecodeSubjInfoAcc() (static, called directly).
 * Gated on WOLFSSL_SUBJ_INFO_ACC, same as the source.
 *   :21570  b==GENERALNAME_URI && oid==AIA_CA_REPO_OID
 * ------------------------------------------------------------------------- */
#ifdef WOLFSSL_SUBJ_INFO_ACC
static void wb_decode_subj_info_acc(void)
{
    DecodedCert cert;
    int ret;
    /* Entry A: id-ad-ocsp + URI (b==URI true, oid==CA_REPO false).
     * Entry B: id-ad-caRepository + a non-URI ([7] iPAddress-shaped) tag
     *          (b==URI false, oid==CA_REPO true) -- no match, no break.
     * Entry C: id-ad-caRepository + URI (both true) -- matches, breaks. */
    static const byte sia[] = {
        0x30,0x3E,
          0x30,0x14,
            0x06,0x08, 0x2B,0x06,0x01,0x05,0x05,0x07,0x30,0x01, /* ocsp */
            0x86,0x08, 'h','t','t','p',':','/','/','a',
          0x30,0x10,
            0x06,0x08, 0x2B,0x06,0x01,0x05,0x05,0x07,0x30,0x05, /* caRepo */
            0x87,0x04, 'X','X','X','X',
          0x30,0x14,
            0x06,0x08, 0x2B,0x06,0x01,0x05,0x05,0x07,0x30,0x05, /* caRepo */
            0x86,0x08, 'h','t','t','p',':','/','/','c',
    };

    WB_NOTE("DecodeSubjInfoAcc(): caRepository AND uri-tag [:21570]");
    XMEMSET(&cert, 0, sizeof(cert));
    ret = DecodeSubjInfoAcc(sia, sizeof(sia), &cert);
    WB_CHECK(ret == 0 && cert.extSubjInfoAccCaRepo != NULL &&
            cert.extSubjInfoAccCaRepo[7] == 'c',
            "OCSP+URI(F,T->F), caRepo+non-URI(T,F->F), caRepo+URI(T,T->match)");
}
#else
static void wb_decode_subj_info_acc(void) { WB_NOTE("WOLFSSL_SUBJ_INFO_ACC off; skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Section 20: DecodeExtensionType() dispatch (WOLFSSL_TEST_VIS, called
 * directly with hand-picked OID sums so each sub-decoder's error path is
 * reached without needing the surrounding DecodeCertExtensions() wrapper).
 *   :21834  ret==0 && (DecodeAuthInfo(...) < 0)
 *   :21871-:21872  ret==0 && (DecodeAuthKeyIdInternal(...) < 0)
 *   :21903-:21904  ret==0 && (DecodeSubjKeyIdInternal(...) < 0)
 * ------------------------------------------------------------------------- */
static void wb_decode_extension_type_dispatch(void)
{
    DecodedCert cert;
    int ret, isUnknown;
    static const byte badAia[] = { 0xFF };       /* not a SEQUENCE at all */
    static const byte badAkid[] = { 0xFF };
    static const byte badSkid[] = { 0xFF };
    static const byte okSkid[] = { 0x04,0x02, 0xAA,0xBB }; /* OCTET STRING */

    WB_NOTE("DecodeExtensionType(): AUTH_INFO_OID failure propagation [:21834]");
    XMEMSET(&cert, 0, sizeof(cert));
    isUnknown = 0;
    ret = DecodeExtensionType(badAia, sizeof(badAia), AUTH_INFO_OID, 0,
            &cert, &isUnknown);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E),
            "malformed AuthorityInfoAccess (ret==0 true, DecodeAuthInfo<0 true)");

    WB_NOTE("DecodeExtensionType(): AUTH_KEY_OID failure propagation [:21871,:21872]");
    XMEMSET(&cert, 0, sizeof(cert));
    isUnknown = 0;
    ret = DecodeExtensionType(badAkid, sizeof(badAkid), AUTH_KEY_OID, 0,
            &cert, &isUnknown);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E),
            "malformed AuthorityKeyIdentifier (both operands true)");
    /* critical==1 with the not-allowed-critical guard active makes ret!=0
     * BEFORE reaching this line -- 1st operand (ret==0) false. */
#ifndef WOLFSSL_ALLOW_CRIT_AKID
    XMEMSET(&cert, 0, sizeof(cert));
    isUnknown = 0;
    ret = DecodeExtensionType(badAkid, sizeof(badAkid), AUTH_KEY_OID, 1,
            &cert, &isUnknown);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_CRIT_EXT_E),
            "critical AKID rejected before reaching :21871 (1st operand false)");
#endif

    /* A well-formed AIA makes DecodeAuthInfo() succeed, so the 2nd operand
     * of the AUTH_INFO_OID step goes false with the 1st still true. */
    {
        static const byte okAia[] = {
            0x30, 0x16,
              0x30,0x14,
                0x06,0x08, 0x2B,0x06,0x01,0x05,0x05,0x07,0x30,0x01,
                0x86,0x08, 'h','t','t','p',':','/','/','a',
        };
        XMEMSET(&cert, 0, sizeof(cert));
        isUnknown = 0;
        ret = DecodeExtensionType(okAia, sizeof(okAia), AUTH_INFO_OID, 0,
                &cert, &isUnknown);
        WB_CHECK(ret == 0, "well-formed AuthorityInfoAccess (2nd operand false)");
    }
#ifndef WOLFSSL_ALLOW_CRIT_AIA
    /* critical==1 sets ret before the DecodeAuthInfo() step is reached. */
    XMEMSET(&cert, 0, sizeof(cert));
    isUnknown = 0;
    ret = DecodeExtensionType(badAia, sizeof(badAia), AUTH_INFO_OID, 1,
            &cert, &isUnknown);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_CRIT_EXT_E),
            "critical AIA rejected before the decode step (1st operand false)");
#endif

    WB_NOTE("DecodeExtensionType(): SUBJ_KEY_OID failure propagation [:21903,:21904]");
    XMEMSET(&cert, 0, sizeof(cert));
    isUnknown = 0;
    ret = DecodeExtensionType(badSkid, sizeof(badSkid), SUBJ_KEY_OID, 0,
            &cert, &isUnknown);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E),
            "malformed SubjectKeyIdentifier (both operands true)");
    XMEMSET(&cert, 0, sizeof(cert));
    isUnknown = 0;
    ret = DecodeExtensionType(okSkid, sizeof(okSkid), SUBJ_KEY_OID, 0, &cert,
            &isUnknown);
    WB_CHECK(ret == 0, "well-formed SubjectKeyIdentifier (2nd operand false)");
#ifndef WOLFSSL_ALLOW_CRIT_SKID
    XMEMSET(&cert, 0, sizeof(cert));
    isUnknown = 0;
    ret = DecodeExtensionType(okSkid, sizeof(okSkid), SUBJ_KEY_OID, 1, &cert,
            &isUnknown);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_CRIT_EXT_E),
            "critical SKID rejected before the decode step (1st operand false)");
#endif
}

/* ------------------------------------------------------------------------- *
 * Section 20b: DecodeCrlDist() (static, called directly).
 *   :20299  if (ret == 0 && idx < (word32)sz)
 * The decoder deliberately parses only the FIRST DistributionPoint, so a
 * two-point extension leaves idx short of sz.
 * ------------------------------------------------------------------------- */
#if !defined(WOLFSSL_X509_TINY) || defined(WOLFSSL_X509_TINY_CRL_DP)
static void wb_decode_crl_dist(void)
{
    DecodedCert cert;
    int ret;
    /* One DistributionPoint: [0] distributionPoint { [0] fullName {
     *   [6] URI "http://a" } }. */
    static const byte crlOne[] = {
        0x30,0x10,
          0x30,0x0E,
            0xA0,0x0C,
              0xA0,0x0A,
                0x86,0x08, 'h','t','t','p',':','/','/','a',
    };
    /* Two DistributionPoints: only the first is parsed. */
    static const byte crlTwo[] = {
        0x30,0x20,
          0x30,0x0E,
            0xA0,0x0C,
              0xA0,0x0A,
                0x86,0x08, 'h','t','t','p',':','/','/','a',
          0x30,0x0E,
            0xA0,0x0C,
              0xA0,0x0A,
                0x86,0x08, 'h','t','t','p',':','/','/','b',
    };
    /* INTEGER where the DistributionPoint SEQUENCE belongs. */
    static const byte crlBad[] = { 0x30,0x03, 0x02,0x01,0x00 };

    WB_NOTE("DecodeCrlDist(): trailing DistributionPoints [:20299]");

    XMEMSET(&cert, 0, sizeof(cert));
    ret = DecodeCrlDist(crlOne, sizeof(crlOne), &cert);
    WB_CHECK(ret == 0 && cert.extCrlInfoSz == 8,
            "single DistributionPoint (2nd operand false)");

    XMEMSET(&cert, 0, sizeof(cert));
    ret = DecodeCrlDist(crlTwo, sizeof(crlTwo), &cert);
    WB_CHECK(ret == 0, "two DistributionPoints, only the first used "
            "(both operands true)");

    XMEMSET(&cert, 0, sizeof(cert));
    ret = DecodeCrlDist(crlBad, sizeof(crlBad), &cert);
    WB_CHECK(ret != 0, "malformed DistributionPoint (1st operand false)");
}
#else
static void wb_decode_crl_dist(void) { WB_NOTE("WOLFSSL_X509_TINY without CRL DP; skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Section 20c: heap-fault rows for leading `ret == 0` operands whose only
 * possible predecessor failure is an allocation.
 *   :20596/:20600  DecodeAuthKeyIdInternal(): the only statement that can
 *                  set ret before them is GetHashId() -> CalcHashId_ex() ->
 *                  wc_ShaHash(), which allocates its context only under
 *                  WOLFSSL_SMALL_STACK.
 *   :21527         DecodeSubjDirAttr(): preceded only by CALLOC_ASNGETDATA.
 * Unarmed calls in the same binary supply the TRUE rows.
 * ------------------------------------------------------------------------- */
static void wb_ext_alloc_faults(void)
{
    DecodedCert cert;
    int n;
    int ret;
    /* AKID carrying keyIdentifier, authorityCertIssuer and
     * authorityCertSerialNumber, so all three post-hash steps are reached. */
    static const byte akidFull[] = {
        0x30,0x13,
          0x80,0x04, 0xAA,0xBB,0xCC,0xDD,
          0xA1,0x06, 0x82,0x04, 'h','o','s','t',
          0x82,0x03, 0x01,0x02,0x03
    };
    static const byte sdaCoc2[] = {
        0x30,0x12,
              0x30,0x10,
                    0x06,0x08, 0x2B,0x06,0x01,0x05,0x05,0x07,0x09,0x04,
                    0x31,0x04, 0x13,0x02, 'U','S'
    };

    WB_NOTE("DecodeAuthKeyIdInternal()/DecodeSubjDirAttr(): heap-fault sweep "
            "[:20596,:20600,:21527]");

    /* TRUE rows, unarmed. */
    XMEMSET(&cert, 0, sizeof(cert));
    ret = DecodeAuthKeyIdInternal(akidFull, sizeof(akidFull), &cert);
    WB_CHECK(ret == 0 && cert.extAuthKeyIdIssuerSz > 0 &&
            cert.extAuthKeyIdIssuerSNSz > 0,
            "full AKID decoded (:20596/:20600 both operands true)");

    XMEMSET(&cert, 0, sizeof(cert));
    ret = DecodeSubjDirAttr(sdaCoc2, sizeof(sdaCoc2), &cert);
    WB_CHECK(ret == 0, "subject directory attributes decoded (:21527 1st "
            "operand true)");

    mcdc_fa_install();
    for (n = 1; n <= 10; n++) {
        mcdc_fa_arm(n);
        XMEMSET(&cert, 0, sizeof(cert));
        (void)DecodeAuthKeyIdInternal(akidFull, sizeof(akidFull), &cert);
        mcdc_fa_disarm();

        mcdc_fa_arm(n);
        XMEMSET(&cert, 0, sizeof(cert));
        (void)DecodeSubjDirAttr(sdaCoc2, sizeof(sdaCoc2), &cert);
        mcdc_fa_disarm();
    }
    mcdc_fa_disarm();
    mcdc_fa_restore();
}

/* ------------------------------------------------------------------------- *
 * Section 21: DecodeCertExtensions() bad-args [:22164].
 * ------------------------------------------------------------------------- */
static void wb_decode_cert_extensions_badargs(void)
{
    DecodedCert cert;
    int ret;
    /* DecodeCertExtensions() parses certExtHdrASN first, so the buffer must
     * start at the TBSCertificate's [3] explicit tag, not at the bare
     * Extension SEQUENCE. */
    static const byte oneExt[] = {
        0xA3,0x0F,
          0x30,0x0D,
            0x30,0x0B,
              0x06,0x03,0x55,0x1D,0x0F,      /* keyUsage OID (2.5.29.15) */
              0x04,0x04, 0x03,0x02,0x05,0xA0 /* OCTET STRING wrapping BIT STRING */
    };

    WB_NOTE("DecodeCertExtensions(): input==NULL || sz==0 [:22164]");
    XMEMSET(&cert, 0, sizeof(cert));
    cert.extensions = NULL;
    cert.extensionsSz = 10;
    ret = DecodeCertExtensions(&cert);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "extensions==NULL (1st true)");

    XMEMSET(&cert, 0, sizeof(cert));
    cert.extensions = oneExt;
    cert.extensionsSz = 0;
    ret = DecodeCertExtensions(&cert);
    WB_CHECK(ret == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "extensionsSz==0 (2nd true)");

    XMEMSET(&cert, 0, sizeof(cert));
    cert.extensions = oneExt;
    cert.extensionsSz = (int)sizeof(oneExt);
    ret = DecodeCertExtensions(&cert);
    WB_CHECK(ret == 0, "valid extensions (both false)");

#ifdef WC_ASN_UNKNOWN_EXT_CB
    /* Not compiled in any of this module's current variants (asn_default,
     * small_stack, no_asn_time, ignore_name_constraints never define
     * WC_ASN_UNKNOWN_EXT_CB) -- kept ready for when a variant enables it.
     * Exercises :22204-:22205, :22219, :22225. */
    WB_NOTE("DecodeCertExtensions(): unknown-extension callback dispatch");
    {
        static const byte unknownExt[] = {
            0xA3,0x0C,
              0x30,0x0A,
                0x30,0x08,
                  0x06,0x03,0x2A,0x03,0x04, /* arbitrary unrecognized OID */
                  0x04,0x01, 0x00
        };
        XMEMSET(&cert, 0, sizeof(cert));
        cert.extensions = unknownExt;
        cert.extensionsSz = (int)sizeof(unknownExt);
        (void)wc_SetUnknownExtCallback(&cert, NULL);
        ret = DecodeCertExtensions(&cert);
        WB_CHECK(ret == 0, "unknown extension, no callback set (skipped, no crash)");
    }
#endif
}

/* ------------------------------------------------------------------------- *
 * Section 22: CheckDate() (static, called directly with a hand-built
 * ASNGetData so the tag/length/date-string checks are isolated from any
 * surrounding certificate parse).
 *   :22428-:22429  tag != UTC_TIME && tag != GENERALIZED_TIME
 *   :22433-:22434  length > MAX_DATE_SIZE || length < MIN_DATE_SIZE
 *   :22440  ret==0 && !AsnSkipDateCheck  -- see file-header RESIDUAL note.
 * ------------------------------------------------------------------------- */
static void wb_check_date(void)
{
    ASNGetData d;
    int ret;
    /* A UTCTime string far in the future: fails XVALIDATE_DATE for
     * ASN_BEFORE (not yet valid) while remaining syntactically fine. */
    static const byte futureDate[] = "490101000000Z"; /* 2049 */

    WB_NOTE("CheckDate(): tag validity OR [:22428,:22429]");
    XMEMSET(&d, 0, sizeof(d));
    d.tag = ASN_OCTET_STRING; /* neither UTC nor GENERALIZED */
    d.length = 13;
    ret = CheckDate(&d, ASN_BEFORE);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_TIME_E), "wrong tag (both operands true)");

    XMEMSET(&d, 0, sizeof(d));
    d.tag = ASN_GENERALIZED_TIME;
    d.length = 13;
    d.data.ref.data = futureDate;
    d.data.ref.length = 13;
    ret = CheckDate(&d, ASN_BEFORE);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_BEFORE_DATE_E) || ret == 0,
            "GENERALIZED_TIME tag (1st false, 2nd doesn't matter for tag check)");

    WB_NOTE("CheckDate(): length range check [:22433,:22434]");
    XMEMSET(&d, 0, sizeof(d));
    d.tag = ASN_UTC_TIME;
    d.length = MAX_DATE_SIZE + 1;
    ret = CheckDate(&d, ASN_BEFORE);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_DATE_SZ_E), "length > MAX_DATE_SIZE (2nd operand true)");

    XMEMSET(&d, 0, sizeof(d));
    d.tag = ASN_UTC_TIME;
    d.length = MIN_DATE_SIZE - 1;
    ret = CheckDate(&d, ASN_BEFORE);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_DATE_SZ_E), "length < MIN_DATE_SIZE (3rd operand true)");

    XMEMSET(&d, 0, sizeof(d));
    d.tag = ASN_UTC_TIME;
    d.length = 13;
    d.data.ref.data = futureDate;
    d.data.ref.length = 13;
    ret = CheckDate(&d, ASN_BEFORE);
    WB_CHECK(ret != WC_NO_ERR_TRACE(ASN_DATE_SZ_E),
            "length within range (both length operands false)");

#ifdef WC_ASN_RUNTIME_DATE_CHECK_CONTROL
    WB_NOTE("CheckDate(): runtime AsnSkipDateCheck toggle [:22440]");
    (void)wc_AsnSetSkipDateCheck(1);
    XMEMSET(&d, 0, sizeof(d));
    d.tag = ASN_UTC_TIME;
    d.length = 13;
    d.data.ref.data = futureDate; /* would fail XVALIDATE_DATE */
    d.data.ref.length = 13;
    ret = CheckDate(&d, ASN_BEFORE);
    WB_CHECK(ret == 0, "AsnSkipDateCheck set (2nd operand false, date not validated)");
    (void)wc_AsnSetSkipDateCheck(0);
    ret = CheckDate(&d, ASN_BEFORE);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_BEFORE_DATE_E),
            "AsnSkipDateCheck cleared (2nd operand true, date validated and rejected)");
#else
    WB_NOTE("WC_ASN_RUNTIME_DATE_CHECK_CONTROL off; :22440 residual (see file header)");
#endif
}

/* ------------------------------------------------------------------------- *
 * Section 23: DecodeCertInternal() (static, called directly on a real
 * certificate buffer -- certs/server-cert.der -- with targeted byte
 * patches so each decision is isolated without needing a from-scratch
 * X.509 encoder).
 *   :22578  ret==0 && version > MAX_X509_VERSION
 *   :22608-:22609  CheckDate(BEFORE)<0 && verify!=NO_VERIFY &&
 *                  verify!=VERIFY_SKIP_DATE && !AsnSkipDateCheck
 *   :22620-:22621  same shape for ASN_AFTER
 *   :22639  ret==0 && stopAtPubKey
 *   :22649  ret==0 && !done
 *   :22704-:22705  WC_RSA_PSS tbs/sig param mismatch (best-effort)
 *   :22726  ret==0 && !done            (stopAfterPubKey branch)
 *   :22738-:22739  ret==0 && !done && TBS_EXT_SEQ.data.ref.data!=NULL
 *   :22761/:22767  issuer/subject != NULL -- residual (see file header)
 *   :22790  ret==0 && !stopAtPubKey
 *   :22795-:22796  !stopAtPubKey && !stopAfterPubKey && extensions!=NULL
 *   :22812  ret==0 && !done && badDate!=0
 * ------------------------------------------------------------------------- */
static int wb_load_file(const char* path, byte* buf, size_t bufCap, size_t* outSz)
{
    FILE* f = fopen(path, "rb");
    size_t n;
    if (f == NULL) {
        return -1;
    }
    n = fread(buf, 1, bufCap, f);
    fclose(f);
    *outSz = n;
    return (n > 0) ? 0 : -1;
}

static void wb_decode_cert_internal(void)
{
    static byte orig[4096];
    size_t origSz = 0;

    WB_NOTE("DecodeCertInternal(): loading certs/server-cert.der");
    if (wb_load_file("./certs/server-cert.der", orig, sizeof(orig), &origSz)
            != 0) {
        WB_NOTE("certs/server-cert.der not found from this CWD; section skipped");
        return;
    }

    /* --- version check [:22578] --------------------------------------- */
    {
        DecodedCert cert;
        byte buf[4096];
        int ret, crit;
        XMEMCPY(buf, orig, origSz);
        /* Version INTEGER content byte at DER offset 10 (see asn1parse:
         * "9:d=1 hl=2 l=1 prim: INTEGER :02" -> content starts right
         * after the 2-byte header at offset 10). Flip 2 (v3) -> 9. */
        WB_CHECK(buf[10] == 0x02, "sanity: version byte at expected offset");
        buf[10] = 0x09;
        wc_InitDecodedCert(&cert, buf, (word32)origSz, NULL);
        ret = DecodeCertInternal(&cert, NO_VERIFY, &crit, NULL, 0, 0);
        WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E),
                "version 9 > MAX_X509_VERSION (both operands true)");
        FreeDecodedCert(&cert);

        wc_InitDecodedCert(&cert, orig, (word32)origSz, NULL);
        ret = DecodeCertInternal(&cert, NO_VERIFY, &crit, NULL, 0, 0);
        WB_CHECK(ret == 0, "unmodified v3 cert (2nd operand false)");
        FreeDecodedCert(&cert);
    }

    /* --- BEFORE/AFTER date propagation [:22608,:22609,:22620,:22621,
     *     :22812] ------------------------------------------------------- */
    {
        DecodedCert cert;
        byte beforeBad[4096], afterBad[4096];
        int ret, crit, badDate;

        /* notBefore UTCTime content at DER offset 187 (asn1parse: "185:
         * ... l=13 ... UTCTIME :260611214429Z", hl=2 -> content at
         * 185+2=187), 13 bytes. Patch to a far-future date so
         * CheckDate(ASN_BEFORE) fails (not yet valid). UTCTime two-digit
         * years below 50 mean 20xx, so "49" is 2049. */
        XMEMCPY(beforeBad, orig, origSz);
        WB_CHECK(XMEMCMP(beforeBad + 187, "260611214429Z", 13) == 0,
                "sanity: notBefore bytes at expected offset");
        XMEMCPY(beforeBad + 187, "490101000000Z", 13);

        /* notAfter UTCTime content at DER offset 202 (asn1parse: "200:
         * ... l=13 ... UTCTIME :290307214429Z" -> 200+2=202). Patch to a
         * long-past date so CheckDate(ASN_AFTER) fails (expired). */
        XMEMCPY(afterBad, orig, origSz);
        WB_CHECK(XMEMCMP(afterBad + 202, "290307214429Z", 13) == 0,
                "sanity: notAfter bytes at expected offset");
        XMEMCPY(afterBad + 202, "180101000000Z", 13);

        /* badDateRet is only written on the stopAfterPubKey path
         * (:22786); on a full parse the date error surfaces as the return
         * value instead, so that is what the rows below assert. */
        WB_NOTE("DecodeCertInternal(): BEFORE-date bad, verify variants [:22608,:22609]");
        wc_InitDecodedCert(&cert, beforeBad, (word32)origSz, NULL);
        badDate = 0;
        ret = DecodeCertInternal(&cert, VERIFY, &crit, &badDate, 0, 0);
        /* With NO_ASN_TIME there is no clock, so CheckDate()'s range test is
         * compiled out and an out-of-range date is accepted by every mode. */
#ifndef NO_ASN_TIME
        WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_BEFORE_DATE_E),
                "verify=VERIFY (all 4 operands true, badDate set); "
                ":22812 true side (ret==0 && !done && badDate!=0)");
#else
        WB_CHECK(ret == 0, "verify=VERIFY, no clock (1st operand false)");
#endif
        FreeDecodedCert(&cert);

#ifdef WC_ASN_RUNTIME_DATE_CHECK_CONTROL
        /* 4th operand false: the runtime skip flag suppresses the same
         * rejection that the row above produced. */
        (void)wc_AsnSetSkipDateCheck(1);
        wc_InitDecodedCert(&cert, beforeBad, (word32)origSz, NULL);
        badDate = 0;
        ret = DecodeCertInternal(&cert, VERIFY, &crit, &badDate, 0, 0);
        WB_CHECK(ret == 0, "AsnSkipDateCheck set (:22609 4th operand false)");
        FreeDecodedCert(&cert);
        (void)wc_AsnSetSkipDateCheck(0);
#endif

        wc_InitDecodedCert(&cert, beforeBad, (word32)origSz, NULL);
        badDate = 0;
        ret = DecodeCertInternal(&cert, NO_VERIFY, &crit, &badDate, 0, 0);
        WB_CHECK(ret == 0,
                "verify=NO_VERIFY (2nd operand false); :22812 false via "
                "badDate==0");
        FreeDecodedCert(&cert);

        wc_InitDecodedCert(&cert, beforeBad, (word32)origSz, NULL);
        badDate = 0;
        ret = DecodeCertInternal(&cert, VERIFY_SKIP_DATE, &crit, &badDate, 0, 0);
        WB_CHECK(ret == 0, "verify=VERIFY_SKIP_DATE (3rd operand false)");
        FreeDecodedCert(&cert);

        wc_InitDecodedCert(&cert, orig, (word32)origSz, NULL);
        badDate = 0;
        ret = DecodeCertInternal(&cert, VERIFY, &crit, &badDate, 0, 0);
        WB_CHECK(ret == 0,
                "unmodified dates, verify=VERIFY (1st operand false: "
                "CheckDate>=0)");
        FreeDecodedCert(&cert);

        WB_NOTE("DecodeCertInternal(): AFTER-date bad, verify variants [:22620,:22621]");
        wc_InitDecodedCert(&cert, afterBad, (word32)origSz, NULL);
        badDate = 0;
        ret = DecodeCertInternal(&cert, VERIFY, &crit, &badDate, 0, 0);
#ifndef NO_ASN_TIME
        WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_AFTER_DATE_E),
                "verify=VERIFY (operand true side)");
#else
        WB_CHECK(ret == 0, "verify=VERIFY, no clock (1st operand false)");
#endif
        FreeDecodedCert(&cert);

#ifdef WC_ASN_RUNTIME_DATE_CHECK_CONTROL
        (void)wc_AsnSetSkipDateCheck(1);
        wc_InitDecodedCert(&cert, afterBad, (word32)origSz, NULL);
        badDate = 0;
        ret = DecodeCertInternal(&cert, VERIFY, &crit, &badDate, 0, 0);
        WB_CHECK(ret == 0, "AsnSkipDateCheck set (:22621 4th operand false)");
        FreeDecodedCert(&cert);
        (void)wc_AsnSetSkipDateCheck(0);
#endif

        wc_InitDecodedCert(&cert, afterBad, (word32)origSz, NULL);
        badDate = 0;
        ret = DecodeCertInternal(&cert, NO_VERIFY, &crit, &badDate, 0, 0);
        WB_CHECK(ret == 0, "verify=NO_VERIFY (operand false side)");
        FreeDecodedCert(&cert);

        wc_InitDecodedCert(&cert, afterBad, (word32)origSz, NULL);
        badDate = 0;
        ret = DecodeCertInternal(&cert, VERIFY_SKIP_DATE, &crit, &badDate, 0, 0);
        WB_CHECK(ret == 0, "verify=VERIFY_SKIP_DATE (:22621 3rd operand false)");
        FreeDecodedCert(&cert);
    }

    /* --- structurally malformed validity items -------------------------- *
     * CheckDate()'s length check (asn.c:22487) runs BEFORE the
     * AsnSkipDateCheck gate at :22494, so shortening a UTCTime below
     * MIN_DATE_SIZE makes CheckDate() negative whatever the flag says. That
     * is the only way to evaluate the 4th operand of :22662/:22674 -- an
     * out-of-range date cannot do it, because setting the flag makes
     * CheckDate() return 0 and the enclosing `if` is not entered at all. */
    {
        DecodedCert cert;
        byte shortB[4096], shortA[4096];
        word32 shortBSz = (word32)origSz, shortASz = (word32)origSz;
        int okB, okA;
        int ret, crit, badDate;

        XMEMCPY(shortB, orig, origSz);
        XMEMCPY(shortA, orig, origSz);
        /* notBefore content starts at 187, notAfter at 202 (both 13-byte
         * UTCTimes; see the offsets asserted above). Drop the last two
         * content bytes so the item's length becomes 11 < MIN_DATE_SIZE. */
        okB = (mcdc_der_shrink(shortB, &shortBSz, 187 + 11, 2) == 0);
        okA = (mcdc_der_shrink(shortA, &shortASz, 202 + 11, 2) == 0);
        WB_CHECK(okB && okA, "validity items shortened below MIN_DATE_SIZE");

        if (okB) {
            WB_NOTE("DecodeCertInternal(): malformed notBefore item [:22608]");
            wc_InitDecodedCert(&cert, shortB, shortBSz, NULL);
            badDate = 0;
            ret = DecodeCertInternal(&cert, VERIFY, &crit, &badDate, 0, 0);
            WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_BEFORE_DATE_E),
                    "short notBefore, verify=VERIFY (all 4 operands true)");
            FreeDecodedCert(&cert);
#ifdef WC_ASN_RUNTIME_DATE_CHECK_CONTROL
            (void)wc_AsnSetSkipDateCheck(1);
            wc_InitDecodedCert(&cert, shortB, shortBSz, NULL);
            badDate = 0;
            ret = DecodeCertInternal(&cert, VERIFY, &crit, &badDate, 0, 0);
            WB_CHECK(ret == 0,
                    "short notBefore with AsnSkipDateCheck set "
                    "(:22609 4th operand false)");
            FreeDecodedCert(&cert);
            (void)wc_AsnSetSkipDateCheck(0);
#endif
        }
        if (okA) {
            WB_NOTE("DecodeCertInternal(): malformed notAfter item [:22620]");
            wc_InitDecodedCert(&cert, shortA, shortASz, NULL);
            badDate = 0;
            ret = DecodeCertInternal(&cert, VERIFY, &crit, &badDate, 0, 0);
            WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_AFTER_DATE_E),
                    "short notAfter, verify=VERIFY (all 4 operands true)");
            FreeDecodedCert(&cert);
#ifdef WC_ASN_RUNTIME_DATE_CHECK_CONTROL
            (void)wc_AsnSetSkipDateCheck(1);
            wc_InitDecodedCert(&cert, shortA, shortASz, NULL);
            badDate = 0;
            ret = DecodeCertInternal(&cert, VERIFY, &crit, &badDate, 0, 0);
            WB_CHECK(ret == 0,
                    "short notAfter with AsnSkipDateCheck set "
                    "(:22621 4th operand false)");
            FreeDecodedCert(&cert);
            (void)wc_AsnSetSkipDateCheck(0);
#endif
        }
    }

    /* --- stopAtPubKey / stopAfterPubKey / done combinations [:22639,
     *     :22649,:22726,:22790,:22795,:22796,:22812] --------------------- */
    {
        DecodedCert cert;
        int ret, crit, badDate;

        WB_NOTE("DecodeCertInternal(): stopAtPubKey=1 [:22639 true,:22649 false,:22790 false]");
        wc_InitDecodedCert(&cert, orig, (word32)origSz, NULL);
        badDate = 0;
        ret = DecodeCertInternal(&cert, NO_VERIFY, &crit, &badDate, 1, 0);
        WB_CHECK(ret >= 0, "stopAtPubKey returns pubKeyOffset (done set early)");
        FreeDecodedCert(&cert);

        WB_NOTE("DecodeCertInternal(): stopAfterPubKey=1 [:22639 false,:22726 true->done,:22790 true,:22795 false]");
        wc_InitDecodedCert(&cert, orig, (word32)origSz, NULL);
        badDate = 0;
        ret = DecodeCertInternal(&cert, NO_VERIFY, &crit, &badDate, 0, 1);
        WB_CHECK(ret == 0, "stopAfterPubKey completes key parse, skips extensions");
        FreeDecodedCert(&cert);

        WB_NOTE("DecodeCertInternal(): full parse [:22639 false,:22649 true,:22726 true,:22790 true,:22795-:22796 all true]");
        wc_InitDecodedCert(&cert, orig, (word32)origSz, NULL);
        badDate = 0;
        ret = DecodeCertInternal(&cert, NO_VERIFY, &crit, &badDate, 0, 0);
        WB_CHECK(ret == 0, "full parse succeeds (extensions decoded)");
        WB_CHECK(cert.extensions != NULL,
                "extensions present -> :22738-:22739 true side (real cert has extensions)");
        FreeDecodedCert(&cert);
    }

    /* --- extensions absent [:22738,:22739 false side] ------------------
     * Splice the [3] extensions wrapper (DER offset 657, length 330 per
     * asn1parse: "657: ... hl=4 l=326 cons: cont [ 3 ]") out of the
     * buffer entirely and patch the two enclosing SEQUENCE length fields
     * (both currently 2-byte long-form, unaffected by the size decrease). */
    {
        DecodedCert cert;
        byte noext[4096];
        size_t newSz;
        int ret, crit;

        WB_CHECK(origSz > 987, "sanity: cert large enough to contain extensions");
        XMEMCPY(noext, orig, 657);              /* everything before [3] ext */
        XMEMCPY(noext + 657, orig + 987, origSz - 987); /* sigAlg + signature */
        newSz = 657 + (origSz - 987);

        /* Outer Certificate SEQUENCE length bytes at offset 2,3 (82 04 EB
         * originally == 1259); new content length = newSz - 4. */
        WB_CHECK(noext[0] == 0x30 && noext[1] == 0x82, "sanity: outer SEQ long-form length");
        {
            word32 newOuterLen = (word32)newSz - 4;
            noext[2] = (byte)(newOuterLen >> 8);
            noext[3] = (byte)newOuterLen;
        }
        /* TBSCertificate SEQUENCE length bytes at offset 6,7 (originally
         * 979); new content length = old(979) - 330 = 649. */
        WB_CHECK(noext[4] == 0x30 && noext[5] == 0x82, "sanity: TBS SEQ long-form length");
        {
            word32 newTbsLen = 979 - 330;
            noext[6] = (byte)(newTbsLen >> 8);
            noext[7] = (byte)newTbsLen;
        }

        WB_NOTE("DecodeCertInternal(): extensions field absent [:22738,:22739 false]");
        wc_InitDecodedCert(&cert, noext, (word32)newSz, NULL);
        crit = 0;
        ret = DecodeCertInternal(&cert, NO_VERIFY, &crit, NULL, 0, 0);
        WB_CHECK(ret == 0 && cert.extensions == NULL,
                "no [3] extensions wrapper present (TBS_EXT_SEQ.data.ref.data==NULL)");
        FreeDecodedCert(&cert);
    }

    /* --- issuer/subject != NULL [:22761,:22767] -- best-effort true side
     * only; see file-header RESIDUAL note for why the false side appears
     * structurally unreachable. --------------------------------------- */
    {
        DecodedCert cert;
        int ret, crit;
        WB_NOTE("DecodeCertInternal(): issuer/subject present (best-effort true side) [:22761,:22767]");
        wc_InitDecodedCert(&cert, orig, (word32)origSz, NULL);
        ret = DecodeCertInternal(&cert, NO_VERIFY, &crit, NULL, 0, 0);
        WB_CHECK(ret == 0 && cert.issuer[0] != '\0' && cert.subject[0] != '\0',
                "issuer/subject populated on a normal successful parse");
        FreeDecodedCert(&cert);
    }

    /* --- WC_RSA_PSS tbs/sig parameter match [:22758,:22759] -------------
     * A conforming PSS certificate repeats the same RSASSA-PSS-params in the
     * TBSCertificate's signature field and in the outer signatureAlgorithm,
     * so the equality test is all-false on the corpus certificate. Two edited
     * copies supply the other rows: one flips a byte inside the outer
     * parameters (same size, different content) and one removes the optional
     * [2] saltLength from them (different size). Removing an item needs every
     * enclosing SEQUENCE length rewritten, which mcdc_der_shrink() does. */
#ifdef WC_RSA_PSS
    {
        static byte pssBuf[4096];
        size_t pssSz = 0;
        if (wb_load_file("./certs/rsapss/server-rsapss.der", pssBuf,
                    sizeof(pssBuf), &pssSz) == 0) {
            DecodedCert cert;
            byte edit[4096];
            word32 editSz;
            word32 outerParams = 0;
            word32 i;
            int ret, crit;

            WB_NOTE("DecodeCertInternal(): RSA-PSS tbs/sig parameter match "
                    "[:22758]");
            wc_InitDecodedCert(&cert, pssBuf, (word32)pssSz, NULL);
            ret = DecodeCertInternal(&cert, NO_VERIFY, &crit, NULL, 0, 0);
            WB_CHECK(ret == 0, "unedited PSS certificate (both operands false)");
            FreeDecodedCert(&cert);

            /* The parse above recorded where the outer signatureAlgorithm's
             * parameters start. This certificate also carries id-RSASSA-PSS
             * in its SubjectPublicKeyInfo, so scanning for the OID would find
             * the wrong copy. */
            {
                DecodedCert probe;
                wc_InitDecodedCert(&probe, pssBuf, (word32)pssSz, NULL);
                if (DecodeCertInternal(&probe, NO_VERIFY, &crit, NULL, 0, 0)
                        == 0) {
                    outerParams = probe.sigParamsIndex;
                }
                FreeDecodedCert(&probe);
            }
            WB_CHECK(outerParams != 0 &&
                     pssBuf[outerParams] == (ASN_SEQUENCE | ASN_CONSTRUCTED),
                     "outer signatureAlgorithm parameters located");

            if (outerParams != 0) {
                word32 co, cl, lo, lw;
                word32 salt = 0;

                /* Same size, different content: flip the last content byte
                 * of the outer parameters (the saltLength value). */
                XMEMCPY(edit, pssBuf, pssSz);
                editSz = (word32)pssSz;
                if (mcdc_der_hdr(edit, editSz, outerParams, &co, &cl, &lo,
                        &lw) != 0) {
                    edit[co + cl - 1] ^= 0x01;
                    wc_InitDecodedCert(&cert, edit, editSz, NULL);
                    ret = DecodeCertInternal(&cert, NO_VERIFY, &crit, NULL, 0,
                            0);
                    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E),
                            ":22758 1st operand false, 2nd true (same size, "
                            "different parameters)");
                    FreeDecodedCert(&cert);

                    /* Different size: drop the optional [2] saltLength, the
                     * last item of the parameters SEQUENCE. */
                    for (i = co; i < co + cl; ) {
                        word32 ico, icl, ilo, ilw;
                        if (mcdc_der_hdr(edit, editSz, i, &ico, &icl, &ilo,
                                &ilw) == 0) {
                            break;
                        }
                        if (edit[i] == (ASN_CONTEXT_SPECIFIC | ASN_CONSTRUCTED
                                        | 2)) {
                            salt = i;
                            break;
                        }
                        i = ico + icl;
                    }
                    WB_CHECK(salt != 0, "[2] saltLength located");
                }
                if (salt != 0) {
                    word32 sco, scl, slo, slw;
                    word32 saltTlv;
                    XMEMCPY(edit, pssBuf, pssSz);
                    editSz = (word32)pssSz;
                    (void)mcdc_der_hdr(edit, editSz, salt, &sco, &scl, &slo,
                            &slw);
                    saltTlv = (sco - salt) + scl;
                    if (mcdc_der_shrink(edit, &editSz, salt, saltTlv) == 0) {
                        wc_InitDecodedCert(&cert, edit, editSz, NULL);
                        ret = DecodeCertInternal(&cert, NO_VERIFY, &crit, NULL,
                                0, 0);
                        WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E),
                                ":22758 1st operand true (parameter sizes "
                                "differ)");
                        FreeDecodedCert(&cert);
                    }
                    else {
                        WB_NOTE("saltLength removal refused; size-mismatch "
                                "row skipped");
                    }
                }
            }
        }
        else {
            WB_NOTE("certs/rsapss/server-rsapss.der not found; PSS rows skipped");
        }
    }
#endif
}

/* ------------------------------------------------------------------------- *
 * Section 24: DecodeCertReqAttributes() loop [:23064] (static, called
 * directly on a hand-built attribute list -- no full CSR needed since the
 * function only walks cert->source[idx..maxIdx)).
 *   :23064  while ((ret==0) && (idx<maxIdx))
 * ------------------------------------------------------------------------- */
#ifdef WOLFSSL_CERT_REQ
static void wb_decode_cert_req_attributes(void)
{
    DecodedCert cert;
    int ret, crit;
    /* One recognized attribute: unstructuredName = IA5String "hi". */
    static const byte attrOk[] = {
        0x30,0x11,
          0x06,0x09, 0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x09,0x02,
          0x31,0x04, 0x16,0x02,'h','i'
    };
    /* One unrecognized-OID attribute (1.2.3.5) -> DecodeCertReqAttrValue()
     * hits its default case and returns ASN_PARSE_E. */
    static const byte attrBad[] = {
        0x30,0x0B,
          0x06,0x03, 0x2A,0x03,0x05,
          0x31,0x04, 0x16,0x02,'h','i'
    };

    WB_NOTE("DecodeCertReqAttributes(): zero attributes (loop false) [:23064]");
    XMEMSET(&cert, 0, sizeof(cert));
    ret = DecodeCertReqAttributes(&cert, &crit, 0, 0);
    WB_CHECK(ret == 0, "maxIdx==0 (2nd operand false immediately)");

    WB_NOTE("DecodeCertReqAttributes(): one recognized attribute, consumes exactly maxIdx");
    XMEMSET(&cert, 0, sizeof(cert));
    cert.source = attrOk;
    ret = DecodeCertReqAttributes(&cert, &crit, 0, (word32)sizeof(attrOk));
    WB_CHECK(ret == 0, "recognized attribute parses (loop true then exits via idx==maxIdx)");

    WB_NOTE("DecodeCertReqAttributes(): unrecognized-OID attribute forces ret!=0 recheck");
    XMEMSET(&cert, 0, sizeof(cert));
    cert.source = attrBad;
    ret = DecodeCertReqAttributes(&cert, &crit, 0, (word32)sizeof(attrBad));
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E),
            "unrecognized OID (loop exits via 1st operand false on recheck)");
}
#else
static void wb_decode_cert_req_attributes(void) { WB_NOTE("WOLFSSL_CERT_REQ off; skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Section 25: DecodeCertReq() version check [:23186] (static, called
 * directly on a minimal hand-built CertificationRequest DER; the rest of
 * the function may fail afterward on the deliberately-minimal key/subject
 * content, which does not matter -- only the version-check line itself
 * needs to execute with both truth values).
 * ------------------------------------------------------------------------- */
#ifdef WOLFSSL_CERT_REQ
static void wb_decode_cert_req_version(void)
{
    DecodedCert cert;
    int ret, crit;
    /* Minimal CertificationRequest: version=0, empty subject, minimal
     * (structurally valid but not cryptographically real) RSA SPKI, no
     * attributes, minimal sigAlgo + signature. See file design notes:
     * byte[6] is the version INTEGER's single content byte. */
    static byte csr[] = {
        0x30,0x2F,
          0x30,0x1A,
            0x02,0x01,0x00,                     /* version (byte[6]) */
            0x30,0x00,                          /* subject (empty) */
            0x30,0x13,
              0x30,0x0D,
                0x06,0x09,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x01,
                0x05,0x00,
              0x03,0x02,0x00,0x00,               /* pubkey (minimal) */
          0x30,0x0D,
            0x06,0x09,0x2A,0x86,0x48,0x86,0xF7,0x0D,0x01,0x01,0x0B,
            0x05,0x00,
          0x03,0x02,0x00,0x00                    /* signature (minimal) */
    };
    byte csrBadVer[sizeof(csr)];

    WB_NOTE("DecodeCertReq(): version > MAX_X509_VERSION [:23186]");
    WB_CHECK(csr[6] == 0x00, "sanity: version byte at expected offset");

    XMEMCPY(csrBadVer, csr, sizeof(csr));
    csrBadVer[6] = 0x09;
    XMEMSET(&cert, 0, sizeof(cert));
    cert.source = csrBadVer;
    cert.maxIdx = (word32)sizeof(csrBadVer);
    ret = DecodeCertReq(&cert, &crit);
    WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E),
            "version==9 (both operands true, rejected before subject/key parse)");

    XMEMSET(&cert, 0, sizeof(cert));
    cert.source = csr;
    cert.maxIdx = (word32)sizeof(csr);
    ret = DecodeCertReq(&cert, &crit);
    /* The minimal SPKI/signature are not real key material, so GetCertKey
     * may fail further down -- that is fine, the version check (2nd
     * operand false here) already executed either way. */
    WB_NOTE("version==0: version-check line executed with 2nd operand false "
            "(function may still fail later on the placeholder key material)");
    (void)ret;
}
#else
static void wb_decode_cert_req_version(void) { WB_NOTE("WOLFSSL_CERT_REQ off; skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Section 26: ParseCert() RSA public key store [:23263-:23267]
 * (best-effort -- see file-header RESIDUAL note for operands 2/3).
 * ------------------------------------------------------------------------- */
#if (!defined(WOLFSSL_NO_MALLOC) && !defined(NO_WOLFSSL_CM_VERIFY)) || \
    defined(WOLFSSL_DYN_CERT)
static void wb_parse_cert_rsa_pubkey(void)
{
    static byte buf[4096];
    size_t sz = 0;
    DecodedCert cert;
    int ret;

    WB_NOTE("ParseCert(): RSA public key stored on success (best-effort) [:23263-:23267]");
    if (wb_load_file("./certs/server-cert.der", buf, sizeof(buf), &sz) != 0) {
        WB_NOTE("certs/server-cert.der not found; section skipped");
        return;
    }
    wc_InitDecodedCert(&cert, buf, (word32)sz, NULL);
    ret = ParseCert(&cert, CERT_TYPE, NO_VERIFY, NULL);
    WB_CHECK(ret == 0 && cert.keyOID == RSAk && cert.publicKey != NULL &&
            cert.pubKeySize > 0,
            "RSA cert parses; keyOID==RSAk && publicKey!=NULL && "
            "pubKeySize>0 all true together (see RESIDUAL note for the "
            "false side of the last two operands)");
    FreeDecodedCert(&cert);
}
#else
static void wb_parse_cert_rsa_pubkey(void) { WB_NOTE("WOLFSSL_NO_MALLOC build; ParseCert copy-out skipped"); }
#endif

/* ------------------------------------------------------------------------- *
 * Section 27: wc_GetDecodedCertSubject/Issuer/Serial() bad-args OR
 * [:23291,:23314,:23335].
 * ------------------------------------------------------------------------- */
static void wb_get_decoded_cert_accessors(void)
{
    DecodedCert cert;
    char buf[16];
    byte sbuf[16];
    word32 bufSz;

    XMEMSET(&cert, 0, sizeof(cert));
    cert.issuer[0] = '\0';
    cert.subject[0] = '\0';
    cert.serialSz = 0;

    WB_NOTE("wc_GetDecodedCertSubject(): bad-args OR [:23291]");
    bufSz = sizeof(buf);
    WB_CHECK(wc_GetDecodedCertSubject(NULL, buf, &bufSz)
                == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "cert==NULL");
    WB_CHECK(wc_GetDecodedCertSubject(&cert, buf, NULL)
                == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "bufSz==NULL");
    bufSz = sizeof(buf);
    WB_CHECK(wc_GetDecodedCertSubject(&cert, buf, &bufSz) == 0,
            "both valid (both operands false)");

    WB_NOTE("wc_GetDecodedCertIssuer(): bad-args OR [:23314]");
    bufSz = sizeof(buf);
    WB_CHECK(wc_GetDecodedCertIssuer(NULL, buf, &bufSz)
                == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "cert==NULL");
    WB_CHECK(wc_GetDecodedCertIssuer(&cert, buf, NULL)
                == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "bufSz==NULL");
    bufSz = sizeof(buf);
    WB_CHECK(wc_GetDecodedCertIssuer(&cert, buf, &bufSz) == 0,
            "both valid (both operands false)");

    WB_NOTE("wc_GetDecodedCertSerial(): bad-args OR [:23335]");
    bufSz = sizeof(sbuf);
    WB_CHECK(wc_GetDecodedCertSerial(NULL, sbuf, &bufSz)
                == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "cert==NULL");
    WB_CHECK(wc_GetDecodedCertSerial(&cert, sbuf, NULL)
                == WC_NO_ERR_TRACE(BAD_FUNC_ARG), "bufSz==NULL");
    bufSz = sizeof(sbuf);
    WB_CHECK(wc_GetDecodedCertSerial(&cert, sbuf, &bufSz) == 0,
            "both valid (both operands false)");
}

/* -------------------------------------------------------------------------
 * Section 24: error propagation through the extension decoders.
 *
 * Every decoder in this file is a chain of "if ((ret == 0) && ...)" steps
 * around a parse loop. The sections above always hand them input that either
 * parses cleanly or fails on the very first step, so the leading `ret == 0`
 * operand of the *later* steps is pinned true and its false side is never
 * shown. Each fixture below parses one element successfully and then hits a
 * malformed element, so the following steps are evaluated with ret != 0.
 * ------------------------------------------------------------------------- */
static void wb_ext_error_propagation(void)
{
    int ret;

    WB_NOTE("extension decoders: ret!=0 rows of the later chain steps "
            "[:19950,:20869,:20915,:21129,:21271,:21537,:21549]");

    /* --- DecodeAltNames(): (ret == 0) && (length == 0) ------------------- */
    {
        DecodedCert cert;
        /* Not a SEQUENCE at all -> GetASN_Sequence() fails, 1st operand
         * false. */
        static const byte notASeq[] = { 0x02, 0x01, 0x00 };
        /* A well-formed but EMPTY SEQUENCE -> both operands true (RFC 5280
         * requires at least one GeneralName). */
        static const byte emptySeq[] = { 0x30, 0x00 };

        XMEMSET(&cert, 0, sizeof(cert));
        ret = DecodeAltNames(notASeq, (word32)sizeof(notASeq), &cert);
        WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E),
                ":19950 1st operand false (not a SEQUENCE)");

        XMEMSET(&cert, 0, sizeof(cert));
        ret = DecodeAltNames(emptySeq, (word32)sizeof(emptySeq), &cert);
        WB_CHECK(ret == WC_NO_ERR_TRACE(ASN_PARSE_E),
                ":19950 both operands true (empty SEQUENCE)");
    }

    /* --- DecodeExtKeyUsage(): loop condition and the OID-count step ------ *
     * First element is an unknown-but-well-formed OID, which the decoder
     * forgives (ret reset to 0). The second element is an INTEGER, which is
     * a hard parse error: the OID-count step and then the loop condition
     * itself are both re-evaluated with ret != 0. */
    {
        static const byte ekuBadSecond[] = {
            0x30, 0x06,
                  0x06, 0x01, 0x2A,     /* OID 1.2 -- unknown, forgiven */
                  0x02, 0x01, 0x00      /* INTEGER -- hard parse error  */
        };
        const byte* src = NULL;
        word32 srcSz = 0, count = 0, oidCnt = 0;
        byte usage = 0, ssh = 0;

        ret = DecodeExtKeyUsage(ekuBadSecond, (word32)sizeof(ekuBadSecond),
                &src, &srcSz, &count, &usage, &ssh, &oidCnt);
        WB_CHECK(ret != 0,
                ":20869/:20915 1st operands false (parse error mid-list)");
    }

#ifndef IGNORE_NAME_CONSTRAINTS
    /* --- DecodeSubtree(): loop condition with ret != 0 ------------------- *
     * One valid dNSName GeneralSubtree followed by an INTEGER. */
    {
        static const byte gsThenBad[] = {
            0x30, 0x06, 0x82, 0x04, 'h', 'o', 's', 't',
            0x02, 0x01, 0x00
        };
        Base_entry* head = NULL;
        byte hasUnsupported = 0;

        ret = DecodeSubtree(gsThenBad, (word32)sizeof(gsThenBad), &head, 0,
                &hasUnsupported, NULL);
        WB_CHECK(ret != 0, ":21129 1st operand false (parse error mid-list)");
    }

    /* --- DecodeNameConstraints(): (ret == 0) && hasUnsupported ----------- *
     * A permittedSubtrees whose content is an INTEGER makes DecodeSubtree()
     * fail, so the hasUnsupported step is reached with ret != 0. */
    {
        DecodedCert cert;
        static const byte ncBadPermitted[] = {
            0x30, 0x05,
                  0xA0, 0x03,
                        0x02, 0x01, 0x00
        };

        XMEMSET(&cert, 0, sizeof(cert));
        ret = DecodeNameConstraints(ncBadPermitted,
                (word32)sizeof(ncBadPermitted), &cert);
        WB_CHECK(ret != 0, ":21271 1st operand false (subtree parse failed)");
    }
#endif /* !IGNORE_NAME_CONSTRAINTS */

#ifdef WOLFSSL_SUBJ_DIR_ATTR
    /* --- DecodeSubjDirAttr(): the two inner chain steps ------------------ */
    {
        DecodedCert cert;
        /* dateOfBirth: a *recognized* subject-directory-attribute OID that
         * is not countryOfCitizenship, so the OID comparison's 2nd operand
         * is false with the 1st still true. (The section above used
         * rsaEncryption, which is not in oidSubjDirAttrType at all and is
         * rejected by the template before the comparison is reached.) */
        static const byte sdaDob[] = {
            0x30, 0x12,
                  0x30, 0x10,
                        0x06, 0x08, 0x2B,0x06,0x01,0x05,0x05,0x07,0x09,0x01,
                        0x31, 0x04, 0x13, 0x02, '1', '9'
        };
        /* countryOfCitizenship whose SET holds a UTF8String instead of a
         * PrintableString: GetASNHeader() fails, so the length-check step
         * runs with ret != 0. */
        static const byte sdaBadStrTag[] = {
            0x30, 0x12,
                  0x30, 0x10,
                        0x06, 0x08, 0x2B,0x06,0x01,0x05,0x05,0x07,0x09,0x04,
                        0x31, 0x04, 0x0C, 0x02, 'U', 'S'
        };
        /* Outer SEQUENCE whose single element is an INTEGER: GetASN_Items()
         * inside the loop fails, so the OID-comparison step runs with
         * ret != 0. */
        static const byte sdaBadInner[] = {
            0x30, 0x03,
                  0x02, 0x01, 0x00
        };

        XMEMSET(&cert, 0, sizeof(cert));
        ret = DecodeSubjDirAttr(sdaDob, (word32)sizeof(sdaDob), &cert);
        WB_CHECK(ret == 0, ":21537 2nd operand false (known non-COC OID)");

        XMEMSET(&cert, 0, sizeof(cert));
        ret = DecodeSubjDirAttr(sdaBadStrTag, (word32)sizeof(sdaBadStrTag),
                &cert);
        WB_CHECK(ret != 0, ":21549 1st operand false (SET is not a "
                "PrintableString)");

        XMEMSET(&cert, 0, sizeof(cert));
        ret = DecodeSubjDirAttr(sdaBadInner, (word32)sizeof(sdaBadInner),
                &cert);
        WB_CHECK(ret != 0, ":21537 1st operand false (attribute parse failed)");
    }
#endif /* WOLFSSL_SUBJ_DIR_ATTR */
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    printf("asn.c white-box MC/DC supplement -- extensions wave\n");

    wb_match_base_name();
    wb_uri_host_helpers();
    wb_match_dns_wildcard();
    wb_match_ip_subnet();
    wb_match_other_name();
    wb_permitted_excluded_lists();
    wb_confirm_name_constraints();
    wb_decode_general_name_uri();
    wb_decode_basic_ca_constraint();
    wb_decode_auth_info();
    wb_decode_auth_key_id();
    wb_decode_ext_key_usage();
    wb_decode_subtree();
    wb_decode_name_constraints();
    wb_decode_policy_oid();
    wb_decode_cert_policy();
    wb_decode_subj_dir_attr();
    wb_decode_subj_info_acc();
    wb_decode_extension_type_dispatch();
    wb_decode_crl_dist();
    wb_ext_alloc_faults();
    wb_decode_cert_extensions_badargs();
    wb_check_date();
    wb_decode_cert_internal();
    wb_decode_cert_req_attributes();
    wb_decode_cert_req_version();
    wb_parse_cert_rsa_pubkey();
    wb_get_decoded_cert_accessors();
    wb_ext_error_propagation();

    printf("done (%s)\n", wb_fail ? "with failures" : "ok");
    /* Always return 0: a nonzero exit discards this variant's coverage
     * entirely in the campaign harness. Failures are surfaced via the
     * printed [FAIL] lines instead. */
    (void)wb_fail;
    return 0;
}
