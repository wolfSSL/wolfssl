/* test_srp.c
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

#include <tests/unit.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include <wolfssl/wolfcrypt/srp.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <tests/api/api.h>
#include <tests/api/test_srp.h>

#if defined(WOLFCRYPT_HAVE_SRP) && !defined(NO_SHA256)

/* RFC 5054-style 1024-bit test group: small enough to build under every
 * math backend/configuration while comfortably exceeding
 * SRP_MODULUS_MIN_BITS (512). Generator is 2, as in wolfcrypt/test/test.c's
 * srp_test_digest(). */
static const byte srpN[] = {
    0xEE, 0xAF, 0x0A, 0xB9, 0xAD, 0xB3, 0x8D, 0xD6,
    0x9C, 0x33, 0xF8, 0x0A, 0xFA, 0x8F, 0xC5, 0xE8,
    0x60, 0x72, 0x61, 0x87, 0x75, 0xFF, 0x3C, 0x0B,
    0x9E, 0xA2, 0x31, 0x4C, 0x9C, 0x25, 0x65, 0x76,
    0xD6, 0x74, 0xDF, 0x74, 0x96, 0xEA, 0x81, 0xD3,
    0x38, 0x3B, 0x48, 0x13, 0xD6, 0x92, 0xC6, 0xE0,
    0xE0, 0xD5, 0xD8, 0xE2, 0x50, 0xB9, 0x8B, 0xE4,
    0x8E, 0x49, 0x5C, 0x1D, 0x60, 0x89, 0xDA, 0xD1,
    0x5D, 0xC7, 0xD7, 0xB4, 0x61, 0x54, 0xD6, 0xB6,
    0xCE, 0x8E, 0xF4, 0xAD, 0x69, 0xB1, 0x5D, 0x49,
    0x82, 0x55, 0x9B, 0x29, 0x7B, 0xCF, 0x18, 0x85,
    0xC5, 0x29, 0xF5, 0x66, 0x66, 0x0E, 0x57, 0xEC,
    0x68, 0xED, 0xBC, 0x3C, 0x05, 0x72, 0x6C, 0xC0,
    0x2F, 0xD4, 0xCB, 0xF4, 0x97, 0x6E, 0xAA, 0x9A,
    0xFD, 0x51, 0x38, 0xFE, 0x83, 0x76, 0x43, 0x5B,
    0x9F, 0xC6, 0x1D, 0x2F, 0xC0, 0xEB, 0x06, 0xE3
};
static const byte srpG[] = { 0x02 };
static const byte srpSalt[] = {
    0xBE, 0xB2, 0x53, 0x79, 0xD1, 0xA8, 0x58, 0x1E,
    0xB5, 0xA7
};
static const byte srpUser[] = "user";
static const byte srpPass[] = "password";

#define SRP_N_SZ    ((word32)sizeof(srpN))
#define SRP_USER_SZ ((word32)4)
#define SRP_PASS_SZ ((word32)8)
#define SRP_SALT_SZ ((word32)sizeof(srpSalt))

#endif /* WOLFCRYPT_HAVE_SRP && !NO_SHA256 */

/*
 * MC/DC: argument/state-validation decisions in wolfcrypt/src/srp.c.
 *
 * wc_SrpInit()/wc_SrpInit_ex() (srp.c:214-293; wc_SrpInit() is a thin
 * wrapper that forwards to wc_SrpInit_ex(), so exercising it through
 * wc_SrpInit() covers the same decisions):
 *   srp.c:220-221  !srp -> BAD_FUNC_ARG
 *   srp.c:223-224  side != SRP_CLIENT_SIDE && side != SRP_SERVER_SIDE
 *                  -> BAD_FUNC_ARG
 *                  c0 = side != CLIENT, c1 = side != SERVER. Only 3 value
 *                  classes exist (CLIENT/SERVER/invalid); side=CLIENT
 *                  (c0=F,c1=T) vs side=invalid (c0=T,c1=T) isolates c0
 *                  (c1 held true); side=SERVER (c0=T,c1=F) vs side=invalid
 *                  isolates c1 (c0 held true).
 *   srp.c:226-257  switch(type) default -> BAD_FUNC_ARG
 *
 * wc_SrpTerm() (srp.c:300-322):
 *   srp.c:302      if (srp) -- NULL is a legitimate no-op.
 *
 * wc_SrpSetUsername() (srp.c:324-339):
 *   srp.c:326-327  !srp || !username -> BAD_FUNC_ARG
 *
 * wc_SrpSetParams() (srp.c:341-434):
 *   srp.c:353-354  !srp || !N || !g || !salt || (nSz < gSz) -> BAD_FUNC_ARG
 *   srp.c:356-357  !srp->user -> SRP_CALL_ORDER_E
 *   srp.c:359-361  hashSize < 0 -> return hashSize (ALGO_ID_E)
 *   srp.c:367-368  mp_count_bits(N) < SRP_MODULUS_MIN_BITS -> BAD_FUNC_ARG
 *   srp.c:374-375  mp_cmp(N, g) != MP_GT -> BAD_FUNC_ARG
 *   srp.c:378-383  if (srp->salt) -- re-set/free-then-realloc branch
 *   srp.c:364-365 and 371-372 (mp_read_unsigned_bin() != MP_OKAY ->
 *                  MP_READ_E for N and g) are NOT exercised: with a
 *                  properly-sized byte buffer this call effectively cannot
 *                  fail through the public API; forcing it needs a
 *                  build-specific oversized N/g tuned past the compiled
 *                  math backend's limit (SP_INT_BITS/FP_MAX_BITS), or a
 *                  whitebox mock of mp_read_unsigned_bin().
 *
 * wc_SrpSetPassword() (srp.c:436-474):
 *   srp.c:443-444  !srp || !password || side != CLIENT -> BAD_FUNC_ARG
 *   srp.c:446-447  !srp->salt -> SRP_CALL_ORDER_E
 *   srp.c:449-451  digestSz < 0 -> return digestSz (ALGO_ID_E)
 *
 * wc_SrpGetVerifier() (srp.c:476-505):
 *   srp.c:481-482  !srp || !verifier || !size || side != CLIENT
 *                  -> BAD_FUNC_ARG
 *   srp.c:484-485  mp_iszero(auth) == MP_YES -> SRP_CALL_ORDER_E
 *   srp.c:497      *size < verifier size -> BUFFER_E
 *
 * wc_SrpSetVerifier() (srp.c:507-513):
 *   srp.c:509      !srp || !verifier || side != SERVER -> BAD_FUNC_ARG
 *
 * wc_SrpSetPrivate() (srp.c:515-542):
 *   srp.c:520-521  !srp || !priv || !size -> BAD_FUNC_ARG
 *   srp.c:523-524  mp_iszero(auth) == MP_YES -> SRP_CALL_ORDER_E
 *   srp.c:536      mp_iszero(priv mod N) == MP_YES -> SRP_BAD_KEY_E
 *
 * wc_SrpGetPublic() (srp.c:561-647):
 *   srp.c:568-569  !srp || !pub || !size -> BAD_FUNC_ARG
 *   srp.c:571-573  hashSize < 0 -> return hashSize (ALGO_ID_E)
 *   srp.c:575-576  mp_iszero(auth) == MP_YES -> SRP_CALL_ORDER_E
 *   srp.c:579-580  *size < modulus size -> BUFFER_E
 *   srp.c:595/599  client-side vs server-side branch
 *   srp.c:616      server-side: mp_iszero(k-as-int) == MP_YES
 *                  -> SRP_BAD_KEY_E (forced by zeroing the public srp->k
 *                  field directly, then restored via a fresh
 *                  wc_SrpSetParams() call to exercise the false side)
 *
 * wc_SrpComputeKey() (srp.c:703-951):
 *   srp.c:727-728  !srp || !clientPubKey || clientPubKeySz==0 ||
 *                  !serverPubKey || serverPubKeySz==0 -> BAD_FUNC_ARG
 *   srp.c:756-758  mp_iszero(priv) == MP_YES -> SRP_CALL_ORDER_E
 *   srp.c:775-778  secretSz < clientPubKeySz || secretSz < serverPubKeySz
 *                  -> BAD_FUNC_ARG
 *   client-side (srp.c:814-849):
 *     srp.c:819-822  mp_iszero(k-as-int) == MP_YES -> SRP_BAD_KEY_E
 *     srp.c:829-832  mp_iszero(serverPubKey-as-int) == MP_YES
 *                    -> SRP_BAD_KEY_E
 *     srp.c:833-836  serverPubKey >= N -> SRP_BAD_KEY_E
 *   server-side (srp.c:850-886):
 *     srp.c:858-861  mp_iszero(clientPubKey-as-int) == MP_YES
 *                    -> SRP_BAD_KEY_E
 *     srp.c:862-865  clientPubKey >= N -> SRP_BAD_KEY_E
 *     srp.c:872-875 and 878-881 (temp2 <= 1, temp2 == N-1 -> SRP_BAD_KEY_E)
 *                  are NOT exercised: temp2 = A * v^u % N is a live modular
 *                  arithmetic result, so landing it on 0/1/N-1 needs a
 *                  clientPubKey solved against the concrete v/u/N values in
 *                  play, not a fixed byte pattern; a whitebox able to drive
 *                  the same modmath (or mock mp_mulmod/mp_exptmod) would be
 *                  needed to hit these two directly.
 *
 * wc_SrpGetProof() (srp.c:953-982):
 *   srp.c:958-959  !srp || !proof || !size -> BAD_FUNC_ARG
 *   srp.c:961-963  hashSize < 0 -> ALGO_ID_E
 *   srp.c:965-966  *size < hashSize -> BUFFER_E
 *   srp.c:968-970/975  client-side vs server-side branch
 *
 * wc_SrpVerifyPeersProof() (srp.c:984-1015):
 *   srp.c:990-991  !srp || !proof -> BAD_FUNC_ARG
 *   srp.c:993-995  hashSize < 0 -> ALGO_ID_E
 *   srp.c:997-998  size != hashSize || size > INT_MAX -> BUFFER_E
 *                  The second operand cannot be exercised independently:
 *                  whenever size == hashSize is false, hashSize is one of
 *                  the small fixed digest sizes, so "size > INT_MAX" can
 *                  never simultaneously be true in a way that changes the
 *                  outcome -- this half of the decision is structurally
 *                  masked through the public API, not merely untested.
 *   srp.c:1000-1001/1003  client-side vs server-side branch
 *   srp.c:1009     ConstantCompare(proof, digest) != 0 -> SRP_VERIFY_E
 *                  (the mismatch direction is covered here; the matching
 *                  direction is exercised, along with the full handshake,
 *                  in test_wc_Srp_FeatureCoverage())
 */
int test_wc_Srp_DecisionCoverage(void)
{
    EXPECT_DECLS;
#ifdef WOLFCRYPT_HAVE_SRP
#ifndef NO_SHA256
    Srp srp;

    XMEMSET(&srp, 0, sizeof(srp));

    /* --- wc_SrpInit() / wc_SrpInit_ex() --- */

    /* c0: !srp (srp.c:220-221) */
    ExpectIntEQ(wc_SrpInit(NULL, SRP_TYPE_SHA256, SRP_CLIENT_SIDE),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* side guard (srp.c:223-224): see the header comment above for the
     * 3-way (CLIENT/SERVER/invalid) independence-pair reasoning. */
    ExpectIntEQ(wc_SrpInit(&srp, SRP_TYPE_SHA256, SRP_CLIENT_SIDE), 0);
    wc_SrpTerm(&srp);
    ExpectIntEQ(wc_SrpInit(&srp, SRP_TYPE_SHA256, SRP_SERVER_SIDE), 0);
    wc_SrpTerm(&srp);
    ExpectIntEQ(wc_SrpInit(&srp, SRP_TYPE_SHA256, (SrpSide)99),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* type switch default (srp.c:255-256): SRP_TYPE_SHA256 above already
     * exercises a recognized case; an out-of-range type falls to
     * default. */
    ExpectIntEQ(wc_SrpInit(&srp, (SrpType)0, SRP_CLIENT_SIDE),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* --- wc_SrpTerm() --- */

    /* srp.c:302: NULL is a legitimate silent no-op. */
    wc_SrpTerm(NULL);
    ExpectIntEQ(wc_SrpInit(&srp, SRP_TYPE_SHA256, SRP_CLIENT_SIDE), 0);
    wc_SrpTerm(&srp); /* true branch: valid pointer, resources released. */

    /* --- wc_SrpSetUsername() --- */

    ExpectIntEQ(wc_SrpInit(&srp, SRP_TYPE_SHA256, SRP_CLIENT_SIDE), 0);

    /* c0: !srp (srp.c:326) */
    ExpectIntEQ(wc_SrpSetUsername(NULL, srpUser, SRP_USER_SZ),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* c1: !username, c0 false */
    ExpectIntEQ(wc_SrpSetUsername(&srp, NULL, SRP_USER_SZ),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* baseline: both valid -> success */
    ExpectIntEQ(wc_SrpSetUsername(&srp, srpUser, SRP_USER_SZ), 0);

    /* --- wc_SrpSetParams() --- */

    /* Top guard (srp.c:353-354): isolate each operand true individually
     * against the all-false baseline established further below. */
    ExpectIntEQ(wc_SrpSetParams(NULL, srpN, SRP_N_SZ, srpG,
        (word32)sizeof(srpG), srpSalt, SRP_SALT_SZ),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                         /* c0: !srp */
    ExpectIntEQ(wc_SrpSetParams(&srp, NULL, SRP_N_SZ, srpG,
        (word32)sizeof(srpG), srpSalt, SRP_SALT_SZ),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                         /* c1: !N */
    ExpectIntEQ(wc_SrpSetParams(&srp, srpN, SRP_N_SZ, NULL,
        (word32)sizeof(srpG), srpSalt, SRP_SALT_SZ),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                         /* c2: !g */
    ExpectIntEQ(wc_SrpSetParams(&srp, srpN, SRP_N_SZ, srpG,
        (word32)sizeof(srpG), NULL, SRP_SALT_SZ),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));                         /* c3: !salt */
    /* c4: nSz < gSz -- swap which buffer plays N vs g so nSz(1) < gSz(128)
     * while both pointers remain valid. */
    ExpectIntEQ(wc_SrpSetParams(&srp, srpG, (word32)sizeof(srpG), srpN,
        SRP_N_SZ, srpSalt, SRP_SALT_SZ), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* !srp->user -> SRP_CALL_ORDER_E (srp.c:356-357): top guard all
     * false, but SetUsername was never called on this fresh instance. */
    {
        Srp srpNoUser;

        XMEMSET(&srpNoUser, 0, sizeof(srpNoUser));
        ExpectIntEQ(wc_SrpInit(&srpNoUser, SRP_TYPE_SHA256,
            SRP_CLIENT_SIDE), 0);
        ExpectIntEQ(wc_SrpSetParams(&srpNoUser, srpN, SRP_N_SZ, srpG,
            (word32)sizeof(srpG), srpSalt, SRP_SALT_SZ),
            WC_NO_ERR_TRACE(SRP_CALL_ORDER_E));
        wc_SrpTerm(&srpNoUser);
    }

    /* hashSize < 0 -> ALGO_ID_E (srp.c:359-361): corrupt srp->type to an
     * unrecognized value right after SetUsername succeeds, so
     * SrpHashSize() falls to its default case. */
    srp.type = (SrpType)0;
    ExpectIntEQ(wc_SrpSetParams(&srp, srpN, SRP_N_SZ, srpG,
        (word32)sizeof(srpG), srpSalt, SRP_SALT_SZ),
        WC_NO_ERR_TRACE(ALGO_ID_E));
    srp.type = SRP_TYPE_SHA256;

    /* modulus-too-small -> BAD_FUNC_ARG (srp.c:367-368): N with far fewer
     * than SRP_MODULUS_MIN_BITS (512) bits. */
    ExpectIntEQ(wc_SrpSetParams(&srp, srpG, (word32)sizeof(srpG), srpG,
        (word32)sizeof(srpG), srpSalt, SRP_SALT_SZ),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* g >= N -> BAD_FUNC_ARG (srp.c:374-375): valid-size N, but g == N so
     * mp_cmp() yields MP_EQ, not MP_GT. */
    ExpectIntEQ(wc_SrpSetParams(&srp, srpN, SRP_N_SZ, srpN, SRP_N_SZ,
        srpSalt, SRP_SALT_SZ), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

    /* Baseline + salt re-set branch (srp.c:378-383): first call finds
     * srp->salt NULL (false branch, first allocation); the second call on
     * the same instance finds a previously-allocated salt (true branch,
     * freed then re-allocated). Both calls also complete the top guard,
     * call-order, hashSize, bits and cmp checks with every operand false,
     * establishing their all-false baseline. */
    ExpectIntEQ(wc_SrpSetParams(&srp, srpN, SRP_N_SZ, srpG,
        (word32)sizeof(srpG), srpSalt, SRP_SALT_SZ), 0);
    ExpectIntEQ(wc_SrpSetParams(&srp, srpN, SRP_N_SZ, srpG,
        (word32)sizeof(srpG), srpSalt, SRP_SALT_SZ), 0);

    wc_SrpTerm(&srp);

    /* --- wc_SrpSetPassword() --- */

    {
        Srp cli;
        Srp srv;

        XMEMSET(&cli, 0, sizeof(cli));
        XMEMSET(&srv, 0, sizeof(srv));

        /* c0: !srp (srp.c:443) */
        ExpectIntEQ(wc_SrpSetPassword(NULL, srpPass, SRP_PASS_SZ),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        ExpectIntEQ(wc_SrpInit(&cli, SRP_TYPE_SHA256, SRP_CLIENT_SIDE), 0);
        ExpectIntEQ(wc_SrpSetUsername(&cli, srpUser, SRP_USER_SZ), 0);

        /* c1: !password, c0/c2 false */
        ExpectIntEQ(wc_SrpSetPassword(&cli, NULL, SRP_PASS_SZ),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* c2: side != CLIENT, c0/c1 false (use a server-side instance;
         * this guard runs before any call-order check). */
        ExpectIntEQ(wc_SrpInit(&srv, SRP_TYPE_SHA256, SRP_SERVER_SIDE), 0);
        ExpectIntEQ(wc_SrpSetUsername(&srv, srpUser, SRP_USER_SZ), 0);
        ExpectIntEQ(wc_SrpSetPassword(&srv, srpPass, SRP_PASS_SZ),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* !srp->salt -> SRP_CALL_ORDER_E (srp.c:446-447): top guard all
         * false, but SetParams not yet called. */
        ExpectIntEQ(wc_SrpSetPassword(&cli, srpPass, SRP_PASS_SZ),
            WC_NO_ERR_TRACE(SRP_CALL_ORDER_E));

        ExpectIntEQ(wc_SrpSetParams(&cli, srpN, SRP_N_SZ, srpG,
            (word32)sizeof(srpG), srpSalt, SRP_SALT_SZ), 0);

        /* digestSz < 0 -> ALGO_ID_E (srp.c:449-451) */
        cli.type = (SrpType)0;
        ExpectIntEQ(wc_SrpSetPassword(&cli, srpPass, SRP_PASS_SZ),
            WC_NO_ERR_TRACE(ALGO_ID_E));
        cli.type = SRP_TYPE_SHA256;

        /* baseline: all guards false, salt set, valid type -> success. */
        ExpectIntEQ(wc_SrpSetPassword(&cli, srpPass, SRP_PASS_SZ), 0);

        wc_SrpTerm(&cli);
        wc_SrpTerm(&srv);
    }

    /* --- wc_SrpSetVerifier() --- */

    {
        Srp cli;
        Srp srv;

        XMEMSET(&cli, 0, sizeof(cli));
        XMEMSET(&srv, 0, sizeof(srv));

        ExpectIntEQ(wc_SrpInit(&cli, SRP_TYPE_SHA256, SRP_CLIENT_SIDE), 0);
        ExpectIntEQ(wc_SrpInit(&srv, SRP_TYPE_SHA256, SRP_SERVER_SIDE), 0);

        /* c0: !srp (srp.c:509) */
        ExpectIntEQ(wc_SrpSetVerifier(NULL, srpG, (word32)sizeof(srpG)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        /* c1: !verifier, c0/c2 false (server side) */
        ExpectIntEQ(wc_SrpSetVerifier(&srv, NULL, (word32)sizeof(srpG)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        /* c2: side != SERVER, c0/c1 false (client side) */
        ExpectIntEQ(wc_SrpSetVerifier(&cli, srpG, (word32)sizeof(srpG)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        /* baseline: all false -> success */
        ExpectIntEQ(wc_SrpSetVerifier(&srv, srpG, (word32)sizeof(srpG)), 0);

        wc_SrpTerm(&cli);
        wc_SrpTerm(&srv);
    }

    /* --- wc_SrpGetVerifier() --- */

    {
        Srp cli;
        Srp srv;
        byte verifier[SRP_N_SZ];
        word32 vSz;

        XMEMSET(&cli, 0, sizeof(cli));
        XMEMSET(&srv, 0, sizeof(srv));
        XMEMSET(verifier, 0, sizeof(verifier));

        ExpectIntEQ(wc_SrpInit(&cli, SRP_TYPE_SHA256, SRP_CLIENT_SIDE), 0);
        ExpectIntEQ(wc_SrpInit(&srv, SRP_TYPE_SHA256, SRP_SERVER_SIDE), 0);

        vSz = SRP_N_SZ;
        /* c0: !srp (srp.c:481) */
        ExpectIntEQ(wc_SrpGetVerifier(NULL, verifier, &vSz),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        /* c1: !verifier */
        ExpectIntEQ(wc_SrpGetVerifier(&cli, NULL, &vSz),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        /* c2: !size */
        ExpectIntEQ(wc_SrpGetVerifier(&cli, verifier, NULL),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        /* c3: side != CLIENT (server side) */
        vSz = SRP_N_SZ;
        ExpectIntEQ(wc_SrpGetVerifier(&srv, verifier, &vSz),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* auth == 0 -> SRP_CALL_ORDER_E (srp.c:484-485): client side,
         * before SetPassword. */
        vSz = SRP_N_SZ;
        ExpectIntEQ(wc_SrpGetVerifier(&cli, verifier, &vSz),
            WC_NO_ERR_TRACE(SRP_CALL_ORDER_E));

        ExpectIntEQ(wc_SrpSetUsername(&cli, srpUser, SRP_USER_SZ), 0);
        ExpectIntEQ(wc_SrpSetParams(&cli, srpN, SRP_N_SZ, srpG,
            (word32)sizeof(srpG), srpSalt, SRP_SALT_SZ), 0);
        ExpectIntEQ(wc_SrpSetPassword(&cli, srpPass, SRP_PASS_SZ), 0);

        /* buffer too small -> BUFFER_E (srp.c:497) */
        vSz = 1;
        ExpectIntEQ(wc_SrpGetVerifier(&cli, verifier, &vSz),
            WC_NO_ERR_TRACE(BUFFER_E));

        /* baseline: all guards false, buffer big enough -> success. */
        vSz = SRP_N_SZ;
        ExpectIntEQ(wc_SrpGetVerifier(&cli, verifier, &vSz), 0);

        wc_SrpTerm(&cli);
        wc_SrpTerm(&srv);
    }

    /* --- wc_SrpSetPrivate() --- */

    {
        Srp cli;
        byte privBuf[8];

        XMEMSET(&cli, 0, sizeof(cli));
        XMEMSET(privBuf, 0, sizeof(privBuf));
        privBuf[0] = 0x05;

        ExpectIntEQ(wc_SrpInit(&cli, SRP_TYPE_SHA256, SRP_CLIENT_SIDE), 0);

        /* c0: !srp (srp.c:520) */
        ExpectIntEQ(wc_SrpSetPrivate(NULL, privBuf, (word32)sizeof(privBuf)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        /* c1: !priv */
        ExpectIntEQ(wc_SrpSetPrivate(&cli, NULL, (word32)sizeof(privBuf)),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        /* c2: !size */
        ExpectIntEQ(wc_SrpSetPrivate(&cli, privBuf, 0),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* auth == 0 -> SRP_CALL_ORDER_E (srp.c:523-524): before
         * SetParams/SetPassword. */
        ExpectIntEQ(wc_SrpSetPrivate(&cli, privBuf, (word32)sizeof(privBuf)),
            WC_NO_ERR_TRACE(SRP_CALL_ORDER_E));

        ExpectIntEQ(wc_SrpSetUsername(&cli, srpUser, SRP_USER_SZ), 0);
        ExpectIntEQ(wc_SrpSetParams(&cli, srpN, SRP_N_SZ, srpG,
            (word32)sizeof(srpG), srpSalt, SRP_SALT_SZ), 0);
        ExpectIntEQ(wc_SrpSetPassword(&cli, srpPass, SRP_PASS_SZ), 0);

        /* priv mod N == 0 -> SRP_BAD_KEY_E (srp.c:536): pass N itself as
         * the private value so priv mod N == 0. */
        ExpectIntEQ(wc_SrpSetPrivate(&cli, srpN, SRP_N_SZ),
            WC_NO_ERR_TRACE(SRP_BAD_KEY_E));

        /* baseline: all guards false, priv mod N != 0 -> success. */
        ExpectIntEQ(wc_SrpSetPrivate(&cli, privBuf, (word32)sizeof(privBuf)),
            0);

        wc_SrpTerm(&cli);
    }

    /* --- wc_SrpGetPublic() --- */

    {
        Srp cli;
        Srp srv;
        byte pub[SRP_N_SZ];
        word32 pubSz;
        static const byte tinyVerifier[1] = { 0x07 };

        XMEMSET(&cli, 0, sizeof(cli));
        XMEMSET(&srv, 0, sizeof(srv));
        XMEMSET(pub, 0, sizeof(pub));

        ExpectIntEQ(wc_SrpInit(&cli, SRP_TYPE_SHA256, SRP_CLIENT_SIDE), 0);

        pubSz = SRP_N_SZ;
        /* c0: !srp (srp.c:568) */
        ExpectIntEQ(wc_SrpGetPublic(NULL, pub, &pubSz),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        /* c1: !pub */
        ExpectIntEQ(wc_SrpGetPublic(&cli, NULL, &pubSz),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        /* c2: !size */
        ExpectIntEQ(wc_SrpGetPublic(&cli, pub, NULL),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* hashSize < 0 -> ALGO_ID_E (srp.c:571-573) */
        cli.type = (SrpType)0;
        pubSz = SRP_N_SZ;
        ExpectIntEQ(wc_SrpGetPublic(&cli, pub, &pubSz),
            WC_NO_ERR_TRACE(ALGO_ID_E));
        cli.type = SRP_TYPE_SHA256;

        /* auth == 0 -> SRP_CALL_ORDER_E (srp.c:575-576): before
         * SetPassword. */
        pubSz = SRP_N_SZ;
        ExpectIntEQ(wc_SrpGetPublic(&cli, pub, &pubSz),
            WC_NO_ERR_TRACE(SRP_CALL_ORDER_E));

        ExpectIntEQ(wc_SrpSetUsername(&cli, srpUser, SRP_USER_SZ), 0);
        ExpectIntEQ(wc_SrpSetParams(&cli, srpN, SRP_N_SZ, srpG,
            (word32)sizeof(srpG), srpSalt, SRP_SALT_SZ), 0);
        ExpectIntEQ(wc_SrpSetPassword(&cli, srpPass, SRP_PASS_SZ), 0);

        /* buffer too small -> BUFFER_E (srp.c:579-580) */
        pubSz = 4;
        ExpectIntEQ(wc_SrpGetPublic(&cli, pub, &pubSz),
            WC_NO_ERR_TRACE(BUFFER_E));

        /* baseline: client-side branch (srp.c:595-596). */
        pubSz = SRP_N_SZ;
        ExpectIntEQ(wc_SrpGetPublic(&cli, pub, &pubSz), 0);
        wc_SrpTerm(&cli);

        /* server-side branch (srp.c:599-634) + k==0 bad-key path
         * (srp.c:616). */
        ExpectIntEQ(wc_SrpInit(&srv, SRP_TYPE_SHA256, SRP_SERVER_SIDE), 0);
        ExpectIntEQ(wc_SrpSetUsername(&srv, srpUser, SRP_USER_SZ), 0);
        ExpectIntEQ(wc_SrpSetParams(&srv, srpN, SRP_N_SZ, srpG,
            (word32)sizeof(srpG), srpSalt, SRP_SALT_SZ), 0);
        ExpectIntEQ(wc_SrpSetVerifier(&srv, tinyVerifier,
            (word32)sizeof(tinyVerifier)), 0);

        /* Directly zero the public srp->k field to force the
         * multiplier-as-zero bad-key branch. */
        XMEMSET(srv.k, 0, sizeof(srv.k));
        pubSz = SRP_N_SZ;
        ExpectIntEQ(wc_SrpGetPublic(&srv, pub, &pubSz),
            WC_NO_ERR_TRACE(SRP_BAD_KEY_E));

        /* Re-derive k (a fresh SetParams() recomputes k = H(N, g)) to
         * exercise the false direction of the same check. */
        ExpectIntEQ(wc_SrpSetParams(&srv, srpN, SRP_N_SZ, srpG,
            (word32)sizeof(srpG), srpSalt, SRP_SALT_SZ), 0);
        pubSz = SRP_N_SZ;
        ExpectIntEQ(wc_SrpGetPublic(&srv, pub, &pubSz), 0);

        wc_SrpTerm(&srv);
    }

    /* --- wc_SrpComputeKey() --- */

    {
        Srp cli;
        Srp srv;
        byte pubBuf[SRP_N_SZ];
        byte bigBuf[SRP_N_SZ + 8];
        byte nCopy[SRP_N_SZ];
        byte zeroByte[1] = { 0x00 };
        byte oneByte[1]  = { 0x01 };
        word32 pubSz;

        /* wc_SrpComputeKey() takes non-const byte* peer-key arguments
         * (it only reads them), so a mutable copy of srpN is needed
         * wherever N's bytes are reused as a bad-key test value. */
        XMEMCPY(nCopy, srpN, sizeof(nCopy));

        XMEMSET(&cli, 0, sizeof(cli));
        XMEMSET(&srv, 0, sizeof(srv));
        XMEMSET(pubBuf, 0, sizeof(pubBuf));
        XMEMSET(bigBuf, 0, sizeof(bigBuf));

        ExpectIntEQ(wc_SrpInit(&cli, SRP_TYPE_SHA256, SRP_CLIENT_SIDE), 0);

        /* Top guard (srp.c:727-728): isolate each operand true
         * individually. */
        ExpectIntEQ(wc_SrpComputeKey(NULL, oneByte, 1, oneByte, 1),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));                     /* c0: !srp */
        ExpectIntEQ(wc_SrpComputeKey(&cli, NULL, 1, oneByte, 1),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));           /* c1: !clientPubKey */
        ExpectIntEQ(wc_SrpComputeKey(&cli, oneByte, 0, oneByte, 1),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));       /* c2: clientPubKeySz==0 */
        ExpectIntEQ(wc_SrpComputeKey(&cli, oneByte, 1, NULL, 1),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));           /* c3: !serverPubKey */
        ExpectIntEQ(wc_SrpComputeKey(&cli, oneByte, 1, oneByte, 0),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));       /* c4: serverPubKeySz==0 */

        ExpectIntEQ(wc_SrpSetUsername(&cli, srpUser, SRP_USER_SZ), 0);
        ExpectIntEQ(wc_SrpSetParams(&cli, srpN, SRP_N_SZ, srpG,
            (word32)sizeof(srpG), srpSalt, SRP_SALT_SZ), 0);
        ExpectIntEQ(wc_SrpSetPassword(&cli, srpPass, SRP_PASS_SZ), 0);

        /* priv == 0 -> SRP_CALL_ORDER_E (srp.c:756-758): before
         * SetPrivate/GetPublic. */
        ExpectIntEQ(wc_SrpComputeKey(&cli, oneByte, 1, oneByte, 1),
            WC_NO_ERR_TRACE(SRP_CALL_ORDER_E));

        pubSz = SRP_N_SZ;
        ExpectIntEQ(wc_SrpGetPublic(&cli, pubBuf, &pubSz), 0);

        /* secretSz < clientPubKeySz / < serverPubKeySz (srp.c:775-778):
         * isolate each operand with an oversized peer buffer. */
        ExpectIntEQ(wc_SrpComputeKey(&cli, bigBuf, (word32)sizeof(bigBuf),
            oneByte, 1), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_SrpComputeKey(&cli, oneByte, 1, bigBuf,
            (word32)sizeof(bigBuf)), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* client-side bad-key branches: */

        /* temp1 (k) == 0 -> SRP_BAD_KEY_E (srp.c:819-822) */
        {
            byte savedK[SRP_MAX_DIGEST_SIZE];

            XMEMCPY(savedK, cli.k, sizeof(savedK));
            XMEMSET(cli.k, 0, sizeof(cli.k));
            ExpectIntEQ(wc_SrpComputeKey(&cli, pubBuf, pubSz, pubBuf, pubSz),
                WC_NO_ERR_TRACE(SRP_BAD_KEY_E));
            XMEMCPY(cli.k, savedK, sizeof(savedK));
        }

        /* serverPubKey == 0 -> SRP_BAD_KEY_E (srp.c:829-832) */
        ExpectIntEQ(wc_SrpComputeKey(&cli, pubBuf, pubSz, zeroByte, 1),
            WC_NO_ERR_TRACE(SRP_BAD_KEY_E));

        /* serverPubKey >= N -> SRP_BAD_KEY_E (srp.c:833-836) */
        ExpectIntEQ(wc_SrpComputeKey(&cli, pubBuf, pubSz, nCopy, SRP_N_SZ),
            WC_NO_ERR_TRACE(SRP_BAD_KEY_E));

        /* The false direction of all three client-side bad-key checks,
         * plus the true (all guards false) baseline of the top guard and
         * secretSz check, is exercised by the two-party handshake in
         * test_wc_Srp_FeatureCoverage() instead of repeating it here. */

        wc_SrpTerm(&cli);

        /* server-side bad-key branches: */

        ExpectIntEQ(wc_SrpInit(&srv, SRP_TYPE_SHA256, SRP_SERVER_SIDE), 0);
        ExpectIntEQ(wc_SrpSetUsername(&srv, srpUser, SRP_USER_SZ), 0);
        ExpectIntEQ(wc_SrpSetParams(&srv, srpN, SRP_N_SZ, srpG,
            (word32)sizeof(srpG), srpSalt, SRP_SALT_SZ), 0);
        ExpectIntEQ(wc_SrpSetVerifier(&srv, oneByte, 1), 0);
        pubSz = SRP_N_SZ;
        ExpectIntEQ(wc_SrpGetPublic(&srv, pubBuf, &pubSz), 0);

        /* s (clientPubKey) == 0 -> SRP_BAD_KEY_E (srp.c:858-861) */
        ExpectIntEQ(wc_SrpComputeKey(&srv, zeroByte, 1, pubBuf, pubSz),
            WC_NO_ERR_TRACE(SRP_BAD_KEY_E));

        /* s >= N -> SRP_BAD_KEY_E (srp.c:862-865) */
        ExpectIntEQ(wc_SrpComputeKey(&srv, nCopy, SRP_N_SZ, pubBuf, pubSz),
            WC_NO_ERR_TRACE(SRP_BAD_KEY_E));

        wc_SrpTerm(&srv);
    }

    /* --- wc_SrpGetProof() --- */

    {
        Srp cli;
        Srp srv;
        byte proof[SRP_MAX_DIGEST_SIZE];
        word32 proofSz;

        XMEMSET(&cli, 0, sizeof(cli));
        XMEMSET(&srv, 0, sizeof(srv));
        XMEMSET(proof, 0, sizeof(proof));

        ExpectIntEQ(wc_SrpInit(&cli, SRP_TYPE_SHA256, SRP_CLIENT_SIDE), 0);

        proofSz = SRP_MAX_DIGEST_SIZE;
        /* c0: !srp (srp.c:958) */
        ExpectIntEQ(wc_SrpGetProof(NULL, proof, &proofSz),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        /* c1: !proof */
        ExpectIntEQ(wc_SrpGetProof(&cli, NULL, &proofSz),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        /* c2: !size */
        ExpectIntEQ(wc_SrpGetProof(&cli, proof, NULL),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* hashSize < 0 -> ALGO_ID_E (srp.c:961-963) */
        cli.type = (SrpType)0;
        proofSz = SRP_MAX_DIGEST_SIZE;
        ExpectIntEQ(wc_SrpGetProof(&cli, proof, &proofSz),
            WC_NO_ERR_TRACE(ALGO_ID_E));
        cli.type = SRP_TYPE_SHA256;

        /* buffer too small -> BUFFER_E (srp.c:965-966) */
        proofSz = 1;
        ExpectIntEQ(wc_SrpGetProof(&cli, proof, &proofSz),
            WC_NO_ERR_TRACE(BUFFER_E));

        /* baseline + client-side branch (srp.c:968-970, 975). */
        proofSz = SRP_MAX_DIGEST_SIZE;
        ExpectIntEQ(wc_SrpGetProof(&cli, proof, &proofSz), 0);
        wc_SrpTerm(&cli);

        /* server-side branch: the "update server_proof" step under
         * "if (srp->side == SRP_CLIENT_SIDE)" (srp.c:975) is skipped. */
        ExpectIntEQ(wc_SrpInit(&srv, SRP_TYPE_SHA256, SRP_SERVER_SIDE), 0);
        proofSz = SRP_MAX_DIGEST_SIZE;
        ExpectIntEQ(wc_SrpGetProof(&srv, proof, &proofSz), 0);
        wc_SrpTerm(&srv);
    }

    /* --- wc_SrpVerifyPeersProof() --- */

    {
        Srp cli;
        byte proof[SRP_MAX_DIGEST_SIZE];

        XMEMSET(&cli, 0, sizeof(cli));
        XMEMSET(proof, 0, sizeof(proof));

        ExpectIntEQ(wc_SrpInit(&cli, SRP_TYPE_SHA256, SRP_CLIENT_SIDE), 0);

        /* c0: !srp (srp.c:990) */
        ExpectIntEQ(wc_SrpVerifyPeersProof(NULL, proof,
            WC_SHA256_DIGEST_SIZE), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        /* c1: !proof */
        ExpectIntEQ(wc_SrpVerifyPeersProof(&cli, NULL,
            WC_SHA256_DIGEST_SIZE), WC_NO_ERR_TRACE(BAD_FUNC_ARG));

        /* hashSize < 0 -> ALGO_ID_E (srp.c:993-995) */
        cli.type = (SrpType)0;
        ExpectIntEQ(wc_SrpVerifyPeersProof(&cli, proof,
            WC_SHA256_DIGEST_SIZE), WC_NO_ERR_TRACE(ALGO_ID_E));
        cli.type = SRP_TYPE_SHA256;

        /* size != hashSize -> BUFFER_E (srp.c:997-998). The second OR
         * operand (size > INT_MAX) is structurally masked here -- see the
         * header comment above. */
        ExpectIntEQ(wc_SrpVerifyPeersProof(&cli, proof,
            (word32)(WC_SHA256_DIGEST_SIZE - 1)),
            WC_NO_ERR_TRACE(BUFFER_E));

        /* baseline (size == hashSize) + ConstantCompare mismatch ->
         * SRP_VERIFY_E (srp.c:1009): a freshly Init'd client's
         * server_proof hash context has not been fed the expected
         * transcript, so any candidate proof legitimately fails
         * verification. The matching/verified direction is covered by
         * the full handshake in test_wc_Srp_FeatureCoverage(). */
        ExpectIntEQ(wc_SrpVerifyPeersProof(&cli, proof,
            WC_SHA256_DIGEST_SIZE), WC_NO_ERR_TRACE(SRP_VERIFY_E));

        wc_SrpTerm(&cli);
    }
#endif /* !NO_SHA256 */
#endif /* WOLFCRYPT_HAVE_SRP */
    return EXPECT_RESULT();
}

/*
 * Positive/feature coverage: a full client+server SRP-6a handshake using
 * SHA-256, modeled on wolfcrypt/test/test.c's srp_test_digest(). Both
 * sides use a fixed (non-random) private ephemeral value via
 * wc_SrpSetPrivate() so the exchange is deterministic:
 *   wc_SrpInit -> wc_SrpSetUsername -> wc_SrpSetParams ->
 *   wc_SrpSetPassword (client) / wc_SrpSetVerifier (server, fed by the
 *   client's wc_SrpGetVerifier) -> wc_SrpSetPrivate -> wc_SrpGetPublic
 *   (both sides) -> wc_SrpComputeKey (both sides) -> wc_SrpGetProof /
 *   wc_SrpVerifyPeersProof (both directions) -> wc_SrpTerm.
 * A second client instance then repeats the exchange and demonstrates that
 * a corrupted server proof is rejected with SRP_VERIFY_E, mirroring the
 * negative check at the end of srp_test_digest().
 */
int test_wc_Srp_FeatureCoverage(void)
{
    EXPECT_DECLS;
#ifdef WOLFCRYPT_HAVE_SRP
#ifndef NO_SHA256
    Srp cli;
    Srp srv;
    byte clientPubKey[SRP_N_SZ];
    byte serverPubKey[SRP_N_SZ];
    word32 clientPubKeySz;
    word32 serverPubKeySz;
    byte verifier[SRP_N_SZ];
    word32 verifierSz;
    byte clientProof[SRP_MAX_DIGEST_SIZE];
    byte serverProof[SRP_MAX_DIGEST_SIZE];
    word32 clientProofSz;
    word32 serverProofSz;
    static const byte clientPriv[] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01,
        0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x12
    };
    static const byte serverPriv[] = {
        0x21, 0x32, 0x43, 0x54, 0x65, 0x76, 0x87, 0x98,
        0xA9, 0xBA, 0xCB, 0xDC, 0xED, 0xFE, 0x0F, 0x1A,
        0x2B, 0x3C, 0x4D, 0x5E, 0x6F, 0x70, 0x81, 0x92,
        0xA3, 0xB4, 0xC5, 0xD6, 0xE7, 0xF8, 0x09, 0x1B
    };

    XMEMSET(&cli, 0, sizeof(cli));
    XMEMSET(&srv, 0, sizeof(srv));
    XMEMSET(clientPubKey, 0, sizeof(clientPubKey));
    XMEMSET(serverPubKey, 0, sizeof(serverPubKey));
    XMEMSET(verifier, 0, sizeof(verifier));
    XMEMSET(clientProof, 0, sizeof(clientProof));
    XMEMSET(serverProof, 0, sizeof(serverProof));

    /* Client knows username + password; derives the verifier to hand to
     * the server out-of-band. */
    ExpectIntEQ(wc_SrpInit(&cli, SRP_TYPE_SHA256, SRP_CLIENT_SIDE), 0);
    ExpectIntEQ(wc_SrpSetUsername(&cli, srpUser, SRP_USER_SZ), 0);
    ExpectIntEQ(wc_SrpSetParams(&cli, srpN, SRP_N_SZ, srpG,
        (word32)sizeof(srpG), srpSalt, SRP_SALT_SZ), 0);
    ExpectIntEQ(wc_SrpSetPassword(&cli, srpPass, SRP_PASS_SZ), 0);
    verifierSz = SRP_N_SZ;
    ExpectIntEQ(wc_SrpGetVerifier(&cli, verifier, &verifierSz), 0);

    /* Client sends its username to the server; the server already knows
     * N/g/salt and stores the verifier. */
    ExpectIntEQ(wc_SrpInit(&srv, SRP_TYPE_SHA256, SRP_SERVER_SIDE), 0);
    ExpectIntEQ(wc_SrpSetUsername(&srv, srpUser, SRP_USER_SZ), 0);
    ExpectIntEQ(wc_SrpSetParams(&srv, srpN, SRP_N_SZ, srpG,
        (word32)sizeof(srpG), srpSalt, SRP_SALT_SZ), 0);
    ExpectIntEQ(wc_SrpSetVerifier(&srv, verifier, verifierSz), 0);

    /* Both sides pin a fixed private ephemeral value for a deterministic
     * exchange, then derive their public ephemeral values. */
    ExpectIntEQ(wc_SrpSetPrivate(&cli, clientPriv,
        (word32)sizeof(clientPriv)), 0);
    ExpectIntEQ(wc_SrpSetPrivate(&srv, serverPriv,
        (word32)sizeof(serverPriv)), 0);

    clientPubKeySz = SRP_N_SZ;
    ExpectIntEQ(wc_SrpGetPublic(&cli, clientPubKey, &clientPubKeySz), 0);
    serverPubKeySz = SRP_N_SZ;
    ExpectIntEQ(wc_SrpGetPublic(&srv, serverPubKey, &serverPubKeySz), 0);

    /* Server sends N/g/salt/B to the client; client computes the shared
     * session key and its own proof. */
    clientProofSz = SRP_MAX_DIGEST_SIZE;
    ExpectIntEQ(wc_SrpComputeKey(&cli, clientPubKey, clientPubKeySz,
        serverPubKey, serverPubKeySz), 0);
    ExpectIntEQ(wc_SrpGetProof(&cli, clientProof, &clientProofSz), 0);

    /* Client sends A and M1 to the server; the server computes the same
     * session key, verifies the client's proof, and replies with its
     * own. */
    serverProofSz = SRP_MAX_DIGEST_SIZE;
    ExpectIntEQ(wc_SrpComputeKey(&srv, clientPubKey, clientPubKeySz,
        serverPubKey, serverPubKeySz), 0);
    ExpectIntEQ(wc_SrpVerifyPeersProof(&srv, clientProof, clientProofSz), 0);
    ExpectIntEQ(wc_SrpGetProof(&srv, serverProof, &serverProofSz), 0);

    /* Server sends M2 to the client; client verifies it. */
    ExpectIntEQ(wc_SrpVerifyPeersProof(&cli, serverProof, serverProofSz), 0);

    /* Negative check mirroring wolfcrypt/test/test.c's srp_test_digest():
     * a corrupted server proof must be rejected with SRP_VERIFY_E, on a
     * second client instance that repeats the same exchange against the
     * same server public key/private auth material. */
    {
        Srp cli2;
        byte clientPubKey2[SRP_N_SZ];
        word32 clientPubKey2Sz;
        byte clientProof2[SRP_MAX_DIGEST_SIZE];
        word32 clientProof2Sz;
        byte badServerProof[SRP_MAX_DIGEST_SIZE];

        XMEMSET(&cli2, 0, sizeof(cli2));
        XMEMSET(clientPubKey2, 0, sizeof(clientPubKey2));
        XMEMSET(clientProof2, 0, sizeof(clientProof2));
        XMEMCPY(badServerProof, serverProof, sizeof(badServerProof));
        badServerProof[0] = (byte)(badServerProof[0] ^ 0x01);

        ExpectIntEQ(wc_SrpInit(&cli2, SRP_TYPE_SHA256, SRP_CLIENT_SIDE), 0);
        ExpectIntEQ(wc_SrpSetUsername(&cli2, srpUser, SRP_USER_SZ), 0);
        ExpectIntEQ(wc_SrpSetParams(&cli2, srpN, SRP_N_SZ, srpG,
            (word32)sizeof(srpG), srpSalt, SRP_SALT_SZ), 0);
        ExpectIntEQ(wc_SrpSetPassword(&cli2, srpPass, SRP_PASS_SZ), 0);
        ExpectIntEQ(wc_SrpSetPrivate(&cli2, clientPriv,
            (word32)sizeof(clientPriv)), 0);
        clientPubKey2Sz = SRP_N_SZ;
        ExpectIntEQ(wc_SrpGetPublic(&cli2, clientPubKey2, &clientPubKey2Sz),
            0);
        ExpectIntEQ(wc_SrpComputeKey(&cli2, clientPubKey2, clientPubKey2Sz,
            serverPubKey, serverPubKeySz), 0);
        clientProof2Sz = SRP_MAX_DIGEST_SIZE;
        ExpectIntEQ(wc_SrpGetProof(&cli2, clientProof2, &clientProof2Sz), 0);
        ExpectIntEQ(wc_SrpVerifyPeersProof(&cli2, badServerProof,
            serverProofSz), WC_NO_ERR_TRACE(SRP_VERIFY_E));

        wc_SrpTerm(&cli2);
    }

    wc_SrpTerm(&cli);
    wc_SrpTerm(&srv);
#endif /* !NO_SHA256 */
#endif /* WOLFCRYPT_HAVE_SRP */
    return EXPECT_RESULT();
}
