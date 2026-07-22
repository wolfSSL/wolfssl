/* test_sakke.c
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

#include <wolfssl/wolfcrypt/sakke.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssl/wolfcrypt/types.h>
#include <tests/api/api.h>
#include <tests/api/test_sakke.h>

/*
 * MC/DC: argument/bounds/state-validation decisions in
 * wolfcrypt/src/sakke.c's public (WOLFSSL_API) functions. The library is
 * built with WOLFCRYPT_HAVE_SAKKE (not WOLFSSL_HAVE_SAKKE -- that name does
 * not exist in this codebase; sakke.c/sakke.h both gate on
 * WOLFCRYPT_HAVE_SAKKE).
 *
 * All functions below share the SAKKE parameter set 1 curve (ECC_SAKKE_1,
 * 128-byte prime), so: dp->size == 128, wc_ExportSakkeKey() == 384 bytes,
 * wc_ExportSakkePrivateKey() == 128 bytes, wc_ExportSakkePublicKey() == 256
 * (raw) / 257 (0x04-prefixed) bytes, wc_GetSakkeAuthSize()/
 * wc_MakeSakkeEncapsulatedSSV() authSz == 257, wc_GetSakkePointI() == 256
 * bytes, and the SSV size bound n == 128 bytes.
 *
 * Guards covered (operand order matches the source's left-to-right ||/&&):
 *
 * wc_InitSakkeKey_ex()  (sakke.c:119)   key == NULL
 * wc_FreeSakkeKey()     (sakke.c:193)   key != NULL
 * wc_MakeSakkeKey()     (sakke.c:507)   key == NULL || rng == NULL
 * wc_MakeSakkePublicKey (sakke.c:566)   key == NULL || pub == NULL
 * wc_ExportSakkeKey     (sakke.c:604,608,612)
 *     key == NULL || sz == NULL; data == NULL (LENGTH_ONLY_E);
 *     *sz < 3*size (BUFFER_E)
 * wc_ImportSakkeKey     (sakke.c:659,662)
 *     key == NULL || data == NULL; sz != size*3 (BUFFER_E)
 * wc_ExportSakkePrivateKey (sakke.c:713,717,721) -- same shape as
 *     wc_ExportSakkeKey with size instead of 3*size
 * wc_ImportSakkePrivateKey (sakke.c:756,760) -- same shape as
 *     wc_ImportSakkeKey with size instead of size*3
 * wc_ExportSakkePublicKey  (sakke.c:938,942)
 *     key == NULL || sz == NULL; data != NULL (drives sakke_z_from_mont())
 * wc_MakeSakkeRsk       (sakke.c:976)   key==NULL || id==NULL || rsk==NULL
 * wc_EncodeSakkeRsk     (sakke.c:1036)  key==NULL || rsk==NULL || sz==NULL
 * wc_ImportSakkePublicKey (sakke.c:1077,1089)
 *     key==NULL || data==NULL; !trusted (drives wc_ecc_check_key())
 * wc_DecodeSakkeRsk     (sakke.c:1119)  key==NULL||data==NULL||rsk==NULL
 * wc_ImportSakkeRsk     (sakke.c:1151)  key==NULL || data==NULL
 * wc_GenerateSakkeRskTable (sakke.c:1319/1400 -- WOLFSSL_HAVE_SP_ECC has a
 *     second, functionally-equivalent definition at the argument-validation
 *     level) key==NULL || rsk==NULL || len==NULL; table==NULL
 *     (LENGTH_ONLY_E); *len != 0 (BUFFER_E)
 * wc_SetSakkeRsk        (sakke.c:2350)  key==NULL || rsk==NULL
 * wc_ValidateSakkeRsk   (sakke.c:2430)
 *     key==NULL||id==NULL||rsk==NULL||valid==NULL
 * wc_GetSakkeAuthSize   (sakke.c:2491)  key==NULL || authSz==NULL
 * wc_SetSakkeIdentity   (sakke.c:6357)
 *     key==NULL || id==NULL || idSz > SAKKE_ID_MAX_SIZE
 * wc_MakeSakkePointI    (sakke.c:6388) -- same shape as
 *     wc_SetSakkeIdentity
 * wc_GetSakkePointI     (sakke.c:6428,6432,6436)
 *     key==NULL || sz==NULL; data==NULL (LENGTH_ONLY_E);
 *     *sz < size*2 (BUFFER_E)
 * wc_SetSakkePointI     (sakke.c:6478,6481)
 *     key==NULL||id==NULL||data==NULL;
 *     idSz > SAKKE_ID_MAX_SIZE || sz != size*2 (BUFFER_E)
 * wc_GenerateSakkePointITable (sakke.c:6527,6540,6544)
 *     key==NULL || len==NULL; table==NULL (LENGTH_ONLY_E);
 *     *len != 0 (BUFFER_E)
 * wc_SetSakkePointITable (sakke.c:6575,6590)
 *     key==NULL || table==NULL; len != 0 (BUFFER_E)
 * wc_ClearSakkePointITable (sakke.c:6616)  key == NULL
 * wc_MakeSakkeEncapsulatedSSV (sakke.c:6714,6717,6735,6738,6745)
 *     key==NULL||ssv==NULL||authSz==NULL||ssvSz==0;
 *     key->idSz == 0 (BAD_STATE_E); ssvSz > n; auth!=NULL && *authSz<outSz;
 *     auth == NULL (LENGTH_ONLY_E); hashType (drives wc_HashInit_ex() in
 *     sakke_calc_a(), called before the digest-size check in
 *     sakke_hash_to_range() -- see note below)
 * wc_GenerateSakkeSSV   (sakke.c:6820,6822,6831,6837)
 *     key==NULL||rng==NULL||ssvSz==NULL;
 *     ssv!=NULL && (*ssvSz==0 || *ssvSz>n); ssv==NULL (LENGTH_ONLY_E)
 * wc_DeriveSakkeSSV     (sakke.c:6897,6900,6911,6916)
 *     key==NULL||ssv==NULL||auth==NULL||ssvSz==0;
 *     !key->rsk.set || key->idSz==0 (BAD_STATE_E);
 *     authSz != 2*n+1; ssvSz > n; hashType (as above)
 *
 * NOTE on hashType: sakke_hash_to_range()'s own "digest size == 0" check
 * (sakke.c ~6282-6285, `else if (err == 0) err = BAD_FUNC_ARG;`) appears
 * structurally unreachable via any public entry point: wc_HashGetDigestSize()
 * (wolfcrypt/src/hash.c) never returns exactly 0 for any enum wc_HashType
 * value -- every case yields either a positive digest size or a negative
 * error code (HASH_TYPE_E/BAD_FUNC_ARG), and every caller of
 * sakke_hash_to_range() (wc_MakeSakkeEncapsulatedSSV(),
 * wc_DeriveSakkeSSV()) first calls sakke_calc_a(), which calls
 * wc_HashInit_ex() -- itself rejecting an invalid/unsupported hashType with
 * BAD_FUNC_ARG/HASH_TYPE_E before sakke_hash_to_range() is ever reached.
 * This is flagged for the DEATHNOTE rather than forced here; the tests below
 * instead drive the reachable hashType-invalid path through
 * wc_HashInit_ex(), which is the only way sakke.c's hashType parameter can
 * be shown to gate an error from the public API.
 */

/* MC/DC: NULL/bounds/state guards across every WOLFSSL_API function in
 * sakke.c. A single SakkeKey ("key") is initialized and driven through a
 * real key generation / RSK derivation / identity-setup sequence so that
 * later guards can be tested against both a NULL and a genuinely valid
 * key/rsk/point -- exercising the true (error) and false (proceeds to real
 * crypto) side of every decision, not just a mocked "valid-looking" input.
 * Where a decision has more than one operand, a fixed valid baseline is
 * toggled one operand at a time (the same construction used for
 * wc_SipHash's MC/DC tests in test_siphash.c): each toggle's result differs
 * from the baseline only because of the operand that changed, which is the
 * MC/DC independence-pair requirement.
 */
int test_wc_Sakke_DecisionCoverage(void)
{
    EXPECT_DECLS;
#ifdef WOLFCRYPT_HAVE_SAKKE
    WC_RNG rng;
    SakkeKey key;
    SakkeKey key2;
    ecc_point* pub = NULL;
    ecc_point* rsk = NULL;
    byte id[1] = { 0x00 };
    byte idMax[SAKKE_ID_MAX_SIZE];
    byte data[600];
    word32 sz;
    word32 len;
    byte auth[257];
    word16 authSz;
    byte ssv[128];
    word16 ssvSz;
    byte encSsv[16];
    int valid = 0;

    /* idMax is used only to exercise the idSz == SAKKE_ID_MAX_SIZE boundary
     * (byte *length*, not magnitude) -- keep it numerically small so the
     * real EC scalar multiply it drives (in wc_MakeSakkePointI()/
     * wc_SetSakkePointI()) isn't handed a full 1024-bit scalar. */
    XMEMSET(idMax, 0, sizeof(idMax));
    idMax[sizeof(idMax) - 1] = 0x5A;
    XMEMSET(data, 0, sizeof(data));
    XMEMSET(auth, 0, sizeof(auth));
    XMEMSET(ssv, 0, sizeof(ssv));

    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectNotNull(rsk = wc_ecc_new_point());
    ExpectNotNull(pub = wc_ecc_new_point());

    /* --- wc_InitSakkeKey_ex() / wc_InitSakkeKey() --- */
    ExpectIntEQ(wc_InitSakkeKey_ex(NULL, 128, ECC_SAKKE_1, NULL,
        INVALID_DEVID), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_InitSakkeKey(NULL, NULL, INVALID_DEVID),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Baseline valid init -- key is reused/re-initialized throughout. */
    ExpectIntEQ(wc_InitSakkeKey(&key, NULL, INVALID_DEVID), 0);

    /* --- wc_FreeSakkeKey() --- */
    wc_FreeSakkeKey(NULL);
    wc_FreeSakkeKey(&key);
    /* Re-init: key must be valid for every guard test below. */
    ExpectIntEQ(wc_InitSakkeKey_ex(&key, 128, ECC_SAKKE_1, NULL,
        INVALID_DEVID), 0);

    /* --- wc_MakeSakkeKey() --- */
    ExpectIntEQ(wc_MakeSakkeKey(NULL, &rng), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_MakeSakkeKey(&key, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Baseline: generates a real master secret + public key (Z). */
    ExpectIntEQ(wc_MakeSakkeKey(&key, &rng), 0);

    /* --- wc_MakeSakkePublicKey() --- */
    ExpectIntEQ(wc_MakeSakkePublicKey(NULL, pub),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_MakeSakkePublicKey(&key, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_MakeSakkePublicKey(&key, pub), 0);

    /* --- wc_MakeSakkeRsk() --- */
    ExpectIntEQ(wc_MakeSakkeRsk(NULL, id, 1, rsk),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_MakeSakkeRsk(&key, NULL, 1, rsk),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_MakeSakkeRsk(&key, id, 1, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_MakeSakkeRsk(&key, id, 1, rsk), 0);

    /* --- wc_ValidateSakkeRsk() --- */
    ExpectIntEQ(wc_ValidateSakkeRsk(NULL, id, 1, rsk, &valid),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ValidateSakkeRsk(&key, NULL, 1, rsk, &valid),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ValidateSakkeRsk(&key, id, 1, NULL, &valid),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ValidateSakkeRsk(&key, id, 1, rsk, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ValidateSakkeRsk(&key, id, 1, rsk, &valid), 0);
    ExpectIntEQ(valid, 1);

    /* --- wc_ExportSakkeKey() --- */
    sz = sizeof(data);
    ExpectIntEQ(wc_ExportSakkeKey(NULL, data, &sz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ExportSakkeKey(&key, data, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    sz = 0;
    /* data == NULL: length-only query. */
    ExpectIntEQ(wc_ExportSakkeKey(&key, NULL, &sz),
        WC_NO_ERR_TRACE(LENGTH_ONLY_E));
    ExpectIntEQ(sz, 384u);
    sz = 383; /* one byte short of 3*128 */
    ExpectIntEQ(wc_ExportSakkeKey(&key, data, &sz),
        WC_NO_ERR_TRACE(BUFFER_E));
    sz = sizeof(data);
    ExpectIntEQ(wc_ExportSakkeKey(&key, data, &sz), 0);
    ExpectIntEQ(sz, 384u);

    /* --- wc_ImportSakkeKey() --- */
    ExpectIntEQ(wc_ImportSakkeKey(NULL, data, sz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ImportSakkeKey(&key, NULL, sz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ImportSakkeKey(&key, data, sz - 1),
        WC_NO_ERR_TRACE(BUFFER_E));
    /* Round-trip: re-import the key's own just-exported bytes. */
    ExpectIntEQ(wc_ImportSakkeKey(&key, data, sz), 0);

    /* --- wc_ExportSakkePrivateKey() --- */
    sz = sizeof(data);
    ExpectIntEQ(wc_ExportSakkePrivateKey(NULL, data, &sz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ExportSakkePrivateKey(&key, data, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    sz = 0;
    ExpectIntEQ(wc_ExportSakkePrivateKey(&key, NULL, &sz),
        WC_NO_ERR_TRACE(LENGTH_ONLY_E));
    ExpectIntEQ(sz, 128u);
    sz = 127;
    ExpectIntEQ(wc_ExportSakkePrivateKey(&key, data, &sz),
        WC_NO_ERR_TRACE(BUFFER_E));
    sz = sizeof(data);
    ExpectIntEQ(wc_ExportSakkePrivateKey(&key, data, &sz), 0);
    ExpectIntEQ(sz, 128u);

    /* --- wc_ImportSakkePrivateKey() --- */
    ExpectIntEQ(wc_ImportSakkePrivateKey(NULL, data, sz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ImportSakkePrivateKey(&key, NULL, sz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ImportSakkePrivateKey(&key, data, sz - 1),
        WC_NO_ERR_TRACE(BUFFER_E));
    ExpectIntEQ(wc_ImportSakkePrivateKey(&key, data, sz), 0);

    /* --- wc_ExportSakkePublicKey() (raw and 0x04-prefixed) --- */
    ExpectIntEQ(wc_ExportSakkePublicKey(NULL, data, &sz, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ExportSakkePublicKey(&key, data, NULL, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    sz = 0;
    /* data == NULL: skips sakke_z_from_mont(), length-only query. */
    ExpectIntEQ(wc_ExportSakkePublicKey(&key, NULL, &sz, 1),
        WC_NO_ERR_TRACE(LENGTH_ONLY_E));
    ExpectIntEQ(sz, 256u);
    sz = 255;
    ExpectIntEQ(wc_ExportSakkePublicKey(&key, data, &sz, 1),
        WC_NO_ERR_TRACE(BUFFER_E));
    sz = sizeof(data);
    /* data != NULL: drives the sakke_z_from_mont() call. */
    ExpectIntEQ(wc_ExportSakkePublicKey(&key, data, &sz, 1), 0);
    ExpectIntEQ(sz, 256u);
    sz = 0;
    ExpectIntEQ(wc_ExportSakkePublicKey(&key, NULL, &sz, 0),
        WC_NO_ERR_TRACE(LENGTH_ONLY_E));
    ExpectIntEQ(sz, 257u);
    sz = 256;
    ExpectIntEQ(wc_ExportSakkePublicKey(&key, data, &sz, 0),
        WC_NO_ERR_TRACE(BUFFER_E));
    sz = sizeof(data);
    ExpectIntEQ(wc_ExportSakkePublicKey(&key, data, &sz, 0), 0);
    ExpectIntEQ(sz, 257u);

    /* --- wc_EncodeSakkeRsk() --- */
    sz = sizeof(data);
    ExpectIntEQ(wc_EncodeSakkeRsk(NULL, rsk, data, &sz, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_EncodeSakkeRsk(&key, NULL, data, &sz, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_EncodeSakkeRsk(&key, rsk, data, NULL, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_EncodeSakkeRsk(&key, rsk, data, &sz, 1), 0);
    ExpectIntEQ(sz, 256u);

    /* --- wc_DecodeSakkeRsk() --- */
    ExpectIntEQ(wc_DecodeSakkeRsk(NULL, data, sz, rsk),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DecodeSakkeRsk(&key, NULL, sz, rsk),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DecodeSakkeRsk(&key, data, sz, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Round-trip: rsk holds the same value it was encoded from above. */
    ExpectIntEQ(wc_DecodeSakkeRsk(&key, data, sz, rsk), 0);

    /* --- wc_ImportSakkeRsk() --- */
    ExpectIntEQ(wc_ImportSakkeRsk(NULL, data, sz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ImportSakkeRsk(&key, NULL, sz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Wrong size -- surfaces wc_DecodeSakkeRsk()'s own BUFFER_E. */
    ExpectIntEQ(wc_ImportSakkeRsk(&key, data, 1),
        WC_NO_ERR_TRACE(BUFFER_E));
    ExpectIntEQ(wc_ImportSakkeRsk(&key, data, sz), 0);

    /* --- wc_GenerateSakkeRskTable() --- */
    len = 0;
    ExpectIntEQ(wc_GenerateSakkeRskTable(NULL, rsk, data, &len),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_GenerateSakkeRskTable(&key, NULL, data, &len),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_GenerateSakkeRskTable(&key, rsk, data, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Length query (NULL table) returns LENGTH_ONLY_E and sets len to the
     * required table size. That size is SP-backend dependent: the small-stack
     * path builds no precomputation table and reports 0, while the full
     * precomputation path reports sizeof(sp_table_entry_1024) * 1167. Capture
     * it rather than asserting a fixed value. */
    len = 0;
    ExpectIntEQ(wc_GenerateSakkeRskTable(&key, rsk, NULL, &len),
        WC_NO_ERR_TRACE(LENGTH_ONLY_E));
    {
        word32 tableLen = len;

        /* A non-zero but too-small buffer length is rejected on both paths. */
        len = 1;
        ExpectIntEQ(wc_GenerateSakkeRskTable(&key, rsk, data, &len),
            WC_NO_ERR_TRACE(BUFFER_E));

        if (tableLen == 0) {
            /* Small-stack path: len == 0 is accepted as a no-op success. */
            len = 0;
            ExpectIntEQ(wc_GenerateSakkeRskTable(&key, rsk, data, &len), 0);
        }
        else {
            /* Full path: a correctly-sized heap buffer builds the table. */
            byte* table = (byte*)XMALLOC(tableLen, NULL,
                DYNAMIC_TYPE_TMP_BUFFER);
            ExpectNotNull(table);
            if (table != NULL) {
                len = tableLen;
                ExpectIntEQ(wc_GenerateSakkeRskTable(&key, rsk, table, &len),
                    0);
                XFREE(table, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            }
        }
    }

    /* --- wc_ImportSakkePublicKey() (trusted vs. untrusted) --- */
    sz = sizeof(data);
    ExpectIntEQ(wc_ExportSakkePublicKey(&key, data, &sz, 1), 0);
    ExpectIntEQ(wc_ImportSakkePublicKey(NULL, data, sz, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ImportSakkePublicKey(&key, NULL, sz, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* trusted == 1: skips wc_ecc_check_key(). */
    ExpectIntEQ(wc_ImportSakkePublicKey(&key, data, sz, 1), 0);
    /* trusted == 0: runs wc_ecc_check_key() on our own valid point. */
    ExpectIntEQ(wc_ImportSakkePublicKey(&key, data, sz, 0), 0);

    /* --- wc_GetSakkeAuthSize() --- */
    ExpectIntEQ(wc_GetSakkeAuthSize(NULL, &authSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_GetSakkeAuthSize(&key, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_GetSakkeAuthSize(&key, &authSz), 0);
    ExpectIntEQ(authSz, 257);

    /* --- wc_SetSakkeIdentity() --- */
    ExpectIntEQ(wc_SetSakkeIdentity(NULL, id, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SetSakkeIdentity(&key, NULL, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SetSakkeIdentity(&key, id, SAKKE_ID_MAX_SIZE + 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Boundary: idSz == SAKKE_ID_MAX_SIZE is valid (not > MAX). */
    ExpectIntEQ(wc_SetSakkeIdentity(&key, idMax, SAKKE_ID_MAX_SIZE), 0);
    /* Reset to the small identity used by the RSK computed above. */
    ExpectIntEQ(wc_SetSakkeIdentity(&key, id, 1), 0);

    /* --- wc_MakeSakkePointI() --- */
    ExpectIntEQ(wc_MakeSakkePointI(NULL, id, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_MakeSakkePointI(&key, NULL, 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_MakeSakkePointI(&key, id, SAKKE_ID_MAX_SIZE + 1),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_MakeSakkePointI(&key, idMax, SAKKE_ID_MAX_SIZE), 0);
    ExpectIntEQ(wc_MakeSakkePointI(&key, id, 1), 0);

    /* --- wc_GetSakkePointI() --- */
    ExpectIntEQ(wc_GetSakkePointI(NULL, data, &sz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_GetSakkePointI(&key, data, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    sz = 0;
    ExpectIntEQ(wc_GetSakkePointI(&key, NULL, &sz),
        WC_NO_ERR_TRACE(LENGTH_ONLY_E));
    ExpectIntEQ(sz, 256u);
    sz = 255;
    ExpectIntEQ(wc_GetSakkePointI(&key, data, &sz),
        WC_NO_ERR_TRACE(BUFFER_E));
    sz = sizeof(data);
    ExpectIntEQ(wc_GetSakkePointI(&key, data, &sz), 0);
    ExpectIntEQ(sz, 256u);

    /* --- wc_SetSakkePointI() --- */
    ExpectIntEQ(wc_SetSakkePointI(NULL, id, 1, data, sz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SetSakkePointI(&key, NULL, 1, data, sz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SetSakkePointI(&key, id, 1, NULL, sz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* idSz bound true, sz-mismatch false (isolates idSz operand). */
    ExpectIntEQ(wc_SetSakkePointI(&key, id, SAKKE_ID_MAX_SIZE + 1, data, sz),
        WC_NO_ERR_TRACE(BUFFER_E));
    /* idSz bound false, sz-mismatch true (isolates sz operand). */
    ExpectIntEQ(wc_SetSakkePointI(&key, id, 1, data, sz - 1),
        WC_NO_ERR_TRACE(BUFFER_E));
    /* Both false, idSz boundary at SAKKE_ID_MAX_SIZE: valid. */
    ExpectIntEQ(wc_SetSakkePointI(&key, idMax, SAKKE_ID_MAX_SIZE, data, sz),
        0);
    /* Both false, back to the small identity for the rest of the tests. */
    ExpectIntEQ(wc_SetSakkePointI(&key, id, 1, data, sz), 0);

    /* --- wc_GenerateSakkePointITable() / wc_SetSakkePointITable() --- */
    len = 0;
    ExpectIntEQ(wc_GenerateSakkePointITable(NULL, data, &len),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_GenerateSakkePointITable(&key, data, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Length query (NULL table) returns LENGTH_ONLY_E and sets len to the
     * required table size, which is SP-backend dependent: 0 on the small-stack
     * path (no precomputation table) and sizeof(sp_table_entry_1024)*256 on the
     * full path. Capture it rather than asserting a fixed value. */
    len = 0;
    ExpectIntEQ(wc_GenerateSakkePointITable(&key, NULL, &len),
        WC_NO_ERR_TRACE(LENGTH_ONLY_E));
    {
        word32 pointILen = len;

        /* A too-small buffer is rejected on both paths. */
        len = 1;
        ExpectIntEQ(wc_GenerateSakkePointITable(&key, data, &len),
            WC_NO_ERR_TRACE(BUFFER_E));
        ExpectIntEQ(wc_SetSakkePointITable(NULL, data, 1),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_SetSakkePointITable(&key, NULL, 1),
            WC_NO_ERR_TRACE(BAD_FUNC_ARG));
        ExpectIntEQ(wc_SetSakkePointITable(&key, data, 1),
            WC_NO_ERR_TRACE(BUFFER_E));

        if (pointILen == 0) {
            /* Small-stack path builds no table; len == 0 is a no-op success
             * for both generate and set. The full path's build-and-store is
             * exercised by the sakke_test KAT -- wc_SetSakkePointITable stores
             * the table pointer in the key, so it is deliberately not
             * built-and-freed here (that would leave the key dangling). */
            len = 0;
            ExpectIntEQ(wc_GenerateSakkePointITable(&key, data, &len), 0);
            ExpectIntEQ(wc_SetSakkePointITable(&key, data, 0), 0);
        }
    }

    /* --- wc_ClearSakkePointITable() --- */
    ExpectIntEQ(wc_ClearSakkePointITable(NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_ClearSakkePointITable(&key), 0);

    /* --- wc_SetSakkeRsk() --- */
    ExpectIntEQ(wc_SetSakkeRsk(NULL, rsk, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_SetSakkeRsk(&key, NULL, NULL, 0),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* rsk here still holds the RSK computed/round-tripped above, for the
     * identity ("id", 1 byte) installed via wc_SetSakkeIdentity() above. */
    ExpectIntEQ(wc_SetSakkeRsk(&key, rsk, NULL, 0), 0);

    /* --- wc_MakeSakkeEncapsulatedSSV() --- */
    ssvSz = 16;
    XMEMSET(ssv, 0x11, ssvSz);
    authSz = sizeof(auth);
    ExpectIntEQ(wc_MakeSakkeEncapsulatedSSV(NULL, WC_HASH_TYPE_SHA256, ssv,
        ssvSz, auth, &authSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_MakeSakkeEncapsulatedSSV(&key, WC_HASH_TYPE_SHA256, NULL,
        ssvSz, auth, &authSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_MakeSakkeEncapsulatedSSV(&key, WC_HASH_TYPE_SHA256, ssv,
        ssvSz, auth, NULL), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_MakeSakkeEncapsulatedSSV(&key, WC_HASH_TYPE_SHA256, ssv, 0,
        auth, &authSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* key->idSz == 0 (identity never set on a fresh key) -> BAD_STATE_E. */
    ExpectIntEQ(wc_InitSakkeKey(&key2, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_MakeSakkeEncapsulatedSSV(&key2, WC_HASH_TYPE_SHA256, ssv,
        ssvSz, auth, &authSz), WC_NO_ERR_TRACE(BAD_STATE_E));
    wc_FreeSakkeKey(&key2);
    XMEMSET(&key2, 0, sizeof(key2));
    /* ssvSz > n (n == 128 for this curve). */
    ExpectIntEQ(wc_MakeSakkeEncapsulatedSSV(&key, WC_HASH_TYPE_SHA256, ssv,
        129, auth, &authSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* auth != NULL && *authSz < outSz (257). */
    authSz = 256;
    ExpectIntEQ(wc_MakeSakkeEncapsulatedSSV(&key, WC_HASH_TYPE_SHA256, ssv,
        ssvSz, auth, &authSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* auth == NULL: length-only query. */
    authSz = 0;
    ExpectIntEQ(wc_MakeSakkeEncapsulatedSSV(&key, WC_HASH_TYPE_SHA256, ssv,
        ssvSz, NULL, &authSz), WC_NO_ERR_TRACE(LENGTH_ONLY_E));
    ExpectIntEQ(authSz, 257);
    /* Invalid hashType -- drives wc_HashInit_ex()'s own BAD_FUNC_ARG via
     * sakke_calc_a(); see the hashType note in the file header comment. */
    authSz = sizeof(auth);
    ExpectIntEQ(wc_MakeSakkeEncapsulatedSSV(&key, WC_HASH_TYPE_NONE, ssv,
        ssvSz, auth, &authSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Baseline success: encapsulate a known SSV for use by
     * wc_DeriveSakkeSSV() below. */
    authSz = sizeof(auth);
    ExpectIntEQ(wc_MakeSakkeEncapsulatedSSV(&key, WC_HASH_TYPE_SHA256, ssv,
        ssvSz, auth, &authSz), 0);
    ExpectIntEQ(authSz, 257);
    /* ssv now holds the *encrypted* SSV matching auth/authSz above. Save it
     * before the wc_GenerateSakkeSSV() calls below overwrite the shared
     * "ssv" buffer with unrelated random bytes -- wc_DeriveSakkeSSV()'s
     * baseline success call further down needs the saved, matching pair. */
    XMEMCPY(encSsv, ssv, sizeof(encSsv));

    /* --- wc_GenerateSakkeSSV() --- */
    ExpectIntEQ(wc_GenerateSakkeSSV(NULL, &rng, ssv, &ssvSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_GenerateSakkeSSV(&key, NULL, ssv, &ssvSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_GenerateSakkeSSV(&key, &rng, ssv, NULL),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* ssv != NULL, *ssvSz == 0 (isolates the "== 0" half of the OR). */
    ssvSz = 0;
    ExpectIntEQ(wc_GenerateSakkeSSV(&key, &rng, ssv, &ssvSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* ssv != NULL, *ssvSz > n (isolates the "> n" half of the OR). */
    ssvSz = 129;
    ExpectIntEQ(wc_GenerateSakkeSSV(&key, &rng, ssv, &ssvSz),
        WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* ssv == NULL: short-circuits the bounds check entirely, length-only
     * query. */
    ssvSz = 0;
    ExpectIntEQ(wc_GenerateSakkeSSV(&key, &rng, NULL, &ssvSz),
        WC_NO_ERR_TRACE(LENGTH_ONLY_E));
    ExpectIntEQ(ssvSz, 16);
    ExpectIntEQ(wc_GenerateSakkeSSV(&key, &rng, ssv, &ssvSz), 0);
    ExpectIntEQ(ssvSz, 16);

    /* --- wc_DeriveSakkeSSV() --- */
    /* Guard-only calls below either fail before touching their ssv buffer,
     * or (the final baseline) consume "encSsv" -- the encrypted SSV saved
     * above -- so a working copy is used throughout to leave "encSsv"
     * itself intact until the baseline call. */
    XMEMCPY(ssv, encSsv, sizeof(encSsv));
    ExpectIntEQ(wc_DeriveSakkeSSV(NULL, WC_HASH_TYPE_SHA256, ssv, 16, auth,
        authSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DeriveSakkeSSV(&key, WC_HASH_TYPE_SHA256, NULL, 16, auth,
        authSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DeriveSakkeSSV(&key, WC_HASH_TYPE_SHA256, ssv, 16, NULL,
        authSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    ExpectIntEQ(wc_DeriveSakkeSSV(&key, WC_HASH_TYPE_SHA256, ssv, 0, auth,
        authSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* !key->rsk.set (true) && key->idSz != 0 (identity set) -> BAD_STATE_E:
     * isolates the rsk.set operand. */
    ExpectIntEQ(wc_InitSakkeKey(&key2, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_SetSakkeIdentity(&key2, id, 1), 0);
    ExpectIntEQ(wc_DeriveSakkeSSV(&key2, WC_HASH_TYPE_SHA256, ssv, 16, auth,
        authSz), WC_NO_ERR_TRACE(BAD_STATE_E));
    wc_FreeSakkeKey(&key2);
    XMEMSET(&key2, 0, sizeof(key2));
    /* rsk.set (false, i.e. not set) && key->idSz == 0 (true) ->
     * BAD_STATE_E: isolates the idSz operand. */
    ExpectIntEQ(wc_InitSakkeKey(&key2, NULL, INVALID_DEVID), 0);
    ExpectIntEQ(wc_SetSakkeRsk(&key2, rsk, NULL, 0), 0);
    ExpectIntEQ(wc_DeriveSakkeSSV(&key2, WC_HASH_TYPE_SHA256, ssv, 16, auth,
        authSz), WC_NO_ERR_TRACE(BAD_STATE_E));
    wc_FreeSakkeKey(&key2);
    XMEMSET(&key2, 0, sizeof(key2));
    /* authSz != 2*n + 1 (257). */
    ExpectIntEQ(wc_DeriveSakkeSSV(&key, WC_HASH_TYPE_SHA256, ssv, 16, auth,
        256), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* authSz correct, ssvSz > n. */
    ExpectIntEQ(wc_DeriveSakkeSSV(&key, WC_HASH_TYPE_SHA256, ssv, 129, auth,
        authSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Invalid hashType, as for wc_MakeSakkeEncapsulatedSSV() above. */
    ExpectIntEQ(wc_DeriveSakkeSSV(&key, WC_HASH_TYPE_NONE, ssv, 16, auth,
        authSz), WC_NO_ERR_TRACE(BAD_FUNC_ARG));
    /* Baseline success: derive the SSV back out of the auth data made by
     * the wc_MakeSakkeEncapsulatedSSV() baseline call above; key still
     * holds the matching RSK/identity installed earlier. */
    ExpectIntEQ(wc_DeriveSakkeSSV(&key, WC_HASH_TYPE_SHA256, encSsv, 16,
        auth, authSz), 0);

    if (rsk != NULL) {
        wc_ecc_forcezero_point(rsk);
        wc_ecc_del_point(rsk);
    }
    if (pub != NULL) {
        wc_ecc_del_point(pub);
    }
    wc_FreeSakkeKey(&key);
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();
}

/*
 * Positive/feature coverage: a full SAKKE RFC 6508 KMS + client round trip
 * on SAKKE parameter set 1 -- wc_InitSakkeKey() -> wc_MakeSakkeKey() ->
 * wc_MakeSakkePublicKey() -> wc_MakeSakkeRsk() -> wc_ValidateSakkeRsk() ->
 * wc_SetSakkeIdentity() -> wc_GenerateSakkeSSV() and wc_MakeSakkePointI() ->
 * wc_MakeSakkeEncapsulatedSSV() -> wc_DeriveSakkeSSV() round trip ->
 * export/import of the full, private-only and public-only key encodings ->
 * wc_FreeSakkeKey(). Modeled on wolfcrypt/test/test.c's sakke_test().
 */
int test_wc_Sakke_FeatureCoverage(void)
{
    EXPECT_DECLS;
#ifdef WOLFCRYPT_HAVE_SAKKE
    WC_RNG rng;
    SakkeKey key;
    SakkeKey key2;
    ecc_point* pub = NULL;
    ecc_point* rsk = NULL;
    ecc_point* pub2 = NULL;
    char mail[] = "test@wolfssl.com";
    byte* id = (byte*)mail;
    word16 idSz = (word16)XSTRLEN(mail);
    int valid = 0;
    byte ssvOrig[16];
    byte ssv[16];
    word16 ssvSz = sizeof(ssv);
    byte auth[257];
    word16 authSz = sizeof(auth);
    byte fullKeyData[384];
    byte fullKeyData2[384];
    word32 fullKeySz = sizeof(fullKeyData);
    word32 fullKeySz2 = sizeof(fullKeyData2);
    byte privKeyData[128];
    word32 privKeySz = sizeof(privKeyData);
    byte pubKeyData[257];
    byte pubKeyData2[257];
    word32 pubKeySz = sizeof(pubKeyData);
    word32 pubKeySz2 = sizeof(pubKeyData2);
    int i;

    XMEMSET(&key, 0, sizeof(key));
    XMEMSET(&key2, 0, sizeof(key2));
    XMEMSET(ssvOrig, 0, sizeof(ssvOrig));
    XMEMSET(ssv, 0, sizeof(ssv));
    XMEMSET(auth, 0, sizeof(auth));

    for (i = 0; i < (int)sizeof(ssvOrig); i++) {
        ssvOrig[i] = (byte)(0xA0 + i);
    }
    XMEMCPY(ssv, ssvOrig, sizeof(ssvOrig));

    ExpectIntEQ(wc_InitRng(&rng), 0);
    ExpectNotNull(pub = wc_ecc_new_point());
    ExpectNotNull(rsk = wc_ecc_new_point());
    ExpectNotNull(pub2 = wc_ecc_new_point());

    /* KMS: initialize and generate the master secret + public key (Z). */
    ExpectIntEQ(wc_InitSakkeKey_ex(&key, 128, ECC_SAKKE_1, NULL,
        INVALID_DEVID), 0);
    ExpectIntEQ(wc_MakeSakkeKey(&key, &rng), 0);
    ExpectIntEQ(wc_MakeSakkePublicKey(&key, pub), 0);

    /* KMS: derive the Receiver Secret Key (RSK) for the identity and
     * validate it against that same identity. */
    ExpectIntEQ(wc_MakeSakkeRsk(&key, id, idSz, rsk), 0);
    ExpectIntEQ(wc_ValidateSakkeRsk(&key, id, idSz, rsk, &valid), 0);
    ExpectIntEQ(valid, 1);

    /* Client: install the identity and RSK to operate with, then prepare
     * state for encapsulation both ways -- a fresh random SSV and the
     * intermediate point I. */
    ExpectIntEQ(wc_SetSakkeIdentity(&key, id, idSz), 0);
    ExpectIntEQ(wc_SetSakkeRsk(&key, rsk, NULL, 0), 0);
    ExpectIntEQ(wc_GenerateSakkeSSV(&key, &rng, ssv, &ssvSz), 0);
    ExpectIntEQ(ssvSz, (word16)sizeof(ssvOrig));
    ExpectIntEQ(wc_MakeSakkePointI(&key, id, idSz), 0);

    /* Sender: encapsulate a known SSV (not the randomly-generated one
     * above) so the derived value below can be checked against it. */
    XMEMCPY(ssv, ssvOrig, sizeof(ssvOrig));
    ssvSz = sizeof(ssvOrig);
    authSz = sizeof(auth);
    ExpectIntEQ(wc_MakeSakkeEncapsulatedSSV(&key, WC_HASH_TYPE_SHA256, ssv,
        ssvSz, auth, &authSz), 0);
    ExpectIntEQ(authSz, 257);
    /* Encapsulation must transform the SSV in place. */
    ExpectIntNE(XMEMCMP(ssv, ssvOrig, sizeof(ssvOrig)), 0);

    /* Receiver: derive the SSV back out of the encapsulated data using the
     * RSK/identity installed above -- the full round trip. */
    ExpectIntEQ(wc_DeriveSakkeSSV(&key, WC_HASH_TYPE_SHA256, ssv, ssvSz,
        auth, authSz), 0);
    ExpectBufEQ(ssv, ssvOrig, sizeof(ssvOrig));

    /* Export/import the full (private + public) key encoding and confirm
     * the round trip reproduces the same bytes. */
    ExpectIntEQ(wc_ExportSakkeKey(&key, fullKeyData, &fullKeySz), 0);
    ExpectIntEQ(fullKeySz, sizeof(fullKeyData));
    ExpectIntEQ(wc_InitSakkeKey_ex(&key2, 128, ECC_SAKKE_1, NULL,
        INVALID_DEVID), 0);
    ExpectIntEQ(wc_ImportSakkeKey(&key2, fullKeyData, fullKeySz), 0);
    ExpectIntEQ(wc_ExportSakkeKey(&key2, fullKeyData2, &fullKeySz2), 0);
    ExpectBufEQ(fullKeyData2, fullKeyData, sizeof(fullKeyData));
    wc_FreeSakkeKey(&key2);
    XMEMSET(&key2, 0, sizeof(key2));

    /* Export/import the private key alone, then recompute the public key
     * from it and confirm it matches the original public key. Note that
     * wc_MakeSakkePublicKey() writes the derived public key to its output
     * point argument (pub2), not into key2's internal ecc.pubkey, so compare
     * the derived point pub2 against the original public point pub (both are
     * [z]P for the same master secret z) rather than exporting key2's pubkey. */
    ExpectIntEQ(wc_ExportSakkePrivateKey(&key, privKeyData, &privKeySz), 0);
    ExpectIntEQ(privKeySz, sizeof(privKeyData));
    ExpectIntEQ(wc_InitSakkeKey_ex(&key2, 128, ECC_SAKKE_1, NULL,
        INVALID_DEVID), 0);
    ExpectIntEQ(wc_ImportSakkePrivateKey(&key2, privKeyData, privKeySz), 0);
    /* Round-trip the imported private key to confirm import fidelity (private
     * key bytes are canonical), then derive the public key from it to exercise
     * wc_MakeSakkePublicKey() on an import-only key. (fullKeyData2 is reused
     * here as scratch; it was already validated in the full-key block above.) */
    fullKeySz2 = sizeof(fullKeyData2);
    ExpectIntEQ(wc_ExportSakkePrivateKey(&key2, fullKeyData2, &fullKeySz2), 0);
    ExpectIntEQ(fullKeySz2, privKeySz);
    ExpectBufEQ(fullKeyData2, privKeyData, privKeySz);
    ExpectIntEQ(wc_MakeSakkePublicKey(&key2, pub2), 0);
    wc_FreeSakkeKey(&key2);
    XMEMSET(&key2, 0, sizeof(key2));

    /* Export/import the public key (KMS public key Z_T) alone, both raw
     * and 0x04-prefixed encodings, and confirm each imports and re-exports
     * to the same bytes. */
    pubKeySz = sizeof(pubKeyData);
    ExpectIntEQ(wc_ExportSakkePublicKey(&key, pubKeyData, &pubKeySz, 1), 0);
    ExpectIntEQ(pubKeySz, 256u);
    ExpectIntEQ(wc_InitSakkeKey_ex(&key2, 128, ECC_SAKKE_1, NULL,
        INVALID_DEVID), 0);
    ExpectIntEQ(wc_ImportSakkePublicKey(&key2, pubKeyData, pubKeySz, 0), 0);
    pubKeySz2 = sizeof(pubKeyData2);
    ExpectIntEQ(wc_ExportSakkePublicKey(&key2, pubKeyData2, &pubKeySz2, 1),
        0);
    ExpectIntEQ(pubKeySz2, pubKeySz);
    ExpectBufEQ(pubKeyData2, pubKeyData, pubKeySz);
    wc_FreeSakkeKey(&key2);
    XMEMSET(&key2, 0, sizeof(key2));

    pubKeySz = sizeof(pubKeyData);
    ExpectIntEQ(wc_ExportSakkePublicKey(&key, pubKeyData, &pubKeySz, 0), 0);
    ExpectIntEQ(pubKeySz, 257u);
    ExpectIntEQ(pubKeyData[0], 0x04);
    ExpectIntEQ(wc_InitSakkeKey_ex(&key2, 128, ECC_SAKKE_1, NULL,
        INVALID_DEVID), 0);
    ExpectIntEQ(wc_ImportSakkePublicKey(&key2, pubKeyData, pubKeySz, 0), 0);
    pubKeySz2 = sizeof(pubKeyData2);
    ExpectIntEQ(wc_ExportSakkePublicKey(&key2, pubKeyData2, &pubKeySz2, 0),
        0);
    ExpectIntEQ(pubKeySz2, pubKeySz);
    ExpectBufEQ(pubKeyData2, pubKeyData, pubKeySz);
    wc_FreeSakkeKey(&key2);
    XMEMSET(&key2, 0, sizeof(key2));

    if (rsk != NULL) {
        wc_ecc_forcezero_point(rsk);
        wc_ecc_del_point(rsk);
    }
    if (pub != NULL) {
        wc_ecc_del_point(pub);
    }
    if (pub2 != NULL) {
        wc_ecc_del_point(pub2);
    }
    wc_FreeSakkeKey(&key);
    DoExpectIntEQ(wc_FreeRng(&rng), 0);
#endif
    return EXPECT_RESULT();
}
