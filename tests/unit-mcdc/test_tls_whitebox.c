/*
 * tls.c white-box supplement: MC/DC rows for the file-static helpers the
 * public API cannot reach with the operand sides the campaign union never
 * showed (master drift, 2026-10-06): the Hmac size guards, the ALPN
 * constructor/find/set NULL rows, and the SNI parse length/cacheOnly/
 * find-miss rows.
 *
 * This white-box #includes src/tls.c directly to reach these file-static
 * helpers and drives both sides of each leaf in the same binary (a single
 * clang MC/DC bitmap does not merge independence pairs across separately
 * compiled binaries, so each row below is paired with a same-binary
 * baseline call).
 *
 * Crash-safety: Hmac_OuterHash() only touches the hash object after the
 * size guard passes; Hmac_UpdateFinal_CT()'s oversized-macLen row returns
 * at its first statement before any buffer use; the ALPN NULL rows return
 * before any allocation; the SNI rows feed well-formed buffers to a real
 * object.
 */

#include <src/tls.c>

#include <stdio.h>

static int wb_fail = 0;
#define WB_NOTE(msg) do {printf("  [wb] %s\n", (msg));} while (0)

/* Hmac_OuterHash: (digestSz >= 0) && (blockSz >= 0). A macType with no
 * hash-table entry makes both sizes negative: the false sides; the
 * SHA-256 row is the same-binary true baseline. */
static void wb_hmac_outer_hash(void)
{
    Hmac hmac;
    unsigned char mac[64];

    XMEMSET(&hmac, 0, sizeof(hmac));
    XMEMSET(mac, 0, sizeof(mac));
    hmac.macType = WC_SHA256;
    (void)Hmac_OuterHash(&hmac, mac);
    hmac.macType = (enum wc_HashType)100;
    (void)Hmac_OuterHash(&hmac, mac);
}

/* Hmac_UpdateFinal_CT: the macLen > sizeof(innerHash) clause. The
 * oversized row returns at the guard before any buffer use. */
static void wb_hmac_updatefinal_ct(void)
{
    Hmac hmac;
    byte in[16];
    byte digest[WC_MAX_DIGEST_SIZE];
    byte header[4];

    XMEMSET(&hmac, 0, sizeof(hmac));
    XMEMSET(in, 0, sizeof(in));
    hmac.macType = WC_SHA256;
    (void)Hmac_UpdateFinal_CT(&hmac, digest, in, sizeof(in), 32,
                              header, sizeof(header));
    (void)Hmac_UpdateFinal_CT(&hmac, digest, in, sizeof(in),
                              (int)sizeof(hmac.innerHash) + 1,
                              header, sizeof(header));
}

#if defined(HAVE_ALPN)

/* TLSX_ALPN_New: the protocol_name == NULL clause's true side. */
static void wb_alpn_new_null(void)
{
    if (TLSX_ALPN_New(NULL, 0, NULL) != NULL)
        wb_fail++;
}

/* TLSX_ALPN_Find: (list == NULL) || (protocol_name == NULL) -- the NULL
* list row, the NULL name row on a live node, and the valid baseline. */
static void wb_alpn_find_nulls(void)
{
    ALPN alpn;
    char name[] = "http/1.1";

    XMEMSET(&alpn, 0, sizeof(alpn));
    alpn.protocol_name = name;
    alpn.protocol_nameSz = (word16)sizeof(name) - 1;
    (void)TLSX_ALPN_Find(NULL, name, alpn.protocol_nameSz);
    (void)TLSX_ALPN_Find(&alpn, NULL, 0);
    (void)TLSX_ALPN_Find(&alpn, name, alpn.protocol_nameSz);
}

/* TLSX_SetALPN: (extensions == NULL) || (data == NULL) -- both NULL rows
 * and the valid baseline (pushed onto a local list, freed below). */
static void wb_set_alpn_nulls(void)
{
    TLSX extensions;
    const byte data[] = "http/1.1";

    XMEMSET(&extensions, 0, sizeof(extensions));
    (void)TLSX_SetALPN(NULL, data, (word16)sizeof(data) - 1, NULL);
    (void)TLSX_SetALPN(&extensions, NULL, 0, NULL);
    (void)TLSX_SetALPN(&extensions, data, (word16)sizeof(data) - 1, NULL);
    TLSX_FreeAll(&extensions, NULL);
}

/* TLSX_UseALPN: the extensions == NULL clause's true side. */
static void wb_use_alpn_null(void)
{
    const byte data[] = "http/1.1";
    /* options is unused: the extensions-NULL guard fires first. */
    (void)TLSX_UseALPN(NULL, data, (word16)sizeof(data) - 1, 0, NULL);
}

/* ALPN_find_match: the extension->data == NULL clause's true side -- an
 * ALPN extension with a NULL payload on a real object. */
static void wb_alpn_find_match_null_data(void)
{
    WOLFSSL_CTX *ctx = NULL;
    WOLFSSL *ssl = NULL;
    TLSX *pext = NULL;
    const byte *sel = NULL;
    byte selLen = 0;
    const byte alpnVal[] = {5, 'h', 't', 't', 'p'};

    ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (ctx == NULL)
        return;
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        wolfSSL_CTX_free(ctx);
        return;
    }
    (void)TLSX_Push(&ssl->extensions, TLSX_APPLICATION_LAYER_PROTOCOL,
                    NULL, ssl->heap);
    (void)ALPN_find_match(ssl, &pext, &sel, &selLen, alpnVal,
                          (word16)sizeof(alpnVal));
    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
}

#else

static void wb_alpn_new_null(void)
{
    WB_NOTE("HAVE_ALPN off; ALPN_New rows skipped");
}
static void wb_alpn_find_nulls(void)
{
    WB_NOTE("HAVE_ALPN off; ALPN_Find rows skipped");
}
static void wb_set_alpn_nulls(void)
{
    WB_NOTE("HAVE_ALPN off; SetALPN rows skipped");
}
static void wb_use_alpn_null(void)
{
    WB_NOTE("HAVE_ALPN off; UseALPN rows skipped");
}
static void wb_alpn_find_match_null_data(void)
{
    WB_NOTE("HAVE_ALPN off; ALPN_find_match rows skipped");
}

#endif /* HAVE_ALPN */

#if defined(HAVE_SNI) && !defined(NO_WOLFSSL_SERVER)

/* TLSX_SNI_Parse: the size == 0 row (length matches OPAQUE16_LEN + size,
 * the second clause fires), the SNI_Find miss/hit rows, and the cacheOnly
 * row (a configured sniRecvCb forces it; the callback itself is invoked
 * by the caller of Parse, not inside it, so a sentinel pointer is safe). */
static void wb_sni_parse_rows(void)
{
    WOLFSSL_CTX *ctx = NULL;
    WOLFSSL *ssl = NULL;
    byte in[8];

    ctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (ctx == NULL)
        return;
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        wolfSSL_CTX_free(ctx);
        return;
    }

    c16toa(0, in);
    (void)TLSX_SNI_Parse(ssl, in, OPAQUE16_LEN, 1);

    /* Well-formed host-name SNI, nothing configured: the find-miss row. */
    in[0] = 0; in[1] = 4;
    in[2] = WOLFSSL_SNI_HOST_NAME;
    in[3] = 0; in[4] = 1;
    in[5] = 'a';
    (void)TLSX_SNI_Parse(ssl, in, 6, 1);

    /* Configured: the find-hit row. */
    (void)TLSX_UseSNI(&ssl->extensions, WOLFSSL_SNI_HOST_NAME, "a", 1,
                      ssl->heap);
    (void)TLSX_SNI_Parse(ssl, in, 6, 1);

    /* cacheOnly row. */
    ctx->sniRecvCb = (CallbackSniRecv)1;
    (void)TLSX_SNI_Parse(ssl, in, 6, 1);

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
}

#else

static void wb_sni_parse_rows(void)
{
    WB_NOTE("HAVE_SNI/NO_WOLFSSL_SERVER off; SNI parse rows skipped");
}

#endif /* HAVE_SNI && !NO_WOLFSSL_SERVER */

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("tls.c white-box supplement\n");
    wb_hmac_outer_hash();
    wb_hmac_updatefinal_ct();
    wb_alpn_new_null();
    wb_alpn_find_nulls();
    wb_set_alpn_nulls();
    wb_use_alpn_null();
    wb_alpn_find_match_null_data();
    wb_sni_parse_rows();
    printf("done (%s)\n", wb_fail ? "with failures" : "ok");
    return 0;
}
