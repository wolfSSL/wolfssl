/* test_esp_crt_bundle.c
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

/* Host test of the ESP-IDF certificate bundle verify callback.
 *
 * Builds the real esp_crt_bundle.c against a host wolfSSL (configured with
 * --enable-opensslextra, see test_esp_crt_bundle.sh), with stub ESP headers.
 *
 *   test_esp_crt_bundle order <bundle>
 *       Every entry's DecodedCert subject must be strictly increasing under
 *       strcmp(), and the bundle search must find each entry by its subject,
 *       also when every other entry fails to parse.
 *
 *   test_esp_crt_bundle chain <bundle> <chain.pem> accept|reject <log text>
 *       A TLS 1.2 client gets a ServerHello and a Certificate message with
 *       the chain (lowest cert first) over in-memory I/O. The chain must be
 *       accepted or rejected, and the callback must have logged <log text>.
 *
 * Link with -Wl,--wrap=time: the date is fixed at TEST_NOW so the real
 * certificates in certs/ stay valid. The TEST_NOW environment variable
 * (seconds since the epoch) sets another date. */

/* The host wolfSSL headers come first, so structs match the library. The
 * port file is then compiled as if for ESP-IDF; its own includes of these
 * headers do nothing. */
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/internal.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssl/wolfcrypt/logging.h>
/* misc.c for c32to24(), as in tests/api.c */
#define WOLFSSL_MISC_INCLUDED
#include <wolfcrypt/src/misc.c>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define WOLFSSL_ESPIDF
#define WOLFSSL_USER_SETTINGS
#define WOLFSSL_ESPIDF_COMPONENT_VERSION 1
#include "sdkconfig.h"
#include "esp_log.h"

#include "../esp_crt_bundle.c"

/* 2026-12-01 00:00:00 UTC */
#define TEST_NOW 1796083200

/* The linker sends wolfSSL's time() calls here. */
time_t __wrap_time(time_t* t)
{
    const char* env = getenv("TEST_NOW");
    time_t now = (env != NULL) ? (time_t)strtoll(env, NULL, 10) : TEST_NOW;

    if (t != NULL) {
        *t = now;
    }
    return now;
}

/* esp_crt_bundle.c refers to the bundle linked into an ESP-IDF build. This
 * test sets the bundle with esp_crt_bundle_set() instead. */
const uint8_t test_bundle_start[1]
    __asm__("_binary_x509_crt_bundle_wolfssl_start") = { 0 };
const uint8_t test_bundle_end[1]
    __asm__("_binary_x509_crt_bundle_wolfssl_end") = { 0 };

static char log_buf[1 << 20];
static size_t log_len = 0;
static int verbose = 0;

/* ESP_LOGx sink: append the message to log_buf, and print it if verbose.
 * Returns the vsnprintf() result, or 0 when log_buf is full. */
int test_log(char level, const char* tag, const char* fmt, ...)
{
    va_list args;
    int n = 0;

    if (log_len < sizeof(log_buf) - 1) {
        va_start(args, fmt);
        n = vsnprintf(log_buf + log_len, sizeof(log_buf) - log_len, fmt,
                      args);
        va_end(args);
        if (n > 0) {
            log_len += (size_t)n;
            if (log_len > sizeof(log_buf) - 2) {
                log_len = sizeof(log_buf) - 2;
            }
            log_buf[log_len++] = '\n';
            log_buf[log_len] = '\0';
        }
    }
    if (verbose) {
        va_start(args, fmt);
        fprintf(stderr, "%c (%s) ", level, tag);
        vfprintf(stderr, fmt, args);
        fprintf(stderr, "\n");
        va_end(args);
    }
    return n;
}

/* Read a whole file, NUL terminated. Returns the malloc'd buffer and sets
 * sz, or NULL on error. */
static unsigned char* read_file(const char* path, long* sz)
{
    FILE* f = fopen(path, "rb");
    unsigned char* buf = NULL;

    if (f == NULL) {
        perror(path);
        return NULL;
    }
    if ((fseek(f, 0, SEEK_END) == 0) && ((*sz = ftell(f)) > 0) &&
        (fseek(f, 0, SEEK_SET) == 0)) {
        buf = (unsigned char*)malloc((size_t)*sz + 1);
        if ((buf != NULL) && (fread(buf, 1, (size_t)*sz, f) != (size_t)*sz)) {
            free(buf);
            buf = NULL;
        }
    }
    fclose(f);
    if (buf != NULL) {
        buf[*sz] = '\0';
    }
    return buf;
}

/* Read a bundle file and set it as the cert bundle. Returns 0 on success. */
static int load_bundle(const char* path, unsigned char** bundle)
{
    long sz = 0;

    *bundle = read_file(path, &sz);
    if (*bundle == NULL) {
        return -1;
    }
    if (esp_crt_bundle_set(*bundle, (size_t)sz) != ESP_OK) {
        fprintf(stderr, "%s: esp_crt_bundle_set() failed\n", path);
        return -1;
    }
    return 0;
}

/* A build without a key type the bundle uses (e.g. NO_RSA) can't parse those
 * entries. Break every other entry in turn, and check the search still finds
 * each of the rest. Returns 0 on success. */
static int check_unparsed(const char* path, DecodedCert* dcert)
{
    unsigned char* tag;
    const unsigned char* der;
    const unsigned char* found_der;
    char name[WC_ASN_NAME_MAX];
    int der_sz;
    int found_sz;
    int is_ca;
    int skip;
    int i;
    int failed = 0;

    for (skip = 0; (skip < 2) && (failed == 0); skip++) {
        /* An entry whose DER doesn't start with a SEQUENCE won't parse. */
        for (i = skip; i < s_crt_bundle.num_certs; i += 2) {
            tag = (unsigned char*)(s_crt_bundle.crts[i] + CRT_HEADER_OFFSET);
            *tag = 0x00;
        }
        for (i = 1 - skip; (i < s_crt_bundle.num_certs) && (failed == 0);
             i += 2) {
            der_sz = (s_crt_bundle.crts[i][0] << 8) | s_crt_bundle.crts[i][1];
            der = s_crt_bundle.crts[i] + CRT_HEADER_OFFSET;
            wc_InitDecodedCert(dcert, der, (word32)der_sz, NULL);
            if (wc_ParseCert(dcert, CA_TYPE, NO_VERIFY, NULL) != 0) {
                failed = 1;
            }
            strncpy(name, dcert->subject, sizeof(name) - 1);
            name[sizeof(name) - 1] = '\0';
            wc_FreeDecodedCert(dcert);
            if ((failed != 0) ||
                (wolfssl_bundle_find(dcert, name, &found_der, &found_sz,
                                     &is_ca) != 1) ||
                (found_der != der)) {
                printf("FAIL %s: with every other entry unparsable, search "
                       "does not find entry %d\n  %s\n", path, i, name);
                failed = 1;
            }
        }
        for (i = skip; i < s_crt_bundle.num_certs; i += 2) {
            tag = (unsigned char*)(s_crt_bundle.crts[i] + CRT_HEADER_OFFSET);
            *tag = ASN_SEQUENCE | ASN_CONSTRUCTED;
        }
    }
    return failed;
}

/* Check the bundle is in the order the binary search expects and that every
 * cert can be found, also when some entries don't parse. Returns 0 on
 * success. */
static int check_order(const char* path)
{
    unsigned char* bundle = NULL;
    DecodedCert* dcert = NULL;
    char prev[WC_ASN_NAME_MAX];
    const unsigned char* der;
    const unsigned char* found_der;
    int der_sz;
    int found_sz;
    int is_ca;
    int i;
    int failed = 0;

    if (load_bundle(path, &bundle) != 0) {
        return 1;
    }
    dcert = (DecodedCert*)malloc(sizeof(DecodedCert));
    if (dcert == NULL) {
        return 1;
    }
    prev[0] = '\0';
    for (i = 0; i < s_crt_bundle.num_certs; i++) {
        der_sz = (s_crt_bundle.crts[i][0] << 8) | s_crt_bundle.crts[i][1];
        der = s_crt_bundle.crts[i] + CRT_HEADER_OFFSET;
        wc_InitDecodedCert(dcert, der, (word32)der_sz, NULL);
        if (wc_ParseCert(dcert, CA_TYPE, NO_VERIFY, NULL) != 0) {
            printf("FAIL %s: entry %d does not parse\n", path, i);
            failed = 1;
        }
        else if ((i > 0) && (strcmp(prev, dcert->subject) >= 0)) {
            printf("FAIL %s: entry %d is out of order\n  %s\n  %s\n", path,
                   i, prev, dcert->subject);
            failed = 1;
        }
        else {
            strncpy(prev, dcert->subject, sizeof(prev) - 1);
            prev[sizeof(prev) - 1] = '\0';
        }
        wc_FreeDecodedCert(dcert);

        /* The callback's search must land on this same entry. */
        if ((failed == 0) &&
            ((wolfssl_bundle_find(dcert, prev, &found_der, &found_sz,
                                  &is_ca) != 1) ||
             (found_der != der))) {
            printf("FAIL %s: search does not find entry %d\n  %s\n", path, i,
                   prev);
            failed = 1;
        }
    }
    if (failed == 0) {
        failed = check_unparsed(path, dcert);
    }
    if (failed == 0) {
        printf("ok   order %s: %d certificates\n", path,
               s_crt_bundle.num_certs);
    }
    free(dcert);
    free(bundle);
    return failed;
}

/* Server side of the in-memory connection: a ServerHello and a Certificate
 * message, then end of input. */
static unsigned char srv_buf[64 * 1024];
static int srv_len = 0;
static int srv_pos = 0;
/* The last cert of the chain: the one cross-signed by an issuer outside the
 * bundle. */
static const unsigned char* top_der = NULL;
static int top_sz = 0;

/* I/O callback: hand out the canned server flight. Returns bytes read. */
static int test_recv(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    int n = srv_len - srv_pos;

    (void)ssl;
    (void)ctx;
    if (n <= 0) {
        return WOLFSSL_CBIO_ERR_CONN_CLOSE;
    }
    if (n > sz) {
        n = sz;
    }
    memcpy(buf, srv_buf + srv_pos, (size_t)n);
    srv_pos += n;
    return n;
}

/* I/O callback: drop what the client sends. Returns sz. */
static int test_send(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    (void)ssl;
    (void)buf;
    (void)ctx;
    return sz; /* the ClientHello and any alert are dropped */
}

/* Build the server flight from the PEM chain. Returns 0 on success. */
static int build_server_flight(const char* chain_path)
{
    static const unsigned char server_hello[] = {
        0x03, 0x03,                                  /* TLS 1.2 */
        0x5e, 0x5e, 0x5e, 0x5e, 0x5e, 0x5e, 0x5e, 0x5e, /* random */
        0x5e, 0x5e, 0x5e, 0x5e, 0x5e, 0x5e, 0x5e, 0x5e,
        0x5e, 0x5e, 0x5e, 0x5e, 0x5e, 0x5e, 0x5e, 0x5e,
        0x5e, 0x5e, 0x5e, 0x5e, 0x5e, 0x5e, 0x5e, 0x5e,
        0x00,                                        /* no session ID */
        0xc0, 0x2b,          /* TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 */
        0x00,                                        /* no compression */
        0x00, 0x09,                                  /* extensions */
        0xff, 0x01, 0x00, 0x01, 0x00,                /* renegotiation_info */
        0x00, 0x17, 0x00, 0x00                       /* extended master */
    };
    static const char begin[] = "-----BEGIN CERTIFICATE-----";
    static const char end[] = "-----END CERTIFICATE-----";
    unsigned char* pem;
    unsigned char* msgs;
    char* p;
    char* e;
    long pem_sz = 0;
    int msgs_len = 0;
    int list_len = 0;
    int list_at;
    int der_sz;

    pem = read_file(chain_path, &pem_sz);
    if (pem == NULL) {
        return -1;
    }

    /* Record header, then the handshake messages. */
    msgs = srv_buf + 5;
    msgs[0] = 2; /* server_hello */
    c32to24((word32)sizeof(server_hello), msgs + 1);
    memcpy(msgs + 4, server_hello, sizeof(server_hello));
    msgs_len = 4 + (int)sizeof(server_hello);

    msgs[msgs_len] = 11; /* certificate */
    list_at = msgs_len + 7; /* after the type, the length and the list length */
    for (p = strstr((char*)pem, begin); p != NULL; p = strstr(e, begin)) {
        e = strstr(p, end);
        if (e == NULL) {
            break;
        }
        e += sizeof(end) - 1;
        der_sz = wc_CertPemToDer((const unsigned char*)p, (int)(e - p),
                                 srv_buf + 5 + list_at + list_len + 3,
                                 (int)sizeof(srv_buf) - 5 - list_at -
                                 list_len - 3, CERT_TYPE);
        if (der_sz <= 0) {
            fprintf(stderr, "%s: bad PEM certificate\n", chain_path);
            free(pem);
            return -1;
        }
        c32to24((word32)der_sz, srv_buf + 5 + list_at + list_len);
        top_der = srv_buf + 5 + list_at + list_len + 3;
        top_sz = der_sz;
        list_len += 3 + der_sz;
    }
    free(pem);
    c32to24((word32)list_len + 3, msgs + msgs_len + 1);
    c32to24((word32)list_len, msgs + msgs_len + 4);
    msgs_len += 7 + list_len;

    srv_buf[0] = 0x16; /* handshake */
    srv_buf[1] = 0x03;
    srv_buf[2] = 0x03;
    srv_buf[3] = (unsigned char)(msgs_len >> 8);
    srv_buf[4] = (unsigned char)msgs_len;
    srv_len = 5 + msgs_len;
    srv_pos = 0;
    return 0;
}

/* After a chain is accepted as a cross-sign of a bundle root, the only signer
 * in the Certificate Manager with the top cert's subject must be the bundle
 * root that the callback loaded. wolfSSL keeps the accepted top cert on the
 * connection's waived-CA list, which it searches only after the Certificate
 * Manager, so later certs are verified with the root. Returns 0 when that
 * holds. */
static int check_signers(WOLFSSL_CERT_MANAGER* cm, const char* chain_path)
{
    DecodedCert top;
    Signer* signer;
    int user_ca = 0;
    int other = 0;
    int i;

    wc_InitDecodedCert(&top, top_der, (word32)top_sz, NULL);
    if (wc_ParseCert(&top, CERT_TYPE, NO_VERIFY, NULL) != 0) {
        printf("FAIL %s: top cert does not parse\n", chain_path);
        wc_FreeDecodedCert(&top);
        return -1;
    }
    for (i = 0; i < CA_TABLE_SIZE; i++) {
        for (signer = cm->caTable[i]; signer != NULL; signer = signer->next) {
            if (memcmp(signer->subjectNameHash, top.subjectHash,
                       SIGNER_DIGEST_SIZE) != 0) {
                continue;
            }
            if (signer->type == WOLFSSL_USER_CA) {
                user_ca++;
            }
            else {
                other++;
            }
        }
    }
    wc_FreeDecodedCert(&top);

    if ((user_ca != 1) || (other != 0)) {
        printf("FAIL %s: %d bundle root and %d other signers for the top "
               "cert's subject\n", chain_path, user_ca, other);
        return -1;
    }
    return 0;
}

/* The callback installed by esp_crt_bundle_attach(), and whether it rejected
 * any certificate. */
static VerifyCallback bundle_cb = NULL;
static int bundle_cb_rejected = 0;

/* Wrap the bundle callback to note a rejection. Returns its result. */
static int test_verify_cb(int preverify, WOLFSSL_X509_STORE_CTX* store)
{
    int ret = bundle_cb(preverify, store);

    if (ret == 0) {
        bundle_cb_rejected = 1;
    }
    return ret;
}

/* Handshake against a chain and check the result and log against expect
 * and log_text. Returns 0 on pass. */
static int check_chain(const char* bundle_path, const char* chain_path,
                       const char* expect, const char* log_text)
{
    unsigned char* bundle = NULL;
    WOLFSSL_CTX* ctx = NULL;
    WOLFSSL* ssl = NULL;
    wolfssl_ssl_config conf;
    int ret;
    int err;
    int accepted;
    int failed = 1;

    if ((load_bundle(bundle_path, &bundle) != 0) ||
        (build_server_flight(chain_path) != 0)) {
        return 1;
    }

    ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    if (ctx == NULL) {
        return 1;
    }
    memset(&conf, 0, sizeof(conf));
    conf.priv_ctx = ctx;
    if (esp_crt_bundle_attach(&conf) != ESP_OK) {
        fprintf(stderr, "esp_crt_bundle_attach() failed\n");
        return 1;
    }
    bundle_cb = ctx->verifyCallback;
    if (bundle_cb == NULL) {
        fprintf(stderr, "no verify callback after esp_crt_bundle_attach()\n");
        return 1;
    }
    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, test_verify_cb);
    wolfSSL_CTX_SetIORecv(ctx, test_recv);
    wolfSSL_CTX_SetIOSend(ctx, test_send);
    ssl = wolfSSL_new(ctx);
    if (ssl == NULL) {
        return 1;
    }

    ret = wolfSSL_connect(ssl);
    err = wolfSSL_get_error(ssl, ret);
    /* The handshake can't finish: the server sends nothing after its
     * Certificate message. An accepted chain gets that far and then runs
     * out of input; a rejected one fails in the verify callback. */
    accepted = (bundle_cb_rejected == 0) && (srv_pos == srv_len) &&
               (err == WC_NO_ERR_TRACE(SOCKET_ERROR_E));
    if ((!accepted) && (bundle_cb_rejected == 0)) {
        printf("FAIL %s: not accepted, but not by the callback (error %d)\n",
               chain_path, err);
    }
    else if (accepted != (strcmp(expect, "accept") == 0)) {
        printf("FAIL %s: %s, expected %s (error %d)\n", chain_path,
               accepted ? "accepted" : "rejected", expect, err);
    }
    else if (strstr(log_buf, log_text) == NULL) {
        printf("FAIL %s: %s, but the log lacks \"%s\"\n", chain_path, expect,
               log_text);
    }
    else if (accepted &&
             (strstr(log_buf, "Accepted a cross-signed copy") != NULL) &&
             (check_signers(ctx->cm, chain_path) != 0)) {
        /* reported */
    }
    else {
        printf("ok   %s: %s\n", chain_path, expect);
        failed = 0;
    }

    wolfSSL_free(ssl);
    wolfSSL_CTX_free(ctx);
    wolfSSL_bundle_cleanup();
    free(bundle);
    return failed;
}

/* Run the order or chain check given on the command line. Returns 0 on
 * pass. */
int main(int argc, char** argv)
{
    int ret = 2;

    verbose = (getenv("TEST_ESP_CRT_BUNDLE_VERBOSE") != NULL);
    wolfSSL_Init();
    if ((argc == 3) && (strcmp(argv[1], "order") == 0)) {
        ret = check_order(argv[2]);
    }
    else if ((argc == 6) && (strcmp(argv[1], "chain") == 0)) {
        ret = check_chain(argv[2], argv[3], argv[4], argv[5]);
    }
    else {
        fprintf(stderr, "usage: %s order <bundle>\n"
                        "       %s chain <bundle> <chain.pem> "
                        "accept|reject <log text>\n", argv[0], argv[0]);
    }
    wolfSSL_Cleanup();
    return ret;
}
