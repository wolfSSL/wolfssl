/* tinytls13_smoke.c
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

/* Self-contained TLS 1.3 handshake smoke test for the tiny TLS 1.3 profile.
 *
 * Single process, no sockets, no threads (SINGLE_THREADED safe): the client
 * and server WOLFSSL objects are wired together through two in-memory byte
 * queues, and the handshake is driven to completion in one loop. It exercises
 * the real TLS 1.3 handshake state machine for builds where the example/unit
 * test harness is not available, e.g. --enable-tinytls13=psk,p256
 * --disable-examples.
 *
 * On the PSK floor it runs a PSK + ECDHE handshake. On the cert profile
 * (WOLFSSL_TINY_TLS13_CERT) it runs a certificate handshake: the server
 * presents an ECDSA P-256 certificate and the client validates it, driving
 * the Certificate / CertificateVerify path. Cert files default to ../certs
 * (the layout used by parallel-make-check.py builds); pass a directory as
 * argv[1] to override.
 *
 * Build against a static tiny build and run:
 *   cc -I<build> -I<src> tinytls13_smoke.c <build>/src/.libs/libwolfssl.a -lm \
 *      -o tinytls13_smoke && ./tinytls13_smoke
 */

#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include <string.h>
#include <stdio.h>

#define MEM_BUF_SZ 32768

typedef struct membuf {
    unsigned char data[MEM_BUF_SZ];
    int len;
} membuf;

/* recv: drain from the queue this endpoint reads from */
static int mem_recv(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    membuf* mb = (membuf*)ctx;
    int n;

    (void)ssl;
    if (mb->len == 0)
        return WOLFSSL_CBIO_ERR_WANT_READ;
    n = (sz < mb->len) ? sz : mb->len;
    XMEMCPY(buf, mb->data, (size_t)n);
    XMEMMOVE(mb->data, mb->data + n, (size_t)(mb->len - n));
    mb->len -= n;
    return n;
}

/* send: append to the queue the peer reads from */
static int mem_send(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    membuf* mb = (membuf*)ctx;

    (void)ssl;
    if (sz < 0 || mb->len > MEM_BUF_SZ - sz)
        return WOLFSSL_CBIO_ERR_WANT_WRITE;
    XMEMCPY(mb->data + mb->len, buf, (size_t)sz);
    mb->len += sz;
    return sz;
}

#ifndef WOLFSSL_TINY_TLS13_CERT
static const unsigned char psk_key[16] = {
    0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x70, 0x81,
    0x92, 0xa3, 0xb4, 0xc5, 0xd6, 0xe7, 0xf8, 0x09
};
static const char psk_identity[] = "tinytls13-client";

static unsigned int psk_client_cb(WOLFSSL* ssl, const char* hint,
    char* identity, unsigned int id_max, unsigned char* key,
    unsigned int key_max)
{
    (void)ssl;
    (void)hint;
    if (id_max < sizeof(psk_identity) || key_max < sizeof(psk_key))
        return 0;
    XMEMCPY(identity, psk_identity, sizeof(psk_identity));
    XMEMCPY(key, psk_key, sizeof(psk_key));
    return (unsigned int)sizeof(psk_key);
}

static unsigned int psk_server_cb(WOLFSSL* ssl, const char* identity,
    unsigned char* key, unsigned int key_max)
{
    (void)ssl;
    (void)identity;
    if (key_max < sizeof(psk_key))
        return 0;
    XMEMCPY(key, psk_key, sizeof(psk_key));
    return (unsigned int)sizeof(psk_key);
}
#endif /* !WOLFSSL_TINY_TLS13_CERT */

int main(int argc, char** argv)
{
    WOLFSSL_CTX* cctx = NULL;
    WOLFSSL_CTX* sctx = NULL;
    WOLFSSL* c = NULL;
    WOLFSSL* s = NULL;
    membuf c2s; /* client writes, server reads */
    membuf s2c; /* server writes, client reads */
    int i, cdone = 0, sdone = 0, ret = 1;
    int cret = WOLFSSL_FATAL_ERROR, sret = WOLFSSL_FATAL_ERROR;
    const char* cipher = (argc > 1) ? argv[1] : "-";
    const char* group  = (argc > 2) ? argv[2] : "-";
    int mlkemGroup[1];
#ifdef WOLFSSL_TINY_TLS13_CERT
    const char* certDir = (argc > 3) ? argv[3] : "../certs";
    char sCert[300];
    char sKey[300];
    char cCa[300];
#endif

    XMEMSET(&c2s, 0, sizeof(c2s));
    XMEMSET(&s2c, 0, sizeof(s2c));

    wolfSSL_Init();

    cctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    sctx = wolfSSL_CTX_new(wolfTLSv1_3_server_method());
    if (cctx == NULL || sctx == NULL) {
        printf("smoke: CTX_new failed\n");
        goto done;
    }

    /* Force a specific suite when asked, so an adder config proves its cipher
     * negotiates: a single-suite list means a completed handshake used it. */
    if (cipher[0] != '\0' && cipher[0] != '-') {
        wolfSSL_CTX_set_cipher_list(cctx, cipher);
        wolfSSL_CTX_set_cipher_list(sctx, cipher);
    }

#ifdef WOLFSSL_TINY_TLS13_CERT
    /* Server presents a P-256 ECDSA leaf; the client validates it against the
     * CA. The leaf is signed by the CA whose algorithm this profile verifies,
     * so a completed handshake drives that verify path (ECDSA, ML-DSA-65, or
     * RSA-PSS). */
    #if defined(WOLFSSL_HAVE_MLDSA)
        XSNPRINTF(sCert, sizeof(sCert), "%s/mldsa/ecc-leaf-mldsa65.pem", certDir);
        XSNPRINTF(cCa,   sizeof(cCa),   "%s/mldsa/mldsa65-cert.pem", certDir);
    #elif defined(WOLFSSL_TINY_TLS13_RSA_VERIFY)
        XSNPRINTF(sCert, sizeof(sCert), "%s/rsapss/ecc-leaf-rsapss.pem", certDir);
        XSNPRINTF(cCa,   sizeof(cCa),   "%s/rsapss/ca-rsapss.pem", certDir);
    #else
        XSNPRINTF(sCert, sizeof(sCert), "%s/server-ecc.pem", certDir);
        XSNPRINTF(cCa,   sizeof(cCa),   "%s/ca-ecc-cert.pem", certDir);
    #endif
    XSNPRINTF(sKey,  sizeof(sKey),  "%s/ecc-key.pem", certDir);
    if (wolfSSL_CTX_use_certificate_file(sctx, sCert, WOLFSSL_FILETYPE_PEM)
            != WOLFSSL_SUCCESS ||
        wolfSSL_CTX_use_PrivateKey_file(sctx, sKey, WOLFSSL_FILETYPE_PEM)
            != WOLFSSL_SUCCESS ||
        wolfSSL_CTX_load_verify_locations(cctx, cCa, NULL)
            != WOLFSSL_SUCCESS) {
        printf("smoke: cert load failed (certDir=%s)\n", certDir);
        goto done;
    }
#else
    wolfSSL_CTX_set_psk_client_callback(cctx, psk_client_cb);
    wolfSSL_CTX_set_psk_server_callback(sctx, psk_server_cb);
#endif

    wolfSSL_CTX_SetIORecv(cctx, mem_recv);
    wolfSSL_CTX_SetIOSend(cctx, mem_send);
    wolfSSL_CTX_SetIORecv(sctx, mem_recv);
    wolfSSL_CTX_SetIOSend(sctx, mem_send);

    c = wolfSSL_new(cctx);
    s = wolfSSL_new(sctx);
    if (c == NULL || s == NULL) {
        printf("smoke: SSL_new failed\n");
        goto done;
    }

    /* Restrict to the ML-KEM hybrid key share when asked, so a completed
     * handshake proves the hybrid KEX was negotiated. */
    if (XSTRCMP(group, "mlkem") == 0) {
        mlkemGroup[0] = WOLFSSL_X25519MLKEM768;
        wolfSSL_set_groups(c, mlkemGroup, 1);
        wolfSSL_set_groups(s, mlkemGroup, 1);
    }

    /* client reads s2c, writes c2s; server reads c2s, writes s2c */
    wolfSSL_SetIOReadCtx(c, &s2c);
    wolfSSL_SetIOWriteCtx(c, &c2s);
    wolfSSL_SetIOReadCtx(s, &c2s);
    wolfSSL_SetIOWriteCtx(s, &s2c);

    for (i = 0; i < 50 && !(cdone && sdone); i++) {
        if (!cdone) {
            cret = wolfSSL_connect(c);
            if (cret == WOLFSSL_SUCCESS)
                cdone = 1;
        }
        if (!sdone) {
            sret = wolfSSL_accept(s);
            if (sret == WOLFSSL_SUCCESS)
                sdone = 1;
        }
    }

    if (cdone && sdone &&
            XSTRCMP(wolfSSL_get_version(c), "TLSv1.3") == 0) {
        printf("tinytls13 handshake OK: %s %s\n",
            wolfSSL_get_version(c), wolfSSL_get_cipher(c));
        ret = 0;
    }
    else {
        printf("tinytls13 handshake FAILED (client err %d, server err %d)\n",
            wolfSSL_get_error(c, cret), wolfSSL_get_error(s, sret));
    }

done:
    wolfSSL_free(c);
    wolfSSL_free(s);
    wolfSSL_CTX_free(cctx);
    wolfSSL_CTX_free(sctx);
    wolfSSL_Cleanup();
    return ret;
}
