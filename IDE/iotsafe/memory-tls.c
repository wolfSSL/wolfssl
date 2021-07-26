/* memory-tls.c
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

/* IoT-safe client side demo
    - server uses software crypto and buffers
    - client uses IoT-Safe

    Client and server communicates in a cooperative
    scheduling mechanism within the same thread.
    Two buffers in memory are used for client<=>server communication.
*/

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/port/iotsafe/iotsafe.h>

#include <stdio.h>
#include <string.h>

#include "ca-cert.c"

/* IoTSAFE Certificate slots */

/* File Slot '03' is pre-provisioned with
 * local certificate.
 */
#define CRT_CLIENT_FILE_ID 0x03     /* pre-provisioned */

/* File Slot '04' is pre-provisioned with the
 * server's EC public key certificate
 */
#define CRT_SERVER_FILE_ID 0x04

/* IoTSAFE Key slots */

/* Key slot '02' is pre-provisioned with
 * the client private key.
 */
#define PRIVKEY_ID      0x02 /* pre-provisioned */

/* Key slot '03' is used by wolfSSL to generate
 * the ECDH key that will be used during the TLS
 * session.
 */
#define ECDH_KEYPAIR_ID 0x03

/* Key slot '04' is used to store the public key
 * received from the peer.
 */
#define PEER_PUBKEY_ID  0x04

/* Key slot '05' is used to store a public key
 * used for ecc verification
 */
#define PEER_CERT_ID    0x05

/* The following define
 * activates mutual authentication */
#define CLIENT_AUTH


#define CLIENT_IOTSAFE
#define CA_ECC

/* client messages to server in memory */
#define TLS_BUFFERS_SZ (1024 * 8)
static unsigned char to_server[TLS_BUFFERS_SZ];
static int server_bytes;
static int server_write_idx;
static int server_read_idx;

/* server messages to client in memory */
unsigned char to_client[TLS_BUFFERS_SZ];
int client_bytes;
int client_write_idx;
int client_read_idx;

/* server send callback */
int ServerSend(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    if (client_write_idx + sz > TLS_BUFFERS_SZ)
        return -SSL_ERROR_WANT_WRITE;
    printf("=== Srv-Cli: %d\n", sz);
    memcpy(&to_client[client_write_idx], buf, sz);
    client_write_idx += sz;
    client_bytes += sz;
    return sz;
}


/* server recv callback */
int ServerRecv(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{

    if (server_bytes - server_read_idx < sz)
        return -SSL_ERROR_WANT_READ;
    memcpy(buf, &to_server[server_read_idx], sz);
    server_read_idx += sz;

    if (server_read_idx == server_write_idx) {
        server_read_idx = server_write_idx = 0;
        server_bytes = 0;
    }
    printf("=== Srv RX: %d\n", sz);
    return sz;
}


/* client send callback */
int ClientSend(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{
    if (server_write_idx + sz > TLS_BUFFERS_SZ)
        return -SSL_ERROR_WANT_WRITE;

    printf("=== Cli->Srv: %d\n", sz);
    memcpy(&to_server[server_write_idx], buf, sz);
    server_write_idx += sz;
    server_bytes += sz;

    return sz;
}


/* client recv callback */
int ClientRecv(WOLFSSL* ssl, char* buf, int sz, void* ctx)
{

    if (client_bytes - client_read_idx < sz)
        return -SSL_ERROR_WANT_READ;

    memcpy(buf, &to_client[client_read_idx], sz);
    client_read_idx += sz;

    if (client_read_idx == client_write_idx) {
        client_read_idx = client_write_idx = 0;
        client_bytes = 0;
    }
    printf("=== Cli RX: %d\n", sz);
    return sz;
}

static int client_state = 0;
static int server_state = 0;

static uint8_t cert_buffer[2048];
static uint32_t cert_buffer_size;


/* wolfSSL Client loop */
static int client_loop(void)
{
    /* set up client */
    int ret;
    static WOLFSSL_CTX *cli_ctx = NULL;
    static WOLFSSL *cli_ssl = NULL;


    printf("=== CLIENT step %d ===\n", client_state);
    if (client_state == 0) {
        printf("Client: Creating new CTX\n");
        cli_ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
        if (cli_ctx == NULL) {
            printf("bad client ctx new");
            return 0;
        }
        printf("Client: Enabling IoT Safe in CTX\n");
        wolfSSL_CTX_iotsafe_enable(cli_ctx);

        printf("Loading CA\n");
        ret = wolfSSL_CTX_load_verify_buffer(cli_ctx, ca_ecc_cert_der_256,
                sizeof_ca_ecc_cert_der_256, SSL_FILETYPE_ASN1);
        if (ret != SSL_SUCCESS) {
            printf("Bad CA\n");
            return -1;
        }

        cert_buffer_size = wolfIoTSafe_GetCert(CRT_SERVER_FILE_ID, cert_buffer, 2048);
        if (cert_buffer_size < 1) {
            printf("Bad server cert\n");
            return -1;
        }
        printf("Loaded Server certificate from IoT-Safe, size = %lu\n",
                cert_buffer_size);
        WOLFSSL_BUFFER(cert_buffer, cert_buffer_size);
        if (wolfSSL_CTX_load_verify_buffer(cli_ctx, cert_buffer, cert_buffer_size,
                    SSL_FILETYPE_ASN1) != SSL_SUCCESS) {
            printf("Cannot load server cert\n");
            return -1;
        }
        printf("Server certificate successfully imported.\n");
        wolfSSL_CTX_set_verify(cli_ctx, SSL_VERIFY_PEER, 0);

#ifdef CLIENT_AUTH
        cert_buffer_size = wolfIoTSafe_GetCert(CRT_CLIENT_FILE_ID, cert_buffer, 2048);
        if (cert_buffer_size < 1) {
            printf("Bad cli cert\n");
            return -1;
        }
        printf("Loaded Client certificate from IoT-Safe, size = %lu\n", cert_buffer_size);
        WOLFSSL_BUFFER(cert_buffer, cert_buffer_size);
        if (wolfSSL_CTX_use_certificate_buffer(cli_ctx, cert_buffer,
                    cert_buffer_size, SSL_FILETYPE_ASN1) != SSL_SUCCESS) {
            printf("Cannot load client cert\n");
            return -1;
        }
        printf("Client certificate successfully imported.\n");
#endif

        /* Setting IO Send/Receive functions to local memory-based message
         * passing (ClientSend, ClientRecv)
         */
        wolfSSL_SetIOSend(cli_ctx, ClientSend);
        wolfSSL_SetIORecv(cli_ctx, ClientRecv);

        printf("Creating new SSL\n");
        cli_ssl = wolfSSL_new(cli_ctx);
        if (cli_ssl == NULL)  {
            printf("bad client new");
            return 0;
        }
        printf("Setting SSL options: non blocking\n");
        wolfSSL_set_using_nonblock(cli_ssl, 1);
        printf("Setting SSL options: turn on IoT-safe for this socket\n");
        wolfSSL_iotsafe_on(cli_ssl, PRIVKEY_ID, ECDH_KEYPAIR_ID, PEER_PUBKEY_ID,
                PEER_CERT_ID);
        client_state++;
    }

    if (client_state == 1) {
        int err;
        printf("Connecting to server...\n");
        ret = wolfSSL_connect(cli_ssl);
        if (ret != SSL_SUCCESS) {
            if (wolfSSL_want_read(cli_ssl))
                return 0;
            printf("error in client tls connect: %d\n", wolfSSL_get_error(cli_ssl, ret));
            client_state = 0;
            wolfSSL_free(cli_ssl);
            wolfSSL_CTX_free(cli_ctx);
            cli_ssl = NULL;
            cli_ctx = NULL;
            return -1;
        }
        printf("Client connected! Sending hello message...\n");
        client_state++;
    }

    ret = wolfSSL_write(cli_ssl, "hello iot-safe wolfSSL",22);
    if (ret >= 0) {
        printf("wolfSSL client success!\n");
    } else if (wolfSSL_get_error(cli_ssl, ret) != SSL_ERROR_WANT_WRITE) {
        printf("error in client tls write");
        client_state = 0;
        wolfSSL_free(cli_ssl);
        wolfSSL_CTX_free(cli_ctx);
        cli_ssl = NULL;
        cli_ctx = NULL;
        return -1;
    }
    /* clean up */
    wolfSSL_free(cli_ssl);
    wolfSSL_CTX_free(cli_ctx);
    return 1;
}

uint8_t srv_cert[1260];
uint32_t srv_cert_size;

/* wolfSSL Server Loop */
static int server_loop(void)
{
    static WOLFSSL_CTX* srv_ctx = NULL;
    static WOLFSSL* srv_ssl = NULL;
    unsigned char buf[80];
    int ret;
    printf("=== SERVER step %d ===\n", server_state);

    if (server_state == 0) {
        srv_ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method());
        if (srv_ctx == NULL) {
            printf("bad server ctx new");
            return -1;
        }
#ifdef CLIENT_AUTH
        ret = wolfSSL_CTX_load_verify_buffer(srv_ctx, ca_ecc_cert_der_256,
                sizeof_ca_ecc_cert_der_256, SSL_FILETYPE_ASN1);
        if (ret != SSL_SUCCESS) {
            printf("Bad CA load: %d\n", ret);
        }
        ret = wolfSSL_CTX_load_verify_buffer(srv_ctx, cliecc_cert_der_256,
                sizeof_cliecc_cert_der_256, SSL_FILETYPE_ASN1);
        if (ret != SSL_SUCCESS) {
            printf("Bad Client cert load: %d\n", ret);
        }
        wolfSSL_CTX_set_verify(srv_ctx, SSL_VERIFY_PEER, 0);
#endif

        if (wolfSSL_CTX_use_PrivateKey_buffer(srv_ctx, ecc_key_der_256,
                    sizeof_ecc_key_der_256, SSL_FILETYPE_ASN1)
                != SSL_SUCCESS) {
            printf("Cannot load server private key\n");
        }
        if (wolfSSL_CTX_use_certificate_buffer(srv_ctx, serv_ecc_der_256,
                    sizeof_serv_ecc_der_256, SSL_FILETYPE_ASN1) != SSL_SUCCESS)
        {
            printf("Cannot load server cert\n");
        }
        wolfSSL_SetIOSend(srv_ctx, ServerSend);
        wolfSSL_SetIORecv(srv_ctx, ServerRecv);
        srv_ssl = wolfSSL_new(srv_ctx);
        if (srv_ssl == NULL) {
            printf("bad server new");
            return -1;
        }
        wolfSSL_set_using_nonblock(srv_ssl, 1);
        server_state++;
    }

    if (server_state == 1) {
        /* accept tls connection without tcp sockets */
        ret = wolfSSL_accept(srv_ssl);
        if (ret != SSL_SUCCESS) {
            if (wolfSSL_want_read(srv_ssl))
                return 0;
            printf("error in server tls accept");
            server_state = 0;
            wolfSSL_free(srv_ssl);
            wolfSSL_CTX_free(srv_ctx);
            srv_ssl = NULL;
            srv_ctx = NULL;
            return -1;
        }
        printf("wolfSSL accept success!\n");
        server_state++;
    }
    if (server_state == 2) {
        ret = wolfSSL_read(srv_ssl, buf, sizeof(buf)-1);
        if (wolfSSL_get_error(srv_ssl, ret) == SSL_ERROR_WANT_READ) {
            return 0;
        }
        if (ret < 0) {
            printf("SERVER READ ERROR: %d\n", wolfSSL_get_error(srv_ssl, ret));
            return -1;
        }
        if (ret > 0) {
            printf("++++++ Server received msg from client: '%s'\n", buf);
            printf("IoT-Safe TEST SUCCESSFUL\n");
        }
    }
    return 0;
}


int memory_tls_test(void)
{
    int ret_s, ret_c;

    printf("Starting memory-tls test...\n");
    do {
        ret_s = server_loop();
        ret_c = client_loop();

    } while ((ret_s >= 0) && (ret_c >= 0));
    return 0;
}
