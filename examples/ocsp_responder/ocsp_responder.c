/* ocsp_responder.c
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

/* This is a test program and should not be used as an example. */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#ifndef WOLFSSL_USER_SETTINGS
    #include <wolfssl/options.h>
#endif
#include <wolfssl/wolfcrypt/settings.h>

#undef TEST_OPENSSL_COEXIST /* can't use this option with this example */
#undef OPENSSL_COEXIST /* can't use this option with this example */

#include <wolfssl/ssl.h>
#include <wolfssl/ocsp.h>
#include <wolfssl/test.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/asn.h>

#include <examples/ocsp_responder/ocsp_responder.h>

/* Check if we have the required features */
#if defined(HAVE_OCSP) && defined(HAVE_OCSP_RESPONDER) && !defined(NO_FILESYSTEM)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Define mygetopt variables (used by mygetopt_long in test.h) */
int myoptind = 0;
char* myoptarg = NULL;

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #define SOCKET_T SOCKET
    #define close(s) closesocket(s)
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <errno.h>
    #include <signal.h>
    #define SOCKET_T int
#ifndef INVALID_SOCKET
    #define INVALID_SOCKET (-1)
#endif
    #define SOCKET_ERROR (-1)
#endif

/* Default values */
#define DEFAULT_PORT      8888
#define MAX_REQUEST_SIZE  65536
#define MAX_RESPONSE_SIZE 65536
#define MAX_HTTP_HEADER   4096
#define MAX_PATH_LEN      256
#define MAX_CERTS         16

/* Simple logging macro */
#define LOG_ERROR(...)                                                         \
    do {                                                                       \
        if (got_signal)                                                        \
            fprintf(stderr, "Shutdown requested, exiting loop\n");             \
        else                                                                   \
            fprintf(stderr, __VA_ARGS__);                                      \
    } while (0)


#define LOG_MSG(...)                                                           \
    do {                                                                       \
        printf(__VA_ARGS__);                                                   \
        fflush(stdout);                                                        \
    } while(0)

#ifndef _WIN32
/* Signal handler flag */
static volatile int got_signal = 0;

static void sig_handler(int sig)
{
    (void)sig;
    got_signal = 1;
}
#endif

/* Index file entry structure */
typedef struct IndexEntry {
    char status;                /* V=valid, R=revoked, E=expired */
    time_t expirationTime;
    time_t revocationTime;
    char serial[64];
    char filename[256];
    char subject[512];
    struct IndexEntry* next;
} IndexEntry;

/* Program options */
typedef struct {
    word16 port;
    const char* certFile;
    const char* responderCertFile;
    const char* keyFile;
    const char* indexFile;
    const char* readyFile;
    int nrequests;
    int verbose;
    int sendCerts;
} OcspResponderOptions;

/* Usage help */

/* Usage help */
static void Usage(void)
{
    LOG_MSG("OCSP Responder Example\n\n");
    LOG_MSG("Usage: ocsp_responder [options]\n\n");
    LOG_MSG("Options:\n");
    LOG_MSG("  -?           Help\n");
    LOG_MSG("  -p <num>     Port (default %d)\n", DEFAULT_PORT);
    LOG_MSG("  -c <file>    CA certificate (issuer)\n");
    LOG_MSG("  -r <file>    Responder certificate (for authorized responder)\n");
    LOG_MSG("  -k <file>    Signing private key\n");
    LOG_MSG("  -i <file>    Index file for cert status\n");
    LOG_MSG("  -R <file>    Ready file for external monitor\n");
    LOG_MSG("  -n <num>     Exit after n requests\n");
    LOG_MSG("  -v           Verbose\n");
    LOG_MSG("  -x           Exclude certs from response\n");
}

/* Load file into buffer, auto-detect PEM vs DER */
static int LoadFile(const char* filename, byte** buf, word32* bufSz, int* isPem)
{
    int ret;
    size_t sz = 0;

    ret = load_file(filename, buf, &sz);
    if (ret != 0) {
        LOG_ERROR("Error opening file: %s\n", filename);
        return ret;
    }

    /* Check if PEM format by looking for -----BEGIN */
    if (isPem) {
        *isPem = (XSTRSTR((char*)*buf, "-----BEGIN") != NULL) ? 1 : 0;
    }

    *bufSz = (word32)sz;
    return 0;
}

/* Convert PEM to DER */
static int ConvertPemToDer(const byte* pem, word32 pemSz, byte** der, word32* derSz, int type)
{
    int ret;
    DerBuffer* derBuf = NULL;

    ret = wc_PemToDer(pem, pemSz, type, &derBuf, NULL, NULL, NULL);
    if (ret != 0 || derBuf == NULL) {
        return ret;
    }

    *der = (byte*)XMALLOC(derBuf->length, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (*der == NULL) {
        wc_FreeDer(&derBuf);
        return MEMORY_E;
    }

    XMEMCPY(*der, derBuf->buffer, derBuf->length);
    *derSz = derBuf->length;
    wc_FreeDer(&derBuf);

    return 0;
}

/* Load certificate in DER format */
static int LoadCertDer(const char* filename, byte** der, word32* derSz)
{
    byte* buf = NULL;
    word32 bufSz = 0;
    int isPem = 0;
    int ret;

    ret = LoadFile(filename, &buf, &bufSz, &isPem);
    if (ret != 0) {
        return ret;
    }

    if (isPem) {
        ret = ConvertPemToDer(buf, bufSz, der, derSz, CERT_TYPE);
        XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }
    else {
        *der = buf;
        *derSz = bufSz;
        return 0;
    }
}

/* Load private key in DER format */
static int LoadKeyDer(const char* filename, byte** der, word32* derSz)
{
    byte* buf = NULL;
    word32 bufSz = 0;
    int isPem = 0;
    int ret;

    ret = LoadFile(filename, &buf, &bufSz, &isPem);
    if (ret != 0) {
        return ret;
    }

    if (isPem) {
        ret = ConvertPemToDer(buf, bufSz, der, derSz, PRIVATEKEY_TYPE);
        XFREE(buf, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        return ret;
    }
    else {
        *der = buf;
        *derSz = bufSz;
        return 0;
    }
}

/* Free index entries */
static void FreeIndexEntries(IndexEntry* head)
{
    while (head) {
        IndexEntry* next = head->next;
        XFREE(head, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        head = next;
    }
}

/* Parse OpenSSL index.txt file
 * Format: status\texpiration\trevocation\tserial\tfilename\tsubject
 * V = valid, R = revoked, E = expired
 */
static IndexEntry* ParseIndexFile(const char* filename)
{
    XFILE f = XBADFILE;
    char line[1024];
    IndexEntry* head = NULL;
    IndexEntry* tail = NULL;
    IndexEntry* entry = NULL;
    IndexEntry* ret = NULL;

    if (filename == NULL) {
        LOG_ERROR("Invalid filename parameter\n");
        goto cleanup;
    }

    f = XFOPEN(filename, "r");
    if (f == XBADFILE) {
        LOG_ERROR("Error opening index file: %s\n", filename);
        goto cleanup;
    }

    while (XFGETS(line, sizeof(line), f) != NULL) {
        char* p = line;
        char* field;
        int fieldNum = 0;

        /* Skip empty lines */
        if (line[0] == '\n' || line[0] == '\r' || line[0] == '\0')
            continue;

        entry = (IndexEntry*)XMALLOC(sizeof(IndexEntry), NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (entry == NULL) {
            LOG_ERROR("Memory allocation failed for index entry\n");
            goto cleanup;
        }
        XMEMSET(entry, 0, sizeof(IndexEntry));

        /* Parse tab-separated fields */
        while ((field = XSTRSEP(&p, "\t")) != NULL && fieldNum < 6) {
            switch (fieldNum) {
                case 0: /* Status */
                    entry->status = field[0];
                    break;
                case 1: /* Expiration time (YYMMDDHHMMSSZ format) */
                    /* Parse if needed */
                    break;
                case 2: /* Revocation time */
                    /* Parse if needed, empty for valid certs */
                    if (field[0] != '\0') {
                        struct tm tm;
                        XMEMSET(&tm, 0, sizeof(tm));
                        /* Format: YYMMDDHHMMSSZ */
                        if (XSTRLEN(field) >= 12) {
                            int year = (field[0] - '0') * 10 + (field[1] - '0');
                            tm.tm_year = (year < 50) ? (100 + year) : year;
                            tm.tm_mon = (field[2] - '0') * 10 + (field[3] - '0') - 1;
                            tm.tm_mday = (field[4] - '0') * 10 + (field[5] - '0');
                            tm.tm_hour = (field[6] - '0') * 10 + (field[7] - '0');
                            tm.tm_min = (field[8] - '0') * 10 + (field[9] - '0');
                            tm.tm_sec = (field[10] - '0') * 10 + (field[11] - '0');
                            entry->revocationTime = XMKTIME(&tm);
                        }
                    }
                    break;
                case 3: /* Serial (hex) */
                    XSTRNCPY(entry->serial, field, sizeof(entry->serial) - 1);
                    break;
                case 4: /* Filename */
                    XSTRNCPY(entry->filename, field, sizeof(entry->filename) - 1);
                    break;
                case 5: /* Subject */
                    /* Remove trailing newline */
                    {
                        size_t len = XSTRLEN(field);
                        if (len > 0 && (field[len-1] == '\n' || field[len-1] == '\r'))
                            field[len-1] = '\0';
                        if (len > 1 && (field[len-2] == '\n' || field[len-2] == '\r'))
                            field[len-2] = '\0';
                    }
                    XSTRNCPY(entry->subject, field, sizeof(entry->subject) - 1);
                    break;
            }
            fieldNum++;
        }

        /* Validate that we got at least status and serial */
        if (fieldNum < 4 || entry->serial[0] == '\0' ||
                entry->revocationTime == (time_t)-1) {
            LOG_ERROR("Invalid index entry - missing required fields\n");
            XFREE(entry, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            entry = NULL;
            goto cleanup;
        }

        /* Add to list */
        entry->next = NULL;
        if (tail) {
            tail->next = entry;
            tail = entry;
        }
        else {
            head = tail = entry;
        }
        entry = NULL;
    }

    /* Success */
    ret = head;
    head = NULL;

cleanup:
    if (f != XBADFILE)
        XFCLOSE(f);
    if (entry != NULL)
        XFREE(entry, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    FreeIndexEntries(head);
    return ret;
}

/* Lookup certificate status by serial number */
static int PopulateResponderFromIndex(OcspResponder* responder, IndexEntry* index,
                                       DecodedCert* caCert)
{
    IndexEntry* entry;
    const char* caSubject;
    word32 caSubjSz;
    int count = 0;
    int ret;

    if (responder == NULL || index == NULL || caCert == NULL) {
        return BAD_FUNC_ARG;
    }

    caSubject = wc_GetDecodedCertSubject(caCert, &caSubjSz);
    if (caSubject == NULL || caSubjSz == 0) {
        LOG_ERROR("Could not get CA subject\n");
        return BAD_FUNC_ARG;
    }

    for (entry = index; entry != NULL; entry = entry->next) {
        byte serial[64];
        word32 serialLen = 0;
        enum Ocsp_Cert_Status status;
        time_t revTime = 0;
        enum WC_CRL_Reason revReason = CRL_REASON_UNSPECIFIED;
        word32 validity = 86400;
        char* p = entry->serial;
        word32 i;

        /* Convert hex string to bytes */
        serialLen = (word32)XSTRLEN(entry->serial) / 2;
        if (serialLen == 0 || serialLen > sizeof(serial)) {
            continue;
        }

        for (i = 0; i < serialLen; i++) {
            int high = (p[i*2] >= 'A') ? (p[i*2] - 'A' + 10) :
                      (p[i*2] >= 'a') ? (p[i*2] - 'a' + 10) : (p[i*2] - '0');
            int low = (p[i*2+1] >= 'A') ? (p[i*2+1] - 'A' + 10) :
                     (p[i*2+1] >= 'a') ? (p[i*2+1] - 'a' + 10) : (p[i*2+1] - '0');
            serial[i] = (byte)((high << 4) | low);
        }

        /* Determine status */
        if (entry->status == 'V') {
            status = CERT_GOOD;
        }
        else if (entry->status == 'R') {
            status = CERT_REVOKED;
            revTime = entry->revocationTime;
            revReason = CRL_REASON_UNSPECIFIED;
            validity = 0;
        }
        else {
            status = CERT_UNKNOWN;
            validity = 0;
        }

        ret = wc_OcspResponder_SetCertStatus(responder,
                                              caSubject, caSubjSz,
                                              serial, serialLen,
                                              status, revTime, revReason, validity);
        if (ret == 0) {
            count++;
        }
    }

    return count;
}

/* Receive a complete HTTP request, looping until the full body arrives */
static int RecvHttpRequest(SOCKET_T fd, byte* buf, int bufSz)
{
    int totalLen = 0;
    int contentLen = 0;
    int headerSz = 0;

    while (totalLen < bufSz - 1) {
        int n = (int)recv(fd, (char*)buf + totalLen,
                          (size_t)(bufSz - 1 - totalLen), 0);
        if (n <= 0)
            break;
        totalLen += n;
        buf[totalLen] = '\0';

        /* Once we find end-of-headers, parse Content-Length */
        if (headerSz == 0) {
            const char* hdrEnd = XSTRSTR((char*)buf, "\r\n\r\n");
            if (hdrEnd != NULL) {
                const char* cl;
                headerSz = (int)(hdrEnd + 4 - (char*)buf);
                cl = XSTRSTR((char*)buf, "Content-Length:");
                if (cl == NULL)
                    cl = XSTRSTR((char*)buf, "content-length:");
                if (cl != NULL)
                    contentLen = atoi(cl + 15);
            }
        }
        /* Check if we have the full body */
        if (headerSz > 0 && totalLen >= headerSz + contentLen)
            break;
    }
    return totalLen;
}

/* Parse HTTP request and extract OCSP request body */
static int ParseHttpRequest(const byte* httpReq, int httpReqSz,
                            const byte** body, int* bodySz,
                            char* path, int pathSz)
{
    /* Initialize outputs */
    *body = NULL;
    *bodySz = 0;
    if (path && pathSz > 0)
        path[0] = '\0';

    /* Check for POST method */
    if (XSTRNCMP((char*)httpReq, "POST ", 5) == 0) {
        const char* contentLen;
        /* Extract path */
        const char* pathStart = (const char*)httpReq + 5;
        const char* pathEnd = XSTRSTR(pathStart, " ");
        if (pathEnd && path && pathSz > 0) {
            int len = (int)(pathEnd - pathStart);
            if (len >= pathSz) len = pathSz - 1;
            XMEMCPY(path, pathStart, (size_t)len);
            path[len] = '\0';
        }

        /* Find Content-Length */
        contentLen = XSTRSTR((char*)httpReq, "Content-Length:");
        if (contentLen == NULL) {
            contentLen = XSTRSTR((char*)httpReq, "content-length:");
        }
        if (contentLen) {
            *bodySz = atoi(contentLen + 15);
        }

        /* Find body (after \r\n\r\n) */
        *body = (const byte*)XSTRSTR((char*)httpReq, "\r\n\r\n");
        if (*body) {
            *body += 4;
            /* Use Content-Length if available, otherwise use remaining data */
            if (*bodySz == 0) {
                *bodySz = httpReqSz - (int)(*body - httpReq);
            }
            return 0;
        }
    }
    /* Check for GET method with URL-encoded request */
    else if (XSTRNCMP((char*)httpReq, "GET ", 4) == 0) {
        /* GET requests have base64-encoded OCSP request in URL */
        /* For simplicity, we'll require POST for now */
        LOG_ERROR("GET method not fully supported, use POST\n");
        return -1;
    }

    return -1;
}

/* Send HTTP response with OCSP response body */
static int SendHttpResponse(SOCKET_T clientfd, const byte* ocspResp, int ocspRespSz)
{
    char header[MAX_HTTP_HEADER];
    int headerLen;
    int sent;

    headerLen = snprintf(header, sizeof(header),
        "HTTP/1.0 200 OK\r\n"
        "Content-Type: application/ocsp-response\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n", ocspRespSz);

    /* Send header */
    sent = (int)send(clientfd, header, (size_t)headerLen, 0);
    if (sent != headerLen) {
        LOG_ERROR("Failed to send HTTP header\n");
        return -1;
    }

    /* Send body */
    sent = (int)send(clientfd, (const char*)ocspResp, (size_t)ocspRespSz, 0);
    if (sent != ocspRespSz) {
        LOG_ERROR("Failed to send OCSP response\n");
        return -1;
    }

    return 0;
}

/* Send HTTP error response */
static int SendHttpError(SOCKET_T clientfd, int statusCode, const char* statusMsg)
{
    char response[512];
    int len;
    int sent;

    len = snprintf(response, sizeof(response),
        "HTTP/1.0 %d %s\r\n"
        "Content-Type: text/plain\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
        "\r\n"
        "%s", statusCode, statusMsg, (int)XSTRLEN(statusMsg), statusMsg);

    sent = (int)send(clientfd, response, (size_t)len, 0);
    return (sent == len) ? 0 : -1;
}

/* Map error codes to OCSP response status */
static enum Ocsp_Response_Status MapErrorToOcspStatus(int err)
{
    switch (err) {
        case ASN_PARSE_E:
            return OCSP_MALFORMED_REQUEST;
        case ASN_SIG_HASH_E:
            /* Unsupported hash algorithm */
            return OCSP_INTERNAL_ERROR;
        case ASN_NO_SIGNER_E:
            return OCSP_UNAUTHORIZED;
        case OCSP_CERT_UNKNOWN:
            return OCSP_UNAUTHORIZED;
        default:
            return OCSP_INTERNAL_ERROR;
    }
}

/* Main OCSP responder function */
THREAD_RETURN WOLFSSL_THREAD ocsp_responder_test(void* args)
{
    func_args* myargs = (func_args*)args;
    int argc = myargs->argc;
    char** argv = myargs->argv;
    int ret;
    int ch;

    OcspResponderOptions opts;
    OcspResponder* responder = NULL;
    IndexEntry* indexEntries = NULL;
    DecodedCert caCert;
    SOCKET_T sockfd = INVALID_SOCKET;
    SOCKET_T clientfd = INVALID_SOCKET;

    byte* caCertDer = NULL;
    word32 caCertDerSz = 0;
    byte* responderCertDer = NULL;
    word32 responderCertDerSz = 0;
    byte* caKeyDer = NULL;
    word32 caKeyDerSz = 0;

    byte httpBuf[MAX_REQUEST_SIZE];
    byte respBuf[MAX_RESPONSE_SIZE];
    word32 respSz;

    int requestsProcessed = 0;
    word32 caSubjectSz = 0;

    static const struct mygetopt_long_config long_options[] = {
        { "help", 0, '?' },
        { NULL, 0, 0 }
    };

    /* Initialize options */
    XMEMSET(&opts, 0, sizeof(opts));
    opts.port = DEFAULT_PORT;
    opts.nrequests = 0;
    opts.verbose = 0;
    opts.sendCerts = 1;
    opts.readyFile = NULL;

    /* Parse command line arguments */
    while ((ch = mygetopt_long(argc, argv, "?p:c:r:k:i:R:n:vx", long_options, 0)) != -1) {
        switch (ch) {
            case '?':
                Usage();
                ret = 0;
                goto cleanup;
            case 'p':
                opts.port = (word16)atoi(myoptarg);
                break;
            case 'c':
                opts.certFile = myoptarg;
                break;
            case 'r':
                opts.responderCertFile = myoptarg;
                break;
            case 'k':
                opts.keyFile = myoptarg;
                break;
            case 'i':
                opts.indexFile = myoptarg;
                break;
            case 'R':
                opts.readyFile = myoptarg;
                break;
            case 'n':
                opts.nrequests = atoi(myoptarg);
                break;
            case 'v':
                opts.verbose = 1;
                break;
            case 'x':
                opts.sendCerts = 0;
                break;
            default:
                Usage();
                ret = MY_EX_USAGE;
                goto cleanup;
        }
    }

    /* Validate required options */
    if (opts.certFile == NULL) {
        LOG_ERROR("Error: CA certificate required (-c)\n");
        Usage();
        ret = MY_EX_USAGE;
        goto cleanup;
    }
    if (opts.keyFile == NULL) {
        LOG_ERROR("Error: CA key required (-k)\n");
        Usage();
        ret = MY_EX_USAGE;
        goto cleanup;
    }

    /* Load CA certificate */
    ret = LoadCertDer(opts.certFile, &caCertDer, &caCertDerSz);
    if (ret != 0) {
        LOG_ERROR("Error loading CA certificate: %s\n", opts.certFile);
        ret = -1;
        goto cleanup;
    }
    if (opts.verbose) {
        LOG_MSG("Loaded CA certificate: %s (%d bytes)\n", opts.certFile, caCertDerSz);
    }

    /* Load responder certificate if provided */
    if (opts.responderCertFile != NULL) {
        ret = LoadCertDer(opts.responderCertFile, &responderCertDer, &responderCertDerSz);
        if (ret != 0) {
            LOG_ERROR("Error loading responder certificate: %s\n", opts.responderCertFile);
            ret = -1;
            goto cleanup;
        }
        if (opts.verbose) {
            LOG_MSG("Loaded responder certificate: %s (%d bytes)\n",
                    opts.responderCertFile, responderCertDerSz);
        }
    }

    /* Load CA key */
    ret = LoadKeyDer(opts.keyFile, &caKeyDer, &caKeyDerSz);
    if (ret != 0) {
        LOG_ERROR("Error loading signing key: %s\n", opts.keyFile);
        ret = -1;
        goto cleanup;
    }
    if (opts.verbose) {
        LOG_MSG("Loaded signing key: %s (%d bytes)\n", opts.keyFile, caKeyDerSz);
    }

    /* Parse CA certificate to get subject */
    XMEMSET(&caCert, 0, sizeof(caCert));
    wc_InitDecodedCert(&caCert, caCertDer, caCertDerSz, NULL);
    ret = wc_ParseCert(&caCert, CERT_TYPE, 0, NULL);
    if (ret != 0) {
        LOG_ERROR("Error parsing CA certificate: %d\n", ret);
        ret = -1;
        goto cleanup;
    }
    (void)wc_GetDecodedCertSubject(&caCert, &caSubjectSz);
    (void)caSubjectSz; /* Not used in current implementation */

    /* Load index file if provided */
    if (opts.indexFile) {
        indexEntries = ParseIndexFile(opts.indexFile);
        if (indexEntries == NULL) {
            LOG_ERROR("Warning: Could not parse index file: %s\n", opts.indexFile);
        }
        else if (opts.verbose) {
            LOG_MSG("Loaded index file: %s\n", opts.indexFile);
        }
    }

    /* Create OCSP responder */
    responder = wc_OcspResponder_new(NULL, opts.sendCerts);
    if (responder == NULL) {
        LOG_ERROR("Error creating OCSP responder\n");
        ret = -1;
        goto cleanup;
    }

    /* Add signer to responder */
    if (opts.responderCertFile != NULL) {
        /* Authorized responder: use responder cert as signer, CA cert as issuer */
        ret = wc_OcspResponder_AddSigner(responder, responderCertDer, responderCertDerSz,
                                      caKeyDer, caKeyDerSz, caCertDer, caCertDerSz);
        if (ret != 0) {
            LOG_ERROR("Error adding authorized responder to responder: %d\n", ret);
            goto cleanup;
        }
        if (opts.verbose) {
            LOG_MSG("Added authorized responder with CA issuer\n");
        }
    }
    else {
        /* CA as signer (self-signed) */
        ret = wc_OcspResponder_AddSigner(responder, caCertDer, caCertDerSz,
                                      caKeyDer, caKeyDerSz, NULL, 0);
        if (ret != 0) {
            LOG_ERROR("Error adding CA to responder: %d\n", ret);
            goto cleanup;
        }
        if (opts.verbose) {
            LOG_MSG("Added CA to responder\n");
        }
    }

    /* Populate responder with certificate statuses from index */
    if (indexEntries != NULL) {
        int statusCount = PopulateResponderFromIndex(responder, indexEntries, &caCert);
        if (statusCount < 0) {
            LOG_ERROR("Error populating responder from index: %d\n", statusCount);
        }
        else if (opts.verbose) {
            LOG_MSG("Populated responder with %d certificate statuses\n", statusCount);
        }
    }

    /* Create and listen on server socket */
    tcp_listen(&sockfd, &opts.port, 1, 0, 0);

    /* Write ready file if requested */
    if (opts.readyFile != NULL) {
        XFILE rf = XFOPEN(opts.readyFile, "w");
        if (rf != NULL) {
            fprintf(rf, "%d\n", (int)opts.port);
            fclose(rf);
            if (opts.verbose) {
                LOG_MSG("Ready file created: %s\n", opts.readyFile);
            }
        }
        else {
            LOG_ERROR("Warning: Failed to create ready file: %s\n", opts.readyFile);
        }
    }

#ifndef _WIN32
    /* Install signal handlers for clean shutdown */
    {
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = sig_handler;
        /* Do NOT set SA_RESTART so accept() is interrupted */
        sigaction(SIGTERM, &sa, NULL);
        sigaction(SIGINT, &sa, NULL);
    }
    if (opts.verbose) {
        LOG_MSG("Signal handlers installed\n");
    }
#endif

    /* Main loop */
    while ((opts.nrequests == 0 || requestsProcessed < opts.nrequests)
#ifndef _WIN32
           && !got_signal
#endif
          ) {
        struct sockaddr_in clientAddr;
        socklen_t clientAddrLen = sizeof(clientAddr);
        int recvLen;
        const byte* ocspReq;
        int ocspReqSz;
        char path[MAX_PATH_LEN];

        /* Accept connection */
        clientfd = accept(sockfd, (struct sockaddr*)&clientAddr, &clientAddrLen);
        if (clientfd == INVALID_SOCKET) {
            LOG_ERROR("accept() failed\n");
            continue;
        }

        if (opts.verbose) {
            LOG_MSG("Connection from %s:%d\n",
                   inet_ntoa(clientAddr.sin_addr), ntohs(clientAddr.sin_port));
        }

        /* Receive HTTP request */
        recvLen = RecvHttpRequest(clientfd, httpBuf, (int)sizeof(httpBuf));
        if (recvLen <= 0) {
            LOG_ERROR("recv() failed\n");
            close(clientfd);
            continue;
        }
        httpBuf[recvLen] = '\0';

        if (opts.verbose) {
            LOG_MSG("Received %d bytes\n", recvLen);
        }

        /* Parse HTTP request */
        ret = ParseHttpRequest(httpBuf, recvLen, &ocspReq, &ocspReqSz, path, sizeof(path));
        if (ret != 0 || ocspReq == NULL || ocspReqSz <= 0) {
            LOG_ERROR("Invalid HTTP request\n");
            SendHttpError(clientfd, 400, "Bad Request");
            close(clientfd);
            continue;
        }

        if (opts.verbose) {
            LOG_MSG("OCSP request: %d bytes, path: %s\n", ocspReqSz, path);
        }

        /* Process OCSP request and generate response */
        respSz = sizeof(respBuf);
        ret = wc_OcspResponder_WriteResponse(responder, ocspReq, (word32)ocspReqSz,
                                              respBuf, &respSz);

        if (ret != 0) {
            enum Ocsp_Response_Status errStatus;
            LOG_ERROR("Error generating OCSP response: %d\n", ret);

            /* Generate appropriate OCSP error response */
            errStatus = MapErrorToOcspStatus(ret);
            respSz = sizeof(respBuf);
            ret = wc_OcspResponder_WriteErrorResponse(errStatus, respBuf, &respSz);

            if (ret != 0) {
                /* If we can't even encode an error response, send HTTP error */
                LOG_ERROR("Error encoding OCSP error response: %d\n", ret);
                SendHttpError(clientfd, 500, "Internal Server Error");
                close(clientfd);
                continue;
            }

            if (opts.verbose) {
                LOG_MSG("Generated OCSP error response (status=%d): %d bytes\n",
                       errStatus, respSz);
            }
        }

        if (opts.verbose) {
            LOG_MSG("Generated OCSP response: %d bytes\n", respSz);
        }

        /* Send HTTP response */
        ret = SendHttpResponse(clientfd, respBuf, (int)respSz);
        if (ret != 0) {
            LOG_ERROR("Error sending response\n");
        }

        close(clientfd);
        clientfd = INVALID_SOCKET;
        requestsProcessed++;

        if (opts.verbose) {
            LOG_MSG("Processed request %d\n", requestsProcessed);
        }
    }

    ret = 0;

cleanup:
    if (clientfd != INVALID_SOCKET)
        close(clientfd);
    if (sockfd != INVALID_SOCKET)
        close(sockfd);

    wc_FreeDecodedCert(&caCert);

    if (responder)
        wc_OcspResponder_free(responder);
    if (indexEntries)
        FreeIndexEntries(indexEntries);
    if (caCertDer)
        XFREE(caCertDer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (responderCertDer)
        XFREE(responderCertDer, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (caKeyDer)
        XFREE(caKeyDer, NULL, DYNAMIC_TYPE_TMP_BUFFER);

#ifdef _WIN32
    WSACleanup();
#endif

    myargs->return_code = ret;
#ifndef WOLFSSL_THREAD_VOID_RETURN
    return (THREAD_RETURN)0;
#else
    return;
#endif
}

#ifndef NO_MAIN_DRIVER
int main(int argc, char** argv)
{
    func_args args;
    int ret;

#ifdef HAVE_WNR
    if (wc_InitNetRandom(wnrConfigFile, NULL, 5000) != 0) {
        err_sys("Whitewood netRandom global config failed");
    }
#endif

    ret = wolfSSL_Init();
    if (ret != WOLFSSL_SUCCESS) {
        err_sys("wolfSSL_Init failed");
    }

    args.argc = argc;
    args.argv = argv;
    args.return_code = 0;

    ocsp_responder_test(&args);

    wolfSSL_Cleanup();

#ifdef HAVE_WNR
    if (wc_FreeNetRandom() < 0)
        err_sys("Failed to free netRandom context");
#endif

    return args.return_code;
}
#endif /* !NO_MAIN_DRIVER */

#else /* HAVE_OCSP && HAVE_OCSP_RESPONDER && !NO_FILESYSTEM */

#ifndef NO_MAIN_DRIVER
int main(int argc, char** argv)
{
    (void)argc;
    (void)argv;
    printf("OCSP Responder requires HAVE_OCSP, HAVE_OCSP_RESPONDER, and filesystem support\n");
    return 0;
}
#endif

THREAD_RETURN WOLFSSL_THREAD ocsp_responder_test(void* args)
{
    func_args* myargs = (func_args*)args;
    printf("OCSP Responder requires HAVE_OCSP, HAVE_OCSP_RESPONDER, and filesystem support\n");
    myargs->return_code = 0;
    WOLFSSL_RETURN_FROM_THREAD(0);
}

#endif /* HAVE_OCSP && HAVE_OCSP_RESPONDER && !NO_FILESYSTEM */
