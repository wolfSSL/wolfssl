/* snifftest.c
 *
 * Copyright (C) 2006-2020 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */


#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/logging.h>

#ifdef WOLFSSL_SNIFFER_STORE_DATA_CB
    #include <wolfssl/wolfcrypt/memory.h>
#endif

#ifdef _WIN32
    #define WOLFSSL_SNIFFER
#endif

#ifndef WOLFSSL_SNIFFER
#ifndef NO_MAIN_DRIVER
/* blank build */
#include <stdio.h>
#include <stdlib.h>
int main(void)
{
    printf("do ./configure --enable-sniffer to enable build support\n");
    return EXIT_SUCCESS;
}
#endif /* !NO_MAIN_DRIVER */
#else
/* do a full build */

#ifdef _MSC_VER
    /* builds on *nix too, for scanf device and port */
    #define _CRT_SECURE_NO_WARNINGS
#endif

#include <pcap/pcap.h>     /* pcap stuff */
#include <stdio.h>         /* printf */
#include <stdlib.h>        /* EXIT_SUCCESS */
#include <string.h>        /* strcmp */
#include <signal.h>        /* signal */
#include <ctype.h>         /* isprint */

#include <cyassl/sniffer.h>


#ifndef _WIN32
    #include <sys/socket.h>    /* AF_INET */
    #include <arpa/inet.h>
    #include <netinet/in.h>
#endif

typedef unsigned char byte;

enum {
    ETHER_IF_FRAME_LEN = 14,   /* ethernet interface frame length */
    NULL_IF_FRAME_LEN =   4,   /* no link interface frame length  */
};


/* A TLS record can be 16k and change. The chain is broken up into 2K chunks.
 * This covers the TLS record, plus a chunk for TCP/IP headers. */
#ifndef CHAIN_INPUT_CHUNK_SIZE
    #define CHAIN_INPUT_CHUNK_SIZE 2048
#elif (CHAIN_INPUT_CHUNK_SIZE < 256)
    #undef CHAIN_INPUT_CHUNK_SIZE
    #define CHAIN_INPUT_CHUNK_SIZE 256
#elif (CHAIN_INPUT_CHUNK_SIZE > 16384)
    #undef CHAIN_INPUT_CHUNK_SIZE
    #define CHAIN_INPUT_CHUNK_SIZE 16384
#endif
#define CHAIN_INPUT_COUNT ((16384 / CHAIN_INPUT_CHUNK_SIZE) + 1)


#ifndef STORE_DATA_BLOCK_SZ
    #define STORE_DATA_BLOCK_SZ 1024
#endif


#define DEFAULT_SERVER_EPH_KEY_ECC "../../certs/statickeys/ecc-secp256r1.pem"
#define DEFAULT_SERVER_EPH_KEY_DH  "../../certs/statickeys/dh-ffdhe2048.pem"
#ifndef DEFAULT_SERVER_EPH_KEY
    #if defined(HAVE_ECC) && !defined(NO_ECC_SECP) && \
        (!defined(NO_ECC256) || defined(HAVE_ALL_CURVES))
        #if !defined(NO_DH)
            #define DEFAULT_SERVER_EPH_KEY DEFAULT_SERVER_EPH_KEY_ECC "," DEFAULT_SERVER_EPH_KEY_DH
        #else
            #define DEFAULT_SERVER_EPH_KEY DEFAULT_SERVER_EPH_KEY_ECC
        #endif
    #elif !defined(NO_DH)
        #define DEFAULT_SERVER_EPH_KEY DEFAULT_SERVER_EPH_KEY_DH
    #endif
#endif

#define DEFAULT_SERVER_KEY_RSA "../../certs/server-key.pem"
#define DEFAULT_SERVER_KEY_ECC "../../certs/ecc-key.pem"
#ifndef DEFAULT_SERVER_KEY
    #ifndef NO_RSA
        #define DEFAULT_SERVER_KEY DEFAULT_SERVER_KEY_RSA
    #elif defined(HAVE_ECC)
        #define DEFAULT_SERVER_KEY DEFAULT_SERVER_KEY_ECC
    #endif
#endif
     

#ifdef WOLFSSL_SNIFFER_WATCH
static const byte rsaHash[] = {
    0x4e, 0xa8, 0x55, 0x02, 0xe1, 0x84, 0x7e, 0xe1, 
    0xb5, 0x97, 0xd2, 0xf0, 0x92, 0x3a, 0xfd, 0x0d, 
    0x98, 0x26, 0x06, 0x85, 0x8d, 0xa4, 0xc7, 0x35, 
    0xd4, 0x74, 0x8f, 0xd0, 0xe7, 0xa8, 0x27, 0xaa
};
static const byte eccHash[] = {
    0x80, 0x3d, 0xff, 0xca, 0x2e, 0x20, 0xd9, 0xdf, 
    0xfe, 0x64, 0x4e, 0x25, 0x6a, 0xee, 0xee, 0x60, 
    0xc1, 0x48, 0x7b, 0xff, 0xa0, 0xfb, 0xeb, 0xac, 
    0xe2, 0xa4, 0xdd, 0xb5, 0x18, 0x38, 0x78, 0x38
};
#endif


pcap_t* pcap = NULL;
pcap_if_t* alldevs = NULL;


static void FreeAll(void)
{
    if (pcap)
        pcap_close(pcap);
    if (alldevs)
        pcap_freealldevs(alldevs);
#ifndef _WIN32
    ssl_FreeSniffer();
#endif
}


#ifdef WOLFSSL_SNIFFER_STATS
static void DumpStats(void)
{
    SSLStats sslStats;
    ssl_ReadStatistics(&sslStats);

    printf("SSL Stats (sslStandardConns):%lu\n",
            sslStats.sslStandardConns);
    printf("SSL Stats (sslClientAuthConns):%lu\n",
            sslStats.sslClientAuthConns);
    printf("SSL Stats (sslResumedConns):%lu\n",
            sslStats.sslResumedConns);
    printf("SSL Stats (sslEphemeralMisses):%lu\n",
            sslStats.sslEphemeralMisses);
    printf("SSL Stats (sslResumeMisses):%lu\n",
            sslStats.sslResumeMisses);
    printf("SSL Stats (sslCiphersUnsupported):%lu\n",
            sslStats.sslCiphersUnsupported);
    printf("SSL Stats (sslKeysUnmatched):%lu\n",
            sslStats.sslKeysUnmatched);
    printf("SSL Stats (sslKeyFails):%lu\n",
            sslStats.sslKeyFails);
    printf("SSL Stats (sslDecodeFails):%lu\n",
            sslStats.sslDecodeFails);
    printf("SSL Stats (sslAlerts):%lu\n",
            sslStats.sslAlerts);
    printf("SSL Stats (sslDecryptedBytes):%lu\n",
            sslStats.sslDecryptedBytes);
    printf("SSL Stats (sslEncryptedBytes):%lu\n",
            sslStats.sslEncryptedBytes);
    printf("SSL Stats (sslEncryptedPackets):%lu\n",
            sslStats.sslEncryptedPackets);
    printf("SSL Stats (sslDecryptedPackets):%lu\n",
            sslStats.sslDecryptedPackets);
    printf("SSL Stats (sslKeyMatches):%lu\n",
            sslStats.sslKeyMatches);
    printf("SSL Stats (sslEncryptedConns):%lu\n",
            sslStats.sslEncryptedConns);
}
#endif /* WOLFSSL_SNIFFER_STATS */


static void sig_handler(const int sig)
{
    printf("SIGINT handled = %d.\n", sig);
    FreeAll();
#ifdef WOLFSSL_SNIFFER_STATS
    DumpStats();
#endif
    if (sig)
        exit(EXIT_SUCCESS);
}


static void err_sys(const char* msg)
{
    fprintf(stderr, "%s\n", msg);
    if (msg)
        exit(EXIT_FAILURE);
}


#ifdef _WIN32
    #define SNPRINTF _snprintf
#else
    #define SNPRINTF snprintf
#endif


static char* iptos(const struct in_addr* addr)
{
    static char output[32];
    byte *p = (byte*)&addr->s_addr;

    snprintf(output, sizeof(output), "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);

    return output;
}

static const char* ip6tos(const struct in6_addr* addr)
{
    static char output[42];
    return inet_ntop(AF_INET6, addr, output, 42);
}


#if defined(WOLFSSL_SNIFFER_STORE_DATA_CB) || defined(WOLFSSL_SNIFFER_CHAIN_INPUT)
static inline unsigned int min(unsigned int a, unsigned int b)
{
    return a > b ? b : a;
}
#endif


#ifdef WOLFSSL_SNIFFER_WATCH
static int myWatchCb(void* vSniffer,
        const unsigned char* certHash, unsigned int certHashSz,
        const unsigned char* certChain, unsigned int certChainSz,
        void* ctx, char* error)
{
    const char* certName = NULL;

    (void)certChain;
    (void)certChainSz;
    (void)ctx;

    if (certHashSz == sizeof(rsaHash) &&
            XMEMCMP(certHash, rsaHash, certHashSz) == 0) {
        certName = DEFAULT_SERVER_KEY_RSA;
    }
    if (certHashSz == sizeof(eccHash) &&
            XMEMCMP(certHash, eccHash, certHashSz) == 0) {
        certName = DEFAULT_SERVER_KEY_ECC;
    }

    if (certName == NULL) {
        /* don't return error if key is not loaded */
        printf("Warning: No matching key found for cert hash\n");
        return 0;
    }

    return ssl_SetWatchKey_file(vSniffer, certName, FILETYPE_PEM, NULL, error);
}
#endif /* WOLFSSL_SNIFFER_WATCH */


#ifdef WOLFSSL_SNIFFER_STORE_DATA_CB
static int myStoreDataCb(const unsigned char* decryptBuf,
        unsigned int decryptBufSz, unsigned int decryptBufOffset, void* ctx)
{
    byte** data = (byte**)ctx;
    unsigned int qty;

    if (data == NULL)
        return -1;

    if (decryptBufSz < decryptBufOffset)
        return -1;

    qty = min(decryptBufSz - decryptBufOffset, STORE_DATA_BLOCK_SZ);

    if (*data == NULL) {
        byte* tmpData;
        tmpData = (byte*)XREALLOC(*data, decryptBufSz + 1,
                NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (tmpData == NULL) {
            XFREE(*data, NULL, DYNAMIC_TYPE_TMP_BUFFER);
            *data = NULL;
            return -1;
        }
        *data = tmpData;
    }

    XMEMCPY(*data + decryptBufOffset, decryptBuf + decryptBufOffset, qty);

    return qty;
}
#endif /* WOLFSSL_SNIFFER_STORE_DATA_CB */

/* try and load as both static ephemeral and private key */
/* only fail if no key is loaded */
/* Allow comma seperated list of files */
static int load_key(const char* name, const char* server, int port, 
    const char* keyFiles, const char* passwd, char* err)
{
    int ret = -1;
    int loadCount = 0;
    char *keyFile, *ptr = NULL;

    keyFile = XSTRTOK((char*)keyFiles, ",", &ptr);
    while (keyFile != NULL) {
#ifdef WOLFSSL_STATIC_EPHEMERAL
    #ifdef HAVE_SNI
        ret = ssl_SetNamedEphemeralKey(name, server, port, keyFile,
                            FILETYPE_PEM, passwd, err);
    #else
        ret = ssl_SetEphemeralKey(server, port, keyFile,
                            FILETYPE_PEM, passwd, err);
    #endif
        if (ret == 0)
            loadCount++;
#endif
    #ifdef HAVE_SNI
        ret = ssl_SetNamedPrivateKey(name, server, port, keyFile,
                            FILETYPE_PEM, passwd, err);
    #else
        ret = ssl_SetPrivateKey(server, port, keyFile,
                            FILETYPE_PEM, passwd, err);
    #endif
        if (ret == 0)
            loadCount++;
        
        if (loadCount == 0) {
            printf("Failed loading private key %s: ret %d\n", keyFile, ret);
            printf("Please run directly from sslSniffer/sslSnifferTest dir\n");
            ret = -1;
        }
        else {
            ret = 0;
        }

        keyFile = XSTRTOK(NULL, ",", &ptr);
    }

    (void)name;
    return ret;
}

int main(int argc, char** argv)
{
    int          ret = 0;
    int          hadBadPacket = 0;
    int          inum = 0;
    int          port = 0;
    int          saveFile = 0;
    int          i = 0, defDev = 0;
    int          frame = ETHER_IF_FRAME_LEN;
    char         err[PCAP_ERRBUF_SIZE];
    char         filter[32];
    const char  *keyFilesSrc = NULL;
    char         keyFilesBuf[MAX_FILENAME_SZ];
    char         keyFilesUser[MAX_FILENAME_SZ];
    const char  *server = NULL;
    const char  *sniName = NULL;
    struct       bpf_program fp;
    pcap_if_t   *d;
    pcap_addr_t *a;
#ifdef WOLFSSL_SNIFFER_CHAIN_INPUT
    struct iovec chain[CHAIN_INPUT_COUNT];
    int          chainSz;
#endif

    signal(SIGINT, sig_handler);

#ifndef _WIN32
    ssl_InitSniffer();   /* dll load on Windows */
#endif
#ifdef DEBUG_WOLFSSL
    //wolfSSL_Debugging_ON();
#endif
    ssl_Trace("./tracefile.txt", err);
    ssl_EnableRecovery(1, -1, err);
#ifdef WOLFSSL_SNIFFER_WATCH
    ssl_SetWatchKeyCallback(myWatchCb, err);
#endif
#ifdef WOLFSSL_SNIFFER_STORE_DATA_CB
    ssl_SetStoreDataCallback(myStoreDataCb);
#endif

    if (argc == 1) {
        char cmdLineArg[128];
        /* normal case, user chooses device and port */

        if (pcap_findalldevs(&alldevs, err) == -1)
            err_sys("Error in pcap_findalldevs");

        for (d = alldevs; d; d=d->next) {
            printf("%d. %s", ++i, d->name);
            if (strcmp(d->name, "lo0") == 0) {
                defDev = i;
            }
            if (d->description)
                printf(" (%s)\n", d->description);
            else
                printf(" (No description available)\n");
        }

        if (i == 0)
            err_sys("No interfaces found! Make sure pcap or WinPcap is"
                    " installed correctly and you have sufficient permissions");

        printf("Enter the interface number (1-%d) [default: %d]: ", i, defDev);
        XMEMSET(cmdLineArg, 0, sizeof(cmdLineArg));
        if (XFGETS(cmdLineArg, sizeof(cmdLineArg), stdin))
            inum = XATOI(cmdLineArg);
        if (inum == 0)
            inum = defDev;
        else if (inum < 1 || inum > i)
            err_sys("Interface number out of range");

        /* Jump to the selected adapter */
        for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

        pcap = pcap_create(d->name, err);

        if (pcap == NULL) printf("pcap_create failed %s\n", err);

        /* print out addresses for selected interface */
        for (a = d->addresses; a; a = a->next) {
            if (a->addr->sa_family == AF_INET) {
                server =
                    iptos(&((struct sockaddr_in *)a->addr)->sin_addr);
                printf("server = %s\n", server);
            }
            else if (a->addr->sa_family == AF_INET6) {
                server =
                    ip6tos(&((struct sockaddr_in6 *)a->addr)->sin6_addr);
                printf("server = %s\n", server);
            }
        }
        if (server == NULL)
            err_sys("Unable to get device IPv4 or IPv6 address");

        ret = pcap_set_snaplen(pcap, 65536);
        if (ret != 0) printf("pcap_set_snaplen failed %s\n", pcap_geterr(pcap));

        ret = pcap_set_timeout(pcap, 1000);
        if (ret != 0) printf("pcap_set_timeout failed %s\n", pcap_geterr(pcap));

        ret = pcap_set_buffer_size(pcap, 1000000);
        if (ret != 0)
            printf("pcap_set_buffer_size failed %s\n", pcap_geterr(pcap));

        ret = pcap_set_promisc(pcap, 1);
        if (ret != 0) printf("pcap_set_promisc failed %s\n", pcap_geterr(pcap));


        ret = pcap_activate(pcap);
        if (ret != 0) printf("pcap_activate failed %s\n", pcap_geterr(pcap));

        printf("Enter the port to scan [default: 11111]: ");
        XMEMSET(cmdLineArg, 0, sizeof(cmdLineArg));
        if (XFGETS(cmdLineArg, sizeof(cmdLineArg), stdin)) {
            port = XATOI(cmdLineArg);
        }
        if (port <= 0)
            port = 11111;

        SNPRINTF(filter, sizeof(filter), "tcp and port %d", port);

        ret = pcap_compile(pcap, &fp, filter, 0, 0);
        if (ret != 0) printf("pcap_compile failed %s\n", pcap_geterr(pcap));

        ret = pcap_setfilter(pcap, &fp);
        if (ret != 0) printf("pcap_setfilter failed %s\n", pcap_geterr(pcap));

        /* optionally enter the private key to use */
    #if defined(WOLFSSL_STATIC_EPHEMERAL) && defined(DEFAULT_SERVER_EPH_KEY)
        keyFilesSrc = DEFAULT_SERVER_EPH_KEY;
    #else
        keyFilesSrc = DEFAULT_SERVER_KEY;
    #endif
        printf("Enter the server key [default: %s]: ", keyFilesSrc);
        XMEMSET(keyFilesBuf, 0, sizeof(keyFilesBuf));
        XMEMSET(keyFilesUser, 0, sizeof(keyFilesUser));
        if (XFGETS(keyFilesUser, sizeof(keyFilesUser), stdin)) {
            word32 strSz;
            if (keyFilesUser[0] != '\r' && keyFilesUser[0] != '\n') {
                keyFilesSrc = keyFilesUser;
            }
            strSz = (word32)XSTRLEN(keyFilesUser);
            if (keyFilesUser[strSz-1] == '\n')
                keyFilesUser[strSz-1] = '\0';
        }
        XSTRNCPY(keyFilesBuf, keyFilesSrc, sizeof(keyFilesBuf));

        /* optionally enter a named key (SNI) */
    #if !defined(WOLFSSL_SNIFFER_WATCH) && defined(HAVE_SNI)
        printf("Enter alternate SNI [default: none]: ");
        XMEMSET(cmdLineArg, 0, sizeof(cmdLineArg));
        if (XFGETS(cmdLineArg, sizeof(cmdLineArg), stdin)) {
            if (XSTRLEN(cmdLineArg) > 0) {
                sniName = cmdLineArg;
            }
        }
    #endif /* !WOLFSSL_SNIFFER_WATCH && HAVE_SNI */

        /* get IPv4 or IPv6 addresses for selected interface */
        for (a = d->addresses; a; a = a->next) {
            server = NULL;
            if (a->addr->sa_family == AF_INET) {
                server =
                    iptos(&((struct sockaddr_in *)a->addr)->sin_addr);
            }
            else if (a->addr->sa_family == AF_INET6) {
                server =
                    ip6tos(&((struct sockaddr_in6 *)a->addr)->sin6_addr);
            }

            if (server) {
                XSTRNCPY(keyFilesBuf, keyFilesSrc, sizeof(keyFilesBuf));
                ret = load_key(sniName, server, port, keyFilesBuf, NULL, err);
                if (ret != 0) {
                    exit(EXIT_FAILURE);
                }
            }
        }
    }
    else if (argc >= 3) {
        saveFile = 1;
        pcap = pcap_open_offline(argv[1], err);
        if (pcap == NULL) {
            printf("pcap_open_offline failed %s\n", err);
            ret = -1;
        }
        else {
            const char* passwd = NULL;

            /* defaults for server and port */
            port = 443;
            server = "127.0.0.1";
            keyFilesSrc = argv[2];

            if (argc >= 4)
                server = argv[3];

            if (argc >= 5)
                port = XATOI(argv[4]);

            if (argc >= 6)
                passwd = argv[5];

            ret = load_key(NULL, server, port, keyFilesSrc, passwd, err);
            if (ret != 0) {
                exit(EXIT_FAILURE);
            }

            /* Only let through TCP/IP packets */
            ret = pcap_compile(pcap, &fp, "(ip6 or ip) and tcp", 0, 0);
            if (ret != 0) {
                printf("pcap_compile failed %s\n", pcap_geterr(pcap));
                exit(EXIT_FAILURE);
            }

            ret = pcap_setfilter(pcap, &fp);
            if (ret != 0) {
                printf("pcap_setfilter failed %s\n", pcap_geterr(pcap));
                exit(EXIT_FAILURE);
            }
        }
    }
    else {
        /* usage error */
        printf( "usage: ./snifftest or ./snifftest dump pemKey"
                " [server] [port] [password]\n");
        exit(EXIT_FAILURE);
    }

    if (ret != 0)
        err_sys(err);

    if (pcap_datalink(pcap) == DLT_NULL)
        frame = NULL_IF_FRAME_LEN;

    while (1) {
        static int packetNumber = 0;
        struct pcap_pkthdr header;
        const unsigned char* packet = pcap_next(pcap, &header);
        SSLInfo sslInfo;
        packetNumber++;
        if (packet) {

            byte* data = NULL;

            if (header.caplen > 40)  { /* min ip(20) + min tcp(20) */
                packet        += frame;
                header.caplen -= frame;
            }
            else
                continue;
#ifdef WOLFSSL_SNIFFER_CHAIN_INPUT
            {
                unsigned int j = 0;
                unsigned int remainder = header.caplen;

                chainSz = 0;
                do {
                    unsigned int chunkSz;

                    chunkSz = min(remainder, CHAIN_INPUT_CHUNK_SIZE);
                    chain[chainSz].iov_base = (void*)(packet + j);
                    chain[chainSz].iov_len = chunkSz;
                    j += chunkSz;
                    remainder -= chunkSz;
                    chainSz++;
                } while (j < header.caplen);
            }
#endif

#if defined(WOLFSSL_SNIFFER_CHAIN_INPUT) && \
    defined(WOLFSSL_SNIFFER_STORE_DATA_CB)
            ret = ssl_DecodePacketWithChainSessionInfoStoreData(chain, chainSz,
                    &data, &sslInfo, err);
#elif defined(WOLFSSL_SNIFFER_CHAIN_INPUT)
            (void)sslInfo;
            ret = ssl_DecodePacketWithChain(chain, chainSz, &data, err);
#elif defined(WOLFSSL_SNIFFER_STORE_DATA_CB)
            ret = ssl_DecodePacketWithSessionInfoStoreData(packet,
                    header.caplen, &data, &sslInfo, err);
#else
            ret = ssl_DecodePacketWithSessionInfo(packet, header.caplen, &data,
                                                  &sslInfo, err);
#endif
            if (ret < 0) {
                printf("ssl_Decode ret = %d, %s\n", ret, err);
                hadBadPacket = 1;
            }
            if (ret > 0) {
                int j;
                /* Convert non-printable data to periods. */
                for (j = 0; j < ret; j++) {
                    if (isprint(data[j]) || isspace(data[j])) continue;
                    data[j] = '.';
                }
                data[ret] = 0;
                printf("SSL App Data(%d:%d):%s\n", packetNumber, ret, data);
                ssl_FreeZeroDecodeBuffer(&data, ret, err);
            }
        }
        else if (saveFile)
            break;      /* we're done reading file */
    }
    FreeAll();

    return hadBadPacket ? EXIT_FAILURE : EXIT_SUCCESS;
}

#endif /* full build */
