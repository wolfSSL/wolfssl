/* ocsp.c
 *
 * Copyright (C) 2006-2012 Sawtooth Consulting Ltd.
 *
 * This file is part of CyaSSL.
 *
 * CyaSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * CyaSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <cyassl/error.h>
#include <cyassl/ocsp.h>
#include <cyassl/internal.h>
#include <ctype.h>

#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>


#ifdef HAVE_OCSP
CYASSL_API int ocsp_test(unsigned char* buf, int sz);
#define CYASSL_OCSP_ENABLE       0x0001 /* Enable OCSP lookups */
#define CYASSL_OCSP_URL_OVERRIDE 0x0002 /* Use the override URL instead of URL
                                         * in certificate */

typedef struct sockaddr_in  SOCKADDR_IN_T;
#define AF_INET_V    AF_INET
#define SOCKET_T unsigned int
   

int ocsp_test(unsigned char* buf, int sz)
{
    CYASSL_OCSP ocsp;
    OcspResponse resp;
    int result;
    
    CyaSSL_OCSP_Init(&ocsp);
    InitOcspResponse(&resp, buf, sz, NULL);

    ocsp.enabled = 1;
    ocsp.useOverrideUrl = 1;
    CyaSSL_OCSP_set_override_url(&ocsp, "http://ocsp.example.com:8080/bob");
    CyaSSL_OCSP_Lookup_Cert(&ocsp, NULL);

    result = OcspResponseDecode(&resp);
    
    FreeOcspResponse(&resp);
    CyaSSL_OCSP_Cleanup(&ocsp);

    return result;
}


int CyaSSL_OCSP_Init(CYASSL_OCSP* ocsp)
{
    if (ocsp != NULL) {
        XMEMSET(ocsp, 0, sizeof(*ocsp));
        return 0;
    }

    return -1;
}


void CyaSSL_OCSP_Cleanup(CYASSL_OCSP* ocsp)
{
    ocsp->enabled = 0;
    /* Deallocate memory */
}


int CyaSSL_OCSP_set_override_url(CYASSL_OCSP* ocsp, const char* url)
{
    if (ocsp != NULL && url != NULL) {
        int i, cur, hostname;

        /* need to break the url down into scheme, address, and port */
        /* "http://example.com:8080/" */
        if (XSTRNCMP(url, "http://", 7) == 0) {
            cur = 7;
        } else cur = 0;

        i = 0;
        while (url[cur] != 0 && url[cur] != ':' && url[cur] != '/') {
            ocsp->overrideName[i++] = url[cur++];
        }
        ocsp->overrideName[i] = 0;
        /* Need to pick out the path after the domain name */

        if (url[cur] == ':') {
            char port[6];
            int j;
            i = 0;
            cur++;
            while (url[cur] != 0 && url[cur] != '/' && i < 6) {
                port[i++] = url[cur++];
            }

            ocsp->overridePort = 0;
            for (j = 0; j < i; j++) {
                if (port[j] < '0' || port[j] > '9') return -1;
                ocsp->overridePort = 
                            (ocsp->overridePort * 10) + (port[j] - '0');
            }
        }
        else
            ocsp->overridePort = 80;

        return 1;
    }

    return 0;
}


static INLINE void tcp_socket(SOCKET_T* sockfd, SOCKADDR_IN_T* addr,
                              const char* peer, word16 port)
{
    const char* host = peer;

    /* peer could be in human readable form */
    if (peer != INADDR_ANY && isalpha(peer[0])) {
        struct hostent* entry = gethostbyname(peer);

        if (entry) {
            struct sockaddr_in tmp;
            memset(&tmp, 0, sizeof(struct sockaddr_in));
            memcpy(&tmp.sin_addr.s_addr, entry->h_addr_list[0],
                   entry->h_length);
            host = inet_ntoa(tmp.sin_addr);
        }
        else
            CYASSL_MSG("no entry for host");
    }

    *sockfd = socket(AF_INET_V, SOCK_STREAM, 0);
    memset(addr, 0, sizeof(SOCKADDR_IN_T));

    addr->sin_family = AF_INET_V;
    addr->sin_port = htons(port);
    if (host == INADDR_ANY)
        addr->sin_addr.s_addr = INADDR_ANY;
    else
        addr->sin_addr.s_addr = inet_addr(host);
}


static INLINE void tcp_connect(SOCKET_T* sockfd, const char* ip, word16 port)
{
    SOCKADDR_IN_T addr;
    tcp_socket(sockfd, &addr, ip, port);

    if (connect(*sockfd, (const struct sockaddr*)&addr, sizeof(addr)) != 0)
        CYASSL_MSG("tcp connect failed");
}


static void close_connection();

const char http_ocsp_pre[]  = "POST ";
const char http_ocsp_post[] = " HTTP/1.1\r\nHost: ";
const char http_ocsp_len[]  = "\r\nContent-Length: ";
const char http_ocsp_type[] = "\r\nContent-Type: application/ocsp-request"
                              "\r\n\r\n";
const char arglebargle[] = "arglebargle";


int CyaSSL_OCSP_Lookup_Cert(CYASSL_OCSP* ocsp, DecodedCert* cert)
{
    SOCKET_T sfd = -1;
	char buf[1024];
	int bufRemainder = 1023;

    /* If OCSP lookups are disabled, return success. */
    if (!ocsp->enabled) return 1;

    /* If OCSP lookups are enabled, but URL Override is disabled, return 
    ** a failure. Need to have an override URL for right now. */
    if (!ocsp->useOverrideUrl || cert == NULL) return 0;

    XMEMCPY(ocsp->status[0].subjectHash, cert->subjectHash, SHA_SIZE);
    XMEMCPY(ocsp->status[0].issuerHash, cert->issuerHash, SHA_SIZE);
    XMEMCPY(ocsp->status[0].serial, cert->serial, cert->serialSz);
    ocsp->status[0].serialSz = cert->serialSz;

//    tcp_connect(&sfd, ocsp->overrideName, ocsp->overridePort);

	memset(buf, 0, sizeof(buf));

    strncat(buf, http_ocsp_pre, bufRemainder);
	bufRemainder -= strlen(http_ocsp_pre);

	strncat(buf, "/", bufRemainder);
	bufRemainder -= 1;
    
	strncat(buf, http_ocsp_post, bufRemainder);
	bufRemainder -= strlen(http_ocsp_post);
    
	strncat(buf, ocsp->overrideName, bufRemainder);
	bufRemainder -= strlen(ocsp->overrideName);
    
	strncat(buf, http_ocsp_len, bufRemainder);
	bufRemainder -= strlen(http_ocsp_len);
   
	strncat(buf, "11", bufRemainder);
	bufRemainder -= 2;

	strncat(buf, http_ocsp_type, bufRemainder);
	bufRemainder -= strlen(http_ocsp_type);

	strncat(buf, arglebargle, bufRemainder);
	bufRemainder -= strlen(arglebargle);

//    close(sfd);

    return 1;
}


#endif /* HAVE_OCSP */

