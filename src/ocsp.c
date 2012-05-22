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
}


static int decode_url(const char* url, int urlSz,
	char* outName, char* outPath, int* outPort)
{
	if (outName != NULL && outPath != NULL && outPort != NULL)
	{
		if (url == NULL || urlSz == 0)
		{
			*outName = 0;
			*outPath = 0;
			*outPort = 0;
		}
		else
		{
	        int i, cur, hostname;
	
	        /* need to break the url down into scheme, address, and port */
	        /* "http://example.com:8080/" */
	        if (XSTRNCMP(url, "http://", 7) == 0) {
	            cur = 7;
	        } else cur = 0;
	
	        i = 0;
	        while (url[cur] != 0 && url[cur] != ':' && url[cur] != '/') {
	            outName[i++] = url[cur++];
	        }
	        outName[i] = 0;
	        /* Need to pick out the path after the domain name */
	
	        if (cur < urlSz && url[cur] == ':') {
	            char port[6];
	            int j;
	            i = 0;
	            cur++;
	            while (cur < urlSz && url[cur] != 0 && url[cur] != '/' &&
						i < 6) {
	                port[i++] = url[cur++];
	            }
	
	            *outPort = 0;
	            for (j = 0; j < i; j++) {
	                if (port[j] < '0' || port[j] > '9') return -1;
	                *outPort = (*outPort * 10) + (port[j] - '0');
	            }
	        }
	        else
	            *outPort = 80;
	
	        if (cur < urlSz && url[cur] == '/') {
	            i = 0;
	            while (cur < urlSz && url[cur] != 0 && i < 80) {
	                outPath[i++] = url[cur++];
	            }
	            outPath[i] = 0;
	        }
	        else {
	            outPath[0] = '/';
	            outPath[1] = 0;
	        }
		}
	}

	return 0;
}


int CyaSSL_OCSP_set_override_url(CYASSL_OCSP* ocsp, const char* url)
{
    if (ocsp != NULL) {
		int urlSz = strlen(url);
		decode_url(url, urlSz,
			ocsp->overrideName, ocsp->overridePath, &ocsp->overridePort);
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


static int build_http_request(const char* domainName, const char* path,
									int ocspReqSz, byte* buf, int bufSize)
{
    return snprintf((char*)buf, bufSize,
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Length: %d\r\n"
        "Content-Type: application/ocsp-request\r\n"
        "\r\n", 
        path, domainName, ocspReqSz);
}


static byte* decode_http_response(byte* httpBuf, int httpBufSz, int* ocspRespSz)
{
    int idx = 0;
    int stop = 0;
    byte* contentType = NULL;
    byte* contentLength = NULL;
    byte* content = NULL;
    char* buf = (char*)httpBuf; /* kludge so I'm not constantly casting */

    if (strncasecmp(buf, "HTTP/1", 6) != 0)
        return NULL;
    
    idx = 9; /* sets to the first byte after "HTTP/1.X ", which should be the
              * HTTP result code */

     if (strncasecmp(&buf[idx], "200 OK", 6) != 0)
        return NULL;
    
    idx += 8;

    while (idx < httpBufSz && !stop) {
        if (buf[idx] == '\r' && buf[idx+1] == '\n') {
            stop = 1;
            idx += 2;
        }
        else {
            if (contentType == NULL &&
                strncasecmp(&buf[idx], "Content-Type:", 13) == 0) {
                idx += 13;
                if (buf[idx] == ' ') idx++;
                if (strncasecmp(&buf[idx], "application/ocsp-response", 25) != 0)
                    return NULL;
                idx += 27;
            } else if (contentLength == NULL &&
                strncasecmp(&buf[idx], "Content-Length:", 15) == 0) {
                int len = 0;
                idx += 15;
                if (buf[idx] == ' ') idx++;
                while (buf[idx] >= '0' && buf[idx] <= '9' && idx < httpBufSz) {
                    len = (len * 10) + (buf[idx] - '0');
                    idx++;
                }
                *ocspRespSz = len;
                idx += 2; /* skip the crlf */
            } else {
                /* Advance idx past the next \r\n */
                char* end = strstr(&buf[idx], "\r\n");
                idx = end - buf + 2;
                stop = 1;
            }
        }
    }
    return &httpBuf[idx];
}


#define SCRATCH_BUFFER_SIZE 2048

int CyaSSL_OCSP_Lookup_Cert(CYASSL_OCSP* ocsp, DecodedCert* cert)
{
    SOCKET_T sfd = -1;
    byte buf[SCRATCH_BUFFER_SIZE];
    byte* httpBuf = &buf[0];
    int httpBufSz = SCRATCH_BUFFER_SIZE/4;
    byte* ocspReqBuf = &buf[httpBufSz];
    int ocspReqSz = SCRATCH_BUFFER_SIZE - httpBufSz;
    OcspResponse ocspResponse;
    int result = 0;
	char domainName[80], path[80];
	int port;

    /* If OCSP lookups are disabled, return success. */
    if (!ocsp->enabled) {
        CYASSL_MSG("OCSP lookup disabled, assuming CERT_GOOD");
        return 0;
    }

    if (ocsp->useOverrideUrl || cert->extAuthInfo == NULL) {
    	if (ocsp->overrideName != NULL) {
			XMEMCPY(domainName, ocsp->overrideName, 80);
			XMEMCPY(path, ocsp->overridePath, 80);
			port = ocsp->overridePort;
		} else
			return OCSP_NEED_URL;
	} else {
		if (!decode_url((const char*)cert->extAuthInfo, cert->extAuthInfoSz,
													domainName, path, &port))
			return OCSP_NEED_URL;
	}

    XMEMCPY(ocsp->status[0].issuerHash, cert->issuerHash, SHA_SIZE);
    XMEMCPY(ocsp->status[0].issuerKeyHash, cert->issuerKeyHash, SHA_SIZE);
    XMEMCPY(ocsp->status[0].serial, cert->serial, cert->serialSz);
    ocsp->status[0].serialSz = cert->serialSz;
    ocsp->statusLen = 1;

    ocspReqSz = EncodeOcspRequest(cert, ocspReqBuf, ocspReqSz);
    httpBufSz = build_http_request(domainName, path, ocspReqSz,
														httpBuf, httpBufSz);

    tcp_connect(&sfd, domainName, port);
    if (sfd > 0) {
        int written;
        written = write(sfd, httpBuf, httpBufSz);
        if (written == httpBufSz) {
            written = write(sfd, ocspReqBuf, ocspReqSz);
            if (written == ocspReqSz) {
                httpBufSz = read(sfd, buf, SCRATCH_BUFFER_SIZE);
                if (httpBufSz > 0) {
                    ocspReqBuf = decode_http_response(buf, httpBufSz,
                        &ocspReqSz);
                }
            }
        }
        close(sfd);
        if (ocspReqBuf == NULL) {
            CYASSL_MSG("HTTP response was not OK, no OCSP response");
            return OCSP_LOOKUP_FAIL;
        }
    } else {
        CYASSL_MSG("OCSP Responder connection failed");
        return OCSP_LOOKUP_FAIL;
    }

    InitOcspResponse(&ocspResponse, ocspReqBuf, ocspReqSz, NULL);
    OcspResponseDecode(&ocspResponse);

    if (ocspResponse.responseStatus != OCSP_SUCCESSFUL) {
        CYASSL_MSG("OCSP Responder failure");
		result = OCSP_LOOKUP_FAIL;
    } else {
		switch (ocspResponse.certStatus[0]) {
			case CERT_GOOD:
				result = 0;
				break;
			case CERT_REVOKED:
				result = OCSP_CERT_REVOKED;
				break;
			default:
				result = OCSP_CERT_UNKNOWN;
				break;
		}
    }
    FreeOcspResponse(&ocspResponse);

    return result;
}


#endif /* HAVE_OCSP */

