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


#ifdef HAVE_OCSP
CYASSL_API int ocsp_test(unsigned char* buf, int sz);
#define CYASSL_OCSP_ENABLE       0x0001 /* Enable OCSP lookups */
#define CYASSL_OCSP_URL_OVERRIDE 0x0002 /* Use the override URL instead of URL
                                         * in certificate */


int ocsp_test(unsigned char* buf, int sz)
{
    CYASSL_OCSP ocsp;
    OcspResponse resp;
    int result;
    
    CyaSSL_OCSP_Init(&ocsp);
    InitOcspResponse(&resp, buf, sz, NULL);

    ocsp.enabled = 1;
    ocsp.useOverrideUrl = 1;
    CyaSSL_OCSP_set_override_url(&ocsp, "http://ocsp.example.com:8080/");
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


int CyaSSL_OCSP_Lookup_Cert(CYASSL_OCSP* ocsp, DecodedCert* cert)
{
    /* If OCSP lookups are disabled, return success. */
    if (!ocsp->enabled) return 1;

    /* If OCSP lookups are enabled, but URL Override is disabled, return 
    ** a failure. Need to have an override URL for right now. */
    if (!ocsp->useOverrideUrl || cert == NULL) return 0;

    XMEMCPY(ocsp->status[0].subjectHash, cert->subjectHash, SHA_SIZE);
    XMEMCPY(ocsp->status[0].issuerHash, cert->issuerHash, SHA_SIZE);
    XMEMCPY(ocsp->status[0].serial, cert->serial, cert->serialSz);
    ocsp->status[0].serialSz = cert->serialSz;

    return 1;
}


#endif /* HAVE_OCSP */

