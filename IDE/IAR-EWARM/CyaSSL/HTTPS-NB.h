/* HTTPS-NB.h
 *
 * Copyright (C) 2006-2014 wolfSSL Inc.
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
 
#ifndef HTTPS_NB_H
#define HTTPS_NB_H

extern int CyaSSL_GetDataFromPbuf(char *buff, struct pbuf *p, int size) ;

#define IP4_LONG_2_ADDR(ipaddr, iplong) \
        (ipaddr)->addr = htonl(((u32_t)(iplong) & 0xFF000000) | \
                               ((u32_t)(iplong) & 0xFF0000)   | \
                               ((u32_t)(iplong) & 0xFF00)     | \
                                (u32_t)(iplong) & 0xFF)

#define IP_ADDR(a,b,c,d) (((a)|((b)<<8)|((c)<<16)|(d)<<24))

enum HTTPS_Stat {
    BEGIN,
    GET_MYIP,
    INITIALIZED,
    TCP_CONNECT,
    TCP_CONNECTED,
    SSL_INIT,
    SSL_CONN,
    SSL_CONN_WAITING,
    HTTP_SEND,
    HTTP_RECEIVE,
    HTTP_DONE,
    SSL_CLOSE,
    TCP_CLOSE,
    WAITING,
    IDLE
} ;


#define HTTPS_PORT 443

typedef struct {
    CYASSL *ssl ;
    CYASSL_CTX *ctx ;
    enum HTTPS_Stat stat ;
    struct tcp_pcb * pcb ;
    unsigned long ipaddress ;
    struct ip_addr localIP_em;
    unsigned long localPort ;
    struct ip_addr serverIP_em ;
    unsigned long serverPort ;
    char   *hostname ;
    char   *path ;
    int    idle ;
    int    wait_cnt ; /* wait tick counter */
} CYASSL_HTTPS_NB ;

extern void CyaSSL_HTTPS_Client_NB_init(void *nb, 
     struct ip_addr svIP, unsigned long svPort, char *host, char *path) ;
extern int CyaSSL_HTTPS_Client_NB(void *nb) ;

#endif
