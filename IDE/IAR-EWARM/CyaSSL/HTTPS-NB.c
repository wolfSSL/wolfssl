/* HTTPS-NB.c
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

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
 
#include <cyassl/ctaocrypt/settings.h>
 
#if defined(CYASSL_MDK_ARM)
      #include <stdio.h>
        #include <string.h>
        #include <rtl.h>
        #include "cyassl_MDK_ARM.h"
#endif

#if defined(CYASSL_IAR_ARM)
    #include <stdio.h>
    #include <string.h>
#endif

#if defined(CYASSL_LWIP)
#include "lwip/tcp.h"
#include "lwip/sockets.h"
#endif

#include <cyassl/ctaocrypt/settings.h>
#include <cyassl/ssl.h>
#include <cyassl/ctaocrypt/memory.h>
#include "SSL-NB.h"
#include "HTTPS-NB.h"

#if 0
/*Enable debug*/
#include <cstdio>
#define DBG_PRINTF(x, ...) printf("[HTTPSClient : DBG]"x"\r\n", ##__VA_ARGS__);
#else
/*Disable debug*/
#define DBG_PRINTF(x, ...)
#endif

#define ERR_PRINTF(x, ...) printf("[HTTPSClient:ERROR]"x"\r\n", ##__VA_ARGS__);

static unsigned long localPort = 0 ;
static unsigned long getPort(void) {
      return (localPort++ + 0x200) & 0x7fff ;
}


static err_t DataConnectedCallback (void *arg, struct tcp_pcb *pcb, s8_t err)
{
    *(enum HTTPS_Stat *)arg = TCP_CONNECTED ;
    return ERR_OK;
}

static err_t DataSentCallback (void *arg, struct tcp_pcb *pcb, u16_t err)
{
    DBG_PRINTF("LwIPtest: Data Sent(SentCallBack1)\n") ;
    return ERR_OK;
}

static err_t DataReceiveCallback(void *cb, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    struct pbuf *next ;
    CYASSL_NB *ssl_nb ;
    ssl_nb = (CYASSL_NB *)cb ;
    
    DBG_PRINTF("LwIPtest: Data Received(DataReceiveCallback), pbuf->len=%d, err=%d\n", p->tot_len , err) ;
    
    if(p==0) { /* throw away */
        return ERR_OK ;
    }
    if(*(enum HTTPS_Stat *)(ssl_nb->arg) == WAITING) {
        *(enum HTTPS_Stat *)(ssl_nb->arg) = HTTP_RECEIVE ;
    } else { 
        CyaSSL_PbufFree(p) ;
        tcp_recved(pcb,p->tot_len) ;
        return ERR_OK ;
    }
    /* put it into the queue */
    if(ssl_nb->pbuf) {
        next = ssl_nb->pbuf ;
        while(1) {
            DBG_PRINTF("pbuf=%x, pbuf->next=%x, ",ssl_nb->pbuf, next) ;
            if(next->next)
                next = next->next ;
            else break ;
        }
        next->next = p ;
        ssl_nb->pbuf->tot_len += p->tot_len ;
    } else {
        ssl_nb->pbuf = p ;
    }
    ssl_nb->pulled = 0 ;

    if(ssl_nb->wait < 0)
        ssl_nb->wait = 1000 ;
    ssl_nb->pulled = 0 ;
    return ERR_OK;
}

static int count = 0 ;

void CyaSSL_HTTPS_Client_NB_init(void *nb, 
     struct ip_addr svIP, unsigned long svPort, char *host, char *path)
{
    CYASSL_HTTPS_NB *https_nb ;
    https_nb = (CYASSL_HTTPS_NB *)nb ;
    
    https_nb->serverIP_em = svIP ;
    https_nb->serverPort = svPort ;
    https_nb->hostname = host ;
    https_nb->path = path ;
    
    https_nb->stat = BEGIN ;
    
}

int CyaSSL_HTTPS_Client_NB(void *nb)
{
    char *p ;
    int ret ;
    CYASSL_HTTPS_NB *https_nb ;
    CYASSL_NB       *ssl_nb ;
    
    https_nb = (CYASSL_HTTPS_NB *)nb ;
    ssl_nb   = (CYASSL_NB       *)&(https_nb->ssl_nb) ;
    
    /*CyaSSL_Debugging_ON() ; */

    switch(https_nb->stat) {
    case BEGIN:
        printf("======= LwIP: HTTPS Client Test(%x): %d =========\n", nb, count ++) ;
        
        p = (char *)malloc(1) ;
        printf("Warter mark: %x\n", p) ;
        free(p) ;
        /*** Assuming LwIP has been initialized ***/
        https_nb->stat = INITIALIZED ; 
    case INITIALIZED:
        https_nb->pcb = tcp_new();
        if(https_nb->pcb) {
    	        tcp_arg(https_nb->pcb, (void *)&(https_nb->stat)) ;    
                DBG_PRINTF("LwIPtest: New PCB(tcp_new=%x), &https->stat=%x\n", https_nb->pcb, &https_nb->stat) ;
        } else {
    	    ERR_PRINTF("tcp_new, ret=%d\n", https_nb->pcb) ;
            https_nb->stat = IDLE ;
    	    return !ERR_OK ;
        }
         
        tcp_arg(https_nb->pcb, (void *)&https_nb->stat) ;

        https_nb->localPort = getPort() ;
        printf("local Port=%d\n", https_nb->localPort) ;
        ret = tcp_bind (https_nb->pcb, &(https_nb->localIP_em),
                        https_nb->localPort) ;
        if(ret == ERR_OK) {
            https_nb->stat = TCP_CONNECT ;
            return ERR_OK;
        } else {
    	    ERR_PRINTF("tcp_bind, ret=%d\n", ret) ;
            https_nb->stat = INITIALIZED ;
            return !ERR_OK ;
        }

    case TCP_CONNECT:
        DBG_PRINTF("LwIPtest: TCP_CONNECT\n") ;
        DBG_PRINTF("LwIPtest: Server IP Addrress(%d.%d.%d.%d)\n", 
              (*(unsigned long *)&https_nb->serverIP_em&0xff),
              (*(unsigned long *)&https_nb->serverIP_em>>8)&0xff, 
              (*(unsigned long *)&https_nb->serverIP_em>>16)&0xff, 
              (*(unsigned long *)&https_nb->serverIP_em>>24)&0xff) ;

        if(CyaSSL_cb_mutex)return ERR_OK ;
        else CyaSSL_cb_mutex = 1 ;
        ret = tcp_connect(https_nb->pcb, &(https_nb->serverIP_em),
                          https_nb->serverPort, DataConnectedCallback); 
 
        if(ret == ERR_OK) {
    	     https_nb->stat = WAITING ;
             return ERR_OK;
        } else {
    	    ERR_PRINTF("tcp_connect, ret=%d\n", ret) ;
            https_nb->stat = TCP_CLOSE ;
    	    return !ERR_OK;
        }
        
    case TCP_CONNECTED:
        printf("LwIPtest: TCP CONNECTED\n") ;
        CyaSSL_cb_mutex = 0 ; 
        ret = CyaSSL_init_NB(&(https_nb->ssl_nb), https_nb->pcb) ;
        if(ret != ERR_OK) {
            https_nb->stat = TCP_CLOSE ;
            return !ERR_OK ;
        }
        https_nb->stat = SSL_CONN ;
        
    case SSL_CONN: /* handshaking */
        ret = CyaSSL_connecting_NB(&(https_nb->ssl_nb)) ;
        if(ret == SSL_NB_ERROR) {
             ERR_PRINTF("CyaSSL_connecting, ret=%d\n", ret) ;
             https_nb->stat = SSL_CLOSE ; 
             return !ERR_OK ;
        } else if(ret == SSL_NB_CONNECTED)
             https_nb->stat = HTTP_SEND ;
        else return ERR_OK;
        
    case HTTP_SEND: 
      {
        #define SEND_BUFF_SIZE 100
        char sendBuff[SEND_BUFF_SIZE] ;    
        int size ;
        printf("LwIPtest: SSL CONNECTED\n") ;
        CyaSSL_NB_setCallbackArg(ssl_nb, &(https_nb->stat)) ;
        tcp_sent(https_nb->pcb, DataSentCallback); 
        tcp_recv(https_nb->pcb, DataReceiveCallback); 

        DBG_PRINTF("LwIPtest: HTTPS GET\n") ;
        sprintf(sendBuff,
                "GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n", 
                https_nb->path, https_nb->hostname) ;
        size = strlen((char const *)sendBuff) ;
        
        if(CyaSSL_cb_mutex)return ERR_OK ;
        else CyaSSL_cb_mutex = 1 ; /* lock */
        CyaSSL_write(ssl_nb->ssl, sendBuff, size) ;

        https_nb->stat = WAITING ;
        return ERR_OK;
      }
      
    case HTTP_RECEIVE: 
      {
        #define HTTP_BUFF_SIZE 2048
        char httpbuff[HTTP_BUFF_SIZE] ;
        
        memset(httpbuff, '\0', HTTP_BUFF_SIZE) ;
        ret = CyaSSL_read(ssl_nb->ssl, httpbuff, HTTP_BUFF_SIZE) ;
        printf("LwIPtest: HTTPS GET, Received(%d)\n",strlen(httpbuff)) ;
        CyaSSL_cb_mutex = 0 ; 
        /* puts(httpbuff) ;*/ 
        puts("===================\n") ; 
      }
      case SSL_CLOSE:        
        CyaSSL_close_NB(ssl_nb) ;
        
        https_nb->stat = TCP_CLOSE ;

        return ERR_OK ;
      
      case TCP_CLOSE:
        tcp_close(https_nb->pcb) ;
        https_nb->idle = 0 ;
        https_nb->stat = IDLE ;

    
      case IDLE:
          https_nb->idle ++ ;
          if(https_nb->idle > 50000)
              https_nb->stat = BEGIN ;
        case WAITING:
        default:
            return ERR_OK;
    }
}
