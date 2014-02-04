/* https-nb.c
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

#if defined(HAVE_LWIP_NATIVE)

#if defined(CYASSL_IAR_ARM)
    #include <stdio.h>
    #include <string.h>
#endif

#include "lwip/tcp.h"
#include "lwip/sockets.h"

#include <cyassl/ctaocrypt/settings.h>
#include <cyassl/ssl.h>
#include <cyassl/internal.h>
#include <cyassl/ctaocrypt/memory.h>
#include "https-nb.h"

#if 0
/*Enable debug*/
#include <cstdio>
#define DBG_PRINTF(x, ...) printf("[HTTPSClient : DBG]"x"\r\n", ##__VA_ARGS__);
#define ERR_PRINTF(x, ...) printf("[HTTPSClient:ERROR]"x"\r\n", ##__VA_ARGS__);
#else
/*Disable debug*/
#define DBG_PRINTF(x, ...)
#define ERR_PRINTF(x, ...)
#endif

static int LwIP_cb_mutex = 0 ; 

static unsigned long localPort = 0 ;
static unsigned long getPort(void) {
      return (localPort++ + 0x200) & 0x7fff ;
}

static err_t TcpConnectedCallback (void *arg, struct tcp_pcb *pcb, s8_t err)
{
    DBG_PRINTF("TcpConnectedCallback(arg=%x, pcb=%x, err=%x)\n", arg, pcb, err) ;
    *(enum HTTPS_Stat *)arg = TCP_CONNECTED ;
    return ERR_OK;
}

static err_t DataReceiveCallback(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    DBG_PRINTF("DataReceiveCallback, pbuf->len=%d, err=%d\n", p->tot_len , err) ;
    if(*(enum HTTPS_Stat *)(arg) == WAITING) {
        *(enum HTTPS_Stat *)(arg) = HTTP_RECEIVE ;
        return ERR_OK ;
    } else return !ERR_OK ;
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
    int ret ;
    CYASSL_HTTPS_NB *https_nb ;
    
    https_nb = (CYASSL_HTTPS_NB *)nb ;
    
    CyaSSL_Debugging_ON() ; 

    switch(https_nb->stat) {
    case BEGIN:
        printf("======= LwIP: HTTPS Client Test(%x): %d ====\n", nb, count ++) ;
        /*** Assuming LwIP has been initialized ***/
        https_nb->stat = INITIALIZED ; 
    case INITIALIZED:
        https_nb->pcb = tcp_new();
        if(https_nb->pcb) {
    	        tcp_arg(https_nb->pcb, (void *)&(https_nb->stat)) ;    
                DBG_PRINTF("New PCB(tcp_new=%x), &https->stat=%x\n",
                                           https_nb->pcb, &https_nb->stat) ;
        } else {
    	    ERR_PRINTF("tcp_new, ret=%d\n", https_nb->pcb) ;
            https_nb->stat = IDLE ;
    	    return !ERR_OK ;
        }

        tcp_arg(https_nb->pcb, (void *)&https_nb->stat) ;

        https_nb->localPort = getPort() ;
        DBG_PRINTF("local Port=%d\n", https_nb->localPort) ;
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
        if(LwIP_cb_mutex)return ERR_OK ;
        else LwIP_cb_mutex = 1 ;
        DBG_PRINTF("LwIPtest: TCP_CONNECT(%x)\n", https_nb) ;
        DBG_PRINTF("LwIPtest: Server IP Addrress(%d.%d.%d.%d)\n", 
              (*(unsigned long *)&https_nb->serverIP_em&0xff),
              (*(unsigned long *)&https_nb->serverIP_em>>8)&0xff, 
              (*(unsigned long *)&https_nb->serverIP_em>>16)&0xff, 
              (*(unsigned long *)&https_nb->serverIP_em>>24)&0xff) ;
        ret = tcp_connect(https_nb->pcb, &(https_nb->serverIP_em),
                          https_nb->serverPort, TcpConnectedCallback); 
 
        if(ret == ERR_OK) {
    	     https_nb->stat = WAITING ;
             return ERR_OK;
        } else {
    	    ERR_PRINTF("tcp_connect, ret=%d\n", ret) ;
            https_nb->stat = TCP_CLOSE ;
    	    return !ERR_OK;
        }
        
    case TCP_CONNECTED:
        printf("LwIPtest: TCP CONNECTED(%x)\n", https_nb) ;
        LwIP_cb_mutex = 0 ; 

        /*CyaSSLv3_client_method()
        CyaTLSv1_client_method()
        CyaTLSv1_1_client_method()
        CyaTLSv1_2_client_method() */
        https_nb->ctx = CyaSSL_CTX_new(CyaTLSv1_2_client_method());
        if (https_nb->ctx == NULL) {
            ERR_PRINTF("CyaSSL_CTX_new: unable to get ctx");
            return !ERR_OK ;
        }
    
        CyaSSL_CTX_set_verify(https_nb->ctx, SSL_VERIFY_NONE, 0);

        https_nb->ssl = CyaSSL_new(https_nb->ctx);
        if (https_nb->ssl == NULL) {
            ERR_PRINTF("CyaSSL_new: unable to get SSL object");
            return !ERR_OK ;
        }
        
        CyaSSL_SetIO_LwIP(https_nb->ssl, https_nb->pcb, 
                          DataReceiveCallback, NULL, (void *)&https_nb->stat);

        https_nb->stat = SSL_CONN ;
        
    case SSL_CONN: /* handshaking */
        if(LwIP_cb_mutex) return ERR_OK ;
        ret = CyaSSL_connect(https_nb->ssl); 
        DBG_PRINTF("CyaSSL_connect, ret = %d\n", ret) ;
        if(ret == SSL_SUCCESS) {
            DBG_PRINTF("SSL Connected\n") ;
            https_nb->stat = HTTP_SEND ;
        } else {
            ret = CyaSSL_get_error(https_nb->ssl, NULL) ;
            if(ret == SSL_ERROR_WANT_READ) {
                 https_nb->ssl->lwipCtx.wait = -1 ;
                 https_nb->stat = SSL_CONN_WAITING ;
                return ERR_OK ;
            } else {
                ERR_PRINTF("CyaSSL_connecting_NB:ssl=%x, ret=%d\n", https_nb->ssl, ret) ;   
                return !ERR_OK ;
            }
        }
        return ERR_OK ; 
         
    case SSL_CONN_WAITING:

        if(https_nb->ssl->lwipCtx.wait-- == 0) { 
            /* counting down after the callback for multiple callbacks */
            https_nb->stat = SSL_CONN ;
            LwIP_cb_mutex = 0 ; 
        }
        return ERR_OK ;
    
    case HTTP_SEND: 
    {
        #define SEND_BUFF_SIZE 100
        char sendBuff[SEND_BUFF_SIZE] ;    
        int size ;
        if(LwIP_cb_mutex)return ERR_OK ;
        else LwIP_cb_mutex = 1 ; /* lock */
        printf("SSL CONNECTED(%x)\n", https_nb) ;
        sprintf(sendBuff,
                "GET %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n", 
                https_nb->path, https_nb->hostname) ;
        size = strlen((char const *)sendBuff) ;

        CyaSSL_write(https_nb->ssl, sendBuff, size) ;

        https_nb->stat = WAITING ;
        return ERR_OK;
    }

    case HTTP_RECEIVE: 
    {
        #define HTTP_BUFF_SIZE 2048
        char httpbuff[HTTP_BUFF_SIZE] ;
        
        LwIP_cb_mutex = 0 ;
        memset(httpbuff, '\0', HTTP_BUFF_SIZE) ;
        ret = CyaSSL_read(https_nb->ssl, httpbuff, HTTP_BUFF_SIZE) ;
        printf("HTTPS GET(%x), Received(%d)\n",https_nb, strlen(httpbuff)) ;
        /* puts(httpbuff) ; */ 
        /* puts("===================\n") ; */
    }
    case SSL_CLOSE:  
    {
        CYASSL_CTX *ctx ; ;
    
        ctx = https_nb->ssl->ctx ;
        DBG_PRINTF("CyaSSL_close(%x)", https_nb->ssl) ;
        CyaSSL_shutdown(https_nb->ssl);
        CyaSSL_free(https_nb->ssl);
        CyaSSL_CTX_free(ctx); ;
        https_nb->stat = TCP_CLOSE ;
    }
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

/*********************************************************************/
/*
    Usage Example:
        CyaSSL_HTTPS_Client_NB_init
        CyaSSL_HTTPS_Client_NB
                                                                     */
/*********************************************************************/
#ifndef NO_MAIN_DRIVER

CYASSL_HTTPS_NB CyaSSL_HTTPS_Client_1 ;
void *CyaSSL_HTTPS_ClientP_1 = (void *)&CyaSSL_HTTPS_Client_1 ;
CYASSL_HTTPS_NB CyaSSL_HTTPS_Client_2 ;
void *CyaSSL_HTTPS_ClientP_2 = (void *)&CyaSSL_HTTPS_Client_2 ;
CYASSL_HTTPS_NB CyaSSL_HTTPS_Client_3 ;
void *CyaSSL_HTTPS_ClientP_3 = (void *)&CyaSSL_HTTPS_Client_3 ;
CYASSL_HTTPS_NB CyaSSL_HTTPS_Client_4 ;
void *CyaSSL_HTTPS_ClientP_4 = (void *)&CyaSSL_HTTPS_Client_4 ;
CYASSL_HTTPS_NB CyaSSL_HTTPS_Client_5 ;
void *CyaSSL_HTTPS_ClientP_5 = (void *)&CyaSSL_HTTPS_Client_5 ;


#define HTTPS_PORT   443
#define IP_ADDR(a,b,c,d) (((a)|((b)<<8)|((c)<<16)|(d)<<24))
static struct ip_addr server_em = { IP_ADDR(192,168,11,9) } ; 

void HTTPSClient_main_init() {

  CyaSSL_HTTPS_Client_NB_init(CyaSSL_HTTPS_ClientP_1, 
                              server_em, HTTPS_PORT, "xxx.com", "/") ;
  CyaSSL_HTTPS_Client_NB_init(CyaSSL_HTTPS_ClientP_2, 
                              server_em, HTTPS_PORT, "xxx.com", "/") ;
  CyaSSL_HTTPS_Client_NB_init(CyaSSL_HTTPS_ClientP_3, 
                              server_em, HTTPS_PORT, "xxx.com", "/") ;
  CyaSSL_HTTPS_Client_NB_init(CyaSSL_HTTPS_ClientP_4, 
                              server_em, HTTPS_PORT, "xxx.com", "/") ;
  CyaSSL_HTTPS_Client_NB_init(CyaSSL_HTTPS_ClientP_5, 
                              server_em, HTTPS_PORT, "xxx.com", "/") ;  
}
 
void HTTPSClient_main(int i)
{
    if((i % 1) == 0) { /* wait for initializing TCP/IP, DHCP */
        CyaSSL_HTTPS_Client_NB(CyaSSL_HTTPS_ClientP_1) ;
    }

    if((i % 2) == 0) { /* wait for initializing TCP/IP, DHCP */
        CyaSSL_HTTPS_Client_NB(CyaSSL_HTTPS_ClientP_2) ;
    }

    if((i % 3) == 0) { /* wait for initializing TCP/IP, DHCP */
        CyaSSL_HTTPS_Client_NB(CyaSSL_HTTPS_ClientP_3) ;
    }

    if((i % 4) == 0) { /* wait for initializing TCP/IP, DHCP */
        CyaSSL_HTTPS_Client_NB(CyaSSL_HTTPS_ClientP_4) ;
    }

    if((i % 5) == 0) { /* wait for initializing TCP/IP, DHCP */
        CyaSSL_HTTPS_Client_NB(CyaSSL_HTTPS_ClientP_5) ;
    }

}

#endif /* NO_MAIN_DRIVER  */
#endif /* HAVE_LWIP_NATIVE */
