/* SSL-NB.c
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
#include "lwip/pbuf.h"
#include "lwip/sockets.h"
#endif

#include <cyassl/ctaocrypt/settings.h>
#include <cyassl/ssl.h>
#include <cyassl/internal.h>
#include <SSL-NB.h>

#if 0
/*Enable debug*/
#include <cstdio>
#define DBG_PRINTF(x, ...) printf("[HTTPSClient : DBG]"x"\r\n", ##__VA_ARGS__);
#else
/*Disable debug*/
#define DBG_PRINTF(x, ...)
#endif
#define ERR_PRINTF(x, ...) printf("[SSLClient:ERROR]"x"\r\n", ##__VA_ARGS__);

#if 0
/*Enable debug*/
#define DBG_PRINTF_CB(x, ...) printf("[HTTPSClient : DBG]"x"\r\n", ##__VA_ARGS__);
#else
/*Disable debug*/
#define DBG_PRINTF_CB(x, ...)
#endif

CyaSSL_CALLBACK_MUTEX CyaSSL_cb_mutex = 0 ;

static err_t CyaSSL_connectCallback(void *cb, struct tcp_pcb *pcb, struct pbuf *p, s8_t err)
{
    struct pbuf *next ;
    CYASSL_NB *ssl_nb ;
    ssl_nb = (CYASSL_NB *)cb ;
    
    if((cb == NULL)||(pcb == NULL))
        ERR_PRINTF("CyaSSL_connectCallBack, cb=%x, pcb=%d\n", cb, pcb) ;
    if(p && (err == 0)) {
        printf("pbuf=%x\n", p) ;
        DBG_PRINTF_CB("LwIPtest: CyaSSL connect, started(CyaSSL_connectCallBack1), pbuf=%x, err=%d, tot_len=%d\n", p, err, p->tot_len) ;
    }else {
        ERR_PRINTF("CyaSSL_connectCallBack, pbuf=%x, err=%d\n", p, err) ;
        return ERR_OK; /* don't go to SSL_CONN */
    }

    if(ssl_nb->pbuf) {
        next = ssl_nb->pbuf ;
        while(1) {
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
        ssl_nb->wait = 10000 ;
    return ERR_OK; 
}

static err_t DataSentCallback (void *arg, struct tcp_pcb *pcb, u16_t err)
{
    DBG_PRINTF_CB("LwIPtest: Data Sent(SentCallBack1), err=%d\n", err) ;
    return ERR_OK;
}

int CyaSSL_init_NB(CYASSL_NB *nb, struct tcp_pcb * pcb)
{
    CYASSL_NB *ssl_nb ; 
    ssl_nb = nb ;
    
    /*CyaSSLv3_client_method()
      CyaTLSv1_client_method()
      CyaTLSv1_1_client_method()
      CyaTLSv1_2_client_method() */
    ssl_nb->ctx = CyaSSL_CTX_new(CyaTLSv1_2_client_method());
    if (ssl_nb->ctx == NULL) {
        ERR_PRINTF("CyaSSL_CTX_new: unable to get ctx");
        return !ERR_OK ;
    }
    
    CyaSSL_CTX_set_verify(ssl_nb->ctx, SSL_VERIFY_NONE, 0);

    ssl_nb->ssl = CyaSSL_new(ssl_nb->ctx);
    if (ssl_nb->ssl == NULL) {
        ERR_PRINTF("CyaSSL_new: unable to get SSL object");
        return !ERR_OK ;
    }
    
    ssl_nb->pcb = pcb ;
    ssl_nb->pbuf = NULL ;
    ssl_nb->pulled = 0 ;
    ssl_nb->stat = SSL_NB_CONN ;
    
    /* set up callbacks */
    CyaSSL_SetIOReadCtx (ssl_nb->ssl, (void *)ssl_nb) ;
    CyaSSL_SetIOWriteCtx(ssl_nb->ssl, (void *)ssl_nb) ;
    tcp_recv(ssl_nb->pcb, CyaSSL_connectCallback);
    tcp_sent(ssl_nb->pcb, DataSentCallback); 
    tcp_arg(ssl_nb->pcb, (void *)ssl_nb) ;
    
    CyaSSL_SetVersion(ssl_nb->ssl, CYASSL_TLSV1_2) ;
    CyaSSL_set_using_nonblock(ssl_nb->ssl, (0==0)) ;
                                         /* Non-blocking CyaSSL_connect */
    DBG_PRINTF("Return CyaSSL_init_NB = %x\n", ssl_nb) ;
    return ERR_OK ;
}

/*** Non-Bloking Cyassl_connect, ... */
/* to be called in infinit loop ***/
int CyaSSL_connecting_NB(CYASSL_NB *ssl_nb)
{
    int ret ;
    
    switch(ssl_nb->stat) {
    case SSL_NB_CONN:
        if(CyaSSL_cb_mutex)return SSL_NB_WAITING ;
        ret = CyaSSL_connect(ssl_nb->ssl); 
        DBG_PRINTF("LwIPtest: SSL Connecting(CyaSSL_connect), ret = %d\n", ret) ;

        if(ret == SSL_CONNECT_WAITING) {
            if(CyaSSL_cb_mutex)
                return SSL_NB_WAITING ;
            else CyaSSL_cb_mutex = 1 ; /* lock */
            ssl_nb->wait = -1 ; /* wait until first callback */
            ssl_nb->stat = SSL_NB_WAITING ;
            return SSL_NB_CONNECTING ;
        } else if(ret == SSL_CONNECTING) {
            return SSL_NB_CONNECTING ;
        } else if(ret == SSL_SUCCESS) {
            ssl_nb->stat = SSL_NB_WAITING ;
            DBG_PRINTF("LwIPtest: SSL Connected\n") ;
            return SSL_NB_CONNECTED ;
        } else {
            ret = CyaSSL_get_error(ssl_nb->ssl, NULL) ;
              ssl_nb->stat = SSL_NB_WAITING ;
            return SSL_NB_CONNECTING ;
        }
        
    case SSL_NB_WAITING:
      if(ssl_nb->wait-- == 0) { /* counting down after the callback 
                   for multiple callbacks */
            ssl_nb->stat = SSL_NB_CONN ;
            CyaSSL_cb_mutex = 0 ; 
      }
      return SSL_NB_CONNECTING ;
    default:
        return SSL_NB_ERROR ;
    }
}

/** disconnect */
int CyaSSL_close_NB(CYASSL_NB *ssl_nb)
{
    CyaSSL_shutdown(ssl_nb->ssl);
    CyaSSL_free(ssl_nb->ssl);
    CyaSSL_CTX_free(ssl_nb->ctx);
    ssl_nb->stat = SSL_NB_BEGIN ;

    return ERR_OK ;
}

void CyaSSL_NB_setCallbackArg(CYASSL_NB *ssl_nb, void *arg)
{
    ssl_nb->arg = arg ; 
}