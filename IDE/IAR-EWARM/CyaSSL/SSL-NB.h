/* SSLcon-NB.h
 *
 * Copyright (C) 2006-2013 wolfSSL Inc.
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

#ifndef __SSLCONN_NB_H__
#define __SSLCONN_NB_H__

#define mem_malloc malloc
#define mem_free   free

enum SSL_Stat {
    SSL_NB_BEGIN,
    SSL_NB_WAITING,
    SSL_NB_CONN,
}  ;

enum SSL_NB_Ret {
    SSL_NB_ERROR,
    SSL_NB_CONNECTING,
    SSL_NB_CONNECTED,
}  ;

typedef struct CyaSSL_nb {
    CYASSL *ssl ;
    CYASSL_CTX *ctx ;
    struct tcp_pcb * pcb ;
    int    pulled  ; 
    struct pbuf *pbuf ;
    enum   SSL_Stat stat ;
    int    wait ;
    void * arg ;   /* arg for application */
    int    idle_count ;
} CYASSL_NB ;

extern int CyaSSL_init_NB(CYASSL_NB *nb, struct tcp_pcb * pcb) ;
extern int CyaSSL_connecting_NB(CYASSL_NB *ssl_nb) ;
extern int CyaSSL_close_NB(CYASSL_NB *ssl_nb) ;
extern void CyaSSL_NB_setCallbackArg(CYASSL_NB *ssl_nb, void *arg) ; 
                         /* Set it to CYASSL_NB.arg for callback arg */

extern int CyaSSL_write(struct CYASSL *pcbSSL, const void *buffer, int len) ;
extern int CyaSSL_recv(struct CYASSL *pcbSSL, void *buffer, int len, int flg) ;
extern int CyaSSL_read(struct CYASSL *pcbSSL, void *buffer, int len) ;

extern void CyaSSL_PbufFree(struct pbuf * p) ;

typedef int CyaSSL_CALLBACK_MUTEX ;

extern  CyaSSL_CALLBACK_MUTEX CyaSSL_cb_mutex ;

#endif
