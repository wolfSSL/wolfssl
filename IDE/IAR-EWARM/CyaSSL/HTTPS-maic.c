/* HTTPS-MAIN.c
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

#include "lwip/tcp.h"
#include "lwip/sockets.h"

#include <cyassl/ctaocrypt/settings.h>
#include <cyassl/ssl.h>
#include <cyassl/ctaocrypt/memory.h>
#include "SSL-NB.h"
#include "HTTPS-NB.h"
#include "HTTPS-main.h"

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


extern  void CyaSSL_HTTPS_Client_NB_init(void *nb, 
           struct ip_addr svIP, unsigned long svPort, char *host, char *path) ;
  
#define HTTPS_PORT   443
#define IP_ADDR(a,b,c,d) (((a)|((b)<<8)|((c)<<16)|(d)<<24))
static struct ip_addr server_em = { IP_ADDR(192,168,11,9) } ;

static int i = 0 ;

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

void HTTPSClient_main(void)
{

    if(i++ < 10000)return ;
    
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
#if 0
    if((i % 5) == 0) { /* wait for initializing TCP/IP, DHCP */
        CyaSSL_HTTPS_Client_NB(CyaSSL_HTTPS_ClientP_5) ;
    }
#endif
}