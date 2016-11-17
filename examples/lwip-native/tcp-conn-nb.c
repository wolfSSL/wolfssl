/* tcp-conn-nb.c
 *
 * Copyright (C) 2006-2016 wolfSSL Inc.
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

/*** Simulating tcp_connect by LwIP Native TCP ***/


#if defined(HAVE_LWIP_NATIVE)
#include <wolfssl/wolfcrypt/types.h>
#include <string.h>
#include "lwip/tcp.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "lwip/ip_addr.h"

#include "wolfssl/ssl.h"
#include "tcp-conn-nb.h" 

int   myoptind;
char* myoptarg;


static struct tcp_cb {
    enum TCP_stat stat ;
    struct tcp_pcb *pcb ;
    unsigned long localPort;
    ip_addr_t localIP_em ;
    unsigned long serverPort ;
    ip_addr_t serverIP_em ;    
} tcp ;


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


static err_t TcpConnectedCallback (void *arg, struct tcp_pcb *pcb, s8_t err)
{
    DBG_PRINTF("TcpConnectedCallback(arg=%x, pcb=%x, err=%x)\n", arg, pcb, err) ;
    *(int *)arg = TCP_CONNECTED ;
    return ERR_OK;
}

/** strictly IPV4 ***/
#define IP_ADDR(a,b,c,d) (((a)|((b)<<8)|((c)<<16)|(d)<<24))
ip_addr_t ip_addr_s2i(const char *ip_s) {
    unsigned int ip[4] ;
    ip_addr_t ip_addr ;
    
    sscanf(ip_s, "%d.%d.%d.%d", 
                 &(ip[0]), &(ip[1]), &(ip[2]), &(ip[3])) ;
    ip_addr.addr = IP_ADDR(ip[0], ip[1], ip[2], ip[3]) ;
    return ip_addr ;
}

/** Placeholders for now **/
void tcp_socket(SOCKET_T *s, int flag) { }
void build_addr(int *addr, char *host, int port, int mode) { }
void tcp_CloseSocket_nb(SOCKET_T *sockfd) { }
void tcp_select(SOCKET_T *s, int flag) { }
unsigned long current_time(void) { return 0 ; }

static int wait_count ;
static unsigned long localPort = 0 ;
static unsigned long getPort(void) {
      return (localPort++ + 0x200) & 0x7fff ;
}

void tcp_connect_init(void) {
     tcp.stat = TCP_BEGIN ;
     wait_count = 0 ;
}

int tcp_connect_nb(struct tcp_pcb **pcb, const char* ip, word16 port,
                               int udp)
{
    int ret ;
    
    switch(tcp.stat) {
    case TCP_BEGIN:
        tcp.pcb = tcp_new() ;
        if(tcp.pcb) {
    	        tcp_arg(tcp.pcb, (void *)&(tcp.stat)) ;    
                DBG_PRINTF("New PCB(tcp_new=%x), &https->stat=%x\n",
                                           tcp.pcb, &tcp.stat) ;
        } else {
    	    ERR_PRINTF("tcp_new, ret=%d\n", tcp.pcb) ;
            tcp.stat = TCP_IDLE ;
    	    return TCP_ERROR ;
        }
        
        *pcb = tcp.pcb ;
        tcp_arg(tcp.pcb, (void *)&tcp.stat) ;

        tcp.localPort = getPort();
        DBG_PRINTF("local Port=%d\n", tcp.localPort) ;
        ret = tcp_bind (tcp.pcb, &(tcp.localIP_em),
                        tcp.localPort) ;
        if(ret == ERR_OK) {
            tcp.stat = TCP_CONNECTING ;
            return TCP_CONNECTING ;
        } else {
    	    ERR_PRINTF("tcp_bind, ret=%d\n", ret) ;
            tcp.stat = TCP_CLOSE ;
            return TCP_CONNECTING ;
        }

    case TCP_CONNECTING:
        tcp.serverPort  = port ;
        tcp.serverIP_em = ip_addr_s2i(ip) ;
        DBG_PRINTF("TCP_CONNECT(%x)\n", tcp.pcb) ;
        wait_count = 1000 ;
        ret = tcp_connect(tcp.pcb, &(tcp.serverIP_em),
                          tcp.serverPort, TcpConnectedCallback); 
        if(ret == ERR_OK) {
    	     tcp.stat = TCP_WAITING ;
             return TCP_CONNECTING ;
        } else {
    	    ERR_PRINTF("tcp_connect, ret=%d\n", ret) ;
            tcp.stat = TCP_CLOSE ;
    	    return TCP_ERROR ;
        }

    case TCP_WAITING:
        return TCP_CONNECTING ;
        
    case TCP_CONNECTED:
        if(wait_count --)return TCP_CONNECTING ;
        *pcb = tcp.pcb ;
        wait_count = 0 ;
        return TCP_CONNECTED ;
        
    case TCP_CLOSE:
        tcp_close(tcp.pcb) ;
        tcp.stat = TCP_IDLE ;
        return TCP_CONNECTING ;
    
    case TCP_IDLE:
    default:
        return TCP_CONNECTING ;
    }
}

void tcp_close_nb(void) {
     tcp_close(tcp.pcb) ;
     tcp.stat = TCP_BEGIN ;
     wait_count = 0 ;
}

#endif
