/* client-nb.h
 *
 * Copyright (C) 2006-2014 wolfSSL Inc.
 *
 * This file is part of 
 .
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#pragma once

THREAD_RETURN WOLFSSL_THREAD client_test(void* args);

#if defined(HAVE_LWIP_NATIVE)

static enum Client_Stat {
        CLIENT_BEGIN ,
        CLIENT_TCP_CONN ,
        CLIENT_SSL_CONN ,
        CLIENT_SSL_READ ,
} client_stat ;

int tcp_connect_nb(struct tcp_pcb **pcb, const char* ip, word16 port, int udp);
void tcp_CloseSocket_nb(struct tcp_pcb *pcb) ;
#define tcp_connect(s, h, p, f) tcp_connect_nb(s, h, p, f)
#define CloseSocket(s) tcp_CloseSocket_nb(s)
#define wolfSSL_set_fd(ssl, s)

#endif


#if defined(HAVE_LWIP_NATIVE)

#define SWITCH_STAT       switch(client_stat) { case CLIENT_BEGIN:
#define CASE(stat)        client_stat = stat ; case stat 
#define BREAK             break
#define END_SWITCH        }
#define STATIC_NB         static

#else

#define SWITCH_STAT
#define CASE(value)
#define BREAK
#define END_SWITHCH
#define STATIC_NB

#endif


