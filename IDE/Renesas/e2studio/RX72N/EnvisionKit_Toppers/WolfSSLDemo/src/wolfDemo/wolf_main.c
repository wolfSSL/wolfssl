/* wolf_main.c
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
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
#include <string.h>
#include <wolf_main.h>
#include "r_sys_time_rx_if.h"
#include "r_cmt_rx_if.h"
#include "Pin.h"
#include "r_t4_itcpip.h"

#define SSL_SERVER
#define ETHER_TASK
extern const UB _t4_dhcp_enable;
static int dhcp_accept_flg = 0;
static UW tcpudp_work[14800] = {0};
UB	dhcp_evt = 0;
void dhcp_check(void);
void print_dhcp(VP param);
#define DHCP_ENABEL        (1)
#define IF_CH_NUMBER       (0)

void main(void) 
{
    /*Toopers start function */
    startw();
}

void timer_int_Wrapper() 
{
#ifndef ETHER_TASK
    cmt1_isr();
#endif
 }

 void timer_cm2_int_Wrapper() 
 {
    int du = 0;
    timeTick((void *)&du);
 }
extern bool		sns_ctx(void);

void ether_int_Wrapper() 
{
    R_BSP_InterruptControl(BSP_INT_SRC_AL1_EDMAC0_EINT0, BSP_INT_CMD_CALL_CALLBACK, FIT_NO_PTR);
}
void taskEther(intptr_t exinf) 
{
    int dhcp_cnt = 0;
    bool flg = false;
    while(1) {
        if (flg == false) {
            waisem_ether_wrapper();
            flg = true;
        }
        dhcp_check();
        dly_tsk(1);
    }
}
/* DHCP Reset Event Check */
void dhcp_check(void)
{

    if (DHCP_ENABEL == _t4_dhcp_enable && dhcp_evt == DHCP_EV_PLEASE_RESET) {
        tcpudp_reset(IF_CH_NUMBER);
        dhcp_evt = 0;
    }
    return;
}

void taskNetWork(intptr_t exinf) 
{
    UB ctl = 0;
    UW i = 0;
    while(1) {
        if (!(i % 10)) {
            ctl = ctl ? 0 : 1;
        }
        LED_CTL(ctl)
        i++;
#ifdef ETHER_TASK
        cmt1_isr();
#endif
        dly_tsk(1);
    }

}
#define FREQ 10000 /* Hz */
extern void timeTick(void *pdata);

void taskDemoWolf(intptr_t exinf) 
{
    uint32_t channel = 0;
    wolfSSL_init();
    if (!init_ether()) 
        return ;
    R_CMT_CreatePeriodic(FREQ, &timeTick, &channel);
    ICU.SLIBXR128.BYTE = 1; /* select B */

    sigsem_ether_wrapper();
    while(1) {
        dly_tsk(10);
        if (dhcp_accept_flg == 1) {
            dly_tsk(100);
#ifdef SSL_SERVER
            wolfSSL_TLS_server_Wrapper();
#else
            wolfSSL_TLS_client_Wrapper();
#endif
        }
    }
}

bool init_ether() 
{
    ER   ercd;
    W    size;
    sys_time_err_t systime_ercd;
    systime_ercd = R_SYS_TIME_Open();
    if (systime_ercd != SYS_TIME_SUCCESS) {
        printf("init_ether R_SYS_TIME_Open Error%d \n",systime_ercd);
        return false;
    }
    R_Pins_Create();

    ercd = lan_open();
    if (ercd != E_OK) {
        printf("lan_open Error%d \n",ercd);
        return false;
    }

    size = tcpudp_get_ramsize();
    if (size > (sizeof(tcpudp_work))) {
        printf("tcpudp_get_ramsize size over %d \n",size);
        return false;
    }
    ercd = tcpudp_open(tcpudp_work);
    if (ercd != E_OK) {
        printf("tcpudp_open Open Error %d \n",ercd);
        return false;
    }
    return true;
}
void print_dhcp(VP param)
{
    DHCP* dhcp_data = (DHCP*)param;
    printf("Accept DHCP.ipaddr[4]   %d.%d.%d.%d\n",dhcp_data->ipaddr[0], dhcp_data->ipaddr[1],
    dhcp_data->ipaddr[2], dhcp_data->ipaddr[3]);
    printf("Accept DHCP.maskaddr[4] %d.%d.%d.%d\n",dhcp_data->maskaddr[0], dhcp_data->maskaddr[1],
    dhcp_data->maskaddr[2], dhcp_data->maskaddr[3]);
    printf("Accept DHCP.gwaddr[4]   %d.%d.%d.%d\n",dhcp_data->gwaddr[0], dhcp_data->gwaddr[1],
    dhcp_data->gwaddr[2], dhcp_data->gwaddr[3]);
    printf("Accept DHCP.dnsaddr[4]  %d.%d.%d.%d\n",dhcp_data->dnsaddr[0], dhcp_data->dnsaddr[1],
    dhcp_data->dnsaddr[2], dhcp_data->dnsaddr[3]);
    printf("Accept DHCP.dnsaddr2[4] %d.%d.%d.%d\n",dhcp_data->dnsaddr2[0], dhcp_data->dnsaddr2[1],
    dhcp_data->dnsaddr2[2], dhcp_data->dnsaddr2[3]);
    printf("Accept DHCP.macaddr[6]  %02X:%02X:%02X:%02X:%02X:%02X\n",dhcp_data->macaddr[0],  dhcp_data->macaddr[1],  dhcp_data->macaddr[2],
    dhcp_data->macaddr[3],  dhcp_data->macaddr[4],  dhcp_data->macaddr[5]);
    printf("Accept DHCP.domain[%d] %s\n", strlen(dhcp_data->domain), dhcp_data->domain);
    printf("\n");
    return;
}

ER system_callback(UB channel, UW eventid, VP param)
{
    printf("Network callback accept channel=%d,EventNo=%d \n",channel,eventid);
    dhcp_evt = eventid;
    switch(eventid) {
        case ETHER_EV_LINK_OFF:
            {
                printf("DHCP Event Accept ETHER_EV_LINK_OFF\n");
            }
            break;
        case ETHER_EV_LINK_ON:
            {
                printf("DHCP Event Accept ETHER_EV_LINK_ON\n");
            }
            break;
     case ETHER_EV_COLLISION_IP:
            {
                 printf("DHCP Event Accept ETHER_EV_COLLISION_IP\n");
            }
            break;
     case DHCP_EV_LEASE_IP:
           {
                printf("DHCP Event Accept DHCP_EV_LEASE_IP\n");
                print_dhcp(param);
                dhcp_accept_flg = 1;
            }
            break;
     case DHCP_EV_LEASE_OVER:
           {
                printf("DHCP Event Accept DHCP_EV_LEASE_OVER\n");
           }
           break;
     case DHCP_EV_INIT:
           {
               printf("DHCP Event Accept DHCP_EV_INIT\n");
           } 
           break;
     case DHCP_EV_INIT_REBOOT:
           {
               printf("DHCP Event Accept DHCP_EV_INIT_REBOOT\n");
           }
           break;
     case DHCP_EV_APIPA:
           {
               printf("DHCP Event Accept DHCP_EV_LEASE_IP\n");
               print_dhcp(param);
               dhcp_accept_flg = 1;
           }
           break;
     case DHCP_EV_NAK:
           {
               printf("DHCP Event Accept DHCP_EV_NAK\n");
           }
           break;
     case DHCP_EV_FATAL_ERROR:
           {
               printf("DHCP Event Accept DHCP_EV_FATAL_ERROR\n");
           }
           break;
     case DHCP_EV_PLEASE_RESET:
           {
                printf("DHCP Event Accept DHCP_EV_PLEASE_RESET\n");
           }
           break;
     default:
           {
                printf("DHCP Event Accept undefined\n");
           }
           break;
    }
    return 0;
}



