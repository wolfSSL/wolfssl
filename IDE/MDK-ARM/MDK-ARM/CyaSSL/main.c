/* main.c
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
 
#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <cyassl/ctaocrypt/visibility.h>
#include <cyassl/ctaocrypt/logging.h>

#include <RTL.h>
#include <stdio.h>
#include "cyassl_MDK_ARM.h"

#include "stm32f2xx_tim.h"
#include "stm32f2xx_rcc.h"


/*-----------------------------------------------------------------------------
 *        Initialize a Flash Memory Card
 *----------------------------------------------------------------------------*/
#if !defined(NO_FILESYSTEM)
static void init_card (void) 
{
    U32 retv;

    while ((retv = finit (NULL)) != 0) {     /* Wait until the Card is ready */
        if (retv == 1) {
            printf ("\nSD/MMC Init Failed");
            printf ("\nInsert Memory card and press key...\n");
        } else {
            printf ("\nSD/MMC Card is Unformatted");
        }
     }
}
#endif


/*-----------------------------------------------------------------------------
 *        TCP/IP tasks
 *----------------------------------------------------------------------------*/
#ifdef CYASSL_KEIL_TCP_NET
__task void tcp_tick (void) 
{
    
    CYASSL_MSG("Time tick started.") ;
    #if defined (HAVE_KEIL_RTX)
    os_itv_set (10);
    #endif
  
    while (1) {
        #if defined (HAVE_KEIL_RTX)
        os_itv_wait ();
        #endif
        /* Timer tick every 100 ms */
        timer_tick ();
    }
}

__task void tcp_poll (void)
{
    CYASSL_MSG("TCP polling started.\n") ;
    while (1) {
        main_TcpNet ();
        #if defined (HAVE_KEIL_RTX)
        os_tsk_pass ();
        #endif
    }
}
#endif

/*-----------------------------------------------------------------------------
 *        initialize RTC 
 *----------------------------------------------------------------------------*/
#include "stm32f2xx_rtc.h"
#include "stm32f2xx_rcc.h"
#include "stm32f2xx_pwr.h"

static init_RTC() 
{
    RTC_InitTypeDef RTC_InitStruct ;
    
    RTC_TimeTypeDef RTC_Time ;
    RTC_DateTypeDef RTC_Date ;

    
    /* Enable the PWR clock */
    RCC_APB1PeriphClockCmd(RCC_APB1Periph_PWR, ENABLE);

    /* Allow access to RTC */
    PWR_BackupAccessCmd(ENABLE);

/***Configures the External Low Speed oscillator (LSE)****/

    RCC_LSEConfig(RCC_LSE_ON);

    /* Wait till LSE is ready */  
    while(RCC_GetFlagStatus(RCC_FLAG_LSERDY) == RESET)
    {
    }

    /* Select the RTC Clock Source */
    RCC_RTCCLKConfig(RCC_RTCCLKSource_LSE);
   
    /* Enable the RTC Clock */
    RCC_RTCCLKCmd(ENABLE);

    /* Wait for RTC APB registers synchronisation */
    RTC_WaitForSynchro();

    /* Calendar Configuration with LSI supposed at 32KHz */
    RTC_InitStruct.RTC_AsynchPrediv = 0x7F;
    RTC_InitStruct.RTC_SynchPrediv =  0xFF; 
    RTC_InitStruct.RTC_HourFormat = RTC_HourFormat_24;
    RTC_Init(&RTC_InitStruct);

    RTC_GetTime(RTC_Format_BIN, &RTC_Time) ;
    RTC_GetDate(RTC_Format_BIN, &RTC_Date) ;
}

/*-----------------------------------------------------------------------------
 *        initialize TIM
 *----------------------------------------------------------------------------*/
void init_timer()
{
    TIM_TimeBaseInitTypeDef TIM_TimeBaseStructure ;

    RCC_APB1PeriphClockCmd(RCC_APB1Periph_TIM2, ENABLE) ;

    TIM_TimeBaseStructInit(&TIM_TimeBaseStructure);
    TIM_TimeBaseStructure.TIM_Prescaler = 60;
    TIM_TimeBaseStructure.TIM_CounterMode = TIM_CounterMode_Up;
    TIM_TimeBaseStructure.TIM_Period = 0xffffffff;
    TIM_TimeBaseStructure.TIM_ClockDivision = 0;
    TIM_TimeBaseStructure.TIM_RepetitionCounter = 0;

    TIM_TimeBaseInit(TIM2, &TIM_TimeBaseStructure);

    TIM_TimeBaseInit(TIM2, &TIM_TimeBaseStructure) ;
    TIM_Cmd(TIM2, ENABLE) ;
}

#if defined(HAVE_KEIL_RTX) && defined(CYASSL_MDK_SHELL)
#define SHELL_STACKSIZE 1000
static unsigned char Shell_stack[SHELL_STACKSIZE] ;
#endif


#if  defined(CYASSL_MDK_SHELL)
extern void shell_main(void) ;
#endif

extern void time_main(int) ;
extern void benchmark_test(void) ;
extern void SER_Init(void) ;

/*-----------------------------------------------------------------------------
 *       mian entry 
 *----------------------------------------------------------------------------*/

/*** This is the parent task entry ***/
void main_task (void) 
{
    #ifdef CYASSL_KEIL_TCP_NET
    init_TcpNet ();

    os_tsk_create (tcp_tick, 2);
    os_tsk_create (tcp_poll, 1);    
    #endif
    
    #ifdef CYASSL_MDK_SHELL 
        #ifdef  HAVE_KEIL_RTX
           os_tsk_create_user(shell_main, 1, Shell_stack, SHELL_STACKSIZE) ;
       #else
           shell_main() ;
       #endif
    #else
    
    /************************************/
    /*** USER APPLICATION HERE        ***/
    /************************************/

    #endif 

    #ifdef   HAVE_KEIL_RTX
    CYASSL_MSG("Terminating tcp_main\n") ;
    os_tsk_delete_self ();
    #endif

}


    int myoptind = 0;
    char* myoptarg = NULL;

    #if defined(DEBUG_CYASSL)
                extern void CyaSSL_Debugging_ON(void) ;
#endif


/*** main entry ***/
int main() {
        /* stm32_Init ();                  STM32 setup */
        
    #if !defined(NO_FILESYSTEM)
    init_card () ;                                    /* initializing SD card */
    #endif
    
    init_RTC() ;
    init_timer() ;
    SER_Init() ;
    
    #if defined(DEBUG_CYASSL)
         printf("Turning ON Debug message\n") ;
         CyaSSL_Debugging_ON() ;
    #endif
    
    #ifdef   HAVE_KEIL_RTX
         os_sys_init (main_task) ;
    #else
         main_task() ;
    #endif
    
    return 0 ; /* There should be no return here */

}
