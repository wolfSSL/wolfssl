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

#include "time.h"
#include "stm32f2xx_tim.h"
#include "stm32f2xx_rcc.h"


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
static void init_TIM()
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

void init_time(void) {
	  init_RTC() ;
    init_TIM() ;
}

struct tm *Cyassl_MDK_gmtime(const time_t *c) 
{ 

    RTC_TimeTypeDef RTC_Time ;
    RTC_DateTypeDef RTC_Date ;
    static struct tm date ; 

    RTC_GetTime(RTC_Format_BIN, &RTC_Time) ;
    RTC_GetDate(RTC_Format_BIN, &RTC_Date) ;

    date.tm_year = RTC_Date.RTC_Year + 100 ;
    date.tm_mon = RTC_Date.RTC_Month - 1 ;
    date.tm_mday = RTC_Date.RTC_Date ;
    date.tm_hour = RTC_Time.RTC_Hours ;
    date.tm_min = RTC_Time.RTC_Minutes ;
    date.tm_sec = RTC_Time.RTC_Seconds ;

    #if defined(DEBUG_CYASSL) 
    {
        char msg[100] ;
        sprintf(msg, "Debug::Cyassl_KEIL_gmtime(DATE=/%4d/%02d/%02d TIME=%02d:%02d:%02d)\n",
        RTC_Date.RTC_Year+2000,  RTC_Date.RTC_Month, RTC_Date.RTC_Date,
        RTC_Time.RTC_Hours,  RTC_Time.RTC_Minutes,  RTC_Time.RTC_Seconds) ; 
        CYASSL_MSG(msg) ;   
    }
    #endif
    
    return(&date) ;
}

double current_time() 
{
      return ((double)TIM2->CNT/1000000.0) ;
}

typedef struct func_args {
    int    argc;
    char** argv;
    int    return_code;
} func_args;


#include <stdio.h>

void time_main(void *args) 
{
    char * datetime ;
    RTC_TimeTypeDef RTC_Time ;
    RTC_DateTypeDef RTC_Date ;
    int year ;
    if( args == NULL || ((func_args *)args)->argc == 1) {
        RTC_GetTime(RTC_Format_BIN, &RTC_Time) ;
        RTC_GetDate(RTC_Format_BIN, &RTC_Date) ;
        printf("Date: %d/%d/%d, Time: %02d:%02d:%02d\n", 
             RTC_Date.RTC_Month, RTC_Date.RTC_Date, RTC_Date.RTC_Year+2000,  
             RTC_Time.RTC_Hours,  RTC_Time.RTC_Minutes,  RTC_Time.RTC_Seconds) ;              
    } else if(((func_args *)args)->argc == 3 && 
              ((func_args *)args)->argv[1][0] == '-' && 
              ((func_args *)args)->argv[1][1] == 'd' ) {
        datetime = ((func_args *)args)->argv[2];
        sscanf(datetime, "%d/%d/%d", 
             (int *)&RTC_Date.RTC_Month, (int *)&RTC_Date.RTC_Date, &year) ;
        RTC_Date.RTC_Year = year - 2000 ;   
        RTC_Date.RTC_WeekDay = 0 ;
        RTC_SetDate(RTC_Format_BIN, &RTC_Date) ;        
    } else if(((func_args *)args)->argc == 3 && 
              ((func_args *)args)->argv[1][0] == '-' && 
              ((func_args *)args)->argv[1][1] == 't' ) {
        datetime = ((func_args *)args)->argv[2];
        sscanf(datetime, "%d:%d:%d",            
            (int *)&RTC_Time.RTC_Hours, 
            (int *)&RTC_Time.RTC_Minutes, 
            (int *)&RTC_Time.RTC_Seconds
        ) ;
        RTC_SetTime(RTC_Format_BIN, &RTC_Time) ;
    } else printf("Invalid argument\n") ; 
}


