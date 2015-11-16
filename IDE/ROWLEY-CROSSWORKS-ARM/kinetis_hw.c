/* kinetis_hw.c
 *
 * Copyright (C) 2006-2015 wolfSSL Inc.
 *
 * This file is part of wolfSSL. (formerly known as CyaSSL)
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

#include "hw.h"

#if defined(FREESCALE) && defined(K_SERIES)


/**********************************************
 * NOTE: Customize for actual hardware
 **********************************************/

// CPU include for Rowley CrossWorks packages
// $(TargetsDir) location:
// On Mac OS/X: Users/USERNAME/Library/Rowley Associates Limited/CrossWorks for ARM/packages/targets/
// On Windows: C:/Users/USERNAME/Application Data/Local/Rowley Associates Limited/CrossWorks for ARM/packages/targets/
#include <MK64F12.h> // Located in $(TargetsDir)/Kinetis/CMSIS/

// System clock
#define SYS_CLK_KHZ     96000ul                     /* Core system clock in KHz */
#define SYS_CLK_DRS     MCG_C4_DRST_DRS(0x03)       /* DRS 0=24MHz, 1=48MHz, 2=72MHz, 3=96MHz */
#define SYS_CLK_DMX     MCG_C4_DMX32_MASK           /* 0=Disable DMX32 (lower actual speed), MCG_C4_DMX32_MASK=Enable DMX32 */
#define SYS_CLK_DIV     1                           /* System clock divisor */
#define BUS_CLK_DIV     2                           /* Bus clock divisor */
#define BUS_CLK_KHZ     (SYS_CLK_KHZ/BUS_CLK_DIV)   /* Helper to calculate bus speed for UART */
#define FLASH_CLK_DIV   4                           /* Flash clock divisor */

// UART TX Port, Pin, Mux and Baud
#define UART_PORT       UART5                       /* UART Port */
#define UART_TX_PORT    PORTE                       /* UART TX Port */
#define UART_TX_PIN     8                           /* UART TX Pin */
#define UART_TX_MUX     0x3                         /* Kinetis UART pin mux */
#define UART_BAUD       115200                      /* UART Baud Rate */
/* Note: You will also need to update the UART clock gate in hw_uart_init (SIM_SCGC1_UART5_MASK) */
/* Note: TWR-K60 is UART3, PTC17 */

/***********************************************/

// Private functions
static void hw_mcg_init(void)
{
    /* Adjust clock dividers (core/system=div/1, bus=div/2, flex bus=div/2, flash=div/4) */
    SIM->CLKDIV1 = SIM_CLKDIV1_OUTDIV1(SYS_CLK_DIV-1) | SIM_CLKDIV1_OUTDIV2(BUS_CLK_DIV-1) | 
        SIM_CLKDIV1_OUTDIV3(BUS_CLK_DIV-1) | SIM_CLKDIV1_OUTDIV4(FLASH_CLK_DIV-1);
   
    /* Configure FEI internal clock speed */
    MCG->C4 = (SYS_CLK_DMX | SYS_CLK_DRS);
    while((MCG->C4 & (MCG_C4_DRST_DRS_MASK | MCG_C4_DMX32_MASK)) != (SYS_CLK_DMX | SYS_CLK_DRS));
}

static void hw_gpio_init(void)
{
    /* Enable clocks to all GPIO ports */
    SIM->SCGC5 |= (SIM_SCGC5_PORTA_MASK | SIM_SCGC5_PORTB_MASK
#ifdef SIM_SCGC5_PORTC_MASK
        | SIM_SCGC5_PORTC_MASK
#endif
#ifdef SIM_SCGC5_PORTD_MASK
        | SIM_SCGC5_PORTD_MASK
#endif
#ifdef SIM_SCGC5_PORTE_MASK
        | SIM_SCGC5_PORTE_MASK
#endif
   );
}

static void hw_uart_init(void)
{
    register uint16_t sbr, brfa;
    uint8_t temp;

    /* Enable UART core clock */
    SIM->SCGC1 |= SIM_SCGC1_UART5_MASK;
    
    /* Configure UART TX pin */
    UART_TX_PORT->PCR[UART_TX_PIN] = PORT_PCR_MUX(UART_TX_MUX);

    /* Disable transmitter and receiver while we change settings. */
    UART_PORT->C2 &= ~(UART_C2_TE_MASK | UART_C2_RE_MASK );

    /* Configure the UART for 8-bit mode, no parity */
    UART_PORT->C1 = 0;
    
    /* Calculate baud settings */
    sbr = (uint16_t)((BUS_CLK_KHZ * 1000)/(UART_BAUD * 16));
    temp = UART_PORT->BDH & ~(UART_BDH_SBR(0x1F));
    UART_PORT->BDH = temp | UART_BDH_SBR(((sbr & 0x1F00) >> 8));
    UART_PORT->BDL = (uint8_t)(sbr & UART_BDL_SBR_MASK);
    
    /* Determine if a fractional divider is needed to get closer to the baud rate */
    brfa = (((BUS_CLK_KHZ * 32000)/(UART_BAUD * 16)) - (sbr * 32));
    temp = UART_PORT->C4 & ~(UART_C4_BRFA(0x1F));
    UART_PORT->C4 = temp | UART_C4_BRFA(brfa);    

    /* Enable receiver and transmitter */
	UART_PORT->C2 |= (UART_C2_TE_MASK | UART_C2_RE_MASK);
}

static void hw_rtc_init(void)
{
    /* Enable RTC clock and oscillator */
    SIM->SCGC6 |= SIM_SCGC6_RTC_MASK;
    RTC->CR |= RTC_CR_OSCE_MASK;
}

static void hw_rand_init(void)
{
    /* Enable RNG clocks */
    SIM->SCGC6 |= SIM_SCGC6_RNGA_MASK;
    SIM->SCGC3 |= SIM_SCGC3_RNGA_MASK;

    /* Wake up RNG to normal mode (take out of sleep) */
    RNG->CR &= ~RNG_CR_SLP_MASK;

    /* Enable High Assurance mode (Enables notification of security violations via SR[SECV]) */
    RNG->CR |= RNG_CR_HA_MASK;

    /* Enable RNG generation to RANDOUT FIFO */
    RNG->CR |= RNG_CR_GO_MASK;
}


/* Public Functions */
void hw_init(void)
{
    hw_mcg_init();
    hw_gpio_init();
    hw_uart_init();
    hw_rtc_init();
    hw_rand_init();
}

uint32_t hw_get_time_sec(void)
{
    /* Return RTC seconds */
    return RTC->TSR;
}

uint32_t hw_get_time_msec(void)
{
    /* RTC TPR precision register increments every 32.768 kHz clock cycle */
    /* Convert with rounding crystal count (32768 or (1 << 15)) to milliseconds */
    return ( ((uint32_t)RTC->TPR * 1000) + ((1 << 15) / 2) ) / (1 << 15);
}

void hw_uart_printchar(int c)
{
    while(!(UART_PORT->S1 & UART_S1_TDRE_MASK)); /* Wait until space is available in the FIFO */
    UART_PORT->D = (uint8_t)c; /* Send the character */
}

uint32_t hw_rand(void)
{
    while((RNG->SR & RNG_SR_OREG_LVL(0xF)) == 0) {}; /* Wait until FIFO has a value available */
    return RNG->OR; /* Return next value in FIFO output register */
}

// Watchdog
void hw_watchdog_disable(void)
{
    WDOG->UNLOCK = 0xC520;
    WDOG->UNLOCK = 0xD928;
    WDOG->STCTRLH = WDOG_STCTRLH_ALLOWUPDATE_MASK;
}

// Flash configuration
#define FSEC_UNSECURE             2
#define FSEC_SECURE               0
#define FSEC_FSLACC_DENIED        2
#define FSEC_FSLACC_GRANTED       3
#define FSEC_KEY_ENABLED          2
#define FSEC_KEY_DISABLED         3
#define FSEC_MASS_ERASE_DISABLE   2
#define FSEC_MASS_ERASE_ENABLE    3

struct flash_conf {
   uint8_t backdoor_key[8];   /* Backdoor Comparison Key */
   uint8_t fprot[4];          /* Program flash protection bytes */
   uint8_t fsec;              /* Flash security byte */
   uint8_t fopt;              /* Flash nonvolatile option byte */
   uint8_t feprot;            /* FlexNVM: EEPROM protection byte */
   uint8_t fdprot;            /* FlexNVM: Data flash protection byte */
};
const struct flash_conf flash_conf __attribute__ ((section (".flashconf"),used)) =
{
   .backdoor_key = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
   .fprot = { 0xFF, 0xFF, 0xFF, 0xFF },
   .fsec = NV_FSEC_SEC(FSEC_UNSECURE) | NV_FSEC_FSLACC(FSEC_FSLACC_GRANTED) | 
           NV_FSEC_MEEN(FSEC_MASS_ERASE_ENABLE) | NV_FSEC_KEYEN(FSEC_KEY_DISABLED),
   .fopt = 0xFF,
   .feprot = 0xFF,
   .fdprot = 0xFF
};

#endif /* FREESCALE && K_SERIES */
