/* arm_startup.c
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
#include <stdio.h>

// Memory initialization
extern uint32_t __data_load_start__[];
extern uint32_t __data_start__[];
extern uint32_t __data_end__[];

extern uint32_t __bss_start__[];
extern uint32_t __bss_end__[];

extern uint32_t __fast_load_start__[];
extern uint32_t __fast_start__[];
extern uint32_t __fast_end__[];

extern uint32_t __stack_process_end__[];

extern uint32_t __heap_start__[];
extern uint32_t __heap_end__[];

// Copy memory: src=Source, dst_beg=Destination Begin, dst_end=Destination End
void memcpy32(uint32_t* src, uint32_t* dst_beg, uint32_t* dst_end)
{
    while (dst_beg < dst_end) {
        *dst_beg++ = *src++;
    }
}
// Zero address in range
void meminit32(uint32_t* start, uint32_t* end)
{
    while (start < end) {
	    *start++ = 0;
    }
}

// Entry Point
void reset_handler(void)
{
    // Disable Watchdog
    hw_watchdog_disable();

    // Init sections
    memcpy32(__data_load_start__, __data_start__, __data_end__);
    meminit32(__bss_start__, __bss_end__);
    memcpy32(__fast_load_start__, __fast_start__, __fast_end__);
    
    // Init heap
    __heap_start__[0] = 0;
    __heap_start__[1] = ((uint32_t)__heap_end__ - (uint32_t)__heap_start__);

    // Init hardware
    hw_init();

    // Start main
    extern void main(void);
    main();

    // Application has ended, so busy wait
    while(1);
}

// Vector Exception/Interrupt Handlers
static void Default_Handler(void)
{
}

void HardFault_HandlerC( uint32_t *hardfault_args )
{
    /* These are volatile to try and prevent the compiler/linker optimizing them
    away as the variables never actually get used.  If the debugger won't show the
    values of the variables, make them global my moving their declaration outside
    of this function. */
    volatile uint32_t stacked_r0;
	volatile uint32_t stacked_r1;
	volatile uint32_t stacked_r2;
	volatile uint32_t stacked_r3;
	volatile uint32_t stacked_r12;
	volatile uint32_t stacked_lr;
    volatile uint32_t stacked_pc;
	volatile uint32_t stacked_psr;
	volatile uint32_t _CFSR;
	volatile uint32_t _HFSR;
	volatile uint32_t _DFSR;
	volatile uint32_t _AFSR;
	volatile uint32_t _BFAR;
	volatile uint32_t _MMAR;

	stacked_r0 = ((uint32_t)hardfault_args[0]);
	stacked_r1 = ((uint32_t)hardfault_args[1]);
	stacked_r2 = ((uint32_t)hardfault_args[2]);
	stacked_r3 = ((uint32_t)hardfault_args[3]);
	stacked_r12 = ((uint32_t)hardfault_args[4]);
	stacked_lr = ((uint32_t)hardfault_args[5]);
	stacked_pc = ((uint32_t)hardfault_args[6]);
	stacked_psr = ((uint32_t)hardfault_args[7]);

    // Configurable Fault Status Register
    // Consists of MMSR, BFSR and UFSR
	_CFSR = (*((volatile uint32_t *)(0xE000ED28)));	
											
	// Hard Fault Status Register
	_HFSR = (*((volatile uint32_t *)(0xE000ED2C)));

	// Debug Fault Status Register
	_DFSR = (*((volatile uint32_t *)(0xE000ED30)));

	// Auxiliary Fault Status Register
	_AFSR = (*((volatile uint32_t *)(0xE000ED3C)));

	// Read the Fault Address Registers. These may not contain valid values.
	// Check BFARVALID/MMARVALID to see if they are valid values
	// MemManage Fault Address Register
	_MMAR = (*((volatile uint32_t *)(0xE000ED34)));
	// Bus Fault Address Register
	_BFAR = (*((volatile uint32_t *)(0xE000ED38)));

    printf ("\n\nHard fault handler (all numbers in hex):\n");
    printf ("R0 = %x\n", stacked_r0);
    printf ("R1 = %x\n", stacked_r1);
    printf ("R2 = %x\n", stacked_r2);
    printf ("R3 = %x\n", stacked_r3);
    printf ("R12 = %x\n", stacked_r12);
    printf ("LR [R14] = %x  subroutine call return address\n", stacked_lr);
    printf ("PC [R15] = %x  program counter\n", stacked_pc);
    printf ("PSR = %x\n", stacked_psr);
    printf ("CFSR = %x\n", _CFSR);
    printf ("HFSR = %x\n", _HFSR);
    printf ("DFSR = %x\n", _DFSR);
    printf ("AFSR = %x\n", _AFSR);
    printf ("MMAR = %x\n", _MMAR);
    printf ("BFAR = %x\n", _BFAR);

    // Break into the debugger
	__asm("BKPT #0\n");
}

__attribute__( ( naked ) ) 
void HardFault_Handler(void)
{
    __asm volatile
    (
        " tst lr, #4                                                \n"
        " ite eq                                                    \n"
        " mrseq r0, msp                                             \n"
        " mrsne r0, psp                                             \n"
        " ldr r1, [r0, #24]                                         \n"
        " ldr r2, handler2_address_const                            \n"
        " bx r2                                                     \n"
        " handler2_address_const: .word HardFault_HandlerC          \n"
    );
}

// Vectors
typedef void (*vector_entry)(void);
const vector_entry vectors[] __attribute__ ((section(".vectors"),used)) =
{
    /* Interrupt Vector Table Function Pointers */
                        // Address     Vector IRQ   Source module    Source description
    (vector_entry)__stack_process_end__, //         ARM core         Initial Supervisor SP
    reset_handler,      // 0x0000_0004 1 -          ARM core         Initial Program Counter
    Default_Handler,    // 0x0000_0008 2 -          ARM core         Non-maskable Interrupt (NMI)
    HardFault_Handler,  // 0x0000_000C 3 -          ARM core         Hard Fault
    Default_Handler,    // 0x0000_0010 4 -
    HardFault_Handler,  // 0x0000_0014 5 -          ARM core         Bus Fault
    HardFault_Handler,  // 0x0000_0018 6 -          ARM core         Usage Fault
    Default_Handler,    // 0x0000_001C 7 -
    Default_Handler,    // 0x0000_0020 8 -
    Default_Handler,    // 0x0000_0024 9 -
    Default_Handler,    // 0x0000_0028 10 -
    Default_Handler,    // 0x0000_002C 11 -         ARM core         Supervisor call (SVCall)
    Default_Handler,    // 0x0000_0030 12 -         ARM core         Debug Monitor
    Default_Handler,    // 0x0000_0034 13 -
    Default_Handler,    // 0x0000_0038 14 -         ARM core         Pendable request for system service (PendableSrvReq)
    Default_Handler,    // 0x0000_003C 15 -         ARM core         System tick timer (SysTick)

    // Add specific driver interrupt handlers below
};
