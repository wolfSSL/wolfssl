/* Minimal startup code for STM32H753 running under Renode */

#include <stdint.h>
#include <stddef.h>

extern int main(int argc, char** argv);

void Default_Handler(void);
void Reset_Handler(void);

/* Symbols provided by the linker script */
extern unsigned long _estack;
extern unsigned long __data_start__;
extern unsigned long __data_end__;
extern unsigned long __bss_start__;
extern unsigned long __bss_end__;
extern unsigned long _sidata; /* start of .data in flash */

/* Minimal init_array support */
extern void (*__preinit_array_start[])(void);
extern void (*__preinit_array_end[])(void);
extern void (*__init_array_start[])(void);
extern void (*__init_array_end[])(void);

static void call_init_array(void)
{
    size_t count, i;

    count = __preinit_array_end - __preinit_array_start;
    for (i = 0; i < count; i++)
        __preinit_array_start[i]();

    count = __init_array_end - __init_array_start;
    for (i = 0; i < count; i++)
        __init_array_start[i]();
}

void Reset_Handler(void)
{
    unsigned long *src, *dst;

    /* Copy .data from flash to RAM */
    src = &_sidata;
    for (dst = &__data_start__; dst < &__data_end__;)
        *dst++ = *src++;

    /* Zero .bss */
    for (dst = &__bss_start__; dst < &__bss_end__;)
        *dst++ = 0;

    /* Call static constructors */
    call_init_array();

    /* Call main */
    (void)main(0, (char**)0);

    /* Infinite loop after main returns */
    while (1) {
        __asm__ volatile ("wfi");
    }
}

void Default_Handler(void)
{
    while (1) {
        __asm__ volatile ("wfi");
    }
}

/* Exception handlers - all weak aliases to Default_Handler */
void NMI_Handler(void) __attribute__((weak, alias("Default_Handler")));
void HardFault_Handler(void) __attribute__((weak, alias("Default_Handler")));
void MemManage_Handler(void) __attribute__((weak, alias("Default_Handler")));
void BusFault_Handler(void) __attribute__((weak, alias("Default_Handler")));
void UsageFault_Handler(void) __attribute__((weak, alias("Default_Handler")));
void SVC_Handler(void) __attribute__((weak, alias("Default_Handler")));
void DebugMon_Handler(void) __attribute__((weak, alias("Default_Handler")));
void PendSV_Handler(void) __attribute__((weak, alias("Default_Handler")));
void SysTick_Handler(void) __attribute__((weak, alias("Default_Handler")));

/* Vector table */
__attribute__ ((section(".isr_vector"), used))
void (* const g_pfnVectors[])(void) = {
    (void (*)(void))(&_estack), /* Initial stack pointer */
    Reset_Handler,              /* Reset Handler */
    NMI_Handler,                /* NMI Handler */
    HardFault_Handler,          /* Hard Fault Handler */
    MemManage_Handler,          /* MPU Fault Handler */
    BusFault_Handler,           /* Bus Fault Handler */
    UsageFault_Handler,         /* Usage Fault Handler */
    0,                          /* Reserved */
    0,                          /* Reserved */
    0,                          /* Reserved */
    0,                          /* Reserved */
    SVC_Handler,                /* SVCall Handler */
    DebugMon_Handler,           /* Debug Monitor Handler */
    0,                          /* Reserved */
    PendSV_Handler,             /* PendSV Handler */
    SysTick_Handler             /* SysTick Handler */
    /* IRQ vectors would continue here */
};
