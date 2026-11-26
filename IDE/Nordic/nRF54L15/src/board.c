/* board.c
 *
 * Copyright (C) 2006-2026 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
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

/* nRF54L15 DK board support: console on UARTE20 (P1.04 TX, the DK's VCOM0),
 * newlib syscalls, and a cycle counter. Uses the header-only nrfx HAL. */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <nrfx.h>
#include <hal/nrf_uarte.h>
#include <hal/nrf_gpio.h>
#include <hal/nrf_timer.h>

#include "board.h"

/* TAMPC, from the nRF54L15 datasheet (7.8.6.6); the MDK has no register map */
#define TAMPC_BASE              0x500DC000UL
#define TAMPC_EVENTS_TAMPER     (*(volatile uint32_t*)(TAMPC_BASE + 0x100UL))
#define TAMPC_STATUS            (*(volatile uint32_t*)(TAMPC_BASE + 0x400UL))
#define TAMPC_CRACENTAMP_STATUS (*(volatile uint32_t*)(TAMPC_BASE + 0x93CUL))
#define TAMPC_INTRESETEN_CTRL   (*(volatile uint32_t*)(TAMPC_BASE + 0x978UL))
#define TAMPC_CTRL_KEY          (0x50FAUL << 16)
#define TAMPC_CTRL_WRPROT_CLEAR (0xFUL << 4)

/* Cycle counter: TIMER00 ticks at the CPU clock and sits outside the debug
 * power domain. */
#define CYCLE_TIMER     NRF_TIMER00

#define CONSOLE_UARTE   NRF_UARTE20
#define CONSOLE_TX_PIN  NRF_GPIO_PIN_MAP(1, 4)

/* EasyDMA source: must be in RAM */
static uint8_t uartBuf[64];

static void uart_send(const uint8_t* p, size_t n)
{
    while (n > 0) {
        size_t c = (n > sizeof(uartBuf)) ? sizeof(uartBuf) : n;
        memcpy(uartBuf, p, c);
        nrf_uarte_event_clear(CONSOLE_UARTE, NRF_UARTE_EVENT_ENDTX);
        nrf_uarte_tx_buffer_set(CONSOLE_UARTE, uartBuf, c);
        nrf_uarte_task_trigger(CONSOLE_UARTE, NRF_UARTE_TASK_STARTTX);
        while (!nrf_uarte_event_check(CONSOLE_UARTE, NRF_UARTE_EVENT_ENDTX)) {
        }
        p += c;
        n -= c;
    }
}

void board_init(void)
{
    nrf_uarte_config_t cfg;

    memset(&cfg, 0, sizeof(cfg));
    cfg.hwfc   = NRF_UARTE_HWFC_DISABLED;
    cfg.parity = NRF_UARTE_PARITY_EXCLUDED;
    cfg.stop   = NRF_UARTE_STOP_ONE;
#if NRF_UARTE_HAS_FRAME_TIMEOUT
    cfg.frame_timeout = NRF_UARTE_FRAME_TIMEOUT_DIS;
#endif

    nrf_gpio_pin_set(CONSOLE_TX_PIN);
    nrf_gpio_cfg_output(CONSOLE_TX_PIN);
    nrf_uarte_txrx_pins_set(CONSOLE_UARTE, CONSOLE_TX_PIN,
        NRF_UARTE_PSEL_DISCONNECTED);
    nrf_uarte_baudrate_set(CONSOLE_UARTE, NRF_UARTE_BAUDRATE_115200);
    nrf_uarte_configure(CONSOLE_UARTE, &cfg);
    nrf_uarte_enable(CONSOLE_UARTE);
    /* newlib sees no tty and would buffer a kilobyte before writing */
    setvbuf(stdout, NULL, _IONBF, 0);

    nrf_timer_mode_set(CYCLE_TIMER, NRF_TIMER_MODE_TIMER);
    nrf_timer_bit_width_set(CYCLE_TIMER, NRF_TIMER_BIT_WIDTH_32);
    nrf_timer_prescaler_set(CYCLE_TIMER, 0);
    nrf_timer_task_trigger(CYCLE_TIMER, NRF_TIMER_TASK_CLEAR);
    nrf_timer_task_trigger(CYCLE_TIMER, NRF_TIMER_TASK_START);
}

uint32_t board_cycles(void)
{
    nrf_timer_task_trigger(CYCLE_TIMER, NRF_TIMER_TASK_CAPTURE0);
    return nrf_timer_cc_get(CYCLE_TIMER, NRF_TIMER_CC_CHANNEL0);
}

uint32_t board_clock_hz(void)
{
    /* TIMER00 ticks at the CPU clock */
    SystemCoreClockUpdate();
    return SystemCoreClock;
}

/* newlib: stdout/stderr to the console, LF expanded to CRLF */
int _write(int fd, const char* buf, int len)
{
    static uint8_t line[128];
    size_t n = 0;
    int i;

    (void)fd;
    for (i = 0; i < len; i++) {
        if (buf[i] == '\n') {
            if (n == sizeof(line)) {
                uart_send(line, n);
                n = 0;
            }
            line[n++] = '\r';
        }
        if (n == sizeof(line)) {
            uart_send(line, n);
            n = 0;
        }
        line[n++] = (uint8_t)buf[i];
    }
    if (n > 0)
        uart_send(line, n);
    return len;
}

/* newlib: heap between the MDK's __HeapBase and __HeapLimit */
void* _sbrk(ptrdiff_t incr)
{
    extern char __HeapBase[];
    extern char __HeapLimit[];
    static char* brk = NULL;
    char* prev;

    if (brk == NULL)
        brk = __HeapBase;
    if (brk + incr > __HeapLimit || brk + incr < __HeapBase) {
        errno = ENOMEM;
        return (void*)-1;
    }
    prev = brk;
    brk += incr;
    return prev;
}

void board_tamper_reset_disable(void)
{
    /* the write protection is cleared in a separate write, then VALUE = 0 */
    TAMPC_INTRESETEN_CTRL = TAMPC_CTRL_KEY | TAMPC_CTRL_WRPROT_CLEAR;
    TAMPC_INTRESETEN_CTRL = TAMPC_CTRL_KEY;
}

uint32_t board_tamper_status(uint32_t* events, uint32_t* cracenTamp)
{
    if (events != NULL)
        *events = TAMPC_EVENTS_TAMPER;
    if (cracenTamp != NULL)
        *cracenTamp = TAMPC_CRACENTAMP_STATUS;
    return TAMPC_STATUS;
}
