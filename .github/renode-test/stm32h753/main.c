/* main.c - Entry point for wolfCrypt test on STM32H753 under Renode
 *
 * Runs the wolfCrypt test suite with output via USART3.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

/* wolfCrypt test entry point */
extern int wolfcrypt_test(void *args);

/* USART3 registers (STM32H7) */
#define USART3_BASE     0x40004800UL
#define USART3_CR1      (*(volatile uint32_t *)(USART3_BASE + 0x00))
#define USART3_BRR      (*(volatile uint32_t *)(USART3_BASE + 0x0C))
#define USART3_ISR      (*(volatile uint32_t *)(USART3_BASE + 0x1C))
#define USART3_TDR      (*(volatile uint32_t *)(USART3_BASE + 0x28))

#define USART_CR1_UE    (1 << 0)
#define USART_CR1_TE    (1 << 3)
#define USART_ISR_TXE   (1 << 7)

/* RCC registers for enabling USART3 clock */
#define RCC_BASE        0x58024400UL
#define RCC_APB1LENR    (*(volatile uint32_t *)(RCC_BASE + 0xE8))
#define RCC_APB1LENR_USART3EN (1 << 18)

static void uart_init(void)
{
    /* Enable USART3 clock */
    RCC_APB1LENR |= RCC_APB1LENR_USART3EN;
    
    /* Configure USART3: 115200 baud at 64MHz HSI */
    USART3_BRR = 64000000 / 115200;
    USART3_CR1 = USART_CR1_UE | USART_CR1_TE;
}

static void uart_putc(char c)
{
    while (!(USART3_ISR & USART_ISR_TXE))
        ;
    USART3_TDR = c;
}

static void uart_puts(const char *s)
{
    while (*s) {
        if (*s == '\n')
            uart_putc('\r');
        uart_putc(*s++);
    }
}

/* newlib _write syscall - redirects printf to UART */
int _write(int fd, const char *buf, int len)
{
    (void)fd;
    for (int i = 0; i < len; i++) {
        if (buf[i] == '\n')
            uart_putc('\r');
        uart_putc(buf[i]);
    }
    return len;
}

/* Heap management for malloc - required by printf with format strings */
extern char __heap_start__;
extern char __heap_end__;

void *_sbrk(ptrdiff_t incr)
{
    static char *heap_ptr = NULL;
    char *prev_heap_ptr;

    if (heap_ptr == NULL) {
        heap_ptr = &__heap_start__;
    }

    prev_heap_ptr = heap_ptr;

    if (heap_ptr + incr > &__heap_end__) {
        /* Out of heap memory */
        return (void *)-1;
    }

    heap_ptr += incr;
    return prev_heap_ptr;
}

/* Simple counter for time - used by GENSEED_FORTEST */
static volatile uint32_t tick_counter = 0;

/* time() stub for wolfSSL GENSEED_FORTEST */
#include <time.h>
time_t time(time_t *t)
{
    tick_counter += 12345;  /* Simple pseudo-random increment */
    time_t val = (time_t)tick_counter;
    if (t)
        *t = val;
    return val;
}

/* Result variable - can be monitored by Renode at fixed address */
volatile int test_result __attribute__((section(".data"))) = -1;
volatile int test_complete __attribute__((section(".data"))) = 0;


int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    uart_init();
    uart_puts("\n\n=== Starting wolfCrypt test ===\n\n");

    test_result = wolfcrypt_test(NULL);
    test_complete = 1;

    if (test_result == 0) {
        uart_puts("\n\n=== wolfCrypt test passed! ===\n");
    } else {
        uart_puts("\n\n=== wolfCrypt test FAILED ===\n");
    }

    /* Spin forever after the test completes */
    while (1) {
        __asm__ volatile ("wfi");
    }

    return test_result;
}

