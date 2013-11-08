/* -----------------------------------------------------------------------------
 * Copyright (C) 2013 ARM Limited. All rights reserved.
 *  
 * $Date:        27. June 2013
 * $Revision:    V1.01
 *  
 * Project:      RTE Device Configuration for ST STM32F2xx
 * -------------------------------------------------------------------------- */

//-------- <<< Use Configuration Wizard in Context Menu >>> --------------------

#ifndef __RTE_DEVICE_H
#define __RTE_DEVICE_H


#define GPIO_PORT(num) \
 ((num == 0) ? GPIOA : \
  (num == 1) ? GPIOB : \
  (num == 2) ? GPIOC : \
  (num == 3) ? GPIOD : \
  (num == 4) ? GPIOE : \
  (num == 5) ? GPIOF : \
  (num == 6) ? GPIOG : \
  (num == 7) ? GPIOH : \
  (num == 8) ? GPIOI : \
  NULL)


// <h> Clock Configuration
//   <o> High-speed Internal Clock <1-999999999>
#define RTE_HSI                         16000000
//   <o> High-speed External Clock <1-999999999>
#define RTE_HSE                         25000000
//   <o> System Clock <1-999999999>
#define RTE_SYSCLK                      120000000
//   <o> AHB Clock    <1-999999999>
#define RTE_HCLK                        120000000
//   <o> APB1 Clock   <1-999999999>
#define RTE_PCLK1                       30000000
//   <o> APB2 Clock   <1-999999999>
#define RTE_PCLK2                       60000000
//       48MHz Clock
#define RTE_PLL48CK                     48000000
// </h>


// <e> USART1 (Universal synchronous asynchronous receiver transmitter) [Driver_UART1]
// <i> Configuration settings for Driver_UART1 in component ::Drivers:UART
#define RTE_USART1                      0

//   <o> USART1_TX Pin <0=>PA9 <1=>PB6
#define RTE_USART1_TX_ID                0
#if    (RTE_USART1_TX_ID == 0)
#define RTE_USART1_TX_PORT              GPIOA
#define RTE_USART1_TX_BIT               9
#elif  (RTE_USART1_TX_ID == 1)
#define RTE_USART1_TX_PORT              GPIOB
#define RTE_USART1_TX_BIT               6
#else
#error "Invalid USART1_TX Pin Configuration!"
#endif

//   <o> USART1_RX Pin <0=>PA10 <1=>PB7
#define RTE_USART1_RX_ID                0
#if    (RTE_USART1_RX_ID == 0)
#define RTE_USART1_RX_PORT              GPIOA
#define RTE_USART1_RX_BIT               10
#elif  (RTE_USART1_RX_ID == 1)
#define RTE_USART1_RX_PORT              GPIOB
#define RTE_USART1_RX_BIT               7
#else
#error "Invalid USART1_RX Pin Configuration!"
#endif

//     <e> Synchronous
//       <o1> USART1_CK Pin <0=>PA8
//     </e>
#define RTE_USART1_CK                   0
#define RTE_USART1_CK_ID                0
#if    (RTE_USART1_CK_ID == 0)
#define RTE_USART1_CK_PORT              GPIOA
#define RTE_USART1_CK_BIT               8
#else
#error "Invalid USART1_CK Pin Configuration!"
#endif

//     <e> Hardware flow control
//       <o1> USART1_CTS Pin <0=>PA11
//       <o2> USART1_RTS Pin <0=>PA12
//       <o3.0> Manual CTS/RTS
//     </e>
#define RTE_USART1_HW_FLOW              0
#define RTE_USART1_CTS_ID               0
#define RTE_USART1_RTS_ID               0
#define RTE_USART1_MANUAL_FLOW          0
#if    (RTE_USART1_CTS_ID == 0)
#define RTE_USART1_CTS_PORT             GPIOA
#define RTE_USART1_CTS_BIT              11
#else
#error "Invalid USART1_CTS Pin Configuration!"
#endif
#if    (RTE_USART1_RTS_ID == 0)
#define RTE_USART1_RTS_PORT             GPIOA
#define RTE_USART1_RTS_BIT              12
#else
#error "Invalid USART1_RTS Pin Configuration!"
#endif

//   <e> DMA Rx
//     <o1> Number <2=>2
//     <i>  Selects DMA Number (only DMA2 can be used)
//     <o2> Stream <2=>2 <5=>5
//     <i>  Selects DMA Stream (only Stream 2 or 5 can be used)
//     <o3> Channel <4=>4
//     <i>  Selects DMA Channel (only Channel 4 can be used)
//     <o4> Priority <0=>Low <1=>Medium <2=>High <3=>Very High
//     <i>  Selects DMA Priority
//   </e>
#define RTE_USART1_RX_DMA               1
#define RTE_USART1_RX_DMA_NUMBER        2
#define RTE_USART1_RX_DMA_STREAM        2
#define RTE_USART1_RX_DMA_CHANNEL       4
#define RTE_USART1_RX_DMA_PRIORITY      0

//   <e> DMA Tx
//     <o1> Number <2=>2
//     <i>  Selects DMA Number (only DMA2 can be used)
//     <o2> Stream <7=>7
//     <i>  Selects DMA Stream (only Stream 7 can be used)
//     <o3> Channel <4=>4
//     <i>  Selects DMA Channel (only Channel 4 can be used)
//     <o4> Priority <0=>Low <1=>Medium <2=>High <3=>Very High
//     <i>  Selects DMA Priority
//   </e>
#define RTE_USART1_TX_DMA               1
#define RTE_USART1_TX_DMA_NUMBER        2
#define RTE_USART1_TX_DMA_STREAM        7
#define RTE_USART1_TX_DMA_CHANNEL       4
#define RTE_USART1_TX_DMA_PRIORITY      0

// </e>


// <e> USART2 (Universal synchronous asynchronous receiver transmitter) [Driver_UART2]
// <i> Configuration settings for Driver_UART2 in component ::Drivers:UART
#define RTE_USART2                      0

//   <o> USART2_TX Pin <0=>PA2 <1=>PD5
#define RTE_USART2_TX_ID                0
#if    (RTE_USART2_TX_ID == 0)
#define RTE_USART2_TX_PORT              GPIOA
#define RTE_USART2_TX_BIT               2
#elif  (RTE_USART2_TX_ID == 1)
#define RTE_USART2_TX_PORT              GPIOD
#define RTE_USART2_TX_BIT               5
#else
#error "Invalid USART2_TX Pin Configuration!"
#endif

//   <o> USART2_RX Pin <0=>PA3 <1=>PD6
#define RTE_USART2_RX_ID                0
#if    (RTE_USART2_RX_ID == 0)
#define RTE_USART2_RX_PORT              GPIOA
#define RTE_USART2_RX_BIT               3
#elif  (RTE_USART2_RX_ID == 1)
#define RTE_USART2_RX_PORT              GPIOD
#define RTE_USART2_RX_BIT               6
#else
#error "Invalid USART2_RX Pin Configuration!"
#endif

//     <e> Synchronous
//       <o1> USART2_CK Pin <0=>PA4 <1=>PD7
//     </e>
#define RTE_USART2_CK                   0
#define RTE_USART2_CK_ID                0
#if    (RTE_USART2_CK_ID == 0)
#define RTE_USART2_CK_PORT              GPIOA
#define RTE_USART2_CK_BIT               4
#elif  (RTE_USART2_CK_ID == 1)
#define RTE_USART2_CK_PORT              GPIOD
#define RTE_USART2_CK_BIT               7
#else
#error "Invalid USART2_CK Pin Configuration!"
#endif

//     <e> Hardware flow control
//       <o1> USART2_CTS Pin <0=>PA0 <1=>PD3
//       <o2> USART2_RTS Pin <0=>PA1 <1=>PD4
//       <o3.0> Manual CTS/RTS
//     </e>
#define RTE_USART2_HW_FLOW              0
#define RTE_USART2_CTS_ID               0
#define RTE_USART2_RTS_ID               0
#define RTE_USART2_MANUAL_FLOW          0
#if    (RTE_USART2_CTS_ID == 0)
#define RTE_USART2_CTS_PORT             GPIOA
#define RTE_USART2_CTS_BIT              0
#elif  (RTE_USART2_CTS_ID == 1)
#define RTE_USART2_CTS_PORT             GPIOD
#define RTE_USART2_CTS_BIT              3
#else
#error "Invalid USART2_CTS Pin Configuration!"
#endif
#if    (RTE_USART2_RTS_ID == 0)
#define RTE_USART2_RTS_PORT             GPIOA
#define RTE_USART2_RTS_BIT              1
#elif  (RTE_USART2_RTS_ID == 1)
#define RTE_USART2_RTS_PORT             GPIOD
#define RTE_USART2_RTS_BIT              4
#else
#error "Invalid USART2_RTS Pin Configuration!"
#endif

//   <e> DMA Rx
//     <o1> Number <1=>1
//     <i>  Selects DMA Number (only DMA1 can be used)
//     <o2> Stream <5=>5
//     <i>  Selects DMA Stream (only Stream 5 can be used)
//     <o3> Channel <4=>4
//     <i>  Selects DMA Channel (only Channel 4 can be used)
//     <o4> Priority <0=>Low <1=>Medium <2=>High <3=>Very High
//     <i>  Selects DMA Priority
//   </e>
#define RTE_USART2_RX_DMA               1
#define RTE_USART2_RX_DMA_NUMBER        1
#define RTE_USART2_RX_DMA_STREAM        5
#define RTE_USART2_RX_DMA_CHANNEL       4
#define RTE_USART2_RX_DMA_PRIORITY      0

//   <e> DMA Tx
//     <o1> Number <1=>1
//     <i>  Selects DMA Number (only DMA1 can be used)
//     <o2> Stream <6=>6
//     <i>  Selects DMA Stream (only Stream 6 can be used)
//     <o3> Channel <4=>4
//     <i>  Selects DMA Channel (only Channel 4 can be used)
//     <o4> Priority <0=>Low <1=>Medium <2=>High <3=>Very High
//     <i>  Selects DMA Priority
//   </e>
#define RTE_USART2_TX_DMA               1
#define RTE_USART2_TX_DMA_NUMBER        1
#define RTE_USART2_TX_DMA_STREAM        6
#define RTE_USART2_TX_DMA_CHANNEL       4
#define RTE_USART2_TX_DMA_PRIORITY      0

// </e>


// <e> USART3 (Universal synchronous asynchronous receiver transmitter) [Driver_UART3]
// <i> Configuration settings for Driver_UART3 in component ::Drivers:UART
#define RTE_USART3                      0

//   <o> USART3_TX Pin <0=>PB10 <1=>PC10 <2=>PD8
#define RTE_USART3_TX_ID                0
#if    (RTE_USART3_TX_ID == 0)
#define RTE_USART3_TX_PORT              GPIOB
#define RTE_USART3_TX_BIT               10
#elif  (RTE_USART3_TX_ID == 1)
#define RTE_USART3_TX_PORT              GPIOC
#define RTE_USART3_TX_BIT               10
#elif  (RTE_USART3_TX_ID == 2)
#define RTE_USART3_TX_PORT              GPIOD
#define RTE_USART3_TX_BIT               8
#else
#error "Invalid USART3_TX Pin Configuration!"
#endif

//   <o> USART3_RX Pin <0=>PB11 <1=>PC11 <2=>PD9
#define RTE_USART3_RX_ID                0
#if    (RTE_USART3_RX_ID == 0)
#define RTE_USART3_RX_PORT              GPIOB
#define RTE_USART3_RX_BIT               11
#elif  (RTE_USART3_RX_ID == 1)
#define RTE_USART3_RX_PORT              GPIOC
#define RTE_USART3_RX_BIT               11
#elif  (RTE_USART3_RX_ID == 2)
#define RTE_USART3_RX_PORT              GPIOD
#define RTE_USART3_RX_BIT               9
#else
#error "Invalid USART3_RX Pin Configuration!"
#endif

//     <e> Synchronous
//       <o1> USART3_CK Pin <0=>PB12 <1=>PC12 <2=>PD10
//     </e>
#define RTE_USART3_CK                   0
#define RTE_USART3_CK_ID                0
#if    (RTE_USART3_CK_ID == 0)
#define RTE_USART3_CK_PORT              GPIOB
#define RTE_USART3_CK_BIT               12
#elif  (RTE_USART3_CK_ID == 1)
#define RTE_USART3_CK_PORT              GPIOC
#define RTE_USART3_CK_BIT               12
#elif  (RTE_USART3_CK_ID == 2)
#define RTE_USART3_CK_PORT              GPIOD
#define RTE_USART3_CK_BIT               10
#else
#error "Invalid USART3_CK Pin Configuration!"
#endif

//     <e> Hardware flow control
//       <o1> USART3_CTS Pin <0=>PB13 <1=>PD11
//       <o2> USART3_RTS Pin <0=>PB14 <1=>PD12
//       <o3.0> Manual CTS/RTS
//     </e>
#define RTE_USART3_HW_FLOW              0
#define RTE_USART3_CTS_ID               0
#define RTE_USART3_RTS_ID               0
#define RTE_USART3_MANUAL_FLOW          0
#if    (RTE_USART3_CTS_ID == 0)
#define RTE_USART3_CTS_PORT             GPIOB
#define RTE_USART3_CTS_BIT              13
#elif  (RTE_USART3_CTS_ID == 1)
#define RTE_USART3_CTS_PORT             GPIOD
#define RTE_USART3_CTS_BIT              11
#else
#error "Invalid USART3_CTS Pin Configuration!"
#endif
#if    (RTE_USART3_RTS_ID == 0)
#define RTE_USART3_RTS_PORT             GPIOB
#define RTE_USART3_RTS_BIT              14
#elif  (RTE_USART3_RTS_ID == 1)
#define RTE_USART3_RTS_PORT             GPIOD
#define RTE_USART3_RTS_BIT              12
#else
#error "Invalid USART3_RTS Pin Configuration!"
#endif

//   <e> DMA Rx
//     <o1> Number <1=>1
//     <i>  Selects DMA Number (only DMA1 can be used)
//     <o2> Stream <1=>1
//     <i>  Selects DMA Stream (only Stream 1 can be used)
//     <o3> Channel <4=>4
//     <i>  Selects DMA Channel (only Channel 4 can be used)
//     <o4> Priority <0=>Low <1=>Medium <2=>High <3=>Very High
//     <i>  Selects DMA Priority
//   </e>
#define RTE_USART3_RX_DMA               1
#define RTE_USART3_RX_DMA_NUMBER        1
#define RTE_USART3_RX_DMA_STREAM        1
#define RTE_USART3_RX_DMA_CHANNEL       4
#define RTE_USART3_RX_DMA_PRIORITY      0

//   <e> DMA Tx
//     <o1> Number <1=>1
//     <i>  Selects DMA Number (only DMA1 can be used)
//     <o2> Stream <3=>3
//     <i>  Selects DMA Stream (only Stream 3 can be used)
//     <o3> Channel <4=>4
//     <i>  Selects DMA Channel (only Channel 4 can be used)
//     <o4> Priority <0=>Low <1=>Medium <2=>High <3=>Very High
//     <i>  Selects DMA Priority
//   </e>
#define RTE_USART3_TX_DMA               1
#define RTE_USART3_TX_DMA_NUMBER        1
#define RTE_USART3_TX_DMA_STREAM        3
#define RTE_USART3_TX_DMA_CHANNEL       4
#define RTE_USART3_TX_DMA_PRIORITY      0

// </e>


// <e> UART4 (Universal asynchronous receiver transmitter) [Driver_UART4]
// <i> Configuration settings for Driver_UART4 in component ::Drivers:UART
#define RTE_UART4                       0

//   <o> UART4_TX Pin <0=>PA0 <1=>PC10
#define RTE_UART4_TX_ID                 0
#if    (RTE_UART4_TX_ID == 0)
#define RTE_UART4_TX_PORT               GPIOA
#define RTE_UART4_TX_BIT                0
#elif  (RTE_UART4_TX_ID == 1)
#define RTE_UART4_TX_PORT               GPIOC
#define RTE_UART4_TX_BIT                10
#else
#error "Invalid UART4_TX Pin Configuration!"
#endif

//   <o> UART4_RX Pin <0=>PA1 <1=>PC11
#define RTE_UART4_RX_ID                 0
#if    (RTE_UART4_RX_ID == 0)
#define RTE_UART4_RX_PORT               GPIOA
#define RTE_UART4_RX_BIT                1
#elif  (RTE_UART4_RX_ID == 1)
#define RTE_UART4_RX_PORT               GPIOC
#define RTE_UART4_RX_BIT                11
#else
#error "Invalid UART4_RX Pin Configuration!"
#endif

//   <e> DMA Rx
//     <o1> Number <1=>1
//     <i>  Selects DMA Number (only DMA1 can be used)
//     <o2> Stream <2=>2
//     <i>  Selects DMA Stream (only Stream 2 can be used)
//     <o3> Channel <4=>4
//     <i>  Selects DMA Channel (only Channel 4 can be used)
//     <o4> Priority <0=>Low <1=>Medium <2=>High <3=>Very High
//     <i>  Selects DMA Priority
//   </e>
#define RTE_UART4_RX_DMA                1
#define RTE_UART4_RX_DMA_NUMBER         1
#define RTE_UART4_RX_DMA_STREAM         2
#define RTE_UART4_RX_DMA_CHANNEL        4
#define RTE_UART4_RX_DMA_PRIORITY       0

//   <e> DMA Tx
//     <o1> Number <1=>1
//     <i>  Selects DMA Number (only DMA1 can be used)
//     <o2> Stream <4=>4
//     <i>  Selects DMA Stream (only Stream 4 can be used)
//     <o3> Channel <4=>4
//     <i>  Selects DMA Channel (only Channel 4 can be used)
//     <o4> Priority <0=>Low <1=>Medium <2=>High <3=>Very High
//     <i>  Selects DMA Priority
//   </e>
#define RTE_UART4_TX_DMA                1
#define RTE_UART4_TX_DMA_NUMBER         1
#define RTE_UART4_TX_DMA_STREAM         4
#define RTE_UART4_TX_DMA_CHANNEL        4
#define RTE_UART4_TX_DMA_PRIORITY       0

// </e>


// <e> UART5 (Universal asynchronous receiver transmitter) [Driver_UART5]
// <i> Configuration settings for Driver_UART5 in component ::Drivers:UART
#define RTE_UART5                       0

//   <o> UART5_TX Pin <0=>PC12
#define RTE_UART5_TX_ID                 0
#if    (RTE_UART5_TX_ID == 0)
#define RTE_UART5_TX_PORT               GPIOC
#define RTE_UART5_TX_BIT                12
#else
#error "Invalid UART5_TX Pin Configuration!"
#endif

//   <o> UART5_RX Pin <0=>PD2
#define RTE_UART5_RX_ID                 0
#if    (RTE_UART5_RX_ID == 0)
#define RTE_UART5_RX_PORT               GPIOD
#define RTE_UART5_RX_BIT                2
#else
#error "Invalid UART5_RX Pin Configuration!"
#endif

//   <e> DMA Rx
//     <o1> Number <1=>1
//     <i>  Selects DMA Number (only DMA1 can be used)
//     <o2> Stream <0=>0
//     <i>  Selects DMA Stream (only Stream 0 can be used)
//     <o3> Channel <4=>4
//     <i>  Selects DMA Channel (only Channel 4 can be used)
//     <o4> Priority <0=>Low <1=>Medium <2=>High <3=>Very High
//     <i>  Selects DMA Priority
//   </e>
#define RTE_UART5_RX_DMA                1
#define RTE_UART5_RX_DMA_NUMBER         1
#define RTE_UART5_RX_DMA_STREAM         0
#define RTE_UART5_RX_DMA_CHANNEL        4
#define RTE_UART5_RX_DMA_PRIORITY       0

//   <e> DMA Tx
//     <o1> Number <1=>1
//     <i>  Selects DMA Number (only DMA1 can be used)
//     <o2> Stream <7=>7
//     <i>  Selects DMA Stream (only Stream 7 can be used)
//     <o3> Channel <4=>4
//     <i>  Selects DMA Channel (only Channel 4 can be used)
//     <o4> Priority <0=>Low <1=>Medium <2=>High <3=>Very High
//     <i>  Selects DMA Priority
//   </e>
#define RTE_UART5_TX_DMA                1
#define RTE_UART5_TX_DMA_NUMBER         1
#define RTE_UART5_TX_DMA_STREAM         7
#define RTE_UART5_TX_DMA_CHANNEL        4
#define RTE_UART5_TX_DMA_PRIORITY       0

// </e>


// <e> USART6 (Universal synchronous asynchronous receiver transmitter) [Driver_UART6]
// <i> Configuration settings for Driver_UART6 in component ::Drivers:UART
#define RTE_USART6                      0

//   <o> USART6_TX Pin <0=>PC6 <1=>PG14
#define RTE_USART6_TX_ID                0
#if    (RTE_USART6_TX_ID == 0)
#define RTE_USART6_TX_PORT              GPIOC
#define RTE_USART6_TX_BIT               6
#elif  (RTE_USART6_TX_ID == 1)
#define RTE_USART6_TX_PORT              GPIOG
#define RTE_USART6_TX_BIT               14
#else
#error "Invalid USART6_TX Pin Configuration!"
#endif

//   <o> USART6_RX Pin <0=>PC7 <1=>PG9
#define RTE_USART6_RX_ID                0
#if    (RTE_USART6_RX_ID == 0)
#define RTE_USART6_RX_PORT              GPIOC
#define RTE_USART6_RX_BIT               7
#elif  (RTE_USART6_RX_ID == 1)
#define RTE_USART6_RX_PORT              GPIOG
#define RTE_USART6_RX_BIT               9
#else
#error "Invalid USART6_RX Pin Configuration!"
#endif

//     <e> Synchronous
//       <o1> USART6_CK Pin <0=>PC8 <1=>PG7
//     </e>
#define RTE_USART6_CK                   0
#define RTE_USART6_CK_ID                0
#if    (RTE_USART6_CK_ID == 0)
#define RTE_USART6_CK_PORT              GPIOC
#define RTE_USART6_CK_BIT               8
#elif  (RTE_USART6_CK_ID == 1)
#define RTE_USART6_CK_PORT              GPIOG
#define RTE_USART6_CK_BIT               7
#else
#error "Invalid USART6_CK Pin Configuration!"
#endif

//     <e> Hardware flow control
//       <o1> USART6_CTS Pin <0=>PG13 <1=>PG15
//       <o2> USART6_RTS Pin <0=>PG8  <1=>PG12
//       <o3.0> Manual CTS/RTS
//     </e>
#define RTE_USART6_HW_FLOW              0
#define RTE_USART6_CTS_ID               0
#define RTE_USART6_RTS_ID               0
#define RTE_USART6_MANUAL_FLOW          0
#if    (RTE_USART6_CTS_ID == 0)
#define RTE_USART6_CTS_PORT             GPIOG
#define RTE_USART6_CTS_BIT              13
#elif  (RTE_USART6_CTS_ID == 1)
#define RTE_USART6_CTS_PORT             GPIOG
#define RTE_USART6_CTS_BIT              15
#else
#error "Invalid USART6_CTS Pin Configuration!"
#endif
#if    (RTE_USART6_RTS_ID == 0)
#define RTE_USART6_RTS_PORT             GPIOG
#define RTE_USART6_RTS_BIT              8
#elif  (RTE_USART6_RTS_ID == 1)
#define RTE_USART6_RTS_PORT             GPIOG
#define RTE_USART6_RTS_BIT              12
#else
#error "Invalid USART6_RTS Pin Configuration!"
#endif

//   <e> DMA Rx
//     <o1> Number <2=>2
//     <i>  Selects DMA Number (only DMA2 can be used)
//     <o2> Stream <1=>1 <2=>2
//     <i>  Selects DMA Stream (only Stream 1 or 2 can be used)
//     <o3> Channel <5=>5
//     <i>  Selects DMA Channel (only Channel 5 can be used)
//     <o4> Priority <0=>Low <1=>Medium <2=>High <3=>Very High
//     <i>  Selects DMA Priority
//   </e>
#define RTE_USART6_RX_DMA               1
#define RTE_USART6_RX_DMA_NUMBER        2
#define RTE_USART6_RX_DMA_STREAM        1
#define RTE_USART6_RX_DMA_CHANNEL       5
#define RTE_USART6_RX_DMA_PRIORITY      0

//   <e> DMA Tx
//     <o1> Number <2=>2
//     <i>  Selects DMA Number (only DMA2 can be used)
//     <o2> Stream <6=>6 <7=>7
//     <i>  Selects DMA Stream (only Stream 6 or 7 can be used)
//     <o3> Channel <5=>5
//     <i>  Selects DMA Channel (only Channel 5 can be used)
//     <o4> Priority <0=>Low <1=>Medium <2=>High <3=>Very High
//     <i>  Selects DMA Priority
//   </e>
#define RTE_USART6_TX_DMA               1
#define RTE_USART6_TX_DMA_NUMBER        2
#define RTE_USART6_TX_DMA_STREAM        6
#define RTE_USART6_TX_DMA_CHANNEL       5
#define RTE_USART6_TX_DMA_PRIORITY      0

// </e>


// <e> I2C1 (Inter-integrated Circuit Interface 1) [Driver_I2C1]
// <i> Configuration settings for Driver_I2C1 in component ::Drivers:I2C
#define RTE_I2C1                        0

//   <o> I2C1_SCL Pin <0=>PB6 <1=>PB8
#define RTE_I2C1_SCL_PORT_ID            0
#if    (RTE_I2C1_SCL_PORT_ID == 0)
#define RTE_I2C1_SCL_PORT               GPIOB
#define RTE_I2C1_SCL_BIT                6
#elif  (RTE_I2C1_SCL_PORT_ID == 1)
#define RTE_I2C1_SCL_PORT               GPIOB
#define RTE_I2C1_SCL_BIT                8
#else
#error "Invalid I2C1_SCL Pin Configuration!"
#endif

//   <o> I2C1_SDA Pin <0=>PB7 <1=>PB9
#define RTE_I2C1_SDA_PORT_ID            0
#if    (RTE_I2C1_SDA_PORT_ID == 0)
#define RTE_I2C1_SDA_PORT               GPIOB
#define RTE_I2C1_SDA_BIT                7
#elif  (RTE_I2C1_SDA_PORT_ID == 1)
#define RTE_I2C1_SDA_PORT               GPIOB
#define RTE_I2C1_SDA_BIT                9
#else
#error "Invalid I2C1_SDA Pin Configuration!"
#endif

//   <e> DMA Rx
//     <o1> Number <1=>1
//     <i>  Selects DMA Number (only DMA1 can be used)
//     <o2> Stream <0=>0 <5=>5
//     <i>  Selects DMA Stream (only Stream 0 or 5 can be used)
//     <o3> Channel <1=>1
//     <i>  Selects DMA Channel (only Channel 1 can be used)
//     <o4> Priority <0=>Low <1=>Medium <2=>High <3=>Very High
//     <i>  Selects DMA Priority
//   </e>
#define RTE_I2C1_RX_DMA                 1
#define RTE_I2C1_RX_DMA_NUMBER          1
#define RTE_I2C1_RX_DMA_STREAM          0
#define RTE_I2C1_RX_DMA_CHANNEL         1
#define RTE_I2C1_RX_DMA_PRIORITY        0

//   <e> DMA Tx
//     <o1> Number <1=>1
//     <i>  Selects DMA Number (only DMA1 can be used)
//     <o2> Stream <6=>6 <7=>7
//     <i>  Selects DMA Stream (only Stream 6 or 7 can be used)
//     <o3> Channel <1=>1
//     <i>  Selects DMA Channel (only Channel 1 can be used)
//     <o4> Priority <0=>Low <1=>Medium <2=>High <3=>Very High
//     <i>  Selects DMA Priority
//   </e>
#define RTE_I2C1_TX_DMA                 1
#define RTE_I2C1_TX_DMA_NUMBER          1
#define RTE_I2C1_TX_DMA_STREAM          6
#define RTE_I2C1_TX_DMA_CHANNEL         1
#define RTE_I2C1_TX_DMA_PRIORITY        0

// </e>


// <e> I2C2 (Inter-integrated Circuit Interface 2) [Driver_I2C2]
// <i> Configuration settings for Driver_I2C2 in component ::Drivers:I2C
#define RTE_I2C2                        0

//   <o> I2C2_SCL Pin <0=>PF1 <1=>PH4 <2=>PB10
#define RTE_I2C2_SCL_PORT_ID            0
#if    (RTE_I2C2_SCL_PORT_ID == 0)
#define RTE_I2C2_SCL_PORT               GPIOF
#define RTE_I2C2_SCL_BIT                1
#elif  (RTE_I2C2_SCL_PORT_ID == 1)
#define RTE_I2C2_SCL_PORT               GPIOH
#define RTE_I2C2_SCL_BIT                4
#elif  (RTE_I2C2_SCL_PORT_ID == 2)
#define RTE_I2C2_SCL_PORT               GPIOB
#define RTE_I2C2_SCL_BIT                10
#else
#error "Invalid I2C2_SCL Pin Configuration!"
#endif

//   <o> I2C2_SDA Pin <0=>PF0 <1=>PH5 <2=>PB11
#define RTE_I2C2_SDA_PORT_ID            0
#if    (RTE_I2C2_SDA_PORT_ID == 0)
#define RTE_I2C2_SDA_PORT               GPIOF
#define RTE_I2C2_SDA_BIT                0
#elif  (RTE_I2C2_SDA_PORT_ID == 1)
#define RTE_I2C2_SDA_PORT               GPIOH
#define RTE_I2C2_SDA_BIT                5
#elif  (RTE_I2C2_SDA_PORT_ID == 2)
#define RTE_I2C2_SDA_PORT               GPIOB
#define RTE_I2C2_SDA_BIT                11
#else
#error "Invalid I2C2_SCL Pin Configuration!"
#endif

//   <e> DMA Rx
//     <o1> Number <1=>1
//     <i>  Selects DMA Number (only DMA1 can be used)
//     <o2> Stream <2=>2 <3=>3
//     <i>  Selects DMA Stream (only Stream 2 or 3 can be used)
//     <o3> Channel <7=>7
//     <i>  Selects DMA Channel (only Channel 7 can be used)
//     <o4> Priority <0=>Low <1=>Medium <2=>High <3=>Very High
//     <i>  Selects DMA Priority
//   </e>
#define RTE_I2C2_RX_DMA                 1
#define RTE_I2C2_RX_DMA_NUMBER          1
#define RTE_I2C2_RX_DMA_STREAM          2
#define RTE_I2C2_RX_DMA_CHANNEL         7
#define RTE_I2C2_RX_DMA_PRIORITY        0

//   <e> DMA Tx
//     <o1> Number <1=>1
//     <i>  Selects DMA Number (only DMA1 can be used)
//     <o2> Stream <7=>7
//     <i>  Selects DMA Stream (only Stream 7 can be used)
//     <o3> Channel <7=>7
//     <i>  Selects DMA Channel (only Channel 1 can be used)
//     <o4> Priority <0=>Low <1=>Medium <2=>High <3=>Very High
//     <i>  Selects DMA Priority
//   </e>
#define RTE_I2C2_TX_DMA                 1
#define RTE_I2C2_TX_DMA_NUMBER          1
#define RTE_I2C2_TX_DMA_STREAM          7
#define RTE_I2C2_TX_DMA_CHANNEL         7
#define RTE_I2C2_TX_DMA_PRIORITY        0

// </e>


// <e> I2C3 (Inter-integrated Circuit Interface 3) [Driver_I2C3]
// <i> Configuration settings for Driver_I2C3 in component ::Drivers:I2C
#define RTE_I2C3                        0

//   <o> I2C3_SCL Pin <0=>PH7 <1=>PA8
#define RTE_I2C3_SCL_PORT_ID            0
#if    (RTE_I2C3_SCL_PORT_ID == 0)
#define RTE_I2C3_SCL_PORT               GPIOH
#define RTE_I2C3_SCL_BIT                7
#elif  (RTE_I2C3_SCL_PORT_ID == 1)
#define RTE_I2C3_SCL_PORT               GPIOA
#define RTE_I2C3_SCL_BIT                8
#else
#error "Invalid I2C3_SCL Pin Configuration!"
#endif

//   <o> I2C3_SDA Pin <0=>PH8 <1=>PC9
#define RTE_I2C3_SDA_PORT_ID            0
#if    (RTE_I2C3_SDA_PORT_ID == 0)
#define RTE_I2C3_SDA_PORT               GPIOH
#define RTE_I2C3_SDA_BIT                8
#elif  (RTE_I2C3_SDA_PORT_ID == 1)
#define RTE_I2C3_SDA_PORT               GPIOC
#define RTE_I2C3_SDA_BIT                9
#else
#error "Invalid I2C3_SCL Pin Configuration!"
#endif

//   <e> DMA Rx
//     <o1> Number <1=>1
//     <i>  Selects DMA Number (only DMA1 can be used)
//     <o2> Stream <2=>2
//     <i>  Selects DMA Stream (only Stream 2 can be used)
//     <o3> Channel <3=>3
//     <i>  Selects DMA Channel (only Channel 3 can be used)
//     <o4> Priority <0=>Low <1=>Medium <2=>High <3=>Very High
//     <i>  Selects DMA Priority
//   </e>
#define RTE_I2C3_RX_DMA                 1
#define RTE_I2C3_RX_DMA_NUMBER          1
#define RTE_I2C3_RX_DMA_STREAM          2
#define RTE_I2C3_RX_DMA_CHANNEL         3
#define RTE_I2C3_RX_DMA_PRIORITY        0

//   <e> DMA Tx
//     <o1> Number <1=>1
//     <i>  Selects DMA Number (only DMA1 can be used)
//     <o2> Stream <4=>4
//     <i>  Selects DMA Stream (only Stream 4 can be used)
//     <o3> Channel <3=>3
//     <i>  Selects DMA Channel (only Channel 3 can be used)
//     <o4> Priority <0=>Low <1=>Medium <2=>High <3=>Very High
//     <i>  Selects DMA Priority
//   </e>
#define RTE_I2C3_TX_DMA                 1
#define RTE_I2C3_TX_DMA_NUMBER          1
#define RTE_I2C3_TX_DMA_STREAM          4
#define RTE_I2C3_TX_DMA_CHANNEL         3
#define RTE_I2C3_TX_DMA_PRIORITY        0

// </e>


// <e> SPI1 (Serial Peripheral Interface 1) [Driver_SPI1]
// <i> Configuration settings for Driver_SPI1 in component ::Drivers:SPI
#define RTE_SPI1                        0

//   <e> SPI1_NSS Pin
//   <i> Configure Pin if exists
//   <i> GPIO Pxy (x = A..H, y = 0..15) or (x = I, y = 0..11)
//     <o1> Port <0=>GPIOA <1=>GPIOB <2=>GPIOC <3=>GPIOD
//               <4=>GPIOE <5=>GPIOF <6=>GPIOG <7=>GPIOH <8=>GPIOI
//     <i>  Selects Port Name
//     <o2> Bit <0-15>
//     <i>  Selects Port Bit
//   </e>
#define RTE_SPI1_NSS_PIN                1
#define RTE_SPI1_NSS_PORT               GPIO_PORT(0)
#define RTE_SPI1_NSS_BIT                4

//   <o> SPI1_SCK Pin <0=>PA5 <1=>PB3
#define RTE_SPI1_SCL_PORT_ID            0
#if    (RTE_SPI1_SCL_PORT_ID == 0)
#define RTE_SPI1_SCL_PORT               GPIOA
#define RTE_SPI1_SCL_BIT                5
#elif  (RTE_SPI1_SCL_PORT_ID == 1)
#define RTE_SPI1_SCL_PORT               GPIOB
#define RTE_SPI1_SCL_BIT                3
#else
#error "Invalid SPI1_SCK Pin Configuration!"
#endif

//   <o> SPI1_MISO Pin <0=>PA6 <1=>PB4
#define RTE_SPI1_MISO_PORT_ID           0
#if    (RTE_SPI1_MISO_PORT_ID == 0)
#define RTE_SPI1_MISO_PORT              GPIOA
#define RTE_SPI1_MISO_BIT               6
#elif  (RTE_SPI1_MISO_PORT_ID == 1)
#define RTE_SPI1_MISO_PORT              GPIOB
#define RTE_SPI1_MISO_BIT               4
#else
#error "Invalid SPI1_MISO Pin Configuration!"
#endif

//   <o> SPI1_MOSI Pin <0=>PA7 <1=>PB5
#define RTE_SPI1_MOSI_PORT_ID           0
#if    (RTE_SPI1_MOSI_PORT_ID == 0)
#define RTE_SPI1_MOSI_PORT              GPIOA
#define RTE_SPI1_MOSI_BIT               7
#elif  (RTE_SPI1_MOSI_PORT_ID == 1)
#define RTE_SPI1_MOSI_PORT              GPIOB
#define RTE_SPI1_MOSI_BIT               5
#else
#error "Invalid SPI1_MISO Pin Configuration!"
#endif

//   <e> DMA Rx
//     <o1> Number <2=>2
//     <i>  Selects DMA Number (only DMA2 can be used)
//     <o2> Stream <0=>0 <2=>2
//     <i>  Selects DMA Stream (only Stream 0 or 2 can be used)
//     <o3> Channel <3=>3
//     <i>  Selects DMA Channel (only Channel 3 can be used)
//     <o4> Priority <0=>Low <1=>Medium <2=>High <3=>Very High
//     <i>  Selects DMA Priority
//   </e>
#define RTE_SPI1_RX_DMA                 1
#define RTE_SPI1_RX_DMA_NUMBER          2
#define RTE_SPI1_RX_DMA_STREAM          0
#define RTE_SPI1_RX_DMA_CHANNEL         3
#define RTE_SPI1_RX_DMA_PRIORITY        0

//   <e> DMA Tx
//     <o1> Number <2=>2
//     <i>  Selects DMA Number (only DMA2 can be used)
//     <o2> Stream <3=>3 <5=>5
//     <i>  Selects DMA Stream (only Stream 3 or 5 can be used)
//     <o3> Channel <3=>3
//     <i>  Selects DMA Channel (only Channel 3 can be used)
//     <o4> Priority <0=>Low <1=>Medium <2=>High <3=>Very High
//     <i>  Selects DMA Priority
//   </e>
#define RTE_SPI1_TX_DMA                 1
#define RTE_SPI1_TX_DMA_NUMBER          2
#define RTE_SPI1_TX_DMA_STREAM          5
#define RTE_SPI1_TX_DMA_CHANNEL         3
#define RTE_SPI1_TX_DMA_PRIORITY        0

// </e>


// <e> SPI2 (Serial Peripheral Interface 2) [Driver_SPI2]
// <i> Configuration settings for Driver_SPI2 in component ::Drivers:SPI
#define RTE_SPI2                        0

//   <e> SPI2_NSS Pin
//   <i> Configure Pin if exists
//   <i> GPIO Pxy (x = A..H, y = 0..15) or (x = I, y = 0..11)
//     <o1> Port <0=>GPIOA <1=>GPIOB <2=>GPIOC <3=>GPIOD
//               <4=>GPIOE <5=>GPIOF <6=>GPIOG <7=>GPIOH <8=>GPIOI
//     <i>  Selects Port Name
//     <o2> Bit <0-15>
//     <i>  Selects Port Bit
//   </e>
#define RTE_SPI2_NSS_PIN                1
#define RTE_SPI2_NSS_PORT               GPIO_PORT(1)
#define RTE_SPI2_NSS_BIT                12

//   <o> SPI2_SCK Pin <0=>PB10 <1=>PB13 <2=>PI1
#define RTE_SPI2_SCL_PORT_ID            0
#if    (RTE_SPI2_SCL_PORT_ID == 0)
#define RTE_SPI2_SCL_PORT               GPIOB
#define RTE_SPI2_SCL_BIT                10
#elif  (RTE_SPI2_SCL_PORT_ID == 1)
#define RTE_SPI2_SCL_PORT               GPIOB
#define RTE_SPI2_SCL_BIT                13
#elif  (RTE_SPI2_SCL_PORT_ID == 2)
#define RTE_SPI2_SCL_PORT               GPIOI
#define RTE_SPI2_SCL_BIT                1
#else
#error "Invalid SPI2_SCK Pin Configuration!"
#endif

//   <o> SPI2_MISO Pin <0=>PB14 <1=>PC2 <2=>PI2
#define RTE_SPI2_MISO_PORT_ID           0
#if    (RTE_SPI2_MISO_PORT_ID == 0)
#define RTE_SPI2_MISO_PORT              GPIOB
#define RTE_SPI2_MISO_BIT               14
#elif  (RTE_SPI2_MISO_PORT_ID == 1)
#define RTE_SPI2_MISO_PORT              GPIOC
#define RTE_SPI2_MISO_BIT               2
#elif  (RTE_SPI2_MISO_PORT_ID == 2)
#define RTE_SPI2_MISO_PORT              GPIOI
#define RTE_SPI2_MISO_BIT               2
#else
#error "Invalid SPI2_MISO Pin Configuration!"
#endif

//   <o> SPI2_MOSI Pin <0=>PB15 <1=>PC3 <2=>OI3
#define RTE_SPI2_MOSI_PORT_ID           0
#if    (RTE_SPI2_MOSI_PORT_ID == 0)
#define RTE_SPI2_MOSI_PORT              GPIOB
#define RTE_SPI2_MOSI_BIT               15
#elif  (RTE_SPI2_MOSI_PORT_ID == 1)
#define RTE_SPI2_MOSI_PORT              GPIOC
#define RTE_SPI2_MOSI_BIT               3
#elif  (RTE_SPI2_MOSI_PORT_ID == 2)
#define RTE_SPI2_MOSI_PORT              GPIOI
#define RTE_SPI2_MOSI_BIT               3
#else
#error "Invalid SPI2_MISO Pin Configuration!"
#endif

//   <e> DMA Rx
//     <o1> Number <1=>1
//     <i>  Selects DMA Number (only DMA1 can be used)
//     <o2> Stream <2=>2
//     <i>  Selects DMA Stream (only Stream 2 can be used)
//     <o3> Channel <0=>0
//     <i>  Selects DMA Channel (only Channel 0 can be used)
//     <o4> Priority <0=>Low <1=>Medium <2=>High <3=>Very High
//     <i>  Selects DMA Priority
//   </e>
#define RTE_SPI2_RX_DMA                 1
#define RTE_SPI2_RX_DMA_NUMBER          1
#define RTE_SPI2_RX_DMA_STREAM          2
#define RTE_SPI2_RX_DMA_CHANNEL         0
#define RTE_SPI2_RX_DMA_PRIORITY        0

//   <e> DMA Tx
//     <o1> Number <1=>1
//     <i>  Selects DMA Number (only DMA1 can be used)
//     <o2> Stream <3=>3
//     <i>  Selects DMA Stream (only Stream 3 can be used)
//     <o3> Channel <0=>0
//     <i>  Selects DMA Channel (only Channel 0 can be used)
//     <o4> Priority <0=>Low <1=>Medium <2=>High <3=>Very High
//     <i>  Selects DMA Priority
//   </e>
#define RTE_SPI2_TX_DMA                 1
#define RTE_SPI2_TX_DMA_NUMBER          1
#define RTE_SPI2_TX_DMA_STREAM          3
#define RTE_SPI2_TX_DMA_CHANNEL         0
#define RTE_SPI2_TX_DMA_PRIORITY        0

// </e>


// <e> SPI3 (Serial Peripheral Interface 3) [Driver_SPI3]
// <i> Configuration settings for Driver_SPI3 in component ::Drivers:SPI
#define RTE_SPI3                        0

//   <e> SPI3_NSS Pin
//   <i> Configure Pin if exists
//   <i> GPIO Pxy (x = A..H, y = 0..15) or (x = I, y = 0..11)
//     <o1> Port <0=>GPIOA <1=>GPIOB <2=>GPIOC <3=>GPIOD
//               <4=>GPIOE <5=>GPIOF <6=>GPIOG <7=>GPIOH <8=>GPIOI
//     <i>  Selects Port Name
//     <o2> Bit <0-15>
//     <i>  Selects Port Bit
//   </e>
#define RTE_SPI3_NSS_PIN                1
#define RTE_SPI3_NSS_PORT               GPIO_PORT(0)
#define RTE_SPI3_NSS_BIT                15

//   <o> SPI3_SCK Pin <0=>PB3 <1=>PC10
#define RTE_SPI3_SCL_PORT_ID            0
#if    (RTE_SPI3_SCL_PORT_ID == 0)
#define RTE_SPI3_SCL_PORT               GPIOB
#define RTE_SPI3_SCL_BIT                3
#elif  (RTE_SPI3_SCL_PORT_ID == 1)
#define RTE_SPI3_SCL_PORT               GPIOC
#define RTE_SPI3_SCL_BIT                10
#else
#error "Invalid SPI3_SCK Pin Configuration!"
#endif

//   <o> SPI3_MISO Pin <0=>PB4 <1=>PC11
#define RTE_SPI3_MISO_PORT_ID           0
#if    (RTE_SPI3_MISO_PORT_ID == 0)
#define RTE_SPI3_MISO_PORT              GPIOB
#define RTE_SPI3_MISO_BIT               4
#elif  (RTE_SPI3_MISO_PORT_ID == 1)
#define RTE_SPI3_MISO_PORT              GPIOC
#define RTE_SPI3_MISO_BIT               11
#else
#error "Invalid SPI3_MISO Pin Configuration!"
#endif

//   <o> SPI3_MOSI Pin <0=>PB5 <1=>PC12
#define RTE_SPI3_MOSI_PORT_ID           0
#if    (RTE_SPI3_MOSI_PORT_ID == 0)
#define RTE_SPI3_MOSI_PORT              GPIOB
#define RTE_SPI3_MOSI_BIT               5
#elif  (RTE_SPI3_MOSI_PORT_ID == 1)
#define RTE_SPI3_MOSI_PORT              GPIOC
#define RTE_SPI3_MOSI_BIT               12
#else
#error "Invalid SPI3_MISO Pin Configuration!"
#endif

//   <e> DMA Rx
//     <o1> Number <1=>1
//     <i>  Selects DMA Number (only DMA1 can be used)
//     <o2> Stream <0=>0 <2=>2
//     <i>  Selects DMA Stream (only Stream 0 or 2 can be used)
//     <o3> Channel <0=>0
//     <i>  Selects DMA Channel (only Channel 0 can be used)
//     <o4> Priority <0=>Low <1=>Medium <2=>High <3=>Very High
//     <i>  Selects DMA Priority
//   </e>
#define RTE_SPI3_RX_DMA                 1
#define RTE_SPI3_RX_DMA_NUMBER          1
#define RTE_SPI3_RX_DMA_STREAM          0
#define RTE_SPI3_RX_DMA_CHANNEL         0
#define RTE_SPI3_RX_DMA_PRIORITY        0

//   <e> DMA Tx
//     <o1> Number <1=>1
//     <i>  Selects DMA Number (only DMA1 can be used)
//     <o2> Stream <5=>5 <7=>7
//     <i>  Selects DMA Stream (only Stream 5 or 7 can be used)
//     <o3> Channel <0=>0
//     <i>  Selects DMA Channel (only Channel 0 can be used)
//     <o4> Priority <0=>Low <1=>Medium <2=>High <3=>Very High
//     <i>  Selects DMA Priority
//   </e>
#define RTE_SPI3_TX_DMA                 1
#define RTE_SPI3_TX_DMA_NUMBER          1
#define RTE_SPI3_TX_DMA_STREAM          5
#define RTE_SPI3_TX_DMA_CHANNEL         0
#define RTE_SPI3_TX_DMA_PRIORITY        0

// </e>


// <e> SDIO (Secure Digital Input/Output) [Driver_MCI0]
// <i> Configuration settings for Driver_MCI0 in component ::Drivers:MCI
#define RTE_SDIO                        1

//   <e> SDIO_CD (Card Detect) Pin
//   <i> Configure Pin if exists
//   <i> GPIO Pxy (x = A..H, y = 0..15) or (x = I, y = 0..11)
//     <o1> Active State <0=>Low <1=>High
//     <i>  Selects Active State Logical Level
//     <o2> Port <0=>GPIOA <1=>GPIOB <2=>GPIOC <3=>GPIOD
//               <4=>GPIOE <5=>GPIOF <6=>GPIOG <7=>GPIOH <8=>GPIOI
//     <i>  Selects Port Name
//     <o3> Bit <0-15>
//     <i>  Selects Port Bit
//   </e>
#define RTE_SDIO_CD_PIN                 1
#define RTE_SDIO_CD_ACTIVE              0
#define RTE_SDIO_CD_PORT                GPIO_PORT(7)
#define RTE_SDIO_CD_BIT                 15

//   <e> SDIO_WP (Write Protect) Pin
//   <i> Configure Pin if exists
//   <i> GPIO Pxy (x = A..H, y = 0..15) or (x = I, y = 0..11)
//     <o1> Active State <0=>Low <1=>High
//     <i>  Selects Active State Logical Level
//     <o2> Port <0=>GPIOA <1=>GPIOB <2=>GPIOC <3=>GPIOD
//               <4=>GPIOE <5=>GPIOF <6=>GPIOG <7=>GPIOH <8=>GPIOI
//     <i>  Selects Port Name
//     <o3> Bit <0-15>
//     <i>  Selects Port Bit
//   </e>
#define RTE_SDIO_WP_PIN                 0
#define RTE_SDIO_WP_ACTIVE              0
#define RTE_SDIO_WP_PORT                GPIO_PORT(7)
#define RTE_SDIO_WP_BIT                 16

//   <h> SDIO Bus
//     <o> SDIO_CK Pin <0=>PC12
#define RTE_SDIO_CK_PORT_ID             0
#if    (RTE_SDIO_CK_PORT_ID == 0)
#define RTE_SDIO_CK_PORT                GPIOC
#define RTE_SDIO_CK_PIN                 12
#else
#error "Invalid SDIO_CK Pin Configuration!"
#endif
//     <o> SDIO_CMD Pin <0=>PD2
#define RTE_SDIO_CMD_PORT_ID            0
#if    (RTE_SDIO_CMD_PORT_ID == 0)
#define RTE_SDIO_CMD_PORT               GPIOD
#define RTE_SDIO_CMD_PIN                2
#else
#error "Invalid SDIO_CDM Pin Configuration!"
#endif
//     <o> SDIO_D0 Pin <0=>PC8
#define RTE_SDIO_D0_PORT_ID             0
#if    (RTE_SDIO_D0_PORT_ID == 0)
#define RTE_SDIO_D0_PORT                GPIOC
#define RTE_SDIO_D0_PIN                 8
#else
#error "Invalid SDIO_D0 Pin Configuration!"
#endif
//     <o> SDIO_D1 Pin <0=>PC9
#define RTE_SDIO_D1_PORT_ID             0
#if    (RTE_SDIO_D1_PORT_ID == 0)
#define RTE_SDIO_D1_PORT                GPIOC
#define RTE_SDIO_D1_PIN                 9
#else
#error "Invalid SDIO_D1 Pin Configuration!"
#endif
//     <o> SDIO_D2 Pin <0=>PC10
#define RTE_SDIO_D2_PORT_ID             0
#if    (RTE_SDIO_D2_PORT_ID == 0)
#define RTE_SDIO_D2_PORT                GPIOC
#define RTE_SDIO_D2_PIN                 10
#else
#error "Invalid SDIO_D2 Pin Configuration!"
#endif
//     <o> SDIO_D3 Pin <0=>PC11
#define RTE_SDIO_D3_PORT_ID             0
#if    (RTE_SDIO_D3_PORT_ID == 0)
#define RTE_SDIO_D3_PORT                GPIOC
#define RTE_SDIO_D3_PIN                 11
#else
#error "Invalid SDIO_D3 Pin Configuration!"
#endif
//     <o> SDIO_D4 Pin <0=>PB8
#define RTE_SDIO_D4_PORT_ID             0
#if    (RTE_SDIO_D4_PORT_ID == 0)
#define RTE_SDIO_D4_PORT                GPIOB
#define RTE_SDIO_D4_PIN                 8
#else
#error "Invalid SDIO_D4 Pin Configuration!"
#endif
//     <o> SDIO_D5 Pin <0=>PB9
#define RTE_SDIO_D5_PORT_ID             0
#if    (RTE_SDIO_D5_PORT_ID == 0)
#define RTE_SDIO_D5_PORT                GPIOB
#define RTE_SDIO_D5_PIN                 9
#else
#error "Invalid SDIO_D5 Pin Configuration!"
#endif
//     <o> SDIO_D6 Pin <0=>PC6
#define RTE_SDIO_D6_PORT_ID             0
#if    (RTE_SDIO_D6_PORT_ID == 0)
#define RTE_SDIO_D6_PORT                GPIOC
#define RTE_SDIO_D6_PIN                 6
#else
#error "Invalid SDIO_D6 Pin Configuration!"
#endif
//     <o> SDIO_D7 Pin <0=>PC7
#define RTE_SDIO_D7_PORT_ID             0
#if    (RTE_SDIO_D7_PORT_ID == 0)
#define RTE_SDIO_D7_PORT                GPIOC
#define RTE_SDIO_D7_PIN                 7
#else
#error "Invalid SDIO_D7 Pin Configuration!"
#endif
//   </h>

//   <e> DMA
//     <o1> Number <2=>2
//     <i>  Selects DMA Number (only DMA2 can be used)
//     <o2> Stream <3=>3 <6=>6
//     <i>  Selects DMA Stream (only Stream 3 or 6 can be used)
//     <o3> Channel <4=>4
//     <i>  Selects DMA Channel (only Channel 4 can be used)
//     <o4> Priority <0=>Low <1=>Medium <2=>High <3=>Very High
//     <i>  Selects DMA Priority
//   </e>
#define RTE_SDIO_DMA                    1
#define RTE_SDIO_DMA_NUMBER             2
#define RTE_SDIO_DMA_STREAM             3
#define RTE_SDIO_DMA_CHANNEL            4
#define RTE_SDIO_DMA_PRIORITY           0

// </e>


// <e> ETH (Ethernet Interface) [Driver_ETH_MAC0]
// <i> Configuration settings for Driver_ETH_MAC0 in component ::Drivers:Ethernet MAC
#define RTE_ETH                         1

//   <e> MII (Media Independent Interface)
#define RTE_ETH_MII                     0

//     <o> ETH_MII_TX_CLK Pin <0=>PC3
#define RTE_ETH_MII_TX_CLK_PORT_ID      0
#if    (RTE_ETH_MII_TX_CLK_PORT_ID == 0)
#define RTE_ETH_MII_TX_CLK_PORT         GPIOC
#define RTE_ETH_MII_TX_CLK_PIN          3
#else
#error "Invalid ETH_MII_TX_CLK Pin Configuration!"
#endif
//     <o> ETH_MII_TXD0 Pin <0=>PB12 <1=>PG13
#define RTE_ETH_MII_TXD0_PORT_ID        0
#if    (RTE_ETH_MII_TXD0_PORT_ID == 0)
#define RTE_ETH_MII_TXD0_PORT           GPIOB
#define RTE_ETH_MII_TXD0_PIN            12
#elif  (RTE_ETH_MII_TXD0_PORT_ID == 1)
#define RTE_ETH_MII_TXD0_PORT           GPIOG
#define RTE_ETH_MII_TXD0_PIN            13
#else
#error "Invalid ETH_MII_TXD0 Pin Configuration!"
#endif
//     <o> ETH_MII_TXD1 Pin <0=>PB13 <1=>PG14
#define RTE_ETH_MII_TXD1_PORT_ID        0
#if    (RTE_ETH_MII_TXD1_PORT_ID == 0)
#define RTE_ETH_MII_TXD1_PORT           GPIOB
#define RTE_ETH_MII_TXD1_PIN            13
#elif  (RTE_ETH_MII_TXD1_PORT_ID == 1)
#define RTE_ETH_MII_TXD1_PORT           GPIOG
#define RTE_ETH_MII_TXD1_PIN            14
#else
#error "Invalid ETH_MII_TXD1 Pin Configuration!"
#endif
//     <o> ETH_MII_TXD2 Pin <0=>PC2
#define RTE_ETH_MII_TXD2_PORT_ID        0
#if    (RTE_ETH_MII_TXD2_PORT_ID == 0)
#define RTE_ETH_MII_TXD2_PORT           GPIOC
#define RTE_ETH_MII_TXD2_PIN            2
#else
#error "Invalid ETH_MII_TXD2 Pin Configuration!"
#endif
//     <o> ETH_MII_TXD3 Pin <0=>PB8 <1=>PE2
#define RTE_ETH_MII_TXD3_PORT_ID        0
#if    (RTE_ETH_MII_TXD3_PORT_ID == 0)
#define RTE_ETH_MII_TXD3_PORT           GPIOB
#define RTE_ETH_MII_TXD3_PIN            8
#elif  (RTE_ETH_MII_TXD3_PORT_ID == 1)
#define RTE_ETH_MII_TXD3_PORT           GPIOE
#define RTE_ETH_MII_TXD3_PIN            2
#else
#error "Invalid ETH_MII_TXD3 Pin Configuration!"
#endif
//     <o> ETH_MII_TX_EN Pin <0=>PB11 <1=>PG11
#define RTE_ETH_MII_TX_EN_PORT_ID       0
#if    (RTE_ETH_MII_TX_EN_PORT_ID == 0)
#define RTE_ETH_MII_TX_EN_PORT          GPIOB
#define RTE_ETH_MII_TX_EN_PIN           11
#elif  (RTE_ETH_MII_TX_EN_PORT_ID == 1)
#define RTE_ETH_MII_TX_EN_PORT          GPIOG
#define RTE_ETH_MII_TX_EN_PIN           11
#else
#error "Invalid ETH_MII_TX_EN Pin Configuration!"
#endif
//     <o> ETH_MII_RX_CLK Pin <0=>PA1
#define RTE_ETH_MII_RX_CLK_PORT_ID        0
#if    (RTE_ETH_MII_RX_CLK_PORT_ID == 0)
#define RTE_ETH_MII_RX_CLK_PORT         GPIOA
#define RTE_ETH_MII_RX_CLK_PIN          1
#else
#error "Invalid ETH_MII_RX_CLK Pin Configuration!"
#endif
//     <o> ETH_MII_RXD0 Pin <0=>PC4
#define RTE_ETH_MII_RXD0_PORT_ID        0
#if    (RTE_ETH_MII_RXD0_PORT_ID == 0)
#define RTE_ETH_MII_RXD0_PORT           GPIOC
#define RTE_ETH_MII_RXD0_PIN            4
#else
#error "Invalid ETH_MII_RXD0 Pin Configuration!"
#endif
//     <o> ETH_MII_RXD1 Pin <0=>PC5
#define RTE_ETH_MII_RXD1_PORT_ID        0
#if    (RTE_ETH_MII_RXD1_PORT_ID == 0)
#define RTE_ETH_MII_RXD1_PORT           GPIOC
#define RTE_ETH_MII_RXD1_PIN            5
#else
#error "Invalid ETH_MII_RXD1 Pin Configuration!"
#endif
//     <o> ETH_MII_RXD2 Pin <0=>PB0 <1=>PH6
#define RTE_ETH_MII_RXD2_PORT_ID        0
#if    (RTE_ETH_MII_RXD2_PORT_ID == 0)
#define RTE_ETH_MII_RXD2_PORT           GPIOB
#define RTE_ETH_MII_RXD2_PIN            0
#elif  (RTE_ETH_MII_RXD2_PORT_ID == 1)
#define RTE_ETH_MII_RXD2_PORT           GPIOH
#define RTE_ETH_MII_RXD2_PIN            6
#else
#error "Invalid ETH_MII_RXD2 Pin Configuration!"
#endif
//     <o> ETH_MII_RXD3 Pin <0=>PB1 <1=>PH7
#define RTE_ETH_MII_RXD3_PORT_ID        0
#if    (RTE_ETH_MII_RXD3_PORT_ID == 0)
#define RTE_ETH_MII_RXD3_PORT           GPIOB
#define RTE_ETH_MII_RXD3_PIN            1
#elif  (RTE_ETH_MII_RXD3_PORT_ID == 1)
#define RTE_ETH_MII_RXD3_PORT           GPIOH
#define RTE_ETH_MII_RXD3_PIN            7
#else
#error "Invalid ETH_MII_RXD3 Pin Configuration!"
#endif
//     <o> ETH_MII_RX_DV Pin <0=>PA7
#define RTE_ETH_MII_RX_DV_PORT_ID       0
#if    (RTE_ETH_MII_RX_DV_PORT_ID == 0)
#define RTE_ETH_MII_RX_DV_PORT          GPIOA
#define RTE_ETH_MII_RX_DV_PIN           7
#else
#error "Invalid ETH_MII_RX_DV Pin Configuration!"
#endif
//     <o> ETH_MII_RX_ER Pin <0=>PB10 <1=>PI10
#define RTE_ETH_MII_RX_ER_PORT_ID       0
#if    (RTE_ETH_MII_RX_ER_PORT_ID == 0)
#define RTE_ETH_MII_RX_ER_PORT          GPIOB
#define RTE_ETH_MII_RX_ER_PIN           10
#elif  (RTE_ETH_MII_RXD3_PORT_ID == 1)
#define RTE_ETH_MII_RX_ER_PORT          GPIOI
#define RTE_ETH_MII_RX_ER_PIN           10
#else
#error "Invalid ETH_MII_RX_ER Pin Configuration!"
#endif
//     <o> ETH_MII_CRS Pin <0=>PA0 <1=>PH2
#define RTE_ETH_MII_CRS_PORT_ID       0
#if    (RTE_ETH_MII_CRS_PORT_ID == 0)
#define RTE_ETH_MII_CRS_PORT            GPIOA
#define RTE_ETH_MII_CRS_PIN             0
#elif  (RTE_ETH_MII_CRS_PORT_ID == 1)
#define RTE_ETH_MII_CRS_PORT            GPIOH
#define RTE_ETH_MII_CRS_PIN             2
#else
#error "Invalid ETH_MII_CRS Pin Configuration!"
#endif
//     <o> ETH_MII_COL Pin <0=>PA3 <1=>PH3
#define RTE_ETH_MII_COL_PORT_ID       0
#if    (RTE_ETH_MII_COL_PORT_ID == 0)
#define RTE_ETH_MII_COL_PORT            GPIOA
#define RTE_ETH_MII_COL_PIN             3
#elif  (RTE_ETH_MII_COL_PORT_ID == 1)
#define RTE_ETH_MII_COL_PORT            GPIOH
#define RTE_ETH_MII_COL_PIN             3
#else
#error "Invalid ETH_MII_COL Pin Configuration!"
#endif

//   </e>

//   <e> RMII (Reduced Media Independent Interface)
#define RTE_ETH_RMII                    1

//     <o> ETH_RMII_TXD0 Pin <0=>PB12 <1=>PG13
#define RTE_ETH_RMII_TXD0_PORT_ID       1
#if    (RTE_ETH_RMII_TXD0_PORT_ID == 0)
#define RTE_ETH_RMII_TXD0_PORT          GPIOB
#define RTE_ETH_RMII_TXD0_PIN           12
#elif  (RTE_ETH_RMII_TXD0_PORT_ID == 1)
#define RTE_ETH_RMII_TXD0_PORT          GPIOG
#define RTE_ETH_RMII_TXD0_PIN           13
#else
#error "Invalid ETH_RMII_TXD0 Pin Configuration!"
#endif
//     <o> ETH_RMII_TXD1 Pin <0=>PB13 <1=>PG14
#define RTE_ETH_RMII_TXD1_PORT_ID       1
#if    (RTE_ETH_RMII_TXD1_PORT_ID == 0)
#define RTE_ETH_RMII_TXD1_PORT          GPIOB
#define RTE_ETH_RMII_TXD1_PIN           13
#elif  (RTE_ETH_RMII_TXD1_PORT_ID == 1)
#define RTE_ETH_RMII_TXD1_PORT          GPIOG
#define RTE_ETH_RMII_TXD1_PIN           14
#else
#error "Invalid ETH_RMII_TXD1 Pin Configuration!"
#endif
//     <o> ETH_RMII_TX_EN Pin <0=>PB11 <1=>PG11
#define RTE_ETH_RMII_TX_EN_PORT_ID      1
#if    (RTE_ETH_RMII_TX_EN_PORT_ID == 0)
#define RTE_ETH_RMII_TX_EN_PORT         GPIOB
#define RTE_ETH_RMII_TX_EN_PIN          11
#elif  (RTE_ETH_RMII_TX_EN_PORT_ID == 1)
#define RTE_ETH_RMII_TX_EN_PORT         GPIOG
#define RTE_ETH_RMII_TX_EN_PIN          11
#else
#error "Invalid ETH_RMII_TX_EN Pin Configuration!"
#endif
//     <o> ETH_RMII_RXD0 Pin <0=>PC4
#define RTE_ETH_RMII_RXD0_PORT_ID       0
#if    (RTE_ETH_RMII_RXD0_PORT_ID == 0)
#define RTE_ETH_RMII_RXD0_PORT          GPIOC
#define RTE_ETH_RMII_RXD0_PIN           4
#else
#error "Invalid ETH_RMII_RXD0 Pin Configuration!"
#endif
//     <o> ETH_RMII_RXD1 Pin <0=>PC5
#define RTE_ETH_RMII_RXD1_PORT_ID       0
#if    (RTE_ETH_RMII_RXD1_PORT_ID == 0)
#define RTE_ETH_RMII_RXD1_PORT          GPIOC
#define RTE_ETH_RMII_RXD1_PIN           5
#else
#error "Invalid ETH_RMII_RXD1 Pin Configuration!"
#endif
//     <o> ETH_RMII_REF_CLK Pin <0=>PA1
#define RTE_ETH_RMII_REF_CLK_PORT_ID    0
#if    (RTE_ETH_RMII_REF_CLK_PORT_ID == 0)
#define RTE_ETH_RMII_REF_CLK_PORT       GPIOA
#define RTE_ETH_RMII_REF_CLK_PIN        1
#else
#error "Invalid ETH_RMII_REF_CLK Pin Configuration!"
#endif
//     <o> ETH_RMII_CRS_DV Pin <0=>PA7
#define RTE_ETH_RMII_CRS_DV_PORT_ID     0
#if    (RTE_ETH_RMII_CRS_DV_PORT_ID == 0)
#define RTE_ETH_RMII_CRS_DV_PORT        GPIOA
#define RTE_ETH_RMII_CRS_DV_PIN         7
#else
#error "Invalid ETH_RMII_CRS_DV Pin Configuration!"
#endif

//   </e>

//   <h> Management Data Interface
//     <o> ETH_MDC Pin <0=>PC1
#define RTE_ETH_MDI_MDC_PORT_ID         0
#if    (RTE_ETH_MDI_MDC_PORT_ID == 0)
#define RTE_ETH_MDI_MDC_PORT            GPIOC
#define RTE_ETH_MDI_MDC_PIN             1
#else
#error "Invalid ETH_MDC Pin Configuration!"
#endif
//     <o> ETH_MDIO Pin <0=>PA2
#define RTE_ETH_MDI_MDIO_PORT_ID        0
#if    (RTE_ETH_MDI_MDIO_PORT_ID == 0)
#define RTE_ETH_MDI_MDIO_PORT           GPIOA
#define RTE_ETH_MDI_MDIO_PIN            2
#else
#error "Invalid ETH_MDIO Pin Configuration!"
#endif
//   </h>

//   <e> Reference 25MHz/50MHz Clock generation
#define RTE_ETH_REF_CLOCK               0

//     <o> MCO Pin <0=>PA2 <1=>PC9
#define RTE_ETH_REF_CLOCK_PORT_ID       0
#if    (RTE_ETH_REF_CLOCK_PORT_ID == 0)
#define RTE_ETH_REF_CLOCK_PORT          GPIOA
#define RTE_ETH_REF_CLOCK_PIN           8
#elif  (RTE_ETH_REF_CLOCK_PORT_ID == 1)
#define RTE_ETH_REF_CLOCK_PORT          GPIOC
#define RTE_ETH_REF_CLOCK_PIN           9
#else
#error "Invalid MCO Pin Configuration!"
#endif

//   </e>

// </e>


// <e> USB OTG Full-speed
#define RTE_USB_OTG_FS                  0

//   <e> Device [Driver_USBD0]
//   <i> Configuration settings for Driver_USBD0 in component ::Drivers:USB Device
#define RTE_USB_OTG_FS_DEV              1

//     <h> Endpoints
//     <i> Reduce memory requirements of Driver by disabling unused endpoints
//       <e0.1> Endpoint 1
//         <o1.1>  Bulk OUT
//         <o1.17> Bulk IN
//         <o2.1>  Interrupt OUT
//         <o2.17> Interrupt IN
//         <o3.1>  Isochronous OUT
//         <o3.17> Isochronous IN
//       </e>
//       <e0.2> Endpoint 2
//         <o1.2>  Bulk OUT
//         <o1.18> Bulk IN
//         <o2.2>  Interrupt OUT
//         <o2.18> Interrupt IN
//         <o3.2>  Isochronous OUT
//         <o3.18> Isochronous IN
//       </e>
//       <e0.3> Endpoint 3
//         <o1.3>  Bulk OUT
//         <o1.19> Bulk IN
//         <o2.3>  Interrupt OUT
//         <o2.19> Interrupt IN
//         <o3.3>  Isochronous OUT
//         <o3.19> Isochronous IN
//       </e>
//     </h>
#define RTE_USB_OTG_FS_DEV_EP           0x0000000F
#define RTE_USB_OTG_FS_DEV_EP_BULK      0x000E000E
#define RTE_USB_OTG_FS_DEV_EP_INT       0x000E000E
#define RTE_USB_OTG_FS_DEV_EP_ISO       0x000E000E

//   </e>

//   <e> Host [Driver_USBH0]
//   <i> Configuration settings for Driver_USBH0 in component ::Drivers:USB Host

#define RTE_USB_OTG_FS_HOST             1

//     <e> VBUS Power On/Off Pin
//     <i> Configure Pin for driving VBUS
//     <i> GPIO Pxy (x = A..H, y = 0..15) or (x = I, y = 0..11)
//       <o1> Active State <0=>Low <1=>High
//       <i>  Selects Active State Logical Level
//       <o2> Port <0=>GPIOA <1=>GPIOB <2=>GPIOC <3=>GPIOD
//                 <4=>GPIOE <5=>GPIOF <6=>GPIOG <7=>GPIOH <8=>GPIOI
//       <i>  Selects Port Name
//       <o3> Bit <0-15>
//       <i>  Selects Port Bit
//     </e>
#define RTE_OTG_FS_VBUS_PIN             1
#define RTE_OTG_FS_VBUS_ACTIVE          0
#define RTE_OTG_FS_VBUS_PORT            GPIO_PORT(7)
#define RTE_OTG_FS_VBUS_BIT             5

//     <e> Overcurrent Detection Pin
//     <i> Configure Pin for overcurrent detection
//     <i> GPIO Pxy (x = A..H, y = 0..15) or (x = I, y = 0..11)
//       <o1> Active State <0=>Low <1=>High
//       <i>  Selects Active State Logical Level
//       <o2> Port <0=>GPIOA <1=>GPIOB <2=>GPIOC <3=>GPIOD
//                 <4=>GPIOE <5=>GPIOF <6=>GPIOG <7=>GPIOH <8=>GPIOI
//       <i>  Selects Port Name
//       <o3> Bit <0-15>
//       <i>  Selects Port Bit
//     </e>
#define RTE_OTG_FS_OC_PIN               1
#define RTE_OTG_FS_OC_ACTIVE            0
#define RTE_OTG_FS_OC_PORT              GPIO_PORT(5)
#define RTE_OTG_FS_OC_BIT               11
//   </e>

// </e>


// <e> USB OTG High-speed
#define RTE_USB_OTG_HS                  0

//   <h> PHY (Physical Layer)

//     <o> PHY Interface
//       <0=>On-chip full-speed PHY
//       <1=>External ULPI high-speed PHY
#define RTE_USB_OTG_HS_PHY              1

//     <h> External ULPI Pins (UTMI+ Low Pin Interface)

//       <o> OTG_HS_ULPI_CK Pin <0=>PA5
#define RTE_USB_OTG_HS_ULPI_CK_PORT_ID  0
#if    (RTE_USB_OTG_HS_ULPI_CK_PORT_ID == 0)
#define RTE_USB_OTG_HS_ULPI_CK_PORT     GPIOA
#define RTE_USB_OTG_HS_ULPI_CK_PIN      5
#else
#error "Invalid OTG_HS_ULPI_CK Pin Configuration!"
#endif
//       <o> OTG_HS_ULPI_DIR Pin <0=>PI11 <1=>PC2
#define RTE_USB_OTG_HS_ULPI_DIR_PORT_ID 0
#if    (RTE_USB_OTG_HS_ULPI_DIR_PORT_ID == 0)
#define RTE_USB_OTG_HS_ULPI_DIR_PORT    GPIOI
#define RTE_USB_OTG_HS_ULPI_DIR_PIN     11
#elif  (RTE_USB_OTG_HS_ULPI_DIR_PORT_ID == 1)
#define RTE_USB_OTG_HS_ULPI_DIR_PORT    GPIOC
#define RTE_USB_OTG_HS_ULPI_DIR_PIN     2
#else
#error "Invalid OTG_HS_ULPI_DIR Pin Configuration!"
#endif
//       <o> OTG_HS_ULPI_STP Pin <0=>PC0
#define RTE_USB_OTG_HS_ULPI_STP_PORT_ID 0
#if    (RTE_USB_OTG_HS_ULPI_STP_PORT_ID == 0)
#define RTE_USB_OTG_HS_ULPI_STP_PORT    GPIOC
#define RTE_USB_OTG_HS_ULPI_STP_PIN     0
#else
#error "Invalid OTG_HS_ULPI_STP Pin Configuration!"
#endif
//       <o> OTG_HS_ULPI_NXT Pin <0=>PC2 <1=>PH4
#define RTE_USB_OTG_HS_ULPI_NXT_PORT_ID 1
#if    (RTE_USB_OTG_HS_ULPI_NXT_PORT_ID == 0)
#define RTE_USB_OTG_HS_ULPI_NXT_PORT    GPIOC
#define RTE_USB_OTG_HS_ULPI_NXT_PIN     2
#elif  (RTE_USB_OTG_HS_ULPI_NXT_PORT_ID == 1)
#define RTE_USB_OTG_HS_ULPI_NXT_PORT    GPIOH
#define RTE_USB_OTG_HS_ULPI_NXT_PIN     4
#else
#error "Invalid OTG_HS_ULPI_NXT Pin Configuration!"
#endif
//       <o> OTG_HS_ULPI_D0 Pin <0=>PA3
#define RTE_USB_OTG_HS_ULPI_D0_PORT_ID  0
#if    (RTE_USB_OTG_HS_ULPI_D0_PORT_ID == 0)
#define RTE_USB_OTG_HS_ULPI_D0_PORT     GPIOA
#define RTE_USB_OTG_HS_ULPI_D0_PIN      3
#else
#error "Invalid OTG_HS_ULPI_D0 Pin Configuration!"
#endif
//       <o> OTG_HS_ULPI_D1 Pin <0=>PB0
#define RTE_USB_OTG_HS_ULPI_D1_PORT_ID  0
#if    (RTE_USB_OTG_HS_ULPI_D1_PORT_ID == 0)
#define RTE_USB_OTG_HS_ULPI_D1_PORT     GPIOB
#define RTE_USB_OTG_HS_ULPI_D1_PIN      0
#else
#error "Invalid OTG_HS_ULPI_D1 Pin Configuration!"
#endif
//       <o> OTG_HS_ULPI_D2 Pin <0=>PB1
#define RTE_USB_OTG_HS_ULPI_D2_PORT_ID  0
#if    (RTE_USB_OTG_HS_ULPI_D2_PORT_ID == 0)
#define RTE_USB_OTG_HS_ULPI_D2_PORT     GPIOB
#define RTE_USB_OTG_HS_ULPI_D2_PIN      1
#else
#error "Invalid OTG_HS_ULPI_D2 Pin Configuration!"
#endif
//       <o> OTG_HS_ULPI_D3 Pin <0=>PB10
#define RTE_USB_OTG_HS_ULPI_D3_PORT_ID  0
#if    (RTE_USB_OTG_HS_ULPI_D3_PORT_ID == 0)
#define RTE_USB_OTG_HS_ULPI_D3_PORT     GPIOB
#define RTE_USB_OTG_HS_ULPI_D3_PIN      10
#else
#error "Invalid OTG_HS_ULPI_D3 Pin Configuration!"
#endif
//       <o> OTG_HS_ULPI_D4 Pin <0=>PB11
#define RTE_USB_OTG_HS_ULPI_D4_PORT_ID  0
#if    (RTE_USB_OTG_HS_ULPI_D4_PORT_ID == 0)
#define RTE_USB_OTG_HS_ULPI_D4_PORT     GPIOB
#define RTE_USB_OTG_HS_ULPI_D4_PIN      11
#else
#error "Invalid OTG_HS_ULPI_D4 Pin Configuration!"
#endif
//       <o> OTG_HS_ULPI_D5 Pin <0=>PB12
#define RTE_USB_OTG_HS_ULPI_D5_PORT_ID  0
#if    (RTE_USB_OTG_HS_ULPI_D5_PORT_ID == 0)
#define RTE_USB_OTG_HS_ULPI_D5_PORT     GPIOB
#define RTE_USB_OTG_HS_ULPI_D5_PIN      12
#else
#error "Invalid OTG_HS_ULPI_D5 Pin Configuration!"
#endif
//       <o> OTG_HS_ULPI_D6 Pin <0=>PB13
#define RTE_USB_OTG_HS_ULPI_D6_PORT_ID  0
#if    (RTE_USB_OTG_HS_ULPI_D6_PORT_ID == 0)
#define RTE_USB_OTG_HS_ULPI_D6_PORT     GPIOB
#define RTE_USB_OTG_HS_ULPI_D6_PIN      13
#else
#error "Invalid OTG_HS_ULPI_D6 Pin Configuration!"
#endif
//       <o> OTG_HS_ULPI_D7 Pin <0=>PB5
#define RTE_USB_OTG_HS_ULPI_D7_PORT_ID  0
#if    (RTE_USB_OTG_HS_ULPI_D7_PORT_ID == 0)
#define RTE_USB_OTG_HS_ULPI_D7_PORT     GPIOB
#define RTE_USB_OTG_HS_ULPI_D7_PIN      5
#else
#error "Invalid OTG_HS_ULPI_D7 Pin Configuration!"
#endif

//     </h>

//   </h>

//   <e> Device [Driver_USBD1]
//   <i> Configuration settings for Driver_USBD1 in component ::Drivers:USB Device
#define RTE_USB_OTG_HS_DEV              1

//     <h> Endpoints
//     <i> Reduce memory requirements of Driver by disabling unused endpoints
//       <e0.1> Endpoint 1
//         <o1.1>  Bulk OUT
//         <o1.17> Bulk IN
//         <o2.1>  Interrupt OUT
//         <o2.17> Interrupt IN
//         <o3.1>  Isochronous OUT
//         <o3.17> Isochronous IN
//       </e>
//       <e0.2> Endpoint 2
//         <o1.2>  Bulk OUT
//         <o1.18> Bulk IN
//         <o2.2>  Interrupt OUT
//         <o2.18> Interrupt IN
//         <o3.2>  Isochronous OUT
//         <o3.18> Isochronous IN
//       </e>
//       <e0.3> Endpoint 3
//         <o1.3>  Bulk OUT
//         <o1.19> Bulk IN
//         <o2.3>  Interrupt OUT
//         <o2.19> Interrupt IN
//         <o3.3>  Isochronous OUT
//         <o3.19> Isochronous IN
//       </e>
//       <e0.4> Endpoint 4
//         <o1.4>  Bulk OUT
//         <o1.20> Bulk IN
//         <o2.4>  Interrupt OUT
//         <o2.20> Interrupt IN
//         <o3.4>  Isochronous OUT
//         <o3.20> Isochronous IN
//       </e>
//       <e0.5> Endpoint 5
//         <o1.5>  Bulk OUT
//         <o1.21> Bulk IN
//         <o2.5>  Interrupt OUT
//         <o2.21> Interrupt IN
//         <o3.5>  Isochronous OUT
//         <o3.21> Isochronous IN
//       </e>
//     </h>
#define RTE_USB_OTG_HS_DEV_EP           0x0000003F
#define RTE_USB_OTG_HS_DEV_EP_BULK      0x003E003E
#define RTE_USB_OTG_HS_DEV_EP_INT       0x003E003E
#define RTE_USB_OTG_HS_DEV_EP_ISO       0x003E003E

//   </e>

//   <e> Host [Driver_USBH1]
//   <i> Configuration settings for Driver_USBH1 in component ::Drivers:USB Host
#define RTE_USB_OTG_HS_HOST             1

//     <e> VBUS Power On/Off Pin
//     <i> Configure Pin for driving VBUS
//     <i> GPIO Pxy (x = A..H, y = 0..15) or (x = I, y = 0..11)
//       <o1> Active State <0=>Low <1=>High
//       <i>  Selects Active State Logical Level
//       <o2> Port <0=>GPIOA <1=>GPIOB <2=>GPIOC <3=>GPIOD
//                 <4=>GPIOE <5=>GPIOF <6=>GPIOG <7=>GPIOH <8=>GPIOI
//       <i>  Selects Port Name
//       <o3> Bit <0-15>
//       <i>  Selects Port Bit
//     </e>
#define RTE_OTG_HS_VBUS_PIN             1
#define RTE_OTG_HS_VBUS_ACTIVE          0
#define RTE_OTG_HS_VBUS_PORT            GPIO_PORT(2)
#define RTE_OTG_HS_VBUS_BIT             2

//     <e> Overcurrent Detection Pin
//     <i> Configure Pin for overcurrent detection
//     <i> GPIO Pxy (x = A..H, y = 0..15) or (x = I, y = 0..11)
//       <o1> Active State <0=>Low <1=>High
//       <i>  Selects Active State Logical Level
//       <o2> Port <0=>GPIOA <1=>GPIOB <2=>GPIOC <3=>GPIOD
//                 <4=>GPIOE <5=>GPIOF <6=>GPIOG <7=>GPIOH <8=>GPIOI
//       <i>  Selects Port Name
//       <o3> Bit <0-15>
//       <i>  Selects Port Bit
//     </e>
#define RTE_OTG_HS_OC_PIN               1
#define RTE_OTG_HS_OC_ACTIVE            0
#define RTE_OTG_HS_OC_PORT              GPIO_PORT(5)
#define RTE_OTG_HS_OC_BIT               12
//   </e>

// </e>


// <e> EXTI (External Interrupt/Event Controller)
#define RTE_EXTI                        0

//   <e> EXTI0 Line
#define RTE_EXTI0                       0
//     <o> Pin   <0=>PA0  <1=>PB0  <2=>PC0  <3=>PD0  <4=>PE0  <5=>PF0  <6=>PG0  <7=>PH0  <8=>PI0
#define RTE_EXTI0_PIN                   0
//     <o> Mode  <0=>Interrupt  <1=>Event
#define RTE_EXTI0_MODE                  0
//     <o> Trigger  <0=>None  <1=>Raising edge <2=>Falling edge <3=>Any edge
#define RTE_EXTI0_TRIGGER               0
//   </e>

//   <e> EXTI1 Line
#define RTE_EXTI1                       0
//     <o> Pin   <0=>PA1  <1=>PB1  <2=>PC1  <3=>PD1  <4=>PE1  <5=>PF1  <6=>PG1  <7=>PH1  <8=>PI1
#define RTE_EXTI1_PIN                   0
//     <o> Mode  <0=>Interrupt  <1=>Event
#define RTE_EXTI1_MODE                  0
//     <o> Trigger  <0=>None  <1=>Raising edge <2=>Falling edge <3=>Any edge
#define RTE_EXTI1_TRIGGER               0
//   </e>

//   <e> EXTI2 Line
#define RTE_EXTI2                       0
//     <o> Pin   <0=>PA2  <1=>PB2  <2=>PC2  <3=>PD2  <4=>PE2  <5=>PF2  <6=>PG2  <7=>PH2  <8=>PI2
#define RTE_EXTI2_PIN                   0
//     <o> Mode  <0=>Interrupt  <1=>Event
#define RTE_EXTI2_MODE                  0
//     <o> Trigger  <0=>None  <1=>Raising edge <2=>Falling edge <3=>Any edge
#define RTE_EXTI2_TRIGGER               0
//   </e>

//   <e> EXTI3 Line
#define RTE_EXTI3                       0
//     <o> Pin   <0=>PA3  <1=>PB3  <2=>PC3  <3=>PD3  <4=>PE3  <5=>PF3  <6=>PG3  <7=>PH3  <8=>PI3
#define RTE_EXTI3_PIN                   0
//     <o> Mode  <0=>Interrupt  <1=>Event
#define RTE_EXTI3_MODE                  0
//     <o> Trigger  <0=>None  <1=>Raising edge <2=>Falling edge <3=>Any edge
#define RTE_EXTI3_TRIGGER               0
//   </e>

//   <e> EXTI4 Line
#define RTE_EXTI4                       0
//     <o> Pin   <0=>PA4  <1=>PB4  <2=>PC4  <3=>PD4  <4=>PE4  <5=>PF4  <6=>PG4  <7=>PH4  <8=>PI4
#define RTE_EXTI4_PIN                   0
//     <o> Mode  <0=>Interrupt  <1=>Event
#define RTE_EXTI4_MODE                  0
//     <o> Trigger  <0=>None  <1=>Raising edge <2=>Falling edge <3=>Any edge
#define RTE_EXTI4_TRIGGER               0
//   </e>

//   <e> EXTI5 Line
#define RTE_EXTI5                       0
//     <o> Pin   <0=>PA5  <1=>PB5  <2=>PC5  <3=>PD5  <4=>PE5  <5=>PF5  <6=>PG5  <7=>PH5  <8=>PI5
#define RTE_EXTI5_PIN                   0
//     <o> Mode  <0=>Interrupt  <1=>Event
#define RTE_EXTI5_MODE                  0
//     <o> Trigger  <0=>None  <1=>Raising edge <2=>Falling edge <3=>Any edge
#define RTE_EXTI5_TRIGGER               0
//   </e>

//   <e> EXTI6 Line
#define RTE_EXTI6                       0
//     <o> Pin   <0=>PA6  <1=>PB6  <2=>PC6  <3=>PD6  <4=>PE6  <5=>PF6  <6=>PG6  <7=>PH6  <8=>PI6
#define RTE_EXTI6_PIN                   0
//     <o> Mode  <0=>Interrupt  <1=>Event
#define RTE_EXTI6_MODE                  0
//     <o> Trigger  <0=>None  <1=>Raising edge <2=>Falling edge <3=>Any edge
#define RTE_EXTI6_TRIGGER               0
//   </e>

//   <e> EXTI7 Line
#define RTE_EXTI7                       0
//     <o> Pin   <0=>PA7  <1=>PB7  <2=>PC7  <3=>PD7  <4=>PE7  <5=>PF7  <6=>PG7  <7=>PH7  <8=>PI7
#define RTE_EXTI7_PIN                   0
//     <o> Mode  <0=>Interrupt  <1=>Event
#define RTE_EXTI7_MODE                  0
//     <o> Trigger  <0=>None  <1=>Raising edge <2=>Falling edge <3=>Any edge
#define RTE_EXTI7_TRIGGER               0
//   </e>

//   <e> EXTI8 Line
#define RTE_EXTI8                       0
//     <o> Pin   <0=>PA8  <1=>PB8  <2=>PC8  <3=>PD8  <4=>PE8  <5=>PF8  <6=>PG8  <7=>PH8  <8=>PI8
#define RTE_EXTI8_PIN                   0
//     <o> Mode  <0=>Interrupt  <1=>Event
#define RTE_EXTI8_MODE                  0
//     <o> Trigger  <0=>None  <1=>Raising edge <2=>Falling edge <3=>Any edge
#define RTE_EXTI8_TRIGGER               0
//   </e>

//   <e> EXTI9 Line
#define RTE_EXTI9                       0
//     <o> Pin   <0=>PA9  <1=>PB9  <2=>PC9  <3=>PD9  <4=>PE9  <5=>PF9  <6=>PG9  <7=>PH9  <8=>PI9
#define RTE_EXTI9_PIN                   0
//     <o> Mode  <0=>Interrupt  <1=>Event
#define RTE_EXTI9_MODE                  0
//     <o> Trigger  <0=>None  <1=>Raising edge <2=>Falling edge <3=>Any edge
#define RTE_EXTI9_TRIGGER               0
//   </e>

//   <e> EXTI10 Line
#define RTE_EXTI10                      0
//     <o> Pin   <0=>PA10 <1=>PB10 <2=>PC10 <3=>PD10 <4=>PE10 <5=>PF10 <6=>PG10 <7=>PH10 <8=>PI10
#define RTE_EXTI10_PIN                  0
//     <o> Mode  <0=>Interrupt  <1=>Event
#define RTE_EXTI10_MODE                 0
//     <o> Trigger  <0=>None  <1=>Raising edge <2=>Falling edge <3=>Any edge
#define RTE_EXTI10_TRIGGER              0
//   </e>

//   <e> EXTI11 Line
#define RTE_EXTI11                      0
//     <o> Pin   <0=>PA11 <1=>PB11 <2=>PC11 <3=>PD11 <4=>PE11 <5=>PF11 <6=>PG11 <7=>PH11 <8=>PI11
#define RTE_EXTI11_PIN                  0
//     <o> Mode  <0=>Interrupt  <1=>Event
#define RTE_EXTI11_MODE                 0
//     <o> Trigger  <0=>None  <1=>Raising edge <2=>Falling edge <3=>Any edge
#define RTE_EXTI11_TRIGGER              0
//   </e>

//   <e> EXTI12 Line
#define RTE_EXTI12                      0
//     <o> Pin   <0=>PA12 <1=>PB12 <2=>PC12 <3=>PD12 <4=>PE12 <5=>PF12 <6=>PG12 <7=>PH12
#define RTE_EXTI12_PIN                  0
//     <o> Mode  <0=>Interrupt  <1=>Event
#define RTE_EXTI12_MODE                 0
//     <o> Trigger  <0=>None  <1=>Raising edge <2=>Falling edge <3=>Any edge
#define RTE_EXTI12_TRIGGER              0
//   </e>

//   <e> EXTI13 Line
#define RTE_EXTI13                      0
//     <o> Pin   <0=>PA13 <1=>PB13 <2=>PC13 <3=>PD13 <4=>PE13 <5=>PF13 <6=>PG13 <7=>PH13
#define RTE_EXTI13_PIN                  0
//     <o> Mode  <0=>Interrupt  <1=>Event
#define RTE_EXTI13_MODE                 0
//     <o> Trigger  <0=>None  <1=>Raising edge <2=>Falling edge <3=>Any edge
#define RTE_EXTI13_TRIGGER              0
//   </e>

//   <e> EXTI14 Line
#define RTE_EXTI14                      0
//     <o> Pin   <0=>PA14 <1=>PB14 <2=>PC14 <3=>PD14 <4=>PE14 <5=>PF14 <6=>PG14 <7=>PH14
#define RTE_EXTI14_PIN                  0
//     <o> Mode  <0=>Interrupt  <1=>Event
#define RTE_EXTI14_MODE                 0
//     <o> Trigger  <0=>None  <1=>Raising edge <2=>Falling edge <3=>Any edge
#define RTE_EXTI14_TRIGGER              0
//   </e>

//   <e> EXTI15 Line
#define RTE_EXTI15                      0
//     <o> Pin   <0=>PA15 <1=>PB15 <2=>PC15 <3=>PD15 <4=>PE15 <5=>PF15 <6=>PG15 <7=>PH15
#define RTE_EXTI15_PIN                  0
//     <o> Mode  <0=>Interrupt  <1=>Event
#define RTE_EXTI15_MODE                 0
//     <o> Trigger  <0=>None  <1=>Raising edge <2=>Falling edge <3=>Any edge
#define RTE_EXTI15_TRIGGER              0
//   </e>

//   <e> EXTI16 Line: PVD Output
#define RTE_EXTI16                      0
//     <o> Mode  <0=>Interrupt  <1=>Event
#define RTE_EXTI16_MODE                 0
//     <o> Trigger  <0=>None  <1=>Raising edge <2=>Falling edge <3=>Any edge
#define RTE_EXTI16_TRIGGER              0
//   </e>

//   <e> EXTI17 Line: RTC Alarm
#define RTE_EXTI17                      0
//     <o> Mode  <0=>Interrupt  <1=>Event
#define RTE_EXTI17_MODE                 0
//     <o> Trigger  <0=>None  <1=>Raising edge <2=>Falling edge <3=>Any edge
#define RTE_EXTI17_TRIGGER              0
//   </e>

//   <e> EXTI18 Line: USB OTG FS Wakeup
#define RTE_EXTI18                      0
//     <o> Mode  <0=>Interrupt  <1=>Event
#define RTE_EXTI18_MODE                 0
//     <o> Trigger  <0=>None  <1=>Raising edge <2=>Falling edge <3=>Any edge
#define RTE_EXTI18_TRIGGER              0
//   </e>

//   <e> EXTI19 Line: Ethernet Wakeup
#define RTE_EXTI19                      0
//     <o> Mode  <0=>Interrupt  <1=>Event
#define RTE_EXTI19_MODE                 0
//     <o> Trigger  <0=>None  <1=>Raising edge <2=>Falling edge <3=>Any edge
#define RTE_EXTI19_TRIGGER              0
//   </e>

//   <e> EXTI20 Line: USB OTG HS Wakeup
#define RTE_EXTI20                      0
//     <o> Mode  <0=>Interrupt  <1=>Event
#define RTE_EXTI20_MODE                 0
//     <o> Trigger  <0=>None  <1=>Raising edge <2=>Falling edge <3=>Any edge
#define RTE_EXTI20_TRIGGER              0
//   </e>

//   <e> EXTI21 Line: RTC Tamper and TimeStamp
#define RTE_EXTI21                      0
//     <o> Mode  <0=>Interrupt  <1=>Event
#define RTE_EXTI21_MODE                 0
//     <o> Trigger  <0=>None  <1=>Raising edge <2=>Falling edge <3=>Any edge
#define RTE_EXTI21_TRIGGER              0
//   </e>

//   <e> EXTI22 Line: RTC Wakeup
#define RTE_EXTI22                      0
//     <o> Mode  <0=>Interrupt  <1=>Event
#define RTE_EXTI22_MODE                 0
//     <o> Trigger  <0=>None  <1=>Raising edge <2=>Falling edge <3=>Any edge
#define RTE_EXTI22_TRIGGER              0
//   </e>

// </e>


// <e> FSMC (Flexible Static Memory Controller)
#define RTE_FSMC                        0

//   <e> Pin Configuration
//   <i> Configure Pins
#define RTE_FSMC_PINS                   0

//     <o> Address Bus Pins
//       <0=>A[17:16]
//       <1=>A[10:0]   <2=>A[15:0]   <3=>A[16:0]   <4=>A[17:0]
//       <5=>A[18:0]   <6=>A[19:0]   <7=>A[20:0]   <8=>A[21:0]
//       <9=>A[22:0]  <10=>A[23:0]  <11=>A[24:0]  <12=>A[25:0]
#define RTE_FSMC_ABUS_PINS              10
//     <o> Data Bus Pins  <0=>D[7:0] <1=>D[15:0]
#define RTE_FSMC_DBUS_PINS              0
//     <q> FSMC_NOE Pin
#define RTE_FSMC_NOE_PIN                0
//     <q> FSMC_NWE Pin
#define RTE_FSMC_NWE_PIN                0
//     <q> FSMC_NBL0 Pin
#define RTE_FSMC_NBL0_PIN               0
//     <q> FSMC_NBL1 Pin
#define RTE_FSMC_NBL1_PIN               0
//     <q> FSMC_NL Pin
#define RTE_FSMC_NL_PIN                 0
//     <q> FSMC_NWAIT Pin
#define RTE_FSMC_NWAIT_PIN              0
//     <q> FSMC_CLK Pin
#define RTE_FSMC_CLK_PIN                0
//     <q> FSMC_NE1/NCE2 Pin
#define RTE_FSMC_NE1_PIN                0
//     <q> FSMC_NE2/NCE3 Pin
#define RTE_FSMC_NE2_PIN                0
//     <q> FSMC_NE3/NCE4_1 Pin
#define RTE_FSMC_NE3_PIN                0
//     <q> FSMC_NE4 Pin
#define RTE_FSMC_NE4_PIN                0
//     <q> FSMC_NCE4_2 Pin
#define RTE_FSMC_NCE42_PIN              0
//     <q> FSMC_INT2 Pin
#define RTE_FSMC_INT2_PIN               0
//     <q> FSMC_INT3 Pin
#define RTE_FSMC_INT3_PIN               0
//     <q> FSMC_INTR Pin
#define RTE_FSMC_INTR_PIN               0
//     <q> FSMC_NIORD Pin
#define RTE_FSMC_NIORD_PIN              0
//     <q> FSMC_NIOWR Pin
#define RTE_FSMC_NIOWR_PIN              0
//     <q> FSMC_NREG Pin
#define RTE_FSMC_NREG_PIN               0
//     <q> FSMC_CD Pin
#define RTE_FSMC_CD_PIN                 0

//   </e>

//   <h> NOR Flash / PSRAM Controller

//     <e> FSMC_NE1 Chip Select
//     <i> Configure Device on Chip Select FSMC_NE1
#define RTE_FSMC_NE1                    0

//       <h> Chip-select control
//         <o0> CBURSTRW: Write burst enable <0=>Asynchronous write <1=>Synchronous write
//         <i> For Cellular RAM, this enables synchronous burst protocol during write operations. For Flash
//         <i> memory access in burst mode, this enables/disables the wait state insertion via the NWAIT signal.
//         <q1> ASYNCWAIT: Wait signal during asynchronous transfer
//         <i> Enables the FSMC to use the wait signal even during an asynchronous protocol.
//         <q2> EXTMOD: Extended mode enable
//         <i> Enables the FSMC to program inside the write timing register, so it allows different timings for read and write.
//         <q3> WAITEN: Wait enable
//         <i> For Flash memory access in burst mode, this enables/disables wait-state insertion via the NWAIT signal.
//         <q4> WREN: Write enable
//         <i> Enable/disable write operations in the current bank by the FSMC
//         <o5> WAITCFG: Wait timing configuration <0=> NWAIT active before wait state <1=>NWAIT active during wait state
//         <i> For memory access in burst mode, the NWAIT signal indicates whether the data from the memory
//         <i> are valid or if a wait state must be inserted. This configuration bit determines if NWAIT is asserted
//         <i> by the memory one clock cycle before the wait state or during the wait state
//         <o7> WAITPOL: Wait signal polarity <0=>NWAIT active low <1=>NWAIT active high
//         <i> Defines the polarity of the wait signal from memory. Valid only when accessing the memory in burst mode.
//         <q8> BURSTEN: Burst enable
//         <i> Enables the burst access mode for the memory. Valid only with synchronous burst memories.
//         <q9> FACCEN: Flash access enable
//         <i> Enables NOR Flash memory access operations.
//         <o10> MWID: Memory databus width <0=>8 bits <1=>16 bits
//         <i> Defines the external memory device width, valid for all type of memories.
//         <o11> MTYP: Memory type <0=>SRAM, ROM <1=>PSRAM (Cellular RAM: CRAM) <2=>NOR Flash/OneNAND Flash
//         <i> Defines the type of external memory attached to the corresponding memory bank.
//         <q12> MUXEN: Address/data multiplexing enable
//         <i> When enabled, the address and data values are multiplexed on the databus, valid only with NOR and PSRAM memories.
//         <q13> MBKEN: Memory bank enable
//         <i> Enables the memory bank. After reset Bank1 is enabled, all others are disabled. Accessing a
//         <i> disabled bank causes an ERROR on AHB bus.
#define RTE_FSMC_BCR1_CBURSTRW          0
#define RTE_FSMC_BCR1_ASYNCWAIT         0
#define RTE_FSMC_BCR1_EXTMOD            0
#define RTE_FSMC_BCR1_WAITEN            1
#define RTE_FSMC_BCR1_WREN              1
#define RTE_FSMC_BCR1_WAITCFG           0
#define RTE_FSMC_BCR1_WRAPMOD           0
#define RTE_FSMC_BCR1_WAITPOL           0
#define RTE_FSMC_BCR1_BURSTEN           0
#define RTE_FSMC_BCR1_FACCEN            1
#define RTE_FSMC_BCR1_MWID              1
#define RTE_FSMC_BCR1_MTYP              2
#define RTE_FSMC_BCR1_MUXEN             1
#define RTE_FSMC_BCR1_MBKEN             1
//       </h>

//       <h> Chip-select timing
//         <o0> ACCMOD: Access mode <0=>Mode A <1=>Mode B <2=>Mode C <3=>Mode D
//         <i> Specifies the asynchronous access modes. Access mode is taken into account only when
//         <i> Extended mode is enabled in the Chip-select control register.
//         <o1> DATLAT: Data latency <0-15>
//         <i> For NOR Flash with synchronous burst mode enabled, defines the number of memory clock
//         <i> cycles (+2) to issue to the memory before getting the first data:
//         <i> 0000: Data latency of 2 CLK clock cycles for first burst access
//         <i> 1111: Data latency of 17 CLK clock cycles for first burst access (default value after reset)
//         <i> Note: This timing parameter is not expressed in HCLK periods, but in Flash clock (CLK)
//         <i> periods. In asynchronous NOR Flash, SRAM or ROM accesses, this value is don't care.
//         <i> In the case of CRAM, this field must be set to ‘0’.
//         <o2> CLKDIV: Clock divide ratio (for CLK signal) <1-15>
//         <i> Defines the period of CLK clock output signal, expressed in number of HCLK cycles:
//         <i> 0000: Reserved
//         <i> 0001: CLK period = 2 × HCLK periods
//         <i> 0010: CLK period = 3 × HCLK periods
//         <i> 1111: CLK period = 16 × HCLK periods (default value after reset)
//         <i> In asynchronous NOR Flash, SRAM or ROM accesses, this value is don’t care.
//         <o3> BUSTURN: Bus turnaround phase duration <0-15>
//         <i> Define the bus turnaround delay after a read access only
//         <i> from multiplexed NOR Flash memory to avoid bus contention if the controller needs to drive
//         <i> addresses on the databus for the next side-by-side transaction. BUSTURN can be set to the
//         <i> minimum if the slowest memory does not take more than 6 HCLK clock cycles to put the
//         <i> databus in Hi-Z state.
//         <i> These bits are written by software to add a delay at the end of a write/read transaction. This
//         <i> delay allows to match the minimum time between consecutive transactions (tEHEL from NEx
//         <i> high to NEx low) and the maximum time needed by the memory to free the data bus after a
//         <i> read access (tEHQZ):
//         <i> (BUSTRUN + 1)HCLK period = tEHELmin and (BUSTRUN + 2)HCLK period = tEHQZmax if
//         <i> EXTMOD = ‘0’
//         <i> (BUSTRUN + 2)HCLK period = max (tEHELmin, tEHQZmax) if EXTMOD = ‘1’.
//         <i> 0000: BUSTURN phase duration = 0 HCLK clock cycle added
//         <i> ...
//         <i> 1111: BUSTURN phase duration = 15 × HCLK clock cycles (default value after reset)
//         <o4> DATAST: Data phase duration <1-255>
//         <i> Define the duration of the data phase used in SRAMs, ROMs and asynchronous NOR Flash accesses.
//         <i> 0000 0000: Reserved
//         <i> 0000 0001: DATAST phase duration = 1 × HCLK clock cycles
//         <i> 0000 0010: DATAST phase duration = 2 × HCLK clock cycles
//         <i> ...
//         <i> 1111 1111: DATAST phase duration = 255 × HCLK clock cycles (default value after reset)
//         <i> Note: In synchronous accesses, this value is don't care.
//         <o5> ADDHLD: Address hold phase duration <1-15>
//         <i> Define the duration of the address hold phase used in mode D and multiplexed accesses.
//         <i> 0000: Reserved
//         <i> 0001: ADDHLD phase duration =1 × HCLK clock cycle
//         <i> 0010: ADDHLD phase duration = 2 × HCLK clock cycle
//         <i> ...
//         <i> 1111: ADDHLD phase duration = 15 × HCLK clock cycles (default value after reset)
//         <i> Note: In synchronous accesses, this value is not used, the address hold phase is always 1
//         <i> memory clock period duration.
//         <o6> ADDSET: Address setup phase duration <0-15>
//         <i> Define the duration of the address setup phase used in SRAMs, ROMs and asynchronous NOR Flash accesses.
//         <i> 0000: ADDSET phase duration = 0 × HCLK clock cycle
//         <i> ...
//         <i> 1111: ADDSET phase duration = 1615 × HCLK clock cycles (default value after reset)
//         <i> Note: In synchronous accesses, this value is don’t care.
#define RTE_FSMC_BTR1_ACCMOD            0
#define RTE_FSMC_BTR1_DATLAT            15
#define RTE_FSMC_BTR1_CLKDIV            15
#define RTE_FSMC_BTR1_BUSTURN           15
#define RTE_FSMC_BTR1_DATAST            255
#define RTE_FSMC_BTR1_ADDHLD            15
#define RTE_FSMC_BTR1_ADDSET            15
//       </h>

//       <h> Write timing
//         <o0> ACCMOD: Access mode <0=>Mode A <1=>Mode B <2=>Mode C <3=>Mode D
//         <i> Specifies the asynchronous access modes. Access mode is taken into account only when
//         <i> Extended mode is enabled in the Chip-select control register.
//         <o1> DATLAT: Data latency <0-15>
//         <i> For NOR Flash with Synchronous burst mode enabled, defines the number of memory clock cycles
//         <i> (+2) to issue to the memory before getting the first data.
//         <i> 0000: (0x0) Data latency of 2 CLK clock cycles for first burst access
//         <i> ...
//         <i> 1111: (0xF) Data latency of 17 CLK clock cycles for first burst access (default value after reset)
//         <i> Note: This timing parameter is not expressed in HCLK periods, but in Flash clock (CLK) periods. In
//         <i> asynchronous NOR Flash, SRAM or ROM accesses, this value is don’t care. In case of
//         <i> CRAM, this field must be set to 0
//         <o2> CLKDIV: Clock divide ratio (for CLK signal) <1-15>
//         <i> Defines the period of CLK clock output signal, expressed in number of HCLK cycles.
//         <i> 0000: Reserved
//         <i> 0001 CLK period = 2 × HCLK periods
//         <i> 0010 CLK period = 3 × HCLK periods
//         <i> 1111: CLK period = 16 × HCLK periods (default value after reset)
//         <i> In asynchronous NOR Flash, SRAM or ROM accesses, this value is don’t care.
//         <o3> BUSTURN: Bus turnaround phase duration <0-15>
//         <i> Defines a delay at the end of a write transaction to match the minimum time between consecutive transactions (tEHEL from ENx high to ENx low).
//         <i> (BUSTRUN + 1) HCLK period = tEHELmin.
//         <i> 0000: BUSTURN phase duration = 0 HCLK clock cycle added
//         <i> ...
//         <i> 1111: BUSTURN phase duration = 15 HCLK clock cycles added (default value after reset)
//         <o4> DATAST: Data phase duration <1-255>
//         <i> Defines the duration of the data phase used in SRAMs, ROMs and asynchronous NOR Flash accesses.
//         <i> 0000 0000: Reserved
//         <i> 0000 0001: DATAST phase duration = 1 × HCLK clock cycles
//         <i> 0000 0010: DATAST phase duration = 2 × HCLK clock cycles
//         <i> ...
//         <i> 1111 1111: DATAST phase duration = 255 × HCLK clock cycles (default value after reset)
//         <i> Note: In synchronous accesses, this value is don't care.
//         <o5> ADDHLD: Address hold phase duration <1-15>
//         <i> Defines the duration of the address hold phase used in SRAMs, ROMs and asynchronous multiplexed NOR Flash accesses.
//         <i> 0000: Reserved
//         <i> 0001: ADDHLD phase duration = 1 × HCLK clock cycle
//         <i> 0010: ADDHLD phase duration = 2 × HCLK clock cycle
//         <i> ...
//         <i> 1111: ADDHLD phase duration = 15 × HCLK clock cycles (default value after reset)
//         <i> Note: In synchronous NOR Flash accesses, this value is not used, the address hold phase is always 1 Flash clock period duration.
//         <o6> ADDSET: Address setup phase duration <1-15>
//         <i> Defines the duration of the address setup phase in HCLK cycles used in SRAMs, ROMs and asynchronous NOR Flash accessed.
//         <i> 0000: ADDSET phase duration = 0 × HCLK clock cycle
//         <i> ...
//         <i> 1111: ADDSET phase duration = 15 × HCLK clock cycles (default value after reset)
//         <i> Note: In synchronous NOR Flash accesses, this value is don’t care.
#define RTE_FSMC_BWTR1_ACCMOD        0
#define RTE_FSMC_BWTR1_DATLAT        15
#define RTE_FSMC_BWTR1_CLKDIV        15
#define RTE_FSMC_BWTR1_BUSTURN       15
#define RTE_FSMC_BWTR1_DATAST        255
#define RTE_FSMC_BWTR1_ADDHLD        15
#define RTE_FSMC_BWTR1_ADDSET        15
//       </h>
//     </e>

//     <e> FSMC_NE2 Chip Select
//     <i> Configure Device on Chip Select FSMC_NE2
#define RTE_FSMC_NE2                    0

//       <h> Chip-select control
//         <o0> CBURSTRW: Write burst enable <0=>Asynchronous write <1=>Synchronous write
//         <i> For Cellular RAM, this enables synchronous burst protocol during write operations. For Flash
//         <i> memory access in burst mode, this enables/disables the wait state insertion via the NWAIT signal.
//         <q1> ASYNCWAIT: Wait signal during asynchronous transfer
//         <i> Enables the FSMC to use the wait signal even during an asynchronous protocol.
//         <q2> EXTMOD: Extended mode enable
//         <i> Enables the FSMC to program inside the write timing register, so it allows different timings for read and write.
//         <q3> WAITEN: Wait enable
//         <i> For Flash memory access in burst mode, this enables/disables wait-state insertion via the NWAIT signal.
//         <q4> WREN: Write enable
//         <i> Enable/disable write operations in the current bank by the FSMC
//         <o5> WAITCFG: Wait timing configuration <0=> NWAIT active before wait state <1=>NWAIT active during wait state
//         <i> For memory access in burst mode, the NWAIT signal indicates whether the data from the memory
//         <i> are valid or if a wait state must be inserted. This configuration bit determines if NWAIT is asserted
//         <i> by the memory one clock cycle before the wait state or during the wait state
//         <o7> WAITPOL: Wait signal polarity <0=>NWAIT active low <1=>NWAIT active high
//         <i> Defines the polarity of the wait signal from memory. Valid only when accessing the memory in burst mode.
//         <q8> BURSTEN: Burst enable
//         <i> Enables the burst access mode for the memory. Valid only with synchronous burst memories.
//         <q9> FACCEN: Flash access enable
//         <i> Enables NOR Flash memory access operations.
//         <o10> MWID: Memory databus width <0=>8 bits <1=>16 bits
//         <i> Defines the external memory device width, valid for all type of memories.
//         <o11> MTYP: Memory type <0=>SRAM, ROM <1=>PSRAM (Cellular RAM: CRAM) <2=>NOR Flash/OneNAND Flash
//         <i> Defines the type of external memory attached to the corresponding memory bank.
//         <q12> MUXEN: Address/data multiplexing enable
//         <i> When enabled, the address and data values are multiplexed on the databus, valid only with NOR and PSRAM memories.
//         <q13> MBKEN: Memory bank enable
//         <i> Enables the memory bank. After reset Bank1 is enabled, all others are disabled. Accessing a
//         <i> disabled bank causes an ERROR on AHB bus.
#define RTE_FSMC_BCR2_CBURSTRW          0
#define RTE_FSMC_BCR2_ASYNCWAIT         0
#define RTE_FSMC_BCR2_EXTMOD            0
#define RTE_FSMC_BCR2_WAITEN            1
#define RTE_FSMC_BCR2_WREN              1
#define RTE_FSMC_BCR2_WAITCFG           0
#define RTE_FSMC_BCR2_WRAPMOD           0
#define RTE_FSMC_BCR2_WAITPOL           0
#define RTE_FSMC_BCR2_BURSTEN           0
#define RTE_FSMC_BCR2_FACCEN            1
#define RTE_FSMC_BCR2_MWID              1
#define RTE_FSMC_BCR2_MTYP              0
#define RTE_FSMC_BCR2_MUXEN             1
#define RTE_FSMC_BCR2_MBKEN             0
//       </h>

//       <h> Chip-select timing
//         <o0> ACCMOD: Access mode <0=>Mode A <1=>Mode B <2=>Mode C <3=>Mode D
//         <i> Specifies the asynchronous access modes. Access mode is taken into account only when
//         <i> Extended mode is enabled in the Chip-select control register.
//         <o1> DATLAT: Data latency <0-15>
//         <i> For NOR Flash with synchronous burst mode enabled, defines the number of memory clock
//         <i> cycles (+2) to issue to the memory before getting the first data:
//         <i> 0000: Data latency of 2 CLK clock cycles for first burst access
//         <i> 1111: Data latency of 17 CLK clock cycles for first burst access (default value after reset)
//         <i> Note: This timing parameter is not expressed in HCLK periods, but in Flash clock (CLK)
//         <i> periods. In asynchronous NOR Flash, SRAM or ROM accesses, this value is don't care.
//         <i> In the case of CRAM, this field must be set to ‘0’.
//         <o2> CLKDIV: Clock divide ratio (for CLK signal) <1-15>
//         <i> Defines the period of CLK clock output signal, expressed in number of HCLK cycles:
//         <i> 0000: Reserved
//         <i> 0001: CLK period = 2 × HCLK periods
//         <i> 0010: CLK period = 3 × HCLK periods
//         <i> 1111: CLK period = 16 × HCLK periods (default value after reset)
//         <i> In asynchronous NOR Flash, SRAM or ROM accesses, this value is don’t care.
//         <o3> BUSTURN: Bus turnaround phase duration <0-15>
//         <i> Define the bus turnaround delay after a read access only
//         <i> from multiplexed NOR Flash memory to avoid bus contention if the controller needs to drive
//         <i> addresses on the databus for the next side-by-side transaction. BUSTURN can be set to the
//         <i> minimum if the slowest memory does not take more than 6 HCLK clock cycles to put the
//         <i> databus in Hi-Z state.
//         <i> These bits are written by software to add a delay at the end of a write/read transaction. This
//         <i> delay allows to match the minimum time between consecutive transactions (tEHEL from NEx
//         <i> high to NEx low) and the maximum time needed by the memory to free the data bus after a
//         <i> read access (tEHQZ):
//         <i> (BUSTRUN + 1)HCLK period = tEHELmin and (BUSTRUN + 2)HCLK period = tEHQZmax if
//         <i> EXTMOD = ‘0’
//         <i> (BUSTRUN + 2)HCLK period = max (tEHELmin, tEHQZmax) if EXTMOD = ‘1’.
//         <i> 0000: BUSTURN phase duration = 0 HCLK clock cycle added
//         <i> ...
//         <i> 1111: BUSTURN phase duration = 15 × HCLK clock cycles (default value after reset)
//         <o4> DATAST: Data phase duration <1-255>
//         <i> Define the duration of the data phase used in SRAMs, ROMs and asynchronous NOR Flash accesses.
//         <i> 0000 0000: Reserved
//         <i> 0000 0001: DATAST phase duration = 1 × HCLK clock cycles
//         <i> 0000 0010: DATAST phase duration = 2 × HCLK clock cycles
//         <i> ...
//         <i> 1111 1111: DATAST phase duration = 255 × HCLK clock cycles (default value after reset)
//         <i> Note: In synchronous accesses, this value is don't care.
//         <o5> ADDHLD: Address hold phase duration <1-15>
//         <i> Define the duration of the address hold phase used in mode D and multiplexed accesses.
//         <i> 0000: Reserved
//         <i> 0001: ADDHLD phase duration =1 × HCLK clock cycle
//         <i> 0010: ADDHLD phase duration = 2 × HCLK clock cycle
//         <i> ...
//         <i> 1111: ADDHLD phase duration = 15 × HCLK clock cycles (default value after reset)
//         <i> Note: In synchronous accesses, this value is not used, the address hold phase is always 1
//         <i> memory clock period duration.
//         <o6> ADDSET: Address setup phase duration <0-15>
//         <i> Define the duration of the address setup phase used in SRAMs, ROMs and asynchronous NOR Flash accesses.
//         <i> 0000: ADDSET phase duration = 0 × HCLK clock cycle
//         <i> ...
//         <i> 1111: ADDSET phase duration = 1615 × HCLK clock cycles (default value after reset)
//         <i> Note: In synchronous accesses, this value is don’t care.
#define RTE_FSMC_BTR2_ACCMOD            0
#define RTE_FSMC_BTR2_DATLAT            15
#define RTE_FSMC_BTR2_CLKDIV            15
#define RTE_FSMC_BTR2_BUSTURN           15
#define RTE_FSMC_BTR2_DATAST            255
#define RTE_FSMC_BTR2_ADDHLD            15
#define RTE_FSMC_BTR2_ADDSET            15
//       </h>

//       <h> Write timing
//         <o0> ACCMOD: Access mode <0=>Mode A <1=>Mode B <2=>Mode C <3=>Mode D
//         <i> Specifies the asynchronous access modes. Access mode is taken into account only when
//         <i> Extended mode is enabled in the Chip-select control register.
//         <o1> DATLAT: Data latency <0-15>
//         <i> For NOR Flash with Synchronous burst mode enabled, defines the number of memory clock cycles
//         <i> (+2) to issue to the memory before getting the first data.
//         <i> 0000: (0x0) Data latency of 2 CLK clock cycles for first burst access
//         <i> ...
//         <i> 1111: (0xF) Data latency of 17 CLK clock cycles for first burst access (default value after reset)
//         <i> Note: This timing parameter is not expressed in HCLK periods, but in Flash clock (CLK) periods. In
//         <i> asynchronous NOR Flash, SRAM or ROM accesses, this value is don’t care. In case of
//         <i> CRAM, this field must be set to 0
//         <o2> CLKDIV: Clock divide ratio (for CLK signal) <1-15>
//         <i> Defines the period of CLK clock output signal, expressed in number of HCLK cycles.
//         <i> 0000: Reserved
//         <i> 0001 CLK period = 2 × HCLK periods
//         <i> 0010 CLK period = 3 × HCLK periods
//         <i> 1111: CLK period = 16 × HCLK periods (default value after reset)
//         <i> In asynchronous NOR Flash, SRAM or ROM accesses, this value is don’t care.
//         <o3> BUSTURN: Bus turnaround phase duration <0-15>
//         <i> Defines a delay at the end of a write transaction to match the minimum time between consecutive transactions (tEHEL from ENx high to ENx low).
//         <i> (BUSTRUN + 1) HCLK period = tEHELmin.
//         <i> 0000: BUSTURN phase duration = 0 HCLK clock cycle added
//         <i> ...
//         <i> 1111: BUSTURN phase duration = 15 HCLK clock cycles added (default value after reset)
//         <o4> DATAST: Data phase duration <1-255>
//         <i> Defines the duration of the data phase used in SRAMs, ROMs and asynchronous NOR Flash accesses.
//         <i> 0000 0000: Reserved
//         <i> 0000 0001: DATAST phase duration = 1 × HCLK clock cycles
//         <i> 0000 0010: DATAST phase duration = 2 × HCLK clock cycles
//         <i> ...
//         <i> 1111 1111: DATAST phase duration = 255 × HCLK clock cycles (default value after reset)
//         <i> Note: In synchronous accesses, this value is don't care.
//         <o5> ADDHLD: Address hold phase duration <1-15>
//         <i> Defines the duration of the address hold phase used in SRAMs, ROMs and asynchronous multiplexed NOR Flash accesses.
//         <i> 0000: Reserved
//         <i> 0001: ADDHLD phase duration = 1 × HCLK clock cycle
//         <i> 0010: ADDHLD phase duration = 2 × HCLK clock cycle
//         <i> ...
//         <i> 1111: ADDHLD phase duration = 15 × HCLK clock cycles (default value after reset)
//         <i> Note: In synchronous NOR Flash accesses, this value is not used, the address hold phase is always 1 Flash clock period duration.
//         <o6> ADDSET: Address setup phase duration <1-15>
//         <i> Defines the duration of the address setup phase in HCLK cycles used in SRAMs, ROMs and asynchronous NOR Flash accessed.
//         <i> 0000: ADDSET phase duration = 0 × HCLK clock cycle
//         <i> ...
//         <i> 1111: ADDSET phase duration = 15 × HCLK clock cycles (default value after reset)
//         <i> Note: In synchronous NOR Flash accesses, this value is don’t care.
#define RTE_FSMC_BWTR2_ACCMOD        0
#define RTE_FSMC_BWTR2_DATLAT        15
#define RTE_FSMC_BWTR2_CLKDIV        15
#define RTE_FSMC_BWTR2_BUSTURN       15
#define RTE_FSMC_BWTR2_DATAST        255
#define RTE_FSMC_BWTR2_ADDHLD        15
#define RTE_FSMC_BWTR2_ADDSET        15
//       </h>
//     </e>

//     <e> FSMC_NE3 Chip Select
//     <i> Configure Device on Chip Select FSMC_NE3
#define RTE_FSMC_NE3                    0

//       <h> Chip-select control
//         <o0> CBURSTRW: Write burst enable <0=>Asynchronous write <1=>Synchronous write
//         <i> For Cellular RAM, this enables synchronous burst protocol during write operations. For Flash
//         <i> memory access in burst mode, this enables/disables the wait state insertion via the NWAIT signal.
//         <q1> ASYNCWAIT: Wait signal during asynchronous transfer
//         <i> Enables the FSMC to use the wait signal even during an asynchronous protocol.
//         <q2> EXTMOD: Extended mode enable
//         <i> Enables the FSMC to program inside the write timing register, so it allows different timings for read and write.
//         <q3> WAITEN: Wait enable
//         <i> For Flash memory access in burst mode, this enables/disables wait-state insertion via the NWAIT signal.
//         <q4> WREN: Write enable
//         <i> Enable/disable write operations in the current bank by the FSMC
//         <o5> WAITCFG: Wait timing configuration <0=> NWAIT active before wait state <1=>NWAIT active during wait state
//         <i> For memory access in burst mode, the NWAIT signal indicates whether the data from the memory
//         <i> are valid or if a wait state must be inserted. This configuration bit determines if NWAIT is asserted
//         <i> by the memory one clock cycle before the wait state or during the wait state
//         <o7> WAITPOL: Wait signal polarity <0=>NWAIT active low <1=>NWAIT active high
//         <i> Defines the polarity of the wait signal from memory. Valid only when accessing the memory in burst mode.
//         <q8> BURSTEN: Burst enable
//         <i> Enables the burst access mode for the memory. Valid only with synchronous burst memories.
//         <q9> FACCEN: Flash access enable
//         <i> Enables NOR Flash memory access operations.
//         <o10> MWID: Memory databus width <0=>8 bits <1=>16 bits
//         <i> Defines the external memory device width, valid for all type of memories.
//         <o11> MTYP: Memory type <0=>SRAM, ROM <1=>PSRAM (Cellular RAM: CRAM) <2=>NOR Flash/OneNAND Flash
//         <i> Defines the type of external memory attached to the corresponding memory bank.
//         <q12> MUXEN: Address/data multiplexing enable
//         <i> When enabled, the address and data values are multiplexed on the databus, valid only with NOR and PSRAM memories.
//         <q13> MBKEN: Memory bank enable
//         <i> Enables the memory bank. After reset Bank1 is enabled, all others are disabled. Accessing a
//         <i> disabled bank causes an ERROR on AHB bus.
#define RTE_FSMC_BCR3_CBURSTRW          0
#define RTE_FSMC_BCR3_ASYNCWAIT         0
#define RTE_FSMC_BCR3_EXTMOD            0
#define RTE_FSMC_BCR3_WAITEN            1
#define RTE_FSMC_BCR3_WREN              1
#define RTE_FSMC_BCR3_WAITCFG           0
#define RTE_FSMC_BCR3_WRAPMOD           0
#define RTE_FSMC_BCR3_WAITPOL           0
#define RTE_FSMC_BCR3_BURSTEN           0
#define RTE_FSMC_BCR3_FACCEN            1
#define RTE_FSMC_BCR3_MWID              1
#define RTE_FSMC_BCR3_MTYP              0
#define RTE_FSMC_BCR3_MUXEN             1
#define RTE_FSMC_BCR3_MBKEN             0
//       </h>

//       <h> Chip-select timing
//         <o0> ACCMOD: Access mode <0=>Mode A <1=>Mode B <2=>Mode C <3=>Mode D
//         <i> Specifies the asynchronous access modes. Access mode is taken into account only when
//         <i> Extended mode is enabled in the Chip-select control register.
//         <o1> DATLAT: Data latency <0-15>
//         <i> For NOR Flash with synchronous burst mode enabled, defines the number of memory clock
//         <i> cycles (+2) to issue to the memory before getting the first data:
//         <i> 0000: Data latency of 2 CLK clock cycles for first burst access
//         <i> 1111: Data latency of 17 CLK clock cycles for first burst access (default value after reset)
//         <i> Note: This timing parameter is not expressed in HCLK periods, but in Flash clock (CLK)
//         <i> periods. In asynchronous NOR Flash, SRAM or ROM accesses, this value is don't care.
//         <i> In the case of CRAM, this field must be set to ‘0’.
//         <o2> CLKDIV: Clock divide ratio (for CLK signal) <1-15>
//         <i> Defines the period of CLK clock output signal, expressed in number of HCLK cycles:
//         <i> 0000: Reserved
//         <i> 0001: CLK period = 2 × HCLK periods
//         <i> 0010: CLK period = 3 × HCLK periods
//         <i> 1111: CLK period = 16 × HCLK periods (default value after reset)
//         <i> In asynchronous NOR Flash, SRAM or ROM accesses, this value is don’t care.
//         <o3> BUSTURN: Bus turnaround phase duration <0-15>
//         <i> Define the bus turnaround delay after a read access only
//         <i> from multiplexed NOR Flash memory to avoid bus contention if the controller needs to drive
//         <i> addresses on the databus for the next side-by-side transaction. BUSTURN can be set to the
//         <i> minimum if the slowest memory does not take more than 6 HCLK clock cycles to put the
//         <i> databus in Hi-Z state.
//         <i> These bits are written by software to add a delay at the end of a write/read transaction. This
//         <i> delay allows to match the minimum time between consecutive transactions (tEHEL from NEx
//         <i> high to NEx low) and the maximum time needed by the memory to free the data bus after a
//         <i> read access (tEHQZ):
//         <i> (BUSTRUN + 1)HCLK period = tEHELmin and (BUSTRUN + 2)HCLK period = tEHQZmax if
//         <i> EXTMOD = ‘0’
//         <i> (BUSTRUN + 2)HCLK period = max (tEHELmin, tEHQZmax) if EXTMOD = ‘1’.
//         <i> 0000: BUSTURN phase duration = 0 HCLK clock cycle added
//         <i> ...
//         <i> 1111: BUSTURN phase duration = 15 × HCLK clock cycles (default value after reset)
//         <o4> DATAST: Data phase duration <1-255>
//         <i> Define the duration of the data phase used in SRAMs, ROMs and asynchronous NOR Flash accesses.
//         <i> 0000 0000: Reserved
//         <i> 0000 0001: DATAST phase duration = 1 × HCLK clock cycles
//         <i> 0000 0010: DATAST phase duration = 2 × HCLK clock cycles
//         <i> ...
//         <i> 1111 1111: DATAST phase duration = 255 × HCLK clock cycles (default value after reset)
//         <i> Note: In synchronous accesses, this value is don't care.
//         <o5> ADDHLD: Address hold phase duration <1-15>
//         <i> Define the duration of the address hold phase used in mode D and multiplexed accesses.
//         <i> 0000: Reserved
//         <i> 0001: ADDHLD phase duration =1 × HCLK clock cycle
//         <i> 0010: ADDHLD phase duration = 2 × HCLK clock cycle
//         <i> ...
//         <i> 1111: ADDHLD phase duration = 15 × HCLK clock cycles (default value after reset)
//         <i> Note: In synchronous accesses, this value is not used, the address hold phase is always 1
//         <i> memory clock period duration.
//         <o6> ADDSET: Address setup phase duration <0-15>
//         <i> Define the duration of the address setup phase used in SRAMs, ROMs and asynchronous NOR Flash accesses.
//         <i> 0000: ADDSET phase duration = 0 × HCLK clock cycle
//         <i> ...
//         <i> 1111: ADDSET phase duration = 1615 × HCLK clock cycles (default value after reset)
//         <i> Note: In synchronous accesses, this value is don’t care.
#define RTE_FSMC_BTR3_ACCMOD            0
#define RTE_FSMC_BTR3_DATLAT            15
#define RTE_FSMC_BTR3_CLKDIV            15
#define RTE_FSMC_BTR3_BUSTURN           15
#define RTE_FSMC_BTR3_DATAST            255
#define RTE_FSMC_BTR3_ADDHLD            15
#define RTE_FSMC_BTR3_ADDSET            15
//       </h>

//       <h> Write timing
//         <o0> ACCMOD: Access mode <0=>Mode A <1=>Mode B <2=>Mode C <3=>Mode D
//         <i> Specifies the asynchronous access modes. Access mode is taken into account only when
//         <i> Extended mode is enabled in the Chip-select control register.
//         <o1> DATLAT: Data latency <0-15>
//         <i> For NOR Flash with Synchronous burst mode enabled, defines the number of memory clock cycles
//         <i> (+2) to issue to the memory before getting the first data.
//         <i> 0000: (0x0) Data latency of 2 CLK clock cycles for first burst access
//         <i> ...
//         <i> 1111: (0xF) Data latency of 17 CLK clock cycles for first burst access (default value after reset)
//         <i> Note: This timing parameter is not expressed in HCLK periods, but in Flash clock (CLK) periods. In
//         <i> asynchronous NOR Flash, SRAM or ROM accesses, this value is don’t care. In case of
//         <i> CRAM, this field must be set to 0
//         <o2> CLKDIV: Clock divide ratio (for CLK signal) <1-15>
//         <i> Defines the period of CLK clock output signal, expressed in number of HCLK cycles.
//         <i> 0000: Reserved
//         <i> 0001 CLK period = 2 × HCLK periods
//         <i> 0010 CLK period = 3 × HCLK periods
//         <i> 1111: CLK period = 16 × HCLK periods (default value after reset)
//         <i> In asynchronous NOR Flash, SRAM or ROM accesses, this value is don’t care.
//         <o3> BUSTURN: Bus turnaround phase duration <0-15>
//         <i> Defines a delay at the end of a write transaction to match the minimum time between consecutive transactions (tEHEL from ENx high to ENx low).
//         <i> (BUSTRUN + 1) HCLK period = tEHELmin.
//         <i> 0000: BUSTURN phase duration = 0 HCLK clock cycle added
//         <i> ...
//         <i> 1111: BUSTURN phase duration = 15 HCLK clock cycles added (default value after reset)
//         <o4> DATAST: Data phase duration <1-255>
//         <i> Defines the duration of the data phase used in SRAMs, ROMs and asynchronous NOR Flash accesses.
//         <i> 0000 0000: Reserved
//         <i> 0000 0001: DATAST phase duration = 1 × HCLK clock cycles
//         <i> 0000 0010: DATAST phase duration = 2 × HCLK clock cycles
//         <i> ...
//         <i> 1111 1111: DATAST phase duration = 255 × HCLK clock cycles (default value after reset)
//         <i> Note: In synchronous accesses, this value is don't care.
//         <o5> ADDHLD: Address hold phase duration <1-15>
//         <i> Defines the duration of the address hold phase used in SRAMs, ROMs and asynchronous multiplexed NOR Flash accesses.
//         <i> 0000: Reserved
//         <i> 0001: ADDHLD phase duration = 1 × HCLK clock cycle
//         <i> 0010: ADDHLD phase duration = 2 × HCLK clock cycle
//         <i> ...
//         <i> 1111: ADDHLD phase duration = 15 × HCLK clock cycles (default value after reset)
//         <i> Note: In synchronous NOR Flash accesses, this value is not used, the address hold phase is always 1 Flash clock period duration.
//         <o6> ADDSET: Address setup phase duration <1-15>
//         <i> Defines the duration of the address setup phase in HCLK cycles used in SRAMs, ROMs and asynchronous NOR Flash accessed.
//         <i> 0000: ADDSET phase duration = 0 × HCLK clock cycle
//         <i> ...
//         <i> 1111: ADDSET phase duration = 15 × HCLK clock cycles (default value after reset)
//         <i> Note: In synchronous NOR Flash accesses, this value is don’t care.
#define RTE_FSMC_BWTR3_ACCMOD        0
#define RTE_FSMC_BWTR3_DATLAT        15
#define RTE_FSMC_BWTR3_CLKDIV        15
#define RTE_FSMC_BWTR3_BUSTURN       15
#define RTE_FSMC_BWTR3_DATAST        255
#define RTE_FSMC_BWTR3_ADDHLD        15
#define RTE_FSMC_BWTR3_ADDSET        15
//       </h>
//     </e>

//     <e> FSMC_NE4 Chip Select
//     <i> Configure Device on Chip Select FSMC_NE4
#define RTE_FSMC_NE4                    0

//       <h> Chip-select control
//         <o0> CBURSTRW: Write burst enable <0=>Asynchronous write <1=>Synchronous write
//         <i> For Cellular RAM, this enables synchronous burst protocol during write operations. For Flash
//         <i> memory access in burst mode, this enables/disables the wait state insertion via the NWAIT signal.
//         <q1> ASYNCWAIT: Wait signal during asynchronous transfer
//         <i> Enables the FSMC to use the wait signal even during an asynchronous protocol.
//         <q2> EXTMOD: Extended mode enable
//         <i> Enables the FSMC to program inside the write timing register, so it allows different timings for read and write.
//         <q3> WAITEN: Wait enable
//         <i> For Flash memory access in burst mode, this enables/disables wait-state insertion via the NWAIT signal.
//         <q4> WREN: Write enable
//         <i> Enable/disable write operations in the current bank by the FSMC
//         <o5> WAITCFG: Wait timing configuration <0=> NWAIT active before wait state <1=>NWAIT active during wait state
//         <i> For memory access in burst mode, the NWAIT signal indicates whether the data from the memory
//         <i> are valid or if a wait state must be inserted. This configuration bit determines if NWAIT is asserted
//         <i> by the memory one clock cycle before the wait state or during the wait state
//         <o7> WAITPOL: Wait signal polarity <0=>NWAIT active low <1=>NWAIT active high
//         <i> Defines the polarity of the wait signal from memory. Valid only when accessing the memory in burst mode.
//         <q8> BURSTEN: Burst enable
//         <i> Enables the burst access mode for the memory. Valid only with synchronous burst memories.
//         <q9> FACCEN: Flash access enable
//         <i> Enables NOR Flash memory access operations.
//         <o10> MWID: Memory databus width <0=>8 bits <1=>16 bits
//         <i> Defines the external memory device width, valid for all type of memories.
//         <o11> MTYP: Memory type <0=>SRAM, ROM <1=>PSRAM (Cellular RAM: CRAM) <2=>NOR Flash/OneNAND Flash
//         <i> Defines the type of external memory attached to the corresponding memory bank.
//         <q12> MUXEN: Address/data multiplexing enable
//         <i> When enabled, the address and data values are multiplexed on the databus, valid only with NOR and PSRAM memories.
//         <q13> MBKEN: Memory bank enable
//         <i> Enables the memory bank. After reset Bank1 is enabled, all others are disabled. Accessing a
//         <i> disabled bank causes an ERROR on AHB bus.
#define RTE_FSMC_BCR4_CBURSTRW          0
#define RTE_FSMC_BCR4_ASYNCWAIT         0
#define RTE_FSMC_BCR4_EXTMOD            0
#define RTE_FSMC_BCR4_WAITEN            1
#define RTE_FSMC_BCR4_WREN              1
#define RTE_FSMC_BCR4_WAITCFG           0
#define RTE_FSMC_BCR4_WRAPMOD           0
#define RTE_FSMC_BCR4_WAITPOL           0
#define RTE_FSMC_BCR4_BURSTEN           0
#define RTE_FSMC_BCR4_FACCEN            1
#define RTE_FSMC_BCR4_MWID              1
#define RTE_FSMC_BCR4_MTYP              0
#define RTE_FSMC_BCR4_MUXEN             1
#define RTE_FSMC_BCR4_MBKEN             0
//       </h>

//       <h> Chip-select timing
//         <o0> ACCMOD: Access mode <0=>Mode A <1=>Mode B <2=>Mode C <3=>Mode D
//         <i> Specifies the asynchronous access modes. Access mode is taken into account only when
//         <i> Extended mode is enabled in the Chip-select control register.
//         <o1> DATLAT: Data latency <0-15>
//         <i> For NOR Flash with synchronous burst mode enabled, defines the number of memory clock
//         <i> cycles (+2) to issue to the memory before getting the first data:
//         <i> 0000: Data latency of 2 CLK clock cycles for first burst access
//         <i> 1111: Data latency of 17 CLK clock cycles for first burst access (default value after reset)
//         <i> Note: This timing parameter is not expressed in HCLK periods, but in Flash clock (CLK)
//         <i> periods. In asynchronous NOR Flash, SRAM or ROM accesses, this value is don't care.
//         <i> In the case of CRAM, this field must be set to ‘0’.
//         <o2> CLKDIV: Clock divide ratio (for CLK signal) <1-15>
//         <i> Defines the period of CLK clock output signal, expressed in number of HCLK cycles:
//         <i> 0000: Reserved
//         <i> 0001: CLK period = 2 × HCLK periods
//         <i> 0010: CLK period = 3 × HCLK periods
//         <i> 1111: CLK period = 16 × HCLK periods (default value after reset)
//         <i> In asynchronous NOR Flash, SRAM or ROM accesses, this value is don’t care.
//         <o3> BUSTURN: Bus turnaround phase duration <0-15>
//         <i> Define the bus turnaround delay after a read access only
//         <i> from multiplexed NOR Flash memory to avoid bus contention if the controller needs to drive
//         <i> addresses on the databus for the next side-by-side transaction. BUSTURN can be set to the
//         <i> minimum if the slowest memory does not take more than 6 HCLK clock cycles to put the
//         <i> databus in Hi-Z state.
//         <i> These bits are written by software to add a delay at the end of a write/read transaction. This
//         <i> delay allows to match the minimum time between consecutive transactions (tEHEL from NEx
//         <i> high to NEx low) and the maximum time needed by the memory to free the data bus after a
//         <i> read access (tEHQZ):
//         <i> (BUSTRUN + 1)HCLK period = tEHELmin and (BUSTRUN + 2)HCLK period = tEHQZmax if
//         <i> EXTMOD = ‘0’
//         <i> (BUSTRUN + 2)HCLK period = max (tEHELmin, tEHQZmax) if EXTMOD = ‘1’.
//         <i> 0000: BUSTURN phase duration = 0 HCLK clock cycle added
//         <i> ...
//         <i> 1111: BUSTURN phase duration = 15 × HCLK clock cycles (default value after reset)
//         <o4> DATAST: Data phase duration <1-255>
//         <i> Define the duration of the data phase used in SRAMs, ROMs and asynchronous NOR Flash accesses.
//         <i> 0000 0000: Reserved
//         <i> 0000 0001: DATAST phase duration = 1 × HCLK clock cycles
//         <i> 0000 0010: DATAST phase duration = 2 × HCLK clock cycles
//         <i> ...
//         <i> 1111 1111: DATAST phase duration = 255 × HCLK clock cycles (default value after reset)
//         <i> Note: In synchronous accesses, this value is don't care.
//         <o5> ADDHLD: Address hold phase duration <1-15>
//         <i> Define the duration of the address hold phase used in mode D and multiplexed accesses.
//         <i> 0000: Reserved
//         <i> 0001: ADDHLD phase duration =1 × HCLK clock cycle
//         <i> 0010: ADDHLD phase duration = 2 × HCLK clock cycle
//         <i> ...
//         <i> 1111: ADDHLD phase duration = 15 × HCLK clock cycles (default value after reset)
//         <i> Note: In synchronous accesses, this value is not used, the address hold phase is always 1
//         <i> memory clock period duration.
//         <o6> ADDSET: Address setup phase duration <0-15>
//         <i> Define the duration of the address setup phase used in SRAMs, ROMs and asynchronous NOR Flash accesses.
//         <i> 0000: ADDSET phase duration = 0 × HCLK clock cycle
//         <i> ...
//         <i> 1111: ADDSET phase duration = 1615 × HCLK clock cycles (default value after reset)
//         <i> Note: In synchronous accesses, this value is don’t care.
#define RTE_FSMC_BTR4_ACCMOD            0
#define RTE_FSMC_BTR4_DATLAT            15
#define RTE_FSMC_BTR4_CLKDIV            15
#define RTE_FSMC_BTR4_BUSTURN           15
#define RTE_FSMC_BTR4_DATAST            255
#define RTE_FSMC_BTR4_ADDHLD            15
#define RTE_FSMC_BTR4_ADDSET            15
//       </h>

//       <h> Write timing
//         <o0> ACCMOD: Access mode <0=>Mode A <1=>Mode B <2=>Mode C <3=>Mode D
//         <i> Specifies the asynchronous access modes. Access mode is taken into account only when
//         <i> Extended mode is enabled in the Chip-select control register.
//         <o1> DATLAT: Data latency <0-15>
//         <i> For NOR Flash with Synchronous burst mode enabled, defines the number of memory clock cycles
//         <i> (+2) to issue to the memory before getting the first data.
//         <i> 0000: (0x0) Data latency of 2 CLK clock cycles for first burst access
//         <i> ...
//         <i> 1111: (0xF) Data latency of 17 CLK clock cycles for first burst access (default value after reset)
//         <i> Note: This timing parameter is not expressed in HCLK periods, but in Flash clock (CLK) periods. In
//         <i> asynchronous NOR Flash, SRAM or ROM accesses, this value is don’t care. In case of
//         <i> CRAM, this field must be set to 0
//         <o2> CLKDIV: Clock divide ratio (for CLK signal) <1-15>
//         <i> Defines the period of CLK clock output signal, expressed in number of HCLK cycles.
//         <i> 0000: Reserved
//         <i> 0001 CLK period = 2 × HCLK periods
//         <i> 0010 CLK period = 3 × HCLK periods
//         <i> 1111: CLK period = 16 × HCLK periods (default value after reset)
//         <i> In asynchronous NOR Flash, SRAM or ROM accesses, this value is don’t care.
//         <o3> BUSTURN: Bus turnaround phase duration <0-15>
//         <i> Defines a delay at the end of a write transaction to match the minimum time between consecutive transactions (tEHEL from ENx high to ENx low).
//         <i> (BUSTRUN + 1) HCLK period = tEHELmin.
//         <i> 0000: BUSTURN phase duration = 0 HCLK clock cycle added
//         <i> ...
//         <i> 1111: BUSTURN phase duration = 15 HCLK clock cycles added (default value after reset)
//         <o4> DATAST: Data phase duration <1-255>
//         <i> Defines the duration of the data phase used in SRAMs, ROMs and asynchronous NOR Flash accesses.
//         <i> 0000 0000: Reserved
//         <i> 0000 0001: DATAST phase duration = 1 × HCLK clock cycles
//         <i> 0000 0010: DATAST phase duration = 2 × HCLK clock cycles
//         <i> ...
//         <i> 1111 1111: DATAST phase duration = 255 × HCLK clock cycles (default value after reset)
//         <i> Note: In synchronous accesses, this value is don't care.
//         <o5> ADDHLD: Address hold phase duration <1-15>
//         <i> Defines the duration of the address hold phase used in SRAMs, ROMs and asynchronous multiplexed NOR Flash accesses.
//         <i> 0000: Reserved
//         <i> 0001: ADDHLD phase duration = 1 × HCLK clock cycle
//         <i> 0010: ADDHLD phase duration = 2 × HCLK clock cycle
//         <i> ...
//         <i> 1111: ADDHLD phase duration = 15 × HCLK clock cycles (default value after reset)
//         <i> Note: In synchronous NOR Flash accesses, this value is not used, the address hold phase is always 1 Flash clock period duration.
//         <o6> ADDSET: Address setup phase duration <1-15>
//         <i> Defines the duration of the address setup phase in HCLK cycles used in SRAMs, ROMs and asynchronous NOR Flash accessed.
//         <i> 0000: ADDSET phase duration = 0 × HCLK clock cycle
//         <i> ...
//         <i> 1111: ADDSET phase duration = 15 × HCLK clock cycles (default value after reset)
//         <i> Note: In synchronous NOR Flash accesses, this value is don’t care.
#define RTE_FSMC_BWTR4_ACCMOD        0
#define RTE_FSMC_BWTR4_DATLAT        15
#define RTE_FSMC_BWTR4_CLKDIV        15
#define RTE_FSMC_BWTR4_BUSTURN       15
#define RTE_FSMC_BWTR4_DATAST        255
#define RTE_FSMC_BWTR4_ADDHLD        15
#define RTE_FSMC_BWTR4_ADDSET        15
//       </h>
//     </e>

//   </h>

//   <h> NAND Flash Controller

//     <e> FSMC_NCE2 Chip Select
//     <i> Configure NAND Device on Chip Select FSMC_NCE2
#define RTE_FSMC_NCE2                   0

//       <h> NAND Flash Control
//         <o0> ECCPS: ECC page size <0=> 256 bytes <1=> 512 bytes <2=> 1024 bytes <3=> 2048 bytes <4=> 4096 bytes <5=> 8192 bytes
//         <i> Defines the page size for the extended ECC.
//         <o1> TAR: ALE to RE delay <0-15>
//         <i> Sets time from ALE low to RE low in number of AHB clock cycles (HCLK).
//         <i> Time is: t_ar = (TAR + SET + 2) × THCLK where THCLK is the HCLK clock period
//         <i> 0000: 1 HCLK cycle (default)
//         <i> 1111: 16 HCLK cycles
//         <i> Note: SET is MEMSET or ATTSET according to the addressed space.
//         <o2> TCLR: CLE to RE delay <0-15>
//         <i> Sets time from CLE low to RE low in number of AHB clock cycles (HCLK).
//         <i> Time is t_clr = (TCLR + SET + 2) × THCLK where THCLK is the HCLK clock period
//         <i> 0000: 1 HCLK cycle (default)
//         <i> 1111: 16 HCLK cycles
//         <i> Note: SET is MEMSET or ATTSET according to the addressed space.
//         <q3> ECCEN: ECC computation logic enable 
//         <o4>PWID: Databus width <0=>8 bits <1=>16 bits
//         <i> Defines the external memory device width.
//         <o5> PTYP: Memory type <1=>NAND Flash
//         <i> Defines the type of device attached to the corresponding memory bank.
//         <q6> PBKEN: NAND Flash memory bank enable
//         <i> Enables the memory bank. Accessing a disabled memory bank causes an ERROR on AHB bus.
//         <q7> PWAITEN: Wait feature enable
//         <i> Enables the Wait feature for the PC Card/NAND Flash memory bank.
#define RTE_FSMC_PCR2_ECCPS             0
#define RTE_FSMC_PCR2_TAR               0
#define RTE_FSMC_PCR2_TCLR              0
#define RTE_FSMC_PCR2_ECCEN             0
#define RTE_FSMC_PCR2_PWID              0
#define RTE_FSMC_PCR2_PTYP              1
#define RTE_FSMC_PCR2_PBKEN             0
#define RTE_FSMC_PCR2_PWAITEN           0

//       </h>

//       <h> Interrupt configuration
//         <q0>IFEN: Falling edge detection enable
//         <q1>ILEN: High-level detection enable
//         <q2>IREN: Rising edge detection enable
#define RTE_FSMC_SR2_IFEN               0
#define RTE_FSMC_SR2_ILEN               0
#define RTE_FSMC_SR2_IREN               0

//       </h>

//       <h>Common memory space timing
//         <o0> MEMHIZ: Databus HiZ time <0-255>
//         <i>  Defines the number of HCLK clock cycles during which the databus is kept in HiZ after the
//         <i>  start of a NAND Flash write access.
//         <i>  0000 0000: 0 HCLK cycle
//         <i>  1111 1111: 255 HCLK cycles (default value after reset)
//         <o1> MEMHOLD: Hold time <1-255>
//         <i>  Defines the number of HCLK clock cycles to hold address (and data for write access) after
//         <i>  the command deassertion (NWE, NOE), for NAND Flash read or write access.
//         <i>  0000 0000: reserved
//         <i>  0000 0001: 1 HCLK cycle
//         <i>  1111 1111: 255 HCLK cycles (default value after reset)
//         <o2> MEMWAIT: Wait time <1-255>
//         <i>  Defines the minimum number of HCLK (+1) clock cycles to assert the command (NWE,
//         <i>  NOE), for NAND Flash read or write access to. The duration for command assertion
//         <i>  is extended if the wait signal (NWAIT) is active (low) at the end of the programmed value.
//         <i>  0000 0000: reserved
//         <i>  0000 0001: 2 HCLK cycles (+ wait cycle introduced by deasserting NWAIT)
//         <i>  1111 1111: 256 HCLK cycles (+ wait cycle introduced by the Card deasserting NWAIT) (default value after reset)
//         <o3> MEMSET: Setup time <0-255>
//         <i>  Defines the number of HCLK (+1) clock cycles to set up the address before the command
//         <i>  assertion (NWE, NOE), for NAND Flash read or write access.
//         <i>  0000 0000: 2 HCLK cycles (for NAND Flash)
//         <i>  1111 1111: 257 HCLK cycles (for NAND Flash) (default value after reset)
#define RTE_FSMC_PMEM2_MEMHIZ           255
#define RTE_FSMC_PMEM2_MEMHOLD          255
#define RTE_FSMC_PMEM2_MEMWAIT          255
#define RTE_FSMC_PMEM2_MEMSET           255

//       </h>

//       <h>Attribute memory space timing
//         <o0> ATTHIZ: Databus HiZ time <0-255>
//         <i>  Defines the number of HCLK clock cycles during which the databus is kept in HiZ after the
//         <i>  start of a NAND Flash write access.
//         <i>  0000 0000: 0 HCLK cycle
//         <i>  1111 1111: 255 HCLK cycles (default value after reset)
//         <o1> ATTHOLD: Hold time <1-255>
//         <i>  Defines the number of HCLK clock cycles to hold address (and data for write access) after
//         <i>  the command deassertion (NWE, NOE), for NAND Flash read or write access.
//         <i>  0000 0000: reserved
//         <i>  0000 0001: 1 HCLK cycle
//         <i>  1111 1111: 255 HCLK cycles (default value after reset)
//         <o2> ATTWAIT: Wait time <1-255>
//         <i>  Defines the minimum number of HCLK (+1) clock cycles to assert the command (NWE,
//         <i>  NOE), for NAND Flash read or write access. The duration for command assertion
//         <i>  is extended if the wait signal (NWAIT) is active (low) at the end of the programmed value.
//         <i>  0000 0000: reserved
//         <i>  0000 0001: 2 HCLK cycles (+ wait cycle introduced by deassertion of NWAIT)
//         <i>  1111 1111: 256 HCLK cycles (+ wait cycle introduced by the card deasserting NWAIT)
//         <o3> ATTSET: Setup time <0-255>
//         <i>  Defines the number of HCLK (+1) clock cycles to set up address before the command
//         <i>  assertion (NWE, NOE), for NAND Flash read or write access.
//         <i>  0000 0000: 1 HCLK cycle
//         <i>  1111 1111: 256 HCLK cycles (default value after reset)
#define RTE_FSMC_PATT2_ATTHIZ           255
#define RTE_FSMC_PATT2_ATTHOLD          255
#define RTE_FSMC_PATT2_ATTWAIT          255
#define RTE_FSMC_PATT2_ATTSET           255

//       </h>

//     </e>

//     <e> FSMC_NCE3 Chip Select
//     <i> Configure NAND Device on Chip Select FSMC_NCE3
#define RTE_FSMC_NCE3                   0

//       <h> NAND Flash Control
//         <o0> ECCPS: ECC page size <0=> 256 bytes <1=> 512 bytes <2=> 1024 bytes <3=> 2048 bytes <4=> 4096 bytes <5=> 8192 bytes
//         <i> Defines the page size for the extended ECC.
//         <o1> TAR: ALE to RE delay <0-15>
//         <i> Sets time from ALE low to RE low in number of AHB clock cycles (HCLK).
//         <i> Time is: t_ar = (TAR + SET + 2) × THCLK where THCLK is the HCLK clock period
//         <i> 0000: 1 HCLK cycle (default)
//         <i> 1111: 16 HCLK cycles
//         <i> Note: SET is MEMSET or ATTSET according to the addressed space.
//         <o2> TCLR: CLE to RE delay <0-15>
//         <i> Sets time from CLE low to RE low in number of AHB clock cycles (HCLK).
//         <i> Time is t_clr = (TCLR + SET + 2) × THCLK where THCLK is the HCLK clock period
//         <i> 0000: 1 HCLK cycle (default)
//         <i> 1111: 16 HCLK cycles
//         <i> Note: SET is MEMSET or ATTSET according to the addressed space.
//         <q3> ECCEN: ECC computation logic enable 
//         <o4>PWID: Databus width <0=>8 bits <1=>16 bits
//         <i> Defines the external memory device width.
//         <o5> PTYP: Memory type <1=>NAND Flash
//         <i> Defines the type of device attached to the corresponding memory bank.
//         <q6> PBKEN: NAND Flash memory bank enable
//         <i> Enables the memory bank. Accessing a disabled memory bank causes an ERROR on AHB bus.
//         <q7> PWAITEN: Wait feature enable
//         <i> Enables the Wait feature for the PC Card/NAND Flash memory bank.
#define RTE_FSMC_PCR3_ECCPS             0
#define RTE_FSMC_PCR3_TAR               0
#define RTE_FSMC_PCR3_TCLR              0
#define RTE_FSMC_PCR3_ECCEN             0
#define RTE_FSMC_PCR3_PWID              0
#define RTE_FSMC_PCR3_PTYP              1
#define RTE_FSMC_PCR3_PBKEN             0
#define RTE_FSMC_PCR3_PWAITEN           0

//       </h>

//       <h> Interrupt configuration
//         <q0>IFEN: Falling edge detection enable
//         <q1>ILEN: High-level detection enable
//         <q2>IREN: Rising edge detection enable
#define RTE_FSMC_SR3_IFEN               0
#define RTE_FSMC_SR3_ILEN               0
#define RTE_FSMC_SR3_IREN               0

//       </h>

//       <h>Common memory space timing
//         <o0> MEMHIZ: Databus HiZ time <0-255>
//         <i>  Defines the number of HCLK clock cycles during which the databus is kept in HiZ after the
//         <i>  start of a NAND Flash write access.
//         <i>  0000 0000: 0 HCLK cycle
//         <i>  1111 1111: 255 HCLK cycles (default value after reset)
//         <o1> MEMHOLD: Hold time <1-255>
//         <i>  Defines the number of HCLK clock cycles to hold address (and data for write access) after
//         <i>  the command deassertion (NWE, NOE), for NAND Flash read or write access.
//         <i>  0000 0000: reserved
//         <i>  0000 0001: 1 HCLK cycle
//         <i>  1111 1111: 255 HCLK cycles (default value after reset)
//         <o2> MEMWAIT: Wait time <1-255>
//         <i>  Defines the minimum number of HCLK (+1) clock cycles to assert the command (NWE,
//         <i>  NOE), for NAND Flash read or write access to. The duration for command assertion
//         <i>  is extended if the wait signal (NWAIT) is active (low) at the end of the programmed value.
//         <i>  0000 0000: reserved
//         <i>  0000 0001: 2 HCLK cycles (+ wait cycle introduced by deasserting NWAIT)
//         <i>  1111 1111: 256 HCLK cycles (+ wait cycle introduced by the Card deasserting NWAIT) (default value after reset)
//         <o3> MEMSET: Setup time <0-255>
//         <i>  Defines the number of HCLK (+1) clock cycles to set up the address before the command
//         <i>  assertion (NWE, NOE), for NAND Flash read or write access.
//         <i>  0000 0000: 2 HCLK cycles (for NAND Flash)
//         <i>  1111 1111: 257 HCLK cycles (for NAND Flash) (default value after reset)
#define RTE_FSMC_PMEM3_MEMHIZ           255
#define RTE_FSMC_PMEM3_MEMHOLD          255
#define RTE_FSMC_PMEM3_MEMWAIT          255
#define RTE_FSMC_PMEM3_MEMSET           255

//       </h>

//       <h>Attribute memory space timing
//         <o0> ATTHIZ: Databus HiZ time <0-255>
//         <i>  Defines the number of HCLK clock cycles during which the databus is kept in HiZ after the
//         <i>  start of a NAND Flash write access.
//         <i>  0000 0000: 0 HCLK cycle
//         <i>  1111 1111: 255 HCLK cycles (default value after reset)
//         <o1> ATTHOLD: Hold time <1-255>
//         <i>  Defines the number of HCLK clock cycles to hold address (and data for write access) after
//         <i>  the command deassertion (NWE, NOE), for NAND Flash read or write access.
//         <i>  0000 0000: reserved
//         <i>  0000 0001: 1 HCLK cycle
//         <i>  1111 1111: 255 HCLK cycles (default value after reset)
//         <o2> ATTWAIT: Wait time <1-255>
//         <i>  Defines the minimum number of HCLK (+1) clock cycles to assert the command (NWE,
//         <i>  NOE), for NAND Flash read or write access. The duration for command assertion
//         <i>  is extended if the wait signal (NWAIT) is active (low) at the end of the programmed value.
//         <i>  0000 0000: reserved
//         <i>  0000 0001: 2 HCLK cycles (+ wait cycle introduced by deassertion of NWAIT)
//         <i>  1111 1111: 256 HCLK cycles (+ wait cycle introduced by the card deasserting NWAIT)
//         <o3> ATTSET: Setup time <0-255>
//         <i>  Defines the number of HCLK (+1) clock cycles to set up address before the command
//         <i>  assertion (NWE, NOE), for NAND Flash read or write access.
//         <i>  0000 0000: 1 HCLK cycle
//         <i>  1111 1111: 256 HCLK cycles (default value after reset)
#define RTE_FSMC_PATT3_ATTHIZ           255
#define RTE_FSMC_PATT3_ATTHOLD          255
#define RTE_FSMC_PATT3_ATTWAIT          255
#define RTE_FSMC_PATT3_ATTSET           255

//       </h>

//     </e>

//   </h>

//   <h> PC Card Controller

//     <e> FSMC_NCE4_x Chip Select
//     <i> Configure PC Card/CompactFlash Device on Chip Select FSMC_NCE4_1/FSMC_NCE4_2
#define RTE_FSMC_NCE4              0

//       <h> PC Card Control
//         <o0> ECCPS: ECC page size <0=> 256 bytes <1=> 512 bytes <2=> 1024 bytes <3=> 2048 bytes <4=> 4096 bytes <5=> 8192 bytes
//         <i> Defines the page size for the extended ECC.
//         <o1> TAR: ALE to RE delay <0-15>
//         <i> Sets time from ALE low to RE low in number of AHB clock cycles (HCLK).
//         <i> Time is: t_ar = (TAR + SET + 2) × THCLK where THCLK is the HCLK clock period
//         <i> 0000: 1 HCLK cycle (default)
//         <i> 1111: 16 HCLK cycles
//         <i> Note: SET is MEMSET or ATTSET according to the addressed space.
//         <o2> TCLR: CLE to RE delay <0-15>
//         <i> Sets time from CLE low to RE low in number of AHB clock cycles (HCLK).
//         <i> Time is t_clr = (TCLR + SET + 2) × THCLK where THCLK is the HCLK clock period
//         <i> 0000: 1 HCLK cycle (default)
//         <i> 1111: 16 HCLK cycles
//         <i> Note: SET is MEMSET or ATTSET according to the addressed space.
//         <q3> ECCEN: ECC computation logic enable
//         <o4>PWID: Databus width <0=>8 bits <1=>16 bits
//         <i> Defines the external memory device width.
//         <o5> PTYP: Memory type <0=>PC Card, CompactFlash, CF+ or PCMCIOA
//         <i> Defines the type of device attached to the corresponding memory bank.
//         <q6> PBKEN: PC Card memory bank enable
//         <i> Enables the memory bank. Accessing a disabled memory bank causes an ERROR on AHB bus.
//         <q7> PWAITEN: Wait feature enable
//         <i> Enables the Wait feature for the PC Card/NAND Flash memory bank.
#define RTE_FSMC_PCR4_ECCPS             0
#define RTE_FSMC_PCR4_TAR               0
#define RTE_FSMC_PCR4_TCLR              0
#define RTE_FSMC_PCR4_ECCEN             0
#define RTE_FSMC_PCR4_PWID              0
#define RTE_FSMC_PCR4_PTYP              0
#define RTE_FSMC_PCR4_PBKEN             0
#define RTE_FSMC_PCR4_PWAITEN           0

//       </h>

//       <h> Interrupt configuration
//         <q0>IFEN: Falling edge detection enable
//         <q1>ILEN: High-level detection enable
//         <q2>IREN: Rising edge detection enable
#define RTE_FSMC_SR4_IFEN               0
#define RTE_FSMC_SR4_ILEN               0
#define RTE_FSMC_SR4_IREN               0

//       </h>

//       <h> Common memory space timing
//         <o0> MEMHIZ: Databus HiZ time <0-255>
//         <i>  Defines the number of HCLK clock cycles during which the databus is kept in HiZ after the
//         <i>  start of a NAND Flash write access.
//         <i>  0000 0000: 0 HCLK cycle
//         <i>  1111 1111: 255 HCLK cycles (default value after reset)
//         <o1> MEMHOLD: Hold time <1-255>
//         <i>  Defines the number of HCLK clock cycles to hold address (and data for write access) after
//         <i>  the command deassertion (NWE, NOE), for NAND Flash read or write access.
//         <i>  0000 0000: reserved
//         <i>  0000 0001: 1 HCLK cycle
//         <i>  1111 1111: 255 HCLK cycles (default value after reset)
//         <o2> MEMWAIT: Wait time <1-255>
//         <i>  Defines the minimum number of HCLK (+1) clock cycles to assert the command (NWE,
//         <i>  NOE), for NAND Flash read or write access to. The duration for command assertion
//         <i>  is extended if the wait signal (NWAIT) is active (low) at the end of the programmed value.
//         <i>  0000 0000: reserved
//         <i>  0000 0001: 2 HCLK cycles (+ wait cycle introduced by deasserting NWAIT)
//         <i>  1111 1111: 256 HCLK cycles (+ wait cycle introduced by the Card deasserting NWAIT) (default value after reset)
//         <o3> MEMSET: Setup time <0-255>
//         <i>  Defines the number of HCLK (+1) clock cycles to set up the address before the command
//         <i>  assertion (NWE, NOE), for NAND Flash read or write access.
//         <i>  0000 0000: 2 HCLK cycles (for NAND Flash)
//         <i>  1111 1111: 257 HCLK cycles (for NAND Flash) (default value after reset)
#define RTE_FSMC_PMEM4_MEMHIZ           255
#define RTE_FSMC_PMEM4_MEMHOLD          255
#define RTE_FSMC_PMEM4_MEMWAIT          255
#define RTE_FSMC_PMEM4_MEMSET           255

//       </h>

//       <h> Attribute memory space timing
//         <o0> ATTHIZ: Databus HiZ time <0-255>
//         <i>  Defines the number of HCLK clock cycles during which the databus is kept in HiZ after the
//         <i>  start of a NAND Flash write access.
//         <i>  0000 0000: 0 HCLK cycle
//         <i>  1111 1111: 255 HCLK cycles (default value after reset)
//         <o1> ATTHOLD: Hold time <1-255>
//         <i>  Defines the number of HCLK clock cycles to hold address (and data for write access) after
//         <i>  the command deassertion (NWE, NOE), for NAND Flash read or write access.
//         <i>  0000 0000: reserved
//         <i>  0000 0001: 1 HCLK cycle
//         <i>  1111 1111: 255 HCLK cycles (default value after reset)
//         <o2> ATTWAIT: Wait time <1-255>
//         <i>  Defines the minimum number of HCLK (+1) clock cycles to assert the command (NWE,
//         <i>  NOE), for NAND Flash read or write access. The duration for command assertion
//         <i>  is extended if the wait signal (NWAIT) is active (low) at the end of the programmed value.
//         <i>  0000 0000: reserved
//         <i>  0000 0001: 2 HCLK cycles (+ wait cycle introduced by deassertion of NWAIT)
//         <i>  1111 1111: 256 HCLK cycles (+ wait cycle introduced by the card deasserting NWAIT)
//         <o3> ATTSET: Setup time <0-255>
//         <i>  Defines the number of HCLK (+1) clock cycles to set up address before the command
//         <i>  assertion (NWE, NOE), for NAND Flash read or write access.
//         <i>  0000 0000: 1 HCLK cycle
//         <i>  1111 1111: 256 HCLK cycles (default value after reset)
#define RTE_FSMC_PATT4_ATTHIZ           255
#define RTE_FSMC_PATT4_ATTHOLD          255
#define RTE_FSMC_PATT4_ATTWAIT          255
#define RTE_FSMC_PATT4_ATTSET           255

//       </h>

//       <h> I/O space timing
//         <o0> IOHIZ: Databus HiZ time <0-255>
//         <i>  Defines the number of HCLK clock cycles during which the databus is kept in HiZ after the
//         <i>  start of a PC Card write access. Only valid for write transaction.
//         <i>  0000 0000: 0 HCLK cycle
//         <i>  1111 1111: 255 HCLK cycles (default value after reset)
//         <o1> IOHOLD: Hold time <1-255>
//         <i>  Defines the number of HCLK clock cycles to hold address (and data for write access) after
//         <i>  the command deassertion (NWE, NOE), for PC Card read or write access.
//         <i>  0000 0000: reserved
//         <i>  0000 0001: 1 HCLK cycle
//         <i>  1111 1111: 255 HCLK cycles (default value after reset)
//         <o2> IOWAIT: Wait time <1-255>
//         <i>  Defines the minimum number of HCLK (+1) clock cycles to assert the command (SMNWE,
//         <i>  SMNOE), for PC Card read or write access. The duration for command assertion is
//         <i>  extended if the wait signal (NWAIT) is active (low) at the end of the
//         <i>  programmed value of HCLK.
//         <i>  0000 0000: reserved, do not use this value
//         <i>  0000 0001: 2 HCLK cycles (+ wait cycle introduced by deassertion of NWAIT)
//         <i>  1111 1111: 256 HCLK cycles
//         <o3> IOSET: Setup time <0-255>
//         <i>  Defines the number of HCLK (+1) clock cycles to set up the address before the command
//         <i>  assertion (NWE, NOE), for PC Card read or write access.
//         <i>  0000 0000: 1 HCLK cycle
//         <i>  1111 1111: 256 HCLK cycles (default value after reset)
#define RTE_FSMC_PIO4_IOHIZ             255
#define RTE_FSMC_PIO4_IOHOLD            255
#define RTE_FSMC_PIO4_IOWAIT            255
#define RTE_FSMC_PIO4_IOSET             255

//       </h>

//     </e>

//   </h>

// </e>


#endif  /* __RTE_DEVICE_H */
