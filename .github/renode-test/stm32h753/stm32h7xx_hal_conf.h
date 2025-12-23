/* Minimal HAL configuration for STM32H753 wolfCrypt build under Renode.
 * RNG and CRYP HAL are enabled. CRYP is used for AES_GCM only (other AES modes disabled).
 * HASH is disabled as Renode doesn't implement it.
 */

#ifndef STM32H7xx_HAL_CONF_H
#define STM32H7xx_HAL_CONF_H

#ifdef __cplusplus
extern "C" {
#endif

/* -------------------------  Module Selection  ----------------------------- */
#define HAL_MODULE_ENABLED
#define HAL_CORTEX_MODULE_ENABLED
#define HAL_RCC_MODULE_ENABLED
#define HAL_GPIO_MODULE_ENABLED
#define HAL_RNG_MODULE_ENABLED
#define HAL_CRYP_MODULE_ENABLED  /* Enabled for AES_GCM only */
/* #define HAL_HASH_MODULE_ENABLED */  /* Disabled - Renode doesn't implement HASH */
#define HAL_DMA_MODULE_ENABLED
#define HAL_FLASH_MODULE_ENABLED
#define HAL_PWR_MODULE_ENABLED
#define HAL_EXTI_MODULE_ENABLED

/* Disabled modules (explicit for clarity) */
/* #define HAL_SDRAM_MODULE_ENABLED */

/* -------------------------  Oscillator Values  ---------------------------- */
#if !defined(HSE_VALUE)
#define HSE_VALUE    25000000UL  /* External oscillator frequency in Hz */
#endif

#if !defined(HSE_STARTUP_TIMEOUT)
#define HSE_STARTUP_TIMEOUT  100UL  /* Time out for HSE start up in ms */
#endif

#if !defined(CSI_VALUE)
#define CSI_VALUE    4000000UL   /* Internal oscillator CSI in Hz */
#endif

#if !defined(HSI_VALUE)
#define HSI_VALUE    64000000UL  /* Internal oscillator HSI in Hz */
#endif

#if !defined(HSI48_VALUE)
#define HSI48_VALUE  48000000UL  /* Value of the Internal High Speed oscillator for USB in Hz */
#endif

#if !defined(LSE_VALUE)
#define LSE_VALUE    32768UL     /* External low speed oscillator in Hz */
#endif

#if !defined(LSE_STARTUP_TIMEOUT)
#define LSE_STARTUP_TIMEOUT  5000UL  /* Time out for LSE start up in ms */
#endif

#if !defined(LSI_VALUE)
#define LSI_VALUE    32000UL     /* Internal low speed oscillator in Hz */
#endif

#if !defined(EXTERNAL_CLOCK_VALUE)
#define EXTERNAL_CLOCK_VALUE  12288000UL  /* External audio clock in Hz */
#endif

/* -------------------------  System Configuration  -------------------------- */
#define VDD_VALUE                  3300UL  /* Value of VDD in mV */
#define TICK_INT_PRIORITY          0x0FUL  /* Tick interrupt priority */
#define USE_RTOS                   0U
#define PREFETCH_ENABLE            0U
#define USE_HAL_ADC_REGISTER_CALLBACKS         0U
#define USE_HAL_CEC_REGISTER_CALLBACKS         0U
#define USE_HAL_COMP_REGISTER_CALLBACKS        0U
#define USE_HAL_CORDIC_REGISTER_CALLBACKS      0U
#define USE_HAL_CRYP_REGISTER_CALLBACKS        0U
#define USE_HAL_DAC_REGISTER_CALLBACKS         0U
#define USE_HAL_DCMI_REGISTER_CALLBACKS         0U
#define USE_HAL_DFSDM_REGISTER_CALLBACKS       0U
#define USE_HAL_DMA_REGISTER_CALLBACKS         0U
#define USE_HAL_DMA2D_REGISTER_CALLBACKS       0U
#define USE_HAL_DSI_REGISTER_CALLBACKS         0U
#define USE_HAL_DTS_REGISTER_CALLBACKS         0U
#define USE_HAL_ETH_REGISTER_CALLBACKS         0U
#define USE_HAL_FDCAN_REGISTER_CALLBACKS       0U
#define USE_HAL_FMAC_REGISTER_CALLBACKS        0U
#define USE_HAL_GFXMMU_REGISTER_CALLBACKS      0U
#define USE_HAL_HASH_REGISTER_CALLBACKS        0U
#define USE_HAL_HCD_REGISTER_CALLBACKS         0U
#define USE_HAL_HRTIM_REGISTER_CALLBACKS       0U
#define USE_HAL_I2C_REGISTER_CALLBACKS         0U
#define USE_HAL_I2S_REGISTER_CALLBACKS         0U
#define USE_HAL_IRDA_REGISTER_CALLBACKS        0U
#define USE_HAL_JPEG_REGISTER_CALLBACKS        0U
#define USE_HAL_LPTIM_REGISTER_CALLBACKS       0U
#define USE_HAL_LTDC_REGISTER_CALLBACKS        0U
#define USE_HAL_MDIOS_REGISTER_CALLBACKS       0U
#define USE_HAL_MMC_REGISTER_CALLBACKS         0U
#define USE_HAL_NAND_REGISTER_CALLBACKS        0U
#define USE_HAL_NOR_REGISTER_CALLBACKS         0U
#define USE_HAL_OPAMP_REGISTER_CALLBACKS       0U
#define USE_HAL_OSPI_REGISTER_CALLBACKS        0U
#define USE_HAL_OTFDEC_REGISTER_CALLBACKS      0U
#define USE_HAL_PCD_REGISTER_CALLBACKS         0U
#define USE_HAL_PSSI_REGISTER_CALLBACKS        0U
#define USE_HAL_QSPI_REGISTER_CALLBACKS        0U
#define USE_HAL_RNG_REGISTER_CALLBACKS         0U
#define USE_HAL_RTC_REGISTER_CALLBACKS         0U
#define USE_HAL_SAI_REGISTER_CALLBACKS         0U
#define USE_HAL_SD_REGISTER_CALLBACKS          0U
#define USE_HAL_SDRAM_REGISTER_CALLBACKS       0U
#define USE_HAL_SMARTCARD_REGISTER_CALLBACKS   0U
#define USE_HAL_SMBUS_REGISTER_CALLBACKS       0U
#define USE_HAL_SPDIFRX_REGISTER_CALLBACKS     0U
#define USE_HAL_SPI_REGISTER_CALLBACKS         0U
#define USE_HAL_SRAM_REGISTER_CALLBACKS         0U
#define USE_HAL_SWPMI_REGISTER_CALLBACKS       0U
#define USE_HAL_TIM_REGISTER_CALLBACKS         0U
#define USE_HAL_UART_REGISTER_CALLBACKS        0U
#define USE_HAL_USART_REGISTER_CALLBACKS       0U
#define USE_HAL_WWDG_REGISTER_CALLBACKS        0U
#define USE_HAL_XSPI_REGISTER_CALLBACKS        0U

/* -------------------------  SPI peripheral configuration  ------------------ */
#define USE_SPI_CRC  0U

/* -------------------------  Assertion  ------------------------------------- */
/* #define USE_FULL_ASSERT  1U */
#define assert_param(expr)  ((void)0U)

/* -------------------------  Ethernet Configuration  ------------------------ */
#define ETH_TX_DESC_CNT  4U
#define ETH_RX_DESC_CNT  4U
#define ETH_MAC_ADDR0    0x02U
#define ETH_MAC_ADDR1    0x00U
#define ETH_MAC_ADDR2    0x00U
#define ETH_MAC_ADDR3    0x00U
#define ETH_MAC_ADDR4    0x00U
#define ETH_MAC_ADDR5    0x00U

/* -------------------------  Include HAL headers  --------------------------- */
/**
  * @brief Include module's header file
  */

#ifdef HAL_RCC_MODULE_ENABLED
  #include "stm32h7xx_hal_rcc.h"
#endif /* HAL_RCC_MODULE_ENABLED */

#ifdef HAL_GPIO_MODULE_ENABLED
  #include "stm32h7xx_hal_gpio.h"
#endif /* HAL_GPIO_MODULE_ENABLED */

#ifdef HAL_DMA_MODULE_ENABLED
  #include "stm32h7xx_hal_dma.h"
#endif /* HAL_DMA_MODULE_ENABLED */

#ifdef HAL_CORTEX_MODULE_ENABLED
  #include "stm32h7xx_hal_cortex.h"
#endif /* HAL_CORTEX_MODULE_ENABLED */

#ifdef HAL_EXTI_MODULE_ENABLED
  #include "stm32h7xx_hal_exti.h"
#endif /* HAL_EXTI_MODULE_ENABLED */

#ifdef HAL_FLASH_MODULE_ENABLED
  #include "stm32h7xx_hal_flash.h"
#endif /* HAL_FLASH_MODULE_ENABLED */

#ifdef HAL_PWR_MODULE_ENABLED
  #include "stm32h7xx_hal_pwr.h"
#endif /* HAL_PWR_MODULE_ENABLED */

#ifdef HAL_RNG_MODULE_ENABLED
  #include "stm32h7xx_hal_rng.h"
#endif /* HAL_RNG_MODULE_ENABLED */

/* CRYP enabled for AES_GCM only */
#ifdef HAL_CRYP_MODULE_ENABLED
  #include "stm32h7xx_hal_cryp.h"
#endif

/* #ifdef HAL_HASH_MODULE_ENABLED
  #include "stm32h7xx_hal_hash.h"
#endif */

/* Exported macro ------------------------------------------------------------*/
#ifdef  USE_FULL_ASSERT
/**
  * @brief  The assert_param macro is used for function's parameters check.
  * @param  expr: If expr is false, it calls assert_failed function
  *         which reports the name of the source file and the source
  *         line number of the call that failed.
  *         If expr is true, it returns no value.
  * @retval None
  */
  #define assert_param(expr) ((expr) ? (void)0U : assert_failed((uint8_t *)__FILE__, __LINE__))
/* Exported functions ------------------------------------------------------- */
  void assert_failed(uint8_t *file, uint32_t line);
#else
  #define assert_param(expr) ((void)0U)
#endif /* USE_FULL_ASSERT */

#ifdef __cplusplus
}
#endif

#endif /* STM32H7xx_HAL_CONF_H */

