# wolfSSL Crypt Test Example

This ESP32 example uses the [wolfSSL wolfcrypt Test Application](https://github.com/wolfSSL/wolfssl/tree/master/wolfcrypt/test).

Other target boards _should_ work, but have not yet been tested.

For general information on [wolfSSL examples for Espressif](../README.md), see the
[README](https://github.com/wolfSSL/wolfssl/blob/master/IDE/Espressif/ESP-IDF/README.md) file.


## Example Output

Note the default wolfSSL `user_settings.h` is configured by default to be the most
compatible across the widest ranges of targets. Contact wolfSSL at support@wolfssl.com
for help in optimizing for your particular application, or see the
[docs](https://www.wolfssl.com/documentation/manuals/wolfssl/index.html).


```
ets Jun  8 2016 00:22:57

rst:0x1 (POWERON_RESET),boot:0x13 (SPI_FAST_FLASH_BOOT)
configsip: 0, SPIWP:0xee
clk_drv:0x00,q_drv:0x00,d_drv:0x00,cs0_drv:0x00,hd_drv:0x00,wp_drv:0x00
mode:DIO, clock div:2
load:0x3fff0030,len:7168
load:0x40078000,len:15612
load:0x40080400,len:4
load:0x40080404,len:3736
entry 0x40080624
I (28) boot: ESP-IDF 5.2.1 2nd stage bootloader
I (29) boot: compile time May 17 2024 19:32:25
W (29) boot: Unicore bootloader
I (32) boot: chip revision: v1.0
I (36) boot.esp32: SPI Speed      : 40MHz
I (41) boot.esp32: SPI Mode       : DIO
I (45) boot.esp32: SPI Flash Size : 4MB
I (50) boot: Enabling RNG early entropy source...
I (55) boot: Partition Table:
I (59) boot: ## Label            Usage          Type ST Offset   Length
I (66) boot:  0 nvs              WiFi data        01 02 00009000 00006000
I (74) boot:  1 phy_init         RF data          01 01 0000f000 00001000
I (81) boot:  2 factory          factory app      00 00 00010000 00100000
I (89) boot: End of partition table
I (93) esp_image: segment 0: paddr=00010020 vaddr=3f400020 size=31e24h (204324) map
I (175) esp_image: segment 1: paddr=00041e4c vaddr=3ffb0000 size=01c54h (  7252) load
I (178) esp_image: segment 2: paddr=00043aa8 vaddr=40080000 size=0b3c0h ( 46016) load
I (200) esp_image: segment 3: paddr=0004ee70 vaddr=50000000 size=00004h (     4) load
I (200) esp_image: segment 4: paddr=0004ee7c vaddr=00000000 size=0119ch (  4508)
I (207) esp_image: segment 5: paddr=00050020 vaddr=400d0020 size=abb7ch (703356) map
I (473) boot: Loaded app from partition at offset 0x10000
I (474) boot: Disabling RNG early entropy source...
I (485) cpu_start: Unicore app
I (485) cpu_start: Single core mode
I (493) cpu_start: Pro cpu start user code
I (493) cpu_start: cpu freq: 240000000 Hz
I (493) cpu_start: Application information:
I (498) cpu_start: Project name:     ESP_IDF_Hello_World
I (504) cpu_start: App version:      v5.7.0-stable-512-g15af87af8-di
I (511) cpu_start: Compile time:     May 17 2024 19:31:47
I (517) cpu_start: ELF file SHA256:  40b2541a0...
I (523) cpu_start: ESP-IDF:          5.2.1
I (528) cpu_start: Min chip rev:     v0.0
I (532) cpu_start: Max chip rev:     v3.99
I (537) cpu_start: Chip rev:         v1.0
I (542) heap_init: Initializing. RAM available for dynamic allocation:
I (549) heap_init: At 3FFAE6E0 len 00001920 (6 KiB): DRAM
I (555) heap_init: At 3FFB38C0 len 0002C740 (177 KiB): DRAM
I (561) heap_init: At 3FFE0440 len 0001FBC0 (126 KiB): D/IRAM
I (568) heap_init: At 40078000 len 00008000 (32 KiB): IRAM
I (574) heap_init: At 4008B3C0 len 00014C40 (83 KiB): IRAM
I (580) heap_init: At 3FF80000 len 00002000 (8 KiB): RTCRAM
I (588) spi_flash: detected chip: generic
I (591) spi_flash: flash io: dio
I (595) main_task: Started on CPU0
I (598) main_task: Calling app_main()
I (603) wolfSSL demo: Found WOLFSSL_ESPIDF!
Hello World wolfSSL Version 5.7.0
I (611) esp32_util: Extended Version and Platform Information.
I (617) esp32_util: Chip revision: v1.0
I (622) esp32_util: SSID and plain text WiFi password not displayed in startup logs.
I (630) esp32_util:   Define SHOW_SSID_AND_PASSWORD to enable display.
W (637) esp32_util: Warning: old cmake, user_settings.h location unknown.
I (645) esp32_util: LIBWOLFSSL_VERSION_STRING = 5.7.0
I (650) esp32_util: LIBWOLFSSL_VERSION_HEX = 5007000
I (656) esp32_util: Stack HWM: 9212
I (660) esp32_util:
I (663) esp32_util: Macro Name                 Defined   Not Defined
I (670) esp32_util: ------------------------- --------- -------------
I (677) esp32_util: NO_ESPIDF_DEFAULT........                 X
I (684) esp32_util: HW_MATH_ENABLED..........     X
I (689) esp32_util: WOLFSSL_SHA224...........     X
I (695) esp32_util: WOLFSSL_SHA384...........     X
I (700) esp32_util: WOLFSSL_SHA512...........     X
I (706) esp32_util: WOLFSSL_SHA3.............     X
I (712) esp32_util: HAVE_ED25519.............     X
I (717) esp32_util: HAVE_AES_ECB.............                 X
I (724) esp32_util: HAVE_AES_DIRECT..........                 X
I (730) esp32_util: USE_FAST_MATH............     X
I (736) esp32_util: WOLFSSL_SP_MATH_ALL......                 X
I (743) esp32_util: SP_MATH..................                 X
I (749) esp32_util: WOLFSSL_HW_METRICS.......     X
I (755) esp32_util: RSA_LOW_MEM..............     X
I (760) esp32_util: SMALL_SESSION_CACHE......                 X
I (767) esp32_util: WC_NO_HARDEN.............                 X
I (773) esp32_util: TFM_TIMING_RESISTANT.....     X
I (779) esp32_util: ECC_TIMING_RESISTANT.....     X
I (785) esp32_util: WC_NO_CACHE_RESISTANT....     X
I (790) esp32_util: WC_AES_BITSLICED.........                 X
I (797) esp32_util: WOLFSSL_AES_NO_UNROLL....                 X
I (803) esp32_util: TFM_TIMING_RESISTANT.....     X
I (809) esp32_util: ECC_TIMING_RESISTANT.....     X
I (814) esp32_util: WC_RSA_BLINDING..........     X
I (820) esp32_util: NO_WRITEV................     X
I (825) esp32_util: FREERTOS.................     X
I (831) esp32_util: NO_WOLFSSL_DIR...........     X
I (837) esp32_util: WOLFSSL_NO_CURRDIR.......     X
I (842) esp32_util: WOLFSSL_LWIP.............     X
I (848) esp32_util:
I (851) esp32_util: Compiler Optimization: Default
I (856) esp32_util:
I (859) esp32_util: CONFIG_IDF_TARGET = esp32
W (864) esp32_util: Watchdog active; missing WOLFSSL_ESP_NO_WATCHDOG definition.
I (872) esp32_util: CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ: 240 MHz
I (879) esp32_util: Xthal_have_ccount: 1
I (883) esp32_util: CONFIG_MAIN_TASK_STACK_SIZE: 10500
I (889) esp32_util: CONFIG_ESP_MAIN_TASK_STACK_SIZE: 10500
I (895) esp32_util: CONFIG_TIMER_TASK_STACK_SIZE: 3584
I (901) esp32_util: CONFIG_TIMER_TASK_STACK_DEPTH: 2048
I (907) esp32_util: Stack HWM: 8988
I (911) esp32_util: ESP32_CRYPT is enabled for ESP32.
I (917) esp32_util: NOT SINGLE_THREADED
I (921) esp32_util: Boot count: 1
------------------------------------------------------------------------------
 wolfSSL version 5.7.0
------------------------------------------------------------------------------
error    test passed!
MEMORY   test passed!
base64   test passed!
base16   test passed!
asn      test passed!
RANDOM   test passed!
MD5      test passed!
MD2      test passed!
MD4      test passed!
SHA      test passed!
SHA-224  test passed!
SHA-256  test passed!
SHA-384  test passed!
SHA-512  test passed!
SHA-512/224  test passed!
SHA-512/256  test passed!
SHA-3    test passed!
SHAKE128 test passed!
SHAKE256 test passed!
Hash     test passed!
BLAKE2b  test passed!
BLAKE2s  test passed!
HMAC-MD5 test passed!
HMAC-SHA test passed!
HMAC-SHA224 test passed!
HMAC-SHA256 test passed!
HMAC-SHA384 test passed!
HMAC-SHA512 test passed!
HMAC-SHA3   test passed!
HMAC-KDF    test passed!
SSH-KDF     test passed!
PRF         test passed!
TLSv1.2 KDF test passed!
TLSv1.3 KDF test passed!
X963-KDF    test passed!
HPKE     test passed!
GMAC     test passed!
RC2      test passed!
ARC4     test passed!
POLY1305 test passed!
DES      test passed!
DES3     test passed!
AES      test passed!
AES192   test passed!
AES256   test passed!
AES-OFB   test passed!
AES-GCM  test passed!
AES-CFB  test passed!
AES-XTS  test passed!
AES Key Wrap test passed!
AES-SIV  test passed!
AES-EAX  test passed!
RSA      test passed!
DH       test passed!
DSA      test passed!
SRP      test passed!
PWDBASED test passed!
PKCS12   test passed!
openSSL extra test
OPENSSL  test passed!
OPENSSL (EVP MD) passed!
OPENSSL (PKEY0) passed!
OPENSSL (PKEY1) passed!
OPENSSL (EVP Sign/Verify) passed!
ECC      test passed!
ECC buffer test passed!
CURVE25519 test passed!
ED25519  test passed!
CMAC     test passed!
PKCS7encrypted  test passed!
PKCS7signed     test passed!
PKCS7enveloped  test passed!
PKCS7authenveloped  test passed!
mp       test passed!
prime    test passed!
logging  test passed!
time     test passed!
mutex    test passed!
cert piv test passed!
I (261247) wolfssl_esp32_mp:
I (261248) wolfssl_esp32_mp: esp_mp_mul HW acceleration enabled.
I (261255) wolfssl_esp32_mp: Number of calls to esp_mp_mul: 3413
I (261262) wolfssl_esp32_mp: Success: no esp_mp_mul() errors.
I (261268) wolfssl_esp32_mp:
I (261272) wolfssl_esp32_mp: esp_mp_mulmod HW acceleration enabled.
I (261279) wolfssl_esp32_mp: Number of calls to esp_mp_mulmod: 2170
I (261286) wolfssl_esp32_mp: Number of fallback to SW mp_mulmod: 331
I (261293) wolfssl_esp32_mp: Success: no esp_mp_mulmod errors.
I (261299) wolfssl_esp32_mp: Success: no esp_mp_mulmod even mod.
I (261306) wolfssl_esp32_mp: Success: no esp_mp_mulmod small x or y.
I (261313) wolfssl_esp32_mp:
I (261317) wolfssl_esp32_mp: Number of calls to esp_mp_exptmod: 659
I (261324) wolfssl_esp32_mp: Number of fallback to SW mp_exptmod: 105
I (261331) wolfssl_esp32_mp: Success: no esp_mp_exptmod errors.
I (261337) wolfssl_esp32_mp: Max N->used: esp_mp_max_used = 64
I (261344) wolfssl_esp32_mp: Max timeout: esp_mp_max_timeout = 1
Test complete
I (261352) wc_test: Exiting main with return code:  0


wolf_test_task complete! result code: 0
I (261361) main_task: Returned from app_main()
```

See the README.md file in the upper level 'examples' directory for [more information about examples](../README.md).
