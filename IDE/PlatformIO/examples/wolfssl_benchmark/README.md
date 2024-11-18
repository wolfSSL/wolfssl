# wolfSSL Benchmark Example

This ESP32 example uses the [wolfSSL wolfcrypt Benchmark Application](https://github.com/wolfSSL/wolfssl/tree/master/wolfcrypt/benchmark).

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
I (29) boot: compile time May 17 2024 19:42:46
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
I (93) esp_image: segment 0: paddr=00010020 vaddr=3f400020 size=1900ch (102412) map
I (138) esp_image: segment 1: paddr=00029034 vaddr=3ffb0000 size=01794h (  6036) load
I (141) esp_image: segment 2: paddr=0002a7d0 vaddr=40080000 size=05848h ( 22600) load
I (154) esp_image: segment 3: paddr=00030020 vaddr=400d0020 size=4bc50h (310352) map
I (266) esp_image: segment 4: paddr=0007bc78 vaddr=40085848 size=05b64h ( 23396) load
I (276) esp_image: segment 5: paddr=000817e4 vaddr=50000000 size=00004h (     4) load
I (282) boot: Loaded app from partition at offset 0x10000
I (282) boot: Disabling RNG early entropy source...
I (297) cpu_start: Unicore app
I (297) cpu_start: Single core mode
I (305) cpu_start: Pro cpu start user code
I (305) cpu_start: cpu freq: 240000000 Hz
I (305) cpu_start: Application information:
I (310) cpu_start: Project name:     ESP_IDF_Hello_World
I (316) cpu_start: App version:      v5.7.0-stable-512-g15af87af8-di
I (323) cpu_start: Compile time:     May 17 2024 19:42:07
I (329) cpu_start: ELF file SHA256:  eebe816ce...
I (334) cpu_start: ESP-IDF:          5.2.1
I (339) cpu_start: Min chip rev:     v0.0
I (344) cpu_start: Max chip rev:     v3.99
I (349) cpu_start: Chip rev:         v1.0
I (354) heap_init: Initializing. RAM available for dynamic allocation:
I (361) heap_init: At 3FFAE6E0 len 00001920 (6 KiB): DRAM
I (367) heap_init: At 3FFB2018 len 0002DFE8 (183 KiB): DRAM
I (373) heap_init: At 3FFE0440 len 0001FBC0 (126 KiB): D/IRAM
I (379) heap_init: At 40078000 len 00008000 (32 KiB): IRAM
I (386) heap_init: At 4008B3AC len 00014C54 (83 KiB): IRAM
I (392) heap_init: At 3FF80000 len 00002000 (8 KiB): RTCRAM
I (399) spi_flash: detected chip: generic
I (403) spi_flash: flash io: dio
I (407) main_task: Started on CPU0
I (410) main_task: Calling app_main()
I (415) wolfSSL demo: Found WOLFSSL_ESPIDF!

Hello World wolfSSL Version 5.7.0
I (423) esp32_util: Extended Version and Platform Information.
I (429) esp32_util: Chip revision: v1.0
I (434) esp32_util: SSID and plain text WiFi password not displayed in startup logs.
I (442) esp32_util:   Define SHOW_SSID_AND_PASSWORD to enable display.
W (449) esp32_util: Warning: old cmake, user_settings.h location unknown.
I (457) esp32_util: LIBWOLFSSL_VERSION_STRING = 5.7.0
I (463) esp32_util: LIBWOLFSSL_VERSION_HEX = 5007000
I (468) esp32_util: Stack HWM: 9204
I (472) esp32_util:
I (475) esp32_util: Macro Name                 Defined   Not Defined
I (482) esp32_util: ------------------------- --------- -------------
I (489) esp32_util: NO_ESPIDF_DEFAULT........                 X
I (496) esp32_util: HW_MATH_ENABLED..........     X
I (502) esp32_util: WOLFSSL_SHA224...........     X
I (507) esp32_util: WOLFSSL_SHA384...........     X
I (513) esp32_util: WOLFSSL_SHA512...........     X
I (518) esp32_util: WOLFSSL_SHA3.............     X
I (524) esp32_util: HAVE_ED25519.............     X
I (529) esp32_util: HAVE_AES_ECB.............                 X
I (536) esp32_util: HAVE_AES_DIRECT..........                 X
I (543) esp32_util: USE_FAST_MATH............     X
I (548) esp32_util: WOLFSSL_SP_MATH_ALL......                 X
I (555) esp32_util: SP_MATH..................                 X
I (561) esp32_util: WOLFSSL_HW_METRICS.......     X
I (567) esp32_util: RSA_LOW_MEM..............     X
I (572) esp32_util: SMALL_SESSION_CACHE......                 X
I (579) esp32_util: WC_NO_HARDEN.............                 X
I (586) esp32_util: TFM_TIMING_RESISTANT.....     X
I (591) esp32_util: ECC_TIMING_RESISTANT.....     X
I (597) esp32_util: WC_NO_CACHE_RESISTANT....     X
I (602) esp32_util: WC_AES_BITSLICED.........                 X
I (609) esp32_util: WOLFSSL_AES_NO_UNROLL....                 X
I (615) esp32_util: TFM_TIMING_RESISTANT.....     X
I (621) esp32_util: ECC_TIMING_RESISTANT.....     X
I (627) esp32_util: WC_RSA_BLINDING..........     X
I (632) esp32_util: NO_WRITEV................     X
I (638) esp32_util: FREERTOS.................     X
I (643) esp32_util: NO_WOLFSSL_DIR...........     X
I (649) esp32_util: WOLFSSL_NO_CURRDIR.......     X
I (654) esp32_util: WOLFSSL_LWIP.............     X
I (660) esp32_util:
I (663) esp32_util: Compiler Optimization: Default
I (668) esp32_util:
I (671) esp32_util: CONFIG_IDF_TARGET = esp32
W (676) esp32_util: Watchdog active; missing WOLFSSL_ESP_NO_WATCHDOG definition.
I (684) esp32_util: CONFIG_ESP32_DEFAULT_CPU_FREQ_MHZ: 240 MHz
I (691) esp32_util: Xthal_have_ccount: 1
I (695) esp32_util: CONFIG_MAIN_TASK_STACK_SIZE: 10500
I (701) esp32_util: CONFIG_ESP_MAIN_TASK_STACK_SIZE: 10500
I (707) esp32_util: CONFIG_TIMER_TASK_STACK_SIZE: 3584
I (713) esp32_util: CONFIG_TIMER_TASK_STACK_DEPTH: 2048
I (719) esp32_util: Stack HWM: 3ffb4ebf
I (724) esp32_util: ESP32_CRYPT is enabled for ESP32.
I (729) esp32_util: SINGLE_THREADED
I (733) esp32_util: Boot count: 1
wolfCrypt Benchmark (block bytes 1024, min 1.0 sec each)
RNG                       1625 KiB took 1.016 seconds, 1599.409 KiB/s Cycles per byte = 251.56
AES-128-CBC-enc           7600 KiB took 1.003 seconds, 7577.268 KiB/s Cycles per byte =  30.93
AES-128-CBC-dec           7350 KiB took 1.001 seconds, 7342.657 KiB/s Cycles per byte =  31.94
AES-192-CBC-enc           7575 KiB took 1.001 seconds, 7567.433 KiB/s Cycles per byte =  30.97
AES-192-CBC-dec           7325 KiB took 1.000 seconds, 7325.000 KiB/s Cycles per byte =  31.98
AES-256-CBC-enc           7375 KiB took 1.000 seconds, 7375.000 KiB/s Cycles per byte =  31.77
AES-256-CBC-dec           7325 KiB took 1.001 seconds, 7317.682 KiB/s Cycles per byte =  32.02
AES-128-GCM-enc            350 KiB took 1.008 seconds,  347.222 KiB/s Cycles per byte = 675.33
AES-128-GCM-dec            350 KiB took 1.009 seconds,  346.878 KiB/s Cycles per byte = 675.81
AES-192-GCM-enc            350 KiB took 1.013 seconds,  345.508 KiB/s Cycles per byte = 678.52
AES-192-GCM-dec            350 KiB took 1.014 seconds,  345.168 KiB/s Cycles per byte = 679.06
AES-256-GCM-enc            350 KiB took 1.018 seconds,  343.811 KiB/s Cycles per byte = 681.98
AES-256-GCM-dec            350 KiB took 1.020 seconds,  343.137 KiB/s Cycles per byte = 682.55
GMAC Default               415 KiB took 1.001 seconds,  414.585 KiB/s Cycles per byte = 565.02
AES-XTS-enc               1950 KiB took 1.000 seconds, 1950.000 KiB/s Cycles per byte = 120.17
AES-XTS-dec               1950 KiB took 1.002 seconds, 1946.108 KiB/s Cycles per byte = 120.49
AES-128-CFB               2425 KiB took 1.009 seconds, 2403.370 KiB/s Cycles per byte =  97.53
AES-192-CFB               2350 KiB took 1.010 seconds, 2326.733 KiB/s Cycles per byte = 100.67
AES-256-CFB               2250 KiB took 1.000 seconds, 2250.000 KiB/s Cycles per byte = 104.12
AES-128-OFB               2425 KiB took 1.009 seconds, 2403.370 KiB/s Cycles per byte =  97.47
AES-192-OFB               2350 KiB took 1.009 seconds, 2329.039 KiB/s Cycles per byte = 100.62
AES-256-OFB               2275 KiB took 1.010 seconds, 2252.475 KiB/s Cycles per byte = 104.07
AES-128-CTR               2450 KiB took 1.007 seconds, 2432.969 KiB/s Cycles per byte =  96.33
AES-192-CTR               2375 KiB took 1.009 seconds, 2353.816 KiB/s Cycles per byte =  99.50
AES-256-CTR               2275 KiB took 1.000 seconds, 2275.000 KiB/s Cycles per byte = 102.92
AES-256-SIV-enc            900 KiB took 1.019 seconds,  883.219 KiB/s Cycles per byte = 265.22
AES-256-SIV-dec            900 KiB took 1.019 seconds,  883.219 KiB/s Cycles per byte = 265.40
AES-384-SIV-enc            875 KiB took 1.015 seconds,  862.069 KiB/s Cycles per byte = 271.82
AES-384-SIV-dec            875 KiB took 1.016 seconds,  861.220 KiB/s Cycles per byte = 272.09
AES-512-SIV-enc            850 KiB took 1.012 seconds,  839.921 KiB/s Cycles per byte = 279.14
AES-512-SIV-dec            850 KiB took 1.014 seconds,  838.264 KiB/s Cycles per byte = 279.36
ARC4                      4100 KiB took 1.003 seconds, 4087.737 KiB/s Cycles per byte =  57.30
3DES                       450 KiB took 1.001 seconds,  449.550 KiB/s Cycles per byte = 521.21
MD5                      13775 KiB took 1.000 seconds, 13775.000 KiB/s Cycles per byte =  17.01
POLY1305                  7350 KiB took 1.000 seconds, 7350.000 KiB/s Cycles per byte =  31.89
SHA                      16175 KiB took 1.000 seconds, 16175.000 KiB/s Cycles per byte =  14.49
SHA-224                   1325 KiB took 1.004 seconds, 1319.721 KiB/s Cycles per byte = 177.55
SHA-256                  15975 KiB took 1.001 seconds, 15959.041 KiB/s Cycles per byte =  14.69
SHA-384                  17400 KiB took 1.000 seconds, 17400.000 KiB/s Cycles per byte =  13.48
SHA-512                  17200 KiB took 1.000 seconds, 17200.000 KiB/s Cycles per byte =  13.63
SHA-512/224               1150 KiB took 1.012 seconds, 1136.364 KiB/s Cycles per byte = 206.14
SHA-512/256               1150 KiB took 1.010 seconds, 1138.614 KiB/s Cycles per byte = 205.91
SHA3-224                  1125 KiB took 1.001 seconds, 1123.876 KiB/s Cycles per byte = 208.50
SHA3-256                  1075 KiB took 1.013 seconds, 1061.204 KiB/s Cycles per byte = 220.77
SHA3-384                   825 KiB took 1.007 seconds,  819.265 KiB/s Cycles per byte = 285.94
SHA3-512                   575 KiB took 1.002 seconds,  573.852 KiB/s Cycles per byte = 408.48
SHAKE128                  1300 KiB took 1.000 seconds, 1300.000 KiB/s Cycles per byte = 180.29
SHAKE256                  1075 KiB took 1.012 seconds, 1062.253 KiB/s Cycles per byte = 220.72
BLAKE2b                   1650 KiB took 1.007 seconds, 1638.530 KiB/s Cycles per byte = 143.04
BLAKE2s                   3475 KiB took 1.003 seconds, 3464.606 KiB/s Cycles per byte =  67.59
AES-128-CMAC              2350 KiB took 1.009 seconds, 2329.039 KiB/s Cycles per byte = 100.65
AES-256-CMAC              2200 KiB took 1.006 seconds, 2186.879 KiB/s Cycles per byte = 107.22
HMAC-MD5                 13625 KiB took 1.000 seconds, 13625.000 KiB/s Cycles per byte =  17.21
HMAC-SHA                 15800 KiB took 1.000 seconds, 15800.000 KiB/s Cycles per byte =  14.84
HMAC-SHA224               1325 KiB took 1.012 seconds, 1309.289 KiB/s Cycles per byte = 179.02
HMAC-SHA256              15575 KiB took 1.000 seconds, 15575.000 KiB/s Cycles per byte =  15.05
HMAC-SHA384              16375 KiB took 1.000 seconds, 16375.000 KiB/s Cycles per byte =  14.32
HMAC-SHA512              15850 KiB took 1.000 seconds, 15850.000 KiB/s Cycles per byte =  14.80
PBKDF2                       1 KiB took 1.024 seconds,    0.549 KiB/s Cycles per byte = 426593.36
RSA     1024  key gen         1 ops took 1.142 sec, avg 1142.000 ms, 0.876 ops/sec
RSA     2048  key gen         1 ops took 2.817 sec, avg 2817.000 ms, 0.355 ops/sec
RSA     2048   public        14 ops took 1.115 sec, avg 79.643 ms, 12.556 ops/sec
RSA     2048  private         6 ops took 1.272 sec, avg 212.000 ms, 4.717 ops/sec
DH      2048  key gen         5 ops took 1.206 sec, avg 241.200 ms, 4.146 ops/sec
DH      2048    agree        14 ops took 1.106 sec, avg 79.000 ms, 12.658 ops/sec
ECC   [      SECP256R1]   256  key gen         4 ops took 1.525 sec, avg 381.250 ms, 2.623 ops/sec
ECDHE [      SECP256R1]   256    agree         4 ops took 1.522 sec, avg 380.500 ms, 2.628 ops/sec
ECDSA [      SECP256R1]   256     sign         4 ops took 1.541 sec, avg 385.250 ms, 2.596 ops/sec
ECDSA [      SECP256R1]   256   verify         4 ops took 1.014 sec, avg 253.500 ms, 3.945 ops/sec
CURVE  25519  key gen         3 ops took 1.186 sec, avg 395.333 ms, 2.530 ops/sec
CURVE  25519    agree         4 ops took 1.577 sec, avg 394.250 ms, 2.536 ops/sec
ED     25519  key gen        45 ops took 1.006 sec, avg 22.356 ms, 44.732 ops/sec
ED     25519     sign        40 ops took 1.036 sec, avg 25.900 ms, 38.610 ops/sec
ED     25519   verify        26 ops took 1.014 sec, avg 39.000 ms, 25.641 ops/sec
Benchmark complete

benchmark_test complete! result code: 0
I (82083) main_task: Returned from app_main()
```

See the README.md file in the upper level 'examples' directory for [more information about examples](../README.md).
