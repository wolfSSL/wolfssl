# WolfSSL Examples using the OM13076 (LPCXpresso18S37) board

To use, install the NXP LPCXpresso IDE and import the projects in a new workspace.

## WolfSSL example projects:

1. `wolf_demo_aes` based on the `periph_aes` example. It has console options to run the Wolf tests and benchmarks ('t' for the WolfSSL Tests and 'b' for the WolfSSL Benchmarks).

2. `wolf_demo_lwip` which includes FreeRTOS and the LWIP network stack for Ethernet support (originally based on the `lwip_freertos_tcpecho` example). 

## Static libraries projects:

1. `lib_wolfssl` for WolfSSL. The WolfSSL port for the LPC18XX platform is located in `workspace/lib_wolfssl/lpc_18xx_port.c`. This has port functions for `current_time` and `rand_gen`. The `WOLF_USER_SETTINGS` define is set which allows all WolfSSL settings to exist in the `user_settings.h` file (see this for all customizations set).

2. `lib_freertos` for FreeRTOS. Due to the fragmented RAM areas on the LPC18S37 the FreeRTOS memeory management scheme heap5 was used, which allows multiple RAM areas to be defined for the heap. The RedLib heap is still used for printf support, so the first 0x200 is reserved for RedLib heap. See `#define REDLIB_HEAP` in heap5.c. The heap is using the remainder of RAM1 (~30KB) and all of RAM2 (40KB).

3. `lib_lwip` for LWIP. This contains the Ethernet driver and LWIP network stack.

## Important Files

1. `lib_wolfssl/user_settings.h`. This provides a reference for library settings used to optimize for this embedded platform.

2. `lib_wolfssl/lpc_18xx_port.c`. This defines the required time and random number functions for the WolfSSL library.

3. `lib_freerots/src/heap5.c`. This defines multiple RAM regions to extend the heap to about 70KB. Default implementation provides about 30KB for heap and stack.

4. `wolf_demo_aes/example/aes.c`. This shows use of the WolfSSL tests and benchmarks. It also is their example driver for using their AES HW acceleration, which would be the next step for integration into the WolfSSL library.

5. `wolf_demo_lwip/examples/main.c`. This shows use of the WolfSSL library with FreeRTOS and LWIP.