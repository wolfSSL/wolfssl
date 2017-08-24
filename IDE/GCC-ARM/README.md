# Example Project for GCC ARM

## Design

* All library options are defined in `Header/user_settings.h`.
* The memory map is located in the linker file in `linker.ld`.
* Entry point function is `reset_handler` in `retarget.c`.
* The RTC and RNG hardware interface needs implemented for real production applications in `retarget.c`

## Building

1. Make sure you have `gcc-arm-none-eabi` installed.
2. Modify the `Makefile` to point to correct `TOOLCHAIN_DIR`.
3. Use `make` and it will build both targets as `.elf` and `.hex` in `/Build`.

Example:

```
   text	   data	    bss	    dec	    hex   filename
  50076	   2508	     44	  52628	   cd94   ./Build/WolfCryptTest.elf

   text	   data	    bss	    dec	    hex   filename
  39155	   2508	     60	  41723	   a2fb   ./Build/WolfCryptBench.elf
```

## Performace Tuning Options

* `DEBUG_WOLFSSL`: Undefine this to disable debug logging.
* `NO_INLINE`: Disabling inline function saves about 1KB, but is slower.
* `WOLFSSL_SMALL_STACK`: Enables stack reduction techniques to allocate stack sections over 100 bytes from heap.
* `USE_FAST_MATH`: Uses stack based math, which is faster than the heap based math.
* `ECC_SHAMIR`: Doubles heap usage, but slightly faster
* `RSA_LOW_MEM`: Half as much memory but twice as slow. Uses Non-CRT method for private key.
AES GCM: `GCM_SMALL`, `GCM_WORD32` or `GCM_TABLE`: Tunes performance and flash/memory usage.
* `CURVED25519_SMALL`: Enables small versions of Ed/Curve (FE/GE math).
* `USE_SLOW_SHA`: Enables smaller/slower version of SHA.
* `USE_SLOW_SHA2`: Over twice as small, but 50% slower
* `FP_MAX_BITS`: Is the maximum math size (key size * 2). Used only with `USE_FAST_MATH`.
* `USE_CERT_BUFFERS_1024` or `USE_CERT_BUFFERS_2048`: Size of RSA certs / keys to test with. 
