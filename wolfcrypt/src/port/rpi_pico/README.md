# wolfSSL Raspberry Pi Pico Acceleration

wolfSSL supports RNG acceleration on the Raspberry Pi RP2040 and RP2350
microcontrollers. Everything here assumes you are using the standard [Raspberry
Pi Pico SDK](https://github.com/raspberrypi/pico-sdk).

It has only been tested with the ARM cores of the RP2350, not the RISC-V cores.

## RNG Acceleration

The Pico SDK has RNG functions for both the RP2040 and RP2350. In the RP2040
this is an optimised PRNG method, in the RP2350 it uses a built-in TRNG. The
same API is used for both.

## Compiling wolfSSL

In your `user_settings.h`, you should set the following to add support in
wolfSSL:

```c
#define WOLFSSL_RPIPICO
```

Then for an RP2040, enable the ARM Thumb instructions:

```c
#define WOLFSSL_SP_ARM_THUMB_ASM
```

or for an RP2350, the Cortex-M instructions should be used:

```c
#define WOLFSSL_SP_ARM_CORTEX_M_ASM
```

To enable the RNG acceleration add the following:

```c
#define WC_NO_HASHDRBG
#define CUSTOM_RAND_GENERATE_BLOCK wc_pico_rng_gen_block
```

In CMake you should add the following linking to both wolfSSL and the end
application:

```cmake
target_link_libraries(wolfssl
    pico_stdlib
    pico_rand
)
```

A full example can be found in the
[`RPi-Pico`](https://github.com/wolfSSL/wolfssl-examples/tree/master/RPi-Pico)
directory of the
[`wolfssl-examples`](https://github.com/wolfSSL/wolfssl-examples) GitHub
repository.

## Note on RP2350 SHA256

Although RP2350 has SHA256 acceleration, we cannot use this. It is because
we need to get an intermediate result using `wc_Sha256GetHash()`. The hardware
will only deal with 64byte packets of data, so to get a result we need to do
SHA padding. Once the SHA padding is done, it is not in a state to add more
data.
The only real workaround would be to cache everything being sent into the
hardware and replay it as a new instance when trying to get an intermediate
result. This would not very efficient for an embedded device.

## Support

For questions please email support@wolfssl.com
