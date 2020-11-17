# Silicon Labs (sliabs) Port

Support for the ERF32 Gecko
 * Series 2 device config 1 (Secure Element)
 https://docs.silabs.com/mcu/latest/efr32mg21/group-SE
 https://docs.silabs.com/mcu/latest/efr32bg21/group-SE
 https://docs.silabs.com/mcu/5.9/efr32bg21/group-SE
 https://docs.silabs.com/mcu/5.9/efr32mg21/group-SE


For details see our [](https://www.wolfssl.com/docs/)


### Building

To enable support define one of the following:

```
#define WOLFSSL_SILABS_SE_ACCEL
```

### Coding

In your application you must include <wolfssl/wolfcrypt/settings.h>
before any other wolfSSL headers. If building the sources directly we
recommend defining `WOLFSSL_USER_SETTINGS` and adding your own
`user_settings.h` file. You can find a good reference for this in
`IDE/GCC-ARM/Header/user_settings.h`.

### Caveats

 * AES GCM tags of some lengths do not pass tests.


### Benchmarks

See our [benchmarks](https://www.wolfssl.com/docs/benchmarks/) on the wolfSSL website.

### Benchmarks and Memory Use

Software only implementation (ERF32, Fast Math):

```
```

Memory Use:

```
Peak Stack: 
Peak Heap: 
Total: 
```

## Support

Email us at [support@wolfssl.com](mailto:support@wolfssl.com).
