# NXP Ports

Support for the NXP DCP, KSDK and SE050 hardware acceleration boards. 

## NXP SE050

Support for the SE050 on-board crypto hardware acceleration for symmetric AES, SHA1/SHA256/SHA384/SHA512, ECC (including ed25519) and RNG.

## SE050 Acceleration

For details about SE050 HW acceleration, see [NXP's SE050 page](https://www.nxp.com/products/security-and-authentication/authentication/edgelock-se050-plug-trust-secure-element-family-enhanced-iot-security-with-maximum-flexibility:SE050).

## Building simw-top

The code required to communicate with the SE050 is the `EdgeLock SE05x Plug & Trust Middleware (03.03.00)`, which can be found here [link](https://www.nxp.com/products/security-and-authentication/authentication/edgelock-se050-plug-trust-secure-element-family-enhanced-iot-security-with-maximum-flexibility:SE050?tab=Design_Tools_Tab) (An NXP account is required to download).

Follow the build instruction in AN12570 (EdgeLockTM SE05x Quick start guide with Raspberry Pi) [here](https://www.nxp.com/docs/en/application-note/AN12570.pdf). 

In summary here are the steps for building:

```
# from simw-top directory
mkdir build
cd build
ccmake ..
# Change:
#   `Host OS` to `Raspbian`
#   `Host Crypto` to `None`
#   `SMCOM` to `T1oI2C`
c # to configure
q
make
```

## Building wolfSSL

To enable support run:

``sh
./configure --with-se050=PATH
make
``

Where `PATH` is the directory location of `simw-top`.
Example: `./configure --with-se050=/home/pi/simw-top CFLAGS="-DWOLFSSL_SE050_INIT"`

To enable AES Cipher support use `WOLFSSL_SE050_CRYPT`
To enable SHA-1 and SHA-2 support use `WOLFSSL_SE050_HASH`

## Building Examples

Confirm that you are able to run the examples from the directory:

``sh
/simw-top_build/raspbian_native_se050_t1oi2c/bin/
``

Modify one of those examples in order to tie into wolfSSL. The `./se05x_Minimal` is the easiest one to modify.

Open the `simw-top/demos/se05x/se05x_Minimal` directory and edit `se05x_Minimal.c`. Add these headers to source file:

``c
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/port/nxp/se050_port.h>
`` 

If you would like to run our wolfcrypt test or benchmark tool, add: `#include "test.h"` or `#include benchmark.h`.

Below is the code that was replaced in `ex_sss_entry()` to run the wolfcrypt test:

``c
sss_status_t status = kStatus_SSS_Success;
int ret;

sss_session_t *pSession2 = (sss_session_t *)&pCtx->session;
sss_key_store_t *pHostSession = (sss_key_store_t *)&pCtx->host_ks;

LOG_I("running setconfig");
ret = wc_se050_set_config(pSession2, pHostSession);
if (ret != 0) {
    return kStatus_SSS_Fail;
}
LOG_I("ran setconfig correctly");
wolfcrypt_test(NULL);

LOG_I("ran wolfcrypt test");
return status;
``

Note: `wolfcrypt_test(NULL);` can be replaced with `benchmark_test();`

The two variables used in `wc_se050_set_config` are session and key store variables that are required to reference parts of the hardware.

The Makefile needs to be edited. At the top of the Makefile, the base wolfssl directory needs to be added to `INCLUDE_FLAGS`.

Next, Inside `CFLAGS`, the `se05x_Minimal` directory needs to be added so that test.c and benchmark.c are included.

Finally, underneath 'all', test.c, test.h, benchmark.c and benchmark.h need to be added, along with `-L[wolfssl directory] -lwolfssl` at the end of the line. 

### Wolfcrypt Test

To run the wolfcrypt test, two files, `test.h` and `test.c` need to be added to the `./se05x_Minimal` directory. These files can be found inside of `/wolfcrypt/test`. 
Make sure `NO_MAIN_DRIVER` is defined to avoid `int main()` conflicts. Either in the Makefile or modify test.h to define it.

You should be able to run `wolfcrypt_test()` now. 

### wolfCrypt Benchmark 

To run the benchmark, both `benchmark.c` and `benchmark.h` need to be copied from wolfcrypt/benchmark to the `./se05x_Minimal` directory.
In addition, the entire `./certs` directory will need to copied into the directory. 
Make sure `NO_MAIN_DRIVER` is defined to avoid `int main()` conflicts. Either in the Makefile or modify test.h to define it.
Now you can run `benchmark_test()`. 

## Support

For questions please email support@wolfssl.com
