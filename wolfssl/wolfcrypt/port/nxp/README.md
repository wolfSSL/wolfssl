
# NXP Ports

Support for the NXP DCP, KSDK and SE050 hardware acceleration boards. 

## NXP SE050
Support for the SE050 on-board crypto hardware acceleration for symmetric AES, SHA1/SHA256/SHA384/SHA512, ECC (including ed25519) and RNG. **(discuss p-256 ECC)**

## SE050 Acceleration
For details about SE050 HW acceleration, see [NXP's SE050 page](https://www.nxp.com/products/security-and-authentication/authentication/edgelock-se050-plug-trust-secure-element-family-enhanced-iot-security-with-maximum-flexibility:SE050).

## Building

To enable support run:
```
./configure --with-se050=PATH
```
Followed by:
```
make && make install
```
With PATH being the directory location of simw-top.

The code required to communicate with the SE050 can be found at this NXP [link](https://www.nxp.com/products/security-and-authentication/authentication/edgelock-se050-plug-trust-secure-element-family-enhanced-iot-security-with-maximum-flexibility:SE050?tab=Design_Tools_Tab) (An NXP account is required to download). Follow the instructions [here](https://www.nxp.com/docs/en/application-note/AN12570.pdf) to install and setup with a Raspberry Pi. 
Confirm that you are able to run the examples from the 
```
/simw-top_build/raspbian_native_se050_t1oi2c/bin/
```
directory. Once that's done, it's time to modify one of those examples in order to tie into wolfSSL. 
The ``./se05x_Minimal `` is the easiest one to modify. Open the ``simw-top/demos/se05x/se05x_Minimal `` directory and edit ``se05x_Minimal.c``. Add these headers to source file:
```
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/types.h>
#include <wolfssl/wolfcrypt/port/nxp/se050_port.h>
``` 
If you would like to run our wolfcrypt test or  benchmark tool, add:
``#include "test.h"`` or ``#include benchmark.h``, respectively. Below is the code that was replaced in ``ex_sss_entry()`` that ran the wolfcrypt test:
```
    sss_status_t status = kStatus_SSS_Success;
    int ret;
    
    sss_session_t *pSession2 = (sss_session_t *)&pCtx->session;
    sss_key_store_t *pHostSession = (sss_key_store_t *)&pCtx->host_ks;

    LOG_I("running setconfig");
    ret = wolfcrypt_se050_SetConfig(pSession2, pHostSession);
    if (ret != 0) {
        return kStatus_SSS_Fail;
    }
    LOG_I("ran setconfig correctly");
    wolfcrypt_test(NULL);

    LOG_I("ran wolfcrypt test");
    return status;
```

``wolfcrypt_test(NULL);`` can be replaced with ``benchmark_test();``
The two variables used in  ``wolfcrypt_se050_SetConfig`` are session and key store variables that are required to reference parts of the hardware. 

Next, the Makefile needs to be edited.
At the top of the Makefile, the base wolfssl directory needs to be added to ``INCLUDE_FLAGS``. Next, Inside ``CFLAGS``, the ``se05x_Minimal`` directory needs to be added so that test.c and benchmark.c are included. Finally, underneath 'all', test.c, test.h, benchmark.c and benchmark.h need to be added, along with ``-L (wolfssl directory) -lwolfssl`` at the end of the line. 
## Wolfcrypt Test
To run the wolfcrypt test, two files, ``test.h`` and ``test.c`` need to be added to the ``./se05x_Minimal`` directory. These files can be found inside of ``/wolfcrypt/test``. 
Next, ``#define NO_MAIN_DRIVER`` needs to be added to test.h.
You should be able to run `wolfcrypt_test()` now. 

## Benchmark 
To run the benchmark, both ``benchmark.c`` and ``benchmark.h`` need to be copied from wolfcrypt/benchmark to the `./se05x_Minimal` directory.  In addition, the entire `./certs` directory will need to copied into the directory. ``#define NO_MAIN_DRIVER`` will need to be added to `benchmark.h`. You should be able to run `benchmark_test() ` now. 
