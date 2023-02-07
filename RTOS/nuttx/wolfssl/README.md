# NuttX + wolfSSL

## Instructions

1) Create working directory (e.g. ~/nuttxspace):
    ```
    $ cd ~
    $ mkdir nuttxspace
    ```
2) Install dependencies:
    ```
    $ cd ~/nuttxspace
    $ sudo apt install -y bison flex gettext texinfo libncurses5-dev libncursesw5-dev gperf automake libtool pkg-config build-essential gperf genromfs libgmp-dev libmpc-dev libmpfr-dev libisl-dev binutils-dev libelf-dev libexpat-dev gcc-multilib g++-multilib picocom u-boot-tools util-linux
    $ sudo apt install -y kconfig-frontends
    $ sudo apt install -y gcc-arm-none-eabi binutils-arm-none-eabi
    ```
3) Clone nuttx and nuttx-apps into working directory:
    ```
    $ git clone https://github.com/apache/nuttx.git nuttx
    $ git clone https://github.com/apache/nuttx-apps apps
    ```
4) Copy this directory into the working directory applications:
    ```
    $ cp -R RTOS/nuttx/wolfssl ~/nuttxspace/apps/crypto/wolfssl
    ```
5) Setup wolfSSL in preparation for the build, `WOLFSSL_DIR` must be the path to the original wolfssl repo:
    ```
    $ cd ~/nuttxspace/apps/crypto/wolfssl
    $ WOLFSSL_DIR=<path-to-wolfssl-repo> ./setup-wolfssl.sh
    ```
6) Setup baseline NuttX configuration (board + NuttX Shell):
    ```
    $ cd ~/nuttxspace/nuttx
    $ ./tools/configure.sh -l <board>:nsh
    ```
   If you are using wolfSSL for TLS you should use the `netnsh` target if your board supports it
   ```
    $ ./tools/configure.sh -l <board>:netnsh
   ```
> **EXAMPLES:**
>   - For NuttX Simulator: `$ ./tools/configure.sh sim:nsh`
>   - For BL602 (RISC-V): `$ ./tools/configure.sh -l bl602evb:nsh`
>   - For NUCLEO-L552ZE-Q (Cortex-M33): `$ ./tools/configure.sh -l nucleo-l552ze:nsh`
>   - For NUCLEO-H753ZI: `$ ./tools/configure.sh -l nucleo-h743zi:nsh`
>   - For NUCLEO-F756ZG: `./tools/configure.sh -l nucleo-144:f746-nsh`

7) Start custom configuration system:
    ```
    $ make menuconfig
    ```
8) Configure NuttX to enable the wolfSSL crypto library test applications:
    - From main menu select: **Application Configuration > Cryptography Library Support**
    - Enable and then select **wolfSSL SSL/TLS Cryptography Library**
    - Enable and then select **wolfSSL applications**
    - Enable applications:
        - **wolfCrypt Benchmark application**
        - **wolfCrypt Test application**
        - **wolfSSL client and server example**
    - Select Save from bottom menu, saving to `.config` file
    - Exit configuration tool

    If you are using wolfSSL for TLS you should use the `netnsh` target and should enable an NTP or some for of system time keeping so that wolfSSL has the current date to check certificates. You will also need to set the right networking settings for NuttX to connect to the internet.
9) Build NuttX and wolfSSL:
    ```
    $ make
    ```
    Example Output:
    ```
CC:  wolfssl/wolfcrypt/src/random.c /home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl/wolfcrypt/src/random.c:3781:10: warning: #warning "write a real random seed!!!!, just for testing now" [-Wcpp]
 3781 |         #warning "write a real random seed!!!!, just for testing now"
      |          ^~~~~~~
CC:  wolfssl-examples/embedded/tls-client-server.c /home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c: In function 'wolfssl_client_new':
/home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c:163:9: warning: implicit declaration of function 'printf' [-Wimplicit-function-declaration]
  163 |         printf("ERROR: failed to create WOLFSSL_CTX\n");
      |         ^~~~~~
/home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c:163:9: warning: incompatible implicit declaration of built-in function 'printf'
/home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c:29:1: note: include '<stdio.h>' or provide a declaration of 'printf'
   28 | #include "certs.h"
  +++ |+#include <stdio.h>
   29 | 
/home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c:171:13: warning: incompatible implicit declaration of built-in function 'printf'
  171 |             printf("ERROR: failed to load CA certificate\n");
      |             ^~~~~~
/home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c:171:13: note: include '<stdio.h>' or provide a declaration of 'printf'
/home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c:185:13: warning: incompatible implicit declaration of built-in function 'printf'
  185 |             printf("ERROR: failed to create WOLFSSL object\n");
      |             ^~~~~~
/home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c:185:13: note: include '<stdio.h>' or provide a declaration of 'printf'
/home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c: In function 'wolfssl_client_connect':
/home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c:211:13: warning: incompatible implicit declaration of built-in function 'printf'
  211 |             printf("Client waiting for server\n");
      |             ^~~~~~
/home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c:211:13: note: include '<stdio.h>' or provide a declaration of 'printf'
/home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c:214:13: warning: incompatible implicit declaration of built-in function 'printf'
  214 |             printf("Client waiting for buffer\n");
      |             ^~~~~~
/home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c:214:13: note: include '<stdio.h>' or provide a declaration of 'printf'
/home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c: In function 'wolfssl_server_new':
/home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c:234:9: warning: incompatible implicit declaration of built-in function 'printf'
  234 |         printf("ERROR: failed to create WOLFSSL_CTX\n");
      |         ^~~~~~
/home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c:234:9: note: include '<stdio.h>' or provide a declaration of 'printf'
/home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c:242:13: warning: incompatible implicit declaration of built-in function 'printf'
  242 |             printf("ERROR: failed to load server certificate\n");
      |             ^~~~~~
/home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c:242:13: note: include '<stdio.h>' or provide a declaration of 'printf'
/home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c:252:13: warning: incompatible implicit declaration of built-in function 'printf'
  252 |             printf("ERROR: failed to load server key\n");
      |             ^~~~~~
/home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c:252:13: note: include '<stdio.h>' or provide a declaration of 'printf'
/home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c:266:13: warning: incompatible implicit declaration of built-in function 'printf'
  266 |             printf("ERROR: failed to create WOLFSSL object\n");
      |             ^~~~~~
/home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c:266:13: note: include '<stdio.h>' or provide a declaration of 'printf'
/home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c: In function 'wolfssl_server_accept':
/home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c:291:13: warning: incompatible implicit declaration of built-in function 'printf'
  291 |             printf("Server waiting for server\n");
      |             ^~~~~~
/home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c:291:13: note: include '<stdio.h>' or provide a declaration of 'printf'
/home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c:294:13: warning: incompatible implicit declaration of built-in function 'printf'
  294 |             printf("Server waiting for buffer\n");
      |             ^~~~~~
/home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c:294:13: note: include '<stdio.h>' or provide a declaration of 'printf'
/home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c: In function 'wolfssl_send':
/home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c:309:5: warning: incompatible implicit declaration of built-in function 'printf'
  309 |     printf("%s", msg);
      |     ^~~~~~
/home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c:309:5: note: include '<stdio.h>' or provide a declaration of 'printf'
/home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c: In function 'wolfssl_recv':
/home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c:328:9: warning: incompatible implicit declaration of built-in function 'printf'
  328 |         printf("%s", reply);
      |         ^~~~~~
/home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c:328:9: note: include '<stdio.h>' or provide a declaration of 'printf'
/home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c: In function 'wolfssl_client_server_main':
/home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c:434:9: warning: incompatible implicit declaration of built-in function 'printf'
  434 |         printf("Handshake complete\n");
      |         ^~~~~~
/home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c:434:9: note: include '<stdio.h>' or provide a declaration of 'printf'
/home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c:438:9: warning: incompatible implicit declaration of built-in function 'printf'
  438 |         printf("\nClient Sending:\n");
      |         ^~~~~~
/home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c:438:9: note: include '<stdio.h>' or provide a declaration of 'printf'
/home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c:442:9: warning: incompatible implicit declaration of built-in function 'printf'
  442 |         printf("\nServer Received:\n");
      |         ^~~~~~
/home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c:442:9: note: include '<stdio.h>' or provide a declaration of 'printf'
/home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c:446:9: warning: incompatible implicit declaration of built-in function 'printf'
  446 |         printf("\nServer Sending:\n");
      |         ^~~~~~
/home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c:446:9: note: include '<stdio.h>' or provide a declaration of 'printf'
/home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c:450:9: warning: incompatible implicit declaration of built-in function 'printf'
  450 |         printf("\nClient Received:\n");
      |         ^~~~~~
/home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c:450:9: note: include '<stdio.h>' or provide a declaration of 'printf'
/home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c:466:9: warning: incompatible implicit declaration of built-in function 'printf'
  466 |         printf("Done\n");
      |         ^~~~~~
/home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c:466:9: note: include '<stdio.h>' or provide a declaration of 'printf'
/home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c:469:9: warning: incompatible implicit declaration of built-in function 'printf'
  469 |         printf("Error: %d, %s\n", ret, wolfSSL_ERR_error_string(ret, buffer));
      |         ^~~~~~
/home/john/Documents/nuttxspace/apps/crypto/wolfssl/wolfssl-examples/embedded/tls-client-server.c:469:9: note: include '<stdio.h>' or provide a declaration of 'printf'
AR (add): libapps.a    wolfssl/src/crl.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/src/internal.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/src/keys.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/src/ocsp.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/src/sniffer.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/src/ssl.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/src/tls.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/src/tls13.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/src/wolfio.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/aes.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/cmac.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/des3.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/dh.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/ecc.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/hmac.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/random.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/rsa.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/sha.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/sha256.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/sha512.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/sha3.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/asm.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/asn.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/blake2s.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/chacha.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/chacha20_poly1305.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/coding.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/compress.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/cpuid.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/cryptocb.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/curve25519.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/curve448.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/ecc_fp.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/eccsi.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/ed25519.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/ed448.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/error.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/fe_448.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/fe_low_mem.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/fe_operations.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/ge_448.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/ge_low_mem.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/ge_operations.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/hash.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/kdf.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/integer.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/logging.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/md5.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/memory.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/pkcs12.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/pkcs7.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/poly1305.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/pwdbased.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/rc2.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/sakke.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/signature.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/srp.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/sp_arm32.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/sp_arm64.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/sp_armthumb.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/sp_c32.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/sp_c64.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/sp_cortexm.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/sp_dsp32.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/sp_int.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/sp_x86_64.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/tfm.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/wc_dsp.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/wc_encrypt.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/wc_pkcs11.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/wc_port.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/wolfevent.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/src/wolfmath.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o    wolfssl/wolfcrypt/benchmark/benchmark.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl/wolfcrypt/test/test.c.home.john.Documents.nuttxspace.apps.crypto.wolfssl.o wolfssl-examples/embedded/tls-client-server.c.home.john.DocumentsAR (add): libapps.a    mkfatfs.c.home.john.Documents.nuttxspace.apps.fsutils.mkfatfs.o configfat.c.home.john.Documents.nuttxspace.apps.fsutils.mkfatfs.o writefat.c.home.john.Documents.nuttxspace.apps.fsutils.mkfAR (add): libapps.a    netlib_ipv4addrconv.c.home.john.Documents.nuttxspace.apps.netutils.netlib.o netlib_ethaddrconv.c.home.john.Documents.nuttxspace.apps.netutils.netlib.o netlib_parsehttpurl.c.home.john.Documents.nuttxspace.apps.netutils.netlib.o netlib_setifstatus.c.home.john.Documents.nuttxspace.apps.netutils.netlib.o netlib_getifstatus.c.home.john.Documents.nuttxspace.apps.netutils.netlib.o netlib_parseurl.c.home.john.Documents.nuttxspace.apps.netutils.netlib.o netlib_setipv4addr.c.home.john.Documents.nuttxspace.apps.netutils.netlib.o netlib_getipv4addr.c.home.john.Documents.nuttxspace.apps.netutils.netlib.o netlib_setdripv4addr.c.home.john.Documents.nuttxspace.apps.netutils.netlib.o netlib_setipv4netmask.c.home.john.Documents.nuttxspace.apps.netutils.netlib.o netlib_getdripv4addr.c.home.john.Documents.nuttxspace.apps.netutils.netlib.o netlib_getipv4netmask.c.home.john.Documents.nuttxspace.apps.netutils.netlib.o netlib_ipv4adaptor.c.home.john.Documents.nuttxspace.apps.netutils.netlib.o netlib_getarp.c.home.john.Documents.nuttxspace.apps.netutils.netlib.o netlib_setarp.c.home.john.Documents.nuttxspace.apps.netutils.netlib.o netlib_delarp.c.home.john.Documents.nuttxspace.apps.netutils.netlib.o netlib_setipv4dnsaddr.c.home.john.Documents.nuttxspace.apps.netutils.netlib.o netlib_ipv4route.c.home.john.Documents.nuttxspace.apps.netutils.netlib.o netlib_ipv4router.c.home.john.Documents.nuttxspace.apps.netutils.netlib.o netlib_server.c.home.john.Documents.nuttxspace.apps.netutils.netlib.o netlib_listenon.c.home.john.Documents.nuttxspace.apps.netutils.netlib.o netlib_setmacaddr.c.home.john.Documents.nuttxspace.apps.netutils.netlib.o netlib_getmacaddr.c.home.john.AR (add): libapps.a    nsh_init.c.home.john.Documents.nuttxspace.apps.nshlib.o nsh_parse.c.home.john.Documents.nuttxspace.apps.nshlib.o nsh_console.c.home.john.Documents.nuttxspace.apps.nshlib.o nsh_script.c.home.john.Documents.nuttxspace.apps.nshlib.o nsh_system.c.home.john.Documents.nuttxspace.apps.nshlib.o nsh_command.c.home.john.Documents.nuttxspace.apps.nshlib.o nsh_fscmds.c.home.john.Documents.nuttxspace.apps.nshlib.o nsh_ddcmd.c.home.john.Documents.nuttxspace.apps.nshlib.o nsh_proccmds.c.home.john.Documents.nuttxspace.apps.nshlib.o nsh_mmcmds.c.home.john.Documents.nuttxspace.apps.nshlib.o nsh_timcmds.c.home.john.Documents.nuttxspace.apps.nshlib.o nsh_envcmds.c.home.john.Documents.nuttxspace.apps.nshlib.o nsh_syscmds.c.home.john.Documents.nuttxspace.apps.nshlib.o nsh_dbgcmds.c.home.john.Documents.nuttxspace.apps.nshlib.o nsh_session.c.home.john.Documents.nuttxspace.apps.nshlib.o nsh_fsutils.c.home.john.Documents.nuttxspace.apps.nshlib.o nsh_builtin.c.home.john.Documents.nuttxspace.apps.nshlib.o nsh_netcmds.c.home.john.Documents.nuttxspace.apps.nshlib.o nsh_routecmds.c.home.john.Documents.nuttxspace.apps.nshlib.o nsh_mntcmds.c.home.john.Documents.nuttxspace.apps.nshlib.o nsh_consolemain.c.home.john.Documents.nuttxspace.apps.nshlib.o nsh_prinAR (add): libapps.a    readline.c.home.john.Documents.nuttxspace.apps.system.readline.o readline_fd.c.home.john.Documents.nuttxspace.apps.system.readline.o readline_common.c.home.john.Documents.nuttxspace.apps.sCC:  inet/ipv4_setsockopt.c /home/john/Documents/nuttxspace/nuttx/net/inet/ipv4_setsockopt.c: In function 'ipv4_setsockopt':
/home/john/Documents/nuttxspace/nuttx/net/inet/ipv4_setsockopt.c:229:2: warning: #warning Missing logic [-Wcpp]
  229 | #warning Missing logic
      |  ^~~~~~~
LD: nuttx
CP: nuttx.hex
CP: nuttx.bin
    ```
10) Flash the target
    ### Simulator
      ./nuttx
    ### STM32 Targets (address may vary)
      STM32_Programmer_CLI -c port=swd -d ./nuttx.bin 0x08000000
11) Connect to the target with a serial monitoring tool, the device on linux is usually /dev/ttyACM0 but it may vary
    - minicom -D /dev/ttyACM0
12) Run the wolfcrypt benchmark and/or test in the NuttX Shell:
    ```
    nsh> wolfcrypt_test
    nsh> wolfcrypt_benchmark
    nsh> wolfssl_client_server
    ```
## Notes
- Developed using the following targets:
    - STM NUCLEO-L552ZE-Q (Cortex-M33)
    - STM NUCLEO-H753ZI
    - STM NUCLEO-F756ZG
    - DT-BL10 / BL602 (RISC-V)
    - NuttX simulator
