# wolfSSL library for the Vitis Unified IDE (SDT flow)

Packages wolfSSL as an embedded software library for the Vitis Unified
IDE (2023.2 and later, system device tree flow). Once the repository is
added, wolfssl appears as a library checkbox in a standalone domain's
BSP settings.

## Adding wolfSSL to a Vitis application

1. Add `<wolfssl>/IDE/XilinxSDK/vitis_sdt` as an embedded software
   repository (Vitis > Embedded SW Repositories). Do this before
   creating the platform.

2. Open your platform, pick a standalone domain, open its BSP settings
   > Libraries, and enable wolfssl.

3. Build the platform. The first build creates a starter
   `user_settings.h` at `<platform>/<domain>/bsp/user_settings.h`, next
   to `bsp.yaml`. Edit that file to configure wolfSSL, then rebuild the
   platform; it is never overwritten. All wolfSSL feature choices
   happen in this one file.

4. Create the application: File > New Component > Application, same
   platform and domain. It links the library on its own. Include
   headers as usual:

   ```c
   #include <wolfssl/wolfcrypt/settings.h>
   #include <wolfssl/wolfcrypt/sha256.h>
   ```

5. Build and run. Give the application a large heap in `lscript.ld`
   (8 MB or more for the wolfCrypt self-test).

## Library options (BSP settings GUI)

- `wolfssl_user_settings_path` (default empty). Absolute path to your
  `user_settings.h`. Leave empty to use the one in the domain's BSP
  directory.
- `wolfssl_source_path` (default empty). Path to the wolfSSL checkout.
  Leave empty for auto-detect.
