# WISeKey / SealSQ VaultIC Port

This port offloads ECC P-256 operations to a WISeKey/SealSQ VaultIC secure
element (for example the VaultIC 408 on the DEVKIT_VIC408). The private key
never leaves the chip.

It exposes the device through two mechanisms, which can be used independently
or together:

* **TLS PK callbacks** - route the ECC operations of a TLS handshake
  (`WOLFSSL_CTX` / `WOLFSSL`) to the device via wolfSSL's public-key (PK)
  callback framework.
* **wolfCrypt crypto callback (devId)** - route wolfCrypt ECC operations (not
  just the TLS handshake) to the device via the `WOLF_CRYPTO_CB` / devId
  framework, so bare `wc_ecc_*` calls and a whole `WOLFSSL_CTX` can be pointed
  at the chip with a single devId.

Both share the same underlying VaultIC-TLS SDK entry points; see "Usage" for
which one to pick.

## What it does

`wolfcrypt/src/port/sealsq/vaultic.c` provides:

ECC operations on the device (used by both mechanisms):

* `WOLFSSL_VAULTIC_EccSignCb` - ECDSA P-256 sign on the device
* `WOLFSSL_VAULTIC_EccVerifyCb` - ECDSA P-256 verify on the device
* `WOLFSSL_VAULTIC_EccKeyGenCb` - ephemeral P-256 key generation on the device
* `WOLFSSL_VAULTIC_EccSharedSecretCb` - ECDH P-256 shared secret on the device

TLS PK callback registration:

* `WOLFSSL_VAULTIC_SetupPkCallbacks` / `WOLFSSL_VAULTIC_SetupPkCallbackCtx` -
  register the PK callbacks on a `WOLFSSL_CTX` / `WOLFSSL`

Crypto callback (devId) registration:

* `WOLFSSL_VAULTIC_RegisterCryptoCb` - register the VaultIC crypto callback
  under a devId (`WOLF_VAULTIC_DEVID`)

Certificate helper:

* `WOLFSSL_VAULTIC_LoadCertificates` - read the device and CA certificates
  stored on the chip into a `WOLFSSL_CTX`

The key-generation and shared-secret (ECDH) callbacks can be compiled out by
defining `VLT_TLS_NO_ECDH`, matching the vendor library configuration.

## Dependencies

This port is glue only. It requires the external SealSQ **VaultIC-TLS SDK**,
which provides `vaultic_tls.h` and the `vlt_tls_*` P-256 API that talks to the
chip. That SDK is distributed by SealSQ and is not part of wolfSSL.

## Building

Enable the port and point the compiler/linker at the vendor SDK:

```sh
./configure --enable-vaultic \
    CFLAGS="-I/path/to/VaultIC-TLS/vaultic_tls-4xx/src" \
    LIBS="-lvaultic_tls_408"
make
```

`--enable-vaultic` defines `WOLFSSL_VAULTIC` and automatically enables both PK
callbacks (`HAVE_PK_CALLBACKS`) and crypto callbacks (`WOLF_CRYPTO_CB`), so
either mechanism is available out of the box. The port compiles to nothing when
`WOLFSSL_VAULTIC` is not defined.

### Building the port outside libwolfssl

Like other wolfSSL port files, `vaultic.c` is meant to be compiled as part of
libwolfssl (via `--enable-vaultic`), where it inherits the wolfSSL
configuration through `config.h`. If instead you compile `vaultic.c` in a
separate target (for example the SealSQ devkit builds it into its own
`vaultic_wolfssl` library alongside an `add_subdirectory(wolfssl)` CMake
build), two things are required so the file sees the wolfSSL configuration:

* Make the file see the wolfSSL configuration. For an autotools build define
  `WOLFSSL_USE_OPTIONS_H`, so `settings.h` pulls in the generated
  `wolfssl/options.h`. For a build that does not use `./configure` (so there is
  no generated `options.h`), define `WOLFSSL_USER_SETTINGS` instead and provide
  a `user_settings.h` that lists all the build options. Without one of these the
  wolfSSL headers fall back to defaults (`ecc_key` is incomplete,
  `ECC_SECP256R1` is undeclared).
* Enable PK callbacks through the wolfSSL build option
  (autotools `--enable-pkcallbacks`, CMake `WOLFSSL_PKCALLBACKS=yes`), not a
  bare `-DHAVE_PK_CALLBACKS` compile flag. The generated `options.h` contains
  `#undef HAVE_PK_CALLBACKS` for disabled options, which cancels a
  command-line define once `options.h` is included.

## Usage

The port offers two ways to route ECC to the chip (see the overview at the
top). Use the PK callbacks when you only need the TLS handshake offloaded and
want per-`WOLFSSL` control; use the crypto callback (devId) when you want all
wolfCrypt ECC - including bare `wc_ecc_*` calls - routed to the device, or
prefer a single devId on the `WOLFSSL_CTX`.

### TLS PK callbacks

```c
WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfTLS_client_method());

/* register the VaultIC ECC PK callbacks */
WOLFSSL_VAULTIC_SetupPkCallbacks(ctx);

/* load the device + CA certificates stored on the chip */
WOLFSSL_VAULTIC_LoadCertificates(ctx);

WOLFSSL* ssl = wolfSSL_new(ctx);
WOLFSSL_VAULTIC_SetupPkCallbackCtx(ssl, NULL);
/* ... proceed with the TLS handshake ... */
```

### Crypto callback (devId)

The crypto callback dispatches wolfCrypt ECC operations (not just the TLS
handshake) to the VaultIC through the `WOLF_CRYPTO_CB` / devId framework.
Register the device once, then select it with a devId:

```c
/* register the VaultIC crypto callback under a devId */
WOLFSSL_VAULTIC_RegisterCryptoCb(WOLF_VAULTIC_DEVID);

/* TLS: route this CTX's crypto to the device */
wolfSSL_CTX_SetDevId(ctx, WOLF_VAULTIC_DEVID);

/* or bare wolfCrypt: init a key against the device */
wc_ecc_init_ex(&key, NULL, WOLF_VAULTIC_DEVID);
```

The VaultIC-TLS SDK must be initialized (`vlt_tls_init()`) before use and
closed (`vlt_tls_close()`) afterwards; see the SealSQ devkit sample
applications.

### Curve support

The port offloads P-256 (SECP256R1) only. The VaultIC 408 silicon supports
P-384, but the vendor `vlt_tls` API exposes P-256 entry points only, so
P-384 would require vendor `vlt_tls_*_P384` functions. For any other curve
the crypto callback returns `CRYPTOCB_UNAVAILABLE` and the PK callbacks
return `NOT_COMPILED_IN`, so wolfSSL falls back to software.

## Building and provisioning with the SealSQ devkit

The SealSQ VaultIC-TLS devkit (for example `DEVKIT_VIC408_TLS_RPI`) drives the
whole build/provision/run flow with shell scripts. High-level orientation and
the files that matter:

* SDK library: `VaultIC-TLS/vaultic_tls/vaultic_tls-4xx/src` (`vaultic_tls.h`
  API, `vaultic_tls_config.h`), on top of the low-level chip library
  `vaultic_tls/vaultic_elib_408` (its Raspberry Pi I2C/SPI drivers live under
  `src/arch/embedded/raspberry/pi3`, e.g. `vaultic_twi_driver.c`).
* Glue build: `vaultic_tls/vaultic_wolfssl/CMakeLists.txt` compiles this
  port's `vaultic.c` and links it against `wolfssl` and `vaultic_tls_408`.
* Config: `demos/config.cfg` selects `PRODUCT` (408), `VAULTIC_COMM`
  (`SPI` or `I2C`), and log level.
* Scripts: `demos/wolfssl/tls_client/scripts` - `install.sh` (set up the
  CMake build trees), `build.sh` (build the perso apps, the glue, and the
  demos), `perso_client_vaultic.sh` (provision the chip), `run_server.sh` and
  `run_client_vaultic.sh` (start the plain server, then the VaultIC client).

Steps:

1. Set `demos/config.cfg` (`PRODUCT=408`, `VAULTIC_COMM=I2C` or `SPI`), then
   run `install.sh` and `build.sh`. Point the glue at a wolfSSL tree that
   contains this port (the devkit's `wolfssl_patch` copy is no longer needed
   once the port is upstream). When the glue compiles `vaultic.c` in its own
   library, apply the two flags from "Building the port outside libwolfssl"
   above.
2. Provision the chip once with `perso_client_vaultic.sh`. It runs the
   `perso_tls` app (`vaultic_tls-4xx/apps/perso_tls`) with the device key,
   device cert, and root CA cert from `VaultIC-TLS/certificates`
   (`deviceKey.der`, `deviceCert.der`, `rootCACert.der`), submitting the
   manufacturer password supplied by your SealSQ FAE, then runs
   `check_tls_perso` (`vaultic_tls-4xx/apps/check_tls_perso`) to read the
   certificates back off the chip and confirm success.
3. Run `run_server.sh` in one shell and `run_client_vaultic.sh` in another to
   perform TLS 1.2 and TLS 1.3 handshakes whose ECC operations run on the
   VaultIC.

## Raspberry Pi I2C and clock stretching

This section is about the external VaultIC-TLS SDK's I2C transport on a
Raspberry Pi, not about the wolfSSL port itself, but it is the most common
thing that blocks bring-up, so it is documented here. The VaultIC is an I2C
(or SPI) secure element; when it is attached over I2C it stretches the clock
(holds SCL low) while it performs internal operations, and the Raspberry Pi
I2C hardware has long-standing trouble with clock-stretching peripherals.

Symptoms of the problem are `TWI Send/Receive failure` (status `CF0D`/`CF0F`),
`Block Protocol WARNING (comm error)` / `resync request` messages, and finally
`Block Protocol ERROR (too many rsync requests)`. Short exchanges (for example
reading a status) may succeed while longer, multi-block transfers (for example
the certificate writes done during personalization) fail.

### Raspberry Pi 2/3/4 (BCM I2C)

The classic workaround is to lower the I2C bus clock so the timing margins are
wide enough to tolerate the stretching. The VaultIC-TLS SDK's own I2C driver
tries to do this by writing the BCM I2C `DIV` register directly through
`/dev/mem` (which is why it wants to be run with `sudo`), using hardcoded
controller base addresses for the Pi 2/3 (`0x3f804000`) and Pi 4
(`0xfe804000`). A bus clock around 50 kHz is typically reliable.

### Raspberry Pi 5 (RP1 / DesignWare I2C) - use a bit-banged bus

The Pi 5 does not work with the SDK's built-in bitrate control: its I2C
controller lives in the RP1 chip (a DesignWare I2C controller behind
PCIe) at a different address, so the SDK's `/dev/mem` register poke targets a
controller that is not there and has no effect. Worse, the RP1 DesignWare
controller itself hangs on the VaultIC's clock stretching during longer
transfers, reporting `i2c_designware ...: SDA stuck at low` in `dmesg`.
Lowering `dtparam=i2c_arm_baudrate` (even down to 10 kHz) does not fix this,
because the failure is the controller mishandling the stretch, not a timing
margin.

The reliable fix on the Pi 5 is to drive the same SDA/SCL pins with the
kernel's software (bit-banged) I2C driver, which polls SCL and therefore
honours clock stretching correctly. In `/boot/firmware/config.txt`, disable
the hardware I2C on those pins and add a software bus on GPIO 2 (SDA) and
GPIO 3 (SCL):

```
# dtparam=i2c_arm=on
dtoverlay=i2c-gpio,i2c_gpio_sda=2,i2c_gpio_scl=3,i2c_gpio_delay_us=4
```

After rebooting, find the new bus (its `name` reads `i2c-gpio`, for example
`/dev/i2c-13`) and point the SDK's I2C device path at it (the VaultIC-TLS
elib hardcodes `/dev/i2c-1` in its Raspberry Pi TWI driver). With the
bit-banged bus, personalization and full TLS 1.2 / TLS 1.3 handshakes to the
VaultIC 408 complete with no I2C errors.

Alternatively, wiring the VaultIC over SPI avoids clock stretching entirely.
