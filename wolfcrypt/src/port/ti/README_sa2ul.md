# wolfSSL TI SA2UL Hardware Acceleration Port

wolfSSL supports hardware acceleration on the TI AM6442 via the SA2UL peripheral.

## SA2UL on the TI AM6442

The TI AM6442 is a multi-core SoC, with one dual-core Cortex-A53, two dual-core Cortex-R5F,
a Cortex-M4F, and a dedicated security core based on a Cortex-M3. This support has been
tested on the TMDS64EVM board (rev 101D).

Basic hardware acceleration supported:
- TRNG (NRBG and CTR-DRBG SP800-90A)
- AES-ECB (128, 256)
- AES-CBC (128, 256)
- AES-GCM (128, 256)
- SHA256, SHA512
- HMAC-SHA256, HMAC-SHA512
- CMAC-AES (128, 256)

Note: The wolfCrypt sa2ul support depends on the TI MCU Plus SDK.  wolfBoot has
an example (ti-am64x.config) of how to compile with the MCU Plus SDK.

### wolfSSL TI AM64x Hardware Acceleration Switches

To enable all the above, with TRNG in NRBG mode, set the following build switch:

**`WOLFSSL_TI_AM64X`**

To change the TRNG to CTR-DRBG mode, then also set this switch:

**`WOLFSSL_TI_AM64X_RNG_CTR_DRBG`**

In addition, parts of the hardware acceleration can be disabled (in favor of
wolfCrypt software algorithms), with the following switches:

**`WOLFSSL_TI_AM64X_NO_AES`**

**`WOLFSSL_TI_AM64X_NO_SHA`**

## Support

For questions please email support@wolfssl.com

