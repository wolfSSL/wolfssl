# m33mu-falcon-verify

Minimal STM32H563 (Cortex-M33) bare-metal firmware that drives wolfCrypt's
native **Falcon-512 verify** path under `m33mu`, exercising the ARM DSP
acceleration (SMLAxx / SMUAD + packed-halfword SADD16/SSUB16/USUB16/SEL) that
auto-enables on cores with the DSP extension (`__ARM_FEATURE_DSP`).

The firmware imports the Falcon-512 KAT public key, verifies a genuine
signature (must be accepted) and a one-byte-tampered signature (must be
rejected). The NTT / iNTT / pointwise multiply / squared-norm all run through
the DSP path (`WOLFSSL_FALCON_NTT_DSP`, bit-identical to the scalar Barrett
path).

BKPT markers:
- `0x7f`: valid accepted **and** tampered rejected (success)
- `0x7c`: valid signature was rejected
- `0x7d`: tampered signature was accepted
- `0x71`: verify returned an operational error
- `0x70`: setup/init failure

Build (needs `arm-none-eabi-gcc` on PATH):
```sh
make -C IDE/m33mu-falcon-verify
```

Run:
```sh
m33mu --cpu stm32h563 --expect-bkpt 0x7f IDE/m33mu-falcon-verify/app-falcon.bin
```

Confirm the DSP instructions were actually compiled in:
```sh
make -C IDE/m33mu-falcon-verify symbols
grep -E '\b(smuad|smlabb|usub16|sel)\b' IDE/m33mu-falcon-verify/app-falcon.dis
```

`kat.h` holds the Falcon-512 KAT vectors (public key + signature) extracted from
`wolfcrypt/test/test.c`.
