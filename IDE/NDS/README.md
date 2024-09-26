# wolfSSL for libnds

## Requirements

[Devkitpro](https://devkitpro.org/wiki/Getting_Started) with libnds.


## Building

```
$ ./configure \
    --host=arm-none-eabi \
    CC=$DEVKITARM/bin/arm-none-eabi-g++ \
    AR=$DEVKITARM/bin/arm-none-eabi-ar \
    STRIP=$DEVKITARM/bin/arm-none-eabi-strip \
    RANLIB=$DEVKITARM/bin/arm-none-eabi-ranlib \
    LIBS="-lfat -lnds9" \
    LDFLAGS="-L/opt/devkitpro/libnds/lib" \
    --prefix=$DEVKITPRO/portlibs/nds \
    CFLAGS="-march=armv5te -mtune=arm946e-s \
        --specs=ds_arm9.specs -DARM9 -DWOLFSSL_NDS \
        -DWOLFSSL_USER_IO \
        -I$DEVKITPRO/libnds/include" \
    --enable-fastmath --disable-benchmark \
    --disable-shared --disable-examples --disable-ecc
$ make
$ sudo make install
```

## Run the Tests

To run the Crypttests type the following.
1. Run `$ ndstool -9 ./wolfcrypt/test/testwolfcrypt  -c ./wolfcrypt/test/testwolfcrypt.nds`
2. copy `./certs` to `your_nds_sd_card/_nds/certs`

3. Run the Rom (located in ./wolfcrypt/test/testwolfcrypt.nds) in an Emulator or real Hardware.
