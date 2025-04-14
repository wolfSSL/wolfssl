# wolfSSL for libnds

## Requirements

[Devkitpro](https://devkitpro.org/wiki/Getting_Started) with libnds, nds-tool and nds-dev.


## Building

For MelonDS
```
$ ./configure \
    --host=arm-none-eabi \
    CC=$DEVKITARM/bin/arm-none-eabi-g++ \
    AR=$DEVKITARM/bin/arm-none-eabi-ar \
    STRIP=$DEVKITARM/bin/arm-none-eabi-strip \
    RANLIB=$DEVKITARM/bin/arm-none-eabi-ranlib \
    LIBS="-lfat -lnds9 -lcalico_ds9" \
    LDFLAGS="-L$DEVKITPRO/libnds/lib \
        -L$DEVKITPRO/calico/lib" \
    --prefix=$DEVKITPRO/portlibs/nds \
    CFLAGS="-march=armv5te -mtune=arm946e-s \
        -specs=$DEVKITPRO/calico/share/ds9.specs \
        -D__NDS__ -DARM9 -D__thumb__=0 \
        -DWOLFSSL_MELONDS \
        -DWOLFSSL_NDS -DWOLFSSL_USER_IO \
        -I$DEVKITPRO/calico/include \
        -I$DEVKITPRO/libnds/include" \
    --enable-fastmath --disable-benchmark \
    --disable-shared --disable-examples --disable-ecc
$ make
$ sudo make install
```

For Hardware
```
$ ./configure \
    --host=arm-none-eabi \
    CC=$DEVKITARM/bin/arm-none-eabi-g++ \
    AR=$DEVKITARM/bin/arm-none-eabi-ar \
    STRIP=$DEVKITARM/bin/arm-none-eabi-strip \
    RANLIB=$DEVKITARM/bin/arm-none-eabi-ranlib \
    LIBS="-lfat -lnds9 -lcalico_ds9" \
    LDFLAGS="-L$DEVKITPRO/libnds/lib \
        -L$DEVKITPRO/calico/lib" \
    --prefix=$DEVKITPRO/portlibs/nds \
    CFLAGS="-march=armv5te -mtune=arm946e-s \
        -specs=$DEVKITPRO/calico/share/ds9.specs \
        -D__NDS__ -DARM9 -D__thumb__=0 \
        -DWOLFSSL_NDS -DWOLFSSL_USER_IO \
        -I$DEVKITPRO/calico/include \
        -I$DEVKITPRO/libnds/include" \
    --enable-fastmath --disable-benchmark \
    --disable-shared --disable-examples --disable-ecc
$ make
$ sudo make install
```

## Run the Tests

To run the Crypttests type the following.
Run `$ ndstool -9 ./wolfcrypt/test/testwolfcrypt  -c ./wolfcrypt/test/testwolfcrypt.nds`

copy `./certs` to `your_nds_sd_card/_nds/certs` (Follow Virtual SD card steps below for Emulator)

Run the Rom (located in ./wolfcrypt/test/testwolfcrypt.nds) in an Emulator or real Hardware.

If running on MelonDS it must be using the DSi mode in order to use certs from an SD card.

## Making a virtual SD card (MacOS)

```
Create Virtual SD card image

$ dd if=/dev/zero of=~/my_sd_card.img bs=1M count=64

Format image to FAT32

$ hdiutil attach -imagekey diskimage-class=CRawDiskImage -nomount ~/my_sd_card.img
$ diskutil eraseDisk FAT32 MYSDCARD MBRFormat /dev/diskX
$ hdiutil detach /dev/diskX

Mount to Create Folder Structure and Copy Certs

$ mkdir -p /Volumes/MYSDCARD/_nds
$ cp -r ~/wolfssl/certs /Volumes/MYSDCARD/_nds/

Unmount

hdiutil detach /dev/diskX
```

## Making a virtual SD card (Linux)

```
Create Virtual SD card image

$ dd if=/dev/zero of=~/my_sd_card.img bs=1M count=64

Format image to FAT32

$ sudo losetup -fP ~/my_sd_card.img
$ sudo losetup -l
$ sudo mkfs.vfat -F 32 /dev/loop0
$ sudo losetup -d /dev/loop0

Mount to Create Folder Structure and Copy Certs

$ sudo mount ~/my_sd_card.img /mnt
$ sudo mkdir -p /mnt/_nds
$ sudo cp -r ~/wolfssl/certs /mnt/_nds/

Unmount

hdiutil detach /dev/diskX
```
