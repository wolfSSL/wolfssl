# SiFive HiFive Unleashed

Instructions for cross-compiling and running wolfSSL on the HiFive Unleashed board.

## Board SiFive HiFive Unleashed Board

SiFive Freedom U540 SoC at 1.5GHz

Getting started guide: 
https://sifive.cdn.prismic.io/sifive%2Ffa3a584a-a02f-4fda-b758-a2def05f49f9_hifive-unleashed-getting-started-guide-v1p1.pdf

Make sure your ethernet is attached and power up board. You can connecct the micro-usb to get a UART console that will display the DHCP IP address. Default login password is "sifive".

## Building Freedom-U-SDK

```sh
git clone https://github.com/sifive/freedom-u-sdk.git
cd freedom-u-sdk
git submodule update --recursive --init
make
```

See `freedom-u-sdk/README.md` file for instructions on updating the SD card U-Boot and Linux image.

Here is a summary of the steps:

Insert SD card from Unleashed into host and determine the assigned character sequence (X) for the media.

From `freedom-u-sdk` directory:

```sh
sudo make DISK=/dev/sdX format-boot-loader

# Copy U-Boot .fit image to first FAT partition (32MB)
sudo mkdir /media/hifiveu_boot
sudo mount -t vfat /dev/sdX1 /media/hifiveu_boot
cp ./work/image-<GITID>.fit /media/hifiveu_boot/hifiveu.fit
sudo umount /media/hifiveu_boot

# Copy Linux FS
sudo dd if=./work/hifive-unleashed-<ID>.gpt of=/dev/sdX2 bs=1M
```

Note: Make sure S1 Switch 5 (MSEL2) is OFF, rest ON (MSEL=1011) to boot from SD


## Building wolfSSL

This example assumes the `wolfssl` root directory is along side the `freedom-u-sdk` directory. If not then adjust paths.

```
~\
	wolfssl
	freedom-u-sdk
```

```sh
./configure --host=riscv64 \
	CC="`pwd`/../freedom-u-sdk/work/buildroot_initramfs/host/bin/riscv64-sifive-linux-gnu-gcc" \
	--with-sysroot="`pwd`/../freedom-u-sdk/work/buildroot_initramfs_sysroot/" \
	--disable-shared \
	--enable-sp \
	CFLAGS="-mabi=lp64d -march=rv64imafdc"
make
```

Copy files to device (replace IP address):

```sh
scp ./wolfcrypt/test/testwolfcrypt root@192.168.0.144:~
scp ./wolfcrypt/benchmark/benchmark root@192.168.0.144:~
scp ./examples/client/client root@192.168.0.144:~
scp ./examples/server/server root@192.168.0.144:~

# manually `mkdir certs` on target
scp ./certs/* root@192.168.0.144:~/certs
```

## Benchmark Results

```sh
# ./benchmark
------------------------------------------------------------------------------
 wolfSSL version 4.1.0
------------------------------------------------------------------------------
wolfCrypt Benchmark (block bytes 1048576, min 1.0 sec each)
RNG                 10 MB took 1.709 seconds,    5.853 MB/s
AES-128-CBC-enc      5 MB took 1.578 seconds,    3.168 MB/s
AES-128-CBC-dec     10 MB took 1.330 seconds,    7.521 MB/s
AES-192-CBC-enc      5 MB took 1.739 seconds,    2.875 MB/s
AES-192-CBC-dec     10 MB took 1.485 seconds,    6.736 MB/s
AES-256-CBC-enc      5 MB took 1.869 seconds,    2.675 MB/s
AES-256-CBC-dec     10 MB took 1.636 seconds,    6.114 MB/s
AES-128-GCM-enc      5 MB took 2.328 seconds,    2.147 MB/s
AES-128-GCM-dec      5 MB took 2.210 seconds,    2.263 MB/s
AES-192-GCM-enc      5 MB took 2.592 seconds,    1.929 MB/s
AES-192-GCM-dec      5 MB took 2.369 seconds,    2.110 MB/s
AES-256-GCM-enc      5 MB took 2.633 seconds,    1.899 MB/s
AES-256-GCM-dec      5 MB took 2.607 seconds,    1.918 MB/s
CHACHA              15 MB took 1.013 seconds,   14.808 MB/s
CHA-POLY            15 MB took 1.286 seconds,   11.666 MB/s
MD5                 55 MB took 1.026 seconds,   53.628 MB/s
POLY1305            60 MB took 1.090 seconds,   55.024 MB/s
SHA                 30 MB took 1.121 seconds,   26.763 MB/s
SHA-256             15 MB took 1.134 seconds,   13.226 MB/s
SHA-384             20 MB took 1.270 seconds,   15.743 MB/s
SHA-512             20 MB took 1.270 seconds,   15.744 MB/s
HMAC-MD5            55 MB took 1.025 seconds,   53.635 MB/s
HMAC-SHA            30 MB took 1.120 seconds,   26.783 MB/s
HMAC-SHA256         15 MB took 1.135 seconds,   13.217 MB/s
HMAC-SHA384         20 MB took 1.270 seconds,   15.743 MB/s
HMAC-SHA512         20 MB took 1.271 seconds,   15.741 MB/s
RSA     2048 public       1400 ops took 1.077 sec, avg 0.769 ms, 1300.132 ops/sec
RSA     2048 private       100 ops took 2.562 sec, avg 25.615 ms, 39.040 ops/sec
DH      2048 key gen        91 ops took 1.007 sec, avg 11.063 ms, 90.394 ops/sec
DH      2048 agree         100 ops took 1.122 sec, avg 11.224 ms, 89.097 ops/sec
ECC      256 key gen       892 ops took 1.001 sec, avg 1.122 ms, 891.293 ops/sec
ECDHE    256 agree         300 ops took 1.392 sec, avg 4.640 ms, 215.516 ops/sec
ECDSA    256 sign          700 ops took 1.089 sec, avg 1.556 ms, 642.730 ops/sec
ECDSA    256 verify        200 ops took 1.102 sec, avg 5.508 ms, 181.568 ops/sec
Benchmark complete
```

## Support

For questions please email us at support@wolfssl.com.
