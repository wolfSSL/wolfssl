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

### Installing U-Boot

Insert SD card from Unleashed into host and determine the assigned `/dev/sdX` for the media.

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

### Installing Debian

Insert SD card from Unleashed into host and determine the assigned character sequence (X) for the media.

From `freedom-u-sdk` directory:

```sh
sudo make DISK=/dev/sdX format-demo-image
```

## Building wolfSSL

Make sure you are using wolfSSL sources based on this PR https://github.com/wolfSSL/wolfssl/pull/2456
The PR 2456 includes a patch to `wolfssl/wolfcrypt/types.h` to detect 64-bit types based on the `__riscv_xlen` macro.

### Cross Compiling

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

### Native Compiler

```sh
./configure --enable-sp
make
```

## Benchmark Results

The following is running the wolfCrypt benchmark at 1.5GHz on a single thread (default CPU speed is 1.0GHz).

```sh
echo 1500000000 > /sys/devices/platform/soc/10000000.prci/rate

./benchmark
------------------------------------------------------------------------------
 wolfSSL version 4.1.0
------------------------------------------------------------------------------
wolfCrypt Benchmark (block bytes 1048576, min 1.0 sec each)
RNG                 10 MB took 1.165 seconds,    8.585 MB/s
AES-128-CBC-enc     15 MB took 1.346 seconds,   11.141 MB/s
AES-128-CBC-dec     15 MB took 1.380 seconds,   10.867 MB/s
AES-192-CBC-enc     10 MB took 1.002 seconds,    9.983 MB/s
AES-192-CBC-dec     10 MB took 1.020 seconds,    9.805 MB/s
AES-256-CBC-enc     10 MB took 1.100 seconds,    9.091 MB/s
AES-256-CBC-dec     10 MB took 1.117 seconds,    8.952 MB/s
AES-128-GCM-enc     10 MB took 1.809 seconds,    5.528 MB/s
AES-128-GCM-dec     10 MB took 1.810 seconds,    5.524 MB/s
AES-192-GCM-enc     10 MB took 1.911 seconds,    5.233 MB/s
AES-192-GCM-dec     10 MB took 1.911 seconds,    5.232 MB/s
AES-256-GCM-enc      5 MB took 1.013 seconds,    4.935 MB/s
AES-256-GCM-dec      5 MB took 1.014 seconds,    4.933 MB/s
CHACHA              25 MB took 1.181 seconds,   21.168 MB/s
CHA-POLY            20 MB took 1.188 seconds,   16.833 MB/s
MD5                 80 MB took 1.025 seconds,   78.066 MB/s
POLY1305            85 MB took 1.032 seconds,   82.357 MB/s
SHA                 40 MB took 1.033 seconds,   38.728 MB/s
SHA-256             20 MB took 1.023 seconds,   19.557 MB/s
SHA-384             25 MB took 1.059 seconds,   23.597 MB/s
SHA-512             25 MB took 1.059 seconds,   23.597 MB/s
HMAC-MD5            80 MB took 1.026 seconds,   77.950 MB/s
HMAC-SHA            40 MB took 1.034 seconds,   38.700 MB/s
HMAC-SHA256         20 MB took 1.023 seconds,   19.559 MB/s
HMAC-SHA384         25 MB took 1.059 seconds,   23.598 MB/s
HMAC-SHA512         25 MB took 1.059 seconds,   23.599 MB/s
RSA     2048 public       2000 ops took 1.032 sec, avg 0.516 ms, 1938.304 ops/sec
RSA     2048 private       100 ops took 1.713 sec, avg 17.132 ms, 58.370 ops/sec
DH      2048 key gen       133 ops took 1.003 sec, avg 7.544 ms, 132.552 ops/sec
DH      2048 agree         200 ops took 1.531 sec, avg 7.653 ms, 130.676 ops/sec
ECC      256 key gen      1330 ops took 1.001 sec, avg 0.752 ms, 1329.260 ops/sec
ECDHE    256 agree         400 ops took 1.243 sec, avg 3.107 ms, 321.830 ops/sec
ECDSA    256 sign         1000 ops took 1.043 sec, avg 1.043 ms, 958.539 ops/sec
ECDSA    256 verify        300 ops took 1.104 sec, avg 3.680 ms, 271.766 ops/sec
Benchmark complete
```

## Support

For questions please email us at support@wolfssl.com.
