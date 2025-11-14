# Cavium Nitrox V Support

## Directory Structure:
`/`
    `/CNN55XX-SDK`
    `/wolfssl`

## Building Cavium Driver

Tested using `CNN55XX-Driver-Linux-KVM-XEN-PF-SDK-1.4.14.tar`

### Installation

```sh
$ cd CN55XX-SDK
$ make clean
$ make
$ cd bin
$ sudo perl ./init_nitrox.pl

NITROX-V devices found: 1
NITROX-V driver(nitrox_drv.ko) load: SUCCESS
NITROX-V Device-0 part:  CNN5560-900BG676-C45-G

Reading config file: ../microcode/ssl.conf
Device count: 1  Config file device count: 2

 NITROX Model: 0x1200 [ CNN55XX PASS 1.0 ]

 Microcode Details:
    Version : CNN5x-MC-AE-MAIN-0001
    Core Count : 80
    Code length : 9514
    Block number: 0

 Microcode Details:
    Version : CNN5x-MC-SE-SSL-0004
    Core Count : 64
    Code length : 23738
    Block number: 1

 Microcode Load Succeed on device: 0

 [ AE ] Microcode: CNN5x-MC-AE-MAIN-0001
    Group : 0
    Core Mask [Hi Low]: ffff ffffffffffffffff [ 80 ]

 [ SE ] Microcode: CNN5x-MC-SE-SSL-0004
    Group : 0
    Core Mask : ffffffffffffffff [ 64 ]

Microcode Load success
```

```sh
$ lspci | grep Cavium
09:00.0 Network and computing encryption device: Cavium, Inc. Nitrox XL NPX (rev 01)
81:00.0 Network and computing encryption device: Cavium, Inc. Device 0012
```

#### Issues

1. Fixes to Nitrox Driver for includes into wolfSSL

a. Modify `include/vf_defs.h:120` -> `vf_config_mode_str()` function to:

```c
static inline const char *vf_config_mode_str(vf_config_type_t vf_mode)
{
    const char *vf_mode_str;
```

b. Add `case PF:` to `include/vf_defs.h:82` above `default:` in `vf_config_mode_to_num_vfs()`.

c. In `include/linux/sysdep.h:46` rename `__BYTED_ORDER` to `__BYTE_ORDER`.


2. If the CNN55XX driver is not extracted on the Linux box it can cause issues with the symbolic links in the microcode folder. Fix was to resolve the symbolic links in `./microcode`.

```sh
NITROX Model: 0x1200 [ CNN55XX PASS 1.0 ]
Invalid microcode
ucode_dload: failed to initialize
```

Resolve Links:
```sh
cd microcode
rm main_asym.out
ln -s ./build/main_ae.out ./main_asym.out
rm main_ipsec.out
ln -s ./build/main_ipsec.out ./main_ipsec.out
rm main_ssl.out
ls -s ./build/main_ssl.out ./main_ssl.out
```


## Building wolfSSL

```sh
./configure --with-cavium-v=../CNN55XX-SDK --enable-asynccrypt --enable-aesni --enable-intelasm
make
sudo make install
```

### CFLAGS

`CFLAGS+= -DHAVE_CAVIUM -DHAVE_CAVIUM_V -DWOLFSSL_ASYNC_CRYPT -DHAVE_WOLF_EVENT -DHAVE_WOLF_BIGINT`
`CFLAGS+= -I../CNN55XX-SDK/include -lrt -lcrypto`

* `HAVE_CAVIUM`: The Cavium define
* `HAVE_CAVIUM_V`: Nitrox V
* `WOLFSSL_ASYNC_CRYPT`: Enable asynchronous wolfCrypt.
* `HAVE_WOLF_EVENT`: Enable wolf event support (required for async)
* `HAVE_WOLF_BIGINT`: Enable wolf big integer support (required for async)


### LDFLAGS

Include the libnitrox static library:
`LDFLAGS+= ../CNN55XX-SDK/lib/libnitrox.a`


### wolfSSL Build Issues

a. If building with debug `-g` and using an older binutils LD version 2.23 or less you may see a linker crash. Example of error: `BFD (GNU Binutils) 2.23.2 internal error, aborting at merge.c line 873 in _bfd_merged_section_offset`. Resolution is to use this in the CFLAGS `-g -fno-merge-debug-strings -fdebug-types-section`.


## Usage

Note: Must run applications with `sudo` to access device.

```
sudo ./wolfcrypt/benchmark/benchmark
sudo ./wolfcrypt/test/testwolfcrypt
```


## TLS Code Template

```c
/* GLOBAL DEVICE IDENTIFIER */
#ifdef WOLFSSL_ASYNC_CRYPT
    static int devId = INVALID_DEVID;
#endif


/* DONE AT INIT */
#ifdef WOLFSSL_ASYNC_CRYPT
    if (wolfAsync_DevOpen(&devId) != 0) {
        fprintf(stderr, "Async device open failed\nRunning without async\n");
    }

    wolfSSL_CTX_UseAsync(ctx, devId);
#endif

/* DONE IN YOUR WORKER LOOP IN WC_PENDING_E CASES AGAINST YOUR WOLFSSL_CTX */
#ifdef WOLFSSL_ASYNC_CRYPT
    int ret;
    WOLF_EVENT* wolfEvents[MAX_WOLF_EVENTS];
    int eventCount, i;

    /* get list of events that are done (not pending) */
    ret = wolfSSL_CTX_AsyncPoll(ctx, wolfEvents, MAX_WOLF_EVENTS, WOLF_POLL_FLAG_CHECK_HW, &eventCount);
    if (ret != 0)
        goto error;

    for (i = 0; i < eventCount; i++) {
        WOLFSSL* ssl = (WOLFSSL*)wolfEvents[i]->context;
        if (ssl) {
            /* your SSL object is ready to be called again */
        }
    }
#endif

/* DONE AT CLEANUP */
#ifdef WOLFSSL_ASYNC_CRYPT
    wolfAsync_DevClose(&devId);
#endif
```

## Benchmarks

Nitrox V: CNN5560-900-C45
Intel(R) Core(TM) i7-4790 CPU @ 3.60GHz
CentOS: Kernel 3.10.0-514.16.1.el7.x86_64
Single Thread

```
./configure --with-cavium-v=../CNN55XX-SDK --enable-asynccrypt --enable-aesni --enable-intelasm --enable-sp --enable-sp-asm CFLAGS="-DWC_NO_ASYNC_THREADING" && make

sudo ./wolfcrypt/benchmark/benchmark

wolfCrypt Benchmark (block bytes 1048576, min 1.0 sec each)
RNG             SW   135 MB took 1.012 seconds,  133.356 MB/s Cycles per byte =  25.69
RNG             HW    85 MB took 1.049 seconds,   81.039 MB/s Cycles per byte =  42.27
AES-128-CBC-enc SW   845 MB took 1.001 seconds,  844.293 MB/s Cycles per byte =   4.06
AES-128-CBC-dec SW  6060 MB took 1.001 seconds, 6055.102 MB/s Cycles per byte =   0.57
AES-192-CBC-enc SW   710 MB took 1.004 seconds,  707.248 MB/s Cycles per byte =   4.84
AES-192-CBC-dec SW  5055 MB took 1.001 seconds, 5050.086 MB/s Cycles per byte =   0.68
AES-256-CBC-enc SW   610 MB took 1.003 seconds,  608.296 MB/s Cycles per byte =   5.63
AES-256-CBC-dec SW  4330 MB took 1.001 seconds, 4326.604 MB/s Cycles per byte =   0.79
AES-128-CBC-enc HW   240 MB took 1.018 seconds,  235.801 MB/s Cycles per byte =  14.53
AES-128-CBC-dec HW   240 MB took 1.011 seconds,  237.312 MB/s Cycles per byte =  14.43
AES-192-CBC-enc HW   220 MB took 1.021 seconds,  215.411 MB/s Cycles per byte =  15.90
AES-192-CBC-dec HW   215 MB took 1.002 seconds,  214.516 MB/s Cycles per byte =  15.97
AES-256-CBC-enc HW   200 MB took 1.016 seconds,  196.910 MB/s Cycles per byte =  17.40
AES-256-CBC-dec HW   200 MB took 1.016 seconds,  196.758 MB/s Cycles per byte =  17.41
AES-128-GCM-enc SW  3095 MB took 1.000 seconds, 3093.571 MB/s Cycles per byte =   1.11
AES-128-GCM-dec SW  3090 MB took 1.001 seconds, 3087.702 MB/s Cycles per byte =   1.11
AES-192-GCM-enc SW  2825 MB took 1.002 seconds, 2820.654 MB/s Cycles per byte =   1.21
AES-192-GCM-dec SW  2815 MB took 1.000 seconds, 2814.153 MB/s Cycles per byte =   1.22
AES-256-GCM-enc SW  2550 MB took 1.001 seconds, 2548.379 MB/s Cycles per byte =   1.34
AES-256-GCM-dec SW  2555 MB took 1.002 seconds, 2550.183 MB/s Cycles per byte =   1.34
AES-128-GCM-enc HW   135 MB took 1.018 seconds,  132.618 MB/s Cycles per byte =  25.83
AES-128-GCM-dec HW   130 MB took 1.022 seconds,  127.202 MB/s Cycles per byte =  26.93
AES-192-GCM-enc HW   135 MB took 1.019 seconds,  132.435 MB/s Cycles per byte =  25.86
AES-192-GCM-dec HW   130 MB took 1.025 seconds,  126.789 MB/s Cycles per byte =  27.02
AES-256-GCM-enc HW   135 MB took 1.019 seconds,  132.418 MB/s Cycles per byte =  25.87
AES-256-GCM-dec HW   130 MB took 1.023 seconds,  127.071 MB/s Cycles per byte =  26.96
CHACHA          SW  3245 MB took 1.001 seconds, 3241.680 MB/s Cycles per byte =   1.06
CHA-POLY        SW  1930 MB took 1.000 seconds, 1929.817 MB/s Cycles per byte =   1.77
MD5             SW   710 MB took 1.005 seconds,  706.678 MB/s Cycles per byte =   4.85
POLY1305        SW  4850 MB took 1.000 seconds, 4849.127 MB/s Cycles per byte =   0.71
SHA             SW   560 MB took 1.008 seconds,  555.558 MB/s Cycles per byte =   6.17
SHA-224         SW   460 MB took 1.002 seconds,  459.021 MB/s Cycles per byte =   7.46
SHA-256         SW   460 MB took 1.002 seconds,  459.013 MB/s Cycles per byte =   7.46
SHA-384         SW   690 MB took 1.002 seconds,  688.368 MB/s Cycles per byte =   4.98
SHA-512         SW   690 MB took 1.002 seconds,  688.414 MB/s Cycles per byte =   4.98
SHA3-224        SW   330 MB took 1.007 seconds,  327.713 MB/s Cycles per byte =  10.45
SHA3-256        SW   310 MB took 1.000 seconds,  309.909 MB/s Cycles per byte =  11.05
SHA3-384        SW   235 MB took 1.007 seconds,  233.355 MB/s Cycles per byte =  14.68
SHA3-512        SW   170 MB took 1.027 seconds,  165.547 MB/s Cycles per byte =  20.69
HMAC-MD5        SW   705 MB took 1.002 seconds,  703.344 MB/s Cycles per byte =   4.87
HMAC-MD5        HW 62670 MB took 1.000 seconds,62666.115 MB/s Cycles per byte =   0.05
HMAC-SHA        SW   555 MB took 1.000 seconds,  554.964 MB/s Cycles per byte =   6.17
HMAC-SHA        HW 62745 MB took 1.000 seconds,62744.312 MB/s Cycles per byte =   0.05
HMAC-SHA224     SW   475 MB took 1.005 seconds,  472.870 MB/s Cycles per byte =   7.24
HMAC-SHA224     HW 62415 MB took 1.000 seconds,62412.262 MB/s Cycles per byte =   0.05
HMAC-SHA256     SW   475 MB took 1.005 seconds,  472.710 MB/s Cycles per byte =   7.25
HMAC-SHA256     HW 63185 MB took 1.000 seconds,63180.255 MB/s Cycles per byte =   0.05
HMAC-SHA384     SW   690 MB took 1.005 seconds,  686.794 MB/s Cycles per byte =   4.99
HMAC-SHA384     HW 62575 MB took 1.000 seconds,62573.195 MB/s Cycles per byte =   0.05
HMAC-SHA512     SW   690 MB took 1.004 seconds,  687.563 MB/s Cycles per byte =   4.98
HMAC-SHA512     HW 62430 MB took 1.000 seconds,62428.497 MB/s Cycles per byte =   0.05
RSA     2048 public    SW   3900 ops took 1.026 sec, avg 0.263 ms, 3801.211 ops/sec
RSA     2048 private   SW    300 ops took 1.035 sec, avg 3.452 ms, 289.722 ops/sec
RSA     2048 public    HW 140900 ops took 1.001 sec, avg 0.007 ms, 140825.228 ops/sec
RSA     2048 private   HW   8300 ops took 1.004 sec, avg 0.121 ms, 8267.789 ops/sec
DH      2048 key gen   SW   1010 ops took 1.004 sec, avg 0.994 ms, 1005.939 ops/sec
DH      2048 agree     SW   1000 ops took 1.005 sec, avg 1.005 ms, 995.404 ops/sec
ECC      256 key gen   SW   1090 ops took 1.001 sec, avg 0.918 ms, 1089.153 ops/sec
ECDHE    256 agree     SW   1400 ops took 1.038 sec, avg 0.742 ms, 1348.211 ops/sec
ECDSA    256 sign      SW   1400 ops took 1.076 sec, avg 0.769 ms, 1300.595 ops/sec
ECDSA    256 verify    SW   1900 ops took 1.016 sec, avg 0.535 ms, 1870.353 ops/sec
ECDHE    256 agree     HW  10500 ops took 1.001 sec, avg 0.095 ms, 10485.383 ops/sec
ECDSA    256 sign      HW  22200 ops took 1.001 sec, avg 0.045 ms, 22169.233 ops/sec
ECDSA    256 verify    HW   7500 ops took 1.012 sec, avg 0.135 ms, 7408.213 ops/sec
```


## Support

For questions or issues email us at support@wolfssl.com.
