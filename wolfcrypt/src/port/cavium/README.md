# Cavium Nitrox V Support

## Directory Structure:
`/`
    `/CNN55XX-SDK`
    `/wolfssl`

## Cavium Driver

Tested again `CNN55XX-Driver-Linux-KVM-XEN-PF-SDK-0.2-04.tar`
From inside `CNN55XX-SDK`:
1. `make`
    Note: To resolve warnings in `CNN55XX-SDK/include/vf_defs.h`:
    a. Changed `vf_config_mode_str` to return `const char*` and modify `vf_mode_str` to be `const char*`.
    b. In `vf_config_mode_to_num_vfs` above `default:` add `case PF:`.

2. `sudo make load`

## wolfSSL

Currently the AES and DES3 benchmark tests causes the kernel to crash, so they are disabled for now, even though the wolfCrypt tests pass for those.

From inside `wolfssl`:
1. `./configure --with-cavium-v=../CNN55XX-SDK --enable-asynccrypt --enable-aesni --enable-intelasm --disable-aes --disable-aesgcm --disable-des3`
2. `make`

## Usage

Note: Must run applications with sudo to access device.

`sudo ./wolfcrypt/benchmark/benchmark`
`sudo ./wolfcrypt/test/testwolfcrypt`
