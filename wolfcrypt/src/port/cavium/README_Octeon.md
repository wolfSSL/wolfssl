# Octeon III

Guide for setting up wolfSSL on the Octeon III CN7300

## Octeon SDK

```sh
sudo yum install libuuid-devel
sudo yum install perl-Env

sudo rpm -i OCTEON-SDK-5.1.0-609.x86_64.rpm
```

The OCTEON-SDK package has been successfully installed under the
/usr/local/Cavium_Networks directory.

The installation requires the OCTEON_MODEL environment variable
to be set. To set this environment variable, cd to the
/usr/local/Cavium_Networks/OCTEON-SDK directory, and invoke

	  source env-setup <OCTEON_MODEL>

script. Valid OCTEON_MODELs are listed in octeon-models.txt file
under OCTEON-SDK directory.

You may want to copy the OCTEON-SDK package to your home directory to allow
modification without root privileges.

For more information please refer to the online SDK documentation:
file:///usr/local/Cavium_Networks/OCTEON-SDK/docs/html/index.html

```sh
sudo rpm -i OCTEON-CRYPTO-CORE-5.1.0-01.x86_64.rpm
```

The OCTEON-CRYPTO-CORE is installed under
/usr/local/Cavium_Networks/OCTEON-SDK/components/crypto-api/core directory.
This package installs the following sources.
   * Crypto-Core API Sources
   * Sample Crypto-Core Test Applications

Please refer to following documentation under
/usr/local/Cavium_Networks/OCTEON-SDK/components/crypto-api/core directory
   * README.txt        - contains build instructions and other details
   * Release_Notes.txt - contains change history

```sh
sudo rpm -i OCTEON-LINUX-5.1.0-609.x86_64.rpm
```

The Linux Kernel has been successfully installed under the directory
/usr/local/Cavium_Networks/OCTEON-SDK/linux

Please refer to file:///usr/local/Cavium_Networks/OCTEON-SDK/docs/html/linux.html
on how to use Linux on the OCTEON.


Final Setup:

```sh
cp -r /usr/local/Cavium_Networks/OCTEON-SDK/ ~
cd OCTEON-SDK
source env-setup OCTEON_CN73XX

cd examples
make
```

Note: You must run `source env-setup OCTEON_CN73XX` anytime a new shell is opened to setup the build environment.

## Building Linux (Busybox)

```sh
cd $OCTEON_ROOT/linux
make clean
cd embedded_rootfs
make menuconfig
cd ..
make kernel
make strip

cp ./kernel/linux/vmlinux.64 /run/media/dgarske/9016-4EF8/
```

```
telnet 192.168.0.114 9761

fatls mmc 0
fatload mmc 0 $(loadaddr) vmlinux.64
bootoctlinux $(loadaddr) coremask=0x1 root=/dev/sda2 mem=0
```

Shortcut macro from U-Boot:

```
linux_mmc=fatload mmc 0 $(loadaddr) vmlinux.64;bootoctlinux $(loadaddr) coremask=0xffff root=/dev/sda2 mem=0
run linux_mmc
```

## Building Linux Debian

```sh
cd linux
make kernel-deb
cd debian
sudo -E make DISK=/dev/sdc compact-flash
```
modprobe octeon-ethernet


## wolfSSL Building for Octeon

```sh
cd examples
ln -s ../../wolfssl wolfssl
cd wolfssl
./autogen.sh
./configure --host=mips64 CC="mips64-octeon-linux-gnu-gcc -mabi=64" --with-octeon=/home/dgarske/OCTEON-SDK --enable-des3 --enable-cryptocb CFLAGS="-DWOLFSSL_AES_DIRECT"
make

```

Installing to USB media for use on Octeon Board:

```sh
cp -r src /run/media/dgarske/OCTEON/
cp -r wolfcrypt/ /run/media/dgarske/OCTEON/
cp -r wolfssl /run/media/dgarske/OCTEON/
cp -r certs /run/media/dgarske/OCTEON/
```


## Remote Access

### UART and Telnet

Device ID (MAC):
EBB7304_DEFAULT	D8-80-39-7D-6D-0B

Telnet Ports:
telnet 192.168.0.114 9760
telnet 192.168.0.114 9761

Setting Date:
date 070216502019


## Support

For questions please email wolfSSL at support@wolfssl.com
