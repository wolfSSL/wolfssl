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

Setup for CN73XX board EVB7304

```sh
setenv qlm2_mode pcie
setenv pcie2_mode ep
setenv pcie2_gen 2
setenv pcie2_lanes 4
setenv qlm2_mode sgmii

setenv qlm4_mode sata

#setenv ethact octeth0
#setenv ethprime octeth0
dhcp

saveenv
```

## Building bootloader

```sh
# On Host
cd OCTEON-SDK/bootloader/u-boot
make distclean
make octeon_ebb7304
make

cp *.bin /mnt/cf1

# On Target
fatls mmc 1
fatload mmc 1 $(loadaddr) u-boot-octeon_ebb7304.bin

bootloadervalidate
bootloaderupdate
```

Note: You must run `source env-setup OCTEON_CN73XX` anytime a new shell is opened to setup the build environment.

## Building Linux Kernel (Busybox)

```sh
# On Host
su root
cd OCTEON-SDK
source env-setup OCTEON_CN73XX
cd linux
make clean
cd embedded_rootfs
make menuconfig
cd ..
make kernel
make strip

cp ./kernel/linux/vmlinux.64 /mnt/cf1
```

```sh
# On Target
telnet 192.168.0.114 9761

fatls mmc 1
fatload mmc 1 $(loadaddr) vmlinux.64
bootoctlinux $(loadaddr) coremask=0xffff root=/dev/sda2 mem=0
```

Shortcut macro from U-Boot:

```sh
# On Target
setenv linux_mmc 'fatload mmc 1 $(loadaddr) vmlinux.64;bootoctlinux $(loadaddr) coremask=0xffff root=/dev/sda2 mem=0'
run linux_mmc
saveenv
```

## Building Linux Debian

```sh
su root
cd OCTEON-SDK
source env-setup OCTEON_CN73XX

cd linux
make kernel-deb

# Identify external /dev/sd*
fdisk -l

# Edit /etc/fstab. Replace "sda" with the device name determined from above.
/dev/sdb1       /mnt/cf1        auto    noauto,noatime,user     0 0
/dev/sdb2       /mnt/cf2        ext3    noauto,noatime,user     0 0

mkdir -p /mnt/cf1
mkdir -p /mnt/cf2

cd debian
make DISK=/dev/sdb compact-flash
cd ..
make kernel-deb flash

usb start
fatls usb 0
fatload usb 0 $(loadaddr) vmlinux.64

fatls mmc 0
fatload mmc 0 $(loadaddr) vmlinux.64
bootoctlinux $(loadaddr) coremask=0xffff root=/dev/mmcblk0p2 mem=0 rootdelay=5
```

### Setting up default boot

```sh
setenv bootcmd 'fatload mmc 0 $(loadaddr) vmlinux.64; bootoctlinux $(loadaddr) coremask=0xffff root=/dev/mmcblk0p2 mem=0 rootdelay=5'
saveenv
reset
```

### Debian Packages

```sh
vi /etc/sources.list
deb http://archive.debian.org/debian/ jessie main contrib non-free
deb-src http://archive.debian.org/debian/ jessie main contrib non-free
#deb-src http://archive.debian.org/ jessie/updates main contrib non-free
#deb http://archive.debian.org/ jessie/updates main contrib non-free
```

## wolfSSL Building for Octeon

```sh
cd examples
ln -s ../../wolfssl wolfssl
cd wolfssl
./autogen.sh
./configure --host=mips64 CC="mips64-octeon-linux-gnu-gcc -mabi=64" \
    --with-octeon-sync=../OCTEON-SDK OCTEON_OBJ=obj-octeon3 \
    --enable-cryptocb --enable-des3 CPPFLAGS="-DWOLFSSL_AES_DIRECT" \
    CFLAGS="-Wno-error=redundant-decls"
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

EBB7304_DEFAULT    D8-80-39-7D-6D-0B

telnet 192.168.0.114 9760
telnet 192.168.0.114 9761

date 070216502019


## Support

For questions please email wolfSSL at support@wolfssl.com
