# Gaisler BCC

This document outlines how to compile for the Gaisler LEON range of Sparc CPUs
using the BCC2 toolkit. The steps here should also work for the original BCC.

## Compiler

In the examples in this document, a Linux computer is used as a cross compiler
and the compilers have been extracted to `/opt`. You can install them elsewhere,
but please adjust commands accordingly.

### Bare-metal

To compile for bare-metal, you need to download the BCC2 binaries from
[here](https://www.gaisler.com/index.php/downloads/compilers). You can use
either the GCC or CLang version, but do note that you will need to set the
CFLAG `-std=c99` to compile in CLang.

### Linux

For Linux, you will need the "GNU toolchains for LEON and NOEL" from
[this link](https://www.gaisler.com/index.php/downloads/linux).

## Compiling

### Bare metal

Copy the file `examples/config/user_settings_template.h` to `user_settings.h` in
the root of the source code. Then edit this to add the following:

```c
#define WOLFSSL_GAISLER_BCC
#define WOLFSSL_GENSEED_FORTEST
```

The first `#define` is only required to compile the wolfCrypt benchmark.

**Note:** that most Gaisler LEON processors do not have a good source of
entropy for the RNG. It is recommended an external entropy source is used when
developing for production.

You can then compile with the following. Change `leon5` to the LEON CPU version
used:

```sh
export CC=/opt/sparc-bcc-2.3.1-gcc/bin/sparc-gaisler-elf-gcc
export CXX=/opt/sparc-bcc-2.3.1-gcc/bin/sparc-gaisler-elf-g++
export CFLAGS="-mcpu=leon5"

./configure --host=sparc --enable-usersettings --disable-examples --enable-static
make
```

### Linux

To compile for Linux on the LEON use the following commands:

```sh
export CC=/opt/sparc-gaisler-linux5.10/bin/sparc-gaisler-linux5.10-gcc
export CXX=/opt/sparc-gaisler-linux5.10/bin/sparc-gaisler-linux5.10-g++
export CFLAGS="-mcpu=leon5"

./configure --host=sparc-linux
make
```
