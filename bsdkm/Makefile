# wolfssl kernel module name and source, and root dir.
KMOD        = libwolfssl
SRCS        = wolfkmod.c
WOLFSSL_DIR = ../

CFLAGS+=-I${WOLFSSL_DIR}
CFLAGS+=-DWOLFSSL_IGNORE_FILE_WARN -DHAVE_CONFIG_H -DNO_MAIN_DRIVER

#
# debug options
#   verbose printing:
#   CFLAGS += -DWOLFSSL_BSDKM_VERBOSE_DEBUG
#
#   print memory mallocs / frees:
#   CFLAGS += -DWOLFSSL_BSDKM_MEMORY_DEBUG
#
CFLAGS += $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS)

.if defined(ENABLED_BSDKM_REGISTER)
  # These device header files are generated during build.
  SRCS += bus_if.h cryptodev_if.h device_if.h
.endif

# FreeBSD make does not support GNU make's patsubst and related. Filter
# through sed instead.
WOLFSSL_OBJS != echo ${src_libwolfssl_la_OBJECTS} | \
  sed 's|src_libwolfssl_la-||g' | sed 's|\.lo|.o|g' | \
  sed 's|wolfcrypt/src/|${WOLFSSL_DIR}/wolfcrypt/src/|g'

# wolfcrypt test
.if ${ENABLED_CRYPT_TESTS} == "yes"
    WOLFSSL_OBJS += ${WOLFSSL_DIR}/wolfcrypt/test/test.o
.else
    CFLAGS += -DNO_CRYPT_TEST
.endif

# wolfcrypt benchmark
.if ${ENABLED_KERNEL_BENCHMARKS} == "yes"
    WOLFSSL_OBJS += ${WOLFSSL_DIR}/wolfcrypt/benchmark/benchmark.o
    CFLAGS+=-DWOLFSSL_NO_FLOAT_FMT
.endif

OBJS += ${WOLFSSL_OBJS}

# Export no public symbols by default.
.if !defined(BSDKM_EXPORT_SYMS)
    EXPORT_SYMS = NO
.else
    EXPORT_SYMS = ${BSDKM_EXPORT_SYMS}
.endif

# Default to live kernel src tree makefile at
# /usr/src/sys/conf/kmod.mk
.if !defined(KERNEL_ROOT)
    SYSDIR?= /usr/src/sys
.else
    SYSDIR?= ${KERNEL_ROOT}
.endif
.include "${SYSDIR}/conf/kmod.mk"

# To use aesni in FreeBSD kernel we need to adjust build flags.
# See these for reference:
#   - /usr/src/sys/modules/aesni/Makefile
#   - /usr/src/sys/conf/kern.mk
.if ${ENABLED_ASM} == "yes"
  CFLAGS.aes.c += -msse -msse2 -msse4.1 -maes -mpclmul -mavx -mavx2
  CFLAGS.aes.c := ${CFLAGS.aes.c:N-nostdinc}
  CFLAGS.aes.c += -I${SYSDIR}/../contrib/llvm-project/clang/lib/Headers

  CFLAGS.poly1305.c += -msse -msse2 -msse4.1 -maes -mpclmul
  CFLAGS.poly1305.c := ${CFLAGS.aes.c:N-nostdinc}
  CFLAGS.poly1305.c += -I${SYSDIR}/../contrib/llvm-project/clang/lib/Headers

  CFLAGS.chacha.c += -msse -msse2 -msse4.1 -maes -mpclmul
  CFLAGS.chacha.c := ${CFLAGS.aes.c:N-nostdinc}
  CFLAGS.chacha.c += -I${SYSDIR}/../contrib/llvm-project/clang/lib/Headers

  CFLAGS.sha.c += -msse -msse2 -msse4.1 -maes -mpclmul -mavx -mavx2
  CFLAGS.sha256.c += -msse -msse2 -msse4.1 -maes -mpclmul -mavx -mavx2
  CFLAGS.benchmark.c += -msse -msse2 -msse4.1 -maes -mpclmul -mavx -mavx2
  CFLAGS.benchmark.c := ${CFLAGS.aes.c:N-nostdinc}
  CFLAGS.benchmark.c += -I${SYSDIR}/../contrib/llvm-project/clang/lib/Headers
  .PATH: ${SYSDIR}/../contrib/llvm-project/clang/lib/Headers
.endif

# Smooth out a few inconsistencies between FreeBSD default compiler flags
# in /usr/src/sys/conf/kern.mk, vs wolfssl harden flags in
# m4/ax_harden_compiler_flags.m4. E.g. some FreeBSD header files shorten
# 64 to 32 bit, and some wolfcrypt functions cast away const.
CFLAGS += -Wno-unused-function
CFLAGS += -Wno-cast-qual
CFLAGS += -Wno-error=cast-qual
CFLAGS += -Wno-shorten-64-to-32
CFLAGS += -DLIBWOLFSSL_GLOBAL_EXTRA_CFLAGS="\" $(KERNEL_EXTRA_CFLAGS)\""
