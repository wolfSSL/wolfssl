# wolfssl kernel module name and main source, and wolfssl root dir.
KMOD        = libwolfssl
SRCS        = wolfkmod.c
WOLFSSL_DIR = ../

CFLAGS += -I${WOLFSSL_DIR}
CFLAGS += -DWOLFSSL_IGNORE_FILE_WARN -DHAVE_CONFIG_H -DNO_MAIN_DRIVER
#
# debug options
#   verbose printing:
#   CFLAGS += -DWOLFSSL_BSDKM_VERBOSE_DEBUG
#
#   print memory mallocs / frees:
#   CFLAGS += -DWOLFSSL_BSDKM_MEMORY_DEBUG
#
#   print fpu_kern_enter / leave:
#   CFLAGS += WOLFSSL_BSDKM_FPU_DEBUG
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
    CFLAGS += -DWOLFSSL_NO_FLOAT_FMT
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

#
# To use aesni and friends in FreeBSD kernel we need to adjust build flags.
# See these kernel makefiles for reference:
#   - /usr/src/sys/modules/aesni/Makefile
#   - /usr/src/sys/conf/kern.mk
#
WOLFKMOD_SIMD_BASE = -msse -msse2 -msse4.1
WOLFKMOD_SIMD_AES  = -maes -mpclmul
WOLFKMOD_SIMD_AVX  = -mavx -mavx2

.if ${ENABLED_AESNI} == "yes"
  CFLAGS.aes.c += ${WOLFKMOD_SIMD_BASE}
  CFLAGS.aes.c += ${WOLFKMOD_SIMD_AES}
.if ${ENABLED_AESNI_WITH_AVX} == "yes"
  CFLAGS.aes.c += ${WOLFKMOD_SIMD_AVX}
.endif # ENABLED_AESNI_WITH_AVX #
  CFLAGS.aes.c := ${CFLAGS.aes.c:N-nostdinc}
  CFLAGS.aes.c += -I${SYSDIR}/../contrib/llvm-project/clang/lib/Headers
.PATH: ${SYSDIR}/../contrib/llvm-project/clang/lib/Headers
.endif # ENABLED_AESNI

.if ${ENABLED_ASM} == "yes"
.for f in chacha dilithium poly1305 sha sha256 sha3 sha512
  CFLAGS.${f}.c += ${WOLFKMOD_SIMD_BASE}
  CFLAGS.${f}.c += ${WOLFKMOD_SIMD_AVX}
  CFLAGS.${f}.c := ${CFLAGS.${f}.c:N-nostdinc}
  CFLAGS.${f}.c += -I${SYSDIR}/../contrib/llvm-project/clang/lib/Headers
.endfor

.PATH: ${SYSDIR}/../contrib/llvm-project/clang/lib/Headers
.endif # ENABLED_ASM == "yes"

# wolfcrypt benchmark always needs simd for the floating point timings.
.if ${ENABLED_KERNEL_BENCHMARKS} == "yes"
  CFLAGS.benchmark.c += ${WOLFKMOD_SIMD_BASE}
  CFLAGS.benchmark.c := ${CFLAGS.benchmark.c:N-nostdinc}
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
