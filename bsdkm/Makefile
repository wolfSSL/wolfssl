# wolfssl module name and source.
KMOD=libwolfssl
SRCS=wolfkmod.c
WOLFSSL_DIR=../

CFLAGS+=-I/usr/include/sys
CFLAGS+=-I${WOLFSSL_DIR}
CFLAGS+=-DWOLFSSL_IGNORE_FILE_WARN -DHAVE_CONFIG_H
CFLAGS+=-DNO_MAIN_DRIVER
# debug mode
CFLAGS+=-DWOLFSSL_BSDKM_VERBOSE_DEBUG
CFLAGS+=$(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS)

# FreeBSD make does not support GNU make's patsubst and related.
# Just include everything under wolfcrypt/src/ except port, and let
# define flags filter the rest.
OBJS != find ${WOLFSSL_DIR}/wolfcrypt/src -path \
  '${WOLFSSL_DIR}/wolfcrypt/src/port' -prune -o -name \
  '*.c' -print | sed 's,\.c$$,.o,'

.if ${ENABLED_CRYPT_TESTS} == "yes"
    OBJS += ${WOLFSSL_DIR}/wolfcrypt/test/test.o
    # freebsd kernel compiler insists fiducial line vars are unused.
    CFLAGS+=-Wno-error=unused-const-variable
.else
    CFLAGS+=-DNO_CRYPT_TEST
.endif

# Export no public symbols by default.
.if !defined(BSDKM_EXPORT_SYMS)
    EXPORT_SYMS=NO
.else
    EXPORT_SYMS=${BSDKM_EXPORT_SYMS}
.endif

# Default to live kernel src tree makefile at
# /usr/src/sys/conf/kmod.mk
.if !defined(KERNEL_ROOT)
    SYSDIR?= /usr/src/sys
.else
    SYSDIR?= ${KERNEL_ROOT}
.endif
.include "${SYSDIR}/conf/kmod.mk"

# Suppress wolfcrypt/src/misc.c drops const qualifier, and similar.
CFLAGS+= -Wno-unused-function
CFLAGS+= -Wno-cast-qual
CFLAGS+= -Wno-error=cast-qual
CFLAGS+= -Wno-shorten-64-to-32
CFLAGS+= -DLIBWOLFSSL_GLOBAL_EXTRA_CFLAGS="\" $(KERNEL_EXTRA_CFLAGS)\""
