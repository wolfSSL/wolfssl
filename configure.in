# configure.in
#
# Copyright (C) 2006-2011 Sawtooth Consulting Ltd.
#
# This file is part of CyaSSL.
#
# CyaSSL is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# CyaSSL is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
#

AC_INIT(cyassl,2.0.0rc2,http://www.yassl.com)    # !!! also change in ssl.h !!!
AC_CONFIG_AUX_DIR(config)
AM_CONFIG_HEADER(ctaocrypt/include/ctc_config.h)
AC_CONFIG_MACRO_DIR([m4])
AC_CANONICAL_SYSTEM

AM_INIT_AUTOMAKE(subdir-objects)

#shared library versioning
CYASSL_LIBRARY_VERSION=2:1:0
#                      | | |
#               +------+ | +---+
#               |        |     |
#              current:revision:age
#               |        |     |
#               |        |     +- increment if interfaces have been added
#               |        |        set to zero if interfaces have been removed
#                        |        or changed
#               |        +- increment if source code has changed
#               |           set to zero if current is incremented
#               +- increment if interfaces have been added, removed or changed
AC_SUBST(CYASSL_LIBRARY_VERSION)


# make sure configure doesn't add to CFLAGS
CFLAGS="$CFLAGS $C_EXTRA_FLAGS"    

AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_CC_C_O
AM_PROG_AS
AC_PROG_INSTALL
AC_LIBTOOL_WIN32_DLL
AC_DISABLE_STATIC
AC_PROG_LIBTOOL

AC_PREFIX_DEFAULT(/usr/local/cyassl)

AC_C_BIGENDIAN

AC_CHECK_SIZEOF(long, 4)
AC_CHECK_SIZEOF(long long, 8)

AC_CHECK_LIB(network,socket)
AC_CHECK_LIBM

AC_CHECK_HEADERS(errno.h)


OPTIMIZE_CFLAGS="-Os -fomit-frame-pointer"
OPTIMIZE_FAST_CFLAGS="-O3 -fomit-frame-pointer"
OPTIMIZE_HUGE_CFLAGS="-funroll-loops -DTFM_SMALL_SET"
DEBUG_CFLAGS="-g -DDEBUG -DDEBUG_CYASSL"


# DEBUG
AC_ARG_ENABLE(debug,
    [  --enable-debug          Enable CyaSSL debugging support (default: disabled)],
    [ ENABLED_DEBUG=$enableval ],
    [ ENABLED_DEBUG=no ]
    )
if test "$ENABLED_DEBUG" = "yes"
then
  # Full debug. Very slow in some cases
  CFLAGS="$DEBUG_CFLAGS $CFLAGS"
else
  # Optimized version. No debug
  CFLAGS="$CFLAGS -DNDEBUG"
fi


# SMALL BUILD
AC_ARG_ENABLE(small,
    [  --enable-small          Enable smallest build (default: disabled)],
    [ ENABLED_SMALL=$enableval ],
    [ ENABLED_SMALL=no ]
    )
if test "$ENABLED_SMALL" = "yes"
then
  # make small no tls build with smallest cipher
  # if you only want server or client you can define NO_CYASSL_SERVER or
  # NO_CYASSL_CLIENT but then some of the examples and testsuite won't build
  # note that TLS needs HMAC
  CFLAGS="-DNO_TLS -DNO_HMAC -DNO_AES -DNO_DES3 -DNO_SHA256 -DNO_ERROR_STRINGS -DNO_HC128 -DNO_RABBIT -DNO_PSK -DNO_DSA -DNO_DH -DNO_PWDBASED $CFLAGS" 
fi


# SINGLE THREADED
AC_ARG_ENABLE(singleThreaded,
    [  --enable-singleThreaded Enable CyaSSL single threaded (default: disabled)],
    [ ENABLED_SINGLETHREADED=$enableval ],
    [ ENABLED_SINGLETHREADED=no ]
    )
if test "$ENABLED_SINGLETHREADED" = "yes"
then
  CFLAGS="-DSINGLE_THREADED $CFLAGS"
fi


# DTLS
AC_ARG_ENABLE(dtls,
    [  --enable-dtls           Enable CyaSSL DTLS (default: disabled)],
    [ ENABLED_DTLS=$enableval ],
    [ ENABLED_DTLS=no ]
    )
if test "$ENABLED_DTLS" = "yes"
then
  CFLAGS="-DCYASSL_DTLS $CFLAGS"
fi


# OPENSSL Extra Compatibility
AC_ARG_ENABLE(opensslExtra,
    [  --enable-opensslExtra   Enable extra OpenSSL API, size+ (default: disabled)],
    [ ENABLED_OPENSSLEXTRA=$enableval ],
    [ ENABLED_OPENSSLEXTRA=no ]
    )
if test "$ENABLED_OPENSSLEXTRA" = "yes"
then
  CFLAGS="-DOPENSSL_EXTRA $CFLAGS"
fi

if test "$ENABLED_OPENSSLEXTRA" = "yes" && test "$ENABLED_SMALL" = "yes"
then
    AC_MSG_ERROR([can't enable small and opensslExtra, only one or the other.]) 
fi


# IPv6 Test Apps
AC_ARG_ENABLE(ipv6,
    [  --enable-ipv6           Enable testing of IPV6 (default: disabled)],
    [ ENABLED_IPV6=$enableval ],
    [ ENABLED_IPV6=no ]
    )

if test "$ENABLED_IPV6" = "yes"
then
    CFLAGS="$CFLAGS -DTEST_IPV6"
fi


# fastmath
AC_ARG_ENABLE(fastmath,
    [  --enable-fastmath       Enable fast math for BigInts (default: disabled)],
    [ ENABLED_FASTMATH=$enableval ],
    [ ENABLED_FASTMATH=no ]
    )

if test "$ENABLED_FASTMATH" = "yes"
then
    CFLAGS="$CFLAGS -DUSE_FAST_MATH"
fi


# fast HUGE math
AC_ARG_ENABLE(fasthugemath,
    [  --enable-fasthugemath   Enable fast math + huge code (default: disabled)],
    [ ENABLED_FASTHUGEMATH=$enableval ],
    [ ENABLED_FASTHUGEMATH=no ]
    )

if test "$ENABLED_FASTHUGEMATH" = "yes"
then
    ENABLED_FASTMATH="yes"
    CFLAGS="$CFLAGS -DUSE_FAST_MATH"
fi

AM_CONDITIONAL([BUILD_FASTMATH], [test "x$ENABLED_FASTMATH" = "xyes"])


# big cache
AC_ARG_ENABLE(bigcache,
    [  --enable-bigcache       Enable big session cache (default: disabled)],
    [ ENABLED_BIGCACHE=$enableval ],
    [ ENABLED_BIGCACHE=no ]
    )

if test "$ENABLED_BIGCACHE" = "yes"
then
    CFLAGS="$CFLAGS -DBIG_SESSION_CACHE"
fi


# HUGE cache
AC_ARG_ENABLE(hugecache,
    [  --enable-hugecache      Enable huge session cache (default: disabled)],
    [ ENABLED_HUGECACHE=$enableval ],
    [ ENABLED_HUGECACHE=no ]
    )

if test "$ENABLED_HUGECACHE" = "yes"
then
    CFLAGS="$CFLAGS -DHUGE_SESSION_CACHE"
fi


# SNIFFER
AC_ARG_ENABLE(sniffer,
    [  --enable-sniffer        Enable CyaSSL sniffer support (default: disabled)],
    [ ENABLED_SNIFFER=$enableval ],
    [ ENABLED_SNIFFER=no ]
    )

if test "$ENABLED_SNIFFER" = "yes"
then
    CFLAGS="$CFLAGS -DCYASSL_SNIFFER -DOPENSSL_EXTRA"
fi

AM_CONDITIONAL([BUILD_SNIFFER], [test "x$ENABLED_SNIFFER" = "xyes"])

# AES-NI
AC_ARG_ENABLE(aesni,
    [  --enable-aesni          Enable CyaSSL AES-NI support (default: disabled)],
    [ ENABLED_AESNI=$enableval ],
    [ ENABLED_AESNI=no ]
    )

if test "$ENABLED_AESNI" = "yes"
then
    CFLAGS="$CFLAGS -DCYASSL_AESNI"
    if test "$GCC" = "yes"
    then
        # GCC needs these flags, icc doesn't
        CFLAGS="$CFLAGS -maes -msse4"
    fi
fi

AM_CONDITIONAL([BUILD_AESNI], [test "x$ENABLED_AESNI" = "xyes"])


# RIPEMD
AC_ARG_ENABLE(ripemd,
    [  --enable-ripemd         Enable CyaSSL RIPEMD-160 support (default: disabled)],
    [ ENABLED_RIPEMD=$enableval ],
    [ ENABLED_RIPEMD=no ]
    )

if test "$ENABLED_RIPEMD" = "yes"
then
    CFLAGS="$CFLAGS -DCYASSL_RIPEMD"
fi

AM_CONDITIONAL([BUILD_RIPEMD], [test "x$ENABLED_RIPEMD" = "xyes"])


# SHA512
AC_ARG_ENABLE(sha512,
    [  --enable-sha512         Enable CyaSSL SHA-160 support (default: disabled)],
    [ ENABLED_SHA512=$enableval ],
    [ ENABLED_SHA512=no ]
    )

if test "$ENABLED_SHA512" = "yes"
then
    CFLAGS="$CFLAGS -DCYASSL_SHA512"
fi

AM_CONDITIONAL([BUILD_SHA512], [test "x$ENABLED_SHA512" = "xyes"])


# SESSION CERTS
AC_ARG_ENABLE(sessioncerts,
    [  --enable-sessioncerts   Enable session cert storing (default: disabled)],
    [ ENABLED_SESSIONCERTS=$enableval ],
    [ ENABLED_SESSIONCERTS=no ]
    )

if test "$ENABLED_SESSIONCERTS" = "yes"
then
    CFLAGS="$CFLAGS -DSESSION_CERTS"
fi


# KEY GENERATION
AC_ARG_ENABLE(keygen,
    [  --enable-keygen         Enable key generation (default: disabled)],
    [ ENABLED_KEYGEN=$enableval ],
    [ ENABLED_KEYGEN=no ]
    )

if test "$ENABLED_KEYGEN" = "yes"
then
    CFLAGS="$CFLAGS -DCYASSL_KEY_GEN"
fi


# CERT GENERATION
AC_ARG_ENABLE(certgen,
    [  --enable-certgen        Enable cert generation (default: disabled)],
    [ ENABLED_CERTGEN=$enableval ],
    [ ENABLED_CERTGEN=no ]
    )

if test "$ENABLED_CERTGEN" = "yes"
then
    CFLAGS="$CFLAGS -DCYASSL_CERT_GEN"
fi


# HC128
AC_ARG_ENABLE(hc128,
    [  --enable-hc128          Enable HC-128 (default: disabled)],
    [ ENABLED_HC128=$enableval ],
    [ ENABLED_HC128=no ]
    )

if test "$ENABLED_HC128" = "no"
then
    CFLAGS="$CFLAGS -DNO_HC128"
fi

AM_CONDITIONAL([BUILD_HC128], [test "x$ENABLED_HC128" = "xyes"])


# PSK 
AC_ARG_ENABLE(psk,
    [  --enable-psk            Enable PSK (default: disabled)],
    [ ENABLED_PSK=$enableval ],
    [ ENABLED_PSK=no ]
    )

if test "$ENABLED_PSK" = "no"
then
    CFLAGS="$CFLAGS -DNO_PSK"
fi


# Web Server Build 
AC_ARG_ENABLE(webServer,
    [  --enable-webServer      Enable Web Server (default: disabled)],
    [ ENABLED_WEBSERVER=$enableval ],
    [ ENABLED_WEBSERVER=no ]
    )

if test "$ENABLED_WEBSERVER" = "yes"
then
    CFLAGS="$CFLAGS -DHAVE_WEBSERVER"
fi


# No Filesystem Build 
AC_ARG_ENABLE(noFilesystem,
    [  --enable-noFilesystem   Enable No Filesystem (default: disabled)],
    [ ENABLED_NOFILESYSTEM=$enableval ],
    [ ENABLED_NOFILESYSTEM=no ]
    )

if test "$ENABLED_NOFILESYSTEM" = "yes"
then
    CFLAGS="$CFLAGS -DNO_FILESYSTEM"
fi


# ECC 
AC_ARG_ENABLE(ecc,
    [  --enable-ecc            Enable ECC (default: disabled)],
    [ ENABLED_ECC=$enableval ],
    [ ENABLED_ECC=no ]
    )

if test "$ENABLED_ECC" = "yes"
then
    CFLAGS="$CFLAGS -DHAVE_ECC"
fi

AM_CONDITIONAL([BUILD_ECC], [test "x$ENABLED_ECC" = "xyes"])


if test "$ENABLED_ECC" = "yes" && test "$ENABLED_SMALL" = "yes"
then
    AC_MSG_ERROR([can't enable ecc and small, ecc requires TLS which small turns off.]) 
fi


# NTRU
ntruHome=`pwd`/NTRU_algorithm
ntruInclude=$ntruHome/cryptolib
ntruLib=$ntruHome
AC_ARG_ENABLE(ntru,
    [  --enable-ntru           Enable NTRU (default: disabled)],
    [ ENABLED_NTRU=$enableval ],
    [ ENABLED_NTRU=no ]
    )

if test "$ENABLED_NTRU" = "yes"
then
    CFLAGS="$CFLAGS -DHAVE_NTRU -I$ntruInclude"
    LDFLAGS="$LDFLAGS -L$ntruLib"
    LIBS="$LIBS -lntru_encrypt"
fi

AM_CONDITIONAL([BUILD_NTRU], [test "x$ENABLED_NTRU" = "xyes"])

if test "$ENABLED_NTRU" = "yes" && test "$ENABLED_SMALL" = "yes"
then
    AC_MSG_ERROR([can't enable ntru and small, ntru requires TLS which small turns off.]) 
fi


# Test certs, use internal cert functions for extra testing 
AC_ARG_ENABLE(testcert,
    [  --enable-testcert       Enable Test Cert (default: disabled)],
    [ ENABLED_TESTCERT=$enableval ],
    [ ENABLED_TESTCERT=no ]
    )

if test "$ENABLED_TESTCERT" = "yes"
then
    CFLAGS="$CFLAGS -DCYASSL_TEST_CERT"
fi


# LIBZ
trylibzdir=""
AC_ARG_WITH(libz,
    [  --with-libz=PATH        PATH to libz install (default /usr/) ],
    [
        AC_MSG_CHECKING([for libz])
        CPPFLAGS="$CPPFLAGS -DHAVE_LIBZ"
        LIBS="$LIBS -lz"

        AC_TRY_LINK([#include <zlib.h>], [ deflateInit(0, 8); ],
            [ libz_linked=yes ], [ libz_linked=no ])

        if test "x$libz_linked" == "xno" ; then
            if test "x$withval" != "xno" ; then
                trylibzdir=$withval
            fi
            if test "x$withval" == "xyes" ; then
                trylibzdir="/usr"
            fi

            LDFLAGS="$LDFLAGS -L$trylibzdir/lib"
            CPPFLAGS="$CPPFLAGS -I$trylibzdir/include"

            AC_TRY_LINK([#include <zlib.h>], [ deflateInit(0, 8); ],
                [ libz_linked=yes ], [ libz_linked=no ])

            if test "x$libz_linked" == "xno" ; then
                AC_MSG_ERROR([libz isn't found.
                If it's already installed, specify its path using --with-libz=/dir/])
            fi
            AC_MSG_RESULT([yes])
        else
            AC_MSG_RESULT([yes])
        fi

    ]
)


# OPTIMIZE FLAGS
if test "$GCC" = "yes"
then
    CFLAGS="$CFLAGS -Wall -Wno-unused"
    if test "$ENABLED_DEBUG" = "no"
    then
        if test "$ENABLED_FASTMATH" = "yes"
        then
            CFLAGS="$CFLAGS $OPTIMIZE_FAST_CFLAGS"
            if test "$ENABLED_FASTHUGEMATH" = "yes"
            then
                CFLAGS="$CFLAGS $OPTIMIZE_HUGE_CFLAGS"
            fi
        else
            CFLAGS="$CFLAGS $OPTIMIZE_CFLAGS"
        fi
    fi
fi




ACX_PTHREAD

LIBS="$PTHREAD_LIBS $LIBM $LIBS"
CFLAGS="$CFLAGS $PTHREAD_CFLAGS"

LIB_SOCKET_NSL

dnl Various GCC warnings that should never fire for release quality code
GCCWARNINGS="-Wall -fno-strict-aliasing -W -Wfloat-equal -Wundef        \
-Wpointer-arith -Wstrict-prototypes -Wmissing-prototypes                \
-Wwrite-strings -Wredundant-decls -Wchar-subscripts -Wcomment           \
-Wformat=2 -Wwrite-strings -Wmissing-declarations -Wredundant-decls     \
-Wnested-externs -Wbad-function-cast -Wswitch-enum -Winit-self          \
-Wmissing-field-initializers -Wdeclaration-after-statement              \
-Wold-style-definition -Waddress -Wmissing-noreturn -Wnormalized=id     \
-Woverride-init -Wstrict-overflow=1 -Wextra -Warray-bounds              \
-Wstack-protector -Wformat -Wformat-security -Wpointer-sign -Wshadow    \
-Wswitch-default"

AC_ARG_ENABLE(gcc-lots-o-warnings,
AS_HELP_STRING(--enable-gcc-lots-o-warnings, Enable lots of gcc warnings (default: disabled)),
[if test x$enableval = xyes; then
    CFLAGS="$CFLAGS $GCCWARNINGS"
fi])

AC_ARG_ENABLE(gcc-hardening,
AS_HELP_STRING(--enable-gcc-hardening, Enable compiler security checks (default: disabled)),
[if test x$enableval = xyes; then
    CFLAGS="$CFLAGS -D_FORTIFY_SOURCE=2 -fstack-protector-all"
    CFLAGS="$CFLAGS -fwrapv -fPIE -Wstack-protector"
    CFLAGS="$CFLAGS --param ssp-buffer-size=1"
    LDFLAGS="$LDFLAGS -pie"
fi])

dnl Linker hardening options
dnl Currently these options are ELF specific - you can't use this with MacOSX
AC_ARG_ENABLE(linker-hardening,
AS_HELP_STRING(--enable-linker-hardening, Enable linker security fixups (default: disabled)),
[if test x$enableval = xyes; then
    LDFLAGS="$LDFLAGS -z relro -z now"
fi])


PANDORA_VISIBILITY
CFLAGS="$CFLAGS $CFLAG_VISIBILITY"

AC_SUBST(CFLAGS)
AC_SUBST(LIBS)



# FINAL
AC_CONFIG_FILES([Makefile])
AC_OUTPUT

