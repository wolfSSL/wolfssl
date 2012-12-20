# configure.ac
#
# Copyright (C) 2006-2012 Sawtooth Consulting Ltd.
#
# This file is part of CyaSSL.
#
#

AC_INIT([cyassl],[2.4.6],[http://www.yassl.com])

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

AC_CANONICAL_TARGET
AC_USE_SYSTEM_EXTENSIONS

AM_INIT_AUTOMAKE([-Wall -Werror -Wno-portability foreign tar-ustar subdir-objects])

AC_CANONICAL_HOST
AC_CANONICAL_BUILD

AC_PREREQ([2.61])


AC_CONFIG_HEADERS([config.h:config.in])dnl Keep filename to 8.3 for MS-DOS.


#shared library versioning
CYASSL_LIBRARY_VERSION=4:0:0
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
AC_SUBST([CYASSL_LIBRARY_VERSION])

# capture user C_EXTRA_FLAGS from ./configure line, CFLAGS may hold -g -O2 even
# if user doesn't override, no way to tell
USER_C_EXTRA_FLAGS="$C_EXTRA_FLAGS"

LT_INIT([win32-dll])
LT_LANG([C++])
LT_LANG([C])
gl_VISIBILITY
AS_IF([ test -n "$CFLAG_VISIBILITY" ], [
       AM_CPPFLAGS="$AM_CPPFLAGS $CFLAG_VISIBILITY"
       CPPFLAGS="$CPPFLAGS $CFLAG_VISIBILITY"
       ])

m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])

AX_CXX_COMPILER_VERSION

AC_CHECK_FUNCS([gethostbyname])
AC_CHECK_FUNCS([gettimeofday])
AC_CHECK_FUNCS([inet_ntoa])
AC_CHECK_FUNCS([memset])
AC_CHECK_FUNCS([socket])
AC_CHECK_HEADERS([arpa/inet.h])
AC_CHECK_HEADERS([fcntl.h])
AC_CHECK_HEADERS([limits.h])
AC_CHECK_HEADERS([netdb.h])
AC_CHECK_HEADERS([netinet/in.h])
AC_CHECK_HEADERS([stddef.h])
AC_CHECK_HEADERS([sys/ioctl.h])
AC_CHECK_HEADERS([sys/socket.h])
AC_CHECK_HEADERS([sys/time.h])
AC_CHECK_HEADERS([errno.h])
AC_CHECK_LIB(network,socket)
AC_CHECK_SIZEOF(long long, 8)
AC_CHECK_SIZEOF(long, 4)
AC_C_BIGENDIAN
AC_DISABLE_STATIC
# mktime check takes forever on some systems, if time supported it would be
# highly unusual for mktime to be missing
#AC_FUNC_MKTIME 

AC_PROG_CC
AC_PROG_CC_C_O
AC_PROG_CXX
AC_PROG_INSTALL
LT_INIT
AC_TYPE_SIZE_T
AC_TYPE_UINT8_T
AM_PROG_AS
AM_PROG_CC_C_O
LT_LIB_M

OPTIMIZE_CFLAGS="-Os -fomit-frame-pointer"
OPTIMIZE_FAST_CFLAGS="-O3 -fomit-frame-pointer"
OPTIMIZE_HUGE_CFLAGS="-funroll-loops -DTFM_SMALL_SET"
DEBUG_CFLAGS="-g -DDEBUG -DDEBUG_CYASSL"


# DEBUG
AX_DEBUG
AS_IF([test "$ax_enable_debug" = "yes"],
      [AM_CFLAGS="$DEBUG_CFLAGS $AM_CFLAGS"],
      [AM_CFLAGS="$AM_CFLAGS -DNDEBUG"])


# SINGLE THREADED
AC_ARG_ENABLE([singleThreaded],
    [  --enable-singleThreaded Enable CyaSSL single threaded (default: disabled)],
    [ ENABLED_SINGLETHREADED=$enableval ],
    [ ENABLED_SINGLETHREADED=no ])

AS_IF([ test "x$ENABLED_SINGLETHREADED" = "xno" ],[
       AX_PTHREAD([
                   AC_DEFINE([HAVE_PTHREAD], [1], [Define if you have POSIX threads libraries and header files.])
                   AM_CFLAGS="-D_POSIX_THREADS $AM_CFLAGS"
                   ],[
                      ENABLED_SINGLETHREADED=yes
                      ])
       ])

AS_IF([ test "x$ENABLED_SINGLETHREADED" = "xyes" ],[ AM_CFLAGS="-DSINGLE_THREADED $AM_CFLAGS" ])


# DTLS
AC_ARG_ENABLE([dtls],
    [  --enable-dtls           Enable CyaSSL DTLS (default: disabled)],
    [ ENABLED_DTLS=$enableval ],
    [ ENABLED_DTLS=no ]
    )
if test "$ENABLED_DTLS" = "yes"
then
  AM_CFLAGS="-DCYASSL_DTLS $AM_CFLAGS"
fi


# OPENSSL Extra Compatibility
AC_ARG_ENABLE([opensslExtra],
    [  --enable-opensslExtra   Enable extra OpenSSL API, size+ (default: disabled)],
    [ ENABLED_OPENSSLEXTRA=$enableval ],
    [ ENABLED_OPENSSLEXTRA=no ]
    )
if test "$ENABLED_OPENSSLEXTRA" = "yes"
then
  AM_CFLAGS="-DOPENSSL_EXTRA $AM_CFLAGS"
fi

if test "$ENABLED_OPENSSLEXTRA" = "yes" && test "$ENABLED_SMALL" = "yes"
then
    AC_MSG_ERROR([cannot enable small and opensslExtra, only one or the other.])
fi


# IPv6 Test Apps
AC_ARG_ENABLE([ipv6],
    [  --enable-ipv6           Enable testing of IPV6 (default: disabled)],
    [ ENABLED_IPV6=$enableval ],
    [ ENABLED_IPV6=no ]
    )

if test "$ENABLED_IPV6" = "yes"
then
    AM_CFLAGS="$AM_CFLAGS -DTEST_IPV6"
fi


# Fortress build 
AC_ARG_ENABLE([fortress],
    [  --enable-fortress       Enable SSL fortress build (default: disabled)],
    [ ENABLED_FORTRESS=$enableval ],
    [ ENABLED_FORTRESS=no ]
    )

if test "$ENABLED_FORTRESS" = "yes"
then
    AM_CFLAGS="$AM_CFLAGS -DFORTRESS -DOPENSSL_EXTRA -DCYASSL_DES_ECB -DCYASSL_AES_COUNTER -DCYASSL_AES_DIRECT -DCYASSL_DER_LOAD -DCYASSL_SHA512 -DCYASSL_SHA384 -DCYASSL_KEY_GEN"
fi


# ssl bump build 
AC_ARG_ENABLE([bump],
    [  --enable-bump           Enable SSL Bump build (default: disabled)],
    [ ENABLED_BUMP=$enableval ],
    [ ENABLED_BUMP=no ]
    )

if test "$ENABLED_BUMP" = "yes"
then
    AM_CFLAGS="$AM_CFLAGS -DLARGE_STATIC_BUFFERS -DCYASSL_CERT_GEN -DCYASSL_KEY_GEN -DHUGE_SESSION_CACHE -DOPENSSL_EXTRA -DFP_MAX_BITS=8192 -DCYASSL_DER_LOAD -DCYASSL_ALT_NAMES -DCYASSL_TEST_CERT"
fi

ENABLED_SLOWMATH="yes"

# lean psk build 
AC_ARG_ENABLE([leanpsk],
    [  --enable-leanpsk        Enable Lean PSK build (default: disabled)],
    [ ENABLED_LEANPSK=$enableval ],
    [ ENABLED_LEANPSK=no ]
    )

if test "$ENABLED_LEANPSK" = "yes"
then
    AM_CFLAGS="$AM_CFLAGS -DCYASSL_LEANPSK -DHAVE_NULL_CIPHER -DSINGLE_THREADED -DNO_AES -DNO_FILESYSTEM -DNO_RABBIT -DNO_RSA -DNO_DSA -DNO_DH -DNO_CERTS -DNO_PWDBASED -DNO_DES3 -DNO_MD4 -DNO_MD5 -DNO_ERROR_STRINGS -DNO_OLD_TLS -DNO_RC4 -DNO_WRITEV -DNO_SESSION_CACHE -DNO_DEV_RANDOM -DCYASSL_USER_IO -DUSE_SLOW_SHA"
    ENABLED_SLOWMATH="no"
    ENABLED_SINGLETHREADED="yes"
fi

AM_CONDITIONAL([BUILD_LEANPSK], [test "x$ENABLED_LEANPSK" = "xyes"])


# fastmath
AC_ARG_ENABLE([fastmath],
    [  --enable-fastmath       Enable fast math for BigInts (default: disabled)],
    [ ENABLED_FASTMATH=$enableval ],
    [ ENABLED_FASTMATH=no ]
    )

if test "x$ENABLED_FASTMATH" = "xyes"
then
    AM_CFLAGS="$AM_CFLAGS -DUSE_FAST_MATH"
    ENABLED_SLOWMATH="no"
fi


# fast HUGE math
AC_ARG_ENABLE([fasthugemath],
    [  --enable-fasthugemath   Enable fast math + huge code (default: disabled)],
    [ ENABLED_FASTHUGEMATH=$enableval ],
    [ ENABLED_FASTHUGEMATH=no ]
    )

if test "$ENABLED_BUMP" = "yes"
then
    ENABLED_FASTHUGEMATH="yes"
fi

if test "$ENABLED_FASTHUGEMATH" = "yes"
then
    ENABLED_FASTMATH="yes"
    AM_CFLAGS="$AM_CFLAGS -DUSE_FAST_MATH"
    ENABLED_SLOWMATH="no"
fi

AM_CONDITIONAL([BUILD_FASTMATH], [test "x$ENABLED_FASTMATH" = "xyes"])
AM_CONDITIONAL([BUILD_SLOWMATH], [test "x$ENABLED_SLOWMATH" = "xyes"])

# big cache
AC_ARG_ENABLE([bigcache],
    [  --enable-bigcache       Enable big session cache (default: disabled)],
    [ ENABLED_BIGCACHE=$enableval ],
    [ ENABLED_BIGCACHE=no ]
    )

if test "$ENABLED_BIGCACHE" = "yes"
then
    AM_CFLAGS="$AM_CFLAGS -DBIG_SESSION_CACHE"
fi


# HUGE cache
AC_ARG_ENABLE([hugecache],
    [  --enable-hugecache      Enable huge session cache (default: disabled)],
    [ ENABLED_HUGECACHE=$enableval ],
    [ ENABLED_HUGECACHE=no ]
    )

if test "$ENABLED_HUGECACHE" = "yes"
then
    AM_CFLAGS="$AM_CFLAGS -DHUGE_SESSION_CACHE"
fi


# SMALL cache
AC_ARG_ENABLE([smallcache],
    [  --enable-smallcache     Enable small session cache (default: disabled)],
    [ ENABLED_SMALLCACHE=$enableval ],
    [ ENABLED_SMALLCACHE=no ]
    )

if test "$ENABLED_SMALLCACHE" = "yes"
then
    AM_CFLAGS="$AM_CFLAGS -DSMALL_SESSION_CACHE"
fi


# SNIFFER
AC_ARG_ENABLE([sniffer],
              [AS_HELP_STRING([--enable-sniffer],[ Enable CyaSSL sniffer support (default: disabled) ])],[
               AS_IF([ test "x$enableval" = "xyes" ],[ AC_CHECK_HEADERS([pcap/pcap.h],[ 
                      ENABLED_SNIFFER=yes 
                      AM_CFLAGS="$AM_CFLAGS -DCYASSL_SNIFFER -DOPENSSL_EXTRA"
                      ],[ ENABLED_SNIFFER=no ]) ])
               ],[
                  ENABLED_SNIFFER=no
                  ])

AM_CONDITIONAL([BUILD_SNIFFER], [ test "x$ENABLED_SNIFFER" = "xyes" ])

# AES-GCM
AC_ARG_ENABLE([aesgcm],
    [  --enable-aesgcm         Enable CyaSSL AES-GCM support (default: disabled)],
    [ ENABLED_AESGCM=$enableval ],
    [ ENABLED_AESGCM=no ]
    )

if test "$ENABLED_AESGCM" = "word32"
then
    AM_CFLAGS="$AM_CFLAGS -DGCM_WORD32"
    ENABLED_AESGCM=yes
fi

if test "$ENABLED_AESGCM" = "small"
then
    AM_CFLAGS="$AM_CFLAGS -DGCM_SMALL"
    ENABLED_AESGCM=yes
fi

if test "$ENABLED_AESGCM" = "table"
then
    AM_CFLAGS="$AM_CFLAGS -DGCM_TABLE"
    ENABLED_AESGCM=yes
fi

if test "$ENABLED_AESGCM" = "yes"
then
    AM_CFLAGS="$AM_CFLAGS -DHAVE_AESGCM -DCYASSL_SHA384 -DCYASSL_SHA512"
fi

AM_CONDITIONAL([BUILD_AESGCM], [test "x$ENABLED_AESGCM" = "xyes"])

# AES-NI
AC_ARG_ENABLE([aesni],
    [  --enable-aesni          Enable CyaSSL AES-NI support (default: disabled)],
    [ ENABLED_AESNI=$enableval ],
    [ ENABLED_AESNI=no ]
    )

if test "$ENABLED_AESNI" = "yes"
then
    AM_CFLAGS="$AM_CFLAGS -DCYASSL_AESNI"
    if test "$GCC" = "yes"
    then
        # GCC needs these flags, icc doesn't
        AM_CFLAGS="$AM_CFLAGS -maes -msse4"
    fi
fi

AM_CONDITIONAL([BUILD_AESNI], [test "x$ENABLED_AESNI" = "xyes"])


# MD2
AC_ARG_ENABLE([md2],
    [  --enable-md2            Enable CyaSSL MD2 support (default: disabled)],
    [ ENABLED_MD2=$enableval ],
    [ ENABLED_MD2=no ]
    )

if test "$ENABLED_BUMP" = "yes"
then
    ENABLED_MD2="yes"
fi

if test "$ENABLED_MD2" = "yes"
then
    AM_CFLAGS="$AM_CFLAGS -DCYASSL_MD2"
fi

AM_CONDITIONAL([BUILD_MD2], [test "x$ENABLED_MD2" = "xyes"])


# RIPEMD
AC_ARG_ENABLE([ripemd],
    [  --enable-ripemd         Enable CyaSSL RIPEMD-160 support (default: disabled)],
    [ ENABLED_RIPEMD=$enableval ],
    [ ENABLED_RIPEMD=no ]
    )

if test "$ENABLED_RIPEMD" = "yes"
then
    AM_CFLAGS="$AM_CFLAGS -DCYASSL_RIPEMD"
fi

AM_CONDITIONAL([BUILD_RIPEMD], [test "x$ENABLED_RIPEMD" = "xyes"])


# SHA512
AC_ARG_ENABLE([sha512],
    [  --enable-sha512         Enable CyaSSL SHA-512 support (default: disabled)],
    [ ENABLED_SHA512=$enableval ],
    [ ENABLED_SHA512=no ]
    )

if test "$ENABLED_SHA512" = "yes"
then
    AM_CFLAGS="$AM_CFLAGS -DCYASSL_SHA512"
fi

if test "$ENABLED_FORTRESS" = "yes"
then
    ENABLED_SHA512="yes"
fi

if test "$ENABLED_AESGCM" = "yes"
then
    ENABLED_SHA512="yes"
fi


AM_CONDITIONAL([BUILD_SHA512], [test "x$ENABLED_SHA512" = "xyes"])


# SESSION CERTS
AC_ARG_ENABLE([sessioncerts],
    [  --enable-sessioncerts   Enable session cert storing (default: disabled)],
    [ ENABLED_SESSIONCERTS=$enableval ],
    [ ENABLED_SESSIONCERTS=no ]
    )

if test "$ENABLED_SESSIONCERTS" = "yes"
then
    AM_CFLAGS="$AM_CFLAGS -DSESSION_CERTS"
fi


# KEY GENERATION
AC_ARG_ENABLE([keygen],
    [  --enable-keygen         Enable key generation (default: disabled)],
    [ ENABLED_KEYGEN=$enableval ],
    [ ENABLED_KEYGEN=no ]
    )

if test "$ENABLED_KEYGEN" = "yes"
then
    AM_CFLAGS="$AM_CFLAGS -DCYASSL_KEY_GEN"
fi


# CERT GENERATION
AC_ARG_ENABLE([certgen],
    [  --enable-certgen        Enable cert generation (default: disabled)],
    [ ENABLED_CERTGEN=$enableval ],
    [ ENABLED_CERTGEN=no ]
    )

if test "$ENABLED_CERTGEN" = "yes"
then
    AM_CFLAGS="$AM_CFLAGS -DCYASSL_CERT_GEN"
fi


# HC128 
AC_ARG_ENABLE([hc128],
    [  --enable-hc128          Enable HC-128 (default: disabled)],
    [ ENABLED_HC128=$enableval ],
    [ ENABLED_HC128=no ]
    )

if test "$ENABLED_HC128" = "no"
then
    AM_CFLAGS="$AM_CFLAGS -DNO_HC128"
else
    AM_CFLAGS="$AM_CFLAGS -DHAVE_HC128"
fi

AM_CONDITIONAL([BUILD_HC128], [test "x$ENABLED_HC128" = "xyes"])


# RABBIT
AC_ARG_ENABLE([rabbit],
    [  --enable-rabbit         Enable RABBIT (default: disabled)],
    [ ENABLED_RABBIT=$enableval ],
    [ ENABLED_RABBIT=no ]
    )

if test "$ENABLED_RABBIT" = "no"
then
    AM_CFLAGS="$AM_CFLAGS -DNO_RABBIT"
else
    AM_CFLAGS="$AM_CFLAGS -DHAVE_RABBIT"
fi

AM_CONDITIONAL([BUILD_RABBIT], [test "x$ENABLED_RABBIT" = "xyes"])


# PSK 
AC_ARG_ENABLE([psk],
    [  --enable-psk            Enable PSK (default: disabled)],
    [ ENABLED_PSK=$enableval ],
    [ ENABLED_PSK=no ]
    )

if test "$ENABLED_PSK" = "no" && test "$ENABLED_LEANPSK" = "no"
then
    AM_CFLAGS="$AM_CFLAGS -DNO_PSK"
fi


# Web Server Build 
AC_ARG_ENABLE([webServer],
    [  --enable-webServer      Enable Web Server (default: disabled)],
    [ ENABLED_WEBSERVER=$enableval ],
    [ ENABLED_WEBSERVER=no ]
    )

if test "$ENABLED_WEBSERVER" = "yes"
then
    AM_CFLAGS="$AM_CFLAGS -DHAVE_WEBSERVER"
fi


# No Filesystem Build 
AC_ARG_ENABLE([noFilesystem],
    [  --enable-noFilesystem   Enable No Filesystem (default: disabled)],
    [ ENABLED_NOFILESYSTEM=$enableval ],
    [ ENABLED_NOFILESYSTEM=no ]
    )

if test "$ENABLED_NOFILESYSTEM" = "yes"
then
    AM_CFLAGS="$AM_CFLAGS -DNO_FILESYSTEM"
fi


# No inline Build 
AC_ARG_ENABLE([noInline],
    [  --enable-noInline       Enable No inline (default: disabled)],
    [ ENABLED_NOINLINE=$enableval ],
    [ ENABLED_NOINLINE=no ]
    )

if test "$ENABLED_NOINLINE" = "yes"
then
    AM_CFLAGS="$AM_CFLAGS -DNO_INLINE"
fi

AM_CONDITIONAL([BUILD_NOINLINE], [test "x$ENABLED_NOINLINE" = "xyes"])


# ECC 
AC_ARG_ENABLE([ecc],
    [  --enable-ecc            Enable ECC (default: disabled)],
    [ ENABLED_ECC=$enableval ],
    [ ENABLED_ECC=no ]
    )

if test "$ENABLED_ECC" = "yes"
then
    AM_CFLAGS="$AM_CFLAGS -DHAVE_ECC"
fi

AM_CONDITIONAL([BUILD_ECC], [test "x$ENABLED_ECC" = "xyes"])


if test "$ENABLED_ECC" = "yes" && test "$ENABLED_SMALL" = "yes"
then
    AC_MSG_ERROR([cannot enable ecc and small, ecc requires TLS which small turns off.]) 
fi


# OCSP
AC_ARG_ENABLE([ocsp],
    [  --enable-ocsp           Enable OCSP (default: disabled)],
    [ ENABLED_OCSP=$enableval ],
    [ ENABLED_OCSP=no ],
    )

if test "$ENABLED_OCSP" = "yes"
then
    AM_CFLAGS="$AM_CFLAGS -DHAVE_OCSP"
fi

AM_CONDITIONAL([BUILD_OCSP], [test "x$ENABLED_OCSP" = "xyes"])


# CRL 
AC_ARG_ENABLE([crl],
    [  --enable-crl            Enable CRL (default: disabled)],
    [ ENABLED_CRL=$enableval ],
    [ ENABLED_CRL=no ],
    )

if test "$ENABLED_CRL" = "yes"
then
    AM_CFLAGS="$AM_CFLAGS -DHAVE_CRL"
fi

AM_CONDITIONAL([BUILD_CRL], [test "x$ENABLED_CRL" = "xyes"])


# CRL Monitor
AC_ARG_ENABLE([crl-monitor],
    [  --enable-crl-monitor    Enable CRL Monitor (default: disabled)],
    [ ENABLED_CRL_MONITOR=$enableval ],
    [ ENABLED_CRL_MONITOR=no ],
    )

if test "$ENABLED_CRL_MONITOR" = "yes"
then
    case $host_os in
    *linux* | *darwin* | *freebsd*)
        AM_CFLAGS="$AM_CFLAGS -DHAVE_CRL_MONITOR" ;;
    *)
        AC_MSG_ERROR([crl monitor only allowed on linux, OS X, or freebsd]) ;;
    esac
fi

AM_CONDITIONAL([BUILD_CRL_MONITOR], [test "x$ENABLED_CRL_MONITOR" = "xyes"])


# NTRU
ntruHome=`pwd`/NTRU_algorithm
ntruInclude=$ntruHome/cryptolib
ntruLib=$ntruHome
AC_ARG_ENABLE([ntru],
    [  --enable-ntru           Enable NTRU (default: disabled)],
    [ ENABLED_NTRU=$enableval ],
    [ ENABLED_NTRU=no ]
    )

if test "$ENABLED_NTRU" = "yes"
then
    AM_CFLAGS="$AM_CFLAGS -DHAVE_NTRU -I$ntruInclude"
    AM_LDFLAGS="$AM_LDFLAGS -L$ntruLib"
    LIBS="$LIBS -lntru_encrypt"
fi

AM_CONDITIONAL([BUILD_NTRU], [test "x$ENABLED_NTRU" = "xyes"])

if test "$ENABLED_NTRU" = "yes" && test "$ENABLED_SMALL" = "yes"
then
    AC_MSG_ERROR([cannot enable ntru and small, ntru requires TLS which small turns off.]) 
fi


#valgrind
AC_ARG_ENABLE([valgrind],
    [  --enable-valgrind       Enable valgrind for unit tests (default: disabled)],
    [ ENABLED_VALGRIND=$enableval ],
    [ ENABLED_VALGRIND=no ]
    )

if test "$ENABLED_VALGRIND" = "yes"
then
    AC_CHECK_PROG([HAVE_VALGRIND],[valgrind],[yes],[no])

    if [["$HAVE_VALGRIND" = "no" ]]; then
        AC_MSG_ERROR([Valgrind not found.])
    fi
    enable_shared=no
fi

AM_CONDITIONAL([USE_VALGRIND], [test "x$ENABLED_VALGRIND" = "xyes"])


# Test certs, use internal cert functions for extra testing 
AC_ARG_ENABLE([testcert],
    [  --enable-testcert       Enable Test Cert (default: disabled)],
    [ ENABLED_TESTCERT=$enableval ],
    [ ENABLED_TESTCERT=no ]
    )

if test "$ENABLED_TESTCERT" = "yes"
then
    AM_CFLAGS="$AM_CFLAGS -DCYASSL_TEST_CERT"
fi


# Enable Examples, used to disable examples
AC_ARG_ENABLE([examples],
    [  --enable-examples       Enable Examples  (default: enabled)],
    [ ENABLED_EXAMPLES=$enableval ],
    [ ENABLED_EXAMPLES=yes ]
    )

AS_IF([test "x$ENABLED_SINGLETHREADED" = "xyes"], [ENABLED_EXAMPLES="no"])
AS_IF([test "x$ENABLED_NOFILESYSTEM" = "xyes"], [ENABLED_EXAMPLES="no"])
AM_CONDITIONAL([BUILD_EXAMPLES], [test "x$ENABLED_EXAMPLES" = "xyes"])

# LIBZ
trylibzdir=""
AC_ARG_WITH([libz],
    [  --with-libz=PATH        PATH to libz install (default /usr/) ],
    [
        AC_MSG_CHECKING([for libz])
        CPPFLAGS="$CPPFLAGS -DHAVE_LIBZ"
        LIBS="$LIBS -lz"

        AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <zlib.h>]], [[ deflateInit(0, 8); ]])],[ libz_linked=yes ],[ libz_linked=no ])

        if test "x$libz_linked" == "xno" ; then
            if test "x$withval" != "xno" ; then
                trylibzdir=$withval
            fi
            if test "x$withval" == "xyes" ; then
                trylibzdir="/usr"
            fi

            AM_LDFLAGS="$AM_LDFLAGS -L$trylibzdir/lib"
            CPPFLAGS="$CPPFLAGS -I$trylibzdir/include"

            AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <zlib.h>]], [[ deflateInit(0, 8); ]])],[ libz_linked=yes ],[ libz_linked=no ])

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
    AM_CFLAGS="$AM_CFLAGS -Wall -Wno-unused"
    if test "$ax_enable_debug" = "no"
    then
        if test "$ENABLED_FASTMATH" = "yes"
        then
            AM_CFLAGS="$AM_CFLAGS $OPTIMIZE_FAST_CFLAGS"
            if test "$ENABLED_FASTHUGEMATH" = "yes"
            then
                AM_CFLAGS="$AM_CFLAGS $OPTIMIZE_HUGE_CFLAGS"
            fi
        else
            AM_CFLAGS="$AM_CFLAGS $OPTIMIZE_CFLAGS"
        fi
    fi
fi

LIB_SOCKET_NSL

AC_ARG_ENABLE([gcc-hardening],
AS_HELP_STRING(--enable-gcc-hardening, Enable compiler security checks (default: disabled)),
[if test x$enableval = xyes; then
    AM_CFLAGS="$AM_CFLAGS -D_FORTIFY_SOURCE=2 -fstack-protector-all"
    AM_CFLAGS="$AM_CFLAGS -fwrapv -fPIE -Wstack-protector"
    AM_CFLAGS="$AM_CFLAGS --param ssp-buffer-size=1"
    LDFLAGS="$LDFLAGS -pie"
fi])

AX_HARDEN_CC_COMPILER_FLAGS

# add user C_EXTRA_FLAGS back
CFLAGS="$CFLAGS $USER_C_EXTRA_FLAGS"

CREATE_HEX_VERSION
AC_SUBST([AM_CPPFLAGS])
AC_SUBST([AM_CFLAGS])
AC_SUBST([AM_LDFLAGS])

# FINAL
AC_CONFIG_FILES([stamp-h], [echo timestamp > stamp-h])
AC_CONFIG_FILES([Makefile])
AC_CONFIG_FILES([cyassl/version.h])
AC_CONFIG_FILES([support/libcyassl.pc])
AC_CONFIG_FILES([rpm/spec])

AX_CREATE_GENERIC_CONFIG
AX_AM_JOBSERVER([yes])

AC_OUTPUT

echo "---"
echo "Running make clean..."
make clean >/dev/null 2>&1
echo

echo "---"
echo "Configuration summary for $PACKAGE_NAME version $VERSION"
echo ""
echo "   * Installation prefix:       $prefix"
echo "   * System type:               $host_vendor-$host_os"
echo "   * Host CPU:                  $host_cpu"
echo "   * C Compiler:                $CC_VERSION"
echo "   * C Flags:                   $CFLAGS"
echo "   * C++ Compiler:              $CXX_VERSION"
echo "   * C++ Flags:                 $CXXFLAGS"
echo "   * CPP Flags:                 $CPPFLAGS"
echo "   * LIB Flags:                 $LIB"
echo "   * Debug enabled:             $ax_enable_debug"
echo "   * Warnings as failure:       $ac_cv_warnings_as_errors"
echo "   * make -j:                   $enable_jobserver"
echo "   * VCS checkout:              $ac_cv_vcs_checkout"
echo 
echo "   Features "
echo "   * Single threaded:           $ENABLED_SINGLETHREADED"
echo "   * DTLS:                      $ENABLED_DTLS"
echo "   * Enable extra OpenSSL API:  $ENABLED_OPENSSLEXTRA"
echo "   * fastmath:                  $ENABLED_FASTMATH"
echo "   * sniffer:                   $ENABLED_SNIFFER"
echo "   * AES-NI:                    $ENABLED_AESNI"
echo "   * AES-GCM:                   $ENABLED_AESGCM"
echo "   * RIPEMD:                    $ENABLED_RIPEMD"
echo "   * SHA-512:                   $ENABLED_SHA512"
echo "   * keygen:                    $ENABLED_KEYGEN"
echo "   * certgen:                   $ENABLED_CERTGEN"
echo "   * HC-128:                    $ENABLED_HC128"
echo "   * RABBIT:                    $ENABLED_RABBIT"
echo "   * PSK:                       $ENABLED_PSK"
echo "   * LEANPSK:                   $ENABLED_LEANPSK"
echo "   * ECC:                       $ENABLED_ECC"
echo "   * OCSP:                      $ENABLED_OCSP"
echo "   * CRL:                       $ENABLED_CRL"
echo "   * CRL-MONITOR:               $ENABLED_CRL_MONITOR"
echo "   * NTRU:                      $ENABLED_NTRU"
echo "   * valgrind unit tests:       $ENABLED_VALGRIND"
echo "   * Examples:                  $ENABLED_EXAMPLES"
echo ""
echo "---"

