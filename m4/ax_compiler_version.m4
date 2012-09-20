AC_DEFUN([AX_C_COMPILER_VERSION],[

    dnl Print version of C compiler
    AC_MSG_CHECKING("C Compiler version--$GCC")
    AS_IF([test "$GCC" = "yes"],[
      CC_VERSION=`$CC --version | sed 1q` ],[
      test "$SUNCC" = "yes"],[
      CC_VERSION=`$CC -V 2>&1 | sed 1q` ],[
      test "$CLANG" = "yes"],[
      CC_VERSION=`$CC --version 2>&1 | sed 1q` ],[
      CC_VERSION=""
      ])
    AC_MSG_RESULT("$CC_VERSION")
    AC_SUBST(CC_VERSION)
    ])


AC_DEFUN([AX_CXX_COMPILER_VERSION], [

    dnl Check C version while at it
    AC_REQUIRE([AX_C_COMPILER_VERSION])

    dnl Print version of CXX compiler
    AC_MSG_CHECKING("C++ Compiler version")
    AS_IF([test "$GCC" = "yes"],[
      CXX_VERSION=`$CXX --version | sed 1q` ],[
      test "$SUNCC" = "yes"],[
      CXX_VERSION=`$CXX -V 2>&1 | sed 1q` ],[
      test "$CLANG" = "yes"],[
      CXX_VERSION=`$CXX --version 2>&1 | sed 1q` ],[
      CXX_VERSION=""
      ])
    AC_MSG_RESULT("$CXX_VERSION")
    AC_SUBST(CXX_VERSION)
  ])

