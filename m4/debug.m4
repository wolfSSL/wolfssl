AC_DEFUN([AX_DEBUG],[
  AC_ARG_WITH([debug],
    [AS_HELP_STRING([--with-debug],
       [Add debug code/turns off optimizations (yes|no) @<:@default=no@:>@])],
    [ax_with_debug=$withval],
    [ax_with_debug=no])
  AS_IF([test "$ax_with_debug" = "yes"],[
    # Debugging. No optimization.
    AM_CFLAGS="${AM_CFLAGS} ${DEBUG_CFLAGS} -DDEBUG"
    AM_CXXFLAGS="${AM_CXXFLAGS} ${DEBUG_CXXFLAGS} -DDEBUG"
    AC_DEFINE(DEBUG, [ 1 ], [Define to 1 to enable debugging code.])
  ],[
    # Optimized version. No debug
    AM_CFLAGS="${AM_CFLAGS} ${OPTIMIZE_CFLAGS}"
    AM_CXXFLAGS="${AM_CXXFLAGS} ${OPTIMIZE_CXXFLAGS}"
    AC_DEFINE(DEBUG, [ 0 ], [Define to 1 to enable debugging code.])
  ])
])
