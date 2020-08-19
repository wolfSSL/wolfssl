AC_DEFUN([AC_PATH_DEFAULT_KERNEL_SOURCE],
[
AC_MSG_CHECKING([for default kernel build root])
if test -d /lib/modules/`uname -r`/build/.config; then
  DEFAULT_KROOT=/lib/modules/`uname -r`/build
  AC_MSG_RESULT([$DEFAULT_KROOT])
elif test -r /usr/src/linux/.config; then
  DEFAULT_KROOT=/usr/src/linux
  AC_MSG_RESULT([$DEFAULT_KROOT])
else
  AC_MSG_RESULT([no default configured kernel found])
fi
])

AC_DEFUN([AC_DEFAULT_KERNEL_ARCH],
[
AC_REQUIRE([AC_PROG_AWK])
AC_MSG_CHECKING([for default kernel arch])
if test -f ${KROOT}/.config; then
  # "# Linux/x86 5.8.1-gentoo Kernel Configuration"
  DEFAULT_KARCH=`$AWK '/^# Linux/\
{split($[]2,arch_fields,"/"); print arch_fields[[2]]; exit(0);}' ${KROOT}/.config`
fi
if test -n "$DEFAULT_KARCH"; then
  AC_MSG_RESULT([$DEFAULT_KARCH])
else
  AC_MSG_RESULT([no default configured kernel arch found])
fi
])
