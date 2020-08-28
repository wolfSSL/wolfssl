AC_DEFUN([AC_PATH_DEFAULT_KERNEL_SOURCE],
[
AC_MSG_CHECKING([for default kernel build root])
if test -d /lib/modules/`uname -r`/build/.config; then
  DEFAULT_KERNEL_ROOT=/lib/modules/`uname -r`/build
  AC_MSG_RESULT([$DEFAULT_KERNEL_ROOT])
elif test -r /usr/src/linux/.config; then
  DEFAULT_KERNEL_ROOT=/usr/src/linux
  AC_MSG_RESULT([$DEFAULT_KERNEL_ROOT])
else
  AC_MSG_RESULT([no default configured kernel found])
fi
])

AC_DEFUN([AC_DEFAULT_KERNEL_ARCH],
[
AC_REQUIRE([AC_PROG_AWK])
AC_MSG_CHECKING([for default kernel arch])
if test -f ${KERNEL_ROOT}/.config; then
  # "# Linux/x86 5.8.1-gentoo Kernel Configuration"
  DEFAULT_KERNEL_ARCH=`$AWK '/^# Linux/\
{split($[]2,arch_fields,"/"); print arch_fields[[2]]; exit(0);}' ${KERNEL_ROOT}/.config`
fi
if test -n "$DEFAULT_KERNEL_ARCH"; then
  AC_MSG_RESULT([$DEFAULT_KERNEL_ARCH])
else
  AC_MSG_RESULT([no default configured kernel arch found])
fi
])
