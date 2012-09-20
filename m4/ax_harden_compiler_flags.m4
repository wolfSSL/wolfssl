# ===========================================================================
#      http://www.gnu.org/software/autoconf-archive/ax_append_flag.html
# ===========================================================================
#
# SYNOPSIS
#
#   AX_HARDEN_COMPILER_FLAGS
#
# DESCRIPTION
#
#   Any compiler flag that "hardens" or tests code. C99 is assumed.
#
#   NOTE: Implementation based on AX_APPEND_FLAG.
#
# LICENSE
#
#  Copyright (C) 2012 Brian Aker
#  All rights reserved.
#  
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions are
#  met:
#  
#      * Redistributions of source code must retain the above copyright
#  notice, this list of conditions and the following disclaimer.
#  
#      * Redistributions in binary form must reproduce the above
#  copyright notice, this list of conditions and the following disclaimer
#  in the documentation and/or other materials provided with the
#  distribution.
#  
#      * The names of its contributors may not be used to endorse or
#  promote products derived from this software without specific prior
#  written permission.
#  
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
#  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
#  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
#  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
#  OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
#  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
#  LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
#  DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
#  THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
#  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
#  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# The Following flags are not checked for
# -Wdeclaration-after-statement is counter to C99
# AX_APPEND_COMPILE_FLAGS([-std=c++11]) -- Not ready yet
# AX_APPEND_COMPILE_FLAGS([-pedantic]) -- ?
# AX_APPEND_COMPILE_FLAGS([-Wstack-protector]) -- Issues on 32bit compile
# AX_APPEND_COMPILE_FLAGS([-fstack-protector-all]) -- Issues on 32bit compile
# AX_APPEND_COMPILE_FLAGS([-Wlong-long]) -- Don't turn on for compatibility issues memcached_stat_st

#serial 2
  AC_DEFUN([AX_HARDEN_LINKER_FLAGS], [
      AC_REQUIRE([AX_CHECK_LINK_FLAG])
      AC_REQUIRE([AX_VCS_CHECKOUT])
      AC_REQUIRE([AX_DEBUG])

      AS_IF([test "$ac_cv_vcs_checkout" = yes], [
          AX_CHECK_LINK_FLAG([-Werror])
          ])
      AX_CHECK_LINK_FLAG([-z relro -z now])
      ])

  AC_DEFUN([AX_HARDEN_C_COMPILER_FLAGS], [
      AC_REQUIRE([AX_APPEND_COMPILE_FLAGS])
      AC_REQUIRE([AX_HARDEN_LINKER_FLAGS])

      AC_LANG_PUSH([C])
      AS_IF([test "$ax_with_debug" = yes], [
        AX_APPEND_COMPILE_FLAGS([-O0])],[
        AX_APPEND_COMPILE_FLAGS([-O2])
        ])

      ac_cv_warnings_as_errors=no
      AS_IF([test "$ac_cv_vcs_checkout" = yes], [
        AX_APPEND_COMPILE_FLAGS([-Werror])
        ac_cv_warnings_as_errors=yes
        ])

      AX_APPEND_COMPILE_FLAGS([-Wall])
      AX_APPEND_COMPILE_FLAGS([-Wextra])
      AX_APPEND_COMPILE_FLAGS([-std=c99])
      AX_APPEND_COMPILE_FLAGS([-Wbad-function-cast])
      AX_APPEND_COMPILE_FLAGS([-Wmissing-prototypes])
      AX_APPEND_COMPILE_FLAGS([-Wnested-externs])
      AX_APPEND_COMPILE_FLAGS([-Wold-style-definition])
      AX_APPEND_COMPILE_FLAGS([-Woverride-init])
      AX_APPEND_COMPILE_FLAGS([-Wstrict-prototypes])
      AX_APPEND_COMPILE_FLAGS([-Wlogical-op])
      AC_LANG_POP

      ])

  AC_DEFUN([AX_HARDEN_CC_COMPILER_FLAGS], [
      AC_REQUIRE([AX_HARDEN_C_COMPILER_FLAGS])
      AC_LANG_PUSH([C++])

      AS_IF([test "$ax_with_debug" = yes], [
        AX_APPEND_COMPILE_FLAGS([-O0])],[
        AX_APPEND_COMPILE_FLAGS([-O2])
        AX_APPEND_COMPILE_FLAGS([-D_FORTIFY_SOURCE=2])
        ])

      AS_IF([test "$ac_cv_vcs_checkout" = yes], [
        AX_APPEND_COMPILE_FLAGS([-Werror])
        ])

      AX_APPEND_COMPILE_FLAGS([-Wall])
      AX_APPEND_COMPILE_FLAGS([-Wextra])
      AX_APPEND_COMPILE_FLAGS([-Wpragmas])
      AX_APPEND_COMPILE_FLAGS([--paramssp-buffer-size=1])
      AX_APPEND_COMPILE_FLAGS([-Waddress])
      AX_APPEND_COMPILE_FLAGS([-Warray-bounds])
      AX_APPEND_COMPILE_FLAGS([-Wchar-subscripts])
      AX_APPEND_COMPILE_FLAGS([-Wcomment])
      AX_APPEND_COMPILE_FLAGS([-Wctor-dtor-privacy])
      AX_APPEND_COMPILE_FLAGS([-Wfloat-equal])
      AX_APPEND_COMPILE_FLAGS([-Wformat=2])
      AX_APPEND_COMPILE_FLAGS([-Wmaybe-uninitialized])
      AX_APPEND_COMPILE_FLAGS([-Wmissing-field-initializers])
      AX_APPEND_COMPILE_FLAGS([-Wmissing-noreturn])
      AX_APPEND_COMPILE_FLAGS([-Wlogical-op])
      AX_APPEND_COMPILE_FLAGS([-Wnon-virtual-dtor])
      AX_APPEND_COMPILE_FLAGS([-Wnormalized=id])
      AX_APPEND_COMPILE_FLAGS([-Woverloaded-virtual])
      AX_APPEND_COMPILE_FLAGS([-Wpointer-arith])
      AX_APPEND_COMPILE_FLAGS([-Wredundant-decls])
      AX_APPEND_COMPILE_FLAGS([-Wshadow])
      AX_APPEND_COMPILE_FLAGS([-Wshorten-64-to-32])
      AX_APPEND_COMPILE_FLAGS([-Wsign-compare])
      AX_APPEND_COMPILE_FLAGS([-Wstrict-overflow=1])
      AX_APPEND_COMPILE_FLAGS([-Wswitch-enum])
      AX_APPEND_COMPILE_FLAGS([-Wundef])
      AX_APPEND_COMPILE_FLAGS([-Wunused-result])
      AX_APPEND_COMPILE_FLAGS([-Wunused-variable])
      AX_APPEND_COMPILE_FLAGS([-Wwrite-strings])
      AX_APPEND_COMPILE_FLAGS([-floop-parallelize-all])
      AX_APPEND_COMPILE_FLAGS([-fwrapv])
      AX_APPEND_COMPILE_FLAGS([-ggdb])
      AC_LANG_POP
  ])
