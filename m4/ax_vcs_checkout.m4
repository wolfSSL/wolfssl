# ===========================================================================
#      http://
# ===========================================================================
#
# SYNOPSIS
#
#   AX_VCS_CHECKOUT
#
# DESCRIPTION
#
#   Discover whether or not we are operating with a tree which
#   has been checked out of a version control system.
#
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

#serial 1
 
AC_DEFUN([AX_VCS_CHECKOUT],[
    AC_CACHE_CHECK([for vcs checkout], [ac_cv_vcs_checkout], [
      AS_IF([test -d ".bzr"],[ac_cv_vcs_checkout=yes])
      AS_IF([test -d ".svn"],[ac_cv_vcs_checkout=yes])
      AS_IF([test -d ".hg"], [ac_cv_vcs_checkout=yes])
      AS_IF([test -d ".git"],[ac_cv_vcs_checkout=yes])
      ])

    AS_IF([test "$ac_cv_vcs_checkout" = yes], [])
    ])
