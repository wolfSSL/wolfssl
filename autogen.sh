#!/bin/sh
#
# Create configure and makefile stuff...
#

# Git hooks should come before autoreconf.
if test -d .git; then
  if ! test -d .git/hooks; then
    mkdir .git/hooks
  fi
  ln -s -f ../../pre-commit.sh .git/hooks/pre-commit
fi

# Set HAVE_FIPS_SOURCE to 1 in your .profile if you have access to the FIPS
# repository. (Hint: If you don't work for us, you don't. This will fail.)
if test -n "$HAVE_FIPS_SOURCE" -a ! -d ./fips; then
  git clone git@github.com:wolfSSL/fips.git
  SAVEDIR=`pwd`
  cd ./ctaocrypt/src
  ln -sf ../../fips/fips.c
  ln -sf ../../fips/fips_test.c
  cd $SAVEDIR
fi

# If this is a source checkout then call autoreconf with error as well
if test -d .git; then
  WARNINGS="all,error"
else
  WARNINGS="all"
fi

autoreconf --install --force --verbose

