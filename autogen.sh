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
  ln -s -f ../../pre-push.sh .git/hooks/pre-push
fi

# If this is a source checkout then call autoreconf with error as well
if test -e .git; then
  WARNINGS="all,error"
  # touch fips files for non fips distribution
  touch ./ctaocrypt/src/fips.c
  touch ./ctaocrypt/src/fips_test.c

  # touch async crypt files
  touch ./wolfcrypt/src/async.c
  touch ./wolfssl/wolfcrypt/async.h
else
  WARNINGS="all"
fi

autoreconf --install --force --verbose

