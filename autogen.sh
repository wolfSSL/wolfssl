#!/bin/sh
#
# Create configure and makefile stuff...
#

if test -d .git; then
  WARNINGS="all,error"
else
  WARNINGS="all"
fi

autoreconf --install --force --verbose

if test -d .git; then
    ln -s -f ../../pre-commit.sh .git/hooks/pre-commit
fi
