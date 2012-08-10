#!/bin/sh
#
# Create configure and makefile stuff...
#

autoreconf -ivf -Wall
ln -s -f ../../pre-commit.sh .git/hooks/pre-commit
