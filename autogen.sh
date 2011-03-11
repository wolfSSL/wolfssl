#!/bin/sh
#
# Create configure and makefile stuff...
#

set -e

autoreconf -ivf
aclocal -I m4
autoheader
autoconf
automake --add-missing --copy
