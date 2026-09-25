#!/usr/bin/env bash

./autogen.sh
./configure --enable-certgen --enable-certreq --enable-certext --enable-pkcs7 --enable-cryptocb --enable-aescfb
make

