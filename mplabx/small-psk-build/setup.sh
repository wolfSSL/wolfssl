#!/bin/bash

cp -r ../../wolfssl ../../../tls/
cp psk-tls.c ../../../tls/
cp psk-ssl.c ../../../tls/
cp user_settings.h ../../../tls/
cp ../../wolfcrypt/src/random.c ../../../tls/
cp ../../wolfcrypt/src/aes.c ../../../tls/
cp ../../wolfcrypt/src/hmac.c ../../../tls/
cp ../../wolfcrypt/src/sha256.c ../../../tls/
cp ../../wolfcrypt/src/misc.c ../../../tls/

