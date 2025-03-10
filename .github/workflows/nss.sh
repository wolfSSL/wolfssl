#!/usr/bin/env bash

set -e
set -x

# Setup nss cert db
mkdir nssdb
./dist/Debug/bin/certutil -d nssdb -N --empty-password
./dist/Debug/bin/certutil -d nssdb  -A -a -i  wolfssl/certs/test/server-localhost.pem \
    -t TCP -n 'wolf localhost'

# App data for nss
echo Hello from nss > /tmp/in

# TLS 1.3 test
env -C wolfssl ./examples/server/server -v 4 -p 4433 \
    -c certs/test/server-localhost.pem -d -w > /tmp/server.log 2>&1 &
sleep 0.1
./dist/Debug/bin/tstclnt -V tls1.3: -h localhost -p 4433 -d nssdb -C -4 -A /tmp/in -v
sleep 0.1

# DTLS 1.3 test
env -C wolfssl ./examples/server/server -v 4 -p 4433 -u \
    -c certs/test/server-localhost.pem -d -w > /tmp/server.log 2>&1 &
sleep 0.1
./dist/Debug/bin/tstclnt -V tls1.3: -P client -h localhost -p 4433 -d nssdb -C -4 -A /tmp/in -v
sleep 0.1
