#!/usr/bin/env bash

set -e
set -x

# Basic TLS test
./mbedtls/build/programs/ssl/ssl_server2 > /tmp/server.log 2>&1 &
SERVER_PID=$!
sleep 0.1
./mbedtls/build/programs/ssl/ssl_client2 # Confirm working with mbed
env -C wolfssl ./examples/client/client -p 4433 -g \
  -A ../mbedtls/framework/data_files/test-ca-sha256.crt \
  -c ../mbedtls/framework/data_files/cli-rsa-sha256.crt \
  -k ../mbedtls/framework/data_files/cli-rsa-sha256.key.pem
kill $SERVER_PID
sleep 0.1
env -C wolfssl ./examples/server/server -p 4433 -i -g \
  -A ../mbedtls/framework/data_files/test-ca-sha256.crt \
  -c ../mbedtls/framework/data_files/server2-sha256.crt \
  -k ../mbedtls/framework/data_files/server2.key.pem > /tmp/server.log 2>&1 &
SERVER_PID=$!
sleep 0.1
./mbedtls/build/programs/ssl/ssl_client2
env -C wolfssl ./examples/client/client -p 4433 -g \
  -A ../mbedtls/framework/data_files/test-ca-sha256.crt \
  -c ../mbedtls/framework/data_files/cli-rsa-sha256.crt \
  -k ../mbedtls/framework/data_files/cli-rsa-sha256.key.pem
kill $SERVER_PID
sleep 0.1

# Basic DTLS test
./mbedtls/build/programs/ssl/ssl_server2 dtls=1 > /tmp/server.log 2>&1 &
SERVER_PID=$!
sleep 0.1
./mbedtls/build/programs/ssl/ssl_client2 dtls=1 # Confirm working with mbed
env -C wolfssl ./examples/client/client -p 4433 -g -u \
  -A ../mbedtls/framework/data_files/test-ca-sha256.crt \
  -c ../mbedtls/framework/data_files/cli-rsa-sha256.crt \
  -k ../mbedtls/framework/data_files/cli-rsa-sha256.key.pem
kill $SERVER_PID
sleep 0.1
env -C wolfssl ./examples/server/server -p 4433 -i -g -u \
  -A ../mbedtls/framework/data_files/test-ca-sha256.crt \
  -c ../mbedtls/framework/data_files/server2-sha256.crt \
  -k ../mbedtls/framework/data_files/server2.key.pem > /tmp/server.log 2>&1 &
SERVER_PID=$!
sleep 0.1
env -C wolfssl ./examples/client/client -p 4433 -g -u \
  -A ../mbedtls/framework/data_files/test-ca-sha256.crt \
  -c ../mbedtls/framework/data_files/cli-rsa-sha256.crt \
  -k ../mbedtls/framework/data_files/cli-rsa-sha256.key.pem
./mbedtls/build/programs/ssl/ssl_client2 dtls=1
kill $SERVER_PID
sleep 0.1

# DTLS 1.2 CID test
./mbedtls/build/programs/ssl/ssl_server2 dtls=1 cid=1 cid_val=121212 > /tmp/server.log 2>&1 &
SERVER_PID=$!
sleep 0.1
./mbedtls/build/programs/ssl/ssl_client2 dtls=1 cid=1 cid_val=232323  # Confirm working with mbed
env -C wolfssl ./examples/client/client -p 4433 -g -u --cid 232323 \
  -A ../mbedtls/framework/data_files/test-ca-sha256.crt \
  -c ../mbedtls/framework/data_files/cli-rsa-sha256.crt \
  -k ../mbedtls/framework/data_files/cli-rsa-sha256.key.pem
kill $SERVER_PID
sleep 0.1
env -C wolfssl ./examples/server/server -p 4433 -i -g -u --cid 121212 \
  -A ../mbedtls/framework/data_files/test-ca-sha256.crt \
  -c ../mbedtls/framework/data_files/server2-sha256.crt \
  -k ../mbedtls/framework/data_files/server2.key.pem > /tmp/server.log 2>&1 &
SERVER_PID=$!
sleep 0.1
./mbedtls/build/programs/ssl/ssl_client2 dtls=1 cid_val=232323
env -C wolfssl ./examples/client/client -p 4433 -g -u --cid 232323 \
  -A ../mbedtls/framework/data_files/test-ca-sha256.crt \
  -c ../mbedtls/framework/data_files/cli-rsa-sha256.crt \
  -k ../mbedtls/framework/data_files/cli-rsa-sha256.key.pem
kill $SERVER_PID
sleep 0.1
