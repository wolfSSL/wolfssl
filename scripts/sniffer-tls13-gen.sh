#!/bin/bash

# Run these configures and the example server/client below
# Script to generate wireshark trace for sniffer-tls13-ecc.pcap
#./configure --enable-sniffer --enable-session-ticket && make

# Script to generate wireshark trace for sniffer-tls13-dh.pcap
#./configure --enable-sniffer --enable-session-ticket --disable-ecc && make

# Run: with dh or ecc
if [ "$1" == "dh" ] || [ "$1" == "ecc" ]; then
    # TLS v1.3
    ./examples/server/server -v 4 -l TLS13-AES128-GCM-SHA256 &
    ./examples/client/client -v 4 -l TLS13-AES128-GCM-SHA256
    ./examples/server/server -v 4 -l TLS13-AES256-GCM-SHA384 &
    ./examples/client/client -v 4 -l TLS13-AES256-GCM-SHA384
    ./examples/server/server -v 4 -l TLS13-CHACHA20-POLY1305-SHA256 &
    ./examples/client/client -v 4 -l TLS13-CHACHA20-POLY1305-SHA256

    # TLS v1.3 Resumption
    ./examples/server/server -v 4 -l TLS13-AES128-GCM-SHA256 -r &
    ./examples/client/client -v 4 -l TLS13-AES128-GCM-SHA256 -r
    ./examples/server/server -v 4 -l TLS13-AES256-GCM-SHA384 -r &
    ./examples/client/client -v 4 -l TLS13-AES256-GCM-SHA384 -r
    ./examples/server/server -v 4 -l TLS13-CHACHA20-POLY1305-SHA256 -r &
    ./examples/client/client -v 4 -l TLS13-CHACHA20-POLY1305-SHA256 -r
fi

# Script to generate wireshark trace for sniffer-tls13-x25519.pcap
#./configure --enable-sniffer --enable-session-ticket --enable-curve25519 --disable-dh --disable-ecc && make
# Run: with x25519
if [ "$1" == "x25519" ]; then
    # TLS v1.3
    ./examples/server/server -v 4 -l TLS13-AES128-GCM-SHA256 -c ./certs/ed25519/server-ed25519.pem -k ./certs/ed25519/server-ed25519-priv.pem -A ./certs/ed25519/client-ed25519.pem &
    sleep 0.1
    ./examples/client/client -v 4 -l TLS13-AES128-GCM-SHA256 -c ./certs/ed25519/client-ed25519.pem -k ./certs/ed25519/client-ed25519-priv.pem -A ./certs/ed25519/root-ed25519.pem

    ./examples/server/server -v 4 -l TLS13-AES256-GCM-SHA384 -c ./certs/ed25519/server-ed25519.pem -k ./certs/ed25519/server-ed25519-priv.pem -A ./certs/ed25519/client-ed25519.pem &
    sleep 0.1
    ./examples/client/client -v 4 -l TLS13-AES256-GCM-SHA384 -c ./certs/ed25519/client-ed25519.pem -k ./certs/ed25519/client-ed25519-priv.pem -A ./certs/ed25519/root-ed25519.pem

    ./examples/server/server -v 4 -l TLS13-CHACHA20-POLY1305-SHA256 -c ./certs/ed25519/server-ed25519.pem -k ./certs/ed25519/server-ed25519-priv.pem -A ./certs/ed25519/client-ed25519.pem &
    sleep 0.1
    ./examples/client/client -v 4 -l TLS13-CHACHA20-POLY1305-SHA256 -c ./certs/ed25519/client-ed25519.pem -k ./certs/ed25519/client-ed25519-priv.pem -A ./certs/ed25519/root-ed25519.pem

    # TLS v1.3 Resumption
    ./examples/server/server -v 4 -l TLS13-AES128-GCM-SHA256 -r -c ./certs/ed25519/server-ed25519.pem -k ./certs/ed25519/server-ed25519-priv.pem -A ./certs/ed25519/client-ed25519.pem &
    sleep 0.1
    ./examples/client/client -v 4 -l TLS13-AES128-GCM-SHA256 -r -c ./certs/ed25519/client-ed25519.pem -k ./certs/ed25519/client-ed25519-priv.pem -A ./certs/ed25519/root-ed25519.pem

    ./examples/server/server -v 4 -l TLS13-AES256-GCM-SHA384 -r -c ./certs/ed25519/server-ed25519.pem -k ./certs/ed25519/server-ed25519-priv.pem -A ./certs/ed25519/client-ed25519.pem &
    sleep 0.1
    ./examples/client/client -v 4 -l TLS13-AES256-GCM-SHA384 -r -c ./certs/ed25519/client-ed25519.pem -k ./certs/ed25519/client-ed25519-priv.pem -A ./certs/ed25519/root-ed25519.pem

    ./examples/server/server -v 4 -l TLS13-CHACHA20-POLY1305-SHA256 -r -c ./certs/ed25519/server-ed25519.pem -k ./certs/ed25519/server-ed25519-priv.pem -A ./certs/ed25519/client-ed25519.pem &
    sleep 0.1
    ./examples/client/client -v 4 -l TLS13-CHACHA20-POLY1305-SHA256 -r -c ./certs/ed25519/client-ed25519.pem -k ./certs/ed25519/client-ed25519-priv.pem -A ./certs/ed25519/root-ed25519.pem
fi

# TLS v1.3 Hello Retry Request (save this as sniffer-tls13-hrr.pcap)
# ./configure --enable-sniffer CFLAGS="-DWOLFSSL_SNIFFER_WATCH" --disable-dh && make

# Run ./scripts/sniffer-tls13-gen.sh hrr
if [ "$1" == "hrr" ]; then
    # TLS v1.3 Hello Retry Request 
    ./examples/server/server -v 4 -i -x -g &
    sleep 0.1

    ./examples/client/client -v 4 -J
fi
