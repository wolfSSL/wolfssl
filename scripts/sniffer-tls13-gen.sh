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
fi

# Run this script from the wolfSSL root
if [ ! -f wolfssl/ssl.h ]; then
    echo "Run from the wolfssl root"
    exit 1
fi

run_sequence() {
    if [ "$1" == "dh" ] || [ "$1" == "ecc" ]; then
        # TLS v1.3
        ./examples/server/server -v 4 -l TLS13-AES128-GCM-SHA256 &
        sleep 0.1
        ./examples/client/client -v 4 -l TLS13-AES128-GCM-SHA256

        ./examples/server/server -v 4 -l TLS13-AES256-GCM-SHA384 &
        sleep 0.1
        ./examples/client/client -v 4 -l TLS13-AES256-GCM-SHA384

        ./examples/server/server -v 4 -l TLS13-CHACHA20-POLY1305-SHA256 &
        sleep 0.1
        ./examples/client/client -v 4 -l TLS13-CHACHA20-POLY1305-SHA256
    fi
    if [ "$1" == "dh-resume" ] || [ "$1" == "ecc-resume" ]; then
        # TLS v1.3 Resumption
        ./examples/server/server -v 4 -l TLS13-AES128-GCM-SHA256 -r &
        sleep 0.1
        ./examples/client/client -v 4 -l TLS13-AES128-GCM-SHA256 -r

        ./examples/server/server -v 4 -l TLS13-AES256-GCM-SHA384 -r &
        sleep 0.1
        ./examples/client/client -v 4 -l TLS13-AES256-GCM-SHA384 -r

        ./examples/server/server -v 4 -l TLS13-CHACHA20-POLY1305-SHA256 -r &
        sleep 0.1
        ./examples/client/client -v 4 -l TLS13-CHACHA20-POLY1305-SHA256 -r
    fi

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
    fi
    # Run: with x25519_resume
    if [ "$1" == "x25519-resume" ]; then
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

    # TLS v1.3 Hello Retry Request
    if [ "$1" == "hrr" ]; then
        # TLS v1.3 Hello Retry Request
        ./examples/server/server -v 4 -i -x -g &
        sleep 0.1
        ./examples/client/client -v 4 -J
    fi
    sleep 1
}

run_capture(){
    echo "configuring and building wolfssl..."
    ./configure --enable-sniffer $2 1>/dev/null || exit $?
    make 1>/dev/null || exit $?
    echo "starting capture"
    tcpdump -i lo0 -nn port 11111 -w ./scripts/sniffer-tls13-$1.pcap &
    tcpdump_pid=$!
    run_sequence $1
    kill $tcpdump_pid
}

run_capture "ecc"           ""
run_capture "ecc-resume"    "--enable-session-ticket"
run_capture "dh"            "--disable-ecc"
run_capture "dh-resume"     "--disable-ecc --enable-session-ticket"
run_capture "x25519"        "--enable-curve25519 --disable-dh --disable-ecc"
run_capture "x25519-resume" "--enable-curve25519 --disable-dh --disable-ecc --enable-session-ticket"
run_capture "hrr"           "--disable-dh CFLAGS=-DWOLFSSL_SNIFFER_WATCH"
