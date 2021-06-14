#!/bin/bash

# Run these configures and the example server/client below
# Script to generate wireshark trace for sniffer-tls13-ecc.pcap
#./configure --enable-sniffer --enable-session-ticket && make

# Script to generate wireshark trace for sniffer-tls13-dh.pcap
#./configure --enable-sniffer --enable-session-ticket --disable-ecc && make

# TLS v1.3
./test_apps/server/server -v 4 -l TLS13-AES128-GCM-SHA256 &
./test_apps/client/client -v 4 -l TLS13-AES128-GCM-SHA256
./test_apps/server/server -v 4 -l TLS13-AES256-GCM-SHA384 &
./test_apps/client/client -v 4 -l TLS13-AES256-GCM-SHA384
./test_apps/server/server -v 4 -l TLS13-CHACHA20-POLY1305-SHA256 &
./test_apps/client/client -v 4 -l TLS13-CHACHA20-POLY1305-SHA256

# TLS v1.3 Resumption
./test_apps/server/server -v 4 -l TLS13-AES128-GCM-SHA256 -r &
./test_apps/client/client -v 4 -l TLS13-AES128-GCM-SHA256 -r
./test_apps/server/server -v 4 -l TLS13-AES256-GCM-SHA384 -r &
./test_apps/client/client -v 4 -l TLS13-AES256-GCM-SHA384 -r
./test_apps/server/server -v 4 -l TLS13-CHACHA20-POLY1305-SHA256 -r &
./test_apps/client/client -v 4 -l TLS13-CHACHA20-POLY1305-SHA256 -r

# TLS v1.3 Hello Retry Request (save this as sniffer-tls13-hrr.pcap)
# ./configure --enable-sniffer CFLAGS="-DWOLFSSL_SNIFFER_WATCH" --disable-dh && make
./test_apps/server/server -v 4 -i -x -g &
./test_apps/client/client -v 4 -J
