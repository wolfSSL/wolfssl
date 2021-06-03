#!/bin/bash

# Run these configures and the example server/client below
# Script to generate wireshark trace for sniffer-tls13-ecc.pcap
#./configure --enable-sniffer --enable-session-ticket && make

# Script to generate wireshark trace for sniffer-tls13-dh.pcap
#./configure --enable-sniffer --enable-session-ticket --disable-ecc && make

# TLS v1.3
./testApps/server/server -v 4 -l TLS13-AES128-GCM-SHA256 &
./testApps/client/client -v 4 -l TLS13-AES128-GCM-SHA256
./testApps/server/server -v 4 -l TLS13-AES256-GCM-SHA384 &
./testApps/client/client -v 4 -l TLS13-AES256-GCM-SHA384
./testApps/server/server -v 4 -l TLS13-CHACHA20-POLY1305-SHA256 &
./testApps/client/client -v 4 -l TLS13-CHACHA20-POLY1305-SHA256

# TLS v1.3 Resumption
./testApps/server/server -v 4 -l TLS13-AES128-GCM-SHA256 -r &
./testApps/client/client -v 4 -l TLS13-AES128-GCM-SHA256 -r
./testApps/server/server -v 4 -l TLS13-AES256-GCM-SHA384 -r &
./testApps/client/client -v 4 -l TLS13-AES256-GCM-SHA384 -r
./testApps/server/server -v 4 -l TLS13-CHACHA20-POLY1305-SHA256 -r &
./testApps/client/client -v 4 -l TLS13-CHACHA20-POLY1305-SHA256 -r

# TLS v1.3 Hello Retry Request (save this as sniffer-tls13-hrr.pcap)
# ./configure --enable-sniffer CFLAGS="-DWOLFSSL_SNIFFER_WATCH" --disable-dh && make
./testApps/server/server -v 4 -i -x -g &
./testApps/client/client -v 4 -J
