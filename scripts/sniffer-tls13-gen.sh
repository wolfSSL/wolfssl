#!/bin/bash

# Run these configures and the example server/client below
# Script to generate wireshark trace for sniffer-tls13-ecc.pcap
#./configure --enable-sniffer --enable-session-ticket && make

# Script to generate wireshark trace for sniffer-tls13-dh.pcap
#./configure --enable-sniffer --enable-session-ticket --disable-ecc && make

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
