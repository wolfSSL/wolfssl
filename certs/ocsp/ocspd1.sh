#!/bin/bash

openssl ocsp                         \
    -index index1.txt                \
    -port 22221                      \
    -rsigner ocsp-responder-cert.pem \
    -rkey ocsp-responder-key.pem     \
    -CA intermediate1-ca-cert.pem    \
    -nmin 1                          \
    -text
