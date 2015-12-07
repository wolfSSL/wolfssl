#!/bin/bash

openssl ocsp                         \
    -index index2.txt                \
    -port 22222                      \
    -rsigner ocsp-responder-cert.pem \
    -rkey ocsp-responder-key.pem     \
    -CA intermediate2-ca-cert.pem    \
    -nmin 1                          \
    -text
