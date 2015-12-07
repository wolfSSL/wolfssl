#!/bin/bash

openssl ocsp                         \
    -index index0.txt                \
    -port 22220                      \
    -rsigner ocsp-responder-cert.pem \
    -rkey ocsp-responder-key.pem     \
    -CA root-ca-cert.pem             \
    -nmin 1                          \
    -text
