#!/bin/bash

openssl ocsp -index index.txt       \
             -port 22222            \
             -rsigner ocsp-cert.pem \
             -rkey ocsp-key.pem     \
             -CA ../ca-cert.pem     \
             -nmin 1                \
             -text
