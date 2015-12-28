#!/bin/bash

openssl ocsp -port 22220 -nmin 1                \
    -index   certs/ocsp/index0.txt              \
    -rsigner certs/ocsp/ocsp-responder-cert.pem \
    -rkey    certs/ocsp/ocsp-responder-key.pem  \
    -CA      certs/ocsp/root-ca-cert.pem        \
    $@
