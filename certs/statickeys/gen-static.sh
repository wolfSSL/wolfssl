#!/bin/bash

# run from wolfssl root

# SECP256R1
openssl ecparam -name secp256r1 -genkey -noout -out certs/statickeys/ecc-secp256r1.pem -noout
openssl ec -inform pem -in certs/statickeys/ecc-secp256r1.pem -outform der -out certs/statickeys/ecc-secp256r1.der

# DH 2048-bit (keySz = 29)
# Using one generated and capture with wolfSSL using wc_DhGenerateKeyPair (openssl generates DH keys with 2048-bits... based on the DH "p" prime size)
#openssl genpkey -paramfile certs/statickeys/dh-ffdhe2048-params.pem -out certs/statickeys/dh-ffdhe2048.der
openssl pkey -inform der -in certs/statickeys/dh-ffdhe2048.der -outform pem -out certs/statickeys/dh-ffdhe2048.pem
