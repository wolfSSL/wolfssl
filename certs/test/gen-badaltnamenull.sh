#!/bin/sh

echo "step 1 create key"
openssl genrsa -out server-badaltnamenull.key 2048

echo "step 2 create csr"
echo "US\nMontana\nBozeman\nEngineering\nlocalhost\n.\n" | openssl req -new -sha256 -out server-badaltnamenull.csr -key server-badaltnamenull.key -config server-badaltnamenull.conf

echo "step 3 check csr"
openssl req -text -noout -in server-badaltnamenull.csr

echo "step 4 create cert"
openssl x509 -req -days 1000 -in server-badaltnamenull.csr -signkey server-badaltnamenull.key \
             -out server-badaltnamenull.pem -extensions req_ext -extfile server-badaltnamenull.conf

echo "step 5 make human reviewable"
openssl x509 -inform pem -in server-badaltnamenull.pem -text > tmp.pem
mv tmp.pem server-badaltnamenull.pem

openssl x509 -inform pem -in server-badaltnamenull.pem -outform der -out server-badaltnamenull.der
