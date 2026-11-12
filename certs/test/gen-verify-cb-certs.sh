#!/bin/sh
# Generates certs with the name and key of ../ca-cert.pem for the verify
# callback tests. Run from certs/test.
#  server-self-issued-cert.pem: server cert with the CA's name as subject and
#    issuer, signed by the CA.
#  ca-cert-unknown-crit-ext.pem: the CA with an unknown critical extension.

ext=$(mktemp) || exit 1
csr=$(mktemp) || exit 1
subj=$(openssl x509 -in ../ca-cert.pem -noout -subject -nameopt compat | \
    sed 's/^subject=//')

cat > "$ext" <<EOT
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
EOT
openssl req -new -key ../server-key.pem -subj "$subj" -out "$csr" &&
openssl x509 -req -in "$csr" -CA ../ca-cert.pem -CAkey ../ca-key.pem \
    -set_serial 0x5e1f155ed -days 3650 -sha256 -extfile "$ext" \
    -out server-self-issued-cert.pem
ret=$?

if [ $ret -eq 0 ]; then
    cat > "$ext" <<EOT
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
1.3.6.1.4.1.50263.1 = critical, ASN1:NULL
EOT
    openssl req -new -key ../ca-key.pem -subj "$subj" -out "$csr" &&
    openssl x509 -req -in "$csr" -signkey ../ca-key.pem \
        -set_serial 0x5e1fca -days 3650 -sha256 -extfile "$ext" \
        -out ca-cert-unknown-crit-ext.pem
    ret=$?
fi
rm -f "$ext" "$csr"
exit $ret
