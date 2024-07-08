#!/bin/sh

TMP="/tmp/`basename $0`"

KEY=certs/server-key.der
gen_cert() {
    openssl req -x509 -keyform DER -key $KEY \
      -days 1000 -new -outform DER -out $OUT.der -config $CONFIG \
        >$TMP 2>&1

    if [ "$?" = "0" -a -f $OUT.der ]; then
        echo "Created: $OUT"
    else
        cat $TMP
        echo "Failed:  $OUT"
    fi

    openssl x509 -in $OUT.der -inform DER -outform PEM > $OUT.pem

    rm $TMP
}

OUT=certs/test/cert-ext-nc
KEYFILE=certs/test/cert-ext-nc-key.der
CONFIG=certs/test/cert-ext-nc.cfg
tee >$CONFIG <<EOF
[ req ]
distinguished_name = req_distinguished_name
prompt             = no
x509_extensions    = v3_ca

[ req_distinguished_name ]
C             = AU
ST            = Queensland
L             = Brisbane
O             = wolfSSL Inc
OU            = Engineering
CN            = www.wolfssl.com

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
nameConstraints = critical,permitted;email:.wolfssl.com
nsComment       = "Testing name constraints"

EOF
gen_cert


OUT=certs/test/cert-ext-mnc
KEYFILE=certs/test/cert-ext-mnc-key.der
CONFIG=certs/test/cert-ext-mnc.cfg
tee >$CONFIG <<EOF
[ req ]
distinguished_name = req_distinguished_name
prompt             = no
x509_extensions    = v3_ca

[ req_distinguished_name ]
C             = AU
ST            = Queensland
L             = Brisbane
O             = wolfSSL Inc
OU            = Engineering
CN            = www.wolfssl.com

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
nameConstraints = critical,permitted;email:.wolfssl.com, permitted;email:.example.com
nsComment       = "Testing name constraints"

EOF
gen_cert
rm -f ./certs/test/cert-ext-mnc.cfg
rm -f ./certs/test/cert-ext-mnc.pem


OUT=certs/test/cert-ext-ncdns
KEYFILE=certs/test/cert-ext-nc-key.der
CONFIG=certs/test/cert-ext-ncdns.cfg
tee >$CONFIG <<EOF
[ req ]
distinguished_name = req_distinguished_name
prompt             = no
x509_extensions    = v3_ca

[ req_distinguished_name ]
C             = AU
ST            = Queensland
L             = Brisbane
O             = wolfSSL Inc
OU            = Engineering
CN            = www.wolfssl.com

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
nameConstraints = critical,permitted;DNS:wolfssl.com, permitted;DNS:example.com
nsComment       = "Testing name constraints"

EOF
gen_cert
rm -f ./certs/test/cert-ext-ncdns.cfg
rm -f ./certs/test/cert-ext-ncdns.pem

OUT=certs/test/cert-ext-ncmixed
KEYFILE=certs/test/cert-ext-ncmixed-key.der
CONFIG=certs/test/cert-ext-ncmixed.cfg
tee >$CONFIG <<EOF
[ req ]
distinguished_name = req_distinguished_name
prompt             = no
x509_extensions    = v3_ca

[ req_distinguished_name ]
C             = AU
ST            = Queensland
L             = Brisbane
O             = wolfSSL Inc
OU            = Engineering
CN            = www.wolfssl.com

[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
nameConstraints = critical,permitted;DNS:example, permitted;email:.wolfssl.com
nsComment       = "Testing name constraints"

EOF
gen_cert
rm -f ./certs/test/cert-ext-ncmixed.cfg
rm -f ./certs/test/cert-ext-ncmixed.pem

OUT=certs/test/cert-ext-ia
KEYFILE=certs/test/cert-ext-ia-key.der
CONFIG=certs/test/cert-ext-ia.cfg
tee >$CONFIG <<EOF
[ req ]
distinguished_name = req_distinguished_name
prompt             = no
x509_extensions    = v3_ca

[ req_distinguished_name ]
C             = AU
ST            = Queensland
L             = Brisbane
O             = wolfSSL Inc
OU            = Engineering
CN            = www.wolfssl.com
emailAddress  = support@wolfssl.com

[ v3_ca ]
inhibitAnyPolicy = critical,1
nsComment        = "Testing inhibit any"

EOF
gen_cert

OUT=certs/test/cert-ext-nct
KEYFILE=certs/test/cert-ext-mct-key.der
CONFIG=certs/test/cert-ext-nct.cfg
tee >$CONFIG <<EOF
[ req ]
distinguished_name = req_distinguished_name
prompt             = no
x509_extensions    = v3_ca

[ req_distinguished_name ]
C             = AU
ST            = Queensland
L             = Brisbane
O             = wolfSSL Inc
OU            = Engineering
CN            = www.wolfssl.com
emailAddress  = support@wolfssl.com

[ v3_ca ]
nsCertType       = critical,server
nsComment        = "Testing Netscape Certificate Type"

EOF
gen_cert

KEY=certs/ca-key.der
OUT=certs/test/cert-ext-ndir
KEYFILE=certs/ca-key.der
CONFIG=certs/test/cert-ext-ndir.cfg
tee >$CONFIG <<EOF
[ req ]
distinguished_name = req_distinguished_name
prompt             = no
x509_extensions    = constraints

[ req_distinguished_name ]
C             = US
ST            = Montana
L             = Bozeman
O             = Sawtooth
OU            = Consulting
CN            = www.wolfssl.com
emailAddress  = info@wolfsssl.com

[constraints]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer:always
basicConstraints=CA:TRUE
nameConstraints=critical,permitted;dirName:dir_name

[dir_name]
countryName = US

EOF
gen_cert

OUT=certs/test/cert-ext-ndir-exc
KEYFILE=certs/ca-key.der
CONFIG=certs/test/cert-ext-ndir-exc.cfg
tee >$CONFIG <<EOF
[ req ]
distinguished_name = req_distinguished_name
prompt             = no
x509_extensions    = constraints

[ req_distinguished_name ]
C             = US
ST            = Montana
L             = Bozeman
O             = Sawtooth
OU            = Consulting
CN            = www.wolfssl.com
emailAddress  = info@wolfsssl.com

[constraints]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer:always
basicConstraints=CA:TRUE
nameConstraints=critical,excluded;dirName:dir_name_exclude

[dir_name_exclude]
countryName = US
stateOrProvinceName = California

EOF
gen_cert

OUT=certs/test/cert-ext-joi
KEYFILE=certs/ca-key.der
CONFIG=certs/test/cert-ext-joi.cfg
tee >$CONFIG <<EOF
[ req ]
distinguished_name = req_distinguished_name
prompt             = no
x509_extensions    = constraints

[ req_distinguished_name ]
C             = US
ST            = Montana
L             = Bozeman
O             = Sawtooth
OU            = Consulting
CN            = www.wolfssl.com
emailAddress  = info@wolfsssl.com
jurisdictionC = US
jurisdictionST = California

[constraints]
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid:always,issuer:always
basicConstraints=CA:TRUE

EOF
gen_cert

OUT=certs/test/cert-ext-multiple
KEYFILE=certs/test/cert-ext-mct-key.der
CONFIG=certs/test/cert-ext-multiple.cfg
tee >$CONFIG <<EOF
[ req ]
distinguished_name = req_distinguished_name
prompt             = no
x509_extensions    = v3_ca

[ req_distinguished_name ]
C             = AU
ST            = Queensland
L             = Brisbane
O             = wolfSSL Inc
OU            = Engineering
CN            = www.wolfssl.com
emailAddress  = support@wolfssl.com
postalCode    = 56-131
street        = Main St

[ v3_ca ]
nsCertType       = server
crlDistributionPoints = URI:http://www.wolfssl.com/crl.pem
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer:always


EOF
gen_cert

OUT=certs/test/cert-over-max-nc
KEYFILE=certs/ca-key.der
CONFIG=certs/test/cert-over-max-nc.cfg
tee >$CONFIG <<EOF
[ req ]
default_bits        = 2048
prompt              = no
distinguished_name  = dn
x509_extensions     = extensions

[ dn ]
C  = US
ST = Montana
L  = Bozeman
O  = wolfSSL Inc
OU = Engineering
CN = www.wolfssl.com

[ extensions ]
basicConstraints=critical,CA:true
nameConstraints = permitted;DNS:.ex1.com,permitted;DNS:.ex2.com,permitted;\
DNS:.ex3.com,permitted;DNS:.ex4.com,permitted;DNS:.ex5.com,permitted;\
DNS:.ex6.com,permitted;DNS:.ex7.com,permitted;DNS:.ex8.com,permitted;\
DNS:.ex9.com,permitted;DNS:.ex10.com,permitted;DNS:.ex11.com,permitted;\
DNS:.ex12.com,permitted;DNS:.ex13.com,permitted;DNS:.ex14.com,permitted;\
DNS:.ex15.com,permitted;DNS:.ex16.com,permitted;DNS:.ex17.com,permitted;\
DNS:.ex18.com,permitted;DNS:.ex19.com,permitted;DNS:.ex20.com,permitted;\
DNS:.ex21.com,permitted;DNS:.ex22.com,permitted;DNS:.ex23.com,permitted;\
DNS:.ex24.com,permitted;DNS:.ex25.com,permitted;DNS:.ex26.com,permitted;\
DNS:.ex27.com,permitted;DNS:.ex28.com,permitted;DNS:.ex29.com,permitted;\
DNS:.ex30.com,permitted;DNS:.ex31.com,permitted;DNS:.ex32.com,permitted;\
DNS:.ex33.com,permitted;DNS:.ex34.com,permitted;DNS:.ex35.com,permitted;\
DNS:.ex36.com,permitted;DNS:.ex37.com,permitted;DNS:.ex38.com,permitted;\
DNS:.ex39.com,permitted;DNS:.ex40.com,permitted;DNS:.ex41.com,permitted;\
DNS:.ex42.com,permitted;DNS:.ex43.com,permitted;DNS:.ex44.com,permitted;\
DNS:.ex45.com,permitted;DNS:.ex46.com,permitted;DNS:.ex47.com,permitted;\
DNS:.ex48.com,permitted;DNS:.ex49.com,permitted;DNS:.ex50.com,permitted;\
DNS:.ex51.com,permitted;DNS:.ex52.com,permitted;DNS:.ex53.com,permitted;\
DNS:.ex54.com,permitted;DNS:.ex55.com,permitted;DNS:.ex56.com,permitted;\
DNS:.ex57.com,permitted;DNS:.ex58.com,permitted;DNS:.ex59.com,permitted;\
DNS:.ex60.com,permitted;DNS:.ex61.com,permitted;DNS:.ex62.com,permitted;\
DNS:.ex63.com,permitted;DNS:.ex64.com,permitted;DNS:.ex65.com,permitted;\
DNS:.ex66.com,permitted;DNS:.ex67.com,permitted;DNS:.ex68.com,permitted;\
DNS:.ex69.com,permitted;DNS:.ex70.com,permitted;DNS:.ex71.com,permitted;\
DNS:.ex72.com,permitted;DNS:.ex73.com,permitted;DNS:.ex74.com,permitted;\
DNS:.ex75.com,permitted;DNS:.ex76.com,permitted;DNS:.ex77.com,permitted;\
DNS:.ex78.com,permitted;DNS:.ex79.com,permitted;DNS:.ex80.com,permitted;\
DNS:.ex81.com,permitted;DNS:.ex82.com,permitted;DNS:.ex83.com,permitted;\
DNS:.ex84.com,permitted;DNS:.ex85.com,permitted;DNS:.ex86.com,permitted;\
DNS:.ex87.com,permitted;DNS:.ex88.com,permitted;DNS:.ex89.com,permitted;\
DNS:.ex90.com,permitted;DNS:.ex91.com,permitted;DNS:.ex92.com,permitted;\
DNS:.ex93.com,permitted;DNS:.ex94.com,permitted;DNS:.ex95.com,permitted;\
DNS:.ex96.com,permitted;DNS:.ex97.com,permitted;DNS:.ex98.com,permitted;\
DNS:.ex99.com,permitted;DNS:.ex100.com,permitted;DNS:.ex101.com,permitted;\
DNS:.ex102.com,permitted;DNS:.ex103.com,permitted;DNS:.ex104.com,permitted;\
DNS:.ex105.com,permitted;DNS:.ex106.com,permitted;DNS:.ex107.com,permitted;\
DNS:.ex108.com,permitted;DNS:.ex109.com,permitted;DNS:.ex110.com,permitted;\
DNS:.ex111.com,permitted;DNS:.ex112.com,permitted;DNS:.ex113.com,permitted;\
DNS:.ex114.com,permitted;DNS:.ex115.com,permitted;DNS:.ex116.com,permitted;\
DNS:.ex117.com,permitted;DNS:.ex118.com,permitted;DNS:.ex119.com,permitted;\
DNS:.ex120.com,permitted;DNS:.ex121.com,permitted;DNS:.ex122.com,permitted;\
DNS:.ex123.com,permitted;DNS:.ex124.com,permitted;DNS:.ex125.com,permitted;\
DNS:.ex126.com,permitted;DNS:.ex127.com,permitted;DNS:.ex128.com,permitted;\
DNS:.ex129.com,permitted;DNS:.ex130.com

EOF
gen_cert

OUT=certs/test/cert-over-max-altnames
KEYFILE=certs/ca-key.der
CONFIG=certs/test/cert-over-max-altnames.cfg
tee >$CONFIG <<EOF
[ req ]
default_bits        = 2048
prompt              = no
distinguished_name  = dn
x509_extensions     = extensions

[ dn ]
C  = US
ST = Montana
L  = Bozeman
O  = wolfSSL Inc
OU = Engineering
CN = www.wolfssl.com

[ extensions ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = example1.com
DNS.2 = example2.com
DNS.3 = example3.com
DNS.4 = example4.com
DNS.5 = example5.com
DNS.6 = example6.com
DNS.7 = example7.com
DNS.8 = example8.com
DNS.9 = example9.com
DNS.10 = example10.com
DNS.11 = example11.com
DNS.12 = example12.com
DNS.13 = example13.com
DNS.14 = example14.com
DNS.15 = example15.com
DNS.16 = example16.com
DNS.17 = example17.com
DNS.18 = example18.com
DNS.19 = example19.com
DNS.20 = example20.com
DNS.21 = example21.com
DNS.22 = example22.com
DNS.23 = example23.com
DNS.24 = example24.com
DNS.25 = example25.com
DNS.26 = example26.com
DNS.27 = example27.com
DNS.28 = example28.com
DNS.29 = example29.com
DNS.30 = example30.com
DNS.31 = example31.com
DNS.32 = example32.com
DNS.33 = example33.com
DNS.34 = example34.com
DNS.35 = example35.com
DNS.36 = example36.com
DNS.37 = example37.com
DNS.38 = example38.com
DNS.39 = example39.com
DNS.40 = example40.com
DNS.41 = example41.com
DNS.42 = example42.com
DNS.43 = example43.com
DNS.44 = example44.com
DNS.45 = example45.com
DNS.46 = example46.com
DNS.47 = example47.com
DNS.48 = example48.com
DNS.49 = example49.com
DNS.50 = example50.com
DNS.51 = example51.com
DNS.52 = example52.com
DNS.53 = example53.com
DNS.54 = example54.com
DNS.55 = example55.com
DNS.56 = example56.com
DNS.57 = example57.com
DNS.58 = example58.com
DNS.59 = example59.com
DNS.60 = example60.com
DNS.61 = example61.com
DNS.62 = example62.com
DNS.63 = example63.com
DNS.64 = example64.com
DNS.65 = example65.com
DNS.66 = example66.com
DNS.67 = example67.com
DNS.68 = example68.com
DNS.69 = example69.com
DNS.70 = example70.com
DNS.71 = example71.com
DNS.72 = example72.com
DNS.73 = example73.com
DNS.74 = example74.com
DNS.75 = example75.com
DNS.76 = example76.com
DNS.77 = example77.com
DNS.78 = example78.com
DNS.79 = example79.com
DNS.80 = example80.com
DNS.81 = example81.com
DNS.82 = example82.com
DNS.83 = example83.com
DNS.84 = example84.com
DNS.85 = example85.com
DNS.86 = example86.com
DNS.87 = example87.com
DNS.88 = example88.com
DNS.89 = example89.com
DNS.90 = example90.com
DNS.91 = example91.com
DNS.92 = example92.com
DNS.93 = example93.com
DNS.94 = example94.com
DNS.95 = example95.com
DNS.96 = example96.com
DNS.97 = example97.com
DNS.98 = example98.com
DNS.99 = example99.com
DNS.100 = example100.com
DNS.101 = example101.com
DNS.102 = example102.com
DNS.103 = example103.com
DNS.104 = example104.com
DNS.105 = example105.com
DNS.106 = example106.com
DNS.107 = example107.com
DNS.108 = example108.com
DNS.109 = example109.com
DNS.110 = example110.com
DNS.111 = example111.com
DNS.112 = example112.com
DNS.113 = example113.com
DNS.114 = example114.com
DNS.115 = example115.com
DNS.116 = example116.com
DNS.117 = example117.com
DNS.118 = example118.com
DNS.119 = example119.com
DNS.120 = example120.com
DNS.121 = example121.com
DNS.122 = example122.com
DNS.123 = example123.com
DNS.124 = example124.com
DNS.125 = example125.com
DNS.126 = example126.com
DNS.127 = example127.com
DNS.128 = example128.com
DNS.129 = example129.com
DNS.130 = example130.com

EOF
gen_cert

