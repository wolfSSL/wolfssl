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
DNS.131 = example131.com
DNS.132 = example132.com
DNS.133 = example133.com
DNS.134 = example134.com
DNS.135 = example135.com
DNS.136 = example136.com
DNS.137 = example137.com
DNS.138 = example138.com
DNS.139 = example139.com
DNS.140 = example140.com
DNS.141 = example141.com
DNS.142 = example142.com
DNS.143 = example143.com
DNS.144 = example144.com
DNS.145 = example145.com
DNS.146 = example146.com
DNS.147 = example147.com
DNS.148 = example148.com
DNS.149 = example149.com
DNS.150 = example150.com
DNS.151 = example151.com
DNS.152 = example152.com
DNS.153 = example153.com
DNS.154 = example154.com
DNS.155 = example155.com
DNS.156 = example156.com
DNS.157 = example157.com
DNS.158 = example158.com
DNS.159 = example159.com
DNS.160 = example160.com
DNS.161 = example161.com
DNS.162 = example162.com
DNS.163 = example163.com
DNS.164 = example164.com
DNS.165 = example165.com
DNS.166 = example166.com
DNS.167 = example167.com
DNS.168 = example168.com
DNS.169 = example169.com
DNS.170 = example170.com
DNS.171 = example171.com
DNS.172 = example172.com
DNS.173 = example173.com
DNS.174 = example174.com
DNS.175 = example175.com
DNS.176 = example176.com
DNS.177 = example177.com
DNS.178 = example178.com
DNS.179 = example179.com
DNS.180 = example180.com
DNS.181 = example181.com
DNS.182 = example182.com
DNS.183 = example183.com
DNS.184 = example184.com
DNS.185 = example185.com
DNS.186 = example186.com
DNS.187 = example187.com
DNS.188 = example188.com
DNS.189 = example189.com
DNS.190 = example190.com
DNS.191 = example191.com
DNS.192 = example192.com
DNS.193 = example193.com
DNS.194 = example194.com
DNS.195 = example195.com
DNS.196 = example196.com
DNS.197 = example197.com
DNS.198 = example198.com
DNS.199 = example199.com
DNS.200 = example200.com
DNS.201 = example201.com
DNS.202 = example202.com
DNS.203 = example203.com
DNS.204 = example204.com
DNS.205 = example205.com
DNS.206 = example206.com
DNS.207 = example207.com
DNS.208 = example208.com
DNS.209 = example209.com
DNS.210 = example210.com
DNS.211 = example211.com
DNS.212 = example212.com
DNS.213 = example213.com
DNS.214 = example214.com
DNS.215 = example215.com
DNS.216 = example216.com
DNS.217 = example217.com
DNS.218 = example218.com
DNS.219 = example219.com
DNS.220 = example220.com
DNS.221 = example221.com
DNS.222 = example222.com
DNS.223 = example223.com
DNS.224 = example224.com
DNS.225 = example225.com
DNS.226 = example226.com
DNS.227 = example227.com
DNS.228 = example228.com
DNS.229 = example229.com
DNS.230 = example230.com
DNS.231 = example231.com
DNS.232 = example232.com
DNS.233 = example233.com
DNS.234 = example234.com
DNS.235 = example235.com
DNS.236 = example236.com
DNS.237 = example237.com
DNS.238 = example238.com
DNS.239 = example239.com
DNS.240 = example240.com
DNS.241 = example241.com
DNS.242 = example242.com
DNS.243 = example243.com
DNS.244 = example244.com
DNS.245 = example245.com
DNS.246 = example246.com
DNS.247 = example247.com
DNS.248 = example248.com
DNS.249 = example249.com
DNS.250 = example250.com
DNS.251 = example251.com
DNS.252 = example252.com
DNS.253 = example253.com
DNS.254 = example254.com
DNS.255 = example255.com
DNS.256 = example256.com
DNS.257 = example257.com
DNS.258 = example258.com
DNS.259 = example259.com
DNS.260 = example260.com
DNS.261 = example261.com
DNS.262 = example262.com
DNS.263 = example263.com
DNS.264 = example264.com
DNS.265 = example265.com
DNS.266 = example266.com
DNS.267 = example267.com
DNS.268 = example268.com
DNS.269 = example269.com
DNS.270 = example270.com
DNS.271 = example271.com
DNS.272 = example272.com
DNS.273 = example273.com
DNS.274 = example274.com
DNS.275 = example275.com
DNS.276 = example276.com
DNS.277 = example277.com
DNS.278 = example278.com
DNS.279 = example279.com
DNS.280 = example280.com
DNS.281 = example281.com
DNS.282 = example282.com
DNS.283 = example283.com
DNS.284 = example284.com
DNS.285 = example285.com
DNS.286 = example286.com
DNS.287 = example287.com
DNS.288 = example288.com
DNS.289 = example289.com
DNS.290 = example290.com
DNS.291 = example291.com
DNS.292 = example292.com
DNS.293 = example293.com
DNS.294 = example294.com
DNS.295 = example295.com
DNS.296 = example296.com
DNS.297 = example297.com
DNS.298 = example298.com
DNS.299 = example299.com
DNS.300 = example300.com
DNS.301 = example301.com
DNS.302 = example302.com
DNS.303 = example303.com
DNS.304 = example304.com
DNS.305 = example305.com
DNS.306 = example306.com
DNS.307 = example307.com
DNS.308 = example308.com
DNS.309 = example309.com
DNS.310 = example310.com
DNS.311 = example311.com
DNS.312 = example312.com
DNS.313 = example313.com
DNS.314 = example314.com
DNS.315 = example315.com
DNS.316 = example316.com
DNS.317 = example317.com
DNS.318 = example318.com
DNS.319 = example319.com
DNS.320 = example320.com
DNS.321 = example321.com
DNS.322 = example322.com
DNS.323 = example323.com
DNS.324 = example324.com
DNS.325 = example325.com
DNS.326 = example326.com
DNS.327 = example327.com
DNS.328 = example328.com
DNS.329 = example329.com
DNS.330 = example330.com
DNS.331 = example331.com
DNS.332 = example332.com
DNS.333 = example333.com
DNS.334 = example334.com
DNS.335 = example335.com
DNS.336 = example336.com
DNS.337 = example337.com
DNS.338 = example338.com
DNS.339 = example339.com
DNS.340 = example340.com
DNS.341 = example341.com
DNS.342 = example342.com
DNS.343 = example343.com
DNS.344 = example344.com
DNS.345 = example345.com
DNS.346 = example346.com
DNS.347 = example347.com
DNS.348 = example348.com
DNS.349 = example349.com
DNS.350 = example350.com
DNS.351 = example351.com
DNS.352 = example352.com
DNS.353 = example353.com
DNS.354 = example354.com
DNS.355 = example355.com
DNS.356 = example356.com
DNS.357 = example357.com
DNS.358 = example358.com
DNS.359 = example359.com
DNS.360 = example360.com
DNS.361 = example361.com
DNS.362 = example362.com
DNS.363 = example363.com
DNS.364 = example364.com
DNS.365 = example365.com
DNS.366 = example366.com
DNS.367 = example367.com
DNS.368 = example368.com
DNS.369 = example369.com
DNS.370 = example370.com
DNS.371 = example371.com
DNS.372 = example372.com
DNS.373 = example373.com
DNS.374 = example374.com
DNS.375 = example375.com
DNS.376 = example376.com
DNS.377 = example377.com
DNS.378 = example378.com
DNS.379 = example379.com
DNS.380 = example380.com
DNS.381 = example381.com
DNS.382 = example382.com
DNS.383 = example383.com
DNS.384 = example384.com
DNS.385 = example385.com
DNS.386 = example386.com
DNS.387 = example387.com
DNS.388 = example388.com
DNS.389 = example389.com
DNS.390 = example390.com
DNS.391 = example391.com
DNS.392 = example392.com
DNS.393 = example393.com
DNS.394 = example394.com
DNS.395 = example395.com
DNS.396 = example396.com
DNS.397 = example397.com
DNS.398 = example398.com
DNS.399 = example399.com
DNS.400 = example400.com
DNS.401 = example401.com
DNS.402 = example402.com
DNS.403 = example403.com
DNS.404 = example404.com
DNS.405 = example405.com
DNS.406 = example406.com
DNS.407 = example407.com
DNS.408 = example408.com
DNS.409 = example409.com
DNS.410 = example410.com
DNS.411 = example411.com
DNS.412 = example412.com
DNS.413 = example413.com
DNS.414 = example414.com
DNS.415 = example415.com
DNS.416 = example416.com
DNS.417 = example417.com
DNS.418 = example418.com
DNS.419 = example419.com
DNS.420 = example420.com
DNS.421 = example421.com
DNS.422 = example422.com
DNS.423 = example423.com
DNS.424 = example424.com
DNS.425 = example425.com
DNS.426 = example426.com
DNS.427 = example427.com
DNS.428 = example428.com
DNS.429 = example429.com
DNS.430 = example430.com
DNS.431 = example431.com
DNS.432 = example432.com
DNS.433 = example433.com
DNS.434 = example434.com
DNS.435 = example435.com
DNS.436 = example436.com
DNS.437 = example437.com
DNS.438 = example438.com
DNS.439 = example439.com
DNS.440 = example440.com
DNS.441 = example441.com
DNS.442 = example442.com
DNS.443 = example443.com
DNS.444 = example444.com
DNS.445 = example445.com
DNS.446 = example446.com
DNS.447 = example447.com
DNS.448 = example448.com
DNS.449 = example449.com
DNS.450 = example450.com
DNS.451 = example451.com
DNS.452 = example452.com
DNS.453 = example453.com
DNS.454 = example454.com
DNS.455 = example455.com
DNS.456 = example456.com
DNS.457 = example457.com
DNS.458 = example458.com
DNS.459 = example459.com
DNS.460 = example460.com
DNS.461 = example461.com
DNS.462 = example462.com
DNS.463 = example463.com
DNS.464 = example464.com
DNS.465 = example465.com
DNS.466 = example466.com
DNS.467 = example467.com
DNS.468 = example468.com
DNS.469 = example469.com
DNS.470 = example470.com
DNS.471 = example471.com
DNS.472 = example472.com
DNS.473 = example473.com
DNS.474 = example474.com
DNS.475 = example475.com
DNS.476 = example476.com
DNS.477 = example477.com
DNS.478 = example478.com
DNS.479 = example479.com
DNS.480 = example480.com
DNS.481 = example481.com
DNS.482 = example482.com
DNS.483 = example483.com
DNS.484 = example484.com
DNS.485 = example485.com
DNS.486 = example486.com
DNS.487 = example487.com
DNS.488 = example488.com
DNS.489 = example489.com
DNS.490 = example490.com
DNS.491 = example491.com
DNS.492 = example492.com
DNS.493 = example493.com
DNS.494 = example494.com
DNS.495 = example495.com
DNS.496 = example496.com
DNS.497 = example497.com
DNS.498 = example498.com
DNS.499 = example499.com
DNS.500 = example500.com
DNS.501 = example501.com
DNS.502 = example502.com
DNS.503 = example503.com
DNS.504 = example504.com
DNS.505 = example505.com
DNS.506 = example506.com
DNS.507 = example507.com
DNS.508 = example508.com
DNS.509 = example509.com
DNS.510 = example510.com
DNS.511 = example511.com
DNS.512 = example512.com
DNS.513 = example513.com
DNS.514 = example514.com
DNS.515 = example515.com
DNS.516 = example516.com
DNS.517 = example517.com
DNS.518 = example518.com
DNS.519 = example519.com
DNS.520 = example520.com
DNS.521 = example521.com
DNS.522 = example522.com
DNS.523 = example523.com
DNS.524 = example524.com
DNS.525 = example525.com
DNS.526 = example526.com
DNS.527 = example527.com
DNS.528 = example528.com
DNS.529 = example529.com
DNS.530 = example530.com
DNS.531 = example531.com
DNS.532 = example532.com
DNS.533 = example533.com
DNS.534 = example534.com
DNS.535 = example535.com
DNS.536 = example536.com
DNS.537 = example537.com
DNS.538 = example538.com
DNS.539 = example539.com
DNS.540 = example540.com
DNS.541 = example541.com
DNS.542 = example542.com
DNS.543 = example543.com
DNS.544 = example544.com
DNS.545 = example545.com
DNS.546 = example546.com
DNS.547 = example547.com
DNS.548 = example548.com
DNS.549 = example549.com
DNS.550 = example550.com
DNS.551 = example551.com
DNS.552 = example552.com
DNS.553 = example553.com
DNS.554 = example554.com
DNS.555 = example555.com
DNS.556 = example556.com
DNS.557 = example557.com
DNS.558 = example558.com
DNS.559 = example559.com
DNS.560 = example560.com
DNS.561 = example561.com
DNS.562 = example562.com
DNS.563 = example563.com
DNS.564 = example564.com
DNS.565 = example565.com
DNS.566 = example566.com
DNS.567 = example567.com
DNS.568 = example568.com
DNS.569 = example569.com
DNS.570 = example570.com
DNS.571 = example571.com
DNS.572 = example572.com
DNS.573 = example573.com
DNS.574 = example574.com
DNS.575 = example575.com
DNS.576 = example576.com
DNS.577 = example577.com
DNS.578 = example578.com
DNS.579 = example579.com
DNS.580 = example580.com
DNS.581 = example581.com
DNS.582 = example582.com
DNS.583 = example583.com
DNS.584 = example584.com
DNS.585 = example585.com
DNS.586 = example586.com
DNS.587 = example587.com
DNS.588 = example588.com
DNS.589 = example589.com
DNS.590 = example590.com
DNS.591 = example591.com
DNS.592 = example592.com
DNS.593 = example593.com
DNS.594 = example594.com
DNS.595 = example595.com
DNS.596 = example596.com
DNS.597 = example597.com
DNS.598 = example598.com
DNS.599 = example599.com
DNS.600 = example600.com
DNS.601 = example601.com
DNS.602 = example602.com
DNS.603 = example603.com
DNS.604 = example604.com
DNS.605 = example605.com
DNS.606 = example606.com
DNS.607 = example607.com
DNS.608 = example608.com
DNS.609 = example609.com
DNS.610 = example610.com
DNS.611 = example611.com
DNS.612 = example612.com
DNS.613 = example613.com
DNS.614 = example614.com
DNS.615 = example615.com
DNS.616 = example616.com
DNS.617 = example617.com
DNS.618 = example618.com
DNS.619 = example619.com
DNS.620 = example620.com
DNS.621 = example621.com
DNS.622 = example622.com
DNS.623 = example623.com
DNS.624 = example624.com
DNS.625 = example625.com
DNS.626 = example626.com
DNS.627 = example627.com
DNS.628 = example628.com
DNS.629 = example629.com
DNS.630 = example630.com
DNS.631 = example631.com
DNS.632 = example632.com
DNS.633 = example633.com
DNS.634 = example634.com
DNS.635 = example635.com
DNS.636 = example636.com
DNS.637 = example637.com
DNS.638 = example638.com
DNS.639 = example639.com
DNS.640 = example640.com
DNS.641 = example641.com
DNS.642 = example642.com
DNS.643 = example643.com
DNS.644 = example644.com
DNS.645 = example645.com
DNS.646 = example646.com
DNS.647 = example647.com
DNS.648 = example648.com
DNS.649 = example649.com
DNS.650 = example650.com
DNS.651 = example651.com
DNS.652 = example652.com
DNS.653 = example653.com
DNS.654 = example654.com
DNS.655 = example655.com
DNS.656 = example656.com
DNS.657 = example657.com
DNS.658 = example658.com
DNS.659 = example659.com
DNS.660 = example660.com
DNS.661 = example661.com
DNS.662 = example662.com
DNS.663 = example663.com
DNS.664 = example664.com
DNS.665 = example665.com
DNS.666 = example666.com
DNS.667 = example667.com
DNS.668 = example668.com
DNS.669 = example669.com
DNS.670 = example670.com
DNS.671 = example671.com
DNS.672 = example672.com
DNS.673 = example673.com
DNS.674 = example674.com
DNS.675 = example675.com
DNS.676 = example676.com
DNS.677 = example677.com
DNS.678 = example678.com
DNS.679 = example679.com
DNS.680 = example680.com
DNS.681 = example681.com
DNS.682 = example682.com
DNS.683 = example683.com
DNS.684 = example684.com
DNS.685 = example685.com
DNS.686 = example686.com
DNS.687 = example687.com
DNS.688 = example688.com
DNS.689 = example689.com
DNS.690 = example690.com
DNS.691 = example691.com
DNS.692 = example692.com
DNS.693 = example693.com
DNS.694 = example694.com
DNS.695 = example695.com
DNS.696 = example696.com
DNS.697 = example697.com
DNS.698 = example698.com
DNS.699 = example699.com
DNS.700 = example700.com
DNS.701 = example701.com
DNS.702 = example702.com
DNS.703 = example703.com
DNS.704 = example704.com
DNS.705 = example705.com
DNS.706 = example706.com
DNS.707 = example707.com
DNS.708 = example708.com
DNS.709 = example709.com
DNS.710 = example710.com
DNS.711 = example711.com
DNS.712 = example712.com
DNS.713 = example713.com
DNS.714 = example714.com
DNS.715 = example715.com
DNS.716 = example716.com
DNS.717 = example717.com
DNS.718 = example718.com
DNS.719 = example719.com
DNS.720 = example720.com
DNS.721 = example721.com
DNS.722 = example722.com
DNS.723 = example723.com
DNS.724 = example724.com
DNS.725 = example725.com
DNS.726 = example726.com
DNS.727 = example727.com
DNS.728 = example728.com
DNS.729 = example729.com
DNS.730 = example730.com
DNS.731 = example731.com
DNS.732 = example732.com
DNS.733 = example733.com
DNS.734 = example734.com
DNS.735 = example735.com
DNS.736 = example736.com
DNS.737 = example737.com
DNS.738 = example738.com
DNS.739 = example739.com
DNS.740 = example740.com
DNS.741 = example741.com
DNS.742 = example742.com
DNS.743 = example743.com
DNS.744 = example744.com
DNS.745 = example745.com
DNS.746 = example746.com
DNS.747 = example747.com
DNS.748 = example748.com
DNS.749 = example749.com
DNS.750 = example750.com
DNS.751 = example751.com
DNS.752 = example752.com
DNS.753 = example753.com
DNS.754 = example754.com
DNS.755 = example755.com
DNS.756 = example756.com
DNS.757 = example757.com
DNS.758 = example758.com
DNS.759 = example759.com
DNS.760 = example760.com
DNS.761 = example761.com
DNS.762 = example762.com
DNS.763 = example763.com
DNS.764 = example764.com
DNS.765 = example765.com
DNS.766 = example766.com
DNS.767 = example767.com
DNS.768 = example768.com
DNS.769 = example769.com
DNS.770 = example770.com
DNS.771 = example771.com
DNS.772 = example772.com
DNS.773 = example773.com
DNS.774 = example774.com
DNS.775 = example775.com
DNS.776 = example776.com
DNS.777 = example777.com
DNS.778 = example778.com
DNS.779 = example779.com
DNS.780 = example780.com
DNS.781 = example781.com
DNS.782 = example782.com
DNS.783 = example783.com
DNS.784 = example784.com
DNS.785 = example785.com
DNS.786 = example786.com
DNS.787 = example787.com
DNS.788 = example788.com
DNS.789 = example789.com
DNS.790 = example790.com
DNS.791 = example791.com
DNS.792 = example792.com
DNS.793 = example793.com
DNS.794 = example794.com
DNS.795 = example795.com
DNS.796 = example796.com
DNS.797 = example797.com
DNS.798 = example798.com
DNS.799 = example799.com
DNS.800 = example800.com
DNS.801 = example801.com
DNS.802 = example802.com
DNS.803 = example803.com
DNS.804 = example804.com
DNS.805 = example805.com
DNS.806 = example806.com
DNS.807 = example807.com
DNS.808 = example808.com
DNS.809 = example809.com
DNS.810 = example810.com
DNS.811 = example811.com
DNS.812 = example812.com
DNS.813 = example813.com
DNS.814 = example814.com
DNS.815 = example815.com
DNS.816 = example816.com
DNS.817 = example817.com
DNS.818 = example818.com
DNS.819 = example819.com
DNS.820 = example820.com
DNS.821 = example821.com
DNS.822 = example822.com
DNS.823 = example823.com
DNS.824 = example824.com
DNS.825 = example825.com
DNS.826 = example826.com
DNS.827 = example827.com
DNS.828 = example828.com
DNS.829 = example829.com
DNS.830 = example830.com
DNS.831 = example831.com
DNS.832 = example832.com
DNS.833 = example833.com
DNS.834 = example834.com
DNS.835 = example835.com
DNS.836 = example836.com
DNS.837 = example837.com
DNS.838 = example838.com
DNS.839 = example839.com
DNS.840 = example840.com
DNS.841 = example841.com
DNS.842 = example842.com
DNS.843 = example843.com
DNS.844 = example844.com
DNS.845 = example845.com
DNS.846 = example846.com
DNS.847 = example847.com
DNS.848 = example848.com
DNS.849 = example849.com
DNS.850 = example850.com
DNS.851 = example851.com
DNS.852 = example852.com
DNS.853 = example853.com
DNS.854 = example854.com
DNS.855 = example855.com
DNS.856 = example856.com
DNS.857 = example857.com
DNS.858 = example858.com
DNS.859 = example859.com
DNS.860 = example860.com
DNS.861 = example861.com
DNS.862 = example862.com
DNS.863 = example863.com
DNS.864 = example864.com
DNS.865 = example865.com
DNS.866 = example866.com
DNS.867 = example867.com
DNS.868 = example868.com
DNS.869 = example869.com
DNS.870 = example870.com
DNS.871 = example871.com
DNS.872 = example872.com
DNS.873 = example873.com
DNS.874 = example874.com
DNS.875 = example875.com
DNS.876 = example876.com
DNS.877 = example877.com
DNS.878 = example878.com
DNS.879 = example879.com
DNS.880 = example880.com
DNS.881 = example881.com
DNS.882 = example882.com
DNS.883 = example883.com
DNS.884 = example884.com
DNS.885 = example885.com
DNS.886 = example886.com
DNS.887 = example887.com
DNS.888 = example888.com
DNS.889 = example889.com
DNS.890 = example890.com
DNS.891 = example891.com
DNS.892 = example892.com
DNS.893 = example893.com
DNS.894 = example894.com
DNS.895 = example895.com
DNS.896 = example896.com
DNS.897 = example897.com
DNS.898 = example898.com
DNS.899 = example899.com
DNS.900 = example900.com
DNS.901 = example901.com
DNS.902 = example902.com
DNS.903 = example903.com
DNS.904 = example904.com
DNS.905 = example905.com
DNS.906 = example906.com
DNS.907 = example907.com
DNS.908 = example908.com
DNS.909 = example909.com
DNS.910 = example910.com
DNS.911 = example911.com
DNS.912 = example912.com
DNS.913 = example913.com
DNS.914 = example914.com
DNS.915 = example915.com
DNS.916 = example916.com
DNS.917 = example917.com
DNS.918 = example918.com
DNS.919 = example919.com
DNS.920 = example920.com
DNS.921 = example921.com
DNS.922 = example922.com
DNS.923 = example923.com
DNS.924 = example924.com
DNS.925 = example925.com
DNS.926 = example926.com
DNS.927 = example927.com
DNS.928 = example928.com
DNS.929 = example929.com
DNS.930 = example930.com
DNS.931 = example931.com
DNS.932 = example932.com
DNS.933 = example933.com
DNS.934 = example934.com
DNS.935 = example935.com
DNS.936 = example936.com
DNS.937 = example937.com
DNS.938 = example938.com
DNS.939 = example939.com
DNS.940 = example940.com
DNS.941 = example941.com
DNS.942 = example942.com
DNS.943 = example943.com
DNS.944 = example944.com
DNS.945 = example945.com
DNS.946 = example946.com
DNS.947 = example947.com
DNS.948 = example948.com
DNS.949 = example949.com
DNS.950 = example950.com
DNS.951 = example951.com
DNS.952 = example952.com
DNS.953 = example953.com
DNS.954 = example954.com
DNS.955 = example955.com
DNS.956 = example956.com
DNS.957 = example957.com
DNS.958 = example958.com
DNS.959 = example959.com
DNS.960 = example960.com
DNS.961 = example961.com
DNS.962 = example962.com
DNS.963 = example963.com
DNS.964 = example964.com
DNS.965 = example965.com
DNS.966 = example966.com
DNS.967 = example967.com
DNS.968 = example968.com
DNS.969 = example969.com
DNS.970 = example970.com
DNS.971 = example971.com
DNS.972 = example972.com
DNS.973 = example973.com
DNS.974 = example974.com
DNS.975 = example975.com
DNS.976 = example976.com
DNS.977 = example977.com
DNS.978 = example978.com
DNS.979 = example979.com
DNS.980 = example980.com
DNS.981 = example981.com
DNS.982 = example982.com
DNS.983 = example983.com
DNS.984 = example984.com
DNS.985 = example985.com
DNS.986 = example986.com
DNS.987 = example987.com
DNS.988 = example988.com
DNS.989 = example989.com
DNS.990 = example990.com
DNS.991 = example991.com
DNS.992 = example992.com
DNS.993 = example993.com
DNS.994 = example994.com
DNS.995 = example995.com
DNS.996 = example996.com
DNS.997 = example997.com
DNS.998 = example998.com
DNS.999 = example999.com
DNS.1000 = example1000.com
DNS.1001 = example1001.com
DNS.1002 = example1002.com
DNS.1003 = example1003.com
DNS.1004 = example1004.com
DNS.1005 = example1005.com
DNS.1006 = example1006.com
DNS.1007 = example1007.com
DNS.1008 = example1008.com
DNS.1009 = example1009.com
DNS.1010 = example1010.com
DNS.1011 = example1011.com
DNS.1012 = example1012.com
DNS.1013 = example1013.com
DNS.1014 = example1014.com
DNS.1015 = example1015.com
DNS.1016 = example1016.com
DNS.1017 = example1017.com
DNS.1018 = example1018.com
DNS.1019 = example1019.com
DNS.1020 = example1020.com
DNS.1021 = example1021.com
DNS.1022 = example1022.com
DNS.1023 = example1023.com
DNS.1024 = example1024.com
DNS.1025 = example1025.com
DNS.1026 = example1026.com
DNS.1027 = example1027.com
DNS.1028 = example1028.com
DNS.1029 = example1029.com
DNS.1030 = example1030.com
DNS.1031 = example1031.com
DNS.1032 = example1032.com
DNS.1033 = example1033.com
DNS.1034 = example1034.com
DNS.1035 = example1035.com
DNS.1036 = example1036.com
DNS.1037 = example1037.com
DNS.1038 = example1038.com
DNS.1039 = example1039.com
DNS.1040 = example1040.com
DNS.1041 = example1041.com
DNS.1042 = example1042.com
DNS.1043 = example1043.com
DNS.1044 = example1044.com
DNS.1045 = example1045.com
DNS.1046 = example1046.com
DNS.1047 = example1047.com
DNS.1048 = example1048.com
DNS.1049 = example1049.com
DNS.1050 = example1050.com


EOF
gen_cert

