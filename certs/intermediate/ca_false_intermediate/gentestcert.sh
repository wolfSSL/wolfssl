#!/bin/bash

# Script for generating RSA CA and server certs based on it.
#
SERVER_PEM='test_sign_bynoca_srv.pem'
INTCA_PEM='test_int_not_cacert.pem'
CA_PEM='test_ca.pem'

CURRENT=$(cd $(dirname $0);pwd)
# OpenSSL configuration files
OPENSSL_BASE_CA_CONF='wolfssl_base.conf'
OPENSSL_CA_CONF='wolfssl_ca.conf'
OPENSSL_INTCA_CONF='wolfssl_int_ca.conf'
OPENSSL_SRV_CONF='wolfssl_srv.conf'
# SEt ver
CA_NAME="test_ca"
INTCA_NAME="int_ca"
SRVCERT_NAME="server_ext"
CRT_HOSTNAME="WOLFSSL"
CRT_DN="${CRT_HOSTNAME%% *}"
CRT_ALT_NAME="$(echo $CRT_HOSTNAME | sed -e "s/^/DNS:/" -e "s/ /,DNS:/g")"

CA_HOME=$(cd $(dirname $0);pwd)/pki/$CA_NAME
INT_CA_HOME="$CA_HOME/gen_int/$CRT_DN"
SRV_CRT_HOME="$CA_HOME/gen_srv/$CRT_DN"

Prepare_folder_file(){
    mkdir -m 700 pki

    # Create folders for CA
    mkdir "$CA_HOME"/{,certs,db,gen_srv,gen_int}
    mkdir -m 700 "$CA_HOME/private"
    # Create folders for Intermediate CA
    mkdir "$INT_CA_HOME"
    mkdir "$INT_CA_HOME"/{,certs,db}
    mkdir -m 700 "$INT_CA_HOME/private"
    # Create folders for Server
    mkdir "$SRV_CRT_HOME"
    mkdir -m 700 "$SRV_CRT_HOME/private"

    # Create and populate openssl CA files
    touch "$CA_HOME"/db/index
    openssl rand -hex 16 > "$CA_HOME"/db/serial

    touch "$INT_CA_HOME"/db/index
    openssl rand -hex 16 > "$INT_CA_HOME"/db/serial

    # Copy openssl config and private key
    cp "$OPENSSL_CA_CONF" "$CA_HOME"
    cp ./"$CA_NAME".key ./pki/$CA_NAME/private/"$CA_NAME".key

    cp "$OPENSSL_INTCA_CONF" "$INT_CA_HOME"
    cp ./"$INTCA_NAME".key "$INT_CA_HOME"/private/"$INTCA_NAME".key

    cp "$OPENSSL_SRV_CONF" "$SRV_CRT_HOME"
    cp ./server.key "$SRV_CRT_HOME"/private/server.key
}

Generate_conf(){
    # copy conf from base
    cp $OPENSSL_BASE_CA_CONF $OPENSSL_CA_CONF
    cp $OPENSSL_BASE_CA_CONF $OPENSSL_INTCA_CONF
    # Replace contents
    # For CA
    sed -i "s/_CA_NAME_/$CA_NAME/" "$OPENSSL_CA_CONF"
    sed -i "s/_CERT_NAME_/$INTCA_NAME/" "$OPENSSL_CA_CONF"
    sed -i "s/_CA_DEPART_/Development/" "$OPENSSL_CA_CONF"
    # For Intermediate CA
    sed -i "s/_CA_NAME_/$INTCA_NAME/" "$OPENSSL_INTCA_CONF"
    sed -i "s/_CERT_NAME_/$SRVCERT_NAME/" "$OPENSSL_INTCA_CONF"
    sed -i "s/_CA_DEPART_/Product_Support/" "$OPENSSL_INTCA_CONF"
}

cleanup_files(){
    rm -f wolfssl_ca.conf
    rm -f wolfssl_int_ca.conf
    rm -rf pki/
}

# clean up
if [ "$1" = "clean" ]; then
    echo "Cleaning temp files"
    cleanup_files
    exit 0
fi
if [ "$1" = "cleanall" ]; then
    echo "Cleaning all files"
    rm -f ./"$SERVER_PEM"
    rm -f ./"$INTCA_PEM"
    rm -f ./"$CA_PEM"
    cleanup_files
    exit 0
fi
# Generate OpenSSL Conf files
Generate_conf
# Prepare folders and files
Prepare_folder_file
##########################################
## Create CA, Intermediate and Server Cert
##########################################
# Generate CA
cd "$CA_HOME"

# Generate CA private key and csr - use config file info
openssl req -new -config "$OPENSSL_CA_CONF" \
                            -out "$CA_NAME.csr" -key "private/$CA_NAME.key"

# Self-sign CA certificate - use config file info
# Note: Use extension from config "ca_ext" section
openssl ca -selfsign -config "$OPENSSL_CA_CONF" \
        -notext -in "$CA_NAME.csr" -out "$CA_NAME.crt" -extensions ca_ext -batch

# Generate Intermediate CA
# cd into Cert generation folder
cd "$INT_CA_HOME"

# Create private key and csr
openssl req -new -config "$OPENSSL_INTCA_CONF" \
            -out "$INTCA_NAME.csr" -key "private/$INTCA_NAME.key"

cd "$CA_HOME"
# Sign certificate with CA
openssl ca -config "$OPENSSL_CA_CONF" -notext \
    -in "$INT_CA_HOME/$INTCA_NAME.csr" -out "$INT_CA_HOME/$INTCA_NAME.crt" \
    -extensions "$INTCA_NAME" -batch

# cd into Cert generation folder
cd "$SRV_CRT_HOME"
# Create private key and csr
openssl req -new -config "$OPENSSL_SRV_CONF" \
                                    -out server.csr -key private/server.key

# cd into intermediate CA home
cd "$CA_HOME/gen_int/WOLFSSL/"

# Sign certificate with CA
openssl ca -config "$OPENSSL_INTCA_CONF" -notext \
    -in "$SRV_CRT_HOME/server.csr" -out "$SRV_CRT_HOME/server.crt" \
    -extensions server_ext -batch


# cp generate certificates
cd $CURRENT
# CA
openssl x509 -in ./pki/$CA_NAME/$CA_NAME.crt -inform PEM -noout -text > ./pki/$CA_NAME/$CA_NAME.pem
cat ./pki/$CA_NAME/$CA_NAME.crt >> ./pki/$CA_NAME/$CA_NAME.pem
mv ./pki/$CA_NAME/$CA_NAME.pem $CA_PEM

# Intermediate CA
openssl x509 -in $INT_CA_HOME/$INTCA_NAME.crt -inform PEM -noout -text > $INT_CA_HOME/$INTCA_NAME.pem
cat $INT_CA_HOME/$INTCA_NAME.crt >> $INT_CA_HOME/$INTCA_NAME.pem
mv $INT_CA_HOME/$INTCA_NAME.pem $INTCA_PEM
# Server
openssl x509 -in $SRV_CRT_HOME/server.crt -inform PEM -noout -text > $SRV_CRT_HOME/server.pem
cat $SRV_CRT_HOME/server.crt >> $SRV_CRT_HOME/server.pem
mv $SRV_CRT_HOME/server.pem $SERVER_PEM

# clean up
cleanup_files

echo "Completed"
