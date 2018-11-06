#!/bin/bash
# renewcerts.sh
#
# renews the following certs:
#                       client-cert.pem
#                       client-cert.der
#                       client-ecc-cert.pem
#                       client-ecc-cert.der
#                       ca-cert.pem
#                       ca-cert.der
#                       ca-ecc-cert.pem
#                       ca-ecc-cert.der
#                       ca-ecc384-cert.pem
#                       ca-ecc384-cert.der
#                       server-cert.pem
#                       server-cert.der
#                       server-ecc-rsa.pem
#                       server-ecc.pem
#                       1024/client-cert.der
#                       1024/client-cert.pem
#                       server-ecc-comp.pem
#                       client-ca.pem
#                       test/digsigku.pem
#                       ecc-privOnlyCert.pem
#                       client-uri-cert.pem
#                       client-relative-uri.pem
# updates the following crls:
#                       crl/cliCrl.pem
#                       crl/crl.pem
#                       crl/crl.revoked
#                       crl/eccCliCRL.pem
#                       crl/eccSrvCRL.pem
#
#                       pkcs7:
#                       test-degenerate.p7b
# if HAVE_NTRU
#                       ntru-cert.pem
#                       ntru-key.raw
###############################################################################
######################## FUNCTIONS SECTION ####################################
###############################################################################

#function for restoring a previous configure state
restore_config(){
    mv tmp.status config.status
    mv tmp.options.h wolfssl/options.h
    make clean
    make -j 8
}

check_result(){
    if [ $1 -ne 0 ]; then
        echo "Failed at \"$2\", Abort"
        if [ "$2" = "configure for ntru" ] || \
           [ "$2" = "make check with ntru" ]; then
            restore_config
        fi
        exit 1
    else
        echo "Step Succeeded!"
    fi
}

#the function that will be called when we are ready to renew the certs.
run_renewcerts(){
    cd certs/ || { echo "Couldn't cd to certs directory"; exit 1; }
    echo ""
    #move the custom cnf into our working directory
    cp renewcerts/wolfssl.cnf wolfssl.cnf || exit 1

    # To generate these all in sha1 add the flag "-sha1" on appropriate lines
    # That is all lines beginning with:  "openssl req"

    ############################################################
    #### update the self-signed (2048-bit) client-uri-cert.pem #
    ############################################################
    echo "Updating 2048-bit client-uri-cert.pem"
    echo ""
    #pipe the following arguments to openssl req...
    echo -e "US\\nMontana\\nBozeman\\nwolfSSL_2048\\nURI\\nwww.wolfssl.com\\ninfo@wolfssl.com\\n.\\n.\\n" | openssl req -new -key client-key.pem -config ./wolfssl.cnf -nodes -out client-cert.csr
    check_result $? "Step 1"

    openssl x509 -req -in client-cert.csr -days 1000 -extfile wolfssl.cnf -extensions uri -signkey client-key.pem -out client-uri-cert.pem
    check_result $? "Step 2"
    rm client-cert.csr

    openssl x509 -in client-uri-cert.pem -text > tmp.pem
    check_result $? "Step 3"
    mv tmp.pem client-uri-cert.pem
    echo "End of section"
    echo "---------------------------------------------------------------------"
    ############################################################
    #### update the self-signed (2048-bit) client-relative-uri.pem
    ############################################################
    echo "Updating 2048-bit client-relative-uri.pem"
    echo ""
    #pipe the following arguments to openssl req...
    echo -e "US\\nMontana\\nBozeman\\nwolfSSL_2048\\nRELATIVE_URI\\nwww.wolfssl.com\\ninfo@wolfssl.com\\n.\\n.\\n" | openssl req -new -key client-key.pem -config ./wolfssl.cnf -nodes -out client-cert.csr
    check_result $? "Step 1"


    openssl x509 -req -in client-cert.csr -days 1000 -extfile wolfssl.cnf -extensions relative_uri -signkey client-key.pem -out client-relative-uri.pem
    check_result $? "Step 2"
    rm client-cert.csr

    openssl x509 -in client-relative-uri.pem -text > tmp.pem
    check_result $? "Step 3"
    mv tmp.pem client-relative-uri.pem
    echo "End of section"
    echo "---------------------------------------------------------------------"
    ############################################################
    #### update the self-signed (2048-bit) client-cert.pem #####
    ############################################################
    echo "Updating 2048-bit client-cert.pem"
    echo ""
    #pipe the following arguments to openssl req...
    echo -e "US\\nMontana\\nBozeman\\nwolfSSL_2048\\nProgramming-2048\\nwww.wolfssl.com\\ninfo@wolfssl.com\\n.\\n.\\n" | openssl req -new -key client-key.pem -config ./wolfssl.cnf -nodes -out client-cert.csr
    check_result $? "Step 1"


    openssl x509 -req -in client-cert.csr -days 1000 -extfile wolfssl.cnf -extensions wolfssl_opts -signkey client-key.pem -out client-cert.pem
    check_result $? "Step 2"
    rm client-cert.csr

    openssl x509 -in client-cert.pem -text > tmp.pem
    check_result $? "Step 3"
    mv tmp.pem client-cert.pem
    echo "End of section"
    echo "---------------------------------------------------------------------"
    ############################################################
    #### update the self-signed (3072-bit) client-cert.pem #####
    ############################################################
    echo "Updating 3072-bit client-cert.pem"
    echo ""
    #pipe the following arguments to openssl req...
    echo -e "US\\nMontana\\nBozeman\\nwolfSSL_3072\\nProgramming-3072\\nwww.wolfssl.com\\ninfo@wolfssl.com\\n.\\n.\\n" | openssl req -new -newkey rsa:3072 -keyout client-key-3072.pem -config ./wolfssl.cnf -nodes -out client-cert-3072.csr
    check_result $? "Step 1"


    openssl x509 -req -in client-cert-3072.csr -days 1000 -extfile wolfssl.cnf -extensions wolfssl_opts -signkey client-key-3072.pem -out client-cert-3072.pem
    check_result $? "Step 2"
    rm client-cert-3072.csr

    openssl x509 -in client-cert-3072.pem -text > tmp.pem
    check_result $? "Step 3"
    mv tmp.pem client-cert-3072.pem
    echo "End of section"
    echo "---------------------------------------------------------------------"
    ############################################################
    #### update the self-signed (1024-bit) client-cert.pem #####
    ############################################################
    echo "Updating 1024-bit client-cert.pem"
    echo ""
    #pipe the following arguments to openssl req...
    echo -e "US\\nMontana\\nBozeman\\nwolfSSL_1024\\nProgramming-1024\\nwww.wolfssl.com\\ninfo@wolfssl.com\\n.\\n.\\n" | openssl req -new -key ./1024/client-key.pem -config ./wolfssl.cnf -nodes -out ./1024/client-cert.csr
    check_result $? "Step 1"


    openssl x509 -req -in ./1024/client-cert.csr -days 1000 -extfile wolfssl.cnf -extensions wolfssl_opts -signkey ./1024/client-key.pem -out ./1024/client-cert.pem
    check_result $? "Step 2"
    rm ./1024/client-cert.csr

    openssl x509 -in ./1024/client-cert.pem -text > ./1024/tmp.pem
    check_result $? "Step 3"
    mv ./1024/tmp.pem ./1024/client-cert.pem
    echo "End of section"
    echo "---------------------------------------------------------------------"
    ############################################################
    ########## update the self-signed ca-cert.pem ##############
    ############################################################
    echo "Updating ca-cert.pem"
    echo ""
    #pipe the following arguments to openssl req...
    echo -e  "US\\nMontana\\nBozeman\\nSawtooth\\nConsulting\\nwww.wolfssl.com\\ninfo@wolfssl.com\\n.\\n.\\n" | openssl req -new -key ca-key.pem -config ./wolfssl.cnf -nodes -out ca-cert.csr
    check_result $? "Step 1"

    openssl x509 -req -in ca-cert.csr -days 1000 -extfile wolfssl.cnf -extensions wolfssl_opts -signkey ca-key.pem -out ca-cert.pem
    check_result $? "Step 2"
    rm ca-cert.csr

    openssl x509 -in ca-cert.pem -text > tmp.pem
    check_result $? "Step 3"
    mv tmp.pem ca-cert.pem
    echo "End of section"
    echo "---------------------------------------------------------------------"
    ############################################################
    ########## update the self-signed ca-ecc-cert.pem ##########
    ############################################################
    echo "Updating ca-ecc-cert.pem"
    echo ""
    #pipe the following arguments to openssl req...
    echo -e  "US\\nWashington\\nSeattle\\nwolfSSL\\nDevelopment\\nwww.wolfssl.com\\ninfo@wolfssl.com\\n.\\n.\\n" | openssl req -new -key ca-ecc-key.pem -config ./wolfssl.cnf -nodes -out ca-ecc-cert.csr
    check_result $? "Step 1"

    openssl x509 -req -in ca-ecc-cert.csr -days 1000 -extfile wolfssl.cnf -extensions ca_ecc_cert -signkey ca-ecc-key.pem -out ca-ecc-cert.pem
    check_result $? "Step 2"
    rm ca-ecc-cert.csr

    openssl x509 -in ca-ecc-cert.pem -text > tmp.pem
    check_result $? "Step 3"
    mv tmp.pem ca-ecc-cert.pem
    echo "End of section"
    echo "---------------------------------------------------------------------"
    ############################################################
    ########## update the self-signed ca-ecc384-cert.pem #######
    ############################################################
    echo "Updating ca-ecc384-cert.pem"
    echo ""
    #pipe the following arguments to openssl req...
    echo -e  "US\\nWashington\\nSeattle\\nwolfSSL\\nDevelopment\\nwww.wolfssl.com\\ninfo@wolfssl.com\\n.\\n.\\n" | openssl req -new -key ca-ecc384-key.pem -config ./wolfssl.cnf -nodes -sha384 -out ca-ecc384-cert.csr
    check_result $? "Step 1"

    openssl x509 -req -in ca-ecc384-cert.csr -days 1000 -extfile wolfssl.cnf -extensions ca_ecc_cert -signkey ca-ecc384-key.pem -sha384 -out ca-ecc384-cert.pem
    check_result $? "Step 2"
    rm ca-ecc384-cert.csr

    openssl x509 -in ca-ecc384-cert.pem -text > tmp.pem
    check_result $? "Step 3"
    mv tmp.pem ca-ecc384-cert.pem
    echo "End of section"
    echo "---------------------------------------------------------------------"
    ############################################################
    ##### update the self-signed (1024-bit) ca-cert.pem ########
    ############################################################
    echo "Updating 1024-bit ca-cert.pem"
    echo ""
    #pipe the following arguments to openssl req...
    echo -e  "US\\nMontana\\nBozeman\\nSawtooth\\nConsulting_1024\\nwww.wolfssl.com\\ninfo@wolfssl.com\\n.\\n.\\n" | openssl req -new -key ./1024/ca-key.pem -config ./wolfssl.cnf -nodes -sha1 -out ./1024/ca-cert.csr
    check_result $? "Step 1"

    openssl x509 -req -in ./1024/ca-cert.csr -days 1000 -extfile wolfssl.cnf -extensions wolfssl_opts -signkey ./1024/ca-key.pem -out ./1024/ca-cert.pem
    check_result $? "Step 2"
    rm ./1024/ca-cert.csr

    openssl x509 -in ./1024/ca-cert.pem -text > ./1024/tmp.pem
    check_result $? "Step 3"
    mv ./1024/tmp.pem ./1024/ca-cert.pem
    echo "End of section"
    echo "---------------------------------------------------------------------"
    ###########################################################
    ########## update and sign server-cert.pem ################
    ###########################################################
    echo "Updating server-cert.pem"
    echo ""
    #pipe the following arguments to openssl req...
    echo -e "US\\nMontana\\nBozeman\\nwolfSSL\\nSupport\\nwww.wolfssl.com\\ninfo@wolfssl.com\\n.\\n.\\n" | openssl req -new -key server-key.pem -config ./wolfssl.cnf -nodes > server-req.pem
    check_result $? "Step 1"

    openssl x509 -req -in server-req.pem -extfile wolfssl.cnf -extensions wolfssl_opts -days 1000 -CA ca-cert.pem -CAkey ca-key.pem -set_serial 01 > server-cert.pem
    check_result $? "Step 2"

    rm server-req.pem

    openssl x509 -in ca-cert.pem -text > ca_tmp.pem
    check_result $? "Step 3"
    openssl x509 -in server-cert.pem -text > srv_tmp.pem
    check_result $? "Step 4"
    mv srv_tmp.pem server-cert.pem
    cat ca_tmp.pem >> server-cert.pem
    rm ca_tmp.pem
    echo "End of section"
    echo "---------------------------------------------------------------------"
    ###########################################################
    ########## update and sign server-revoked-key.pem #########
    ###########################################################
    echo "Updating server-revoked-cert.pem"
    echo ""
    #pipe the following arguments to openssl req...
    echo -e "US\\nMontana\\nBozeman\\nwolfSSL_revoked\\nSupport_revoked\\nwww.wolfssl.com\\ninfo@wolfssl.com\\n.\\n.\\n" | openssl req -new -key server-revoked-key.pem -config ./wolfssl.cnf -nodes > server-revoked-req.pem
    check_result $? "Step 1"

    openssl x509 -req -in server-revoked-req.pem -extfile wolfssl.cnf -extensions wolfssl_opts -days 1000 -CA ca-cert.pem -CAkey ca-key.pem -set_serial 02 > server-revoked-cert.pem
    check_result $? "Step 2"
    rm server-revoked-req.pem

    openssl x509 -in ca-cert.pem -text > ca_tmp.pem
    check_result $? "Step 3"
    openssl x509 -in server-revoked-cert.pem -text > srv_tmp.pem
    check_result $? "Step 4"
    mv srv_tmp.pem server-revoked-cert.pem
    cat ca_tmp.pem >> server-revoked-cert.pem
    rm ca_tmp.pem
    echo "End of section"
    echo "---------------------------------------------------------------------"
    ###########################################################
    ########## update and sign server-duplicate-policy.pem ####
    ###########################################################
    echo "Updating server-duplicate-policy.pem"
    echo ""
    #pipe the following arguments to openssl req...
    echo -e "US\\nMontana\\nBozeman\\nwolfSSL\\ntesting duplicate policy\\nwww.wolfssl.com\\ninfo@wolfssl.com\\n.\\n.\\n" | openssl req -new -key server-key.pem -config ./wolfssl.cnf -nodes > ./test/server-duplicate-policy-req.pem
    check_result $? "Step 1"

    openssl x509 -req -in ./test/server-duplicate-policy-req.pem -extfile wolfssl.cnf -extensions policy_test -days 1000 -CA ca-cert.pem -CAkey ca-key.pem -set_serial 02 > ./test/server-duplicate-policy.pem
    check_result $? "Step 2"
    rm ./test/server-duplicate-policy-req.pem

    openssl x509 -in ca-cert.pem -text > ca_tmp.pem
    check_result $? "Step 3"
    openssl x509 -in ./test/server-duplicate-policy.pem -text > srv_tmp.pem
    check_result $? "Step 4"
    mv srv_tmp.pem ./test/server-duplicate-policy.pem
    cat ca_tmp.pem >> ./test/server-duplicate-policy.pem
    rm ca_tmp.pem
    echo "End of section"
    echo "---------------------------------------------------------------------"
    ###########################################################
    #### update and sign (1024-bit) server-cert.pem ###########
    ###########################################################
    echo "Updating 1024-bit server-cert.pem"
    echo ""
    #pipe the following arguments to openssl req...
    echo -e "US\\nMontana\\nBozeman\\nwolfSSL\\nSupport_1024\\nwww.wolfssl.com\\ninfo@wolfssl.com\\n.\\n.\\n" | openssl req -new -key ./1024/server-key.pem -config ./wolfssl.cnf -nodes -sha1 > ./1024/server-req.pem
    check_result $? "Step 1"

    openssl x509 -req -in ./1024/server-req.pem -extfile wolfssl.cnf -extensions wolfssl_opts -days 1000 -CA ./1024/ca-cert.pem -CAkey ./1024/ca-key.pem -set_serial 01 > ./1024/server-cert.pem
    check_result $? "Step 2"
    rm ./1024/server-req.pem

    openssl x509 -in ./1024/ca-cert.pem -text > ./1024/ca_tmp.pem
    check_result $? "Step 3"
    openssl x509 -in ./1024/server-cert.pem -text > ./1024/srv_tmp.pem
    check_result $? "Step 4"
    mv ./1024/srv_tmp.pem ./1024/server-cert.pem
    cat ./1024/ca_tmp.pem >> ./1024/server-cert.pem
    rm ./1024/ca_tmp.pem
    echo "End of section"
    echo "---------------------------------------------------------------------"
    ############################################################
    ########## update and sign the server-ecc-rsa.pem ##########
    ############################################################
    echo "Updating server-ecc-rsa.pem"
    echo ""
    echo -e "US\\nMontana\\nBozeman\\nElliptic - RSAsig\\nECC-RSAsig\\nwww.wolfssl.com\\ninfo@wolfssl.com\\n.\\n.\\n" | openssl req -new -key ecc-key.pem -config ./wolfssl.cnf -nodes > server-ecc-req.pem
    check_result $? "Step 1"

    openssl x509 -req -in server-ecc-req.pem -extfile wolfssl.cnf -extensions wolfssl_opts -days 1000 -CA ca-cert.pem -CAkey ca-key.pem -set_serial 01 > server-ecc-rsa.pem
    check_result $? "Step 2"
    rm server-ecc-req.pem

    openssl x509 -in server-ecc-rsa.pem -text > tmp.pem
    check_result $? "Step 3"
    mv tmp.pem server-ecc-rsa.pem
    echo "End of section"
    echo "---------------------------------------------------------------------"
    ############################################################
    ####### update the self-signed client-ecc-cert.pem #########
    ############################################################
    echo "Updating client-ecc-cert.pem"
    echo ""
    #pipe the following arguments to openssl req...
    echo -e "US\\nOregon\\nSalem\\nClient ECC\\nFast\\nwww.wolfssl.com\\ninfo@wolfssl.com\\n.\\n.\\n" | openssl req -new -key ecc-client-key.pem -config ./wolfssl.cnf -nodes -out client-ecc-cert.csr
    check_result $? "Step 1"

    openssl x509 -req -in client-ecc-cert.csr -days 1000 -extfile wolfssl.cnf -extensions wolfssl_opts -signkey ecc-client-key.pem -out client-ecc-cert.pem
    check_result $? "Step 2"
    rm client-ecc-cert.csr

    openssl x509 -in client-ecc-cert.pem -text > tmp.pem
    check_result $? "Step 3"
    mv tmp.pem client-ecc-cert.pem
    echo "End of section"
    echo "---------------------------------------------------------------------"
    ############################################################
    ########## update the server-ecc.pem #######################
    ############################################################
    echo "Updating server-ecc.pem"
    echo ""
    #pipe the following arguments to openssl req...
    echo -e "US\\nWashington\\nSeattle\\nEliptic\\nECC\\nwww.wolfssl.com\\ninfo@wolfssl.com\\n.\\n.\\n" | openssl req -new -key ecc-key.pem -config ./wolfssl.cnf -nodes -out server-ecc.csr
    check_result $? "Step 1"

    openssl x509 -req -in server-ecc.csr -days 1000 -extfile wolfssl.cnf -extensions server_ecc -CA ca-ecc-cert.pem -CAkey ca-ecc-key.pem -set_serial 03 -out server-ecc.pem
    check_result $? "Step 2"
    rm server-ecc.csr

    openssl x509 -in server-ecc.pem -text > tmp.pem
    check_result $? "Step 3"
    mv tmp.pem server-ecc.pem
    echo "End of section"
    echo "---------------------------------------------------------------------"
    ############################################################
    ###### update the self-signed server-ecc-comp.pem ##########
    ############################################################
    echo "Updating server-ecc-comp.pem"
    echo ""
    #pipe the following arguments to openssl req...
    echo -e "US\\nMontana\\nBozeman\\nElliptic - comp\\nServer ECC-comp\\nwww.wolfssl.com\\ninfo@wolfssl.com\\n.\\n.\\n" | openssl req -new -key ecc-key-comp.pem -config ./wolfssl.cnf -nodes -out server-ecc-comp.csr
    check_result $? "Step 1"

    openssl x509 -req -in server-ecc-comp.csr -days 1000 -extfile wolfssl.cnf -extensions wolfssl_opts -signkey ecc-key-comp.pem -out server-ecc-comp.pem
    check_result $? "Step 2"
    rm server-ecc-comp.csr

    openssl x509 -in server-ecc-comp.pem -text > tmp.pem
    check_result $? "Step 3"
    mv tmp.pem server-ecc-comp.pem
    echo "End of section"
    echo "---------------------------------------------------------------------"
    ############################################################
    ############## create the client-ca.pem file ###############
    ############################################################
    echo "Updating client-ca.pem"
    echo ""
    cat client-cert.pem client-ecc-cert.pem > client-ca.pem
    echo "End of section"
    echo "---------------------------------------------------------------------"
    ############################################################
    ###### update the self-signed ecc-privOnlyCert.pem #########
    ############################################################
    echo "Updating ecc-privOnlyCert.pem"
    echo ""
    #pipe the following arguments to openssl req...
    echo -e ".\\n.\\n.\\nWR\\n.\\nDE\\n.\\n.\\n.\\n" | openssl req -new -key ecc-privOnlyKey.pem -config ./wolfssl.cnf -nodes -out ecc-privOnly.csr
    check_result $? "Step 1"

    openssl x509 -req -in ecc-privOnly.csr -days 1000 -signkey ecc-privOnlyKey.pem -out ecc-privOnlyCert.pem
    check_result $? "Step 2"
    rm ecc-privOnly.csr
    echo "End of section"
    echo "---------------------------------------------------------------------"
    ############################################################
    ###### update the self-signed test/digsigku.pem   ##########
    ############################################################
    echo "Updating test/digsigku.pem"
    echo ""
    #pipe the following arguments to openssl req...
    echo -e "US\\nWashington\\nSeattle\\nFoofarah\\nArglebargle\\nfoobarbaz\\ninfo@worlss.com\\n.\\n.\\n" | openssl req -new -key ecc-key.pem -config ./wolfssl.cnf -nodes -sha1 -out digsigku.csr
    check_result $? "Step 1"

    openssl x509 -req -in digsigku.csr -days 1000 -extfile wolfssl.cnf -extensions digsigku -signkey ecc-key.pem -sha1 -set_serial 16393466893990650224 -out digsigku.pem
    check_result $? "Step 2"
    rm digsigku.csr

    openssl x509 -in digsigku.pem -text > tmp.pem
    check_result $? "Step 3"
    mv tmp.pem digsigku.pem
    mv digsigku.pem test/digsigku.pem
    echo "End of section"
    echo "---------------------------------------------------------------------"
    ############################################################
    ########## make .der files from .pem files #################
    ############################################################
    echo "Creating der formatted certs..."
    echo ""
    openssl x509 -inform PEM -in ./1024/client-cert.pem -outform DER -out ./1024/client-cert.der
    check_result $? "Der Cert 1"
    openssl x509 -inform PEM -in ./1024/server-cert.pem -outform DER -out ./1024/server-cert.der
    check_result $? "Der Cert 2"
    openssl x509 -inform PEM -in ./1024/ca-cert.pem -outform DER -out ./1024/ca-cert.der
    check_result $? "Der Cert 3"

    openssl x509 -inform PEM -in ca-cert.pem -outform DER -out ca-cert.der
    check_result $? "Der Cert 4"
    openssl x509 -inform PEM -in ca-ecc-cert.pem -outform DER -out ca-ecc-cert.der
    check_result $? "Der Cert 5"
    openssl x509 -inform PEM -in ca-ecc384-cert.pem -outform DER -out ca-ecc384-cert.der
    check_result $? "Der Cert 6"
    openssl x509 -inform PEM -in client-cert.pem -outform DER -out client-cert.der
    check_result $? "Der Cert 7"
    openssl x509 -inform PEM -in server-cert.pem -outform DER -out server-cert.der
    check_result $? "Der Cert 8"
    openssl x509 -inform PEM -in client-ecc-cert.pem -outform DER -out client-ecc-cert.der
    check_result $? "Der Cert 9"
    openssl x509 -inform PEM -in server-ecc-rsa.pem -outform DER -out server-ecc-rsa.der
    check_result $? "Der Cert 10"
    openssl x509 -inform PEM -in server-ecc.pem -outform DER -out server-ecc.der
    check_result $? "Der Cert 11"
    openssl x509 -inform PEM -in server-ecc-comp.pem -outform DER -out server-ecc-comp.der
    check_result $? "Der Cert 12"
    echo "End of section"
    echo "---------------------------------------------------------------------"
    ############################################################
    ###### update the ecc-rsa-server.p12 file ##################
    ############################################################
    echo "Updating ecc-rsa-server.p12 (password is \"\")"
    echo ""
    echo "" | openssl pkcs12 -des3 -descert -export -in server-ecc-rsa.pem -inkey ecc-key.pem -certfile server-ecc.pem -out ecc-rsa-server.p12 -password stdin
    check_result $? "Step 1"
    echo "End of section"
    echo "---------------------------------------------------------------------"
    ############################################################
    ###### update the test-servercert.p12 file #################
    ############################################################
    echo "Updating test-servercert.p12 (password is \"wolfSSL test\")"
    echo ""
    echo "wolfSSL test" | openssl pkcs12 -des3 -descert -export -in server-cert.pem -inkey server-key.pem -certfile ca-cert.pem -out test-servercert.p12 -password stdin
    check_result $? "Step 1"
    echo "End of section"
    echo "---------------------------------------------------------------------"
    ############################################################
    ###### calling gen-ext-certs.sh           ##################
    ############################################################
    echo "Calling gen-ext-certs.sh"
    echo ""
    cd .. || exit 1
    ./certs/test/gen-ext-certs.sh
    check_result $? "gen-ext-certs.sh"
    cd ./certs || { echo "Couldn't cd to certs directory"; exit 1; }
    echo "End of section"
    echo "---------------------------------------------------------------------"
    ############################################################
    ###### calling gen-badsig.sh              ##################
    ############################################################
    echo "Calling gen-badsig.sh"
    echo ""
    cd ./test || { echo "Failed to switch to dir ./test"; exit 1; }
    ./gen-badsig.sh
    check_result $? "gen-badsig.sh"
    cd ../ || exit 1
    echo "End of section"
    echo "---------------------------------------------------------------------"
    ############################################################
    ########## generate ocsp certs        ######################
    ############################################################
    echo "Changing directory to ocsp..."
    echo ""

    # guard against recursive calls to renewcerts.sh
    if [ -d ocsp ]; then
        cd ./ocsp || { echo "Failed to switch to dir ./ocsp"; exit 1; }
        echo "Execute ocsp/renewcerts.sh..."
        ./renewcerts.sh
        check_result $? "renewcerts.sh"
        cd ../ || exit 1
    else
        echo "Error could not find ocsp directory"
        exit 1
    fi
    echo "End of section"
    echo "---------------------------------------------------------------------"
    ############################################################
    ###### calling assemble-chains.sh         ##################
    ############################################################
    echo "Calling assemble-chains.sh"
    echo ""
    cd ./test-pathlen || { echo "Failed to switch to dir ./test-pathlen";
                           exit 1; }
    ./assemble-chains.sh
    check_result $? "assemble-chains.sh"
    cd ../ || exit 1
    echo "End of section"
    echo "---------------------------------------------------------------------"
    ############################################################
    ########## store DER files as buffers ######################
    ############################################################
    echo "Changing directory to wolfssl root..."
    echo ""
    cd ../ || exit 1
    echo "Execute ./gencertbuf.pl..."
    echo ""
    ./gencertbuf.pl
    check_result $? "gencertbuf.pl"
    echo "End of section"
    echo "---------------------------------------------------------------------"
    ############################################################
    ########## generate the new crls ###########################
    ############################################################

    echo "Change directory to wolfssl/certs"
    echo ""
    cd ./certs || { echo "Failed to switch to dir ./certs"; exit 1; }
    echo "We are back in the certs directory"
    echo ""

    echo "Updating the crls..."
    echo ""
    cd ./crl || { echo "Failed to switch to dir ./crl"; exit 1; }
    echo "changed directory: cd/crl"
    echo ""
    ./gencrls.sh
    check_result $? "gencrls.sh"
    echo "ran ./gencrls.sh"
    echo ""

    ############################################################
    ########## generate PKCS7 bundles ##########################
    ############################################################
    echo "Changing directory to wolfssl certs..."
    echo ""
    cd ../ || exit 1
    echo "Creating test-degenerate.p7b..."
    echo ""
    openssl crl2pkcs7 -nocrl -certfile ./client-cert.pem -out test-degenerate.p7b -outform DER
    check_result $? ""
    echo "End of section"
    echo "---------------------------------------------------------------------"

    #cleanup the file system now that we're done
    echo "Performing final steps, cleaning up the file system..."
    echo ""

    rm ../wolfssl.cnf
    echo "End of Updates. Everything was successfully updated!"
    echo "---------------------------------------------------------------------"
}

#function for copy and pasting ntru updates
move_ntru(){
    cp ntru-cert.pem certs/ntru-cert.pem || exit 1
    cp ntru-key.raw certs/ntru-key.raw || exit 1
    cp ntru-cert.der certs/ntru-cert.der || exit 1
}

###############################################################################
##################### THE EXECUTABLE BODY #####################################
###############################################################################

#start in root.
cd ../ || exit 1
#if HAVE_NTRU already defined && there is no argument
if grep HAVE_NTRU "wolfssl/options.h" && [ -z "$1" ]
then

    #run the function to renew the certs
    run_renewcerts
    # run_renewcerts will end in the wolfssl/certs/crl dir, backup to root.
    cd ../ || exit 1
    CURRDIR=${PWD##*/}
    if [ "$CURRDIR" = "certs" ]; then
        cd ../ || exit 1
    else
        echo "We are not in the right directory! Abort."
        exit 1
    fi
    echo "changed directory to wolfssl root directory."
    echo ""

    echo ""
    echo "Enter directory to ed25519 certificate generation example."
    echo "Can be found at https://github.com/wolfSSL/wolfssl-examples"
    read -r ED25519_DIR
    if [ -d "${ED25519_DIR}" ]; then
        pushd ./certs/ed25519 || { echo "Failed to push certs/ed25519";
                                   exit 1; }
        ./gen-ed25519.sh "${ED25519_DIR}"
        check_result $? "./gen-ed25519.sh"
        popd || exit 1
    else
        echo "Unable to find directory ${ED25519_DIR}"
        exit 1
    fi

    ############################################################
    ########## update ntru if already installed ################
    ############################################################

    # We cannot assume that user has certgen and keygen enabled
    CFLAG_TMP="-DWOLFSSL_STATIC_RSA"
    export CFLAGS=${CFLAG_TMP}
    ./configure --with-ntru --enable-certgen --enable-keygen
    check_result $? "configure for ntru"
    make check
    check_result $? "make check with ntru"
    export CFLAGS=""

    #copy/paste ntru-certs and key to certs/
    move_ntru

#else if there was an argument given, check it for validity or print out error
elif [ ! -z "$1" ]; then
    #valid argument then renew certs without ntru
    if [ "$1" == "--override-ntru" ]; then
        echo "overriding ntru, update all certs except ntru."
        run_renewcerts
    #valid argument create ed25519 certificates
    elif [ "$1" == "--ed25519" ] || [ "$2" == "--ed25519" ]; then
        echo ""
        echo "Enter directory to ed25519 certificate generation example."
        echo "Can be found at https://github.com/wolfSSL/wolfssl-examples"
        read -r ED25519_DIR
        pushd ./certs/ed25519 || { echo "failed to push ./certs/ed25519";
                                   exit 1; }
        ./gen-ed25519.sh "${ED25519_DIR}"
        check_result $? "./gen-ed25519.sh"
        popd || exit 1
    #valid argument print out other valid arguments
    elif [ "$1" == "-h" ] || [ "$1" == "-help" ]; then
        echo ""
        echo "\"no argument\"        will attempt to update all certificates"
        echo "--override-ntru      updates all certificates except ntru"
        echo "--ed25519            updates all ed25519 certificates"
        echo "-h or -help          display this menu"
        echo ""
        echo ""
    #else the argument was invalid, tell user to use -h or -help
    else
        echo ""
        echo "That is not a valid option."
        echo ""
        echo "use -h or -help for a list of available options."
        echo ""
    fi
#else HAVE_NTRU not already defined
else
    echo "Saving the configure state"
    echo ""
    cp config.status tmp.status || exit 1
    cp wolfssl/options.h tmp.options.h || exit 1

    echo "Running make clean"
    echo ""
    make clean
    check_result $? "make clean"

    #attempt to define ntru by configuring with ntru
    echo "Configuring with ntru, enabling certgen and keygen"
    echo ""
    CFLAG_TMP="-DWOLFSSL_STATIC_RSA"
    export CFLAGS=${CFLAG_TMP}
    ./configure --with-ntru --enable-certgen --enable-keygen
    check_result $? "configure for ntru"
    make check
    check_result $? "make check with ntru"
    export CFLAGS=""

    # check options.h a second time, if the user had
    # ntru installed on their system and in the default
    # path location, then it will now be defined, if the
    # user does not have ntru on their system this will fail
    # again and we will not update any certs until user installs
    # ntru in the default location

    # if now defined
    if grep HAVE_NTRU "wolfssl/options.h"; then
        run_renewcerts
        #run_renewcerts leaves us in wolfssl/certs/crl, backup to root
        cd ../ || exit 1
        CURRDIR=${PWD##*/}
        if [ "$CURRDIR" = "certs" ]; then
            cd ../ || exit 1
        else
            echo "We are not in the right directory! Abort."
            exit 1
        fi
        echo "changed directory to wolfssl root directory."
        echo ""

        move_ntru

        echo "ntru-certs, and ntru-key.raw have been updated"
        echo ""

        # restore previous configure state
        restore_config
        check_result $? "restoring old configuration"
    else

        # restore previous configure state
        restore_config
        check_result $? "restoring old configuration"

        echo ""
        echo "ntru is not installed at the default location,"
        echo "or ntru not installed, none of the certs were updated."
        echo ""
        echo "clone the ntru repository into your \"cd ~\" directory then,"
        echo "\"cd NTRUEncrypt\" and run \"make\" then \"make install\""
        echo "once complete run this script again to update all the certs."
        echo ""
        echo "To update all certs except ntru use \"./renewcerts.sh --override-ntru\""
        echo ""

    fi #END now defined
fi #END already defined

exit 0
