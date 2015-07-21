    ###########################################################
    ########## update and sign server-cert.pem ################
    ###########################################################
    echo "Updating server-cert.pem"
    echo ""
    #pipe the following arguments to openssl req...
    echo -e "US\nMontana\nBozeman\nwolfSSL\nSupport\nwww.wolfssl.com\ninfo@wolfssl.com\n.\n.\n" | openssl req -new -key server-key.pem -nodes > server-req.pem

    openssl x509 -req -in server-req.pem -extfile renewcerts/wolfssl.cnf -extensions wolfssl_opts -days 1000 -CA ca-cert.pem -CAkey ca-key.pem -set_serial 01 > server-revoked.pem

    rm server-req.pem

    openssl x509 -in ca-cert.pem -text > ca_tmp.pem
    openssl x509 -in server-revoked.pem -text > srv_tmp.pem
    mv srv_tmp.pem server-revoked.pem
    cat ca_tmp.pem >> server-revoked.pem
    rm ca_tmp.pem

