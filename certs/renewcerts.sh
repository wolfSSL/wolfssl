#!/bin/bash
###############################################################################
######################## FUNCTIONS SECTION ####################################
###############################################################################

#the function that will be called when we are ready to renew the certs.
function run_renewcerts(){
    cd certs/
    echo ""
    #move the custom cnf into our working directory
    cp renewcerts/cyassl.cnf cyassl.cnf

    # To generate these all in sha1 add the flag "-sha1" on appropriate lines
    # That is all lines beginning with:  "openssl req"

    ############################################################
    ########## update the self-signed client-cert.pem ##########
    ############################################################
    echo "Updating client-cert.pem"
    echo ""
    #pipe the following arguments to openssl req...
    echo -e "US\nMontana\nBozeman\nwolfSSL\nProgramming\nwww.wolfssl.com\ninfo@wolfssl.com\n.\n.\n" | openssl req -new -key client-key.pem -nodes -out client-cert.csr


    openssl x509 -req -in client-cert.csr -days 1000 -extfile cyassl.cnf -extensions cyassl_opts -signkey client-key.pem -out client-cert.pem
    rm client-cert.csr

    openssl x509 -in client-cert.pem -text > tmp.pem
    mv tmp.pem client-cert.pem
    ############################################################
    ########## update the self-signed ca-cert.pem ##############
    ############################################################
    echo "Updating ca-cert.pem"
    echo ""
    #pipe the following arguments to openssl req...
    echo -e  "US\nMontana\nBozeman\nSawtooth\nConsulting\nwww.wolfssl.com\ninfo@wolfssl.com\n.\n.\n" | openssl req -new -key ca-key.pem -nodes -out ca-cert.csr

    openssl x509 -req -in ca-cert.csr -days 1000 -extfile cyassl.cnf -extensions cyassl_opts -signkey ca-key.pem -out ca-cert.pem
    rm ca-cert.csr

    openssl x509 -in ca-cert.pem -text > tmp.pem
    mv tmp.pem ca-cert.pem
    ###########################################################
    ########## update and sign server-cert.ptm ################
    ###########################################################
    echo "Updating server-cert.pem"
    echo ""
    #pipe the following arguments to openssl req...
    echo -e "US\nMontana\nBozeman\nwolfSSL\nSupport\nwww.wolfssl.com\ninfo@wolfssl.com\n.\n.\n" | openssl req -new -key server-key.pem -nodes > server-req.pem

    openssl x509 -req -in server-req.pem -extfile cyassl.cnf -extensions cyassl_opts -days 1000 -CA ca-cert.pem -CAkey ca-key.pem -set_serial 01 > server-cert.pem

    rm server-req.pem

    openssl x509 -in ca-cert.pem -text > ca_tmp.pem
    openssl x509 -in server-cert.pem -text > srv_tmp.pem
    mv srv_tmp.pem server-cert.pem
    cat ca_tmp.pem >> server-cert.pem
    rm ca_tmp.pem
    ############################################################
    ########## update and sign the server-ecc-rsa.pem ##########
    ############################################################
    echo "Updating server-ecc-rsa.pem"
    echo ""
    echo -e "US\nMontana\nBozeman\nElliptic - RSAsig\nECC-RSAsig\nwww.wolfssl.com\ninfo@wolfssl.com\n.\n.\n" | openssl req -new -key ecc-key.pem -nodes > server-ecc-req.pem

    openssl x509 -req -in server-ecc-req.pem -extfile cyassl.cnf -extensions cyassl_opts -days 1000 -CA ca-cert.pem -CAkey ca-key.pem -set_serial 01 > server-ecc-rsa.pem

    rm server-ecc-req.pem

    openssl x509 -in server-ecc-rsa.pem -text > tmp.pem
    mv tmp.pem server-ecc-rsa.pem

    ############################################################
    ########## make .der files from .pem files #################
    ############################################################
    echo "Generating new ca-cert.der, client-cert.der, server-cert.der..."
    echo ""
    openssl x509 -inform PEM -in ca-cert.pem -outform DER -out ca-cert.der
    openssl x509 -inform PEM -in client-cert.pem -outform DER -out client-cert.der
    openssl x509 -inform PEM -in server-cert.pem -outform DER -out server-cert.der
    echo "Changing directory to cyassl root..."
    echo ""
    cd ../
    echo "Execute ./gencertbuf.pl..."
    echo ""
    ./gencertbuf.pl
    ############################################################
    ########## generate the new crls ###########################
    ############################################################

    echo "Change directory to cyassl/certs"
    echo ""
    cd certs
    echo "We are back in the certs directory"
    echo ""

    #set up the file system for updating the crls
    echo "setting up the file system for generating the crls..."
    echo ""
    touch crl/index.txt
    touch crl/crlnumber
    echo "01" >> crl/crlnumber
    touch crl/blank.index.txt
    mkdir crl/demoCA
    touch crl/demoCA/index.txt

    echo "Updating the crls..."
    echo ""
    cd crl
    echo "changed directory: cd/crl"
    echo ""
    ./gencrls.sh
    echo "ran ./gencrls.sh"
    echo ""

    #cleanup the file system now that we're done
    echo "Performing final steps, cleaning up the file system..."
    echo ""

    rm ../cyassl.cnf
    rm blank.index.txt
    rm index.*
    rm crlnumber*
    rm -r demoCA
    echo "Removed ../cyassl.cnf, blank.index.txt, index.*, crlnumber*, demoCA/"
    echo ""

}

#function for restoring a previous configure state
function restore_config(){
    mv tmp.status config.status
    mv tmp.options.h cyassl/options.h
    make clean
    make -j 8
}

#function for copy and pasting ntru updates
function move_ntru(){
    cp ntru-cert.pem certs/ntru-cert.pem
    cp ntru-key.raw certs/ntru-key.raw
}

###############################################################################
##################### THE EXECUTABLE BODY #####################################
###############################################################################

#start in root.
cd ../
#if HAVE_NTRU already defined && there is no argument
if grep HAVE_NTRU "cyassl/options.h" && [ -z "$1" ]
then

    #run the function to renew the certs
    run_renewcerts
    # run_renewcerts will end in the cyassl/certs/crl dir, backup to root.
    cd ../../
    echo "changed directory to cyassl root directory."
    echo ""

    ############################################################
    ########## update ntru if already installed ################
    ############################################################

    # We cannot assume that user has certgen and keygen enabled
    ./configure --with-ntru --enable-certgen --enable-keygen
    make check

    #copy/paste ntru-certs and key to certs/
    move_ntru

#else if there was an argument given, check it for validity or print out error
elif [ ! -z "$1" ]; then
    #valid argument then renew certs without ntru
    if [ "$1" == "--override-ntru" ]; then
        echo "overriding ntru, update all certs except ntru."
        run_renewcerts
    #valid argument print out other valid arguments
    elif [ "$1" == "-h" ] || [ "$1" == "-help" ]; then
        echo ""
        echo "\"no argument\"        will attempt to update all certificates"
        echo "--override-ntru      updates all certificates except ntru"
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
    cp config.status tmp.status
    cp cyassl/options.h tmp.options.h

    echo "Running make clean"
    echo ""
    make clean

    #attempt to define ntru by configuring with ntru
    echo "Configuring with ntru, enabling certgen and keygen"
    echo ""
    ./configure --with-ntru --enable-certgen --enable-keygen
    make check

    # check options.h a second time, if the user had
    # ntru installed on their system and in the default
    # path location, then it will now be defined, if the 
    # user does not have ntru on their system this will fail
    # again and we will not update any certs until user installs
    # ntru in the default location

    # if now defined
    if grep HAVE_NTRU "cyassl/options.h"; then
        run_renewcerts
        #run_renewcerts leaves us in cyassl/certs/crl, backup to root
        cd ../../
        echo "changed directory to cyassl root directory."
        echo ""

        move_ntru
             
        echo "ntru-certs, and ntru-key.raw have been updated"
        echo ""

        # restore previous configure state
        restore_config
    else

        # restore previous configure state
        restore_config

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

