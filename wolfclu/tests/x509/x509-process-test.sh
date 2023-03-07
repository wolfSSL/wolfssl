#!/bin/bash

if [ ! -d ./certs/ ]; then
    #return 77 to indicate to automake that the test was skipped
    exit 77
fi

# Skip test if filesystem disabled
FILESYSTEM=`cat config.log | grep "disable\-filesystem"`
if [ "$FILESYSTEM" != "" ]
then
    exit 77
fi

test_case() {
    echo "testing: ./wolfssl -x509 $1"
    OUTPUT=$(./wolfssl -x509 $1)
    RESULT=$?
    if [ $RESULT != 0 ]; then
        echo "Failed when expected to pass"
        exit 99
    fi
}

fail_case() {
    echo "testing: ./wolfssl -x509 $1"
    OUTPUT=$(./wolfssl -x509 $1)
    RESULT=$?
    if [ $RESULT == 0 ]; then
        echo "Success when expected to fail"
        exit 99
    fi
}

cert_test_case() {
    echo "testing: ./wolfssl -x509 $1"
    OUTPUT=$(./wolfssl -x509 $1)
    RESULT=$?
    echo "RESULT: $RESULT"
    diff $2 $3
    RESULT=$?
    echo "RESULT OF DIFF: $RESULT"
    [ $RESULT != 0 ] && echo "DIFF FAILED" && exit 5
    echo ""
}

# For check_cert_signature to perform a meaningful check, it needs the public
# key used to sign the cert (i.e. the cert must be self-signed).
check_cert_signature() {
    local FAILED=0

    echo "Checking certificate $1's signature."

    # Use OpenSSL to convert to PEM to remove any leading text in the
    # certificate file or to convert DER to PEM.
    openssl x509 -in $1 -out cert_stripped.pem -outform PEM

    # Extract the hex of the signature from the cert. OpenSSL 3+ uses
    # 'Signature Value' for the signature label string
    openssl x509 -in cert_stripped.pem -text -noout \
                                 -certopt ca_default -certopt no_validity \
                                 -certopt no_serial -certopt no_subject \
                                 -certopt no_extensions -certopt no_signame | \
                                 grep -v 'Signature Algorithm' | \
                                 grep -v 'Signature Value' | \
                                 tr -d '[:space:]:' > cert_sig_hex.bin
    # Convert hex string to binary file.
    cat cert_sig_hex.bin | xxd -r -p > cert_sig.bin
    # Write the certificate body to a binary file.
    openssl asn1parse -in cert_stripped.pem -strparse 4 \
                      -out cert_body.bin -noout
    RESULT=$?
    if [ $RESULT != 0 ]; then
        echo "Failed to extract certificate body from $1."
        FAILED=1
    fi
    if [ $FAILED == 0 ]; then
        # Extract the public key from the cert.
        openssl x509 -in cert_stripped.pem -noout -pubkey > cert_pub.pem
        RESULT=$?
        if [ $RESULT != 0 ]; then
            echo "Failed to extract public key from $1."
            FAILED=1
        fi
    fi
    if [ $FAILED == 0 ]; then
        # Verify the signature.
        openssl dgst -$2 -verify cert_pub.pem \
                     -signature cert_sig.bin cert_body.bin
        RESULT=$?
        if [ $RESULT != 0 ]; then
            echo "Signature for $1 is bad."
            FAILED=1
        fi
    fi

    if [ $FAILED == 1 ]; then
        exit 99
    fi

    rm -f cert_sig.bin
    rm -f cert_sig_hex.bin
    rm -f cert_body.bin
    rm -f cert_pub.pem
}

run1() {
    echo "TEST 1: VALID"
    echo "TEST 1.a"
    test_case "-inform pem -outform pem -in certs/ca-cert.pem -out test.pem"
    # Check PEM -> PEM didn't alter any data by checking the validity of the
    # signature.
    check_cert_signature test.pem sha256
    if [ ! -f test.pem ]; then
        echo "issue creating output file"
        exit 99
    fi
    echo ""

    echo "TEST 1.b"
    ./wolfssl x509 -in test.pem -text -noout -out test.pem
    ./wolfssl x509 -in certs/ca-cert.pem -text -noout -out ca-cert.pem
    diff "./ca-cert.pem" "./test.pem" &> /dev/null
    if [ $? != 0 ]; then
        echo "issue with in pem out pem matching"
        exit 99
    fi
    rm -f ca-cert.pem
    rm -f test.pem
    echo ""

    echo "TEST 1.c"
    test_case "-inform pem -outform der -in certs/ca-cert.pem -out test.der"
    # Check PEM -> DER didn't alter any data
    check_cert_signature test.der sha256
    rm -f test.der
    echo ""

    echo "TEST 1.d"
    test_case "-inform der -outform pem -in certs/ca-cert.der"
    echo ""

    echo "TEST 1.e"
    test_case "-inform der -outform der -in certs/ca-cert.der -out test.der"
    # Check DER -> DER didn't alter any data
    check_cert_signature test.der sha256
    rm -f test.der
    echo ""

    echo "TEST 1.f"
    test_case "-inform der -text -noout -in certs/ca-cert.der"
    echo ""

    echo "TEST 1.g"
    test_case "-inform der -pubkey -noout -in certs/ca-cert.der"
    echo ""

    echo "TEST 1.h"
    test_case "-inform der -outform pem -in certs/ca-cert.der -out test.pem"
    # Check DER -> PEM didn't alter any data
    check_cert_signature test.pem sha256
    echo ""

    echo "TEST 1.i"
    cat ./certs/ca-key.pem > combined.pem
    cat ./certs/ca-cert.pem >> combined.pem
    test_case "-in combined.pem -out process_x509.pem"
    test_case "-in process_x509.pem -text"
    echo -e $OUTPUT > ./process_x509.pem

    test_case "-in ./certs/ca-cert.pem -text"
    echo -e $OUTPUT > ./process_ca-cert.pem
    diff ./process_ca-cert.pem ./process_x509.pem
    if [ $? -ne 0 ]; then
        echo "Unexpected output difference"
        exit 99
    fi

    MODULUS=`./wolfssl x509 -in certs/server-cert.pem -modulus -noout`
    if [ "$MODULUS" != "Modulus=C09508E15741F2716DB7D24541270165C645AEF2BC2430B895CE2F4ED6F61C88BC7C9FFBA8677FFE5C9C5175F78ACA07E7352F8FE1BD7BC02F7CAB64A817FCCA5D7BBAE021E5722E6F2E86D89573DAAC1B53B95F3FD7190D254FE16363518B0B643FAD43B8A51C5C34B3AE00A063C5F67F0B59687873A68C18A9026DAFC319012EB810E3C6CC40B469A3463369876EC4BB17A6F3E8DDAD73BC7B2F21B5FD66510CBD54B3E16D5F1CBC2373D109038914D210B964C32AD0A1964ABCE1D41A5BC7A0C0C163780F443730329680322395A177BA13D29773E25D25C96A0DC33960A4B4B069424209E9D808BC3320B35822A7AAEBC4E1E66183C5D296DFD9D04FADD7" ]
    then
        echo "found unexpected Modulus : $MODULUS"
        exit 99
    fi


    rm -f combined.pem
    rm -f process_x509.pem
    rm -f process_ca-cert.pem
    echo ""
}

run2() {
    echo "TEST 2: INVALID INPUT"
    echo "TEST 2.a"
    fail_case "-inform pem -inform der"
    echo "TEST 2.b"
    fail_case "-outform pem -outform der"
    echo "TEST 2.c"
    fail_case "-inform -inform"
    echo "TEST 2.d"
    fail_case "-outform -outform"
    echo "TEST 2.e"
    fail_case "-inform pem -inform der -inform"
    echo "TEST 2.f"
    fail_case "-outform pem -outform der -outform"
    echo "TEST 2.g"
    fail_case "-inform pem -outform der -inform"
    echo "TEST 2.h"
    fail_case "-outform pem -inform der -outform"
    echo "TEST 2.i"
    fail_case "-inform"
    echo "TEST 2.j"
    fail_case "-outform"
    echo "TEST 2.k"
    fail_case "-outform pem -outform der -noout"
    echo "TEST 2.l"
    fail_case "-outform -outform -noout"
    echo "TEST 2.m"
    fail_case "-outform pem -outform der -outform -noout"
    echo "TEST 2.n"
    fail_case "-inform pem -outform der -inform -noout"
    echo "TEST 2.o"
    fail_case "-outform pem -inform der -outform -noout"
    echo "TEST 2.p"
    fail_case "-outform -noout"

#    hangs waiting on stdin input (same as openssl)
#    echo "TEST 2.q"
#    fail_case "-inform pem -outform pem -noout"
}

run3() {
    echo "TEST3: VALID INPUT FILES"
    echo "TEST 3.a"
    # convert ca-cert.der to tmp.pem and compare to ca-cert.pem for valid
    # transform
    ./wolfssl x509 -inform pem -in certs/ca-cert.pem -outform pem -out test.pem
    cert_test_case "-inform der -in certs/ca-cert.der -outform pem -out tmp.pem" \
                   test.pem tmp.pem
    rm -f test.pem tmp.pem
    echo "TEST 3.b"
    ./wolfssl x509 -inform pem -in certs/ca-cert.pem -outform der -out x509_test.der
    cert_test_case "-inform pem -outform der -in certs/ca-cert.pem -out x509_tmp.der" \
                    x509_test.der x509_tmp.der
    rm -f x509_test.pem x509_tmp.pem
    echo "TEST 3.c"
    test_case "-in certs/server-cert.pem -subject -noout"
    EXPECTED="/C=US/ST=Montana/L=Bozeman/O=wolfSSL/OU=Support/CN=www.wolfssl.com/emailAddress=info@wolfssl.com"
    if [ "$OUTPUT" != "$EXPECTED" ]; then
        echo "found unexpected $OUTPUT"
        echo "expected $EXPECTED"
        exit 99
    fi
    echo "TEST 3.d"
    test_case "-in certs/server-cert.pem -issuer -noout"
    EXPECTED="/C=US/ST=Montana/L=Bozeman/O=Sawtooth/OU=Consulting/CN=www.wolfssl.com/emailAddress=info@wolfssl.com"
    if [ "$OUTPUT" != "$EXPECTED" ]; then
        echo "found unexpected $OUTPUT"
        echo "expected $EXPECTED"
        exit 99
    fi
    echo "TEST 3.e"
    test_case "-in certs/ca-cert.pem -serial -noout"
    EXPECTED="serial=7D947088BA07428DAAAF4FBEC21A48F0D140E642"
    if [ "$OUTPUT" != "$EXPECTED" ]; then
        echo "found unexpected $OUTPUT"
        echo "expected $EXPECTED"
        exit 99
    fi
    echo "TEST 3.f"
    test_case "-in certs/server-cert.pem -serial -noout"
    EXPECTED="serial=01"
    if [ "$OUTPUT" != "$EXPECTED" ]; then
        echo "found unexpected $OUTPUT"
        echo "expected $EXPECTED"
        exit 99
    fi
    echo "TEST 3.g"
    test_case "-in certs/server-cert.pem -dates -noout"
    EXPECTED="notBefore=Dec 20 23:07:25 2021 GMT
notAfter=Sep 15 23:07:25 2024 GMT"
    if [ "$OUTPUT" != "$EXPECTED" ]; then
        echo "found unexpected $OUTPUT"
        echo "expected $EXPECTED"
        exit 99
    fi
    echo "TEST 3.h"
    test_case "-in certs/server-cert.pem -email -noout"
    EXPECTED="info@wolfssl.com"
    if [ "$OUTPUT" != "$EXPECTED" ]; then
        echo "found unexpected $OUTPUT"
        echo "expected $EXPECTED"
        exit 99
    fi
    echo "TEST 3.i"
    test_case "-in certs/server-cert.pem -fingerprint -noout"
    EXPECTED="SHA1 of cert. DER : 52686B24F54652F04B0D87BA9F591B393C86C407"
    if [ "$OUTPUT" != "$EXPECTED" ]; then
        echo "found unexpected $OUTPUT"
        echo "expected $EXPECTED"
        exit 99
    fi
    echo "TEST 3.j"
    test_case "-in certs/server-cert.pem -purpose -noout"
    EXPECTED="Certificate Purpose:
Any Extended Key Usage : YES
TLS Web Server Authentication : YES
TLS Web Client Authentication : NO
OCSP Signing : YES
Email Protect : YES
Time Stamp Signing : YES"
    if [ "$OUTPUT" != "$EXPECTED" ]; then
        echo "found unexpected $OUTPUT"
        echo "expected $EXPECTED"
        exit 99
    fi
    echo "TEST 3.k"
    test_case "-in certs/server-cert.pem -hash -noout"
    EXPECTED="137dc03f"
    OLD_EXPECTED="f6cf410e" #was fixed to match OpenSSL after release 5.1.1
    if [ "$OUTPUT" != "$EXPECTED" ] && [ "$OUTPUT" != "$OLD_EXPECTED" ]; then
        echo "found unexpected $OUTPUT"
        echo "expected $EXPECTED"
        exit 99
    fi
    echo "TEST 3.l"
    ./wolfssl req -new -days 3650 -key ./certs/server-key.pem -subj /O=wolfSSL/C=US/ST=WA/L=Seattle/CN=wolfSSL/OU=org-unit -out x509-process-tmp.cert -x509
    test_case "-in x509-process-tmp.cert -email -noout"
    rm -f x509-process-tmp.cert
}

run4() {
    echo "TEST4: INVALID INPUT FILES"
    echo "TEST 4.a"
    #convert ca-cert.der to tmp.pem and compare to ca-cert.pem for valid transform
    fail_case "-inform der -in certs/ca-cert.der
                    -in certs/ca-cert.der -outform pem -out tmp.pem"
    echo "TEST 4.b"
    fail_case "-inform der -in certs/ca-cert.der
                    -outform pem -out tmp.pem -out tmp.pem"

    echo "TEST 4.c"
    fail_case "-inform pem -outform der -in certs/ca-cert.pem
                    -out tmp.der -out tmp.der -in certs/ca-cert.pem"
    echo "TEST 4.d"
    rm -f test.der
    fail_case "-inform pem -in certs/ca-cert.der -outform der -out test.der"
    if [ -f test.der ]; then
        echo "./wolfssl x509 -inform pem -in certs/ca-cert.der -outform der -out test.der"
        echo "Should not have created output file in error case!"
        rm -f test.der
        exit 99
    fi
    rm -f test.der
    echo "TEST 4.e"
    fail_case "-inform der -in ca-cert.pem -outform der -out out.txt"
    echo "TEST 4.f"
    fail_case "-inform pem -in ca-cert.pem -outform pem -out out.txt"
}

run1
run2
run3
run4

rm -f out.txt
rm -f tmp.pem
rm -f tmp.der

echo "Done"
exit 0
