#!/usr/bin/env bash
#
# Regenerate SLH-DSA root certificates and ML-DSA-44 entity certificates
# used by tests/test-tls13-slhdsa-{shake,sha2}.conf.
#
# Requires: OpenSSL >= 3.5 (native SLH-DSA + ML-DSA support).
#
# The ML-DSA-44 entity keys are reused from ../mldsa/ (mldsa44_bare-priv.der
# for the server, mldsa44_seed-priv.der for the client) so this script does
# not generate or write new entity private keys.

check_result(){
    if [ "$1" -ne 0 ]; then
        echo "Failed at \"$2\", Abort"
        exit 1
    else
        echo "Step Succeeded!"
    fi
}

# Always operate inside the script's own directory so relative paths
# (../mldsa/, ../renewcerts/) resolve regardless of where the script
# was invoked from.
cd "$(dirname "$0")"

# Capability probe: bail out cleanly if the local OpenSSL doesn't speak
# SLH-DSA (e.g. < 3.5). The committed PEM/DER under this directory are the
# authoritative test fixtures; this script is for renewal only. `-help`
# prints regardless of algorithm support, so we actually try a generation
# (output discarded) and check the exit code.
if ! openssl genpkey -algorithm SLH-DSA-SHAKE-128s -out /dev/null \
        >/dev/null 2>&1; then
    echo "OpenSSL does not support SLH-DSA"
    echo "Skipping SLH-DSA certificate renewal"
    exit 0
fi

if ! openssl genpkey -algorithm ML-DSA-44 -out /dev/null \
        >/dev/null 2>&1; then
    echo "OpenSSL does not support ML-DSA"
    echo "Skipping SLH-DSA certificate renewal"
    exit 0
fi

CNF=../renewcerts/wolfssl.cnf
SERVER_KEY_DER=../mldsa/mldsa44_bare-priv.der
CLIENT_KEY_DER=../mldsa/mldsa44_seed-priv.der

if [ ! -f "$SERVER_KEY_DER" ] || [ ! -f "$CLIENT_KEY_DER" ]; then
    echo "Missing reused ML-DSA-44 entity keys under ../mldsa/"
    exit 1
fi

# wolfSSL example server only loads PEM keys from CLI, so emit a PEM
# transcoding of each reused DER key under this directory. These are
# byte-for-byte the same key material as the source .der files; we just
# wrap them in PEM headers so the .conf-driven test harness can use them.
SERVER_KEY=server-mldsa44-priv.pem
CLIENT_KEY=client-mldsa44-priv.pem

openssl pkey -in "$SERVER_KEY_DER" -inform DER -out "$SERVER_KEY"
check_result $? "Convert server ML-DSA-44 key to PEM"
openssl pkey -in "$CLIENT_KEY_DER" -inform DER -out "$CLIENT_KEY"
check_result $? "Convert client ML-DSA-44 key to PEM"

# $1 = tag (shake|sha2), $2 = OpenSSL algorithm name
gen_variant() {
    local tag=$1
    local alg=$2
    local root_base="root-slhdsa-${tag}-128s"

    echo "====================================================================="
    echo " Generating ${alg} root + ML-DSA-44 entity certs (tag=${tag})"
    echo "====================================================================="

    ############################################################
    # Self-signed SLH-DSA root
    ############################################################
    echo "Generating ${root_base} key + self-signed cert"
    openssl genpkey -algorithm "$alg" -out "${root_base}-priv.pem"
    check_result $? "Generate SLH-DSA root key (${tag})"

    echo -e "US\\nMontana\\nBozeman\\nwolfSSL_SLH-DSA\\nRoot-SLH-DSA-${tag}\\nwww.wolfssl.com\\ninfo@wolfssl.com\\n.\\n.\\n" | \
        openssl req -new -key "${root_base}-priv.pem" -config "$CNF" -nodes \
            -out "${root_base}.csr"
    check_result $? "Generate root CSR (${tag})"

    openssl x509 -req -in "${root_base}.csr" -days 1000 \
        -extfile "$CNF" -extensions ca_ecc_cert \
        -signkey "${root_base}-priv.pem" \
        -out "${root_base}.pem"
    check_result $? "Generate root cert (${tag})"
    rm -f "${root_base}.csr"

    openssl x509 -in "${root_base}.pem" -outform DER > "${root_base}.der"
    check_result $? "Convert root cert to DER (${tag})"
    openssl pkey -in "${root_base}-priv.pem" -outform DER \
        -out "${root_base}-priv.der"
    check_result $? "Convert root key to DER (${tag})"

    openssl x509 -in "${root_base}.pem" -text > tmp.pem
    mv tmp.pem "${root_base}.pem"

    ############################################################
    # ML-DSA-44 server cert signed by the SLH-DSA root
    ############################################################
    local server_cert="server-mldsa44-${tag}.pem"
    echo "Generating ${server_cert}"
    echo -e "US\\nMontana\\nBozeman\\nwolfSSL_SLH-DSA\\nServer-mldsa44-${tag}\\nwww.wolfssl.com\\ninfo@wolfssl.com\\n\\n\\n\\n" | \
        openssl req -new -key "$SERVER_KEY" -config "$CNF" -nodes \
            -out "server-mldsa44-${tag}.csr"
    check_result $? "Generate server CSR (${tag})"

    openssl x509 -req -in "server-mldsa44-${tag}.csr" -days 1000 \
        -extfile "$CNF" -extensions server_ecc \
        -CA "${root_base}.pem" -CAkey "${root_base}-priv.pem" \
        -set_serial 01 \
        -out "server-mldsa44-${tag}-cert.pem"
    check_result $? "Sign server cert (${tag})"
    rm -f "server-mldsa44-${tag}.csr"

    openssl x509 -in "server-mldsa44-${tag}-cert.pem" -outform DER \
        > "server-mldsa44-${tag}.der"
    check_result $? "Server cert to DER (${tag})"

    openssl x509 -in "server-mldsa44-${tag}-cert.pem" -text > tmp.pem
    mv tmp.pem "server-mldsa44-${tag}-cert.pem"

    # Server-served chain: leaf || root (ed25519 convention)
    cat "server-mldsa44-${tag}-cert.pem" "${root_base}.pem" > "$server_cert"
    rm -f "server-mldsa44-${tag}-cert.pem"

    ############################################################
    # ML-DSA-44 client cert signed by the SLH-DSA root
    ############################################################
    local client_cert="client-mldsa44-${tag}.pem"
    echo "Generating ${client_cert}"
    echo -e "US\\nMontana\\nBozeman\\nwolfSSL_SLH-DSA\\nClient-mldsa44-${tag}\\nwww.wolfssl.com\\ninfo@wolfssl.com\\n\\n\\n\\n" | \
        openssl req -new -key "$CLIENT_KEY" -config "$CNF" -nodes \
            -out "client-mldsa44-${tag}.csr"
    check_result $? "Generate client CSR (${tag})"

    openssl x509 -req -in "client-mldsa44-${tag}.csr" -days 1000 \
        -extfile "$CNF" -extensions client_ecc \
        -CA "${root_base}.pem" -CAkey "${root_base}-priv.pem" \
        -set_serial 02 \
        -out "client-mldsa44-${tag}-cert.pem"
    check_result $? "Sign client cert (${tag})"
    rm -f "client-mldsa44-${tag}.csr"

    openssl x509 -in "client-mldsa44-${tag}-cert.pem" -outform DER \
        > "client-mldsa44-${tag}.der"
    check_result $? "Client cert to DER (${tag})"

    openssl x509 -in "client-mldsa44-${tag}-cert.pem" -text > tmp.pem
    mv tmp.pem "client-mldsa44-${tag}-cert.pem"

    cat "client-mldsa44-${tag}-cert.pem" "${root_base}.pem" > "$client_cert"
    rm -f "client-mldsa44-${tag}-cert.pem"

    echo "Variant ${tag} complete."
}

gen_variant shake SLH-DSA-SHAKE-128s
gen_variant sha2  SLH-DSA-SHA2-128s

echo
echo "All SLH-DSA / ML-DSA-44 test certificates regenerated."
