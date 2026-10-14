#!/usr/bin/env bash
#
# openvpn-cert-verify.sh
#
# OpenVPN handshakes that check how the peer cert is verified: with
# --peer-fingerprint and no CA (wolfSSL/wolfssl#11698), and with a CA and
# --crl-verify or --verify-hash. Both ends run on localhost with --dev null, so
# no root or tun device is needed.
#
# Usage:
#   openvpn-cert-verify.sh <openvpn binary>

set -euo pipefail

if [ $# -ne 1 ]; then
    echo "usage: $0 <openvpn binary>" >&2
    exit 2
fi

OPENVPN=$(realpath "$1")
WORK=$(mktemp -d)
cd "$WORK"

COMMON=(--dev null --verb 3 --ping 1 --ping-exit 10 --hand-window 10
        --tls-exit --data-ciphers AES-256-GCM)
port=21194
failed=0

cat > openssl.cnf <<'EOF'
[req]
distinguished_name = dn
prompt = no
[dn]
[ca_ext]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[leaf_ext]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
[root_ca]
database = root.db
crlnumber = root.crlnum
default_md = sha256
default_crl_days = 30
[int_ca]
database = int.db
crlnumber = int.crlnum
default_md = sha256
default_crl_days = 30
EOF

# cert <name> <extensions> [issuer]
cert() {
    if [ $# -eq 2 ]; then
        openssl req -x509 -config openssl.cnf -extensions "$2" -newkey ec \
            -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 30 \
            -subj "/CN=$1" -keyout "$1.key" -out "$1.crt" 2>/dev/null
    else
        openssl req -new -config openssl.cnf -newkey ec \
            -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
            -subj "/CN=$1" -keyout "$1.key" -out "$1.csr" 2>/dev/null
        openssl x509 -req -in "$1.csr" -CA "$3.crt" -CAkey "$3.key" \
            -CAcreateserial -days 30 -extfile openssl.cnf -extensions "$2" \
            -out "$1.crt" 2>/dev/null
    fi
}

# crl <ca> <out>
crl() {
    openssl ca -config openssl.cnf -name "$1_ca" -gencrl -cert "$1.crt" \
        -keyfile "$1.key" -out "$2" 2>/dev/null
}

# revoke <ca> <cert>
revoke() {
    openssl ca -config openssl.cnf -name "$1_ca" -revoke "$2" \
        -cert "$1.crt" -keyfile "$1.key" 2>/dev/null
}

fp() {
    openssl x509 -in "$1" -noout -fingerprint -sha256 | cut -d= -f2
}

# Self-signed peer certs, as in the report.
cert server leaf_ext
cert client leaf_ext
# Certs issued by an intermediate, sent with it.
cert root ca_ext
cert int ca_ext root
cert chain leaf_ext int
cert chain-client leaf_ext int
cat chain.crt int.crt > chain-full.crt
cat chain-client.crt int.crt > chain-client-full.crt
# A cert issued by the root itself, and another root.
cert direct leaf_ext root
cert root2 ca_ext
cat root.crt root2.crt > roots.crt
cat direct.crt root2.crt > direct-root2.crt

for ca in root int; do
    : > "$ca.db"
    echo 01 > "$ca.crlnum"
done
crl root root.crl
crl int int.crl
cat root.crl int.crl > crl-good.pem
# The intermediate's status is unknown without the root's CRL.
cp int.crl crl-no-root.pem
revoke int chain.crt
crl int int-revoked.crl
cat root.crl int-revoked.crl > crl-revoked.pem
revoke root int.crt
crl root root-revoked.crl
cat root-revoked.crl int.crl > crl-revoked-int.pem

# run <name> <expect>
# Handshake with the server options in srv and the client options in cli.
# <expect> is "connect", or a line the client has to log instead.
run() {
    local name=$1 expect=$2 result=failed ok=0 spid cpid
    local slog=$name-server.log clog=$name-client.log

    port=$((port + 1))
    "$OPENVPN" "${COMMON[@]}" --tls-server --dh none --proto udp4 \
        --local 127.0.0.1 --lport "$port" "${srv[@]}" > "$slog" 2>&1 &
    spid=$!
    "$OPENVPN" "${COMMON[@]}" --tls-client --proto udp4 \
        --remote 127.0.0.1 "$port" --nobind "${cli[@]}" > "$clog" 2>&1 &
    cpid=$!

    for _ in $(seq 100); do
        sleep 0.2
        if grep -q 'Initialization Sequence Completed' "$slog" &&
           grep -q 'Initialization Sequence Completed' "$clog"; then
            result=connect
            break
        fi
        if ! kill -0 "$spid" 2>/dev/null || ! kill -0 "$cpid" 2>/dev/null; then
            break
        fi
    done
    kill "$spid" "$cpid" 2>/dev/null || true
    wait "$spid" "$cpid" 2>/dev/null || true

    if [ "$expect" = connect ]; then
        if [ "$result" = connect ]; then
            ok=1
        fi
    elif [ "$result" != connect ] && grep -q -- "$expect" "$clog"; then
        ok=1
    fi
    if grep -q 'Sanitizer' "$slog" "$clog"; then
        ok=0
    fi

    if [ "$ok" = 1 ]; then
        echo "PASS $name"
    else
        echo "FAIL $name (expected: $expect)"
        echo "---- $name server log ----"
        tail -n 40 "$slog"
        echo "---- $name client log ----"
        tail -n 40 "$clog"
        failed=$((failed + 1))
    fi
}

# --peer-fingerprint without a CA
srv=(--cert server.crt --key server.key --peer-fingerprint "$(fp client.crt)")
cli=(--cert client.crt --key client.key --peer-fingerprint "$(fp server.crt)")
run fingerprint connect

srv+=(--tls-version-max 1.2)
cli+=(--tls-version-max 1.2)
run fingerprint-tls12 connect

srv=(--cert server.crt --key server.key --peer-fingerprint "$(fp client.crt)")
cli=(--cert client.crt --key client.key --peer-fingerprint "$(fp client.crt)")
run wrong-fingerprint 'certificate hash verification failed'

srv=(--cert chain-full.crt --key chain.key
     --peer-fingerprint "$(fp client.crt)")
cli=(--cert client.crt --key client.key --peer-fingerprint "$(fp chain.crt)")
run chain connect

# The intermediate must not be taken for the peer cert.
cli=(--cert client.crt --key client.key --peer-fingerprint "$(fp int.crt)")
run chain-intermediate-fingerprint 'certificate hash verification failed'

# A CA and --crl-verify
srv=(--ca root.crt --cert chain-full.crt --key chain.key)
cli=(--ca root.crt --cert chain-client-full.crt --key chain-client.key)
run ca connect

cli+=(--crl-verify crl-good.pem)
run ca-crl connect

cli=(--ca root.crt --cert chain-client-full.crt --key chain-client.key
     --crl-verify crl-revoked.pem)
run ca-crl-revoked 'VERIFY.*ERROR'

cli=(--ca root.crt --cert chain-client-full.crt --key chain-client.key
     --crl-verify crl-revoked-int.pem)
run ca-crl-revoked-intermediate 'VERIFY.*ERROR'

# A missing CRL must not stop the checks of the peer cert. OpenVPN before 2.7
# does not set a cert verify callback. Its verify callback then gets wolfSSL's
# own error for the missing CRL, not X509_V_ERR_UNABLE_TO_GET_CRL, and rejects
# the intermediate.
cli=(--ca root.crt --cert chain-client-full.crt --key chain-client.key
     --crl-verify crl-no-root.pem --verify-x509-name wrong name)
case $("$OPENVPN" --version | awk 'NR == 1 { print $2 }') in
    2.[0-6][._]*) expect='VERIFY ERROR: depth=1' ;;
    *) expect='VERIFY X509NAME ERROR' ;;
esac
run ca-crl-missing-wrong-name "$expect"

# --verify-hash checks the CA that signed the peer cert. Here that is a trust
# anchor, which the peer does not send.
srv=(--ca root.crt --cert direct.crt --key direct.key)
cli=(--ca roots.crt --cert chain-client-full.crt --key chain-client.key
     --verify-hash "$(fp root.crt)" SHA256)
run verify-hash connect

cli=(--ca roots.crt --cert chain-client-full.crt --key chain-client.key
     --verify-hash "$(fp root2.crt)" SHA256)
run verify-hash-other-ca 'certificate hash verification failed'

# The peer sends the pinned CA as if it signed its cert.
srv=(--ca root.crt --cert direct-root2.crt --key direct.key)
run verify-hash-sent-other-ca 'certificate hash verification failed'

cd /
rm -rf "$WORK"
if [ "$failed" != 0 ]; then
    echo "$failed case(s) failed"
    exit 1
fi
