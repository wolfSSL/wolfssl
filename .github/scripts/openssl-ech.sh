#!/bin/bash

set -e

cleanup() {
    cat "$TMP_LOG"
    rm -f "$TMP_LOG"
}
trap cleanup EXIT

usage() {
    echo "Usage: $0 <client|server> [--suite <KEM,KDF,AEAD>] [--workspace <path>]"
    exit 1
}

MODE=""
SUITE=""

WORKSPACE=${GITHUB_WORKSPACE:-"."}

if [ $# -lt 1 ]; then
    usage
fi

case "$1" in
    client|server) MODE="$1" ;;
    *) usage ;;
esac
shift

while [ $# -gt 0 ]; do
    case "$1" in
        --suite)
            [ -z "$2" ] && { echo "ERROR: --suite requires a value"; exit 1; }
            SUITE="$2"
            shift 2
            echo ""
            echo "Using suite: $SUITE"
            echo ""
            ;;
        --workspace)
            [ -z "$2" ] && { echo "ERROR: --workspace requires a value"; exit 1; }
            WORKSPACE="$2"
            shift 2
            ;;
        *) echo "Unknown argument: $1"; usage ;;
    esac
done

OPENSSL=${OPENSSL:-"openssl"}
WOLFSSL_CLIENT=${WOLFSSL_CLIENT:-"$WORKSPACE/examples/client/client"}
WOLFSSL_SERVER=${WOLFSSL_SERVER:-"$WORKSPACE/examples/server/server"}
CERT_DIR=${CERT_DIR:-"$WORKSPACE/certs"}

TMP_LOG="$WORKSPACE/tmp_file.log"
PRIV_NAME="ech-private-name.com"
PUB_NAME="ech-public-name.com"
MAX_WAIT=50

openssl_server(){
    local ech_file="$WORKSPACE/ech_config.pem"
    local ech_config=""
    local port=""

    rm -f "$ech_file"

    $OPENSSL ech -public_name "$PUB_NAME" -out "$ech_file" $SUITE &>> "$TMP_LOG"

    # parse ECH config from file
    ech_config=$(sed -n '/BEGIN ECHCONFIG/,/END ECHCONFIG/{/BEGIN ECHCONFIG\|END ECHCONFIG/d;p}' "$ech_file" | tr -d '\n')
    echo "parsed ech config: $ech_config" &>> "$TMP_LOG"

    # start OpenSSL ECH server with ephemeral port and make sure it is
    # line-buffered
    stdbuf -oL $OPENSSL s_server \
        -tls1_3 \
        -cert "$CERT_DIR/server-cert.pem" \
        -key "$CERT_DIR/server-key.pem" \
        -cert2 "$CERT_DIR/server-cert.pem" \
        -key2 "$CERT_DIR/server-key.pem" \
        -ech_key "$ech_file" \
        -servername "$PRIV_NAME" \
        -accept 0 \
        -naccept 1 \
        &>> "$TMP_LOG" <<< "wolfssl!" &

    # wait for server port to be ready and capture it
    counter=0
    while [ -z "$port" ]; do
        port=$(grep -m1 "ACCEPT" "$TMP_LOG" | sed 's/.*:\([0-9]*\)$/\1/')
        sleep 0.1
        counter=$((counter + 1))
        if [ "$counter" -gt "$MAX_WAIT" ]; then
            echo "ERROR: server port not found" &>> "$TMP_LOG"
            exit 1
        fi
    done
    echo "parsed port: $port" &>> "$TMP_LOG"

    # test with wolfssl client
    $WOLFSSL_CLIENT -v 4 \
        -p "$port" \
        -S "$PRIV_NAME" \
        --ech "$ech_config" \
        &>> "$TMP_LOG"

    rm -f "$ech_file"

    grep -q "ech_success=1" "$TMP_LOG"
}

openssl_client(){
    local ready_file="$WORKSPACE/wolfssl_tls13_ready$$"
    local ech_config=""
    local port=0

    rm -f "$ready_file"

    # start server with ephemeral port + ready file
    # also set server to be line buffered so the log can be grepped
    stdbuf -oL $WOLFSSL_SERVER \
                -v 4 \
                -R "$ready_file" \
                -p "$port" \
                -S "$PRIV_NAME" \
                --ech "$PUB_NAME" \
                $SUITE \
                &>> "$TMP_LOG" &

    # wait for server to be ready, then get port
    counter=0
    while [ ! -s "$ready_file" ]; do
        sleep 0.1
        counter=$((counter + 1))
        if [ "$counter" -gt "$MAX_WAIT" ]; then
            echo "ERROR: no ready file" &>> "$TMP_LOG"
            exit 1
        fi
    done
    port="$(cat "$ready_file")"
    rm -f "$ready_file"
    echo "parsed port: $port" &>> "$TMP_LOG"

    # get ECH config from server
    counter=0
    while [ -z "$ech_config" ]; do
        ech_config=$(grep -m1 "ECH config (base64): " "$TMP_LOG" \
            2>/dev/null | sed 's/ECH config (base64): //g')
        sleep 0.1
        counter=$((counter + 1))
        if [ "$counter" -gt "$MAX_WAIT" ]; then
            echo "ERROR: no ECH configs" &>> "$TMP_LOG"
            exit 1
        fi
    done
    echo "parsed ech config: $ech_config" &>> "$TMP_LOG"

    # Test with OpenSSL s_client using ECH
    echo "wolfssl" | $OPENSSL s_client \
        -tls1_3 \
        -connect "localhost:$port" \
        -cert "$CERT_DIR/client-cert.pem" \
        -key "$CERT_DIR/client-key.pem" \
        -CAfile "$CERT_DIR/ca-cert.pem" \
        -servername "$PRIV_NAME" \
        -ech_config_list "$ech_config" \
        &>> "$TMP_LOG"

    grep -q "ECH: success: 1" "$TMP_LOG"
}

rm -f "$TMP_LOG"

case "$MODE" in
    server)
        if [ -n "$SUITE" ]; then
            SUITE="-suite $SUITE"
        fi
        openssl_server
        ;;
    client)
        if [ -n "$SUITE" ]; then
            SUITE="--ech-suite $SUITE"
        fi
        openssl_client
        ;;
    *)
        exit 1
        ;;
esac
