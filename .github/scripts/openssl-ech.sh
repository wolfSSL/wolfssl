#!/bin/bash

set -e

cleanup() {
    if [ -f "$TMP_LOG" ]; then
        cat "$TMP_LOG"
        rm -f "$TMP_LOG"
    fi
}
trap cleanup EXIT

usage() {
    echo "Usage: $0 <client|server> [--suite <KEM,KDF,AEAD>] [--pqc <group>] [--hrr] [--workspace <path>]"
    exit 1
}

# --------------------------------------------------------------------------
# Argument parsing
# --------------------------------------------------------------------------
MODE=""
SUITE=""
PQC=""
FORCE_HRR=0

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
            ;;
        --pqc)
            [ -z "$2" ] && { echo "ERROR: --pqc requires a value"; exit 1; }
            PQC="$2"
            shift 2
            ;;
        --hrr)
            FORCE_HRR=1
            shift
            ;;
        --workspace)
            [ -z "$2" ] && { echo "ERROR: --workspace requires a value"; exit 1; }
            WORKSPACE="$2"
            shift 2
            ;;
        *) echo "Unknown argument: $1"; usage ;;
    esac
done

if [ "$FORCE_HRR" -ne 0 ] && [ -n "$PQC" ]; then
    echo "ERROR: --hrr and --pqc are mutually exclusive"
    exit 1
fi

# Pick exactly one test variant. The variant decides which -groups go to
# each side and any extra flags needed to drive the desired handshake.
#   default - both sides use secp256r1 (no HRR)
#   pqc     - both sides use the chosen PQC group
#   hrr     - pin one side to a group the other doesn't keyshare by
#             default, forcing the server to send HelloRetryRequest
if [ -n "$PQC" ]; then
    VARIANT="pqc"
elif [ "$FORCE_HRR" -ne 0 ]; then
    VARIANT="hrr"
else
    VARIANT="default"
fi

OPENSSL=${OPENSSL:-"openssl"}
WOLFSSL_CLIENT=${WOLFSSL_CLIENT:-"$WORKSPACE/examples/client/client"}
WOLFSSL_SERVER=${WOLFSSL_SERVER:-"$WORKSPACE/examples/server/server"}
CERT_DIR=${CERT_DIR:-"$WORKSPACE/certs"}

TMP_LOG="$WORKSPACE/tmp_file.log"
PRIV_NAME="ech-private-name.com"
PUB_NAME="ech-public-name.com"
MAX_WAIT=50

# --------------------------------------------------------------------------
# server mode -- OpenSSL is the server, wolfSSL is the client
# --------------------------------------------------------------------------
openssl_server(){
    local ech_file="$WORKSPACE/ech_config.pem"
    local ech_config=""
    local port=""

    # Per-variant args.
    #   openssl_groups : -groups passed to OpenSSL s_server
    #   openssl_suite  : -suite passed to `openssl ech` for key generation
    #   wolfssl_extra  : extra flags for the wolfSSL client
    local openssl_groups=""
    local openssl_suite=""
    local wolfssl_extra=""

    case "$VARIANT" in
        default)
            openssl_groups="-groups secp256r1"
            ;;
        pqc)
            openssl_groups="-groups $PQC"
            wolfssl_extra="--pqc $PQC"
            ;;
        hrr)
            # wolfSSL client keyshares X25519 by default; pin OpenSSL
            # server to secp384r1 so it must send HelloRetryRequest.
            openssl_groups="-groups secp384r1"
            ;;
    esac
    [ -n "$SUITE" ] && openssl_suite="-suite $SUITE"

    rm -f "$ech_file"

    $OPENSSL ech -public_name "$PUB_NAME" -out "$ech_file" $openssl_suite \
        &>> "$TMP_LOG"

    # parse ECH config from file
    ech_config=$(sed -n '/BEGIN ECHCONFIG/,/END ECHCONFIG/{/BEGIN ECHCONFIG\|END ECHCONFIG/d;p}' "$ech_file" | tr -d '\n')
    echo "parsed ech config: $ech_config" &>> "$TMP_LOG"

    # start OpenSSL ECH server with ephemeral port; line-buffer so the
    # log can be grepped
    stdbuf -oL $OPENSSL s_server \
        -tls1_3 \
        -cert "$CERT_DIR/server-cert.pem" \
        -key "$CERT_DIR/server-key.pem" \
        -cert2 "$CERT_DIR/server-cert.pem" \
        -key2 "$CERT_DIR/server-key.pem" \
        -ech_key "$ech_file" \
        -servername "$PRIV_NAME" \
        $openssl_groups \
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
        $wolfssl_extra \
        &>> "$TMP_LOG"

    rm -f "$ech_file"

    grep -q "ech_success=1" "$TMP_LOG"
}

# --------------------------------------------------------------------------
# client mode -- wolfSSL is the server, OpenSSL is the client
# --------------------------------------------------------------------------
openssl_client(){
    local ready_file="$WORKSPACE/wolfssl_tls13_ready$$"
    local ech_config=""
    local port=0

    # Per-variant args.
    #   openssl_groups : -groups passed to OpenSSL s_client
    #   wolfssl_suite  : --ech-suite passed to wolfSSL server for key gen
    #   wolfssl_extra  : extra flags for the wolfSSL server
    local openssl_groups=""
    local wolfssl_suite=""
    local wolfssl_extra=""

    case "$VARIANT" in
        default)
            openssl_groups="-groups secp256r1"
            ;;
        pqc)
            openssl_groups="-groups $PQC"
            wolfssl_extra="--pqc $PQC"
            ;;
        hrr)
            # Pin wolfSSL server to SECP384R1 only. Have OpenSSL offer
            # X25519 as keyshare with P-384 in supported_groups: the
            # mismatched keyshare forces HelloRetryRequest, and P-384 in
            # supported_groups lets the client answer it.
            openssl_groups="-groups X25519:P-384"
            wolfssl_extra="--force-curve SECP384R1"
            ;;
    esac
    [ -n "$SUITE" ] && wolfssl_suite="--ech-suite $SUITE"

    rm -f "$ready_file"

    # start server with ephemeral port + ready file; line-buffer so the
    # log can be grepped
    stdbuf -oL $WOLFSSL_SERVER \
                -v 4 \
                -R "$ready_file" \
                -p "$port" \
                -S "$PRIV_NAME" \
                --ech "$PUB_NAME" \
                $wolfssl_suite \
                $wolfssl_extra \
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

    # test with OpenSSL s_client using ECH
    echo "wolfssl" | $OPENSSL s_client \
        -tls1_3 \
        -connect "localhost:$port" \
        -cert "$CERT_DIR/client-cert.pem" \
        -key "$CERT_DIR/client-key.pem" \
        -CAfile "$CERT_DIR/ca-cert.pem" \
        -servername "$PRIV_NAME" \
        -ech_config_list "$ech_config" \
        $openssl_groups \
        &>> "$TMP_LOG"

    grep -q "ECH: success: 1" "$TMP_LOG"
}

rm -f "$TMP_LOG"

case "$MODE" in
    server) openssl_server ;;
    client) openssl_client ;;
    *)      exit 1 ;;
esac
