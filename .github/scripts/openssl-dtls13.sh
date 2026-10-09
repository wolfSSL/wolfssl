#!/usr/bin/env bash
#
# DTLS 1.3 interoperability between wolfSSL and OpenSSL (4.1 and later).
#
# Runs the wolfSSL example client and server against `openssl s_server` and
# `openssl s_client` over loopback UDP, in both directions, and checks each
# handshake negotiates DTLS 1.3, the expected group, and exchanges data.
#
# Run from the root of a built wolfSSL tree (the examples use certs/).
#   OPENSSL         openssl binary with DTLS 1.3       (default: openssl)
#   WOLFSSL_CLIENT  wolfSSL example client   (default: examples/client/client)
#   WOLFSSL_SERVER  wolfSSL example server   (default: examples/server/server)
#
# wolfSSL must be built with at least:
#   --enable-dtls --enable-dtls13 --enable-dtls-mtu --enable-dtls-frag-ch
#   --enable-hrrcookie --enable-mlkem

set -u

OPENSSL=${OPENSSL:-openssl}
WOLFSSL_CLIENT=${WOLFSSL_CLIENT:-./examples/client/client}
WOLFSSL_SERVER=${WOLFSSL_SERVER:-./examples/server/server}
LOG_DIR=$(mktemp -d)
# Upper bound for one side of one case, in seconds.
CASE_TIMEOUT=20

# How the wolfSSL server is run for a case whose first ClientHello is
# fragmented (a post-quantum key share, or a small MTU on the client).
#   cookie     the cookie exchange is on: the stateless server reassembles the
#              ClientHello within a bounded budget before the cookie is
#              verified (wolfSSL_dtls13_reassemble_ch_before_cookie(), on by
#              default), then runs the cookie check on the complete message.
#   no-cookie  the cookie exchange is disabled (-J n): the server is stateful
#              from the first datagram and reassembles the ClientHello.
FRAG_CH_SERVER_MODES="cookie no-cookie"

PASS=0
FAIL=0
FAILED_CASES=""

trap 'rm -rf "$LOG_DIR"' EXIT

fail() {
    local name=$1 why=$2
    echo "FAIL: $name: $why"
    FAIL=$((FAIL + 1))
    FAILED_CASES="$FAILED_CASES $name"
    for f in "$LOG_DIR/$name".*; do
        echo "----- $f"
        cat "$f"
    done
}

# wolfSSL client <-> OpenSSL server
#   $1 case name
#   $2 extra s_server arguments
#   $3 extra wolfSSL client arguments
#   $4 group the wolfSSL client must report as negotiated
ossl_server() {
    local name=$1 oargs=$2 wargs=$3 group=$4
    local slog="$LOG_DIR/$name.server" clog="$LOG_DIR/$name.client"
    local port="" spid crc src i

    : > "$slog"
    # s_server exits on EOF on stdin, and writing before the handshake
    # completes drives it early: hold stdin open, then send one line.
    (sleep 2; echo "hello-from-openssl"; sleep 6) | \
        timeout "$CASE_TIMEOUT" stdbuf -oL "$OPENSSL" s_server -dtls1_3 \
            -accept 127.0.0.1:0 -naccept 1 \
            -cert certs/server-cert.pem -key certs/server-key.pem \
            $oargs >> "$slog" 2>&1 &
    spid=$!
    for i in $(seq 50); do
        port=$(grep -m1 -oE '^ACCEPT .*:[0-9]+' "$slog" | sed 's/.*://')
        [ -n "$port" ] && break
        sleep 0.1
    done
    if [ -z "$port" ]; then
        kill "$spid" 2>/dev/null
        wait "$spid" 2>/dev/null
        fail "$name" "s_server did not start"
        return
    fi

    timeout "$CASE_TIMEOUT" "$WOLFSSL_CLIENT" -v 4 -h 127.0.0.1 -p "$port" \
        $wargs > "$clog" 2>&1
    crc=$?
    wait "$spid"
    src=$?

    if [ $crc -ne 0 ] || [ $src -ne 0 ]; then
        fail "$name" "exit codes: wolfSSL client $crc, s_server $src"
    elif ! grep -q "SSL version is DTLSv1.3" "$clog"; then
        fail "$name" "DTLS 1.3 not negotiated"
    elif ! grep -q "SSL curve name is $group\$" "$clog"; then
        fail "$name" "group $group not negotiated"
    elif ! grep -q "hello-from-openssl" "$clog" ||
         ! grep -q "hello wolfssl!" "$slog"; then
        fail "$name" "application data not exchanged"
    else
        echo "PASS: $name"
        PASS=$((PASS + 1))
    fi
}

# OpenSSL client <-> wolfSSL server
#   $1 case name
#   $2 extra wolfSSL server arguments
#   $3 extra s_client arguments
#   $4 group the wolfSSL server must report as negotiated
wolf_server() {
    local name=$1 wargs=$2 oargs=$3 group=$4
    local slog="$LOG_DIR/$name.server" clog="$LOG_DIR/$name.client"
    local ready="$LOG_DIR/$name.ready" port spid crc src i

    timeout "$CASE_TIMEOUT" "$WOLFSSL_SERVER" -v 4 -u -p 0 -R "$ready" \
        $wargs > "$slog" 2>&1 &
    spid=$!
    for i in $(seq 50); do
        [ -s "$ready" ] && break
        sleep 0.1
    done
    if [ ! -s "$ready" ]; then
        kill "$spid" 2>/dev/null
        wait "$spid" 2>/dev/null
        fail "$name" "wolfSSL server did not start"
        return
    fi
    port=$(cat "$ready")

    # s_client exits on EOF on stdin: keep it open for the server's reply.
    (echo "hello-from-openssl"; sleep 2) | \
        timeout "$CASE_TIMEOUT" "$OPENSSL" s_client -dtls1_3 \
            -connect "127.0.0.1:$port" \
            -CAfile certs/ca-cert.pem -verify_return_error \
            -cert certs/client-cert.pem -key certs/client-key.pem \
            $oargs > "$clog" 2>&1
    crc=$?
    wait "$spid"
    src=$?

    if [ $crc -ne 0 ] || [ $src -ne 0 ]; then
        fail "$name" "exit codes: s_client $crc, wolfSSL server $src"
    elif ! grep -q "Protocol: DTLSv1.3" "$clog"; then
        fail "$name" "DTLS 1.3 not negotiated"
    elif ! grep -q "SSL curve name is $group\$" "$slog"; then
        fail "$name" "group $group not negotiated"
    elif ! grep -q "Client message: hello-from-openssl" "$slog" ||
         ! grep -q "I hear you fa shizzle!" "$clog"; then
        fail "$name" "application data not exchanged"
    else
        echo "PASS: $name"
        PASS=$((PASS + 1))
    fi
}

# OpenSSL client <-> wolfSSL server, first ClientHello fragmented: run once
# per mode in FRAG_CH_SERVER_MODES. Arguments as for wolf_server().
wolf_server_frag_ch() {
    local name=$1 wargs=$2 oargs=$3 group=$4 mode
    for mode in $FRAG_CH_SERVER_MODES; do
        case "$mode" in
            cookie)    wolf_server "$name-cookie" "$wargs" "$oargs" "$group" ;;
            no-cookie) wolf_server "$name-no-cookie" "-J n $wargs" "$oargs" \
                           "$group" ;;
            *)         echo "unknown mode $mode"; exit 1 ;;
        esac
    done
}

"$OPENSSL" version

# OpenSSL server. s_server always runs the DTLS 1.3 cookie exchange, so
# every case also exercises the wolfSSL client's HelloRetryRequest path.
ossl_server ossl-server-default "" "-u" "X25519MLKEM768"
# The wolfSSL client key shares a group s_server does not accept.
ossl_server ossl-server-hrr-group "-groups secp384r1" "-u" "SECP384R1"
ossl_server ossl-server-x25519mlkem768 "-groups X25519MLKEM768" \
    "-u --pqc X25519MLKEM768" "X25519MLKEM768"
ossl_server ossl-server-p384mlkem1024 "-groups SecP384r1MLKEM1024" \
    "-u --pqc SecP384r1MLKEM1024" "SecP384r1MLKEM1024"
ossl_server ossl-server-mtu512 "" "-u 512" "X25519MLKEM768"
ossl_server ossl-server-p384mlkem1024-mtu512 "-groups SecP384r1MLKEM1024" \
    "-u 512 --pqc SecP384r1MLKEM1024" "SecP384r1MLKEM1024"

# wolfSSL server, first ClientHello in one datagram, cookie exchange on.
wolf_server wolf-server-default "" "" "X25519MLKEM768"
# s_client key shares X25519, which the wolfSSL server does not accept.
wolf_server wolf-server-hrr-group "--force-curve SECP384R1" \
    "-groups X25519:P-384" "SECP384R1"
wolf_server wolf-server-x25519mlkem768 "--pqc X25519MLKEM768" \
    "-groups X25519MLKEM768" "X25519MLKEM768"
wolf_server wolf-server-default-no-cookie "-J n" "" "X25519MLKEM768"

# wolfSSL server, first ClientHello fragmented.
wolf_server_frag_ch wolf-server-mtu512 "" "-mtu 512" "X25519MLKEM768"
wolf_server_frag_ch wolf-server-mtu256 "" "-mtu 256" "X25519MLKEM768"
# Loopback has a 64 KiB MTU, so without -mtu s_client sends a ClientHello
# larger than an Ethernet datagram unfragmented, beyond what the server reads
# in one datagram. -mtu 1500 makes it fragment as on a real link.
wolf_server_frag_ch wolf-server-p384mlkem1024 "--pqc SecP384r1MLKEM1024" \
    "-groups SecP384r1MLKEM1024 -mtu 1500" "SecP384r1MLKEM1024"
wolf_server_frag_ch wolf-server-x25519mlkem768-mtu512 \
    "--pqc X25519MLKEM768" "-groups X25519MLKEM768 -mtu 512" "X25519MLKEM768"

echo "passed: $PASS, failed: $FAIL"
if [ $FAIL -ne 0 ]; then
    echo "failed cases:$FAILED_CASES"
    exit 1
fi
