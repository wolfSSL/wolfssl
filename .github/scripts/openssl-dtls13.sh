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
XFAIL=0
FAILED_CASES=""
# Set by xfail() for the case it runs: a pattern one of the case's logs must
# show for the failure to be the known one, and why the case fails.
XFAIL_PATTERN=""
XFAIL_WHY=""

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

# Record the outcome of a case: $2 is empty on success, else why it failed.
report() {
    local name=$1 why=$2
    if [ -n "$XFAIL_PATTERN" ]; then
        if [ -z "$why" ]; then
            fail "$name" "passed, but expected to fail ($XFAIL_WHY):\
 drop the xfail if that is fixed"
        elif cat "$LOG_DIR/$name".* | grep -q -- "$XFAIL_PATTERN"; then
            echo "XFAIL: $name: $XFAIL_WHY"
            XFAIL=$((XFAIL + 1))
        else
            fail "$name" "$why (expected to fail only with '$XFAIL_PATTERN')"
        fi
    elif [ -n "$why" ]; then
        fail "$name" "$why"
    else
        echo "PASS: $name"
        PASS=$((PASS + 1))
    fi
}

# Run a case that fails for a known reason outside wolfSSL.
#   $1 pattern a log of the case must show when it fails as expected
#   $2 why the case is expected to fail
#   $@ the case: ossl_server ... or wolf_server ...
xfail() {
    XFAIL_PATTERN=$1
    XFAIL_WHY=$2
    shift 2
    "$@"
    XFAIL_PATTERN=""
    XFAIL_WHY=""
}

# Wait for an OpenSSL log to show the handshake completed, then type a
# KeyUpdate command on its stdin: K requests the peer to update too, k does
# not.
#   $1 log  $2 line s_client/s_server prints once the handshake is done
#   $3 K or k
type_key_update() {
    local log=$1 done=$2 cmd=$3 i
    for i in $(seq $((CASE_TIMEOUT * 10))); do
        grep -q "$done" "$log" 2>/dev/null && break
        sleep 0.1
    done
    echo "$cmd"
    # s_client/s_server read stdin in chunks and drop the rest of a chunk
    # that holds a command: keep the next line out of it.
    sleep 1
}

# wolfSSL client <-> OpenSSL server
#   $1 case name
#   $2 extra s_server arguments
#   $3 extra wolfSSL client arguments
#   $4 group the wolfSSL client must report as negotiated
#   $5 KeyUpdate, optional:
#        K, k  s_server sends a KeyUpdate, requesting one back (K) or not (k)
#        wolf  the wolfSSL client sends a KeyUpdate requesting one back (-I)
#      before the data each side sends, and that KeyUpdate must be seen.
ossl_server() {
    local name=$1 oargs=$2 wargs=$3 group=$4 ku=${5:-}
    local slog="$LOG_DIR/$name.server" clog="$LOG_DIR/$name.client"
    local port="" spid crc src i

    case "$ku" in
        K|k)  oargs="$oargs -msg" ;;
        wolf) oargs="$oargs -msg"; wargs="$wargs -I" ;;
    esac

    : > "$slog"
    # s_server exits on EOF on stdin, and writing before the handshake
    # completes drives it early: hold stdin open, then send one line.
    (if [ "$ku" = K ] || [ "$ku" = k ]; then
         type_key_update "$slog" "^CIPHER is" "$ku"
     else
         sleep 2
     fi
     echo "hello-from-openssl"; sleep 6) | \
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
        report "$name" "s_server did not start"
        return
    fi

    timeout "$CASE_TIMEOUT" "$WOLFSSL_CLIENT" -v 4 -h 127.0.0.1 -p "$port" \
        $wargs > "$clog" 2>&1
    crc=$?
    wait "$spid"
    src=$?

    if [ $crc -ne 0 ] || [ $src -ne 0 ]; then
        report "$name" "exit codes: wolfSSL client $crc, s_server $src"
    elif ! grep -q "SSL version is DTLSv1.3" "$clog"; then
        report "$name" "DTLS 1.3 not negotiated"
    elif ! grep -q "SSL curve name is $group\$" "$clog"; then
        report "$name" "group $group not negotiated"
    elif [ "$ku" = wolf ] && ! grep -q "^<<< .*, KeyUpdate$" "$slog"; then
        report "$name" "s_server did not receive a KeyUpdate"
    elif [ -n "$ku" ] && [ "$ku" != wolf ] &&
         ! grep -q "^>>> .*, KeyUpdate$" "$slog"; then
        report "$name" "s_server did not send a KeyUpdate"
    elif ! grep -q "hello-from-openssl" "$clog" ||
         ! grep -q "hello wolfssl!" "$slog"; then
        report "$name" "application data not exchanged"
    else
        report "$name" ""
    fi
}

# OpenSSL client <-> wolfSSL server
#   $1 case name
#   $2 extra wolfSSL server arguments
#   $3 extra s_client arguments
#   $4 group the wolfSSL server must report as negotiated
#   $5 KeyUpdate, optional:
#        K, k  s_client sends a KeyUpdate, requesting one back (K) or not (k)
#        wolf  the wolfSSL server sends a KeyUpdate requesting one back (-U)
#      before the data each side sends, and that KeyUpdate must be seen.
wolf_server() {
    local name=$1 wargs=$2 oargs=$3 group=$4 ku=${5:-}
    local slog="$LOG_DIR/$name.server" clog="$LOG_DIR/$name.client"
    local ready="$LOG_DIR/$name.ready" port spid crc src i

    case "$ku" in
        K|k)  oargs="$oargs -msg" ;;
        wolf) oargs="$oargs -msg"; wargs="$wargs -U" ;;
    esac

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
        report "$name" "wolfSSL server did not start"
        return
    fi
    port=$(cat "$ready")

    # s_client exits on EOF on stdin: keep it open for the server's reply.
    # After its KeyUpdate (-U) the wolfSSL server reads a second message.
    : > "$clog"
    (if [ "$ku" = K ] || [ "$ku" = k ]; then
         type_key_update "$clog" "^Protocol: DTLSv1.3" "$ku"
     fi
     echo "hello-from-openssl"
     if [ "$ku" = wolf ]; then
         sleep 1
         echo "hello-again-from-openssl"
     fi
     sleep 2) | \
        timeout "$CASE_TIMEOUT" "$OPENSSL" s_client -dtls1_3 \
            -connect "127.0.0.1:$port" \
            -CAfile certs/ca-cert.pem -verify_return_error \
            -cert certs/client-cert.pem -key certs/client-key.pem \
            $oargs >> "$clog" 2>&1
    crc=$?
    wait "$spid"
    src=$?

    if [ $crc -ne 0 ] || [ $src -ne 0 ]; then
        report "$name" "exit codes: s_client $crc, wolfSSL server $src"
    elif ! grep -q "Protocol: DTLSv1.3" "$clog"; then
        report "$name" "DTLS 1.3 not negotiated"
    elif ! grep -q "SSL curve name is $group\$" "$slog"; then
        report "$name" "group $group not negotiated"
    elif [ "$ku" = wolf ] && ! grep -q "^<<< .*, KeyUpdate$" "$clog"; then
        report "$name" "s_client did not receive a KeyUpdate"
    elif [ -n "$ku" ] && [ "$ku" != wolf ] &&
         ! grep -q "^>>> .*, KeyUpdate$" "$clog"; then
        report "$name" "s_client did not send a KeyUpdate"
    elif ! grep -q "Client message: hello-from-openssl" "$slog" ||
         ! grep -q "I hear you fa shizzle!" "$clog"; then
        report "$name" "application data not exchanged"
    elif [ "$ku" = wolf ] &&
         ! grep -q "Client message: hello-again-from-openssl" "$slog"; then
        report "$name" "application data after the KeyUpdate not received"
    else
        report "$name" ""
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

# KeyUpdate (RFC 9147 section 8), from each side, with and without asking
# the peer to update too. The sender keeps its old keys until the KeyUpdate
# is ACKed, so data sent right after it is at the old epoch, which the
# receiver has already moved past.
ossl_server ossl-server-keyupdate "" "-u" "X25519MLKEM768" k
# s_server, after sending its KeyUpdate, waits in TLS_ST_SW_KEY_UPDATE, where
# only an ACK is a valid message (ssl/statem/statem_srvr.c:163-170 at 4.1.0
# beta2). wolfSSL answers update_requested with its own KeyUpdate at once,
# before the ACK, as the crossing allowed by RFC 9147 section 8 and RFC 8446
# section 4.6.3, and s_server fails with unexpected_message
# (statem_srvr.c:342). OpenSSL's own client only answers with its next data,
# by which time the ACK has arrived.
xfail "ossl_statem_server_read_transition:unexpected message" \
    "OpenSSL server rejects a crossing KeyUpdate" \
    ossl_server ossl-server-keyupdate-requested "" "-u" "X25519MLKEM768" K
ossl_server ossl-server-wolf-keyupdate "" "-u" "X25519MLKEM768" wolf
wolf_server wolf-server-keyupdate "" "" "X25519MLKEM768" k
wolf_server wolf-server-keyupdate-requested "" "" "X25519MLKEM768" K
wolf_server wolf-server-wolf-keyupdate "" "" "X25519MLKEM768" wolf

echo "passed: $PASS, expected failures: $XFAIL, failed: $FAIL"
if [ $FAIL -ne 0 ]; then
    echo "failed cases:$FAILED_CASES"
    exit 1
fi
