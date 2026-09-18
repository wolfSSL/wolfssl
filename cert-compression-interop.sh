#!/usr/bin/env bash
# OpenSSL interop tests for TLS 1.3 certificate compression (RFC 8879).
#
# wolfSSL client <-> OpenSSL s_server, every combination of:
#   server certificate compressed or not (s_server -cert_comp)
#   client auth off or on (s_server -Verify)
#   with client auth, s_server offering compress_certificate in its
#   CertificateRequest or not (-no_rx_cert_comp)
#
# wolfSSL server <-> OpenSSL s_client, every combination of:
#   s_client offering compress_certificate in its ClientHello or not
#   (-no_rx_cert_comp)
#   client auth off or on (wolfSSL server -d turns it off)
#   with client auth, s_client compressing its certificate or not
#   (-no_tx_cert_comp)
#
# Compression is optional, so every case must complete the handshake. Each
# case also checks, from both ends, which form of Certificate each side sent:
# what wolfSSL processed (its debug log) and what went over the wire (OpenSSL
# -trace).
#
# Build first with ./cert-compression-test.sh && make (needs --enable-debug).
# Needs OpenSSL >= 3.2 built with zlib.
#
# usage: ./cert-compression-interop.sh [-v]
#   -v  print the logs of failing cases
# env: OPENSSL (default: openssl), PORT_BASE (default: random), TIMEOUT (s)
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

OPENSSL=${OPENSSL:-openssl}
TIMEOUT=${TIMEOUT:-10}
PORT=${PORT_BASE:-$((20000 + RANDOM % 20000))}
VERBOSE=0
[ "${1:-}" = "-v" ] && VERBOSE=1

die() { echo "error: $*" >&2; exit 2; }

[ -x examples/client/client ] && [ -x examples/server/server ] ||
    die "examples not built; run ./cert-compression-test.sh && make"
grep -q "WOLFSSL_CERT_COMPRESSION" wolfssl/options.h 2>/dev/null ||
    die "build is not configured with --enable-cert-compression"
grep -q "DEBUG_WOLFSSL" wolfssl/options.h ||
    die "build needs --enable-debug; the checks read wolfSSL's debug log"
"$OPENSSL" s_server -help 2>&1 | grep -q -- "-cert_comp" ||
    die "$OPENSSL does not support certificate compression (need >= 3.2)"

LOGDIR=$(mktemp -d "${TMPDIR:-/tmp}/cert-comp-interop.XXXXXX")
PASS=0
FAIL=0
FAILED=()

# Wait until something is listening on the port, without connecting to it
# (the wolfSSL example server only accepts one connection).
wait_listen() {
    local i
    for i in $(seq 1 100); do
        if command -v ss > /dev/null; then
            ss -Hltn "sport = :$1" 2>/dev/null | grep -q . && return 0
        elif [ "$i" -ge 10 ]; then
            return 0
        fi
        sleep 0.1
    done
    return 1
}

# Which form of Certificate wolfSSL processed: compressed, plain or none.
wolf_recv() {
    if grep -qx "processing compressed certificate" "$1"; then
        echo compressed
    elif grep -qx "processing certificate" "$1"; then
        echo plain
    else
        echo none
    fi
}

# Which form of Certificate OpenSSL's trace shows in one direction
# (sent|recv): compressed, plain or none.
ossl_cert() {
    awk -v want="$2" '
        /^Sent TLS Record/                     { d = "sent" }
        /^Received TLS Record/                 { d = "recv" }
        /^ +CompressedCertificate, Length=/    { if (d == want) f = "compressed" }
        /^ +Certificate, Length=/              { if (d == want && f == "") f = "plain" }
        END { print (f == "") ? "none" : f }' "$1"
}

# name ok reason wolfRecv expRecv wolfSent expSent opensslLog logs...
report() {
    local name=$1 ok=$2 why=$3 got_r=$4 exp_r=$5 got_s=$6 exp_s=$7 olog=$8
    local wire_r
    shift 7
    wire_r=$(ossl_cert "$olog" sent)
    if [ "$ok" = 1 ] && [ "$got_r" != "$wire_r" ]; then
        ok=0; why="wolfSSL log says $got_r received, OpenSSL sent $wire_r"
    fi
    if [ "$ok" = 1 ] && [ "$got_r" != "$exp_r" ]; then
        ok=0; why="wolfSSL received $got_r certificate, expected $exp_r"
    fi
    if [ "$ok" = 1 ] && [ "$got_s" != "$exp_s" ]; then
        ok=0; why="wolfSSL sent $got_s certificate, expected $exp_s"
    fi
    if [ "$ok" = 1 ]; then
        PASS=$((PASS + 1))
        printf "PASS  %-52s recv=%-10s sent=%s\n" "$name" "$got_r" "$got_s"
    else
        FAIL=$((FAIL + 1))
        FAILED+=("$name")
        printf "FAIL  %-52s %s\n" "$name" "$why"
        if [ "$VERBOSE" = 1 ]; then
            local f
            for f in "$@"; do
                echo "  ---- $f (last 25 lines)"
                tail -n 25 "$f" | sed 's/^/  | /'
            done
        fi
    fi
}

# wolfSSL client against OpenSSL s_server.
#   name expRecv expSent -- s_server args...
# expRecv: form of the server certificate wolfSSL must receive.
# expSent: form of the client certificate wolfSSL must send (none = not
#          asked for one).
client_case() {
    local name=$1 exp_r=$2 exp_s=$3
    shift 3
    local port=$((PORT++))
    local olog="$LOGDIR/$name.openssl.log" wlog="$LOGDIR/$name.wolfssl.log"
    local ok=1 why="" rc spid

    "$OPENSSL" s_server -accept "$port" -naccept 1 -tls1_3 \
        -cert certs/server-cert.pem -key certs/server-key.pem \
        -www -trace "$@" > "$olog" 2>&1 &
    spid=$!
    if ! wait_listen "$port"; then
        kill "$spid" 2>/dev/null; wait "$spid" 2>/dev/null
        report "$name" 0 "s_server did not start" - "$exp_r" - "$exp_s" "$olog"
        return
    fi

    timeout "$TIMEOUT" ./examples/client/client -v 4 -p "$port" \
        -A certs/ca-cert.pem -g > "$wlog" 2>&1
    rc=$?
    kill "$spid" 2>/dev/null; wait "$spid" 2>/dev/null

    if [ "$rc" -ne 0 ] || ! grep -q "HTTP/1.0 200 ok" "$wlog"; then
        ok=0; why="handshake failed (wolfSSL client rc=$rc)"
    fi
    report "$name" "$ok" "$why" \
        "$(wolf_recv "$wlog")" "$exp_r" "$(ossl_cert "$olog" recv)" "$exp_s" \
        "$olog" "$wlog"
}

# wolfSSL server against OpenSSL s_client.
#   name expRecv expSent wolfServerArgs -- s_client args...
# expRecv: form of the client certificate wolfSSL must receive (none = client
#          auth off).
# expSent: form of the server certificate wolfSSL must send.
server_case() {
    local name=$1 exp_r=$2 exp_s=$3 wargs=$4
    shift 4
    local port=$((PORT++))
    local olog="$LOGDIR/$name.openssl.log" wlog="$LOGDIR/$name.wolfssl.log"
    local ok=1 why="" rc src spid

    # shellcheck disable=SC2086
    timeout "$TIMEOUT" ./examples/server/server -v 4 -p "$port" $wargs \
        > "$wlog" 2>&1 &
    spid=$!
    if ! wait_listen "$port"; then
        kill "$spid" 2>/dev/null; wait "$spid" 2>/dev/null
        report "$name" 0 "wolfSSL server did not start" - "$exp_r" - "$exp_s" \
            "$wlog"
        return
    fi

    printf 'hello wolfssl\n' | timeout "$TIMEOUT" "$OPENSSL" s_client \
        -connect "127.0.0.1:$port" -tls1_3 -CAfile certs/ca-cert.pem \
        -cert certs/client-cert.pem -key certs/client-key.pem \
        -verify_return_error -ign_eof -trace "$@" > "$olog" 2>&1
    rc=$?
    wait "$spid"
    src=$?

    if [ "$rc" -ne 0 ] || [ "$src" -ne 0 ] ||
            ! grep -q "I hear you fa shizzle" "$olog"; then
        ok=0
        why="handshake failed (s_client rc=$rc, wolfSSL server rc=$src)"
    fi
    report "$name" "$ok" "$why" \
        "$(wolf_recv "$wlog")" "$exp_r" "$(ossl_cert "$olog" recv)" "$exp_s" \
        "$olog" "$wlog"
}

AUTH="-Verify 1 -verify_return_error -CAfile certs/client-cert.pem"

echo "OpenSSL: $("$OPENSSL" version)"
echo "logs:    $LOGDIR"
echo
echo "== wolfSSL client <-> OpenSSL s_server =="
# shellcheck disable=SC2086
{
client_case client_recvComp_noAuth           compressed none  -cert_comp
client_case client_recvPlain_noAuth          plain      none
client_case client_recvComp_auth_peerOffers  compressed plain -cert_comp $AUTH
client_case client_recvComp_auth_noOffer     compressed plain -cert_comp $AUTH \
    -no_rx_cert_comp
client_case client_recvPlain_auth_peerOffers plain      plain $AUTH
client_case client_recvPlain_auth_noOffer    plain      plain $AUTH \
    -no_rx_cert_comp
}

echo
echo "== wolfSSL server <-> OpenSSL s_client =="
server_case server_noAuth_peerOffers         none       plain -d
server_case server_noAuth_noOffer            none       plain -d \
    -no_rx_cert_comp
server_case server_recvComp_peerOffers       compressed plain ""
server_case server_recvPlain_peerOffers      plain      plain "" \
    -no_tx_cert_comp
server_case server_recvComp_noOffer          compressed plain "" \
    -no_rx_cert_comp
server_case server_recvPlain_noOffer         plain      plain "" \
    -no_rx_cert_comp -no_tx_cert_comp

echo
echo "passed: $PASS  failed: $FAIL"
if [ "$FAIL" -ne 0 ]; then
    printf '  %s\n' "${FAILED[@]}"
    echo "logs in $LOGDIR (rerun with -v to print them)"
    exit 1
fi
exit 0
