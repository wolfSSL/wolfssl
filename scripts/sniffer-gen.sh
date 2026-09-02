#!/usr/bin/env bash
#set -x

# if we can, isolate the network namespace to eliminate port collisions.
if [[ -n "$NETWORK_UNSHARE_HELPER" ]]; then
     if [[ -z "$NETWORK_UNSHARE_HELPER_CALLED" ]]; then
         export NETWORK_UNSHARE_HELPER_CALLED=yes
         exec "$NETWORK_UNSHARE_HELPER" "$0" "$@" || exit $?
     fi
elif [ "${AM_BWRAPPED-}" != "yes" ]; then
    bwrap_path="$(command -v bwrap)"
    if [ -n "$bwrap_path" ]; then
        export AM_BWRAPPED=yes
        exec "$bwrap_path" --cap-add ALL --unshare-net --dev-bind / / "$0" "$@"
    fi
    unset AM_BWRAPPED
fi

# Run this script from the wolfSSL root
if [ ! -f wolfssl/ssl.h ]; then
    echo "Run from the wolfssl root"
    exit 1
fi

server_pid=0
tcpdump_pid=0

# tcpdump names the loopback interface differently across platforms.
if [ -z "$LOOPBACK_IF" ]; then
    case "$(uname -s)" in
        Darwin|*BSD) LOOPBACK_IF=lo0 ;;
        *)           LOOPBACK_IF=lo  ;;
    esac
fi

# stdbuf is GNU coreutils, absent on the BSDs.
STDBUF=()
if command -v stdbuf >/dev/null 2>&1; then
    STDBUF=(stdbuf -oL -eL)
fi

# With no arguments every capture is regenerated, otherwise only the named
# ones, e.g. `scripts/sniffer-gen.sh tls12-etm ipv6`.
CAPTURES=("$@")
MATCHED=()

cleanup() {
    if [ "$server_pid" -ne 0 ]; then kill $server_pid; server_pid=0; fi
    if [ "$tcpdump_pid" -ne 0 ]; then sleep 1; kill -15 $tcpdump_pid; tcpdump_pid=0; fi
}
trap cleanup EXIT INT TERM HUP

set -o pipefail
prepend() { # Usage: cmd 2>&1 | prepend "sometext "
    while read line; do echo "${1}${line}"; done
}

run_test() { # Usage: run_test <cipher> [serverArgs [clientArgs]]
    echo "Running test $1"
    CIPHER=$1
    if [ "$CIPHER" != "" ]; then
        CIPHER="-l $CIPHER"
    fi
    "${STDBUF[@]}" ./examples/server/server -i -x $CIPHER $2 2>&1 | prepend "[server] " &
    server_pid=$!
    ((server_pid--)) # Get the first PID in the pipe
    sleep 0.1
    "${STDBUF[@]}" ./examples/client/client $CIPHER $3 2>&1 | prepend "[client] "
    RET=$?
    if [ "$RET" != 0 ]; then
        echo "Error in test: $RET"
        exit $RET
    fi
    kill $server_pid; server_pid=0
    echo "Test passed: $1"
}

run_sequence() {
    if [ "$1" == "tls13-dh" ] || [ "$1" == "tls13-ecc" ] || [ "$1" == "tls13-keylog" ]; then # TLS v1.3
        run_test "TLS13-AES128-GCM-SHA256" "-v 4" "-v 4"
        run_test "TLS13-AES256-GCM-SHA384" "-v 4" "-v 4"
        run_test "TLS13-CHACHA20-POLY1305-SHA256" "-v 4" "-v 4"
    elif [ "$1" == "tls12" ] || [ "$1" == "tls12-keylog" ]; then # TLS v1.2
        run_test "ECDHE-ECDSA-AES128-GCM-SHA256" "-v 3 -A ./certs/ca-ecc-cert.pem -k ./certs/ecc-key.pem -c ./certs/intermediate/server-chain-ecc.pem -V" "-v 3 -A ./certs/ca-ecc-cert.pem -k ./certs/ecc-client-key.pem -c ./certs/intermediate/client-chain-ecc.pem -C"
        run_test "ECDHE-ECDSA-AES256-GCM-SHA384" "-v 3 -A ./certs/ca-ecc-cert.pem -k ./certs/ecc-key.pem -c ./certs/intermediate/server-chain-ecc.pem -V" "-v 3 -A ./certs/ca-ecc-cert.pem -k ./certs/ecc-client-key.pem -c ./certs/intermediate/client-chain-ecc.pem -C"
    elif [ "$1" == "tls13-dh-resume" ] || [ "$1" == "tls13-ecc-resume" ]; then # TLS v1.3 Resumption
        run_test "TLS13-AES128-GCM-SHA256" "-v 4 -r" "-v 4 -r"
        run_test "TLS13-AES256-GCM-SHA384" "-v 4 -r" "-v 4 -r"
        run_test "TLS13-CHACHA20-POLY1305-SHA256" "-v 4 -r" "-v 4 -r"
    elif [ "$1" == "tls13-x25519" ]; then # TLS v1.3
        run_test "TLS13-AES128-GCM-SHA256" "-v 4 -c ./certs/ed25519/server-ed25519.pem -k ./certs/ed25519/server-ed25519-priv.pem -A ./certs/ed25519/client-ed25519.pem" "-v 4 -c ./certs/ed25519/client-ed25519.pem -k ./certs/ed25519/client-ed25519-priv.pem -A ./certs/ed25519/root-ed25519.pem"
        run_test "TLS13-AES256-GCM-SHA384" "-v 4 -c ./certs/ed25519/server-ed25519.pem -k ./certs/ed25519/server-ed25519-priv.pem -A ./certs/ed25519/client-ed25519.pem" "-v 4 -c ./certs/ed25519/client-ed25519.pem -k ./certs/ed25519/client-ed25519-priv.pem -A ./certs/ed25519/root-ed25519.pem"
        run_test "TLS13-CHACHA20-POLY1305-SHA256" "-v 4 -c ./certs/ed25519/server-ed25519.pem -k ./certs/ed25519/server-ed25519-priv.pem -A ./certs/ed25519/client-ed25519.pem" "-v 4 -c ./certs/ed25519/client-ed25519.pem -k ./certs/ed25519/client-ed25519-priv.pem -A ./certs/ed25519/root-ed25519.pem"
    elif [ "$1" == "tls13-x25519-resume" ]; then # TLS v1.3 x25519 Resumption
        run_test "TLS13-AES128-GCM-SHA256" "-v 4 -r -c ./certs/ed25519/server-ed25519.pem -k ./certs/ed25519/server-ed25519-priv.pem -A ./certs/ed25519/client-ed25519.pem" "-v 4 -r -c ./certs/ed25519/client-ed25519.pem -k ./certs/ed25519/client-ed25519-priv.pem -A ./certs/ed25519/root-ed25519.pem"
        run_test "TLS13-AES256-GCM-SHA384" "-v 4 -r -c ./certs/ed25519/server-ed25519.pem -k ./certs/ed25519/server-ed25519-priv.pem -A ./certs/ed25519/client-ed25519.pem" "-v 4 -r -c ./certs/ed25519/client-ed25519.pem -k ./certs/ed25519/client-ed25519-priv.pem -A ./certs/ed25519/root-ed25519.pem"
        run_test "TLS13-CHACHA20-POLY1305-SHA256" "-v 4 -r -c ./certs/ed25519/server-ed25519.pem -k ./certs/ed25519/server-ed25519-priv.pem -A ./certs/ed25519/client-ed25519.pem" "-v 4 -r -c ./certs/ed25519/client-ed25519.pem -k ./certs/ed25519/client-ed25519-priv.pem -A ./certs/ed25519/root-ed25519.pem"
    elif [ "$1" == "tls12-etm" ]; then # TLS v1.2 static RSA CBC, Encrypt-Then-MAC
        run_test "AES128-SHA" "-v 3" "-v 3"
        run_test "AES256-SHA256" "-v 3" "-v 3"
    elif [ "$1" == "tls12-etm-keylog" ]; then # TLS v1.2 ECDHE CBC, Encrypt-Then-MAC
        run_test "ECDHE-RSA-AES128-SHA256" "-v 3" "-v 3"
        run_test "ECDHE-RSA-AES256-SHA384" "-v 3" "-v 3"
    elif [ "$1" == "static-rsa" ] || [ "$1" == "ipv6" ]; then # TLS v1.2 static RSA
        run_test "AES128-SHA" "-v 3" "-v 3"
    elif [ "$1" == "tls13-hrr" ]; then # TLS v1.3 Hello Retry Request
        run_test "" "-v 4 -g" "-v 4 -J"
    else
        echo "Invalid test"
        exit 1
    fi
}


run_capture() {
    local config_flags=()

    if [ ${#CAPTURES[@]} -ne 0 ] &&
       ! printf '%s\n' "${CAPTURES[@]}" | grep -qx -- "$1"; then
        return
    fi
    MATCHED+=("$1")
    echo -e "\nconfiguring and building wolfssl ($1)..."

    # Add default flags
    config_flags+=(--enable-sniffer)

    # If additional arguments are provided, add them to the array
    if [ -n "$2" ]; then
        # Convert string into an array, respecting quoted strings as a single element
        eval "config_flags+=($2)"
    fi

    ./configure "${config_flags[@]}" 1>/dev/null || exit $?
    make 1>/dev/null || exit $?

    if [[ "$1" == *keylog ]]; then
        rm -f ./sslkeylog.log
    fi

    echo "starting capture"
    tcpdump -i "$LOOPBACK_IF" -n port 11111 -w ./scripts/sniffer-${1}.pcap -U &
    tcpdump_pid=$!
    run_sequence $1
    sleep 1
    kill -15 $tcpdump_pid; tcpdump_pid=0

    if [[ "$1" == *keylog ]]; then
        cp ./sslkeylog.log ./scripts/sniffer-${1}.sslkeylog
    fi

    run_snifftest $1
}

# Regenerate the known good output for the captures that sniffer-testsuite.test
# compares against one. The arguments have to match the ones the test uses.
run_snifftest() {
    local args=()

    case "$1" in
        tls12-etm)
            args=(-key ./certs/server-key.pem) ;;
        tls12-keylog|tls13-keylog|tls12-etm-keylog)
            args=(-keylogfile "./scripts/sniffer-${1}.sslkeylog") ;;
        *)
            return ;;
    esac

    echo "regenerating scripts/sniffer-${1}.out"

    # Only the decrypted records are compared by sniffer-testsuite.test, and
    # they are the only lines every build agrees on: the banner names whatever
    # features the capture happened to be built with. Write to a temporary
    # file so a failed run cannot leave the tracked one truncated.
    local out
    out=$(mktemp)
    ./sslSniffer/sslSnifferTest/snifftest -expectdata \
        -pcap ./scripts/sniffer-${1}.pcap "${args[@]}" \
        -server 127.0.0.1 -port 11111 \
        | grep '^SSL App Data' > "$out"
    local rc=$?

    if [ $rc -ne 0 ]; then
        rm -f "$out"
        echo "snifftest could not read scripts/sniffer-${1}.pcap"
        exit $rc
    fi

    mv "$out" ./scripts/sniffer-${1}.out
    chmod 644 ./scripts/sniffer-${1}.out   # mktemp hands back 0600
}

run_capture "static-rsa"          "--enable-enc-then-mac=no"
run_capture "ipv6"                "--enable-enc-then-mac=no --enable-ipv6"
run_capture "tls12"               ""
run_capture "tls12-keylog"        "--enable-enc-then-mac=no --enable-keylog-export CFLAGS='-Wno-cpp -DWOLFSSL_SNIFFER_KEYLOGFILE'"
run_capture "tls13-keylog"        "--enable-keylog-export CFLAGS='-Wno-cpp -DWOLFSSL_SNIFFER_KEYLOGFILE'"
run_capture "tls13-ecc"           ""
run_capture "tls13-ecc-resume"    "--enable-session-ticket"
run_capture "tls13-dh"            "--disable-ecc"
run_capture "tls13-dh-resume"     "--disable-ecc --enable-session-ticket"
run_capture "tls13-x25519"        "--enable-curve25519 --enable-ed25519 --disable-dh --disable-ecc --disable-mlkem"
run_capture "tls13-x25519-resume" "--enable-curve25519 --enable-ed25519 --disable-dh --disable-ecc --disable-mlkem --enable-session-ticket"
run_capture "tls12-etm"           ""
run_capture "tls12-etm-keylog"    "--enable-keylog-export CFLAGS='-Wno-cpp -DWOLFSSL_SNIFFER_KEYLOGFILE'"
run_capture "tls13-hrr"           "--disable-dh CFLAGS=-DWOLFSSL_SNIFFER_WATCH"

if [ ${#CAPTURES[@]} -ne 0 ]; then
    for want in "${CAPTURES[@]}"; do
        if ! printf '%s\n' "${MATCHED[@]}" | grep -qx -- "$want"; then
            echo "No such capture: $want"
            exit 1
        fi
    done
fi

echo "Tests passed in $SECONDS seconds"
