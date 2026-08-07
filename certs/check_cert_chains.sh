#!/bin/sh

# Verify each committed leaf certificate still chains to its committed CA, so a
# CA re-issue (subject DN or key change) that skips the leaf is caught here
# rather than as a runtime TLS handshake failure. Two checks per pair:
#   1. identity: leaf issuer DN == CA subject DN and leaf AKID == CA SKID; runs
#      on any OpenSSL and catches the DN drift that has actually broken CI.
#   2. crypto: openssl verify, only when this OpenSSL will verify the leaf's
#      signature algorithm (ML-DSA needs 3.5+, SHA-1 is refused outright by some
#      distributions); otherwise skipped with notice. Exit 0 if all consistent.

# Run from the certs directory regardless of the caller's working directory.
cd "$(dirname "$0")" || exit 1

# Pairs to check: "<leaf-pem> <ca-pem> <alg-class>", one per line. alg-class is
# "classic" (RSA/ECDSA), "mldsa" (needs OpenSSL 3.5+ to verify) or "sha1"; it is
# stated here, not parsed, since old OpenSSL cannot decode an ML-DSA cert. A
# multi-certificate file is checked on its first certificate, which is the leaf.
# Add lines here.
pairs="rsapss/ecc-leaf-rsapss.pem rsapss/ca-rsapss.pem classic
mldsa/ecc-leaf-mldsa44.pem mldsa/mldsa44-cert.pem mldsa
server-cert-sha1.pem ca-cert.pem sha1
client-cert-sha1.pem ca-cert.pem sha1
server-cert-sha1-root.pem ca-cert.pem classic"

failed=0

# Report whether this OpenSSL can cryptographically verify the given signature
# algorithm class. Returns 0 (supported) or 1 (not supported).
#
# $1  Algorithm class from the pairs table (classic, mldsa or sha1).
crypto_supported() {
    case $1 in
        mldsa)
            openssl list -signature-algorithms 2>/dev/null \
                | grep -iq 'ML-DSA'
            return $?
            ;;
        sha1)
            # Stock OpenSSL still verifies a SHA-1 signature at the default
            # security level, but distributions that apply a system crypto
            # policy refuse it. Rely on the identity check, which is portable.
            return 1
            ;;
        *)
            # classic: RSA, RSA-PSS and ECDSA verify on any modern OpenSSL.
            return 0
            ;;
    esac
}

# Read a key identifier from an "openssl x509 -ext" dump on stdin and print it
# as bare hex. Two layouts occur: a bare value (subjectKeyIdentifier, and an
# authorityKeyIdentifier built from keyid alone) and a labelled value where
# keyid, DirName and serial each get a line. Only the keyid is wanted, so stop
# at the first value rather than joining every hex run in the dump. POSIX awk
# because grep -o is not portable and could silently yield an empty id.
extract_key_id() {
    awk '
        /[Kk]eyid:/ {
            sub(/^.*[Kk]eyid:/, "")
            print
            exit
        }
        match($0, /[0-9A-Fa-f][0-9A-Fa-f](:[0-9A-Fa-f][0-9A-Fa-f])+/) {
            print substr($0, RSTART, RLENGTH)
            exit
        }
    ' | tr -cd '0-9A-Fa-f'
}

# Identity check ($1 leaf, $2 CA): leaf issuer DN == CA subject DN and, when
# both present, leaf AKID == CA SKID. Signature-independent (works on any
# OpenSSL). Returns 0 on match, 1 on mismatch.
identity_matches() {
    leaf=$1
    ca=$2

    iss=`openssl x509 -in "$leaf" -noout -issuer  -nameopt RFC2253 \
         | sed 's/^issuer= *//'`
    sub=`openssl x509 -in "$ca"   -noout -subject -nameopt RFC2253 \
         | sed 's/^subject= *//'`
    if [ "$iss" != "$sub" ]; then
        echo "MISMATCH (issuer/subject): $leaf"
        echo "    leaf issuer : $iss"
        echo "    ca subject  : $sub"
        return 1
    fi

    akid=`openssl x509 -in "$leaf" -noout -ext authorityKeyIdentifier \
          2>/dev/null | extract_key_id`
    skid=`openssl x509 -in "$ca"   -noout -ext subjectKeyIdentifier \
          2>/dev/null | extract_key_id`
    if [ -n "$akid" ] && [ -n "$skid" ] && [ "$akid" != "$skid" ]; then
        echo "MISMATCH (AKID/SKID): $leaf vs $ca"
        echo "    leaf AKID : $akid"
        echo "    ca   SKID : $skid"
        return 1
    fi

    return 0
}

# A here-document (not a pipe) feeds the loop so the body runs in this shell
# and updates to "failed" survive after the loop, per POSIX.
while read -r leaf ca alg
do
    [ -z "$leaf" ] && continue

    if [ ! -f "$leaf" ] || [ ! -f "$ca" ]; then
        echo "MISSING: $leaf or $ca"
        failed=1
        continue
    fi

    if ! identity_matches "$leaf" "$ca"; then
        failed=1
        continue
    fi

    if crypto_supported "$alg"; then
        if openssl verify -partial_chain -CAfile "$ca" "$leaf" >/dev/null 2>&1; then
            echo "OK (crypto): $leaf -> $ca"
        else
            echo "VERIFY FAILED (crypto): $leaf -> $ca"
            openssl verify -partial_chain -CAfile "$ca" "$leaf"
            failed=1
        fi
    else
        echo "OK (identity only, crypto verify skipped): $leaf -> $ca"
    fi
done <<EOF
$pairs
EOF

if [ "$failed" != "0" ]; then
    echo ""
    echo "One or more committed leaf certificates no longer chain to their CA."
    echo "Regenerate the affected leaf from certs/renewcerts.sh (or the matching"
    echo "renew-*.sh) so it is re-signed by the current CA, then re-run this check."
fi

exit $failed
