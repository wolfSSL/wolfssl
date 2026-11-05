#!/bin/bash

# Regenerate the certificates with fixed dates used by the chain check tests
# of X509_verify_cert() in tests/api/test_ossl_x509_str.c.
#
#   dated-root-cert         a self-signed CA, valid 2000 to 2049
#   dated-root-late-cert    dated-root-cert valid 2020 to 2049, same name and
#                           key
#   expired-root-cert       a self-signed CA, valid 2010 to 2019
#   expired-root-leaf-cert  issued by expired-root-cert, valid 2000 to 2049
#   expired-int-cert        a CA issued by dated-root-cert, valid 2010 to 2019
#   dated-int-cert          expired-int-cert valid 2000 to 2049, same name and
#                           key
#   dated-int-leaf-cert     issued by dated-int-cert, valid 2000 to 2049
#   notca-root-cert         a self-signed cert with CA:FALSE
#   notca-root-leaf-cert    issued by notca-root-cert
#   nobc-root-cert          a self-signed v3 cert without basicConstraints or
#                           keyUsage
#   nobc-root-leaf-cert     issued by nobc-root-cert
#   v1-root-cert            a self-signed X.509 v1 cert
#   v1-root-leaf-cert       issued by v1-root-cert
#   cross-root-cert         dated-root-cert's name and key, issued by
#                           expired-root-cert, valid 2000 to 2049
#   cross-root-late-cert    cross-root-cert valid 2020 to 2049
#   renewed-root-cert       a self-signed CA with expired-root-cert's name and
#                           a new key, valid 2020 to 2049
#   renewed-root-leaf-cert  issued by renewed-root-cert, no authority key id,
#                           valid 2000 to 2049
#   expired-root-int-cert   a CA issued by expired-root-cert, valid 2000 to
#                           2049
#   expired-root-int-leaf-cert  issued by expired-root-int-cert, valid 2000 to
#                           2049
#   expired-root-link-cert  a CA with expired-root-cert's name and a new key,
#                           issued by expired-root-cert, valid 2000 to 2049
#   expired-root-old-link-cert  expired-root-link-cert valid 2010 to 2019
#   expired-root-link-leaf-cert  issued by expired-root-link-cert, valid 2000
#                           to 2049
#   expired-root-nokid-cert  a self-signed CA with expired-root-cert's name, a
#                           new key and no key ids, valid 2000 to 2049
#   nokid-root-cert         a self-signed CA without key ids, valid 2000 to
#                           2049
#   badkid-int-cert         a CA issued by nokid-root-cert with an authority
#                           key id that does not match, valid 2010 to 2019
#   badkid-int-leaf-cert    issued by badkid-int-cert, valid 2000 to 2049
#   noaki-root-cert         a self-signed CA without an authority key id,
#                           valid 2000 to 2049
#   noaki-root-link-cert    a CA with noaki-root-cert's name and a new key,
#                           issued by noaki-root-cert, valid 2000 to 2049
#   noaki-root-leaf-cert    issued by noaki-root-cert, valid 2000 to 2049
#   forge-root-cert         a self-signed CA
#   forge-int-cert          a CA issued by forge-root-cert, subject key id
#                           07:07:...
#   forge-fake-int-cert     a CA with forge-int-cert's name, a new key and the
#                           subject key id 00:00:..., issued by forge-q-cert
#   forge-fake-int-leaf-cert  issued by forge-fake-int-cert
#   forge-q-cert            a CA without an authority key id, signed by the
#                           forge-fake-int-cert key in forge-int-cert's name
#   forge-bad-sub-cert      a CA with the authority key id 00:00:..., signed
#                           by another key in forge-int-cert's name
#   forge-sub-cert          forge-bad-sub-cert's name and key, without an
#                           authority key id, signed by the
#                           forge-fake-int-cert key in forge-int-cert's name
#   forge-sub-leaf-cert     issued by forge-sub-cert
#   alt-root-cert           a self-signed CA
#   alt-int-cert            a CA issued by alt-root-cert, valid 2020 to 2049
#   alt-end-cert            a CA issued by a CA that is not kept, so no
#                           chain goes on above it
#   alt-end-int-cert        alt-int-cert's name and key, issued by
#                           alt-end-cert, valid 2000 to 2049
#   alt-old-int-cert        alt-end-int-cert valid 2010 to 2019
#   alt-notca-int-cert      alt-end-int-cert with CA:FALSE
#   alt-int-leaf-cert       issued by the key of alt-int-cert
#   wrongca-root-cert       a self-signed CA
#   wrongca-cert            a CA issued by wrongca-root-cert
#   wrongca-int-cert        a CA without an authority key id, named as issued
#                           by wrongca-cert but signed by another key
#   wrongca-old-int-cert    wrongca-int-cert valid 2010 to 2019, with the
#                           authority key id of that key
#   wrongca-int-leaf-cert   issued by wrongca-int-cert
#   int-crl                 an empty CRL of the expired-int-cert key
#   dated-root-empty-crl    an empty CRL of dated-root-cert
#   dated-root-crl          a CRL of dated-root-cert, revokes expired-int-cert
#
# RSA-2048 / SHA-256. The keys are not kept.
#
# Requires: OpenSSL 3.0 or later and GNU sed.

set -e
cd "$(dirname "$0")"

OPENSSL="${OPENSSL:-openssl}"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/ca.cnf" <<'CNF'
[ca]
default_ca = ca_sect
[ca_sect]
dir = .
database = $dir/index.txt
new_certs_dir = $dir
serial = $dir/serial
crlnumber = $dir/crlnumber
crl_extensions = crl_ext
default_md = sha256
policy = policy_any
unique_subject = no
[policy_any]
commonName = supplied
[req]
distinguished_name = dn
[dn]
[ca_ext]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
[notca_ext]
basicConstraints = critical, CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
[nobc_ext]
subjectKeyIdentifier = hash
[leaf_ext]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
[v1_leaf_ext]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
subjectKeyIdentifier = hash
[noaki_leaf_ext]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = none
[nokid_ca_ext]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = none
authorityKeyIdentifier = none
[badkid_ca_ext]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
2.5.29.35 = DER:30168014010101010101010101010101010101010101010101
[noaki_ca_ext]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = none
[forge_int_ext]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
2.5.29.14 = DER:04140707070707070707070707070707070707070707
authorityKeyIdentifier = keyid:always
[forge_fake_ext]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
2.5.29.14 = DER:04140000000000000000000000000000000000000000
authorityKeyIdentifier = keyid:always
[crl_ext]
authorityKeyIdentifier = keyid:always
CNF
: > "$WORK/index.txt"
echo 1000 > "$WORK/crlnumber"

genkey() { "$OPENSSL" genrsa -out "$WORK/$1" 2048 2>/dev/null; }

# The serial of each cert, as in the committed set. Sets were made in
# separate runs, so some serials repeat.
serial_of() {
    case "$1" in
        dated-root-cert.pem|wrongca-root-cert.pem) echo 1000 ;;
        expired-root-cert.pem|wrongca-cert.pem) echo 1001 ;;
        expired-root-leaf-cert.pem|wrongca-gone-self.pem) echo 1002 ;;
        expired-int-cert.pem|wrongca-int-cert.pem) echo 1003 ;;
        dated-int-cert.pem|wrongca-old-int-cert.pem) echo 1004 ;;
        dated-int-leaf-cert.pem|wrongca-int-leaf-cert.pem) echo 1005 ;;
        notca-root-cert.pem) echo 1006 ;;
        notca-root-leaf-cert.pem) echo 1007 ;;
        nobc-root-cert.pem|v1-root-cert.pem) echo 1008 ;;
        nobc-root-leaf-cert.pem|v1-root-leaf-cert.pem) echo 1009 ;;
        cross-root-cert.pem) echo 100A ;;
        renewed-root-cert.pem) echo 100B ;;
        renewed-root-leaf-cert.pem) echo 100C ;;
        expired-root-int-cert.pem) echo 100D ;;
        expired-root-int-leaf-cert.pem) echo 100E ;;
        dated-root-late-cert.pem) echo 100F ;;
        cross-root-late-cert.pem) echo 1010 ;;
        expired-root-link-cert.pem) echo 1011 ;;
        expired-root-old-link-cert.pem) echo 1012 ;;
        expired-root-link-leaf-cert.pem) echo 1013 ;;
        nokid-root-cert.pem) echo 1014 ;;
        badkid-int-cert.pem) echo 1015 ;;
        badkid-int-leaf-cert.pem|expired-root-nokid-cert.pem) echo 1016 ;;
        noaki-root-cert.pem) echo 1019 ;;
        noaki-root-link-cert.pem|forge-root-cert.pem) echo 101A ;;
        noaki-root-leaf-cert.pem|forge-int-cert.pem) echo 101B ;;
        forge-fake-self.pem) echo 101C ;;
        forge-junk-self.pem) echo 101D ;;
        forge-q-cert.pem) echo 101E ;;
        forge-fake-int-cert.pem) echo 101F ;;
        forge-fake-int-leaf-cert.pem) echo 1020 ;;
        forge-bad-sub-cert.pem) echo 1021 ;;
        forge-sub-cert.pem) echo 1022 ;;
        forge-sub-leaf-cert.pem) echo 1023 ;;
        alt-root-cert.pem) echo 1027 ;;
        alt-int-cert.pem) echo 1028 ;;
        alt-gone-self.pem) echo 1029 ;;
        alt-end-cert.pem) echo 102A ;;
        alt-end-int-cert.pem) echo 102B ;;
        alt-old-int-cert.pem) echo 102C ;;
        alt-notca-int-cert.pem) echo 102D ;;
        alt-int-leaf-cert.pem) echo 102E ;;
        *) echo "No serial for $1" >&2; return 1 ;;
    esac
}

# Issue a cert, with a database of its own so that serials can repeat:
# issue <out> <CN> <key> <issuer-cert|self> <issuer-key> <ext|none>
#       <start> <end>
issue() {
    local sign ext
    : > "$WORK/index.txt"
    serial_of "$1" > "$WORK/serial"
    "$OPENSSL" req -new -key "$WORK/$3" -subj "/CN=$2" -config "$WORK/ca.cnf" \
        -out "$WORK/req.csr"
    if [ "$4" = "self" ]; then
        sign=(-selfsign -keyfile "$WORK/$5")
    else
        sign=(-cert "$WORK/$4" -keyfile "$WORK/$5")
    fi
    ext=()
    if [ "$6" != "none" ]; then
        ext=(-extensions "$6")
    fi
    (cd "$WORK" && "$OPENSSL" ca -batch -config ca.cnf -notext \
        "${sign[@]}" "${ext[@]}" -startdate "$7" -enddate "$8" \
        -in req.csr -out "$1" 2>/dev/null)
}

# Make a CRL that lists the certs revoked so far:
# crl <out> <issuer-cert> <issuer-key>
crl() {
    (cd "$WORK" && "$OPENSSL" ca -gencrl -config ca.cnf \
        -cert "$2" -keyfile "$3" -crl_lastupdate "$LONG" \
        -crl_nextupdate "$LONG_END" -out "$1" 2>/dev/null)
}

# Revoke a cert at the start of 2010: revoke <cert> <issuer-cert> <issuer-key>
revoke() {
    (cd "$WORK" && "$OPENSSL" ca -config ca.cnf -revoke "$1" \
        -cert "$2" -keyfile "$3" 2>/dev/null)
    sed -i 's/^\(R\t[^\t]*\t\)[^\t]*/\1100101000000Z/' "$WORK/index.txt"
}

OLD=20100101000000Z
OLD_END=20191231235959Z
NEW=20200101000000Z
LONG=20000101000000Z
LONG_END=20491231235959Z

genkey root.key
genkey expired-root.key
genkey int.key
genkey notca.key
genkey nobc.key
genkey v1.key
genkey leaf.key
genkey renewed-root.key
genkey expired-root-int.key
genkey expired-root-link.key
genkey expired-root-nokid.key
genkey nokid-root.key
genkey badkid-int.key
genkey noaki-root.key
genkey noaki-link.key
genkey forge-root.key
genkey forge-int.key
genkey forge-fake.key
genkey forge-junk.key
genkey forge-q.key
genkey forge-sub.key
genkey alt-root.key
genkey alt-int.key
genkey alt-end.key
genkey alt-gone.key
genkey wrongca-root.key
genkey wrongca.key
genkey wrongca-gone.key
genkey wrongca-int.key

issue dated-root-cert.pem "wolfSSL Chain Test Dated Root" root.key self \
    root.key ca_ext $LONG $LONG_END
issue expired-root-cert.pem "wolfSSL Chain Test Expired Root" \
    expired-root.key self expired-root.key ca_ext $OLD $OLD_END
issue expired-root-leaf-cert.pem "wolfSSL Chain Test Expired Root Leaf" \
    leaf.key expired-root-cert.pem expired-root.key leaf_ext $LONG $LONG_END
issue expired-int-cert.pem "wolfSSL Chain Test Int" int.key \
    dated-root-cert.pem root.key ca_ext $OLD $OLD_END
issue dated-int-cert.pem "wolfSSL Chain Test Int" int.key \
    dated-root-cert.pem root.key ca_ext $LONG $LONG_END
issue dated-int-leaf-cert.pem "wolfSSL Chain Test Int Leaf" leaf.key \
    dated-int-cert.pem int.key leaf_ext $LONG $LONG_END
issue notca-root-cert.pem "wolfSSL Chain Test Not CA Root" notca.key self \
    notca.key notca_ext $LONG $LONG_END
issue notca-root-leaf-cert.pem "wolfSSL Chain Test Not CA Root Leaf" \
    leaf.key notca-root-cert.pem notca.key leaf_ext $LONG $LONG_END
issue nobc-root-cert.pem "wolfSSL Chain Test No BC Root" nobc.key self \
    nobc.key nobc_ext $LONG $LONG_END
issue nobc-root-leaf-cert.pem "wolfSSL Chain Test No BC Root Leaf" \
    leaf.key nobc-root-cert.pem nobc.key leaf_ext $LONG $LONG_END
issue v1-root-cert.pem "wolfSSL Chain Test V1 Root" v1.key self v1.key \
    none $LONG $LONG_END
issue v1-root-leaf-cert.pem "wolfSSL Chain Test V1 Root Leaf" leaf.key \
    v1-root-cert.pem v1.key v1_leaf_ext $LONG $LONG_END
issue cross-root-cert.pem "wolfSSL Chain Test Dated Root" root.key \
    expired-root-cert.pem expired-root.key ca_ext $LONG $LONG_END
issue renewed-root-cert.pem "wolfSSL Chain Test Expired Root" \
    renewed-root.key self renewed-root.key ca_ext $NEW $LONG_END
issue renewed-root-leaf-cert.pem "wolfSSL Chain Test Renewed Root Leaf" \
    leaf.key renewed-root-cert.pem renewed-root.key noaki_leaf_ext $LONG \
    $LONG_END
issue expired-root-int-cert.pem "wolfSSL Chain Test Expired Root Int" \
    expired-root-int.key expired-root-cert.pem expired-root.key ca_ext \
    $LONG $LONG_END
issue expired-root-int-leaf-cert.pem \
    "wolfSSL Chain Test Expired Root Int Leaf" leaf.key \
    expired-root-int-cert.pem expired-root-int.key leaf_ext $LONG $LONG_END
issue dated-root-late-cert.pem "wolfSSL Chain Test Dated Root" root.key self \
    root.key ca_ext $NEW $LONG_END
issue cross-root-late-cert.pem "wolfSSL Chain Test Dated Root" root.key \
    expired-root-cert.pem expired-root.key ca_ext $NEW $LONG_END
issue expired-root-link-cert.pem "wolfSSL Chain Test Expired Root" \
    expired-root-link.key expired-root-cert.pem expired-root.key ca_ext \
    $LONG $LONG_END
issue expired-root-old-link-cert.pem "wolfSSL Chain Test Expired Root" \
    expired-root-link.key expired-root-cert.pem expired-root.key ca_ext \
    $OLD $OLD_END
issue expired-root-link-leaf-cert.pem \
    "wolfSSL Chain Test Expired Root Link Leaf" leaf.key \
    expired-root-link-cert.pem expired-root-link.key leaf_ext $LONG $LONG_END
issue expired-root-nokid-cert.pem "wolfSSL Chain Test Expired Root" \
    expired-root-nokid.key self expired-root-nokid.key nokid_ca_ext $LONG \
    $LONG_END
issue nokid-root-cert.pem "wolfSSL Chain Test No Key Id Root" nokid-root.key \
    self nokid-root.key nokid_ca_ext $LONG $LONG_END
issue badkid-int-cert.pem "wolfSSL Chain Test Bad Key Id Int" badkid-int.key \
    nokid-root-cert.pem nokid-root.key badkid_ca_ext $OLD $OLD_END
issue badkid-int-leaf-cert.pem "wolfSSL Chain Test Bad Key Id Int Leaf" \
    leaf.key badkid-int-cert.pem badkid-int.key leaf_ext $LONG $LONG_END
issue noaki-root-cert.pem "wolfSSL Chain Test No AKI Root" noaki-root.key \
    self noaki-root.key noaki_ca_ext $LONG $LONG_END
issue noaki-root-link-cert.pem "wolfSSL Chain Test No AKI Root" \
    noaki-link.key noaki-root-cert.pem noaki-root.key ca_ext $LONG $LONG_END
issue noaki-root-leaf-cert.pem "wolfSSL Chain Test No AKI Root Leaf" \
    leaf.key noaki-root-cert.pem noaki-root.key leaf_ext $LONG $LONG_END

# A forged chain. The subject key id 00:00:... puts forge-fake-int-cert in
# the first row of the cert manager's CA table, before forge-int-cert, so a
# lookup by name finds it first. forge-fake-self and forge-junk-self only
# sign other certs.
issue forge-root-cert.pem "wolfSSL Chain Test Forge Root" forge-root.key \
    self forge-root.key ca_ext $LONG $LONG_END
issue forge-int-cert.pem "wolfSSL Chain Test Forge Int" forge-int.key \
    forge-root-cert.pem forge-root.key forge_int_ext $LONG $LONG_END
issue forge-fake-self.pem "wolfSSL Chain Test Forge Int" forge-fake.key \
    self forge-fake.key forge_fake_ext $LONG $LONG_END
issue forge-junk-self.pem "wolfSSL Chain Test Forge Int" forge-junk.key \
    self forge-junk.key forge_fake_ext $LONG $LONG_END
issue forge-q-cert.pem "wolfSSL Chain Test Forge Q" forge-q.key \
    forge-fake-self.pem forge-fake.key noaki_ca_ext $LONG $LONG_END
issue forge-fake-int-cert.pem "wolfSSL Chain Test Forge Int" forge-fake.key \
    forge-q-cert.pem forge-q.key forge_fake_ext $LONG $LONG_END
issue forge-fake-int-leaf-cert.pem "wolfSSL Chain Test Forge Fake Int Leaf" \
    leaf.key forge-fake-int-cert.pem forge-fake.key leaf_ext $LONG $LONG_END
issue forge-bad-sub-cert.pem "wolfSSL Chain Test Forge Sub" forge-sub.key \
    forge-junk-self.pem forge-junk.key ca_ext $LONG $LONG_END
issue forge-sub-cert.pem "wolfSSL Chain Test Forge Sub" forge-sub.key \
    forge-fake-self.pem forge-fake.key noaki_ca_ext $LONG $LONG_END
issue forge-sub-leaf-cert.pem "wolfSSL Chain Test Forge Sub Leaf" leaf.key \
    forge-sub-cert.pem forge-sub.key leaf_ext $LONG $LONG_END

# Two paths to the issuer of alt-int-leaf-cert: through alt-int-cert to
# alt-root-cert, or through alt-end-cert, which alt-gone-self signed and so
# ends nowhere.
issue alt-root-cert.pem "wolfSSL Chain Test Alt Root" alt-root.key self \
    alt-root.key ca_ext $LONG $LONG_END
issue alt-int-cert.pem "wolfSSL Chain Test Alt Int" alt-int.key \
    alt-root-cert.pem alt-root.key ca_ext $NEW $LONG_END
issue alt-gone-self.pem "wolfSSL Chain Test Alt Gone" alt-gone.key self \
    alt-gone.key ca_ext $LONG $LONG_END
issue alt-end-cert.pem "wolfSSL Chain Test Alt End" alt-end.key \
    alt-gone-self.pem alt-gone.key ca_ext $LONG $LONG_END
issue alt-end-int-cert.pem "wolfSSL Chain Test Alt Int" alt-int.key \
    alt-end-cert.pem alt-end.key ca_ext $LONG $LONG_END
issue alt-old-int-cert.pem "wolfSSL Chain Test Alt Int" alt-int.key \
    alt-end-cert.pem alt-end.key ca_ext $OLD $OLD_END
issue alt-notca-int-cert.pem "wolfSSL Chain Test Alt Int" alt-int.key \
    alt-end-cert.pem alt-end.key notca_ext $LONG $LONG_END
issue alt-int-leaf-cert.pem "wolfSSL Chain Test Alt Int Leaf" leaf.key \
    alt-int-cert.pem alt-int.key leaf_ext $LONG $LONG_END

# A trusted issuer whose key did not sign: wrongca-int-cert names
# wrongca-cert's name as its issuer and has no authority key id, but the key
# of wrongca-gone-self signed it. wrongca-old-int-cert is its untrusted twin,
# out of date, with the authority key id of that key.
issue wrongca-root-cert.pem "wolfSSL Chain Test Wrong CA Root" \
    wrongca-root.key self wrongca-root.key ca_ext $LONG $LONG_END
issue wrongca-cert.pem "wolfSSL Chain Test Wrong CA" wrongca.key \
    wrongca-root-cert.pem wrongca-root.key ca_ext $LONG $LONG_END
issue wrongca-gone-self.pem "wolfSSL Chain Test Wrong CA" wrongca-gone.key \
    self wrongca-gone.key ca_ext $LONG $LONG_END
issue wrongca-int-cert.pem "wolfSSL Chain Test Wrong CA Int" \
    wrongca-int.key wrongca-gone-self.pem wrongca-gone.key noaki_ca_ext \
    $LONG $LONG_END
issue wrongca-old-int-cert.pem "wolfSSL Chain Test Wrong CA Int" \
    wrongca-int.key wrongca-gone-self.pem wrongca-gone.key ca_ext $OLD \
    $OLD_END
issue wrongca-int-leaf-cert.pem "wolfSSL Chain Test Wrong CA Int Leaf" \
    leaf.key wrongca-int-cert.pem wrongca-int.key leaf_ext $LONG $LONG_END

crl int-crl.pem dated-int-cert.pem int.key
crl dated-root-empty-crl.pem dated-root-cert.pem root.key
revoke expired-int-cert.pem dated-root-cert.pem root.key
crl dated-root-crl.pem dated-root-cert.pem root.key

# Only now, so a failed run leaves the certs and CRLs as they were.
cp "$WORK"/*-cert.pem "$WORK"/*-crl.pem .
echo "Completed"
