#!/bin/bash

# example usage
# ./generate_SignedCA.sh rsa_private.pem rsa_public.pem ../../../../../../../certs/ca-cert.der ../../../../../../../../wolfssl/
# ./generate_SignedCA.sh rsa_private.pem rsa_public.pem ../../../../../../../certs/ca-ecc-cert.der ../../../../../../../../wolfssl
#
SIGOPT=rsa_padding_mode:pss
SIGOPT2=rsa_pss_saltlen:-1
CURRENT=$(cd $(dirname $0);pwd)

function usage() {
    cat <<- _EOT_
    Usage:
      $0 private-key public-key file-name wolfssl-dir

    Options:
      private-key : private key for sign/verify
      public-key  : public key for verify
      file-name   : file name to be signed
      wolfssl-dir : wolfssl folder path

_EOT_
exit 1
}

if [ $# -ne 4 ]; then
    usage
fi

# $1 private key for sign/verify
# $2 public key for verify
# $3 file for sign/verify
signed_file=$(basename $3)
wolf_dir=$4

openssl dgst -sha256 -sign $1 -sigopt $SIGOPT -sigopt $SIGOPT2 -out ${CURRENT}/${signed_file}.sign $3

echo Verify by private key
openssl dgst -sha256 -prverify $1 -sigopt $SIGOPT -sigopt $SIGOPT2 -signature ${CURRENT}/${signed_file}.sign $3
echo Verify by public key
openssl dgst -sha256 -verify $2 -sigopt $SIGOPT -sigopt $SIGOPT2 -signature ${CURRENT}/${signed_file}.sign $3

# Convert Signed CA to c source
${wolf_dir}/scripts/dertoc.pl ${CURRENT}/${signed_file}.sign  XXXXXXX ${signed_file}.c
