#!/bin/sh

# genkey-sign-ver-test.sh
#
# Copyright (C) 2006-2021 wolfSSL Inc.
#
# This file is part of wolfSSL.
#
# wolfSSL is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# wolfSSL is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
#/
#/
#

# Skip test if filesystem disabled
FILESYSTEM=`cat config.log | grep "disable\-filesystem"`
if [ "$FILESYSTEM" != "" ]
then
    exit 77
fi

cleanup_genkey_sign_ver(){
    rm -f ecckey
    rm ecckey.priv
    rm ecckey.pub
    rm edkey.priv
    rm edkey.pub
    rm rsakey.priv
    rm rsakey.pub
    rm ecc-signed.sig
    rm ed-signed.sig
    rm rsa-signed.sig
    rm rsa-sigout.private_result
    rm rsa-sigout.public_result
    rm sign-this.txt
}
trap cleanup_genkey_sign_ver INT TERM EXIT

create_sign_data_file(){
    printf '%s\n' "Sign this data" > sign-this.txt
}

rsa_compare_decrypted(){
    if [ "${1}" = "${2}" ]; then
        printf '%s\n' "Decrypted matches original, success!"
        printf '%s\n' "DECRYPTED --> ${1}"
        printf '%s\n' "ORIGINAL --> ${2}"
    else
        printf '%s\n' "Decrypted mismatch with original, FAILURE!"
        printf '%s\n' "DECRYPTED --> ${1}"
        printf '%s\n' "ORIGINAL --> ${2}" && exit -1
    fi
}

gen_key_sign_ver_test(){

    # generate a key pair for signing
    ./wolfssl -genkey $1 -out $2 -outform der KEYPAIR
    RESULT=$?
    printf '%s\n' "genkey RESULT - $RESULT"
    [ $RESULT -ne 0 ] && printf '%s\n' "Failed $1 genkey" && \
    printf '%s\n' "Before running this test please configure wolfssl with" && \
    printf '%s\n' "--enable-keygen" && exit -1

    # test signing with priv key
    ./wolfssl -$1 -sign -inkey $2.priv -in sign-this.txt -out $3
    RESULT=$?
    printf '%s\n' "sign RESULT - $RESULT"
    [ $RESULT -ne 0 ] && printf '%s\n' "Failed $1 sign" && exit -1

    # test verifying with priv key
    if [ "${1}" = "rsa" ]; then
        ./wolfssl -$1 -verify -inkey $2.priv -sigfile $3 -in sign-this.txt \
                  -out $4.private_result
    else
        ./wolfssl -$1 -verify -inkey $2.priv -sigfile $3 -in sign-this.txt
    fi
    RESULT=$?
    printf '%s\n' "private verify RESULT - $RESULT"
    [ $RESULT -ne 0 ] && printf '%s\n' "Failed $1 sign" && exit -1

    # test verifying with pub key
    if [ "${1}" = "rsa" ]; then
        ./wolfssl -$1 -verify -inkey $2.pub -sigfile $3 -in sign-this.txt \
                  -out $4.public_result -pubin
    else
        ./wolfssl -$1 -verify -inkey $2.pub -sigfile $3 -in sign-this.txt -pubin
    fi
    RESULT=$?
    printf '%s\n' "public verify RESULT - $RESULT"
    [ $RESULT -ne 0 ] && printf '%s\n' "Failed $1 sign" && exit -1

    if [ $1 = "rsa" ]; then
        ORIGINAL=`cat -A sign-this.txt`

        DECRYPTED=`cat -A $4.private_result`
        rsa_compare_decrypted "${DECRYPTED}" "${ORIGINAL}"

        DECRYPTED=`cat -A $4.public_result`
        rsa_compare_decrypted "${DECRYPTED}" "${ORIGINAL}"
    fi

}

create_sign_data_file

ALGORITHM="ed25519"
KEYFILENAME="edkey"
SIGOUTNAME="ed-signed.sig"
gen_key_sign_ver_test ${ALGORITHM} ${KEYFILENAME} ${SIGOUTNAME}

ALGORITHM="ecc"
KEYFILENAME="ecckey"
SIGOUTNAME="ecc-signed.sig"
gen_key_sign_ver_test ${ALGORITHM} ${KEYFILENAME} ${SIGOUTNAME}

ALGORITHM="rsa"
KEYFILENAME="rsakey"
SIGOUTNAME="rsa-signed.sig"
VERIFYOUTNAME="rsa-sigout"
gen_key_sign_ver_test ${ALGORITHM} ${KEYFILENAME} ${SIGOUTNAME} ${VERIFYOUTNAME}

exit 0
