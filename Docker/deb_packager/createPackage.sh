#!/bin/bash
set -e # error on any call failure

WOLFSSL_OLD_VERSION=5.5.4-2
WOLFSSL_NEW_VERSION=5.6.0-1
LIBWOLFSSL_OLD_VERSION=libwolfssl35
LIBWOLFSSL_NEW_VERSION=libwolfssl36

dget https://deb.debian.org/debian/pool/main/w/wolfssl/wolfssl_${WOLFSSL_OLD_VERSION}.dsc
cd wolfssl-${WOLFSSL_OLD_VERSION%-*}
uscan -v
cd .. 
tar xvf wolfssl_${WOLFSSL_NEW_VERSION%-*}.orig.tar.gz
cd wolfssl-${WOLFSSL_NEW_VERSION%-*}-stable
tar xvf ../wolfssl_${WOLFSSL_OLD_VERSION}.debian.tar.xz
echo -e "In the next prompt, update release version to ${WOLFSSL_NEW_VERSION%-*}-1\nPress <Enter> when ready to continue..."
read
dch
set +e # Expecting an error
debuild -S
set -e
#cd ..
#dpkg-source -x wolfssl_${WOLFSSL_NEW_VERSION}.dsc
#cd wolfssl-${WOLFSSL_NEW_VERSION%-*}
quilt applied
quilt pop -a
set +e # Expecting an error
while true; do
    out=$(quilt push && quilt refresh)
    if [[ $? != 0 ]]; then
        break
    fi
done
set -e
debuild -S
set +e # Expecting an error
debuild -b
set -e
sed -i "s/${WOLFSSL_NEW_VERSION}/${WOLFSSL_NEW_VERSION%-*}/g" debian/${LIBWOLFSSL_OLD_VERSION}/DEBIAN/symbols
cp debian/${LIBWOLFSSL_OLD_VERSION}/DEBIAN/symbols debian/${LIBWOLFSSL_OLD_VERSION}.symbols
rename "s/${LIBWOLFSSL_OLD_VERSION}/${LIBWOLFSSL_NEW_VERSION}/" debian/libwolfssl*
sed -i "s/${LIBWOLFSSL_OLD_VERSION}/${LIBWOLFSSL_NEW_VERSION}/g" debian/control
debclean
#debuild -b
dch -r
debuild

echo "Successfully build package"
