#!/bin/bash
set -e # Halt on errors
if [ "$DEBFULLNAME" == "" ]; then
    echo "What is your full name? "
    read DEBFULLNAME
fi
if [ "$DEBEMAIL" == "" ]; then
    echo "What is your e-mail? "
    read DEBEMAIL
fi

echo "Using $DEBFULLNAME <$DEBEMAIL>"
docker build -t deb --build-arg DEBEMAIL="$DEBEMAIL" --build-arg DEBFULLNAME="$DEBFULLNAME" .
TMPDIR=$(mktemp -d -p $(pwd))
docker run --rm -it -u docker -v $(pwd):/docker -v $TMPDIR:/workdir -v ${HOME}/.gnupg:/home/docker/.gnupg:ro deb /docker/createPackage.sh
echo "Now just need to run 'cd ${TMPDIR} && dput mentors wolfssl_%{WOLFSSL_NEW_VERSION}_amd64.changes'"
