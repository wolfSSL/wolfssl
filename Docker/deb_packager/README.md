This container is useful for creating the official wolfSSL Debian packages.

You'll need to modify `createPackage.sh` to use the correct `WOLFSSL_*_VERSION` and `LIBWOLFSSL_*_VERSION`. The script should build everything but you will need to have your GPG keys all set up on https://mentors.debian.net. While the script is running, it will prompt you to update the change log.

To use the script, you can run it like so:
```
DEBFULLNAME="First Last" DEBEMAIL="first@wolfssl.com" ./run.sh
```
