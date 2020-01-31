abi-client
==========

The _abi-client_ is a testing client that only uses the functions available
in the ABI build of wolfSSL. All functions in wolfSSL and wolfCrypt become
private and only a handful are usable. This client will exercise those
functions.

The client requires a server to test against, and the wolfSSL server is
disabled in the ABI build. From a copy of the wolfSSL source tree, build
and run the server:

    $ ./configure --enable-all && make
    $ ./examples/server/server -c ./certs/test/server-localhost.pem -d -v d -i

To configure and build the ABI client, from the source directory for the
_abi-client_:

    $ ./configure --enable-abi && make
    $ ./tests/abi/abi-client

The server and client both default to using port 11111.

The client will output the names of some functions, some information about
certificates, the return codes of several functions, and will perform both
a TLSv1.2 and TLSv1.3 connection.
