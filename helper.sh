set -x

function build(){
    ./autogen.sh
    ./configure
    make -j 10
    make check
    # install
}

function test(){
    # ./testsuite/testsuite.test
    # ./examples/client/client --help > client.help
    # This tells the client to connect to (-h) example.com on the HTTPS port (-p) of 443 and sends a generic (-g) GET request.
    ./examples/client/client \
    -h 127.0.0.1 \
    -p 32055 \
    -d \
    -g
}

$@