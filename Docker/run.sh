echo "Running with \"${@}\"..."

# Assume we're in wolfssl/Docker
WOLFSSL_DIR=$(builtin cd ${BASH_SOURCE%/*}/..; pwd)

docker build -t wolfssl --build-arg UID=$(id -u) --build-arg GID=$(id -g) ${WOLFSSL_DIR}/Docker && \
docker run -it -v ${WOLFSSL_DIR}:/tmp/wolfssl -w /tmp/wolfssl wolfssl /bin/bash -c "./autogen.sh && ./configure $(echo ${@}) && make && ./testsuite/testsuite.test" && \
docker run -it -v ${WOLFSSL_DIR}:/tmp/wolfssl -w /tmp/wolfssl wolfssl /bin/bash
echo "Exited with error code $?"
