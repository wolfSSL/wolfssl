echo "Running with \"${@}\"..."
docker build -t wolfssl . && \
docker run -it -v $(pwd)/..:/tmp/wolfssl -w /tmp/wolfssl wolfssl /bin/bash -c "./autogen.sh && ./configure $(echo ${@}) && make && ./testsuite/testsuite.test" && \
docker run -it -v $(pwd)/..:/tmp/wolfssl -w /tmp/wolfssl wolfssl /bin/bash
echo "Exited with error code $?"
