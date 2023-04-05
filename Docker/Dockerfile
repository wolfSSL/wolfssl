ARG DOCKER_BASE_IMAGE=ubuntu:22.04
FROM $DOCKER_BASE_IMAGE

USER root

ARG DEPS_WOLFSSL="build-essential autoconf libtool clang clang-tools zlib1g-dev libuv1-dev libpam0g-dev valgrind git linux-headers-generic gcc-multilib g++-multilib libpcap-dev bubblewrap gdb iputils-ping lldb bsdmainutils netcat binutils-arm-linux-gnueabi binutils-aarch64-linux-gnu"
ARG DEPS_LIBOQS="astyle cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz python3-yaml valgrind git"
ARG DEPS_TESTS="abi-dumper libcurl4-openssl-dev tcpdump"
RUN DEBIAN_FRONTEND=noninteractive apt update && apt install -y apt-utils \
                    && apt install -y ${DEPS_WOLFSSL} ${DEPS_LIBOQS} ${DEPS_TESTS} \
                    && apt clean -y && rm -rf /var/lib/apt/lists/*

ARG USER=docker
ARG UID=1000
ARG GID=1000
RUN groupadd -f -g ${GID} docker && ( getent passwd ${UID} || useradd -ms /bin/bash ${USER} -u ${UID} -g ${GID} )

# install liboqs
RUN git clone --single-branch https://github.com/open-quantum-safe/liboqs.git && cd liboqs && git checkout af76ca3b1f2fbc1f4f0967595f3bb07692fb3d82 \
    && mkdir build && cd build && cmake -DOQS_DIST_BUILD=ON -DOQS_USE_CPUFEATURE_INSTRUCTIONS=OFF -DOQS_USE_OPENSSL=0 .. && make -j8 all && make install && cd ../.. && rm -rf liboqs

# Allow non-root to use tcpdump (will need NET_RAW and NET_ADMIN capability when running the container)
RUN setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /usr/bin/tcpdump

USER ${UID}:${GID}