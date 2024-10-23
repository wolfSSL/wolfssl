ARG DOCKER_BASE_IMAGE=ubuntu:22.04
FROM $DOCKER_BASE_IMAGE

USER root

# Set timezone to UTC
RUN ln -snf /usr/share/zoneinfo/UTC /etc/localtime && echo UTC > /etc/timezone

ARG DEPS_WOLFSSL="build-essential autoconf libtool clang clang-tools zlib1g-dev libuv1-dev libpam0g-dev valgrind git linux-headers-generic gcc-multilib g++-multilib libpcap-dev bubblewrap gdb iputils-ping lldb bsdmainutils netcat-traditional binutils-arm-linux-gnueabi binutils-aarch64-linux-gnu"
ARG DEPS_LIBOQS="astyle cmake gcc ninja-build libssl-dev python3-pytest python3-pytest-xdist unzip xsltproc doxygen graphviz python3-yaml valgrind git"
ARG DEPS_UDP_PROXY="wget libevent-dev"
ARG DEPS_TESTS="abi-dumper libcurl4-openssl-dev tcpdump libpsl-dev python3-pandas python3-tabulate libnl-genl-3-dev libcap-ng-dev python3-virtualenv curl jq"
ARG DEPS_TOOLS="ccache clang-tidy maven libfile-util-perl android-tools-adb usbutils shellcheck"
RUN DEBIAN_FRONTEND=noninteractive apt update && apt install -y apt-utils \
                    && apt install -y ${DEPS_WOLFSSL} ${DEPS_LIBOQS} ${DEPS_UDP_PROXY} ${DEPS_TESTS} ${DEPS_TOOLS} \
                    && apt clean -y && rm -rf /var/lib/apt/lists/*

# Add 'docker' user
ARG USER=docker
ARG UID=1000
ARG GID=1000
RUN groupadd -f -g ${GID} docker && ( getent passwd ${UID} || useradd -ms /bin/bash ${USER} -u ${UID} -g ${GID} )

# Add github.com as an SSH known host
RUN ssh -o StrictHostKeyChecking=no -T git@github.com; cat ~/.ssh/known_hosts >> /etc/ssh/ssh_known_hosts

# install ccache
RUN mkdir -p /opt/ccache/bin && for prog in gcc g++ cc c++ cpp arm-none-eabi-c++ arm-none-eabi-cpp arm-none-eabi-gcc arm-none-eabi-g++; do ln -s /usr/bin/ccache /opt/ccache/bin/$(basename $prog); done
ENV PATH /opt/ccache/bin:$PATH

# install liboqs
RUN git clone --single-branch https://github.com/open-quantum-safe/liboqs.git && cd liboqs && git checkout db08f12b5a96aa6582a82aac7f65cf8a4d8b231f \
    && mkdir build && cd build && cmake -DOQS_DIST_BUILD=ON -DOQS_USE_CPUFEATURE_INSTRUCTIONS=OFF -DOQS_USE_OPENSSL=0 .. && make -j8 all && make install && cd ../.. && rm -rf liboqs

RUN mkdir /opt/sources

# install liblms
RUN cd /opt/sources && git clone --single-branch https://github.com/cisco/hash-sigs.git && cd hash-sigs && git checkout b0631b8891295bf2929e68761205337b7c031726 \
    && sed -i 's/USE_OPENSSL 1/USE_OPENSSL 0/g' sha256.h && make -j4 hss_lib_thread.a

# Install pkixssh to /opt/pkixssh for X509 interop testing with wolfSSH
RUN mkdir /var/empty
RUN cd /opt/sources && wget -q -O- https://roumenpetrov.info/secsh/src/pkixssh-15.1.tar.gz | tar xzf - && cd pkixssh-15.1 && ./configure --prefix=/opt/pkixssh/ --exec-prefix=/opt/pkixssh/ && make install

# Install udp/tcp-proxy
RUN cd /opt/sources && git clone --depth=1 --single-branch --branch=main http://github.com/wolfssl/udp-proxy && cd udp-proxy && make && cp tcp_proxy udp_proxy /bin/.
# Install libbacktrace
RUN cd /opt/sources && git clone --depth=1 --single-branch https://github.com/ianlancetaylor/libbacktrace.git && cd libbacktrace && mkdir build && cd build && ../configure && make && make install

# Allow non-root to use tcpdump (will need NET_RAW and NET_ADMIN capability when running the container)
RUN setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /usr/bin/tcpdump
# Allow non-root to use gdb on processes (will need SYS_PTRACE capability when running the container)
RUN setcap 'CAP_SYS_PTRACE+eip' /usr/bin/gdb

# Add in Jenkins userID
RUN for i in $(seq 1001 1010); do ( getent passwd ${i} || useradd -ms /bin/bash jenkins${i} -u ${i} -g ${GID} ); done

USER ${UID}:${GID}
