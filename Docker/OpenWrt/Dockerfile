# This Dockerfile is used in conjunction with the docker-OpenWrt.yml GitHub Action.
FROM alpine:latest AS builder

RUN apk add argp-standalone asciidoc bash bc binutils bzip2 cdrkit coreutils \
  diffutils elfutils-dev findutils flex musl-fts-dev g++ gawk gcc gettext git \
  grep intltool libxslt linux-headers make musl-libintl musl-obstack-dev \
  ncurses-dev openssl-dev patch perl python3-dev rsync tar \
  unzip util-linux wget zlib-dev autoconf automake libtool
COPY . /workspace
RUN cd /workspace && ./autogen.sh && ./configure --enable-all && make

FROM openwrt/rootfs:x86-64-22.03.0

RUN mkdir -p /var/lock # Fix for parent container
COPY --from=builder /workspace/src/.libs/libwolfssl.so.35.3.0 /tmp/libwolfssl.so
RUN export LIBWOLFSSL=$(ls /usr/lib/libwolfssl.so.* -1); \
                      rm ${LIBWOLFSSL} && ln -s /tmp/libwolfssl.so ${LIBWOLFSSL}
COPY Docker/OpenWrt/runTests.sh /tmp/.
RUN /tmp/runTests.sh
