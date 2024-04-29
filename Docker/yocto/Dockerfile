FROM ubuntu

# Set timezone to UTC
RUN ln -snf /usr/share/zoneinfo/UTC /etc/localtime && echo UTC > /etc/timezone

RUN DEBIAN_FRONTEND=noninteractive apt update && apt install -y gawk wget git diffstat unzip texinfo gcc build-essential chrpath socat cpio python3 python3-pip python3-pexpect xz-utils debianutils iputils-ping python3-git python3-jinja2 libegl1-mesa libsdl1.2-dev python3-subunit mesa-common-dev zstd liblz4-tool file locales libacl1 vim && apt clean -y && rm -rf /var/lib/apt/lists/*
RUN locale-gen en_US.UTF-8

# Add in non-root user
ENV UID_OF_DOCKERUSER 1000
RUN useradd -m -s /bin/bash -g users -u ${UID_OF_DOCKERUSER} dockerUser
RUN chown -R dockerUser:users /home/dockerUser && chown dockerUser:users /opt

USER dockerUser

RUN cd /opt && git clone git://git.yoctoproject.org/poky
WORKDIR /opt/poky

ARG YOCTO_VERSION=kirkstone
RUN git checkout -t origin/${YOCTO_VERSION} -b ${YOCTO_VERSION} && git pull

# This arg is to be able to force a rebuild starting from this line
ARG DUMMY=date
RUN DUMMY=${DUMMY} git clone --single-branch --branch=master https://github.com/wolfssl/meta-wolfssl.git && \
    /bin/bash -c "source oe-init-build-env" && \
    echo 'IMAGE_INSTALL:append = " wolfssl wolfclu wolfssh wolfmqtt wolftpm wolfclu "' >> /opt/poky/build/conf/local.conf && \
    sed -i '/\/opt\/poky\/meta-poky \\/a \\t/opt/poky/meta-wolfssl \\' /opt/poky/build/conf/bblayers.conf

RUN /bin/bash -c "source oe-init-build-env && bitbake core-image-minimal"
