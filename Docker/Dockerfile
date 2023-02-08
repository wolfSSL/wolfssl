ARG DOCKER_BASE_IMAGE=ubuntu:22.04
FROM $DOCKER_BASE_IMAGE

USER root

RUN DEBIAN_FRONTEND=noninteractive apt update && apt install -y build-essential autoconf libtool git gdb iputils-ping clang lldb bsdmainutils

ARG USER=docker
ARG UID=1000
ARG GID=1000
RUN groupadd -f -g ${GID} docker && ( getent passwd ${UID} || useradd -ms /bin/bash ${USER} -u ${UID} -g ${GID} )

USER ${UID}:${GID}